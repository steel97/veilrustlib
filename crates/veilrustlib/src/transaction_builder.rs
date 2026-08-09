//! RingCT transaction construction.
//!
//! Port of `src/TransactionBuilder.ts`. Builds Veil RingCT transactions:
//! selects coins, creates blinded outputs with range proofs, assembles rings
//! from decoys, and signs each input with an MLSAG ring signature.
//!
//! Unlike the TypeScript original there is no initialization step, since
//! `veil-crypto` is linked directly rather than loaded as a WASM module.

use crate::crypto::{
    create_commitment, derive_public_key, ecdh_nonce, generate_key_image, generate_mlsag,
    generate_range_proof, point_multiply, prepare_mlsag, private_add, sha256,
    sum_blinds, verify_mlsag, GenerateMlsagParams, PrepareMlsagParams, VerifyMlsagParams,
};
use crate::error::{Result, VeilError};
use crate::range_proof_params::{select_range_proof_parameters, validate_range_proof_params};
use crate::serialization::{
    calculate_txid, encode_anon_prevout_hash, encode_leb128, serialize_output_data,
    serialize_transaction, serialize_transaction_bytes,
};
use crate::stealth::{generate_ephemeral_keys, generate_stealth_address};
use crate::types::{
    AnonOutput, Blind, Commitment, DataOutputType, OutPoint, PublicKey, ScriptStack, SecretKey,
    Transaction, TransactionType, TxOutput, Utxo, ANON_MARKER,
};
use crate::utils::{is_valid_amount, is_valid_ring_size, random_32, random_sample, satoshis_to_veil};

/// Smallest permitted ring size.
pub const MIN_RING_SIZE: usize = 3;

/// Largest permitted ring size.
pub const MAX_RING_SIZE: usize = 32;

/// Ring size used when none is configured.
pub const DEFAULT_RING_SIZE: usize = 11;

/// Consensus limit on RingCT inputs per transaction.
pub const MAX_ANON_INPUTS: usize = 32;

/// Outputs at or below this value are dust.
pub const DUST_THRESHOLD: u64 = 1_000;

/// Default fee rate, in satoshis per kilobyte.
pub const DEFAULT_FEE_PER_KB: u64 = 10_000;

/// UTXO count above which consolidation is worth suggesting.
pub const CONSOLIDATION_THRESHOLD: usize = 10;

/// Builder configuration.
#[derive(Debug, Clone)]
pub struct TransactionBuilderConfig {
    /// Ring size, between [`MIN_RING_SIZE`] and [`MAX_RING_SIZE`].
    pub ring_size: usize,
    /// Fee rate in satoshis per kilobyte.
    pub fee_per_kb: u64,
}

impl Default for TransactionBuilderConfig {
    fn default() -> Self {
        Self {
            ring_size: DEFAULT_RING_SIZE,
            fee_per_kb: DEFAULT_FEE_PER_KB,
        }
    }
}

/// A payment destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recipient {
    /// Destination stealth address.
    pub address: String,
    /// Amount in satoshis.
    pub amount: u64,
}

impl Recipient {
    /// Build a recipient from an address and amount.
    pub fn new(address: impl Into<String>, amount: u64) -> Self {
        Self {
            address: address.into(),
            amount,
        }
    }
}

/// A completed transaction, ready to broadcast.
#[derive(Debug, Clone)]
pub struct BuildTransactionResult {
    /// Serialized transaction, hex-encoded.
    pub tx_hex: String,
    /// Transaction ID, in display order.
    pub txid: String,
    /// Fee paid, in satoshis.
    pub fee: u64,
    /// Change returned to the sender, in satoshis.
    pub change: u64,
    /// Serialized size, in bytes.
    pub size: usize,
    /// The UTXOs spent.
    pub inputs: Vec<Utxo>,
    /// The outputs created.
    pub outputs: Vec<TxOutput>,
}

/// The result of coin selection.
#[derive(Debug, Clone)]
struct CoinSelection {
    utxos: Vec<Utxo>,
    /// Combined value of the selected UTXOs.
    ///
    /// The builder works from `fee` and `change` directly; this is retained
    /// because it makes the balance invariant
    /// `total_value == target + fee + change` checkable, which the tests assert.
    #[allow(dead_code)]
    total_value: u64,
    fee: u64,
    change: u64,
}

/// A recipient with its derived one-time keys.
#[derive(Debug, Clone)]
struct PreparedRecipient {
    address: String,
    amount: u64,
    ephemeral_pubkey: PublicKey,
    ephemeral_secret: SecretKey,
    dest_pubkey: PublicKey,
}

/// A health assessment of a UTXO set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtxoAnalysis {
    /// Number of UTXOs.
    pub total_utxos: usize,
    /// Combined value, in satoshis.
    pub total_value: u64,
    /// Mean value, in satoshis.
    pub average_value: u64,
    /// Largest single UTXO.
    pub largest_utxo: u64,
    /// Smallest single UTXO.
    pub smallest_utxo: u64,
    /// Whether the set has more UTXOs than [`CONSOLIDATION_THRESHOLD`].
    pub is_fragmented: bool,
    /// Whether the set exceeds [`MAX_ANON_INPUTS`] and so cannot be spent at once.
    pub needs_consolidation: bool,
    /// The most that can be sent in one transaction, after fees.
    pub max_sendable_in_single_tx: u64,
}

/// Whether a UTXO set is healthy enough to spend from comfortably.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletHealth {
    /// The set is compact.
    Healthy,
    /// The set is larger than ideal but still fully spendable.
    Fragmented,
    /// The set exceeds the per-transaction input limit.
    Critical,
}

/// A single transaction within a multi-transaction plan.
#[derive(Debug, Clone)]
pub struct PlannedTransaction {
    /// UTXOs this transaction would spend.
    pub input_utxos: Vec<Utxo>,
    /// Amount it would send.
    pub amount: u64,
    /// Estimated fee.
    pub estimated_fee: u64,
}

/// A plan to send an amount that does not fit in one transaction.
#[derive(Debug, Clone)]
pub struct MultiTransactionPlan {
    /// The transactions to send, in order.
    pub transactions: Vec<PlannedTransaction>,
    /// Combined fees.
    pub total_fees: u64,
}

/// Builds RingCT transactions.
#[derive(Debug, Clone)]
pub struct TransactionBuilder {
    config: TransactionBuilderConfig,
}

impl Default for TransactionBuilder {
    fn default() -> Self {
        Self::new(TransactionBuilderConfig::default())
            .expect("the default configuration is always valid")
    }
}

impl TransactionBuilder {
    /// Create a builder.
    ///
    /// # Errors
    ///
    /// Returns [`VeilError::InvalidInput`] when the ring size is outside
    /// [`MIN_RING_SIZE`]..=[`MAX_RING_SIZE`].
    pub fn new(config: TransactionBuilderConfig) -> Result<Self> {
        if !is_valid_ring_size(config.ring_size) {
            return Err(VeilError::invalid_input(format!(
                "ring size must be between {MIN_RING_SIZE} and {MAX_RING_SIZE}, got {}",
                config.ring_size
            )));
        }

        Ok(Self { config })
    }

    /// The configured ring size.
    pub fn ring_size(&self) -> usize {
        self.config.ring_size
    }

    /// The configured fee rate, in satoshis per kilobyte.
    pub fn fee_per_kb(&self) -> u64 {
        self.config.fee_per_kb
    }

    // ========================================================================
    // Fee and size estimation
    // ========================================================================

    /// Estimate the serialized size of a transaction, in bytes.
    fn estimate_size(&self, num_inputs: usize, num_outputs: usize) -> usize {
        100 // header, counts, and the fee data output
            + num_inputs * (self.config.ring_size * 33 + 100)
            + num_outputs * 156
    }

    /// Estimate the fee for a transaction of the given shape.
    pub fn estimate_fee(&self, num_inputs: usize, num_outputs: usize) -> u64 {
        let size = self.estimate_size(num_inputs, num_outputs) as u64;
        // Round up to the next whole kilobyte.
        size.div_ceil(1000) * self.config.fee_per_kb
    }

    // ========================================================================
    // Building
    // ========================================================================

    /// Build a RingCT transaction.
    ///
    /// `decoys` must supply at least `ring_size - 1` outputs per input, none of
    /// which may be a UTXO being spent. Fetch them with
    /// [`crate::rpc::fetch_decoy_outputs`].
    pub fn build_transaction(
        &self,
        spend_key: &SecretKey,
        scan_key: &SecretKey,
        recipients: &[Recipient],
        available_utxos: &[Utxo],
        decoys: &[AnonOutput],
    ) -> Result<BuildTransactionResult> {
        self.validate_inputs(recipients, available_utxos)?;

        let total_output: u64 = recipients
            .iter()
            .try_fold(0u64, |acc, r| acc.checked_add(r.amount))
            .ok_or_else(|| VeilError::invalid_input("recipient amounts overflow"))?;

        // 1. Choose which UTXOs to spend.
        let selection = self.select_coins(available_utxos, total_output)?;

        // 2. Derive one-time keys for every output, including change.
        let mut prepared = Vec::with_capacity(recipients.len() + 1);
        for recipient in recipients {
            prepared.push(prepare_recipient(recipient)?);
        }

        if selection.change > 0 {
            let change_recipient = self.build_change_recipient(spend_key, scan_key, selection.change)?;
            prepared.push(prepare_recipient(&change_recipient)?);
        }

        // 3. Lay out the transaction.
        let mut tx = Transaction {
            version: 2,
            tx_type: TransactionType::Standard,
            has_witness: true, // RingCT always carries witness data.
            lock_time: 0,
            inputs: Vec::new(),
            outputs: Vec::new(),
            ring_size: self.config.ring_size,
            witness: Vec::new(),
            fee: selection.fee,
        };

        // 4. Add the fee marker and the blinded outputs.
        let fee_commitment = self.add_ct_data(&mut tx, &prepared)?;

        // 5. Build a ring per input.
        let secret_indices = self.add_inputs(&mut tx, &selection.utxos, decoys)?;

        // 6. Publish a key image per input.
        self.insert_key_images(&mut tx, &selection.utxos, spend_key, scan_key)?;

        // 7. Sign each input.
        self.generate_mlsag_signatures(
            &mut tx,
            &selection.utxos,
            decoys,
            spend_key,
            scan_key,
            &secret_indices,
            fee_commitment.as_ref(),
        )?;

        // 8. Collect per-input witnesses for serialization.
        tx.witness = tx
            .inputs
            .iter()
            .map(|input| {
                input
                    .script_witness
                    .clone()
                    .ok_or_else(|| VeilError::Mlsag("input is missing its witness".into()))
            })
            .collect::<Result<Vec<_>>>()?;

        let tx_hex = serialize_transaction(&tx);
        let size = serialize_transaction_bytes(&tx).len();
        let txid = calculate_txid(&tx);

        Ok(BuildTransactionResult {
            tx_hex,
            txid,
            fee: selection.fee,
            change: selection.change,
            size,
            inputs: selection.utxos,
            outputs: tx.outputs,
        })
    }

    /// Build a transaction that merges many UTXOs into one output.
    ///
    /// Consolidation lowers the fees of later sends and lifts the effective
    /// spending cap imposed by [`MAX_ANON_INPUTS`].
    pub fn build_consolidation_transaction(
        &self,
        spend_key: &SecretKey,
        scan_key: &SecretKey,
        utxos: &[Utxo],
        decoys: &[AnonOutput],
        max_inputs: usize,
    ) -> Result<BuildTransactionResult> {
        if utxos.is_empty() {
            return Err(VeilError::invalid_input("no UTXOs to consolidate"));
        }

        if !(1..=MAX_ANON_INPUTS).contains(&max_inputs) {
            return Err(VeilError::invalid_input(format!(
                "max_inputs must be between 1 and {MAX_ANON_INPUTS}, got {max_inputs}"
            )));
        }

        // Prefer the largest UTXOs so the fee is amortized over more value.
        let mut sorted = utxos.to_vec();
        sorted.sort_unstable_by(|a, b| b.amount.cmp(&a.amount));
        sorted.truncate(max_inputs.min(utxos.len()));

        let total_input: u64 = sorted.iter().map(|u| u.amount).sum();

        // A single output, so there is no change.
        let estimated_fee = self.estimate_fee(sorted.len(), 1);

        if total_input <= estimated_fee {
            return Err(VeilError::InsufficientFunds {
                required: estimated_fee,
                available: total_input,
            });
        }

        let spend_pubkey = derive_public_key(spend_key)?;
        let scan_pubkey = derive_public_key(scan_key)?;
        let address = generate_stealth_address(&scan_pubkey, &spend_pubkey, None)?;

        let recipient = Recipient::new(address, total_input - estimated_fee);

        self.build_transaction(spend_key, scan_key, &[recipient], &sorted, decoys)
    }

    // ========================================================================
    // Validation and coin selection
    // ========================================================================

    fn validate_inputs(&self, recipients: &[Recipient], utxos: &[Utxo]) -> Result<()> {
        if recipients.is_empty() {
            return Err(VeilError::invalid_input(
                "a transaction needs at least one recipient",
            ));
        }

        for recipient in recipients {
            if !is_valid_amount(recipient.amount) {
                return Err(VeilError::invalid_input(format!(
                    "invalid amount: {}",
                    recipient.amount
                )));
            }
        }

        if utxos.is_empty() {
            return Err(VeilError::invalid_input("no UTXOs available to spend"));
        }

        for (i, utxo) in utxos.iter().enumerate() {
            if utxo.amount == 0 {
                return Err(VeilError::invalid_input(format!(
                    "UTXO {i} has no amount, so its blind cannot be verified"
                )));
            }
            if utxo.ringct_index.is_none() {
                return Err(VeilError::invalid_input(format!(
                    "UTXO {i} is missing its ringct_index, which is required to build a ring"
                )));
            }
        }

        Ok(())
    }

    /// Select UTXOs to cover `target_amount` plus fees.
    ///
    /// UTXOs are shuffled first, matching Veil Core's behavior in
    /// `anonwallet.cpp:6455`: unpredictable selection avoids leaking a pattern
    /// that would link transactions.
    fn select_coins(&self, utxos: &[Utxo], target_amount: u64) -> Result<CoinSelection> {
        let mut shuffled = utxos.to_vec();
        crate::utils::shuffle(&mut shuffled);

        let mut selected: Vec<Utxo> = Vec::new();
        let mut total_value: u64 = 0;

        for utxo in shuffled {
            if selected.len() >= MAX_ANON_INPUTS {
                break;
            }

            total_value = total_value.saturating_add(utxo.amount);
            selected.push(utxo);

            // Two outputs: the recipient and the change.
            let fee = self.estimate_fee(selected.len(), 2);

            if let Some(required) = target_amount.checked_add(fee) {
                if total_value >= required {
                    return Ok(CoinSelection {
                        total_value,
                        fee,
                        change: total_value - required,
                        utxos: selected,
                    });
                }
            }
        }

        let fee = self.estimate_fee(selected.len().max(1), 2);
        Err(VeilError::InsufficientFunds {
            required: target_amount.saturating_add(fee),
            available: total_value,
        })
    }

    /// Build a recipient that returns change to the sender's own address.
    fn build_change_recipient(
        &self,
        spend_key: &SecretKey,
        scan_key: &SecretKey,
        change_amount: u64,
    ) -> Result<Recipient> {
        let spend_pubkey = derive_public_key(spend_key)?;
        let scan_pubkey = derive_public_key(scan_key)?;
        let address = generate_stealth_address(&scan_pubkey, &spend_pubkey, None)?;

        Ok(Recipient::new(address, change_amount))
    }

    // ========================================================================
    // Outputs
    // ========================================================================

    /// Add the fee marker and one blinded RingCT output per recipient.
    ///
    /// Returns the fee commitment, which the MLSAG must include so the daemon's
    /// balance check succeeds.
    fn add_ct_data(
        &self,
        tx: &mut Transaction,
        recipients: &[PreparedRecipient],
    ) -> Result<Option<(Commitment, Blind)>> {
        tx.outputs.clear();

        let mut fee_commitment = None;

        if tx.fee > 0 {
            // The protocol carries the fee in a data output, LEB128-encoded.
            let mut v_data = Vec::with_capacity(9);
            v_data.push(DataOutputType::Fee as u8);
            v_data.extend_from_slice(&encode_leb128(tx.fee));

            tx.outputs.push(TxOutput::Data { v_data });

            // The fee also needs a commitment so the Pedersen sums balance. The
            // blind must be zero: the daemon verifies against a zero blind in
            // `anon.cpp:38`.
            let fee_blind: Blind = [0u8; 32];
            fee_commitment = Some((create_commitment(tx.fee, &fee_blind)?, fee_blind));
        }

        // Every output gets a random blind. The balance is reconciled by
        // prepare_mlsag, which derives the blind sum as the commitment row's
        // secret key, so no output needs a computed blind here.
        for recipient in recipients {
            let blind = crate::crypto::generate_blind();
            let commitment = create_commitment(recipient.amount, &blind)?;

            // The rewind nonce is the double-hashed ECDH result; see
            // `anonwallet.cpp:1602`.
            let nonce = ecdh_nonce(&recipient.dest_pubkey, &recipient.ephemeral_secret)?;

            let params = select_range_proof_parameters(recipient.amount);
            if !validate_range_proof_params(&params) {
                return Err(VeilError::invalid_input(format!(
                    "range proof parameters {params:?} are invalid for amount {}",
                    recipient.amount
                )));
            }

            let range_proof = generate_range_proof(&crate::crypto::RangeProofParams {
                commitment: &commitment,
                value: recipient.amount,
                blind: &blind,
                nonce: &nonce,
                message: None,
                min_value: params.min_value,
                exp: params.exponent,
                min_bits: params.min_bits,
            })?;

            tx.outputs.push(TxOutput::RingCt {
                pk: recipient.dest_pubkey,
                commitment,
                // RingCT vData is the bare ephemeral pubkey, with no prefix.
                v_data: recipient.ephemeral_pubkey.to_vec(),
                v_rangeproof: range_proof.proof,
                amount: recipient.amount,
                blind: Some(blind),
                address: recipient.address.clone(),
            });
        }

        Ok(fee_commitment)
    }

    // ========================================================================
    // Inputs
    // ========================================================================

    /// Build one ring per input and return each input's secret index.
    ///
    /// Every input gets an independently chosen secret index, matching
    /// `lightwallet.cpp:1476`. Reusing one position across inputs would leak
    /// which ring member is real.
    fn add_inputs(
        &self,
        tx: &mut Transaction,
        real_utxos: &[Utxo],
        decoys: &[AnonOutput],
    ) -> Result<Vec<usize>> {
        tx.inputs.clear();

        let ring_size = self.config.ring_size;
        let mut secret_indices = Vec::with_capacity(real_utxos.len());

        // Track consumed decoys so no output appears in two rings.
        let mut used_decoy_indices: std::collections::HashSet<u64> = std::collections::HashSet::new();

        for real_utxo in real_utxos {
            let secret_index = rand::Rng::gen_range(&mut rand::thread_rng(), 0..ring_size);
            secret_indices.push(secret_index);

            let chosen = self.select_decoys(decoys, ring_size - 1, &used_decoy_indices, real_utxos)?;
            for decoy in &chosen {
                used_decoy_indices.insert(decoy.index);
            }

            let ringct_index = real_utxo.ringct_index.ok_or_else(|| {
                VeilError::invalid_input("real UTXO is missing its ringct_index")
            })?;

            // Place the real key at the secret index and the decoys around it,
            // keeping decoy order so ring[i] and ring_indices[i] stay aligned.
            let mut ring = Vec::with_capacity(ring_size);
            let mut ring_indices = Vec::with_capacity(ring_size);
            let mut decoy_cursor = 0;

            for col in 0..ring_size {
                if col == secret_index {
                    ring.push(real_utxo.pubkey);
                    ring_indices.push(ringct_index);
                } else {
                    ring.push(chosen[decoy_cursor].pubkey);
                    ring_indices.push(chosen[decoy_cursor].index);
                    decoy_cursor += 1;
                }
            }

            tx.inputs.push(crate::types::TxInput {
                ring,
                key_image: [0u8; 33], // Filled in by insert_key_images.
                secret_index,
                prevout: OutPoint {
                    // RingCT reuses the prevout hash to carry nInputs and
                    // nRingSize; there is one UTXO per input here.
                    hash: encode_anon_prevout_hash(1, ring_size as u32),
                    n: ANON_MARKER,
                },
                script_sig: Vec::new(),
                sequence: 0xffff_ffff,
                script_data: Some(ScriptStack::default()),
                script_witness: None,
                ring_indices,
            });
        }

        Ok(secret_indices)
    }

    /// Choose `count` decoys, excluding spent UTXOs and already-used decoys.
    ///
    /// A UTXO being spent must never appear as its own decoy, and no decoy may
    /// be reused across rings: either would narrow the anonymity set.
    fn select_decoys(
        &self,
        decoys: &[AnonOutput],
        count: usize,
        used_decoy_indices: &std::collections::HashSet<u64>,
        real_utxos: &[Utxo],
    ) -> Result<Vec<AnonOutput>> {
        let real_pubkeys: std::collections::HashSet<PublicKey> =
            real_utxos.iter().map(|u| u.pubkey).collect();

        let available: Vec<AnonOutput> = decoys
            .iter()
            .filter(|d| !real_pubkeys.contains(&d.pubkey))
            .filter(|d| !used_decoy_indices.contains(&d.index))
            .cloned()
            .collect();

        if available.len() < count {
            return Err(VeilError::invalid_input(format!(
                "not enough decoys: need {count}, have {} after excluding {} spent outputs and {} already-used decoys",
                available.len(),
                real_pubkeys.len(),
                used_decoy_indices.len()
            )));
        }

        random_sample(&available, count)
    }

    /// Compute and publish a key image for each input.
    ///
    /// The key image must come from the output's one-time destination key, not
    /// the wallet's spend key, or the daemon will reject it.
    fn insert_key_images(
        &self,
        tx: &mut Transaction,
        utxos: &[Utxo],
        spend_key: &SecretKey,
        scan_key: &SecretKey,
    ) -> Result<()> {
        for (i, input) in tx.inputs.iter_mut().enumerate() {
            let utxo = utxos
                .get(i)
                .ok_or_else(|| VeilError::invalid_input("input count exceeds UTXO count"))?;

            let destination_key =
                derive_destination_key(spend_key, scan_key, &utxo.ephemeral_pubkey)?;

            let key_image = generate_key_image(&utxo.pubkey, &destination_key)?;

            input.key_image = key_image;
            input
                .script_data
                .get_or_insert_with(ScriptStack::default)
                .stack
                .push(key_image.to_vec());
        }

        Ok(())
    }

    // ========================================================================
    // Signing
    // ========================================================================

    /// Sign every input, producing one MLSAG per input.
    #[allow(clippy::too_many_arguments)]
    fn generate_mlsag_signatures(
        &self,
        tx: &mut Transaction,
        utxos: &[Utxo],
        decoys: &[AnonOutput],
        spend_key: &SecretKey,
        scan_key: &SecretKey,
        secret_indices: &[usize],
        fee_commitment: Option<&(Commitment, Blind)>,
    ) -> Result<()> {
        let num_inputs = tx.inputs.len();

        if num_inputs == 1 {
            // With one input the MLSAG covers every output commitment directly.
            let witness = self.sign_single_input(
                tx,
                0,
                &utxos[0],
                decoys,
                spend_key,
                scan_key,
                secret_indices[0],
                fee_commitment,
            )?;
            tx.inputs[0].script_witness = Some(witness);
        } else {
            self.sign_multiple_inputs(
                tx,
                utxos,
                decoys,
                spend_key,
                scan_key,
                secret_indices,
                fee_commitment,
            )?;
        }

        Ok(())
    }

    /// Sign the sole input of a single-input transaction.
    #[allow(clippy::too_many_arguments)]
    fn sign_single_input(
        &self,
        tx: &Transaction,
        input_index: usize,
        utxo: &Utxo,
        decoys: &[AnonOutput],
        spend_key: &SecretKey,
        scan_key: &SecretKey,
        secret_index: usize,
        fee_commitment: Option<&(Commitment, Blind)>,
    ) -> Result<ScriptStack> {
        let input = &tx.inputs[input_index];
        let ring_size = input.ring.len();
        let n_rows = 2; // one input row plus the commitment row

        // Row 0 of the matrix holds the ring public keys, in row-major order.
        let mut m = vec![0u8; ring_size * n_rows * 33];
        for (col, pk) in input.ring.iter().enumerate() {
            let offset = col * 33;
            m[offset..offset + 33].copy_from_slice(pk);
        }

        let in_commits = collect_ring_commitments(&input.ring, utxo, decoys)?;

        // The daemon adds the fee commitment before the output commitments
        // (`anon.cpp:96`), so the order here must match.
        let mut out_commits = Vec::new();
        let mut blinds = vec![utxo.blind];

        if let Some((commitment, blind)) = fee_commitment {
            out_commits.push(*commitment);
            blinds.push(*blind);
        }

        for output in &tx.outputs {
            if let Some(commitment) = output.commitment() {
                out_commits.push(*commitment);
                if let Some(blind) = output.blind() {
                    blinds.push(*blind);
                }
            }
        }

        // The daemon passes out_commits.len() for both nOuts and nBlinded
        // (`anon.cpp:154`), counting the fee commitment among the blinded set.
        let prepared = prepare_mlsag(&PrepareMlsagParams {
            m: &m,
            n_outs: out_commits.len(),
            n_blinded: out_commits.len(),
            n_cols: ring_size,
            n_rows,
            in_commits: &in_commits,
            out_commits: &out_commits,
            blinds: &blinds,
        })?;

        let destination_key = derive_destination_key(spend_key, scan_key, &utxo.ephemeral_pubkey)?;

        // A mismatch here means the ring would be signed with the wrong key,
        // so fail loudly rather than emit an invalid signature.
        if derive_public_key(&destination_key)? != utxo.pubkey {
            return Err(VeilError::Mlsag(format!(
                "derived destination key does not match the UTXO public key for input {input_index}"
            )));
        }

        let secret_keys = [destination_key, prepared.sk];
        let preimage = calculate_transaction_hash(&tx.outputs);
        let nonce = random_32();

        let signature = generate_mlsag(&GenerateMlsagParams {
            nonce: &nonce,
            preimage: &preimage,
            n_cols: ring_size,
            n_rows,
            index: secret_index,
            secret_keys: &secret_keys,
            public_keys: &prepared.m,
        })?;

        let valid = verify_mlsag(&VerifyMlsagParams {
            preimage: &preimage,
            n_cols: ring_size,
            n_rows,
            public_keys: &prepared.m,
            key_images: &signature.key_images,
            pc: &signature.pc,
            ps: &signature.ps,
        })?;

        if !valid {
            return Err(VeilError::Mlsag(format!(
                "MLSAG verification failed for input {input_index}"
            )));
        }

        // The witness carries the ring indices and the signature.
        let mut v_dl = Vec::with_capacity(signature.pc.len() + signature.ps.len());
        v_dl.extend_from_slice(&signature.pc);
        v_dl.extend_from_slice(&signature.ps);

        Ok(ScriptStack {
            stack: vec![encode_ring_indices(&input.ring_indices), v_dl],
        })
    }

    /// Sign each input of a multi-input transaction with a split commitment.
    ///
    /// Each input commits only to the value it contributes, and the last input's
    /// blind is chosen so the split commitments balance the outputs plus fee.
    #[allow(clippy::too_many_arguments)]
    fn sign_multiple_inputs(
        &self,
        tx: &mut Transaction,
        utxos: &[Utxo],
        decoys: &[AnonOutput],
        spend_key: &SecretKey,
        scan_key: &SecretKey,
        secret_indices: &[usize],
        fee_commitment: Option<&(Commitment, Blind)>,
    ) -> Result<()> {
        let num_inputs = tx.inputs.len();

        // Gather the blinds the split commitments must balance against.
        let mut output_blinds: Vec<Blind> = Vec::new();
        if let Some((_, blind)) = fee_commitment {
            output_blinds.push(*blind);
        }
        for output in &tx.outputs {
            if let Some(blind) = output.blind() {
                output_blinds.push(*blind);
            }
        }

        let mut split_blinds: Vec<Blind> = Vec::with_capacity(num_inputs);
        for i in 0..num_inputs {
            if i == num_inputs - 1 {
                // The final blind balances the equation:
                // sum(split) = sum(outputs) + fee.
                let mut all_blinds = output_blinds.clone();
                all_blinds.extend_from_slice(&split_blinds);
                split_blinds.push(sum_blinds(&all_blinds, output_blinds.len())?);
            } else {
                split_blinds.push(crate::crypto::generate_blind());
            }
        }

        let preimage = calculate_transaction_hash(&tx.outputs);

        let mut witnesses = Vec::with_capacity(num_inputs);

        for i in 0..num_inputs {
            let utxo = &utxos[i];
            let input = &tx.inputs[i];
            let ring_size = input.ring.len();
            let n_rows = 2;

            let split_commitment = create_commitment(utxo.amount, &split_blinds[i])?;

            let mut m = vec![0u8; ring_size * n_rows * 33];
            for (col, pk) in input.ring.iter().enumerate() {
                let offset = col * 33;
                m[offset..offset + 33].copy_from_slice(pk);
            }

            let in_commits = collect_ring_commitments(&input.ring, utxo, decoys)?;

            // Each input's MLSAG sees only its own split commitment.
            let out_commits = [split_commitment];
            let blinds = [utxo.blind, split_blinds[i]];

            let prepared = prepare_mlsag(&PrepareMlsagParams {
                m: &m,
                n_outs: 1,
                n_blinded: 1,
                n_cols: ring_size,
                n_rows,
                in_commits: &in_commits,
                out_commits: &out_commits,
                blinds: &blinds,
            })?;

            let destination_key =
                derive_destination_key(spend_key, scan_key, &utxo.ephemeral_pubkey)?;

            if derive_public_key(&destination_key)? != utxo.pubkey {
                return Err(VeilError::Mlsag(format!(
                    "derived destination key does not match the UTXO public key for input {i}"
                )));
            }

            let secret_keys = [destination_key, prepared.sk];
            let nonce = random_32();

            let signature = generate_mlsag(&GenerateMlsagParams {
                nonce: &nonce,
                preimage: &preimage,
                n_cols: ring_size,
                n_rows,
                index: secret_indices[i],
                secret_keys: &secret_keys,
                public_keys: &prepared.m,
            })?;

            let valid = verify_mlsag(&VerifyMlsagParams {
                preimage: &preimage,
                n_cols: ring_size,
                n_rows,
                public_keys: &prepared.m,
                key_images: &signature.key_images,
                pc: &signature.pc,
                ps: &signature.ps,
            })?;

            if !valid {
                return Err(VeilError::Mlsag(format!(
                    "MLSAG verification failed for input {i}"
                )));
            }

            // Multi-input witnesses append the split commitment so the daemon
            // can reconstruct the balance.
            let mut v_dl =
                Vec::with_capacity(signature.pc.len() + signature.ps.len() + 33);
            v_dl.extend_from_slice(&signature.pc);
            v_dl.extend_from_slice(&signature.ps);
            v_dl.extend_from_slice(&split_commitment);

            witnesses.push(ScriptStack {
                stack: vec![encode_ring_indices(&input.ring_indices), v_dl],
            });
        }

        for (input, witness) in tx.inputs.iter_mut().zip(witnesses) {
            input.script_witness = Some(witness);
        }

        Ok(())
    }

    // ========================================================================
    // UTXO analysis
    // ========================================================================

    /// Summarize a UTXO set's size, value, and spendability.
    pub fn analyze_utxos(&self, utxos: &[Utxo]) -> UtxoAnalysis {
        if utxos.is_empty() {
            return UtxoAnalysis {
                total_utxos: 0,
                total_value: 0,
                average_value: 0,
                largest_utxo: 0,
                smallest_utxo: 0,
                is_fragmented: false,
                needs_consolidation: false,
                max_sendable_in_single_tx: 0,
            };
        }

        let total_value: u64 = utxos.iter().map(|u| u.amount).sum();
        let average_value = total_value / utxos.len() as u64;

        let mut sorted: Vec<u64> = utxos.iter().map(|u| u.amount).collect();
        sorted.sort_unstable_by(|a, b| b.cmp(a));

        let take = MAX_ANON_INPUTS.min(sorted.len());
        let max_with_input_cap: u64 = sorted[..take].iter().sum();
        let estimated_fee = self.estimate_fee(take, 2);

        UtxoAnalysis {
            total_utxos: utxos.len(),
            total_value,
            average_value,
            largest_utxo: sorted[0],
            smallest_utxo: sorted[sorted.len() - 1],
            is_fragmented: utxos.len() > CONSOLIDATION_THRESHOLD,
            needs_consolidation: utxos.len() > MAX_ANON_INPUTS,
            max_sendable_in_single_tx: max_with_input_cap.saturating_sub(estimated_fee),
        }
    }

    /// Classify a UTXO set's health.
    pub fn wallet_health(&self, utxos: &[Utxo]) -> WalletHealth {
        let analysis = self.analyze_utxos(utxos);

        if analysis.needs_consolidation {
            WalletHealth::Critical
        } else if analysis.is_fragmented {
            WalletHealth::Fragmented
        } else {
            WalletHealth::Healthy
        }
    }

    /// Determine whether `amount` can be sent in one transaction.
    ///
    /// Returns the number of inputs required on success.
    pub fn can_send_in_single_transaction(&self, utxos: &[Utxo], amount: u64) -> Option<usize> {
        let mut sorted: Vec<u64> = utxos.iter().map(|u| u.amount).collect();
        sorted.sort_unstable_by(|a, b| b.cmp(a));

        let mut total_value: u64 = 0;

        for (i, value) in sorted.iter().take(MAX_ANON_INPUTS).enumerate() {
            total_value = total_value.saturating_add(*value);
            let input_count = i + 1;
            let fee = self.estimate_fee(input_count, 2);

            if total_value >= amount.saturating_add(fee) {
                return Some(input_count);
            }
        }

        None
    }

    /// Split a send that exceeds the input cap into a sequence of transactions.
    pub fn plan_multi_transaction(
        &self,
        utxos: &[Utxo],
        total_amount: u64,
    ) -> Result<MultiTransactionPlan> {
        let analysis = self.analyze_utxos(utxos);

        if total_amount > analysis.total_value {
            return Err(VeilError::InsufficientFunds {
                required: total_amount,
                available: analysis.total_value,
            });
        }

        let mut sorted = utxos.to_vec();
        sorted.sort_unstable_by(|a, b| b.amount.cmp(&a.amount));

        let mut transactions = Vec::new();
        let mut total_fees: u64 = 0;
        let mut remaining = total_amount;
        let mut cursor = 0;

        while remaining > 0 && cursor < sorted.len() {
            let end = (cursor + MAX_ANON_INPUTS).min(sorted.len());
            let batch = sorted[cursor..end].to_vec();
            cursor = end;

            let batch_value: u64 = batch.iter().map(|u| u.amount).sum();
            let estimated_fee = self.estimate_fee(batch.len(), 2);

            if batch_value <= estimated_fee {
                return Err(VeilError::invalid_input(
                    "the remaining UTXOs are too small to cover their own fees",
                ));
            }

            let sendable = batch_value - estimated_fee;
            let amount = remaining.min(sendable);

            transactions.push(PlannedTransaction {
                input_utxos: batch,
                amount,
                estimated_fee,
            });

            total_fees = total_fees.saturating_add(estimated_fee);
            remaining -= amount;
        }

        if remaining > 0 {
            return Err(VeilError::InsufficientFunds {
                required: total_amount,
                available: total_amount - remaining,
            });
        }

        Ok(MultiTransactionPlan {
            transactions,
            total_fees,
        })
    }

    /// A human-readable summary of a UTXO set's health.
    pub fn describe_health(&self, utxos: &[Utxo]) -> String {
        let analysis = self.analyze_utxos(utxos);

        match self.wallet_health(utxos) {
            WalletHealth::Critical => format!(
                "{} UTXOs exceeds the {MAX_ANON_INPUTS}-input limit; only {} VEIL can be sent at once. Consolidate first.",
                analysis.total_utxos,
                satoshis_to_veil(analysis.max_sendable_in_single_tx)
            ),
            WalletHealth::Fragmented => format!(
                "{} UTXOs is more than ideal. Consider consolidating when fees are low.",
                analysis.total_utxos
            ),
            WalletHealth::Healthy => format!("{} UTXOs; the set is healthy.", analysis.total_utxos),
        }
    }
}

// ============================================================================
// Free functions
// ============================================================================

/// Derive the one-time secret key for an output paid to this wallet.
///
/// Computes `spend_key + SHA256(scan_key * ephemeral_pubkey)`, matching the
/// Dart implementation's `getDestinationKeyForOutput`. The point is multiplied
/// and hashed explicitly here rather than via `ecdh_veil` so the derivation
/// stays visible at the call site.
pub fn derive_destination_key(
    spend_key: &SecretKey,
    scan_key: &SecretKey,
    ephemeral_pubkey: &PublicKey,
) -> Result<SecretKey> {
    let shared_point = point_multiply(ephemeral_pubkey, scan_key)?;
    let shared = sha256(&shared_point);
    private_add(spend_key, &shared)
}

/// Derive one-time keys for a recipient's stealth address.
fn prepare_recipient(recipient: &Recipient) -> Result<PreparedRecipient> {
    let ephemeral = generate_ephemeral_keys(&recipient.address)?;

    Ok(PreparedRecipient {
        address: recipient.address.clone(),
        amount: recipient.amount,
        ephemeral_pubkey: ephemeral.ephemeral_pubkey,
        ephemeral_secret: ephemeral.ephemeral_secret,
        dest_pubkey: ephemeral.dest_pubkey,
    })
}

/// Collect the commitment for every ring member.
///
/// The real UTXO supplies its own commitment; the rest are matched by public key
/// against the decoy set.
fn collect_ring_commitments(
    ring: &[PublicKey],
    utxo: &Utxo,
    decoys: &[AnonOutput],
) -> Result<Vec<Commitment>> {
    ring.iter()
        .enumerate()
        .map(|(col, pubkey)| {
            if *pubkey == utxo.pubkey {
                return Ok(utxo.commitment);
            }

            decoys
                .iter()
                .find(|d| d.pubkey == *pubkey)
                .map(|d| d.commitment)
                .ok_or_else(|| {
                    VeilError::invalid_input(format!(
                        "no commitment found for the ring member at position {col}"
                    ))
                })
        })
        .collect()
}

/// LEB128-encode the ring member indices for the witness stack.
///
/// Matches `PutVarInt(vPubkeyMatrixIndices, ...)` in `lightwallet.cpp:1536`.
fn encode_ring_indices(indices: &[u64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(indices.len() * 2);
    for index in indices {
        out.extend_from_slice(&encode_leb128(*index));
    }
    out
}

/// Compute the MLSAG preimage by folding the output hashes together.
///
/// Matches the Dart `CMutableTransaction.getOutputsHash`: for each output, hash
/// its body twice, concatenate that with the running hash, then hash twice
/// again. Outputs are serialized without their type byte.
pub fn calculate_transaction_hash(outputs: &[TxOutput]) -> [u8; 32] {
    let mut hash_outputs = [0u8; 32];

    for output in outputs {
        let serialized = serialize_output_data(output);
        let output_hash = sha256(&sha256(&serialized));

        let mut combined = Vec::with_capacity(64);
        combined.extend_from_slice(&output_hash);
        combined.extend_from_slice(&hash_outputs);

        hash_outputs = sha256(&sha256(&combined));
    }

    hash_outputs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{generate_range_proof, point_add_scalar, RangeProofParams};
    use crate::stealth::{restore_wallet, VeilWallet};

    fn wallet() -> VeilWallet {
        restore_wallet(&[0x11u8; 32], &[0x22u8; 32]).unwrap()
    }

    /// Build a UTXO the test wallet can actually spend, deriving the same
    /// destination key the builder will recompute.
    fn owned_utxo(amount: u64, ringct_index: u64, ephemeral_seed: u8) -> Utxo {
        let w = wallet();
        let ephemeral_secret = [ephemeral_seed; 32];
        let ephemeral_pubkey = derive_public_key(&ephemeral_secret).unwrap();

        // The builder derives the destination key as
        // spend + SHA256(scan * ephemeral_pubkey), so mirror that here.
        let shared_point = point_multiply(&ephemeral_pubkey, &w.scan_secret).unwrap();
        let shared = sha256(&shared_point);
        let dest_pubkey = point_add_scalar(&w.spend_pubkey, &shared).unwrap();

        let blind = [0xAB ^ ephemeral_seed; 32];
        let commitment = create_commitment(amount, &blind).unwrap();

        Utxo {
            txid: hex::encode([ephemeral_seed; 32]),
            vout: 0,
            amount,
            commitment,
            blind,
            pubkey: dest_pubkey,
            ephemeral_pubkey,
            block_height: 1,
            spendable: true,
            ringct_index: Some(ringct_index),
        }
    }

    /// Build decoys with valid commitments and distinct public keys.
    fn decoys(count: usize, start_index: u64) -> Vec<AnonOutput> {
        (0..count)
            .map(|i| {
                // Vary a single byte per decoy so every key is distinct. An
                // earlier version OR'd in the low bit, which collided even and
                // odd seeds onto the same key.
                let mut secret = [0x40u8; 32];
                secret[31] = (i as u8).wrapping_add(1);
                let pubkey = derive_public_key(&secret).unwrap();

                let mut blind = [0x80u8; 32];
                blind[31] = (i as u8).wrapping_add(1);
                let commitment = create_commitment(1_000 + i as u64, &blind).unwrap();

                AnonOutput {
                    pubkey,
                    commitment,
                    index: start_index + i as u64,
                    txid: None,
                    vout: None,
                }
            })
            .collect()
    }

    #[test]
    fn rejects_an_out_of_range_ring_size() {
        for ring_size in [0, 1, 2, 33, 100] {
            assert!(TransactionBuilder::new(TransactionBuilderConfig {
                ring_size,
                fee_per_kb: DEFAULT_FEE_PER_KB,
            })
            .is_err());
        }
    }

    #[test]
    fn accepts_ring_sizes_within_limits() {
        for ring_size in [MIN_RING_SIZE, DEFAULT_RING_SIZE, MAX_RING_SIZE] {
            let builder = TransactionBuilder::new(TransactionBuilderConfig {
                ring_size,
                fee_per_kb: DEFAULT_FEE_PER_KB,
            })
            .unwrap();
            assert_eq!(builder.ring_size(), ring_size);
        }
    }

    #[test]
    fn fee_grows_with_inputs_and_outputs() {
        let builder = TransactionBuilder::default();
        let small = builder.estimate_fee(1, 2);
        let more_inputs = builder.estimate_fee(4, 2);
        let more_outputs = builder.estimate_fee(1, 8);

        assert!(more_inputs > small);
        assert!(more_outputs > small);
        assert_eq!(small % DEFAULT_FEE_PER_KB, 0);
    }

    #[test]
    fn validation_rejects_empty_recipients_and_utxos() {
        let builder = TransactionBuilder::default();
        let utxo = owned_utxo(100_000_000, 1, 0x33);
        let recipient = Recipient::new(wallet().stealth_address, 1_000);

        assert!(builder
            .validate_inputs(&[], std::slice::from_ref(&utxo))
            .is_err());
        assert!(builder
            .validate_inputs(std::slice::from_ref(&recipient), &[])
            .is_err());
        assert!(builder.validate_inputs(&[recipient], &[utxo]).is_ok());
    }

    #[test]
    fn validation_rejects_a_zero_amount_recipient() {
        let builder = TransactionBuilder::default();
        let utxo = owned_utxo(100_000_000, 1, 0x33);
        let recipient = Recipient::new(wallet().stealth_address, 0);

        assert!(builder.validate_inputs(&[recipient], &[utxo]).is_err());
    }

    #[test]
    fn validation_requires_a_ringct_index() {
        let builder = TransactionBuilder::default();
        let mut utxo = owned_utxo(100_000_000, 1, 0x33);
        utxo.ringct_index = None;

        let recipient = Recipient::new(wallet().stealth_address, 1_000);
        assert!(builder.validate_inputs(&[recipient], &[utxo]).is_err());
    }

    #[test]
    fn coin_selection_covers_the_target_plus_fee() {
        let builder = TransactionBuilder::default();
        let utxos = vec![
            owned_utxo(100_000_000, 1, 0x33),
            owned_utxo(200_000_000, 2, 0x34),
        ];

        let selection = builder.select_coins(&utxos, 50_000_000).unwrap();

        assert!(selection.total_value >= 50_000_000 + selection.fee);
        assert_eq!(
            selection.total_value,
            50_000_000 + selection.fee + selection.change
        );
    }

    #[test]
    fn coin_selection_reports_insufficient_funds() {
        let builder = TransactionBuilder::default();
        let utxos = vec![owned_utxo(1_000, 1, 0x33)];

        match builder.select_coins(&utxos, 100_000_000) {
            Err(VeilError::InsufficientFunds {
                required,
                available,
            }) => {
                assert!(required > available);
                assert_eq!(available, 1_000);
            }
            other => panic!("expected InsufficientFunds, got {other:?}"),
        }
    }

    #[test]
    fn coin_selection_respects_the_input_cap() {
        let builder = TransactionBuilder::default();
        // Many tiny UTXOs cannot fund a large send within 32 inputs.
        let utxos: Vec<Utxo> = (0..40)
            .map(|i| owned_utxo(10_000, i as u64, (i as u8) | 1))
            .collect();

        assert!(builder.select_coins(&utxos, 10_000_000_000).is_err());
    }

    #[test]
    fn decoy_selection_excludes_spent_outputs() {
        let builder = TransactionBuilder::default();
        let utxo = owned_utxo(100_000_000, 1, 0x33);

        // Offer the real UTXO's own key as a decoy; it must be filtered out.
        let mut available = decoys(10, 100);
        available.push(AnonOutput {
            pubkey: utxo.pubkey,
            commitment: utxo.commitment,
            index: 999,
            txid: None,
            vout: None,
        });

        let used = std::collections::HashSet::new();
        let chosen = builder
            .select_decoys(&available, 10, &used, std::slice::from_ref(&utxo))
            .unwrap();

        assert_eq!(chosen.len(), 10);
        assert!(chosen.iter().all(|d| d.pubkey != utxo.pubkey));
    }

    #[test]
    fn decoy_selection_excludes_already_used_decoys() {
        let builder = TransactionBuilder::default();
        let utxo = owned_utxo(100_000_000, 1, 0x33);
        let available = decoys(10, 100);

        let mut used = std::collections::HashSet::new();
        used.insert(100);
        used.insert(101);

        let chosen = builder
            .select_decoys(&available, 8, &used, std::slice::from_ref(&utxo))
            .unwrap();

        assert_eq!(chosen.len(), 8);
        assert!(chosen.iter().all(|d| d.index != 100 && d.index != 101));
    }

    #[test]
    fn decoy_selection_fails_when_there_are_too_few() {
        let builder = TransactionBuilder::default();
        let utxo = owned_utxo(100_000_000, 1, 0x33);
        let available = decoys(3, 100);
        let used = std::collections::HashSet::new();

        assert!(builder
            .select_decoys(&available, 10, &used, std::slice::from_ref(&utxo))
            .is_err());
    }

    #[test]
    fn destination_key_derivation_reproduces_the_utxo_pubkey() {
        let w = wallet();
        let utxo = owned_utxo(100_000_000, 1, 0x33);

        let destination_key =
            derive_destination_key(&w.spend_secret, &w.scan_secret, &utxo.ephemeral_pubkey)
                .unwrap();

        assert_eq!(derive_public_key(&destination_key).unwrap(), utxo.pubkey);
    }

    #[test]
    fn transaction_hash_is_order_dependent_and_stable() {
        let a = TxOutput::Data {
            v_data: vec![0x06, 0x01],
        };
        let b = TxOutput::Data {
            v_data: vec![0x06, 0x02],
        };

        let forward = calculate_transaction_hash(&[a.clone(), b.clone()]);
        let reverse = calculate_transaction_hash(&[b, a.clone()]);

        assert_ne!(forward, reverse);
        assert_eq!(forward, calculate_transaction_hash(&[a.clone(), {
            TxOutput::Data {
                v_data: vec![0x06, 0x02],
            }
        }]));

        // An empty output set folds to zero.
        assert_eq!(calculate_transaction_hash(&[]), [0u8; 32]);
    }

    #[test]
    fn ring_indices_encode_as_concatenated_leb128() {
        let encoded = encode_ring_indices(&[0, 127, 128, 253_687]);

        let mut expected = Vec::new();
        expected.extend_from_slice(&[0x00]);
        expected.extend_from_slice(&[0x7f]);
        expected.extend_from_slice(&[0x80, 0x01]);
        expected.extend_from_slice(&[0xf7, 0xbd, 0x0f]);

        assert_eq!(encoded, expected);
    }

    #[test]
    fn ring_commitments_match_real_and_decoy_members() {
        let utxo = owned_utxo(100_000_000, 1, 0x33);
        let available = decoys(2, 100);

        let ring = vec![available[0].pubkey, utxo.pubkey, available[1].pubkey];
        let commitments = collect_ring_commitments(&ring, &utxo, &available).unwrap();

        assert_eq!(commitments[0], available[0].commitment);
        assert_eq!(commitments[1], utxo.commitment);
        assert_eq!(commitments[2], available[1].commitment);
    }

    #[test]
    fn ring_commitments_fail_on_an_unknown_member() {
        let utxo = owned_utxo(100_000_000, 1, 0x33);
        let available = decoys(2, 100);
        let stranger = derive_public_key(&[0x5Au8; 32]).unwrap();

        let ring = vec![utxo.pubkey, stranger];
        assert!(collect_ring_commitments(&ring, &utxo, &available).is_err());
    }

    #[test]
    fn analysis_of_an_empty_set_is_all_zero() {
        let builder = TransactionBuilder::default();
        let analysis = builder.analyze_utxos(&[]);

        assert_eq!(analysis.total_utxos, 0);
        assert_eq!(analysis.total_value, 0);
        assert_eq!(analysis.max_sendable_in_single_tx, 0);
        assert!(!analysis.is_fragmented);
        assert!(!analysis.needs_consolidation);
        assert_eq!(builder.wallet_health(&[]), WalletHealth::Healthy);
    }

    #[test]
    fn analysis_reports_totals_and_extremes() {
        let builder = TransactionBuilder::default();
        let utxos = vec![
            owned_utxo(100_000_000, 1, 0x33),
            owned_utxo(300_000_000, 2, 0x34),
            owned_utxo(200_000_000, 3, 0x35),
        ];

        let analysis = builder.analyze_utxos(&utxos);

        assert_eq!(analysis.total_utxos, 3);
        assert_eq!(analysis.total_value, 600_000_000);
        assert_eq!(analysis.average_value, 200_000_000);
        assert_eq!(analysis.largest_utxo, 300_000_000);
        assert_eq!(analysis.smallest_utxo, 100_000_000);
        assert!(!analysis.is_fragmented);
        assert_eq!(builder.wallet_health(&utxos), WalletHealth::Healthy);
    }

    #[test]
    fn health_escalates_with_fragmentation() {
        let builder = TransactionBuilder::default();

        let fragmented: Vec<Utxo> = (0..15)
            .map(|i| owned_utxo(10_000_000, i as u64, (i as u8) | 1))
            .collect();
        assert_eq!(
            builder.wallet_health(&fragmented),
            WalletHealth::Fragmented
        );

        let critical: Vec<Utxo> = (0..40)
            .map(|i| owned_utxo(10_000_000, i as u64, (i as u8) | 1))
            .collect();
        assert_eq!(builder.wallet_health(&critical), WalletHealth::Critical);
        assert!(builder.analyze_utxos(&critical).needs_consolidation);
        assert!(builder.describe_health(&critical).contains("Consolidate"));
    }

    #[test]
    fn single_transaction_feasibility_reports_input_count() {
        let builder = TransactionBuilder::default();
        let utxos = vec![
            owned_utxo(100_000_000, 1, 0x33),
            owned_utxo(100_000_000, 2, 0x34),
        ];

        // One large UTXO suffices for a small send.
        assert_eq!(builder.can_send_in_single_transaction(&utxos, 1_000), Some(1));

        // A larger send needs both.
        assert_eq!(
            builder.can_send_in_single_transaction(&utxos, 150_000_000),
            Some(2)
        );

        // Beyond the total, it is impossible.
        assert_eq!(
            builder.can_send_in_single_transaction(&utxos, 10_000_000_000),
            None
        );
    }

    #[test]
    fn multi_transaction_plan_covers_the_full_amount() {
        let builder = TransactionBuilder::default();
        let utxos: Vec<Utxo> = (0..40)
            .map(|i| owned_utxo(100_000_000, i as u64, (i as u8) | 1))
            .collect();

        // More than 32 inputs' worth of value forces a split.
        let target = 3_500_000_000u64;
        let plan = builder.plan_multi_transaction(&utxos, target).unwrap();

        assert!(plan.transactions.len() >= 2);
        assert_eq!(
            plan.transactions.iter().map(|t| t.amount).sum::<u64>(),
            target
        );
        assert!(plan.total_fees > 0);
        assert!(plan
            .transactions
            .iter()
            .all(|t| t.input_utxos.len() <= MAX_ANON_INPUTS));
    }

    #[test]
    fn multi_transaction_plan_rejects_an_impossible_amount() {
        let builder = TransactionBuilder::default();
        let utxos = vec![owned_utxo(100_000_000, 1, 0x33)];

        assert!(matches!(
            builder.plan_multi_transaction(&utxos, 10_000_000_000),
            Err(VeilError::InsufficientFunds { .. })
        ));
    }

    #[test]
    fn consolidation_rejects_an_empty_or_dust_set() {
        let builder = TransactionBuilder::default();
        let w = wallet();
        let available = decoys(20, 100);

        assert!(builder
            .build_consolidation_transaction(
                &w.spend_secret,
                &w.scan_secret,
                &[],
                &available,
                MAX_ANON_INPUTS
            )
            .is_err());

        // A UTXO smaller than the fee cannot fund its own consolidation.
        let dust = vec![owned_utxo(1, 1, 0x33)];
        assert!(matches!(
            builder.build_consolidation_transaction(
                &w.spend_secret,
                &w.scan_secret,
                &dust,
                &available,
                MAX_ANON_INPUTS
            ),
            Err(VeilError::InsufficientFunds { .. })
        ));
    }

    #[test]
    fn consolidation_rejects_an_invalid_input_cap() {
        let builder = TransactionBuilder::default();
        let w = wallet();
        let utxos = vec![owned_utxo(100_000_000, 1, 0x33)];
        let available = decoys(20, 100);

        for max_inputs in [0, MAX_ANON_INPUTS + 1] {
            assert!(builder
                .build_consolidation_transaction(
                    &w.spend_secret,
                    &w.scan_secret,
                    &utxos,
                    &available,
                    max_inputs
                )
                .is_err());
        }
    }

    #[test]
    fn builds_and_verifies_a_single_input_transaction() {
        let builder = TransactionBuilder::new(TransactionBuilderConfig {
            ring_size: MIN_RING_SIZE,
            fee_per_kb: DEFAULT_FEE_PER_KB,
        })
        .unwrap();

        let w = wallet();
        let utxos = vec![owned_utxo(100_000_000, 7, 0x33)];
        let available = decoys(8, 200);
        let recipient = Recipient::new(w.stealth_address.clone(), 10_000_000);

        let result = builder
            .build_transaction(
                &w.spend_secret,
                &w.scan_secret,
                &[recipient],
                &utxos,
                &available,
            )
            .expect("a single-input transaction should build");

        // The MLSAG is verified inside build_transaction, so reaching here means
        // the ring signature validated.
        assert!(!result.tx_hex.is_empty());
        assert_eq!(result.txid.len(), 64);
        assert_eq!(result.size, result.tx_hex.len() / 2);
        assert!(result.fee > 0);
        assert_eq!(result.inputs.len(), 1);

        // A fee data output, the recipient, and the change output.
        assert_eq!(result.outputs.len(), 3);
        assert!(matches!(result.outputs[0], TxOutput::Data { .. }));
        assert!(matches!(result.outputs[1], TxOutput::RingCt { .. }));

        // The serialized form must parse back cleanly.
        let parsed = crate::serialization::deserialize_transaction(&result.tx_hex).unwrap();
        assert_eq!(parsed.inputs.len(), 1);
        assert_eq!(parsed.outputs.len(), 3);
        assert!(parsed.has_witness);
        assert_eq!(parsed.inputs[0].prevout.n, ANON_MARKER);

        // The fee in the data output must match the reported fee.
        assert_eq!(
            crate::serialization::extract_fee(&parsed).unwrap(),
            Some(result.fee)
        );

        // The witness must carry the ring indices and the signature.
        assert_eq!(parsed.witness[0].stack.len(), 2);
    }

    #[test]
    fn builds_and_verifies_a_multi_input_transaction() {
        let builder = TransactionBuilder::new(TransactionBuilderConfig {
            ring_size: MIN_RING_SIZE,
            fee_per_kb: DEFAULT_FEE_PER_KB,
        })
        .unwrap();

        let w = wallet();
        // Two UTXOs, neither of which alone covers the send plus fee.
        let utxos = vec![
            owned_utxo(60_000_000, 7, 0x33),
            owned_utxo(60_000_000, 8, 0x34),
        ];
        let available = decoys(12, 300);
        let recipient = Recipient::new(w.stealth_address.clone(), 100_000_000);

        let result = builder
            .build_transaction(
                &w.spend_secret,
                &w.scan_secret,
                &[recipient],
                &utxos,
                &available,
            )
            .expect("a multi-input transaction should build");

        assert_eq!(result.inputs.len(), 2);

        let parsed = crate::serialization::deserialize_transaction(&result.tx_hex).unwrap();
        assert_eq!(parsed.inputs.len(), 2);
        assert_eq!(parsed.witness.len(), 2);

        // Multi-input witnesses append a 33-byte split commitment.
        let single_input_len = MIN_RING_SIZE * 2 * 32 + 32;
        assert_eq!(parsed.witness[0].stack[1].len(), single_input_len + 33);
    }

    #[test]
    fn build_fails_without_enough_decoys() {
        let builder = TransactionBuilder::new(TransactionBuilderConfig {
            ring_size: DEFAULT_RING_SIZE,
            fee_per_kb: DEFAULT_FEE_PER_KB,
        })
        .unwrap();

        let w = wallet();
        let utxos = vec![owned_utxo(100_000_000, 7, 0x33)];
        // A ring of 11 needs 10 decoys; supply only 3.
        let available = decoys(3, 400);

        assert!(builder
            .build_transaction(
                &w.spend_secret,
                &w.scan_secret,
                &[Recipient::new(w.stealth_address.clone(), 10_000_000)],
                &utxos,
                &available,
            )
            .is_err());
    }

    #[test]
    fn build_fails_when_the_utxo_is_not_ours() {
        let builder = TransactionBuilder::new(TransactionBuilderConfig {
            ring_size: MIN_RING_SIZE,
            fee_per_kb: DEFAULT_FEE_PER_KB,
        })
        .unwrap();

        let w = wallet();
        let mut utxo = owned_utxo(100_000_000, 7, 0x33);
        // Replace the destination key with one we cannot derive.
        utxo.pubkey = derive_public_key(&[0x5Au8; 32]).unwrap();

        let available = decoys(8, 500);

        let err = builder
            .build_transaction(
                &w.spend_secret,
                &w.scan_secret,
                &[Recipient::new(w.stealth_address.clone(), 10_000_000)],
                &[utxo],
                &available,
            )
            .unwrap_err();

        // The mismatch must surface rather than produce a bad signature.
        assert!(matches!(err, VeilError::Mlsag(_) | VeilError::InvalidInput(_)));
    }

    #[test]
    fn a_recipient_output_is_recoverable_by_its_owner() {
        // End-to-end check that the builder's outputs are actually spendable by
        // the recipient: scan the built transaction with the wallet's keys.
        let builder = TransactionBuilder::new(TransactionBuilderConfig {
            ring_size: MIN_RING_SIZE,
            fee_per_kb: DEFAULT_FEE_PER_KB,
        })
        .unwrap();

        let w = wallet();
        let utxos = vec![owned_utxo(100_000_000, 7, 0x33)];
        let available = decoys(8, 600);
        let send_amount = 25_000_000u64;

        let result = builder
            .build_transaction(
                &w.spend_secret,
                &w.scan_secret,
                &[Recipient::new(w.stealth_address.clone(), send_amount)],
                &utxos,
                &available,
            )
            .unwrap();

        let scanned = crate::scanner::scan_transaction(
            &result.outputs,
            &w.scan_secret,
            &w.spend_secret,
            Some(&result.txid),
        )
        .unwrap();

        let recovered: Vec<u64> = scanned
            .iter()
            .filter(|s| s.is_mine)
            .filter_map(|s| s.value)
            .collect();

        // Both the payment and the change are addressed to this wallet.
        assert!(
            recovered.contains(&send_amount),
            "expected to recover {send_amount}, got {recovered:?}"
        );
        assert_eq!(recovered.len(), 2);

        // Inputs must equal outputs plus the fee.
        let total_out: u64 = recovered.iter().sum();
        assert_eq!(total_out + result.fee, 100_000_000);
    }

    #[test]
    fn range_proof_nonce_uses_the_double_hashed_ecdh_result() {
        // The builder must derive the rewind nonce as SHA256(SHA256(point)); a
        // single hash would make the recipient unable to rewind.
        let w = wallet();
        let ephemeral = generate_ephemeral_keys(&w.stealth_address).unwrap();

        let sender_nonce =
            ecdh_nonce(&ephemeral.dest_pubkey, &ephemeral.ephemeral_secret).unwrap();

        let dest_secret = crate::stealth::derive_destination_key(
            &w.spend_secret,
            &w.scan_secret,
            &ephemeral.ephemeral_pubkey,
        )
        .unwrap();
        let recipient_nonce = ecdh_nonce(&ephemeral.ephemeral_pubkey, &dest_secret).unwrap();

        assert_eq!(sender_nonce, recipient_nonce);

        // Confirm a proof built with that nonce actually rewinds.
        let blind = [0x5Cu8; 32];
        let amount = 7_777u64;
        let commitment = create_commitment(amount, &blind).unwrap();
        let proof = generate_range_proof(&RangeProofParams {
            commitment: &commitment,
            value: amount,
            blind: &blind,
            nonce: &sender_nonce,
            message: None,
            min_value: 0,
            exp: 0,
            min_bits: 32,
        })
        .unwrap();

        let rewound =
            crate::crypto::rewind_range_proof(&recipient_nonce, &commitment, &proof.proof).unwrap();
        assert_eq!(rewound.value, amount);
    }
}
