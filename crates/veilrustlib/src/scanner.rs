//! Output scanning.
//!
//! Port of `src/scanner.ts`. Given a wallet's scan and spend keys, determines
//! which outputs in a transaction or block belong to the wallet and recovers
//! their values.
//!
//! Ownership is established differently per output type: a RingCT output is ours
//! when the derived destination key reproduces the published `pk`, while a CT
//! output is ours when its range proof rewinds successfully.

use crate::crypto::{
    derive_public_key, ecdh_nonce, perform_ecdh, point_add_scalar, private_add, rewind_range_proof,
};
use crate::error::Result;
use crate::types::{Blind, PublicKey, SecretKey, TxOutput, Utxo};
use crate::utils::slice_to_array;

/// The result of scanning a single output.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScannedOutput {
    /// Whether the output belongs to this wallet.
    pub is_mine: bool,
    /// Recovered amount, when the range proof rewound.
    pub value: Option<u64>,
    /// Recovered blinding factor, when the range proof rewound.
    pub blind: Option<Blind>,
    /// The scalar to add to the spend secret to spend this output.
    pub shared_secret: Option<[u8; 32]>,
    /// The output's public key.
    pub pubkey: Option<PublicKey>,
    /// Ephemeral public key from the output.
    pub ephemeral_pubkey: Option<PublicKey>,
    /// Output index within its transaction.
    pub vout: Option<u32>,
    /// Transaction ID.
    pub txid: Option<String>,
}

impl ScannedOutput {
    /// A result indicating the output is not ours.
    fn not_mine() -> Self {
        Self::default()
    }
}

/// Extract the ephemeral public key from an output's `vData`.
///
/// Veil writes the 33-byte key at the start of `vData` for RingCT outputs. Some
/// encoders prepend a single-byte push opcode, so a 34-byte payload is also
/// accepted by skipping the first byte.
fn extract_ephemeral_pubkey(v_data: &[u8]) -> Option<PublicKey> {
    match v_data.len() {
        33 => slice_to_array(v_data).ok(),
        n if n >= 34 => {
            // Prefer a leading 33-byte key; fall back to skipping a push byte.
            slice_to_array::<33>(&v_data[0..33])
                .ok()
                .filter(|pk| pk[0] == 0x02 || pk[0] == 0x03)
                .or_else(|| slice_to_array(&v_data[1..34]).ok())
        }
        _ => None,
    }
}

/// Scan a RingCT output.
///
/// Derives the expected destination key from the wallet's keys and compares it
/// against the output's `pk`. On a match, rewinds the range proof with the
/// double-hashed ECDH nonce to recover the amount and blind.
pub fn scan_ringct_output(
    output: &TxOutput,
    scan_secret: &SecretKey,
    spend_secret: &SecretKey,
) -> Result<ScannedOutput> {
    let TxOutput::RingCt {
        pk,
        commitment,
        v_data,
        v_rangeproof,
        ..
    } = output
    else {
        return Ok(ScannedOutput::not_mine());
    };

    let Some(ephemeral_pubkey) = extract_ephemeral_pubkey(v_data) else {
        return Ok(ScannedOutput::not_mine());
    };

    let spend_pubkey = derive_public_key(spend_secret)?;

    // performEcdh already hashes the shared point.
    let shared = match perform_ecdh(&ephemeral_pubkey, scan_secret) {
        Ok(s) => s,
        Err(_) => return Ok(ScannedOutput::not_mine()),
    };

    let expected_pubkey = match point_add_scalar(&spend_pubkey, &shared) {
        Ok(p) => p,
        Err(_) => return Ok(ScannedOutput::not_mine()),
    };

    if &expected_pubkey != pk {
        return Ok(ScannedOutput::not_mine());
    }

    // The output is ours. Recover the amount using the destination key, which is
    // what the sender used to build the rewind nonce.
    let destination_key = private_add(spend_secret, &shared)?;
    let nonce = ecdh_nonce(&ephemeral_pubkey, &destination_key)?;

    let (value, blind) = match rewind_range_proof(&nonce, commitment, v_rangeproof) {
        Ok(rewound) => (Some(rewound.value), Some(rewound.blind)),
        Err(_) => (None, None),
    };

    Ok(ScannedOutput {
        is_mine: true,
        value,
        blind,
        shared_secret: Some(shared),
        pubkey: Some(*pk),
        ephemeral_pubkey: Some(ephemeral_pubkey),
        vout: None,
        txid: None,
    })
}

/// Scan a CT output.
///
/// CT outputs carry a `scriptPubKey` rather than a bare destination key, so
/// ownership is proven by successfully rewinding the range proof.
pub fn scan_ct_output(
    output: &TxOutput,
    scan_secret: &SecretKey,
    spend_secret: &SecretKey,
) -> Result<ScannedOutput> {
    let TxOutput::Ct {
        commitment,
        v_data,
        v_rangeproof,
        ..
    } = output
    else {
        return Ok(ScannedOutput::not_mine());
    };

    let Some(ephemeral_pubkey) = extract_ephemeral_pubkey(v_data) else {
        return Ok(ScannedOutput::not_mine());
    };

    let shared = match perform_ecdh(&ephemeral_pubkey, scan_secret) {
        Ok(s) => s,
        Err(_) => return Ok(ScannedOutput::not_mine()),
    };

    let destination_key = private_add(spend_secret, &shared)?;
    let derived_pubkey = derive_public_key(&destination_key)?;
    let nonce = ecdh_nonce(&ephemeral_pubkey, &destination_key)?;

    match rewind_range_proof(&nonce, commitment, v_rangeproof) {
        Ok(rewound) => Ok(ScannedOutput {
            is_mine: true,
            value: Some(rewound.value),
            blind: Some(rewound.blind),
            shared_secret: Some(shared),
            pubkey: Some(derived_pubkey),
            ephemeral_pubkey: Some(ephemeral_pubkey),
            vout: None,
            txid: None,
        }),
        Err(_) => Ok(ScannedOutput::not_mine()),
    }
}

/// Scan any output, dispatching on its type.
///
/// Standard and data outputs are never confidential, so they are never ours.
pub fn scan_output(
    output: &TxOutput,
    scan_secret: &SecretKey,
    spend_secret: &SecretKey,
) -> Result<ScannedOutput> {
    match output {
        TxOutput::RingCt { .. } => scan_ringct_output(output, scan_secret, spend_secret),
        TxOutput::Ct { .. } => scan_ct_output(output, scan_secret, spend_secret),
        TxOutput::Standard { .. } | TxOutput::Data { .. } => Ok(ScannedOutput::not_mine()),
    }
}

/// Scan every output in a transaction, tagging matches with their index.
pub fn scan_transaction(
    outputs: &[TxOutput],
    scan_secret: &SecretKey,
    spend_secret: &SecretKey,
    txid: Option<&str>,
) -> Result<Vec<ScannedOutput>> {
    let mut results = Vec::with_capacity(outputs.len());

    for (vout, output) in outputs.iter().enumerate() {
        let mut result = scan_output(output, scan_secret, spend_secret)?;

        if result.is_mine {
            result.vout = Some(vout as u32);
            result.txid = txid.map(str::to_owned);
        }

        results.push(result);
    }

    Ok(results)
}

/// Convert a scan result into a spendable [`Utxo`].
///
/// Returns `None` when the output is not ours or when the amount and blind could
/// not be recovered, since such an output cannot be spent.
pub fn scanned_output_to_utxo(
    scanned: &ScannedOutput,
    commitment: &crate::types::Commitment,
    block_height: u32,
) -> Option<Utxo> {
    if !scanned.is_mine {
        return None;
    }

    let value = scanned.value?;
    let blind = scanned.blind?;
    let pubkey = scanned.pubkey?;
    let ephemeral_pubkey = scanned.ephemeral_pubkey?;

    Some(Utxo {
        txid: scanned.txid.clone().unwrap_or_default(),
        vout: scanned.vout.unwrap_or(0),
        amount: value,
        commitment: *commitment,
        blind,
        pubkey,
        ephemeral_pubkey,
        block_height,
        spendable: true,
        ringct_index: None,
    })
}

/// A transaction reduced to what the scanner needs.
#[derive(Debug, Clone)]
pub struct ScannableTransaction {
    /// Transaction ID, in display order.
    pub txid: String,
    /// The transaction's outputs.
    pub outputs: Vec<TxOutput>,
}

/// Scan every transaction in a block and collect the wallet's UTXOs.
pub fn scan_block(
    transactions: &[ScannableTransaction],
    scan_secret: &SecretKey,
    spend_secret: &SecretKey,
    block_height: u32,
) -> Result<Vec<Utxo>> {
    let mut utxos = Vec::new();

    for tx in transactions {
        let scanned = scan_transaction(&tx.outputs, scan_secret, spend_secret, Some(&tx.txid))?;

        for (result, output) in scanned.iter().zip(tx.outputs.iter()) {
            if !result.is_mine {
                continue;
            }

            if let Some(commitment) = output.commitment() {
                if let Some(utxo) = scanned_output_to_utxo(result, commitment, block_height) {
                    utxos.push(utxo);
                }
            }
        }
    }

    Ok(utxos)
}

/// Whether an output can be spent by this wallet.
pub fn can_spend_output(
    output: &TxOutput,
    scan_secret: &SecretKey,
    spend_secret: &SecretKey,
) -> Result<bool> {
    Ok(scan_output(output, scan_secret, spend_secret)?.is_mine)
}

/// Sum the recovered values of all owned outputs.
pub fn get_total_balance(scanned: &[ScannedOutput]) -> u64 {
    scanned
        .iter()
        .filter(|o| o.is_mine)
        .filter_map(|o| o.value)
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{create_commitment, generate_range_proof, RangeProofParams};
    use crate::ct_utils::create_p2pkh_script_pubkey;

    const SPEND_SECRET: SecretKey = [0x11u8; 32];
    const SCAN_SECRET: SecretKey = [0x22u8; 32];
    const EPHEMERAL_SECRET: SecretKey = [0x33u8; 32];

    /// Build an output addressed to the test wallet, as a sender would.
    fn build_owned_output(amount: u64, ringct: bool) -> (TxOutput, Blind) {
        let scan_pubkey = derive_public_key(&SCAN_SECRET).unwrap();
        let spend_pubkey = derive_public_key(&SPEND_SECRET).unwrap();
        let ephemeral_pubkey = derive_public_key(&EPHEMERAL_SECRET).unwrap();

        let shared = perform_ecdh(&scan_pubkey, &EPHEMERAL_SECRET).unwrap();
        let dest_pubkey = point_add_scalar(&spend_pubkey, &shared).unwrap();
        let dest_secret = private_add(&SPEND_SECRET, &shared).unwrap();
        let nonce = ecdh_nonce(&ephemeral_pubkey, &dest_secret).unwrap();

        let blind = [0xABu8; 32];
        let commitment = create_commitment(amount, &blind).unwrap();

        let proof = generate_range_proof(&RangeProofParams {
            commitment: &commitment,
            value: amount,
            blind: &blind,
            nonce: &nonce,
            message: None,
            min_value: 0,
            exp: 0,
            min_bits: 32,
        })
        .unwrap();

        let output = if ringct {
            TxOutput::RingCt {
                pk: dest_pubkey,
                commitment,
                v_data: ephemeral_pubkey.to_vec(),
                v_rangeproof: proof.proof,
                amount: 0,
                blind: None,
                address: String::new(),
            }
        } else {
            TxOutput::Ct {
                commitment,
                v_data: ephemeral_pubkey.to_vec(),
                script_pubkey: create_p2pkh_script_pubkey(&dest_pubkey),
                v_rangeproof: proof.proof,
                amount: 0,
                blind: None,
                address: String::new(),
            }
        };

        (output, blind)
    }

    /// Build a RingCT output addressed to somebody else.
    fn build_foreign_output(amount: u64) -> TxOutput {
        let foreign_scan = [0x77u8; 32];
        let foreign_spend = [0x88u8; 32];

        let scan_pubkey = derive_public_key(&foreign_scan).unwrap();
        let spend_pubkey = derive_public_key(&foreign_spend).unwrap();
        let ephemeral_pubkey = derive_public_key(&EPHEMERAL_SECRET).unwrap();

        let shared = perform_ecdh(&scan_pubkey, &EPHEMERAL_SECRET).unwrap();
        let dest_pubkey = point_add_scalar(&spend_pubkey, &shared).unwrap();

        let blind = [0xCDu8; 32];
        let commitment = create_commitment(amount, &blind).unwrap();

        TxOutput::RingCt {
            pk: dest_pubkey,
            commitment,
            v_data: ephemeral_pubkey.to_vec(),
            v_rangeproof: vec![0u8; 100],
            amount: 0,
            blind: None,
            address: String::new(),
        }
    }

    #[test]
    fn recognizes_an_owned_ringct_output() {
        let amount = 250_000_000u64;
        let (output, blind) = build_owned_output(amount, true);

        let result = scan_output(&output, &SCAN_SECRET, &SPEND_SECRET).unwrap();

        assert!(result.is_mine);
        assert_eq!(result.value, Some(amount));
        assert_eq!(result.blind, Some(blind));
        assert!(result.pubkey.is_some());
    }

    #[test]
    fn recognizes_an_owned_ct_output() {
        let amount = 42_000u64;
        let (output, blind) = build_owned_output(amount, false);

        let result = scan_output(&output, &SCAN_SECRET, &SPEND_SECRET).unwrap();

        assert!(result.is_mine);
        assert_eq!(result.value, Some(amount));
        assert_eq!(result.blind, Some(blind));
    }

    #[test]
    fn rejects_an_output_for_another_wallet() {
        let output = build_foreign_output(1_000);
        let result = scan_output(&output, &SCAN_SECRET, &SPEND_SECRET).unwrap();
        assert!(!result.is_mine);
    }

    #[test]
    fn transparent_outputs_are_never_ours() {
        let standard = TxOutput::Standard {
            amount: 1_000,
            script_pubkey: vec![0x76, 0xa9],
        };
        let data = TxOutput::Data {
            v_data: vec![0x06, 0x01],
        };

        assert!(!scan_output(&standard, &SCAN_SECRET, &SPEND_SECRET)
            .unwrap()
            .is_mine);
        assert!(!scan_output(&data, &SCAN_SECRET, &SPEND_SECRET)
            .unwrap()
            .is_mine);
    }

    #[test]
    fn malformed_vdata_does_not_panic() {
        let output = TxOutput::RingCt {
            pk: [0x02u8; 33],
            commitment: [0x08u8; 33],
            v_data: vec![0xaa; 4],
            v_rangeproof: vec![0u8; 10],
            amount: 0,
            blind: None,
            address: String::new(),
        };

        assert!(!scan_output(&output, &SCAN_SECRET, &SPEND_SECRET)
            .unwrap()
            .is_mine);
    }

    #[test]
    fn scan_transaction_tags_matches_with_index_and_txid() {
        let (owned, _) = build_owned_output(1_000, true);
        let foreign = build_foreign_output(2_000);

        let outputs = vec![foreign, owned];
        let results =
            scan_transaction(&outputs, &SCAN_SECRET, &SPEND_SECRET, Some("deadbeef")).unwrap();

        assert_eq!(results.len(), 2);
        assert!(!results[0].is_mine);
        assert!(results[1].is_mine);
        assert_eq!(results[1].vout, Some(1));
        assert_eq!(results[1].txid.as_deref(), Some("deadbeef"));
    }

    #[test]
    fn scan_block_collects_owned_utxos() {
        let (owned, blind) = build_owned_output(777_000, true);
        let foreign = build_foreign_output(1_000);

        let block = vec![
            ScannableTransaction {
                txid: "aa".repeat(32),
                outputs: vec![foreign],
            },
            ScannableTransaction {
                txid: "bb".repeat(32),
                outputs: vec![owned],
            },
        ];

        let utxos = scan_block(&block, &SCAN_SECRET, &SPEND_SECRET, 12_345).unwrap();

        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].amount, 777_000);
        assert_eq!(utxos[0].blind, blind);
        assert_eq!(utxos[0].block_height, 12_345);
        assert_eq!(utxos[0].txid, "bb".repeat(32));
        assert!(utxos[0].spendable);
    }

    #[test]
    fn total_balance_sums_only_owned_outputs() {
        let scanned = vec![
            ScannedOutput {
                is_mine: true,
                value: Some(100),
                ..Default::default()
            },
            ScannedOutput {
                is_mine: false,
                value: Some(999),
                ..Default::default()
            },
            ScannedOutput {
                is_mine: true,
                value: Some(50),
                ..Default::default()
            },
            // Owned but unrecovered: contributes nothing.
            ScannedOutput {
                is_mine: true,
                value: None,
                ..Default::default()
            },
        ];

        assert_eq!(get_total_balance(&scanned), 150);
    }

    #[test]
    fn utxo_conversion_requires_a_recovered_amount() {
        let commitment = [0x08u8; 33];

        let incomplete = ScannedOutput {
            is_mine: true,
            value: None,
            blind: Some([0u8; 32]),
            pubkey: Some([0x02u8; 33]),
            ephemeral_pubkey: Some([0x02u8; 33]),
            ..Default::default()
        };
        assert!(scanned_output_to_utxo(&incomplete, &commitment, 0).is_none());

        let not_mine = ScannedOutput::not_mine();
        assert!(scanned_output_to_utxo(&not_mine, &commitment, 0).is_none());
    }

    #[test]
    fn can_spend_output_agrees_with_scan() {
        let (owned, _) = build_owned_output(1_000, true);
        let foreign = build_foreign_output(1_000);

        assert!(can_spend_output(&owned, &SCAN_SECRET, &SPEND_SECRET).unwrap());
        assert!(!can_spend_output(&foreign, &SCAN_SECRET, &SPEND_SECRET).unwrap());
    }

    #[test]
    fn ephemeral_pubkey_extraction_handles_both_layouts() {
        let pubkey = derive_public_key(&EPHEMERAL_SECRET).unwrap();

        // Bare 33-byte key.
        assert_eq!(extract_ephemeral_pubkey(&pubkey).unwrap(), pubkey);

        // Prefixed with a push opcode.
        let mut prefixed = vec![0x21];
        prefixed.extend_from_slice(&pubkey);
        assert_eq!(extract_ephemeral_pubkey(&prefixed).unwrap(), pubkey);

        assert!(extract_ephemeral_pubkey(&[0xaa; 10]).is_none());
    }
}
