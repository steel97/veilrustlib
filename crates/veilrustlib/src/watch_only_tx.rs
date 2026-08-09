//! Watch-only transaction parsing.
//!
//! Port of `src/watch-only-tx.ts`. Decodes the binary blobs returned by the
//! `getwatchonlytxes` RPC method, recovering amounts, blinds, and key images for
//! outputs that belong to the wallet.
//!
//! The TypeScript version exposed mutable classes with getter methods; this port
//! uses plain structs whose fields are populated by `deserialize` and then
//! filled in by `decode`.

use crate::buffer_reader::BufferReader;
use crate::crypto::{
    derive_public_key, ecdh_nonce, generate_key_image, hash160, perform_ecdh, private_add,
    rewind_range_proof,
};
use crate::error::{Result, VeilError};
use crate::types::{Blind, Commitment, KeyImage, PublicKey, SecretKey};
use crate::utils::{hash_to_display_hex, slice_to_array};

/// Which flavor of output a watch-only record carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchOnlyTxType {
    /// A CT (stealth) output.
    Stealth,
    /// A RingCT (anon) output.
    Anon,
}

impl WatchOnlyTxType {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::Stealth),
            1 => Some(Self::Anon),
            _ => None,
        }
    }
}

/// A CT output from a watch-only record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CTxOutCt {
    /// Pedersen commitment.
    pub commitment: Commitment,
    /// Raw `vData`; the first 33 bytes are the ephemeral public key.
    pub v_data: Vec<u8>,
    /// Script pubkey guarding the output.
    pub script_pubkey: Vec<u8>,
    /// Range proof.
    pub v_rangeproof: Vec<u8>,
    /// Ephemeral public key extracted from `vData`.
    pub ephemeral_pubkey: PublicKey,
    /// Amount, once decoded.
    pub amount: Option<u64>,
    /// Blinding factor, once decoded.
    pub blind: Option<Blind>,
    /// Derived destination public key, once decoded.
    pub derived_pubkey: Option<PublicKey>,
}

impl CTxOutCt {
    /// Parse a CT output: commitment, `vData`, `scriptPubKey`, range proof.
    pub fn deserialize(buffer: &[u8]) -> Result<Self> {
        let mut reader = BufferReader::new(buffer);

        let commitment = reader.read_array::<33>()?;
        let v_data = reader.read_var_slice()?.to_vec();
        let script_pubkey = reader.read_var_slice()?.to_vec();
        let v_rangeproof = reader.read_var_slice()?.to_vec();

        if v_data.len() < 33 {
            return Err(VeilError::deserialization(
                "CT vData is too short to hold an ephemeral public key",
            ));
        }
        let ephemeral_pubkey = slice_to_array(&v_data[0..33])?;

        Ok(Self {
            commitment,
            v_data,
            script_pubkey,
            v_rangeproof,
            ephemeral_pubkey,
            amount: None,
            blind: None,
            derived_pubkey: None,
        })
    }

    /// Recover the amount and blind for an output owned by this wallet.
    ///
    /// # Errors
    ///
    /// Returns [`VeilError::InvalidInput`] when the derived key does not match
    /// the output's `scriptPubKey`, which means the output is not ours. A range
    /// proof that fails to rewind is not an error: the amount may still arrive
    /// from RPC metadata.
    pub fn decode(&mut self, spend_secret: &SecretKey, scan_secret: &SecretKey) -> Result<()> {
        // sShared = SHA256(scan_secret * ephemeral_pubkey)
        let shared = perform_ecdh(&self.ephemeral_pubkey, scan_secret)?;
        let destination_key = private_add(spend_secret, &shared)?;
        let derived_pubkey = derive_public_key(&destination_key)?;
        self.derived_pubkey = Some(derived_pubkey);

        // For CT the ownership check runs against the script's pubkey hash.
        if self.script_pubkey.len() == 25 {
            let script_hash = &self.script_pubkey[3..23];
            if script_hash != hash160(&derived_pubkey) {
                return Err(VeilError::invalid_input(
                    "derived pubkey hash does not match scriptPubKey: output is not for this wallet",
                ));
            }
        }

        // Veil Core double-hashes the ECDH result for the rewind nonce.
        let nonce = ecdh_nonce(&self.ephemeral_pubkey, &destination_key)?;

        if let Ok(rewound) = rewind_range_proof(&nonce, &self.commitment, &self.v_rangeproof) {
            self.amount = Some(rewound.value);
            self.blind = Some(rewound.blind);
        }

        Ok(())
    }
}

/// A RingCT output from a watch-only record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CTxOutRingCt {
    /// One-time destination public key.
    pub pubkey: PublicKey,
    /// Pedersen commitment.
    pub commitment: Commitment,
    /// Raw `vData`; the first 33 bytes are the ephemeral public key.
    pub v_data: Vec<u8>,
    /// Range proof.
    pub v_rangeproof: Vec<u8>,
    /// Ephemeral public key extracted from `vData`.
    pub ephemeral_pubkey: PublicKey,
    /// Key image, once decoded.
    pub key_image: Option<KeyImage>,
    /// Amount, once decoded.
    pub amount: Option<u64>,
    /// Blinding factor, once decoded.
    pub blind: Option<Blind>,
}

impl CTxOutRingCt {
    /// Parse a RingCT output: pubkey, commitment, `vData`, range proof.
    pub fn deserialize(buffer: &[u8]) -> Result<Self> {
        let mut reader = BufferReader::new(buffer);

        let pubkey = reader.read_array::<33>()?;
        let commitment = reader.read_array::<33>()?;
        let v_data = reader.read_var_slice()?.to_vec();
        let v_rangeproof = reader.read_var_slice()?.to_vec();

        if v_data.len() < 33 {
            return Err(VeilError::deserialization(
                "RingCT vData is too short to hold an ephemeral public key",
            ));
        }
        let ephemeral_pubkey = slice_to_array(&v_data[0..33])?;

        Ok(Self {
            pubkey,
            commitment,
            v_data,
            v_rangeproof,
            ephemeral_pubkey,
            key_image: None,
            amount: None,
            blind: None,
        })
    }

    /// Recover the key image, amount, and blind for an output we own.
    ///
    /// # Errors
    ///
    /// Returns [`VeilError::InvalidInput`] when the derived destination key does
    /// not reproduce the output's public key, mirroring the ownership check in
    /// Veil Core's `watchonly.cpp:565`.
    pub fn decode(&mut self, spend_secret: &SecretKey, scan_secret: &SecretKey) -> Result<()> {
        let shared = perform_ecdh(&self.ephemeral_pubkey, scan_secret)?;

        // destination_sk = spend_sk + sShared (mod n)
        let destination_key = private_add(spend_secret, &shared)?;

        let derived_pubkey = derive_public_key(&destination_key)?;
        if derived_pubkey != self.pubkey {
            return Err(VeilError::invalid_input(
                "derived destination pubkey does not match output pubkey: output is not for this wallet",
            ));
        }

        self.key_image = Some(generate_key_image(&self.pubkey, &destination_key)?);

        // Veil Core double-hashes the ECDH result for the rewind nonce; see
        // anonwallet.cpp:5572.
        let nonce = ecdh_nonce(&self.ephemeral_pubkey, &destination_key)?;

        // A failed rewind is tolerated: amount and blind may come from RPC.
        if let Ok(rewound) = rewind_range_proof(&nonce, &self.commitment, &self.v_rangeproof) {
            self.amount = Some(rewound.value);
            self.blind = Some(rewound.blind);
        }

        Ok(())
    }
}

/// The output carried by a watch-only record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchOnlyOutput {
    /// A CT (stealth) output.
    Ct(CTxOutCt),
    /// A RingCT (anon) output.
    RingCt(CTxOutRingCt),
}

/// A watch-only transaction record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchOnlyTx {
    /// Record type.
    pub tx_type: WatchOnlyTxType,
    /// Scan secret the node matched against.
    pub scan_secret: [u8; 32],
    /// Transaction hash, in internal byte order.
    pub tx_hash: [u8; 32],
    /// Output index within the transaction.
    pub tx_index: u32,
    /// The decoded output.
    pub output: WatchOnlyOutput,
    /// Global RingCT index, present on `getwatchonlytxes` records.
    pub ringct_index: Option<u64>,
}

impl WatchOnlyTx {
    /// Parse a record body, without the leading RingCT index.
    ///
    /// Layout: `[type:4][scanSecret:32][valid:1][compressed:1][txHash:32][txIndex:4][output...]`
    pub fn deserialize(buffer: &[u8]) -> Result<Self> {
        let mut reader = BufferReader::new(buffer);

        let type_value = reader.read_i32()?;
        let tx_type = WatchOnlyTxType::from_i32(type_value).ok_or_else(|| {
            VeilError::deserialization(format!("unknown watch-only tx type: {type_value}"))
        })?;

        let scan_secret = reader.read_array::<32>()?;

        // Two key-metadata flags we do not use but must skip.
        let _valid = reader.read_u8()?;
        let _compressed = reader.read_u8()?;

        let tx_hash = reader.read_array::<32>()?;
        let tx_index = reader.read_u32()?;

        let rest = reader.rest();
        let output = match tx_type {
            WatchOnlyTxType::Anon => WatchOnlyOutput::RingCt(CTxOutRingCt::deserialize(rest)?),
            WatchOnlyTxType::Stealth => WatchOnlyOutput::Ct(CTxOutCt::deserialize(rest)?),
        };

        Ok(Self {
            tx_type,
            scan_secret,
            tx_hash,
            tx_index,
            output,
            ringct_index: None,
        })
    }

    /// Parse a record that is prefixed with its 8-byte RingCT index.
    ///
    /// This is the shape `getwatchonlytxes` returns.
    pub fn deserialize_with_index(buffer: &[u8]) -> Result<Self> {
        let mut reader = BufferReader::new(buffer);
        let ringct_index = reader.read_u64()?;

        let mut tx = Self::deserialize(reader.rest())?;
        tx.ringct_index = Some(ringct_index);
        Ok(tx)
    }

    /// Parse a hex-encoded record with a leading RingCT index.
    pub fn from_hex(raw_hex: &str) -> Result<Self> {
        let bytes = crate::utils::hex_to_bytes(raw_hex)?;
        Self::deserialize_with_index(&bytes)
    }

    /// The transaction ID in display order.
    pub fn txid(&self) -> String {
        hash_to_display_hex(&self.tx_hash)
    }

    /// The RingCT output, when this record carries one.
    pub fn ringct_output(&self) -> Option<&CTxOutRingCt> {
        match &self.output {
            WatchOnlyOutput::RingCt(o) => Some(o),
            _ => None,
        }
    }

    /// The CT output, when this record carries one.
    pub fn ct_output(&self) -> Option<&CTxOutCt> {
        match &self.output {
            WatchOnlyOutput::Ct(o) => Some(o),
            _ => None,
        }
    }

    /// Mutable access to the RingCT output, for decoding.
    pub fn ringct_output_mut(&mut self) -> Option<&mut CTxOutRingCt> {
        match &mut self.output {
            WatchOnlyOutput::RingCt(o) => Some(o),
            _ => None,
        }
    }

    /// Mutable access to the CT output, for decoding.
    pub fn ct_output_mut(&mut self) -> Option<&mut CTxOutCt> {
        match &mut self.output {
            WatchOnlyOutput::Ct(o) => Some(o),
            _ => None,
        }
    }
}

/// A decoded RingCT UTXO recovered from a watch-only record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedUtxo {
    /// Transaction ID, in display order.
    pub txid: String,
    /// Output index.
    pub vout: u32,
    /// Amount in satoshis; zero when it could not be recovered.
    pub amount: u64,
    /// Pedersen commitment.
    pub commitment: Commitment,
    /// Blinding factor; zeroed when it could not be recovered.
    pub blind: Blind,
    /// One-time destination public key.
    pub pubkey: PublicKey,
    /// Ephemeral public key.
    pub ephemeral_pubkey: PublicKey,
    /// Key image.
    pub key_image: KeyImage,
    /// Global RingCT index.
    pub ringct_index: Option<u64>,
}

impl ParsedUtxo {
    /// Whether the amount and blind were both recovered.
    ///
    /// A UTXO missing either cannot be spent until they are supplied.
    pub fn is_spendable(&self) -> bool {
        self.amount > 0 && self.blind != [0u8; 32]
    }
}

/// A decoded CT UTXO recovered from a watch-only record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedUtxoCt {
    /// Transaction ID, in display order.
    pub txid: String,
    /// Output index.
    pub vout: u32,
    /// Amount in satoshis; zero when it could not be recovered.
    pub amount: u64,
    /// Pedersen commitment.
    pub commitment: Commitment,
    /// Blinding factor; zeroed when it could not be recovered.
    pub blind: Blind,
    /// Script pubkey guarding the output.
    pub script_pubkey: Vec<u8>,
    /// Derived destination public key.
    pub pubkey: PublicKey,
    /// Ephemeral public key.
    pub ephemeral_pubkey: PublicKey,
}

impl ParsedUtxoCt {
    /// Whether the amount and blind were both recovered.
    pub fn is_spendable(&self) -> bool {
        self.amount > 0 && self.blind != [0u8; 32]
    }
}

/// Amount and blind supplied alongside a record by the RPC layer.
///
/// The node's values are authoritative when present: they avoid depending on a
/// successful range proof rewind.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransactionMetadata {
    /// Amount in satoshis.
    pub amount: Option<u64>,
    /// Blinding factor.
    pub blind: Option<Blind>,
    /// Global RingCT index.
    pub ringct_index: Option<u64>,
}

/// Parse hex-encoded records into RingCT UTXOs.
///
/// Records that fail to parse or that belong to another wallet are skipped, so a
/// single bad entry does not abort the scan.
pub fn parse_watch_only_transactions(
    transactions: &[String],
    spend_secret: &SecretKey,
    scan_secret: &SecretKey,
    metadata: Option<&[TransactionMetadata]>,
) -> Vec<ParsedUtxo> {
    let mut utxos = Vec::new();

    for (i, raw_tx) in transactions.iter().enumerate() {
        let tx_metadata = metadata.and_then(|m| m.get(i));

        let Ok(mut tx) = WatchOnlyTx::from_hex(raw_tx) else {
            continue;
        };

        if tx.tx_type != WatchOnlyTxType::Anon {
            continue;
        }

        // Capture the record-level fields before borrowing the output mutably.
        let record_ringct_index = tx.ringct_index;
        let txid = tx.txid();
        let vout = tx.tx_index;

        let Some(output) = tx.ringct_output_mut() else {
            continue;
        };

        if output.decode(spend_secret, scan_secret).is_err() {
            continue;
        }

        // Prefer the node's values over a local rewind.
        if let Some(meta) = tx_metadata {
            if let Some(amount) = meta.amount {
                output.amount = Some(amount);
            }
            if let Some(blind) = meta.blind {
                output.blind = Some(blind);
            }
        }

        let Some(key_image) = output.key_image else {
            continue;
        };

        let ringct_index = tx_metadata
            .and_then(|m| m.ringct_index)
            .or(record_ringct_index);

        utxos.push(ParsedUtxo {
            txid,
            vout,
            amount: output.amount.unwrap_or(0),
            commitment: output.commitment,
            blind: output.blind.unwrap_or([0u8; 32]),
            pubkey: output.pubkey,
            ephemeral_pubkey: output.ephemeral_pubkey,
            key_image,
            ringct_index,
        });
    }

    utxos
}

/// Parse hex-encoded records into CT UTXOs.
pub fn parse_watch_only_transactions_ct(
    transactions: &[String],
    spend_secret: &SecretKey,
    scan_secret: &SecretKey,
    metadata: Option<&[TransactionMetadata]>,
) -> Vec<ParsedUtxoCt> {
    let mut utxos = Vec::new();

    for (i, raw_tx) in transactions.iter().enumerate() {
        let tx_metadata = metadata.and_then(|m| m.get(i));

        let Ok(mut tx) = WatchOnlyTx::from_hex(raw_tx) else {
            continue;
        };

        if tx.tx_type != WatchOnlyTxType::Stealth {
            continue;
        }

        // Capture the record-level fields before borrowing the output mutably.
        let txid = tx.txid();
        let vout = tx.tx_index;

        let Some(output) = tx.ct_output_mut() else {
            continue;
        };

        if output.decode(spend_secret, scan_secret).is_err() {
            continue;
        }

        if let Some(meta) = tx_metadata {
            if let Some(amount) = meta.amount {
                output.amount = Some(amount);
            }
            if let Some(blind) = meta.blind {
                output.blind = Some(blind);
            }
        }

        let Some(pubkey) = output.derived_pubkey else {
            continue;
        };

        utxos.push(ParsedUtxoCt {
            txid,
            vout,
            amount: output.amount.unwrap_or(0),
            commitment: output.commitment,
            blind: output.blind.unwrap_or([0u8; 32]),
            script_pubkey: output.script_pubkey.clone(),
            pubkey,
            ephemeral_pubkey: output.ephemeral_pubkey,
        });
    }

    utxos
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{create_commitment, generate_range_proof, point_add_scalar, RangeProofParams};
    use crate::ct_utils::create_p2pkh_script_pubkey;
    use crate::serialization::write_var_slice;

    const SPEND_SECRET: SecretKey = [0x11u8; 32];
    const SCAN_SECRET: SecretKey = [0x22u8; 32];
    const EPHEMERAL_SECRET: SecretKey = [0x33u8; 32];

    /// Build a RingCT output addressed to the test wallet, mirroring what a
    /// sender would construct.
    fn build_owned_ringct_output(amount: u64) -> (PublicKey, Commitment, Vec<u8>, Vec<u8>, Blind) {
        let scan_pubkey = derive_public_key(&SCAN_SECRET).unwrap();
        let spend_pubkey = derive_public_key(&SPEND_SECRET).unwrap();
        let ephemeral_pubkey = derive_public_key(&EPHEMERAL_SECRET).unwrap();

        let shared = perform_ecdh(&scan_pubkey, &EPHEMERAL_SECRET).unwrap();
        let dest_pubkey = point_add_scalar(&spend_pubkey, &shared).unwrap();

        // The rewind nonce is ECDH against the destination key, double-hashed.
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

        (
            dest_pubkey,
            commitment,
            ephemeral_pubkey.to_vec(),
            proof.proof,
            blind,
        )
    }

    fn encode_record(
        tx_type: i32,
        tx_hash: [u8; 32],
        tx_index: u32,
        ringct_index: u64,
        output_body: &[u8],
    ) -> String {
        let mut buf = Vec::new();
        buf.extend_from_slice(&ringct_index.to_le_bytes());
        buf.extend_from_slice(&tx_type.to_le_bytes());
        buf.extend_from_slice(&SCAN_SECRET);
        buf.push(1); // scanSecretValid
        buf.push(1); // scanSecretCompressed
        buf.extend_from_slice(&tx_hash);
        buf.extend_from_slice(&tx_index.to_le_bytes());
        buf.extend_from_slice(output_body);
        hex::encode(buf)
    }

    fn encode_ringct_body(
        pubkey: &PublicKey,
        commitment: &Commitment,
        v_data: &[u8],
        proof: &[u8],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(pubkey);
        body.extend_from_slice(commitment);
        write_var_slice(&mut body, v_data);
        write_var_slice(&mut body, proof);
        body
    }

    #[test]
    fn ringct_record_round_trips_and_decodes() {
        let amount = 123_456_789u64;
        let (dest_pubkey, commitment, v_data, proof, blind) = build_owned_ringct_output(amount);
        let body = encode_ringct_body(&dest_pubkey, &commitment, &v_data, &proof);
        let raw = encode_record(1, [0x77u8; 32], 3, 42, &body);

        let mut tx = WatchOnlyTx::from_hex(&raw).unwrap();
        assert_eq!(tx.tx_type, WatchOnlyTxType::Anon);
        assert_eq!(tx.tx_index, 3);
        assert_eq!(tx.ringct_index, Some(42));
        assert_eq!(tx.scan_secret, SCAN_SECRET);

        let output = tx.ringct_output_mut().unwrap();
        assert_eq!(output.pubkey, dest_pubkey);
        assert_eq!(output.commitment, commitment);

        output.decode(&SPEND_SECRET, &SCAN_SECRET).unwrap();
        assert_eq!(output.amount, Some(amount));
        assert_eq!(output.blind, Some(blind));
        assert!(output.key_image.is_some());
    }

    #[test]
    fn txid_is_reported_in_display_order() {
        let (pk, commitment, v_data, proof, _) = build_owned_ringct_output(1_000);
        let body = encode_ringct_body(&pk, &commitment, &v_data, &proof);

        let mut tx_hash = [0u8; 32];
        tx_hash[0] = 0xaa;
        tx_hash[31] = 0xbb;

        let raw = encode_record(1, tx_hash, 0, 0, &body);
        let tx = WatchOnlyTx::from_hex(&raw).unwrap();

        // Display order is the byte reversal of internal order.
        assert!(tx.txid().starts_with("bb"));
        assert!(tx.txid().ends_with("aa"));
    }

    #[test]
    fn decode_rejects_an_output_for_another_wallet() {
        let (_, commitment, v_data, proof, _) = build_owned_ringct_output(1_000);

        // Substitute an unrelated destination key.
        let foreign_pubkey = derive_public_key(&[0x99u8; 32]).unwrap();
        let body = encode_ringct_body(&foreign_pubkey, &commitment, &v_data, &proof);
        let raw = encode_record(1, [0x01u8; 32], 0, 0, &body);

        let mut tx = WatchOnlyTx::from_hex(&raw).unwrap();
        let output = tx.ringct_output_mut().unwrap();
        assert!(output.decode(&SPEND_SECRET, &SCAN_SECRET).is_err());
    }

    #[test]
    fn parse_extracts_owned_ringct_utxos() {
        let amount = 500_000_000u64;
        let (pk, commitment, v_data, proof, blind) = build_owned_ringct_output(amount);
        let body = encode_ringct_body(&pk, &commitment, &v_data, &proof);
        let raw = encode_record(1, [0x55u8; 32], 7, 99, &body);

        let utxos =
            parse_watch_only_transactions(&[raw], &SPEND_SECRET, &SCAN_SECRET, None);

        assert_eq!(utxos.len(), 1);
        let utxo = &utxos[0];
        assert_eq!(utxo.amount, amount);
        assert_eq!(utxo.blind, blind);
        assert_eq!(utxo.vout, 7);
        assert_eq!(utxo.ringct_index, Some(99));
        assert_eq!(utxo.pubkey, pk);
        assert!(utxo.is_spendable());
    }

    #[test]
    fn rpc_metadata_overrides_the_local_rewind() {
        let (pk, commitment, v_data, proof, _) = build_owned_ringct_output(1_000);
        let body = encode_ringct_body(&pk, &commitment, &v_data, &proof);
        let raw = encode_record(1, [0x55u8; 32], 0, 5, &body);

        let metadata = [TransactionMetadata {
            amount: Some(777),
            blind: Some([0xEEu8; 32]),
            ringct_index: Some(1234),
        }];

        let utxos = parse_watch_only_transactions(
            &[raw],
            &SPEND_SECRET,
            &SCAN_SECRET,
            Some(&metadata),
        );

        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].amount, 777);
        assert_eq!(utxos[0].blind, [0xEEu8; 32]);
        assert_eq!(utxos[0].ringct_index, Some(1234));
    }

    #[test]
    fn parse_skips_foreign_and_malformed_records() {
        let (pk, commitment, v_data, proof, _) = build_owned_ringct_output(1_000);
        let good = encode_record(
            1,
            [0x55u8; 32],
            0,
            1,
            &encode_ringct_body(&pk, &commitment, &v_data, &proof),
        );

        let foreign_pk = derive_public_key(&[0x99u8; 32]).unwrap();
        let foreign = encode_record(
            1,
            [0x56u8; 32],
            0,
            2,
            &encode_ringct_body(&foreign_pk, &commitment, &v_data, &proof),
        );

        let malformed = "00ff".to_string();

        let utxos = parse_watch_only_transactions(
            &[malformed, foreign, good],
            &SPEND_SECRET,
            &SCAN_SECRET,
            None,
        );

        // Only the owned, well-formed record survives.
        assert_eq!(utxos.len(), 1);
    }

    #[test]
    fn stealth_records_are_ignored_by_the_ringct_parser() {
        let scan_pubkey = derive_public_key(&SCAN_SECRET).unwrap();
        let ephemeral_pubkey = derive_public_key(&EPHEMERAL_SECRET).unwrap();
        let shared = perform_ecdh(&scan_pubkey, &EPHEMERAL_SECRET).unwrap();
        let dest_secret = private_add(&SPEND_SECRET, &shared).unwrap();
        let dest_pubkey = derive_public_key(&dest_secret).unwrap();

        let blind = [0xCDu8; 32];
        let amount = 42_000u64;
        let commitment = create_commitment(amount, &blind).unwrap();
        let nonce = ecdh_nonce(&ephemeral_pubkey, &dest_secret).unwrap();
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

        let mut body = Vec::new();
        body.extend_from_slice(&commitment);
        write_var_slice(&mut body, &ephemeral_pubkey);
        write_var_slice(&mut body, &create_p2pkh_script_pubkey(&dest_pubkey));
        write_var_slice(&mut body, &proof.proof);

        let raw = encode_record(0, [0x66u8; 32], 1, 0, &body);

        // The RingCT parser must skip a stealth record...
        assert!(parse_watch_only_transactions(
            std::slice::from_ref(&raw),
            &SPEND_SECRET,
            &SCAN_SECRET,
            None
        )
        .is_empty());

        // ...while the CT parser decodes it.
        let ct_utxos =
            parse_watch_only_transactions_ct(&[raw], &SPEND_SECRET, &SCAN_SECRET, None);
        assert_eq!(ct_utxos.len(), 1);
        assert_eq!(ct_utxos[0].amount, amount);
        assert_eq!(ct_utxos[0].blind, blind);
        assert_eq!(ct_utxos[0].pubkey, dest_pubkey);
    }

    #[test]
    fn truncated_record_is_an_error() {
        assert!(WatchOnlyTx::from_hex("00").is_err());
        assert!(WatchOnlyTx::deserialize(&[0u8; 4]).is_err());
    }

    #[test]
    fn unknown_record_type_is_an_error() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.extend_from_slice(&7i32.to_le_bytes()); // not a known type
        buf.extend_from_slice(&[0u8; 32]);
        buf.extend_from_slice(&[1, 1]);
        buf.extend_from_slice(&[0u8; 32]);
        buf.extend_from_slice(&0u32.to_le_bytes());

        assert!(WatchOnlyTx::deserialize_with_index(&buf).is_err());
    }

    #[test]
    fn short_vdata_is_rejected() {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x02u8; 33]);
        body.extend_from_slice(&[0x08u8; 33]);
        write_var_slice(&mut body, &[0xaa; 10]); // too short for a pubkey
        write_var_slice(&mut body, &[0xbb; 10]);

        assert!(CTxOutRingCt::deserialize(&body).is_err());
    }
}
