//! Confidential Transaction (CT) spending utilities.
//!
//! Port of `src/ct-utils.ts`: P2PKH script construction, legacy sighash
//! computation, and CT input serialization.
//!
//! CT outputs are guarded by a standard `scriptPubKey` and spent with ECDSA
//! signatures, unlike RingCT outputs which use MLSAG ring signatures.

use crate::crypto::{double_sha256, hash160, perform_ecdh, private_add};
use crate::error::{Result, VeilError};
use crate::serialization::{encode_var_int, write_var_slice};
use crate::types::{Commitment, OutPoint, PublicKey, SecretKey, TxInputCt, TxOutput};

/// Sign all inputs and outputs.
pub const SIGHASH_ALL: u8 = 0x01;

/// Sequence value marking an input as final, disabling RBF.
pub const SEQUENCE_FINAL: u32 = 0xffff_ffff;

/// Sequence value opting into BIP125 replace-by-fee.
pub const SEQUENCE_RBF: u32 = 0xffff_fffe;

// ============================================================================
// P2PKH scripts
// ============================================================================

/// Build a P2PKH `scriptPubKey` for `pubkey`.
///
/// Layout: `OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG`.
pub fn create_p2pkh_script_pubkey(pubkey: &PublicKey) -> Vec<u8> {
    let pubkey_hash = hash160(pubkey);

    let mut script = Vec::with_capacity(25);
    script.extend_from_slice(&[0x76, 0xa9, 0x14]); // OP_DUP OP_HASH160 PUSH20
    script.extend_from_slice(&pubkey_hash);
    script.extend_from_slice(&[0x88, 0xac]); // OP_EQUALVERIFY OP_CHECKSIG
    script
}

/// Build a P2PKH `scriptSig` from a signature and public key.
///
/// Layout: `PUSH(<sig> || sighash_type) PUSH(<pubkey>)`.
pub fn create_p2pkh_script_sig(
    signature: &[u8],
    pubkey: &PublicKey,
    sighash_type: u8,
) -> Result<Vec<u8>> {
    // Each push here uses a single-byte opcode, so the payload must stay under
    // the OP_PUSHDATA1 boundary.
    if signature.len() >= 0x4c {
        return Err(VeilError::invalid_input(format!(
            "signature too long for a direct push: {} bytes",
            signature.len()
        )));
    }

    let mut script = Vec::with_capacity(signature.len() + pubkey.len() + 3);
    script.push((signature.len() + 1) as u8);
    script.extend_from_slice(signature);
    script.push(sighash_type);
    script.push(pubkey.len() as u8);
    script.extend_from_slice(pubkey);
    Ok(script)
}

/// Extract the 20-byte hash from a P2PKH `scriptPubKey`.
///
/// Returns `None` when the script is not exactly P2PKH.
pub fn extract_p2pkh_hash(script_pubkey: &[u8]) -> Option<[u8; 20]> {
    if script_pubkey.len() != 25
        || script_pubkey[0] != 0x76  // OP_DUP
        || script_pubkey[1] != 0xa9  // OP_HASH160
        || script_pubkey[2] != 0x14  // PUSH20
        || script_pubkey[23] != 0x88 // OP_EQUALVERIFY
        || script_pubkey[24] != 0xac
    // OP_CHECKSIG
    {
        return None;
    }

    Some(
        script_pubkey[3..23]
            .try_into()
            .expect("slice is exactly 20 bytes"),
    )
}

/// Whether a script is a standard P2PKH script.
pub fn is_p2pkh(script_pubkey: &[u8]) -> bool {
    extract_p2pkh_hash(script_pubkey).is_some()
}

/// Whether `pubkey` is the key committed to by a P2PKH script.
pub fn p2pkh_matches_pubkey(script_pubkey: &[u8], pubkey: &PublicKey) -> bool {
    extract_p2pkh_hash(script_pubkey).is_some_and(|hash| hash == hash160(pubkey))
}

// ============================================================================
// Sighash
// ============================================================================

/// The subset of transaction fields needed to compute a CT sighash.
#[derive(Debug, Clone)]
pub struct SighashTx<'a> {
    /// Transaction version, serialized as a 4-byte signed integer.
    pub version: i32,
    /// Inputs, reduced to the fields the sighash covers.
    pub inputs: &'a [(OutPoint, u32)],
    /// Full output set.
    pub outputs: &'a [TxOutput],
    /// Lock time.
    pub lock_time: u32,
}

/// Compute the sighash for a CT input.
///
/// Veil signs CT inputs with the standard Bitcoin legacy algorithm, not its own
/// transaction format: `CTransactionSignatureSerializer` writes `nVersion` as a
/// plain 4-byte `int32_t` and omits the per-output type byte.
pub fn compute_ct_sighash(
    tx: &SighashTx<'_>,
    input_index: usize,
    script_pubkey: &[u8],
    sighash_type: u8,
) -> Result<[u8; 32]> {
    if input_index >= tx.inputs.len() {
        return Err(VeilError::invalid_input(format!(
            "input index {input_index} out of range for {} inputs",
            tx.inputs.len()
        )));
    }

    let mut buf = Vec::new();

    buf.extend_from_slice(&tx.version.to_le_bytes());
    buf.extend_from_slice(&encode_var_int(tx.inputs.len() as u64));

    for (i, (prevout, sequence)) in tx.inputs.iter().enumerate() {
        buf.extend_from_slice(&prevout.hash);
        buf.extend_from_slice(&prevout.n.to_le_bytes());

        // Only the input being signed carries a script; the rest are blank.
        if i == input_index {
            write_var_slice(&mut buf, script_pubkey);
        } else {
            buf.push(0x00);
        }

        buf.extend_from_slice(&sequence.to_le_bytes());
    }

    buf.extend_from_slice(&encode_var_int(tx.outputs.len() as u64));
    buf.extend_from_slice(&serialize_outputs_for_legacy_sighash(tx.outputs));

    buf.extend_from_slice(&tx.lock_time.to_le_bytes());
    buf.extend_from_slice(&i32::from(sighash_type).to_le_bytes());

    Ok(double_sha256(&buf))
}

/// Serialize outputs for a legacy sighash, omitting each type byte.
///
/// `SerializeTransaction` writes a type byte per output, but the signature
/// serializer does not, so this must not reuse `serialize_output`.
fn serialize_outputs_for_legacy_sighash(outputs: &[TxOutput]) -> Vec<u8> {
    let mut buf = Vec::new();

    for output in outputs {
        match output {
            TxOutput::RingCt {
                pk,
                commitment,
                v_data,
                v_rangeproof,
                ..
            } => {
                buf.extend_from_slice(pk);
                buf.extend_from_slice(commitment);
                write_var_slice(&mut buf, v_data);
                write_var_slice(&mut buf, v_rangeproof);
            }
            TxOutput::Ct {
                commitment,
                v_data,
                script_pubkey,
                v_rangeproof,
                ..
            } => {
                buf.extend_from_slice(commitment);
                write_var_slice(&mut buf, v_data);
                write_var_slice(&mut buf, script_pubkey);
                write_var_slice(&mut buf, v_rangeproof);
            }
            TxOutput::Data { v_data } => {
                write_var_slice(&mut buf, v_data);
            }
            TxOutput::Standard {
                amount,
                script_pubkey,
            } => {
                buf.extend_from_slice(&amount.to_le_bytes());
                write_var_slice(&mut buf, script_pubkey);
            }
        }
    }

    buf
}

// ============================================================================
// Input serialization
// ============================================================================

/// Serialize a CT input in standard Bitcoin form.
pub fn serialize_ct_input(input: &TxInputCt) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32 + 4 + input.script_sig.len() + 9 + 4);
    buf.extend_from_slice(&input.prevout.hash);
    buf.extend_from_slice(&input.prevout.n.to_le_bytes());
    write_var_slice(&mut buf, &input.script_sig);
    buf.extend_from_slice(&input.sequence.to_le_bytes());
    buf
}

/// Derive the one-time secret key that unlocks a CT output.
///
/// Computes `spend_secret + SHA256(ECDH(scan_secret, ephemeral_pubkey))`, the
/// same derivation RingCT outputs use.
pub fn derive_ct_spend_key(
    spend_secret: &SecretKey,
    scan_secret: &SecretKey,
    ephemeral_pubkey: &PublicKey,
) -> Result<SecretKey> {
    let shared_secret = perform_ecdh(ephemeral_pubkey, scan_secret)?;
    private_add(spend_secret, &shared_secret)
}

/// Sign a CT input and build its P2PKH `scriptSig`.
///
/// The commitment is not covered by the legacy sighash; it is accepted here to
/// keep the call site explicit about which output is being spent.
pub fn sign_ct_input(
    tx: &SighashTx<'_>,
    input_index: usize,
    script_pubkey: &[u8],
    _commitment: &Commitment,
    secret_key: &SecretKey,
    pubkey: &PublicKey,
) -> Result<Vec<u8>> {
    let sighash = compute_ct_sighash(tx, input_index, script_pubkey, SIGHASH_ALL)?;
    let signature = crate::crypto::ecdsa_sign(&sighash, secret_key)?;
    create_p2pkh_script_sig(&signature, pubkey, SIGHASH_ALL)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::derive_public_key;

    fn test_pubkey() -> PublicKey {
        derive_public_key(&[0x11u8; 32]).unwrap()
    }

    #[test]
    fn p2pkh_script_has_the_expected_shape() {
        let pubkey = test_pubkey();
        let script = create_p2pkh_script_pubkey(&pubkey);

        assert_eq!(script.len(), 25);
        assert!(is_p2pkh(&script));
        assert_eq!(extract_p2pkh_hash(&script).unwrap(), hash160(&pubkey));
        assert!(p2pkh_matches_pubkey(&script, &pubkey));
    }

    #[test]
    fn non_p2pkh_scripts_are_rejected() {
        assert!(!is_p2pkh(&[]));
        assert!(!is_p2pkh(&[0x76, 0xa9, 0x14]));
        assert!(!is_p2pkh(&[0xffu8; 25]));

        // Correct length, wrong trailing opcode.
        let mut script = create_p2pkh_script_pubkey(&test_pubkey());
        script[24] = 0x00;
        assert!(!is_p2pkh(&script));
    }

    #[test]
    fn p2pkh_rejects_a_different_pubkey() {
        let script = create_p2pkh_script_pubkey(&test_pubkey());
        let other = derive_public_key(&[0x22u8; 32]).unwrap();
        assert!(!p2pkh_matches_pubkey(&script, &other));
    }

    #[test]
    fn script_sig_layout_is_push_sig_then_push_pubkey() {
        let pubkey = test_pubkey();
        let signature = vec![0xAAu8; 70];
        let script_sig = create_p2pkh_script_sig(&signature, &pubkey, SIGHASH_ALL).unwrap();

        // PUSH(71) || sig(70) || sighash(1) || PUSH(33) || pubkey(33)
        assert_eq!(script_sig[0], 71);
        assert_eq!(&script_sig[1..71], &signature[..]);
        assert_eq!(script_sig[71], SIGHASH_ALL);
        assert_eq!(script_sig[72], 33);
        assert_eq!(&script_sig[73..106], &pubkey[..]);
        assert_eq!(script_sig.len(), 106);
    }

    #[test]
    fn script_sig_rejects_an_oversized_signature() {
        let pubkey = test_pubkey();
        assert!(create_p2pkh_script_sig(&[0u8; 0x4c], &pubkey, SIGHASH_ALL).is_err());
    }

    fn sample_sighash_inputs() -> Vec<(OutPoint, u32)> {
        vec![
            (
                OutPoint {
                    hash: [0x01u8; 32],
                    n: 0,
                },
                SEQUENCE_FINAL,
            ),
            (
                OutPoint {
                    hash: [0x02u8; 32],
                    n: 1,
                },
                SEQUENCE_FINAL,
            ),
        ]
    }

    fn sample_outputs() -> Vec<TxOutput> {
        vec![
            TxOutput::Data {
                v_data: vec![0x06, 0x01],
            },
            TxOutput::RingCt {
                pk: [0x02u8; 33],
                commitment: [0x08u8; 33],
                v_data: vec![0xbb; 33],
                v_rangeproof: vec![0xcc; 64],
                amount: 0,
                blind: None,
                address: String::new(),
            },
        ]
    }

    #[test]
    fn sighash_is_deterministic() {
        let inputs = sample_sighash_inputs();
        let outputs = sample_outputs();
        let tx = SighashTx {
            version: 2,
            inputs: &inputs,
            outputs: &outputs,
            lock_time: 0,
        };

        let a = compute_ct_sighash(&tx, 0, &[0x76, 0xa9], SIGHASH_ALL).unwrap();
        let b = compute_ct_sighash(&tx, 0, &[0x76, 0xa9], SIGHASH_ALL).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn sighash_differs_per_input_index() {
        let inputs = sample_sighash_inputs();
        let outputs = sample_outputs();
        let tx = SighashTx {
            version: 2,
            inputs: &inputs,
            outputs: &outputs,
            lock_time: 0,
        };

        let first = compute_ct_sighash(&tx, 0, &[0x76, 0xa9], SIGHASH_ALL).unwrap();
        let second = compute_ct_sighash(&tx, 1, &[0x76, 0xa9], SIGHASH_ALL).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn sighash_changes_with_the_signed_script() {
        let inputs = sample_sighash_inputs();
        let outputs = sample_outputs();
        let tx = SighashTx {
            version: 2,
            inputs: &inputs,
            outputs: &outputs,
            lock_time: 0,
        };

        let a = compute_ct_sighash(&tx, 0, &[0x76, 0xa9], SIGHASH_ALL).unwrap();
        let b = compute_ct_sighash(&tx, 0, &[0x76, 0xaa], SIGHASH_ALL).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn sighash_rejects_an_out_of_range_index() {
        let inputs = sample_sighash_inputs();
        let outputs = sample_outputs();
        let tx = SighashTx {
            version: 2,
            inputs: &inputs,
            outputs: &outputs,
            lock_time: 0,
        };

        assert!(compute_ct_sighash(&tx, 2, &[], SIGHASH_ALL).is_err());
    }

    #[test]
    fn legacy_sighash_outputs_omit_the_type_byte() {
        let outputs = sample_outputs();
        let serialized = serialize_outputs_for_legacy_sighash(&outputs);

        // A data output contributes only its length-prefixed payload.
        assert_eq!(serialized[0], 2);
        assert_eq!(&serialized[1..3], &[0x06, 0x01]);

        // The RingCT output follows immediately, starting with its pk.
        assert_eq!(serialized[3], 0x02);
    }

    #[test]
    fn ct_input_serializes_to_the_expected_length() {
        let input = TxInputCt {
            prevout: OutPoint {
                hash: [0x01u8; 32],
                n: 3,
            },
            script_sig: vec![0xAA; 106],
            sequence: SEQUENCE_FINAL,
            script_witness: None,
        };

        let serialized = serialize_ct_input(&input);
        // 32 hash + 4 index + 1 length + 106 script + 4 sequence
        assert_eq!(serialized.len(), 147);
        assert_eq!(&serialized[0..32], &[0x01u8; 32]);
        assert_eq!(serialized[36], 106);
    }

    #[test]
    fn ct_spend_key_matches_the_published_output_key() {
        let spend_secret = [0x33u8; 32];
        let scan_secret = [0x44u8; 32];
        let ephemeral_secret = [0x55u8; 32];

        let scan_pubkey = derive_public_key(&scan_secret).unwrap();
        let ephemeral_pubkey = derive_public_key(&ephemeral_secret).unwrap();
        let spend_pubkey = derive_public_key(&spend_secret).unwrap();

        // Sender side: derive the destination key from the scan pubkey.
        let sender_shared = perform_ecdh(&scan_pubkey, &ephemeral_secret).unwrap();
        let dest_pubkey = crate::crypto::point_add_scalar(&spend_pubkey, &sender_shared).unwrap();

        // Recipient side: recover the matching secret.
        let spend_key =
            derive_ct_spend_key(&spend_secret, &scan_secret, &ephemeral_pubkey).unwrap();

        assert_eq!(derive_public_key(&spend_key).unwrap(), dest_pubkey);
    }

    #[test]
    fn signed_ct_input_produces_a_valid_script_sig() {
        let spend_secret = [0x33u8; 32];
        let pubkey = derive_public_key(&spend_secret).unwrap();
        let script_pubkey = create_p2pkh_script_pubkey(&pubkey);

        let inputs = sample_sighash_inputs();
        let outputs = sample_outputs();
        let tx = SighashTx {
            version: 2,
            inputs: &inputs,
            outputs: &outputs,
            lock_time: 0,
        };

        let script_sig =
            sign_ct_input(&tx, 0, &script_pubkey, &[0x08u8; 33], &spend_secret, &pubkey).unwrap();

        // The trailing push must be the pubkey that the script commits to.
        assert_eq!(&script_sig[script_sig.len() - 33..], &pubkey[..]);
        assert!(p2pkh_matches_pubkey(&script_pubkey, &pubkey));
    }
}
