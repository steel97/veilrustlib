//! Cryptographic primitives.
//!
//! Merges `src/crypto.ts` and `src/wasm.ts`. The TypeScript version routed
//! every operation through a WASM module that had to be initialized at runtime;
//! here `veil-crypto` is linked directly, so there is no `initWasm` step and no
//! JSON marshalling between layers.

use crate::error::{Result, VeilError};
use crate::types::{Blind, Commitment, KeyImage, PublicKey, SecretKey};
use crate::utils::slice_to_array;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

/// The secp256k1 group order, big-endian.
const CURVE_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

// ============================================================================
// Hashing
// ============================================================================

/// SHA-256.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// SHA-256 applied twice, as used for transaction IDs.
pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

/// RIPEMD-160.
pub fn ripemd160(data: &[u8]) -> [u8; 20] {
    Ripemd160::digest(data).into()
}

/// RIPEMD-160 of SHA-256, as used for P2PKH script hashes.
pub fn hash160(data: &[u8]) -> [u8; 20] {
    ripemd160(&sha256(data))
}

// ============================================================================
// Elliptic curve operations
// ============================================================================

/// Derive the compressed public key for `secret`.
pub fn derive_public_key(secret: &SecretKey) -> Result<PublicKey> {
    let pubkey = veil_crypto::derive_pubkey(secret)?;
    slice_to_array(&pubkey)
}

/// Compute `pubkey + scalar * G`.
///
/// Used to derive a stealth destination key from a recipient's spend key.
pub fn point_add_scalar(pubkey: &PublicKey, scalar: &[u8; 32]) -> Result<PublicKey> {
    let result = veil_crypto::point_add_scalar(pubkey, scalar)?;
    slice_to_array(&result)
}

/// Compute `scalar * pubkey`.
pub fn point_multiply(pubkey: &PublicKey, scalar: &SecretKey) -> Result<PublicKey> {
    let result = veil_crypto::point_multiply(pubkey, scalar)?;
    slice_to_array(&result)
}

/// Compute `(a + b) mod n`.
pub fn private_add(a: &SecretKey, b: &[u8; 32]) -> Result<SecretKey> {
    let result = veil_crypto::private_add(a, b)?;
    slice_to_array(&result)
}

/// Compute `(a - b) mod n`.
///
/// `veil-crypto` exposes no scalar subtraction, so this negates `b` modulo the
/// group order and reuses [`private_add`].
pub fn private_sub(a: &SecretKey, b: &SecretKey) -> Result<SecretKey> {
    let negated = negate_scalar(b);
    private_add(a, &negated)
}

/// Compute `n - value` modulo the group order, with `0` mapping to `0`.
fn negate_scalar(value: &[u8; 32]) -> [u8; 32] {
    if value.iter().all(|&b| b == 0) {
        return [0u8; 32];
    }

    let mut result = [0u8; 32];
    let mut borrow = 0i16;

    for i in (0..32).rev() {
        let diff = i16::from(CURVE_ORDER[i]) - i16::from(value[i]) - borrow;
        if diff < 0 {
            result[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            result[i] = diff as u8;
            borrow = 0;
        }
    }

    result
}

// ============================================================================
// Key generation
// ============================================================================

/// Generate a uniformly random, in-range secret key.
pub fn generate_private_key() -> SecretKey {
    loop {
        let key = crate::utils::random_32();
        if !key.iter().all(|&b| b == 0) && key < CURVE_ORDER {
            return key;
        }
    }
}

/// Generate a random blinding factor.
pub fn generate_blind() -> Blind {
    generate_private_key()
}

// ============================================================================
// Veil-specific primitives
// ============================================================================

/// Perform Veil's ECDH, returning `SHA256(compressed(privkey * pubkey))`.
///
/// The hash is applied inside `veil-crypto`, so callers must not hash again
/// unless the protocol calls for a double hash, as range proof nonces do.
pub fn perform_ecdh(pubkey: &PublicKey, privkey: &SecretKey) -> Result<[u8; 32]> {
    let shared = veil_crypto::ecdh_veil(pubkey, privkey)?;
    slice_to_array(&shared)
}

/// Derive a range proof rewind nonce: `SHA256(SHA256(ECDH_point))`.
///
/// Veil Core hashes the ECDH result a second time before using it as a rewind
/// nonce; see `anonwallet.cpp:1602`.
pub fn ecdh_nonce(pubkey: &PublicKey, privkey: &SecretKey) -> Result<[u8; 32]> {
    Ok(sha256(&perform_ecdh(pubkey, privkey)?))
}

/// Generate the key image that marks a RingCT output as spent.
pub fn generate_key_image(pk: &PublicKey, sk: &SecretKey) -> Result<KeyImage> {
    let key_image = veil_crypto::get_keyimage(pk, sk)?;
    slice_to_array(&key_image)
}

/// Create a Pedersen commitment `C = value * H + blind * G`.
pub fn create_commitment(value: u64, blind: &Blind) -> Result<Commitment> {
    let commitment = veil_crypto::pedersen_commit(value, blind)?;
    slice_to_array(&commitment)
}

/// Sum blinding factors, treating the first `n_positive` as additive and the
/// rest as subtractive.
pub fn sum_blinds(blinds: &[Blind], n_positive: usize) -> Result<Blind> {
    let owned: Vec<Vec<u8>> = blinds.iter().map(|b| b.to_vec()).collect();
    let sum = veil_crypto::pedersen_blind_sum(&owned, n_positive)?;
    slice_to_array(&sum)
}

/// Parameters for [`generate_range_proof`].
#[derive(Debug, Clone)]
pub struct RangeProofParams<'a> {
    /// Commitment the proof will cover.
    pub commitment: &'a Commitment,
    /// Value committed to.
    pub value: u64,
    /// Blinding factor of the commitment.
    pub blind: &'a Blind,
    /// Nonce that allows the recipient to rewind the proof.
    pub nonce: &'a [u8; 32],
    /// Optional embedded message.
    pub message: Option<&'a [u8]>,
    /// Lower bound of the proven range.
    pub min_value: u64,
    /// Base-10 exponent, or `-1` to choose automatically.
    pub exp: i32,
    /// Minimum number of bits to prove, or `0` to choose automatically.
    pub min_bits: i32,
}

/// Generate a range proof showing the committed value lies in a valid range.
pub fn generate_range_proof(params: &RangeProofParams<'_>) -> Result<crate::types::RangeProof> {
    let result = veil_crypto::rangeproof_sign(
        params.commitment,
        params.value,
        params.blind,
        params.nonce,
        params.message,
        params.min_value,
        params.exp,
        params.min_bits,
    )?;

    Ok(crate::types::RangeProof {
        proof: result.proof,
        commitment: slice_to_array(&result.commitment)?,
        blind: slice_to_array(&result.blind)?,
        nonce: slice_to_array(&result.nonce)?,
    })
}

/// The value range a proof establishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedRange {
    /// Lower bound.
    pub min_value: u64,
    /// Upper bound.
    pub max_value: u64,
}

/// Verify a range proof against its commitment.
pub fn verify_range_proof(commitment: &Commitment, proof: &[u8]) -> Result<VerifiedRange> {
    let result = veil_crypto::rangeproof_verify(commitment, proof)?;
    Ok(VerifiedRange {
        min_value: result.min_value,
        max_value: result.max_value,
    })
}

/// The value and blind recovered by rewinding a range proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewoundProof {
    /// Recovered blinding factor.
    pub blind: Blind,
    /// Recovered value.
    pub value: u64,
    /// Lower bound of the proven range.
    pub min_value: u64,
    /// Upper bound of the proven range.
    pub max_value: u64,
    /// Embedded message, if any.
    pub message: Vec<u8>,
}

/// Rewind a range proof to recover the value and blind.
///
/// This is how a wallet detects and values its own outputs: only the holder of
/// the correct nonce can rewind the proof.
pub fn rewind_range_proof(
    nonce: &[u8; 32],
    commitment: &Commitment,
    proof: &[u8],
) -> Result<RewoundProof> {
    let result = veil_crypto::rangeproof_rewind(nonce, commitment, proof)?;
    Ok(RewoundProof {
        blind: slice_to_array(&result.blind)?,
        value: result.value,
        min_value: result.min_value,
        max_value: result.max_value,
        message: result.message,
    })
}

/// The prepared MLSAG matrix and the derived blind-sum secret key.
#[derive(Debug, Clone)]
pub struct PreparedMlsag {
    /// Public key matrix with the commitment row filled in.
    pub m: Vec<u8>,
    /// Blind sum, used as the secret key for the commitment row.
    pub sk: [u8; 32],
}

/// Parameters for [`prepare_mlsag`].
#[derive(Debug, Clone)]
pub struct PrepareMlsagParams<'a> {
    /// Public key matrix, with row 0 populated.
    pub m: &'a [u8],
    /// Number of output commitments.
    pub n_outs: usize,
    /// Number of blinded outputs.
    pub n_blinded: usize,
    /// Ring size.
    pub n_cols: usize,
    /// Rows in the matrix: inputs plus one commitment row.
    pub n_rows: usize,
    /// Input commitments, one per ring member.
    pub in_commits: &'a [Commitment],
    /// Output commitments.
    pub out_commits: &'a [Commitment],
    /// Blinding factors: inputs first, then outputs.
    pub blinds: &'a [Blind],
}

/// Compute the blind sum and fill the commitment row of the MLSAG matrix.
pub fn prepare_mlsag(params: &PrepareMlsagParams<'_>) -> Result<PreparedMlsag> {
    let in_flat: Vec<u8> = params.in_commits.iter().flatten().copied().collect();
    let out_flat: Vec<u8> = params.out_commits.iter().flatten().copied().collect();
    let blinds_flat: Vec<u8> = params.blinds.iter().flatten().copied().collect();

    let result = veil_crypto::prepare_mlsag(
        params.m,
        params.n_outs,
        params.n_blinded,
        params.in_commits.len(),
        params.blinds.len(),
        params.n_cols,
        params.n_rows,
        &in_flat,
        &out_flat,
        &blinds_flat,
    )?;

    Ok(PreparedMlsag {
        m: result.m,
        sk: slice_to_array(&result.sk)?,
    })
}

/// A generated MLSAG ring signature.
#[derive(Debug, Clone)]
pub struct MlsagSignature {
    /// Concatenated key images, one per input row.
    pub key_images: Vec<u8>,
    /// Initial challenge scalar.
    pub pc: Vec<u8>,
    /// Response scalars, `n_cols * n_rows` of them.
    pub ps: Vec<u8>,
}

/// Parameters for [`generate_mlsag`].
#[derive(Debug, Clone)]
pub struct GenerateMlsagParams<'a> {
    /// Random nonce.
    pub nonce: &'a [u8; 32],
    /// Signature preimage, the hash of the outputs.
    pub preimage: &'a [u8; 32],
    /// Ring size.
    pub n_cols: usize,
    /// Rows in the matrix.
    pub n_rows: usize,
    /// Position of the real input in the ring.
    pub index: usize,
    /// Secret keys: the input key, then the blind sum.
    pub secret_keys: &'a [[u8; 32]],
    /// Prepared public key matrix.
    pub public_keys: &'a [u8],
}

/// Produce an MLSAG ring signature.
pub fn generate_mlsag(params: &GenerateMlsagParams<'_>) -> Result<MlsagSignature> {
    let sk_flat: Vec<u8> = params.secret_keys.iter().flatten().copied().collect();

    let result = veil_crypto::generate_mlsag(
        params.nonce,
        params.preimage,
        params.n_cols,
        params.n_rows,
        params.index,
        &sk_flat,
        params.public_keys,
    )?;

    Ok(MlsagSignature {
        key_images: result.key_images,
        pc: result.pc,
        ps: result.ps,
    })
}

/// Parameters for [`verify_mlsag`].
#[derive(Debug, Clone)]
pub struct VerifyMlsagParams<'a> {
    /// Signature preimage.
    pub preimage: &'a [u8; 32],
    /// Ring size.
    pub n_cols: usize,
    /// Rows in the matrix.
    pub n_rows: usize,
    /// Prepared public key matrix.
    pub public_keys: &'a [u8],
    /// Key images from the signature.
    pub key_images: &'a [u8],
    /// Initial challenge scalar.
    pub pc: &'a [u8],
    /// Response scalars.
    pub ps: &'a [u8],
}

/// Verify an MLSAG ring signature.
pub fn verify_mlsag(params: &VerifyMlsagParams<'_>) -> Result<bool> {
    veil_crypto::verify_mlsag(
        params.preimage,
        params.n_cols,
        params.n_rows,
        params.public_keys,
        params.key_images,
        params.pc,
        params.ps,
    )
    .map_err(VeilError::from)
}

/// Sign a 32-byte hash, returning a DER-encoded ECDSA signature.
///
/// Used to spend CT outputs, which are guarded by a standard `scriptPubKey`.
pub fn ecdsa_sign(message_hash: &[u8; 32], secret_key: &SecretKey) -> Result<Vec<u8>> {
    veil_crypto::ecdsa_sign(message_hash, secret_key).map_err(VeilError::from)
}

/// Sign a 32-byte hash, returning a 64-byte compact signature.
pub fn ecdsa_sign_compact(message_hash: &[u8; 32], secret_key: &SecretKey) -> Result<Vec<u8>> {
    veil_crypto::ecdsa_sign_compact(message_hash, secret_key).map_err(VeilError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_known_vector() {
        // SHA-256("abc")
        assert_eq!(
            hex::encode(sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hash160_matches_known_vector() {
        // RIPEMD160(SHA256("abc"))
        assert_eq!(
            hex::encode(hash160(b"abc")),
            "bb1be98c142444d7a56aa3981c3942a978e4dc33"
        );
    }

    #[test]
    fn derive_public_key_produces_compressed_key() {
        let secret = [0x11u8; 32];
        let pubkey = derive_public_key(&secret).unwrap();
        assert!(pubkey[0] == 0x02 || pubkey[0] == 0x03);
    }

    #[test]
    fn private_add_then_sub_round_trips() {
        let a = [0x11u8; 32];
        let b = [0x22u8; 32];
        let sum = private_add(&a, &b).unwrap();
        assert_eq!(private_sub(&sum, &b).unwrap(), a);
    }

    #[test]
    fn negate_scalar_of_zero_is_zero() {
        assert_eq!(negate_scalar(&[0u8; 32]), [0u8; 32]);
    }

    #[test]
    fn generated_private_key_is_in_range() {
        let key = generate_private_key();
        assert!(!key.iter().all(|&b| b == 0));
        assert!(key < CURVE_ORDER);
    }

    #[test]
    fn commitment_has_pedersen_prefix() {
        let blind = [0xAAu8; 32];
        let commitment = create_commitment(1000, &blind).unwrap();
        assert!(commitment[0] == 0x08 || commitment[0] == 0x09);
    }

    #[test]
    fn range_proof_round_trips_through_rewind() {
        let blind = [0xABu8; 32];
        let value = 12_345u64;
        let commitment = create_commitment(value, &blind).unwrap();
        let nonce = [0xCDu8; 32];

        let proof = generate_range_proof(&RangeProofParams {
            commitment: &commitment,
            value,
            blind: &blind,
            nonce: &nonce,
            message: None,
            min_value: 0,
            exp: 0,
            min_bits: 32,
        })
        .unwrap();

        let verified = verify_range_proof(&commitment, &proof.proof).unwrap();
        assert!(verified.min_value <= value && value <= verified.max_value);

        let rewound = rewind_range_proof(&nonce, &commitment, &proof.proof).unwrap();
        assert_eq!(rewound.value, value);
        assert_eq!(rewound.blind, blind);
    }

    #[test]
    fn ecdh_is_symmetric_across_key_pairs() {
        let sk_a = [0x01u8; 32];
        let sk_b = [0x02u8; 32];
        let pk_a = derive_public_key(&sk_a).unwrap();
        let pk_b = derive_public_key(&sk_b).unwrap();

        assert_eq!(
            perform_ecdh(&pk_b, &sk_a).unwrap(),
            perform_ecdh(&pk_a, &sk_b).unwrap()
        );
    }

    #[test]
    fn stealth_destination_key_matches_derived_pubkey() {
        // The sender computes destPubkey = spendPubkey + shared * G; the
        // recipient computes destSecret = spendSecret + shared. Both must agree.
        let spend_secret = [0x33u8; 32];
        let ephemeral_secret = [0x44u8; 32];
        let scan_secret = [0x55u8; 32];

        let spend_pubkey = derive_public_key(&spend_secret).unwrap();
        let scan_pubkey = derive_public_key(&scan_secret).unwrap();
        let ephemeral_pubkey = derive_public_key(&ephemeral_secret).unwrap();

        let sender_shared = perform_ecdh(&scan_pubkey, &ephemeral_secret).unwrap();
        let dest_pubkey = point_add_scalar(&spend_pubkey, &sender_shared).unwrap();

        let recipient_shared = perform_ecdh(&ephemeral_pubkey, &scan_secret).unwrap();
        let dest_secret = private_add(&spend_secret, &recipient_shared).unwrap();

        assert_eq!(sender_shared, recipient_shared);
        assert_eq!(derive_public_key(&dest_secret).unwrap(), dest_pubkey);
    }
}
