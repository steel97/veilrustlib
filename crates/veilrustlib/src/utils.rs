//! General utilities.
//!
//! Port of `src/utils.ts`: hex conversion, amount conversion, byte helpers,
//! randomness, and validation predicates.

use crate::error::{Result, VeilError};
use rand::RngCore;

/// Decode a hex string, tolerating a leading `0x`.
///
/// # Errors
///
/// Returns [`VeilError::InvalidInput`] when the string has odd length, and
/// [`VeilError::Hex`] when it contains a non-hex character.
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>> {
    let clean = hex.strip_prefix("0x").unwrap_or(hex);

    if !clean.len().is_multiple_of(2) {
        return Err(VeilError::invalid_input(
            "invalid hex string: odd length",
        ));
    }

    Ok(hex::decode(clean)?)
}

/// Encode bytes as lowercase hex.
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Decode a hex string into a fixed-size array.
///
/// # Errors
///
/// Returns [`VeilError::InvalidInput`] when the decoded length is not `N`.
pub fn hex_to_array<const N: usize>(hex: &str) -> Result<[u8; N]> {
    let bytes = hex_to_bytes(hex)?;
    bytes.try_into().map_err(|v: Vec<u8>| {
        VeilError::invalid_input(format!("expected {N} bytes, got {}", v.len()))
    })
}

/// Copy a slice into a fixed-size array.
///
/// # Errors
///
/// Returns [`VeilError::InvalidInput`] when `slice` is not exactly `N` bytes.
pub fn slice_to_array<const N: usize>(slice: &[u8]) -> Result<[u8; N]> {
    slice.try_into().map_err(|_| {
        VeilError::invalid_input(format!("expected {N} bytes, got {}", slice.len()))
    })
}

/// Convert VEIL to satoshis, truncating toward zero.
pub fn veil_to_satoshis(veil: f64) -> u64 {
    (veil * crate::types::SATOSHIS_PER_VEIL as f64).floor() as u64
}

/// Convert satoshis to VEIL.
pub fn satoshis_to_veil(satoshis: u64) -> f64 {
    satoshis as f64 / crate::types::SATOSHIS_PER_VEIL as f64
}

/// Format an amount for display, e.g. `1.00000000 VEIL`.
pub fn format_amount(satoshis: u64, decimals: usize) -> String {
    format!("{:.*} VEIL", decimals, satoshis_to_veil(satoshis))
}

/// Format an amount with the default eight decimal places.
pub fn format_amount_default(satoshis: u64) -> String {
    format_amount(satoshis, 8)
}

/// Check the surface format of a Veil stealth address.
///
/// This validates the `sv1` prefix, the length envelope, and the bech32
/// character set. It does not verify the checksum; use
/// [`crate::stealth::validate_address`] for a full check.
pub fn is_valid_stealth_address(address: &str) -> bool {
    let Some(data) = address.strip_prefix("sv1") else {
        return false;
    };

    if address.len() < 95 || address.len() > 122 {
        return false;
    }

    !data.is_empty()
        && data
            .chars()
            .all(|c| matches!(c, 'a' | 'c'..='h' | 'j'..='n' | 'p'..='z' | '0' | '2'..='9'))
}

/// Fill a buffer with cryptographically secure random bytes.
pub fn random_bytes(length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

/// Generate a cryptographically secure random 32-byte array.
pub fn random_32() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

/// Shuffle a slice in place using the thread-local CSPRNG.
pub fn shuffle<T>(items: &mut [T]) {
    use rand::seq::SliceRandom;
    items.shuffle(&mut rand::thread_rng());
}

/// Take `count` distinct random elements from `items`.
///
/// # Errors
///
/// Returns [`VeilError::InvalidInput`] when `count` exceeds `items.len()`.
pub fn random_sample<T: Clone>(items: &[T], count: usize) -> Result<Vec<T>> {
    if count > items.len() {
        return Err(VeilError::invalid_input(format!(
            "cannot sample {count} elements from a set of {}",
            items.len()
        )));
    }

    use rand::seq::SliceRandom;
    Ok(items
        .choose_multiple(&mut rand::thread_rng(), count)
        .cloned()
        .collect())
}

/// Concatenate byte slices into one buffer.
pub fn concat_bytes(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(parts.iter().map(|p| p.len()).sum());
    for part in parts {
        out.extend_from_slice(part);
    }
    out
}

/// Check that an amount is positive and within the supply cap.
pub fn is_valid_amount(amount: u64) -> bool {
    amount > 0 && amount <= crate::types::MAX_MONEY
}

/// Check that a ring size is within consensus limits.
pub fn is_valid_ring_size(ring_size: usize) -> bool {
    (crate::transaction_builder::MIN_RING_SIZE..=crate::transaction_builder::MAX_RING_SIZE)
        .contains(&ring_size)
}

/// Check that bytes look like a compressed secp256k1 public key.
pub fn is_valid_public_key(pubkey: &[u8]) -> bool {
    pubkey.len() == 33 && (pubkey[0] == 0x02 || pubkey[0] == 0x03)
}

/// Check that bytes are the right length for a secret key.
pub fn is_valid_secret_key(seckey: &[u8]) -> bool {
    seckey.len() == 32
}

/// Check that bytes look like a Pedersen commitment.
pub fn is_valid_commitment(commitment: &[u8]) -> bool {
    commitment.len() == 33 && (commitment[0] == 0x08 || commitment[0] == 0x09)
}

/// Reverse a 32-byte hash into display order and hex-encode it.
pub fn hash_to_display_hex(hash: &[u8; 32]) -> String {
    let mut reversed = *hash;
    reversed.reverse();
    hex::encode(reversed)
}

/// Decode a display-order transaction ID into internal byte order.
///
/// # Errors
///
/// Returns [`VeilError::InvalidInput`] when `txid` is not 32 bytes of hex.
pub fn display_hex_to_hash(txid: &str) -> Result<[u8; 32]> {
    let mut bytes: [u8; 32] = hex_to_array(txid)?;
    bytes.reverse();
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ported from tests/utils.test.ts -> "Hex Conversion"
    #[test]
    fn hex_to_bytes_converts_correctly() {
        let bytes = hex_to_bytes("0123456789abcdef").unwrap();
        assert_eq!(bytes, vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
    }

    #[test]
    fn bytes_to_hex_converts_correctly() {
        let bytes = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        assert_eq!(bytes_to_hex(&bytes), "0123456789abcdef");
    }

    #[test]
    fn hex_round_trips() {
        let original = "0123456789abcdef";
        assert_eq!(bytes_to_hex(&hex_to_bytes(original).unwrap()), original);
    }

    #[test]
    fn hex_to_bytes_handles_0x_prefix() {
        assert_eq!(hex_to_bytes("0x1234").unwrap(), vec![0x12, 0x34]);
    }

    #[test]
    fn hex_to_bytes_rejects_odd_length() {
        let err = hex_to_bytes("123").unwrap_err();
        assert!(err.to_string().contains("odd length"));
    }

    // Ported from tests/utils.test.ts -> "Amount Conversion"
    #[test]
    fn veil_to_satoshis_converts_correctly() {
        assert_eq!(veil_to_satoshis(1.0), 100_000_000);
        assert_eq!(veil_to_satoshis(0.5), 50_000_000);
        assert_eq!(veil_to_satoshis(0.000_000_01), 1);
    }

    #[test]
    fn satoshis_to_veil_converts_correctly() {
        assert_eq!(satoshis_to_veil(100_000_000), 1.0);
        assert_eq!(satoshis_to_veil(50_000_000), 0.5);
        assert_eq!(satoshis_to_veil(1), 0.000_000_01);
    }

    #[test]
    fn format_amount_formats_correctly() {
        assert_eq!(format_amount_default(100_000_000), "1.00000000 VEIL");
        assert_eq!(format_amount_default(50_000_000), "0.50000000 VEIL");
        assert_eq!(format_amount_default(1), "0.00000001 VEIL");
    }

    #[test]
    fn format_amount_respects_decimals() {
        assert_eq!(format_amount(100_000_000, 2), "1.00 VEIL");
        assert_eq!(format_amount(100_000_000, 0), "1 VEIL");
    }

    // Ported from tests/utils.test.ts -> "Stealth Address Validation"
    #[test]
    fn rejects_addresses_with_wrong_prefix() {
        assert!(!is_valid_stealth_address("bv1qqqqqqqqqqqqqqqqq"));
        assert!(!is_valid_stealth_address("sv2qqqqqqqqqqqqqqqqq"));
    }

    #[test]
    fn rejects_addresses_that_are_too_short() {
        assert!(!is_valid_stealth_address("sv1qq"));
    }

    #[test]
    fn rejects_addresses_that_are_too_long() {
        let too_long = format!("sv1{}", "q".repeat(200));
        assert!(!is_valid_stealth_address(&too_long));
    }

    #[test]
    fn rejects_addresses_with_invalid_characters() {
        // bech32 excludes 'b', 'i', and 'o'.
        let with_b = format!("sv1qqq{}", "q".repeat(88)).replacen('q', "b", 1);
        assert!(!is_valid_stealth_address(&with_b));
    }

    #[test]
    fn accepts_valid_looking_addresses() {
        let valid_format = format!("sv1{}", "q".repeat(100));
        assert!(is_valid_stealth_address(&valid_format));
    }

    // Ported from tests/utils.test.ts -> "Validation Functions"
    #[test]
    fn is_valid_amount_accepts_valid_amounts() {
        assert!(is_valid_amount(1));
        assert!(is_valid_amount(100_000_000));
        assert!(is_valid_amount(1_000_000_000_000_000));
    }

    #[test]
    fn is_valid_amount_rejects_invalid_amounts() {
        assert!(!is_valid_amount(0));
        assert!(!is_valid_amount(crate::types::MAX_MONEY + 1));
    }

    #[test]
    fn is_valid_ring_size_accepts_valid_sizes() {
        assert!(is_valid_ring_size(3));
        assert!(is_valid_ring_size(11));
        assert!(is_valid_ring_size(32));
    }

    #[test]
    fn is_valid_ring_size_rejects_invalid_sizes() {
        assert!(!is_valid_ring_size(2));
        assert!(!is_valid_ring_size(33));
        assert!(!is_valid_ring_size(0));
    }

    // Ported from tests/utils.test.ts -> "Byte Array Utilities"
    #[test]
    fn concat_bytes_concatenates() {
        let result = concat_bytes(&[&[1, 2, 3], &[4, 5, 6], &[7, 8, 9]]);
        assert_eq!(result, vec![1, 2, 3, 4, 5, 6, 7, 8, 9]);
    }

    #[test]
    fn random_sample_rejects_oversized_request() {
        assert!(random_sample(&[1, 2, 3], 4).is_err());
        assert_eq!(random_sample(&[1, 2, 3], 3).unwrap().len(), 3);
    }

    #[test]
    fn txid_display_order_round_trips() {
        let hash = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let display = hash_to_display_hex(&hash);
        assert_eq!(display_hex_to_hash(&display).unwrap(), hash);
    }
}
