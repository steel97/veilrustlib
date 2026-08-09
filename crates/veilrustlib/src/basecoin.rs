//! Basecoin (transparent) Veil addresses.
//!
//! Port of `CVeilAddress.addressToOutputScript` from
//! `ref/veil-dart/lib/src/veil/cveil_address.dart`, which turns a transparent
//! Veil address into the `scriptPubKey` an `OUTPUT_STANDARD` output carries.
//!
//! Two forms exist, and the Dart reference accepts exactly these two:
//!
//! - base58check with version byte `0x46`, rendered as a `V...` address, paid
//!   with a P2PKH script
//! - bech32 with the human-readable part `bv`, witness version 0 and a 20-byte
//!   program, paid with a P2WPKH script
//!
//! Stealth (`sv1...`) addresses are a different family and are handled by
//! [`crate::stealth`]. The two are mutually exclusive: a stealth address is
//! paid as a blinded RingCT output, a basecoin address as a transparent one.
//!
//! ## Why transparent, and what it costs
//!
//! Veil permits a RingCT-input transaction to pay a transparent output; the
//! daemon balances the Pedersen sums by committing to the plain value with a
//! zero blinding factor. See [`crate::transaction_builder`] for that side.
//!
//! The privacy consequence is worth stating plainly: the amount sent to a
//! basecoin address is public, and so is the destination. Only the *sender*
//! stays hidden, protected by the ring. Paying a stealth address hides the
//! amount and the recipient as well.

use crate::crypto::{double_sha256, hash160};
use crate::error::{Result, VeilError};

/// Base58 version byte for a Veil P2PKH address, `base58Prefixes.PUBKEY_ADDRESS`.
///
/// Addresses with this version render with a leading `V`.
pub const PUBKEY_ADDRESS_VERSION: u8 = 0x46;

/// Base58 version byte for a Veil P2SH address, `base58Prefixes.SCRIPT_ADDRESS`.
///
/// Recognized so a P2SH address can be rejected with a useful message rather
/// than a generic checksum failure. The Dart reference also refuses to pay one.
pub const SCRIPT_ADDRESS_VERSION: u8 = 0x05;

/// Bech32 human-readable part for a transparent Veil address,
/// `bech32Prefixes.BASE_ADDRESS`.
pub const BASE_HRP: &str = "bv";

/// Witness version of the only bech32 form the reference accepts.
const SUPPORTED_WITNESS_VERSION: u8 = 0;

/// Length of the witness program in a P2WPKH address.
const P2WPKH_PROGRAM_LEN: usize = 20;

/// Longest basecoin address accepted, generous enough for both forms.
const MAX_ADDRESS_LENGTH: usize = 90;

/// The base58 alphabet, in value order.
const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// The bech32 character set, in value order.
const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Checksum constant for bech32. Veil basecoin addresses are bech32, not
/// bech32m, matching the `bech32` package the Dart reference uses.
const BECH32_CONST: u32 = 1;

// ============================================================================
// Script opcodes
// ============================================================================

const OP_0: u8 = 0x00;
const OP_DUP: u8 = 0x76;
const OP_EQUALVERIFY: u8 = 0x88;
const OP_HASH160: u8 = 0xa9;
const OP_CHECKSIG: u8 = 0xac;
const PUSH_20: u8 = 0x14;

/// A decoded transparent Veil address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BasecoinAddress {
    /// Pay to public key hash, from a base58check `V...` address.
    P2pkh {
        /// HASH160 of the recipient's public key.
        hash: [u8; 20],
    },
    /// Pay to witness public key hash, from a bech32 `bv1...` address.
    P2wpkh {
        /// The 20-byte witness program, a HASH160 of the public key.
        hash: [u8; 20],
    },
}

impl BasecoinAddress {
    /// Build the `scriptPubKey` that pays this address.
    ///
    /// P2PKH: `OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG`, 25 bytes.
    /// P2WPKH: `OP_0 <hash>`, 22 bytes.
    pub fn script_pubkey(&self) -> Vec<u8> {
        match self {
            Self::P2pkh { hash } => {
                let mut script = Vec::with_capacity(25);
                script.push(OP_DUP);
                script.push(OP_HASH160);
                script.push(PUSH_20);
                script.extend_from_slice(hash);
                script.push(OP_EQUALVERIFY);
                script.push(OP_CHECKSIG);
                script
            }
            Self::P2wpkh { hash } => {
                let mut script = Vec::with_capacity(22);
                script.push(OP_0);
                script.push(PUSH_20);
                script.extend_from_slice(hash);
                script
            }
        }
    }

    /// The HASH160 this address commits to.
    pub fn hash(&self) -> &[u8; 20] {
        match self {
            Self::P2pkh { hash } | Self::P2wpkh { hash } => hash,
        }
    }
}

/// Decode a transparent Veil address.
///
/// Accepts a base58check `V...` address or a bech32 `bv1...` address. A stealth
/// `sv1...` address is rejected: it belongs to a different family and is paid
/// as a RingCT output, so silently treating it as basecoin would leak the
/// amount the caller expected to be blinded.
///
/// # Errors
///
/// Returns [`VeilError::InvalidAddress`] when the address is empty, too long,
/// fails its checksum, carries an unsupported version, or is a form the Veil
/// reference implementation does not pay to (P2SH, or a witness version other
/// than 0).
pub fn decode_basecoin_address(address: &str) -> Result<BasecoinAddress> {
    let trimmed = address.trim();

    if trimmed.is_empty() {
        return Err(VeilError::InvalidAddress("address cannot be empty".into()));
    }

    // Reject a stealth address explicitly, and before the length check: a real
    // stealth address is longer than any basecoin form, so a generic "too long"
    // would be the only thing the caller ever saw, which says nothing useful.
    if trimmed.to_ascii_lowercase().starts_with("sv1") {
        return Err(VeilError::InvalidAddress(
            "sv1 is a stealth address, not a basecoin address; pay it as a RingCT output".into(),
        ));
    }

    if trimmed.len() > MAX_ADDRESS_LENGTH {
        return Err(VeilError::InvalidAddress(format!(
            "address is too long: {} characters, maximum is {MAX_ADDRESS_LENGTH}",
            trimmed.len()
        )));
    }

    // Try bech32 first when the prefix says so, otherwise base58check. The Dart
    // reference tries base58 first, but the two forms are unambiguous, so the
    // order only affects which error message a malformed address produces.
    if trimmed.to_ascii_lowercase().starts_with("bv1") {
        return decode_bech32_address(trimmed);
    }

    decode_base58_address(trimmed)
}

/// Whether `address` is a payable transparent Veil address.
pub fn is_basecoin_address(address: &str) -> bool {
    decode_basecoin_address(address).is_ok()
}

/// Build the `scriptPubKey` that pays a transparent Veil address.
///
/// Convenience over [`decode_basecoin_address`] followed by
/// [`BasecoinAddress::script_pubkey`].
pub fn address_to_script_pubkey(address: &str) -> Result<Vec<u8>> {
    Ok(decode_basecoin_address(address)?.script_pubkey())
}

// ============================================================================
// base58check
// ============================================================================

/// Decode a base58check address into its version byte and payload.
fn decode_base58_address(address: &str) -> Result<BasecoinAddress> {
    let decoded = base58check_decode(address)?;

    let (&version, payload) = decoded
        .split_first()
        .ok_or_else(|| VeilError::InvalidAddress("base58 address has no version byte".into()))?;

    match version {
        PUBKEY_ADDRESS_VERSION => {
            let hash: [u8; 20] = payload.try_into().map_err(|_| {
                VeilError::InvalidAddress(format!(
                    "P2PKH address payload must be 20 bytes, got {}",
                    payload.len()
                ))
            })?;

            Ok(BasecoinAddress::P2pkh { hash })
        }
        SCRIPT_ADDRESS_VERSION => Err(VeilError::InvalidAddress(
            "P2SH addresses are not supported as payment destinations".into(),
        )),
        other => Err(VeilError::InvalidAddress(format!(
            "unknown base58 version byte {other:#04x}, expected {PUBKEY_ADDRESS_VERSION:#04x}"
        ))),
    }
}

/// Decode base58check, verifying the trailing 4-byte double-SHA256 checksum.
///
/// Returns the payload with the checksum removed, version byte still attached.
fn base58check_decode(input: &str) -> Result<Vec<u8>> {
    let decoded = base58_decode(input)?;

    if decoded.len() < 5 {
        return Err(VeilError::InvalidAddress(format!(
            "base58check payload is too short: {} bytes",
            decoded.len()
        )));
    }

    let split = decoded.len() - 4;
    let (payload, checksum) = decoded.split_at(split);

    let expected = double_sha256(payload);

    if checksum != &expected[..4] {
        return Err(VeilError::InvalidAddress(
            "base58check checksum mismatch; the address has a typo".into(),
        ));
    }

    Ok(payload.to_vec())
}

/// Decode base58 into bytes.
///
/// Implemented here rather than pulled in as a dependency: the crate keeps a
/// deliberately small dependency set and already has the hashes base58check
/// needs.
fn base58_decode(input: &str) -> Result<Vec<u8>> {
    // Leading '1's encode leading zero bytes and carry no positional value.
    let leading_zeros = input.bytes().take_while(|&b| b == b'1').count();

    let mut bytes: Vec<u8> = Vec::with_capacity(input.len());

    for character in input.bytes() {
        let value = BASE58_ALPHABET
            .iter()
            .position(|&c| c == character)
            .ok_or_else(|| {
                VeilError::InvalidAddress(format!(
                    "invalid base58 character {:?} in address",
                    character as char
                ))
            })? as u32;

        // bytes holds a big-endian base-256 number; multiply by 58 and add.
        let mut carry = value;
        for byte in bytes.iter_mut().rev() {
            let intermediate = u32::from(*byte) * 58 + carry;
            *byte = (intermediate & 0xff) as u8;
            carry = intermediate >> 8;
        }
        while carry > 0 {
            bytes.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }

    // Re-attach the zero bytes the leading '1's stood for.
    let mut result = vec![0u8; leading_zeros];
    result.extend_from_slice(&bytes);

    Ok(result)
}

/// Encode bytes as base58check, prepending `version` and appending a checksum.
///
/// Provided so a decoded address can be round-tripped, which is what the tests
/// check, and so callers can render an address they derived from a public key.
pub fn base58check_encode(version: u8, payload: &[u8]) -> String {
    let mut data = Vec::with_capacity(payload.len() + 5);
    data.push(version);
    data.extend_from_slice(payload);

    let checksum = double_sha256(&data);
    data.extend_from_slice(&checksum[..4]);

    base58_encode(&data)
}

/// Encode bytes as base58.
fn base58_encode(input: &[u8]) -> String {
    let leading_zeros = input.iter().take_while(|&&b| b == 0).count();

    let mut digits: Vec<u8> = Vec::with_capacity(input.len() * 2);

    for &byte in input {
        let mut carry = u32::from(byte);
        for digit in digits.iter_mut() {
            let intermediate = (u32::from(*digit) << 8) + carry;
            *digit = (intermediate % 58) as u8;
            carry = intermediate / 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }

    let mut out = String::with_capacity(leading_zeros + digits.len());
    for _ in 0..leading_zeros {
        out.push('1');
    }
    for &digit in digits.iter().rev() {
        out.push(BASE58_ALPHABET[digit as usize] as char);
    }

    // An all-zero input produces only the leading '1's, which is correct.
    out
}

/// Build a P2PKH address string for a public key hash.
pub fn p2pkh_address_from_hash(hash: &[u8; 20]) -> String {
    base58check_encode(PUBKEY_ADDRESS_VERSION, hash)
}

/// Build a P2PKH address string for a public key.
pub fn p2pkh_address_from_pubkey(pubkey: &[u8]) -> String {
    p2pkh_address_from_hash(&hash160(pubkey))
}

// ============================================================================
// bech32
// ============================================================================

/// Decode a bech32 `bv1...` address.
fn decode_bech32_address(address: &str) -> Result<BasecoinAddress> {
    let (hrp, words) = bech32_decode(address)?;

    if hrp != BASE_HRP {
        return Err(VeilError::InvalidAddress(format!(
            "unexpected bech32 prefix {hrp:?}, expected {BASE_HRP:?}"
        )));
    }

    let (&witness_version, program_words) = words.split_first().ok_or_else(|| {
        VeilError::InvalidAddress("bech32 address carries no witness program".into())
    })?;

    if witness_version != SUPPORTED_WITNESS_VERSION {
        return Err(VeilError::InvalidAddress(format!(
            "unsupported witness version {witness_version}, expected {SUPPORTED_WITNESS_VERSION}"
        )));
    }

    let program = convert_bits(program_words, 5, 8, false)?;

    if program.len() != P2WPKH_PROGRAM_LEN {
        return Err(VeilError::InvalidAddress(format!(
            "witness version 0 program must be {P2WPKH_PROGRAM_LEN} bytes, got {}",
            program.len()
        )));
    }

    let hash: [u8; 20] = program
        .try_into()
        .map_err(|_| VeilError::InvalidAddress("witness program is not 20 bytes".into()))?;

    Ok(BasecoinAddress::P2wpkh { hash })
}

/// Encode a witness program as a bech32 `bv1...` address.
pub fn bech32_address_from_hash(hash: &[u8; 20]) -> Result<String> {
    let mut words = vec![SUPPORTED_WITNESS_VERSION];
    words.extend_from_slice(&convert_bits(hash, 8, 5, true)?);

    Ok(bech32_encode(BASE_HRP, &words))
}

/// Regroup bits between bases, padding on encode and rejecting slop on decode.
///
/// Mirrors the private helper in [`crate::stealth`]; duplicated rather than
/// shared so neither module's address family constrains the other's.
fn convert_bits(data: &[u8], from_bits: u32, to_bits: u32, pad: bool) -> Result<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut result = Vec::new();
    let max_value = (1u32 << to_bits) - 1;

    for &value in data {
        let value = u32::from(value);
        if value >> from_bits != 0 {
            return Err(VeilError::InvalidAddress(
                "value out of range for bit conversion".into(),
            ));
        }

        acc = (acc << from_bits) | value;
        bits += from_bits;

        while bits >= to_bits {
            bits -= to_bits;
            result.push(((acc >> bits) & max_value) as u8);
        }
    }

    if pad {
        if bits > 0 {
            result.push(((acc << (to_bits - bits)) & max_value) as u8);
        }
    } else if bits >= from_bits || ((acc << (to_bits - bits)) & max_value) != 0 {
        return Err(VeilError::InvalidAddress(
            "invalid padding in bit conversion".into(),
        ));
    }

    Ok(result)
}

/// The bech32 checksum polynomial.
fn polymod(values: &[u8]) -> u32 {
    const GENERATOR: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];

    let mut checksum: u32 = 1;

    for &value in values {
        let top = checksum >> 25;
        checksum = ((checksum & 0x1ff_ffff) << 5) ^ u32::from(value);

        for (i, generator) in GENERATOR.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                checksum ^= generator;
            }
        }
    }

    checksum
}

/// Expand a human-readable part for checksum computation.
fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut result: Vec<u8> = hrp.bytes().map(|c| c >> 5).collect();
    result.push(0);
    result.extend(hrp.bytes().map(|c| c & 0x1f));
    result
}

/// Compute the 6-word bech32 checksum.
fn create_checksum(hrp: &str, data: &[u8]) -> Vec<u8> {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0, 0, 0, 0, 0, 0]);

    let polymod_value = polymod(&values) ^ BECH32_CONST;

    (0..6)
        .map(|i| ((polymod_value >> (5 * (5 - i))) & 0x1f) as u8)
        .collect()
}

/// Encode a human-readable part and 5-bit words as bech32.
fn bech32_encode(hrp: &str, data: &[u8]) -> String {
    let checksum = create_checksum(hrp, data);

    let mut out = String::with_capacity(hrp.len() + 1 + data.len() + checksum.len());
    out.push_str(hrp);
    out.push('1');

    for &word in data.iter().chain(checksum.iter()) {
        out.push(BECH32_CHARSET[word as usize] as char);
    }

    out
}

/// Decode a bech32 string into its human-readable part and 5-bit words.
fn bech32_decode(input: &str) -> Result<(String, Vec<u8>)> {
    let has_lower = input.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = input.chars().any(|c| c.is_ascii_uppercase());

    if has_lower && has_upper {
        return Err(VeilError::InvalidAddress(
            "bech32 addresses must not mix case".into(),
        ));
    }

    let lowered = input.to_ascii_lowercase();

    let separator = lowered
        .rfind('1')
        .ok_or_else(|| VeilError::InvalidAddress("bech32 separator is missing".into()))?;

    if separator < 1 || separator + 7 > lowered.len() {
        return Err(VeilError::InvalidAddress(
            "bech32 address is malformed".into(),
        ));
    }

    let hrp = lowered[..separator].to_string();
    let mut data = Vec::with_capacity(lowered.len() - separator - 1);

    for character in lowered[separator + 1..].bytes() {
        let value = BECH32_CHARSET
            .iter()
            .position(|&c| c == character)
            .ok_or_else(|| {
                VeilError::InvalidAddress(format!(
                    "invalid bech32 character {:?} in address",
                    character as char
                ))
            })?;

        data.push(value as u8);
    }

    let mut values = hrp_expand(&hrp);
    values.extend_from_slice(&data);

    if polymod(&values) != BECH32_CONST {
        return Err(VeilError::InvalidAddress(
            "bech32 checksum mismatch; the address has a typo".into(),
        ));
    }

    data.truncate(data.len() - 6);

    Ok((hrp, data))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A hash whose bytes are all distinct, so a byte-order slip is visible.
    fn sample_hash() -> [u8; 20] {
        let mut hash = [0u8; 20];
        for (i, byte) in hash.iter_mut().enumerate() {
            *byte = i as u8 + 1;
        }
        hash
    }

    #[test]
    fn base58_round_trips_through_base58check() {
        let hash = sample_hash();
        let address = p2pkh_address_from_hash(&hash);

        // Version 0x46 renders as a leading 'V'; that is how a Veil address is
        // recognized by eye.
        assert!(
            address.starts_with('V'),
            "expected a V-prefixed address, got {address}"
        );

        let decoded = decode_basecoin_address(&address).unwrap();
        assert_eq!(decoded, BasecoinAddress::P2pkh { hash });
    }

    #[test]
    fn bech32_round_trips() {
        let hash = sample_hash();
        let address = bech32_address_from_hash(&hash).unwrap();

        assert!(
            address.starts_with("bv1"),
            "expected a bv1 address, got {address}"
        );

        let decoded = decode_basecoin_address(&address).unwrap();
        assert_eq!(decoded, BasecoinAddress::P2wpkh { hash });
    }

    #[test]
    fn bech32_decoding_is_case_insensitive_but_not_mixed() {
        let address = bech32_address_from_hash(&sample_hash()).unwrap();

        assert!(decode_basecoin_address(&address.to_uppercase()).is_ok());
        assert!(decode_basecoin_address(&address).is_ok());

        // Mixed case is ambiguous for the checksum, so bech32 forbids it.
        let mixed = format!("bV1{}", &address[3..]);
        assert!(decode_basecoin_address(&mixed).is_err());
    }

    #[test]
    fn p2pkh_script_matches_the_bitcoin_template() {
        let hash = sample_hash();
        let script = BasecoinAddress::P2pkh { hash }.script_pubkey();

        assert_eq!(script.len(), 25);
        assert_eq!(&script[..3], &[OP_DUP, OP_HASH160, PUSH_20]);
        assert_eq!(&script[3..23], &hash);
        assert_eq!(&script[23..], &[OP_EQUALVERIFY, OP_CHECKSIG]);

        // The existing CT helper must agree, since both pay the same script.
        assert!(crate::ct_utils::is_p2pkh(&script));
        assert_eq!(crate::ct_utils::extract_p2pkh_hash(&script), Some(hash));
    }

    #[test]
    fn p2wpkh_script_is_op0_push20() {
        let hash = sample_hash();
        let script = BasecoinAddress::P2wpkh { hash }.script_pubkey();

        assert_eq!(script.len(), 22);
        assert_eq!(&script[..2], &[OP_0, PUSH_20]);
        assert_eq!(&script[2..], &hash);
    }

    #[test]
    fn a_corrupted_checksum_is_rejected() {
        let address = p2pkh_address_from_hash(&sample_hash());

        // Flip one character to a different valid base58 digit.
        let mut corrupted: Vec<char> = address.chars().collect();
        let last = corrupted.len() - 1;
        corrupted[last] = if corrupted[last] == 'z' { 'y' } else { 'z' };
        let corrupted: String = corrupted.into_iter().collect();

        let error = decode_basecoin_address(&corrupted).unwrap_err();
        assert!(
            error.to_string().contains("checksum"),
            "expected a checksum error, got {error}"
        );
    }

    #[test]
    fn a_corrupted_bech32_checksum_is_rejected() {
        let address = bech32_address_from_hash(&sample_hash()).unwrap();

        let mut corrupted: Vec<char> = address.chars().collect();
        let last = corrupted.len() - 1;
        corrupted[last] = if corrupted[last] == 'q' { 'p' } else { 'q' };
        let corrupted: String = corrupted.into_iter().collect();

        assert!(decode_basecoin_address(&corrupted).is_err());
    }

    #[test]
    fn p2sh_is_rejected_with_a_specific_reason() {
        let address = base58check_encode(SCRIPT_ADDRESS_VERSION, &sample_hash());

        let error = decode_basecoin_address(&address).unwrap_err();
        assert!(
            error.to_string().contains("P2SH"),
            "expected a P2SH-specific error, got {error}"
        );
    }

    #[test]
    fn an_unknown_version_byte_is_rejected() {
        let address = base58check_encode(0x21, &sample_hash());

        let error = decode_basecoin_address(&address).unwrap_err();
        assert!(
            error.to_string().contains("version"),
            "expected a version error, got {error}"
        );
    }

    #[test]
    fn a_stealth_address_is_rejected_as_basecoin() {
        let wallet = crate::stealth::create_wallet().unwrap();

        let error = decode_basecoin_address(&wallet.stealth_address).unwrap_err();
        assert!(
            error.to_string().contains("stealth"),
            "expected a stealth-specific error, got {error}"
        );

        assert!(!is_basecoin_address(&wallet.stealth_address));
    }

    #[test]
    fn a_non_zero_witness_version_is_rejected() {
        // Witness version 1 with a 20-byte program: well-formed bech32, but not
        // a form the Veil reference pays to.
        let mut words = vec![1u8];
        words.extend_from_slice(&convert_bits(&sample_hash(), 8, 5, true).unwrap());
        let address = bech32_encode(BASE_HRP, &words);

        let error = decode_basecoin_address(&address).unwrap_err();
        assert!(
            error.to_string().contains("witness version"),
            "expected a witness version error, got {error}"
        );
    }

    #[test]
    fn a_wrong_length_witness_program_is_rejected() {
        // Witness version 0 with a 32-byte program is P2WSH, which the
        // reference implementation does not pay to.
        let mut words = vec![0u8];
        words.extend_from_slice(&convert_bits(&[0x11u8; 32], 8, 5, true).unwrap());
        let address = bech32_encode(BASE_HRP, &words);

        assert!(decode_basecoin_address(&address).is_err());
    }

    #[test]
    fn a_wrong_hrp_is_rejected() {
        let mut words = vec![0u8];
        words.extend_from_slice(&convert_bits(&sample_hash(), 8, 5, true).unwrap());
        let address = bech32_encode("bc", &words);

        assert!(decode_basecoin_address(&address).is_err());
    }

    #[test]
    fn empty_and_oversized_addresses_are_rejected() {
        assert!(decode_basecoin_address("").is_err());
        assert!(decode_basecoin_address("   ").is_err());
        assert!(decode_basecoin_address(&"V".repeat(200)).is_err());
    }

    #[test]
    fn surrounding_whitespace_is_tolerated() {
        let address = p2pkh_address_from_hash(&sample_hash());
        let padded = format!("  {address}\n");

        assert_eq!(
            decode_basecoin_address(&padded).unwrap(),
            decode_basecoin_address(&address).unwrap()
        );
    }

    #[test]
    fn base58_leading_zero_bytes_survive_a_round_trip() {
        // A hash starting with zero bytes exercises the leading-'1' handling.
        let mut hash = [0u8; 20];
        hash[19] = 0xff;

        let address = p2pkh_address_from_hash(&hash);
        assert_eq!(
            decode_basecoin_address(&address).unwrap(),
            BasecoinAddress::P2pkh { hash }
        );
    }

    #[test]
    fn a_real_mainnet_p2pkh_address_decodes() {
        // A real Veil mainnet address, to pin the version byte and the script
        // template against something not produced by this module's own encoder.
        let address = "VVfLuXqCkguTxnMA7YPMuFeSeT5UBk7Dfh";

        let decoded = decode_basecoin_address(address).unwrap();

        let hash = *decoded.hash();
        assert_eq!(decoded, BasecoinAddress::P2pkh { hash });

        // 25-byte P2PKH script, and the hash sits where the CT helper expects it.
        let script = decoded.script_pubkey();
        assert_eq!(script.len(), 25);
        assert_eq!(crate::ct_utils::extract_p2pkh_hash(&script), Some(hash));

        // Re-encoding must reproduce the address exactly, which proves the version
        // byte and checksum were read correctly rather than merely accepted.
        assert_eq!(p2pkh_address_from_hash(&hash), address);

        // And the builder must route it to a transparent output.
        let destination = crate::transaction_builder::classify_address(address).unwrap();
        assert!(destination.is_transparent());
        assert_eq!(
            destination.output_type(),
            crate::types::OutputType::Standard
        );
    }

    #[test]
    fn a_pubkey_derived_address_commits_to_its_hash160() {
        let wallet = crate::stealth::create_wallet().unwrap();
        let address = p2pkh_address_from_pubkey(&wallet.spend_pubkey);

        let decoded = decode_basecoin_address(&address).unwrap();
        assert_eq!(decoded.hash(), &hash160(&wallet.spend_pubkey));
    }

    #[test]
    fn address_to_script_pubkey_matches_the_decoded_form() {
        let address = p2pkh_address_from_hash(&sample_hash());

        assert_eq!(
            address_to_script_pubkey(&address).unwrap(),
            decode_basecoin_address(&address).unwrap().script_pubkey()
        );
    }
}
