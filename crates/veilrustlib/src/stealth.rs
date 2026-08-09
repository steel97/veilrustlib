//! Stealth addresses.
//!
//! Port of `src/stealth.ts`, including the inlined bech32 implementation. Veil
//! stealth addresses use the `sv` HRP with the standard bech32 checksum
//! constant, not bech32m.
//!
//! The payload layout is:
//!
//! ```text
//! [options:1][scanPubkey:33][numSpendKeys:1][spendPubkey:33]
//! [numSignatures:1][prefixBits:1][prefixBitfield:0|4]
//! ```

use crate::crypto::{derive_public_key, generate_private_key, perform_ecdh, point_add_scalar, private_add};
use crate::error::{Result, VeilError};
use crate::types::{PublicKey, SecretKey};
use crate::utils::{is_valid_public_key, is_valid_secret_key, slice_to_array};

/// Length of a compressed public key.
const EC_COMPRESSED_SIZE: usize = 33;

/// Human-readable part of a Veil stealth address.
const HRP: &str = "sv";

/// Bech32 checksum constant. Veil uses bech32, not bech32m.
const BECH32_CONST: u32 = 1;

/// The bech32 alphabet.
const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Longest address the decoder will accept.
///
/// BIP173 caps segwit addresses at 90 characters and the TypeScript original
/// used 122, but neither bound applies here: a stealth address carries two
/// 33-byte keys, so the base payload alone encodes to about 110 characters and a
/// 4-byte prefix bitfield pushes it past 128. This cap is set above every
/// payload [`generate_stealth_address`] can produce so the decoder never rejects
/// an address the encoder emitted.
const MAX_ADDRESS_LENGTH: usize = 160;

/// Optional stealth address flags.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StealthAddressOptions {
    /// Options bitfield.
    pub options: u8,
    /// Number of signatures required.
    pub number_signatures: u8,
    /// Number of significant prefix bits.
    pub prefix_number_bits: u8,
    /// Prefix bitfield, written big-endian when `prefix_number_bits` is nonzero.
    pub prefix_bitfield: u32,
}

/// The decoded contents of a stealth address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedStealthAddress {
    /// Scan public key, used to detect incoming payments.
    pub scan_pubkey: PublicKey,
    /// Spend public key, used to derive destination keys.
    pub spend_pubkey: PublicKey,
    /// Options bitfield.
    pub options: u8,
    /// Number of signatures required.
    pub number_signatures: u8,
    /// Number of significant prefix bits.
    pub prefix_number_bits: u8,
    /// Prefix bitfield.
    pub prefix_bitfield: u32,
}

/// A wallet's key material and its stealth address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VeilWallet {
    /// Spend secret key. Keep this secret.
    pub spend_secret: SecretKey,
    /// Scan secret key. Keep this secret.
    pub scan_secret: SecretKey,
    /// Spend public key.
    pub spend_pubkey: PublicKey,
    /// Scan public key.
    pub scan_pubkey: PublicKey,
    /// The wallet's stealth address.
    pub stealth_address: String,
}

impl VeilWallet {
    /// Hex-encode the spend secret, for backup.
    pub fn spend_secret_hex(&self) -> String {
        hex::encode(self.spend_secret)
    }

    /// Hex-encode the scan secret, for backup.
    pub fn scan_secret_hex(&self) -> String {
        hex::encode(self.scan_secret)
    }
}

/// The sender-side result of deriving a one-time destination for a recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EphemeralKeys {
    /// Ephemeral public key to publish in the transaction.
    pub ephemeral_pubkey: PublicKey,
    /// Shared secret from ECDH against the recipient's scan key.
    pub shared_secret: [u8; 32],
    /// One-time destination public key that receives the funds.
    pub dest_pubkey: PublicKey,
    /// Ephemeral secret key, retained by the sender only.
    pub ephemeral_secret: SecretKey,
}

// ============================================================================
// Address encoding
// ============================================================================

/// Build a stealth address from a scan and spend public key.
///
/// Most callers want [`create_wallet`] instead.
pub fn generate_stealth_address(
    scan_pubkey: &PublicKey,
    spend_pubkey: &PublicKey,
    options: Option<StealthAddressOptions>,
) -> Result<String> {
    if !is_valid_public_key(scan_pubkey) {
        return Err(VeilError::invalid_input("invalid scan public key"));
    }
    if !is_valid_public_key(spend_pubkey) {
        return Err(VeilError::invalid_input("invalid spend public key"));
    }

    let opts = options.unwrap_or_default();

    let mut data = Vec::with_capacity(72);
    data.push(opts.options);
    data.extend_from_slice(scan_pubkey);
    data.push(1); // Veil always carries exactly one spend key.
    data.extend_from_slice(spend_pubkey);
    data.push(opts.number_signatures);
    data.push(opts.prefix_number_bits);

    if opts.prefix_number_bits > 0 {
        data.extend_from_slice(&opts.prefix_bitfield.to_be_bytes());
    }

    Ok(bech32_encode(HRP, &convert_bits(&data, 8, 5, true)?))
}

/// Decode a stealth address into its components.
pub fn decode_stealth_address(address: &str) -> Result<DecodedStealthAddress> {
    if !address.starts_with("sv1") {
        return Err(VeilError::InvalidAddress(
            "address must start with sv1".into(),
        ));
    }

    let (hrp, words) = bech32_decode(address)?;
    if hrp != HRP {
        return Err(VeilError::InvalidAddress(format!(
            "unexpected prefix: {hrp}"
        )));
    }

    let data = convert_bits(&words, 5, 8, false)?;

    // options + scan key + count + at least one spend key + 2 trailing bytes
    let min_len = 1 + EC_COMPRESSED_SIZE + 1 + EC_COMPRESSED_SIZE + 2;
    if data.len() < min_len {
        return Err(VeilError::InvalidAddress(format!(
            "payload too short: {} bytes, need at least {min_len}",
            data.len()
        )));
    }

    let mut offset = 0;

    let options = data[offset];
    offset += 1;

    let scan_pubkey: PublicKey = slice_to_array(&data[offset..offset + EC_COMPRESSED_SIZE])
        .map_err(|_| VeilError::InvalidAddress("truncated scan public key".into()))?;
    offset += EC_COMPRESSED_SIZE;

    let num_spend_pubkeys = data[offset];
    offset += 1;

    if num_spend_pubkeys != 1 {
        return Err(VeilError::InvalidAddress(format!(
            "expected exactly 1 spend key, found {num_spend_pubkeys}"
        )));
    }

    if data.len() < offset + EC_COMPRESSED_SIZE + 2 {
        return Err(VeilError::InvalidAddress(
            "truncated spend public key".into(),
        ));
    }

    let spend_pubkey: PublicKey = slice_to_array(&data[offset..offset + EC_COMPRESSED_SIZE])
        .map_err(|_| VeilError::InvalidAddress("truncated spend public key".into()))?;
    offset += EC_COMPRESSED_SIZE;

    let number_signatures = data[offset];
    offset += 1;

    let prefix_number_bits = data[offset];
    offset += 1;

    let prefix_bitfield = if prefix_number_bits > 0 {
        if data.len() < offset + 4 {
            return Err(VeilError::InvalidAddress(
                "truncated prefix bitfield".into(),
            ));
        }
        u32::from_be_bytes(
            slice_to_array(&data[offset..offset + 4])
                .map_err(|_| VeilError::InvalidAddress("truncated prefix bitfield".into()))?,
        )
    } else {
        0
    };

    Ok(DecodedStealthAddress {
        scan_pubkey,
        spend_pubkey,
        options,
        number_signatures,
        prefix_number_bits,
        prefix_bitfield,
    })
}

// ============================================================================
// Ephemeral key derivation
// ============================================================================

/// Derive a one-time destination for a recipient's stealth address.
///
/// The sender publishes [`EphemeralKeys::ephemeral_pubkey`] and pays to
/// [`EphemeralKeys::dest_pubkey`]; only the recipient can link the two.
pub fn generate_ephemeral_keys(recipient_address: &str) -> Result<EphemeralKeys> {
    let decoded = decode_stealth_address(recipient_address)?;
    generate_ephemeral_keys_for(&decoded.scan_pubkey, &decoded.spend_pubkey)
}

/// Derive a one-time destination from already-decoded recipient keys.
pub fn generate_ephemeral_keys_for(
    scan_pubkey: &PublicKey,
    spend_pubkey: &PublicKey,
) -> Result<EphemeralKeys> {
    let ephemeral_secret = generate_private_key();
    let ephemeral_pubkey = derive_public_key(&ephemeral_secret)?;

    // performEcdh already returns SHA256 of the shared point.
    let shared_secret = perform_ecdh(scan_pubkey, &ephemeral_secret)?;
    let dest_pubkey = point_add_scalar(spend_pubkey, &shared_secret)?;

    Ok(EphemeralKeys {
        ephemeral_pubkey,
        shared_secret,
        dest_pubkey,
        ephemeral_secret,
    })
}

/// Compute the shared secret and destination key for a given ephemeral secret.
pub fn stealth_secret(
    ephemeral_secret: &SecretKey,
    scan_pubkey: &PublicKey,
    spend_pubkey: &PublicKey,
) -> Result<([u8; 32], PublicKey)> {
    let shared_secret = perform_ecdh(scan_pubkey, ephemeral_secret)?;
    let dest_pubkey = point_add_scalar(spend_pubkey, &shared_secret)?;
    Ok((shared_secret, dest_pubkey))
}

/// Recover the secret key for a received stealth payment.
///
/// Computes `spend_secret + shared_secret (mod n)`.
pub fn derive_spend_key(
    spend_secret: &SecretKey,
    shared_secret: &[u8; 32],
) -> Result<SecretKey> {
    private_add(spend_secret, shared_secret)
}

/// Derive the one-time secret key for an output addressed to this wallet.
///
/// Computes `spend_secret + SHA256(ECDH(scan_secret, ephemeral_pubkey))`.
pub fn derive_destination_key(
    spend_secret: &SecretKey,
    scan_secret: &SecretKey,
    ephemeral_pubkey: &PublicKey,
) -> Result<SecretKey> {
    let shared = perform_ecdh(ephemeral_pubkey, scan_secret)?;
    private_add(spend_secret, &shared)
}

// ============================================================================
// Wallet creation
// ============================================================================

/// Create a wallet with freshly generated keys.
///
/// Back up both secrets: they are the only way to restore the wallet.
pub fn create_wallet() -> Result<VeilWallet> {
    let spend_secret = generate_private_key();
    let scan_secret = generate_private_key();
    build_wallet(spend_secret, scan_secret)
}

/// Restore a wallet from its two secret keys.
pub fn restore_wallet(spend_secret: &[u8], scan_secret: &[u8]) -> Result<VeilWallet> {
    if !is_valid_secret_key(spend_secret) {
        return Err(VeilError::invalid_input("invalid spend secret key"));
    }
    if !is_valid_secret_key(scan_secret) {
        return Err(VeilError::invalid_input("invalid scan secret key"));
    }

    build_wallet(slice_to_array(spend_secret)?, slice_to_array(scan_secret)?)
}

/// Restore a wallet from hex-encoded secret keys.
pub fn restore_wallet_from_hex(spend_secret_hex: &str, scan_secret_hex: &str) -> Result<VeilWallet> {
    let spend = crate::utils::hex_to_bytes(spend_secret_hex)?;
    let scan = crate::utils::hex_to_bytes(scan_secret_hex)?;
    restore_wallet(&spend, &scan)
}

fn build_wallet(spend_secret: SecretKey, scan_secret: SecretKey) -> Result<VeilWallet> {
    let spend_pubkey = derive_public_key(&spend_secret)?;
    let scan_pubkey = derive_public_key(&scan_secret)?;
    let stealth_address = generate_stealth_address(&scan_pubkey, &spend_pubkey, None)?;

    Ok(VeilWallet {
        spend_secret,
        scan_secret,
        spend_pubkey,
        scan_pubkey,
        stealth_address,
    })
}

// ============================================================================
// Validation
// ============================================================================

/// The outcome of validating an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressValidation {
    /// The address decoded and both keys are well-formed.
    Valid(DecodedStealthAddress),
    /// The address is unusable, with a human-readable reason.
    Invalid(String),
}

/// Validate an address, reporting why it failed when it does.
///
/// Prefer this over [`crate::utils::is_valid_stealth_address`] before sending
/// funds: it verifies the checksum and the embedded public keys.
pub fn validate_address(address: &str) -> AddressValidation {
    if address.is_empty() {
        return AddressValidation::Invalid("address cannot be empty".into());
    }

    if !address.starts_with("sv1") {
        return AddressValidation::Invalid(
            "invalid prefix: Veil stealth addresses start with sv1".into(),
        );
    }

    if address.len() < 60 {
        return AddressValidation::Invalid("address is too short".into());
    }

    match decode_stealth_address(address) {
        Ok(decoded) => {
            if !is_valid_public_key(&decoded.scan_pubkey) {
                return AddressValidation::Invalid("invalid scan public key in address".into());
            }
            if !is_valid_public_key(&decoded.spend_pubkey) {
                return AddressValidation::Invalid("invalid spend public key in address".into());
            }
            AddressValidation::Valid(decoded)
        }
        Err(e) => AddressValidation::Invalid(format!("invalid address format: {e}")),
    }
}

/// Whether an address is valid.
pub fn is_valid_address(address: &str) -> bool {
    matches!(validate_address(address), AddressValidation::Valid(_))
}

// ============================================================================
// bech32
// ============================================================================

/// Regroup bits between bases, padding on encode and rejecting slop on decode.
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
        return Err(VeilError::InvalidAddress("invalid padding".into()));
    }

    Ok(result)
}

fn polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];
    let mut chk: u32 = 1;

    for &value in values {
        let b = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(value);
        for (i, gen) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= gen;
            }
        }
    }

    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut result = Vec::with_capacity(hrp.len() * 2 + 1);
    for b in hrp.bytes() {
        result.push(b >> 5);
    }
    result.push(0);
    for b in hrp.bytes() {
        result.push(b & 31);
    }
    result
}

fn create_checksum(hrp: &str, data: &[u8]) -> Vec<u8> {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0, 0, 0, 0, 0, 0]);

    let modulus = polymod(&values) ^ BECH32_CONST;
    (0..6)
        .map(|i| ((modulus >> (5 * (5 - i))) & 31) as u8)
        .collect()
}

fn bech32_encode(hrp: &str, data: &[u8]) -> String {
    let checksum = create_checksum(hrp, data);
    let mut result = String::with_capacity(hrp.len() + 1 + data.len() + 6);
    result.push_str(hrp);
    result.push('1');
    for &value in data.iter().chain(checksum.iter()) {
        result.push(CHARSET[value as usize] as char);
    }
    result
}

fn bech32_decode(s: &str) -> Result<(String, Vec<u8>)> {
    let has_lower = s.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = s.chars().any(|c| c.is_ascii_uppercase());
    if has_lower && has_upper {
        return Err(VeilError::InvalidAddress("mixed case string".into()));
    }

    let lowered = s.to_ascii_lowercase();

    let pos = lowered
        .rfind('1')
        .ok_or_else(|| VeilError::InvalidAddress("missing separator".into()))?;

    if pos < 1 || pos + 7 > lowered.len() || lowered.len() > MAX_ADDRESS_LENGTH {
        return Err(VeilError::InvalidAddress("invalid bech32 string".into()));
    }

    let hrp = lowered[..pos].to_string();
    let mut data = Vec::with_capacity(lowered.len() - pos - 1);

    for c in lowered[pos + 1..].bytes() {
        let value = CHARSET
            .iter()
            .position(|&x| x == c)
            .ok_or_else(|| VeilError::InvalidAddress("invalid bech32 character".into()))?;
        data.push(value as u8);
    }

    let mut values = hrp_expand(&hrp);
    values.extend_from_slice(&data);
    if polymod(&values) != BECH32_CONST {
        return Err(VeilError::InvalidAddress("invalid bech32 checksum".into()));
    }

    data.truncate(data.len() - 6);
    Ok((hrp, data))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_wallet() -> VeilWallet {
        restore_wallet(&[0x11u8; 32], &[0x22u8; 32]).unwrap()
    }

    #[test]
    fn created_wallet_has_consistent_keys() {
        let wallet = create_wallet().unwrap();
        assert_eq!(
            derive_public_key(&wallet.spend_secret).unwrap(),
            wallet.spend_pubkey
        );
        assert_eq!(
            derive_public_key(&wallet.scan_secret).unwrap(),
            wallet.scan_pubkey
        );
        assert!(wallet.stealth_address.starts_with("sv1"));
    }

    #[test]
    fn restore_is_deterministic() {
        let a = test_wallet();
        let b = test_wallet();
        assert_eq!(a, b);
    }

    #[test]
    fn restore_from_hex_matches_restore_from_bytes() {
        let from_bytes = test_wallet();
        let from_hex = restore_wallet_from_hex(&"11".repeat(32), &"22".repeat(32)).unwrap();
        assert_eq!(from_bytes, from_hex);
    }

    #[test]
    fn restore_rejects_wrong_length_keys() {
        assert!(restore_wallet(&[0x11u8; 31], &[0x22u8; 32]).is_err());
        assert!(restore_wallet(&[0x11u8; 32], &[0x22u8; 33]).is_err());
    }

    #[test]
    fn address_round_trips_through_bech32() {
        let wallet = test_wallet();
        let decoded = decode_stealth_address(&wallet.stealth_address).unwrap();
        assert_eq!(decoded.scan_pubkey, wallet.scan_pubkey);
        assert_eq!(decoded.spend_pubkey, wallet.spend_pubkey);
        assert_eq!(decoded.options, 0);
        assert_eq!(decoded.number_signatures, 0);
        assert_eq!(decoded.prefix_number_bits, 0);
    }

    #[test]
    fn generated_address_passes_surface_validation() {
        let wallet = test_wallet();
        // The address length must fall inside the range utils.rs enforces.
        assert!(crate::utils::is_valid_stealth_address(
            &wallet.stealth_address
        ));
    }

    #[test]
    fn address_with_prefix_bits_round_trips() {
        let wallet = test_wallet();
        let options = StealthAddressOptions {
            options: 0,
            number_signatures: 1,
            prefix_number_bits: 8,
            prefix_bitfield: 0xdead_beef,
        };
        let address =
            generate_stealth_address(&wallet.scan_pubkey, &wallet.spend_pubkey, Some(options))
                .unwrap();

        let decoded = decode_stealth_address(&address).unwrap();
        assert_eq!(decoded.number_signatures, 1);
        assert_eq!(decoded.prefix_number_bits, 8);
        assert_eq!(decoded.prefix_bitfield, 0xdead_beef);
    }

    #[test]
    fn corrupted_checksum_is_rejected() {
        let wallet = test_wallet();
        let mut chars: Vec<char> = wallet.stealth_address.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == 'q' { 'p' } else { 'q' };
        let corrupted: String = chars.into_iter().collect();

        assert!(decode_stealth_address(&corrupted).is_err());
        assert!(!is_valid_address(&corrupted));
    }

    #[test]
    fn validation_rejects_malformed_input() {
        assert!(matches!(
            validate_address(""),
            AddressValidation::Invalid(_)
        ));
        assert!(matches!(
            validate_address("bv1qqqq"),
            AddressValidation::Invalid(_)
        ));
        assert!(matches!(
            validate_address("sv1qq"),
            AddressValidation::Invalid(_)
        ));
    }

    #[test]
    fn validation_accepts_a_generated_address() {
        let wallet = test_wallet();
        assert!(is_valid_address(&wallet.stealth_address));
        match validate_address(&wallet.stealth_address) {
            AddressValidation::Valid(decoded) => {
                assert_eq!(decoded.spend_pubkey, wallet.spend_pubkey);
            }
            AddressValidation::Invalid(e) => panic!("expected a valid address, got: {e}"),
        }
    }

    #[test]
    fn sender_and_recipient_agree_on_the_destination_key() {
        let wallet = test_wallet();

        let ephemeral = generate_ephemeral_keys(&wallet.stealth_address).unwrap();

        // The recipient recomputes the shared secret from the published key.
        let recipient_secret = derive_destination_key(
            &wallet.spend_secret,
            &wallet.scan_secret,
            &ephemeral.ephemeral_pubkey,
        )
        .unwrap();

        assert_eq!(
            derive_public_key(&recipient_secret).unwrap(),
            ephemeral.dest_pubkey
        );
    }

    #[test]
    fn stealth_secret_matches_generate_ephemeral_keys() {
        let wallet = test_wallet();
        let ephemeral_secret = [0x44u8; 32];

        let (shared, dest) = stealth_secret(
            &ephemeral_secret,
            &wallet.scan_pubkey,
            &wallet.spend_pubkey,
        )
        .unwrap();

        assert_eq!(
            derive_spend_key(&wallet.spend_secret, &shared)
                .and_then(|sk| derive_public_key(&sk))
                .unwrap(),
            dest
        );
    }

    #[test]
    fn convert_bits_round_trips() {
        let data = [0x00, 0x01, 0x02, 0xff, 0xfe];
        let words = convert_bits(&data, 8, 5, true).unwrap();
        let back = convert_bits(&words, 5, 8, false).unwrap();
        assert_eq!(back, data);
    }
}
