//! Hierarchical deterministic wallets: BIP39 seeds and BIP32 derivation.
//!
//! Port of the key-derivation half of the Dart `veil_light_plugin`:
//! `Lightwallet` (`lib/src/veil/lightwallet.dart`), `LightwalletAccount`
//! (`lib/src/veil/lightwallet_account.dart`), and the key accessors of
//! `LightwalletAddress` (`lib/src/veil/lightwallet_address.dart`).
//!
//! The Dart code builds the tree with the `bip39` and `bip32` pub packages. Both
//! are reimplemented here directly rather than pulled in as dependencies, so the
//! derivation is byte-for-byte the same without adding a BIP32 crate.
//!
//! ## The derivation tree
//!
//! Every node below the coin level is hardened, matching Dart:
//!
//! ```text
//! m                                  BIP32.fromSeed(mnemonicSeed)
//! └─ 44'                             derive(BIP44_PURPOSE)
//!    └─ 698'                         derive(chainParams.nBIP44ID)
//!       └─ <account_id>'             deriveHardened(accountId)
//!          └─ 20000'                 deriveHardened(nRingCTAccount)
//!             └─ 1' | 2' | 3'        DEFAULT | STEALTH | CHANGE
//!                └─ <index>'         the address key
//!                   ├─ 1'            scan key
//!                   └─ 2'            spend key
//! ```
//!
//! So the scan and spend secrets for the first default address are
//! `m/44'/698'/0'/20000'/1'/0'/1'` and `m/44'/698'/0'/20000'/1'/0'/2'`.
//!
//! ## Example
//!
//! ```
//! use veilrustlib::hdwallet::{derive_stealth_keys, AccountType};
//!
//! let mnemonic = "abandon abandon abandon abandon abandon abandon \
//!                 abandon abandon abandon abandon abandon about";
//!
//! let keys = derive_stealth_keys(mnemonic, "", 0, AccountType::Default, 0)?;
//! assert!(keys.stealth_address()?.starts_with("sv1"));
//! # Ok::<(), veilrustlib::VeilError>(())
//! ```

use crate::crypto::{derive_public_key, hash160, private_add};
use crate::error::{Result, VeilError};
use crate::stealth::{generate_stealth_address, VeilWallet};
use crate::types::{PublicKey, SecretKey};
use crate::utils::slice_to_array;
use hmac::{Hmac, Mac};
use sha2::Sha512;

/// Index offset that marks a derivation step as hardened.
pub const HARDENED_OFFSET: u32 = 0x8000_0000;

/// Largest index accepted by [`ExtendedKey::derive_hardened`], i.e. `2^31 - 1`.
pub const MAX_HARDENED_INDEX: u32 = HARDENED_OFFSET - 1;

/// BIP44 purpose node, already hardened.
///
/// Dart passes this to `derive`, not `deriveHardened`, because the constant
/// already has the hardened bit set.
pub const BIP44_PURPOSE: u32 = 0x8000_002C;

/// Veil's BIP44 coin type, already hardened. `Chainparams.nBIP44ID`.
pub const VEIL_BIP44_ID: u32 = 0x8000_02ba;

/// Veil's RingCT account branch. `Chainparams.nRingCTAccount`.
pub const VEIL_RINGCT_ACCOUNT: u32 = 20000;

/// HMAC key used to turn a seed into a master key, per BIP32.
const MASTER_SEED_KEY: &[u8] = b"Bitcoin seed";

/// PBKDF2 salt prefix used by BIP39.
const MNEMONIC_SALT_PREFIX: &str = "mnemonic";

/// PBKDF2 iteration count used by BIP39.
const MNEMONIC_ITERATIONS: u32 = 2048;

/// Length of a BIP39 seed.
pub const SEED_SIZE: usize = 64;

/// Shortest seed BIP32 accepts, in bytes.
const MIN_SEED_SIZE: usize = 16;

/// Longest seed BIP32 accepts, in bytes.
const MAX_SEED_SIZE: usize = 64;

type HmacSha512 = Hmac<Sha512>;

/// Which branch of the RingCT account an address belongs to.
///
/// Mirrors the Dart `AccountType` enum, including its `value`. Note that the
/// branch index used for derivation is `value + 1`, because Dart derives
/// `1'`, `2'`, and `3'` under `keyMasterAnon`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum AccountType {
    /// Receiving addresses. `AccountType.DEFAULT`, derived from `1'`.
    #[default]
    Default,
    /// Stealth addresses. `AccountType.STEALTH`, derived from `2'`.
    Stealth,
    /// Change addresses. `AccountType.CHANGE`, derived from `3'`.
    Change,
}

impl AccountType {
    /// The value carried by the Dart enum: 0, 1, or 2.
    pub fn value(self) -> u32 {
        match self {
            AccountType::Default => 0,
            AccountType::Stealth => 1,
            AccountType::Change => 2,
        }
    }

    /// The hardened child index of this branch under the RingCT account.
    pub fn branch_index(self) -> u32 {
        self.value() + 1
    }

    /// Recover an [`AccountType`] from its Dart enum value.
    ///
    /// # Errors
    ///
    /// Returns [`VeilError::InvalidInput`] for values other than 0, 1, or 2.
    pub fn from_value(value: u32) -> Result<Self> {
        match value {
            0 => Ok(AccountType::Default),
            1 => Ok(AccountType::Stealth),
            2 => Ok(AccountType::Change),
            other => Err(VeilError::invalid_input(format!(
                "unknown account type {other}, expected 0, 1, or 2"
            ))),
        }
    }
}

// ============================================================================
// BIP39
// ============================================================================

/// PBKDF2-HMAC-SHA512, the only KDF BIP39 uses.
fn pbkdf2_hmac_sha512(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    const HASH_LEN: usize = 64;

    for (block_index, chunk) in out.chunks_mut(HASH_LEN).enumerate() {
        // Blocks are numbered from 1, and the counter is appended big-endian.
        let counter = (block_index as u32 + 1).to_be_bytes();

        let mut mac = HmacSha512::new_from_slice(password)
            .expect("HMAC accepts keys of any length");
        mac.update(salt);
        mac.update(&counter);
        let mut u = mac.finalize().into_bytes();

        let mut accumulator = u;
        for _ in 1..iterations {
            let mut mac = HmacSha512::new_from_slice(password)
                .expect("HMAC accepts keys of any length");
            mac.update(&u);
            u = mac.finalize().into_bytes();

            for (acc, byte) in accumulator.iter_mut().zip(u.iter()) {
                *acc ^= byte;
            }
        }

        chunk.copy_from_slice(&accumulator[..chunk.len()]);
    }
}

/// Turn a mnemonic into a 64-byte BIP39 seed.
///
/// This matches Dart's `bip39.mnemonicToSeed`: the mnemonic is used verbatim as
/// the PBKDF2 password and `"mnemonic" + passphrase` as the salt, with 2048
/// iterations of HMAC-SHA512.
///
/// Two deliberate omissions, both matching the Dart package:
///
/// - the mnemonic is **not** validated, so an invalid phrase silently yields a
///   seed; call [`verify_mnemonic_shape`] first if that matters
/// - the mnemonic is **not** NFKD-normalized, so non-ASCII wordlists may not
///   agree with fully BIP39-compliant implementations
pub fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> [u8; SEED_SIZE] {
    let salt = format!("{MNEMONIC_SALT_PREFIX}{passphrase}");
    let mut seed = [0u8; SEED_SIZE];
    pbkdf2_hmac_sha512(
        mnemonic.as_bytes(),
        salt.as_bytes(),
        MNEMONIC_ITERATIONS,
        &mut seed,
    );
    seed
}

/// Check that a mnemonic has a plausible BIP39 shape.
///
/// This verifies the word count only; it does not check the words against a
/// wordlist or verify the checksum, so it cannot detect a typo. It exists to
/// catch obviously malformed input before [`mnemonic_to_seed`] turns it into a
/// seed for a wallet that will never receive funds.
pub fn verify_mnemonic_shape(mnemonic: &str) -> bool {
    let words = mnemonic.split_whitespace().count();
    matches!(words, 12 | 15 | 18 | 21 | 24)
}

/// Normalize a mnemonic to single-space-separated words.
///
/// Dart callers pass a `List<String>` and join with a space; this is the
/// equivalent for input that may carry stray or repeated whitespace.
pub fn normalize_mnemonic(mnemonic: &str) -> String {
    mnemonic.split_whitespace().collect::<Vec<_>>().join(" ")
}

// ============================================================================
// BIP32
// ============================================================================

/// A BIP32 extended private key.
///
/// Only private nodes are modelled: every derivation in Veil's tree is hardened,
/// which a neutered (public-only) node cannot perform.
#[derive(Clone)]
pub struct ExtendedKey {
    secret: SecretKey,
    chain_code: [u8; 32],
    depth: u8,
    index: u32,
    parent_fingerprint: u32,
}

impl std::fmt::Debug for ExtendedKey {
    /// Deliberately omits the secret key and chain code so a node cannot leak
    /// into logs through a derived `Debug` impl.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtendedKey")
            .field("depth", &self.depth)
            .field("index", &self.index)
            .field("parent_fingerprint", &self.parent_fingerprint)
            .finish_non_exhaustive()
    }
}

impl ExtendedKey {
    /// Derive the master key from a seed, per BIP32.
    ///
    /// # Errors
    ///
    /// Returns [`VeilError::InvalidInput`] when the seed is outside the 16..=64
    /// byte range BIP32 allows, or in the negligible case that the seed hashes
    /// to an out-of-range key.
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        if seed.len() < MIN_SEED_SIZE {
            return Err(VeilError::invalid_input(format!(
                "seed must be at least {MIN_SEED_SIZE} bytes, got {}",
                seed.len()
            )));
        }
        if seed.len() > MAX_SEED_SIZE {
            return Err(VeilError::invalid_input(format!(
                "seed must be at most {MAX_SEED_SIZE} bytes, got {}",
                seed.len()
            )));
        }

        let mut mac =
            HmacSha512::new_from_slice(MASTER_SEED_KEY).expect("HMAC accepts keys of any length");
        mac.update(seed);
        let digest = mac.finalize().into_bytes();

        let secret: SecretKey = slice_to_array(&digest[..32])?;
        let chain_code: [u8; 32] = slice_to_array(&digest[32..])?;

        if !crate::crypto::is_secret_key_in_range(&secret) {
            return Err(VeilError::invalid_input(
                "seed produced an out-of-range master key",
            ));
        }

        Ok(Self {
            secret,
            chain_code,
            depth: 0,
            index: 0,
            parent_fingerprint: 0,
        })
    }

    /// The node's private key.
    ///
    /// This is secret material; do not log it.
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret
    }

    /// The node's compressed public key.
    pub fn public_key(&self) -> Result<PublicKey> {
        derive_public_key(&self.secret)
    }

    /// The node's chain code.
    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }

    /// Depth below the master key.
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// The child index this node was derived at.
    pub fn index(&self) -> u32 {
        self.index
    }

    /// The first four bytes of `hash160(public_key)`.
    pub fn fingerprint(&self) -> Result<[u8; 4]> {
        let identifier = hash160(&self.public_key()?);
        slice_to_array(&identifier[..4])
    }

    /// Derive a child node.
    ///
    /// Indices at or above [`HARDENED_OFFSET`] are hardened. As in BIP32 and in
    /// Dart's `bip32`, an index that yields an invalid key falls through to
    /// `index + 1`.
    ///
    /// # Errors
    ///
    /// Returns [`VeilError::InvalidInput`] when the fallback would overflow past
    /// the end of the index space.
    pub fn derive(&self, index: u32) -> Result<Self> {
        let mut data = [0u8; 37];

        if index >= HARDENED_OFFSET {
            // Hardened: commit to the parent private key.
            data[0] = 0x00;
            data[1..33].copy_from_slice(&self.secret);
        } else {
            data[..33].copy_from_slice(&self.public_key()?);
        }
        data[33..].copy_from_slice(&index.to_be_bytes());

        let mut mac = HmacSha512::new_from_slice(&self.chain_code)
            .expect("HMAC accepts keys of any length");
        mac.update(&data);
        let digest = mac.finalize().into_bytes();

        let tweak: SecretKey = slice_to_array(&digest[..32])?;
        let chain_code: [u8; 32] = slice_to_array(&digest[32..])?;

        // BIP32: if IL is out of range, or the sum is zero, skip this index.
        let child_secret = if crate::crypto::is_secret_key_in_range(&tweak) {
            private_add(&self.secret, &tweak).ok()
        } else {
            None
        };

        let Some(secret) = child_secret else {
            let next = index.checked_add(1).ok_or_else(|| {
                VeilError::invalid_input("no valid child key below the end of the index space")
            })?;

            // Never silently cross from hardened into non-hardened territory.
            if (index < HARDENED_OFFSET) != (next < HARDENED_OFFSET) {
                return Err(VeilError::invalid_input(
                    "no valid child key within this index range",
                ));
            }

            return self.derive(next);
        };

        Ok(Self {
            secret,
            chain_code,
            depth: self.depth.saturating_add(1),
            index,
            parent_fingerprint: u32::from_be_bytes(self.fingerprint()?),
        })
    }

    /// Derive a hardened child, adding [`HARDENED_OFFSET`] to `index`.
    ///
    /// # Errors
    ///
    /// Returns [`VeilError::InvalidInput`] when `index` exceeds
    /// [`MAX_HARDENED_INDEX`].
    pub fn derive_hardened(&self, index: u32) -> Result<Self> {
        if index > MAX_HARDENED_INDEX {
            return Err(VeilError::invalid_input(format!(
                "hardened index must be at most {MAX_HARDENED_INDEX}, got {index}"
            )));
        }

        self.derive(index + HARDENED_OFFSET)
    }

    /// Derive along a path such as `m/44'/698'/0'`.
    ///
    /// A leading `m/` is optional and only allowed on a master node. Both `'`
    /// and `h` mark a step as hardened.
    ///
    /// # Errors
    ///
    /// Returns [`VeilError::InvalidInput`] for a malformed path, or for a path
    /// rooted at `m` applied to a non-master node.
    pub fn derive_path(&self, path: &str) -> Result<Self> {
        let mut segments = path.split('/').peekable();

        if matches!(segments.peek(), Some(&"m") | Some(&"M")) {
            if self.depth != 0 {
                return Err(VeilError::invalid_input(
                    "a path rooted at m can only be derived from a master key",
                ));
            }
            segments.next();
        }

        let mut current = self.clone();

        for segment in segments {
            if segment.is_empty() {
                return Err(VeilError::invalid_input(format!(
                    "malformed derivation path: {path}"
                )));
            }

            let (digits, hardened) = match segment.strip_suffix(['\'', 'h', 'H']) {
                Some(digits) => (digits, true),
                None => (segment, false),
            };

            let index: u32 = digits.parse().map_err(|_| {
                VeilError::invalid_input(format!("invalid path segment: {segment}"))
            })?;

            current = if hardened {
                current.derive_hardened(index)?
            } else {
                current.derive(index)?
            };
        }

        Ok(current)
    }
}

// ============================================================================
// Veil wallet tree
// ============================================================================

/// A Veil light wallet derived from a seed.
///
/// Port of the Dart `Lightwallet`, minus the storage and RPC members: this type
/// holds only the coin-level key, which is all that key derivation needs.
#[derive(Debug, Clone)]
pub struct HdWallet {
    coin_key: ExtendedKey,
}

impl HdWallet {
    /// Build a wallet from a mnemonic and optional passphrase.
    ///
    /// Equivalent to Dart's `Lightwallet.fromMnemonic`.
    pub fn from_mnemonic(mnemonic: &str, passphrase: &str) -> Result<Self> {
        let seed = mnemonic_to_seed(&normalize_mnemonic(mnemonic), passphrase);
        Self::from_seed(&seed)
    }

    /// Build a wallet from a raw BIP39 seed.
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        let master = ExtendedKey::from_seed(seed)?;

        // Dart calls `derive` here, not `deriveHardened`: both constants
        // already carry the hardened bit.
        let purpose_key = master.derive(BIP44_PURPOSE)?;
        let coin_key = purpose_key.derive(VEIL_BIP44_ID)?;

        Ok(Self { coin_key })
    }

    /// The coin-level key, `m/44'/698'`. Dart's `getKeyCoin`.
    pub fn coin_key(&self) -> &ExtendedKey {
        &self.coin_key
    }

    /// Open one of the wallet's accounts.
    ///
    /// Equivalent to constructing Dart's `LightwalletAccount`.
    pub fn account(&self, account_id: u32) -> Result<HdAccount> {
        HdAccount::new(&self.coin_key, account_id)
    }
}

/// One account of an [`HdWallet`], holding its three RingCT branches.
///
/// Port of the Dart `LightwalletAccount` constructor.
#[derive(Debug, Clone)]
pub struct HdAccount {
    account_id: u32,
    default_account: ExtendedKey,
    stealth_account: ExtendedKey,
    change_account: ExtendedKey,
}

impl HdAccount {
    fn new(coin_key: &ExtendedKey, account_id: u32) -> Result<Self> {
        let wallet_account = coin_key.derive_hardened(account_id)?;
        let key_master_anon = wallet_account.derive_hardened(VEIL_RINGCT_ACCOUNT)?;

        Ok(Self {
            account_id,
            default_account: key_master_anon.derive_hardened(AccountType::Default.branch_index())?,
            stealth_account: key_master_anon.derive_hardened(AccountType::Stealth.branch_index())?,
            change_account: key_master_anon.derive_hardened(AccountType::Change.branch_index())?,
        })
    }

    /// The account index this was opened at.
    pub fn account_id(&self) -> u32 {
        self.account_id
    }

    /// The branch key for `account_type`. Dart's `getAccount`.
    pub fn branch_key(&self, account_type: AccountType) -> &ExtendedKey {
        match account_type {
            AccountType::Default => &self.default_account,
            AccountType::Stealth => &self.stealth_account,
            AccountType::Change => &self.change_account,
        }
    }

    /// Derive the address key at `index` under `account_type`.
    ///
    /// This is the `_addressKey` of Dart's `LightwalletAddress`; the scan and
    /// spend keys hang off it.
    pub fn address_key(&self, account_type: AccountType, index: u32) -> Result<ExtendedKey> {
        self.branch_key(account_type).derive_hardened(index)
    }

    /// Extract the scan and spend keys for one address.
    ///
    /// Matches Dart's `getScanKey` (`1'`) and `getSpendKey` (`2'`).
    pub fn stealth_keys(&self, account_type: AccountType, index: u32) -> Result<StealthKeys> {
        let address_key = self.address_key(account_type, index)?;

        let scan_key = address_key.derive_hardened(1)?;
        let spend_key = address_key.derive_hardened(2)?;

        Ok(StealthKeys {
            scan_secret: *scan_key.secret_key(),
            spend_secret: *spend_key.secret_key(),
            scan_pubkey: scan_key.public_key()?,
            spend_pubkey: spend_key.public_key()?,
            account_type,
            index,
        })
    }
}

/// The scan and spend key pair for a single derived address.
#[derive(Clone, PartialEq, Eq)]
pub struct StealthKeys {
    /// Scan secret key. Keep this secret.
    pub scan_secret: SecretKey,
    /// Spend secret key. Keep this secret.
    pub spend_secret: SecretKey,
    /// Scan public key.
    pub scan_pubkey: PublicKey,
    /// Spend public key.
    pub spend_pubkey: PublicKey,
    /// The branch this address came from.
    pub account_type: AccountType,
    /// The address index within the branch.
    pub index: u32,
}

impl std::fmt::Debug for StealthKeys {
    /// Deliberately omits both secrets.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StealthKeys")
            .field("account_type", &self.account_type)
            .field("index", &self.index)
            .field("scan_pubkey", &hex::encode(self.scan_pubkey))
            .field("spend_pubkey", &hex::encode(self.spend_pubkey))
            .finish_non_exhaustive()
    }
}

impl StealthKeys {
    /// Encode the bech32 stealth address for these keys.
    ///
    /// Equivalent to Dart's `LightwalletAddress.getStringAddress`.
    pub fn stealth_address(&self) -> Result<String> {
        generate_stealth_address(&self.scan_pubkey, &self.spend_pubkey, None)
    }

    /// The spend key hash Dart stores as `spend_secret_id`.
    pub fn spend_secret_id(&self) -> [u8; 20] {
        hash160(&self.spend_secret)
    }

    /// Convert into the [`VeilWallet`] the rest of this crate takes.
    pub fn to_wallet(&self) -> Result<VeilWallet> {
        crate::stealth::restore_wallet(&self.spend_secret, &self.scan_secret)
    }
}

/// Derive the scan and spend keys for one address straight from a mnemonic.
///
/// Convenience wrapper over [`HdWallet::from_mnemonic`],
/// [`HdWallet::account`], and [`HdAccount::stealth_keys`].
pub fn derive_stealth_keys(
    mnemonic: &str,
    passphrase: &str,
    account_id: u32,
    account_type: AccountType,
    index: u32,
) -> Result<StealthKeys> {
    HdWallet::from_mnemonic(mnemonic, passphrase)?
        .account(account_id)?
        .stealth_keys(account_type, index)
}

/// Derive the scan and spend keys for one address from a raw BIP39 seed.
pub fn derive_stealth_keys_from_seed(
    seed: &[u8],
    account_id: u32,
    account_type: AccountType,
    index: u32,
) -> Result<StealthKeys> {
    HdWallet::from_seed(seed)?
        .account(account_id)?
        .stealth_keys(account_type, index)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The BIP39 all-`abandon` test vector.
    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon \
                                 abandon abandon abandon abandon abandon about";

    #[test]
    fn mnemonic_to_seed_matches_the_bip39_test_vector() {
        // Vector 1 from BIP39's English test vectors, passphrase "TREZOR".
        let seed = mnemonic_to_seed(TEST_MNEMONIC, "TREZOR");
        assert_eq!(
            hex::encode(seed),
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553\
             1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        );
    }

    #[test]
    fn mnemonic_to_seed_matches_the_empty_passphrase_vector() {
        let seed = mnemonic_to_seed(TEST_MNEMONIC, "");
        assert_eq!(
            hex::encode(seed),
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1\
             9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
        );
    }

    #[test]
    fn master_key_matches_the_bip32_test_vector() {
        // BIP32 test vector 1: seed 000102030405060708090a0b0c0d0e0f.
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedKey::from_seed(&seed).unwrap();

        assert_eq!(
            hex::encode(master.secret_key()),
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        );
        assert_eq!(
            hex::encode(master.chain_code()),
            "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"
        );
        assert_eq!(master.depth(), 0);
    }

    #[test]
    fn hardened_derivation_matches_the_bip32_test_vector() {
        // BIP32 test vector 1, chain m/0'.
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let child = ExtendedKey::from_seed(&seed)
            .unwrap()
            .derive_hardened(0)
            .unwrap();

        assert_eq!(
            hex::encode(child.secret_key()),
            "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"
        );
        assert_eq!(
            hex::encode(child.chain_code()),
            "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"
        );
        assert_eq!(child.depth(), 1);
        assert_eq!(child.index(), HARDENED_OFFSET);
    }

    #[test]
    fn non_hardened_derivation_matches_the_bip32_test_vector() {
        // BIP32 test vector 1, chain m/0'/1.
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let child = ExtendedKey::from_seed(&seed)
            .unwrap()
            .derive_hardened(0)
            .unwrap()
            .derive(1)
            .unwrap();

        assert_eq!(
            hex::encode(child.secret_key()),
            "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368"
        );
        assert_eq!(
            hex::encode(child.chain_code()),
            "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19"
        );
    }

    #[test]
    fn derive_path_matches_step_by_step_derivation() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedKey::from_seed(&seed).unwrap();

        let stepwise = master
            .derive_hardened(0)
            .unwrap()
            .derive(1)
            .unwrap()
            .derive_hardened(2)
            .unwrap();
        let by_path = master.derive_path("m/0'/1/2'").unwrap();

        assert_eq!(stepwise.secret_key(), by_path.secret_key());
        assert_eq!(stepwise.chain_code(), by_path.chain_code());

        // 'h' is accepted as a hardened marker, and the leading m/ is optional.
        let alternate = master.derive_path("0h/1/2h").unwrap();
        assert_eq!(alternate.secret_key(), by_path.secret_key());
    }

    #[test]
    fn derive_path_rejects_malformed_input() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedKey::from_seed(&seed).unwrap();

        assert!(master.derive_path("m/0'//1").is_err());
        assert!(master.derive_path("m/notanumber").is_err());
        assert!(master.derive_path("m/4294967296").is_err());

        // A path rooted at m is only valid on a master node.
        let child = master.derive_hardened(0).unwrap();
        assert!(child.derive_path("m/0'").is_err());
    }

    #[test]
    fn seed_length_is_bounded() {
        assert!(ExtendedKey::from_seed(&[0u8; 15]).is_err());
        assert!(ExtendedKey::from_seed(&[0u8; 16]).is_ok());
        assert!(ExtendedKey::from_seed(&[0u8; 64]).is_ok());
        assert!(ExtendedKey::from_seed(&[0u8; 65]).is_err());
    }

    #[test]
    fn hardened_index_is_bounded() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedKey::from_seed(&seed).unwrap();

        assert!(master.derive_hardened(MAX_HARDENED_INDEX).is_ok());
        assert!(master.derive_hardened(HARDENED_OFFSET).is_err());
    }

    #[test]
    fn account_type_values_match_the_dart_enum() {
        assert_eq!(AccountType::Default.value(), 0);
        assert_eq!(AccountType::Stealth.value(), 1);
        assert_eq!(AccountType::Change.value(), 2);

        // Dart derives 1', 2', and 3' under keyMasterAnon.
        assert_eq!(AccountType::Default.branch_index(), 1);
        assert_eq!(AccountType::Stealth.branch_index(), 2);
        assert_eq!(AccountType::Change.branch_index(), 3);

        assert_eq!(AccountType::from_value(0).unwrap(), AccountType::Default);
        assert_eq!(AccountType::from_value(2).unwrap(), AccountType::Change);
        assert!(AccountType::from_value(3).is_err());
    }

    #[test]
    fn keys_follow_the_documented_derivation_path() {
        let wallet = HdWallet::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let keys = wallet
            .account(0)
            .unwrap()
            .stealth_keys(AccountType::Default, 0)
            .unwrap();

        // The same secrets must fall out of an explicit path derivation.
        let master = ExtendedKey::from_seed(&mnemonic_to_seed(TEST_MNEMONIC, "")).unwrap();
        let address_key = master.derive_path("m/44'/698'/0'/20000'/1'/0'").unwrap();

        assert_eq!(
            keys.scan_secret,
            *address_key.derive_hardened(1).unwrap().secret_key()
        );
        assert_eq!(
            keys.spend_secret,
            *address_key.derive_hardened(2).unwrap().secret_key()
        );
    }

    #[test]
    fn derivation_is_deterministic() {
        let first = derive_stealth_keys(TEST_MNEMONIC, "", 0, AccountType::Default, 0).unwrap();
        let second = derive_stealth_keys(TEST_MNEMONIC, "", 0, AccountType::Default, 0).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn branches_indexes_accounts_and_passphrases_all_change_the_keys() {
        let base = derive_stealth_keys(TEST_MNEMONIC, "", 0, AccountType::Default, 0).unwrap();

        let other_branch =
            derive_stealth_keys(TEST_MNEMONIC, "", 0, AccountType::Change, 0).unwrap();
        let other_index = derive_stealth_keys(TEST_MNEMONIC, "", 0, AccountType::Default, 1).unwrap();
        let other_account =
            derive_stealth_keys(TEST_MNEMONIC, "", 1, AccountType::Default, 0).unwrap();
        let with_passphrase =
            derive_stealth_keys(TEST_MNEMONIC, "hunter2", 0, AccountType::Default, 0).unwrap();

        for other in [other_branch, other_index, other_account, with_passphrase] {
            assert_ne!(base.scan_secret, other.scan_secret);
            assert_ne!(base.spend_secret, other.spend_secret);
        }
    }

    #[test]
    fn scan_and_spend_keys_differ() {
        let keys = derive_stealth_keys(TEST_MNEMONIC, "", 0, AccountType::Default, 0).unwrap();
        assert_ne!(keys.scan_secret, keys.spend_secret);
        assert_ne!(keys.scan_pubkey, keys.spend_pubkey);
    }

    #[test]
    fn public_keys_match_their_secrets() {
        let keys = derive_stealth_keys(TEST_MNEMONIC, "", 0, AccountType::Default, 0).unwrap();
        assert_eq!(derive_public_key(&keys.scan_secret).unwrap(), keys.scan_pubkey);
        assert_eq!(
            derive_public_key(&keys.spend_secret).unwrap(),
            keys.spend_pubkey
        );
    }

    #[test]
    fn derived_keys_produce_a_valid_stealth_address() {
        let keys = derive_stealth_keys(TEST_MNEMONIC, "", 0, AccountType::Default, 0).unwrap();
        let address = keys.stealth_address().unwrap();

        assert!(crate::stealth::is_valid_address(&address));

        let decoded = crate::stealth::decode_stealth_address(&address).unwrap();
        assert_eq!(decoded.scan_pubkey, keys.scan_pubkey);
        assert_eq!(decoded.spend_pubkey, keys.spend_pubkey);
    }

    #[test]
    fn wallet_conversion_keeps_the_same_address() {
        let keys = derive_stealth_keys(TEST_MNEMONIC, "", 0, AccountType::Default, 0).unwrap();
        let wallet = keys.to_wallet().unwrap();

        assert_eq!(wallet.stealth_address, keys.stealth_address().unwrap());
        assert_eq!(wallet.scan_secret, keys.scan_secret);
        assert_eq!(wallet.spend_secret, keys.spend_secret);
    }

    #[test]
    fn mnemonic_and_seed_entry_points_agree() {
        let seed = mnemonic_to_seed(TEST_MNEMONIC, "");
        let from_mnemonic =
            derive_stealth_keys(TEST_MNEMONIC, "", 0, AccountType::Default, 0).unwrap();
        let from_seed =
            derive_stealth_keys_from_seed(&seed, 0, AccountType::Default, 0).unwrap();

        assert_eq!(from_mnemonic, from_seed);
    }

    #[test]
    fn extra_whitespace_in_a_mnemonic_is_normalized_away() {
        let messy = format!("  {}  ", TEST_MNEMONIC.replace(' ', "   "));
        assert_eq!(normalize_mnemonic(&messy), TEST_MNEMONIC);

        let from_messy = derive_stealth_keys(&messy, "", 0, AccountType::Default, 0).unwrap();
        let from_clean = derive_stealth_keys(TEST_MNEMONIC, "", 0, AccountType::Default, 0).unwrap();
        assert_eq!(from_messy, from_clean);
    }

    #[test]
    fn mnemonic_shape_check_counts_words() {
        assert!(verify_mnemonic_shape(TEST_MNEMONIC));
        assert!(verify_mnemonic_shape(&"abandon ".repeat(24)));
        assert!(!verify_mnemonic_shape("abandon abandon"));
        assert!(!verify_mnemonic_shape(""));
    }

    #[test]
    fn secrets_are_kept_out_of_debug_output() {
        let keys = derive_stealth_keys(TEST_MNEMONIC, "", 0, AccountType::Default, 0).unwrap();

        let rendered = format!("{keys:?}");
        assert!(!rendered.contains(&hex::encode(keys.scan_secret)));
        assert!(!rendered.contains(&hex::encode(keys.spend_secret)));

        let master = ExtendedKey::from_seed(&mnemonic_to_seed(TEST_MNEMONIC, "")).unwrap();
        let rendered = format!("{master:?}");
        assert!(!rendered.contains(&hex::encode(master.secret_key())));
        assert!(!rendered.contains(&hex::encode(master.chain_code())));
    }

    #[test]
    fn spend_secret_id_is_the_hash160_of_the_spend_secret() {
        let keys = derive_stealth_keys(TEST_MNEMONIC, "", 0, AccountType::Default, 0).unwrap();
        assert_eq!(keys.spend_secret_id(), hash160(&keys.spend_secret));
    }
}
