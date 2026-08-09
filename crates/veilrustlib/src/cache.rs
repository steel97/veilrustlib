//! Persistent caching for balance scans.
//!
//! Walking the node's watch-only records is the expensive part of
//! [`crate::balance::get_balance`]: every call re-fetches every record and
//! re-checks every key image. This module stores the results of a scan so the
//! next one only has to fetch what arrived since.
//!
//! ## Layout
//!
//! - [`CacheStore`] is the storage interface: a small byte-oriented key/value
//!   API. Anything that can persist bytes can back the cache.
//! - [`MemoryStore`] implements it with a `HashMap`, for tests and for targets
//!   with no filesystem.
//! - [`RedbStore`] implements it on top of [redb], a pure-Rust single-file
//!   embedded database. It is behind the `cache-redb` feature so that platforms
//!   without file access (wasm) do not have to compile it.
//! - [`BalanceCache`] sits on top of a store and handles framing, integrity
//!   checking, and schema versioning.
//!
//! ## Corruption is expected, not exceptional
//!
//! A cache can be truncated by a crash, half-written by a killed process, or
//! left behind by an older version of this library. Every record is therefore
//! framed with a magic number, a schema version, a length, and a SHA-256 digest
//! of its payload. Anything that fails those checks is reported as
//! [`CacheLoad::Corrupt`] rather than returned as data, and the caller falls
//! back to a full scan.
//!
//! Reads never fail the operation they support. A store that cannot be reached
//! at all yields [`CacheLoad::Unavailable`], which callers treat the same as a
//! miss. That is what keeps the cache optional on wasm.
//!
//! ## Trusting the cache only so far
//!
//! Integrity checks prove a record is the one that was written; they cannot
//! prove it still matches the chain. A cached UTXO may have been spent since,
//! and a cache written by a buggy build may simply be wrong.
//! [`RecoveryPolicy`] decides how much re-verification to do against the node
//! before trusting cached entries, and the default re-checks the most recent 50.
//!
//! [redb]: https://docs.rs/redb

use std::collections::HashMap;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Result, VeilError};
use crate::types::{KeyImage, SecretKey, Utxo, UtxoCt};
use crate::utils::{bytes_to_hex, hex_to_bytes};
use crate::watch_only_tx::{ParsedUtxo, ParsedUtxoCt};

/// Schema version of the cached payload.
///
/// Bump this whenever [`WalletCacheData`] changes in a way older readers cannot
/// understand. Records written by a different version are reported as
/// [`CacheLoad::Stale`] and rebuilt from the node instead of being decoded.
pub const CACHE_SCHEMA_VERSION: u32 = 1;

/// Records [`RecoveryPolicy::default`] rewinds before resuming a scan.
///
/// The resume point is walked back by this many watch-only records so a scan
/// re-reads the tail it already covered. That is what catches a reorg, or a
/// record the previous run recorded a resume index for but did not fully
/// process.
pub const DEFAULT_REWIND_RECORDS: u64 = 50;

/// Magic number identifying a framed cache record.
const MAGIC: [u8; 4] = *b"VLCH";

/// `MAGIC` + schema version + payload length + SHA-256 digest.
const HEADER_LEN: usize = 4 + 4 + 8 + 32;

/// Domain separator for wallet identifiers, so the digest cannot collide with
/// any other use of the scan secret.
const WALLET_ID_DOMAIN: &[u8] = b"veilrustlib/balance-cache/wallet-id/v1";

// ---------------------------------------------------------------------------
// Storage interface
// ---------------------------------------------------------------------------

/// Byte-oriented key/value storage backing a [`BalanceCache`].
///
/// Implementations must be safe to share across threads because scans hold a
/// reference to the store across `await` points.
///
/// Methods take `&self` rather than `&mut self`: a store is expected to manage
/// its own interior mutability, which is what lets a single store be shared by
/// several scans.
pub trait CacheStore: Send + Sync {
    /// Read the value stored under `key`, or `None` when absent.
    fn load(&self, key: &str) -> Result<Option<Vec<u8>>>;

    /// Write `value` under `key`, replacing any previous value.
    fn store(&self, key: &str, value: &[u8]) -> Result<()>;

    /// Delete `key`. Removing an absent key is not an error.
    fn remove(&self, key: &str) -> Result<()>;

    /// Force pending writes to durable storage.
    ///
    /// The default is a no-op, which suits stores that commit on every write.
    fn flush(&self) -> Result<()> {
        Ok(())
    }
}

/// An in-memory [`CacheStore`].
///
/// Useful in tests and on targets with no usable filesystem. It makes repeat
/// scans cheap within one process but keeps nothing across restarts.
#[derive(Debug, Default)]
pub struct MemoryStore {
    entries: Mutex<HashMap<String, Vec<u8>>>,
}

impl MemoryStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of records held.
    pub fn len(&self) -> usize {
        self.entries.lock().map(|e| e.len()).unwrap_or(0)
    }

    /// Whether the store holds no records.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn entries(&self) -> Result<std::sync::MutexGuard<'_, HashMap<String, Vec<u8>>>> {
        self.entries
            .lock()
            .map_err(|_| VeilError::cache("in-memory cache lock was poisoned"))
    }
}

impl CacheStore for MemoryStore {
    fn load(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.entries()?.get(key).cloned())
    }

    fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        self.entries()?.insert(key.to_owned(), value.to_vec());
        Ok(())
    }

    fn remove(&self, key: &str) -> Result<()> {
        self.entries()?.remove(key);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// redb backend
// ---------------------------------------------------------------------------

#[cfg(feature = "cache-redb")]
mod redb_store {
    use super::{CacheStore, Result, VeilError};
    use redb::{Database, ReadableDatabase, TableDefinition};
    use std::path::{Path, PathBuf};

    /// The single table holding every cache record.
    const TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("veil_balance_cache");

    /// A single-file [`CacheStore`] backed by [redb](https://docs.rs/redb).
    ///
    /// redb is pure Rust with no C dependency, so it cross-compiles to iOS,
    /// Android, and every desktop target without extra toolchain setup. All
    /// data lives in one file, and writes are ACID: a crash mid-commit leaves
    /// the previous committed state intact rather than a torn record.
    #[derive(Debug)]
    pub struct RedbStore {
        db: Database,
        path: PathBuf,
    }

    impl RedbStore {
        /// Open the database at `path`, creating it when absent.
        ///
        /// Returns an error if the file exists but cannot be opened, including
        /// when redb reports it as corrupt. Use [`Self::open_or_recreate`] to
        /// discard a damaged file automatically.
        pub fn open(path: impl AsRef<Path>) -> Result<Self> {
            let path = path.as_ref().to_path_buf();

            let db = Database::create(&path).map_err(|e| {
                VeilError::cache(format!("could not open cache at {}: {e}", path.display()))
            })?;

            Ok(Self { db, path })
        }

        /// Open the database at `path`, discarding and rebuilding it if it
        /// cannot be opened.
        ///
        /// The cache is derived data, so throwing away an unreadable file and
        /// rescanning is always safe. Nothing here is unrecoverable: the node
        /// remains the source of truth.
        ///
        /// Returns the store and whether the previous file had to be deleted.
        pub fn open_or_recreate(path: impl AsRef<Path>) -> Result<(Self, bool)> {
            let path = path.as_ref();

            match Self::open(path) {
                Ok(store) => Ok((store, false)),
                Err(_) => {
                    std::fs::remove_file(path).map_err(|e| {
                        VeilError::cache(format!(
                            "cache at {} is unreadable and could not be removed: {e}",
                            path.display()
                        ))
                    })?;

                    Ok((Self::open(path)?, true))
                }
            }
        }

        /// Path of the database file.
        pub fn path(&self) -> &Path {
            &self.path
        }
    }

    impl CacheStore for RedbStore {
        fn load(&self, key: &str) -> Result<Option<Vec<u8>>> {
            let txn = self
                .db
                .begin_read()
                .map_err(|e| VeilError::cache(format!("cache read transaction failed: {e}")))?;

            // A database that has never been written has no table yet, which is
            // a miss rather than a failure.
            let table = match txn.open_table(TABLE) {
                Ok(table) => table,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
                Err(e) => return Err(VeilError::cache(format!("cache table unavailable: {e}"))),
            };

            let value = table
                .get(key)
                .map_err(|e| VeilError::cache(format!("cache lookup failed: {e}")))?
                .map(|v| v.value().to_vec());

            Ok(value)
        }

        fn store(&self, key: &str, value: &[u8]) -> Result<()> {
            let txn = self
                .db
                .begin_write()
                .map_err(|e| VeilError::cache(format!("cache write transaction failed: {e}")))?;

            {
                let mut table = txn
                    .open_table(TABLE)
                    .map_err(|e| VeilError::cache(format!("cache table unavailable: {e}")))?;

                table
                    .insert(key, value)
                    .map_err(|e| VeilError::cache(format!("cache insert failed: {e}")))?;
            }

            txn.commit()
                .map_err(|e| VeilError::cache(format!("cache commit failed: {e}")))
        }

        fn remove(&self, key: &str) -> Result<()> {
            let txn = self
                .db
                .begin_write()
                .map_err(|e| VeilError::cache(format!("cache write transaction failed: {e}")))?;

            {
                let mut table = match txn.open_table(TABLE) {
                    Ok(table) => table,
                    Err(redb::TableError::TableDoesNotExist(_)) => return Ok(()),
                    Err(e) => {
                        return Err(VeilError::cache(format!("cache table unavailable: {e}")))
                    }
                };

                table
                    .remove(key)
                    .map_err(|e| VeilError::cache(format!("cache remove failed: {e}")))?;
            }

            txn.commit()
                .map_err(|e| VeilError::cache(format!("cache commit failed: {e}")))
        }
    }
}

#[cfg(feature = "cache-redb")]
pub use redb_store::RedbStore;

// ---------------------------------------------------------------------------
// Cached records
// ---------------------------------------------------------------------------

/// A cached RingCT UTXO.
///
/// Byte fields are stored as hex rather than raw arrays: `serde` has no
/// implementations for arrays longer than 32 bytes, and a textual form stays
/// readable and stable across schema versions.
///
/// Unlike [`Utxo`] this keeps the key image, which is what makes it possible to
/// re-check a cached entry's spent status without re-parsing the record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedUtxo {
    /// Transaction ID, in display order.
    pub txid: String,
    /// Output index within the transaction.
    pub vout: u32,
    /// Amount in satoshis.
    pub amount: u64,
    /// Pedersen commitment, hex-encoded.
    pub commitment: String,
    /// Blinding factor, hex-encoded.
    pub blind: String,
    /// One-time destination public key, hex-encoded.
    pub pubkey: String,
    /// Ephemeral public key, hex-encoded.
    pub ephemeral_pubkey: String,
    /// Key image, hex-encoded.
    pub key_image: String,
    /// Global RingCT index.
    pub ringct_index: Option<u64>,
}

impl CachedUtxo {
    /// Capture a freshly parsed UTXO for storage.
    pub fn from_parsed(utxo: &ParsedUtxo) -> Self {
        Self {
            txid: utxo.txid.clone(),
            vout: utxo.vout,
            amount: utxo.amount,
            commitment: bytes_to_hex(&utxo.commitment),
            blind: bytes_to_hex(&utxo.blind),
            pubkey: bytes_to_hex(&utxo.pubkey),
            ephemeral_pubkey: bytes_to_hex(&utxo.ephemeral_pubkey),
            key_image: bytes_to_hex(&utxo.key_image),
            ringct_index: utxo.ringct_index,
        }
    }

    /// Outpoint identity, `txid:vout`, used to deduplicate entries.
    pub fn outpoint(&self) -> String {
        format!("{}:{}", self.txid, self.vout)
    }

    /// The key image as bytes.
    ///
    /// Fails when the stored hex is not a valid 33-byte key image, which means
    /// the record is corrupt.
    pub fn key_image_bytes(&self) -> Result<KeyImage> {
        hex_array::<33>("key_image", &self.key_image)
    }

    /// Rebuild the spendable [`Utxo`].
    ///
    /// `block_height` is zero because `getwatchonlytxes` never reported it.
    pub fn to_utxo(&self) -> Result<Utxo> {
        Ok(Utxo {
            txid: self.txid.clone(),
            vout: self.vout,
            amount: self.amount,
            commitment: hex_array::<33>("commitment", &self.commitment)?,
            blind: hex_array::<32>("blind", &self.blind)?,
            pubkey: hex_array::<33>("pubkey", &self.pubkey)?,
            ephemeral_pubkey: hex_array::<33>("ephemeral_pubkey", &self.ephemeral_pubkey)?,
            block_height: 0,
            spendable: true,
            ringct_index: self.ringct_index,
        })
    }

    /// Rebuild the parsed form, for callers that want key images back.
    pub fn to_parsed(&self) -> Result<ParsedUtxo> {
        Ok(ParsedUtxo {
            txid: self.txid.clone(),
            vout: self.vout,
            amount: self.amount,
            commitment: hex_array::<33>("commitment", &self.commitment)?,
            blind: hex_array::<32>("blind", &self.blind)?,
            pubkey: hex_array::<33>("pubkey", &self.pubkey)?,
            ephemeral_pubkey: hex_array::<33>("ephemeral_pubkey", &self.ephemeral_pubkey)?,
            key_image: hex_array::<33>("key_image", &self.key_image)?,
            ringct_index: self.ringct_index,
        })
    }
}

/// A cached CT (stealth) UTXO.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedUtxoCt {
    /// Transaction ID, in display order.
    pub txid: String,
    /// Output index within the transaction.
    pub vout: u32,
    /// Amount in satoshis.
    pub amount: u64,
    /// Pedersen commitment, hex-encoded.
    pub commitment: String,
    /// Blinding factor, hex-encoded.
    pub blind: String,
    /// Script pubkey, hex-encoded.
    pub script_pubkey: String,
    /// Derived destination public key, hex-encoded.
    pub pubkey: String,
    /// Ephemeral public key, hex-encoded.
    pub ephemeral_pubkey: String,
}

impl CachedUtxoCt {
    /// Capture a freshly parsed CT UTXO for storage.
    pub fn from_parsed(utxo: &ParsedUtxoCt) -> Self {
        Self {
            txid: utxo.txid.clone(),
            vout: utxo.vout,
            amount: utxo.amount,
            commitment: bytes_to_hex(&utxo.commitment),
            blind: bytes_to_hex(&utxo.blind),
            script_pubkey: bytes_to_hex(&utxo.script_pubkey),
            pubkey: bytes_to_hex(&utxo.pubkey),
            ephemeral_pubkey: bytes_to_hex(&utxo.ephemeral_pubkey),
        }
    }

    /// Outpoint identity, `txid:vout`.
    ///
    /// CT outputs carry no key image, so this is also how spends are tracked.
    pub fn outpoint(&self) -> String {
        format!("{}:{}", self.txid, self.vout)
    }

    /// Rebuild the spendable [`UtxoCt`].
    pub fn to_utxo(&self) -> Result<UtxoCt> {
        Ok(UtxoCt {
            txid: self.txid.clone(),
            vout: self.vout,
            amount: self.amount,
            commitment: hex_array::<33>("commitment", &self.commitment)?,
            blind: hex_array::<32>("blind", &self.blind)?,
            script_pubkey: hex_to_bytes(&self.script_pubkey)?,
            ephemeral_pubkey: hex_array::<33>("ephemeral_pubkey", &self.ephemeral_pubkey)?,
            pubkey: hex_array::<33>("pubkey", &self.pubkey)?,
            block_height: 0,
            spendable: true,
        })
    }
}

/// Everything cached for one wallet.
///
/// This is the resume state of a scan: where the last one stopped, what it
/// found, and which outputs were known to be spent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletCacheData {
    /// Wallet this record belongs to, from [`wallet_id`].
    pub wallet_id: String,
    /// Record index a RingCT scan should resume from.
    pub last_processed_index: u64,
    /// Record index a CT scan should resume from.
    pub ct_last_processed_index: u64,
    /// Chain height at which the watch-only records were last walked.
    ///
    /// New outputs can only arrive in new blocks, so when the tip has not moved
    /// since this height there is nothing new to fetch and the expensive
    /// `getwatchonlytxes` walk can be skipped entirely. This is the single
    /// biggest saving the cache provides.
    #[serde(default)]
    pub scanned_at_height: u64,
    /// Chain height at which the CT records were last walked.
    ///
    /// Tracked separately from [`Self::scanned_at_height`] because the RingCT
    /// and CT scans advance independently.
    #[serde(default)]
    pub ct_scanned_at_height: u64,
    /// Unspent RingCT UTXOs as of the last scan.
    pub utxos: Vec<CachedUtxo>,
    /// Unspent CT UTXOs as of the last scan.
    pub ct_utxos: Vec<CachedUtxoCt>,
    /// Key images known to be spent, hex-encoded.
    pub spent_key_images: Vec<String>,
    /// Outpoints known to be spent, formatted `txid:vout`.
    pub spent_outpoints: Vec<String>,
}

impl WalletCacheData {
    /// An empty record for `wallet_id`.
    pub fn new(wallet_id: impl Into<String>) -> Self {
        Self {
            wallet_id: wallet_id.into(),
            ..Default::default()
        }
    }

    /// Sum of the cached RingCT amounts, in satoshis.
    pub fn total_balance(&self) -> u64 {
        self.utxos
            .iter()
            .fold(0u64, |acc, u| acc.saturating_add(u.amount))
    }

    /// Sum of the cached CT amounts, in satoshis.
    pub fn total_balance_ct(&self) -> u64 {
        self.ct_utxos
            .iter()
            .fold(0u64, |acc, u| acc.saturating_add(u.amount))
    }
}

// ---------------------------------------------------------------------------
// Load outcomes and recovery policy
// ---------------------------------------------------------------------------

/// The result of reading a cache record.
///
/// Only [`Self::Loaded`] carries data. Every other variant means the caller
/// should scan from the node, and they are kept distinct so the reason can be
/// reported instead of silently swallowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheLoad {
    /// Nothing has been cached for this wallet yet.
    Missing,
    /// A record was found and passed every integrity check.
    Loaded(Box<WalletCacheData>),
    /// A record was found but failed framing, digest, or decoding checks.
    Corrupt(String),
    /// A record was written by a different schema version.
    Stale {
        /// Version found in the record.
        found: u32,
        /// Version this build understands.
        expected: u32,
    },
    /// The store itself could not be read, as on a platform with no database.
    Unavailable(String),
}

impl CacheLoad {
    /// The cached data, when the record was usable.
    pub fn data(self) -> Option<WalletCacheData> {
        match self {
            Self::Loaded(data) => Some(*data),
            _ => None,
        }
    }

    /// Whether usable data was returned.
    pub fn is_hit(&self) -> bool {
        matches!(self, Self::Loaded(_))
    }

    /// Whether a record existed but could not be trusted.
    pub fn is_damaged(&self) -> bool {
        matches!(self, Self::Corrupt(_) | Self::Stale { .. })
    }
}

/// How much work to do against the node before trusting a cache.
///
/// Integrity checks confirm a record was stored intact; they cannot confirm it
/// still matches the chain. This is the knob the plan leaves to the end
/// developer.
///
/// ## Why this is about records, not key images
///
/// `checkkeyimages` only examines the key images it is given, so its cost is
/// bounded by the wallet's own UTXO count and it batches into very few requests.
/// Every policy except [`Self::CacheOnly`] therefore checks all cached key
/// images: skipping some would let a spent output sit in the balance undetected
/// while saving almost nothing.
///
/// The expensive call is `getwatchonlytxes`. It returns records in fixed pages of
/// 1000 that cannot be tuned, so walking the whole history is what makes a scan
/// slow. What varies between policies is how many of those records get re-walked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryPolicy {
    /// Return the cache as-is, making no node requests at all.
    ///
    /// Intended for first paint in a UI: the last known balance appears
    /// immediately, and a revalidating scan can follow. The result may be stale,
    /// and [`CacheInfo::up_to_date`] is false to say so.
    CacheOnly,
    /// Verify cached spends, then resume the record walk `n` records early.
    ///
    /// The rewind re-reads a tail the previous scan already covered, which is
    /// what recovers from a reorg or a partially processed page. This is the
    /// default, with [`DEFAULT_REWIND_RECORDS`].
    Rewind(u64),
    /// Verify cached spends and walk every record from the beginning.
    ///
    /// The most thorough option and the slowest: it re-fetches and re-parses the
    /// wallet's entire history. Use it to audit a cache that is suspected wrong
    /// in a way the integrity checks cannot see.
    FullRescan,
}

impl Default for RecoveryPolicy {
    fn default() -> Self {
        Self::Rewind(DEFAULT_REWIND_RECORDS)
    }
}

impl RecoveryPolicy {
    /// Whether this policy contacts the node at all.
    pub fn hits_network(&self) -> bool {
        !matches!(self, Self::CacheOnly)
    }

    /// Whether cached key images should be re-checked for spends.
    ///
    /// True for every policy that talks to the node, because it is one request.
    pub fn verifies_spends(&self) -> bool {
        self.hits_network()
    }

    /// Where the record walk should resume, given the cached high-water mark.
    ///
    /// Saturates at zero, so a rewind larger than the index simply starts over.
    pub fn resume_index(&self, cached_index: u64) -> u64 {
        match self {
            Self::CacheOnly => cached_index,
            Self::Rewind(n) => cached_index.saturating_sub(*n),
            Self::FullRescan => 0,
        }
    }
}

/// What the cache contributed to a scan.
///
/// Attached to a balance result so callers can tell a cached answer from a
/// fresh one, and can see when a cache was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CacheInfo {
    /// Whether a cache was consulted at all.
    pub enabled: bool,
    /// Number of UTXOs loaded from the cache.
    pub loaded: usize,
    /// Number of cached UTXOs re-checked against the node.
    pub revalidated: usize,
    /// Whether the watch-only record walk was skipped.
    ///
    /// True when the cache was returned without walking records, either because
    /// the chain tip had not moved or because the policy was
    /// [`RecoveryPolicy::CacheOnly`]. This is where a warm scan saves its time.
    pub skipped_scan: bool,
    /// Record index the walk resumed from, when it ran.
    ///
    /// Lower than the cached high-water mark when a rewind was applied.
    pub resumed_from: Option<u64>,
    /// Number of cached UTXOs dropped because they turned out to be spent.
    pub dropped: usize,
    /// Whether a full rescan was forced because the cache was unusable.
    pub rebuilt: bool,
    /// Whether updated results were written back.
    pub saved: bool,
    /// Whether the answer came entirely from the cache, with no record scan.
    ///
    /// True when the chain tip had not moved since the cache was written, so
    /// neither the watch-only walk nor any key image check was needed.
    pub up_to_date: bool,
    /// Why the cache was rejected or could not be used, when it was not.
    pub note: Option<String>,
}

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

/// Derive a stable, non-reversible identifier for a wallet.
///
/// The scan secret keys the cache but is never stored: only this digest is, so
/// a leaked cache file does not leak the ability to scan the wallet.
pub fn wallet_id(scan_secret: &SecretKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(WALLET_ID_DOMAIN);
    hasher.update(scan_secret);
    bytes_to_hex(&hasher.finalize())
}

/// Frame a payload with its magic number, version, length, and digest.
fn encode_envelope(payload: &[u8]) -> Vec<u8> {
    let digest = Sha256::digest(payload);

    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&CACHE_SCHEMA_VERSION.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    out.extend_from_slice(&digest);
    out.extend_from_slice(payload);
    out
}

/// Verify framing and return the payload, or say why it cannot be trusted.
///
/// The order matters: the magic number rules out foreign data, the version
/// check runs before decoding so an old record is reported as stale rather than
/// as garbage, and the digest is verified before the payload is parsed at all.
fn decode_envelope(bytes: &[u8]) -> std::result::Result<&[u8], CacheLoad> {
    if bytes.len() < HEADER_LEN {
        return Err(CacheLoad::Corrupt(format!(
            "record is {} bytes, shorter than the {HEADER_LEN}-byte header",
            bytes.len()
        )));
    }

    if bytes[..4] != MAGIC {
        return Err(CacheLoad::Corrupt(
            "record does not start with the cache magic number".to_string(),
        ));
    }

    let version = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if version != CACHE_SCHEMA_VERSION {
        return Err(CacheLoad::Stale {
            found: version,
            expected: CACHE_SCHEMA_VERSION,
        });
    }

    let declared = u64::from_le_bytes(
        bytes[8..16]
            .try_into()
            .expect("slice of 8 bytes is always a [u8; 8]"),
    );
    let payload = &bytes[HEADER_LEN..];

    if declared != payload.len() as u64 {
        return Err(CacheLoad::Corrupt(format!(
            "record declares a {declared}-byte payload but carries {}",
            payload.len()
        )));
    }

    if Sha256::digest(payload)[..] != bytes[16..HEADER_LEN] {
        return Err(CacheLoad::Corrupt(
            "payload does not match its checksum".to_string(),
        ));
    }

    Ok(payload)
}

/// Decode a hex string into a fixed-size array, reporting a corrupt cache.
fn hex_array<const N: usize>(field: &str, value: &str) -> Result<[u8; N]> {
    let bytes = hex_to_bytes(value)
        .map_err(|e| VeilError::cache(format!("cached {field} is not valid hex: {e}")))?;

    bytes.try_into().map_err(|_| {
        VeilError::cache(format!(
            "cached {field} has the wrong length, expected {N} bytes"
        ))
    })
}

// ---------------------------------------------------------------------------
// BalanceCache
// ---------------------------------------------------------------------------

/// Reads and writes wallet cache records in a [`CacheStore`].
///
/// This is the layer that makes a store safe to use: it frames records,
/// verifies them on the way back in, and converts every storage failure into a
/// [`CacheLoad`] variant so a broken cache degrades to a slow scan instead of a
/// failed one.
pub struct BalanceCache<'a> {
    store: &'a dyn CacheStore,
}

impl std::fmt::Debug for BalanceCache<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The store is a trait object with no Debug bound, so only the wrapper
        // is described.
        f.debug_struct("BalanceCache").finish_non_exhaustive()
    }
}

impl<'a> BalanceCache<'a> {
    /// Wrap a store.
    pub fn new(store: &'a dyn CacheStore) -> Self {
        Self { store }
    }

    /// Storage key for a wallet's record.
    fn key(wallet_id: &str) -> String {
        format!("balance/{wallet_id}")
    }

    /// Read the record for `wallet_id`.
    ///
    /// Never returns an error: an unreachable store, a damaged record, and an
    /// absent one are all reported through [`CacheLoad`], because none of them
    /// should stop a caller from falling back to the node.
    pub fn load(&self, wallet_id: &str) -> CacheLoad {
        let raw = match self.store.load(&Self::key(wallet_id)) {
            Ok(Some(raw)) => raw,
            Ok(None) => return CacheLoad::Missing,
            Err(e) => return CacheLoad::Unavailable(e.to_string()),
        };

        let payload = match decode_envelope(&raw) {
            Ok(payload) => payload,
            Err(outcome) => return outcome,
        };

        let data: WalletCacheData = match serde_json::from_slice(payload) {
            Ok(data) => data,
            Err(e) => return CacheLoad::Corrupt(format!("payload did not decode: {e}")),
        };

        // A digest-valid record filed under the wrong wallet means the store
        // returned someone else's data; using it would report a wrong balance.
        if data.wallet_id != wallet_id {
            return CacheLoad::Corrupt(format!(
                "record is filed under {wallet_id} but claims to belong to {}",
                data.wallet_id
            ));
        }

        CacheLoad::Loaded(Box::new(data))
    }

    /// Write `data`, replacing any existing record for its wallet.
    pub fn save(&self, data: &WalletCacheData) -> Result<()> {
        let payload = serde_json::to_vec(data)?;
        self.store
            .store(&Self::key(&data.wallet_id), &encode_envelope(&payload))?;
        self.store.flush()
    }

    /// Delete the record for `wallet_id`, forcing the next scan to start over.
    pub fn clear(&self, wallet_id: &str) -> Result<()> {
        self.store.remove(&Self::key(wallet_id))?;
        self.store.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed_utxo(txid: &str, vout: u32, amount: u64, key_image: u8) -> ParsedUtxo {
        ParsedUtxo {
            txid: txid.to_string(),
            vout,
            amount,
            commitment: [0x08u8; 33],
            blind: [0xABu8; 32],
            pubkey: [0x02u8; 33],
            ephemeral_pubkey: [0x03u8; 33],
            key_image: [key_image; 33],
            ringct_index: Some(u64::from(vout)),
        }
    }

    fn sample_data() -> WalletCacheData {
        let mut data = WalletCacheData::new("wallet-1");
        data.last_processed_index = 1_234;
        data.utxos = vec![
            CachedUtxo::from_parsed(&parsed_utxo("aa", 0, 100, 0x01)),
            CachedUtxo::from_parsed(&parsed_utxo("bb", 1, 250, 0x02)),
        ];
        data.spent_key_images = vec![bytes_to_hex(&[0x09u8; 33])];
        data
    }

    #[test]
    fn a_saved_record_round_trips() {
        let store = MemoryStore::new();
        let cache = BalanceCache::new(&store);
        let data = sample_data();

        cache.save(&data).unwrap();

        let loaded = cache.load("wallet-1").data().unwrap();
        assert_eq!(loaded, data);
        assert_eq!(loaded.total_balance(), 350);
    }

    #[test]
    fn an_unwritten_wallet_reads_as_a_miss() {
        let store = MemoryStore::new();
        let cache = BalanceCache::new(&store);

        assert_eq!(cache.load("wallet-1"), CacheLoad::Missing);
    }

    #[test]
    fn clearing_a_record_makes_it_a_miss_again() {
        let store = MemoryStore::new();
        let cache = BalanceCache::new(&store);

        cache.save(&sample_data()).unwrap();
        assert!(cache.load("wallet-1").is_hit());

        cache.clear("wallet-1").unwrap();
        assert_eq!(cache.load("wallet-1"), CacheLoad::Missing);
    }

    #[test]
    fn a_flipped_payload_byte_is_caught_by_the_checksum() {
        let store = MemoryStore::new();
        let cache = BalanceCache::new(&store);
        cache.save(&sample_data()).unwrap();

        let key = BalanceCache::key("wallet-1");
        let mut raw = store.load(&key).unwrap().unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0xFF;
        store.store(&key, &raw).unwrap();

        match cache.load("wallet-1") {
            CacheLoad::Corrupt(reason) => assert!(reason.contains("checksum")),
            other => panic!("expected a corrupt record, got {other:?}"),
        }
    }

    #[test]
    fn a_truncated_record_is_rejected() {
        let store = MemoryStore::new();
        let cache = BalanceCache::new(&store);
        cache.save(&sample_data()).unwrap();

        let key = BalanceCache::key("wallet-1");
        let raw = store.load(&key).unwrap().unwrap();
        store.store(&key, &raw[..raw.len() - 4]).unwrap();

        assert!(matches!(cache.load("wallet-1"), CacheLoad::Corrupt(_)));
    }

    #[test]
    fn a_header_only_record_is_rejected() {
        let store = MemoryStore::new();
        let cache = BalanceCache::new(&store);

        store
            .store(&BalanceCache::key("wallet-1"), b"short")
            .unwrap();

        assert!(matches!(cache.load("wallet-1"), CacheLoad::Corrupt(_)));
    }

    #[test]
    fn foreign_data_is_not_mistaken_for_a_cache_record() {
        let store = MemoryStore::new();
        let cache = BalanceCache::new(&store);

        store
            .store(&BalanceCache::key("wallet-1"), &[0u8; HEADER_LEN + 8])
            .unwrap();

        match cache.load("wallet-1") {
            CacheLoad::Corrupt(reason) => assert!(reason.contains("magic")),
            other => panic!("expected a corrupt record, got {other:?}"),
        }
    }

    #[test]
    fn a_record_from_another_schema_version_reads_as_stale() {
        let payload = serde_json::to_vec(&sample_data()).unwrap();
        let mut raw = encode_envelope(&payload);
        raw[4..8].copy_from_slice(&(CACHE_SCHEMA_VERSION + 1).to_le_bytes());

        let store = MemoryStore::new();
        store.store(&BalanceCache::key("wallet-1"), &raw).unwrap();

        assert_eq!(
            BalanceCache::new(&store).load("wallet-1"),
            CacheLoad::Stale {
                found: CACHE_SCHEMA_VERSION + 1,
                expected: CACHE_SCHEMA_VERSION,
            }
        );
    }

    #[test]
    fn a_record_belonging_to_another_wallet_is_refused() {
        let store = MemoryStore::new();
        let cache = BalanceCache::new(&store);
        cache.save(&sample_data()).unwrap();

        // Same intact bytes, filed under a different wallet.
        let raw = store.load(&BalanceCache::key("wallet-1")).unwrap().unwrap();
        store.store(&BalanceCache::key("wallet-2"), &raw).unwrap();

        assert!(cache.load("wallet-2").is_damaged());
    }

    #[test]
    fn an_unreachable_store_reports_unavailable() {
        struct Broken;

        impl CacheStore for Broken {
            fn load(&self, _key: &str) -> Result<Option<Vec<u8>>> {
                Err(VeilError::cache("no database on this platform"))
            }
            fn store(&self, _key: &str, _value: &[u8]) -> Result<()> {
                Err(VeilError::cache("no database on this platform"))
            }
            fn remove(&self, _key: &str) -> Result<()> {
                Err(VeilError::cache("no database on this platform"))
            }
        }

        let broken = Broken;
        let load = BalanceCache::new(&broken).load("wallet-1");

        assert!(matches!(load, CacheLoad::Unavailable(_)));
        assert!(!load.is_hit());
        assert!(!load.is_damaged());
    }

    #[test]
    fn cached_utxos_convert_back_to_spendable_form() {
        let parsed = parsed_utxo("aa", 3, 500, 0x07);
        let cached = CachedUtxo::from_parsed(&parsed);

        assert_eq!(cached.outpoint(), "aa:3");
        assert_eq!(cached.key_image_bytes().unwrap(), [0x07u8; 33]);
        assert_eq!(cached.to_parsed().unwrap(), parsed);

        let utxo = cached.to_utxo().unwrap();
        assert_eq!(utxo.amount, 500);
        assert_eq!(utxo.commitment, [0x08u8; 33]);
        assert_eq!(utxo.ringct_index, Some(3));
        assert!(utxo.spendable);
    }

    #[test]
    fn a_cached_utxo_with_a_bad_field_length_fails_to_convert() {
        let mut cached = CachedUtxo::from_parsed(&parsed_utxo("aa", 0, 1, 0x01));
        cached.commitment = bytes_to_hex(&[0x08u8; 8]);

        assert!(cached.to_utxo().is_err());
    }

    #[test]
    fn ct_records_round_trip_through_the_cache() {
        let parsed = ParsedUtxoCt {
            txid: "cc".to_string(),
            vout: 2,
            amount: 700,
            commitment: [0x09u8; 33],
            blind: [0xCDu8; 32],
            script_pubkey: vec![0x76, 0xa9, 0x14],
            pubkey: [0x02u8; 33],
            ephemeral_pubkey: [0x03u8; 33],
        };

        let cached = CachedUtxoCt::from_parsed(&parsed);
        assert_eq!(cached.outpoint(), "cc:2");

        let utxo = cached.to_utxo().unwrap();
        assert_eq!(utxo.amount, 700);
        assert_eq!(utxo.script_pubkey, vec![0x76, 0xa9, 0x14]);

        let mut data = WalletCacheData::new("wallet-ct");
        data.ct_utxos = vec![cached];
        assert_eq!(data.total_balance_ct(), 700);
    }

    #[test]
    fn wallet_ids_are_stable_and_hide_the_secret() {
        let secret = [0x11u8; 32];
        let other = [0x22u8; 32];

        let id = wallet_id(&secret);
        assert_eq!(id, wallet_id(&secret));
        assert_ne!(id, wallet_id(&other));

        // 32 bytes of digest, and nothing resembling the input.
        assert_eq!(id.len(), 64);
        assert!(!id.contains(&bytes_to_hex(&secret)));
    }

    /// A scratch path inside the OS temp directory, unique per test.
    #[cfg(feature = "cache-redb")]
    fn temp_db_path(label: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);

        let unique = format!(
            "veilrustlib-cache-test-{label}-{}-{}.redb",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );

        let path = std::env::temp_dir().join(unique);
        let _ = std::fs::remove_file(&path);
        path
    }

    #[cfg(feature = "cache-redb")]
    #[test]
    fn a_redb_cache_survives_reopening_as_a_single_file() {
        let path = temp_db_path("persist");
        let data = sample_data();

        {
            let store = RedbStore::open(&path).unwrap();
            BalanceCache::new(&store).save(&data).unwrap();
        }

        // Everything lives in one file, as the plan requires.
        assert!(path.is_file());

        {
            let store = RedbStore::open(&path).unwrap();
            let loaded = BalanceCache::new(&store).load("wallet-1").data().unwrap();
            assert_eq!(loaded, data);
            assert_eq!(loaded.last_processed_index, 1_234);
        }

        std::fs::remove_file(&path).unwrap();
    }

    #[cfg(feature = "cache-redb")]
    #[test]
    fn a_fresh_redb_cache_reads_as_a_miss_not_an_error() {
        let path = temp_db_path("fresh");

        let store = RedbStore::open(&path).unwrap();
        // No table exists yet; that is a miss, not a failure.
        assert_eq!(BalanceCache::new(&store).load("wallet-1"), CacheLoad::Missing);

        std::fs::remove_file(&path).unwrap();
    }

    #[cfg(feature = "cache-redb")]
    #[test]
    fn a_damaged_redb_file_is_rebuilt_rather_than_failing() {
        let path = temp_db_path("damaged");

        // Not a redb database at all, which is what a truncated or foreign file
        // looks like on open.
        std::fs::write(&path, b"this is not a database").unwrap();
        assert!(RedbStore::open(&path).is_err());

        let (store, recreated) = RedbStore::open_or_recreate(&path).unwrap();
        assert!(recreated);

        let cache = BalanceCache::new(&store);
        cache.save(&sample_data()).unwrap();
        assert!(cache.load("wallet-1").is_hit());

        drop(store);
        std::fs::remove_file(&path).unwrap();
    }

    #[cfg(feature = "cache-redb")]
    #[test]
    fn open_or_recreate_keeps_a_healthy_file_intact() {
        let path = temp_db_path("healthy");

        {
            let store = RedbStore::open(&path).unwrap();
            BalanceCache::new(&store).save(&sample_data()).unwrap();
        }

        let (store, recreated) = RedbStore::open_or_recreate(&path).unwrap();
        assert!(!recreated, "a readable cache must not be discarded");
        assert!(BalanceCache::new(&store).load("wallet-1").is_hit());

        drop(store);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn the_scan_height_round_trips_and_defaults_to_zero() {
        let mut data = sample_data();
        data.scanned_at_height = 1_500_000;
        data.ct_scanned_at_height = 1_499_000;

        let store = MemoryStore::new();
        let cache = BalanceCache::new(&store);
        cache.save(&data).unwrap();

        let loaded = cache.load("wallet-1").data().unwrap();
        assert_eq!(loaded.scanned_at_height, 1_500_000);
        assert_eq!(loaded.ct_scanned_at_height, 1_499_000);

        // A record written before these fields existed must still decode, with
        // a zero height so it is treated as never scanned rather than current.
        let legacy = serde_json::json!({
            "wallet_id": "wallet-1",
            "last_processed_index": 10,
            "ct_last_processed_index": 0,
            "utxos": [],
            "ct_utxos": [],
            "spent_key_images": [],
            "spent_outpoints": [],
        });

        let decoded: WalletCacheData = serde_json::from_value(legacy).unwrap();
        assert_eq!(decoded.scanned_at_height, 0);
        assert_eq!(decoded.ct_scanned_at_height, 0);
        assert_eq!(decoded.last_processed_index, 10);
    }

    #[test]
    fn recovery_policies_decide_where_the_walk_resumes() {
        // CacheOnly makes no requests, so it neither rewinds nor verifies.
        assert!(!RecoveryPolicy::CacheOnly.hits_network());
        assert!(!RecoveryPolicy::CacheOnly.verifies_spends());
        assert_eq!(RecoveryPolicy::CacheOnly.resume_index(1_927), 1_927);

        // A rewind re-reads the tail the previous scan already covered.
        assert_eq!(RecoveryPolicy::Rewind(50).resume_index(1_927), 1_877);
        assert!(RecoveryPolicy::Rewind(50).hits_network());
        assert!(RecoveryPolicy::Rewind(50).verifies_spends());

        // A rewind larger than the index starts over rather than underflowing.
        assert_eq!(RecoveryPolicy::Rewind(50).resume_index(10), 0);
        assert_eq!(RecoveryPolicy::Rewind(u64::MAX).resume_index(5), 0);

        // FullRescan always walks everything.
        assert_eq!(RecoveryPolicy::FullRescan.resume_index(1_927), 0);
        assert!(RecoveryPolicy::FullRescan.verifies_spends());

        assert_eq!(
            RecoveryPolicy::default(),
            RecoveryPolicy::Rewind(DEFAULT_REWIND_RECORDS)
        );
    }
}
