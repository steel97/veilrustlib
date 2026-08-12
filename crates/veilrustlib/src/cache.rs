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
//! - [`SentCache`] is a second layer in the same store, recording the
//!   transactions this wallet successfully broadcast.
//!
//! ## Two layers, one store
//!
//! Balance records answer "what do I own". They cannot answer "where did it come
//! from": an output the wallet created as change and an output someone paid it
//! are both just owned outputs in the watch-only stream. [`SentCache`] keeps the
//! missing half, a list of transactions this wallet sent, under its own key
//! prefix in the same store. Comparing the two is what lets a UTXO be labelled
//! [`crate::types::TxDirection::Send`] or
//! [`crate::types::TxDirection::Receive`] instead of
//! [`crate::types::TxDirection::Unknown`].
//!
//! ## Binary payloads
//!
//! Records are written with a hand-rolled little-endian codec rather than JSON.
//! Keys, commitments, and blinds are fixed-length byte arrays, so JSON spent
//! two hex characters plus quoting and field names on every byte of them. The
//! codec writes them raw, which cuts a typical record to roughly a third of its
//! JSON size and removes hex parsing from the read path entirely: a field that
//! decodes at all is already the right length.
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

use crate::error::{Result, VeilError};
use crate::types::{KeyImage, SecretKey, TxDirection, Utxo, UtxoCt};
use crate::utils::bytes_to_hex;
use crate::watch_only_tx::{ParsedUtxo, ParsedUtxoCt};

use sha2::{Digest, Sha256};

/// Schema version of the cached payload.
///
/// Bump this whenever [`WalletCacheData`] changes in a way older readers cannot
/// understand. Records written by a different version are reported as
/// [`CacheLoad::Stale`] and rebuilt from the node instead of being decoded.
///
/// ## Version history
///
/// - **v1**: JSON-encoded payloads, no direction field, no binary codec.
/// - **v2**: Binary codec, TxDirection added to UTXOs.
/// - **v3**: Transaction IDs stored as 32 raw bytes instead of a length-prefixed
///   64-character hex string. The field width changed, so a v2 reader and a v3
///   reader disagree about every offset after the first txid; the bump is what
///   makes an older record report as [`CacheLoad::Stale`] and get rebuilt rather
///   than decode into plausible nonsense.
/// - **v4**: Added `seen_txids` map to track all transactions encountered during
///   scanning (both spent and unspent), enabling complete transaction history.
///
/// Only the newest version is readable. The cache is derived data, so a version
/// mismatch costs one rescan and nothing else.
pub const CACHE_SCHEMA_VERSION: u32 = 4;

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

/// Decode a display-order transaction ID into the 32 bytes the cache stores.
///
/// ## Byte order
///
/// The bytes are stored exactly as the display hex spells them, not reversed
/// into the internal consensus order. That keeps the cache a pure re-encoding of
/// the string it replaces: `parse_txid` then [`bytes_to_hex`] returns the
/// original txid unchanged, so nothing downstream has to know the cache switched
/// representations. Reversing here would silently flip every txid a caller reads
/// back out.
///
/// # Errors
///
/// Returns [`VeilError::Cache`] when `txid` is not exactly 64 hex characters.
fn parse_txid(txid: &str) -> Result<[u8; 32]> {
    crate::utils::hex_to_array::<32>(txid)
        .map_err(|e| VeilError::cache(format!("txid {txid:?} is not 32 bytes of hex: {e}")))
}

/// A cached RingCT UTXO, stored in binary format.
///
/// Unlike [`Utxo`] this keeps the key image, which is what makes it possible to
/// re-check a cached entry's spent status without re-parsing the record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedUtxo {
    /// Transaction ID, in display (reversed) byte order.
    pub txid: [u8; 32],
    /// Output index within the transaction.
    pub vout: u32,
    /// Amount in satoshis.
    pub amount: u64,
    /// Pedersen commitment.
    pub commitment: [u8; 33],
    /// Blinding factor.
    pub blind: [u8; 32],
    /// One-time destination public key.
    pub pubkey: [u8; 33],
    /// Ephemeral public key.
    pub ephemeral_pubkey: [u8; 33],
    /// Key image.
    pub key_image: [u8; 33],
    /// Global RingCT index.
    pub ringct_index: Option<u64>,
    /// Direction: send, receive, or unknown.
    pub direction: TxDirection,
}

impl CachedUtxo {
    /// Capture a freshly parsed UTXO for storage, with the origin still unknown.
    ///
    /// A parse alone cannot say where an output came from, so this is the honest
    /// default. Use [`Self::from_parsed_with_direction`] when the sent-
    /// transaction history has already been consulted.
    ///
    /// # Errors
    ///
    /// Returns [`VeilError::Cache`] when [`ParsedUtxo::txid`] is not 64 hex
    /// characters. The parser always produces that, but the field is public, so
    /// this cannot be an assertion.
    pub fn from_parsed(utxo: &ParsedUtxo) -> Result<Self> {
        Self::from_parsed_with_direction(utxo, TxDirection::Unknown)
    }

    /// Capture a freshly parsed UTXO, labelling where it came from.
    ///
    /// # Errors
    ///
    /// As [`Self::from_parsed`].
    pub fn from_parsed_with_direction(
        utxo: &ParsedUtxo,
        direction: TxDirection,
    ) -> Result<Self> {
        Ok(Self {
            txid: parse_txid(&utxo.txid)?,
            vout: utxo.vout,
            amount: utxo.amount,
            commitment: utxo.commitment,
            blind: utxo.blind,
            pubkey: utxo.pubkey,
            ephemeral_pubkey: utxo.ephemeral_pubkey,
            key_image: utxo.key_image,
            ringct_index: utxo.ringct_index,
            direction,
        })
    }

    /// Rebuild the parsed form, for callers that want key images back.
    pub fn to_parsed(&self) -> ParsedUtxo {
        ParsedUtxo {
            txid: bytes_to_hex(&self.txid),
            vout: self.vout,
            amount: self.amount,
            commitment: self.commitment,
            blind: self.blind,
            pubkey: self.pubkey,
            ephemeral_pubkey: self.ephemeral_pubkey,
            key_image: self.key_image,
            ringct_index: self.ringct_index,
        }
    }

    /// The key image, hex-encoded, as the spent-set uses it.
    pub fn key_image_hex(&self) -> String {
        bytes_to_hex(&self.key_image)
    }

    /// Outpoint identity, `txid:vout`, used to deduplicate entries.
    pub fn outpoint(&self) -> String {
        format!("{}:{}", bytes_to_hex(&self.txid), self.vout)
    }

    /// Transaction ID as hex string, in display order.
    pub fn txid_hex(&self) -> String {
        bytes_to_hex(&self.txid)
    }

    /// The key image as a byte array.
    pub fn key_image_bytes(&self) -> KeyImage {
        self.key_image
    }

    /// Rebuild the spendable [`Utxo`].
    ///
    /// `block_height` is zero because `getwatchonlytxes` never reported it.
    pub fn to_utxo(&self) -> Result<Utxo> {
        Ok(Utxo {
            txid: bytes_to_hex(&self.txid),
            vout: self.vout,
            amount: self.amount,
            commitment: self.commitment,
            blind: self.blind,
            pubkey: self.pubkey,
            ephemeral_pubkey: self.ephemeral_pubkey,
            block_height: 0,
            spendable: true,
            ringct_index: self.ringct_index,
            direction: self.direction,
        })
    }
}

/// A cached CT (stealth) UTXO, stored in binary format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedUtxoCt {
    /// Transaction ID, in display (reversed) byte order.
    pub txid: [u8; 32],
    /// Output index within the transaction.
    pub vout: u32,
    /// Amount in satoshis.
    pub amount: u64,
    /// Pedersen commitment.
    pub commitment: [u8; 33],
    /// Blinding factor.
    pub blind: [u8; 32],
    /// Script pubkey.
    pub script_pubkey: Vec<u8>,
    /// Derived destination public key.
    pub pubkey: [u8; 33],
    /// Ephemeral public key.
    pub ephemeral_pubkey: [u8; 33],
    /// Direction: send, receive, or unknown.
    pub direction: TxDirection,
}

impl CachedUtxoCt {
    /// Capture a freshly parsed CT UTXO for storage, origin still unknown.
    ///
    /// # Errors
    ///
    /// Returns [`VeilError::Cache`] when [`ParsedUtxoCt::txid`] is not 64 hex
    /// characters.
    pub fn from_parsed(utxo: &ParsedUtxoCt) -> Result<Self> {
        Self::from_parsed_with_direction(utxo, TxDirection::Unknown)
    }

    /// Capture a freshly parsed CT UTXO, labelling where it came from.
    ///
    /// # Errors
    ///
    /// As [`Self::from_parsed`].
    pub fn from_parsed_with_direction(
        utxo: &ParsedUtxoCt,
        direction: TxDirection,
    ) -> Result<Self> {
        Ok(Self {
            txid: parse_txid(&utxo.txid)?,
            vout: utxo.vout,
            amount: utxo.amount,
            commitment: utxo.commitment,
            blind: utxo.blind,
            script_pubkey: utxo.script_pubkey.clone(),
            pubkey: utxo.pubkey,
            ephemeral_pubkey: utxo.ephemeral_pubkey,
            direction,
        })
    }

    /// Outpoint identity, `txid:vout`.
    ///
    /// CT outputs carry no key image, so this is also how spends are tracked.
    pub fn outpoint(&self) -> String {
        format!("{}:{}", bytes_to_hex(&self.txid), self.vout)
    }

    /// Transaction ID as hex string, in display order.
    pub fn txid_hex(&self) -> String {
        bytes_to_hex(&self.txid)
    }

    /// Rebuild the spendable [`UtxoCt`].
    pub fn to_utxo(&self) -> Result<UtxoCt> {
        Ok(UtxoCt {
            txid: bytes_to_hex(&self.txid),
            vout: self.vout,
            amount: self.amount,
            commitment: self.commitment,
            blind: self.blind,
            script_pubkey: self.script_pubkey.clone(),
            ephemeral_pubkey: self.ephemeral_pubkey,
            pubkey: self.pubkey,
            block_height: 0,
            spendable: true,
            direction: self.direction,
        })
    }
}

/// Everything cached for one wallet.
///
/// This is the resume state of a scan: where the last one stopped, what it
/// found, and which outputs were known to be spent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
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
    pub scanned_at_height: u64,
    /// Chain height at which the CT records were last walked.
    ///
    /// Tracked separately from [`Self::scanned_at_height`] because the RingCT
    /// and CT scans advance independently.
    pub ct_scanned_at_height: u64,
    /// Unspent RingCT UTXOs as of the last scan.
    pub utxos: Vec<CachedUtxo>,
    /// Unspent CT UTXOs as of the last scan.
    pub ct_utxos: Vec<CachedUtxoCt>,
    /// Key images known to be spent, hex-encoded.
    ///
    /// Still hex rather than raw bytes, unlike the UTXO fields. The spent set is
    /// hex all the way out through [`crate::balance::BalanceResult`] and the
    /// node-facing options, so storing bytes here would mean a fallible
    /// hex-to-bytes conversion on every save. A save that can fail on a
    /// malformed string is a worse trade than the ~37 bytes per entry it saves.
    pub spent_key_images: Vec<String>,
    /// Outpoints known to be spent, formatted `txid:vout`.
    ///
    /// Hex for the same reason as [`Self::spent_key_images`].
    pub spent_outpoints: Vec<String>,
    /// Every transaction ID encountered during scanning, mapped to its
    /// [`TxDirection`].
    ///
    /// Unlike [`Self::utxos`] and [`Self::ct_utxos`], which only hold
    /// **unspent** outputs, this map accumulates txids from every output the
    /// scanner decoded, including those that were subsequently spent.  That
    /// is what lets the FFI layer return a complete transaction history rather
    /// than only the current unspent set.
    ///
    /// Stored as raw 32-byte hashes in display (reversed) order so they can be
    /// hex-encoded directly on the way out.
    pub seen_txids: Vec<([u8; 32], TxDirection)>,
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
// Binary codec
// ---------------------------------------------------------------------------

/// Write a variable-length byte slice: length as u32 LE, then the bytes.
fn write_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
    buf.extend_from_slice(data);
}

/// Write a string: length as u32 LE, then UTF-8 bytes.
fn write_string(buf: &mut Vec<u8>, s: &str) {
    write_bytes(buf, s.as_bytes());
}

/// Write an optional u64: 0x00 for None, 0x01 then u64 LE for Some.
fn write_option_u64(buf: &mut Vec<u8>, value: Option<u64>) {
    match value {
        None => buf.push(0x00),
        Some(v) => {
            buf.push(0x01);
            buf.extend_from_slice(&v.to_le_bytes());
        }
    }
}

/// Write a 32-byte hash directly, no length prefix.
fn write_hash32(buf: &mut Vec<u8>, hash: &[u8; 32]) {
    buf.extend_from_slice(hash);
}

/// Write a 33-byte key image or commitment directly, no length prefix.
fn write_bytes33(buf: &mut Vec<u8>, data: &[u8; 33]) {
    buf.extend_from_slice(data);
}

/// Largest single variable-length field the decoder will accept, in bytes.
///
/// The length prefix comes from the file, so it is untrusted: a corrupt record
/// can claim up to 4 GiB and a decoder that believed it would allocate that
/// much before discovering the data is not there. Nothing legitimate comes
/// close. The largest variable field is a CT script pubkey, normally 25 bytes,
/// and a txid string is 64.
const MAX_FIELD_LEN: usize = 1024 * 1024;

/// Largest element count the decoder will accept for any collection.
///
/// Bounds the same attack as [`MAX_FIELD_LEN`] one level up: a count is also
/// read from the file, and every element costs at least one allocation.
const MAX_COLLECTION_LEN: usize = 5_000_000;

/// Take `n` bytes, refusing to read past the end.
///
/// Uses checked arithmetic throughout. `offset + n` can wrap on a 32-bit
/// target, and a wrapped sum compares as smaller than the buffer, which is
/// exactly the case that would turn a bounds check into an out-of-bounds read.
fn take<'a>(data: &'a [u8], offset: &mut usize, n: usize) -> Result<&'a [u8]> {
    let end = offset
        .checked_add(n)
        .ok_or_else(|| VeilError::cache("cache offset overflowed"))?;

    if end > data.len() {
        return Err(VeilError::cache(format!(
            "truncated record: need {n} bytes at offset {offset}, {} remain",
            data.len().saturating_sub(*offset)
        )));
    }

    let slice = &data[*offset..end];
    *offset = end;
    Ok(slice)
}

/// Read a `u8`.
fn read_u8(data: &[u8], offset: &mut usize) -> Result<u8> {
    Ok(take(data, offset, 1)?[0])
}

/// Read a little-endian `u32`.
fn read_u32(data: &[u8], offset: &mut usize) -> Result<u32> {
    let bytes = take(data, offset, 4)?;
    Ok(u32::from_le_bytes(
        bytes.try_into().expect("take returned exactly 4 bytes"),
    ))
}

/// Read a little-endian `u64`.
fn read_u64(data: &[u8], offset: &mut usize) -> Result<u64> {
    let bytes = take(data, offset, 8)?;
    Ok(u64::from_le_bytes(
        bytes.try_into().expect("take returned exactly 8 bytes"),
    ))
}

/// Read a length-prefixed byte slice, rejecting an implausible length.
fn read_bytes(data: &[u8], offset: &mut usize) -> Result<Vec<u8>> {
    let len = read_u32(data, offset)? as usize;

    // Checked before allocating, so a corrupt length cannot be turned into a
    // multi-gigabyte reservation.
    if len > MAX_FIELD_LEN {
        return Err(VeilError::cache(format!(
            "cached field claims {len} bytes, above the {MAX_FIELD_LEN}-byte limit"
        )));
    }

    Ok(take(data, offset, len)?.to_vec())
}

/// Read a length-prefixed UTF-8 string.
fn read_string(data: &[u8], offset: &mut usize) -> Result<String> {
    let bytes = read_bytes(data, offset)?;
    String::from_utf8(bytes).map_err(|_| VeilError::cache("invalid UTF-8 in cached string"))
}

/// Read a fixed-size array.
fn read_array<const N: usize>(data: &[u8], offset: &mut usize) -> Result<[u8; N]> {
    let slice = take(data, offset, N)?;
    Ok(slice.try_into().expect("take returned exactly N bytes"))
}

/// Read a 32-byte hash with no length prefix.
fn read_hash32(data: &[u8], offset: &mut usize) -> Result<[u8; 32]> {
    read_array::<32>(data, offset)
}

/// Read an element count, rejecting one too large to be real.
///
/// The returned value is also safe to use as an allocation hint, which is why
/// the cap is applied here rather than at each call site.
fn read_count(data: &[u8], offset: &mut usize, label: &str) -> Result<usize> {
    let count = read_u32(data, offset)? as usize;

    if count > MAX_COLLECTION_LEN {
        return Err(VeilError::cache(format!(
            "cached {label} count of {count} is above the {MAX_COLLECTION_LEN} limit"
        )));
    }

    // A record cannot hold more elements than it has bytes remaining, so a
    // count larger than that is corrupt no matter what the cap says. This also
    // keeps the with_capacity below proportional to the real record size.
    let remaining = data.len().saturating_sub(*offset);
    if count > remaining {
        return Err(VeilError::cache(format!(
            "cached {label} count of {count} exceeds the {remaining} bytes remaining"
        )));
    }

    Ok(count)
}

/// Read an optional u64.
fn read_option_u64(data: &[u8], offset: &mut usize) -> Result<Option<u64>> {
    match read_u8(data, offset)? {
        0x00 => Ok(None),
        0x01 => Ok(Some(read_u64(data, offset)?)),
        tag => Err(VeilError::cache(format!(
            "invalid option discriminant: {tag}"
        ))),
    }
}

/// Encode a [`CachedUtxo`] into binary.
fn encode_cached_utxo(utxo: &CachedUtxo, buf: &mut Vec<u8>) {
    write_hash32(buf, &utxo.txid);
    buf.extend_from_slice(&utxo.vout.to_le_bytes());
    buf.extend_from_slice(&utxo.amount.to_le_bytes());
    write_bytes33(buf, &utxo.commitment);
    buf.extend_from_slice(&utxo.blind);
    write_bytes33(buf, &utxo.pubkey);
    write_bytes33(buf, &utxo.ephemeral_pubkey);
    write_bytes33(buf, &utxo.key_image);
    write_option_u64(buf, utxo.ringct_index);
    buf.push(utxo.direction.as_u8());
}

/// Decode a [`CachedUtxo`] from binary.
fn decode_cached_utxo(data: &[u8], offset: &mut usize) -> Result<CachedUtxo> {
    let txid = read_hash32(data, offset)?;
    let vout = read_u32(data, offset)?;
    let amount = read_u64(data, offset)?;
    let commitment = read_array::<33>(data, offset)?;
    let blind = read_array::<32>(data, offset)?;
    let pubkey = read_array::<33>(data, offset)?;
    let ephemeral_pubkey = read_array::<33>(data, offset)?;
    let key_image = read_array::<33>(data, offset)?;
    let ringct_index = read_option_u64(data, offset)?;
    let direction = TxDirection::from_u8(read_u8(data, offset)?);

    Ok(CachedUtxo {
        txid,
        vout,
        amount,
        commitment,
        blind,
        pubkey,
        ephemeral_pubkey,
        key_image,
        ringct_index,
        direction,
    })
}

/// Encode a [`CachedUtxoCt`] into binary.
fn encode_cached_utxo_ct(utxo: &CachedUtxoCt, buf: &mut Vec<u8>) {
    write_hash32(buf, &utxo.txid);
    buf.extend_from_slice(&utxo.vout.to_le_bytes());
    buf.extend_from_slice(&utxo.amount.to_le_bytes());
    write_bytes33(buf, &utxo.commitment);
    buf.extend_from_slice(&utxo.blind);
    write_bytes(buf, &utxo.script_pubkey);
    write_bytes33(buf, &utxo.pubkey);
    write_bytes33(buf, &utxo.ephemeral_pubkey);
    buf.push(utxo.direction.as_u8());
}

/// Decode a [`CachedUtxoCt`] from binary.
fn decode_cached_utxo_ct(data: &[u8], offset: &mut usize) -> Result<CachedUtxoCt> {
    let txid = read_hash32(data, offset)?;
    let vout = read_u32(data, offset)?;
    let amount = read_u64(data, offset)?;
    let commitment = read_array::<33>(data, offset)?;
    let blind = read_array::<32>(data, offset)?;
    let script_pubkey = read_bytes(data, offset)?;
    let pubkey = read_array::<33>(data, offset)?;
    let ephemeral_pubkey = read_array::<33>(data, offset)?;
    let direction = TxDirection::from_u8(read_u8(data, offset)?);

    Ok(CachedUtxoCt {
        txid,
        vout,
        amount,
        commitment,
        blind,
        script_pubkey,
        pubkey,
        ephemeral_pubkey,
        direction,
    })
}

/// Encode [`WalletCacheData`] into binary.
fn encode_wallet_cache(data: &WalletCacheData) -> Vec<u8> {
    let mut buf = Vec::new();
    
    write_string(&mut buf, &data.wallet_id);
    buf.extend_from_slice(&data.last_processed_index.to_le_bytes());
    buf.extend_from_slice(&data.ct_last_processed_index.to_le_bytes());
    buf.extend_from_slice(&data.scanned_at_height.to_le_bytes());
    buf.extend_from_slice(&data.ct_scanned_at_height.to_le_bytes());
    
    // RingCT UTXOs
    buf.extend_from_slice(&(data.utxos.len() as u32).to_le_bytes());
    for utxo in &data.utxos {
        encode_cached_utxo(utxo, &mut buf);
    }
    
    // CT UTXOs
    buf.extend_from_slice(&(data.ct_utxos.len() as u32).to_le_bytes());
    for utxo in &data.ct_utxos {
        encode_cached_utxo_ct(utxo, &mut buf);
    }
    
    // Spent key images
    buf.extend_from_slice(&(data.spent_key_images.len() as u32).to_le_bytes());
    for ki in &data.spent_key_images {
        write_string(&mut buf, ki);
    }
    
    // Spent outpoints
    buf.extend_from_slice(&(data.spent_outpoints.len() as u32).to_le_bytes());
    for op in &data.spent_outpoints {
        write_string(&mut buf, op);
    }

    // Seen txids with direction (v4)
    buf.extend_from_slice(&(data.seen_txids.len() as u32).to_le_bytes());
    for (txid, direction) in &data.seen_txids {
        write_hash32(&mut buf, txid);
        buf.push(direction.as_u8());
    }
    
    buf
}

/// Decode [`WalletCacheData`] from binary.
fn decode_wallet_cache(data: &[u8]) -> Result<WalletCacheData> {
    let mut offset = 0;
    
    let wallet_id = read_string(data, &mut offset)?;
    let last_processed_index = read_u64(data, &mut offset)?;
    let ct_last_processed_index = read_u64(data, &mut offset)?;
    let scanned_at_height = read_u64(data, &mut offset)?;
    let ct_scanned_at_height = read_u64(data, &mut offset)?;
    
    // RingCT UTXOs
    let utxo_count = read_count(data, &mut offset, "UTXO")?;
    let mut utxos = Vec::with_capacity(utxo_count);
    for _ in 0..utxo_count {
        utxos.push(decode_cached_utxo(data, &mut offset)?);
    }
    
    // CT UTXOs
    let ct_utxo_count = read_count(data, &mut offset, "CT UTXO")?;
    let mut ct_utxos = Vec::with_capacity(ct_utxo_count);
    for _ in 0..ct_utxo_count {
        ct_utxos.push(decode_cached_utxo_ct(data, &mut offset)?);
    }
    
    // Spent key images
    let ki_count = read_count(data, &mut offset, "spent key image")?;
    let mut spent_key_images = Vec::with_capacity(ki_count);
    for _ in 0..ki_count {
        spent_key_images.push(read_string(data, &mut offset)?);
    }
    
    // Spent outpoints
    let op_count = read_count(data, &mut offset, "spent outpoint")?;
    let mut spent_outpoints = Vec::with_capacity(op_count);
    for _ in 0..op_count {
        spent_outpoints.push(read_string(data, &mut offset)?);
    }

    // Seen txids with direction (v4)
    let seen_count = read_count(data, &mut offset, "seen txid")?;
    let mut seen_txids = Vec::with_capacity(seen_count);
    for _ in 0..seen_count {
        let txid = read_hash32(data, &mut offset)?;
        let direction = TxDirection::from_u8(read_u8(data, &mut offset)?);
        seen_txids.push((txid, direction));
    }
    
    Ok(WalletCacheData {
        wallet_id,
        last_processed_index,
        ct_last_processed_index,
        scanned_at_height,
        ct_scanned_at_height,
        utxos,
        ct_utxos,
        spent_key_images,
        spent_outpoints,
        seen_txids,
    })
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

        let data: WalletCacheData = match decode_wallet_cache(payload) {
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
        let payload = encode_wallet_cache(data);
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

// ---------------------------------------------------------------------------
// Sent-transaction cache
// ---------------------------------------------------------------------------

/// A transaction this wallet successfully sent.
///
/// Recorded after `sendrawtransaction` returns, so the wallet knows which of
/// its outputs were change rather than incoming payments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentTransaction {
    /// Transaction ID, 32-byte hash in internal byte order.
    pub txid: [u8; 32],
    /// When the broadcast succeeded, as unix timestamp.
    pub sent_at: u64,
}

impl SentTransaction {
    /// Create a record for a transaction that was just broadcast.
    pub fn new(txid: [u8; 32]) -> Self {
        Self {
            txid,
            sent_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

/// Encode a [`SentTransaction`] into binary.
fn encode_sent_tx(tx: &SentTransaction, buf: &mut Vec<u8>) {
    write_hash32(buf, &tx.txid);
    buf.extend_from_slice(&tx.sent_at.to_le_bytes());
}

/// Decode a [`SentTransaction`] from binary.
fn decode_sent_tx(data: &[u8], offset: &mut usize) -> Result<SentTransaction> {
    let txid = read_hash32(data, offset)?;
    let sent_at = read_u64(data, offset)?;
    Ok(SentTransaction { txid, sent_at })
}

/// Encode a list of sent transactions.
fn encode_sent_txs(txs: &[SentTransaction]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(txs.len() as u32).to_le_bytes());
    for tx in txs {
        encode_sent_tx(tx, &mut buf);
    }
    buf
}

/// Decode a list of sent transactions.
fn decode_sent_txs(data: &[u8]) -> Result<Vec<SentTransaction>> {
    let mut offset = 0;
    let count = read_count(data, &mut offset, "sent transaction")?;
    let mut txs = Vec::with_capacity(count);
    for _ in 0..count {
        txs.push(decode_sent_tx(data, &mut offset)?);
    }
    Ok(txs)
}

/// Records transactions this wallet successfully broadcast.
///
/// Used to distinguish change (outputs in a transaction the wallet sent) from
/// incoming payments (outputs in a transaction it did not send). The two look
/// identical in the watch-only stream, so the distinction is recovered by
/// consulting this layer.
pub struct SentCache<'a> {
    store: &'a dyn CacheStore,
}

impl<'a> SentCache<'a> {
    /// Wrap a store.
    pub fn new(store: &'a dyn CacheStore) -> Self {
        Self { store }
    }

    /// Storage key for a wallet's sent-transaction list.
    fn key(wallet_id: &str) -> String {
        format!("sent/{wallet_id}")
    }

    /// Read the sent-transaction history for `wallet_id`.
    ///
    /// Returns `None` when no sent-transaction cache exists yet, which means the
    /// wallet has never recorded a broadcast. Returns `Some(vec)` when a cache
    /// exists, even if it is empty—an empty cache means the wallet has been used
    /// but has never sent a transaction, which is a different state that still
    /// permits labelling UTXOs as received rather than unknown.
    ///
    /// A corrupt record also returns `None`: the history was lost, so the safest
    /// fallback is treating it as never having existed, which keeps all UTXOs
    /// labelled [`TxDirection::Unknown`] rather than incorrectly relabelling
    /// existing change as received.
    pub fn load(&self, wallet_id: &str) -> Option<Vec<SentTransaction>> {
        let raw = self.store.load(&Self::key(wallet_id)).ok()??;
        let payload = decode_envelope(&raw).ok()?;
        decode_sent_txs(payload).ok()
    }

    /// Record that a transaction was successfully broadcast.
    ///
    /// Write failures are swallowed: sent-transaction history is derived
    /// bookkeeping, so a lost write degrades to UTXOs being labelled
    /// [`TxDirection::Unknown`] rather than stopping the broadcast.
    pub fn record(&self, wallet_id: &str, tx: &SentTransaction) -> Result<()> {
        let mut txs = self.load(wallet_id).unwrap_or_default();
        
        // Deduplicate: if a transaction was recorded once, recording it again
        // is a no-op rather than an error.
        if txs.iter().any(|t| t.txid == tx.txid) {
            return Ok(());
        }
        
        txs.push(tx.clone());
        
        let payload = encode_sent_txs(&txs);
        self.store
            .store(&Self::key(wallet_id), &encode_envelope(&payload))?;
        self.store.flush()
    }

    /// Whether `txid` is in the sent-transaction history.
    pub fn contains(&self, wallet_id: &str, txid: &[u8; 32]) -> bool {
        self.load(wallet_id)
            .map(|txs| txs.iter().any(|t| &t.txid == txid))
            .unwrap_or(false)
    }

    /// Delete the sent-transaction history for `wallet_id`.
    pub fn clear(&self, wallet_id: &str) -> Result<()> {
        self.store.remove(&Self::key(wallet_id))?;
        self.store.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Expand a short label into a full 64-character txid.
    ///
    /// A real txid is 32 bytes, and the cache now stores it as such, so a
    /// two-character stand-in no longer decodes. Repeating the label keeps the
    /// tests readable while producing something the codec accepts.
    fn txid(label: &str) -> String {
        label.repeat(64 / label.len())
    }

    fn parsed_utxo(label: &str, vout: u32, amount: u64, key_image: u8) -> ParsedUtxo {
        ParsedUtxo {
            txid: txid(label),
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

    fn parsed_utxo_ct(label: &str, vout: u32, amount: u64, script_pubkey: Vec<u8>) -> ParsedUtxoCt {
        ParsedUtxoCt {
            txid: txid(label),
            vout,
            amount,
            commitment: [0x08u8; 33],
            blind: [0xABu8; 32],
            pubkey: [0x02u8; 33],
            ephemeral_pubkey: [0x03u8; 33],
            script_pubkey,
        }
    }

    /// A 32-byte txid built from a short label, for the sent-cache tests.
    fn txid_bytes(label: &str) -> [u8; 32] {
        parse_txid(&txid(label)).expect("test labels expand to valid hex")
    }

    fn sample_data() -> WalletCacheData {
        let mut data = WalletCacheData::new("wallet-1");
        data.last_processed_index = 1_234;
        data.utxos = vec![
            CachedUtxo::from_parsed(&parsed_utxo("aa", 0, 100, 0x01)).unwrap(),
            CachedUtxo::from_parsed(&parsed_utxo("bb", 1, 250, 0x02)).unwrap(),
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
        let payload = encode_wallet_cache(&sample_data());
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
        let cached = CachedUtxo::from_parsed(&parsed).unwrap();

        assert_eq!(cached.outpoint(), format!("{}:3", txid("aa")));
        assert_eq!(cached.key_image_bytes(), [0x07u8; 33]);

        // The txid survives the string-to-bytes-to-string trip unchanged, which
        // is the property that keeps the binary representation invisible to
        // callers.
        assert_eq!(cached.to_parsed(), parsed);
        assert_eq!(cached.txid_hex(), parsed.txid);

        let utxo = cached.to_utxo().unwrap();
        assert_eq!(utxo.txid, parsed.txid);
        assert_eq!(utxo.amount, 500);
        assert_eq!(utxo.commitment, [0x08u8; 33]);
        assert_eq!(utxo.ringct_index, Some(3));
        assert!(utxo.spendable);
    }

    #[test]
    fn a_txid_that_is_not_32_bytes_is_refused() {
        // Short labels were valid stand-ins while the txid was a string. Now the
        // cache stores 32 bytes, so a malformed id has to be rejected rather
        // than silently padded or truncated into a different transaction.
        let mut parsed = parsed_utxo("aa", 0, 100, 0x01);
        parsed.txid = "abcd".to_string();

        assert!(CachedUtxo::from_parsed(&parsed).is_err());

        let mut parsed_ct = parsed_utxo_ct("cc", 0, 100, Vec::new());
        parsed_ct.txid = "not hex at all".to_string();

        assert!(CachedUtxoCt::from_parsed(&parsed_ct).is_err());
    }

    // The old "a cached UTXO with a bad field length fails to convert" test is
    // gone by construction: commitment, blind, and the keys are fixed-size
    // arrays now, so a wrong length cannot be represented in memory at all. The
    // check moved to decode time, where a truncated field is caught by
    // `a_truncated_payload_is_reported_rather_than_panicking`.

    #[test]
    fn cached_ct_utxos_also_convert_back() {
        let parsed = parsed_utxo_ct("cc", 2, 700, vec![0x76, 0xa9, 0x14]);

        let cached = CachedUtxoCt::from_parsed(&parsed).unwrap();
        assert_eq!(cached.outpoint(), format!("{}:2", txid("cc")));

        let utxo = cached.to_utxo().unwrap();
        assert_eq!(utxo.txid, parsed.txid);
        assert_eq!(utxo.amount, 700);
        assert_eq!(utxo.script_pubkey, vec![0x76, 0xa9, 0x14]);

        let mut data = WalletCacheData::new("wallet-ct");
        data.ct_utxos = vec![cached];
        assert_eq!(data.total_balance_ct(), 700);
    }

    #[test]
    fn sent_transaction_history_round_trips() {
        let store = MemoryStore::new();
        let cache = SentCache::new(&store);

        // Nothing recorded yet is None, not an empty list: the wallet cannot
        // claim it has sent nothing, only that it does not know.
        assert_eq!(cache.load("wallet-1"), None);

        let tx1 = SentTransaction {
            txid: txid_bytes("aa"),
            sent_at: 1234567890,
        };

        cache.record("wallet-1", &tx1).unwrap();
        assert_eq!(cache.load("wallet-1"), Some(vec![tx1.clone()]));
        assert!(cache.contains("wallet-1", &txid_bytes("aa")));
        assert!(!cache.contains("wallet-1", &txid_bytes("bb")));

        let tx2 = SentTransaction {
            txid: txid_bytes("bb"),
            sent_at: 1234567900,
        };

        cache.record("wallet-1", &tx2).unwrap();
        let loaded = cache.load("wallet-1").unwrap();
        assert_eq!(loaded.len(), 2);
        assert!(loaded.contains(&tx1));
        assert!(loaded.contains(&tx2));

        // Clearing takes the history back to "unknown", not to "sent nothing".
        cache.clear("wallet-1").unwrap();
        assert_eq!(cache.load("wallet-1"), None);
    }

    #[test]
    fn an_empty_history_is_distinct_from_an_absent_one() {
        // This is the distinction the direction labelling depends on. A wallet
        // with a recorded but empty history has sent nothing, so its outputs
        // were all received. A wallet with no record cannot say either way, and
        // must stay Unknown.
        let store = MemoryStore::new();
        let cache = SentCache::new(&store);

        assert_eq!(cache.load("wallet-1"), None);

        // Write an empty history explicitly, as a wallet that has been scanned
        // but has never spent would have.
        let payload = encode_sent_txs(&[]);
        store
            .store(&SentCache::key("wallet-1"), &encode_envelope(&payload))
            .unwrap();

        assert_eq!(cache.load("wallet-1"), Some(Vec::new()));
    }

    #[test]
    fn recording_a_transaction_twice_is_a_no_op() {
        let store = MemoryStore::new();
        let cache = SentCache::new(&store);

        let tx = SentTransaction {
            txid: txid_bytes("aa"),
            sent_at: 1234567890,
        };

        cache.record("wallet-1", &tx).unwrap();
        cache.record("wallet-1", &tx).unwrap();
        cache.record("wallet-1", &tx).unwrap();

        let loaded = cache.load("wallet-1").unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0], tx);
    }

    #[test]
    fn sent_cache_degrades_gracefully_when_corrupted() {
        let store = MemoryStore::new();
        let cache = SentCache::new(&store);

        store
            .store(&SentCache::key("wallet-1"), b"corrupted")
            .unwrap();

        // A damaged record returns None rather than erroring, so the balance
        // scan continues with all UTXOs labelled Unknown.
        assert_eq!(cache.load("wallet-1"), None);
        assert!(!cache.contains("wallet-1", &txid_bytes("aa")));
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
    fn the_scan_height_round_trips() {
        let mut data = sample_data();
        data.scanned_at_height = 1_500_000;
        data.ct_scanned_at_height = 1_499_000;

        let store = MemoryStore::new();
        let cache = BalanceCache::new(&store);
        cache.save(&data).unwrap();

        let loaded = cache.load("wallet-1").data().unwrap();
        assert_eq!(loaded.scanned_at_height, 1_500_000);
        assert_eq!(loaded.ct_scanned_at_height, 1_499_000);
    }

    #[test]
    fn every_field_survives_the_binary_codec() {
        // A record with all fields populated, including the ones an empty
        // sample would leave at their defaults, so a codec that silently drops
        // a field is caught rather than passing by coincidence.
        let mut data = WalletCacheData::new("wallet-full");
        data.last_processed_index = u64::MAX - 3;
        data.ct_last_processed_index = 987_654;
        data.scanned_at_height = 1_234_567;
        data.ct_scanned_at_height = 1_234_000;

        data.utxos = vec![
            CachedUtxo::from_parsed_with_direction(
                &parsed_utxo("aa", 0, 100, 0x01),
                TxDirection::Send,
            )
            .unwrap(),
            CachedUtxo::from_parsed_with_direction(
                &parsed_utxo("bb", u32::MAX, u64::MAX, 0x02),
                TxDirection::Receive,
            )
            .unwrap(),
            // A UTXO with no global index, which is the None branch of the
            // option encoding.
            {
                let mut parsed = parsed_utxo("cc", 7, 42, 0x03);
                parsed.ringct_index = None;
                CachedUtxo::from_parsed(&parsed).unwrap()
            },
        ];

        data.ct_utxos = vec![
            CachedUtxoCt::from_parsed_with_direction(
                &parsed_utxo_ct("dd", 1, 700, vec![0x76, 0xa9, 0x14]),
                TxDirection::Send,
            )
            .unwrap(),
            // An empty script, which is the zero-length branch of write_bytes.
            CachedUtxoCt::from_parsed(&parsed_utxo_ct("ee", 2, 800, Vec::new())).unwrap(),
        ];

        data.spent_key_images = vec![bytes_to_hex(&[0x09u8; 33]), bytes_to_hex(&[0x0Au8; 33])];
        data.spent_outpoints = vec!["ff:0".to_string(), "ff:1".to_string()];

        let store = MemoryStore::new();
        let cache = BalanceCache::new(&store);
        cache.save(&data).unwrap();

        assert_eq!(cache.load("wallet-full").data().unwrap(), data);
    }

    #[test]
    fn binary_records_are_smaller_than_their_hex_equivalent() {
        // The point of the codec is size. A cached UTXO holds 164 bytes of
        // fixed-length keys and commitments; as hex those alone cost 328
        // characters before quoting or field names.
        let data = sample_data();
        let payload = encode_wallet_cache(&data);

        let hex_bytes_per_utxo = (33 + 32 + 33 + 33 + 33) * 2;
        let hex_floor = data.utxos.len() * hex_bytes_per_utxo;

        assert!(
            payload.len() < hex_floor,
            "binary payload of {} bytes should beat the {hex_floor}-byte hex floor",
            payload.len()
        );
    }

    #[test]
    fn a_truncated_payload_is_reported_rather_than_panicking() {
        // Every decode path is bounds-checked, so a payload cut at any offset
        // must come back as an error. A panic here would take down a caller
        // that only wanted a balance.
        let payload = encode_wallet_cache(&sample_data());

        for cut in 0..payload.len() {
            let result = decode_wallet_cache(&payload[..cut]);
            assert!(
                result.is_err(),
                "a payload truncated to {cut} of {} bytes decoded anyway",
                payload.len()
            );
        }

        // The intact payload still decodes, so the loop above was not passing
        // because the codec rejects everything.
        assert!(decode_wallet_cache(&payload).is_ok());
    }

    #[test]
    fn an_unrecognized_direction_byte_reads_as_unknown() {
        // Direction is derived bookkeeping. A value this build does not know
        // must degrade to Unknown rather than making the whole record corrupt
        // and forcing a full rescan.
        let mut data = WalletCacheData::new("wallet-1");
        data.utxos = vec![CachedUtxo::from_parsed_with_direction(
            &parsed_utxo("aa", 0, 100, 0x01),
            TxDirection::Send,
        )
        .unwrap()];

        // Locate the direction byte by encoding the same record twice, once per
        // direction, and finding where the two differ. Hardcoding an offset
        // would silently start testing the wrong byte the moment a field is
        // added ahead of it.
        let mut receive = data.clone();
        receive.utxos[0].direction = TxDirection::Receive;

        let sent_payload = encode_wallet_cache(&data);
        let receive_payload = encode_wallet_cache(&receive);

        let differing: Vec<usize> = sent_payload
            .iter()
            .zip(receive_payload.iter())
            .enumerate()
            .filter_map(|(i, (a, b))| (a != b).then_some(i))
            .collect();

        assert_eq!(
            differing.len(),
            1,
            "direction should occupy exactly one byte, found {differing:?}"
        );

        let mut payload = sent_payload;
        payload[differing[0]] = 0x7F;

        let decoded = decode_wallet_cache(&payload).unwrap();
        assert_eq!(decoded.utxos[0].direction, TxDirection::Unknown);
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
