//! Balance retrieval.
//!
//! Port of `src/balance.ts`. Walks the node's watch-only records page by page,
//! decodes the outputs that belong to the wallet, filters out spent ones, and
//! sums the rest.
//!
//! Each page is fully processed before the next is fetched, so peak memory stays
//! proportional to one page rather than the whole wallet history.
//!
//! Gated behind the `rpc` feature.

use crate::cache::{
    wallet_id, BalanceCache, CacheInfo, CacheLoad, CacheStore, CachedUtxo, CachedUtxoCt,
    RecoveryPolicy, SentCache, SentTransaction, WalletCacheData,
};
use crate::error::{Result, VeilError};
use crate::rpc::RpcClient;
use crate::types::{KeyImage, SecretKey, TxDirection, Utxo, UtxoCt};
use crate::utils::bytes_to_hex;
use crate::watch_only_tx::{
    parse_watch_only_transactions, parse_watch_only_transactions_ct, ParsedUtxo, ParsedUtxoCt,
    TransactionMetadata,
};
use std::collections::HashSet;

/// Page size the node uses for `getwatchonlytxes`.
const PAGE_SIZE: usize = 1000;

/// Default number of key images to check per RPC round trip.
pub const DEFAULT_KEY_IMAGE_BATCH_SIZE: usize = 1000;

/// Options for [`get_balance`].
#[derive(Debug, Clone, Default)]
pub struct GetBalanceOptions {
    /// Key images already known to be spent, hex-encoded.
    ///
    /// Carry these over between calls to avoid re-checking them.
    pub known_spent_key_images: HashSet<String>,
    /// Record index to resume from.
    pub start_index: u64,
    /// Key images to check per RPC call; `None` uses the default.
    pub key_image_batch_size: Option<usize>,
}

impl GetBalanceOptions {
    fn batch_size(&self) -> Result<usize> {
        let size = self
            .key_image_batch_size
            .unwrap_or(DEFAULT_KEY_IMAGE_BATCH_SIZE);

        if !(1..=10_000).contains(&size) {
            return Err(VeilError::invalid_input(format!(
                "key_image_batch_size must be between 1 and 10000, got {size}"
            )));
        }

        Ok(size)
    }
}

/// The outcome of a balance scan.
#[derive(Debug, Clone, Default)]
pub struct BalanceResult {
    /// Sum of all unspent UTXOs, in satoshis.
    pub total_balance: u64,
    /// The unspent UTXOs found.
    pub utxos: Vec<Utxo>,
    /// Index to resume from on the next call.
    pub last_processed_index: u64,
    /// Every key image known to be spent, hex-encoded. Cache these.
    pub spent_key_images: HashSet<String>,
    /// Number of records fetched from the node.
    pub total_outputs_scanned: usize,
    /// Number of records that belonged to this wallet.
    pub owned_outputs_found: usize,
}

/// Options for [`get_balance_ct`].
#[derive(Debug, Clone, Default)]
pub struct GetBalanceCtOptions {
    /// Record index to resume from.
    pub start_index: u64,
    /// Outpoints already known to be spent, formatted `txid:vout`.
    ///
    /// CT outputs have no key images, so spends are tracked by outpoint.
    pub known_spent_outpoints: HashSet<String>,
}

/// The outcome of a CT balance scan.
#[derive(Debug, Clone, Default)]
pub struct BalanceResultCt {
    /// Sum of all unspent CT UTXOs, in satoshis.
    pub total_balance: u64,
    /// The unspent CT UTXOs found.
    pub utxos: Vec<UtxoCt>,
    /// Index to resume from on the next call.
    pub last_processed_index: u64,
    /// Number of records fetched from the node.
    pub total_outputs_scanned: usize,
    /// Number of records that belonged to this wallet.
    pub owned_outputs_found: usize,
}

/// Ask the node which of `key_images` are spent, recording the results.
///
/// Images already present in `known_spent` are not re-checked.
async fn check_key_images_spent_status(
    client: &RpcClient,
    key_images: &[KeyImage],
    known_spent: &mut HashSet<String>,
    batch_size: usize,
) -> Result<()> {
    let to_check: Vec<KeyImage> = key_images
        .iter()
        .filter(|ki| !known_spent.contains(&bytes_to_hex(ki.as_slice())))
        .copied()
        .collect();

    if to_check.is_empty() {
        return Ok(());
    }

    for batch in to_check.chunks(batch_size) {
        for status in client.check_key_images(batch).await? {
            if status.is_spent() {
                known_spent.insert(status.key_image);
            }
        }
    }

    Ok(())
}

/// Hex-encode a key image into a caller-supplied buffer.
///
/// The spent set is keyed by hex string, so every membership test needs the hex
/// form of a key image. Allocating a `String` per test costs one allocation per
/// UTXO per pass, and the spent check runs three times per scan. Writing into a
/// reused stack buffer removes all of them while leaving the set's key type, and
/// therefore the spend-detection logic, untouched.
fn key_image_hex_in<'a>(key_image: &KeyImage, buf: &'a mut [u8; 66]) -> &'a str {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    for (i, byte) in key_image.iter().enumerate() {
        buf[i * 2] = HEX[usize::from(byte >> 4)];
        buf[i * 2 + 1] = HEX[usize::from(byte & 0x0f)];
    }

    std::str::from_utf8(buf).expect("hex digits are always valid UTF-8")
}

/// A cached output that can be labelled with where it came from.
///
/// Exists so the two scan paths share one labelling implementation instead of
/// carrying a copy each, which is how the RingCT and CT rules would drift apart.
trait Directional {
    /// The transaction that created this output, as a raw hash.
    fn txid(&self) -> &[u8; 32];
    /// Record where the output came from.
    fn set_direction(&mut self, direction: TxDirection);
}

impl Directional for CachedUtxo {
    fn txid(&self) -> &[u8; 32] {
        &self.txid
    }

    fn set_direction(&mut self, direction: TxDirection) {
        self.direction = direction;
    }
}

impl Directional for CachedUtxoCt {
    fn txid(&self) -> &[u8; 32] {
        &self.txid
    }

    fn set_direction(&mut self, direction: TxDirection) {
        self.direction = direction;
    }
}

/// Label each output as change or incoming, given the wallet's send history.
///
/// This is the one place the two cache layers meet. An output whose transaction
/// the wallet broadcast is change; anything else in a wallet with a known history
/// arrived from elsewhere. Callers pass `None` when no history exists, which
/// leaves every direction untouched at [`TxDirection::Unknown`], because a wallet
/// that cannot remember what it sent cannot honestly call anything received.
fn label_directions<T: Directional>(utxos: &mut [T], sent: Option<&HashSet<[u8; 32]>>) {
    let Some(sent) = sent else {
        return;
    };

    for utxo in utxos {
        let direction = if sent.contains(utxo.txid()) {
            TxDirection::Send
        } else {
            TxDirection::Receive
        };

        utxo.set_direction(direction);
    }
}

/// Drop spent RingCT UTXOs and convert the rest into [`Utxo`] values.
fn filter_unspent(
    parsed: Vec<ParsedUtxo>,
    spent_key_images: &HashSet<String>,
) -> (Vec<Utxo>, Vec<ParsedUtxo>) {
    let mut unspent_utxos = Vec::new();
    let mut unspent_parsed = Vec::new();

    for utxo in parsed {
        if spent_key_images.contains(&bytes_to_hex(utxo.key_image.as_slice())) {
            continue;
        }

        unspent_utxos.push(Utxo {
            txid: utxo.txid.clone(),
            vout: utxo.vout,
            amount: utxo.amount,
            commitment: utxo.commitment,
            blind: utxo.blind,
            pubkey: utxo.pubkey,
            ephemeral_pubkey: utxo.ephemeral_pubkey,
            block_height: 0, // Not reported by getwatchonlytxes.
            spendable: true,
            ringct_index: utxo.ringct_index,
            direction: TxDirection::Unknown,
        });
        unspent_parsed.push(utxo);
    }

    (unspent_utxos, unspent_parsed)
}

/// Drop spent CT UTXOs and convert the rest into [`UtxoCt`] values.
fn filter_unspent_ct(
    parsed: Vec<ParsedUtxoCt>,
    spent_outpoints: &HashSet<String>,
) -> (Vec<UtxoCt>, Vec<ParsedUtxoCt>) {
    let mut unspent_utxos = Vec::new();
    let mut unspent_parsed = Vec::new();

    for utxo in parsed {
        if spent_outpoints.contains(&format!("{}:{}", utxo.txid, utxo.vout)) {
            continue;
        }

        unspent_utxos.push(UtxoCt {
            txid: utxo.txid.clone(),
            vout: utxo.vout,
            amount: utxo.amount,
            commitment: utxo.commitment,
            blind: utxo.blind,
            script_pubkey: utxo.script_pubkey.clone(),
            ephemeral_pubkey: utxo.ephemeral_pubkey,
            pubkey: utxo.pubkey,
            block_height: 0,
            spendable: true,
            direction: TxDirection::Unknown,
        });
        unspent_parsed.push(utxo);
    }

    (unspent_utxos, unspent_parsed)
}

/// Fetch the wallet's RingCT balance.
///
/// Pass [`BalanceResult::last_processed_index`] and
/// [`BalanceResult::spent_key_images`] back in on a later call to resume instead
/// of rescanning from the start.
pub async fn get_balance(
    client: &RpcClient,
    spend_secret: &SecretKey,
    scan_secret: &SecretKey,
    options: &GetBalanceOptions,
) -> Result<BalanceResult> {
    get_balance_with_callback(client, spend_secret, scan_secret, options, |_| {}).await
}

/// Fetch the wallet's RingCT balance, reporting each page as it is processed.
///
/// `on_utxos` receives only the unspent UTXOs from each page, which suits
/// incremental UI updates on large wallets.
pub async fn get_balance_with_callback<F>(
    client: &RpcClient,
    spend_secret: &SecretKey,
    scan_secret: &SecretKey,
    options: &GetBalanceOptions,
    mut on_utxos: F,
) -> Result<BalanceResult>
where
    F: FnMut(&[ParsedUtxo]),
{
    let batch_size = options.batch_size()?;

    let mut all_unspent: Vec<Utxo> = Vec::new();
    let mut total_balance: u64 = 0;
    let mut current_index = options.start_index;
    let mut last_processed_index = options.start_index;
    let mut total_outputs_scanned = 0usize;
    let mut owned_outputs_found = 0usize;
    let mut spent_key_images = options.known_spent_key_images.clone();

    let scan_secret_hex = bytes_to_hex(scan_secret);

    loop {
        let page = client
            .get_watch_only_txes(&scan_secret_hex, current_index)
            .await?;

        if page.anon.is_empty() {
            break;
        }

        total_outputs_scanned += page.anon.len();

        let raw: Vec<String> = page.anon.iter().map(|r| r.raw.clone()).collect();
        let metadata: Vec<TransactionMetadata> = page
            .anon
            .iter()
            .map(|r| TransactionMetadata {
                amount: r.amount,
                blind: r.blind,
                ringct_index: r.ringct_index,
            })
            .collect();

        let parsed =
            parse_watch_only_transactions(&raw, spend_secret, scan_secret, Some(&metadata));
        owned_outputs_found += parsed.len();

        let key_images: Vec<KeyImage> = parsed.iter().map(|u| u.key_image).collect();
        check_key_images_spent_status(client, &key_images, &mut spent_key_images, batch_size)
            .await?;

        let (page_unspent, page_parsed) = filter_unspent(parsed, &spent_key_images);

        total_balance = total_balance.saturating_add(
            page_unspent
                .iter()
                .fold(0u64, |acc, u| acc.saturating_add(u.amount)),
        );
        all_unspent.extend(page_unspent);

        if !page_parsed.is_empty() {
            on_utxos(&page_parsed);
        }

        // Advance using the node's own index so no record is processed twice.
        if let Some(dbindex) = page.anon.last().and_then(|r| r.dbindex) {
            last_processed_index = dbindex + 1;
        } else if page.anon.len() >= PAGE_SIZE {
            // Without a dbindex there is no safe way to advance a full page.
            return Err(VeilError::rpc(
                "getwatchonlytxes returned a full page without a dbindex, cannot paginate safely",
            ));
        }

        if page.anon.len() < PAGE_SIZE {
            break;
        }

        current_index = last_processed_index;
    }

    Ok(BalanceResult {
        total_balance,
        utxos: all_unspent,
        last_processed_index,
        spent_key_images,
        total_outputs_scanned,
        owned_outputs_found,
    })
}

/// Fetch the wallet's CT (stealth) balance.
///
/// CT outputs carry no key images, so spends must be tracked externally through
/// [`GetBalanceCtOptions::known_spent_outpoints`].
pub async fn get_balance_ct(
    client: &RpcClient,
    spend_secret: &SecretKey,
    scan_secret: &SecretKey,
    options: &GetBalanceCtOptions,
) -> Result<BalanceResultCt> {
    get_balance_ct_with_callback(client, spend_secret, scan_secret, options, |_| {}).await
}

/// Fetch the wallet's CT balance, reporting each page as it is processed.
pub async fn get_balance_ct_with_callback<F>(
    client: &RpcClient,
    spend_secret: &SecretKey,
    scan_secret: &SecretKey,
    options: &GetBalanceCtOptions,
    mut on_utxos: F,
) -> Result<BalanceResultCt>
where
    F: FnMut(&[ParsedUtxoCt]),
{
    let mut all_unspent: Vec<UtxoCt> = Vec::new();
    let mut total_balance: u64 = 0;
    let mut current_index = options.start_index;
    let mut last_processed_index = options.start_index;
    let mut total_outputs_scanned = 0usize;
    let mut owned_outputs_found = 0usize;

    let scan_secret_hex = bytes_to_hex(scan_secret);

    loop {
        let page = client
            .get_watch_only_txes(&scan_secret_hex, current_index)
            .await?;

        if page.stealth.is_empty() {
            break;
        }

        total_outputs_scanned += page.stealth.len();

        let raw: Vec<String> = page.stealth.iter().map(|r| r.raw.clone()).collect();
        let metadata: Vec<TransactionMetadata> = page
            .stealth
            .iter()
            .map(|r| TransactionMetadata {
                amount: r.amount,
                blind: r.blind,
                ringct_index: None,
            })
            .collect();

        let parsed =
            parse_watch_only_transactions_ct(&raw, spend_secret, scan_secret, Some(&metadata));
        owned_outputs_found += parsed.len();

        let (page_unspent, page_parsed) =
            filter_unspent_ct(parsed, &options.known_spent_outpoints);

        total_balance = total_balance.saturating_add(
            page_unspent
                .iter()
                .fold(0u64, |acc, u| acc.saturating_add(u.amount)),
        );
        all_unspent.extend(page_unspent);

        if !page_parsed.is_empty() {
            on_utxos(&page_parsed);
        }

        if let Some(dbindex) = page.stealth.last().and_then(|r| r.dbindex) {
            last_processed_index = dbindex + 1;
        } else if page.stealth.len() >= PAGE_SIZE {
            return Err(VeilError::rpc(
                "getwatchonlytxes returned a full page without a dbindex, cannot paginate safely",
            ));
        }

        if page.stealth.len() < PAGE_SIZE {
            break;
        }

        current_index = last_processed_index;
    }

    Ok(BalanceResultCt {
        total_balance,
        utxos: all_unspent,
        last_processed_index,
        total_outputs_scanned,
        owned_outputs_found,
    })
}

// ---------------------------------------------------------------------------
// Cached scanning
// ---------------------------------------------------------------------------

/// A balance result together with what the cache contributed to it.
#[derive(Debug, Clone, Default)]
pub struct CachedBalanceResult {
    /// The balance itself, identical in meaning to an uncached scan's result.
    ///
    /// [`BalanceResult::total_outputs_scanned`] counts only records actually
    /// fetched this call, so on a cache hit it reflects the incremental work
    /// done rather than the size of the wallet's history.
    pub balance: BalanceResult,
    /// What the cache contributed, and why it was rejected when it was.
    pub cache: CacheInfo,
}

/// A balance result for CT outputs, together with cache statistics.
#[derive(Debug, Clone, Default)]
pub struct CachedBalanceResultCt {
    /// The CT balance.
    pub balance: BalanceResultCt,
    /// What the cache contributed.
    pub cache: CacheInfo,
}

/// Scans a wallet's balance, optionally through a persistent cache.
///
/// Without a cache this behaves like [`get_balance`]: every record is fetched
/// from the node. With one, only records added since the last scan are fetched,
/// and cached UTXOs are re-verified according to a [`RecoveryPolicy`].
///
/// ```no_run
/// # use veilrustlib::balance::BalanceScanner;
/// # use veilrustlib::cache::{MemoryStore, RecoveryPolicy};
/// # use veilrustlib::rpc::RpcClient;
/// # async fn example(client: &RpcClient, spend: &[u8; 32], scan: &[u8; 32])
/// #     -> Result<(), veilrustlib::VeilError> {
/// let store = MemoryStore::new();
///
/// let result = BalanceScanner::new(client)
///     .with_cache(&store)
///     .with_recovery(RecoveryPolicy::Rewind(50))
///     .balance(spend, scan)
///     .await?;
///
/// println!("{} satoshis, {} from cache", result.balance.total_balance, result.cache.loaded);
/// # Ok(())
/// # }
/// ```
///
/// ## Failure behaviour
///
/// A cache is an optimization and is never allowed to break a scan. An
/// unreachable store, a corrupt record, or one written by another schema
/// version all fall back to a full scan from the node, with the reason recorded
/// in [`CacheInfo::note`]. Write failures are reported the same way rather than
/// returned as errors, which is what lets the same code path run on wasm with no
/// database available.
pub struct BalanceScanner<'a> {
    client: &'a RpcClient,
    store: Option<&'a dyn CacheStore>,
    recovery: RecoveryPolicy,
    key_image_batch_size: Option<usize>,
    extra_spent_outpoints: HashSet<String>,
}

impl<'a> BalanceScanner<'a> {
    /// Scan through `client`, with no cache.
    pub fn new(client: &'a RpcClient) -> Self {
        Self {
            client,
            store: None,
            recovery: RecoveryPolicy::default(),
            key_image_batch_size: None,
            extra_spent_outpoints: HashSet::new(),
        }
    }

    /// Cache results in `store`.
    ///
    /// Pass a [`crate::cache::RedbStore`] to persist to a single file, or a
    /// [`crate::cache::MemoryStore`] where there is no filesystem.
    pub fn with_cache(mut self, store: &'a dyn CacheStore) -> Self {
        self.store = Some(store);
        self
    }

    /// Set how much of the cache to re-verify against the node.
    ///
    /// Defaults to [`RecoveryPolicy::Rewind`] with
    /// [`crate::cache::DEFAULT_REWIND_RECORDS`] records.
    pub fn with_recovery(mut self, policy: RecoveryPolicy) -> Self {
        self.recovery = policy;
        self
    }

    /// Set how many key images to check per RPC round trip.
    pub fn with_key_image_batch_size(mut self, size: usize) -> Self {
        self.key_image_batch_size = Some(size);
        self
    }

    /// Supply CT outpoints known to be spent, formatted `txid:vout`.
    ///
    /// CT outputs have no key images, so the node cannot be asked whether one
    /// was spent. These are merged into the cached set and persisted.
    pub fn with_spent_outpoints(mut self, outpoints: HashSet<String>) -> Self {
        self.extra_spent_outpoints = outpoints;
        self
    }

    // -----------------------------------------------------------------------
    // Sent-transaction history
    // -----------------------------------------------------------------------

    /// Record that this wallet successfully broadcast `txid`.
    ///
    /// Call this after `sendrawtransaction` returns. The recorded history is
    /// what lets a later scan label change as [`TxDirection::Send`] instead of
    /// [`TxDirection::Unknown`].
    ///
    /// Does nothing when no cache is configured, since there is nowhere to keep
    /// the record. A store that cannot be written returns an error, but callers
    /// should treat it as non-fatal: the transaction is already broadcast, and
    /// the only loss is direction labelling.
    ///
    /// # Errors
    ///
    /// Returns [`VeilError::Cache`] when `txid` is not 64 hex characters, since
    /// a record filed under a mangled id would never match a scanned output.
    pub fn record_sent(&self, scan_secret: &SecretKey, txid: &str) -> Result<()> {
        let Some(store) = self.store else {
            return Ok(());
        };

        // The txid arrives as the hex string the node returned, and is stored as
        // the 32 bytes it spells. This is the same encoding CachedUtxo uses, so
        // the two sides compare directly during direction labelling.
        let hash = crate::utils::hex_to_array::<32>(txid)
            .map_err(|e| VeilError::cache(format!("sent txid {txid:?} is not 32 bytes of hex: {e}")))?;

        SentCache::new(store).record(&wallet_id(scan_secret), &SentTransaction::new(hash))
    }

    /// Broadcast `tx_hex` and record it as sent if the node accepts it.
    ///
    /// The order matters and is deliberate: the transaction is broadcast first,
    /// and only a txid the node actually returned is recorded. Recording first
    /// would claim a send that may never have happened.
    ///
    /// A failed cache write does not fail the broadcast. The transaction is
    /// already irreversibly on the network at that point, so reporting an error
    /// would invite a caller to retry and pay twice. The lost record only means
    /// the resulting change shows as [`TxDirection::Unknown`].
    ///
    /// Returns the txid the node reported.
    pub async fn broadcast_and_record(
        &self,
        scan_secret: &SecretKey,
        tx_hex: &str,
    ) -> Result<String> {
        let txid = self.client.send_raw_transaction(tx_hex).await?;

        // Deliberately ignored: see the note above on why this cannot fail the
        // call.
        let _ = self.record_sent(scan_secret, &txid);

        Ok(txid)
    }

    /// Read this wallet's sent-transaction history.
    ///
    /// Empty when no cache is configured or nothing has been recorded.
    pub fn sent_transactions(&self, scan_secret: &SecretKey) -> Vec<SentTransaction> {
        match self.store {
            Some(store) => SentCache::new(store).load(&wallet_id(scan_secret)).unwrap_or_default(),
            None => Vec::new(),
        }
    }

    /// Forget this wallet's sent-transaction history.
    ///
    /// Directions fall back to [`TxDirection::Unknown`] on the next scan, since
    /// the wallet no longer has anything to compare against.
    pub fn clear_sent(&self, scan_secret: &SecretKey) -> Result<()> {
        match self.store {
            Some(store) => SentCache::new(store).clear(&wallet_id(scan_secret)),
            None => Ok(()),
        }
    }

    /// The set of txids this wallet has sent, for direction labelling.
    ///
    /// Returns `None` when no history is available at all, which is the case
    /// that must stay [`TxDirection::Unknown`]: an empty history and an absent
    /// one are different claims. An empty recorded history means "this wallet
    /// has sent nothing", so everything it owns was received. An absent one
    /// means nothing is known either way.
    fn sent_txids(&self, scan_secret: &SecretKey) -> Option<HashSet<[u8; 32]>> {
        let store = self.store?;
        let history = SentCache::new(store).load(&wallet_id(scan_secret))?;

        // An empty cache is still a usable history: it means this wallet has been
        // used but has never sent a transaction, so every owned output was received.
        Some(history.into_iter().map(|tx| tx.txid).collect())
    }

    /// Fetch the RingCT balance, using and updating the cache.
    pub async fn balance(
        &self,
        spend_secret: &SecretKey,
        scan_secret: &SecretKey,
    ) -> Result<CachedBalanceResult> {
        self.scan(spend_secret, scan_secret, false).await
    }

    /// Return the cached RingCT balance without contacting the node.
    ///
    /// Makes no requests at all, so it returns as fast as the store can be read.
    /// This is the call a UI makes on startup to show the last known balance
    /// immediately, then follows with [`Self::balance`] to revalidate.
    ///
    /// The result may be stale, and [`CacheInfo::up_to_date`] is false to say so.
    /// With no cache configured, or with nothing cached yet, the balance is zero
    /// and [`CacheInfo::loaded`] is zero.
    pub async fn cached_balance(
        &self,
        spend_secret: &SecretKey,
        scan_secret: &SecretKey,
    ) -> Result<CachedBalanceResult> {
        let cache_only = Self {
            client: self.client,
            store: self.store,
            recovery: RecoveryPolicy::CacheOnly,
            key_image_batch_size: self.key_image_batch_size,
            extra_spent_outpoints: self.extra_spent_outpoints.clone(),
        };

        cache_only.scan(spend_secret, scan_secret, false).await
    }

    /// Return the cached CT balance without contacting the node.
    ///
    /// The CT counterpart of [`Self::cached_balance`].
    pub async fn cached_balance_ct(
        &self,
        spend_secret: &SecretKey,
        scan_secret: &SecretKey,
    ) -> Result<CachedBalanceResultCt> {
        let cache_only = Self {
            client: self.client,
            store: self.store,
            recovery: RecoveryPolicy::CacheOnly,
            key_image_batch_size: self.key_image_batch_size,
            extra_spent_outpoints: self.extra_spent_outpoints.clone(),
        };

        cache_only.scan_ct(spend_secret, scan_secret, false).await
    }

    /// Fetch the RingCT balance, re-walking every record from the beginning.
    ///
    /// Ignores both the cached UTXOs and the cached resume point, so it costs the
    /// same as a first-ever scan. The cache is rebuilt from the result, which
    /// makes this the way to audit a cache suspected of being wrong in a way the
    /// integrity checks cannot detect.
    pub async fn rescan(
        &self,
        spend_secret: &SecretKey,
        scan_secret: &SecretKey,
    ) -> Result<CachedBalanceResult> {
        self.scan(spend_secret, scan_secret, true).await
    }

    /// Delete this wallet's cached state.
    ///
    /// Does nothing when no cache is configured.
    pub fn clear_cache(&self, scan_secret: &SecretKey) -> Result<()> {
        match self.store {
            Some(store) => BalanceCache::new(store).clear(&wallet_id(scan_secret)),
            None => Ok(()),
        }
    }

    /// Read the cached state without contacting the node.
    ///
    /// Returns [`CacheLoad::Unavailable`] when no cache is configured, since
    /// from the caller's point of view that is the same situation as a store
    /// that cannot be read.
    pub fn peek_cache(&self, scan_secret: &SecretKey) -> CacheLoad {
        match self.store {
            Some(store) => BalanceCache::new(store).load(&wallet_id(scan_secret)),
            None => CacheLoad::Unavailable("no cache is configured".to_string()),
        }
    }

    /// Options for one incremental pass.
    fn options(&self, start_index: u64, known_spent: HashSet<String>) -> GetBalanceOptions {
        GetBalanceOptions {
            known_spent_key_images: known_spent,
            start_index,
            key_image_batch_size: self.key_image_batch_size,
        }
    }

    /// Load the cached record, deciding whether it can be trusted.
    ///
    /// Returns the starting state and the cache statistics that describe how it
    /// was obtained. A damaged record is discarded here, so callers downstream
    /// only ever see data that passed every check.
    fn open_cache(
        &self,
        cache: &BalanceCache<'_>,
        id: &str,
        force_full: bool,
    ) -> (WalletCacheData, CacheInfo) {
        let mut info = CacheInfo {
            enabled: true,
            ..Default::default()
        };

        if force_full {
            info.rebuilt = true;
            info.note = Some("a full rescan was requested".to_string());
            return (WalletCacheData::new(id), info);
        }

        match cache.load(id) {
            CacheLoad::Loaded(data) => {
                info.loaded = data.utxos.len() + data.ct_utxos.len();
                (*data, info)
            }
            CacheLoad::Missing => (WalletCacheData::new(id), info),
            CacheLoad::Corrupt(reason) => {
                info.rebuilt = true;
                info.note = Some(format!("cache was corrupt, rebuilding: {reason}"));
                // Drop the bad record so a later failure cannot resurrect it.
                let _ = cache.clear(id);
                (WalletCacheData::new(id), info)
            }
            CacheLoad::Stale { found, expected } => {
                info.rebuilt = true;
                info.note = Some(format!(
                    "cache uses schema version {found}, this build expects {expected}; rebuilding"
                ));
                let _ = cache.clear(id);
                (WalletCacheData::new(id), info)
            }
            CacheLoad::Unavailable(reason) => {
                info.rebuilt = true;
                info.note = Some(format!("cache is unavailable, scanning from the node: {reason}"));
                (WalletCacheData::new(id), info)
            }
        }
    }

    /// Persist `data`, downgrading a write failure to a note.
    ///
    /// A cache that cannot be written is a lost optimization, not a failed
    /// balance query.
    fn save_cache(&self, cache: &BalanceCache<'_>, data: &WalletCacheData, info: &mut CacheInfo) {
        match cache.save(data) {
            Ok(()) => info.saved = true,
            Err(e) => {
                info.saved = false;
                let note = format!("results could not be cached: {e}");
                info.note = Some(match info.note.take() {
                    Some(existing) => format!("{existing}; {note}"),
                    None => note,
                });
            }
        }
    }

    /// The RingCT scan, cached or not.
    async fn scan(
        &self,
        spend_secret: &SecretKey,
        scan_secret: &SecretKey,
        force_full: bool,
    ) -> Result<CachedBalanceResult> {
        // Validate up front so a bad batch size fails before any RPC or IO.
        let batch_size = self.options(0, HashSet::new()).batch_size()?;

        let Some(store) = self.store else {
            let balance = get_balance(
                self.client,
                spend_secret,
                scan_secret,
                &self.options(0, HashSet::new()),
            )
            .await?;

            return Ok(CachedBalanceResult {
                balance,
                cache: CacheInfo::default(),
            });
        };

        let cache = BalanceCache::new(store);
        let id = wallet_id(scan_secret);
        let (mut data, mut info) = self.open_cache(&cache, &id, force_full);

        // CacheOnly answers from stored data alone, with no requests at all.
        // A UI uses this to paint the last known balance immediately, then runs
        // a revalidating scan behind it.
        if self.recovery == RecoveryPolicy::CacheOnly && !info.rebuilt {
            let utxos: Vec<Utxo> = data
                .utxos
                .iter()
                .map(|u| u.to_utxo())
                .collect::<Result<_>>()?;

            let total_balance = utxos
                .iter()
                .fold(0u64, |acc, u| acc.saturating_add(u.amount));

            info.skipped_scan = true;
            // Deliberately not up to date: nothing was checked against the node.
            info.up_to_date = false;
            info.note = Some(
                "served from cache without contacting the node; may be stale".to_string(),
            );

            return Ok(CachedBalanceResult {
                balance: BalanceResult {
                    total_balance,
                    utxos,
                    last_processed_index: data.last_processed_index,
                    spent_key_images: data.spent_key_images.iter().cloned().collect(),
                    total_outputs_scanned: 0,
                    owned_outputs_found: 0,
                },
                cache: info,
            });
        }

        // The chain tip gates the expensive record walk. Outputs and spends can
        // only appear in new blocks, so an unmoved tip means the walk cannot
        // discover anything.
        let tip = self.client.get_blockchain_info().await?.blocks;
        let chain_moved = tip == 0 || tip != data.scanned_at_height;

        let mut spent: HashSet<String> = data.spent_key_images.iter().cloned().collect();

        // Cached entries must decode before they can be trusted. A single bad
        // field means the record is unusable, so fall back to a full scan
        // rather than reporting a balance built from partial data.
        let mut surviving = std::mem::take(&mut data.utxos);
        if let Some(bad) = surviving.iter().find(|u| u.to_utxo().is_err()) {
            let reason = format!(
                "cached UTXO {} did not decode, rebuilding from the node",
                bad.outpoint()
            );

            surviving.clear();
            data = WalletCacheData::new(&id);
            spent.clear();
            info.loaded = 0;
            info.rebuilt = true;
            info.note = Some(reason);
            let _ = cache.clear(&id);
        }

        // Entries already known to be spent never needed re-checking.
        let mut hex_buf = [0u8; 66];
        let before = surviving.len();
        surviving.retain(|u| !spent.contains(key_image_hex_in(&u.key_image, &mut hex_buf)));
        info.dropped += before - surviving.len();

        // Re-check every cached key image. This is scoped to the wallet's own
        // UTXOs, so it is a small number of requests, and checking all of them
        // is what makes a spend impossible to miss.
        //
        // This runs even when the chain tip has not moved: a spend enters the
        // mempool before it is mined, and `checkkeyimages` reports that through
        // `spentinmempool`. Gating this on the tip would let a UTXO that is
        // already being spent still look spendable, which is how a cached
        // balance turns into an attempted double spend.
        if !surviving.is_empty() {
            let key_images: Vec<KeyImage> = surviving
                .iter()
                .map(|u| u.key_image_bytes())
                .collect();

            check_key_images_spent_status(self.client, &key_images, &mut spent, batch_size).await?;
            info.revalidated = surviving.len();

            let mut hex_buf = [0u8; 66];
            let before = surviving.len();
            surviving.retain(|u| !spent.contains(key_image_hex_in(&u.key_image, &mut hex_buf)));
            info.dropped += before - surviving.len();
        }

        // Walk records, rewinding the resume point so the tail the previous scan
        // already covered is re-read. Skipped entirely when the tip has not
        // moved, since `getwatchonlytxes` is the expensive call and no new
        // records can exist.
        let mut fresh: Vec<CachedUtxo> = Vec::new();
        // The page callback cannot return an error, so a malformed txid is held
        // here and raised once the walk finishes. Skipping the entry instead
        // would silently drop a spendable output from the balance.
        let mut convert_error: Option<VeilError> = None;
        let mut total_outputs_scanned = 0usize;
        let mut owned_outputs_found = 0usize;
        let mut scanned_to = data.last_processed_index;

        info.skipped_scan = !chain_moved && !info.rebuilt;
        info.up_to_date = info.skipped_scan;

        if info.skipped_scan {
            info.note = Some(format!(
                "chain tip is unchanged at height {tip}; no records were fetched"
            ));
        } else {
            // A forced rescan discards the resume point entirely; otherwise the
            // policy decides how far back to rewind.
            let resume_from = if force_full {
                0
            } else {
                self.recovery.resume_index(data.last_processed_index)
            };
            info.resumed_from = Some(resume_from);

            let result = get_balance_with_callback(
                self.client,
                spend_secret,
                scan_secret,
                &self.options(resume_from, spent.clone()),
                |page| {
                    for parsed in page {
                        match CachedUtxo::from_parsed(parsed) {
                            Ok(utxo) => fresh.push(utxo),
                            Err(e) => {
                                convert_error.get_or_insert(e);
                            }
                        }
                    }
                },
            )
            .await?;

            if let Some(e) = convert_error {
                return Err(e);
            }

            spent.extend(result.spent_key_images.iter().cloned());
            total_outputs_scanned = result.total_outputs_scanned;
            owned_outputs_found = result.owned_outputs_found;
            // Never move the resume point backwards: a rewound scan that finds
            // nothing new must not lower the high-water mark.
            scanned_to = result.last_processed_index.max(data.last_processed_index);
            info.up_to_date = true;
        }

        // Merge, keeping the cached entries and adding outpoints not already
        // held. The node can re-report a record, so dedupe rather than trust
        // the pagination to be exact.
        let mut seen: HashSet<String> = surviving.iter().map(|u| u.outpoint()).collect();
        for utxo in fresh {
            if seen.insert(utxo.outpoint()) {
                surviving.push(utxo);
            }
        }

        // The scan may have learned about spends affecting cached entries.
        let mut hex_buf = [0u8; 66];
        surviving.retain(|u| !spent.contains(key_image_hex_in(&u.key_image, &mut hex_buf)));

        // Label each output against the wallet's own send history. This is the
        // only place the two cache layers meet: an output whose transaction the
        // wallet broadcast is change, anything else in a wallet with a known
        // history was received, and a wallet with no history at all stays
        // Unknown.
        let sent = self.sent_txids(scan_secret);
        label_directions(&mut surviving, sent.as_ref());

        let utxos: Vec<Utxo> = surviving
            .iter()
            .map(|u| u.to_utxo())
            .collect::<Result<_>>()?;

        let total_balance = utxos
            .iter()
            .fold(0u64, |acc, u| acc.saturating_add(u.amount));

        let last_processed_index = scanned_to;

        data.last_processed_index = last_processed_index;
        data.utxos = surviving;
        data.spent_key_images = spent.iter().cloned().collect();
        data.scanned_at_height = tip;

        self.save_cache(&cache, &data, &mut info);

        Ok(CachedBalanceResult {
            balance: BalanceResult {
                total_balance,
                utxos,
                last_processed_index,
                spent_key_images: spent,
                total_outputs_scanned,
                owned_outputs_found,
            },
            cache: info,
        })
    }

    /// Fetch the CT balance, using and updating the cache.
    ///
    /// CT outputs carry no key images, so [`RecoveryPolicy`] does not apply:
    /// there is no node call that can re-check a cached CT entry. Spends must be
    /// supplied through [`Self::with_spent_outpoints`], which is merged into the
    /// cached set and persisted for later calls.
    pub async fn balance_ct(
        &self,
        spend_secret: &SecretKey,
        scan_secret: &SecretKey,
    ) -> Result<CachedBalanceResultCt> {
        self.scan_ct(spend_secret, scan_secret, false).await
    }

    /// Fetch the CT balance, ignoring any cached state.
    pub async fn rescan_ct(
        &self,
        spend_secret: &SecretKey,
        scan_secret: &SecretKey,
    ) -> Result<CachedBalanceResultCt> {
        self.scan_ct(spend_secret, scan_secret, true).await
    }

    /// The CT scan, cached or not.
    async fn scan_ct(
        &self,
        spend_secret: &SecretKey,
        scan_secret: &SecretKey,
        force_full: bool,
    ) -> Result<CachedBalanceResultCt> {
        let Some(store) = self.store else {
            let balance = get_balance_ct(
                self.client,
                spend_secret,
                scan_secret,
                &GetBalanceCtOptions {
                    start_index: 0,
                    known_spent_outpoints: self.extra_spent_outpoints.clone(),
                },
            )
            .await?;

            return Ok(CachedBalanceResultCt {
                balance,
                cache: CacheInfo::default(),
            });
        };

        let cache = BalanceCache::new(store);
        let id = wallet_id(scan_secret);
        let (mut data, mut info) = self.open_cache(&cache, &id, force_full);

        // Caller-supplied spends are a local fact the node cannot confirm, so
        // new ones must be applied even when nothing else has changed.
        let new_spends = self
            .extra_spent_outpoints
            .iter()
            .any(|o| !data.spent_outpoints.contains(o));

        // CacheOnly answers without contacting the node, for immediate display.
        if self.recovery == RecoveryPolicy::CacheOnly && !info.rebuilt && !new_spends {
            let utxos: Vec<UtxoCt> = data
                .ct_utxos
                .iter()
                .map(|u| u.to_utxo())
                .collect::<Result<_>>()?;

            let total_balance = utxos
                .iter()
                .fold(0u64, |acc, u| acc.saturating_add(u.amount));

            info.skipped_scan = true;
            info.up_to_date = false;
            info.note = Some(
                "served from cache without contacting the node; may be stale".to_string(),
            );

            return Ok(CachedBalanceResultCt {
                balance: BalanceResultCt {
                    total_balance,
                    utxos,
                    last_processed_index: data.ct_last_processed_index,
                    total_outputs_scanned: 0,
                    owned_outputs_found: 0,
                },
                cache: info,
            });
        }

        let tip = self.client.get_blockchain_info().await?.blocks;
        let chain_moved = tip == 0 || tip != data.ct_scanned_at_height;

        let mut spent: HashSet<String> = data.spent_outpoints.iter().cloned().collect();
        spent.extend(self.extra_spent_outpoints.iter().cloned());

        let mut surviving = std::mem::take(&mut data.ct_utxos);
        if let Some(bad) = surviving.iter().find(|u| u.to_utxo().is_err()) {
            let reason = format!(
                "cached CT UTXO {} did not decode, rebuilding from the node",
                bad.outpoint()
            );

            surviving.clear();
            data.ct_last_processed_index = 0;
            info.loaded = 0;
            info.rebuilt = true;
            info.note = Some(reason);
        }

        let before = surviving.len();
        surviving.retain(|u| !spent.contains(&u.outpoint()));
        info.dropped += before - surviving.len();

        let mut fresh: Vec<CachedUtxoCt> = Vec::new();
        // As in the RingCT path: the callback cannot fail, so a malformed txid is
        // held and raised after the walk rather than dropping the output.
        let mut convert_error: Option<VeilError> = None;
        let mut total_outputs_scanned = 0usize;
        let mut owned_outputs_found = 0usize;
        let mut scanned_to = data.ct_last_processed_index;

        // New CT outputs can only arrive in new blocks, so an unmoved tip means
        // the walk cannot find anything.
        info.skipped_scan = !chain_moved && !info.rebuilt;
        info.up_to_date = info.skipped_scan;

        if info.skipped_scan {
            info.note = Some(format!(
                "chain tip is unchanged at height {tip}; no records were fetched"
            ));
        } else {
            let resume_from = if force_full {
                0
            } else {
                self.recovery.resume_index(data.ct_last_processed_index)
            };
            info.resumed_from = Some(resume_from);

            let result = get_balance_ct_with_callback(
                self.client,
                spend_secret,
                scan_secret,
                &GetBalanceCtOptions {
                    start_index: resume_from,
                    known_spent_outpoints: spent.clone(),
                },
                |page| {
                    for parsed in page {
                        match CachedUtxoCt::from_parsed(parsed) {
                            Ok(utxo) => fresh.push(utxo),
                            Err(e) => {
                                convert_error.get_or_insert(e);
                            }
                        }
                    }
                },
            )
            .await?;

            if let Some(e) = convert_error {
                return Err(e);
            }

            total_outputs_scanned = result.total_outputs_scanned;
            owned_outputs_found = result.owned_outputs_found;
            scanned_to = result
                .last_processed_index
                .max(data.ct_last_processed_index);
            info.up_to_date = true;
        }

        let mut seen: HashSet<String> = surviving.iter().map(|u| u.outpoint()).collect();
        for utxo in fresh {
            if seen.insert(utxo.outpoint()) {
                surviving.push(utxo);
            }
        }

        // Label each output against the wallet's own send history.
        let sent = self.sent_txids(scan_secret);
        label_directions(&mut surviving, sent.as_ref());

        let utxos: Vec<UtxoCt> = surviving
            .iter()
            .map(|u| u.to_utxo())
            .collect::<Result<_>>()?;

        let total_balance = utxos
            .iter()
            .fold(0u64, |acc, u| acc.saturating_add(u.amount));

        let last_processed_index = scanned_to;

        data.ct_last_processed_index = last_processed_index;
        data.ct_utxos = surviving;
        data.spent_outpoints = spent.iter().cloned().collect();

        // CT outputs have no key images to re-check, so a completed scan always
        // leaves the cache current as of this tip.
        data.ct_scanned_at_height = tip;

        self.save_cache(&cache, &data, &mut info);

        Ok(CachedBalanceResultCt {
            balance: BalanceResultCt {
                total_balance,
                utxos,
                last_processed_index,
                total_outputs_scanned,
                owned_outputs_found,
            },
            cache: info,
        })
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
            ephemeral_pubkey: [0x02u8; 33],
            key_image: [key_image; 33],
            ringct_index: Some(u64::from(vout)),
        }
    }

    fn parsed_utxo_ct(txid: &str, vout: u32, amount: u64) -> ParsedUtxoCt {
        ParsedUtxoCt {
            txid: txid.to_string(),
            vout,
            amount,
            commitment: [0x08u8; 33],
            blind: [0xABu8; 32],
            script_pubkey: vec![0x76, 0xa9],
            pubkey: [0x02u8; 33],
            ephemeral_pubkey: [0x02u8; 33],
        }
    }

    #[test]
    fn filter_drops_spent_utxos_and_keeps_the_rest() {
        let spent_image = [0x01u8; 33];
        let mut spent = HashSet::new();
        spent.insert(bytes_to_hex(spent_image.as_slice()));

        let parsed = vec![
            parsed_utxo("aa", 0, 100, 0x01), // spent
            parsed_utxo("bb", 1, 250, 0x02), // unspent
        ];

        let (utxos, still_parsed) = filter_unspent(parsed, &spent);

        assert_eq!(utxos.len(), 1);
        assert_eq!(still_parsed.len(), 1);
        assert_eq!(utxos[0].amount, 250);
        assert_eq!(utxos[0].txid, "bb");
        assert!(utxos[0].spendable);
        assert_eq!(utxos[0].ringct_index, Some(1));
    }

    #[test]
    fn filter_keeps_everything_when_nothing_is_spent() {
        let parsed = vec![
            parsed_utxo("aa", 0, 100, 0x01),
            parsed_utxo("bb", 1, 250, 0x02),
        ];

        let (utxos, _) = filter_unspent(parsed, &HashSet::new());
        assert_eq!(utxos.len(), 2);
        assert_eq!(utxos.iter().map(|u| u.amount).sum::<u64>(), 350);
    }

    #[test]
    fn ct_filter_matches_on_outpoint() {
        let mut spent = HashSet::new();
        spent.insert("aa:0".to_string());

        let parsed = vec![
            parsed_utxo_ct("aa", 0, 100), // spent
            parsed_utxo_ct("aa", 1, 250), // different vout, unspent
            parsed_utxo_ct("bb", 0, 500), // different txid, unspent
        ];

        let (utxos, _) = filter_unspent_ct(parsed, &spent);

        assert_eq!(utxos.len(), 2);
        assert_eq!(utxos.iter().map(|u| u.amount).sum::<u64>(), 750);
    }

    #[test]
    fn batch_size_validation_bounds_the_request() {
        let ok = GetBalanceOptions {
            key_image_batch_size: Some(500),
            ..Default::default()
        };
        assert_eq!(ok.batch_size().unwrap(), 500);

        let defaulted = GetBalanceOptions::default();
        assert_eq!(defaulted.batch_size().unwrap(), DEFAULT_KEY_IMAGE_BATCH_SIZE);

        let zero = GetBalanceOptions {
            key_image_batch_size: Some(0),
            ..Default::default()
        };
        assert!(zero.batch_size().is_err());

        let too_big = GetBalanceOptions {
            key_image_batch_size: Some(10_001),
            ..Default::default()
        };
        assert!(too_big.batch_size().is_err());
    }

    #[test]
    fn known_spent_images_carry_into_the_result() {
        let mut known = HashSet::new();
        known.insert("ab".repeat(33));

        let options = GetBalanceOptions {
            known_spent_key_images: known.clone(),
            start_index: 42,
            key_image_batch_size: None,
        };

        // The scan seeds its spent set from the caller's cache.
        assert_eq!(options.known_spent_key_images, known);
        assert_eq!(options.start_index, 42);
    }
}
