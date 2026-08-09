//! Example: cached balance scans.
//!
//! Shows the persistent side of [`BalanceScanner`]: the first scan pays the full
//! cost of walking every watch-only record, and later scans read the cached
//! UTXOs from a single-file redb database, fetch only what arrived since, and
//! re-verify a bounded window of cached entries against the node.
//!
//! The second scan is the interesting one: when the chain tip has not moved it
//! skips the `getwatchonlytxes` walk and every key image check, because neither
//! can discover anything without a new block.
//!
//! ## Environment
//!
//! ```text
//! VEIL_SEED_PHRASE       required  the BIP39 mnemonic, space separated
//! VEIL_SEED_PASSPHRASE   optional  BIP39 passphrase, defaults to empty
//! VEIL_ACCOUNT_ID        optional  BIP44 account, defaults to 0
//! VEIL_CACHE_PATH        optional  cache file, defaults to veil-balance-cache.redb
//! VEIL_REWIND            optional  records to rewind, or "full"/"cache"
//! VEIL_NODE_URL          optional  node URL, defaults to the public endpoint
//! VEIL_NODE_USERNAME     optional  RPC user, for an authenticated node
//! VEIL_NODE_PASSWORD     optional  RPC password, for an authenticated node
//! ```
//!
//! ## Running
//!
//! ```text
//! $env:VEIL_SEED_PHRASE = "word word ... word"
//! cargo run -p veilrustlib-examples --bin cached-balance
//! ```
//!
//! Run it twice: the second run is the interesting one, because it starts from
//! the cache the first run left behind.
//!
//! ## A note on privacy
//!
//! `getwatchonlytxes` sends the scan *private* key to the node, which can then
//! link every output belonging to this wallet. Point `VEIL_NODE_URL` at a node
//! you control if that matters.
//!
//! The cache file itself holds decoded UTXOs, including amounts and blinding
//! factors, so treat it as wallet data. It never stores the scan or spend
//! secret: wallets are keyed by a SHA-256 digest of the scan secret instead.

use std::time::Instant;

use veilrustlib::balance::{BalanceScanner, CachedBalanceResult};
use veilrustlib::cache::{CacheLoad, RecoveryPolicy, RedbStore};
use veilrustlib::hdwallet::{derive_stealth_keys, verify_mnemonic_shape, AccountType, StealthKeys};
use veilrustlib::rpc::RpcClient;
use veilrustlib::utils::{bytes_to_hex, satoshis_to_veil};
use veilrustlib::VeilError;

const RULE: &str = "----------------------------------------";

/// Read the seed phrase and derive the first stealth address's keys.
fn keys_from_environment() -> Result<StealthKeys, VeilError> {
    let mnemonic = std::env::var("VEIL_SEED_PHRASE").map_err(|_| {
        VeilError::invalid_input(
            "VEIL_SEED_PHRASE is not set; export your BIP39 seed phrase and try again",
        )
    })?;

    if !verify_mnemonic_shape(&mnemonic) {
        return Err(VeilError::invalid_input(
            "VEIL_SEED_PHRASE does not have 12, 15, 18, 21, or 24 words",
        ));
    }

    let passphrase = std::env::var("VEIL_SEED_PASSPHRASE").unwrap_or_default();

    let account_id: u32 = match std::env::var("VEIL_ACCOUNT_ID") {
        Ok(value) => value.trim().parse().map_err(|_| {
            VeilError::invalid_input(format!("VEIL_ACCOUNT_ID is not a number: {value}"))
        })?,
        Err(_) => 0,
    };

    derive_stealth_keys(&mnemonic, &passphrase, account_id, AccountType::Stealth, 1)
}

/// Read the recovery policy from the environment.
///
/// This is the knob the library leaves to the end developer: how much of the
/// cache to re-verify against the node before trusting it.
fn recovery_from_environment() -> Result<RecoveryPolicy, VeilError> {
    let raw = match std::env::var("VEIL_REWIND") {
        Ok(value) => value,
        Err(_) => return Ok(RecoveryPolicy::default()),
    };

    match raw.trim().to_ascii_lowercase().as_str() {
        "all" | "full" => Ok(RecoveryPolicy::FullRescan),
        "cache" | "none" => Ok(RecoveryPolicy::CacheOnly),
        other => other
            .parse::<u64>()
            .map(RecoveryPolicy::Rewind)
            .map_err(|_| {
                VeilError::invalid_input(format!(
                    "VEIL_REWIND must be a number, \"full\", or \"cache\", got {other}"
                ))
            }),
    }
}

/// Print a result and what the cache contributed to it.
fn print_result(label: &str, result: &CachedBalanceResult, duration_ms: u128) {
    let cache = &result.cache;

    println!("{label}:");
    println!(
        "   Total balance:        {} VEIL",
        satoshis_to_veil(result.balance.total_balance)
    );
    println!("   Unspent UTXOs:        {}", result.balance.utxos.len());
    println!(
        "   Records fetched:      {}",
        result.balance.total_outputs_scanned
    );
    println!(
        "   Last processed index: {}",
        result.balance.last_processed_index
    );
    println!("   Duration:             {duration_ms}ms");
    println!("   Cache:");
    println!("      enabled:      {}", cache.enabled);
    println!("      loaded:       {} UTXOs", cache.loaded);
    println!("      revalidated:  {} UTXOs", cache.revalidated);
    println!(
        "      dropped:      {} spent since last scan",
        cache.dropped
    );
    println!("      skipped scan: {}", cache.skipped_scan);
    println!("      up to date:   {}", cache.up_to_date);
    match cache.resumed_from {
        Some(index) => println!("      resumed from: record {index}"),
        None => println!("      resumed from: n/a, no walk"),
    }
    println!("      rebuilt:      {}", cache.rebuilt);
    println!("      saved:        {}", cache.saved);
    if let Some(note) = &cache.note {
        println!("      note:         {note}");
    }
    println!();
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("Error: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), VeilError> {
    println!("Veil cached balance example");
    println!("{RULE}\n");

    // ------------------------------------------------------------------
    // 1. Derive the wallet and connect to the node
    // ------------------------------------------------------------------
    println!("1. Deriving keys and connecting...");
    let keys = keys_from_environment()?;
    let address = keys.stealth_address()?;

    println!("   Address:      {address}");
    println!("   Scan pubkey:  {}", bytes_to_hex(&keys.scan_pubkey));

    let client = RpcClient::from_env()?;
    println!("   Node:         {}", client.url());

    match client.get_blockchain_info().await {
        Ok(info) => println!(
            "   Chain:        {} at height {}\n",
            info.chain, info.blocks
        ),
        Err(error) => {
            return Err(VeilError::rpc(format!(
                "could not reach the node at {}: {error}",
                client.url()
            )))
        }
    }

    // ------------------------------------------------------------------
    // 2. Open the cache
    // ------------------------------------------------------------------
    let cache_path =
        std::env::var("VEIL_CACHE_PATH").unwrap_or_else(|_| "veil-balance-cache.redb".to_string());
    let recovery = recovery_from_environment()?;

    println!("2. Opening the cache...");

    // open_or_recreate discards a file that cannot be opened at all. The cache
    // is derived data, so rebuilding it is always safe.
    let (store, recreated) = RedbStore::open_or_recreate(&cache_path)?;
    println!("   File:     {}", store.path().display());
    if recreated {
        println!("   The previous cache file was unreadable and has been recreated.");
    }
    println!("   Recovery: {recovery:?}\n");

    let scanner = BalanceScanner::new(&client)
        .with_cache(&store)
        .with_recovery(recovery);

    match scanner.peek_cache(&keys.scan_secret) {
        CacheLoad::Loaded(data) => println!(
            "   Found a cached scan: {} UTXOs, resuming from index {}.\n",
            data.utxos.len(),
            data.last_processed_index
        ),
        CacheLoad::Missing => {
            println!("   No cache for this wallet yet; this run will build one.\n")
        }
        other => println!("   Cache is not usable ({other:?}); this run will rebuild it.\n"),
    }

    // ------------------------------------------------------------------
    // TEST 0: instant read, no node requests
    // ------------------------------------------------------------------
    println!("{RULE}");
    println!("3. TEST 0: instant read from cache only");
    println!("{RULE}\n");

    println!("   This is what a UI shows on startup: no requests, so it returns at once.\n");

    let started = Instant::now();
    let instant = scanner
        .cached_balance(&keys.spend_secret, &keys.scan_secret)
        .await?;
    print_result("Cache-only read", &instant, started.elapsed().as_millis());

    // ------------------------------------------------------------------
    // TEST 1: scan with whatever the cache holds
    // ------------------------------------------------------------------
    println!("{RULE}");
    println!("4. TEST 1: revalidating scan");
    println!("{RULE}\n");

    let started = Instant::now();
    let cached = scanner
        .balance(&keys.spend_secret, &keys.scan_secret)
        .await?;
    print_result("Revalidating scan", &cached, started.elapsed().as_millis());

    if !cached.balance.utxos.is_empty() {
        println!("Unspent UTXOs:");
        for (i, utxo) in cached.balance.utxos.iter().enumerate() {
            println!(
                "   {}. {} VEIL  {}:{}",
                i + 1,
                satoshis_to_veil(utxo.amount),
                utxo.txid,
                utxo.vout
            );
        }
        println!();
    }

    // ------------------------------------------------------------------
    // TEST 2: the same scan again, now guaranteed to be warm
    // ------------------------------------------------------------------
    println!("{RULE}");
    println!("5. TEST 2: immediate second scan");
    println!("{RULE}\n");

    let started = Instant::now();
    let warm = scanner
        .balance(&keys.spend_secret, &keys.scan_secret)
        .await?;
    print_result("Warm scan", &warm, started.elapsed().as_millis());

    // ------------------------------------------------------------------
    // Verification
    // ------------------------------------------------------------------
    println!("{RULE}");
    println!("6. Verification");
    println!("{RULE}\n");

    println!("Both scans should report the same balance:");
    println!(
        "   first scan:          {} VEIL",
        satoshis_to_veil(cached.balance.total_balance)
    );
    println!(
        "   second scan:         {} VEIL",
        satoshis_to_veil(warm.balance.total_balance)
    );
    println!();

    if cached.balance.total_balance == warm.balance.total_balance {
        println!("The two scans agree.\n");
    } else {
        println!("Warning: the scans disagree. A transaction arriving mid-run can cause this;");
        println!("re-run to confirm before treating it as a bug.\n");
    }

    println!("Records fetched from the node:");
    println!(
        "   first scan:          {}",
        cached.balance.total_outputs_scanned
    );
    println!(
        "   second scan:         {}",
        warm.balance.total_outputs_scanned
    );
    println!();

    if warm.cache.skipped_scan {
        println!("The second scan skipped the watch-only walk entirely: the chain tip had not");
        println!("moved, so no new records could exist. That is where the time is saved.\n");
    } else {
        println!("The second scan still walked records, so the chain tip advanced between the");
        println!("two runs. Expect the saving to show once the tip is stable.\n");
    }

    println!("{RULE}");
    println!("Usage notes");
    println!("{RULE}\n");
    println!("   1. Reuse one RedbStore for the life of the process; it is a single file");
    println!("   2. In a UI, call cached_balance() first to paint the last known balance with");
    println!("      no requests at all, then call balance() to revalidate in the background");
    println!("   3. A repeat scan at an unchanged chain tip costs one getblockchaininfo call:");
    println!("      no getwatchonlytxes walk, since no new records can exist without a block");
    println!("   4. RecoveryPolicy controls the walk once the tip moves:");
    println!("      CacheOnly makes no requests, Rewind(n) re-reads the last n records to");
    println!("      catch a reorg, FullRescan re-walks the entire history");
    println!("   5. Cached key images are always re-checked when the tip moves; that call is");
    println!("      scoped to your own UTXOs, so it stays cheap");
    println!("   6. Check CacheInfo::rebuilt and CacheInfo::note to see when a cache was");
    println!("      rejected, and why");
    println!("   7. Call rescan() to audit a cache you suspect is wrong in a way the");
    println!("      integrity checks cannot see");
    println!("   8. On wasm, build without the cache-redb feature and pass a MemoryStore,");
    println!("      or no store at all, and every call falls back to a node scan\n");

    Ok(())
}
