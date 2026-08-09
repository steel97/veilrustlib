//! Example: get a wallet's balance.
//!
//! Port of `ref/veil-wasm-wrapper-master/examples/get-balance.ts`, with the
//! wallet source swapped out: instead of reading `test-wallet.json`, the scan
//! and spend secrets are derived from a BIP39 seed phrase read from the
//! environment, using `AccountType::Default` at index 0. That is the same
//! address the Dart `veil_light_plugin` hands out first.
//!
//! There is no `initWasm()` step: `veilrustlib` links its cryptography
//! directly, so the equivalent calls work immediately.
//!
//! ## Environment
//!
//! ```text
//! VEIL_SEED_PHRASE       required  the BIP39 mnemonic, space separated
//! VEIL_SEED_PASSPHRASE   optional  BIP39 passphrase, defaults to empty
//! VEIL_ACCOUNT_ID        optional  BIP44 account, defaults to 0
//! VEIL_NODE_URL          optional  node URL, defaults to the public endpoint
//! VEIL_NODE_USERNAME     optional  RPC user, for an authenticated node
//! VEIL_NODE_PASSWORD     optional  RPC password, for an authenticated node
//! VEIL_IMPORT_ADDRESS    optional  set to 1 to register the address first
//! ```
//!
//! ## Running
//!
//! ```text
//! $env:VEIL_SEED_PHRASE = "word word ... word"
//! cargo run -p veilrustlib-examples --bin get-balance
//! ```
//!
//! ## A note on privacy
//!
//! `getwatchonlytxes` sends the scan *private* key to the node, which can then
//! link every output belonging to this wallet. Point `VEIL_NODE_URL` at a node
//! you control if that matters. `VEIL_IMPORT_ADDRESS=1` additionally asks the
//! node to store the key and scan the chain for it, which is why it is opt-in.

use std::collections::HashSet;
use std::time::Instant;

use veilrustlib::balance::{get_balance, BalanceResult, GetBalanceOptions};
use veilrustlib::hdwallet::{derive_stealth_keys, verify_mnemonic_shape, AccountType, StealthKeys};
use veilrustlib::rpc::RpcClient;
use veilrustlib::utils::{bytes_to_hex, satoshis_to_veil};
use veilrustlib::VeilError;

const RULE: &str = "----------------------------------------";

/// Read the seed phrase and derive the first default address's keys.
///
/// This is step 5 of the plan: `AccountType::Default`, index 0.
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

/// Print the parts of a result the TypeScript example printed.
fn print_result(result: &BalanceResult, duration_ms: u128) {
    println!("Results:");
    println!(
        "   Total balance:        {} VEIL",
        satoshis_to_veil(result.total_balance)
    );
    println!("   Unspent UTXOs:        {}", result.utxos.len());
    println!("   Outputs scanned:      {}", result.total_outputs_scanned);
    println!("   Owned outputs found:  {}", result.owned_outputs_found);
    println!("   Spent key images:     {}", result.spent_key_images.len());
    println!("   Last processed index: {}", result.last_processed_index);
    println!("   Duration:             {duration_ms}ms");
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
    println!("Veil get balance example");
    println!("{RULE}\n");

    // ------------------------------------------------------------------
    // 1. Derive the wallet from the seed phrase
    // ------------------------------------------------------------------
    println!("1. Deriving keys from VEIL_SEED_PHRASE...");
    let keys = keys_from_environment()?;
    let address = keys.stealth_address()?;

    println!("   Account type:  {:?}", keys.account_type);
    println!("   Address index: {}", keys.index);
    println!("   Address:       {address}");
    // Only the public halves are printed; the secrets stay out of the log.
    println!("   Scan pubkey:   {}", bytes_to_hex(&keys.scan_pubkey));
    println!("   Spend pubkey:  {}", bytes_to_hex(&keys.spend_pubkey));
    println!();

    // ------------------------------------------------------------------
    // 2. Connect to the node
    // ------------------------------------------------------------------
    println!("2. Connecting to the node...");
    let client = RpcClient::from_env()?;
    println!("   Node: {}", client.url());

    match client.get_blockchain_info().await {
        Ok(info) => println!("   Chain: {} at height {}\n", info.chain, info.blocks),
        Err(error) => {
            return Err(VeilError::rpc(format!(
                "could not reach the node at {}: {error}",
                client.url()
            )))
        }
    }

    // Registering the address is opt-in: it hands the scan private key to the
    // node for storage. Without it, a node that has never seen this address
    // will report no transactions and the balance will read as zero.
    if std::env::var("VEIL_IMPORT_ADDRESS").as_deref() == Ok("1") {
        println!("   VEIL_IMPORT_ADDRESS=1, registering the address for watch-only scanning...");
        client
            .import_lightwallet_address(
                &bytes_to_hex(&keys.scan_secret),
                &bytes_to_hex(&keys.spend_pubkey),
                0,
            )
            .await?;
        println!("   Registered. The node may need time to finish scanning.\n");
    }

    // ------------------------------------------------------------------
    // TEST 1: no cached key images
    // ------------------------------------------------------------------
    println!("{RULE}");
    println!("3. TEST 1: balance without known key images");
    println!("{RULE}\n");

    let started = Instant::now();
    let result1 = get_balance(
        &client,
        &keys.spend_secret,
        &keys.scan_secret,
        &GetBalanceOptions::default(),
    )
    .await?;
    let duration1 = started.elapsed().as_millis();

    print_result(&result1, duration1);

    if !result1.utxos.is_empty() {
        println!("Unspent UTXOs:");
        for (i, utxo) in result1.utxos.iter().enumerate() {
            println!("   {}. {} VEIL", i + 1, satoshis_to_veil(utxo.amount));
            println!("      txid:         {}", utxo.txid);
            println!("      vout:         {}", utxo.vout);
            match utxo.ringct_index {
                Some(index) => println!("      ringct index: {index}"),
                None => println!("      ringct index: n/a"),
            }
        }
        println!();
    }

    // ------------------------------------------------------------------
    // TEST 2: reuse the key images TEST 1 discovered
    // ------------------------------------------------------------------
    println!("{RULE}");
    println!("4. TEST 2: balance with known key images (cached)");
    println!("{RULE}\n");

    println!(
        "   Reusing {} spent key images from TEST 1...\n",
        result1.spent_key_images.len()
    );

    let started = Instant::now();
    let result2 = get_balance(
        &client,
        &keys.spend_secret,
        &keys.scan_secret,
        &GetBalanceOptions {
            known_spent_key_images: result1.spent_key_images.clone(),
            // Start from the beginning so the totals are comparable.
            start_index: 0,
            key_image_batch_size: None,
        },
    )
    .await?;
    let duration2 = started.elapsed().as_millis();

    print_result(&result2, duration2);

    // ------------------------------------------------------------------
    // TEST 3: resume from the last processed index
    // ------------------------------------------------------------------
    // The TypeScript example took its third set of cached key images from
    // test-wallet.json. Keys here come from a seed phrase, so there is no
    // wallet file to read; this instead exercises the other half of the
    // caching story, resuming a scan from where the last one stopped.
    println!("{RULE}");
    println!("5. TEST 3: incremental scan from the last processed index");
    println!("{RULE}\n");

    println!(
        "   Resuming at index {} with {} cached key images...\n",
        result1.last_processed_index,
        result1.spent_key_images.len()
    );

    let started = Instant::now();
    let result3 = get_balance(
        &client,
        &keys.spend_secret,
        &keys.scan_secret,
        &GetBalanceOptions {
            known_spent_key_images: result1.spent_key_images.clone(),
            start_index: result1.last_processed_index,
            key_image_batch_size: None,
        },
    )
    .await?;
    let duration3 = started.elapsed().as_millis();

    print_result(&result3, duration3);

    // ------------------------------------------------------------------
    // Verification
    // ------------------------------------------------------------------
    println!("{RULE}");
    println!("6. Verification");
    println!("{RULE}\n");

    // TEST 1 and TEST 2 both scan from zero, so they must agree exactly.
    let balances_match = result1.total_balance == result2.total_balance;
    let utxo_counts_match = result1.utxos.len() == result2.utxos.len();

    println!("Consistency of the two full scans:");
    println!(
        "   Balances match:    {}",
        if balances_match { "yes" } else { "NO" }
    );
    println!(
        "     TEST 1: {} VEIL",
        satoshis_to_veil(result1.total_balance)
    );
    println!(
        "     TEST 2: {} VEIL",
        satoshis_to_veil(result2.total_balance)
    );
    println!(
        "   UTXO counts match: {}",
        if utxo_counts_match { "yes" } else { "NO" }
    );
    println!("     TEST 1: {} UTXOs", result1.utxos.len());
    println!("     TEST 2: {} UTXOs", result2.utxos.len());
    println!();

    // TEST 3 starts partway through, so it reports only what came after the
    // resume point rather than the full balance.
    println!("Incremental scan:");
    println!(
        "   TEST 3 covered {} new records from index {} and found {} VEIL",
        result3.total_outputs_scanned,
        result1.last_processed_index,
        satoshis_to_veil(result3.total_balance)
    );
    let combined: HashSet<&String> = result1
        .spent_key_images
        .iter()
        .chain(result3.spent_key_images.iter())
        .collect();
    println!(
        "   Combined spent key image cache: {} entries",
        combined.len()
    );
    println!();

    println!("Timing:");
    println!("   TEST 1 (no cache):        {duration1}ms");
    println!("   TEST 2 (cached images):   {duration2}ms");
    println!("   TEST 3 (incremental):     {duration3}ms");
    if duration2 < duration1 && duration1 > 0 {
        let improvement = (duration1 - duration2) as f64 / duration1 as f64 * 100.0;
        println!("   Cache improvement: {improvement:.1}% faster");
    }
    println!();

    if balances_match && utxo_counts_match {
        println!("The two full scans agree.\n");
    } else {
        println!("Warning: the two full scans disagree. New transactions arriving mid-run can");
        println!("cause this; re-run to confirm.\n");
    }

    println!("{RULE}");
    println!("Usage notes");
    println!("{RULE}\n");
    println!("   1. Cache spent key images between calls to skip redundant RPC checks");
    println!("   2. Pass last_processed_index as start_index to resume a scan");
    println!("   3. Persist both alongside the account and address index, not the secrets");
    println!("   4. Re-run periodically to pick up incoming transactions");
    println!("   5. The seed phrase alone regenerates every key, so back it up and nothing else\n");

    Ok(())
}
