//! Example: build, and optionally broadcast, a RingCT transaction.
//!
//! Port of `ref/veil-wasm-wrapper-master/examples/build-transaction.ts`, with
//! the mock parts of that example replaced by real data:
//!
//! - The sender wallet is derived from a BIP39 seed phrase in the environment
//!   rather than freshly generated, so the transaction spends real coins.
//! - The recipient address comes from the environment rather than a throwaway
//!   generated address, and may be either family: an `sv1...` stealth address,
//!   paid as a blinded RingCT output, or a `V...`/`bv1...` basecoin address, paid
//!   as a transparent output.
//! - Input UTXOs are scanned from the node instead of being fabricated, and the
//!   scan is cached: a later run resumes 20 records before where the last one
//!   stopped rather than re-walking the whole wallet history.
//! - Decoys are always fetched from the node. There is no mock-decoy fallback:
//!   a failed fetch is retried with backoff, and if it still fails the example
//!   stops rather than building a transaction the network would reject.
//! - The send amount is given in VEIL and converted with `veil_to_satoshis`.
//! - The finished transaction can be broadcast with `sendrawtransaction`.
//!
//! There is no `initWasm()` step: `veilrustlib` links its cryptography
//! directly, so the equivalent calls work immediately.
//!
//! ## Environment
//!
//! ```text
//! VEIL_SEED_PHRASE        required  the BIP39 mnemonic, space separated
//! VEIL_RECIPIENT_ADDRESS  required  destination sv1... (private) or V.../bv1... (public)
//! VEIL_SEND_AMOUNT        required  amount to send, in VEIL (e.g. 0.5)
//! VEIL_SEED_PASSPHRASE    optional  BIP39 passphrase, defaults to empty
//! VEIL_ACCOUNT_ID         optional  BIP44 account, defaults to 0
//! VEIL_NODE_URL           optional  node URL, defaults to the public endpoint
//! VEIL_NODE_USERNAME      optional  RPC user, for an authenticated node
//! VEIL_NODE_PASSWORD      optional  RPC password, for an authenticated node
//! VEIL_CACHE_PATH         optional  cache file, defaults to veil-balance-cache.redb
//! VEIL_BROADCAST          optional  set to 1 to actually broadcast the tx
//! ```
//!
//! ## Running
//!
//! ```text
//! $env:VEIL_SEED_PHRASE = "word word ... word"
//! $env:VEIL_RECIPIENT_ADDRESS = "sv1..."
//! $env:VEIL_SEND_AMOUNT = "0.5"
//! cargo run -p veilrustlib-examples --bin tx
//! ```
//!
//! Without `VEIL_BROADCAST=1` the transaction is built, verified, and printed,
//! but never sent. Broadcasting is irreversible, so it is opt-in.
//!
//! ## A note on privacy
//!
//! The recipient address decides what the transaction publishes:
//!
//! | Address | Output | Amount | Recipient |
//! |---------|--------|--------|-----------|
//! | `sv1...` stealth | RingCT, blinded | hidden | hidden |
//! | `V...` / `bv1...` basecoin | standard, transparent | **public** | **public** |
//!
//! The sender is hidden either way, protected by the ring, and change is always
//! returned as a blinded RingCT output, so a transparent payment never publishes
//! the sender's remaining balance. The example prints which form it is building
//! before it builds it.
//!
//! Scanning for UTXOs uses `getwatchonlytxes`, which sends the scan *private*
//! key to the node; the node can then link every output belonging to this
//! wallet. Point `VEIL_NODE_URL` at a node you control if that matters.
//!
//! The cache file holds decoded UTXOs, including amounts and blinding factors,
//! so treat it as wallet data. It never stores the scan or spend secret.

use std::collections::HashSet;
use std::future::Future;
use std::time::Duration;

use veilrustlib::balance::BalanceScanner;
use veilrustlib::cache::{RecoveryPolicy, RedbStore};
use veilrustlib::hdwallet::{derive_stealth_keys, verify_mnemonic_shape, AccountType, StealthKeys};
use veilrustlib::rpc::{fetch_decoy_outputs, RpcClient};
use veilrustlib::basecoin::BasecoinAddress;
use veilrustlib::stealth::{validate_address, AddressValidation};
use veilrustlib::transaction_builder::{
    classify_address, Destination, Recipient, TransactionBuilder, TransactionBuilderConfig,
};
use veilrustlib::types::{AnonOutput, TxOutput, Utxo};
use veilrustlib::utils::{bytes_to_hex, satoshis_to_veil, veil_to_satoshis};
use veilrustlib::{VeilError, DEFAULT_RING_SIZE, MAX_ANON_INPUTS};

const RULE: &str = "----------------------------------------";

/// Attempts made before an RPC step is treated as failed.
const RETRY_ATTEMPTS: u32 = 5;

/// Delay before the first retry; doubles on each subsequent attempt.
const INITIAL_RETRY_DELAY: Duration = Duration::from_millis(500);

/// Ceiling on the backoff delay.
const MAX_RETRY_DELAY: Duration = Duration::from_secs(8);

/// Records the cached scan rewinds before resuming.
///
/// Spending needs inputs that are genuinely unspent, so the walk re-reads the
/// tail it already covered rather than trusting the stored resume point exactly.
/// Cached key images are re-checked on every run regardless, which is what
/// catches a spend already sitting in the mempool.
const REWIND_RECORDS: u64 = 20;

/// Read the seed phrase and derive the sender's stealth keys.
///
/// This is step 1 of the plan: the wallet is derived from the environment
/// rather than generated, so the example spends coins that actually exist.
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

/// Read and validate the destination address.
///
/// This is step 2 of the plan. `classify_address` is used rather than the cheaper
/// surface check because a typo here sends funds nowhere recoverable: it verifies
/// the checksum and, for a stealth address, the embedded public keys.
///
/// Both address families are accepted, and the choice changes what the
/// transaction publishes:
///
/// - `sv1...` stealth: a blinded RingCT output, hiding the amount and recipient
/// - `V...` or `bv1...` basecoin: a transparent output, publishing both
///
/// The returned [`Destination`] is carried through to the report so the example
/// can state which was built.
fn recipient_from_environment() -> Result<(String, Destination), VeilError> {
    let address = std::env::var("VEIL_RECIPIENT_ADDRESS").map_err(|_| {
        VeilError::invalid_input(
            "VEIL_RECIPIENT_ADDRESS is not set; export the destination address, \
             either sv1... (private) or V.../bv1... (transparent)",
        )
    })?;
    let address = address.trim().to_string();

    // classify_address reports the basecoin failure when neither decode succeeds,
    // which is the more likely mistake, but an sv1 typo deserves the stealth
    // decoder's own explanation. Ask it directly in that case.
    let destination = match classify_address(&address) {
        Ok(destination) => destination,
        Err(error) => {
            if let AddressValidation::Invalid(reason) = validate_address(&address) {
                if address.to_ascii_lowercase().starts_with("sv1") {
                    return Err(VeilError::invalid_input(format!(
                        "VEIL_RECIPIENT_ADDRESS is not a valid Veil stealth address: {reason}"
                    )));
                }
            }

            return Err(VeilError::invalid_input(format!(
                "VEIL_RECIPIENT_ADDRESS is unusable: {error}"
            )));
        }
    };

    Ok((address, destination))
}

/// Read the send amount, given in VEIL, and convert it to satoshis.
///
/// This is step 5 of the plan: the amount is entered in VEIL, which is what a
/// person actually knows, and `veil_to_satoshis` does the conversion.
fn send_amount_from_environment() -> Result<u64, VeilError> {
    let raw = std::env::var("VEIL_SEND_AMOUNT").map_err(|_| {
        VeilError::invalid_input("VEIL_SEND_AMOUNT is not set; export the amount to send, in VEIL")
    })?;

    let veil: f64 = raw.trim().parse().map_err(|_| {
        VeilError::invalid_input(format!("VEIL_SEND_AMOUNT is not a number: {raw}"))
    })?;

    if !veil.is_finite() || veil <= 0.0 {
        return Err(VeilError::invalid_input(format!(
            "VEIL_SEND_AMOUNT must be a positive amount, got {raw}"
        )));
    }

    let satoshis = veil_to_satoshis(veil);

    if satoshis == 0 {
        return Err(VeilError::invalid_input(format!(
            "VEIL_SEND_AMOUNT of {raw} VEIL rounds down to zero satoshis"
        )));
    }

    Ok(satoshis)
}

/// Run an RPC step, retrying with exponential backoff before giving up.
///
/// This is step 4 of the plan. The original example silently fell back to mock
/// decoys when the node was unreachable, which produces a transaction that can
/// never verify. Retrying and then failing is the honest behavior.
async fn with_retry<T, F, Fut>(label: &str, mut operation: F) -> Result<T, VeilError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, VeilError>>,
{
    let mut delay = INITIAL_RETRY_DELAY;
    let mut attempt = 1;

    loop {
        match operation().await {
            Ok(value) => return Ok(value),
            Err(error) => {
                if attempt >= RETRY_ATTEMPTS {
                    return Err(VeilError::rpc(format!(
                        "{label} failed after {RETRY_ATTEMPTS} attempts: {error}"
                    )));
                }

                println!("   {label} failed (attempt {attempt}/{RETRY_ATTEMPTS}): {error}");
                println!("   Retrying in {}ms...", delay.as_millis());

                tokio::time::sleep(delay).await;

                delay = (delay * 2).min(MAX_RETRY_DELAY);
                attempt += 1;
            }
        }
    }
}

/// Count how many distinct ring positions the decoy set can actually fill.
///
/// The builder rejects a decoy whose index is already used by another ring, so
/// duplicate indices do not count toward the requirement.
fn distinct_decoy_indices(decoys: &[AnonOutput]) -> usize {
    decoys.iter().map(|d| d.index).collect::<HashSet<_>>().len()
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("Error: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), VeilError> {
    println!("Veil transaction building example");
    println!("{RULE}\n");

    // ------------------------------------------------------------------
    // 1. Derive the sender wallet from the seed phrase
    // ------------------------------------------------------------------
    println!("1. Deriving sender keys from VEIL_SEED_PHRASE...");
    let keys = keys_from_environment()?;
    let sender_address = keys.stealth_address()?;

    println!("   Account type:  {:?}", keys.account_type);
    println!("   Address index: {}", keys.index);
    println!("   Address:       {sender_address}");
    // Only the public halves are printed; the secrets stay out of the log.
    println!("   Scan pubkey:   {}", bytes_to_hex(&keys.scan_pubkey));
    println!("   Spend pubkey:  {}", bytes_to_hex(&keys.spend_pubkey));
    println!();

    // ------------------------------------------------------------------
    // 2. Read the recipient and the amount
    // ------------------------------------------------------------------
    println!("2. Reading the payment details...");
    let (recipient_address, destination) = recipient_from_environment()?;
    let send_amount = send_amount_from_environment()?;

    println!("   To:     {recipient_address}");
    println!(
        "   Amount: {} VEIL ({send_amount} satoshis)",
        satoshis_to_veil(send_amount)
    );

    // Say plainly what this address publishes, because the two families differ in
    // exactly that and the difference is not recoverable after broadcast.
    match &destination {
        Destination::Stealth(_) => {
            println!("   Output: RingCT, blinded");
            println!("   The amount and the recipient stay private.");
        }
        Destination::Basecoin(basecoin) => {
            let kind = match basecoin {
                BasecoinAddress::P2pkh { .. } => "P2PKH",
                BasecoinAddress::P2wpkh { .. } => "P2WPKH",
            };

            println!("   Output: standard, transparent ({kind})");
            println!(
                "   Warning: the amount and the destination will be public on chain.\n   \
                 Only the sender stays hidden, protected by the ring. Send to an\n   \
                 sv1... stealth address instead if that is not what you want."
            );
        }
    }

    if recipient_address == sender_address {
        println!("   Note: the destination is this wallet's own address.");
    }
    println!();

    // ------------------------------------------------------------------
    // 3. Connect to the node
    // ------------------------------------------------------------------
    println!("3. Connecting to the node...");
    let client = RpcClient::from_env()?;
    println!("   Node: {}", client.url());

    let info = with_retry("getblockchaininfo", || client.get_blockchain_info()).await?;
    println!("   Chain: {} at height {}\n", info.chain, info.blocks);

    // ------------------------------------------------------------------
    // 4. Scan the chain for spendable UTXOs
    // ------------------------------------------------------------------
    // Step 3 of the plan: real inputs, scanned from the node, instead of the
    // fabricated UTXOs the TypeScript example used.
    println!("4. Scanning for spendable UTXOs...");

    // The cache holds the UTXOs an earlier run already decoded, so only records
    // after the stored resume point are fetched. `getwatchonlytxes` is the
    // expensive call, and this is what avoids re-walking the whole history.
    let cache_path =
        std::env::var("VEIL_CACHE_PATH").unwrap_or_else(|_| "veil-balance-cache.redb".to_string());

    let (store, recreated) = RedbStore::open_or_recreate(&cache_path)?;
    println!("   Cache:           {}", store.path().display());
    if recreated {
        println!("   The previous cache file was unreadable and has been recreated.");
    }

    let scanner = BalanceScanner::new(&client)
        .with_cache(&store)
        .with_recovery(RecoveryPolicy::Rewind(REWIND_RECORDS));

    let scan = with_retry("getbalance scan", || {
        scanner.balance(&keys.spend_secret, &keys.scan_secret)
    })
    .await?;

    let balance = scan.balance;

    println!(
        "   Balance:         {} VEIL",
        satoshis_to_veil(balance.total_balance)
    );
    println!("   Unspent UTXOs:   {}", balance.utxos.len());
    println!("   Outputs scanned: {}", balance.total_outputs_scanned);
    println!(
        "   From cache:      {} UTXOs, {} re-checked, {} newly spent",
        scan.cache.loaded, scan.cache.revalidated, scan.cache.dropped
    );

    match scan.cache.resumed_from {
        Some(index) => println!(
            "   Resumed at:      record {index} (rewound {REWIND_RECORDS} from {})",
            balance.last_processed_index
        ),
        None => println!("   Resumed at:      no walk needed, chain tip unchanged"),
    }

    if let Some(note) = &scan.cache.note {
        println!("   Note:            {note}");
    }

    // A ring cannot be built for an output whose global index is unknown, so
    // those UTXOs are not spendable here even though they hold value.
    let (spendable, unusable): (Vec<Utxo>, Vec<Utxo>) = balance
        .utxos
        .into_iter()
        .partition(|utxo| utxo.spendable && utxo.ringct_index.is_some() && utxo.amount > 0);

    if !unusable.is_empty() {
        let stranded: u64 = unusable.iter().map(|u| u.amount).sum();
        println!(
            "   Skipping {} UTXO(s) worth {} VEIL with no usable ringct index",
            unusable.len(),
            satoshis_to_veil(stranded)
        );
    }

    if spendable.is_empty() {
        return Err(VeilError::invalid_input(
            "no spendable UTXOs were found for this wallet; fund it, or wait for confirmations",
        ));
    }

    let available: u64 = spendable.iter().map(|u| u.amount).sum();
    println!(
        "   Spendable:       {} VEIL across {} UTXOs\n",
        satoshis_to_veil(available),
        spendable.len()
    );

    // ------------------------------------------------------------------
    // 5. Fetch decoys from the node
    // ------------------------------------------------------------------
    println!("5. Fetching decoy outputs...");

    let ring_size = DEFAULT_RING_SIZE;

    // Coin selection is randomized and capped at MAX_ANON_INPUTS, so the input
    // count is not known yet. Fetch enough decoys for the worst case.
    let max_inputs = spendable.len().min(MAX_ANON_INPUTS);
    let required_decoys = (ring_size - 1) * max_inputs;

    let decoys = with_retry("getanonoutputs", || {
        fetch_decoy_outputs(&client, ring_size, max_inputs)
    })
    .await?;

    let distinct = distinct_decoy_indices(&decoys);

    println!(
        "   Ring size:       {ring_size} (1 real + {} decoys per input)",
        ring_size - 1
    );
    println!(
        "   Decoys returned: {} ({distinct} distinct indices)",
        decoys.len()
    );
    println!("   Decoys needed:   {required_decoys} (worst case, {max_inputs} inputs)");

    if distinct < required_decoys {
        return Err(VeilError::rpc(format!(
            "the node returned only {distinct} distinct decoy outputs, but up to {required_decoys} \
             are needed for {max_inputs} inputs at ring size {ring_size}"
        )));
    }

    println!("   Using real blockchain decoys; no mock fallback.\n");

    // ------------------------------------------------------------------
    // 6. Build the transaction
    // ------------------------------------------------------------------
    println!("6. Building the transaction...");
    println!("   Generating range proofs and MLSAG signatures, this takes a moment...\n");

    let builder = TransactionBuilder::new(TransactionBuilderConfig {
        ring_size,
        fee_per_kb: 100_000, // 0.001 VEIL; or use DEFAULT_FEE_PER_KB
    })?;

    println!("   {}", builder.describe_health(&spendable));

    let recipients = [Recipient::new(recipient_address.clone(), send_amount)];

    let result = builder.build_transaction(
        &keys.spend_secret,
        &keys.scan_secret,
        &recipients,
        &spendable,
        &decoys,
    )?;

    println!("   Built and MLSAG-verified.\n");

    // ------------------------------------------------------------------
    // 7. Report
    // ------------------------------------------------------------------
    println!("{RULE}");
    println!("7. Transaction details");
    println!("{RULE}\n");

    println!("   TXID:    {}", result.txid);
    println!("   Size:    {} bytes", result.size);
    println!("   Fee:     {} VEIL", satoshis_to_veil(result.fee));
    println!("   Change:  {} VEIL", satoshis_to_veil(result.change));
    println!("   Inputs:  {}", result.inputs.len());
    println!(
        "   Outputs: {} ({} recipient, {} change)",
        result.outputs.len(),
        recipients.len(),
        u8::from(result.change > 0)
    );
    println!();

    println!("   Spending:");
    for (i, utxo) in result.inputs.iter().enumerate() {
        println!(
            "     {}. {} VEIL from {}:{}",
            i + 1,
            satoshis_to_veil(utxo.amount),
            utxo.txid,
            utxo.vout
        );
    }
    println!();

    // Show what each output reveals, which is where the two address families
    // become visible in the finished transaction.
    println!("   Creating:");
    for (i, output) in result.outputs.iter().enumerate() {
        match output {
            TxOutput::Data { .. } => println!("     {}. fee marker", i + 1),
            TxOutput::Standard { amount, .. } => println!(
                "     {}. {} VEIL, transparent (amount visible on chain)",
                i + 1,
                satoshis_to_veil(*amount)
            ),
            TxOutput::RingCt { amount, .. } => println!(
                "     {}. {} VEIL, blinded (amount hidden on chain)",
                i + 1,
                satoshis_to_veil(*amount)
            ),
            TxOutput::Ct { amount, .. } => println!(
                "     {}. {} VEIL, blinded CT",
                i + 1,
                satoshis_to_veil(*amount)
            ),
        }
    }
    println!();

    let preview_len = result.tx_hex.len().min(100);
    println!("   Raw transaction ({} hex chars):", result.tx_hex.len());
    println!("     {}...", &result.tx_hex[..preview_len]);
    println!();

    // ------------------------------------------------------------------
    // 8. Broadcast, only when asked
    // ------------------------------------------------------------------
    println!("{RULE}");
    println!("8. Broadcast");
    println!("{RULE}\n");

    if std::env::var("VEIL_BROADCAST").as_deref() != Ok("1") {
        println!("   VEIL_BROADCAST is not 1, so nothing was sent.");
        println!("   Set VEIL_BROADCAST=1 to broadcast. Spending is irreversible.\n");
        return Ok(());
    }

    println!("   VEIL_BROADCAST=1, sending the transaction...");

    // Deliberately not retried: a "failure" may be a lost response to a
    // transaction the node already accepted, and resending risks confusion
    // about whether the spend happened. Check the txid before retrying.
    let res = client.send_raw_transaction(&result.tx_hex).await;

    match res {
        Ok(txid) => {
            println!("   Accepted by the node.");
            println!("   TXID: {txid}");

            if txid != result.txid {
                println!(
                    "   Note: the node reported a different txid than was computed locally ({}).",
                    result.txid
                );
            }
        }
        Err(err) => {
            println!("   tx send error: {}", err);
        }
    }
    println!();

    Ok(())
}
