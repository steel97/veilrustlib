//! Example: a Veil faucet Discord bot.
//!
//! A one-to-one replacement for the Dart bot in `ref/veil-faucet`: the same
//! `.env` keys, the same `db.sqlite` file and schema, the same `/getcoins`
//! command, and the same user-visible messages. An existing deployment can swap
//! the binary in place and keep its database and configuration.
//!
//! Two things run concurrently:
//!
//! 1. a Discord gateway client, which answers `/getcoins` by validating an
//!    address and adding it to the queue
//! 2. a payout loop, which every `FAUCET_PAYOUTS_DELAY` seconds takes the oldest
//!    queued requests, pays them in one RingCT transaction, and announces it
//!
//! ## What this example demonstrates
//!
//! - Paying **both** address families in one transaction: `sv1...` stealth
//!   addresses become blinded RingCT outputs, `V...` and `bv1...` basecoin
//!   addresses become transparent standard outputs. See
//!   [`veilrustlib::classify_address`].
//! - Cached balance scanning, so a payout cycle running every minute does not
//!   re-walk the wallet's history each time. See [`payout`].
//! - Persisting state in SQLite through a pure-Rust engine, so the build needs no
//!   C compiler. See [`db`].
//!
//! ## Environment
//!
//! Identical to the Dart bot's `.env.example`, with one addition:
//!
//! ```text
//! DISCORD_TOKEN               required  bot token
//! DISCORD_SERVER_ID           required  guild the command is registered in
//! DISCORD_TARGET_CHANNEL_ID   required  channel payouts are announced in
//! VEIL_MNEMONIC               required  faucet wallet seed phrase
//! VEIL_ENCRYPTION_PASSWORD    optional  BIP39 passphrase, empty if unencrypted
//! VEIL_NODE_ADDRESS           optional  node URL, defaults to the public endpoint
//! VEIL_NODE_USER              optional  RPC username, new in this port
//! VEIL_NODE_PASSWORD          optional  RPC password
//! VEIL_EXPLORER_TX            optional  explorer prefix for announcements
//! FAUCET_TIMESTAMP_LIMIT      optional  seconds between requests per user
//! FAUCET_PAYOUTS_DELAY        optional  seconds between payout cycles
//! FAUCET_PAYOUTS_PER_CYCLE    optional  recipients per transaction
//! FAUCET_PAYOUTS_AMOUNT       optional  VEIL sent per user
//! ```
//!
//! `DISCORD_CLIENT_ID` is accepted in the file but unused: serenity reads the
//! application id from the token, so it never needs to be configured.
//!
//! `VEIL_NODE_USER` is the one addition. The Dart bot sent `VEIL_NODE_PASSWORD`
//! verbatim as the `Authorization: Basic` value, meaning it held an
//! already-base64-encoded `user:pass` pair. This port takes the username and
//! password separately and does the encoding itself, which is both clearer and
//! consistent with the rest of the library.
//!
//! ## Running
//!
//! ```text
//! cp ref/veil-faucet/.env.example .env    # then fill it in
//! cargo run -p veilrustlib-examples --bin veilfaucet
//! ```
//!
//! The faucet prints its own address at startup. Send coins there to fund it.
//!
//! ## A note on privacy and safety
//!
//! Scanning uses `getwatchonlytxes`, which sends the scan *private* key to the
//! node; the node can then link every output belonging to this wallet. Point
//! `VEIL_NODE_ADDRESS` at a node you control if that matters.
//!
//! `faucet-storage.redb` holds decoded UTXOs, including amounts and blinding
//! factors, so treat it as wallet data. It never stores the scan or spend secret.
//!
//! Use a dedicated wallet. This process holds a spendable mnemonic in memory and
//! broadcasts transactions automatically, with no confirmation step.
//!
//! ## Taking over an existing db.sqlite
//!
//! The queue file is a standard SQLite database and is read and written in place,
//! verified against the stock `sqlite3` CLI in
//! `tests/faucet_db_cross_engine.rs`. One caveat: the pure-Rust engine will not
//! write a database with `auto_vacuum` enabled, and opens it read-only instead.
//! SQLite defaults that off, so a file the Dart bot created is fine. If the file
//! has since been compacted with `PRAGMA auto_vacuum=FULL`, the faucet says so at
//! startup and prints the command to undo it.

mod command;
mod config;
mod db;
mod dotenv;
mod error;
mod payout;
mod util;

use std::sync::Arc;

use serenity::all::{Interaction, Ready};
use serenity::async_trait;
use serenity::builder::CreateMessage;
use serenity::client::{Client, Context, EventHandler};
use serenity::model::channel::MessageFlags;
use serenity::model::gateway::GatewayIntents;
use serenity::model::id::GuildId;

use veilrustlib::utils::satoshis_to_veil;

use crate::config::Config;
use crate::db::Queue;
use crate::error::FaucetError;
use crate::payout::{PayoutOutcome, PayoutWallet};

const RULE: &str = "----------------------------------------";

/// Shared state the gateway handler needs.
struct Handler {
    config: Arc<Config>,
    queue: Arc<Queue>,
}

#[async_trait]
impl EventHandler for Handler {
    async fn ready(&self, ctx: Context, ready: Ready) {
        println!("Connected to Discord as {}", ready.user.name);

        // Register the command on the configured guild. A guild command appears
        // immediately, where a global one can take an hour to propagate.
        let guild = GuildId::new(self.config.discord_server_id.get());

        match guild
            .set_commands(&ctx.http, vec![command::definition()])
            .await
        {
            Ok(_) => println!("Registered /{} in guild {guild}", command::COMMAND_NAME),
            Err(error) => eprintln!(
                "Could not register /{} in guild {guild}: {error}\n\
                 Check that the bot is in that server and DISCORD_SERVER_ID is correct.",
                command::COMMAND_NAME
            ),
        }
    }

    async fn interaction_create(&self, ctx: Context, interaction: Interaction) {
        let Interaction::Command(command) = interaction else {
            return;
        };

        if command.data.name != command::COMMAND_NAME {
            return;
        }

        // One user's failed command must not take the bot down, so the error is
        // logged and the loop continues.
        if let Err(error) = command::handle(&ctx, &command, &self.config, &self.queue).await {
            eprintln!("/{} failed: {error}", command::COMMAND_NAME);
        }
    }
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("Error: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), FaucetError> {
    println!("Veil faucet");
    println!("{RULE}\n");

    // ------------------------------------------------------------------
    // 1. Configuration
    // ------------------------------------------------------------------
    config::load_dotenv();

    let config = Arc::new(Config::from_env()?);

    println!("Payout:  {} VEIL per user", satoshis_to_veil(config.payout_amount));
    println!("Batch:   up to {} user(s) per transaction", config.payouts_per_cycle);
    println!("Cycle:   every {} seconds", config.payouts_delay.as_secs());
    println!("Cooloff: {} seconds per user", config.timestamp_limit.as_secs());
    println!();

    // ------------------------------------------------------------------
    // 2. Queue database
    // ------------------------------------------------------------------
    let queue = Arc::new(Queue::open(db::DB_PATH).await?);

    println!("Queue:   {} ({} pending)", db::DB_PATH, queue.pending_count().await?);

    // ------------------------------------------------------------------
    // 3. Wallet and node
    // ------------------------------------------------------------------
    let wallet = Arc::new(PayoutWallet::open(&config)?);

    println!("Node:    {}", wallet.node_url());
    println!("Cache:   {}", wallet.cache_path().display());
    println!("Address: {}", wallet.address());

    // Scan once up front, so an unfunded or unreachable faucet is obvious now
    // rather than after the first cycle.
    match wallet.report_balance().await {
        Ok((balance, spendable)) => {
            println!(
                "Balance: {} VEIL ({} VEIL spendable)",
                satoshis_to_veil(balance),
                satoshis_to_veil(spendable)
            );

            if spendable < config.payout_amount {
                println!(
                    "\nWarning: the spendable balance is below one payout of {} VEIL.\n\
                     Fund the address above before requests start arriving.",
                    satoshis_to_veil(config.payout_amount)
                );
            }
        }
        Err(error) => {
            // A node that is down now may be up by the first payout cycle, so
            // this is a warning rather than a failure to start.
            eprintln!("\nWarning: could not read the balance: {error}");
        }
    }

    println!();

    // ------------------------------------------------------------------
    // 4. Discord client
    // ------------------------------------------------------------------
    // Only the default intents are needed: the bot acts on slash commands and
    // posts messages, and never reads message content.
    let intents = GatewayIntents::non_privileged();

    let mut client = Client::builder(&config.discord_token, intents)
        .event_handler(Handler {
            config: Arc::clone(&config),
            queue: Arc::clone(&queue),
        })
        .await?;

    // The payout loop needs an http handle to announce transactions.
    let http = Arc::clone(&client.http);
    let shard_manager = Arc::clone(&client.shard_manager);

    let payout_task = tokio::spawn(run_payout_loop(
        Arc::clone(&config),
        Arc::clone(&queue),
        Arc::clone(&wallet),
        http,
    ));

    println!("Starting the gateway and the payout loop...\n");

    // Stop cleanly on Ctrl-C, so the shard closes its session rather than
    // timing out.
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            println!("\nShutting down...");
            shard_manager.shutdown_all().await;
        }
    });

    let result = client.start().await;

    // The gateway has stopped, so stop paying out too.
    payout_task.abort();

    result.map_err(FaucetError::from)
}

/// Pay the queue on a fixed interval, forever.
///
/// Port of `runService` in `payout_service.dart`. A failed cycle is logged and
/// the loop continues: the node being briefly unreachable must not end the bot.
async fn run_payout_loop(
    config: Arc<Config>,
    queue: Arc<Queue>,
    wallet: Arc<PayoutWallet>,
    http: Arc<serenity::http::Http>,
) {
    println!("Running the payout cycle every {} seconds", config.payouts_delay.as_secs());

    loop {
        if let Err(error) = run_payout_cycle(&config, &queue, &wallet, &http).await {
            eprintln!("Payout cycle failed: {error}");

            if error.is_fatal() {
                eprintln!("This error is not recoverable; the payout loop is stopping.");
                return;
            }
        }

        tokio::time::sleep(config.payouts_delay).await;
    }
}

/// Run one payout cycle.
async fn run_payout_cycle(
    config: &Config,
    queue: &Queue,
    wallet: &PayoutWallet,
    http: &Arc<serenity::http::Http>,
) -> Result<(), FaucetError> {
    let requests = queue.oldest_pending(config.payouts_per_cycle).await?;

    if requests.is_empty() {
        return Ok(());
    }

    match wallet.pay(&requests, config.payout_amount).await? {
        PayoutOutcome::QueueEmpty => {}

        PayoutOutcome::Paid {
            txid,
            paid_ids,
            recipients,
            fee,
        } => {
            println!(
                "Made payout, txid = {txid}, count = {recipients}, fee = {} VEIL",
                satoshis_to_veil(fee)
            );

            // Mark the rows paid before announcing. If the announcement fails
            // the coins are still sent, and paying twice is far worse than a
            // missing message.
            queue.mark_used(&paid_ids).await?;

            announce_payout(config, http, &txid, recipients).await;
        }

        PayoutOutcome::AllAddressesInvalid { rejected_ids } => {
            // Retire the rows so one unpayable address cannot stall the queue.
            queue.mark_used(&rejected_ids).await?;
            eprintln!(
                "Retired {} queue row(s) with unpayable addresses",
                rejected_ids.len()
            );
        }

        PayoutOutcome::InsufficientFunds {
            required,
            available,
        } => {
            eprintln!(
                "Not enough coins: need {} VEIL, have {} VEIL spendable",
                satoshis_to_veil(required),
                satoshis_to_veil(available)
            );
        }

        PayoutOutcome::WaitingForChange { balance, spendable } => {
            println!(
                "Waiting for change: {} VEIL total, {} VEIL spendable now",
                satoshis_to_veil(balance),
                satoshis_to_veil(spendable)
            );
        }
    }

    Ok(())
}

/// Post a payout announcement to the configured channel.
///
/// A failure here is logged but never propagated: the transaction is already
/// broadcast, and the queue is already updated.
async fn announce_payout(
    config: &Config,
    http: &Arc<serenity::http::Http>,
    txid: &str,
    recipients: usize,
) {
    let content = if config.explorer_tx.is_empty() {
        format!("Made payout to {recipients} user(s)! tx: {txid}")
    } else {
        format!(
            "Made payout to {recipients} user(s)! tx: {}{txid}",
            config.explorer_tx
        )
    };

    // Embeds are suppressed so the explorer link does not expand into a preview,
    // matching the Dart bot's SUPPRESS_EMBEDS flag.
    let message = CreateMessage::new()
        .content(content)
        .flags(MessageFlags::SUPPRESS_EMBEDS);

    if let Err(error) = config
        .discord_target_channel_id
        .send_message(http, message)
        .await
    {
        eprintln!("Could not announce the payout in the target channel: {error}");
    }
}
