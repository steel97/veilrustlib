//! Configuration, read from the same `.env` the Dart bot used.
//!
//! Every key the Dart faucet read is read here, with the same name and the same
//! meaning, so an existing deployment can swap the binary and keep its file.

use std::time::Duration;

use serenity::model::id::{ChannelId, GuildId};

use crate::error::FaucetError;

/// Path to the `.env` file, matching the Dart bot's `dotenv` default.
pub const ENV_PATH: &str = ".env";

/// Fallback request interval, in seconds, when `FAUCET_TIMESTAMP_LIMIT` is unset.
///
/// Matches the Dart default in `db.dart`, where `ev` starts at 3600.
const DEFAULT_TIMESTAMP_LIMIT: u64 = 3600;

/// Fallback payout interval when `FAUCET_PAYOUTS_DELAY` is unset.
///
/// The Dart bot defaulted this to `60000` and passed it to
/// `Duration(milliseconds:)`, so despite the variable being documented in
/// seconds its default behaved as 60 seconds. That is reproduced here.
const DEFAULT_PAYOUTS_DELAY: u64 = 60;

/// Fallback recipients per transaction, matching `db.dart`'s `?? '1'`.
const DEFAULT_PAYOUTS_PER_CYCLE: usize = 1;

/// Fallback payout size in VEIL, matching `payout_service.dart`'s `?? '1'`.
const DEFAULT_PAYOUTS_AMOUNT: f64 = 1.0;

/// Everything the faucet needs to run.
#[derive(Debug, Clone)]
pub struct Config {
    /// Discord bot token.
    pub discord_token: String,
    /// Guild the bot registers its command in.
    pub discord_server_id: GuildId,
    /// Channel payout announcements are posted to.
    pub discord_target_channel_id: ChannelId,
    /// BIP39 mnemonic for the faucet wallet.
    pub mnemonic: String,
    /// BIP39 passphrase; empty when the wallet is not encrypted.
    pub encryption_password: String,
    /// Veil node URL.
    pub node_address: String,
    /// Node RPC username, when the node requires authentication.
    pub node_user: Option<String>,
    /// Node RPC password, when the node requires authentication.
    pub node_password: Option<String>,
    /// Explorer prefix a txid is appended to for announcements.
    pub explorer_tx: String,
    /// How long a user must wait between requests.
    pub timestamp_limit: Duration,
    /// How long the payout loop sleeps between cycles.
    pub payouts_delay: Duration,
    /// How many queued users are paid per transaction.
    pub payouts_per_cycle: usize,
    /// How much each user receives, in satoshis.
    pub payout_amount: u64,
}

impl Config {
    /// Load configuration from the process environment.
    ///
    /// Call [`load_dotenv`] first to populate it from `.env`.
    pub fn from_env() -> Result<Self, FaucetError> {
        let timestamp_limit = optional_u64("FAUCET_TIMESTAMP_LIMIT")?.unwrap_or_else(|| {
            eprintln!(
                "FAUCET_TIMESTAMP_LIMIT is not set; defaulting to {DEFAULT_TIMESTAMP_LIMIT} seconds"
            );
            DEFAULT_TIMESTAMP_LIMIT
        });

        let payouts_delay =
            optional_u64("FAUCET_PAYOUTS_DELAY")?.unwrap_or(DEFAULT_PAYOUTS_DELAY);

        let payouts_per_cycle = match optional_u64("FAUCET_PAYOUTS_PER_CYCLE")? {
            Some(value) => usize::try_from(value).map_err(|_| {
                FaucetError::config(format!("FAUCET_PAYOUTS_PER_CYCLE is too large: {value}"))
            })?,
            None => DEFAULT_PAYOUTS_PER_CYCLE,
        };

        if payouts_per_cycle == 0 {
            return Err(FaucetError::config(
                "FAUCET_PAYOUTS_PER_CYCLE must be at least 1, or no one is ever paid",
            ));
        }

        // MAX_ANON_INPUTS caps how many inputs one transaction may spend, and a
        // very large recipient count makes a transaction the network will reject
        // on size alone. Warn rather than refuse: the operator may know better.
        if payouts_per_cycle > 32 {
            eprintln!(
                "FAUCET_PAYOUTS_PER_CYCLE is {payouts_per_cycle}; a transaction with that many \
                 outputs may be rejected as oversized"
            );
        }

        let payout_veil = match optional_var("FAUCET_PAYOUTS_AMOUNT") {
            Some(raw) => raw.trim().parse::<f64>().map_err(|_| {
                FaucetError::config(format!("FAUCET_PAYOUTS_AMOUNT is not a number: {raw}"))
            })?,
            None => DEFAULT_PAYOUTS_AMOUNT,
        };

        if !payout_veil.is_finite() || payout_veil <= 0.0 {
            return Err(FaucetError::config(format!(
                "FAUCET_PAYOUTS_AMOUNT must be a positive amount of VEIL, got {payout_veil}"
            )));
        }

        let payout_amount = veilrustlib::utils::veil_to_satoshis(payout_veil);

        if payout_amount == 0 {
            return Err(FaucetError::config(format!(
                "FAUCET_PAYOUTS_AMOUNT of {payout_veil} VEIL rounds down to zero satoshis"
            )));
        }

        let mnemonic = required_var("VEIL_MNEMONIC")?;

        if !veilrustlib::hdwallet::verify_mnemonic_shape(&mnemonic) {
            return Err(FaucetError::config(
                "VEIL_MNEMONIC does not have 12, 15, 18, 21, or 24 words",
            ));
        }

        Ok(Self {
            discord_token: required_var("DISCORD_TOKEN")?,
            discord_server_id: GuildId::new(required_id("DISCORD_SERVER_ID")?),
            discord_target_channel_id: ChannelId::new(required_id("DISCORD_TARGET_CHANNEL_ID")?),
            mnemonic,
            encryption_password: optional_var("VEIL_ENCRYPTION_PASSWORD").unwrap_or_default(),
            node_address: optional_var("VEIL_NODE_ADDRESS")
                .unwrap_or_else(|| veilrustlib::rpc::DEFAULT_NODE_URL.to_string()),
            node_user: optional_var("VEIL_NODE_USER"),
            node_password: optional_var("VEIL_NODE_PASSWORD"),
            explorer_tx: optional_var("VEIL_EXPLORER_TX").unwrap_or_default(),
            timestamp_limit: Duration::from_secs(timestamp_limit),
            payouts_delay: Duration::from_secs(payouts_delay),
            payouts_per_cycle,
            payout_amount,
        })
    }

    /// The wait between requests, in seconds, as stored alongside timestamps.
    pub fn timestamp_limit_secs(&self) -> i64 {
        // Timestamps are stored as seconds, so the limit is compared in seconds.
        self.timestamp_limit.as_secs() as i64
    }

    /// Build the RPC configuration for the faucet's node.
    pub fn rpc_config(&self) -> veilrustlib::rpc::RpcConfig {
        veilrustlib::rpc::RpcConfig {
            url: self.node_address.clone(),
            username: self.node_user.clone(),
            password: self.node_password.clone(),
            timeout: veilrustlib::rpc::DEFAULT_TIMEOUT,
        }
    }
}

/// Load `.env` into the process environment, if the file exists.
///
/// A missing file is not an error: the operator may set the variables directly,
/// which is common in a container.
///
/// A variable already present in the environment wins, so a container or shell
/// can override the file without editing it. This matches Dart's `dotenv`, which
/// merges its map over `Platform.environment` but reads the platform value first
/// during interpolation.
pub fn load_dotenv() {
    let content = match std::fs::read_to_string(ENV_PATH) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            println!("No {ENV_PATH} file found; reading configuration from the environment");
            return;
        }
        Err(error) => {
            eprintln!("Could not read {ENV_PATH}: {error}");
            return;
        }
    };

    let mut loaded = 0;

    for (key, value) in crate::dotenv::parse(&content) {
        if std::env::var_os(&key).is_some() {
            continue;
        }

        // Safety: this runs once, before any thread is spawned.
        std::env::set_var(&key, &value);
        loaded += 1;
    }

    println!("Loaded {loaded} setting(s) from {ENV_PATH}");
}

/// Read a variable, treating an empty value as absent.
///
/// The Dart `.env.example` marks several keys optional by leaving them blank, so
/// an empty string must not be mistaken for a real value.
fn optional_var(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(value) if !value.trim().is_empty() => Some(value.trim().to_string()),
        _ => None,
    }
}

/// Read a variable that must be present and non-empty.
fn required_var(key: &str) -> Result<String, FaucetError> {
    optional_var(key)
        .ok_or_else(|| FaucetError::config(format!("{key} is not set; add it to {ENV_PATH}")))
}

/// Read an optional variable that must parse as a number when present.
fn optional_u64(key: &str) -> Result<Option<u64>, FaucetError> {
    match optional_var(key) {
        Some(raw) => raw
            .parse::<u64>()
            .map(Some)
            .map_err(|_| FaucetError::config(format!("{key} is not a whole number: {raw}"))),
        None => Ok(None),
    }
}

/// Read a required Discord snowflake.
fn required_id(key: &str) -> Result<u64, FaucetError> {
    let raw = required_var(key)?;

    let id = raw
        .parse::<u64>()
        .map_err(|_| FaucetError::config(format!("{key} is not a Discord ID: {raw}")))?;

    if id == 0 {
        return Err(FaucetError::config(format!("{key} must not be zero")));
    }

    Ok(id)
}
