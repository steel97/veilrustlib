//! Building and broadcasting faucet payouts.
//!
//! Port of `ref/veil-faucet/lib/services/payout_service.dart`, with the coin
//! selection and mempool bookkeeping that file did by hand replaced by the
//! library's cached scanner and coin selector.
//!
//! ## What the cache buys
//!
//! The Dart bot called `fetchTxes()` then `getUnspentOutputs(fetchIfCacheExists:
//! false)` on every cycle, re-walking the wallet's whole watch-only history each
//! time. Here a [`BalanceScanner`] backed by a [`RedbStore`] fetches only the
//! records added since the last scan, and skips the walk entirely when the chain
//! tip has not moved. With a payout cycle running every minute, that is the
//! difference between a constant full rescan and one `getblockchaininfo` call.
//!
//! Cached key images are re-checked whenever the tip moves, which is what
//! catches a UTXO already spent by the previous cycle's transaction, including
//! while it is still in the mempool. That replaces the Dart bot's explicit
//! `getrawmempool` filter.

use std::path::PathBuf;

use veilrustlib::balance::BalanceScanner;
use veilrustlib::cache::{RecoveryPolicy, RedbStore};
use veilrustlib::hdwallet::{derive_stealth_keys, AccountType, StealthKeys};
use veilrustlib::rpc::{fetch_decoy_outputs, RpcClient};
use veilrustlib::transaction_builder::{
    Recipient, TransactionBuilder, TransactionBuilderConfig, DEFAULT_RING_SIZE, MAX_ANON_INPUTS,
};
use veilrustlib::types::Utxo;
use veilrustlib::utils::satoshis_to_veil;
use veilrustlib::VeilError;

use crate::config::Config;
use crate::error::FaucetError;

/// Cache file for the wallet's scanned UTXOs.
///
/// The Dart bot kept its scan in `./faucet-storage`; this is the equivalent, in
/// the single-file format the library's cache uses.
pub const CACHE_PATH: &str = "./faucet-storage.redb";

/// BIP44 account the faucet wallet uses.
///
/// The Dart bot constructed `LightwalletAccount(wallet)` with the default
/// `accountId = 0`.
const ACCOUNT_ID: u32 = 0;

/// Address index within the stealth branch.
///
/// `getAddress(AccountType.STEALTH)` defaults to `index = 1`, so the same index
/// is used here and the same address is derived from the same mnemonic.
const ADDRESS_INDEX: u32 = 1;

/// Fee rate, in satoshis per kilobyte.
///
/// The Dart bot charged a flat `CENT` (0.01 VEIL) per transaction regardless of
/// size, with a `TODO` to ask the node for a real rate. A per-kilobyte rate is
/// used instead, which is what the network actually prices, and the library
/// derives the fee from the transaction's estimated size.
const FEE_PER_KB: u64 = 100_000;

/// How many records the cached scan rewinds before resuming.
///
/// Spending needs inputs that are genuinely unspent, so the walk re-reads the
/// tail it already covered rather than trusting the stored resume point exactly.
const REWIND_RECORDS: u64 = 20;

/// The outcome of one payout cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayoutOutcome {
    /// Nothing was queued, so nothing was done.
    QueueEmpty,
    /// A transaction was broadcast.
    Paid {
        /// Transaction id the node accepted.
        txid: String,
        /// Row ids that were paid, to be marked used.
        paid_ids: Vec<i64>,
        /// How many recipients were paid.
        recipients: usize,
        /// Fee paid, in satoshis.
        fee: u64,
    },
    /// Every queued address was unusable, and those rows were consumed.
    ///
    /// Returning the ids lets the caller retire them, so one bad address cannot
    /// block the queue forever.
    AllAddressesInvalid {
        /// Row ids that can never be paid.
        rejected_ids: Vec<i64>,
    },
    /// The wallet cannot cover the batch right now.
    InsufficientFunds {
        /// What the batch needs, in satoshis.
        required: u64,
        /// What is currently spendable, in satoshis.
        available: u64,
    },
    /// Funds exist but are not yet spendable, typically unconfirmed change.
    WaitingForChange {
        /// Total balance, in satoshis.
        balance: u64,
        /// The part of it that can be spent now, in satoshis.
        spendable: u64,
    },
}

/// The faucet's wallet and the node it talks to.
pub struct PayoutWallet {
    keys: StealthKeys,
    address: String,
    client: RpcClient,
    store: RedbStore,
    builder: TransactionBuilder,
}

impl PayoutWallet {
    /// Derive the faucet wallet and open its cache.
    pub fn open(config: &Config) -> Result<Self, FaucetError> {
        let keys = derive_stealth_keys(
            &config.mnemonic,
            &config.encryption_password,
            ACCOUNT_ID,
            AccountType::Stealth,
            ADDRESS_INDEX,
        )?;

        let address = keys.stealth_address()?;

        let client = RpcClient::new(config.rpc_config())?;

        let (store, recreated) = RedbStore::open_or_recreate(CACHE_PATH)?;
        if recreated {
            println!("The scan cache was unreadable and has been recreated");
        }

        let builder = TransactionBuilder::new(TransactionBuilderConfig {
            ring_size: DEFAULT_RING_SIZE,
            fee_per_kb: FEE_PER_KB,
        })?;

        Ok(Self {
            keys,
            address,
            client,
            store,
            builder,
        })
    }

    /// The faucet's own stealth address, where it must be funded.
    pub fn address(&self) -> &str {
        &self.address
    }

    /// The node URL in use.
    pub fn node_url(&self) -> &str {
        self.client.url()
    }

    /// The cache file backing the scan.
    pub fn cache_path(&self) -> PathBuf {
        self.store.path().to_path_buf()
    }

    /// Scan for spendable UTXOs, reusing the cache.
    async fn spendable_utxos(&self) -> Result<(Vec<Utxo>, u64), FaucetError> {
        let scanner = BalanceScanner::new(&self.client)
            .with_cache(&self.store)
            .with_recovery(RecoveryPolicy::Rewind(REWIND_RECORDS));

        let scan = scanner
            .balance(&self.keys.spend_secret, &self.keys.scan_secret)
            .await?;

        let balance = scan.balance.total_balance;

        // A UTXO with no global ringct index cannot be placed in a ring, so it
        // holds value that cannot be spent from here.
        let spendable: Vec<Utxo> = scan
            .balance
            .utxos
            .into_iter()
            .filter(|utxo| utxo.spendable && utxo.ringct_index.is_some() && utxo.amount > 0)
            .collect();

        Ok((spendable, balance))
    }

    /// Report the wallet's balance, for the startup log.
    pub async fn report_balance(&self) -> Result<(u64, u64), FaucetError> {
        let (spendable, balance) = self.spendable_utxos().await?;
        let usable: u64 = spendable.iter().map(|utxo| utxo.amount).sum();

        Ok((balance, usable))
    }

    /// Build and broadcast a payout for `requests`.
    ///
    /// Addresses are validated here rather than when queued, because an address
    /// that was valid at queue time is still validated before it is paid.
    pub async fn pay(
        &self,
        requests: &[crate::db::QueuedRequest],
        amount_each: u64,
    ) -> Result<PayoutOutcome, FaucetError> {
        if requests.is_empty() {
            return Ok(PayoutOutcome::QueueEmpty);
        }

        // Split the batch into payable and unpayable rows.
        let mut recipients = Vec::with_capacity(requests.len());
        let mut paid_ids = Vec::with_capacity(requests.len());
        let mut rejected_ids = Vec::new();

        for request in requests {
            match veilrustlib::classify_address(&request.address) {
                Ok(_) => {
                    recipients.push(Recipient::new(request.address.trim(), amount_each));
                    paid_ids.push(request.id);
                }
                Err(error) => {
                    // The address passed validation when it was queued, so this
                    // is unexpected; retire the row rather than retry it every
                    // cycle.
                    eprintln!(
                        "Queue row {} has an unpayable address, retiring it: {error}",
                        request.id
                    );
                    rejected_ids.push(request.id);
                }
            }
        }

        if recipients.is_empty() {
            return Ok(PayoutOutcome::AllAddressesInvalid { rejected_ids });
        }

        let (spendable, balance) = self.spendable_utxos().await?;

        if spendable.is_empty() {
            return Ok(PayoutOutcome::WaitingForChange {
                balance,
                spendable: 0,
            });
        }

        let total_out = amount_each
            .checked_mul(recipients.len() as u64)
            .ok_or_else(|| FaucetError::config("the payout batch total overflows"))?;

        // Decoys are fetched for the worst-case input count, since coin selection
        // is randomized and its result is not known until the build runs.
        let max_inputs = spendable.len().min(MAX_ANON_INPUTS);
        let decoys = fetch_decoy_outputs(&self.client, DEFAULT_RING_SIZE, max_inputs).await?;

        let result = match self.builder.build_transaction(
            &self.keys.spend_secret,
            &self.keys.scan_secret,
            &recipients,
            &spendable,
            &decoys,
        ) {
            Ok(result) => result,
            Err(VeilError::InsufficientFunds {
                required,
                available,
            }) => {
                // Distinguish "not enough coins" from "coins exist but are
                // locked up in unconfirmed change", which is the distinction the
                // Dart bot logged as "waiting for change".
                if balance > available {
                    return Ok(PayoutOutcome::WaitingForChange {
                        balance,
                        spendable: available,
                    });
                }

                return Ok(PayoutOutcome::InsufficientFunds {
                    required,
                    available,
                });
            }
            Err(error) => return Err(error.into()),
        };

        println!(
            "Built a payout of {} VEIL to {} recipient(s), fee {} VEIL, spending {} of {} UTXOs",
            satoshis_to_veil(total_out),
            recipients.len(),
            satoshis_to_veil(result.fee),
            result.inputs.len(),
            spendable.len()
        );

        // Deliberately not retried. A failed response may be a lost reply to a
        // transaction the node already accepted, and resending would pay twice.
        //
        // Broadcast through the scanner rather than the client directly, so the
        // txid is recorded in the sent-transaction cache. The faucet spends its
        // own change constantly, and without that record every change output it
        // creates reads back as `TxDirection::Unknown` on the next scan instead
        // of as change it produced itself.
        //
        // A failed cache write does not fail the payout: the transaction is
        // already irreversible by then, so the only loss is the direction label.
        let scanner = BalanceScanner::new(&self.client)
            .with_cache(&self.store)
            .with_recovery(RecoveryPolicy::Rewind(REWIND_RECORDS));

        let txid = scanner
            .broadcast_and_record(&self.keys.scan_secret, &result.tx_hex)
            .await?;

        Ok(PayoutOutcome::Paid {
            txid,
            paid_ids,
            recipients: recipients.len(),
            fee: result.fee,
        })
    }
}
