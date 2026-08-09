//! JSON-RPC client for Veil nodes.
//!
//! Port of `src/rpc.ts`. The TypeScript original used a class with mutable
//! static configuration; this port uses an owned [`RpcClient`] so several
//! endpoints can be used concurrently without shared state.
//!
//! Gated behind the `rpc` feature.

use crate::error::{Result, VeilError};
use crate::types::{AnonOutput, KeyImage};
use crate::utils::{bytes_to_hex, hex_to_array};
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Default public endpoint, matching the TypeScript default.
pub const DEFAULT_NODE_URL: &str = "https://api.veil.zelcore.io";

/// Default request timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Chain state reported by `getblockchaininfo`.
#[derive(Debug, Clone, Deserialize)]
pub struct BlockchainInfo {
    /// Current chain height.
    pub blocks: u64,
    /// Hash of the best block.
    #[serde(default)]
    pub bestblockhash: String,
    /// Chain name: `main`, `test`, or `regtest`.
    #[serde(default)]
    pub chain: String,
    /// Verification progress, from 0 to 1.
    #[serde(default)]
    pub verificationprogress: f64,
    /// Accumulated chain work.
    #[serde(default)]
    pub chainwork: String,
}

/// The spent status of a key image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyImageStatus {
    /// The key image, hex-encoded.
    pub key_image: String,
    /// Whether the node accepted the key image as well-formed.
    pub valid: bool,
    /// Explanation when `valid` is false.
    pub msg: Option<String>,
    /// Whether the key image is spent on chain.
    pub spent: bool,
    /// Whether the key image is spent in the mempool.
    pub spent_in_mempool: bool,
    /// The transaction that spent it, when known.
    pub txid: Option<String>,
}

impl KeyImageStatus {
    /// Whether this key image is spent either on chain or in the mempool.
    pub fn is_spent(&self) -> bool {
        self.spent || self.spent_in_mempool
    }
}

/// A page of watch-only records returned by `getwatchonlytxes`.
#[derive(Debug, Clone, Default)]
pub struct WatchOnlyTxes {
    /// RingCT (anon) records.
    pub anon: Vec<WatchOnlyRecord>,
    /// CT (stealth) records.
    pub stealth: Vec<WatchOnlyRecord>,
}

/// A single watch-only record, with any metadata the node supplied.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WatchOnlyRecord {
    /// Hex-encoded record blob.
    pub raw: String,
    /// Amount, when the node decoded it.
    pub amount: Option<u64>,
    /// Blinding factor, when the node decoded it.
    pub blind: Option<[u8; 32]>,
    /// Global RingCT index.
    pub ringct_index: Option<u64>,
    /// Database index, used to resume pagination.
    pub dbindex: Option<u64>,
}

/// Configuration for an [`RpcClient`].
#[derive(Debug, Clone)]
pub struct RpcConfig {
    /// Node URL.
    pub url: String,
    /// RPC username, when the node requires authentication.
    pub username: Option<String>,
    /// RPC password, when the node requires authentication.
    pub password: Option<String>,
    /// Request timeout.
    pub timeout: Duration,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            url: std::env::var("VEIL_NODE_URL").unwrap_or_else(|_| DEFAULT_NODE_URL.to_string()),
            username: std::env::var("VEIL_NODE_USERNAME").ok(),
            password: std::env::var("VEIL_NODE_PASSWORD").ok(),
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

/// A JSON-RPC 2.0 client for a Veil node.
///
/// Credentials are sent as HTTP basic auth, so prefer an HTTPS URL or a node on
/// localhost; over plain HTTP the password is exposed in transit.
#[derive(Debug)]
pub struct RpcClient {
    config: RpcConfig,
    http: reqwest::Client,
    request_id: AtomicU64,
}

impl RpcClient {
    /// Build a client from explicit configuration.
    pub fn new(config: RpcConfig) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|e| VeilError::rpc(format!("failed to build HTTP client: {e}")))?;

        Ok(Self {
            config,
            http,
            request_id: AtomicU64::new(0),
        })
    }

    /// Build a client for `url` with no authentication.
    pub fn from_url(url: impl Into<String>) -> Result<Self> {
        Self::new(RpcConfig {
            url: url.into(),
            ..Default::default()
        })
    }

    /// Build a client from the `VEIL_NODE_*` environment variables.
    pub fn from_env() -> Result<Self> {
        Self::new(RpcConfig::default())
    }

    /// The configured node URL.
    pub fn url(&self) -> &str {
        &self.config.url
    }

    /// Send a JSON-RPC call and return the `result` field.
    pub async fn send(&self, method: &str, params: Value) -> Result<Value> {
        let id = self.request_id.fetch_add(1, Ordering::Relaxed) + 1;

        let request = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });

        let mut builder = self.http.post(&self.config.url).json(&request);

        if let Some(password) = &self.config.password {
            let username = self.config.username.as_deref().unwrap_or("");
            let credentials =
                base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
            builder = builder.header("Authorization", format!("Basic {credentials}"));
        }

        let response = builder
            .send()
            .await
            .map_err(|e| VeilError::rpc(format!("{method} request failed: {e}")))?;

        let status = response.status();
        if !status.is_success() {
            return Err(VeilError::rpc(format!(
                "{method} returned HTTP {}: {}",
                status.as_u16(),
                status.canonical_reason().unwrap_or("unknown")
            )));
        }

        let body: Value = response
            .json()
            .await
            .map_err(|e| VeilError::rpc(format!("{method} returned invalid JSON: {e}")))?;

        if let Some(error) = body.get("error").filter(|e| !e.is_null()) {
            let code = error.get("code").and_then(Value::as_i64).unwrap_or(0);
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unknown error");
            return Err(VeilError::rpc(format!("{method} failed ({code}): {message}")));
        }

        body.get("result")
            .cloned()
            .ok_or_else(|| VeilError::rpc(format!("{method} response is missing a result")))
    }

    /// Fetch decoy outputs for ring signatures.
    ///
    /// Each input needs `ring_size - 1` decoys.
    pub async fn get_anon_outputs(
        &self,
        input_size: usize,
        ring_size: usize,
    ) -> Result<Vec<AnonOutput>> {
        let result = self
            .send("getanonoutputs", json!([input_size, ring_size]))
            .await?;

        let items = result
            .as_array()
            .ok_or_else(|| VeilError::rpc("getanonoutputs did not return an array"))?;

        let mut outputs = Vec::with_capacity(items.len());

        for item in items {
            let pubkey_hex = item
                .get("pubkey")
                .and_then(Value::as_str)
                .ok_or_else(|| VeilError::rpc("anon output is missing a pubkey"))?;
            let commitment_hex = item
                .get("commitment")
                .and_then(Value::as_str)
                .ok_or_else(|| VeilError::rpc("anon output is missing a commitment"))?;

            // Veil reports the global index as `ringctindex`; older or proxied
            // nodes may use `index` or `global_index`.
            let index = ["ringctindex", "index", "global_index"]
                .iter()
                .find_map(|key| item.get(*key).and_then(Value::as_u64))
                .unwrap_or(0);

            outputs.push(AnonOutput {
                pubkey: hex_to_array(pubkey_hex)?,
                commitment: hex_to_array(commitment_hex)?,
                index,
                txid: item
                    .get("txid")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                vout: item
                    .get("vout")
                    .and_then(Value::as_u64)
                    .and_then(|v| u32::try_from(v).ok()),
            });
        }

        Ok(outputs)
    }

    /// Broadcast a serialized transaction, returning its ID.
    pub async fn send_raw_transaction(&self, tx_hex: &str) -> Result<String> {
        let result = self.send("sendrawtransaction", json!([tx_hex])).await?;
        result
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| VeilError::rpc("sendrawtransaction did not return a txid"))
    }

    /// Fetch current chain state.
    pub async fn get_blockchain_info(&self) -> Result<BlockchainInfo> {
        let result = self.send("getblockchaininfo", json!([])).await?;
        serde_json::from_value(result).map_err(VeilError::from)
    }

    /// Check whether key images have already been spent.
    pub async fn check_key_images(&self, key_images: &[KeyImage]) -> Result<Vec<KeyImageStatus>> {
        let hex_images: Vec<String> = key_images.iter().map(|ki| bytes_to_hex(ki)).collect();

        let result = self
            .send("checkkeyimages", json!([hex_images.clone()]))
            .await?;

        let items = result
            .as_array()
            .ok_or_else(|| VeilError::rpc("checkkeyimages did not return an array"))?;

        Ok(items
            .iter()
            .enumerate()
            .map(|(i, item)| {
                let key_image = hex_images.get(i).cloned().unwrap_or_default();
                let valid = item.get("status").and_then(Value::as_str) != Some("invalid");

                KeyImageStatus {
                    key_image,
                    valid,
                    msg: item.get("msg").and_then(Value::as_str).map(str::to_owned),
                    spent: valid
                        && item
                            .get("spent")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                    spent_in_mempool: valid
                        && item
                            .get("spentinmempool")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                    txid: item.get("txid").and_then(Value::as_str).map(str::to_owned),
                }
            })
            .collect())
    }

    /// Fetch a raw transaction, either as hex or as a decoded object.
    pub async fn get_raw_transaction(&self, txid: &str, verbose: bool) -> Result<Value> {
        self.send("getrawtransaction", json!([txid, verbose])).await
    }

    /// Fetch a block by hash.
    pub async fn get_block(&self, block_hash: &str, verbosity: u8) -> Result<Value> {
        self.send("getblock", json!([block_hash, verbosity])).await
    }

    /// Fetch a block hash by height.
    pub async fn get_block_hash(&self, height: u64) -> Result<String> {
        let result = self.send("getblockhash", json!([height])).await?;
        result
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| VeilError::rpc("getblockhash did not return a hash"))
    }

    /// Check whether the node is reachable.
    pub async fn test_connection(&self) -> bool {
        self.get_blockchain_info().await.is_ok()
    }

    /// Register a light wallet address for watch-only monitoring.
    ///
    /// This sends the scan *private* key to the node, which can then link every
    /// output belonging to the wallet. Use it only with a node you control.
    pub async fn import_lightwallet_address(
        &self,
        scan_key_private: &str,
        spend_key_public: &str,
        from_block: u64,
    ) -> Result<Value> {
        self.send(
            "importlightwalletaddress",
            json!([scan_key_private, spend_key_public, from_block]),
        )
        .await
    }

    /// Fetch watch-only sync status.
    pub async fn get_watch_only_status(
        &self,
        scan_key_private: &str,
        spend_key_public: &str,
    ) -> Result<Value> {
        self.send(
            "getwatchonlystatus",
            json!([scan_key_private, spend_key_public]),
        )
        .await
    }

    /// Fetch a page of watch-only transactions.
    pub async fn get_watch_only_txes(
        &self,
        scan_key_private: &str,
        offset: u64,
    ) -> Result<WatchOnlyTxes> {
        let result = self
            .send("getwatchonlytxes", json!([scan_key_private, offset]))
            .await?;

        Ok(WatchOnlyTxes {
            anon: parse_watch_only_records(result.get("anon")),
            stealth: parse_watch_only_records(result.get("stealth")),
        })
    }
}

/// Parse the record array from a `getwatchonlytxes` response.
///
/// Field names vary across node versions, so several spellings are accepted.
fn parse_watch_only_records(value: Option<&Value>) -> Vec<WatchOnlyRecord> {
    let Some(items) = value.and_then(Value::as_array) else {
        return Vec::new();
    };

    items
        .iter()
        .filter_map(|item| {
            // An entry may be a bare hex string or an object wrapping one.
            if let Some(raw) = item.as_str() {
                return Some(WatchOnlyRecord {
                    raw: raw.to_owned(),
                    ..Default::default()
                });
            }

            let raw = ["raw", "hex"]
                .iter()
                .find_map(|key| item.get(*key).and_then(Value::as_str))?
                .to_owned();

            // The node may report the amount as a number or a string.
            let amount = item.get("amount").and_then(|a| {
                a.as_u64()
                    .or_else(|| a.as_str().and_then(|s| s.parse::<u64>().ok()))
            });

            let blind = item
                .get("blind")
                .and_then(Value::as_str)
                .and_then(|s| hex_to_array::<32>(s).ok());

            let ringct_index = ["ringct_index", "ringctindex"]
                .iter()
                .find_map(|key| item.get(*key).and_then(Value::as_u64));

            Some(WatchOnlyRecord {
                raw,
                amount,
                blind,
                ringct_index,
                dbindex: item.get("dbindex").and_then(Value::as_u64),
            })
        })
        .collect()
}

/// Fetch decoy outputs for a transaction's rings.
pub async fn fetch_decoy_outputs(
    client: &RpcClient,
    ring_size: usize,
    num_inputs: usize,
) -> Result<Vec<AnonOutput>> {
    client.get_anon_outputs(num_inputs, ring_size).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_uses_the_public_endpoint() {
        // Only meaningful when VEIL_NODE_URL is unset in the environment.
        if std::env::var("VEIL_NODE_URL").is_err() {
            assert_eq!(RpcConfig::default().url, DEFAULT_NODE_URL);
        }
    }

    #[test]
    fn client_reports_its_configured_url() {
        let client = RpcClient::from_url("http://localhost:58810").unwrap();
        assert_eq!(client.url(), "http://localhost:58810");
    }

    #[test]
    fn key_image_status_treats_mempool_spends_as_spent() {
        let on_chain = KeyImageStatus {
            key_image: "aa".into(),
            valid: true,
            msg: None,
            spent: true,
            spent_in_mempool: false,
            txid: None,
        };
        let in_mempool = KeyImageStatus {
            spent: false,
            spent_in_mempool: true,
            ..on_chain.clone()
        };
        let unspent = KeyImageStatus {
            spent: false,
            spent_in_mempool: false,
            ..on_chain.clone()
        };

        assert!(on_chain.is_spent());
        assert!(in_mempool.is_spent());
        assert!(!unspent.is_spent());
    }

    #[test]
    fn parses_records_from_objects() {
        let value = serde_json::json!([
            {
                "raw": "abcd",
                "amount": 1000,
                "blind": "11".repeat(32),
                "ringct_index": 7,
                "dbindex": 42
            },
            {
                "hex": "ef01",
                "amount": "2000"
            }
        ]);

        let records = parse_watch_only_records(Some(&value));

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].raw, "abcd");
        assert_eq!(records[0].amount, Some(1000));
        assert_eq!(records[0].blind, Some([0x11u8; 32]));
        assert_eq!(records[0].ringct_index, Some(7));
        assert_eq!(records[0].dbindex, Some(42));

        // An amount reported as a string still parses.
        assert_eq!(records[1].raw, "ef01");
        assert_eq!(records[1].amount, Some(2000));
    }

    #[test]
    fn parses_records_given_as_bare_strings() {
        let value = serde_json::json!(["aabb", "ccdd"]);
        let records = parse_watch_only_records(Some(&value));

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].raw, "aabb");
        assert_eq!(records[1].amount, None);
    }

    #[test]
    fn missing_or_malformed_record_arrays_yield_nothing() {
        assert!(parse_watch_only_records(None).is_empty());
        assert!(parse_watch_only_records(Some(&serde_json::json!(null))).is_empty());
        assert!(parse_watch_only_records(Some(&serde_json::json!({}))).is_empty());

        // An object with no usable raw field is skipped.
        let value = serde_json::json!([{ "amount": 1 }]);
        assert!(parse_watch_only_records(Some(&value)).is_empty());
    }
}
