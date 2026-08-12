use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
#[serde(tag = "@type")]
pub enum Request {
    #[serde(rename = "createClient")]
    CreateClient {
        #[serde(rename = "@extra")]
        extra: Option<String>,
        rpc_url: Option<String>,
        rpc_username: Option<String>,
        rpc_password: Option<String>,
        cache_path: Option<String>,
        timeout_ms: Option<u64>,
    },
    #[serde(rename = "closeClient")]
    CloseClient {
        #[serde(rename = "@extra")]
        extra: Option<String>,
        client_id: u64,
    },
    #[serde(rename = "deriveStealthKeys")]
    DeriveStealthKeys {
        #[serde(rename = "@extra")]
        extra: Option<String>,
        client_id: u64,
        mnemonic: String,
        passphrase: Option<String>,
        account_id: Option<u32>,
        account_type: Option<String>,
        index: Option<u32>,
    },
    #[serde(rename = "getBalance")]
    GetBalance {
        #[serde(rename = "@extra")]
        extra: Option<String>,
        client_id: u64,
        recovery_policy: Option<String>,
    },
    #[serde(rename = "listUtxos")]
    ListUtxos {
        #[serde(rename = "@extra")]
        extra: Option<String>,
        client_id: u64,
        min_amount: Option<u64>,
        only_spendable: Option<bool>,
    },
    #[serde(rename = "getTransactionHistory")]
    GetTransactionHistory {
        #[serde(rename = "@extra")]
        extra: Option<String>,
        client_id: u64,
    },
    #[serde(rename = "createTransaction")]
    CreateTransaction {
        #[serde(rename = "@extra")]
        extra: Option<String>,
        client_id: u64,
        recipients: Vec<RecipientRequest>,
        ring_size: Option<u32>,
        fee_per_kb: Option<u64>,
    },
    #[serde(rename = "sendTransaction")]
    SendTransaction {
        #[serde(rename = "@extra")]
        extra: Option<String>,
        client_id: u64,
        tx_hex: String,
    },
    #[serde(rename = "buildAndSendTransaction")]
    BuildAndSendTransaction {
        #[serde(rename = "@extra")]
        extra: Option<String>,
        client_id: u64,
        recipients: Vec<RecipientRequest>,
        ring_size: Option<u32>,
        fee_per_kb: Option<u64>,
    },
    #[serde(rename = "clearCache")]
    ClearCache {
        #[serde(rename = "@extra")]
        extra: Option<String>,
        client_id: u64,
    },
    #[serde(rename = "clearSent")]
    ClearSent {
        #[serde(rename = "@extra")]
        extra: Option<String>,
        client_id: u64,
    },
    #[serde(rename = "validateAddress")]
    ValidateAddress {
        #[serde(rename = "@extra")]
        extra: Option<String>,
        address: String,
    },
    #[serde(rename = "getBlockchainInfo")]
    GetBlockchainInfo {
        #[serde(rename = "@extra")]
        extra: Option<String>,
        client_id: u64,
    },
}

#[derive(Debug, Deserialize)]
pub struct RecipientRequest {
    pub address: String,
    pub amount: u64,
}

#[derive(Debug, Serialize)]
#[serde(tag = "@type")]
pub enum Response {
    #[serde(rename = "client")]
    Client {
        #[serde(rename = "@extra", skip_serializing_if = "Option::is_none")]
        extra: Option<String>,
        client_id: u64,
        rpc_url: String,
    },
    #[serde(rename = "ok")]
    Ok {
        #[serde(rename = "@extra", skip_serializing_if = "Option::is_none")]
        extra: Option<String>,
    },
    #[serde(rename = "stealthKeys")]
    StealthKeys {
        #[serde(rename = "@extra", skip_serializing_if = "Option::is_none")]
        extra: Option<String>,
        client_id: u64,
        address: String,
        scan_pubkey: String,
        spend_pubkey: String,
        account_type: String,
        index: u32,
    },
    #[serde(rename = "balance")]
    Balance {
        #[serde(rename = "@extra", skip_serializing_if = "Option::is_none")]
        extra: Option<String>,
        client_id: u64,
        total_balance: u64,
        utxos: Vec<UtxoResponse>,
        transactions: Vec<TransactionResponse>,
        cache_info: CacheInfoResponse,
    },
    #[serde(rename = "transactionHistory")]
    TransactionHistory {
        #[serde(rename = "@extra", skip_serializing_if = "Option::is_none")]
        extra: Option<String>,
        client_id: u64,
        transactions: Vec<TransactionResponse>,
    },
    #[serde(rename = "transactionCreated")]
    TransactionCreated {
        #[serde(rename = "@extra", skip_serializing_if = "Option::is_none")]
        extra: Option<String>,
        client_id: u64,
        tx_hex: String,
        txid: String,
        fee: u64,
        change: u64,
        size: usize,
    },
    #[serde(rename = "transactionSent")]
    TransactionSent {
        #[serde(rename = "@extra", skip_serializing_if = "Option::is_none")]
        extra: Option<String>,
        client_id: u64,
        txid: String,
    },
    #[serde(rename = "addressValidation")]
    AddressValidation {
        #[serde(rename = "@extra", skip_serializing_if = "Option::is_none")]
        extra: Option<String>,
        valid: bool,
        address_type: Option<String>,
    },
    #[serde(rename = "blockchainInfo")]
    BlockchainInfo {
        #[serde(rename = "@extra", skip_serializing_if = "Option::is_none")]
        extra: Option<String>,
        client_id: u64,
        blocks: u64,
        chain: String,
        bestblockhash: String,
    },
    #[serde(rename = "error")]
    Error {
        #[serde(rename = "@extra", skip_serializing_if = "Option::is_none")]
        extra: Option<String>,
        code: i32,
        message: String,
    },
}

#[derive(Debug, Serialize)]
pub struct UtxoResponse {
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
    pub ringct_index: u64,
    pub spendable: bool,
    pub direction: String,
}

#[derive(Debug, Serialize)]
pub struct CacheInfoResponse {
    pub loaded: usize,
    pub revalidated: usize,
    pub dropped: usize,
    pub up_to_date: bool,
}

#[derive(Debug, Serialize)]
pub struct TransactionResponse {
    pub txid: String,
    pub timestamp: u64,
    pub direction: String,
}

impl Request {
    pub fn extra(&self) -> Option<String> {
        match self {
            Request::CreateClient { extra, .. } => extra.clone(),
            Request::CloseClient { extra, .. } => extra.clone(),
            Request::DeriveStealthKeys { extra, .. } => extra.clone(),
            Request::GetBalance { extra, .. } => extra.clone(),
            Request::ListUtxos { extra, .. } => extra.clone(),
            Request::GetTransactionHistory { extra, .. } => extra.clone(),
            Request::CreateTransaction { extra, .. } => extra.clone(),
            Request::SendTransaction { extra, .. } => extra.clone(),
            Request::BuildAndSendTransaction { extra, .. } => extra.clone(),
            Request::ClearCache { extra, .. } => extra.clone(),
            Request::ClearSent { extra, .. } => extra.clone(),
            Request::ValidateAddress { extra, .. } => extra.clone(),
            Request::GetBlockchainInfo { extra, .. } => extra.clone(),
        }
    }
}

impl Response {
    pub fn error(extra: Option<String>, code: i32, message: String) -> Self {
        Response::Error {
            extra,
            code,
            message,
        }
    }
}
