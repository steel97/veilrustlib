use crate::client::ClientRegistry;
use crate::error::{map_veil_error_code, ERROR_CODE_INTERNAL, ERROR_CODE_NOT_FOUND};
use crate::protocol::*;
use std::collections::HashMap;
use std::sync::Arc;
use veilrustlib::{
    balance::BalanceScanner, classify_address, derive_stealth_keys, rpc::RpcConfig,
    AccountType, RecoveryPolicy, RpcClient, TransactionBuilder, TransactionBuilderConfig, Recipient,
};
use veilrustlib::cache::{BalanceCache, RedbStore, wallet_id};

pub async fn handle_request(json_request: &str) -> String {
    let request = match serde_json::from_str::<Request>(json_request) {
        Ok(req) => req,
        Err(e) => {
            let response = Response::error(None, ERROR_CODE_INTERNAL, format!("Invalid JSON: {}", e));
            return serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string());
        }
    };

    let extra = request.extra();
    let response = match request {
        Request::CreateClient {
            rpc_url,
            rpc_username,
            rpc_password,
            cache_path,
            timeout_ms,
            ..
        } => handle_create_client(rpc_url, rpc_username, rpc_password, cache_path, timeout_ms).await,
        Request::CloseClient { client_id, .. } => handle_close_client(client_id),
        Request::DeriveStealthKeys {
            client_id,
            mnemonic,
            passphrase,
            account_id,
            account_type,
            index,
            ..
        } => handle_derive_stealth_keys(
            client_id,
            mnemonic,
            passphrase,
            account_id,
            account_type,
            index,
        ),
        Request::GetBalance {
            client_id,
            recovery_policy,
            ..
        } => handle_get_balance(client_id, recovery_policy).await,
        Request::ListUtxos {
            client_id,
            min_amount,
            only_spendable,
            ..
        } => handle_list_utxos(client_id, min_amount, only_spendable).await,
        Request::GetTransactionHistory { client_id, .. } => {
            handle_get_transaction_history(client_id).await
        }
        Request::CreateTransaction {
            client_id,
            recipients,
            ring_size,
            fee_per_kb,
            ..
        } => handle_create_transaction(client_id, recipients, ring_size, fee_per_kb).await,
        Request::SendTransaction { client_id, tx_hex, .. } => {
            handle_send_transaction(client_id, tx_hex).await
        }
        Request::BuildAndSendTransaction {
            client_id,
            recipients,
            ring_size,
            fee_per_kb,
            ..
        } => handle_build_and_send_transaction(client_id, recipients, ring_size, fee_per_kb).await,
        Request::ClearCache { client_id, .. } => handle_clear_cache(client_id).await,
        Request::ClearSent { client_id, .. } => handle_clear_sent(client_id).await,
        Request::ValidateAddress { address, .. } => handle_validate_address(address),
        Request::GetBlockchainInfo { client_id, .. } => handle_get_blockchain_info(client_id).await,
    };

    let mut response = response;
    if let Response::Error { extra: ref mut e, .. } = response {
        *e = extra;
    } else {
        // Set extra on success responses
        match &mut response {
            Response::Client { extra: e, .. }
            | Response::Ok { extra: e }
            | Response::StealthKeys { extra: e, .. }
            | Response::Balance { extra: e, .. }
            | Response::TransactionHistory { extra: e, .. }
            | Response::TransactionCreated { extra: e, .. }
            | Response::TransactionSent { extra: e, .. }
            | Response::AddressValidation { extra: e, .. }
            | Response::BlockchainInfo { extra: e, .. } => {
                *e = extra;
            }
            _ => {}
        }
    }

    serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string())
}

async fn handle_create_client(
    rpc_url: Option<String>,
    rpc_username: Option<String>,
    rpc_password: Option<String>,
    cache_path: Option<String>,
    timeout_ms: Option<u64>,
) -> Response {
    let url = rpc_url.unwrap_or_else(|| "https://explorer-api.veil-project.com".to_string());
    
    let config = RpcConfig {
        url: url.clone(),
        username: rpc_username,
        password: rpc_password,
        timeout: std::time::Duration::from_millis(timeout_ms.unwrap_or(30000)),
    };

    let client = match RpcClient::new(config) {
        Ok(c) => c,
        Err(e) => {
            return Response::error(
                None,
                ERROR_CODE_INTERNAL,
                format!("Failed to create RPC client: {}", e),
            );
        }
    };

    let cache_store = if let Some(path) = cache_path {
        match RedbStore::open_or_recreate(&path) {
            Ok((store, _created)) => Some(store),
            Err(e) => {
                return Response::error(
                    None,
                    ERROR_CODE_INTERNAL,
                    format!("Failed to open cache: {}", e),
                );
            }
        }
    } else {
        None
    };

    let client_id = ClientRegistry::create_client(client, cache_store);
    
    Response::Client {
        extra: None,
        client_id,
        rpc_url: url,
    }
}

fn handle_close_client(client_id: u64) -> Response {
    if ClientRegistry::close_client(client_id) {
        Response::Ok { extra: None }
    } else {
        Response::error(None, ERROR_CODE_NOT_FOUND, "Client not found".to_string())
    }
}

fn handle_derive_stealth_keys(
    client_id: u64,
    mnemonic: String,
    passphrase: Option<String>,
    account_id: Option<u32>,
    account_type: Option<String>,
    index: Option<u32>,
) -> Response {
    let account_type_enum = match account_type.as_deref() {
        Some("Stealth") | None => AccountType::Stealth,
        Some("Default") => AccountType::Default,
        Some("Change") => AccountType::Change,
        Some(other) => {
            return Response::error(
                None,
                ERROR_CODE_INTERNAL,
                format!("Invalid account type: {}", other),
            );
        }
    };

    let keys = match derive_stealth_keys(
        &mnemonic,
        &passphrase.unwrap_or_default(),
        account_id.unwrap_or(0),
        account_type_enum,
        index.unwrap_or(1),
    ) {
        Ok(k) => k,
        Err(e) => {
            return Response::error(None, map_veil_error_code(&e), e.to_string());
        }
    };

    let address = match keys.stealth_address() {
        Ok(addr) => addr,
        Err(e) => {
            return Response::error(None, map_veil_error_code(&e), e.to_string());
        }
    };
    
    let scan_pubkey = hex::encode(&keys.scan_pubkey);
    let spend_pubkey = hex::encode(&keys.spend_pubkey);
    let account_type_str = match account_type_enum {
        AccountType::Stealth => "Stealth".to_string(),
        AccountType::Default => "Default".to_string(),
        AccountType::Change => "Change".to_string(),
    };

    // Store keys in session
    let stored = ClientRegistry::with_client_mut(client_id, |session| {
        session.stealth_keys = Some(keys);
    });

    if stored.is_none() {
        return Response::error(None, ERROR_CODE_NOT_FOUND, "Client not found".to_string());
    }

    Response::StealthKeys {
        extra: None,
        client_id,
        address,
        scan_pubkey,
        spend_pubkey,
        account_type: account_type_str,
        index: index.unwrap_or(1),
    }
}

async fn handle_get_balance(client_id: u64, recovery_policy: Option<String>) -> Response {
    // Clone what we need from the session
    let session_data = ClientRegistry::with_client(client_id, |session| {
        (session.stealth_keys.clone(), Arc::clone(&session.rpc_client), session.cache_store.is_some())
    });

    let (keys_opt, rpc_client, _has_cache) = match session_data {
        Some(data) => data,
        None => return Response::error(None, ERROR_CODE_NOT_FOUND, "Client not found".to_string()),
    };

    let keys = match keys_opt {
        Some(k) => k,
        None => {
            return Response::error(
                None,
                ERROR_CODE_INTERNAL,
                "Stealth keys not derived. Call deriveStealthKeys first.".to_string(),
            );
        }
    };

    let recovery = match recovery_policy.as_deref() {
        Some("FullRescan") => RecoveryPolicy::FullRescan,
        Some("CacheOnly") => RecoveryPolicy::CacheOnly,
        Some(s) if s.starts_with("Rewind(") => {
            let num_str = s.trim_start_matches("Rewind(").trim_end_matches(')');
            let num = num_str.parse::<u64>().unwrap_or(50);
            RecoveryPolicy::Rewind(num)
        }
        _ => RecoveryPolicy::Rewind(50),
    };

    // Now work with the scanner inside the client registry scope
    let balance_result = ClientRegistry::with_client(client_id, |session| {
        let mut scanner = BalanceScanner::new(rpc_client.as_ref()).with_recovery(recovery);
        
        if let Some(cache) = &session.cache_store {
            scanner = scanner.with_cache(cache);
        }

        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                scanner.balance(&keys.spend_secret, &keys.scan_secret).await
            })
        })
    });

    let balance_result = match balance_result {
        Some(Ok(b)) => b,
        Some(Err(e)) => {
            return Response::error(None, map_veil_error_code(&e), e.to_string());
        }
        None => return Response::error(None, ERROR_CODE_NOT_FOUND, "Client not found".to_string()),
    };

    let total_balance: u64 = balance_result.balance.utxos.iter().map(|u| u.amount).sum();

    let utxos: Vec<UtxoResponse> = balance_result
        .balance
        .utxos
        .iter()
        .map(|u| UtxoResponse {
            txid: u.txid.clone(),
            vout: u.vout,
            amount: u.amount,
            ringct_index: u.ringct_index.unwrap_or(0),
            spendable: u.spendable,
            direction: format!("{:?}", u.direction),
        })
        .collect();

    // Build the transactions list from the cache's seen_txids table, which
    // accumulates every txid encountered during scanning — including those
    // whose outputs have since been spent.  Fall back to the current UTXOs
    // when no cache is configured (no cache → no history beyond current UTXOs).
    let transactions: Vec<TransactionResponse> =
        ClientRegistry::with_client(client_id, |session| {
            if let Some(store) = &session.cache_store {
                let wid = wallet_id(&keys.scan_secret);
                if let veilrustlib::CacheLoad::Loaded(data) =
                    BalanceCache::new(store as &dyn veilrustlib::CacheStore).load(&wid)
                {
                    return data
                        .seen_txids
                        .iter()
                        .map(|(txid, direction)| TransactionResponse {
                            txid: hex::encode(txid),
                            timestamp: 0,
                            direction: format!("{:?}", direction),
                        })
                        .collect();
                }
            }
            // No cache: fall back to current UTXOs only
            let mut tx_map: HashMap<String, String> = HashMap::new();
            for u in &balance_result.balance.utxos {
                tx_map
                    .entry(u.txid.clone())
                    .or_insert_with(|| format!("{:?}", u.direction));
            }
            tx_map
                .into_iter()
                .map(|(txid, direction)| TransactionResponse {
                    txid,
                    timestamp: 0,
                    direction,
                })
                .collect()
        })
        .unwrap_or_default();

    let cache_info = CacheInfoResponse {
        loaded: balance_result.cache.loaded,
        revalidated: balance_result.cache.revalidated,
        dropped: balance_result.cache.dropped,
        up_to_date: balance_result.cache.up_to_date,
    };

    Response::Balance {
        extra: None,
        client_id,
        total_balance,
        utxos,
        transactions,
        cache_info,
    }
}

async fn handle_list_utxos(
    client_id: u64,
    min_amount: Option<u64>,
    only_spendable: Option<bool>,
) -> Response {
    let response = handle_get_balance(client_id, None).await;
    
    if let Response::Balance {
        extra,
        client_id,
        mut utxos,
        transactions,
        cache_info,
        ..
    } = response
    {
        if let Some(min) = min_amount {
            utxos.retain(|u| u.amount >= min);
        }
        if only_spendable.unwrap_or(false) {
            utxos.retain(|u| u.spendable);
        }
        
        let total_balance = utxos.iter().map(|u| u.amount).sum();
        
        Response::Balance {
            extra,
            client_id,
            total_balance,
            utxos,
            transactions,
            cache_info,
        }
    } else {
        response
    }
}

async fn handle_get_transaction_history(client_id: u64) -> Response {
    let response = handle_get_balance(client_id, None).await;

    match response {
        Response::Balance {
            transactions,
            ..
        } => Response::TransactionHistory {
            extra: None,
            client_id,
            transactions,
        },
        other => other,
    }
}

async fn handle_create_transaction(
    client_id: u64,
    recipients: Vec<RecipientRequest>,
    ring_size: Option<u32>,
    fee_per_kb: Option<u64>,
) -> Response {
    // Clone session data
    let session_data = ClientRegistry::with_client(client_id, |session| {
        (session.stealth_keys.clone(), Arc::clone(&session.rpc_client))
    });

    let (keys_opt, rpc_client) = match session_data {
        Some(data) => data,
        None => return Response::error(None, ERROR_CODE_NOT_FOUND, "Client not found".to_string()),
    };

    let keys = match keys_opt {
        Some(k) => k,
        None => {
            return Response::error(
                None,
                ERROR_CODE_INTERNAL,
                "Stealth keys not derived".to_string(),
            );
        }
    };

    // Get balance
    let balance_result = ClientRegistry::with_client(client_id, |session| {
        let mut scanner = BalanceScanner::new(rpc_client.as_ref());
        if let Some(cache) = &session.cache_store {
            scanner = scanner.with_cache(cache);
        }

        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                scanner.balance(&keys.spend_secret, &keys.scan_secret).await
            })
        })
    });

    let balance_result = match balance_result {
        Some(Ok(b)) => b,
        Some(Err(e)) => {
            return Response::error(None, map_veil_error_code(&e), e.to_string());
        }
        None => return Response::error(None, ERROR_CODE_NOT_FOUND, "Client not found".to_string()),
    };

    // Convert recipients
    let veil_recipients: Vec<Recipient> = recipients
        .iter()
        .map(|r| Recipient::new(r.address.clone(), r.amount))
        .collect();

    // Fetch decoys
    let ring = ring_size.unwrap_or(11) as usize;
    let decoy_count = ring * veil_recipients.len();
    let decoys = match veilrustlib::rpc::fetch_decoy_outputs(rpc_client.as_ref(), decoy_count, 3).await {
        Ok(d) => d,
        Err(e) => {
            return Response::error(None, map_veil_error_code(&e), e.to_string());
        }
    };

    // Build transaction
    let config = TransactionBuilderConfig {
        ring_size: ring,
        fee_per_kb: fee_per_kb.unwrap_or(100000),
    };

    let builder = match TransactionBuilder::new(config) {
        Ok(b) => b,
        Err(e) => {
            return Response::error(None, map_veil_error_code(&e), e.to_string());
        }
    };

    let tx_result = match builder.build_transaction(
        &keys.spend_secret,
        &keys.scan_secret,
        &veil_recipients,
        &balance_result.balance.utxos,
        &decoys,
    ) {
        Ok(r) => r,
        Err(e) => {
            return Response::error(None, map_veil_error_code(&e), e.to_string());
        }
    };

    Response::TransactionCreated {
        extra: None,
        client_id,
        tx_hex: tx_result.tx_hex,
        txid: tx_result.txid,
        fee: tx_result.fee,
        change: tx_result.change,
        size: tx_result.size,
    }
}

async fn handle_send_transaction(client_id: u64, tx_hex: String) -> Response {
    let session_data = ClientRegistry::with_client(client_id, |session| {
        (session.stealth_keys.clone(), Arc::clone(&session.rpc_client))
    });

    let (keys_opt, rpc_client) = match session_data {
        Some(data) => data,
        None => return Response::error(None, ERROR_CODE_NOT_FOUND, "Client not found".to_string()),
    };

    let keys = match keys_opt {
        Some(k) => k,
        None => {
            return Response::error(
                None,
                ERROR_CODE_INTERNAL,
                "Stealth keys not derived".to_string(),
            );
        }
    };

    let txid = ClientRegistry::with_client(client_id, |session| {
        let mut scanner = BalanceScanner::new(rpc_client.as_ref());
        if let Some(cache) = &session.cache_store {
            scanner = scanner.with_cache(cache);
        }

        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                scanner.broadcast_and_record(&keys.scan_secret, &tx_hex).await
            })
        })
    });

    let txid = match txid {
        Some(Ok(id)) => id,
        Some(Err(e)) => {
            return Response::error(None, map_veil_error_code(&e), e.to_string());
        }
        None => return Response::error(None, ERROR_CODE_NOT_FOUND, "Client not found".to_string()),
    };

    Response::TransactionSent {
        extra: None,
        client_id,
        txid,
    }
}

async fn handle_build_and_send_transaction(
    client_id: u64,
    recipients: Vec<RecipientRequest>,
    ring_size: Option<u32>,
    fee_per_kb: Option<u64>,
) -> Response {
    let create_response = handle_create_transaction(client_id, recipients, ring_size, fee_per_kb).await;
    
    if let Response::TransactionCreated { tx_hex, .. } = create_response {
        handle_send_transaction(client_id, tx_hex).await
    } else {
        create_response
    }
}

async fn handle_clear_cache(client_id: u64) -> Response {
    let keys_opt = ClientRegistry::with_client(client_id, |session| {
        session.stealth_keys.clone()
    });

    let keys = match keys_opt.flatten() {
        Some(k) => k,
        None => {
            return Response::error(
                None,
                ERROR_CODE_INTERNAL,
                "Stealth keys not derived".to_string(),
            );
        }
    };

    let result = ClientRegistry::with_client(client_id, |session| {
        let mut scanner = BalanceScanner::new(&session.rpc_client);
        if let Some(cache) = &session.cache_store {
            scanner = scanner.with_cache(cache);
        }
        scanner.clear_cache(&keys.scan_secret)
    });

    match result {
        Some(Ok(_)) => Response::Ok { extra: None },
        Some(Err(e)) => Response::error(None, map_veil_error_code(&e), e.to_string()),
        None => Response::error(None, ERROR_CODE_NOT_FOUND, "Client not found".to_string()),
    }
}

async fn handle_clear_sent(client_id: u64) -> Response {
    let keys_opt = ClientRegistry::with_client(client_id, |session| {
        session.stealth_keys.clone()
    });

    let keys = match keys_opt.flatten() {
        Some(k) => k,
        None => {
            return Response::error(
                None,
                ERROR_CODE_INTERNAL,
                "Stealth keys not derived".to_string(),
            );
        }
    };

    let result = ClientRegistry::with_client(client_id, |session| {
        let mut scanner = BalanceScanner::new(&session.rpc_client);
        if let Some(cache) = &session.cache_store {
            scanner = scanner.with_cache(cache);
        }
        scanner.clear_sent(&keys.scan_secret)
    });

    match result {
        Some(Ok(_)) => Response::Ok { extra: None },
        Some(Err(e)) => Response::error(None, map_veil_error_code(&e), e.to_string()),
        None => Response::error(None, ERROR_CODE_NOT_FOUND, "Client not found".to_string()),
    }
}

fn handle_validate_address(address: String) -> Response {
    match classify_address(&address) {
        Ok(addr_type) => Response::AddressValidation {
            extra: None,
            valid: true,
            address_type: Some(format!("{:?}", addr_type)),
        },
        Err(_) => Response::AddressValidation {
            extra: None,
            valid: false,
            address_type: None,
        },
    }
}

async fn handle_get_blockchain_info(client_id: u64) -> Response {
    let rpc_client = ClientRegistry::with_client(client_id, |session| {
        Arc::clone(&session.rpc_client)
    });

    let rpc_client = match rpc_client {
        Some(client) => client,
        None => return Response::error(None, ERROR_CODE_NOT_FOUND, "Client not found".to_string()),
    };

    match rpc_client.get_blockchain_info().await {
        Ok(info) => Response::BlockchainInfo {
            extra: None,
            client_id,
            blocks: info.blocks,
            chain: info.chain,
            bestblockhash: info.bestblockhash,
        },
        Err(e) => Response::error(None, map_veil_error_code(&e), e.to_string()),
    }
}
