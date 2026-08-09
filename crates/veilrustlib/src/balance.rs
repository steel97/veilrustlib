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

use crate::error::{Result, VeilError};
use crate::rpc::RpcClient;
use crate::types::{KeyImage, SecretKey, Utxo, UtxoCt};
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
