//! # veilrustlib
//!
//! Rust library for the Veil blockchain: RingCT transaction building, stealth
//! address wallets, output scanning, and node RPC.
//!
//! This is a port of the `@blondfrogs/veil-wasm-wrapper` TypeScript library.
//! Cryptography comes from the [`veil_crypto`] crate, which replaces the
//! `@blondfrogs/secp256k1-wasm` module the TypeScript version loaded at runtime.
//! There is no initialization step: where the original required `await
//! initWasm()`, the equivalent Rust calls work immediately.
//!
//! ## Layout
//!
//! - [`types`] — protocol types: outputs, inputs, transactions, UTXOs
//! - [`crypto`] — commitments, range proofs, MLSAG, ECDH, key images
//! - [`stealth`] — stealth addresses, wallet creation, key derivation
//! - [`serialization`] — the Veil transaction wire format
//! - [`transaction_builder`] — RingCT transaction construction
//! - [`scanner`] — detecting and valuing owned outputs
//! - [`watch_only_tx`] — parsing `getwatchonlytxes` records
//! - [`ct_utils`] — spending CT outputs with ECDSA
//! - [`rpc`] and [`balance`] — node communication (requires the `rpc` feature)
//!
//! ## Creating a wallet
//!
//! ```
//! use veilrustlib::stealth::create_wallet;
//!
//! let wallet = create_wallet()?;
//! println!("address: {}", wallet.stealth_address);
//!
//! // Back up both secrets; they are the only way to restore the wallet.
//! let spend_backup = wallet.spend_secret_hex();
//! let scan_backup = wallet.scan_secret_hex();
//! # let _ = (spend_backup, scan_backup);
//! # Ok::<(), veilrustlib::VeilError>(())
//! ```
//!
//! ## Validating an address before sending
//!
//! ```
//! use veilrustlib::stealth::{create_wallet, is_valid_address};
//!
//! let wallet = create_wallet()?;
//! assert!(is_valid_address(&wallet.stealth_address));
//! assert!(!is_valid_address("sv1notarealaddress"));
//! # Ok::<(), veilrustlib::VeilError>(())
//! ```
//!
//! ## Building a transaction
//!
//! Decoys must be fetched from a node first; see
//! [`rpc::fetch_decoy_outputs`].
//!
//! ```no_run
//! use veilrustlib::transaction_builder::{Recipient, TransactionBuilder};
//! # use veilrustlib::types::{AnonOutput, Utxo};
//! # fn example(utxos: &[Utxo], decoys: &[AnonOutput]) -> Result<(), veilrustlib::VeilError> {
//! let wallet = veilrustlib::stealth::create_wallet()?;
//! let builder = TransactionBuilder::default();
//!
//! let result = builder.build_transaction(
//!     &wallet.spend_secret,
//!     &wallet.scan_secret,
//!     &[Recipient::new("sv1...", 100_000_000)],
//!     utxos,
//!     decoys,
//! )?;
//!
//! println!("txid: {}, fee: {}", result.txid, result.fee);
//! # Ok(())
//! # }
//! ```
//!
//! ## Security notes
//!
//! - A wallet's spend and scan secrets grant full control of its funds. The
//!   `*_hex` accessors exist for backup; avoid logging their output.
//! - `importlightwalletaddress` and `getwatchonlytxes` send the scan *private*
//!   key to the node, which can then link every output belonging to the wallet.
//!   Use them only against a node you control.
//! - `veil-crypto` has not been independently audited, and its own
//!   documentation recommends testnet use pending review.

#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod buffer_reader;
pub mod crypto;
pub mod ct_utils;
pub mod error;
pub mod range_proof_params;
pub mod scanner;
pub mod serialization;
pub mod stealth;
pub mod transaction_builder;
pub mod types;
pub mod utils;
pub mod watch_only_tx;

#[cfg(feature = "rpc")]
pub mod balance;
#[cfg(feature = "rpc")]
pub mod rpc;

// Re-export the most commonly used items.
pub use error::{Result, VeilError};
pub use types::{
    AnonOutput, Balance, Blind, Commitment, DataOutputType, Hash, KeyImage, OutPoint, OutputType,
    PublicKey, RangeProof, SecretKey, Transaction, TransactionType, TxInput, TxInputCt, TxOutput,
    Utxo, UtxoCt, ANON_MARKER, MAX_MONEY, SATOSHIS_PER_VEIL,
};

pub use buffer_reader::BufferReader;
pub use stealth::{
    create_wallet, decode_stealth_address, generate_ephemeral_keys, generate_stealth_address,
    is_valid_address, restore_wallet, validate_address, VeilWallet,
};
pub use transaction_builder::{
    BuildTransactionResult, Recipient, TransactionBuilder, TransactionBuilderConfig, WalletHealth,
    DEFAULT_RING_SIZE, MAX_ANON_INPUTS, MAX_RING_SIZE, MIN_RING_SIZE,
};
pub use utils::{
    bytes_to_hex, format_amount, hex_to_bytes, satoshis_to_veil, veil_to_satoshis,
};

#[cfg(feature = "rpc")]
pub use rpc::{RpcClient, RpcConfig};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_wallet_produces_a_usable_address() {
        let wallet = create_wallet().unwrap();

        assert!(wallet.stealth_address.starts_with("sv1"));
        assert!(is_valid_address(&wallet.stealth_address));

        let decoded = decode_stealth_address(&wallet.stealth_address).unwrap();
        assert_eq!(decoded.scan_pubkey, wallet.scan_pubkey);
        assert_eq!(decoded.spend_pubkey, wallet.spend_pubkey);
    }

    #[test]
    fn a_wallet_restores_to_the_same_address() {
        let original = create_wallet().unwrap();
        let restored = restore_wallet(&original.spend_secret, &original.scan_secret).unwrap();

        assert_eq!(original.stealth_address, restored.stealth_address);
    }

    #[test]
    fn amount_conversion_round_trips() {
        assert_eq!(veil_to_satoshis(1.5), 150_000_000);
        assert_eq!(satoshis_to_veil(150_000_000), 1.5);
        assert_eq!(format_amount(150_000_000, 2), "1.50 VEIL");
    }
}
