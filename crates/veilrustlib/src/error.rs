//! Error types for the Veil library.
//!
//! Ports the error classes from `src/types.ts` (`TransactionBuilderError`,
//! `InsufficientFundsError`, `InvalidAddressError`, `RpcError`) to a single
//! idiomatic Rust error enum.

use thiserror::Error;

/// Result alias used throughout this crate.
pub type Result<T> = std::result::Result<T, VeilError>;

/// Errors produced by transaction building, wallet, and RPC operations.
#[derive(Debug, Error)]
pub enum VeilError {
    /// A cryptographic primitive from `veil-crypto` failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] veil_crypto::VeilCryptoError),

    /// A hex string could not be decoded.
    #[error("invalid hex: {0}")]
    Hex(#[from] hex::FromHexError),

    /// Not enough funds to cover the requested amount plus fees.
    #[error("insufficient funds: required {required}, available {available}")]
    InsufficientFunds {
        /// Amount needed, in satoshis (outputs + fee).
        required: u64,
        /// Amount actually available, in satoshis.
        available: u64,
    },

    /// A stealth address was malformed or failed validation.
    #[error("invalid stealth address: {0}")]
    InvalidAddress(String),

    /// A value did not satisfy a documented precondition.
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// Binary data was truncated or otherwise unparseable.
    #[error("deserialization failed: {0}")]
    Deserialization(String),

    /// A ring signature could not be produced or did not verify.
    #[error("mlsag error: {0}")]
    Mlsag(String),

    /// A JSON-RPC call failed.
    #[error("rpc error: {0}")]
    Rpc(String),

    /// JSON encoding or decoding failed.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// The balance cache could not be read or written.
    ///
    /// The cache is derived data, so this is recoverable: the node remains the
    /// source of truth and callers can fall back to a full scan.
    #[error("cache error: {0}")]
    Cache(String),
}

impl VeilError {
    /// Build an [`VeilError::InvalidInput`] from anything string-like.
    pub fn invalid_input(msg: impl Into<String>) -> Self {
        Self::InvalidInput(msg.into())
    }

    /// Build a [`VeilError::Deserialization`] from anything string-like.
    pub fn deserialization(msg: impl Into<String>) -> Self {
        Self::Deserialization(msg.into())
    }

    /// Build a [`VeilError::Rpc`] from anything string-like.
    pub fn rpc(msg: impl Into<String>) -> Self {
        Self::Rpc(msg.into())
    }

    /// Build a [`VeilError::Cache`] from anything string-like.
    pub fn cache(msg: impl Into<String>) -> Self {
        Self::Cache(msg.into())
    }
}
