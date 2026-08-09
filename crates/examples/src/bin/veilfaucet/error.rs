//! Error type for the faucet.
//!
//! The Dart bot caught exceptions broadly and printed them. A single typed error
//! is used here instead, so the payout loop can decide what is worth retrying
//! and what should stop the process.

use std::fmt;

/// Anything that can go wrong while running the faucet.
#[derive(Debug)]
pub enum FaucetError {
    /// The environment is missing or malformed.
    ///
    /// Always fatal: a misconfigured faucet cannot be fixed by retrying.
    Config(String),
    /// The queue database could not be opened, read, or written.
    Database(String),
    /// A Veil library or node operation failed.
    Veil(veilrustlib::VeilError),
    /// Discord rejected a request, or the gateway failed.
    Discord(String),
}

impl FaucetError {
    /// Build a [`FaucetError::Config`].
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    /// Build a [`FaucetError::Database`].
    pub fn database(message: impl Into<String>) -> Self {
        Self::Database(message.into())
    }

    /// Whether the faucet should stop rather than retry.
    ///
    /// Configuration problems are permanent. Everything else may be transient,
    /// such as a node restart or a Discord outage, so the payout loop keeps
    /// going and tries again on the next cycle.
    pub fn is_fatal(&self) -> bool {
        matches!(self, Self::Config(_))
    }
}

impl fmt::Display for FaucetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(message) => write!(f, "configuration error: {message}"),
            Self::Database(message) => write!(f, "database error: {message}"),
            Self::Veil(error) => write!(f, "veil error: {error}"),
            Self::Discord(message) => write!(f, "discord error: {message}"),
        }
    }
}

impl std::error::Error for FaucetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Veil(error) => Some(error),
            _ => None,
        }
    }
}

impl From<veilrustlib::VeilError> for FaucetError {
    fn from(error: veilrustlib::VeilError) -> Self {
        Self::Veil(error)
    }
}

impl From<turso::Error> for FaucetError {
    fn from(error: turso::Error) -> Self {
        Self::Database(error.to_string())
    }
}

impl From<serenity::Error> for FaucetError {
    fn from(error: serenity::Error) -> Self {
        Self::Discord(error.to_string())
    }
}
