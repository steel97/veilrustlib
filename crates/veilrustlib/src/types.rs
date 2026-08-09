//! Core Veil types.
//!
//! Direct port of `src/types.ts`. TypeScript's `Uint8Array` aliases become
//! fixed-size arrays where the protocol fixes the length (keys, commitments,
//! hashes) and `Vec<u8>` where it does not (scripts, range proofs, `vData`).
//! `bigint` amounts become `u64` satoshis.

use crate::error::{Result, VeilError};

/// A 32-byte hash.
pub type Hash = [u8; 32];
/// A compressed secp256k1 public key.
pub type PublicKey = [u8; 33];
/// A secp256k1 secret key.
pub type SecretKey = [u8; 32];
/// A Pedersen blinding factor.
pub type Blind = [u8; 32];
/// A Pedersen commitment (`0x08`/`0x09` prefix + x-coordinate).
pub type Commitment = [u8; 33];
/// A RingCT key image.
pub type KeyImage = [u8; 33];

/// Satoshis per VEIL.
pub const SATOSHIS_PER_VEIL: u64 = 100_000_000;

/// Maximum VEIL supply, in satoshis.
pub const MAX_MONEY: u64 = 21_000_000 * SATOSHIS_PER_VEIL;

/// Marker placed in `prevout.n` to flag a RingCT (anon) input.
pub const ANON_MARKER: u32 = 0xffff_ffa0;

/// Veil output types, matching `OutputType` in `primitives/transaction.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum OutputType {
    /// Null output, a marker for `CCoinsView`.
    Null = 0,
    /// Standard Bitcoin-style output.
    Standard = 1,
    /// Confidential Transaction output: blinded, no ring.
    Ct = 2,
    /// Ring Confidential Transaction output.
    RingCt = 3,
    /// Data output, carrying fee or narration.
    Data = 4,
}

impl OutputType {
    /// Parse the on-the-wire type byte.
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Null),
            1 => Ok(Self::Standard),
            2 => Ok(Self::Ct),
            3 => Ok(Self::RingCt),
            4 => Ok(Self::Data),
            other => Err(VeilError::deserialization(format!(
                "unknown output type: {other}"
            ))),
        }
    }
}

/// `vData[0]` markers identifying the payload of an [`OutputType::Data`] output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DataOutputType {
    /// Plain narration.
    NarrPlain = 1,
    /// Encrypted narration.
    NarrCrypt = 2,
    /// Stealth address.
    Stealth = 3,
    /// Stealth address prefix.
    StealthPrefix = 4,
    /// Voting data.
    Vote = 5,
    /// Transaction fee.
    Fee = 6,
    /// Dev fund carry-forward.
    DevFundCfwd = 7,
    /// Fund message.
    FundMsg = 8,
}

/// Veil transaction types, encoded in the high byte of `nVersion`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum TransactionType {
    /// Standard transaction.
    #[default]
    Standard = 0,
    /// Coinbase transaction.
    Coinbase = 1,
    /// Coinstake transaction.
    Coinstake = 2,
}

/// An unspent RingCT output owned by the wallet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Utxo {
    /// Transaction ID, in display (reversed) hex order.
    pub txid: String,
    /// Output index within the transaction.
    pub vout: u32,
    /// Amount in satoshis.
    pub amount: u64,
    /// Pedersen commitment to [`Self::amount`].
    pub commitment: Commitment,
    /// Blinding factor for [`Self::commitment`].
    pub blind: Blind,
    /// One-time destination public key for this output.
    pub pubkey: PublicKey,
    /// Ephemeral public key from the originating transaction.
    pub ephemeral_pubkey: PublicKey,
    /// Block height at which this output confirmed.
    pub block_height: u32,
    /// Whether this output is currently spendable.
    pub spendable: bool,
    /// Global RingCT output index, required to build a ring.
    pub ringct_index: Option<u64>,
}

/// An unspent CT output owned by the wallet.
///
/// CT outputs carry a `scriptPubKey` and are spent with ECDSA signatures,
/// so they need neither a ring nor a key image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtxoCt {
    /// Transaction ID, in display (reversed) hex order.
    pub txid: String,
    /// Output index within the transaction.
    pub vout: u32,
    /// Amount in satoshis.
    pub amount: u64,
    /// Pedersen commitment to [`Self::amount`].
    pub commitment: Commitment,
    /// Blinding factor for [`Self::commitment`].
    pub blind: Blind,
    /// Script pubkey, typically P2PKH.
    pub script_pubkey: Vec<u8>,
    /// Ephemeral public key from the originating transaction.
    pub ephemeral_pubkey: PublicKey,
    /// Derived destination public key for this output.
    pub pubkey: PublicKey,
    /// Block height at which this output confirmed.
    pub block_height: u32,
    /// Whether this output is currently spendable.
    pub spendable: bool,
}

/// A witness stack: a list of variable-length byte pushes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScriptStack {
    /// The stack items, serialized in order.
    pub stack: Vec<Vec<u8>>,
}

/// Reference to the output being spent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutPoint {
    /// Transaction hash, or the encoded `nInputs`/`nRingSize` pair for RingCT.
    pub hash: Hash,
    /// Output index, or [`ANON_MARKER`] for RingCT inputs.
    pub n: u32,
}

/// A RingCT transaction input.
#[derive(Debug, Clone)]
pub struct TxInput {
    /// Ring of candidate public keys, decoys plus the real key.
    pub ring: Vec<PublicKey>,
    /// Key image preventing a double spend.
    pub key_image: KeyImage,
    /// Position of the real key within [`Self::ring`].
    pub secret_index: usize,
    /// Previous output reference.
    pub prevout: OutPoint,
    /// Script signature; empty for RingCT.
    pub script_sig: Vec<u8>,
    /// Sequence number.
    pub sequence: u32,
    /// Script data, carrying key images for RingCT.
    pub script_data: Option<ScriptStack>,
    /// Script witness, carrying the MLSAG signature.
    pub script_witness: Option<ScriptStack>,
    /// Global RingCT indices of each ring member, parallel to [`Self::ring`].
    pub ring_indices: Vec<u64>,
}

/// A standard Bitcoin-style input, used to spend CT outputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxInputCt {
    /// Previous output reference.
    pub prevout: OutPoint,
    /// ECDSA signature and public key.
    pub script_sig: Vec<u8>,
    /// Sequence number.
    pub sequence: u32,
    /// Script witness, for segwit spends.
    pub script_witness: Option<ScriptStack>,
}

/// A transaction output.
///
/// Replaces the TypeScript `TxOutput` union. `address`, `amount`, and `blind`
/// are bookkeeping fields the builder uses and are not serialized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxOutput {
    /// A standard, transparent output.
    Standard {
        /// Amount in satoshis.
        amount: u64,
        /// Script pubkey.
        script_pubkey: Vec<u8>,
    },
    /// A Confidential Transaction output.
    Ct {
        /// Pedersen commitment to the amount.
        commitment: Commitment,
        /// Ephemeral public key payload.
        v_data: Vec<u8>,
        /// Script pubkey.
        script_pubkey: Vec<u8>,
        /// Range proof over the commitment.
        v_rangeproof: Vec<u8>,
        /// Plaintext amount, known only to the builder.
        amount: u64,
        /// Blinding factor, known only to the builder.
        blind: Option<Blind>,
        /// Destination stealth address, for bookkeeping.
        address: String,
    },
    /// A Ring Confidential Transaction output.
    RingCt {
        /// One-time destination public key.
        pk: PublicKey,
        /// Pedersen commitment to the amount.
        commitment: Commitment,
        /// Ephemeral public key payload.
        v_data: Vec<u8>,
        /// Range proof over the commitment.
        v_rangeproof: Vec<u8>,
        /// Plaintext amount, known only to the builder.
        amount: u64,
        /// Blinding factor, known only to the builder.
        blind: Option<Blind>,
        /// Destination stealth address, for bookkeeping.
        address: String,
    },
    /// A data output, carrying the fee or narration.
    Data {
        /// Data payload; `v_data[0]` is a [`DataOutputType`] marker.
        v_data: Vec<u8>,
    },
}

impl TxOutput {
    /// The output type byte written during serialization.
    pub fn output_type(&self) -> OutputType {
        match self {
            Self::Standard { .. } => OutputType::Standard,
            Self::Ct { .. } => OutputType::Ct,
            Self::RingCt { .. } => OutputType::RingCt,
            Self::Data { .. } => OutputType::Data,
        }
    }

    /// The Pedersen commitment, for outputs that carry one.
    pub fn commitment(&self) -> Option<&Commitment> {
        match self {
            Self::Ct { commitment, .. } | Self::RingCt { commitment, .. } => Some(commitment),
            _ => None,
        }
    }

    /// The blinding factor, for outputs that carry one.
    pub fn blind(&self) -> Option<&Blind> {
        match self {
            Self::Ct { blind, .. } | Self::RingCt { blind, .. } => blind.as_ref(),
            _ => None,
        }
    }
}

/// A Veil transaction.
#[derive(Debug, Clone, Default)]
pub struct Transaction {
    /// Transaction version, the low byte of `nVersion`.
    pub version: u8,
    /// Transaction type, the high byte of `nVersion`.
    pub tx_type: TransactionType,
    /// Whether witness data is present.
    pub has_witness: bool,
    /// Lock time.
    pub lock_time: u32,
    /// Transaction inputs.
    pub inputs: Vec<TxInput>,
    /// Transaction outputs.
    pub outputs: Vec<TxOutput>,
    /// Ring size used by the inputs.
    pub ring_size: usize,
    /// Per-input witness stacks.
    pub witness: Vec<ScriptStack>,
    /// Fee in satoshis.
    pub fee: u64,
}

/// A generated range proof and the data needed to rewind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeProof {
    /// Proof bytes.
    pub proof: Vec<u8>,
    /// Commitment the proof covers.
    pub commitment: Commitment,
    /// Blinding factor of the commitment.
    pub blind: Blind,
    /// Nonce needed to rewind the proof.
    pub nonce: [u8; 32],
}

/// An anonymous output fetched from the chain, used as a ring decoy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnonOutput {
    /// Output public key.
    pub pubkey: PublicKey,
    /// Pedersen commitment.
    pub commitment: Commitment,
    /// Global RingCT output index.
    pub index: u64,
    /// Transaction ID, when reported.
    pub txid: Option<String>,
    /// Output index within the transaction, when reported.
    pub vout: Option<u32>,
}

/// Aggregate wallet balance.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Balance {
    /// Total balance in satoshis.
    pub total: u64,
    /// Confirmed balance in satoshis.
    pub confirmed: u64,
    /// Unconfirmed balance in satoshis.
    pub unconfirmed: u64,
    /// Number of UTXOs counted.
    pub utxo_count: usize,
}
