//! Veil transaction serialization.
//!
//! Port of `src/serialization.ts`, matching the wire format in Veil Core's
//! `primitives/transaction.h`:
//!
//! ```text
//! [version:1][txType:1][hasWitness:1][lockTime:4]
//! [inputCount][inputs...][outputCount][outputs...][witness...]
//! ```

use crate::buffer_reader::BufferReader;
use crate::error::{Result, VeilError};
use crate::types::{
    OutPoint, OutputType, ScriptStack, Transaction, TransactionType, TxInput, TxOutput, ANON_MARKER,
};
use crate::utils::slice_to_array;

/// Append a Bitcoin-style compact size integer.
pub fn write_var_int(out: &mut Vec<u8>, value: u64) {
    match value {
        n if n < 0xfd => out.push(n as u8),
        n if n <= u64::from(u16::MAX) => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        n if n <= u64::from(u32::MAX) => {
            out.push(0xfe);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
        n => {
            out.push(0xff);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}

/// Encode a compact size integer to a fresh buffer.
pub fn encode_var_int(value: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(9);
    write_var_int(&mut out, value);
    out
}

/// Append a LEB128-encoded integer, matching Veil's `PutVarInt`.
///
/// Used for ring member indices and fee values, which are *not* compact size.
pub fn write_leb128(out: &mut Vec<u8>, value: u64) {
    let mut remaining = value;
    while remaining > 0x7f {
        out.push((remaining as u8 & 0x7f) | 0x80);
        remaining >>= 7;
    }
    out.push(remaining as u8 & 0x7f);
}

/// Encode a LEB128 integer to a fresh buffer.
pub fn encode_leb128(value: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(10);
    write_leb128(&mut out, value);
    out
}

/// Append a compact-size length followed by `data`.
pub fn write_var_slice(out: &mut Vec<u8>, data: &[u8]) {
    write_var_int(out, data.len() as u64);
    out.extend_from_slice(data);
}

/// Append a stack: an item count followed by each length-prefixed item.
pub fn write_stack(out: &mut Vec<u8>, stack: &[Vec<u8>]) {
    write_var_int(out, stack.len() as u64);
    for item in stack {
        write_var_slice(out, item);
    }
}

/// Serialize a RingCT input.
fn write_input(out: &mut Vec<u8>, input: &TxInput) {
    out.extend_from_slice(&input.prevout.hash);
    out.extend_from_slice(&input.prevout.n.to_le_bytes());
    write_var_slice(out, &input.script_sig);
    out.extend_from_slice(&input.sequence.to_le_bytes());

    // Anon inputs carry their key images in scriptData.
    if input.prevout.n == ANON_MARKER {
        if let Some(script_data) = &input.script_data {
            write_stack(out, &script_data.stack);
        }
    }
}

/// Serialize an output body, without the leading type byte.
///
/// This is the form used for signature and preimage hashing, matching
/// `CTxOutBase::Serialize`.
pub fn serialize_output_data(output: &TxOutput) -> Vec<u8> {
    let mut out = Vec::new();

    match output {
        TxOutput::Standard {
            amount,
            script_pubkey,
        } => {
            out.extend_from_slice(&amount.to_le_bytes());
            write_var_slice(&mut out, script_pubkey);
        }
        TxOutput::Ct {
            commitment,
            v_data,
            script_pubkey,
            v_rangeproof,
            ..
        } => {
            out.extend_from_slice(commitment);
            write_var_slice(&mut out, v_data);
            write_var_slice(&mut out, script_pubkey);
            write_var_slice(&mut out, v_rangeproof);
        }
        TxOutput::RingCt {
            pk,
            commitment,
            v_data,
            v_rangeproof,
            ..
        } => {
            out.extend_from_slice(pk);
            out.extend_from_slice(commitment);
            write_var_slice(&mut out, v_data);
            write_var_slice(&mut out, v_rangeproof);
        }
        TxOutput::Data { v_data } => {
            write_var_slice(&mut out, v_data);
        }
    }

    out
}

/// Serialize an output including its leading type byte.
pub fn serialize_output(output: &TxOutput) -> Vec<u8> {
    let mut out = Vec::with_capacity(1);
    out.push(output.output_type() as u8);
    out.extend_from_slice(&serialize_output_data(output));
    out
}

/// Serialize a transaction to raw bytes.
pub fn serialize_transaction_bytes(tx: &Transaction) -> Vec<u8> {
    let mut out = Vec::new();

    let version = if tx.version == 0 { 2 } else { tx.version };
    let n_version = (u16::from(tx.tx_type as u8) << 8) | u16::from(version);

    out.push((n_version & 0xff) as u8);
    out.push(((n_version >> 8) & 0xff) as u8);
    out.push(u8::from(tx.has_witness));
    out.extend_from_slice(&tx.lock_time.to_le_bytes());

    write_var_int(&mut out, tx.inputs.len() as u64);
    for input in &tx.inputs {
        write_input(&mut out, input);
    }

    write_var_int(&mut out, tx.outputs.len() as u64);
    for output in &tx.outputs {
        out.extend_from_slice(&serialize_output(output));
    }

    if tx.has_witness {
        for witness in &tx.witness {
            write_stack(&mut out, &witness.stack);
        }
    }

    out
}

/// Serialize a transaction to hex.
pub fn serialize_transaction(tx: &Transaction) -> String {
    hex::encode(serialize_transaction_bytes(tx))
}

/// The serialized size of a transaction, in bytes.
pub fn calculate_transaction_size(tx: &Transaction) -> usize {
    serialize_transaction_bytes(tx).len()
}

/// Parse a transaction from raw bytes.
///
/// Fields the wire format does not carry, such as ring keys and secret indices,
/// are left empty.
pub fn deserialize_transaction_bytes(bytes: &[u8]) -> Result<Transaction> {
    let mut reader = BufferReader::new(bytes);

    let version_low = reader.read_u8()?;
    let version_high = reader.read_u8()?;
    let version = version_low;
    let tx_type = match version_high {
        0 => TransactionType::Standard,
        1 => TransactionType::Coinbase,
        2 => TransactionType::Coinstake,
        other => {
            return Err(VeilError::deserialization(format!(
                "unknown transaction type: {other}"
            )))
        }
    };

    let has_witness = reader.read_u8()? == 1;
    let lock_time = reader.read_u32()?;

    let num_inputs = reader.read_var_int()?;
    let num_inputs = usize::try_from(num_inputs)
        .map_err(|_| VeilError::deserialization("input count exceeds usize"))?;

    let mut inputs = Vec::with_capacity(num_inputs.min(reader.remaining()));
    for _ in 0..num_inputs {
        let hash = reader.read_array::<32>()?;
        let n = reader.read_u32()?;
        let script_sig = reader.read_var_slice()?.to_vec();
        let sequence = reader.read_u32()?;

        let script_data = if n == ANON_MARKER {
            Some(ScriptStack {
                stack: reader.read_stack()?,
            })
        } else {
            None
        };

        inputs.push(TxInput {
            ring: Vec::new(),
            key_image: [0u8; 33],
            secret_index: 0,
            prevout: OutPoint { hash, n },
            script_sig,
            sequence,
            script_data,
            script_witness: None,
            ring_indices: Vec::new(),
        });
    }

    let num_outputs = reader.read_var_int()?;
    let num_outputs = usize::try_from(num_outputs)
        .map_err(|_| VeilError::deserialization("output count exceeds usize"))?;

    let mut outputs = Vec::with_capacity(num_outputs.min(reader.remaining()));
    for _ in 0..num_outputs {
        let output_type = OutputType::from_u8(reader.read_u8()?)?;

        let output = match output_type {
            OutputType::Standard => TxOutput::Standard {
                amount: reader.read_u64()?,
                script_pubkey: reader.read_var_slice()?.to_vec(),
            },
            OutputType::Ct => TxOutput::Ct {
                commitment: reader.read_array::<33>()?,
                v_data: reader.read_var_slice()?.to_vec(),
                script_pubkey: reader.read_var_slice()?.to_vec(),
                v_rangeproof: reader.read_var_slice()?.to_vec(),
                amount: 0,
                blind: None,
                address: String::new(),
            },
            OutputType::RingCt => TxOutput::RingCt {
                pk: reader.read_array::<33>()?,
                commitment: reader.read_array::<33>()?,
                v_data: reader.read_var_slice()?.to_vec(),
                v_rangeproof: reader.read_var_slice()?.to_vec(),
                amount: 0,
                blind: None,
                address: String::new(),
            },
            OutputType::Data => TxOutput::Data {
                v_data: reader.read_var_slice()?.to_vec(),
            },
            OutputType::Null => {
                return Err(VeilError::deserialization(
                    "OUTPUT_NULL is not valid on the wire",
                ))
            }
        };

        outputs.push(output);
    }

    let mut witness = Vec::new();
    if has_witness {
        for _ in 0..num_inputs {
            witness.push(ScriptStack {
                stack: reader.read_stack()?,
            });
        }
    }

    Ok(Transaction {
        version,
        tx_type,
        has_witness,
        lock_time,
        inputs,
        outputs,
        ring_size: 0,
        witness,
        fee: 0,
    })
}

/// Parse a transaction from hex.
pub fn deserialize_transaction(hex_str: &str) -> Result<Transaction> {
    let bytes = crate::utils::hex_to_bytes(hex_str)?;
    deserialize_transaction_bytes(&bytes)
}

/// Extract the fee from a `DO_FEE` data output, if present.
pub fn extract_fee(tx: &Transaction) -> Result<Option<u64>> {
    for output in &tx.outputs {
        if let TxOutput::Data { v_data } = output {
            if v_data.first() == Some(&(crate::types::DataOutputType::Fee as u8)) {
                let mut reader = BufferReader::new(&v_data[1..]);
                return Ok(Some(reader.read_leb128()?));
            }
        }
    }
    Ok(None)
}

/// Compute a transaction ID: reversed double SHA-256 of the serialization.
pub fn calculate_txid(tx: &Transaction) -> String {
    let bytes = serialize_transaction_bytes(tx);
    let hash = crate::crypto::double_sha256(&bytes);
    crate::utils::hash_to_display_hex(&hash)
}

/// Build the RingCT prevout hash, which encodes `nInputs` and `nRingSize`.
///
/// Veil's `GetAnonInfo` reads these as two little-endian `u32`s from the front
/// of the otherwise-unused prevout hash.
pub fn encode_anon_prevout_hash(n_inputs: u32, ring_size: u32) -> [u8; 32] {
    let mut hash = [0u8; 32];
    hash[0..4].copy_from_slice(&n_inputs.to_le_bytes());
    hash[4..8].copy_from_slice(&ring_size.to_le_bytes());
    hash
}

/// Read back the `nInputs` and `nRingSize` pair from a RingCT prevout hash.
pub fn decode_anon_prevout_hash(hash: &[u8; 32]) -> Result<(u32, u32)> {
    let n_inputs = u32::from_le_bytes(slice_to_array::<4>(&hash[0..4])?);
    let ring_size = u32::from_le_bytes(slice_to_array::<4>(&hash[4..8])?);
    Ok((n_inputs, ring_size))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn var_int_encodes_all_widths() {
        assert_eq!(encode_var_int(0x10), vec![0x10]);
        assert_eq!(encode_var_int(0x1234), vec![0xfd, 0x34, 0x12]);
        assert_eq!(
            encode_var_int(0x1234_5678),
            vec![0xfe, 0x78, 0x56, 0x34, 0x12]
        );
        assert_eq!(encode_var_int(0x1_0000_0000), vec![0xff, 0, 0, 0, 0, 1, 0, 0, 0]);
    }

    #[test]
    fn leb128_matches_veil_reference_vector() {
        // 253687 = 0x3DEF7: low 7 bits 0x77 twice with continuation, then 0x0f.
        assert_eq!(encode_leb128(253_687), vec![0xf7, 0xbd, 0x0f]);
        assert_eq!(encode_leb128(0), vec![0x00]);
        assert_eq!(encode_leb128(127), vec![0x7f]);
        assert_eq!(encode_leb128(128), vec![0x80, 0x01]);
    }

    #[test]
    fn leb128_round_trips_through_reader() {
        for value in [0u64, 1, 127, 128, 253_687, u64::MAX] {
            let encoded = encode_leb128(value);
            let mut reader = BufferReader::new(&encoded);
            assert_eq!(reader.read_leb128().unwrap(), value);
        }
    }

    fn sample_transaction() -> Transaction {
        Transaction {
            version: 2,
            tx_type: TransactionType::Standard,
            has_witness: true,
            lock_time: 0,
            inputs: vec![TxInput {
                ring: Vec::new(),
                key_image: [0u8; 33],
                secret_index: 0,
                prevout: OutPoint {
                    hash: encode_anon_prevout_hash(1, 11),
                    n: ANON_MARKER,
                },
                script_sig: Vec::new(),
                sequence: 0xffff_ffff,
                script_data: Some(ScriptStack {
                    stack: vec![vec![0xaa; 33]],
                }),
                script_witness: None,
                ring_indices: Vec::new(),
            }],
            outputs: vec![
                TxOutput::Data {
                    v_data: {
                        let mut v = vec![crate::types::DataOutputType::Fee as u8];
                        v.extend_from_slice(&encode_leb128(12_345));
                        v
                    },
                },
                TxOutput::RingCt {
                    pk: [0x02; 33],
                    commitment: [0x08; 33],
                    v_data: vec![0xbb; 33],
                    v_rangeproof: vec![0xcc; 100],
                    amount: 0,
                    blind: None,
                    address: String::new(),
                },
            ],
            ring_size: 11,
            witness: vec![ScriptStack {
                stack: vec![vec![0x01, 0x02], vec![0xdd; 64]],
            }],
            fee: 12_345,
        }
    }

    #[test]
    fn transaction_round_trips_through_serialization() {
        let tx = sample_transaction();
        let hex_str = serialize_transaction(&tx);
        let parsed = deserialize_transaction(&hex_str).unwrap();

        assert_eq!(parsed.version, tx.version);
        assert_eq!(parsed.tx_type, tx.tx_type);
        assert_eq!(parsed.has_witness, tx.has_witness);
        assert_eq!(parsed.lock_time, tx.lock_time);
        assert_eq!(parsed.inputs.len(), 1);
        assert_eq!(parsed.outputs.len(), 2);
        assert_eq!(parsed.witness.len(), 1);
        assert_eq!(parsed.inputs[0].prevout.n, ANON_MARKER);
        assert_eq!(
            parsed.inputs[0].script_data.as_ref().unwrap().stack,
            vec![vec![0xaa; 33]]
        );
        assert_eq!(parsed.outputs[1], tx.outputs[1]);
        assert_eq!(parsed.witness[0].stack, tx.witness[0].stack);

        // Re-serializing the parsed form must be byte-identical.
        assert_eq!(serialize_transaction(&parsed), hex_str);
    }

    #[test]
    fn output_data_omits_the_type_byte() {
        let output = TxOutput::Data {
            v_data: vec![0x06, 0x01],
        };
        let with_type = serialize_output(&output);
        let without_type = serialize_output_data(&output);

        assert_eq!(with_type[0], OutputType::Data as u8);
        assert_eq!(&with_type[1..], &without_type[..]);
    }

    #[test]
    fn fee_is_recoverable_from_data_output() {
        let tx = sample_transaction();
        assert_eq!(extract_fee(&tx).unwrap(), Some(12_345));
    }

    #[test]
    fn anon_prevout_hash_round_trips() {
        let hash = encode_anon_prevout_hash(1, 11);
        assert_eq!(decode_anon_prevout_hash(&hash).unwrap(), (1, 11));
    }

    #[test]
    fn size_matches_serialized_length() {
        let tx = sample_transaction();
        assert_eq!(
            calculate_transaction_size(&tx),
            serialize_transaction(&tx).len() / 2
        );
    }

    #[test]
    fn truncated_input_is_rejected() {
        assert!(deserialize_transaction("0200").is_err());
    }
}
