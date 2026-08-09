//! Cursor for reading binary transaction data.
//!
//! Port of `src/buffer-reader.ts`. Every read is bounds-checked and returns a
//! [`Result`] instead of reading past the end of the buffer, which the
//! TypeScript `DataView` version did silently.

use crate::error::{Result, VeilError};

/// A forward-only cursor over a byte buffer.
#[derive(Debug, Clone)]
pub struct BufferReader<'a> {
    buffer: &'a [u8],
    offset: usize,
}

impl<'a> BufferReader<'a> {
    /// Create a reader positioned at the start of `buffer`.
    pub fn new(buffer: &'a [u8]) -> Self {
        Self { buffer, offset: 0 }
    }

    /// The current read position.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// Bytes not yet consumed.
    pub fn remaining(&self) -> usize {
        self.buffer.len().saturating_sub(self.offset)
    }

    /// Whether any bytes remain.
    pub fn has_more(&self) -> bool {
        self.offset < self.buffer.len()
    }

    /// The unconsumed remainder of the buffer.
    pub fn rest(&self) -> &'a [u8] {
        &self.buffer[self.offset.min(self.buffer.len())..]
    }

    fn take(&mut self, size: usize) -> Result<&'a [u8]> {
        let end = self.offset.checked_add(size).ok_or_else(|| {
            VeilError::deserialization("read length overflowed")
        })?;

        if end > self.buffer.len() {
            return Err(VeilError::deserialization(format!(
                "unexpected end of buffer: need {size} bytes at offset {}, {} remain",
                self.offset,
                self.remaining()
            )));
        }

        let slice = &self.buffer[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    /// Read a `u8`.
    pub fn read_u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    /// Read a little-endian `i32`.
    pub fn read_i32(&mut self) -> Result<i32> {
        let bytes = self.take(4)?;
        Ok(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Read a little-endian `u16`.
    pub fn read_u16(&mut self) -> Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    /// Read a little-endian `u32`.
    pub fn read_u32(&mut self) -> Result<u32> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Read a little-endian `u64`.
    pub fn read_u64(&mut self) -> Result<u64> {
        let bytes = self.take(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Read a fixed-size slice.
    pub fn read_slice(&mut self, size: usize) -> Result<&'a [u8]> {
        self.take(size)
    }

    /// Read a fixed-size array.
    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let slice = self.take(N)?;
        Ok(slice.try_into().expect("take returned exactly N bytes"))
    }

    /// Read a Bitcoin-style compact size integer.
    pub fn read_var_int(&mut self) -> Result<u64> {
        let first = self.read_u8()?;
        match first {
            n if n < 0xfd => Ok(u64::from(n)),
            0xfd => Ok(u64::from(self.read_u16()?)),
            0xfe => Ok(u64::from(self.read_u32()?)),
            _ => self.read_u64(),
        }
    }

    /// Read a compact-size length followed by that many bytes.
    pub fn read_var_slice(&mut self) -> Result<&'a [u8]> {
        let length = self.read_var_int()?;
        let length = usize::try_from(length)
            .map_err(|_| VeilError::deserialization("var slice length exceeds usize"))?;
        self.take(length)
    }

    /// Read a LEB128-encoded integer, as written by Veil's `PutVarInt`.
    pub fn read_leb128(&mut self) -> Result<u64> {
        let mut result: u64 = 0;
        let mut shift = 0u32;

        loop {
            let byte = self.read_u8()?;
            let payload = u64::from(byte & 0x7f);

            if shift >= 64 || (shift == 63 && payload > 1) {
                return Err(VeilError::deserialization("LEB128 value overflows u64"));
            }

            result |= payload << shift;

            if byte & 0x80 == 0 {
                return Ok(result);
            }

            shift += 7;
        }
    }

    /// Read a stack: a count followed by that many length-prefixed items.
    pub fn read_stack(&mut self) -> Result<Vec<Vec<u8>>> {
        let count = self.read_var_int()?;
        let count = usize::try_from(count)
            .map_err(|_| VeilError::deserialization("stack count exceeds usize"))?;

        let mut stack = Vec::with_capacity(count.min(self.remaining()));
        for _ in 0..count {
            stack.push(self.read_var_slice()?.to_vec());
        }
        Ok(stack)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_integers_little_endian() {
        let data = [0x01, 0x02, 0x00, 0x00, 0x00];
        let mut reader = BufferReader::new(&data);
        assert_eq!(reader.read_u8().unwrap(), 0x01);
        assert_eq!(reader.read_u32().unwrap(), 2);
        assert!(!reader.has_more());
    }

    #[test]
    fn reads_all_var_int_widths() {
        let mut reader = BufferReader::new(&[0x10]);
        assert_eq!(reader.read_var_int().unwrap(), 0x10);

        let mut reader = BufferReader::new(&[0xfd, 0x34, 0x12]);
        assert_eq!(reader.read_var_int().unwrap(), 0x1234);

        let mut reader = BufferReader::new(&[0xfe, 0x78, 0x56, 0x34, 0x12]);
        assert_eq!(reader.read_var_int().unwrap(), 0x1234_5678);

        let mut reader = BufferReader::new(&[0xff, 1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(reader.read_var_int().unwrap(), 1);
    }

    #[test]
    fn reads_var_slice() {
        let data = [0x03, 0xaa, 0xbb, 0xcc];
        let mut reader = BufferReader::new(&data);
        assert_eq!(reader.read_var_slice().unwrap(), &[0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn decodes_leb128_reference_vector() {
        // 253687 = 0x3DEF7, which encodes as f7 bd 0f in LEB128.
        let data = [0xf7, 0xbd, 0x0f];
        let mut reader = BufferReader::new(&data);
        assert_eq!(reader.read_leb128().unwrap(), 253_687);
    }

    #[test]
    fn overrun_is_an_error_not_a_panic() {
        let data = [0x01];
        let mut reader = BufferReader::new(&data);
        assert!(reader.read_u32().is_err());
    }

    #[test]
    fn reads_stack_of_items() {
        let data = [0x02, 0x01, 0xaa, 0x02, 0xbb, 0xcc];
        let mut reader = BufferReader::new(&data);
        let stack = reader.read_stack().unwrap();
        assert_eq!(stack, vec![vec![0xaa], vec![0xbb, 0xcc]]);
    }
}
