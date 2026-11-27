// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The deterministic encoding of CBOR (RFC 8949, section 4.2.1) a sealed command is written in:
//! a reader that takes that one encoding and refuses every other, and a writer that writes only
//! it.
//!
//! The reader is a schema reader, not a general decoder: the caller asks for the item the format
//! has next, so an item of another kind, or a map whose keys come in another order, is not the
//! schema. What the reader refuses on its own is a head that is not deterministic: an argument
//! longer than its value needs and an indefinite length, which are well-formed CBOR with a second
//! spelling of the same value. Accepting one would give a signed object two encodings.

use crate::SealError;

/// The major types, as the top three bits of an initial byte, so a head is compared with no shift.
pub(crate) const MAJOR_UINT: u8 = 0x00;
pub(crate) const MAJOR_NINT: u8 = 0x20;
pub(crate) const MAJOR_BSTR: u8 = 0x40;
pub(crate) const MAJOR_TSTR: u8 = 0x60;
pub(crate) const MAJOR_ARRAY: u8 = 0x80;
pub(crate) const MAJOR_MAP: u8 = 0xa0;
pub(crate) const MAJOR_TAG: u8 = 0xc0;
pub(crate) const MAJOR_SIMPLE: u8 = 0xe0;

const MAJOR_BITS: u8 = 0xe0;
const INFO_BITS: u8 = 0x1f;
const INFO_ONE_BYTE: u8 = 24;
const INFO_TWO_BYTES: u8 = 25;
const INFO_FOUR_BYTES: u8 = 26;
const INFO_EIGHT_BYTES: u8 = 27;
const INFO_INDEFINITE: u8 = 31;

/// The least value each argument length is needed for: below it, a shorter one holds the value.
const LEAST_TWO_BYTES: u64 = 0x100;
const LEAST_FOUR_BYTES: u64 = 0x1_0000;
const LEAST_EIGHT_BYTES: u64 = 0x1_0000_0000;

/// The simple value `null` (major type 7, value 22).
pub(crate) const SIMPLE_NULL: u64 = 22;

/// One head: the major type and its argument.
pub(crate) type Head = (u8, u64);

/// Reads the items of one encoded value in order.
pub(crate) struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], SealError> {
        let (taken, rest) = self
            .rest
            .split_at_checked(len)
            .ok_or(SealError::Malformed)?;
        self.rest = rest;
        Ok(taken)
    }

    /// The next `N` bytes as they are, for the content of a string whose head was read.
    pub(crate) fn raw_array<const N: usize>(&mut self) -> Result<[u8; N], SealError> {
        <[u8; N]>::try_from(self.take(N)?).map_err(|_| SealError::Malformed)
    }

    /// The next head, refused when its argument is not written in the fewest bytes or its
    /// length is indefinite (RFC 8949, section 4.2.1).
    pub(crate) fn head(&mut self) -> Result<Head, SealError> {
        let [initial] = self.raw_array::<1>()?;
        let major = initial & MAJOR_BITS;
        let info = initial & INFO_BITS;
        let value = match info {
            0..INFO_ONE_BYTE => u64::from(info),
            INFO_ONE_BYTE => {
                let [byte] = self.raw_array::<1>()?;
                shortest(u64::from(byte), u64::from(INFO_ONE_BYTE))?
            }
            INFO_TWO_BYTES => shortest(
                u64::from(u16::from_be_bytes(self.raw_array()?)),
                LEAST_TWO_BYTES,
            )?,
            INFO_FOUR_BYTES => shortest(
                u64::from(u32::from_be_bytes(self.raw_array()?)),
                LEAST_FOUR_BYTES,
            )?,
            INFO_EIGHT_BYTES => shortest(u64::from_be_bytes(self.raw_array()?), LEAST_EIGHT_BYTES)?,
            INFO_INDEFINITE => return Err(SealError::NonCanonical),
            _ => return Err(SealError::Malformed),
        };
        Ok((major, value))
    }

    /// The next head, which must be exactly `expected`.
    pub(crate) fn expect(&mut self, expected: Head) -> Result<(), SealError> {
        if self.head()? == expected {
            Ok(())
        } else {
            Err(SealError::Malformed)
        }
    }

    /// The next item, an unsigned integer.
    pub(crate) fn uint(&mut self) -> Result<u64, SealError> {
        match self.head()? {
            (MAJOR_UINT, value) => Ok(value),
            _ => Err(SealError::Malformed),
        }
    }

    /// The next item, an unsigned integer or `null`.
    pub(crate) fn uint_or_null(&mut self) -> Result<Option<u64>, SealError> {
        match self.head()? {
            (MAJOR_UINT, value) => Ok(Some(value)),
            (MAJOR_SIMPLE, SIMPLE_NULL) => Ok(None),
            _ => Err(SealError::Malformed),
        }
    }

    /// The `len` bytes of a string whose head has been read.
    fn content(&mut self, len: u64) -> Result<&'a [u8], SealError> {
        self.take(usize::try_from(len).map_err(|_| SealError::Malformed)?)
    }

    /// The next item, a byte string.
    pub(crate) fn bstr(&mut self) -> Result<&'a [u8], SealError> {
        match self.head()? {
            (MAJOR_BSTR, len) => self.content(len),
            _ => Err(SealError::Malformed),
        }
    }

    /// The next item, a byte string of exactly `N` bytes.
    pub(crate) fn bstr_array<const N: usize>(&mut self) -> Result<[u8; N], SealError> {
        <[u8; N]>::try_from(self.bstr()?).map_err(|_| SealError::Malformed)
    }

    /// The next item, a text string, as its bytes.
    pub(crate) fn tstr(&mut self) -> Result<&'a [u8], SealError> {
        match self.head()? {
            (MAJOR_TSTR, len) => self.content(len),
            _ => Err(SealError::Malformed),
        }
    }

    /// Nothing may follow the value.
    pub(crate) fn end(&self) -> Result<(), SealError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(SealError::Malformed)
        }
    }
}

/// `value`, if it needed the argument length it was written with: at least `least`.
fn shortest(value: u64, least: u64) -> Result<u64, SealError> {
    if value < least {
        Err(SealError::NonCanonical)
    } else {
        Ok(value)
    }
}

/// Writes items in the deterministic encoding into a caller's buffer.
pub(crate) struct Writer<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> Writer<'a> {
    pub(crate) fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, len: 0 }
    }

    /// How many bytes have been written.
    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    fn raw(&mut self, bytes: &[u8]) -> Result<(), SealError> {
        let end = self
            .len
            .checked_add(bytes.len())
            .ok_or(SealError::BufferTooSmall)?;
        self.buf
            .get_mut(self.len..end)
            .ok_or(SealError::BufferTooSmall)?
            .copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }

    /// A head, its argument in the fewest bytes that hold it.
    pub(crate) fn head(&mut self, (major, value): Head) -> Result<(), SealError> {
        if let Some(small) = u8::try_from(value)
            .ok()
            .filter(|small| *small < INFO_ONE_BYTE)
        {
            self.raw(&[major | small])
        } else if let Ok(byte) = u8::try_from(value) {
            self.raw(&[major | INFO_ONE_BYTE, byte])
        } else if let Ok(short) = u16::try_from(value) {
            self.raw(&[major | INFO_TWO_BYTES])?;
            self.raw(&short.to_be_bytes())
        } else if let Ok(word) = u32::try_from(value) {
            self.raw(&[major | INFO_FOUR_BYTES])?;
            self.raw(&word.to_be_bytes())
        } else {
            self.raw(&[major | INFO_EIGHT_BYTES])?;
            self.raw(&value.to_be_bytes())
        }
    }

    fn string(&mut self, major: u8, bytes: &[u8]) -> Result<(), SealError> {
        let len = u64::try_from(bytes.len()).map_err(|_| SealError::BufferTooSmall)?;
        self.head((major, len))?;
        self.raw(bytes)
    }

    /// A byte string.
    pub(crate) fn bstr(&mut self, bytes: &[u8]) -> Result<(), SealError> {
        self.string(MAJOR_BSTR, bytes)
    }

    /// `null`, where a number is absent.
    pub(crate) fn null(&mut self) -> Result<(), SealError> {
        self.head((MAJOR_SIMPLE, SIMPLE_NULL))
    }

    /// A text string.
    pub(crate) fn tstr(&mut self, text: &str) -> Result<(), SealError> {
        self.string(MAJOR_TSTR, text.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn written(head: Head) -> std::vec::Vec<u8> {
        let mut buf = [0u8; 9];
        let mut writer = Writer::new(&mut buf);
        writer.head(head).expect("a head fits nine bytes");
        let len = writer.len();
        buf[..len].to_vec()
    }

    #[test]
    fn every_argument_length_is_written_shortest_and_read_back() {
        let cases: [(u64, &[u8]); 9] = [
            (0, &[0x00]),
            (23, &[0x17]),
            (24, &[0x18, 0x18]),
            (255, &[0x18, 0xff]),
            (256, &[0x19, 0x01, 0x00]),
            (65_535, &[0x19, 0xff, 0xff]),
            (65_536, &[0x1a, 0x00, 0x01, 0x00, 0x00]),
            (u64::from(u32::MAX), &[0x1a, 0xff, 0xff, 0xff, 0xff]),
            (
                u64::from(u32::MAX) + 1,
                &[0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
            ),
        ];
        for (value, encoding) in cases {
            assert_eq!(written((MAJOR_UINT, value)), encoding, "{value}");
            let mut reader = Reader::new(encoding);
            assert_eq!(reader.uint(), Ok(value), "{value}");
            assert_eq!(reader.end(), Ok(()));
        }
        assert_eq!(written((MAJOR_NINT, 6)), [0x26], "-7, the ES256 label");
        assert_eq!(written((MAJOR_TAG, 18)), [0xd2], "the COSE_Sign1 tag");
    }

    #[test]
    fn an_argument_longer_than_its_value_needs_is_refused() {
        let longer: [&[u8]; 4] = [
            &[0x18, 0x17],
            &[0x19, 0x00, 0xff],
            &[0x1a, 0x00, 0x00, 0xff, 0xff],
            &[0x1b, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff],
        ];
        for encoding in longer {
            assert_eq!(
                Reader::new(encoding).uint(),
                Err(SealError::NonCanonical),
                "{encoding:02x?}"
            );
        }
    }

    #[test]
    fn an_indefinite_length_is_refused_and_a_reserved_one_is_malformed() {
        assert_eq!(
            Reader::new(&[0x9f, 0xff]).head(),
            Err(SealError::NonCanonical)
        );
        assert_eq!(
            Reader::new(&[0x5f, 0xff]).bstr(),
            Err(SealError::NonCanonical)
        );
        assert_eq!(Reader::new(&[0x1c]).head(), Err(SealError::Malformed));
    }

    #[test]
    fn a_string_shorter_than_its_head_says_and_bytes_after_the_value_are_malformed() {
        assert_eq!(
            Reader::new(&[0x43, 0x01, 0x02]).bstr(),
            Err(SealError::Malformed)
        );
        let mut reader = Reader::new(&[0x41, 0x01, 0x00]);
        assert_eq!(reader.bstr(), Ok(&[0x01][..]));
        assert_eq!(reader.end(), Err(SealError::Malformed));
    }

    #[test]
    fn null_is_read_where_a_number_may_be_absent_and_nothing_else_is() {
        assert_eq!(Reader::new(&[0xf6]).uint_or_null(), Ok(None));
        assert_eq!(Reader::new(&[0x07]).uint_or_null(), Ok(Some(7)));
        assert_eq!(
            Reader::new(&[0xf7]).uint_or_null(),
            Err(SealError::Malformed)
        );
        assert_eq!(Reader::new(&[0xf6]).uint(), Err(SealError::Malformed));
    }

    #[test]
    fn a_buffer_too_small_is_refused_and_keeps_what_fit() {
        let mut buf = [0u8; 2];
        let mut writer = Writer::new(&mut buf);
        assert_eq!(writer.bstr(&[1, 2]), Err(SealError::BufferTooSmall));
        assert_eq!(writer.len(), 1, "the head fit, the content did not");
    }
}
