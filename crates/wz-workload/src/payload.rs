// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a stream sends: the bytes of its n-th send.
//!
//! A payload is fixed (the same bytes every time, written as text or as hex, and a body may hold
//! `0x00`) or generated: a size and a fill rule, applied to the send's sequence number, so the
//! bytes of any send are a pure function of the plan and its index and a receiver can tell which
//! send it holds. The rules are the contract and this module's tests hold them as bytes:
//!
//! * `zero`: every byte 0;
//! * `counter`: the sequence number, little-endian, in the first eight bytes (fewer when the
//!   payload is shorter), and 0 after them, which is what a receiver measuring loss and reordering
//!   reads;
//! * `seeded`: the little-endian bytes of successive SplitMix64 words from the state
//!   `seed ^ sequence`, so every send differs and the same plan repeats the same bytes.

use alloc::vec::Vec;

use crate::mutation::splitmix64;

/// How a generated payload's bytes are made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fill {
    /// Every byte 0.
    Zero,
    /// The sequence number, little-endian, then 0.
    Counter,
    /// Bytes from the seeded generator, a different run for each sequence number.
    Seeded { seed: u64 },
}

/// The bytes a stream sends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    /// The same bytes every send.
    Fixed(Vec<u8>),
    /// `size` bytes made by `fill` for each send.
    Generated { size: usize, fill: Fill },
}

impl Payload {
    /// How long every send is.
    pub fn len(&self) -> usize {
        match self {
            Self::Fixed(bytes) => bytes.len(),
            Self::Generated { size, .. } => *size,
        }
    }

    /// Whether every send is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Write the bytes of the send numbered `sequence` into `out`, which must be [`Self::len`]
    /// long: the form a fixed-memory interpreter uses, with a buffer it owns.
    pub fn write(&self, sequence: u64, out: &mut [u8]) {
        match self {
            Self::Fixed(bytes) => out.copy_from_slice(bytes),
            Self::Generated { fill, .. } => fill_into(*fill, sequence, out),
        }
    }

    /// The bytes of the send numbered `sequence`.
    pub fn bytes(&self, sequence: u64) -> Vec<u8> {
        let mut out = alloc::vec![0u8; self.len()];
        self.write(sequence, &mut out);
        out
    }
}

/// Fill `out` by `fill` for the send numbered `sequence`.
pub fn fill_into(fill: Fill, sequence: u64, out: &mut [u8]) {
    match fill {
        Fill::Zero => out.fill(0),
        Fill::Counter => {
            out.fill(0);
            let word = sequence.to_le_bytes();
            let n = out.len().min(word.len());
            out[..n].copy_from_slice(&word[..n]);
        }
        Fill::Seeded { seed } => {
            let mut state = seed ^ sequence;
            for chunk in out.chunks_mut(8) {
                let word = splitmix64(&mut state).to_le_bytes();
                chunk.copy_from_slice(&word[..chunk.len()]);
            }
        }
    }
}

/// Why text is not hex bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexError {
    /// An odd number of digits, so the last byte is half written.
    OddLength,
    /// A character that is not a hex digit, at this offset.
    NotHex { at: usize },
}

impl core::fmt::Display for HexError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OddLength => write!(f, "has an odd number of hex digits"),
            Self::NotHex { at } => {
                write!(f, "has a character that is not a hex digit at offset {at}")
            }
        }
    }
}

/// The bytes hex text writes, two digits a byte, either case, nothing else.
pub fn parse_hex(text: &str) -> Result<Vec<u8>, HexError> {
    let digits = text.as_bytes();
    if digits.len() % 2 != 0 {
        return Err(HexError::OddLength);
    }
    let value = |at: usize| match digits[at] {
        d @ b'0'..=b'9' => Ok(d - b'0'),
        d @ b'a'..=b'f' => Ok(d - b'a' + 10),
        d @ b'A'..=b'F' => Ok(d - b'A' + 10),
        _ => Err(HexError::NotHex { at }),
    };
    (0..digits.len())
        .step_by(2)
        .map(|at| Ok(value(at)? << 4 | value(at + 1)?))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fills_are_these_bytes() {
        let counter = Payload::Generated {
            size: 10,
            fill: Fill::Counter,
        };
        assert_eq!(counter.bytes(0x0102), [0x02, 0x01, 0, 0, 0, 0, 0, 0, 0, 0]);
        let short = Payload::Generated {
            size: 3,
            fill: Fill::Counter,
        };
        assert_eq!(short.bytes(0x0a0b0c0d), [0x0d, 0x0c, 0x0b]);
        assert_eq!(
            Payload::Generated {
                size: 4,
                fill: Fill::Zero
            }
            .bytes(9),
            [0; 4]
        );
        // seed 0 and sequence 0 is the generator's own state 0, whose first word is published.
        let seeded = Payload::Generated {
            size: 10,
            fill: Fill::Seeded { seed: 0 },
        };
        assert_eq!(
            seeded.bytes(0),
            [0xaf, 0xcd, 0x1d, 0x7b, 0x39, 0xa8, 0x20, 0xe2, 0xf4, 0x65]
        );
        assert_ne!(seeded.bytes(1), seeded.bytes(0));
        assert_eq!(seeded.bytes(1), seeded.bytes(1));
        let fixed = Payload::Fixed(alloc::vec![0, 1, 0]);
        assert_eq!((fixed.bytes(7), fixed.len()), (alloc::vec![0, 1, 0], 3));
    }

    #[test]
    fn hex_is_two_digits_a_byte() {
        assert_eq!(parse_hex("00ff10"), Ok(alloc::vec![0x00, 0xff, 0x10]));
        assert_eq!(parse_hex("ABcd"), Ok(alloc::vec![0xab, 0xcd]));
        assert_eq!(parse_hex(""), Ok(alloc::vec![]));
        assert_eq!(parse_hex("abc"), Err(HexError::OddLength));
        assert_eq!(parse_hex("0g"), Err(HexError::NotHex { at: 1 }));
        assert_eq!(parse_hex("0x10"), Err(HexError::NotHex { at: 1 }));
    }
}
