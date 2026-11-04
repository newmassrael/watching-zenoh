// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A REPRODUCIBLE SOURCE OF MESSAGE-SHAPED BYTES, for the property tests that
//! hold the dissection and what reads its trees to every shape a walker can
//! produce.
//!
//! The messages are seeded noise behind a chosen first byte, not a list of
//! built messages: a list holds the shapes its author thought of, and what
//! these tests guard against is a shape nobody thought of. A length or a count
//! read out of the noise is small most of the time, so a walk goes on past it
//! and reaches the fields behind; any byte the rest of the time, so every flag
//! and every id is reached.
//!
//! One definition for every crate whose tests walk the same population (the
//! declared shape's own, and the selector's over a capture), so a population a
//! test pins is the one the other reads.

use alloc::vec::Vec;

/// The transport message ids a population reaches, every header flag on top.
pub const TRANSPORT_MIDS: core::ops::RangeInclusive<u8> = 0x00..=0x07;
/// The scouting message ids.
pub const SCOUTING_MIDS: [u8; 2] = [0x01, 0x02];
/// The network message ids.
pub const NETWORK_MIDS: core::ops::RangeInclusive<u8> = 0x19..=0x1F;

/// A seeded byte source: xorshift64.
#[derive(Debug, Clone)]
pub struct WireNoise(u64);

impl WireNoise {
    /// The source every population of the crate's tests starts from.
    pub const SEED: u64 = 0x9E37_79B9_7F4A_7C15;

    /// A source from `seed`, which must not be zero (xorshift stays at zero).
    pub const fn new(seed: u64) -> Self {
        Self(if seed == 0 { Self::SEED } else { seed })
    }

    /// The next word.
    pub fn next_word(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    /// The three header flag bits of a round, as the top bits of a first byte.
    pub fn flags(&mut self) -> u8 {
        (self.next_word() as u8) & 0xE0
    }

    /// A byte that is SMALL most of the time and any byte the rest of it.
    pub fn byte(&mut self) -> u8 {
        let r = self.next_word();
        if r % 3 == 0 {
            (r >> 8) as u8
        } else {
            ((r >> 8) % 6) as u8
        }
    }

    /// A message: `first`, then one to 48 bytes of noise.
    pub fn message(&mut self, first: u8) -> Vec<u8> {
        let len = 1 + (self.next_word() % 48) as usize;
        let mut out = alloc::vec![first];
        out.extend((0..len).map(|_| self.byte()));
        out
    }
}

impl Default for WireNoise {
    fn default() -> Self {
        Self::new(Self::SEED)
    }
}
