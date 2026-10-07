// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

#![no_std]

//! The rules of an SPI master built on an Infineon SCB block, and the
//! [`SpiTransfer`] it presents. The registers are the board's.
//!
//! The SCB block is one piece of silicon on a family of chips, and a board that
//! uses it as an SPI master needs three things that are true of the block rather
//! than of the board, which is why they are here and not in the image that drives
//! a particular SCB:
//!
//! * a RATE: the block's data rate is its clock over an oversample factor of 4 to
//!   16, and that clock is the peripheral clock over a divider, so a requested
//!   rate is a pair of numbers, and which pair is arithmetic ([`Rate::choose`]).
//!   Nothing here is told the peripheral clock: the board reads it off the running
//!   chip and passes it in, so the divider follows the clock the chip actually has
//!   instead of a number someone wrote down for a clock tree that may have moved;
//! * a MODE: the clock polarity and phase ([`SpiMode`]), which belong to the
//!   CHIP on the other end. The block takes any of the four; which one is right is
//!   the chip crate's to say, and a TC6 chip's is not guessed at here;
//! * the SHAPE of an exchange ([`ScbSpi`]): one call is one chip-select
//!   assertion, full duplex, and no longer than the FIFO. The last is a hardware
//!   fact with a protocol consequence. The block releases chip select when its
//!   transmit FIFO runs dry, so an exchange is loaded whole before it starts, and
//!   one that did not fit would not be refused by the block: it would be cut in
//!   two by a chip-select release in the middle of a frame, which a framed
//!   protocol reads as two frames.
//!
//! ## What is claimed
//!
//! BUILT. The tests check the arithmetic against a brute-force search and the
//! rules against a model of the board's side; nothing here has been on a block's
//! clock.

use wz_runtime_core::SpiTransfer;

/// The SCB's FIFO, in 8-bit entries, which is the most one exchange may carry: the
/// PDL's `CY_SCB_FIFO_SIZE`, the whole memory with the block in byte mode.
pub const FIFO_BYTES: usize = 128;

/// The least oversample factor a master that reads MISO may use, per the PDL.
pub const OVERSAMPLE_MIN: u32 = 4;

/// The most oversample factor, per the PDL.
pub const OVERSAMPLE_MAX: u32 = 16;

/// The four SPI clock polarity and phase combinations, by the usual numbering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpiMode {
    /// Idle low, data sampled on the leading (rising) edge.
    Mode0,
    /// Idle low, data sampled on the trailing (falling) edge.
    Mode1,
    /// Idle high, data sampled on the leading (falling) edge.
    Mode2,
    /// Idle high, data sampled on the trailing (rising) edge.
    Mode3,
}

impl SpiMode {
    /// The clock's idle level: `true` when it idles high.
    pub const fn cpol(self) -> bool {
        matches!(self, Self::Mode2 | Self::Mode3)
    }

    /// `true` when data is sampled on the trailing edge of the clock.
    pub const fn cpha(self) -> bool {
        matches!(self, Self::Mode1 | Self::Mode3)
    }

    /// The mode's number, 0 to 3: `cpol` is its high bit and `cpha` its low one.
    pub const fn number(self) -> u8 {
        (self.cpol() as u8) << 1 | self.cpha() as u8
    }
}

/// A clock rate as the block takes it: the peripheral clock divided by `divider`,
/// then by `oversample`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rate {
    /// What the peripheral clock is divided by, 1 or more. The hardware register
    /// holds one less; that is the board's to write.
    pub divider: u32,
    /// The oversample factor, [`OVERSAMPLE_MIN`] to [`OVERSAMPLE_MAX`].
    pub oversample: u32,
    /// The data rate this pair gives, in hertz, rounded down.
    pub achieved_hz: u32,
}

/// Why no [`Rate`] could be chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateError {
    /// A peripheral clock of 0 Hz is not a clock a divider can work from: the
    /// board read it wrong, or the clock is not running.
    ZeroSource,
    /// A rate of 0 Hz was asked for.
    ZeroTarget,
    /// The board allows no divider at all.
    NoDivider,
    /// Even the largest divider and oversample factor give a rate above the one
    /// asked for. The slowest the block can run from this clock is carried.
    TooSlow {
        /// The slowest rate the block can run at from this clock, in hertz.
        slowest_hz: u32,
    },
}

impl Rate {
    /// The pair that gives the HIGHEST rate that does not exceed `target_hz`, from a
    /// peripheral clock of `source_hz` and dividers of 1 to `divider_max`.
    ///
    /// "Does not exceed" is the direction that matters: a chip's rated clock is a
    /// ceiling, so a rate the block cannot hit exactly is rounded DOWN, and the rate
    /// it did give is returned for the caller to read rather than assumed. A target
    /// above what the block can do is not an error: the fastest it can do is
    /// returned, which is below the target by construction.
    ///
    /// Of pairs giving the same rate the one with the larger oversample factor is
    /// taken, since it samples each bit more times.
    pub fn choose(source_hz: u32, target_hz: u32, divider_max: u32) -> Result<Self, RateError> {
        if source_hz == 0 {
            return Err(RateError::ZeroSource);
        }
        if target_hz == 0 {
            return Err(RateError::ZeroTarget);
        }
        if divider_max == 0 {
            return Err(RateError::NoDivider);
        }
        // The least `divider * oversample` whose rate is at or under the target.
        let total = u64::from(source_hz).div_ceil(u64::from(target_hz));
        let mut best: Option<(u64, u32, u32)> = None;
        for oversample in (OVERSAMPLE_MIN..=OVERSAMPLE_MAX).rev() {
            let divider = total.div_ceil(u64::from(oversample)).max(1);
            if divider > u64::from(divider_max) {
                continue;
            }
            let product = divider * u64::from(oversample);
            // Strictly less keeps the larger oversample among equal products,
            // because this walks the factors from the largest down.
            let better = match best {
                Some((least, _, _)) => product < least,
                None => true,
            };
            if better {
                best = Some((product, divider as u32, oversample));
            }
        }
        match best {
            Some((product, divider, oversample)) => Ok(Self {
                divider,
                oversample,
                achieved_hz: (u64::from(source_hz) / product) as u32,
            }),
            None => {
                let slowest = u64::from(divider_max) * u64::from(OVERSAMPLE_MAX);
                Err(RateError::TooSlow {
                    slowest_hz: (u64::from(source_hz) / slowest) as u32,
                })
            }
        }
    }
}

/// The board's side of an exchange: the hardware, once the rules have passed.
pub trait ScbMaster {
    /// What a failed exchange reports.
    type Error: core::fmt::Debug;

    /// Load the whole of `tx` into the transmit FIFO, run the clocks with chip
    /// select asserted, and read `rx.len()` bytes back, which is `tx.len()`.
    ///
    /// The caller has checked that the lengths are equal, that they are not zero
    /// and that they fit the FIFO: an implementation may rely on all three.
    fn exchange(&mut self, tx: &[u8], rx: &mut [u8]) -> Result<(), Self::Error>;
}

/// Why an exchange was refused or failed.
#[derive(Debug, PartialEq, Eq)]
pub enum Error<E> {
    /// Nothing to exchange: an exchange of no bytes asserts chip select for no
    /// clocks, which no protocol means.
    Empty,
    /// `tx` and `rx` differ in length: a full-duplex exchange clocks as many bytes
    /// in as it clocks out.
    LengthMismatch {
        /// The length of `tx`.
        tx: usize,
        /// The length of `rx`.
        rx: usize,
    },
    /// The exchange is longer than the FIFO, so it would not be one chip-select
    /// assertion. Nothing was sent.
    TooLong {
        /// The length asked for.
        len: usize,
    },
    /// The board's hardware failed.
    Master(E),
}

/// An [`SpiTransfer`] over a board's [`ScbMaster`], with the rules enforced first.
pub struct ScbSpi<M: ScbMaster> {
    master: M,
}

impl<M: ScbMaster> ScbSpi<M> {
    /// Wrap a board's master.
    pub fn new(master: M) -> Self {
        Self { master }
    }

    /// The board's master, for what a board does that this does not (reconfigure,
    /// read a status).
    pub fn master_mut(&mut self) -> &mut M {
        &mut self.master
    }
}

impl<M: ScbMaster> SpiTransfer for ScbSpi<M> {
    type Error = Error<M::Error>;

    fn transfer(&mut self, tx: &[u8], rx: &mut [u8]) -> Result<(), Self::Error> {
        if tx.len() != rx.len() {
            return Err(Error::LengthMismatch {
                tx: tx.len(),
                rx: rx.len(),
            });
        }
        if tx.is_empty() {
            return Err(Error::Empty);
        }
        if tx.len() > FIFO_BYTES {
            return Err(Error::TooLong { len: tx.len() });
        }
        self.master.exchange(tx, rx).map_err(Error::Master)
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;
