// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The kit's SPI master: SCB3 on the MikroBUS socket, through the C driver
//! (`src/scb_spi.c`, which holds the PDL calls) and the rules of
//! `wz-spi-scb` (which hold everything that does not need a register).
//!
//! What this file adds to those two is the order they are used in, and the
//! guarantee that the block is opened once:
//!
//! 1. the board routes the socket's SPI pins and says which slave select line
//!    carries chip select (`boards/<board>/*_spi_pins.c`);
//! 2. the driver claims a free peripheral clock divider and reports the clock
//!    it gives;
//! 3. [`wz_spi_scb::Rate::choose`] turns the rate the caller asked for into a
//!    divider and an oversample factor from THAT clock, so the divider follows the
//!    clock the chip actually has;
//! 4. the driver configures and enables the block in the mode asked for.
//!
//! The mode and the rate are the CALLER's, because they are the chip's. BUILT, not
//! run: nothing here has been on an SCB.

use core::ffi::{c_int, CStr};
use core::sync::atomic::{AtomicBool, Ordering};

use wz_spi_scb::{Rate, RateError, ScbMaster, ScbSpi, SpiMode};

extern "C" {
    /// The board's: route the socket's SPI pins and write the slave select line that
    /// carries chip select. Zero on success.
    fn wz_board_spi_pins_init(select: *mut u8) -> c_int;
    /// Claim a free peripheral clock divider for the SCB, enable it dividing by one
    /// and return the clock that gives, in hertz; zero when there is none.
    fn wz_scb_spi_clock_claim() -> u32;
    /// Set the claimed divider, configure the block as a master in `mode` with
    /// `oversample`, using slave select line `select`, and enable it. Zero on
    /// success.
    fn wz_scb_spi_start(mode: u8, select: u8, divider: u32, oversample: u32) -> c_int;
    /// One exchange of `len` bytes. Zero on success, a negative errno otherwise.
    fn wz_scb_spi_exchange(tx: *const u8, rx: *mut u8, len: u32) -> c_int;
}

/// What an 8-bit peripheral clock divider divides by at most; the driver claims one.
const DIVIDER_MAX: u32 = 256;

/// The block can be opened once: a second open would claim another divider and
/// reconfigure a running master under whoever holds the first.
static OPENED: AtomicBool = AtomicBool::new(false);

/// The block, once it is open. Only [`open`] makes one.
pub struct Scb3 {
    _opened: (),
}

impl ScbMaster for Scb3 {
    /// The driver's negative errno.
    type Error = i32;

    fn exchange(&mut self, tx: &[u8], rx: &mut [u8]) -> Result<(), i32> {
        // SAFETY: both slices are live for `tx.len()` bytes, and `ScbSpi` checked
        // before this call that the lengths are equal, not zero and within the FIFO,
        // which is the whole of what the driver relies on.
        let rc = unsafe { wz_scb_spi_exchange(tx.as_ptr(), rx.as_mut_ptr(), tx.len() as u32) };
        if rc == 0 {
            Ok(())
        } else {
            Err(rc)
        }
    }
}

/// Open the kit's SPI master in `mode` at the highest rate not above `hz`, and
/// return it with the rate it was given, which is what the block really runs at.
pub fn open(mode: SpiMode, hz: u32) -> Result<(ScbSpi<Scb3>, Rate), &'static CStr> {
    if OPENED.swap(true, Ordering::AcqRel) {
        return Err(c"wz: FAIL - the SPI block was opened twice");
    }
    let mut select = 0u8;
    // SAFETY: the board's pin routing, which writes one byte through the pointer.
    if unsafe { wz_board_spi_pins_init(&mut select) } != 0 {
        return Err(c"wz: FAIL - the board could not route the SPI pins");
    }
    // SAFETY: no arguments; the driver touches the clock block and the SCB only.
    let source_hz = unsafe { wz_scb_spi_clock_claim() };
    if source_hz == 0 {
        return Err(c"wz: FAIL - no peripheral clock divider is free for the SPI block");
    }
    let rate = Rate::choose(source_hz, hz, DIVIDER_MAX).map_err(|why| match why {
        RateError::ZeroSource => c"wz: FAIL - the SPI block's clock reads as zero",
        RateError::ZeroTarget => c"wz: FAIL - an SPI rate of zero was asked for",
        RateError::NoDivider => c"wz: FAIL - no divider is allowed for the SPI block",
        RateError::TooSlow { .. } => {
            c"wz: FAIL - the SPI rate asked for is below what the clock can make"
        }
    })?;
    // SAFETY: arguments were derived above within the ranges the driver checks.
    let rc = unsafe { wz_scb_spi_start(mode.number(), select, rate.divider, rate.oversample) };
    if rc != 0 {
        return Err(c"wz: FAIL - the SPI block could not be configured");
    }
    Ok((ScbSpi::new(Scb3 { _opened: () }), rate))
}
