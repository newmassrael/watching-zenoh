// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The Microchip LAN8650/1 of a 10BASE-T1S expansion board in the kit's MikroBUS
//! socket, as the lwIP backend's second MAC.
//!
//! `wz-eth-lan865x` is the chip's bring-up and `wz-spi-scb` the SPI master it runs
//! over (`spi_cyt4bf` is that master on SCB3); this is the part that is the BOARD's:
//! the two control lines, the numbers the lab stated in Kconfig, and what the console
//! says. The pins are C (`boards/<board>/*_t1s_lines.c`).
//!
//! The order of the bring-up, and what each step relies on:
//!
//! 1. The control lines the build says are wired are routed, the reset line released.
//! 2. The SPI master is opened, in mode 0 (the data sheet: data is captured on the
//!    rising edge of SCLK and changes on the falling edge, DS60001734F 5.1) at the
//!    rate Kconfig gave, which the block rounds down.
//! 3. If the reset line is wired, the chip is reset by it: held low for
//!    [`RESET_HOLD_US`], released, and then waited for until it says it is ready (its
//!    IRQ_N asserts, DS60001734F 4.1.2) when that line is wired too, or for
//!    `CONFIG_WZ_T1S_RESET_WAIT_MS` when it is not.
//! 4. `wz_eth_lan865x` identifies the part by `DEVID`, resets it by software,
//!    configures it and declares it ready. A part it does not know is refused with
//!    nothing written.
//! 5. If IRQ_N is wired, its level is handed to the interface, so that a receive
//!    costs no exchange while the chip is quiet.
//!
//! A failure at any step stops the node with a line that says which: an image built
//! for this interface that cannot reach it is a fault to be seen, not one to run on
//! without.
//!
//! Claim: BUILT. Nothing here has run on silicon, and no emulator carries the chip.
//! One assumption in step 3 is not measured: that IRQ_N, which the chip floats while
//! in reset (DS60001734F Table 3-3), has been pulled high by the MCU's pull-up by the
//! time the reset is released, so that a level read right after the release is the
//! chip's new assertion and not the old one. If it were not, the open would start
//! early and fail on the bus with a line that says so.

use alloc::format;
use core::ffi::CStr;

use wz::runtime_coop::ClockSource;
use wz::runtime_core::EthernetMac;
use wz::runtime_zephyr::glue::{delay_us, log_line};
use wz::runtime_zephyr::{u32_from_build, ZephyrClock};
use wz_eth_lan865x::{Config, OpenError, PacedMac, Plca, ServiceEvent};
use wz_spi_scb::{ScbSpi, SpiMode};

use crate::net_lwip::BoardMac;
use crate::spi_cyt4bf::{self, Scb3};
use crate::TICK_HZ;

extern "C" {
    /// The board's (`boards/<board>/*_t1s_lines.c`): route the control lines the
    /// build says are wired and return which they are, as the bits below.
    fn wz_board_t1s_lines_init() -> u32;
    /// Drive RESET_N: asserted is low. Does nothing on a board whose reset line is
    /// not wired.
    fn wz_board_t1s_reset_set(asserted: bool);
    /// Whether the chip asserts IRQ_N. False on a board whose interrupt line is not
    /// wired.
    fn wz_board_t1s_irq_asserted() -> bool;
}

/// `wz_board_t1s_lines_init`: the reset line is wired.
const LINE_RESET: u32 = 0x1;
/// `wz_board_t1s_lines_init`: the interrupt line is wired.
const LINE_IRQ: u32 = 0x2;

/// How long RESET_N is held low. The data sheet asks for at least 5 microseconds
/// (DS60001734F Table 9-8, `trstia`); 10 is what Zephyr's driver for this chip holds
/// it for, twice the minimum.
const RESET_HOLD_US: u32 = 10;

/// How often the waits on IRQ_N look at it, in microseconds.
const IRQ_POLL_US: u32 = 100;

const SPI_HZ: u32 = u32_from_build!("WZ_T1S_SPI_HZ");
const SERVICE_MS: u32 = u32_from_build!("WZ_T1S_SERVICE_MS");
const RESET_WAIT_MS: u32 = u32_from_build!("WZ_T1S_RESET_WAIT_MS");

/// The build was made with `overlays/t2g_t1s_build_values.conf`: its PLCA id, count and
/// address are numbers made up so that Layer Qzb can build, and describe no segment.
const BUILD_VALUES_ONLY: bool = u32_from_build!("WZ_T1S_BUILD_VALUES") != 0;

/// The PLCA setting the lab stated. The build has already refused an id above 254, a
/// count of 0 and a count not above the id; the checks below make the same refusals
/// part of the compile, so that a build that bypassed CMake does not run on a value
/// the chip crate would only refuse at boot.
const PLCA: Plca = if u32_from_build!("WZ_T1S_PLCA_ON") == 0 {
    Plca::Off
} else {
    plca_node(
        u32_from_build!("WZ_T1S_PLCA_ID"),
        u32_from_build!("WZ_T1S_PLCA_COUNT"),
    )
};

/// PLCA as node `id` of `count`, refusing at compile time what no segment can have.
const fn plca_node(id: u32, count: u32) -> Plca {
    assert!(id <= 254, "a PLCA node id is 0 to 254");
    assert!(count != 0 && count < 256, "a PLCA node count is 1 to 255");
    assert!(count > id, "the node count must exceed the node id");
    Plca::Node {
        id: id as u8,
        count: count as u8,
    }
}

const ACCEPT_ALL_MULTICAST: bool = u32_from_build!("WZ_T1S_MULTICAST") != 0;

/// The chip crate's own check of the stated configuration, made at compile time with
/// a placeholder station address (a locally administered unicast one, which is valid
/// by construction; the real one is drawn or given and is checked at boot).
const _: () = {
    let probe = Config {
        mac_address: [0x02, 0, 0, 0, 0, 0x01],
        plca: PLCA,
        accept_all_multicast: ACCEPT_ALL_MULTICAST,
        accept_newer_revisions: false,
    };
    match probe.validate() {
        Ok(()) => {}
        Err(_) => panic!("the 10BASE-T1S configuration the build states is refused"),
    }
};

/// The chip crate's configuration for station address `mac_address`.
///
/// A part newer than the documents the chip crate grades is refused
/// (`accept_newer_revisions` is off): turning it on is a decision to be made after
/// reading the current configuration note against the crate's copy of its sequence,
/// and not one a build should make by default.
fn config(mac_address: [u8; 6]) -> Config {
    Config {
        mac_address,
        plca: PLCA,
        accept_all_multicast: ACCEPT_ALL_MULTICAST,
        accept_newer_revisions: false,
    }
}

fn now_us() -> u64 {
    ZephyrClock::<TICK_HZ>.now_us()
}

fn irq_asserted() -> bool {
    // SAFETY: the board's read of a pin; no arguments, no state.
    unsafe { wz_board_t1s_irq_asserted() }
}

/// Reset the chip through its reset line, and wait until it is ready. See step 3 of
/// the module documentation.
fn reset_by_line(lines: u32) -> Result<(), &'static CStr> {
    // SAFETY: the board's drive of a pin it routed in `wz_board_t1s_lines_init`.
    unsafe { wz_board_t1s_reset_set(true) };
    delay_us(RESET_HOLD_US);
    // SAFETY: as above.
    unsafe { wz_board_t1s_reset_set(false) };

    let deadline_us = now_us() + u64::from(RESET_WAIT_MS) * 1000;
    if lines & LINE_IRQ == 0 {
        // No signal to wait for: the whole wait is the bound.
        while now_us() < deadline_us {
            delay_us(IRQ_POLL_US);
        }
        return Ok(());
    }
    while !irq_asserted() {
        if now_us() >= deadline_us {
            return Err(c"wz: FAIL - the LAN865x did not signal the end of its reset on IRQ_N");
        }
        delay_us(IRQ_POLL_US);
    }
    Ok(())
}

/// The reason, on the console, that the chip could not be opened; and the line that
/// stops the node.
fn refuse(error: OpenError<wz_spi_scb::Error<i32>>) -> &'static CStr {
    match error {
        OpenError::Config(why) => {
            log_line(format!("wz: t1s: the configuration was refused: {why:?}"));
            c"wz: FAIL - the 10BASE-T1S configuration was refused"
        }
        OpenError::Identity(why) => {
            log_line(format!("wz: t1s: DEVID names no LAN8650/1: {why:?}"));
            c"wz: FAIL - what answers on the MikroBUS socket is not a LAN8650/1"
        }
        OpenError::RevisionNotAccepted(found) => {
            log_line(format!(
                "wz: t1s: the part is a revision no document grades: {found:?}"
            ));
            c"wz: FAIL - the LAN865x is a silicon revision this build does not accept"
        }
        OpenError::Bus(why) => {
            log_line(format!(
                "wz: t1s: the bus failed during the bring-up: {why:?}"
            ));
            c"wz: FAIL - the LAN865x bring-up failed on the SPI bus"
        }
    }
}

/// The chip crate's MAC over the kit's SPI master, with the board's delay and clock
/// as plain functions.
type Mac = PacedMac<ScbSpi<Scb3>, fn(u32), fn() -> u64>;

/// The chip, as the lwIP backend holds it: the chip crate's MAC with its
/// housekeeping paced.
pub struct T1sMac {
    inner: Mac,
}

impl EthernetMac for T1sMac {
    fn mac_address(&self) -> [u8; 6] {
        self.inner.mac_address()
    }

    fn transmit(&mut self, frame: &[u8]) -> bool {
        self.inner.transmit(frame)
    }

    fn receive(&mut self, buf: &mut [u8]) -> Option<usize> {
        self.inner.receive(buf)
    }
}

impl BoardMac for T1sMac {
    /// The chip's housekeeping runs on the cadence it was opened with, on the same
    /// kernel clock this call's argument is read from, so the argument is not needed.
    fn service(&mut self, _now_ms: u64) {
        match self.inner.service() {
            ServiceEvent::Quiet => {}
            ServiceEvent::Report(report) => log_line(format!(
                "zephyr-admin-node: t1s: reconfigured {}, status0 {:#04x}, phy status {:#06x}",
                report.reconfigured, report.status0, report.phy_status
            )),
            ServiceEvent::Failed(why) => log_line(format!(
                "zephyr-admin-node: t1s: housekeeping failed, not reported again until it \
                 recovers: {why:?}"
            )),
            ServiceEvent::Recovered(report) => log_line(format!(
                "zephyr-admin-node: t1s: housekeeping recovered after {} failure(s), \
                 reconfigured {}, status0 {:#04x}, phy status {:#06x}",
                self.inner.failures(),
                report.reconfigured,
                report.status0,
                report.phy_status
            )),
        }
    }
}

/// Bring the chip up as the interface with station address `mac_address`. See the
/// module documentation for the order.
pub fn open(mac_address: [u8; 6]) -> Result<T1sMac, &'static CStr> {
    if BUILD_VALUES_ONLY {
        // Said once and first, before anything a lab would be reading for: an image
        // like this has configured a segment with numbers nobody chose.
        log_line(format!(
            "wz: FAIL - this image was built with made-up values for a build, not a lab's: \
             PLCA {PLCA:?} and address {} describe no segment (overlays/t2g_t1s_build_values.conf)",
            env!("WZ_T1S_IPV4")
        ));
    }
    // SAFETY: the board's routing of the pins; no arguments.
    let lines = unsafe { wz_board_t1s_lines_init() };
    log_line(format!(
        "wz: t1s: reset line {}, interrupt line {}",
        if lines & LINE_RESET != 0 {
            "wired"
        } else {
            "not wired"
        },
        if lines & LINE_IRQ != 0 {
            "wired"
        } else {
            "not wired"
        }
    ));
    let (spi, rate) = spi_cyt4bf::open(SpiMode::Mode0, SPI_HZ)?;
    log_line(format!(
        "wz: t1s: SCB3, mode 0, {} Hz (divider {}, oversample {})",
        rate.achieved_hz, rate.divider, rate.oversample
    ));
    if lines & LINE_RESET != 0 {
        reset_by_line(lines)?;
    }
    let mut inner = PacedMac::open(
        spi,
        &config(mac_address),
        delay_us as fn(u32),
        now_us as fn() -> u64,
        SERVICE_MS,
    )
    .map_err(refuse)?;
    let identity = inner.identity();
    log_line(format!(
        "wz: t1s: {:?} revision {:?}, PLCA {}",
        identity.product,
        identity.revision,
        match PLCA {
            Plca::Off => alloc::string::String::from("off"),
            Plca::Node { id: 0, count } => format!("coordinator, {count} node(s)"),
            Plca::Node { id, count } => format!("follower {id}, count {count}"),
        }
    ));
    if lines & LINE_IRQ != 0 {
        inner.set_interrupt_probe(irq_asserted);
    }
    Ok(T1sMac { inner })
}
