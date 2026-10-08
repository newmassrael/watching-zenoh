// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The CYT4BF family's ETH0, as the lwIP backend's MAC.
//!
//! `wz-eth-mac-cyt4bf` is the driver; this is the part that is the BOARD's:
//! where the registers are, where the DMA memory lives, which reference clock the
//! PHY gives, how long to wait for a link, and what the console says when the
//! link changes. The pins' routing and drive settings are C (the PDL's GPIO
//! driver, in `boards/<board>/`), run before the MAC is touched.
//!
//! Claim: this path is BUILT. No emulator carries the block. The first boot on a
//! CYT4BF printed its station address and the probe's lines and then nothing for
//! 100 seconds, with the core running and idle and no fault, so how far this path
//! gets there is not yet known: the stage lines below, each with the kernel's own
//! uptime, are what says. A bench reads them beside a wall clock; the two agree
//! only if the kernel's time base is what the build assumed.

use alloc::format;
use core::ffi::CStr;
use core::sync::atomic::{AtomicBool, Ordering};

use wz::runtime_coop::ClockSource;
use wz::runtime_core::EthernetMac;
use wz::runtime_zephyr::glue::{delay_us, log, log_line};
use wz::runtime_zephyr::ZephyrClock;
use wz_eth_mac_cyt4bf::{
    Config, Cyt4bfBoard, Cyt4bfMac, DmaArea, LinkError, LinkEvent, LinkMode, RefClock,
};

use crate::net_lwip::BoardMac;
use crate::TICK_HZ;

/// ETH0's register base: `ETH0_BASE` in the PDL's device header, the same address
/// on every CYT4BF part (the `CYT4BF8CDS` the Zephyr board names and the
/// `CYT4BF8CEE` that is on a bench differ in FlexRay and nothing on Ethernet).
const ETH0_BASE: usize = 0x4048_0000;

/// Receive and transmit slots: eight 1536-byte buffers in, four out, ~18 KiB.
const RX_SLOTS: usize = 8;
const TX_SLOTS: usize = 4;

/// The DMA memory, in Zephyr's non-cacheable section.
///
/// The controller reads and writes it behind the CPU's back, and on a Cortex-M7
/// with a data cache that is only coherent if the memory is not cached (or every
/// access is wrapped in cache maintenance, which the driver would then need per
/// descriptor). `.nocache` is the section Zephyr's linker script gathers and its
/// MPU setup marks non-cacheable when `CONFIG_NOCACHE_MEMORY` is on, the way the
/// STM32 Ethernet driver places its rings. It must be in system SRAM (the default
/// RAM region): the DMA master cannot reach DTCM.
///
/// The section is `NOLOAD` (`arch/common/nocache.ld`): the zeroes `DmaArea::new`
/// builds here are not applied at boot, and the RAM holds what it held at reset.
/// The driver therefore writes the whole area itself before it uses it.
#[link_section = ".nocache"]
static mut DMA: DmaArea<RX_SLOTS, TX_SLOTS> = DmaArea::new();

/// `DMA` may be handed out once.
static DMA_TAKEN: AtomicBool = AtomicBool::new(false);

extern "C" {
    /// Route and configure ETH0's pins for RMII (boards/<board>/*.c). 0 on
    /// success.
    fn wz_board_eth_pins_init() -> i32;
}

/// The clock every wait of the driver is bounded by: the kernel's monotonic tick
/// count, in microseconds (`ZephyrClock`, the same clock the node's own timers
/// run on). Its resolution is one kernel tick, so a bound ends up to a tick late
/// and never early. It is the kernel's own time: a bound on it is as long in wall
/// time as the kernel's tick is, which is why the image checks the core clock
/// before anything waits.
fn now_us() -> u64 {
    ZephyrClock::<TICK_HZ>.now_us()
}

/// The MAC, as the lwIP backend holds it.
pub struct T2gMac {
    inner: Cyt4bfMac<Cyt4bfBoard, RX_SLOTS, TX_SLOTS>,
}

impl EthernetMac for T2gMac {
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

impl BoardMac for T2gMac {
    fn service(&mut self, now_ms: u64) {
        match self.inner.service_link(now_ms) {
            LinkEvent::Steady => {}
            LinkEvent::Up(mode) => {
                log_line(format!("zephyr-admin-node: link up, {}", describe(mode)))
            }
            LinkEvent::Down => log(c"zephyr-admin-node: link down"),
        }
    }
}

fn describe(mode: LinkMode) -> &'static str {
    match (mode.speed_100, mode.full_duplex) {
        (true, true) => "100 Mbps full duplex",
        (true, false) => "100 Mbps half duplex",
        (false, true) => "10 Mbps full duplex",
        (false, false) => "10 Mbps half duplex",
    }
}

/// One console line saying which step of the bring-up is starting or has ended,
/// with the kernel's uptime. The uptime is the point: it is the kernel's own count
/// of how long boot has taken, so a bench that timestamps the console sees at once
/// whether the kernel's second is the wall clock's second.
fn stage(what: &str) {
    log_line(format!(
        "wz: eth0: {what} (kernel uptime {} ms)",
        crate::uptime_ms()
    ));
}

/// Bring ETH0 up: pins, MAC, PHY, and a link if one comes within `link_wait_ms`.
///
/// A missing link is NOT a failure: the node starts and the loop's link service
/// picks the link up when the cable goes in. Everything else is: no PHY answering
/// on the management bus, a PHY that will not reset, a management port that hangs.
pub fn open(
    mac_address: [u8; 6],
    ref_clock: RefClock,
    link_wait_ms: u32,
) -> Result<T2gMac, &'static CStr> {
    stage("routing ETH0's pins");
    // SAFETY: the board's pin routing function, with no arguments.
    if unsafe { wz_board_eth_pins_init() } != 0 {
        return Err(c"wz: FAIL - the board could not route ETH0's pins");
    }
    if DMA_TAKEN.swap(true, Ordering::AcqRel) {
        return Err(c"wz: FAIL - ETH0 was opened twice");
    }
    // SAFETY: `DMA_TAKEN` made this the only borrow of the static, and nothing
    // else names it.
    let area: &'static mut DmaArea<RX_SLOTS, TX_SLOTS> =
        unsafe { &mut *core::ptr::addr_of_mut!(DMA) };
    // SAFETY: ETH0_BASE is the MXETH block of every CYT4BF part, used by nothing
    // else in this image, `delay_us` waits at least what it is told, and the
    // kernel's tick count never goes backwards.
    let board = unsafe { Cyt4bfBoard::new(ETH0_BASE, delay_us, now_us) };
    let mut config = Config::new(mac_address);
    config.ref_clock = ref_clock;
    let mut inner = Cyt4bfMac::new(board, area, &config).map_err(|e| match e {
        wz_eth_mac_cyt4bf::InitError::InvalidMac => {
            c"wz: FAIL - the MAC address is multicast or zero"
        }
        wz_eth_mac_cyt4bf::InitError::InvalidRefDivider => {
            c"wz: FAIL - the reference clock divider is outside 1 to 256"
        }
        wz_eth_mac_cyt4bf::InitError::RingTooSmall => c"wz: FAIL - a descriptor ring is too small",
        wz_eth_mac_cyt4bf::InitError::UnknownDmaBusWidth(field) => {
            // The static message cannot carry the value, and the value is what a
            // bench needs to see.
            log_line(format!(
                "wz: eth0: DESIGNCFG_DEBUG1 DMA_BUS_WIDTH reads {field}; the driver knows 1, 2 and 4"
            ));
            c"wz: FAIL - the MAC's DMA bus width is not one this driver knows"
        }
    })?;
    stage(&format!(
        "MAC initialised; finding the PHY, then waiting up to {link_wait_ms} ms for a link"
    ));
    let outcome = inner.bring_up_link(link_wait_ms.saturating_mul(1000));
    stage("link bring-up returned");
    match outcome {
        Ok(mode) => log_line(format!("zephyr-admin-node: link up, {}", describe(mode))),
        Err(LinkError::NoLink) => {
            log(c"zephyr-admin-node: no link yet; the node starts and waits for one")
        }
        Err(LinkError::NoPhy) => return Err(c"wz: FAIL - no PHY answered on the management bus"),
        Err(LinkError::ResetTimeout) => return Err(c"wz: FAIL - the PHY did not finish its reset"),
        Err(LinkError::Mdio(_)) => return Err(c"wz: FAIL - the management port never went idle"),
        Err(LinkError::UnresolvedMode) => {
            return Err(c"wz: FAIL - the link partner advertises nothing this driver can resolve")
        }
    }
    Ok(T2gMac { inner })
}
