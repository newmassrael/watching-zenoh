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
//! 100 seconds, with the core running and idle and no fault: the M7 ran at the 8 MHz
//! oscillator where 350 MHz was built in, so every wait lasted about 44 times what
//! it was told. The image now checks the core clock before it waits for anything
//! (`wz_runtime_zephyr::core_clock`), and the MAC driver bounds its waits on the
//! kernel clock instead of counting the waits it asked for. The stage lines below,
//! each with the kernel's own uptime, stay: a bench reads them beside a wall clock,
//! and the two agree only if the kernel's time base is what the build assumed.

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

/// Receive buffers the DMA area holds: one per descriptor, or none when the
/// receive ring draws them from the receive pool (`CONFIG_WZ_CYT4BF_RX_POOL`).
#[cfg(not(feature = "rx-pool"))]
const RX_BUFS: usize = RX_SLOTS;
#[cfg(feature = "rx-pool")]
const RX_BUFS: usize = 0;

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
static mut DMA: DmaArea<RX_SLOTS, TX_SLOTS, RX_BUFS> = DmaArea::new();

/// `DMA` may be handed out once.
static DMA_TAKEN: AtomicBool = AtomicBool::new(false);

/// ARCHITECTURE section 9.1 -- the transmit pool the node's datagrams are encoded
/// into and the MAC reads in place (`CONFIG_WZ_CYT4BF_TX_POOL`), in the same
/// non-cacheable section as the rings, for the same reasons: the controller reads
/// it behind the CPU's back, and this board cleans no cache. `NOLOAD` too, so it
/// holds nothing until `tx_pool::install` writes all of it.
#[cfg(feature = "tx-pool")]
#[link_section = ".nocache"]
static mut TX_POOL: wz_link_lwip::tx_pool::TxPoolStorage =
    wz_link_lwip::tx_pool::TxPoolStorage::uninit();

/// ARCHITECTURE section 9.2 -- the receive pool the MAC's receive descriptors are
/// armed with (`CONFIG_WZ_CYT4BF_RX_POOL`), in the same non-cacheable section as the
/// rings, for the same reasons: the controller writes it behind the CPU's back, and
/// this board invalidates no cache. `NOLOAD` too, so it holds nothing until
/// `mac_rx_pool::install` writes all of it.
#[cfg(feature = "rx-pool")]
#[link_section = ".nocache"]
static mut RX_POOL: wz_link_lwip::mac_rx_pool::RxPoolStorage =
    wz_link_lwip::mac_rx_pool::RxPoolStorage::uninit();

#[cfg(any(feature = "tx-pool", feature = "rx-pool"))]
extern "C" {
    /// The bounds of the non-cacheable section, from Zephyr's linker script
    /// (`include/zephyr/arch/common/nocache.ld`, `CONFIG_NOCACHE_MEMORY`). Read only
    /// for their addresses, which the console line prints beside the pool's.
    static _nocache_ram_start: u8;
    static _nocache_ram_end: u8;
}

/// The bounds of the non-cacheable section, as addresses.
#[cfg(any(feature = "tx-pool", feature = "rx-pool"))]
fn nocache_section() -> (usize, usize) {
    // Only the addresses of the linker's symbols are taken, never their contents.
    (
        core::ptr::addr_of!(_nocache_ram_start) as usize,
        core::ptr::addr_of!(_nocache_ram_end) as usize,
    )
}

/// How often the transmit counts are printed when they have moved.
#[cfg(feature = "tx-pool")]
const TX_REPORT_MS: u64 = 10_000;

/// How often the receive counts are printed when they have moved.
#[cfg(feature = "rx-pool")]
const RX_REPORT_MS: u64 = 10_000;

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
    inner: Cyt4bfMac<Cyt4bfBoard, RX_SLOTS, TX_SLOTS, RX_BUFS>,
    /// When the transmit counts are next looked at, and what they were when last
    /// printed.
    #[cfg(feature = "tx-pool")]
    next_tx_report_ms: u64,
    #[cfg(feature = "tx-pool")]
    tx_reported: Option<TxReport>,
    /// Likewise for the receive counts.
    #[cfg(feature = "rx-pool")]
    next_rx_report_ms: u64,
    #[cfg(feature = "rx-pool")]
    rx_reported: Option<RxReport>,
}

/// What a receive-pool line says: the MAC's counts, the pool's free slots and
/// size, the slots the ring holds, lwIP's frames taken lent and copied, and the
/// session socket's datagrams read in place and copied.
#[cfg(feature = "rx-pool")]
type RxReport = (
    wz_eth_mac_cyt4bf::RxCounts,
    (usize, usize),
    usize,
    (u32, u32),
    (u32, u32),
);

/// What a transmit-pool line says: the MAC's counts and the pool's.
#[cfg(feature = "tx-pool")]
type TxReport = (
    wz_eth_mac_cyt4bf::TxCounts,
    wz_link_lwip::tx_pool::TxPoolStats,
);

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

    // ARCHITECTURE section 9.1, with the transmit pool: lwIP hands the MAC each
    // frame in pieces, and the MAC reads in place the ones inside the pool (the
    // only memory its board lets it read so) and copies the rest into its ring.
    // Without the pool the MAC is offered whole frames only, as before.
    #[cfg(feature = "tx-pool")]
    fn gathers_in_place(&self) -> bool {
        self.inner.gathers_in_place()
    }

    #[cfg(feature = "tx-pool")]
    unsafe fn transmit_gather(
        &mut self,
        segments: &[wz::runtime_core::TxSegment],
        cookie: u32,
    ) -> wz::runtime_core::TxGather {
        // SAFETY: the caller's contract, passed on unchanged.
        unsafe { self.inner.transmit_gather(segments, cookie) }
    }

    #[cfg(feature = "tx-pool")]
    fn reap_tx(&mut self, done: &mut dyn FnMut(u32)) {
        self.inner.reap_tx(done);
    }

    // ARCHITECTURE section 9.2, with the receive pool: the MAC lends each received
    // frame in the pool slot the controller wrote it into, lwIP reads it there, and
    // the slot comes back when lwIP (or the session socket that holds it) lets go.
    // Without the pool the MAC is asked for copies, as before: its own ring would
    // keep a descriptor out for every frame the stack held.
    #[cfg(feature = "rx-pool")]
    fn loans_rx(&self) -> bool {
        self.inner.loans_rx()
    }

    #[cfg(feature = "rx-pool")]
    fn receive_loan(&mut self) -> Option<wz::runtime_core::RxLoan> {
        self.inner.receive_loan()
    }

    #[cfg(feature = "rx-pool")]
    fn return_rx(&mut self, cookie: u32) {
        self.inner.return_rx(cookie);
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
        #[cfg(feature = "tx-pool")]
        self.report_tx(now_ms);
        #[cfg(feature = "rx-pool")]
        self.report_rx(now_ms);
    }
}

#[cfg(feature = "rx-pool")]
impl T2gMac {
    /// One console line, at most every `RX_REPORT_MS` and only when something
    /// moved, with what a bench needs to tell a frame read in its slot from a copy:
    /// the MAC's frames lent from a slot and given back, its descriptors left
    /// unarmed for want of a slot, its frames dropped and copied; the pool's free
    /// slots and the slots the ring holds; the frames lwIP took lent and copied in;
    /// and the session socket's datagrams read in place and copied.
    fn report_rx(&mut self, now_ms: u64) {
        if now_ms < self.next_rx_report_ms {
            return;
        }
        self.next_rx_report_ms = now_ms + RX_REPORT_MS;
        let (Some(pool), Some(in_ring)) =
            (self.inner.rx_pool_free(), self.inner.rx_slots_in_ring())
        else {
            return;
        };
        let now = (
            self.inner.rx_counts(),
            pool,
            in_ring,
            wz_link_lwip::ethernet::rx_frames_taken(),
            wz_link_lwip::rx_hold::counts(),
        );
        if self.rx_reported == Some(now) {
            return;
        }
        self.rx_reported = Some(now);
        let (mac, (free, size), in_ring, (taken_lent, taken_copied), (read, copied)) = now;
        log_line(format!(
            "wz: rx-pool: lent {}, returned {}, refused {}, dropped {}, copied {}; \
             pool free {}, in the ring {}, of {}; lwIP took {} lent, {} copied; \
             the session read {} in place, {} copied",
            mac.lent,
            mac.returned,
            mac.refused,
            mac.dropped,
            mac.copied,
            free,
            in_ring,
            size,
            taken_lent,
            taken_copied,
            read,
            copied,
        ));
    }
}

/// Install the receive pool and say where it is, beside the bounds of the section
/// it is in. Returns the pool, for the MAC to arm its receive ring with.
#[cfg(feature = "rx-pool")]
fn install_rx_pool() -> &'static mut wz_link_lwip::mac_rx_pool::EthRxRing {
    use wz::runtime_core::MacRxPool;
    // SAFETY: called once, from `open`, after `DMA_TAKEN` made `open` itself run
    // once; nothing else names the static.
    let storage = unsafe { &mut *core::ptr::addr_of_mut!(RX_POOL) };
    let pool = wz_link_lwip::mac_rx_pool::install(storage);
    let (start, len) = pool.span();
    let (section_start, section_end) = nocache_section();
    log_line(format!(
        "wz: eth0: receive pool of {} slots at {:#010x} to {:#010x}, in the non-cacheable \
         section {:#010x} to {:#010x}, written in place by the MAC",
        pool.slot_count(),
        start as usize,
        start as usize + len,
        section_start,
        section_end,
    ));
    pool
}

#[cfg(feature = "tx-pool")]
impl T2gMac {
    /// One console line, at most every `TX_REPORT_MS` and only when something
    /// moved, with what a bench needs to tell a frame read out of a pool slot from
    /// a copy: how many frames the controller read in place and how many it sent
    /// from its ring, the bus address the last in-place frame's first descriptor
    /// was written with, and the pool's own account of its slots.
    fn report_tx(&mut self, now_ms: u64) {
        if now_ms < self.next_tx_report_ms {
            return;
        }
        self.next_tx_report_ms = now_ms + TX_REPORT_MS;
        let Some(pool) = wz_link_lwip::tx_pool::stats() else {
            return;
        };
        let now = (self.inner.tx_counts(), pool);
        if self.tx_reported == Some(now) {
            return;
        }
        self.tx_reported = Some(now);
        let (mac, pool) = now;
        let last = match mac.last_in_place_bus {
            Some(bus) => format!("{bus:#010x}"),
            None => alloc::string::String::from("none"),
        };
        log_line(format!(
            "wz: tx-pool: in place {}, copied {}, last descriptor {}; pool lent {}, \
             started {}, completed {}, unarmed {}, abandoned {}, free {} of {}",
            mac.in_place,
            mac.copied,
            last,
            pool.lent,
            pool.started,
            pool.completed,
            pool.unarmed,
            pool.abandoned,
            pool.free,
            wz_link_lwip::session_tx_pool_mcu::SLOT_COUNT,
        ));
    }
}

/// Install the transmit pool and say where it is, beside the bounds of the section
/// it is in. Returns the window the MAC may read in place: the pool's slots.
#[cfg(feature = "tx-pool")]
fn install_tx_pool() -> wz_link_lwip::tx_pool::TxPoolSpan {
    // SAFETY: called once, from `open`, after `DMA_TAKEN` made `open` itself run
    // once; nothing else names the static.
    let storage = unsafe { &mut *core::ptr::addr_of_mut!(TX_POOL) };
    let span = wz_link_lwip::tx_pool::install(storage);
    // Only the addresses of the linker's symbols are taken, never their contents.
    let (section_start, section_end) = (
        core::ptr::addr_of!(_nocache_ram_start) as usize,
        core::ptr::addr_of!(_nocache_ram_end) as usize,
    );
    log_line(format!(
        "wz: eth0: transmit pool of {} slots at {:#010x} to {:#010x}, in the non-cacheable \
         section {:#010x} to {:#010x}, read in place by the MAC",
        wz_link_lwip::session_tx_pool_mcu::SLOT_COUNT,
        span.start as usize,
        span.start as usize + span.len,
        section_start,
        section_end,
    ));
    span
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
    let area: &'static mut DmaArea<RX_SLOTS, TX_SLOTS, RX_BUFS> =
        unsafe { &mut *core::ptr::addr_of_mut!(DMA) };
    // SAFETY: ETH0_BASE is the MXETH block of every CYT4BF part, used by nothing
    // else in this image, `delay_us` waits at least what it is told, and the
    // kernel's tick count never goes backwards.
    let board = unsafe { Cyt4bfBoard::new(ETH0_BASE, delay_us, now_us) };
    // With the transmit pool, the controller reads in place what lies in the pool
    // and nothing else: the pool is in the non-cacheable section, and every other
    // buffer lwIP sends from (its own heap) is cached memory this board cannot
    // clean, so those frames are copied into the ring as before.
    #[cfg(feature = "tx-pool")]
    let board = {
        let span = install_tx_pool();
        // SAFETY: the pool is in `.nocache`, system SRAM the Ethernet DMA reaches
        // (the rings beside it are read from there) and the MPU marks uncached.
        unsafe { board.with_in_place_window(span.start, span.len) }
    };
    let mut config = Config::new(mac_address);
    config.ref_clock = ref_clock;
    // With the receive pool, the controller writes received frames into the pool's
    // slots and nowhere else, and the MAC refuses a pool outside that window.
    #[cfg(feature = "rx-pool")]
    let made = {
        use wz::runtime_core::MacRxPool;
        let pool = install_rx_pool();
        let (start, len) = pool.span();
        // SAFETY: the pool is in `.nocache`, system SRAM the Ethernet DMA reaches
        // (the rings beside it are written there) and the MPU marks uncached.
        let board = unsafe { board.with_receive_window(start, len) };
        Cyt4bfMac::new_pooled(board, area, pool, &config)
    };
    #[cfg(not(feature = "rx-pool"))]
    let made = Cyt4bfMac::new(board, area, &config);
    let mut inner = made.map_err(|e| match e {
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
        wz_eth_mac_cyt4bf::InitError::RxPoolSlotTooSmall => {
            c"wz: FAIL - the receive pool's slots are smaller than the MAC's receive buffer"
        }
        wz_eth_mac_cyt4bf::InitError::RxPoolTooFewSlots => {
            c"wz: FAIL - the receive pool has fewer slots than the receive ring"
        }
        wz_eth_mac_cyt4bf::InitError::RxPoolMisaligned => {
            c"wz: FAIL - the receive pool's slots are not on 32-byte boundaries"
        }
        wz_eth_mac_cyt4bf::InitError::RxPoolOutsideWindow => {
            c"wz: FAIL - the receive pool is not where the MAC may write it in place"
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
    Ok(T2gMac {
        inner,
        #[cfg(feature = "tx-pool")]
        next_tx_report_ms: 0,
        #[cfg(feature = "tx-pool")]
        tx_reported: None,
        #[cfg(feature = "rx-pool")]
        next_rx_report_ms: 0,
        #[cfg(feature = "rx-pool")]
        rx_reported: None,
    })
}
