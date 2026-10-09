// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

#![no_std]

//! The Ethernet MAC of Infineon's CYT4BF (T2G body, high) family, as a
//! [`wz_runtime_core::EthernetMac`].
//!
//! The `MXETH` block is a Cadence GEM_GXL behind a small wrapper. This driver
//! runs it POLLED, with one descriptor ring each way over a [`DmaArea`] the board
//! places in non-cacheable memory, and presents it as the frame-at-a-time seam a
//! network stack (lwIP's `ethernetif` through `wz-link-lwip`) drives. Receive
//! copies out of the ring; handing the ring's buffer up without the copy is the
//! `RxSlots` seam's job.
//!
//! ## What is the driver's and what is the board's
//!
//! The driver programs the MAC, the DMA and the rings, speaks clause 22 to the PHY
//! and applies what negotiation resolved. The BOARD supplies everything that is
//! wiring or clocking: the register base, the way to wait and the monotonic clock
//! every wait is bounded by (a wait promises only "at least", so no bound counts
//! waits), where the DMA area lives and how addresses look to a bus master
//! ([`Board`]), the pins' HSIOM and drive settings, which reference clock the PHY
//! gives, and the PHY's reset line. Nothing here names a board, a PHY part or a
//! PHY address: the address is found by scanning, or given.
//!
//! ## What is claimed
//!
//! BUILT. No emulator models this block. A bench kit has run the driver since, and
//! that run found the bus-width defect below, but no ledger record grades it above
//! BUILT. The host tests drive the driver against a model of the controller written
//! from the same documents it was written from, and started from the register
//! values that kit read, which checks the ring logic and the order of register
//! programming, not the documents. The driver says so in its own manifest and the
//! board table grades its rows accordingly.
//!
//! ## The DMA data bus width is the hardware's statement
//!
//! `NETWORK_CONFIG.DATA_BUS_WIDTH` has to agree with the width the block was
//! built with, which `DESIGNCFG_DEBUG1.DMA_BUS_WIDTH` states. The driver reads the
//! second and programs the first from it, and refuses a design value that is not
//! 1, 2 or 4 ([`InitError::UnknownDmaBusWidth`]). It does not assume a width: the
//! configuration register is written whole, and a field it does not name is
//! written as zero (32 bits), which on a 64-bit design stopped the transmit DMA
//! with an AMBA error at the first frame and made the receive DMA keep every other
//! 32-bit word. A CYT4BF8CEE kit read the design field as 2 (64 bits), and both
//! defects vanished with the field set to 1. That is the ONE width seen on silicon:
//! 32 and 128 bits follow from the same encodings (the PDL's Cadence core driver,
//! `cedi.h` and `edd.c`) and are untested on this chip.
//!
//! ## Provenance
//!
//! The register map and the order of the bring-up come from Infineon's PDL
//! (release-v3.23.0: `cy_ethif.c`, its Cadence core driver and `cyip_eth.h`,
//! Apache-2.0), read as a reference; the code is new. The two delays after a
//! management access (800 us after a read, 200 us after a write) are the PDL's own
//! and are kept for the reason it keeps them: the shift register reports idle
//! before the data is settled.

pub mod dma;
pub mod phy;
pub mod regs;

use core::ptr::{addr_of_mut, NonNull};
use core::sync::atomic::{fence, Ordering};

pub use dma::{DmaArea, BUF_LEN};
pub use phy::{LinkError, LinkMode, MdioError};
use wz_runtime_core::{join_segments, EthernetMac, RxLoan, TxGather, TxSegment};

use dma::{Buffer, Descriptor, Slot, RX_BUF_UNITS};
use regs::*;

/// What the driver needs from the board.
pub trait Board {
    /// Read the 32-bit register at `offset` from the block's base.
    fn read(&mut self, offset: usize) -> u32;
    /// Write the 32-bit register at `offset` from the block's base.
    fn write(&mut self, offset: usize, value: u32);
    /// The address the DMA master sees for CPU address `ptr`. Identity on this
    /// chip for system SRAM; DTCM is not reachable by the DMA at all, which is why
    /// the area must not be placed there.
    fn bus_address(&self, ptr: *const u8) -> u32;
    /// Write the cache lines covering `[ptr, ptr + len)` back to memory, before
    /// the controller reads them. A no-op for non-cacheable memory.
    fn clean(&mut self, _ptr: *const u8, _len: usize) {}
    /// Drop the cache lines covering `[ptr, ptr + len)`, before the CPU reads what
    /// the controller wrote. A no-op for non-cacheable memory.
    fn invalidate(&mut self, _ptr: *const u8, _len: usize) {}
    /// Wait AT LEAST `us` microseconds. A wait promises no upper bound, and on a
    /// board whose time base runs slow it lasts many times what was asked, so the
    /// driver never adds up the waits it asked for to measure how long it has
    /// waited: that is [`now_us`](Self::now_us)'s job.
    fn delay_us(&mut self, us: u32);
    /// Microseconds on a monotonic clock: never decreasing, counted from any fixed
    /// instant. Every bound in this driver (the management port going idle, the
    /// PHY's reset, the link coming up) is the difference of two readings of it,
    /// and [`delay_us`](Self::delay_us) is only how the driver waits between
    /// looks. A clock coarser than a microsecond makes a bound end up to one step
    /// late and never early.
    fn now_us(&mut self) -> u64;
}

/// The board of a running chip: volatile MMIO at `base`, identity bus addresses,
/// no cache maintenance (the area lives in non-cacheable memory), a delay and a
/// monotonic clock the firmware provides.
pub struct Cyt4bfBoard {
    base: usize,
    delay: fn(u32),
    now: fn() -> u64,
}

impl Cyt4bfBoard {
    /// # Safety
    /// `base` must be the address of an `MXETH` block (ETH0 is `0x4048_0000` on
    /// the CYT4BF), exclusively this driver's, `delay` must wait at least the
    /// microseconds it is given, and `now` must return microseconds on a clock
    /// that never goes backwards.
    pub const unsafe fn new(base: usize, delay: fn(u32), now: fn() -> u64) -> Self {
        Self { base, delay, now }
    }
}

impl Board for Cyt4bfBoard {
    fn read(&mut self, offset: usize) -> u32 {
        // SAFETY: `new`'s contract; 32-bit registers at word-aligned offsets.
        unsafe { core::ptr::read_volatile((self.base + offset) as *const u32) }
    }

    fn write(&mut self, offset: usize, value: u32) {
        // SAFETY: as `read`.
        unsafe { core::ptr::write_volatile((self.base + offset) as *mut u32, value) }
    }

    fn bus_address(&self, ptr: *const u8) -> u32 {
        ptr as usize as u32
    }

    fn delay_us(&mut self, us: u32) {
        (self.delay)(us);
    }

    fn now_us(&mut self) -> u64 {
        (self.now)()
    }
}

/// Where the RMII reference clock comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefClock {
    /// From the HSIO pin: the PHY supplies it. A board whose PHY has its own
    /// crystal and drives REF_CLK takes this.
    External,
    /// From the internal PLL, divided by `divider` (1 to 256).
    InternalPll { divider: u16 },
}

/// The MDC divider: the management clock is the bus clock over this, and must
/// stay under 2.5 MHz.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MdcDiv {
    By8 = 0,
    By16 = 1,
    By32 = 2,
    By48 = 3,
    By64 = 4,
    By96 = 5,
    By128 = 6,
    By224 = 7,
}

/// The AMBA burst the DMA attempts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DmaBurst {
    /// Always single beats: slowest, and valid on any bus.
    Single = 0x01,
    Incr4 = 0x04,
    Incr8 = 0x08,
    Incr16 = 0x10,
}

/// How the MAC is brought up.
#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// This station's address: unicast, non-zero.
    pub mac_address: [u8; 6],
    pub ref_clock: RefClock,
    /// The default is the slowest divider, which is under 2.5 MHz for any bus
    /// clock up to 560 MHz; a board that wants faster scans names its own.
    pub mdc_div: MdcDiv,
    pub dma_burst: DmaBurst,
    /// Accept every multicast frame (the hash filter all ones). A node that does
    /// zenoh multicast scouting needs it; a unicast-only node can refuse it.
    pub accept_all_multicast: bool,
    /// The PHY's management address when the board knows it; `None` scans.
    pub phy_address: Option<u8>,
}

impl Config {
    /// External reference clock, the slowest MDC, single-beat DMA, all
    /// multicast accepted, PHY found by scan.
    pub const fn new(mac_address: [u8; 6]) -> Self {
        Self {
            mac_address,
            ref_clock: RefClock::External,
            mdc_div: MdcDiv::By224,
            dma_burst: DmaBurst::Single,
            accept_all_multicast: true,
            phy_address: None,
        }
    }
}

/// Why [`Cyt4bfMac::new`] refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitError {
    /// The station address is a multicast address or all zeros.
    InvalidMac,
    /// The PLL divider is outside 1 to 256.
    InvalidRefDivider,
    /// A ring needs at least two slots.
    RingTooSmall,
    /// `DESIGNCFG_DEBUG1.DMA_BUS_WIDTH` holds something other than 1, 2 or 4, the
    /// three one-hot widths (32, 64 and 128 bits). The value is carried. The DMA
    /// moves data correctly only when the bus width it is told agrees with the
    /// design, and a value that names no width cannot be turned into one: a
    /// block that does not answer (all ones) reads this way too.
    UnknownDmaBusWidth(u32),
}

/// The `NETWORK_CONFIG.DATA_BUS_WIDTH` value that agrees with the DMA bus width a
/// `DESIGNCFG_DEBUG1` value states, or the error naming what it held.
///
/// The two registers encode the width differently: the design register is one-hot
/// (1, 2, 4 for 32, 64, 128 bits) and the configuration field counts (0, 1, 2).
/// The 64-bit case, design 2 and field 1, was MEASURED on a CYT4BF8CEE kit. The
/// 32-bit and 128-bit cases follow from the same two encodings, as the PDL's
/// Cadence core driver states them (`cedi.h`, `edd.c`), and have not been seen
/// on this chip.
fn data_bus_width_field(design_debug1: u32) -> Result<u32, InitError> {
    let design = (design_debug1 >> DESIGN_DMA_BUS_WIDTH_POS) & DESIGN_DMA_BUS_WIDTH_MASK;
    match design {
        DESIGN_BUS_32 => Ok(NWCFG_BUS_32),
        DESIGN_BUS_64 => Ok(NWCFG_BUS_64),
        DESIGN_BUS_128 => Ok(NWCFG_BUS_128),
        other => Err(InitError::UnknownDmaBusWidth(other)),
    }
}

/// Whether the link is known to be up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    /// The link was never brought up or serviced: the driver sends anyway.
    Unknown,
    Down,
    Up(LinkMode),
}

/// What a [`Cyt4bfMac::service_link`] pass found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkEvent {
    /// Not time yet, or nothing changed.
    Steady,
    /// The link came up, or came back in a different mode, and the MAC now
    /// matches it.
    Up(LinkMode),
    /// The link went down.
    Down,
}

/// The management port was idle-polled this long, on the board's clock, before
/// giving up.
const MDIO_BUDGET_US: u32 = 10_000;
/// How long the driver waits between two looks at the management port.
const MDIO_POLL_US: u32 = 10;
/// Kept from the PDL: the shift register reports idle before read data settles.
const MDIO_READ_SETTLE_US: u32 = 800;
/// Kept from the PDL: likewise after a write.
const MDIO_WRITE_SETTLE_US: u32 = 200;
/// How often [`Cyt4bfMac::service_link`] touches the PHY.
const LINK_POLL_MS: u64 = 250;

/// The CYT4BF Ethernet MAC, as an [`EthernetMac`].
pub struct Cyt4bfMac<B: Board, const RX: usize, const TX: usize> {
    board: B,
    area: NonNull<DmaArea<RX, TX>>,
    mac: [u8; 6],
    /// What `NETWORK_CONTROL` holds, less the command bits.
    network_control: u32,
    rx_head: usize,
    /// The next transmit descriptor software will fill.
    tx_head: usize,
    /// The oldest descriptor not yet given back to software: the first
    /// descriptor of the oldest frame queued and not reclaimed.
    tx_tail: usize,
    /// How many descriptors lie from `tx_tail` up to `tx_head`.
    tx_inflight: usize,
    /// For each frame queued and not reclaimed, indexed by its FIRST descriptor:
    /// how many descriptors it took, and the caller's cookie when the controller
    /// reads it in place.
    chains: [Chain; TX],
    /// Which receive slots hold a frame lent out in place
    /// ([`EthernetMac::receive_loan`]): their buffers are the stack's to read and
    /// stay out of the controller's reach until [`EthernetMac::return_rx`].
    rx_loaned: [bool; RX],
    phy: Option<u8>,
    link: LinkState,
    next_link_poll_ms: u64,
    tx_recoveries: u32,
}

/// One frame in the transmit ring.
#[derive(Clone, Copy)]
struct Chain {
    /// Descriptors the frame occupies; `0` marks a first-descriptor index no
    /// frame starts at.
    ndesc: u16,
    /// `Some` when the controller reads the frame IN PLACE: the caller is owed a
    /// report ([`EthernetMac::reap_tx`]) when it no longer does.
    cookie: Option<u32>,
}

impl Chain {
    const EMPTY: Chain = Chain {
        ndesc: 0,
        cookie: None,
    };
}

// SAFETY: the driver owns its `DmaArea` exclusively (it took the `&'static mut`);
// moving it between threads moves that ownership with it.
unsafe impl<B: Board + Send, const RX: usize, const TX: usize> Send for Cyt4bfMac<B, RX, TX> {}

impl<B: Board, const RX: usize, const TX: usize> Cyt4bfMac<B, RX, TX> {
    /// Program the wrapper, the MAC, the DMA and both rings, and enable receive,
    /// transmit and the management port. The link is NOT brought up: call
    /// [`bring_up_link`](Self::bring_up_link).
    pub fn new(
        mut board: B,
        area: &'static mut DmaArea<RX, TX>,
        config: &Config,
    ) -> Result<Self, InitError> {
        if RX < 2 || TX < 2 {
            return Err(InitError::RingTooSmall);
        }
        if config.mac_address[0] & 1 != 0 || config.mac_address == [0; 6] {
            return Err(InitError::InvalidMac);
        }
        // The area is written before anything else is done with it, whatever the
        // image or the loader did or did not put there.
        area.clear();
        let ref_clock_bits = match config.ref_clock {
            RefClock::External => 0,
            RefClock::InternalPll { divider } => {
                if !(1..=256).contains(&divider) {
                    return Err(InitError::InvalidRefDivider);
                }
                (1 << CTL_REFCLK_SRC_SEL_POS) | ((u32::from(divider) - 1) << CTL_REFCLK_DIV_POS)
            }
        };

        // 1. The wrapper: RMII and the reference clock first, and ENABLED last,
        //    because the GEM registers answer only once the block is enabled.
        let mode = (CTL_ETH_MODE_RMII << CTL_ETH_MODE_POS) | ref_clock_bits;
        board.write(CTL, mode);
        board.write(CTL, mode | CTL_ENABLED);

        // 1b. The DMA data bus width is the design's, and the design states it in
        //     a register that answers once the block is enabled. It is read before
        //     any GEM register is written, so a design this driver cannot name
        //     leaves the controller exactly as it was found.
        let bus_width = data_bus_width_field(board.read(DESIGNCFG_DEBUG1))?;

        let mut mac = Self {
            board,
            area: NonNull::from(area),
            mac: config.mac_address,
            network_control: NWCTRL_MAN_PORT_EN,
            rx_head: 0,
            tx_head: 0,
            tx_tail: 0,
            tx_inflight: 0,
            chains: [Chain::EMPTY; TX],
            rx_loaned: [false; RX],
            phy: config.phy_address,
            link: LinkState::Unknown,
            next_link_poll_ms: 0,
            tx_recoveries: 0,
        };

        // 2. Quiesce: nothing runs while the registers are set up.
        mac.board.write(NETWORK_CONTROL, 0);

        // 3. The network configuration: 100 Mbps full duplex until negotiation
        //    says otherwise, 1536-byte frames, FCS stripped, the DMA bus width the
        //    design stated, and the multicast hash filter on when every multicast
        //    frame is wanted. The register is written whole, so the bus width is
        //    named here: left out, it is written as zero (32 bits), which on a
        //    64-bit design stopped the transmit DMA with an AMBA error and made the
        //    receive DMA keep every other word.
        let mut netcfg = NWCFG_SPEED_100
            | NWCFG_FULL_DUPLEX
            | NWCFG_RECEIVE_1536
            | NWCFG_FCS_REMOVE
            | (bus_width << NWCFG_DATA_BUS_WIDTH_POS)
            | ((config.mdc_div as u32) << NWCFG_MDC_DIV_POS);
        if config.accept_all_multicast {
            netcfg |= NWCFG_MULTICAST_HASH_ENABLE;
        }
        mac.board.write(NETWORK_CONFIG, netcfg);

        // 4. The DMA: burst, the block's full packet buffers (the PDL's own
        //    values: 4 KiB transmit, 8 KiB receive), the receive buffer size in
        //    units of 64, and errored frames discarded by the controller.
        mac.board.write(
            DMA_CONFIG,
            ((config.dma_burst as u32) << DMACFG_AMBA_BURST_POS)
                | (3 << DMACFG_RX_PBUF_SIZE_POS)
                | (1 << DMACFG_TX_PBUF_SIZE_POS)
                | (RX_BUF_UNITS << DMACFG_RX_BUF_SIZE_POS)
                | DMACFG_FORCE_DISCARD_ON_ERR,
        );

        // 5. The block has three queues each way and this driver uses the first:
        //    the others are disabled, as the PDL does for queues it does not use,
        //    or their DMA would chase pointers nobody set.
        for q in [
            TRANSMIT_Q1_PTR,
            TRANSMIT_Q2_PTR,
            RECEIVE_Q1_PTR,
            RECEIVE_Q2_PTR,
        ] {
            mac.board.write(q, QPTR_DISABLE);
        }

        // 6. Polled: no interrupt enabled, and no stale status.
        mac.board.write(INT_DISABLE, 0xFFFF_FFFF);
        mac.board.write(INT_STATUS, 0xFFFF_FFFF);
        mac.board.write(TRANSMIT_STATUS, TXSR_ALL);
        mac.board.write(RECEIVE_STATUS, RXSR_ALL);

        // 7. The filters: all multicast through the hash, or none; and this
        //    station's address in the first specific-address register.
        let hash = if config.accept_all_multicast {
            0xFFFF_FFFF
        } else {
            0
        };
        mac.board.write(HASH_BOTTOM, hash);
        mac.board.write(HASH_TOP, hash);
        let m = config.mac_address;
        mac.board.write(
            SPEC_ADD1_BOTTOM,
            u32::from_le_bytes([m[0], m[1], m[2], m[3]]),
        );
        mac.board
            .write(SPEC_ADD1_TOP, u32::from(m[4]) | (u32::from(m[5]) << 8));

        // 8. The rings, and the controller pointed at them.
        mac.init_rx_ring();
        mac.init_tx_ring();
        let rx0 = mac.rx_slot(0).0 as *const u8;
        let tx0 = mac.tx_slot(0).0 as *const u8;
        let (rx_bus, tx_bus) = (mac.board.bus_address(rx0), mac.board.bus_address(tx0));
        mac.board.write(RECEIVE_Q_PTR, rx_bus & !QPTR_DISABLE);
        mac.board.write(TRANSMIT_Q_PTR, tx_bus & !QPTR_DISABLE);

        // 9. Go.
        mac.network_control |= NWCTRL_ENABLE_RECEIVE | NWCTRL_ENABLE_TRANSMIT;
        mac.board.write(NETWORK_CONTROL, mac.network_control);
        Ok(mac)
    }

    // ---- ring geometry -----------------------------------------------------

    fn rx_slot(&self, i: usize) -> Slot {
        // SAFETY: `i < RX` at every call; the area is live and ours.
        unsafe {
            let base = addr_of_mut!((*self.area.as_ptr()).rx_desc) as *mut Descriptor;
            Slot(base.add(i))
        }
    }

    fn tx_slot(&self, i: usize) -> Slot {
        // SAFETY: `i < TX` at every call; the area is live and ours.
        unsafe {
            let base = addr_of_mut!((*self.area.as_ptr()).tx_desc) as *mut Descriptor;
            Slot(base.add(i))
        }
    }

    fn rx_buf(&self, i: usize) -> *mut u8 {
        // SAFETY: as `rx_slot`.
        unsafe {
            let base = addr_of_mut!((*self.area.as_ptr()).rx_buf) as *mut Buffer;
            base.add(i) as *mut u8
        }
    }

    fn tx_buf(&self, i: usize) -> *mut u8 {
        // SAFETY: as `tx_slot`.
        unsafe {
            let base = addr_of_mut!((*self.area.as_ptr()).tx_buf) as *mut Buffer;
            base.add(i) as *mut u8
        }
    }

    /// Send one frame of `len` bytes from a copy: `fill` writes it into the next
    /// ring slot's own buffer, and one descriptor sends it. Nothing is waiting for
    /// a copied frame, so it has no cookie and the ring takes it back on its own.
    ///
    /// `fill` is given the buffer's address and writes exactly `len <= BUF_LEN`
    /// bytes. It is called once, and only when the frame will be sent.
    fn send_copied(&mut self, len: usize, fill: impl FnOnce(*mut u8)) -> bool {
        if len == 0 || len > BUF_LEN {
            return false;
        }
        // A link known to be down would only fill the ring with frames the wire
        // then takes in a burst when it returns.
        if self.link == LinkState::Down {
            return false;
        }
        if self.board.read(TRANSMIT_STATUS) & TXSR_FATAL != 0 {
            self.recover_tx();
        }
        // Descriptors the controller has finished with come back first, so a ring
        // that was full a moment ago is not refused on stale news.
        self.reclaim(None);
        let slot = self.tx_slot(self.tx_head);
        self.board
            .invalidate(slot.0 as *const u8, core::mem::size_of::<Descriptor>());
        if self.tx_inflight == TX || slot.word1() & TXD_USED == 0 {
            // The controller still owns the next slot: the ring is full.
            return false;
        }
        let buf = self.tx_buf(self.tx_head);
        fill(buf);
        self.board.clean(buf, len);
        let wrap = if self.tx_head == TX - 1 { TXD_WRAP } else { 0 };
        slot.set_word0(self.board.bus_address(buf));
        // Clearing used (it is absent from this word) is the release to the
        // controller, so it is written last and the frame's bytes and the address
        // are made visible before it.
        fence(Ordering::Release);
        slot.set_word1((len as u32 & TXD_LEN_MASK) | TXD_LAST | wrap);
        self.board
            .clean(slot.0 as *const u8, core::mem::size_of::<Descriptor>());
        // A frame of one descriptor, copied: no one is waiting for it.
        self.chains[self.tx_head] = Chain {
            ndesc: 1,
            cookie: None,
        };
        self.tx_head = (self.tx_head + 1) % TX;
        self.tx_inflight += 1;
        // The descriptor must be visible before the kick that makes the DMA read it.
        fence(Ordering::Release);
        self.board
            .write(NETWORK_CONTROL, self.network_control | NWCTRL_TX_START);
        true
    }

    /// Hand every receive buffer to the controller; the last slot wraps.
    ///
    /// A buffer lent to the stack is NOT handed back here, because the stack is
    /// still reading it: the controller would write over it. It goes back when
    /// the stack returns it, and the ring walks past it until then.
    fn init_rx_ring(&mut self) {
        for i in 0..RX {
            if !self.rx_loaned[i] {
                self.give_rx(i);
            }
        }
        self.rx_head = 0;
    }

    /// The descriptor word of the finished frame at `rx_head`, or `None` when no
    /// finished frame is waiting there.
    ///
    /// A slot whose buffer is lent out is not finished news but an old frame the
    /// stack still holds, so it reads as nothing waiting (the ring has come all
    /// the way round to a buffer not yet returned). Otherwise, when nothing is
    /// waiting and the controller ran out of buffers, it has stopped and says so;
    /// the buffers are free again now, so the condition is cleared and it carries
    /// on with the next frame.
    fn rx_ready(&mut self) -> Option<u32> {
        let slot = self.rx_slot(self.rx_head);
        self.board
            .invalidate(slot.0 as *const u8, core::mem::size_of::<Descriptor>());
        if self.rx_loaned[self.rx_head] {
            return None;
        }
        if slot.word0() & RXD_USED == 0 {
            let status = self.board.read(RECEIVE_STATUS);
            if status & (RXSR_BUFFER_NOT_AVAILABLE | RXSR_OVERRUN) != 0 {
                self.board.write(
                    RECEIVE_STATUS,
                    status & (RXSR_BUFFER_NOT_AVAILABLE | RXSR_OVERRUN),
                );
            }
            return None;
        }
        // The used bit says the controller finished the frame; the length and the
        // bytes are read only after it was seen.
        fence(Ordering::Acquire);
        Some(slot.word1())
    }

    /// Give receive slot `i` back to the controller: its buffer address, the wrap
    /// flag on the last slot, and the used bit CLEAR, which is the release.
    fn give_rx(&mut self, i: usize) {
        let slot = self.rx_slot(i);
        let addr = self.board.bus_address(self.rx_buf(i)) & RXD_ADDR_MASK;
        let wrap = if i == RX - 1 { RXD_WRAP } else { 0 };
        slot.set_word1(0);
        // The address word carries the release, so every earlier store must be
        // visible to the controller first.
        fence(Ordering::Release);
        slot.set_word0(addr | wrap);
        self.board
            .clean(slot.0 as *const u8, core::mem::size_of::<Descriptor>());
    }

    /// Every transmit slot software-owned (used set); the last wraps. Nothing is
    /// queued afterwards.
    fn init_tx_ring(&mut self) {
        self.release_all_tx_slots();
        self.tx_head = 0;
        self.tx_tail = 0;
        self.tx_inflight = 0;
        self.chains = [Chain::EMPTY; TX];
    }

    /// Write every transmit descriptor as software-owned (used set, the last
    /// wrapping), leaving the ring's bookkeeping alone.
    fn release_all_tx_slots(&mut self) {
        for i in 0..TX {
            let slot = self.tx_slot(i);
            let wrap = if i == TX - 1 { TXD_WRAP } else { 0 };
            slot.set_word0(0);
            slot.set_word1(TXD_USED | wrap);
            self.board
                .clean(slot.0 as *const u8, core::mem::size_of::<Descriptor>());
        }
    }

    /// The transmit DMA stopped on an error: it will not move until the queue is
    /// re-armed, and the frames queued behind the failure are lost. Disable
    /// transmit, clear the status, make every slot software-owned again, point the
    /// controller at the start and enable it. This is the Cadence driver's own
    /// reset of a transmit queue (`emacResetTxQ`: disabled, all used, pointer
    /// rewritten) in this driver's terms.
    ///
    /// A frame the controller was to read IN PLACE is lost to the wire like any
    /// other, but its owner is still owed the report that the memory is free, and
    /// the DMA being stopped is exactly what makes it free. Those frames keep their
    /// place in the bookkeeping, now complete, for [`EthernetMac::reap_tx`] to
    /// report; the copied frames, which have no one waiting, are dropped. When none
    /// is left the ring restarts from its first slot as it always did; when one is,
    /// the controller is pointed at the head instead, because the descriptors
    /// between the tail and the head are still accounted for.
    fn recover_tx(&mut self) {
        self.board.write(
            NETWORK_CONTROL,
            self.network_control & !NWCTRL_ENABLE_TRANSMIT,
        );
        self.board.write(TRANSMIT_STATUS, TXSR_ALL);
        self.release_all_tx_slots();
        self.reclaim(None);
        if self.tx_inflight == 0 {
            self.tx_head = 0;
            self.tx_tail = 0;
        }
        let restart = self.tx_slot(self.tx_head).0 as *const u8;
        let bus = self.board.bus_address(restart);
        self.board.write(TRANSMIT_Q_PTR, bus & !QPTR_DISABLE);
        self.board.write(NETWORK_CONTROL, self.network_control);
        self.tx_recoveries = self.tx_recoveries.wrapping_add(1);
    }

    /// Take back the descriptors of every frame the controller has finished, oldest
    /// first, and stop at the first it has not.
    ///
    /// A frame is finished when the USED bit of its FIRST descriptor is set: that
    /// is the one the controller writes back, and the only one the Cadence driver
    /// reads (`emacFreeTxDesc`: "only test used bit state for first buffer in
    /// frame"). It leaves the later descriptors of a frame as it found them, so
    /// software marks them used itself, as that driver does, before they count as
    /// free again.
    ///
    /// With `done` the cookie of a frame read in place is reported. Without it such
    /// a frame is left where it is, still owed to [`EthernetMac::reap_tx`], and
    /// everything behind it waits too: the ring is reclaimed in order, so a caller
    /// that queues in place and never reaps is refused once the ring is full, which
    /// is the right back-pressure for memory it has not been given back.
    fn reclaim(&mut self, mut done: Option<&mut dyn FnMut(u32)>) {
        while self.tx_inflight > 0 {
            let chain = self.chains[self.tx_tail];
            if chain.cookie.is_some() && done.is_none() {
                return;
            }
            let first = self.tx_slot(self.tx_tail);
            self.board
                .invalidate(first.0 as *const u8, core::mem::size_of::<Descriptor>());
            if first.word1() & TXD_USED == 0 {
                return;
            }
            // Every descriptor between tail and head belongs to a recorded frame;
            // a record of none would leave this loop standing still, so it is
            // loud in a test and one descriptor in a build.
            debug_assert!(chain.ndesc > 0, "an in-flight descriptor with no frame");
            let ndesc = usize::from(chain.ndesc).max(1);
            for k in 1..ndesc {
                let later = self.tx_slot((self.tx_tail + k) % TX);
                later.set_word1(later.word1() | TXD_USED);
                self.board
                    .clean(later.0 as *const u8, core::mem::size_of::<Descriptor>());
            }
            if let (Some(cookie), Some(report)) = (chain.cookie, done.as_mut()) {
                report(cookie);
            }
            self.chains[self.tx_tail] = Chain::EMPTY;
            self.tx_tail = (self.tx_tail + ndesc) % TX;
            self.tx_inflight -= ndesc;
        }
    }

    /// How many times a stopped transmit queue was re-armed.
    pub fn tx_recoveries(&self) -> u32 {
        self.tx_recoveries
    }

    // ---- management port (MDIO) -------------------------------------------

    /// Wait for the management shift register to go idle, for at most
    /// `MDIO_BUDGET_US` by the board's clock. The port is looked at once more
    /// after a wait that overran, so a late look is never a false timeout.
    fn mdio_wait_idle(&mut self) -> Result<(), MdioError> {
        let started = self.board.now_us();
        while self.board.read(NETWORK_STATUS) & NWSR_MAN_DONE == 0 {
            if self.board.now_us().saturating_sub(started) >= u64::from(MDIO_BUDGET_US) {
                return Err(MdioError::Timeout);
            }
            self.board.delay_us(MDIO_POLL_US);
        }
        Ok(())
    }

    fn mdio_frame(op: u32, phy: u8, reg_no: u8, data: u16) -> u32 {
        MDIO_START_C22
            | (op << MDIO_OP_POS)
            | (u32::from(phy & 0x1F) << MDIO_PHY_POS)
            | (u32::from(reg_no & 0x1F) << MDIO_REG_POS)
            | MDIO_TURNAROUND
            | u32::from(data)
    }

    // ---- link ---------------------------------------------------------------

    /// Find the PHY, reset it, negotiate, wait up to `budget_us` for a link, and
    /// set the MAC's speed and duplex to what was agreed. The budget is time on
    /// the board's clock ([`Board::now_us`]), measured from the start of the wait
    /// for the link, not the sum of the waits asked of the board.
    pub fn bring_up_link(&mut self, budget_us: u32) -> Result<LinkMode, LinkError> {
        let phy = match self.phy {
            Some(addr) => addr,
            None => phy::find(self)?.ok_or(LinkError::NoPhy)?,
        };
        self.phy = Some(phy);
        phy::reset(self, phy)?;
        phy::start_autoneg(self, phy)?;
        match phy::wait_for_link(self, phy, budget_us) {
            Ok(mode) => {
                self.apply_link(mode);
                Ok(mode)
            }
            Err(e) => {
                self.link = LinkState::Down;
                Err(e)
            }
        }
    }

    /// Re-read the link every `LINK_POLL_MS` and bring the MAC in step with it.
    /// A firmware calls this from its main loop with a millisecond clock; between
    /// polls it costs nothing. Does nothing until a PHY has been found.
    pub fn service_link(&mut self, now_ms: u64) -> LinkEvent {
        let Some(phy) = self.phy else {
            return LinkEvent::Steady;
        };
        if now_ms < self.next_link_poll_ms {
            return LinkEvent::Steady;
        }
        self.next_link_poll_ms = now_ms + LINK_POLL_MS;
        match phy::negotiated(self, phy) {
            Ok(Some(mode)) => {
                if self.link == LinkState::Up(mode) {
                    LinkEvent::Steady
                } else {
                    self.apply_link(mode);
                    LinkEvent::Up(mode)
                }
            }
            // No link, or one this driver cannot resolve: treated as down. A
            // failed management access is not a verdict on the link, so that case
            // keeps the state it had.
            Ok(None) | Err(LinkError::UnresolvedMode) => {
                if self.link == LinkState::Down {
                    LinkEvent::Steady
                } else {
                    self.link = LinkState::Down;
                    LinkEvent::Down
                }
            }
            Err(_) => LinkEvent::Steady,
        }
    }

    /// The link as last seen.
    pub fn link_state(&self) -> LinkState {
        self.link
    }

    /// The PHY's management address, once found.
    pub fn phy_address(&self) -> Option<u8> {
        self.phy
    }

    /// Set the MAC's speed and duplex. Receive and transmit are held off while
    /// the configuration register changes, so no frame is cut in half by it.
    fn apply_link(&mut self, mode: LinkMode) {
        let quiet = self.network_control & !(NWCTRL_ENABLE_RECEIVE | NWCTRL_ENABLE_TRANSMIT);
        self.board.write(NETWORK_CONTROL, quiet);
        let mut cfg = self.board.read(NETWORK_CONFIG) & !(NWCFG_SPEED_100 | NWCFG_FULL_DUPLEX);
        if mode.speed_100 {
            cfg |= NWCFG_SPEED_100;
        }
        if mode.full_duplex {
            cfg |= NWCFG_FULL_DUPLEX;
        }
        self.board.write(NETWORK_CONFIG, cfg);
        self.board.write(NETWORK_CONTROL, self.network_control);
        self.link = LinkState::Up(mode);
    }
}

impl<B: Board, const RX: usize, const TX: usize> phy::Mdio for Cyt4bfMac<B, RX, TX> {
    fn mdio_read(&mut self, phy: u8, reg_no: u8) -> Result<u16, MdioError> {
        self.board.write(
            PHY_MANAGEMENT,
            Self::mdio_frame(MDIO_OP_READ, phy, reg_no, 0),
        );
        self.mdio_wait_idle()?;
        self.board.delay_us(MDIO_READ_SETTLE_US);
        Ok(self.board.read(PHY_MANAGEMENT) as u16)
    }

    fn mdio_write(&mut self, phy: u8, reg_no: u8, value: u16) -> Result<(), MdioError> {
        self.board.write(
            PHY_MANAGEMENT,
            Self::mdio_frame(MDIO_OP_WRITE, phy, reg_no, value),
        );
        self.mdio_wait_idle()?;
        self.board.delay_us(MDIO_WRITE_SETTLE_US);
        Ok(())
    }

    fn delay_us(&mut self, us: u32) {
        self.board.delay_us(us);
    }

    fn now_us(&mut self) -> u64 {
        self.board.now_us()
    }
}

impl<B: Board, const RX: usize, const TX: usize> EthernetMac for Cyt4bfMac<B, RX, TX> {
    fn mac_address(&self) -> [u8; 6] {
        self.mac
    }

    fn transmit(&mut self, frame: &[u8]) -> bool {
        self.send_copied(frame.len(), |buf| {
            // SAFETY: `buf` is the ring slot's `BUF_LEN` bytes, software-owned, and
            // `send_copied` calls this only for `frame.len() <= BUF_LEN`.
            unsafe { core::ptr::copy_nonoverlapping(frame.as_ptr(), buf, frame.len()) };
        })
    }

    fn gathers_in_place(&self) -> bool {
        true
    }

    /// ARCHITECTURE section 9.1 — one frame from several pieces, one descriptor
    /// each, read by the controller where the pieces lie.
    ///
    /// The protocol is the Cadence driver's own (`emacQueueTxBuf`): the FIRST
    /// descriptor of a frame of more than one is written with USED set, so the
    /// controller, which stops at a used descriptor, cannot start on a frame whose
    /// tail is not yet in the ring; the others are written normally, the last
    /// carrying LAST; and the first descriptor's USED is cleared only once the rest
    /// are in place, which is the release of the whole frame.
    ///
    /// Frames that cannot be queued in place are copied instead, through the
    /// one-buffer path: more pieces than the ring has descriptors (it could never
    /// fit), which the caller sees as [`TxGather::Copied`].
    unsafe fn transmit_gather(&mut self, segments: &[TxSegment], cookie: u32) -> TxGather {
        let n = segments.len();
        let mut total = 0usize;
        for s in segments {
            // A descriptor's length field is 14 bits, and a zero length is not a
            // buffer.
            if s.len == 0 || s.len > TXD_LEN_MASK as usize {
                return TxGather::Refused;
            }
            total += s.len;
        }
        if n == 0 || total > BUF_LEN {
            return TxGather::Refused;
        }
        if n > TX {
            // Joined straight into the ring slot's own buffer, so a frame this
            // long costs no stack.
            let sent = self.send_copied(total, |buf| {
                // SAFETY: `buf` is `BUF_LEN` bytes and `total <= BUF_LEN`; the
                // caller's contract makes every segment readable, and none lies in
                // the ring's own buffers.
                let out = unsafe { core::slice::from_raw_parts_mut(buf, total) };
                let _ = unsafe { join_segments(segments, out) };
            });
            return if sent {
                TxGather::Copied
            } else {
                TxGather::Refused
            };
        }
        if self.link == LinkState::Down {
            return TxGather::Refused;
        }
        if self.board.read(TRANSMIT_STATUS) & TXSR_FATAL != 0 {
            self.recover_tx();
        }
        self.reclaim(None);
        if TX - self.tx_inflight < n {
            return TxGather::Refused;
        }
        let first_index = self.tx_head;
        for (k, segment) in segments.iter().enumerate() {
            let index = (first_index + k) % TX;
            let slot = self.tx_slot(index);
            // The controller reads these bytes by DMA, so any copy the CPU still
            // holds must reach memory first.
            self.board.clean(segment.ptr, segment.len);
            let last = if k == n - 1 { TXD_LAST } else { 0 };
            let wrap = if index == TX - 1 { TXD_WRAP } else { 0 };
            let held = if k == 0 && n > 1 { TXD_USED } else { 0 };
            slot.set_word0(self.board.bus_address(segment.ptr));
            fence(Ordering::Release);
            slot.set_word1((segment.len as u32 & TXD_LEN_MASK) | last | wrap | held);
            self.board
                .clean(slot.0 as *const u8, core::mem::size_of::<Descriptor>());
        }
        if n > 1 {
            // The release of the frame: every descriptor behind the first is in the
            // ring and visible before the one the controller is waiting on is let go.
            fence(Ordering::Release);
            let first = self.tx_slot(first_index);
            first.set_word1(first.word1() & !TXD_USED);
            self.board
                .clean(first.0 as *const u8, core::mem::size_of::<Descriptor>());
        }
        self.chains[first_index] = Chain {
            ndesc: n as u16,
            cookie: Some(cookie),
        };
        self.tx_head = (first_index + n) % TX;
        self.tx_inflight += n;
        fence(Ordering::Release);
        self.board
            .write(NETWORK_CONTROL, self.network_control | NWCTRL_TX_START);
        TxGather::Queued
    }

    fn reap_tx(&mut self, done: &mut dyn FnMut(u32)) {
        self.reclaim(Some(done));
    }

    fn receive(&mut self, out: &mut [u8]) -> Option<usize> {
        // At most one pass over the ring per call: a ring full of frames the
        // caller cannot hold is drained, not spun on.
        for _ in 0..RX {
            let word1 = self.rx_ready()?;
            let len = (word1 & RXD_LEN_MASK) as usize;
            let buf = self.rx_buf(self.rx_head);
            // One frame is one buffer here (1536 bytes against a 1518-byte
            // maximum); a frame that spans buffers, or has no length, is not a
            // frame this driver can hand up and is dropped whole.
            let whole = word1 & RXD_SOF != 0 && word1 & RXD_EOF != 0 && len > 0 && len <= BUF_LEN;
            let kept = if whole && len <= out.len() {
                self.board.invalidate(buf, len);
                // SAFETY: `buf` holds `len <= BUF_LEN` bytes the controller wrote,
                // and `out` holds at least `len` (checked above).
                unsafe { core::ptr::copy_nonoverlapping(buf, out.as_mut_ptr(), len) };
                Some(len)
            } else {
                None
            };
            let released = self.rx_head;
            self.rx_head = (self.rx_head + 1) % RX;
            self.give_rx(released);
            if kept.is_some() {
                return kept;
            }
        }
        None
    }

    fn loans_rx(&self) -> bool {
        true
    }

    /// ARCHITECTURE section 9.2 — the received frame is lent where the controller
    /// wrote it: no copy, and the slot is withheld from the controller until
    /// [`return_rx`](Self::return_rx). A frame that is not whole (it spans buffers
    /// or has no length) is dropped, and its buffer returned to the controller, as
    /// [`receive`](Self::receive) does.
    fn receive_loan(&mut self) -> Option<RxLoan> {
        for _ in 0..RX {
            let word1 = self.rx_ready()?;
            let len = (word1 & RXD_LEN_MASK) as usize;
            let index = self.rx_head;
            let buf = self.rx_buf(index);
            let whole = word1 & RXD_SOF != 0 && word1 & RXD_EOF != 0 && len > 0 && len <= BUF_LEN;
            self.rx_head = (index + 1) % RX;
            if whole {
                self.board.invalidate(buf, len);
                self.rx_loaned[index] = true;
                return Some(RxLoan {
                    ptr: buf,
                    len,
                    cookie: index as u32,
                });
            }
            self.give_rx(index);
        }
        None
    }

    fn return_rx(&mut self, cookie: u32) {
        let index = cookie as usize;
        // Only a slot that is lent goes back: a stale or foreign cookie must not
        // arm a buffer the controller is already filling.
        if index < RX && self.rx_loaned[index] {
            self.rx_loaned[index] = false;
            self.give_rx(index);
        }
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;
