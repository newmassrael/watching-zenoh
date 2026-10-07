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
//! wiring or clocking: the register base, the way to wait, where the DMA area
//! lives and how addresses look to a bus master ([`Board`]), the pins' HSIOM and
//! drive settings, which reference clock the PHY gives, and the PHY's reset line.
//! Nothing here names a board, a PHY part or a PHY address: the address is found
//! by scanning, or given.
//!
//! ## What is claimed
//!
//! BUILT. No emulator models this block, so nothing here has run on a CYT4BF; the
//! host tests drive the driver against a model of the controller written from the
//! same documents it was written from, which checks the ring logic and the order
//! of register programming, not the documents. The driver says so in its own
//! manifest and the board table grades its rows accordingly.
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
use wz_runtime_core::EthernetMac;

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
    /// Wait about `us` microseconds.
    fn delay_us(&mut self, us: u32);
}

/// The board of a running chip: volatile MMIO at `base`, identity bus addresses,
/// no cache maintenance (the area lives in non-cacheable memory), a delay the
/// firmware provides.
pub struct Cyt4bfBoard {
    base: usize,
    delay: fn(u32),
}

impl Cyt4bfBoard {
    /// # Safety
    /// `base` must be the address of an `MXETH` block (ETH0 is `0x4048_0000` on
    /// the CYT4BF), exclusively this driver's, and `delay` must wait at least the
    /// microseconds it is given.
    pub const unsafe fn new(base: usize, delay: fn(u32)) -> Self {
        Self { base, delay }
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

/// The management port was idle-polled this long before giving up.
const MDIO_BUDGET_US: u32 = 10_000;
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
    tx_head: usize,
    phy: Option<u8>,
    link: LinkState,
    next_link_poll_ms: u64,
    tx_recoveries: u32,
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

        let mut mac = Self {
            board,
            area: NonNull::from(area),
            mac: config.mac_address,
            network_control: NWCTRL_MAN_PORT_EN,
            rx_head: 0,
            tx_head: 0,
            phy: config.phy_address,
            link: LinkState::Unknown,
            next_link_poll_ms: 0,
            tx_recoveries: 0,
        };

        // 2. Quiesce: nothing runs while the registers are set up.
        mac.board.write(NETWORK_CONTROL, 0);

        // 3. The network configuration: 100 Mbps full duplex until negotiation
        //    says otherwise, 1536-byte frames, FCS stripped, 32-bit bus, and the
        //    multicast hash filter on when every multicast frame is wanted.
        let mut netcfg = NWCFG_SPEED_100
            | NWCFG_FULL_DUPLEX
            | NWCFG_RECEIVE_1536
            | NWCFG_FCS_REMOVE
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

    /// Hand every receive buffer to the controller; the last slot wraps.
    fn init_rx_ring(&mut self) {
        for i in 0..RX {
            self.give_rx(i);
        }
        self.rx_head = 0;
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

    /// Every transmit slot software-owned (used set); the last wraps.
    fn init_tx_ring(&mut self) {
        for i in 0..TX {
            let slot = self.tx_slot(i);
            let wrap = if i == TX - 1 { TXD_WRAP } else { 0 };
            slot.set_word0(0);
            slot.set_word1(TXD_USED | wrap);
            self.board
                .clean(slot.0 as *const u8, core::mem::size_of::<Descriptor>());
        }
        self.tx_head = 0;
    }

    /// The transmit DMA stopped on an error: it will not move until the queue is
    /// re-armed, and the frames queued behind the failure are lost. Disable
    /// transmit, clear the status, make every slot software-owned again, point the
    /// controller at the start and enable it. This is the Cadence driver's own
    /// reset of a transmit queue (`emacResetTxQ`: disabled, all used, pointer
    /// rewritten) in this driver's terms.
    fn recover_tx(&mut self) {
        self.board.write(
            NETWORK_CONTROL,
            self.network_control & !NWCTRL_ENABLE_TRANSMIT,
        );
        self.board.write(TRANSMIT_STATUS, TXSR_ALL);
        self.init_tx_ring();
        let tx0 = self.tx_slot(0).0 as *const u8;
        let bus = self.board.bus_address(tx0);
        self.board.write(TRANSMIT_Q_PTR, bus & !QPTR_DISABLE);
        self.board.write(NETWORK_CONTROL, self.network_control);
        self.tx_recoveries = self.tx_recoveries.wrapping_add(1);
    }

    /// How many times a stopped transmit queue was re-armed.
    pub fn tx_recoveries(&self) -> u32 {
        self.tx_recoveries
    }

    // ---- management port (MDIO) -------------------------------------------

    fn mdio_wait_idle(&mut self) -> Result<(), MdioError> {
        let mut waited = 0;
        while self.board.read(NETWORK_STATUS) & NWSR_MAN_DONE == 0 {
            if waited >= MDIO_BUDGET_US {
                return Err(MdioError::Timeout);
            }
            self.board.delay_us(MDIO_POLL_US);
            waited += MDIO_POLL_US;
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
    /// set the MAC's speed and duplex to what was agreed.
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
}

impl<B: Board, const RX: usize, const TX: usize> EthernetMac for Cyt4bfMac<B, RX, TX> {
    fn mac_address(&self) -> [u8; 6] {
        self.mac
    }

    fn transmit(&mut self, frame: &[u8]) -> bool {
        if frame.is_empty() || frame.len() > BUF_LEN {
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
        let slot = self.tx_slot(self.tx_head);
        self.board
            .invalidate(slot.0 as *const u8, core::mem::size_of::<Descriptor>());
        if slot.word1() & TXD_USED == 0 {
            // The controller still owns the next slot: the ring is full.
            return false;
        }
        let buf = self.tx_buf(self.tx_head);
        // SAFETY: `buf` is this slot's `BUF_LEN` bytes, software-owned (used set),
        // and `frame.len() <= BUF_LEN`.
        unsafe { core::ptr::copy_nonoverlapping(frame.as_ptr(), buf, frame.len()) };
        self.board.clean(buf, frame.len());
        let wrap = if self.tx_head == TX - 1 { TXD_WRAP } else { 0 };
        slot.set_word0(self.board.bus_address(buf));
        // Clearing used (it is absent from this word) is the release to the
        // controller, so it is written last and the frame's bytes and the address
        // are made visible before it.
        fence(Ordering::Release);
        slot.set_word1((frame.len() as u32 & TXD_LEN_MASK) | TXD_LAST | wrap);
        self.board
            .clean(slot.0 as *const u8, core::mem::size_of::<Descriptor>());
        self.tx_head = (self.tx_head + 1) % TX;
        // The descriptor must be visible before the kick that makes the DMA read it.
        fence(Ordering::Release);
        self.board
            .write(NETWORK_CONTROL, self.network_control | NWCTRL_TX_START);
        true
    }

    fn receive(&mut self, out: &mut [u8]) -> Option<usize> {
        // At most one pass over the ring per call: a ring full of frames the
        // caller cannot hold is drained, not spun on.
        for _ in 0..RX {
            let slot = self.rx_slot(self.rx_head);
            self.board
                .invalidate(slot.0 as *const u8, core::mem::size_of::<Descriptor>());
            if slot.word0() & RXD_USED == 0 {
                // Nothing waiting. If the controller ran out of buffers it has
                // stopped and says so; the buffers are free again now, so the
                // condition is cleared and it carries on with the next frame.
                let status = self.board.read(RECEIVE_STATUS);
                if status & (RXSR_BUFFER_NOT_AVAILABLE | RXSR_OVERRUN) != 0 {
                    self.board.write(
                        RECEIVE_STATUS,
                        status & (RXSR_BUFFER_NOT_AVAILABLE | RXSR_OVERRUN),
                    );
                }
                return None;
            }
            // The used bit says the controller finished the frame; the length and
            // the bytes are read only after it was seen.
            fence(Ordering::Acquire);
            let word1 = slot.word1();
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
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;
