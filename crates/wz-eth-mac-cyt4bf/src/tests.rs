// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The driver against a model of the controller.
//!
//! The model is written from the documents the driver was written from (the
//! register map and the descriptor layout in Infineon's PDL, and the behaviour its
//! Cadence core driver relies on: the controller sets a receive descriptor's used
//! bit when it has filled the buffer, sets a transmit descriptor's used bit when
//! it has sent the frame, stops at a used transmit descriptor, and stops on a
//! transmit error until the queue pointer is rewritten). So these tests check the
//! driver's ring logic and the ORDER of its register programming; they cannot
//! check that the documents describe the silicon, and the crate claims BUILT, not
//! HARDWARE, for that reason.

use super::*;
use crate::dma::Slot;
use std::boxed::Box;
use std::cell::RefCell;
use std::collections::HashMap;
use std::format;
use std::rc::Rc;
use std::string::String;
use std::vec;
use std::vec::Vec;
use wz_runtime_core::EthernetMac;

const BUS_BASE: u32 = 0x2000_0000;
/// Where caller memory the controller can reach (outside the DMA area) appears on
/// the bus, one `EXT_BUS_STRIDE` range per registered window.
const EXT_BUS_BASE: u32 = 0x4000_0000;
const EXT_BUS_STRIDE: u32 = 0x0010_0000;
const RX: usize = 4;
const TX: usize = 3;
type Area = DmaArea<RX, TX>;
const MAC: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];

/// The GEM registers sit above this offset and answer only once the wrapper is
/// enabled (`CTL.ENABLED`).
const GEM: usize = 0x1000;

/// `DESIGNCFG_DEBUG5` (`cyip_eth.h`, offset `0x1290`): its bits 11:10 are the reset
/// default of `NETWORK_CONFIG.DATA_BUS_WIDTH`.
const DESIGNCFG_DEBUG5: usize = 0x1290;

/// What ETH0 of a CYT4BF8CEE kit read after its wrapper was enabled and before any
/// driver code ran, as the lab measured it. These are values read off one kit, not
/// data-sheet facts, and the model starts from them so that a register the driver
/// writes WHOLE shows which fields it replaced without naming them.
const RESET_NETWORK_CONFIG: u32 = 0x002c_0000;
const RESET_DMA_CONFIG: u32 = 0x0018_0704;
/// `DMA_BUS_WIDTH` (bits 27:25) reads 2 on that kit: 64 bits.
const RESET_DESIGNCFG_DEBUG1: u32 = 0x0450_8503;
/// Its bits 11:10 read 1 on that kit, the reset value of `NETWORK_CONFIG`'s field.
const RESET_DESIGNCFG_DEBUG5: u32 = 0x518e_3744;

/// A PHY on the management bus, and the controller in front of it.
struct Model {
    start: usize,
    regs: HashMap<usize, u32>,
    tx_idx: usize,
    rx_idx: usize,
    tx_halted: bool,
    /// Caller memory outside the DMA area that the controller can read:
    /// `(host address, length)`.
    ext: Vec<(usize, usize)>,
    /// Each transmit descriptor the driver published, and its second word at that
    /// moment, in order.
    desc_cleans: Vec<(usize, u32)>,
    /// A frame being read across descriptors, and the descriptor it began at.
    assembling: Vec<u8>,
    assembling_first: Option<usize>,
    wire: Vec<Vec<u8>>,
    log: Vec<(usize, u32)>,
    /// What the board's own behaviour, or the driver's use of it, got wrong.
    violations: Vec<String>,
    /// How many register writes had been made when the design register was read.
    design_read_after_writes: Option<usize>,
    /// The sum of the waits asked for, and how many were asked.
    delays_us: u32,
    delay_calls: u32,
    /// The board's monotonic clock: a wait of `us` advances it by `stretch * us`,
    /// as a board whose time base runs slow, or whose wait lasts longer than it
    /// promised, does.
    clock_us: u64,
    delay_stretch: u64,
    // controller behaviour switches
    hold_tx: bool,
    fail_next_tx: bool,
    // management bus
    phy_addr: u8,
    phy_present: bool,
    phy_regs: [u16; 32],
    phy_link: bool,
    mdio_busy_polls: u32,
    mdio_busy_left: u32,
    mdio_stuck: bool,
    /// The management port reads busy until the clock reaches this.
    mdio_busy_until_us: u64,
    mdio_data: u16,
    bad_frames: u32,
    phys_touched: Vec<u8>,
}

impl Model {
    fn new(start: usize) -> Self {
        let mut phy_regs = [0u16; 32];
        phy_regs[2] = 0x2000;
        phy_regs[3] = 0x1234;
        phy_regs[4] = 0x01E0; // ANAR: 10 half/full, 100 half/full
        let regs = HashMap::from([
            (NETWORK_CONFIG, RESET_NETWORK_CONFIG),
            (DMA_CONFIG, RESET_DMA_CONFIG),
            (DESIGNCFG_DEBUG1, RESET_DESIGNCFG_DEBUG1),
            (DESIGNCFG_DEBUG5, RESET_DESIGNCFG_DEBUG5),
        ]);
        Self {
            start,
            regs,
            tx_idx: 0,
            rx_idx: 0,
            tx_halted: false,
            ext: Vec::new(),
            desc_cleans: Vec::new(),
            assembling: Vec::new(),
            assembling_first: None,
            wire: Vec::new(),
            log: Vec::new(),
            violations: Vec::new(),
            design_read_after_writes: None,
            delays_us: 0,
            delay_calls: 0,
            clock_us: 0,
            delay_stretch: 1,
            hold_tx: false,
            fail_next_tx: false,
            phy_addr: 1,
            phy_present: true,
            phy_regs,
            phy_link: false,
            mdio_busy_polls: 2,
            mdio_busy_left: 0,
            mdio_stuck: false,
            mdio_busy_until_us: 0,
            mdio_data: 0,
            bad_frames: 0,
            phys_touched: Vec::new(),
        }
    }

    fn area(&self) -> *mut Area {
        self.start as *mut Area
    }

    fn bus(&self, ptr: *const u8) -> u32 {
        let at = ptr as usize;
        // Memory the caller keeps outside the DMA area (a session's frame buffer,
        // read in place): each registered window has a bus range of its own, so the
        // model can tell the controller's own buffers from the caller's.
        for (i, (start, len)) in self.ext.iter().enumerate() {
            if (*start..*start + *len).contains(&at) {
                return EXT_BUS_BASE + i as u32 * EXT_BUS_STRIDE + (at - start) as u32;
            }
        }
        BUS_BASE + (at - self.start) as u32
    }

    fn ptr(&self, bus: u32) -> *mut u8 {
        if bus >= EXT_BUS_BASE {
            let i = ((bus - EXT_BUS_BASE) / EXT_BUS_STRIDE) as usize;
            let off = ((bus - EXT_BUS_BASE) % EXT_BUS_STRIDE) as usize;
            return (self.ext[i].0 + off) as *mut u8;
        }
        (self.start + (bus - BUS_BASE) as usize) as *mut u8
    }

    /// Make `buf` reachable by the controller, as system SRAM outside the DMA area
    /// is on the board.
    fn expose(&mut self, buf: &[u8]) {
        self.ext.push((buf.as_ptr() as usize, buf.len()));
    }

    /// Whether `[ptr, ptr + len)` lies inside one window the test exposed: caller
    /// memory the controller reaches. Anything else it cannot read in place.
    fn exposed(&self, ptr: *const u8, len: usize) -> bool {
        let at = ptr as usize;
        self.ext
            .iter()
            .any(|(start, n)| at >= *start && at + len <= start + n)
    }

    fn rx_desc(&self, i: usize) -> Slot {
        // SAFETY: inside the leaked area.
        unsafe { Slot((addr_of_mut!((*self.area()).rx_desc) as *mut Descriptor).add(i)) }
    }

    fn tx_desc(&self, i: usize) -> Slot {
        // SAFETY: inside the leaked area.
        unsafe { Slot((addr_of_mut!((*self.area()).tx_desc) as *mut Descriptor).add(i)) }
    }

    fn desc_index(&self, bus: u32, first: Slot) -> usize {
        ((bus - self.bus(first.0 as *const u8)) / 8) as usize
    }

    fn reg(&self, off: usize) -> u32 {
        *self.regs.get(&off).unwrap_or(&0)
    }

    /// A GEM register is touched: it answers only once the wrapper is enabled.
    fn gem_answers(&mut self, off: usize, what: &str) -> bool {
        let answers = off < GEM || self.reg(CTL) & CTL_ENABLED != 0;
        if !answers {
            self.violations
                .push(format!("{what} of {off:#x} before the wrapper was enabled"));
        }
        answers
    }

    /// The `NETWORK_CONFIG.DATA_BUS_WIDTH` value that agrees with the width the
    /// design register states, or `None` for a design value that names no width.
    /// Written out from the PDL's encodings (design: 1, 2, 4 are 32, 64, 128 bits;
    /// field: 0, 1, 2), not from the driver's constants, so the model is an
    /// independent reading.
    fn design_field(&self) -> Option<u32> {
        match (self.reg(DESIGNCFG_DEBUG1) >> 25) & 7 {
            1 => Some(0),
            2 => Some(1),
            4 => Some(2),
            _ => None,
        }
    }

    fn configured_field(&self) -> u32 {
        (self.reg(NETWORK_CONFIG) >> 21) & 3
    }

    fn width_agrees(&self) -> bool {
        self.design_field() == Some(self.configured_field())
    }

    /// Set the design register's `DMA_BUS_WIDTH` field to `value`, whatever it is.
    fn set_design_bus_width(&mut self, value: u32) {
        let design = self.reg(DESIGNCFG_DEBUG1) & !(7 << 25);
        self.regs
            .insert(DESIGNCFG_DEBUG1, design | ((value & 7) << 25));
    }

    /// The board's rule: the DMA moves data correctly only while the bus width it
    /// is configured with agrees with the design. Checked wherever either side of
    /// the agreement or the DMA's enable changes.
    fn check_width(&mut self, after: &str) {
        let running = self.reg(NETWORK_CONTROL) & (NWCTRL_ENABLE_RECEIVE | NWCTRL_ENABLE_TRANSMIT);
        if running != 0 && !self.width_agrees() {
            let (design, field) = (self.design_field(), self.configured_field());
            self.violations.push(format!(
                "{after}: the DMA is enabled with bus width field {field} but the design \
                 register asks for {design:?}"
            ));
        }
    }

    /// What the receive DMA stored when the design bus was wider than the field
    /// said, as measured: frame words 1, 3, 5, ... landed at buffer words 0, 2, 4,
    /// ... and the words between them were zero. A field WIDER than the design was
    /// not measured, so it is not given a behaviour here beyond the violation.
    fn as_the_board_stored(&self, frame: &[u8]) -> Vec<u8> {
        let wider_design = self
            .design_field()
            .is_some_and(|d| d > self.configured_field());
        if self.width_agrees() || !wider_design {
            return frame.to_vec();
        }
        let mut stored = vec![0u8; frame.len()];
        for word in (1..frame.len().div_ceil(4)).step_by(2) {
            let from = word * 4..(word * 4 + 4).min(frame.len());
            let to = (word - 1) * 4;
            stored[to..to + from.len()].copy_from_slice(&frame[from]);
        }
        stored
    }

    fn read(&mut self, off: usize) -> u32 {
        if !self.gem_answers(off, "read") {
            return 0;
        }
        match off {
            DESIGNCFG_DEBUG1 => {
                self.design_read_after_writes.get_or_insert(self.log.len());
                self.reg(off)
            }
            NETWORK_STATUS => {
                if self.mdio_stuck || self.clock_us < self.mdio_busy_until_us {
                    0
                } else if self.mdio_busy_left > 0 {
                    self.mdio_busy_left -= 1;
                    0
                } else {
                    NWSR_MAN_DONE
                }
            }
            PHY_MANAGEMENT => u32::from(self.mdio_data),
            o => self.reg(o),
        }
    }

    fn write(&mut self, off: usize, v: u32) {
        self.log.push((off, v));
        if !self.gem_answers(off, "write") {
            return;
        }
        match off {
            NETWORK_CONTROL => {
                self.regs.insert(off, v & !NWCTRL_TX_START);
                self.check_width("NETWORK_CONTROL written");
                if v & NWCTRL_TX_START != 0 && v & NWCTRL_ENABLE_TRANSMIT != 0 {
                    self.run_tx();
                }
            }
            NETWORK_CONFIG => {
                self.regs.insert(off, v);
                self.check_width("NETWORK_CONFIG written");
            }
            TRANSMIT_STATUS | RECEIVE_STATUS => {
                let cur = self.reg(off);
                self.regs.insert(off, cur & !v);
            }
            TRANSMIT_Q_PTR => {
                self.regs.insert(off, v);
                self.tx_idx = self.desc_index(v & !QPTR_DISABLE, self.tx_desc(0));
                self.tx_halted = false;
                // A frame the controller was partway through is abandoned.
                self.assembling.clear();
                self.assembling_first = None;
            }
            RECEIVE_Q_PTR => {
                self.regs.insert(off, v);
                self.rx_idx = self.desc_index(v & !QPTR_DISABLE, self.rx_desc(0));
            }
            PHY_MANAGEMENT => self.mdio(v),
            _ => {
                self.regs.insert(off, v);
            }
        }
    }

    fn mdio(&mut self, frame: u32) {
        let c22 = frame & MDIO_START_C22 != 0;
        let turnaround = frame & (3 << 16) == MDIO_TURNAROUND;
        if !c22 || !turnaround {
            self.bad_frames += 1;
        }
        let op = (frame >> MDIO_OP_POS) & 3;
        let phy = ((frame >> MDIO_PHY_POS) & 0x1F) as u8;
        let reg_no = ((frame >> MDIO_REG_POS) & 0x1F) as usize;
        let data = (frame & 0xFFFF) as u16;
        self.phys_touched.push(phy);
        self.mdio_busy_left = self.mdio_busy_polls;
        if op == MDIO_OP_WRITE {
            if phy == self.phy_addr && self.phy_present {
                self.phy_regs[reg_no] = data;
                if reg_no == 0 {
                    // Self-clearing reset bit.
                    self.phy_regs[0] &= !(1 << 15);
                }
            }
        } else if op == MDIO_OP_READ {
            self.mdio_data = if phy == self.phy_addr && self.phy_present {
                if reg_no == 1 {
                    if self.phy_link && self.phy_regs[0] & (1 << 12) != 0 {
                        (1 << 2) | (1 << 5)
                    } else {
                        0
                    }
                } else {
                    self.phy_regs[reg_no]
                }
            } else {
                0xFFFF
            };
        } else {
            self.bad_frames += 1;
        }
    }

    /// The transmit DMA: walk from where it stands, stop at a software-owned
    /// slot, send what software released, mark it used. An error stops it.
    fn run_tx(&mut self) {
        if self.tx_halted {
            return;
        }
        loop {
            let d = self.tx_desc(self.tx_idx);
            let w1 = d.word1();
            if w1 & TXD_USED != 0 {
                if self.assembling_first.is_some() {
                    // The controller read the first descriptors of a frame and
                    // then a software-owned one: the frame was released before
                    // its last descriptor was in place.
                    self.violations.push(format!(
                        "the transmit DMA stopped inside a frame, at descriptor {}",
                        self.tx_idx
                    ));
                    self.assembling.clear();
                    self.assembling_first = None;
                }
                let st = self.reg(TRANSMIT_STATUS) | TXSR_USED_BIT_READ;
                self.regs.insert(TRANSMIT_STATUS, st);
                return;
            }
            if self.fail_next_tx {
                self.fail_next_tx = false;
                let st = self.reg(TRANSMIT_STATUS) | TXSR_RETRY_LIMIT_EXCEEDED;
                self.regs.insert(TRANSMIT_STATUS, st);
                self.tx_halted = true;
                return;
            }
            if !self.width_agrees() {
                // As measured: a descriptor was consumed by a DMA whose bus width
                // disagreed with the design, and the first frame ended in an AMBA
                // error.
                let st = self.reg(TRANSMIT_STATUS) | TXSR_AMBA_ERROR;
                self.regs.insert(TRANSMIT_STATUS, st);
                self.tx_halted = true;
                return;
            }
            if self.hold_tx {
                return;
            }
            let len = (w1 & TXD_LEN_MASK) as usize;
            let buf = self.ptr(d.word0());
            // SAFETY: the driver wrote `len <= BUF_LEN` bytes there, or the caller
            // keeps them in place for it.
            let piece = unsafe { std::slice::from_raw_parts(buf, len) }.to_vec();
            if self.assembling_first.is_none() {
                self.assembling_first = Some(self.tx_idx);
            }
            self.assembling.extend_from_slice(&piece);
            if w1 & TXD_LAST != 0 {
                // The frame is on the wire. As the Cadence driver relies on, the
                // controller writes USED back to the FIRST descriptor of the frame
                // and leaves the others as it found them (software marks those
                // itself when it takes the frame back).
                let frame = std::mem::take(&mut self.assembling);
                self.wire.push(frame);
                let first_idx = self.assembling_first.take().unwrap_or(self.tx_idx);
                let first = self.tx_desc(first_idx);
                first.set_word1(first.word1() | TXD_USED);
                let st = self.reg(TRANSMIT_STATUS) | TXSR_TRANSMIT_COMPLETE;
                self.regs.insert(TRANSMIT_STATUS, st);
            }
            // The controller follows the wrap flag and nothing else: a last slot
            // that lost it sends the DMA into whatever memory follows the ring.
            self.tx_idx = if w1 & TXD_WRAP != 0 {
                0
            } else {
                self.tx_idx + 1
            };
            assert!(
                self.tx_idx < TX,
                "the transmit DMA walked off the end of the ring: the last slot has no wrap flag"
            );
        }
    }

    /// Resume a transmit DMA that was being held, as time passing would.
    fn drain(&mut self) {
        self.hold_tx = false;
        self.run_tx();
    }

    /// The controller receiving `frame`. `false` when it had no buffer.
    fn inject_rx(&mut self, frame: &[u8]) -> bool {
        let d = self.rx_desc(self.rx_idx);
        let w0 = d.word0();
        if w0 & RXD_USED != 0 {
            let st = self.reg(RECEIVE_STATUS) | RXSR_BUFFER_NOT_AVAILABLE;
            self.regs.insert(RECEIVE_STATUS, st);
            return false;
        }
        let buf = self.ptr(w0 & RXD_ADDR_MASK);
        let stored = self.as_the_board_stored(frame);
        // SAFETY: the buffer is `BUF_LEN` bytes and the tests inject less.
        unsafe { std::ptr::copy_nonoverlapping(stored.as_ptr(), buf, stored.len()) };
        d.set_word1(frame.len() as u32 | RXD_SOF | RXD_EOF);
        d.set_word0(w0 | RXD_USED);
        let st = self.reg(RECEIVE_STATUS) | RXSR_FRAME_RECEIVED;
        self.regs.insert(RECEIVE_STATUS, st);
        // As for transmit: the wrap flag is the only thing that closes the ring.
        self.rx_idx = if w0 & RXD_WRAP != 0 {
            0
        } else {
            self.rx_idx + 1
        };
        assert!(
            self.rx_idx < RX,
            "the receive DMA walked off the end of the ring: the last slot has no wrap flag"
        );
        true
    }
}

#[derive(Clone)]
struct Gem(Rc<RefCell<Model>>);

impl Board for Gem {
    fn read(&mut self, offset: usize) -> u32 {
        self.0.borrow_mut().read(offset)
    }

    fn write(&mut self, offset: usize, value: u32) {
        self.0.borrow_mut().write(offset, value);
    }

    fn bus_address(&self, ptr: *const u8) -> u32 {
        self.0.borrow().bus(ptr)
    }

    fn reads_in_place(&self, ptr: *const u8, len: usize) -> bool {
        self.0.borrow().exposed(ptr, len)
    }

    /// The controller writes received frames only into memory it reaches, which in
    /// the model is what the test exposed.
    fn receives_in_place(&self, ptr: *const u8, len: usize) -> bool {
        self.0.borrow().exposed(ptr, len)
    }

    /// Cache maintenance on a transmit descriptor is the moment the driver
    /// PUBLISHES it, so the model notes what the descriptor said then: the order
    /// of a frame's descriptors, and when its first is let go, is read from here.
    fn clean(&mut self, ptr: *const u8, _len: usize) {
        let mut m = self.0.borrow_mut();
        let base = m.tx_desc(0).0 as usize;
        let at = ptr as usize;
        if at >= base && at < base + TX * core::mem::size_of::<Descriptor>() {
            let index = (at - base) / core::mem::size_of::<Descriptor>();
            let word1 = m.tx_desc(index).word1();
            m.desc_cleans.push((index, word1));
        }
    }

    fn delay_us(&mut self, us: u32) {
        let mut m = self.0.borrow_mut();
        m.delays_us += us;
        m.delay_calls += 1;
        let elapsed = m.delay_stretch * u64::from(us);
        m.clock_us += elapsed;
    }

    fn now_us(&mut self) -> u64 {
        self.0.borrow().clock_us
    }
}

/// The driver over a model that `setup` has shaped before `new` runs.
fn rig_on<const R: usize, const T: usize>(
    config: &Config,
    setup: impl FnOnce(&mut Model),
) -> (Result<Cyt4bfMac<Gem, R, T>, InitError>, Rc<RefCell<Model>>) {
    let area: &'static mut DmaArea<R, T> = Box::leak(Box::new(DmaArea::new()));
    let start = &mut *area as *mut DmaArea<R, T> as usize;
    let mut model = Model::new(start);
    setup(&mut model);
    let model = Rc::new(RefCell::new(model));
    (Cyt4bfMac::new(Gem(model.clone()), area, config), model)
}

fn rig_with<const R: usize, const T: usize>(
    config: &Config,
) -> (Result<Cyt4bfMac<Gem, R, T>, InitError>, Rc<RefCell<Model>>) {
    rig_on(config, |_| {})
}

fn rig() -> (Cyt4bfMac<Gem, RX, TX>, Rc<RefCell<Model>>) {
    let (mac, model) = rig_with::<RX, TX>(&Config::new(MAC));
    let mac = mac.expect("a valid configuration");
    assert_eq!(
        model.borrow().violations,
        Vec::<String>::new(),
        "bringing the block up broke a rule of the board"
    );
    (mac, model)
}

fn position(log: &[(usize, u32)], off: usize, nth: usize) -> usize {
    log.iter()
        .enumerate()
        .filter(|(_, (o, _))| *o == off)
        .nth(nth)
        .map(|(i, _)| i)
        .unwrap_or_else(|| panic!("register {off:#x} written fewer than {} times", nth + 1))
}

fn frame(tag: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| tag.wrapping_add(i as u8)).collect()
}

/// The block is programmed in the order the PDL's bring-up has: mode before
/// enable (the GEM registers answer only once enabled), quiesce before the
/// configuration, the pointers before receive and transmit are switched on.
#[test]
fn init_programs_the_block_in_order_and_points_the_dma_at_the_rings() {
    let (mac, model) = rig();
    let m = model.borrow();
    let log = &m.log;

    let mode_only = position(log, CTL, 0);
    let enabled = position(log, CTL, 1);
    assert_eq!(
        log[mode_only].1,
        CTL_ETH_MODE_RMII << CTL_ETH_MODE_POS,
        "RMII, external clock"
    );
    assert_eq!(
        log[enabled].1,
        (CTL_ETH_MODE_RMII << CTL_ETH_MODE_POS) | CTL_ENABLED
    );
    assert!(
        enabled < position(log, NETWORK_CONTROL, 0),
        "the block is enabled before any GEM register"
    );

    let quiesce = position(log, NETWORK_CONTROL, 0);
    assert_eq!(
        log[quiesce].1, 0,
        "nothing runs while the registers are set"
    );
    assert!(quiesce < position(log, NETWORK_CONFIG, 0));

    let netcfg = log[position(log, NETWORK_CONFIG, 0)].1;
    assert_ne!(netcfg & NWCFG_SPEED_100, 0);
    assert_ne!(netcfg & NWCFG_FULL_DUPLEX, 0);
    assert_ne!(netcfg & NWCFG_RECEIVE_1536, 0);
    assert_ne!(
        netcfg & NWCFG_FCS_REMOVE,
        0,
        "the FCS is stripped before the frame is handed up"
    );
    assert_ne!(netcfg & NWCFG_MULTICAST_HASH_ENABLE, 0);
    assert_eq!(netcfg & NWCFG_COPY_ALL_FRAMES, 0, "not promiscuous");
    assert_eq!(
        (netcfg >> NWCFG_MDC_DIV_POS) & 7,
        MdcDiv::By224 as u32,
        "the safe MDC divider"
    );

    let dma = log[position(log, DMA_CONFIG, 0)].1;
    assert_eq!(dma & 0x1F, DmaBurst::Single as u32);
    assert_eq!(
        (dma >> DMACFG_RX_BUF_SIZE_POS) & 0xFF,
        24,
        "1536 bytes in units of 64"
    );
    assert_ne!(dma & DMACFG_FORCE_DISCARD_ON_ERR, 0);

    for q in [
        TRANSMIT_Q1_PTR,
        TRANSMIT_Q2_PTR,
        RECEIVE_Q1_PTR,
        RECEIVE_Q2_PTR,
    ] {
        assert_eq!(m.reg(q), QPTR_DISABLE, "unused queue {q:#x} is disabled");
    }
    assert_eq!(m.reg(HASH_BOTTOM), 0xFFFF_FFFF);
    assert_eq!(m.reg(HASH_TOP), 0xFFFF_FFFF);
    assert_eq!(
        m.reg(SPEC_ADD1_BOTTOM),
        0x3322_1102,
        "the station address, little-endian words"
    );
    assert_eq!(m.reg(SPEC_ADD1_TOP), 0x5544);

    // The pointers are the bus addresses of the first descriptors.
    assert_eq!(m.reg(RECEIVE_Q_PTR), m.bus(m.rx_desc(0).0 as *const u8));
    assert_eq!(m.reg(TRANSMIT_Q_PTR), m.bus(m.tx_desc(0).0 as *const u8));
    let ptrs = position(log, TRANSMIT_Q_PTR, 0).max(position(log, RECEIVE_Q_PTR, 0));
    let go = position(log, NETWORK_CONTROL, 1);
    assert!(
        ptrs < go,
        "the pointers are set before receive and transmit are enabled"
    );
    assert_eq!(
        log[go].1,
        NWCTRL_MAN_PORT_EN | NWCTRL_ENABLE_RECEIVE | NWCTRL_ENABLE_TRANSMIT
    );

    // The rings: receive slots released with their buffers and a wrap on the last,
    // transmit slots all software-owned with a wrap on the last.
    for i in 0..RX {
        let d = m.rx_desc(i);
        let buf = m.bus(mac.rx_buf(i));
        assert_eq!(d.word0() & RXD_ADDR_MASK, buf);
        assert_eq!(
            d.word0() & RXD_USED,
            0,
            "slot {i} belongs to the controller"
        );
        assert_eq!(d.word0() & RXD_WRAP != 0, i == RX - 1);
    }
    for i in 0..TX {
        let d = m.tx_desc(i);
        assert_ne!(d.word1() & TXD_USED, 0, "slot {i} belongs to software");
        assert_eq!(d.word1() & TXD_WRAP != 0, i == TX - 1);
    }
    assert_eq!(mac.mac_address(), MAC);
}

#[test]
fn a_mac_that_could_not_be_this_station_is_refused() {
    let mut multicast = Config::new(MAC);
    multicast.mac_address[0] = 0x01;
    assert_eq!(
        rig_with::<RX, TX>(&multicast).0.err(),
        Some(InitError::InvalidMac)
    );
    assert_eq!(
        rig_with::<RX, TX>(&Config::new([0; 6])).0.err(),
        Some(InitError::InvalidMac)
    );

    for bad in [0u16, 257] {
        let mut c = Config::new(MAC);
        c.ref_clock = RefClock::InternalPll { divider: bad };
        assert_eq!(
            rig_with::<RX, TX>(&c).0.err(),
            Some(InitError::InvalidRefDivider),
            "divider {bad}"
        );
    }
    assert_eq!(
        rig_with::<1, TX>(&Config::new(MAC)).0.err(),
        Some(InitError::RingTooSmall)
    );
    assert_eq!(
        rig_with::<RX, 1>(&Config::new(MAC)).0.err(),
        Some(InitError::RingTooSmall)
    );
}

#[test]
fn the_pll_reference_clock_is_selected_and_divided_by_the_field_plus_one() {
    let mut c = Config::new(MAC);
    c.ref_clock = RefClock::InternalPll { divider: 4 };
    c.accept_all_multicast = false;
    let (_mac, model) = rig_with::<RX, TX>(&c);
    let m = model.borrow();
    let ctl = m.log[position(&m.log, CTL, 1)].1;
    assert_eq!((ctl >> CTL_REFCLK_SRC_SEL_POS) & 1, 1, "internal PLL");
    assert_eq!(
        (ctl >> CTL_REFCLK_DIV_POS) & 0xFF,
        3,
        "divide by four is the field three"
    );
    assert_eq!(
        m.reg(HASH_BOTTOM),
        0,
        "multicast refused when not asked for"
    );
    assert_eq!(m.reg(NETWORK_CONFIG) & NWCFG_MULTICAST_HASH_ENABLE, 0);
}

#[test]
fn frames_sent_go_out_whole_and_in_order_across_the_ring_wrap() {
    let (mut mac, model) = rig();
    let sent: Vec<Vec<u8>> = (0..TX * 3).map(|i| frame(i as u8, 60 + i * 7)).collect();
    for f in &sent {
        assert!(mac.transmit(f), "the controller drains each frame");
        let m = model.borrow();
        // Every send kicks the DMA.
        assert_ne!(m.log.last().unwrap().1 & NWCTRL_TX_START, 0);
    }
    assert_eq!(
        model.borrow().wire,
        sent,
        "byte-exact, in order, none lost across the wrap"
    );
}

#[test]
fn a_full_transmit_ring_refuses_until_the_controller_drains_it() {
    let (mut mac, model) = rig();
    model.borrow_mut().hold_tx = true;
    let held: Vec<Vec<u8>> = (0..TX).map(|i| frame(0x10 + i as u8, 80)).collect();
    for f in &held {
        assert!(mac.transmit(f));
    }
    assert!(
        !mac.transmit(&frame(0x99, 80)),
        "every slot is released and none sent"
    );
    assert!(model.borrow().wire.is_empty(), "the model is holding them");

    model.borrow_mut().drain();
    assert_eq!(
        model.borrow().wire,
        held,
        "the held frames leave in the order queued"
    );
    let next = frame(0x77, 90);
    assert!(mac.transmit(&next), "the ring has room again");
    assert_eq!(model.borrow().wire.last(), Some(&next));
}

#[test]
fn a_frame_with_no_bytes_or_too_many_is_not_queued() {
    let (mut mac, model) = rig();
    assert!(!mac.transmit(&[]));
    assert!(!mac.transmit(&vec![0u8; BUF_LEN + 1]));
    assert!(
        mac.transmit(&vec![0u8; BUF_LEN]),
        "the buffer's own size is the limit"
    );
    assert_eq!(model.borrow().wire.len(), 1);
}

// ---- gathered transmit: the controller reads the caller's memory in place -------

fn seg(bytes: &[u8]) -> TxSegment {
    TxSegment {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
    }
}

/// Everything `reap_tx` reports right now.
fn reaped(mac: &mut Cyt4bfMac<Gem, RX, TX>) -> Vec<u32> {
    let mut out = Vec::new();
    mac.reap_tx(&mut |cookie| out.push(cookie));
    out
}

/// The point of the seam: a frame in two pieces leaves as ONE frame, and the
/// descriptors point at the caller's own buffers, not at a copy in the ring.
#[test]
fn a_gathered_frame_leaves_whole_and_is_read_where_the_caller_wrote_it() {
    let (mut mac, model) = rig();
    let (header, payload) = (frame(0x10, 14), frame(0x40, 100));
    assert!(
        mac.gathers_in_place(),
        "this MAC says it can read in place, so a stack offers it pieces"
    );
    model.borrow_mut().expose(&header);
    model.borrow_mut().expose(&payload);

    // SAFETY: both buffers outlive the test and are not touched until it is over.
    let outcome = unsafe { mac.transmit_gather(&[seg(&header), seg(&payload)], 7) };

    assert_eq!(outcome, TxGather::Queued);
    let m = model.borrow();
    assert_eq!(m.wire, vec![[header.clone(), payload.clone()].concat()]);
    assert_eq!(m.violations, Vec::<String>::new());
    assert_eq!(
        m.tx_desc(0).word0(),
        m.bus(header.as_ptr()),
        "the first descriptor points at the caller's header"
    );
    assert_eq!(
        m.tx_desc(1).word0(),
        m.bus(payload.as_ptr()),
        "the second at the caller's payload"
    );
    assert_eq!(
        m.tx_desc(0).word1() & TXD_LAST,
        0,
        "the header is not the last"
    );
    assert_ne!(
        m.tx_desc(1).word1() & TXD_LAST,
        0,
        "the payload carries LAST"
    );
}

/// The caller owns the memory until it is told. Reported once, with its cookie,
/// and only after the controller finished with the frame.
#[test]
fn a_gathered_frame_is_reported_done_once_and_only_when_the_controller_has_read_it() {
    let (mut mac, model) = rig();
    let (a, b) = (frame(1, 20), frame(2, 30));
    model.borrow_mut().expose(&a);
    model.borrow_mut().expose(&b);
    model.borrow_mut().hold_tx = true;

    // SAFETY: as above.
    assert_eq!(
        unsafe { mac.transmit_gather(&[seg(&a), seg(&b)], 41) },
        TxGather::Queued
    );
    assert_eq!(
        reaped(&mut mac),
        Vec::<u32>::new(),
        "the controller has not read it"
    );

    model.borrow_mut().drain();
    assert_eq!(reaped(&mut mac), vec![41], "now it has");
    assert_eq!(reaped(&mut mac), Vec::<u32>::new(), "and it is said once");
}

/// A frame of several descriptors is released as a whole: its first descriptor is
/// published HELD, the rest follow, and the first is let go last. Read off the
/// order the descriptors were published in, since a polled model cannot be
/// raced.
#[test]
fn a_gathered_frame_is_released_by_its_first_descriptor_and_last() {
    let (mut mac, model) = rig();
    let parts = [frame(1, 14), frame(2, 40), frame(3, 60)];
    for p in &parts {
        model.borrow_mut().expose(p);
    }
    model.borrow_mut().desc_cleans.clear();

    // SAFETY: as above.
    let outcome =
        unsafe { mac.transmit_gather(&[seg(&parts[0]), seg(&parts[1]), seg(&parts[2])], 1) };
    assert_eq!(outcome, TxGather::Queued);

    let m = model.borrow();
    let order: Vec<usize> = m.desc_cleans.iter().map(|(i, _)| *i).collect();
    assert_eq!(
        order,
        vec![0, 1, 2, 0],
        "the first is published again, last"
    );
    assert_ne!(
        m.desc_cleans[0].1 & TXD_USED,
        0,
        "first published held, so the controller cannot start on a partial frame"
    );
    assert_eq!(
        m.desc_cleans[3].1 & TXD_USED,
        0,
        "and its release is the last thing written"
    );
    assert_eq!(
        m.violations,
        Vec::<String>::new(),
        "the controller never stopped inside the frame"
    );
    assert_eq!(m.wire.len(), 1);
}

/// A frame that wraps past the end of the ring: the wrap flag is on the last
/// slot only, and the controller follows it.
#[test]
fn a_gathered_frame_can_straddle_the_ring_wrap() {
    let (mut mac, model) = rig();
    let (f1, f2) = (frame(0x11, 70), frame(0x22, 71));
    assert!(mac.transmit(&f1));
    assert!(mac.transmit(&f2));
    let (a, b) = (frame(0x33, 20), frame(0x44, 25));
    model.borrow_mut().expose(&a);
    model.borrow_mut().expose(&b);

    // Slots 0 and 1 are used and done, so the next descriptor is 2 and the frame
    // takes 2 and then 0.
    // SAFETY: as above.
    assert_eq!(
        unsafe { mac.transmit_gather(&[seg(&a), seg(&b)], 9) },
        TxGather::Queued
    );

    let m = model.borrow();
    assert_eq!(
        m.wire,
        vec![f1, f2, [a.clone(), b.clone()].concat()],
        "the straddling frame is whole and in order"
    );
    assert_eq!(m.violations, Vec::<String>::new());
    assert_ne!(m.tx_desc(TX - 1).word1() & TXD_WRAP, 0);
    drop(m);
    assert_eq!(reaped(&mut mac), vec![9]);
}

/// More pieces than the ring has descriptors can never be queued, so they are
/// sent from a copy, which the caller can tell: nothing is held and no cookie
/// comes.
#[test]
fn more_pieces_than_descriptors_are_copied_and_nothing_is_held() {
    let (mut mac, model) = rig();
    let parts: Vec<Vec<u8>> = (0..=TX as u8).map(|i| frame(i, 10 + i as usize)).collect();
    let segs: Vec<TxSegment> = parts.iter().map(|p| seg(p)).collect();

    // SAFETY: the pieces outlive the call; being copied, nothing outlives it.
    assert_eq!(unsafe { mac.transmit_gather(&segs, 3) }, TxGather::Copied);

    assert_eq!(model.borrow().wire, vec![parts.concat()]);
    assert_eq!(reaped(&mut mac), Vec::<u32>::new());
}

/// A piece the board does not let the controller read where it lies (memory its DMA
/// master cannot reach, or that the CPU caches) is never handed over in place: the
/// whole frame is copied into the ring's own buffer, the descriptor points THERE,
/// and nothing is held. One piece outside is enough, since a frame is read whole.
#[test]
fn a_gathered_frame_with_a_piece_the_board_does_not_reach_is_copied_into_the_ring() {
    let (mut mac, model) = rig();
    let (header, payload) = (frame(0x10, 14), frame(0x40, 100));
    model.borrow_mut().expose(&header);
    // The payload is NOT exposed: on the board, cached or unreachable memory.

    // SAFETY: both buffers outlive the call; being copied, nothing outlives it.
    let outcome = unsafe { mac.transmit_gather(&[seg(&header), seg(&payload)], 21) };

    assert_eq!(outcome, TxGather::Copied);
    let m = model.borrow();
    assert_eq!(m.wire, vec![[header.clone(), payload.clone()].concat()]);
    assert_eq!(
        m.tx_desc(0).word0(),
        m.bus(mac.tx_buf(0)),
        "the descriptor points at the ring's own buffer, not the caller's"
    );
    drop(m);
    assert_eq!(
        reaped(&mut mac),
        Vec::<u32>::new(),
        "a copy reports no cookie"
    );
    let counts = mac.tx_counts();
    assert_eq!((counts.in_place, counts.copied), (0, 1));
    assert_eq!(counts.last_in_place_bus, None);
}

/// The counts a bench reads off a running node: a frame read in place counts as
/// such, and the address its first descriptor was written with is the caller's
/// first byte, as the controller sees it; a copied frame counts apart.
#[test]
fn the_counts_say_which_frames_were_read_in_place_and_where_the_last_began() {
    let (mut mac, model) = rig();
    let (header, payload) = (frame(0x20, 14), frame(0x50, 60));
    model.borrow_mut().expose(&header);
    model.borrow_mut().expose(&payload);

    assert!(mac.transmit(&frame(0x01, 60)), "one from a copy first");
    // SAFETY: both buffers outlive the test and are not touched until it is over.
    let outcome = unsafe { mac.transmit_gather(&[seg(&header), seg(&payload)], 3) };
    assert_eq!(outcome, TxGather::Queued);

    let counts = mac.tx_counts();
    assert_eq!((counts.in_place, counts.copied), (1, 1));
    assert_eq!(
        counts.last_in_place_bus,
        Some(model.borrow().bus(header.as_ptr())),
        "the first descriptor of the frame read in place names the caller's header"
    );
}

/// The real board reads in place only inside the window the firmware names, and a
/// board with no window reads nothing in place: it cleans no cache, so memory it has
/// not been told is uncached is memory it must not hand the controller.
#[test]
fn the_chip_board_reads_in_place_only_inside_its_window() {
    fn delay(_: u32) {}
    fn now() -> u64 {
        0
    }
    let window = [0u8; 64];
    let start = window.as_ptr();
    // SAFETY: neither board is used for MMIO here; only its in-place predicate is
    // asked, which reads no register.
    let bare = unsafe { Cyt4bfBoard::new(0, delay, now) };
    assert!(
        !bare.reads_in_place(start, 8),
        "no window, nothing in place"
    );
    // SAFETY: as above; the window is only compared against.
    let board = unsafe { Cyt4bfBoard::new(0, delay, now).with_in_place_window(start, 64) };
    assert!(board.reads_in_place(start, 64), "the whole window");
    // SAFETY: pointer arithmetic inside and one past `window`.
    let (inside, last, past) = unsafe { (start.add(10), start.add(63), start.add(64)) };
    assert!(board.reads_in_place(inside, 20));
    assert!(board.reads_in_place(last, 1));
    assert!(
        !board.reads_in_place(last, 2),
        "a piece that runs past the end"
    );
    assert!(!board.reads_in_place(past, 1), "a piece after it");
    let before = (start as usize - 1) as *const u8;
    assert!(
        !board.reads_in_place(before, 2),
        "a piece that starts before it"
    );
}

/// While a gathered frame's cookie has not been taken, the ring is held in order
/// behind it: the caller who queues in place and never reaps is refused once the
/// ring is full, which is back-pressure on memory it has not been given back.
#[test]
fn an_unreaped_frame_holds_its_descriptors_until_it_is_reaped() {
    let (mut mac, model) = rig();
    let (a, b) = (frame(5, 20), frame(6, 20));
    model.borrow_mut().expose(&a);
    model.borrow_mut().expose(&b);

    // SAFETY: as above.
    assert_eq!(
        unsafe { mac.transmit_gather(&[seg(&a), seg(&b)], 77) },
        TxGather::Queued
    );
    assert!(mac.transmit(&frame(7, 60)), "the third descriptor is free");
    assert!(
        !mac.transmit(&frame(8, 60)),
        "all three are still accounted for, though the controller is done"
    );

    assert_eq!(reaped(&mut mac), vec![77]);
    assert!(mac.transmit(&frame(9, 60)), "reaping gave the ring back");
    assert_eq!(model.borrow().wire.len(), 3);
}

/// A frame that needs more descriptors than are free is refused, and nothing is
/// written for it; with room it goes.
#[test]
fn a_gathered_frame_without_room_is_refused_and_leaves_the_ring_alone() {
    let (mut mac, model) = rig();
    let (a, b) = (frame(1, 20), frame(2, 20));
    model.borrow_mut().expose(&a);
    model.borrow_mut().expose(&b);
    model.borrow_mut().hold_tx = true;
    assert!(mac.transmit(&frame(0x50, 60)));
    assert!(mac.transmit(&frame(0x51, 60)));
    model.borrow_mut().desc_cleans.clear();

    // SAFETY: as above.
    assert_eq!(
        unsafe { mac.transmit_gather(&[seg(&a), seg(&b)], 5) },
        TxGather::Refused,
        "one descriptor free, two wanted"
    );
    assert!(
        model.borrow().desc_cleans.is_empty(),
        "a refused frame writes no descriptor"
    );

    model.borrow_mut().drain();
    // SAFETY: as above.
    assert_eq!(
        unsafe { mac.transmit_gather(&[seg(&a), seg(&b)], 5) },
        TxGather::Queued
    );
    assert_eq!(reaped(&mut mac), vec![5]);
}

#[test]
fn a_gather_that_is_not_a_frame_is_refused() {
    let (mut mac, _model) = rig();
    let one = frame(1, 10);
    let empty: [u8; 0] = [];
    let oversize = vec![0u8; TXD_LEN_MASK as usize + 1];
    let too_long = vec![0u8; BUF_LEN];
    // SAFETY: every piece is readable for the call and none is queued.
    unsafe {
        assert_eq!(mac.transmit_gather(&[], 1), TxGather::Refused, "no pieces");
        assert_eq!(
            mac.transmit_gather(&[seg(&one), seg(&empty)], 1),
            TxGather::Refused,
            "a piece of no bytes"
        );
        assert_eq!(
            mac.transmit_gather(&[seg(&oversize)], 1),
            TxGather::Refused,
            "a piece the length field cannot hold"
        );
        assert_eq!(
            mac.transmit_gather(&[seg(&too_long), seg(&one)], 1),
            TxGather::Refused,
            "more than a buffer's worth in all"
        );
    }
}

/// A transmit error loses the wire's frame but not its owner's memory: the DMA
/// is stopped, so the frame is complete as far as the memory goes, and its
/// cookie is reported. The frame behind it, and the ring, work again.
#[test]
fn a_gathered_frame_lost_to_a_transmit_error_is_still_reported_and_the_ring_recovers() {
    let (mut mac, model) = rig();
    let (a, b) = (frame(1, 20), frame(2, 20));
    model.borrow_mut().expose(&a);
    model.borrow_mut().expose(&b);
    model.borrow_mut().fail_next_tx = true;

    // SAFETY: as above.
    assert_eq!(
        unsafe { mac.transmit_gather(&[seg(&a), seg(&b)], 12) },
        TxGather::Queued
    );
    assert!(model.borrow().wire.is_empty(), "the controller stopped");

    let next = frame(3, 64);
    assert!(
        mac.transmit(&next),
        "the stopped queue is re-armed, then used"
    );
    assert_eq!(mac.tx_recoveries(), 1);
    assert_eq!(model.borrow().wire, vec![next], "the failed frame was lost");
    assert_eq!(model.borrow().violations, Vec::<String>::new());
    assert_eq!(
        reaped(&mut mac),
        vec![12],
        "but its memory is free, and it is said"
    );
}

/// A link known to be down takes no frame, gathered or not.
#[test]
fn a_gather_is_refused_while_the_link_is_down() {
    let (mut mac, model) = rig();
    model.borrow_mut().phy_link = false;
    assert_eq!(mac.bring_up_link(50_000), Err(LinkError::NoLink));
    assert_eq!(mac.link_state(), LinkState::Down);
    let bytes = frame(1, 30);
    model.borrow_mut().expose(&bytes);

    // SAFETY: the piece is readable for the call and nothing is queued.
    assert_eq!(
        unsafe { mac.transmit_gather(&[seg(&bytes)], 1) },
        TxGather::Refused,
        "a link known down is not sent into"
    );
    assert!(model.borrow().wire.is_empty());
}

#[test]
fn a_transmit_error_that_halts_the_dma_is_recovered_by_rearming_the_queue() {
    let (mut mac, model) = rig();
    model.borrow_mut().fail_next_tx = true;
    assert!(
        mac.transmit(&frame(1, 70)),
        "queued; the failure comes after"
    );
    assert!(
        model.borrow().wire.is_empty(),
        "the controller stopped on the error"
    );
    assert_ne!(model.borrow().reg(TRANSMIT_STATUS) & TXSR_FATAL, 0);

    let next = frame(2, 75);
    assert!(
        mac.transmit(&next),
        "the stopped queue is re-armed, then used"
    );
    assert_eq!(mac.tx_recoveries(), 1);
    let m = model.borrow();
    assert_eq!(
        m.wire,
        vec![next],
        "the frame behind the failure is lost, the next one is sent"
    );
    assert_eq!(
        m.reg(TRANSMIT_STATUS) & TXSR_FATAL,
        0,
        "the error was cleared"
    );
    let rearm = position(&m.log, TRANSMIT_Q_PTR, 1);
    assert_eq!(
        m.log[rearm].1,
        m.bus(m.tx_desc(0).0 as *const u8),
        "pointed back at the first slot"
    );
}

#[test]
fn frames_received_come_out_in_order_and_the_ring_is_reused_past_its_wrap() {
    let (mut mac, model) = rig();
    let mut buf = [0u8; 1600];
    assert_eq!(mac.receive(&mut buf), None, "CONTROL: nothing arrived");
    for round in 0..RX * 3 {
        let f = frame(round as u8, 64 + round * 11);
        assert!(
            model.borrow_mut().inject_rx(&f),
            "a free buffer for frame {round}"
        );
        let got = mac.receive(&mut buf).expect("the frame is waiting");
        assert_eq!(&buf[..got], &f[..], "frame {round}");
    }
    assert_eq!(mac.receive(&mut buf), None);
}

#[test]
fn several_frames_waiting_are_returned_one_per_call_in_arrival_order() {
    let (mut mac, model) = rig();
    let frames: Vec<Vec<u8>> = (0..RX).map(|i| frame(0x40 + i as u8, 100)).collect();
    for f in &frames {
        assert!(model.borrow_mut().inject_rx(f));
    }
    let mut buf = [0u8; 256];
    for f in &frames {
        assert_eq!(
            mac.receive(&mut buf).map(|n| buf[..n].to_vec()),
            Some(f.clone())
        );
    }
    assert_eq!(mac.receive(&mut buf), None);
}

// ---- received frames lent in place ------------------------------------------

/// The bytes of a loan, read where the MAC says they are.
fn loan_bytes(loan: &RxLoan) -> Vec<u8> {
    // SAFETY: the loan is live; the test returns it only afterwards.
    unsafe { std::slice::from_raw_parts(loan.ptr, loan.len) }.to_vec()
}

/// The point of the seam: the frame is lent in the controller's own buffer, not
/// copied out of it, and the MAC says it can lend.
#[test]
fn a_received_frame_is_lent_in_the_buffer_the_controller_wrote() {
    let (mut mac, model) = rig();
    assert!(mac.loans_rx(), "this MAC says it lends received frames");
    assert!(mac.receive_loan().is_none(), "CONTROL: nothing arrived");

    let f = frame(0x31, 200);
    assert!(model.borrow_mut().inject_rx(&f));
    let loan = mac.receive_loan().expect("the frame is waiting");

    assert_eq!(loan_bytes(&loan), f);
    let m = model.borrow();
    let slot_buffer = m.ptr(m.rx_desc(0).word0() & RXD_ADDR_MASK) as *const u8;
    assert_eq!(
        loan.ptr, slot_buffer,
        "the loan IS the slot's buffer, so nothing was copied"
    );
    assert_eq!(loan.cookie, 0);
}

/// A lent buffer is the stack's to read, so the controller must not get it back
/// until it is returned: with every other buffer in use the ring is full, which
/// the controller reports as no buffer available, and it receives again as soon
/// as the loan comes back.
#[test]
fn a_lent_buffer_stays_out_of_the_controllers_reach_until_it_is_returned() {
    let (mut mac, model) = rig();
    let first = frame(0x01, 90);
    assert!(model.borrow_mut().inject_rx(&first));
    let loan = mac.receive_loan().expect("lent");

    // The other buffers are used and given back as usual.
    let mut buf = [0u8; 256];
    for i in 1..RX {
        assert!(model.borrow_mut().inject_rx(&frame(0x10 + i as u8, 70)));
        mac.receive(&mut buf).expect("a copied frame");
    }
    // The ring has come round to the lent buffer: no room for one more.
    assert!(
        !model.borrow_mut().inject_rx(&frame(0x77, 60)),
        "the controller has no buffer: the lent one is not its to fill"
    );
    assert_ne!(
        model.borrow().reg(RECEIVE_STATUS) & RXSR_BUFFER_NOT_AVAILABLE,
        0
    );
    assert_eq!(loan_bytes(&loan), first, "and the lent frame is untouched");

    mac.return_rx(loan.cookie);
    let again = frame(0x78, 66);
    assert!(
        model.borrow_mut().inject_rx(&again),
        "the returned buffer is the controller's again"
    );
    assert_eq!(
        mac.receive_loan().map(|l| loan_bytes(&l)),
        Some(again),
        "and the next frame arrives in it"
    );
}

/// The ring coming all the way round to a buffer that is still lent must not hand
/// the old frame up a second time: the descriptor still says "finished", but the
/// stack already holds that frame.
#[test]
fn a_lap_of_the_ring_does_not_deliver_a_lent_frame_twice() {
    let (mut mac, model) = rig();
    assert!(model.borrow_mut().inject_rx(&frame(0x05, 80)));
    let loan = mac.receive_loan().expect("lent");
    let mut buf = [0u8; 256];
    for i in 1..RX {
        assert!(model.borrow_mut().inject_rx(&frame(0x20 + i as u8, 80)));
        mac.receive(&mut buf).expect("copied");
    }
    assert!(
        mac.receive_loan().is_none(),
        "the head is back on the lent slot: nothing new is waiting"
    );
    assert!(mac.receive(&mut buf).is_none(), "nor by the copying door");
    mac.return_rx(loan.cookie);
}

/// A cookie that names no lent buffer is ignored: returning one twice, or one that
/// was never lent, must not arm a buffer the controller is filling.
#[test]
fn a_stale_or_foreign_cookie_arms_nothing() {
    let (mut mac, model) = rig();
    assert!(model.borrow_mut().inject_rx(&frame(0x09, 70)));
    let loan = mac.receive_loan().expect("lent");
    mac.return_rx(loan.cookie);

    // The slot is now the controller's; a frame arrives in it.
    let f = frame(0x0a, 71);
    for i in 1..RX {
        assert!(model.borrow_mut().inject_rx(&frame(0x30 + i as u8, 60)));
    }
    let mut buf = [0u8; 256];
    for _ in 1..RX {
        mac.receive(&mut buf).expect("drain the others");
    }
    assert!(model.borrow_mut().inject_rx(&f), "slot 0 again");
    mac.return_rx(loan.cookie); // a second return of the same loan
    mac.return_rx(3); // never lent
    mac.return_rx(99); // not a slot at all
    assert_eq!(
        mac.receive(&mut buf).map(|n| buf[..n].to_vec()),
        Some(f),
        "the frame the controller wrote survived"
    );
}

/// A frame that spans buffers is no frame this driver can hand up, lent or not:
/// it is dropped and its buffer goes straight back.
#[test]
fn a_frame_that_is_not_whole_is_not_lent_and_its_buffer_is_returned() {
    let (mut mac, model) = rig();
    {
        let m = model.borrow();
        let d = m.rx_desc(0);
        d.set_word1(1000 | RXD_SOF);
        d.set_word0(d.word0() | RXD_USED);
    }
    let whole = frame(0x44, 100);
    // The model's own cursor has to move past slot 0 for the next frame.
    model.borrow_mut().rx_idx = 1;
    assert!(model.borrow_mut().inject_rx(&whole));
    let loan = mac
        .receive_loan()
        .expect("the whole frame after the bad one");
    assert_eq!(loan_bytes(&loan), whole);
    assert_eq!(loan.cookie, 1, "slot 0 was dropped, not lent");
    mac.return_rx(loan.cookie);
}

/// Re-arming the whole ring (a link change does it) must leave a lent buffer
/// alone: the stack is still reading it.
#[test]
fn re_arming_the_ring_leaves_a_lent_buffer_alone() {
    let (mut mac, model) = rig();
    let f = frame(0x61, 120);
    assert!(model.borrow_mut().inject_rx(&f));
    let loan = mac.receive_loan().expect("lent");

    mac.init_rx_ring();

    assert_ne!(
        model.borrow().rx_desc(0).word0() & RXD_USED,
        0,
        "the lent slot is still software-owned, so the controller cannot fill it"
    );
    assert_eq!(loan_bytes(&loan), f);
    mac.return_rx(loan.cookie);
    assert_eq!(
        model.borrow().rx_desc(0).word0() & RXD_USED,
        0,
        "and it is the controller's once returned"
    );
}

#[test]
fn a_frame_longer_than_the_callers_buffer_is_dropped_whole_not_truncated() {
    let (mut mac, model) = rig();
    assert!(model.borrow_mut().inject_rx(&frame(1, 900)));
    let small = frame(2, 60);
    assert!(model.borrow_mut().inject_rx(&small));
    let mut buf = [0u8; 128];
    let got = mac.receive(&mut buf).expect("the one that fits");
    assert_eq!(
        &buf[..got],
        &small[..],
        "the long one was dropped, not cut to fit"
    );
    assert_eq!(mac.receive(&mut buf), None);
}

#[test]
fn a_frame_that_spans_buffers_is_not_handed_up_and_its_slot_is_returned() {
    let (mut mac, model) = rig();
    {
        let m = model.borrow();
        let d = m.rx_desc(0);
        // SOF without EOF: the first buffer of a longer frame.
        d.set_word1(1000 | RXD_SOF);
        d.set_word0(d.word0() | RXD_USED);
    }
    let mut buf = [0u8; 1600];
    assert_eq!(mac.receive(&mut buf), None);
    let m = model.borrow();
    assert_eq!(
        m.rx_desc(0).word0() & RXD_USED,
        0,
        "the slot is the controller's again"
    );
}

#[test]
fn a_receive_ring_that_ran_dry_recovers_once_the_buffers_are_taken() {
    let (mut mac, model) = rig();
    for i in 0..RX {
        assert!(model.borrow_mut().inject_rx(&frame(i as u8, 64)));
    }
    assert!(
        !model.borrow_mut().inject_rx(&frame(0xEE, 64)),
        "no buffer left: the frame is lost"
    );
    assert_ne!(
        model.borrow().reg(RECEIVE_STATUS) & RXSR_BUFFER_NOT_AVAILABLE,
        0
    );

    let mut buf = [0u8; 256];
    for _ in 0..RX {
        assert!(mac.receive(&mut buf).is_some());
    }
    assert_eq!(mac.receive(&mut buf), None);
    assert_eq!(
        model.borrow().reg(RECEIVE_STATUS) & RXSR_BUFFER_NOT_AVAILABLE,
        0,
        "the condition is cleared once the buffers are free"
    );
    assert!(
        model.borrow_mut().inject_rx(&frame(0x55, 64)),
        "reception carries on"
    );
}

// ---- a pooled receive ring (ARCHITECTURE section 9.2) ----------------------------
//
// The ring's receive buffers are the slots of the GENERATED Ethernet receive pool
// (`sources/network/eth_rx_pool_mcu.scxml`, 16 slots of 1536 bytes), bound through
// the lwIP link crate's binding, which an image installs the same way.

type PooledArea = DmaArea<RX, TX, 0>;
type PooledMac = Cyt4bfMac<Gem, RX, TX, 0>;

/// The generated pool's slot count, the pool every pooled test binds.
const POOL_SLOTS: usize = wz_link_lwip::eth_rx_pool_mcu::SLOT_COUNT;

/// A freshly installed generated pool, and where its slots are.
fn generated_pool() -> (&'static mut (dyn MacRxPool + Send), (usize, usize)) {
    let storage: &'static mut wz_link_lwip::mac_rx_pool::RxPoolStorage =
        Box::leak(Box::new(wz_link_lwip::mac_rx_pool::RxPoolStorage::uninit()));
    let ring = wz_link_lwip::mac_rx_pool::install(storage);
    let (start, len) = ring.span();
    (ring, (start as usize, len))
}

/// What a pooled rig is: the MAC (or why it refused), the model, and where the
/// pool's slots are.
type PooledRig = (
    Result<PooledMac, InitError>,
    Rc<RefCell<Model>>,
    (usize, usize),
);

/// A pooled MAC over the model, with the pool exposed to the controller (`expose`)
/// or not.
fn pooled_rig_on(expose: bool) -> PooledRig {
    let area: &'static mut PooledArea = Box::leak(Box::new(DmaArea::new()));
    let start = &mut *area as *mut PooledArea as usize;
    let mut model = Model::new(start);
    let (pool, span) = generated_pool();
    if expose {
        // SAFETY: the pool's slots, leaked for the test's life.
        model.expose(unsafe { std::slice::from_raw_parts(span.0 as *const u8, span.1) });
    }
    let model = Rc::new(RefCell::new(model));
    let mac = Cyt4bfMac::new_pooled(Gem(model.clone()), area, pool, &Config::new(MAC));
    (mac, model, span)
}

fn pooled_rig() -> (PooledMac, Rc<RefCell<Model>>, (usize, usize)) {
    let (mac, model, span) = pooled_rig_on(true);
    let mac = mac.expect("a valid configuration and pool");
    assert_eq!(model.borrow().violations, Vec::<String>::new());
    (mac, model, span)
}

/// The slot of the generated pool `ptr` is the first byte of, if it is one.
fn slot_at(span: (usize, usize), ptr: *const u8) -> Option<usize> {
    let offset = (ptr as usize).checked_sub(span.0)?;
    (offset < span.1 && offset % BUF_LEN == 0).then_some(offset / BUF_LEN)
}

/// Every slot of the pool is free, held by a receive descriptor, or lent to the
/// stack, and the MAC's and the pool's own counts say which: free plus held plus
/// lent and not returned is the pool's size.
fn assert_every_slot_is_accounted_for(mac: &PooledMac, what: &str) {
    let (free, size) = mac.rx_pool_free().expect("a pooled ring");
    let in_ring = mac.rx_slots_in_ring().expect("a pooled ring");
    let c = mac.rx_counts();
    let out = c.lent.wrapping_sub(c.returned) as usize;
    assert_eq!(
        free + in_ring + out,
        size,
        "{what}: free {free} + in the ring {in_ring} + lent {out} is not {size}"
    );
}

/// The point: the frame is lent IN A SLOT OF THE GENERATED POOL, at the slot's
/// first byte, which is where the controller wrote it, and the descriptor it came
/// from is armed again at once with another slot.
#[test]
fn a_pooled_ring_lends_a_frame_in_the_pool_slot_the_controller_wrote() {
    let (mut mac, model, span) = pooled_rig();
    assert_every_slot_is_accounted_for(&mac, "at bring-up");
    assert_eq!(mac.rx_slots_in_ring(), Some(RX), "every descriptor armed");
    let written_into = {
        let m = model.borrow();
        m.ptr(m.rx_desc(0).word0() & RXD_ADDR_MASK) as *const u8
    };
    assert!(
        slot_at(span, written_into).is_some(),
        "the descriptor points into the pool, not the area"
    );

    let f = frame(0x31, 200);
    assert!(model.borrow_mut().inject_rx(&f));
    let loan = mac.receive_loan().expect("the frame is waiting");

    assert_eq!(loan_bytes(&loan), f);
    assert_eq!(loan.ptr, written_into, "lent where the controller wrote it");
    assert_eq!(
        slot_at(span, loan.ptr),
        Some(loan.cookie as usize),
        "the cookie is the slot's index"
    );
    let rearmed = {
        let m = model.borrow();
        let d = m.rx_desc(0);
        (
            d.word0() & RXD_USED,
            m.ptr(d.word0() & RXD_ADDR_MASK) as *const u8,
        )
    };
    assert_eq!(rearmed.0, 0, "the descriptor is the controller's again");
    assert_ne!(rearmed.1, loan.ptr, "with another slot");
    assert!(slot_at(span, rearmed.1).is_some());
    assert_every_slot_is_accounted_for(&mac, "with one frame lent");

    mac.return_rx(loan.cookie);
    assert_eq!(mac.rx_counts().returned, 1);
    assert_every_slot_is_accounted_for(&mac, "after the return");
    assert_eq!(mac.rx_pool_free(), Some((POOL_SLOTS - RX, POOL_SLOTS)));
}

/// A lent frame holds its slot and not the ring: a ring that owns its buffers
/// stops at a lent one, and a pooled ring takes a full lap of frames behind it,
/// the lent frame untouched.
#[test]
fn a_frame_the_stack_holds_does_not_hold_the_pooled_ring() {
    let (mut mac, model, _) = pooled_rig();
    let first = frame(0x01, 90);
    assert!(model.borrow_mut().inject_rx(&first));
    let held = mac.receive_loan().expect("lent");

    for lap in 0..2 {
        for i in 0..RX {
            assert!(
                model.borrow_mut().inject_rx(&frame(0x10 + i as u8, 70)),
                "lap {lap} frame {i}: a buffer, though the first frame is still held"
            );
        }
        let mut buf = [0u8; 256];
        for _ in 0..RX {
            mac.receive(&mut buf).expect("a copied frame");
        }
    }
    assert_eq!(loan_bytes(&held), first, "and the held frame is untouched");
    mac.return_rx(held.cookie);
    assert_every_slot_is_accounted_for(&mac, "after the laps");

    // CONTROL: the ring that owns its buffers does stop at the lent one.
    let (mut owned, owned_model) = rig();
    assert!(owned_model.borrow_mut().inject_rx(&first));
    let _lent = owned.receive_loan().expect("lent");
    let mut buf = [0u8; 256];
    for i in 1..RX {
        assert!(owned_model.borrow_mut().inject_rx(&frame(i as u8, 70)));
        owned.receive(&mut buf).expect("copied");
    }
    assert!(
        !owned_model.borrow_mut().inject_rx(&frame(0x77, 60)),
        "CONTROL: the owned ring is full at its lent buffer"
    );
}

/// A BURST LARGER THAN THE POOL NEVER LOSES A SLOT. The stack holds every frame
/// it is lent: the ring re-arms from the pool until the pool is dry, then each
/// descriptor taken is left unarmed and counted, the controller reports no buffer
/// rather than writing anywhere, and every frame lent is a distinct slot with its
/// own bytes. When the stack gives them all back, every descriptor is armed again
/// and reception carries on; at every step free, held and lent add up to the pool.
#[test]
fn a_burst_larger_than_the_pool_never_loses_a_slot_and_counts_its_refusals() {
    let (mut mac, model, span) = pooled_rig();
    let mut loans = Vec::new();
    let mut injected = 0usize;
    let mut refused_by_controller = 0usize;
    for n in 0..POOL_SLOTS + RX + 3 {
        let f = frame(n as u8, 60 + n);
        if model.borrow_mut().inject_rx(&f) {
            injected += 1;
            let loan = mac.receive_loan().expect("the frame just written");
            assert_eq!(loan_bytes(&loan), f, "frame {n}");
            loans.push((loan, f));
        } else {
            refused_by_controller += 1;
        }
        assert_every_slot_is_accounted_for(&mac, &format!("after frame {n}"));
    }
    assert_eq!(
        injected, POOL_SLOTS,
        "every slot carried one frame, no more"
    );
    assert_eq!(refused_by_controller, RX + 3);
    assert_eq!(mac.rx_pool_free(), Some((0, POOL_SLOTS)));
    assert_eq!(mac.rx_slots_in_ring(), Some(0), "the ring is unarmed");
    assert_eq!(
        mac.rx_counts().refused as usize,
        RX,
        "each descriptor that could not be re-armed is counted once"
    );
    assert_ne!(
        model.borrow().reg(RECEIVE_STATUS) & RXSR_BUFFER_NOT_AVAILABLE,
        0,
        "the controller says no buffer, it does not write"
    );
    let mut slots: Vec<usize> = loans
        .iter()
        .map(|(l, _)| slot_at(span, l.ptr).expect("a slot"))
        .collect();
    slots.sort_unstable();
    slots.dedup();
    assert_eq!(slots.len(), POOL_SLOTS, "every loan is its own slot");
    for (loan, f) in &loans {
        assert_eq!(&loan_bytes(loan), f, "no frame was written over");
    }

    for (loan, _) in &loans {
        mac.return_rx(loan.cookie);
        assert_every_slot_is_accounted_for(&mac, "while returning");
    }
    assert_eq!(mac.rx_counts().returned as usize, POOL_SLOTS);
    assert_eq!(
        mac.rx_slots_in_ring(),
        Some(RX),
        "every descriptor armed again"
    );
    assert_eq!(mac.rx_pool_free(), Some((POOL_SLOTS - RX, POOL_SLOTS)));
    let after = frame(0xEE, 99);
    assert!(model.borrow_mut().inject_rx(&after), "reception carries on");
    assert_eq!(mac.receive_loan().map(|l| loan_bytes(&l)), Some(after));
}

/// The bytes a pooled ring lends are the bytes the copying ring hands up, frame
/// for frame, across more than a lap of the ring.
#[test]
fn a_pooled_ring_hands_up_the_bytes_the_copying_ring_does() {
    let frames: Vec<Vec<u8>> = (0..RX * 3)
        .map(|i| frame(i as u8 * 7, 64 + i * 13))
        .collect();
    let (mut copying, copying_model) = rig();
    let mut buf = [0u8; 1600];
    let copied: Vec<Vec<u8>> = frames
        .iter()
        .map(|f| {
            assert!(copying_model.borrow_mut().inject_rx(f));
            let n = copying.receive(&mut buf).expect("waiting");
            buf[..n].to_vec()
        })
        .collect();
    let (mut pooled, pooled_model, _) = pooled_rig();
    let lent: Vec<Vec<u8>> = frames
        .iter()
        .map(|f| {
            assert!(pooled_model.borrow_mut().inject_rx(f));
            let loan = pooled.receive_loan().expect("waiting");
            let bytes = loan_bytes(&loan);
            pooled.return_rx(loan.cookie);
            bytes
        })
        .collect();
    assert_eq!(lent, copied);
    assert_eq!(lent, frames);
}

/// The copying door works on a pooled ring too, and its slot goes straight home.
#[test]
fn a_pooled_ring_copies_out_through_the_copying_door_and_keeps_no_slot() {
    let (mut mac, model, _) = pooled_rig();
    let f = frame(0x42, 300);
    assert!(model.borrow_mut().inject_rx(&f));
    let mut buf = [0u8; 1600];
    let n = mac.receive(&mut buf).expect("waiting");
    assert_eq!(&buf[..n], &f[..]);
    assert_eq!(mac.rx_counts().copied, 1);
    assert_eq!(mac.rx_pool_free(), Some((POOL_SLOTS - RX, POOL_SLOTS)));
    assert_every_slot_is_accounted_for(&mac, "after a copy");
}

/// A cookie that names no lent slot frees nothing: a second return, a slot the
/// ring holds, and an index past the pool.
#[test]
fn a_pooled_ring_frees_nothing_for_a_stale_or_foreign_cookie() {
    let (mut mac, model, span) = pooled_rig();
    assert!(model.borrow_mut().inject_rx(&frame(0x09, 70)));
    let loan = mac.receive_loan().expect("lent");
    mac.return_rx(loan.cookie);
    let in_ring = {
        let m = model.borrow();
        slot_at(span, m.ptr(m.rx_desc(1).word0() & RXD_ADDR_MASK)).expect("a slot")
    };
    let before = (mac.rx_counts(), mac.rx_pool_free());
    mac.return_rx(loan.cookie);
    mac.return_rx(in_ring as u32);
    mac.return_rx(POOL_SLOTS as u32 + 7);
    assert_eq!((mac.rx_counts(), mac.rx_pool_free()), before);
    let f = frame(0x0a, 71);
    assert!(model.borrow_mut().inject_rx(&f));
    assert_eq!(mac.receive_loan().map(|l| loan_bytes(&l)), Some(f));
}

/// A frame that is not one buffer long is dropped on a pooled ring as on the
/// other, its slot goes home, the descriptor is armed again, and it is counted.
#[test]
fn a_frame_that_is_not_whole_on_a_pooled_ring_returns_its_slot() {
    let (mut mac, model, _) = pooled_rig();
    {
        let m = model.borrow();
        let d = m.rx_desc(0);
        d.set_word1(1000 | RXD_SOF);
        d.set_word0(d.word0() | RXD_USED);
    }
    model.borrow_mut().rx_idx = 1;
    let whole = frame(0x44, 100);
    assert!(model.borrow_mut().inject_rx(&whole));
    let loan = mac
        .receive_loan()
        .expect("the whole frame after the bad one");
    assert_eq!(loan_bytes(&loan), whole);
    assert_eq!(mac.rx_counts().dropped, 1);
    assert_eq!(model.borrow().rx_desc(0).word0() & RXD_USED, 0, "re-armed");
    assert_every_slot_is_accounted_for(&mac, "after the drop");
    mac.return_rx(loan.cookie);
}

/// A pool is refused before any register is written when the controller may not
/// write it for the CPU to read in place, when its slots are smaller than the
/// receive buffer, when it has fewer slots than the ring has descriptors, and when
/// its slots are not 32-byte aligned.
#[test]
fn a_pool_the_ring_cannot_use_is_refused_before_the_block_is_touched() {
    let (mac, model, _) = pooled_rig_on(false);
    assert_eq!(mac.err(), Some(InitError::RxPoolOutsideWindow));
    assert!(model.borrow().log.is_empty(), "no register written");

    /// A pool that only answers questions about its shape.
    struct Shape {
        size: usize,
        count: usize,
        start: usize,
    }
    impl MacRxPool for Shape {
        fn slot_size(&self) -> usize {
            self.size
        }
        fn slot_count(&self) -> usize {
            self.count
        }
        fn span(&self) -> (*const u8, usize) {
            (self.start as *const u8, self.size * self.count)
        }
        fn arm_rx(&mut self) -> Option<(usize, *mut u8)> {
            None
        }
        unsafe fn start_rx(&mut self, _: usize) -> bool {
            false
        }
        unsafe fn complete_rx(&mut self, _: usize) -> Option<*const u8> {
            None
        }
        fn release_rx(&mut self, _: usize) -> bool {
            false
        }
        fn free_count(&self) -> usize {
            0
        }
    }
    for (shape, refusal) in [
        (
            Shape {
                size: 1024,
                count: 16,
                start: 0x1000,
            },
            InitError::RxPoolSlotTooSmall,
        ),
        (
            Shape {
                size: 1536,
                count: RX - 1,
                start: 0x1000,
            },
            InitError::RxPoolTooFewSlots,
        ),
        (
            Shape {
                size: 1536,
                count: 16,
                start: 0x1010,
            },
            InitError::RxPoolMisaligned,
        ),
        (
            Shape {
                size: 1544,
                count: 16,
                start: 0x1000,
            },
            InitError::RxPoolMisaligned,
        ),
    ] {
        let area: &'static mut PooledArea = Box::leak(Box::new(DmaArea::new()));
        let model = Rc::new(RefCell::new(Model::new(
            &mut *area as *mut PooledArea as usize,
        )));
        let pool: &'static mut (dyn MacRxPool + Send) = Box::leak(Box::new(shape));
        let mac = Cyt4bfMac::new_pooled(Gem(model.clone()), area, pool, &Config::new(MAC));
        assert_eq!(mac.err(), Some(refusal));
        assert!(
            model.borrow().log.is_empty(),
            "{refusal:?}: no register written"
        );
    }
}

/// The chip's board lets the controller write received frames only inside the
/// window the firmware names for that, and a board given none refuses every pool.
#[test]
fn the_chip_board_receives_in_place_only_inside_its_receive_window() {
    fn delay(_: u32) {}
    fn now() -> u64 {
        0
    }
    let window = [0u8; 256];
    // SAFETY: a base no register is read through in this test.
    let bare = unsafe { Cyt4bfBoard::new(0, delay, now) };
    assert!(
        !bare.receives_in_place(window.as_ptr(), 1),
        "no window, nothing"
    );
    // SAFETY: as above; the window is only compared against.
    let board = unsafe { bare.with_receive_window(window.as_ptr(), window.len()) };
    assert!(board.receives_in_place(window.as_ptr(), window.len()));
    // SAFETY: pointer arithmetic for comparison only.
    let inside = unsafe { window.as_ptr().add(100) };
    assert!(board.receives_in_place(inside, 156));
    assert!(
        !board.receives_in_place(inside, 157),
        "one byte past the end"
    );
    assert!(
        !board.reads_in_place(window.as_ptr(), 1),
        "the receive window is not the transmit window"
    );
}

#[test]
fn management_frames_are_clause_22_and_wait_for_the_port_to_go_idle() {
    use phy::Mdio;
    let (mut mac, model) = rig();
    model.borrow_mut().phy_addr = 5;
    model.borrow_mut().mdio_busy_polls = 4;
    let before = model.borrow().delays_us;
    let id = mac.mdio_read(5, phy::reg::PHYIDR1).unwrap();
    assert_eq!(id, 0x2000);
    {
        let m = model.borrow();
        let (off, word) = *m
            .log
            .iter()
            .rev()
            .find(|(o, _)| *o == PHY_MANAGEMENT)
            .unwrap();
        assert_eq!(off, PHY_MANAGEMENT);
        assert_eq!(
            word,
            MDIO_START_C22
                | (MDIO_OP_READ << MDIO_OP_POS)
                | (5 << MDIO_PHY_POS)
                | (2 << MDIO_REG_POS)
                | MDIO_TURNAROUND,
            "a clause 22 read of register 2 at address 5"
        );
        assert!(
            m.delays_us - before >= 4 * MDIO_POLL_US + MDIO_READ_SETTLE_US,
            "it polled the busy port and then let the data settle"
        );
        assert_eq!(m.bad_frames, 0);
    }
    mac.mdio_write(5, phy::reg::ANAR, 0x0123).unwrap();
    let m = model.borrow();
    let (_, word) = *m
        .log
        .iter()
        .rev()
        .find(|(o, _)| *o == PHY_MANAGEMENT)
        .unwrap();
    assert_eq!(
        word,
        MDIO_START_C22
            | (MDIO_OP_WRITE << MDIO_OP_POS)
            | (5 << MDIO_PHY_POS)
            | (4 << MDIO_REG_POS)
            | MDIO_TURNAROUND
            | 0x0123
    );
    assert_eq!(m.phy_regs[4], 0x0123);
}

#[test]
fn a_management_port_that_never_goes_idle_times_out_instead_of_hanging() {
    use phy::Mdio;
    let (mut mac, model) = rig();
    model.borrow_mut().mdio_stuck = true;
    assert_eq!(mac.mdio_read(1, 2), Err(MdioError::Timeout));
    assert!(model.borrow().delays_us >= MDIO_BUDGET_US);
}

/// Every bound is measured on the board's clock, not counted in the waits asked
/// for. A wait promises AT LEAST its length: the first boot of a CYT4BF image ran
/// its core at 8 MHz where 350 MHz was assumed and every wait took about 44 times
/// what it was told, so a budget counted in waits lasted 44 times its length.
const SLOW: u64 = 44;

#[test]
fn the_management_port_budget_is_the_clocks_not_the_number_of_waits_asked_for() {
    use phy::Mdio;
    let (mut mac, model) = rig();
    {
        let mut m = model.borrow_mut();
        m.mdio_stuck = true;
        m.delay_stretch = SLOW;
    }
    let (clock0, asks0) = {
        let m = model.borrow();
        (m.clock_us, m.delay_calls)
    };
    assert_eq!(mac.mdio_read(1, 2), Err(MdioError::Timeout));

    let m = model.borrow();
    let step = SLOW * u64::from(MDIO_POLL_US);
    let budget = u64::from(MDIO_BUDGET_US);
    let spent = m.clock_us - clock0;
    assert_eq!(
        u64::from(m.delay_calls - asks0),
        budget.div_ceil(step),
        "the clock ended the wait; counting the asks would have made {}",
        budget / u64::from(MDIO_POLL_US)
    );
    assert!(
        spent >= budget && spent < budget + step,
        "it ended within one wait of the budget: {spent} us"
    );
}

#[test]
fn a_management_port_that_goes_idle_during_a_wait_that_overran_is_not_a_timeout() {
    use phy::Mdio;
    let (mut mac, model) = rig();
    {
        let mut m = model.borrow_mut();
        m.delay_stretch = SLOW;
        m.mdio_busy_polls = 0;
        // Past the budget, inside the wait that crosses it.
        m.mdio_busy_until_us = m.clock_us + u64::from(MDIO_BUDGET_US) + 100;
    }
    assert_eq!(
        mac.mdio_read(1, phy::reg::PHYIDR1),
        Ok(0x2000),
        "the port is looked at once more after the wait that overran"
    );
    assert!(model.borrow().clock_us > u64::from(MDIO_BUDGET_US));
}

#[test]
fn the_link_budget_of_bring_up_is_the_clocks_not_the_number_of_waits_asked_for() {
    let mut config = Config::new(MAC);
    config.phy_address = Some(1);
    let (mac, model) = rig_with::<RX, TX>(&config);
    let mut mac = mac.unwrap();
    model.borrow_mut().delay_stretch = SLOW;
    let budget = 1_000_000u32;

    assert_eq!(mac.bring_up_link(budget), Err(LinkError::NoLink));

    let m = model.borrow();
    assert!(
        m.clock_us >= u64::from(budget),
        "it waited out the budget: {} us",
        m.clock_us
    );
    // Counted in waits of 10 ms, 1 s is a hundred of them, each 44 times as long
    // here: more than a minute. On the clock it is a few seconds.
    assert!(
        m.clock_us < 3 * u64::from(budget),
        "the budget ended on the clock, not on a count: {} us",
        m.clock_us
    );
}

#[test]
fn the_link_comes_up_through_a_scanned_phy_and_the_mac_takes_the_negotiated_mode() {
    let (mut mac, model) = rig();
    {
        let mut m = model.borrow_mut();
        m.phy_addr = 9;
        m.phy_link = true;
        m.phy_regs[5] = (1 << 7) | (1 << 5); // ANLPAR: 100 half and 10 half
    }
    assert_eq!(mac.link_state(), LinkState::Unknown);
    let mode = mac.bring_up_link(1_000_000).expect("link");
    assert_eq!(
        mode,
        LinkMode {
            speed_100: true,
            full_duplex: false
        }
    );
    assert_eq!(
        mac.phy_address(),
        Some(9),
        "found by scanning, not written down"
    );
    assert_eq!(mac.link_state(), LinkState::Up(mode));
    let m = model.borrow();
    let cfg = m.reg(NETWORK_CONFIG);
    assert_ne!(cfg & NWCFG_SPEED_100, 0);
    assert_eq!(cfg & NWCFG_FULL_DUPLEX, 0, "half duplex was agreed");
    assert_eq!(
        (cfg >> NWCFG_MDC_DIV_POS) & 7,
        MdcDiv::By224 as u32,
        "the other fields were kept"
    );
    assert_ne!(cfg & NWCFG_FCS_REMOVE, 0);
    assert_eq!(
        (cfg >> NWCFG_DATA_BUS_WIDTH_POS) & 3,
        1,
        "the DMA bus width the design asked for survived the reconfiguration"
    );
    assert_eq!(m.violations, Vec::<String>::new());
    assert_eq!(m.bad_frames, 0);
    assert_eq!(
        m.reg(NETWORK_CONTROL),
        NWCTRL_MAN_PORT_EN | NWCTRL_ENABLE_RECEIVE | NWCTRL_ENABLE_TRANSMIT,
        "receive and transmit are back on after the reconfiguration"
    );
}

#[test]
fn a_board_that_names_its_phy_address_is_not_scanned() {
    let mut config = Config::new(MAC);
    config.phy_address = Some(7);
    let (mac, model) = rig_with::<RX, TX>(&config);
    let mut mac = mac.unwrap();
    {
        let mut m = model.borrow_mut();
        m.phy_addr = 7;
        m.phy_link = true;
        m.phy_regs[5] = 1 << 8; // 100 full
    }
    assert_eq!(
        mac.bring_up_link(1_000_000),
        Ok(LinkMode {
            speed_100: true,
            full_duplex: true
        })
    );
    assert!(
        model.borrow().phys_touched.iter().all(|&p| p == 7),
        "no other address was read: {:?}",
        model.borrow().phys_touched
    );
}

#[test]
fn no_phy_and_no_link_are_reported_and_a_down_link_refuses_to_send() {
    let (mut mac, model) = rig();
    model.borrow_mut().phy_present = false;
    assert_eq!(mac.bring_up_link(100_000), Err(LinkError::NoPhy));

    let (mut mac, model) = rig();
    model.borrow_mut().phy_link = false;
    assert_eq!(mac.bring_up_link(50_000), Err(LinkError::NoLink));
    assert_eq!(mac.link_state(), LinkState::Down);
    assert!(
        !mac.transmit(&frame(1, 64)),
        "a link known down is not sent into"
    );
    assert!(model.borrow().wire.is_empty());
}

#[test]
fn the_link_is_re_read_on_a_schedule_and_the_mac_follows_a_change() {
    let (mut mac, model) = rig();
    {
        let mut m = model.borrow_mut();
        m.phy_link = true;
        m.phy_regs[5] = 1 << 5; // 10 half
    }
    assert_eq!(
        mac.bring_up_link(1_000_000),
        Ok(LinkMode {
            speed_100: false,
            full_duplex: false
        })
    );
    let touched = model.borrow().phys_touched.len();

    assert_eq!(mac.service_link(0), LinkEvent::Steady, "polled, unchanged");
    let after_first = model.borrow().phys_touched.len();
    assert!(after_first > touched, "the first call reads the PHY");
    assert_eq!(mac.service_link(100), LinkEvent::Steady);
    assert_eq!(
        model.borrow().phys_touched.len(),
        after_first,
        "not time yet: the PHY is not touched"
    );

    // The partner now offers 100 full: the next poll moves the MAC.
    model.borrow_mut().phy_regs[5] = 1 << 8;
    let up = LinkMode {
        speed_100: true,
        full_duplex: true,
    };
    assert_eq!(mac.service_link(250), LinkEvent::Up(up));
    assert_ne!(model.borrow().reg(NETWORK_CONFIG) & NWCFG_SPEED_100, 0);
    assert_ne!(model.borrow().reg(NETWORK_CONFIG) & NWCFG_FULL_DUPLEX, 0);
    assert_eq!(mac.service_link(500), LinkEvent::Steady, "unchanged again");

    // The link drops, is reported once, and stays down quietly.
    model.borrow_mut().phy_link = false;
    assert_eq!(mac.service_link(750), LinkEvent::Down);
    assert_eq!(mac.link_state(), LinkState::Down);
    assert_eq!(mac.service_link(1000), LinkEvent::Steady);

    // And back.
    model.borrow_mut().phy_link = true;
    assert_eq!(mac.service_link(1250), LinkEvent::Up(up));
    let resumed = frame(3, 64);
    assert!(mac.transmit(&resumed), "sending resumes with the link");
    let m = model.borrow();
    assert_eq!(
        m.wire.last(),
        Some(&resumed),
        "and the frame leaves: the DMA agrees with the design after every reconfiguration"
    );
    assert_eq!(m.violations, Vec::<String>::new());
}

#[test]
fn servicing_the_link_before_a_phy_is_known_does_nothing() {
    let (mut mac, model) = rig();
    let before = model.borrow().log.len();
    assert_eq!(mac.service_link(10_000), LinkEvent::Steady);
    assert_eq!(model.borrow().log.len(), before, "no register was touched");
}

/// The area a firmware puts in Zephyr's `.nocache` section starts with whatever
/// the RAM held at reset, not with the zeroes `DmaArea::new` builds: the section is
/// `NOLOAD`. The driver writes the area itself, so nothing the RAM held reaches the
/// controller. On the board, a read by the transmit DMA of a word nothing had
/// written stopped it with an AMBA error.
#[test]
fn the_dma_area_is_written_by_the_driver_and_not_trusted_to_the_loader() {
    const STALE: u32 = 0xDEAD_BEEF;
    let area: &'static mut Area = Box::leak(Box::new(DmaArea::new()));
    let words = core::mem::size_of::<Area>() / 4;
    let base = area as *mut Area as *mut u32;
    for i in 0..words {
        // SAFETY: `i < words` of the area this test just allocated and owns.
        unsafe { base.add(i).write(STALE) };
    }
    let model = Rc::new(RefCell::new(Model::new(base as usize)));
    let _mac = Cyt4bfMac::new(Gem(model), area, &Config::new(MAC)).expect("a valid configuration");

    let stale = (0..words)
        // SAFETY: as above; the driver owns the area but this test only reads it.
        .filter(|&i| unsafe { base.add(i).read() } == STALE)
        .count();
    assert_eq!(
        stale, 0,
        "{stale} of {words} words of the area still hold what the RAM held at reset"
    );
}

// ---- the DMA data bus width is the hardware's statement -------------------------
//
// On a CYT4BF8CEE kit the design register read 2 (64 bits), the configuration
// register's field was written 0 (32 bits) by a whole-register write that did not
// name it, the first transmit ended in an AMBA error and the receive DMA kept every
// other word. The model encodes that rule (see `Model::check_width`).

/// The width pairs the driver must produce: the design register's field and the
/// `NETWORK_CONFIG` encoding that agrees with it. Only the middle row was seen on a
/// kit; the others follow the PDL's two encodings.
const WIDTHS: [(u32, u32); 3] = [(1, 0), (2, 1), (4, 2)];

#[test]
fn the_bus_width_field_is_programmed_from_the_design_register() {
    for (design, field) in WIDTHS {
        let (mac, model) = rig_on::<RX, TX>(&Config::new(MAC), |m| m.set_design_bus_width(design));
        let mut mac = mac.unwrap_or_else(|e| panic!("design {design}: {e:?}"));
        assert_eq!(
            model.borrow().configured_field(),
            field,
            "design register {design}"
        );
        assert_eq!(model.borrow().violations, Vec::<String>::new());

        // And the data moves whole, which is what the disagreement broke: a frame
        // of 98 bytes is 24 whole words and a half word.
        let sent = frame(0x30, 98);
        assert!(mac.transmit(&sent));
        assert_eq!(
            model.borrow().wire,
            vec![sent],
            "design {design}: the transmit DMA ended in an error"
        );
        let arriving = frame(0x70, 98);
        assert!(model.borrow_mut().inject_rx(&arriving));
        let mut buf = [0u8; 256];
        let got = mac.receive(&mut buf).expect("the frame is waiting");
        assert_eq!(&buf[..got], &arriving[..], "design {design}");
    }
}

#[test]
fn the_design_register_is_read_once_the_block_is_enabled_and_before_any_gem_register() {
    let (mac, model) = rig_with::<RX, TX>(&Config::new(MAC));
    let _mac = mac.unwrap();
    let m = model.borrow();
    assert_eq!(
        m.design_read_after_writes,
        Some(2),
        "after the two writes of CTL (the mode, then enabled) and before the first GEM register"
    );
    assert_eq!(m.log[1].0, CTL);
    assert_ne!(m.log[1].1 & CTL_ENABLED, 0);
    assert_eq!(m.violations, Vec::<String>::new());
}

#[test]
fn the_bus_width_is_in_the_configuration_before_receive_and_transmit_are_enabled() {
    let (mac, model) = rig_with::<RX, TX>(&Config::new(MAC));
    let _mac = mac.unwrap();
    let m = model.borrow();
    let configured = position(&m.log, NETWORK_CONFIG, 0);
    let enabled = m
        .log
        .iter()
        .position(|&(off, value)| {
            off == NETWORK_CONTROL && value & (NWCTRL_ENABLE_RECEIVE | NWCTRL_ENABLE_TRANSMIT) != 0
        })
        .expect("receive and transmit are enabled");
    assert!(
        configured < enabled,
        "the configuration is written before the DMA is let go"
    );
    assert_eq!(
        (m.log[configured].1 >> NWCFG_DATA_BUS_WIDTH_POS) & 3,
        1,
        "64 bits is 1 in the field's encoding, and it is in that first write"
    );
    assert_eq!(m.violations, Vec::<String>::new());
}

#[test]
fn a_design_bus_width_that_names_no_width_is_refused_and_nothing_is_programmed() {
    // 0 is a bus nobody built; 3, 5, 6 and 7 are not one-hot. The driver does not
    // pick the nearest width.
    for design in [0u32, 3, 5, 6, 7] {
        let (mac, model) = rig_on::<RX, TX>(&Config::new(MAC), |m| m.set_design_bus_width(design));
        assert_eq!(
            mac.err(),
            Some(InitError::UnknownDmaBusWidth(design)),
            "design register {design}"
        );
        let m = model.borrow();
        let programmed: Vec<_> = m.log.iter().filter(|&&(off, _)| off >= GEM).collect();
        assert!(
            programmed.is_empty(),
            "design {design}: GEM registers written: {programmed:x?}"
        );
        assert_eq!(m.violations, Vec::<String>::new());
    }

    // A block that does not answer reads all ones, which is 7 in the field.
    let (mac, _) = rig_on::<RX, TX>(&Config::new(MAC), |m| {
        m.regs.insert(DESIGNCFG_DEBUG1, u32::MAX);
    });
    assert_eq!(mac.err(), Some(InitError::UnknownDmaBusWidth(7)));
}

/// The bits of `after` that differ from `reset` and are not in `named`.
fn unnamed_changes(reset: u32, after: u32, named: u32) -> u32 {
    (reset ^ after) & !named
}

/// The two registers `new` writes whole, against the values the kit held before
/// the driver ran: what differs from them is what the driver named. A field the
/// driver forgets keeps its reset value only if it is written back as it was, so a
/// nameless overwrite of ANY field, not just the bus width, shows here.
#[test]
fn new_replaces_only_the_fields_it_names_in_the_registers_it_writes_whole() {
    let mut multicast_refused = Config::new(MAC);
    multicast_refused.accept_all_multicast = false;
    multicast_refused.mdc_div = MdcDiv::By64;
    // INCR4 is the kit's reset burst: naming it changes nothing.
    multicast_refused.dma_burst = DmaBurst::Incr4;
    let mut wide_burst = Config::new(MAC);
    wide_burst.dma_burst = DmaBurst::Incr16;
    wide_burst.mdc_div = MdcDiv::By32;

    // `NETWORK_CONFIG`'s reset value for the bus width is the design's default, read
    // from `DESIGNCFG_DEBUG5` bits 11:10 on that kit.
    let reset_field = (RESET_DESIGNCFG_DEBUG5 >> 10) & 3;
    assert_eq!(reset_field, 1, "the measured default is 64 bits");
    assert_eq!(
        (RESET_NETWORK_CONFIG >> 21) & 3,
        reset_field,
        "and it is what NETWORK_CONFIG held"
    );

    for config in [Config::new(MAC), multicast_refused, wide_burst] {
        for (design, field) in WIDTHS {
            let (mac, model) = rig_on::<RX, TX>(&config, |m| m.set_design_bus_width(design));
            let _mac = mac.unwrap();
            let m = model.borrow();

            // NETWORK_CONFIG: speed, duplex, frame size, FCS, the MDC divider and
            // (on request) the multicast hash are the driver's; the bus width is the
            // design's, and differs from the reset value only when the design does.
            let mdc_mask = 7 << NWCFG_MDC_DIV_POS;
            let mut named = NWCFG_SPEED_100
                | NWCFG_FULL_DUPLEX
                | NWCFG_RECEIVE_1536
                | NWCFG_FCS_REMOVE
                | mdc_mask;
            if config.accept_all_multicast {
                named |= NWCFG_MULTICAST_HASH_ENABLE;
            }
            if field != reset_field {
                named |= 3 << NWCFG_DATA_BUS_WIDTH_POS;
            }
            let netcfg = m.reg(NETWORK_CONFIG);
            let stray = unnamed_changes(RESET_NETWORK_CONFIG, netcfg, named);
            assert_eq!(
                stray, 0,
                "design {design}: NETWORK_CONFIG {netcfg:#010x} changed bits {stray:#010x} of the \
                 reset {RESET_NETWORK_CONFIG:#010x} that no field names"
            );
            let mut expected = (RESET_NETWORK_CONFIG
                & !(named
                    | mdc_mask
                    | (3 << NWCFG_DATA_BUS_WIDTH_POS)
                    | NWCFG_MULTICAST_HASH_ENABLE))
                | NWCFG_SPEED_100
                | NWCFG_FULL_DUPLEX
                | NWCFG_RECEIVE_1536
                | NWCFG_FCS_REMOVE
                | ((config.mdc_div as u32) << NWCFG_MDC_DIV_POS)
                | (field << NWCFG_DATA_BUS_WIDTH_POS);
            if config.accept_all_multicast {
                expected |= NWCFG_MULTICAST_HASH_ENABLE;
            }
            assert_eq!(
                netcfg, expected,
                "design {design}: the named fields' values"
            );

            // DMA_CONFIG: the burst length and discard-on-error are the driver's.
            let burst_mask = 0x1F << DMACFG_AMBA_BURST_POS;
            let named = burst_mask | DMACFG_FORCE_DISCARD_ON_ERR;
            let dmacfg = m.reg(DMA_CONFIG);
            let stray = unnamed_changes(RESET_DMA_CONFIG, dmacfg, named);
            assert_eq!(
                stray, 0,
                "design {design}: DMA_CONFIG {dmacfg:#010x} changed bits {stray:#010x} of the \
                 reset {RESET_DMA_CONFIG:#010x} that no field names"
            );
            assert_eq!(
                dmacfg,
                (RESET_DMA_CONFIG & !named)
                    | ((config.dma_burst as u32) << DMACFG_AMBA_BURST_POS)
                    | DMACFG_FORCE_DISCARD_ON_ERR,
                "design {design}: the named fields' values"
            );
        }
    }
}
