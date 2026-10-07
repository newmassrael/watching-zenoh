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
use std::rc::Rc;
use std::vec;
use std::vec::Vec;
use wz_runtime_core::EthernetMac;

const BUS_BASE: u32 = 0x2000_0000;
const RX: usize = 4;
const TX: usize = 3;
type Area = DmaArea<RX, TX>;
const MAC: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];

/// A PHY on the management bus, and the controller in front of it.
struct Model {
    start: usize,
    regs: HashMap<usize, u32>,
    tx_idx: usize,
    rx_idx: usize,
    tx_halted: bool,
    wire: Vec<Vec<u8>>,
    log: Vec<(usize, u32)>,
    delays_us: u32,
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
        Self {
            start,
            regs: HashMap::new(),
            tx_idx: 0,
            rx_idx: 0,
            tx_halted: false,
            wire: Vec::new(),
            log: Vec::new(),
            delays_us: 0,
            hold_tx: false,
            fail_next_tx: false,
            phy_addr: 1,
            phy_present: true,
            phy_regs,
            phy_link: false,
            mdio_busy_polls: 2,
            mdio_busy_left: 0,
            mdio_stuck: false,
            mdio_data: 0,
            bad_frames: 0,
            phys_touched: Vec::new(),
        }
    }

    fn area(&self) -> *mut Area {
        self.start as *mut Area
    }

    fn bus(&self, ptr: *const u8) -> u32 {
        BUS_BASE + (ptr as usize - self.start) as u32
    }

    fn ptr(&self, bus: u32) -> *mut u8 {
        (self.start + (bus - BUS_BASE) as usize) as *mut u8
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

    fn read(&mut self, off: usize) -> u32 {
        match off {
            NETWORK_STATUS => {
                if self.mdio_stuck {
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
        match off {
            NETWORK_CONTROL => {
                self.regs.insert(off, v & !NWCTRL_TX_START);
                if v & NWCTRL_TX_START != 0 && v & NWCTRL_ENABLE_TRANSMIT != 0 {
                    self.run_tx();
                }
            }
            TRANSMIT_STATUS | RECEIVE_STATUS => {
                let cur = self.reg(off);
                self.regs.insert(off, cur & !v);
            }
            TRANSMIT_Q_PTR => {
                self.regs.insert(off, v);
                self.tx_idx = self.desc_index(v & !QPTR_DISABLE, self.tx_desc(0));
                self.tx_halted = false;
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
            if self.hold_tx {
                return;
            }
            let len = (w1 & TXD_LEN_MASK) as usize;
            let buf = self.ptr(d.word0());
            // SAFETY: the driver wrote `len <= BUF_LEN` bytes there.
            let frame = unsafe { std::slice::from_raw_parts(buf, len) }.to_vec();
            self.wire.push(frame);
            d.set_word1(w1 | TXD_USED);
            let st = self.reg(TRANSMIT_STATUS) | TXSR_TRANSMIT_COMPLETE;
            self.regs.insert(TRANSMIT_STATUS, st);
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
        // SAFETY: the buffer is `BUF_LEN` bytes and the tests inject less.
        unsafe { std::ptr::copy_nonoverlapping(frame.as_ptr(), buf, frame.len()) };
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

    fn delay_us(&mut self, us: u32) {
        self.0.borrow_mut().delays_us += us;
    }
}

fn rig_with<const R: usize, const T: usize>(
    config: &Config,
) -> (Result<Cyt4bfMac<Gem, R, T>, InitError>, Rc<RefCell<Model>>) {
    let area: &'static mut DmaArea<R, T> = Box::leak(Box::new(DmaArea::new()));
    let start = &mut *area as *mut DmaArea<R, T> as usize;
    let model = Rc::new(RefCell::new(Model::new(start)));
    (Cyt4bfMac::new(Gem(model.clone()), area, config), model)
}

fn rig() -> (Cyt4bfMac<Gem, RX, TX>, Rc<RefCell<Model>>) {
    let (mac, model) = rig_with::<RX, TX>(&Config::new(MAC));
    (mac.expect("a valid configuration"), model)
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
    assert!(mac.transmit(&frame(3, 64)), "sending resumes with the link");
}

#[test]
fn servicing_the_link_before_a_phy_is_known_does_nothing() {
    let (mut mac, model) = rig();
    let before = model.borrow().log.len();
    assert_eq!(mac.service_link(10_000), LinkEvent::Steady);
    assert_eq!(model.borrow().log.len(), before, "no register was touched");
}
