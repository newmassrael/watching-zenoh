// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The protocol against a model of a TC6 MAC-PHY.
//!
//! The model is written from the interface as `oa_tc6.h`/`oa_tc6.c` lay it out:
//! a control transaction is a header, then the device's echo of the header and the
//! data; a data exchange is a header and a chunk payload out, and a chunk payload
//! and a footer back; every header and footer carries odd parity; and the footer
//! reports the device's transmit credits and waiting receive chunks. The tests
//! check the driver's framing, parity, credit accounting and chunking against it.
//! They cannot check the model against a chip, which is why the crate claims BUILT.

use super::proto::*;
use super::*;
use std::collections::{HashMap, VecDeque};
use std::vec;
use std::vec::Vec;

const CPS: usize = 64;

/// A chunk the model will hand to the host on a receive exchange.
struct RxChunk {
    payload: Vec<u8>,
    start: bool,
    /// Where the frame starts in the chunk, in words; ZARFE has it zero.
    start_offset: u8,
    end: bool,
    end_offset: u8,
    drop_frame: bool,
}

struct Chip {
    regs: HashMap<(u8, u16), u32>,
    protected: bool,
    cps: usize,
    synced: bool,
    extended_status: bool,
    /// The device reports that the last header it was sent failed its parity.
    reject_header: bool,
    /// Transmit credits the device has, and how many a frame in flight holds.
    credits: u8,
    credits_cap: u8,
    hold_credits: bool,
    held: u8,
    tx_frame: Vec<u8>,
    wire: Vec<Vec<u8>>,
    rx: VecDeque<RxChunk>,
    bad_headers: u32,
    corrupt_header_echo: bool,
    corrupt_data_echo: bool,
    corrupt_footer_parity: bool,
    corrupt_complement: bool,
    exchanges: u32,
    data_headers: Vec<DataHeader>,
}

impl Chip {
    fn new() -> Self {
        Self {
            regs: HashMap::new(),
            protected: false,
            cps: CPS,
            synced: true,
            extended_status: false,
            reject_header: false,
            credits: 8,
            credits_cap: 8,
            hold_credits: false,
            held: 0,
            tx_frame: Vec::new(),
            wire: Vec::new(),
            rx: VecDeque::new(),
            bad_headers: 0,
            corrupt_header_echo: false,
            corrupt_data_echo: false,
            corrupt_footer_parity: false,
            corrupt_complement: false,
            exchanges: 0,
            data_headers: Vec::new(),
        }
    }

    fn reg(&self, reg: Reg) -> u32 {
        *self.regs.get(&(reg.mms, reg.addr)).unwrap_or(&0)
    }

    /// Queue `frame` as the chunks a device sends, in ZARFE mode.
    fn queue_rx(&mut self, frame: &[u8]) {
        let chunks: Vec<&[u8]> = frame.chunks(self.cps).collect();
        let n = chunks.len();
        for (i, c) in chunks.into_iter().enumerate() {
            let mut payload = vec![0u8; self.cps];
            payload[..c.len()].copy_from_slice(c);
            self.rx.push_back(RxChunk {
                payload,
                start: i == 0,
                start_offset: 0,
                end: i + 1 == n,
                end_offset: (c.len() - 1) as u8,
                drop_frame: false,
            });
        }
    }

    fn footer(&self, rx_chunk: Option<&RxChunk>) -> u32 {
        let mut b = FooterBuilder {
            extended_status: self.extended_status,
            header_bad: self.reject_header,
            synced: self.synced,
            rca: self.rx.len().min(31) as u8,
            txc: self.credits.min(31),
            ..FooterBuilder::default()
        };
        if let Some(c) = rx_chunk {
            b.data_valid = true;
            b.start_valid = c.start;
            b.start_word_offset = c.start_offset;
            b.end_valid = c.end;
            b.end_byte_offset = if c.end { c.end_offset } else { 0 };
            b.frame_drop = c.drop_frame;
        }
        let word = b.word();
        if self.corrupt_footer_parity {
            word ^ 1
        } else {
            word
        }
    }

    fn control(&mut self, tx: &[u8], rx: &mut [u8]) {
        let header = u32::from_be_bytes([tx[0], tx[1], tx[2], tx[3]]);
        if !parity_ok(header) {
            self.bad_headers += 1;
        }
        let write = header & (1 << 29) != 0;
        let reg = Reg::new(
            ((header >> 24) & 0xF) as u8,
            ((header >> 8) & 0xFFFF) as u16,
        );
        let word =
            |i: usize| u32::from_be_bytes([tx[i * 4], tx[i * 4 + 1], tx[i * 4 + 2], tx[i * 4 + 3]]);
        let mut put = |i: usize, v: u32| rx[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
        // The mode THIS transaction is framed in: a write that changes it takes
        // effect from the next one.
        let protected_now = self.protected;
        // Word 0 clocked in during the header carries nothing.
        put(0, 0);
        put(
            1,
            if self.corrupt_header_echo {
                header ^ 0x100
            } else {
                header
            },
        );
        if write {
            let value = word(1);
            let complement_ok = !protected_now || word(2) == !value;
            if complement_ok {
                if reg == std_reg::STATUS0 || reg == std_reg::STATUS1 {
                    // Write one to clear.
                    let cur = self.reg(reg);
                    self.regs.insert((reg.mms, reg.addr), cur & !value);
                } else {
                    self.regs.insert((reg.mms, reg.addr), value);
                }
                if reg == std_reg::CONFIG0 {
                    // The device is protected from the NEXT transaction on.
                    self.protected = value & std_reg::CONFIG0_PROTE != 0;
                }
                if reg == std_reg::RESET && value & std_reg::RESET_SWRESET != 0 {
                    self.protected = false;
                    self.regs.insert(
                        (std_reg::STATUS0.mms, std_reg::STATUS0.addr),
                        std_reg::STATUS0_RESETC,
                    );
                    self.synced = false;
                }
            }
            put(
                2,
                if self.corrupt_data_echo {
                    value ^ 1
                } else {
                    value
                },
            );
            if protected_now {
                put(3, !value);
            }
        } else {
            let value = self.reg(reg);
            put(2, value);
            if protected_now {
                put(
                    3,
                    if self.corrupt_complement {
                        value
                    } else {
                        !value
                    },
                );
            }
        }
    }

    fn data(&mut self, tx: &[u8], rx: &mut [u8]) {
        self.exchanges += 1;
        let header_word = u32::from_be_bytes([tx[0], tx[1], tx[2], tx[3]]);
        let cps = self.cps;
        let Some(h) = DataHeader::parse(header_word) else {
            self.bad_headers += 1;
            return;
        };
        self.data_headers.push(h);
        if h.data_valid {
            let payload = &tx[WORD..WORD + cps];
            if h.start_valid {
                self.tx_frame.clear();
            }
            let take = if h.end_valid {
                usize::from(h.end_byte_offset) + 1
            } else {
                cps
            };
            self.tx_frame.extend_from_slice(&payload[..take]);
            self.credits = self.credits.saturating_sub(1);
            self.held += 1;
            if h.end_valid {
                let frame = std::mem::take(&mut self.tx_frame);
                self.wire.push(frame);
                if !self.hold_credits {
                    self.credits = (self.credits + self.held).min(self.credits_cap);
                    self.held = 0;
                }
            }
        }
        let chunk = if h.no_receive {
            None
        } else {
            self.rx.pop_front()
        };
        match &chunk {
            Some(c) => rx[..cps].copy_from_slice(&c.payload),
            None => rx[..cps].fill(0),
        }
        let footer = self.footer(chunk.as_ref());
        rx[cps..cps + WORD].copy_from_slice(&footer.to_be_bytes());
    }
}

impl SpiTransfer for Chip {
    type Error = ();

    fn transfer(&mut self, tx: &[u8], rx: &mut [u8]) -> Result<(), ()> {
        assert_eq!(
            tx.len(),
            rx.len(),
            "full duplex: the same number of bytes each way"
        );
        if tx[0] & 0x80 == 0 {
            self.control(tx, rx);
        } else {
            self.data(tx, rx);
        }
        Ok(())
    }
}

fn tc6() -> Tc6<Chip> {
    Tc6::new(Chip::new(), ChunkSize::B64)
}

fn pattern(tag: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| tag.wrapping_add(i as u8)).collect()
}

/// Odd parity counted the slow way, so the check does not share code with the
/// function under test.
fn odd(word: u32) -> bool {
    (0..32).filter(|b| word >> b & 1 == 1).count() % 2 == 1
}

#[test]
fn headers_and_footers_carry_odd_parity_and_the_two_known_words_come_out_right() {
    // A read of OA_ID: MMS 0, address 0, nothing set, so P is 1.
    assert_eq!(control_header(false, std_reg::ID), 0x0000_0001);
    // A write of CONFIG0: WNR (bit 29) and address 4 (bit 10) set, two ones, so P is 1.
    assert_eq!(control_header(true, std_reg::CONFIG0), 0x2000_0401);
    // A read of STATUS0 (address 8): one one, so P stays 0.
    assert_eq!(control_header(false, std_reg::STATUS0), 0x0000_0800);
    for write in [false, true] {
        for reg in [
            std_reg::ID,
            std_reg::CONFIG0,
            std_reg::STATUS0,
            Reg::new(4, 0xCA01),
            Reg::new(15, 0xFFFF),
        ] {
            assert!(odd(control_header(write, reg)), "{reg:?} write={write}");
        }
    }
    for dv in [false, true] {
        for sv in [false, true] {
            for ev in [false, true] {
                for ebo in [0u8, 1, 17, 63] {
                    let h = DataHeader {
                        data_valid: dv,
                        no_receive: dv,
                        start_valid: sv,
                        end_valid: ev,
                        end_byte_offset: ebo,
                    };
                    assert!(odd(h.word()));
                    let back = DataHeader::parse(h.word()).unwrap();
                    assert_eq!(back.end_valid, ev);
                    assert_eq!(back.end_byte_offset, if ev { ebo } else { 0 });
                }
            }
        }
    }
    // A header that is data-not-control is not a control header, and bad parity
    // is refused on the way back in.
    assert_eq!(DataHeader::parse(0x0000_0001), None, "DNC clear");
    assert_eq!(
        DataHeader::parse(DataHeader::STATUS.word() ^ 1),
        None,
        "parity flipped"
    );
}

#[test]
fn a_footer_is_read_field_by_field() {
    let w = FooterBuilder {
        extended_status: true,
        synced: true,
        rca: 5,
        data_valid: true,
        start_valid: true,
        end_valid: true,
        end_byte_offset: 22,
        txc: 7,
        frame_drop: true,
        ..FooterBuilder::default()
    }
    .word();
    let f = Footer(w);
    assert!(f.parity_ok());
    assert!(f.extended_status() && f.synced() && f.data_valid() && f.start_valid());
    assert!(f.end_valid() && f.frame_drop() && !f.header_bad());
    assert_eq!(f.receive_chunks_available(), 5);
    assert_eq!(f.transmit_credits(), 7);
    assert_eq!(f.end_byte_offset(), 22);
    assert_eq!(f.start_word_offset(), 0);
    assert!(!Footer(w ^ 1).parity_ok());
}

#[test]
fn a_register_is_written_and_read_back_in_the_plain_and_the_protected_mode() {
    let mut t = tc6();
    let reg = Reg::new(1, 0x0042);
    t.reg_write(reg, 0xDEAD_BEEF).unwrap();
    assert_eq!(t.reg_read(reg).unwrap(), 0xDEAD_BEEF);
    assert_eq!(
        t.spi_mut().bad_headers,
        0,
        "every header carried odd parity"
    );

    // Turning protection on: the write that enables it is itself plain, and what
    // follows carries the complement.
    t.set_protected(true).unwrap();
    assert!(t.spi_mut().protected);
    t.reg_write(reg, 0x1234_5678).unwrap();
    assert_eq!(t.reg_read(reg).unwrap(), 0x1234_5678);
    assert_eq!(t.spi_mut().reg(reg), 0x1234_5678);
    t.set_protected(false).unwrap();
    assert_eq!(t.reg_read(reg).unwrap(), 0x1234_5678, "and back to plain");
    assert_eq!(t.spi_mut().bad_headers, 0);
}

#[test]
fn a_control_transaction_the_device_garbles_is_refused_not_believed() {
    let reg = Reg::new(0, 0x10);
    let mut t = tc6();
    t.spi_mut().corrupt_header_echo = true;
    assert_eq!(t.reg_read(reg), Err(Error::HeaderEcho));

    let mut t = tc6();
    t.spi_mut().corrupt_data_echo = true;
    assert_eq!(t.reg_write(reg, 7), Err(Error::DataEcho));

    let mut t = tc6();
    t.set_protected(true).unwrap();
    t.spi_mut().corrupt_complement = true;
    assert_eq!(t.reg_read(reg), Err(Error::Protected));
}

#[test]
fn a_modify_changes_only_the_masked_bits() {
    let mut t = tc6();
    let reg = Reg::new(2, 9);
    t.reg_write(reg, 0xFFFF_0F0F).unwrap();
    t.reg_modify(reg, 0x0000_FF00, 0x0000_A500).unwrap();
    assert_eq!(t.reg_read(reg).unwrap(), 0xFFFF_A50F);
}

#[test]
fn a_frame_that_fits_a_chunk_goes_out_as_one_start_and_end_chunk() {
    let mut t = tc6();
    let frame = pattern(1, 60);
    assert_eq!(t.send_frame(&frame), Ok(true));
    assert_eq!(t.spi_mut().wire, vec![frame]);
    let hs = &t.spi_mut().data_headers;
    // The status read that learned the credits, then the one data chunk.
    let data: Vec<_> = hs.iter().filter(|h| h.data_valid).collect();
    assert_eq!(data.len(), 1);
    assert!(data[0].start_valid && data[0].end_valid);
    assert_eq!(data[0].end_byte_offset, 59, "the last valid byte");
    assert!(
        data[0].no_receive,
        "a transmit chunk asks for no receive data"
    );
}

#[test]
fn a_longer_frame_is_chunked_with_the_start_on_the_first_and_the_end_on_the_last() {
    for len in [65usize, 128, 129, 150, 1514] {
        let mut t = tc6();
        t.spi_mut().credits = 31;
        t.spi_mut().credits_cap = 31;
        let frame = pattern(len as u8, len);
        assert_eq!(t.send_frame(&frame), Ok(true), "length {len}");
        assert_eq!(
            t.spi_mut().wire,
            vec![frame],
            "reassembled byte-exact, length {len}"
        );
        let chunks = len.div_ceil(CPS);
        let data: Vec<_> = t
            .spi_mut()
            .data_headers
            .iter()
            .filter(|h| h.data_valid)
            .copied()
            .collect();
        assert_eq!(data.len(), chunks);
        for (i, h) in data.iter().enumerate() {
            assert_eq!(
                h.start_valid,
                i == 0,
                "start only on the first, length {len}"
            );
            assert_eq!(
                h.end_valid,
                i == chunks - 1,
                "end only on the last, length {len}"
            );
        }
        let last_valid = len - (chunks - 1) * CPS;
        assert_eq!(data[chunks - 1].end_byte_offset as usize, last_valid - 1);
    }
}

#[test]
fn a_frame_the_device_has_no_credits_for_is_not_sent_and_may_be_tried_again() {
    let mut t = tc6();
    t.spi_mut().hold_credits = true;
    // Eight credits, and the device does not give them back.
    let frame = pattern(3, 200); // four chunks
    assert_eq!(t.send_frame(&frame), Ok(true));
    assert_eq!(t.send_frame(&frame), Ok(true));
    let sent = t.spi_mut().wire.len();
    assert_eq!(sent, 2);
    // The ninth chunk: no credit left, so nothing goes out and nothing is lost.
    assert_eq!(t.send_frame(&frame), Ok(false));
    assert_eq!(t.spi_mut().wire.len(), sent, "nothing was sent");

    // The device frees its buffers: the same frame now goes.
    {
        let chip = t.spi_mut();
        chip.hold_credits = false;
        chip.credits = chip.credits_cap;
        chip.held = 0;
    }
    assert_eq!(t.send_frame(&frame), Ok(true));
    assert_eq!(t.spi_mut().wire.len(), sent + 1);
}

#[test]
fn an_empty_or_oversize_frame_is_not_sent() {
    let mut t = tc6();
    assert_eq!(t.send_frame(&[]), Ok(false));
    assert_eq!(t.send_frame(&vec![0u8; RX_FRAME_MAX + 1]), Ok(false));
    assert!(t.spi_mut().wire.is_empty());
}

#[test]
fn received_frames_come_out_whole_whether_they_take_one_chunk_or_several() {
    let mut t = tc6();
    let frames = [
        pattern(1, 40),
        pattern(2, 64),
        pattern(3, 65),
        pattern(4, 300),
        pattern(5, 1514),
    ];
    for f in &frames {
        t.spi_mut().queue_rx(f);
    }
    let mut out = [0u8; 1600];
    for f in &frames {
        let got = t
            .receive_frame(&mut out)
            .unwrap()
            .expect("a frame is waiting");
        assert_eq!(&out[..got], &f[..]);
    }
    assert_eq!(t.receive_frame(&mut out), Ok(None), "and then nothing");
}

#[test]
fn nothing_waiting_costs_one_status_exchange_and_returns_none() {
    let mut t = tc6();
    let mut out = [0u8; 64];
    assert_eq!(t.receive_frame(&mut out), Ok(None));
    assert_eq!(t.spi_mut().exchanges, 1, "one footer read");
    assert!(t.spi_mut().data_headers[0].no_receive);
}

#[test]
fn a_quiet_interrupt_line_costs_no_exchange_at_all() {
    fn quiet() -> bool {
        false
    }
    let mut t = tc6();
    t.set_interrupt_probe(quiet);
    let mut out = [0u8; 64];
    assert_eq!(t.receive_frame(&mut out), Ok(None));
    assert_eq!(
        t.spi_mut().exchanges,
        0,
        "the line said nothing was waiting"
    );
}

#[test]
fn a_frame_longer_than_the_callers_buffer_or_marked_for_drop_is_dropped_whole() {
    let mut t = tc6();
    t.spi_mut().queue_rx(&pattern(9, 500));
    t.spi_mut().queue_rx(&pattern(8, 70));
    let mut small = [0u8; 100];
    let got = t
        .receive_frame(&mut small)
        .unwrap()
        .expect("the one that fits");
    assert_eq!(
        &small[..got],
        &pattern(8, 70)[..],
        "the long one was dropped, not cut"
    );

    let mut t = tc6();
    t.spi_mut().queue_rx(&pattern(7, 130)); // three chunks
    t.spi_mut().rx.back_mut().unwrap().drop_frame = true; // the device asks for the drop on the last
    t.spi_mut().queue_rx(&pattern(6, 50));
    let mut out = [0u8; 200];
    let got = t.receive_frame(&mut out).unwrap().expect("the next frame");
    assert_eq!(
        &out[..got],
        &pattern(6, 50)[..],
        "the marked frame was discarded"
    );
}

#[test]
fn a_chunk_of_a_frame_whose_start_was_never_seen_is_ignored() {
    let mut t = tc6();
    t.spi_mut().queue_rx(&pattern(1, 130));
    t.spi_mut().rx.pop_front(); // lose the start chunk
    t.spi_mut().queue_rx(&pattern(2, 30));
    let mut out = [0u8; 200];
    let got = t
        .receive_frame(&mut out)
        .unwrap()
        .expect("the whole frame after it");
    assert_eq!(&out[..got], &pattern(2, 30)[..]);
}

#[test]
fn a_frame_beyond_the_reassembly_limit_is_dropped_not_overrun() {
    let mut t = tc6();
    let giant = pattern(1, RX_FRAME_MAX + 200);
    t.spi_mut().queue_rx(&giant);
    t.spi_mut().queue_rx(&pattern(2, 80));
    let mut out = vec![0u8; 4096];
    // The giant spans more chunks than one call reads; the next call finishes it.
    let mut got = None;
    for _ in 0..4 {
        if let Some(n) = t.receive_frame(&mut out).unwrap() {
            got = Some(n);
            break;
        }
    }
    let n = got.expect("the frame after the giant");
    assert_eq!(&out[..n], &pattern(2, 80)[..]);
}

#[test]
fn a_footer_that_says_the_device_lost_its_configuration_is_an_error() {
    let mut t = tc6();
    t.spi_mut().synced = false;
    assert_eq!(t.read_status().map(|_| ()), Err(Error::NotSynced));
    let mut out = [0u8; 64];
    assert_eq!(t.receive_frame(&mut out), Err(Error::NotSynced));
    assert_eq!(t.send_frame(&pattern(1, 20)), Err(Error::NotSynced));
}

#[test]
fn a_footer_with_bad_parity_is_refused() {
    let mut t = tc6();
    t.spi_mut().corrupt_footer_parity = true;
    assert_eq!(t.read_status().map(|_| ()), Err(Error::FooterParity));
}

#[test]
fn a_footer_that_says_the_device_rejected_the_header_is_an_error_on_every_path() {
    let mut t = tc6();
    t.spi_mut().reject_header = true;
    assert_eq!(t.read_status().map(|_| ()), Err(Error::HeaderRejected));
    let mut out = [0u8; 64];
    assert_eq!(t.receive_frame(&mut out), Err(Error::HeaderRejected));
    assert_eq!(t.send_frame(&pattern(1, 20)), Err(Error::HeaderRejected));

    // CONTROL: the same chip, header accepted, is read without complaint.
    t.spi_mut().reject_header = false;
    assert!(t.read_status().is_ok());
}

#[test]
fn a_frame_that_does_not_start_on_a_chunk_boundary_is_dropped_whole() {
    // ZARFE puts every frame at the start of a chunk. A device that reports a
    // start at word 2 is not in that mode, and the bytes cannot be placed as if
    // it were: the frame is dropped, all of its chunks, and the next one is read.
    let mut t = tc6();
    t.spi_mut().queue_rx(&pattern(1, 130)); // three chunks
    t.spi_mut().rx.front_mut().unwrap().start_offset = 2;
    t.spi_mut().queue_rx(&pattern(2, 50));
    let mut out = [0u8; 200];
    let got = t.receive_frame(&mut out).unwrap().expect("the next frame");
    assert_eq!(&out[..got], &pattern(2, 50)[..], "only the aligned frame");

    // CONTROL: the same three chunks at offset zero are delivered whole.
    let mut t = tc6();
    t.spi_mut().queue_rx(&pattern(1, 130));
    let got = t.receive_frame(&mut out).unwrap().expect("the frame");
    assert_eq!(&out[..got], &pattern(1, 130)[..]);
}

#[test]
fn a_sent_frame_clears_the_extended_status_the_footer_announced() {
    let mut t = tc6();
    t.spi_mut().extended_status = true;
    t.spi_mut().regs.insert((0, 0x008), 1 << 5);
    assert_eq!(t.send_frame(&pattern(3, 90)), Ok(true));
    assert_eq!(
        t.spi_mut().reg(std_reg::STATUS0),
        0,
        "written back, which is the device's clear"
    );
    assert_eq!(t.take_events(), 1 << 5, "and the chip crate learns of it");
}

#[test]
fn extended_status_is_cleared_by_writing_it_back_and_the_bits_are_kept() {
    let mut t = tc6();
    {
        let chip = t.spi_mut();
        chip.extended_status = true;
        chip.regs.insert((0, 0x008), 0x0000_0042);
        chip.regs.insert((0, 0x009), 0x0000_0008);
    }
    t.read_status().unwrap();
    assert!(t.status.extended);
    t.clear_extended_status().unwrap();
    assert_eq!(t.spi_mut().reg(std_reg::STATUS0), 0, "write one to clear");
    assert_eq!(t.spi_mut().reg(std_reg::STATUS1), 0);
    assert_eq!(
        t.take_events(),
        0x42,
        "the chip crate learns what was flagged"
    );
    assert_eq!(t.take_events(), 0, "once");
}

#[test]
fn receive_clears_extended_status_the_footer_announces() {
    let mut t = tc6();
    t.spi_mut().extended_status = true;
    t.spi_mut().regs.insert((0, 0x008), 1 << 3);
    let mut out = [0u8; 64];
    assert_eq!(t.receive_frame(&mut out), Ok(None));
    assert_eq!(t.take_events(), 1 << 3);
}

#[test]
fn a_soft_reset_waits_for_completion_clears_it_and_forgets_protection() {
    let mut t = tc6();
    t.set_protected(true).unwrap();
    let clock = std::cell::Cell::new(0u64);
    // The model raises RESETC at once; the driver still waits one tick first.
    t.soft_reset(
        |us| clock.set(clock.get() + u64::from(us)),
        || clock.get(),
        10,
    )
    .unwrap();
    assert!(clock.get() >= 1_000, "it waited a tick before it looked");
    assert!(!t.protected, "the device is unconfigured after a reset");
    assert_eq!(
        t.spi_mut().reg(std_reg::STATUS0) & std_reg::STATUS0_RESETC,
        0,
        "RESETC was cleared"
    );

    // A device that never reports completion times out at the budget. This one
    // forgets to raise RESETC: its status register is cleared after every exchange.
    struct Mute(Chip);
    impl SpiTransfer for Mute {
        type Error = ();
        fn transfer(&mut self, tx: &[u8], rx: &mut [u8]) -> Result<(), ()> {
            self.0.transfer(tx, rx)?;
            self.0.regs.insert((0, 0x008), 0);
            Ok(())
        }
    }
    let mut mute = Tc6::new(Mute(Chip::new()), ChunkSize::B64);
    let clock = std::cell::Cell::new(0u64);
    let mut asks = 0;
    assert_eq!(
        mute.soft_reset(
            |us| {
                asks += 1;
                clock.set(clock.get() + u64::from(us));
            },
            || clock.get(),
            5,
        ),
        Err(Error::ResetTimeout)
    );
    assert_eq!(
        asks, 5,
        "five waits of a millisecond use up five milliseconds"
    );
}

/// The budget is measured on the clock, not counted in the waits asked for. A wait
/// is a promise of AT LEAST its length, and on a board whose time base runs slow it
/// takes far longer: this wait costs ten times what it was told, so a 5 ms budget
/// is gone after the first. Counting the asks would have let it run five times.
#[test]
fn a_reset_budget_is_the_clocks_not_the_number_of_waits_asked_for() {
    struct Mute(Chip);
    impl SpiTransfer for Mute {
        type Error = ();
        fn transfer(&mut self, tx: &[u8], rx: &mut [u8]) -> Result<(), ()> {
            self.0.transfer(tx, rx)?;
            self.0.regs.insert((0, 0x008), 0);
            Ok(())
        }
    }
    let mut mute = Tc6::new(Mute(Chip::new()), ChunkSize::B64);
    let clock = std::cell::Cell::new(0u64);
    let mut asks = 0;
    assert_eq!(
        mute.soft_reset(
            |us| {
                asks += 1;
                clock.set(clock.get() + 10 * u64::from(us));
            },
            || clock.get(),
            5,
        ),
        Err(Error::ResetTimeout)
    );
    assert_eq!(asks, 1, "the clock, not the count of asks, ended the wait");
}

#[test]
fn sync_and_zarfe_are_declared_without_disturbing_the_other_config_bits() {
    let mut t = tc6();
    t.reg_write(std_reg::CONFIG0, 0x0000_0007).unwrap();
    t.enable_sync().unwrap();
    assert_eq!(
        t.reg_read(std_reg::CONFIG0).unwrap(),
        0x0000_0007 | std_reg::CONFIG0_SYNC | std_reg::CONFIG0_RFA_ZARFE
    );
}

#[test]
fn the_mac_wrapper_sends_receives_and_counts_what_it_absorbs() {
    let mut mac = Tc6Mac::new(tc6(), [2, 0, 0x5e, 0, 0, 7]);
    assert_eq!(mac.mac_address(), [2, 0, 0x5e, 0, 0, 7]);
    let f = pattern(1, 100);
    assert!(mac.transmit(&f));
    assert_eq!(mac.tc6_mut().spi_mut().wire, vec![f.clone()]);

    mac.tc6_mut().spi_mut().queue_rx(&pattern(2, 90));
    let mut buf = [0u8; 256];
    let n = mac.receive(&mut buf).expect("a frame");
    assert_eq!(&buf[..n], &pattern(2, 90)[..]);
    assert_eq!(mac.errors(), 0);

    // A device that has lost its configuration turns into counted failures, not a
    // wrong frame and not a panic.
    mac.tc6_mut().spi_mut().synced = false;
    assert!(!mac.transmit(&f));
    assert_eq!(mac.receive(&mut buf), None);
    assert_eq!(mac.errors(), 2);
}
