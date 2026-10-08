// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A register-level model of the LAN8650/1, for the tests.
//!
//! It is written from the data sheet (DS60001734F), the configuration note
//! (AN1760, DS60001760G) and the errata sheet (DS80001075F), and models only what
//! those documents state and the crate depends on. Each behaviour names where it
//! comes from. What the documents do not state is not modelled: how long a reset
//! takes, the SPI-valid time after power-up, and anything about what the vendor
//! configuration registers do (the data sheet does not describe them).
//!
//! The control-transaction framing (header echo, parity, the data word) is the
//! TC6 interface's and follows the model in `wz-oa-tc6`'s own tests.

use std::collections::{HashMap, VecDeque};
use std::vec;
use std::vec::Vec;
use wz_oa_tc6::proto::{parity_ok, std_reg, DataHeader, FooterBuilder, Reg, WORD};
use wz_runtime_core::SpiTransfer;

/// The chunk payload size the model runs at: `OA_CONFIG0.BPS` resets to 0b110
/// (DS60001734F 11.1.5).
const CPS: usize = 64;

/// Bits above the five an indirect read's mask keeps. AN1760 masks the result
/// with 0x1F, which is only needed if the register's other bits can be set, so the
/// model sets them: a driver that forgets the mask reads a wrong offset.
const INDIRECT_JUNK: u16 = 0xA5E0;

const CONFIG0_SYNC: u32 = 1 << 15;
const NCR_TXEN: u32 = 1 << 3;
const NCR_RXEN: u32 = 1 << 2;
const NCFGR_RFCS: u32 = 1 << 17;
const NCFGR_MTIHEN: u32 = 1 << 6;
const NCFGR_NBC: u32 = 1 << 5;
const PLCA_STS_PST: u32 = 1 << 15;
const STS1_PSTC: u32 = 1 << 11;

/// What the model puts after a received frame when `RFCS` is clear (DS60001734F
/// 5.2: by default the FCS is passed to the host). Its value is the model's.
pub(crate) const FCS: [u8; 4] = [0xFC, 0xFC, 0xFC, 0xFC];

/// One control access the model served, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Access {
    Read(Reg),
    Write(Reg, u32),
}

impl Access {
    pub(crate) fn reg(self) -> Reg {
        match self {
            Access::Read(reg) | Access::Write(reg, _) => reg,
        }
    }
}

struct RxChunk {
    payload: Vec<u8>,
    start: bool,
    end: bool,
    end_offset: u8,
}

pub(crate) struct Chip {
    regs: HashMap<(u8, u16), u32>,
    /// Every control access, in order.
    pub accesses: Vec<Access>,
    /// Every SPI transfer, control or data.
    pub transfers: usize,
    /// Fail the SPI transfer with this index, once.
    pub fail_at: Option<usize>,
    pub devid: u32,
    /// What indirect address `a` holds: the five bits AN1760 reads.
    pub indirect: HashMap<u16, u16>,
    indirect_address: u32,
    indirect_result: u16,
    /// Completed software resets, power-on not counted.
    pub resets: u32,
    /// A part whose software reset never reports completion.
    pub reset_never_completes: bool,
    /// Which `OA_STATUS0` bits raise the footer's extended-status flag. `RESETC`
    /// is always among them (`OA_IMASK0.RESETCM` is read-only 0, DS60001734F
    /// 11.1.9).
    pub unmasked_status0: u32,
    address1_active: bool,
    rx: VecDeque<RxChunk>,
    tx_frame: Vec<u8>,
    /// Frames that reached the wire.
    pub wire: Vec<Vec<u8>>,
    /// Transmit frames the model dropped because the MAC transmitter or `SYNC`
    /// was not enabled.
    pub tx_dropped: u32,
}

impl Chip {
    /// A part just powered on: reset state, `RESETC` set (DS60001734F 4.1.1.1).
    pub(crate) fn new(devid: u32) -> Self {
        let mut chip = Self {
            regs: HashMap::new(),
            accesses: Vec::new(),
            transfers: 0,
            fail_at: None,
            devid,
            indirect: HashMap::new(),
            indirect_address: 0,
            indirect_result: 0xDEAD,
            resets: 0,
            reset_never_completes: false,
            unmasked_status0: std_reg::STATUS0_RESETC,
            address1_active: false,
            rx: VecDeque::new(),
            tx_frame: Vec::new(),
            wire: Vec::new(),
            tx_dropped: 0,
        };
        chip.load_reset_values();
        chip.set(std_reg::STATUS0, std_reg::STATUS0_RESETC);
        chip
    }

    /// The reset values of the registers the crate touches, from their
    /// descriptions in DS60001734F: `OA_CONFIG0` 0x0006 (11.1.5), `MAC_NCFGR`
    /// 0x0008_0000 (11.2.2), `PLCA_CTRL1` 0x08FF (11.5.59) and `CDCTL0` 0x80C3
    /// (11.5.51). Every other register is zero. `SYNC` is clear.
    fn load_reset_values(&mut self) {
        self.regs.clear();
        self.regs.insert((0, 0x004), 0x0000_0006);
        self.regs.insert((1, 0x0001), 0x0008_0000);
        self.regs.insert((4, 0xCA02), 0x0000_08FF);
        self.regs.insert((4, 0x0087), 0x0000_80C3);
        self.address1_active = false;
        self.tx_frame.clear();
    }

    pub(crate) fn get(&self, reg: Reg) -> u32 {
        *self.regs.get(&(reg.mms, reg.addr)).unwrap_or(&0)
    }

    pub(crate) fn set(&mut self, reg: Reg, value: u32) {
        self.regs.insert((reg.mms, reg.addr), value);
    }

    pub(crate) fn synced(&self) -> bool {
        self.get(std_reg::CONFIG0) & CONFIG0_SYNC != 0
    }

    /// The station address as the first specific-address pair decodes: bytes 0 to
    /// 3 of the destination address in the bottom register, least significant
    /// byte first, and bytes 4 and 5 in the top register (DS60001734F 6.4.4).
    pub(crate) fn address1(&self) -> [u8; 6] {
        let bottom = self.get(Reg::new(1, 0x0022)).to_le_bytes();
        let top = self.get(Reg::new(1, 0x0023)).to_le_bytes();
        [bottom[0], bottom[1], bottom[2], bottom[3], top[0], top[1]]
    }

    /// The pair is deactivated at reset and when the bottom register is written,
    /// and activated when the top one is (DS60001734F 11.2.5, 11.2.6).
    pub(crate) fn address1_active(&self) -> bool {
        self.address1_active
    }

    /// A full-device reset from outside the SPI port (power, the reset pin): the
    /// registers go to their reset values, `RESETC` is set and `SYNC` is clear
    /// (DS60001734F Figure 4-1).
    pub(crate) fn reset(&mut self) {
        self.load_reset_values();
        self.set(std_reg::STATUS0, std_reg::STATUS0_RESETC);
    }

    /// A reset of the integrated PHY alone (`BASIC_CONTROL.SW_RESET`): the PHY's
    /// registers (MMS 2 to 4) go to their reset values and `RESETC` is set, while
    /// the MAC and the OPEN Alliance registers, `SYNC` included, are kept
    /// (DS60001734F 4.1.1.3: "will reset only the internal PHY, not the entire
    /// device"). The data sheet's Figure 4-1 lists this reset among those that
    /// clear `SYNC`; this is the other reading of the two, the one `SYNC` stays
    /// set under.
    pub(crate) fn reset_phy_only(&mut self) {
        self.regs.retain(|&(mms, _), _| !(2..=4).contains(&mms));
        self.regs.insert((4, 0xCA02), 0x0000_08FF);
        self.regs.insert((4, 0x0087), 0x0000_80C3);
        let status0 = self.get(std_reg::STATUS0);
        self.set(std_reg::STATUS0, status0 | std_reg::STATUS0_RESETC);
    }

    /// The PHY reports PLCA active or not. A change sets `STS1.PSTC` (DS60001734F
    /// 11.5.2).
    pub(crate) fn set_plca_active(&mut self, active: bool) {
        let before = self.get(Reg::new(4, 0xCA03)) & PLCA_STS_PST != 0;
        self.set(Reg::new(4, 0xCA03), if active { PLCA_STS_PST } else { 0 });
        if before != active {
            let sts1 = self.get(Reg::new(4, 0x0018));
            self.set(Reg::new(4, 0x0018), sts1 | STS1_PSTC);
        }
    }

    /// Set Status 1 flags, as the PHY would on an event.
    pub(crate) fn raise_sts1(&mut self, bits: u32) {
        let sts1 = self.get(Reg::new(4, 0x0018));
        self.set(Reg::new(4, 0x0018), sts1 | bits);
    }

    // ---- the network side ---------------------------------------------------

    /// A frame arrives from the network (no FCS in `frame`). The MAC accepts it if
    /// the receiver and `SYNC` are on and the destination address matches: the
    /// active specific address, the broadcast address (`NBC` clear), or a
    /// multicast address the hash register selects when `MTIHEN` is set
    /// (DS60001734F 6.4.4 to 6.4.6, 6.5.1.5). An accepted frame is queued for the
    /// host with its FCS unless `RFCS` is set.
    pub(crate) fn network_frame(&mut self, frame: &[u8]) -> bool {
        if !(self.synced() && self.get(Reg::new(1, 0)) & NCR_RXEN != 0) {
            return false;
        }
        let ncfgr = self.get(Reg::new(1, 1));
        let da: [u8; 6] = frame[..6].try_into().unwrap();
        let unicast_match = self.address1_active && da == self.address1();
        let broadcast = da == [0xFF; 6] && ncfgr & NCFGR_NBC == 0;
        let hash =
            u64::from(self.get(Reg::new(1, 0x21))) << 32 | u64::from(self.get(Reg::new(1, 0x20)));
        let multicast =
            da[0] & 1 == 1 && ncfgr & NCFGR_MTIHEN != 0 && (hash >> hash_index(&da)) & 1 == 1;
        if !(unicast_match || broadcast || multicast) {
            return false;
        }
        let mut bytes = frame.to_vec();
        if ncfgr & NCFGR_RFCS == 0 {
            bytes.extend_from_slice(&FCS);
        }
        self.queue_rx(&bytes);
        true
    }

    /// Queue `frame` as the chunks the part sends in ZARFE mode.
    fn queue_rx(&mut self, frame: &[u8]) {
        let chunks: Vec<&[u8]> = frame.chunks(CPS).collect();
        let n = chunks.len();
        for (i, chunk) in chunks.into_iter().enumerate() {
            let mut payload = vec![0u8; CPS];
            payload[..chunk.len()].copy_from_slice(chunk);
            self.rx.push_back(RxChunk {
                payload,
                start: i == 0,
                end: i + 1 == n,
                end_offset: (chunk.len() - 1) as u8,
            });
        }
    }

    // ---- the SPI side -------------------------------------------------------

    fn read_reg(&mut self, reg: Reg) -> u32 {
        if reg == Reg::new(10, 0x0094) {
            return self.devid;
        }
        if reg == Reg::new(4, 0x00D9) {
            return u32::from(self.indirect_result);
        }
        let value = self.get(reg);
        if reg == Reg::new(4, 0x0018) {
            // Status 1 is read-to-clear (DS60001734F 11.5.2).
            self.set(reg, 0);
        }
        value
    }

    fn write_reg(&mut self, reg: Reg, value: u32) {
        match (reg.mms, reg.addr) {
            // Write one to clear (DS60001734F 11.1.6).
            (0, 0x008) | (0, 0x009) => {
                let current = self.get(reg);
                self.set(reg, current & !value);
            }
            // `SYNC` is write-one-to-set and "may only be cleared by a reset"
            // (DS60001734F 11.1.5).
            (0, 0x004) => {
                let sync = (self.get(reg) | value) & CONFIG0_SYNC;
                self.set(reg, (value & !CONFIG0_SYNC) | sync);
            }
            // `OA_RESET.SWRESET`: a full reset, after which `RESETC` is set.
            (0, 0x003) => {
                if value & std_reg::RESET_SWRESET != 0 {
                    self.reset();
                    self.resets += 1;
                    if self.reset_never_completes {
                        self.set(std_reg::STATUS0, 0);
                    }
                }
            }
            (1, 0x0022) => {
                self.address1_active = false;
                self.set(reg, value);
            }
            (1, 0x0023) => {
                self.address1_active = true;
                self.set(reg, value);
            }
            // AN1760's indirect read: the address, then 2 to start it.
            (4, 0x00D8) => self.indirect_address = value,
            (4, 0x00DA) => {
                if value == 2 {
                    let held = self
                        .indirect
                        .get(&(self.indirect_address as u16))
                        .copied()
                        .unwrap_or(0x1F);
                    self.indirect_result = held | INDIRECT_JUNK;
                }
            }
            // `PLCA_STS` is read-only.
            (4, 0xCA03) => {}
            _ => self.set(reg, value),
        }
    }

    fn control(&mut self, tx: &[u8], rx: &mut [u8]) {
        let header = u32::from_be_bytes([tx[0], tx[1], tx[2], tx[3]]);
        assert!(parity_ok(header), "a control header with even parity");
        let write = header & (1 << 29) != 0;
        let reg = Reg::new(
            ((header >> 24) & 0xF) as u8,
            ((header >> 8) & 0xFFFF) as u16,
        );
        let put = |rx: &mut [u8], i: usize, v: u32| {
            rx[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
        };
        put(rx, 0, 0);
        put(rx, 1, header);
        if write {
            let value = u32::from_be_bytes([tx[4], tx[5], tx[6], tx[7]]);
            self.accesses.push(Access::Write(reg, value));
            self.write_reg(reg, value);
            put(rx, 2, value);
        } else {
            self.accesses.push(Access::Read(reg));
            let value = self.read_reg(reg);
            put(rx, 2, value);
        }
    }

    fn data(&mut self, tx: &[u8], rx: &mut [u8]) {
        let header_word = u32::from_be_bytes([tx[0], tx[1], tx[2], tx[3]]);
        let h = DataHeader::parse(header_word).expect("a data header with odd parity");
        if h.data_valid {
            let payload = &tx[WORD..WORD + CPS];
            if h.start_valid {
                self.tx_frame.clear();
            }
            let take = if h.end_valid {
                usize::from(h.end_byte_offset) + 1
            } else {
                CPS
            };
            self.tx_frame.extend_from_slice(&payload[..take]);
            if h.end_valid {
                let frame = std::mem::take(&mut self.tx_frame);
                // Frames go out when `SYNC` is set and the transmitter is enabled
                // (DS60001734F 6.5.1.4).
                if self.synced() && self.get(Reg::new(1, 0)) & NCR_TXEN != 0 {
                    self.wire.push(frame);
                } else {
                    self.tx_dropped += 1;
                }
            }
        }
        let chunk = if h.no_receive || !self.synced() {
            None
        } else {
            self.rx.pop_front()
        };
        match &chunk {
            Some(c) => rx[..CPS].copy_from_slice(&c.payload),
            None => rx[..CPS].fill(0),
        }
        let mut footer = FooterBuilder {
            extended_status: self.get(std_reg::STATUS0) & self.unmasked_status0 != 0,
            synced: self.synced(),
            rca: self.rx.len().min(31) as u8,
            txc: 8,
            ..FooterBuilder::default()
        };
        if let Some(c) = &chunk {
            footer.data_valid = true;
            footer.start_valid = c.start;
            footer.end_valid = c.end;
            footer.end_byte_offset = if c.end { c.end_offset } else { 0 };
        }
        rx[CPS..CPS + WORD].copy_from_slice(&footer.word().to_be_bytes());
    }
}

/// The 6-bit hash index of a destination address: the exclusive OR of every sixth
/// bit, `hash_index[k] = da[k] ^ da[k + 6] ^ ... ^ da[k + 42]`, where `da[0]` is
/// the least significant bit of the first byte (DS60001734F 6.4.6).
pub(crate) fn hash_index(da: &[u8; 6]) -> u32 {
    let bit = |n: usize| u32::from((da[n / 8] >> (n % 8)) & 1);
    (0..6usize)
        .map(|k| (0..8usize).fold(0, |acc, j| acc ^ bit(k + 6 * j)) << k)
        .sum()
}

impl SpiTransfer for Chip {
    type Error = ();

    fn transfer(&mut self, tx: &[u8], rx: &mut [u8]) -> Result<(), ()> {
        assert_eq!(tx.len(), rx.len(), "full duplex: the same bytes each way");
        let index = self.transfers;
        self.transfers += 1;
        if self.fail_at == Some(index) {
            self.fail_at = None;
            return Err(());
        }
        if tx[0] & 0x80 == 0 {
            self.control(tx, rx);
        } else {
            self.data(tx, rx);
        }
        Ok(())
    }
}
