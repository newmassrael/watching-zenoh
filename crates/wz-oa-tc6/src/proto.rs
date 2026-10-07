// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The bit layouts of the OPEN Alliance TC6 serial interface: the control
//! header, the data header and footer, the parity rule, and the standard
//! registers of memory map selector 0.
//!
//! The layouts are those `oa_tc6.h` gives (Zephyr, Apache-2.0), which follow the
//! OPEN Alliance specification. Every word on the wire is big-endian.

/// A header or footer is one 32-bit word.
pub const WORD: usize = 4;
/// The largest chunk payload the interface defines.
pub const CPS_MAX: usize = 64;

/// The parity bit a word needs: the interface uses ODD parity over the whole
/// 32-bit word, bit 0 (P) included. `word` has P clear; the result is the P that
/// makes the count of ones odd.
pub const fn parity_bit(word: u32) -> u32 {
    (word.count_ones() + 1) & 1
}

/// `word` (P included) carries odd parity, which is what a valid header or
/// footer has.
pub const fn parity_ok(word: u32) -> bool {
    word.count_ones() & 1 == 1
}

/// `word` with its parity bit set as the interface requires.
pub const fn with_parity(word: u32) -> u32 {
    (word & !1) | parity_bit(word & !1)
}

/// A register address: a memory map selector and a 16-bit address in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reg {
    /// Memory map selector, 0 to 15.
    pub mms: u8,
    pub addr: u16,
}

impl Reg {
    /// A register of memory map selector `mms` at `addr`.
    pub const fn new(mms: u8, addr: u16) -> Self {
        Self { mms, addr }
    }
}

/// The standard registers, memory map selector 0.
pub mod std_reg {
    use super::Reg;

    /// Identification: the interface version (`0x11` for 1.1 per Zephyr).
    pub const ID: Reg = Reg::new(0, 0x000);
    pub const PHYID: Reg = Reg::new(0, 0x001);
    pub const RESET: Reg = Reg::new(0, 0x003);
    pub const CONFIG0: Reg = Reg::new(0, 0x004);
    pub const STATUS0: Reg = Reg::new(0, 0x008);
    pub const STATUS1: Reg = Reg::new(0, 0x009);
    pub const BUFSTS: Reg = Reg::new(0, 0x00B);
    pub const IMASK0: Reg = Reg::new(0, 0x00C);
    pub const IMASK1: Reg = Reg::new(0, 0x00D);

    /// `RESET.SWRESET`.
    pub const RESET_SWRESET: u32 = 1 << 0;
    /// `CONFIG0.SYNC`: the host declares the configuration done; the device
    /// reports it in every footer, and a footer without it means the device lost
    /// its configuration (a reset) and must be set up again.
    pub const CONFIG0_SYNC: u32 = 1 << 15;
    /// `CONFIG0.RFA`'s ZARFE value (bit 12): receive frames start at the first
    /// byte of a chunk, which is what lets the receive path stay simple.
    pub const CONFIG0_RFA_ZARFE: u32 = 1 << 12;
    /// `CONFIG0.PROTE`: control transactions carry a complement of each data word.
    pub const CONFIG0_PROTE: u32 = 1 << 5;
    /// `STATUS0.RESETC`: the device finished a reset.
    pub const STATUS0_RESETC: u32 = 1 << 6;
}

// ---- control header ------------------------------------------------------

const CTRL_WNR: u32 = 1 << 29;
const CTRL_MMS_POS: u32 = 24;
const CTRL_ADDR_POS: u32 = 8;

/// The header of a control transaction for ONE register: data-not-control clear,
/// address increment on, the length field (bits 7:1) left at 0 for a count of
/// one, parity set.
pub const fn control_header(write: bool, reg: Reg) -> u32 {
    let mut word = ((reg.mms as u32 & 0xF) << CTRL_MMS_POS) | ((reg.addr as u32) << CTRL_ADDR_POS);
    if write {
        word |= CTRL_WNR;
    }
    with_parity(word)
}

// ---- data header ----------------------------------------------------------

const DATA_DNC: u32 = 1 << 31;
const DATA_NORX: u32 = 1 << 29;
const DATA_DV: u32 = 1 << 21;
const DATA_SV: u32 = 1 << 20;
const DATA_EV: u32 = 1 << 14;
const DATA_EBO_POS: u32 = 8;

/// What a data chunk exchange carries on the host's side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataHeader {
    /// The chunk's payload is transmit data.
    pub data_valid: bool,
    /// Do not send receive data in this exchange.
    pub no_receive: bool,
    /// The payload starts a frame (at byte 0: no start offset is used).
    pub start_valid: bool,
    /// The payload ends a frame, with `end_byte_offset` its last valid byte.
    pub end_valid: bool,
    pub end_byte_offset: u8,
}

impl DataHeader {
    /// An exchange that sends nothing and asks for whatever is waiting.
    pub const RECEIVE: Self = Self {
        data_valid: false,
        no_receive: false,
        start_valid: false,
        end_valid: false,
        end_byte_offset: 0,
    };

    /// An exchange that only reads the footer: nothing sent, nothing asked for.
    pub const STATUS: Self = Self {
        data_valid: false,
        no_receive: true,
        start_valid: false,
        end_valid: false,
        end_byte_offset: 0,
    };

    /// The header word, parity set.
    pub const fn word(self) -> u32 {
        let mut word = DATA_DNC;
        if self.data_valid {
            word |= DATA_DV;
        }
        if self.no_receive {
            word |= DATA_NORX;
        }
        if self.start_valid {
            word |= DATA_SV;
        }
        if self.end_valid {
            word |= DATA_EV | ((self.end_byte_offset as u32 & 0x3F) << DATA_EBO_POS);
        }
        with_parity(word)
    }

    /// Read a header word back (a device model, or a test).
    pub const fn parse(word: u32) -> Option<Self> {
        if word & DATA_DNC == 0 || !parity_ok(word) {
            return None;
        }
        Some(Self {
            data_valid: word & DATA_DV != 0,
            no_receive: word & DATA_NORX != 0,
            start_valid: word & DATA_SV != 0,
            end_valid: word & DATA_EV != 0,
            end_byte_offset: ((word >> DATA_EBO_POS) & 0x3F) as u8,
        })
    }
}

// ---- data footer ------------------------------------------------------------

const FTR_EXST: u32 = 1 << 31;
const FTR_HDRB: u32 = 1 << 30;
const FTR_SYNC: u32 = 1 << 29;
const FTR_RCA_POS: u32 = 24;
const FTR_DV: u32 = 1 << 21;
const FTR_SV: u32 = 1 << 20;
const FTR_SWO_POS: u32 = 16;
const FTR_FD: u32 = 1 << 15;
const FTR_EV: u32 = 1 << 14;
const FTR_EBO_POS: u32 = 8;
const FTR_TXC_POS: u32 = 1;

/// The footer of a data chunk exchange: the device's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Footer(pub u32);

impl Footer {
    /// An interrupt-class condition is pending in the status registers.
    pub const fn extended_status(self) -> bool {
        self.0 & FTR_EXST != 0
    }
    /// The device rejected the header's parity.
    pub const fn header_bad(self) -> bool {
        self.0 & FTR_HDRB != 0
    }
    /// The device holds the configuration the host declared with `CONFIG0.SYNC`.
    pub const fn synced(self) -> bool {
        self.0 & FTR_SYNC != 0
    }
    /// Receive chunks the device has waiting, saturating at 31.
    pub const fn receive_chunks_available(self) -> u8 {
        ((self.0 >> FTR_RCA_POS) & 0x1F) as u8
    }
    /// The receive payload of this exchange is valid.
    pub const fn data_valid(self) -> bool {
        self.0 & FTR_DV != 0
    }
    /// The receive payload starts a frame.
    pub const fn start_valid(self) -> bool {
        self.0 & FTR_SV != 0
    }
    /// The start offset in 32-bit words (0 in ZARFE mode).
    pub const fn start_word_offset(self) -> u8 {
        ((self.0 >> FTR_SWO_POS) & 0xF) as u8
    }
    /// The device asks that the frame this payload belongs to be dropped.
    pub const fn frame_drop(self) -> bool {
        self.0 & FTR_FD != 0
    }
    /// The receive payload ends a frame.
    pub const fn end_valid(self) -> bool {
        self.0 & FTR_EV != 0
    }
    /// The last valid byte of an ending chunk.
    pub const fn end_byte_offset(self) -> u8 {
        ((self.0 >> FTR_EBO_POS) & 0x3F) as u8
    }
    /// Transmit chunks the device can still take, saturating at 31.
    pub const fn transmit_credits(self) -> u8 {
        ((self.0 >> FTR_TXC_POS) & 0x1F) as u8
    }
    /// The footer carries odd parity.
    pub const fn parity_ok(self) -> bool {
        parity_ok(self.0)
    }
}

/// A footer as a device builds it (a device model, or a test).
#[derive(Debug, Clone, Copy, Default)]
pub struct FooterBuilder {
    pub extended_status: bool,
    pub header_bad: bool,
    pub synced: bool,
    pub rca: u8,
    pub data_valid: bool,
    pub start_valid: bool,
    /// Where in the chunk the frame starts, in 32-bit words (four bits).
    /// Meaningful only with `start_valid`.
    pub start_word_offset: u8,
    pub frame_drop: bool,
    pub end_valid: bool,
    pub end_byte_offset: u8,
    pub txc: u8,
}

impl FooterBuilder {
    /// The footer word, parity set.
    pub const fn word(self) -> u32 {
        let mut w = 0u32;
        if self.extended_status {
            w |= FTR_EXST;
        }
        if self.header_bad {
            w |= FTR_HDRB;
        }
        if self.synced {
            w |= FTR_SYNC;
        }
        w |= (self.rca as u32 & 0x1F) << FTR_RCA_POS;
        if self.data_valid {
            w |= FTR_DV;
        }
        if self.start_valid {
            w |= FTR_SV | ((self.start_word_offset as u32 & 0xF) << FTR_SWO_POS);
        }
        if self.frame_drop {
            w |= FTR_FD;
        }
        if self.end_valid {
            w |= FTR_EV | ((self.end_byte_offset as u32 & 0x3F) << FTR_EBO_POS);
        }
        w |= (self.txc as u32 & 0x1F) << FTR_TXC_POS;
        with_parity(w)
    }
}
