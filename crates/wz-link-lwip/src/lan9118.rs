// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2836 — an SMSC LAN9118 Ethernet MAC, as an
//! [`crate::ethernet::EthernetMac`].
//!
//! The LAN9118 is the Ethernet controller on Arm's MPS2 boards, and so on
//! QEMU's `mps2-an385` / `an386` / `an500` / `an511` machines, which is what
//! lets a wz MCU node under QEMU reach a host over real Ethernet frames. The
//! register behaviour here was read off QEMU 8.2.2 `hw/net/lan9118.c`, the
//! model the lanes run against, and kept to what the part's own programming
//! model also requires (it polls the busy bits QEMU clears at once).
//!
//! The chip is driven through its FIFO ports in 32-bit mode:
//!
//! * TRANSMIT: two command words, then the frame in little-endian words.
//!   Command A carries the buffer size and the FIRST/LAST segment bits; one
//!   buffer is one frame. Command B carries the packet length and a tag.
//! * RECEIVE: the RX status FIFO holds one word per frame whose length field
//!   counts the FCS; the data FIFO then holds that many bytes, rounded up to
//!   whole words, and the FCS is dropped here.
//!
//! The packing is split into [`crate::lan9118::tx_words`] and
//! [`crate::lan9118::rx_unpack`], which touch no
//! register, so they are tested against a transcription of the model's own
//! reassembly and packing without a board.

use crate::ethernet::EthernetMac;

/// The LAN9118's base on QEMU's `mps2-an385`, `an386` and `an511`.
pub const MPS2_BASE: usize = 0x4020_0000;
/// The LAN9118's base on QEMU's `mps2-an500`.
pub const MPS2_AN500_BASE: usize = 0xa000_0000;

const RX_DATA_FIFO: usize = 0x00;
const TX_DATA_FIFO: usize = 0x20;
const RX_STATUS_FIFO: usize = 0x40;
const TX_STATUS_FIFO: usize = 0x48;
const BYTE_TEST: usize = 0x64;
const TX_CFG: usize = 0x70;
const HW_CFG: usize = 0x74;
const RX_FIFO_INF: usize = 0x7c;
const TX_FIFO_INF: usize = 0x80;
const MAC_CSR_CMD: usize = 0xa4;
const MAC_CSR_DATA: usize = 0xa8;

const BYTE_TEST_VALUE: u32 = 0x8765_4321;
const HW_CFG_SRST: u32 = 1 << 0;
const TX_CFG_TX_ON: u32 = 1 << 1;
const CSR_BUSY: u32 = 1 << 31;
const CSR_READ: u32 = 1 << 30;

const MAC_CR: u32 = 1;
const MAC_ADDRH: u32 = 2;
const MAC_ADDRL: u32 = 3;
const MAC_CR_TXEN: u32 = 1 << 3;
const MAC_CR_RXEN: u32 = 1 << 2;

const TX_CMD_A_FIRST: u32 = 1 << 13;
const TX_CMD_A_LAST: u32 = 1 << 12;
const TX_BUFFER_SIZE_MASK: u32 = 0x7ff;
const RX_STATUS_ERROR: u32 = 1 << 15;
const FCS_LEN: usize = 4;

/// How many times a busy bit is polled before the chip is declared stuck.
const POLL_LIMIT: u32 = 100_000;

/// Why the chip could not be brought up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lan9118Error {
    /// `BYTE_TEST` did not read `0x87654321`: nothing answers at the base,
    /// or the bus is not 32-bit.
    NotPresent,
    /// A busy bit never cleared.
    Stuck,
}

/// The words that put `frame` on the wire: command A, command B, then the
/// frame packed little-endian into whole words, the last padded with zeros.
pub fn tx_words(frame: &[u8]) -> impl Iterator<Item = u32> + '_ {
    let len = frame.len() as u32 & TX_BUFFER_SIZE_MASK;
    let command_a = TX_CMD_A_FIRST | TX_CMD_A_LAST | len;
    // Command B: the tag (echoed in TX status) in the high half, the packet
    // length in the low bits.
    let command_b = (len << 16) | len;
    [command_a, command_b]
        .into_iter()
        .chain(frame.chunks(4).map(|chunk| {
            let mut word = [0u8; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            u32::from_le_bytes(word)
        }))
}

/// Take one received frame out of the data FIFO.
///
/// `status` is the frame's RX status word; `words` yields the data FIFO. The
/// frame's words are consumed whatever happens, so the FIFO stays in step:
/// a frame in error, shorter than its FCS, or longer than `buf` is drained
/// and `None` is returned. Otherwise the frame without its FCS is in `buf`
/// and its length is returned.
pub fn rx_unpack(status: u32, mut words: impl FnMut() -> u32, buf: &mut [u8]) -> Option<usize> {
    let with_fcs = ((status >> 16) & 0x3fff) as usize;
    let word_count = with_fcs.div_ceil(4);
    let keep =
        with_fcs >= FCS_LEN && with_fcs - FCS_LEN <= buf.len() && status & RX_STATUS_ERROR == 0;
    let frame_len = with_fcs.saturating_sub(FCS_LEN);
    for i in 0..word_count {
        let bytes = words().to_le_bytes();
        if keep {
            for (j, byte) in bytes.into_iter().enumerate() {
                let at = i * 4 + j;
                if at < frame_len {
                    buf[at] = byte;
                }
            }
        }
    }
    keep.then_some(frame_len)
}

/// A LAN9118 at a fixed MMIO base.
pub struct Lan9118 {
    base: usize,
}

impl Lan9118 {
    /// A driver for the chip at `base` — [`MPS2_BASE`] or
    /// [`MPS2_AN500_BASE`] under QEMU.
    ///
    /// # Safety
    ///
    /// `base` must be the chip's register block, mapped and not driven by
    /// anything else for as long as this value lives.
    pub const unsafe fn new(base: usize) -> Self {
        Self { base }
    }

    fn read(&self, offset: usize) -> u32 {
        // SAFETY: `new`'s contract makes `base + offset` a register of the
        // chip, and every offset used here is one.
        unsafe { core::ptr::read_volatile((self.base + offset) as *const u32) }
    }

    fn write(&self, offset: usize, value: u32) {
        // SAFETY: as in `read`.
        unsafe { core::ptr::write_volatile((self.base + offset) as *mut u32, value) }
    }

    fn wait_clear(&self, offset: usize, bit: u32) -> Result<(), Lan9118Error> {
        for _ in 0..POLL_LIMIT {
            if self.read(offset) & bit == 0 {
                return Ok(());
            }
        }
        Err(Lan9118Error::Stuck)
    }

    fn mac_read(&self, reg: u32) -> Result<u32, Lan9118Error> {
        self.write(MAC_CSR_CMD, CSR_BUSY | CSR_READ | reg);
        self.wait_clear(MAC_CSR_CMD, CSR_BUSY)?;
        Ok(self.read(MAC_CSR_DATA))
    }

    fn mac_write(&self, reg: u32, value: u32) -> Result<(), Lan9118Error> {
        self.write(MAC_CSR_DATA, value);
        self.write(MAC_CSR_CMD, CSR_BUSY | reg);
        self.wait_clear(MAC_CSR_CMD, CSR_BUSY)
    }

    /// Reset the chip and enable its transmitter and receiver. The station
    /// address is the one the chip holds (its EEPROM's, or QEMU's `-nic`
    /// `mac=`).
    pub fn init(&mut self) -> Result<(), Lan9118Error> {
        if self.read(BYTE_TEST) != BYTE_TEST_VALUE {
            return Err(Lan9118Error::NotPresent);
        }
        self.write(HW_CFG, HW_CFG_SRST);
        self.wait_clear(HW_CFG, HW_CFG_SRST)?;
        // Unicast to this address and broadcast; not promiscuous.
        self.mac_write(MAC_CR, MAC_CR_TXEN | MAC_CR_RXEN)?;
        self.write(TX_CFG, TX_CFG_TX_ON);
        Ok(())
    }
}

impl EthernetMac for Lan9118 {
    fn mac_address(&self) -> [u8; 6] {
        let low = self.mac_read(MAC_ADDRL).unwrap_or(0).to_le_bytes();
        let high = self.mac_read(MAC_ADDRH).unwrap_or(0).to_le_bytes();
        [low[0], low[1], low[2], low[3], high[0], high[1]]
    }

    fn transmit(&mut self, frame: &[u8]) -> bool {
        // Retire finished transmissions so the status FIFO never fills.
        while (self.read(TX_FIFO_INF) >> 16) & 0xff != 0 {
            let _ = self.read(TX_STATUS_FIFO);
        }
        // Two command words and the padded frame must fit the data FIFO.
        let needed = 8 + frame.len().div_ceil(4) * 4;
        if (self.read(TX_FIFO_INF) & 0xffff) < needed as u32 {
            return false;
        }
        for word in tx_words(frame) {
            self.write(TX_DATA_FIFO, word);
        }
        true
    }

    fn receive(&mut self, buf: &mut [u8]) -> Option<usize> {
        loop {
            if (self.read(RX_FIFO_INF) >> 16) & 0xff == 0 {
                return None;
            }
            let status = self.read(RX_STATUS_FIFO);
            if let Some(len) = rx_unpack(status, || self.read(RX_DATA_FIFO), buf) {
                return Some(len);
            }
            // A frame that could not be kept was drained; try the next.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// QEMU 8.2.2 `hw/net/lan9118.c` `tx_fifo_push`, for the one-buffer,
    /// zero-offset frames this driver sends: command A, command B, then
    /// `buffer_size` bytes taken little-endian from each word; the packet
    /// goes out when the buffer is exhausted and command A has LAST.
    fn qemu_reassembles(words: &[u32]) -> Option<Vec<u8>> {
        let command_a = *words.first()?;
        let _command_b = *words.get(1)?;
        if command_a & TX_CMD_A_FIRST == 0 || command_a & TX_CMD_A_LAST == 0 {
            return None;
        }
        let mut remaining = (command_a & 0x7ff) as usize;
        let mut frame = Vec::new();
        for word in &words[2..] {
            let n = remaining.min(4);
            frame.extend_from_slice(&word.to_le_bytes()[..n]);
            remaining -= n;
        }
        (remaining == 0).then_some(frame)
    }

    /// QEMU 8.2.2 `lan9118_receive`, zero RX offset: the frame packed
    /// little-endian, the CRC appended, and a status word whose length is
    /// `size + 4`.
    fn qemu_packs(frame: &[u8]) -> (u32, Vec<u32>) {
        let mut bytes = frame.to_vec();
        bytes.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let words = bytes
            .chunks(4)
            .map(|c| {
                let mut w = [0u8; 4];
                w[..c.len()].copy_from_slice(c);
                u32::from_le_bytes(w)
            })
            .collect();
        (((frame.len() + 4) as u32) << 16, words)
    }

    #[test]
    fn a_sent_frame_is_what_the_model_reassembles() {
        for len in [60usize, 61, 62, 63, 64, 1514] {
            let frame: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let words: Vec<u32> = tx_words(&frame).collect();
            std::assert_eq!(words.len(), 2 + len.div_ceil(4), "{len}");
            std::assert_eq!(qemu_reassembles(&words), Some(frame), "{len}");
        }
    }

    #[test]
    fn a_received_frame_comes_out_without_its_fcs() {
        for len in [42usize, 60, 61, 62, 63, 1514] {
            let frame: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
            let (status, words) = qemu_packs(&frame);
            let mut feed = words.iter().copied();
            let mut buf = [0u8; 1514];
            let got = rx_unpack(status, || feed.next().unwrap(), &mut buf);
            std::assert_eq!(got, Some(len), "{len}");
            std::assert_eq!(&buf[..len], &frame[..], "{len}");
            std::assert!(feed.next().is_none(), "every word consumed at {len}");
        }
    }

    /// A frame that cannot be kept is still drained, so the next frame's
    /// words are not read as this one's.
    #[test]
    fn a_frame_too_long_or_in_error_is_drained_and_dropped() {
        let frame = [0x55u8; 100];
        let (status, words) = qemu_packs(&frame);

        let mut feed = words.iter().copied();
        let mut small = [0u8; 64];
        std::assert_eq!(rx_unpack(status, || feed.next().unwrap(), &mut small), None);
        std::assert!(feed.next().is_none(), "too long: drained");

        let mut feed = words.iter().copied();
        let mut buf = [0u8; 1514];
        let errored = status | RX_STATUS_ERROR;
        std::assert_eq!(rx_unpack(errored, || feed.next().unwrap(), &mut buf), None);
        std::assert!(feed.next().is_none(), "in error: drained");
    }
}
