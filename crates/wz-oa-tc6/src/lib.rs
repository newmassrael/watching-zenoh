// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

#![no_std]

//! The OPEN Alliance 10BASE-T1x MAC-PHY serial interface (TC6), as a
//! [`wz_runtime_core::EthernetMac`] over a [`wz_runtime_core::SpiTransfer`].
//!
//! A TC6 MAC-PHY is a whole Ethernet controller and a 10BASE-T1S PHY behind an SPI
//! port, and the interface is the same for every chip that implements it: this
//! crate is that interface and nothing of any chip. It owns
//!
//! * CONTROL transactions: one register read or write, with the header parity and
//!   the protected mode in which every data word travels with its complement
//!   ([`Tc6::reg_read`], [`Tc6::reg_write`], [`Tc6::reg_modify`]);
//! * DATA chunk exchanges: a 4-byte header out and a 4-byte footer back around a
//!   chunk payload each way, with the device's transmit credits and receive chunk
//!   count read off the footer ([`Tc6::send_frame`], [`Tc6::receive_frame`]);
//! * the chunking of an Ethernet frame each way, and the reassembly of a received
//!   one, in the ZARFE receive mode in which a frame starts on a chunk boundary.
//!
//! It deliberately does NOT own what differs per chip: the identity registers, the
//! errata fixups a part wants before it runs, the MAC address and filter
//! registers, the PLCA setup of the multidrop bus, the reset line and the interrupt
//! pin. A chip crate does that over [`Tc6`] and hands the result to [`Tc6Mac`].
//! The chunk payload size is the chip's too: the interface lets the host choose it
//! (8, 16, 32 or 64 bytes), and [`Tc6::new`] takes the size the chip crate has
//! left the device configured for.
//!
//! ## What is claimed
//!
//! BUILT. No emulator models a TC6 MAC-PHY. The host tests run this crate against
//! a model of the chip written from the same reading of the interface, so they
//! check the framing, the parity, the credit accounting and the chunking, not the
//! chip.
//!
//! ## Provenance
//!
//! The interface as `oa_tc6.h` and `oa_tc6.c` lay it out (Zephyr, Apache-2.0),
//! which follow the OPEN Alliance specification, read as a reference. The code is
//! new, and polled where Zephyr's is interrupt driven: a receive call is a status
//! exchange when nothing is known to be waiting, unless the board supplies the
//! interrupt line's level ([`Tc6::set_interrupt_probe`]).

pub mod proto;

use proto::{control_header, std_reg, DataHeader, Footer, Reg, CPS_MAX, WORD};
use wz_runtime_core::{EthernetMac, SpiTransfer};

/// The longest frame reassembled for the caller: a 1518-byte frame, tagged, plus
/// slack. A frame beyond it is dropped whole.
pub const RX_FRAME_MAX: usize = 1536;

/// The most chunk exchanges one receive call makes before returning: a device that
/// keeps offering chunks must not hold the caller's loop.
const MAX_CHUNKS_PER_RECEIVE: usize = 64;

/// The chunk payload size the device is configured for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkSize {
    B8 = 8,
    B16 = 16,
    B32 = 32,
    B64 = 64,
}

impl ChunkSize {
    /// The payload size in bytes.
    pub const fn bytes(self) -> usize {
        self as usize
    }
}

/// Why an operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error<E> {
    /// The SPI exchange itself failed.
    Spi(E),
    /// A control transaction's echo of the header was not the header sent.
    HeaderEcho,
    /// A write's echo of the data word was not the word sent.
    DataEcho,
    /// In protected mode a read's data word and its complement disagreed.
    Protected,
    /// A footer did not carry odd parity.
    FooterParity,
    /// The device rejected a header's parity.
    HeaderRejected,
    /// The footer says the device does not hold the configuration the host
    /// declared with `CONFIG0.SYNC`: it was reset and must be set up again.
    NotSynced,
    /// A software reset never reported completion.
    ResetTimeout,
}

/// What the last footer said.
#[derive(Debug, Clone, Copy, Default)]
struct Status {
    extended: bool,
    rca: u8,
    txc: u8,
}

/// A frame being put together from receive chunks.
struct Assembly {
    bytes: [u8; RX_FRAME_MAX],
    len: usize,
    open: bool,
    overflow: bool,
}

/// The TC6 interface over an SPI master.
pub struct Tc6<S: SpiTransfer> {
    spi: S,
    cps: usize,
    protected: bool,
    status: Status,
    interrupt: Option<fn() -> bool>,
    assembly: Assembly,
    /// `STATUS0` bits seen while clearing extended status, for the chip crate.
    events: u32,
}

impl<S: SpiTransfer> Tc6<S> {
    /// The interface over `spi`, the device configured for chunks of `cps` bytes.
    pub fn new(spi: S, cps: ChunkSize) -> Self {
        Self {
            spi,
            cps: cps.bytes(),
            protected: false,
            status: Status::default(),
            interrupt: None,
            assembly: Assembly {
                bytes: [0; RX_FRAME_MAX],
                len: 0,
                open: false,
                overflow: false,
            },
            events: 0,
        }
    }

    /// The SPI master, for a chip crate that needs the bus for itself.
    pub fn spi_mut(&mut self) -> &mut S {
        &mut self.spi
    }

    /// Give the interface the level of the device's interrupt line (true while the
    /// device has something to say). With it a receive call that knows of nothing
    /// waiting costs no SPI exchange while the line is quiet; without it the
    /// interface polls the footer.
    pub fn set_interrupt_probe(&mut self, probe: fn() -> bool) {
        self.interrupt = Some(probe);
    }

    // ---- control transactions -----------------------------------------------

    /// One control transaction for one register. `value` is `Some` for a write.
    /// Returns the data word the device echoed (the value read, or the value
    /// written).
    fn control(&mut self, reg: Reg, value: Option<u32>) -> Result<u32, Error<S::Error>> {
        let write = value.is_some();
        let header = control_header(write, reg);
        // header, then the data word and its complement when protected, then the
        // word the echo of the last data word arrives in.
        let words = if self.protected { 4 } else { 3 };
        let len = words * WORD;
        let mut tx = [0u8; 4 * WORD];
        let mut rx = [0u8; 4 * WORD];
        tx[..WORD].copy_from_slice(&header.to_be_bytes());
        if let Some(v) = value {
            tx[WORD..2 * WORD].copy_from_slice(&v.to_be_bytes());
            if self.protected {
                tx[2 * WORD..3 * WORD].copy_from_slice(&(!v).to_be_bytes());
            }
        }
        self.spi
            .transfer(&tx[..len], &mut rx[..len])
            .map_err(Error::Spi)?;

        let word = |i: usize| {
            u32::from_be_bytes([
                rx[i * WORD],
                rx[i * WORD + 1],
                rx[i * WORD + 2],
                rx[i * WORD + 3],
            ])
        };
        // Word 0 is clocked in while the header goes out and carries nothing; word 1
        // is the device's echo of the header; word 2 is the data.
        if word(1) != header {
            return Err(Error::HeaderEcho);
        }
        let data = word(2);
        if self.protected && data != !word(3) {
            return Err(Error::Protected);
        }
        if let Some(v) = value {
            if data != v {
                return Err(Error::DataEcho);
            }
        }
        Ok(data)
    }

    /// Read one register.
    pub fn reg_read(&mut self, reg: Reg) -> Result<u32, Error<S::Error>> {
        self.control(reg, None)
    }

    /// Write one register.
    pub fn reg_write(&mut self, reg: Reg, value: u32) -> Result<(), Error<S::Error>> {
        self.control(reg, Some(value)).map(|_| ())
    }

    /// Read a register, clear the bits of `mask`, set `bits`, write it back.
    pub fn reg_modify(&mut self, reg: Reg, mask: u32, bits: u32) -> Result<(), Error<S::Error>> {
        let current = self.reg_read(reg)?;
        self.reg_write(reg, (current & !mask) | bits)
    }

    /// Turn the protected control mode on or off: the device's `CONFIG0.PROTE`
    /// first, then this side, because the write that turns it on is itself an
    /// unprotected transaction.
    pub fn set_protected(&mut self, on: bool) -> Result<(), Error<S::Error>> {
        let bit = if on { std_reg::CONFIG0_PROTE } else { 0 };
        self.reg_modify(std_reg::CONFIG0, std_reg::CONFIG0_PROTE, bit)?;
        self.protected = on;
        Ok(())
    }

    /// Software-reset the device and wait for it to say it finished.
    ///
    /// `delay_us` waits; the reset has completed when `STATUS0.RESETC` is set, and
    /// that bit is cleared by writing it back. The device is unconfigured after a
    /// reset, protected mode included, so this side forgets it too.
    ///
    /// The budget is the time `now_us` says has passed, not the sum of the waits
    /// asked of `delay_us`: a wait promises at least what it is told, and a board
    /// whose clock runs slow takes far longer than it asked for, so counting the
    /// asks would let a budget of 100 ms last minutes.
    ///
    /// A `RESETC` that is already set is cleared first. A device reports `RESETC`
    /// after its power-on reset and keeps reporting it until the host writes it
    /// back, so without the clear the wait below would take the old flag for the
    /// completion of THIS reset and return before the device has finished.
    pub fn soft_reset(
        &mut self,
        mut delay_us: impl FnMut(u32),
        mut now_us: impl FnMut() -> u64,
        budget_ms: u32,
    ) -> Result<(), Error<S::Error>> {
        self.reg_write(std_reg::STATUS0, std_reg::STATUS0_RESETC)?;
        // The write that resets the device is a transaction in the mode the device
        // is in NOW; it is unconfigured only once the reset has happened.
        self.reg_write(std_reg::RESET, std_reg::RESET_SWRESET)?;
        self.protected = false;
        self.status = Status::default();
        let started = now_us();
        let budget_us = u64::from(budget_ms) * 1_000;
        loop {
            delay_us(1_000);
            let status0 = self.reg_read(std_reg::STATUS0)?;
            if status0 & std_reg::STATUS0_RESETC != 0 {
                return self.reg_write(std_reg::STATUS0, status0);
            }
            if now_us().saturating_sub(started) >= budget_us {
                return Err(Error::ResetTimeout);
            }
        }
    }

    /// Declare the configuration done (`CONFIG0.SYNC`) and select the receive mode
    /// this crate reassembles (ZARFE: a frame starts on a chunk boundary).
    pub fn enable_sync(&mut self) -> Result<(), Error<S::Error>> {
        self.reg_modify(
            std_reg::CONFIG0,
            0,
            std_reg::CONFIG0_SYNC | std_reg::CONFIG0_RFA_ZARFE,
        )
    }

    /// Clear what the device flagged in its status registers, and remember it.
    ///
    /// Called when a footer said extended status is pending. `STATUS0` and
    /// `STATUS1` are cleared by writing back what was read; the `STATUS0` bits are
    /// kept for [`take_events`](Self::take_events), because a reset reported there
    /// needs a chip's own reconfiguration, which only the chip crate knows.
    pub fn clear_extended_status(&mut self) -> Result<(), Error<S::Error>> {
        let status0 = self.reg_read(std_reg::STATUS0)?;
        if status0 != 0 {
            self.reg_write(std_reg::STATUS0, status0)?;
            self.events |= status0;
        }
        let status1 = self.reg_read(std_reg::STATUS1)?;
        if status1 != 0 {
            self.reg_write(std_reg::STATUS1, status1)?;
        }
        self.status.extended = false;
        Ok(())
    }

    /// The `STATUS0` bits cleared since the last call.
    pub fn take_events(&mut self) -> u32 {
        core::mem::take(&mut self.events)
    }

    // ---- data chunk exchanges -------------------------------------------------

    /// One data chunk exchange: send `header` and `tx` (zero padded to a chunk),
    /// take back the chunk payload and the footer.
    fn exchange(
        &mut self,
        header: DataHeader,
        tx: &[u8],
        rx_payload: &mut [u8; CPS_MAX],
    ) -> Result<Footer, Error<S::Error>> {
        let cps = self.cps;
        let mut out = [0u8; WORD + CPS_MAX];
        let mut back = [0u8; WORD + CPS_MAX];
        out[..WORD].copy_from_slice(&header.word().to_be_bytes());
        out[WORD..WORD + tx.len()].copy_from_slice(tx);
        self.spi
            .transfer(&out[..WORD + cps], &mut back[..WORD + cps])
            .map_err(Error::Spi)?;
        // The device answers with the receive payload first and the footer last.
        rx_payload[..cps].copy_from_slice(&back[..cps]);
        let footer = Footer(u32::from_be_bytes([
            back[cps],
            back[cps + 1],
            back[cps + 2],
            back[cps + 3],
        ]));
        if !footer.parity_ok() {
            return Err(Error::FooterParity);
        }
        if footer.header_bad() {
            return Err(Error::HeaderRejected);
        }
        self.status = Status {
            extended: footer.extended_status(),
            rca: footer.receive_chunks_available(),
            txc: footer.transmit_credits(),
        };
        if !footer.synced() {
            return Err(Error::NotSynced);
        }
        Ok(footer)
    }

    /// An exchange that only reads the footer: how many receive chunks wait and how
    /// many transmit chunks the device can take.
    pub fn read_status(&mut self) -> Result<Footer, Error<S::Error>> {
        let mut sink = [0u8; CPS_MAX];
        self.exchange(DataHeader::STATUS, &[], &mut sink)
    }

    /// Send one Ethernet frame (no FCS). `Ok(false)` when the device does not
    /// have the transmit credits for all its chunks: nothing was sent, and the
    /// caller may try again.
    pub fn send_frame(&mut self, frame: &[u8]) -> Result<bool, Error<S::Error>> {
        if frame.is_empty() || frame.len() > RX_FRAME_MAX {
            return Ok(false);
        }
        let cps = self.cps;
        let chunks = frame.len().div_ceil(cps);
        if chunks > usize::from(self.status.txc) {
            // The credits last seen may be old: ask once before refusing.
            self.read_status()?;
            if chunks > usize::from(self.status.txc) {
                return Ok(false);
            }
        }
        let mut sink = [0u8; CPS_MAX];
        for (i, payload) in frame.chunks(cps).enumerate() {
            let last = i + 1 == chunks;
            let header = DataHeader {
                data_valid: true,
                no_receive: true,
                start_valid: i == 0,
                end_valid: last,
                end_byte_offset: if last { (payload.len() - 1) as u8 } else { 0 },
            };
            self.exchange(header, payload, &mut sink)?;
        }
        if self.status.extended {
            self.clear_extended_status()?;
        }
        Ok(true)
    }

    /// Take the next received frame (no FCS) into `out`: its length, or `None`
    /// when no whole frame is waiting. A frame longer than `out`, one the device
    /// marked for dropping, and one beyond [`RX_FRAME_MAX`] are dropped whole.
    pub fn receive_frame(&mut self, out: &mut [u8]) -> Result<Option<usize>, Error<S::Error>> {
        let cps = self.cps;
        for _ in 0..MAX_CHUNKS_PER_RECEIVE {
            if self.status.rca == 0 {
                if let Some(probe) = self.interrupt {
                    if !probe() {
                        return Ok(None);
                    }
                }
                self.read_status()?;
                if self.status.extended {
                    self.clear_extended_status()?;
                }
                if self.status.rca == 0 {
                    return Ok(None);
                }
            }
            let mut payload = [0u8; CPS_MAX];
            let footer = self.exchange(DataHeader::RECEIVE, &[], &mut payload)?;
            if !footer.data_valid() {
                continue;
            }
            if footer.start_valid() {
                // ZARFE: a frame starts on a chunk boundary. One that does not is
                // not a frame this receive path can place.
                self.assembly.len = 0;
                self.assembly.open = footer.start_word_offset() == 0;
                self.assembly.overflow = !self.assembly.open;
            }
            if !self.assembly.open && !self.assembly.overflow {
                // A chunk of a frame whose start was never seen.
                continue;
            }
            let valid = if footer.end_valid() {
                usize::from(footer.end_byte_offset()) + 1
            } else {
                cps
            }
            .min(cps);
            if self.assembly.len + valid > RX_FRAME_MAX {
                self.assembly.overflow = true;
            }
            if !self.assembly.overflow {
                let at = self.assembly.len;
                self.assembly.bytes[at..at + valid].copy_from_slice(&payload[..valid]);
                self.assembly.len += valid;
            }
            if footer.end_valid() {
                self.assembly.open = false;
                let kept = !footer.frame_drop()
                    && !self.assembly.overflow
                    && self.assembly.len > 0
                    && self.assembly.len <= out.len();
                let len = self.assembly.len;
                self.assembly.len = 0;
                self.assembly.overflow = false;
                if kept {
                    out[..len].copy_from_slice(&self.assembly.bytes[..len]);
                    return Ok(Some(len));
                }
            }
        }
        Ok(None)
    }
}

/// A TC6 MAC-PHY as an [`EthernetMac`]: the interface, once a chip crate has
/// configured the device, and the station address it programmed.
pub struct Tc6Mac<S: SpiTransfer> {
    tc6: Tc6<S>,
    mac: [u8; 6],
    errors: u32,
}

impl<S: SpiTransfer> Tc6Mac<S> {
    /// Wrap a configured interface. `mac` is the address the chip crate wrote to
    /// the device's address registers, which this type only reports.
    pub fn new(tc6: Tc6<S>, mac: [u8; 6]) -> Self {
        Self {
            tc6,
            mac,
            errors: 0,
        }
    }

    /// The interface, for the chip crate's housekeeping.
    pub fn tc6_mut(&mut self) -> &mut Tc6<S> {
        &mut self.tc6
    }

    /// How many SPI-level or protocol failures the MAC absorbed. A frame lost to
    /// one is a lost frame to the stack above; this counts the cause.
    pub fn errors(&self) -> u32 {
        self.errors
    }
}

impl<S: SpiTransfer> EthernetMac for Tc6Mac<S> {
    fn mac_address(&self) -> [u8; 6] {
        self.mac
    }

    fn transmit(&mut self, frame: &[u8]) -> bool {
        match self.tc6.send_frame(frame) {
            Ok(sent) => sent,
            Err(_) => {
                self.errors = self.errors.wrapping_add(1);
                false
            }
        }
    }

    fn receive(&mut self, buf: &mut [u8]) -> Option<usize> {
        match self.tc6.receive_frame(buf) {
            Ok(got) => got,
            Err(_) => {
                self.errors = self.errors.wrapping_add(1);
                None
            }
        }
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;
