// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

#![no_std]

//! The Microchip LAN8650 / LAN8651 10BASE-T1S MAC-PHY, as a
//! [`wz_runtime_core::EthernetMac`] over a [`wz_runtime_core::SpiTransfer`].
//!
//! The protocol on the SPI wire is the OPEN Alliance TC6 interface, which
//! `wz-oa-tc6` owns for every chip that speaks it. This crate is what is specific
//! to this chip family, and it leaves to the board what only a board knows:
//!
//! * [`identify`]: which part is on the bus, from `DEVID` (the standard `OA_PHYID`
//!   cannot say; errata item s1);
//! * [`open`]: reset the part, run the vendor's configuration sequence, set up
//!   PLCA, program the MAC address and filters, and declare the configuration
//!   done;
//! * [`Lan865xMac::service`]: the housekeeping after that, which keeps collision
//!   detection in step with PLCA and notices that the part was reset, in which
//!   case it runs the whole sequence again.
//!
//! ## The bring-up, in order
//!
//! 1. The config is checked ([`Config::validate`]) before any bus traffic.
//! 2. `DEVID` is read and the part identified, BEFORE anything is written, so a
//!    wrong or absent part is refused with the bus untouched. A part newer than
//!    the documents grade is refused unless the config accepts it.
//! 3. Any `RESETC` left from power-on is cleared, then the part is soft-reset
//!    (`Tc6::soft_reset`). The clear matters: power-on sets `RESETC` (DS60001734F
//!    4.1.1.1) and the bit is write-one-to-clear (11.1.6), so it stays set until
//!    the host clears it, and without the clear the wait for the reset's own
//!    `RESETC` would be satisfied by the old one.
//! 4. The vendor's configuration (AN1760, DS60001760G): two indirect reads for the
//!    part's trim offsets, the two parameters computed from them, and the table of
//!    register writes, in the document's order. The note requires this after
//!    every reset and in that order.
//! 5. PLCA (AN1760, "Enabling PLCA"): the coordinator count or follower ID, the
//!    enable bit, then collision detection switched off by read-modify-write.
//!    Nothing is written for [`Plca::Off`]: the part resets to CSMA/CD.
//! 6. The MAC: the receive-FCS removal bit (the part's default hands the host a
//!    frame with its FCS, DS60001734F 5.2 and 5.2.3, while an `EthernetMac` frame
//!    carries none; transmit needs nothing, the MAC pads and appends the FCS),
//!    the optional accept-all-multicast hash, and the station address, bottom
//!    half then top half, because the top half's write is what activates the
//!    address (DS60001734F 11.2.5, 11.2.6, 6.5.1.2).
//! 7. The MAC's transmitter and receiver are enabled, and only then
//!    `CONFIG0.SYNC` is set (`Tc6::enable_sync`): DS60001734F 6.5.1.4 and 6.5.1.5
//!    put the enable first, and frames are ignored while `SYNC` is clear.
//!
//! ## What the board owns
//!
//! * The reset line (`RESET_N`). It is optional: the part resets itself on power
//!   and [`open`] soft-resets it anyway, and an unused pin is tied to the supply
//!   (DS60001734F 4.1.1.2). If the board drives it, it must hold it low at least
//!   5 µs (DS60001734F Table 9-8, `trstia`) before `open`. The data sheet gives NO
//!   time from the end of reset, or from the supplies being valid, until the SPI
//!   port answers: that entry of its wake-up timing table (Table 9-14, `tpo_spi`)
//!   has no value. The board waits as long as its own measurement says; a part
//!   that is not answering shows as a bus error or an unknown model from `open`,
//!   not as a hang.
//! * The interrupt line (`IRQ_N`), if it is wired: hand its level to
//!   [`Lan865xMac::set_interrupt_probe`]. Nothing here depends on it.
//! * The SPI master, its mode and clock, and the monotonic clock and delay that
//!   `open` and `service` take as closures.
//!
//! ## After a reset
//!
//! A reset clears the part's configuration, and the part is useless until it is
//! configured again. [`Lan865xMac::service`] notices two kinds and, for either,
//! runs the whole bring-up again, identity check included. This is the "re-open
//! behaviour"; it needs the delay and clock, so they are arguments of `service`
//! and not state.
//!
//! * The footer loses `SYNC`. A reset clears `OA_CONFIG0.SYNC`, which every
//!   footer reports (DS60001734F Figure 4-1), and every data exchange then fails
//!   with `Error::NotSynced`: `transmit` and `receive` fail and are counted
//!   ([`Lan865xMac::errors`]) until `service` has run, and `service` sees the same
//!   error on its own footer exchange. `Tc6::take_events` cannot carry this
//!   news, because the exchange fails before the status registers are read.
//! * `RESETC` is reported. A reset of the PHY alone (`BASIC_CONTROL.SW_RESET`)
//!   resets "only the internal PHY, not the entire device", and the data sheet says
//!   to reset the entire device when the host sees `RESETC` after one
//!   (DS60001734F 4.1.1.3). The data sheet is not consistent about whether that
//!   reset also clears `SYNC` (its Figure 4-1 lists it among the sources that do),
//!   so both signals are read: if `SYNC` stays set the exchanges succeed, the
//!   PHY's vendor configuration is gone, and `RESETC` is the only sign. `service`
//!   clears the status the footer announces and reads `Tc6::take_events`, which
//!   includes what the transmit and receive paths collected.
//!
//! Once a reset is seen the bring-up is owed until it succeeds, so a failure
//! part-way (or before the part's first write) is retried by the next call.
//!
//! `service` also polls the PHY's Status 1 register when PLCA is on. The PHY's
//! interrupts are masked after a reset (DS60001734F 7.1) and this crate leaves
//! them masked: unmasking one would raise `PHYINT` and with it the footer's
//! extended-status flag until Status 1 is read, so the flag would be paid for on
//! every exchange of a host that serviced late. The cost of the poll is one
//! control transaction per call; the caller sets the cadence.
//!
//! ## Errata taken into account (DS80001075F)
//!
//! * s1, the product cannot be told from `OA_PHYID`: [`identify`] reads `DEVID`.
//! * s3 (B0 only), a receive transfer can halt when a frame starts in the same
//!   chunk in which the previous one ends: `Tc6::enable_sync` selects ZARFE, in
//!   which a frame starts at the first word of a chunk (DS60001734F, `OA_CONFIG0`
//!   `RFA`), so that cannot happen. This is read off the register's definition,
//!   not observed.
//! * s4 (both revisions), transmission can halt after excessive collisions when
//!   the host puts the end of one frame and the start of the next in one chunk:
//!   `Tc6::send_frame` never does, every frame starts a chunk of its own.
//! * s5, a coordinator that hears another coordinator's BEACON stops transmitting:
//!   the work-around is the station management's. `service` returns the Status 1
//!   bits it read ([`regs::sts1::UNEXPB`]) so that it can act; this crate does not
//!   choose a follower ID on the board's behalf.
//! * s6 and s8 concern `SLPCTL0` and `PLCA_TOTMR`, neither of which is written.
//!
//! Not done, on purpose: the optional SQI configuration, burst mode, sleep and
//! wake, timestamping, cut-through, control-data protection and configuration
//! protection. A host that wants one adds it over `Tc6`.
//!
//! ## What is claimed
//!
//! BUILT. No emulator models this chip, and the crate has never run on one. The
//! host tests drive it against a register-level model written from the data sheet
//! (DS60001734F), the configuration note (AN1760, DS60001760G) and the errata
//! sheet (DS80001075F): they check the order and values of the register accesses
//! and the behaviour the documents describe, not the chip. What the documents do
//! not state (how long a reset takes, the SPI-valid time) is not modelled and is
//! named above.
//!
//! ## Provenance
//!
//! Written from the three vendor documents above; no code was copied.

mod an1760;
mod config;
mod identity;
pub mod regs;

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod model;
#[cfg(test)]
mod tests;

pub use config::{Config, ConfigError, Plca};
pub use identity::{identify, Identity, IdentityError, Product, Revision};

use regs::{
    CDCTL0, CDCTL0_CDEN, DEVID, MAC_HRB, MAC_HRT, MAC_NCFGR, MAC_NCR, MAC_SAB1, MAC_SAT1,
    NCFGR_MTIHEN, NCFGR_RFCS, NCR_RXEN, NCR_TXEN, PLCA_CTRL0, PLCA_CTRL0_EN, PLCA_CTRL1, PLCA_STS,
    PLCA_STS_PST, STS1,
};
use wz_oa_tc6::proto::std_reg;
use wz_oa_tc6::{ChunkSize, Error, Tc6, Tc6Mac};
use wz_runtime_core::{EthernetMac, SpiTransfer};

/// How long a soft reset may take before it is called failed.
///
/// No document states it: the data sheet describes the software reset
/// (DS60001734F 4.1.1.3, `OA_RESET`) without a duration, and the one SPI timing
/// entry that would bound a start-up, `tpo_spi` in Table 9-14, is empty. So this is
/// not a vendor figure. It is a bound on a dead bus, long enough that a part
/// which is merely slow is not failed (the wait polls every millisecond and ends
/// as soon as the part answers) and short enough that a part that never answers
/// is reported within a tenth of a second. Replace it with a measurement when
/// there is one.
const RESET_BUDGET_MS: u32 = 100;

/// Why [`open`] or [`Lan865xMac::service`] failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenError<E> {
    /// The config was refused; no bus traffic took place.
    Config(ConfigError),
    /// `DEVID` is not a LAN8650 or LAN8651. Nothing was written.
    Identity(IdentityError),
    /// The part is a recognised product at a revision newer than the documents
    /// grade, and the config does not accept those. Nothing was written.
    RevisionNotAccepted(Identity),
    /// The TC6 interface failed, which includes an SPI error and a reset that did
    /// not report completion.
    Bus(Error<E>),
}

impl<E> From<ConfigError> for OpenError<E> {
    fn from(error: ConfigError) -> Self {
        Self::Config(error)
    }
}

impl<E> From<IdentityError> for OpenError<E> {
    fn from(error: IdentityError) -> Self {
        Self::Identity(error)
    }
}

impl<E> From<Error<E>> for OpenError<E> {
    fn from(error: Error<E>) -> Self {
        Self::Bus(error)
    }
}

/// What one [`Lan865xMac::service`] call found and did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ServiceReport {
    /// The part had been reset and the whole bring-up ran again.
    pub reconfigured: bool,
    /// The `OA_STATUS0` bits cleared since the last call (`Tc6::take_events`),
    /// which is where the transmit-protocol, buffer-overflow and header errors
    /// show. `RESETC` is among them when a reset was found that way.
    pub status0: u32,
    /// The PHY Status 1 flags this call read, and with the read cleared (see
    /// [`regs::sts1`]). Zero when PLCA is off, where the register is not read.
    pub phy_status: u16,
}

/// Run the bring-up on a reset-state or unconfigured part. See the crate
/// documentation for the order and its reasons.
///
/// It is the same code for the first open and for a re-open after a reset, and it
/// always starts by resetting, so a failure part-way leaves a part whose
/// `CONFIG0.SYNC` is clear, which the next `service` call finds and retries.
fn configure<S: SpiTransfer>(
    tc6: &mut Tc6<S>,
    config: &Config,
    delay_us: impl FnMut(u32),
    now_us: impl FnMut() -> u64,
) -> Result<Identity, OpenError<S::Error>> {
    let identity = identify(tc6.reg_read(DEVID)?)?;
    if matches!(identity.revision, Revision::Newer(_)) && !config.accept_newer_revisions {
        return Err(OpenError::RevisionNotAccepted(identity));
    }

    // Write one to clear: the power-on RESETC is not the reset's.
    tc6.reg_write(std_reg::STATUS0, std_reg::STATUS0_RESETC)?;
    tc6.soft_reset(delay_us, now_us, RESET_BUDGET_MS)?;

    an1760::apply(tc6)?;
    configure_plca(tc6, config.plca)?;
    configure_mac(tc6, config)?;

    tc6.reg_write(MAC_NCR, NCR_TXEN | NCR_RXEN)?;
    tc6.enable_sync()?;
    Ok(identity)
}

/// AN1760 Table 3: PLCA_CTRL1, PLCA_CTRL0, then CDCTL0 with `CDEN` cleared. The
/// note's caution is to read-modify-write the last, "to avoid accidental
/// modifications to reserved fields".
fn configure_plca<S: SpiTransfer>(tc6: &mut Tc6<S>, plca: Plca) -> Result<(), Error<S::Error>> {
    let Some(param) = config::plca_ctrl1(plca) else {
        return Ok(());
    };
    tc6.reg_write(PLCA_CTRL1, u32::from(param))?;
    tc6.reg_write(PLCA_CTRL0, PLCA_CTRL0_EN)?;
    tc6.reg_modify(CDCTL0, CDCTL0_CDEN, 0)
}

/// The MAC's receive configuration and station address. The address pair goes
/// last and bottom first: writing the bottom half deactivates the address and
/// writing the top half activates it (DS60001734F 6.5.1.2).
fn configure_mac<S: SpiTransfer>(tc6: &mut Tc6<S>, config: &Config) -> Result<(), Error<S::Error>> {
    // `MAC_NCFGR` has a reserved bit whose reset value is 1, so it is modified.
    let mut ncfgr = NCFGR_RFCS;
    if config.accept_all_multicast {
        // "To receive all multicast frames, the Hash register should be set with
        // all ones and the Multicast Hash Enable bit should be set" (DS60001734F
        // 6.4.6).
        tc6.reg_write(MAC_HRB, 0xFFFF_FFFF)?;
        tc6.reg_write(MAC_HRT, 0xFFFF_FFFF)?;
        ncfgr |= NCFGR_MTIHEN;
    }
    tc6.reg_modify(MAC_NCFGR, NCFGR_RFCS | NCFGR_MTIHEN, ncfgr)?;

    let (bottom, top) = config::address_words(config.mac_address);
    tc6.reg_write(MAC_SAB1, bottom)?;
    tc6.reg_write(MAC_SAT1, top)
}

/// A LAN8650 or LAN8651, configured and running, as an [`EthernetMac`].
pub struct Lan865xMac<S: SpiTransfer> {
    mac: Tc6Mac<S>,
    identity: Identity,
    config: Config,
    /// Whether the collision-detect setting is known to match PLCA's state: it is
    /// not after a (re)configuration, which leaves collision detection off while
    /// PLCA has not yet come up, and not after a Status 1 read that saw the
    /// change but did not finish acting on it.
    plca_reconciled: bool,
    /// A reset was seen and the bring-up has not yet succeeded since.
    reconfigure_owed: bool,
}

/// Open the part: validate `config`, identify the part, reset it, configure it
/// and declare the configuration done. See the crate documentation for the
/// order.
///
/// `delay_us` waits at least the given number of microseconds and `now_us` is a
/// monotonic clock in microseconds; the reset's budget is measured on the clock,
/// not on the waits (see `Tc6::soft_reset`).
///
/// `spi` is consumed, and dropped with the error if `open` fails. A caller that
/// wants to retry builds the SPI master again, or checks the config first with
/// [`Config::validate`], which is the one failure that needs no bus.
pub fn open<S: SpiTransfer>(
    spi: S,
    config: &Config,
    delay_us: impl FnMut(u32),
    now_us: impl FnMut() -> u64,
) -> Result<Lan865xMac<S>, OpenError<S::Error>> {
    config.validate()?;
    // The part resets to 64-byte chunks (`OA_CONFIG0.BPS` resets to 0b110,
    // DS60001734F 11.1.5), and `configure` resets it before anything depends on
    // that.
    let mut tc6 = Tc6::new(spi, ChunkSize::B64);
    let identity = configure(&mut tc6, config, delay_us, now_us)?;
    Ok(Lan865xMac {
        mac: Tc6Mac::new(tc6, config.mac_address),
        identity,
        config: *config,
        plca_reconciled: false,
        reconfigure_owed: false,
    })
}

impl<S: SpiTransfer> Lan865xMac<S> {
    /// The part found on the bus by the last bring-up.
    pub fn identity(&self) -> Identity {
        self.identity
    }

    /// How many SPI-level or protocol failures the MAC absorbed so far; see
    /// `Tc6Mac::errors`.
    pub fn errors(&self) -> u32 {
        self.mac.errors()
    }

    /// Give the interface the level of `IRQ_N` (true while the part has something
    /// to say); see `Tc6::set_interrupt_probe`.
    pub fn set_interrupt_probe(&mut self, probe: fn() -> bool) {
        self.mac.tc6_mut().set_interrupt_probe(probe);
    }

    /// Housekeeping. Call it regularly; the cadence is the caller's.
    ///
    /// 1. One footer exchange, and the status it announces is cleared. A footer
    ///    without `SYNC`, or a `RESETC` among the status bits collected (here or
    ///    by `transmit` and `receive`), means the part was reset and holds no
    ///    configuration: the whole bring-up runs again (`delay_us` and `now_us`
    ///    are for that, as in [`open`]) and the report says so. If it fails the
    ///    next call tries again; the status bits of a call that failed are lost
    ///    with its error.
    /// 2. With PLCA on, one control read of Status 1. When it says the PLCA status
    ///    changed, and on the first call after any bring-up, PLCA's state is read
    ///    and collision detection set to match: off while PLCA is active, on
    ///    while it has fallen back to CSMA/CD (AN1760, "Managing Collision
    ///    Detection", Figure 1).
    ///
    /// The first-call reconcile goes beyond Figure 1, which acts on a change only.
    /// The bring-up turns collision detection off (AN1760 Table 3) while PLCA, off
    /// at reset, has not yet come up; if it never does there is no change to act
    /// on, and the node would run CSMA/CD with collision detection disabled.
    pub fn service(
        &mut self,
        delay_us: impl FnMut(u32),
        now_us: impl FnMut() -> u64,
    ) -> Result<ServiceReport, OpenError<S::Error>> {
        let mut report = ServiceReport::default();
        let tc6 = self.mac.tc6_mut();
        match tc6.read_status() {
            Ok(footer) => {
                if footer.extended_status() {
                    tc6.clear_extended_status()?;
                }
            }
            Err(Error::NotSynced) => self.reconfigure_owed = true,
            Err(other) => return Err(other.into()),
        }
        report.status0 = tc6.take_events();
        if report.status0 & std_reg::STATUS0_RESETC != 0 {
            self.reconfigure_owed = true;
        }
        if self.reconfigure_owed {
            self.identity = configure(tc6, &self.config, delay_us, now_us)?;
            self.reconfigure_owed = false;
            self.plca_reconciled = false;
            report.reconfigured = true;
        }
        if matches!(self.config.plca, Plca::Node { .. }) {
            report.phy_status = self.follow_plca()?;
        }
        Ok(report)
    }

    /// AN1760 Figure 1, plus the first-call reconcile described at
    /// [`service`](Self::service). Returns the Status 1 flags it read.
    fn follow_plca(&mut self) -> Result<u16, Error<S::Error>> {
        let tc6 = self.mac.tc6_mut();
        // Status 1 is read-to-clear, so the change has to be remembered before
        // anything below can fail: a failure after this read would otherwise lose
        // it for good.
        let sts1 = (tc6.reg_read(STS1)? & 0xFFFF) as u16;
        if sts1 & regs::sts1::PSTC != 0 {
            self.plca_reconciled = false;
        }
        if !self.plca_reconciled {
            let active = tc6.reg_read(PLCA_STS)? & PLCA_STS_PST != 0;
            let cden = if active { 0 } else { CDCTL0_CDEN };
            tc6.reg_modify(CDCTL0, CDCTL0_CDEN, cden)?;
            self.plca_reconciled = true;
        }
        Ok(sts1)
    }

    /// The part, with the interface borrowed for a test.
    #[cfg(test)]
    pub(crate) fn chip(&mut self) -> &mut S {
        self.mac.tc6_mut().spi_mut()
    }
}

impl<S: SpiTransfer> EthernetMac for Lan865xMac<S> {
    fn mac_address(&self) -> [u8; 6] {
        self.mac.mac_address()
    }

    fn transmit(&mut self, frame: &[u8]) -> bool {
        self.mac.transmit(frame)
    }

    fn receive(&mut self, buf: &mut [u8]) -> Option<usize> {
        self.mac.receive(buf)
    }
}
