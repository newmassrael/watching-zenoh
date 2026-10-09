// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A [`Lan865xMac`] that keeps its own housekeeping: the cadence of
//! [`Lan865xMac::service`], the time sources it needs, and what is worth telling
//! the board.
//!
//! A firmware loop calls its MAC's housekeeping on every pass, and a pass is a
//! millisecond or less. [`Lan865xMac::service`] is one footer exchange and, with
//! PLCA on, one control read, so called on every pass it would spend most of the
//! bus on asking whether anything changed, and, if its failures were logged as they
//! came, most of the console too. Its cadence is therefore the caller's choice, and
//! so is what to do with a result that is the same as the last one. This wrapper
//! makes both choices once, so that each board does not remake them:
//!
//! * [`PacedMac::service`] does nothing until `interval_ms` has passed since it
//!   last ran;
//! * it answers with a [`ServiceEvent`] that is [`Quiet`](ServiceEvent::Quiet)
//!   unless something changed: the part was reset, a status flag was raised, the
//!   PLCA state moved, or the housekeeping began failing or stopped failing. A bus
//!   that stays broken is reported once, not once per interval.
//!
//! The delay and the clock are stored, because [`Lan865xMac::service`] needs them
//! when it finds the part reset and runs the bring-up again.

use crate::{open, Config, Lan865xMac, OpenError, ServiceReport};
use wz_runtime_core::{EthernetMac, SpiTransfer};

/// What one [`PacedMac::service`] call has to tell the board.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceEvent<E> {
    /// Nothing to say: the interval has not passed, or the housekeeping ran and
    /// found the part as it was, or it is still failing as it was.
    Quiet,
    /// The housekeeping ran and the part had changed: it was reset and configured
    /// again, or a status flag was raised, or PLCA moved.
    Report(ServiceReport),
    /// The housekeeping failed, and the call before it did not. The failures that
    /// follow are counted ([`PacedMac::failures`]) and not reported again until
    /// one succeeds.
    Failed(OpenError<E>),
    /// The housekeeping succeeded after one or more failures. Carries what that
    /// call found, which is the whole of it: the failures before were reported.
    Recovered(ServiceReport),
}

/// A [`Lan865xMac`] with its housekeeping paced and its results reduced to
/// changes. See the module documentation.
pub struct PacedMac<S: SpiTransfer, D, N> {
    mac: Lan865xMac<S>,
    delay_us: D,
    now_us: N,
    interval_ms: u64,
    /// The time, in milliseconds on `now_us`'s clock, before which `service` does
    /// nothing. Zero at the start: the first call runs.
    next_due_ms: u64,
    /// The last housekeeping that ran failed.
    failing: bool,
    failures: u32,
}

impl<S, D, N> PacedMac<S, D, N>
where
    S: SpiTransfer,
    D: FnMut(u32),
    N: FnMut() -> u64,
{
    /// [`open`] the part, then keep its housekeeping every `interval_ms`
    /// milliseconds of `now_us`'s clock. An interval of zero runs it on every
    /// call.
    ///
    /// `delay_us` and `now_us` are as for [`open`] and are kept for the bring-ups
    /// that [`service`](Self::service) may owe later.
    pub fn open(
        spi: S,
        config: &Config,
        mut delay_us: D,
        mut now_us: N,
        interval_ms: u32,
    ) -> Result<Self, OpenError<S::Error>> {
        let mac = open(spi, config, &mut delay_us, &mut now_us)?;
        Ok(Self {
            mac,
            delay_us,
            now_us,
            interval_ms: u64::from(interval_ms),
            next_due_ms: 0,
            failing: false,
            failures: 0,
        })
    }

    /// Run the housekeeping if it is due, and say what changed.
    ///
    /// A call that runs it always schedules the next one a whole interval later,
    /// failed or not: a part that does not answer is asked again at the same
    /// cadence, not harder.
    pub fn service(&mut self) -> ServiceEvent<S::Error> {
        let now_ms = (self.now_us)() / 1000;
        if now_ms < self.next_due_ms {
            return ServiceEvent::Quiet;
        }
        self.next_due_ms = now_ms + self.interval_ms;
        match self.mac.service(&mut self.delay_us, &mut self.now_us) {
            Ok(report) => {
                let was_failing = core::mem::take(&mut self.failing);
                if was_failing {
                    ServiceEvent::Recovered(report)
                } else if report.reconfigured || report.status0 != 0 || report.phy_status != 0 {
                    ServiceEvent::Report(report)
                } else {
                    ServiceEvent::Quiet
                }
            }
            Err(error) => {
                self.failures = self.failures.saturating_add(1);
                if core::mem::replace(&mut self.failing, true) {
                    ServiceEvent::Quiet
                } else {
                    ServiceEvent::Failed(error)
                }
            }
        }
    }

    /// How many housekeeping runs have failed so far, reported or not.
    pub fn failures(&self) -> u32 {
        self.failures
    }

    /// The part found on the bus by the last bring-up.
    pub fn identity(&self) -> crate::Identity {
        self.mac.identity()
    }

    /// How many SPI-level or protocol failures the MAC absorbed so far; see
    /// [`Lan865xMac::errors`].
    pub fn errors(&self) -> u32 {
        self.mac.errors()
    }

    /// Give the interface the level of `IRQ_N`; see
    /// [`Lan865xMac::set_interrupt_probe`].
    pub fn set_interrupt_probe(&mut self, probe: fn() -> bool) {
        self.mac.set_interrupt_probe(probe);
    }

    /// The MAC, for a test that looks at the part behind it.
    #[cfg(test)]
    pub(crate) fn mac_mut(&mut self) -> &mut Lan865xMac<S> {
        &mut self.mac
    }
}

impl<S, D, N> EthernetMac for PacedMac<S, D, N>
where
    S: SpiTransfer,
    D: FnMut(u32),
    N: FnMut() -> u64,
{
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
