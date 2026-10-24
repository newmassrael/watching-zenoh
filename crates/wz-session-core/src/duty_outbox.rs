// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The duties a generated machine's action bodies recorded and its host has not
//! yet performed, one bit per duty.
//!
//! An engine-free statechart states its effects as `<sce:action effect="duty">`
//! host calls. The bodies only record which duty ran; the host performs each
//! right after the event that ran it, so a machine's behaviour is a pure
//! function of the events it is given and a host test reads what it was asked
//! to do. Shared by every machine that works this way: the multicast peer and
//! session machines and the per-peer connection machine (decision D5 of
//! `docs/session-lifecycle-intent.md`).

use core::sync::atomic::{AtomicU8, Ordering};

/// The recorded duties.
///
/// A body writes it through `&mut self`; the host reads it through the shared
/// reference the generated policy lends (`actions()`), so the byte is atomic.
/// Taken as a load then a store rather than a swap: a Cortex-M0 has no
/// compare-and-swap, and nothing runs between the two, since the machine and
/// the host that drives it are one thread.
#[derive(Default)]
pub struct DutyOutbox(AtomicU8);

impl DutyOutbox {
    /// Record `duty` (one bit).
    pub fn record(&mut self, duty: u8) {
        *self.0.get_mut() |= duty;
    }

    /// The duties recorded since the last take, cleared.
    pub fn take(&self) -> Duties {
        let recorded = self.0.load(Ordering::Relaxed);
        self.0.store(0, Ordering::Relaxed);
        Duties(recorded)
    }
}

/// What one [`DutyOutbox::take`] found. The default is no duty.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Duties(u8);

impl Duties {
    /// Whether `duty` was recorded.
    pub fn has(self, duty: u8) -> bool {
        self.0 & duty != 0
    }

    /// Whether no duty was recorded.
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
}
