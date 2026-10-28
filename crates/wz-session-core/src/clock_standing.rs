// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! How far a node may trust its clock: the [`clock_quality`](crate::clock_quality) machine and
//! the host that drives it (`docs/observation-plane.md` M1).
//!
//! A clock port ([`EpochSource`](crate::epoch::EpochSource)) says what time it is. This says how
//! much that is worth, and it is told by the host, which is the only party that knows: a time
//! daemon's state, a satellite lock, a fieldbus master. The host raises
//! [`sync_acquired`](ClockStanding::sync_acquired) and [`sync_lost`](ClockStanding::sync_lost),
//! and, for a clock it registered, [`holdover_expired`](ClockStanding::holdover_expired) when its
//! own bound on running without a reference has passed. This machine holds no timer and reads no
//! clock, so what it does is a function of the events it was given.
//!
//! Every call returns whether the standing changed, and the number of changes is counted: a clock
//! that flaps between synchronised and not is the thing an operator looks for, and a count of it
//! costs one word.

use sce_rust_runtime::Engine;

use crate::clock_quality::{
    ClockQualityActions, ClockQualityEvent, ClockQualityPolicy, ClockQualityState,
};
use crate::constant_session_id::built_under_constant_id;
use crate::duty_outbox::DutyOutbox;

/// The id the machine is built under (SCE ADR 0045: the host gives a machine its id). A
/// constant, so the generated constructor never refuses it.
const CLOCK_QUALITY_SESSION_ID: &str = "wz-clock-quality";

#[derive(Default)]
struct QualityBinding {
    duties: DutyOutbox,
}

impl QualityBinding {
    const CHANGED: u8 = 1 << 0;
}

impl ClockQualityActions for QualityBinding {
    const REALIZATION: ::sce_rust_runtime::ActionRealization =
        ::sce_rust_runtime::ActionRealization::Performs;

    fn quality_changed(&mut self) {
        self.duties.record(Self::CHANGED);
    }
}

/// The standing of a node's clock, and the machine that moves it.
pub struct ClockStanding {
    engine: Engine<ClockQualityPolicy<QualityBinding>>,
    changes: u32,
}

impl Default for ClockStanding {
    fn default() -> Self {
        Self::new()
    }
}

impl ClockStanding {
    /// A clock no reference has been acquired for: `Unsynchronized`.
    pub fn new() -> Self {
        let mut engine = Engine::new(built_under_constant_id(
            ClockQualityPolicy::new_with_session_id(
                CLOCK_QUALITY_SESSION_ID,
                QualityBinding::default(),
            ),
            "the clock quality session id",
        ));
        // W3C SCXML 3.3: enter the initial `Unsynchronized` leaf. Entering it is the start, not a
        // change, so the duty it recorded is dropped.
        engine.initialize();
        let _ = engine.policy().actions().duties.take();
        Self { engine, changes: 0 }
    }

    /// The standing now.
    pub fn state(&self) -> ClockQualityState {
        self.engine.get_current_state()
    }

    /// Whether a stamp made now is made from a clock the node trusts: one that follows a
    /// reference, or that did a moment ago and is still within the host's holdover bound.
    pub fn is_trusted(&self) -> bool {
        match self.state() {
            ClockQualityState::Synchronized => true,
            #[cfg(feature = "clock-source")]
            ClockQualityState::Holdover => true,
            _ => false,
        }
    }

    /// How many times the standing has changed since the node started.
    pub fn changes(&self) -> u32 {
        self.changes
    }

    /// A reference is acquired, for the first time or after a loss.
    pub fn sync_acquired(&mut self) -> bool {
        self.drive(ClockQualityEvent::SyncAcquired)
    }

    /// The reference is gone. With `clock-source` the clock is held over; without it the clock is
    /// `Unsynchronized` again.
    pub fn sync_lost(&mut self) -> bool {
        self.drive(ClockQualityEvent::SyncLost)
    }

    /// The host's holdover bound passed with no reference back.
    #[cfg(feature = "clock-source")]
    pub fn holdover_expired(&mut self) -> bool {
        self.drive(ClockQualityEvent::HoldoverExpired)
    }

    /// Give the machine `event`; whether it moved the standing.
    fn drive(&mut self, event: ClockQualityEvent) -> bool {
        self.engine.process_event(event);
        let changed = self
            .engine
            .policy()
            .actions()
            .duties
            .take()
            .has(QualityBinding::CHANGED);
        if changed {
            self.changes = self.changes.saturating_add(1);
        }
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_clock_is_unsynchronized_untrusted_and_has_not_changed() {
        let standing = ClockStanding::new();
        assert_eq!(standing.state(), ClockQualityState::Unsynchronized);
        assert!(!standing.is_trusted());
        assert_eq!(standing.changes(), 0);
    }

    #[test]
    fn acquiring_a_reference_makes_the_clock_trusted_once() {
        let mut standing = ClockStanding::new();
        assert!(standing.sync_acquired());
        assert_eq!(standing.state(), ClockQualityState::Synchronized);
        assert!(standing.is_trusted());
        // Already synchronised: nothing moves, and nothing is counted.
        assert!(!standing.sync_acquired());
        assert_eq!(standing.changes(), 1);
    }

    #[test]
    fn a_loss_with_no_reference_held_changes_nothing() {
        let mut standing = ClockStanding::new();
        assert!(!standing.sync_lost());
        assert_eq!(standing.state(), ClockQualityState::Unsynchronized);
        assert_eq!(standing.changes(), 0);
    }

    #[cfg(not(feature = "clock-source"))]
    #[test]
    fn without_a_registered_clock_a_lost_reference_is_unsynchronized_again() {
        let mut standing = ClockStanding::new();
        standing.sync_acquired();
        assert!(standing.sync_lost());
        assert_eq!(standing.state(), ClockQualityState::Unsynchronized);
        assert!(!standing.is_trusted());
        assert_eq!(standing.changes(), 2);
    }

    #[cfg(feature = "clock-source")]
    #[test]
    fn a_registered_clock_is_held_over_then_free_running_and_trusted_only_while_held_over() {
        let mut standing = ClockStanding::new();
        standing.sync_acquired();

        assert!(standing.sync_lost());
        assert_eq!(standing.state(), ClockQualityState::Holdover);
        assert!(standing.is_trusted());

        assert!(standing.holdover_expired());
        assert_eq!(standing.state(), ClockQualityState::FreeRunning);
        assert!(!standing.is_trusted());

        // A free-running clock does not go back to holdover on another loss.
        assert!(!standing.sync_lost());
        assert_eq!(standing.state(), ClockQualityState::FreeRunning);

        assert!(standing.sync_acquired());
        assert_eq!(standing.state(), ClockQualityState::Synchronized);
        assert_eq!(standing.changes(), 4);
    }

    #[cfg(feature = "clock-source")]
    #[test]
    fn a_reference_back_inside_the_holdover_bound_ends_the_holdover() {
        let mut standing = ClockStanding::new();
        standing.sync_acquired();
        standing.sync_lost();
        assert!(standing.sync_acquired());
        assert_eq!(standing.state(), ClockQualityState::Synchronized);
        // The bound passing later is nothing to a clock that is synchronised again.
        assert!(!standing.holdover_expired());
        assert_eq!(standing.state(), ClockQualityState::Synchronized);
    }
}
