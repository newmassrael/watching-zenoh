// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311il — host-owned handshake deadline config + comparator for the
//! engine-free unicast session FSM.
//!
//! The engine-free [`crate::session_fsm_unicast`] FSM is codegen'd
//! `--no-std` (`type Hal = NoOpHal`), so a W3C SCXML `<send delay>` would
//! be a dead element (NoOpHal's clock never advances). The FSM therefore
//! arms no self-timer; it owns the timeout TRANSITIONS only
//! (`link.open_timeout`, `init_ack.timeout`, `open_ack.timeout`,
//! `accepting.inactivity_timeout`, `closing.timeout`) and the host drive
//! loop owns the CLOCK, raising each event when its deadline elapses.
//! Mirrors the scouting drive loop's deadline measurement and the
//! reassembly dispatcher's deadline-sweep split: value = spec,
//! transition = statechart, clock = runtime.
//!
//! This module is the runtime-agnostic half — the spec-sourced deadline
//! VALUES ([`SessionTimeouts`]) plus the pure state -> deadline mapping
//! ([`handshake_deadline_for`]) — so the MCU drive loop reuses it exactly
//! as the AP `drive_session_until_terminal` does (the sibling of
//! [`crate::lease::LeaseCheckOutcome`] for the Established lease deadline).
//! The clock source + the `select!` race live in the runtime-specific
//! drive loop.

use crate::session_fsm_unicast::{SessionFsmUnicastEvent, SessionFsmUnicastState};

/// Host-owned handshake deadline values (docs/session-fsm.md §2.5).
///
/// NOT wire-encoded — unlike [`crate::session_init_params::SessionInitParams::lease`]
/// (the Established lease, which travels VLE-encoded in the OPEN body),
/// these are local timing config the host drive loop consults to raise
/// the FSM's handshake-timeout transitions. Carried host-side so SSOT is
/// preserved: the value is spec-sourced, the transition lives in the
/// statechart, and the clock lives in the runtime.
#[derive(Debug, Clone, Copy)]
pub struct SessionTimeouts {
    /// `LinkOpening` -> `link.open_timeout` window (§2.5: 5s).
    pub link_open_ms: u64,
    /// `SentInitSyn` -> `init_ack.timeout` window (§2.5: 2s).
    pub init_ack_ms: u64,
    /// `GotInitAck` -> `open_ack.timeout` window (§2.5: 2s).
    pub open_ack_ms: u64,
    /// `Accepting` whole-handshake -> `accepting.inactivity_timeout`
    /// window (§2.5: 1s). A single bound armed once on accept entry, NOT
    /// reset as the Accepting children advance.
    pub accepting_inactivity_ms: u64,
    /// `Closing` -> `closing.timeout` window (§2.5: 100ms).
    pub closing_ms: u64,
}

impl SessionTimeouts {
    /// The docs/session-fsm.md §2.5 reference values (link.open 5s,
    /// init_ack 2s, open_ack 2s, accepting.inactivity 1s, closing 100ms).
    ///
    /// A named constructor rather than a `Default` impl so a caller
    /// cannot zero-fill the deadlines silently (mirrors
    /// [`crate::session_init_params::SessionInitParams`]'s deliberate
    /// no-`Default` policy — a zero deadline would fire every timeout
    /// immediately). Production callers source per-deploy overrides from
    /// `deploy.yaml`; this is the spec baseline.
    pub const fn spec_defaults() -> Self {
        Self {
            link_open_ms: 5_000,
            init_ack_ms: 2_000,
            open_ack_ms: 2_000,
            accepting_inactivity_ms: 1_000,
            closing_ms: 100,
        }
    }
}

/// One armed handshake deadline: the state whose entry arms it (the
/// re-arm key), the spec-sourced window, and the event the host raises
/// when it elapses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeDeadline {
    /// The state keyed for re-arm. The three `Accepting` children
    /// (`AwaitingInitSyn` / `SentInitAck` / `SentOpenAck`) all map to the
    /// parent `Accepting` key so the whole-handshake inactivity bound is
    /// armed once on accept entry and is NOT reset as the children
    /// advance (§2.5 / the session_fsm_unicast.scxml header "Deadline
    /// scoping"). The per-phase keys (`LinkOpening` / `SentInitSyn` /
    /// `GotInitAck` / `Closing`) re-arm on entry to that exact state, so
    /// a stale deadline that elapses after the phase advanced is keyed to
    /// a state that is no longer current and is discarded by the drive
    /// loop's key comparison (R311fa staleness rule).
    pub arming_key: SessionFsmUnicastState,
    /// The spec-sourced window in milliseconds (from [`SessionTimeouts`]).
    pub deadline_ms: u64,
    /// The timeout event the host raises once `deadline_ms` has elapsed
    /// since the deadline was armed.
    pub event: SessionFsmUnicastEvent,
}

/// Map the current leaf state to its host-owned handshake deadline, or
/// `None` for states that carry no host handshake deadline:
///   - `Init` — pre-handshake idle, no deadline.
///   - `Opening` / `Accepting` — compound parents; the current leaf is
///     always one of their atomic children, so these never appear as the
///     `get_current_state()` value, but they are matched for
///     exhaustiveness.
///   - `Established` — its lease deadline is owned by the separate,
///     keepalive-resetting [`crate::lease`] path, not the fixed
///     handshake sweep.
///   - `Closed` — the final state; nothing left to time out.
pub fn handshake_deadline_for(
    state: SessionFsmUnicastState,
    timeouts: &SessionTimeouts,
) -> Option<HandshakeDeadline> {
    use SessionFsmUnicastEvent as E;
    use SessionFsmUnicastState as S;
    let (arming_key, deadline_ms, event) = match state {
        S::LinkOpening => (S::LinkOpening, timeouts.link_open_ms, E::LinkOpenTimeout),
        S::SentInitSyn => (S::SentInitSyn, timeouts.init_ack_ms, E::InitAckTimeout),
        S::GotInitAck => (S::GotInitAck, timeouts.open_ack_ms, E::OpenAckTimeout),
        S::AwaitingInitSyn | S::SentInitAck | S::SentOpenAck => (
            S::Accepting,
            timeouts.accepting_inactivity_ms,
            E::AcceptingInactivityTimeout,
        ),
        S::Closing => (S::Closing, timeouts.closing_ms, E::ClosingTimeout),
        S::Init | S::Opening | S::Accepting | S::Established | S::Closed => return None,
    };
    Some(HandshakeDeadline {
        arming_key,
        deadline_ms,
        event,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session_fsm_unicast::{SessionFsmUnicastEvent as E, SessionFsmUnicastState as S};

    #[test]
    fn spec_defaults_match_section_2_5() {
        let t = SessionTimeouts::spec_defaults();
        assert_eq!(t.link_open_ms, 5_000);
        assert_eq!(t.init_ack_ms, 2_000);
        assert_eq!(t.open_ack_ms, 2_000);
        assert_eq!(t.accepting_inactivity_ms, 1_000);
        assert_eq!(t.closing_ms, 100);
    }

    #[test]
    fn per_phase_states_map_to_their_own_arming_key() {
        let t = SessionTimeouts::spec_defaults();
        for (state, key, ms, ev) in [
            (S::LinkOpening, S::LinkOpening, 5_000, E::LinkOpenTimeout),
            (S::SentInitSyn, S::SentInitSyn, 2_000, E::InitAckTimeout),
            (S::GotInitAck, S::GotInitAck, 2_000, E::OpenAckTimeout),
            (S::Closing, S::Closing, 100, E::ClosingTimeout),
        ] {
            let hd = handshake_deadline_for(state, &t).expect("per-phase deadline");
            assert_eq!(hd.arming_key, key);
            assert_eq!(hd.deadline_ms, ms);
            assert_eq!(hd.event, ev);
        }
    }

    #[test]
    fn accepting_children_share_the_parent_arming_key() {
        // The whole-handshake bound is armed once on accept entry: all
        // three children carry the Accepting key + the same window, so the
        // drive loop's key comparison keeps the original armed-at stamp as
        // the children advance.
        let t = SessionTimeouts::spec_defaults();
        for child in [S::AwaitingInitSyn, S::SentInitAck, S::SentOpenAck] {
            let hd = handshake_deadline_for(child, &t).expect("accept deadline");
            assert_eq!(hd.arming_key, S::Accepting);
            assert_eq!(hd.deadline_ms, 1_000);
            assert_eq!(hd.event, E::AcceptingInactivityTimeout);
        }
    }

    #[test]
    fn no_handshake_deadline_states_return_none() {
        let t = SessionTimeouts::spec_defaults();
        for state in [S::Init, S::Opening, S::Accepting, S::Established, S::Closed] {
            assert!(handshake_deadline_for(state, &t).is_none());
        }
    }
}
