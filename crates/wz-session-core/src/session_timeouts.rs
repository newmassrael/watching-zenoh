// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
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
/// NOT wire-encoded — unlike `crate::session_init_params::SessionInitParams::lease`
/// (the Established lease, which travels VLE-encoded in the OPEN body),
/// these are local timing config the host drive loop consults to raise
/// the FSM's handshake-timeout transitions. Carried host-side so SSOT is
/// preserved: the value is spec-sourced, the transition lives in the
/// statechart, and the clock lives in the runtime.
#[derive(Debug, Clone, Copy)]
pub struct SessionTimeouts {
    /// `LinkOpening` -> `link.open_timeout` window (§2.5: 5s).
    pub link_open_ms: u64,
    /// `Opening` whole-handshake: how long the initiator's handshake, its InitSyn to the peer's
    /// OpenAck, may take. A single bound armed once on entry to `Opening` and NOT reset when the
    /// InitAck moves it on; when it passes, the host raises the timeout event of the child it is
    /// in (`init_ack.timeout` in `SentInitSyn`, `open_ack.timeout` in `GotInitAck`). Neither
    /// upstream has a shorter window for one step: zenoh holds the whole open to
    /// `transport/unicast/open_timeout` (`io/zenoh-transport/src/unicast/manager.rs` @
    /// `tokio::time::timeout(self.config.unicast.open_timeout, async {`), and zenoh-pico both of
    /// its receives to one deadline (`vendor/zenoh-pico/src/transport/unicast/transport.c` @
    /// `z_clock_advance_ms(&recv_deadline, Z_TRANSPORT_CONNECT_TIMEOUT);`). [`OPEN_TIMEOUT_MS`]
    /// unless the host states the bound its node is configured with.
    pub opening_ms: u64,
    /// `Accepting` whole-handshake -> `accepting.inactivity_timeout`
    /// window (§2.5: 1s, zenoh-pico's `Z_TRANSPORT_ACCEPT_TIMEOUT`). A single bound armed once on
    /// accept entry, NOT reset as the Accepting children advance. A host that stands for zenoh
    /// states its own: `transport/unicast/accept_timeout`, ten seconds.
    pub accepting_inactivity_ms: u64,
    /// `Closing` -> `closing.timeout` window (§2.5: 100ms).
    pub closing_ms: u64,
}

/// How long an initiator's handshake may take when its host states no bound, in milliseconds:
/// ten seconds, the default both upstreams give it, zenoh's `transport/unicast/open_timeout`
/// (`commons/zenoh-config/src/defaults.rs` @ `open_timeout: 10_000,`) and zenoh-pico's
/// `Z_TRANSPORT_CONNECT_TIMEOUT` (`vendor/zenoh-pico/cmake/feature_config.cmake` @
/// `set(Z_TRANSPORT_CONNECT_TIMEOUT 10000`). A build with no configuration, an MCU image, still
/// needs a bound so that a peer that never answers does not hold the link forever.
pub const OPEN_TIMEOUT_MS: u64 = 10_000;

impl SessionTimeouts {
    /// The reference values: link.open 5s, the initiator's whole handshake [`OPEN_TIMEOUT_MS`],
    /// accepting.inactivity 1s, closing 100ms (docs/session-fsm.md §2.5).
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
            opening_ms: OPEN_TIMEOUT_MS,
            accepting_inactivity_ms: 1_000,
            closing_ms: 100,
        }
    }

    /// The values an engine hands its drive loop when its host states none of its own: the
    /// reference values. The handshake's bound is a node's configuration and not a build limit,
    /// so a host that has one states it with [`Self::with_open_timeout`].
    pub const fn from_build() -> Self {
        Self::spec_defaults()
    }

    /// These deadlines with the initiator's whole handshake held to `open_timeout`, the bound a
    /// node states for one open of an endpoint (`transport/unicast/open_timeout`). A bound
    /// beyond `u64::MAX` milliseconds is held to `u64::MAX`, which the tracker's saturating
    /// arithmetic reads as never.
    pub const fn with_open_timeout(self, open_timeout: core::time::Duration) -> Self {
        let ms = open_timeout.as_millis();
        Self {
            opening_ms: if ms > u64::MAX as u128 {
                u64::MAX
            } else {
                ms as u64
            },
            ..self
        }
    }
}

/// One armed handshake deadline: the state whose entry arms it (the
/// re-arm key), the spec-sourced window, and the event the host raises
/// when it elapses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeDeadline {
    /// The state keyed for re-arm. Each role's handshake is one bound keyed to
    /// its parent: the three `Accepting` children (`AwaitingInitSyn` /
    /// `SentInitAck` / `SentOpenAck`) map to `Accepting`, and the two
    /// `Opening` children (`SentInitSyn` / `GotInitAck`) map to `Opening`, so
    /// the bound is armed once on entry and is NOT reset as the children
    /// advance. The per-phase keys (`LinkOpening` / `Closing`) re-arm on
    /// entry to that exact state, so a stale deadline that elapses after the
    /// phase advanced is keyed to a state that is no longer current and is
    /// discarded by the drive loop's key comparison (R311fa staleness rule).
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
        // One bound over both children, keyed to the parent so the InitAck does not re-arm it;
        // the event is the one the current child handles, so it is never stale.
        S::SentInitSyn => (S::Opening, timeouts.opening_ms, E::InitAckTimeout),
        S::GotInitAck => (S::Opening, timeouts.opening_ms, E::OpenAckTimeout),
        // The accepting role's states and its deadline event exist in a build with
        // `session-unicast-accept` only (the session machine states that gate).
        #[cfg(feature = "session-unicast-accept")]
        S::AwaitingInitSyn | S::SentInitAck | S::SentOpenAck => (
            S::Accepting,
            timeouts.accepting_inactivity_ms,
            E::AcceptingInactivityTimeout,
        ),
        S::Closing => (S::Closing, timeouts.closing_ms, E::ClosingTimeout),
        #[cfg(feature = "session-unicast-accept")]
        S::Accepting => return None,
        S::Init | S::Opening | S::Established | S::Closed => return None,
    };
    Some(HandshakeDeadline {
        arming_key,
        deadline_ms,
        event,
    })
}

/// Stateful host-side tracker for the currently-armed handshake deadline.
///
/// Wraps the [`SessionTimeouts`] config plus the arming-state key and the
/// monotonic instant the deadline was armed. A session drive loop calls
/// [`HandshakeDeadlineTracker::poll`] once per iteration to get the
/// in-flight deadline without re-deriving the arming-key staleness logic
/// inline — both session drive loops (the handshake-open loop in
/// `session_open` and the steady-state loop in `session_glue`) share this,
/// so the §2.5 deadline ownership has a single implementation:
///   - per-phase deadlines (LinkOpening / Closing) re-arm on entry to their
///     arming state;
///   - the `Opening` children share the parent `Opening` key and the three
///     `Accepting` children the parent `Accepting` key, so each role's
///     whole-handshake bound is armed once and not reset as they advance;
///   - a state with no host handshake deadline disarms the tracker.
pub struct HandshakeDeadlineTracker {
    timeouts: SessionTimeouts,
    armed: Option<(SessionFsmUnicastState, u64)>,
}

impl HandshakeDeadlineTracker {
    /// Construct a disarmed tracker over the spec-sourced `timeouts`.
    pub fn new(timeouts: SessionTimeouts) -> Self {
        Self {
            timeouts,
            armed: None,
        }
    }

    /// Return the in-flight handshake deadline for `state` as an absolute
    /// monotonic-ms instant plus the event to raise when it elapses, or
    /// `None` if `state` carries no host handshake deadline (Init / the
    /// compound parents / Established / Closed — see
    /// [`handshake_deadline_for`]).
    ///
    /// `now_ms` is the runtime monotonic clock reading; it is consumed
    /// only when (re-)arming — i.e. when the arming-state key changes — so
    /// the per-phase deadlines measure from entry to their state and the
    /// `Opening` and `Accepting` bounds keep their original armed-at instant
    /// across the child transitions. A state with no deadline disarms the tracker so
    /// a later re-entry re-arms from its own entry instant.
    pub fn poll(
        &mut self,
        state: SessionFsmUnicastState,
        now_ms: u64,
    ) -> Option<(u64, SessionFsmUnicastEvent)> {
        match handshake_deadline_for(state, &self.timeouts) {
            Some(hd) => {
                let armed_at = match self.armed {
                    Some((key, at)) if key == hd.arming_key => at,
                    _ => {
                        self.armed = Some((hd.arming_key, now_ms));
                        now_ms
                    }
                };
                Some((armed_at.saturating_add(hd.deadline_ms), hd.event))
            }
            None => {
                self.armed = None;
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session_fsm_unicast::{SessionFsmUnicastEvent as E, SessionFsmUnicastState as S};

    #[test]
    fn spec_defaults_match_section_2_5() {
        let t = SessionTimeouts::spec_defaults();
        assert_eq!(t.link_open_ms, 5_000);
        assert_eq!(t.opening_ms, 10_000);
        assert_eq!(t.accepting_inactivity_ms, 1_000);
        assert_eq!(t.closing_ms, 100);
    }

    /// With no bound stated, an initiator's handshake gets the ten seconds both upstreams give it,
    /// and no window of its own shorter than that.
    #[test]
    fn a_handshake_with_no_stated_bound_gets_upstreams_ten_seconds() {
        assert_eq!(OPEN_TIMEOUT_MS, 10_000);
        assert_eq!(SessionTimeouts::from_build().opening_ms, OPEN_TIMEOUT_MS);
        let t = SessionTimeouts::from_build();
        for state in [S::SentInitSyn, S::GotInitAck] {
            let hd = handshake_deadline_for(state, &t).expect("an opening deadline");
            assert_eq!(hd.deadline_ms, OPEN_TIMEOUT_MS);
        }
    }

    /// `with_open_timeout` states the initiator's whole handshake and nothing else, and a bound
    /// too long for the field is held to never rather than wrapped to a short one.
    #[test]
    fn with_open_timeout_states_the_opening_bound_and_keeps_the_rest() {
        let spec = SessionTimeouts::spec_defaults();
        let stated = spec.with_open_timeout(core::time::Duration::from_millis(3_000));
        assert_eq!(stated.opening_ms, 3_000);
        assert_eq!(stated.link_open_ms, spec.link_open_ms);
        assert_eq!(stated.accepting_inactivity_ms, spec.accepting_inactivity_ms);
        assert_eq!(stated.closing_ms, spec.closing_ms);
        let longest = spec.with_open_timeout(core::time::Duration::MAX);
        assert_eq!(longest.opening_ms, u64::MAX);
    }

    #[test]
    fn per_phase_states_map_to_their_own_arming_key() {
        let t = SessionTimeouts::spec_defaults();
        for (state, key, ms, ev) in [
            (S::LinkOpening, S::LinkOpening, 5_000, E::LinkOpenTimeout),
            (S::Closing, S::Closing, 100, E::ClosingTimeout),
        ] {
            let hd = handshake_deadline_for(state, &t).expect("per-phase deadline");
            assert_eq!(hd.arming_key, key);
            assert_eq!(hd.deadline_ms, ms);
            assert_eq!(hd.event, ev);
        }
    }

    /// The initiator's two handshake children share one bound keyed to `Opening`, each raising
    /// the event the statechart handles in it.
    #[test]
    fn opening_children_share_the_parent_arming_key() {
        let t =
            SessionTimeouts::spec_defaults().with_open_timeout(core::time::Duration::from_secs(3));
        for (child, ev) in [
            (S::SentInitSyn, E::InitAckTimeout),
            (S::GotInitAck, E::OpenAckTimeout),
        ] {
            let hd = handshake_deadline_for(child, &t).expect("opening deadline");
            assert_eq!(hd.arming_key, S::Opening);
            assert_eq!(hd.deadline_ms, 3_000);
            assert_eq!(hd.event, ev);
        }
    }

    /// The InitAck does not re-arm the bound: an OpenAck that is late is late against the
    /// instant the InitSyn went out, as upstream's one timer measures it.
    #[test]
    fn tracker_opening_children_keep_one_stamp() {
        let t =
            SessionTimeouts::spec_defaults().with_open_timeout(core::time::Duration::from_secs(3));
        let mut tr = HandshakeDeadlineTracker::new(t);
        assert_eq!(
            tr.poll(S::SentInitSyn, 1_000),
            Some((4_000, E::InitAckTimeout))
        );
        assert_eq!(
            tr.poll(S::GotInitAck, 2_500),
            Some((4_000, E::OpenAckTimeout))
        );
    }

    #[cfg(feature = "session-unicast-accept")]
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
        for state in [S::Init, S::Opening, S::Established, S::Closed] {
            assert!(handshake_deadline_for(state, &t).is_none());
        }
        // The compound accepting parent is never the current leaf, and has no deadline of its own.
        #[cfg(feature = "session-unicast-accept")]
        assert!(handshake_deadline_for(S::Accepting, &t).is_none());
    }

    #[test]
    fn tracker_per_phase_rearms_on_key_change() {
        let mut tr = HandshakeDeadlineTracker::new(SessionTimeouts::spec_defaults());
        // LinkOpening armed at t=1000 -> 1000 + 5000.
        assert_eq!(
            tr.poll(S::LinkOpening, 1_000),
            Some((6_000, E::LinkOpenTimeout))
        );
        // Re-poll same state at a later now does NOT re-arm (stamp kept).
        assert_eq!(
            tr.poll(S::LinkOpening, 4_999),
            Some((6_000, E::LinkOpenTimeout))
        );
        // Advancing to SentInitSyn re-arms from the new now (2000 + 10000).
        assert_eq!(
            tr.poll(S::SentInitSyn, 2_000),
            Some((12_000, E::InitAckTimeout))
        );
    }

    #[cfg(feature = "session-unicast-accept")]
    #[test]
    fn tracker_accepting_children_keep_one_stamp() {
        let mut tr = HandshakeDeadlineTracker::new(SessionTimeouts::spec_defaults());
        // Armed on first Accepting child at t=1000 -> 1000 + 1000.
        assert_eq!(
            tr.poll(S::AwaitingInitSyn, 1_000),
            Some((2_000, E::AcceptingInactivityTimeout))
        );
        // Children advance, now=1500/1800 — the whole-handshake bound keeps
        // its original armed_at (1000), so the deadline stays 2000 (NOT
        // re-armed to 2500/2800).
        assert_eq!(
            tr.poll(S::SentInitAck, 1_500),
            Some((2_000, E::AcceptingInactivityTimeout))
        );
        assert_eq!(
            tr.poll(S::SentOpenAck, 1_800),
            Some((2_000, E::AcceptingInactivityTimeout))
        );
    }

    #[test]
    fn tracker_disarms_on_no_deadline_state_then_rearms_fresh() {
        let mut tr = HandshakeDeadlineTracker::new(SessionTimeouts::spec_defaults());
        assert_eq!(tr.poll(S::Closing, 1_000), Some((1_100, E::ClosingTimeout)));
        // Established has no host handshake deadline -> disarm.
        assert_eq!(tr.poll(S::Established, 2_000), None);
        // Re-entering a handshake state re-arms from the new now, not the
        // pre-disarm stamp.
        assert_eq!(tr.poll(S::Closing, 5_000), Some((5_100, E::ClosingTimeout)));
    }
}
