// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311ik — scouting FSM <-> multicast-link glue (active mode),
//! engine-free.
//!
//! Hosts the four `scouting.scxml` actions
//! (`sources/session/scouting.scxml`, codegen'd engine-free into
//! [`wz_session_core::scouting`]) as native `<sce:action>` trait methods
//! and drives the FSM against a UDP-multicast scouting link. This is the
//! engine-free successor of the R311ep Lua-bound glue: the generated
//! [`wz_session_core::scouting::ScoutingActions`] trait replaces the Lua
//! registration, so no `IScriptEngine` / `LuaEngine` is involved and the
//! scouting path no longer pulls `sce-rust-lua` (one half of the runtime
//! schism that blocked hosting the reassembly FSM and the session FSMs in
//! one `sce-rust-runtime`).
//!
//! ## IO ownership — actions are pure, the loop owns the socket
//!
//! The script actions are **pure** — `scout_emit` encodes a Scout frame
//! and stages the bytes in [`ScoutingActions::pending_scout`];
//! `record_hello_and_emit` records the staged [`ScoutedHello`]. All socket
//! IO lives in the async [`drive_scouting_until_resolved`] loop, which owns
//! the `&mut` link driver. This (a) keeps the actions trivially
//! unit-testable without a socket, and (b) makes the `link.tx_failed` arm
//! real: a failed multicast send feeds `LinkTxFailed` instead of being
//! unreachable.
//!
//! The inbound Hello DECODE ([`decode_scouted_hello`]) is the loop's, not
//! the action's, and that placement is load-bearing rather than tidy:
//! zenoh-pico decodes before its MID switch and `continue`s on failure
//! (`src/session/scout.c:71-76`), so a malformed datagram never reaches the
//! state machine. An action cannot reproduce that, because it runs after
//! its transition's guard has already picked the target state.
//!
//! A single UDP multicast socket both sends the Scout and receives the
//! Hello (zenoh-pico `__z_scout` does the same: send the wbuf, then read
//! replies on the same link).
//!
//! ## Action state sharing — the trait moves, the Arc stays
//!
//! [`wz_session_core::scouting::ScoutingPolicy<A>`] takes `A` (the action
//! impl) **by value**, and the engine's policy field is private, so the
//! drive loop cannot read the staging slots back out of the engine. The
//! shared state therefore lives in an [`ScoutingActions`] the caller holds
//! behind an `Arc`; the policy is parameterised over a thin
//! [`ScoutActionsBinding`] newtype that wraps a clone of that `Arc` and
//! impls the generated trait through the `Arc`'s interior-mutable slots.
//! (The trait cannot be impl'd directly on `Arc<ScoutingActions>` — the
//! orphan rule rejects `impl ForeignTrait for Arc<Local>` since `Arc` is
//! not a fundamental type — so the local newtype carries the impl.)
//!
//! ## Timeout ownership — the loop owns the clock
//!
//! The engine-free FSM is codegen'd `--no-std` (`type Hal = NoOpHal`), so
//! a W3C SCXML `<send delay>` would be a dead element (NoOpHal's clock
//! never advances). The FSM therefore arms no timer; it owns only the
//! `scout.timer.elapsed` transition. This loop owns the clock: it measures
//! the [`ScoutParams::timeout_ms`] window against the runtime's monotonic
//! clock and raises `ScoutingEvent::ScoutTimerElapsed` when it elapses.
//! Mirrors the reassembly dispatcher's deadline-sweep split (FSM owns the
//! transition, runtime owns the clock; the value stays spec-sourced).

use std::sync::Arc;

use sce_rust_runtime::Engine;

#[cfg(test)]
use wz_codecs::wire_const;
use wz_session_core::link::{LinkEvent, TxFrame};
use wz_session_core::reliability::Reliability;
// R311y428 — `pub` (was a private `use`): re-exported alongside the
// `ScoutingActions::new` it parameterises, mirroring `session_glue`'s
// `SessionInitParams` / `WhatAmI` re-export (session_glue.rs:178) and for the
// same reason. A consumer reaches this crate through the wz facade
// (`wz::runtime_tokio::*`), which re-exports no `wz-session-core` path of its
// own, so without this the module's own public constructor cannot be CALLED
// from there — its parameter type is unnameable. The in-tree tests never hit
// it: they carry a direct wz-session-core dev-dep the facade's consumers lack.
// R2334 — the initiator's ignore verdict. Re-exported because it is part of
// this module's READ surface: `ScoutingActions::ignored_datagrams` returns it,
// so a caller must be able to name it without depending on the core crate.
// R2610 — `hello_advances_window` joins them for the same reason: it is the
// rule the window applies to decide whether an observed Hello ends the cycle,
// and a caller reading `ignored_datagrams` cannot interpret a
// `LocatorlessHello` entry without being able to name it.
pub use wz_session_core::scout_initiator::{
    classify_ignored_scout_rx, hello_advances_window, ScoutRxIgnored,
};
pub use wz_session_core::scout_params::ScoutParams;
// The window itself (the actions, the hello decode, the machine and its pump) is the session's
// (`wz_session_core::scouting_host`): it names no socket and no executor, so the cooperative
// host pumps the same value. What stays here is this runtime's half, the drive loop that owns a
// tokio link driver and a tokio timer.
#[cfg(test)]
use wz_codecs::{scout::Scout, whatami::WhatAmI};
use wz_session_core::scouting::ScoutingPolicy;
#[cfg(test)]
use wz_session_core::scouting::{
    ScoutingEvent, ScoutingHelloReceivedPayload, ScoutingInject, ScoutingState,
};
pub use wz_session_core::scouting_host::{decode_scouted_hello, ScoutOutcome, ScoutedHello};
use wz_session_core::scouting_host::{
    open_window, window_datagram, window_outcome, window_resolved, window_sent, window_tick,
};

use wz_runtime_core::TimeSource;

use crate::runtime_impl::TokioRuntime;
use crate::LinkDriver;

/// Shared host state for one active-scouting cycle, over the tokio runtime's locks unless a
/// runtime is named: the session's own type (`wz_session_core::scouting_host::ScoutingActions`).
pub type ScoutingActions<R = TokioRuntime> = wz_session_core::scouting_host::ScoutingActions<R>;

/// The generated policy's owner of the shared state, over the tokio runtime unless a runtime is
/// named.
pub type ScoutActionsBinding<R = TokioRuntime> =
    wz_session_core::scouting_host::ScoutActionsBinding<R>;

/// Build a production scouting engine: an [`Engine`] over the generated engine-free
/// [`ScoutingPolicy`], parameterised over a [`ScoutActionsBinding`] wrapping a clone of `actions`.
/// The caller retains `actions` and drives the engine with [`drive_scouting_until_resolved`].
pub fn new_scouting_engine(
    actions: &Arc<ScoutingActions>,
) -> Engine<ScoutingPolicy<ScoutActionsBinding>> {
    wz_session_core::scouting_host::new_scouting_engine(actions)
}

/// Drive one active-scouting cycle to resolution: emit a Scout on the
/// multicast `driver`, then await a Hello until the
/// [`ScoutParams::timeout_ms`] window elapses.
///
/// The engine-free FSM arms no timer of its own (engine-free no_std binds
/// `NoOpHal`, so a `<send delay>` would never fire), so this loop owns the
/// clock: it records a monotonic start instant on entry and raises
/// `ScoutingEvent::ScoutTimerElapsed` once `timeout_ms` has elapsed with
/// no Hello (driving the FSM's `AwaitingHello -> Idle` timeout). A Hello
/// datagram races the `tick_interval_ms` cadence via `poll_event`, so the
/// common case resolves as soon as the peer replies. The window duration
/// is the spec-sourced `ScoutParams::timeout_ms`, not duplicated here.
///
/// `max_iters` bounds the select loop for tests; production passes `None`.
/// Returns once the FSM returns to `Idle` (Hello captured or timed out) or
/// the link is lost. With [`ScoutParams::exit_on_first`] clear the FSM
/// self-transitions on every Hello, so only the deadline ends the cycle and
/// every responder in the window is recorded — read them from
/// [`ScoutingActions::scouted_hellos`] when this returns, which is where
/// upstream reads them too (`_z_scout` drains the list `__z_scout_loop`
/// filled, AFTER the window, `src/net/primitives.c:81-90`).
pub async fn drive_scouting_until_resolved<D, T>(
    driver: &mut D,
    actions: &Arc<ScoutingActions>,
    engine: &mut Engine<ScoutingPolicy<ScoutActionsBinding>>,
    clock: &T,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> ScoutOutcome
where
    D: LinkDriver,
    T: TimeSource,
{
    // Idle -> Sending: the machine stages the Scout, and this loop transmits it. The send result
    // drives the Sending -> AwaitingHello (tx.done) vs Sending -> Idle (tx_failed) branch; a
    // Scout that was not staged (which should not happen) counts as a failed send, so the
    // machine returns to Idle deterministically.
    let sent = match open_window(actions, engine) {
        Some(datagram) => {
            let frame = TxFrame { bytes: &datagram };
            driver.send(&frame, Reliability::BestEffort).await.is_ok()
        }
        None => false,
    };
    window_sent(engine, sent);

    // The host owns the scout deadline (see module doc). Measure the spec-sourced window
    // against the runtime monotonic clock.
    let start_ms = clock.now_monotonic_ms();

    let mut iter: usize = 0;
    loop {
        if window_resolved(engine) {
            break;
        }
        if let Some(limit) = max_iters {
            if iter >= limit {
                return ScoutOutcome::IterationLimit;
            }
            iter += 1;
        }
        tokio::select! {
            event = driver.poll_event() => match event {
                // What the window takes as an answer and what it names and drops is the
                // session's (`window_datagram`), the same for every host.
                LinkEvent::Rx(rx) => window_datagram(actions, engine, &rx.bytes),
                LinkEvent::Lost { cause } => return ScoutOutcome::LinkLost(cause),
                LinkEvent::Ready => {}
            },
            _ = clock.sleep(tick_interval_ms) => {
                window_tick(
                    actions,
                    engine,
                    clock.now_monotonic_ms().saturating_sub(start_ms),
                );
            }
        }
    }

    window_outcome(actions)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::runtime_impl::TokioTime;

    fn fixture_actions() -> Arc<ScoutingActions> {
        fixture_actions_mode(true)
    }

    /// `exit_on_first` is the axis this fixture parameterises: `true` is the
    /// session-open implicit scout (pico `net/session.c:69`), `false` the
    /// `z_scout` survey (pico `net/primitives.c:81`).
    fn fixture_actions_mode(exit_on_first: bool) -> Arc<ScoutingActions> {
        ScoutingActions::new(ScoutParams {
            what: 0x03, // ROUTER | PEER
            zid: vec![0xAA, 0xBB, 0xCC, 0xDD],
            timeout_ms: 1000,
            exit_on_first,
        })
    }

    /// Stage a crafted datagram the way the drive loop does — through the
    /// real decode — and feed the FSM the typed `hello.received` its guards
    /// read. Tests that drive the engine by hand must go through this, or
    /// they would assert against a mode the statechart never saw.
    fn feed_hello(
        actions: &Arc<ScoutingActions>,
        engine: &mut Engine<ScoutingPolicy<ScoutActionsBinding>>,
        dgram: &[u8],
    ) {
        if let Some(hello) = decode_scouted_hello(dgram) {
            *actions.pending_hello.lock().unwrap() = Some(hello);
        }
        engine.raise_hello_received(ScoutingHelloReceivedPayload {
            exit_on_first: u8::from(actions.params.exit_on_first),
        });
        engine.step();
    }

    /// `scout_emit` (Idle -> Sending entering transition) stages a
    /// correctly-framed Scout datagram: MID header + version +
    /// cbyte(what|I|zid_len_m1) + zid.
    #[test]
    fn scout_emit_stages_framed_datagram() {
        let actions = fixture_actions();
        let mut engine = new_scouting_engine(&actions);
        engine.initialize();
        engine.process_event(ScoutingEvent::SessionOpenRequested);

        assert_eq!(engine.get_current_state(), ScoutingState::Sending);
        assert_eq!(actions.trace_snapshot().scout_emit, 1);
        let dgram = actions
            .pending_scout
            .lock()
            .unwrap()
            .clone()
            .expect("scout_emit staged a datagram");
        // [S_MID_SCOUT, version, cbyte, zid(4)]
        let cbyte = 0x03 /*what*/ | 0x08 /*I*/ | ((4 - 1) << 4) /*zid_len_m1*/;
        assert_eq!(
            dgram,
            vec![wire_const::S_MID_SCOUT, 0x09, cbyte, 0xAA, 0xBB, 0xCC, 0xDD]
        );
    }

    /// `record_hello_and_emit` decodes a staged Hello datagram and
    /// captures its first locator.
    #[test]
    fn record_hello_extracts_first_locator() {
        let actions = fixture_actions();
        let mut engine = new_scouting_engine(&actions);
        engine.initialize();
        engine.process_event(ScoutingEvent::SessionOpenRequested);
        engine.process_event(ScoutingEvent::ScoutTxDone);
        assert_eq!(engine.get_current_state(), ScoutingState::AwaitingHello);

        // Stage a Hello carrying one locator, then drive the FSM.
        feed_hello(
            &actions,
            &mut engine,
            &craft_hello_datagram("udp/127.0.0.1:7447"),
        );

        assert_eq!(engine.get_current_state(), ScoutingState::Idle);
        assert_eq!(actions.trace_snapshot().record_hello, 1);
        assert_eq!(
            actions.discovered_locator().as_deref(),
            Some("udp/127.0.0.1:7447")
        );
    }

    /// `scout.timer.elapsed` (no Hello) routes through `emit_scout_timeout`
    /// and leaves `discovered` unset.
    #[test]
    fn scout_timeout_leaves_no_locator() {
        let actions = fixture_actions();
        let mut engine = new_scouting_engine(&actions);
        engine.initialize();
        engine.process_event(ScoutingEvent::SessionOpenRequested);
        engine.process_event(ScoutingEvent::ScoutTxDone);
        engine.process_event(ScoutingEvent::ScoutTimerElapsed);

        assert_eq!(engine.get_current_state(), ScoutingState::Idle);
        assert_eq!(actions.trace_snapshot().scout_timeout, 1);
        assert!(actions.discovered_locator().is_none());
    }

    /// Build a Hello datagram `[S_MID_HELLO|L][version][cbyte][zid][VLE
    /// n][locator...]` carrying a single locator. Mirrors the
    /// `layer3_hello` wire shape.
    fn craft_hello_datagram(locator: &str) -> Vec<u8> {
        craft_hello_with(0x01, &[0x01, 0x02, 0x03], &[locator])
    }

    /// R311y520 — the general builder: an explicit `whatami` wire value, an
    /// explicit zid, and ZERO OR MORE locators.
    ///
    /// The single-locator helper above delegates here so both shapes stay one
    /// encoder. `locators` empty emits the Hello with the L flag CLEAR, which
    /// is the locator-less shape pico still surfaces (`scout.c:104-110`) —
    /// crafting it required this generalisation, which is why the residual
    /// went unmeasured for as long as it did.
    fn craft_hello_with(whatami: u8, zid: &[u8], locators: &[&str]) -> Vec<u8> {
        use wz_codecs::hello::HelloOwned;
        use wz_codecs::locator::LocatorOwned;

        // cbyte: whatami wire-form (low 2 bits) | zid_len_m1 << 4. Verified
        // against pico `message.c:675-676` + `transport.c:35-37`.
        let cbyte = (whatami & 0x03) | (((zid.len() as u8) - 1) << 4);
        let l_flag: u8 = u8::from(!locators.is_empty());
        let owned: HelloOwned = HelloOwned {
            version: 0x09,
            cbyte,
            zid: wz_session_core::codec_owned::owned_bytes(zid).unwrap(),
            num_locators: (!locators.is_empty()).then_some(locators.len() as u64),
            locators: (!locators.is_empty()).then(|| {
                locators
                    .iter()
                    .map(|l| LocatorOwned {
                        locator_len: l.len() as u64,
                        locator: wz_session_core::codec_owned::owned_string(l).unwrap(),
                    })
                    .collect()
            }),
        };
        let body = owned
            .try_as_borrowed()
            .expect("borrowed projection of owned Hello")
            .encode_to_vec(l_flag);

        let mut dgram = Vec::with_capacity(1 + body.len());
        let mut header = wire_const::S_MID_HELLO;
        if l_flag == 1 {
            header |= wire_const::FLAG_S_HELLO_L;
        }
        dgram.push(header);
        dgram.extend_from_slice(&body);
        dgram
    }

    /// Drive one staged Hello through the FSM and hand back the recorded set.
    fn scout_one(dgram: Vec<u8>) -> (Arc<ScoutingActions>, Vec<ScoutedHello>) {
        let actions = fixture_actions();
        let mut engine = new_scouting_engine(&actions);
        engine.initialize();
        engine.process_event(ScoutingEvent::SessionOpenRequested);
        engine.process_event(ScoutingEvent::ScoutTxDone);
        assert_eq!(engine.get_current_state(), ScoutingState::AwaitingHello);
        feed_hello(&actions, &mut engine, &dgram);
        assert_eq!(engine.get_current_state(), ScoutingState::Idle);
        let hellos = actions.scouted_hellos();
        (actions, hellos)
    }

    /// R311y520 residual 4 — EVERY locator of a multi-locator Hello survives.
    ///
    /// Pre-R311y520 the decode took `locators[0]` and dropped the rest, so a
    /// peer advertising a reachable address behind an unreachable one was
    /// undialable through wz while pico could reach it (`scout.c:94-103` copies
    /// the whole array).
    #[test]
    fn a_multi_locator_hello_surfaces_every_locator() {
        let (actions, hellos) = scout_one(craft_hello_with(
            0x01,
            &[0x01, 0x02, 0x03],
            &["udp/127.0.0.1:7447", "tcp/127.0.0.1:7448", "tcp/[::1]:7449"],
        ));
        assert_eq!(hellos.len(), 1, "one Hello in, one record out");
        assert_eq!(
            hellos[0].locators,
            vec![
                "udp/127.0.0.1:7447".to_string(),
                "tcp/127.0.0.1:7448".to_string(),
                "tcp/[::1]:7449".to_string(),
            ],
            "all three locators must survive in wire order"
        );
        // The pre-existing dial-target read is unchanged: still the first.
        assert_eq!(
            actions.discovered_locator().as_deref(),
            Some("udp/127.0.0.1:7447")
        );
    }

    /// R311y520 residual 2 — version / whatami / zid reach the caller.
    ///
    /// A consumer cannot pick a peer by ROLE if the role never leaves the
    /// decoder. The whatami here is the CLIENT wire value (0b10), chosen
    /// because it is neither the fixture's previous value nor the
    /// default-on-failure one, so a decode that quietly defaults fails this.
    #[test]
    fn a_hello_surfaces_its_version_role_and_zid() {
        let zid = [0xDE, 0xAD, 0xBE, 0xEF, 0x01];
        let (_actions, hellos) = scout_one(craft_hello_with(0x02, &zid, &["udp/127.0.0.1:7447"]));
        assert_eq!(hellos.len(), 1);
        assert_eq!(hellos[0].version, 0x09);
        assert_eq!(
            hellos[0].whatami,
            Some(WhatAmI::Client),
            "the role rides the low 2 bits of the cbyte (pico transport.c:35-37)"
        );
        assert_eq!(
            hellos[0].zid, zid,
            "the zid must survive whole; its length rides the cbyte high nibble"
        );
    }

    /// R311y520 residual 3 — a LOCATOR-LESS Hello is a discovered peer, not
    /// silence.
    ///
    /// This is the sharpest of the three, because the old code and a timed-out
    /// window were indistinguishable to every caller: both left `discovered`
    /// at `None`. The assertion pairs the two reads deliberately — a recorded
    /// peer WITH no dial target.
    ///
    /// R2610 MOVED IT TO THE SURVEY ARM, which is the only arm where upstream
    /// makes this claim. `vendor/zenoh-pico/src/session/scout.c` @
    /// `if ((locator_count == 0) && exit_on_first) {` records a locator-less
    /// Hello when it is COLLECTING and declines it when a first hello would
    /// close the search; the test used to run the exit-on-first fixture and so
    /// asserted the half upstream does not hold. The drive-loop twin of the
    /// other half is
    /// [`a_locator_less_hello_does_not_end_an_exit_on_first_window`].
    #[test]
    fn a_locator_less_hello_is_still_a_discovered_peer() {
        let actions = fixture_actions_mode(false);
        let mut engine = new_scouting_engine(&actions);
        engine.initialize();
        engine.process_event(ScoutingEvent::SessionOpenRequested);
        engine.process_event(ScoutingEvent::ScoutTxDone);
        assert_eq!(engine.get_current_state(), ScoutingState::AwaitingHello);
        feed_hello(
            &actions,
            &mut engine,
            &craft_hello_with(0x00, &[0x07, 0x08], &[]),
        );
        assert_eq!(
            engine.get_current_state(),
            ScoutingState::AwaitingHello,
            "a survey window is closed by its deadline, not by a responder"
        );
        let hellos = actions.scouted_hellos();
        assert_eq!(
            hellos.len(),
            1,
            "a Hello with no locator is still a peer that answered"
        );
        assert!(
            hellos[0].locators.is_empty(),
            "and it advertised no address, which is what empty means"
        );
        assert_eq!(hellos[0].whatami, Some(WhatAmI::Router));
        assert_eq!(hellos[0].zid, vec![0x07, 0x08]);
        assert!(
            actions.discovered_locator().is_none(),
            "no locator to dial — the old read stays honest"
        );
    }

    // ── exit_on_first: pico's `__z_scout_loop` parameter, both arms ──

    /// The implicit-scout arm (pico `net/session.c:69` passes `true`): the
    /// FIRST Hello ends the cycle. Two responders answer; the FSM is in
    /// `Idle` after the first, which is what makes the host drive loop
    /// return, so the second is never recorded.
    ///
    /// The pair is the point — this and
    /// [`a_survey_window_records_every_responder_and_stays_awaiting`] feed the
    /// SAME two datagrams and differ only in the mode, so neither can pass by
    /// recording an amount that has nothing to do with the flag.
    #[test]
    fn an_exit_on_first_window_stops_at_the_first_hello() {
        let actions = fixture_actions_mode(true);
        let mut engine = new_scouting_engine(&actions);
        engine.initialize();
        engine.process_event(ScoutingEvent::SessionOpenRequested);
        engine.process_event(ScoutingEvent::ScoutTxDone);

        feed_hello(
            &actions,
            &mut engine,
            &craft_hello_with(0x01, &[0xA1], &["udp/127.0.0.1:7447"]),
        );
        assert_eq!(
            engine.get_current_state(),
            ScoutingState::Idle,
            "exit_on_first leaves AwaitingHello on the first Hello"
        );

        feed_hello(
            &actions,
            &mut engine,
            &craft_hello_with(0x01, &[0xB2], &["udp/127.0.0.1:7448"]),
        );
        let hellos = actions.scouted_hellos();
        assert_eq!(hellos.len(), 1, "the cycle is over; the second is not ours");
        assert_eq!(hellos[0].zid, vec![0xA1]);
    }

    /// The survey arm (pico `net/primitives.c:81` passes `false`): every
    /// responder in the window is recorded and the FSM STAYS in
    /// `AwaitingHello`, so the host drive loop keeps running until the
    /// deadline. This is pico's `if (!empty && exit_on_first) break;` NOT
    /// breaking (`src/session/scout.c:121-123`).
    ///
    /// Before the statechart carried this arm, `wz-capi-pico`'s `z_scout`
    /// had to re-enter whole scouting CYCLES to see a second peer — which
    /// re-sent a Scout per cycle and delayed every callback by up to one
    /// cycle.
    #[test]
    fn a_survey_window_records_every_responder_and_stays_awaiting() {
        let actions = fixture_actions_mode(false);
        let mut engine = new_scouting_engine(&actions);
        engine.initialize();
        engine.process_event(ScoutingEvent::SessionOpenRequested);
        engine.process_event(ScoutingEvent::ScoutTxDone);

        for (zid, locator) in [
            (0xA1u8, "udp/127.0.0.1:7447"),
            (0xB2, "udp/127.0.0.1:7448"),
            (0xC3, "udp/127.0.0.1:7449"),
        ] {
            feed_hello(
                &actions,
                &mut engine,
                &craft_hello_with(0x01, &[zid], &[locator]),
            );
            assert_eq!(
                engine.get_current_state(),
                ScoutingState::AwaitingHello,
                "the survey arm re-enters AwaitingHello; only the deadline ends it"
            );
        }

        let hellos = actions.scouted_hellos();
        assert_eq!(hellos.len(), 3, "every responder in the window is recorded");
        assert_eq!(
            hellos.iter().map(|h| h.zid.clone()).collect::<Vec<_>>(),
            vec![vec![0xA1], vec![0xB2], vec![0xC3]],
            "in ARRIVAL order — pico's slist is newest-first, so a consumer \
             that must match its delivery order reverses on the way out"
        );
        // `discovered` keeps its former meaning through the survey arm too:
        // the first locator seen, not the last.
        assert_eq!(
            actions.discovered_locator().as_deref(),
            Some("udp/127.0.0.1:7447")
        );

        // The deadline is what closes a survey window.
        engine.process_event(ScoutingEvent::ScoutTimerElapsed);
        assert_eq!(engine.get_current_state(), ScoutingState::Idle);
        assert_eq!(actions.trace_snapshot().scout_timeout, 1);
        assert_eq!(
            actions.scouted_hellos().len(),
            3,
            "closing the window records nothing extra"
        );
    }

    /// The dial target is FIRST-WINS, and "first" means the first CAPTURED
    /// locator, not the first responder.
    ///
    /// A locator-less peer answers first and a dialable one second: the read
    /// must name the second. Then a third dialable peer answers and must NOT
    /// re-point it. Both halves are needed — last-wins passes the first half
    /// on its own, and "set once, on the first Hello" passes the second.
    #[test]
    fn the_dial_target_is_the_first_captured_locator_and_a_later_peer_cannot_move_it() {
        let actions = fixture_actions_mode(false);
        let mut engine = new_scouting_engine(&actions);
        engine.initialize();
        engine.process_event(ScoutingEvent::SessionOpenRequested);
        engine.process_event(ScoutingEvent::ScoutTxDone);

        feed_hello(&actions, &mut engine, &craft_hello_with(0x01, &[0xA1], &[]));
        assert!(
            actions.discovered_locator().is_none(),
            "a peer that advertised no address gives nothing to dial"
        );

        feed_hello(
            &actions,
            &mut engine,
            &craft_hello_with(0x01, &[0xB2], &["udp/127.0.0.1:7448"]),
        );
        feed_hello(
            &actions,
            &mut engine,
            &craft_hello_with(0x01, &[0xC3], &["udp/127.0.0.1:7449"]),
        );

        assert_eq!(
            actions.discovered_locator().as_deref(),
            Some("udp/127.0.0.1:7448"),
            "the first captured locator holds; the third peer does not re-point it"
        );
        assert_eq!(
            actions.scouted_hellos().len(),
            3,
            "all three are still recorded — first-wins governs the dial target only"
        );
    }

    /// The negative arm that keeps the three above from being tautologies: a
    /// window that really did time out records NOTHING, so "one record" above
    /// cannot be satisfied by an unconditional push.
    #[test]
    fn a_timed_out_window_records_no_hello() {
        let actions = fixture_actions();
        let mut engine = new_scouting_engine(&actions);
        engine.initialize();
        engine.process_event(ScoutingEvent::SessionOpenRequested);
        engine.process_event(ScoutingEvent::ScoutTxDone);
        engine.process_event(ScoutingEvent::ScoutTimerElapsed);
        assert!(actions.scouted_hellos().is_empty());
        assert!(actions.discovered_locator().is_none());
    }

    // ── drive-loop level: the ingress filter and the per-Hello observer ──

    /// A scouting link that hands the loop a scripted datagram list and then
    /// never resolves, so `select!` falls through to the deadline tick.
    struct ScriptedScoutLink {
        inbound: std::collections::VecDeque<Vec<u8>>,
        sent: Vec<Vec<u8>>,
    }

    impl ScriptedScoutLink {
        fn with(inbound: impl IntoIterator<Item = Vec<u8>>) -> Self {
            Self {
                inbound: inbound.into_iter().collect(),
                sent: Vec::new(),
            }
        }
    }

    impl LinkDriver for ScriptedScoutLink {
        async fn open(&mut self) -> std::io::Result<()> {
            Ok(())
        }
        async fn send(
            &mut self,
            frame: &TxFrame<'_>,
            _reliability: Reliability,
        ) -> std::io::Result<()> {
            self.sent.push(frame.bytes.to_vec());
            Ok(())
        }
        async fn close(&mut self) -> std::io::Result<()> {
            Ok(())
        }
        async fn poll_event(&mut self) -> LinkEvent {
            if let Some(bytes) = self.inbound.pop_front() {
                return LinkEvent::Rx(wz_session_core::link::RxFrame::new(bytes));
            }
            // Drained: never resolve, so the loop reaches its deadline.
            core::future::pending().await
        }
    }

    /// A datagram carrying the Hello MID that does NOT decode is dropped by
    /// the loop's ingress filter — pico `continue`s on a failed
    /// `_z_scouting_message_decode` (`src/session/scout.c:71-76`).
    ///
    /// The mode here is exit_on_first, which is where it BITES: if the
    /// malformed datagram reached the FSM it would take the exit arm, and the
    /// cycle would end having discovered nothing — a scouting window that any
    /// sender on the untrusted multicast group could close with three bytes.
    /// The assertion pairs "timed out" with "the well-formed Hello that
    /// arrived AFTER it was still recorded", so the test cannot pass by the
    /// loop simply dying.
    #[tokio::test]
    async fn a_malformed_hello_neither_records_nor_ends_an_exit_on_first_window() {
        let malformed = vec![wire_const::S_MID_HELLO | wire_const::FLAG_S_HELLO_L, 0x09];
        let good = craft_hello_with(0x01, &[0xA1], &["udp/127.0.0.1:7447"]);
        let mut driver = ScriptedScoutLink::with([malformed, good]);
        let actions = ScoutingActions::new(ScoutParams {
            what: 0x03,
            zid: vec![0xAA],
            timeout_ms: 400,
            exit_on_first: true,
        });
        let mut engine = new_scouting_engine(&actions);
        let clock = TokioTime::new();

        let outcome =
            drive_scouting_until_resolved(&mut driver, &actions, &mut engine, &clock, None, 5)
                .await;

        assert_eq!(
            outcome,
            ScoutOutcome::Discovered("udp/127.0.0.1:7447".into()),
            "the malformed datagram must not have ended the window"
        );
        let hellos = actions.scouted_hellos();
        assert_eq!(hellos.len(), 1, "only the well-formed Hello is a peer");
        assert_eq!(hellos[0].zid, vec![0xA1]);
        assert_eq!(
            actions.trace_snapshot().record_hello,
            1,
            "the action never ran for the malformed datagram"
        );
        assert_eq!(actions.trace_snapshot().scout_timeout, 0);
    }

    /// A Scout datagram carrying `zid`, built through the CODEC.
    ///
    /// Not by hand: the id rides an `I` flag as well as the `zid_len_m1`
    /// nibble, so hand-assembled bytes decode to `zid: None` and every
    /// self-echo silently reads as a stranger. Measured — that is exactly how
    /// the first draft of the conservation test below failed.
    fn craft_scout_with(zid: &[u8]) -> Vec<u8> {
        let mut scout = Scout::new();
        scout.version = 0x09;
        scout.set_what(0x03);
        scout.set_i(true);
        scout.set_zid_len_m1((zid.len() - 1) as u8);
        scout.zid = Some(zid);
        let mut wire = vec![wire_const::S_MID_SCOUT];
        wire.extend_from_slice(&scout.encode_to_vec());
        wire
    }

    /// R2334 — CONSERVATION. Every datagram the window observes lands in
    /// EXACTLY ONE of the two accumulators, and none is dropped silently.
    ///
    /// This is the check the `scouting-active` residual actually wanted. That
    /// residual named one drop site (the MID filter); there were two, and the
    /// thing that makes a THIRD impossible is not another named site but this
    /// arithmetic — `hellos + ignored == observed`. A future arm added to the
    /// `Rx` match that forgets to account for its datagram fails here, whatever
    /// shape it takes and whatever it logs.
    ///
    /// The window runs the SURVEY arm so it does not exit on the first Hello,
    /// which is what lets one window observe all five shapes.
    #[tokio::test]
    async fn every_observed_datagram_lands_in_exactly_one_accumulator() {
        const OUR_ZID: &[u8] = &[0xAA];
        let observed: Vec<Vec<u8>> = vec![
            // 1. a usable Hello -> `hellos`
            craft_hello_with(0x01, &[0xA1], &["udp/127.0.0.1:7447"]),
            // 2. Hello MID, undecodable body -> pico's "malformed message"
            vec![wire_const::S_MID_HELLO | wire_const::FLAG_S_HELLO_L, 0x09],
            // 3. our own Scout, back from IP_MULTICAST_LOOP
            craft_scout_with(OUR_ZID),
            // 4. another node's Scout: a question, not our answer
            craft_scout_with(&[0x77]),
            // 5. a MID in neither arm -> pico's `default:`
            vec![0x1E, 0x00, 0x00],
        ];
        let count = observed.len();
        let mut driver = ScriptedScoutLink::with(observed);
        let actions = ScoutingActions::new(ScoutParams {
            what: 0x03,
            zid: OUR_ZID.to_vec(),
            timeout_ms: 400,
            exit_on_first: false,
        });
        let mut engine = new_scouting_engine(&actions);
        let clock = TokioTime::new();

        drive_scouting_until_resolved(&mut driver, &actions, &mut engine, &clock, None, 5).await;

        let hellos = actions.scouted_hellos();
        let ignored = actions.ignored_datagrams();
        assert_eq!(
            hellos.len() + ignored.len(),
            count,
            "every observed datagram must be accounted for exactly once; \
             hellos={hellos:?} ignored={ignored:?}",
        );
        assert_eq!(hellos.len(), 1, "only the well-formed Hello is a peer");
        // In arrival order, and each naming what it was — the residual asked
        // for observability, so the RECORD has to be specific, not a count.
        assert_eq!(
            ignored,
            vec![
                ScoutRxIgnored::Undecodable,
                ScoutRxIgnored::SelfEcho,
                ScoutRxIgnored::ForeignScout,
                ScoutRxIgnored::UnknownMid { mid: 0x1E },
            ],
        );
    }

    /// DISCRIMINATOR for the arm above: the self-echo verdict must depend on
    /// OUR zid, not on "it was a Scout".
    ///
    /// Same window, same datagram, different `ScoutParams::zid` — the verdict
    /// must move from `SelfEcho` to `ForeignScout`. Without this the
    /// conservation test would pass on a loop that called every Scout its own
    /// echo, which is the classification a reader would most likely write by
    /// accident and which would hide a real peer's question.
    #[tokio::test]
    async fn the_self_echo_verdict_follows_our_own_zid() {
        let echoed = craft_scout_with(&[0xAA]);
        let mut driver = ScriptedScoutLink::with([echoed]);
        let actions = ScoutingActions::new(ScoutParams {
            what: 0x03,
            // NOT the zid in the datagram above.
            zid: vec![0xBB],
            timeout_ms: 200,
            exit_on_first: false,
        });
        let mut engine = new_scouting_engine(&actions);
        let clock = TokioTime::new();

        drive_scouting_until_resolved(&mut driver, &actions, &mut engine, &clock, None, 5).await;

        assert_eq!(
            actions.ignored_datagrams(),
            vec![ScoutRxIgnored::ForeignScout],
            "a Scout carrying somebody else's zid is not our loopback",
        );
    }

    /// R2610 — ONE empty answer must not close the session-open scout.
    ///
    /// The exit-on-first arm is the implicit scout a session open runs, and the
    /// group it listens on is untrusted, so "a Hello ends the window" hands
    /// anyone on that group a way to end everybody's discovery with a datagram
    /// that costs nothing to send. Both references keep looking past it.
    /// zenoh-pico declines to RECORD it, which is what its break reads:
    /// `vendor/zenoh-pico/src/session/scout.c` @ `if ((locator_count == 0) && exit_on_first) {`
    /// And zenoh's scout callback returns `Loop::Continue` at
    /// `zenoh/src/net/runtime/orchestrator.rs` @ `if !hello.locators.is_empty() {`
    ///
    /// The second responder is what makes this a POSITIVE claim rather than the
    /// absence of one: the window must go on to discover the peer that did
    /// advertise an address, so a loop that merely dropped the first datagram on
    /// the floor would still have to reach it.
    #[tokio::test]
    async fn a_locator_less_hello_does_not_end_an_exit_on_first_window() {
        let mut driver = ScriptedScoutLink::with([
            craft_hello_with(0x01, &[0xA1], &[]),
            craft_hello_with(0x01, &[0xB2], &["udp/127.0.0.1:7447"]),
        ]);
        let actions = ScoutingActions::new(ScoutParams {
            what: 0x03,
            zid: vec![0xAA],
            timeout_ms: 400,
            exit_on_first: true,
        });
        let mut engine = new_scouting_engine(&actions);
        let clock = TokioTime::new();

        let outcome =
            drive_scouting_until_resolved(&mut driver, &actions, &mut engine, &clock, None, 5)
                .await;

        assert_eq!(
            outcome,
            ScoutOutcome::Discovered("udp/127.0.0.1:7447".into()),
            "the empty answer must not have ended the window before the real peer",
        );
        assert_eq!(
            actions.scouted_hellos().len(),
            1,
            "only the peer that advertised an address is a discovery",
        );
        assert_eq!(
            actions.trace_snapshot().record_hello,
            1,
            "the declined Hello never reached the FSM action",
        );
        assert_eq!(
            actions.ignored_datagrams(),
            vec![ScoutRxIgnored::LocatorlessHello],
            "and it is ACCOUNTED for, not dropped silently",
        );
    }

    /// ONE Scout carries a whole survey window, and every responder in it is
    /// recorded — the drive-loop twin of the FSM-level survey test.
    ///
    /// The Scout count is the half the FSM-level test cannot see: the old
    /// consumers re-entered whole scouting CYCLES to reach a second peer, and
    /// each cycle re-emitted a Scout onto the group. `sent.len() == 1` is what
    /// says that is gone, and it is upstream's arithmetic — `__z_scout_loop`
    /// sends the wbuf once and then reads until `period` elapses
    /// (`src/session/scout.c:56-63`).
    #[tokio::test]
    async fn one_scout_carries_the_whole_survey_window() {
        let mut driver = ScriptedScoutLink::with([
            craft_hello_with(0x01, &[0xA1], &["udp/127.0.0.1:7447"]),
            craft_hello_with(0x02, &[0xB2], &["udp/127.0.0.1:7448"]),
        ]);
        let actions = ScoutingActions::new(ScoutParams {
            what: 0x03,
            zid: vec![0xAA],
            timeout_ms: 400,
            exit_on_first: false,
        });
        let mut engine = new_scouting_engine(&actions);
        let clock = TokioTime::new();

        let outcome =
            drive_scouting_until_resolved(&mut driver, &actions, &mut engine, &clock, None, 5)
                .await;

        assert_eq!(
            outcome,
            ScoutOutcome::Discovered("udp/127.0.0.1:7447".into())
        );
        assert_eq!(
            actions
                .scouted_hellos()
                .iter()
                .map(|h| h.zid.clone())
                .collect::<Vec<_>>(),
            vec![vec![0xA1], vec![0xB2]],
            "both responders are in the record when the window closes"
        );
        assert_eq!(
            driver.sent.len(),
            1,
            "ONE Scout for the whole survey — pico sends one and listens"
        );
        assert_eq!(
            actions.trace_snapshot().scout_timeout,
            1,
            "and it is the deadline that closed it, not a peer"
        );
    }
}
