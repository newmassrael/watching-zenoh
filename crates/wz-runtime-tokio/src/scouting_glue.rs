// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311ep — scouting FSM <-> multicast-link glue (active mode).
//!
//! Wires the four `scouting.scxml` script actions
//! (`sources/session/scouting.scxml`, codegen'd into
//! [`crate::scouting_fsm`]) onto a Lua engine and drives the FSM against
//! a UDP-multicast scouting link. This is the B-2 body of the
//! scouting-subsystem implementation begun by the R311en scaffold; it
//! turns "find a peer to handshake with" into a concrete unicast locator
//! the session FSM can dial (docs/scouting-fsm.md §1.1, §2.4.1).
//!
//! ## IO ownership — actions are pure, the loop owns the socket
//!
//! The session glue's outbound actions (`send_init_syn`, …) call
//! `BoxedLinkDriver::send_blocking`, which bridges the sync Lua callback
//! to the async link via `Handle::block_on` (session_glue.rs ~315, with
//! a documented current-thread-runtime deadlock caveat). Scouting takes
//! the cleaner path: the script actions are **pure** — `scout_emit`
//! encodes a Scout frame and stages the bytes in
//! [`ScoutingActions::pending_scout`]; `record_hello_and_emit` decodes a
//! staged Hello and stores the locator. All socket IO lives in the async
//! [`drive_scouting_until_resolved`] loop, which owns the `&mut` link
//! driver. This (a) avoids `block_on` entirely, (b) keeps the actions
//! trivially unit-testable without a socket, and (c) makes the
//! `link.tx_failed` arm real: a failed multicast send feeds
//! `LinkTxFailed` instead of being unreachable.
//!
//! A single UDP multicast socket both sends the Scout and receives the
//! Hello (zenoh-pico `__z_scout` does the same: send the wbuf, then read
//! replies on the same link). The session glue could split a TCP stream
//! into read/write halves to give the actions and the loop independent
//! handles, but a UDP socket has no such split, so loop-owned IO is the
//! natural fit.

use std::sync::Arc;

use sce_forge_runtime::codec::SceCursor;
use sce_rust_lua::LuaEngine;
use sce_rust_runtime::scripting::IScriptEngine;
use sce_rust_runtime::Engine;

use wz_codecs::hello::Hello;
use wz_codecs::scout::Scout;
use wz_codecs::wire_const;
use wz_session_core::link::{LinkEvent, LostCause, TxFrame};
use wz_session_core::reliability::Reliability;
use wz_session_core::scout_params::ScoutParams;
use wz_session_core::scout_trace::ScoutTrace;

use wz_runtime_core::{Runtime, TimeSource};

use crate::runtime_impl::TokioRuntime;
use crate::scouting_fsm::{ScoutingEvent, ScoutingPolicy, ScoutingState};
use crate::script_bind::bind_unit;
use crate::sync::Mutex;
use crate::LinkDriver;

/// SCE-runtime session id the generated scouting state-machine
/// dispatches against — the `name="scouting"` attribute of
/// `sources/session/scouting.scxml`.
pub const SCOUTING_SESSION_ID: &str = "scouting";

/// Deps bundle captured by the four scouting script-action closures.
///
/// Distinct from [`crate::session_glue::SessionLinkActions`] (the session
/// handshake bundle): scouting is a pre-session, untrusted-link
/// subsystem, so its parameters / trace / staging slots are not folded
/// into the session bundle. Generic over the runtime `R` to match the
/// crate's `R::Mutex` convention; the AP profile (`TokioRuntime`, the
/// only one that compiles `scouting-active` today since it implies
/// `transport-link-udp`) is constructed via [`ScoutingActions::new`].
pub struct ScoutingActions<R: Runtime = TokioRuntime> {
    /// Inputs for the outbound Scout frame (version / what / zid).
    pub params: ScoutParams,
    /// Script-action dispatch counters, read in tests via
    /// [`ScoutingActions::trace_snapshot`].
    pub trace: R::Mutex<ScoutTrace>,
    /// Set by `scout_emit`: the fully-framed Scout datagram
    /// (`[S_MID_SCOUT][version][cbyte][zid]`) awaiting transmission. The
    /// drive loop takes it, sends it on the multicast link, and clears
    /// the slot.
    pub pending_scout: R::Mutex<Option<Vec<u8>>>,
    /// Set by the drive loop before it feeds `HelloReceived`: the raw
    /// inbound Hello datagram (`[S_MID_HELLO|flags][hello body]`).
    /// `record_hello_and_emit` decodes it and clears the slot.
    pub pending_hello: R::Mutex<Option<Vec<u8>>>,
    /// The discovered peer locator string (e.g. `"udp/127.0.0.1:7447"`),
    /// extracted by `record_hello_and_emit` from the first Hello locator.
    /// `None` until a Hello with a locator arrives (active MVP =
    /// exit-on-first, so a single locator is captured;
    /// `deploy.scouting.hello_max_peers` bounds the deferred passive
    /// multi-peer accumulator, Phase D+ / OQ-W23).
    pub discovered: R::Mutex<Option<String>>,
}

impl ScoutingActions<TokioRuntime> {
    /// Construct an active-scouting action bundle for one discovery
    /// cycle. `params` are captured by value; the staging slots start
    /// empty.
    pub fn new(params: ScoutParams) -> Arc<Self> {
        Arc::new(Self {
            params,
            trace: TokioRuntime::new_mutex(ScoutTrace::default()),
            pending_scout: Mutex::new(None),
            pending_hello: Mutex::new(None),
            discovered: Mutex::new(None),
        })
    }

    /// Field-by-field `Copy` snapshot of the dispatch counters, lifted
    /// out from under the runtime mutex.
    pub fn trace_snapshot(&self) -> ScoutTrace {
        self.trace.lock().unwrap().clone_via_copy()
    }

    /// The discovered locator, if a Hello locator was captured.
    pub fn discovered_locator(&self) -> Option<String> {
        self.discovered.lock().unwrap().clone()
    }
}

/// Register the four scouting script actions onto `script_engine` and
/// create the SCE-runtime scouting session. Mirrors
/// [`crate::session_glue::install_session_actions`]; each closure
/// captures a clone of `actions` via the generic
/// [`crate::script_bind::bind_unit`] binder.
pub fn install_scouting_actions(
    actions: Arc<ScoutingActions>,
    script_engine: &Arc<dyn IScriptEngine>,
) {
    script_engine.create_session(SCOUTING_SESSION_ID);
    register_scout_fns(script_engine.as_ref(), &actions);
}

/// Bind the four `scouting.scxml` script-action names. Public so a
/// future test-support composition can vary the registration set; the
/// production path reaches this through [`install_scouting_actions`].
pub fn register_scout_fns(lua: &dyn IScriptEngine, actions: &Arc<ScoutingActions>) {
    // Sending.onentry — encode one Scout frame and stage the datagram
    // for the drive loop to transmit. Pure: no socket access. Mirrors
    // zenoh-pico scout.c:57 `_z_link_send_wbuf`, except the send itself
    // is the loop's job (see module doc).
    bind_unit(lua, "scout_emit", actions, |a| {
        a.trace.lock().unwrap().scout_emit += 1;
        let zid = &a.params.zid;
        let mut scout = Scout::new();
        scout.version = a.params.version;
        scout.set_what(a.params.what);
        if !zid.is_empty() {
            // I=1 + zid_len_m1 packed into cbyte, then the id bytes
            // (scout.scxml present-if gate, zenoh-pico message.c:611-616).
            scout.set_i(true);
            scout.set_zid_len_m1((zid.len() - 1) as u8);
            scout.zid = Some(zid);
        }
        let body = scout.encode_to_vec();
        let mut datagram = Vec::with_capacity(1 + body.len());
        // Scouting-message envelope: prepend the MID header byte the
        // body codec omits (mirror of session_glue prepending T_MID_*).
        datagram.push(wire_const::S_MID_SCOUT);
        datagram.extend_from_slice(&body);
        *a.pending_scout.lock().unwrap() = Some(datagram);
    });

    // AwaitingHello -> Idle on hello.received — decode the staged Hello
    // datagram and capture its first locator (exit-on-first MVP).
    bind_unit(lua, "record_hello_and_emit", actions, |a| {
        a.trace.lock().unwrap().record_hello += 1;
        let bytes = match a.pending_hello.lock().unwrap().take() {
            Some(b) => b,
            None => return,
        };
        if bytes.is_empty() {
            return;
        }
        // header byte carries the MID (low 5 bits, already matched to
        // HELLO by the loop) and the locators-present flag in bit 5; the
        // hello body codec wants that flag projected to its 1-bit `l`.
        // The decode borrows `bytes`, so confine it to an inner scope
        // that yields an owned locator string before `bytes` drops.
        let locator: Option<String> = {
            let l = (bytes[0] >> 5) & 1;
            let mut cursor = SceCursor::new(&bytes[1..]);
            match Hello::decode(&mut cursor, l) {
                Ok(hello) => hello
                    .locators
                    .as_ref()
                    .and_then(|locs| locs.iter().next())
                    .map(|first| first.locator.to_string()),
                Err(_) => None,
            }
        };
        if let Some(loc) = locator {
            *a.discovered.lock().unwrap() = Some(loc);
        }
    });

    // AwaitingHello -> Idle on scout.timer.elapsed — the window expired
    // with no Hello. Observability only; `discovered` stays None.
    bind_unit(lua, "emit_scout_timeout", actions, |a| {
        a.trace.lock().unwrap().scout_timeout += 1;
    });

    // Sending -> Idle on link.tx_failed — the multicast Scout transmit
    // errored. Fed by the drive loop when `driver.send` returns Err.
    bind_unit(lua, "diag_scout_tx_failed", actions, |a| {
        a.trace.lock().unwrap().tx_failed += 1;
    });
}

/// Build a production scouting engine: a fresh `LuaEngine` with the four
/// actions installed, wrapped in an [`Engine`] over the generated
/// [`ScoutingPolicy`]. The caller drives it with
/// [`drive_scouting_until_resolved`].
pub fn new_scouting_engine(actions: &Arc<ScoutingActions>) -> Engine<ScoutingPolicy> {
    let lua: Arc<dyn IScriptEngine> = Arc::new(LuaEngine::new());
    install_scouting_actions(actions.clone(), &lua);
    Engine::new(ScoutingPolicy::new(lua))
}

/// Outcome of one active-scouting cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScoutOutcome {
    /// A Hello arrived and a locator was captured.
    Discovered(String),
    /// The scouting window elapsed with no usable Hello.
    TimedOut,
    /// The scouting link was lost before resolution.
    LinkLost(LostCause),
    /// The bounded iteration budget was exhausted (test guard).
    IterationLimit,
}

/// Drive one active-scouting cycle to resolution: emit a Scout on the
/// multicast `driver`, then await a Hello until the `scouting.scxml`
/// timer (`AwaitingHello.onentry <send delay>`) elapses.
///
/// The SCXML `<send delay>` is serviced by the SCE engine's own
/// scheduler (real host monotonic clock via the runtime `Hal`), so the
/// loop calls [`Engine::tick`] on a `tick_interval_ms` cadence to give
/// the scheduler a chance to fire `scout.timer.elapsed`. The cadence is
/// a host polling detail; the window duration itself stays the SCXML's
/// single source of truth (it is not duplicated here). A Hello datagram
/// races the cadence via `poll_event`, so the common case resolves as
/// soon as the peer replies.
///
/// `max_iters` bounds the select loop for tests; production passes
/// `None`. Returns once the FSM returns to `Idle` (Hello captured or
/// timed out) or the link is lost.
pub async fn drive_scouting_until_resolved<D, T>(
    driver: &mut D,
    actions: &Arc<ScoutingActions>,
    engine: &mut Engine<ScoutingPolicy>,
    clock: &T,
    max_iters: Option<usize>,
    tick_interval_ms: u64,
) -> ScoutOutcome
where
    D: LinkDriver,
    T: TimeSource,
{
    engine.initialize();
    // Idle -> Sending: scout_emit fires on Sending.onentry and stages
    // the datagram.
    engine.process_event(ScoutingEvent::SessionOpenRequested);
    // Transmit the staged Scout; the send result drives the
    // Sending -> AwaitingHello (tx.done) vs Sending -> Idle (tx_failed)
    // branch.
    let staged = actions.pending_scout.lock().unwrap().take();
    match staged {
        Some(datagram) => {
            let frame = TxFrame { bytes: &datagram };
            match driver.send(&frame, Reliability::BestEffort).await {
                Ok(()) => engine.process_event(ScoutingEvent::ScoutTxDone),
                Err(_) => engine.process_event(ScoutingEvent::LinkTxFailed),
            }
        }
        // scout_emit failed to stage (should not happen) — treat as a
        // transmit failure so the FSM returns to Idle deterministically.
        None => engine.process_event(ScoutingEvent::LinkTxFailed),
    }

    let mut iter: usize = 0;
    loop {
        if engine.get_current_state() == ScoutingState::Idle {
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
                LinkEvent::Rx(rx) => {
                    // Only Hello datagrams advance the FSM. With
                    // set_multicast_loop_v4(true) our own Scout echoes
                    // back (MID 0x01); the MID filter drops it.
                    if rx.bytes.first().map(|h| h & 0x1f) == Some(wire_const::S_MID_HELLO) {
                        *actions.pending_hello.lock().unwrap() = Some(rx.bytes);
                        engine.process_event(ScoutingEvent::HelloReceived);
                    }
                }
                LinkEvent::Lost { cause } => return ScoutOutcome::LinkLost(cause),
                LinkEvent::Ready => {}
            },
            _ = clock.sleep(tick_interval_ms) => {
                // Let the SCE scheduler fire scout.timer.elapsed if the
                // SCXML window has elapsed (-> emit_scout_timeout -> Idle).
                engine.tick();
            }
        }
    }

    match actions.discovered_locator() {
        Some(locator) => ScoutOutcome::Discovered(locator),
        None => ScoutOutcome::TimedOut,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_actions() -> Arc<ScoutingActions> {
        ScoutingActions::new(ScoutParams {
            version: 0x09,
            what: 0x03, // ROUTER | PEER
            zid: vec![0xAA, 0xBB, 0xCC, 0xDD],
        })
    }

    /// `scout_emit` (Sending.onentry) stages a correctly-framed Scout
    /// datagram: MID header + version + cbyte(what|I|zid_len_m1) + zid.
    #[test]
    fn scout_emit_stages_framed_datagram() {
        let actions = fixture_actions();
        let lua: Arc<dyn IScriptEngine> = Arc::new(LuaEngine::new());
        install_scouting_actions(actions.clone(), &lua);
        let mut engine = Engine::new(ScoutingPolicy::new(lua));
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
        let lua: Arc<dyn IScriptEngine> = Arc::new(LuaEngine::new());
        install_scouting_actions(actions.clone(), &lua);
        let mut engine = Engine::new(ScoutingPolicy::new(lua));
        engine.initialize();
        engine.process_event(ScoutingEvent::SessionOpenRequested);
        engine.process_event(ScoutingEvent::ScoutTxDone);
        assert_eq!(engine.get_current_state(), ScoutingState::AwaitingHello);

        // Stage a Hello carrying one locator, then drive the FSM.
        *actions.pending_hello.lock().unwrap() = Some(craft_hello_datagram("udp/127.0.0.1:7447"));
        engine.process_event(ScoutingEvent::HelloReceived);

        assert_eq!(engine.get_current_state(), ScoutingState::Idle);
        assert_eq!(actions.trace_snapshot().record_hello, 1);
        assert_eq!(
            actions.discovered_locator().as_deref(),
            Some("udp/127.0.0.1:7447")
        );
    }

    /// `scout.timer.elapsed` (no Hello) routes through
    /// `emit_scout_timeout` and leaves `discovered` unset.
    #[test]
    fn scout_timeout_leaves_no_locator() {
        let actions = fixture_actions();
        let lua: Arc<dyn IScriptEngine> = Arc::new(LuaEngine::new());
        install_scouting_actions(actions.clone(), &lua);
        let mut engine = Engine::new(ScoutingPolicy::new(lua));
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
        use wz_codecs::hello::HelloOwned;
        use wz_codecs::locator::LocatorOwned;

        let zid = vec![0x01, 0x02, 0x03];
        // cbyte: whatami wire-form (low 2 bits) | zid_len_m1 << 4.
        let cbyte = 0x01 | (((zid.len() as u8) - 1) << 4);
        let body = HelloOwned {
            version: 0x09,
            cbyte,
            zid,
            num_locators: Some(1),
            locators: Some(vec![LocatorOwned {
                locator_len: locator.len() as u64,
                locator: locator.to_string(),
            }]),
        }
        .try_as_borrowed()
        .expect("borrowed projection of owned Hello")
        .encode_to_vec(1 /* L flag projected */);

        let mut dgram = Vec::with_capacity(1 + body.len());
        dgram.push(wire_const::S_MID_HELLO | wire_const::FLAG_S_HELLO_L);
        dgram.extend_from_slice(&body);
        dgram
    }
}
