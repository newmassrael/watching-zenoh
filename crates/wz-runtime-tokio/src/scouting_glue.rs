// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//! `record_hello_and_emit` decodes a staged Hello and stores the locator.
//! All socket IO lives in the async [`drive_scouting_until_resolved`]
//! loop, which owns the `&mut` link driver. This (a) keeps the actions
//! trivially unit-testable without a socket, and (b) makes the
//! `link.tx_failed` arm real: a failed multicast send feeds `LinkTxFailed`
//! instead of being unreachable.
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
//! clock and raises [`ScoutingEvent::ScoutTimerElapsed`] when it elapses.
//! Mirrors the reassembly dispatcher's deadline-sweep split (FSM owns the
//! transition, runtime owns the clock; the value stays spec-sourced).

use std::sync::Arc;

use sce_forge_runtime::codec::SceCursor;
use sce_rust_runtime::Engine;

use wz_codecs::hello::Hello;
use wz_codecs::scout::Scout;
use wz_codecs::wire_const;
use wz_session_core::link::{LinkEvent, LostCause, TxFrame};
use wz_session_core::reliability::Reliability;
use wz_session_core::scout_params::ScoutParams;
use wz_session_core::scout_trace::ScoutTrace;
// The generated engine-free action trait. Aliased so the trait name does
// not shadow the host-side [`ScoutingActions`] state struct below (the
// struct holds the shared staging slots the caller reads; the trait is
// what the generated policy dispatches through).
use wz_session_core::scouting::ScoutingActions as ScoutingActionsTrait;
use wz_session_core::scouting::{ScoutingEvent, ScoutingPolicy, ScoutingState};

use wz_runtime_core::{Runtime, TimeSource};

use crate::runtime_impl::TokioRuntime;
use crate::sync::Mutex;
use crate::LinkDriver;

/// Shared host state for one active-scouting cycle.
///
/// Distinct from [`crate::session_glue::SessionLinkActions`] (the session
/// handshake bundle): scouting is a pre-session, untrusted-link
/// subsystem, so its parameters / trace / staging slots are not folded
/// into the session bundle. Generic over the runtime `R` to match the
/// crate's `R::Mutex` convention; the AP profile (`TokioRuntime`, the
/// only one that compiles `scouting-active` today since it implies
/// `transport-link-udp`) is constructed via [`ScoutingActions::new`].
///
/// The caller holds this behind an `Arc`; [`new_scouting_engine`] wraps a
/// clone of that `Arc` in a [`ScoutActionsBinding`] for the policy to own,
/// so the caller can still read [`ScoutingActions::discovered_locator`] /
/// [`ScoutingActions::trace_snapshot`] after the policy takes the binding.
pub struct ScoutingActions<R: Runtime = TokioRuntime> {
    /// Inputs for the outbound Scout frame + the scouting deadline
    /// (version / what / zid / timeout_ms).
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
    /// Construct an active-scouting state bundle for one discovery cycle.
    /// `params` are captured by value; the staging slots start empty.
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

/// Thin newtype that carries the generated [`ScoutingActionsTrait`] impl
/// for the policy to own by value. Wraps a clone of the caller's
/// `Arc<`[`ScoutingActions`]`>` so the four native actions mutate the same
/// shared staging slots the caller reads back (the orphan rule forbids
/// impl'ing the foreign trait on `Arc<ScoutingActions>` directly).
pub struct ScoutActionsBinding<R: Runtime = TokioRuntime> {
    inner: Arc<ScoutingActions<R>>,
}

// Concrete `TokioRuntime` impl: the actions reach through the runtime
// `R::Mutex` staging slots, and only `TokioRuntime`'s `Mutex` (std
// `std::sync::Mutex`) exposes `.lock()` here — `scouting-active` is an
// AP-only feature (it implies `transport-link-udp`), so the single
// concrete impl matches `ScoutingActions<TokioRuntime>`'s inherent impl.
impl ScoutingActionsTrait for ScoutActionsBinding<TokioRuntime> {
    /// Idle -> Sending entering transition — encode one Scout frame and
    /// stage the datagram for the drive loop to transmit. Pure: no socket
    /// access. Mirrors zenoh-pico scout.c:57 `_z_link_send_wbuf`, except
    /// the send itself is the loop's job (see module doc).
    fn scout_emit(&mut self) {
        let a = &self.inner;
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
        // Scouting-message envelope: prepend the MID header byte the body
        // codec omits (mirror of session_glue prepending T_MID_*).
        datagram.push(wire_const::S_MID_SCOUT);
        datagram.extend_from_slice(&body);
        *a.pending_scout.lock().unwrap() = Some(datagram);
    }

    /// AwaitingHello -> Idle on hello.received — decode the staged Hello
    /// datagram and capture its first locator (exit-on-first MVP).
    fn record_hello_and_emit(&mut self) {
        let a = &self.inner;
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
        // The decode borrows `bytes`, so confine it to an inner scope that
        // yields an owned locator string before `bytes` drops.
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
    }

    /// AwaitingHello -> Idle on scout.timer.elapsed — the window expired
    /// with no Hello. Observability only; `discovered` stays None.
    fn emit_scout_timeout(&mut self) {
        self.inner.trace.lock().unwrap().scout_timeout += 1;
    }

    /// Sending -> Idle on link.tx_failed — the multicast Scout transmit
    /// errored. Fed by the drive loop when `driver.send` returns Err.
    fn diag_scout_tx_failed(&mut self) {
        self.inner.trace.lock().unwrap().tx_failed += 1;
    }
}

/// Build a production scouting engine: an [`Engine`] over the generated
/// engine-free [`ScoutingPolicy`], parameterised over a
/// [`ScoutActionsBinding`] wrapping a clone of `actions`. The caller
/// retains `actions` and drives the engine with
/// [`drive_scouting_until_resolved`].
pub fn new_scouting_engine(
    actions: &Arc<ScoutingActions>,
) -> Engine<ScoutingPolicy<ScoutActionsBinding>> {
    let binding = ScoutActionsBinding {
        inner: actions.clone(),
    };
    Engine::new(ScoutingPolicy::new(binding))
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
/// multicast `driver`, then await a Hello until the
/// [`ScoutParams::timeout_ms`] window elapses.
///
/// The engine-free FSM arms no timer of its own (engine-free no_std binds
/// `NoOpHal`, so a `<send delay>` would never fire), so this loop owns the
/// clock: it records a monotonic start instant on entry and raises
/// [`ScoutingEvent::ScoutTimerElapsed`] once `timeout_ms` has elapsed with
/// no Hello (driving the FSM's `AwaitingHello -> Idle` timeout). A Hello
/// datagram races the `tick_interval_ms` cadence via `poll_event`, so the
/// common case resolves as soon as the peer replies. The window duration
/// is the spec-sourced `ScoutParams::timeout_ms`, not duplicated here.
///
/// `max_iters` bounds the select loop for tests; production passes `None`.
/// Returns once the FSM returns to `Idle` (Hello captured or timed out) or
/// the link is lost.
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
    engine.initialize();
    // Idle -> Sending: scout_emit fires on the entering transition and
    // stages the datagram.
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

    // The host owns the scout deadline (see module doc). Measure the
    // spec-sourced window against the runtime monotonic clock.
    let deadline_ms = actions.params.timeout_ms;
    let start_ms = clock.now_monotonic_ms();

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
                // Raise the timeout once the spec-sourced window has
                // elapsed with no Hello (-> emit_scout_timeout -> Idle).
                // Only AwaitingHello handles the event; firing it in any
                // other state is a no-op transition in the generated FSM.
                if clock.now_monotonic_ms().saturating_sub(start_ms) >= deadline_ms
                    && engine.get_current_state() == ScoutingState::AwaitingHello
                {
                    engine.process_event(ScoutingEvent::ScoutTimerElapsed);
                }
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
            timeout_ms: 1000,
        })
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
        *actions.pending_hello.lock().unwrap() = Some(craft_hello_datagram("udp/127.0.0.1:7447"));
        engine.process_event(ScoutingEvent::HelloReceived);

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
        use wz_codecs::hello::HelloOwned;
        use wz_codecs::locator::LocatorOwned;

        let zid = vec![0x01, 0x02, 0x03];
        // cbyte: whatami wire-form (low 2 bits) | zid_len_m1 << 4.
        let cbyte = 0x01 | (((zid.len() as u8) - 1) << 4);
        let body = HelloOwned {
            version: 0x09,
            cbyte,
            zid: wz_session_core::codec_owned::owned_bytes(&zid).unwrap(),
            num_locators: Some(1),
            locators: Some(vec![LocatorOwned {
                locator_len: locator.len() as u64,
                locator: wz_session_core::codec_owned::owned_string(locator).unwrap(),
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
