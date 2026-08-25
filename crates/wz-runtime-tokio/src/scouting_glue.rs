// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//! clock and raises [`ScoutingEvent::ScoutTimerElapsed`] when it elapses.
//! Mirrors the reassembly dispatcher's deadline-sweep split (FSM owns the
//! transition, runtime owns the clock; the value stays spec-sourced).

use std::sync::Arc;

use sce_forge_runtime::codec::SceCursor;
use sce_rust_runtime::Engine;

use wz_codecs::hello::Hello;
use wz_codecs::scout::Scout;
use wz_codecs::whatami::WhatAmI;
use wz_codecs::wire_const;
use wz_session_core::link::{LinkEvent, LostCause, TxFrame};
use wz_session_core::reliability::Reliability;
// R311y428 — `pub` (was a private `use`): re-exported alongside the
// `ScoutingActions::new` it parameterises, mirroring `session_glue`'s
// `SessionInitParams` / `WhatAmI` re-export (session_glue.rs:178) and for the
// same reason. A consumer reaches this crate through the wz facade
// (`wz::runtime_tokio::*`), which re-exports no `wz-session-core` path of its
// own, so without this the module's own public constructor cannot be CALLED
// from there — its parameter type is unnameable. The in-tree tests never hit
// it: they carry a direct wz-session-core dev-dep the facade's consumers lack.
pub use wz_session_core::scout_params::ScoutParams;
use wz_session_core::scout_trace::ScoutTrace;
// The generated engine-free action trait. Aliased so the trait name does
// not shadow the host-side [`ScoutingActions`] state struct below (the
// struct holds the shared staging slots the caller reads; the trait is
// what the generated policy dispatches through).
use wz_session_core::scouting::ScoutingActions as ScoutingActionsTrait;
use wz_session_core::scouting::{
    ScoutingEvent, ScoutingHelloReceivedPayload, ScoutingInject, ScoutingPolicy, ScoutingState,
};

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
    /// Set by the drive loop before it feeds `HelloReceived`: the DECODED
    /// inbound Hello. `record_hello_and_emit` takes it and records it.
    ///
    /// The decode sits in the loop, not in the action, because that is
    /// where zenoh-pico puts it: `__z_scout_loop` runs
    /// `_z_scouting_message_decode` and `continue`s on failure
    /// (`src/session/scout.c:71-76`) — a datagram that does not decode
    /// never reaches the MID switch, so it can neither be recorded nor end
    /// an `exit_on_first` window. Staging raw bytes here and decoding
    /// inside the action put that verdict AFTER the transition had already
    /// been taken, which on the exit-on-first arm let one malformed
    /// datagram from anywhere on the untrusted multicast group close the
    /// scouting window with nothing discovered.
    pub pending_hello: R::Mutex<Option<ScoutedHello>>,
    /// The discovered peer locator string (e.g. `"udp/127.0.0.1:7447"`),
    /// extracted by `record_hello_and_emit` from the first Hello locator.
    /// `None` until a Hello with a locator arrives.
    ///
    /// FIRST-WINS across the cycle: once a locator is captured a later
    /// responder does not re-point it. Under [`ScoutParams::exit_on_first`]
    /// there is one Hello per cycle so the rule is invisible; under the
    /// survey arm it is what stops the LAST peer to answer from silently
    /// replacing a dial target the caller may already have acted on. A
    /// locator-less Hello never sets it (a peer that advertised no address is
    /// in [`Self::hellos`], but there is nothing to dial).
    ///
    /// R311y520 — kept EXACTLY as it was. It is the pre-existing consumer
    /// surface (`ScoutOutcome::Discovered`, `open_session_at`), and the
    /// complete record now lives beside it in [`Self::hellos`]; widening this
    /// field would have been a signature change for every caller that only
    /// ever wanted a dial target.
    pub discovered: R::Mutex<Option<String>>,
    /// R311y520 — every Hello decoded in the window, in ARRIVAL order.
    ///
    /// The clause this replaces said "as zenoh-pico's `_z_hello_slist_t`
    /// carries them", and that comparison is FALSE: `_z_hello_slist_push_empty`
    /// prepends (`collections/list.c:287-295`), so pico's list is newest-first
    /// and its `_z_scout` drain hands the user callback the LAST responder
    /// first (`net/primitives.c:81-90`). Arrival order is this accumulator's
    /// own choice; a consumer that must match upstream's delivery order
    /// reverses on the way out, which is what `wz-capi-core`'s `run_scout`
    /// does and tests.
    ///
    /// The pre-R311y520 code decoded a Hello, took `locators[0]`, and dropped
    /// the rest on the floor: version, whatami and zid never reached the
    /// caller, a multi-locator Hello lost every locator but the first, and a
    /// LOCATOR-LESS Hello was indistinguishable from no discovery at all —
    /// where pico pushes it to the list with an empty locator vector
    /// (`src/session/scout.c:104-110`). A consumer cannot choose a peer by
    /// role or identity if it never sees either, so this is the field that
    /// makes the decoded Hello usable rather than merely sufficient to dial.
    ///
    /// Holds ONE entry per cycle when [`ScoutParams::exit_on_first`] is set
    /// (the session-open implicit scout leaves `AwaitingHello` on the first
    /// Hello), and every responder in the window when it is clear — pico's
    /// `exit_on_first == false` survey arm, which the statechart's
    /// self-transition carries since the round that split those two
    /// `hello.received` transitions.
    pub hellos: R::Mutex<Vec<ScoutedHello>>,
}

/// One decoded Hello, carrying what zenoh-pico's `_z_hello_t` carries:
/// protocol version, the peer's role, its zid, and ALL of its locators.
///
/// Mirrors `_z_hello_t` (`include/zenoh-pico/api/types.h`) field for field;
/// pico builds it in `_z_scout_inner`'s HELLO arm (`src/session/scout.c:88-110`),
/// including the `else` branch that clears the locator vector rather than
/// dropping the hello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScoutedHello {
    /// Protocol version byte, verbatim from the wire.
    pub version: u8,
    /// The peer's role, decoded from the low 2 bits of the Hello `cbyte`.
    /// `None` when those bits carry a value no role maps to — kept DISTINCT
    /// from a role rather than defaulted, so "the peer said something we do
    /// not understand" cannot read as "the peer said peer".
    ///
    /// The layout is verified against both references rather than assumed:
    /// pico decodes `_whatami = _z_whatami_from_uint8(cbyte)` with
    /// `1 << (b & 0x03)` (`src/protocol/codec/{message.c:675,transport.c:35-37}`),
    /// and wz's own [`WhatAmI::from_wire`] masks the same two bits.
    pub whatami: Option<WhatAmI>,
    /// The peer's zid, verbatim. Its length rides the `cbyte` high nibble
    /// (`zidlen = ((cbyte & 0xF0) >> 4) + 1`, pico `message.c:676`); the codec
    /// has already applied that, so this is the id bytes alone.
    pub zid: Vec<u8>,
    /// EVERY locator the Hello advertised, in wire order. Empty for a
    /// locator-less Hello — which is a real peer that simply advertised no
    /// address, not an absence of discovery.
    pub locators: Vec<String>,
}

/// Decode one inbound scouting datagram into a [`ScoutedHello`], or `None`
/// when it is not a well-formed Hello.
///
/// This is zenoh-pico's `_z_scouting_message_decode` position in
/// `__z_scout_loop` (`src/session/scout.c:71-76`): a datagram that fails to
/// decode is `continue`d — it never reaches the MID switch, is never
/// recorded, and never ends the window. Keeping the decode here rather than
/// inside `record_hello_and_emit` is what lets the drive loop honour that,
/// because a transition action runs AFTER its guard has already chosen the
/// target state.
///
/// `bytes` is the whole datagram: the header byte carries the MID in its low
/// 5 bits and the locators-present flag in bit 5, which the Hello body codec
/// wants projected to its 1-bit `l`. The caller has already matched the MID.
pub fn decode_scouted_hello(bytes: &[u8]) -> Option<ScoutedHello> {
    let (&header, body) = bytes.split_first()?;
    let l = (header >> 5) & 1;
    let mut cursor = SceCursor::new(body);
    let hello = Hello::decode(&mut cursor, l).ok()?;
    Some(ScoutedHello {
        version: hello.version,
        // Low 2 bits of the cbyte; `None` when they name no role, rather
        // than defaulting to one.
        whatami: WhatAmI::from_wire(hello.cbyte),
        zid: hello.zid.to_vec(),
        // EVERY locator, in wire order. `None` (the L flag clear) and an
        // empty list both mean "advertised no address" and both keep the
        // hello.
        locators: hello
            .locators
            .as_ref()
            .map(|locs| locs.iter().map(|l| l.locator.to_string()).collect())
            .unwrap_or_default(),
    })
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
            hellos: Mutex::new(Vec::new()),
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

    /// R311y520 — every Hello decoded in this scouting cycle, in arrival
    /// order, complete with role / zid / all locators. The pico-shaped read;
    /// [`Self::discovered_locator`] stays the dial-target read.
    ///
    /// A non-empty result with an EMPTY `locators` is meaningful: a peer
    /// answered and advertised no address. Before R311y520 that was
    /// indistinguishable from silence.
    pub fn scouted_hellos(&self) -> Vec<ScoutedHello> {
        self.hellos.lock().unwrap().clone()
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

    /// `hello.received` — record the staged Hello whole.
    ///
    /// This is pico's `_Z_MID_HELLO` arm and nothing else: push the decoded
    /// hello onto the list (`src/session/scout.c:86-111`). The DECODE that
    /// used to live here moved to the drive loop, where pico keeps it —
    /// see [`ScoutingActions::pending_hello`] for why that position is
    /// load-bearing rather than cosmetic.
    ///
    /// Runs on BOTH `hello.received` arms. pico pushes before it consults
    /// `exit_on_first` (`:121`), so the mode decides whether the window
    /// keeps running, never whether the peer is recorded.
    ///
    /// R311y520 — the record is the complete [`ScoutedHello`] (version /
    /// whatami / zid / every locator), not a projection down to
    /// `locators[0]`. `discovered` keeps its exact former meaning: the first
    /// locator, for callers that only want a dial target. A Hello that
    /// carries NO locator is recorded too — pico's `else` branch clears the
    /// locator vector and keeps the hello (`scout.c:104-110`); dropping it
    /// made a peer that answered indistinguishable from a window that timed
    /// out.
    fn record_hello_and_emit(&mut self) {
        let a = &self.inner;
        a.trace.lock().unwrap().record_hello += 1;
        let Some(scouted) = a.pending_hello.lock().unwrap().take() else {
            return;
        };
        // FIRST-WINS, and the survey arm is what made that a decision rather
        // than a tautology. `discovered` is the DIAL TARGET read
        // (`ScoutOutcome::Discovered`, `open_session_at`), and with
        // exit_on_first there is one Hello per cycle so first and last are the
        // same value. Under the survey arm a plain assignment would let the
        // LAST peer to answer silently re-point a target the caller may
        // already have acted on, and a locator-less late answer would not even
        // clear it — the read would name a peer that is not the one it
        // describes. Keeping the first captured locator also keeps the field's
        // documented meaning intact.
        {
            let mut discovered = a.discovered.lock().unwrap();
            if discovered.is_none() {
                if let Some(first) = scouted.locators.first() {
                    *discovered = Some(first.clone());
                }
            }
        }
        a.hellos.lock().unwrap().push(scouted);
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
                    // back (MID 0x01); the MID filter drops it. A datagram
                    // that carries the Hello MID but does not DECODE is
                    // dropped here too — pico `continue`s on a failed
                    // `_z_scouting_message_decode` (scout.c:71-76), so it
                    // never reaches the FSM and cannot end an
                    // exit-on-first window with nothing discovered.
                    if rx.bytes.first().map(|h| h & 0x1f) == Some(wire_const::S_MID_HELLO) {
                        if let Some(hello) = decode_scouted_hello(&rx.bytes) {
                            *actions.pending_hello.lock().unwrap() = Some(hello);
                            // The cycle's mode rides the event: the
                            // engine-free statechart has no datamodel, so
                            // its two `hello.received` arms guard on this
                            // typed field (scouting.scxml + the
                            // hello_received_schema EventSchema).
                            engine.raise_hello_received(ScoutingHelloReceivedPayload {
                                exit_on_first: u8::from(actions.params.exit_on_first),
                            });
                            engine.step();
                        }
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

    use crate::runtime_impl::TokioTime;

    fn fixture_actions() -> Arc<ScoutingActions> {
        fixture_actions_mode(true)
    }

    /// `exit_on_first` is the axis this fixture parameterises: `true` is the
    /// session-open implicit scout (pico `net/session.c:69`), `false` the
    /// `z_scout` survey (pico `net/primitives.c:81`).
    fn fixture_actions_mode(exit_on_first: bool) -> Arc<ScoutingActions> {
        ScoutingActions::new(ScoutParams {
            version: 0x09,
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
    /// at `None`. Pico clears the locator vector and KEEPS the hello
    /// (`scout.c:104-110`). The assertion pairs the two reads deliberately —
    /// a recorded peer WITH no dial target.
    #[test]
    fn a_locator_less_hello_is_still_a_discovered_peer() {
        let (actions, hellos) = scout_one(craft_hello_with(0x00, &[0x07, 0x08], &[]));
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
                return LinkEvent::Rx(wz_session_core::link::RxFrame { bytes, src: None });
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
            version: 0x09,
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
            version: 0x09,
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
