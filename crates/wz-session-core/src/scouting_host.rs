// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The active-scouting window, with no socket and no executor in it.
//!
//! A scouting window asks the multicast group who is there and collects the answers for a
//! budget: one Scout goes out, Hellos come back, and the window ends when its deadline passes
//! (or at the first Hello, for the lookup a session open makes). The rules of it are the
//! session's: what a Scout says, what a Hello is, which datagrams a window takes as an answer and
//! which it names and drops, and when it is over. The sockets and the clock are a host's, and a
//! host is whatever holds a multicast socket: the tokio runtime's drive loop (`.await` on its link
//! driver, a `select!` against its timer), or a blocking loop over the operating system's sockets
//! that serves a C program stepping its own session.
//!
//! So the window is a value a host PUMPS. A host opens it ([`open_window`]) and sends the Scout
//! that came out, tells it whether the send went ([`window_sent`]), hands it each datagram that
//! arrives ([`window_datagram`]) and the time that has passed ([`window_tick`]), and stops when it
//! is resolved ([`window_resolved`]); the answers are on the [`ScoutingActions`] it was built over.
//! [`ScoutWindow`] holds the pieces together for a host that wants one value.
//!
//! ## IO ownership: the actions are pure, the host owns the socket
//!
//! The generated machine's four actions are native trait methods ([`ScoutActionsBinding`]).
//! `scout_emit` encodes a Scout frame and stages the bytes in [`ScoutingActions::pending_scout`];
//! `record_hello_and_emit` records the staged [`ScoutedHello`]. That keeps the actions testable
//! with no socket, and makes the `link.tx_failed` arm real: a failed multicast send feeds
//! `LinkTxFailed` and is not unreachable.
//!
//! The inbound Hello DECODE ([`decode_scouted_hello`]) is the pump's and not the action's, and
//! that placement is load-bearing: zenoh-pico decodes before its MID switch and `continue`s on
//! failure (`vendor/zenoh-pico/src/session/scout.c` @ `_z_scouting_message_decode`), so a
//! malformed datagram never reaches the machine. An action cannot reproduce that, because it runs
//! after its transition's guard has already picked the target state.
//!
//! ## Action state sharing: the trait moves, the Arc stays
//!
//! The generated policy takes the action implementation BY VALUE and keeps it private, so the
//! pump cannot read the staging slots back out of the engine. The shared state therefore lives in
//! a [`ScoutingActions`] the caller holds behind an `Arc`; the policy is parameterised over a thin
//! [`ScoutActionsBinding`] that wraps a clone of that `Arc` (the orphan rule forbids implementing
//! the foreign trait on `Arc<ScoutingActions>` itself).
//!
//! ## Timeout ownership: the host owns the clock
//!
//! The generated machine is code-generated `no_std` (`NoOpHal`), so a `<send delay>` would be a
//! dead element: it arms no timer and owns only the `scout.timer.elapsed` transition. The host
//! measures the window's budget on its own clock and calls [`window_tick`] with the time since the
//! Scout went out.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use sce_forge_runtime::codec::SceCursor;
use sce_rust_runtime::Engine;
use wz_codecs::hello::Hello;
use wz_codecs::scout::Scout;
use wz_codecs::whatami::WhatAmI;
use wz_codecs::wire_const;
use wz_runtime_core::Runtime;

use crate::link::LostCause;
pub use crate::scout_initiator::{
    classify_ignored_scout_rx, hello_advances_window, ScoutRxIgnored,
};
pub use crate::scout_params::ScoutParams;
use crate::scout_trace::ScoutTrace;
// The generated action trait, aliased so its name does not shadow the host-side state struct
// below (the struct holds the staging slots the caller reads; the trait is what the generated
// policy dispatches through).
use crate::scouting::ScoutingActions as ScoutingActionsTrait;
use crate::scouting::{
    ScoutingEvent, ScoutingHelloReceivedPayload, ScoutingInject, ScoutingPolicy, ScoutingState,
};

/// Shared host state for one active-scouting window.
///
/// Distinct from the session handshake's bundle: scouting is a pre-session, untrusted-link
/// subsystem, so its parameters, trace and staging slots are not folded into the session's.
/// Generic over the runtime `R` for its locks, as the rest of the session model is.
///
/// The caller holds this behind an `Arc`; [`new_scouting_engine`] wraps a clone of that `Arc` in
/// a [`ScoutActionsBinding`] for the policy to own, so the caller can still read
/// [`Self::discovered_locator`] and [`Self::scouted_hellos`] after the policy takes the binding.
pub struct ScoutingActions<R: Runtime> {
    /// Inputs for the outbound Scout frame and the scouting deadline (what, zid, timeout).
    pub params: ScoutParams,
    /// Script-action dispatch counters, read in tests through [`Self::trace_snapshot`].
    pub trace: R::Mutex<ScoutTrace>,
    /// Set by `scout_emit`: the fully-framed Scout datagram (`[S_MID_SCOUT][version][cbyte][zid]`)
    /// awaiting transmission. The host takes it, sends it on the multicast link and clears the
    /// slot.
    pub pending_scout: R::Mutex<Option<Vec<u8>>>,
    /// Set by the pump before it feeds `HelloReceived`: the DECODED inbound Hello.
    /// `record_hello_and_emit` takes it and records it.
    ///
    /// The decode sits in the pump, not in the action, because that is where zenoh-pico puts it
    /// (see the module doc): a datagram that does not decode never reaches the machine, so it
    /// can neither be recorded nor end an `exit_on_first` window. Staging raw bytes here and
    /// decoding inside the action would put that verdict AFTER the transition had been taken,
    /// which on the exit-on-first arm let one malformed datagram from anywhere on the untrusted
    /// group close the window with nothing discovered.
    pub pending_hello: R::Mutex<Option<ScoutedHello>>,
    /// The discovered peer locator (for example `"udp/127.0.0.1:7447"`), taken from the first
    /// Hello locator. `None` until a Hello with a locator arrives.
    ///
    /// FIRST-WINS across the window: once a locator is captured a later responder does not
    /// re-point it. With [`ScoutParams::exit_on_first`] there is one Hello per window so the rule
    /// is invisible; under the survey arm it stops the LAST peer to answer from silently
    /// replacing a dial target the caller may already have acted on. A locator-less Hello never
    /// sets it: that peer is in [`Self::hellos`], but there is nothing to dial.
    pub discovered: R::Mutex<Option<String>>,
    /// Every Hello decoded in the window, in ARRIVAL order.
    ///
    /// zenoh-pico's list is the other way round: `_z_hello_slist_push_empty` prepends, so its
    /// `_z_scout` drain hands the callback the LAST responder first. Arrival order is this
    /// accumulator's own choice; a consumer that must match upstream's delivery order reverses
    /// on the way out.
    ///
    /// Holds ONE entry per window with [`ScoutParams::exit_on_first`] (the session-open implicit
    /// scout leaves `AwaitingHello` on the first Hello), and every responder in the window
    /// without it: pico's `exit_on_first == false` survey arm, which the statechart's
    /// self-transition carries.
    pub hellos: R::Mutex<Vec<ScoutedHello>>,
    /// Every datagram the window OBSERVED and did not take as a Hello, with the reason, in
    /// arrival order.
    ///
    /// A log line alone is the wrong instrument for "a datagram was dropped": a log needle dies
    /// two ways (the level is filtered, or the wording drifts) and a test that greps for one
    /// asserts on prose. So the verdict is recorded here as a value, and logged beside it.
    /// Together with [`Self::hellos`] it makes the handling of inbound datagrams CONSERVATIVE:
    /// every datagram the window receives lands in exactly one of the two, so a future silent
    /// drop is a broken count and not a missing log line.
    pub ignored: R::Mutex<Vec<ScoutRxIgnored>>,
}

/// One decoded Hello, carrying what zenoh-pico's `_z_hello_t` carries: protocol version, the
/// peer's role, its zid, and ALL of its locators.
///
/// Mirrors `_z_hello_t` field for field; pico builds it in `_z_scout_inner`'s HELLO arm
/// (`vendor/zenoh-pico/src/session/scout.c`), including the `else` branch that clears the locator
/// vector and keeps the hello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScoutedHello {
    /// Protocol version byte, verbatim from the wire.
    pub version: u8,
    /// The peer's role, decoded from the low 2 bits of the Hello `cbyte`. `None` when those bits
    /// carry a value no role maps to, kept DISTINCT from a role rather than defaulted, so "the
    /// peer said something we do not understand" cannot read as "the peer said peer".
    pub whatami: Option<WhatAmI>,
    /// The peer's zid, verbatim. Its length rides the `cbyte` high nibble; the codec has already
    /// applied that, so this is the id bytes alone.
    pub zid: Vec<u8>,
    /// EVERY locator the Hello advertised, in wire order. Empty for a locator-less Hello, which
    /// is a real peer that advertised no address and not an absence of discovery.
    pub locators: Vec<String>,
}

/// Decode one inbound scouting datagram into a [`ScoutedHello`], or `None` when it is not a
/// well-formed Hello.
///
/// This is zenoh-pico's `_z_scouting_message_decode` position in `__z_scout_loop`: a datagram
/// that fails to decode is `continue`d, never reaches the MID switch, is never recorded and never
/// ends the window.
///
/// `bytes` is the whole datagram: the header byte carries the MID in its low 5 bits and the
/// locators-present flag in bit 5, which the Hello body codec wants projected to its 1-bit `l`.
/// The caller has already matched the MID.
pub fn decode_scouted_hello(bytes: &[u8]) -> Option<ScoutedHello> {
    let (&header, body) = bytes.split_first()?;
    let l = (header >> 5) & 1;
    let mut cursor = SceCursor::new(body);
    let hello = Hello::decode(&mut cursor, l).ok()?;
    Some(ScoutedHello {
        version: hello.version,
        whatami: WhatAmI::from_wire(hello.cbyte),
        zid: hello.zid.to_vec(),
        locators: hello
            .locators
            .as_ref()
            .map(|locs| locs.iter().map(|l| l.locator.to_string()).collect())
            .unwrap_or_default(),
    })
}

impl<R: Runtime> ScoutingActions<R> {
    /// The state bundle for one discovery window. `params` are captured by value; the staging
    /// slots start empty.
    pub fn new(params: ScoutParams) -> Arc<Self> {
        Arc::new(Self {
            params,
            trace: R::new_mutex(ScoutTrace::default()),
            pending_scout: R::new_mutex(None),
            pending_hello: R::new_mutex(None),
            discovered: R::new_mutex(None),
            hellos: R::new_mutex(Vec::new()),
            ignored: R::new_mutex(Vec::new()),
        })
    }

    /// Field-by-field `Copy` snapshot of the dispatch counters, lifted out from under the lock.
    pub fn trace_snapshot(&self) -> ScoutTrace {
        R::with_mutex_mut(&self.trace, |trace| trace.clone_via_copy())
    }

    /// The discovered locator, if a Hello locator was captured.
    pub fn discovered_locator(&self) -> Option<String> {
        R::with_mutex_mut(&self.discovered, |locator| locator.clone())
    }

    /// Every Hello decoded in this window, in arrival order, complete with role, zid and all
    /// locators: the pico-shaped read, where [`Self::discovered_locator`] is the dial-target
    /// read.
    ///
    /// A non-empty result with an EMPTY `locators` is meaningful: a peer answered and advertised
    /// no address, which must not read as silence.
    pub fn scouted_hellos(&self) -> Vec<ScoutedHello> {
        R::with_mutex_mut(&self.hellos, |hellos| hellos.clone())
    }

    /// Every datagram this window observed and did not take as a Hello, with the reason, in
    /// arrival order. See [`Self::ignored`] for why the record is a value.
    pub fn ignored_datagrams(&self) -> Vec<ScoutRxIgnored> {
        R::with_mutex_mut(&self.ignored, |ignored| ignored.clone())
    }

    /// Record one non-Hello observation, and say so at a severity that matches what the verdict
    /// MEANS here, which is not always what it means upstream.
    ///
    /// `Undecodable` and `UnknownMid` are upstream's two error arms and are anomalous here too.
    /// The other three are not: the scouting socket asks for `IP_MULTICAST_LOOP` so its own Scout
    /// comes back, a second node scouting the same group is ordinary, and a peer that answers
    /// with no address is a peer. Logging those at pico's severity would put a warning on the
    /// window's own traffic once per cycle (see [`crate::scout_initiator`]).
    fn record_ignored(&self, why: ScoutRxIgnored) {
        match &why {
            ScoutRxIgnored::Undecodable => {
                log::warn!("scouting window: received malformed message; ignored")
            }
            ScoutRxIgnored::UnknownMid { mid } => {
                log::warn!("scouting window: received unexpected message (mid {mid:#04x}); ignored")
            }
            ScoutRxIgnored::SelfEcho => {
                log::debug!("scouting window: our own Scout, looped back; ignored")
            }
            ScoutRxIgnored::ForeignScout => {
                log::debug!("scouting window: another node's Scout; ignored")
            }
            ScoutRxIgnored::LocatorlessHello => {
                log::debug!("scouting window: a Hello advertising no locator; still searching")
            }
        }
        R::with_mutex_mut(&self.ignored, |ignored| ignored.push(why));
    }
}

/// The generated policy's owner of the shared state: a clone of the caller's
/// `Arc<`[`ScoutingActions`]`>`, so the four native actions mutate the slots the caller reads
/// back.
pub struct ScoutActionsBinding<R: Runtime> {
    inner: Arc<ScoutingActions<R>>,
}

impl<R: Runtime> ScoutingActionsTrait for ScoutActionsBinding<R> {
    // This host performs the machine's duties. `scout_emit` stages the datagram the host sends
    // and `record_hello_and_emit` writes the slots the caller reads back. `emit_scout_timeout`
    // and `diag_scout_tx_failed` are notices that only count: a window that ends with no Hello
    // leaves `discovered` unset whether or not they run.
    const REALIZATION: ::sce_rust_runtime::ActionRealization =
        ::sce_rust_runtime::ActionRealization::Performs;

    /// Idle -> Sending entering transition: encode one Scout frame and stage the datagram for the
    /// host to transmit. Pure: no socket access. Mirrors zenoh-pico's `_z_link_send_wbuf` in
    /// `scout.c`, except the send itself is the host's job.
    fn scout_emit(&mut self) {
        let a = &self.inner;
        R::with_mutex_mut(&a.trace, |trace| trace.scout_emit += 1);
        let zid = &a.params.zid;
        let mut scout = Scout::new();
        scout.version = wz_codecs::wire_const::PROTOCOL_VERSION;
        scout.set_what(a.params.what);
        if !zid.is_empty() {
            // I=1 and zid_len_m1 packed into cbyte, then the id bytes (the scout.scxml
            // present-if gate; zenoh-pico `message.c` writes the same).
            scout.set_i(true);
            scout.set_zid_len_m1((zid.len() - 1) as u8);
            scout.zid = Some(zid);
        }
        let body = scout.encode_to_vec();
        let mut datagram = Vec::with_capacity(1 + body.len());
        // The scouting-message envelope: the MID header byte the body codec omits.
        datagram.push(wire_const::S_MID_SCOUT);
        datagram.extend_from_slice(&body);
        R::with_mutex_mut(&a.pending_scout, |slot| *slot = Some(datagram));
    }

    /// `hello.received`: record the staged Hello whole.
    ///
    /// This is pico's `_Z_MID_HELLO` arm and nothing else: push the decoded hello onto the list.
    /// Runs on BOTH `hello.received` arms, because pico pushes before it consults
    /// `exit_on_first`: the mode decides whether the window keeps running, never whether the peer
    /// is recorded.
    fn record_hello_and_emit(&mut self) {
        let a = &self.inner;
        R::with_mutex_mut(&a.trace, |trace| trace.record_hello += 1);
        let Some(scouted) = R::with_mutex_mut(&a.pending_hello, |slot| slot.take()) else {
            return;
        };
        // FIRST-WINS, which the survey arm turned from a tautology into a decision: `discovered`
        // is the DIAL TARGET read, and a plain assignment would let the LAST peer to answer
        // silently re-point a target the caller may already have acted on, while a locator-less
        // late answer would not even clear it.
        R::with_mutex_mut(&a.discovered, |discovered| {
            if discovered.is_none() {
                if let Some(first) = scouted.locators.first() {
                    *discovered = Some(first.clone());
                }
            }
        });
        R::with_mutex_mut(&a.hellos, |hellos| hellos.push(scouted));
    }

    /// AwaitingHello -> Idle on scout.timer.elapsed: the window expired with no Hello.
    /// Observability only; `discovered` stays `None`.
    fn emit_scout_timeout(&mut self) {
        R::with_mutex_mut(&self.inner.trace, |trace| trace.scout_timeout += 1);
    }

    /// Sending -> Idle on link.tx_failed: the multicast Scout transmit errored.
    fn diag_scout_tx_failed(&mut self) {
        R::with_mutex_mut(&self.inner.trace, |trace| trace.tx_failed += 1);
    }
}

/// The scouting machine a host pumps.
pub type ScoutEngine<R> = Engine<ScoutingPolicy<ScoutActionsBinding<R>>>;

/// Build a scouting engine over the generated policy, parameterised over a
/// [`ScoutActionsBinding`] wrapping a clone of `actions`. The caller retains `actions` and pumps
/// the engine ([`open_window`] and the functions after it).
pub fn new_scouting_engine<R: Runtime>(actions: &Arc<ScoutingActions<R>>) -> ScoutEngine<R> {
    let binding = ScoutActionsBinding {
        inner: actions.clone(),
    };
    Engine::new(crate::constant_session_id::built_under_constant_id(
        ScoutingPolicy::new_with_session_id(SCOUTING_SESSION_ID, binding),
        "the scouting session id",
    ))
}

/// The id the scouting machine is built under (the host gives a machine its id, and the generated
/// constructor refuses a text that is not an XML Nmtoken). A constant, so that refusal is never
/// met.
const SCOUTING_SESSION_ID: &str = "wz-scouting";

/// How a scouting window ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScoutOutcome {
    /// A Hello arrived and a locator was captured.
    Discovered(String),
    /// The window elapsed with no usable Hello.
    TimedOut,
    /// The scouting link was lost before the window resolved.
    LinkLost(LostCause),
    /// The bounded iteration budget was exhausted (a test guard).
    IterationLimit,
}

/// Open the window: start the machine and take the Scout datagram it staged, which the host sends
/// on the group. `None` when nothing was staged (which does not happen); the host then reports
/// the send as failed ([`window_sent`]), so the machine returns to `Idle` deterministically.
pub fn open_window<R: Runtime>(
    actions: &Arc<ScoutingActions<R>>,
    engine: &mut ScoutEngine<R>,
) -> Option<Vec<u8>> {
    engine.initialize();
    // Idle -> Sending: `scout_emit` fires on the entering transition and stages the datagram.
    engine.process_event(ScoutingEvent::SessionOpenRequested);
    R::with_mutex_mut(&actions.pending_scout, |slot| slot.take())
}

/// Tell the machine whether the Scout went out: `Sending -> AwaitingHello` when it did,
/// `Sending -> Idle` when the send failed.
pub fn window_sent<R: Runtime>(engine: &mut ScoutEngine<R>, sent: bool) {
    engine.process_event(if sent {
        ScoutingEvent::ScoutTxDone
    } else {
        ScoutingEvent::LinkTxFailed
    });
}

/// Hand the window one datagram that arrived on the group.
///
/// Only Hello datagrams advance the machine. The scouting socket asks for
/// `IP_MULTICAST_LOOP`, so the window's own Scout echoes back (MID 0x01) and the MID filter drops
/// it. A datagram that carries the Hello MID but does not DECODE is dropped here too: pico
/// `continue`s on a failed `_z_scouting_message_decode`, so it never reaches the machine and
/// cannot end an exit-on-first window with nothing discovered. A THIRD datagram does not advance
/// the window either, and it is the one a stranger can send on purpose: a well-formed Hello
/// advertising no address ([`hello_advances_window`]). Both upstreams keep searching past it.
///
/// The verdict is computed at ONE place on purpose: an `advanced` flag, and not a record call per
/// drop site, so a future arm cannot forget to account for its datagram. Every datagram the
/// window observes lands in exactly one of `hellos` and `ignored`.
pub fn window_datagram<R: Runtime>(
    actions: &Arc<ScoutingActions<R>>,
    engine: &mut ScoutEngine<R>,
    bytes: &[u8],
) {
    let advanced = if bytes.first().map(|h| h & 0x1f) == Some(wire_const::S_MID_HELLO) {
        match decode_scouted_hello(bytes) {
            Some(hello)
                if hello_advances_window(actions.params.exit_on_first, hello.locators.len()) =>
            {
                R::with_mutex_mut(&actions.pending_hello, |slot| *slot = Some(hello));
                // The window's mode rides the event: the generated machine has no datamodel, so
                // its two `hello.received` arms guard on this typed field.
                engine.raise_hello_received(ScoutingHelloReceivedPayload {
                    exit_on_first: u8::from(actions.params.exit_on_first),
                });
                engine.step();
                true
            }
            // Undecodable, or decodable and declined by the rule above: both land in `ignored`,
            // each under its own verdict.
            _ => false,
        }
    } else {
        false
    };
    if !advanced {
        actions.record_ignored(classify_ignored_scout_rx(&actions.params.zid, bytes));
    }
}

/// Tell the window that `elapsed_ms` have passed since the Scout went out: once the budget
/// ([`ScoutParams::timeout_ms`]) has elapsed with no Hello, raise the timeout (`AwaitingHello ->
/// Idle`). Only `AwaitingHello` handles the event, so calling it in any other state is a no-op.
pub fn window_tick<R: Runtime>(
    actions: &Arc<ScoutingActions<R>>,
    engine: &mut ScoutEngine<R>,
    elapsed_ms: u64,
) {
    if elapsed_ms >= actions.params.timeout_ms
        && engine.get_current_state() == ScoutingState::AwaitingHello
    {
        engine.process_event(ScoutingEvent::ScoutTimerElapsed);
    }
}

/// Whether the window is over: the machine is back in `Idle`, because a Hello ended it, its budget
/// elapsed, or the Scout could not be sent.
pub fn window_resolved<R: Runtime>(engine: &ScoutEngine<R>) -> bool {
    engine.get_current_state() == ScoutingState::Idle
}

/// How a resolved window ended: the first locator it captured, or that it timed out.
pub fn window_outcome<R: Runtime>(actions: &ScoutingActions<R>) -> ScoutOutcome {
    match actions.discovered_locator() {
        Some(locator) => ScoutOutcome::Discovered(locator),
        None => ScoutOutcome::TimedOut,
    }
}

/// One scouting window as a single value, for a host that pumps it from a loop of its own: the
/// actions the answers land on, the machine, and the time the Scout went out.
///
/// ```text
/// let mut window = ScoutWindow::<R>::new(params);
/// let scout = window.open();                    // the datagram to send on the group
/// window.sent(now_ms, send(scout).is_ok());     // the budget runs from here
/// while !window.resolved() {
///     for datagram in receive() { window.datagram(&datagram); }
///     window.tick(now_ms());
/// }
/// let hellos = window.actions().scouted_hellos();
/// ```
pub struct ScoutWindow<R: Runtime> {
    actions: Arc<ScoutingActions<R>>,
    engine: ScoutEngine<R>,
    started_ms: u64,
}

impl<R: Runtime> ScoutWindow<R> {
    /// A window over `params`, not yet open.
    pub fn new(params: ScoutParams) -> Self {
        let actions = ScoutingActions::<R>::new(params);
        let engine = new_scouting_engine(&actions);
        Self {
            actions,
            engine,
            started_ms: 0,
        }
    }

    /// The state the answers land on.
    pub fn actions(&self) -> &Arc<ScoutingActions<R>> {
        &self.actions
    }

    /// Open the window ([`open_window`]): the Scout datagram to send.
    pub fn open(&mut self) -> Option<Vec<u8>> {
        open_window(&self.actions, &mut self.engine)
    }

    /// The Scout was sent, or was not ([`window_sent`]); `now_ms` is the host's clock, from which
    /// the budget runs.
    pub fn sent(&mut self, now_ms: u64, sent: bool) {
        self.started_ms = now_ms;
        window_sent(&mut self.engine, sent);
    }

    /// One datagram arrived ([`window_datagram`]).
    pub fn datagram(&mut self, bytes: &[u8]) {
        window_datagram(&self.actions, &mut self.engine, bytes);
    }

    /// The host's clock reads `now_ms` ([`window_tick`]).
    pub fn tick(&mut self, now_ms: u64) {
        window_tick(
            &self.actions,
            &mut self.engine,
            now_ms.saturating_sub(self.started_ms),
        );
    }

    /// Whether the window is over ([`window_resolved`]).
    pub fn resolved(&self) -> bool {
        window_resolved(&self.engine)
    }

    /// How it ended ([`window_outcome`]).
    pub fn outcome(&self) -> ScoutOutcome {
        window_outcome(&self.actions)
    }
}
