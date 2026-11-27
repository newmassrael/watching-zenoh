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
//! ## Action state sharing: the trait moves, the state stays
//!
//! The generated policy takes the action implementation BY VALUE and keeps it private, so the
//! pump cannot read the staging slots back out of the engine. The state therefore lives in a
//! [`ScoutingActions`] the caller holds, and the policy is parameterised over a thin
//! [`ScoutActionsBinding`] that reaches it. How it reaches the state is a type ([`ActionsReach`]):
//! a host with a heap holds the state behind an `Arc`, a clone of which the binding keeps; a host
//! with none holds it in the window's own place, which does not move while the window lives
//! ([`ScoutWindowPlace::build_over`]), and the binding points at it ([`PlacedActions`]). Where
//! the window records its Hellos is a type too ([`HelloRecord`]): the heap collection
//! ([`HelloList`]) or a table its host lends ([`LentTable`]). A host names both, so a window links
//! the one form of each it uses: a window over a lent table, held in its place, makes no
//! allocation and links neither the collection nor the `Arc`.
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
use core::mem::MaybeUninit;
use core::ops::Deref;
use core::ptr::NonNull;

use sce_forge_runtime::codec::{SceCursor, SliceSink};
use sce_rust_runtime::Engine;
use wz_codecs::scout::{Scout, ScoutParts};
use wz_codecs::scouting_hello::ScoutingHelloView;
use wz_codecs::scouting_scout::{ScoutingScoutParts, ScoutingScoutWire};
use wz_codecs::whatami::WhatAmI;
use wz_codecs::wire_const;
use wz_runtime_core::Runtime;

use crate::caps;
use crate::limits::{MaxLocatorLenHeld, RuntimeLimits};
use crate::link::LostCause;
pub use crate::scout_initiator::hello_advances_window;
#[cfg(feature = "scout-rx-verdicts")]
pub use crate::scout_initiator::{classify_ignored_scout_rx, ScoutRxIgnored};
pub use crate::scout_params::ScoutParams;
use crate::scout_trace::ScoutTrace;
use crate::session_zid::SessionZid;
// The generated action trait, aliased so its name does not shadow the host-side state struct
// below (the struct holds the staging slots the caller reads; the trait is what the generated
// policy dispatches through).
use crate::scouting::ScoutingActions as ScoutingActionsTrait;
use crate::scouting::{
    ScoutingEvent, ScoutingHelloReceivedRef, ScoutingInject, ScoutingPolicy, ScoutingState,
};

/// Shared host state for one active-scouting window.
///
/// Distinct from the session handshake's bundle: scouting is a pre-session, untrusted-link
/// subsystem, so its parameters, trace and staging slots are not folded into the session's.
/// Generic over the runtime `R` for its locks, as the rest of the session model is, and over the
/// record `K` the window keeps its Hellos in ([`HelloRecord`]): the heap collection unless one is
/// named ([`HelloList`]), or a table its host lends ([`LentTable`]).
///
/// The caller holds this behind an `Arc`, and [`new_scouting_engine`] wraps a clone of that `Arc`
/// in a [`ScoutActionsBinding`] for the policy to own, so the caller can still read
/// [`Self::discovered_locator`] and the record after the policy takes the binding; or a window
/// holds it in its own place ([`ScoutWindowPlace::build_over`]).
pub struct ScoutingActions<R: Runtime, K = HelloList<R>> {
    /// Inputs for the outbound Scout frame and the scouting deadline (what, zid, timeout).
    pub params: ScoutParams,
    /// Script-action dispatch counters, read in tests through [`Self::trace_snapshot`].
    pub trace: R::Mutex<ScoutTrace>,
    /// Set by `scout_emit`: the fully-framed Scout datagram (`[S_MID_SCOUT][version][cbyte][zid]`)
    /// awaiting transmission, in bytes of its own. The host takes it, sends it on the multicast
    /// link and clears the slot.
    pub pending_scout: R::Mutex<Option<ScoutFrame>>,
    /// Where the window records the Hellos it takes, and what it keeps of the datagrams it does
    /// not; a host reads it through `record`.
    record: K,
    /// How many datagrams the window observed and did not take as a Hello, by verdict with
    /// `scout-rx-verdicts`: the count every window keeps, whatever its record.
    ///
    /// Together with the Hellos the record holds (or counts as refused), it makes the handling of
    /// inbound datagrams CONSERVATIVE: every datagram the window receives lands in exactly one of
    /// them, so a future silent drop is a broken count and not a missing log line.
    ignored_counts: R::Mutex<IgnoredCounts>,
}

/// Where a window records the Hellos it takes, and, with `scout-rx-verdicts`, what it keeps of
/// the datagrams it does not beyond the count every window keeps
/// ([`ScoutingActions::ignored_counts`]). A host names its record as a type, so a window links the
/// one it records in.
pub trait HelloRecord<R: Runtime>: Sized + 'static {
    /// `bytes`, a datagram of the Hello MID, decoded and staged for the machine's next
    /// `hello.received`: whether it is a Hello the window advances on ([`hello_advances_window`]).
    /// A datagram that does not decode stages nothing.
    ///
    /// The decode sits before the machine, not in its action, because that is where zenoh-pico
    /// puts it (see the module doc): a datagram that does not decode never reaches the machine, so
    /// it can neither be recorded nor end an `exit_on_first` window. Decoding inside the action
    /// would put that verdict AFTER the transition had been taken, which on the exit-on-first arm
    /// let one malformed datagram from anywhere on the untrusted group close the window with
    /// nothing discovered.
    fn stage(&self, bytes: &[u8], exit_on_first: bool) -> bool;
    /// The staged Hello recorded after the others: the machine took it.
    fn record_staged(&self);
    /// One datagram the window observed and did not take as a Hello, already counted.
    #[cfg(feature = "scout-rx-verdicts")]
    fn record_ignored(&self, why: ScoutRxIgnored);
    /// The first locator a recorded Hello advertised, the dial target: `None` until a Hello with
    /// a locator is recorded.
    fn discovered_locator(&self) -> Option<String>;
}

/// The record a host with a heap keeps, zenoh's: every Hello decoded onto the heap, with no bound,
/// and with `scout-rx-verdicts` every datagram not taken listed with its verdict.
pub struct HelloList<R: Runtime> {
    /// Set by [`HelloRecord::stage`] before the pump feeds `HelloReceived`: the DECODED inbound
    /// Hello, which `record_hello_and_emit` takes and records.
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
    /// self-transition carries. Zenoh's collection, with no bound.
    pub hellos: R::Mutex<Vec<ScoutedHello>>,
    /// Every datagram the window OBSERVED and did not take as a Hello, with the reason, in
    /// arrival order.
    ///
    /// A log line alone is the wrong instrument for "a datagram was dropped": a log needle dies
    /// two ways (the level is filtered, or the wording drifts) and a test that greps for one
    /// asserts on prose. So the verdict is recorded here as a value, and logged beside it.
    #[cfg(feature = "scout-rx-verdicts")]
    pub ignored: R::Mutex<Vec<ScoutRxIgnored>>,
}

impl<R: Runtime> HelloList<R> {
    /// A record of no Hello and no datagram.
    pub fn new() -> Self {
        Self {
            pending_hello: R::new_mutex(None),
            discovered: R::new_mutex(None),
            hellos: R::new_mutex(Vec::new()),
            #[cfg(feature = "scout-rx-verdicts")]
            ignored: R::new_mutex(Vec::new()),
        }
    }
}

impl<R: Runtime> Default for HelloList<R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: Runtime> HelloRecord<R> for HelloList<R> {
    fn stage(&self, bytes: &[u8], exit_on_first: bool) -> bool {
        match decode_scouted_hello(bytes) {
            Some(hello) if hello_advances_window(exit_on_first, hello.locators.len()) => {
                R::with_mutex_mut(&self.pending_hello, |slot| *slot = Some(hello));
                true
            }
            _ => false,
        }
    }

    fn record_staged(&self) {
        let Some(scouted) = R::with_mutex_mut(&self.pending_hello, |slot| slot.take()) else {
            return;
        };
        // FIRST-WINS, which the survey arm turned from a tautology into a decision: `discovered`
        // is the DIAL TARGET read, and a plain assignment would let the LAST peer to answer
        // silently re-point a target the caller may already have acted on, while a locator-less
        // late answer would not even clear it.
        R::with_mutex_mut(&self.discovered, |discovered| {
            if discovered.is_none() {
                *discovered = scouted.locators.first().cloned();
            }
        });
        R::with_mutex_mut(&self.hellos, |hellos| hellos.push(scouted));
    }

    #[cfg(feature = "scout-rx-verdicts")]
    fn record_ignored(&self, why: ScoutRxIgnored) {
        R::with_mutex_mut(&self.ignored, |ignored| ignored.push(why));
    }

    fn discovered_locator(&self) -> Option<String> {
        R::with_mutex_mut(&self.discovered, |locator| locator.clone())
    }
}

/// The most bytes a Scout datagram holds: its header and the longest body the codec writes. The
/// window states no extension of a Scout.
pub const SCOUT_DATAGRAM_BYTES: usize = 1 + Scout::<'static>::MAX_ENCODED_BYTES;

/// One Scout datagram, encoded where it is held: what a window stages for its host to send, in
/// bytes of its own and none of the heap.
#[derive(Clone, Copy)]
pub struct ScoutFrame {
    bytes: [u8; SCOUT_DATAGRAM_BYTES],
    len: usize,
}

impl ScoutFrame {
    /// The datagram's bytes.
    pub fn as_slice(&self) -> &[u8] {
        // `len` is where the encoder's sink over `bytes` stopped.
        self.bytes.get(..self.len).unwrap_or_default()
    }
}

impl Deref for ScoutFrame {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl core::fmt::Debug for ScoutFrame {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(self.as_slice(), f)
    }
}

impl PartialEq for ScoutFrame {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for ScoutFrame {}

impl PartialEq<[u8]> for ScoutFrame {
    fn eq(&self, other: &[u8]) -> bool {
        self.as_slice() == other
    }
}

impl PartialEq<Vec<u8>> for ScoutFrame {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.as_slice() == other.as_slice()
    }
}

/// How many datagrams a window observed and did not take as a Hello: the record a window over a
/// lent table keeps in place of a list. By verdict (`ScoutRxIgnored`) with `scout-rx-verdicts`;
/// without it in one count, as zenoh-pico's scout names one error for each
/// (`vendor/zenoh-pico/src/session/scout.c` @ `ret = _Z_ERR_MESSAGE_UNEXPECTED;`), and no datagram
/// is classified.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IgnoredCounts {
    /// [`ScoutRxIgnored::Undecodable`].
    #[cfg(feature = "scout-rx-verdicts")]
    pub undecodable: usize,
    /// [`ScoutRxIgnored::SelfEcho`].
    #[cfg(feature = "scout-rx-verdicts")]
    pub self_echo: usize,
    /// [`ScoutRxIgnored::ForeignScout`].
    #[cfg(feature = "scout-rx-verdicts")]
    pub foreign_scout: usize,
    /// [`ScoutRxIgnored::UnknownMid`], whatever the MID.
    #[cfg(feature = "scout-rx-verdicts")]
    pub unknown_mid: usize,
    /// [`ScoutRxIgnored::LocatorlessHello`].
    #[cfg(feature = "scout-rx-verdicts")]
    pub locatorless_hello: usize,
    /// Every datagram not taken, whatever it was.
    #[cfg(not(feature = "scout-rx-verdicts"))]
    not_taken: usize,
}

impl IgnoredCounts {
    /// One more datagram not taken.
    #[cfg(not(feature = "scout-rx-verdicts"))]
    fn count_one(&mut self) {
        self.not_taken = self.not_taken.saturating_add(1);
    }

    /// One more datagram of the verdict `why`.
    #[cfg(feature = "scout-rx-verdicts")]
    fn count(&mut self, why: &ScoutRxIgnored) {
        let slot = match why {
            ScoutRxIgnored::Undecodable => &mut self.undecodable,
            ScoutRxIgnored::SelfEcho => &mut self.self_echo,
            ScoutRxIgnored::ForeignScout => &mut self.foreign_scout,
            ScoutRxIgnored::UnknownMid { .. } => &mut self.unknown_mid,
            ScoutRxIgnored::LocatorlessHello => &mut self.locatorless_hello,
        };
        *slot = slot.saturating_add(1);
    }

    /// How many datagrams in all.
    pub fn total(&self) -> usize {
        #[cfg(feature = "scout-rx-verdicts")]
        {
            self.undecodable
                .saturating_add(self.self_echo)
                .saturating_add(self.foreign_scout)
                .saturating_add(self.unknown_mid)
                .saturating_add(self.locatorless_hello)
        }
        #[cfg(not(feature = "scout-rx-verdicts"))]
        {
            self.not_taken
        }
    }
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
    /// applied that, so this is the id bytes alone, and a Hello naming no zid a node can have is
    /// not decoded into one ([`decode_scouted_hello`]).
    pub zid: SessionZid,
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
/// `bytes` is the whole datagram, read by the message's document
/// (`sources/codecs/scouting_hello.scxml`): the header byte, whose locators-present flag the
/// document binds to the body's list, the body, and the extension chain the header's Z flag
/// announces. The caller has already matched the MID.
pub fn decode_scouted_hello(bytes: &[u8]) -> Option<ScoutedHello> {
    let view = ScoutingHelloView::decode(&mut SceCursor::new(bytes)).ok()?;
    let hello = view.body;
    // A Hello naming a zid no node has is no Hello, as for zenoh's decoder
    // (`crate::scouting_message::parse_scouting` cites it).
    let zid = SessionZid::new(hello.zid.into_inner()).ok()?;
    Some(ScoutedHello {
        version: hello.version,
        whatami: WhatAmI::from_wire(hello.cbyte),
        zid,
        locators: hello
            .locators
            .as_ref()
            .map(|locs| locs.inner().iter().map(|l| l.locator.to_string()).collect())
            .unwrap_or_default(),
    })
}

/// What a delivered Hello says, whichever form holds it: the [`ScoutedHello`] a host keeps, or
/// the [`HelloRow`] of a window's table, which a scout lends its callback.
pub trait HelloFacts {
    /// The peer's role, `None` for bits no role maps to.
    fn whatami(&self) -> Option<WhatAmI>;
    /// The peer's zid.
    fn zid(&self) -> &SessionZid;
    /// How many locators the Hello holds.
    fn locator_count(&self) -> usize;
    /// The `k`th locator, in wire order.
    fn locator(&self, k: usize) -> Option<&str>;
}

impl HelloFacts for ScoutedHello {
    fn whatami(&self) -> Option<WhatAmI> {
        self.whatami
    }

    fn zid(&self) -> &SessionZid {
        &self.zid
    }

    fn locator_count(&self) -> usize {
        self.locators.len()
    }

    fn locator(&self, k: usize) -> Option<&str> {
        self.locators.get(k).map(String::as_str)
    }
}

/// The locator text one row holds: `SCOUT_HELLO_LOCATORS` locators of the build's
/// `MAX_LOCATOR_LEN` bytes each, the most any window's limits admit.
type HelloLocatorText = [u8; caps::SCOUT_HELLO_LOCATORS * caps::MAX_LOCATOR_LEN];

/// The bytes of [`HelloLocatorText`].
const HELLO_LOCATOR_TEXT: usize = core::mem::size_of::<HelloLocatorText>();

/// One Hello as a window keeps it: what [`ScoutedHello`] carries, its locators in a text of the
/// row's own, so a window records its Hellos in a table of a size the build fixes and decodes none
/// onto the heap. A locator longer than the `MAX_LOCATOR_LEN` the window's runtime limits state,
/// or one past `SCOUT_HELLO_LOCATORS`, is skipped, never cut short, and counted.
#[derive(Debug, Clone)]
pub struct HelloRow {
    /// Protocol version byte, verbatim from the wire.
    pub version: u8,
    /// The peer's role, as [`ScoutedHello::whatami`].
    pub whatami: Option<WhatAmI>,
    /// The peer's zid, verbatim.
    pub zid: SessionZid,
    /// Where each kept locator ends in `text`.
    ends: [usize; caps::SCOUT_HELLO_LOCATORS],
    kept: usize,
    skipped: usize,
    text: HelloLocatorText,
}

impl PartialEq for HelloRow {
    /// The same Hello: its version, role, zid and the locators it kept and skipped. The bytes of
    /// the text past the kept locators are no part of it.
    fn eq(&self, other: &Self) -> bool {
        self.version == other.version
            && self.whatami == other.whatami
            && self.zid == other.zid
            && self.skipped == other.skipped
            && self.locators().eq(other.locators())
    }
}

impl Eq for HelloRow {}

impl HelloRow {
    /// A row of no Hello: what a table's rows hold before one is decoded into them. Its zid is a
    /// placeholder no read of the table reaches.
    pub const EMPTY: Self = Self {
        version: 0,
        whatami: None,
        zid: PLACEHOLDER_ZID,
        ends: [0; caps::SCOUT_HELLO_LOCATORS],
        kept: 0,
        skipped: 0,
        text: [0; HELLO_LOCATOR_TEXT],
    };

    /// The row made over again for a Hello of no locator yet, in place: its text is not cleared,
    /// as only the kept locators' bytes are read.
    fn reset(&mut self, version: u8, whatami: Option<WhatAmI>, zid: SessionZid) {
        self.version = version;
        self.whatami = whatami;
        self.zid = zid;
        self.kept = 0;
        self.skipped = 0;
    }

    /// Decode one inbound scouting datagram into this row, in place, as [`decode_scouted_hello`]
    /// decodes it, writing the locators into the row's text and nothing onto the heap, each held
    /// to `locator_len`, the `MAX_LOCATOR_LEN` of the window's runtime limits: `false` when it is
    /// no well-formed Hello naming a zid, the row then holding no Hello to read.
    pub fn decode_into(&mut self, bytes: &[u8], locator_len: MaxLocatorLenHeld) -> bool {
        let Ok(view) = ScoutingHelloView::decode(&mut SceCursor::new(bytes)) else {
            return false;
        };
        let hello = view.body;
        let Ok(zid) = SessionZid::new(hello.zid.into_inner()) else {
            return false;
        };
        self.reset(hello.version, WhatAmI::from_wire(hello.cbyte), zid);
        if let Some(locators) = hello.locators.as_ref() {
            for entry in locators.inner().iter() {
                self.keep(entry.locator.inner(), locator_len);
            }
        }
        true
    }

    /// This row made a copy of `source`, in place: no row passes through a stack.
    fn copy_from(&mut self, source: &HelloRow) {
        self.reset(source.version, source.whatami, source.zid);
        let used = source.start_of(source.kept);
        if let (Some(into), Some(from)) = (self.text.get_mut(..used), source.text.get(..used)) {
            into.copy_from_slice(from);
        }
        self.ends = source.ends;
        self.kept = source.kept;
        self.skipped = source.skipped;
    }

    /// `locator` kept after the others, or skipped and counted when the row has no row for it,
    /// it is longer than `locator_len` admits, or the row's text has no room for it (a build that
    /// fixes `MAX_LOCATOR_LEN` leaves its bound to that room).
    fn keep(&mut self, locator: &str, locator_len: MaxLocatorLenHeld) {
        let start = self.start_of(self.kept);
        let end = start.saturating_add(locator.len());
        // No end left for one more locator, or no room in the text for this one: skipped.
        let room = (self.text.get_mut(start..end), self.ends.get_mut(self.kept));
        let (Some(into), Some(slot)) = room else {
            self.skipped = self.skipped.saturating_add(1);
            return;
        };
        if !locator_len.admits(locator.len()) {
            self.skipped = self.skipped.saturating_add(1);
            return;
        }
        into.copy_from_slice(locator.as_bytes());
        *slot = end;
        self.kept = self.kept.saturating_add(1);
    }

    fn start_of(&self, k: usize) -> usize {
        k.checked_sub(1)
            .and_then(|last| self.ends.get(last))
            .copied()
            .unwrap_or(0)
    }

    /// The row of `hello`, its locators kept as a window whose runtime limits state no
    /// `MAX_LOCATOR_LEN` keeps them.
    pub fn of(hello: &ScoutedHello) -> Self {
        let locator_len = RuntimeLimits::BUILD.max_locator_len_held();
        let mut row = Self::EMPTY;
        row.reset(hello.version, hello.whatami, hello.zid);
        for locator in &hello.locators {
            row.keep(locator, locator_len);
        }
        row
    }

    /// The locators kept, in wire order.
    pub fn locators(&self) -> impl Iterator<Item = &str> + '_ {
        (0..self.kept).filter_map(|k| HelloFacts::locator(self, k))
    }

    /// How many locators the Hello advertised and the row skipped.
    pub fn skipped_locators(&self) -> usize {
        self.skipped
    }

    /// How many locators the Hello advertised, kept or skipped.
    pub fn advertised_locators(&self) -> usize {
        self.kept.saturating_add(self.skipped)
    }

    /// The Hello as a host keeps it, its kept locators copied.
    pub fn to_hello(&self) -> ScoutedHello {
        ScoutedHello {
            version: self.version,
            whatami: self.whatami,
            zid: self.zid,
            locators: self.locators().map(String::from).collect(),
        }
    }
}

impl HelloFacts for HelloRow {
    fn whatami(&self) -> Option<WhatAmI> {
        self.whatami
    }

    fn zid(&self) -> &SessionZid {
        &self.zid
    }

    fn locator_count(&self) -> usize {
        self.kept
    }

    fn locator(&self, k: usize) -> Option<&str> {
        if k >= self.kept {
            return None;
        }
        let end = *self.ends.get(k)?;
        core::str::from_utf8(self.text.get(self.start_of(k)..end)?).ok()
    }
}

/// The zid of a row no Hello was decoded into: a zid is never zero, and no read of a table reaches
/// a row's before a Hello is decoded into it.
const PLACEHOLDER_ZID: SessionZid = SessionZid::from_array([1]);

/// The Hellos a window records, in arrival order, in a table of `MAX_SCOUT_HELLOS` rows and one
/// more the next Hello is decoded into: what a host with no heap lends its window
/// ([`ScoutWindowPlace::build_over`]). It is made where the host keeps the scout's state, never on
/// a stack, which its size is not for. A Hello past the rows is counted and not recorded.
#[derive(Debug)]
pub struct HelloTable {
    rows: [HelloRow; caps::MAX_SCOUT_HELLOS + 1],
    held: usize,
    refused: usize,
    /// The longest locator a row keeps, `MAX_LOCATOR_LEN` as the creator's runtime limits state it
    /// ([`Self::limit_to`]).
    locator_len: MaxLocatorLenHeld,
}

impl Default for HelloTable {
    fn default() -> Self {
        Self::new()
    }
}

impl HelloTable {
    /// A table of no Hello, which a `static` can hold, keeping locators to the build's
    /// `MAX_LOCATOR_LEN` until its creator states the runtime's ([`Self::limit_to`]).
    pub const fn new() -> Self {
        Self {
            rows: [HelloRow::EMPTY; caps::MAX_SCOUT_HELLOS + 1],
            held: 0,
            refused: 0,
            locator_len: RuntimeLimits::BUILD.max_locator_len_held(),
        }
    }

    /// [`Self::new`] made in `place`, whatever it held, and lent back, with no table made beside it
    /// and copied in. A host that keeps the table in a static of no initial value makes it there
    /// for each window, so the library's file holds none of it and only a scout writes its memory.
    /// The bytes are zeroed, and then the fields whose zero is no value of theirs are written: each
    /// row's role and zid, and the locator quota.
    pub fn init_in(place: &mut MaybeUninit<Self>) -> &mut Self {
        let at = place.as_mut_ptr();
        // SAFETY: `at` is valid for writes of a table, borrowed through `place`. Zero is a value of
        // every field but a row's role and zid and the quota, which are written before the table is
        // lent: it then holds what `Self::new` makes.
        unsafe {
            at.write_bytes(0, 1);
            let rows = core::ptr::addr_of_mut!((*at).rows).cast::<HelloRow>();
            for i in 0..caps::MAX_SCOUT_HELLOS + 1 {
                let row = rows.add(i);
                core::ptr::addr_of_mut!((*row).whatami).write(None);
                core::ptr::addr_of_mut!((*row).zid).write(PLACEHOLDER_ZID);
            }
            core::ptr::addr_of_mut!((*at).locator_len)
                .write(RuntimeLimits::BUILD.max_locator_len_held());
            place.assume_init_mut()
        }
    }

    /// Holds the locators the rows keep from the next Hello on to `quota`, `MAX_LOCATOR_LEN` as
    /// the creator's runtime limits state it: a longer one is skipped and counted with its Hello.
    /// A window clears the table and keeps this.
    pub fn limit_to(&mut self, quota: MaxLocatorLenHeld) {
        self.locator_len = quota;
    }

    /// No Hello recorded and none refused, for the next window.
    pub fn clear(&mut self) {
        self.held = 0;
        self.refused = 0;
    }

    /// The row the next Hello is decoded into: the one past those held, of which the table keeps
    /// one more than it records, so it is always there.
    fn staged(&mut self) -> Option<&mut HelloRow> {
        self.rows.get_mut(self.held)
    }

    /// `bytes` decoded into the staged row: whether it is a Hello the window advances on.
    fn stage(&mut self, bytes: &[u8], exit_on_first: bool) -> bool {
        let locator_len = self.locator_len;
        self.staged().is_some_and(|row| {
            row.decode_into(bytes, locator_len)
                && hello_advances_window(exit_on_first, row.advertised_locators())
        })
    }

    /// The staged row recorded after the others, or counted when the rows are full.
    fn record_staged(&mut self) {
        if self.held < caps::MAX_SCOUT_HELLOS {
            self.held = self.held.saturating_add(1);
        } else {
            self.refused = self.refused.saturating_add(1);
        }
    }

    /// A copy of `row` recorded after the others; `false`, and the copy counted, when the rows are
    /// full.
    pub fn push(&mut self, row: &HelloRow) -> bool {
        let recorded = self.held < caps::MAX_SCOUT_HELLOS;
        if let Some(staged) = self.staged() {
            staged.copy_from(row);
        }
        self.record_staged();
        recorded
    }

    /// The rows, in arrival order.
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &HelloRow> + '_ {
        self.rows.iter().take(self.held)
    }

    /// How many Hellos are recorded.
    pub fn len(&self) -> usize {
        self.held
    }

    /// Whether none is.
    pub fn is_empty(&self) -> bool {
        self.held == 0
    }

    /// The first Hello recorded.
    pub fn first(&self) -> Option<&HelloRow> {
        self.iter().next()
    }

    /// How many Hellos the window took and did not record, its rows full.
    pub fn refused(&self) -> usize {
        self.refused
    }
}

/// The record a host with no heap lends its window: a [`HelloTable`] where the host keeps the
/// scout's state, which the window records its Hellos in and its holder reads once the window has
/// resolved. It keeps no list of the datagrams the window drops: their counts are every window's.
/// Made only by [`ScoutWindowPlace::build_over`], whose contract it holds.
pub struct LentTable(NonNull<HelloTable>);

// SAFETY: the table is reached through this only while the window that was lent it is pumped, by
// the one thread that pumps it (`ScoutWindowPlace::build_over`'s contract).
unsafe impl Send for LentTable {}
// SAFETY: as for `Send`.
unsafe impl Sync for LentTable {}

impl LentTable {
    /// The table.
    ///
    /// # Safety
    /// As [`ScoutWindowPlace::build_over`] states: the table outlives the window and nothing else
    /// reaches it while the window is pumped.
    unsafe fn get<'t>(&self) -> &'t mut HelloTable {
        &mut *self.0.as_ptr()
    }
}

impl<R: Runtime> HelloRecord<R> for LentTable {
    fn stage(&self, bytes: &[u8], exit_on_first: bool) -> bool {
        // SAFETY: `build_over`'s contract: the window that is pumped owns the table.
        unsafe { self.get() }.stage(bytes, exit_on_first)
    }

    fn record_staged(&self) {
        // SAFETY: as for `stage`.
        unsafe { self.get() }.record_staged();
    }

    #[cfg(feature = "scout-rx-verdicts")]
    fn record_ignored(&self, _why: ScoutRxIgnored) {}

    /// The first locator of the first row that kept one: the table's rows are what the window
    /// discovered, and no locator is copied out of them until it is asked for.
    fn discovered_locator(&self) -> Option<String> {
        // SAFETY: as for `stage`: the table outlives the state that holds this.
        unsafe { self.get() }
            .iter()
            .find_map(|row| row.locator(0))
            .map(String::from)
    }
}

impl<R: Runtime> ScoutingActions<R> {
    /// The state bundle for one discovery window over the heap collection. `params` are captured
    /// by value; the staging slots start empty.
    pub fn new(params: ScoutParams) -> Arc<Self> {
        Arc::new(Self::with(params, HelloList::new()))
    }

    /// Every Hello decoded in this window, in arrival order, complete with role, zid and all
    /// locators: the pico-shaped read, where [`Self::discovered_locator`] is the dial-target
    /// read.
    ///
    /// A non-empty result with an EMPTY `locators` is meaningful: a peer answered and advertised
    /// no address, which must not read as silence.
    pub fn scouted_hellos(&self) -> Vec<ScoutedHello> {
        R::with_mutex_mut(&self.record.hellos, |hellos| hellos.clone())
    }

    /// Every datagram this window observed and did not take as a Hello, with the reason, in
    /// arrival order. See [`HelloList::ignored`] for why the record is a value.
    #[cfg(feature = "scout-rx-verdicts")]
    pub fn ignored_datagrams(&self) -> Vec<ScoutRxIgnored> {
        R::with_mutex_mut(&self.record.ignored, |ignored| ignored.clone())
    }
}

impl<R: Runtime> ScoutingActions<R, LentTable> {
    /// The state bundle for one window that records its Hellos in `table`, which it clears: the
    /// form of a host with no heap, whose table lies where it keeps the scout's state. The bundle
    /// holds a pointer to the table and none of it.
    ///
    /// # Safety
    /// `table` outlives every use of the bundle, and nothing else reads or writes it until the
    /// window is over: its holder reads it once the window has resolved.
    unsafe fn over_table(params: ScoutParams, table: &mut HelloTable) -> Self {
        table.clear();
        Self::with(params, LentTable(NonNull::from(table)))
    }

    /// How many Hellos the window took and did not record, past the lent table's rows.
    pub fn hellos_refused(&self) -> usize {
        // SAFETY: `over_table`'s contract: the table outlives the bundle.
        unsafe { self.record.get() }.refused()
    }
}

impl<R: Runtime, K: HelloRecord<R>> ScoutingActions<R, K> {
    fn with(params: ScoutParams, record: K) -> Self {
        Self {
            params,
            trace: R::new_mutex(ScoutTrace::default()),
            pending_scout: R::new_mutex(None),
            record,
            ignored_counts: R::new_mutex(IgnoredCounts::default()),
        }
    }

    /// Where the window records its Hellos.
    pub fn record(&self) -> &K {
        &self.record
    }

    /// Field-by-field `Copy` snapshot of the dispatch counters, lifted out from under the lock.
    pub fn trace_snapshot(&self) -> ScoutTrace {
        R::with_mutex_mut(&self.trace, |trace| trace.clone_via_copy())
    }

    /// The discovered locator, if a Hello locator was captured
    /// ([`HelloRecord::discovered_locator`]).
    pub fn discovered_locator(&self) -> Option<String> {
        self.record.discovered_locator()
    }

    /// How many datagrams this window observed and did not take as a Hello, by verdict with
    /// `scout-rx-verdicts`: the record every window keeps, and the only one a window over a lent
    /// table keeps.
    pub fn ignored_counts(&self) -> IgnoredCounts {
        R::with_mutex_mut(&self.ignored_counts, |counts| *counts)
    }

    /// Record one non-Hello observation, and say so at a severity that matches what the verdict
    /// MEANS here, which is not always what it means upstream.
    ///
    /// `Undecodable` and `UnknownMid` are upstream's two error arms and are anomalous here too.
    /// The other three are not: the scouting socket asks for `IP_MULTICAST_LOOP` so its own Scout
    /// comes back, a second node scouting the same group is ordinary, and a peer that answers
    /// with no address is a peer. Logging those at pico's severity would put a warning on the
    /// window's own traffic once per cycle (see [`crate::scout_initiator`]).
    #[cfg(feature = "scout-rx-verdicts")]
    fn record_ignored(&self, why: ScoutRxIgnored) {
        match &why {
            ScoutRxIgnored::Undecodable => {
                crate::diag_warn!("scouting window: received malformed message; ignored")
            }
            ScoutRxIgnored::UnknownMid { mid } => {
                crate::diag_warn!(
                    "scouting window: received unexpected message (mid {mid:#04x}); ignored"
                )
            }
            ScoutRxIgnored::SelfEcho => {
                crate::diag_debug!("scouting window: our own Scout, looped back; ignored")
            }
            ScoutRxIgnored::ForeignScout => {
                crate::diag_debug!("scouting window: another node's Scout; ignored")
            }
            ScoutRxIgnored::LocatorlessHello => {
                crate::diag_debug!(
                    "scouting window: a Hello advertising no locator; still searching"
                )
            }
        }
        R::with_mutex_mut(&self.ignored_counts, |counts| counts.count(&why));
        self.record.record_ignored(why);
    }

    /// Record one datagram the window observed and did not take as a Hello, in the one count a
    /// window keeps without the verdicts.
    #[cfg(not(feature = "scout-rx-verdicts"))]
    fn count_not_taken(&self) {
        R::with_mutex_mut(&self.ignored_counts, IgnoredCounts::count_one);
    }

    /// Idle -> Sending entering transition: encode one Scout frame and stage the datagram for the
    /// host to transmit. Pure: no socket access. Mirrors zenoh-pico's `_z_link_send_wbuf` in
    /// `scout.c`, except the send itself is the host's job.
    fn scout_emit(&self) {
        let a = self;
        R::with_mutex_mut(&a.trace, |trace| {
            trace.scout_emit = trace.scout_emit.saturating_add(1)
        });
        let zid = a.params.zid;
        // `what` in the flags byte's low three bits; the I flag and the zid's length
        // above them are the document's, from whether a zid is presented. No zid
        // is the Scout that names no asker (I clear), as zenoh's own is.
        let mut flags = Scout::new();
        flags.set_what(a.params.what);
        let body = ScoutParts {
            version: wz_codecs::wire_const::PROTOCOL_VERSION,
            cbyte: flags.cbyte,
            // A zid holds its bytes within the codec's own bounds (`zid_len_m1`
            // is four bits).
            zid: zid.as_ref().map(SessionZid::as_field),
        };
        // The whole message, header and chain included, by its document
        // (`sources/codecs/scouting_scout.scxml`).
        let message = ScoutingScoutParts {
            header: wire_const::S_MID_SCOUT,
            body: &body,
            extensions: None,
        };
        let mut frame = ScoutFrame {
            bytes: [0; SCOUT_DATAGRAM_BYTES],
            len: 0,
        };
        let mut sink = SliceSink::new(&mut frame.bytes);
        let written =
            ScoutingScoutWire::encode_source(&message, &mut sink).map(|()| sink.position());
        // A Scout this codec writes fits the frame; one that did not would stage nothing, and the
        // host reports the send as failed.
        let staged = written.ok().map(|len| {
            frame.len = len;
            frame
        });
        R::with_mutex_mut(&a.pending_scout, |slot| *slot = staged);
    }

    /// `hello.received`: record the staged Hello whole.
    ///
    /// This is pico's `_Z_MID_HELLO` arm and nothing else: push the decoded hello onto the list.
    /// Runs on BOTH `hello.received` arms, because pico pushes before it consults
    /// `exit_on_first`: the mode decides whether the window keeps running, never whether the peer
    /// is recorded.
    fn record_hello(&self) {
        R::with_mutex_mut(&self.trace, |trace| {
            trace.record_hello = trace.record_hello.saturating_add(1)
        });
        self.record.record_staged();
    }

    /// AwaitingHello -> Idle on scout.timer.elapsed: the window expired with no Hello.
    /// Observability only; nothing is discovered.
    fn count_timeout(&self) {
        R::with_mutex_mut(&self.trace, |trace| {
            trace.scout_timeout = trace.scout_timeout.saturating_add(1)
        });
    }

    /// Sending -> Idle on link.tx_failed: the multicast Scout transmit errored.
    fn count_tx_failed(&self) {
        R::with_mutex_mut(&self.trace, |trace| {
            trace.tx_failed = trace.tx_failed.saturating_add(1)
        });
    }
}

/// How the scouting machine's actions reach the state they write: an `Arc` of it the machine
/// shares with its holder, or a pointer to a state its holder keeps in place ([`PlacedActions`]).
pub trait ActionsReach: 'static {
    /// The runtime of the state's locks.
    type Runtime: Runtime;
    /// The record the state keeps its Hellos in.
    type Record: HelloRecord<Self::Runtime>;
    /// The state.
    fn reached(&self) -> &ScoutingActions<Self::Runtime, Self::Record>;
}

impl<R: Runtime, K: HelloRecord<R>> ActionsReach for Arc<ScoutingActions<R, K>> {
    type Runtime = R;
    type Record = K;

    fn reached(&self) -> &ScoutingActions<R, K> {
        self
    }
}

/// A reach of a state its holder keeps in place and shares with no one: a pointer, which no `Arc`
/// backs. Made only by a window that holds its state ([`WindowHolding::reach`]), which outlives
/// the machine that owns this and does not move while it lives.
pub struct PlacedActions<R: Runtime, K>(NonNull<ScoutingActions<R, K>>);

// SAFETY: the reach lends the state as a shared reference only, so it may go to another thread, or
// be shared between threads, exactly when a shared reference to the state may.
unsafe impl<R: Runtime, K> Send for PlacedActions<R, K> where ScoutingActions<R, K>: Sync {}
// SAFETY: as for `Send`.
unsafe impl<R: Runtime, K> Sync for PlacedActions<R, K> where ScoutingActions<R, K>: Sync {}

impl<R: Runtime, K: HelloRecord<R>> ActionsReach for PlacedActions<R, K> {
    type Runtime = R;
    type Record = K;

    fn reached(&self) -> &ScoutingActions<R, K> {
        // SAFETY: the state's holder keeps it in place for longer than the machine that owns this
        // reach (`WindowHolding::reach`).
        unsafe { self.0.as_ref() }
    }
}

/// The generated policy's owner of the state: a reach of the caller's [`ScoutingActions`], so the
/// four native actions mutate the slots the caller reads back. Over a shared state the reach is a
/// clone of the caller's `Arc`; over a state a window holds in its place it is a pointer, which
/// the window outlives ([`ScoutWindowPlace::build_over`]).
pub struct ScoutActionsBinding<A> {
    reach: A,
}

impl<A: ActionsReach> ScoutingActionsTrait for ScoutActionsBinding<A> {
    // This host performs the machine's duties. `scout_emit` stages the datagram the host sends
    // and `record_hello_and_emit` writes the record the caller reads back. `emit_scout_timeout`
    // and `diag_scout_tx_failed` are notices that only count: a window that ends with no Hello
    // discovers nothing whether or not they run.
    const REALIZATION: ::sce_rust_runtime::ActionRealization =
        ::sce_rust_runtime::ActionRealization::Performs;

    fn scout_emit(&mut self) {
        self.reach.reached().scout_emit();
    }

    fn record_hello_and_emit(&mut self) {
        self.reach.reached().record_hello();
    }

    fn emit_scout_timeout(&mut self) {
        self.reach.reached().count_timeout();
    }

    fn diag_scout_tx_failed(&mut self) {
        self.reach.reached().count_tx_failed();
    }
}

/// The scouting machine a host pumps, its actions reaching their state through `A`.
pub type ScoutEngine<A> = Engine<ScoutingPolicy<ScoutActionsBinding<A>>>;

/// Build a scouting engine over the generated policy, parameterised over a
/// [`ScoutActionsBinding`] wrapping a clone of `actions`. The caller retains `actions` and pumps
/// the engine ([`open_window`] and the functions after it).
pub fn new_scouting_engine<R: Runtime, K: HelloRecord<R>>(
    actions: &Arc<ScoutingActions<R, K>>,
) -> ScoutEngine<Arc<ScoutingActions<R, K>>> {
    engine_over(Arc::clone(actions))
}

fn engine_over<A: ActionsReach>(reach: A) -> ScoutEngine<A> {
    Engine::new(ScoutingPolicy::new_with_checked_session_id(
        SCOUTING_SESSION_ID,
        ScoutActionsBinding { reach },
    ))
}

/// The id the scouting machine is built under (the host gives a machine its id, and the generated
/// constructor refuses a text that is not an XML Nmtoken). A constant, so that refusal is never
/// met.
const SCOUTING_SESSION_ID: sce_rust_runtime::helpers::session_id::SessionId =
    sce_rust_runtime::session_id!("wz-scouting");

/// zenoh's default scouting multicast locator.
pub const MULTICAST_LOCATOR_DEFAULT: &str = "udp/224.0.0.224:7446";

/// The default scouting budget, in milliseconds (pico `Z_CONFIG_SCOUTING_TIMEOUT_DEFAULT`).
pub const SCOUTING_TIMEOUT_DEFAULT_MS: u64 = 1000;

/// The default `what` mask (pico `Z_CONFIG_SCOUTING_WHAT_DEFAULT`): router and peer.
pub const SCOUTING_WHAT_DEFAULT: u8 = 0x03;

/// The tick a host that polls its sockets paces its window by, in milliseconds.
pub const SCOUT_TICK_MS: u64 = 50;

/// Parse a `udp/ADDR:PORT` multicast locator. An IPv6 group is bracketed, as a socket address
/// writes it (`udp/[ff05::231]:7446`).
///
/// `None` for anything a UDP scouting window cannot bind, so an unsupported locator FAILS the
/// scout rather than silently falling back to the default group: a scout that searches somewhere
/// the caller did not ask about is worse than an error.
pub fn parse_multicast_locator(locator: &str) -> Option<(core::net::IpAddr, u16)> {
    let rest = locator.strip_prefix("udp/")?;
    let addr: core::net::SocketAddr = rest.parse().ok()?;
    Some((addr.ip(), addr.port()))
}

/// Hand the window's peers to `on_hello` in UPSTREAM'S DELIVERY ORDER, which is the REVERSE of
/// arrival, and return how many were delivered.
///
/// This is not a detail: it is observable through both C ABIs. `_z_scout_inner` accumulates with
/// `_z_hello_slist_push_empty`, which PREPENDS (`vendor/zenoh-pico/src/collections/list.c` @
/// `_z_list_t *_z_list_push(`), and `_z_scout` then drains from the head
/// (`vendor/zenoh-pico/src/net/primitives.c` @ `_z_hello_slist_t *hellos = _z_scout_inner(`). So
/// a pico program's closure sees the LAST responder first. The window records in arrival order,
/// the useful order for everything else, so the reversal lives here, at the one seam where
/// upstream's contract is imitated, and not in the accumulator where it would be a strange rule
/// with no reason attached.
///
/// Delivery happens AFTER the window for the same reason: upstream's callback is not called from
/// inside the scouting loop. `_z_scout_inner` returns a list and only then is it drained, so a
/// pico program prints nothing for the whole budget and then everything at once. Firing per-Hello
/// would be a divergence in this implementation's favour, which is still a divergence.
pub fn deliver_in_upstream_order(
    hellos: &[ScoutedHello],
    mut on_hello: impl FnMut(&ScoutedHello),
) -> usize {
    for hello in hellos.iter().rev() {
        on_hello(hello);
    }
    hellos.len()
}

/// [`deliver_in_upstream_order`] over a window's own table: each row lent to `on_hello`, last
/// responder first, and none copied.
pub fn deliver_rows_in_upstream_order(
    hellos: &HelloTable,
    mut on_hello: impl FnMut(&HelloRow),
) -> usize {
    for hello in hellos.iter().rev() {
        on_hello(hello);
    }
    hellos.len()
}

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
pub fn open_window<R: Runtime, K: HelloRecord<R>, A: ActionsReach>(
    actions: &ScoutingActions<R, K>,
    engine: &mut ScoutEngine<A>,
) -> Option<ScoutFrame> {
    engine.initialize().unwrap_or_else(|never| match never {});
    // Idle -> Sending: `scout_emit` fires on the entering transition and stages the datagram.
    engine.process_event(ScoutingEvent::SessionOpenRequested);
    R::with_mutex_mut(&actions.pending_scout, |slot| slot.take())
}

/// Tell the machine whether the Scout went out: `Sending -> AwaitingHello` when it did,
/// `Sending -> Idle` when the send failed.
pub fn window_sent<A: ActionsReach>(engine: &mut ScoutEngine<A>, sent: bool) {
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
/// window observes lands in exactly one of the record's Hellos (recorded, or counted as refused)
/// and the ignored counts.
pub fn window_datagram<R: Runtime, K: HelloRecord<R>, A: ActionsReach>(
    actions: &ScoutingActions<R, K>,
    engine: &mut ScoutEngine<A>,
    bytes: &[u8],
) {
    let exit_on_first = actions.params.exit_on_first;
    let advanced = if bytes.first().map(|h| h & 0x1f) == Some(wire_const::S_MID_HELLO) {
        let staged = actions.record.stage(bytes, exit_on_first);
        // Undecodable, or decodable and declined by the window's rule: both are counted as
        // ignored, each under its own verdict.
        if staged {
            // The window's mode rides the event: the generated machine has no datamodel, so its
            // two `hello.received` arms guard on this typed field. Lent for the one call that
            // processes it, so no payload is queued.
            engine.process_hello_received_with(ScoutingHelloReceivedRef {
                exit_on_first: u8::from(exit_on_first),
            });
        }
        staged
    } else {
        false
    };
    if !advanced {
        #[cfg(feature = "scout-rx-verdicts")]
        actions.record_ignored(classify_ignored_scout_rx(
            actions.params.zid.as_deref().unwrap_or(&[]),
            bytes,
        ));
        #[cfg(not(feature = "scout-rx-verdicts"))]
        actions.count_not_taken();
    }
}

/// Tell the window that `elapsed_ms` have passed since the Scout went out: once the budget
/// ([`ScoutParams::timeout_ms`]) has elapsed with no Hello, raise the timeout (`AwaitingHello ->
/// Idle`). Only `AwaitingHello` handles the event, so calling it in any other state is a no-op.
pub fn window_tick<R: Runtime, K: HelloRecord<R>, A: ActionsReach>(
    actions: &ScoutingActions<R, K>,
    engine: &mut ScoutEngine<A>,
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
pub fn window_resolved<A: ActionsReach>(engine: &ScoutEngine<A>) -> bool {
    engine.get_current_state() == ScoutingState::Idle
}

/// How a resolved window ended: the first locator it captured, or that it timed out.
pub fn window_outcome<R: Runtime, K: HelloRecord<R>>(
    actions: &ScoutingActions<R, K>,
) -> ScoutOutcome {
    match actions.discovered_locator() {
        Some(locator) => ScoutOutcome::Discovered(locator),
        None => ScoutOutcome::TimedOut,
    }
}

/// One scouting window as a single value, for a host that pumps it from a loop of its own: the
/// actions the answers land on, the machine, and the time the Scout went out. How the window holds
/// its state is its type `S` ([`WindowHolding`]): shared behind an `Arc`
/// ([`SharedWindowState`]), or held in the window over a table its host lends
/// ([`LentWindowState`]).
///
/// ```text
/// let mut window = ScoutWindow::<SharedWindowState<R>>::new(params);
/// let scout = window.open();                    // the datagram to send on the group
/// window.sent(now_ms, send(scout).is_ok());     // the budget runs from here
/// while !window.resolved() {
///     for datagram in receive() { window.datagram(&datagram); }
///     window.tick(now_ms());
/// }
/// let hellos = window.actions().scouted_hellos();
/// ```
pub struct ScoutWindow<S: WindowHolding> {
    // Before `actions`, so the machine that reaches them goes first.
    engine: ScoutEngine<S::Reach>,
    actions: S,
    started_ms: u64,
}

/// How a window holds the state its machine's actions write, and how the machine reaches it.
pub trait WindowHolding: Sized + 'static {
    /// The runtime of the state's locks.
    type Runtime: Runtime;
    /// The record the state keeps its Hellos in.
    type Record: HelloRecord<Self::Runtime>;
    /// How the machine reaches the state.
    type Reach: ActionsReach<Runtime = Self::Runtime, Record = Self::Record>;
    /// The state.
    fn state(&self) -> &ScoutingActions<Self::Runtime, Self::Record>;
    /// The reach the window's machine keeps.
    ///
    /// # Safety
    /// A state held by value ([`PlacedActions`]) is not moved while the reach lives: the reach
    /// points where it lies.
    unsafe fn reach(&self) -> Self::Reach;
}

/// The state of a window that shares it behind an `Arc` and records into the heap collection:
/// what a host with a heap pumps, and reads once the window is gone.
pub type SharedWindowState<R> = Arc<ScoutingActions<R>>;

/// The state of a window that holds it in its place and records into a table its host lends:
/// what a host with no heap pumps ([`ScoutWindowPlace::build_over`]).
pub type LentWindowState<R> = ScoutingActions<R, LentTable>;

impl<R: Runtime, K: HelloRecord<R>> WindowHolding for Arc<ScoutingActions<R, K>> {
    type Runtime = R;
    type Record = K;
    type Reach = Self;

    fn state(&self) -> &ScoutingActions<R, K> {
        self
    }

    unsafe fn reach(&self) -> Self {
        Arc::clone(self)
    }
}

impl<R: Runtime, K: HelloRecord<R>> WindowHolding for ScoutingActions<R, K> {
    type Runtime = R;
    type Record = K;
    type Reach = PlacedActions<R, K>;

    fn state(&self) -> &ScoutingActions<R, K> {
        self
    }

    unsafe fn reach(&self) -> PlacedActions<R, K> {
        PlacedActions(NonNull::from(self))
    }
}

impl<R: Runtime> ScoutWindow<SharedWindowState<R>> {
    /// A window over `params`, not yet open, recording into the heap collection.
    pub fn new(params: ScoutParams) -> Self {
        let mut place = MaybeUninit::uninit();
        // SAFETY: a window over a shared state may move: its machine reaches the state in the
        // `Arc`, not in the window.
        unsafe { Self::write_in(&mut place, ScoutingActions::<R>::new(params)) };
        // SAFETY: `write_in` wrote every field of the window into `place`.
        unsafe { place.assume_init() }
    }
}

impl<R: Runtime, K: HelloRecord<R>> ScoutWindow<Arc<ScoutingActions<R, K>>> {
    /// The state the answers land on as the window shares it, for a holder that reads it once the
    /// window is gone.
    pub fn shared_actions(&self) -> &Arc<ScoutingActions<R, K>> {
        &self.actions
    }
}

impl<S: WindowHolding> ScoutWindow<S> {
    /// The window over `actions` written field by field into `place`, which is overwritten without
    /// dropping what it held. Never inlined, for the stack: the machine is made in this frame and
    /// written into its field, and the frame has returned before the window is pumped.
    ///
    /// # Safety
    /// A window whose state it holds by value is not moved out of `place` while it lives: its
    /// machine reaches the state where it was written.
    #[inline(never)]
    unsafe fn write_in(place: &mut MaybeUninit<Self>, actions: S) {
        let at = place.as_mut_ptr();
        // SAFETY: `at` is valid for writes of a `Self`, and each field is written once; the state
        // is written before the machine that reaches it, and the caller keeps a held state where
        // it was written for as long as the window, whose machine is dropped first.
        unsafe {
            core::ptr::addr_of_mut!((*at).actions).write(actions);
            let reach = (*core::ptr::addr_of!((*at).actions)).reach();
            core::ptr::addr_of_mut!((*at).engine).write(engine_over(reach));
            core::ptr::addr_of_mut!((*at).started_ms).write(0);
        }
    }

    /// The state the answers land on.
    pub fn actions(&self) -> &ScoutingActions<S::Runtime, S::Record> {
        self.actions.state()
    }

    /// Open the window ([`open_window`]): the Scout datagram to send.
    pub fn open(&mut self) -> Option<ScoutFrame> {
        open_window(self.actions.state(), &mut self.engine)
    }

    /// The Scout was sent, or was not ([`window_sent`]); `now_ms` is the host's clock, from which
    /// the budget runs.
    pub fn sent(&mut self, now_ms: u64, sent: bool) {
        self.started_ms = now_ms;
        window_sent(&mut self.engine, sent);
    }

    /// One datagram arrived ([`window_datagram`]).
    pub fn datagram(&mut self, bytes: &[u8]) {
        window_datagram(self.actions.state(), &mut self.engine, bytes);
    }

    /// The host's clock reads `now_ms` ([`window_tick`]).
    pub fn tick(&mut self, now_ms: u64) {
        window_tick(
            self.actions.state(),
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
        window_outcome(self.actions.state())
    }
}

/// A place a [`ScoutWindow`] is built in where its holder lies, and dropped with it: what a host
/// whose stack is to stay shallow pumps its window from. The window (the scouting machine and its
/// actions) is written once in the holder's frame, never returned into it, and the frame that
/// builds the machine has returned before the window is pumped.
pub struct ScoutWindowPlace<S: WindowHolding> {
    window: MaybeUninit<ScoutWindow<S>>,
    built: bool,
}

impl<S: WindowHolding> ScoutWindowPlace<S> {
    /// A place with no window in it.
    pub const fn empty() -> Self {
        Self {
            window: MaybeUninit::uninit(),
            built: false,
        }
    }

    /// # Safety
    /// As [`ScoutWindow::write_in`]: a held state is not moved out of the place.
    unsafe fn build_with(&mut self, actions: S) -> &mut ScoutWindow<S> {
        assert!(!self.built, "a place holds one window");
        // SAFETY: the caller's; the place lends the window only through `&mut`, and gives no
        // other way to it.
        unsafe { ScoutWindow::write_in(&mut self.window, actions) };
        self.built = true;
        // SAFETY: `write_in` wrote every field of the window into this place.
        unsafe { self.window.assume_init_mut() }
    }
}

impl<R: Runtime> ScoutWindowPlace<SharedWindowState<R>> {
    /// A window over `params` built in this place and lent for as long as the place is. A place
    /// holds one window: building a second in it is refused with a panic, and the first is kept.
    pub fn build(&mut self, params: ScoutParams) -> &mut ScoutWindow<SharedWindowState<R>> {
        // SAFETY: a window over a shared state may move.
        unsafe { self.build_with(ScoutingActions::<R>::new(params)) }
    }
}

impl<R: Runtime> ScoutWindowPlace<LentWindowState<R>> {
    /// A window over `params` that records its Hellos in `table`, which it clears, built in this
    /// place as [`ScoutWindowPlace::build`] builds one, its state held in the place beside its
    /// machine: the window makes no allocation.
    ///
    /// # Safety
    /// `table` outlives this place, and nothing else reads or writes it until the window has
    /// resolved. The window lent is not moved out of the place (by `core::mem::swap` or
    /// `core::mem::replace`): its machine reaches its state where the place holds it.
    pub unsafe fn build_over(
        &mut self,
        params: ScoutParams,
        table: &mut HelloTable,
    ) -> &mut ScoutWindow<LentWindowState<R>> {
        // SAFETY: the caller's.
        unsafe { self.build_with(ScoutingActions::over_table(params, table)) }
    }
}

impl<S: WindowHolding> Drop for ScoutWindowPlace<S> {
    fn drop(&mut self) {
        if self.built {
            // SAFETY: `built` is set only once `build` wrote the window here, and it is dropped
            // here alone, once.
            unsafe { self.window.assume_init_drop() };
        }
    }
}

#[cfg(test)]
mod tests;
