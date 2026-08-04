// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! The C session's face registry and subscription SSOT — the join between
//! pico's "one session, N peers" model and wz's "one session, one peer".
//!
//! ## Why a registry rather than a session
//!
//! pico models a session as a PEER LIST: `_z_transport_peer_unicast_slist_t
//! *_peers` (`~/zenoh-pico/include/zenoh-pico/transport/transport.h:200`). A
//! `client` session holds exactly one peer (the router it dialed); a `listen`
//! peer session accepts multiple CONCURRENT inbound peers.
//!
//! DIVERGENCE (named, not mirrored): pico caps a listener at
//! `Z_LISTEN_MAX_CONNECTION_NB` = 10 and REFUSES the 11th before its handshake
//! (`src/transport/unicast/accept.c:85-92`,
//! `include/zenoh-pico/config.h.in:213`; pinned by
//! `tests/z_test_peer_unicast.c` — 10 admitted, the 11th rejected). wz's
//! `accept_loop` enforces NO connection cap and holds unbounded faces, so a
//! program relying on the 11th `z_open` failing as back-pressure sees it
//! succeed here. The cap is an embedded static-array-sizing artifact with no
//! hosted-runtime rationale, so this is a deliberate superset, not a bug;
//! matching it would need a configurable pre-handshake cap in `accept_loop`
//! (which has no such knob today) and is deferred.
//!
//! wz models a unicast `Session` as exactly ONE peer (its engine is an
//! `Engine<SessionFsmUnicastPolicy>`) and holds N peers as N sessions
//! multiplexed on one accept loop ([`wz_runtime_tokio::accept_loop`]). So the
//! C handle cannot BE a wz session; it is a REGISTRY of per-face wz sessions
//! plus the C-declared subscription SSOT replayed onto each face as it comes
//! up. `connect` fills exactly one face, `listen` fills N — the same shape
//! pico's `_peers` list has for the same two roles (see the cap divergence
//! above).
//!
//! ## Why per-face sessions, not one shared observer
//!
//! Each face gets its OWN [`TokioSession`], hence its own
//! [`ApplicationLayerObserver`]. That is load-bearing, not incidental: the
//! observer's peer-declared keyexpr alias table (expr-id -> keyexpr) is a
//! PER-PEER id space. One observer shared across N faces would conflate them
//! — peer A's `id=7 -> "home/temp"` and peer B's `id=7 -> "office/light"`
//! would collide and silently mis-route every aliased sample. Per-face
//! sessions make that unrepresentable rather than merely untested, and the
//! fan-out lives here at the C layer, where the subscription SSOT already is.
//!
//! ## Declare-before-peer
//!
//! pico supports declaring subscribers before any peer connects: declarations
//! live in the session's local tables and are pushed to each peer as it joins
//! (`src/transport/unicast/accept.c:148-149`). Here that falls out of the
//! registry for free — [`SharedSession::declare_subscriber`] records a
//! [`SubEntry`] in the SSOT and declares it on whatever faces exist (possibly
//! none); [`SharedSession::face_up`] replays the whole SSOT onto each new
//! face.
//!
//! ## Locking discipline
//!
//! Every path that can invoke the C side — dispatching a sample (fires the
//! subscriber callback) or dropping a subscriber / the last closure reference
//! (fires the C `drop(context)`) — first moves what it needs OUT of the
//! registry lock and only then calls into C. A pico callback is explicitly
//! allowed to re-enter the session (`z_put` from inside a subscriber callback
//! is a supported pattern, and this crate's own round-trip test does it), so
//! holding the lock across a C call would deadlock.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex as StdMutex, MutexGuard};

use tokio::sync::Notify;

use wz_runtime_tokio::accept_loop::{FaceForwarder, FaceId};
use wz_runtime_tokio::declare::LivelinessSample;
use wz_runtime_tokio::locality::Locality;
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::query_sink::{QueryView, ReplyOut};
use wz_runtime_tokio::runtime_impl::{TokioRuntime, TokioTime};
use wz_runtime_tokio::session::{
    LivelinessOptions, LivelinessSubscriber, LivelinessSubscriberOptions, LivelinessToken,
};
use wz_runtime_tokio::session::{
    MatchingListener, MatchingStatus, PublishAliasError, PublishError, PublishOptions, Queryable,
    QueryableOptions, SubscribeOptions, Subscriber, TokioSession,
};
use wz_runtime_tokio::session_glue::{IterationEvent, SessionLinkActions};
use wz_runtime_tokio::sink::SampleView;
use wz_runtime_tokio::sync::Mutex as WzMutex;

// R311y498 — NO `use crate::pubsub` / `use crate::query` here, deliberately.
//
// This registry used to import the C closure TYPES and the `make_*_callback`
// constructors that turn them into wz callbacks, which pointed the dependency
// the wrong way: the ABI-neutral face/declaration model reached UP into one
// specific C ABI's closure shape. That is what made it impossible to put a
// second C ABI (§5.27 `api-compat-c`, the zenoh-c drop-in) over the same session
// model without either duplicating this file or generalising it.
//
// The dependency is inverted through the three FACTORY aliases below: the ABI
// shim hands in something that MINTS a callback, and this file never learns what
// it closes over. A factory rather than a ready-made callback because a callback
// is needed once PER FACE — every declaration is replayed onto each new face
// (`face_up`), so a single pre-built callback could not be reused.
//
// The C drop semantics are preserved exactly, and they are the delicate part:
// the factory owns whatever the shim captured (its `Arc<CClosure>`), so the last
// factory released still runs the C `drop(context)` — which is why every release
// below stays OUTSIDE the registry lock.

/// Mints one subscriber callback per face — the inverted form of what used to be
/// `make_subscriber_callback(Arc<CClosure>)`.
pub type SubscriberSink =
    Arc<dyn Fn() -> Box<dyn FnMut(&dyn SampleView) + Send + 'static> + Send + Sync>;

/// Mints one liveliness-subscriber callback per face.
pub type LivelinessSink =
    Arc<dyn Fn() -> Box<dyn for<'a> FnMut(LivelinessSample<'a>) + Send + 'static> + Send + Sync>;

/// Mints one queryable callback per face.
pub type QueryableSink = Arc<
    dyn Fn() -> Box<dyn FnMut(&dyn QueryView, &mut dyn ReplyOut) + Send + 'static> + Send + Sync,
>;

/// Delivers ONE aggregated matching verdict to C.
///
/// Unlike the four sinks above this is NOT a per-face factory, and the
/// difference is the whole design of the matching plane: a C program holds one
/// matching listener and must be told about the SESSION's verdict, not about
/// each face's. See [`SharedSession::declare_matching_listener`] for why a
/// per-face pass-through would report the opposite of the truth.
pub type MatchingSink = Arc<dyn Fn(bool) + Send + Sync>;

/// A C-level matching-listener id, keying the per-face wz listeners one C
/// declaration spawned.
pub type MatchId = u64;

/// Why a fan-out publish could not be delivered to ANY face.
///
/// Named `FanoutError`, not `PublishError`: wz-runtime-tokio already exports a
/// per-session `PublishError` that this module imports, and two types with one
/// name in one file is the shape a later reader resolves wrongly.
///
/// R311y498 — a real type rather than `Result<_, ()>`, and not merely to satisfy
/// `clippy::result_unit_err`: this became public when the model moved out of the
/// ABI crate, and a public function whose error carries no information leaves
/// every shim mapping "something went wrong" onto its own generic code with no
/// way to do better. The variant is face-INDEPENDENT by construction — a
/// per-face failure is skipped rather than surfaced (see the fan-out docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FanoutError {
    /// The payload or keyexpr exceeded the bounded codec's capacity, so no face
    /// could have carried it.
    ExceedsCapacity,
}

/// A C-level subscription id — what a `z_owned_subscriber_t` handle carries.
/// It keys the per-face wz [`Subscriber`]s this one C subscription spawned.
pub type SubId = u64;

/// A C-level queryable id — what a `z_owned_queryable_t` handle carries. The
/// responder-side mirror of [`SubId`], keying the per-face wz [`Queryable`]s
/// one C queryable declaration spawned.
pub type QblId = u64;

/// The face id the dial (`connect`) role occupies. A dialed session has
/// exactly one peer, so it needs no id space of its own; the accept role's
/// ids come from the accept loop's own monotonic `FaceId`.
pub const DIAL_FACE_ID: u64 = 0;

/// One connected peer: its wz session, plus the wz subscribers this face
/// carries keyed by the C subscription id that spawned them. Dropping the
/// entry drops the subscribers (each emitting its wire undeclare) and then
/// the session.
struct FaceEntry {
    session: TokioSession,
    subs: BTreeMap<SubId, Subscriber<TokioRuntime>>,
    qbls: BTreeMap<QblId, Queryable<TokioRuntime>>,
    /// Per-face liveliness TOKENS. Dropping one emits that face's UndeclToken,
    /// which is how a C `z_drop` on the owned token reaches every peer.
    tokens: BTreeMap<TokenId, LivelinessToken<TokioRuntime>>,
    /// Per-face liveliness SUBSCRIBERS, keyed by the C subscription id so they
    /// share `SubId` space with the ordinary ones — a C `z_owned_subscriber_t`
    /// is the same type either way, so its undeclare must find both.
    live_subs: BTreeMap<SubId, LivelinessSubscriber<TokioRuntime>>,
    /// Per-face matching listeners, keyed by the C listener id. Holding the
    /// handle is what keeps the watch installed; dropping it undeclares that
    /// face's half of one C listener.
    matches: BTreeMap<MatchId, MatchingListener<TokioRuntime>>,
    /// R311y296 — the signal that this face's drive loop should re-arm its wake
    /// because a `z_get` just registered a pending query with a nearer deadline
    /// than whatever the loop is currently parked on. Owned per face because
    /// each face has its own session, pending table, and drive wake.
    revised: Arc<Notify>,
}

/// A C-declared subscription — the SSOT replayed onto every face that comes
/// up. `closure` is shared (an `Arc`) across every face's callback, so the C
/// `drop(context)` fires exactly once, when the last face's subscriber and
/// this entry are both gone.
struct SubEntry {
    id: SubId,
    keyexpr: String,
    sink: SubscriberSink,
}

/// A C-declared queryable — the responder-side SSOT, replayed onto every face
/// exactly as [`SubEntry`] is. pico does the same for the responder plane:
/// a new peer is sent the session's current queryable declarations
/// (`_z_interest_send_decl_queryable`,
/// `~/zenoh-pico/src/session/interest.c`), so a queryable declared before any
/// peer connected still answers that peer's queries.
struct QblEntry {
    id: QblId,
    keyexpr: String,
    complete: bool,
    sink: QueryableSink,
}

/// A C-declared keyexpr alias — the third SSOT, replayed onto every face
/// exactly as [`SubEntry`] and [`QblEntry`] are.
///
/// The mapping id is allocated ONCE per C declaration and reused on every
/// face, which is pico's model rather than a shortcut: `_z_get_resource_id`
/// is a session-global counter and the same id is announced to every peer.
/// It is safe because a keyexpr mapping table is DIRECTIONAL — each peer
/// holds our ids in its own inbound table, so two peers cannot collide, and
/// a peer's own outbound ids live in a different table entirely.
struct KexprEntry {
    id: u64,
    keyexpr: String,
}

/// A C-declared liveliness TOKEN — the fourth SSOT. Replayed onto every face
/// exactly as the others are, which is what makes a token declared before any
/// peer connected visible to that peer when it arrives. Upstream's
/// `z_liveliness.c` declares and then sleeps, so that is the common case, not
/// the corner one.
struct TokenEntry {
    id: TokenId,
    keyexpr: String,
}

/// A C-declared liveliness SUBSCRIPTION — the fifth SSOT. Shares `SubId` space
/// with the ordinary subscriptions because both are handed back to C as a
/// `z_owned_subscriber_t`; `undeclare_subscriber` therefore looks in both maps.
struct LiveSubEntry {
    id: SubId,
    keyexpr: String,
    history: bool,
    sink: LivelinessSink,
}

/// A C-level liveliness token id, keying the per-face wz tokens one C
/// declaration spawned.
pub type TokenId = u64;

/// The cross-face aggregate behind ONE C matching listener.
///
/// `faces` is the set of face ids whose own wz listener currently reports a
/// match; the session verdict is `!faces.is_empty()`. `last` is the verdict
/// already DELIVERED to C, so a change that does not move the aggregate stays
/// silent — pico's transition semantics, applied at the level the C program
/// observes.
///
/// It carries its own mutex rather than living in [`Inner`] on purpose. The
/// per-face wz callback runs on the drive thread from
/// `Session::drain_deferred_fires`, and it must both update this state and
/// invoke the C closure; routing that through the registry lock would put a C
/// callback under the lock a re-entrant `z_declare_*` needs, which is the
/// deadlock the whole file's snapshot-then-call discipline exists to avoid.
///
/// R311y528 — this mutex is held ACROSS the C call, and the earlier "held only
/// across the set update, never across the C call" discipline was the bug. See
/// [`deliver_matching_flip`] for why it has to be, and the MATCHING LOCK ORDER
/// rule in that same doc comment for the invariant that makes it safe.
#[derive(Default)]
struct MatchAggregate {
    faces: BTreeSet<u64>,
    last: bool,
}

impl MatchAggregate {
    /// Record face `id`'s verdict and return `Some(new_aggregate)` when the
    /// SESSION verdict changed, `None` when it did not.
    fn apply(&mut self, id: u64, matching: bool) -> Option<bool> {
        if matching {
            self.faces.insert(id);
        } else {
            self.faces.remove(&id);
        }
        self.settle()
    }

    /// Drop face `id` entirely — a face that went DOWN can no longer be the
    /// reason C believes a subscriber exists. Same flip-only return.
    fn forget(&mut self, id: u64) -> Option<bool> {
        self.faces.remove(&id);
        self.settle()
    }

    fn settle(&mut self) -> Option<bool> {
        let now = !self.faces.is_empty();
        if now == self.last {
            return None;
        }
        self.last = now;
        Some(now)
    }
}

/// A C-declared matching listener — the SIXTH SSOT, replayed onto every face
/// exactly as [`SubEntry`] and [`QblEntry`] are.
///
/// `state` is shared with every per-face callback this entry spawned; the entry
/// holds the per-face wz listener handles inside [`FaceEntry::matches`].
struct MatchEntry {
    id: MatchId,
    keyexpr: String,
    sink: MatchingSink,
    state: Arc<StdMutex<MatchAggregate>>,
}

/// Fold `update` into one entry's aggregate and, when the SESSION verdict
/// flipped, deliver it to C — **both under the same aggregate mutex**.
///
/// ## MATCHING LOCK ORDER — the one rule this plane rests on
///
/// **A [`MatchAggregate`] mutex is never acquired while the registry lock is
/// held.** Every path that needs both snapshots what it needs out of the
/// registry first: `declare_matching_listener` phase 2 drops its guard before
/// installing, and [`SharedSession::face_down`] collects `(state, sink)` pairs
/// and releases before folding. So the only order that exists is
/// `aggregate -> registry` — the one a C callback re-entering `z_declare_*` from
/// inside this function takes — and no thread takes it backwards.
///
/// Reaching an aggregate any other way is what a future call site would have to
/// do to break this, so a new one belongs here rather than open-coding the fold.
/// The two existing callers are [`face_matching_callback`] and
/// [`SharedSession::face_down`].
///
/// ## Why the C call is inside the lock (R311y528 — this was a real defect)
///
/// Two threads reach one entry's `sink`: the drive thread, through
/// [`face_matching_callback`] and through [`SharedSession::face_down`]'s purge;
/// and the C application thread, through `declare_matching_listener` phase 2,
/// where an already-matching per-face registration fires `true` synchronously.
/// Phase 1 publishes the [`MatchEntry`] under the registry lock BEFORE phase 2
/// installs, so `face_down` can already see an entry whose C-thread registration
/// is still running. A peer dropping in that window produced two concurrent
/// `call(context)` on one C context — exactly the data race pico's
/// single-threaded-callback contract forbids, and the same class R311y288 fixed
/// on the publish plane.
///
/// Releasing the mutex before `sink` (what this code did until R311y528) also
/// lost ORDERING even when the calls did not overlap: two threads could compute
/// `true` then `false` and deliver them in the opposite order, leaving C with a
/// verdict the aggregate disagrees with. Folding and delivering under one
/// acquisition makes the pair atomic, so C observes exactly the sequence of
/// flips the aggregate computed.
///
/// ## Why holding it is deadlock-free
///
/// By the lock order above: no caller holds the registry lock when it gets
/// here, so a C callback that re-enters the session — `z_put`,
/// `z_declare_subscriber`, `z_publisher_get_matching_status`, even
/// `z_publisher_declare_matching_listener` on the same keyexpr — takes the
/// registry lock with only this aggregate held, and nothing takes them the other
/// way round. A re-entrant declare allocates a NEW entry with a NEW aggregate,
/// so it cannot block on this one; `z_undeclare_matching_listener` for this very
/// id takes the registry lock, removes the entry and calls
/// `MatchingListener::undeclare`, which retracts the watch without firing
/// (`wz-runtime-tokio/src/session/matching_listener.rs`), so it never re-enters
/// this function. The `state` and `sink` handles are `Arc` clones held by the
/// caller, so that undeclare cannot free what this call is using.
fn deliver_matching_flip(
    state: &StdMutex<MatchAggregate>,
    sink: &MatchingSink,
    update: impl FnOnce(&mut MatchAggregate) -> Option<bool>,
) {
    let mut agg = state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(now) = update(&mut agg) {
        sink(now);
    }
    // `agg` is dropped HERE, after the C call — see the doc comment.
}

/// The per-face callback one [`MatchEntry`] installs on face `face_id`: fold
/// this face's verdict into the aggregate and deliver to C only on a SESSION
/// flip.
///
/// One function rather than the closure written twice, because the two call
/// sites are the declare path and the `face_up` replay path and they must not
/// drift — a replay that folded differently from the original would make the
/// verdict depend on when a peer happened to connect.
///
/// Runs from `Session::drain_deferred_fires`, which is called with the observer
/// lock released and — per the lock order in [`deliver_matching_flip`] — never with the registry
/// lock held.
fn face_matching_callback(
    face_id: u64,
    entry: &MatchEntry,
) -> impl FnMut(MatchingStatus) + Send + 'static {
    let state = entry.state.clone();
    let sink = entry.sink.clone();
    move |status| {
        deliver_matching_flip(&state, &sink, |agg| agg.apply(face_id, status.matching));
    }
}

#[derive(Default)]
struct Inner {
    faces: BTreeMap<u64, FaceEntry>,
    subs: Vec<SubEntry>,
    next_sub_id: SubId,
    qbls: Vec<QblEntry>,
    next_qbl_id: QblId,
    tokens: Vec<TokenEntry>,
    next_token_id: TokenId,
    live_subs: Vec<LiveSubEntry>,
    matches: Vec<MatchEntry>,
    next_match_id: MatchId,
    kexprs: Vec<KexprEntry>,
    /// Next alias id to hand out. Starts at 0 and is PRE-incremented, so the
    /// first id issued is 1: zero is reserved on the wire
    /// (`SendDeclareError::ReservedMappingIdZero`) and is also this crate's
    /// "not declared" discriminant in `z_loaned_keyexpr_t::_mapping`.
    next_kexpr_id: u64,
}

/// The registry behind a `z_owned_session_t`, shared between the C thread
/// (which declares and publishes) and the drive thread (which brings faces up
/// and dispatches inbound samples).
pub struct SharedSession {
    inner: StdMutex<Inner>,
    clock: TokioTime,
}

impl SharedSession {
    pub fn new(clock: TokioTime) -> Self {
        Self {
            inner: StdMutex::new(Inner::default()),
            clock,
        }
    }

    /// The registry lock, poison-tolerant. A C callback that panics is caught
    /// at the FFI boundary (`crate::ffi`), so poisoning should not happen; if
    /// it somehow does, the registry is still structurally sound (a panic
    /// cannot leave a `BTreeMap` torn), and refusing to serve the session
    /// afterwards would be a worse failure than continuing.
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// A face reached Established: build its session and replay the whole
    /// declaration SSOT — subscriptions AND queryables — onto it (pico's
    /// push-declarations-to-the-new-peer, `accept.c:148-149`).
    pub fn face_up(&self, id: u64, actions: &Arc<SessionLinkActions>) {
        let observer = Arc::new(WzMutex::new(ApplicationLayerObserver::new()));
        let session = TokioSession::new(actions.clone(), observer, Arc::new(self.clock));

        let mut guard = self.lock();
        // Keyexpr aliases replay FIRST, before the subscriber and queryable
        // declares below. Ordering is load-bearing on the reliable channel: a
        // peer resolves an aliased id through the mapping table it built from
        // our DeclareKeyExpr, so any declaration or Push that could reference
        // the alias must not reach it earlier. Cheap to guarantee here, and
        // impossible to notice if it were wrong until a race showed up.
        for entry in &guard.kexprs {
            // Best-effort per face, exactly as the sub/qbl replays below: a
            // face mid-teardown drops its declare and the SSOT entry survives
            // for the next face.
            let _ = session
                .actions()
                .send_declare_keyexpr(entry.id, &entry.keyexpr);
        }
        let mut subs = BTreeMap::new();
        for entry in &guard.subs {
            if let Ok(sub) = session.declare_subscriber(
                entry.keyexpr.clone(),
                SubscribeOptions::default(),
                (entry.sink)(),
            ) {
                subs.insert(entry.id, sub);
            }
        }
        let mut qbls = BTreeMap::new();
        for entry in &guard.qbls {
            if let Ok(qbl) = session.declare_queryable(
                entry.keyexpr.clone(),
                queryable_options(entry.complete),
                (entry.sink)(),
            ) {
                qbls.insert(entry.id, qbl);
            }
        }
        // Drop any replaced entry OUTSIDE the lock: `insert` returns the
        // previous `FaceEntry` for this id, whose teardown drops subscribers /
        // queryables and may release the last `Arc<CClosure>` — running the C
        // `drop(context)` under the registry lock. A fresh face id makes this
        // `None` in practice; the discipline is uniform rather than
        // conditional on that.
        // Liveliness replay: tokens first, then the liveliness subscriptions.
        // A token this session already holds must be ANNOUNCED to the new peer
        // (pico pushes its declarations at accept time), and a liveliness
        // subscription must be re-declared so the new peer's tokens reach the
        // one C callback.
        let mut tokens = BTreeMap::new();
        for entry in &guard.tokens {
            if let Ok(tok) = session.declare_token(entry.keyexpr.clone(), LivelinessOptions::new())
            {
                tokens.insert(entry.id, tok);
            }
        }
        let mut live_subs = BTreeMap::new();
        for entry in &guard.live_subs {
            let mut opts = LivelinessSubscriberOptions::default();
            opts.history = entry.history;
            if let Ok(sub) =
                session.declare_liveliness_subscriber(entry.keyexpr.clone(), opts, (entry.sink)())
            {
                live_subs.insert(entry.id, sub);
            }
        }
        // Matching-listener replay. A C listener declared before this peer
        // connected must watch it too, so each entry gets a per-face wz
        // listener whose callback folds THIS face's verdict into the entry's
        // cross-face aggregate.
        //
        // Registering under the registry lock is safe HERE for a reason worth
        // stating, because it is not the general rule in this file:
        // `Publisher::declare_matching_listener` delivers an already-matching
        // registration synchronously, which would put a C callback under the
        // lock. It cannot fire here — `session` was constructed a few lines
        // above with a FRESH `ApplicationLayerObserver`, so its remote-
        // subscriber registry is empty and the initial verdict is necessarily
        // `false`. A future refactor that hands `face_up` an already-populated
        // observer must move this replay out of the lock.
        let mut matches = BTreeMap::new();
        for entry in &guard.matches {
            let pubr = session.declare_publisher(entry.keyexpr.clone(), PublishOptions::put());
            if let Ok(listener) = pubr.declare_matching_listener(face_matching_callback(id, entry))
            {
                matches.insert(entry.id, listener);
            }
        }
        let replaced = guard.faces.insert(
            id,
            FaceEntry {
                session,
                subs,
                qbls,
                tokens,
                live_subs,
                matches,
                revised: Arc::new(Notify::new()),
            },
        );
        drop(guard);
        drop(replaced);
    }

    /// A face left the live set (peer Close / link loss).
    ///
    /// R311y522 — before the entry is dropped, every remote liveliness token
    /// that face announced is delivered to the C application as a `Delete`.
    /// This is the ACCEPT-side half of the R311y521 flush, and pico draws no
    /// dial/accept distinction: it fires
    /// `_z_liveliness_subscription_undeclare_all` from unicast transport
    /// FAILURE generally (`src/transport/unicast/lease.c:74-78`).
    ///
    /// Without it, dropping the entry silently discarded the whole per-face
    /// observer — registry cleaned, application never told. A C program that
    /// declared `z_liveliness_declare_subscriber` therefore kept believing a
    /// token was alive after the peer that announced it was gone, and no
    /// `UndeclToken` can rescue that: the link that would carry one is exactly
    /// what died.
    ///
    /// ## The drain is not optional, and it is the whole reason this was hard
    ///
    /// `flush_liveliness_on_link_loss` does NOT run the C callback. The
    /// registry's slot holds a DEFERRED-FIRE staging sink (R311lg): it copies
    /// each matched sample onto the session's fire queue so the callback runs
    /// after the observer lock drops, which is what lets a C callback re-enter
    /// the session without self-deadlocking. The drive loop normally drains
    /// that queue — but this runs AFTER the drive loop has returned, so
    /// nothing else ever will. Flushing without draining stages Deletes that
    /// no one delivers, which measures as "1 slot fired" and reaches the
    /// application as silence.
    ///
    /// Flushing the WHOLE observer is correct HERE, where it would not be on a
    /// node with one shared observer: `face_up` builds a fresh
    /// `ApplicationLayerObserver` per face, so this observer's remote tokens
    /// all came from THIS face. That per-face scoping is what lets pico's
    /// single-session "flush everything" transcribe without attribution.
    pub fn face_down(&self, id: u64) {
        // Drop OUTSIDE the lock: dropping the entry drops its subscribers,
        // and the last one may release the final `Arc<CClosure>` and run the
        // C `drop(context)`.
        let removed = self.lock().faces.remove(&id);
        if let Some(entry) = &removed {
            // Both steps run BEFORE the drop: the sinks that must receive the
            // Deletes are owned by the entry being dropped.
            let observer = entry.session.observer();
            let staged = match observer.lock() {
                Ok(mut o) => o.flush_liveliness_on_link_loss(),
                // A panicking C callback poisons the mutex; recover rather
                // than skip the flush, matching this file's other `lock()`.
                Err(poisoned) => poisoned.into_inner().flush_liveliness_on_link_loss(),
            };
            if staged > 0 {
                // Runs the C callbacks, with the observer lock released.
                entry.session.drain_deferred_fires();
            }
        }
        // Purge the departed face from every matching aggregate. Same reasoning
        // as the liveliness flush above and the same failure mode: this face's
        // subscribers cannot undeclare, because the link that would carry the
        // UndeclSubscriber is what died. Its per-face wz listener therefore
        // never fires `false`, so without this the face stays in the aggregate
        // set forever and a C program is told it still has matching subscribers
        // after its only subscribing peer vanished — and, worse, the aggregate
        // never flips again, so a genuine later `true` is suppressed as
        // "no change".
        //
        // R311y528 — the `(state, sink)` pairs are snapshotted out of the
        // registry lock BEFORE either is touched, and the fold + C delivery then
        // run under the aggregate mutex alone. Folding under the registry lock
        // (what this did until R311y528) established a `registry -> aggregate`
        // order, which is the half of the ABBA pair that made holding the
        // aggregate across the C call unsafe. See `deliver_matching_flip`.
        let watches: Vec<(Arc<StdMutex<MatchAggregate>>, MatchingSink)> = {
            let guard = self.lock();
            guard
                .matches
                .iter()
                .map(|entry| (entry.state.clone(), entry.sink.clone()))
                .collect()
        };
        for (state, sink) in watches {
            deliver_matching_flip(&state, &sink, |agg| agg.forget(id));
        }
        drop(removed);
    }

    /// Drop EVERY face — what `z_close` runs once its drive thread has joined.
    ///
    /// # Why `z_close` must do this, and why it is not merely tidy
    ///
    /// This is pico's `_z_session_close` → `_z_flush_pending_queries`
    /// (`~/zenoh-pico/src/session/utils.c:194`, `src/session/query.c:276-283`):
    /// closing a session ENDS every in-flight get, running each pending query's
    /// drop handler.
    ///
    /// Without it a `z_get` outstanding at `z_close` would never complete. The
    /// accept loop's shutdown path breaks out and drops its own per-face
    /// `OpenedSession`s, but it never calls `deregister` — that runs only when a
    /// face's own drive finishes (`accept_loop.rs`, the `Step::Driven` arm). So
    /// the registry's `FaceEntry`s — each holding its OWN `TokioSession`, hence
    /// its own `ReplyRegistry` and every pending entry's `Arc` clone — would
    /// outlive the drive thread with nothing left to sweep them. The C
    /// `drop(context)`, which IS the get's completion signal, would fire only at
    /// `z_session_drop`, and never at all for a program that keeps the handle
    /// (`z_close` does not free it). A `z_get` issued AFTER `z_close` would be
    /// worse: it would find the orphaned faces, register a deadlined entry, and
    /// hang forever — where pico completes it at once (a closed session has an
    /// empty peer set).
    ///
    /// It also removes a role asymmetry that made identical C code behave
    /// differently: the DIAL role already drops its face explicitly after its
    /// drive returns (`session::drive_dial`), so only `listen` leaked.
    ///
    /// Running the C `drop(context)` on the calling (C) thread is sound here and
    /// is pico's own behaviour: by the time this runs the drive thread has been
    /// joined, so no `call` can be in flight to race it — and the `Arc` refcount
    /// serialises it regardless (see the `unsafe impl Sync for CReplyClosure`).
    pub fn clear_faces(&self) {
        // Take OUTSIDE the lock, drop OUTSIDE the lock — the standing
        // discipline: dropping a face runs the C `drop(context)` for any
        // closure it held the last reference to.
        let faces = std::mem::take(&mut self.lock().faces);
        drop(faces);
    }

    /// One inbound iteration event for `id` — dispatched into that face's own
    /// session (and so its own observer, keeping the peer's keyexpr alias id
    /// space private to it), then that face's expired `z_get`s are swept.
    ///
    /// # The sweep must live HERE, and only here
    ///
    /// This is the `on_event` path — the drive thread — for BOTH roles (the
    /// dial role's own drive closure and, via [`CApiForwarder::forward`], every
    /// accepted face). That is the one thread on which a C closure may be
    /// invoked, and sweeping a timed-out `z_get` FIRES the C reply closure's
    /// `on_final`. Calling [`TokioSession::sweep_expired_queries`] from the C
    /// application thread instead — e.g. straight out of `z_get` — would run
    /// that closure's `drop`/final concurrently with a drive-thread `call` on
    /// another face: two C callbacks at once on one context, which is exactly
    /// the unsound-`Sync` bug R311y288 fixed on the publish plane.
    ///
    /// The hazard is real rather than theoretical, and it is NOT contained by
    /// the `Locality::Remote` pin that protects the queryable plane: unlike
    /// [`TokioSession::query`], whose in-process fan and drain are both gated on
    /// `allows_local`, `sweep_expired_queries`' `drain_deferred_fires` is
    /// UNGATED (`session/mod.rs`) — it takes the whole per-session deferred
    /// queue and runs it on the CALLING thread whatever the locality. So the
    /// only thing keeping it sound is the caller, and the caller is this
    /// function.
    ///
    /// Cadence comes from the wake this face arms via
    /// [`CApiForwarder::next_extra_deadline_ms`] /
    /// [`Self::next_reply_deadline_ms`], so an expiring `z_get` wakes the drive
    /// loop and lands here on time rather than on the ~3333 ms keepalive
    /// cadence. Sweeping on EVERY event (not only a deadline wake) is
    /// deliberate: it is idempotent and cheap when nothing is expired, and it
    /// means inbound traffic also clears the table.
    pub fn dispatch(&self, id: u64, event: IterationEvent<'_>) {
        // Clone the session out of the lock first: the dispatch fires the C
        // subscriber callback, which may re-enter this session (`z_put` from
        // inside a callback is a supported pico pattern), so holding the lock
        // across it would deadlock. The sweep below fires the C reply
        // closure's final and is re-entrant the same way, so it too runs with
        // the lock released.
        let session = self.lock().faces.get(&id).map(|face| face.session.clone());
        if let Some(session) = session {
            session.dispatch_iteration_event(event);
            session.sweep_expired_queries();
        }
    }

    /// When face `id`'s earliest pending `z_get` is due, or `None` if it has
    /// none — the wake [`Self::dispatch`]'s sweep rides on.
    ///
    /// Per-face because each face has its OWN session (and so its own pending
    /// table): a `z_get` fans one wz `query` per face, and each face's drive
    /// loop arms only its own deadline. A face with no pending get arms
    /// nothing, so an idle session's cadence is unchanged.
    pub fn next_reply_deadline_ms(&self, id: u64) -> Option<u64> {
        let session = self.lock().faces.get(&id).map(|face| face.session.clone());
        session.and_then(|session| session.next_reply_deadline_ms())
    }

    /// Publish to every connected peer (pico `z_put` / `z_publisher_put`
    /// semantics: the write goes to the session's whole peer set).
    ///
    /// Best-effort per face, matching pico's multi-peer send, which discards
    /// each peer's send result and returns OK even if some/all peer sends fail
    /// (`~/zenoh-pico/src/transport/common/tx.c:92-95,139-150` — contrast the
    /// single-peer path's `_Z_RETURN_IF_ERR`). Concretely a face mid-teardown
    /// yields `PublishError::TransportUnavailable` (the F2 gate — per-face and
    /// transient); swallowing it and continuing means a healthy peer ordered
    /// after it in the map still receives the sample. Only a DETERMINISTIC,
    /// face-independent error — the payload/keyexpr overflowing the bounded
    /// codec (`ExceedsCapacity`), which would fail identically on every face —
    /// is surfaced. Zero faces is `Ok(0)`: a put with no peer connected simply
    /// has no recipient (pico's empty peer list → OK).
    pub fn publish_all(
        &self,
        keyexpr: &str,
        payload: &[u8],
        opts: &PublishOptions,
    ) -> Result<usize, FanoutError> {
        let sessions = self.face_sessions();
        let mut delivered = 0usize;
        for session in sessions {
            match session.publish(keyexpr, payload, opts.clone()) {
                Ok(n) => delivered += n,
                // Per-face transient failure (link released / reconnecting):
                // best-effort, keep delivering to the surviving faces.
                Err(PublishError::TransportUnavailable) => {}
                // Deterministic, face-independent: fails on every face.
                Err(_) => return Err(FanoutError::ExceedsCapacity),
            }
        }
        Ok(delivered)
    }

    /// Fan an ALIASED publish over every face (pico `_z_write` on a
    /// `_z_declared_keyexpr_t` whose declaration is live).
    ///
    /// Each face resolves the literal from its OWN outbound mapping table via
    /// `publish_aliased_auto`, which is why the id can be session-global while
    /// the resolution stays per-face: the table was populated by that face's
    /// own `send_declare_keyexpr`, either at declare time or on replay.
    ///
    /// `UnknownMapping` on a face is treated as the per-face transient
    /// [`Self::publish_all`] treats `TransportUnavailable`. It is reachable
    /// without any bug: a face whose declare failed mid-teardown never got the
    /// table entry, and skipping it lets the healthy peers still receive the
    /// sample. Every other error is deterministic and face-independent, so it
    /// is surfaced.
    pub fn publish_aliased_all(
        &self,
        mapping_id: u64,
        payload: &[u8],
        opts: &PublishOptions,
    ) -> Result<usize, FanoutError> {
        let sessions = self.face_sessions();
        let mut delivered = 0usize;
        for session in sessions {
            match session.publish_aliased_auto(mapping_id, None, payload, opts.clone()) {
                Ok(n) => delivered += n,
                Err(PublishAliasError::UnknownMapping(_)) => {}
                Err(PublishAliasError::TransportUnavailable) => {}
                Err(_) => return Err(FanoutError::ExceedsCapacity),
            }
        }
        Ok(delivered)
    }

    /// Record a C keyexpr declaration in the SSOT and announce it on every live
    /// face, returning the allocated mapping id (never 0).
    ///
    /// Same declare-before-peer semantics as [`Self::declare_subscriber`]: with
    /// no face yet, nothing goes on the wire and the entry is still recorded,
    /// so every FUTURE face replays it in [`Self::face_up`].
    ///
    /// Returns `None` when the id space is exhausted. The space is the WIRE's,
    /// not ours: zenoh types `DeclareKeyExpr.id` as `ExprId = u16` and pico's
    /// `_z_decl_kexpr_t` holds a `uint16_t`, so ids above `u16::MAX` are
    /// rejected by `send_declare_keyexpr` and must not be handed out. Refusing
    /// is the honest answer — wrapping would silently re-issue a live id and
    /// re-point a peer's existing alias at a different keyexpr.
    pub fn declare_keyexpr(&self, keyexpr: String) -> Option<u64> {
        let mut guard = self.lock();
        let id = guard.next_kexpr_id.checked_add(1)?;
        if id > u64::from(u16::MAX) {
            return None;
        }
        guard.next_kexpr_id = id;

        for face in guard.faces.values() {
            let _ = face.session.actions().send_declare_keyexpr(id, &keyexpr);
        }
        guard.kexprs.push(KexprEntry { id, keyexpr });
        Some(id)
    }

    /// Retract a C keyexpr declaration: drop the SSOT entry so no future face
    /// replays it, and emit the wire undeclare on every live face.
    ///
    /// No cross-lock drop dance is needed here, unlike the subscriber and
    /// queryable twins: a [`KexprEntry`] owns a `String` and no `Arc<CClosure>`,
    /// so releasing it cannot run C code.
    pub fn undeclare_keyexpr(&self, mapping_id: u64) {
        let mut guard = self.lock();
        if let Some(pos) = guard.kexprs.iter().position(|e| e.id == mapping_id) {
            guard.kexprs.remove(pos);
        }
        for face in guard.faces.values() {
            face.session.actions().send_undeclare_kexpr(mapping_id);
        }
    }

    /// Record a C liveliness TOKEN in the SSOT and declare it on every live
    /// face, returning its id.
    ///
    /// Declare-before-peer, like every other declaration here: with no face
    /// yet nothing goes on the wire and the entry is still recorded, so each
    /// future face announces it in [`Self::face_up`]. That is the ordinary case
    /// for upstream's `z_liveliness.c`, which declares and then sleeps.
    ///
    /// `None` when the id space is exhausted, which cannot happen in practice
    /// (u64) but is surfaced rather than wrapped, for the same reason
    /// [`Self::declare_keyexpr`] refuses: a reused id would retract a live
    /// token belonging to someone else.
    pub fn declare_liveliness_token(&self, keyexpr: String) -> Option<TokenId> {
        let mut guard = self.lock();
        let id = guard.next_token_id.checked_add(1)?;
        guard.next_token_id = id;

        for face in guard.faces.values_mut() {
            if let Ok(tok) = face
                .session
                .declare_token(keyexpr.clone(), LivelinessOptions::new())
            {
                face.tokens.insert(id, tok);
            }
        }
        guard.tokens.push(TokenEntry { id, keyexpr });
        Some(id)
    }

    /// Retract a C liveliness token: drop the SSOT entry so no future face
    /// announces it, and drop every face's wz token — each emitting that face's
    /// UndeclToken, which is what tells subscribers the resource is gone.
    pub fn undeclare_liveliness_token(&self, id: TokenId) {
        let mut dropped = Vec::new();
        {
            let mut guard = self.lock();
            if let Some(pos) = guard.tokens.iter().position(|e| e.id == id) {
                guard.tokens.remove(pos);
            }
            for face in guard.faces.values_mut() {
                if let Some(tok) = face.tokens.remove(&id) {
                    dropped.push(tok);
                }
            }
        }
        // Drop OUTSIDE the lock. A token teardown emits on the wire and can
        // re-enter the session, which the non-reentrant registry mutex would
        // deadlock on — the same discipline every other teardown here follows.
        drop(dropped);
    }

    /// Record a C liveliness SUBSCRIPTION in the SSOT and declare it on every
    /// live face, returning its id.
    ///
    /// Shares [`SubId`] space with [`Self::declare_subscriber`] on purpose: C
    /// gets back a `z_owned_subscriber_t` either way, so one id space is what
    /// lets [`Self::undeclare_subscriber`] serve both without the caller
    /// having to remember which kind it holds.
    pub fn declare_liveliness_subscriber(
        &self,
        keyexpr: String,
        options: LivelinessSubscriberOptions,
        sink: LivelinessSink,
    ) -> SubId {
        let mut guard = self.lock();
        let id = guard.next_sub_id;
        guard.next_sub_id = guard.next_sub_id.wrapping_add(1);

        for face in guard.faces.values_mut() {
            if let Ok(sub) =
                face.session
                    .declare_liveliness_subscriber(keyexpr.clone(), options.clone(), sink())
            {
                face.live_subs.insert(id, sub);
            }
        }
        guard.live_subs.push(LiveSubEntry {
            id,
            keyexpr,
            history: options.history,
            sink,
        });
        id
    }

    /// A snapshot of every connected face's session, taken OUT of the registry
    /// lock — what a fan-out operation iterates.
    ///
    /// Returning a snapshot rather than lending the guard is the crate's
    /// standing locking discipline made reusable: every fan (`publish_all`,
    /// `z_get`) may invoke C code, and a pico callback is allowed to re-enter
    /// the session, so walking `guard.faces` while calling into a face would
    /// deadlock the non-reentrant mutex.
    pub fn face_sessions(&self) -> Vec<TokioSession> {
        self.lock()
            .faces
            .values()
            .map(|face| face.session.clone())
            .collect()
    }

    /// A snapshot of every connected face's session PAIRED with its re-arm
    /// signal — what [`crate::get::fan_get`] iterates.
    ///
    /// Paired rather than looked up per face afterwards because the two must
    /// come from the same snapshot: a face that leaves the registry between the
    /// two reads would otherwise have its query issued and its wake never
    /// notified.
    pub fn face_sessions_with_wake(&self) -> Vec<(TokioSession, Arc<Notify>)> {
        self.lock()
            .faces
            .values()
            .map(|face| (face.session.clone(), face.revised.clone()))
            .collect()
    }

    /// Face `id`'s drive-loop re-arm signal (see [`FaceEntry::revised`]).
    pub fn deadline_revised(&self, id: u64) -> Option<Arc<Notify>> {
        self.lock().faces.get(&id).map(|face| face.revised.clone())
    }

    /// Record a C subscription in the SSOT and declare it on every live face.
    ///
    /// The SSOT entry is the LOCAL registration and is recorded
    /// unconditionally, mirroring pico: `_z_register_subscriber` records the
    /// subscription in the session tables first and its wire announce to peers
    /// is best-effort after (`~/zenoh-pico/src/net/primitives.c:209-248`). So a
    /// per-face wire declare that fails (a face mid-teardown) is ignored exactly
    /// as [`Self::face_up`] ignores a failed replay, and the SSOT entry persists
    /// so every FUTURE face still gets it. With no face yet (a listener before
    /// its first peer) this declares nothing on the wire and still records the
    /// entry — pico's declare-before-peer. Infallible today; keyexpr canonicity
    /// validation is a separate follow-up.
    pub fn declare_subscriber(&self, keyexpr: String, sink: SubscriberSink) -> SubId {
        let mut guard = self.lock();
        let id = guard.next_sub_id;
        guard.next_sub_id = guard.next_sub_id.wrapping_add(1);

        for face in guard.faces.values_mut() {
            if let Ok(sub) = face.session.declare_subscriber(
                keyexpr.clone(),
                SubscribeOptions::default(),
                sink(),
            ) {
                face.subs.insert(id, sub);
            }
        }
        guard.subs.push(SubEntry { id, keyexpr, sink });
        id
    }

    /// Record a C matching listener in the SSOT and install it on every live
    /// face, delivering the CURRENT session verdict if it is already `true`.
    ///
    /// ## Why the verdict is aggregated instead of passed through
    ///
    /// A C program holds ONE `z_owned_matching_listener_t` and asks one
    /// question: does anybody out there subscribe to what I publish. wz answers
    /// it per FACE, because the remote-subscriber registry is per-session and a
    /// session is per-peer. Forwarding each face's verdict straight to C would
    /// therefore report the opposite of the truth in the ordinary two-peer
    /// case: peer B undeclaring its subscriber would deliver
    /// `matching = false` — upstream's `z_pub.c` prints "Publisher has NO MORE
    /// matching subscribers." — while peer A is still subscribed and every
    /// subsequent put still reaches it. pico has no such split (one session,
    /// one write-filter context, `src/net/filtering.c`), so parity here is
    /// specifically the aggregation: the C verdict is the OR across faces, and
    /// it is delivered only when that OR moves.
    ///
    /// ## Registration happens OUTSIDE the registry lock
    ///
    /// Deliberate, and not merely tidy: `Publisher::declare_matching_listener`
    /// delivers an already-matching registration synchronously (pico's
    /// fire-before-insert), so installing it under the lock would run a C
    /// callback while holding the mutex every `z_declare_*` needs — and that
    /// callback is entitled to declare. So the SSOT entry is pushed under the
    /// lock, the per-face installs run unlocked, and the handles are filed back
    /// in a second short critical section. A face that left in between simply
    /// has no handle filed; its listener handle is dropped after the lock is
    /// released.
    pub fn declare_matching_listener(&self, keyexpr: String, sink: MatchingSink) -> MatchId {
        let state = Arc::new(StdMutex::new(MatchAggregate::default()));
        // Phase 1 — allocate the id, publish the SSOT entry, snapshot the faces.
        let (id, faces) = {
            let mut guard = self.lock();
            let id = guard.next_match_id;
            guard.next_match_id = guard.next_match_id.wrapping_add(1);
            let faces: Vec<(u64, TokioSession)> = guard
                .faces
                .iter()
                .map(|(fid, face)| (*fid, face.session.clone()))
                .collect();
            guard.matches.push(MatchEntry {
                id,
                keyexpr: keyexpr.clone(),
                sink,
                state: state.clone(),
            });
            (id, faces)
        };

        // Phase 2 — install per face with NO lock held, so an already-matching
        // face may deliver its `true` to C right here.
        let mut installed = Vec::new();
        {
            let guard = self.lock();
            let entry = guard
                .matches
                .iter()
                .find(|e| e.id == id)
                .expect("the entry pushed in phase 1 is still present");
            let callbacks: Vec<_> = faces
                .iter()
                .map(|(fid, _)| face_matching_callback(*fid, entry))
                .collect();
            drop(guard);
            for ((fid, session), callback) in faces.into_iter().zip(callbacks) {
                let pubr = session.declare_publisher(keyexpr.clone(), PublishOptions::put());
                if let Ok(listener) = pubr.declare_matching_listener(callback) {
                    installed.push((fid, listener));
                }
            }
        }

        // Phase 3 — file the handles back; a face that left keeps none.
        let mut orphans = Vec::new();
        {
            let mut guard = self.lock();
            for (fid, listener) in installed {
                match guard.faces.get_mut(&fid) {
                    Some(face) => {
                        face.matches.insert(id, listener);
                    }
                    None => orphans.push(listener),
                }
            }
        }
        drop(orphans);
        id
    }

    /// The SESSION's matching verdict for `keyexpr` (pico
    /// `z_publisher_get_matching_status`): `true` when ANY connected peer has a
    /// matching subscriber.
    ///
    /// The OR across faces is the same aggregation
    /// [`Self::declare_matching_listener`] delivers, computed fresh here rather
    /// than read off a listener's cached state — so the poll answers correctly
    /// for a publisher that never declared a listener at all, and cannot
    /// disagree with one that did.
    ///
    /// Sessions are snapshotted out of the lock before being consulted, the
    /// same discipline as every other fan-out here: `get_matching_status` takes
    /// the face's observer mutex, and taking it under the registry lock would
    /// invert the two locks' order against the drive thread.
    pub fn has_matching(&self, keyexpr: &str) -> bool {
        self.face_sessions().into_iter().any(|session| {
            session
                .declare_publisher(keyexpr.to_owned(), PublishOptions::put())
                .get_matching_status()
                .matching
        })
    }

    /// Drop a C matching listener: remove the SSOT entry so no future face
    /// installs it, and undeclare every face's watch.
    ///
    /// The per-face `MatchingListener::undeclare` is called explicitly rather
    /// than left to the handle's drop, because wz's handle has no `Drop` hook —
    /// dropping it leaves the watch installed, which would keep firing the
    /// aggregate for a listener C has already released.
    pub fn undeclare_matching_listener(&self, id: MatchId) {
        let mut removed = Vec::new();
        let mut entry = None;
        {
            let mut guard = self.lock();
            if let Some(pos) = guard.matches.iter().position(|e| e.id == id) {
                entry = Some(guard.matches.remove(pos));
            }
            for face in guard.faces.values_mut() {
                if let Some(listener) = face.matches.remove(&id) {
                    removed.push(listener);
                }
            }
        }
        // OUTSIDE the lock: `undeclare` reaches into the face session's
        // observer, and releasing the entry may drop the last `MatchingSink`
        // reference — which for the pico shim runs the C `drop(context)`.
        for listener in removed {
            listener.undeclare();
        }
        drop(entry);
    }

    /// Drop a C subscription: remove it from the SSOT so no future face
    /// replays it, and drop every face's wz subscriber for it (each emitting
    /// its wire undeclare).
    pub fn undeclare_subscriber(&self, id: SubId) {
        let mut dropped = Vec::new();
        let mut dropped_entry = None;
        let mut dropped_live = Vec::new();
        let mut dropped_live_entry = None;
        {
            let mut guard = self.lock();
            // Remove the SSOT entry into a binding rather than `retain`-dropping
            // it in place: with no live face (a listener that never had a peer,
            // or one whose per-face declares all failed) the entry holds the
            // LAST `Arc<CClosure>`, so dropping it here would run the C
            // `drop(context)` under the lock.
            if let Some(pos) = guard.subs.iter().position(|entry| entry.id == id) {
                dropped_entry = Some(guard.subs.remove(pos));
            }
            for face in guard.faces.values_mut() {
                if let Some(sub) = face.subs.remove(&id) {
                    dropped.push(sub);
                }
            }
            // The LIVELINESS subscriptions share this id space (see
            // `declare_liveliness_subscriber`), so an id belongs to exactly one
            // of the two maps and both must be searched — a `z_owned_subscriber_t`
            // does not record which kind it came from, and it should not have to.
            if let Some(pos) = guard.live_subs.iter().position(|entry| entry.id == id) {
                let entry = guard.live_subs.remove(pos);
                dropped_live_entry = Some(entry);
            }
            for face in guard.faces.values_mut() {
                if let Some(sub) = face.live_subs.remove(&id) {
                    dropped_live.push(sub);
                }
            }
        }
        // Drop OUTSIDE the lock: releasing the last `Arc<CClosure>` — whether
        // the final per-face subscriber or the SSOT entry — runs the C
        // `drop(context)`, which must not run under the registry lock (a drop
        // that re-enters the session would deadlock the non-reentrant mutex).
        drop(dropped);
        drop(dropped_entry);
        drop(dropped_live);
        drop(dropped_live_entry);
    }

    /// Record a C queryable in the SSOT and declare it on every live face —
    /// the responder-side mirror of [`Self::declare_subscriber`], with the
    /// same declare-before-peer semantics (no face yet → the entry is still
    /// recorded and every future face replays it).
    ///
    /// Per-face rid independence makes cross-face request-id collision
    /// unrepresentable rather than merely unlikely: each face's wz session
    /// allocates its own request ids (`alloc_next_request_id` is per
    /// `SessionLinkActions`), so two peers querying concurrently cannot
    /// correlate onto one another's reply chain.
    pub fn declare_queryable(&self, keyexpr: String, complete: bool, sink: QueryableSink) -> QblId {
        let mut guard = self.lock();
        let id = guard.next_qbl_id;
        guard.next_qbl_id = guard.next_qbl_id.wrapping_add(1);

        for face in guard.faces.values_mut() {
            if let Ok(qbl) =
                face.session
                    .declare_queryable(keyexpr.clone(), queryable_options(complete), sink())
            {
                face.qbls.insert(id, qbl);
            }
        }
        guard.qbls.push(QblEntry {
            id,
            keyexpr,
            complete,
            sink,
        });
        id
    }

    /// Drop a C queryable: remove it from the SSOT so no future face replays
    /// it, and drop every face's wz queryable for it (each emitting its wire
    /// `Declare(UndeclQueryable)`). Mirror of [`Self::undeclare_subscriber`],
    /// including the drop-outside-the-lock discipline.
    pub fn undeclare_queryable(&self, id: QblId) {
        let mut dropped = Vec::new();
        let mut dropped_entry = None;
        {
            let mut guard = self.lock();
            if let Some(pos) = guard.qbls.iter().position(|entry| entry.id == id) {
                dropped_entry = Some(guard.qbls.remove(pos));
            }
            for face in guard.faces.values_mut() {
                if let Some(qbl) = face.qbls.remove(&id) {
                    dropped.push(qbl);
                }
            }
        }
        // Drop OUTSIDE the lock — see `undeclare_subscriber`: the last
        // `Arc<CQueryClosure>` release runs the C `drop(context)`.
        drop(dropped);
        drop(dropped_entry);
    }
}

/// The wz queryable options one C `z_queryable_options_t` maps to.
///
/// `allowed_origin` is pinned `Locality::Remote`, mirroring the fan-out
/// publish's choice (`pubsub::put_options`), for two independent reasons:
///
/// **Fidelity.** pico's `Z_FEATURE_LOCAL_QUERYABLE` defaults to **0**
/// (`~/zenoh-pico/CMakeLists.txt:353`) — that is why its default
/// `z_queryable_options_t` has no `allowed_origin` field at all (see
/// [`crate::query::z_queryable_options_t`]). A default pico build has NO local
/// queryable, so Remote-only IS the faithful default rather than a restriction.
///
/// **Soundness — and this one is load-bearing.** `Locality::Any::allows_local()`
/// is TRUE (`wz-session-core/src/locality.rs:70-72`). The `unsafe impl Sync for
/// CQueryClosure` rests on the C application thread never invoking the queryable
/// handler; `Session::query` gates its in-process fan and its drain on
/// `allows_local` (`session/mod.rs:1976, 2023`), which protects a Remote-only
/// get but NOT a default-locality one. So an `Any` queryable would make that
/// `unsafe impl` FALSE the moment `z_get` lands: a C-thread get would run
/// `local_query` + `drain_deferred_fires` on the C thread while a drive thread
/// ran `call` on another face — two `call(context)` at once on one C context,
/// which is precisely the unsound-`Sync` bug R311y288 already fixed once on the
/// publish plane. Pinning Remote makes the obligation MECHANICAL instead of a
/// promise in prose that a future round can silently break.
///
/// Consequence, named: an in-process `z_get` will not reach this session's own
/// queryable — matching pico's default build, and the same
/// `Z_FEATURE_LOCAL_*` divergence already named for local subscriber delivery.
fn queryable_options(complete: bool) -> QueryableOptions {
    QueryableOptions::new()
        .with_complete(complete)
        .with_allowed_origin(Locality::Remote)
}

/// The [`FaceForwarder`] the accept loop threads its held faces through. The
/// stock forwarders route BETWEEN faces (a router); this one instead lands
/// each face in the C session's registry and dispatches its inbound events
/// into that face's own session, which is what fires the C subscriber
/// callback. It holds `Arc<SharedSession>` (so it is `Send`, unlike the
/// `Rc`/`RefCell` routing forwarders) because the same registry is reachable
/// from the C thread.
pub struct CApiForwarder {
    shared: Arc<SharedSession>,
}

impl CApiForwarder {
    pub fn new(shared: Arc<SharedSession>) -> Self {
        Self { shared }
    }
}

impl FaceForwarder for CApiForwarder {
    fn register(&self, id: FaceId, actions: &Arc<SessionLinkActions>) {
        self.shared.face_up(id.0, actions);
    }

    fn deregister(&self, id: FaceId) {
        self.shared.face_down(id.0);
    }

    fn forward(&self, id: FaceId, event: IterationEvent<'_>) {
        self.shared.dispatch(id.0, event);
    }

    /// Arm this face's drive loop on its earliest pending `z_get` deadline, so
    /// [`SharedSession::dispatch`]'s sweep runs when a get is actually due.
    ///
    /// Without this the accepted faces would sweep only on the keepalive wake
    /// (~3333 ms for this crate's 10 s lease), because a query timing out is by
    /// definition traffic-free — so nothing else would wake the loop and a
    /// `timeout_ms = 100` get would report its final 33x late.
    fn next_extra_deadline_ms(&self, id: FaceId) -> Option<u64> {
        self.shared.next_reply_deadline_ms(id.0)
    }

    /// Let a C-thread `z_get` wake this face's drive loop so it re-arms on the
    /// new pending query's deadline. Without it the deadline above would only
    /// be re-read at the loop's next wake — the keepalive one, ~3333 ms away —
    /// and every get issued into an idle session would be that late.
    fn deadline_revised(&self, id: FaceId) -> Option<Arc<tokio::sync::Notify>> {
        self.shared.deadline_revised(id.0)
    }
}

#[cfg(test)]
mod matching_aggregate_tests {
    use super::*;

    /// R311y528 — THE defect this round closed, asserted at the mechanism.
    ///
    /// Two threads reach one C matching closure: the drive thread (per-face
    /// callback, and `face_down`'s purge) and the C application thread (an
    /// already-matching registration delivering synchronously). What makes that
    /// sound is that [`deliver_matching_flip`] holds the entry's aggregate mutex
    /// ACROSS the call, so the two cannot overlap.
    ///
    /// The assertion is a `try_lock` from INSIDE the sink and is fully
    /// deterministic — no threads, no sleeps, no window to get unlucky in.
    /// `std::sync::Mutex::try_lock` reports `WouldBlock` for a lock already held
    /// by the calling thread, so "the mutex is held right now" is directly
    /// observable at the one instant that matters. R311y527's code released the
    /// mutex before the sink; against that build this reads `Ok` and reds.
    #[test]
    fn the_aggregate_mutex_is_held_across_the_c_call() {
        let state = Arc::new(StdMutex::new(MatchAggregate::default()));
        let probe = state.clone();
        let observed = Arc::new(StdMutex::new(Vec::new()));
        let log = observed.clone();

        let sink: MatchingSink = Arc::new(move |now| {
            log.lock().unwrap().push(now);
            assert!(
                probe.try_lock().is_err(),
                "the aggregate mutex was NOT held across the C call -- two \
                 threads can then invoke one C context concurrently"
            );
        });

        deliver_matching_flip(&state, &sink, |agg| agg.apply(7, true));
        assert_eq!(*observed.lock().unwrap(), vec![true], "the flip delivered");
    }

    /// The OR across faces, at the fold: a second matching face is NOT a second
    /// `true`, one face leaving while another still matches is SILENT, and only
    /// the last one leaving delivers `false`.
    ///
    /// This is the aggregation `MatchAggregate` exists for. A build that
    /// forwarded each face's verdict straight through would deliver
    /// `[true, true, false, false]` here.
    #[test]
    fn the_verdict_is_the_or_across_faces() {
        let state = Arc::new(StdMutex::new(MatchAggregate::default()));
        let observed = Arc::new(StdMutex::new(Vec::new()));
        let log = observed.clone();
        let sink: MatchingSink = Arc::new(move |now| log.lock().unwrap().push(now));

        deliver_matching_flip(&state, &sink, |agg| agg.apply(1, true));
        deliver_matching_flip(&state, &sink, |agg| agg.apply(2, true));
        deliver_matching_flip(&state, &sink, |agg| agg.apply(1, false));
        deliver_matching_flip(&state, &sink, |agg| agg.apply(2, false));

        assert_eq!(
            *observed.lock().unwrap(),
            vec![true, false],
            "the C side must see the SESSION verdict flip twice, not once per face"
        );
    }

    /// `face_down`'s purge and an ordinary `false` from the same face must not
    /// both flip: whichever lands first owns the transition.
    ///
    /// This is why the purge uses `forget` (idempotent removal) rather than
    /// `apply(id, false)` — but both settle through the same `settle()`, so the
    /// property to pin is that the second one is silent.
    #[test]
    fn a_purge_after_an_ordinary_false_is_silent() {
        let state = Arc::new(StdMutex::new(MatchAggregate::default()));
        let observed = Arc::new(StdMutex::new(Vec::new()));
        let log = observed.clone();
        let sink: MatchingSink = Arc::new(move |now| log.lock().unwrap().push(now));

        deliver_matching_flip(&state, &sink, |agg| agg.apply(3, true));
        deliver_matching_flip(&state, &sink, |agg| agg.apply(3, false));
        deliver_matching_flip(&state, &sink, |agg| agg.forget(3));

        assert_eq!(*observed.lock().unwrap(), vec![true, false]);
    }

    /// Two threads folding into ONE entry deliver strictly serialised, ordered
    /// calls — never overlapping, and never `false` before the `true` that the
    /// aggregate computed first.
    ///
    /// The in-flight counter can only under-report (a scheduler that never
    /// overlaps the two threads passes trivially), so this CORROBORATES
    /// [`the_aggregate_mutex_is_held_across_the_c_call`] rather than replacing
    /// it — that one is the deterministic proof. What this adds is the ORDER
    /// property, which the single-threaded probe cannot see: releasing the mutex
    /// before the sink lost ordering even when the calls did not overlap.
    #[test]
    fn concurrent_folds_deliver_serialised_and_in_order() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let state = Arc::new(StdMutex::new(MatchAggregate::default()));
        let inflight = Arc::new(AtomicUsize::new(0));
        let overlaps = Arc::new(AtomicUsize::new(0));
        let observed = Arc::new(StdMutex::new(Vec::new()));

        let sink: MatchingSink = {
            let inflight = inflight.clone();
            let overlaps = overlaps.clone();
            let log = observed.clone();
            Arc::new(move |now| {
                if inflight.fetch_add(1, Ordering::SeqCst) != 0 {
                    overlaps.fetch_add(1, Ordering::SeqCst);
                }
                log.lock().unwrap().push(now);
                std::thread::yield_now();
                inflight.fetch_sub(1, Ordering::SeqCst);
            })
        };

        // Face 1 arrives and stays; then two threads race the arrival of face 2
        // against the departure of face 1. Whatever the interleaving, the
        // aggregate is non-empty throughout, so the CORRECT observation is that
        // nothing further is delivered at all.
        deliver_matching_flip(&state, &sink, |agg| agg.apply(1, true));

        let a = {
            let (state, sink) = (state.clone(), sink.clone());
            std::thread::spawn(move || {
                for _ in 0..200 {
                    deliver_matching_flip(&state, &sink, |agg| agg.apply(2, true));
                }
            })
        };
        let b = {
            let (state, sink) = (state.clone(), sink.clone());
            std::thread::spawn(move || {
                for _ in 0..200 {
                    deliver_matching_flip(&state, &sink, |agg| agg.forget(2));
                }
            })
        };
        a.join().unwrap();
        b.join().unwrap();

        assert_eq!(
            overlaps.load(Ordering::SeqCst),
            0,
            "two threads were inside the C sink at once"
        );
        assert_eq!(
            *observed.lock().unwrap(),
            vec![true],
            "face 1 never left, so the session verdict never moved off true"
        );
    }
}
