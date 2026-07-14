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

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex as StdMutex, MutexGuard};

use tokio::sync::Notify;

use wz_runtime_tokio::accept_loop::{FaceForwarder, FaceId};
use wz_runtime_tokio::locality::Locality;
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::{TokioRuntime, TokioTime};
use wz_runtime_tokio::session::{
    PublishError, PublishOptions, Queryable, QueryableOptions, SubscribeOptions, Subscriber,
    TokioSession,
};
use wz_runtime_tokio::session_glue::{IterationEvent, SessionLinkActions};
use wz_runtime_tokio::sync::Mutex as WzMutex;

use crate::pubsub::{make_subscriber_callback, CClosure};
use crate::query::{make_queryable_callback, CQueryClosure};

/// A C-level subscription id — what a `z_owned_subscriber_t` handle carries.
/// It keys the per-face wz [`Subscriber`]s this one C subscription spawned.
pub(crate) type SubId = u64;

/// A C-level queryable id — what a `z_owned_queryable_t` handle carries. The
/// responder-side mirror of [`SubId`], keying the per-face wz [`Queryable`]s
/// one C queryable declaration spawned.
pub(crate) type QblId = u64;

/// The face id the dial (`connect`) role occupies. A dialed session has
/// exactly one peer, so it needs no id space of its own; the accept role's
/// ids come from the accept loop's own monotonic `FaceId`.
pub(crate) const DIAL_FACE_ID: u64 = 0;

/// One connected peer: its wz session, plus the wz subscribers this face
/// carries keyed by the C subscription id that spawned them. Dropping the
/// entry drops the subscribers (each emitting its wire undeclare) and then
/// the session.
struct FaceEntry {
    session: TokioSession,
    subs: BTreeMap<SubId, Subscriber<TokioRuntime>>,
    qbls: BTreeMap<QblId, Queryable<TokioRuntime>>,
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
    closure: Arc<CClosure>,
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
    closure: Arc<CQueryClosure>,
}

#[derive(Default)]
struct Inner {
    faces: BTreeMap<u64, FaceEntry>,
    subs: Vec<SubEntry>,
    next_sub_id: SubId,
    qbls: Vec<QblEntry>,
    next_qbl_id: QblId,
}

/// The registry behind a `z_owned_session_t`, shared between the C thread
/// (which declares and publishes) and the drive thread (which brings faces up
/// and dispatches inbound samples).
pub(crate) struct SharedSession {
    inner: StdMutex<Inner>,
    clock: TokioTime,
}

impl SharedSession {
    pub(crate) fn new(clock: TokioTime) -> Self {
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
    pub(crate) fn face_up(&self, id: u64, actions: &Arc<SessionLinkActions>) {
        let observer = Arc::new(WzMutex::new(ApplicationLayerObserver::new()));
        let session = TokioSession::new(actions.clone(), observer, Arc::new(self.clock));

        let mut guard = self.lock();
        let mut subs = BTreeMap::new();
        for entry in &guard.subs {
            if let Ok(sub) = session.declare_subscriber(
                entry.keyexpr.clone(),
                SubscribeOptions::default(),
                make_subscriber_callback(entry.closure.clone()),
            ) {
                subs.insert(entry.id, sub);
            }
        }
        let mut qbls = BTreeMap::new();
        for entry in &guard.qbls {
            if let Ok(qbl) = session.declare_queryable(
                entry.keyexpr.clone(),
                queryable_options(entry.complete),
                make_queryable_callback(entry.closure.clone()),
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
        let replaced = guard.faces.insert(
            id,
            FaceEntry {
                session,
                subs,
                qbls,
                revised: Arc::new(Notify::new()),
            },
        );
        drop(guard);
        drop(replaced);
    }

    /// A face left the live set (peer Close / link loss).
    pub(crate) fn face_down(&self, id: u64) {
        // Drop OUTSIDE the lock: dropping the entry drops its subscribers,
        // and the last one may release the final `Arc<CClosure>` and run the
        // C `drop(context)`.
        let removed = self.lock().faces.remove(&id);
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
    pub(crate) fn clear_faces(&self) {
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
    pub(crate) fn dispatch(&self, id: u64, event: IterationEvent<'_>) {
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
    pub(crate) fn next_reply_deadline_ms(&self, id: u64) -> Option<u64> {
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
    pub(crate) fn publish_all(
        &self,
        keyexpr: &str,
        payload: &[u8],
        opts: &PublishOptions,
    ) -> Result<usize, ()> {
        let sessions = self.face_sessions();
        let mut delivered = 0usize;
        for session in sessions {
            match session.publish(keyexpr, payload, opts.clone()) {
                Ok(n) => delivered += n,
                // Per-face transient failure (link released / reconnecting):
                // best-effort, keep delivering to the surviving faces.
                Err(PublishError::TransportUnavailable) => {}
                // Deterministic, face-independent: fails on every face.
                Err(_) => return Err(()),
            }
        }
        Ok(delivered)
    }

    /// A snapshot of every connected face's session, taken OUT of the registry
    /// lock — what a fan-out operation iterates.
    ///
    /// Returning a snapshot rather than lending the guard is the crate's
    /// standing locking discipline made reusable: every fan (`publish_all`,
    /// `z_get`) may invoke C code, and a pico callback is allowed to re-enter
    /// the session, so walking `guard.faces` while calling into a face would
    /// deadlock the non-reentrant mutex.
    pub(crate) fn face_sessions(&self) -> Vec<TokioSession> {
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
    pub(crate) fn face_sessions_with_wake(&self) -> Vec<(TokioSession, Arc<Notify>)> {
        self.lock()
            .faces
            .values()
            .map(|face| (face.session.clone(), face.revised.clone()))
            .collect()
    }

    /// Face `id`'s drive-loop re-arm signal (see [`FaceEntry::revised`]).
    pub(crate) fn deadline_revised(&self, id: u64) -> Option<Arc<Notify>> {
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
    pub(crate) fn declare_subscriber(&self, keyexpr: String, closure: Arc<CClosure>) -> SubId {
        let mut guard = self.lock();
        let id = guard.next_sub_id;
        guard.next_sub_id = guard.next_sub_id.wrapping_add(1);

        for face in guard.faces.values_mut() {
            if let Ok(sub) = face.session.declare_subscriber(
                keyexpr.clone(),
                SubscribeOptions::default(),
                make_subscriber_callback(closure.clone()),
            ) {
                face.subs.insert(id, sub);
            }
        }
        guard.subs.push(SubEntry {
            id,
            keyexpr,
            closure,
        });
        id
    }

    /// Drop a C subscription: remove it from the SSOT so no future face
    /// replays it, and drop every face's wz subscriber for it (each emitting
    /// its wire undeclare).
    pub(crate) fn undeclare_subscriber(&self, id: SubId) {
        let mut dropped = Vec::new();
        let mut dropped_entry = None;
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
        }
        // Drop OUTSIDE the lock: releasing the last `Arc<CClosure>` — whether
        // the final per-face subscriber or the SSOT entry — runs the C
        // `drop(context)`, which must not run under the registry lock (a drop
        // that re-enters the session would deadlock the non-reentrant mutex).
        drop(dropped);
        drop(dropped_entry);
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
    pub(crate) fn declare_queryable(
        &self,
        keyexpr: String,
        complete: bool,
        closure: Arc<CQueryClosure>,
    ) -> QblId {
        let mut guard = self.lock();
        let id = guard.next_qbl_id;
        guard.next_qbl_id = guard.next_qbl_id.wrapping_add(1);

        for face in guard.faces.values_mut() {
            if let Ok(qbl) = face.session.declare_queryable(
                keyexpr.clone(),
                queryable_options(complete),
                make_queryable_callback(closure.clone()),
            ) {
                face.qbls.insert(id, qbl);
            }
        }
        guard.qbls.push(QblEntry {
            id,
            keyexpr,
            complete,
            closure,
        });
        id
    }

    /// Drop a C queryable: remove it from the SSOT so no future face replays
    /// it, and drop every face's wz queryable for it (each emitting its wire
    /// `Declare(UndeclQueryable)`). Mirror of [`Self::undeclare_subscriber`],
    /// including the drop-outside-the-lock discipline.
    pub(crate) fn undeclare_queryable(&self, id: QblId) {
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
pub(crate) struct CApiForwarder {
    shared: Arc<SharedSession>,
}

impl CApiForwarder {
    pub(crate) fn new(shared: Arc<SharedSession>) -> Self {
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
