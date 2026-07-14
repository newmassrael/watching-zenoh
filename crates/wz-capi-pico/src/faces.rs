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

use wz_runtime_tokio::accept_loop::{FaceForwarder, FaceId};
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::{TokioRuntime, TokioTime};
use wz_runtime_tokio::session::{
    PublishError, PublishOptions, SubscribeOptions, Subscriber, TokioSession,
};
use wz_runtime_tokio::session_glue::{IterationEvent, SessionLinkActions};
use wz_runtime_tokio::sync::Mutex as WzMutex;

use crate::pubsub::{make_subscriber_callback, CClosure};

/// A C-level subscription id — what a `z_owned_subscriber_t` handle carries.
/// It keys the per-face wz [`Subscriber`]s this one C subscription spawned.
pub(crate) type SubId = u64;

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

#[derive(Default)]
struct Inner {
    faces: BTreeMap<u64, FaceEntry>,
    subs: Vec<SubEntry>,
    next_sub_id: SubId,
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
    /// subscription SSOT onto it (pico's push-declarations-to-the-new-peer,
    /// `accept.c:148-149`).
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
        guard.faces.insert(id, FaceEntry { session, subs });
    }

    /// A face left the live set (peer Close / link loss).
    pub(crate) fn face_down(&self, id: u64) {
        // Drop OUTSIDE the lock: dropping the entry drops its subscribers,
        // and the last one may release the final `Arc<CClosure>` and run the
        // C `drop(context)`.
        let removed = self.lock().faces.remove(&id);
        drop(removed);
    }

    /// One inbound iteration event for `id` — dispatched into that face's own
    /// session (and so its own observer, keeping the peer's keyexpr alias id
    /// space private to it).
    pub(crate) fn dispatch(&self, id: u64, event: IterationEvent<'_>) {
        // Clone the session out of the lock first: the dispatch fires the C
        // subscriber callback, which may re-enter this session (`z_put` from
        // inside a callback is a supported pico pattern), so holding the lock
        // across it would deadlock.
        let session = self.lock().faces.get(&id).map(|face| face.session.clone());
        if let Some(session) = session {
            session.dispatch_iteration_event(event);
        }
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
        let sessions: Vec<TokioSession> = {
            let guard = self.lock();
            guard
                .faces
                .values()
                .map(|face| face.session.clone())
                .collect()
        };
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
}
