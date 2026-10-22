// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! Open-debt item 913 — the MULTICAST faces of a C session: a group the session
//! joined, held as one face beside its unicast ones.
//!
//! ## Why a face of its own kind, and not a `FaceEntry`
//!
//! A unicast face is one peer over its own link, and the registry keeps a
//! session per face because a peer's keyexpr aliases are an id space of its
//! own. A group is the other shape: ONE session reaches every member with one
//! send, and a query on it expects one final from each member it holds when it
//! is sent (`vendor/zenoh-pico/src/net/primitives.c` @
//! `_z_transport_get_peers_count`). Its replay, its publish leg and its query
//! leg each differ from a unicast face's, and an entry of its own makes each
//! difference a place in the code rather than a branch inside the unicast one.
//!
//! ## What a group face carries, and what it does not send
//!
//! The session's subscribers and queryables: a member's put reaches the C
//! subscriber, and a member's query the C queryable, whose replies and final
//! leave on the group. A put or a get names its key by the literal, because
//! zenoh-pico declares no keyexpr on a multicast transport unless its
//! `Z_FEATURE_MULTICAST_DECLARATIONS` is on, which it is not by default
//! (`vendor/zenoh-pico/src/session/keyexpr.c` @
//! `#if Z_FEATURE_MULTICAST_DECLARATIONS == 0`).
//!
//! Not sent: the Declare of each subscriber, queryable and liveliness token,
//! which zenoh-pico sends over whatever transport its session holds
//! (`_z_send_declare`, `vendor/zenoh-pico/src/net/primitives.c`). A member
//! that reads them (a write filter, a matching listener, a liveliness
//! subscriber) hears none from this face; a member's put and query reach it
//! whether or not it heard any, which is what a group carries without them.
//!
//! ## Who drives it
//!
//! The drive role, on the thread that runs the session's callbacks: the loop
//! that hears the group hands each event to [`dispatch_mcast_event`], and a
//! second arm, [`sweep_mcast_face`], expires the gets that wait on the group.

use std::collections::BTreeMap;
use std::sync::Arc;

use tokio::sync::Notify;

use wz_runtime_tokio::multicast_glue::{McastGroupMembership, MulticastTxProducer};
use wz_runtime_tokio::observer::ApplicationLayerObserver;
#[cfg(feature = "queryable")]
use wz_runtime_tokio::session::Queryable;
#[cfg(feature = "queryable")]
use wz_runtime_tokio::session::TokioQueryHolder;
use wz_runtime_tokio::session::{
    LocalDeliveryDrain, SubscribeOptions, Subscriber, TokioMulticastSession,
};
use wz_runtime_tokio::session_glue::IterationEvent;
use wz_runtime_tokio::sync::PlainMutex as WzMutex;

#[cfg(feature = "queryable")]
use super::{queryable_options, QblEntry, QblId};
use super::{Inner, SharedSession, SubEntry, SubId};

/// One joined group: its session and the wz entities each C declaration has on
/// it, keyed by the C id, as a unicast face keys its own.
pub(super) struct McastFaceEntry {
    pub(super) session: TokioMulticastSession,
    pub(super) subs: BTreeMap<SubId, Subscriber>,
    #[cfg(feature = "queryable")]
    pub(super) qbls: BTreeMap<QblId, Queryable>,
    /// The group's re-arm signal, the twin of a unicast face's: a get that
    /// registers a pending query on the group wakes [`sweep_mcast_face`], so the
    /// sweep arms on the new deadline instead of the one it was parked on.
    pub(super) revised: Arc<Notify>,
}

/// A group face as a sender takes it: the session and its re-arm signal, read
/// together so a get's leg and the wake it owes come from one step of the
/// registry.
#[derive(Clone)]
pub(super) struct McastLeg {
    pub(super) session: TokioMulticastSession,
    pub(super) revised: Arc<Notify>,
}

impl Inner {
    /// Rebuild [`Inner::mcast_set`] from `mcast_faces`, with the lock held, as
    /// [`Inner::refresh_face_set`] does for the unicast faces.
    pub(super) fn refresh_mcast_set(&mut self) {
        self.mcast_set = Arc::new(
            self.mcast_faces
                .values()
                .map(|face| McastLeg {
                    session: face.session.clone(),
                    revised: face.revised.clone(),
                })
                .collect(),
        );
    }
}

/// Declare the C subscription `entry` on a group's session. A group is told of
/// no declaration, so this registers the callback and sends nothing.
fn subscribe_on(session: &TokioMulticastSession, entry: &SubEntry) -> Subscriber {
    session.declare_subscriber(
        entry.keyexpr.clone(),
        SubscribeOptions::default().with_allowed_origin(entry.allowed_origin),
        (entry.sink)(),
    )
}

/// Declare the C queryable `entry` on a group's session. Its handler is minted
/// with the GROUP as the holder of an escaped query, so a query that came over
/// the group is answered on the group.
#[cfg(feature = "queryable")]
fn answer_on(session: &TokioMulticastSession, entry: &QblEntry) -> Queryable {
    session.declare_queryable(
        entry.keyexpr.clone(),
        queryable_options(entry.complete, entry.allowed_origin),
        (entry.sink)(&TokioQueryHolder::Group(session.clone())),
    )
}

impl SharedSession {
    /// A session for a group this node joins, sending through `producer`, the
    /// group's transmit seam, and counting the members `membership` holds when a
    /// get is sent on it.
    ///
    /// Its drain is the drive task's, as a unicast face's is: what a member
    /// sends is delivered on the thread that runs the session's callbacks.
    pub fn new_mcast_face_session(
        &self,
        producer: MulticastTxProducer,
        membership: &McastGroupMembership,
    ) -> TokioMulticastSession {
        let observer = Arc::new(WzMutex::new(ApplicationLayerObserver::new()));
        let session =
            TokioMulticastSession::new_multicast(observer, Arc::new(self.clock), producer)
                .with_local_delivery_drain(LocalDeliveryDrain::DriveTask);
        // A fresh session holds no membership, so the attach cannot be refused. Without the
        // query plane nothing counts the members.
        #[cfg(feature = "query")]
        let _ = session.attach_group_membership(membership);
        #[cfg(not(feature = "query"))]
        let _ = membership;
        session
    }

    /// A group face came up: replay the session's subscribers and queryables onto
    /// `session` and register it as face `id`, with `revised` as its re-arm signal,
    /// the one its [`sweep_mcast_face`] waits on.
    ///
    /// A face already registered under `id` is replaced, and its entities are
    /// dropped outside the registry lock, as a replaced unicast face's are.
    pub fn mcast_face_up(&self, id: u64, session: &TokioMulticastSession, revised: &Arc<Notify>) {
        let mut guard = self.lock();
        let subs = guard
            .subs
            .iter()
            .map(|entry| (entry.id, subscribe_on(session, entry)))
            .collect();
        #[cfg(feature = "queryable")]
        let qbls = guard
            .qbls
            .iter()
            .map(|entry| (entry.id, answer_on(session, entry)))
            .collect();
        let replaced = guard.mcast_faces.insert(
            id,
            McastFaceEntry {
                session: session.clone(),
                subs,
                #[cfg(feature = "queryable")]
                qbls,
                revised: revised.clone(),
            },
        );
        guard.refresh_mcast_set();
        drop(guard);
        drop(replaced);
    }

    /// A group face left: the group's link is gone for good, or the session is
    /// closing. Its entities are dropped outside the registry lock, since the last
    /// of them may release a C closure.
    pub fn mcast_face_down(&self, id: u64) {
        let removed = {
            let mut guard = self.lock();
            let removed = guard.mcast_faces.remove(&id);
            guard.refresh_mcast_set();
            removed
        };
        drop(removed);
    }

    /// Declare the C subscription `entry` on every group face.
    pub(super) fn subscribe_on_groups(guard: &mut Inner, entry: &SubEntry) {
        for face in guard.mcast_faces.values_mut() {
            let sub = subscribe_on(&face.session, entry);
            face.subs.insert(entry.id, sub);
        }
    }

    /// Declare the C queryable `entry` on every group face.
    #[cfg(feature = "queryable")]
    pub(super) fn answer_on_groups(guard: &mut Inner, entry: &QblEntry) {
        for face in guard.mcast_faces.values_mut() {
            let qbl = answer_on(&face.session, entry);
            face.qbls.insert(entry.id, qbl);
        }
    }

    /// Take subscription `id` off every group face, for the caller to drop
    /// outside the lock.
    pub(super) fn unsubscribe_on_groups(guard: &mut Inner, id: SubId) -> Vec<Subscriber> {
        guard
            .mcast_faces
            .values_mut()
            .filter_map(|face| face.subs.remove(&id))
            .collect()
    }

    /// Take queryable `id` off every group face, for the caller to drop outside the
    /// lock.
    #[cfg(feature = "queryable")]
    pub(super) fn unanswer_on_groups(guard: &mut Inner, id: QblId) -> Vec<Queryable> {
        guard
            .mcast_faces
            .values_mut()
            .filter_map(|face| face.qbls.remove(&id))
            .collect()
    }
}

/// One event the loop of a group face heard: dispatched into the face's session,
/// whose subscribers and queryables run, and then the gets that expired on it
/// are ended, on the thread that runs the session's callbacks, as
/// [`SharedSession::dispatch`] ends a unicast face's.
pub fn dispatch_mcast_event(session: &TokioMulticastSession, event: IterationEvent<'_>) {
    session.dispatch_multicast_iteration_event(event);
    #[cfg(feature = "query")]
    if session.sweep_expired_queries_staged() > 0 {
        session.drain_deferred_fires();
    }
}

/// The arm that ends the gets waiting on a group when their deadline passes.
/// Never returns.
///
/// A unicast face's drive loop arms its own wake on its earliest deadline; a
/// group's loop ticks on its own schedule and knows nothing of the gets, so this
/// arm waits for the earliest deadline the session holds, or for `revised`, which
/// a get that registers on the group notifies, and sweeps. A group with no get
/// pending waits on `revised` alone.
#[cfg(feature = "query")]
pub async fn sweep_mcast_face(session: &TokioMulticastSession, revised: &Notify) {
    use wz_runtime_core::TimeSource as _;

    loop {
        match session.next_reply_deadline_ms() {
            Some(due) => {
                let wait = due.saturating_sub(session.clock().now_monotonic_ms());
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_millis(wait)) => {}
                    _ = revised.notified() => {}
                }
            }
            None => revised.notified().await,
        }
        if session.sweep_expired_queries_staged() > 0 {
            session.drain_deferred_fires();
        }
    }
}

/// Without the query plane there is no get to end: the arm waits forever, as a
/// group with no get pending does.
#[cfg(not(feature = "query"))]
pub async fn sweep_mcast_face(_session: &TokioMulticastSession, _revised: &Notify) {
    std::future::pending::<()>().await
}
