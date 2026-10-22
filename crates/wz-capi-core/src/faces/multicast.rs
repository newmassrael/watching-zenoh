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

use wz_runtime_tokio::multicast_glue::{
    McastGroupMembership, MulticastMember, MulticastTxProducer,
};
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

use wz_runtime_tokio::session_glue::LinkKind;

#[cfg(feature = "queryable")]
use super::{queryable_options, QblEntry, QblId};
use super::{
    FaceEventKind, FaceSnapshot, GroupLink, Inner, LinkSnapshot, SharedSession, SubEntry, SubId,
};

/// One member of a group as the transport both upstreams report it as: its zid and role,
/// neither QoS nor shared memory, and one link from this node's locator on the group to the
/// member's address, over the group (`src`, `group` and `endpoint` label it; see
/// [`GroupLink`]). `None` for a member whose JOIN named a role this node does not know,
/// which a transport cannot report, as [`FaceSnapshot`] refuses a face with no role.
///
/// The link is a UDP datagram link, whose MTU each ABI reports by its own table.
fn member_snapshot(
    member: &MulticastMember,
    src: &str,
    group: &str,
    endpoint: &str,
) -> Option<FaceSnapshot> {
    let whatami = member.whatami?.to_wire();
    let peer = member.peer.as_slice();
    let mut zid = [0u8; 16];
    let n = peer.len().min(16);
    zid[..n].copy_from_slice(&peer[..n]);
    Some(FaceSnapshot {
        zid,
        whatami,
        is_qos: false,
        is_multicast: true,
        is_shm: false,
        links: vec![LinkSnapshot {
            src: src.to_owned(),
            dst: format!("udp/{}", member.locator),
            kind: Some(LinkKind::Udp),
            interfaces: None,
            mtu: 0,
            group: Some(GroupLink {
                locator: group.to_owned(),
                endpoint: endpoint.to_owned(),
            }),
        }],
    })
}

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
    /// Who is on the group, as the face's loop keeps it.
    pub(super) membership: McastGroupMembership,
    /// The group's transmit seam, which a JOIN asked for on the session's word goes
    /// through.
    pub(super) producer: MulticastTxProducer,
    /// The endpoint the session joined the group by, as the session was given it.
    pub(super) endpoint: String,
    /// The members announced as connected so far, each as it was announced, so a
    /// departure is announced as the arrival was even when the join that held it is gone.
    pub(super) announced: Vec<(MulticastMember, FaceSnapshot)>,
}

/// What a group face is made of when it comes up ([`SharedSession::mcast_face_up`]).
pub struct McastFaceParts<'a> {
    /// The group's session.
    pub session: &'a TokioMulticastSession,
    /// The group's re-arm signal, the one its [`sweep_mcast_face`] waits on.
    pub revised: &'a Arc<Notify>,
    /// Who is on the group.
    pub membership: &'a McastGroupMembership,
    /// The group's transmit seam.
    pub producer: &'a MulticastTxProducer,
    /// The endpoint the session joined the group by.
    pub endpoint: &'a str,
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
    /// its session and register it as face `id`.
    ///
    /// A face already registered under `id` is replaced, and its entities are
    /// dropped outside the registry lock, as a replaced unicast face's are.
    pub fn mcast_face_up(&self, id: u64, parts: McastFaceParts<'_>) {
        let McastFaceParts {
            session,
            revised,
            membership,
            producer,
            endpoint,
        } = parts;
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
                membership: membership.clone(),
                producer: producer.clone(),
                endpoint: endpoint.to_owned(),
                announced: Vec::new(),
            },
        );
        guard.refresh_mcast_set();
        drop(guard);
        drop(replaced);
    }

    /// Every member of every group the session joined, each as the multicast transport
    /// both upstreams report it as, with its one link: in pico's `z_info_transports` /
    /// `z_info_links` (`vendor/zenoh-pico/src/api/api.c` @
    /// `z_result_t z_info_transports(const z_loaned_session_t *zs, z_moved_closure_transport_t *callback) {`)
    /// and zenoh's
    /// peers of a multicast transport (`io/zenoh-transport/src/multicast/transport.rs` @
    /// `link.dst = p.locator.clone();`).
    ///
    /// Not among [`Self::face_snapshots`], which a caller that reports unicast faces
    /// alone reads: pico's admin space leaves a multicast transport out
    /// (`vendor/zenoh-pico/src/api/admin_space.c` @
    /// `if (transport == NULL || z_transport_is_multicast(transport)) {`).
    pub fn group_member_snapshots(&self) -> Vec<FaceSnapshot> {
        self.lock()
            .mcast_faces
            .values()
            .flat_map(|face| face.announced.iter().map(|(_, snapshot)| snapshot.clone()))
            .collect()
    }

    /// The members of group face `id` are now `members`: announce each that left as a
    /// departed transport and each that came as an arrived one, as pico announces a member
    /// connected at its JOIN and disconnected at its lease, its Close or a JOIN that
    /// changes it (`vendor/zenoh-pico/src/transport/multicast/rx.c` @
    /// `_z_connectivity_peer_connected(_z_transport_common_get_session(&ztm->_common), &connected_peer, true, mtu,`).
    ///
    /// A member is the same member while its zid, role and address are: a JOIN that moves
    /// any of them is a departure and an arrival. Departures are announced first, so a
    /// member that re-joined changed is never reported twice at once. The events run
    /// outside the registry lock ([`Self::fire_face_event`]).
    pub(crate) fn group_members_moved(&self, id: u64, members: &[MulticastMember]) {
        let (departed, arrived) = {
            let mut guard = self.lock();
            let Some(face) = guard.mcast_faces.get_mut(&id) else {
                return;
            };
            let labels = face.membership.link();
            let (kept, departed): (Vec<_>, Vec<_>) = std::mem::take(&mut face.announced)
                .into_iter()
                .partition(|(member, _)| members.contains(member));
            face.announced = kept;
            let mut arrived = Vec::new();
            for member in members {
                if face.announced.iter().any(|(held, _)| held == member) {
                    continue;
                }
                let Some((src, group)) = labels.as_ref() else {
                    continue;
                };
                let Some(snapshot) = member_snapshot(member, src, group, &face.endpoint) else {
                    continue;
                };
                face.announced.push((*member, snapshot.clone()));
                arrived.push(snapshot);
            }
            (departed, arrived)
        };
        for (_, snapshot) in &departed {
            self.fire_face_event(FaceEventKind::Down, snapshot);
        }
        for snapshot in &arrived {
            self.fire_face_event(FaceEventKind::Up, snapshot);
        }
    }

    /// Ask every group face to send its JOIN now (pico's `zp_send_join`); how many were
    /// asked.
    pub fn send_join_on_groups(&self) -> usize {
        let guard = self.lock();
        for face in guard.mcast_faces.values() {
            face.producer.request_join();
        }
        guard.mcast_faces.len()
    }

    /// The zid of every member of every group the session joined, as each group's peer
    /// table holds it: what pico's `z_info_peers_zid` reports for a multicast transport,
    /// whatever role a member announced (`vendor/zenoh-pico/src/transport/multicast.c` @
    /// `void _zp_multicast_fetch_zid(`).
    pub fn group_member_zids(&self) -> Vec<Vec<u8>> {
        // Cloned out of the registry lock: each membership has a lock of its own, which its
        // face's loop takes to write.
        let memberships: Vec<McastGroupMembership> = self
            .lock()
            .mcast_faces
            .values()
            .map(|face| face.membership.clone())
            .collect();
        memberships
            .iter()
            .flat_map(McastGroupMembership::members)
            .map(|member| member.peer.as_slice().to_vec())
            .collect()
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
