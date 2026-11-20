// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The multicast groups a session joins, each a face of the session beside its links.
//!
//! A group's session is the session shell's (`wz_session_mcu::group_drive`), the one an MCU image
//! runs, hosted as a task of the session's local set as each link's session is: its JOIN beacon,
//! the members it admits, its lease sweep, the per-member order of what they send and the framing
//! of what it sends are that session's, and every rule they follow is the session core's
//! (`multicast_dispatch`, `multicast_rx`, `multicast_tx`). The dispatcher keeps each member's
//! declarations apart from the moment it is built (`MulticastConfig::of_group`, the config the
//! tokio engine's group face builds its dispatcher from too), since two members number their
//! entities alike.
//!
//! What this module adds is the hosting: the group's tables in the session's registry, where what
//! a member sends is dispatched as a peer's frames are; the queue the session puts its own
//! messages on, which the group's task drains with the replies its dispatch stages; the members
//! the group's JOINs admitted; and the stop the session's close asks for, after which the task
//! tells the group it leaves.

use alloc::rc::Rc;
use core::cell::{Cell, RefCell};
use core::net::SocketAddr;

use wz_capi_port::group::{GroupDeclarations, GroupJoin};
use wz_capi_port::{FanoutError, WireKey};
use wz_runtime_coop::group_transport::GroupTransport;
use wz_runtime_coop::{ClockSource, CoopLocalJoinHandle, CoopLocalSet};
use wz_session_core::declare_build::{build_group_announcement, build_group_retraction};
use wz_session_core::declare_form::{GroupDeclaration, GroupKey, RetractionKey};
use wz_session_core::driver_loop::IterationEvent;
#[cfg(feature = "liveliness")]
use wz_session_core::interest_build::{build_interest_exact, build_interest_final, InterestKinds};
use wz_session_core::locality::Locality;
use wz_session_core::metadata::PushMetadata;
use wz_session_core::multicast_dispatch::MulticastConfig;
use wz_session_core::multicast_dispatch::MulticastMember;
use wz_session_core::multicast_params::{MulticastOutcome, MulticastParams};
use wz_session_core::multicast_reply_sink::{MulticastReplyEnqueue, MulticastReplySink};
use wz_session_core::multicast_tx::MulticastTxItem;
use wz_session_core::policy::SessionPolicy;
use wz_session_core::push_build;
use wz_session_core::qos::Priority;
use wz_session_core::sample::SampleKind;
use wz_session_core::wire_id::{EntityId, ExprId};
use wz_session_mcu::group_drive::{
    spawn_multicast_session_seeded, JoinAsk, MulticastReplyQueue, MulticastSessionSeed,
};
#[cfg(feature = "connectivity")]
use {
    super::faces::FacePlane,
    wz_session_core::face::{FaceEventKind, FaceSnapshot, GroupMemberLink},
};
#[cfg(feature = "query")]
use {
    wz_session_core::metadata::QueryMetadata,
    wz_session_core::request_build::build_request_query_with_meta,
    wz_session_core::wire_id::RequestId,
};

#[allow(unused_imports)]
use crate::prelude::*;

use super::registry::{FaceId, Registry};

/// The rows of each group's member table: a member whose JOIN finds them all held is turned
/// away, as a group whose `max_sessions` is reached turns one away. A table that does not grow,
/// so that what a group holds is what it was given when it was joined; the tokio engine's group
/// face starts from the same count of rows and grows past it, and zenoh-pico states no cap.
pub(super) const GROUP_MEMBERS: usize = 32;

/// How often a group's task looks at its beacon, its lease sweep and its stop when nothing
/// arrives, in milliseconds, and so the longest a read waits while the session holds a group: the
/// tick of the tokio engine's group face, shorter than any beacon interval an ABI advertises.
pub(super) const GROUP_TICK_MS: u32 = 50;

/// What a group's dispatch hands what it staged to: the group's queue, which its task drains.
pub(super) type GroupReplies = MulticastReplySink<MulticastReplyQueue>;

/// How the session reports a member of a group as a transport of its own: the group's locator,
/// which this node's end of the member's link is labelled by too (the address the program's stack
/// sends from is the stack's to know, as on the tokio engine's group over a program's stack), the
/// endpoint the group was joined by, and whether its transports are shared-memory ones.
#[cfg(feature = "connectivity")]
struct GroupLabel {
    group: String,
    endpoint: String,
    is_shm: bool,
}

#[cfg(feature = "connectivity")]
impl GroupLabel {
    fn of(join: &GroupJoin) -> Self {
        let group = join
            .endpoint
            .split(['#', '?'])
            .next()
            .unwrap_or(&join.endpoint);
        Self {
            group: String::from(group),
            endpoint: join.endpoint.clone(),
            is_shm: join.is_shm,
        }
    }

    /// `member` as a transport: the session core's snapshot of a group member, over a UDP link.
    fn snapshot(&self, member: &MulticastMember) -> Option<FaceSnapshot> {
        FaceSnapshot::of_group_member(
            member,
            GroupMemberLink::udp(&self.group, member, &self.group, &self.endpoint),
            self.is_shm,
        )
    }
}

/// The face events a group's members are, for the session's watchers of its faces: a member the
/// group admits came up, and one it lost went down (`connectivity`).
#[cfg(feature = "connectivity")]
struct MemberEvents {
    watchers: alloc::sync::Arc<FacePlane>,
    label: GroupLabel,
}

#[cfg(feature = "connectivity")]
impl MemberEvents {
    fn tell(&self, kind: FaceEventKind, member: &MulticastMember) {
        if !self.watchers.watched() {
            return;
        }
        if let Some(snapshot) = self.label.snapshot(member) {
            self.watchers.happened(kind, snapshot);
        }
    }
}

/// The stack's group transport as the group's task holds it, marked each time it hands the task
/// a datagram: the task takes one datagram a step, as the group's loop always has, so a group
/// that took one may hold more, and the session's read steps it again at once rather than after
/// a tick.
struct Watched {
    inner: alloc::boxed::Box<dyn GroupTransport>,
    took: Rc<Cell<bool>>,
}

impl GroupTransport for Watched {
    fn open(&mut self) -> bool {
        self.inner.open()
    }

    fn close(&mut self) {
        self.inner.close();
    }

    fn service(&self) {
        self.inner.service();
    }

    fn carrier_up(&self) -> bool {
        self.inner.carrier_up()
    }

    fn send_to_group(&mut self, datagram: &[u8]) {
        self.inner.send_to_group(datagram);
    }

    fn recv_with(&mut self, f: &mut dyn FnMut(&[u8], SocketAddr)) -> bool {
        let took = self.inner.recv_with(f);
        if took {
            self.took.set(true);
        }
        took
    }
}

/// What a group is joined with: the face its tables are in, the group as the ABI stated it (where
/// it is, what the session advertises and tells it), the stack's transport and the parameters its
/// session runs with.
pub(super) struct GroupJoining {
    pub(super) id: FaceId,
    pub(super) join: GroupJoin,
    pub(super) transport: alloc::boxed::Box<dyn GroupTransport>,
    pub(super) params: MulticastParams,
    pub(super) policy: SessionPolicy,
    /// The generation a member's query is held and answered under (`queryable`).
    #[cfg(feature = "queryable")]
    pub(super) generation: u64,
    /// The session's watchers of its faces, told of each member (`connectivity`).
    #[cfg(feature = "connectivity")]
    pub(super) watchers: alloc::sync::Arc<FacePlane>,
}

/// One group of the session: its face, its task, its queue, its members and its stop.
pub(super) struct GroupFace {
    id: FaceId,
    join: GroupJoin,
    /// The group's session; `None` once the session's end was read ([`Self::take_outcome`]).
    task: Option<CoopLocalJoinHandle<MulticastOutcome>>,
    /// When the group, whose session ended on its own, is joined again.
    rejoin_at_us: Option<u64>,
    tx: MulticastReplyQueue,
    members: Rc<RefCell<Vec<MulticastMember>>>,
    took: Rc<Cell<bool>>,
    stop: Rc<Cell<bool>>,
    /// The JOIN the session asks of the group between two beacons ([`Self::ask_join`]).
    join_ask: JoinAsk,
    /// The entities this join of the group was told of, which their retractions are told by.
    announced: RefCell<Vec<Announced>>,
    /// What the session's watchers of its faces are told of the members (`connectivity`).
    #[cfg(feature = "connectivity")]
    events: Rc<MemberEvents>,
    /// The generation a member's query is held and answered under, and the sink its answers are
    /// queued through (`queryable`).
    #[cfg(feature = "queryable")]
    generation: u64,
    #[cfg(feature = "queryable")]
    replies: GroupReplies,
    /// The request id the group's next get is asked under: the group's own, as each link's are
    /// its own, so a member's answer names it on this face alone (`query`).
    #[cfg(feature = "query")]
    next_request: Cell<RequestId>,
}

impl GroupFace {
    /// Join the group `joining` names, whose tables the registry holds already, its session
    /// spawned on `local`: each event of it goes through `dispatch`, with the sink the group's
    /// replies are queued on, after the members it admits and loses are noted. The task opens the
    /// transport as the session's link at its first step, which the caller runs.
    pub(super) fn join<C, D>(local: &CoopLocalSet<C>, joining: GroupJoining, dispatch: D) -> Self
    where
        C: ClockSource + 'static,
        D: FnMut(IterationEvent<'_, '_>, &GroupReplies) + 'static,
    {
        let GroupJoining {
            id,
            join,
            transport,
            params,
            policy,
            #[cfg(feature = "queryable")]
            generation,
            #[cfg(feature = "connectivity")]
            watchers,
        } = joining;
        #[cfg(feature = "connectivity")]
        let events = Rc::new(MemberEvents {
            watchers,
            label: GroupLabel::of(&join),
        });
        let tx = MulticastReplyQueue::new();
        let members: Rc<RefCell<Vec<MulticastMember>>> = Rc::new(RefCell::new(Vec::new()));
        let took = Rc::new(Cell::new(false));
        let stop = Rc::new(Cell::new(false));
        let join_ask = JoinAsk::default();
        // The session core's config for a group, the tokio engine's group face's too, with each
        // member's declarations kept apart: the group's events feed one session's tables.
        let config = MulticastConfig::of_group(&params, true);
        let seed: MulticastSessionSeed<Watched, GROUP_MEMBERS> = MulticastSessionSeed::new(
            config,
            Watched {
                inner: transport,
                took: Rc::clone(&took),
            },
            params,
            policy,
            u64::from(GROUP_TICK_MS),
        )
        .with_join_ask(join_ask.clone());
        let on_event = noting_members(
            Rc::clone(&members),
            MulticastReplySink::new(tx.clone()),
            dispatch,
            #[cfg(feature = "connectivity")]
            Rc::clone(&events),
        );
        let next_tx = {
            let tx = tx.clone();
            move || tx.pop()
        };
        let should_stop = {
            let stop = Rc::clone(&stop);
            move || stop.get()
        };
        let task = spawn_multicast_session_seeded(local, seed, on_event, next_tx, should_stop);
        Self {
            id,
            join,
            task: Some(task),
            rejoin_at_us: None,
            #[cfg(feature = "queryable")]
            generation,
            #[cfg(feature = "queryable")]
            replies: MulticastReplySink::new(tx.clone()),
            #[cfg(feature = "query")]
            next_request: Cell::new(0),
            tx,
            members,
            took,
            stop,
            join_ask,
            announced: RefCell::new(Vec::new()),
            #[cfg(feature = "connectivity")]
            events,
        }
    }

    /// Ask the group's session for its JOIN at its next step, between two beacons, as the tokio
    /// engine's group sends one when it is asked (zenoh-pico's `zp_send_join`): whether the group
    /// was asked, which one whose session ended is not.
    pub(super) fn ask_join(&self) -> bool {
        if self.has_ended() {
            return false;
        }
        self.join_ask.ask();
        true
    }

    /// Whether a query that came in under `generation` came on this group, whose session has
    /// not ended: where its answer goes (`queryable`).
    #[cfg(feature = "queryable")]
    pub(super) fn answers_as(&self, generation: u64) -> bool {
        self.generation == generation && !self.has_ended()
    }

    /// The sink a member's query is answered through: the group's queue (`queryable`).
    #[cfg(feature = "queryable")]
    pub(super) fn replies(&self) -> &GroupReplies {
        &self.replies
    }

    /// How many members the group holds now, each of which owes a get asked of the group one
    /// Final, as the tokio engine's group counts them (`query`).
    #[cfg(feature = "query")]
    pub(super) fn member_count(&self) -> u32 {
        if self.has_ended() {
            return 0;
        }
        u32::try_from(self.members.borrow().len()).unwrap_or(u32::MAX)
    }

    /// The request id the group's next get is asked under (`query`).
    #[cfg(feature = "query")]
    pub(super) fn alloc_request_id(&self) -> RequestId {
        let rid = self.next_request.get();
        self.next_request.set(rid.wrapping_add(1));
        rid
    }

    /// Ask the group the query `rid` on `keyexpr`, naming the key in full as a put does here,
    /// with the slots `meta` states: built by the session core's request builder, as a link's
    /// query is, and sent reliably by the group's task, as zenoh-pico sends one on its multicast
    /// transport. `false` when the query cannot be built, and nothing is queued.
    #[cfg(feature = "query")]
    pub(super) fn ask(&self, rid: RequestId, keyexpr: &str, meta: &QueryMetadata) -> bool {
        match build_request_query_with_meta(rid, 0, Some(keyexpr), meta) {
            Ok(request) => {
                self.tx.enqueue(MulticastTxItem::Request {
                    request: alloc::boxed::Box::new(request),
                });
                true
            }
            Err(_) => false,
        }
    }

    /// The face the group's tables are in.
    pub(super) fn id(&self) -> FaceId {
        self.id
    }

    /// What the session tells the group of its declarations.
    pub(super) fn declarations(&self) -> GroupDeclarations {
        self.join.declarations
    }

    /// The group as the ABI stated it, which it is joined again by.
    pub(super) fn group_join(&self) -> &GroupJoin {
        &self.join
    }

    /// Whether the group's session has ended: it left the group, lost its link, or could not
    /// open it.
    pub(super) fn has_ended(&self) -> bool {
        match &self.task {
            Some(task) => task.is_finished(),
            None => true,
        }
    }

    /// How the group's session ended, read once: `None` while it runs, and after it was read.
    /// The members it held go with it.
    pub(super) fn take_outcome<C: ClockSource + 'static>(
        &mut self,
        local: &CoopLocalSet<C>,
    ) -> Option<MulticastOutcome> {
        if !self.task.as_ref()?.is_finished() {
            return None;
        }
        let task = self.task.take()?;
        // The members go with the group's link, and a watcher of the faces is told each went.
        let gone = core::mem::take(&mut *self.members.borrow_mut());
        #[cfg(feature = "connectivity")]
        for member in &gone {
            self.events.tell(FaceEventKind::Down, member);
        }
        #[cfg(not(feature = "connectivity"))]
        drop(gone);
        // A finished task's output is taken without stepping anything.
        local.block_on_local(task).ok()
    }

    /// Join the group again at `at_us`, on the session's clock.
    pub(super) fn wait_to_rejoin(&mut self, at_us: u64) {
        self.rejoin_at_us = Some(at_us);
    }

    /// Whether the group waits to be joined again and its time has come.
    pub(super) fn rejoin_due(&self, now_us: u64) -> bool {
        self.rejoin_at_us.is_some_and(|at_us| now_us >= at_us)
    }

    /// Whether the group's task took a datagram since this was last asked.
    pub(super) fn took_input(&self) -> bool {
        self.took.replace(false)
    }

    /// Ask the group's session to stop: at its next step it tells the group it leaves and lets
    /// the group's link go.
    pub(super) fn stop(&self) {
        self.stop.set(true);
    }

    /// The zid of each member the group holds, whatever role it announced; a group whose session
    /// ended holds none.
    pub(super) fn member_zids(&self) -> Vec<Vec<u8>> {
        if self.has_ended() {
            return Vec::new();
        }
        self.members
            .borrow()
            .iter()
            .map(|member| member.peer.as_slice().to_vec())
            .collect()
    }

    /// The members the group holds, each as the transport it is reported as (`connectivity`); a
    /// group whose session ended holds none.
    #[cfg(feature = "connectivity")]
    pub(super) fn member_snapshots(&self) -> Vec<FaceSnapshot> {
        if self.has_ended() {
            return Vec::new();
        }
        self.members
            .borrow()
            .iter()
            .filter_map(|member| self.events.label.snapshot(member))
            .collect()
    }

    /// Tell the group of `entity`, which the session declared, as the group's declarations say
    /// (the port's rules: `GroupDeclarations::announced_id`, `key`, `retraction_key`, the tokio
    /// engine's groups' too), the `Declare` built by the session core's builder
    /// (`build_group_announcement`) and queued for the group's task. What a later retraction
    /// names is kept when the group is told retractions. Best effort, as a put on the group is:
    /// a key past the codec's bound is announced nowhere, and a group whose session ended is told
    /// nothing.
    pub(super) fn announce(&self, entity: GroupEntity<'_>) {
        if self.has_ended() {
            return;
        }
        let told = self.join.declarations;
        let Some(id) = told.announced_id(entity.what, entity.entity, entity.allowed_origin) else {
            return;
        };
        if let Ok(declare) =
            build_group_announcement(entity.what, id, told.key(entity.keyexpr, entity.wire))
        {
            self.tx.enqueue(MulticastTxItem::Declare {
                declare: alloc::boxed::Box::new(declare),
            });
        }
        if told.retracts() {
            let key = told.retraction_key(entity.keyexpr, entity.wire, entity.retraction);
            self.announced.borrow_mut().push(Announced {
                entity: entity.entity,
                what: entity.what,
                id,
                mapping_id: key.mapping_id,
                suffix: key.suffix.map(String::from),
            });
        }
    }

    /// Tell the group that the entity `entity` it was told of is retracted
    /// (`build_group_retraction`); an entity it was not told of, or a group that is told no
    /// retraction, is told nothing.
    pub(super) fn retract(&self, entity: EntityId) {
        let announced = {
            let mut announced = self.announced.borrow_mut();
            let at = announced.iter().position(|told| told.entity == entity);
            at.map(|at| announced.remove(at))
        };
        let Some(announced) = announced else {
            return;
        };
        if self.has_ended() {
            return;
        }
        let key = GroupKey {
            mapping_id: announced.mapping_id,
            suffix: announced.suffix.as_deref(),
        };
        if let Ok(declare) = build_group_retraction(announced.what, announced.id, key) {
            self.tx.enqueue(MulticastTxItem::Declare {
                declare: alloc::boxed::Box::new(declare),
            });
        }
    }

    /// Ask the group for its members' liveliness tokens on the key of the liveliness subscriber
    /// `id` (the Interest is the subscriber's, by its id): the ones to come, and with `history`
    /// the ones alive now. Asked when the group's declarations say so
    /// (`GroupDeclarations::asks_for_liveliness`), as the tokio engine's group asks: zenoh-pico
    /// sends the subscriber's `Interest` over whatever transport it holds (`liveliness`).
    #[cfg(feature = "liveliness")]
    pub(super) fn ask_liveliness(
        &self,
        id: EntityId,
        keyexpr: &str,
        wire: &WireKey,
        history: bool,
    ) {
        let told = self.join.declarations;
        if self.has_ended() || !told.asks_for_liveliness() {
            return;
        }
        let key = told.key(keyexpr, wire);
        if let Ok(interest) = build_interest_exact(
            u64::from(id),
            InterestKinds::TOKENS,
            history,
            /*future=*/ true,
            Some((key.mapping_id, key.suffix)),
        ) {
            self.tx.enqueue(MulticastTxItem::Interest {
                interest: alloc::boxed::Box::new(interest),
            });
        }
    }

    /// End on the group the Interest [`Self::ask_liveliness`] asked for the liveliness subscriber
    /// `id`: its `Interest(Final)`, as zenoh-pico sends one when it undeclares the subscriber
    /// (`liveliness`).
    #[cfg(feature = "liveliness")]
    pub(super) fn end_liveliness_ask(&self, id: EntityId) {
        if self.has_ended() || !self.join.declarations.asks_for_liveliness() {
            return;
        }
        self.tx.enqueue(MulticastTxItem::Interest {
            interest: alloc::boxed::Box::new(build_interest_final(u64::from(id))),
        });
    }

    /// Put a publication on the group, naming its key in full: the group is told no keyexpr the
    /// session declares unless its declarations say so (`GroupDeclarations::declares_keyexprs`),
    /// which a group whose session tells it its entities, or less, does not. Built by the session
    /// core's Push builders, as a link's is, and framed by the group's task with the sequence
    /// number of its channel. A group whose session ended is sent nothing.
    pub(super) fn publish(&self, put: GroupPut<'_>) -> Result<usize, FanoutError> {
        if self.has_ended() {
            return Ok(0);
        }
        let push = match put.kind {
            SampleKind::Put => {
                push_build::build_push_literal_with_meta(put.keyexpr, put.payload, put.meta)
            }
            SampleKind::Del => push_build::build_push_del_literal_with_meta(put.keyexpr, put.meta),
        }
        .map_err(|_| FanoutError::ExceedsCapacity)?;
        self.tx.enqueue(MulticastTxItem::Push {
            push: alloc::boxed::Box::new(push),
            reliable: put.reliable,
            priority: put.priority,
        });
        Ok(0)
    }
}

/// The `on_event` of a group's session: the members its JOINs admit and the ones it loses are
/// noted, each told to the session's watchers of its faces (`connectivity`), and then the event
/// goes through `dispatch` with the sink the group's replies are queued on.
fn noting_members<D>(
    members: Rc<RefCell<Vec<MulticastMember>>>,
    replies: GroupReplies,
    mut dispatch: D,
    #[cfg(feature = "connectivity")] events: Rc<MemberEvents>,
) -> impl FnMut(IterationEvent<'_, '_>) + 'static
where
    D: FnMut(IterationEvent<'_, '_>, &GroupReplies) + 'static,
{
    move |event| {
        match &event {
            IterationEvent::MulticastPeerArrived(arrived) => {
                let member = MulticastMember {
                    peer: arrived.peer,
                    whatami: arrived.whatami,
                    locator: arrived.locator,
                };
                members.borrow_mut().push(member);
                #[cfg(feature = "connectivity")]
                events.tell(FaceEventKind::Up, &member);
            }
            IterationEvent::MulticastPeerLost(lost) => {
                let gone = {
                    let mut held = members.borrow_mut();
                    let at = held.iter().position(|member| member.peer == lost.peer);
                    at.map(|at| held.remove(at))
                };
                #[cfg(feature = "connectivity")]
                if let Some(member) = gone {
                    events.tell(FaceEventKind::Down, &member);
                }
                #[cfg(not(feature = "connectivity"))]
                let _ = gone;
            }
            _ => {}
        }
        dispatch(event, &replies);
    }
}

/// One entity the session declared, as a group is told of it: its kind, its entity id, the key
/// it is declared on and how that key is named to the peers, the key its retraction names, and
/// the traffic it takes.
#[derive(Clone, Copy)]
pub(super) struct GroupEntity<'a> {
    pub(super) what: GroupDeclaration,
    pub(super) entity: EntityId,
    pub(super) keyexpr: &'a str,
    pub(super) wire: &'a WireKey,
    pub(super) retraction: Option<&'a RetractionKey>,
    pub(super) allowed_origin: Locality,
}

/// An entity the group was told of, and what its retraction is told by: the id it was announced
/// under and the key its retraction names.
struct Announced {
    entity: EntityId,
    what: GroupDeclaration,
    id: u64,
    mapping_id: ExprId,
    suffix: Option<String>,
}

/// One publication the session puts on its groups.
pub(super) struct GroupPut<'a> {
    pub(super) keyexpr: &'a str,
    pub(super) payload: &'a [u8],
    pub(super) kind: SampleKind,
    pub(super) meta: &'a PushMetadata,
    pub(super) reliable: bool,
    pub(super) priority: Priority,
}

/// The dispatch of a group whose session answers queries outside its lock: the registry's, with
/// the `ResponseFinal`s it owes held for the queries a callback is still to answer, as a link's
/// is, and what it staged queued on the group. A member's query is held under the group's own
/// `generation`, so the answer it is owed is the group's and no link's.
#[cfg(feature = "queryable")]
pub(super) fn dispatch(
    registry: Rc<RefCell<Registry>>,
    face: FaceId,
    policy: SessionPolicy,
    plane: alloc::sync::Arc<super::query::QueryPlane>,
    generation: u64,
) -> impl FnMut(IterationEvent<'_, '_>, &GroupReplies) + 'static {
    use core::sync::atomic::Ordering;
    use wz_session_core::response_sink::ResponseSink;
    move |event, replies| {
        let mut registry = registry.borrow_mut();
        plane.arriving.store(generation, Ordering::Release);
        registry
            .app
            .set_unanswerable_final(policy.query_unanswerable_final());
        registry.dispatch_event(face, event);
        registry.flush_pending_replies(face, replies);
        for (rid, qos) in registry.take_pending_final_rids(face) {
            if super::lock(&plane.holds).owe(generation, rid, qos) {
                replies.send_response_final(rid, qos);
            }
        }
    }
}

/// The dispatch of a group whose session has no queryable: the registry's, with everything it
/// staged queued on the group at once.
#[cfg(not(feature = "queryable"))]
pub(super) fn dispatch(
    registry: Rc<RefCell<Registry>>,
    face: FaceId,
) -> impl FnMut(IterationEvent<'_, '_>, &GroupReplies) + 'static {
    move |event, replies| registry.borrow_mut().dispatch(face, event, replies)
}
