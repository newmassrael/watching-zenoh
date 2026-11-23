// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The multicast groups a session joins, each a face of the session beside its links.
//!
//! A group's session is the session shell's (`wz_session_mcu::group_drive`), the one an MCU image
//! runs, hosted as a task of the session's local set as each link's session is: its JOIN beacon,
//! the members it admits, its lease sweep and the per-member order of what they send are that
//! session's, and every rule they follow is the session core's (`multicast_dispatch`,
//! `multicast_rx`, `multicast_tx`). What the session sends on the group is written by the thread
//! that sends it, which holds the session, as zenoh-pico's put writes a multicast message on its
//! caller's thread: the group's transport is shared by its task and its face (`GroupLink`), and
//! the task writes only what is left to it, a datagram a full socket refused and the replies its
//! own dispatch staged. The dispatcher keeps each member's
//! declarations apart from the moment it is built (`MulticastConfig::of_group`, the config the
//! tokio engine's group face builds its dispatcher from too), since two members number their
//! entities alike.
//!
//! What this module adds is the hosting: the group's tables in the session's registry, where what
//! a member sends is dispatched as a peer's frames are; the stage the session pushes its own
//! messages onto, framed and numbered as the tokio engine's group producer pushes them, beside the
//! replies its dispatch stages, with its batch window; the members the group's JOINs
//! admitted; and the stop the session's close asks for, after which the task tells the group it
//! leaves.

use alloc::rc::Rc;
use core::cell::{Cell, RefCell};
use core::net::SocketAddr;

use alloc::sync::Arc;

use wz_capi_port::group::{GroupDeclarations, GroupJoin};
use wz_capi_port::{FanoutError, FilterId, FilterPlane, WireKey};
use wz_runtime_coop::executor::SpawnRefusal;
use wz_runtime_coop::group_transport::{GroupSend, GroupTransport};
use wz_runtime_coop::session_drive::{LinkReadiness, LinkWritability};
use wz_runtime_coop::{ClockSource, CoopLocalJoinHandle, CoopLocalSet};
use wz_session_core::declare_build::{
    build_declare_kexpr, build_group_announcement, build_group_retraction, build_undeclare_kexpr,
};
use wz_session_core::declare_form::{GroupDeclaration, GroupKey, RetractionKey};
use wz_session_core::driver_loop::IterationEvent;
use wz_session_core::interest_build::{build_interest_exact, build_interest_final, InterestKinds};
use wz_session_core::limits::SessionLimits;
use wz_session_core::locality::Locality;
use wz_session_core::metadata::PushMetadata;
use wz_session_core::multicast_dispatch::MulticastConfig;
use wz_session_core::multicast_dispatch::MulticastMember;
use wz_session_core::multicast_params::{MulticastOutcome, MulticastParams};
use wz_session_core::multicast_reply_sink::{
    asks_for_declarations, GroupKeyexprAnswers, MulticastReplyEnqueue, MulticastReplySink,
};
use wz_session_core::multicast_tx::MulticastTxItem;
use wz_session_core::policy::SessionPolicy;
use wz_session_core::push_build;
use wz_session_core::qos::Priority;
use wz_session_core::sample::SampleKind;
use wz_session_core::tx_deadline::PushOutcome;
use wz_session_core::wire_id::{EntityId, ExprId};
use wz_session_mcu::group_drive::{
    try_spawn_multicast_session_seeded, GroupDue, GroupInputGate, GroupLink, GroupTxPace,
    GroupTxStage, JoinAsk, MulticastSessionSeed,
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

/// The tick of a group's lease sweep, in milliseconds, which its task is due on while it holds a
/// member (and while its socket holds back a datagram), and the longest a read waits for a group
/// whose stack gives no wait for its input: the tick of the tokio engine's group face, shorter
/// than any beacon interval an ABI advertises.
pub(super) const GROUP_TICK_MS: u32 = 50;

/// What a group's dispatch hands what it staged to: the group's stage, which its task writes.
pub(super) type GroupReplies = MulticastReplySink<GroupTxStage>;

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

    fn try_send_to_group(&mut self, datagram: &[u8]) -> GroupSend {
        self.inner.try_send_to_group(datagram)
    }

    fn wait_for_room(&self, timeout_us: u64) -> bool {
        self.inner.wait_for_room(timeout_us)
    }

    fn writability(&self) -> Option<alloc::boxed::Box<dyn LinkWritability>> {
        self.inner.writability()
    }

    fn readiness(&self) -> Option<alloc::boxed::Box<dyn LinkReadiness>> {
        self.inner.readiness()
    }

    fn recv_with(&mut self, f: &mut dyn FnMut(&[u8], SocketAddr)) -> bool {
        let took = self.inner.recv_with(f);
        if took {
            self.took.set(true);
        }
        took
    }

    fn keeps_input(&self) -> bool {
        self.inner.keeps_input()
    }

    fn keep(&mut self) {
        self.inner.keep();
    }
}

/// What a message of the session waits with when the group's stage has no room for it: a pass of
/// the session's tasks, in which the group's own task writes what the group's socket takes, and
/// the session's clock, which the wait is spent on.
pub(super) trait Pace {
    /// One pass of the session's tasks.
    fn pass(&self);
    /// The session's clock, in microseconds.
    fn now_us(&self) -> u64;
}

/// The session's own tasks and clock, as a group's waits use them.
pub(super) struct SessionPace<C: ClockSource> {
    pub(super) local: CoopLocalSet<C>,
    pub(super) clock: C,
}

impl<C: ClockSource> Pace for SessionPace<C> {
    fn pass(&self) {
        self.local.run_until_idle();
    }

    fn now_us(&self) -> u64 {
        self.clock.now_us()
    }
}

/// What a group is joined with: the face its tables are in, the group as the ABI stated it (where
/// it is, what the session advertises and tells it), the stack's transport, the parameters its
/// session runs with, and what the session's messages wait with on a full queue.
pub(super) struct GroupJoining {
    pub(super) id: FaceId,
    pub(super) join: GroupJoin,
    pub(super) transport: alloc::boxed::Box<dyn GroupTransport>,
    /// Whether the session has room for what the group delivers: the delivery lane's room for one
    /// record of the group's batch.
    pub(super) input_gate: GroupInputGate,
    pub(super) params: MulticastParams,
    pub(super) policy: SessionPolicy,
    /// The session limits the session's open resolved: the group's replies are held to them.
    pub(super) limits: SessionLimits,
    pub(super) pace: Rc<dyn Pace>,
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
    /// The group's stage, which the session's messages and the group's replies are pushed onto,
    /// framed and numbered, and which the face writes after each push and its task at each step.
    tx: GroupTxStage,
    /// The group's transport, which the task opens, reads and lets go of, and which the face
    /// writes the stage on ([`Self::write_staged`]).
    link: GroupLink<Watched>,
    /// What a message of the session waits with on a full lane ([`Self::push`]).
    pace: Rc<dyn Pace>,
    /// The group socket's wait for room, asked from outside its task; `None` for a stack that
    /// gives none.
    room: Option<Arc<dyn LinkWritability>>,
    /// The group socket's wait for input, which a read waits on beside the session's links;
    /// `None` for a stack that gives none, whose group is looked at on its tick.
    input: Option<Arc<dyn LinkReadiness>>,
    /// When the group's session is next due with nothing arriving on it, as its last step said.
    due: GroupDue,
    members: Rc<RefCell<Vec<MulticastMember>>>,
    took: Rc<Cell<bool>>,
    stop: Rc<Cell<bool>>,
    /// The JOIN the session asks of the group between two beacons ([`Self::ask_join`]).
    join_ask: JoinAsk,
    /// The keyexprs this join of the group was told, and the members' asks for them the session
    /// owes an answer ([`GroupKeyexprAnswers`]).
    keyexprs: Rc<RefCell<GroupKeyexprAnswers>>,
    /// Whether this join is still to ask the group for its members' keyexprs
    /// ([`Self::owes_keyexpr_ask`]).
    keyexpr_ask_owed: Cell<bool>,
    /// The write filters that asked this join of the group, each by the interest id it asked by.
    filters: RefCell<Vec<(FilterId, u64)>>,
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
    /// transport as the session's link at its first step, which the caller runs. `Err` when the
    /// session's runtime has no cell for the task (its tables are reserved when the session
    /// opens), the transport let go of with what the task was to be made of.
    pub(super) fn join<C, D>(
        local: &CoopLocalSet<C>,
        joining: GroupJoining,
        dispatch: D,
    ) -> Result<Self, SpawnRefusal>
    where
        C: ClockSource + 'static,
        D: FnMut(IterationEvent<'_, '_>, &GroupReplies) + 'static,
    {
        let GroupJoining {
            id,
            join,
            transport,
            input_gate,
            params,
            policy,
            limits,
            pace,
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
        // Bounded as the tokio engine bounds its group's pipeline: the queue's sizes, in batches
        // of the group's batch, one lane when it runs no QoS. The replies it holds are bounded by
        // the session's limits.
        let tx = GroupTxStage::with_limits(&params, &limits);
        let room = transport.writability().map(Arc::from);
        let input = transport.readiness().map(Arc::from);
        let due = GroupDue::default();
        let members: Rc<RefCell<Vec<MulticastMember>>> = Rc::new(RefCell::new(Vec::new()));
        let took = Rc::new(Cell::new(false));
        let stop = Rc::new(Cell::new(false));
        let join_ask = JoinAsk::default();
        // The session core's config for a group, the tokio engine's group face's too, with each
        // member's declarations kept apart: the group's events feed one session's tables.
        let config = MulticastConfig::of_group(&params, true);
        // Shared by the task, which opens it as the session's link, and the face, which writes on
        // it what the session pushes.
        let link = GroupLink::new(Watched {
            inner: transport,
            took: Rc::clone(&took),
        });
        let seed = MulticastSessionSeed::<GroupLink<Watched>, GROUP_MEMBERS>::new(
            config,
            link.clone(),
            params,
            policy,
            u64::from(GROUP_TICK_MS),
        )
        .with_join_ask(join_ask.clone())
        .with_tx_stage(tx.clone())
        .with_due(due.clone())
        .with_input_gate(input_gate);
        let keyexprs = Rc::new(RefCell::new(GroupKeyexprAnswers::default()));
        let on_event = answering_asks(
            noting_members(
                Rc::clone(&members),
                MulticastReplySink::new(tx.clone()),
                dispatch,
                #[cfg(feature = "connectivity")]
                Rc::clone(&events),
            ),
            Rc::clone(&keyexprs),
            join_ask.clone(),
            tx.clone(),
        );
        let keyexpr_ask_owed = Cell::new(join.declarations.declares_keyexprs());
        let should_stop = {
            let stop = Rc::clone(&stop);
            move || stop.get()
        };
        // Everything the group sends is pushed onto its stage, which the face and the task write
        // from: the task's pull seam yields nothing.
        let task = try_spawn_multicast_session_seeded(local, seed, on_event, || None, should_stop)?;
        Ok(Self {
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
            link,
            pace,
            room,
            input,
            due,
            members,
            took,
            stop,
            join_ask,
            keyexprs,
            keyexpr_ask_owed,
            filters: RefCell::new(Vec::new()),
            announced: RefCell::new(Vec::new()),
            #[cfg(feature = "connectivity")]
            events,
        })
    }

    /// Push `item`, a message of the session, onto the group's stage as the tokio engine's group
    /// producer pushes it (`MulticastTxProducer::push`), through the same session core walk
    /// (`multicast_tx_push`, [`GroupTxStage::push`]): its lane is asked for room before its
    /// sequence number is minted and again before each further fragment, within the message's
    /// `wait_before_drop` when it may be dropped and its `wait_before_close` when it may not; while
    /// the lane is full, the session's tasks are run, in which the group's own writes what its
    /// socket takes, and the socket is waited on for room. A message that finds none is a
    /// congestion drop, counted on its lane, blocking or not, and a chain that runs out of room
    /// between two fragments is stopped by the drop marker: a multicast transport closes nothing on
    /// one, where a unicast one closes its link
    /// (`io/zenoh-transport/src/multicast/tx.rs` @ `fn schedule_on_link(&self, msg: NetworkMessageRef) -> ZResult<bool> {`).
    /// What is pushed while the group's session ends is lost with its link.
    ///
    /// The face writes what the push put on the stage on the caller's thread, before this returns,
    /// as zenoh-pico's put writes it (`vendor/zenoh-pico/src/transport/common/tx.c` @
    /// `static z_result_t _z_transport_tx_send_n_msg_inner(`); a batch window that holds the
    /// message puts nothing on a lane, and its flush writes it.
    fn push(&self, item: MulticastTxItem) -> PushOutcome {
        let outcome = self.tx.push(item, self);
        self.write_staged();
        outcome
    }

    /// Write what the group's stage holds on the group's socket, on this thread, until the stage
    /// is empty or the socket has no room; what it refuses is offered again first at the next
    /// write, the face's or the task's. Whatever the session puts on the stage outside the group's
    /// own step is written so, by the thread that put it: a read already waiting on the group's
    /// socket is not woken by a push, and would hold it until that wait ends.
    pub(super) fn write_staged(&self) {
        self.link.write_staged(&self.tx);
    }

    /// Open the group's batch window (zenoh-pico `zp_batch_start` on its multicast transport):
    /// whether it was opened, which it is not on a group whose session ended.
    pub(super) fn batch_start(&self) -> bool {
        if self.has_ended() {
            return false;
        }
        self.tx.batch_start();
        true
    }

    /// Write what the group's batch window holds and keep it open (zenoh-pico `zp_batch_flush`):
    /// whether the group was flushed, which one whose session ended is not.
    pub(super) fn batch_flush(&self) -> bool {
        if self.has_ended() {
            return false;
        }
        self.tx.batch_flush();
        self.write_staged();
        true
    }

    /// Close the group's batch window and write what it held (zenoh-pico `zp_batch_stop`):
    /// whether the group was stopped, which one whose session ended is not.
    pub(super) fn batch_stop(&self) -> bool {
        if self.has_ended() {
            return false;
        }
        self.tx.batch_stop();
        self.write_staged();
        true
    }

    /// The group socket's wait for room, which a message of the session that finds the session
    /// held asks as it asks a link's.
    pub(super) fn room(&self) -> Option<&Arc<dyn LinkWritability>> {
        self.room.as_ref()
    }

    /// How many messages of `priority` the session put on the group were dropped for want of room.
    /// Read only by `CoopEngine::group_congestion_drops`, and compiled where it is.
    #[cfg(all(test, feature = "app-transport"))]
    pub(super) fn congestion_drops(&self, priority: Priority) -> u32 {
        self.tx.drops(priority)
    }

    /// How many messages the group dropped before they reached its socket (`transport-stats`):
    /// the session's own, of every priority, that found no room on their lane, and the replies its
    /// dispatch staged past the reply limit (`GroupTxStage::dropped`), as the tokio engine's
    /// group counts every message it drops, a reply among them, as the transport's.
    #[cfg(feature = "transport-stats")]
    pub(super) fn drops_total(&self) -> u32 {
        (0..Priority::NUM)
            .map(|at| self.tx.drops(Priority::from_wire(at as u8)))
            .fold(self.tx.dropped(), u32::saturating_add)
    }

    /// The group's stage, as its dispatch stages a reply on it. Read only by
    /// `CoopEngine::stage_group_replies`, and compiled where it is.
    #[cfg(all(test, feature = "app-transport", feature = "transport-stats"))]
    pub(super) fn reply_stage(&self) -> &GroupTxStage {
        &self.tx
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

    /// The sink a member's query is answered through: the group's stage (`queryable`). An answer
    /// made outside the group's step is written after it by the answering thread
    /// (`Self::write_staged`).
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

    /// Ask the group the query `rid` on `keyexpr`, named to the peers as `wire`, with the slots
    /// `meta` states. The key is named as a put on the group names it: by the declaration the
    /// group was told when it is told the session's keyexprs, and in full otherwise
    /// (`GroupDeclarations::key`). Built by the session core's request builder, as a link's
    /// query is, and sent reliably on the group, as zenoh-pico sends one on its multicast
    /// transport. `false` when the query cannot be built, and nothing is pushed.
    #[cfg(feature = "query")]
    pub(super) fn ask(
        &self,
        rid: RequestId,
        keyexpr: &str,
        wire: &WireKey,
        meta: &QueryMetadata,
    ) -> bool {
        let key = self.join.declarations.key(keyexpr, wire);
        match build_request_query_with_meta(rid, key.mapping_id, key.suffix, meta) {
            Ok(request) => {
                self.push(MulticastTxItem::Request {
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

    /// The wait for the group socket's next datagram, while the group's session runs and its stack
    /// gives one.
    pub(super) fn input(&self) -> Option<&Arc<dyn LinkReadiness>> {
        if self.has_ended() {
            return None;
        }
        self.input.as_ref()
    }

    /// Whether the group's session runs over a stack that gives no wait for its input, so that it
    /// is looked at on its tick.
    pub(super) fn unwaited(&self) -> bool {
        !self.has_ended() && self.input.is_none()
    }

    /// When the group must next be looked at, on the session's clock in microseconds, with nothing
    /// arriving on it: its session's next beacon or sweep, as its last step said, or at once when
    /// it has not stepped yet, when it ended and its end is still to be read, or when its stage
    /// holds what its socket has room for (a reply its dispatch staged); no later than its tick
    /// while the socket holds a datagram back, whichever write it refused, as the task's own sweep
    /// tick offers it again; once its end was read, when it is joined again. `None`: nothing is
    /// due.
    pub(super) fn due_us(&self) -> Option<u64> {
        match &self.task {
            Some(task) if task.is_finished() => Some(0),
            Some(_) if self.tx.holds() => {
                let tick_us = self
                    .pace
                    .now_us()
                    .saturating_add(u64::from(GROUP_TICK_MS) * 1_000);
                Some(self.due.due_us().map_or(0, |due_us| due_us.min(tick_us)))
            }
            Some(_) if !self.tx.is_empty() => Some(0),
            Some(_) => Some(self.due.due_us().unwrap_or(0)),
            None => self.rejoin_at_us,
        }
    }

    /// Ask the group's session to stop: at its next step it tells the group it leaves and lets
    /// the group's link go.
    pub(super) fn stop(&self) {
        self.stop.set(true);
    }

    /// The first member at or past place `from` of the group's member table, whatever role it
    /// announced, with its place; a group whose session ended holds none.
    pub(super) fn member_zid_from(
        &self,
        from: usize,
    ) -> Option<(usize, wz_session_core::session_zid::SessionZid)> {
        if self.has_ended() {
            return None;
        }
        self.members
            .borrow()
            .iter()
            .enumerate()
            .skip(from)
            .find_map(|(at, member)| {
                Some((
                    at,
                    wz_session_core::session_zid::SessionZid::new(member.peer.as_slice()).ok()?,
                ))
            })
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
    /// (`build_group_announcement`) and pushed onto the group's stage. What a later retraction
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
            self.push(MulticastTxItem::Declare {
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
            self.push(MulticastTxItem::Declare {
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
            self.push(MulticastTxItem::Interest {
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
        self.push(MulticastTxItem::Interest {
            interest: alloc::boxed::Box::new(build_interest_final(u64::from(id))),
        });
    }

    /// Tell the group the keyexpr the session declared as `id`, when it is told the session's
    /// keyexprs (`GroupDeclarations::declares_keyexprs`), as the tokio engine's group is told it,
    /// and hold it for the members that ask for it.
    pub(super) fn announce_keyexpr(&self, id: ExprId, keyexpr: &str) {
        if id == 0 || self.has_ended() || !self.join.declarations.declares_keyexprs() {
            return;
        }
        if let Ok(declare) = build_declare_kexpr(id, keyexpr) {
            self.keyexprs.borrow_mut().declared(id, keyexpr);
            self.push(MulticastTxItem::Declare {
                declare: alloc::boxed::Box::new(declare),
            });
        }
    }

    /// Retract from the group the keyexpr [`Self::announce_keyexpr`] told it as `id`.
    pub(super) fn retract_keyexpr(&self, id: ExprId) {
        if self.has_ended() || !self.join.declarations.declares_keyexprs() {
            return;
        }
        self.keyexprs.borrow_mut().retracted(id);
        self.push(MulticastTxItem::Declare {
            declare: alloc::boxed::Box::new(build_undeclare_kexpr(id)),
        });
    }

    /// Whether this join is still to ask the group for its members' keyexprs, which it is once,
    /// when it comes up, when the group is told the session's keyexprs; the look answers it.
    pub(super) fn owes_keyexpr_ask(&self) -> bool {
        self.keyexpr_ask_owed.replace(false) && !self.has_ended()
    }

    /// Ask the group for its members' keyexprs, the ones held now, by `interest_id`, as
    /// zenoh-pico asks when it opens its multicast transport
    /// (`vendor/zenoh-pico/src/session/interest.c` @
    /// `z_result_t _z_interest_pull_resource_from_peers(_z_session_t *zn) {`).
    pub(super) fn ask_keyexprs(&self, interest_id: u64) {
        if let Ok(interest) = build_interest_exact(
            interest_id,
            InterestKinds::KEYEXPRS,
            /*current=*/ true,
            /*future=*/ false,
            None,
        ) {
            self.push(MulticastTxItem::Interest {
                interest: alloc::boxed::Box::new(interest),
            });
        }
    }

    /// Ask the group for its members' declarations on `plane` and `keyexpr` (named as the group
    /// was told it, `wire`) for the write filter `filter`, by `interest_id`, when a write filter
    /// asks it (`GroupDeclarations::asks_for_filters`): the current ones and the kind alone, as a
    /// zenoh-pico peer puts its filter's Interest on its multicast transport
    /// (`vendor/zenoh-pico/src/net/filtering.c` @
    /// `uint8_t flags = interest_flag | _Z_INTEREST_FLAG_RESTRICTED | _Z_INTEREST_FLAG_CURRENT;`).
    /// The group keeps the id for [`Self::end_filter`].
    pub(super) fn ask_filter(
        &self,
        filter: FilterId,
        interest_id: u64,
        plane: FilterPlane,
        keyexpr: &str,
        wire: &WireKey,
    ) {
        let told = self.join.declarations;
        if self.has_ended() || !told.asks_for_filters() {
            return;
        }
        let kinds = match plane {
            FilterPlane::Subscribers => InterestKinds::SUBSCRIBERS,
            FilterPlane::Queryables { .. } => InterestKinds::QUERYABLES,
        };
        let key = told.key(keyexpr, wire);
        if let Ok(interest) = build_interest_exact(
            interest_id,
            kinds,
            /*current=*/ true,
            /*future=*/ false,
            Some((key.mapping_id, key.suffix)),
        ) {
            self.push(MulticastTxItem::Interest {
                interest: alloc::boxed::Box::new(interest),
            });
            self.filters.borrow_mut().push((filter, interest_id));
        }
    }

    /// End on the group the Interest write filter `filter` asked it by: its `Interest(Final)`.
    pub(super) fn end_filter(&self, filter: FilterId) {
        let asked = {
            let mut filters = self.filters.borrow_mut();
            let at = filters.iter().position(|(asked, _)| *asked == filter);
            at.map(|at| filters.remove(at).1)
        };
        if let (Some(interest_id), false) = (asked, self.has_ended()) {
            self.push(MulticastTxItem::Interest {
                interest: alloc::boxed::Box::new(build_interest_final(interest_id)),
            });
        }
    }

    /// Put a publication on the group, naming its key by the declaration the group was told when
    /// it is told the session's keyexprs (`GroupDeclarations::declares_keyexprs`), and in full
    /// otherwise, as a group whose session tells it its entities, or less, is. Built by the session
    /// core's Push builders, as a link's is, framed with the sequence number of its channel as it
    /// is pushed onto the group's stage, and written by this call ([`Self::push`]). A group whose
    /// session ended is sent nothing.
    pub(super) fn publish(&self, put: GroupPut<'_>) -> Result<usize, FanoutError> {
        if self.has_ended() {
            return Ok(0);
        }
        // A group told the session's keyexprs is sent the key by its declaration, as the tokio
        // engine's group is; any other by its literal.
        let key = self.join.declarations.key(put.keyexpr, put.wire);
        let push = match (put.kind, key.mapping_id) {
            (SampleKind::Put, 0) => {
                push_build::build_push_literal_with_meta(put.keyexpr, put.payload, put.meta)
            }
            (SampleKind::Del, 0) => {
                push_build::build_push_del_literal_with_meta(put.keyexpr, put.meta)
            }
            (SampleKind::Put, mapping_id) => push_build::build_push_aliased_with_meta(
                mapping_id,
                key.suffix,
                put.payload,
                put.meta,
            ),
            (SampleKind::Del, mapping_id) => {
                push_build::build_push_del_aliased_with_meta(mapping_id, key.suffix, put.meta)
            }
        }
        .map_err(|_| FanoutError::ExceedsCapacity)?;
        self.push(MulticastTxItem::Push {
            push: alloc::boxed::Box::new(push),
            reliable: put.reliable,
            priority: put.priority,
        });
        Ok(0)
    }
}

/// A message of the session that waits for room on the group's stage writes what the group's
/// socket takes, runs the session's tasks, waits on the group's socket, and spends the session's
/// clock; a group whose session ended has nothing to wait for.
impl GroupTxPace for GroupFace {
    fn pass(&self) {
        self.write_staged();
        self.pace.pass();
    }

    fn now_us(&self) -> u64 {
        self.pace.now_us()
    }

    fn wait_writable(&self, wait_us: u64) -> bool {
        match &self.room {
            Some(room) => room.wait_writable(wait_us),
            None => true,
        }
    }

    fn ended(&self) -> bool {
        self.has_ended()
    }
}

/// The `on_event` of a group's session, around `inner`: a member's interest in what is declared
/// now asks the group for a JOIN first, as zenoh-pico pushes one (`asks_for_declarations`), and a
/// member's ask for the session's keyexprs is answered ahead of the session's other declarations
/// (`GroupKeyexprAnswers`), as the tokio engine's group answers both.
fn answering_asks<E>(
    mut inner: E,
    keyexprs: Rc<RefCell<GroupKeyexprAnswers>>,
    join_ask: JoinAsk,
    tx: GroupTxStage,
) -> impl FnMut(IterationEvent<'_, '_>) + 'static
where
    E: FnMut(IterationEvent<'_, '_>) + 'static,
{
    move |event| {
        if asks_for_declarations(&event) {
            // What is queued below, and what the dispatch queues, leaves after the JOIN the
            // group's next step sends: a step sends its beacon before what is queued.
            join_ask.ask();
            let answers = {
                let mut keyexprs = keyexprs.borrow_mut();
                keyexprs.asked(&event);
                keyexprs.take_answers()
            };
            for item in answers {
                tx.enqueue(item);
            }
        }
        inner(event);
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
    /// How the session's peers were told the key, which a group told the session's keyexprs is
    /// told it by too.
    pub(super) wire: &'a WireKey,
    pub(super) payload: &'a [u8],
    pub(super) kind: SampleKind,
    pub(super) meta: &'a PushMetadata<'a>,
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
