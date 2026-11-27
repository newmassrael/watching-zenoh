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

use wz_capi_port::group::{GroupDeclarations, GroupJoin};
use wz_capi_port::{FanoutError, FilterId, FilterPlane, WireKey};
#[cfg(wz_round)]
use wz_runtime_coop::executor::SpawnRefusal;
#[cfg(not(wz_round))]
use wz_runtime_coop::group_transport::GroupReceive;
use wz_runtime_coop::group_transport::{GroupSend, GroupTransport};
use wz_runtime_coop::session_drive::{LinkWait, LinkWaits, WaitOn};
use wz_runtime_coop::transport::GroupRecord;
use wz_runtime_coop::ClockSource;
#[cfg(not(wz_round))]
use wz_runtime_coop::CoopRuntime;
#[cfg(wz_round)]
use wz_runtime_coop::{CoopLocalJoinHandle, CoopLocalSet};
use wz_session_core::bounded::{BoundedVec, Static};
use wz_session_core::caps;
use wz_session_core::declare_form::{GroupDeclaration, GroupKey, RetractionKey};
use wz_session_core::driver_loop::IterationEvent;
use wz_session_core::interest_build::InterestKinds;
use wz_session_core::lent_control::{
    interest_exact, interest_final, kexpr_declaration, undeclare_kexpr_declaration,
};
use wz_session_core::limits::SessionLimits;
use wz_session_core::locality::Locality;
use wz_session_core::metadata::PushMetadata;
use wz_session_core::multicast_dispatch::MulticastConfig;
use wz_session_core::multicast_dispatch::MulticastMember;
use wz_session_core::multicast_params::{MulticastOutcome, MulticastParams};
use wz_session_core::multicast_peer_lost::MulticastPeerId;
use wz_session_core::multicast_reply_sink::{
    asks_for_declarations, GroupKeyexprAnswers, MulticastReplyEnqueue, MulticastReplySink,
};
use wz_session_core::multicast_tx::{
    multicast_tx_declaration, multicast_tx_group_announcement, multicast_tx_group_retraction,
    multicast_tx_interest, multicast_tx_publication, MulticastTxEncoded,
};
#[cfg(any(wz_round, feature = "connectivity", feature = "queryable"))]
use wz_session_core::placed::PlacedRef;
use wz_session_core::policy::SessionPolicy;
use wz_session_core::qos::Priority;
#[cfg(feature = "queryable")]
use wz_session_core::response_sink::ResponseSink;
use wz_session_core::sample::SampleKind;
use wz_session_core::session_tables::WireForm;
#[cfg(feature = "transport-stats")]
use wz_session_core::stats::TransportStats;
use wz_session_core::tx_deadline::PushOutcome;
use wz_session_core::wire_id::{EntityId, ExprId};
#[cfg(not(wz_round))]
use wz_session_mcu::group_drive::MulticastSessionPlace;

#[cfg(not(wz_round))]
use super::direct::FaceRecords;
#[cfg(wz_round)]
use wz_session_mcu::group_drive::{try_spawn_multicast_session_seeded, GroupInputGate};
use wz_session_mcu::group_drive::{
    GroupDue, GroupLink, GroupTxPace, GroupTxStage, JoinAsk, MulticastSessionSeed,
};
#[cfg(feature = "connectivity")]
use {
    super::FacePlane,
    wz_capi_port::told::{ToldBits, ToldKey, ToldPlane},
    wz_session_core::face::{FaceEventKind, FaceLinkRow, FaceSnapshot, GroupMemberLink},
};
#[cfg(feature = "query")]
use {
    wz_session_core::lent_request::RequestWriter,
    wz_session_core::multicast_tx::multicast_tx_request,
    wz_session_core::query_parts::{GetParts, QueryParts},
    wz_session_core::wire_id::RequestId,
};

#[allow(unused_imports)]
use crate::prelude::*;

use super::registry::{FaceId, HeldFace};
#[cfg(wz_round)]
use crate::round::Round;

/// The rows of each group's member table (`MAX_GROUP_MEMBERS`): a member whose JOIN finds them all
/// held is turned away, as a group whose `max_sessions` is reached turns one away. A table that
/// does not grow, so that what a group holds is what it was given when it was joined; the tokio
/// engine's group face starts from the same count of rows and grows past it, and zenoh-pico states
/// no cap.
pub(super) const GROUP_MEMBERS: usize = caps::MAX_GROUP_MEMBERS;

/// A member as a row of the group's member table holds it. With `connectivity`, the row notes the
/// connectivity listeners whose history is being replayed that were told the member stands, and a
/// member that went while one of them is still to be told so stays in its row, gone, as its tomb
/// (`wz_capi_port::told`).
#[derive(Clone, Copy)]
struct MemberRow {
    member: MulticastMember,
    #[cfg(feature = "connectivity")]
    told: ToldBits,
    #[cfg(feature = "connectivity")]
    gone: bool,
}

impl MemberRow {
    fn of(member: MulticastMember) -> Self {
        Self {
            member,
            #[cfg(feature = "connectivity")]
            told: ToldBits::default(),
            #[cfg(feature = "connectivity")]
            gone: false,
        }
    }

    /// Whether the member stands: a tomb is a member that went.
    fn stands(&self) -> bool {
        #[cfg(feature = "connectivity")]
        {
            !self.gone
        }
        #[cfg(not(feature = "connectivity"))]
        {
            true
        }
    }
}

/// The key a member's row is told under: its zid, as its row holds it, of a group's member.
#[cfg(feature = "connectivity")]
fn member_key(member: &MulticastMember) -> ToldKey {
    let mut zid = [0u8; 16];
    for (into, byte) in zid.iter_mut().zip(member.peer.as_slice()) {
        *into = *byte;
    }
    ToldKey {
        zid,
        is_multicast: true,
        link: 0,
    }
}

/// The members a group holds, in the order they came, in as many rows as its session's member
/// table: reserved when the group is joined, so a member that comes or goes allocates nothing and
/// a reader of the session's faces reads each member in place. A member's tomb holds its row until
/// the listeners it is owed to were told it went, or until a member the group admits finds no
/// other row: a member that stands comes before a departure owed.
struct MemberRows {
    /// The rows held, in the order their members came, and only those: a member's row is written
    /// when it comes, so a group joined writes no row.
    rows: BoundedVec<MemberRow, GROUP_MEMBERS, Static>,
}

impl MemberRows {
    const fn new() -> Self {
        Self {
            rows: BoundedVec::new_static(),
        }
    }

    /// Note `member`; `false` when every row is held by a member that stands.
    fn push(&mut self, member: MulticastMember) -> bool {
        // The oldest tomb is given up: its listeners are not told that member left.
        #[cfg(feature = "connectivity")]
        if self.rows.len() >= GROUP_MEMBERS {
            if let Some(at) = self.position(|row| row.gone) {
                self.drop_row(at);
            }
        }
        self.rows.push(MemberRow::of(member)).is_ok()
    }

    /// The member `peer` went: hand it back, its row let go of, the ones after it moving up a
    /// row, or kept as its tomb while a replaying listener told it stands is owed its departure.
    fn remove(&mut self, peer: &MulticastPeerId) -> Option<MulticastMember> {
        let at = self.position(|row| row.stands() && row.member.peer == *peer)?;
        let member = self.rows.get(at)?.member;
        #[cfg(feature = "connectivity")]
        if let Some(row) = self.rows.get_mut(at).filter(|row| !row.told.is_empty()) {
            row.gone = true;
            return Some(member);
        }
        self.drop_row(at);
        Some(member)
    }

    /// The place of the first row that `found` says is the one.
    fn position(&self, found: impl FnMut(&MemberRow) -> bool) -> Option<usize> {
        self.rows.iter().position(found)
    }

    /// Let go of the row at `at`, the ones after it moving up a row; nothing past the rows.
    fn drop_row(&mut self, at: usize) {
        if at < self.rows.len() {
            self.rows.remove(at);
        }
    }

    /// The members that stand, in the order they came.
    fn iter(&self) -> impl Iterator<Item = &MulticastMember> {
        self.rows
            .iter()
            .filter(|row| row.stands())
            .map(|row| &row.member)
    }

    #[cfg(feature = "query")]
    fn len(&self) -> usize {
        self.iter().count()
    }

    /// Note `listener` of `plane` told the member of `key` stands: whether it is to be told,
    /// `false` for a member of no known role (no row reports it) and one it was told already.
    #[cfg(feature = "connectivity")]
    fn came(&mut self, plane: ToldPlane, listener: usize, key: &ToldKey) -> bool {
        self.rows
            .iter_mut()
            .find(|row| {
                row.stands() && row.member.whatami.is_some() && member_key(&row.member) == *key
            })
            .is_some_and(|row| row.told.set(plane, listener))
    }

    /// Whether the tomb of the member of `key` owes `listener` of `plane` its departure.
    #[cfg(feature = "connectivity")]
    fn owes(&self, plane: ToldPlane, listener: usize, key: &ToldKey) -> bool {
        self.position(|row| {
            row.gone && member_key(&row.member) == *key && row.told.has(plane, listener)
        })
        .is_some()
    }

    /// Note `listener` of `plane` told the member of `key` went: whether a tomb owed it that.
    #[cfg(feature = "connectivity")]
    fn went(&mut self, plane: ToldPlane, listener: usize, key: &ToldKey) -> bool {
        let Some(at) = self.position(|row| {
            row.gone && member_key(&row.member) == *key && row.told.has(plane, listener)
        }) else {
            return false;
        };
        self.forget_at(at, plane, listener);
        true
    }

    /// The first member whose departure `listener` of `plane` is owed.
    #[cfg(feature = "connectivity")]
    fn first_gone(&self, plane: ToldPlane, listener: usize) -> Option<MulticastMember> {
        self.rows
            .iter()
            .find(|row| row.gone && row.told.has(plane, listener))
            .map(|row| row.member)
    }

    /// Note nothing more for `listener` of `plane`: a tomb owed only to it is let go of.
    #[cfg(feature = "connectivity")]
    fn forget(&mut self, plane: ToldPlane, listener: usize) {
        // From the last row, so a row let go of moves none still to be looked at.
        let mut at = self.rows.len();
        while let Some(before) = at.checked_sub(1) {
            at = before;
            self.forget_at(at, plane, listener);
        }
    }

    /// Take `listener` of `plane` off the row at `at`, let go of when it is a tomb owed to no one.
    #[cfg(feature = "connectivity")]
    fn forget_at(&mut self, at: usize, plane: ToldPlane, listener: usize) {
        let spent = self.rows.get_mut(at).is_some_and(|row| {
            row.told.clear(plane, listener);
            row.gone && row.told.is_empty()
        });
        if spent {
            self.drop_row(at);
        }
    }

    /// Keep, as tombs, the members of `ended` some replaying listener was told stand: the rows of
    /// a join that ended, its members gone with it, which this table takes over.
    #[cfg(feature = "connectivity")]
    fn keep_tombs_of(&mut self, ended: &Self) {
        for row in ended.rows.iter() {
            if row.told.is_empty() {
                continue;
            }
            if self.rows.push(MemberRow { gone: true, ..*row }).is_err() {
                return;
            }
        }
    }
}

impl Default for MemberRows {
    fn default() -> Self {
        Self::new()
    }
}

/// The tick of a group's lease sweep, in milliseconds, which its task is due on while it holds a
/// member (and while its socket holds back a datagram), and the longest a read waits for a group
/// whose stack gives no wait for its input: the tick of the tokio engine's group face, shorter
/// than any beacon interval an ABI advertises.
pub(super) const GROUP_TICK_MS: u32 = 50;
/// `GROUP_TICK_MS` on the session's clock, in microseconds: a product the build evaluates, so
/// one that did not fit a `u64` would not compile.
const GROUP_TICK_US: u64 = GROUP_TICK_MS as u64 * 1_000;

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

    /// `member` as a transport: the session core's snapshot of a group member, over the link its
    /// group is.
    fn snapshot(&self, member: &MulticastMember) -> Option<FaceSnapshot> {
        FaceSnapshot::of_group_member(
            member,
            GroupMemberLink::of_group(&self.group, member, &self.group, &self.endpoint),
            self.is_shm,
        )
    }
}

/// The face events a group's members are, for the session's watchers of its faces: a member the
/// group admits came up, and one it lost went down (`connectivity`).
#[cfg(feature = "connectivity")]
struct MemberEvents {
    watchers: PlacedRef<FacePlane>,
    label: GroupLabel,
}

#[cfg(feature = "connectivity")]
impl MemberEvents {
    fn tell(&self, kind: FaceEventKind, member: &MulticastMember) {
        if !self.watchers.watched() {
            return;
        }
        let label = &self.label;
        if let Some(row) =
            FaceLinkRow::of_group_member(member, &label.group, &label.endpoint, label.is_shm)
        {
            self.watchers.happened(kind, row);
        }
    }
}

/// The stack's group transport as the group's session holds it. Where the group's session is a
/// task (`wz_round`) it is marked each time it hands the task a datagram: the task takes one
/// datagram a step, as the group's loop always has, so a group that took one may hold more, and
/// the session's read steps it again at once rather than after a tick; a transport that leaves
/// what it lends where it lies until its next receive lends it to the session's round of
/// deliveries, whose records read it there, and the buffer it gives back as the group is left
/// goes back through the round ([`Round::keep_rx`]). Where the read steps the session itself,
/// the step says whether the socket may hold more (`GroupPump::step`), and the receive is the
/// stack's own.
struct Watched {
    inner: alloc::boxed::Box<dyn GroupTransport>,
    #[cfg(wz_round)]
    took: Rc<Cell<bool>>,
    /// The session's round of deliveries.
    #[cfg(wz_round)]
    lane: PlacedRef<Round>,
}

// A read that hands each record out as it is read leaves nothing in the buffer the transport
// gives back, which goes with the transport.
#[cfg(wz_round)]
impl Drop for Watched {
    fn drop(&mut self) {
        if let Some(buf) = self.inner.give_back_rx() {
            // SAFETY: the group's transport is let go of by the session's step, or by the engine's
            // drop, which holds the session's state alone, and nothing borrows the round's table.
            unsafe { self.lane.keep_rx(buf) };
        }
    }
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

    fn room_wait(&self) -> Option<WaitOn> {
        self.inner.room_wait()
    }

    fn input_wait(&self) -> Option<WaitOn> {
        self.inner.input_wait()
    }

    #[cfg(not(wz_round))]
    #[inline]
    fn recv_with(&mut self, f: &mut dyn FnMut(&[u8], SocketAddr)) -> bool {
        self.inner.recv_with(f)
    }

    #[cfg(wz_round)]
    fn recv_with(&mut self, f: &mut dyn FnMut(&[u8], SocketAddr)) -> bool {
        let took = if self.inner.lends_until_next_receive() {
            let lane = &self.lane;
            self.inner.recv_with(&mut |datagram, from| {
                // SAFETY: a group's transport is read by the session's step alone, under its lock,
                // and this one leaves the bytes where they lie until it is next asked to receive,
                // which the group's input gate holds back while a record lies in them
                // (`round::takes_a_group_read`).
                unsafe { lane.set_lending(Some(datagram)) };
                f(datagram, from);
                // SAFETY: as above.
                unsafe { lane.set_lending(None) };
            })
        } else {
            self.inner.recv_with(f)
        };
        if took {
            self.took.set(true);
        }
        took
    }

    fn lends_until_next_receive(&self) -> bool {
        self.inner.lends_until_next_receive()
    }

    fn keeps_input(&self) -> bool {
        self.inner.keeps_input()
    }

    fn keep(&mut self) {
        self.inner.keep();
    }

    fn frame_budget(&self) -> Option<u16> {
        self.inner.frame_budget()
    }
}

/// The group's transport as its session holds it.
#[cfg(wz_round)]
type SessionLink = GroupLink<Watched>;

/// The group's transport as its session holds it.
#[cfg(not(wz_round))]
type SessionLink = GroupSide;

/// The group's transport as its session holds it where the read steps the session itself: the
/// half that sends in the cell the group's face shares (`GroupLink`), which a publish on any
/// thread writes through, and the half that receives held by the session alone, which a receive
/// reads without reaching that cell. A transport whose halves are one receives through the cell.
#[cfg(not(wz_round))]
pub(super) struct GroupSide {
    link: GroupLink<Watched>,
    rx: ReceiveHalf,
}

/// The receive half of a group's transport, which its session reads and its read slot waits in
/// (`GroupPump::await_input`): both are stepped by the one thread that holds the slot.
#[cfg(not(wz_round))]
type ReceiveHalf = Rc<RefCell<alloc::boxed::Box<dyn GroupReceive>>>;

#[cfg(not(wz_round))]
impl GroupSide {
    /// The session's side of `link`, receiving through `rx`, the half split out of the
    /// transport, or through the cell where the transport split none.
    fn new(link: &GroupLink<Watched>, rx: Option<alloc::boxed::Box<dyn GroupReceive>>) -> Self {
        let rx = rx.unwrap_or_else(|| alloc::boxed::Box::new(ThroughCell(link.clone())));
        Self {
            link: link.clone(),
            rx: Rc::new(RefCell::new(rx)),
        }
    }
}

/// Whether a read may wait in the receive of `rx` (`GroupReceive::await_input`) for what it
/// would wait on as `wait`: the half's own input, on a half whose receive waits.
#[cfg(not(wz_round))]
fn awaits_on(rx: &dyn GroupReceive, wait: &LinkWait) -> bool {
    rx.awaits_input()
        && rx
            .input_wait()
            .is_some_and(|on| LinkWait::input(on) == *wait)
}

/// The receive of a transport whose halves are one: through the cell the face shares.
#[cfg(not(wz_round))]
struct ThroughCell(GroupLink<Watched>);

#[cfg(not(wz_round))]
impl GroupReceive for ThroughCell {
    fn recv_with(&mut self, f: &mut dyn FnMut(&[u8], SocketAddr)) -> bool {
        GroupTransport::recv_with(&mut self.0, f)
    }

    fn keeps_input(&self) -> bool {
        GroupTransport::keeps_input(&self.0)
    }

    fn keep(&mut self) {
        GroupTransport::keep(&mut self.0);
    }

    fn lends_until_next_receive(&self) -> bool {
        GroupTransport::lends_until_next_receive(&self.0)
    }

    fn input_wait(&self) -> Option<WaitOn> {
        GroupTransport::input_wait(&self.0)
    }

    // The cell's close closes the transport whole, and its carrier says whether it failed.
    fn close(&mut self) {}
}

#[cfg(not(wz_round))]
impl GroupTransport for GroupSide {
    fn open(&mut self) -> bool {
        self.link.open()
    }

    fn close(&mut self) {
        self.link.close();
        self.rx.borrow_mut().close();
    }

    fn service(&self) {
        self.link.service();
    }

    fn carrier_up(&self) -> bool {
        self.link.carrier_up() && !self.rx.borrow().failed()
    }

    fn send_to_group(&mut self, datagram: &[u8]) {
        self.link.send_to_group(datagram);
    }

    fn try_send_to_group(&mut self, datagram: &[u8]) -> GroupSend {
        self.link.try_send_to_group(datagram)
    }

    fn wait_for_room(&self, timeout_us: u64) -> bool {
        self.link.wait_for_room(timeout_us)
    }

    fn room_wait(&self) -> Option<WaitOn> {
        self.link.room_wait()
    }

    fn input_wait(&self) -> Option<WaitOn> {
        self.rx.borrow().input_wait()
    }

    #[inline]
    fn recv_with(&mut self, f: &mut dyn FnMut(&[u8], SocketAddr)) -> bool {
        self.rx.borrow_mut().recv_with(f)
    }

    fn keeps_input(&self) -> bool {
        self.rx.borrow().keeps_input()
    }

    fn keep(&mut self) {
        self.rx.borrow_mut().keep();
    }

    fn lends_until_next_receive(&self) -> bool {
        self.rx.borrow().lends_until_next_receive()
    }

    fn frame_budget(&self) -> Option<u16> {
        self.link.frame_budget()
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
#[cfg(wz_round)]
pub(super) struct SessionPace<C: ClockSource> {
    pub(super) local: CoopLocalSet<C>,
    pub(super) clock: C,
}

#[cfg(wz_round)]
impl<C: ClockSource> Pace for SessionPace<C> {
    fn pass(&self) {
        self.local.run_until_idle();
    }

    fn now_us(&self) -> u64 {
        self.clock.now_us()
    }
}

/// The session's clock, as a group's waits use it where the read steps the group's session
/// itself: a wait for room runs no task, the group's own write of its stage
/// (`GroupTxPace::pass`) being what frees it.
#[cfg(not(wz_round))]
pub(super) struct ClockPace<C: ClockSource> {
    pub(super) clock: C,
}

#[cfg(not(wz_round))]
impl<C: ClockSource> Pace for ClockPace<C> {
    fn pass(&self) {}

    fn now_us(&self) -> u64 {
        self.clock.now_us()
    }
}

/// What a group is joined with: the face its tables are in, the group as the ABI stated it (where
/// it is, what the session advertises and tells it), the stack's transport, the parameters its
/// session runs with, and what the session's messages wait with on a full queue.
pub(super) struct GroupJoining {
    /// The group's face: its id and the place its tables, and its room, lie at.
    pub(super) face: HeldFace,
    pub(super) join: GroupJoin,
    pub(super) transport: alloc::boxed::Box<dyn GroupTransport>,
    /// Whether the session has room for what the group delivers: the round's room for one record
    /// of the group's batch.
    #[cfg(wz_round)]
    pub(super) input_gate: GroupInputGate,
    /// The session's round of deliveries, which reads what the group's transport lends where it
    /// lies and keeps the buffer it gives back while a record still reads it.
    #[cfg(wz_round)]
    pub(super) lane: PlacedRef<Round>,
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
    pub(super) watchers: PlacedRef<FacePlane>,
}

/// One group of the session: its face, its task, its queue, its members and its stop, the group's
/// socket waited on with `W`, the waits of the session's stack.
pub(super) struct GroupFace<W> {
    face: HeldFace,
    join: GroupJoin,
    /// The group's session; `None` once the session's end was read ([`Self::take_outcome`]).
    #[cfg(wz_round)]
    task: Option<CoopLocalJoinHandle<MulticastOutcome>>,
    /// Where the read that steps the group's session leaves how it ended; `None` once that end
    /// was read ([`Self::take_outcome`]).
    #[cfg(not(wz_round))]
    end: Option<Rc<GroupEnd>>,
    /// When the group, whose session ended on its own, is joined again.
    rejoin_at_us: Option<u64>,
    /// The group's stage, which the session's messages and the group's replies are pushed onto,
    /// framed and numbered, and which the face writes after each push and its task at each step.
    tx: GroupTxStage,
    /// The group's transport, which the task opens, reads and lets go of, and which the face
    /// writes the stage on ([`Self::write_staged`]); `None` once the session's end was read
    /// ([`Self::take_outcome`]), the transport then dropped with what it holds of the session's
    /// (its receive buffer, one of the groups' table), so a join of the group again finds it free.
    link: Option<GroupLink<Watched>>,
    /// The receive half of this join, until the join's read slot takes it (`GroupSeat`).
    #[cfg(not(wz_round))]
    rx: Option<ReceiveHalf>,
    /// What a message of the session waits with on a full lane ([`Self::push_lent`]).
    pace: Rc<dyn Pace>,
    /// The waits of the session's stack, which the group's socket is waited on with.
    waits: W,
    /// What a wait for room on the group's socket waits on, asked from outside its task; `None`
    /// for a stack that gives none.
    room: Option<WaitOn>,
    /// What a read waits on for the group socket's input, beside the session's links; `None` for
    /// a stack that gives none, whose group is looked at on its tick.
    input: Option<WaitOn>,
    /// When the group's session is next due with nothing arriving on it, as its last step said.
    due: GroupDue,
    members: Rc<RefCell<MemberRows>>,
    took: Rc<Cell<bool>>,
    stop: Rc<Cell<bool>>,
    /// The JOIN the session asks of the group between two beacons ([`Self::ask_join`]).
    join_ask: JoinAsk,
    /// What the group's session counted of what it sent and received (`transport-stats`), shared
    /// with its task and its stage; it leaves with the group's join.
    #[cfg(feature = "transport-stats")]
    stats: Rc<TransportStats>,
    /// The spacing of the transport messages this join of the group received (`resource-snapshot`),
    /// fed by its task; retired into the session's reading when the join is replaced or the
    /// session closes (`Core::retired_groups`).
    #[cfg(feature = "resource-snapshot")]
    messages: Rc<wz_session_core::interval_meter::BuildIntervalMeter>,
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
    /// The generation a member's query is held and answered under (`queryable`).
    #[cfg(feature = "queryable")]
    generation: u64,
    /// The sink a member's query is answered through and a declaration of the application's
    /// answers the members' Interests on ([`Self::replies`]).
    replies: GroupReplies,
    /// The request id the group's next get is asked under: the group's own, as each link's are
    /// its own, so a member's answer names it on this face alone (`query`).
    #[cfg(feature = "query")]
    next_request: Cell<RequestId>,
}

impl<W: LinkWaits> GroupFace<W> {
    /// Join the group `joining` names, whose tables the registry holds already, its session
    /// spawned on `local`: each event of it goes through `dispatch`, with the sink the group's
    /// replies are queued on, after the members it admits and loses are noted. The task opens the
    /// transport as the session's link at its first step, which the caller runs. `Err` when the
    /// session's runtime has no cell for the task (its tables are reserved when the session
    /// opens), the transport let go of with what the task was to be made of. The group's socket is
    /// waited on with `waits`, those of the session's stack.
    #[cfg(wz_round)]
    pub(super) fn join<C, D>(
        local: &CoopLocalSet<C>,
        joining: GroupJoining,
        dispatch: D,
        waits: W,
    ) -> Result<Self, SpawnRefusal>
    where
        C: ClockSource + 'static,
        D: FnMut(IterationEvent<'_, '_>, &GroupReplies) + 'static,
    {
        let (mut face, seed) = Self::made(joining, waits);
        let on_event = {
            let members = Rc::clone(&face.members);
            let replies = MulticastReplySink::new(face.tx.clone());
            let keyexprs = Rc::clone(&face.keyexprs);
            let join_ask = face.join_ask.clone();
            let tx = face.tx.clone();
            #[cfg(feature = "connectivity")]
            let events = Rc::clone(&face.events);
            let mut dispatch = dispatch;
            move |event: IterationEvent<'_, '_>| {
                answer_asks(&event, &keyexprs, &join_ask, &tx);
                note_members(
                    &event,
                    &members,
                    #[cfg(feature = "connectivity")]
                    &events,
                );
                dispatch(event, &replies);
            }
        };
        let should_stop = {
            let stop = Rc::clone(&face.stop);
            move || stop.get()
        };
        // Everything the group sends is pushed onto its stage, which the face and the task write
        // from: the task's pull seam yields nothing.
        let task = try_spawn_multicast_session_seeded(local, seed, on_event, || None, should_stop)?;
        face.task = Some(task);
        Ok(face)
    }

    /// Join the group `joining` names, whose tables the registry holds already: the face, and
    /// what the group's read slot takes of this join (`GroupSeat`), a member's query held in
    /// `plane` (`queryable`). The session is built in the slot's place when the seat is taken
    /// (`GroupPump::new`, `GroupPump::rejoin`), and opens the transport as its link then; one
    /// that does not open is told by the first step. The group's socket is waited on with
    /// `waits`, those of the session's stack.
    #[cfg(not(wz_round))]
    pub(super) fn join(
        joining: GroupJoining,
        #[cfg(feature = "queryable")] plane: PlacedRef<super::query::QueryPlane>,
        waits: W,
    ) -> (Self, GroupSeat) {
        let (mut face, seed) = Self::made(joining, waits);
        let end = Rc::new(GroupEnd::default());
        face.end = Some(Rc::clone(&end));
        let reads = GroupReads {
            took: Rc::clone(&face.took),
            members: Rc::clone(&face.members),
            keyexprs: Rc::clone(&face.keyexprs),
            join_ask: face.join_ask.clone(),
            tx: face.tx.clone(),
            stop: Rc::clone(&face.stop),
            end,
            #[cfg(feature = "connectivity")]
            events: Rc::clone(&face.events),
        };
        let records = FaceRecords {
            face: face.face,
            actions: MulticastReplySink::new(face.tx.clone()),
            #[cfg(feature = "queryable")]
            plane,
            #[cfg(feature = "queryable")]
            generation: face.generation,
            after_pushes: false,
        };
        let seat = GroupSeat {
            seed,
            reads,
            records,
            rx: face.rx.take(),
        };
        (face, seat)
    }

    /// The face of the group `joining` names, and the seed of its session, which holds what the
    /// face shares with it: the one body both forms of the join make them in.
    fn made(
        joining: GroupJoining,
        waits: W,
    ) -> (Self, MulticastSessionSeed<SessionLink, GROUP_MEMBERS>) {
        let GroupJoining {
            face,
            join,
            transport,
            #[cfg(wz_round)]
            input_gate,
            #[cfg(wz_round)]
            lane,
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
        // the session's limits. A transport whose datagram carries less than the group's batch (a
        // raw Ethernet frame) has the group's frames cut to it, and the group's JOIN still states
        // its batch, as the tokio engine's group pipeline frames to its link's budget.
        let framed = params.framed_to(transport.frame_budget());
        let tx = GroupTxStage::with_limits(framed.as_ref().unwrap_or(&params), &limits);
        let room = transport.room_wait();
        let input = transport.input_wait();
        let due = GroupDue::default();
        let members = Rc::new(RefCell::new(MemberRows::new()));
        let took = Rc::new(Cell::new(false));
        let stop = Rc::new(Cell::new(false));
        let join_ask = JoinAsk::default();
        // What the group's session receives and its beacons are counted by its task, and each
        // datagram of the stage by whichever writer wrote it.
        #[cfg(feature = "transport-stats")]
        let stats = Rc::new(TransportStats::default());
        #[cfg(feature = "transport-stats")]
        tx.attach_stats(Rc::clone(&stats));
        // The session core's config for a group, the tokio engine's group face's too, with each
        // member's declarations kept apart: the group's events feed one session's tables.
        let config = MulticastConfig::of_group(&params, true);
        // The receive half, where the transport has one apart, is the session's alone: a receive
        // then reaches nothing a publish on another thread reaches.
        #[cfg(not(wz_round))]
        let (transport, rx) = {
            let mut transport = transport;
            let rx = transport.split_receive();
            (transport, rx)
        };
        // Shared by the session, which opens it as its link, and the face, which writes on it
        // what the session pushes.
        let link = GroupLink::new(Watched {
            inner: transport,
            #[cfg(wz_round)]
            took: Rc::clone(&took),
            #[cfg(wz_round)]
            lane,
        });
        #[cfg(not(wz_round))]
        let session_link = GroupSide::new(&link, rx);
        #[cfg(not(wz_round))]
        let half = Rc::clone(&session_link.rx);
        #[cfg(wz_round)]
        let session_link = link.clone();
        let seed = MulticastSessionSeed::<SessionLink, GROUP_MEMBERS>::new(
            config,
            session_link,
            params,
            policy,
            u64::from(GROUP_TICK_MS),
        )
        .with_join_ask(join_ask.clone())
        .with_tx_stage(tx.clone())
        .with_due(due.clone());
        // The round's room for a record of the group's batch gates what the group is handed; a
        // read that hands each record out as it is read needs no room for it.
        #[cfg(wz_round)]
        let seed = seed.with_input_gate(input_gate);
        #[cfg(feature = "transport-stats")]
        let seed = seed.with_stats(Rc::clone(&stats));
        #[cfg(feature = "resource-snapshot")]
        let messages = Rc::new(wz_session_core::interval_meter::BuildIntervalMeter::new());
        #[cfg(feature = "resource-snapshot")]
        let seed = seed.with_meter(Rc::clone(&messages));
        let keyexprs = Rc::new(RefCell::new(GroupKeyexprAnswers::default()));
        let keyexpr_ask_owed = Cell::new(join.declarations.declares_keyexprs());
        let face = Self {
            face,
            join,
            #[cfg(wz_round)]
            task: None,
            #[cfg(not(wz_round))]
            end: None,
            rejoin_at_us: None,
            #[cfg(feature = "queryable")]
            generation,
            replies: MulticastReplySink::new(tx.clone()),
            #[cfg(feature = "query")]
            next_request: Cell::new(0),
            tx,
            link: Some(link),
            #[cfg(not(wz_round))]
            rx: Some(half),
            pace,
            waits,
            room,
            input,
            due,
            members,
            took,
            stop,
            join_ask,
            #[cfg(feature = "transport-stats")]
            stats,
            #[cfg(feature = "resource-snapshot")]
            messages,
            keyexprs,
            keyexpr_ask_owed,
            filters: RefCell::new(Vec::new()),
            announced: RefCell::new(Vec::new()),
            #[cfg(feature = "connectivity")]
            events,
        };
        (face, seed)
    }

    /// Push `message`, a message of the session written from its parts and lent for the call, onto
    /// the group's stage as the tokio engine's group producer pushes one
    /// (`MulticastTxProducer::push`), through the same session core walk
    /// (`multicast_tx_push_encoded`, [`GroupTxStage::push_encoded`]): nothing of it is built on the
    /// heap. Its lane is asked for room before its
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
    /// `static z_result_t _z_transport_tx_send_n_msg_inner(`); a datagram of it that finds nothing
    /// queued or held ahead of it is offered to the socket from where it was written and put on no
    /// lane ([`GroupLink::push_encoded`]). A batch window that holds the message puts nothing on a
    /// lane, and its flush writes it.
    fn push_lent(&self, message: &MulticastTxEncoded<'_>) -> PushOutcome {
        match &self.link {
            Some(link) => link.push_encoded(&self.tx, message, self),
            None => self.tx.push_encoded(message, self),
        }
    }

    /// Write what the group's stage holds on the group's socket, on this thread, until the stage
    /// is empty or the socket has no room; what it refuses is offered again first at the next
    /// write, the face's or the task's. Whatever the session puts on the stage outside the group's
    /// own step is written so, by the thread that put it: a read already waiting on the group's
    /// socket is not woken by a push, and would hold it until that wait ends.
    pub(super) fn write_staged(&self) {
        if let Some(link) = &self.link {
            link.write_staged(&self.tx);
        }
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

    /// What a wait for room on the group's socket waits on, which a message of the session that
    /// finds the session held asks as it asks a link's.
    pub(super) fn room(&self) -> Option<WaitOn> {
        self.room
    }

    /// How many messages of `priority` the session put on the group were dropped for want of room.
    /// Read only by `CoopEngine::group_congestion_drops`, and compiled where it is.
    #[cfg(all(test, feature = "std", feature = "app-transport"))]
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

    /// What the group's session counted (`transport-stats`): the bytes and transport messages of
    /// the datagrams it sent and received, and the network messages read out of those received.
    #[cfg(feature = "transport-stats")]
    pub(super) fn stats_report(&self) -> wz_session_core::stats::TransportStatsReport {
        self.stats.report()
    }

    /// What this join of the group received, spaced (`resource-snapshot`): cumulative.
    #[cfg(feature = "resource-snapshot")]
    pub(super) fn message_reading(
        &self,
    ) -> wz_session_core::resource_snapshot::BuildMessageReading {
        self.messages.reading()
    }

    /// The group's stage, as its dispatch stages a reply on it. Read only by
    /// `CoopEngine::stage_group_replies`, and compiled where it is.
    #[cfg(all(
        test,
        feature = "std",
        feature = "app-transport",
        feature = "transport-stats"
    ))]
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

    /// The sink a member's query is answered through, and what a declaration of the application's
    /// owes the members' Interests: the group's stage. What is put on it outside the group's step
    /// is written after it by the thread that put it (`Self::write_staged`).
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

    /// Ask the group the query `rid` on `keyexpr`, named to the peers as `wire`, asking what
    /// `query` states. The key is named as a put on the group names it: by the declaration the
    /// group was told when it is told the session's keyexprs, and in full otherwise
    /// (`GroupDeclarations::key`). Written straight into the group's stage by the writer a link's
    /// query is written by, and sent reliably on the group, as zenoh-pico sends one on its
    /// multicast transport, its timestamp stack included. One asked from inside another push's wait is kept by the
    /// stage and framed after it. `false` when nothing was queued: the key names none, or the
    /// query cannot be written.
    #[cfg(feature = "query")]
    pub(super) fn ask(
        &self,
        rid: RequestId,
        keyexpr: &str,
        wire: &WireKey,
        query: QueryParts<'_>,
    ) -> bool {
        let key = self.join.declarations.key(keyexpr, wire);
        let Some(key) = wz_session_core::wire_key::WireKey::from_parts(key.mapping_id, key.suffix)
        else {
            return false;
        };
        let writer = RequestWriter::new(GetParts { rid, key, query });
        multicast_tx_request(&writer, query.qos, |message| self.push_lent(message)).is_some()
    }

    /// The face the group's tables are in.
    pub(super) fn id(&self) -> FaceId {
        self.face.id()
    }

    /// The place of the group's face in the session's tables, its room's among them.
    pub(super) fn at(&self) -> usize {
        self.face.at()
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
        self.finished().unwrap_or(true)
    }

    /// Whether the group's session finished, while its end is still to be read: `None` once it
    /// was.
    fn finished(&self) -> Option<bool> {
        #[cfg(wz_round)]
        {
            self.task.as_ref().map(|task| task.is_finished())
        }
        #[cfg(not(wz_round))]
        {
            self.end.as_ref().map(|end| end.finished.get())
        }
    }

    /// How the group's session ended, read once: `None` while it runs, and after it was read.
    /// The members it held go with it, and so does its transport, whose last holder the face is
    /// once the task's output is taken: the group's receive buffer goes back to the session before
    /// the group is joined again, which takes one of the same table.
    pub(super) fn take_outcome(
        &mut self,
        #[cfg(wz_round)] local: &CoopLocalSet<impl ClockSource + 'static>,
    ) -> Option<MulticastOutcome> {
        if !self.finished()? {
            return None;
        }
        #[cfg(wz_round)]
        let task = self.task.take()?;
        #[cfg(not(wz_round))]
        let end = self.end.take()?;
        // The members go with the group's link, and a watcher of the faces is told each went. Those
        // a replaying listener was told stand stay as tombs until it was told they went.
        let gone = core::mem::take(&mut *self.members.borrow_mut());
        #[cfg(feature = "connectivity")]
        {
            for member in gone.iter() {
                self.events.tell(FaceEventKind::Down, member);
            }
            self.members.borrow_mut().keep_tombs_of(&gone);
        }
        #[cfg(not(feature = "connectivity"))]
        let _ = gone;
        // A finished task's output is taken without stepping anything.
        #[cfg(wz_round)]
        let outcome = local.block_on_local(task).ok();
        #[cfg(not(wz_round))]
        let outcome = end.outcome.take();
        self.link = None;
        outcome
    }

    /// Join the group again at `at_us`, on the session's clock.
    pub(super) fn wait_to_rejoin(&mut self, at_us: u64) {
        self.rejoin_at_us = Some(at_us);
    }

    /// Whether the group waits to be joined again and its time has come.
    pub(super) fn rejoin_due(&self, now_us: u64) -> bool {
        self.rejoin_at_us.is_some_and(|at_us| now_us >= at_us)
    }

    /// Whether the group's socket may hold a datagram not yet read, since this was last asked:
    /// its task took one (`wz_round`), or the read's last step of it read to its bound.
    pub(super) fn took_input(&self) -> bool {
        self.took.replace(false)
    }

    /// Whether the group's task took a datagram since `took_input` was last asked, the mark left
    /// for it.
    pub(super) fn holds_input(&self) -> bool {
        self.took.get()
    }

    /// What a read waits on for the group socket's next datagram, while the group's session runs
    /// and its stack gives one.
    pub(super) fn input(&self) -> Option<LinkWait> {
        if self.has_ended() {
            return None;
        }
        self.input.map(LinkWait::input)
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
        match self.finished() {
            Some(true) => Some(0),
            Some(false) if self.tx.holds() => {
                let tick_us = self.pace.now_us().saturating_add(GROUP_TICK_US);
                Some(self.due.due_us().map_or(0, |due_us| due_us.min(tick_us)))
            }
            Some(false) if !self.tx.is_empty() => Some(0),
            Some(false) => Some(self.due.due_us().unwrap_or(0)),
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

    /// How many rows the group's members are read in (`connectivity`): one for each member of a
    /// known role, as [`Self::member_snapshots`] lists them; a group whose session ended holds
    /// none.
    #[cfg(feature = "connectivity")]
    pub(super) fn member_rows(&self) -> usize {
        if self.has_ended() {
            return 0;
        }
        self.members
            .borrow()
            .iter()
            .filter(|member| member.whatami.is_some())
            .count()
    }

    /// The `at`-th of the rows [`Self::member_rows`] counts, read in place: the member's transport
    /// and its one link, every text in the row, so nothing is allocated (`connectivity`).
    #[cfg(feature = "connectivity")]
    pub(super) fn member_row(&self, at: usize) -> Option<FaceLinkRow> {
        if self.has_ended() {
            return None;
        }
        let members = self.members.borrow();
        let member = members
            .iter()
            .filter(|member| member.whatami.is_some())
            .nth(at)?;
        let label = &self.events.label;
        FaceLinkRow::of_group_member(member, &label.group, &label.endpoint, label.is_shm)
    }

    /// Note `listener` of `plane` told the member of `key` stands (`SessionEngine::tell_came`):
    /// whether it is to be told; a group whose session ended holds none that stands.
    #[cfg(feature = "connectivity")]
    pub(super) fn tell_came(&self, plane: ToldPlane, listener: usize, key: &ToldKey) -> bool {
        !self.has_ended() && self.members.borrow_mut().came(plane, listener, key)
    }

    /// Whether `listener` of `plane` is still to be told the member of `key` went.
    #[cfg(feature = "connectivity")]
    pub(super) fn owes_departure(&self, plane: ToldPlane, listener: usize, key: &ToldKey) -> bool {
        self.members.borrow().owes(plane, listener, key)
    }

    /// Note `listener` of `plane` told the member of `key` went (`SessionEngine::tell_went`):
    /// whether a tomb of the group owed it that.
    #[cfg(feature = "connectivity")]
    pub(super) fn tell_went(&self, plane: ToldPlane, listener: usize, key: &ToldKey) -> bool {
        self.members.borrow_mut().went(plane, listener, key)
    }

    /// The row of the first member whose departure `listener` of `plane` is owed, read from its
    /// tomb as `member_row` reads a member that stands.
    #[cfg(feature = "connectivity")]
    pub(super) fn first_told_gone(&self, plane: ToldPlane, listener: usize) -> Option<FaceLinkRow> {
        let member = self.members.borrow().first_gone(plane, listener)?;
        let label = &self.events.label;
        FaceLinkRow::of_group_member(&member, &label.group, &label.endpoint, label.is_shm)
    }

    /// Note nothing more for `listener` of `plane` (`SessionEngine::forget_told`).
    #[cfg(feature = "connectivity")]
    pub(super) fn forget_told(&self, plane: ToldPlane, listener: usize) {
        self.members.borrow_mut().forget(plane, listener);
    }

    /// Take over the tombs of `ended`, the join of this group that ended, which this one replaces.
    #[cfg(feature = "connectivity")]
    pub(super) fn keep_tombs_of(&self, ended: &Self) {
        let ended = ended.members.borrow();
        self.members.borrow_mut().keep_tombs_of(&ended);
    }

    /// Tell the group of `entity`, which the session declared, as the group's declarations say
    /// (the port's rules: `GroupDeclarations::announced_id`, `key`, `retraction_key`, the tokio
    /// engine's groups' too), the `Declare` built by the session core's builder
    /// (`multicast_tx_group_announcement`, written from its parts) and pushed onto the group's stage. What a later retraction
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
        let _ = multicast_tx_group_announcement(
            entity.what,
            id,
            told.key(entity.keyexpr, entity.wire),
            |message| self.push_lent(message),
        );
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
    /// (`multicast_tx_group_retraction`); an entity it was not told of, or a group that is told no
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
        let _ = multicast_tx_group_retraction(announced.what, announced.id, key, |message| {
            self.push_lent(message)
        });
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
        if let Ok(interest) = interest_exact(
            u64::from(id),
            InterestKinds::TOKENS,
            history,
            /*future=*/ true,
            Some((key.mapping_id, key.suffix)),
        ) {
            multicast_tx_interest(&interest, |message| self.push_lent(message));
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
        multicast_tx_interest(&interest_final(u64::from(id)), |message| {
            self.push_lent(message)
        });
    }

    /// Tell the group the keyexpr the session declared as `id`, when it is told the session's
    /// keyexprs (`GroupDeclarations::declares_keyexprs`), as the tokio engine's group is told it,
    /// and hold it for the members that ask for it.
    pub(super) fn announce_keyexpr(&self, id: ExprId, keyexpr: &str) {
        let Some(declared) = core::num::NonZero::new(id) else {
            return;
        };
        if self.has_ended() || !self.join.declarations.declares_keyexprs() {
            return;
        }
        if let Ok(declaration) = kexpr_declaration(declared, keyexpr) {
            self.keyexprs.borrow_mut().declared(id, keyexpr);
            multicast_tx_declaration(&declaration, |message| self.push_lent(message));
        }
    }

    /// Retract from the group the keyexpr [`Self::announce_keyexpr`] told it as `id`.
    pub(super) fn retract_keyexpr(&self, id: ExprId) {
        if self.has_ended() || !self.join.declarations.declares_keyexprs() {
            return;
        }
        self.keyexprs.borrow_mut().retracted(id);
        multicast_tx_declaration(&undeclare_kexpr_declaration(id), |message| {
            self.push_lent(message)
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
        if let Ok(interest) = interest_exact(
            interest_id,
            InterestKinds::KEYEXPRS,
            /*current=*/ true,
            /*future=*/ false,
            None,
        ) {
            multicast_tx_interest(&interest, |message| self.push_lent(message));
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
        if let Ok(interest) = interest_exact(
            interest_id,
            kinds,
            /*current=*/ true,
            /*future=*/ false,
            Some((key.mapping_id, key.suffix)),
        ) {
            multicast_tx_interest(&interest, |message| self.push_lent(message));
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
            multicast_tx_interest(&interest_final(interest_id), |message| {
                self.push_lent(message)
            });
        }
    }

    /// Put a publication on the group, naming its key by the declaration the group was told when
    /// it is told the session's keyexprs (`GroupDeclarations::declares_keyexprs`), and in full
    /// otherwise, as a group whose session tells it its entities, or less, is. Written from its parts
    /// by the session core's publication writer, as a link's is, framed with the sequence number of
    /// its channel as it is pushed onto the group's stage, and written by this call
    /// ([`Self::push_lent`]). A group whose
    /// session ended is sent nothing.
    pub(super) fn publish(&self, put: GroupPut<'_>) -> Result<usize, FanoutError> {
        if self.has_ended() {
            return Ok(0);
        }
        // A group told the session's keyexprs is sent the key by its declaration, as the tokio
        // engine's group is; any other by its literal.
        let key = self.join.declarations.key(put.keyexpr, put.wire);
        // Written from its parts, the bytes of the owned Push the builders would make; a key, a
        // payload or a field past its bound is refused as the builders refuse it.
        let suffix = match key.mapping_id {
            0 => Some(put.keyexpr),
            _ => key.suffix,
        };
        multicast_tx_publication(
            wz_session_core::declare_form::GroupKey {
                mapping_id: key.mapping_id,
                suffix,
            },
            put.kind,
            put.payload,
            put.meta,
            put.reliable,
            put.priority,
            |message| self.push_lent(message),
        )
        .map_err(|_| FanoutError::ExceedsCapacity)?;
        Ok(0)
    }
}

/// How a group's session ended, left by the read that stepped it for the session to read
/// ([`GroupFace::take_outcome`]).
#[cfg(not(wz_round))]
#[derive(Default)]
pub(super) struct GroupEnd {
    finished: Cell<bool>,
    outcome: RefCell<Option<MulticastOutcome>>,
}

/// What the read of a group shares with the group's face: the mark of input the socket may still
/// hold, the members, the keyexpr asks, the JOIN ask, the stage, its stop, and where its end is
/// left.
#[cfg(not(wz_round))]
struct GroupReads {
    took: Rc<Cell<bool>>,
    members: Rc<RefCell<MemberRows>>,
    keyexprs: Rc<RefCell<GroupKeyexprAnswers>>,
    join_ask: JoinAsk,
    tx: GroupTxStage,
    stop: Rc<Cell<bool>>,
    end: Rc<GroupEnd>,
    #[cfg(feature = "connectivity")]
    events: Rc<MemberEvents>,
}

/// What one join of a group gives the group's read slot: the seed of the join's session, what
/// the read notes each event against, and what it hands each record out with.
#[cfg(not(wz_round))]
pub(super) struct GroupSeat {
    seed: MulticastSessionSeed<SessionLink, GROUP_MEMBERS>,
    reads: GroupReads,
    records: FaceRecords<GroupReplies>,
    rx: Option<ReceiveHalf>,
}

/// The read slot of a group (`docs/c-abi-architecture.md` 8.8): the group's session, in the
/// place its read steps it, and what that read notes each event against before it is handed out.
/// It lies apart from the group's face, which the session's state holds, so that the read steps
/// it with the session let go of while each record it read is handed out, and takes the session's
/// lock for each record it dispatches. Its values are one thread's, shared with the group's face:
/// where other threads reach the session (`threads`) the rest of a step is made under the
/// session's lock (`CoopEngine::step_groups`).
/// The place is made once for the group, at the session's open: a session that ended is let go of
/// with the place kept (`Self::let_go`), and each join again builds its session there.
#[cfg(not(wz_round))]
pub(super) struct GroupPump<C: ClockSource + 'static> {
    place: MulticastSessionPlace<C, SessionLink, GROUP_MEMBERS>,
    reads: GroupReads,
    /// What each record is handed out with: the group's face, the sink of its replies, and the
    /// generation a member's query is answered under.
    records: FaceRecords<GroupReplies>,
    /// The receive half of the session's transport, which a read waits in before a step.
    rx: Option<ReceiveHalf>,
}

#[cfg(not(wz_round))]
impl<C: ClockSource + 'static> GroupPump<C> {
    /// The read slot of the group's first join, `seat`, its session built on `runtime`'s clock
    /// in a place of its own, the one place the group's joins take.
    pub(super) fn new(runtime: CoopRuntime<C>, seat: GroupSeat) -> Self {
        let GroupSeat {
            seed,
            reads,
            records,
            rx,
        } = seat;
        Self {
            place: MulticastSessionPlace::new(runtime, seed),
            reads,
            records,
            rx,
        }
    }

    /// Take the group's next join, `seat`, into the slot: its session built in the place the
    /// last one lay in, that one let go of first if the slot still holds it.
    pub(super) fn rejoin(&mut self, seat: GroupSeat) {
        let GroupSeat {
            seed,
            reads,
            records,
            rx,
        } = seat;
        self.place.rejoin(seed);
        self.reads = reads;
        self.records = records;
        self.rx = rx;
    }

    /// Whether a read may wait in the group's receive for what it would wait on as `wait`
    /// (`Self::await_input`): the session runs, and `wait` is its receive half's own input, on a
    /// half whose receive waits.
    pub(super) fn awaits(&self, wait: &LinkWait) -> bool {
        self.holds_session()
            && self
                .rx
                .as_ref()
                .is_some_and(|rx| awaits_on(&**rx.borrow(), wait))
    }

    /// Whether the group's receive half waits in its receive (`Self::await_input`).
    pub(super) fn awaits_input(&self) -> bool {
        self.rx
            .as_ref()
            .is_some_and(|rx| rx.borrow().awaits_input())
    }

    /// Wait in the group's receive, for at most `timeout_us` of the session's clock past its
    /// reading `since_us`, for a member's datagram, kept for the step that follows to read first;
    /// what the group's own sender sent is dropped inside the wait (`GroupReceive::await_input`).
    /// Whether one was kept.
    pub(super) fn await_input(&mut self, timeout_us: u64, since_us: u64) -> bool {
        let Some(rx) = &self.rx else {
            return false;
        };
        let place = &self.place;
        rx.borrow_mut()
            .await_input(timeout_us, since_us, &mut || place.now_us())
    }

    /// Whether the last step read as many datagrams as it was bound to.
    pub(super) fn read_to_bound(&self) -> bool {
        self.place.read_to_bound()
    }

    /// Whether the slot holds a session a read steps: from a join to the session's end.
    pub(super) fn holds_session(&self) -> bool {
        self.place.holds_session()
    }

    /// Let go of the session, which ended: its transport goes now, so the group's next join finds
    /// what it held of the stack's free, and the place stays for that join. The receive half goes
    /// with it: it holds the transport's socket and receive buffer (or, for a transport whose
    /// halves are one, the transport itself), which the next join claims again.
    pub(super) fn let_go(&mut self) {
        self.place.leave();
        self.rx = None;
    }

    /// What the group's records are handed out with, which the read ends a step's records with.
    pub(super) fn records(&mut self) -> &mut FaceRecords<GroupReplies> {
        &mut self.records
    }

    /// A reading of the session's clock, for a step with none at hand.
    pub(super) fn now_us(&self) -> u64 {
        self.place.now_us()
    }

    /// One step of the group's session at the read's reading `now_us` of the session's clock,
    /// reading up to `most` of the group's datagrams: each event it yields noted against the
    /// group (its members, the asks of its members) and then handed to `hand` with the group's
    /// records, as it is read, so each datagram's records are handed out before the next is
    /// received. The group's mark of input (`GroupFace::took_input`) is left where the reads
    /// ended on `most`, the socket then maybe holding more, and cleared where they ended on a
    /// receive that found none. Whether the session ended at this step, its end left for the
    /// session to read.
    pub(super) fn step(
        &mut self,
        hand: &mut dyn FnMut(&mut FaceRecords<GroupReplies>, IterationEvent<'_, '_>),
        most: core::num::NonZeroUsize,
        now_us: u64,
    ) -> bool {
        let reads = &self.reads;
        let records = &mut self.records;
        let mut on_event = |event: IterationEvent<'_, '_>| {
            answer_asks(&event, &reads.keyexprs, &reads.join_ask, &reads.tx);
            note_members(
                &event,
                &reads.members,
                #[cfg(feature = "connectivity")]
                &reads.events,
            );
            hand(&mut *records, event);
        };
        let mut should_stop = || reads.stop.get();
        // Everything the group sends is pushed onto its stage, which the face and the session
        // write from: the session's pull seam yields nothing.
        let outcome = self.place.step_reading(
            &mut on_event,
            &mut || None,
            Some(&mut should_stop as &mut dyn FnMut() -> bool),
            most,
            now_us,
        );
        let Some(outcome) = outcome else {
            reads.took.set(self.place.read_to_bound());
            return false;
        };
        *reads.end.outcome.borrow_mut() = Some(outcome);
        reads.end.finished.set(true);
        true
    }

    /// End the group's session: its stop asked, and its last step taken, which tells the group it
    /// leaves; what that step reads is handed to no one, the session being closed. A slot whose
    /// session ended already has nothing to tell.
    pub(super) fn leave(mut self) {
        if !self.holds_session() {
            return;
        }
        self.reads.stop.set(true);
        let now_us = self.now_us();
        let _ = self.step(
            &mut |_records, _event| {},
            core::num::NonZeroUsize::MIN,
            now_us,
        );
    }
}

/// What the session's transport reads of the group (`wz_runtime_coop::transport`): each a reading
/// of the group's own.
impl<W: LinkWaits> GroupRecord for GroupFace<W> {
    fn id(&self) -> FaceId {
        self.face.id()
    }

    fn took_input(&self) -> bool {
        GroupFace::took_input(self)
    }

    fn holds_input(&self) -> bool {
        GroupFace::holds_input(self)
    }

    fn input(&self) -> Option<LinkWait> {
        GroupFace::input(self)
    }

    fn unwaited(&self) -> bool {
        GroupFace::unwaited(self)
    }

    fn due_us(&self) -> Option<u64> {
        GroupFace::due_us(self)
    }

    fn stop(&self) {
        GroupFace::stop(self);
    }

    #[cfg(feature = "query")]
    fn asks_queries(&self) -> bool {
        self.declarations().asks_queries()
    }

    #[cfg(feature = "queryable")]
    fn answer_sink(&self, generation: u64) -> Option<&dyn ResponseSink> {
        self.answers_as(generation)
            .then_some(self.replies() as &dyn ResponseSink)
    }

    #[cfg(feature = "queryable")]
    fn write_staged(&self) {
        GroupFace::write_staged(self);
    }

    #[cfg(feature = "connectivity")]
    fn member_rows(&self) -> usize {
        GroupFace::member_rows(self)
    }

    #[cfg(feature = "connectivity")]
    fn member_row(&self, at: usize) -> Option<FaceLinkRow> {
        GroupFace::member_row(self, at)
    }

    #[cfg(feature = "connectivity")]
    fn member_snapshots(&self) -> Vec<FaceSnapshot> {
        GroupFace::member_snapshots(self)
    }
}

/// A message of the session that waits for room on the group's stage writes what the group's
/// socket takes, runs the session's tasks, waits on the group's socket, and spends the session's
/// clock; a group whose session ended has nothing to wait for.
impl<W: LinkWaits> GroupTxPace for GroupFace<W> {
    fn pass(&self) {
        self.write_staged();
        self.pace.pass();
    }

    fn now_us(&self) -> u64 {
        self.pace.now_us()
    }

    fn wait_writable(&self, wait_us: u64) -> bool {
        match self.room {
            Some(room) => self.waits.wait_room(room, wait_us),
            None => true,
        }
    }

    fn ended(&self) -> bool {
        self.has_ended()
    }
}

/// What a group's session's event asks of the group before it is dispatched: a member's interest
/// in what is declared now asks the group for a JOIN first, as zenoh-pico pushes one
/// (`asks_for_declarations`), and a member's ask for the session's keyexprs is answered ahead of
/// the session's other declarations (`GroupKeyexprAnswers`), as the tokio engine's group answers
/// both.
fn answer_asks(
    event: &IterationEvent<'_, '_>,
    keyexprs: &RefCell<GroupKeyexprAnswers>,
    join_ask: &JoinAsk,
    tx: &GroupTxStage,
) {
    if asks_for_declarations(event) {
        // What is queued below, and what the dispatch queues, leaves after the JOIN the group's
        // next step sends: a step sends its beacon before what is queued.
        join_ask.ask();
        // A reply is put on the stage without waiting, so the answers go as they are taken, each
        // written from its parts where it waits.
        let mut keyexprs = keyexprs.borrow_mut();
        keyexprs.asked(event);
        keyexprs.take_declarations(|reply| tx.enqueue_declaration_reply(reply));
    }
}

/// Note the member a group's session's event admits or loses, each told to the session's
/// watchers of its faces (`connectivity`), before the event is dispatched.
fn note_members(
    event: &IterationEvent<'_, '_>,
    members: &RefCell<MemberRows>,
    #[cfg(feature = "connectivity")] events: &MemberEvents,
) {
    match event {
        IterationEvent::MulticastPeerArrived(arrived) => {
            let member = MulticastMember {
                peer: arrived.peer,
                whatami: arrived.whatami,
                locator: arrived.locator,
            };
            // The session's member table has as many rows, so it admits no member past them.
            let noted = members.borrow_mut().push(member);
            debug_assert!(noted, "a member past the group's rows was admitted");
            #[cfg(feature = "connectivity")]
            if noted {
                events.tell(FaceEventKind::Up, &member);
            }
        }
        IterationEvent::MulticastPeerLost(lost) => {
            let gone = members.borrow_mut().remove(&lost.peer);
            #[cfg(feature = "connectivity")]
            if let Some(member) = gone {
                events.tell(FaceEventKind::Down, &member);
            }
            #[cfg(not(feature = "connectivity"))]
            let _ = gone;
        }
        _ => {}
    }
}

/// The ABI's form of a key the session's tables name `form` on the wire, for a group told the
/// entity it names: the declaration's id and the rest of the key by its length, read against the
/// key handed beside it ([`WireKey::names_in`]), so the tables stay the one place the form lies
/// and nothing of the key is copied.
pub(super) fn wire_key_of(form: WireForm<'_>) -> WireKey {
    WireKey::aliased_tail(form.mapping, form.suffix.len())
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
#[derive(Clone, Copy)]
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
#[cfg(all(wz_round, feature = "queryable"))]
pub(super) fn dispatch(
    registry: super::RegistryLend,
    face: HeldFace,
    plane: PlacedRef<super::query::QueryPlane>,
    generation: u64,
) -> impl FnMut(IterationEvent<'_, '_>, &GroupReplies) + 'static {
    use wz_session_core::response_sink::ResponseSink;
    move |event, replies| {
        let dispatched = registry.with(|registry| {
            plane.set_arriving(generation);
            registry.dispatch_event(face, event);
            registry.flush_pending_replies(face, replies);
            for (rid, qos) in registry.take_pending_final_rids(face) {
                if plane.with_holds(|holds| holds.owe(generation, rid, qos)) {
                    replies.send_response_final(rid, qos);
                }
            }
        });
        debug_assert!(dispatched.is_some(), "{}", super::UNLENT);
    }
}

/// The dispatch of a group whose session has no queryable: the registry's, with everything it
/// staged queued on the group at once.
#[cfg(all(wz_round, not(feature = "queryable")))]
pub(super) fn dispatch(
    registry: super::RegistryLend,
    face: HeldFace,
) -> impl FnMut(IterationEvent<'_, '_>, &GroupReplies) + 'static {
    move |event, replies| {
        let dispatched = registry.with(|registry| registry.dispatch(face, event, replies));
        debug_assert!(dispatched.is_some(), "{}", super::UNLENT);
    }
}

#[cfg(all(test, feature = "connectivity"))]
mod told_tests {
    use super::*;

    fn member(first: u8) -> MulticastMember {
        MulticastMember {
            peer: MulticastPeerId::from_wire(&[first; 16]),
            whatami: Some(wz_session_core::WhatAmI::Peer),
            locator: core::net::SocketAddr::from(([127, 0, 0, 1], 7447)),
        }
    }

    const PLANE: ToldPlane = ToldPlane::Transports;

    /// A group joined holds no member; a member that goes, told to no listener, leaves its row and
    /// the members after it keep the order they came in; a member that never came is not handed
    /// back. Turned red by a row let go of out of order (the last row moved into its place).
    #[test]
    fn a_member_that_goes_keeps_the_order_of_the_others() {
        let mut rows = MemberRows::new();
        assert_eq!(rows.iter().count(), 0, "a group joined holds no member");
        for first in 1..=3 {
            assert!(rows.push(member(first)));
        }
        assert_eq!(rows.remove(&member(2).peer), Some(member(2)));
        assert_eq!(rows.remove(&member(9).peer), None, "no such member");
        let left: Vec<MulticastMember> = rows.iter().copied().collect();
        assert_eq!(left, [member(1), member(3)]);
        assert_eq!(rows.rows.len(), 2);
    }

    /// A member a replaying listener was told stays in its row, gone, until the listener was told
    /// it went; one no listener was told leaves its row at once.
    ///
    /// # Control
    ///
    /// Letting go of the row whatever its bits (the member table before the told bits) reds the
    /// `owes` assertion.
    #[test]
    fn a_member_told_stays_as_its_tomb_until_its_departure_is_told() {
        let mut rows = MemberRows::new();
        assert!(rows.push(member(1)));
        assert!(rows.push(member(2)));
        let key = member_key(&member(1));
        assert!(rows.came(PLANE, 0, &key));
        assert!(!rows.came(PLANE, 0, &key), "told once");

        assert_eq!(rows.remove(&member(2).peer), Some(member(2)));
        assert_eq!(
            rows.rows.len(),
            1,
            "a member no listener was told leaves its row"
        );
        assert_eq!(rows.remove(&member(1).peer), Some(member(1)));
        assert_eq!(rows.rows.len(), 1, "a member told stays as its tomb");
        assert_eq!(rows.iter().count(), 0, "a tomb is no member that stands");
        assert!(rows.owes(PLANE, 0, &key));
        assert!(!rows.owes(PLANE, 1, &key), "only to the listener told it");
        assert!(
            !rows.came(PLANE, 1, &key),
            "a tomb is told to no one as standing"
        );
        assert_eq!(rows.first_gone(PLANE, 0), Some(member(1)));
        assert!(rows.went(PLANE, 0, &key));
        assert!(!rows.went(PLANE, 0, &key), "told once");
        assert_eq!(rows.rows.len(), 0, "the tomb owed to no one is let go of");
    }

    /// A member the group admits when every row is held takes the oldest tomb's row: a member that
    /// stands comes before a departure owed.
    ///
    /// # Control
    ///
    /// A push that refuses a full table without looking for a tomb reds the first assertion.
    #[test]
    fn a_member_admitted_to_full_rows_takes_the_oldest_tomb() {
        let mut rows = MemberRows::new();
        for first in 0..GROUP_MEMBERS {
            assert!(rows.push(member(u8::try_from(first).expect("a few members"))));
        }
        let key = member_key(&member(0));
        assert!(rows.came(PLANE, 0, &key));
        assert!(rows.remove(&member(0).peer).is_some());
        assert!(rows.push(member(200)), "the tomb's row is taken");
        assert!(!rows.owes(PLANE, 0, &key), "the tomb was given up");
        assert_eq!(rows.iter().count(), GROUP_MEMBERS);
        assert!(!rows.push(member(201)), "no row past members that stand");
    }

    /// The tombs of a join that ended are taken over by the join that replaces it, and a listener
    /// forgotten lets go of a tomb owed only to it.
    ///
    /// # Control
    ///
    /// `keep_tombs_of` that copies nothing reds the first `owes`.
    #[test]
    fn a_rejoin_keeps_the_tombs_and_a_forgotten_listener_lets_them_go() {
        let mut ended = MemberRows::new();
        assert!(ended.push(member(3)));
        assert!(ended.push(member(4)));
        let key = member_key(&member(3));
        assert!(ended.came(ToldPlane::Links, 2, &key));
        let mut joined = MemberRows::new();
        joined.keep_tombs_of(&ended);
        assert_eq!(joined.rows.len(), 1, "only the member a listener was told");
        assert!(joined.owes(ToldPlane::Links, 2, &key));
        assert_eq!(joined.iter().count(), 0, "kept as a tomb");
        joined.forget(ToldPlane::Transports, 2);
        assert!(
            joined.owes(ToldPlane::Links, 2, &key),
            "another plane forgets nothing here"
        );
        joined.forget(ToldPlane::Links, 2);
        assert_eq!(joined.rows.len(), 0);
    }
}

/// What a read that waits in a group's receive does with the group between two turns of its own
/// ([`read_awaited`]): the group's pump, stepped by the read's engine.
#[cfg(not(wz_round))]
pub(super) trait AwaitedReads {
    /// Wait in the group's receive for at most `timeout_us` past the reading `since_us`
    /// ([`GroupPump::await_input`]): whether a member's datagram was kept.
    fn await_input(&mut self, timeout_us: u64, since_us: u64) -> bool;

    /// A reading of the session's clock.
    fn now_us(&mut self) -> u64;

    /// A step of the group at `now_us`, reading up to `most` datagrams: whether its session
    /// ended.
    fn step(&mut self, most: core::num::NonZeroUsize, now_us: u64) -> bool;

    /// Whether the last step read as many datagrams as it was bound to.
    fn read_to_bound(&self) -> bool;

    /// Whether the read owes the session a turn of its own at `now_us` (its bookkeeping, a
    /// periodic job), which only the read's turn takes.
    fn owed(&mut self, now_us: u64) -> bool;
}

/// The reads of a group that is the one input its read waits on, on a receive half whose receive
/// waits (`GroupPump::awaits`), up to `deadline_us`, the end of the read's wait, from the read's
/// reading `since_us`: each a wait in the group's receive for what is left of the time, then a
/// step that reads the datagram the wait kept, as zenoh-pico's read task handles a datagram a
/// receive (`vendor/zenoh-pico/src/transport/multicast/read.c` @
/// `ret = _z_transport_message_decode(&t_msg, &zbuf);`). The read's own turn and its wait are so
/// paid once a deadline and not once a datagram. The reads end at a wait that kept nothing, which
/// is stepped with `most` as a read with no wait of its own steps, at the session's end, at a step
/// that read nothing, at the deadline, and where the read owes the session a turn, which the read
/// then takes: a datagram that wrote the face's tables, or a job that fell due, waits for no later
/// datagram. Whether the session ended.
#[cfg(not(wz_round))]
pub(super) fn read_awaited(
    reads: &mut impl AwaitedReads,
    most: core::num::NonZeroUsize,
    deadline_us: u64,
    since_us: u64,
) -> bool {
    let mut now_us = since_us;
    loop {
        let kept = reads.await_input(deadline_us.saturating_sub(now_us), now_us);
        now_us = reads.now_us();
        if !kept {
            return reads.step(most, now_us);
        }
        // One datagram a step: the next is waited for in the receive, where a step's own receive
        // would find none and cost a system call that answers nothing, when the reader keeps up.
        if reads.step(core::num::NonZeroUsize::MIN, now_us) {
            return true;
        }
        if !reads.read_to_bound() || now_us >= deadline_us || reads.owed(now_us) {
            return false;
        }
    }
}

#[cfg(all(test, not(wz_round)))]
mod side_tests {
    use super::*;

    /// The address a member's datagrams come from.
    fn member() -> SocketAddr {
        SocketAddr::from(([192, 0, 2, 7], 7447))
    }

    /// A receive half that lends `b"half"` at every receive, and says whether it failed.
    struct Half {
        failed: bool,
    }

    impl GroupReceive for Half {
        fn recv_with(&mut self, f: &mut dyn FnMut(&[u8], SocketAddr)) -> bool {
            f(b"half", member());
            true
        }

        fn failed(&self) -> bool {
            self.failed
        }

        fn close(&mut self) {}
    }

    /// A transport whose receive half is `half` until it is taken out, and whose own receive
    /// lends `b"whole"`.
    struct Joined {
        half: Option<alloc::boxed::Box<dyn GroupReceive>>,
    }

    impl GroupTransport for Joined {
        fn open(&mut self) -> bool {
            true
        }

        fn close(&mut self) {}

        fn service(&self) {}

        fn carrier_up(&self) -> bool {
            true
        }

        fn send_to_group(&mut self, _datagram: &[u8]) {}

        fn recv_with(&mut self, f: &mut dyn FnMut(&[u8], SocketAddr)) -> bool {
            f(b"whole", member());
            true
        }

        fn split_receive(&mut self) -> Option<alloc::boxed::Box<dyn GroupReceive>> {
            self.half.take()
        }
    }

    /// The session's side of a group over a transport that splits `half` out, as a join makes it.
    fn side(half: Option<alloc::boxed::Box<dyn GroupReceive>>) -> GroupSide {
        let mut transport: alloc::boxed::Box<dyn GroupTransport> =
            alloc::boxed::Box::new(Joined { half });
        let rx = transport.split_receive();
        let link = GroupLink::new(Watched { inner: transport });
        GroupSide::new(&link, rx)
    }

    /// What one receive of `side` lent.
    fn received(side: &mut GroupSide) -> alloc::vec::Vec<u8> {
        let mut seen = alloc::vec::Vec::new();
        assert!(side.recv_with(&mut |bytes, _| seen = bytes.to_vec()));
        seen
    }

    /// The session's side of a group receives on the half split out of its transport, and through
    /// the cell the group's face shares only where the transport split none; a receive half that
    /// failed ends the link as a lost carrier does. Turned red by a side that receives through the
    /// cell whatever the transport split (`GroupSide::new` passing `rx` over), or a carrier that
    /// does not read the half (`GroupSide::carrier_up`).
    #[test]
    fn a_groups_session_receives_on_the_half_split_out_of_its_transport() {
        let mut split = side(Some(alloc::boxed::Box::new(Half { failed: false })));
        assert_eq!(received(&mut split), b"half");
        assert!(split.carrier_up());
        let mut whole = side(None);
        assert_eq!(
            received(&mut whole),
            b"whole",
            "CONTROL: a transport whose halves are one"
        );
        let failed = side(Some(alloc::boxed::Box::new(Half { failed: true })));
        assert!(!failed.carrier_up(), "a failed receive half ends the link");
    }

    /// A receive half on socket 7, whose receive waits or not.
    struct Waiting(bool);

    impl GroupReceive for Waiting {
        fn recv_with(&mut self, _f: &mut dyn FnMut(&[u8], SocketAddr)) -> bool {
            false
        }

        fn input_wait(&self) -> Option<WaitOn> {
            Some(WaitOn::Socket(7))
        }

        fn awaits_input(&self) -> bool {
            self.0
        }

        fn close(&mut self) {}
    }

    /// A read waits in a group's receive only for the half's own input, on a half whose receive
    /// waits; it waits on any other input, or on a half whose receive returns at once, as it did.
    /// Turned red by a read that waits in a receive that returns at once (`awaits_on` without
    /// `GroupReceive::awaits_input`), which would turn the read with no wait at all, or in the
    /// receive of a group for another socket's input.
    #[test]
    fn a_read_waits_in_a_groups_receive_only_for_its_own_input() {
        let own = LinkWait::input(WaitOn::Socket(7));
        assert!(awaits_on(&Waiting(true), &own));
        assert!(
            !awaits_on(&Waiting(false), &own),
            "a receive that returns at once"
        );
        assert!(
            !awaits_on(&Waiting(true), &LinkWait::input(WaitOn::Socket(8))),
            "another socket's input"
        );
    }

    /// A group whose waits keep what `kept` says in turn, whose clock reads `clock` in turn, whose
    /// read is owed a turn from the reading `owed_at` on, and whose steps end the session or read
    /// to their bound as `ends` and `reads` say; each wait and step is noted with what it was asked.
    struct Script {
        kept: alloc::vec::Vec<bool>,
        clock: alloc::vec::Vec<u64>,
        owed_at: u64,
        ends: bool,
        reads: bool,
        waits: alloc::vec::Vec<(u64, u64)>,
        steps: alloc::vec::Vec<(usize, u64)>,
    }

    impl Script {
        fn new(kept: &[bool], clock: &[u64]) -> Self {
            Self {
                kept: kept.to_vec(),
                clock: clock.to_vec(),
                owed_at: u64::MAX,
                ends: false,
                reads: true,
                waits: alloc::vec::Vec::new(),
                steps: alloc::vec::Vec::new(),
            }
        }
    }

    impl AwaitedReads for Script {
        fn await_input(&mut self, timeout_us: u64, since_us: u64) -> bool {
            self.waits.push((timeout_us, since_us));
            !self.kept.is_empty() && self.kept.remove(0)
        }

        fn now_us(&mut self) -> u64 {
            if self.clock.is_empty() {
                u64::MAX
            } else {
                self.clock.remove(0)
            }
        }

        fn step(&mut self, most: core::num::NonZeroUsize, now_us: u64) -> bool {
            self.steps.push((most.get(), now_us));
            self.ends
        }

        fn read_to_bound(&self) -> bool {
            self.reads
        }

        fn owed(&mut self, now_us: u64) -> bool {
            now_us >= self.owed_at
        }
    }

    /// The bound of a read's steps in these tests.
    const MOST: core::num::NonZeroUsize = core::num::NonZeroUsize::MIN.saturating_add(7);

    /// A read that waits in a group's receive steps each datagram a wait kept, one a step, at the
    /// reading taken after its wait, and waits again for what is left of its time, measured from
    /// that reading; a wait that keeps nothing is stepped with the read's bound, and ends the
    /// reads. Turned red by reads that return to the read after the first datagram
    /// (`read_awaited` without its loop), which pays the read's turn once a datagram, or by a
    /// wait asked for its whole time again.
    #[test]
    fn a_waiting_read_steps_each_kept_datagram_and_waits_on_for_what_is_left() {
        let mut script = Script::new(&[true, true, true, false], &[10, 20, 30, 40]);
        assert!(!read_awaited(&mut script, MOST, 100, 0));
        assert_eq!(script.waits, [(100, 0), (90, 10), (80, 20), (70, 30)]);
        assert_eq!(script.steps, [(1, 10), (1, 20), (1, 30), (8, 40)]);
    }

    /// The reads end at the deadline, where the read owes the session a turn, at the session's
    /// end, and at a step that read nothing, each after the step of the datagram kept. Turned red
    /// by reads that wait past the read's deadline, that leave a turn owed to a later datagram, or
    /// that wait again on a session that ended or a datagram no step took.
    #[test]
    fn a_waiting_read_ends_at_its_deadline_a_turn_owed_an_end_and_a_step_that_read_none() {
        let mut deadline = Script::new(&[true, true, true], &[50, 100, 150]);
        assert!(!read_awaited(&mut deadline, MOST, 100, 0));
        assert_eq!(
            deadline.steps,
            [(1, 50), (1, 100)],
            "none past the deadline"
        );
        assert_eq!(deadline.waits, [(100, 0), (50, 50)]);

        let mut owed = Script::new(&[true, true, true], &[10, 20, 30]);
        owed.owed_at = 20;
        assert!(!read_awaited(&mut owed, MOST, 100, 0));
        assert_eq!(
            owed.steps,
            [(1, 10), (1, 20)],
            "the turn owed is the read's next"
        );

        let mut ended = Script::new(&[true, true], &[10, 20]);
        ended.ends = true;
        assert!(read_awaited(&mut ended, MOST, 100, 0), "the session ended");
        assert_eq!(ended.steps, [(1, 10)]);

        let mut none = Script::new(&[true, true], &[10, 20]);
        none.reads = false;
        assert!(!read_awaited(&mut none, MOST, 100, 0));
        assert_eq!(
            none.waits,
            [(100, 0)],
            "no wait again for a datagram no step took"
        );
    }
}
