// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The transport's part of a session ([`TransportState`]): its links, the ports it listens on and
//! the groups it joined, and the reads and refusals that touch nothing else of the session. What a
//! link coming up or going does to the session's tables, its replay and its watchers is the
//! session's to carry out, with the values these answer ([`FaceStep`]).
//!
//! The session's own records of a face and of a group are its engine's; the transport reads them
//! through [`FaceRecord`], [`TransportSession`] and [`GroupRecord`], named together by
//! [`TransportFaces`]. What the engine listens on, joins, answers and reports is the engine's
//! features of the same names, which it forwards to this crate.

#[cfg(feature = "group")]
use alloc::boxed::Box;
#[cfg(feature = "group")]
use alloc::vec::Vec;
use core::mem::MaybeUninit;
use core::ops::Deref;

use wz_session_core::byte_cells::LentByteCells;
use wz_session_core::driver_loop::{DriverOutcome, EventSink};
#[cfg(feature = "group")]
use wz_session_core::group_locator::parse_group_locator;
use wz_session_core::link::BoxedLinkDriver;
#[cfg(feature = "listen")]
use wz_session_core::link_admission::LinkAdmission;
#[cfg(feature = "listen")]
use wz_session_core::placed::PlacedRef;
#[cfg(all(feature = "queryable", feature = "group"))]
use wz_session_core::response_sink::ResponseSink;
use wz_session_core::session_actions::{HalvesMaking, LinkState, SessionCore, SessionLinkActions};
use wz_session_core::session_init_params::SessionInitParams;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::session_zid::SessionZid;
#[cfg(feature = "shared-key-ids")]
use wz_session_core::shared_key_ids::LinkKeyForms;
use wz_session_core::step_lend::LendCell;
use wz_session_core::unicast_rx::RouterLend;

#[cfg(feature = "group")]
use super::GroupRecord;
use super::{EndpointRefusal, LinkCalls, Refusal, TransportRefusal, TransportSession};
use crate::dial::Begun;
use crate::executor::SpawnRefusal;
#[cfg(feature = "listen")]
use crate::faces::Accepted;
use crate::faces::{
    DialAnswer, DialEndpoint, EndpointTexts, FaceId, FacePlaces, FaceRead, FaceRecord, FaceWire,
    IdleWait, LinkEnd, LinkSupervisor, TaskEnd, Wire,
};
#[cfg(feature = "group")]
use crate::group_transport::GroupTransport;
use crate::link_cells::{CellRc, CountKind, OneTask};
#[cfg(feature = "listen")]
use crate::locator_text::parse_listen_locator;
use crate::reassembly_rx::SessionReassembly;
use crate::session_drive::{
    place_session_with_router, spawn_session_with_router, LinkOpenError, LinkWait, OpenedLink,
    PumpFields, SessionDatagramLink, SessionDriveConfig, SessionLinks, SessionPump, SessionRole,
    WaitOn,
};
use crate::session_runtime::{EntropyCount, SessionEntropy, SessionHandle};
use crate::sync::LockKind;
use crate::{ClockSource, CoopLocalJoinHandle, CoopLocalSet, CoopRuntime, CoopTime};
use wz_session_core::link_life::{Effects, LinkPhase, LinkRole};

/// The runtime of a link's session over the transport of `T`, read under the lock type of the
/// values it lends the session.
type LinkRuntime<T> =
    CoopRuntime<<T as TransportFaces>::Clock, dyn BoxedLinkDriver, <T as TransportFaces>::Lock>;

/// The session of a link over the transport of `T` whose pump its owner holds and steps itself
/// ([`TransportState::place_link`]): it stages its fragments in the session's one Router, lent
/// through the place the link holds, as a task's pump does.
pub type LinkPump<T, P> = SessionPump<
    <T as TransportFaces>::Clock,
    P,
    dyn BoxedLinkDriver,
    RouterLend<SessionReassembly, <T as TransportFaces>::RouterPlace>,
    <T as TransportFaces>::Lock,
>;

/// The handle on the actions of a link's session over the transport of `T`.
type LinkHandle<T> =
    SessionHandle<<T as TransportFaces>::Clock, dyn BoxedLinkDriver, <T as TransportFaces>::Lock>;

/// The session's clock over the transport of `T`.
type LinkTime<T> = CoopTime<<T as TransportFaces>::Clock>;

/// The two halves of the actions of a link over the transport of `T`, not yet made.
type LinkHalves<T> = HalvesMaking<LinkRuntime<T>, LinkTime<T>>;

/// A handle on each half of the actions of a link over the transport of `T`, as they hold them.
type HalvesHeld<T> = (
    CellRc<LinkState<LinkRuntime<T>>, CountOf<T>>,
    CellRc<SessionCore<LinkRuntime<T>, LinkTime<T>>, CountOf<T>>,
);

/// How the handles on the parts of a link over the transport of `T` are counted: as the lock kind
/// of the values its session is lent counts them (`LockKind::LinkCount`).
type CountOf<T> = <<T as TransportFaces>::Lock as LockKind>::LinkCount;

/// How the handles on what the links over the transport of `T` share are counted (the session's
/// entropy): as the lock kind counts them (`LockKind::SharedCount`).
type SharedOf<T> = <<T as TransportFaces>::Lock as LockKind>::SharedCount;

/// The handle on the link a session over the transport of `T` sends and reads by, counted as the
/// link's parts are.
type LinkOf<T> = CellRc<dyn SessionDatagramLink, CountOf<T>>;

/// What a session's transport is made of: the session's clock, the network its links are opened
/// on, and the engine's records of the session's half of a link, of a face and of a group it
/// joined (`group`).
pub trait TransportFaces {
    /// The clock the session's links run on.
    type Clock: ClockSource + 'static;
    /// How the session's runtime locks the values it lends each link's session.
    type Lock: LockKind;
    /// The network the session's links, ports and groups are opened on.
    type Links: SessionLinks<<Self::Lock as LockKind>::LinkCount> + 'static;
    /// The session's half of one link.
    type Session: TransportSession<Self::Clock, Self::Lock>;
    /// What a face holds of its link while the link is up or in its handshake: the session's half
    /// of the link itself, or a handle on the place that holds it apart from the session's state.
    type Wire: FaceWire;
    /// The engine's record of one face.
    type Face: FaceRecord<
        <Self::Lock as LockKind>::LinkCount,
        Wire = Self::Wire,
        Pump = <Self::Links as SessionLinks<<Self::Lock as LockKind>::LinkCount>>::Pump,
        Dial = <Self::Links as SessionLinks<<Self::Lock as LockKind>::LinkCount>>::Dial,
    >;
    /// The table the engine keeps its faces in by their places: one face alone for a session that
    /// only dials, a place for each face for one that takes faces beside it; each place holds the
    /// dial under way of its face.
    type Places: FacePlaces<
        Self::Face,
        Dial = <Self::Links as SessionLinks<<Self::Lock as LockKind>::LinkCount>>::Dial,
    >;
    /// The engine's record of one group the session joined.
    #[cfg(feature = "group")]
    type Group: GroupRecord;
    /// The handle on the place the session lends its Router in ([`TransportState::lend`]): a
    /// counted cell, or one the session's arena holds.
    type RouterPlace: Deref<Target = LendCell<SessionReassembly>> + Clone + 'static;
    /// The Router as the transport holds it ([`TransportState::router`]): the session's one
    /// Router, or nothing where the session keeps its Router apart from its state, beside the
    /// pump of the one link it steps itself, so that a receive that lends the Router does so with
    /// nothing of the session's state held.
    type Router: TransportRouter;
}

/// The Router a transport holds of its session ([`TransportFaces::Router`]): what the transport
/// asks of it as a link is lost.
pub trait TransportRouter {
    /// End the chains the peer `zid` has under way.
    fn abort_peer_chains(&mut self, zid: &[u8]);
}

impl TransportRouter for SessionReassembly {
    fn abort_peer_chains(&mut self, zid: &[u8]) {
        // The count of the chains ended is the Router's own record, read by no caller here.
        let _ended = self.abort_peer(zid);
    }
}

/// A transport whose session keeps its Router apart holds none, and ends no chain of it: the
/// holder of the Router ends a lost peer's chains itself.
impl TransportRouter for () {
    fn abort_peer_chains(&mut self, _zid: &[u8]) {}
}

/// A dial under way over the network of `T`.
type DialOf<T> = <<T as TransportFaces>::Links as SessionLinks<CountOf<T>>>::Dial;
/// What the drive loop pumps for a link over the network of `T`.
type PumpOf<T> = <<T as TransportFaces>::Links as SessionLinks<CountOf<T>>>::Pump;
/// A link over the network of `T` that opened, as its session is made of it.
type OpenedOf<T> = OpenedLink<PumpOf<T>, CountOf<T>>;
/// What a dial over the network of `T` answered: the link it made, the refusal, or `None` while
/// it is under way.
type AnswerOf<T> = DialAnswer<PumpOf<T>, CountOf<T>>;

/// The transport of a session over the faces of [`crate::faces`]: the session's links and what
/// their handshakes and receives are handed. What a link coming up or going does to the session's
/// tables, its replay and its watchers is the session's to carry out, with the values this
/// answers.
pub struct TransportState<T: TransportFaces> {
    /// Whether the links' pool of outbound slots is smaller than the links (`TX_POOL_SLOTS`), so
    /// that a link may find every slot held by another link's frame its stream has not finished:
    /// a publish that may not be dropped then waits for a slot with nothing of the session held
    /// (the engine's publish to a link).
    #[cfg(feature = "listen")]
    pub tx_pool_short: bool,
    /// The session's faces, each at the place the session's tables name it by for as long as it
    /// is held, the dial role's at the first, which is never taken out, over the network their
    /// links are opened on: the faces' links, the dials
    /// under way, the ports listened on and a read's waits are the driver's
    /// (`wz_runtime_coop::faces`). What is declared is declared over each face, and a get is
    /// asked of each.
    pub links: LinkSupervisor<T::Links, T::Face, T::Places, CountOf<T>>,
    /// The texts of the endpoints the session dials and listens on, written once when it opened
    /// into rows of its arena: a dial and a port name their endpoint by its row, and the config's
    /// copies went with the open.
    pub endpoints: EndpointTexts,
    /// The multicast groups the session joined, each a face of its own (`group`).
    #[cfg(feature = "group")]
    pub groups: Vec<T::Group>,
    /// The zid in its wire form, which every handshake of the session announces.
    pub wire_zid: SessionZid,
    /// The session's say on a link to a node it holds a link to, asked while the link's handshake
    /// runs (`install_placed_link_admission`, `listen`): a handle of the admission the engine
    /// owns, which it drops after every link's actions and task.
    #[cfg(feature = "listen")]
    pub admission: PlacedRef<dyn LinkAdmission>,
    /// The cells each link's gates are placed in when the session makes the link, where they hold
    /// the link back (`LinkCalls::gate`), lent from the arena; none for a plan that laid out none.
    pub gate_cells: Option<LentByteCells<<CountOf<T> as CountKind>::Flag>>,
    /// The cells each link's actions are placed in when the session makes the link, lent from the
    /// arena; none for a plan that laid out none.
    pub actions_cells: Option<LentByteCells<<CountOf<T> as CountKind>::Flag>>,
    /// The cells the two halves of each link's actions are placed in together when the session
    /// makes the link (its own state and the session's kernel, `place_halves`), lent from the
    /// arena; none for a plan that laid out none, whose halves lie on the heap.
    pub halves_cells: Option<LentByteCells<<CountOf<T> as CountKind>::Flag>>,
    /// The key-wire form of each link the session opens: the session's, and the one stated for an
    /// endpoint apart from it (`shared-key-ids`).
    #[cfg(feature = "shared-key-ids")]
    pub key_forms: LinkKeyForms,
    /// The one reassembly Router of the session, which its links share: its chains are keyed by
    /// their peers where the session has several (`SessionPeers`), and staged in the session's
    /// buffers for them, each claimed by a chain while it is open, lent from the arena
    /// (`ArenaPlan::reassembly`). The session sweeps it and ends a
    /// lost peer's chains; its links' receives reach it only while the session's pass of its tasks
    /// lends it ([`RouterLend::lend_for`]). None where the session keeps it apart
    /// ([`TransportFaces::Router`]).
    pub router: T::Router,
    /// Where the session lends its Router to its links' receives, each link's task holding the
    /// place: lent for the length of a pass of the tasks and at no other time. A link whose owner
    /// steps it itself looks for its Router in a place of its own face's instead
    /// ([`PumpPlace::lend`]).
    pub lend: RouterLend<SessionReassembly, T::RouterPlace>,
}

/// What a step reads of a face and what its life makes of it ([`TransportState::face_step`]): the
/// face's role and what the session does about its link, and no more, so a step that leaves a face
/// as it is moves a few words. The answer of a dial, and the endpoint it dialled, are written where
/// the step asked for them.
pub struct FaceStep {
    /// Which face it is.
    pub role: LinkRole,
    /// What the session does about the face's link, in the order [`Effects`] names.
    pub effects: Effects,
}

/// What the making of a link's session is handed beside the link ([`TransportState::make_wire`]):
/// the parameters the session opens it with, and what it borrows of the session's driver (the set
/// its task runs on, its source of entropy, its clock and the deadlines of its handshake).
pub struct WireMaking<'a, C: ClockSource + 'static, N: EntropyCount = OneTask> {
    /// The parameters the link's session is opened with.
    pub params: SessionInitParams,
    /// The set the link's task is spawned on.
    pub local: &'a CoopLocalSet<C>,
    /// The session's one source of entropy, which every link's handshake draws from.
    pub entropy: &'a mut SessionEntropy<N>,
    /// The session's clock.
    pub clock: &'a CoopTime<C>,
    /// The deadlines of the link's handshake.
    pub timeouts: SessionTimeouts,
}

/// What a link the session places itself is opened as ([`TransportState::place_wire`]): the
/// face it serves, the role of its handshake, and the endpoint it was dialled to or taken on.
pub struct OpenedAs<'e> {
    /// The face the link serves.
    pub face: FaceId,
    /// The role of the link's handshake.
    pub role: SessionRole,
    /// The endpoint the link was dialled to or taken on, when it was dialled from the session's.
    pub endpoint: Option<&'e DialEndpoint>,
}

/// Where the session of a link its owner steps itself is built, and how the owner ends it
/// ([`TransportState::place_wire`]).
pub struct PumpPlace<'p, T: TransportFaces, E> {
    /// The place the pump is built in, which its owner drops it in.
    pub place: &'p mut MaybeUninit<LinkPump<T, LinkOf<T>>>,
    /// How the owner tells the link's session ended, and ends it.
    pub end: E,
    /// Where the pump's receive looks for the Router its owner lends it for each step: a place of
    /// the face the link serves, which no other face's pump looks in, so a pump reaches its own
    /// face's Router alone while another thread steps another face's.
    pub lend: RouterLend<SessionReassembly, T::RouterPlace>,
}

/// A link whose session its owner steps itself, made ([`TransportState::place_wire`]): the
/// wire its face keeps, what the session hands its reads to, and the pump, in its place.
pub struct PlacedWire<'p, T: TransportFaces, K: LinkCalls<T::Clock, T::Lock>, E> {
    /// The wire the face keeps.
    pub wire: Wire<K::Session, E, CountOf<T>>,
    /// What the owner hands each step of the pump.
    pub dispatch: K::Dispatch,
    /// The pump, in its place.
    pub pump: &'p mut LinkPump<T, LinkOf<T>>,
}

/// What the making of a link's session builds before the session runs
/// ([`TransportState::build_wire`]).
struct WireBuilt<T: TransportFaces, D, S> {
    fields: PumpFields<T::Clock, LinkOf<T>, dyn BoxedLinkDriver, T::Lock>,
    dispatch: D,
    session: S,
    link: LinkOf<T>,
    input_wait: Option<WaitOn>,
    room_wait: Option<WaitOn>,
}

impl<T: TransportFaces> TransportState<T> {
    /// The dial role's face, which the session holds for its whole life: the first of the faces,
    /// placed by the open, so `None` is a session no open made.
    pub fn dial(&self) -> Option<&T::Face> {
        self.links.face(0)
    }

    /// The face of the least id past `after` (any, for none) whose link is up, when `remote`:
    /// how a get walks the faces it asks one at a time, taking the session's lock for each and
    /// keeping no list of them. A face that comes up during the walk with a greater id is asked
    /// too, and one that goes is not.
    #[cfg(feature = "query")]
    pub fn next_up_face(&self, remote: bool, after: Option<FaceId>) -> Option<FaceId> {
        if !remote {
            return None;
        }
        self.links
            .faces()
            .filter(|face| face.up().is_some())
            .map(FaceRecord::id)
            .filter(|id| match after {
                Some(after) => *id > after,
                None => true,
            })
            .min()
    }

    /// The group of the least id past `after` (any, for none) the session asks queries of
    /// (`GroupDeclarations::asks_queries`), when `remote`: how a get walks its groups as it walks
    /// its faces ([`Self::next_up_face`]).
    #[cfg(all(feature = "query", feature = "group"))]
    pub fn next_group_to_ask(&self, remote: bool, after: Option<FaceId>) -> Option<FaceId> {
        if !remote {
            return None;
        }
        self.groups
            .iter()
            .filter(|group| group.asks_queries())
            .map(GroupRecord::id)
            .filter(|id| match after {
                Some(after) => *id > after,
                None => true,
            })
            .min()
    }

    /// Write on its group what the answers to a query that came in under `generation` put on the
    /// group's stage, on this thread, as a put on the group is written by the thread that puts it.
    /// Nothing is done for a query that came in on a link.
    #[cfg(all(feature = "queryable", feature = "group"))]
    pub fn write_answers(&self, generation: u64) {
        if let Some(group) = self
            .groups
            .iter()
            .find(|group| group.answer_sink(generation).is_some())
        {
            group.write_staged();
        }
    }

    /// The sink an answer to a query that came in on a group under `generation` goes through,
    /// while the group's session runs. A query that came in on a link is answered over that link,
    /// which the session finds by its own record of the face.
    #[cfg(all(feature = "queryable", feature = "group"))]
    pub fn group_answer_sink(&self, generation: u64) -> Option<&dyn ResponseSink> {
        self.groups
            .iter()
            .find_map(|group| group.answer_sink(generation))
    }

    /// Begin a dial of `endpoint`, which the network answers later: of the address it names, or of
    /// a host it names at the addresses the network resolves it to, the one dial of every
    /// endpoint ([`LinkSupervisor::begin_dial`]). [`TransportRefusal::Unreachable`] when the
    /// endpoint does not parse, names a host no dial of a name reaches over these links, or the
    /// network refuses the dial at once.
    // Always inlined: the dial role and a face added by the program each begin a dial, in the one
    // cold body of the faces' dial, which writes each refusal into its answer once.
    #[inline(always)]
    pub fn begin_dial(&self, endpoint: &str) -> Result<Begun<DialOf<T>>, TransportRefusal> {
        self.links.begin_dial(endpoint)
    }

    /// The text of the endpoint a dial reaches: the session's, by its row, or the one the dial
    /// named; empty for none.
    pub fn endpoint_text<'a>(&'a self, endpoint: Option<&'a DialEndpoint>) -> &'a str {
        endpoint.map_or("", |endpoint| endpoint.text(&self.endpoints))
    }

    /// A link to `endpoint` refused for want of a cell of the session's tables, as one past the
    /// stack's buffers is. Out of line: each part of a link a cell holds is refused by it.
    #[cold]
    #[inline(never)]
    pub fn cells_exhausted(&self, endpoint: Option<&DialEndpoint>) -> TransportRefusal {
        TransportRefusal::Unreachable(EndpointRefusal::new(
            self.endpoint_text(endpoint),
            Refusal::Link(LinkOpenError::Exhausted),
        ))
    }

    /// The actions of a link the session makes, placed in their cell of the session's table: a
    /// link past the cells is refused as one past the stack's buffers is. With `listen` the link
    /// has its place in the session's admission before its handshake runs, which asks it once the
    /// remote's zid is known: a second link to a node the session holds is refused there, with
    /// nothing declared over it by either end, and not closed after it came up.
    // Always inlined: its one caller held these values in its own frame.
    #[inline(always)]
    pub fn place_actions(
        &self,
        actions: SessionLinkActions<LinkRuntime<T>, LinkTime<T>>,
        role: SessionRole,
        endpoint: Option<&DialEndpoint>,
    ) -> Result<LinkHandle<T>, TransportRefusal> {
        let actions: LinkHandle<T> =
            CellRc::<_, CountOf<T>>::in_cells_of(self.actions_cells.as_ref(), actions)
                .map_err(|_| self.cells_exhausted(endpoint))?;
        #[cfg(feature = "listen")]
        actions
            .install_placed_link_admission(self.admission, matches!(role, SessionRole::Initiator));
        #[cfg(not(feature = "listen"))]
        let _ = role;
        Ok(actions)
    }

    /// The two halves of the actions of a link the session makes, its own state and the session's
    /// kernel, written together in their cell of the session's table, where they stay: a handle on
    /// each, as the actions hold them. Neither half is a value of a frame on the way to the cell.
    /// A link past the cells is refused as one past the stack's buffers is, its halves never made.
    // Always inlined, as the other steps of its one caller, `make_wire`, are.
    #[inline(always)]
    pub fn place_halves(
        &self,
        halves: LinkHalves<T>,
        endpoint: Option<&DialEndpoint>,
    ) -> Result<HalvesHeld<T>, TransportRefusal> {
        let write = |link: *mut LinkState<LinkRuntime<T>>,
                     kernel: *mut SessionCore<LinkRuntime<T>, LinkTime<T>>| {
            // SAFETY: `halves_in` hands the two fields of the pair its cell holds: each of its
            // half's type, apart from the other and holding nothing yet.
            unsafe { halves.write(link, kernel) }
        };
        // SAFETY: `HalvesMaking::write` leaves a whole value at each place when it returns.
        unsafe { CellRc::<_, CountOf<T>>::halves_in_of(self.halves_cells.as_ref(), write) }
            .ok_or_else(|| self.cells_exhausted(endpoint))
    }

    /// The key-wire form of a link dialled to or taken on `endpoint`: the one stated for the
    /// endpoint apart from the session's, or the session's (`shared-key-ids`).
    #[cfg(feature = "shared-key-ids")]
    pub fn key_form_of(
        &self,
        endpoint: Option<&DialEndpoint>,
    ) -> wz_session_core::policy::KeyWireForm {
        self.key_forms
            .form_of(endpoint.map(|endpoint| endpoint.text(&self.endpoints)))
    }

    /// Spawn the task of a link's session on `local`. The link's fragmented messages are staged
    /// by the session's one Router, which its links share, keyed by their peers, in buffers of the
    /// session's one table: a chain claims one when its first fragment arrives and gives it back
    /// when it ends, and a chain that finds none free is refused and counted. The link's task
    /// holds the place the Router is lent in. The runtime's cells were reserved at the open, one
    /// for each link the config admits: a link past them has no task to run its session.
    // Always inlined: its one caller held these values in its own frame.
    #[inline(always)]
    pub fn spawn_link<P, D>(
        &self,
        local: &CoopLocalSet<T::Clock>,
        fields: PumpFields<T::Clock, P, dyn BoxedLinkDriver, T::Lock>,
        dispatch: D,
    ) -> Result<CoopLocalJoinHandle<DriverOutcome>, TransportRefusal>
    where
        P: SessionDatagramLink + 'static,
        D: EventSink + 'static,
    {
        spawn_session_with_router(local, fields, self.lend.clone(), dispatch)
            .map_err(TransportRefusal::NoTask)
    }

    /// [`Self::spawn_link`] with no task: the link's session built in `place`, which its owner
    /// holds, steps itself and drops once no step of it is under way
    /// ([`place_session_with_router`]). Its receive looks for its Router in `lend`, the place of
    /// its owner's face, for the steps its owner lends the Router around. `None` when the Router
    /// could not be built in its place.
    // Always inlined: its one caller holds these values in its own frame.
    #[inline(always)]
    pub fn place_link<'p, P>(
        &self,
        place: &'p mut MaybeUninit<LinkPump<T, P>>,
        runtime: CoopRuntime<T::Clock, dyn BoxedLinkDriver, T::Lock>,
        fields: PumpFields<T::Clock, P, dyn BoxedLinkDriver, T::Lock>,
        lend: RouterLend<SessionReassembly, T::RouterPlace>,
    ) -> Option<&'p mut LinkPump<T, P>>
    where
        P: SessionDatagramLink + 'static,
    {
        place_session_with_router(place, runtime, fields, lend)
    }

    /// Open the link of the group `endpoint` names (`group`), read here once for every stack
    /// (`parse_group_locator`). A member's link is reported by the endpoint the group was joined
    /// by, in a row of `GROUP_ROW_LEN` bytes, which holds the bound of every kind the build joins:
    /// the reading refuses an endpoint past its kind's bound before the group is joined, so no row
    /// of this engine is held on the heap.
    #[cfg(feature = "group")]
    // Always inlined: its one caller held these values in its own frame.
    #[inline(always)]
    pub fn open_group(&self, endpoint: &str) -> Result<Box<dyn GroupTransport>, TransportRefusal> {
        let refused = |why| TransportRefusal::Group(EndpointRefusal::new(endpoint, why));
        let group =
            parse_group_locator(endpoint).map_err(|why| refused(Refusal::GroupEndpoint(why)))?;
        self.links
            .links()
            .open_group(endpoint, &group)
            .map_err(|why| refused(Refusal::Link(why)))
    }

    /// Hold the group the session joined as the face whose id was the next (`group`).
    #[cfg(feature = "group")]
    pub fn add_group(&mut self, group: T::Group) {
        self.links.advance_face_id();
        self.groups.push(group);
    }

    /// End the chains the peer `peer` of a link that is lost has under way in the session's Router:
    /// the Router the session's links share would otherwise splice the fragments of the peer's
    /// next link onto them. A session that keeps its Router apart ends them where it keeps it.
    pub fn end_peer_chains(&mut self, peer: &SessionZid) {
        self.router.abort_peer_chains(peer.as_slice());
    }

    /// Whether the session holds a transport, as zenoh-pico's `_z_transport_get_common` finds
    /// one: a link that is up, a port it listens on (a peer's unicast transport stands before any
    /// peer comes), or a group it joined. A client whose router went away holds none until a dial
    /// of it succeeds again.
    pub fn holds_transport(&self) -> bool {
        #[cfg(feature = "group")]
        if !self.groups.is_empty() {
            return true;
        }
        #[cfg(feature = "listen")]
        if self.listens() {
            return true;
        }
        self.links.faces().any(|face| face.up().is_some())
    }

    /// Whether the session listens on any port.
    #[cfg(feature = "listen")]
    pub fn listens(&self) -> bool {
        self.links.listens()
    }

    /// Listen on every endpoint the config lists. [`TransportRefusal::Listen`] for the first that
    /// does not parse, that the network opens no listener for, or whose port is taken; a build
    /// without `listen` answers every endpoint so.
    pub fn listen_on_config(&mut self) -> Result<(), TransportRefusal> {
        #[cfg(feature = "listen")]
        for row in 0..self.endpoints.listens() {
            let endpoint = self.endpoints.listen_text(row);
            let refused = |why| TransportRefusal::Listen(EndpointRefusal::new(endpoint, why));
            let at =
                parse_listen_locator(endpoint).map_err(|why| refused(Refusal::Locator(why)))?;
            // The key-wire form of a link taken on the port is the one stated for its endpoint
            // (`shared-key-ids`), which the port names by its row.
            #[cfg(feature = "shared-key-ids")]
            let named = Some(row);
            #[cfg(not(feature = "shared-key-ids"))]
            let named = None;
            self.links
                .listen(at, named)
                .map_err(|why| refused(Refusal::Link(why)))?;
        }
        #[cfg(not(feature = "listen"))]
        if self.endpoints.listens() > 0 {
            return Err(TransportRefusal::Listen(EndpointRefusal::new(
                self.endpoints.listen_text(0),
                Refusal::ListeningNotBuilt,
            )));
        }
        Ok(())
    }

    /// Whether a link of the session holds input it has already taken from its stack, or a group
    /// took a datagram its next step reads: what makes a read's wait none ([`Self::idle_wait`]).
    pub fn holds_input(&self) -> bool {
        #[cfg(feature = "group")]
        if self.group_took_input() {
            return true;
        }
        self.links.holds_input()
    }

    /// Whether the dial role's face has what an open waits for: its link is up, or it stands by
    /// for the node it reached, which another face holds (with `listen`).
    pub fn dial_settled(&self) -> bool {
        self.dial()
            .is_some_and(|face| matches!(face.life().phase(), LinkPhase::Up | LinkPhase::Held))
    }

    /// What became of the link of the face at `at`, numbered `id`, read off it at `now_us` with
    /// the face's role, and what the session does about it, which the face's life decides: the
    /// session carries it out, with the answer of a dial and the endpoint it dialled, written to
    /// `answer` and `dialled` when the dial answered ([`LinkSupervisor::read_face`]). A face past
    /// the table asks for nothing.
    // Always inlined: its one caller held these values in its own frame.
    #[inline(always)]
    pub fn face_step(
        &mut self,
        at: usize,
        id: FaceId,
        now_us: u64,
        answer: &mut AnswerOf<T>,
        dialled: &mut Option<DialEndpoint>,
    ) -> FaceStep {
        let FaceRead { role, input } = self.links.read_face(at, id, now_us, answer, dialled);
        // The face is read out of line, so its role is a value here; a table of the dial role's
        // face alone holds no other role, which this step then knows when compiled.
        let role = if self.links.takes_faces() {
            role
        } else {
            LinkRole::Dial
        };
        let effects = self.links.face_mut(at).map_or(Effects::default(), |face| {
            face.life_mut().input(input, now_us)
        });
        FaceStep { role, effects }
    }

    /// End the handshake of the face at `at` that is over, and say why: the Close its peer sent,
    /// its task's end, or its deadline. Its task is told to stop, and ends in the session's next
    /// pass of its tasks; the link is let go of then by the caller.
    pub fn end_handshake(&self, at: usize) -> Refusal {
        let why = Refusal::from(self.links.handshake_end(at));
        self.links.abort_link(at);
        why
    }

    /// The session of the link `opened` as face `face`, in `role`, dialled to or taken on
    /// `endpoint` and opened with `making`'s parameters: its actions and their halves placed in their cells, its
    /// pump behind the gates the session puts it behind (`calls`), placed in theirs, and its task
    /// spawned. What the session's tables keep of the link is the session's to do (`LinkCalls`).
    /// [`TransportRefusal::EntropyUnavailable`] when an acceptor's source is dry, since its
    /// binding would refuse every handshake; [`TransportRefusal::HeapRefused`] when the heap has
    /// no room for the link's shared handle.
    // Always inlined: its one caller is never inlined, so what is built here lies in that frame,
    // which has returned before the link's task first runs.
    #[inline(always)]
    pub fn make_wire<K: LinkCalls<T::Clock, T::Lock>>(
        &self,
        calls: &mut K,
        face: FaceId,
        opened: OpenedOf<T>,
        role: SessionRole,
        endpoint: Option<&DialEndpoint>,
        making: WireMaking<'_, T::Clock, SharedOf<T>>,
    ) -> Result<Wire<K::Session, TaskEnd, CountOf<T>>, TransportRefusal>
    where
        K::Dispatch: EventSink + 'static,
    {
        let local = making.local;
        let built = self.build_wire(calls, face, opened, role, endpoint, making)?;
        let task = self.spawn_link(local, built.fields, built.dispatch)?;
        Ok(Wire::new(
            built.session,
            task,
            built.link,
            built.input_wait,
            built.room_wait,
        ))
    }

    /// [`Self::make_wire`] with no task: the link's session built in `place`, which its owner
    /// holds and steps itself ([`Self::place_link`]), ended by `end`. The wire, what the link's
    /// session hands its reads to, which the owner hands each step of the pump, and the pump.
    /// [`TransportRefusal::NoTask`] when the pump could not be built in its place.
    // Always inlined, as `make_wire` is: its one caller is never inlined.
    #[inline(always)]
    pub fn place_wire<'p, K: LinkCalls<T::Clock, T::Lock>, E: LinkEnd>(
        &self,
        calls: &mut K,
        opened: OpenedOf<T>,
        opened_as: OpenedAs<'_>,
        making: WireMaking<'_, T::Clock, SharedOf<T>>,
        place: PumpPlace<'p, T, E>,
    ) -> Result<PlacedWire<'p, T, K, E>, TransportRefusal> {
        let runtime = making.local.runtime().retyped();
        let OpenedAs {
            face,
            role,
            endpoint,
        } = opened_as;
        let built = self.build_wire(calls, face, opened, role, endpoint, making)?;
        let PumpPlace { place, end, lend } = place;
        let pump = self
            .place_link(place, runtime, built.fields, lend)
            .ok_or(TransportRefusal::NoTask(SpawnRefusal::NoTaskCell))?;
        Ok(PlacedWire {
            wire: Wire::new(
                built.session,
                end,
                built.link,
                built.input_wait,
                built.room_wait,
            ),
            dispatch: built.dispatch,
            pump,
        })
    }

    /// What [`Self::make_wire`] and [`Self::place_wire`] share: the link's actions and their
    /// halves placed in their cells, the session's tables told of the link, its pump behind the
    /// gates, placed in theirs, and the parts the session's pump is built of.
    #[inline(always)]
    fn build_wire<K: LinkCalls<T::Clock, T::Lock>>(
        &self,
        calls: &mut K,
        face: FaceId,
        opened: OpenedOf<T>,
        role: SessionRole,
        endpoint: Option<&DialEndpoint>,
        making: WireMaking<'_, T::Clock, SharedOf<T>>,
    ) -> Result<WireBuilt<T, K::Dispatch, K::Session>, TransportRefusal> {
        let OpenedLink { sink, pump } = opened;
        let WireMaking {
            params,
            local: _,
            entropy,
            clock,
            timeouts,
        } = making;
        // The link's halves lie in its cell of the session's table, as its actions do: a link made
        // after the open takes no memory of the heap for them.
        let actions = SessionLinkActions::<LinkRuntime<T>, LinkTime<T>>::build_held(
            sink,
            params,
            clock.clone(),
            |halves| self.place_halves(halves, endpoint),
        )?;
        let actions = self.place_actions(actions, role, endpoint)?;
        // An acceptor mints a cookie at each InitAck from a nonce its binding draws from the
        // session's source, and one whose source is dry refuses every handshake (fail closed): a
        // source that is dry now is not a link to accept.
        #[cfg(feature = "listen")]
        if matches!(role, SessionRole::Acceptor)
            && wz_session_core::entropy::EntropySource::try_next_u64(&mut *entropy).is_err()
        {
            return Err(TransportRefusal::EntropyUnavailable);
        }
        // One handle to the link, which its gates hold: a stack whose pump is a shared handle
        // already gives that one (`SessionLinks::share_pump`). Had before the session's tables
        // learn of the link, so a heap with no room for it leaves them as they were.
        let pump = <T::Links as SessionLinks<CountOf<T>>>::share_pump(pump)
            .ok_or(TransportRefusal::HeapRefused)?;
        #[cfg(feature = "shared-key-ids")]
        let key_form = Some(self.key_form_of(endpoint));
        #[cfg(not(feature = "shared-key-ids"))]
        let key_form = None;
        calls.link_made(face, &actions, key_form);

        // What the session's read waits on for the link's input and its room, read off it before
        // its gates take it.
        let (input_wait, room_wait) = (pump.input_wait(), pump.room_wait());
        // The gates take a cell of the session's table where they hold the link back, and a link
        // past the cells is refused as one past the buffers is.
        let gate = calls
            .gate(pump, &actions, self.gate_cells.as_ref())
            .ok_or_else(|| self.cells_exhausted(endpoint))?;
        let link = K::gated_link(&gate);
        let (dispatch, session) = calls.wire_parts(face, actions.clone(), &gate);
        Ok(WireBuilt {
            fields: PumpFields {
                link: link.clone(),
                actions,
                entropy: entropy.clone(),
                clock: clock.clone(),
                config: SessionDriveConfig {
                    timeouts,
                    role,
                    max_iters: None,
                },
            },
            dispatch,
            session,
            link,
            input_wait,
            room_wait,
        })
    }

    /// Begin a dial of the session's endpoint at row `row` for the face at `at` and ask it once
    /// ([`LinkSupervisor::ask_dial`]): one the network has not answered yet is put in the face,
    /// and `None` is handed back; one answered at once is handed back with its answer.
    /// [`TransportRefusal::Unreachable`] when the endpoint does not parse or the network refuses
    /// the dial at once.
    // Always inlined: its one caller held these values in its own frame.
    #[inline(always)]
    pub fn dial_row(&mut self, at: usize, row: usize) -> Result<AnswerOf<T>, TransportRefusal> {
        let begun = self.begin_dial(self.endpoints.dial_text(row))?;
        Ok(self.links.ask_dial(at, DialEndpoint::Listed(row), begun))
    }

    /// The link a dial of `endpoint` answered with, or why it is none: the endpoint and the
    /// network's refusal.
    pub fn dialled(
        &self,
        endpoint: Option<&DialEndpoint>,
        answer: Result<OpenedOf<T>, LinkOpenError>,
    ) -> Result<OpenedOf<T>, TransportRefusal> {
        answer.map_err(|refused| {
            TransportRefusal::Unreachable(EndpointRefusal::new(
                self.endpoint_text(endpoint),
                Refusal::Link(refused),
            ))
        })
    }

    /// The next connection that waits on the ports the session listens on, from port `*at` on,
    /// with the endpoint its port is stated for. A port that had no socket or buffer for one just
    /// now is passed, and looked at again on the next step; one that is broken for good is let
    /// go of, and the port after it is at `*at` then. `None` once every port was looked at.
    #[cfg(feature = "listen")]
    // Always inlined: its one caller held these values in its own frame.
    #[inline(always)]
    pub fn next_accepted(&mut self, at: &mut usize) -> Option<(OpenedOf<T>, Option<DialEndpoint>)> {
        while let Some(accepted) = self.links.accept_at(*at) {
            match accepted {
                Accepted::Link(opened, endpoint) => return Some((opened, endpoint)),
                Accepted::Idle => *at = at.saturating_add(1),
                Accepted::Broken => {}
            }
        }
        None
    }

    /// Whether a group took a datagram its next step reads (`group`): it is stepped again at
    /// once, its task taking one a step.
    #[cfg(feature = "group")]
    pub fn group_took_input(&self) -> bool {
        self.groups.iter().any(GroupRecord::took_input)
    }

    /// Whether a group took a datagram this step reads, leaving the mark for the read that asks
    /// [`Self::group_took_input`] (`group`).
    #[cfg(feature = "group")]
    pub fn group_holds_input(&self) -> bool {
        self.groups.iter().any(GroupRecord::holds_input)
    }

    /// When a group's session is next due with nothing arriving, in whole milliseconds of the
    /// session's clock rounded up (`group`): its beacon, its sweep, what the session pushed onto
    /// it, its join again.
    #[cfg(feature = "group")]
    pub fn groups_due_ms(&self) -> Option<u64> {
        self.groups
            .iter()
            .filter_map(GroupRecord::due_us)
            .min()
            .map(|due_us| due_us.div_ceil(1_000))
    }

    /// Whether a group's stack gives no wait for its input, so the group is looked at on its tick
    /// (`group`).
    #[cfg(feature = "group")]
    pub fn group_unwaited(&self) -> bool {
        self.groups.iter().any(GroupRecord::unwaited)
    }

    /// What a read waits on for at most `most` milliseconds: the input of every link and port, and
    /// each group's after them, since a wait over several is made by the first and a link's names a
    /// group's socket to the platform beside its own; `beside` ends it as well. `now_us` reads the
    /// session's clock, once, and only for a face with a time to be looked at again.
    pub fn idle_wait(
        &mut self,
        most: u32,
        now_us: &mut dyn FnMut() -> u64,
        beside: Option<LinkWait>,
    ) -> IdleWait {
        #[cfg(feature = "group")]
        let others = self.groups.iter().filter_map(GroupRecord::input);
        #[cfg(not(feature = "group"))]
        let others = core::iter::empty();
        self.links.idle_wait(most, now_us, others, beside)
    }

    /// Ask each group's session to stop, so that its next step tells the group it leaves and lets
    /// the group's link go; whether the session joined any (`group`).
    #[cfg(feature = "group")]
    pub fn stop_groups(&self) -> bool {
        for group in &self.groups {
            group.stop();
        }
        !self.groups.is_empty()
    }
}
