// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The read of a session that steps each face's link session itself, the dial role's and, with
//! `listen`, each a port gave or an attach dialled, then, with `group`, each group's session,
//! and hands each record out as it is read: a build without `threads`, and with `threads` one
//! whose form gives each value a lock of its own (`build.rs`). A connection a port holds is taken
//! by the read with no face's slot held, and its face's place is taken before the session's lock
//! (`CoopEngine::accept_links`). A group's session lies in a read slot the session holds between
//! two reads, taken out of it for each step and stepped, with other threads, under the session's
//! lock but while a record it read is handed out (`CoopEngine::step_groups`).
//!
//! The link's session lies in the engine's face ([`DirectFace`]), apart from the session's state,
//! in two parts as a send and a receive use it: the receive (the pump, what its steps are handed,
//! and the Router its fragments are staged in) behind the lock the read holds while it steps the
//! pump, and the send (the link's wire) in a place of its own that every send takes, whatever its
//! thread. Each record the pump reads is dispatched under the session's lock, which is then let
//! go of, and handed out to its callback before the next record is read. A callback so finds the
//! session free and what the records before its own did, may send on the session while the link
//! lends the frame it reads, and reads nothing when it reads the session: the face is held. A send
//! never waits for a read's step, nor for a callback inside it: the step does not hold the send's
//! place. A close from a callback ends the link's life and asks its
//! session to end; the pump goes once the read that steps it has returned from it.
//!
//! With `threads` the read task makes this read beside the program's calls, and a face's send place
//! is a lock of its own (`DirectLock`): a send on any thread waits for another send on the face,
//! never for the read. Its holder may then wait for the session's lock, so a look at a face's life,
//! which holds that lock, changes the face's place only by a try, and a change the try finds held
//! is owed to the read, which carries it out once the lock is let go of
//! (`DirectSlot::pay_site`).
//!
//! Where the link stands is the life of the face's record ([`UnicastLink`]), the session's one
//! record of it, as in a build whose links are tasks: the engine's face holds what the life's
//! effects are carried out with (the dial under way, the link it made, the pump) and nothing of
//! where the link stands.

use super::*;

use core::marker::PhantomData;
#[cfg(not(any(feature = "listen", feature = "group")))]
use core::mem::ManuallyDrop;
use core::mem::MaybeUninit;
use core::ptr::addr_of_mut;
use core::sync::atomic::AtomicBool;

#[cfg(feature = "resource-snapshot")]
use wz_runtime_coop::faces::MessageCount;
#[cfg(not(any(feature = "listen", feature = "group")))]
use wz_runtime_coop::faces::SiteSend;
use wz_runtime_coop::faces::{
    Dial, FaceAt, FaceSite, LinkEnd, ReadFacts, SendParts, WireParts, WriteMark,
};
use wz_runtime_coop::link_cells::{FaceHeld, FaceParts};
use wz_runtime_coop::session_drive::LinkOpenError;
#[cfg(not(feature = "threads"))]
use wz_runtime_coop::sync::ConfinedOwner;
use wz_runtime_coop::transport::{LinkPump, OpenedAs, PlacedWire, PumpPlace};
use wz_session_core::driver_loop::DriverLoopOutcome;
use wz_session_core::link_life::{LinkInput, LinkPhase, Refused};

use super::registry::Planes;
#[cfg(feature = "listen")]
use wz_session_core::bounded::{BoundedVec, Lent};
use wz_session_core::response_sink::{DeclareReplySink, LivelinessGetPrune, ResponseSink};

/// The pump of the session's one link, which the read steps itself.
type DirectPump<L, C> = LinkPump<Face<C, L>, CellRc<dyn SessionDatagramLink, LinkCount>>;

/// What the read and the link's end share of the link's session: whether its pump ended, and
/// whether the session asked it to end. Read and written with loads and stores: the pump's end is
/// read by the read that steps it, and the session asks while the read may hold the pump.
#[derive(Default)]
pub(super) struct EndFlags {
    ended: AtomicBool,
    asked: AtomicBool,
}

impl EndFlags {
    /// A link whose session neither ended nor was asked to.
    fn ready(&self) {
        self.ended.store(false, Ordering::Release);
        self.asked.store(false, Ordering::Release);
    }

    /// Whether the link's session ended, or was asked to.
    fn over(&self) -> bool {
        self.ended.load(Ordering::Acquire) || self.asked.load(Ordering::Acquire)
    }
}

/// How the session of the one link the read steps itself ends ([`LinkEnd`]): as the read's last
/// step of the pump said, and, asked by the session, once the read has returned from the pump.
pub(crate) struct DirectEnd {
    flags: NonNull<EndFlags>,
}

impl DirectEnd {
    /// Whether this is the end of the face whose flags are `flags`: each face's flags lie in the
    /// face, so they name it.
    #[cfg(any(feature = "listen", feature = "group"))]
    pub(super) fn is_of(&self, flags: &EndFlags) -> bool {
        core::ptr::eq(self.flags(), flags)
    }

    /// The flags the end reads and writes.
    fn flags(&self) -> &EndFlags {
        // SAFETY: the flags are a field of the engine's face, which lies in the engine's place
        // from the engine's making to its drop. A wire, which holds this end, is reached only
        // through the engine's state: by the engine's drop before its fields go, and not after,
        // as an end does nothing in its own drop.
        unsafe { self.flags.as_ref() }
    }
}

impl LinkEnd for DirectEnd {
    fn finished(&self) -> bool {
        self.flags().ended.load(Ordering::Acquire)
    }

    fn abort(&self) {
        self.flags().asked.store(true, Ordering::Release);
    }
}

/// What the records a read hands out of a face are answered through, beside the session's
/// tables: a link's actions, which answer its one peer, or a group's replies, which answer its
/// members on the group's stage.
pub(crate) trait RecordActions {
    /// What the dispatch of the face's records stages its replies and its answers on.
    type Sink: ResponseSink + DeclareReplySink + LivelinessGetPrune;

    /// The sink the face's records are answered through.
    fn sink(&self) -> &Self::Sink;

    /// The peer the face's records come from, as a declaration watch hears it.
    #[cfg(any(
        feature = "remote-declaration-watch",
        feature = "declarations-synced-event"
    ))]
    fn record_peer(&self) -> Option<wz_session_core::session_zid::SessionZid>;

    /// Keep the key form of each query `event` carries by an id of the shared dictionary, so a
    /// reply on its key mirrors it.
    #[cfg(all(feature = "queryable", feature = "shared-key-ids"))]
    fn keep_request_keys(&self, event: &IterationEvent<'_, '_>);
}

/// A link's records are answered by its session's actions, to its one peer.
// Written for the handle's own type rather than `LinkHandle<C>`: that alias is a projection of
// the runtime's handle type, out of which an impl's header cannot read `C`. The two are one type
// in every build of the engine, its handles counted by `LinkCount` (`form`'s check of the
// session lock's count).
impl<C: ClockSource + 'static> RecordActions for CellRc<LinkActions<C>, LinkCount> {
    type Sink = LinkActions<C>;

    #[inline(always)]
    fn sink(&self) -> &Self::Sink {
        self
    }

    #[cfg(any(
        feature = "remote-declaration-watch",
        feature = "declarations-synced-event"
    ))]
    fn record_peer(&self) -> Option<wz_session_core::session_zid::SessionZid> {
        self.peer_session_zid()
    }

    #[cfg(all(feature = "queryable", feature = "shared-key-ids"))]
    fn keep_request_keys(&self, event: &IterationEvent<'_, '_>) {
        self.note_requests(event);
    }
}

/// A group's records are answered on the group's stage, to its members, none of which is the
/// one peer a declaration watch is told of, and none of which names a key by the shared
/// dictionary a reply mirrors.
#[cfg(feature = "group")]
impl RecordActions for super::group::GroupReplies {
    type Sink = Self;

    #[inline(always)]
    fn sink(&self) -> &Self {
        self
    }

    #[cfg(any(
        feature = "remote-declaration-watch",
        feature = "declarations-synced-event"
    ))]
    fn record_peer(&self) -> Option<wz_session_core::session_zid::SessionZid> {
        None
    }

    #[cfg(all(feature = "queryable", feature = "shared-key-ids"))]
    fn keep_request_keys(&self, _event: &IterationEvent<'_, '_>) {}
}

/// What the read hands each step of a face's pump with, beside the engine: the face the pump
/// serves, what its records are answered through (a link's actions, a group's replies), and the
/// session's planes the dispatch of a record writes ([`FaceDispatch`] in a build whose links run
/// as tasks).
pub(crate) struct FaceRecords<A> {
    pub(super) face: HeldFace,
    pub(super) actions: A,
    #[cfg(feature = "queryable")]
    pub(super) plane: PlacedRef<QueryPlane>,
    /// The face's generation, which the queries it carries are answered under.
    #[cfg(feature = "queryable")]
    pub(super) generation: u64,
    /// Whether Pushes were dispatched whose drains are still owed ([`EventSink::end_records`]).
    pub(super) after_pushes: bool,
}

/// The records of a link, answered by its session's actions.
pub(super) type LinkRecords<C> = FaceRecords<LinkHandle<C>>;

// Written for the handle's own type rather than `LinkRecords<C>`, as `RecordActions`'s impl for a
// link's actions is: the alias's handle is a projection, out of which an impl's header cannot
// read `C`.
impl<C: ClockSource + 'static> FaceRecords<CellRc<LinkActions<C>, LinkCount>> {
    /// What the link whose records these are says of its peer once its handshake completed
    /// (`UpFacts`), read off the records' own handle on the link's actions.
    fn up_facts(&self) -> UpFacts {
        let facts = UpFacts::of_actions(&*self.actions);
        #[cfg(feature = "queryable")]
        {
            facts.under(self.generation)
        }
        #[cfg(not(feature = "queryable"))]
        {
            facts
        }
    }
}

impl<A: RecordActions> FaceRecords<A> {
    /// Dispatch `event`, a record that is not a Push lent where its frame lies, to the planes
    /// `planes` names of the face's tables in `registry`, the held session's, and send what it
    /// staged.
    #[cfg(feature = "queryable")]
    fn dispatch(&self, registry: &mut Registry, event: IterationEvent<'_, '_>, planes: Planes) {
        let face = self.face;
        // What the declaration watches are told of this frame is this face's peer's.
        #[cfg(any(
            feature = "remote-declaration-watch",
            feature = "declarations-synced-event"
        ))]
        registry.hear_decl_link(|| self.actions.record_peer());
        registry.dispatch_event_to(face, event, planes);
        registry.flush_pending_replies(face, self.actions.sink());
        self.owe_finals(registry);
    }

    /// Owe the `Final`s the dispatch of the face's records staged
    /// (`Registry::take_pending_final_rids`), each as `Self::owe_final` owes it.
    #[cfg(feature = "queryable")]
    pub(super) fn owe_finals(&self, registry: &mut Registry) {
        for (rid, qos) in registry.take_pending_final_rids(self.face) {
            self.owe_final(rid, qos);
        }
    }

    /// The query `rid` of the face owes its `Final`, of `qos`: sent now when nothing holds it,
    /// and otherwise once the last callback or kept query holding it lets go.
    #[cfg(feature = "queryable")]
    pub(super) fn owe_final(&self, rid: wz_session_core::wire_id::RequestId, qos: QosLevel) {
        if self
            .plane
            .with_holds(|holds| holds.owe(self.generation, rid, qos))
        {
            self.actions.sink().send_response_final(rid, qos);
        }
    }

    /// Keep the key form of each query `event` carries by an id of the shared dictionary, so a
    /// reply on its key mirrors it.
    #[cfg(all(feature = "queryable", feature = "shared-key-ids"))]
    pub(super) fn note_requests(&self, event: &IterationEvent<'_, '_>) {
        self.actions.keep_request_keys(event);
    }

    /// A build without the shared key ids keeps no key form of a query.
    #[cfg(all(feature = "queryable", not(feature = "shared-key-ids")))]
    pub(super) fn note_requests(&self, _event: &IterationEvent<'_, '_>) {}

    /// See the build with queryables: one without has no query to owe a Final.
    #[cfg(not(feature = "queryable"))]
    fn dispatch(&self, registry: &mut Registry, event: IterationEvent<'_, '_>, planes: Planes) {
        // What the declaration watches are told of this frame is this face's peer's.
        #[cfg(any(
            feature = "remote-declaration-watch",
            feature = "declarations-synced-event"
        ))]
        registry.hear_decl_link(|| self.actions.record_peer());
        registry.dispatch_to(self.face, event, planes, self.actions.sink());
    }
}

/// What a step of the one link's pump hands its records to: each dispatched under the session's
/// lock, which is let go of before the record is handed out, so its callback finds the session
/// free and the next record is read after the callback returned.
struct DirectSink<'a, L: CoopLinks + 'static, C: ClockSource + Clone + 'static, A> {
    engine: &'a CoopEngine<L, C>,
    records: &'a mut FaceRecords<A>,
}

impl<L: CoopLinks + 'static, C: ClockSource + Clone + 'static, A: RecordActions>
    DirectSink<'_, L, C, A>
{
    /// The drains a run of Pushes put off ([`Registry::settle`]), once for the run: at the end of
    /// the frame, or before the first record of it that is not a Push (`within_frame`), which a
    /// test counts as a build whose links are tasks does (`FaceDispatch`). What the drains leave
    /// to hand out is the read's to hand out, once after every face and group it stepped
    /// (`CoopEngine::read_faces`, `CoopEngine::read_dial`), or the next record's of the frame.
    fn drain_pushes(&mut self, within_frame: bool) {
        if !core::mem::take(&mut self.records.after_pushes) {
            return;
        }
        {
            let Some(mut held) = self.engine.live() else {
                return;
            };
            let registry = &mut held.0.session.registry;
            #[cfg(all(test, feature = "std", feature = "queryable"))]
            if within_frame {
                registry.count_drain_within_frame();
            }
            registry.settle(self.records.face, self.records.actions.sink());
        }
        #[cfg(not(all(test, feature = "std", feature = "queryable")))]
        let _ = within_frame;
    }
}

impl<L: CoopLinks + 'static, C: ClockSource + Clone + 'static, A: RecordActions> EventSink
    for DirectSink<'_, L, C, A>
{
    fn event(&mut self, event: IterationEvent<'_, '_>) {
        let push = lent_push(&event);
        if !push {
            // The member a group's walk names ahead of each datagram's records is read by none of
            // the session's planes: dispatched, it would hand the face's tables out to a write and
            // so owe the read its bookkeeping for every datagram of a stream of samples.
            if matches!(event, IterationEvent::MulticastSource(_)) {
                return;
            }
            // What the Pushes before this record put off is done before it, as it was after each.
            self.drain_pushes(true);
        }
        match event {
            // Handed to its subscribers one at a time (`pinned`), none of it into the round.
            // What its callbacks left to hand out is handed out with the drains of its run
            // (`Self::drain_pushes`), once for the run rather than once a Push.
            IterationEvent::InPlace(ref record) if push => {
                self.engine.hand_lent_push(self.records.face, record);
                self.records.after_pushes = true;
                return;
            }
            // Handed to the get it answers with the session let go of (`replies`), none of it
            // into the round.
            #[cfg(feature = "query")]
            IterationEvent::InPlace(ref record) if record.response().is_some() => {
                self.engine.hand_lent_reply(self.records.face, record);
            }
            // A ResponseFinal is read by the pending gets alone: handed to them by its kind, as
            // a Push is to the subscribers, and what follows it is put off alike, the get it ends
            // handed out by the read's delivery.
            #[cfg(feature = "query")]
            IterationEvent::InPlace(ref record) if record.is_reply() => {
                if let Some(mut held) = self.engine.live() {
                    held.0
                        .session
                        .registry
                        .dispatch_reply(self.records.face, record);
                }
                self.records.after_pushes = true;
                return;
            }
            // Handed to each queryable it reaches with the session let go of (`queries`), none of it
            // into the round, a Request the lent form does not represent by its owned projection.
            #[cfg(feature = "queryable")]
            IterationEvent::InPlace(ref record) if record.request().is_some() => {
                self.engine.hand_lent_query(self.records, record, &event);
            }
            // A peer's token is handed to each liveliness subscriber it reaches with the session
            // let go of (`tokens`), an alive token answering a pending liveliness get to that get
            // as a reply is; the rest of a declaration is dispatched as every record is.
            #[cfg(feature = "liveliness")]
            IterationEvent::InPlace(ref record) if record.declare().is_some() => {
                self.engine.hand_lent_declare(self.records, record, event);
            }
            // The subscribers' side of each record first, a Push's sample handed out one row at a
            // time, then the other planes', as the dispatch of the whole frame orders them.
            IterationEvent::Poll(DriverLoopOutcome::FramePayload {
                messages, reliable, ..
            }) => {
                // A query by an id of the shared dictionary is kept before any queryable is handed
                // it, so its replies mirror its key form.
                #[cfg(feature = "queryable")]
                self.records.note_requests(&event);
                if let Some(messages) = wz_session_core::driver_loop::owned_records(messages) {
                    self.engine
                        .hand_copied_records(self.records, messages, *reliable);
                }
                let Some(mut held) = self.engine.live() else {
                    return;
                };
                self.records.dispatch(
                    &mut held.0.session.registry,
                    event,
                    Planes::BesideSubscribers,
                );
            }
            // A frame of plain Puts is the subscribers' alone, handed out one row at a time; what
            // follows it is put off as what follows a lent Push is.
            IterationEvent::Poll(DriverLoopOutcome::FramePlainPuts {
                reliable,
                payload,
                puts,
                ..
            }) => {
                if wz_session_core::driver_loop::OWNED_RECORDS {
                    self.engine
                        .hand_plain_puts(self.records.face, payload, puts, *reliable);
                }
                self.records.after_pushes = true;
                return;
            }
            event => {
                let Some(mut held) = self.engine.live() else {
                    return;
                };
                self.records
                    .dispatch(&mut held.0.session.registry, event, Planes::All);
            }
        }
        self.engine.deliver();
    }

    /// A closed session takes no record past the one whose callback closed it.
    fn takes_another(&mut self) -> bool {
        !self.engine.closed.load(Ordering::Acquire)
    }

    fn end_records(&mut self) {
        self.drain_pushes(false);
    }

    /// The walk never stops on a full round: each record is handed out as it is read.
    fn holds_datagram(&self) -> bool {
        false
    }

    // No record reads a rejoined message past its walk: the message is let go of as each walk
    // over it ends, as the sink's default does.
}

/// A group's pump taken out of its place by a read that waits in the group's receive, stepped
/// by the read's engine ([`super::group::read_awaited`]).
#[cfg(feature = "group")]
struct AwaitedGroup<'a, L: CoopLinks + 'static, C: ClockSource + Clone + 'static> {
    engine: &'a CoopEngine<L, C>,
    pump: &'a mut super::group::GroupPump<C>,
}

#[cfg(feature = "group")]
impl<L: CoopLinks + 'static, C: ClockSource + Clone + 'static> super::group::AwaitedReads
    for AwaitedGroup<'_, L, C>
{
    #[inline]
    fn await_input(&mut self, timeout_us: u64, since_us: u64) -> bool {
        self.pump.await_input(timeout_us, since_us)
    }

    #[inline]
    fn now_us(&mut self) -> u64 {
        self.pump.now_us()
    }

    #[inline]
    fn step(&mut self, most: core::num::NonZeroUsize, now_us: u64) -> bool {
        self.engine.step_group(self.pump, most, now_us)
    }

    #[inline]
    fn read_to_bound(&self) -> bool {
        self.pump.read_to_bound()
    }

    #[inline]
    fn owed(&mut self, now_us: u64) -> bool {
        self.engine.read_owed(now_us)
    }
}

/// The owner of the place of the one link's parts ([`DirectFace`]).
#[cfg(not(feature = "threads"))]
pub(super) enum DirectOwner {}

// SAFETY: a session whose read steps its one link itself is built in the form of one thread
// (`OneThread`, as `threads` is off): the program calls into the engine from one thread at a
// time, so the place of the link's send part, reached by every send and by the read's making and
// dropping of the link, is reached by one thread at a time, and its value never moves to another
// while a lend of it is under way.
#[cfg(not(feature = "threads"))]
unsafe impl ConfinedOwner for DirectOwner {}

/// How the place of the one link's parts is held: by the one thread of the session's form.
#[cfg(not(feature = "threads"))]
type DirectLock = wz_runtime_coop::sync::Confined<DirectOwner>;

/// How the place of a face's link's parts is held where a read task reads beside the program's
/// calls: by a lock of its own, of the kind the session's runtime lends each link's values in,
/// since a send of any thread takes the place while the read steps the face's pump.
#[cfg(feature = "threads")]
type DirectLock = SessionLock;

// Such a read reaches a face's values with no session's lock held, which only a lock of each
// value's own keeps to one thread at a time: a form with none keeps the round (`build.rs`).
#[cfg(feature = "threads")]
const _: fn(PhantomData<SessionLock>) -> PhantomData<wz_runtime_coop::sync::ManyThreads> =
    core::convert::identity;

/// The link the session's record of the face holds while it is up or in its handshake: a handle
/// on the place of the link's parts, which holds none of them.
pub(super) type DirectWire<L, C> = FaceAt<DirectLock, DirectParts<L, C>, DirectEnd>;

/// The place of the one link's send part.
type DirectSite<L, C> = FaceSite<DirectLock, DirectParts<L, C>>;

/// One face's send place an operation holds, taken before the session's lock: the face, named
/// by the flags its link's end shares with the read, the face's wire while the place holds one,
/// and the place held before it, so the places an operation holds are one chain on its stack.
#[cfg(any(feature = "listen", feature = "group"))]
pub(super) struct HeldSend<'a, C: ClockSource + 'static> {
    face: &'a EndFlags,
    wire: Option<&'a Wire<C>>,
    before: Option<&'a HeldSend<'a, C>>,
}

/// An operation run with every face's send place held, then the session's lock
/// (`CoopEngine::live_on_link`), on the session's state and the places it holds. Reached by a
/// vtable of its one method: a closure's vtable would carry a `call_once` shim beside it, into
/// which a small operation is copied whole.
#[cfg(any(feature = "listen", feature = "group"))]
trait UnderHeldFaces<L: CoopLinks + 'static, C: ClockSource + Clone + 'static> {
    /// Run the operation, once.
    fn run(&mut self, core: &mut Core<L, C>, tx: LinkTx<'_, C>);
}

/// The operation `f`, run at most once, and what it answered.
#[cfg(any(feature = "listen", feature = "group"))]
struct HeldOperation<F, U> {
    f: Option<F>,
    answer: Option<U>,
}

#[cfg(any(feature = "listen", feature = "group"))]
impl<L, C, F, U> UnderHeldFaces<L, C> for HeldOperation<F, U>
where
    L: CoopLinks + 'static,
    C: ClockSource + Clone + 'static,
    F: FnOnce(&mut Core<L, C>, LinkTx<'_, C>) -> U,
{
    fn run(&mut self, core: &mut Core<L, C>, tx: LinkTx<'_, C>) {
        if let Some(f) = self.f.take() {
            self.answer = Some(f(core, tx));
        }
    }
}

/// What an operation holds of the faces' send places, taken before the session's lock
/// (`CoopEngine::live_on_link`, `CoopEngine::on_faces`): a send to a held face writes the
/// wire its hold holds; a send to any other face is lent that face's link by a try of its place,
/// which waits for nothing under the session's lock (`super::send_through`). A build that takes
/// no face beside the dial role's holds that face's place alone, and every face's record names
/// that face, so what it holds is the face's wire: no walk finds it and no try reaches past it.
pub(super) struct FaceTx<'a, C: ClockSource + 'static> {
    #[cfg(any(feature = "listen", feature = "group"))]
    held: Option<&'a HeldSend<'a, C>>,
    /// The place of the face a publish's leg through it holds alone (`CoopEngine::on_faces`);
    /// `None` for an operation's hold, which reaches every face.
    #[cfg(any(feature = "listen", feature = "group"))]
    alone: Option<usize>,
    /// The dial role's wire while its place holds one; a place that holds none is not held, and
    /// a try of it would find no link either.
    #[cfg(not(any(feature = "listen", feature = "group")))]
    wire: Option<&'a Wire<C>>,
}

/// The place a publish's leg to the session's groups holds alone (`FaceTx::reaches_groups`):
/// past every face's, so the leg reaches no face's link, no face is asked for its room on its
/// behalf (`LinkRooms::within_face` finds no place there), and no send marked on a face is its.
/// A send on a group is marked at this place (`CoopEngine::publish_to_groups`), so a droppable
/// leg to the groups behind one is dropped as a face's leg behind a send on its face is
/// (`LinkRooms::for_held`): its mark is below those of a holder that sends on no face
/// (`NOT_SENDING`, `WAITING`, `PUBLISHING`), which the last places' marks are.
#[cfg(feature = "group")]
pub(super) const GROUPS_LEG: usize = usize::MAX - 3;

impl<C: ClockSource + 'static> Clone for FaceTx<'_, C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C: ClockSource + 'static> Copy for FaceTx<'_, C> {}

impl<'a, C: ClockSource + 'static> FaceTx<'a, C> {
    /// The hold of the face whose record holds `link`, when its place is held.
    #[cfg(any(feature = "listen", feature = "group"))]
    #[inline]
    fn held_of<L: CoopLinks + 'static>(
        &self,
        link: &DirectWire<L, C>,
    ) -> Option<&'a HeldSend<'a, C>> {
        core::iter::successors(self.held, |held| held.before)
            .find(|held| link.end().is_of(held.face))
    }

    /// Whether `link`, a face's record of its link, lies in a face whose place is held.
    #[cfg(any(feature = "listen", feature = "group"))]
    #[inline]
    pub(super) fn holds<L: CoopLinks + 'static>(&self, link: &DirectWire<L, C>) -> bool {
        self.held_of(link).is_some()
    }

    /// The wire of the face whose record holds `link`, through its held place, found by one walk
    /// of the holds: `None` while that place is not held, and `Some(None)` while it is held and
    /// holds no link, which no try of the place reaches either.
    #[cfg(any(feature = "listen", feature = "group"))]
    #[inline]
    pub(super) fn held_wire<L: CoopLinks + 'static>(
        &self,
        link: &DirectWire<L, C>,
    ) -> Option<Option<&'a Wire<C>>> {
        self.held_of(link).map(|held| held.wire)
    }

    /// The wire of the dial role's face, which every record's link names in a build that takes
    /// no other: always reached through the hold, so no send under it falls back to a try.
    #[cfg(not(any(feature = "listen", feature = "group")))]
    #[inline(always)]
    pub(super) fn held_wire<L: CoopLinks + 'static>(
        &self,
        _link: &DirectWire<L, C>,
    ) -> Option<Option<&'a Wire<C>>> {
        Some(self.wire)
    }

    /// Whether a publish's leg sent through this hold goes to the face whose record holds
    /// `link`: a hold of one face for a leg of its own reaches that face alone, as each face's
    /// leg is sent under its own hold, and an operation's hold reaches every face.
    #[cfg(any(feature = "listen", feature = "group"))]
    #[inline(always)]
    pub(super) fn reaches<L: CoopLinks + 'static>(&self, link: &DirectWire<L, C>) -> bool {
        self.alone.is_none() || self.holds(link)
    }

    /// Whether a publish's leg sent through this hold goes to the session's groups: an
    /// operation's hold reaches every face and every group, and a publish reaches the groups by
    /// the one leg of its own that holds no face's place (`CoopEngine::on_faces`, at
    /// [`GROUPS_LEG`]), so each group is sent a publish once, whatever the faces it is sent on.
    #[cfg(feature = "group")]
    #[inline(always)]
    pub(super) fn reaches_groups(&self) -> bool {
        self.alone.is_none() || self.held.is_none()
    }

    /// Every leg reaches the dial role's face where it is the only face: a publish hands a leg
    /// only to a face whose place it holds.
    #[cfg(not(any(feature = "listen", feature = "group")))]
    #[inline(always)]
    pub(super) fn reaches<L: CoopLinks + 'static>(&self, _link: &DirectWire<L, C>) -> bool {
        true
    }

    /// The wire of the face a publish's leg holds alone, while its place holds one: what the
    /// leg's send writes with that face's send place held and nothing of the session. `None`
    /// for a hold that reaches every face, or a place that holds no link.
    #[cfg(any(feature = "listen", feature = "group"))]
    pub(super) fn alone_wire(&self) -> Option<&'a Wire<C>> {
        self.held
            .filter(|_| self.alone.is_some())
            .and_then(|held| held.wire)
    }

    /// The dial role's wire, while its place holds one: every leg holds that face alone.
    #[cfg(not(any(feature = "listen", feature = "group")))]
    pub(super) fn alone_wire(&self) -> Option<&'a Wire<C>> {
        self.wire
    }

    /// The place of the face a publish's leg holds alone, which a droppable leg that finds the
    /// session held answers for (`LinkRooms::for_held`); `None` for a hold that reaches every
    /// face.
    #[cfg(any(feature = "listen", feature = "group"))]
    pub(super) fn leg_place(&self) -> Option<usize> {
        self.alone
    }

    /// The dial role's face, at the first place, which every leg holds alone.
    #[cfg(not(any(feature = "listen", feature = "group")))]
    pub(super) fn leg_place(&self) -> Option<usize> {
        Some(0)
    }

    /// Wait for room for a blocking message of `priority` on the link of the face a publish's
    /// leg holds alone, with that face's send place held and nothing of the session
    /// (`SessionLinkActions::wait_for_wire_room`). A hold that reaches every face, or a place
    /// that holds no link, waits for nothing: the send answers for itself.
    pub(super) fn wait_for_room(
        &self,
        priority: wz_session_core::qos::Priority,
    ) -> Result<wz_session_core::session_actions::WireRoom, SendWireError> {
        match self.alone_wire() {
            Some(wire) => wire.actions.wait_for_wire_room(priority),
            None => Ok(wz_session_core::session_actions::WireRoom::Send),
        }
    }
}

/// What an operation holds where the dial role's face is the only face
/// (`CoopEngine::live_on_link`): the session's state, and the face's send place, taken before
/// it, both let go of in one body as the hold drops, the session's lock first.
#[cfg(not(any(feature = "listen", feature = "group")))]
struct DialHeld<'a, L: CoopLinks + 'static, C: ClockSource + 'static> {
    core: ManuallyDrop<LiveCore<'a, L, C>>,
    send: ManuallyDrop<Option<SiteSend<'a, DirectLock, DirectParts<L, C>>>>,
    /// The wire `send` reaches, found once as the place was held: it lies in the face's place,
    /// not in the hold, so it stays where it is while the hold is moved and kept.
    wire: Option<NonNull<Wire<C>>>,
}

#[cfg(not(any(feature = "listen", feature = "group")))]
impl<L: CoopLinks + 'static, C: ClockSource + 'static> DialHeld<'_, L, C> {
    /// The session's state, and what an operation sends through: the face's wire while its
    /// place is held and holds one.
    #[inline(always)]
    fn parts(&mut self) -> (&mut Core<L, C>, LinkTx<'_, C>) {
        // SAFETY: the wire lies in the face's place, which does not move (`DirectFace`) and which
        // `send` holds for as long as `self` lives, so no other holder reaches it meanwhile; the
        // operation reaches it only through the shared borrow handed out here, which ends with
        // the borrow of `self`, and nothing of `self` writes it.
        let wire = self.wire.map(|wire| unsafe { wire.as_ref() });
        (&mut self.core.0, FaceTx { wire })
    }
}

#[cfg(not(any(feature = "listen", feature = "group")))]
impl<L: CoopLinks + 'static, C: ClockSource + 'static> Drop for DialHeld<'_, L, C> {
    // Out of line, as `LiveCore`'s drop is: every operation lets the session and the face's place
    // go through this one body.
    #[inline(never)]
    fn drop(&mut self) {
        // SAFETY: this is the hold's drop, so the session is let go of once and nothing reads it
        // after; it goes before the place, which was taken before it.
        unsafe { ManuallyDrop::drop(&mut self.core) };
        // SAFETY: as the session's, once and last.
        unsafe { ManuallyDrop::drop(&mut self.send) };
    }
}

/// The send part of the one link's session, held in the face's place apart from the session's
/// state and from the receive part the read steps (`DirectSlot`): the link's wire, which a send
/// writes. The pump's stack is the link's own, so the parts name it.
pub(super) struct DirectParts<L: CoopLinks + 'static, C: ClockSource + 'static> {
    /// The link's session, which the session's sends are lent.
    wire: Option<Wire<C>>,
    of: PhantomData<fn() -> L>,
}

// SAFETY: the one handle on a cell of the link that the parts hold (the wire's actions) is made by
// the link's making (`CoopEngine::place_link_session`), under the session's lock with the read's
// slot held, and dropped by the read with its slot held too (`DirectSlot::drop_link`): the
// session's record of the face holds a handle on the place, none on the parts, and a send reaches
// the wire only through a hold of the place; the one handle the record keeps on a cell of the link
// (`resource-snapshot`, the kernel's, `KernelCount`) is made and dropped under the session's lock.
// The receive part's handles on the same cells (the pump's link, the records' actions) are made
// and dropped by the read alone, under its slot; the cells they share are reached through the
// link's own cells, of the session's lock kind. Nothing of the parts is bound to a thread, and
// their place is reached by one thread at a time: the one of the session's form (`DirectOwner`),
// or, with `threads`, the holder of the place's own lock (`DirectLock`); a change of the place
// a look at the life could not make under the session's lock is the read's, with its slot held
// (`DirectSlot::pay_site`).
unsafe impl<L: CoopLinks + 'static, C: ClockSource + 'static> FaceParts for DirectParts<L, C> {}

impl<L: CoopLinks + 'static, C: ClockSource + 'static> DirectParts<L, C> {
    /// The parts of the link whose wire is `wire`.
    fn holding(wire: Wire<C>) -> Self {
        Self {
            wire: Some(wire),
            of: PhantomData,
        }
    }
}

impl<L: CoopLinks + 'static, C: ClockSource + 'static> WireParts for DirectParts<L, C> {
    type Wire = Wire<C>;

    #[cfg(feature = "resource-snapshot")]
    type Count = KernelCount<C>;

    fn wire(&self) -> Option<&Wire<C>> {
        self.wire.as_ref()
    }

    /// The parts define no debt of their own: every send of the session reaches the wire through
    /// the link's place, taken before the session's lock, and waits for its holder, so none is
    /// owed.
    fn pay(&mut self, _owed: u32) {}
}

/// `resource-snapshot` — what the session's record of the one link keeps of what the link's
/// receive path counts: a handle on the link's kernel, whose meter that path counts into, apart
/// from the place of the link's parts, so the record reads and retires the link with no lend of
/// that place.
/// Made with the link's wire, before the wire goes into its place, and dropped with the record's
/// handle on the place, both under the session's lock; the kernel's cell is given back once the
/// parts' handles go too.
#[cfg(feature = "resource-snapshot")]
pub(super) struct KernelCount<C: ClockSource + 'static>(
    CellRc<SessionCore<LinkRuntime<C>, CoopTime<C>>, LinkCount>,
);

#[cfg(feature = "resource-snapshot")]
impl<C: ClockSource + 'static> MessageCount for KernelCount<C> {
    fn reading(&self) -> wz_session_core::resource_snapshot::BuildMessageReading {
        self.0.rx_intervals.reading()
    }
}

/// A send writes the link's wire, through a hold of its place.
impl<L: CoopLinks + 'static, C: ClockSource + 'static> SendParts for DirectParts<L, C> {
    type Tx = Option<Wire<C>>;

    fn tx(&mut self) -> &mut Option<Wire<C>> {
        &mut self.wire
    }
}

/// The one link's life, its receive part and what its effects are carried out with, behind the
/// face's lock: the read holds it while it steps the pump. The pump is made in its place here, at
/// the engine's fixed place, and stays there until it is dropped.
pub(super) struct DirectSlot<L: CoopLinks + 'static, C: ClockSource + 'static> {
    /// The face's row in the session's table of faces, which its life and its link lie at.
    at: usize,
    /// The pump of the link, written while `records` is held.
    pump: MaybeUninit<DirectPump<L, C>>,
    /// What each step of the pump is handed, held exactly while the pump is written.
    records: Option<LinkRecords<C>>,
    /// The session's one Router, which the pump's receive is lent for each read.
    router: SessionReassembly,
    /// Where the Router is lent to the pump's receive.
    lend: RouterLend<SessionReassembly, RouterPlace>,
    /// The dial the life asked for, while the network has not answered it.
    dial: Option<Dial<L::Dial>>,
    /// The link a dial made, and the endpoint it reached, until its handshake is begun.
    opened: Option<(OpenedLink<L::Pump, LinkCount>, DialEndpoint)>,
    /// Why the last endpoint tried came to no link: what the session ends with when the life
    /// ends it.
    last: Option<OpenError>,
    /// When the life is next to be looked at, on the session's clock in microseconds.
    life_due_us: u64,
    /// When the pump's own deadlines fall next: 0 for a pump not stepped yet, `u64::MAX` while no
    /// pump is written.
    pump_due_us: u64,
    /// Whether the life brought the link up since the read last told it the replay's first turn
    /// (`CoopEngine::turn_replay`).
    brought_up: bool,
    /// The due the face last showed outside its slot (`DirectFace::note_due`), so that only a
    /// change of it is written there.
    #[cfg(any(feature = "listen", feature = "group"))]
    noted_us: u64,
    /// The change of the face's send place a look at the life made under the session's lock and
    /// found held by another thread: the place emptied (`Some(None)`) or given these parts, the
    /// ones it holds let go of. Carried out once the lock is let go of (`Self::pay_site`).
    #[cfg(feature = "threads")]
    site_owed: Option<Option<FaceHeld<DirectParts<L, C>>>>,
}

impl<L: CoopLinks + 'static, C: ClockSource + 'static> DirectSlot<L, C> {
    /// The face's row in the session's table of faces. The face table's first, a constant, where
    /// the dial role's face is the only face: every look of the face's life and link up in the
    /// table is then made at a place the build knows.
    #[inline(always)]
    fn at(&self) -> usize {
        #[cfg(any(feature = "listen", feature = "group"))]
        {
            self.at
        }
        #[cfg(not(any(feature = "listen", feature = "group")))]
        {
            debug_assert_eq!(
                self.at, 0,
                "the dial role's face lies at the table's first row"
            );
            0
        }
    }

    /// When the face is next due by its life or its pump, on the session's clock in microseconds.
    fn due_us(&self) -> u64 {
        self.life_due_us.min(self.pump_due_us)
    }

    /// Tell `site`, the face's send place, what the step of the pump begun at `mark` left of
    /// the link, read off the read's own handles on it (the pump's link and the records' actions),
    /// so a look at the face lends nothing of the place: whether the link owes its stack a write,
    /// its input and its session's state, and, with `listen`, the node it reached, once. The
    /// read is the facts' one teller (`SiteFacts`): it holds this slot. Nothing while no pump
    /// is written.
    fn tell_facts(&self, site: &DirectSite<L, C>, mark: WriteMark) {
        let Some(records) = self.records.as_ref() else {
            return;
        };
        // SAFETY: the records are held exactly while the pump is written in its place.
        let link = unsafe { self.pump.assume_init_ref() }.link();
        let facts = site.facts();
        facts.wrote(mark, link.owes_write());
        let actions = &records.actions;
        facts.tell(ReadFacts::of_link(
            link,
            actions.is_established(),
            actions.close_reason(),
        ));
        // The node a refused handshake's admission was asked about counts as the node its link
        // reached, as the record's own read of it does (`LinkSession::node`).
        #[cfg(feature = "listen")]
        if !facts.has_node() {
            if let Some(node) = actions
                .peer_session_zid()
                .or_else(|| actions.link_admission_node())
            {
                facts.tell_node(&node);
            }
        }
    }

    /// Drop the pump, when one is written, and what its steps are handed: its deadlines go with
    /// it. The wire stays, for the session's record of the link to close.
    fn drop_pump(&mut self) {
        if self.records.take().is_some() {
            // SAFETY: the records are held exactly while the pump is written in its place
            // (`CoopEngine::place_link_session`), and no step of it is under way: a step holds
            // the slot borrowed, as this does.
            unsafe { self.pump.assume_init_drop() };
        }
        // A deadline of the pump left behind would have each read's wait end at once while no
        // pump is stepped to move it on.
        self.pump_due_us = u64::MAX;
    }

    /// Drop the link whole, as the session's record of the link goes: its pump, then its wire in
    /// `site`. Never inside a lend of the place.
    fn drop_link(&mut self, site: &DirectSite<L, C>) {
        self.drop_pump();
        self.empty_site(site);
    }

    /// Empty `site`, the face's send place, of the parts it holds, under the session's lock.
    #[cfg(not(feature = "threads"))]
    #[inline(always)]
    fn empty_site(&mut self, site: &DirectSite<L, C>) {
        drop(site.take());
    }

    /// Put `parts` in `site`, the face's send place, letting go of the ones it held, under the
    /// session's lock.
    #[cfg(not(feature = "threads"))]
    #[inline(always)]
    fn fill_site(&mut self, site: &DirectSite<L, C>, parts: FaceHeld<DirectParts<L, C>>) {
        drop(site.hold(parts));
    }

    /// What a look at the life owed the face's send place: none where the place is never held
    /// by another thread.
    #[cfg(not(feature = "threads"))]
    #[inline(always)]
    fn pay_site(&mut self, _site: &DirectSite<L, C>) {}

    /// Empty `site`, the face's send place, of the parts it holds, under the session's lock: by a
    /// try, since a send that holds the place may wait for that lock, and owed when the try finds
    /// the place held (`Self::pay_site`). Parts owed to the place and not put in it go.
    #[cfg(feature = "threads")]
    fn empty_site(&mut self, site: &DirectSite<L, C>) {
        self.site_owed = None;
        match site.try_take() {
            wz_runtime_coop::sync::Lend::Held => self.site_owed = Some(None),
            wz_runtime_coop::sync::Lend::Lent(parts) => drop(parts),
            wz_runtime_coop::sync::Lend::Empty => {}
        }
    }

    /// Put `parts` in `site`, the face's send place, letting go of the ones it held, under the
    /// session's lock: by a try, and owed when the try finds the place held, as
    /// [`Self::empty_site`] does.
    #[cfg(feature = "threads")]
    fn fill_site(&mut self, site: &DirectSite<L, C>, parts: FaceHeld<DirectParts<L, C>>) {
        self.site_owed = None;
        match site.try_hold(parts) {
            Ok(held) => drop(held),
            Err(parts) => self.site_owed = Some(Some(parts)),
        }
    }

    /// Carry out the change of `site` a look at the life owed it, with the session's lock let go
    /// of and the slot held: the place taken, waiting for a send that holds it, as a read takes a
    /// face's place before the session's lock.
    #[cfg(feature = "threads")]
    fn pay_site(&mut self, site: &DirectSite<L, C>) {
        match self.site_owed.take() {
            None => {}
            Some(None) => drop(site.take()),
            Some(Some(parts)) => drop(site.hold(parts)),
        }
    }

    /// Let go of the link: the dial and the link it made are let go of, and the pump goes. The
    /// life of the face's record was closed by the session's end of its links (`end_links`).
    fn let_go(&mut self) {
        self.dial = None;
        self.opened = None;
        self.drop_pump();
        #[cfg(feature = "threads")]
        {
            self.site_owed = None;
        }
    }

    /// Let go of all the face's link held, its wire in `site` too, as a face taken beside the dial
    /// role's goes with its link: the row is the next taken face's as the open made it.
    #[cfg(feature = "listen")]
    fn clear(&mut self, site: &DirectSite<L, C>) {
        self.let_go();
        self.empty_site(site);
        self.last = None;
        self.brought_up = false;
        self.life_due_us = u64::MAX;
    }
}

impl<L: CoopLinks + 'static, C: ClockSource + 'static> Drop for DirectSlot<L, C> {
    fn drop(&mut self) {
        self.drop_pump();
    }
}

impl<L: CoopLinks + 'static, C: ClockSource + Clone + 'static> DirectSlot<L, C> {
    /// The id of the face whose row the slot is: read off the face's record, or, where the dial
    /// role's face is the only face, that face's own, which the build knows.
    fn face_id(&self, core: &Core<L, C>) -> Option<FaceId> {
        #[cfg(any(feature = "listen", feature = "group"))]
        {
            core.transport.links.face(self.at()).map(|face| face.id)
        }
        #[cfg(not(any(feature = "listen", feature = "group")))]
        {
            debug_assert!(
                core.transport
                    .links
                    .face(0)
                    .is_some_and(|face| face.id == DIAL_FACE),
                "the dial role's face keeps its row and its id"
            );
            Some(DIAL_FACE)
        }
    }

    /// What the link brings to its life at this look, at `now_us`: a handshake completed, a pump
    /// that ended or was asked to, a dial the network answered, or only the time. With `listen`
    /// the dial role's face reads the node its link reached too (`Self::read_node`), and a dial an
    /// attach left in the face's record is taken into the slot first (`Self::take_owed_dial`).
    fn next_input(&mut self, core: &mut Core<L, C>, end: &EndFlags, now_us: u64) -> LinkInput {
        // The face's record holds the link exactly while its parts hold the pump.
        let linked = core
            .transport
            .links
            .face(self.at())
            .filter(|face| face.link.wire().is_some());
        if let Some(face) = linked {
            let phase = face.life.phase();
            let established = matches!(phase, LinkPhase::Handshaking { .. })
                && face.link.wire().is_some_and(|wire| wire.established());
            if established {
                return LinkInput::Established;
            }
            let input = if end.over() {
                LinkInput::Ended
            } else {
                LinkInput::Tick
            };
            // A handshake is over once its link ended or its deadline passed.
            #[cfg(feature = "listen")]
            {
                let over = match phase {
                    LinkPhase::Handshaking { deadline_us, .. } => {
                        input == LinkInput::Ended || now_us >= deadline_us
                    }
                    _ => false,
                };
                return self.read_node(core, input, over);
            }
            #[cfg(not(feature = "listen"))]
            return input;
        }
        #[cfg(not(feature = "listen"))]
        let _ = now_us;
        #[cfg(feature = "listen")]
        self.take_owed_dial(core);
        match self.take_dial_answer(core) {
            Some(input) => input,
            #[cfg(feature = "listen")]
            None => self.read_node(core, LinkInput::Tick, false),
            #[cfg(not(feature = "listen"))]
            None => LinkInput::Tick,
        }
    }

    /// What the node the dial role's face reached makes of `input`, read off its link (`over` once
    /// its handshake is over): a handshake over at a node another face holds stands the face by
    /// for it, and a face that stands by dials again once no face holds the node, as the round's
    /// read of a face reads it (`LinkSupervisor::read_dial_node`). A taken face's input is as it
    /// came.
    #[cfg(feature = "listen")]
    fn read_node(&self, core: &mut Core<L, C>, input: LinkInput, over: bool) -> LinkInput {
        let at = self.at();
        let Some((id, phase)) = core
            .transport
            .links
            .face(at)
            .map(|face| (face.id, face.life.phase()))
        else {
            return input;
        };
        core.transport
            .links
            .read_dial_node(at, id, phase, input, over)
    }

    /// Take into the slot the dial an attach left in the face's record
    /// (`CoopEngine::attach_face`), which holds the session's lock and not the face's place: a
    /// change of the face's site it owes the face's read, which looks at the life in this turn.
    #[cfg(feature = "listen")]
    fn take_owed_dial(&mut self, core: &mut Core<L, C>) {
        let at = self.at();
        let owed = core
            .transport
            .links
            .face(at)
            .is_some_and(|face| matches!(face.link, Link::Dialing(_)));
        if !owed {
            return;
        }
        let Some(face) = core.transport.links.face_mut(at) else {
            return;
        };
        if let Link::Dialing(dial) = core::mem::replace(&mut face.link, Link::Idle) {
            self.dial = Some(dial);
            self.life_due_us = 0;
        }
    }

    /// Dial the session's endpoint at `row`, as the life asked: what the dial came to at once.
    fn dial_row(&mut self, core: &Core<L, C>, row: usize) -> LinkInput {
        self.dial = None;
        let transport = &core.transport;
        match transport.begin_dial(transport.endpoints.dial_text(row)) {
            Ok(begun) => self.dial = Some(Dial::begun(DialEndpoint::Listed(row), begun)),
            Err(refused) => {
                self.last = Some(OpenError::from(refused));
                return LinkInput::DialRefused;
            }
        }
        self.take_dial_answer(core)
            .unwrap_or(LinkInput::DialPending)
    }

    /// Ask the dial under way once over the session's links: what its answer makes of it, the
    /// link kept or why the network refused it, or `None` while the network has not answered (or
    /// no dial is under way). A dial that answered has handed out all it held for its link, so it
    /// is let go of before the link is opened. Out of line and cold: a dial begun and a dial under
    /// way at a look at the life take their answer in this one body, and no look once a link is
    /// made reaches it.
    #[cold]
    #[inline(never)]
    fn take_dial_answer(&mut self, core: &Core<L, C>) -> Option<LinkInput> {
        let links = &core.transport.links;
        let answer = self
            .dial
            .as_mut()
            .and_then(|dial| links.answer_dial(dial))?;
        let dial = self.dial.take()?;
        Some(self.answered(core, dial.into_endpoint(), answer))
    }

    /// Keep why the endpoint `text` came to no link, `why`: what the session ends with when its
    /// life ends it. Out of line and cold: each way the life gives up on an endpoint keeps its
    /// refusal here.
    #[cold]
    #[inline(never)]
    fn keep_refusal(&mut self, text: &str, why: Refusal) {
        self.last = Some(OpenError::Unreachable(EndpointRefusal::new(text, why)));
    }

    /// The answer of a dial of `endpoint`: the link kept until its handshake is begun, or why
    /// the network refused it.
    fn answered(
        &mut self,
        core: &Core<L, C>,
        endpoint: DialEndpoint,
        answer: Result<OpenedLink<L::Pump, LinkCount>, LinkOpenError>,
    ) -> LinkInput {
        match core.transport.dialled(Some(&endpoint), answer) {
            Ok(opened) => {
                self.opened = Some((opened, endpoint));
                LinkInput::DialMade
            }
            Err(refused) => {
                self.last = Some(OpenError::from(refused));
                LinkInput::DialRefused
            }
        }
    }
}

/// The face of a session whose read steps the one link itself: the link's session and what its
/// life is carried out with ([`DirectSlot`]), behind the form's lock, which a read holds while it
/// steps the pump; and what the link's end shares with the read.
pub(super) struct DirectFace<L: CoopLinks + 'static, C: ClockSource + 'static> {
    slot: StateLock<Confined<DirectSlot<L, C>>>,
    /// The link's send part, apart from the session's state and from the receive part: every send
    /// holds it, from any thread, and the session's record of the face holds a handle on it
    /// (`DirectWire`).
    site: DirectSite<L, C>,
    end: EndFlags,
    /// When the face is next due (`DirectSlot::due_us`), as its read last noted it: a read of
    /// several faces waits for the earliest of them, and the session's bookkeeping counts it,
    /// without holding the faces' slots. The one face's read holds its slot across its wait and
    /// reads the due there, so a build of that face alone keeps no copy of it.
    #[cfg(any(feature = "listen", feature = "group"))]
    due_us: AtomicU64,
    /// Whether the face table's row of the face holds a face, so a read turns it: set as the row
    /// is given to a link taken off a port or a dial attached beside the dial role's, and cleared
    /// as that face goes with its link. A read of many rows turns those alone, so a row no face
    /// holds costs it neither a take of the session nor a reading of the clock.
    #[cfg(feature = "listen")]
    holds_face: AtomicBool,
    /// Whether the face has nothing a look would move: no pump, no dial and no opened link, a
    /// life idle or closed with no wake, and no chain in its Router, so a read passes it over
    /// while it turns another (`CoopEngine::read_faces`). Written under the session's lock: set
    /// by the face's own look and by the open of a dial role that dials nothing, and ended where
    /// the slot is given a link and where the row is given a face (`DirectFaces::hold_face`),
    /// whose attached dial only the face's look takes into its slot. Outside the slot, as an
    /// attach holds the session's lock and not the face's slot.
    #[cfg(any(feature = "listen", feature = "group"))]
    rests: AtomicBool,
}

impl<L: CoopLinks + 'static, C: ClockSource + Clone + 'static> DirectFace<L, C> {
    /// The face of the face table's row `row` of a session, whose Router is `router`, lent
    /// through `lend`, with no link yet, made in `at` with its lock.
    ///
    /// # Safety
    /// `at` is valid for writes of a `Self` and aligned for it, and what it held is overwritten
    /// without being dropped. The face is not moved from `at` until it is dropped there.
    unsafe fn init_at(
        at: NonNull<Self>,
        row: usize,
        router: SessionReassembly,
        lend: RouterLend<SessionReassembly, RouterPlace>,
    ) {
        let at = at.as_ptr();
        // SAFETY: `at` is valid for writes of a `Self` that stays there (the caller's contract),
        // so each field is too, and each is written once.
        unsafe {
            <CoopForm as LockForm>::init_at(
                NonNull::new_unchecked(addr_of_mut!((*at).slot)),
                |slot| {
                    slot.write(Confined(DirectSlot {
                        at: row,
                        pump: MaybeUninit::uninit(),
                        records: None,
                        router,
                        lend,
                        dial: None,
                        opened: None,
                        last: None,
                        life_due_us: u64::MAX,
                        pump_due_us: u64::MAX,
                        brought_up: false,
                        #[cfg(any(feature = "listen", feature = "group"))]
                        noted_us: u64::MAX,
                        #[cfg(feature = "threads")]
                        site_owed: None,
                    }))
                },
            );
            addr_of_mut!((*at).site).write(FaceSite::empty());
            addr_of_mut!((*at).end).write(EndFlags::default());
            #[cfg(any(feature = "listen", feature = "group"))]
            {
                addr_of_mut!((*at).due_us).write(AtomicU64::new(u64::MAX));
                addr_of_mut!((*at).rests).write(AtomicBool::new(false));
            }
            #[cfg(feature = "listen")]
            addr_of_mut!((*at).holds_face).write(AtomicBool::new(false));
        }
    }

    /// Show when the face is next due by `slot`, its read slot, held: written only when it
    /// changed, as a step of the pump moves it with nearly every record.
    #[cfg(any(feature = "listen", feature = "group"))]
    fn note_due(&self, slot: &mut DirectSlot<L, C>) {
        let due_us = slot.due_us();
        if due_us != slot.noted_us {
            slot.noted_us = due_us;
            self.due_us.store(due_us, Ordering::Relaxed);
        }
    }

    /// The end a wire of the face's link holds.
    fn end_handle(&self) -> DirectEnd {
        DirectEnd {
            flags: NonNull::from(&self.end),
        }
    }

    /// Let go of the link with the face owned whole: the engine's drop.
    fn let_go_owned(&mut self) {
        <CoopForm as LockForm>::get_mut(&mut self.slot).0.let_go();
    }
}

/// The faces past the dial role's, a row of the session's arena for each place of the face table
/// after its first, made at the open and kept where they lie for the session's life. Only a port's
/// connection or an attach takes such a face (`listen`): a group's place is read through the
/// group's own session (`CoopEngine::read_groups`), so a build that listens on none has no row.
#[cfg(feature = "listen")]
pub(super) type TakenFaces<L, C> = BoundedVec<DirectFace<L, C>, { usize::MAX }, Lent>;

/// Every face the read steps itself: the dial role's, at the face table's first place, in the
/// engine's place, and, where the session listens, one for each place after it in a table of the
/// session's arena (`TakenFaces`). Each face has its own read slot, Router and send place, so a face's read
/// and its sends never wait on another face's; and none moves, so the session's record of a face
/// reaches its place by a handle.
pub(super) struct DirectFaces<L: CoopLinks + 'static, C: ClockSource + 'static> {
    dial: DirectFace<L, C>,
    #[cfg(feature = "listen")]
    taken: TakenFaces<L, C>,
    /// The rows of `taken` up to the last that holds a face (`Self::hold_face`): the rows past it
    /// hold none, and a read walks the faces several times, so its walks end there.
    #[cfg(feature = "listen")]
    held_rows: core::sync::atomic::AtomicUsize,
}

impl<L: CoopLinks + 'static, C: ClockSource + Clone + 'static> DirectFaces<L, C> {
    /// The faces past the dial role's, `rows` of them lent from `arena`: the face of the face
    /// table's place `n` in the table's row `n - 1`, each with a Router of its own under
    /// `policy`, staging its chains in `chains`, lent through `lend`. Refused past what the
    /// arena has left.
    #[cfg(feature = "listen")]
    pub(super) fn taken_in(
        arena: &mut Arena,
        rows: usize,
        policy: &SessionPolicy,
        chains: &LentByteCells,
        lend: &RouterLend<SessionReassembly, RouterPlace>,
    ) -> Result<TakenFaces<L, C>, LendRefused> {
        let mut taken = arena.lend::<DirectFace<L, C>, { usize::MAX }>(rows)?;
        for at in 1..=rows {
            let router = session_reassembly(policy, SessionChains::over(chains, LENT_CHAINS));
            let lend = lend.clone();
            let write = move |row: &mut MaybeUninit<DirectFace<L, C>>| {
                // SAFETY: the row is aligned and valid for writes of a face, holds none, and is
                // kept where it lies by the table for as long as the face is.
                unsafe { DirectFace::<L, C>::init_at(NonNull::from(row).cast(), at, router, lend) }
            };
            // SAFETY: `write` leaves a whole face in its row, and does not unwind.
            if unsafe { taken.push_in_place(write) }.is_none() {
                break;
            }
        }
        Ok(taken)
    }

    /// The faces, the dial role's made in `at` with `router`, lent through `lend`, and those
    /// past it `taken`.
    ///
    /// # Safety
    /// `at` is valid for writes of a `Self` and aligned for it, and what it held is overwritten
    /// without being dropped. The faces are not moved from `at` until they are dropped there.
    pub(super) unsafe fn init_at(
        at: NonNull<Self>,
        router: SessionReassembly,
        lend: RouterLend<SessionReassembly, RouterPlace>,
        #[cfg(feature = "listen")] taken: TakenFaces<L, C>,
    ) {
        let at = at.as_ptr();
        // SAFETY: `at` is valid for writes of a `Self` that stays there (the caller's contract),
        // so each field is too, and each is written once.
        unsafe {
            DirectFace::init_at(
                NonNull::new_unchecked(addr_of_mut!((*at).dial)),
                0,
                router,
                lend,
            );
            #[cfg(feature = "listen")]
            {
                addr_of_mut!((*at).taken).write(taken);
                addr_of_mut!((*at).held_rows).write(core::sync::atomic::AtomicUsize::new(0));
            }
        }
    }

    /// Every face that may hold a link, in the order of the face table's rows: the dial role's
    /// first, then, where the session listens, each past it in its row of the arena. Only a
    /// port's connection or an attach takes a face past the dial role's, so a build that listens
    /// on none has no row past it (`TakenFaces`), each group's session being read apart
    /// (`CoopEngine::read_groups`).
    #[inline(always)]
    pub(super) fn iter(&self) -> impl Iterator<Item = &DirectFace<L, C>> {
        #[cfg(feature = "listen")]
        {
            core::iter::once(&self.dial).chain(self.taken.iter())
        }
        #[cfg(not(feature = "listen"))]
        {
            core::iter::once(&self.dial)
        }
    }

    /// The faces a read turns, in the order of the face table's rows: the dial role's, whose life
    /// dials the session's endpoints whether or not it holds a link, then each past it whose row
    /// holds a face (`Self::hold_face`).
    #[cfg(any(feature = "listen", feature = "group"))]
    #[inline(always)]
    pub(super) fn turned(&self) -> impl Iterator<Item = &DirectFace<L, C>> {
        #[cfg(feature = "listen")]
        {
            core::iter::once(&self.dial).chain(
                self.taken_walked()
                    .filter(|face| face.holds_face.load(Ordering::Acquire)),
            )
        }
        // Every face that may hold a link is the dial role's alone (`Self::iter`).
        #[cfg(not(feature = "listen"))]
        {
            self.iter()
        }
    }

    /// The faces a read walks, in the order of the face table's rows: the dial role's, then each
    /// row past it up to the last that holds a face (`Self::hold_face`), held or not.
    #[cfg(any(feature = "listen", feature = "group"))]
    #[inline(always)]
    pub(super) fn walked(&self) -> impl Iterator<Item = &DirectFace<L, C>> {
        #[cfg(feature = "listen")]
        {
            core::iter::once(&self.dial).chain(self.taken_walked())
        }
        #[cfg(not(feature = "listen"))]
        {
            self.iter()
        }
    }

    /// The rows past the dial role's up to the last that holds a face, held or not: the dial
    /// role's row holds no mark (`DirectFace::holds_face`), so each walk names it apart.
    #[cfg(feature = "listen")]
    #[inline(always)]
    fn taken_walked(&self) -> impl Iterator<Item = &DirectFace<L, C>> {
        self.taken
            .iter()
            .take(self.held_rows.load(Ordering::Acquire))
    }

    /// Mark whether the face table's row `at`, past the dial role's, holds a face, and move the
    /// bound of the rows a read walks (`Self::walked`) with it. Called under the session's lock,
    /// as every change of a row's face is made, so its writes are one at a time; a read sees a row
    /// held once it sees the bound that reaches it.
    #[cfg(feature = "listen")]
    pub(super) fn hold_face(&self, at: usize, holds: bool) {
        let Some(face) = at.checked_sub(1).and_then(|row| self.taken.get(row)) else {
            return;
        };
        // Ended before the mark is shown: a read that sees the row held sees it awake.
        if holds {
            face.rests.store(false, Ordering::Release);
        }
        face.holds_face.store(holds, Ordering::Release);
        let rows = if holds {
            self.held_rows.load(Ordering::Relaxed).max(at)
        } else {
            self.taken
                .iter()
                .rposition(|face| face.holds_face.load(Ordering::Relaxed))
                .map_or(0, |row| row.saturating_add(1))
        };
        self.held_rows.store(rows, Ordering::Release);
    }

    /// The face of the face table's row `at`: the dial role's at the first, each past it in its
    /// row of the arena; `None` past the rows the open made.
    #[cfg(feature = "listen")]
    pub(super) fn face_at(&self, at: usize) -> Option<&DirectFace<L, C>> {
        match at.checked_sub(1) {
            None => Some(&self.dial),
            Some(row) => self.taken.get(row),
        }
    }

    /// Let go of every face's link with the faces owned whole: the engine's drop.
    pub(super) fn let_go_owned(&mut self) {
        self.dial.let_go_owned();
        #[cfg(feature = "listen")]
        for face in self.taken.iter_mut() {
            face.let_go_owned();
        }
    }
}

/// What a look at the link's life came to, under the session's lock.
struct LinkTurn {
    /// Whether a link lost at the look left tokens its peer declared to retract
    /// (`CoopEngine::hand_lost_tokens`).
    #[cfg(feature = "liveliness")]
    retracts: bool,
    /// The look's reading of the session's clock, in microseconds.
    now_us: u64,
    /// The same instant on the epoch the link's session measures on.
    now_ms: u64,
    /// When a periodic job is due by the look's reading.
    jobs_due_ms: Option<u64>,
    /// Whether the look owes the link that is up a turn of its replay (`CoopEngine::turn_replay`).
    replays: bool,
    /// Whether the look brought the link up (`Takes::brought_up`).
    #[cfg(all(test, feature = "std"))]
    brought_up: bool,
    /// Why the session ended at this look, when it did.
    ended: Option<OpenError>,
    /// Whether a port is to be asked for a connection once the faces were turned
    /// (`CoopEngine::accept_links`).
    #[cfg(feature = "listen")]
    accepts: bool,
}

impl<L: CoopLinks + 'static, C: ClockSource + Clone + 'static> CoopEngine<L, C> {
    /// The bytes of the read slot and send place of one face past the dial role's, a row of which
    /// the open lays out for each (`crate::arena::ArenaPlan::lay_direct_faces`).
    pub(crate) const DIRECT_FACE_BYTES: usize = core::mem::size_of::<DirectFace<L, C>>();

    /// Open the session's one link: the first endpoint dialled, and the link stepped on this thread
    /// until it is up, or the life ends the session with why the last endpoint came to no link. A
    /// session with no endpoint to dial is open at once. Never inlined, as the open of a build
    /// whose links are tasks is not.
    #[inline(never)]
    pub(super) fn open_links(&self) -> Result<(), OpenError> {
        let mut held = <CoopForm as LockForm>::lock(&self.direct.dial.slot);
        let slot = &mut held.0;
        {
            let mut core = self.core.lock();
            let core = &mut core.0;
            core.transport.listen_on_config()?;
            core.join_groups()?;
        }
        // Each group's first step sends its first JOIN, with the session let go of as a read
        // steps it; a group whose link did not open fails the open.
        #[cfg(feature = "group")]
        self.first_group_steps()?;
        {
            let mut core = self.core.lock();
            let core = &mut core.0;
            if !crate::arena::dials_of(
                core.transport.endpoints.dials(),
                core.transport.endpoints.listens(),
                core.config.groups.len(),
            ) {
                // A dial role that dials nothing has no link to look at and no time of its own:
                // its face rests from the open on.
                #[cfg(any(feature = "listen", feature = "group"))]
                self.direct.dial.rests.store(true, Ordering::Release);
                return Ok(());
            }
            let now_us = core.now_us();
            self.drive_link(&self.direct.dial, core, slot, LinkInput::Open, now_us)?;
        }
        slot.pay_site(&self.direct.dial.site);
        while !self.link_is_up(slot.at()) {
            let turn = self
                .link_turn(&self.direct.dial, slot)
                .ok_or(OpenError::NoEndpoint)?;
            if let Some(last) = turn.ended {
                return Err(last);
            }
        }
        Ok(())
    }

    /// The read of a session whose read steps its faces itself: one wait for the input of any
    /// face or the earliest deadline, then each face turned in the order of the face table's rows
    /// (`Self::read_faces`), every record handed out as it is read. A read from a callback reads
    /// nothing: the read under way holds the faces, and any other delivery marks the thread as
    /// delivering.
    pub(super) fn read_direct(&self) -> Result<(), SessionClosed> {
        // A callback reads nothing either while a delivery other than a read's runs it (a put to
        // the session's own subscribers): a record read here would be handed to a callback inside
        // another.
        if self.deliveries.delivers_here() {
            return self.read_nothing();
        }
        #[cfg(any(feature = "listen", feature = "group"))]
        {
            self.read_faces::<false, _, _>(|| self.direct.turned())
        }
        #[cfg(not(any(feature = "listen", feature = "group")))]
        {
            self.read_dial::<false>()
        }
    }

    /// The read the read task makes, over and over: [`Self::read_direct`] by a reader that no
    /// callback is, so a face it finds held is held by a read on another thread, whose wait it
    /// waits behind (`Self::held_elsewhere`) rather than coming straight back.
    #[cfg(feature = "threads")]
    pub(super) fn read_on_task(&self) -> Result<(), SessionClosed> {
        #[cfg(any(feature = "listen", feature = "group"))]
        {
            self.read_faces::<true, _, _>(|| self.direct.turned())
        }
        #[cfg(not(any(feature = "listen", feature = "group")))]
        {
            self.read_dial::<true>()
        }
    }

    /// What a read that finds a face's read slot held answers. A read other than the read task's
    /// may be a callback's, on the thread that holds the slot: it reads nothing and returns at
    /// once. The read task's (`TASK`) is no callback's, so a read on another thread holds the
    /// slot: the task waits as a read waits, until `due_us` or the session's bound, on the links or
    /// behind that read's wait, with nothing of the session held, and hands the wait back, so it
    /// neither spins on the slot nor waits on it for as long as that read's callbacks run.
    #[inline(always)]
    fn held_elsewhere<const TASK: bool>(&self, due_us: u64) -> Result<(), SessionClosed> {
        #[cfg(feature = "threads")]
        if TASK {
            let wait = self.wait_on_faces(due_us).ok_or(SessionClosed)?;
            if let Some(mut held) = self.live() {
                held.0.transport.links.waited(wait);
            }
        }
        #[cfg(not(feature = "threads"))]
        let _ = due_us;
        self.read_nothing()
    }

    /// The read where the dial role's face is the only face: its read slot held for the whole
    /// read, the wait among it, as nothing else of this thread's takes it meanwhile, then the
    /// face's turn and the session's periodic jobs. A slot found held is a read under way on this
    /// thread, whose callback this read is called from: it reads nothing; the read task's
    /// (`TASK`) finds it held by another thread's read (`Self::held_elsewhere`).
    #[cfg(not(any(feature = "listen", feature = "group")))]
    fn read_dial<const TASK: bool>(&self) -> Result<(), SessionClosed> {
        let face = &self.direct.dial;
        let Some(mut held) = <CoopForm as LockForm>::try_lock(&face.slot) else {
            return self.held_elsewhere::<TASK>(u64::MAX);
        };
        let slot = &mut held.0;
        let read = match self.link_turn(face, slot) {
            Some(turn) => {
                self.deliver();
                if turn.ended.is_some() {
                    Err(SessionClosed)
                } else {
                    if let Some(started_ms) = turn.jobs_due_ms {
                        self.run_due_tickers(started_ms);
                    }
                    Ok(())
                }
            }
            None => Err(SessionClosed),
        };
        // A close made while the read stepped the pump (a callback's) ended the link's life but
        // left the pump, which the read held: it goes now, once no step of it is under way.
        if self.closed.load(Ordering::Acquire) {
            slot.let_go();
            return Err(SessionClosed);
        }
        read
    }

    /// What a read that reads nothing answers: whether the session is closed.
    fn read_nothing(&self) -> Result<(), SessionClosed> {
        if self.closed.load(Ordering::Acquire) {
            Err(SessionClosed)
        } else {
            Ok(())
        }
    }

    /// The read of the set of faces `faces` names, each read slot taken in turn: the wait, then a
    /// look at each face's life and a step of its pump, the session's periodic jobs once every
    /// face was turned. A slot found held is a read under way on this thread, whose callback this
    /// read is called from: it reads nothing, so no record is handed out inside another's call;
    /// the read task's (`TASK`) finds it held by another thread's read (`Self::held_elsewhere`).
    #[cfg(any(feature = "listen", feature = "group"))]
    fn read_faces<'f, const TASK: bool, I, F>(&'f self, faces: F) -> Result<(), SessionClosed>
    where
        F: Fn() -> I,
        I: Iterator<Item = &'f DirectFace<L, C>>,
    {
        if !faces().all(|face| <CoopForm as LockForm>::try_lock(&face.slot).is_some()) {
            return self.held_elsewhere::<TASK>(self.faces_due_us());
        }
        // The wait is handed back to the session by the first face's look at its life, or by the
        // read itself when no face was looked at. Each face's records are handed out with its
        // slot still held, so a callback's read finds it held.
        // Where the one input the read would wait on is a group's, the group's step waits in its
        // receive instead, for as long (`Self::wait_or_await_group`).
        #[cfg(feature = "group")]
        let (wait, awaited_us) = self
            .wait_or_await_group(self.faces_due_us())
            .ok_or(SessionClosed)?;
        #[cfg(not(feature = "group"))]
        let wait = self
            .wait_on_faces(self.faces_due_us())
            .ok_or(SessionClosed)?;
        let mut wait = Some(wait);
        let mut read = Ok(());
        let mut jobs_due_ms = None;
        // The last face's reading of the clock, which the groups are stepped at.
        #[cfg(feature = "group")]
        let mut read_us = None;
        #[cfg(feature = "listen")]
        let mut accepts = false;
        // Whether the read goes on to the next face.
        let mut turn_face = |face: &DirectFace<L, C>, slot: &mut DirectSlot<L, C>| -> bool {
            let Some(turn) = self.face_turn(face, slot, wait.take()) else {
                read = Err(SessionClosed);
                return false;
            };
            if turn.ended.is_some() {
                read = Err(SessionClosed);
                return false;
            }
            jobs_due_ms = turn.jobs_due_ms;
            #[cfg(feature = "group")]
            {
                read_us = Some(turn.now_us);
            }
            #[cfg(feature = "listen")]
            {
                accepts |= turn.accepts;
            }
            true
        };
        // A face at rest (`DirectFace::rests`) is passed over while another face is turned, whose
        // look serves the session's own bookkeeping (the ledger, the gets, the jobs, the ports);
        // with no face turned the first at rest is turned all the same, for that bookkeeping.
        let mut rested = None;
        let mut turned = false;
        for face in faces() {
            if face.rests.load(Ordering::Acquire) {
                if rested.is_none() {
                    rested = Some(face);
                }
                continue;
            }
            let Some(mut held) = <CoopForm as LockForm>::try_lock(&face.slot) else {
                continue;
            };
            turned = true;
            if !turn_face(face, &mut held.0) {
                break;
            }
        }
        if let (false, Some(face)) = (turned, rested) {
            if let Some(mut held) = <CoopForm as LockForm>::try_lock(&face.slot) {
                turn_face(face, &mut held.0);
            }
        }
        // Each group's session is stepped after the faces, with no face's slot but the dial
        // role's held (`Self::read_groups`).
        #[cfg(feature = "group")]
        if read.is_ok() {
            self.read_groups(read_us, awaited_us);
        }
        // What the faces' and the groups' records left to hand out, handed out once for the read
        // rather than once a face and once a run of Pushes: no slot is held, and a callback's read
        // reads nothing inside the delivery (`Self::read_direct`).
        self.deliver();
        if let Some(wait) = wait {
            if let Some(mut held) = self.live() {
                held.0.transport.links.waited(wait);
            }
        }
        // Taken with no face's slot held: each connection's face is made in its row's place,
        // which is taken before the session's lock as every read of a face takes them.
        #[cfg(feature = "listen")]
        if accepts && read.is_ok() {
            self.accept_links();
        }
        if read.is_ok() {
            if let Some(started_ms) = jobs_due_ms {
                self.run_due_tickers(started_ms);
            }
        }
        // A close made while a read stepped a pump (a callback's) ended the link's life but left
        // the pump, which the read held: each goes now, once no step of it is under way.
        if self.closed.load(Ordering::Acquire) {
            for face in faces() {
                if let Some(mut held) = <CoopForm as LockForm>::try_lock(&face.slot) {
                    held.0.let_go();
                }
            }
            return Err(SessionClosed);
        }
        read
    }

    /// Step each group's session once (`Self::step_groups`) at `now_us`, the read's reading of
    /// the session's clock when it took one, and read what the steps left
    /// (`Self::poll_groups`), the dial role's read slot held across them, so a read from a
    /// callback of a group's record finds the faces held and reads nothing. A slot found held is
    /// a read under way on this thread, whose callback this is called from: nothing is stepped.
    /// A session that joined no group steps none and takes nothing for them.
    /// A read that made no wait of its own for a group whose receive waits hands `awaited_us`,
    /// the time it would have waited, to that group's step, which waits in its receive for it.
    #[cfg(feature = "group")]
    pub(super) fn read_groups(&self, now_us: Option<u64>, awaited_us: Option<u64>) {
        if !self.joins_groups {
            return;
        }
        if let Some(_reading) = <CoopForm as LockForm>::try_lock(&self.direct.dial.slot) {
            self.step_groups(now_us, awaited_us);
            self.poll_groups();
        }
    }

    /// Step each group's session, its read slot taken out of the session for its steps and put
    /// back after them (`Core::group_pumps`): each record a step reads is dispatched under the
    /// session's lock, which is let go of before it is handed out (`DirectSink`), as a face's
    /// are. A step reads the datagrams of the group's socket up to `GROUP_READS_PER_MOVE` of them,
    /// each datagram's records handed out before the next is received, so a burst is read by one
    /// step of one read, its fixed part (the stop, the carrier, the beacon, the writes) taken
    /// once, and the links are moved once, after it, as a link's one receive is read. The step is
    /// made at `now_us`, the read's reading of the session's clock, or at a reading of its own
    /// where the read took none. What a burst holds past a callback that closed the session is
    /// read and taken by nothing, a closed session's state being reached by no record. A session
    /// that ended at its step is let go of, its place put back for the group's next join and its
    /// end left for the session to read (`Self::poll_groups`); a slot whose session ended is not
    /// stepped. One a read finds the session closed after is stepped once more, which tells the
    /// group it leaves.
    /// A group whose receive waits is handed `awaited_us`, the time the read made no wait for:
    /// it is read in its receive, with nothing of the session held while it waits, a datagram a
    /// step, until that time is out or the read owes the session a turn
    /// ([`super::group::read_awaited`]).
    #[cfg(feature = "group")]
    fn step_groups(&self, now_us: Option<u64>, mut awaited_us: Option<u64>) {
        let mut at = 0;
        loop {
            let (pump, most) = {
                let Some(mut held) = self.live() else {
                    return;
                };
                // The deploy's domain of the bound starts at one.
                let most =
                    core::num::NonZeroUsize::new(held.0.config.limits.group_reads_per_move())
                        .unwrap_or(core::num::NonZeroUsize::MIN);
                let Some(slot) = held.0.group_pumps.get_mut(at) else {
                    return;
                };
                let pump = if slot
                    .as_ref()
                    .is_some_and(super::group::GroupPump::holds_session)
                {
                    slot.take()
                } else {
                    None
                };
                (pump, most)
            };
            let Some(mut pump) = pump else {
                at = at.saturating_add(1);
                continue;
            };
            // A burst read to its bound leaves the group's mark of input for the next read's
            // wait, so that read does not wait for what the socket already holds.
            let ended = match awaited_us {
                Some(timeout_us) if pump.awaits_input() => {
                    awaited_us = None;
                    let since_us = now_us.unwrap_or_else(|| pump.now_us());
                    super::group::read_awaited(
                        &mut AwaitedGroup {
                            engine: self,
                            pump: &mut pump,
                        },
                        most,
                        since_us.saturating_add(timeout_us),
                        since_us,
                    )
                }
                _ => {
                    let now_us = now_us.unwrap_or_else(|| pump.now_us());
                    self.step_group(&mut pump, most, now_us)
                }
            };
            // What the slot shares with the group's face is let go of, stepped or put back under
            // the session's lock, closed or not: a close let go of the face's handles under it.
            let mut core = self.core.lock();
            // The ended session's transport goes before the session's poll joins the group again
            // (`Self::poll_groups`), a join that takes what the transport held of the stack's.
            if ended {
                pump.let_go();
            }
            if self.closed.load(Ordering::Acquire) {
                pump.leave();
                return;
            }
            let unplaced = match core.0.group_pumps.get_mut(at) {
                Some(slot) => {
                    *slot = Some(pump);
                    None
                }
                None => Some(pump),
            };
            drop(unplaced);
            drop(core);
            at = at.saturating_add(1);
        }
    }

    /// One step of a group's session, `pump` its read slot taken out of the session, reading up
    /// to `most` datagrams at `now_us`: what it reads handed out as it is read, and the drains its
    /// Pushes put off made after it. Whether the session ended at it.
    #[cfg(feature = "group")]
    fn step_group(
        &self,
        pump: &mut super::group::GroupPump<C>,
        most: core::num::NonZeroUsize,
        now_us: u64,
    ) -> bool {
        // A group's session is of one thread's types, which it shares with the group's face in
        // the session's state (the stage, the link, the members' rows, the end): with other
        // threads (`threads`) it is stepped with the session's lock held, as every reach of
        // that face is, so they are reached by one thread at a time (`UnderCoreLock`). The
        // lock is let go of only while a record the step read is handed out, which takes it
        // again for the record's dispatch (`DirectSink`) and calls its callbacks with it let
        // go of. With no other thread nothing else reaches them meanwhile, and nothing is held.
        #[cfg(feature = "threads")]
        let mut held = Some(self.core.lock());
        let ended = pump.step(
            &mut |records, event| {
                #[cfg(feature = "threads")]
                drop(held.take());
                DirectSink {
                    engine: self,
                    records,
                }
                .event(event);
                #[cfg(feature = "threads")]
                {
                    held = Some(self.core.lock());
                }
            },
            most,
            now_us,
        );
        #[cfg(feature = "threads")]
        drop(held);
        DirectSink {
            engine: self,
            records: pump.records(),
        }
        .end_records();
        ended
    }

    /// Whether the read owes the session a turn of its own at `now_us`: its bookkeeping
    /// (`Ledger::owes`, what a face's turn looks at first) or a periodic job due. A closed
    /// session is owed the read's end.
    #[cfg(feature = "group")]
    fn read_owed(&self, now_us: u64) -> bool {
        let Some(held) = self.live() else {
            return true;
        };
        held.0.ledger.owes(now_us, held.0.seen()) || held.0.jobs_due_at(now_us).is_some()
    }

    /// Read the end of each group's session a step left, join again each group whose time came
    /// (`Core::poll_groups`), and ask each join that came up for its members' keyexprs
    /// (`Core::ask_groups_for_keyexprs`), under the session's lock: the ask is staged on the
    /// group's stage, which the group's next step writes.
    #[cfg(feature = "group")]
    fn poll_groups(&self) {
        if let Some(mut held) = self.live() {
            let redial_ms = held.0.config.redial_ms;
            held.0.poll_groups(redial_ms);
            held.0.ask_groups_for_keyexprs();
        }
    }

    /// The open's first step of each group it joined (`Self::step_groups`), which sends the
    /// group's first JOIN. [`OpenError::Group`] for the first group whose session ended at it:
    /// its link did not open.
    #[cfg(feature = "group")]
    fn first_group_steps(&self) -> Result<(), OpenError> {
        if !self.joins_groups {
            return Ok(());
        }
        self.step_groups(None, None);
        let held = self.live().ok_or(OpenError::NoEndpoint)?;
        match held
            .0
            .transport
            .groups
            .iter()
            .find(|group| group.has_ended())
        {
            Some(group) => Err(OpenError::Group(EndpointRefusal::new(
                &group.group_join().endpoint,
                Refusal::GroupLinkDidNotOpen,
            ))),
            None => Ok(()),
        }
    }

    /// One turn of the face `face`, its read slot held as `slot`, the open's and, where the dial
    /// role's face is the only face, the read's: the wait for the
    /// link's input or the next deadline, then the face's turn (`Self::face_turn`). `None`
    /// once the session closed. Where the dial role's face is the only face this is the one body
    /// the open and each read turn it through, the face's turn inlined into it.
    #[cfg_attr(not(any(feature = "listen", feature = "group")), inline(never))]
    fn link_turn(&self, face: &DirectFace<L, C>, slot: &mut DirectSlot<L, C>) -> Option<LinkTurn> {
        let wait = self.wait_on_faces(self.wait_due(slot))?;
        self.face_turn(face, slot, Some(wait))
    }

    /// When the faces are next due, for a wait made with `slot`, the read slot of the face the
    /// read turns, held: as each face's read last noted it where a read may turn several faces,
    /// and as `slot` holds it where the dial role's face is the only face, whose read holds that
    /// slot across its wait.
    #[cfg(any(feature = "listen", feature = "group"))]
    fn wait_due(&self, _slot: &DirectSlot<L, C>) -> u64 {
        self.faces_due_us()
    }

    /// When the faces are next due, for a wait made with `slot`, the read slot of the face the
    /// read turns, held: as `slot` holds it, where the dial role's face is the only face, whose
    /// read holds that slot across its wait.
    #[cfg(not(any(feature = "listen", feature = "group")))]
    #[inline(always)]
    fn wait_due(&self, slot: &DirectSlot<L, C>) -> u64 {
        slot.due_us()
    }

    /// The wait for the input of any face or the earliest deadline `due_us`, made with nothing
    /// of the session held. `None` once the session closed.
    fn wait_on_faces(&self, due_us: u64) -> Option<IdleWait> {
        let mut wait = self.link_wait(due_us, None)?;
        #[cfg(test)]
        self.takes.wait(&wait);
        wait.wait(self.rooms.waits(), sleep_ms);
        Some(wait)
    }

    /// [`Self::wait_on_faces`] for a read that steps the groups after its faces: where the one
    /// input the read would wait on is a group's, on a receive half whose receive waits, no wait
    /// is made here, and the time it would have taken is answered beside the wait, for the
    /// group's step to wait in its receive (`Self::step_groups`). A datagram then costs that
    /// receive and no wait beside it, as zenoh-pico's read task waits in its receive
    /// (`vendor/zenoh-pico/src/link/transport/udp/udp_multicast_posix.c` @
    /// `rb = recvfrom(sock._fd, ptr, len, 0, (struct sockaddr *)&raddr, &replen);`).
    #[cfg(feature = "group")]
    fn wait_or_await_group(&self, due_us: u64) -> Option<(IdleWait, Option<u64>)> {
        let mut awaited_us = None;
        let mut wait = self.link_wait(due_us, Some(&mut awaited_us))?;
        #[cfg(test)]
        self.takes.wait(&wait);
        if awaited_us.is_none() {
            wait.wait(self.rooms.waits(), sleep_ms);
        }
        Some((wait, awaited_us))
    }

    /// A turn of `face`, its read slot held as `slot`, after the wait `wait` when this turn
    /// hands it back: a look at the link's life, and a step of the pump unless the look ended the
    /// session. `None` once the session closed. Out of line where a read turns several faces:
    /// the open and each read turn a face through one body. Where the dial role's face is the only
    /// face its one caller is that body (`Self::link_turn`), which holds it inline.
    #[cfg_attr(any(feature = "listen", feature = "group"), inline(never))]
    #[cfg_attr(not(any(feature = "listen", feature = "group")), inline(always))]
    fn face_turn(
        &self,
        face: &DirectFace<L, C>,
        slot: &mut DirectSlot<L, C>,
        wait: Option<IdleWait>,
    ) -> Option<LinkTurn> {
        #[cfg(test)]
        self.takes.face_turns.fetch_add(1, Ordering::Relaxed);
        let turn = self.life_turn(face, slot, wait)?;
        // What the look changed of the face's place under the session's lock, and could not, is
        // carried out before anything is sent through the place.
        slot.pay_site(&face.site);
        #[cfg(all(test, feature = "std"))]
        if turn.brought_up {
            self.takes.brought_up();
        }
        // A lost link's tokens go before anything a link brings after the loss, and with a loss
        // that ended the session too.
        #[cfg(feature = "liveliness")]
        if turn.retracts {
            self.hand_lost_tokens();
        }
        if turn.ended.is_none() {
            // The turn goes through the link's wire, its place taken before the session's lock as
            // every operation's send takes it, so the look's lock is let go of first. A turn that
            // ended the link has the life looked at by the next read, at once.
            let at = slot.at();
            if turn.replays
                && self.live_on_link(|core, tx| self.turn_replay(core, at, turn.now_us, tx))
                    == Some(TurnEnd::EndsLink)
            {
                slot.life_due_us = turn.now_us;
            }
            self.pump_turn(face, slot, &turn);
        }
        #[cfg(any(feature = "listen", feature = "group"))]
        face.note_due(slot);
        Some(turn)
    }

    /// When the earliest face is next due by its life or its pump, as each face's read last noted
    /// it (`DirectFace::note_due`).
    #[cfg(any(feature = "listen", feature = "group"))]
    fn faces_due_us(&self) -> u64 {
        self.direct
            .walked()
            .map(|face| face.due_us.load(Ordering::Relaxed))
            .min()
            .unwrap_or(u64::MAX)
    }

    /// What a read waits for: nothing while a link holds input it already took from its stack,
    /// else, worked out under the session's lock, the links' input, or the earliest of the faces'
    /// deadline `due_us` and the session's. `None` once the session closed.
    ///
    /// Where `awaits` is given and the wait is on one input, a group's that its step can wait for
    /// in its receive (`GroupPump::awaits`), the wait's time is answered in it, in microseconds.
    fn link_wait(&self, due_us: u64, awaits: Option<&mut Option<u64>>) -> Option<IdleWait> {
        // Each face's read tells its facts outside the session (`SiteFacts`), and the faces'
        // records read the same facts under it: a face found holding input here answers the wait
        // with nothing of the session taken, a wait that is none needing no deadline. A group's
        // datagram taken is the session's to read, under its lock below.
        if self.faces_hold_input() {
            if self.closed.load(Ordering::Acquire) {
                return None;
            }
            #[cfg(test)]
            self.takes.held_input_reads.fetch_add(1, Ordering::Relaxed);
            return Some(IdleWait::None);
        }
        let mut held = self.live()?;
        held.0.link_due_us = due_us;
        // Input the link holds is read at once, so no deadline is gathered and the clock is not
        // read for a wait that would be none. What falls due meanwhile is served by the look at
        // the life that follows, which reads the clock whether or not the read waited.
        if held.0.transport.holds_input() {
            #[cfg(test)]
            self.takes.held_input_reads.fetch_add(1, Ordering::Relaxed);
            return Some(IdleWait::None);
        }
        // Marked as a holder that holds no send, so a droppable publish that finds the session
        // held for the wait tries it again at once (`LinkRooms::for_held`).
        let _waiting = SendingOn::enter(&self.sending_on, WAITING);
        let wait = held.0.idle_wait();
        #[cfg(feature = "group")]
        if let (Some(awaits), IdleWait::Input { on, ms }) = (awaits, &wait) {
            if let [only] = on.as_slice() {
                if held
                    .0
                    .group_pumps
                    .iter()
                    .flatten()
                    .any(|pump| pump.awaits(only))
                {
                    *awaits = Some(u64::from(*ms) * 1000);
                }
            }
        }
        #[cfg(not(feature = "group"))]
        let _ = awaits;
        Some(wait)
    }

    /// Whether a face the read may turn holds input its link already took from its stack, as the
    /// face's read last told it (`DirectSlot::tell_facts`), read with nothing of the session
    /// held. A test may have every read find it so (`Takes::input_held`).
    #[inline(always)]
    fn faces_hold_input(&self) -> bool {
        #[cfg(test)]
        if self.takes.input_held.load(Ordering::Relaxed) {
            return true;
        }
        #[cfg(any(feature = "listen", feature = "group"))]
        {
            self.direct
                .walked()
                .any(|face| face.site.facts().read().holds_input)
        }
        #[cfg(not(any(feature = "listen", feature = "group")))]
        {
            self.direct.dial.site.facts().read().holds_input
        }
    }

    /// A look at the link's life under the session's lock, the read's `wait` handed back first
    /// when this look is the one to hand it back: what the link brings is
    /// told to the life and its effects carried out, with the session's bookkeeping, when the
    /// link brings something, the life or the ledger is due, or the Router holds a chain past its
    /// deadline. `None` once the session closed.
    fn life_turn(
        &self,
        face: &DirectFace<L, C>,
        slot: &mut DirectSlot<L, C>,
        wait: Option<IdleWait>,
    ) -> Option<LinkTurn> {
        let mut held = self.live()?;
        let core = &mut held.0;
        // The read's last step of the link, made with nothing of the session held, may have ended
        // its session: the face no longer stands from here on. Read off the read's own handle on
        // the link's actions, so the look lends nothing of the face's send place.
        let established = slot
            .records
            .as_ref()
            .is_some_and(|records| records.actions.is_established());
        core.end_closed_facts(slot.at(), established);
        if let Some(wait) = wait {
            core.transport.links.waited(wait);
        }
        let now_us = core.now_us();
        let now_ms = core.session_time.ms_at(now_us);
        let input = slot.next_input(core, &face.end, now_us);
        let chains_due = now_ms >= slot.router.due_ms();
        // The life moves on only by what the link brings or at its own time: a link that is up
        // and brings nothing is not looked at for the rest of the bookkeeping.
        let moves_link = input != LinkInput::Tick || now_us >= slot.life_due_us;
        let mut ended = None;
        let mut replays = false;
        #[cfg(all(test, feature = "std"))]
        let mut brought_up = false;
        if moves_link || chains_due || core.ledger.owes(now_us, core.seen()) {
            #[cfg(test)]
            core.services.set(core.services.get() + 1);
            if chains_due {
                slot.router.sweep(now_ms);
            }
            core.sweep_gets(now_us);
            let moved = if moves_link {
                #[cfg(test)]
                core.link_polls.set(core.link_polls.get() + 1);
                self.drive_link(face, core, slot, input, now_us)
            } else {
                Ok(())
            };
            match moved {
                // A link the look brought up is owed the replay's first turn, and a paced
                // replay the turn that may be due.
                Ok(()) => {
                    replays = slot.brought_up || ReplayPacing::REACHABLE;
                    #[cfg(all(test, feature = "std"))]
                    {
                        brought_up = slot.brought_up;
                    }
                    slot.brought_up = false;
                }
                Err(last) => {
                    // A handle reads the session closed from its row from here on, as after a
                    // close.
                    self.reach.end();
                    self.closed.store(true, Ordering::Release);
                    ended = Some(last);
                }
            }
            // What the peers declared moved only where a face's tables were written since the
            // listeners were last read.
            let written = core.session.registry.faces_written();
            if core.session.matching.moved(written) {
                self.read_matching(core);
            }
            let life = core.transport.links.face(slot.at()).map(|face| &face.life);
            slot.life_due_us = life
                .and_then(|life| life.wake_at(now_us))
                .unwrap_or(u64::MAX);
            // A life standing by is not at rest: it dials again once no other face holds its
            // node, which only a look at it reads.
            #[cfg(any(feature = "listen", feature = "group"))]
            face.rests.store(
                slot.life_due_us == u64::MAX
                    && slot.records.is_none()
                    && slot.dial.is_none()
                    && slot.opened.is_none()
                    && slot.router.due_ms() == u64::MAX
                    && life.is_none_or(|life| {
                        matches!(life.phase(), LinkPhase::Idle | LinkPhase::Closed)
                    }),
                Ordering::Release,
            );
            // Noted outside the slot for the other faces' reads; the one face's due is the read's
            // own, noted as its turn ends.
            #[cfg(any(feature = "listen", feature = "group"))]
            {
                face.note_due(slot);
                core.link_due_us = self.faces_due_us();
            }
            #[cfg(not(any(feature = "listen", feature = "group")))]
            {
                core.link_due_us = slot.due_us();
            }
            core.settle_ledger();
        }
        let jobs_due_ms = core.jobs_due_at(now_us);
        Some(LinkTurn {
            #[cfg(feature = "liveliness")]
            retracts: core.session.registry.retracting(),
            now_us,
            now_ms,
            jobs_due_ms,
            replays,
            #[cfg(all(test, feature = "std"))]
            brought_up,
            ended,
            #[cfg(feature = "listen")]
            accepts: core.transport.links.ports_to_ask(),
        })
    }

    /// Step the pump with nothing of the session held: its own bookkeeping when it is due or owes
    /// what was asked of it from outside, then the units of input its link holds, the Router lent
    /// for them. A step that took nothing serves the pump, which tells its session of a link that
    /// is gone. A pump that ended has its life looked at by the next read, at once. The link's send
    /// part is not held for the step: a send a callback of a record makes inside it, or another
    /// thread makes meanwhile, holds that part itself.
    fn pump_turn(&self, face: &DirectFace<L, C>, slot: &mut DirectSlot<L, C>, turn: &LinkTurn) {
        // Read before the step, which writes what the link owes its stack beside the sends.
        let mark = face.site.facts().write_mark();
        let Some((ended, due_us)) = self.step_pump(slot, turn) else {
            return;
        };
        slot.tell_facts(&face.site, mark);
        if ended {
            face.end.ended.store(true, Ordering::Release);
            slot.life_due_us = turn.now_us;
        }
        slot.pump_due_us = due_us;
    }

    /// One step of the pump `slot` holds at `turn`: its own bookkeeping when it is due or owes
    /// what was asked of it from outside, then the units of its input the link holds
    /// (`Self::take_held_input`), the slot's Router lent for them. Whether the pump ended, and
    /// when it is due next; `None` while no pump is written.
    fn step_pump(&self, slot: &mut DirectSlot<L, C>, turn: &LinkTurn) -> Option<(bool, u64)> {
        let (now_us, now_ms) = (turn.now_us, turn.now_ms);
        let DirectSlot {
            pump,
            records,
            router,
            lend,
            pump_due_us,
            ..
        } = slot;
        let due_us = *pump_due_us;
        let records = records.as_mut()?;
        // Read before the step: a link the step establishes is brought up by the next look at its
        // life, before which nothing behind its handshake is read.
        let settled = records.actions.is_established();
        // SAFETY: the records are held exactly while the pump is written in its place.
        let pump = unsafe { pump.assume_init_mut() };
        let mut sink = DirectSink {
            engine: self,
            records,
        };
        let ended = 'step: {
            if (now_us >= due_us || pump.owes_out_of_band())
                && pump.service_due(now_ms, &mut sink).is_some()
            {
                break 'step true;
            }
            let took = lend.lend_for(router, || {
                self.take_held_input(&mut *pump, now_ms, settled, &mut sink)
            });
            !took && pump.service_due(now_ms, &mut sink).is_some()
        };
        let due_us = pump.due_ms(now_ms).map_or(u64::MAX, |due_ms| {
            now_us.saturating_add(due_ms.saturating_sub(now_ms).saturating_mul(1000))
        });
        Some((ended, due_us))
    }

    /// Hand the pump the link's next unit of input at `now_ms`, then, on a link whose session was
    /// `settled` (established) before the step, every unit the link already took from its stack
    /// behind it: the wait, the look at the life and the gathering of the pump's deadlines are paid
    /// once for what one receive brought, not once a batch, as zenoh-pico's read of a peer's socket
    /// processes what the read left behind its first batch before it waits again
    /// (`vendor/zenoh-pico/src/transport/unicast/read.c` @
    /// `static z_result_t _zp_unicast_process_peer_event(`). What the link holds bounds the run,
    /// so the next unit read from the stack waits for the next read, which serves what fell due
    /// first. A unit of a link in its handshake is the last of its read: the life brings the link
    /// up at its next look, and what follows the handshake is read after that. A run ends once a
    /// callback closed the session. Whether a unit was taken.
    #[inline(always)]
    fn take_held_input<F: EventSink>(
        &self,
        pump: &mut DirectPump<L, C>,
        now_ms: u64,
        settled: bool,
        sink: &mut F,
    ) -> bool {
        let mut took = false;
        while pump.take_input_now(now_ms, sink) {
            took = true;
            #[cfg(test)]
            self.takes.pump_reads.fetch_add(1, Ordering::Relaxed);
            if !settled || !pump.link().holds_input() || self.closed.load(Ordering::Acquire) {
                break;
            }
        }
        took
    }

    /// Tell the link's life `input` at `now_us` and carry out its effects, in the order the life
    /// names them, until it asks for nothing more. `Err` with why the last endpoint came to no
    /// link when the life ends the session. Out of line: the open's first input and each look at
    /// the life carry the effects out through one body.
    #[inline(never)]
    fn drive_link(
        &self,
        face: &DirectFace<L, C>,
        core: &mut Core<L, C>,
        slot: &mut DirectSlot<L, C>,
        input: LinkInput,
        now_us: u64,
    ) -> Result<(), OpenError> {
        let (mut input, mut now_us) = (input, now_us);
        loop {
            let Some(record) = core.transport.links.face_mut(slot.at()) else {
                return Ok(());
            };
            let was = record.life.phase();
            let effects = record.life.input(input, now_us);
            // A close is told to the life by the slot alone, which lets go of what it holds
            // itself (`DirectSlot::let_go`): no input told here asks for that.
            debug_assert!(!effects.let_go(), "a close told to the life past the slot");
            // A dial the life gave up on before the network answered it is its endpoint's refusal
            // for want of an answer in time, as a build whose links are tasks names it.
            if effects.dial().is_some() || effects.backs_off() || effects.ends_session() {
                if let Some(dial) = slot.dial.take() {
                    let endpoint = dial.into_endpoint();
                    slot.keep_refusal(
                        core.transport.endpoint_text(Some(&endpoint)),
                        Refusal::NoAnswerInTime,
                    );
                }
            }
            if effects.end_handshake() {
                // Why the handshake ended is read off its link before the link goes, and names
                // the endpoint the link was dialled to, which the life stood in.
                let row = match was {
                    LinkPhase::Handshaking { row, .. } => row,
                    _ => 0,
                };
                let why = core.transport.end_handshake(slot.at());
                slot.keep_refusal(core.transport.endpoints.dial_text(row), why);
                // The record lets go of the link while the place still holds its parts, so what
                // the link's session counted is read through the place as it goes.
                core.transport.links.put_link(slot.at(), Link::Idle);
                slot.drop_link(&face.site);
            }
            if effects.lose() {
                // The lost peer's chains end with its link: the next link's fragments would be
                // spliced onto them.
                let peer = core
                    .transport
                    .links
                    .face(slot.at())
                    .and_then(|face| face.facts.as_ref())
                    .and_then(|facts| facts.peer);
                if let Some(zid) = peer {
                    let _ended = slot.router.abort_peer(zid.as_slice());
                }
                if let Some(id) = slot.face_id(core) {
                    core.lose_face_link(slot.at(), id);
                }
                slot.drop_link(&face.site);
                if effects.ends_session() {
                    slot.keep_refusal("", Refusal::LinkLost);
                }
            }
            if effects.bring_up() {
                // What the link says of its peer is read off the read's own handle on its actions,
                // with nothing of the face's send place lent.
                if let Some(facts) = slot.records.as_ref().map(FaceRecords::up_facts) {
                    core.bring_up_with(slot.at(), now_us, facts);
                }
                slot.brought_up = true;
            }
            // The dial under way, if any, was taken above.
            if effects.ends_session() {
                return Err(slot.last.take().unwrap_or(OpenError::NoEndpoint));
            }
            // A face taken beside the dial role's goes with its link: what its place held first,
            // then its record and its tables.
            #[cfg(feature = "listen")]
            if effects.removes() {
                self.direct.hold_face(slot.at(), false);
                slot.clear(&face.site);
                core.remove_face(slot.at());
                return Ok(());
            }
            input = if effects.begin_handshake() {
                self.begin_handshake(face, core, slot)
            } else if let Some(row) = effects.dial() {
                slot.dial_row(core, row)
            } else {
                return Ok(());
            };
            // What the dial or the handshake came to is told at the time read after it: a host
            // may take a while to refuse a dial, and a wait to dial again counted from before the
            // dial would be over by then, so that each read would dial again at once.
            now_us = core.now_us();
        }
    }

    /// Hand the liveliness subscribers the declaration `record` of the face `records` reads, lent
    /// where its frame lies (`event`): its token, when it is one, bound or unbound under the
    /// session's lock and handed to each row it reaches once the lock is let go of, one call at a
    /// time (`tokens`), and the rest of it dispatched to every plane but the token's. An alive
    /// token answering a pending liveliness get is that get's alone, handed to it as a reply is.
    /// A closed session hands nothing.
    #[cfg(feature = "liveliness")]
    fn hand_lent_declare<A: RecordActions>(
        &self,
        records: &FaceRecords<A>,
        record: &wz_session_core::driver_loop::InPlaceRecord<'_, '_>,
        event: IterationEvent<'_, '_>,
    ) {
        let face = records.face;
        #[cfg(feature = "liveliness-get")]
        let held = self.hand_lent_token(face, record);
        #[cfg(not(feature = "liveliness-get"))]
        let held = self.live();
        let Some(mut held) = held else {
            return;
        };
        let mut news = wz_session_core::declare::liveliness_subscriber::TokenNews::default();
        let told = held
            .0
            .session
            .registry
            .take_lent_token(face, record, &mut news);
        records.dispatch(&mut held.0.session.registry, event, Planes::All);
        drop(held);
        if told {
            self.hand_token_row_by_row(&news, false);
        }
    }

    /// Begin the handshake of the link the last dial made: what the life is told of it.
    fn begin_handshake(
        &self,
        face: &DirectFace<L, C>,
        core: &mut Core<L, C>,
        slot: &mut DirectSlot<L, C>,
    ) -> LinkInput {
        let Some((opened, endpoint)) = slot.opened.take() else {
            return LinkInput::HandshakeRefused(Refused::Endpoint);
        };
        match self.place_link_session(
            face,
            core,
            slot,
            opened,
            SessionRole::Initiator,
            Some(&endpoint),
        ) {
            Ok(()) => LinkInput::HandshakeBegun,
            Err(refused) => {
                let why = match refused {
                    OpenError::EntropyUnavailable => Refused::Fatal,
                    OpenError::NoTask(_) => Refused::Task,
                    _ => Refused::Endpoint,
                };
                slot.last = Some(refused);
                LinkInput::HandshakeRefused(why)
            }
        }
    }

    /// The session of the link `opened`, run in `role` and dialled to or taken on `endpoint`,
    /// built in the face's place for it and held by the face's link in its handshake. Never
    /// inlined, for the stack: what is built here lies in this frame alone.
    #[inline(never)]
    fn place_link_session(
        &self,
        face: &DirectFace<L, C>,
        core: &mut Core<L, C>,
        slot: &mut DirectSlot<L, C>,
        opened: OpenedLink<L::Pump, LinkCount>,
        role: SessionRole,
        endpoint: Option<&DialEndpoint>,
    ) -> Result<(), OpenError> {
        slot.drop_link(&face.site);
        face.end.ready();
        let params = core.link_params()?;
        // The face's record at the slot's row names the face its link's session dispatches to.
        let face_id = slot.face_id(core).ok_or(OpenError::NoEndpoint)?;
        let end = face.end_handle();
        // The link's session is made under the session's lock, its pump in the slot's place, which
        // the read that makes it holds.
        let mut calls = LinkMaking {
            session: &mut core.session,
            #[cfg(feature = "shared-key-ids")]
            limits: resolve_limits(&core.config),
        };
        let placed = core
            .transport
            .place_wire(
                &mut calls,
                opened,
                OpenedAs {
                    face: face_id,
                    role,
                    endpoint,
                },
                WireMaking {
                    params,
                    local: &core.local,
                    entropy: &mut core.entropy,
                    clock: &core.session_time,
                    timeouts: core.config.timeouts,
                },
                PumpPlace {
                    place: &mut slot.pump,
                    end,
                },
            )
            .map_err(OpenError::from)?;
        let PlacedWire {
            wire,
            dispatch,
            pump: _,
        } = placed;
        slot.records = Some(dispatch);
        #[cfg(any(feature = "listen", feature = "group"))]
        face.rests.store(false, Ordering::Release);
        // The face's record holds the wire's waits, read once here, and no handle.
        let (input, room) = (wire.input_wait(), wire.room_wait());
        #[cfg(feature = "resource-snapshot")]
        let count = KernelCount(CellRc::clone(&wire.actions.core));
        // The place held no parts from the drop of the last link; the wire goes in whole, as the
        // parts' making takes it, and what was owed to the last link is let go of
        // (`FaceSite::hold`).
        let carried = OnThisThread(wire);
        let parts = FaceHeld::gather(move || DirectParts::holding(carried.get()));
        slot.fill_site(&face.site, parts);
        // A pump not stepped yet is due at once: the read that placed it sends its first frame,
        // and the next wait, the open's too, is none.
        slot.pump_due_us = 0;
        #[cfg(any(feature = "listen", feature = "group"))]
        face.note_due(slot);
        // SAFETY: the site lies in its face, which stays where it lies for the engine's life: the
        // dial role's at the engine's fixed place, each past it in its row of the session's arena
        // (`TakenFaces`). The session's state, which holds this handle, reaches the site only while
        // the engine stands (its drop ends the links before the face goes), and the handle does
        // nothing in its own drop but let go of the count it keeps.
        let wire = unsafe { FaceAt::new(&face.site, face.end_handle(), input, room) };
        #[cfg(feature = "resource-snapshot")]
        let wire = wire.counted_by(count);
        core.transport.links.put_link(slot.at(), Link::Wire(wire));
        Ok(())
    }

    /// The turn of the replay a look at the life owed the link of the face at `at` that is up
    /// (`LinkTurn::replays`), told through the link's wire `tx` at `now_us`: the next turn of a paced replay when one is
    /// due, else the whole of it in one lap, which a look owes only the link it brought up. What
    /// the turn left of the link: a turn the replay is given up on ends the link, as a build whose
    /// links are tasks ends it.
    fn turn_replay(
        &self,
        core: &mut Core<L, C>,
        at: usize,
        now_us: u64,
        tx: LinkTx<'_, C>,
    ) -> TurnEnd {
        if core
            .transport
            .links
            .face(at)
            .and_then(|face| face.up())
            .is_none()
        {
            return TurnEnd::Kept;
        }
        let end = if ReplayPacing::REACHABLE {
            core.replay_turn(at, now_us / 1000, tx)
        } else {
            core.tell_in_one_lap(at, tx)
        };
        if end == TurnEnd::EndsLink {
            core.transport.links.abort_link(at);
        }
        end
    }

    /// Take the connections that wait on the ports the session listens on, each as a face of its
    /// own: a free row of the face table under the session's lock (`Core::take_face`), then the
    /// link's session made in that row's place (`Self::take_link`). Called with no face's slot
    /// held. A connection the session takes no face for is closed unread.
    #[cfg(feature = "listen")]
    fn accept_links(&self) {
        let mut port = 0;
        loop {
            let (opened, endpoint, at) = {
                let Some(mut held) = self.live() else {
                    return;
                };
                let core = &mut held.0;
                let Some((opened, endpoint)) = core.transport.next_accepted(&mut port) else {
                    return;
                };
                let Some(at) = core.take_face() else {
                    continue;
                };
                (opened, endpoint, at)
            };
            self.take_link(at, opened, endpoint);
        }
    }

    /// Make the session of `opened`, a link taken on a port for `endpoint`, in the place of the
    /// face the face table gave the row `at`, in the acceptor's role: the face's place taken first,
    /// then the session's lock, and the face's life begun as a taken link's, its handshake run by
    /// the face's read from here on and given up at its deadline. A row with no place, a place
    /// held, and a link whose session is not made take the face out again, the link closed unread.
    #[cfg(feature = "listen")]
    fn take_link(
        &self,
        at: usize,
        opened: OpenedLink<L::Pump, LinkCount>,
        endpoint: Option<DialEndpoint>,
    ) {
        let Some(face) = self.direct.face_at(at) else {
            self.drop_taken(at);
            return;
        };
        let Some(mut held) = <CoopForm as LockForm>::try_lock(&face.slot) else {
            self.drop_taken(at);
            return;
        };
        let slot = &mut held.0;
        let placed = {
            let Some(mut live) = self.live() else {
                return;
            };
            let core = &mut live.0;
            let placed = self.place_link_session(
                face,
                core,
                slot,
                opened,
                SessionRole::Acceptor,
                endpoint.as_ref(),
            );
            if placed.is_err() {
                core.remove_face(at);
            } else {
                self.direct.hold_face(at, true);
                let now_us = core.now_us();
                if let Some(record) = core.transport.links.face_mut(at) {
                    // A taken link's handshake asks for nothing of the session.
                    let _ = record.life.input(LinkInput::Taken, now_us);
                    slot.life_due_us = record.life.wake_at(now_us).unwrap_or(u64::MAX);
                }
            }
            placed.is_ok()
        };
        // What the making owed the face's place is carried out with the session let go of.
        slot.pay_site(&face.site);
        if placed {
            face.note_due(slot);
        }
    }

    /// Take out the face at `at` the face table gave a connection whose place was not reached.
    #[cfg(feature = "listen")]
    fn drop_taken(&self, at: usize) {
        if let Some(mut live) = self.live() {
            live.0.remove_face(at);
        }
    }

    /// Whether the link of the face at `at` is up, as the life of the face's record says.
    fn link_is_up(&self, at: usize) -> bool {
        self.core
            .lock()
            .0
            .transport
            .links
            .face(at)
            .is_some_and(|face| face.life.phase() == LinkPhase::Up)
    }

    /// `f` on the session's state, with every face's send place held before the session's lock,
    /// in the order of the face table, each by a hold that waits for another send that holds it
    /// now (never for a read's step, which does not hold it): a send to any face under both
    /// neither waits nor is owed, and the session's lock is never held while a place is waited
    /// for. Faces are taken in one order by every operation, and a publish holds one at a time
    /// (`Self::on_faces`), so no two holders wait on each other. A place that holds no link is
    /// not held, and its face is reached by a try, as no send is owed a face with no link. `None`
    /// once the session is closed.
    #[cfg(any(feature = "listen", feature = "group"))]
    #[inline(always)]
    pub(super) fn live_on_link<U>(
        &self,
        f: impl FnOnce(&mut Core<L, C>, LinkTx<'_, C>) -> U,
    ) -> Option<U> {
        let mut operation = HeldOperation {
            f: Some(f),
            answer: None,
        };
        self.hold_faces_from(self.direct.iter(), None, &mut operation);
        operation.answer
    }

    /// Hold the send place of each face `faces` has left, after those `before` holds, then the
    /// session's lock, and run `f` under them: the session's lock is let go of first, then each
    /// place in the reverse of the order it was taken. Each place's hold lies in this frame, so
    /// holding every face takes no storage but the stack.
    // Out of line: every operation but a publish holds the faces through this one body.
    #[cfg(any(feature = "listen", feature = "group"))]
    #[inline(never)]
    fn hold_faces_from<'f>(
        &'f self,
        mut faces: impl Iterator<Item = &'f DirectFace<L, C>>,
        before: Option<&HeldSend<'_, C>>,
        f: &mut (dyn UnderHeldFaces<L, C> + '_),
    ) {
        let Some(face) = faces.next() else {
            if let Some(mut core) = self.live() {
                f.run(
                    &mut core.0,
                    FaceTx {
                        held: before,
                        alone: None,
                    },
                );
            }
            return;
        };
        // SAFETY: an operation reaches the link's send part only as `LinkTx`, a shared borrow of
        // the hold that ends before it, and what it sends is made of the session's state: no
        // handle on a cell of the link leaves the parts and none comes into them.
        let Some(mut send) = (unsafe { face.site.hold_send() }) else {
            return self.hold_faces_from(faces, before, f);
        };
        let held = HeldSend {
            face: &face.end,
            wire: send.tx().and_then(|tx| tx.as_ref()),
            before,
        };
        self.hold_faces_from(faces, Some(&held), f);
    }

    /// A publish's leg to the faces: `leg` on each face's wire (`LinkTx`) in the order of the
    /// face table, the face's send place held as [`Self::live_on_link`] holds each,
    /// and let go of before the next face's is taken, so no thread holds two faces' places and a
    /// face that waits holds up no other. `leg` takes the session's lock its own way inside each
    /// hold (one that may be dropped tries it) and reaches the held face alone
    /// ([`FaceTx::reaches`]). A face whose place holds no parts is not handed to `leg`. The
    /// groups of a session that joined any are one leg after the faces', which reaches them alone
    /// ([`FaceTx::reaches_groups`]). What the last leg that failed came to, else `Ok(0)`, as a
    /// leg's own faces answer.
    // Inlined whole: a publish's path is the one a message takes each time.
    #[cfg(any(feature = "listen", feature = "group"))]
    #[inline(always)]
    pub(super) fn on_faces(
        &self,
        droppable: bool,
        mut leg: impl FnMut(LinkTx<'_, C>) -> Result<usize, FanoutError>,
    ) -> Result<usize, FanoutError> {
        #[cfg(feature = "group")]
        {
            let outcome = self.on_face_legs(droppable, &mut leg);
            self.on_groups_leg(outcome, leg)
        }
        #[cfg(not(feature = "group"))]
        {
            self.on_face_legs(droppable, &mut leg)
        }
    }

    /// [`Self::on_faces`] for a publish whose groups' leg is a body of its own, `groups`: one
    /// that reads only what a group is sent, and none of what a face's leg reads to send on a
    /// face's link.
    #[cfg(feature = "group")]
    #[inline(always)]
    pub(super) fn on_publish_legs(
        &self,
        droppable: bool,
        mut leg: impl FnMut(LinkTx<'_, C>) -> Result<usize, FanoutError>,
        groups: impl FnOnce(LinkTx<'_, C>) -> Result<usize, FanoutError>,
    ) -> Result<usize, FanoutError> {
        let outcome = self.on_face_legs(droppable, &mut leg);
        self.on_groups_leg(outcome, groups)
    }

    /// The faces' legs of [`Self::on_faces`]: `leg` on each face that may hold a link. A face at
    /// rest (`DirectFace::rests`) holds no link that is up, so a leg would send it nothing, and
    /// its place is not tried; nor is a row past the last that holds a face
    /// (`DirectFaces::walked`).
    #[cfg(any(feature = "listen", feature = "group"))]
    #[inline(always)]
    fn on_face_legs(
        &self,
        droppable: bool,
        leg: &mut impl FnMut(LinkTx<'_, C>) -> Result<usize, FanoutError>,
    ) -> Result<usize, FanoutError> {
        let mut outcome = Ok(0);
        for (at, face) in self.direct.walked().enumerate() {
            if face.rests.load(Ordering::Acquire) {
                continue;
            }
            #[cfg(test)]
            self.takes.place_tries.fetch_add(1, Ordering::Relaxed);
            // A place another thread holds is held only where there are other threads.
            let sent = if droppable && <CoopForm as ThreadForm>::OTHER_THREADS {
                self.try_leg(face, at, leg)
            } else {
                Self::wait_leg(face, at, leg)
            };
            if let Some(Err(error)) = sent {
                outcome = Err(error);
            }
        }
        outcome
    }

    /// The groups' leg, after the faces' legs came to `outcome`: a group is written on through its
    /// own stage, under the session's lock, so its leg holds no face's place and reaches no face's
    /// link. A session that joined no group is handed none, which would take the session for
    /// nothing.
    #[cfg(feature = "group")]
    #[inline(always)]
    fn on_groups_leg(
        &self,
        outcome: Result<usize, FanoutError>,
        leg: impl FnOnce(LinkTx<'_, C>) -> Result<usize, FanoutError>,
    ) -> Result<usize, FanoutError> {
        if !self.joins_groups {
            return outcome;
        }
        let sent = leg(FaceTx {
            held: None,
            alone: Some(GROUPS_LEG),
        });
        if sent.is_err() {
            sent
        } else {
            outcome
        }
    }

    /// `leg` on `face`, the face at place `at`, under a hold of its send place, which waits for
    /// whatever holds it now. `None`, with `leg` not run, while the place holds no parts.
    #[cfg(any(feature = "listen", feature = "group"))]
    #[inline(always)]
    fn wait_leg(
        face: &DirectFace<L, C>,
        at: usize,
        leg: &mut impl FnMut(LinkTx<'_, C>) -> Result<usize, FanoutError>,
    ) -> Option<Result<usize, FanoutError>> {
        // SAFETY: as in `Self::hold_faces_from`: `leg` reaches the send part only as `LinkTx`.
        let mut send = unsafe { face.site.hold_send() }?;
        let held = HeldSend {
            face: &face.end,
            wire: send.tx().and_then(|tx| tx.as_ref()),
            before: None,
        };
        Some(leg(FaceTx {
            held: Some(&held),
            alone: Some(at),
        }))
    }

    /// `leg` of a droppable publish on `face`, the face at place `at`: its send place tried, and
    /// while another holder has it, the face passed over or the place waited for as the queue
    /// profile says (`Self::behind_held_place`). A look at the face's link lends nothing of the
    /// place (`SiteFacts`), as zenoh-pico's read takes no transmit lock to look at its transport,
    /// so a place found held is a transmit lock found taken. What the leg left owed on the link
    /// is told to the place as the try lets go. `None`, with `leg` not run, while the place
    /// holds no parts.
    #[cfg(any(feature = "listen", feature = "group"))]
    #[inline(never)]
    fn try_leg(
        &self,
        face: &DirectFace<L, C>,
        at: usize,
        leg: &mut impl FnMut(LinkTx<'_, C>) -> Result<usize, FanoutError>,
    ) -> Option<Result<usize, FanoutError>> {
        loop {
            let lent = face.site.try_lend(|parts| {
                let mark = face.site.facts().write_mark();
                let sent = {
                    // SAFETY: as in `Self::hold_faces_from`: `leg` reaches the send part only as
                    // `LinkTx`, a borrow of the lend that ends before it.
                    let wire = unsafe { parts.parts_mut() }.tx().as_ref();
                    let held = HeldSend {
                        face: &face.end,
                        wire,
                        before: None,
                    };
                    leg(FaceTx {
                        held: Some(&held),
                        alone: Some(at),
                    })
                };
                face.site.tell_written(mark, parts);
                sent
            });
            match lent {
                Lend::Lent(sent) => return Some(sent),
                Lend::Empty => return None,
                Lend::Held => {}
            }
            match self.behind_held_place(at) {
                Behind::TryAgain => core::hint::spin_loop(),
                Behind::WaitForSession => return Self::wait_leg(face, at, leg),
                Behind::Dropped { told, .. } => return Some(self.dropped_on_face(told)),
            }
        }
    }

    /// `f` on the session's state where the dial role's face is the only face: its send place
    /// held, then the session's lock, both let go of as the hold drops (`Self::hold_dial`), and
    /// `f` run in the caller's own body, so an operation costs what it would with the session's
    /// lock alone, and the hold's one call. `None` once the session is closed.
    #[cfg(not(any(feature = "listen", feature = "group")))]
    #[inline(always)]
    pub(super) fn live_on_link<U>(
        &self,
        f: impl FnOnce(&mut Core<L, C>, LinkTx<'_, C>) -> U,
    ) -> Option<U> {
        // Matched where `Self::hold_dial` wrote it, not moved out of its `Option`: each
        // operation's body would otherwise copy the whole hold into a frame of its own.
        let mut held = self.hold_dial();
        let (core, tx) = held.as_mut()?.parts();
        Some(f(core, tx))
    }

    /// The dial role's send place, held by a hold that waits for another send that holds it
    /// now, then the session's lock: what an operation holds where that face is the only face.
    /// A place that holds no link is not held. `None` once the session is closed, the place let
    /// go of first.
    // Out of line: every operation but a publish holds the face through this one body.
    #[cfg(not(any(feature = "listen", feature = "group")))]
    #[inline(never)]
    fn hold_dial(&self) -> Option<DialHeld<'_, L, C>> {
        // SAFETY: an operation reaches the link's send part only as `LinkTx`, a shared borrow of
        // the hold that ends before it (`DialHeld::parts`), and what it sends is made of the
        // session's state: no handle on a cell of the link leaves the parts and none comes into
        // them.
        let mut send = unsafe { self.direct.dial.site.hold_send() };
        // Found here, once, so an operation's body reads the wire and walks no hold.
        let wire = send
            .as_mut()
            .and_then(|send| send.tx())
            .and_then(|tx| tx.as_ref())
            .map(NonNull::from);
        let core = self.live()?;
        Some(DialHeld {
            core: ManuallyDrop::new(core),
            send: ManuallyDrop::new(send),
            wire,
        })
    }

    /// A publish's leg where the dial role's face is the only face: `leg` under a hold of its
    /// send place, unless the place holds no link. What the leg came to when it failed, else
    /// `Ok(0)`, as a leg's own faces answer.
    // Inlined whole: a publish's path is the one a message takes each time.
    #[cfg(not(any(feature = "listen", feature = "group")))]
    #[inline(always)]
    pub(super) fn on_faces(
        &self,
        droppable: bool,
        mut leg: impl FnMut(LinkTx<'_, C>) -> Result<usize, FanoutError>,
    ) -> Result<usize, FanoutError> {
        let face = &self.direct.dial;
        // A place another thread holds is held only where there are other threads.
        if droppable && <CoopForm as ThreadForm>::OTHER_THREADS {
            loop {
                let lent = face.site.try_lend(|parts| {
                    let mark = face.site.facts().write_mark();
                    let sent = {
                        // SAFETY: as in `Self::hold_dial`: `leg` reaches the send part only as
                        // `LinkTx`, a borrow of the lend that ends before it.
                        let wire = unsafe { parts.parts_mut() }.tx().as_ref();
                        leg(FaceTx { wire })
                    };
                    face.site.tell_written(mark, parts);
                    sent
                });
                match lent {
                    Lend::Lent(sent) => return sent.map(|_| 0),
                    Lend::Empty => return Ok(0),
                    Lend::Held => {}
                }
                // A look at the link lends nothing of the place, as `Self::try_leg` reads it: a
                // place found held is a transmit lock found taken. The dial role's face is at the
                // first place.
                match self.behind_held_place(0) {
                    Behind::TryAgain => core::hint::spin_loop(),
                    Behind::WaitForSession => break,
                    Behind::Dropped { told, .. } => return self.dropped_on_face(told),
                }
            }
        }
        // SAFETY: as in `Self::hold_dial`: `leg` reaches the send part only as `LinkTx`.
        let mut send = unsafe { face.site.hold_send() };
        // Matched where it lies, as an operation's hold is (`Self::live_on_link`): the send is
        // not moved out of its `Option` on a publish's path.
        let Some(send) = send.as_mut() else {
            return Ok(0);
        };
        let wire = send.tx().and_then(|tx| tx.as_ref());
        leg(FaceTx { wire })?;
        Ok(0)
    }

    /// What a droppable publish does on the face at place `at`, whose send place another send
    /// holds now, by the queue profile's `held_drop`, with nothing of the session held: pico's
    /// drops it on the face at once and tells the caller, as pico's put fails when its try of the
    /// transmit lock finds it held; zenoh's asks the face's link for room within
    /// `wait_before_drop`, tries the place again once the link took room and drops the publish on
    /// the face, untold, when it took none. A face that names no wait for its room is waited for.
    fn behind_held_place(&self, at: usize) -> Behind<DroppedOn> {
        let room = match self.held_drop {
            HeldDrop::DropAtOnce => Room::Held(mark_of_place(at)),
            HeldDrop::WaitForRoom => self.rooms.within_face(at, self.wait_before_drop_us),
        };
        room.behind()
    }

    /// What a droppable publish's leg answers once it is dropped on a face whose send place
    /// another holder has, counted as the transport's drop as a drop behind the session is.
    fn dropped_on_face(&self, told: bool) -> Result<usize, FanoutError> {
        #[cfg(feature = "transport-stats")]
        self.unsent_drops.fetch_add(1, Ordering::Relaxed);
        if told {
            Err(FanoutError::HeldConduit)
        } else {
            Ok(0)
        }
    }

    /// When the earliest face is next due, as a read's wait reads it and as the faces' slots
    /// hold it.
    #[cfg(all(test, feature = "std", any(feature = "listen", feature = "group")))]
    pub(crate) fn faces_due_waited_and_held(&self) -> (u64, u64) {
        let held = self
            .direct
            .iter()
            .filter_map(|face| {
                <CoopForm as LockForm>::try_lock(&face.slot).map(|slot| slot.0.due_us())
            })
            .min()
            .unwrap_or(u64::MAX);
        (self.faces_due_us(), held)
    }

    /// When the one face is next due, as a read's wait under its slot gives it the session, and
    /// as the slot holds it.
    #[cfg(all(test, feature = "std", not(any(feature = "listen", feature = "group"))))]
    pub(crate) fn faces_due_waited_and_held(&self) -> (u64, u64) {
        let held = <CoopForm as LockForm>::try_lock(&self.direct.dial.slot)
            .expect("no read holds the one face's slot between reads");
        let wait = self.link_wait(self.wait_due(&held.0), None);
        let mut core = self.live().expect("the session is open");
        // The wait is handed back unwaited, as a read hands back the one it made.
        if let Some(wait) = wait {
            core.0.transport.links.waited(wait);
        }
        (core.0.link_due_us, held.0.due_us())
    }

    /// The rows of the session's face table, and the faces of them a read turns: the dial
    /// role's and each past it whose row holds a face (`DirectFaces::turned`).
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn direct_faces(&self) -> (usize, usize) {
        let rows = self.direct.iter().count();
        #[cfg(any(feature = "listen", feature = "group"))]
        let turned = self.direct.turned().count();
        #[cfg(not(any(feature = "listen", feature = "group")))]
        let turned = rows;
        (rows, turned)
    }

    /// The rows a read walks (`DirectFaces::walked`): the dial role's, and each past it up to the
    /// last that holds a face.
    #[cfg(all(
        test,
        feature = "listen",
        feature = "query",
        feature = "queryable",
        feature = "threads"
    ))]
    pub(crate) fn walked_rows(&self) -> usize {
        self.direct.walked().count()
    }

    /// How many legs a publish's walk of the faces hands out (`Self::on_faces`), and how many
    /// faces that are up those legs reach between them.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn legs_of_a_publish(&self) -> (usize, usize) {
        let (mut legs, mut reached) = (0, 0);
        let _ = self.on_faces(false, |tx| {
            legs += 1;
            if let Some(core) = self.live() {
                reached += core
                    .0
                    .up_wires_at()
                    .filter(|(_, wire)| tx.reaches(wire))
                    .count();
            }
            Ok(0)
        });
        (legs, reached)
    }

    /// How many of a publish's legs reach the session's groups (`FaceTx::reaches_groups`).
    #[cfg(all(test, feature = "std", feature = "group"))]
    pub(crate) fn group_legs_of_a_publish(&self) -> usize {
        let mut legs = 0;
        let _ = self.on_faces(false, |tx| {
            legs += usize::from(tx.reaches_groups());
            Ok(0)
        });
        legs
    }

    /// Whether the one link's send place is free now: a try of it finds no holder.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn send_place_is_free(&self) -> bool {
        !matches!(self.direct.dial.site.try_lend(|_| ()), Lend::Held)
    }

    /// Run `held` while this thread holds the send place of the dial role's face, as a send holds
    /// it: what a test of a publish that finds that place held runs beside one. `None`, with
    /// `held` not run, while the place holds no link.
    #[cfg(all(
        test,
        feature = "std",
        feature = "threads",
        not(any(feature = "listen", feature = "group"))
    ))]
    pub(crate) fn holding_the_dial_send_place<U>(&self, held: impl FnOnce() -> U) -> Option<U> {
        // SAFETY: the hold lends nothing of the link: no handle on a cell of it is made.
        let send = unsafe { self.direct.dial.site.hold_send() }?;
        let answer = held();
        drop(send);
        Some(answer)
    }

    /// How many faces that are up an operation reaches through the wire its hold of their place
    /// holds, and how many by a try of their own place.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn faces_reached_by_an_operation(&self) -> (usize, usize) {
        self.live_on_link(|core, tx| {
            core.up_wires_at().fold((0, 0), |(held, tried), (_, wire)| {
                if tx.held_wire(wire).flatten().is_some() {
                    (held + 1, tried)
                } else {
                    (held, tried + 1)
                }
            })
        })
        .unwrap_or((0, 0))
    }

    /// Whether an operation runs now (`Self::live_on_link`): `false` once the session is closed.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn an_operation_runs(&self) -> bool {
        self.live_on_link(|_, _| ()).is_some()
    }

    /// Inside an operation, how many faces whose place holds a link a try of their place finds
    /// held, and how many it finds free.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn places_held_by_an_operation(&self) -> (usize, usize) {
        self.live_on_link(|_, _| {
            self.direct.iter().fold((0, 0), |(held, free), face| {
                match face.site.try_lend(|_| ()) {
                    Lend::Held => (held + 1, free),
                    Lend::Lent(()) => (held, free + 1),
                    Lend::Empty => (held, free),
                }
            })
        })
        .unwrap_or((0, 0))
    }

    /// Let go of each face's link at the close, unless a read steps it now: that read lets it go
    /// once it has returned from the pump.
    pub(super) fn let_go_link(&self) {
        for face in self.direct.iter() {
            if let Some(mut held) = <CoopForm as LockForm>::try_lock(&face.slot) {
                held.0.let_go();
            }
        }
    }

    /// Run `f` on the session's one reassembly Router with the time now on the epoch its chains
    /// are staged on: what a test of the chains the session's read ends stages its chain in and
    /// reads them by. Uncounted as a take and as a reading of the session's clock.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn with_chain_router<T>(
        &self,
        f: impl FnOnce(&mut SessionReassembly, u64) -> T,
    ) -> T {
        let now_ms = {
            let core = self.core.lock();
            core.0.session_time.ms_at(core.0.clock.now_us())
        };
        let mut held = <CoopForm as LockForm>::lock(&self.direct.dial.slot);
        f(&mut held.0.router, now_ms)
    }
}
