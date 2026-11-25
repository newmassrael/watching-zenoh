// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The read of a session that holds one face and runs no read task beside the program's calls (a
//! build with none of `threads`, `listen` and `group`): the read steps the one link's session
//! itself, and hands each record out as it is read.
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
//! Where the link stands is the life of the face's record ([`UnicastLink`]), the session's one
//! record of it, as in a build whose links are tasks: the engine's face holds what the life's
//! effects are carried out with (the dial under way, the link it made, the pump) and nothing of
//! where the link stands.

use super::*;

use core::marker::PhantomData;
use core::mem::{ManuallyDrop, MaybeUninit};
use core::ptr::addr_of_mut;
use core::sync::atomic::AtomicBool;

use wz_runtime_coop::faces::{Dial, FaceAt, FaceSite, LinkEnd, SendParts, SiteSend, WireParts};
use wz_runtime_coop::link_cells::{FaceHeld, FaceParts};
use wz_runtime_coop::session_drive::LinkOpenError;
use wz_runtime_coop::sync::ConfinedOwner;
use wz_runtime_coop::transport::{LinkPump, OpenedAs, PlacedWire, PumpPlace};
use wz_session_core::driver_loop::DriverLoopOutcome;
use wz_session_core::link_life::{LinkInput, LinkPhase, Refused};

use super::registry::Planes;
use wz_session_core::bounded::{BoundedVec, Lent};

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

/// What the read hands each step of the one link's pump with, beside the engine: the face the
/// link serves, the link's actions, and the session's planes the dispatch of a record writes
/// ([`FaceDispatch`] in a build whose links run as tasks).
pub(crate) struct FaceRecords<C: ClockSource + 'static> {
    pub(super) face: HeldFace,
    pub(super) actions: LinkHandle<C>,
    #[cfg(feature = "queryable")]
    pub(super) plane: PlacedRef<QueryPlane>,
    /// The link's generation, which the queries it carries are answered under.
    #[cfg(feature = "queryable")]
    pub(super) generation: u64,
    /// Whether Pushes were dispatched whose drains are still owed ([`EventSink::end_records`]).
    pub(super) after_pushes: bool,
}

impl<C: ClockSource + 'static> FaceRecords<C> {
    /// Dispatch `event`, a record that is not a Push lent where its frame lies, to the planes
    /// `planes` names of the face's tables in `registry`, the held session's, and send what it
    /// staged.
    #[cfg(feature = "queryable")]
    fn dispatch(&self, registry: &mut Registry, event: IterationEvent<'_, '_>, planes: Planes) {
        let face = self.face;
        let actions = &*self.actions;
        // What the declaration watches are told of this frame is this link's peer's.
        #[cfg(any(
            feature = "remote-declaration-watch",
            feature = "declarations-synced-event"
        ))]
        registry.hear_decl_link(|| actions.peer_session_zid());
        registry.dispatch_event_to(face, event, planes);
        registry.flush_pending_replies(face, actions);
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

    /// The query `rid` of the face's link owes its `Final`, of `qos`: sent now when nothing
    /// holds it, and otherwise once the last callback or kept query holding it lets go.
    #[cfg(feature = "queryable")]
    pub(super) fn owe_final(&self, rid: wz_session_core::wire_id::RequestId, qos: QosLevel) {
        if self
            .plane
            .with_holds(|holds| holds.owe(self.generation, rid, qos))
        {
            self.actions.send_response_final(rid, qos);
        }
    }

    /// Keep the key form of each query `event` carries by an id of the shared dictionary, so a
    /// reply on its key mirrors it.
    #[cfg(all(feature = "queryable", feature = "shared-key-ids"))]
    pub(super) fn note_requests(&self, event: &IterationEvent<'_, '_>) {
        self.actions.note_requests(event);
    }

    /// A build without the shared key ids keeps no key form of a query.
    #[cfg(all(feature = "queryable", not(feature = "shared-key-ids")))]
    pub(super) fn note_requests(&self, _event: &IterationEvent<'_, '_>) {}

    /// See the build with queryables: one without has no query to owe a Final.
    #[cfg(not(feature = "queryable"))]
    fn dispatch(&self, registry: &mut Registry, event: IterationEvent<'_, '_>, planes: Planes) {
        let actions = &*self.actions;
        // What the declaration watches are told of this frame is this link's peer's.
        #[cfg(any(
            feature = "remote-declaration-watch",
            feature = "declarations-synced-event"
        ))]
        registry.hear_decl_link(|| actions.peer_session_zid());
        registry.dispatch_to(self.face, event, planes, actions);
    }
}

/// What a step of the one link's pump hands its records to: each dispatched under the session's
/// lock, which is let go of before the record is handed out, so its callback finds the session
/// free and the next record is read after the callback returned.
struct DirectSink<'a, L: CoopLinks + 'static, C: ClockSource + Clone + 'static> {
    engine: &'a CoopEngine<L, C>,
    records: &'a mut FaceRecords<C>,
}

impl<L: CoopLinks + 'static, C: ClockSource + Clone + 'static> DirectSink<'_, L, C> {
    /// The drains a run of Pushes put off ([`Registry::settle`]), once for the run: at the end of
    /// the frame, or before the first record of it that is not a Push (`within_frame`), which a
    /// test counts as a build whose links are tasks does (`FaceDispatch`).
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
            registry.settle(self.records.face, &*self.records.actions);
        }
        #[cfg(not(all(test, feature = "std", feature = "queryable")))]
        let _ = within_frame;
        self.engine.deliver();
    }
}

impl<L: CoopLinks + 'static, C: ClockSource + Clone + 'static> EventSink for DirectSink<'_, L, C> {
    fn event(&mut self, event: IterationEvent<'_, '_>) {
        let push = lent_push(&event);
        // What the Pushes before this record put off is done before it, as it was after each.
        if !push {
            self.drain_pushes(true);
        }
        match event {
            // Handed to its subscribers one at a time (`pinned`), none of it into the round.
            IterationEvent::InPlace(ref record) if push => {
                self.engine.hand_lent_push(self.records.face, record);
                self.records.after_pushes = true;
            }
            // Handed to the get it answers with the session let go of (`replies`), none of it
            // into the round.
            #[cfg(feature = "query")]
            IterationEvent::InPlace(ref record) if record.response().is_some() => {
                self.engine.hand_lent_reply(self.records.face, record);
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

/// The owner of the place of the one link's parts ([`DirectFace`]).
pub(super) enum DirectOwner {}

// SAFETY: a session whose read steps its one link itself is built in the form of one thread
// (`OneThread`, as `threads` is off): the program calls into the engine from one thread at a
// time, so the place of the link's send part, reached by every send and by the read's making and
// dropping of the link, is reached by one thread at a time, and its value never moves to another
// while a lend of it is under way.
unsafe impl ConfinedOwner for DirectOwner {}

/// How the place of the one link's parts is held: by the one thread of the session's form.
type DirectLock = wz_runtime_coop::sync::Confined<DirectOwner>;

/// The link the session's record of the face holds while it is up or in its handshake: a handle
/// on the place of the link's parts, which holds none of them.
pub(super) type DirectWire<L, C> = FaceAt<DirectLock, DirectParts<L, C>, DirectEnd>;

/// The place of the one link's send part.
type DirectSite<L, C> = FaceSite<DirectLock, DirectParts<L, C>>;

/// What an operation holds of one face's send place, taken before the session's lock
/// (`CoopEngine::hold_on_link`): the face, named by the flags its link's end shares with the
/// read, and the face's wire while the place holds one. A send to that face writes the wire; a
/// send to any other face is lent that face's link by a try of its place, which waits for
/// nothing under the session's lock (`super::send_through`).
pub(super) struct FaceTx<'a, C: ClockSource + 'static> {
    face: &'a EndFlags,
    wire: Option<&'a Wire<C>>,
}

impl<C: ClockSource + 'static> Clone for FaceTx<'_, C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<C: ClockSource + 'static> Copy for FaceTx<'_, C> {}

impl<'a, C: ClockSource + 'static> FaceTx<'a, C> {
    /// Whether `link`, a face's record of its link, lies in the face whose place is held.
    #[inline(always)]
    pub(super) fn holds<L: CoopLinks + 'static>(&self, link: &DirectWire<L, C>) -> bool {
        link.end().is_of(self.face)
    }

    /// The held face's wire; `None` while its place holds no link.
    #[inline(always)]
    pub(super) fn wire(&self) -> Option<&'a Wire<C>> {
        self.wire
    }
}

/// The session's state an operation holds, with the one link's place held before it
/// (`CoopEngine::hold_on_link`): let go of in the reverse order, the session's lock first.
pub(super) struct OnLinkHold<'a, L: CoopLinks + 'static, C: ClockSource + 'static> {
    /// The face whose place is held.
    face: &'a EndFlags,
    core: ManuallyDrop<LiveCore<'a, L, C>>,
    place: ManuallyDrop<Option<SiteSend<'a, DirectLock, DirectParts<L, C>>>>,
}

impl<L: CoopLinks + 'static, C: ClockSource + 'static> OnLinkHold<'_, L, C> {
    /// The session's state, and the link's wire it sends through: none where the place holds no
    /// link.
    #[inline(always)]
    pub(super) fn parts(&mut self) -> (&mut Core<L, C>, LinkTx<'_, C>) {
        let wire = self
            .place
            .as_mut()
            .and_then(|send| send.tx())
            .and_then(|tx| tx.as_ref());
        let tx = FaceTx {
            face: self.face,
            wire,
        };
        (&mut self.core.0, tx)
    }
}

impl<L: CoopLinks + 'static, C: ClockSource + 'static> Drop for OnLinkHold<'_, L, C> {
    // Out of line: every operation but a publish lets go of the session and the place through it.
    #[inline(never)]
    fn drop(&mut self) {
        // SAFETY: each field is dropped here alone, once, and not reached after; the session's
        // lock goes before the place it was taken inside.
        unsafe {
            ManuallyDrop::drop(&mut self.core);
            ManuallyDrop::drop(&mut self.place);
        }
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
// the wire only through a hold of the place. The receive part's handles on the same cells (the
// pump's link, the records' actions) are made and dropped by the read alone, under its slot; the
// cells they share are reached through the link's own cells, of the session's lock kind. Nothing of
// the parts is bound to a thread, and their place is reached by the one thread of the session's
// form (`DirectOwner`).
unsafe impl<L: CoopLinks + 'static, C: ClockSource + 'static> FaceParts for DirectParts<L, C> {}

impl<L: CoopLinks + 'static, C: ClockSource + 'static> DirectParts<L, C> {
    /// Parts of no link yet.
    fn none() -> Self {
        Self {
            wire: None,
            of: PhantomData,
        }
    }
}

impl<L: CoopLinks + 'static, C: ClockSource + 'static> WireParts for DirectParts<L, C> {
    type Wire = Wire<C>;

    fn wire(&self) -> Option<&Wire<C>> {
        self.wire.as_ref()
    }

    /// The parts define no debt of their own: every send of the session reaches the wire through
    /// the link's place, taken before the session's lock, and waits for its holder, so none is
    /// owed.
    fn pay(&mut self, _owed: u32) {}
}

/// A send writes the link's wire, through a hold of its place.
impl<L: CoopLinks + 'static, C: ClockSource + 'static> SendParts for DirectParts<L, C> {
    type Tx = Option<Wire<C>>;

    fn tx(&mut self) -> &mut Option<Wire<C>> {
        &mut self.wire
    }

    fn wire_of(tx: &Option<Wire<C>>) -> Option<&Wire<C>> {
        tx.as_ref()
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
    records: Option<FaceRecords<C>>,
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
}

impl<L: CoopLinks + 'static, C: ClockSource + 'static> DirectSlot<L, C> {
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
        drop(site.take());
    }

    /// Let go of the link: the dial and the link it made are let go of, and the pump goes. The
    /// life of the face's record was closed by the session's end of its links (`end_links`).
    fn let_go(&mut self) {
        self.dial = None;
        self.opened = None;
        self.drop_pump();
    }
}

impl<L: CoopLinks + 'static, C: ClockSource + 'static> Drop for DirectSlot<L, C> {
    fn drop(&mut self) {
        self.drop_pump();
    }
}

impl<L: CoopLinks + 'static, C: ClockSource + Clone + 'static> DirectSlot<L, C> {
    /// What the link brings to its life at this look: a handshake completed, a pump that ended or
    /// was asked to, a dial the network answered, or only the time.
    fn next_input(&mut self, core: &Core<L, C>, end: &EndFlags) -> LinkInput {
        // The face's record holds the link exactly while its parts hold the pump.
        let linked = core
            .transport
            .links
            .face(self.at)
            .filter(|face| face.link.wire().is_some());
        if let Some(face) = linked {
            let established = matches!(face.life.phase(), LinkPhase::Handshaking { .. })
                && face.link.wire().is_some_and(|wire| wire.established());
            if established {
                return LinkInput::Established;
            }
            return if end.over() {
                LinkInput::Ended
            } else {
                LinkInput::Tick
            };
        }
        let Some(answer) = self
            .dial
            .as_mut()
            .and_then(|dial| dial.answer::<L::Pump, LinkCount>())
        else {
            return LinkInput::Tick;
        };
        let Some(dial) = self.dial.take() else {
            return LinkInput::Tick;
        };
        self.answered(core, dial.into_endpoint(), answer)
    }

    /// Dial the session's endpoint at `row`, as the life asked: what the dial came to at once.
    fn dial_row(&mut self, core: &Core<L, C>, row: usize) -> LinkInput {
        self.dial = None;
        let transport = &core.transport;
        let pending = match transport.begin_dial(transport.endpoints.dial_text(row)) {
            Ok(pending) => pending,
            Err(refused) => {
                self.last = Some(OpenError::from(refused));
                return LinkInput::DialRefused;
            }
        };
        let mut dial = Dial::new(DialEndpoint::Listed(row), pending);
        match dial.answer::<L::Pump, LinkCount>() {
            None => {
                self.dial = Some(dial);
                LinkInput::DialPending
            }
            // A dial that answered has handed out all it held for its link, so it is let go of
            // before the link is opened.
            Some(answer) => self.answered(core, dial.into_endpoint(), answer),
        }
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
                    }))
                },
            );
            addr_of_mut!((*at).site).write(FaceSite::empty());
            addr_of_mut!((*at).end).write(EndFlags::default());
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
/// after its first, made at the open and kept where they lie for the session's life.
pub(super) type TakenFaces<L, C> = BoundedVec<DirectFace<L, C>, { usize::MAX }, Lent>;

/// Every face the read steps itself: the dial role's, at the face table's first place, in the
/// engine's place, and one for each place after it in a table of the session's arena
/// ([`TakenFaces`]). Each face has its own read slot, Router and send place, so a face's read
/// and its sends never wait on another face's; and none moves, so the session's record of a face
/// reaches its place by a handle.
pub(super) struct DirectFaces<L: CoopLinks + 'static, C: ClockSource + 'static> {
    dial: DirectFace<L, C>,
    taken: TakenFaces<L, C>,
}

impl<L: CoopLinks + 'static, C: ClockSource + Clone + 'static> DirectFaces<L, C> {
    /// The faces past the dial role's, `rows` of them lent from `arena`: the face of the face
    /// table's place `n` in the table's row `n - 1`, each with a Router of its own under
    /// `policy`, staging its chains in `chains`, lent through `lend`. Refused past what the
    /// arena has left.
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
        taken: TakenFaces<L, C>,
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
            addr_of_mut!((*at).taken).write(taken);
        }
    }

    /// Let go of every face's link with the faces owned whole: the engine's drop.
    pub(super) fn let_go_owned(&mut self) {
        self.dial.let_go_owned();
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
            if !crate::arena::dials_of(
                core.transport.endpoints.dials(),
                core.transport.endpoints.listens(),
                core.config.groups.len(),
            ) {
                return Ok(());
            }
            let now_us = core.now_us();
            self.drive_link(core, slot, LinkInput::Open, now_us)?;
        }
        while !self.link_is_up(slot.at) {
            let turn = self.link_turn(slot).ok_or(OpenError::NoEndpoint)?;
            if let Some(last) = turn.ended {
                return Err(last);
            }
        }
        Ok(())
    }

    /// The read of a session whose read steps its one link itself: the wait for the link's input
    /// or the next deadline, a look at the link's life and the session's bookkeeping when they are
    /// owed, then the pump stepped with nothing of the session held, each record handed out as it
    /// is read. A read from a callback reads nothing: the read under way holds the link, and any
    /// other delivery marks the thread as delivering.
    pub(super) fn read_direct(&self) -> Result<(), SessionClosed> {
        // A callback reads nothing either while a delivery other than a read's runs it (a put to
        // the session's own subscribers): a record read here would be handed to a callback inside
        // another.
        let held = if self.deliveries.delivers_here() {
            None
        } else {
            <CoopForm as LockForm>::try_lock(&self.direct.dial.slot)
        };
        let Some(mut held) = held else {
            return if self.closed.load(Ordering::Acquire) {
                Err(SessionClosed)
            } else {
                Ok(())
            };
        };
        let slot = &mut held.0;
        let read = self.read_held(slot);
        // A close made while the read stepped the pump (a callback's) ended the link's life but
        // left the pump, which the read held: it goes now, once no step of it is under way.
        if self.closed.load(Ordering::Acquire) {
            slot.let_go();
        }
        read
    }

    /// [`Self::read_direct`] with the face held.
    fn read_held(&self, slot: &mut DirectSlot<L, C>) -> Result<(), SessionClosed> {
        let turn = self.link_turn(slot).ok_or(SessionClosed)?;
        self.deliver();
        if turn.ended.is_some() {
            return Err(SessionClosed);
        }
        if let Some(started_ms) = turn.jobs_due_ms {
            self.run_due_tickers(started_ms);
        }
        if self.closed.load(Ordering::Acquire) {
            Err(SessionClosed)
        } else {
            Ok(())
        }
    }

    /// One turn of the one link, the open's and each read's: the wait for the link's input or the
    /// next deadline, a look at the link's life, and a step of the pump unless the look ended the
    /// session. `None` once the session closed. Out of line: the open and the read step the link
    /// through one body.
    #[inline(never)]
    fn link_turn(&self, slot: &mut DirectSlot<L, C>) -> Option<LinkTurn> {
        let mut wait = self.link_wait(slot)?;
        #[cfg(test)]
        self.takes.wait(&wait);
        wait.wait(self.rooms.waits(), sleep_ms);
        let turn = self.life_turn(slot, wait)?;
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
            let at = slot.at;
            if turn.replays
                && self.live_on_link(|core, tx| self.turn_replay(core, at, turn.now_us, tx))
                    == Some(TurnEnd::EndsLink)
            {
                slot.life_due_us = turn.now_us;
            }
            self.pump_turn(slot, &turn);
        }
        Some(turn)
    }

    /// What a read waits for, worked out under the session's lock: nothing while the link holds
    /// input it already took from its stack, else the link's input, or the earliest of the link's
    /// deadlines and the session's. `None` once the session closed.
    fn link_wait(&self, slot: &DirectSlot<L, C>) -> Option<IdleWait> {
        let mut held = self.live()?;
        held.0.link_due_us = slot.life_due_us.min(slot.pump_due_us);
        // Input the link holds is read at once, so no deadline is gathered and the clock is not
        // read for a wait that would be none. What falls due meanwhile is served by the look at
        // the life that follows, which reads the clock whether or not the read waited.
        let holds = held.0.transport.holds_input();
        #[cfg(test)]
        let holds = holds || self.takes.input_held.load(Ordering::Relaxed);
        if holds {
            #[cfg(test)]
            self.takes.held_input_reads.fetch_add(1, Ordering::Relaxed);
            return Some(IdleWait::None);
        }
        // Marked as a holder that holds no send, so a droppable publish that finds the session
        // held for the wait tries it again at once (`LinkRooms::for_held`).
        let _waiting = SendingOn::enter(&self.sending_on, WAITING);
        Some(held.0.idle_wait())
    }

    /// A look at the link's life after `wait`, under the session's lock: what the link brings is
    /// told to the life and its effects carried out, with the session's bookkeeping, when the
    /// link brings something, the life or the ledger is due, or the Router holds a chain past its
    /// deadline. `None` once the session closed.
    fn life_turn(&self, slot: &mut DirectSlot<L, C>, wait: IdleWait) -> Option<LinkTurn> {
        let mut held = self.live()?;
        let core = &mut held.0;
        // The read's last step of the link, made with nothing of the session held, may have ended
        // its session: the face no longer stands from here on.
        core.end_closed_facts();
        core.transport.links.waited(wait);
        let now_us = core.now_us();
        let now_ms = core.session_time.ms_at(now_us);
        let input = slot.next_input(core, &self.direct.dial.end);
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
                self.drive_link(core, slot, input, now_us)
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
            slot.life_due_us = core
                .transport
                .links
                .face(slot.at)
                .and_then(|face| face.life.wake_at(now_us))
                .unwrap_or(u64::MAX);
            core.link_due_us = slot.life_due_us.min(slot.pump_due_us);
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
        })
    }

    /// Step the pump with nothing of the session held: its own bookkeeping when it is due or owes
    /// what was asked of it from outside, then one unit of its link's input, the Router lent for
    /// it. A step that took nothing serves the pump, which tells its session of a link that is
    /// gone. A pump that ended has its life looked at by the next read, at once. The link's send
    /// part is not held for the step: a send a callback of a record makes inside it, or another
    /// thread makes meanwhile, holds that part itself.
    fn pump_turn(&self, slot: &mut DirectSlot<L, C>, turn: &LinkTurn) {
        let Some((ended, due_us)) = self.step_pump(slot, turn) else {
            return;
        };
        if ended {
            self.direct.dial.end.ended.store(true, Ordering::Release);
            slot.life_due_us = turn.now_us;
        }
        slot.pump_due_us = due_us;
    }

    /// One step of the pump `slot` holds at `turn`: its own bookkeeping when it is due or owes
    /// what was asked of it from outside, then one unit of its input, the slot's Router lent for
    /// it. Whether the pump ended, and when it is due next; `None` while no pump is written.
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
            let took = lend.lend_for(router, || pump.take_input_now(now_ms, &mut sink));
            #[cfg(test)]
            if took {
                self.takes.pump_reads.fetch_add(1, Ordering::Relaxed);
            }
            !took && pump.service_due(now_ms, &mut sink).is_some()
        };
        let due_us = pump.due_ms(now_ms).map_or(u64::MAX, |due_ms| {
            now_us.saturating_add(due_ms.saturating_sub(now_ms).saturating_mul(1000))
        });
        Some((ended, due_us))
    }

    /// Tell the link's life `input` at `now_us` and carry out its effects, in the order the life
    /// names them, until it asks for nothing more. `Err` with why the last endpoint came to no
    /// link when the life ends the session. Out of line: the open's first input and each look at
    /// the life carry the effects out through one body.
    #[inline(never)]
    fn drive_link(
        &self,
        core: &mut Core<L, C>,
        slot: &mut DirectSlot<L, C>,
        input: LinkInput,
        now_us: u64,
    ) -> Result<(), OpenError> {
        let (mut input, mut now_us) = (input, now_us);
        loop {
            let Some(face) = core.transport.links.face_mut(slot.at) else {
                return Ok(());
            };
            let was = face.life.phase();
            let effects = face.life.input(input, now_us);
            // A close is told to the life by the slot alone, which lets go of what it holds
            // itself (`DirectSlot::let_go`): no input told here asks for that.
            debug_assert!(!effects.let_go(), "a close told to the life past the slot");
            // A dial the life gave up on before the network answered it is its endpoint's refusal
            // for want of an answer in time, as a build whose links are tasks names it.
            if effects.dial().is_some() || effects.backs_off() || effects.ends_session() {
                if let Some(dial) = slot.dial.take() {
                    let endpoint = dial.into_endpoint();
                    slot.last = Some(OpenError::Unreachable(EndpointRefusal::new(
                        core.transport.endpoint_text(Some(&endpoint)),
                        Refusal::NoAnswerInTime,
                    )));
                }
            }
            if effects.end_handshake() {
                // Why the handshake ended is read off its link before the link goes, and names
                // the endpoint the link was dialled to, which the life stood in.
                let row = match was {
                    LinkPhase::Handshaking { row, .. } => row,
                    _ => 0,
                };
                let why = core.transport.end_handshake(slot.at);
                slot.last = Some(OpenError::Unreachable(EndpointRefusal::new(
                    core.transport.endpoints.dial_text(row),
                    why,
                )));
                slot.drop_link(&self.direct.dial.site);
                core.transport.links.put_link(slot.at, Link::Idle);
            }
            if effects.lose() {
                // The lost peer's chains end with its link: the next link's fragments would be
                // spliced onto them.
                let peer = core
                    .transport
                    .links
                    .face(slot.at)
                    .and_then(|face| face.facts.as_ref())
                    .and_then(|facts| facts.peer);
                if let Some(zid) = peer {
                    let _ended = slot.router.abort_peer(zid.as_slice());
                }
                if let Some(id) = core.transport.links.face(slot.at).map(|face| face.id) {
                    core.lose_face_link(slot.at, id);
                }
                slot.drop_link(&self.direct.dial.site);
                if effects.ends_session() {
                    slot.last = Some(OpenError::Unreachable(EndpointRefusal::new(
                        "",
                        Refusal::LinkLost,
                    )));
                }
            }
            if effects.bring_up() {
                core.bring_up(slot.at, now_us);
                slot.brought_up = true;
            }
            // The dial under way, if any, was taken above.
            if effects.ends_session() {
                return Err(slot.last.take().unwrap_or(OpenError::NoEndpoint));
            }
            input = if effects.begin_handshake() {
                self.begin_handshake(core, slot)
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
    fn hand_lent_declare(
        &self,
        records: &FaceRecords<C>,
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
    fn begin_handshake(&self, core: &mut Core<L, C>, slot: &mut DirectSlot<L, C>) -> LinkInput {
        let Some((opened, endpoint)) = slot.opened.take() else {
            return LinkInput::HandshakeRefused(Refused::Endpoint);
        };
        match self.place_link_session(core, slot, opened, &endpoint) {
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

    /// The session of the link `opened`, dialled to `endpoint`, built in the face's place for
    /// it and held by the face's link in its handshake. Never inlined, for the stack: what is built
    /// here lies in this frame alone.
    #[inline(never)]
    fn place_link_session(
        &self,
        core: &mut Core<L, C>,
        slot: &mut DirectSlot<L, C>,
        opened: OpenedLink<L::Pump, LinkCount>,
        endpoint: &DialEndpoint,
    ) -> Result<(), OpenError> {
        slot.drop_link(&self.direct.dial.site);
        self.direct.dial.end.ready();
        // SAFETY: the parts hold no handle on a cell of a link yet.
        let parts = unsafe { FaceHeld::gathered(DirectParts::none()) };
        drop(self.direct.dial.site.hold(parts));
        let params = core.link_params()?;
        // The face's record at the slot's row names the face its link's session dispatches to.
        let face = core
            .transport
            .links
            .face(slot.at)
            .map(|face| face.id)
            .ok_or(OpenError::NoEndpoint)?;
        let end = self.direct.dial.end_handle();
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
                    face,
                    role: SessionRole::Initiator,
                    endpoint: Some(endpoint),
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
        // The face's record holds the wire's waits, read once here, and no handle.
        let (input, room) = (wire.input_wait(), wire.room_wait());
        // The wire goes into its place by a try alone, under the session's lock: a send that holds
        // the place waits for that lock, so the place is never waited for here.
        let carried = OnThisThread(wire);
        let seated = self.direct.dial.site.try_lend(|held| {
            held.lend(move |parts| {
                parts.wire = Some(carried.get());
            })
        });
        if !matches!(seated, Lend::Lent(())) {
            return Err(OpenError::NoEndpoint);
        }
        // A pump not stepped yet is due at once: the read that placed it sends its first frame.
        slot.pump_due_us = 0;
        // SAFETY: the site lies in the engine's face, at the engine's fixed place, for the
        // engine's life. The session's state, which holds this handle, reaches the site only while
        // the engine stands (its drop ends the links before the face goes), and the handle does
        // nothing in its own drop.
        let wire = unsafe {
            FaceAt::new(
                &self.direct.dial.site,
                self.direct.dial.end_handle(),
                input,
                room,
            )
        };
        core.transport.links.put_link(slot.at, Link::Wire(wire));
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

    /// The session's state for an operation that sends on the one link, held with the link's send
    /// place: the place first, by a hold that waits for another send that holds it now (never for
    /// a read's step, which does not hold it), then the session's lock. A send under both neither
    /// waits nor is owed, and the session's lock is never held while the place is waited for.
    /// Where the place holds no link, the session's lock alone is taken and the hold hands no wire
    /// ([`OnLinkHold::parts`]). `None` once the session is closed.
    // Out of line: one body takes the place and the session's lock for every operation but a
    // publish.
    #[inline(never)]
    pub(super) fn hold_on_link(&self) -> Option<OnLinkHold<'_, L, C>> {
        // SAFETY: an operation reaches the link's send part only as `LinkTx`, a shared borrow of
        // the hold that ends before it, and what it sends is made of the session's state: no
        // handle on a cell of the link leaves the parts and none comes into them.
        let place = unsafe { self.direct.dial.site.hold_send() };
        let core = self.live()?;
        Some(OnLinkHold {
            face: &self.direct.dial.end,
            core: ManuallyDrop::new(core),
            place: ManuallyDrop::new(place),
        })
    }

    /// `f` on the session's state and the one link's wire, held as [`Self::hold_on_link`]
    /// holds them. `None` once the session is closed.
    #[inline(always)]
    pub(super) fn live_on_link<U>(
        &self,
        f: impl FnOnce(&mut Core<L, C>, LinkTx<'_, C>) -> U,
    ) -> Option<U> {
        let mut held = self.hold_on_link()?;
        let (core, tx) = held.parts();
        Some(f(core, tx))
    }

    /// `f` on the one link's wire (`LinkTx`), held as [`Self::hold_on_link`] holds the place,
    /// for a publish, which takes the session's lock its own way inside it (one that may be
    /// dropped tries it). `f` is handed no wire where the place holds no link. `Some` once `f`
    /// ran, which it always does.
    // Inlined whole: a publish's path is the one a message takes each time.
    #[inline(always)]
    pub(super) fn on_link<U>(&self, f: impl FnOnce(LinkTx<'_, C>) -> U) -> Option<U> {
        // SAFETY: as in `Self::hold_on_link`: `f` reaches the send part only as `LinkTx`.
        let mut send = unsafe { self.direct.dial.site.hold_send() };
        let wire = send
            .as_mut()
            .and_then(|send| send.tx())
            .and_then(|tx| tx.as_ref());
        Some(f(FaceTx {
            face: &self.direct.dial.end,
            wire,
        }))
    }

    /// Whether the one link's send place is free now: a try of it finds no holder.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn send_place_is_free(&self) -> bool {
        !matches!(self.direct.dial.site.try_lend(|_| ()), Lend::Held)
    }

    /// How many faces that are up an operation holding the dial role's send place reaches
    /// through the wire it holds, and how many by a try of their own place.
    #[cfg(all(test, feature = "std"))]
    pub(crate) fn faces_reached_by_the_dial_hold(&self) -> (usize, usize) {
        self.live_on_link(|core, tx| {
            core.up_wires_at().fold((0, 0), |(held, tried), (_, wire)| {
                if tx.holds(wire) {
                    (held + 1, tried)
                } else {
                    (held, tried + 1)
                }
            })
        })
        .unwrap_or((0, 0))
    }

    /// Let go of the one link's session at the close, unless a read steps it now: that read lets
    /// it go once it has returned from the pump.
    pub(super) fn let_go_link(&self) {
        if let Some(mut held) = <CoopForm as LockForm>::try_lock(&self.direct.dial.slot) {
            held.0.let_go();
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
