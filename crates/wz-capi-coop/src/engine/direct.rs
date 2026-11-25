// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The read of a session that holds one face and runs no read task beside the program's calls (a
//! build with none of `threads`, `listen` and `group`): the read steps the one link's session
//! itself, and hands each record out as it is read.
//!
//! The link's session (its pump) lies in the engine's face ([`DirectFace`]), apart from the
//! session's state and behind a lock of its own, with the Router its fragments are staged in. A
//! read holds the face for as long as it steps the pump; each record the pump reads is dispatched
//! under the session's lock, which is then let go of, and handed out to its callback before the
//! next record is read. A callback so finds the session free and what the records before its own
//! did, may send on the session while the link lends the frame it reads, and reads nothing when it
//! reads the session: the face is held. A close from a callback ends the link's life and asks its
//! session to end; the pump goes once the read that steps it has returned from it.
//!
//! Where the link stands is the link's life ([`UnicastLink`]), the session's one record of it:
//! the face holds what the life's effects are carried out with (the dial under way, the link it
//! made, the pump) and nothing of where the link stands.

use super::*;

use core::mem::MaybeUninit;
use core::sync::atomic::AtomicBool;

use wz_runtime_coop::faces::{Dial, LinkEnd, DIAL_LOOK_MS};
use wz_runtime_coop::transport::{LinkPump, OpenedAs, PlacedWire, PumpPlace};
use wz_session_core::link_life::{LinkInput, LinkPhase, LinkTimes, Refused, UnicastLink};

/// The pump of the session's one link, which the read steps itself.
type DirectPump<L, C> = LinkPump<Face<C, L>, CellRc<dyn SessionDatagramLink>>;

/// What the read and the link's end share of the link's session: whether its pump ended, and
/// whether the session asked it to end. Read and written with loads and stores: the pump's end
/// is read by the read that steps it, and the session asks while the read may hold the pump.
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
    /// The link the records are read from, which keeps where the datagram it lends lies.
    pub(super) link: CellRc<LinkGate<C>>,
    #[cfg(feature = "queryable")]
    pub(super) plane: PlacedRef<QueryPlane>,
    /// The link's generation, which the queries it carries are answered under.
    #[cfg(feature = "queryable")]
    pub(super) generation: u64,
    /// The session's round of deliveries, told where a rejoined message lies while its records
    /// are dispatched.
    pub(super) lane: PlacedRef<Round>,
    /// Whether Pushes were dispatched whose drains are still owed ([`EventSink::end_records`]).
    pub(super) after_pushes: bool,
}

impl<C: ClockSource + 'static> FaceRecords<C> {
    /// Dispatch `event`, a record that is not a Push lent where its frame lies, to the face's
    /// tables in `registry`, and send what it staged.
    #[cfg(feature = "queryable")]
    fn dispatch(&self, registry: &mut Registry, event: IterationEvent<'_, '_>) {
        let face = self.face;
        let actions = &*self.actions;
        let (plane, generation) = (&self.plane, self.generation);
        // The queries this frame carries arrive on this face's link.
        plane.set_arriving(generation);
        // A query by an id of the shared dictionary is kept, so its replies mirror its key form.
        #[cfg(feature = "shared-key-ids")]
        actions.note_requests(&event);
        // What the declaration watches are told of this frame is this link's peer's.
        #[cfg(any(
            feature = "remote-declaration-watch",
            feature = "declarations-synced-event"
        ))]
        registry.hear_decl_link(|| actions.peer_session_zid());
        registry.dispatch_event(face, event);
        registry.flush_pending_replies(face, actions);
        for (rid, qos) in registry.take_pending_final_rids(face) {
            if plane.with_holds(|holds| holds.owe(generation, rid, qos)) {
                actions.send_response_final(rid, qos);
            }
        }
    }

    /// Dispatch `event`, a record that is not a Push lent where its frame lies, to the face's
    /// tables in `registry`, and send what it staged.
    #[cfg(not(feature = "queryable"))]
    fn dispatch(&self, registry: &mut Registry, event: IterationEvent<'_, '_>) {
        let actions = &*self.actions;
        // What the declaration watches are told of this frame is this link's peer's.
        #[cfg(any(
            feature = "remote-declaration-watch",
            feature = "declarations-synced-event"
        ))]
        registry.hear_decl_link(|| actions.peer_session_zid());
        registry.dispatch(self.face, event, actions);
    }
}

/// What a step of the one link's pump hands its records to: each dispatched under the session's
/// lock, which is let go of before the record is handed out, so its callback finds the session
/// free and the next record is read after the callback returned.
struct DirectSink<'a, L: SessionLinks + 'static, C: ClockSource + Clone + 'static> {
    engine: &'a CoopEngine<L, C>,
    records: &'a mut FaceRecords<C>,
}

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> DirectSink<'_, L, C> {
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

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> EventSink
    for DirectSink<'_, L, C>
{
    fn event(&mut self, event: IterationEvent<'_, '_>) {
        let push = lent_push(&event);
        // What the Pushes before this record put off is done before it, as it was after each.
        if !push {
            self.drain_pushes(true);
        }
        {
            let Some(mut held) = self.engine.live() else {
                return;
            };
            // The round reads the record's parts where the link lends them, so it is told where
            // that is for the length of the record's dispatch, as a gate of a build whose links
            // are tasks tells it for the length of the datagram's.
            // SAFETY: the session's lock is held (`held`).
            unsafe { self.records.link.lend_to(&self.records.lane) };
            let registry = &mut held.0.session.registry;
            if push {
                registry.dispatch_push(self.records.face, event);
                self.records.after_pushes = true;
            } else {
                self.records.dispatch(registry, event);
            }
            // SAFETY: as above.
            unsafe { self.records.lane.set_lending(None) };
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

    fn lend_rejoined(&mut self, message: &wz_session_core::byte_cells::KeptBytes) {
        let _held = self.engine.core.lock();
        // SAFETY: the session's lock is held, taken above for the lend.
        unsafe { self.records.lane.lend_rejoined(message) };
    }

    fn end_rejoined(&mut self, message: wz_session_core::byte_cells::KeptBytes) {
        let _held = self.engine.core.lock();
        // SAFETY: as `lend_rejoined`.
        unsafe { self.records.lane.end_rejoined(message) };
    }
}

/// The one link's session and what its life's effects are carried out with, behind the face's
/// lock: the read holds it while it steps the pump.
pub(super) struct DirectSlot<L: SessionLinks + 'static, C: ClockSource + 'static> {
    /// The session's one Router, which the pump's receive is lent for each read.
    router: SessionReassembly,
    /// Where the Router is lent to the pump's receive.
    lend: RouterLend<SessionReassembly, RouterPlace>,
    /// The link's life, built at the open ([`Self::make_life`]).
    life: MaybeUninit<UnicastLink>,
    life_made: bool,
    /// The dial the life asked for, while the network has not answered it.
    dial: Option<Dial<L::Dial>>,
    /// The link a dial made, and the endpoint it reached, until its handshake is begun.
    opened: Option<(OpenedLink<L::Pump>, DialEndpoint)>,
    /// Why the last endpoint tried came to no link: what the session ends with when the life
    /// ends it.
    last: Option<OpenError>,
    /// The pump of the link, written while `records` is held.
    pump: MaybeUninit<DirectPump<L, C>>,
    /// What each step of the pump is handed, held exactly while the pump is written.
    records: Option<FaceRecords<C>>,
    /// When the life is next to be looked at, on the session's clock in microseconds.
    life_due_us: u64,
    /// When the pump's own deadlines fall next: 0 for a pump not stepped yet, `u64::MAX` while no
    /// pump is written.
    pump_due_us: u64,
}

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> DirectSlot<L, C> {
    /// The link's life, once the open built it.
    fn life(&mut self) -> Option<&mut UnicastLink> {
        if !self.life_made {
            return None;
        }
        // SAFETY: `life_made` is set once `init_in` wrote the life (`Self::make_life`).
        Some(unsafe { self.life.assume_init_mut() })
    }

    /// Build the link's life once, for `endpoints` endpoints dialled under `times`.
    fn make_life(&mut self, times: LinkTimes, endpoints: usize) {
        if !self.life_made {
            UnicastLink::init_in(&mut self.life, times, endpoints);
            self.life_made = true;
        }
    }

    /// Whether the link is up.
    fn is_up(&mut self) -> bool {
        self.life()
            .is_some_and(|life| matches!(life.phase(), LinkPhase::Up))
    }

    /// Drop the pump, when one is written: its deadlines go with it.
    fn drop_pump(&mut self) {
        if self.records.take().is_some() {
            // SAFETY: the records are held exactly while the pump is written in its place
            // (`CoopEngine::place_link_session`), and no step of it is under way: the face's lock
            // is held, which every step holds.
            unsafe { self.pump.assume_init_drop() };
        }
        // A deadline of the pump left behind would have each read's wait end at once while no
        // pump is stepped to move it on.
        self.pump_due_us = u64::MAX;
    }

    /// Let go of the link: its life is closed, the dial and the link it made are let go of, and
    /// the pump goes.
    fn let_go(&mut self) {
        if let Some(life) = self.life() {
            // A close reads no time.
            life.input(LinkInput::Close, 0);
        }
        self.dial = None;
        self.opened = None;
        self.drop_pump();
    }

    /// What the link brings to its life at this look: a handshake completed, a pump that ended or
    /// was asked to, a dial the network answered, or only the time.
    fn next_input(&mut self, core: &Core<L, C>, end: &EndFlags) -> LinkInput {
        if self.records.is_some() {
            let established = matches!(
                core.transport.links.face(0).map(|face| &face.link),
                Some(Link::Opening { wire, .. }) if wire.established()
            );
            if established {
                return LinkInput::Established;
            }
            if end.over() {
                return LinkInput::Ended;
            }
            return LinkInput::Tick;
        }
        let Some(answer) = self.dial.as_mut().and_then(|dial| dial.answer::<L::Pump>()) else {
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
        match dial.answer::<L::Pump>() {
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
        answer: Result<OpenedLink<L::Pump>, LinkOpenError>,
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
pub(super) struct DirectFace<L: SessionLinks + 'static, C: ClockSource + 'static> {
    slot: StateLock<Confined<DirectSlot<L, C>>>,
    end: EndFlags,
}

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> DirectFace<L, C> {
    /// The face of a session whose Router is `router`, lent through `lend`, with no link yet.
    pub(super) fn new(
        router: SessionReassembly,
        lend: RouterLend<SessionReassembly, RouterPlace>,
    ) -> Self {
        Self {
            slot: <CoopForm as LockForm>::new(Confined(DirectSlot {
                router,
                lend,
                life: MaybeUninit::uninit(),
                life_made: false,
                dial: None,
                opened: None,
                last: None,
                pump: MaybeUninit::uninit(),
                records: None,
                life_due_us: u64::MAX,
                pump_due_us: u64::MAX,
            })),
            end: EndFlags::default(),
        }
    }

    /// The end a wire of the face's link holds.
    fn end_handle(&self) -> DirectEnd {
        DirectEnd {
            flags: NonNull::from(&self.end),
        }
    }

    /// Let go of the link with the face owned whole: the engine's drop.
    pub(super) fn let_go_owned(&mut self) {
        <CoopForm as LockForm>::get_mut(&mut self.slot).0.let_go();
    }
}

/// What a look at the link's life came to, under the session's lock.
struct LinkTurn {
    /// The look's reading of the session's clock, in microseconds.
    now_us: u64,
    /// The same instant on the epoch the link's session measures on.
    now_ms: u64,
    /// When a periodic job is due by the look's reading.
    jobs_due_ms: Option<u64>,
    /// Why the session ended at this look, when it did.
    ended: Option<OpenError>,
}

impl<L: SessionLinks + 'static, C: ClockSource + Clone + 'static> CoopEngine<L, C> {
    /// Open the session's one link: the first endpoint dialled, and the link stepped on this thread
    /// until it is up, or the life ends the session with why the last endpoint came to no link. A
    /// session with no endpoint to dial is open at once. Never inlined, as the open of a build
    /// whose links are tasks is not.
    #[inline(never)]
    pub(super) fn open_links(&self) -> Result<(), OpenError> {
        let mut held = <CoopForm as LockForm>::lock(&self.direct.slot);
        let slot = &mut held.0;
        {
            let mut core = self.core.lock();
            let core = &mut core.0;
            core.transport.listen_on_config()?;
            core.join_groups()?;
            let times = LinkTimes {
                open_timeout_ms: core.config.open_timeout_ms,
                redial_ms: core.config.redial_ms,
                dial_look_ms: DIAL_LOOK_MS,
            };
            slot.make_life(times, core.transport.endpoints.dials());
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
        while !slot.is_up() {
            let Some(mut wait) = self.link_wait(slot) else {
                return Err(OpenError::NoEndpoint);
            };
            wait.wait(self.rooms.waits(), sleep_ms);
            let Some(turn) = self.life_turn(slot, wait) else {
                return Err(OpenError::NoEndpoint);
            };
            if let Some(last) = turn.ended {
                return Err(last);
            }
            self.pump_turn(slot, &turn);
        }
        Ok(())
    }

    /// The read of a session whose read steps its one link itself: the wait for the link's input
    /// or the next deadline, a look at the link's life and the session's bookkeeping when they are
    /// owed, then the pump stepped with nothing of the session held, each record handed out as it
    /// is read. A read from a callback of a record reads nothing: the read under way holds the
    /// link.
    pub(super) fn read_direct(&self) -> Result<(), SessionClosed> {
        let Some(mut held) = <CoopForm as LockForm>::try_lock(&self.direct.slot) else {
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
        let mut wait = self.link_wait(slot).ok_or(SessionClosed)?;
        #[cfg(test)]
        self.takes.wait(&wait);
        wait.wait(self.rooms.waits(), sleep_ms);
        let turn = self.life_turn(slot, wait).ok_or(SessionClosed)?;
        if turn.ended.is_some() {
            self.deliver();
            return Err(SessionClosed);
        }
        self.pump_turn(slot, &turn);
        self.deliver();
        if let Some(started_ms) = turn.jobs_due_ms {
            self.run_due_tickers(started_ms);
        }
        if self.closed.load(Ordering::Acquire) {
            Err(SessionClosed)
        } else {
            Ok(())
        }
    }

    /// What a read waits for, worked out under the session's lock: the link's input, or the
    /// earliest of the link's deadlines and the session's. `None` once the session closed.
    fn link_wait(&self, slot: &DirectSlot<L, C>) -> Option<IdleWait> {
        let mut held = self.live()?;
        held.0.link_due_us = slot.life_due_us.min(slot.pump_due_us);
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
        core.transport.links.waited(wait);
        // What a lost link's peer is still owed comes before anything the link brings now.
        #[cfg(feature = "liveliness")]
        if self.samples.owes() {
            core.retract_owed();
        }
        let now_us = core.now_us();
        let now_ms = core.session_time.ms_at(now_us);
        let input = slot.next_input(core, &self.direct.end);
        let chains_due = now_ms >= slot.router.due_ms();
        // The life moves on only by what the link brings or at its own time: a link that is up
        // and brings nothing is not looked at for the rest of the bookkeeping.
        let moves_link = input != LinkInput::Tick || now_us >= slot.life_due_us;
        let mut ended = None;
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
                Ok(()) => self.turn_replay(core, now_us),
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
            slot.life_due_us = slot
                .life()
                .and_then(|life| life.wake_at(now_us))
                .unwrap_or(u64::MAX);
            core.link_due_us = slot.life_due_us.min(slot.pump_due_us);
            core.settle_ledger();
        }
        // What the records of a round a delivery handed out still hold (the counts of the key
        // arena, the rejoined buffer kept for them) is let go of before the link is read, as a
        // gate of a build whose links are tasks lets it go before each receive: a key the peer
        // undeclared goes back with no record after it, and the chain a fragment read now starts
        // finds its buffer free.
        // SAFETY: the session's lock is held (`held`), and no borrow of the round's table.
        unsafe { self.samples.settle() };
        let jobs_due_ms = core.jobs_due_at(now_us);
        Some(LinkTurn {
            now_us,
            now_ms,
            jobs_due_ms,
            ended,
        })
    }

    /// Step the pump with nothing of the session held: its own bookkeeping when it is due or owes
    /// what was asked of it from outside, then one unit of its link's input, the Router lent for
    /// it. A step that took nothing serves the pump, which tells its session of a link that is
    /// gone. A pump that ended has its life looked at by the next read, at once.
    fn pump_turn(&self, slot: &mut DirectSlot<L, C>, turn: &LinkTurn) {
        let DirectSlot {
            router,
            lend,
            pump,
            records,
            life_due_us,
            pump_due_us,
            ..
        } = slot;
        let Some(records) = records.as_mut() else {
            return;
        };
        // SAFETY: the records are held exactly while the pump is written in its place.
        let pump = unsafe { pump.assume_init_mut() };
        let (now_us, now_ms) = (turn.now_us, turn.now_ms);
        let mut sink = DirectSink {
            engine: self,
            records,
        };
        let mut ended = false;
        if now_us >= *pump_due_us || pump.owes_out_of_band() {
            ended = pump.service_due(now_ms, &mut sink).is_some();
        }
        if !ended {
            let took = lend.lend_for(router, || pump.take_input_now(now_ms, &mut sink));
            #[cfg(test)]
            if took {
                self.takes.pump_reads.fetch_add(1, Ordering::Relaxed);
            }
            if !took {
                ended = pump.service_due(now_ms, &mut sink).is_some();
            }
        }
        if ended {
            self.direct.end.ended.store(true, Ordering::Release);
            *life_due_us = now_us;
        }
        *pump_due_us = pump.due_ms(now_ms).map_or(u64::MAX, |due_ms| {
            now_us.saturating_add(due_ms.saturating_sub(now_ms).saturating_mul(1000))
        });
    }

    /// Tell the link's life `input` at `now_us` and carry out its effects, in the order the life
    /// names them, until it asks for nothing more. `Err` with why the last endpoint came to no
    /// link when the life ends the session.
    fn drive_link(
        &self,
        core: &mut Core<L, C>,
        slot: &mut DirectSlot<L, C>,
        input: LinkInput,
        now_us: u64,
    ) -> Result<(), OpenError> {
        let (mut input, mut now_us) = (input, now_us);
        loop {
            let Some(life) = slot.life() else {
                return Ok(());
            };
            let effects = life.input(input, now_us);
            if effects.let_go() {
                slot.dial = None;
                slot.opened = None;
                slot.drop_pump();
                core.transport
                    .links
                    .put_link(0, Link::Waiting { at_us: u64::MAX });
            }
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
                // the endpoint the link was dialled to: the one before the next to dial.
                let row = match core.transport.links.face(0).map(|face| &face.link) {
                    Some(Link::Opening { next, .. }) => next.saturating_sub(1),
                    _ => 0,
                };
                let why = core.transport.end_handshake(0);
                slot.last = Some(OpenError::Unreachable(EndpointRefusal::new(
                    core.transport.endpoints.dial_text(row),
                    why,
                )));
                slot.drop_pump();
                // The life keeps when the link is dialled again: a time left on the face would
                // end each read's wait at once.
                core.transport
                    .links
                    .put_link(0, Link::Waiting { at_us: u64::MAX });
            }
            if effects.lose() {
                // The lost peer's chains end with its link: the next link's fragments would be
                // spliced onto them.
                let peer = core
                    .transport
                    .links
                    .face(0)
                    .and_then(|face| face.link.wire())
                    .and_then(|wire| wire.actions.peer_session_zid());
                if let Some(zid) = peer {
                    let _ended = slot.router.abort_peer(zid.as_slice());
                }
                // The face waits with no time of its own, as after a handshake that ended.
                core.lose_face_link(0, DIAL_FACE, u64::MAX);
                slot.drop_pump();
                if effects.ends_session() {
                    slot.last = Some(OpenError::Unreachable(EndpointRefusal::new(
                        "",
                        Refusal::LinkLost,
                    )));
                }
            }
            if effects.bring_up() {
                core.bring_up(0, now_us);
            }
            if effects.ends_session() {
                slot.dial = None;
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
        opened: OpenedLink<L::Pump>,
        endpoint: &DialEndpoint,
    ) -> Result<(), OpenError> {
        slot.drop_pump();
        self.direct.end.ready();
        let next = match slot.life().map(|life| life.phase()) {
            Some(LinkPhase::Dialing { row }) => row.saturating_add(1),
            _ => 0,
        };
        let params = core.link_params()?;
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
                    face: DIAL_FACE,
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
                    end: self.direct.end_handle(),
                },
            )
            .map_err(OpenError::from)?;
        let PlacedWire {
            wire,
            dispatch,
            pump: _,
        } = placed;
        slot.records = Some(dispatch);
        // A pump not stepped yet is due at once: the read that placed it sends its first frame.
        slot.pump_due_us = 0;
        let deadline_us = open_deadline_on(&core.clock, core.config.open_timeout_ms);
        core.transport.links.put_link(
            0,
            Link::Opening {
                wire,
                next,
                deadline_us,
            },
        );
        Ok(())
    }

    /// The next turn of the replay the link that is up owes its peer, when one is due. A turn the
    /// replay is given up on ends the link, as a build whose links are tasks ends it.
    fn turn_replay(&self, core: &mut Core<L, C>, now_us: u64) {
        if !ReplayPacing::REACHABLE {
            return;
        }
        let actions = match core.transport.links.face(0).map(|face| &face.link) {
            Some(Link::Up(wire)) => wire.actions.clone(),
            _ => return,
        };
        if core.replay_turn(0, &actions, now_us / 1000) == TurnEnd::EndsLink {
            core.transport.links.abort_link(0);
        }
    }

    /// Let go of the one link's session at the close, unless a read steps it now: that read lets
    /// it go once it has returned from the pump.
    pub(super) fn let_go_link(&self) {
        if let Some(mut held) = <CoopForm as LockForm>::try_lock(&self.direct.slot) {
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
        let mut held = <CoopForm as LockForm>::lock(&self.direct.slot);
        f(&mut held.0.router, now_ms)
    }
}
