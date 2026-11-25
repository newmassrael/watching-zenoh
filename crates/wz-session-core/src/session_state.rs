// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The session's state as its layer (L3) holds it, apart from what the links carry and from the
//! engine that drives both: what the session declared and asked, over every link, and the round its
//! deliveries go through.
//!
//! The state is a value with no I/O of its own. An engine names the parts it keeps of an engine of
//! its own kind through [`SessionParts`]: the registry of its tables, the plane its queryables
//! answer through, its pending gets and the like, each the engine's own type, and `()` for a part
//! its build leaves out, so a build without a plane keeps no field of it and no `cfg` of a
//! feature reaches the struct: this crate's features are unified across the workspace and the
//! engine's are not, so a field that followed either could be there for one and not the other.
//! What every engine keeps alike (the key arena, the count of the session's own requests, where the
//! matching listeners were last read) is this crate's.
//!
//! [`SessionParts`]: crate::session_state::SessionParts

use core::cell::Cell;
#[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
use core::ops::Deref;

use crate::bounded::Storage;
#[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
use crate::face::{FaceEventKind, FaceLinkRow};
#[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
use crate::face_plane::FaceReports;
use crate::key_arena::KeySpace;
use crate::pending_get::{PendingGet, PendingLegs, SessionFaces};
use crate::replay_pacing::ReplayPacing;
#[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
use crate::round::{Owing, ReadRoom, Round, RoundCalls};
use crate::session_tables::{KeyForm, KeyexprRef, Retraction, RowCallbacks, SessionTables};
use crate::wire_id::{EntityId, RequestId};

/// The parts of a session's state an engine keeps in types of its own: each is `()` where the
/// engine's build leaves the part out. The registry is the one part the state reads itself: it
/// keeps the session's tables ([`Self::tables`]), which the session's own declarations are
/// numbered and named by, and its faces ([`Self::faces`]), which its pending gets are asked of.
pub trait SessionParts {
    /// What the application holds and what the peers declared. It is the session's, so it outlives
    /// each link: a new link is dispatched to the same registry.
    type Registry;
    /// The faces the registry keeps: what each face's peer declared and the gets pending on it.
    type Faces: SessionFaces;
    /// The callbacks the rows of the session's tables hold.
    type Callbacks: RowCallbacks;
    /// Where the session's tables keep their rows.
    type Storage: Storage;
    /// Where a face coming up or going is reported.
    type Watchers;
    /// How many rows each table of the session's own declarations was lent: what a write filter of
    /// each plane is held to.
    type Entities;
    /// The plane the session's queryables answer through.
    type Queryables;
    /// The legs of the session's gets still pending on its links.
    type PendingGets;
    /// The plane the session's gets are handed their replies through.
    type Gets;
    /// The session's round of deliveries, which every link's gate asks before it reads a record.
    type Lane;
    /// The key ids every node of the deployment shares, which the session was opened with
    /// (`shared_key_ids`, an `Option` of them where the engine keeps them).
    type KeyIds;
    /// The ids of the session's gets of its own queryables ([`LocalRequests`]).
    type LocalRequests;

    /// The session's tables, where `registry` keeps them, to read.
    fn tables(registry: &Self::Registry) -> &SessionTables<Self::Callbacks, Self::Storage>;

    /// [`Self::tables`], to write.
    fn tables_mut(
        registry: &mut Self::Registry,
    ) -> &mut SessionTables<Self::Callbacks, Self::Storage>;

    /// The faces, where `registry` keeps them, to read.
    fn faces(registry: &Self::Registry) -> &Self::Faces;

    /// [`Self::faces`], to write.
    fn faces_mut(registry: &mut Self::Registry) -> &mut Self::Faces;
}

impl<P: SessionParts> SessionState<P> {
    /// The session's tables, to read.
    pub fn tables(&self) -> &SessionTables<P::Callbacks, P::Storage> {
        P::tables(&self.registry)
    }

    /// The session's tables, to write.
    pub fn tables_mut(&mut self) -> &mut SessionTables<P::Callbacks, P::Storage> {
        P::tables_mut(&mut self.registry)
    }

    /// The session's next entity id, taken: what a declaration and an Interest of the session are
    /// numbered by, from 1; `None` once every one has been handed out, which refuses the
    /// declaration rather than wrap onto a live id.
    // Out of line: every declaration that numbers an entity of its own takes the id through it.
    #[inline(never)]
    pub fn take_entity_id(&mut self) -> Option<EntityId> {
        self.tables_mut().take_entity_id()
    }

    /// The form an entity's key whose wire names the declaration `declared` (id `0` for none)
    /// takes in the session's tables, read at the row its holder names, retracted naming what
    /// `retraction` says ([`SessionTables::key_form_at`]).
    // Out of line: each declaration of an entity on a key asks it, each a copy inlined.
    #[inline(never)]
    pub fn key_form(&self, declared: KeyexprRef, retraction: Retraction) -> KeyForm {
        self.tables().key_form_at(declared, retraction)
    }
}

/// The session's part of an engine's state: the tables of what it declared and asked, over every
/// link. Its fields are dropped in the order they are declared, the registry first.
pub struct SessionState<P: SessionParts> {
    /// What the application holds and what the peers declared.
    pub registry: P::Registry,
    /// Where a face coming up or going is reported.
    pub watchers: P::Watchers,
    /// How many rows each table of the session's own declarations was lent.
    pub entities: P::Entities,
    /// The key arena the rows of those tables keep their keys in, lent with them.
    pub keys: KeySpace,
    /// The key ids every node of the deployment shares, which the session was opened with: each
    /// link it opens is handed them, its key expressions are declared under ids past theirs, and a
    /// key goes on the wire as the session's key-wire form says.
    pub key_ids: P::KeyIds,
    /// The ids of the session's gets of its own queryables.
    pub local_requests: P::LocalRequests,
    /// Where the matching listeners were last read.
    pub matching: MatchingRead,
    /// How a link that comes up is told the declarations the session holds: a burst at a time at
    /// this pace, or all in one turn (`None`). One for the session, which every face's replay
    /// reads, as the policies the session opened under state it or a caller set it since.
    pub replay_pacing: Option<ReplayPacing>,
    /// The plane the session's queryables answer through.
    pub plane: P::Queryables,
    /// The legs of the session's gets still pending on its links.
    pub pending_gets: P::PendingGets,
    /// The plane the session's gets are handed their replies through.
    pub gets: P::Gets,
    /// The session's round of deliveries.
    pub lane: P::Lane,
}

#[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
impl<P: SessionParts> SessionState<P>
where
    P::Watchers: FaceReports,
{
    /// Whether a face that comes up or goes is worth its rows: something watches the faces.
    /// Watchers that can never watch answer `false` as a constant, so their build reads no row.
    pub fn faces_watched(&self) -> bool {
        <P::Watchers as FaceReports>::WATCHES && self.watchers.watched()
    }

    /// Tell the watchers of the faces a row of a face that came up or went, with the session's
    /// other deliveries ([`Self::faces_watched`] says whether there is anyone to tell).
    // Out of line: the face lost and the face up each tell, a row at a time.
    #[inline(never)]
    pub fn report_face_row(&self, kind: FaceEventKind, row: FaceLinkRow) {
        self.watchers.happened(kind, row);
    }
}

impl<P: SessionParts> SessionState<P>
where
    P::PendingGets: PendingLegs,
{
    /// Hold the pending leg `leg` in a row of the session's: `false` past the rows, which a leg
    /// registered in a face's table of pending gets never reaches, as the rows are one for each
    /// entry of those tables; its entry is dropped then, which says its end, and the leg is over.
    pub fn note_pending(&mut self, leg: PendingGet<<P::PendingGets as PendingLegs>::Fan>) -> bool {
        match self.pending_gets.note(leg) {
            Ok(()) => true,
            Err(leg) => {
                leg.unregister(P::faces_mut(&mut self.registry));
                false
            }
        }
    }

    /// What the lost link of face `face` takes with it: every subscriber, queryable and token its
    /// peer declared, so a matching status or a write filter that counted on one reads the session
    /// as it now is, and every get asked of it, whose Final its peer can no longer send: each
    /// pending leg's entry is dropped, which ends the leg.
    pub fn lose_face(&mut self, face: u64) {
        let faces = P::faces_mut(&mut self.registry);
        faces.lose_face(face);
        self.pending_gets
            .drop_face(face, |leg| leg.unregister(&mut *faces));
    }

    /// When the earliest pending get is due: a query's or a liveliness snapshot's, on any face.
    /// To write, as the faces bring their bound of it up to date as they read it.
    pub fn next_get_deadline_ms(&mut self) -> Option<u64> {
        P::faces_mut(&mut self.registry).next_get_deadline_ms()
    }
}

#[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
impl<P, C> SessionState<P>
where
    P: SessionParts,
    P::Lane: Deref<Target = Round<C>>,
    C: RoundCalls,
{
    /// Retract the tokens the peers of lost links declared, as many as the round of deliveries
    /// takes now, each a record that takes `room` of it, and tell the round whether any is still
    /// owed: while one is, no link is read, so a token's `Delete` comes before anything a link
    /// brings after its loss, and none is dropped.
    ///
    /// # Safety
    /// The caller holds the session's lock, as the round's writer does ([`Round::has_room`]).
    pub unsafe fn retract_owed(&mut self, room: ReadRoom) {
        let round = &self.lane;
        // SAFETY: the caller's contract.
        let mut has_room = || unsafe { round.has_room(room) };
        let done = P::faces_mut(&mut self.registry).retract_owed(&mut has_room);
        round.owe(Owing::Retractions, !done);
    }
}

/// The request ids of a session's gets of its own queryables, counted apart from the ids its links
/// hand out: from 0, wrapping, as a link's own count does.
#[derive(Debug, Default)]
pub struct LocalRequests {
    next: RequestId,
}

impl LocalRequests {
    /// The next id, taken.
    pub fn take(&mut self) -> RequestId {
        let id = self.next;
        self.next = id.wrapping_add(1);
        id
    }
}

/// The count of the faces' writes the session's matching listeners were last read at: a verdict
/// read then holds until the count moves, and a step that finds it moved reads them again.
#[derive(Debug, Default)]
pub struct MatchingRead {
    at: Cell<u64>,
}

impl MatchingRead {
    /// Whether the faces were written since the listeners were last read, `written` being the
    /// count of their writes now.
    pub fn moved(&self, written: u64) -> bool {
        self.at.get() != written
    }

    /// The listeners were read at `written` writes of the faces.
    pub fn read_at(&self, written: u64) {
        self.at.set(written);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounded::{Arena, Profile, ARENA_ALIGN};
    use crate::limits::SessionLimits;
    use crate::pending_get::GetKind;
    use crate::session_tables::Absent;
    #[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
    use core::cell::RefCell;
    use core::ptr::NonNull;

    /// Rows that hold no callback, of no optional kind.
    enum NoCallbacks {}

    impl RowCallbacks for NoCallbacks {
        type Subscriber = ();
        type Queryable = ();
        type LivelinessSubscriber = ();
        type Matching = ();
        type Reply = ();
        type QueryablePresence = Absent;
        type LivelinessPresence = Absent;
        type FilterPresence = Absent;
        type GetPresence = Absent;
    }

    type Tables = SessionTables<NoCallbacks, Profile>;

    /// A registry of the session's tables, which records what its faces are told.
    #[derive(Default)]
    struct Registry {
        tables: Tables,
        ended: std::vec::Vec<(u64, GetKind)>,
        lost: std::vec::Vec<u64>,
        /// The tokens of lost links still to be retracted.
        owed_tokens: usize,
        /// The round each token retracted is offered to, as a record of its `Delete`.
        #[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
        retracts_into: Option<(TestLane, alloc::sync::Arc<crate::round::tests::Log>)>,
    }

    /// The round of a test's session: a handle of a real one, of the calls the round's own tests
    /// make, which the test owns.
    #[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
    type TestLane = crate::placed::PlacedRef<Round<crate::round::tests::Kept>>;

    impl SessionFaces for Registry {
        fn end_leg(&mut self, face: u64, kind: GetKind) {
            self.ended.push((face, kind));
        }

        fn lose_face(&mut self, face: u64) {
            self.lost.push(face);
        }

        fn next_get_deadline_ms(&mut self) -> Option<u64> {
            Some(40)
        }

        fn retract_owed(&mut self, room: &mut dyn FnMut() -> bool) -> bool {
            while self.owed_tokens > 0 {
                if !room() {
                    return false;
                }
                #[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
                if let Some((round, log)) = &self.retracts_into {
                    let call = crate::round::tests::Call {
                        row: 1,
                        log: log.clone(),
                    };
                    let token = crate::declare::liveliness_sample::LivelinessSample {
                        kind: crate::declare::liveliness_sample::LivelinessSampleKind::Delete,
                        keyexpr: "t/1",
                        token_id: 7,
                    };
                    // SAFETY: the test's thread is the round's one writer, as the session's lock
                    // holder is, and it asked the round for the room first.
                    unsafe { round.offer_liveliness(call, &token, None) };
                }
                self.owed_tokens -= 1;
            }
            true
        }
    }

    /// The parts of an engine whose registry is [`Registry`], which reports its faces to
    /// `$watchers`, holds its pending legs in `$legs`, delivers through `$lane` and keeps no
    /// other part.
    macro_rules! tables_only {
        ($name:ident, $watchers:ty, $legs:ty, $lane:ty) => {
            enum $name {}

            impl SessionParts for $name {
                type Registry = Registry;
                type Faces = Registry;
                type Callbacks = NoCallbacks;
                type Storage = Profile;
                type Watchers = $watchers;
                type Entities = ();
                type Queryables = ();
                type PendingGets = $legs;
                type Gets = ();
                type Lane = $lane;
                type KeyIds = ();
                type LocalRequests = LocalRequests;

                fn tables(registry: &Self::Registry) -> &Tables {
                    &registry.tables
                }

                fn tables_mut(registry: &mut Self::Registry) -> &mut Tables {
                    &mut registry.tables
                }

                fn faces(registry: &Self::Registry) -> &Registry {
                    registry
                }

                fn faces_mut(registry: &mut Self::Registry) -> &mut Registry {
                    registry
                }
            }
        };
    }

    /// Rows of two pending legs.
    type TwoLegs = crate::bounded::BoundedVec<PendingGet<u8>, 2, crate::bounded::Static>;

    tables_only!(Unwatched, (), (), ());
    tables_only!(Legs, (), TwoLegs, ());
    #[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
    tables_only!(Rounds, (), (), TestLane);
    #[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
    tables_only!(Watched, WatchedPlane, (), ());

    /// A plane of the faces, made in a box of its own, as the state's field of a test.
    #[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
    struct WatchedPlane(alloc::boxed::Box<crate::face_plane::FacePlane<CellLocks>>);

    #[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
    impl Default for WatchedPlane {
        fn default() -> Self {
            // SAFETY: the box's place is valid for writes of the plane, which stays there.
            Self(crate::plane_lock::boxed_at(|at| unsafe {
                crate::face_plane::FacePlane::init_at(at, crate::caps::MAX_FACE_WATCH_ROWS)
            }))
        }
    }

    #[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
    impl core::ops::Deref for WatchedPlane {
        type Target = crate::face_plane::FacePlane<CellLocks>;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    #[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
    impl crate::face_plane::FaceReports for WatchedPlane {
        const WATCHES: bool = true;

        fn watched(&self) -> bool {
            self.0.watched()
        }

        fn happened(&self, kind: FaceEventKind, row: FaceLinkRow) {
            crate::face_plane::FaceReports::happened(&*self.0, kind, row);
        }
    }

    /// One block of an arena's memory, aligned as an arena's spans start.
    #[derive(Clone, Copy)]
    #[repr(C, align(16))]
    struct Block {
        _bytes: [u8; ARENA_ALIGN],
    }

    /// A key arena of `bytes` bytes of blocks, lent from an arena over memory the test process
    /// leaks, so it outlives every key.
    fn keys(bytes: usize) -> KeySpace {
        let span = KeySpace::span_bytes(bytes).unwrap();
        let blocks = span.div_ceil(ARENA_ALIGN).max(1);
        let region: &'static mut [Block] =
            std::vec![Block { _bytes: [0; ARENA_ALIGN] }; blocks].leak();
        // SAFETY: the region is aligned to `ARENA_ALIGN`, as its blocks are, holds at least `span`
        // bytes, and is leaked, so nothing else uses it and it outlives every key.
        let mut arena = unsafe { Arena::over(NonNull::from(region).cast::<u8>(), span) };
        arena
            .lend_keys(bytes, SessionLimits::defaults().max_keyexpr_bytes_held())
            .unwrap()
    }

    fn new_state<P>() -> SessionState<P>
    where
        P: SessionParts<
            Registry = Registry,
            Entities = (),
            Queryables = (),
            Gets = (),
            KeyIds = (),
            LocalRequests = LocalRequests,
        >,
        P::Watchers: Default,
        P::PendingGets: Default,
        P::Lane: Default,
    {
        new_state_with(Default::default())
    }

    /// A state that delivers through `lane`.
    fn new_state_with<P>(lane: P::Lane) -> SessionState<P>
    where
        P: SessionParts<
            Registry = Registry,
            Entities = (),
            Queryables = (),
            Gets = (),
            KeyIds = (),
            LocalRequests = LocalRequests,
        >,
        P::Watchers: Default,
        P::PendingGets: Default,
    {
        SessionState {
            registry: Registry::default(),
            watchers: Default::default(),
            entities: (),
            keys: keys(64),
            key_ids: (),
            local_requests: LocalRequests::default(),
            matching: MatchingRead::default(),
            replay_pacing: None,
            plane: (),
            pending_gets: Default::default(),
            gets: (),
            lane,
        }
    }

    fn leg(face: u64, id: u64) -> PendingGet<u8> {
        PendingGet {
            face,
            leg: id,
            kind: GetKind::Query(id as RequestId),
            fan: None,
        }
    }

    /// A leg past the rows is refused and its entry ended in the tables of the face it was asked
    /// of; a session that holds no rows refuses every leg so.
    #[test]
    fn a_leg_past_the_rows_is_ended_where_it_was_registered() {
        let mut state = new_state::<Legs>();
        assert!(state.note_pending(leg(1, 1)));
        assert!(state.note_pending(leg(2, 2)));
        assert!(!state.note_pending(leg(3, 3)));
        assert_eq!(faces_told(&state).ended, [(3, GetKind::Query(3))]);
        let mut none = new_state::<Unwatched>();
        let refused = PendingGet {
            face: 5,
            leg: 5,
            kind: GetKind::Query(5),
            fan: None::<core::convert::Infallible>,
        };
        assert!(!none.note_pending(refused));
        assert_eq!(faces_told(&none).ended, [(5, GetKind::Query(5))]);
    }

    /// A lost face takes what its peer declared first, then ends each leg asked of it, once, and
    /// keeps the legs of the other faces.
    #[test]
    fn a_lost_face_ends_the_legs_asked_of_it_and_keeps_the_rest() {
        let mut state = new_state::<Legs>();
        assert!(state.note_pending(leg(1, 1)));
        assert!(state.note_pending(leg(2, 2)));
        state.lose_face(1);
        assert_eq!(faces_told(&state).lost, [1]);
        assert_eq!(faces_told(&state).ended, [(1, GetKind::Query(1))]);
        let kept: std::vec::Vec<u64> = state.pending_gets.iter().map(|leg| leg.leg).collect();
        assert_eq!(kept, [2]);
        assert_eq!(state.next_get_deadline_ms(), Some(40), "read off the faces");
    }

    /// What the faces of `state` were told, read back.
    fn faces_told<P: SessionParts<Registry = Registry>>(state: &SessionState<P>) -> &Registry {
        &state.registry
    }

    /// The state retracts the owed tokens the round of deliveries has room for, each a record of
    /// it, and tells it one is still owed; a sealed round takes none; once the round was handed
    /// out and takes the rest, none is owed.
    #[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
    #[test]
    fn the_state_retracts_what_the_round_takes_and_says_what_is_owed() {
        const OWED: usize = 64;
        let round = crate::round::tests::round();
        // SAFETY: the state and the registry use the handles only while `round`, declared first,
        // lives, and nothing changes the round through its owner meanwhile.
        let lane: TestLane = unsafe { round.share() };
        let log = alloc::sync::Arc::new(crate::round::tests::Log::default());
        let mut state = new_state_with::<Rounds>(lane);
        state.registry.owed_tokens = OWED;
        state.registry.retracts_into = Some((lane, log.clone()));
        let one = ReadRoom { callbacks: 1 };
        // SAFETY: the test's thread is the round's one writer, as the session's lock holder is.
        unsafe { state.retract_owed(one) };
        let left = faces_told(&state).owed_tokens;
        assert!(left > 0 && left < OWED, "the round took some and not all");
        assert!(state.lane.owes(), "one still owed: no link is read");
        // SAFETY: as above.
        unsafe { state.lane.seal() };
        // SAFETY: as above.
        unsafe { state.retract_owed(one) };
        assert_eq!(
            faces_told(&state).owed_tokens,
            left,
            "a sealed round takes none"
        );
        assert!(state.lane.owes());
        assert!(state.lane.deliver());
        assert_eq!(
            log.handed().len(),
            OWED - left,
            "each token retracted is a record handed out"
        );
        state.registry.owed_tokens = 1;
        // SAFETY: as above.
        unsafe { state.retract_owed(one) };
        assert_eq!(faces_told(&state).owed_tokens, 0);
        assert!(!state.lane.owes(), "none owed");
    }

    /// The state numbers the session's entities by the ids its tables hand out, each once.
    #[test]
    fn the_state_takes_each_entity_id_from_its_tables_once() {
        let mut state = new_state::<Unwatched>();
        assert_eq!(state.take_entity_id(), Some(1));
        assert_eq!(state.take_entity_id(), Some(2));
        assert_eq!(
            state.tables().next_entity_id(),
            Some(3),
            "the tables moved past the ids the state took"
        );
    }

    /// The state names an entity's key by the declaration of its tables the wire names, and by
    /// none for a wire that names none.
    #[test]
    fn the_state_names_a_key_by_the_declaration_its_tables_hold() {
        let mut state = new_state::<Unwatched>();
        let declared = state.tables_mut().declare_keyexpr("demo/").unwrap();
        assert_eq!(
            state.key_form(KeyexprRef::by_id(declared.id), Retraction::AsAnnounced),
            KeyForm {
                prefix: Some(declared.handle),
                own: None,
                retraction: Retraction::AsAnnounced
            }
        );
        assert_eq!(
            state.key_form(KeyexprRef::by_id(0), Retraction::ById),
            KeyForm::default()
        );
    }

    /// A session's own request ids count from 0 and wrap past the last.
    #[test]
    fn local_request_ids_count_from_zero_and_wrap() {
        let mut ids = LocalRequests::default();
        assert_eq!((ids.take(), ids.take()), (0, 1));
        let mut last = LocalRequests {
            next: RequestId::MAX,
        };
        assert_eq!((last.take(), last.take()), (RequestId::MAX, 0));
    }

    /// The listeners read at no write yet are current until the faces are written, and current
    /// again once read at the new count.
    #[test]
    fn the_matching_listeners_are_read_again_once_the_faces_moved() {
        let read = MatchingRead::default();
        assert!(!read.moved(0), "nothing was written since the open");
        assert!(read.moved(1));
        read.read_at(1);
        assert!(!read.moved(1));
        assert!(read.moved(2));
    }

    /// Locks of one thread, which is all a test needs.
    #[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
    enum CellLocks {}

    #[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
    impl crate::plane_lock::LockFamily for CellLocks {
        type Lock<T> = RefCell<T>;

        unsafe fn init_at<T>(
            place: core::ptr::NonNull<RefCell<T>>,
            make: impl FnOnce(&mut core::mem::MaybeUninit<T>) -> &mut T,
        ) {
            // SAFETY: `place` is valid for writes of the lock (the caller's contract).
            unsafe {
                place
                    .as_ptr()
                    .write(RefCell::new(crate::plane_lock::made_value(make)))
            }
        }

        fn with<T, R>(lock: &RefCell<T>, f: impl FnOnce(&mut T) -> R) -> R {
            f(&mut lock.borrow_mut())
        }
    }

    #[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
    fn row() -> FaceLinkRow {
        FaceLinkRow {
            zid: [7; 16],
            whatami: 0,
            is_qos: false,
            is_multicast: false,
            is_shm: false,
            link: 0,
            links: 1,
            src: crate::face::RowText::of("tcp/127.0.0.1:1"),
            dst: crate::face::RowText::of("tcp/127.0.0.1:2"),
            kind: None,
            mtu: 0,
            group_endpoint: None,
            lost_after: 0,
        }
    }

    /// A state whose build watches no face is never watched, and a row reported to it is kept
    /// nowhere.
    #[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
    #[test]
    fn a_state_that_watches_no_face_is_never_watched() {
        let state = new_state::<Unwatched>();
        assert!(!state.faces_watched(), "no row is read for nobody");
        state.report_face_row(FaceEventKind::Up, row());
    }

    /// A state with a plane is watched only while something watches, and a row reported to it is
    /// queued there. Turned red by a state that reads itself watched with no watcher, which would
    /// read every face's rows for nobody.
    #[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
    #[test]
    fn a_state_reports_a_face_row_to_its_plane_while_it_is_watched() {
        let state = new_state::<Watched>();
        assert!(!state.faces_watched(), "nothing watches yet");
        let watched =
            state
                .watchers
                .watch(crate::face::FaceRowSink::of_arc(alloc::sync::Arc::new(
                    |_: FaceEventKind, _: &crate::face::FaceLinkRow| {},
                )));
        assert!(watched.is_ok(), "a plane with room takes the watch");
        assert!(state.faces_watched());
        state.report_face_row(FaceEventKind::Down, row());
        let (kind, told) = state.watchers.next_event().unwrap();
        assert_eq!((kind, told.zid), (FaceEventKind::Down, [7; 16]));
        assert!(state.watchers.next_event().is_none(), "one row, one event");
    }
}
