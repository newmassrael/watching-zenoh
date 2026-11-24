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

use core::cell::{Cell, Ref, RefMut};

use crate::bounded::Storage;
#[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
use crate::face::{FaceEventKind, FaceSnapshot};
#[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
use crate::face_plane::FaceReports;
use crate::key_arena::KeySpace;
use crate::session_tables::{KeyForm, RowCallbacks, SessionTables};
use crate::wire_id::{EntityId, ExprId, RequestId};

/// The parts of a session's state an engine keeps in types of its own: each is `()` where the
/// engine's build leaves the part out. The registry is the one part the state reads itself: it
/// keeps the session's tables ([`Self::tables`]), which the session's own declarations are
/// numbered and named by.
pub trait SessionParts {
    /// What the application holds and what the peers declared. It is the session's, so it outlives
    /// each link: a new link is dispatched to the same registry.
    type Registry;
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
    fn tables(registry: &Self::Registry) -> Ref<'_, SessionTables<Self::Callbacks, Self::Storage>>;

    /// [`Self::tables`], to write.
    fn tables_mut(
        registry: &Self::Registry,
    ) -> RefMut<'_, SessionTables<Self::Callbacks, Self::Storage>>;
}

impl<P: SessionParts> SessionState<P> {
    /// The session's tables, to read.
    pub fn tables(&self) -> Ref<'_, SessionTables<P::Callbacks, P::Storage>> {
        P::tables(&self.registry)
    }

    /// The session's tables, to write.
    pub fn tables_mut(&self) -> RefMut<'_, SessionTables<P::Callbacks, P::Storage>> {
        P::tables_mut(&self.registry)
    }

    /// The session's next entity id, taken: what a declaration and an Interest of the session are
    /// numbered by, from 1; `None` once every one has been handed out, which refuses the
    /// declaration rather than wrap onto a live id.
    // Out of line: every declaration that numbers an entity of its own takes the id through it.
    #[inline(never)]
    pub fn take_entity_id(&self) -> Option<EntityId> {
        self.tables_mut().take_entity_id()
    }

    /// The form an entity's key whose wire names the declaration `mapping_id` (`0` for none) takes
    /// in the session's tables ([`SessionTables::key_form`]).
    // Out of line: each declaration of an entity on a key asks it, each a copy inlined.
    #[inline(never)]
    pub fn key_form(&self, mapping_id: ExprId, names_key: bool) -> KeyForm {
        self.tables().key_form(mapping_id, names_key)
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
    /// The face `snapshot` makes, when something watches the faces (an event is the snapshot it
    /// carries); none, and no snapshot made, otherwise. Watchers that can never watch make none in
    /// any case, so their build has no snapshot to link.
    pub fn face_of(&self, snapshot: impl FnOnce() -> Option<FaceSnapshot>) -> Option<FaceSnapshot> {
        if !<P::Watchers as FaceReports>::WATCHES || !self.watchers.watched() {
            return None;
        }
        snapshot()
    }

    /// Tell the watchers of the faces that `face` came up or went, with the session's other
    /// deliveries ([`Self::face_of`] says whether there is anything to tell).
    // Out of line: the face lost and the face up each tell, with the snapshot dropped once.
    #[inline(never)]
    pub fn report_face(&self, kind: FaceEventKind, face: Option<FaceSnapshot>) {
        if let Some(face) = face {
            self.watchers.happened(kind, face);
        }
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
    use crate::session_tables::Absent;
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

    /// The parts of an engine whose registry is its tables alone, which reports its faces to
    /// `$watchers` and keeps no other part.
    macro_rules! tables_only {
        ($name:ident, $watchers:ty) => {
            enum $name {}

            impl SessionParts for $name {
                type Registry = RefCell<Tables>;
                type Callbacks = NoCallbacks;
                type Storage = Profile;
                type Watchers = $watchers;
                type Entities = ();
                type Queryables = ();
                type PendingGets = ();
                type Gets = ();
                type Lane = ();
                type KeyIds = ();
                type LocalRequests = LocalRequests;

                fn tables(registry: &Self::Registry) -> Ref<'_, Tables> {
                    registry.borrow()
                }

                fn tables_mut(registry: &Self::Registry) -> RefMut<'_, Tables> {
                    registry.borrow_mut()
                }
            }
        };
    }

    tables_only!(Unwatched, ());
    #[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
    tables_only!(Watched, crate::face_plane::FacePlane<CellLocks>);

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

    fn state<P>() -> SessionState<P>
    where
        P: SessionParts<
            Registry = RefCell<Tables>,
            Entities = (),
            Queryables = (),
            PendingGets = (),
            Gets = (),
            Lane = (),
            KeyIds = (),
            LocalRequests = LocalRequests,
        >,
        P::Watchers: Default,
    {
        SessionState {
            registry: RefCell::new(Tables::new()),
            watchers: Default::default(),
            entities: (),
            keys: keys(64),
            key_ids: (),
            local_requests: LocalRequests::default(),
            matching: MatchingRead::default(),
            plane: (),
            pending_gets: (),
            gets: (),
            lane: (),
        }
    }

    /// The state numbers the session's entities by the ids its tables hand out, each once.
    #[test]
    fn the_state_takes_each_entity_id_from_its_tables_once() {
        let state = state::<Unwatched>();
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
        let state = state::<Unwatched>();
        let declared = state.tables_mut().declare_keyexpr("demo/").unwrap();
        assert_eq!(
            state.key_form(declared.id, true),
            KeyForm {
                prefix: Some(declared.handle),
                names_key: true
            }
        );
        assert_eq!(state.key_form(0, false), KeyForm::default());
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

        fn new<T>(value: T) -> RefCell<T> {
            RefCell::new(value)
        }

        fn with<T, R>(lock: &RefCell<T>, f: impl FnOnce(&mut T) -> R) -> R {
            f(&mut lock.borrow_mut())
        }
    }

    #[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
    fn face() -> FaceSnapshot {
        FaceSnapshot {
            zid: [7; 16],
            whatami: 0,
            is_qos: false,
            is_multicast: false,
            is_shm: false,
            links: std::vec::Vec::new(),
        }
    }

    /// A state whose build watches no face makes no snapshot and reports nothing.
    #[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
    #[test]
    fn a_state_that_watches_no_face_makes_no_snapshot() {
        let state = state::<Unwatched>();
        let mut made = false;
        assert!(state
            .face_of(|| {
                made = true;
                Some(face())
            })
            .is_none());
        assert!(!made, "no snapshot is made for nobody");
        state.report_face(FaceEventKind::Up, Some(face()));
    }

    /// A state with a plane makes a snapshot only while something watches, and reports it there.
    #[cfg(all(feature = "alloc", target_has_atomic = "ptr"))]
    #[test]
    fn a_state_reports_a_face_to_its_plane_while_it_is_watched() {
        let state = state::<Watched>();
        assert!(
            state.face_of(|| Some(face())).is_none(),
            "nothing watches yet"
        );
        state.watchers.watch(alloc::sync::Arc::new(|_, _| {}));
        let snapshot = state.face_of(|| Some(face()));
        assert!(snapshot.is_some());
        state.report_face(FaceEventKind::Down, snapshot);
        state.report_face(FaceEventKind::Up, None);
        let (kind, told) = state.watchers.next_event().unwrap();
        assert_eq!((kind, told.zid), (FaceEventKind::Down, [7; 16]));
        assert!(state.watchers.next_event().is_none(), "no face, no event");
    }
}
