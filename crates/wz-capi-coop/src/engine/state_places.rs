// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The values a session whose shape the build fixes owns in its state and its tasks reach by
//! handles that count nothing, laid out as fields of the session's region
//! (`crate::region::StateRegion`) instead of placed in its arena: the round of deliveries and the
//! rows of its tables, the planes of its gets, its queryables and the watchers of its faces, and
//! the cells its registry and its Router are lent in for a step. Each lies in a `MaybeUninit` field, which the region's drop does not drop: the
//! [`Placed`] owner written there does, wherever the session holds it, so each value is let go in
//! the order the session lets its owner go, as one the arena held was.
//!
//! Where the tables take their memory at their first row (`tables-on-use`), the same places lie
//! in a state of the session's own (`OwnState`), beside the budget its keys are counted against:
//! one allocation the open takes from the allocator apart from its arena, held by `OwnBlock`,
//! which gives it back after every owner written in it.

#[cfg(all(feature = "tables-on-use", not(feature = "runtime-plan")))]
use core::alloc::Layout;
use core::mem::MaybeUninit;
use core::ptr::{addr_of_mut, NonNull};

use wz_session_core::bounded::{BoundedVec, ZeroEmpty};
#[cfg(any(feature = "query", feature = "queryable"))]
use wz_session_core::caps;
use wz_session_core::placed::Placed;
#[cfg(feature = "query")]
use wz_session_core::reply_hold::{HeldReplies, HeldReplyPlaces};
#[cfg(wz_round)]
use wz_session_core::round::RoundRowPlaces;
use wz_session_core::step_lend::LendCell;

use super::registry::FACE_SETS;
#[cfg(feature = "connectivity")]
use super::FacePlane;
#[cfg(feature = "query")]
use super::GetPlane;
#[cfg(feature = "queryable")]
use super::QueryPlane;
#[cfg(wz_round)]
use super::Registry;
#[cfg(feature = "queryable")]
use super::{query, FinalHold, RefusedFinal};
#[cfg(feature = "query")]
use super::{Ended, LegRow, PendingGet, Rows};
#[cfg(feature = "query")]
use super::{EndedLegs, LegRows};
use super::{RoomPlace, RoomPlaces, SessionReassembly, StepPlaces};
#[cfg(any(feature = "query", feature = "queryable"))]
use crate::arena::SessionRows;
#[cfg(wz_round)]
use crate::calls::CoopCalls;
#[cfg(wz_round)]
use crate::round::{Round, RoundRowCounts, RoundRows};
#[cfg(feature = "query")]
use wz_session_core::bounded::Lent;
#[cfg(all(feature = "tables-on-use", not(feature = "runtime-plan")))]
use wz_session_core::limits::SessionLimits;
#[cfg(all(feature = "tables-on-use", not(feature = "runtime-plan")))]
use wz_session_core::on_use::{BudgetKeys, KeyBudget};

#[cfg(all(feature = "tables-on-use", not(feature = "runtime-plan")))]
use crate::arena::ArenaRefused;

/// The legs a region keeps a row of each table of for: one for each get its tables of pending gets
/// hold, the dial role's face's and, with `local-queryable`, the session's own
/// (`RegistryRegion`).
#[cfg(feature = "query")]
const LEG_ROWS: usize = (caps::MAX_PENDING_QUERIES
    + if cfg!(feature = "liveliness-get") {
        caps::MAX_PENDING_LIVELINESS_GETS
    } else {
        0
    })
    * (1 + cfg!(feature = "local-queryable") as usize);

/// The plain tables of the session's state over the rows of its region
/// ([`StatePlaces::tables`]): what an arena lends a session whose shape the open plans.
#[cfg(any(feature = "query", feature = "queryable"))]
pub(super) struct PlacedTables {
    #[cfg(feature = "query")]
    pub(super) legs: Rows<Ended, { usize::MAX }>,
    #[cfg(feature = "query")]
    pub(super) leg_rows: Rows<Option<LegRow>, { usize::MAX }>,
    #[cfg(feature = "query")]
    pub(super) pending_gets: Rows<PendingGet, { usize::MAX }>,
    #[cfg(feature = "query")]
    pub(super) held_replies: HeldReplies<u64, wz_session_core::bounded::Lent>,
    #[cfg(feature = "queryable")]
    pub(super) held_finals: query::HeldFinals,
    #[cfg(feature = "queryable")]
    pub(super) refused_finals: query::RefusedFinals,
}

/// The places of a session's region its state's own values are written in: see the module
/// documentation.
pub(crate) struct StatePlaces {
    /// Where the registry is lent to the dispatch of a link that runs as a task.
    #[cfg(wz_round)]
    registry_lend: MaybeUninit<LendCell<Registry>>,
    /// Where the reassembly Router is lent to the links' receives.
    router_lend: MaybeUninit<LendCell<SessionReassembly>>,
    /// The session's round of deliveries, none in a build that puts nothing in it (`wz_round`).
    #[cfg(wz_round)]
    round: MaybeUninit<Round>,
    /// The rows of the round's tables, which the round reads where they lie: the build's bound of
    /// each, as the round's form keeps them.
    #[cfg(wz_round)]
    round_rows: RoundRowPlaces<CoopCalls>,
    #[cfg(feature = "query")]
    gets: MaybeUninit<GetPlane>,
    #[cfg(feature = "queryable")]
    queries: MaybeUninit<QueryPlane>,
    #[cfg(feature = "connectivity")]
    faces: MaybeUninit<FacePlane>,
    /// What the face holding each set names for a wait for its room, a place for each set the
    /// region holds.
    room_places: [MaybeUninit<Option<RoomPlace>>; FACE_SETS],
    /// The rows of the session's plain tables, each table's at the build's bound: the ends of the
    /// legs, their callbacks, the session's note of each leg pending and the replies the gets that
    /// consolidate hold, and the Finals the queryables' plane holds and the requests it refused.
    #[cfg(feature = "query")]
    legs: [MaybeUninit<Ended>; LEG_ROWS],
    #[cfg(feature = "query")]
    leg_rows: [MaybeUninit<Option<LegRow>>; LEG_ROWS],
    #[cfg(feature = "query")]
    pending_gets: [MaybeUninit<PendingGet>; LEG_ROWS],
    #[cfg(feature = "query")]
    held_replies: HeldReplyPlaces<u64>,
    #[cfg(feature = "queryable")]
    held_finals: [MaybeUninit<FinalHold>; caps::MAX_PENDING_FINALS],
    #[cfg(feature = "queryable")]
    refused_finals: [MaybeUninit<RefusedFinal>; caps::MAX_PENDING_FINALS],
}

// SAFETY: every field is a `MaybeUninit` or an array of them, which holds no value at any bytes, or
// the round's rows, which are `ZeroEmpty`.
unsafe impl ZeroEmpty for StatePlaces {}

/// Where the value of the field at `field` is to lie.
///
/// # Safety
/// `field` is projected from a pointer to a value that is not null.
unsafe fn value_at<T>(field: *mut MaybeUninit<T>) -> NonNull<T> {
    // SAFETY: the caller's contract: a field of a value that lies at a pointer that is not null
    // is not null either.
    unsafe { NonNull::new_unchecked(field.cast::<T>()) }
}

impl StatePlaces {
    /// The cells the session lends its registry and its Router in for a step, nothing lent in
    /// either, written in their fields of the places at `at`.
    ///
    /// # Safety
    /// `at` points at the places of a region that nothing else reaches the cells' fields of, called
    /// once for them; the region neither moves nor is given back while the owners handed back live.
    pub(super) unsafe fn steps(at: NonNull<Self>) -> StepPlaces {
        let at = at.as_ptr();
        StepPlaces {
            #[cfg(wz_round)]
            // SAFETY: the caller's contract; the field is aligned for a cell and the owner's alone.
            registry: unsafe {
                Placed::written_at(value_at(addr_of_mut!((*at).registry_lend)), |cell| {
                    cell.write(core::cell::Cell::new(None))
                })
            },
            // SAFETY: the caller's contract; the field is aligned for a cell and the owner's alone.
            router: unsafe {
                Placed::written_at(value_at(addr_of_mut!((*at).router_lend)), |cell| {
                    cell.write(core::cell::Cell::new(None))
                })
            },
        }
    }

    /// The session's round over tables of `counts`, written in its field of the places at `at`,
    /// its tables over the rows of the field beside it.
    ///
    /// # Safety
    /// As [`Self::steps`], for the round's field and its rows' field.
    #[cfg(wz_round)]
    pub(super) unsafe fn round(at: NonNull<Self>, counts: RoundRowCounts) -> Placed<Round> {
        let at = at.as_ptr();
        // SAFETY: the caller's contract; the rows' field holds no value and is reached by the
        // round's tables alone, which the round's owner drops before the region goes.
        let rows = unsafe {
            RoundRows::placed_in(
                NonNull::new_unchecked(addr_of_mut!((*at).round_rows)),
                counts,
            )
        };
        // SAFETY: the caller's contract; the field is aligned for a round and the owner's alone.
        unsafe { Round::placed_at(value_at(addr_of_mut!((*at).round)), rows) }
    }

    /// The session's plain tables over the rows of their fields of the places at `at`, each of the
    /// rows `rows` count, at most the region's.
    ///
    /// # Safety
    /// As [`Self::steps`], for the tables' fields: each is reached by the one table placed over it
    /// here, which the session's planes and its state drop before the region goes.
    #[cfg(any(feature = "query", feature = "queryable"))]
    pub(super) unsafe fn tables(at: NonNull<Self>, rows: &SessionRows) -> PlacedTables {
        let at = at.as_ptr();
        // A count past the address space is held to the region's rows as any other.
        #[cfg(feature = "query")]
        let legs = rows.gets().legs().unwrap_or(usize::MAX);
        // SAFETY: the caller's contract; each field holds no value, and a field of a value at a
        // pointer that is not null is not null either.
        unsafe {
            PlacedTables {
                #[cfg(feature = "query")]
                legs: BoundedVec::placed_over(
                    NonNull::new_unchecked(addr_of_mut!((*at).legs)),
                    legs,
                ),
                #[cfg(feature = "query")]
                leg_rows: BoundedVec::placed_over(
                    NonNull::new_unchecked(addr_of_mut!((*at).leg_rows)),
                    legs,
                ),
                #[cfg(feature = "query")]
                pending_gets: BoundedVec::placed_over(
                    NonNull::new_unchecked(addr_of_mut!((*at).pending_gets)),
                    legs,
                ),
                #[cfg(feature = "query")]
                held_replies: HeldReplies::placed_over(
                    NonNull::new_unchecked(addr_of_mut!((*at).held_replies)),
                    rows.held_replies(),
                ),
                #[cfg(feature = "queryable")]
                held_finals: BoundedVec::placed_over(
                    NonNull::new_unchecked(addr_of_mut!((*at).held_finals)),
                    rows.held_queries(),
                ),
                #[cfg(feature = "queryable")]
                refused_finals: BoundedVec::placed_over(
                    NonNull::new_unchecked(addr_of_mut!((*at).refused_finals)),
                    rows.held_queries(),
                ),
            }
        }
    }

    /// The table of the places of the faces' rooms over its field of the places at `at`, `sets`
    /// of them, at most the sets the region holds.
    ///
    /// # Safety
    /// As [`Self::steps`], for the rooms' field: it is reached by the one table placed over it
    /// here.
    pub(super) unsafe fn rooms(at: NonNull<Self>, sets: usize) -> RoomPlaces {
        // SAFETY: the caller's contract; the field holds no value, and a field of a value at a
        // pointer that is not null is not null either.
        unsafe {
            BoundedVec::placed_over(
                NonNull::new_unchecked(addr_of_mut!((*at.as_ptr()).room_places)),
                sets,
            )
        }
    }

    /// The gets' plane over `ended`, `replies` and `legs`, made in its field of the places at
    /// `at` with its locks.
    ///
    /// # Safety
    /// As [`Self::steps`], for the gets' field.
    #[cfg(feature = "query")]
    pub(super) unsafe fn gets(
        at: NonNull<Self>,
        ended: EndedLegs,
        replies: HeldReplies<u64, Lent>,
        legs: LegRows,
    ) -> Placed<GetPlane> {
        // SAFETY: the caller's contract; the field is aligned for the plane, the owner's alone,
        // and stays where it is.
        unsafe {
            Placed::written_at(value_at(addr_of_mut!((*at.as_ptr()).gets)), |place| {
                GetPlane::init_at(NonNull::new_unchecked(place), ended, replies, legs)
            })
        }
    }

    /// The queryables' plane over `holds`, made in its field of the places at `at` with its
    /// locks.
    ///
    /// # Safety
    /// As [`Self::steps`], for the queryables' field.
    #[cfg(feature = "queryable")]
    pub(super) unsafe fn queries(
        at: NonNull<Self>,
        holds: query::FinalHolds,
    ) -> Placed<QueryPlane> {
        // SAFETY: as for the gets' plane.
        unsafe {
            Placed::written_at(value_at(addr_of_mut!((*at.as_ptr()).queries)), |place| {
                QueryPlane::init_at(NonNull::new_unchecked(place), holds)
            })
        }
    }

    /// The plane of the watchers of the faces, its queue of `room` rows, made in its field of the
    /// places at `at` with its locks.
    ///
    /// # Safety
    /// As [`Self::steps`], for the faces' field.
    #[cfg(feature = "connectivity")]
    pub(super) unsafe fn faces(at: NonNull<Self>, room: usize) -> Placed<FacePlane> {
        // SAFETY: as for the gets' plane.
        unsafe {
            Placed::written_at(value_at(addr_of_mut!((*at.as_ptr()).faces)), |place| {
                FacePlane::init_at(NonNull::new_unchecked(place), room)
            })
        }
    }
}

/// The state of a session whose tables take their memory at their first row (`tables-on-use`),
/// held apart from its arena: the places of the state's own values and the budget the session's
/// keys are counted against. The allocator gives it zeroed at the open ([`OwnBlock::take`]),
/// every place holding no value until its owner writes it, and it is reached through a pointer,
/// each field projected from it, as a region is.
#[cfg(all(feature = "tables-on-use", not(feature = "runtime-plan")))]
pub(crate) struct OwnState {
    places: StatePlaces,
    /// The budget the session's keys are counted against, written by the open ([`Self::place`]):
    /// a key is an allocation of its own, which points at its budget, so the budget lies where it
    /// never moves while a key of it lives.
    keys: MaybeUninit<KeyBudget>,
}

// SAFETY: the places are `ZeroEmpty`, and the key budget is a `MaybeUninit`, valid as any bytes.
#[cfg(all(feature = "tables-on-use", not(feature = "runtime-plan")))]
unsafe impl ZeroEmpty for OwnState {}

// The budget lies in a `MaybeUninit`, which the state's drop leaves alone: a budget whose drop did
// anything would not have it done.
#[cfg(all(feature = "tables-on-use", not(feature = "runtime-plan")))]
const _: () = assert!(
    !core::mem::needs_drop::<KeyBudget>(),
    "the state's drop leaves the key budget as it lies"
);

#[cfg(all(feature = "tables-on-use", not(feature = "runtime-plan")))]
impl OwnState {
    /// Write the budget the session's keys are counted against in the zeroed state at `state`:
    /// its keys at most `limits`' `MAX_KEYEXPR_BYTES` long and together at most its
    /// `KEY_ARENA_BYTES`, counted as the key arena would count them; and hand back the handle the
    /// session's tables make their keys through. The state's places are written by their owners
    /// after.
    ///
    /// # Safety
    /// `state` points at an `OwnState` of all zero bytes, aligned, that nothing else reaches, and
    /// which neither moves nor is given back while a key counted against its budget, or a table or
    /// a handle holding the budget, lives.
    pub(crate) unsafe fn place(state: NonNull<Self>, limits: &SessionLimits) -> BudgetKeys {
        // SAFETY: the caller's contract: the budget's field is the state's, aligned for a budget,
        // and reached by this write and the reference after it alone, before any key exists; it is
        // not written again.
        let budget = unsafe {
            let field = addr_of_mut!((*state.as_ptr()).keys).cast::<KeyBudget>();
            field.write(KeyBudget::new(
                limits.key_arena_bytes(),
                limits.max_keyexpr_bytes_held(),
            ));
            &*field
        };
        // SAFETY: the caller's contract: the state, and the budget in it, neither moves nor is
        // given back while a key, a table or a handle of the budget lives.
        unsafe { budget.keys() }
    }

    /// Where the places of the state's own values in the state at `state` lie.
    ///
    /// # Safety
    /// `state` points at an `OwnState`.
    pub(crate) unsafe fn places_at(state: NonNull<Self>) -> NonNull<StatePlaces> {
        // SAFETY: the caller's contract: a field of a value that lies at a pointer that is not null
        // is not null either.
        unsafe { NonNull::new_unchecked(addr_of_mut!((*state.as_ptr()).places)) }
    }
}

/// The zeroed `T` in an allocation of its own the allocator gave, every field of it empty
/// (`ZeroEmpty`) until its owner writes it, dropped in place and given back when this is. It
/// holds the pointer and never a reference to the whole `T`: what lies in it is reached by
/// fields projected from [`Self::as_ptr`], as a region's block is reached.
#[cfg(all(feature = "tables-on-use", not(feature = "runtime-plan")))]
pub(crate) struct OwnBlock<T: ZeroEmpty> {
    at: NonNull<T>,
}

#[cfg(all(feature = "tables-on-use", not(feature = "runtime-plan")))]
impl<T: ZeroEmpty> OwnBlock<T> {
    /// A `T` of all zero bytes in an allocation of its own. Refused, having taken nothing, when
    /// the allocator has no room for it.
    pub(crate) fn take() -> Result<Self, ArenaRefused> {
        const {
            assert!(
                core::mem::size_of::<T>() != 0,
                "an allocation of its own holds some bytes"
            )
        };
        let layout = Layout::new::<T>();
        // SAFETY: the layout's size is not zero (above).
        let at = NonNull::new(unsafe { alloc::alloc::alloc_zeroed(layout) }.cast::<T>()).ok_or(
            ArenaRefused::NoMemory {
                bytes: layout.size(),
            },
        )?;
        Ok(Self { at })
    }

    /// Where the `T` lies, aligned and of all zero bytes until its owner writes it.
    pub(crate) fn as_ptr(&self) -> NonNull<T> {
        self.at
    }
}

// SAFETY: the block owns the `T` at its pointer, which nothing else reaches, as a `Box` owns its
// value.
#[cfg(all(feature = "tables-on-use", not(feature = "runtime-plan")))]
unsafe impl<T: ZeroEmpty + Send> Send for OwnBlock<T> {}
// SAFETY: a shared block hands out nothing but its pointer, as above.
#[cfg(all(feature = "tables-on-use", not(feature = "runtime-plan")))]
unsafe impl<T: ZeroEmpty + Sync> Sync for OwnBlock<T> {}

#[cfg(all(feature = "tables-on-use", not(feature = "runtime-plan")))]
impl<T: ZeroEmpty> Drop for OwnBlock<T> {
    fn drop(&mut self) {
        // SAFETY: the block holds a `T` (zero bytes are one, and every write since kept one),
        // dropped once, here, in place; the allocation is given back after it with the layout it
        // was taken with, and nothing reaches it after.
        unsafe {
            core::ptr::drop_in_place(self.at.as_ptr());
            alloc::alloc::dealloc(self.at.as_ptr().cast::<u8>(), Layout::new::<T>());
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::arena::{ArenaPlan, PlanShape};
    use wz_session_core::limits::SessionLimits;

    /// The table of the rooms' places placed over a region's places takes the sets asked, at most
    /// the sets the region holds, and lies in the places. Turned red by a field of fewer places
    /// than the sets the build's plan counts, or by a table placed anywhere but the places.
    #[test]
    fn the_rooms_places_take_the_regions_sets_at_most() {
        let plan = ArenaPlan::planned(
            PlanShape::dial_only(1, 1024, &wz_session_core::policy::SessionPolicy::defaults()),
            &SessionLimits::BUILD,
        )
        .expect("the build's client");
        let sets = plan.peers().sets();
        assert!(
            sets <= FACE_SETS,
            "the region holds every set the plan counts"
        );
        let mut places = std::boxed::Box::new(MaybeUninit::<StatePlaces>::uninit());
        let at = NonNull::from(&mut *places).cast::<StatePlaces>();
        let start = at.as_ptr() as usize;
        // SAFETY: the places are this test's box, holding no value and reached by the table alone,
        // which is dropped before the next one is placed and before the box.
        let rooms = unsafe { StatePlaces::rooms(at, sets) };
        assert_eq!(rooms.free_slots(), sets);
        assert!((start..=start + core::mem::size_of::<StatePlaces>())
            .contains(&(rooms.as_ptr() as usize)));
        drop(rooms);
        // SAFETY: as above; the table before is gone.
        let past = unsafe { StatePlaces::rooms(at, FACE_SETS + 1) };
        assert_eq!(past.free_slots(), FACE_SETS, "held to the region's sets");
    }

    /// The plain tables placed over a region's places take the rows the build's plan counts, which
    /// the region keeps every one of, and lie in the places. Turned red by a field of fewer rows
    /// than the plan counts (`LEG_ROWS`), by a table held to other counts than the plan's, or by
    /// one placed anywhere but the places.
    #[cfg(any(feature = "query", feature = "queryable"))]
    #[test]
    fn the_plain_tables_take_the_plans_rows_in_the_places() {
        let shape =
            PlanShape::dial_only(1, 1024, &wz_session_core::policy::SessionPolicy::defaults());
        let plan = ArenaPlan::planned(shape, &SessionLimits::BUILD).expect("the build's client");
        let rows = plan.session();
        let mut places = std::boxed::Box::new(MaybeUninit::<StatePlaces>::uninit());
        let at = NonNull::from(&mut *places).cast::<StatePlaces>();
        let start = at.as_ptr() as usize;
        let within = start..=start + core::mem::size_of::<StatePlaces>();
        // SAFETY: the places are this test's box, holding no value and reached by the tables alone,
        // which are dropped before it.
        let tables = unsafe { StatePlaces::tables(at, rows) };
        #[cfg(feature = "query")]
        {
            let legs = rows.gets().legs().expect("within the address space");
            assert!(
                legs <= LEG_ROWS,
                "the region keeps every leg the plan counts"
            );
            assert_eq!(tables.legs.free_slots(), legs);
            assert_eq!(tables.leg_rows.free_slots(), legs);
            assert_eq!(tables.pending_gets.free_slots(), legs);
            assert!(tables.held_replies.is_empty());
            for table in [
                tables.legs.as_ptr() as usize,
                tables.leg_rows.as_ptr() as usize,
                tables.pending_gets.as_ptr() as usize,
            ] {
                assert!(within.contains(&table), "the rows are the region's");
            }
        }
        #[cfg(feature = "queryable")]
        {
            let held = rows.held_queries();
            assert!(held <= caps::MAX_PENDING_FINALS);
            assert_eq!(tables.held_finals.free_slots(), held);
            assert_eq!(tables.refused_finals.free_slots(), held);
            assert!(within.contains(&(tables.held_finals.as_ptr() as usize)));
            assert!(within.contains(&(tables.refused_finals.as_ptr() as usize)));
        }
        drop(tables);
    }

    /// The state a session whose tables take their memory on use holds apart from its arena is an
    /// allocation of its own: it holds the session's key budget, which the open writes at the
    /// session's `KEY_ARENA_BYTES`, a key made through the handle it hands back counted there as
    /// its arena block and given back, and the places of the state's own values lie inside it.
    /// Turned red by a budget of other bytes than the limits state, by a handle of no budget
    /// (`BudgetKeys::default` in place of `budget.keys()`), which keeps no key, or by places
    /// projected anywhere but the state.
    #[cfg(all(feature = "tables-on-use", not(feature = "runtime-plan")))]
    #[test]
    fn an_on_use_state_holds_the_sessions_key_budget_and_its_places() {
        use wz_session_core::bounded::KeyMaker;
        use wz_session_core::key_arena::block_bytes;
        let state = OwnBlock::<OwnState>::take().expect("the test allocator answers");
        let limits = SessionLimits::BUILD;
        // SAFETY: the state is zeroed, aligned and this test's alone, and is given back after the
        // last key counted against its budget.
        let keys = unsafe { OwnState::place(state.as_ptr(), &limits) };
        assert_eq!(keys.counts().bytes, limits.key_arena_bytes());
        assert_eq!(keys.counts().used, 0);
        let key = keys.key("demo/state").expect("room for a key");
        assert_eq!(
            keys.counts().used,
            block_bytes("demo/state".len()).expect("a short key's block")
        );
        drop(key);
        assert_eq!(keys.counts().used, 0, "the key's bytes went back");
        let start = state.as_ptr().as_ptr() as usize;
        // SAFETY: the state is the one taken above.
        let places = unsafe { OwnState::places_at(state.as_ptr()) }.as_ptr() as usize;
        assert!(
            (start..start + core::mem::size_of::<OwnState>()).contains(&places),
            "the places lie in the state"
        );
        drop(state);
    }
}
