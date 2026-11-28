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
//! which gives it back after every owner written in it. The rows of the plain tables and of the
//! round are not among those places: each of those tables takes its own at its first row
//! (`PlacedTables::counted`, `RoundRows::counted`).

#[cfg(wz_on_use)]
use core::alloc::Layout;
#[cfg(wz_on_use)]
use core::mem::ManuallyDrop;
use core::mem::MaybeUninit;
use core::ptr::{addr_of_mut, NonNull};

#[cfg(any(not(wz_on_use), feature = "queryable"))]
use wz_session_core::bounded::BoundedVec;
use wz_session_core::bounded::ZeroEmpty;
#[cfg(all(feature = "queryable", not(wz_on_use)))]
use wz_session_core::caps;
use wz_session_core::placed::Placed;
#[cfg(wz_on_use)]
use wz_session_core::placed::PlacedRef;
#[cfg(all(wz_round, not(wz_on_use)))]
use wz_session_core::round::RoundRowPlaces;
use wz_session_core::step_lend::LendCell;

#[cfg(feature = "queryable")]
use super::query;
#[cfg(not(wz_on_use))]
use super::registry::FACE_SETS;
#[cfg(feature = "connectivity")]
use super::FacePlane;
#[cfg(feature = "queryable")]
use super::QueryPlane;
#[cfg(wz_round)]
use super::Registry;
#[cfg(all(feature = "queryable", not(wz_on_use)))]
use super::{FinalHold, RefusedFinal};
#[cfg(not(wz_on_use))]
use super::{RoomPlace, RoomPlaces};
use super::{SessionReassembly, StepPlaces};
#[cfg(feature = "queryable")]
use crate::arena::SessionRows;
#[cfg(all(wz_round, not(wz_on_use)))]
use crate::calls::CoopCalls;
#[cfg(wz_round)]
use crate::round::{Round, RoundRowCounts, RoundRows};
#[cfg(feature = "queryable")]
use crate::StatePolicy;
#[cfg(wz_on_use)]
use wz_session_core::limits::SessionLimits;
#[cfg(wz_on_use)]
use wz_session_core::on_use::{BudgetKeys, KeyBudget};

#[cfg(wz_on_use)]
use crate::arena::ArenaRefused;

/// The plain tables of the session's state, what an arena lends a session whose shape the open
/// plans: over the rows of its region (`StatePlaces::tables`), or each counted and taking its rows
/// at its first row where the tables take their memory on use (`PlacedTables::counted`).
#[cfg(feature = "queryable")]
pub(super) struct PlacedTables {
    #[cfg(feature = "queryable")]
    pub(super) held_finals: query::HeldFinals<StatePolicy>,
    #[cfg(feature = "queryable")]
    pub(super) refused_finals: query::RefusedFinals<StatePolicy>,
}

#[cfg(all(feature = "queryable", wz_on_use))]
impl PlacedTables {
    /// The session's plain tables where they take their memory on use: each counted as `rows`
    /// counts its rows, under the build's bound, and holding none until its first row. A count past
    /// the address space is a table whose first row the allocator refuses.
    pub(super) fn counted(rows: &SessionRows) -> Self {
        Self {
            #[cfg(feature = "queryable")]
            held_finals: BoundedVec::counted(rows.held_queries()),
            #[cfg(feature = "queryable")]
            refused_finals: BoundedVec::counted(rows.held_queries()),
        }
    }
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
    #[cfg(all(wz_round, not(wz_on_use)))]
    round_rows: RoundRowPlaces<CoopCalls>,
    #[cfg(feature = "queryable")]
    queries: MaybeUninit<QueryPlane>,
    #[cfg(feature = "connectivity")]
    faces: MaybeUninit<FacePlane>,
    /// What the face holding each set names for a wait for its room, a place for each set the
    /// region holds; where the tables take their memory on use, each face's place is made at its
    /// first hold of a wait instead, none in the state (`crate::engine::RoomPlaces`).
    #[cfg(not(wz_on_use))]
    room_places: [MaybeUninit<Option<RoomPlace>>; FACE_SETS],
    /// The rows of the session's plain tables, each table's at the build's bound: the Finals the
    /// queryables' plane holds and the requests it refused.
    #[cfg(all(feature = "queryable", not(wz_on_use)))]
    held_finals: [MaybeUninit<FinalHold>; caps::MAX_PENDING_FINALS],
    #[cfg(all(feature = "queryable", not(wz_on_use)))]
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

    /// The session's round over tables of `counts`, written in its field of the places at `at`:
    /// its tables over the rows of the field beside it, or, where the tables take their memory on
    /// use, counted, taking their rows at the round's first record.
    ///
    /// # Safety
    /// As [`Self::steps`], for the round's field and, where the places keep them, its rows' field.
    #[cfg(wz_round)]
    pub(super) unsafe fn round(at: NonNull<Self>, counts: RoundRowCounts) -> Placed<Round> {
        let at = at.as_ptr();
        // SAFETY: the caller's contract; the rows' field holds no value and is reached by the
        // round's tables alone, which the round's owner drops before the region goes.
        #[cfg(not(wz_on_use))]
        let rows = unsafe {
            RoundRows::placed_in(
                NonNull::new_unchecked(addr_of_mut!((*at).round_rows)),
                counts,
            )
        };
        #[cfg(wz_on_use)]
        let rows = RoundRows::counted(counts);
        // SAFETY: the caller's contract; the field is aligned for a round and the owner's alone.
        unsafe { Round::placed_at(value_at(addr_of_mut!((*at).round)), rows) }
    }

    /// The session's plain tables over the rows of their fields of the places at `at`, each of the
    /// rows `rows` count, at most the region's.
    ///
    /// # Safety
    /// As [`Self::steps`], for the tables' fields: each is reached by the one table placed over it
    /// here, which the session's planes and its state drop before the region goes.
    #[cfg(all(feature = "queryable", not(wz_on_use)))]
    pub(super) unsafe fn tables(at: NonNull<Self>, rows: &SessionRows) -> PlacedTables {
        let at = at.as_ptr();
        // SAFETY: the caller's contract; each field holds no value, and a field of a value at a
        // pointer that is not null is not null either.
        unsafe {
            PlacedTables {
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
    #[cfg(not(wz_on_use))]
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

    /// The queryables' plane over `holds`, made in its field of the places at `at` with its
    /// locks.
    ///
    /// # Safety
    /// As [`Self::steps`], for the queryables' field.
    #[cfg(feature = "queryable")]
    pub(super) unsafe fn queries(
        at: NonNull<Self>,
        holds: query::FinalHolds<StatePolicy>,
    ) -> Placed<QueryPlane> {
        // SAFETY: the caller's contract; the field is aligned for the plane, the owner's alone,
        // and stays where it is.
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
        // SAFETY: the caller's contract; the field is aligned for the plane, the owner's alone,
        // and stays where it is.
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
#[cfg(wz_on_use)]
pub(crate) struct OwnState {
    places: StatePlaces,
    /// The budget the session's keys are counted against, written by the open ([`Self::place`]):
    /// a key is an allocation of its own, which points at its budget, so the budget lies where it
    /// never moves while a key of it lives.
    keys: MaybeUninit<KeyBudget>,
}

// SAFETY: the places are `ZeroEmpty`, and the key budget is a `MaybeUninit`, valid as any bytes.
#[cfg(wz_on_use)]
unsafe impl ZeroEmpty for OwnState {}

// The budget lies in a `MaybeUninit`, which the state's drop leaves alone: a budget whose drop did
// anything would not have it done.
#[cfg(wz_on_use)]
const _: () = assert!(
    !core::mem::needs_drop::<KeyBudget>(),
    "the state's drop leaves the key budget as it lies"
);

#[cfg(wz_on_use)]
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
            field.write(
                KeyBudget::new(limits.key_arena_bytes(), limits.max_keyexpr_bytes_held())
                    .holding_peer_rows_to(limits),
            );
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

/// A value written where it lies in an allocation of its own the allocator gave, owned here as a
/// [`Placed`] owns one whose memory an arena or a region holds: the value is dropped where it lies
/// when this is, and its allocation given back after it, so one owner answers for both and no
/// field is held for its drop alone. What the faces' rooms lie in where the tables take their
/// memory on use (`Core::rooms`).
#[cfg(wz_on_use)]
pub(crate) struct OwnPlaced<T> {
    /// Dropped by this owner's drop, before the allocation it lies in is given back.
    value: ManuallyDrop<Placed<T>>,
}

#[cfg(wz_on_use)]
impl<T> OwnPlaced<T> {
    /// An allocation of its own for one `T`, nothing written in it yet ([`OwnVacant`]): what the
    /// open reserves while what it would write the value from is still whole, and fills once
    /// nothing after it can refuse. Refused, having taken nothing, when the allocator has no room
    /// for it.
    pub(crate) fn vacant() -> Result<OwnVacant<T>, ArenaRefused> {
        const {
            assert!(
                core::mem::size_of::<T>() != 0,
                "an allocation of its own holds some bytes"
            )
        };
        let layout = Layout::new::<T>();
        // SAFETY: the layout's size is not zero (above).
        let at = NonNull::new(unsafe { alloc::alloc::alloc(layout) }.cast::<T>()).ok_or(
            ArenaRefused::NoMemory {
                bytes: layout.size(),
            },
        )?;
        Ok(OwnVacant { at })
    }

    /// A handle of the value that counts nothing, as [`Placed::share`] hands one.
    ///
    /// # Safety
    /// As [`Placed::share`]'s, of this owner.
    pub(crate) unsafe fn share(&self) -> PlacedRef<T> {
        // SAFETY: the caller's contract, which is the owner's.
        unsafe { self.value.share() }
    }
}

#[cfg(wz_on_use)]
impl<T> core::ops::Deref for OwnPlaced<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.value
    }
}

#[cfg(wz_on_use)]
impl<T> Drop for OwnPlaced<T> {
    fn drop(&mut self) {
        let at = NonNull::from(&**self.value).cast::<u8>();
        // SAFETY: the value is dropped once, here, where it lies, and nothing reaches it after
        // (`Placed::share`'s contract); its allocation is the one `OwnPlaced::vacant` took with
        // this layout and `OwnVacant::fill` handed on, given back once, after it.
        unsafe {
            ManuallyDrop::drop(&mut self.value);
            alloc::alloc::dealloc(at.as_ptr(), Layout::new::<T>());
        }
    }
}

/// An allocation of its own the allocator gave for one `T`, nothing written in it
/// ([`OwnPlaced::vacant`]), as a span an arena lends is (`wz_session_core::placed::Vacant`), but
/// owned: given back unwritten when it is dropped unfilled, so a refusal between its reservation
/// and its fill leaves nothing taken.
#[cfg(wz_on_use)]
pub(crate) struct OwnVacant<T> {
    at: NonNull<T>,
}

#[cfg(wz_on_use)]
impl<T> OwnVacant<T> {
    /// The owner of the value `write` writes in the allocation, which drops it there and gives the
    /// allocation back after it.
    ///
    /// # Safety
    /// `write` writes a whole valid `T` at the pointer it is given, which is aligned for `T` and
    /// valid for writes of one.
    pub(crate) unsafe fn fill(self, write: impl FnOnce(*mut T)) -> OwnPlaced<T> {
        // The allocation passes to the owner made here, so this one's drop does not give it back.
        let at = ManuallyDrop::new(self).at;
        // SAFETY: the allocation is aligned and valid for writes of one `T`, which `write` writes
        // whole (the caller's contract); it is reached through the owner and its handles alone,
        // and is given back only after the value is dropped (`OwnPlaced`'s `Drop`).
        let value = unsafe { Placed::written_at(at, write) };
        OwnPlaced {
            value: ManuallyDrop::new(value),
        }
    }
}

#[cfg(wz_on_use)]
impl<T> Drop for OwnVacant<T> {
    fn drop(&mut self) {
        // SAFETY: the allocation is the one `OwnPlaced::vacant` took with this layout, holding no
        // value (a filled one never reaches this drop), given back once, here.
        unsafe { alloc::alloc::dealloc(self.at.as_ptr().cast::<u8>(), Layout::new::<T>()) }
    }
}

/// The zeroed `T` in an allocation of its own the allocator gave, every field of it empty
/// (`ZeroEmpty`) until its owner writes it, dropped in place and given back when this is. It
/// holds the pointer and never a reference to the whole `T`: what lies in it is reached by
/// fields projected from [`Self::as_ptr`], as a region's block is reached.
#[cfg(wz_on_use)]
pub(crate) struct OwnBlock<T: ZeroEmpty> {
    at: NonNull<T>,
}

#[cfg(wz_on_use)]
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
#[cfg(wz_on_use)]
unsafe impl<T: ZeroEmpty + Send> Send for OwnBlock<T> {}
// SAFETY: a shared block hands out nothing but its pointer, as above.
#[cfg(wz_on_use)]
unsafe impl<T: ZeroEmpty + Sync> Sync for OwnBlock<T> {}

#[cfg(wz_on_use)]
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
    #[cfg(any(not(wz_on_use), feature = "queryable"))]
    use crate::arena::{ArenaPlan, PlanShape};
    use wz_session_core::limits::SessionLimits;

    /// The table of the rooms' places placed over a region's places takes the sets asked, at most
    /// the sets the region holds, and lies in the places. Turned red by a field of fewer places
    /// than the sets the build's plan counts, or by a table placed anywhere but the places.
    #[cfg(not(wz_on_use))]
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

    /// An allocation of its own reserved vacant holds nothing until it is filled: what is written
    /// in it then lies where it was reserved and is dropped once, by the owner the fill hands back,
    /// and one dropped unfilled drops no value. Turned red by a fill that writes anywhere but the
    /// allocation reserved, or by `OwnVacant`'s drop dropping a value in place before it gives the
    /// allocation back.
    #[cfg(wz_on_use)]
    #[test]
    fn an_on_use_vacant_allocation_holds_nothing_until_it_is_filled() {
        use core::cell::Cell;

        struct Counted<'d>(&'d Cell<usize>, u32);
        impl Drop for Counted<'_> {
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }

        let drops = Cell::new(0);
        let unfilled = OwnPlaced::<Counted<'_>>::vacant().expect("the test allocator answers");
        drop(unfilled);
        assert_eq!(drops.get(), 0, "an unfilled allocation holds no value");
        let vacant = OwnPlaced::<Counted<'_>>::vacant().expect("the test allocator answers");
        let at = vacant.at;
        // SAFETY: the closure writes a whole value.
        let placed = unsafe { vacant.fill(|place| place.write(Counted(&drops, 4))) };
        assert_eq!(drops.get(), 0, "nothing is dropped as the value is written");
        assert!(
            core::ptr::eq(&*placed, at.as_ptr()),
            "the value lies where the allocation was reserved"
        );
        assert_eq!(placed.1, 4);
        drop(placed);
        assert_eq!(drops.get(), 1, "dropped once, by its owner");
    }

    /// The plain tables placed over a region's places take the rows the build's plan counts, which
    /// the region keeps every one of, and lie in the places. Turned red by a field of fewer rows
    /// than the plan counts, by a table held to other counts than the plan's, or by one placed
    /// anywhere but the places.
    #[cfg(all(feature = "queryable", not(wz_on_use)))]
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

    /// The plain tables of a session whose tables take their memory on use are counted as the build's
    /// plan counts their rows and hold none until their first row: no place of the state keeps
    /// them. Turned red by a table counted with the build's bound in place of the plan's count, or by
    /// one that takes its rows when made (`PlacedTables::counted` over the region's places).
    #[cfg(all(feature = "queryable", wz_on_use))]
    #[test]
    fn the_plain_tables_on_use_hold_the_plans_counts_and_no_row() {
        let shape =
            PlanShape::dial_only(1, 1024, &wz_session_core::policy::SessionPolicy::defaults());
        let plan = ArenaPlan::planned(shape, &SessionLimits::BUILD).expect("the build's client");
        let rows = plan.session();
        let tables = PlacedTables::counted(rows);
        {
            let held = rows.held_queries();
            assert_eq!(tables.held_finals.free_slots(), held);
            assert_eq!(tables.refused_finals.free_slots(), held);
            assert!(
                !tables.held_finals.holds_rows() && !tables.refused_finals.holds_rows(),
                "no row before the first"
            );
        }
        drop(tables);
    }

    /// The state a session whose tables take their memory on use holds apart from its arena is an
    /// allocation of its own: it holds the session's key budget, which the open writes at the
    /// session's `KEY_ARENA_BYTES`, a key made through the handle it hands back counted there as
    /// its arena block and given back, and the places of the state's own values lie inside it.
    /// The budget holds the rows the session's peers write to the limits' session bounds, the
    /// tokens to `SESSION_MAX_REMOTE_DECLS` among them. Turned red by a budget of other bytes than
    /// the limits state, by a handle of no budget (`BudgetKeys::default` in place of
    /// `budget.keys()`), which keeps no key, by a budget held to no peer bound
    /// (`holding_peer_rows_to` left out of `OwnState::place`), or by places projected anywhere
    /// but the state.
    #[cfg(wz_on_use)]
    #[test]
    fn an_on_use_state_holds_the_sessions_key_budget_and_its_places() {
        use wz_session_core::bounded::KeyMaker;
        use wz_session_core::key_arena::block_bytes;
        use wz_session_core::row_pool::PeerSlot;
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
        let budget = keys
            .budget()
            .expect("the handle names the session's budget");
        if let Some(most) = limits.session_max_remote_decls().most() {
            for _ in 0..most {
                assert!(budget.take_peer_row(PeerSlot::Tokens));
            }
            assert!(
                !budget.take_peer_row(PeerSlot::Tokens),
                "the session's SESSION_MAX_REMOTE_DECLS binds its peers' tokens together"
            );
            budget.give_peer_rows(PeerSlot::Tokens, most);
        }
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
