// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The values a session whose shape the build fixes owns in its state and its tasks reach by
//! handles that count nothing, laid out as fields of the session's region
//! (`crate::region::StateRegion`) instead of placed in its arena: the round of deliveries and the
//! rows of its tables, the planes of its gets, its queryables and the watchers of its faces, and
//! the cells its registry and its Router are lent in for a step. Each lies in a `MaybeUninit` field, which the region's drop does not drop: the
//! [`Placed`] owner written there does, wherever the session holds it, so each value is let go in
//! the order the session lets its owner go, as one the arena held was.

use core::mem::MaybeUninit;
use core::ptr::{addr_of_mut, NonNull};

use wz_session_core::bounded::ZeroEmpty;
use wz_session_core::placed::Placed;
use wz_session_core::round::RoundRowPlaces;
use wz_session_core::step_lend::LendCell;

#[cfg(feature = "connectivity")]
use super::FacePlane;
#[cfg(feature = "query")]
use super::GetPlane;
#[cfg(feature = "queryable")]
use super::QueryPlane;
#[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
use super::Registry;
use super::{SessionReassembly, StepPlaces};
use crate::round::{CoopCalls, Round, RoundRowCounts, RoundRows};

/// The places of a session's region its state's own values are written in: see the module
/// documentation.
pub(crate) struct StatePlaces {
    /// Where the registry is lent to the dispatch of a link that runs as a task.
    #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
    registry_lend: MaybeUninit<LendCell<Registry>>,
    /// Where the reassembly Router is lent to the links' receives.
    router_lend: MaybeUninit<LendCell<SessionReassembly>>,
    round: MaybeUninit<Round>,
    /// The rows of the round's tables, which the round reads where they lie: the build's bound of
    /// each, as the round's form keeps them.
    round_rows: RoundRowPlaces<CoopCalls>,
    #[cfg(feature = "query")]
    gets: MaybeUninit<GetPlane>,
    #[cfg(feature = "queryable")]
    queries: MaybeUninit<QueryPlane>,
    #[cfg(feature = "connectivity")]
    faces: MaybeUninit<FacePlane>,
}

// SAFETY: every field is a `MaybeUninit`, which holds no value at any bytes, or the round's rows,
// which are `ZeroEmpty`.
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
            #[cfg(any(feature = "threads", feature = "listen", feature = "group"))]
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

    /// The gets' `plane`, written in its field of the places at `at`.
    ///
    /// # Safety
    /// As [`Self::steps`], for the gets' field.
    #[cfg(feature = "query")]
    pub(super) unsafe fn gets(at: NonNull<Self>, plane: GetPlane) -> Placed<GetPlane> {
        // SAFETY: the caller's contract; the field is aligned for the plane and the owner's alone.
        unsafe {
            Placed::written_at(value_at(addr_of_mut!((*at.as_ptr()).gets)), |place| {
                place.write(plane)
            })
        }
    }

    /// The queryables' `plane`, written in its field of the places at `at`.
    ///
    /// # Safety
    /// As [`Self::steps`], for the queryables' field.
    #[cfg(feature = "queryable")]
    pub(super) unsafe fn queries(at: NonNull<Self>, plane: QueryPlane) -> Placed<QueryPlane> {
        // SAFETY: the caller's contract; the field is aligned for the plane and the owner's alone.
        unsafe {
            Placed::written_at(value_at(addr_of_mut!((*at.as_ptr()).queries)), |place| {
                place.write(plane)
            })
        }
    }

    /// The plane of the watchers of the faces, written in its field of the places at `at`.
    ///
    /// # Safety
    /// As [`Self::steps`], for the faces' field.
    #[cfg(feature = "connectivity")]
    pub(super) unsafe fn faces(at: NonNull<Self>, plane: FacePlane) -> Placed<FacePlane> {
        // SAFETY: the caller's contract; the field is aligned for the plane and the owner's alone.
        unsafe {
            Placed::written_at(value_at(addr_of_mut!((*at.as_ptr()).faces)), |place| {
                place.write(plane)
            })
        }
    }
}
