// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Which face holds each place of the session's faces, the mark of each row of the table of
//! places: the face's id, free (`NO_FACE`) or kept for a departed face's tomb (`KEPT`). The
//! dial role's face holds the first place for the table's life, so its mark is no row of memory;
//! the rows past it are the registry's description's line of the held marks
//! (`RowCount::HeldSets`, a row for each set past the dial role's), lent from the arena or taking
//! their rows at the open where the session's tables take their memory on use, where the build
//! adds faces beside the dial role's (`listen`, `group`); a build of that face alone has none,
//! the bound of the table a build limit and not a type. The other faces a matching verdict counts
//! are the table's rows but the caller's ([`OtherFaces`]): none where the table is of one row.

#[cfg(not(wz_on_use))]
use super::described::HELD_LINES;
use super::{names_face, FaceId, FaceTables, DIAL_FACE};
#[cfg(wz_on_use)]
use crate::arena::ArenaRefused;
#[cfg(wz_lent)]
use wz_session_core::bounded::LendRefused;
#[cfg(not(wz_on_use))]
use wz_session_core::bounded::RegionLines;

#[cfg(any(feature = "listen", feature = "group", all(test, wz_lent)))]
use super::Others;
#[cfg(any(
    feature = "connectivity",
    feature = "listen",
    feature = "group",
    all(test, wz_lent)
))]
use super::NO_FACE;
#[cfg(any(feature = "listen", feature = "group", all(test, wz_lent)))]
use crate::arena::MAX_FACE_SETS;
#[cfg(any(feature = "listen", feature = "group", all(test, wz_lent)))]
use crate::RowPolicy;
#[cfg(any(feature = "listen", feature = "group", all(test, wz_lent)))]
use wz_session_core::bounded::BoundedVec;
#[cfg(all(
    not(wz_on_use),
    any(feature = "listen", feature = "group", all(test, wz_lent))
))]
use wz_session_core::bounded::{RowCount, SeqPlace};

#[cfg(not(any(feature = "listen", feature = "group", all(test, wz_lent))))]
use wz_session_core::slot_observer::NoOtherPeers;

/// The marks of the places past the dial role's, by the place less one: a row for each place the
/// open counted past it, of the policy of the session's tables, lent from the arena with the sets
/// (`crate::arena::ArenaPart::HeldFaces`) or taken at the open where the tables take their memory
/// on use, so a face coming or going writes its place's row and moves none.
#[cfg(any(feature = "listen", feature = "group", all(test, wz_lent)))]
type PastDial = BoundedVec<FaceId, MAX_FACE_SETS, RowPolicy>;

/// See the form of a build that adds faces: a session of its dial role's face alone has no place
/// past it.
#[cfg(not(any(feature = "listen", feature = "group", all(test, wz_lent))))]
type PastDial = [FaceId; 0];

/// The faces other than the one a call acts on, which the matching verdicts of that call count:
/// the sets of the table's rows but the caller's that a face holds.
#[cfg(any(feature = "listen", feature = "group", all(test, wz_lent)))]
pub(super) type OtherFaces<'a> = Others<'a>;

/// See the form of a build that adds faces: the table of one row has no row but the caller's.
#[cfg(not(any(feature = "listen", feature = "group", all(test, wz_lent))))]
pub(super) type OtherFaces<'a> = NoOtherPeers;

/// The table of the session's places, by its marks (see the module documentation).
pub(in crate::engine) struct HeldPlaces {
    past_dial: PastDial,
}

impl HeldPlaces {
    /// The rows the table keeps of `sets` places: a mark for each past the dial role's, whose
    /// mark is no row. What the registry's description lends its line (`RowCount::HeldSets`) and
    /// a plan counts of it (`crate::arena::ArenaPart::HeldFaces`).
    #[cfg(any(wz_lent, all(wz_on_use, any(feature = "listen", feature = "group"))))]
    pub(super) const fn rows_of(sets: usize) -> usize {
        sets.saturating_sub(1)
    }

    /// The table's line in the registry's description, from where the registry keeps it: the
    /// marks past the dial role's, lent `RowCount::HeldSets`, where the build adds faces; none
    /// where the table is of the dial role's one row.
    #[cfg(all(
        not(wz_on_use),
        any(feature = "listen", feature = "group", all(test, wz_lent))
    ))]
    pub(super) const LINES: RegionLines<HELD_LINES> = RegionLines::EMPTY.seq(
        SeqPlace::of::<FaceId>(core::mem::offset_of!(Self, past_dial), 0, MAX_FACE_SETS)
            .counted(RowCount::HeldSets),
    );

    /// See the form of a build that adds faces: the table of one row lends nothing.
    #[cfg(all(
        not(wz_on_use),
        not(any(feature = "listen", feature = "group", all(test, wz_lent)))
    ))]
    pub(super) const LINES: RegionLines<HELD_LINES> = RegionLines::EMPTY;

    /// The table before the registry's walk lends it its rows (`Registry::new`): of no row.
    #[cfg(wz_lent)]
    pub(super) fn rowless() -> Self {
        Self {
            past_dial: PastDial::default(),
        }
    }

    /// Mark free each of `sets` places past the dial role's in the rows the walk lent the table.
    /// Refused when the table was lent fewer rows, which the walk has refused first. A session of
    /// its dial role's face alone is lent one set, and marks nothing.
    #[cfg(wz_lent)]
    pub(super) fn hold_sets(&mut self, sets: usize) -> Result<(), LendRefused> {
        #[cfg(any(feature = "listen", feature = "group", all(test, wz_lent)))]
        for _ in 0..Self::rows_of(sets) {
            self.past_dial
                .push(NO_FACE)
                .map_err(|_| LendRefused::OverCeiling {
                    rows: 1,
                    ceiling: 0,
                })?;
        }
        #[cfg(not(any(feature = "listen", feature = "group", all(test, wz_lent))))]
        debug_assert_eq!(sets, 1, "a session of one face is lent one set");
        Ok(())
    }

    /// The table of `sets` places where the session's tables take their memory at their first
    /// row, each place past the dial role's free. Refused when the allocator has no room for its
    /// rows, which it takes here, at the open, whole at the first mark: a face coming or going
    /// takes nothing.
    #[cfg(wz_on_use)]
    pub(super) fn counted(sets: usize) -> Result<Self, ArenaRefused> {
        #[cfg(any(feature = "listen", feature = "group"))]
        {
            let past = Self::rows_of(sets);
            let mut past_dial = PastDial::counted(past);
            for _ in 0..past {
                past_dial
                    .push(NO_FACE)
                    .map_err(|_| ArenaRefused::NoMemory {
                        bytes: core::mem::size_of::<FaceId>().saturating_mul(past),
                    })?;
            }
            Ok(Self { past_dial })
        }
        #[cfg(not(any(feature = "listen", feature = "group")))]
        {
            debug_assert_eq!(sets, 1, "a session of one face counts one set");
            Ok(Self { past_dial: [] })
        }
    }

    /// How many places the table has, the dial role's among them.
    pub(super) fn count(&self) -> usize {
        self.past_dial.len().saturating_add(1)
    }

    /// The mark of each place, the dial role's first.
    pub(super) fn marks(&self) -> impl Iterator<Item = FaceId> + '_ {
        core::iter::once(DIAL_FACE).chain(self.past_dial.iter().copied())
    }

    /// The marks of the places past the dial role's: every face that may go is named among them.
    #[cfg(all(feature = "liveliness", any(feature = "listen", feature = "group")))]
    pub(super) fn past_dial(&self) -> &[FaceId] {
        &self.past_dial
    }

    /// Whether the place `at` is held by face `id`: read at the place, with no walk.
    #[inline(always)]
    pub(super) fn holds(&self, at: usize, id: FaceId) -> bool {
        match at.checked_sub(1) {
            None => id == DIAL_FACE,
            Some(past) => self.past_dial.get(past) == Some(&id),
        }
    }

    /// Where the place face `id` holds lies: never a free or a kept place, whose mark names no
    /// face.
    pub(super) fn place_of(&self, id: FaceId) -> Option<usize> {
        if id == DIAL_FACE {
            return Some(0);
        }
        if !names_face(id) {
            return None;
        }
        let past = self.past_dial.iter().position(|holder| *holder == id)?;
        Some(past.saturating_add(1))
    }

    /// The marks of the places past the dial role's, to write: the dial role's is never written.
    pub(super) fn past_dial_mut(&mut self) -> &mut [FaceId] {
        &mut self.past_dial
    }

    /// The mark of place `at` to write, past the dial role's alone.
    #[cfg(any(
        feature = "connectivity",
        feature = "listen",
        feature = "group",
        all(test, wz_lent)
    ))]
    pub(super) fn mark_mut(&mut self, at: usize) -> Option<&mut FaceId> {
        self.past_dial.get_mut(at.checked_sub(1)?)
    }

    /// The first place no face holds and no tomb keeps.
    #[cfg(any(
        feature = "connectivity",
        feature = "listen",
        feature = "group",
        all(test, wz_lent)
    ))]
    pub(super) fn free(&self) -> Option<usize> {
        let past = self
            .past_dial
            .iter()
            .position(|holder| *holder == NO_FACE)?;
        Some(past.saturating_add(1))
    }

    /// The set at `at` among `sets`, to write, and the faces of the table's other rows.
    #[cfg(any(feature = "listen", feature = "group", all(test, wz_lent)))]
    pub(super) fn split<'a>(
        &'a self,
        sets: &'a mut [FaceTables],
        at: usize,
    ) -> Option<(&'a mut FaceTables, OtherFaces<'a>)> {
        let (dial, past) = sets.split_first_mut()?;
        let Some(at) = at.checked_sub(1) else {
            let others = Others {
                dial: None,
                before: &[],
                after: &*past,
                held_before: &[],
                held_after: &self.past_dial,
            };
            return Some((dial, others));
        };
        let (before, rest) = past.split_at_mut_checked(at)?;
        let (face, after) = rest.split_first_mut()?;
        let (held_before, rest) = self.past_dial.split_at_checked(at)?;
        let others = Others {
            dial: Some(&*dial),
            before: &*before,
            after: &*after,
            held_before,
            held_after: rest.get(1..)?,
        };
        Some((face, others))
    }

    /// See the form of a build that adds faces: the one set lies at the first place.
    #[cfg(not(any(feature = "listen", feature = "group", all(test, wz_lent))))]
    pub(super) fn split<'a>(
        &'a self,
        sets: &'a mut [FaceTables],
        at: usize,
    ) -> Option<(&'a mut FaceTables, OtherFaces<'a>)> {
        Some((sets.get_mut(at)?, NoOtherPeers))
    }
}
