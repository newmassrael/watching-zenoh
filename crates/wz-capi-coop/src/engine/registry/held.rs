// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Which face holds each place of the session's faces, the mark of each row of the table of
//! places: the face's id, free (`NO_FACE`) or kept for a departed face's tomb (`KEPT`). The
//! dial role's face holds the first place for the table's life, so its mark is no row of memory;
//! the rows past it are lent from the arena where the build adds faces beside the dial role's
//! (`listen`, `group`), and a build of that face alone has none, the bound of the table a
//! build limit and not a type. The other faces a matching verdict counts are the table's rows but
//! the caller's ([`OtherFaces`]): none where the table is of one row.

use super::{names_face, FaceId, FaceTables, DIAL_FACE};
#[cfg(feature = "runtime-plan")]
use wz_session_core::bounded::{Arena, LendRefused};

#[cfg(any(
    feature = "listen",
    feature = "group",
    all(test, feature = "runtime-plan")
))]
use super::Others;
#[cfg(any(
    feature = "connectivity",
    feature = "listen",
    feature = "group",
    all(test, feature = "runtime-plan")
))]
use super::NO_FACE;
#[cfg(any(
    feature = "listen",
    feature = "group",
    all(test, feature = "runtime-plan")
))]
use crate::arena::MAX_FACE_SETS;
#[cfg(any(
    feature = "listen",
    feature = "group",
    all(test, feature = "runtime-plan")
))]
use wz_session_core::bounded::{BoundedVec, Lent};

#[cfg(not(any(
    feature = "listen",
    feature = "group",
    all(test, feature = "runtime-plan")
)))]
use wz_session_core::slot_observer::NoOtherPeers;

/// The marks of the places past the dial role's, by the place less one: a row for each place the
/// open lent past it, lent from the arena with the sets (`crate::arena::ArenaPart::HeldFaces`), so
/// a face coming or going writes its place's row and moves none.
#[cfg(any(
    feature = "listen",
    feature = "group",
    all(test, feature = "runtime-plan")
))]
type PastDial = BoundedVec<FaceId, MAX_FACE_SETS, Lent>;

/// See the form of a build that adds faces: a session of its dial role's face alone has no place
/// past it.
#[cfg(not(any(
    feature = "listen",
    feature = "group",
    all(test, feature = "runtime-plan")
)))]
type PastDial = [FaceId; 0];

/// The faces other than the one a call acts on, which the matching verdicts of that call count:
/// the sets of the table's rows but the caller's that a face holds.
#[cfg(any(
    feature = "listen",
    feature = "group",
    all(test, feature = "runtime-plan")
))]
pub(super) type OtherFaces<'a> = Others<'a>;

/// See the form of a build that adds faces: the table of one row has no row but the caller's.
#[cfg(not(any(
    feature = "listen",
    feature = "group",
    all(test, feature = "runtime-plan")
)))]
pub(super) type OtherFaces<'a> = NoOtherPeers;

/// The table of the session's places, by its marks (see the module documentation).
#[derive(Default)]
pub(in crate::engine) struct HeldPlaces {
    past_dial: PastDial,
}

impl HeldPlaces {
    /// The marks of `sets` places, the rows past the dial role's lent from `arena` and free.
    /// Refused when the arena has not the rows. A session of its dial role's face alone is lent one
    /// set, and this lends nothing.
    #[cfg(feature = "runtime-plan")]
    pub(super) fn lent(arena: &mut Arena, sets: usize) -> Result<Self, LendRefused> {
        #[cfg(any(
            feature = "listen",
            feature = "group",
            all(test, feature = "runtime-plan")
        ))]
        {
            let past = sets.saturating_sub(1);
            let mut past_dial: PastDial = arena.lend(past)?;
            for _ in 0..past {
                past_dial
                    .push(NO_FACE)
                    .map_err(|_| LendRefused::OverCeiling {
                        rows: 1,
                        ceiling: 0,
                    })?;
            }
            Ok(Self { past_dial })
        }
        #[cfg(not(any(
            feature = "listen",
            feature = "group",
            all(test, feature = "runtime-plan")
        )))]
        {
            debug_assert_eq!(sets, 1, "a session of one face is lent one set");
            let _ = arena;
            Ok(Self::default())
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
        all(test, feature = "runtime-plan")
    ))]
    pub(super) fn mark_mut(&mut self, at: usize) -> Option<&mut FaceId> {
        self.past_dial.get_mut(at.checked_sub(1)?)
    }

    /// The first place no face holds and no tomb keeps.
    #[cfg(any(
        feature = "connectivity",
        feature = "listen",
        feature = "group",
        all(test, feature = "runtime-plan")
    ))]
    pub(super) fn free(&self) -> Option<usize> {
        let past = self
            .past_dial
            .iter()
            .position(|holder| *holder == NO_FACE)?;
        Some(past.saturating_add(1))
    }

    /// The set at `at` among `sets`, to write, and the faces of the table's other rows.
    #[cfg(any(
        feature = "listen",
        feature = "group",
        all(test, feature = "runtime-plan")
    ))]
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
    #[cfg(not(any(
        feature = "listen",
        feature = "group",
        all(test, feature = "runtime-plan")
    )))]
    pub(super) fn split<'a>(
        &'a self,
        sets: &'a mut [FaceTables],
        at: usize,
    ) -> Option<(&'a mut FaceTables, OtherFaces<'a>)> {
        Some((sets.get_mut(at)?, NoOtherPeers))
    }
}
