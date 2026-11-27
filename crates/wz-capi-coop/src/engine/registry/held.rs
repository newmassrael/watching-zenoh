// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Which face holds each set of a session's face tables, by the set's place, in the two forms a
//! build may take: a session that adds faces beside its dial role's (`listen`, `group`) keeps an
//! index lent from its arena ([`ManyHolders`]); one of its dial role's face alone knows that face
//! holds the first set and no other face is held ([`OneHolder`]), and lends no index. The registry
//! is written once over [`Holders`], so its tests build either form whatever the build.

#[cfg(any(feature = "runtime-plan", not(feature = "tables-on-use")))]
use super::described::HELD_LINES;
use super::{FaceId, FaceTables, DIAL_FACE};
#[cfg(feature = "runtime-plan")]
use wz_session_core::bounded::LendRefused;
#[cfg(any(feature = "runtime-plan", not(feature = "tables-on-use")))]
use wz_session_core::bounded::RegionLines;
use wz_session_core::slot_observer::OtherPeers;

#[cfg(any(
    feature = "listen",
    feature = "group",
    all(test, feature = "runtime-plan")
))]
use super::{Others, NO_FACE};
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
use wz_session_core::bounded::{BoundedVec, Lent, RowCount, SeqPlace};

#[cfg(any(not(any(feature = "listen", feature = "group")), test))]
use wz_session_core::slot_observer::NoOtherPeers;

/// The index of held sets: a row for each set, naming the face that holds it, `NO_FACE` for a
/// free set and `KEPT` for one a departed face's tomb keeps.
pub(in crate::engine) trait Holders: Sized {
    /// The faces other than the one a call acts on, which the matching verdicts of that call
    /// count.
    type Others<'a>: OtherPeers
    where
        Self: 'a;

    /// The index's lines in the registry's description, from where the registry keeps the index: a
    /// row for each set, lent `RowCount::FaceSets`, where the form keeps an index, and none where
    /// the one set's holder is known when compiled.
    #[cfg(any(feature = "runtime-plan", not(feature = "tables-on-use")))]
    const LINES: RegionLines<HELD_LINES>;

    /// The index before the registry's walk lends it its rows (`RegistryOf::new`): of no row.
    #[cfg(feature = "runtime-plan")]
    fn rowless() -> Self;

    /// Name the holder of each of `sets` sets in the rows the walk lent the index, where the form
    /// keeps one: the dial role's face holds the first set, and every other is free. Refused when
    /// the index was lent fewer rows, which the walk has refused first.
    #[cfg(feature = "runtime-plan")]
    fn hold_sets(&mut self, sets: usize) -> Result<(), LendRefused>;

    /// The face of each set, by the set's place.
    fn rows(&self) -> &[FaceId];

    /// The rows a call may write: a set's that a face other than the dial role's may take.
    fn rows_mut(&mut self) -> &mut [FaceId];

    /// The set at `at` among `sets`, to write, and the others beside it.
    fn split<'a>(
        &'a self,
        sets: &'a mut [FaceTables],
        at: usize,
    ) -> Option<(&'a mut FaceTables, Self::Others<'a>)>;
}

/// The index of a session that adds faces beside its dial role's: a row for each set the open
/// lent, lent from the arena with them (`crate::arena::ArenaPart::HeldFaces`), so a face coming
/// or going writes its set's row and moves none.
#[cfg(any(
    feature = "listen",
    feature = "group",
    all(test, feature = "runtime-plan")
))]
pub(in crate::engine) struct ManyHolders(BoundedVec<FaceId, MAX_FACE_SETS, Lent>);

#[cfg(any(
    feature = "listen",
    feature = "group",
    all(test, feature = "runtime-plan")
))]
impl Holders for ManyHolders {
    type Others<'a>
        = Others<'a>
    where
        Self: 'a;

    #[cfg(any(feature = "runtime-plan", not(feature = "tables-on-use")))]
    const LINES: RegionLines<HELD_LINES> = RegionLines::EMPTY.seq(
        SeqPlace::of::<FaceId>(core::mem::offset_of!(Self, 0), 0, MAX_FACE_SETS)
            .counted(RowCount::FaceSets),
    );

    #[cfg(feature = "runtime-plan")]
    fn rowless() -> Self {
        Self(BoundedVec::default())
    }

    #[cfg(feature = "runtime-plan")]
    fn hold_sets(&mut self, sets: usize) -> Result<(), LendRefused> {
        let faces = core::iter::once(DIAL_FACE).chain(core::iter::repeat(NO_FACE));
        for holder in faces.take(sets) {
            self.0.push(holder).map_err(|_| LendRefused::OverCeiling {
                rows: 1,
                ceiling: 0,
            })?;
        }
        Ok(())
    }

    fn rows(&self) -> &[FaceId] {
        &self.0
    }

    fn rows_mut(&mut self) -> &mut [FaceId] {
        &mut self.0
    }

    fn split<'a>(
        &'a self,
        sets: &'a mut [FaceTables],
        at: usize,
    ) -> Option<(&'a mut FaceTables, Others<'a>)> {
        let (before, rest) = sets.split_at_mut_checked(at)?;
        let (face, after) = rest.split_first_mut()?;
        let (held_before, rest) = self.rows().split_at_checked(at)?;
        let others = Others {
            before: &*before,
            after: &*after,
            held_before,
            held_after: rest.get(1..)?,
        };
        Some((face, others))
    }
}

/// The index of a session of its dial role's face alone: that face holds the first set, which the
/// open lends whether the session dials or not, and no other face is ever held, so the index is
/// known when compiled and the arena lends none. Its one row is never written, so a call that
/// would free or keep a set finds none to write.
#[cfg(any(not(any(feature = "listen", feature = "group")), test))]
pub(in crate::engine) struct OneHolder;

#[cfg(any(not(any(feature = "listen", feature = "group")), test))]
impl Holders for OneHolder {
    type Others<'a>
        = NoOtherPeers
    where
        Self: 'a;

    #[cfg(any(feature = "runtime-plan", not(feature = "tables-on-use")))]
    const LINES: RegionLines<HELD_LINES> = RegionLines::EMPTY;

    #[cfg(feature = "runtime-plan")]
    fn rowless() -> Self {
        Self
    }

    #[cfg(feature = "runtime-plan")]
    fn hold_sets(&mut self, sets: usize) -> Result<(), LendRefused> {
        debug_assert_eq!(sets, 1, "a session of one face is lent one set");
        Ok(())
    }

    fn rows(&self) -> &[FaceId] {
        &[DIAL_FACE]
    }

    fn rows_mut(&mut self) -> &mut [FaceId] {
        &mut []
    }

    fn split<'a>(
        &'a self,
        sets: &'a mut [FaceTables],
        at: usize,
    ) -> Option<(&'a mut FaceTables, NoOtherPeers)> {
        Some((sets.get_mut(at)?, NoOtherPeers))
    }
}
