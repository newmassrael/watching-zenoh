// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Which face holds each set of a session's face tables, by the set's place, in the two forms a
//! build may take: a session that adds faces beside its dial role's (`listen`, `group`) keeps an
//! index of its own ([`ManyHolders`]), lent from its arena or taking its rows at its first, as the
//! session's tables take theirs; one of its dial role's face alone knows that face holds the first
//! set and no other face is held ([`OneHolder`]), and keeps no index. The registry is written once
//! over [`Holders`], so its tests build either form whatever the build.

#[cfg(not(wz_on_use))]
use super::described::HELD_LINES;
use super::{FaceId, FaceTables, DIAL_FACE};
#[cfg(wz_on_use)]
use crate::arena::ArenaRefused;
#[cfg(wz_lent)]
use wz_session_core::bounded::LendRefused;
#[cfg(not(wz_on_use))]
use wz_session_core::bounded::RegionLines;
use wz_session_core::slot_observer::OtherPeers;

#[cfg(any(feature = "listen", feature = "group", all(test, wz_lent)))]
use super::{Others, NO_FACE};
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

#[cfg(any(not(any(feature = "listen", feature = "group")), all(test, wz_lent)))]
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
    /// row for each set, lent `RowCount::HeldSets`, where the form keeps an index, and none where
    /// the one set's holder is known when compiled.
    #[cfg(not(wz_on_use))]
    const LINES: RegionLines<HELD_LINES>;

    /// The index before the registry's walk lends it its rows (`RegistryOf::new`): of no row.
    #[cfg(wz_lent)]
    fn rowless() -> Self;

    /// Name the holder of each of `sets` sets in the rows the walk lent the index, where the form
    /// keeps one: the dial role's face holds the first set, and every other is free. Refused when
    /// the index was lent fewer rows, which the walk has refused first.
    #[cfg(wz_lent)]
    fn hold_sets(&mut self, sets: usize) -> Result<(), LendRefused>;

    /// The index of `sets` sets where the session's tables take their memory at their first row:
    /// the dial role's face holds the first set, and every other is free. Refused when the
    /// allocator has no room for its rows, which it takes here, at the open.
    #[cfg(wz_on_use)]
    fn counted(sets: usize) -> Result<Self, ArenaRefused>;

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
/// counted, of the policy of the session's tables, lent from the arena with them
/// (`crate::arena::ArenaPart::HeldFaces`) or taken at the open where the tables take their memory
/// on use, so a face coming or going writes its set's row and moves none.
#[cfg(any(feature = "listen", feature = "group", all(test, wz_lent)))]
pub(in crate::engine) struct ManyHolders(BoundedVec<FaceId, MAX_FACE_SETS, RowPolicy>);

#[cfg(any(feature = "listen", feature = "group", all(test, wz_lent)))]
impl Holders for ManyHolders {
    type Others<'a>
        = Others<'a>
    where
        Self: 'a;

    #[cfg(not(wz_on_use))]
    const LINES: RegionLines<HELD_LINES> = RegionLines::EMPTY.seq(
        SeqPlace::of::<FaceId>(core::mem::offset_of!(Self, 0), 0, MAX_FACE_SETS)
            .counted(RowCount::HeldSets),
    );

    #[cfg(wz_lent)]
    fn rowless() -> Self {
        Self(BoundedVec::default())
    }

    #[cfg(wz_lent)]
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

    #[cfg(wz_on_use)]
    fn counted(sets: usize) -> Result<Self, ArenaRefused> {
        // Its rows are taken whole at the first push, the dial role's: every row is written at
        // the open, so a face coming or going takes nothing.
        let mut rows = BoundedVec::<FaceId, MAX_FACE_SETS, RowPolicy>::counted(sets);
        let faces = core::iter::once(DIAL_FACE).chain(core::iter::repeat(NO_FACE));
        for holder in faces.take(sets) {
            rows.push(holder).map_err(|_| ArenaRefused::NoMemory {
                bytes: core::mem::size_of::<FaceId>().saturating_mul(sets),
            })?;
        }
        Ok(Self(rows))
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
/// would free or keep a set finds none to write. The lent form's tests build it beside the index
/// of many faces whatever the build.
#[cfg(any(not(any(feature = "listen", feature = "group")), all(test, wz_lent)))]
pub(in crate::engine) struct OneHolder;

#[cfg(any(not(any(feature = "listen", feature = "group")), all(test, wz_lent)))]
impl Holders for OneHolder {
    type Others<'a>
        = NoOtherPeers
    where
        Self: 'a;

    #[cfg(not(wz_on_use))]
    const LINES: RegionLines<HELD_LINES> = RegionLines::EMPTY;

    #[cfg(wz_lent)]
    fn rowless() -> Self {
        Self
    }

    #[cfg(wz_lent)]
    fn hold_sets(&mut self, sets: usize) -> Result<(), LendRefused> {
        debug_assert_eq!(sets, 1, "a session of one face is lent one set");
        Ok(())
    }

    #[cfg(wz_on_use)]
    fn counted(sets: usize) -> Result<Self, ArenaRefused> {
        debug_assert_eq!(sets, 1, "a session of one face counts one set");
        Ok(Self)
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
