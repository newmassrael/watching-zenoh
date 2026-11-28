// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A face added beside the dial role's takes a place the open reserved, its set built there when
//! the first face takes it: what a build that adds faces (`listen`, `group`) does, and the lent
//! form's registry tests. A session of its dial role's face alone holds the set the registry is
//! made with, and its text has none of this.
//!
//! Where the open lends the session's tables (`wz_lent`), it lends the dial face's set and reserves
//! the rows of every other place as one span ([`SpareSets`]), written by nothing: a set is a few
//! words for each of its tables, written where the set lies, and with `storage-profile` its peer's
//! side writes the row it composes keys in as its rows are lent, so a set built for each place at
//! the open wrote pages of the arena for faces that may never come. Where the tables take their
//! memory on use (`wz_on_use`), the table of sets took every set's row with the dial face's, and a
//! set built later is counted in its row, each of its tables taking its memory at its first row.
//! A set once built stays where it lies, emptied for the next face.

#[cfg(wz_lent)]
use super::lend_set;
use super::{names_face, FaceId, FaceTables, HeldFace, Registry};
use crate::arena::MAX_FACE_SETS;
use crate::RowPolicy;
use wz_session_core::bounded::BoundedVec;
#[cfg(wz_lent)]
use wz_session_core::bounded::{Arena, LendRefused};
#[cfg(wz_lent)]
use wz_session_core::key_arena::KeySpace;
use wz_session_core::limits::SessionLimits;
#[cfg(wz_on_use)]
use wz_session_core::on_use::BudgetKeys;
#[cfg(wz_lent)]
use wz_session_core::peer_tables::PeerPools;
use wz_session_core::peer_tables::PeerRows;
use wz_session_core::slot_observer::RequesterRows;

/// A face past the sets the open lent: the session refuses it as one past `max_faces`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::engine) struct FacesFull;

/// What builds the set of a place no face has taken yet: where the open lends the session's
/// tables, the span it reserved for the rows of every such set; and what each set is made with, as
/// the open makes the dial face's.
pub(in crate::engine) struct SpareSets {
    /// The rows of the sets still to be built, lent to each in turn as it is built.
    #[cfg(wz_lent)]
    pub(super) arena: Arena,
    /// The session's key arena, which a set's tables keep their keys in.
    #[cfg(wz_lent)]
    keys: KeySpace,
    /// The session's key budget, which a set's tables count their keys against.
    #[cfg(wz_on_use)]
    keys: BudgetKeys,
    /// The session's pools of what its peers write by their own choice, which every set keeps its
    /// rows in.
    #[cfg(wz_lent)]
    pub(super) pools: PeerPools,
    /// The rows of each set's gets.
    gets: RequesterRows,
    /// The rows of each set's peer tables.
    peer: PeerRows,
    /// The session limits a set's tables are held to.
    limits: SessionLimits,
}

impl SpareSets {
    /// The reserve of `spare` sets of `gets` and `peer` rows each, its span lent from `arena`
    /// whole now and written by none of this, each set's keys kept in `keys` and what its peer
    /// writes in `pools`, held to `limits`. Refused when the arena has not the span, which one
    /// reserved by the plan that counts the sets always has.
    #[cfg(wz_lent)]
    pub(super) fn reserved(
        arena: &mut Arena,
        keys: KeySpace,
        pools: PeerPools,
        gets: RequesterRows,
        peer: PeerRows,
        limits: SessionLimits,
        spare: usize,
    ) -> Result<Self, LendRefused> {
        // The span of one set, as `lend_set` lends it: its description's lines and its peer's row
        // to compose keys in.
        let one = FaceTables::arena_bytes(gets, peer);
        let arena = arena.split_off(one.and_then(|one| one.checked_mul(spare)))?;
        Ok(Self {
            arena,
            keys,
            pools,
            gets,
            peer,
            limits,
        })
    }

    /// What builds each set to come of `gets` and `peer` rows, counted and taking its memory at
    /// its first row, each set's keys counted against `keys`, held to `limits`. Takes nothing:
    /// the rows of the sets were counted with the table of sets.
    #[cfg(wz_on_use)]
    pub(super) fn counted(
        keys: BudgetKeys,
        gets: RequesterRows,
        peer: PeerRows,
        limits: SessionLimits,
    ) -> Self {
        Self {
            keys,
            gets,
            peer,
            limits,
        }
    }

    /// Build the next set at the end of `sets`, its rows lent from the reserve. Refused when the
    /// reserve or `sets` has no room left; a set refused its rows stays in `sets`, whole.
    #[cfg(wz_lent)]
    fn build(
        &mut self,
        sets: &mut BoundedVec<FaceTables, MAX_FACE_SETS, RowPolicy>,
    ) -> Result<(), FacesFull> {
        lend_set(
            sets,
            &mut self.arena,
            self.keys,
            &mut self.pools,
            self.gets,
            self.peer,
            &self.limits,
        )
        .map_err(|_| FacesFull)
    }

    /// Build the next set at the end of `sets`, its tables counted in the row it lies in. Refused
    /// when `sets` has no row left.
    #[cfg(wz_on_use)]
    fn build(
        &mut self,
        sets: &mut BoundedVec<FaceTables, MAX_FACE_SETS, RowPolicy>,
    ) -> Result<(), FacesFull> {
        super::counted::count_set(sets, self.keys, self.gets, self.peer, &self.limits)
            .ok_or(FacesFull)
    }
}

impl Registry {
    /// Tables for a face that has come: those at the first place no face holds and no tomb keeps,
    /// empty, as its peer has said nothing yet, built there first when no face took the place
    /// before; the key of the face, whose place its link and its room keep as well. [`FacesFull`]
    /// when every place is held: the open reserved one for each face the config admits, so the
    /// session refuses such a face before it comes.
    pub(in crate::engine) fn add_face(&mut self, id: FaceId) -> Result<HeldFace, FacesFull> {
        debug_assert!(names_face(id), "no face is numbered as a free or kept row");
        // The table of places has a mark for each place the open reserved, so its first free mark
        // is the first free place.
        let at = self.holders.free().ok_or(FacesFull)?;
        // A face whose tokens would find no row to be owed in as it goes is refused here, before
        // anything is built for it.
        #[cfg(all(feature = "liveliness", any(feature = "listen", feature = "group")))]
        if !self.owed.admits_face(self.holders.past_dial()) {
            return Err(FacesFull);
        }
        self.build_to(at)?;
        let holder = self.holders.mark_mut(at).ok_or(FacesFull)?;
        *holder = id;
        self.writing();
        Ok(HeldFace::new(at, id))
    }

    /// Build the set of every place up to `at` that has none, in place order: a place a tomb kept
    /// before any face took it is passed on the way. The index of the gets' deadlines is rebuilt
    /// over the sets when any was built, a refused one among them.
    fn build_to(&mut self, at: usize) -> Result<(), FacesFull> {
        let before = self.sets.len();
        let mut built = Ok(());
        while built.is_ok() && self.sets.len() <= at {
            built = self.spares.build(&mut self.sets);
        }
        if self.sets.len() != before {
            self.reindex_dues();
        }
        built
    }
}
