// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A face added beside the dial role's takes a place the open reserved, its set built there when
//! the first face takes it: what a build that adds faces (`listen`, `group`) does, and the
//! registry's tests. A session of its dial role's face alone holds the set the registry is made
//! with, and its text has none of this.
//!
//! The open lends the dial face's set and reserves the rows of every other place as one span
//! ([`SpareSets`]), written by nothing: a set is a few words for each of its tables, written where
//! the set lies, and with `storage-profile` its peer's side writes the row it composes keys in as
//! its rows are lent, so a set built for each place at the open wrote pages of the arena for faces
//! that may never come. A set once built stays where it lies, emptied for the next face.

use super::held::{Holders, ManyHolders};
use super::{lend_set, names_face, FaceId, FaceTables, Gets, HeldFace, Peer, RegistryOf, NO_FACE};
use crate::arena::MAX_FACE_SETS;
use crate::RowPolicy;
use wz_session_core::bounded::{Arena, BoundedVec, LendRefused};
use wz_session_core::key_arena::KeySpace;
use wz_session_core::limits::SessionLimits;
use wz_session_core::peer_tables::{PeerPools, PeerRows};
use wz_session_core::slot_observer::RequesterRows;

/// A face past the sets the open lent: the session refuses it as one past `max_faces`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::engine) struct FacesFull;

/// What builds the set of a place no face has taken yet: the span the open reserved for the rows
/// of every such set, and what each set is lent with, as the open lends the dial face's.
pub(in crate::engine) struct SpareSets {
    /// The rows of the sets not built yet, lent to each in turn as it is built.
    pub(super) arena: Arena,
    /// The session's key arena, which a set's tables keep their keys in.
    keys: KeySpace,
    /// The session's pools of what its peers write by their own choice, which every set keeps its
    /// rows in.
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
    pub(super) fn reserved(
        arena: &mut Arena,
        keys: KeySpace,
        pools: PeerPools,
        gets: RequesterRows,
        peer: PeerRows,
        limits: SessionLimits,
        spare: usize,
    ) -> Result<Self, LendRefused> {
        // The span of one set, as `lend_set` lends it and the plan counts it.
        let one = match (Gets::arena_bytes(gets), Peer::arena_bytes(peer)) {
            (Some(gets), Some(peer)) => gets.checked_add(peer),
            _ => None,
        };
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

    /// Build the next set at the end of `sets`, its rows lent from the reserve. Refused when the
    /// reserve or `sets` has no room left; a set refused its rows stays in `sets`, whole.
    fn build(
        &mut self,
        sets: &mut BoundedVec<FaceTables, MAX_FACE_SETS, RowPolicy>,
    ) -> Result<(), LendRefused> {
        lend_set(
            sets,
            &mut self.arena,
            self.keys,
            &mut self.pools,
            self.gets,
            self.peer,
            &self.limits,
        )
    }
}

impl RegistryOf<ManyHolders> {
    /// Tables for a face that has come: those at the first place no face holds and no tomb keeps,
    /// empty, as its peer has said nothing yet, built there first when no face took the place
    /// before; the key of the face, whose place its link and its room keep as well. [`FacesFull`]
    /// when every place is held: the open reserved one for each face the config admits, so the
    /// session refuses such a face before it comes.
    pub(in crate::engine) fn add_face(&mut self, id: FaceId) -> Result<HeldFace, FacesFull> {
        debug_assert!(names_face(id), "no face is numbered as a free or kept row");
        // The index has a row for each place the open reserved, so its first free row is the first
        // free place.
        let at = self
            .holders
            .rows()
            .iter()
            .position(|holder| *holder == NO_FACE)
            .ok_or(FacesFull)?;
        self.build_to(at).map_err(|_| FacesFull)?;
        let holder = self.holders.rows_mut().get_mut(at).ok_or(FacesFull)?;
        *holder = id;
        self.writing();
        Ok(HeldFace::new(at, id))
    }

    /// Build the set of every place up to `at` that has none, in place order: a place a tomb kept
    /// before any face took it is passed on the way. The index of the gets' deadlines is rebuilt
    /// over the sets when any was built, a refused one among them.
    fn build_to(&mut self, at: usize) -> Result<(), LendRefused> {
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
