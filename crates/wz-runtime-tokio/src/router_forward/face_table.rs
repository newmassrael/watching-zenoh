// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The router's faces by id, and by the tier each one is held in.
//!
//! Two questions are asked of the faces. Which face is this id, by every message for the face it
//! came from and the faces it goes to, and which faces does this tier hold, by every fan-out of a
//! message or a declaration into one tier. A map by id answers the first in one lookup and the
//! second only by trying every face, so a router holding 2,048 client faces visited all of them
//! for each Put a client sent, to find the mesh faces of the tier it re-forwards into
//! (`docs/router-table-snapshots.md`, section 6.6). The table keeps both: the map by id, and for
//! each tier the set of its faces' ids, and the two change together in [`insert`](FaceTable::insert)
//! and [`remove`](FaceTable::remove), the only writers of the set, so the set cannot hold a face the
//! map does not or miss one it does.
//!
//! Both are persistent ([`PersistentMap`], [`PersistentSet`]): under the `snapshot` value of the
//! `routing-table-sharing` policy a version of the tables shares them with its readers, and a
//! write of one face copies the path to it and not the whole map.
//!
//! A face's tier is fixed when it is inserted: nothing writes `RouterFaceState::tier` afterwards,
//! and [`get_mut`](FaceTable::get_mut) is for the face's other facts. A face that changes tier is
//! removed and inserted again.

use super::*;
use crate::persistent_map::{Iter, PersistentSet};
use std::ops::Index;

/// The router's faces by id and by tier.
#[derive(Clone, Default)]
pub(super) struct FaceTable {
    /// Every face, by id.
    all: PersistentMap<FaceId, Arc<RouterFaceState>>,
    /// The ids of the faces of each tier.
    by_tier: RegionMap<PersistentSet<FaceId>>,
}

impl FaceTable {
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// The face `id`.
    pub(super) fn get(&self, id: &FaceId) -> Option<&Arc<RouterFaceState>> {
        self.all.get(id)
    }

    /// The face `id`, for writing any fact of it but its tier (see the module).
    pub(super) fn get_mut(&mut self, id: &FaceId) -> Option<&mut Arc<RouterFaceState>> {
        self.all.get_mut(id)
    }

    pub(super) fn contains_key(&self, id: &FaceId) -> bool {
        self.all.contains_key(id)
    }

    pub(super) fn is_empty(&self) -> bool {
        self.all.is_empty()
    }

    /// Every face with its id, in no stated order.
    pub(super) fn iter(&self) -> Iter<'_, FaceId, Arc<RouterFaceState>> {
        self.all.iter()
    }

    /// Every face, in no stated order.
    pub(super) fn values(&self) -> impl Iterator<Item = &Arc<RouterFaceState>> + '_ {
        self.all.values()
    }

    /// The faces of `tier` with their ids, in no stated order. Its cost is the faces of the tier,
    /// not the faces the router holds.
    pub(super) fn of_tier(
        &self,
        tier: Region,
    ) -> impl Iterator<Item = (FaceId, &Arc<RouterFaceState>)> + '_ {
        self.by_tier.get(&tier).into_iter().flat_map(move |ids| {
            ids.iter().map(move |id| {
                let state = self.all.get(id).expect(
                    "a face of a tier is a face of the table (insert and remove keep both)",
                );
                (*id, state)
            })
        })
    }

    /// Hold `state` as face `id`, in the tier it names; the face `id` held before, if any, leaves
    /// its tier.
    pub(super) fn insert(
        &mut self,
        id: FaceId,
        state: Arc<RouterFaceState>,
    ) -> Option<Arc<RouterFaceState>> {
        let tier = state.tier;
        let before = self.all.insert(id, state);
        if let Some(before) = &before {
            self.leave_tier(id, before.tier);
        }
        match self.by_tier.get_mut(&tier) {
            Some(ids) => {
                ids.insert(id);
            }
            None => {
                let mut ids = PersistentSet::default();
                ids.insert(id);
                self.by_tier.insert(tier, ids);
            }
        }
        before
    }

    /// Let face `id` go, from the table and from its tier.
    pub(super) fn remove(&mut self, id: &FaceId) -> Option<Arc<RouterFaceState>> {
        let state = self.all.remove(id)?;
        self.leave_tier(*id, state.tier);
        Some(state)
    }

    fn leave_tier(&mut self, id: FaceId, tier: Region) {
        if let Some(ids) = self.by_tier.get_mut(&tier) {
            ids.remove(&id);
        }
    }
}

/// `faces[&id]`, as a map's: the face `id` holds, and a panic for one it does not.
impl Index<&FaceId> for FaceTable {
    type Output = Arc<RouterFaceState>;

    fn index(&self, id: &FaceId) -> &Arc<RouterFaceState> {
        self.get(id).expect("the table holds the face")
    }
}
