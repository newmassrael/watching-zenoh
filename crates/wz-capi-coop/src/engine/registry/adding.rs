// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A face added beside the dial role's takes a set the open lent: what a build that adds faces
//! (`listen`, `group`) does, and the registry's tests. A session of its dial role's face alone
//! holds the set the registry is made with, and its text has none of this.

use super::{FaceId, HeldSet, Registry};

/// A face past the sets the open lent: the session refuses it as one past `max_faces`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::engine) struct FacesFull;

impl Registry {
    /// Tables for a face that has come: a set the arena lent that no face holds, empty, as its
    /// peer has said nothing yet. [`FacesFull`] when every set is held: the open lent one for each
    /// face the config admits, so the session refuses such a face before it comes.
    pub(in crate::engine) fn add_face(&mut self, id: FaceId) -> Result<(), FacesFull> {
        let at = self.free_set();
        if at >= self.sets.len() {
            return Err(FacesFull);
        }
        self.writing();
        let place = self
            .held
            .iter()
            .position(|held| held.at > at)
            .unwrap_or(self.held.len());
        // The index has a row for each set, and the set at `at` is free, so a row is left.
        self.held.push(HeldSet { at, id }).map_err(|_| FacesFull)?;
        if let Some(after) = self.held.get_mut(place..) {
            after.rotate_right(1);
        }
        Ok(())
    }

    /// The first set no face holds, or the place past the last set. The lent sets lie first, so
    /// the first free set is a lent one while any is.
    fn free_set(&self) -> usize {
        // The index is in set order with one entry for each held set, so the first entry whose set
        // lies past its own place in the index has a free set at that place, and with none the
        // first free set is the one past the last entry.
        self.held
            .iter()
            .enumerate()
            .position(|(place, held)| held.at != place)
            .unwrap_or(self.held.len())
    }
}
