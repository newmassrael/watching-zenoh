// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A face added beside the dial role's takes a set the open lent: what a build that adds faces
//! (`listen`, `group`) does, and the registry's tests. A session of its dial role's face alone
//! holds the set the registry is made with, and its text has none of this.

use super::held::{Holders, ManyHolders};
use super::{names_face, FaceId, HeldFace, RegistryOf, NO_FACE};

/// A face past the sets the open lent: the session refuses it as one past `max_faces`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::engine) struct FacesFull;

impl RegistryOf<ManyHolders> {
    /// Tables for a face that has come: the first set the arena lent that no face holds and no
    /// tomb keeps, empty, as its peer has said nothing yet; the key of the face, whose place its
    /// link and its room keep as well. [`FacesFull`] when every set is held: the open lent one
    /// for each face the config admits, so the session refuses such a face before it comes.
    pub(in crate::engine) fn add_face(&mut self, id: FaceId) -> Result<HeldFace, FacesFull> {
        debug_assert!(names_face(id), "no face is numbered as a free or kept row");
        // The index has a row for each set the open lent, so its first free row is the first
        // free set.
        let at = self
            .holders
            .rows()
            .iter()
            .position(|holder| *holder == NO_FACE)
            .ok_or(FacesFull)?;
        let holder = self.holders.rows_mut().get_mut(at).ok_or(FacesFull)?;
        *holder = id;
        self.writing();
        Ok(HeldFace::new(at, id))
    }
}
