// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Children stored in a vector, searched linearly: the smallest storage, for nodes with few children.

use alloc::vec::Vec;

use zenoh_result::unlikely;

use crate::keyexpr_tree::*;

/// Stores the children of a node in a [`Vec`].
#[derive(Debug)]
pub struct VecSetProvider;

impl<T: 'static> IChildrenProvider<T> for VecSetProvider {
    type Assoc = Vec<T>;
}

impl<'a, 'b, T: HasChunk> IEntry<'a, 'b, T> for Entry<'a, 'b, T> {
    fn get_or_insert_with<F: FnOnce(&'b keyexpr) -> T>(self, f: F) -> &'a mut T {
        match self {
            Entry::Vacant(vec, key) => {
                vec.push(f(key));
                vec.last_mut().unwrap()
            }
            Entry::Occupied(v) => v,
        }
    }
}

/// The entry of a chunk in a vector of children.
#[derive(Debug)]
pub enum Entry<'a, 'b, T> {
    /// There is no such child: the vector it would be pushed to, and its chunk.
    Vacant(&'a mut Vec<T>, &'b keyexpr),
    /// There is one.
    Occupied(&'a mut T),
}

impl<T: HasChunk + AsNode<T> + AsNodeMut<T> + 'static> IChildren<T> for Vec<T> {
    type Node = T;

    fn child_at(&self, chunk: &keyexpr) -> Option<&T> {
        self.iter().find(|t| unlikely(t.chunk() == chunk))
    }

    fn child_at_mut(&mut self, chunk: &keyexpr) -> Option<&mut T> {
        self.iter_mut().find(|t| unlikely(t.chunk() == chunk))
    }

    fn remove(&mut self, chunk: &keyexpr) -> Option<Self::Node> {
        let at = self.iter().position(|t| unlikely(t.chunk() == chunk))?;
        Some(self.swap_remove(at))
    }

    fn len(&self) -> usize {
        self.len()
    }

    fn is_empty(&self) -> bool {
        self.is_empty()
    }

    type Entry<'a, 'b>
        = Entry<'a, 'b, T>
    where
        Self: 'a,
        'a: 'b,
        T: 'b;

    fn entry<'a, 'b>(&'a mut self, chunk: &'b keyexpr) -> Self::Entry<'a, 'b>
    where
        Self: 'a,
        'a: 'b,
        T: 'b,
    {
        // The position is found first, so that the borrow of the search is over before the vector
        // is handed to the vacant arm.
        match self.iter().position(|t| unlikely(t.chunk() == chunk)) {
            Some(at) => Entry::Occupied(&mut self[at]),
            None => Entry::Vacant(self, chunk),
        }
    }

    type Iter<'a>
        = core::slice::Iter<'a, T>
    where
        Self: 'a;

    fn children<'a>(&'a self) -> Self::Iter<'a>
    where
        Self: 'a,
    {
        self.iter()
    }

    type IterMut<'a>
        = core::slice::IterMut<'a, T>
    where
        Self: 'a;

    fn children_mut<'a>(&'a mut self) -> Self::IterMut<'a>
    where
        Self: 'a,
    {
        self.iter_mut()
    }

    fn filter_out<F: FnMut(&mut T) -> bool>(&mut self, predicate: &mut F) {
        for i in (0..self.len()).rev() {
            if predicate(&mut self[i]) {
                self.swap_remove(i);
            }
        }
    }

    type Intersection<'a>
        = super::FilterMap<core::slice::Iter<'a, T>, super::Intersection<'a>>
    where
        Self: 'a,
        Self::Node: 'a;

    fn intersection<'a>(&'a self, key: &'a keyexpr) -> Self::Intersection<'a> {
        super::FilterMap::new(self.iter(), super::Intersection(key))
    }

    type IntersectionMut<'a>
        = super::FilterMap<core::slice::IterMut<'a, T>, super::Intersection<'a>>
    where
        Self: 'a,
        Self::Node: 'a;

    fn intersection_mut<'a>(&'a mut self, key: &'a keyexpr) -> Self::IntersectionMut<'a> {
        super::FilterMap::new(self.iter_mut(), super::Intersection(key))
    }

    type Inclusion<'a>
        = super::FilterMap<core::slice::Iter<'a, T>, super::Inclusion<'a>>
    where
        Self: 'a,
        Self::Node: 'a;

    fn inclusion<'a>(&'a self, key: &'a keyexpr) -> Self::Inclusion<'a> {
        super::FilterMap::new(self.iter(), super::Inclusion(key))
    }

    type InclusionMut<'a>
        = super::FilterMap<core::slice::IterMut<'a, T>, super::Inclusion<'a>>
    where
        Self: 'a,
        Self::Node: 'a;

    fn inclusion_mut<'a>(&'a mut self, key: &'a keyexpr) -> Self::InclusionMut<'a> {
        super::FilterMap::new(self.iter_mut(), super::Inclusion(key))
    }
}
