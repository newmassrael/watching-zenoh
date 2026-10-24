// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The ways a node can store its children, and the filters that select among them.

pub use hashmap_impl::HashMapProvider;
pub use keyed_set_impl::KeyedSetProvider;
pub use vec_set_impl::VecSetProvider;

use crate::keyexpr;

mod hashmap_impl;
mod keyed_set_impl;
mod vec_set_impl;

/// The storage of children that KeTrees use unless told otherwise.
pub type DefaultChildrenProvider = KeyedSetProvider;

/// An iterator that applies an [`IFilter`] to each item of another and keeps what it maps.
#[derive(Debug)]
pub struct FilterMap<I, F> {
    iter: I,
    filter: F,
}

impl<I, F> FilterMap<I, F> {
    fn new(iter: I, filter: F) -> Self {
        Self { iter, filter }
    }
}

/// A selection and a transformation of the items of an iterator.
pub trait IFilter<I> {
    /// What is kept.
    type O;
    /// The item mapped, or `None` to drop it.
    fn filter_map(&self, i: I) -> Option<Self::O>;
}

impl<I: Iterator, F: IFilter<<I as Iterator>::Item>> Iterator for FilterMap<I, F> {
    type Item = F::O;
    fn next(&mut self) -> Option<Self::Item> {
        for next in self.iter.by_ref() {
            if let Some(output) = self.filter.filter_map(next) {
                return Some(output);
            }
        }
        None
    }
}

/// Keeps the children whose chunk intersects a key.
#[derive(Debug)]
pub struct Intersection<'a>(pub &'a keyexpr);

impl<K: core::ops::Deref<Target = keyexpr>, V> IFilter<(&K, V)> for Intersection<'_> {
    type O = V;
    fn filter_map(&self, (k, v): (&K, V)) -> Option<Self::O> {
        self.0.intersects(k).then_some(v)
    }
}

impl<'a, T: super::HasChunk> IFilter<&'a T> for Intersection<'_> {
    type O = &'a T;
    fn filter_map(&self, t: &'a T) -> Option<Self::O> {
        self.0.intersects(t.chunk()).then_some(t)
    }
}

impl<'a, T: super::HasChunk> IFilter<&'a mut T> for Intersection<'_> {
    type O = &'a mut T;
    fn filter_map(&self, t: &'a mut T) -> Option<Self::O> {
        self.0.intersects(t.chunk()).then_some(t)
    }
}

/// Keeps the children whose chunk a key includes.
#[derive(Debug)]
pub struct Inclusion<'a>(pub &'a keyexpr);

impl<K: core::ops::Deref<Target = keyexpr>, V> IFilter<(&K, V)> for Inclusion<'_> {
    type O = V;
    fn filter_map(&self, (k, v): (&K, V)) -> Option<Self::O> {
        self.0.includes(k).then_some(v)
    }
}

impl<'a, T: super::HasChunk> IFilter<&'a T> for Inclusion<'_> {
    type O = &'a T;
    fn filter_map(&self, t: &'a T) -> Option<Self::O> {
        self.0.includes(t.chunk()).then_some(t)
    }
}

impl<'a, T: super::HasChunk> IFilter<&'a mut T> for Inclusion<'_> {
    type O = &'a mut T;
    fn filter_map(&self, t: &'a mut T) -> Option<Self::O> {
        self.0.includes(t.chunk()).then_some(t)
    }
}
