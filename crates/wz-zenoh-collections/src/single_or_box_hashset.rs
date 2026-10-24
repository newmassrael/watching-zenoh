//
// Copyright (c) 2025 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh-collections 1.10.1, file
// src/single_or_box_hashset.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.1).

//! A set that holds nothing, one element in place, or a boxed hash set from the second element.

use core::{borrow::Borrow, mem};
use std::{collections::hash_set, fmt, hash::Hash};

/// A set whose first element costs no allocation, and whose hash set, once there are two, is behind
/// a box so that the set is as large as one element and a tag.
#[allow(clippy::box_collection)]
pub enum SingleOrBoxHashSet<T> {
    Empty,
    Single(T),
    Set(Box<ahash::HashSet<T>>),
}

impl<T> Default for SingleOrBoxHashSet<T>
where
    T: Eq + Hash,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T> fmt::Debug for SingleOrBoxHashSet<T>
where
    T: fmt::Debug + Eq + Hash,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}

impl<T> SingleOrBoxHashSet<T>
where
    T: Eq + Hash,
{
    #[inline]
    pub fn new() -> Self {
        SingleOrBoxHashSet::Empty
    }

    /// Adds the value; false if the set already had it, in which case the set keeps the value it
    /// had, as a hash set does (upstream keeps it when the set is a hash set and replaces it
    /// when the set holds one element).
    #[inline]
    pub fn insert(&mut self, v: T) -> bool {
        match self {
            SingleOrBoxHashSet::Empty => {
                *self = SingleOrBoxHashSet::Single(v);
                true
            }
            SingleOrBoxHashSet::Single(single) => {
                if *single == v {
                    return false;
                }
                // Two elements: the one held, and the new one.
                if let SingleOrBoxHashSet::Single(first) = mem::take(self) {
                    let mut set = Box::<ahash::HashSet<T>>::default();
                    set.insert(first);
                    set.insert(v);
                    *self = SingleOrBoxHashSet::Set(set);
                }
                true
            }
            SingleOrBoxHashSet::Set(set) => {
                if set.is_empty() {
                    *self = SingleOrBoxHashSet::Single(v);
                    true
                } else {
                    set.insert(v)
                }
            }
        }
    }

    pub fn contains<Q>(&self, v: &Q) -> bool
    where
        T: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        match self {
            SingleOrBoxHashSet::Empty => false,
            SingleOrBoxHashSet::Single(single) => Borrow::<Q>::borrow(single) == v,
            SingleOrBoxHashSet::Set(set) => set.contains(v),
        }
    }

    pub fn is_disjoint(&self, other: &SingleOrBoxHashSet<T>) -> bool {
        if self.len() <= other.len() {
            self.iter().all(|v| !other.contains(v))
        } else {
            other.iter().all(|v| !self.contains(v))
        }
    }

    pub fn is_subset(&self, other: &SingleOrBoxHashSet<T>) -> bool {
        if self.len() <= other.len() {
            self.iter().all(|v| other.contains(v))
        } else {
            false
        }
    }

    #[inline]
    pub fn is_superset(&self, other: &SingleOrBoxHashSet<T>) -> bool {
        other.is_subset(self)
    }

    #[inline]
    pub fn get<Q>(&self, v: &Q) -> Option<&T>
    where
        T: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        match self {
            SingleOrBoxHashSet::Empty => None,
            SingleOrBoxHashSet::Single(single) => {
                (Borrow::<Q>::borrow(single) == v).then_some(single)
            }
            SingleOrBoxHashSet::Set(set) => set.get(v),
        }
    }

    /// Whether the set has no element, whichever form it is in.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    pub fn len(&self) -> usize {
        match self {
            SingleOrBoxHashSet::Empty => 0,
            SingleOrBoxHashSet::Single(_) => 1,
            SingleOrBoxHashSet::Set(set) => set.len(),
        }
    }

    #[inline]
    pub fn iter(&self) -> Iter<'_, T> {
        match self {
            SingleOrBoxHashSet::Empty => Iter::Empty,
            SingleOrBoxHashSet::Single(single) => Iter::Single(single),
            SingleOrBoxHashSet::Set(set) => Iter::SetIter(set.iter()),
        }
    }

    /// Adds the value, replacing and returning the element the set had that is equal to it.
    pub fn replace(&mut self, v: T) -> Option<T> {
        match self {
            SingleOrBoxHashSet::Empty => {
                *self = SingleOrBoxHashSet::Single(v);
                None
            }
            SingleOrBoxHashSet::Single(single) => {
                if *single == v {
                    Some(mem::replace(single, v))
                } else {
                    self.insert(v);
                    None
                }
            }
            SingleOrBoxHashSet::Set(set) => set.replace(v),
        }
    }

    /// Removes the value; a hash set that is left with one element becomes that element.
    #[inline]
    pub fn remove<Q>(&mut self, v: &Q) -> bool
    where
        T: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        match self {
            SingleOrBoxHashSet::Empty => false,
            SingleOrBoxHashSet::Single(single) => {
                if Borrow::<Q>::borrow(single) == v {
                    *self = SingleOrBoxHashSet::Empty;
                    true
                } else {
                    false
                }
            }
            SingleOrBoxHashSet::Set(set) => {
                let removed = set.remove(v);
                // The element that is left, taken out before the set is replaced by it.
                let rest = if set.len() == 1 {
                    set.drain().next()
                } else {
                    None
                };
                if let Some(rest) = rest {
                    *self = SingleOrBoxHashSet::Single(rest);
                }
                removed
            }
        }
    }

    /// Removes every element and yields them. The set is empty at once, whether or not what is
    /// yielded is read (upstream leaves an empty hash set behind, which it does not call empty).
    #[inline]
    pub fn drain(&mut self) -> impl Iterator<Item = T> + '_ {
        mem::take(self).into_iter()
    }

    #[inline]
    pub fn clear(&mut self) {
        *self = SingleOrBoxHashSet::Empty;
    }
}

impl<T> PartialEq for SingleOrBoxHashSet<T>
where
    T: Eq + Hash,
{
    fn eq(&self, other: &SingleOrBoxHashSet<T>) -> bool {
        if self.len() != other.len() {
            return false;
        }

        self.iter().all(|key| other.contains(key))
    }
}

impl<T> Eq for SingleOrBoxHashSet<T> where T: Eq + Hash {}

impl<T> FromIterator<T> for SingleOrBoxHashSet<T>
where
    T: Eq + Hash,
{
    #[inline]
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> SingleOrBoxHashSet<T> {
        let mut set = SingleOrBoxHashSet::default();
        set.extend(iter);
        set
    }
}

impl<T> Extend<T> for SingleOrBoxHashSet<T>
where
    T: Eq + Hash,
{
    #[inline]
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        for i in iter {
            self.insert(i);
        }
    }
}

impl<'a, T> Extend<&'a T> for SingleOrBoxHashSet<T>
where
    T: 'a + Eq + Hash + Copy,
{
    #[inline]
    fn extend<I: IntoIterator<Item = &'a T>>(&mut self, iter: I) {
        self.extend(iter.into_iter().cloned());
    }
}

/// The elements of a [`SingleOrBoxHashSet`] by reference.
#[derive(Debug)]
pub enum Iter<'a, T> {
    Empty,
    Single(&'a T),
    SetIter(hash_set::Iter<'a, T>),
}

impl<'a, T> Iterator for Iter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Iter::Empty => None,
            Iter::Single(_) => match mem::replace(self, Iter::Empty) {
                Iter::Single(single) => Some(single),
                _ => None,
            },
            Iter::SetIter(iter) => iter.next(),
        }
    }
}

/// The elements of a [`SingleOrBoxHashSet`] by value.
#[derive(Debug)]
pub enum IntoIter<T> {
    Empty,
    Single(T),
    Set(hash_set::IntoIter<T>),
}

impl<T> Iterator for IntoIter<T> {
    type Item = T;
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            IntoIter::Empty | IntoIter::Single(_) => match mem::replace(self, IntoIter::Empty) {
                IntoIter::Single(single) => Some(single),
                _ => None,
            },
            IntoIter::Set(set) => set.next(),
        }
    }
}

impl<'a, T> IntoIterator for &'a SingleOrBoxHashSet<T>
where
    T: Eq + Hash,
{
    type Item = &'a T;
    type IntoIter = Iter<'a, T>;

    #[inline]
    fn into_iter(self) -> Iter<'a, T> {
        self.iter()
    }
}

impl<T> IntoIterator for SingleOrBoxHashSet<T> {
    type Item = T;
    type IntoIter = IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            SingleOrBoxHashSet::Empty => IntoIter::Empty,
            SingleOrBoxHashSet::Single(first) => IntoIter::Single(first),
            SingleOrBoxHashSet::Set(set) => IntoIter::Set(set.into_iter()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_set_is_empty_then_one_element_then_a_hash_set_and_back() {
        let mut s = SingleOrBoxHashSet::new();
        assert!(s.is_empty() && !s.contains(&1));
        assert!(s.insert(1));
        assert!(matches!(s, SingleOrBoxHashSet::Single(1)));
        assert!(!s.insert(1));
        assert!(s.insert(2) && matches!(s, SingleOrBoxHashSet::Set(_)));
        assert!(s.insert(3) && !s.insert(3));
        assert_eq!(s.len(), 3);
        assert!(s.remove(&1) && !s.remove(&1));
        assert!(s.remove(&2) && matches!(s, SingleOrBoxHashSet::Single(3)));
        assert!(s.remove(&3) && s.is_empty());
    }

    #[test]
    fn a_drained_set_is_empty_in_every_form() {
        let mut s: SingleOrBoxHashSet<u8> = [1, 2, 3].into_iter().collect();
        let mut taken: Vec<u8> = s.drain().collect();
        taken.sort_unstable();
        assert_eq!(taken, [1, 2, 3]);
        assert!(s.is_empty() && matches!(s, SingleOrBoxHashSet::Empty));
        assert_eq!(s.len(), 0);
        let mut one: SingleOrBoxHashSet<u8> = [9].into_iter().collect();
        drop(one.drain());
        assert!(one.is_empty());
    }

    #[test]
    fn a_duplicate_keeps_the_value_the_set_had() {
        #[derive(Debug)]
        struct Keyed(u8, &'static str);
        impl PartialEq for Keyed {
            fn eq(&self, other: &Self) -> bool {
                self.0 == other.0
            }
        }
        impl Eq for Keyed {}
        impl Hash for Keyed {
            fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
                self.0.hash(state);
            }
        }
        let mut s = SingleOrBoxHashSet::new();
        assert!(s.insert(Keyed(1, "first")));
        assert!(!s.insert(Keyed(1, "second")));
        assert_eq!(s.iter().next().unwrap().1, "first");
        assert!(s.insert(Keyed(2, "other")));
        assert!(!s.insert(Keyed(1, "third")));
        assert_eq!(s.get(&Keyed(1, "")).unwrap().1, "first");
        assert_eq!(s.replace(Keyed(1, "replaced")).unwrap().1, "first");
        assert_eq!(s.get(&Keyed(1, "")).unwrap().1, "replaced");
    }

    #[test]
    fn the_relations_between_sets() {
        let a: SingleOrBoxHashSet<u8> = [1, 2].into_iter().collect();
        let b: SingleOrBoxHashSet<u8> = [1, 2, 3].into_iter().collect();
        let c: SingleOrBoxHashSet<u8> = [7].into_iter().collect();
        assert!(a.is_subset(&b) && b.is_superset(&a) && !b.is_subset(&a));
        assert!(a.is_disjoint(&c) && !a.is_disjoint(&b));
        assert_eq!(a, [2, 1].into_iter().collect());
        assert_eq!(format!("{c:?}"), "{7}");
    }
}
