//
// Copyright (c) 2023 ZettaScale Technology
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
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh-collections 1.10.2, file
// src/single_or_vec.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2).

//! A sequence that is stored in place while it holds one element, and in a vector from the second.

use alloc::vec;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::{
    cmp::PartialEq,
    fmt, iter, mem,
    ops::{Index, IndexMut, RangeBounds},
    slice,
};

/// The two ways the elements are held. An empty sequence is an empty vector, which holds nothing
/// and has not allocated.
#[derive(Clone, Eq)]
enum SingleOrVecInner<T> {
    Single(T),
    Vec(Vec<T>),
}

impl<T> SingleOrVecInner<T> {
    const fn empty() -> Self {
        SingleOrVecInner::Vec(Vec::new())
    }

    #[inline(always)]
    fn push(&mut self, value: T) {
        // A vector that has allocated takes the element where it is.
        if let SingleOrVecInner::Vec(vec) = self {
            if vec.capacity() != 0 {
                vec.push(value);
                return;
            }
        }
        // What is left is a single element, which becomes the first of two, or an empty vector,
        // which becomes the single element.
        *self = match mem::take(self) {
            SingleOrVecInner::Single(first) => SingleOrVecInner::Vec(vec![first, value]),
            SingleOrVecInner::Vec(_) => SingleOrVecInner::Single(value),
        };
    }
}

impl<T> PartialEq for SingleOrVecInner<T>
where
    T: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl<T> Default for SingleOrVecInner<T> {
    fn default() -> Self {
        Self::empty()
    }
}

impl<T> AsRef<[T]> for SingleOrVecInner<T> {
    #[inline(always)]
    fn as_ref(&self) -> &[T] {
        match self {
            SingleOrVecInner::Single(t) => slice::from_ref(t),
            SingleOrVecInner::Vec(t) => t,
        }
    }
}

impl<T> AsMut<[T]> for SingleOrVecInner<T> {
    fn as_mut(&mut self) -> &mut [T] {
        match self {
            SingleOrVecInner::Single(t) => slice::from_mut(t),
            SingleOrVecInner::Vec(t) => t,
        }
    }
}

impl<T> fmt::Debug for SingleOrVecInner<T>
where
    T: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.as_ref())
    }
}

/// A sequence that does not allocate for its first element.
#[derive(Clone, PartialEq, Eq)]
pub struct SingleOrVec<T>(SingleOrVecInner<T>);

impl<T> SingleOrVec<T> {
    pub const fn empty() -> Self {
        Self(SingleOrVecInner::empty())
    }

    #[inline(always)]
    pub fn push(&mut self, value: T) {
        self.0.push(value);
    }

    pub fn truncate(&mut self, len: usize) {
        if let SingleOrVecInner::Vec(v) = &mut self.0 {
            v.truncate(len);
        } else if len == 0 {
            self.0 = SingleOrVecInner::Vec(Vec::new());
        }
    }

    pub fn clear(&mut self) {
        self.truncate(0);
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        match &self.0 {
            SingleOrVecInner::Single(_) => 1,
            SingleOrVecInner::Vec(v) => v.len(),
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        matches!(&self.0, SingleOrVecInner::Vec(v) if v.is_empty())
    }

    /// The elements as a vector, which a single element is turned into.
    fn vectorize(&mut self) -> &mut Vec<T> {
        let held = match mem::take(&mut self.0) {
            SingleOrVecInner::Single(value) => vec![value],
            SingleOrVecInner::Vec(vector) => vector,
        };
        self.0 = SingleOrVecInner::Vec(held);
        match &mut self.0 {
            SingleOrVecInner::Vec(vector) => vector,
            SingleOrVecInner::Single(_) => unreachable!("the elements were just put in a vector"),
        }
    }

    pub fn get(&self, index: usize) -> Option<&T> {
        match &self.0 {
            SingleOrVecInner::Single(v) => (index == 0).then_some(v),
            SingleOrVecInner::Vec(v) => v.get(index),
        }
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        match &mut self.0 {
            SingleOrVecInner::Single(v) => (index == 0).then_some(v),
            SingleOrVecInner::Vec(v) => v.get_mut(index),
        }
    }

    pub fn last(&self) -> Option<&T> {
        match &self.0 {
            SingleOrVecInner::Single(v) => Some(v),
            SingleOrVecInner::Vec(v) => v.last(),
        }
    }

    pub fn last_mut(&mut self) -> Option<&mut T> {
        match &mut self.0 {
            SingleOrVecInner::Single(v) => Some(v),
            SingleOrVecInner::Vec(v) => v.last_mut(),
        }
    }

    /// Removes the elements in the range and yields them. A single element is removed when the
    /// range contains its index, 0, and the range of a single element is not otherwise checked.
    pub fn drain<Range: RangeBounds<usize>>(&mut self, range: Range) -> Drain<'_, T> {
        match &mut self.0 {
            this @ SingleOrVecInner::Single(_) if range.contains(&0) => Drain {
                inner: DrainInner::Single(this),
            },
            SingleOrVecInner::Vec(vec) => Drain {
                inner: DrainInner::Vec(vec.drain(range)),
            },
            _ => Drain {
                inner: DrainInner::Done,
            },
        }
    }

    pub fn insert(&mut self, at: usize, value: T) {
        assert!(at <= self.len());
        self.vectorize().insert(at, value);
    }
}

#[derive(Debug)]
enum DrainInner<'a, T> {
    Vec(alloc::vec::Drain<'a, T>),
    Single(&'a mut SingleOrVecInner<T>),
    Done,
}

/// What [`SingleOrVec::drain`] yields.
#[derive(Debug)]
pub struct Drain<'a, T> {
    inner: DrainInner<'a, T>,
}

impl<T> Iterator for Drain<'_, T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.inner {
            DrainInner::Vec(drain) => drain.next(),
            DrainInner::Single(inner) => match mem::take(*inner) {
                SingleOrVecInner::Single(value) => Some(value),
                other => {
                    **inner = other;
                    None
                }
            },
            DrainInner::Done => None,
        }
    }
}

impl<T> Drop for Drain<'_, T> {
    fn drop(&mut self) {
        // A single element that was not taken out is removed all the same.
        if let DrainInner::Single(_) = self.inner {
            self.next();
        }
    }
}

impl<T> Default for SingleOrVec<T> {
    fn default() -> Self {
        Self(SingleOrVecInner::default())
    }
}

impl<T> AsRef<[T]> for SingleOrVec<T> {
    #[inline(always)]
    fn as_ref(&self) -> &[T] {
        self.0.as_ref()
    }
}

impl<T> AsMut<[T]> for SingleOrVec<T> {
    fn as_mut(&mut self) -> &mut [T] {
        self.0.as_mut()
    }
}

impl<T> fmt::Debug for SingleOrVec<T>
where
    T: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<T> IntoIterator for SingleOrVec<T> {
    type Item = T;
    type IntoIter = IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        match self.0 {
            SingleOrVecInner::Single(first) => IntoIter {
                last: Some(first),
                drain: Vec::new().into_iter(),
            },
            SingleOrVecInner::Vec(v) => {
                let mut it = v.into_iter();
                IntoIter {
                    last: it.next_back(),
                    drain: it,
                }
            }
        }
    }
}

impl<T> iter::Extend<T> for SingleOrVec<T> {
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        for value in iter {
            self.push(value);
        }
    }
}

/// The elements of a [`SingleOrVec`], first to last: all but the last come from `drain`, and the
/// last is held apart so that it is moved out last.
#[derive(Debug)]
pub struct IntoIter<T> {
    pub drain: alloc::vec::IntoIter<T>,
    pub last: Option<T>,
}

impl<T> Iterator for IntoIter<T> {
    type Item = T;
    fn next(&mut self) -> Option<Self::Item> {
        self.drain.next().or_else(|| self.last.take())
    }
}

impl<T> Index<usize> for SingleOrVec<T> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        &self.as_ref()[index]
    }
}

impl<T> IndexMut<usize> for SingleOrVec<T> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.as_mut()[index]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sequence_is_one_element_in_place_then_a_vector() {
        let mut s: SingleOrVec<u8> = SingleOrVec::empty();
        assert!(s.is_empty() && s.get(0).is_none());
        assert_eq!(s.len(), 0);
        s.push(1);
        assert!(matches!(s.0, SingleOrVecInner::Single(1)));
        s.push(2);
        s.push(3);
        assert_eq!(s.as_ref(), [1, 2, 3]);
        assert_eq!((s.get(1), s.last(), s[2]), (Some(&2), Some(&3), 3));
        *s.last_mut().unwrap() = 9;
        s[0] = 7;
        assert_eq!(format!("{s:?}"), "[7, 2, 9]");
    }

    #[test]
    fn truncating_and_inserting_move_between_the_two_forms() {
        let mut s = SingleOrVec::empty();
        s.push(5);
        s.truncate(1);
        assert_eq!(s.len(), 1);
        s.truncate(0);
        assert!(s.is_empty());
        s.push(5);
        s.insert(0, 4);
        s.insert(2, 6);
        assert_eq!(s.as_ref(), [4, 5, 6]);
        s.clear();
        assert!(s.is_empty());
    }

    #[test]
    fn a_single_element_drains_when_the_range_holds_its_index() {
        let mut s = SingleOrVec::empty();
        s.push('a');
        assert_eq!(s.drain(1..).count(), 0);
        assert_eq!(s.len(), 1);
        assert_eq!(s.drain(..).collect::<alloc::vec::Vec<_>>(), ['a']);
        assert!(s.is_empty());
        // Dropped without being read, a drain removes the element all the same.
        s.push('b');
        drop(s.drain(0..1));
        assert!(s.is_empty());
        s.extend(['x', 'y', 'z']);
        assert_eq!(s.drain(1..).collect::<alloc::vec::Vec<_>>(), ['y', 'z']);
        assert_eq!(s.as_ref(), ['x']);
    }

    #[test]
    fn the_elements_come_out_in_order_and_equality_ignores_the_form() {
        let mut s = SingleOrVec::empty();
        s.extend([1, 2, 3]);
        assert_eq!(
            s.clone().into_iter().collect::<alloc::vec::Vec<_>>(),
            [1, 2, 3]
        );
        let mut one = SingleOrVec::empty();
        one.push(1);
        let mut vector = SingleOrVec::empty();
        vector.insert(0, 1);
        assert_eq!(one, vector);
        assert_eq!(one.into_iter().collect::<alloc::vec::Vec<_>>(), [1]);
    }
}
