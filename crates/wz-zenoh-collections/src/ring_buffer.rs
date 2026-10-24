// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A bounded queue that can overwrite its oldest element.

use std::collections::VecDeque;

/// A first-in first-out queue of a fixed capacity: `push` refuses an element when it is full and
/// hands it back, and `push_force` makes room by dropping out the oldest one and returning it.
#[derive(Debug)]
pub struct RingBuffer<T> {
    capacity: usize,
    len: usize,
    buffer: VecDeque<T>,
}

impl<T> RingBuffer<T> {
    #[must_use]
    pub fn new(capacity: usize) -> RingBuffer<T> {
        let buffer = VecDeque::<T>::with_capacity(capacity);
        RingBuffer {
            capacity,
            len: 0,
            buffer,
        }
    }

    /// Appends the element unless the queue is full, in which case it is handed back.
    #[inline]
    pub fn push(&mut self, elem: T) -> Option<T> {
        if self.len < self.capacity {
            self.buffer.push_back(elem);
            self.len += 1;
            return None;
        }
        Some(elem)
    }

    /// Appends the element; when the queue is full, the oldest element is removed and returned.
    ///
    /// A queue of capacity zero has no oldest element to drop and no room for this one, so the
    /// element is handed back, as `push` does (upstream stores it, which leaves the queue holding
    /// an element while it reports a length of zero, and a later `pull` underflows the length).
    #[inline]
    pub fn push_force(&mut self, elem: T) -> Option<T> {
        if self.capacity == 0 {
            return Some(elem);
        }
        self.push(elem).and_then(|elem| {
            let ret = self.buffer.pop_front();
            self.buffer.push_back(elem);
            ret
        })
    }

    /// Removes and returns the oldest element.
    #[inline]
    pub fn pull(&mut self) -> Option<T> {
        let x = self.buffer.pop_front();
        if x.is_some() {
            self.len -= 1;
        }
        x
    }

    #[allow(dead_code)]
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    #[inline]
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.len() == self.capacity()
    }

    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_queue_refuses_and_a_forced_push_drops_the_oldest() {
        let mut q = RingBuffer::new(2);
        assert_eq!(q.push(1), None);
        assert_eq!(q.push(2), None);
        assert!(q.is_full());
        assert_eq!(q.push(3), Some(3));
        assert_eq!(q.push_force(3), Some(1));
        assert_eq!((q.pull(), q.pull(), q.pull()), (Some(2), Some(3), None));
        assert!(q.is_empty() && q.capacity() == 2);
        assert_eq!(q.len(), 0);
    }

    #[test]
    fn a_queue_of_no_room_refuses_everything() {
        let mut q = RingBuffer::new(0);
        assert_eq!(q.push(1), Some(1));
        // No room and nothing to drop out: the element comes back, and nothing is stored.
        assert_eq!(q.push_force(1), Some(1));
        assert!(q.is_empty());
        assert_eq!(q.len(), 0);
        assert_eq!(q.pull(), None);
    }
}
