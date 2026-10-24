// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A bounded stack.

use std::collections::VecDeque;

/// A last-in first-out stack that takes no more than its capacity: `push` refuses an element when
/// it is full and hands it back.
///
/// Its capacity is the one its storage reports, which is the capacity asked for at construction.
#[derive(Debug)]
pub struct StackBuffer<T> {
    buffer: VecDeque<T>,
}

impl<T> StackBuffer<T> {
    #[must_use]
    pub fn new(capacity: usize) -> StackBuffer<T> {
        let buffer = VecDeque::<T>::with_capacity(capacity);
        StackBuffer { buffer }
    }

    /// Puts the element on top unless the stack is full, in which case it is handed back.
    #[inline]
    pub fn push(&mut self, elem: T) -> Option<T> {
        if self.len() < self.capacity() {
            self.buffer.push_front(elem);
            None
        } else {
            Some(elem)
        }
    }

    /// Removes and returns the top element.
    #[inline]
    pub fn pop(&mut self) -> Option<T> {
        self.buffer.pop_front()
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
        self.buffer.len()
    }

    #[inline]
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.buffer.capacity()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_last_element_in_is_the_first_out_and_a_full_stack_refuses() {
        let mut s = StackBuffer::new(2);
        assert_eq!((s.push(1), s.push(2), s.push(3)), (None, None, Some(3)));
        assert!(s.is_full() && s.len() == 2);
        assert_eq!((s.pop(), s.pop(), s.pop()), (Some(2), Some(1), None));
        assert!(s.is_empty());
    }
}
