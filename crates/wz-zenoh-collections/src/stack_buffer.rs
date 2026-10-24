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
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh-collections 1.10.1, file
// src/stack_buffer.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.1).

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
