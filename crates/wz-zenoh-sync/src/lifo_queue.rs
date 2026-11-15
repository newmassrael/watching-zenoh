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
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh-sync 1.10.2, file
// src/lifo_queue.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2).
use std::sync::{Condvar, Mutex};

use zenoh_collections::StackBuffer;
use zenoh_core::zlock;

#[derive(Debug)]
pub struct LifoQueue<T> {
    not_empty: Condvar,
    not_full: Condvar,
    buffer: Mutex<StackBuffer<T>>,
}

impl<T> LifoQueue<T> {
    pub fn new(capacity: usize) -> LifoQueue<T> {
        LifoQueue {
            not_empty: Condvar::new(),
            not_full: Condvar::new(),
            buffer: Mutex::new(StackBuffer::new(capacity)),
        }
    }

    pub fn try_push(&self, x: T) -> Option<T> {
        if let Ok(mut guard) = self.buffer.try_lock() {
            let res = guard.push(x);
            if res.is_none() {
                drop(guard);
                self.not_empty.notify_one();
            }
            return res;
        }
        Some(x)
    }

    pub fn push(&self, x: T) {
        let mut guard = zlock!(self.buffer);
        loop {
            if !guard.is_full() {
                guard.push(x);
                drop(guard);
                self.not_empty.notify_one();
                return;
            }
            guard = self.not_full.wait(guard).unwrap();
        }
    }

    pub fn try_pull(&self) -> Option<T> {
        if let Ok(mut guard) = self.buffer.try_lock() {
            if let Some(e) = guard.pop() {
                drop(guard);
                self.not_full.notify_one();
                return Some(e);
            }
        }
        None
    }

    pub fn pull(&self) -> T {
        let mut guard = zlock!(self.buffer);
        loop {
            if let Some(e) = guard.pop() {
                drop(guard);
                self.not_full.notify_one();
                return e;
            }
            guard = self.not_empty.wait(guard).unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::LifoQueue;

    #[test]
    fn the_last_value_pushed_is_the_first_pulled_and_a_full_queue_gives_the_value_back() {
        let queue = LifoQueue::new(2);
        assert_eq!(queue.try_push(1), None);
        assert_eq!(queue.try_push(2), None);
        assert_eq!(queue.try_push(3), Some(3));
        assert_eq!(queue.pull(), 2);
        assert_eq!(queue.try_pull(), Some(1));
        assert_eq!(queue.try_pull(), None);
    }
}
