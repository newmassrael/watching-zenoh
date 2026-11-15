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
// src/fifo_queue.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2).
use tokio::sync::Mutex;
use zenoh_collections::RingBuffer;
use zenoh_core::zasynclock;

use crate::Condition;

#[derive(Debug)]
pub struct FifoQueue<T> {
    not_empty: Condition,
    not_full: Condition,
    buffer: Mutex<RingBuffer<T>>,
}

impl<T> FifoQueue<T> {
    pub fn new(capacity: usize) -> FifoQueue<T> {
        FifoQueue {
            not_empty: Condition::new(),
            not_full: Condition::new(),
            buffer: Mutex::new(RingBuffer::new(capacity)),
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

    pub async fn push(&self, x: T) {
        loop {
            let mut guard = zasynclock!(self.buffer);
            if !guard.is_full() {
                guard.push(x);
                drop(guard);
                self.not_empty.notify_one();
                return;
            }
            self.not_full.wait(guard).await;
        }
    }

    pub fn try_pull(&self) -> Option<T> {
        if let Ok(mut guard) = self.buffer.try_lock() {
            if let Some(e) = guard.pull() {
                drop(guard);
                self.not_full.notify_one();
                return Some(e);
            }
        }
        None
    }

    pub async fn pull(&self) -> T {
        loop {
            let mut guard = zasynclock!(self.buffer);
            if let Some(e) = guard.pull() {
                drop(guard);
                self.not_full.notify_one();
                return e;
            }
            self.not_empty.wait(guard).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use super::FifoQueue;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_full_queue_holds_the_push_until_a_pull_makes_room_and_keeps_the_order() {
        let queue = Arc::new(FifoQueue::new(2));
        assert_eq!(queue.try_push(1), None);
        assert_eq!(queue.try_push(2), None);
        assert_eq!(
            queue.try_push(3),
            Some(3),
            "a full queue gives the value back"
        );
        let pusher = queue.clone();
        let held = tokio::spawn(async move { pusher.push(3).await });
        assert_eq!(queue.pull().await, 1);
        tokio::time::timeout(Duration::from_secs(10), held)
            .await
            .expect("the push went through once there was room")
            .expect("the push ran");
        assert_eq!(queue.pull().await, 2);
        assert_eq!(queue.pull().await, 3);
        assert_eq!(queue.try_pull(), None);
    }
}
