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
// src/mvar.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2). The counts of the waiting
// takers and putters are held for exactly the time a call waits; upstream's subtracts one when the
// value is taken or put, also by a call that never waited, and the count wraps.
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::Mutex;
use zenoh_core::zasynclock;

use crate::Condition;

#[derive(Debug)]
pub struct Mvar<T> {
    inner: Mutex<Option<T>>,
    cond_put: Condition,
    cond_take: Condition,
    wait_put: AtomicUsize,
    wait_take: AtomicUsize,
}

/// One call counted as waiting, for as long as it waits: dropped when the wait ends, and when the
/// future that waits is dropped before it does.
struct Waiting<'a>(&'a AtomicUsize);

impl<'a> Waiting<'a> {
    fn on(count: &'a AtomicUsize) -> Self {
        count.fetch_add(1, Ordering::AcqRel);
        Waiting(count)
    }
}

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl<T> Mvar<T> {
    pub fn new() -> Mvar<T> {
        Mvar {
            inner: Mutex::new(None),
            cond_put: Condition::new(),
            cond_take: Condition::new(),
            wait_put: AtomicUsize::new(0),
            wait_take: AtomicUsize::new(0),
        }
    }

    pub fn has_take_waiting(&self) -> bool {
        self.wait_take.load(Ordering::Acquire) > 0
    }

    pub fn has_put_waiting(&self) -> bool {
        self.wait_put.load(Ordering::Acquire) > 0
    }

    pub async fn try_take(&self) -> Option<T> {
        let mut guard = zasynclock!(self.inner);
        if let Some(inner) = guard.take() {
            drop(guard);
            self.cond_put.notify_one();
            return Some(inner);
        }
        None
    }

    pub async fn take(&self) -> T {
        loop {
            let mut guard = zasynclock!(self.inner);
            if let Some(inner) = guard.take() {
                drop(guard);
                self.cond_put.notify_one();
                return inner;
            }
            let _waiting = Waiting::on(&self.wait_take);
            self.cond_take.wait(guard).await;
        }
    }

    pub async fn put(&self, inner: T) {
        loop {
            let mut guard = zasynclock!(self.inner);
            if guard.is_some() {
                let _waiting = Waiting::on(&self.wait_put);
                self.cond_put.wait(guard).await;
            } else {
                *guard = Some(inner);
                drop(guard);
                self.cond_take.notify_one();
                return;
            }
        }
    }
}

impl<T> Default for Mvar<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use zenoh_result::ZResult;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn mvar() -> ZResult<()> {
        use std::{sync::Arc, time::Duration};

        use super::Mvar;

        const TIMEOUT: Duration = Duration::from_secs(60);

        let count: usize = 1_000;
        let mvar: Arc<Mvar<usize>> = Arc::new(Mvar::new());

        let c_mvar = mvar.clone();
        let ch = tokio::task::spawn(async move {
            for _ in 0..count {
                let n = c_mvar.take().await;
                print!("-{n} ");
            }
        });

        let ph = tokio::task::spawn(async move {
            for i in 0..count {
                mvar.put(i).await;
                print!("+{i} ");
            }
        });

        let _ = tokio::time::timeout(TIMEOUT, ph).await?;
        let _ = tokio::time::timeout(TIMEOUT, ch).await?;
        println!();
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_call_is_counted_as_waiting_only_while_it_waits() {
        use std::{sync::Arc, time::Duration};

        use super::Mvar;

        let mvar = Arc::new(Mvar::new());
        // A put into an empty mvar and a take of a full one wait for nothing.
        mvar.put(1_u8).await;
        assert!(!mvar.has_put_waiting());
        assert_eq!(mvar.take().await, 1);
        assert!(!mvar.has_take_waiting());
        // A take of an empty one waits, and is counted until the put it waited for.
        let taker = mvar.clone();
        let take = tokio::spawn(async move { taker.take().await });
        while !mvar.has_take_waiting() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        mvar.put(2).await;
        let taken = tokio::time::timeout(Duration::from_secs(10), take)
            .await
            .expect("the take ended")
            .expect("the take ran");
        assert_eq!(taken, 2);
        assert!(!mvar.has_take_waiting());
        // A take that is dropped while it waits is no longer counted.
        let taker = mvar.clone();
        let take = tokio::spawn(async move { taker.take().await });
        while !mvar.has_take_waiting() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        take.abort();
        let _ = take.await;
        assert!(!mvar.has_take_waiting());
    }
}
