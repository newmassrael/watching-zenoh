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
// src/condition.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2).

use std::{pin::Pin, sync::MutexGuard};

use event_listener::{Event, EventListener};
use tokio::sync::MutexGuard as AsyncMutexGuard;

/// What [`Condition::waiter`] returns: a future that is ready once the condition is notified.
pub type ConditionWaiter = Pin<Box<EventListener>>;

/// This is a Condition Variable similar to that provided by POSIX.
/// As for POSIX condition variables, this assumes that a mutex is
/// properly used to coordinate behaviour. In other terms there should
/// not be race condition on [notify_one](Condition::notify_one) or
/// [notify_all](Condition::notify_all).
///
#[derive(Debug, Default)]
pub struct Condition {
    event: Event,
}

impl Condition {
    /// Creates a new condition variable with a given capacity.
    /// The capacity indicates the maximum number of tasks that
    /// may be waiting on the condition.
    pub fn new() -> Condition {
        Condition::default()
    }

    /// Waits for the condition to be notified
    #[inline]
    pub async fn wait<T>(&self, guard: AsyncMutexGuard<'_, T>) {
        // The listener is registered before the lock is let go, so a notification that follows
        // the release is not missed.
        let listener = self.event.listen();
        drop(guard);
        listener.await;
    }

    /// A waiter registered while `guard` is held, which lets the lock go: the future is ready once
    /// the condition is notified after this call.
    #[inline]
    pub fn waiter<T>(&self, guard: MutexGuard<'_, T>) -> ConditionWaiter {
        let listener = self.event.listen();
        drop(guard);
        Box::pin(listener)
    }

    /// Notifies one pending listener
    #[inline]
    pub fn notify_one(&self) {
        self.event.notify_additional_relaxed(1);
    }

    /// Notifies all pending listeners
    #[inline]
    pub fn notify_all(&self) {
        self.event.notify_additional_relaxed(usize::MAX);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };

    use super::Condition;

    const BOUND: Duration = Duration::from_secs(10);
    const QUIET: Duration = Duration::from_millis(100);

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_task_waiting_under_the_lock_sees_what_the_notifier_set() {
        let state = Arc::new(tokio::sync::Mutex::new(false));
        let condition = Arc::new(Condition::new());
        let (seen, waited) = (state.clone(), condition.clone());
        let waiter = tokio::spawn(async move {
            let guard = seen.lock().await;
            if !*guard {
                waited.wait(guard).await;
            }
            *seen.lock().await
        });
        *state.lock().await = true;
        condition.notify_all();
        let set = tokio::time::timeout(BOUND, waiter)
            .await
            .expect("the waiter was woken")
            .expect("the waiter ran");
        assert!(set);
    }

    #[tokio::test]
    async fn notify_one_wakes_the_first_waiter_and_leaves_the_second() {
        let lock = Mutex::new(());
        let condition = Condition::new();
        let first = condition.waiter(lock.lock().unwrap());
        let mut second = condition.waiter(lock.lock().unwrap());
        condition.notify_one();
        tokio::time::timeout(BOUND, first)
            .await
            .expect("the first waiter was notified");
        assert!(
            tokio::time::timeout(QUIET, &mut second).await.is_err(),
            "one notification wakes one waiter"
        );
        condition.notify_one();
        tokio::time::timeout(BOUND, second)
            .await
            .expect("the second notification wakes the second waiter");
    }

    #[tokio::test]
    async fn notify_all_wakes_every_waiter_and_none_registered_after_it() {
        let lock = Mutex::new(());
        let condition = Condition::new();
        let waiters: Vec<_> = (0..3)
            .map(|_| condition.waiter(lock.lock().unwrap()))
            .collect();
        condition.notify_all();
        for waiter in waiters {
            tokio::time::timeout(BOUND, waiter)
                .await
                .expect("every waiter registered before the notification is woken");
        }
        let late = condition.waiter(lock.lock().unwrap());
        assert!(
            tokio::time::timeout(QUIET, late).await.is_err(),
            "a waiter registered after the notification waits for the next"
        );
    }
}
