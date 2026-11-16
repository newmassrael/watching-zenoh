// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `zenoh-sync`: upstream's condition variable (`up_sync`) and wz's (`wz_sync`) asked to wake the
//! same waiters, and which of them each woke held equal.
//!
//! A waiter is looked at with a short bound and, once it is ready, not looked at again, so the
//! transcript is the order in which each crate let its waiters go: a notification wakes the waiters
//! registered before it, `notify_one` the first not yet woken and `notify_all` every one, and a
//! waiter registered after a notification waits for the next.

use std::time::Duration;

const BOUND: Duration = Duration::from_secs(10);
const QUIET: Duration = Duration::from_millis(100);

/// Three waiters, one `notify_one`, one `notify_all`, then a fourth waiter: whether each waiter was
/// ready when looked at, in order.
macro_rules! waiters_run {
    ($sync:ident) => {{
        let lock = std::sync::Mutex::new(());
        let condition = $sync::Condition::new();
        let mut waiters: Vec<Option<$sync::ConditionWaiter>> = (0..3)
            .map(|_| Some(condition.waiter(lock.lock().expect("the lock"))))
            .collect();
        let mut seen = Vec::new();
        condition.notify_one();
        for slot in waiters.iter_mut() {
            seen.push(look(slot).await);
        }
        condition.notify_all();
        for slot in waiters.iter_mut().filter(|slot| slot.is_some()) {
            seen.push(look(slot).await);
        }
        let mut late = Some(condition.waiter(lock.lock().expect("the lock")));
        seen.push(look(&mut late).await);
        seen
    }};
}

/// A task that waits under an async lock for a flag another sets under it and then notifies.
macro_rules! wait_run {
    ($sync:ident) => {{
        let state = std::sync::Arc::new(tokio::sync::Mutex::new(false));
        let condition = std::sync::Arc::new($sync::Condition::new());
        let (seen, waited) = (state.clone(), condition.clone());
        // The guard is held across the check and given up only by `wait` or by the end of the
        // task: a waiter that found the flag already set and then locked again would wait on its
        // own guard, which is what happens whenever the notifier takes the lock first. The
        // crate's own unit test of the same shape (`crates/wz-zenoh-sync/src/condition.rs`) was
        // repaired the same way.
        let waiter = tokio::spawn(async move {
            let mut guard = seen.lock().await;
            while !*guard {
                waited.wait(guard).await;
                guard = seen.lock().await;
            }
            *guard
        });
        *state.lock().await = true;
        condition.notify_all();
        tokio::time::timeout(BOUND, waiter)
            .await
            .expect("the waiter was woken")
            .expect("the waiter ran")
    }};
}

/// An event notified twice before one wait, waited for again with a bound, then left by its last
/// notifier: what each wait answered, as text.
macro_rules! event_run {
    ($sync:ident) => {{
        let (notifier, waiter) = $sync::event::new();
        let mut seen = Vec::new();
        seen.push(format!("{:?}", notifier.notify()));
        seen.push(format!("{:?}", notifier.notify()));
        seen.push(format!("{:?}", waiter.wait()));
        seen.push(format!("{:?}", waiter.wait_timeout(QUIET)));
        drop(notifier);
        seen.push(format!("{:?}", waiter.wait()));
        seen
    }};
}

/// Whether the waiter in `slot` is ready within the quiet bound; a ready one is taken out, so a
/// finished future is never polled again.
async fn look<W: std::future::Future<Output = ()> + Unpin>(slot: &mut Option<W>) -> bool {
    let Some(waiter) = slot.as_mut() else {
        return true;
    };
    let ready = tokio::time::timeout(QUIET, waiter).await.is_ok();
    if ready {
        *slot = None;
    }
    ready
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn both_conditions_wake_the_same_waiters_in_the_same_order() {
    let up = waiters_run!(up_sync);
    let wz = waiters_run!(wz_sync);
    assert_eq!(up, wz, "the two conditions differ");
    // What they agree ON: `notify_one` woke the first only, `notify_all` the two others, and the
    // waiter registered after both waits.
    assert_eq!(wz, vec![true, false, false, true, true, false]);
}

#[test]
fn both_events_keep_one_notification_and_close_with_their_last_notifier() {
    let up = event_run!(up_sync);
    let wz = event_run!(wz_sync);
    assert_eq!(up, wz, "the two events differ");
    // Two notifications before a wait are one: the second wait times out, and the event closes
    // when its notifier goes.
    assert_eq!(
        wz,
        ["Ok(())", "Ok(())", "Ok(())", "Err(Timeout expired)", "Err(No notifier available)"]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn both_conditions_let_a_task_waiting_under_the_lock_see_the_flag() {
    let up = wait_run!(up_sync);
    let wz = wait_run!(wz_sync);
    assert_eq!(up, wz, "the two conditions differ");
    assert!(wz, "the waiter saw the flag the notifier set");
}
