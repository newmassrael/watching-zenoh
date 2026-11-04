// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A one-value handoff from a thread that is starting a session to the thread that waits for it.
//!
//! An open starts the drive of a session on a thread of its own and the caller waits for that
//! thread to say whether the session is up. `std::sync::mpsc` does that, and its `recv` takes the
//! caller's `std::thread::Thread` handle to park on, which std creates the first time a thread
//! asks. The caller of a C open is the program's own thread, one std did not start, and that
//! handle then stays in its thread-local storage until the process ends: a memory checker reports
//! it as a lost block, once, from a program that has closed everything it opened
//! (`z_leak_pub_sub_test`, which upstream's library passes). The wait here is a mutex and a
//! condition variable, which park on a futex and need no handle of the thread, so the caller
//! leaves nothing behind.
//!
//! The shape is `mpsc`'s as far as the open uses it: senders are cloneable, the first value sent
//! is the one received, a send to a waiter that is gone says so, and a waiter whose senders have
//! all gone without sending is told that.

use std::sync::{Arc, Condvar, Mutex};

struct State<T> {
    value: Option<T>,
    senders: usize,
    waiting: bool,
}

struct Shared<T> {
    state: Mutex<State<T>>,
    ready: Condvar,
}

impl<T> Shared<T> {
    fn lock(&self) -> std::sync::MutexGuard<'_, State<T>> {
        // A poisoned lock still holds a coherent `State`: every update below is one assignment.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The sending half. Cloneable; the last one dropped without a value sent wakes the waiter.
pub struct Reporter<T> {
    shared: Arc<Shared<T>>,
}

/// The waiting half.
pub struct Waiter<T> {
    shared: Arc<Shared<T>>,
}

/// Every sender has gone and none sent a value.
#[derive(Debug, PartialEq, Eq)]
pub struct Disconnected;

/// A handoff: the sender, and the waiter that takes the first value sent.
pub fn handoff<T>() -> (Reporter<T>, Waiter<T>) {
    let shared = Arc::new(Shared {
        state: Mutex::new(State {
            value: None,
            senders: 1,
            waiting: true,
        }),
        ready: Condvar::new(),
    });
    (
        Reporter {
            shared: shared.clone(),
        },
        Waiter { shared },
    )
}

impl<T> Reporter<T> {
    /// Hand `value` over. The waiter takes the first value sent and the later ones are dropped,
    /// as `mpsc` queues them behind a first that is all the open reads. `Err` returns the value
    /// when the waiter has gone, so a sender can tell the caller is no longer there.
    pub fn send(&self, value: T) -> Result<(), T> {
        let mut state = self.shared.lock();
        if !state.waiting {
            return Err(value);
        }
        if state.value.is_none() {
            state.value = Some(value);
        }
        drop(state);
        self.shared.ready.notify_all();
        Ok(())
    }
}

impl<T> Clone for Reporter<T> {
    fn clone(&self) -> Self {
        self.shared.lock().senders += 1;
        Self {
            shared: self.shared.clone(),
        }
    }
}

impl<T> Drop for Reporter<T> {
    fn drop(&mut self) {
        let mut state = self.shared.lock();
        state.senders -= 1;
        let last = state.senders == 0;
        drop(state);
        if last {
            self.shared.ready.notify_all();
        }
    }
}

impl<T> Waiter<T> {
    /// Wait for the value, or for every sender to go without one.
    pub fn recv(self) -> Result<T, Disconnected> {
        let mut state = self.shared.lock();
        loop {
            if let Some(value) = state.value.take() {
                return Ok(value);
            }
            if state.senders == 0 {
                return Err(Disconnected);
            }
            state = self
                .shared
                .ready
                .wait(state)
                .unwrap_or_else(|e| e.into_inner());
        }
    }
}

impl<T> Drop for Waiter<T> {
    fn drop(&mut self) {
        self.shared.lock().waiting = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_value_sent_is_the_one_received() {
        let (tx, rx) = handoff::<u8>();
        assert!(tx.send(1).is_ok());
        assert!(tx.send(2).is_ok());
        assert_eq!(rx.recv(), Ok(1));
    }

    #[test]
    fn a_waiter_is_woken_by_a_send_from_another_thread() {
        let (tx, rx) = handoff::<&'static str>();
        let sender = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            tx.send("up").expect("the waiter is there");
        });
        assert_eq!(rx.recv(), Ok("up"));
        sender.join().expect("the sender ends");
    }

    #[test]
    fn senders_that_all_go_without_sending_disconnect_the_waiter() {
        let (tx, rx) = handoff::<u8>();
        let second = tx.clone();
        let waiter = std::thread::spawn(move || rx.recv());
        drop(tx);
        std::thread::sleep(std::time::Duration::from_millis(30));
        drop(second);
        assert_eq!(waiter.join().expect("the waiter ends"), Err(Disconnected));
    }

    #[test]
    fn a_value_sent_before_the_senders_go_is_still_received() {
        let (tx, rx) = handoff::<u8>();
        tx.send(7).expect("the waiter is there");
        drop(tx);
        assert_eq!(rx.recv(), Ok(7));
    }

    #[test]
    fn a_send_to_a_waiter_that_has_gone_says_so_and_returns_the_value() {
        let (tx, rx) = handoff::<u8>();
        drop(rx);
        assert_eq!(tx.send(9), Err(9));
    }
}
