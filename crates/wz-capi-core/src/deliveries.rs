// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The deliveries of one session of this engine on the threads that make them
//! ([`wz_capi_port::EngineDeliveries`]).
//!
//! Its callbacks run on the session's drive thread, on the threads of its runtime and on a
//! program's thread that drains the local plane, so what a thread delivers for is the thread's to
//! know: each thread keeps the sessions it is delivering for, innermost last, and each callback the
//! session mints enters its session's mark around the call. A callback that reaches another
//! session's callback from inside it delivers for both until the inner call returns.

use std::cell::RefCell;
use std::sync::atomic::{AtomicUsize, Ordering};

use wz_capi_port::EngineDeliveries;

/// The mark of one session's deliveries: copied into every callback the session mints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Deliveries(usize);

/// The mark the next session is given: no two sessions of the process share one.
static NEXT_MARK: AtomicUsize = AtomicUsize::new(1);

thread_local! {
    /// The marks of the sessions this thread is delivering for, innermost last.
    static DELIVERING: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
}

impl Deliveries {
    /// The mark of a session made now.
    pub(crate) fn new() -> Self {
        Self(NEXT_MARK.fetch_add(1, Ordering::Relaxed))
    }

    /// Run `f`, a callback of the session, as a delivery of it on this thread.
    pub(crate) fn within<R>(self, f: impl FnOnce() -> R) -> R {
        DELIVERING.with(|marks| marks.borrow_mut().push(self.0));
        let _delivering = Delivering(self.0);
        f()
    }
}

/// A delivery of the session of its mark, ended as it drops, so a callback that unwinds ends it
/// too.
struct Delivering(usize);

impl Drop for Delivering {
    fn drop(&mut self) {
        DELIVERING.with(|marks| {
            let mut marks = marks.borrow_mut();
            if let Some(at) = marks.iter().rposition(|mark| *mark == self.0) {
                marks.remove(at);
            }
        });
    }
}

impl EngineDeliveries for Deliveries {
    fn delivers_here(&self) -> bool {
        DELIVERING.with(|marks| marks.borrow().contains(&self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A thread delivers for a session only inside a callback of that session, and still inside
    /// it when an inner callback of the same session has returned. Turned red by a mark that is
    /// not entered, or one an inner delivery's end clears for the outer one.
    #[test]
    fn a_thread_delivers_for_a_session_inside_its_callbacks_alone() {
        let session = Deliveries::new();
        assert!(!session.delivers_here(), "no delivery before the first");
        session.within(|| {
            assert!(session.delivers_here(), "inside its callback");
            session.within(|| assert!(session.delivers_here(), "inside an inner one"));
            assert!(
                session.delivers_here(),
                "the inner end left the outer standing"
            );
        });
        assert!(!session.delivers_here(), "ended with the callback");
    }

    /// A callback of one session is no delivery of another, though the other's callback runs
    /// inside it; and a delivery of one session on one thread is none on another thread. Turned
    /// red by one mark for every session, or one shared by the threads.
    #[test]
    fn a_delivery_of_one_session_is_none_of_another_nor_on_another_thread() {
        let (one, other) = (Deliveries::new(), Deliveries::new());
        assert_ne!(one, other, "two sessions have two marks");
        one.within(|| {
            assert!(!other.delivers_here(), "another session's callback");
            other.within(|| {
                assert!(other.delivers_here(), "inside the inner session's callback");
                assert!(one.delivers_here(), "and still inside the outer one's");
            });
            assert!(!other.delivers_here(), "the inner one ended");
            let elsewhere = std::thread::spawn(move || one.delivers_here())
                .join()
                .expect("the other thread");
            assert!(!elsewhere, "another thread delivers nothing");
        });
    }

    /// A callback that unwinds ends its delivery. Turned red by a mark left standing after the
    /// unwind.
    #[test]
    fn a_callback_that_unwinds_ends_its_delivery() {
        let session = Deliveries::new();
        let unwound = std::panic::catch_unwind(|| session.within(|| panic!("the callback")));
        assert!(unwound.is_err(), "the callback unwound");
        assert!(!session.delivers_here(), "its delivery ended");
    }
}
