// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The two flags every data send reads before it takes a lock: whether its link takes sends
//! ([`SendGate`]) and whether a close for congestion was ordered of its session ([`Latch`]).
//!
//! Each was a `bool` behind a lock of its own, which a send took twice before it reached its
//! conduit. Neither flag is ever read and written in one step: a writer stores a value, a reader
//! loads one. A lock around a `bool` gives exactly two things to such a use, the value and the
//! order of what was written before it; a release store and an acquire load give the same two
//! (a reader that sees a value sees what its writer wrote before storing it), and nothing that
//! a lock gives beyond them (two readers in turn, or a read and a write as one step) is used.
//! No total order across the two flags is relied on either: a send reads both, and either one
//! closed refuses it.

use core::sync::atomic::{AtomicBool, Ordering};

/// Whether a link takes data sends: open while it is established, closed from the moment the
/// session lets the link go (or tears it down for a re-dial) until it is established again.
///
/// `open` and `close` store with `Release` and `is_open` loads with `Acquire`, so a send that
/// reads the gate open also sees what the establishment wrote before opening it, and one that
/// reads it closed sees what the teardown wrote before closing it: the edge the lock gave.
#[derive(Debug)]
pub struct SendGate(AtomicBool);

impl SendGate {
    /// A gate, `open` or not.
    pub const fn new(open: bool) -> Self {
        Self(AtomicBool::new(open))
    }

    /// Let data sends through.
    pub fn open(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// Refuse data sends.
    pub fn close(&self) {
        self.0.store(false, Ordering::Release);
    }

    /// Whether data sends go through.
    pub fn is_open(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// A flag raised once and never lowered: a decision taken for good, such as the close of a
/// session for congestion, which every later send reads to refuse at once.
///
/// `raise` stores with `Release` and `is_raised` loads with `Acquire`, so a reader that sees
/// the flag raised also sees what the thread that raised it wrote first.
#[derive(Debug, Default)]
pub struct Latch(AtomicBool);

impl Latch {
    /// A flag not raised.
    pub const fn new() -> Self {
        Self(AtomicBool::new(false))
    }

    /// Raise the flag; raising it again changes nothing.
    pub fn raise(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// Whether the flag was ever raised.
    pub fn is_raised(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicU32;
    use std::sync::Arc;

    #[test]
    fn a_gate_answers_the_last_value_stored() {
        let gate = SendGate::new(true);
        assert!(gate.is_open(), "made open");
        gate.close();
        assert!(!gate.is_open(), "closed");
        gate.close();
        assert!(!gate.is_open(), "closing twice keeps it closed");
        gate.open();
        assert!(gate.is_open(), "open again");
        assert!(!SendGate::new(false).is_open(), "made closed");
    }

    #[test]
    fn a_latch_once_raised_stays_raised() {
        let latch = Latch::new();
        assert!(!latch.is_raised(), "not raised at first");
        latch.raise();
        assert!(latch.is_raised());
        latch.raise();
        assert!(latch.is_raised(), "raising again changes nothing");
        assert!(!Latch::default().is_raised(), "the default is not raised");
    }

    /// The edge the orderings are chosen for: a value written with no ordering of its own before
    /// the gate is opened is seen by every thread that sees the gate open. On a machine that
    /// orders every store this passes with weaker orderings too; it states the contract the
    /// readers rely on rather than proving the orderings.
    #[test]
    fn what_was_written_before_the_gate_opened_is_seen_by_a_sender_that_sees_it_open() {
        for _ in 0..200 {
            let shared = Arc::new((SendGate::new(false), AtomicU32::new(0)));
            let reader = {
                let shared = shared.clone();
                std::thread::spawn(move || {
                    while !shared.0.is_open() {
                        core::hint::spin_loop();
                    }
                    shared.1.load(Ordering::Relaxed)
                })
            };
            shared.1.store(7, Ordering::Relaxed);
            shared.0.open();
            assert_eq!(reader.join().expect("the reader ran"), 7);
        }
    }
}
