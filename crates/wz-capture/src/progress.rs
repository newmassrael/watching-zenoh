// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A LONG WALK THAT CAN SAY HOW FAR IT HAS GOT, AND BE TOLD TO STOP.
//!
//! # What a consumer was waiting on
//!
//! Building a field document, or a census, over a capture of 100 MB takes tens of
//! seconds, and from the outside it is one call that returns at the end. A caller
//! that wants a progress bar has nothing to draw it from, and a caller whose user
//! closed the window has nothing to stop it with, so the work finishes for nobody.
//!
//! # What this is
//!
//! A [`Progress`] is handed to a walk. The walk calls [`Progress::step`] once per
//! unit of work (a message folded, a row written) and the callback behind it is
//! asked how far the walk has got every [`EVERY`] steps, and may answer that it
//! should stop. The walk then stops at the next step and gives its caller back a
//! result the caller discards: a walk that was stopped has a half-built document
//! and half-advanced folds, and no part of either is a result.
//!
//! # What a stopped walk leaves behind
//!
//! The memory a walk keeps between calls (see [`crate::CensusMemory`] and the
//! field document's own `FieldsMemory`, which is not linked: its module exists only
//! where the field document is built) is dropped, so the next call begins that
//! memory again. That costs what a first call costs and is never a wrong answer;
//! the alternative, a fold that kept the messages it had taken and forgot where it
//! stopped, would fold them twice.

use core::cell::Cell;

/// How many steps pass between two questions to the callback. Asking at every step
/// would cost more than the work it reports on, and a person watching a bar does
/// not need a report per message.
pub const EVERY: u64 = 256;

/// The callback of a walk: how far it has got and whether it should go on.
pub struct Progress<'a> {
    callback: &'a dyn Fn(u64, u64) -> bool,
    done: Cell<u64>,
    total: Cell<u64>,
    cancelled: Cell<bool>,
}

impl<'a> Progress<'a> {
    /// A walk to be reported on. `callback(done, total)` returns `true` to go on and
    /// `false` to stop.
    pub fn new(callback: &'a dyn Fn(u64, u64) -> bool) -> Self {
        Self {
            callback,
            done: Cell::new(0),
            total: Cell::new(0),
            cancelled: Cell::new(false),
        }
    }

    /// `steps` more steps are expected. A walk that cannot know its length before it
    /// starts says what it knows, and `total` is then a floor that grows as the walk
    /// learns more.
    pub fn expect(&self, steps: u64) {
        self.total.set(self.total.get().saturating_add(steps));
    }

    /// One step is done. `false` once the walk has been told to stop, and for every
    /// step after.
    pub fn step(&self) -> bool {
        if self.cancelled.get() {
            return false;
        }
        let done = self.done.get() + 1;
        self.done.set(done);
        // `%` and not `is_multiple_of`: that method is newer than this crate's MSRV.
        #[allow(clippy::manual_is_multiple_of)]
        let due = done % EVERY == 0;
        if due && !(self.callback)(done, self.total.get().max(done)) {
            self.cancelled.set(true);
            return false;
        }
        true
    }

    /// The walk reached its end: report the last figure once. The answer is ignored,
    /// because a walk that is finished has nothing left to stop.
    pub fn finish(&self) {
        if !self.cancelled.get() {
            let done = self.done.get();
            let _ = (self.callback)(done, self.total.get().max(done));
        }
    }

    /// Was the walk told to stop?
    pub fn cancelled(&self) -> bool {
        self.cancelled.get()
    }
}

/// One step of an optional [`Progress`]: `true` when there is none, or when it says
/// to go on.
pub(crate) fn step(progress: Option<&Progress<'_>>) -> bool {
    match progress {
        Some(p) => p.step(),
        None => true,
    }
}

/// Was an optional [`Progress`] told to stop? Read by the field document, which is
/// built by a renderer that cannot return early; the census folds return `None`.
#[cfg(feature = "dissect")]
pub(crate) fn cancelled(progress: Option<&Progress<'_>>) -> bool {
    progress.is_some_and(Progress::cancelled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::RefCell;

    /// The callback is asked once per [`EVERY`] steps and not before, with the
    /// figures the walk gave it, and a final report closes the walk.
    #[test]
    fn it_asks_every_so_many_steps_and_reports_the_end() {
        let asked = RefCell::new(alloc::vec::Vec::new());
        let callback = |done: u64, total: u64| {
            asked.borrow_mut().push((done, total));
            true
        };
        let progress = Progress::new(&callback);
        progress.expect(3 * EVERY);
        for _ in 0..(2 * EVERY + 10) {
            assert!(progress.step());
        }
        assert_eq!(
            *asked.borrow(),
            alloc::vec![(EVERY, 3 * EVERY), (2 * EVERY, 3 * EVERY)]
        );
        progress.finish();
        assert_eq!(asked.borrow().last(), Some(&(2 * EVERY + 10, 3 * EVERY)));
    }

    /// A callback that says stop stops the walk at that step and every one after,
    /// is not asked again, and `finish` reports nothing for a walk that was stopped.
    #[test]
    fn a_stop_is_final() {
        let calls = RefCell::new(0u32);
        let callback = |_: u64, _: u64| {
            *calls.borrow_mut() += 1;
            false
        };
        let progress = Progress::new(&callback);
        let mut taken = 0u64;
        for _ in 0..(3 * EVERY) {
            if progress.step() {
                taken += 1;
            }
        }
        assert_eq!(
            taken,
            EVERY - 1,
            "the walk stops at the step that was asked"
        );
        assert!(progress.cancelled());
        progress.finish();
        assert_eq!(*calls.borrow(), 1, "a stopped walk is not asked again");
    }

    /// `total` is a floor: a walk that learned less than it did reports at least
    /// what is done, so `done` never passes it.
    #[test]
    fn total_is_never_below_done() {
        let asked = RefCell::new(alloc::vec::Vec::new());
        let callback = |done: u64, total: u64| {
            asked.borrow_mut().push((done, total));
            true
        };
        let progress = Progress::new(&callback);
        for _ in 0..EVERY {
            progress.step();
        }
        assert_eq!(*asked.borrow(), alloc::vec![(EVERY, EVERY)]);
    }

    /// A walk nobody watches is never stopped.
    #[test]
    fn no_progress_never_stops() {
        assert!(super::step(None));
    }
}
