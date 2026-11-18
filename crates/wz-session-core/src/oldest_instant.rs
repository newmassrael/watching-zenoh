// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The earliest capture instant among the rows a list holds, kept as rows are
//! appended at its back and released from its front, so asking for it walks no
//! row.
//!
//! # Why a list keeps it
//!
//! A reader that says how far back a capture can still be read asks for the
//! minimum instant over everything held. Over a list of a hundred thousand rows
//! that is a hundred thousand reads per question, and a list that keeps its rows
//! as index entries answers a row only by reading its unit again. The head of
//! the list is not the answer: a capture merged from two taps, or a stream whose
//! segments arrived out of order, can hold a later instant ahead of an earlier
//! one.
//!
//! # The rule
//!
//! A row is a CANDIDATE when it carries an instant and no row after it carries
//! a strictly earlier one. The candidates' instants never fall in row order, so
//! the earliest instant held is the first candidate's: every row before it is
//! either clockless or has a later row with an earlier instant, and following
//! those reaches a candidate. A row appended ends the candidacy of every
//! candidate with a later instant than its own and becomes one itself; a row
//! released from the front takes its own candidacy with it.
//!
//! # Held as runs, not one entry per candidate
//!
//! On a clock that only moves forward every row is a candidate, so a structure
//! with one entry per candidate would grow with the list. The candidates are
//! kept as runs of consecutive rows instead, and a candidate's instant is read
//! off the list when it is needed ([`OldestInstant::push`]'s `instant_of`).
//! Such a list holds one run whatever its length; a run begins where the clock
//! stepped back past a held candidate or a row carried no instant, so the runs
//! follow those events and not the row count.

use alloc::collections::VecDeque;

/// The candidates of one list, as runs of rows `[first, end)` by produced-index,
/// oldest first. See the module doc.
#[derive(Debug, Default, Clone)]
pub struct OldestInstant {
    runs: VecDeque<(u64, u64)>,
}

/// Whether the row at `row` carries an instant later than `at`. A candidate
/// always carries one; a row read back with none is not later, so a list that
/// lost a row's instant keeps more candidates and never names a wrong one.
fn later(instant_of: &impl Fn(u64) -> Option<u64>, row: u64, at: u64) -> bool {
    instant_of(row).is_some_and(|held| held > at)
}

impl OldestInstant {
    /// Nothing held.
    pub const fn new() -> Self {
        Self {
            runs: VecDeque::new(),
        }
    }

    /// Note the row appended at produced-index `row`, which carries `at`.
    ///
    /// `instant_of` reads the instant of a row appended earlier and still held,
    /// by produced-index. Rows are noted in the order they were appended.
    pub fn push(&mut self, row: u64, at: Option<u64>, instant_of: impl Fn(u64) -> Option<u64>) {
        let Some(at) = at else {
            return;
        };
        while let Some(&(first, end)) = self.runs.back() {
            if !later(&instant_of, end - 1, at) {
                break;
            }
            // The candidates of one run carry instants that never fall, so the
            // ones later than `at` are a tail of it: the first is found by halving.
            let (mut low, mut high) = (first, end - 1);
            while low < high {
                let mid = low + (high - low) / 2;
                if later(&instant_of, mid, at) {
                    high = mid;
                } else {
                    low = mid + 1;
                }
            }
            if low == first {
                self.runs.pop_back();
            } else {
                if let Some(back) = self.runs.back_mut() {
                    back.1 = low;
                }
                break;
            }
        }
        match self.runs.back_mut() {
            Some(back) if back.1 == row => back.1 = row + 1,
            _ => self.runs.push_back((row, row + 1)),
        }
    }

    /// The rows up to and including produced-index `row` were released.
    pub fn release_through(&mut self, row: u64) {
        while let Some(front) = self.runs.front_mut() {
            if front.1 <= row + 1 {
                self.runs.pop_front();
            } else {
                front.0 = front.0.max(row + 1);
                break;
            }
        }
    }

    /// The produced-index of the row that carries the earliest instant held, or
    /// `None` when no row held carries one.
    pub fn oldest_row(&self) -> Option<u64> {
        self.runs.front().map(|&(first, _)| first)
    }

    /// Bytes allocated for the runs.
    pub fn allocated_bytes(&self) -> usize {
        crate::heap_account::vec_deque_bytes(&self.runs)
    }

    /// How many runs are held: what a test reads to see that a forward clock
    /// keeps one.
    pub fn runs(&self) -> usize {
        self.runs.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// A list of instants by produced-index, with its front, and the structure
    /// kept beside it: the oracle is the minimum over what the list holds.
    struct Held {
        instants: Vec<Option<u64>>,
        front: u64,
        oldest: OldestInstant,
    }

    impl Held {
        fn new() -> Self {
            Self {
                instants: Vec::new(),
                front: 0,
                oldest: OldestInstant::new(),
            }
        }

        fn push(&mut self, at: Option<u64>) {
            let row = self.instants.len() as u64;
            self.instants.push(at);
            let instants = &self.instants;
            let front = self.front;
            self.oldest.push(row, at, |earlier| {
                assert!(
                    earlier >= front && earlier < row,
                    "row {earlier} is not held and earlier than {row}"
                );
                instants[earlier as usize]
            });
        }

        fn release_one(&mut self) {
            if (self.front as usize) < self.instants.len() {
                self.oldest.release_through(self.front);
                self.front += 1;
            }
        }

        fn kept(&self) -> Option<u64> {
            self.oldest
                .oldest_row()
                .and_then(|row| self.instants[row as usize])
        }

        fn walked(&self) -> Option<u64> {
            self.instants[self.front as usize..]
                .iter()
                .flatten()
                .copied()
                .min()
        }
    }

    #[test]
    fn a_forward_clock_keeps_one_run_and_the_front_is_the_oldest() {
        let mut held = Held::new();
        for k in 0..1_000u64 {
            held.push(Some(10 * k));
            if k % 3 == 0 {
                held.release_one();
            }
            assert_eq!(held.kept(), held.walked(), "after row {k}");
        }
        assert_eq!(held.oldest.runs(), 1, "a forward clock is one run");
    }

    #[test]
    fn equal_instants_stay_candidates() {
        let mut held = Held::new();
        for _ in 0..10 {
            held.push(Some(5));
        }
        assert_eq!(held.oldest.runs(), 1);
        for _ in 0..9 {
            held.release_one();
            assert_eq!(held.kept(), Some(5));
        }
    }

    /// A step back ends the candidacy of the held rows after the instant it
    /// stepped to, and the earliest is found behind the head of the list.
    #[test]
    fn a_step_back_is_found_behind_the_head() {
        let mut held = Held::new();
        for at in [50, 60, 70, 55, 80] {
            held.push(Some(at));
        }
        assert_eq!(held.kept(), Some(50));
        held.release_one();
        assert_eq!(held.kept(), Some(55), "60 and 70 were never the oldest");
        assert_eq!(held.walked(), Some(55));
        held.release_one();
        held.release_one();
        assert_eq!(held.kept(), Some(55));
        held.release_one();
        assert_eq!(held.kept(), Some(80));
    }

    #[test]
    fn a_list_with_no_clock_has_no_oldest_instant() {
        let mut held = Held::new();
        for _ in 0..20 {
            held.push(None);
        }
        assert_eq!(held.kept(), None);
        assert_eq!(held.oldest.runs(), 0);
        assert_eq!(held.oldest.allocated_bytes(), 0, "and allocates nothing");
        held.push(Some(3));
        assert_eq!(held.kept(), Some(3));
    }

    #[test]
    fn releasing_everything_leaves_nothing() {
        let mut held = Held::new();
        for at in [9, 3, 7, 1] {
            held.push(Some(at));
        }
        for _ in 0..4 {
            held.release_one();
        }
        assert_eq!(held.kept(), None);
        assert_eq!(held.oldest.runs(), 0);
    }

    /// Every mix of clock moves the other tests name one at a time, against the
    /// minimum over what is held after every step.
    #[test]
    fn the_kept_instant_is_the_minimum_held_after_every_step() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for case in 0..64 {
            let mut held = Held::new();
            let mut clock = 1_000u64;
            for step in 0..400 {
                let roll = next();
                let at = match roll % 10 {
                    0 => None,
                    1 | 2 => {
                        clock = clock.saturating_sub(roll % 50);
                        Some(clock)
                    }
                    3 => Some(clock),
                    _ => {
                        clock += roll % 20;
                        Some(clock)
                    }
                };
                held.push(at);
                for _ in 0..(next() % 3) {
                    held.release_one();
                }
                assert_eq!(held.kept(), held.walked(), "case {case}, step {step}");
            }
            while (held.front as usize) < held.instants.len() {
                held.release_one();
                assert_eq!(held.kept(), held.walked(), "case {case}, draining");
            }
        }
    }
}
