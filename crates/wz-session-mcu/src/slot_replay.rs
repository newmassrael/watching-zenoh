// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A replay of the client node: a recorded sequence of puts compiled into the image, played on each
//! session from the moment it is established, paced and mutated by the workload's definitions
//! (`wz_workload::pacing`, `wz_workload::mutation`, docs/target-build-contract.md 5c), in fixed
//! memory.
//!
//! What is here is what a replay IS and what is counted of it: the [`Sample`] (a key, the bytes as
//! recorded, the time the capture saw it, a mutation), the [`Replay`] (its samples and the
//! schedule that paces them), the send-side state of a session's replays ([`Replaying`]) and the
//! counts of what went out ([`ReplayCounts`], one `static` of the image's whose initial value is
//! all zero bytes) with the watch the program's loop says them with ([`ReplayWatch`]). The puts are
//! sent by the session's application layer inside its event (`crate::slot_active::Active`), as a
//! publisher's are.
//!
//! # The delays are the replay tool's
//!
//! The delay before each sample is `Pacing`'s walk of the samples' capture times under the
//! schedule (the first waits for nothing; then the declared gap or the recorded interval, divided
//! by the speed, capped), the same walk the driver's `replay` and the replay tool make; each
//! sample's time is the previous one's plus its delay, so the plan does not drift by the lateness
//! of a send. A sample that could not be put at its time is put as soon as it can and the ones
//! behind it follow, at most `CATCH_UP` of one replay in one round; how late the latest was is
//! counted, and nothing is skipped. The bytes are the sample's mutated by `Mutation::apply_into`
//! into the node's one buffer (`crate::slot_publisher::MadeBuffer`), so a replay needs no storage
//! beyond its samples, which are read-only data. A session that is lost stops its replays; the
//! next one plays them again from the first sample.
//!
//! This module does not link `alloc`.

use core::cell::Cell;

use wz_workload::pacing::Pacing;

use crate::slot_publisher::{PublishCounts, CATCH_UP};
use crate::slot_schedule::{Outcome, RETRY_MS};

// The words a replay is written in, so an image (and the constants a node declaration generates for
// it) names one crate for the whole replay.
pub use wz_workload::arrivals::Decimal;
pub use wz_workload::mutation::Mutation;
pub use wz_workload::pacing::{Schedule, Timing};

/// One recorded put.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sample {
    /// The key it is put on, a literal key expression.
    pub key: &'static str,
    /// Its bytes as recorded.
    pub body: &'static [u8],
    /// When the capture saw it, in milliseconds, if it carried a time.
    pub captured_at_ms: Option<u64>,
    /// What is done to its bytes before they are put.
    pub mutation: Mutation,
}

/// A recorded sequence of puts and the schedule that paces it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Replay {
    /// The name the replay is said by: the key of the entity that declared it.
    pub name: &'static str,
    /// Its samples, in the order they are put.
    pub samples: &'static [Sample],
    /// How the delays between them are made.
    pub schedule: Schedule,
}

/// The send-side state of a session's replays: where each is in its samples, its pacing walk, when
/// its next sample is due and when a put the session could not take is to be tried again.
pub struct Replaying<const R: usize> {
    pacing: [Option<Pacing>; R],
    next: [usize; R],
    due_ms: [u64; R],
    retry_at: [Option<u64>; R],
    armed: bool,
}

impl<const R: usize> Replaying<R> {
    /// State that has not started: the first round starts every replay at its first sample.
    pub const fn new() -> Self {
        Self {
            pacing: [const { None }; R],
            next: [0; R],
            due_ms: [0; R],
            retry_at: [None; R],
            armed: false,
        }
    }

    /// The session is not established: the next round plays every replay again from its start.
    pub fn disarm(&mut self) {
        self.armed = false;
    }

    /// When replay `at`'s next sample can be put: its time, or the retry, whichever is later.
    fn ready_ms(&self, at: usize) -> u64 {
        self.retry_at[at].map_or(self.due_ms[at], |retry| retry.max(self.due_ms[at]))
    }

    /// One round at `now_ms`: each sample whose time has come is mutated into `buffer` and handed
    /// to `send` with its replay's index and its key (one longer than `buffer` is refused unsent),
    /// and counted in `counts`. Returns the earliest moment the layer is to be woken at for a
    /// sample, or `None` when every replay has played to its end.
    pub fn poll(
        &mut self,
        now_ms: u64,
        replays: &[Replay],
        buffer: &mut [u8],
        counts: &ReplayCounts<R>,
        mut send: impl FnMut(usize, &'static str, &[u8]) -> Outcome,
    ) -> Option<u64> {
        let count = replays.len().min(R);
        if !self.armed {
            for (at, replay) in replays.iter().take(count).enumerate() {
                let mut pacing = Pacing::new(replay.schedule);
                let first = replay.samples.first().and_then(|s| s.captured_at_ms);
                self.due_ms[at] = now_ms.saturating_add(pacing.next(first).0);
                self.pacing[at] = Some(pacing);
                self.next[at] = 0;
                self.retry_at[at] = None;
            }
            self.armed = true;
        }
        let mut earliest: Option<u64> = None;
        for (at, replay) in replays.iter().take(count).enumerate() {
            let mut made = 0;
            while let Some(sample) = replay.samples.get(self.next[at]) {
                if self.ready_ms(at) > now_ms || made == CATCH_UP {
                    break;
                }
                let (outcome, changed) = match sample.mutation.apply_into(sample.body, buffer) {
                    Some(applied) => (
                        send(at, sample.key, &buffer[..applied.len]),
                        applied.changed,
                    ),
                    None => (Outcome::Refused, false),
                };
                match outcome {
                    Outcome::Retry => {
                        self.retry_at[at] = Some(now_ms + RETRY_MS);
                        break;
                    }
                    Outcome::Sent => {
                        counts.puts.record_sent(at);
                        counts
                            .puts
                            .record_late(at, now_ms.saturating_sub(self.due_ms[at]));
                        if changed {
                            Self::bump(&counts.mutated, at);
                        }
                    }
                    Outcome::Refused => counts.puts.record_refused(at),
                }
                self.retry_at[at] = None;
                self.next[at] += 1;
                made += 1;
                match (replay.samples.get(self.next[at]), self.pacing[at].as_mut()) {
                    (Some(following), Some(pacing)) => {
                        let delay = pacing.next(following.captured_at_ms).0;
                        self.due_ms[at] = self.due_ms[at].saturating_add(delay);
                    }
                    _ => Self::bump(&counts.played, at),
                }
            }
            if self.next[at] < replay.samples.len() {
                let ready = self.ready_ms(at).max(now_ms);
                earliest = Some(earliest.map_or(ready, |e: u64| e.min(ready)));
            }
        }
        earliest
    }

    fn bump(cells: &[Cell<u32>; R], at: usize) {
        if let Some(cell) = cells.get(at) {
            cell.set(cell.get().wrapping_add(1));
        }
    }
}

impl<const R: usize> Default for Replaying<R> {
    fn default() -> Self {
        Self::new()
    }
}

/// What each replay put, had refused and mutated, how late its latest put was, and how many times
/// it was played to its end, in storage the image declares.
pub struct ReplayCounts<const R: usize> {
    puts: PublishCounts<R>,
    mutated: [Cell<u32>; R],
    played: [Cell<u32>; R],
}

// SAFETY: the profile's rule: one thread drives the node, and both the session's layer (which
// writes) and the program's loop (which reads) run on it, never at the same moment.
unsafe impl<const R: usize> Sync for ReplayCounts<R> {}

impl<const R: usize> ReplayCounts<R> {
    /// Every count zero; all zero bytes.
    pub const fn new() -> Self {
        Self {
            puts: PublishCounts::new(),
            mutated: [const { Cell::new(0) }; R],
            played: [const { Cell::new(0) }; R],
        }
    }

    /// The counts of replay `at`: (sent, refused, mutated, late_max_ms, played).
    pub fn of(&self, at: usize) -> (u32, u32, u32, u32, u32) {
        let read = |cells: &[Cell<u32>; R]| cells.get(at).map_or(0, Cell::get);
        (
            self.puts.sent(at),
            self.puts.refused(at),
            read(&self.mutated),
            self.puts.late_max_ms(at),
            read(&self.played),
        )
    }
}

impl<const R: usize> Default for ReplayCounts<R> {
    fn default() -> Self {
        Self::new()
    }
}

/// What the program's loop remembers of the counts between two rounds, to say each change once.
pub struct ReplayWatch<const R: usize> {
    seen: [(u32, u32, u32, u32, u32); R],
}

impl<const R: usize> ReplayWatch<R> {
    /// A watch that has seen nothing.
    pub const fn new() -> Self {
        Self {
            seen: [(0, 0, 0, 0, 0); R],
        }
    }

    /// Call `say(index, (sent, refused, mutated, late_max_ms, played))` for each replay whose counts
    /// moved since the last call.
    pub fn poll(
        &mut self,
        counts: &ReplayCounts<R>,
        mut say: impl FnMut(usize, (u32, u32, u32, u32, u32)),
    ) {
        for (at, seen) in self.seen.iter_mut().enumerate() {
            let now = counts.of(at);
            if now != *seen {
                *seen = now;
                say(at, now);
            }
        }
    }
}

impl<const R: usize> Default for ReplayWatch<R> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    const SAMPLES: [Sample; 3] = [
        Sample {
            key: "lab/r/a",
            body: &[1, 2, 3],
            captured_at_ms: Some(1_000),
            mutation: Mutation::None,
        },
        Sample {
            key: "lab/r/b",
            body: &[4, 5],
            captured_at_ms: Some(1_250),
            mutation: Mutation::FlipBit { at: 0 },
        },
        Sample {
            key: "lab/r/a",
            body: &[6, 7, 8, 9],
            captured_at_ms: None,
            mutation: Mutation::Truncate { to: 2 },
        },
    ];

    fn replay(timing: Timing, speed: f64) -> Replay {
        Replay {
            name: "lab/r",
            samples: &SAMPLES,
            schedule: Schedule {
                timing,
                gap_millis: 100,
                speed,
                max_gap_millis: Some(10_000),
                max_total_millis: None,
            },
        }
    }

    /// What a round put: (replay, key, bytes), in order.
    type Put = Vec<(usize, &'static str, Vec<u8>)>;

    /// One round at `now_ms` answering every put with `outcome`: what it put and the wake.
    fn poll<const R: usize>(
        state: &mut Replaying<R>,
        counts: &ReplayCounts<R>,
        now_ms: u64,
        replays: &[Replay],
        outcome: Outcome,
    ) -> (Put, Option<u64>) {
        let mut put = Vec::new();
        let mut buffer = [0u8; 8];
        let wake = state.poll(now_ms, replays, &mut buffer, counts, |at, key, body| {
            put.push((at, key, body.to_vec()));
            outcome
        });
        (put, wake)
    }

    /// Paced by the capture: the first at once, the second the recorded 250 ms later, the third
    /// (no time) the declared 100 ms after that; each mutated as written, and the end counted.
    #[test]
    fn a_replay_puts_its_samples_mutated_at_the_capture_s_pace() {
        let (mut state, counts) = (Replaying::<1>::new(), ReplayCounts::<1>::new());
        let one = [replay(Timing::Capture, 1.0)];
        let (put, wake) = poll(&mut state, &counts, 10, &one, Outcome::Sent);
        assert_eq!(put, [(0, "lab/r/a", alloc::vec![1, 2, 3])]);
        assert_eq!(wake, Some(260));
        let (put, wake) = poll(&mut state, &counts, 260, &one, Outcome::Sent);
        assert_eq!(
            put,
            [(0, "lab/r/b", alloc::vec![5, 5])],
            "bit 0 of the first byte"
        );
        assert_eq!(wake, Some(360));
        let (put, wake) = poll(&mut state, &counts, 360, &one, Outcome::Sent);
        assert_eq!(
            put,
            [(0, "lab/r/a", alloc::vec![6, 7])],
            "kept to two bytes"
        );
        assert_eq!(wake, None, "played to its end");
        assert_eq!(counts.of(0), (3, 0, 2, 0, 1));
    }

    /// The speed divides every gap, and the plan's times are absolute: a round woken late puts
    /// what is due and says how late, and the times after it do not move.
    #[test]
    fn a_late_round_catches_up_on_the_plan_s_times() {
        let (mut state, counts) = (Replaying::<1>::new(), ReplayCounts::<1>::new());
        let fast = [replay(Timing::Declared, 2.0)];
        poll(&mut state, &counts, 0, &fast, Outcome::Sent);
        let (put, wake) = poll(&mut state, &counts, 120, &fast, Outcome::Sent);
        assert_eq!(put.len(), 2, "the samples due at 50 and 100");
        assert_eq!(wake, None);
        assert_eq!(counts.of(0).3, 70, "the latest was 70 ms behind its time");
    }

    #[test]
    fn a_put_the_session_could_not_take_is_tried_again_and_a_lost_session_starts_over() {
        let (mut state, counts) = (Replaying::<1>::new(), ReplayCounts::<1>::new());
        let one = [replay(Timing::Declared, 1.0)];
        let (_, wake) = poll(&mut state, &counts, 0, &one, Outcome::Retry);
        assert_eq!(wake, Some(RETRY_MS));
        let (put, _) = poll(&mut state, &counts, RETRY_MS, &one, Outcome::Sent);
        assert_eq!(put[0].1, "lab/r/a", "the same sample, not the next");
        state.disarm();
        let (put, wake) = poll(&mut state, &counts, 500, &one, Outcome::Sent);
        assert_eq!((put[0].2.as_slice(), wake), (&[1u8, 2, 3][..], Some(600)));
    }

    #[test]
    fn a_sample_longer_than_the_buffer_is_refused_and_the_replay_goes_on() {
        const LONG: [Sample; 2] = [
            Sample {
                key: "k",
                body: &[0; 16],
                captured_at_ms: None,
                mutation: Mutation::None,
            },
            Sample {
                key: "k",
                body: &[1],
                captured_at_ms: None,
                mutation: Mutation::Extend { count: 2, seed: 0 },
            },
        ];
        let long = [Replay {
            samples: &LONG,
            ..replay(Timing::Declared, 1.0)
        }];
        let (mut state, counts) = (Replaying::<1>::new(), ReplayCounts::<1>::new());
        let (put, _) = poll(&mut state, &counts, 0, &long, Outcome::Sent);
        assert!(put.is_empty());
        let (put, _) = poll(&mut state, &counts, 100, &long, Outcome::Sent);
        assert_eq!(put[0].2.len(), 3, "the second, extended by two");
        assert_eq!(counts.of(0), (1, 1, 1, 0, 1));
    }

    #[test]
    fn the_watch_says_a_change_once() {
        let counts = ReplayCounts::<1>::new();
        let mut watch = ReplayWatch::<1>::new();
        let mut said = Vec::new();
        let mut say = |at, now| said.push((at, now));
        watch.poll(&counts, &mut say);
        counts.puts.record_sent(0);
        watch.poll(&counts, &mut say);
        watch.poll(&counts, &mut say);
        assert_eq!(said, [(0, (1, 0, 0, 0, 0))]);
    }
}
