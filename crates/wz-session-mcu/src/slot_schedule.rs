// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! When a node's periodic behaviours are due: the one schedule a publisher's puts and a querier's
//! gets are both kept on.
//!
//! A pure value. The session's application layer gives it the time and the periods, sends what it
//! says is due, and tells it how that went; what comes back is the earliest moment the drive loop is
//! to be woken at. Nothing here reads a clock or touches a session, so every rule of the cadence is
//! tested without one.
//!
//! # When something is sent
//!
//! The first poll of a session finds everything due, and each following one is a period after the
//! one before it: a loop that was late does not send what it missed, it sends once and starts
//! counting again from there. A send the session cannot take now (it is between transports, or its
//! table is full) is tried again after [`RETRY_MS`] and is not counted; one the wire cannot carry
//! moves the period on. A session that is lost starts over when the next one is established
//! ([`Schedule::disarm`]).
//!
//! This module does not link `alloc`.

/// How long after a send the session could not take, in milliseconds, it is tried again.
pub const RETRY_MS: u64 = 10;

/// Something with a period: a put to make, a query to ask.
pub trait Periodic {
    /// The time between two, in milliseconds (a period of zero is one).
    fn period_ms(&self) -> u32;
}

/// What happened to a send the schedule asked the session to make.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// It went out.
    Sent,
    /// The session could not take it now; ask again soon.
    Retry,
    /// The wire cannot carry it; the period moves on.
    Refused,
}

/// What a session's periodic behaviours are due, as deadlines in the session clock's milliseconds.
pub struct Schedule<const N: usize> {
    due: [u64; N],
    armed: bool,
}

impl<const N: usize> Schedule<N> {
    /// A schedule that has not started: its first poll finds every item due.
    pub const fn new() -> Self {
        Self {
            due: [0; N],
            armed: false,
        }
    }

    /// The session is not established: the next poll starts over, with every item due.
    pub fn disarm(&mut self) {
        self.armed = false;
    }

    /// Offer each item that is due at `now_ms` to `send`, and move its deadline by what `send`
    /// answers. Returns the earliest deadline, which the drive loop is to be woken at, or `None`
    /// when there is no item.
    pub fn poll<T: Periodic>(
        &mut self,
        now_ms: u64,
        items: &[T],
        mut send: impl FnMut(usize, &T) -> Outcome,
    ) -> Option<u64> {
        let count = items.len().min(N);
        if !self.armed {
            self.due[..count].fill(now_ms);
            self.armed = true;
        }
        let mut earliest: Option<u64> = None;
        for (at, item) in items.iter().take(count).enumerate() {
            if now_ms >= self.due[at] {
                self.due[at] = match send(at, item) {
                    Outcome::Retry => now_ms + RETRY_MS,
                    Outcome::Sent | Outcome::Refused => {
                        let period = u64::from(item.period_ms().max(1));
                        let next = self.due[at] + period;
                        // A loop that was late sends once and counts again from here.
                        if next > now_ms {
                            next
                        } else {
                            now_ms + period
                        }
                    }
                };
            }
            earliest = Some(earliest.map_or(self.due[at], |e| e.min(self.due[at])));
        }
        earliest
    }
}

impl<const N: usize> Default for Schedule<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// An item with a period, and nothing else.
    struct Every(u32);

    impl Periodic for Every {
        fn period_ms(&self) -> u32 {
            self.0
        }
    }

    /// Poll `schedule` at `now_ms`, answering each offer with `outcome`; the indexes it was offered
    /// and the deadline it returned.
    fn poll<const N: usize>(
        schedule: &mut Schedule<N>,
        now_ms: u64,
        items: &[Every],
        outcome: Outcome,
    ) -> (Vec<usize>, Option<u64>) {
        let mut offered = Vec::new();
        let next = schedule.poll(now_ms, items, |at, _| {
            offered.push(at);
            outcome
        });
        (offered, next)
    }

    #[test]
    fn the_first_poll_finds_everything_due_and_the_next_is_a_period_on() {
        let mut schedule = Schedule::<2>::new();
        let both = [Every(100), Every(250)];
        let (offered, next) = poll(&mut schedule, 1_000, &both, Outcome::Sent);
        assert_eq!(offered, [0, 1]);
        assert_eq!(next, Some(1_100), "the earliest of the two deadlines");
        let (offered, next) = poll(&mut schedule, 1_050, &both, Outcome::Sent);
        assert!(offered.is_empty(), "nothing is due before its deadline");
        assert_eq!(next, Some(1_100));
        let (offered, next) = poll(&mut schedule, 1_100, &both, Outcome::Sent);
        assert_eq!(offered, [0]);
        assert_eq!(next, Some(1_200));
    }

    #[test]
    fn the_cadence_does_not_drift_by_the_lateness_of_a_wake() {
        let mut schedule = Schedule::<1>::new();
        let one = [Every(100)];
        poll(&mut schedule, 0, &one, Outcome::Sent);
        // Woken 7 ms late: it is sent, and the next is still on the original grid.
        let (offered, next) = poll(&mut schedule, 107, &one, Outcome::Sent);
        assert_eq!(offered, [0]);
        assert_eq!(next, Some(200));
    }

    #[test]
    fn a_loop_that_missed_periods_sends_one_and_counts_again_from_now() {
        let mut schedule = Schedule::<1>::new();
        let one = [Every(100)];
        poll(&mut schedule, 0, &one, Outcome::Sent);
        let (offered, next) = poll(&mut schedule, 1_000, &one, Outcome::Sent);
        assert_eq!(offered, [0], "one send, not ten");
        assert_eq!(next, Some(1_100));
    }

    #[test]
    fn a_send_the_session_could_not_take_is_tried_again_soon_and_not_a_period_later() {
        let mut schedule = Schedule::<1>::new();
        let one = [Every(1_000)];
        let (_, next) = poll(&mut schedule, 500, &one, Outcome::Retry);
        assert_eq!(next, Some(500 + RETRY_MS));
        let (offered, next) = poll(&mut schedule, 500 + RETRY_MS, &one, Outcome::Sent);
        assert_eq!(offered, [0]);
        assert_eq!(next, Some(500 + RETRY_MS + 1_000));
    }

    #[test]
    fn a_refused_send_moves_the_period_on() {
        let mut schedule = Schedule::<1>::new();
        let one = [Every(100)];
        let (_, next) = poll(&mut schedule, 0, &one, Outcome::Refused);
        assert_eq!(next, Some(100));
    }

    #[test]
    fn a_session_that_was_lost_starts_over_when_the_next_is_established() {
        let mut schedule = Schedule::<1>::new();
        let one = [Every(100)];
        poll(&mut schedule, 0, &one, Outcome::Sent);
        schedule.disarm();
        let (offered, next) = poll(&mut schedule, 40, &one, Outcome::Sent);
        assert_eq!(offered, [0], "due at once, not at 100");
        assert_eq!(next, Some(140));
    }

    #[test]
    fn a_node_with_nothing_periodic_wants_no_wake() {
        let mut schedule = Schedule::<0>::new();
        let (offered, next) = poll(&mut schedule, 10, &[], Outcome::Sent);
        assert!(offered.is_empty());
        assert_eq!(next, None);
    }

    #[test]
    fn a_period_of_zero_is_one_millisecond_and_not_a_spin() {
        let mut schedule = Schedule::<1>::new();
        let one = [Every(0)];
        let (_, next) = poll(&mut schedule, 5, &one, Outcome::Sent);
        assert_eq!(next, Some(6));
    }
}
