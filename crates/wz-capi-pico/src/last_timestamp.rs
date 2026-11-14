// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The last time a session gave through `z_timestamp_new`: pico's `_last_timestamp`, and the
//! mutex pico keeps beside it (`vendor/zenoh-pico/src/api/api.c` @
//! `_Z_RETURN_IF_ERR(_z_session_last_timestamp_mutex_lock(s));`).
//!
//! pico gives a program a time strictly greater than any it gave on the same session before: the
//! time read when it is later than the last one given, and the last one plus one otherwise
//! (`vendor/zenoh-pico/src/api/api.c` @ `time = s->_last_timestamp + 1;`), so a clock that stands
//! still, steps back, or is read by two threads in the same instant still yields distinct, ordered
//! stamps. Once the last time given is the greatest one there is, there is no greater to give,
//! and pico refuses (`vendor/zenoh-pico/src/api/api.c` @
//! `_Z_ERROR_RETURN(_Z_ERR_TIMESTAMP_GENERATION_FAILED);`).
//!
//! Every time the session gives passes through this one value ([`SessionTime`]), whichever clock
//! it was read from and whoever asked: a program (`z_timestamp_new`) and the session's advanced
//! publisher alike, as pico's advanced publisher stamps each sample with `z_timestamp_new`
//! (`vendor/zenoh-pico/src/api/advanced_publisher.c` @
//! `_Z_CLEAN_RETURN_IF_ERR(z_timestamp_new(timestamp, &sess_rc), _z_session_rc_drop(&sess_rc));`).
//! A program may register a clock and remove it again on a live session, and the session's stamps
//! go forward across that as they do across a clock that steps.
//!
//! pico has no node clock beside it; wz's session has one (the HLC its advanced publisher
//! proposes stamps from, and a registered clock is read through), so the session's node clock
//! learns every time given (`NodeHlc::absorb_word`), and its own next reading is past it: the two
//! are one order, and the last time given has to step in only where the clock could not learn.
//!
//! The lock is the port's short one ([`Lock`]) rather than the kernel's mutex: the work under it is
//! one comparison and one store, and an MCU image then needs no kernel object per session for it.

use alloc::sync::Arc;

use wz_capi_port::sync::Lock;
#[cfg(any(feature = "advanced", feature = "clock-source"))]
use wz_node_time::node_clock::NodeHlc;

/// Every time one session gives, and the node clock that learns them; see the module doc.
///
/// Cloned into each handle of the session that stamps (the advanced publisher's plane), and every
/// clone is the same session's: one last time given.
#[derive(Clone)]
pub(crate) struct SessionTime {
    last: Arc<LastTimestamp>,
    /// The session's node clock, which learns every time given. `None` for a session whose
    /// stamps no node clock proposes.
    #[cfg(any(feature = "advanced", feature = "clock-source"))]
    clock: Option<NodeHlc>,
}

impl SessionTime {
    /// A session that has given no time yet, whose stamps no node clock learns.
    pub(crate) fn new() -> Self {
        Self {
            last: Arc::new(LastTimestamp::new()),
            #[cfg(any(feature = "advanced", feature = "clock-source"))]
            clock: None,
        }
    }

    /// The same session, whose node clock `clock` learns every time it gives.
    #[cfg(any(feature = "advanced", feature = "clock-source"))]
    pub(crate) fn learned_by(mut self, clock: NodeHlc) -> Self {
        self.clock = Some(clock);
        self
    }

    /// The time to give for a clock that reads `reading` ([`LastTimestamp::give`]), which the
    /// session's node clock then learns. `None` when the session has no greater time to give.
    pub(crate) fn give(&self, reading: u64) -> Option<u64> {
        let given = self.last.give(reading)?;
        // A time further ahead of the clock's own reading than the clock accepts leaves the clock
        // as it was; the last time given still orders the next stamp, whichever clock reads it.
        #[cfg(any(feature = "advanced", feature = "clock-source"))]
        if let Some(clock) = &self.clock {
            let _ = clock.absorb_word(given);
        }
        Some(given)
    }

    /// The time word a sample of the session's advanced publisher carries, for the word its node
    /// clock proposes: the next time the session gives, as pico's sample takes the session's
    /// `z_timestamp_new`.
    ///
    /// Where pico refuses the put of a session with no greater time left, this stamps it with the
    /// greatest time there is: the composite that asks has no refusal to give for a stamp.
    #[cfg(feature = "advanced")]
    pub(crate) fn order_data_stamp(&self, proposed: u64) -> u64 {
        self.give(proposed).unwrap_or(u64::MAX)
    }
}

/// The last time a session gave; see the module doc.
pub(crate) struct LastTimestamp(Lock<u64>);

impl LastTimestamp {
    /// A session that has given no time yet. pico starts its session at 0
    /// (`vendor/zenoh-pico/src/session/utils.c` @ `zn->_last_timestamp = 0;`), so the first time
    /// given is at least 1.
    pub(crate) const fn new() -> Self {
        Self(Lock::new(0))
    }

    /// The time to give for a clock that reads `reading`, now the last one given: `reading` when
    /// it is later than the last, the last plus one otherwise. `None` when the last one given is
    /// `u64::MAX`, which leaves the last one as it was.
    pub(crate) fn give(&self, reading: u64) -> Option<u64> {
        self.0.with(|last| {
            let given = if reading > *last {
                reading
            } else {
                last.checked_add(1)?
            };
            *last = given;
            Some(given)
        })
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use alloc::vec::Vec;

    use super::{LastTimestamp, SessionTime};

    /// A clone of a session's times is the same session's: what one gives, the other gives after.
    #[test]
    fn every_clone_of_a_sessions_time_gives_after_the_others() {
        let program = SessionTime::new();
        let publisher = program.clone();
        assert_eq!(program.give(9), Some(9));
        assert_eq!(publisher.give(9), Some(10));
        assert_eq!(program.give(3), Some(11));
    }

    #[test]
    fn a_reading_later_than_the_last_is_given_as_it_is() {
        let last = LastTimestamp::new();
        assert_eq!(last.give(10), Some(10));
        assert_eq!(last.give(25), Some(25));
    }

    #[test]
    fn a_clock_that_stands_still_still_gives_strictly_increasing_times() {
        let last = LastTimestamp::new();
        let given: Vec<u64> = (0..4).map(|_| last.give(7).expect("room above")).collect();
        assert_eq!(given, [7, 8, 9, 10]);
    }

    #[test]
    fn a_clock_that_steps_back_is_stamped_over_until_it_passes_the_last() {
        let last = LastTimestamp::new();
        assert_eq!(last.give(100), Some(100));
        assert_eq!(last.give(40), Some(101), "behind: the last plus one");
        assert_eq!(last.give(101), Some(102), "equal: the last plus one");
        assert_eq!(last.give(500), Some(500), "past it: the clock again");
    }

    #[test]
    fn a_session_that_has_given_nothing_gives_at_least_one_for_a_clock_at_zero() {
        let last = LastTimestamp::new();
        assert_eq!(last.give(0), Some(1));
        assert_eq!(last.give(0), Some(2));
    }

    #[test]
    fn the_greatest_time_is_given_once_and_then_refused_without_moving_back() {
        let last = LastTimestamp::new();
        assert_eq!(last.give(u64::MAX - 1), Some(u64::MAX - 1));
        assert_eq!(last.give(3), Some(u64::MAX));
        assert!(last.give(3).is_none(), "no greater time to give");
        assert!(last.give(u64::MAX).is_none(), "nor for a clock at the end");
        assert!(
            last.give(0).is_none(),
            "and the refusals moved nothing back"
        );
    }

    /// Threads that read the same instant all at once are each given a time of their own, and
    /// each thread's own stamps go forward: the times given are exactly the run that starts at
    /// the reading, which a lost update would leave a duplicate in and a gap at the top of.
    #[test]
    fn threads_reading_one_instant_together_are_given_distinct_increasing_times() {
        const THREADS: u64 = 8;
        const EACH: u64 = 2_000;
        const READING: u64 = 1_000;
        let last = Arc::new(LastTimestamp::new());
        let threads: Vec<_> = (0..THREADS)
            .map(|_| {
                let last = Arc::clone(&last);
                std::thread::spawn(move || {
                    (0..EACH)
                        .map(|_| last.give(READING).expect("room above"))
                        .collect::<Vec<u64>>()
                })
            })
            .collect();
        let mut all = Vec::new();
        for thread in threads {
            let mine = thread.join().expect("the stamping thread ends");
            assert!(
                mine.windows(2).all(|pair| pair[0] < pair[1]),
                "one thread's stamps go forward"
            );
            all.extend(mine);
        }
        all.sort_unstable();
        let expected: Vec<u64> = (READING..READING + THREADS * EACH).collect();
        assert_eq!(all, expected);
    }
}
