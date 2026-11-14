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
//! Every time `z_timestamp_new` gives passes through this one value, whichever clock it was read
//! from: a program may register a clock and remove it again on a live session, and the session's
//! stamps go forward across that as they do across a clock that steps.
//!
//! The lock is the port's short one ([`Lock`]) rather than the kernel's mutex: the work under it is
//! one comparison and one store, and an MCU image then needs no kernel object per session for it.

use wz_capi_port::sync::Lock;

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

    use super::LastTimestamp;

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
