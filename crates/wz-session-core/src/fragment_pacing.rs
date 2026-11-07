// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! How fast the fragments of one message leave a datagram link: the rule of the
//! `datagram-fragment-pacing` policy, stated once.
//!
//! # The rule
//!
//! A [`FragmentPacer`](crate::fragment_pacing::FragmentPacer) sees each datagram a link's
//! writer is about to write, and the time. A
//! datagram that is not a fragment is never delayed and ends the run of fragments before it. Of
//! a run of fragments, at most `burst` are written back to back; the next waits until `gap_us`
//! has passed since the last datagram was written, and starts a new run. A wait that has already
//! passed (the writer was idle) is not waited again.
//!
//! The rule takes the time as an argument and owns no clock, so it can be tested at every value
//! of its two numbers and be driven by any engine's clock: the tokio writers of UDP unicast and
//! multicast read it today. It sits at the writer and not at the sender that cuts the message
//! into fragments: the sender only queues them, held for room as long as the link's queue is
//! full, while the datagrams leave at the writer, so that is where their spacing is decided.
//!
//! # What is a fragment
//!
//! The first byte of a transport message is its header, whose low five bits are the message id
//! (`T_MID_FRAGMENT`, 0x06). The session writes every fragment as a datagram of its own, so the
//! first byte of a datagram names it.

use crate::policy::SessionPolicy;

/// The message id of a transport `Fragment` (the low five bits of a header).
const T_MID_FRAGMENT: u8 = 0x06;

/// The mask of a header's message id.
const MID_MASK: u8 = 0x1f;

const _: () = assert!(
    crate::caps::DATAGRAM_FRAGMENT_BURST >= 1,
    "DATAGRAM_FRAGMENT_BURST is at least 1"
);
const _: () = assert!(
    crate::caps::DATAGRAM_FRAGMENT_GAP_US >= 1
        && crate::caps::DATAGRAM_FRAGMENT_GAP_US <= 1_000_000,
    "DATAGRAM_FRAGMENT_GAP_US is between 1 and 1000000"
);

/// Whether `datagram` is a transport `Fragment`.
pub const fn is_fragment(datagram: &[u8]) -> bool {
    match datagram {
        [header, ..] => *header & MID_MASK == T_MID_FRAGMENT,
        [] => false,
    }
}

/// The pacing of one writer's fragments. See the module note.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragmentPacer {
    burst: u32,
    gap_us: u64,
    /// Fragments written since the last wait or the last datagram that was not a fragment.
    run: u32,
    /// When the last datagram was written, in the writer's microseconds.
    written_at_us: u64,
}

impl FragmentPacer {
    /// A pacer that lets `burst` fragments through back to back and holds the next one until
    /// `gap_us` after the last write. `burst` is read as at least 1.
    pub const fn new(burst: u32, gap_us: u64) -> Self {
        Self {
            burst: if burst == 0 { 1 } else { burst },
            gap_us,
            run: 0,
            written_at_us: 0,
        }
    }

    /// The pacer of this build: `None` when the `datagram-fragment-pacing` policy is off, which is
    /// upstream's behaviour, so a writer that holds none writes as it always did.
    pub const fn of_build() -> Option<Self> {
        if SessionPolicy::from_build().datagram_fragment_pacing {
            Some(Self::new(
                crate::caps::DATAGRAM_FRAGMENT_BURST as u32,
                crate::caps::DATAGRAM_FRAGMENT_GAP_US as u64,
            ))
        } else {
            None
        }
    }

    /// How long, in microseconds, the writer waits before it writes `datagram` at `now_us`: `0`
    /// to write at once. Call it once for each datagram, then [`Self::wrote`] when the write has
    /// returned.
    pub fn wait_before(&mut self, datagram: &[u8], now_us: u64) -> u64 {
        if !is_fragment(datagram) {
            self.run = 0;
            return 0;
        }
        let wait = if self.run >= self.burst {
            self.run = 0;
            self.gap_us
                .saturating_sub(now_us.saturating_sub(self.written_at_us))
        } else {
            0
        };
        self.run = self.run.saturating_add(1);
        wait
    }

    /// Note that the datagram asked about last has been written, at `now_us`.
    pub fn wrote(&mut self, now_us: u64) {
        self.written_at_us = now_us;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FRAGMENT: [u8; 2] = [0x06 | 0x40, 0];
    const FRAME: [u8; 2] = [0x05, 0];

    /// Write `datagrams` one after another, the writer taking `write_us` to write each, and
    /// return the wait asked before each.
    fn waits(pacer: &mut FragmentPacer, datagrams: &[&[u8]], write_us: u64) -> std::vec::Vec<u64> {
        let mut now = 100;
        let mut out = std::vec::Vec::new();
        for datagram in datagrams {
            let wait = pacer.wait_before(datagram, now);
            out.push(wait);
            now += wait + write_us;
            pacer.wrote(now);
        }
        out
    }

    #[test]
    fn a_fragment_is_the_datagram_whose_header_names_one() {
        assert!(is_fragment(&FRAGMENT));
        assert!(is_fragment(&[0xe6]));
        assert!(!is_fragment(&FRAME));
        assert!(!is_fragment(&[]));
        // The id is the low five bits: a header with another id and a fragment's high bits is not.
        assert!(!is_fragment(&[0xe5]));
    }

    #[test]
    fn at_most_burst_fragments_leave_in_a_row_then_one_waits_the_gap() {
        let mut pacer = FragmentPacer::new(3, 1000);
        let run = [&FRAGMENT[..]; 7];
        // The gap is counted from the end of the last write, and the next fragment is asked about
        // at that moment, so the wait is the whole gap.
        assert_eq!(
            waits(&mut pacer, &run, 10),
            [0, 0, 0, 1000, 0, 0, 1000],
            "three, a wait, three, a wait"
        );
    }

    #[test]
    fn a_burst_of_one_waits_between_every_fragment() {
        let mut pacer = FragmentPacer::new(1, 500);
        let run = [&FRAGMENT[..]; 3];
        assert_eq!(waits(&mut pacer, &run, 0), [0, 500, 500]);
    }

    #[test]
    fn a_datagram_that_is_not_a_fragment_is_never_delayed_and_ends_the_run() {
        let mut pacer = FragmentPacer::new(2, 1000);
        let datagrams: [&[u8]; 7] = [
            &FRAGMENT, &FRAGMENT, &FRAME, &FRAGMENT, &FRAGMENT, &FRAGMENT, &FRAME,
        ];
        // The frame in the middle starts the run again, so the second two are not held, and the
        // third of the second run is.
        assert_eq!(waits(&mut pacer, &datagrams, 0), [0, 0, 0, 0, 0, 1000, 0]);
    }

    #[test]
    fn a_wait_that_has_already_passed_is_not_waited_again() {
        let mut pacer = FragmentPacer::new(1, 1000);
        assert_eq!(pacer.wait_before(&FRAGMENT, 0), 0);
        pacer.wrote(0);
        // The writer was idle for longer than the gap before the next fragment came.
        assert_eq!(pacer.wait_before(&FRAGMENT, 5000), 0);
        pacer.wrote(5000);
        // And one that came 400 us after the last write waits the 600 that remain.
        assert_eq!(pacer.wait_before(&FRAGMENT, 5400), 600);
    }

    #[test]
    fn a_burst_of_zero_is_read_as_one() {
        let mut pacer = FragmentPacer::new(0, 100);
        let run = [&FRAGMENT[..]; 2];
        assert_eq!(waits(&mut pacer, &run, 0), [0, 100]);
    }

    #[test]
    fn the_pacer_of_a_build_is_none_when_the_policy_is_off_and_holds_its_two_limits_when_on() {
        // The policy is off unless the build states it, and then no pacer exists; the build
        // that states it has the pacer of its two limits. Each build runs the arm that is its own.
        let expected = SessionPolicy::from_build()
            .datagram_fragment_pacing
            .then(|| {
                FragmentPacer::new(
                    crate::caps::DATAGRAM_FRAGMENT_BURST as u32,
                    crate::caps::DATAGRAM_FRAGMENT_GAP_US as u64,
                )
            });
        assert_eq!(FragmentPacer::of_build(), expected);
        // And the pacer a build has behaves by those limits: the first fragment past the burst
        // waits the gap, in the build that has one.
        if let Some(mut pacer) = FragmentPacer::of_build() {
            let burst = crate::caps::DATAGRAM_FRAGMENT_BURST;
            for _ in 0..burst {
                assert_eq!(pacer.wait_before(&FRAGMENT, 0), 0);
            }
            pacer.wrote(0);
            assert_eq!(
                pacer.wait_before(&FRAGMENT, 0),
                crate::caps::DATAGRAM_FRAGMENT_GAP_US as u64
            );
        }
    }
}
