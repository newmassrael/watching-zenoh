// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz_session_core::hlc::HlcCore` against `uhlc::HLC`, over the same random clock traces.
//!
//! The core is `uhlc`'s arithmetic in one atomic word (`hlc.rs` says why it exists). This is the
//! test that says the two are the same: every operation is applied to both, and every stamp and
//! every refusal must agree, including after the clock has stepped back, frozen and jumped.
//!
//! `uhlc` takes its clock as a plain `fn() -> NTP64`, so the trace's clock lives in a
//! thread-local and each test runs the whole trace on its own thread.

#![cfg(feature = "time-hlc")]

use std::cell::Cell;
use std::time::Duration;

use wz_session_core::hlc::{ForwardStepRefused, HlcCore};
use wz_session_core::ntp64::Ntp64;

thread_local! {
    static NOW: Cell<u64> = const { Cell::new(0) };
}

fn trace_clock() -> uhlc::NTP64 {
    uhlc::NTP64(NOW.with(Cell::get))
}

/// A small deterministic generator, so a failing seed is a failing seed everywhere.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

fn uhlc_with_delta(delta: Duration) -> uhlc::HLC {
    uhlc::HLCBuilder::new()
        .with_clock(trace_clock)
        .with_id(uhlc::ID::try_from(&[1u8][..]).expect("a non-zero id"))
        .with_max_delta(delta)
        .build()
}

fn second() -> u64 {
    Ntp64::FRAC_PER_SEC
}

/// Move the trace's clock: forward a little, freeze, step back, or jump ahead.
fn move_clock(rng: &mut Rng) {
    let now = NOW.with(Cell::get);
    let next = match rng.below(8) {
        0..=2 => now.saturating_add(rng.below(second() / 100)),
        3 | 4 => now,
        5 => now.saturating_sub(rng.below(second() * 5)),
        6 => now.saturating_add(rng.below(second() * 3)),
        _ => now.saturating_add(second() * 3600 + rng.below(second())),
    };
    NOW.with(|c| c.set(next));
}

fn run_trace(seed: u64, delta: Duration, steps: usize) {
    let mut rng = Rng(seed | 1);
    NOW.with(|c| c.set(1_700_000_000u64 << 32));
    let reference = uhlc_with_delta(delta);
    let core = HlcCore::new();
    let bound = Ntp64::from_duration(delta);
    assert_eq!(
        bound.as_word(),
        reference.get_delta().as_u64(),
        "the bound is not the one uhlc derives from the same span"
    );
    let mut refusals = 0usize;
    for step in 0..steps {
        move_clock(&mut rng);
        let now = Ntp64::from_word(NOW.with(Cell::get));
        if rng.below(3) == 0 {
            // A remote timestamp around the reading: behind, level, within the bound, past it.
            let offset = match rng.below(4) {
                0 => -(rng.below(second() * 2) as i128),
                1 => 0,
                2 => rng.below(bound.as_word().max(1)) as i128,
                _ => bound.as_word() as i128 + 1 + rng.below(second()) as i128,
            };
            let remote_word =
                (now.as_word() as i128 + offset).clamp(1, i128::from(u64::MAX)) as u64;
            let remote_ts = uhlc::Timestamp::new(
                uhlc::NTP64(remote_word),
                uhlc::ID::try_from(&[2u8][..]).expect("a non-zero id"),
            );
            let want = reference.update_with_timestamp(&remote_ts).is_ok();
            let got = core.update_with_timestamp(now, Ntp64::from_word(remote_word), bound);
            assert_eq!(
                got.is_ok(),
                want,
                "seed {seed} step {step}: the core and uhlc disagree on refusing {remote_word:#x}"
            );
            if got.is_err() {
                assert_eq!(got, Err(ForwardStepRefused));
                refusals += 1;
            }
        } else {
            let want = reference.new_timestamp().get_time().as_u64();
            let got = core.new_timestamp(now).as_word();
            assert_eq!(
                got, want,
                "seed {seed} step {step}: the stamps differ (core {got:#x}, uhlc {want:#x})"
            );
        }
    }
    // The reference's own refusals are what the trace exercises; a trace that never refused would
    // prove nothing about the refusal arm.
    assert!(
        refusals > 0,
        "seed {seed}: the trace never reached a refusal"
    );
}

#[test]
fn the_core_and_uhlc_stamp_and_refuse_alike_over_random_clock_traces() {
    for seed in 1..=400u64 {
        run_trace(
            seed.wrapping_mul(0x9E37_79B9_7F4A_7C15),
            Duration::from_millis(500),
            600,
        );
    }
}

/// The node's clock as a caller that holds it sees it: [`NodeHlc::next_word`],
/// [`NodeHlc::absorb_word`] and [`NodeHlc::max_delta_word`], which the Rust API lends as a
/// session's clock in the place of `uhlc::HLC` (`Session::hlc`). The node reads the trace through
/// its own source port, `uhlc` through its `fn() -> NTP64`, and the two read the same word, so
/// every stamp, every refusal and the bound must agree.
mod the_node_clock_lent_as_uhlc {
    use std::cell::Cell;
    use std::time::Duration;

    use wz_codecs::whatami::WhatAmI;
    use wz_node_time::node_clock::{NodeHlc, TimestampingEnabled};
    use wz_session_core::epoch::{EpochSource, EpochUnavailable, SinceEpoch};
    use wz_session_core::ntp64::Ntp64;

    use super::Rng;

    thread_local! {
        static NANOS: Cell<u64> = const { Cell::new(0) };
    }

    fn reading() -> SinceEpoch {
        let nanos = NANOS.with(Cell::get);
        SinceEpoch {
            secs: nanos / 1_000_000_000,
            nanos: (nanos % 1_000_000_000) as u32,
        }
    }

    fn word_now() -> u64 {
        let at = reading();
        Ntp64::from_unix(at.secs, at.nanos).as_word()
    }

    fn trace_clock() -> uhlc::NTP64 {
        uhlc::NTP64(word_now())
    }

    /// The node's source: the same instant, through the port a node reads.
    struct TraceEpoch;

    impl EpochSource for TraceEpoch {
        fn try_since_epoch(&self) -> Result<SinceEpoch, EpochUnavailable> {
            Ok(reading())
        }
    }

    /// The bound a node runs with, by the rule a node reads it with: `UHLC_MAX_DELTA_MS`, else the
    /// limit's default. A stated value the node refuses leaves it with no clock to compare, so this
    /// test is not run under one.
    fn node_bound() -> Duration {
        let ms = match std::env::var("UHLC_MAX_DELTA_MS") {
            Err(std::env::VarError::NotPresent) => {
                wz_session_core::caps::CLOCK_MAX_FORWARD_STEP_MS as u64
            }
            stated => stated
                .ok()
                .and_then(|text| text.parse::<u64>().ok())
                .expect("UHLC_MAX_DELTA_MS is a whole number of milliseconds"),
        };
        Duration::from_millis(ms)
    }

    fn run_trace(seed: u64, steps: usize) {
        let mut rng = Rng(seed | 1);
        NANOS.with(|c| c.set(1_700_000_000u64 * 1_000_000_000));
        let id = [0x5au8, 0x01];
        let node = NodeHlc::for_node_over_source_by(
            &id,
            WhatAmI::Peer,
            TimestampingEnabled::all(true),
            TraceEpoch,
            &wz_session_core::policy::SessionPolicy::defaults(),
            &wz_session_core::limits::RuntimeLimits::BUILD,
        );
        let reference = uhlc::HLCBuilder::new()
            .with_clock(trace_clock)
            .with_id(uhlc::ID::try_from(&id[..]).expect("a non-zero id"))
            .with_max_delta(node_bound())
            .build();
        assert_eq!(
            node.max_delta_word(),
            Some(reference.get_delta().as_u64()),
            "the bound is not uhlc's"
        );
        assert_eq!(node.stamp_zid(), Some(&id[..]));
        let bound = reference.get_delta().as_u64();
        let mut refusals = 0usize;
        for step in 0..steps {
            let now = NANOS.with(Cell::get);
            let next = match rng.below(8) {
                0..=2 => now.saturating_add(rng.below(10_000_000)),
                3 | 4 => now,
                5 => now.saturating_sub(rng.below(5_000_000_000)),
                6 => now.saturating_add(rng.below(3_000_000_000)),
                _ => now.saturating_add(3_600_000_000_000 + rng.below(1_000_000_000)),
            };
            NANOS.with(|c| c.set(next));
            if rng.below(3) == 0 {
                let word = word_now();
                let offset = match rng.below(4) {
                    0 => -(rng.below(Ntp64::FRAC_PER_SEC * 2) as i128),
                    1 => 0,
                    2 => rng.below(bound.max(1)) as i128,
                    _ => bound as i128 + 1 + rng.below(Ntp64::FRAC_PER_SEC) as i128,
                };
                let remote = (word as i128 + offset).clamp(1, i128::from(u64::MAX)) as u64;
                let remote_ts = uhlc::Timestamp::new(
                    uhlc::NTP64(remote),
                    uhlc::ID::try_from(&[2u8][..]).expect("a non-zero id"),
                );
                let want = reference.update_with_timestamp(&remote_ts).is_ok();
                let got = node.absorb_word(remote);
                assert_eq!(
                    got,
                    Some(want),
                    "seed {seed} step {step}: the node and uhlc disagree on refusing {remote:#x}"
                );
                if !want {
                    refusals += 1;
                }
            } else {
                let want = reference.new_timestamp().get_time().as_u64();
                let got = node.next_word();
                assert_eq!(
                    got,
                    Some(want),
                    "seed {seed} step {step}: the stamps differ (uhlc {want:#x})"
                );
            }
        }
        assert!(
            refusals > 0,
            "seed {seed}: the trace never reached a refusal"
        );
    }

    #[test]
    fn the_node_clock_stamps_and_refuses_as_uhlc_over_random_clock_traces() {
        for seed in 1..=200u64 {
            run_trace(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15), 600);
        }
    }

    #[test]
    fn a_node_whose_role_does_not_stamp_lends_no_clock() {
        let node = NodeHlc::for_node_over_source_by(
            &[0x5a],
            WhatAmI::Peer,
            TimestampingEnabled::default(),
            TraceEpoch,
            &wz_session_core::policy::SessionPolicy::defaults(),
            &wz_session_core::limits::RuntimeLimits::BUILD,
        );
        assert_eq!(node.next_word(), None);
        assert_eq!(node.absorb_word(1), None);
        assert_eq!(node.max_delta_word(), None);
        assert_eq!(node.stamp_zid(), None);
    }
}

#[test]
fn they_agree_under_other_bounds_too() {
    for (index, millis) in [0u64, 1, 20, 3_000].into_iter().enumerate() {
        for seed in 1..=60u64 {
            run_trace(
                (seed + 1000 * index as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15),
                Duration::from_millis(millis),
                400,
            );
        }
    }
}
