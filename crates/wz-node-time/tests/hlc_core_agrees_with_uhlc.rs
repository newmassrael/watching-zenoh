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
