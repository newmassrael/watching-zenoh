// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The rate arithmetic against a brute-force search, and the exchange rules against
//! a model of the board's side. Nothing here touches a block.

use super::*;
use std::vec;
use std::vec::Vec;

/// The least `divider * oversample` whose rate does not exceed `target`, found by
/// trying every pair: the oracle the arithmetic is held to, which shares no code
/// with it.
fn brute_least_product(source: u32, target: u32, divider_max: u32) -> Option<u64> {
    let mut least: Option<u64> = None;
    for divider in 1..=u64::from(divider_max) {
        for oversample in u64::from(OVERSAMPLE_MIN)..=u64::from(OVERSAMPLE_MAX) {
            let product = divider * oversample;
            // `source / product <= target`, without rounding either side.
            if product * u64::from(target) >= u64::from(source) {
                least = Some(least.map_or(product, |l| l.min(product)));
            }
        }
    }
    least
}

/// For a grid of clocks and targets and both a one-step and an 8-bit divider, the
/// chosen pair is the one the exhaustive search finds, its rate never exceeds the
/// target, and a target nothing reaches is refused with the slowest the block can
/// do.
#[test]
fn the_rate_is_the_fastest_that_does_not_exceed_the_target() {
    let sources = [
        24_000_000u32,
        50_000_000,
        80_000_000,
        100_000_000,
        160_000_000,
        240_000_000,
    ];
    let targets = [
        100_000u32, 1_000_000, 2_500_000, 4_000_000, 5_000_000, 7_000_000, 10_000_000, 12_500_000,
        15_000_000, 25_000_000, 33_333_333,
    ];
    let mut compared = 0;
    for &source in &sources {
        for &target in &targets {
            for divider_max in [1u32, 256] {
                let chosen = Rate::choose(source, target, divider_max);
                match brute_least_product(source, target, divider_max) {
                    Some(product) => {
                        let rate = chosen.unwrap_or_else(|e| {
                            panic!("{source}/{target}/{divider_max}: a pair exists, got {e:?}")
                        });
                        assert_eq!(
                            u64::from(rate.divider) * u64::from(rate.oversample),
                            product,
                            "{source}/{target}/{divider_max}: the least product"
                        );
                        assert!(rate.achieved_hz <= target, "never above the target");
                        assert!((1..=divider_max).contains(&rate.divider));
                        assert!((OVERSAMPLE_MIN..=OVERSAMPLE_MAX).contains(&rate.oversample));
                        assert_eq!(
                            u64::from(rate.achieved_hz),
                            u64::from(source) / product,
                            "the rate is the clock over the pair, rounded down"
                        );
                    }
                    None => {
                        let slowest = u64::from(source)
                            / (u64::from(divider_max) * u64::from(OVERSAMPLE_MAX));
                        assert_eq!(
                            chosen,
                            Err(RateError::TooSlow {
                                slowest_hz: slowest as u32
                            }),
                            "{source}/{target}/{divider_max}: nothing reaches it"
                        );
                    }
                }
                compared += 1;
            }
        }
    }
    assert_eq!(
        compared,
        sources.len() * targets.len() * 2,
        "every case ran"
    );
}

/// Two pairs can give one rate; the larger oversample factor samples each bit
/// more times, so it wins.
#[test]
fn of_two_pairs_giving_one_rate_the_larger_oversample_is_taken() {
    // 100 MHz down to 12.5 MHz is a product of 8: 1 x 8 and 2 x 4 both make it.
    assert_eq!(
        Rate::choose(100_000_000, 12_500_000, 256),
        Ok(Rate {
            divider: 1,
            oversample: 8,
            achieved_hz: 12_500_000
        })
    );
    // A product of 32 is 2 x 16, 4 x 8 and 8 x 4.
    assert_eq!(
        Rate::choose(100_000_000, 3_125_000, 256),
        Ok(Rate {
            divider: 2,
            oversample: 16,
            achieved_hz: 3_125_000
        })
    );
}

/// A target above what the block can do is not refused: the fastest it has is
/// returned, which is one quarter of its clock.
#[test]
fn a_target_above_the_block_gets_the_fastest_it_has() {
    assert_eq!(
        Rate::choose(100_000_000, 100_000_000, 256),
        Ok(Rate {
            divider: 1,
            oversample: OVERSAMPLE_MIN,
            achieved_hz: 25_000_000
        })
    );
}

#[test]
fn a_rate_that_cannot_be_made_is_refused_for_the_reason_it_cannot() {
    assert_eq!(Rate::choose(0, 1_000_000, 256), Err(RateError::ZeroSource));
    assert_eq!(
        Rate::choose(100_000_000, 0, 256),
        Err(RateError::ZeroTarget)
    );
    assert_eq!(
        Rate::choose(100_000_000, 1_000_000, 0),
        Err(RateError::NoDivider)
    );
    assert_eq!(
        Rate::choose(100_000_000, 1, 256),
        Err(RateError::TooSlow { slowest_hz: 24_414 }),
        "the slowest is the clock over the largest divider and oversample"
    );
}

#[test]
fn the_four_modes_are_the_usual_polarity_and_phase() {
    let modes = [
        (SpiMode::Mode0, 0u8, false, false),
        (SpiMode::Mode1, 1, false, true),
        (SpiMode::Mode2, 2, true, false),
        (SpiMode::Mode3, 3, true, true),
    ];
    for (mode, number, cpol, cpha) in modes {
        assert_eq!(mode.number(), number, "{mode:?}");
        assert_eq!(mode.cpol(), cpol, "{mode:?}");
        assert_eq!(mode.cpha(), cpha, "{mode:?}");
    }
}

/// The board's side as a model: it records every exchange it is asked for, answers
/// each byte with the one it was sent plus one, and can be told to fail.
#[derive(Default)]
struct Board {
    seen: Vec<Vec<u8>>,
    fail: bool,
}

impl ScbMaster for Board {
    type Error = &'static str;

    fn exchange(&mut self, tx: &[u8], rx: &mut [u8]) -> Result<(), Self::Error> {
        self.seen.push(tx.to_vec());
        if self.fail {
            return Err("the block did not answer");
        }
        for (out, back) in tx.iter().zip(rx.iter_mut()) {
            *back = out.wrapping_add(1);
        }
        Ok(())
    }
}

/// What the rules refuse never reaches the board, because a refused exchange that
/// had been sent anyway would be the very cut in two it exists to prevent.
#[test]
fn an_exchange_the_rules_refuse_is_not_sent() {
    let mut spi = ScbSpi::new(Board::default());
    let mut rx3 = [0u8; 3];
    assert_eq!(
        spi.transfer(&[1, 2], &mut rx3),
        Err(Error::LengthMismatch { tx: 2, rx: 3 })
    );
    assert_eq!(spi.transfer(&[], &mut []), Err(Error::Empty));
    let long = vec![0u8; FIFO_BYTES + 1];
    let mut back = vec![0u8; FIFO_BYTES + 1];
    assert_eq!(
        spi.transfer(&long, &mut back),
        Err(Error::TooLong {
            len: FIFO_BYTES + 1
        })
    );
    assert!(
        spi.master_mut().seen.is_empty(),
        "none of the three was sent"
    );
}

/// What the rules allow reaches the board once, byte for byte, and the board's
/// answer comes back; the FIFO's own size is allowed, and a failure is the
/// board's and is passed on as such.
#[test]
fn an_allowed_exchange_goes_through_once_and_a_failure_is_passed_on() {
    let mut spi = ScbSpi::new(Board::default());
    let mut rx = [0u8; 4];
    spi.transfer(&[10, 20, 30, 255], &mut rx).expect("allowed");
    assert_eq!(spi.master_mut().seen, [vec![10u8, 20, 30, 255]]);
    assert_eq!(rx, [11, 21, 31, 0], "the board's answer, untouched");

    let full = vec![7u8; FIFO_BYTES];
    let mut back = vec![0u8; FIFO_BYTES];
    spi.transfer(&full, &mut back)
        .expect("the FIFO's own size fits");
    assert_eq!(spi.master_mut().seen.len(), 2);
    assert!(back.iter().all(|&b| b == 8));

    spi.master_mut().fail = true;
    assert_eq!(
        spi.transfer(&[1], &mut [0]),
        Err(Error::Master("the block did not answer"))
    );
    assert_eq!(spi.master_mut().seen.len(), 3, "it was asked, and said no");
}
