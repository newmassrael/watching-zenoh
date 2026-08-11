// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y700 — the replay engine, driven end to end by a sink that records.

use super::*;
use wz_session_core::passive::Direction;

/// A sink that records instead of sending.
#[derive(Default)]
struct Recorder {
    seen: Vec<(u64, String, Vec<u8>)>,
    fail_at: Option<usize>,
}

impl Sink for Recorder {
    fn emit(&mut self, delay_millis: u64, keyexpr: &str, payload: &[u8]) -> Result<(), String> {
        if self.fail_at == Some(self.seen.len()) {
            return Err(String::from("the peer refused it"));
        }
        self.seen
            .push((delay_millis, keyexpr.to_string(), payload.to_vec()));
        Ok(())
    }
}

fn sample(keyexpr: &str, payload: &[u8]) -> Sample {
    Sample {
        keyexpr: keyexpr.to_string(),
        payload: payload.to_vec(),
        direction: Direction::A,
        origin: 0,
        captured_at_millis: None,
    }
}

/// R311y703 (RP4) — the same sample, with a capture time on it.
fn sample_at(keyexpr: &str, payload: &[u8], at: u64) -> Sample {
    Sample {
        captured_at_millis: Some(at),
        ..sample(keyexpr, payload)
    }
}

fn samples(items: Vec<Sample>) -> Samples {
    Samples {
        items,
        ..Default::default()
    }
}

/// R311y700 ([REDACTED-REQ]) — a capture's samples are re-published, in order, under
/// the key expressions they were captured under.
///
/// The claim is the WIRING plus the ordering: a plan built and played reaches
/// the sink with the same keyexprs and the same bytes, in the same sequence.
#[test]
fn a_plan_reaches_the_sink_in_order_and_unchanged() {
    let input = samples(vec![
        sample("demo/a", b"first"),
        sample("demo/b", b"second"),
    ]);
    let plan = plan(
        &input,
        Schedule::default(),
        Mutation::None,
        Selection::default(),
    );
    let mut sink = Recorder::default();
    assert_eq!(play(&plan, &mut sink), Ok(2));

    assert_eq!(sink.seen.len(), 2);
    assert_eq!(sink.seen[0].1, "demo/a");
    assert_eq!(sink.seen[0].2, b"first");
    assert_eq!(sink.seen[1].1, "demo/b");
    assert_eq!(sink.seen[1].2, b"second");
    // The FIRST emission waits for nothing: a plan that slept before its first
    // sample would add a gap the capture never had.
    assert_eq!(sink.seen[0].0, 0);
    assert_eq!(sink.seen[1].0, 100, "and the second waits the declared gap");
}

/// R311y700 ([REDACTED-REQ]) — the SPEED control, and it is the gaps it changes.
///
/// ## Why three speeds and not one
///
/// A schedule that returned a constant would satisfy a test of any single
/// speed. Faster must be SHORTER, slower must be LONGER, and the first delay
/// must stay zero at every speed — three independent facts, and a build that
/// got one wrong would pass a test of the others.
#[test]
fn the_speed_control_scales_the_gaps_and_never_the_first_one() {
    let base = Schedule {
        gap_millis: 200,
        speed: 1.0,
        max_gap_millis: None,
        ..Schedule::default()
    };
    assert_eq!(base.delay_before(0), 0);
    assert_eq!(base.delay_before(1), 200);

    let fast = Schedule { speed: 4.0, ..base };
    assert_eq!(fast.delay_before(1), 50, "four times as fast is a quarter");
    assert_eq!(
        fast.delay_before(0),
        0,
        "and the first still waits for nothing"
    );

    let slow = Schedule { speed: 0.5, ..base };
    assert_eq!(slow.delay_before(1), 400, "half speed is twice the gap");

    // THE CEILING, which is what stops a slow speed over a large gap from
    // producing a replay that looks like a hang.
    let capped = Schedule {
        gap_millis: 60_000,
        speed: 0.001,
        max_gap_millis: Some(5_000),
        ..Schedule::default()
    };
    assert_eq!(capped.delay_before(1), 5_000);
}

/// R311y700 ([REDACTED-REQ]) — a speed that cannot be played is REFUSED by name.
///
/// Zero is the one a caller types by accident and neither "as fast as
/// possible" nor "never" is obviously what they meant, so it is not clamped.
#[test]
fn a_speed_that_cannot_be_played_is_refused_rather_than_clamped() {
    for speed in [0.0, -1.0] {
        assert_eq!(
            Schedule {
                speed,
                ..Schedule::default()
            }
            .checked(),
            Err(ScheduleError::SpeedNotPositive)
        );
    }
    assert_eq!(
        Schedule {
            speed: f64::NAN,
            ..Schedule::default()
        }
        .checked(),
        Err(ScheduleError::SpeedNotFinite)
    );
    assert!(Schedule::default().checked().is_ok());
}

/// R311y700 ([REDACTED-REQ]) — every mutation changes the bytes, and each says
/// whether it did.
///
/// ## Why `changed` is asserted alongside the bytes
///
/// A fuzzing run whose mutation silently did nothing looks exactly like one
/// that found nothing, and the difference is the whole value of the run. So
/// each mutation is checked for what it produced AND for reporting truthfully
/// that it produced it.
#[test]
fn every_mutation_changes_the_payload_and_reports_whether_it_did() {
    let payload = b"zenoh".to_vec();

    let flip = Mutation::FlipBit { at: 0 }.apply(&payload);
    assert!(flip.changed);
    assert_eq!(flip.payload[0], b'z' ^ 1);
    assert_eq!(&flip.payload[1..], &payload[1..], "and nothing else moved");

    let cut = Mutation::Truncate { to: 2 }.apply(&payload);
    assert!(cut.changed);
    assert_eq!(cut.payload, b"ze");

    let grown = Mutation::Extend { count: 3, seed: 7 }.apply(&payload);
    assert!(grown.changed);
    assert_eq!(grown.payload.len(), 8);
    assert_eq!(&grown.payload[..5], &payload[..]);

    let scrambled = Mutation::Scramble { seed: 7 }.apply(&payload);
    assert!(scrambled.changed);
    assert_eq!(scrambled.payload.len(), payload.len(), "length is kept");
    assert_ne!(scrambled.payload, payload);

    assert!(!Mutation::None.apply(&payload).changed);
}

/// R311y700 ([REDACTED-REQ]) — a mutation whose target is outside the payload reports
/// that it changed NOTHING, rather than silently sending the original.
///
/// This is the case that makes a fuzzing campaign lie: a bit index past the
/// end, or a truncation longer than the payload, produces a run that emits the
/// captured bytes while the operator believes every emission was mutated.
#[test]
fn a_mutation_that_could_not_apply_says_so() {
    let payload = b"ze".to_vec();
    let past_the_end = Mutation::FlipBit { at: 999 }.apply(&payload);
    assert!(!past_the_end.changed);
    assert_eq!(past_the_end.payload, payload);

    let longer = Mutation::Truncate { to: 99 }.apply(&payload);
    assert!(!longer.changed);
    assert_eq!(longer.payload, payload);

    let nothing = Mutation::Extend { count: 0, seed: 1 }.apply(&payload);
    assert!(!nothing.changed);

    let empty = Mutation::Scramble { seed: 1 }.apply(&[]);
    assert!(!empty.changed, "there is nothing to scramble");
}

/// R311y700 ([REDACTED-REQ]) — a seeded mutation is REPEATABLE, and two seeds differ.
///
/// A fuzzing run that cannot be repeated is a bug report nobody can act on;
/// two seeds that produced the same bytes would make the seed a decoration.
#[test]
fn a_seeded_mutation_repeats_and_two_seeds_differ() {
    let payload = b"a zenoh sample".to_vec();
    let a = Mutation::Scramble { seed: 42 }.apply(&payload);
    let again = Mutation::Scramble { seed: 42 }.apply(&payload);
    assert_eq!(a.payload, again.payload, "the same seed, the same bytes");

    let other = Mutation::Scramble { seed: 43 }.apply(&payload);
    assert_ne!(
        a.payload, other.payload,
        "a different seed, different bytes"
    );
}

/// R311y700 ([REDACTED-REQ]) — the selector narrows the PLAN, so what is printed is
/// what will be sent.
#[test]
fn a_selector_narrows_the_plan_by_zenohs_keyexpr_dialect() {
    let input = samples(vec![
        sample("demo/a", b"in"),
        sample("other/b", b"out"),
        sample("demo/deep/c", b"in too"),
    ]);
    let plan = plan(
        &input,
        Schedule::default(),
        Mutation::None,
        Selection {
            keyexpr: Some("demo/**"),
            ..Default::default()
        },
    );
    assert_eq!(plan.emissions.len(), 2);
    assert_eq!(plan.emissions[0].keyexpr, "demo/a");
    assert_eq!(
        plan.emissions[1].keyexpr, "demo/deep/c",
        "`**` reaches past one chunk, which a literal comparison would not"
    );
    // The delays are renumbered over the SELECTED samples: a plan whose second
    // emission waited two gaps because a filtered-out sample sat between them
    // would be reporting a schedule it does not play.
    assert_eq!(plan.emissions[0].delay_millis, 0);
    assert_eq!(plan.emissions[1].delay_millis, 100);
}

/// R311y700 ([REDACTED-REQ]) — a plan states its own FLOOR: what the capture held and
/// this replay will not send.
///
/// A message whose keyexpr is a numeric id cannot be re-published under any
/// name, so it is absent from the plan. A plan that was silent about it would
/// read as "this is everything the capture carried".
#[test]
fn a_plan_says_what_the_capture_held_and_it_will_not_send() {
    let input = Samples {
        items: vec![sample("demo/a", b"x")],
        unresolved: 3,
        undecodable: 1,
        ..Default::default()
    };
    let plan = plan(
        &input,
        Schedule::default(),
        Mutation::None,
        Selection::default(),
    );
    let rendered = render(&plan);
    assert!(
        rendered.contains("3 message(s) carried a payload whose keyexpr is a numeric id"),
        "{rendered}"
    );
    assert!(
        rendered.contains("1 message(s) could not be read at all"),
        "{rendered}"
    );
}

/// R311y700 ([REDACTED-REQ]) — a sink that refuses stops the replay AND says which
/// emission it stopped at.
///
/// A peer that refused one sample will refuse the rest; a replay that reported
/// only a count would leave the reader to guess where it went wrong.
#[test]
fn a_refusal_stops_the_replay_at_the_emission_that_failed() {
    let input = samples(vec![
        sample("demo/a", b"one"),
        sample("demo/b", b"two"),
        sample("demo/c", b"three"),
    ]);
    let plan = plan(
        &input,
        Schedule::default(),
        Mutation::None,
        Selection::default(),
    );
    let mut sink = Recorder {
        fail_at: Some(1),
        ..Default::default()
    };
    assert_eq!(
        play(&plan, &mut sink),
        Err((1, String::from("the peer refused it")))
    );
    assert_eq!(sink.seen.len(), 1, "and it stopped rather than carrying on");
}

/// R311y700 — the rendering a `--dry-run` prints is built from the PLAN, so it
/// is what a live run would do rather than a second computation of it.
#[test]
fn the_dry_run_rendering_is_the_plan_itself() {
    let input = samples(vec![sample("demo/a", b"zenoh")]);
    let plan = plan(
        &input,
        Schedule {
            gap_millis: 50,
            speed: 1.0,
            max_gap_millis: None,
            ..Schedule::default()
        },
        Mutation::Truncate { to: 2 },
        Selection::default(),
    );
    let rendered = render(&plan);
    assert!(rendered.contains("1 emission(s)"), "{rendered}");
    assert!(rendered.contains("1 mutated"), "{rendered}");
    assert!(
        rendered.contains("0: +0 ms `demo/a` 2 byte(s) MUTATED (was 5)"),
        "the row carries the mutated length AND the captured one: {rendered}"
    );
}

/// R311y703 (RP4) — THE SCHEDULE CAN COME FROM THE CAPTURE, and it says per
/// emission when it could not.
///
/// ## The claim two earlier rounds made about this
///
/// R311y700 wrote that a capture's own per-message timing was out of reach and
/// R311y702 repeated it in a carry. Both were wrong:
/// `FlowDissection::packet_for` maps a stream offset to the packet that carried
/// it, and the file carries that packet's time.
///
/// ## Why the fallback is a THIRD state and not the declared one
///
/// A pair of samples with no resolvable time falls back to the declared gap,
/// and a reader who asked for capture timing must be able to see that it
/// happened. `Declared` and `Unmeasurable` produce the same NUMBER and mean
/// opposite things: one is the caller's choice, the other is a measurement that
/// was wanted and missing.
#[test]
fn a_capture_timed_schedule_uses_the_recorded_interval_and_names_the_pairs_it_could_not() {
    let input = samples(vec![
        sample_at("demo/a", b"one", 1_000),
        sample_at("demo/b", b"two", 1_350),
        // No capture time: the pair ending here cannot be measured.
        sample("demo/c", b"three"),
    ]);
    let schedule = Schedule {
        timing: Timing::Capture,
        gap_millis: 100,
        speed: 1.0,
        max_gap_millis: None,
    };

    let measured = plan(&input, schedule, Mutation::None, Selection::default());
    assert_eq!(
        measured
            .emissions
            .iter()
            .map(|e| (e.delay_millis, e.timing))
            .collect::<Vec<_>>(),
        vec![
            (0, TimingSource::Declared),
            (350, TimingSource::Measured),
            (100, TimingSource::Unmeasurable),
        ],
        "the recorded interval, then the fallback, each named"
    );

    // THE CONTROL. The same samples under the declared schedule produce the
    // flat gap throughout, so `350` above is a measurement and not a constant
    // this build would print either way.
    let declared = plan(
        &input,
        Schedule {
            timing: Timing::Declared,
            ..schedule
        },
        Mutation::None,
        Selection::default(),
    );
    assert_eq!(
        declared
            .emissions
            .iter()
            .map(|e| (e.delay_millis, e.timing))
            .collect::<Vec<_>>(),
        vec![
            (0, TimingSource::Declared),
            (100, TimingSource::Declared),
            (100, TimingSource::Declared),
        ]
    );

    // SPEED scales a measured gap exactly as it scales a declared one -- that
    // is what a speed means -- and the ceiling applies to both.
    let fast = plan(
        &input,
        Schedule {
            speed: 2.0,
            ..schedule
        },
        Mutation::None,
        Selection::default(),
    );
    assert_eq!(fast.emissions[1].delay_millis, 175);
    let capped = plan(
        &input,
        Schedule {
            max_gap_millis: Some(50),
            ..schedule
        },
        Mutation::None,
        Selection::default(),
    );
    assert_eq!(capped.emissions[1].delay_millis, 50);
}

/// R311y703 (RP4) — the measured gap is between the samples the plan KEEPS.
///
/// A selector that drops the message between two kept ones widens the real
/// interval, and reproducing the narrower one would play a conversation at a
/// pace it never had. Measured against the alternative: taking the previous
/// SAMPLE's time rather than the previous TAKEN one would print 350 here.
#[test]
fn a_selector_that_drops_a_sample_widens_the_gap_the_capture_recorded() {
    let input = samples(vec![
        sample_at("demo/a", b"one", 1_000),
        sample_at("other/b", b"skipped", 1_350),
        sample_at("demo/c", b"three", 1_900),
    ]);
    let narrowed = plan(
        &input,
        Schedule {
            timing: Timing::Capture,
            max_gap_millis: None,
            ..Schedule::default()
        },
        Mutation::None,
        Selection {
            keyexpr: Some("demo/**"),
            ..Default::default()
        },
    );
    assert_eq!(narrowed.emissions.len(), 2);
    assert_eq!(
        narrowed.emissions[1].delay_millis, 900,
        "1_900 - 1_000, the interval between the two the plan actually sends"
    );
    assert_eq!(narrowed.emissions[1].timing, TimingSource::Measured);
}

/// R311y703 (RP4) — a capture whose clock steps BACKWARDS yields zero rather
/// than an enormous gap from a wrapped subtraction.
///
/// Merged and re-timestamped capture files do this. A `u64` subtraction that
/// underflowed would produce a delay of nearly forever, which is the failure
/// mode `delay_before`'s saturating arithmetic already exists to prevent one
/// layer up.
#[test]
fn a_clock_that_steps_backwards_is_a_zero_gap_and_not_an_eternity() {
    let input = samples(vec![
        sample_at("demo/a", b"one", 2_000),
        sample_at("demo/b", b"two", 1_000),
    ]);
    let out = plan(
        &input,
        Schedule {
            timing: Timing::Capture,
            max_gap_millis: None,
            ..Schedule::default()
        },
        Mutation::None,
        Selection::default(),
    );
    assert_eq!(out.emissions[1].delay_millis, 0);
    assert_eq!(out.emissions[1].timing, TimingSource::Measured);
}
