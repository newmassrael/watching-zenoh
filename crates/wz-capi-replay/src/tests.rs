// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Round 2441 (open-debt item 693) — the door, driven the way C drives it.
//!
//! Every test here calls through the `extern "C"` functions with raw pointers,
//! not through `wz_replay`. A test that reached past the ABI would be checking
//! the library this crate wraps rather than the wrapping, and the wrapping is
//! the whole of what this crate adds.

use super::*;

/// Pace `times` and hand back the records plus the total and the code.
fn pace(
    timing: c_int,
    gap: u64,
    speed: f64,
    max_gap: u64,
    max_total: u64,
    times: Option<&[u64]>,
) -> (c_int, Vec<WzReplayEmission>, u64) {
    let count = times.map_or(0, <[u64]>::len);
    let mut out = vec![
        WzReplayEmission {
            delay_millis: u64::MAX,
            source: -1,
            reserved: -1,
        };
        count
    ];
    let mut total = u64::MAX;
    let code = unsafe {
        wz_replay_plan_delays(
            timing,
            gap,
            speed,
            max_gap,
            max_total,
            times.map_or(core::ptr::null(), <[u64]>::as_ptr),
            count,
            out.as_mut_ptr(),
            out.len(),
            &mut total,
        )
    };
    (code, out, total)
}

/// Mutate through the door, sizing first and reading second the way the header
/// tells a caller to.
fn mutate(kind: c_int, operand: u64, seed: u64, payload: &[u8]) -> (c_int, Vec<u8>, bool) {
    let mut needed = usize::MAX;
    let mut changed = -1;
    let sizing = unsafe {
        wz_replay_mutate(
            kind,
            operand,
            seed,
            payload.as_ptr(),
            payload.len(),
            core::ptr::null_mut(),
            0,
            &mut needed,
            &mut changed,
        )
    };
    if sizing != WZ_REPLAY_ERR_BUFFER_TOO_SMALL {
        return (sizing, Vec::new(), changed == 1);
    }
    let mut buf = vec![0u8; needed];
    let code = unsafe {
        wz_replay_mutate(
            kind,
            operand,
            seed,
            payload.as_ptr(),
            payload.len(),
            buf.as_mut_ptr(),
            buf.len(),
            &mut needed,
            &mut changed,
        )
    };
    buf.truncate(needed);
    (code, buf, changed == 1)
}

/// THE SENTINEL A CONSUMER FEEDS IN IS THE ONE THE READ HALF HANDS OUT.
///
/// The consumer report asked for "the sentinel `wz_dissect_record` already
/// uses", and the whole value of answering that is that a caller can pass
/// `wz_dissect_record.ts_ns` straight in. Two libraries agreeing on a number is
/// exactly the kind of fact that stops being true quietly, so it is measured
/// against the other crate rather than asserted in a comment beside a literal.
///
/// `wz-capi-dissect` is a DEV-dependency and must stay one: this library does
/// not link the read half, and a real dependency would make a consumer that
/// only paces a plan carry a dissector.
#[test]
fn the_no_timestamp_sentinel_is_the_dissect_one() {
    assert_eq!(
        WZ_REPLAY_NO_TIMESTAMP,
        wz_capi_dissect::WZ_DISSECT_NO_TIMESTAMP,
        "a consumer feeds wz_dissect_record.ts_ns straight into \
         wz_replay_plan_delays; the two sentinels must be one number"
    );
}

/// The first emission waits for nothing, on either clock.
#[test]
fn the_first_emission_has_no_delay() {
    for timing in [WZ_REPLAY_TIMING_DECLARED, WZ_REPLAY_TIMING_CAPTURE] {
        let (code, out, total) = pace(
            timing,
            100,
            1.0,
            WZ_REPLAY_NO_CEILING,
            WZ_REPLAY_NO_CEILING,
            Some(&[1_000]),
        );
        assert_eq!(code, WZ_REPLAY_OK);
        assert_eq!(out[0].delay_millis, 0);
        assert_eq!(out[0].source, WZ_REPLAY_SOURCE_DECLARED);
        assert_eq!(total, 0);
    }
}

/// A DECLARED plan spaces by the gap, scaled by the speed, whatever the capture
/// says.
#[test]
fn declared_timing_ignores_the_capture_clock() {
    let (code, out, total) = pace(
        WZ_REPLAY_TIMING_DECLARED,
        100,
        2.0,
        WZ_REPLAY_NO_CEILING,
        WZ_REPLAY_NO_CEILING,
        // Capture times an hour apart, which a declared plan must not read.
        Some(&[0, 3_600_000, 7_200_000]),
    );
    assert_eq!(code, WZ_REPLAY_OK);
    assert_eq!(out[1].delay_millis, 50);
    assert_eq!(out[2].delay_millis, 50);
    assert!(out.iter().all(|e| e.source == WZ_REPLAY_SOURCE_DECLARED));
    assert_eq!(total, 100);
}

/// THE THREE SOURCES ARE TOLD APART, which is the distinction the consumer said
/// they would most likely have got wrong.
///
/// The same 100 ms delay must carry a different word depending on whether the
/// reader asked for capture timing and was not answered, or never asked. That
/// is verbatim what the downstream test pins, so it is what this door has to
/// answer.
#[test]
fn the_same_delay_carries_a_different_source() {
    let never_asked = pace(
        WZ_REPLAY_TIMING_DECLARED,
        100,
        1.0,
        WZ_REPLAY_NO_CEILING,
        WZ_REPLAY_NO_CEILING,
        Some(&[0, 500]),
    );
    let asked_unanswered = pace(
        WZ_REPLAY_TIMING_CAPTURE,
        100,
        1.0,
        WZ_REPLAY_NO_CEILING,
        WZ_REPLAY_NO_CEILING,
        Some(&[WZ_REPLAY_NO_TIMESTAMP, WZ_REPLAY_NO_TIMESTAMP]),
    );
    assert_eq!(never_asked.1[1].delay_millis, 100);
    assert_eq!(asked_unanswered.1[1].delay_millis, 100);
    assert_eq!(never_asked.1[1].source, WZ_REPLAY_SOURCE_DECLARED);
    assert_eq!(
        asked_unanswered.1[1].source, WZ_REPLAY_SOURCE_UNMEASURABLE,
        "a fallback that reads like a choice hides that a measurement was \
         wanted and missing"
    );
}

/// A MEASURED gap comes from the capture and is scaled like any other.
#[test]
fn capture_timing_measures_and_scales() {
    let (code, out, total) = pace(
        WZ_REPLAY_TIMING_CAPTURE,
        100,
        2.0,
        WZ_REPLAY_NO_CEILING,
        WZ_REPLAY_NO_CEILING,
        Some(&[1_000, 1_400, 2_400]),
    );
    assert_eq!(code, WZ_REPLAY_OK);
    assert_eq!(out[1].delay_millis, 200);
    assert_eq!(out[1].source, WZ_REPLAY_SOURCE_MEASURED);
    assert_eq!(out[2].delay_millis, 500);
    assert_eq!(out[2].source, WZ_REPLAY_SOURCE_MEASURED);
    assert_eq!(total, 700);
}

/// A SAMPLE WITH NO TIME DOES NOT RESET THE ANCHOR.
///
/// This is the half of the walk a second implementation gets wrong, and it is
/// why `Pacing` is a type upstream rather than four lines in `plan`. With the
/// anchor sticking, the pair either side of the hole measures ACROSS it; a walk
/// that reset would report `Unmeasurable` twice and replace a real interval
/// with a declared gap.
#[test]
fn a_missing_capture_time_does_not_reset_the_anchor() {
    let (code, out, _) = pace(
        WZ_REPLAY_TIMING_CAPTURE,
        7,
        1.0,
        WZ_REPLAY_NO_CEILING,
        WZ_REPLAY_NO_CEILING,
        Some(&[1_000, WZ_REPLAY_NO_TIMESTAMP, 1_900]),
    );
    assert_eq!(code, WZ_REPLAY_OK);
    assert_eq!(out[1].delay_millis, 7);
    assert_eq!(out[1].source, WZ_REPLAY_SOURCE_UNMEASURABLE);
    assert_eq!(
        out[2].delay_millis, 900,
        "the anchor is the last RESOLVABLE time, so this pair measures 1900-1000"
    );
    assert_eq!(out[2].source, WZ_REPLAY_SOURCE_MEASURED);
}

/// A clock that steps BACKWARDS yields zero, not a wrapped enormity.
#[test]
fn a_backwards_clock_saturates_to_zero() {
    let (_, out, _) = pace(
        WZ_REPLAY_TIMING_CAPTURE,
        50,
        1.0,
        WZ_REPLAY_NO_CEILING,
        WZ_REPLAY_NO_CEILING,
        Some(&[5_000, 1_000]),
    );
    assert_eq!(out[1].delay_millis, 0);
    assert_eq!(out[1].source, WZ_REPLAY_SOURCE_MEASURED);
}

/// The per-gap ceiling caps ONE delay, so an hour of silence cannot make a
/// replay look like a hang.
#[test]
fn the_gap_ceiling_caps_one_delay() {
    let (code, out, total) = pace(
        WZ_REPLAY_TIMING_CAPTURE,
        100,
        1.0,
        2_000,
        WZ_REPLAY_NO_CEILING,
        Some(&[0, 3_600_000]),
    );
    assert_eq!(code, WZ_REPLAY_OK);
    assert_eq!(out[1].delay_millis, 2_000);
    assert_eq!(total, 2_000);
}

/// THE WHOLE-PLAN CEILING REFUSES, AND STILL SHOWS THE PLAN.
///
/// `Plan::within`'s own doc is the reason: the refusal is asked of the plan
/// rather than enforced while building it precisely so an operator who hits it
/// can SEE what was too long. A door answering with an error and an untouched
/// buffer would leave them a number and no listing.
#[test]
fn a_plan_over_its_total_is_refused_with_the_plan_still_written() {
    let (code, out, total) = pace(
        WZ_REPLAY_TIMING_DECLARED,
        1_000,
        1.0,
        WZ_REPLAY_NO_CEILING,
        2_500,
        Some(&[0, 0, 0, 0]),
    );
    assert_eq!(code, WZ_REPLAY_ERR_PLAN_TOO_LONG);
    assert_eq!(total, 3_000);
    assert_eq!(out[3].delay_millis, 1_000);
    assert!(
        out.iter().all(|e| e.delay_millis != u64::MAX),
        "every record was written, not just the ones before the ceiling bit"
    );
}

/// A plan exactly AT its ceiling is played, not refused.
#[test]
fn a_plan_at_its_ceiling_is_not_refused() {
    let (code, _, total) = pace(
        WZ_REPLAY_TIMING_DECLARED,
        1_000,
        1.0,
        WZ_REPLAY_NO_CEILING,
        2_000,
        Some(&[0, 0, 0]),
    );
    assert_eq!(code, WZ_REPLAY_OK);
    assert_eq!(total, 2_000);
}

/// A caller may ask for the verdict alone, before it allocates.
#[test]
fn a_null_buffer_still_answers_the_total_and_the_verdict() {
    let times = [0u64, 0, 0];
    let mut total = u64::MAX;
    let code = unsafe {
        wz_replay_plan_delays(
            WZ_REPLAY_TIMING_DECLARED,
            1_000,
            1.0,
            WZ_REPLAY_NO_CEILING,
            1_500,
            times.as_ptr(),
            times.len(),
            core::ptr::null_mut(),
            0,
            &mut total,
        )
    };
    assert_eq!(code, WZ_REPLAY_ERR_PLAN_TOO_LONG);
    assert_eq!(total, 2_000);
}

/// A null time array is "no sample has a reading", not an error.
#[test]
fn a_null_time_array_paces_as_unmeasurable() {
    let (code, out, _) = pace(
        WZ_REPLAY_TIMING_CAPTURE,
        30,
        1.0,
        WZ_REPLAY_NO_CEILING,
        WZ_REPLAY_NO_CEILING,
        None,
    );
    assert_eq!(code, WZ_REPLAY_OK);
    assert!(out.is_empty());

    let mut records = [WzReplayEmission {
        delay_millis: u64::MAX,
        source: -1,
        reserved: -1,
    }; 2];
    let mut total = 0;
    let code = unsafe {
        wz_replay_plan_delays(
            WZ_REPLAY_TIMING_CAPTURE,
            30,
            1.0,
            WZ_REPLAY_NO_CEILING,
            WZ_REPLAY_NO_CEILING,
            core::ptr::null(),
            2,
            records.as_mut_ptr(),
            2,
            &mut total,
        )
    };
    assert_eq!(code, WZ_REPLAY_OK);
    assert_eq!(records[1].source, WZ_REPLAY_SOURCE_UNMEASURABLE);
    assert_eq!(records[1].delay_millis, 30);
}

/// A buffer shorter than the count is a bug, not a request for a prefix.
#[test]
fn a_short_buffer_is_refused_rather_than_partly_filled() {
    let times = [0u64, 0, 0];
    let mut records = [WzReplayEmission {
        delay_millis: u64::MAX,
        source: -1,
        reserved: -1,
    }; 3];
    let code = unsafe {
        wz_replay_plan_delays(
            WZ_REPLAY_TIMING_DECLARED,
            10,
            1.0,
            WZ_REPLAY_NO_CEILING,
            WZ_REPLAY_NO_CEILING,
            times.as_ptr(),
            3,
            records.as_mut_ptr(),
            2,
            core::ptr::null_mut(),
        )
    };
    assert_eq!(code, WZ_REPLAY_ERR_INVALID_ARG);
    assert!(
        records.iter().all(|r| r.delay_millis == u64::MAX),
        "a refused call writes nothing"
    );
}

/// Both schedule refusals reach C as their own codes, and neither is the
/// generic invalid-argument one.
#[test]
fn the_two_schedule_refusals_have_their_own_codes() {
    assert_eq!(
        wz_replay_schedule_check(WZ_REPLAY_TIMING_DECLARED, 10, 0.0, u64::MAX, u64::MAX),
        WZ_REPLAY_ERR_SPEED_NOT_POSITIVE
    );
    assert_eq!(
        wz_replay_schedule_check(WZ_REPLAY_TIMING_DECLARED, 10, -1.0, u64::MAX, u64::MAX),
        WZ_REPLAY_ERR_SPEED_NOT_POSITIVE
    );
    assert_eq!(
        wz_replay_schedule_check(WZ_REPLAY_TIMING_DECLARED, 10, f64::NAN, u64::MAX, u64::MAX),
        WZ_REPLAY_ERR_SPEED_NOT_FINITE
    );
    assert_eq!(
        wz_replay_schedule_check(
            WZ_REPLAY_TIMING_DECLARED,
            10,
            f64::INFINITY,
            u64::MAX,
            u64::MAX
        ),
        WZ_REPLAY_ERR_SPEED_NOT_FINITE
    );
    assert_eq!(
        wz_replay_schedule_check(WZ_REPLAY_TIMING_DECLARED, 10, 1.0, u64::MAX, u64::MAX),
        WZ_REPLAY_OK
    );
}

/// A timing word this build does not name is REFUSED, not defaulted.
#[test]
fn an_unknown_timing_is_refused_rather_than_defaulted() {
    for bad in [-1, 2, 99] {
        assert_eq!(
            wz_replay_schedule_check(bad, 10, 1.0, u64::MAX, u64::MAX),
            WZ_REPLAY_ERR_UNKNOWN_TIMING,
            "a caller who asked for a pace this build cannot give must not \
             silently get the declared gaps"
        );
        let (code, _, _) = pace(bad, 10, 1.0, u64::MAX, u64::MAX, Some(&[0, 0]));
        assert_eq!(code, WZ_REPLAY_ERR_UNKNOWN_TIMING);
    }
}

/// A schedule refusal beats a buffer complaint: the plan was never playable.
#[test]
fn a_refused_schedule_is_answered_before_the_buffer_is_judged() {
    let times = [0u64, 0];
    let code = unsafe {
        wz_replay_plan_delays(
            WZ_REPLAY_TIMING_DECLARED,
            10,
            0.0,
            u64::MAX,
            u64::MAX,
            times.as_ptr(),
            2,
            core::ptr::null_mut(),
            0,
            core::ptr::null_mut(),
        )
    };
    assert_eq!(code, WZ_REPLAY_ERR_SPEED_NOT_POSITIVE);
}

/// Every mutation arm crosses, and each says whether it changed anything.
#[test]
fn every_mutation_arm_crosses_the_boundary() {
    let payload = [0x11u8, 0x22, 0x33, 0x44];

    let (code, out, changed) = mutate(WZ_REPLAY_MUTATION_NONE, 0, 0, &payload);
    assert_eq!(code, WZ_REPLAY_OK);
    assert_eq!(out, payload);
    assert!(!changed);

    let (code, out, changed) = mutate(WZ_REPLAY_MUTATION_FLIP_BIT, 0, 0, &payload);
    assert_eq!(code, WZ_REPLAY_OK);
    assert_eq!(out, [0x10, 0x22, 0x33, 0x44]);
    assert!(changed);

    let (code, out, changed) = mutate(WZ_REPLAY_MUTATION_TRUNCATE, 2, 0, &payload);
    assert_eq!(code, WZ_REPLAY_OK);
    assert_eq!(out, [0x11, 0x22]);
    assert!(changed);

    let (code, out, changed) = mutate(WZ_REPLAY_MUTATION_EXTEND, 3, 42, &payload);
    assert_eq!(code, WZ_REPLAY_OK);
    assert_eq!(out.len(), 7, "EXTEND is the one arm that grows the payload");
    assert_eq!(&out[..4], &payload);
    assert!(changed);

    let (code, out, changed) = mutate(WZ_REPLAY_MUTATION_SCRAMBLE, 0, 42, &payload);
    assert_eq!(code, WZ_REPLAY_OK);
    assert_eq!(out.len(), 4);
    assert_ne!(out, payload);
    assert!(changed);
}

/// THE SEED IS THE WHOLE POINT: the same command gives the same bytes.
#[test]
fn a_seeded_mutation_repeats_and_a_different_seed_does_not() {
    let payload = [0u8; 16];
    let a = mutate(WZ_REPLAY_MUTATION_SCRAMBLE, 0, 7, &payload);
    let b = mutate(WZ_REPLAY_MUTATION_SCRAMBLE, 0, 7, &payload);
    let c = mutate(WZ_REPLAY_MUTATION_SCRAMBLE, 0, 8, &payload);
    assert_eq!(
        a.1, b.1,
        "a fuzzing run that cannot be repeated is a bug \
                          report nobody can act on"
    );
    assert_ne!(a.1, c.1);
}

/// A mutation whose target is outside the payload says it changed NOTHING.
#[test]
fn a_mutation_that_missed_reports_that_it_missed() {
    let payload = [0xAAu8, 0xBB];
    for (kind, operand) in [
        (WZ_REPLAY_MUTATION_FLIP_BIT, 900u64),
        (WZ_REPLAY_MUTATION_TRUNCATE, 900),
        (WZ_REPLAY_MUTATION_EXTEND, 0),
    ] {
        let (code, out, changed) = mutate(kind, operand, 1, &payload);
        assert_eq!(code, WZ_REPLAY_OK);
        assert_eq!(out, payload);
        assert!(
            !changed,
            "a run that silently changed nothing looks exactly like one that \
             found nothing"
        );
    }
}

/// The sizing call reports the length and writes no bytes.
#[test]
fn the_sizing_call_reports_the_length_without_a_buffer() {
    let payload = [1u8, 2, 3];
    let mut needed = usize::MAX;
    let code = unsafe {
        wz_replay_mutate(
            WZ_REPLAY_MUTATION_EXTEND,
            5,
            1,
            payload.as_ptr(),
            payload.len(),
            core::ptr::null_mut(),
            0,
            &mut needed,
            core::ptr::null_mut(),
        )
    };
    assert_eq!(code, WZ_REPLAY_ERR_BUFFER_TOO_SMALL);
    assert_eq!(needed, 8);
}

/// A buffer one byte short is refused and left untouched.
#[test]
fn a_short_mutation_buffer_is_refused_and_writes_nothing() {
    let payload = [1u8, 2, 3, 4];
    let mut buf = [0xEEu8; 4];
    let mut needed = 0;
    let code = unsafe {
        wz_replay_mutate(
            WZ_REPLAY_MUTATION_NONE,
            0,
            0,
            payload.as_ptr(),
            payload.len(),
            buf.as_mut_ptr(),
            3,
            &mut needed,
            core::ptr::null_mut(),
        )
    };
    assert_eq!(code, WZ_REPLAY_ERR_BUFFER_TOO_SMALL);
    assert_eq!(needed, 4);
    assert_eq!(buf, [0xEE; 4], "a refused call writes nothing");
}

/// A mutation kind this build does not name is refused.
#[test]
fn an_unknown_mutation_is_refused_rather_than_treated_as_none() {
    let payload = [1u8];
    let mut needed = 0;
    for bad in [-1, 5, 77] {
        let code = unsafe {
            wz_replay_mutate(
                bad,
                0,
                0,
                payload.as_ptr(),
                payload.len(),
                core::ptr::null_mut(),
                0,
                &mut needed,
                core::ptr::null_mut(),
            )
        };
        assert_eq!(code, WZ_REPLAY_ERR_UNKNOWN_MUTATION);
    }
}

/// An empty payload is a payload, not a null pointer.
#[test]
fn an_empty_payload_crosses() {
    let mut needed = usize::MAX;
    let mut changed = -1;
    let code = unsafe {
        wz_replay_mutate(
            WZ_REPLAY_MUTATION_SCRAMBLE,
            0,
            1,
            core::ptr::null(),
            0,
            core::ptr::null_mut(),
            0,
            &mut needed,
            &mut changed,
        )
    };
    assert_eq!(code, WZ_REPLAY_ERR_BUFFER_TOO_SMALL);
    assert_eq!(needed, 0);
    assert_eq!(changed, 0, "scrambling nothing changes nothing");
}

/// `out_len` is the one pointer with no null spelling: without it the caller
/// cannot learn the length, so the call has no answer to give.
#[test]
fn a_null_out_len_is_refused() {
    let payload = [1u8];
    let code = unsafe {
        wz_replay_mutate(
            WZ_REPLAY_MUTATION_NONE,
            0,
            0,
            payload.as_ptr(),
            1,
            core::ptr::null_mut(),
            0,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    assert_eq!(code, WZ_REPLAY_ERR_INVALID_ARG);
}

/// A payload pointer that is null while the length is not is a caller bug.
#[test]
fn a_null_payload_with_a_length_is_refused() {
    let mut needed = 0;
    let code = unsafe {
        wz_replay_mutate(
            WZ_REPLAY_MUTATION_NONE,
            0,
            0,
            core::ptr::null(),
            4,
            core::ptr::null_mut(),
            0,
            &mut needed,
            core::ptr::null_mut(),
        )
    };
    assert_eq!(code, WZ_REPLAY_ERR_INVALID_ARG);
}

/// The layout door sizes first and reads second, and reports the real struct.
#[test]
fn the_emission_layout_is_reported_by_the_artifact() {
    let count = unsafe { wz_replay_emission_layout(core::ptr::null_mut(), 0) };
    assert_eq!(count, 5);
    let mut short = [0usize; 4];
    assert_eq!(
        unsafe { wz_replay_emission_layout(short.as_mut_ptr(), 4) },
        5
    );
    assert_eq!(short, [0; 4], "a cap below the count writes nothing");

    let mut layout = [0usize; 5];
    assert_eq!(
        unsafe { wz_replay_emission_layout(layout.as_mut_ptr(), 5) },
        5
    );
    assert_eq!(layout[0], core::mem::size_of::<WzReplayEmission>());
    assert_eq!(layout[1], core::mem::align_of::<WzReplayEmission>());
    assert_eq!(layout[2], 0, "delay_millis leads the record");
    assert!(layout[3] < layout[0] && layout[4] < layout[0]);
}

/// The revision a consumer receives is the one this crate declares.
#[test]
fn the_abi_version_is_the_declared_one() {
    assert_eq!(wz_replay_abi_version(), WZ_REPLAY_ABI_VERSION);
}

/// EVERY VOCABULARY CONSTANT IS DISTINCT WITHIN ITS OWN FAMILY.
///
/// Cheap and load-bearing: two constants sharing a value is a mapping that
/// cannot be inverted, and it is a defect no other test here would see because
/// each one asserts the constant it expects rather than that the constants
/// differ.
#[test]
fn each_vocabulary_family_has_distinct_values() {
    let families: [&[c_int]; 4] = [
        &[WZ_REPLAY_TIMING_DECLARED, WZ_REPLAY_TIMING_CAPTURE],
        &[
            WZ_REPLAY_SOURCE_DECLARED,
            WZ_REPLAY_SOURCE_MEASURED,
            WZ_REPLAY_SOURCE_UNMEASURABLE,
        ],
        &[
            WZ_REPLAY_MUTATION_NONE,
            WZ_REPLAY_MUTATION_FLIP_BIT,
            WZ_REPLAY_MUTATION_TRUNCATE,
            WZ_REPLAY_MUTATION_EXTEND,
            WZ_REPLAY_MUTATION_SCRAMBLE,
        ],
        &[
            WZ_REPLAY_OK,
            WZ_REPLAY_ERR_INVALID_ARG,
            WZ_REPLAY_ERR_UNKNOWN_TIMING,
            WZ_REPLAY_ERR_UNKNOWN_MUTATION,
            WZ_REPLAY_ERR_SPEED_NOT_POSITIVE,
            WZ_REPLAY_ERR_SPEED_NOT_FINITE,
            WZ_REPLAY_ERR_PLAN_TOO_LONG,
            WZ_REPLAY_ERR_BUFFER_TOO_SMALL,
        ],
    ];
    for family in families {
        let mut seen = family.to_vec();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), family.len(), "a family has a repeated value");
    }
}

/// THE DOOR AND THE CLI ANSWER THE SAME PACING FOR THE SAME INPUT.
///
/// This is the property the whole crate is for: the report was that a consumer
/// who cannot call this writes the judgement a second time, and two
/// implementations of one judgement drift. Driving `wz_replay::Pacing` beside
/// the ABI is what makes "no second opinion" a measured fact rather than an
/// architectural intention -- damage either side and this reds.
#[test]
fn the_door_answers_what_the_library_answers() {
    let times = [1_000u64, 1_150, 1_150, 9_999_000];
    let schedule = wz_replay::Schedule {
        timing: wz_replay::Timing::Capture,
        gap_millis: 40,
        speed: 1.5,
        max_gap_millis: Some(5_000),
        max_total_millis: None,
    };
    let mut walk = wz_replay::Pacing::new(schedule);
    let expected: Vec<(u64, c_int)> = times
        .iter()
        .map(|&t| {
            let (delay, source) = walk.next(Some(t));
            (delay, source_code(source))
        })
        .collect();

    let (code, out, _) = pace(
        WZ_REPLAY_TIMING_CAPTURE,
        40,
        1.5,
        5_000,
        WZ_REPLAY_NO_CEILING,
        Some(&times),
    );
    assert_eq!(code, WZ_REPLAY_OK);
    let through_abi: Vec<(u64, c_int)> = out.iter().map(|e| (e.delay_millis, e.source)).collect();
    assert_eq!(through_abi, expected);
}
