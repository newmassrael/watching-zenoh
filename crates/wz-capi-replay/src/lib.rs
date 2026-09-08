// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Round 2441 (open-debt item 693) — the C ABI over `wz-replay`'s PLAN half.
//!
//! ## The measured reason this crate exists
//!
//! `wz-replay` computes how fast a capture plays back and what a fuzzing run
//! does to a payload. Both are pure functions, both are deliberately buildable
//! without the session runtime, and until this round neither could be CALLED by
//! anything but that crate's own binary: no crate in the workspace depended on
//! it and no `wz-capi-*` exported it. A downstream product that links the C ABI
//! only therefore wrote the pacing judgement a second time, took this tree's
//! vocabulary verbatim, and filed a report saying so — because two
//! implementations of one judgement drift, and the drift is silent.
//!
//! This is the door. It is not a new judgement: every answer here comes from
//! [`wz_replay`], and nothing in this crate decides anything the CLI would
//! decide differently. That is the property the whole crate is for, and
//! `scripts/lib/capi_replay_vocabulary.py` is what holds the half of it a
//! compiler cannot see.
//!
//! ## What the ABI promises
//!
//! **NOTHING CROSSES THIS BOUNDARY ALLOCATED.** No strings, no handles, no
//! callbacks. Every door here writes into a buffer the caller owns and sized,
//! and every value it answers with is a scalar. There is no free function in
//! this library because there is nothing to free.
//!
//! That is a STRONGER rule than `wz_dissect.h`'s, and deliberately so. It is
//! available here and was not available there: a dissection must be kept alive
//! between packets and a field tree is not a fixed-size thing, whereas a delay
//! is eight bytes and a mutated payload has a length the caller learns before
//! it asks for the bytes. A promise that can be kept absolutely is worth more
//! than one carrying an exception, and [`wz_replay_abi_version`] moves if this
//! sentence ever does.
//!
//! ## What it does NOT promise
//!
//! The NUMERIC VALUES of the vocabulary constants are part of the ABI and will
//! not change. New ones may be ADDED — a schedule that grew twice already
//! (`Timing` in R311y703, `Schedule::max_total_millis` in R311y704) is a
//! surface that grows — and a consumer must treat an unrecognised
//! `WZ_REPLAY_SOURCE_*` as "a source this build does not name" rather than as
//! corruption. [`wz_replay_abi_version`] moves whenever a symbol, a constant or
//! the memory rule above changes.

// No `c_char`, and its absence is a PROPERTY rather than an omission: no
// string crosses this boundary, which is why this library has no free
// function. See the memory rule above.
use core::ffi::{c_double, c_int};

use wz_replay::{Mutation, Pacing, Schedule, ScheduleError, Timing, TimingSource};

/// The ABI revision.
///
/// Moves when a SYMBOL, a vocabulary CONSTANT or the memory rule changes. It is
/// the number a consumer refuses a library by, so it is pinned outside this
/// file as well — see `scripts/lib/capi_replay_abi_pin.py`, which reads it by
/// LOADING the cdylib and calling this function rather than by finding a
/// literal near it.
pub const WZ_REPLAY_ABI_VERSION: c_int = 1;

/// Success.
pub const WZ_REPLAY_OK: c_int = 0;
/// A null pointer where one is required, a length that cannot be a buffer, or a
/// count that does not fit this platform's `size_t`.
pub const WZ_REPLAY_ERR_INVALID_ARG: c_int = -1;
/// The `timing` argument is not a [`WZ_REPLAY_TIMING_DECLARED`] /
/// [`WZ_REPLAY_TIMING_CAPTURE`] value.
///
/// Its own code and not [`WZ_REPLAY_ERR_INVALID_ARG`] for the reason
/// `wz-replay`'s command line refuses `--timing real` instead of defaulting: a
/// caller who asked for a pace this build does not know and silently got the
/// declared gaps would believe they were replaying the capture's own timing.
pub const WZ_REPLAY_ERR_UNKNOWN_TIMING: c_int = -2;
/// The `mutation` argument is not a `WZ_REPLAY_MUTATION_*` value. Refused
/// rather than treated as [`WZ_REPLAY_MUTATION_NONE`], on the same rule: a
/// fuzzing run that silently changed nothing looks exactly like one that found
/// nothing.
pub const WZ_REPLAY_ERR_UNKNOWN_MUTATION: c_int = -3;
/// `speed` was zero or less. Mirrors [`ScheduleError::SpeedNotPositive`].
pub const WZ_REPLAY_ERR_SPEED_NOT_POSITIVE: c_int = -4;
/// `speed` was not a number at all. Mirrors [`ScheduleError::SpeedNotFinite`].
pub const WZ_REPLAY_ERR_SPEED_NOT_FINITE: c_int = -5;
/// The plan runs longer than `max_total_millis`.
///
/// THE DELAYS AND THE TOTAL ARE STILL WRITTEN. That is not leniency, it is
/// [`wz_replay::Plan::within`]'s own stated rule: the refusal is asked of the
/// plan rather than enforced while building it precisely so an operator who
/// hits it can SEE the plan that was too long. A door that answered with an
/// error and an empty buffer would leave them a number and no listing.
pub const WZ_REPLAY_ERR_PLAN_TOO_LONG: c_int = -6;
/// The output buffer is smaller than the answer. `*out_len` is set to the
/// length required, so the caller sizes first and reads second.
pub const WZ_REPLAY_ERR_BUFFER_TOO_SMALL: c_int = -7;

/// No capture time for this sample.
///
/// Deliberately the same value as `WZ_DISSECT_NO_TIMESTAMP`, because a consumer
/// feeding `wz_dissect_record.ts_ns` straight into [`wz_replay_plan_delays`] is
/// the case this door was asked for. The agreement is PINNED by a test rather
/// than asserted here — see `the_no_timestamp_sentinel_is_the_dissect_one` —
/// since a comment claiming two numbers are equal is exactly the kind of claim
/// that stops being true.
///
/// It is not a magic reading: a capture time of `u64::MAX` milliseconds since
/// the epoch is 584 million years away.
pub const WZ_REPLAY_NO_TIMESTAMP: u64 = u64::MAX;

/// No ceiling, for `max_gap_millis` and `max_total_millis` alike — the ABI
/// spelling of `Option::None` on [`Schedule::max_gap_millis`] and
/// [`Schedule::max_total_millis`].
///
/// Same argument as [`WZ_REPLAY_NO_TIMESTAMP`]: a ceiling of `u64::MAX`
/// milliseconds is a ceiling nothing reaches, so the sentinel costs no
/// expressible value.
pub const WZ_REPLAY_NO_CEILING: u64 = u64::MAX;

// The VOCABULARY. Every constant below mirrors one variant of one `pub enum`
// in `wz-replay`'s plan half, and the mapping is held in two directions:
//
//   * RUST -> here, by the exhaustive `match` in each `from_abi` / `to_abi`
//     below. Add a variant upstream and this crate stops compiling.
//   * here -> `include/wz_replay.h`, by `capi_replay_vocabulary.py`, which
//     derives the variant set from the upstream source rather than from a list
//     anyone wrote down. A header naming five of six states compiles, links and
//     passes every ABI test while telling a C consumer that a value they will
//     receive does not exist; that is the asymmetry the gate exists for, and
//     `wz-capi-dissect` paid for the lesson first.

/// `wz_replay::Timing::Declared`.
pub const WZ_REPLAY_TIMING_DECLARED: c_int = 0;
/// `wz_replay::Timing::Capture`.
pub const WZ_REPLAY_TIMING_CAPTURE: c_int = 1;

/// `wz_replay::TimingSource::Declared`.
pub const WZ_REPLAY_SOURCE_DECLARED: c_int = 0;
/// `wz_replay::TimingSource::Measured`.
pub const WZ_REPLAY_SOURCE_MEASURED: c_int = 1;
/// `wz_replay::TimingSource::Unmeasurable` — the capture was ASKED for a time
/// and could not answer.
///
/// Distinct from [`WZ_REPLAY_SOURCE_DECLARED`] on the rule this workspace
/// applies to every fallback: one that reads like a choice hides the fact that
/// a measurement was wanted and missing. A consumer that folds the two is
/// throwing away the only evidence its own replay was not the capture's pace.
pub const WZ_REPLAY_SOURCE_UNMEASURABLE: c_int = 2;

/// `wz_replay::Mutation::None` — send it as captured.
pub const WZ_REPLAY_MUTATION_NONE: c_int = 0;
/// `wz_replay::Mutation::FlipBit` — `operand` is a BIT index.
pub const WZ_REPLAY_MUTATION_FLIP_BIT: c_int = 1;
/// `wz_replay::Mutation::Truncate` — `operand` is the length to keep.
pub const WZ_REPLAY_MUTATION_TRUNCATE: c_int = 2;
/// `wz_replay::Mutation::Extend` — `operand` is how many bytes to append,
/// derived from `seed`.
pub const WZ_REPLAY_MUTATION_EXTEND: c_int = 3;
/// `wz_replay::Mutation::Scramble` — every byte from `seed`, length kept.
pub const WZ_REPLAY_MUTATION_SCRAMBLE: c_int = 4;

/// One emission's pacing: how long to wait, and which clock said so.
///
/// A fixed-layout record rather than a document, for the reason
/// `WzDissectRecord` is one: these are the scalars a caller reads per emission
/// at the rate its own plan runs, and a self-describing document per delay is
/// work proportional to the traffic for two fields.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WzReplayEmission {
    /// Milliseconds to wait before this emission. Zero for the first.
    pub delay_millis: u64,
    /// One of the `WZ_REPLAY_SOURCE_*` values.
    pub source: c_int,
    /// Explicit rather than implicit tail padding, so the layout this struct
    /// reports is a layout the source states. A reserved field is a fact a
    /// reader can check; padding the compiler inserted is one they must infer.
    pub reserved: c_int,
}

/// The ABI revision this build implements.
#[no_mangle]
pub extern "C" fn wz_replay_abi_version() -> c_int {
    WZ_REPLAY_ABI_VERSION
}

/// The layout of [`WzReplayEmission`], reported by the ARTIFACT.
///
/// Fills `out` with `size, align, offset(delay_millis), offset(source),
/// offset(reserved)` and returns how many values the layout has. A null `out`
/// (or a `cap` below that count) writes nothing and returns the count, so a
/// caller sizes first and reads second.
///
/// # Why this exists, and it is not for consumers
///
/// Exactly `wz_dissect_record_layout`'s reason, which was paid for once
/// already: a layout pinned by a Rust `size_of` test AND a C `sizeof` block is
/// pinned twice by the same commit, so a round can widen the struct, update
/// both, and leave the tree agreeing with itself while the ABI number stands
/// still. This door makes the layout a fact the shipped artifact reports, which
/// `scripts/lib/capi_replay_abi_pin.py` reads through ctypes.
///
/// # Safety
/// `out` must be null, or writable for `cap` `size_t` values.
#[no_mangle]
pub unsafe extern "C" fn wz_replay_emission_layout(out: *mut usize, cap: usize) -> usize {
    let layout: [usize; 5] = [
        core::mem::size_of::<WzReplayEmission>(),
        core::mem::align_of::<WzReplayEmission>(),
        core::mem::offset_of!(WzReplayEmission, delay_millis),
        core::mem::offset_of!(WzReplayEmission, source),
        core::mem::offset_of!(WzReplayEmission, reserved),
    ];
    if !out.is_null() && cap >= layout.len() {
        // SAFETY: the caller promises `out` is writable for `cap` values and
        // `cap` is at least the length just checked.
        unsafe { core::ptr::copy_nonoverlapping(layout.as_ptr(), out, layout.len()) };
    }
    layout.len()
}

/// The ABI code for a schedule refusal.
///
/// Exhaustive on purpose: a variant added upstream stops this crate compiling,
/// which is the only way a new refusal cannot reach a consumer as a code it has
/// no case for.
fn schedule_error_code(error: ScheduleError) -> c_int {
    match error {
        ScheduleError::SpeedNotPositive => WZ_REPLAY_ERR_SPEED_NOT_POSITIVE,
        ScheduleError::SpeedNotFinite => WZ_REPLAY_ERR_SPEED_NOT_FINITE,
    }
}

/// The ABI code for a timing source. Exhaustive for the reason above.
fn source_code(source: TimingSource) -> c_int {
    match source {
        TimingSource::Declared => WZ_REPLAY_SOURCE_DECLARED,
        TimingSource::Measured => WZ_REPLAY_SOURCE_MEASURED,
        TimingSource::Unmeasurable => WZ_REPLAY_SOURCE_UNMEASURABLE,
    }
}

/// A `timing` argument, or nothing if this build does not name it.
fn timing_from_abi(timing: c_int) -> Option<Timing> {
    match timing {
        WZ_REPLAY_TIMING_DECLARED => Some(Timing::Declared),
        WZ_REPLAY_TIMING_CAPTURE => Some(Timing::Capture),
        _ => None,
    }
}

/// A `mutation` argument and its two operands, or nothing if this build does
/// not name the kind.
///
/// `operand` carries the one number each kind needs and `seed` the generator,
/// so the door has a fixed arity across a vocabulary whose arms do not. Which
/// operand a kind reads is stated on its constant and in the header; a kind
/// that reads neither ignores both.
fn mutation_from_abi(mutation: c_int, operand: u64, seed: u64) -> Option<Mutation> {
    // A bit index or a length wider than this platform's `usize` is REFUSED
    // rather than truncated: a caller on a 32-bit target who asked to flip bit
    // 2^33 and silently got bit 2 would be told a mutation happened somewhere
    // it did not.
    let fits = usize::try_from(operand).ok();
    match mutation {
        WZ_REPLAY_MUTATION_NONE => Some(Mutation::None),
        WZ_REPLAY_MUTATION_FLIP_BIT => fits.map(|at| Mutation::FlipBit { at }),
        WZ_REPLAY_MUTATION_TRUNCATE => fits.map(|to| Mutation::Truncate { to }),
        WZ_REPLAY_MUTATION_EXTEND => fits.map(|count| Mutation::Extend { count, seed }),
        WZ_REPLAY_MUTATION_SCRAMBLE => Some(Mutation::Scramble { seed }),
        _ => None,
    }
}

/// Assemble the schedule these arguments describe, or the code that refuses it.
fn schedule_from_abi(
    timing: c_int,
    gap_millis: u64,
    speed: c_double,
    max_gap_millis: u64,
    max_total_millis: u64,
) -> Result<Schedule, c_int> {
    let Some(timing) = timing_from_abi(timing) else {
        return Err(WZ_REPLAY_ERR_UNKNOWN_TIMING);
    };
    let ceiling = |v: u64| (v != WZ_REPLAY_NO_CEILING).then_some(v);
    Schedule {
        timing,
        gap_millis,
        speed,
        max_gap_millis: ceiling(max_gap_millis),
        max_total_millis: ceiling(max_total_millis),
    }
    // `checked` is the library's own refusal and this crate does not repeat
    // its reasoning -- it maps the answer. A second opinion about what a
    // playable speed is would be the defect this whole crate closes.
    .checked()
    .map_err(schedule_error_code)
}

/// Is this schedule one that can be played?
///
/// The cheap door, for a caller validating a control surface as an operator
/// types into it rather than when they press play. It computes no delays and
/// touches no buffer.
///
/// Returns [`WZ_REPLAY_OK`], [`WZ_REPLAY_ERR_UNKNOWN_TIMING`],
/// [`WZ_REPLAY_ERR_SPEED_NOT_POSITIVE`] or [`WZ_REPLAY_ERR_SPEED_NOT_FINITE`].
/// It cannot answer [`WZ_REPLAY_ERR_PLAN_TOO_LONG`]: a whole-plan ceiling is
/// only knowable once the samples are read, which is the distinction
/// `wz_replay::PlanTooLong` is a separate type for.
#[no_mangle]
pub extern "C" fn wz_replay_schedule_check(
    timing: c_int,
    gap_millis: u64,
    speed: c_double,
    max_gap_millis: u64,
    max_total_millis: u64,
) -> c_int {
    match schedule_from_abi(timing, gap_millis, speed, max_gap_millis, max_total_millis) {
        Ok(_) => WZ_REPLAY_OK,
        Err(code) => code,
    }
}

/// PACE a plan: the delay before each emission and which clock it came from.
///
/// `captured_at_millis` is `count` capture times in the order they will be
/// sent, each either a reading in milliseconds since the Unix epoch or
/// [`WZ_REPLAY_NO_TIMESTAMP`]. It may be null, which is every sample having no
/// reading — the shape a caller under [`WZ_REPLAY_TIMING_DECLARED`] has.
///
/// `out` receives `count` [`WzReplayEmission`] records and may be null with
/// `out_cap` zero, which asks only for the total and the verdict — the check a
/// caller makes before allocating. `total_millis_out` receives the whole plan's
/// wall clock and may be null.
///
/// # The times are the ones you are SENDING, not the ones you captured
///
/// Pass the times of the samples this plan will emit, already narrowed. wz's
/// own `Selection` narrows before pacing for a stated reason: a selector that
/// drops the message between two kept ones WIDENS the real interval, and
/// pacing the unnarrowed list would play a conversation that never happened at
/// that pace. A caller that filters after calling this gets the pace of a
/// conversation it is not sending.
///
/// # Returns
///
/// [`WZ_REPLAY_OK`], or [`WZ_REPLAY_ERR_PLAN_TOO_LONG`] with the delays and the
/// total STILL WRITTEN — see that constant. A schedule refusal or a bad
/// argument writes nothing.
///
/// # Safety
/// `captured_at_millis` must be null or point to at least `count` readable
/// `uint64_t`. `out` must be null or writable for `out_cap`
/// [`WzReplayEmission`] records. `total_millis_out` must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_replay_plan_delays(
    timing: c_int,
    gap_millis: u64,
    speed: c_double,
    max_gap_millis: u64,
    max_total_millis: u64,
    captured_at_millis: *const u64,
    count: usize,
    out: *mut WzReplayEmission,
    out_cap: usize,
    total_millis_out: *mut u64,
) -> c_int {
    let schedule =
        match schedule_from_abi(timing, gap_millis, speed, max_gap_millis, max_total_millis) {
            Ok(schedule) => schedule,
            Err(code) => return code,
        };
    // A buffer is optional, but a SHORT one is a bug rather than a request for
    // a prefix: the caller supplied `count`, so the size it needs is a number
    // it already has. Writing part of the plan would hand back a pacing whose
    // tail is missing with no way to tell.
    if !out.is_null() && out_cap < count {
        return WZ_REPLAY_ERR_INVALID_ARG;
    }
    // A null `captured_at_millis` with a positive `count` is NOT an error: it
    // spells "no sample has a resolvable time", which is a real shape and the
    // ordinary one under `WZ_REPLAY_TIMING_DECLARED`. Every index reads `None`.
    let times: Option<&[u64]> = if captured_at_millis.is_null() {
        None
    } else {
        // SAFETY: caller contract above.
        Some(unsafe { core::slice::from_raw_parts(captured_at_millis, count) })
    };

    let mut pacing = Pacing::new(schedule);
    let mut total = 0u64;
    for index in 0..count {
        let at = match times {
            None => None,
            Some(slice) => (slice[index] != WZ_REPLAY_NO_TIMESTAMP).then_some(slice[index]),
        };
        let (delay_millis, source) = pacing.next(at);
        // Saturating, exactly as `Plan::duration_millis` folds it. The two
        // totals must be the same number for the same input or the refusal
        // below is about a different plan than the caller is holding.
        total = total.saturating_add(delay_millis);
        if !out.is_null() {
            let record = WzReplayEmission {
                delay_millis,
                source: source_code(source),
                reserved: 0,
            };
            // SAFETY: `out` is non-null and `out_cap >= count > index`.
            unsafe { out.add(index).write(record) };
        }
    }
    if !total_millis_out.is_null() {
        // SAFETY: caller contract above.
        unsafe { *total_millis_out = total };
    }
    match schedule.max_total_millis {
        Some(limit) if total > limit => WZ_REPLAY_ERR_PLAN_TOO_LONG,
        _ => WZ_REPLAY_OK,
    }
}

/// MUTATE a payload the way a replay would.
///
/// `out` may be null with `out_cap` zero to ask only for the length: `*out_len`
/// is written either way, and a buffer shorter than it answers
/// [`WZ_REPLAY_ERR_BUFFER_TOO_SMALL`] having written nothing to `out`. Only
/// [`WZ_REPLAY_MUTATION_EXTEND`] can produce a payload LONGER than the input,
/// so a caller that never extends can size at `payload_len` and never see that
/// code.
///
/// `changed` receives 1 or 0, and it is not decoration: a mutation whose target
/// lies outside this payload leaves the bytes alone, and a fuzzing run that
/// silently changed nothing looks exactly like one that found nothing. It may
/// be null if the caller genuinely does not want to know.
///
/// # Why the length comes from the mutation and not from a formula
///
/// This door runs the mutation to learn the length, including on the sizing
/// call. A formula predicting the length would be a second opinion about
/// `Mutation::apply`, which is the class of defect this crate exists to close —
/// and it would be wrong the first time a mutation's arm did something the
/// formula did not model.
///
/// # Safety
/// `payload` must be null or point to at least `payload_len` readable bytes.
/// `out` must be null or writable for `out_cap` bytes. `out_len` must not be
/// null; `changed` must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn wz_replay_mutate(
    mutation: c_int,
    operand: u64,
    seed: u64,
    payload: *const u8,
    payload_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
    changed: *mut c_int,
) -> c_int {
    if out_len.is_null() {
        return WZ_REPLAY_ERR_INVALID_ARG;
    }
    if payload.is_null() && payload_len > 0 {
        return WZ_REPLAY_ERR_INVALID_ARG;
    }
    let Some(mutation) = mutation_from_abi(mutation, operand, seed) else {
        // Both an unknown KIND and an operand this platform cannot hold arrive
        // here. They are told apart by the operand a caller passed, which the
        // caller has; folding them costs nothing it cannot recover.
        return WZ_REPLAY_ERR_UNKNOWN_MUTATION;
    };
    let input: &[u8] = if payload.is_null() {
        &[]
    } else {
        // SAFETY: caller contract above.
        unsafe { core::slice::from_raw_parts(payload, payload_len) }
    };
    let outcome = mutation.apply(input);
    // SAFETY: null-checked above.
    unsafe { *out_len = outcome.payload.len() };
    if !changed.is_null() {
        // SAFETY: caller contract above.
        unsafe { *changed = c_int::from(outcome.changed) };
    }
    if out.is_null() || out_cap < outcome.payload.len() {
        return WZ_REPLAY_ERR_BUFFER_TOO_SMALL;
    }
    if !outcome.payload.is_empty() {
        // SAFETY: `out` is non-null and `out_cap` is at least this length.
        unsafe {
            core::ptr::copy_nonoverlapping(outcome.payload.as_ptr(), out, outcome.payload.len())
        };
    }
    WZ_REPLAY_OK
}

#[cfg(test)]
mod tests;
