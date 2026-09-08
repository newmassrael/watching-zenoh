/* SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * Round 2441 (open-debt item 693) — the C ABI over wz-replay's PLAN half.
 *
 * MEMORY RULE, and it is the whole contract: NOTHING CROSSES THIS BOUNDARY
 * ALLOCATED. No strings, no handles, no callbacks. Every door writes into a
 * buffer YOU own and sized, and every value it answers with is a scalar.
 * There is no free function in this library because there is nothing to
 * give back.
 *
 * That is a STRONGER rule than wz_dissect.h's, deliberately. It is available
 * here and was not available there: a dissection must stay alive between
 * packets and a field tree has no fixed size, whereas a delay is eight bytes
 * and a mutated payload has a length you learn before you ask for the bytes.
 * A promise that can be kept absolutely is worth more than one carrying an
 * exception. wz_replay_abi_version moves if this paragraph ever does.
 *
 * WHAT THIS LIBRARY IS FOR. wz-replay decides how fast a capture plays back
 * and what a fuzzing run does to a payload. Both are pure functions of values
 * you already hold, and until this ABI existed a product linking C could call
 * neither — so one wrote the pacing judgement a second time. Two
 * implementations of one judgement drift. Everything below is wz's own
 * answer; nothing here decides anything the wz-replay command line would
 * decide differently.
 *
 * WHAT IT IS NOT. It opens no socket, starts no thread and sends nothing. It
 * tells you WHEN to send and WHAT bytes; the sending is yours, as is which
 * sample is selected and when an operator presses play.
 *
 * THE NUMERIC VALUES BELOW ARE PART OF THE ABI and will not change. New ones
 * may be ADDED: treat an unrecognised WZ_REPLAY_SOURCE_* as "a source this
 * build does not name" rather than as corruption. wz_replay_abi_version moves
 * whenever a symbol, a constant, or the memory rule changes.
 *
 * THREADING. Every function here is a pure function of its arguments. There is
 * no shared state, so any number of threads may call any of them at once.
 */
#ifndef WZ_REPLAY_H
#define WZ_REPLAY_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------- results */

/* Success. */
#define WZ_REPLAY_OK 0
/* A null pointer where one is required, a length that cannot be a buffer, or a
 * count that does not fit this platform's size_t. */
#define WZ_REPLAY_ERR_INVALID_ARG (-1)
/* `timing` is not a WZ_REPLAY_TIMING_* value. Its own code, because a caller
 * who asked for a pace this build cannot give and silently got the declared
 * gaps would believe they were replaying the capture's own timing. */
#define WZ_REPLAY_ERR_UNKNOWN_TIMING (-2)
/* `mutation` is not a WZ_REPLAY_MUTATION_* value, or its operand does not fit
 * this platform's size_t. Refused rather than treated as
 * WZ_REPLAY_MUTATION_NONE: a fuzzing run that silently changed nothing looks
 * exactly like one that found nothing. */
#define WZ_REPLAY_ERR_UNKNOWN_MUTATION (-3)
/* `speed` was zero or less. Refused rather than clamped: a caller who typed
 * zero meant something, and neither "as fast as possible" nor "never" is
 * obviously it. */
#define WZ_REPLAY_ERR_SPEED_NOT_POSITIVE (-4)
/* `speed` was not a number at all. */
#define WZ_REPLAY_ERR_SPEED_NOT_FINITE (-5)
/* The plan runs longer than max_total_millis.
 *
 * THE DELAYS AND THE TOTAL ARE STILL WRITTEN. That is the library's own rule
 * rather than leniency: the refusal is asked of the finished plan precisely so
 * an operator who hits it can SEE what was too long. Narrow the selection,
 * raise the speed, or raise the ceiling — the plan is REFUSED, never silently
 * cut to fit, because a prefix of the traffic under a name that promised all
 * of it reads as a whole replay. */
#define WZ_REPLAY_ERR_PLAN_TOO_LONG (-6)
/* The output buffer is smaller than the answer. *out_len holds the length
 * required, so you size first and read second. */
#define WZ_REPLAY_ERR_BUFFER_TOO_SMALL (-7)

/* -------------------------------------------------------------- sentinels */

/* No capture time for this sample.
 *
 * The SAME NUMBER as WZ_DISSECT_NO_TIMESTAMP, so wz_dissect_record.ts_ns can
 * be fed straight in. The agreement is pinned by a test in this library, not
 * by this comment. Do not read it as zero: a sample with no reading is not a
 * sample captured at the epoch. */
#define WZ_REPLAY_NO_TIMESTAMP UINT64_MAX
/* No ceiling — the spelling of "unbounded" for max_gap_millis and
 * max_total_millis alike. A ceiling of UINT64_MAX ms is one nothing reaches,
 * so the sentinel costs no value you could have meant. */
#define WZ_REPLAY_NO_CEILING UINT64_MAX

/* ------------------------------------------------------------- vocabulary
 *
 * Each block below mirrors one Rust enum in wz-replay's plan half, and the
 * WZ-ABI-MIRRORS line is machine-read: scripts/lib/capi_replay_vocabulary.py
 * DERIVES the variant set from that crate's source and fails if this file does
 * not name a constant for each. A header naming five of six values compiles,
 * links, passes every ABI test, and tells you that a value you will receive
 * does not exist — which is what the gate is for, and what wz-capi-dissect
 * paid for first.
 */

/* WZ-ABI-MIRRORS: Timing -> WZ_REPLAY_TIMING_ */
/* Every gap is `gap_millis`. The DEFAULT the command line keeps. */
#define WZ_REPLAY_TIMING_DECLARED 0
/* Use the interval the CAPTURE recorded between consecutive samples, falling
 * back to `gap_millis` for a pair with no resolvable time. */
#define WZ_REPLAY_TIMING_CAPTURE 1

/* WZ-ABI-MIRRORS: TimingSource -> WZ_REPLAY_SOURCE_ */
/* The declared gap. */
#define WZ_REPLAY_SOURCE_DECLARED 0
/* The interval between this sample's capture time and the previous one's. */
#define WZ_REPLAY_SOURCE_MEASURED 1
/* The capture was ASKED for a time and could not answer.
 *
 * Distinct from WZ_REPLAY_SOURCE_DECLARED on the rule this library applies to
 * every fallback: one that reads like a choice hides the fact that a
 * measurement was wanted and missing. Folding the two throws away the only
 * evidence that your replay was not the capture's pace. */
#define WZ_REPLAY_SOURCE_UNMEASURABLE 2

/* WZ-ABI-MIRRORS: Mutation -> WZ_REPLAY_MUTATION_
 *
 * `operand` and `seed` are wz_replay_mutate's two parameters; which one an arm
 * reads is stated per arm. An arm that reads neither ignores both. Every
 * mutation is a pure function of the payload and these numbers — a fuzzing run
 * that cannot be repeated is a bug report nobody can act on. */
/* Send it as captured. Reads neither operand nor seed. */
#define WZ_REPLAY_MUTATION_NONE 0
/* Flip one bit; `operand` is a BIT index. A payload shorter than that is left
 * alone and *changed is 0. */
#define WZ_REPLAY_MUTATION_FLIP_BIT 1
/* Keep the first `operand` bytes. Longer payloads are cut; shorter ones are
 * left alone. */
#define WZ_REPLAY_MUTATION_TRUNCATE 2
/* Append `operand` bytes derived from `seed` — the arm that finds a length
 * field nobody checks, and the ONLY arm whose output is longer than its
 * input. */
#define WZ_REPLAY_MUTATION_EXTEND 3
/* Rewrite every byte from `seed`, keeping the length. */
#define WZ_REPLAY_MUTATION_SCRAMBLE 4

/* WZ-ABI-MIRRORS: ScheduleError -> WZ_REPLAY_ERR_
 *
 * The two refusals a schedule can carry, mirrored onto the result codes above
 * rather than onto a family of their own: a caller reads one int from
 * wz_replay_schedule_check and must not have to know which namespace a code
 * came from. */

/* ------------------------------------------------------------------ types */

/* One emission's pacing: how long to wait, and which clock said so.
 *
 * A fixed-layout record rather than a document, because these are the scalars
 * you read once per emission at the rate your own plan runs. Confirm the
 * layout with wz_replay_emission_layout if you bind to this from another
 * language. */
typedef struct wz_replay_emission {
    /* Milliseconds to wait before this emission. Zero for the first. */
    uint64_t delay_millis;
    /* One of the WZ_REPLAY_SOURCE_* values. */
    int32_t source;
    /* Explicit tail padding, always zero. Reserved. */
    int32_t reserved;
} wz_replay_emission;

/* ------------------------------------------------------------------ doors */

/* The ABI revision this build implements. Moves when a symbol, a vocabulary
 * constant, or the memory rule changes. */
int32_t wz_replay_abi_version(void);

/* The layout of wz_replay_emission, as the ARTIFACT reports it.
 *
 * Fills `out` with { size, align, offset(delay_millis), offset(source),
 * offset(reserved) } and returns how many values the layout has. A null `out`,
 * or a `cap` below that count, writes nothing and returns the count. */
size_t wz_replay_emission_layout(size_t *out, size_t cap);

/* Is this schedule one that can be played?
 *
 * The cheap door, for validating a control surface as an operator types into
 * it rather than when they press play. Computes no delays and touches no
 * buffer.
 *
 * Returns WZ_REPLAY_OK, WZ_REPLAY_ERR_UNKNOWN_TIMING,
 * WZ_REPLAY_ERR_SPEED_NOT_POSITIVE or WZ_REPLAY_ERR_SPEED_NOT_FINITE. It
 * cannot answer WZ_REPLAY_ERR_PLAN_TOO_LONG: a whole-plan ceiling is only
 * knowable once the samples are known. */
int32_t wz_replay_schedule_check(int32_t timing,
                                 uint64_t gap_millis,
                                 double speed,
                                 uint64_t max_gap_millis,
                                 uint64_t max_total_millis);

/* PACE a plan: the delay before each emission and which clock it came from.
 *
 * `captured_at_millis` is `count` capture times in the order you will send
 * them, each a reading in milliseconds since the Unix epoch or
 * WZ_REPLAY_NO_TIMESTAMP. It may be NULL, which is every sample having no
 * reading.
 *
 * `out` receives `count` records. It may be NULL with `out_cap` zero, which
 * asks only for the total and the verdict — the check to make before you
 * allocate. A NON-NULL `out` with `out_cap` below `count` is
 * WZ_REPLAY_ERR_INVALID_ARG and writes nothing: you supplied `count`, so the
 * size you need is a number you already have, and a partly filled buffer
 * would hand you a pacing whose tail is missing with no way to tell.
 *
 * `total_millis_out` receives the whole plan's wall clock and may be NULL.
 *
 * PASS THE TIMES OF THE SAMPLES YOU WILL ACTUALLY SEND, already narrowed. wz
 * narrows before pacing for a stated reason: a selector that drops the message
 * between two kept ones WIDENS the real interval, and pacing the unnarrowed
 * list plays a conversation you are not sending.
 *
 * A SAMPLE WITH NO TIME DOES NOT RESET THE ANCHOR: the pair either side of a
 * hole measures ACROSS it, against the last resolvable reading.
 *
 * Returns WZ_REPLAY_OK, or WZ_REPLAY_ERR_PLAN_TOO_LONG with the delays and the
 * total STILL WRITTEN. A schedule refusal or a bad argument writes nothing. */
int32_t wz_replay_plan_delays(int32_t timing,
                              uint64_t gap_millis,
                              double speed,
                              uint64_t max_gap_millis,
                              uint64_t max_total_millis,
                              const uint64_t *captured_at_millis,
                              size_t count,
                              wz_replay_emission *out,
                              size_t out_cap,
                              uint64_t *total_millis_out);

/* MUTATE a payload the way a replay would.
 *
 * `out` may be NULL with `out_cap` zero to ask only for the length: *out_len is
 * written either way, and a buffer shorter than it answers
 * WZ_REPLAY_ERR_BUFFER_TOO_SMALL having written nothing to `out`. Only
 * WZ_REPLAY_MUTATION_EXTEND can produce a payload longer than the input, so a
 * caller that never extends may size at `payload_len`.
 *
 * `changed` receives 1 or 0 and may be NULL. It is not decoration: a mutation
 * whose target lies outside the payload leaves the bytes alone, and a run that
 * silently changed nothing looks exactly like one that found nothing.
 *
 * `out_len` is the one pointer with no NULL spelling — without it the call has
 * no answer to give. */
int32_t wz_replay_mutate(int32_t mutation,
                         uint64_t operand,
                         uint64_t seed,
                         const uint8_t *payload,
                         size_t payload_len,
                         uint8_t *out,
                         size_t out_cap,
                         size_t *out_len,
                         int32_t *changed);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* WZ_REPLAY_H */
