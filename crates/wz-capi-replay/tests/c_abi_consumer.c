/* SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * Round 2441 (open-debt item 693) — the C consumer this ABI exists for, as a
 * GATE.
 *
 * The item's done condition is not "the symbols exist". It is that a consumer
 * linking the C ABI ONLY can CALL the plan half — the whole report was that
 * such a consumer could reach none of it and so wrote the judgement a second
 * time. A Rust test in the crate cannot show that: it links the rlib, sees
 * `#[no_mangle]` names the compiler already knows, and would pass against a
 * header that says something else entirely.
 *
 * Only a real C translation unit covers what is ONLY true across the boundary:
 * that the header compiles, that the symbols export under the names it
 * declares, that the calling convention agrees for `double` and `uint64_t`
 * mixed in one signature, and that the record layout C computes with
 * `sizeof` / `offsetof` is the one the artifact reports.
 *
 * Driven by run-ci Layer C1cj. Exit 0 = pass; every failure prints what it
 * expected before returning non-zero, because a lane that fails without saying
 * why costs a whole round to diagnose.
 */
#include "wz_replay.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

/* The alignment operator is spelled differently in the two languages this file
 * must compile as, and the C++ leg found that on its first run: `_Alignof` is
 * C11's and C++ has never had it. Named here rather than worked around at the
 * call site, because a consumer binding this ABI from C++ will meet the same
 * fork the moment it checks the record layout. */
#ifdef __cplusplus
#define WZ_ALIGNOF(type) alignof(type)
#else
#define WZ_ALIGNOF(type) _Alignof(type)
#endif

#define CHECK(cond, ...)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            printf("  C1cj FAIL: ");                                           \
            printf(__VA_ARGS__);                                               \
            printf("\n");                                                      \
            return 1;                                                          \
        }                                                                      \
    } while (0)

/* THE RECORD LAYOUT C SEES IS THE ONE THE LIBRARY REPORTS.
 *
 * `sizeof` and `offsetof` here are the CONSUMER's arithmetic, over the struct
 * declared in the header; wz_replay_emission_layout answers with the Rust
 * type's. A disagreement means a consumer reads `source` out of the padding,
 * and it is precisely the failure a Rust-only test cannot see. */
static int check_layout(void)
{
    size_t reported[8];
    size_t count = wz_replay_emission_layout(NULL, 0);
    CHECK(count == 5, "layout has %zu values, expected 5", count);

    memset(reported, 0xAA, sizeof reported);
    count = wz_replay_emission_layout(reported, 2);
    CHECK(count == 5, "a short cap must still return the count");
    CHECK(reported[0] == (size_t)0xAAAAAAAAAAAAAAAAULL ||
              reported[0] != sizeof(wz_replay_emission),
          "a cap below the count must write nothing");

    count = wz_replay_emission_layout(reported, 5);
    CHECK(count == 5, "layout count changed between calls");
    CHECK(reported[0] == sizeof(wz_replay_emission),
          "library says size %zu, C sizeof says %zu", reported[0],
          sizeof(wz_replay_emission));
    CHECK(reported[1] == WZ_ALIGNOF(wz_replay_emission),
          "library says align %zu, the caller's alignof says %zu", reported[1],
          WZ_ALIGNOF(wz_replay_emission));
    CHECK(reported[2] == offsetof(wz_replay_emission, delay_millis),
          "delay_millis at %zu, C says %zu", reported[2],
          offsetof(wz_replay_emission, delay_millis));
    CHECK(reported[3] == offsetof(wz_replay_emission, source),
          "source at %zu, C says %zu", reported[3],
          offsetof(wz_replay_emission, source));
    CHECK(reported[4] == offsetof(wz_replay_emission, reserved),
          "reserved at %zu, C says %zu", reported[4],
          offsetof(wz_replay_emission, reserved));
    return 0;
}

/* THE PACING A CONSUMER ASKED FOR, over capture times it already holds.
 *
 * These are the times a product gets from wz_dissect_record.ts_ns, sentinel
 * included -- which is why WZ_REPLAY_NO_TIMESTAMP is the same number. */
static int check_pacing(void)
{
    /* A `double` and four `uint64_t` in one signature: the mixed calling
     * convention is a thing only a real C caller exercises. */
    int32_t rc = wz_replay_schedule_check(WZ_REPLAY_TIMING_CAPTURE, 100, 2.0,
                                          WZ_REPLAY_NO_CEILING,
                                          WZ_REPLAY_NO_CEILING);
    CHECK(rc == WZ_REPLAY_OK, "a playable schedule was refused with %d", rc);

    rc = wz_replay_schedule_check(WZ_REPLAY_TIMING_CAPTURE, 100, 0.0,
                                  WZ_REPLAY_NO_CEILING, WZ_REPLAY_NO_CEILING);
    CHECK(rc == WZ_REPLAY_ERR_SPEED_NOT_POSITIVE,
          "speed 0 gave %d, expected WZ_REPLAY_ERR_SPEED_NOT_POSITIVE", rc);

    rc = wz_replay_schedule_check(7, 100, 1.0, WZ_REPLAY_NO_CEILING,
                                  WZ_REPLAY_NO_CEILING);
    CHECK(rc == WZ_REPLAY_ERR_UNKNOWN_TIMING,
          "an unnamed timing word gave %d, expected "
          "WZ_REPLAY_ERR_UNKNOWN_TIMING",
          rc);

    /* Four samples: two measurable, one with no reading, one measuring across
     * the hole. THE THIRD IS THE ONE A SECOND IMPLEMENTATION GETS WRONG. */
    const uint64_t times[4] = {1000, 1400, WZ_REPLAY_NO_TIMESTAMP, 2400};
    wz_replay_emission out[4];
    uint64_t total = 0;

    memset(out, 0xFF, sizeof out);
    rc = wz_replay_plan_delays(WZ_REPLAY_TIMING_CAPTURE, 50, 1.0,
                               WZ_REPLAY_NO_CEILING, WZ_REPLAY_NO_CEILING,
                               times, 4, out, 4, &total);
    CHECK(rc == WZ_REPLAY_OK, "pacing refused with %d", rc);
    CHECK(out[0].delay_millis == 0, "the first emission waits for nothing");
    CHECK(out[0].source == WZ_REPLAY_SOURCE_DECLARED, "first source wrong");
    CHECK(out[1].delay_millis == 400, "1400-1000, got %llu",
          (unsigned long long)out[1].delay_millis);
    CHECK(out[1].source == WZ_REPLAY_SOURCE_MEASURED, "second source wrong");
    CHECK(out[2].delay_millis == 50, "the declared gap fills the hole");
    CHECK(out[2].source == WZ_REPLAY_SOURCE_UNMEASURABLE,
          "a fallback must not read as a choice: source was %d, expected "
          "WZ_REPLAY_SOURCE_UNMEASURABLE",
          out[2].source);
    CHECK(out[3].delay_millis == 1000,
          "the anchor sticks across the hole, so this pair is 2400-1400; got "
          "%llu",
          (unsigned long long)out[3].delay_millis);
    CHECK(out[3].source == WZ_REPLAY_SOURCE_MEASURED, "fourth source wrong");
    CHECK(total == 1450, "total was %llu, expected 1450",
          (unsigned long long)total);

    /* THE REFUSAL STILL SHOWS THE PLAN, which is what an operator who hit a
     * ceiling has to be able to read. */
    memset(out, 0xFF, sizeof out);
    total = 0;
    rc = wz_replay_plan_delays(WZ_REPLAY_TIMING_CAPTURE, 50, 1.0,
                               WZ_REPLAY_NO_CEILING, 1000, times, 4, out, 4,
                               &total);
    CHECK(rc == WZ_REPLAY_ERR_PLAN_TOO_LONG, "a plan over its ceiling gave %d",
          rc);
    CHECK(total == 1450, "the refused plan's total must still be reported");
    CHECK(out[3].delay_millis == 1000,
          "the refused plan's emissions must still be written");

    /* The verdict alone, before allocating anything. */
    total = 0;
    rc = wz_replay_plan_delays(WZ_REPLAY_TIMING_CAPTURE, 50, 1.0,
                               WZ_REPLAY_NO_CEILING, 1000, times, 4, NULL, 0,
                               &total);
    CHECK(rc == WZ_REPLAY_ERR_PLAN_TOO_LONG, "the null-buffer form gave %d",
          rc);
    CHECK(total == 1450, "the null-buffer form must still report the total");
    return 0;
}

/* THE MUTATION HALF, sized first and read second the way the header says. */
static int check_mutation(void)
{
    const uint8_t payload[4] = {0x11, 0x22, 0x33, 0x44};
    uint8_t buf[16];
    size_t needed = 0;
    int32_t changed = -1;
    int32_t rc;

    rc = wz_replay_mutate(WZ_REPLAY_MUTATION_EXTEND, 3, 42, payload,
                          sizeof payload, NULL, 0, &needed, &changed);
    CHECK(rc == WZ_REPLAY_ERR_BUFFER_TOO_SMALL,
          "the sizing call gave %d, expected WZ_REPLAY_ERR_BUFFER_TOO_SMALL",
          rc);
    CHECK(needed == 7, "EXTEND by 3 over 4 bytes needs 7, said %zu", needed);

    memset(buf, 0xEE, sizeof buf);
    rc = wz_replay_mutate(WZ_REPLAY_MUTATION_EXTEND, 3, 42, payload,
                          sizeof payload, buf, needed, &needed, &changed);
    CHECK(rc == WZ_REPLAY_OK, "the sized call gave %d", rc);
    CHECK(needed == 7, "length changed between the two calls");
    CHECK(changed == 1, "EXTEND by 3 changed the payload");
    CHECK(memcmp(buf, payload, sizeof payload) == 0,
          "EXTEND must keep the captured bytes in front");
    CHECK(buf[7] == 0xEE, "the call wrote past the length it reported");

    /* A MUTATION THAT MISSED SAYS SO. A fuzzing run that silently changed
     * nothing looks exactly like one that found nothing. */
    changed = -1;
    rc = wz_replay_mutate(WZ_REPLAY_MUTATION_FLIP_BIT, 9000, 0, payload,
                          sizeof payload, buf, sizeof buf, &needed, &changed);
    CHECK(rc == WZ_REPLAY_OK, "a missed flip gave %d", rc);
    CHECK(changed == 0, "a flip outside the payload must report changed == 0");
    CHECK(needed == sizeof payload, "a missed flip keeps the length");

    /* THE SEED REPEATS, which is what makes a fuzzing find actionable. */
    uint8_t first[8];
    uint8_t again[8];
    rc = wz_replay_mutate(WZ_REPLAY_MUTATION_SCRAMBLE, 0, 7, payload,
                          sizeof payload, first, sizeof first, &needed, NULL);
    CHECK(rc == WZ_REPLAY_OK, "scramble gave %d", rc);
    rc = wz_replay_mutate(WZ_REPLAY_MUTATION_SCRAMBLE, 0, 7, payload,
                          sizeof payload, again, sizeof again, &needed, NULL);
    CHECK(rc == WZ_REPLAY_OK, "the repeat scramble gave %d", rc);
    CHECK(memcmp(first, again, needed) == 0,
          "the same seed must give the same bytes");

    rc = wz_replay_mutate(99, 0, 0, payload, sizeof payload, NULL, 0, &needed,
                          NULL);
    CHECK(rc == WZ_REPLAY_ERR_UNKNOWN_MUTATION,
          "an unnamed mutation gave %d, expected "
          "WZ_REPLAY_ERR_UNKNOWN_MUTATION",
          rc);
    return 0;
}

int main(void)
{
    int32_t version = wz_replay_abi_version();
    if (version < 1) {
        printf("  C1cj FAIL: abi version %d\n", version);
        return 1;
    }
    if (check_layout()) {
        return 1;
    }
    if (check_pacing()) {
        return 1;
    }
    if (check_mutation()) {
        return 1;
    }
    printf("  C1cj: wz-capi-replay C consumer OK (abi %d)\n", version);
    return 0;
}
