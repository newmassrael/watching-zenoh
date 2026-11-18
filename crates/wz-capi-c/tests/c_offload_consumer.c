/* SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * A subscriber whose callback runs off the receive path, declared from a REAL
 * C translation unit: the two structs, the four values a statement takes and
 * the three wz_capi_c_*offload* doors, compiled against wz_capi_c.h and
 * linked against the library built with `rx-callback-offload`.
 *
 * What the Rust tests of the same doors cannot show, and this can: that the
 * header compiles as C, that every symbol exports under the name it declares,
 * that the structs agree in layout on both sides of the boundary (the sizes
 * and offsets are written out here and not taken from the library), and that a
 * callback a C program hands the door runs on a thread that is not the one
 * that made the put.
 *
 * The session is a peer with no link and no scouting, so every sample is one
 * the session puts to itself and the consumer needs no peer. A plain
 * subscriber's callback for such a put runs inside z_put, on the calling
 * thread; the offloaded one must run elsewhere.
 */

#define _POSIX_C_SOURCE 200809L

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "wz_capi_c.h"

static int failures = 0;

#define CHECK(cond, ...)                                                      \
    do {                                                                      \
        if (!(cond)) {                                                        \
            fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);             \
            fprintf(stderr, __VA_ARGS__);                                     \
            fprintf(stderr, "\n");                                            \
            failures++;                                                       \
        }                                                                     \
    } while (0)

/* What one subscriber's callback saw: how many samples, the thread of the
 * first, and how many times its drop ran. */
typedef struct {
    atomic_int calls;
    atomic_int drops;
    atomic_bool first_seen;
    pthread_t first_thread;
} seen_t;

static void seen_init(seen_t *seen) {
    atomic_init(&seen->calls, 0);
    atomic_init(&seen->drops, 0);
    atomic_init(&seen->first_seen, false);
}

static void on_sample(z_loaned_sample_t *sample, void *context) {
    (void)sample;
    seen_t *seen = context;
    if (atomic_fetch_add(&seen->calls, 1) == 0) {
        seen->first_thread = pthread_self();
        atomic_store_explicit(&seen->first_seen, true, memory_order_release);
    }
}

static void on_drop(void *context) {
    seen_t *seen = context;
    atomic_fetch_add(&seen->drops, 1);
}

static void sleep_ms(long ms) {
    struct timespec ts = {ms / 1000, (ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

/* Wait up to ten seconds for `counter` to reach `want`. */
static bool wait_for(atomic_int *counter, int want) {
    for (int i = 0; i < 2000; i++) {
        if (atomic_load(counter) >= want) {
            return true;
        }
        sleep_ms(5);
    }
    return atomic_load(counter) >= want;
}

static void check_layout(void) {
    CHECK(sizeof(wz_capi_c_offload_options_t) == 1, "options size");
    CHECK(offsetof(wz_capi_c_offload_options_t, overload) == 0, "options overload");

    CHECK(sizeof(wz_capi_c_offload_stats_t) == 88, "stats size %zu",
          sizeof(wz_capi_c_offload_stats_t));
    CHECK(offsetof(wz_capi_c_offload_stats_t, queued_events) == 0, "queued_events");
    CHECK(offsetof(wz_capi_c_offload_stats_t, event_capacity) == 8, "event_capacity");
    CHECK(offsetof(wz_capi_c_offload_stats_t, pending_bytes) == 16, "pending_bytes");
    CHECK(offsetof(wz_capi_c_offload_stats_t, byte_capacity) == 24, "byte_capacity");
    CHECK(offsetof(wz_capi_c_offload_stats_t, refused_events_full) == 32, "refused_events_full");
    CHECK(offsetof(wz_capi_c_offload_stats_t, refused_bytes_full) == 40, "refused_bytes_full");
    CHECK(offsetof(wz_capi_c_offload_stats_t, refused_stopping) == 48, "refused_stopping");
    CHECK(offsetof(wz_capi_c_offload_stats_t, evicted) == 56, "evicted");
    CHECK(offsetof(wz_capi_c_offload_stats_t, dropped_reliable) == 64, "dropped_reliable");
    CHECK(offsetof(wz_capi_c_offload_stats_t, dropped_best_effort) == 72, "dropped_best_effort");
    CHECK(offsetof(wz_capi_c_offload_stats_t, overload) == 80, "overload");
}

static void check_values(void) {
    CHECK(WZ_CAPI_C_OVERLOAD_BUILD == 0, "build value");
    CHECK(WZ_CAPI_C_OVERLOAD_BLOCK == 1, "block value");
    CHECK(WZ_CAPI_C_OVERLOAD_REJECT == 2, "reject value");
    CHECK(WZ_CAPI_C_OVERLOAD_KEEP_LATEST == 3, "keep-latest value");

    wz_capi_c_offload_options_t options;
    memset(&options, 0xa5, sizeof options);
    wz_capi_c_offload_options_default(&options);
    CHECK(options.overload == WZ_CAPI_C_OVERLOAD_REJECT, "default statement %d",
          options.overload);
    /* NULL is no write and no fault. */
    wz_capi_c_offload_options_default(NULL);
}

/* The doors called with nothing behind them answer as their z_* twins do. */
static void check_null_refusals(void) {
    z_owned_subscriber_t subscriber;
    memset(&subscriber, 0xa5, sizeof subscriber);
    z_moved_closure_sample_t sample;
    memset(&sample, 0, sizeof sample);
    CHECK(wz_capi_c_declare_subscriber_offloaded(NULL, &subscriber, NULL, &sample, NULL, NULL) ==
              Z_ENULL,
          "declare on no session");
    CHECK(!z_internal_subscriber_check(&subscriber), "a subscriber left behind");

    wz_capi_c_offload_stats_t stats;
    memset(&stats, 0xa5, sizeof stats);
    wz_capi_c_offload_stats_t untouched = stats;
    CHECK(wz_capi_c_subscriber_offload_stats(NULL, &stats) == Z_ENULL, "stats of no subscriber");
    CHECK(memcmp(&stats, &untouched, sizeof stats) == 0, "stats written on a refusal");
}

static z_result_t declare(const z_loaned_session_t *session, z_owned_subscriber_t *subscriber,
                          const char *key, seen_t *seen,
                          const wz_capi_c_offload_options_t *offload) {
    z_view_keyexpr_t keyexpr;
    z_result_t rc = z_view_keyexpr_from_str(&keyexpr, key);
    CHECK(rc == Z_OK, "keyexpr %s", key);
    z_owned_closure_sample_t callback;
    z_closure(&callback, on_sample, on_drop, seen);
    return wz_capi_c_declare_subscriber_offloaded(session, subscriber, z_loan(keyexpr),
                                                  z_move(callback), NULL, offload);
}

static void put(const z_loaned_session_t *session, const char *key) {
    z_view_keyexpr_t keyexpr;
    CHECK(z_view_keyexpr_from_str(&keyexpr, key) == Z_OK, "keyexpr %s", key);
    z_owned_bytes_t payload;
    CHECK(z_bytes_copy_from_str(&payload, "x") == Z_OK, "payload");
    CHECK(z_put(session, z_loan(keyexpr), z_move(payload), NULL) == Z_OK, "put on %s", key);
}

static void check_session(void) {
    z_owned_config_t config;
    CHECK(z_config_default(&config) == Z_OK, "config");
    CHECK(zc_config_insert_json5(z_loan_mut(config), "mode", "\"peer\"") == Z_OK, "mode");
    CHECK(zc_config_insert_json5(z_loan_mut(config), "scouting/multicast/enabled", "false") ==
              Z_OK,
          "scouting");
    z_owned_session_t session;
    if (z_open(&session, z_move(config), NULL) != Z_OK) {
        CHECK(false, "open");
        return;
    }
    const z_loaned_session_t *loaned = z_loan(session);

    /* Declared with NULL, the default statement: reject, in every build. The
     * callback runs, and not on this thread. */
    seen_t seen;
    seen_init(&seen);
    z_owned_subscriber_t subscriber;
    z_result_t rc = declare(loaned, &subscriber, "wz/c/offload", &seen, NULL);
    CHECK(rc == Z_OK, "declare with NULL options answered %d", rc);
    if (rc == Z_OK) {
        put(loaned, "wz/c/offload");
        CHECK(wait_for(&seen.calls, 1), "the offloaded callback never ran");
        if (atomic_load_explicit(&seen.first_seen, memory_order_acquire)) {
            CHECK(!pthread_equal(seen.first_thread, pthread_self()),
                  "the offloaded callback ran on the putting thread");
        }

        wz_capi_c_offload_stats_t stats;
        memset(&stats, 0xa5, sizeof stats);
        CHECK(wz_capi_c_subscriber_offload_stats(z_loan(subscriber), &stats) == Z_OK, "stats");
        CHECK(stats.overload == WZ_CAPI_C_OVERLOAD_REJECT, "stats overload %d", stats.overload);
        CHECK(stats.event_capacity >= 1, "event capacity");
        CHECK(stats.byte_capacity >= 1, "byte capacity");
        CHECK(stats.refused_events_full == 0, "a refusal with room to spare");
        CHECK(stats.dropped_reliable == 0 && stats.dropped_best_effort == 0, "a loss");

        CHECK(wz_capi_c_subscriber_offload_stats(z_loan(subscriber), NULL) == Z_ENULL,
              "stats into nothing");

        z_drop(z_move(subscriber));
        CHECK(wait_for(&seen.drops, 1), "the drop did not run after the undeclare");
        CHECK(atomic_load(&seen.drops) == 1, "drop ran %d times", atomic_load(&seen.drops));
    }

    /* block is refused, the closure dropped once and nothing declared. */
    seen_t blocked;
    seen_init(&blocked);
    wz_capi_c_offload_options_t block = {WZ_CAPI_C_OVERLOAD_BLOCK};
    z_owned_subscriber_t refused;
    memset(&refused, 0xa5, sizeof refused);
    rc = declare(loaned, &refused, "wz/c/offload/block", &blocked, &block);
    CHECK(rc == Z_EUNAVAILABLE, "block answered %d", rc);
    CHECK(!z_internal_subscriber_check(&refused), "a subscriber left behind by block");
    CHECK(atomic_load(&blocked.drops) == 1, "block dropped the closure %d times",
          atomic_load(&blocked.drops));

    /* A value that names no answer. */
    seen_t invalid;
    seen_init(&invalid);
    wz_capi_c_offload_options_t nine = {9};
    memset(&refused, 0xa5, sizeof refused);
    rc = declare(loaned, &refused, "wz/c/offload/invalid", &invalid, &nine);
    CHECK(rc == Z_EINVAL, "an unnamed value answered %d", rc);
    CHECK(!z_internal_subscriber_check(&refused), "a subscriber left behind by Z_EINVAL");
    CHECK(atomic_load(&invalid.drops) == 1, "Z_EINVAL dropped the closure %d times",
          atomic_load(&invalid.drops));

    /* The build's policy, asked for by name: taken, or refused exactly as
     * block is when that policy is block. Which, this program cannot know. */
    seen_t asked;
    seen_init(&asked);
    wz_capi_c_offload_options_t build = {WZ_CAPI_C_OVERLOAD_BUILD};
    z_owned_subscriber_t by_build;
    rc = declare(loaned, &by_build, "wz/c/offload/build", &asked, &build);
    CHECK(rc == Z_OK || rc == Z_EUNAVAILABLE, "the build's policy answered %d", rc);
    if (rc == Z_OK) {
        wz_capi_c_offload_stats_t stats;
        CHECK(wz_capi_c_subscriber_offload_stats(z_loan(by_build), &stats) == Z_OK, "stats");
        CHECK(stats.overload != WZ_CAPI_C_OVERLOAD_BLOCK, "a lane that blocks");
        z_drop(z_move(by_build));
    } else {
        CHECK(!z_internal_subscriber_check(&by_build), "a subscriber left behind by the build");
        CHECK(atomic_load(&asked.drops) == 1, "the closure dropped %d times",
              atomic_load(&asked.drops));
    }

    /* A subscriber z_declare_subscriber made has no lane to read. */
    seen_t plain_seen;
    seen_init(&plain_seen);
    z_view_keyexpr_t plain_key;
    CHECK(z_view_keyexpr_from_str(&plain_key, "wz/c/offload/plain") == Z_OK, "keyexpr");
    z_owned_closure_sample_t plain_callback;
    z_closure(&plain_callback, on_sample, on_drop, &plain_seen);
    z_owned_subscriber_t plain;
    CHECK(z_declare_subscriber(loaned, &plain, z_loan(plain_key), z_move(plain_callback), NULL) ==
              Z_OK,
          "plain declare");
    wz_capi_c_offload_stats_t stats;
    memset(&stats, 0xa5, sizeof stats);
    wz_capi_c_offload_stats_t untouched = stats;
    CHECK(wz_capi_c_subscriber_offload_stats(z_loan(plain), &stats) == Z_EINVAL,
          "stats of a plain subscriber");
    CHECK(memcmp(&stats, &untouched, sizeof stats) == 0, "stats written for a plain subscriber");
    z_drop(z_move(plain));

    (void)z_close(z_loan_mut(session), NULL);
    z_drop(z_move(session));
}

int main(void) {
    CHECK(wz_capi_c_abi_version() == WZ_CAPI_C_ABI_REVISION,
          "the library reports revision %d, the header is %d", (int)wz_capi_c_abi_version(),
          WZ_CAPI_C_ABI_REVISION);
    check_layout();
    check_values();
    check_null_refusals();
    check_session();
    if (failures != 0) {
        fprintf(stderr, "c_offload_consumer: %d failure(s)\n", failures);
        return 1;
    }
    printf("c_offload_consumer: ok\n");
    return 0;
}
