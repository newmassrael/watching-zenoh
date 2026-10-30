/* SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * The four instruments of the observation plane (the clock a program
 * registers, the event log, the supervisor and the resource snapshot),
 * driven from a REAL C translation unit: the wz_capi_c_* doors compiled
 * against wz_capi_c.h and linked against a library built with the four
 * features on, as a consumer's program is.
 *
 * What the Rust tests of the same doors cannot show, and this can: that
 * the header compiles as C, that the symbols export under the names the
 * header declares, that the two structs a program reads and writes
 * (wz_capi_c_event_t, wz_capi_c_resource_reading_t) have the size and the
 * field offsets the header gives them, that a callback written in C is
 * called with the arguments the header says, and that the revision the
 * library reports is the one the header was written for.
 *
 * The layout numbers below are written out here and not taken from the
 * library: a struct whose field moved on one side would fail here rather than
 * agree with itself.
 */

/* nanosleep is POSIX, and the lane compiles with -std=c11. */
#define _POSIX_C_SOURCE 200809L

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

/* ---- The layout both sides must agree on ---------------------------- */

static void check_layout(void) {
    CHECK(sizeof(wz_capi_c_event_t) == 24, "event is %zu bytes", sizeof(wz_capi_c_event_t));
    CHECK(offsetof(wz_capi_c_event_t, kind) == 0, "kind");
    CHECK(offsetof(wz_capi_c_event_t, level) == 1, "level");
    CHECK(offsetof(wz_capi_c_event_t, arg_count) == 2, "arg_count");
    CHECK(offsetof(wz_capi_c_event_t, source) == 4, "source");
    CHECK(offsetof(wz_capi_c_event_t, sequence) == 8, "sequence");
    CHECK(offsetof(wz_capi_c_event_t, timestamp) == 16, "timestamp");

    CHECK(sizeof(wz_capi_c_resource_reading_t) == 24, "reading is %zu bytes",
          sizeof(wz_capi_c_resource_reading_t));
    CHECK(offsetof(wz_capi_c_resource_reading_t, available) == 0, "available");
    CHECK(offsetof(wz_capi_c_resource_reading_t, cpu_permille) == 2, "cpu_permille");
    CHECK(offsetof(wz_capi_c_resource_reading_t, tasks) == 4, "tasks");
    CHECK(offsetof(wz_capi_c_resource_reading_t, heap_in_use) == 8, "heap_in_use");
    CHECK(offsetof(wz_capi_c_resource_reading_t, heap_high_water) == 16, "heap_high_water");

    CHECK(WZ_CAPI_C_E_FULL == -101, "the code for a full thing is %d", WZ_CAPI_C_E_FULL);
    CHECK(wz_capi_c_abi_version() == WZ_CAPI_C_ABI_REVISION,
          "the library is revision %d and this header is %d", (int)wz_capi_c_abi_version(),
          WZ_CAPI_C_ABI_REVISION);
}

/* ---- The clock a program registers ---------------------------------- */

static int8_t read_a_fixed_time(void *context, uint64_t *secs, uint32_t *nanos) {
    (void)context;
    *secs = 1700000000u;
    *nanos = 7u;
    return 0;
}

static void check_clock(void) {
    uint32_t handle = UINT32_MAX;
    CHECK(wz_capi_c_clock_source_register(NULL, NULL, &handle) == Z_ENULL,
          "a NULL callback is Z_ENULL");
    CHECK(wz_capi_c_clock_source_register(read_a_fixed_time, NULL, &handle) == Z_OK,
          "a callback registers");
    CHECK(handle != UINT32_MAX, "the handle was written");
    CHECK(wz_capi_c_clock_report(WZ_CAPI_C_CLOCK_SYNC_ACQUIRED) == Z_OK, "acquired is reported");
    CHECK(wz_capi_c_clock_report(WZ_CAPI_C_CLOCK_SYNC_LOST) == Z_OK, "lost is reported");
    CHECK(wz_capi_c_clock_report(99) == Z_EINVAL, "an unknown event is Z_EINVAL");
    CHECK(wz_capi_c_clock_source_unregister(handle) == Z_OK, "the clock is removed");
    CHECK(wz_capi_c_clock_source_unregister(handle) == Z_EINVAL,
          "a handle is spent once it is removed");
}

/* ---- The event log -------------------------------------------------- */

static void check_events(void) {
    const uint64_t args[3] = {11u, 22u, 33u};
    CHECK(wz_capi_c_event_emit(3, 7, args, 3) == Z_OK, "an event is written");
    CHECK(wz_capi_c_event_emit(3, 7, NULL, 1) == Z_ENULL,
          "NULL arguments with a count are Z_ENULL");

    uint64_t cursor = 0;
    uint64_t got[8];
    int found = 0;
    for (int i = 0; i < 4096 && !found; i++) {
        wz_capi_c_event_t event;
        memset(&event, 0xAA, sizeof event);
        z_result_t rc = wz_capi_c_event_read(&cursor, &event, got, 8);
        CHECK(rc == Z_OK, "a read answers Z_OK, not %d", (int)rc);
        if (event.kind == WZ_CAPI_C_EVENT_EMPTY) {
            break;
        }
        if (event.kind == WZ_CAPI_C_EVENT_RECORD && event.source == 7 && event.level == 3) {
            CHECK(event.arg_count == 3, "the event carries %u integers", (unsigned)event.arg_count);
            CHECK(got[0] == 11u && got[1] == 22u && got[2] == 33u, "its integers came back");
            found = 1;
        }
    }
    CHECK(found, "the event written is in the log");
    CHECK(wz_capi_c_event_release(cursor) == Z_OK, "the reader says it is done");
}

/* ---- The supervisor ------------------------------------------------- */

static int hook_calls = 0;
static uint8_t hook_checkpoint = 255;

static void count_an_expiry(void *context, uint8_t checkpoint) {
    (void)context;
    hook_calls++;
    hook_checkpoint = checkpoint;
}

static void sleep_ms(long ms) {
    struct timespec t;
    t.tv_sec = ms / 1000;
    t.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&t, NULL);
}

static void check_supervision(void) {
    CHECK(wz_capi_c_supervision_start(255, 100) == Z_EINVAL, "a checkpoint there is none of");
    CHECK(wz_capi_c_supervision_state(255) == WZ_CAPI_C_SUPERVISION_NO_SUCH_CHECKPOINT,
          "it has no state");
    CHECK(wz_capi_c_supervision_healthy() == 0, "nothing supervised is not healthy");

    CHECK(wz_capi_c_supervision_set_hook(count_an_expiry, NULL) == Z_OK, "the hook is set");
    CHECK(wz_capi_c_supervision_start(0, 20) == Z_OK, "checkpoint 0 starts");
    CHECK(wz_capi_c_supervision_state(0) == WZ_CAPI_C_SUPERVISION_ARMED, "it is armed");
    CHECK(wz_capi_c_supervision_healthy() == 1, "and the node is healthy");
    CHECK(wz_capi_c_supervision_feed(0) == Z_OK, "a feed in time is taken");

    sleep_ms(60);
    CHECK(wz_capi_c_supervision_check() == Z_OK, "a check runs");
    CHECK(wz_capi_c_supervision_check() == Z_OK, "and runs again");
    CHECK(hook_calls == 1, "the hook ran %d times for one expiry", hook_calls);
    CHECK(hook_checkpoint == 0, "and was told checkpoint %u", (unsigned)hook_checkpoint);
    CHECK(wz_capi_c_supervision_healthy() == 0, "an expired checkpoint is not healthy");
    CHECK(wz_capi_c_supervision_stop(0) == Z_OK, "the program stops it");
    CHECK(wz_capi_c_supervision_set_hook(NULL, NULL) == Z_OK, "the hook is cleared");
}

/* ---- The resource snapshot ------------------------------------------ */

static void check_snapshot(void) {
    /* What a session is needed for is the message count; nothing here opens one. */
    CHECK(wz_capi_c_snapshot_poll(NULL) == Z_ENULL, "poll of no session is Z_ENULL");
    size_t size = wz_capi_c_snapshot_size();
    CHECK(size > 24, "the record is %zu bytes", size);

    uint8_t buffer[4];
    size_t length = 99;
    z_result_t rc = wz_capi_c_snapshot_read(buffer, sizeof buffer, &length);
    CHECK(rc == Z_EGENERIC || rc == WZ_CAPI_C_E_FULL,
          "a read of nothing, or of too little, is refused (%d)", (int)rc);
    CHECK(length == 99, "a refused read writes no length");
    CHECK(wz_capi_c_snapshot_read(NULL, 0, &length) == Z_ENULL, "a NULL buffer is Z_ENULL");
    CHECK(wz_capi_c_snapshot_set_source(NULL, NULL) == Z_OK, "clearing the source is accepted");
}

int main(void) {
    check_layout();
    check_clock();
    check_events();
    check_supervision();
    check_snapshot();
    if (failures != 0) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("c_observation_plane_consumer: ok\n");
    return 0;
}
