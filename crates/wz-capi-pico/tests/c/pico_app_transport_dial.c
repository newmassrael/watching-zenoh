/*
 * SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * A zenoh-pico C program that DIALS over a transport it supplies (wz_ext_transport_*,
 * wz_ext.h) and answers nothing: the client half of pico_app_transport.c, which needs no
 * listener, no group and no query, so it is the check of the app-transport capability on any
 * build that has it (the host library without std among them).
 *
 * What it holds is the wait of a dial: the session asks the program to open a stream, the
 * program answers that the open is under way and reports it connected from a task of its own
 * 300 ms later, and the session's dial, waiting on the program's transport, must be woken by
 * that report (its first bytes, the handshake's opening message, arrive soon after it, not at
 * the end of the dial's bound) and must not have ended before it. A second dial the program
 * never reports up must be given up after a wait, neither at once nor never. Nothing answers
 * the handshake, so both opens fail; that failure is expected.
 *
 * Exit status 0 means every check held; the last line printed is the count either way.
 */

#include <stdio.h>
#include <string.h>

#include <zenoh-pico.h>

#include "wz_ext.h"

/* The report comes from a task, which is the multi-threaded arm's. */
#if Z_FEATURE_MULTI_THREAD != 1
#error "pico_app_transport_dial.c is a program of the multi-threaded arm: build the library with multi-thread"
#endif

#define LOCATOR "tcp/192.0.2.100:7447"
#define REPORT_AFTER_MS 300

static int checks = 0;
static int failures = 0;

#define CHECK(cond, ...)                                                     \
    do {                                                                     \
        checks++;                                                            \
        if (!(cond)) {                                                       \
            failures++;                                                      \
            printf("pico-app-transport-dial: FAIL at line %d: ", __LINE__);  \
            printf(__VA_ARGS__);                                             \
            printf("\n");                                                    \
        }                                                                    \
    } while (0)

/* What the program saw, under `lock`: the session calls in from its own threads. */
static struct {
    z_owned_mutex_t lock;
    wz_ext_owned_transport_t transport;
    int report;               /* report the dial connected from the task */
    int opens;
    int open_kind;
    char open_locator[64];
    wz_ext_link_t link;
    int sends;
    unsigned char first[8];
    size_t first_len;
    unsigned long first_send_ms; /* since the open began */
    unsigned long reported_ms;   /* since the open began, when the task reported */
    int drops;
    z_clock_t started;
} seen;

static void lock(void) { z_mutex_lock(z_mutex_loan_mut(&seen.lock)); }
static void unlock(void) { z_mutex_unlock(z_mutex_loan_mut(&seen.lock)); }

static wz_ext_link_result_t on_open(void *context, wz_ext_link_t link, wz_ext_link_kind_t kind,
                                    const char *locator) {
    (void)context;
    lock();
    seen.opens++;
    seen.open_kind = kind;
    seen.link = link;
    snprintf(seen.open_locator, sizeof seen.open_locator, "%s", locator);
    unlock();
    /* Under way: the task reports it, or nothing ever does. */
    return WZ_EXT_LINK_WOULD_BLOCK;
}

static wz_ext_link_result_t on_send(void *context, wz_ext_link_t link, const uint8_t *data, size_t len,
                                    size_t *written) {
    (void)context;
    (void)link;
    lock();
    if (seen.sends++ == 0) seen.first_send_ms = z_clock_elapsed_ms(&seen.started);
    /* The first bytes, across sends: the length prefix may be a send of its own. */
    size_t room = sizeof seen.first - seen.first_len;
    size_t take = len < room ? len : room;
    memcpy(seen.first + seen.first_len, data, take);
    seen.first_len += take;
    unlock();
    /* Taken and carried nowhere: no peer answers. */
    *written = len;
    return WZ_EXT_LINK_OK;
}

static void on_close(void *context, wz_ext_link_t link) {
    (void)context;
    (void)link;
}

static void on_drained(void *context, wz_ext_link_t link) {
    (void)context;
    (void)link;
}

static void on_drop(void *context) {
    (void)context;
    lock();
    seen.drops++;
    unlock();
}

/* The task: report the dialled link connected REPORT_AFTER_MS after the open began. */
static void *reporter(void *arg) {
    (void)arg;
    wz_ext_link_t link = 0;
    for (int i = 0; i < 500 && link == 0; i++) {
        lock();
        link = seen.link;
        unlock();
        if (link == 0) z_sleep_ms(1);
    }
    z_sleep_ms(REPORT_AFTER_MS);
    lock();
    seen.reported_ms = z_clock_elapsed_ms(&seen.started);
    unlock();
    if (link != 0) {
        wz_ext_transport_event(wz_ext_transport_loan(&seen.transport), link, WZ_EXT_LINK_EVENT_CONNECTED);
    }
    return NULL;
}

/* Open a client session dialling LOCATOR over a fresh transport; the rc of z_open, and how long it
 * took. */
static int dial(int report, unsigned long *took_ms) {
    lock();
    seen.report = report;
    seen.opens = 0;
    seen.link = 0;
    seen.sends = 0;
    seen.first_len = 0;
    seen.reported_ms = 0;
    seen.drops = 0;
    unlock();

    wz_ext_transport_t calls;
    memset(&calls, 0, sizeof calls);
    calls.open = on_open;
    calls.send = on_send;
    calls.close = on_close;
    calls.drained = on_drained;
    calls.drop = on_drop;
    CHECK(wz_ext_transport_new(&seen.transport, &calls) == Z_OK, "wz_ext_transport_new");

    z_owned_config_t config;
    z_config_default(&config);
    zp_config_insert(z_config_loan_mut(&config), Z_CONFIG_CONNECT_KEY, LOCATOR);
    CHECK(wz_ext_config_transport(z_config_loan_mut(&config), wz_ext_transport_loan(&seen.transport)) == Z_OK,
          "wz_ext_config_transport");

    z_owned_task_t task;
    int tasked = 0;
    seen.started = z_clock_now();
    if (report) {
        tasked = z_task_init(&task, NULL, reporter, NULL) == Z_OK;
        CHECK(tasked, "z_task_init");
    }
    z_owned_session_t session;
    int rc = z_open(&session, z_config_move(&config), NULL);
    *took_ms = z_clock_elapsed_ms(&seen.started);
    if (rc == Z_OK) {
        z_close(z_session_loan_mut(&session), NULL);
        z_session_drop(z_session_move(&session));
    }
    if (tasked) z_task_join(z_task_move(&task));
    wz_ext_transport_drop(wz_ext_transport_move(&seen.transport));
    for (int i = 0; i < 1000; i++) {
        lock();
        int drops = seen.drops;
        unlock();
        if (drops > 0) break;
        z_sleep_ms(10);
    }
    return rc;
}

int main(void) {
    memset(&seen, 0, sizeof seen);
    z_mutex_init(&seen.lock);

    /* A dial the program reports connected from its task. */
    unsigned long took = 0;
    int rc = dial(1, &took);
    lock();
    CHECK(seen.opens >= 1, "the session never asked the program to open a link");
    CHECK(seen.open_kind == WZ_EXT_LINK_STREAM_DIAL, "the open was of kind %d, not a stream dial", seen.open_kind);
    CHECK(strcmp(seen.open_locator, LOCATOR) == 0, "the open named '%s'", seen.open_locator);
    CHECK(seen.sends > 0, "the dial sent nothing once reported connected");
    /* A stream is framed by the session: a two-byte length, then the batch, whose first
     * message is the handshake's opening one (zenoh's InitSyn, id 0x01 in the low five bits). */
    CHECK(seen.first_len >= 3 && (seen.first[2] & 0x1f) == 0x01, "the first bytes were not a framed handshake");
    CHECK(seen.reported_ms >= REPORT_AFTER_MS - 50 && seen.first_send_ms + 50 >= seen.reported_ms,
          "the dial sent at %lu ms, before the report at %lu ms", seen.first_send_ms, seen.reported_ms);
    CHECK(seen.first_send_ms < seen.reported_ms + 2000,
          "the dial sent %lu ms after the report: it was not woken by it", seen.first_send_ms - seen.reported_ms);
    CHECK(seen.drops == 1, "the transport dropped %d time(s)", seen.drops);
    unlock();
    CHECK(rc != Z_OK, "an open nothing answered succeeded");
    printf("pico-app-transport-dial: the reported dial ended in %lu ms (rc %d)\n", took, rc);

    /* A dial the program never reports up: given up after a wait, neither at once nor never. */
    rc = dial(0, &took);
    lock();
    CHECK(seen.opens >= 1, "the second dial never asked the program to open a link");
    CHECK(seen.sends == 0, "a link never reported up was sent on");
    unlock();
    CHECK(rc != Z_OK, "an open whose link never came up succeeded");
    CHECK(took >= 1000, "the unanswered dial was given up after %lu ms, at once", took);
    CHECK(took < 60000, "the unanswered dial took %lu ms", took);
    printf("pico-app-transport-dial: the unanswered dial ended in %lu ms (rc %d)\n", took, rc);

    z_mutex_drop(z_mutex_move(&seen.lock));
    printf("pico-app-transport-dial: %d check(s), %d failure(s)\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
