/*
 * SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * Batching switched on and off, with a flush: zp_batch_start, zp_batch_flush and
 * zp_batch_stop on a session that publishes over the host's loopback (tcp/).
 *
 *   off      each put leaves as it is made, and a burst arrives whole;
 *   on       zp_batch_start opens a window: the puts after it are gathered into the
 *            session's batches and leave when the program flushes, when a batch is full,
 *            when a message must leave at once, or when the session sends a keep-alive;
 *   flush    zp_batch_flush sends what the window holds and keeps it open, so the next
 *            burst is gathered again;
 *   stop     zp_batch_stop sends what is left and closes the window: puts leave one by one
 *            again.
 *
 * Whether a burst was still held when the program flushed depends on whether a keep-alive
 * fell inside the burst, so the program prints how many had arrived before each flush and
 * checks only what the contract promises: every put arrives, in order, once the window is
 * flushed or stopped. A session with no transport answers the three calls with
 * _Z_ERR_TRANSPORT_NOT_AVAILABLE; a NULL session, with _Z_ERR_SESSION_CLOSED.
 */

#define EXAMPLE_NAME "example-batching"

#include <zenoh-pico.h>

#include "example_common.h"

#define BURST 20

static struct {
    ex_counter_t count;
    ex_counter_t probes;
    volatile int in_order;
    volatile int next;
} heard;

static void on_sample(z_loaned_sample_t *sample, void *arg) {
    (void)arg;
    char text[32];
    ex_payload_text(z_sample_payload(sample), text, sizeof text);
    if (strcmp(text, "probe") == 0) {
        ex_counter_add(&heard.probes, 1);
        return;
    }
    int seq = -1;
    if (sscanf(text, "seq-%d", &seq) == 1) {
        if (seq != heard.next) heard.in_order = 0;
        heard.next = seq + 1;
        ex_counter_add(&heard.count, 1);
    }
}

/* One burst of BURST puts numbered from `first`. */
static void burst(const z_loaned_session_t *session, int first) {
    char text[32];
    for (int n = first; n < first + BURST; n++) {
        snprintf(text, sizeof text, "seq-%d", n);
        ex_put(session, "example/batching/seq", text, NULL);
    }
}

int main(void) {
    ex_counter_init(&heard.count);
    ex_counter_init(&heard.probes);
    heard.in_order = 1;
    heard.next = 0;
    char locator[64];
    snprintf(locator, sizeof locator, "tcp/127.0.0.1:%u", ex_port());

    z_owned_session_t listener;
    z_result_t rc = ex_open_listener(&listener, locator);
    CHECK(rc == Z_OK, "the listener did not open on %s (rc %d)", locator, (int)rc);
    if (rc != Z_OK) return ex_finish();
    z_owned_closure_sample_t closure;
    z_closure_sample(&closure, on_sample, NULL, NULL);
    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, "example/batching/**");
    z_owned_subscriber_t subscriber;
    CHECK(z_declare_subscriber(z_session_loan(&listener), &subscriber, z_view_keyexpr_loan(&ke),
                               z_closure_sample_move(&closure), NULL) == Z_OK,
          "z_declare_subscriber");

    /* The calls on a session the program does not hold: refused, and nothing is sent. */
    CHECK(zp_batch_start(NULL) == _Z_ERR_SESSION_CLOSED, "zp_batch_start(NULL)");
    CHECK(zp_batch_flush(NULL) == _Z_ERR_SESSION_CLOSED, "zp_batch_flush(NULL)");
    CHECK(zp_batch_stop(NULL) == _Z_ERR_SESSION_CLOSED, "zp_batch_stop(NULL)");

    z_owned_session_t dialer;
    rc = ex_open_dialer(&dialer, locator);
    CHECK(rc == Z_OK, "the dialer did not open to %s (rc %d)", locator, (int)rc);
    if (rc == Z_OK) {
        const z_loaned_session_t *s = z_session_loan(&dialer);
        /* Until the subscriber's declaration has reached this side a put reaches nobody:
         * probe until one is heard, with a payload the numbered count does not read. */
        for (int i = 0; i < 400 && ex_counter_get(&heard.probes) == 0; i++) {
            ex_put(s, "example/batching/probe", "probe", NULL);
            z_sleep_ms(25);
        }
        CHECK(ex_counter_get(&heard.probes) > 0, "the subscriber was never handed a put");
        /* Every put is numbered from 0, so `base` is both the next number and how many
         * the subscriber should have counted before the burst. */
        int base = 0;

        /* Batching off. */
        burst(s, base);
        CHECK(ex_wait_for(&heard.count, base + BURST, 5000), "off: %d of %d puts arrived",
              ex_counter_get(&heard.count) - base, BURST);
        base += BURST;

        /* Batching on, flushed. */
        CHECK(zp_batch_start(s) == Z_OK, "zp_batch_start");
        burst(s, base);
        z_sleep_ms(100);
        printf("%s: on: %d of %d puts had arrived before the flush\n", EXAMPLE_NAME,
               ex_counter_get(&heard.count) - base, BURST);
        CHECK(zp_batch_flush(s) == Z_OK, "zp_batch_flush");
        CHECK(ex_wait_for(&heard.count, base + BURST, 5000), "on, flushed: %d of %d puts arrived",
              ex_counter_get(&heard.count) - base, BURST);
        base += BURST;

        /* Still on after the flush: a second burst, sent by the stop. */
        burst(s, base);
        CHECK(zp_batch_stop(s) == Z_OK, "zp_batch_stop");
        CHECK(ex_wait_for(&heard.count, base + BURST, 5000), "on, stopped: %d of %d puts arrived",
              ex_counter_get(&heard.count) - base, BURST);
        base += BURST;

        /* Off again. */
        burst(s, base);
        CHECK(ex_wait_for(&heard.count, base + BURST, 5000), "off again: %d of %d puts arrived",
              ex_counter_get(&heard.count) - base, BURST);
        CHECK(heard.in_order, "the puts arrived out of order (next %d)", heard.next);
        ex_close(&dialer);
    }

    z_subscriber_drop(z_subscriber_move(&subscriber));
    ex_close(&listener);
    ex_counter_drop(&heard.count);
    ex_counter_drop(&heard.probes);
    return ex_finish();
}
