/*
 * SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * Reception supervision of one periodic stream (wz_ext_stream_supervisor_*): a publisher
 * sends a sample every period, the subscriber tells the supervisor of each, and when the
 * samples stop the supervisor tells the program once that the stream is lost.
 *
 * The supervisor is judged by the program's own clock, here a model clock the program
 * moves by one period per cycle, so the run is the same on every host however slow its
 * sessions are: each cycle publishes, waits until the sample has been handed to the
 * subscriber, advances the clock and polls. The stream's period is 10 ms and it may miss 3
 * periods, so its deadline is 30 ms: three silent cycles are not a loss, the fourth is.
 *
 *   start      a 20 ms start delay: the first poll that has a clock starts it, the poll
 *              20 ms later finds the supervisor ACTIVE;
 *   receiving  ten cycles, each sample received, nothing told;
 *   silence    the publisher stops; the loss is told once, after the deadline, with the
 *              stream's number and its sender, and the error counts are 1;
 *   back       a sample again ends the loss; the counts stay where they were.
 *
 * Built against the library with the e2e-supervision capability, under the build's
 * e2e-supervision-notify policy at its default, status-only, so no value is kept per
 * stream and the loss carries none.
 */

#define EXAMPLE_NAME "example-supervision"

#include <zenoh-pico.h>

#include "wz_ext.h"

#include "example_common.h"

#define PERIOD_MS 10
#define FACTOR 3
#define SENDER 7

static struct {
    z_owned_mutex_t lock;
    uint32_t now_ms;
} model;

static wz_ext_owned_stream_supervisor_t supervisor;
static uint32_t stream;
static ex_counter_t received;

static struct {
    int told;
    uint32_t stream;
    uint32_t sender;
    uint8_t errors;
    uint8_t node_errors;
    int had_value;
} loss;

static int8_t read_model_clock(void *context, uint32_t *now_ms) {
    (void)context;
    z_mutex_lock(z_mutex_loan_mut(&model.lock));
    *now_ms = model.now_ms;
    z_mutex_unlock(z_mutex_loan_mut(&model.lock));
    return 0;
}

static void advance(uint32_t ms) {
    z_mutex_lock(z_mutex_loan_mut(&model.lock));
    model.now_ms += ms;
    z_mutex_unlock(z_mutex_loan_mut(&model.lock));
}

/* Runs inside the poll, on the thread that polls. */
static void on_loss(void *context, const wz_ext_stream_loss_t *lost) {
    (void)context;
    loss.told++;
    loss.stream = lost->stream;
    loss.sender = lost->sender;
    loss.errors = lost->errors;
    loss.node_errors = lost->node_errors;
    loss.had_value = lost->value != NULL;
}

static void on_sample(z_loaned_sample_t *sample, void *arg) {
    (void)arg;
    z_owned_slice_t slice;
    if (z_bytes_to_slice(z_sample_payload(sample), &slice) != Z_OK) return;
    wz_ext_stream_supervisor_received(wz_ext_stream_supervisor_loan(&supervisor), stream,
                                      z_slice_data(z_slice_loan(&slice)), z_slice_len(z_slice_loan(&slice)));
    z_slice_drop(z_slice_move(&slice));
    ex_counter_add(&received, 1);
}

static size_t poll_once(void) {
    size_t told = 0;
    CHECK(wz_ext_stream_supervisor_poll(wz_ext_stream_supervisor_loan(&supervisor), &told) == Z_OK, "poll");
    return told;
}

/* Publish one sample and wait until the subscriber has told the supervisor of it. */
static int one_cycle(const z_loaned_session_t *session, int n) {
    char text[32];
    snprintf(text, sizeof text, "sample-%d", n);
    int before = ex_counter_get(&received);
    ex_put(session, "example/supervision/stream", text, NULL);
    return ex_wait_for(&received, before + 1, 5000);
}

int main(void) {
    z_mutex_init(&model.lock);
    model.now_ms = 1000;
    ex_counter_init(&received);

    /* The table is the program's storage; status-only keeps no value, so no value area. */
    static wz_ext_stream_slot_t slots[2];
    z_result_t rc = wz_ext_stream_supervisor_new(&supervisor, slots, 2, NULL, 0, 20, read_model_clock, NULL);
    CHECK(rc == Z_OK, "wz_ext_stream_supervisor_new (rc %d)", (int)rc);
    if (rc != Z_OK) return ex_finish();
    const wz_ext_loaned_stream_supervisor_t *sv = wz_ext_stream_supervisor_loan(&supervisor);
    CHECK(wz_ext_stream_supervisor_notify(sv) == WZ_EXT_STREAM_NOTIFY_STATUS_ONLY,
          "the build's e2e-supervision-notify is not its default, status-only");
    CHECK(wz_ext_stream_supervisor_set_callback(sv, on_loss, NULL) == Z_OK, "set_callback");

    /* The refused cases: a period of 0, and a reception of a stream there is none of. Both
     * answer the code wz_ext.h calls Z_ERR_INVALID, which zenoh-pico's header does not
     * name, so the program reads only that they were refused. */
    rc = wz_ext_stream_supervisor_add(sv, 0, FACTOR, SENDER, true, NULL);
    CHECK(rc != Z_OK, "a period of 0 was not refused");
    rc = wz_ext_stream_supervisor_received(sv, 99, NULL, 0);
    CHECK(rc != Z_OK, "a reception of stream 99, which was never added, was not refused");
    CHECK(wz_ext_stream_supervisor_add(sv, PERIOD_MS, FACTOR, SENDER, true, &stream) == Z_OK, "add");

    CHECK(poll_once() == 0 && wz_ext_stream_supervisor_phase(sv) == WZ_EXT_STREAM_DELAYING,
          "the first clocked poll did not start the delay (phase %u)", (unsigned)wz_ext_stream_supervisor_phase(sv));
    advance(20);
    CHECK(poll_once() == 0 && wz_ext_stream_supervisor_phase(sv) == WZ_EXT_STREAM_ACTIVE,
          "the supervisor is not active after its start delay (phase %u)",
          (unsigned)wz_ext_stream_supervisor_phase(sv));

    char locator[64];
    snprintf(locator, sizeof locator, "tcp/127.0.0.1:%u", ex_port());
    z_owned_session_t listener;
    rc = ex_open_listener(&listener, locator);
    CHECK(rc == Z_OK, "the listener did not open on %s (rc %d)", locator, (int)rc);
    if (rc == Z_OK) {
        z_owned_closure_sample_t closure;
        z_closure_sample(&closure, on_sample, NULL, NULL);
        z_view_keyexpr_t ke;
        z_view_keyexpr_from_str(&ke, "example/supervision/stream");
        z_owned_subscriber_t subscriber;
        CHECK(z_declare_subscriber(z_session_loan(&listener), &subscriber, z_view_keyexpr_loan(&ke),
                                   z_closure_sample_move(&closure), NULL) == Z_OK,
              "z_declare_subscriber");
        z_owned_session_t dialer;
        rc = ex_open_dialer(&dialer, locator);
        CHECK(rc == Z_OK, "the dialer did not open to %s (rc %d)", locator, (int)rc);
        if (rc == Z_OK) {
            const z_loaned_session_t *s = z_session_loan(&dialer);
            /* The route is up once one sample is heard; the model clock has not moved, so
             * the samples of the wait are receptions at the activation's instant. */
            for (int i = 0; i < 400 && ex_counter_get(&received) == 0; i++) {
                ex_put(s, "example/supervision/stream", "first", NULL);
                z_sleep_ms(25);
            }
            CHECK(ex_counter_get(&received) > 0, "the subscriber was never handed a sample");
            z_sleep_ms(100); /* the extra samples of the wait, still in flight, arrive now */

            size_t told = 0;
            for (int n = 0; n < 10; n++) {
                CHECK(one_cycle(s, n), "cycle %d: the sample was not received", n);
                advance(PERIOD_MS);
                told += poll_once();
            }
            CHECK(told == 0 && loss.told == 0, "a stream received every period was told lost");

            /* Silence: the deadline is FACTOR periods after the last reception. */
            int silent_cycles_to_loss = 0;
            for (int n = 1; n <= 8; n++) {
                advance(PERIOD_MS);
                if (poll_once() > 0 && silent_cycles_to_loss == 0) silent_cycles_to_loss = n;
            }
            /* The last reception was one period before the silence began. */
            CHECK(silent_cycles_to_loss == FACTOR, "the loss was told %d silent cycles in, expected %d",
                  silent_cycles_to_loss, FACTOR);
            CHECK(loss.told == 1, "the loss was told %d times; it is an edge, told once", loss.told);
            CHECK(loss.stream == stream && loss.sender == SENDER, "the loss named stream %u sender %u",
                  (unsigned)loss.stream, (unsigned)loss.sender);
            CHECK(loss.errors == 1 && loss.node_errors == 1, "the loss counted %u, the node %u",
                  (unsigned)loss.errors, (unsigned)loss.node_errors);
            CHECK(!loss.had_value, "a status-only loss carried a value");

            /* Back: a reception ends the loss, which is not told again, and the count stays. */
            CHECK(one_cycle(s, 100), "the sample after the silence was not received");
            advance(PERIOD_MS);
            CHECK(poll_once() == 0, "a stream received again was told lost");
            uint8_t errors = 0;
            CHECK(wz_ext_stream_supervisor_stream_errors(sv, stream, &errors) == Z_OK && errors == 1,
                  "the stream's error count is %u after it came back", (unsigned)errors);
            CHECK(wz_ext_stream_supervisor_node_errors(sv) == 1, "the node's error count moved");
            ex_close(&dialer);
        }
        z_subscriber_drop(z_subscriber_move(&subscriber));
        ex_close(&listener);
    }

    wz_ext_stream_supervisor_drop(wz_ext_stream_supervisor_move(&supervisor));
    ex_counter_drop(&received);
    z_mutex_drop(z_mutex_move(&model.lock));
    return ex_finish();
}
