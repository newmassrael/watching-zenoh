/*
 * SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * A program that runs its own periodic task: every cycle it sends what the cycle produced
 * and takes what arrived since the last one, on its own thread, at its own period. The
 * call order is the one docs/periodic-run-api.md and wz_ext.h ("the periodic run API")
 * state:
 *
 *   open        z_open; in the multi-threaded arm the read task starts with the session
 *               (zp_read_task_is_running says so), and it does the reading, the lease and
 *               the keep-alives between the program's calls;
 *   declare     the subscriber hands its samples to a ring channel, which the program pulls
 *               from its own thread, so no callback of the program runs on the library's;
 *   each cycle  zp_batch_start, the cycle's puts, zp_batch_flush: the cycle's samples
 *               leave together at the flush; then z_ring_handler_sample_try_recv until
 *               Z_CHANNEL_NODATA; then wait for the cycle's deadline, an absolute
 *               z_clock_t reading, with z_condvar_wait_until;
 *   end         zp_batch_stop, the undeclare, z_close.
 *
 * In the single-threaded arm (a library built without multi-thread) there is no read task
 * and the program's cycle also steps the session: zp_spin_once on each session, which reads,
 * keeps the lease and serves what is due on the cooperative engine, and answers for a live
 * session on the tokio engine, which reads on a thread of its own. That arm is the
 * `#if Z_FEATURE_MULTI_THREAD == 0` branch below; the hosted runs build the default library,
 * which is the multi-threaded arm.
 */

#define EXAMPLE_NAME "example-periodic"

#include <zenoh-pico.h>

#include "example_common.h"

#define PERIOD_MS 20
#define CYCLES 25

#if Z_FEATURE_MULTI_THREAD == 1
static z_owned_mutex_t tick_lock;
static z_owned_condvar_t tick;
#endif

/* Wait until `deadline`, a reading of the monotonic clock. In the multi-threaded arm the
 * wait is an event wait that a callback could end early with z_condvar_signal; nothing
 * signals it here, so it ends at the deadline with Z_ETIMEDOUT. */
static int wait_until(const z_clock_t *deadline) {
#if Z_FEATURE_MULTI_THREAD == 1
    z_mutex_lock(z_mutex_loan_mut(&tick_lock));
    z_result_t rc = z_condvar_wait_until(z_condvar_loan_mut(&tick), z_mutex_loan_mut(&tick_lock), deadline);
    z_mutex_unlock(z_mutex_loan_mut(&tick_lock));
    return rc == Z_ETIMEDOUT || rc == Z_OK;
#else
    z_clock_t now = z_clock_now();
    unsigned long left = zp_clock_elapsed_ms_since((z_clock_t *)deadline, &now);
    if (left > 0) z_sleep_ms(left);
    return 1;
#endif
}

int main(void) {
#if Z_FEATURE_MULTI_THREAD == 1
    z_mutex_init(&tick_lock);
    z_condvar_init(&tick);
#endif
    char locator[64];
    snprintf(locator, sizeof locator, "tcp/127.0.0.1:%u", ex_port());

    z_owned_session_t listener;
    z_result_t rc = ex_open_listener(&listener, locator);
    CHECK(rc == Z_OK, "the listener did not open on %s (rc %d)", locator, (int)rc);
    if (rc != Z_OK) return ex_finish();
    z_owned_session_t dialer;
    rc = ex_open_dialer(&dialer, locator);
    CHECK(rc == Z_OK, "the dialer did not open to %s (rc %d)", locator, (int)rc);
    if (rc != Z_OK) {
        ex_close(&listener);
        return ex_finish();
    }
#if Z_FEATURE_MULTI_THREAD == 1
    CHECK(zp_read_task_is_running(z_session_loan(&listener)), "the listener's read task did not start with it");
    CHECK(zp_read_task_is_running(z_session_loan(&dialer)), "the dialer's read task did not start with it");
#endif

    z_owned_closure_sample_t closure;
    z_owned_ring_handler_sample_t handler;
    CHECK(z_ring_channel_sample_new(&closure, &handler, 64) == Z_OK, "z_ring_channel_sample_new");
    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, "example/periodic/**");
    z_owned_subscriber_t subscriber;
    CHECK(z_declare_subscriber(z_session_loan(&listener), &subscriber, z_view_keyexpr_loan(&ke),
                               z_closure_sample_move(&closure), NULL) == Z_OK,
          "z_declare_subscriber");

    /* The route is up once a probe is pulled; what the program pulls before its first
     * cycle is not a cycle's. */
    int routed = 0;
    for (int i = 0; i < 400 && !routed; i++) {
        ex_put(z_session_loan(&dialer), "example/periodic/probe", "probe", NULL);
#if Z_FEATURE_MULTI_THREAD == 0
        zp_spin_once(z_session_loan(&dialer));
        zp_spin_once(z_session_loan(&listener));
#endif
        z_sleep_ms(25);
        z_owned_sample_t sample;
        while (z_ring_handler_sample_try_recv(z_ring_handler_sample_loan(&handler), &sample) == Z_OK) {
            routed = 1;
            z_sample_drop(z_sample_move(&sample));
        }
    }
    CHECK(routed, "the subscriber was never handed a probe");
    z_sleep_ms(100);
    z_owned_sample_t stale;
    while (z_ring_handler_sample_try_recv(z_ring_handler_sample_loan(&handler), &stale) == Z_OK) {
        z_sample_drop(z_sample_move(&stale));
    }

    const z_loaned_session_t *s = z_session_loan(&dialer);
    int pulled = 0;
    int in_order = 1;
    int late_cycles = 0;
    z_clock_t started = z_clock_now();
    z_clock_t deadline = started;
    for (int cycle = 0; cycle < CYCLES; cycle++) {
        z_clock_advance_ms(&deadline, PERIOD_MS);

        /* Send what the cycle produced, as one batch. */
        CHECK(zp_batch_start(s) == Z_OK, "cycle %d: zp_batch_start", cycle);
        char text[32];
        snprintf(text, sizeof text, "tick-%d", cycle);
        ex_put(s, "example/periodic/tick", text, NULL);
        CHECK(zp_batch_flush(s) == Z_OK, "cycle %d: zp_batch_flush", cycle);

#if Z_FEATURE_MULTI_THREAD == 0
        zp_spin_once(s);
        zp_spin_once(z_session_loan(&listener));
#endif

        /* Take what arrived since the last cycle. */
        z_owned_sample_t sample;
        z_result_t got;
        while ((got = z_ring_handler_sample_try_recv(z_ring_handler_sample_loan(&handler), &sample)) == Z_OK) {
            char seen[32];
            ex_payload_text(z_sample_payload(z_sample_loan(&sample)), seen, sizeof seen);
            int seq = -1;
            if (sscanf(seen, "tick-%d", &seq) == 1) {
                if (seq != pulled) in_order = 0;
                pulled = seq + 1;
            }
            z_sample_drop(z_sample_move(&sample));
        }
        CHECK(got == Z_CHANNEL_NODATA, "cycle %d: the channel answered %d, not Z_CHANNEL_NODATA", cycle, (int)got);

        z_clock_t now = z_clock_now();
        if (zp_clock_elapsed_ms_since(&now, &deadline) > 0) late_cycles++;
        CHECK(wait_until(&deadline), "cycle %d: the wait for the deadline failed", cycle);
    }
    CHECK(zp_batch_stop(s) == Z_OK, "zp_batch_stop");

    /* What the last cycle sent arrives after its pull: one more pull, bounded. */
    for (int i = 0; i < 200 && pulled < CYCLES; i++) {
#if Z_FEATURE_MULTI_THREAD == 0
        zp_spin_once(z_session_loan(&listener));
#endif
        z_owned_sample_t sample;
        while (z_ring_handler_sample_try_recv(z_ring_handler_sample_loan(&handler), &sample) == Z_OK) {
            char seen[32];
            ex_payload_text(z_sample_payload(z_sample_loan(&sample)), seen, sizeof seen);
            int seq = -1;
            if (sscanf(seen, "tick-%d", &seq) == 1) {
                if (seq != pulled) in_order = 0;
                pulled = seq + 1;
            }
            z_sample_drop(z_sample_move(&sample));
        }
        if (pulled < CYCLES) z_sleep_ms(10);
    }
    unsigned long elapsed = z_clock_elapsed_ms(&started);
    printf("%s: %d cycles of %d ms in %lu ms, %d past their deadline before the wait\n", EXAMPLE_NAME, CYCLES,
           PERIOD_MS, elapsed, late_cycles);
    CHECK(pulled == CYCLES, "%d of %d cycles' samples were pulled", pulled, CYCLES);
    CHECK(in_order, "the cycles' samples were pulled out of order");
    CHECK(elapsed >= (unsigned long)(CYCLES * PERIOD_MS) - PERIOD_MS, "%d cycles took %lu ms, less than their periods",
          CYCLES, elapsed);

    z_subscriber_drop(z_subscriber_move(&subscriber));
    z_ring_handler_sample_drop(z_ring_handler_sample_move(&handler));
    ex_close(&dialer);
    ex_close(&listener);
#if Z_FEATURE_MULTI_THREAD == 1
    z_condvar_drop(z_condvar_move(&tick));
    z_mutex_drop(z_mutex_move(&tick_lock));
#endif
    return ex_finish();
}
