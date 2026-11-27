/*
 * SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * A program that runs its session on its own cycle and its own time: the session is opened
 * without its read task and stepped by the program with zext_session_step, and its timers
 * (lease, keep-alive, handshake) run on a time base the program supplies and moves by one
 * period per cycle. periodic.c is the other way, the read task beside the program's cycle.
 *
 *   time base   zext_time_base_new over the program's read of its time, handed to the
 *               config with zext_config_time_base; the program moves the time by one period
 *               at the start of each cycle and says so with zext_time_base_advanced;
 *   open        z_open with auto_start_read_task false in its z_open_options_t: no thread of
 *               the library reads the session, so the subscriber's callback runs inside the
 *               program's step, on its thread, and shares the program's counters unlocked;
 *   each cycle  the other end publishes the cycle's sample; the program steps its session
 *               with zext_session_step, its bound what is left of the cycle, until the
 *               cycle's deadline passes: the step is the cycle's wait, and what arrives during
 *               it is handed out at once;
 *   refused     a step of the other end, whose read task runs, answers
 *               ZEXT_ERR_READ_TASK_RUNS; a step of the closed session _Z_ERR_SESSION_CLOSED.
 *
 * The other end is a listener of the same process, opened as the default open runs it (its
 * read task, the system's clock), in the place another node would be.
 *
 * The step is the multi-threaded arm's door, and the cooperative engine's: a library on the
 * tokio engine answers ZEXT_ERR_UNSUPPORTED, which fails the run. Built against the library
 * with the time-base capability, as the package profile host-peer-ext has it.
 *
 * The package tests hold the run to the line below as well as to its exit status
 * (example_common.h):
 *
 * expect-line: example-periodic-step: 25 cycles, 25 samples received
 */

#define EXAMPLE_NAME "example-periodic-step"

#include <zenoh-pico.h>

#include "zext.h"

#include "example_common.h"

#if Z_FEATURE_MULTI_THREAD != 1
#error "zext_session_step is the multi-threaded arm's: build against a library with multi-thread"
#endif

#define PERIOD_MS 20
#define CYCLES 25

/* The program's time, in nanoseconds since its start. The time base may be read from any
 * thread that reads the session's clock, so it is read and moved under a lock. */
static struct {
    z_owned_mutex_t lock;
    uint64_t now_ns;
    uint64_t reads;
} program_time;

static uint64_t read_program_time(void *context) {
    (void)context;
    z_mutex_lock(z_mutex_loan_mut(&program_time.lock));
    uint64_t now = program_time.now_ns;
    program_time.reads++;
    z_mutex_unlock(z_mutex_loan_mut(&program_time.lock));
    return now;
}

static uint64_t program_time_reads(void) {
    z_mutex_lock(z_mutex_loan_mut(&program_time.lock));
    uint64_t reads = program_time.reads;
    z_mutex_unlock(z_mutex_loan_mut(&program_time.lock));
    return reads;
}

static uint64_t program_time_ms(void) {
    z_mutex_lock(z_mutex_loan_mut(&program_time.lock));
    uint64_t now = program_time.now_ns;
    z_mutex_unlock(z_mutex_loan_mut(&program_time.lock));
    return now / 1000000u;
}

static zext_owned_time_base_t time_base;

/* The start of a cycle: its wall-clock deadline one period on, and the program's time one
 * period on, which the program tells the library of. */
static void begin_cycle(z_clock_t *deadline) {
    z_clock_advance_ms(deadline, PERIOD_MS);
    z_mutex_lock(z_mutex_loan_mut(&program_time.lock));
    program_time.now_ns += (uint64_t)PERIOD_MS * 1000000u;
    z_mutex_unlock(z_mutex_loan_mut(&program_time.lock));
    CHECK(zext_time_base_advanced(zext_time_base_loan(&time_base)) == Z_OK, "zext_time_base_advanced");
}

/* Step the session until the cycle's deadline passes, each step bounded by what is left of
 * the cycle; once at least, with a bound of 0 when the cycle is already late. The first
 * answer that is not Z_OK ends the cycle and is returned. */
static z_result_t step_out_cycle(const z_loaned_session_t *session, z_clock_t *deadline) {
    for (;;) {
        z_clock_t now = z_clock_now();
        unsigned long left = zp_clock_elapsed_ms_since(deadline, &now);
        z_result_t stepped = zext_session_step(session, (uint32_t)left);
        if (stepped != Z_OK || left == 0) return stepped;
    }
}

/* What the subscriber was handed. Its callback runs inside the program's step, on the
 * program's thread, so these are the program's own variables. */
static int received = 0;
static int probes = 0;
static int in_order = 1;

static void on_sample(z_loaned_sample_t *sample, void *arg) {
    (void)arg;
    char seen[32];
    ex_payload_text(z_sample_payload(sample), seen, sizeof seen);
    int seq = -1;
    if (sscanf(seen, "tick-%d", &seq) == 1) {
        if (seq != received) in_order = 0;
        received++;
    } else {
        probes++;
    }
}

/* The program's session: a client that dials `locator`, its timers on the program's time,
 * opened without its read task; retried while the listener binds. */
static z_result_t open_stepped(z_owned_session_t *session, const char *locator) {
    z_result_t rc = -1;
    for (int attempt = 0; attempt < 100 && rc != Z_OK; attempt++) {
        z_owned_config_t config;
        z_config_default(&config);
        zp_config_insert(z_config_loan_mut(&config), Z_CONFIG_MODE_KEY, "client");
        zp_config_insert(z_config_loan_mut(&config), Z_CONFIG_CONNECT_KEY, locator);
        rc = zext_config_time_base(z_config_loan_mut(&config), zext_time_base_loan(&time_base));
        if (rc != Z_OK) {
            z_config_drop(z_config_move(&config));
            return rc;
        }
        z_open_options_t options;
        z_open_options_default(&options);
        options.auto_start_read_task = false;
        rc = z_open(session, z_config_move(&config), &options);
        if (rc != Z_OK) z_sleep_ms(100);
    }
    return rc;
}

int main(void) {
    z_mutex_init(&program_time.lock);
    program_time.now_ns = 0;
    program_time.reads = 0;
    zext_time_base_t calls = {.context = NULL, .now_ns = read_program_time, .drop = NULL};
    z_result_t rc = zext_time_base_new(&time_base, &calls);
    CHECK(rc == Z_OK, "zext_time_base_new (rc %d)", (int)rc);
    if (rc != Z_OK) return ex_finish();

    char locator[64];
    snprintf(locator, sizeof locator, "tcp/127.0.0.1:%u", ex_port());
    z_owned_session_t listener;
    rc = ex_open_listener(&listener, locator);
    CHECK(rc == Z_OK, "the listener did not open on %s (rc %d)", locator, (int)rc);
    if (rc != Z_OK) return ex_finish();
    z_owned_session_t dialer;
    rc = open_stepped(&dialer, locator);
    CHECK(rc == Z_OK, "the stepped session did not open to %s (rc %d)", locator, (int)rc);
    if (rc != Z_OK) {
        ex_close(&listener);
        return ex_finish();
    }
    const z_loaned_session_t *s = z_session_loan(&dialer);
    CHECK(!zp_read_task_is_running(s), "the session opened without its read task runs one");

    z_owned_closure_sample_t closure;
    z_closure_sample(&closure, on_sample, NULL, NULL);
    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, "example/step/**");
    z_owned_subscriber_t subscriber;
    CHECK(z_declare_subscriber(s, &subscriber, z_view_keyexpr_loan(&ke), z_closure_sample_move(&closure), NULL) ==
              Z_OK,
          "z_declare_subscriber");

    /* The declaration leaves in a step, and the route is up once a probe is handed back;
     * these cycles are not counted. */
    z_clock_t deadline = z_clock_now();
    for (int i = 0; i < 400 && probes == 0; i++) {
        begin_cycle(&deadline);
        ex_put(z_session_loan(&listener), "example/step/probe", "probe", NULL);
        rc = step_out_cycle(s, &deadline);
        CHECK(rc == Z_OK, "a step before the first cycle answered %d", (int)rc);
        if (rc != Z_OK) break;
    }
    CHECK(probes > 0, "the stepped session was never handed a probe");

    uint64_t reads_before = program_time_reads();
    z_clock_t started = z_clock_now();
    int cycles = 0;
    for (int cycle = 0; cycle < CYCLES && rc == Z_OK; cycle++) {
        begin_cycle(&deadline);
        char text[32];
        snprintf(text, sizeof text, "tick-%d", cycle);
        ex_put(z_session_loan(&listener), "example/step/tick", text, NULL);
        rc = step_out_cycle(s, &deadline);
        CHECK(rc == Z_OK, "cycle %d: zext_session_step answered %d", cycle, (int)rc);
        if (rc == Z_OK) cycles++;
    }

    /* What the last cycle's sample still needs to arrive: more steps, bounded. */
    for (int i = 0; i < 200 && rc == Z_OK && received < CYCLES; i++) {
        begin_cycle(&deadline);
        rc = step_out_cycle(s, &deadline);
    }
    unsigned long elapsed = z_clock_elapsed_ms(&started);
    printf("%s: %d cycles, %d samples received\n", EXAMPLE_NAME, cycles, received);
    printf("%s: %lu ms of the wall clock, %llu ms of the program's time\n", EXAMPLE_NAME, elapsed,
           (unsigned long long)program_time_ms());
    CHECK(cycles == CYCLES, "%d of %d cycles stepped the session", cycles, CYCLES);
    CHECK(received == CYCLES, "%d of the %d cycles' samples were received", received, CYCLES);
    CHECK(in_order, "the cycles' samples were received out of order");
    CHECK(program_time_reads() > reads_before, "the session's steps never read the program's time");

    rc = zext_session_step(z_session_loan(&listener), 0);
    CHECK(rc == ZEXT_ERR_READ_TASK_RUNS, "a step of a session whose read task runs answered %d", (int)rc);

    z_subscriber_drop(z_subscriber_move(&subscriber));
    z_close(z_session_loan_mut(&dialer), NULL);
    rc = zext_session_step(z_session_loan(&dialer), 0);
    CHECK(rc == _Z_ERR_SESSION_CLOSED, "a step of the closed session answered %d", (int)rc);
    z_session_drop(z_session_move(&dialer));
    ex_close(&listener);
    zext_time_base_drop(zext_time_base_move(&time_base));
    z_mutex_drop(z_mutex_move(&program_time.lock));
    return ex_finish();
}
