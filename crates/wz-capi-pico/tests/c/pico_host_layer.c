/*
 * SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * A zenoh-pico C program for the HOST LAYER: the mutex, condition variable, task,
 * clock, wall time and random exports, compiled against zenoh-pico's OWN headers for
 * this host and linked against the wz cdylib in place of libzenohpico.
 *
 * What the Rust unit tests cannot say is what a C program sees. pico's header decides
 * the bytes of every value this program declares: `pthread_mutex_t` on a Unix,
 * `SRWLOCK` on Windows, a `timespec` or a `LARGE_INTEGER` for a clock reading. The
 * program places each such value between guard bytes, hands it to the wz export, and
 * checks that nothing outside the type pico says it is was written, which is the
 * failure a wrong layout produces and which no later call notices. It then uses the
 * values the way pico's own examples do (`z_get.c` waits on a condition variable
 * under a mutex; `z_ping.c` times a round trip with the clock) and checks the answers.
 *
 * It opens no session and touches no network: it is the part of the C ABI that
 * differs by HOST, which is what a host runner can decide. Exit status 0 means every
 * check held; the last line printed is the count either way.
 */

#include <stdio.h>
#include <string.h>

#include <zenoh-pico.h>

#define GUARD 64
#define CANARY 0xA5

static int checks = 0;
static int failures = 0;

#define CHECK(cond, ...)                                  \
    do {                                                  \
        checks++;                                         \
        if (!(cond)) {                                    \
            failures++;                                   \
            printf("pico-host-layer: FAIL at line %d: ", __LINE__); \
            printf(__VA_ARGS__);                          \
            printf("\n");                                 \
        }                                                 \
    } while (0)

/* A value of pico's own type with guard bytes on both sides. A struct lays `before`,
 * the value and `after` out in that order, so a write past the end of what pico's
 * header says the type is lands in `after`. */
#define GUARDED(T, name)         \
    struct {                     \
        unsigned char before[GUARD]; \
        T v;                     \
        unsigned char after[GUARD];  \
    } name

static void guard_arm(unsigned char *before, unsigned char *after) {
    memset(before, CANARY, GUARD);
    memset(after, CANARY, GUARD);
}

static int guard_intact(const unsigned char *before, const unsigned char *after) {
    for (int i = 0; i < GUARD; i++) {
        if (before[i] != CANARY || after[i] != CANARY) return 0;
    }
    return 1;
}

/* ------------------------------------------------------------------ the tasks */

typedef struct {
    z_owned_mutex_t *mutex;
    z_owned_condvar_t *cond;
    int ready;
    int ran;
} handoff_t;

static void *signaller(void *arg) {
    handoff_t *h = (handoff_t *)arg;
    z_sleep_ms(30);
    z_mutex_lock(z_mutex_loan_mut(h->mutex));
    h->ready = 1;
    z_condvar_signal(z_condvar_loan_mut(h->cond));
    z_mutex_unlock(z_mutex_loan_mut(h->mutex));
    h->ran = 1;
    return NULL;
}

/* ---------------------------------------------------------------------- checks */

/* THE CONTROL. The guard is only evidence if it can fail: a one-byte value handed to an
 * export that initialises a whole mutex must trip it. Without this, a guard that never
 * looked at the bytes it was given would pass every check below. */
static void check_the_guard_detects_an_overrun(void) {
    GUARDED(unsigned char, g);
    guard_arm(g.before, g.after);
    z_mutex_init((z_owned_mutex_t *)&g.v);
    CHECK(!guard_intact(g.before, g.after), "the control: initialising a mutex in a one-byte value must trip the guard");
}

static void check_mutex(void) {
    GUARDED(z_owned_mutex_t, g);
    guard_arm(g.before, g.after);
    CHECK(z_mutex_init(&g.v) == Z_OK, "z_mutex_init");
    CHECK(guard_intact(g.before, g.after), "z_mutex_init wrote outside a z_owned_mutex_t (%zu bytes)", sizeof(z_owned_mutex_t));
    CHECK(z_mutex_lock(z_mutex_loan_mut(&g.v)) == Z_OK, "z_mutex_lock");
    CHECK(z_mutex_try_lock(z_mutex_loan_mut(&g.v)) != Z_OK, "try_lock must refuse a mutex held by this thread");
    CHECK(z_mutex_unlock(z_mutex_loan_mut(&g.v)) == Z_OK, "z_mutex_unlock");
    CHECK(z_mutex_try_lock(z_mutex_loan_mut(&g.v)) == Z_OK, "try_lock of a free mutex");
    CHECK(z_mutex_unlock(z_mutex_loan_mut(&g.v)) == Z_OK, "z_mutex_unlock after try_lock");
    CHECK(guard_intact(g.before, g.after), "the mutex calls wrote outside a z_owned_mutex_t");
    CHECK(z_mutex_drop(z_mutex_move(&g.v)) == Z_OK, "z_mutex_drop");
}

static void check_condvar_and_task(void) {
    GUARDED(z_owned_mutex_t, m);
    GUARDED(z_owned_condvar_t, c);
    GUARDED(z_owned_task_t, t);
    guard_arm(m.before, m.after);
    guard_arm(c.before, c.after);
    guard_arm(t.before, t.after);
    CHECK(z_mutex_init(&m.v) == Z_OK, "z_mutex_init for the handoff");
    CHECK(z_condvar_init(&c.v) == Z_OK, "z_condvar_init");
    CHECK(guard_intact(c.before, c.after), "z_condvar_init wrote outside a z_owned_condvar_t (%zu bytes)", sizeof(z_owned_condvar_t));

    handoff_t h = {&m.v, &c.v, 0, 0};
    /* The z_get.c shape: block on the condition variable under the mutex while a task
     * signals it. The flag is read under the lock, so a wait that returned at once
     * would not make this pass. */
    CHECK(z_mutex_lock(z_mutex_loan_mut(&m.v)) == Z_OK, "lock before starting the task");
    CHECK(z_task_init(&t.v, NULL, signaller, &h) == Z_OK, "z_task_init");
    CHECK(guard_intact(t.before, t.after), "z_task_init wrote outside a z_owned_task_t (%zu bytes)", sizeof(z_owned_task_t));
    int waits = 0;
    while (!h.ready && waits < 200) {
        z_condvar_wait(z_condvar_loan_mut(&c.v), z_mutex_loan_mut(&m.v));
        waits++;
    }
    CHECK(h.ready == 1, "the signalled flag was never seen");
    z_mutex_unlock(z_mutex_loan_mut(&m.v));
    CHECK(z_task_join(z_task_move(&t.v)) == Z_OK, "z_task_join");
    CHECK(h.ran == 1, "join returned before the task finished");

    /* A wait with a deadline: z_ping.c's clock is the one the deadline is on, so the
     * deadline is built from z_clock_now and z_clock_advance_ms, and the wait must
     * report the timeout (not the generic error) after about that long. */
    CHECK(z_mutex_lock(z_mutex_loan_mut(&m.v)) == Z_OK, "lock before the timed wait");
    z_clock_t started = z_clock_now();
    z_clock_t deadline = z_clock_now();
    z_clock_advance_ms(&deadline, 150);
    z_result_t rc = z_condvar_wait_until(z_condvar_loan_mut(&c.v), z_mutex_loan_mut(&m.v), &deadline);
    unsigned long waited_ms = z_clock_elapsed_ms(&started);
    CHECK(rc == Z_ETIMEDOUT, "a wait past nobody's signal must be Z_ETIMEDOUT, got %d", (int)rc);
    CHECK(waited_ms >= 100, "a 150 ms deadline returned after %lu ms", waited_ms);
    CHECK(waited_ms < 5000, "a 150 ms deadline took %lu ms", waited_ms);
    z_mutex_unlock(z_mutex_loan_mut(&m.v));

    CHECK(guard_intact(m.before, m.after) && guard_intact(c.before, c.after) && guard_intact(t.before, t.after),
          "the handoff calls wrote outside the owned types");
    CHECK(z_condvar_drop(z_condvar_move(&c.v)) == Z_OK, "z_condvar_drop");
    CHECK(z_mutex_drop(z_mutex_move(&m.v)) == Z_OK, "z_mutex_drop after the handoff");
}

static void check_clock(void) {
    GUARDED(z_clock_t, g);
    guard_arm(g.before, g.after);
    g.v = z_clock_now();
    CHECK(guard_intact(g.before, g.after), "assigning the clock reading wrote outside a z_clock_t (%zu bytes)", sizeof(z_clock_t));
    CHECK(z_sleep_ms(60) == 0, "z_sleep_ms");
    unsigned long ms = z_clock_elapsed_ms(&g.v);
    unsigned long us = z_clock_elapsed_us(&g.v);
    CHECK(ms >= 40 && ms < 5000, "60 ms of sleep read as %lu ms", ms);
    CHECK(us >= ms * 1000 - 2000, "elapsed us (%lu) is below elapsed ms (%lu) times 1000", us, ms);
    /* A reading advanced into the future reads zero, not a wrapped huge value. */
    z_clock_t future = g.v;
    z_clock_advance_s(&future, 60);
    CHECK(z_clock_elapsed_ms(&future) == 0, "a future clock reading must read as 0 elapsed");
    CHECK(z_clock_elapsed_s(&future) == 0, "a future clock reading must read as 0 s elapsed");
}

static void check_time_and_random(void) {
    z_time_t t = z_time_now();
    CHECK(z_time_elapsed_ms(&t) < 2000, "a wall time just read is not 2 s old");
    char buf[GUARD + 64 + GUARD];
    memset(buf, CANARY, sizeof buf);
    const char *s = z_time_now_as_str(buf + GUARD, 64);
    CHECK(s == buf + GUARD, "z_time_now_as_str returns the caller's buffer");
    CHECK(strlen(s) == 20, "%%Y-%%m-%%dT%%H:%%M:%%SZ is 20 characters, got %zu: %s", strlen(s), s);
    CHECK(s[4] == '-' && s[10] == 'T' && s[19] == 'Z', "the rendered time has the ISO shape: %s", s);
    unsigned char before_ok = 1;
    for (int i = 0; i < GUARD; i++) {
        if ((unsigned char)buf[i] != CANARY || (unsigned char)buf[GUARD + 64 + i] != CANARY) before_ok = 0;
    }
    CHECK(before_ok, "z_time_now_as_str wrote outside the buffer it was given");

    CHECK(z_random_u64() != z_random_u64(), "two 64-bit random draws are equal");
    unsigned char r[GUARD + 16 + GUARD];
    memset(r, CANARY, sizeof r);
    z_random_fill(r + GUARD, 16);
    int nonzero = 0, tail_ok = 1;
    for (int i = 0; i < 16; i++) nonzero |= r[GUARD + i] != CANARY;
    for (int i = 0; i < GUARD; i++) {
        if (r[i] != CANARY || r[GUARD + 16 + i] != CANARY) tail_ok = 0;
    }
    CHECK(nonzero, "z_random_fill left sixteen bytes unchanged");
    CHECK(tail_ok, "z_random_fill wrote outside the requested length");
}

int main(void) {
    check_the_guard_detects_an_overrun();
    check_mutex();
    check_condvar_and_task();
    check_clock();
    check_time_and_random();
    printf("pico-host-layer: %d check(s), %d failure(s)\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
