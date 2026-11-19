/*
 * SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * A zenoh-pico C program that calls EVERY public platform export of zenoh-pico's header
 * (system/common/platform.h: random, memory, task, mutex, condition variable, sleep,
 * clock, wall time), compiled against zenoh-pico's own headers for this host and linked
 * against the wz cdylib.
 *
 * pico_host_layer.c holds the layout of each type and the shapes pico's examples use. This
 * program is the rest: that each of the exports links (on Windows through the DLL's import
 * library, which a symbol census of an ELF file does not read), and that the ones the
 * other program does not call answer as zenoh-pico's backend for the host answers: the
 * sleeps sleep at least what they are asked, the `_since` family measures between two
 * readings in its unit, a reallocation keeps its prefix, a detached task runs to its end,
 * a mutex held by another task refuses a try-lock, and take is the struct copy.
 *
 * Exit status 0 means every check held; the last line printed is the count either way.
 */

#include <stdio.h>
#include <string.h>

#include <zenoh-pico.h>

static int checks = 0;
static int failures = 0;

#define CHECK(cond, ...)                                                   \
    do {                                                                   \
        checks++;                                                          \
        if (!(cond)) {                                                     \
            failures++;                                                    \
            printf("pico-platform-surface: FAIL at line %d: ", __LINE__);  \
            printf(__VA_ARGS__);                                           \
            printf("\n");                                                  \
        }                                                                  \
    } while (0)

static void check_random_and_memory(void) {
    (void)z_random_u8();
    (void)z_random_u16();
    uint32_t a = z_random_u32();
    uint32_t b = z_random_u32();
    uint32_t c = z_random_u32();
    CHECK(!(a == b && b == c), "three 32-bit random draws are equal");
    (void)z_random_u64();

    unsigned char *p = (unsigned char *)z_malloc(16);
    CHECK(p != NULL, "z_malloc(16)");
    if (p == NULL) return;
    for (int i = 0; i < 16; i++) p[i] = (unsigned char)i;
    unsigned char *q = (unsigned char *)z_realloc(p, 4096);
    CHECK(q != NULL, "z_realloc to 4096");
    if (q == NULL) {
        z_free(p);
        return;
    }
    int kept = 1;
    for (int i = 0; i < 16; i++) kept &= q[i] == (unsigned char)i;
    CHECK(kept, "z_realloc lost the prefix");
    z_free(q);
    z_free(NULL);
}

static void check_sleep_and_clock(void) {
    z_clock_t t0 = z_clock_now();
    CHECK(z_sleep_us(1500) == 0, "z_sleep_us");
    z_clock_t t1 = z_clock_now();
    CHECK(zp_clock_elapsed_us_since(&t1, &t0) >= 1400, "z_sleep_us(1500) slept %lu us",
          zp_clock_elapsed_us_since(&t1, &t0));
    CHECK(z_sleep_s(1) == 0, "z_sleep_s");
    z_clock_t t2 = z_clock_now();
    CHECK(zp_clock_elapsed_ms_since(&t2, &t1) >= 990, "z_sleep_s(1) slept %lu ms", zp_clock_elapsed_ms_since(&t2, &t1));
    CHECK(z_clock_elapsed_s(&t0) >= 1, "z_clock_elapsed_s across a second's sleep");
    CHECK(z_clock_elapsed_us(&t0) >= 1000000, "z_clock_elapsed_us across a second's sleep");

    /* The _since family between two readings, one advanced from the other. */
    z_clock_t epoch = z_clock_now();
    z_clock_t later = epoch;
    z_clock_advance_ms(&later, 2500);
    unsigned long ms = zp_clock_elapsed_ms_since(&later, &epoch);
    CHECK(ms >= 2499 && ms <= 2501, "2500 ms advanced read as %lu ms", ms);
    /* Whole seconds are pico's per host: on a Unix the difference of the two readings' second
     * fields (system/unix/system.c), so 2.5 s reads 2 or 3 by where in its second the epoch
     * fell; on Windows the counter interval over the frequency, truncated, so it reads 2. */
    unsigned long s = zp_clock_elapsed_s_since(&later, &epoch);
#if defined(ZENOH_WINDOWS)
    LARGE_INTEGER frequency;
    QueryPerformanceFrequency(&frequency);
    unsigned long pico_s = (unsigned long)((double)(later.QuadPart - epoch.QuadPart) / (double)frequency.QuadPart);
#else
    unsigned long pico_s = (unsigned long)(later.tv_sec - epoch.tv_sec);
#endif
    CHECK(s == pico_s, "2500 ms advanced read as %lu s, and pico's formula for this host gives %lu", s, pico_s);
    CHECK(s == 2 || s == 3, "2500 ms advanced read as %lu s", s);
    unsigned long us = zp_clock_elapsed_us_since(&later, &epoch);
    CHECK(us >= 2499000 && us <= 2501000, "2500 ms advanced read as %lu us", us);
    CHECK(zp_clock_elapsed_ms_since(&epoch, &later) == 0, "a reading before its epoch reads 0");
    z_clock_t micro = epoch;
    z_clock_advance_us(&micro, 1500);
    unsigned long mus = zp_clock_elapsed_us_since(&micro, &epoch);
    CHECK(mus >= 1499 && mus <= 1501, "1500 us advanced read as %lu us", mus);

    z_time_t wall = z_time_now();
    CHECK(z_time_elapsed_s(&wall) < 2, "a wall time just read is %lu s old", z_time_elapsed_s(&wall));
    CHECK(z_time_elapsed_us(&wall) < 2000000, "a wall time just read is %lu us old", z_time_elapsed_us(&wall));
}

typedef struct {
    z_owned_mutex_t *mutex;
    volatile int holding;
    volatile int release;
    volatile int ran;
} holder_t;

static void *hold_the_lock(void *arg) {
    holder_t *h = (holder_t *)arg;
    z_mutex_lock(z_mutex_loan_mut(h->mutex));
    h->holding = 1;
    while (!h->release) z_sleep_ms(5);
    z_mutex_unlock(z_mutex_loan_mut(h->mutex));
    h->ran = 1;
    return NULL;
}

static void *mark_ran(void *arg) {
    *(volatile int *)arg = 1;
    return NULL;
}

static void check_sync_and_tasks(void) {
    z_owned_mutex_t m;
    CHECK(z_mutex_init(&m) == Z_OK, "z_mutex_init");
    holder_t h = {&m, 0, 0, 0};
    z_owned_task_t t;
    CHECK(z_task_init(&t, NULL, hold_the_lock, &h) == Z_OK, "z_task_init for the holder");
    for (int i = 0; i < 500 && !h.holding; i++) z_sleep_ms(5);
    CHECK(h.holding, "the holder never took the lock");
    CHECK(z_mutex_try_lock(z_mutex_loan_mut(&m)) != Z_OK, "try_lock of a mutex another task holds succeeded");
    h.release = 1;
    CHECK(z_task_join(z_task_move(&t)) == Z_OK, "z_task_join for the holder");
    CHECK(h.ran, "join returned before the holder let go");
    CHECK(z_mutex_try_lock(z_mutex_loan_mut(&m)) == Z_OK, "try_lock of the released mutex");
    CHECK(z_mutex_unlock(z_mutex_loan_mut(&m)) == Z_OK, "unlock after try_lock");
    const z_loaned_mutex_t *ml = z_mutex_loan(&m);
    CHECK((const void *)ml == (const void *)&m, "z_mutex_loan is the object's address");

    /* take is the struct copy, with nothing written back to the source. */
    z_owned_mutex_t moved;
    memset(&moved, 0xA5, sizeof moved);
    z_mutex_take(&moved, z_mutex_move(&m));
    CHECK(memcmp(&moved, &m, sizeof m) == 0, "z_mutex_take did not copy the mutex");
    CHECK(z_mutex_drop(z_mutex_move(&m)) == Z_OK, "z_mutex_drop");

    z_owned_condvar_t cv;
    CHECK(z_condvar_init(&cv) == Z_OK, "z_condvar_init");
    CHECK(z_condvar_signal(z_condvar_loan_mut(&cv)) == Z_OK, "z_condvar_signal with no waiter");
    const z_loaned_condvar_t *cl = z_condvar_loan(&cv);
    CHECK((const void *)cl == (const void *)&cv, "z_condvar_loan is the object's address");
    z_owned_condvar_t cmoved;
    memset(&cmoved, 0xA5, sizeof cmoved);
    z_condvar_take(&cmoved, z_condvar_move(&cv));
    CHECK(memcmp(&cmoved, &cv, sizeof cv) == 0, "z_condvar_take did not copy the condition variable");
    CHECK(z_condvar_drop(z_condvar_move(&cv)) == Z_OK, "z_condvar_drop");

    /* A detached task runs to its end; a dropped one is detached. */
    volatile int detached_ran = 0;
    z_owned_task_t d;
    CHECK(z_task_init(&d, NULL, mark_ran, (void *)&detached_ran) == Z_OK, "z_task_init for the detached task");
    CHECK(z_task_detach(z_task_move(&d)) == Z_OK, "z_task_detach");
    for (int i = 0; i < 500 && !detached_ran; i++) z_sleep_ms(5);
    CHECK(detached_ran, "the detached task never ran");
    volatile int dropped_ran = 0;
    z_owned_task_t e;
    CHECK(z_task_init(&e, NULL, mark_ran, (void *)&dropped_ran) == Z_OK, "z_task_init for the dropped task");
    const z_loaned_task_t *el = z_task_loan(&e);
    CHECK((const void *)el == (const void *)&e, "z_task_loan is the object's address");
    z_owned_task_t e2;
    z_task_take(&e2, z_task_move(&e));
    CHECK(z_task_drop(z_task_move(&e2)) == Z_OK, "z_task_drop");
    for (int i = 0; i < 500 && !dropped_ran; i++) z_sleep_ms(5);
    CHECK(dropped_ran, "the dropped task never ran");
}

int main(void) {
    check_random_and_memory();
    check_sleep_and_clock();
    check_sync_and_tasks();
    printf("pico-platform-surface: %d check(s), %d failure(s)\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
