// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// THE COUNTED WINDOW of a host bench run under callgrind (scripts/pico-compare.sh opprofile and
// subprofile), and the shared instant it is cut around.
//
// What one operation costs is read as the difference of two runs that do it a different number of
// times, over the difference of the numbers. That holds only when everything else the counted process
// executed is the same in both runs, and the same wall time does not make it so: a loop that polls the
// clock executes as many instructions as the host turned it, which is not a function of the time.
// zenoh-pico's executor polls so for the last millisecond or two before each timer is due
// (`vendor/zenoh-pico/src/runtime/background_executor.c` @ `if (zp_clock_elapsed_ms_since(&res.next_wake_up_time, &now) > 1) {`),
// and a session with no peer makes its read task such a timer every 100 ms
// (`vendor/zenoh-pico/src/transport/unicast/read.c` @ `return _z_fut_fn_result_wake_up_after(100);`).
// While a peer is connected the read task waits in the socket and is always the next task, so the loop
// does not run. A receiver that also counts the seconds before its peer connects and after it leaves
// counts tens of millions of those instructions, a different number in each run, and the difference
// lands on the operations. So the receiver counts a WINDOW that lies inside the time both sessions are
// connected and has the same length in every run:
//
//   * the script picks one instant, START, on CLOCK_MONOTONIC (one clock for every process of the host),
//     and gives it to both processes (-a, in nanoseconds);
//   * the sender begins its paced span at START and keeps its session open until after the window ends;
//   * the receiver calls bench_window_open() at START less its guard and bench_window_close() at
//     START + SECONDS plus its guard. Run under callgrind with --zero-before='bench_window_open*' and
//     --dump-before='bench_window_close*', every cost is zeroed at the first and the window's costs are
//     written to a part file of their own (<out file>.<part>) at the second; what the process does after
//     the window goes to the file of its end, which the reading does not use.
//
// Outside callgrind the two functions are two stores, and a run without -a has no window.
#ifndef WZ_HOST_BENCH_WINDOW_H
#define WZ_HOST_BENCH_WINDOW_H

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

static inline uint64_t bench_now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

// Sleeps, not spins, so that a counted wait costs one call and not the time it waits.
static inline void bench_sleep_until_ns(uint64_t target_ns) {
    const struct timespec ts = {(time_t)(target_ns / 1000000000ULL), (long)(target_ns % 1000000000ULL)};
    while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL) == EINTR) {
    }
}

// The instant of -a: a whole number of nanoseconds on CLOCK_MONOTONIC, or 0 when the text is not one
// (the callers refuse 0).
static inline uint64_t bench_parse_instant(const char *text) {
    char *end = NULL;
    errno = 0;
    const unsigned long long value = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0') return 0;
    return (uint64_t)value;
}

// Distinct bodies, so that no identical-code folding gives the two one address and callgrind one name.
__attribute__((unused)) static volatile int bench_window_state;

__attribute__((noinline, unused)) static void bench_window_open(void) { bench_window_state = 1; }

__attribute__((noinline, unused)) static void bench_window_close(void) { bench_window_state = 2; }

#endif
