// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// A subscriber that COUNTS what it is delivered, for the no-drop rate search of
// scripts/host-bench/nodrop.py. The upstream throughput subscriber prints a rate every 100 ms and
// nothing when it received nothing in the interval; this one says how many it received in all, so the
// publisher's `sent` can be set against it.
//
// It uses only the zenoh-pico C API the upstream examples use, so the SAME source is built once against
// zenoh-pico and once against libwz_capi_pico (scripts/pico-compare.sh nodrop).
//
//   count_sub -m peer -l tcp/127.0.0.1:PORT -d SECONDS [-k KEY] [-a START -t SECONDS -g MS]
//
// It listens for -d SECONDS and prints one line: `count_sub received=<n>`.
//
// With -a START (an instant on CLOCK_MONOTONIC, in nanoseconds) it counts a window for
// scripts/pico-compare.sh subprofile (scripts/host-bench/bench_window.h): it calls bench_window_open() at
// START less -g MS and bench_window_close() at START + -t SECONDS plus -g MS, listens until the later of
// that and the end of -d SECONDS, and the line adds ` in_window=<n>`, what it received between the two.
//
// Against a library of one thread (Z_FEATURE_MULTI_THREAD 0, the form a deployment of one task ships) no
// task reads for the program, so the subscriber spins its session for the SECONDS itself, with no sleep
// between spins, as upstream's single-threaded examples drive theirs; a sleep would cap the rate it reads.
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "bench_api.h"
#include "bench_window.h"

#if Z_FEATURE_SUBSCRIPTION == 1

static _Atomic unsigned long received;

static void on_sample(z_loaned_sample_t *sample, void *context) {
    (void)sample;
    (void)context;
    atomic_fetch_add_explicit(&received, 1, memory_order_relaxed);
}

static void drop_context(void *context) { (void)context; }

int main(int argc, char **argv) {
    const char *keyexpr = "thr";
    unsigned seconds = 8;
    uint64_t start_ns = 0;
    unsigned window_s = 0;
    unsigned guard_ms = 0;

    z_owned_config_t config;
    z_config_default(&config);
    int opt;
    while ((opt = getopt(argc, argv, "k:l:m:d:a:t:g:")) != -1) {
        switch (opt) {
            case 'k':
                keyexpr = optarg;
                break;
            case 'l':
                BENCH_CONFIG_INSERT(config, Z_CONFIG_LISTEN_KEY, optarg);
                break;
            case 'm':
                BENCH_CONFIG_INSERT(config, Z_CONFIG_MODE_KEY, optarg);
                break;
            case 'd':
                seconds = (unsigned)strtoul(optarg, NULL, 10);
                break;
            case 'a':
                start_ns = bench_parse_instant(optarg);
                if (start_ns == 0) {
                    fprintf(stderr, "count_sub: -a takes an instant on CLOCK_MONOTONIC in nanoseconds\n");
                    return 2;
                }
                break;
            case 't':
                window_s = (unsigned)strtoul(optarg, NULL, 10);
                break;
            case 'g':
                guard_ms = (unsigned)strtoul(optarg, NULL, 10);
                break;
            default:
                fprintf(stderr, "usage: count_sub -m peer -l ENDPOINT -d SECONDS [-k KEY] [-a START -t SECONDS -g MS]\n");
                return 2;
        }
    }

    atomic_store_explicit(&received, 0, memory_order_relaxed);
    z_owned_session_t s;
    if (z_open(&s, z_move(config), NULL) < 0) {
        printf("count_sub: unable to open the session\n");
        return 1;
    }
    z_view_keyexpr_t ke;
    if (z_view_keyexpr_from_str(&ke, keyexpr) < 0) {
        printf("count_sub: %s is not a key expression\n", keyexpr);
        return 1;
    }
    z_owned_closure_sample_t callback;
    z_closure(&callback, on_sample, drop_context, NULL);
    if (z_declare_background_subscriber(z_loan(s), z_loan(ke), z_move(callback), NULL) < 0) {
        printf("count_sub: unable to declare the subscriber\n");
        return 1;
    }

    uint64_t end = bench_now_ns() + (uint64_t)seconds * 1000000000ULL;
    uint64_t open_ns = 0, close_ns = 0;
    if (start_ns != 0) {
        const uint64_t guard_ns = (uint64_t)guard_ms * 1000000ULL;
        open_ns = start_ns - guard_ns;
        close_ns = start_ns + (uint64_t)window_s * 1000000000ULL + guard_ns;
        if (bench_now_ns() >= open_ns) {
            printf("count_sub: the subscriber was declared after its window opened\n");
            return 1;
        }
        if (close_ns > end) end = close_ns;
    }
    unsigned long before = 0, in_window = 0;
#if Z_FEATURE_MULTI_THREAD == 1
    if (start_ns != 0) {
        bench_sleep_until_ns(open_ns);
        before = atomic_load_explicit(&received, memory_order_relaxed);
        bench_window_open();
        bench_sleep_until_ns(close_ns);
        bench_window_close();
        in_window = atomic_load_explicit(&received, memory_order_relaxed) - before;
    }
    bench_sleep_until_ns(end);
#else
    // The window's edges are read between two spins: the spin in progress at an edge is the only one
    // that may fall on either side of it.
    int window = start_ns != 0 ? 0 : 2;
    for (uint64_t now = bench_now_ns(); now < end; now = bench_now_ns()) {
        if (window == 0 && now >= open_ns) {
            before = atomic_load_explicit(&received, memory_order_relaxed);
            bench_window_open();
            window = 1;
        } else if (window == 1 && now >= close_ns) {
            bench_window_close();
            in_window = atomic_load_explicit(&received, memory_order_relaxed) - before;
            window = 2;
        }
        (void)zp_spin_once(z_loan(s));
    }
#endif
    printf("count_sub received=%lu", atomic_load_explicit(&received, memory_order_relaxed));
    if (start_ns != 0) printf(" in_window=%lu", in_window);
    printf("\n");
    fflush(stdout);
    z_drop(z_move(s));
    return 0;
}

#else
int main(void) {
    printf("count_sub: this zenoh-pico is built without Z_FEATURE_SUBSCRIPTION\n");
    return 1;
}
#endif
