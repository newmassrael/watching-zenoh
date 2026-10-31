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
//   count_sub -m peer -l tcp/127.0.0.1:PORT -d SECONDS [-k KEY]
//
// It listens for SECONDS and prints one line: `count_sub received=<n>`.
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "zenoh-pico.h"

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

    z_owned_config_t config;
    z_config_default(&config);
    int opt;
    while ((opt = getopt(argc, argv, "k:l:m:d:")) != -1) {
        switch (opt) {
            case 'k':
                keyexpr = optarg;
                break;
            case 'l':
                zp_config_insert(z_loan_mut(config), Z_CONFIG_LISTEN_KEY, optarg);
                break;
            case 'm':
                zp_config_insert(z_loan_mut(config), Z_CONFIG_MODE_KEY, optarg);
                break;
            case 'd':
                seconds = (unsigned)strtoul(optarg, NULL, 10);
                break;
            default:
                fprintf(stderr, "usage: count_sub -m peer -l ENDPOINT -d SECONDS [-k KEY]\n");
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
    sleep(seconds);
    printf("count_sub received=%lu\n", atomic_load_explicit(&received, memory_order_relaxed));
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
