// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// A publisher that OFFERS a stated rate, for the no-drop rate search of scripts/host-bench/nodrop.py
// (RFC 2544: the highest rate at which nothing is lost). The upstream throughput example sends as fast
// as it can, which says how fast a side CAN go and not whether the other side keeps up; this one sends
// what it is told to, and says what it actually did.
//
// It uses only the zenoh-pico C API the upstream examples use, so the SAME source is built once against
// zenoh-pico and once against libwz_capi_pico (scripts/pico-compare.sh nodrop).
//
//   paced_pub -m peer -e tcp/127.0.0.1:PORT -s SIZE -r RATE -t SECONDS [-k KEY] [-b] [-d]
//
// With -b the puts of one slot are one batch (`zp_batch_start` before them and `zp_batch_stop` after, which
// flushes it), as the upstream throughput example does for its whole run: it is how zenoh-pico reaches its
// highest rate, and the program measured without it says what one put costs and not what the library can
// carry. Both are measured, and the result names which.
//
// Time is cut into slots of one millisecond. In each slot the publisher puts the number of messages that
// make RATE a second (the fraction is carried to the next slot) back to back, then spins until the next
// slot. A slot that starts a millisecond or more late is counted in `late_slots`: the offered rate was
// not offered, and the trial does not stand for it. The last line is
//
//   paced_pub sent=<puts that returned 0> failed=<puts that returned an error> elapsed_s=<seconds from the
//   first slot to the end of the last put> late_slots=<n>
//
// The publisher is Z_CONGESTION_CONTROL_BLOCK: a full link slows it down (and shows as an elapsed time
// past the trial and as late slots) and does not drop at the sender, so a message the subscriber never
// counts was lost on the way. With -d it is Z_CONGESTION_CONTROL_DROP, as the upstream throughput example
// sets it: what the sender cannot take it drops and still counts as put, which the subscriber's count
// then shows.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "zenoh-pico.h"

#if Z_FEATURE_PUBLICATION == 1

static void free_with_context(void *ptr, void *context) {
    (void)context;
    z_free(ptr);
}

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

int main(int argc, char **argv) {
    const char *keyexpr = "thr";
    size_t len = 8;
    double rate = 1000.0;
    unsigned seconds = 3;
    int batching = 0;
    int drop = 0;

    z_owned_config_t config;
    z_config_default(&config);
    int opt;
    while ((opt = getopt(argc, argv, "k:e:m:s:r:t:bd")) != -1) {
        switch (opt) {
            case 'b':
                batching = 1;
                break;
            case 'd':
                drop = 1;
                break;
            case 'k':
                keyexpr = optarg;
                break;
            case 'e':
                zp_config_insert(z_loan_mut(config), Z_CONFIG_CONNECT_KEY, optarg);
                break;
            case 'm':
                zp_config_insert(z_loan_mut(config), Z_CONFIG_MODE_KEY, optarg);
                break;
            case 's':
                len = (size_t)strtoul(optarg, NULL, 10);
                break;
            case 'r':
                rate = strtod(optarg, NULL);
                break;
            case 't':
                seconds = (unsigned)strtoul(optarg, NULL, 10);
                break;
            default:
                fprintf(stderr, "usage: paced_pub -m peer -e ENDPOINT -s SIZE -r RATE -t SECONDS [-k KEY] [-b] [-d]\n");
                return 2;
        }
    }

    z_owned_session_t s;
    if (z_open(&s, z_move(config), NULL) < 0) {
        printf("paced_pub: unable to open the session\n");
        return 1;
    }
    // The subscriber's declaration reaches this side a moment after the connection.
    sleep(1);

    z_view_keyexpr_t ke;
    if (z_view_keyexpr_from_str(&ke, keyexpr) < 0) {
        printf("paced_pub: %s is not a key expression\n", keyexpr);
        return 1;
    }
    z_owned_publisher_t pub;
    z_publisher_options_t opts;
    z_publisher_options_default(&opts);
    opts.congestion_control = drop ? Z_CONGESTION_CONTROL_DROP : Z_CONGESTION_CONTROL_BLOCK;
    if (z_declare_publisher(z_loan(s), &pub, z_loan(ke), &opts) < 0) {
        printf("paced_pub: unable to declare the publisher\n");
        return 1;
    }

    uint8_t *value = (uint8_t *)z_malloc(len);
    memset(value, 1, len);
    z_owned_bytes_t payload;
    z_bytes_from_buf(&payload, value, len, free_with_context, NULL);

    (void)batching;
    const uint64_t slot_ns = 1000000ULL;
    const uint64_t run_ns = (uint64_t)seconds * 1000000000ULL;
    const double per_slot = rate / 1000.0;
    double owed = 0.0;
    unsigned long sent = 0, failed = 0, late = 0;
    uint64_t slot = 0;
    const uint64_t t0 = now_ns();
    uint64_t end = t0;
    for (;;) {
        uint64_t target = t0 + slot * slot_ns;
        if (target >= t0 + run_ns) break;
        uint64_t now;
        while ((now = now_ns()) < target) {
        }
        if (now - target >= slot_ns) late++;
        owed += per_slot;
        unsigned long n = (unsigned long)owed;
        owed -= (double)n;
#if Z_FEATURE_BATCHING == 1
        if (batching && n > 1) zp_batch_start(z_loan(s));
#endif
        for (unsigned long i = 0; i < n; i++) {
            z_owned_bytes_t p;
            z_bytes_clone(&p, z_loan(payload));
            if (z_publisher_put(z_loan(pub), z_move(p), NULL) == 0) {
                sent++;
            } else {
                failed++;
            }
        }
#if Z_FEATURE_BATCHING == 1
        if (batching && n > 1) zp_batch_stop(z_loan(s));
#endif
        end = now_ns();
        slot++;
    }
    printf("paced_pub sent=%lu failed=%lu elapsed_s=%.3f late_slots=%lu\n", sent, failed,
           (double)(end - t0) / 1e9, late);
    fflush(stdout);

    z_drop(z_move(pub));
    z_drop(z_move(s));
    z_drop(z_move(payload));
    return 0;
}

#else
int main(void) {
    printf("paced_pub: this zenoh-pico is built without Z_FEATURE_PUBLICATION\n");
    return 1;
}
#endif
