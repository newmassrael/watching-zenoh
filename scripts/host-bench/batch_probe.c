// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// The unicast batch size on the wire, one program for both libraries (scripts/host-bench/batch_control.py,
// run by scripts/pico-compare.sh batch): built once per size against zenoh-pico, whose batch size is
// Z_BATCH_UNICAST_SIZE of the config.h it was built with, and once against libwz_capi_pico, whose session is
// handed the size at run time.
//
//   batch_probe sub -l ENDPOINT -n COUNT [-B BATCH]
//   batch_probe pub -e ENDPOINT -n COUNT [-B BATCH]
//
// Both open in peer mode. sub listens, declares a subscriber on batch/size/burst, prints "ready" and exits 0
// once COUNT samples arrived, 1 when they did not in WAIT_MS. pub dials, declares a publisher, waits until it
// matches the subscriber (a zenoh-pico publisher that knows of no subscriber sends nothing and still answers
// the put), opens a batching window, puts COUNT samples of fifteen bytes, closes the window, and closes the
// session FLUSH_MS later; it prints the batch size its header states and the one it was handed.
//
// -B, in a build with BATCH_PROBE_DOCUMENT (against libwz_capi_pico only), hands the config the document
// {"wz": {"limits": {"PICO_UNICAST_BATCH_BYTES": BATCH}}} through wz_ext_config_document: the size is then
// the session's. zenoh-pico has no such door, and a build without the define refuses -B.

#define _GNU_SOURCE
#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "zenoh-pico.h"

#ifdef BATCH_PROBE_DOCUMENT
#include "wz_ext.h"
#endif

#if Z_FEATURE_BATCHING != 1 || Z_FEATURE_MATCHING != 1
#error "the batch probe needs zp_batch_start and the publisher's matching status"
#endif

#define KEY "batch/size/burst"
#define WAIT_MS 30000
#define MATCH_MS 10000
#define FLUSH_MS 1000

static atomic_int heard = 0;

static void sleep_ms(unsigned ms) {
    struct timespec nap = {(time_t)(ms / 1000), (long)(ms % 1000) * 1000000L};
    while (nanosleep(&nap, &nap) != 0 && errno == EINTR) {
    }
}

static void on_sample(z_loaned_sample_t *sample, void *arg) {
    (void)sample;
    (void)arg;
    atomic_fetch_add(&heard, 1);
}

static int usage(void) {
    fprintf(stderr, "usage: batch_probe sub -l ENDPOINT -n COUNT [-B BATCH] | pub -e ENDPOINT -n COUNT [-B BATCH]\n");
    return 2;
}

static int run_sub(const z_loaned_session_t *session, int count) {
    z_owned_closure_sample_t closure;
    z_closure_sample(&closure, on_sample, NULL, NULL);
    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, KEY);
    z_owned_subscriber_t sub;
    if (z_declare_subscriber(session, &sub, z_view_keyexpr_loan(&ke), z_closure_sample_move(&closure), NULL) !=
        Z_OK) {
        printf("batch_probe sub: unable to declare the subscriber\n");
        return 1;
    }
    printf("batch_probe sub: ready\n");
    fflush(stdout);
    for (unsigned waited = 0; waited < WAIT_MS && atomic_load(&heard) < count; waited += 10) {
        sleep_ms(10);
    }
    int got = atomic_load(&heard);
    printf("batch_probe sub: heard %d of %d\n", got, count);
    z_undeclare_subscriber(z_subscriber_move(&sub));
    return got >= count ? 0 : 1;
}

static int run_pub(const z_loaned_session_t *session, int count, int stated) {
    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, KEY);
    z_publisher_options_t opts;
    z_publisher_options_default(&opts);
    z_owned_publisher_t pub;
    if (z_declare_publisher(session, &pub, z_view_keyexpr_loan(&ke), &opts) != Z_OK) {
        printf("batch_probe pub: unable to declare the publisher\n");
        return 1;
    }
    int matched = 0;
    for (unsigned waited = 0; waited < MATCH_MS && !matched; waited += 10) {
        z_matching_status_t status;
        matched = z_publisher_get_matching_status(z_publisher_loan(&pub), &status) == Z_OK && status.matching;
        if (!matched) sleep_ms(10);
    }
    if (!matched) {
        printf("batch_probe pub: the publisher matched no subscriber in %d ms\n", MATCH_MS);
        z_undeclare_publisher(z_publisher_move(&pub));
        return 1;
    }
    int failed = 0;
    char text[32];
    zp_batch_start(session);
    for (int n = 0; n < count; n++) {
        snprintf(text, sizeof text, "sample-%08d", n);
        z_owned_bytes_t payload;
        z_bytes_copy_from_str(&payload, text);
        if (z_publisher_put(z_publisher_loan(&pub), z_bytes_move(&payload), NULL) != Z_OK) failed++;
    }
    zp_batch_stop(session);
    printf("batch_probe pub: header %d stated %d sent %d failed %d\n", Z_BATCH_UNICAST_SIZE, stated, count - failed,
           failed);
    fflush(stdout);
    sleep_ms(FLUSH_MS);
    z_undeclare_publisher(z_publisher_move(&pub));
    return failed == 0 ? 0 : 1;
}

int main(int argc, char **argv) {
    if (argc < 2) return usage();
    const char *role = argv[1];
    int is_sub = strcmp(role, "sub") == 0;
    if (!is_sub && strcmp(role, "pub") != 0) return usage();
    const char *endpoint = NULL;
    int count = 0;
    int stated = 0;
    int opt;
    while ((opt = getopt(argc - 1, argv + 1, "l:e:n:B:")) != -1) {
        switch (opt) {
            case 'l':
            case 'e':
                endpoint = optarg;
                break;
            case 'n':
                count = atoi(optarg);
                break;
            case 'B':
                stated = atoi(optarg);
                break;
            default:
                return usage();
        }
    }
    if (endpoint == NULL || count <= 0) return usage();
#ifndef BATCH_PROBE_DOCUMENT
    if (stated != 0) {
        fprintf(stderr, "batch_probe: -B needs a build with BATCH_PROBE_DOCUMENT (wz only)\n");
        return 2;
    }
#endif

    z_owned_config_t config;
    z_config_default(&config);
    zp_config_insert(z_config_loan_mut(&config), Z_CONFIG_MODE_KEY, "peer");
    zp_config_insert(z_config_loan_mut(&config), is_sub ? Z_CONFIG_LISTEN_KEY : Z_CONFIG_CONNECT_KEY, endpoint);
#ifdef BATCH_PROBE_DOCUMENT
    if (stated > 0) {
        char document[96];
        snprintf(document, sizeof document, "{\"wz\": {\"limits\": {\"PICO_UNICAST_BATCH_BYTES\": %d}}}", stated);
        z_result_t rc = wz_ext_config_document(z_config_loan_mut(&config), document);
        if (rc != Z_OK) {
            printf("batch_probe %s: the document stating a batch of %d was refused (%d)\n", role, stated, (int)rc);
            z_config_drop(z_config_move(&config));
            return 2;
        }
    }
#endif
    z_owned_session_t session;
    z_result_t opened = z_open(&session, z_config_move(&config), NULL);
    if (opened != Z_OK) {
        printf("batch_probe %s: the session did not open (%d)\n", role, (int)opened);
        return 1;
    }
    int rc = is_sub ? run_sub(z_session_loan(&session), count) : run_pub(z_session_loan(&session), count, stated);
    z_close(z_session_loan_mut(&session), NULL);
    z_session_drop(z_session_move(&session));
    return rc;
}
