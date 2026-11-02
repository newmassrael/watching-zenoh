// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// What the host benches (paced_pub.c, count_sub.c) need of a zenoh C API, in the one place where
// zenoh-pico's and zenoh-c's differ, so the same source is built against either:
//
//   * the header (zenoh-pico.h or zenoh.h);
//   * how a config value is stated: zenoh-pico takes the text of the value, zenoh-c takes JSON5 (the
//     mode is a string, an endpoint key a list);
//   * the Z_FEATURE_* macros the benches test, which zenoh-pico's configuration defines and zenoh-c's
//     does not (it has the publication, the subscription and no batching).
//
// BENCH_ZENOHC is defined by the build for a zenoh-c family (the zenoh-c library or the wz library
// that stands in for it); without it the source is built for zenoh-pico or the wz pico ABI.
#ifndef WZ_HOST_BENCH_API_H
#define WZ_HOST_BENCH_API_H

#include <stdio.h>
#include <string.h>

#ifdef BENCH_ZENOHC

#include "zenoh.h"

#define Z_FEATURE_PUBLICATION 1
#define Z_FEATURE_SUBSCRIPTION 1
#define Z_FEATURE_BATCHING 0

static inline int bench_config_insert(z_loaned_config_t *config, const char *key, const char *value) {
    char json[512];
    const int is_list = strcmp(key, Z_CONFIG_LISTEN_KEY) == 0 || strcmp(key, Z_CONFIG_CONNECT_KEY) == 0;
    snprintf(json, sizeof json, is_list ? "[\"%s\"]" : "\"%s\"", value);
    return zc_config_insert_json5(config, key, json);
}
#define BENCH_CONFIG_INSERT(config, key, value) bench_config_insert(z_loan_mut(config), (key), (value))

// zenoh-c announces a subscriber to the publisher after the connection, in a time the sleep of the bench
// does not bound; a put before the announcement reaches nobody and is counted as lost. The publisher asks
// instead (up to ten seconds) and starts when its key expression has a subscriber.
#include <unistd.h>
static inline void bench_wait_matching(const z_loaned_publisher_t *publisher) {
    for (int i = 0; i < 1000; i++) {
        z_matching_status_t status;
        if (z_publisher_get_matching_status(publisher, &status) == 0 && status.matching) return;
        usleep(10000);
    }
}
#define BENCH_WAIT_MATCHING(publisher) bench_wait_matching(publisher)

#else

#include "zenoh-pico.h"

#define BENCH_CONFIG_INSERT(config, key, value) zp_config_insert(z_loan_mut(config), (key), (value))

#define BENCH_WAIT_MATCHING(publisher) ((void)(publisher))

#endif

#endif
