// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// The facility oracle's driver of libwz_capi_pico (scripts/lib/facility_trace.py,
// docs/target-build-contract.md T9): a library runs only inside a program, so this is the program
// a scenario runs. `pico_session listen|connect <locator> <seconds>` opens a session through the
// pico C ABI (a peer that listens on the locator, or a client that dials it), puts `v` on
// `demo/x` every 100 ms for the given seconds, and closes the session: the run ends by itself,
// through the library's own close. Before it opens, it prints what the library says the config
// asks of the device (`wz_ext_config_device_requires`, of the unstable surface), which the oracle
// holds the traced run to. It exits 0 when every call succeeded and names the one that did not
// otherwise.

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "wz_capi_pico.h"
#include "wz_ext.h"

static int failed(const char *call, int rc) {
    fprintf(stderr, "pico_session: %s returned %d\n", call, rc);
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 4 || (strcmp(argv[1], "listen") && strcmp(argv[1], "connect"))) {
        fprintf(stderr, "usage: pico_session listen|connect <locator> <seconds>\n");
        return 2;
    }
    int listens = !strcmp(argv[1], "listen");
    int seconds = 0;
    if (sscanf(argv[3], "%d", &seconds) != 1 || seconds < 1) {
        fprintf(stderr, "pico_session: <seconds> is not a positive integer\n");
        return 2;
    }

    z_owned_config_t config;
    int rc = z_config_default(&config);
    if (rc != Z_OK) return failed("z_config_default", rc);
    rc = zp_config_insert(z_config_loan_mut(&config), Z_CONFIG_MODE_KEY, listens ? "peer" : "client");
    if (rc != Z_OK) return failed("zp_config_insert(mode)", rc);
    rc = zp_config_insert(z_config_loan_mut(&config), listens ? Z_CONFIG_LISTEN_KEY : Z_CONFIG_CONNECT_KEY,
                          argv[2]);
    if (rc != Z_OK) return failed("zp_config_insert(locator)", rc);
    // What the library says this config asks of the device, on the line the oracle judges the run
    // by (`device_requires <json>`), before the open consumes the config.
    z_owned_string_t requirement;
    rc = wz_ext_config_device_requires(z_config_loan(&config), &requirement);
    if (rc != Z_OK) return failed("wz_ext_config_device_requires", rc);
    printf("device_requires %.*s\n", (int)z_string_len(z_string_loan(&requirement)),
           z_string_data(z_string_loan(&requirement)));
    fflush(stdout);
    z_string_drop(z_string_move(&requirement));

    z_owned_session_t session;
    rc = z_open(&session, z_config_move(&config), NULL);
    if (rc != Z_OK) return failed("z_open", rc);

    z_view_keyexpr_t key;
    rc = z_view_keyexpr_from_str(&key, "demo/x");
    if (rc != Z_OK) return failed("z_view_keyexpr_from_str", rc);
    struct timespec pause = {0, 100 * 1000 * 1000};
    for (int i = 0; i < seconds * 10; i++) {
        z_owned_bytes_t payload;
        rc = z_bytes_copy_from_str(&payload, "v");
        if (rc != Z_OK) return failed("z_bytes_copy_from_str", rc);
        rc = z_put(z_session_loan(&session), z_view_keyexpr_loan(&key), z_bytes_move(&payload), NULL);
        if (rc != Z_OK) return failed("z_put", rc);
        nanosleep(&pause, NULL);
    }

    rc = z_close(z_session_loan_mut(&session), NULL);
    if (rc != Z_OK) return failed("z_close", rc);
    z_session_drop(z_session_move(&session));
    return 0;
}
