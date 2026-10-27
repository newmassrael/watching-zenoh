// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// The facility oracle's driver of libwz_capi_c (scripts/lib/facility_trace.py,
// docs/target-build-contract.md T9): `c_session listen|connect <locator> <seconds>` opens a
// session through the zenoh-c ABI (a peer that listens on the locator, or a client that dials it),
// puts `v` on `demo/x` every 100 ms for the given seconds, and closes it.
//
// It declares the calls it makes instead of including zenoh.h. The sizes of zenoh-c's owned types
// depend on the arm a build is (Z_FEATURE_UNSTABLE_API, Z_FEATURE_SHARED_MEMORY), and the header of
// another arm would give this program storage of the wrong size for the library it runs with. Every
// call below passes its objects by pointer, which is the same in every arm, so storage larger than
// any arm's type, aligned for any of its members, is right for all four. The largest of them is the
// config, 2064 bytes in the unstable-shm arm's zenoh_opaque.h (zenoh-c 1.10.1); 16 KiB leaves it
// room to grow eightfold. A `z_moved_X_t` is
// `struct { z_owned_X_t _this; }` and zenoh-c's `z_X_move` is a cast in its header, so the owned
// object's address is passed where a moved one is asked for.

#define _POSIX_C_SOURCE 200809L

#include <stdalign.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

typedef signed char z_result_t;
typedef struct {
    alignas(16) unsigned char bytes[16384];
} storage;

extern z_result_t z_config_default(storage *config);
extern void *z_config_loan_mut(storage *config);
extern z_result_t zc_config_insert_json5(void *config, const char *key, const char *value);
extern z_result_t z_open(storage *session, storage *config, const void *options);
extern const void *z_session_loan(const storage *session);
extern z_result_t z_view_keyexpr_from_str(storage *key, const char *expr);
extern const void *z_view_keyexpr_loan(const storage *key);
extern z_result_t z_bytes_copy_from_str(storage *bytes, const char *value);
extern z_result_t z_put(const void *session, const void *key, storage *payload, const void *options);
extern z_result_t z_close(void *session, const void *options);
extern void *z_session_loan_mut(storage *session);
extern void z_session_drop(storage *session);

static int failed(const char *call, int rc) {
    fprintf(stderr, "c_session: %s returned %d\n", call, rc);
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 4 || (strcmp(argv[1], "listen") && strcmp(argv[1], "connect"))) {
        fprintf(stderr, "usage: c_session listen|connect <locator> <seconds>\n");
        return 2;
    }
    int listens = !strcmp(argv[1], "listen");
    int seconds = 0;
    if (sscanf(argv[3], "%d", &seconds) != 1 || seconds < 1) {
        fprintf(stderr, "c_session: <seconds> is not a positive integer\n");
        return 2;
    }
    char endpoints[512];
    if (snprintf(endpoints, sizeof endpoints, "[\"%s\"]", argv[2]) >= (int)sizeof endpoints) {
        fprintf(stderr, "c_session: the locator is too long\n");
        return 2;
    }

    static storage config, session, key, payload;
    int rc = z_config_default(&config);
    if (rc != 0) return failed("z_config_default", rc);
    rc = zc_config_insert_json5(z_config_loan_mut(&config), "mode", listens ? "\"peer\"" : "\"client\"");
    if (rc != 0) return failed("zc_config_insert_json5(mode)", rc);
    rc = zc_config_insert_json5(z_config_loan_mut(&config), listens ? "listen/endpoints" : "connect/endpoints",
                                endpoints);
    if (rc != 0) return failed("zc_config_insert_json5(endpoints)", rc);
    rc = z_open(&session, &config, NULL);
    if (rc != 0) return failed("z_open", rc);

    rc = z_view_keyexpr_from_str(&key, "demo/x");
    if (rc != 0) return failed("z_view_keyexpr_from_str", rc);
    struct timespec pause = {0, 100 * 1000 * 1000};
    for (int i = 0; i < seconds * 10; i++) {
        rc = z_bytes_copy_from_str(&payload, "v");
        if (rc != 0) return failed("z_bytes_copy_from_str", rc);
        rc = z_put(z_session_loan(&session), z_view_keyexpr_loan(&key), &payload, NULL);
        if (rc != 0) return failed("z_put", rc);
        nanosleep(&pause, NULL);
    }

    rc = z_close(z_session_loan_mut(&session), NULL);
    if (rc != 0) return failed("z_close", rc);
    z_session_drop(&session);
    return 0;
}
