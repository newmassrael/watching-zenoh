/* SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * A client of a declared node's lifecycle verbs, written as a consumer's program
 * is: C, against wz_capi_c.h, linked against the library built with the doors it
 * calls (`lifecycle-doors`, `identity-make`). The witness of the Zcmd lane
 * (crates/wz-integration-tests/tests/it/files/wz_declared_commander_zenohd_interop.rs)
 * runs it against a node built from deploy/nodes/slot-commander.toml.
 *
 *   c_lifecycle_witness make <certificate> <private_key>
 *       makes the client's identity on this computer (wz_capi_c_identity_make)
 *       and prints `zid <zid>`, the spelling a configuration's `id` takes;
 *   c_lifecycle_witness ask <config> <verb> <of> <about>
 *       opens a session from the configuration file (the canonical one is
 *       deploy/clients/commander.json5, filled in), makes the verb's key from
 *       its words (wz_capi_c_lifecycle_key), asks it with z_get and reads each
 *       reply (wz_capi_c_lifecycle_read), printing `key <key>`, one
 *       `reply kind=<k> verdict=<v> reason=<r>` per reply and `replies <n>`.
 *
 * Every line goes to standard output; a call that fails prints `FAIL <what>`
 * to standard error and the program exits 1.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "wz_capi_c.h"

static int fail(const char *what, int rc) {
    fprintf(stderr, "FAIL %s (%d)\n", what, rc);
    return 1;
}

static const char *or_dash(const char *word) { return word != NULL ? word : "-"; }

static int make(const char *certificate, const char *private_key) {
    wz_capi_c_identity_t id;
    z_result_t rc = wz_capi_c_identity_make(certificate, private_key, &id);
    if (rc != Z_OK) {
        fprintf(stderr, "FAIL identity: %s: %s\n", or_dash(id.file), or_dash(id.reason));
        return 1;
    }
    printf("zid %s\n", id.zid);
    return 0;
}

static int ask(const char *config_path, const char *verb, const char *of, const char *about) {
    char key[WZ_CAPI_C_LIFECYCLE_KEY_MAX];
    const char *refusal = NULL;
    wz_capi_c_lifecycle_words_t words = {
        .verb = verb,
        .of = of,
        .about = about,
        .whatami = NULL,
        .has_generation = false,
        .generation = 0,
        .mode = NULL,
    };
    z_result_t rc = wz_capi_c_lifecycle_key(&words, key, sizeof key, &refusal);
    if (rc != Z_OK) {
        fprintf(stderr, "FAIL key: %s\n", or_dash(refusal));
        return 1;
    }
    printf("key %s\n", key);

    z_owned_config_t config;
    rc = zc_config_from_file(&config, config_path);
    if (rc != Z_OK) {
        return fail("config", rc);
    }
    z_owned_session_t session;
    rc = z_open(&session, z_move(config), NULL);
    if (rc != Z_OK) {
        return fail("open", rc);
    }

    z_view_keyexpr_t keyexpr;
    rc = z_view_keyexpr_from_str(&keyexpr, key);
    if (rc != Z_OK) {
        z_drop(z_move(session));
        return fail("keyexpr", rc);
    }
    z_owned_closure_reply_t closure;
    z_owned_fifo_handler_reply_t handler;
    z_fifo_channel_reply_new(&closure, &handler, 16);
    z_get_options_t options;
    z_get_options_default(&options);
    options.timeout_ms = 5000;
    rc = z_get(z_loan(session), z_loan(keyexpr), "", z_move(closure), &options);
    if (rc != Z_OK) {
        z_drop(z_move(handler));
        z_drop(z_move(session));
        return fail("get", rc);
    }

    int replies = 0;
    z_owned_reply_t reply;
    for (z_result_t got = z_recv(z_loan(handler), &reply); got == Z_OK;
         got = z_recv(z_loan(handler), &reply)) {
        if (z_reply_is_ok(z_loan(reply))) {
            const z_loaned_sample_t *sample = z_reply_ok(z_loan(reply));
            z_owned_slice_t payload;
            z_bytes_to_slice(z_sample_payload(sample), &payload);
            wz_capi_c_lifecycle_read_t read;
            rc = wz_capi_c_lifecycle_read(z_slice_data(z_loan(payload)),
                                          z_slice_len(z_loan(payload)), &read);
            z_drop(z_move(payload));
            if (rc != Z_OK) {
                z_drop(z_move(reply));
                z_drop(z_move(handler));
                z_drop(z_move(session));
                return fail("read", rc);
            }
            printf("reply kind=%d verdict=%s reason=%s\n", (int)read.kind,
                   or_dash(read.verdict), or_dash(read.reason));
            replies++;
        } else {
            printf("reply error\n");
        }
        z_drop(z_move(reply));
    }
    printf("replies %d\n", replies);
    z_drop(z_move(handler));
    z_drop(z_move(session));
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 4 && strcmp(argv[1], "make") == 0) {
        return make(argv[2], argv[3]);
    }
    if (argc == 6 && strcmp(argv[1], "ask") == 0) {
        return ask(argv[2], argv[3], argv[4], argv[5]);
    }
    fprintf(stderr,
            "usage: %s make <certificate> <private_key>\n"
            "       %s ask <config> <verb> <of> <about>\n",
            argv[0], argv[0]);
    return 2;
}
