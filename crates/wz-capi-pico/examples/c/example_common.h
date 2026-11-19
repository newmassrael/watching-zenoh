/*
 * SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * What the C examples of the pico C ABI share: the check count, a port drawn from the
 * library's random source, the two ends of a session pair in one process, and a counter
 * a callback and the program's own thread both touch.
 *
 * Each example is one translation unit that defines EXAMPLE_NAME and includes this file
 * after <zenoh-pico.h>. It is compiled against zenoh-pico's own headers for the host and
 * linked against the wz library in place of libzenohpico (scripts/pico-c-program.sh), so
 * what it shows is what a pico program sees. Every example ends with ex_finish(), whose
 * status is 0 when every check held; the last line printed is the count either way.
 */

#ifndef WZ_EXAMPLE_COMMON_H
#define WZ_EXAMPLE_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef EXAMPLE_NAME
#error "an example defines EXAMPLE_NAME before it includes example_common.h"
#endif

static int ex_checks = 0;
static int ex_failures = 0;

#define CHECK(cond, ...)                                              \
    do {                                                              \
        ex_checks++;                                                  \
        if (!(cond)) {                                                \
            ex_failures++;                                            \
            printf("%s: FAIL at line %d: ", EXAMPLE_NAME, __LINE__);  \
            printf(__VA_ARGS__);                                      \
            printf("\n");                                             \
        }                                                             \
    } while (0)

static inline int ex_finish(void) {
    printf("%s: %d check(s), %d failure(s)\n", EXAMPLE_NAME, ex_checks, ex_failures);
    return ex_failures == 0 ? 0 : 1;
}

/* A port from the library's random source: two sessions of this process have to agree on
 * one, and a fixed number would collide with another run on the same host. */
static inline unsigned ex_port(void) { return 20000u + (unsigned)(z_random_u32() % 20000u); }

/* The listening end: a session that binds `locator` and accepts the other. */
static inline z_result_t ex_open_listener(z_owned_session_t *session, const char *locator) {
    z_owned_config_t config;
    z_config_default(&config);
    zp_config_insert(z_config_loan_mut(&config), Z_CONFIG_LISTEN_KEY, locator);
    return z_open(session, z_config_move(&config), NULL);
}

/* The dialling end: a client that connects to `locator`, retried while the listener binds. */
static inline z_result_t ex_open_dialer(z_owned_session_t *session, const char *locator) {
    z_result_t rc = -1;
    for (int attempt = 0; attempt < 100 && rc != Z_OK; attempt++) {
        z_owned_config_t config;
        z_config_default(&config);
        zp_config_insert(z_config_loan_mut(&config), Z_CONFIG_MODE_KEY, "client");
        zp_config_insert(z_config_loan_mut(&config), Z_CONFIG_CONNECT_KEY, locator);
        rc = z_open(session, z_config_move(&config), NULL);
        if (rc != Z_OK) z_sleep_ms(100);
    }
    return rc;
}

/* A member of a group: a peer that joins the multicast group `locator` names. */
static inline z_result_t ex_open_member(z_owned_session_t *session, const char *locator) {
    z_owned_config_t config;
    z_config_default(&config);
    zp_config_insert(z_config_loan_mut(&config), Z_CONFIG_MODE_KEY, "peer");
    zp_config_insert(z_config_loan_mut(&config), Z_CONFIG_LISTEN_KEY, locator);
    return z_open(session, z_config_move(&config), NULL);
}

static inline void ex_close(z_owned_session_t *session) {
    z_close(z_session_loan_mut(session), NULL);
    z_session_drop(z_session_move(session));
}

static inline z_result_t ex_put(const z_loaned_session_t *session, const char *key, const char *text,
                                z_put_options_t *options) {
    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, key);
    z_owned_bytes_t payload;
    z_bytes_copy_from_str(&payload, text);
    return z_put(session, z_view_keyexpr_loan(&ke), z_bytes_move(&payload), options);
}

/* A count a callback raises on a session thread and the program reads on its own. */
typedef struct {
    z_owned_mutex_t lock;
    int value;
} ex_counter_t;

static inline void ex_counter_init(ex_counter_t *c) {
    z_mutex_init(&c->lock);
    c->value = 0;
}

static inline void ex_counter_add(ex_counter_t *c, int n) {
    z_mutex_lock(z_mutex_loan_mut(&c->lock));
    c->value += n;
    z_mutex_unlock(z_mutex_loan_mut(&c->lock));
}

static inline int ex_counter_get(ex_counter_t *c) {
    z_mutex_lock(z_mutex_loan_mut(&c->lock));
    int value = c->value;
    z_mutex_unlock(z_mutex_loan_mut(&c->lock));
    return value;
}

static inline void ex_counter_drop(ex_counter_t *c) { z_mutex_drop(z_mutex_move(&c->lock)); }

/* Wait until `c` reaches `at_least` or `ms` milliseconds pass; whether it did. */
static inline int ex_wait_for(ex_counter_t *c, int at_least, int ms) {
    for (int waited = 0; waited < ms; waited += 10) {
        if (ex_counter_get(c) >= at_least) return 1;
        z_sleep_ms(10);
    }
    return ex_counter_get(c) >= at_least;
}

/* The text of a payload, cut to `cap - 1` bytes and NUL-terminated. */
static inline void ex_payload_text(const z_loaned_bytes_t *payload, char *out, size_t cap) {
    z_owned_string_t value;
    out[0] = '\0';
    if (z_bytes_to_string(payload, &value) != Z_OK) return;
    size_t len = z_string_len(z_string_loan(&value));
    if (len >= cap) len = cap - 1;
    memcpy(out, z_string_data(z_string_loan(&value)), len);
    out[len] = '\0';
    z_string_drop(z_string_move(&value));
}

#endif /* WZ_EXAMPLE_COMMON_H */
