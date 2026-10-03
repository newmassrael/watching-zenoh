/*
 * SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * A zenoh-pico C program for the SESSION surface: two sessions over the host's
 * loopback, a publisher and a subscriber, compiled against zenoh-pico's OWN headers for
 * this host and linked against the wz cdylib in place of libzenohpico.
 *
 * `pico_host_layer.c` covers the exports that differ by host and opens no session. This
 * is the other half of what a pico program does: it opens a config, opens a session,
 * declares a subscriber with a closure, publishes a payload and reads the sample the
 * closure is handed, with the pico types the program declares (`z_owned_config_t`,
 * `z_owned_session_t`, `z_owned_subscriber_t`, `z_owned_closure_sample_t`,
 * `z_owned_bytes_t`) placed between guard bytes, so an export that writes past the
 * size pico's header gives a type is caught where it happens. The sessions are the
 * shape of pico's `z_put.c` and `z_sub.c` examples, and the acceptor and the dialer
 * are both the wz library, which is what a single process can hold.
 *
 * Exit status 0 means every check held; the last line printed is the count either way.
 */

#include <stdio.h>
#include <string.h>

#include <zenoh-pico.h>

#define GUARD 64
#define CANARY 0xA5
#define KEYEXPR "wz/host/session"
#define PAYLOAD "hello-from-a-pico-c-program"

static int checks = 0;
static int failures = 0;

#define CHECK(cond, ...)                                  \
    do {                                                  \
        checks++;                                         \
        if (!(cond)) {                                    \
            failures++;                                   \
            printf("pico-session-loopback: FAIL at line %d: ", __LINE__); \
            printf(__VA_ARGS__);                          \
            printf("\n");                                 \
        }                                                 \
    } while (0)

#define GUARDED(T, name)             \
    struct {                         \
        unsigned char before[GUARD]; \
        T v;                         \
        unsigned char after[GUARD];  \
    } name

static void guard_arm(unsigned char *before, unsigned char *after) {
    memset(before, CANARY, GUARD);
    memset(after, CANARY, GUARD);
}

static int guard_intact(const unsigned char *before, const unsigned char *after) {
    for (int i = 0; i < GUARD; i++) {
        if (before[i] != CANARY || after[i] != CANARY) return 0;
    }
    return 1;
}

/* What the subscriber's closure writes. `received` is the last thing it sets, and it is
 * read from another thread, so it is volatile; the strings are complete before it is. */
typedef struct {
    volatile int received;
    char key[64];
    char payload[64];
} sample_t;

static void on_sample(z_loaned_sample_t *sample, void *arg) {
    sample_t *out = (sample_t *)arg;
    z_view_string_t keystr;
    z_keyexpr_as_view_string(z_sample_keyexpr(sample), &keystr);
    size_t klen = z_string_len(z_view_string_loan(&keystr));
    if (klen < sizeof out->key) {
        memcpy(out->key, z_string_data(z_view_string_loan(&keystr)), klen);
        out->key[klen] = '\0';
    }
    z_owned_string_t value;
    z_bytes_to_string(z_sample_payload(sample), &value);
    size_t vlen = z_string_len(z_string_loan(&value));
    if (vlen < sizeof out->payload) {
        memcpy(out->payload, z_string_data(z_string_loan(&value)), vlen);
        out->payload[vlen] = '\0';
    }
    z_string_drop(z_string_move(&value));
    out->received = 1;
}

/* The acceptor: opens a listening session, then publishes until the dialer's subscriber
 * has received (its declaration takes a moment to reach this side) or a bound runs out. */
typedef struct {
    char listen[64];
    sample_t *sample;
    int opened;
    int published;
    int rc;
} acceptor_t;

static void *acceptor_main(void *arg) {
    acceptor_t *a = (acceptor_t *)arg;
    z_owned_config_t config;
    z_config_default(&config);
    zp_config_insert(z_config_loan_mut(&config), Z_CONFIG_LISTEN_KEY, a->listen);
    z_owned_session_t s;
    a->rc = z_open(&s, z_config_move(&config), NULL);
    if (a->rc < 0) return NULL;
    a->opened = 1;

    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, KEYEXPR);
    for (int i = 0; i < 400 && !a->sample->received; i++) {
        z_owned_bytes_t payload;
        z_bytes_copy_from_str(&payload, PAYLOAD);
        if (z_put(z_session_loan(&s), z_view_keyexpr_loan(&ke), z_bytes_move(&payload), NULL) == Z_OK) {
            a->published++;
        }
        z_sleep_ms(25);
    }
    z_close(z_session_loan_mut(&s), NULL);
    z_session_drop(z_session_move(&s));
    return NULL;
}

int main(void) {
    sample_t sample;
    memset(&sample, 0, sizeof sample);

    /* A port from the library's own random source: two sessions in this process have to
     * agree on one, and a fixed number would collide with a second run on the same host. */
    unsigned port = 20000u + (unsigned)(z_random_u32() % 20000u);
    acceptor_t acceptor;
    memset(&acceptor, 0, sizeof acceptor);
    snprintf(acceptor.listen, sizeof acceptor.listen, "tcp/127.0.0.1:%u", port);
    acceptor.sample = &sample;

    GUARDED(z_owned_task_t, task);
    guard_arm(task.before, task.after);
    CHECK(z_task_init(&task.v, NULL, acceptor_main, &acceptor) == Z_OK, "z_task_init for the acceptor");

    /* The dialer: pico's z_sub.c shape, in client mode, retried because the acceptor
     * binds on its own thread. Every owned type this program declares is guarded. */
    GUARDED(z_owned_config_t, config);
    GUARDED(z_owned_session_t, session);
    GUARDED(z_owned_closure_sample_t, callback);
    GUARDED(z_owned_subscriber_t, subscriber);
    guard_arm(config.before, config.after);
    guard_arm(session.before, session.after);
    guard_arm(callback.before, callback.after);
    guard_arm(subscriber.before, subscriber.after);

    char connect[64];
    snprintf(connect, sizeof connect, "tcp/127.0.0.1:%u", port);
    int opened = -1;
    int configs_ok = 1;
    for (int attempt = 0; attempt < 100 && opened < 0; attempt++) {
        if (z_config_default(&config.v) != Z_OK) configs_ok = 0;
        zp_config_insert(z_config_loan_mut(&config.v), Z_CONFIG_MODE_KEY, "client");
        zp_config_insert(z_config_loan_mut(&config.v), Z_CONFIG_CONNECT_KEY, connect);
        opened = z_open(&session.v, z_config_move(&config.v), NULL);
        if (opened < 0) z_sleep_ms(100);
    }
    CHECK(configs_ok, "z_config_default failed on an attempt");
    CHECK(opened == Z_OK, "the dialer could not open a session to %s (rc %d)", connect, opened);
    CHECK(guard_intact(config.before, config.after), "z_config_default / z_open wrote outside a z_owned_config_t (%zu bytes)", sizeof(z_owned_config_t));
    CHECK(guard_intact(session.before, session.after), "z_open wrote outside a z_owned_session_t (%zu bytes)", sizeof(z_owned_session_t));

    if (opened == Z_OK) {
        z_closure_sample(&callback.v, on_sample, NULL, &sample);
        CHECK(guard_intact(callback.before, callback.after), "z_closure_sample wrote outside a z_owned_closure_sample_t (%zu bytes)", sizeof(z_owned_closure_sample_t));
        z_view_keyexpr_t ke;
        CHECK(z_view_keyexpr_from_str(&ke, KEYEXPR) == Z_OK, "z_view_keyexpr_from_str");
        CHECK(z_declare_subscriber(z_session_loan(&session.v), &subscriber.v, z_view_keyexpr_loan(&ke),
                                   z_closure_sample_move(&callback.v), NULL) == Z_OK,
              "z_declare_subscriber");
        CHECK(guard_intact(subscriber.before, subscriber.after), "z_declare_subscriber wrote outside a z_owned_subscriber_t (%zu bytes)", sizeof(z_owned_subscriber_t));

        for (int i = 0; i < 1000 && !sample.received; i++) z_sleep_ms(10);
        CHECK(sample.received == 1, "the subscriber was never handed a sample");
        CHECK(strcmp(sample.key, KEYEXPR) == 0, "the sample's key expression was '%s'", sample.key);
        CHECK(strcmp(sample.payload, PAYLOAD) == 0, "the sample's payload was '%s'", sample.payload);

        z_subscriber_drop(z_subscriber_move(&subscriber.v));
        z_close(z_session_loan_mut(&session.v), NULL);
        z_session_drop(z_session_move(&session.v));
    }

    CHECK(z_task_join(z_task_move(&task.v)) == Z_OK, "z_task_join for the acceptor");
    CHECK(guard_intact(task.before, task.after), "the task calls wrote outside a z_owned_task_t");
    CHECK(acceptor.opened == 1, "the acceptor's z_open returned %d", acceptor.rc);
    CHECK(acceptor.published >= 1, "the acceptor never published");

    printf("pico-session-loopback: %d check(s), %d failure(s)\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
