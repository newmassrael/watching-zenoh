/*
 * SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * A single-threaded zenoh-pico C program on the cooperative engine: the program owns the only
 * thread there is and steps its session from its own loop (`zp_read`, `zp_send_keep_alive`,
 * `zp_spin_once`), so every callback runs on that thread, inside one of those calls. It is
 * compiled against zenoh-pico's own headers for the library's single-threaded arm
 * (`Z_FEATURE_MULTI_THREAD 0`) and linked against the wz library built on the cooperative engine
 * in place of libzenohpico.
 *
 * One session per process: a session that dials waits in `z_open` for the far end's answer,
 * which a second session of the same single thread could never give, so the program is run
 * twice, as two processes on one port:
 *
 *   pico_coop_single_thread listen <port>   a listening session on tcp/127.0.0.1:<port> with a
 *                                           subscriber that counts the puts it is handed and a
 *                                           queryable that answers how many it has counted
 *   pico_coop_single_thread dial <port>     a client of that session that puts, steps, and gets
 *                                           until the answer says a put arrived, then closes
 *
 * Exit status 0 means every check of the role held; the last line printed is the count either
 * way. Each role gives up after a bound of its own, so a run never hangs its caller.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zenoh-pico.h>

#if Z_FEATURE_MULTI_THREAD == 0 && Z_FEATURE_PUBLICATION == 1 && Z_FEATURE_SUBSCRIPTION == 1 && \
    Z_FEATURE_QUERY == 1 && Z_FEATURE_QUERYABLE == 1

#define PUT_KEY "wz/coop/single/put"
#define GET_KEY "wz/coop/single/get"
#define PUT_PAYLOAD "coop-single-thread-put"
/* How long a role may run before it gives up, and how long the listener goes on stepping after
 * its answer so that the reply and the end of the query leave before it closes. */
#define ROLE_BOUND_MS 30000ul
#define LISTEN_TAIL_MS 2000ul

static const char *role = "?";
static int checks = 0;
static int failures = 0;

#define CHECK(cond, ...)                                                       \
    do {                                                                       \
        checks++;                                                              \
        if (!(cond)) {                                                         \
            failures++;                                                        \
            printf("pico-coop-single-thread %s: FAIL at line %d: ", role, __LINE__); \
            printf(__VA_ARGS__);                                               \
            printf("\n");                                                      \
        }                                                                      \
    } while (0)

/* One turn of the program's own loop over its session: read what arrived (callbacks run here),
 * keep the lease, and run what is due. A closed session is the loop's end. */
static int step(const z_owned_session_t *s) {
    if (zp_read(z_session_loan(s), NULL) < 0) return 0;
    if (zp_send_keep_alive(z_session_loan(s), NULL) < 0) return 0;
    return zp_spin_once(z_session_loan(s)) ? 1 : 0;
}

/* ---- the listening role ------------------------------------------------------------------- */

typedef struct {
    int received;
    int payload_ok;
    int answered;
    int answered_after_put;
} listener_t;

static void on_put(z_loaned_sample_t *sample, void *arg) {
    listener_t *l = (listener_t *)arg;
    z_owned_string_t value;
    z_bytes_to_string(z_sample_payload(sample), &value);
    size_t len = z_string_len(z_string_loan(&value));
    if (len == strlen(PUT_PAYLOAD) && memcmp(z_string_data(z_string_loan(&value)), PUT_PAYLOAD, len) == 0) {
        l->payload_ok = 1;
    }
    z_string_drop(z_string_move(&value));
    l->received++;
}

static void on_query(z_loaned_query_t *query, void *arg) {
    listener_t *l = (listener_t *)arg;
    char answer[32];
    snprintf(answer, sizeof answer, "seen=%d", l->received);
    z_owned_bytes_t payload;
    z_bytes_copy_from_str(&payload, answer);
    if (z_query_reply(query, z_query_keyexpr(query), z_bytes_move(&payload), NULL) == Z_OK) {
        l->answered++;
        if (l->received > 0) l->answered_after_put = 1;
    }
}

static void run_listener(const char *locator) {
    listener_t l;
    memset(&l, 0, sizeof l);

    z_owned_config_t config;
    z_config_default(&config);
    zp_config_insert(z_config_loan_mut(&config), Z_CONFIG_LISTEN_KEY, locator);
    z_owned_session_t s;
    z_result_t opened = z_open(&s, z_config_move(&config), NULL);
    CHECK(opened == Z_OK, "the listening session did not open on %s (rc %d)", locator, (int)opened);
    if (opened != Z_OK) return;

    z_view_keyexpr_t put_ke;
    z_view_keyexpr_t get_ke;
    z_view_keyexpr_from_str(&put_ke, PUT_KEY);
    z_view_keyexpr_from_str(&get_ke, GET_KEY);
    z_owned_closure_sample_t on_sample;
    z_closure_sample(&on_sample, on_put, NULL, &l);
    z_owned_subscriber_t sub;
    CHECK(z_declare_subscriber(z_session_loan(&s), &sub, z_view_keyexpr_loan(&put_ke),
                               z_closure_sample_move(&on_sample), NULL) == Z_OK,
          "z_declare_subscriber");
    z_owned_closure_query_t on_q;
    z_closure_query(&on_q, on_query, NULL, &l);
    z_owned_queryable_t qable;
    CHECK(z_declare_queryable(z_session_loan(&s), &qable, z_view_keyexpr_loan(&get_ke),
                              z_closure_query_move(&on_q), NULL) == Z_OK,
          "z_declare_queryable");

    z_clock_t started = z_clock_now();
    z_clock_t answered_at = started;
    int alive = 1;
    while (alive && z_clock_elapsed_ms(&started) < ROLE_BOUND_MS) {
        if (!l.answered_after_put) answered_at = z_clock_now();
        else if (z_clock_elapsed_ms(&answered_at) >= LISTEN_TAIL_MS) break;
        alive = step(&s);
    }
    CHECK(alive, "the session ended under the program's loop");
    CHECK(l.received >= 1, "the subscriber was handed no put");
    CHECK(l.payload_ok, "no put carried the payload that was sent");
    CHECK(l.answered_after_put, "no query was answered after a put arrived (%d answered)", l.answered);

    z_queryable_drop(z_queryable_move(&qable));
    z_subscriber_drop(z_subscriber_move(&sub));
    CHECK(z_close(z_session_loan_mut(&s), NULL) == Z_OK, "z_close");
    z_session_drop(z_session_move(&s));
    printf("pico-coop-single-thread %s: %d put(s) received, %d quer(ies) answered\n", role, l.received,
           l.answered);
}

/* ---- the dialling role -------------------------------------------------------------------- */

typedef struct {
    int pending;
    int replies;
    int best_seen;
} dialer_t;

static void on_reply(z_loaned_reply_t *reply, void *arg) {
    dialer_t *d = (dialer_t *)arg;
    if (!z_reply_is_ok(reply)) return;
    z_owned_string_t value;
    z_bytes_to_string(z_sample_payload(z_reply_ok(reply)), &value);
    char text[32];
    size_t len = z_string_len(z_string_loan(&value));
    if (len < sizeof text) {
        memcpy(text, z_string_data(z_string_loan(&value)), len);
        text[len] = '\0';
        if (strncmp(text, "seen=", 5) == 0) {
            int seen = atoi(text + 5);
            if (seen > d->best_seen) d->best_seen = seen;
        }
    }
    z_string_drop(z_string_move(&value));
    d->replies++;
}

/* The end of a get: the next one may be asked. */
static void on_reply_end(void *arg) { ((dialer_t *)arg)->pending = 0; }

static void run_dialer(const char *locator) {
    dialer_t d;
    memset(&d, 0, sizeof d);

    /* The listener is another process, which may not be listening yet: a refused open is tried
     * again, as pico's examples are run against a router that starts on its own. */
    z_owned_session_t s;
    z_result_t opened = -1;
    for (int attempt = 0; attempt < 100 && opened != Z_OK; attempt++) {
        z_owned_config_t config;
        z_config_default(&config);
        zp_config_insert(z_config_loan_mut(&config), Z_CONFIG_MODE_KEY, "client");
        zp_config_insert(z_config_loan_mut(&config), Z_CONFIG_CONNECT_KEY, locator);
        opened = z_open(&s, z_config_move(&config), NULL);
        if (opened != Z_OK) z_sleep_ms(100);
    }
    CHECK(opened == Z_OK, "the dialling session did not open to %s (rc %d)", locator, (int)opened);
    if (opened != Z_OK) return;

    z_view_keyexpr_t put_ke;
    z_view_keyexpr_t get_ke;
    z_view_keyexpr_from_str(&put_ke, PUT_KEY);
    z_view_keyexpr_from_str(&get_ke, GET_KEY);

    int put_count = 0;
    int gets = 0;
    int put_failed = 0;
    int get_failed = 0;
    z_clock_t started = z_clock_now();
    z_clock_t last_put = started;
    int alive = 1;
    int first = 1;
    while (alive && d.best_seen < 1 && z_clock_elapsed_ms(&started) < ROLE_BOUND_MS) {
        /* A put every 200 ms until one is counted: the listener's subscriber may reach this
         * session's write filter a few steps after the open. */
        if (first || z_clock_elapsed_ms(&last_put) >= 200) {
            first = 0;
            last_put = z_clock_now();
            z_owned_bytes_t payload;
            z_bytes_copy_from_str(&payload, PUT_PAYLOAD);
            if (z_put(z_session_loan(&s), z_view_keyexpr_loan(&put_ke), z_bytes_move(&payload), NULL) == Z_OK) {
                put_count++;
            } else {
                put_failed++;
            }
        }
        /* One get at a time: the next is asked once the last has ended. */
        if (!d.pending) {
            z_owned_closure_reply_t callback;
            z_closure_reply(&callback, on_reply, on_reply_end, &d);
            d.pending = 1;
            if (z_get(z_session_loan(&s), z_view_keyexpr_loan(&get_ke), "", z_closure_reply_move(&callback), NULL) ==
                Z_OK) {
                gets++;
            } else {
                d.pending = 0;
                get_failed++;
            }
        }
        alive = step(&s);
    }
    CHECK(alive, "the session ended under the program's loop");
    CHECK(put_count >= 1, "no put was taken (%d refused)", put_failed);
    CHECK(get_failed == 0, "%d get(s) were refused", get_failed);
    CHECK(d.replies >= 1, "no reply came back to %d get(s)", gets);
    CHECK(d.best_seen >= 1, "no reply said a put had arrived (best %d)", d.best_seen);

    CHECK(z_close(z_session_loan_mut(&s), NULL) == Z_OK, "z_close");
    z_session_drop(z_session_move(&s));
    printf("pico-coop-single-thread %s: %d put(s), %d get(s), %d repl(ies), best seen %d\n", role, put_count, gets,
           d.replies, d.best_seen);
}

int main(int argc, char **argv) {
    /* Two processes write to one console: unbuffered, so the lines of each come out whole and
     * in the order they were written. */
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc != 3 || (strcmp(argv[1], "listen") != 0 && strcmp(argv[1], "dial") != 0)) {
        printf("usage: %s listen|dial <port>\n", argv[0]);
        return 2;
    }
    role = argv[1];
    int port = atoi(argv[2]);
    if (port <= 0 || port > 65535) {
        printf("pico-coop-single-thread: the port '%s' is not one\n", argv[2]);
        return 2;
    }
    char locator[64];
    snprintf(locator, sizeof locator, "tcp/127.0.0.1:%d", port);
    if (strcmp(role, "listen") == 0) {
        run_listener(locator);
    } else {
        run_dialer(locator);
    }
    printf("pico-coop-single-thread %s: %d check(s), %d failure(s)\n", role, checks, failures);
    return failures == 0 ? 0 : 1;
}

#else
int main(void) {
    printf(
        "pico-coop-single-thread: the library's header arm is not the single-threaded one with "
        "publication, subscription, query and queryable\n");
    return 2;
}
#endif
