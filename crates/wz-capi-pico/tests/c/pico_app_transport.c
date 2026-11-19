/*
 * SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * A zenoh-pico C program whose sessions open no socket: two sessions in one process,
 * one listening and one dialling, joined by an in-memory transport this program
 * implements through the wz extension doors (wz_ext_transport_*, wz_ext.h). Compiled
 * against zenoh-pico's OWN headers for this host plus wz_ext.h, linked against the wz
 * cdylib built with the app-transport capability.
 *
 * The program's transport hands every byte one side sends to the other side's
 * wz_ext_transport_received from inside send, and answers some sends of the dialling
 * side as a stack under load does: half of the bytes taken, or would-block with the
 * link reported writable again before the answer is returned. The handshake still
 * completes, a put reaches the subscriber, a sequence arrives whole and in order, a
 * query gets its reply, and both transports' drop runs once at the end.
 *
 * Exit status 0 means every check held; the last line printed is the count either way.
 */

#include <stdio.h>
#include <string.h>

#include <zenoh-pico.h>

#include "wz_ext.h"

#define LISTEN "tcp/192.0.2.100:7447"
#define ACCEPTED_REMOTE "tcp/192.0.2.200:41000"
#define SEQUENCE 30
#define MAX_PAIRS 8

static int checks = 0;
static int failures = 0;

#define CHECK(cond, ...)                                                \
    do {                                                                \
        checks++;                                                       \
        if (!(cond)) {                                                  \
            failures++;                                                 \
            printf("pico-app-transport: FAIL at line %d: ", __LINE__);  \
            printf(__VA_ARGS__);                                        \
            printf("\n");                                               \
        }                                                               \
    } while (0)

enum { LISTENING = 0, DIALLING = 1 };

/* The pipe: both transports, the listening side's listener, the paired links and what
 * the pipe saw. Every field is under `lock`: the sessions call in from their threads. */
static struct {
    z_owned_mutex_t lock;
    wz_ext_owned_transport_t transport[2];
    int side_id[2];
    wz_ext_link_t listener;
    struct {
        int used;
        wz_ext_link_t link[2];
    } pairs[MAX_PAIRS];
    int dials;
    int dialler_sends;
    int partials;
    int blocks;
    int closes;
    int drops;
} pipe_state;

static void pipe_lock(void) { z_mutex_lock(z_mutex_loan_mut(&pipe_state.lock)); }
static void pipe_unlock(void) { z_mutex_unlock(z_mutex_loan_mut(&pipe_state.lock)); }

static const wz_ext_loaned_transport_t *loan_of(int side) {
    return wz_ext_transport_loan(&pipe_state.transport[side]);
}

/* The link paired with `link` of `side`, or 0. Called with the lock held. */
static wz_ext_link_t peer_of(int side, wz_ext_link_t link) {
    for (int i = 0; i < MAX_PAIRS; i++) {
        if (pipe_state.pairs[i].used && pipe_state.pairs[i].link[side] == link) {
            return pipe_state.pairs[i].link[1 - side];
        }
    }
    return 0;
}

static int read_counter(const int *counter) {
    pipe_lock();
    int value = *counter;
    pipe_unlock();
    return value;
}

static wz_ext_link_result_t on_open(void *context, wz_ext_link_t link, wz_ext_link_kind_t kind,
                                    const char *locator) {
    int side = *(int *)context;
    if (strcmp(locator, LISTEN) != 0) return WZ_EXT_LINK_FAILED;
    if (side == LISTENING && kind == WZ_EXT_LINK_STREAM_LISTEN) {
        pipe_lock();
        pipe_state.listener = link;
        pipe_unlock();
        return WZ_EXT_LINK_OK;
    }
    if (side == DIALLING && kind == WZ_EXT_LINK_STREAM_DIAL) {
        pipe_lock();
        wz_ext_link_t listener = pipe_state.listener;
        pipe_unlock();
        /* The listening program accepts the stream; the two links are paired before the
         * dial is answered up, so neither side sends into nothing. */
        wz_ext_link_t accepted = 0;
        if (wz_ext_transport_accepted(loan_of(LISTENING), listener, ACCEPTED_REMOTE, &accepted) != Z_OK) {
            return WZ_EXT_LINK_FAILED;
        }
        pipe_lock();
        pipe_state.dials++;
        for (int i = 0; i < MAX_PAIRS; i++) {
            if (!pipe_state.pairs[i].used) {
                pipe_state.pairs[i].used = 1;
                pipe_state.pairs[i].link[DIALLING] = link;
                pipe_state.pairs[i].link[LISTENING] = accepted;
                break;
            }
        }
        pipe_unlock();
        return WZ_EXT_LINK_OK;
    }
    return WZ_EXT_LINK_FAILED;
}

static wz_ext_link_result_t on_send(void *context, wz_ext_link_t link, const uint8_t *data, size_t len,
                                    size_t *written) {
    int side = *(int *)context;
    size_t take = len;
    pipe_lock();
    wz_ext_link_t peer = peer_of(side, link);
    int fault = 0; /* 1 would-block, 2 partial */
    if (peer != 0 && side == DIALLING) {
        int n = pipe_state.dialler_sends++;
        if (n % 7 == 3) {
            fault = 1;
            pipe_state.blocks++;
        } else if (n % 5 == 1 && len > 1) {
            fault = 2;
            pipe_state.partials++;
        }
    }
    pipe_unlock();
    if (peer == 0) return WZ_EXT_LINK_CLOSED;
    if (fault == 1) {
        /* Writable before the would-block is even answered: the session sends again. */
        wz_ext_transport_event(loan_of(DIALLING), link, WZ_EXT_LINK_EVENT_WRITABLE);
        return WZ_EXT_LINK_WOULD_BLOCK;
    }
    if (fault == 2) take = len / 2;
    if (wz_ext_transport_received(loan_of(1 - side), peer, data, take, NULL) != Z_OK) {
        return WZ_EXT_LINK_CLOSED;
    }
    *written = take;
    return WZ_EXT_LINK_OK;
}

static void on_close(void *context, wz_ext_link_t link) {
    int side = *(int *)context;
    wz_ext_link_t peer = 0;
    pipe_lock();
    pipe_state.closes++;
    for (int i = 0; i < MAX_PAIRS; i++) {
        if (pipe_state.pairs[i].used && pipe_state.pairs[i].link[side] == link) {
            peer = pipe_state.pairs[i].link[1 - side];
            pipe_state.pairs[i].used = 0;
        }
    }
    pipe_unlock();
    /* The other end hears the close, from inside this close. */
    if (peer != 0) wz_ext_transport_event(loan_of(1 - side), peer, WZ_EXT_LINK_EVENT_CLOSED);
}

static void on_drop(void *context) {
    (void)context;
    pipe_lock();
    pipe_state.drops++;
    pipe_unlock();
}

/* What the listening side's subscriber was handed, in order. */
static struct {
    z_owned_mutex_t lock;
    int count;
    char last[64];
    int in_order;
    int next_seq;
} heard;

static void on_sample(z_loaned_sample_t *sample, void *arg) {
    (void)arg;
    z_owned_string_t value;
    z_bytes_to_string(z_sample_payload(sample), &value);
    size_t len = z_string_len(z_string_loan(&value));
    char text[64] = {0};
    if (len < sizeof text) memcpy(text, z_string_data(z_string_loan(&value)), len);
    z_string_drop(z_string_move(&value));
    z_mutex_lock(z_mutex_loan_mut(&heard.lock));
    heard.count++;
    memcpy(heard.last, text, sizeof text);
    int seq = -1;
    if (sscanf(text, "seq-%d", &seq) == 1) {
        if (seq != heard.next_seq) heard.in_order = 0;
        heard.next_seq = seq + 1;
    }
    z_mutex_unlock(z_mutex_loan_mut(&heard.lock));
}

static void on_query(z_loaned_query_t *query, void *arg) {
    (void)arg;
    z_owned_bytes_t payload;
    z_bytes_copy_from_str(&payload, "answer-over-the-pipe");
    z_query_reply(query, z_query_keyexpr(query), z_bytes_move(&payload), NULL);
}

static struct {
    volatile int replies;
    volatile int done;
    char payload[64];
} asked;

static void on_reply(z_loaned_reply_t *reply, void *arg) {
    (void)arg;
    if (!z_reply_is_ok(reply)) return;
    z_owned_string_t value;
    z_bytes_to_string(z_sample_payload(z_reply_ok(reply)), &value);
    size_t len = z_string_len(z_string_loan(&value));
    if (len < sizeof asked.payload) {
        memcpy(asked.payload, z_string_data(z_string_loan(&value)), len);
        asked.payload[len] = '\0';
    }
    z_string_drop(z_string_move(&value));
    asked.replies++;
}

static void on_reply_drop(void *arg) {
    (void)arg;
    asked.done = 1;
}

static int heard_count(void) {
    z_mutex_lock(z_mutex_loan_mut(&heard.lock));
    int n = heard.count;
    z_mutex_unlock(z_mutex_loan_mut(&heard.lock));
    return n;
}

static void put(const z_loaned_session_t *session, const char *key, const char *text) {
    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, key);
    z_owned_bytes_t payload;
    z_bytes_copy_from_str(&payload, text);
    z_put(session, z_view_keyexpr_loan(&ke), z_bytes_move(&payload), NULL);
}

int main(void) {
    memset(&pipe_state, 0, sizeof pipe_state);
    memset(&heard, 0, sizeof heard);
    heard.in_order = 1;
    CHECK(z_mutex_init(&pipe_state.lock) == Z_OK, "z_mutex_init for the pipe");
    CHECK(z_mutex_init(&heard.lock) == Z_OK, "z_mutex_init for the subscriber");

    for (int side = 0; side < 2; side++) {
        pipe_state.side_id[side] = side;
        wz_ext_transport_t calls;
        calls.context = &pipe_state.side_id[side];
        calls.open = on_open;
        calls.send = on_send;
        calls.close = on_close;
        calls.drop = on_drop;
        CHECK(wz_ext_transport_new(&pipe_state.transport[side], &calls) == Z_OK, "wz_ext_transport_new");
    }

    /* The listening session: its open is its listener's, which the program answers up. */
    z_owned_config_t config;
    z_config_default(&config);
    zp_config_insert(z_config_loan_mut(&config), Z_CONFIG_LISTEN_KEY, LISTEN);
    CHECK(wz_ext_config_transport(z_config_loan_mut(&config), loan_of(LISTENING)) == Z_OK,
          "wz_ext_config_transport (listening)");
    z_owned_session_t listening;
    int rc = z_open(&listening, z_config_move(&config), NULL);
    CHECK(rc == Z_OK, "the listening session opened (rc %d)", rc);
    if (rc != Z_OK) goto done;

    z_owned_closure_sample_t sample_closure;
    z_closure_sample(&sample_closure, on_sample, NULL, NULL);
    z_view_keyexpr_t sub_ke;
    z_view_keyexpr_from_str(&sub_ke, "demo/pipe/**");
    z_owned_subscriber_t subscriber;
    CHECK(z_declare_subscriber(z_session_loan(&listening), &subscriber, z_view_keyexpr_loan(&sub_ke),
                               z_closure_sample_move(&sample_closure), NULL) == Z_OK,
          "z_declare_subscriber");

    z_owned_closure_query_t query_closure;
    z_closure_query(&query_closure, on_query, NULL, NULL);
    z_view_keyexpr_t qbl_ke;
    z_view_keyexpr_from_str(&qbl_ke, "demo/ask");
    z_owned_queryable_t queryable;
    CHECK(z_declare_queryable(z_session_loan(&listening), &queryable, z_view_keyexpr_loan(&qbl_ke),
                              z_closure_query_move(&query_closure), NULL) == Z_OK,
          "z_declare_queryable");

    /* The dialling session: z_open runs the handshake over the pipe, through the faults
     * the pipe injects from the first byte on. */
    z_config_default(&config);
    zp_config_insert(z_config_loan_mut(&config), Z_CONFIG_CONNECT_KEY, LISTEN);
    CHECK(wz_ext_config_transport(z_config_loan_mut(&config), loan_of(DIALLING)) == Z_OK,
          "wz_ext_config_transport (dialling)");
    z_owned_session_t dialling;
    rc = z_open(&dialling, z_config_move(&config), NULL);
    CHECK(rc == Z_OK, "the dialling session opened over the program's transport (rc %d)", rc);
    if (rc == Z_OK) {
        /* A put reaches the subscriber once its declaration has. */
        for (int i = 0; i < 500 && heard_count() == 0; i++) {
            put(z_session_loan(&dialling), "demo/pipe/probe", "probe");
            z_sleep_ms(20);
        }
        CHECK(heard_count() > 0, "the subscriber was never handed a put");

        /* A sequence arrives whole and in order. */
        z_mutex_lock(z_mutex_loan_mut(&heard.lock));
        int before = heard.count;
        heard.next_seq = 0;
        heard.in_order = 1;
        z_mutex_unlock(z_mutex_loan_mut(&heard.lock));
        char text[32];
        for (int n = 0; n < SEQUENCE; n++) {
            snprintf(text, sizeof text, "seq-%d", n);
            put(z_session_loan(&dialling), "demo/pipe/seq", text);
        }
        for (int i = 0; i < 1000 && heard_count() < before + SEQUENCE; i++) z_sleep_ms(10);
        z_mutex_lock(z_mutex_loan_mut(&heard.lock));
        int got = heard.count - before;
        int in_order = heard.in_order;
        int next = heard.next_seq;
        z_mutex_unlock(z_mutex_loan_mut(&heard.lock));
        CHECK(got >= SEQUENCE, "%d of %d puts of the sequence arrived", got, SEQUENCE);
        CHECK(in_order && next == SEQUENCE, "the sequence arrived out of order (next %d)", next);
        CHECK(read_counter(&pipe_state.partials) > 0, "no partial send was injected");
        CHECK(read_counter(&pipe_state.blocks) > 0, "no would-block was injected");

        /* A query gets its reply. */
        z_owned_closure_reply_t reply_closure;
        z_closure_reply(&reply_closure, on_reply, on_reply_drop, NULL);
        z_view_keyexpr_t get_ke;
        z_view_keyexpr_from_str(&get_ke, "demo/ask");
        z_get_options_t opts;
        z_get_options_default(&opts);
        opts.timeout_ms = 5000;
        CHECK(z_get(z_session_loan(&dialling), z_view_keyexpr_loan(&get_ke), "", z_closure_reply_move(&reply_closure),
                    &opts) == Z_OK,
              "z_get");
        for (int i = 0; i < 1000 && !asked.done; i++) z_sleep_ms(10);
        CHECK(asked.done, "the get never completed");
        CHECK(asked.replies == 1, "the get had %d replies", asked.replies);
        CHECK(strcmp(asked.payload, "answer-over-the-pipe") == 0, "the reply was '%s'", asked.payload);

        z_close(z_session_loan_mut(&dialling), NULL);
        z_session_drop(z_session_move(&dialling));
    }
    CHECK(read_counter(&pipe_state.dials) == 1, "the dialling session dialled %d times", read_counter(&pipe_state.dials));

    z_subscriber_drop(z_subscriber_move(&subscriber));
    z_queryable_drop(z_queryable_move(&queryable));
    z_close(z_session_loan_mut(&listening), NULL);
    z_session_drop(z_session_move(&listening));

done:
    for (int side = 0; side < 2; side++) wz_ext_transport_drop(wz_ext_transport_move(&pipe_state.transport[side]));
    /* Each transport's drop runs once, when the sessions and the program have let go. */
    for (int i = 0; i < 1000 && read_counter(&pipe_state.drops) < 2; i++) z_sleep_ms(10);
    CHECK(read_counter(&pipe_state.drops) == 2, "%d of the two transports dropped", read_counter(&pipe_state.drops));
    CHECK(read_counter(&pipe_state.closes) > 0, "the sessions closed no link on the program");

    printf("pico-app-transport: %d check(s), %d failure(s)\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
