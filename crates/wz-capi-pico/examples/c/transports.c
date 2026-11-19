/*
 * SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * The three transport configs over the operating system's sockets: a put to a subscriber
 * and a query to its reply on each.
 *
 *   tcp/  a stream pair: one session listens on the loopback, a client dials it;
 *   udp/  a datagram pair: one session listens for datagrams, a client sends to it;
 *   udp/ with #iface=, a group: two peers join one multicast group.
 *
 * The group needs an interface the host carries multicast on, which differs by host (the
 * loopback on Linux, the default adapter on Windows, where the loopback adapter does not
 * carry a group). The program takes it from WZ_EXAMPLE_GROUP_IFACE, in the form #iface=
 * reads on that host; without it the group is not joined and the program says so.
 *
 * The same three configs over a transport the program supplies, with no socket of the
 * system's, are the program tests/c/pico_app_transport.c: it builds against the library
 * with the app-transport capability and carries the same exchange over a stream pair, a
 * datagram pair and a two-member group of its own.
 */

#define EXAMPLE_NAME "example-transports"

#include <zenoh-pico.h>

#include "example_common.h"

static ex_counter_t heard;
static ex_counter_t replies;
static volatile int reply_done;
static char reply_text[64];

static void on_sample(z_loaned_sample_t *sample, void *arg) {
    (void)sample;
    (void)arg;
    ex_counter_add(&heard, 1);
}

static void on_query(z_loaned_query_t *query, void *arg) {
    (void)arg;
    z_owned_bytes_t payload;
    z_bytes_copy_from_str(&payload, "answer-over-the-link");
    z_query_reply(query, z_query_keyexpr(query), z_bytes_move(&payload), NULL);
}

static void on_reply(z_loaned_reply_t *reply, void *arg) {
    (void)arg;
    if (!z_reply_is_ok(reply)) return;
    ex_payload_text(z_sample_payload(z_reply_ok(reply)), reply_text, sizeof reply_text);
    ex_counter_add(&replies, 1);
}

static void on_reply_drop(void *arg) {
    (void)arg;
    reply_done = 1;
}

static void on_peer(const z_id_t *id, void *arg) {
    (void)id;
    (*(int *)arg)++;
}

/* Wait until `session` knows a peer, as z_info_peers_zid lists them; 1 when it does. A group
 * member knows another only from the other's JOIN, which zenoh-pico sends every
 * Z_JOIN_INTERVAL (2500 ms by default) and not in answer to a new member's own, and a get
 * a session asks while it knows no peer completes at once with no reply
 * (src/net/primitives.c, _z_query: remaining_finals == 0). A client of a pair knows its
 * peer from its open, so this returns at once there. */
static int wait_for_peer(const z_loaned_session_t *session) {
    for (int i = 0; i < 1000; i++) {
        int peers = 0;
        z_owned_closure_zid_t closure;
        z_closure_zid(&closure, on_peer, NULL, &peers);
        z_info_peers_zid(session, z_closure_zid_move(&closure));
        if (peers > 0) return 1;
        z_sleep_ms(10);
    }
    return 0;
}

static int ask(const z_loaned_session_t *session) {
    for (int attempt = 0; attempt < 15; attempt++) {
        reply_done = 0;
        z_owned_closure_reply_t closure;
        z_closure_reply(&closure, on_reply, on_reply_drop, NULL);
        z_view_keyexpr_t ke;
        z_view_keyexpr_from_str(&ke, "example/transports/ask");
        z_get_options_t options;
        z_get_options_default(&options);
        options.timeout_ms = 1000;
        if (z_get(session, z_view_keyexpr_loan(&ke), "", z_closure_reply_move(&closure), &options) != Z_OK) {
            return 0;
        }
        for (int i = 0; i < 500 && !reply_done; i++) z_sleep_ms(10);
        if (ex_counter_get(&replies) > 0) return 1;
        /* A get that found no target completed at once; the next is asked after a pause. */
        z_sleep_ms(200);
    }
    return 0;
}

/* The answering side's entities, on `one`; the put and the get go from `two`. */
static void exchange(const char *what, z_owned_session_t *one, z_owned_session_t *two) {
    ex_counter_init(&heard);
    ex_counter_init(&replies);
    reply_text[0] = '\0';

    z_owned_closure_sample_t sample_closure;
    z_closure_sample(&sample_closure, on_sample, NULL, NULL);
    z_view_keyexpr_t sub_ke;
    z_view_keyexpr_from_str(&sub_ke, "example/transports/data");
    z_owned_subscriber_t subscriber;
    CHECK(z_declare_subscriber(z_session_loan(one), &subscriber, z_view_keyexpr_loan(&sub_ke),
                               z_closure_sample_move(&sample_closure), NULL) == Z_OK,
          "%s: z_declare_subscriber", what);
    z_owned_closure_query_t query_closure;
    z_closure_query(&query_closure, on_query, NULL, NULL);
    z_view_keyexpr_t qbl_ke;
    z_view_keyexpr_from_str(&qbl_ke, "example/transports/ask");
    z_owned_queryable_t queryable;
    CHECK(z_declare_queryable(z_session_loan(one), &queryable, z_view_keyexpr_loan(&qbl_ke),
                              z_closure_query_move(&query_closure), NULL) == Z_OK,
          "%s: z_declare_queryable", what);

    for (int i = 0; i < 400 && ex_counter_get(&heard) == 0; i++) {
        ex_put(z_session_loan(two), "example/transports/data", "over-the-link", NULL);
        z_sleep_ms(25);
    }
    CHECK(ex_counter_get(&heard) > 0, "%s: the subscriber was never handed a put", what);
    CHECK(wait_for_peer(z_session_loan(two)), "%s: the asking session never knew a peer", what);
    CHECK(ask(z_session_loan(two)), "%s: no get was answered", what);
    CHECK(strcmp(reply_text, "answer-over-the-link") == 0, "%s: the reply was '%s'", what, reply_text);

    z_subscriber_drop(z_subscriber_move(&subscriber));
    z_queryable_drop(z_queryable_move(&queryable));
    ex_counter_drop(&heard);
    ex_counter_drop(&replies);
}

/* A listener on `scheme`/127.0.0.1 and a client dialling it. */
static void run_pair(const char *scheme) {
    char locator[64];
    snprintf(locator, sizeof locator, "%s/127.0.0.1:%u", scheme, ex_port());
    printf("%s: %s\n", EXAMPLE_NAME, locator);
    z_owned_session_t one;
    z_owned_session_t two;
    z_result_t rc = ex_open_listener(&one, locator);
    CHECK(rc == Z_OK, "%s: the listener did not open (rc %d)", locator, (int)rc);
    if (rc != Z_OK) return;
    rc = ex_open_dialer(&two, locator);
    CHECK(rc == Z_OK, "%s: the client did not open (rc %d)", locator, (int)rc);
    if (rc == Z_OK) {
        exchange(locator, &one, &two);
        ex_close(&two);
    }
    ex_close(&one);
}

/* Two peers in one multicast group on the interface `iface`. */
static void run_group(const char *iface) {
    char locator[96];
    snprintf(locator, sizeof locator, "udp/224.0.0.224:%u#iface=%s", ex_port(), iface);
    printf("%s: %s\n", EXAMPLE_NAME, locator);
    z_owned_session_t one;
    z_owned_session_t two;
    z_result_t rc = ex_open_member(&one, locator);
    CHECK(rc == Z_OK, "%s: the first member did not join (rc %d)", locator, (int)rc);
    if (rc != Z_OK) return;
    rc = ex_open_member(&two, locator);
    CHECK(rc == Z_OK, "%s: the second member did not join (rc %d)", locator, (int)rc);
    if (rc == Z_OK) {
        exchange(locator, &one, &two);
        ex_close(&two);
    }
    ex_close(&one);
}

int main(void) {
    run_pair("tcp");
    run_pair("udp");
    const char *iface = getenv("WZ_EXAMPLE_GROUP_IFACE");
    if (iface != NULL && iface[0] != '\0') {
        run_group(iface);
    } else {
        printf("%s: the group was not joined: WZ_EXAMPLE_GROUP_IFACE names no interface\n", EXAMPLE_NAME);
    }
    return ex_finish();
}
