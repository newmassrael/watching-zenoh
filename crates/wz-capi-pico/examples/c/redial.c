/*
 * SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * A client whose link is lost dials it again by itself, and what it publishes and what it
 * subscribed to go on over the new link with nothing done by the program: the session is the
 * program's, a link is only one connection of it, as zenoh-pico's client reopens its session
 * (Z_FEATURE_AUTO_RECONNECT, once every 1000 ms while the reopen fails).
 *
 *   linked     a node listens on the loopback and a client dials it; each subscribes to what
 *              the other puts, and each hears the other;
 *   lost       the node closes: the client lists no peer, and its session is not closed;
 *   back       a NEW node (another zid) listens on the same port; the client lists it, its put
 *              reaches the new node's subscriber, and the subscriber it declared once, before
 *              the loss, hears what the new node puts.
 *
 * The program never opens the client again: the only link to the new node is one the client's
 * own redial made, and the new node never saw the first declaration, so what it hears and what
 * the client hears both came over the redialled link.
 */

#define EXAMPLE_NAME "example-redial"

#include <zenoh-pico.h>

#include "example_common.h"

#define TO_LISTENER "example/redial/to-listener"
#define TO_DIALER "example/redial/to-dialer"

/* How long the client may take to see the node go: a closing node tells it at once, and the
 * lease the client holds the link to (Z_TRANSPORT_LEASE) is the bound when that word is lost. */
#define LOSS_MS 20000
/* How long the redial may take once the new node listens: a redial period, after a dial made
 * while nobody held the port, which a host may be slow to refuse. */
#define REDIAL_MS 30000

/* What the client hears on TO_DIALER, over the first link and the second. */
static ex_counter_t at_dialer;

static void on_sample(z_loaned_sample_t *sample, void *arg) {
    (void)sample;
    ex_counter_add((ex_counter_t *)arg, 1);
}

typedef struct {
    int count;
    z_id_t last;
} peers_t;

static void on_peer(const z_id_t *id, void *arg) {
    peers_t *peers = (peers_t *)arg;
    peers->count++;
    peers->last = *id;
}

/* The peers `session` lists now; z_info_peers_zid calls back before it returns. */
static peers_t peers_of(const z_loaned_session_t *session) {
    peers_t peers;
    memset(&peers, 0, sizeof peers);
    z_owned_closure_zid_t closure;
    z_closure_zid(&closure, on_peer, NULL, &peers);
    z_info_peers_zid(session, z_closure_zid_move(&closure));
    return peers;
}

static int same_id(const z_id_t *a, const z_id_t *b) { return memcmp(a->id, b->id, sizeof a->id) == 0; }

/* Wait until `session` lists exactly `want` peers, for at most `ms`; what it lists last. */
static peers_t wait_for_peers(const z_loaned_session_t *session, int want, int ms) {
    peers_t peers = peers_of(session);
    for (int waited = 0; waited < ms && peers.count != want; waited += 10) {
        z_sleep_ms(10);
        peers = peers_of(session);
    }
    return peers;
}

/* Put `key` from `from` until `heard` passes `above`; whether it did. */
static int put_until_heard(const z_loaned_session_t *from, const char *key, ex_counter_t *heard, int above) {
    for (int i = 0; i < 400 && ex_counter_get(heard) <= above; i++) {
        ex_put(from, key, "over-the-link", NULL);
        z_sleep_ms(25);
    }
    return ex_counter_get(heard) > above;
}

static z_result_t subscribe(const z_loaned_session_t *session, z_owned_subscriber_t *subscriber, const char *key,
                            ex_counter_t *heard) {
    z_owned_closure_sample_t closure;
    z_closure_sample(&closure, on_sample, NULL, heard);
    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, key);
    return z_declare_subscriber(session, subscriber, z_view_keyexpr_loan(&ke), z_closure_sample_move(&closure),
                                NULL);
}

/* The node again on `locator`, retried while the port the closed node held is let go. */
static z_result_t open_listener_again(z_owned_session_t *session, const char *locator) {
    z_result_t rc = ex_open_listener(session, locator);
    for (int attempt = 0; attempt < 100 && rc != Z_OK; attempt++) {
        z_sleep_ms(100);
        rc = ex_open_listener(session, locator);
    }
    return rc;
}

int main(void) {
    ex_counter_init(&at_dialer);
    ex_counter_t at_first;
    ex_counter_init(&at_first);
    ex_counter_t at_second;
    ex_counter_init(&at_second);

    char locator[64];
    snprintf(locator, sizeof locator, "tcp/127.0.0.1:%u", ex_port());
    printf("%s: %s\n", EXAMPLE_NAME, locator);

    /* linked */
    z_owned_session_t first;
    z_result_t rc = ex_open_listener(&first, locator);
    CHECK(rc == Z_OK, "the first node did not open on %s (rc %d)", locator, (int)rc);
    if (rc != Z_OK) return ex_finish();
    z_id_t first_id = z_info_zid(z_session_loan(&first));
    z_owned_subscriber_t first_sub;
    CHECK(subscribe(z_session_loan(&first), &first_sub, TO_LISTENER, &at_first) == Z_OK,
          "the first node's z_declare_subscriber");

    z_owned_session_t dialer;
    rc = ex_open_dialer(&dialer, locator);
    CHECK(rc == Z_OK, "the client did not open to %s (rc %d)", locator, (int)rc);
    if (rc != Z_OK) {
        z_subscriber_drop(z_subscriber_move(&first_sub));
        ex_close(&first);
        return ex_finish();
    }
    const z_loaned_session_t *client = z_session_loan(&dialer);
    z_owned_subscriber_t dialer_sub;
    CHECK(subscribe(client, &dialer_sub, TO_DIALER, &at_dialer) == Z_OK, "the client's z_declare_subscriber");

    peers_t peers = wait_for_peers(client, 1, 5000);
    CHECK(peers.count == 1 && same_id(&peers.last, &first_id), "the client lists %d peer(s), not the first node",
          peers.count);
    CHECK(put_until_heard(client, TO_LISTENER, &at_first, 0), "linked: the first node never heard the client");
    CHECK(put_until_heard(z_session_loan(&first), TO_DIALER, &at_dialer, 0),
          "linked: the client never heard the first node");

    /* lost */
    z_subscriber_drop(z_subscriber_move(&first_sub));
    ex_close(&first);
    peers = wait_for_peers(client, 0, LOSS_MS);
    CHECK(peers.count == 0, "lost: the client still lists %d peer(s) after the node closed", peers.count);
    CHECK(!z_session_is_closed(client), "lost: the client's session ended with its link");
    int heard_before = ex_counter_get(&at_dialer);

    /* back */
    z_owned_session_t second;
    rc = open_listener_again(&second, locator);
    CHECK(rc == Z_OK, "the new node did not open on %s (rc %d)", locator, (int)rc);
    if (rc == Z_OK) {
        z_id_t second_id = z_info_zid(z_session_loan(&second));
        CHECK(!same_id(&second_id, &first_id), "the new node opened on the first node's zid");
        z_owned_subscriber_t second_sub;
        CHECK(subscribe(z_session_loan(&second), &second_sub, TO_LISTENER, &at_second) == Z_OK,
              "the new node's z_declare_subscriber");

        peers = wait_for_peers(client, 1, REDIAL_MS);
        CHECK(peers.count == 1 && same_id(&peers.last, &second_id),
              "back: the client lists %d peer(s), not the new node: it did not dial again", peers.count);
        CHECK(!z_session_is_closed(client), "back: the client's session is closed");
        CHECK(put_until_heard(client, TO_LISTENER, &at_second, 0),
              "back: the new node never heard the client's put over the redialled link");
        CHECK(put_until_heard(z_session_loan(&second), TO_DIALER, &at_dialer, heard_before),
              "back: the subscriber the client declared before the loss never heard the new node");

        z_subscriber_drop(z_subscriber_move(&second_sub));
        ex_close(&second);
    }

    z_subscriber_drop(z_subscriber_move(&dialer_sub));
    ex_close(&dialer);
    ex_counter_drop(&at_dialer);
    ex_counter_drop(&at_first);
    ex_counter_drop(&at_second);
    return ex_finish();
}
