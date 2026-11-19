/*
 * SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * A zenoh-pico C program whose sessions open no socket: two sessions in one process
 * joined by an in-memory transport this program implements through the wz extension
 * doors (wz_ext_transport_*, wz_ext.h). Compiled against zenoh-pico's OWN headers for
 * this host plus wz_ext.h, linked against the wz cdylib built with the app-transport
 * capability.
 *
 * Three joins, each carrying a put to a subscriber and a query to its reply:
 *   - a stream pair (tcp/): one session listens, the other dials; the dialling side's
 *     sends are answered as a stack under load answers them, half of the bytes taken,
 *     or would-block with the link reported writable before the answer returns, and a
 *     sequence of puts still arrives whole and in order;
 *   - a datagram pair (udp/): one session listens for datagrams and the program accepts
 *     the other's source on it; each datagram crosses whole, with its source;
 *   - a two-member group (udp/ with an interface): each session joins, and the program
 *     hands each member's datagrams to the other with the member's address.
 * Each transport's drop runs once at the end of each join.
 *
 * Exit status 0 means every check held; the last line printed is the count either way.
 */

#include <stdio.h>
#include <string.h>

#include <zenoh-pico.h>

#include "wz_ext.h"

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

/* The addresses each side is known by. Synthetic: no socket is opened for any. */
static const char *const DATAGRAM_SOURCE[2] = {"udp/192.0.2.100:7447", "udp/192.0.2.200:41000"};
static const char *const MEMBER_SOURCE[2] = {"udp/192.0.2.1:7447", "udp/192.0.2.2:7447"};

/* The pipe: both transports, the listening side's listener, the paired links and what
 * the pipe saw. Every field is under `lock`: the sessions call in from their threads. */
static struct {
    z_owned_mutex_t lock;
    wz_ext_owned_transport_t transport[2];
    int side_id[2];
    int faults;
    wz_ext_link_t listener;
    wz_ext_link_t group[2];
    struct {
        int used;
        int datagram;
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

/* The pair `link` of `side` is in, or -1. Called with the lock held. */
static int pair_of(int side, wz_ext_link_t link) {
    for (int i = 0; i < MAX_PAIRS; i++) {
        if (pipe_state.pairs[i].used && pipe_state.pairs[i].link[side] == link) return i;
    }
    return -1;
}

static int read_counter(const int *counter) {
    pipe_lock();
    int value = *counter;
    pipe_unlock();
    return value;
}

/* The listening program accepts the dialled `link` on its listener, under `remote`, and
 * the two are paired before the dial is answered, so neither side sends into nothing. */
static int accept_and_pair(wz_ext_link_t link, const char *remote, int datagram) {
    pipe_lock();
    wz_ext_link_t listener = pipe_state.listener;
    pipe_unlock();
    wz_ext_link_t accepted = 0;
    if (wz_ext_transport_accepted(loan_of(LISTENING), listener, remote, &accepted) != Z_OK) return 0;
    pipe_lock();
    pipe_state.dials++;
    for (int i = 0; i < MAX_PAIRS; i++) {
        if (!pipe_state.pairs[i].used) {
            pipe_state.pairs[i].used = 1;
            pipe_state.pairs[i].datagram = datagram;
            pipe_state.pairs[i].link[DIALLING] = link;
            pipe_state.pairs[i].link[LISTENING] = accepted;
            break;
        }
    }
    pipe_unlock();
    return 1;
}

static wz_ext_link_result_t on_open(void *context, wz_ext_link_t link, wz_ext_link_kind_t kind,
                                    const char *locator) {
    int side = *(int *)context;
    (void)locator;
    if (kind == WZ_EXT_LINK_STREAM_LISTEN || kind == WZ_EXT_LINK_DATAGRAM_LISTEN) {
        pipe_lock();
        pipe_state.listener = link;
        pipe_unlock();
        return WZ_EXT_LINK_OK;
    }
    if (kind == WZ_EXT_LINK_GROUP) {
        pipe_lock();
        pipe_state.group[side] = link;
        pipe_unlock();
        return WZ_EXT_LINK_OK;
    }
    if (side == DIALLING && kind == WZ_EXT_LINK_STREAM_DIAL) {
        return accept_and_pair(link, "tcp/192.0.2.200:41000", 0) ? WZ_EXT_LINK_OK : WZ_EXT_LINK_FAILED;
    }
    if (side == DIALLING && kind == WZ_EXT_LINK_DATAGRAM) {
        return accept_and_pair(link, DATAGRAM_SOURCE[DIALLING], 1) ? WZ_EXT_LINK_OK : WZ_EXT_LINK_FAILED;
    }
    return WZ_EXT_LINK_FAILED;
}

static wz_ext_link_result_t on_send(void *context, wz_ext_link_t link, const uint8_t *data, size_t len,
                                    size_t *written) {
    int side = *(int *)context;
    size_t take = len;
    pipe_lock();
    /* A group member's datagram goes to the other member, with this member's address. */
    if (pipe_state.group[side] == link && link != 0) {
        wz_ext_link_t other = pipe_state.group[1 - side];
        pipe_unlock();
        if (other != 0) wz_ext_transport_received(loan_of(1 - side), other, data, len, MEMBER_SOURCE[side]);
        *written = len;
        return WZ_EXT_LINK_OK;
    }
    int pair = pair_of(side, link);
    wz_ext_link_t peer = pair < 0 ? 0 : pipe_state.pairs[pair].link[1 - side];
    int datagram = pair < 0 ? 0 : pipe_state.pairs[pair].datagram;
    int fault = 0; /* 1 would-block, 2 partial */
    if (peer != 0 && !datagram && side == DIALLING && pipe_state.faults) {
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
    /* A datagram crosses whole, with the address the other side knows this one by. */
    const char *source = datagram ? DATAGRAM_SOURCE[side] : NULL;
    if (wz_ext_transport_received(loan_of(1 - side), peer, data, take, source) != Z_OK) {
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
    if (pipe_state.group[side] == link) pipe_state.group[side] = 0;
    int pair = pair_of(side, link);
    if (pair >= 0) {
        peer = pipe_state.pairs[pair].link[1 - side];
        pipe_state.pairs[pair].used = 0;
    }
    pipe_unlock();
    /* The other end hears the close, from inside this close. */
    if (peer != 0) wz_ext_transport_event(loan_of(1 - side), peer, WZ_EXT_LINK_EVENT_CLOSED);
}

static void on_drained(void *context, wz_ext_link_t link) {
    (void)context;
    (void)link;
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

static void on_peer(const z_id_t *id, void *arg) {
    (void)id;
    (*(int *)arg)++;
}

/* Wait until `session` knows a peer, as z_info_peers_zid lists them; 1 when it does. A group
 * member knows another only from the other's JOIN, which zenoh-pico sends every
 * Z_JOIN_INTERVAL (2500 ms by default) and not in answer to a new member's own, and a get
 * a session asks while it knows no peer completes at once with no reply
 * (src/net/primitives.c, _z_query: remaining_finals == 0). So a get on a group waits for
 * this first. */
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

/* Ask `demo/ask` until a get is answered or the bound runs out. 1 when one was. */
static int ask(const z_loaned_session_t *session) {
    for (int attempt = 0; attempt < 15; attempt++) {
        asked.replies = 0;
        asked.done = 0;
        asked.payload[0] = '\0';
        z_owned_closure_reply_t reply_closure;
        z_closure_reply(&reply_closure, on_reply, on_reply_drop, NULL);
        z_view_keyexpr_t ke;
        z_view_keyexpr_from_str(&ke, "demo/ask");
        z_get_options_t opts;
        z_get_options_default(&opts);
        opts.timeout_ms = 1000;
        if (z_get(session, z_view_keyexpr_loan(&ke), "", z_closure_reply_move(&reply_closure), &opts) != Z_OK) {
            return 0;
        }
        for (int i = 0; i < 500 && !asked.done; i++) z_sleep_ms(10);
        if (asked.replies > 0) return 1;
        /* A get that found no target completed at once; the next is asked after a pause,
         * so the attempts span time rather than a few microseconds. */
        z_sleep_ms(200);
    }
    return 0;
}

/* Fresh pipe state and two transports over it. */
static void pipe_reset(int faults) {
    z_mutex_drop(z_mutex_move(&pipe_state.lock));
    memset(&pipe_state, 0, sizeof pipe_state);
    z_mutex_init(&pipe_state.lock);
    pipe_state.faults = faults;
    for (int side = 0; side < 2; side++) {
        pipe_state.side_id[side] = side;
        wz_ext_transport_t calls;
        memset(&calls, 0, sizeof calls);
        calls.context = &pipe_state.side_id[side];
        calls.open = on_open;
        calls.send = on_send;
        calls.close = on_close;
        calls.drained = on_drained;
        calls.drop = on_drop;
        CHECK(wz_ext_transport_new(&pipe_state.transport[side], &calls) == Z_OK, "wz_ext_transport_new");
    }
}

static int open_over(z_owned_session_t *session, uint8_t key, const char *locator, int side) {
    z_owned_config_t config;
    z_config_default(&config);
    zp_config_insert(z_config_loan_mut(&config), key, locator);
    CHECK(wz_ext_config_transport(z_config_loan_mut(&config), loan_of(side)) == Z_OK, "wz_ext_config_transport");
    int rc = z_open(session, z_config_move(&config), NULL);
    CHECK(rc == Z_OK, "%s did not open over the program's transport (rc %d)", locator, rc);
    return rc == Z_OK;
}

/* One join: `first` opens on `first_key`, `second` on `second_key`; the subscriber and the
 * queryable are on the first, the puts and the get from the second. */
static void run_join(const char *what, uint8_t first_key, const char *first, uint8_t second_key,
                     const char *second, int faults, int sequence) {
    printf("pico-app-transport: %s\n", what);
    pipe_reset(faults);
    memset(&heard, 0, sizeof heard);
    z_mutex_init(&heard.lock);
    heard.in_order = 1;

    z_owned_session_t one;
    z_owned_session_t two;
    if (!open_over(&one, first_key, first, LISTENING)) goto done;

    z_owned_closure_sample_t sample_closure;
    z_closure_sample(&sample_closure, on_sample, NULL, NULL);
    z_view_keyexpr_t sub_ke;
    z_view_keyexpr_from_str(&sub_ke, "demo/pipe/**");
    z_owned_subscriber_t subscriber;
    CHECK(z_declare_subscriber(z_session_loan(&one), &subscriber, z_view_keyexpr_loan(&sub_ke),
                               z_closure_sample_move(&sample_closure), NULL) == Z_OK,
          "z_declare_subscriber");
    z_owned_closure_query_t query_closure;
    z_closure_query(&query_closure, on_query, NULL, NULL);
    z_view_keyexpr_t qbl_ke;
    z_view_keyexpr_from_str(&qbl_ke, "demo/ask");
    z_owned_queryable_t queryable;
    CHECK(z_declare_queryable(z_session_loan(&one), &queryable, z_view_keyexpr_loan(&qbl_ke),
                              z_closure_query_move(&query_closure), NULL) == Z_OK,
          "z_declare_queryable");

    if (open_over(&two, second_key, second, DIALLING)) {
        /* A put reaches the subscriber once its declaration has. */
        for (int i = 0; i < 500 && heard_count() == 0; i++) {
            put(z_session_loan(&two), "demo/pipe/probe", "probe");
            z_sleep_ms(20);
        }
        CHECK(heard_count() > 0, "%s: the subscriber was never handed a put", what);

        if (sequence) {
            /* A sequence arrives whole and in order, through the faults. */
            z_mutex_lock(z_mutex_loan_mut(&heard.lock));
            int before = heard.count;
            heard.next_seq = 0;
            heard.in_order = 1;
            z_mutex_unlock(z_mutex_loan_mut(&heard.lock));
            char text[32];
            for (int n = 0; n < SEQUENCE; n++) {
                snprintf(text, sizeof text, "seq-%d", n);
                put(z_session_loan(&two), "demo/pipe/seq", text);
            }
            for (int i = 0; i < 1000 && heard_count() < before + SEQUENCE; i++) z_sleep_ms(10);
            z_mutex_lock(z_mutex_loan_mut(&heard.lock));
            int got = heard.count - before;
            int in_order = heard.in_order;
            int next = heard.next_seq;
            z_mutex_unlock(z_mutex_loan_mut(&heard.lock));
            CHECK(got >= SEQUENCE, "%s: %d of %d puts of the sequence arrived", what, got, SEQUENCE);
            CHECK(in_order && next == SEQUENCE, "%s: the sequence arrived out of order (next %d)", what, next);
            CHECK(read_counter(&pipe_state.partials) > 0, "%s: no partial send was injected", what);
            CHECK(read_counter(&pipe_state.blocks) > 0, "%s: no would-block was injected", what);
        }

        /* A query gets its reply, once the asking session knows the answering one. */
        CHECK(wait_for_peer(z_session_loan(&two)), "%s: the asking session never knew a peer", what);
        CHECK(ask(z_session_loan(&two)), "%s: no get was answered", what);
        CHECK(strcmp(asked.payload, "answer-over-the-pipe") == 0, "%s: the reply was '%s'", what, asked.payload);

        z_close(z_session_loan_mut(&two), NULL);
        z_session_drop(z_session_move(&two));
    }

    z_subscriber_drop(z_subscriber_move(&subscriber));
    z_queryable_drop(z_queryable_move(&queryable));
    z_close(z_session_loan_mut(&one), NULL);
    z_session_drop(z_session_move(&one));

done:
    for (int side = 0; side < 2; side++) wz_ext_transport_drop(wz_ext_transport_move(&pipe_state.transport[side]));
    /* Each transport's drop runs once, when the sessions and the program have let go. */
    for (int i = 0; i < 1000 && read_counter(&pipe_state.drops) < 2; i++) z_sleep_ms(10);
    CHECK(read_counter(&pipe_state.drops) == 2, "%s: %d of the two transports dropped", what,
          read_counter(&pipe_state.drops));
    CHECK(read_counter(&pipe_state.closes) > 0, "%s: the sessions closed no link on the program", what);
    z_mutex_drop(z_mutex_move(&heard.lock));
}

int main(void) {
    memset(&pipe_state, 0, sizeof pipe_state);
    z_mutex_init(&pipe_state.lock);

    run_join("a stream pair", Z_CONFIG_LISTEN_KEY, "tcp/192.0.2.100:7447", Z_CONFIG_CONNECT_KEY,
             "tcp/192.0.2.100:7447", 1, 1);
    run_join("a datagram pair", Z_CONFIG_LISTEN_KEY, "udp/192.0.2.100:7447", Z_CONFIG_CONNECT_KEY,
             "udp/192.0.2.100:7447", 0, 0);
    run_join("a two-member group", Z_CONFIG_LISTEN_KEY, "udp/239.1.2.3:7447#iface=lan7", Z_CONFIG_LISTEN_KEY,
             "udp/239.1.2.3:7447#iface=lan7", 0, 0);

    z_mutex_drop(z_mutex_move(&pipe_state.lock));
    printf("pico-app-transport: %d check(s), %d failure(s)\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
