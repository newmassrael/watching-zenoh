/*
 * SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * A network stack of the program's own under the sessions: the guide to plugging a TCP/IP
 * stack that is not the operating system's into the library, through the program's transport
 * (wz_ext_transport_*; wz_ext.h, the section "the program's transport", states the contract).
 *
 * The file is in three parts. A program that brings its own stack keeps the shape of the second
 * and puts its stack in place of the first:
 *
 *   1. THE STACK. A stand-in for the program's TCP/IP: an in-process wire between two hosts,
 *      192.0.2.1 and 192.0.2.2 (documentation addresses; no socket of the system's is opened).
 *      Each end of a connection queues what it sends (a stream end in a window of
 *      STREAM_WINDOW bytes), and the stack's own thread carries the queues across, at most
 *      WIRE_CHUNK bytes of each end per tick, as a link slower than the program does. A burst
 *      of sends fills a stream's window: a send then takes part of what it is offered, or
 *      nothing until the wire has carried some of it.
 *   2. THE GLUE. The calls the library makes into the stack (open, send, close, drained, drop)
 *      and the three the stack makes into the library when something happens on the wire
 *      (wz_ext_transport_received, _event and _accepted). This is the part to write for a real
 *      stack: open is its connect, bind or group join; send its non-blocking send; close its
 *      close; and its receive, connected and writable callbacks become the calls into the
 *      library.
 *   3. THE EXCHANGE. Two sessions over the stack, three times: a stream pair (tcp/: one listens,
 *      the other dials), a datagram pair (udp/: one listens for datagrams, the other sends to
 *      it) and a two-member group (udp/ with #iface=). On each, a burst of puts under BLOCK
 *      congestion control arrives whole and in order; on the stream pair the burst fills the
 *      window, and the sessions ride over the partial sends and would-blocks the stack answers.
 *      First, a dial to an address where nothing listens fails the open.
 *
 * The rules the glue keeps, each written where it applies:
 *   - a stream send takes what fits and says how much; it answers WOULD_BLOCK when nothing
 *     fits, and the stack reports WRITABLE once something does: the session sends again from
 *     the first byte the stack did not take;
 *   - a datagram is taken whole or not at all;
 *   - a connect that needs a round trip answers WOULD_BLOCK, then reports CONNECTED, or CLOSED
 *     when it is refused;
 *   - bytes a session refuses (WZ_EXT_ERR_LINK_FULL) stay in the stack until it says drained;
 *   - the stack never holds its own lock across a call into the library: such a call may run
 *     the program's close or drained before it returns, and those take that lock.
 *
 * Built against the library with the app-transport capability.
 */

#define EXAMPLE_NAME "example-own-transport"

#include <zenoh-pico.h>

#include "wz_ext.h"

#include "example_common.h"

/* ================================================================ 1. the stack */

#define HOSTS 2
#define ENDS 16                                 /* ends of connections the stack holds at once */
#define STREAM_WINDOW 1000                      /* bytes a stream end may have in flight */
#define DATAGRAM_MAX 65535                      /* the longest datagram the stack carries */
#define DATAGRAM_QUEUE (2 * (4 + DATAGRAM_MAX)) /* two of them, each after its length */
#define WIRE_CHUNK 256                          /* bytes of one stream end carried per tick */
#define GROUP_PORT 7447
#define NAME_LEN 96                             /* room for a locator or an address */

/* The calls into the library the stack makes when something happens on the wire; part 2
 * defines them. A real stack makes them from its receive, connected and writable callbacks. */
static z_result_t upcall_received(int host, wz_ext_link_t link, const uint8_t *data, size_t len,
                                  const char *source);
static z_result_t upcall_accepted(int host, wz_ext_link_t listener, const char *remote, wz_ext_link_t *out);
static void upcall_event(int host, wz_ext_link_t link, wz_ext_link_event_t event);

/* A bounded byte queue: a stream end's window, or a datagram end's queue of length-prefixed
 * datagrams. */
typedef struct {
    uint8_t *bytes;
    size_t cap;
    size_t head; /* where the oldest byte held is */
    size_t len;  /* how many bytes are held */
} ring_t;

static int ring_init(ring_t *r, size_t cap) {
    r->bytes = (uint8_t *)malloc(cap);
    r->cap = r->bytes != NULL ? cap : 0;
    r->head = 0;
    r->len = 0;
    return r->bytes != NULL;
}

static void ring_free(ring_t *r) {
    free(r->bytes);
    memset(r, 0, sizeof *r);
}

static size_t ring_room(const ring_t *r) { return r->cap - r->len; }

/* Append `n` bytes; the caller has checked the room. */
static void ring_put(ring_t *r, const uint8_t *data, size_t n) {
    size_t tail = (r->head + r->len) % r->cap;
    size_t first = n < r->cap - tail ? n : r->cap - tail;
    memcpy(r->bytes + tail, data, first);
    memcpy(r->bytes, data + first, n - first);
    r->len += n;
}

/* Copy `n` bytes from `offset` past the oldest, without taking them. */
static void ring_peek(const ring_t *r, size_t offset, uint8_t *out, size_t n) {
    size_t at = (r->head + offset) % r->cap;
    size_t first = n < r->cap - at ? n : r->cap - at;
    memcpy(out, r->bytes + at, first);
    memcpy(out + first, r->bytes, n - first);
}

static void ring_take(ring_t *r, size_t n) {
    r->head = r->cap == 0 ? 0 : (r->head + n) % r->cap;
    r->len -= n;
}

/* A datagram as one record: its length in four bytes, then its bytes. */
static void ring_put_record(ring_t *r, const uint8_t *data, size_t n) {
    uint8_t length[4] = {(uint8_t)n, (uint8_t)(n >> 8), (uint8_t)(n >> 16), (uint8_t)(n >> 24)};
    ring_put(r, length, sizeof length);
    ring_put(r, data, n);
}

/* The length of the oldest record; the queue holds one. */
static size_t ring_record_len(const ring_t *r) {
    uint8_t length[4];
    ring_peek(r, 0, length, sizeof length);
    return (size_t)length[0] | ((size_t)length[1] << 8) | ((size_t)length[2] << 16) | ((size_t)length[3] << 24);
}

/* What an end of a connection is. */
enum { ROLE_STREAM_LISTENER, ROLE_DATAGRAM_LISTENER, ROLE_STREAM, ROLE_DATAGRAM, ROLE_GROUP };

/* What an end is doing. */
enum {
    END_FREE = 0,
    END_LISTENING,  /* a bound listener, on which streams or datagram sources are accepted */
    END_CONNECTING, /* a dialled stream whose connect is under way */
    END_ACCEPTING,  /* the listening side of a connect, until the library names its link */
    END_OPEN,
    END_CLOSED /* the session closed it; the stack's thread finishes it */
};

typedef struct {
    int state;
    int role;
    int host;
    /* The session's name for this end, as a stack keeps a pointer of its user's with each
     * socket; 0 until the library names it. */
    wz_ext_link_t link;
    int peer;          /* the other end of a stream or datagram pair, or -1 */
    int blocked;       /* a send found no room: WRITABLE is owed */
    int full;          /* the session refused bytes for this end: wait for drained */
    unsigned drained;  /* how many times the session said this end was read down */
    char locator[NAME_LEN]; /* a listener's or a group's locator, or a dial's destination */
    char address[NAME_LEN]; /* where this end's traffic comes from, as the other end sees it */
    ring_t out;        /* what this end sent that the wire has not carried yet */
} wire_end_t;

static struct {
    z_owned_mutex_t lock;
    wire_end_t end[ENDS];
    wz_ext_owned_transport_t transport[HOSTS];
    int host_id[HOSTS];
    unsigned next_port;
    int stopping;
    z_owned_task_t wire;
    /* What happened, which the exchange reads. */
    int partial_sends;
    int would_blocks;
    int writables;
    int link_full;
    int drains;
    int closes;
    int group_losses;
    int drops;
} net;

/* The wire's one buffer: only its thread uses it. */
static uint8_t carried[DATAGRAM_MAX];

static void net_lock(void) { z_mutex_lock(z_mutex_loan_mut(&net.lock)); }
static void net_unlock(void) { z_mutex_unlock(z_mutex_loan_mut(&net.lock)); }

static int read_stat(const int *stat) {
    net_lock();
    int value = *stat;
    net_unlock();
    return value;
}

/* A new end of `host` in `state`, or -1 when the stack is out of ends or memory. Called with the
 * lock held. */
static int end_new(int host, int role, wz_ext_link_t link, int state) {
    for (int i = 0; i < ENDS; i++) {
        wire_end_t *e = &net.end[i];
        if (e->state != END_FREE) continue;
        memset(e, 0, sizeof *e);
        if (role == ROLE_STREAM || role == ROLE_DATAGRAM || role == ROLE_GROUP) {
            if (!ring_init(&e->out, role == ROLE_STREAM ? STREAM_WINDOW : DATAGRAM_QUEUE)) return -1;
        }
        e->role = role;
        e->host = host;
        e->link = link;
        e->peer = -1;
        e->state = state;
        return i;
    }
    return -1;
}

/* Called with the lock held. */
static void end_release(int i) {
    ring_free(&net.end[i].out);
    memset(&net.end[i], 0, sizeof net.end[i]);
}

/* The end `host`'s session names `link`, or -1. Called with the lock held. */
static int end_find(int host, wz_ext_link_t link) {
    for (int i = 0; i < ENDS; i++) {
        if (net.end[i].state != END_FREE && net.end[i].host == host && net.end[i].link == link && link != 0) {
            return i;
        }
    }
    return -1;
}

/* The listener of `role` bound to `locator`, or -1. Called with the lock held. */
static int end_listener(int role, const char *locator) {
    for (int i = 0; i < ENDS; i++) {
        if (net.end[i].state == END_LISTENING && net.end[i].role == role && strcmp(net.end[i].locator, locator) == 0) {
            return i;
        }
    }
    return -1;
}

/* Take `n` bytes out of end `i`'s queue: the link to report WRITABLE on when a send of it waits
 * for room, else 0. Called with the lock held. */
static wz_ext_link_t end_took(int i, size_t n) {
    wire_end_t *e = &net.end[i];
    ring_take(&e->out, n);
    if (!e->blocked || e->state != END_OPEN) return 0;
    e->blocked = 0;
    net.writables++;
    return e->link;
}

/* A dialled stream reaches the listener its locator names: the listening host accepts it, and
 * the dialling host then hears CONNECTED; CLOSED when nothing listens there. */
static void wire_connect(int i) {
    net_lock();
    wire_end_t *dial = &net.end[i];
    if (dial->state != END_CONNECTING) {
        net_unlock();
        return;
    }
    int dial_host = dial->host;
    int l = end_listener(ROLE_STREAM_LISTENER, dial->locator);
    int a = l < 0 ? -1 : end_new(net.end[l].host, ROLE_STREAM, 0, END_ACCEPTING);
    if (a < 0) {
        /* Refused. The stack lets the end go itself, whether or not the session then closes
         * the link whose open failed. */
        wz_ext_link_t refused = dial->link;
        dial->state = END_CLOSED;
        net_unlock();
        upcall_event(dial_host, refused, WZ_EXT_LINK_EVENT_CLOSED);
        return;
    }
    wire_end_t *acc = &net.end[a];
    acc->peer = i;
    dial->peer = a;
    snprintf(acc->address, sizeof acc->address, "%s", net.end[l].locator);
    int listen_host = net.end[l].host;
    wz_ext_link_t listener = net.end[l].link;
    char remote[NAME_LEN];
    snprintf(remote, sizeof remote, "%s", dial->address);
    net_unlock();

    wz_ext_link_t accepted = 0;
    z_result_t rc = upcall_accepted(listen_host, listener, remote, &accepted);

    net_lock();
    wz_ext_link_t connected = 0;
    wz_ext_link_t refused = 0;
    if (rc == Z_OK) {
        acc->link = accepted;
        acc->state = END_OPEN;
        /* A dial the session gave up meanwhile is finished by the wire, which closes this end's
         * peer then. */
        if (dial->state == END_CONNECTING) {
            dial->state = END_OPEN;
            connected = dial->link;
        }
    } else {
        end_release(a);
        dial->peer = -1;
        if (dial->state == END_CONNECTING) {
            dial->state = END_CLOSED;
            refused = dial->link;
        }
    }
    net_unlock();
    if (connected != 0) upcall_event(dial_host, connected, WZ_EXT_LINK_EVENT_CONNECTED);
    if (refused != 0) upcall_event(dial_host, refused, WZ_EXT_LINK_EVENT_CLOSED);
}

/* Carry up to WIRE_CHUNK bytes of stream end `i` to its peer. */
static void carry_stream(int i) {
    net_lock();
    wire_end_t *e = &net.end[i];
    int host = e->host;
    int p = e->peer;
    if (p < 0 || net.end[p].state != END_OPEN) {
        /* The other end is gone: what this end still holds goes nowhere. */
        ring_take(&e->out, e->out.len);
        net_unlock();
        return;
    }
    if (net.end[p].full) {
        net_unlock();
        return;
    }
    size_t n = e->out.len < WIRE_CHUNK ? e->out.len : WIRE_CHUNK;
    ring_peek(&e->out, 0, carried, n);
    int to_host = net.end[p].host;
    wz_ext_link_t to_link = net.end[p].link;
    unsigned drained_seen = net.end[p].drained;
    net_unlock();

    z_result_t rc = upcall_received(to_host, to_link, carried, n, NULL);

    net_lock();
    wz_ext_link_t writable = 0;
    if (rc == WZ_EXT_ERR_LINK_FULL) {
        /* The session holds all it takes: the bytes stay here until it says drained. A drained
         * that came while this call was out means it takes bytes again already. */
        net.link_full++;
        if (net.end[p].drained == drained_seen) net.end[p].full = 1;
    } else if (rc != WZ_EXT_ERR_LINK_NOT_OPEN) {
        /* Carried, or the other end is gone: either way the bytes have left this end. */
        writable = end_took(i, n);
    }
    net_unlock();
    if (writable != 0) upcall_event(host, writable, WZ_EXT_LINK_EVENT_WRITABLE);
}

/* Carry the oldest datagram of datagram end `i` to its peer. The first datagram to a listening
 * address makes the peer: the host listening there accepts its source as a link of its own. */
static void carry_datagram(int i) {
    net_lock();
    wire_end_t *e = &net.end[i];
    int host = e->host;
    size_t n = ring_record_len(&e->out);
    int p = e->peer;
    if (p < 0) {
        int l = e->state == END_OPEN ? end_listener(ROLE_DATAGRAM_LISTENER, e->locator) : -1;
        int a = l < 0 ? -1 : end_new(net.end[l].host, ROLE_DATAGRAM, 0, END_ACCEPTING);
        if (a < 0) {
            /* Nobody listens there: the datagram is lost, as one sent to no socket is. */
            wz_ext_link_t writable = end_took(i, 4 + n);
            net_unlock();
            if (writable != 0) upcall_event(host, writable, WZ_EXT_LINK_EVENT_WRITABLE);
            return;
        }
        wire_end_t *acc = &net.end[a];
        acc->peer = i;
        e->peer = a;
        snprintf(acc->address, sizeof acc->address, "%s", net.end[l].locator);
        int listen_host = net.end[l].host;
        wz_ext_link_t listener = net.end[l].link;
        char remote[NAME_LEN];
        snprintf(remote, sizeof remote, "%s", e->address);
        net_unlock();

        wz_ext_link_t accepted = 0;
        z_result_t rc = upcall_accepted(listen_host, listener, remote, &accepted);

        net_lock();
        if (rc == Z_OK) {
            acc->link = accepted;
            acc->state = END_OPEN;
        } else {
            end_release(a);
            e->peer = -1;
        }
        net_unlock();
        /* The datagram crosses on the next tick, or is lost then if nobody took its source. */
        return;
    }
    wire_end_t *to = &net.end[p];
    if (to->state != END_OPEN) {
        wz_ext_link_t writable = end_took(i, 4 + n);
        net_unlock();
        if (writable != 0) upcall_event(host, writable, WZ_EXT_LINK_EVENT_WRITABLE);
        return;
    }
    if (to->full) {
        net_unlock();
        return;
    }
    ring_peek(&e->out, 4, carried, n);
    int to_host = to->host;
    wz_ext_link_t to_link = to->link;
    unsigned drained_seen = to->drained;
    char source[NAME_LEN];
    snprintf(source, sizeof source, "%s", e->address);
    net_unlock();

    /* A datagram is handed in whole, with the address it came from. */
    z_result_t rc = upcall_received(to_host, to_link, carried, n, source);

    net_lock();
    wz_ext_link_t writable = 0;
    if (rc == WZ_EXT_ERR_LINK_FULL) {
        net.link_full++;
        if (net.end[p].drained == drained_seen) net.end[p].full = 1;
    } else if (rc != WZ_EXT_ERR_LINK_NOT_OPEN) {
        writable = end_took(i, 4 + n);
    }
    net_unlock();
    if (writable != 0) upcall_event(host, writable, WZ_EXT_LINK_EVENT_WRITABLE);
}

/* Carry the oldest datagram of group end `i` to every other member of its group, with the
 * address of the member that sent it, which is how the members are told apart. */
static void carry_group(int i) {
    wz_ext_link_t links[ENDS];
    int hosts[ENDS];
    int members = 0;
    char source[NAME_LEN];
    net_lock();
    wire_end_t *e = &net.end[i];
    int host = e->host;
    size_t n = ring_record_len(&e->out);
    ring_peek(&e->out, 4, carried, n);
    snprintf(source, sizeof source, "%s", e->address);
    for (int m = 0; m < ENDS; m++) {
        wire_end_t *to = &net.end[m];
        if (m == i || to->role != ROLE_GROUP || to->state != END_OPEN || strcmp(to->locator, e->locator) != 0) {
            continue;
        }
        links[members] = to->link;
        hosts[members] = to->host;
        members++;
    }
    net_unlock();

    for (int k = 0; k < members; k++) {
        /* A member whose session holds all it takes loses the datagram, as a socket whose
         * buffer is full loses one; a group has no flow control. */
        if (upcall_received(hosts[k], links[k], carried, n, source) == WZ_EXT_ERR_LINK_FULL) {
            net_lock();
            net.group_losses++;
            net_unlock();
        }
    }

    net_lock();
    wz_ext_link_t writable = end_took(i, 4 + n);
    net_unlock();
    if (writable != 0) upcall_event(host, writable, WZ_EXT_LINK_EVENT_WRITABLE);
}

/* An end the session closed is let go once the stack is done with it: a stream's queued bytes
 * are carried first, and its peer then hears CLOSED, as a stream's end of data follows its
 * data. */
static void wire_finish(int i) {
    net_lock();
    wire_end_t *e = &net.end[i];
    if (e->state != END_CLOSED) {
        net_unlock();
        return;
    }
    int p = e->peer;
    int peer_open = p >= 0 && net.end[p].state == END_OPEN;
    if (e->role == ROLE_STREAM && peer_open && e->out.len > 0) {
        net_unlock();
        return;
    }
    wz_ext_link_t tell = 0;
    int tell_host = 0;
    if (p >= 0 && net.end[p].state != END_FREE && net.end[p].peer == i) {
        net.end[p].peer = -1;
        if (e->role == ROLE_STREAM && peer_open) {
            tell = net.end[p].link;
            tell_host = net.end[p].host;
        }
    }
    end_release(i);
    net_unlock();
    if (tell != 0) upcall_event(tell_host, tell, WZ_EXT_LINK_EVENT_CLOSED);
}

/* One tick of end `i`. */
static void wire_step(int i) {
    net_lock();
    int state = net.end[i].state;
    int role = net.end[i].role;
    size_t queued = net.end[i].out.len;
    net_unlock();
    if (state == END_CONNECTING) {
        wire_connect(i);
        return;
    }
    if (state != END_OPEN && state != END_CLOSED) return;
    if (queued > 0) {
        if (role == ROLE_STREAM) carry_stream(i);
        if (role == ROLE_DATAGRAM) carry_datagram(i);
        if (role == ROLE_GROUP) carry_group(i);
    }
    wire_finish(i);
}

/* The stack's own thread. Only it carries, accepts, connects and lets ends go, so an end it
 * reads before a call into the library is still there after the call. */
static void *wire_task(void *arg) {
    (void)arg;
    for (;;) {
        net_lock();
        int stopping = net.stopping;
        net_unlock();
        if (stopping) break;
        for (int i = 0; i < ENDS; i++) wire_step(i);
        z_sleep_ms(1);
    }
    return NULL;
}

/* ================================================================ 2. the glue */

/* The session opens a link: `kind` says which, `locator` names where (as the config wrote it).
 * The handle `link` is the session's name for it from now on; it is valid before this is
 * called, so the stack may report the link from its own thread before this returns. */
static wz_ext_link_result_t glue_open(void *context, wz_ext_link_t link, wz_ext_link_kind_t kind,
                                      const char *locator) {
    int host = *(const int *)context;
    int role;
    int state;
    wz_ext_link_result_t answer = WZ_EXT_LINK_OK;
    switch (kind) {
        case WZ_EXT_LINK_STREAM_LISTEN: /* bind and listen */
            role = ROLE_STREAM_LISTENER;
            state = END_LISTENING;
            break;
        case WZ_EXT_LINK_DATAGRAM_LISTEN: /* bind; each new source is accepted on it */
            role = ROLE_DATAGRAM_LISTENER;
            state = END_LISTENING;
            break;
        case WZ_EXT_LINK_STREAM_DIAL:
            /* A connect takes a round trip: under way now, CONNECTED or CLOSED from the stack's
             * thread later. */
            role = ROLE_STREAM;
            state = END_CONNECTING;
            answer = WZ_EXT_LINK_WOULD_BLOCK;
            break;
        case WZ_EXT_LINK_DATAGRAM: /* nothing to set up: up at once */
            role = ROLE_DATAGRAM;
            state = END_OPEN;
            break;
        case WZ_EXT_LINK_GROUP: /* join the group: up at once */
            role = ROLE_GROUP;
            state = END_OPEN;
            break;
        default:
            return WZ_EXT_LINK_FAILED;
    }
    net_lock();
    int i = end_new(host, role, link, state);
    if (i >= 0) {
        wire_end_t *e = &net.end[i];
        snprintf(e->locator, sizeof e->locator, "%s", locator);
        if (role == ROLE_STREAM) {
            snprintf(e->address, sizeof e->address, "tcp/192.0.2.%d:%u", host + 1, net.next_port++);
        } else if (role == ROLE_DATAGRAM) {
            snprintf(e->address, sizeof e->address, "udp/192.0.2.%d:%u", host + 1, net.next_port++);
        } else if (role == ROLE_GROUP) {
            snprintf(e->address, sizeof e->address, "udp/192.0.2.%d:%d", host + 1, GROUP_PORT);
        } else {
            snprintf(e->address, sizeof e->address, "%s", locator);
        }
    }
    net_unlock();
    return i < 0 ? WZ_EXT_LINK_FAILED : answer;
}

/* The session sends `len` bytes on `link`. The bytes are valid only during the call, so the
 * stack copies what it takes. */
static wz_ext_link_result_t glue_send(void *context, wz_ext_link_t link, const uint8_t *data, size_t len,
                                      size_t *written) {
    int host = *(const int *)context;
    wz_ext_link_result_t answer;
    net_lock();
    int i = end_find(host, link);
    wire_end_t *e = i < 0 ? NULL : &net.end[i];
    if (e == NULL || e->state != END_OPEN) {
        answer = WZ_EXT_LINK_CLOSED;
    } else if (e->role == ROLE_STREAM) {
        /* What fits in the window: all of it, part of it (the session sends the rest from where
         * the stack stopped), or nothing (WOULD_BLOCK; WRITABLE follows once the wire has
         * carried some of the window). */
        size_t room = ring_room(&e->out);
        size_t take = len < room ? len : room;
        if (take == 0) {
            e->blocked = 1;
            net.would_blocks++;
            answer = WZ_EXT_LINK_WOULD_BLOCK;
        } else {
            ring_put(&e->out, data, take);
            if (take < len) net.partial_sends++;
            *written = take;
            answer = WZ_EXT_LINK_OK;
        }
    } else if (len > DATAGRAM_MAX) {
        /* A datagram the stack can never carry: taking part of it would cut it. */
        answer = WZ_EXT_LINK_FAILED;
    } else if (ring_room(&e->out) < 4 + len) {
        /* A datagram is taken whole or not at all. */
        e->blocked = 1;
        net.would_blocks++;
        answer = WZ_EXT_LINK_WOULD_BLOCK;
    } else {
        ring_put_record(&e->out, data, len);
        *written = len;
        answer = WZ_EXT_LINK_OK;
    }
    net_unlock();
    return answer;
}

/* The session closes `link`. The stack reports nothing more of it after this returns: every
 * report checks that the end is still open first, and one already on its way when the close
 * came is refused by the library. The stack's thread carries what the end still holds and lets
 * it go. */
static void glue_close(void *context, wz_ext_link_t link) {
    int host = *(const int *)context;
    net_lock();
    int i = end_find(host, link);
    if (i >= 0) net.end[i].state = END_CLOSED;
    net.closes++;
    net_unlock();
}

/* The session has read `link` down after refusing bytes for it (WZ_EXT_ERR_LINK_FULL): the
 * stack hands them in again. Called from a session thread. */
static void glue_drained(void *context, wz_ext_link_t link) {
    int host = *(const int *)context;
    net_lock();
    int i = end_find(host, link);
    if (i >= 0) {
        net.end[i].full = 0;
        net.end[i].drained++;
    }
    net.drains++;
    net_unlock();
}

/* The last reference to the transport is gone: no call of open, send or close comes after. */
static void glue_drop(void *context) {
    (void)context;
    net_lock();
    net.drops++;
    net_unlock();
}

static const wz_ext_loaned_transport_t *host_transport(int host) {
    return wz_ext_transport_loan(&net.transport[host]);
}

/* Bytes that arrived for `link`: copied before this returns. WZ_EXT_ERR_LINK_FULL when the
 * session holds all it takes, nothing taken. */
static z_result_t upcall_received(int host, wz_ext_link_t link, const uint8_t *data, size_t len,
                                  const char *source) {
    return wz_ext_transport_received(host_transport(host), link, data, len, source);
}

/* A stream, or a datagram source, the stack accepted on `listener`: the handle the session names
 * it by from now on. */
static z_result_t upcall_accepted(int host, wz_ext_link_t listener, const char *remote, wz_ext_link_t *out) {
    return wz_ext_transport_accepted(host_transport(host), listener, remote, out);
}

/* CONNECTED, CLOSED or WRITABLE. A report that crosses the session's close of the link is
 * refused (WZ_EXT_ERR_LINK_UNKNOWN or _CLOSED), and there is nothing more to tell then. */
static void upcall_event(int host, wz_ext_link_t link, wz_ext_link_event_t event) {
    (void)wz_ext_transport_event(host_transport(host), link, event);
}

/* One transport for each host, over the glue, and the stack's thread. */
static int stack_start(void) {
    memset(&net, 0, sizeof net);
    z_mutex_init(&net.lock);
    net.next_port = 41000;
    for (int h = 0; h < HOSTS; h++) {
        net.host_id[h] = h;
        wz_ext_transport_t calls;
        memset(&calls, 0, sizeof calls);
        calls.context = &net.host_id[h];
        calls.open = glue_open;
        calls.send = glue_send;
        calls.close = glue_close;
        calls.drained = glue_drained;
        calls.drop = glue_drop;
        if (wz_ext_transport_new(&net.transport[h], &calls) != Z_OK) return 0;
    }
    return z_task_init(&net.wire, NULL, wire_task, NULL) == Z_OK;
}

/* Stop the stack's thread once the sessions are closed, let the transports go, and free what the
 * stack holds once the library has let go of them too. */
static void stack_stop(void) {
    net_lock();
    net.stopping = 1;
    net_unlock();
    z_task_join(z_task_move(&net.wire));
    for (int h = 0; h < HOSTS; h++) wz_ext_transport_drop(wz_ext_transport_move(&net.transport[h]));
    for (int i = 0; i < 1000 && read_stat(&net.drops) < HOSTS; i++) z_sleep_ms(10);
    CHECK(read_stat(&net.drops) == HOSTS, "%d of the %d transports were let go", read_stat(&net.drops), HOSTS);
    if (read_stat(&net.drops) == HOSTS) {
        net_lock();
        for (int i = 0; i < ENDS; i++) {
            if (net.end[i].state != END_FREE) end_release(i);
        }
        net_unlock();
        z_mutex_drop(z_mutex_move(&net.lock));
    }
}

/* ================================================================ 3. the exchange */

#define BURST 24
#define BURST_PAYLOAD 900

/* What host 0's subscriber was handed. */
static struct {
    z_owned_mutex_t lock;
    int probes;
    int count;
    int next;
    int in_order;
} heard;

static void on_sample(z_loaned_sample_t *sample, void *arg) {
    (void)arg;
    char text[32];
    ex_payload_text(z_sample_payload(sample), text, sizeof text);
    int seq = -1;
    z_mutex_lock(z_mutex_loan_mut(&heard.lock));
    if (strcmp(text, "probe") == 0) {
        heard.probes++;
    } else if (sscanf(text, "seq-%d", &seq) == 1) {
        if (seq != heard.next) heard.in_order = 0;
        heard.next = seq + 1;
        heard.count++;
    }
    z_mutex_unlock(z_mutex_loan_mut(&heard.lock));
}

static int heard_read(const int *field) {
    z_mutex_lock(z_mutex_loan_mut(&heard.lock));
    int value = *field;
    z_mutex_unlock(z_mutex_loan_mut(&heard.lock));
    return value;
}

/* A session of `host` whose config names `locator` under `key` (and `mode`, when it is not
 * NULL): every link it opens goes over the host's stack, and none over the system's sockets. */
static z_result_t open_over(z_owned_session_t *session, int host, const char *mode, uint8_t key,
                            const char *locator) {
    z_owned_config_t config;
    z_config_default(&config);
    if (mode != NULL) zp_config_insert(z_config_loan_mut(&config), Z_CONFIG_MODE_KEY, mode);
    zp_config_insert(z_config_loan_mut(&config), key, locator);
    z_result_t rc = wz_ext_config_transport(z_config_loan_mut(&config), host_transport(host));
    if (rc != Z_OK) {
        z_config_drop(z_config_move(&config));
        return rc;
    }
    return z_open(session, z_config_move(&config), NULL);
}

/* Host 0 opens on `locator0` and subscribes; host 1 opens on `locator1` and puts. */
static void run_join(const char *what, const char *mode0, uint8_t key0, const char *locator0, const char *mode1,
                     uint8_t key1, const char *locator1, int stream) {
    printf("%s: %s\n", EXAMPLE_NAME, what);
    z_mutex_lock(z_mutex_loan_mut(&heard.lock));
    heard.probes = 0;
    heard.count = 0;
    heard.next = 0;
    heard.in_order = 1;
    z_mutex_unlock(z_mutex_loan_mut(&heard.lock));

    z_owned_session_t one;
    z_result_t rc = open_over(&one, 0, mode0, key0, locator0);
    CHECK(rc == Z_OK, "%s: host 0 did not open on %s (rc %d)", what, locator0, (int)rc);
    if (rc != Z_OK) return;
    z_owned_closure_sample_t closure;
    z_closure_sample(&closure, on_sample, NULL, NULL);
    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, "example/own-transport/**");
    z_owned_subscriber_t subscriber;
    CHECK(z_declare_subscriber(z_session_loan(&one), &subscriber, z_view_keyexpr_loan(&ke),
                               z_closure_sample_move(&closure), NULL) == Z_OK,
          "%s: z_declare_subscriber", what);

    z_owned_session_t two;
    rc = open_over(&two, 1, mode1, key1, locator1);
    CHECK(rc == Z_OK, "%s: host 1 did not open on %s (rc %d)", what, locator1, (int)rc);
    if (rc == Z_OK) {
        const z_loaned_session_t *s = z_session_loan(&two);
        /* A put reaches the subscriber once its declaration has (on a group, once the members
         * have heard each other). */
        for (int i = 0; i < 400 && heard_read(&heard.probes) == 0; i++) {
            ex_put(s, "example/own-transport/probe", "probe", NULL);
            z_sleep_ms(25);
        }
        CHECK(heard_read(&heard.probes) > 0, "%s: the subscriber was never handed a put", what);

        int partial_before = read_stat(&net.partial_sends);
        int blocks_before = read_stat(&net.would_blocks);
        int writable_before = read_stat(&net.writables);
        /* The burst: BLOCK makes a put wait while the session's queue is full, so none is
         * dropped while the stack is slower than the program. */
        char text[BURST_PAYLOAD + 1];
        for (int n = 0; n < BURST; n++) {
            int head = snprintf(text, sizeof text, "seq-%d:", n);
            memset(text + head, 'x', (size_t)(BURST_PAYLOAD - head));
            text[BURST_PAYLOAD] = '\0';
            z_put_options_t options;
            z_put_options_default(&options);
            options.congestion_control = Z_CONGESTION_CONTROL_BLOCK;
            ex_put(s, "example/own-transport/seq", text, &options);
        }
        for (int i = 0; i < 3000 && heard_read(&heard.count) < BURST; i++) z_sleep_ms(10);
        int partials = read_stat(&net.partial_sends) - partial_before;
        int blocks = read_stat(&net.would_blocks) - blocks_before;
        int writables = read_stat(&net.writables) - writable_before;
        printf("%s: %s: %d partial sends, %d would-blocks, %d writables\n", EXAMPLE_NAME, what, partials, blocks,
               writables);
        CHECK(heard_read(&heard.count) == BURST, "%s: %d of %d puts of the burst arrived", what,
              heard_read(&heard.count), BURST);
        CHECK(heard_read(&heard.in_order), "%s: the burst arrived out of order (next %d)", what,
              heard_read(&heard.next));
        if (stream) {
            /* The window is far smaller than the burst: the stack took parts of sends, refused
             * whole ones, and said writable again each time the wire made room. */
            CHECK(partials > 0, "%s: no send was taken in part", what);
            CHECK(blocks > 0, "%s: no send would block", what);
            CHECK(writables > 0, "%s: the stack never reported a link writable", what);
        }
        ex_close(&two);
    }
    z_subscriber_drop(z_subscriber_move(&subscriber));
    ex_close(&one);
}

int main(void) {
    z_mutex_init(&heard.lock);
    if (!stack_start()) {
        CHECK(0, "the stack did not start");
        return ex_finish();
    }

    /* Refused: a dial to an address where nothing listens. The stack answers the open
     * WOULD_BLOCK, finds no listener, and reports the link CLOSED; the open fails. */
    z_owned_session_t nobody;
    z_result_t rc = open_over(&nobody, 1, "client", Z_CONFIG_CONNECT_KEY, "tcp/192.0.2.1:9");
    CHECK(rc != Z_OK, "a dial to an address where nothing listens opened");
    if (rc == Z_OK) ex_close(&nobody);

    run_join("a stream pair", NULL, Z_CONFIG_LISTEN_KEY, "tcp/192.0.2.1:7447", "client", Z_CONFIG_CONNECT_KEY,
             "tcp/192.0.2.1:7447", 1);
    run_join("a datagram pair", NULL, Z_CONFIG_LISTEN_KEY, "udp/192.0.2.1:7447", "client", Z_CONFIG_CONNECT_KEY,
             "udp/192.0.2.1:7447", 0);
    run_join("a two-member group", "peer", Z_CONFIG_LISTEN_KEY, "udp/239.1.2.3:7447#iface=wire0", "peer",
             Z_CONFIG_LISTEN_KEY, "udp/239.1.2.3:7447#iface=wire0", 0);

    printf("%s: %d link(s) closed, %d refusal(s) for a full session, %d drained, %d lost in a group\n",
           EXAMPLE_NAME, read_stat(&net.closes), read_stat(&net.link_full), read_stat(&net.drains),
           read_stat(&net.group_losses));
    CHECK(read_stat(&net.closes) > 0, "the sessions closed no link on the stack");
    stack_stop();
    z_mutex_drop(z_mutex_move(&heard.lock));
    return ex_finish();
}
