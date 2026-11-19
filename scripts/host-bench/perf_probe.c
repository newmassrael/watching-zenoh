// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// One program of the host performance matrix (scripts/host-bench/perf_matrix.py, docs/pico-perf-matrix.md),
// in four roles. It uses only the zenoh-pico C API, so the SAME source is built once against zenoh-pico (the
// reference, built as the same build) and once against libwz_capi_pico; built with PERF_PROGRAM_TRANSPORT it
// also carries the session's links over a transport this program supplies (wz_ext_transport_*, wz_ext.h),
// which exists only in wz, and is built only against it.
//
//   perf_probe pong -m peer (-l|-e) ENDPOINT [-b] [-T NAME]
//   perf_probe ping -m peer (-l|-e) ENDPOINT -s SIZE -n PINGS -w WARMUP_MS [-o TIMEOUT_MS] [-b] [-M] [-T NAME]
//   perf_probe sub  -m peer (-l|-e) ENDPOINT -w WARMUP_MS -t WINDOW_S [-T NAME]
//   perf_probe pub  -m peer (-l|-e) ENDPOINT -s SIZE -t SECONDS [-b] [-d] [-M] [-T NAME]
//
// -l and -e may each be given once and both may be given (a multicast group is a listen on both sides).
//
// ping / pong: the round trip. ping puts SIZE bytes on perf/ping whose first eight bytes are a sequence
// number; pong puts the same payload back on perf/pong; ping waits (spinning, as upstream's z_ping does) for
// the answer that carries its number, up to TIMEOUT_MS (default 100), and counts a round trip that did not
// come back as lost. The first WARMUP_MS are not counted. At the end ping prints, in nanoseconds,
//
//   perf_probe ping round_trips=<n> lost=<n> aborted=<0|1> p50_ns=<..> p90_ns=<..> p99_ns=<..> min_ns=<..>
//     max_ns=<..> mean_ns=<..> all_round_trips=<warm-up and counted> cpu_ns=<process CPU from the first put
//     to the last answer>
//
// (one line), percentiles by nearest rank over the counted round trips, and then puts perf/stop three times.
// pong prints `perf_probe pong answered=<n> cpu_ns=<process CPU from the first ping to the stop>
// stopped_by=<stop|signal>` when the stop arrives, or when it is sent SIGTERM (then the window ends at the
// signal and includes the idle time after the last ping, which the reader does not use). A run that lost more
// than a tenth of the counted round trips stops early with aborted=1.
//
// sub / pub: the throughput. pub puts SIZE bytes on perf/thr as fast as the session takes them for SECONDS
// (congestion control BLOCK, or DROP with -d) and prints
//
//   perf_probe pub sent=<puts that returned 0> failed=<n> elapsed_ns=<..> cpu_ns=<process CPU over the loop>
//     start_ns=<..> end_ns=<..>
//
// sub counts what it is handed; from its first sample it waits WARMUP_MS, then reads the count, the payload
// bytes and its process CPU at the start and the end of a WINDOW_S window, and prints
//
//   perf_probe sub received=<n> bytes=<n> window_ns=<..> cpu_ns=<process CPU over the window> start_ns=<..>
//     end_ns=<..>
//
// start_ns and end_ns are CLOCK_MONOTONIC, which both processes read on the one host, so the reader can tell
// whether the subscriber's window lay inside the publisher's loop.
//
// then keeps its session until SIGTERM, so the publisher never puts into a peer that has gone, and prints
// `perf_probe sub total=<n>` on its way out. The count is taken by the callback alone (two relaxed atomic
// additions); the window is read by the main thread, so no clock is read per sample.
//
// With -b the batching of zenoh-pico (zp_batch_start / zp_batch_stop) is on: pub opens one batch window
// for its whole loop, as upstream's z_pub_thr does; ping and pong open and close one around each put, the
// close flushing it, so a round trip with batching on is the cost of the window on the path, not a delay.
//
// The active side (ping, pub) prepares its publisher as upstream's z_pub_thr does: it waits a second after
// the open before declaring it, then up to ten seconds until z_info_peers_zid lists a peer (a group member
// learns another only from its JOIN), and with -M up to ten seconds more until the publisher matches a
// subscriber (z_publisher_get_matching_status). A zenoh-pico publisher sends no put while it knows of no
// subscriber and still returns success, so without the match a throughput loop that starts before the
// subscriber's declaration arrived counts puts that went nowhere. -M is for the transports that carry
// declarations; a group of the pico preset carries none and sends every put.
//
// -T NAME (PERF_PROGRAM_TRANSPORT only): every link of the session goes over the program's transport, here an
// AF_UNIX stream in the abstract namespace under NAME. A tcp/ listen locator is a listening socket of that
// name, whose accepted streams the program names with wz_ext_transport_accepted; a tcp/ connect locator is a
// stream connected to it. Each link has one thread that reads it and hands the bytes in, and reports a link
// whose send would block writable again; a send never blocks.
//
// Exit status: 0 when the role ran, 1 when the session or an entity could not be made, 2 for a usage error or
// an option the build does not have.

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "zenoh-pico.h"

#ifdef PERF_PROGRAM_TRANSPORT
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "wz_ext.h"
#endif

#if Z_FEATURE_PUBLICATION == 1 && Z_FEATURE_SUBSCRIPTION == 1 && Z_FEATURE_MULTI_THREAD == 1

#define KEY_PING "perf/ping"
#define KEY_PONG "perf/pong"
#define KEY_STOP "perf/stop"
#define KEY_THR "perf/thr"
#define SEQ_BYTES 8
#define PEER_WAIT_MS 10000
#define SUB_PREPARE_MS 1000

static volatile sig_atomic_t terminated = 0;

static void on_terminate(int signo) {
    (void)signo;
    terminated = 1;
}

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static uint64_t cpu_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void sleep_ms(unsigned ms) {
    struct timespec nap = {(time_t)(ms / 1000U), (long)(ms % 1000U) * 1000000L};
    while (nanosleep(&nap, &nap) != 0 && errno == EINTR && !terminated) {
    }
}

static void drop_nothing(void *context) { (void)context; }

// ---------------------------------------------------------------------------------------------------------
// The program's transport: an AF_UNIX stream in the abstract namespace, one reading thread per link.
// ---------------------------------------------------------------------------------------------------------

#ifdef PERF_PROGRAM_TRANSPORT

#define PT_MAX_LINKS 8

struct pt_link {
    int used;
    wz_ext_link_t link;
    int fd;
    int wake[2];
    pthread_t reader;
    int reader_started;
    _Atomic int want_write;
    _Atomic int closing;
    pthread_mutex_t lock;
    pthread_cond_t drained_cond;
    int drained;
};

static struct {
    pthread_mutex_t lock;
    wz_ext_owned_transport_t transport;
    const char *name;
    int listen_fd;
    wz_ext_link_t listener;
    pthread_t acceptor;
    int acceptor_started;
    unsigned accepted;
    struct pt_link links[PT_MAX_LINKS];
} pt = {.lock = PTHREAD_MUTEX_INITIALIZER, .listen_fd = -1};

static const wz_ext_loaned_transport_t *pt_loan(void) { return wz_ext_transport_loan(&pt.transport); }

static socklen_t pt_address(struct sockaddr_un *addr) {
    memset(addr, 0, sizeof *addr);
    addr->sun_family = AF_UNIX;
    size_t n = strlen(pt.name);
    if (n > sizeof addr->sun_path - 1) n = sizeof addr->sun_path - 1;
    // sun_path[0] stays NUL: the abstract namespace, so the name is no file and needs no cleanup.
    memcpy(addr->sun_path + 1, pt.name, n);
    return (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + n);
}

static struct pt_link *pt_find(wz_ext_link_t link) {
    struct pt_link *found = NULL;
    pthread_mutex_lock(&pt.lock);
    for (int i = 0; i < PT_MAX_LINKS; i++) {
        if (pt.links[i].used && pt.links[i].link == link) {
            found = &pt.links[i];
            break;
        }
    }
    pthread_mutex_unlock(&pt.lock);
    return found;
}

static void pt_wake(struct pt_link *l) {
    const char byte = 1;
    ssize_t ignored = write(l->wake[1], &byte, 1);
    (void)ignored;
}

// Hand `len` bytes of `l` in; past the receive bound, wait for the transport's drained (or a 10 ms tick,
// as a program that gives no drained would retry) and hand the same bytes in again. 0 while the link lives.
static int pt_hand_in(struct pt_link *l, const uint8_t *data, size_t len) {
    for (;;) {
        z_result_t rc = wz_ext_transport_received(pt_loan(), l->link, data, len, NULL);
        if (rc == Z_OK) return 0;
        if (rc != WZ_EXT_ERR_LINK_FULL) return -1;
        pthread_mutex_lock(&l->lock);
        if (!l->drained && !atomic_load(&l->closing)) {
            struct timespec until;
            clock_gettime(CLOCK_REALTIME, &until);
            until.tv_nsec += 10000000L;
            if (until.tv_nsec >= 1000000000L) {
                until.tv_sec += 1;
                until.tv_nsec -= 1000000000L;
            }
            pthread_cond_timedwait(&l->drained_cond, &l->lock, &until);
        }
        l->drained = 0;
        pthread_mutex_unlock(&l->lock);
        if (atomic_load(&l->closing)) return -1;
    }
}

static void *pt_read(void *arg) {
    struct pt_link *l = arg;
    static _Thread_local uint8_t buf[65536];
    for (;;) {
        struct pollfd fds[2] = {
            {l->fd, (short)(POLLIN | (atomic_load(&l->want_write) ? POLLOUT : 0)), 0},
            {l->wake[0], POLLIN, 0},
        };
        if (poll(fds, 2, -1) < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (fds[1].revents & POLLIN) {
            char sink[64];
            while (read(l->wake[0], sink, sizeof sink) > 0) {
            }
        }
        if (atomic_load(&l->closing)) break;
        if ((fds[0].revents & POLLOUT) && atomic_exchange(&l->want_write, 0)) {
            wz_ext_transport_event(pt_loan(), l->link, WZ_EXT_LINK_EVENT_WRITABLE);
        }
        if (fds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            ssize_t n = recv(l->fd, buf, sizeof buf, MSG_DONTWAIT);
            if (n > 0) {
                if (pt_hand_in(l, buf, (size_t)n) != 0) break;
            } else if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
                // The other end went: the session hears it as a socket the peer closed.
                if (!atomic_load(&l->closing)) wz_ext_transport_event(pt_loan(), l->link, WZ_EXT_LINK_EVENT_CLOSED);
                break;
            }
        }
    }
    return NULL;
}

// A slot for `link` over `fd`, its reading thread started. 0, or -1 when the table is full.
static int pt_add(wz_ext_link_t link, int fd) {
    struct pt_link *l = NULL;
    pthread_mutex_lock(&pt.lock);
    for (int i = 0; i < PT_MAX_LINKS; i++) {
        if (!pt.links[i].used) {
            l = &pt.links[i];
            break;
        }
    }
    if (l == NULL || pipe2(l->wake, O_NONBLOCK | O_CLOEXEC) != 0) {
        pthread_mutex_unlock(&pt.lock);
        return -1;
    }
    l->used = 1;
    l->link = link;
    l->fd = fd;
    l->drained = 0;
    l->reader_started = 0;
    atomic_store(&l->want_write, 0);
    atomic_store(&l->closing, 0);
    pthread_mutex_init(&l->lock, NULL);
    pthread_cond_init(&l->drained_cond, NULL);
    pthread_mutex_unlock(&pt.lock);
    if (pthread_create(&l->reader, NULL, pt_read, l) == 0) {
        l->reader_started = 1;
        return 0;
    }
    // No thread to read it: the slot goes back and the caller closes the stream.
    pthread_mutex_destroy(&l->lock);
    pthread_cond_destroy(&l->drained_cond);
    close(l->wake[0]);
    close(l->wake[1]);
    pthread_mutex_lock(&pt.lock);
    l->used = 0;
    pthread_mutex_unlock(&pt.lock);
    return -1;
}

static void *pt_accept(void *arg) {
    (void)arg;
    for (;;) {
        int fd = accept4(pt.listen_fd, NULL, NULL, SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EINTR) continue;
            return NULL;  // the listener was shut down
        }
        char remote[64];
        pthread_mutex_lock(&pt.lock);
        unsigned n = ++pt.accepted;
        wz_ext_link_t listener = pt.listener;
        pthread_mutex_unlock(&pt.lock);
        // A synthetic address per stream (TEST-NET-1): the session tells accepted streams apart by it.
        snprintf(remote, sizeof remote, "tcp/192.0.2.2:%u", 40000U + n);
        wz_ext_link_t link = 0;
        if (wz_ext_transport_accepted(pt_loan(), listener, remote, &link) != Z_OK || pt_add(link, fd) != 0) {
            close(fd);
        }
    }
}

static wz_ext_link_result_t pt_open(void *context, wz_ext_link_t link, wz_ext_link_kind_t kind,
                                    const char *locator) {
    (void)context;
    (void)locator;
    struct sockaddr_un addr;
    socklen_t len = pt_address(&addr);
    if (kind == WZ_EXT_LINK_STREAM_LISTEN) {
        int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) return WZ_EXT_LINK_FAILED;
        if (bind(fd, (struct sockaddr *)&addr, len) != 0 || listen(fd, 8) != 0) {
            close(fd);
            return WZ_EXT_LINK_FAILED;
        }
        pthread_mutex_lock(&pt.lock);
        pt.listen_fd = fd;
        pt.listener = link;
        pthread_mutex_unlock(&pt.lock);
        if (pthread_create(&pt.acceptor, NULL, pt_accept, NULL) != 0) return WZ_EXT_LINK_FAILED;
        pt.acceptor_started = 1;
        return WZ_EXT_LINK_OK;
    }
    if (kind == WZ_EXT_LINK_STREAM_DIAL) {
        int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) return WZ_EXT_LINK_FAILED;
        if (connect(fd, (struct sockaddr *)&addr, len) != 0 || pt_add(link, fd) != 0) {
            close(fd);
            return WZ_EXT_LINK_FAILED;  // the session dials again on its schedule
        }
        return WZ_EXT_LINK_OK;
    }
    return WZ_EXT_LINK_FAILED;  // this program carries streams only
}

static wz_ext_link_result_t pt_send(void *context, wz_ext_link_t link, const uint8_t *data, size_t len,
                                    size_t *written) {
    (void)context;
    struct pt_link *l = pt_find(link);
    if (l == NULL) return WZ_EXT_LINK_CLOSED;
    for (;;) {
        ssize_t n = send(l->fd, data, len, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (n > 0) {
            *written = (size_t)n;
            return WZ_EXT_LINK_OK;
        }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            // The reading thread polls for room and reports the link writable.
            atomic_store(&l->want_write, 1);
            pt_wake(l);
            return WZ_EXT_LINK_WOULD_BLOCK;
        }
        return WZ_EXT_LINK_CLOSED;
    }
}

static void pt_close(void *context, wz_ext_link_t link) {
    (void)context;
    if (link == pt.listener && pt.listen_fd >= 0) {
        shutdown(pt.listen_fd, SHUT_RDWR);
        if (pt.acceptor_started) pthread_join(pt.acceptor, NULL);
        pt.acceptor_started = 0;
        close(pt.listen_fd);
        pt.listen_fd = -1;
        return;
    }
    struct pt_link *l = pt_find(link);
    if (l == NULL) return;
    atomic_store(&l->closing, 1);
    shutdown(l->fd, SHUT_RDWR);
    pt_wake(l);
    pthread_mutex_lock(&l->lock);
    pthread_cond_signal(&l->drained_cond);
    pthread_mutex_unlock(&l->lock);
    if (l->reader_started && !pthread_equal(pthread_self(), l->reader)) pthread_join(l->reader, NULL);
    close(l->fd);
    close(l->wake[0]);
    close(l->wake[1]);
    pthread_mutex_destroy(&l->lock);
    pthread_cond_destroy(&l->drained_cond);
    pthread_mutex_lock(&pt.lock);
    l->used = 0;
    pthread_mutex_unlock(&pt.lock);
}

static void pt_drained(void *context, wz_ext_link_t link) {
    (void)context;
    struct pt_link *l = pt_find(link);
    if (l == NULL) return;
    pthread_mutex_lock(&l->lock);
    l->drained = 1;
    pthread_cond_signal(&l->drained_cond);
    pthread_mutex_unlock(&l->lock);
}

static int pt_attach(z_owned_config_t *config, const char *name) {
    pt.name = name;
    wz_ext_transport_t calls;
    memset(&calls, 0, sizeof calls);
    calls.open = pt_open;
    calls.send = pt_send;
    calls.close = pt_close;
    calls.drained = pt_drained;
    if (wz_ext_transport_new(&pt.transport, &calls) != Z_OK) return -1;
    return wz_ext_config_transport(z_config_loan_mut(config), pt_loan()) == Z_OK ? 0 : -1;
}

#endif

// ---------------------------------------------------------------------------------------------------------
// The options and the session.
// ---------------------------------------------------------------------------------------------------------

struct options {
    const char *role;
    size_t size;
    unsigned pings;
    unsigned warmup_ms;
    unsigned timeout_ms;
    unsigned seconds;
    int batching;
    int drop;
    int match;
    const char *transport_name;
};

static int usage(void) {
    fprintf(stderr,
            "usage: perf_probe ping|pong|pub|sub -m MODE [-l ENDPOINT] [-e ENDPOINT] [-s SIZE] [-n PINGS]\n"
            "                  [-w WARMUP_MS] [-o TIMEOUT_MS] [-t SECONDS] [-b] [-d] [-M] [-T NAME]\n");
    return 2;
}

// Batching on the session around one put (ping, pong) or the whole loop (pub). A build without
// Z_FEATURE_BATCHING has no window to open, and the program refuses -b there before it opens anything.
static void batch_start(const z_loaned_session_t *session) {
#if Z_FEATURE_BATCHING == 1
    zp_batch_start(session);
#else
    (void)session;
#endif
}

static void batch_stop(const z_loaned_session_t *session) {
#if Z_FEATURE_BATCHING == 1
    zp_batch_stop(session);
#else
    (void)session;
#endif
}

static void count_peer(const z_id_t *id, void *context) {
    (void)id;
    (*(int *)context)++;
}

// 1 once the session lists a peer, 0 when none came in PEER_WAIT_MS.
static int wait_for_peer(const z_loaned_session_t *session) {
    for (unsigned waited = 0; waited < PEER_WAIT_MS && !terminated; waited += 10) {
        int peers = 0;
        z_owned_closure_zid_t closure;
        z_closure_zid(&closure, count_peer, NULL, &peers);
        z_info_peers_zid(session, z_closure_zid_move(&closure));
        if (peers > 0) return 1;
        sleep_ms(10);
    }
    return 0;
}

// The publishers a role declares, dropped by main after the session is closed: a callback that answers
// on one (pong) can then never run against a publisher already gone.
#define MAX_PUBLISHERS 2
static z_owned_publisher_t publishers[MAX_PUBLISHERS];
static int publisher_count = 0;

// A publisher on `key`, held in `publishers`, loaned; NULL when it could not be declared.
static const z_loaned_publisher_t *declare_publisher(const z_loaned_session_t *session, const char *key, int drop) {
    if (publisher_count == MAX_PUBLISHERS) return NULL;
    z_view_keyexpr_t ke;
    if (z_view_keyexpr_from_str(&ke, key) != Z_OK) return NULL;
    z_publisher_options_t opts;
    z_publisher_options_default(&opts);
    opts.congestion_control = drop ? Z_CONGESTION_CONTROL_DROP : Z_CONGESTION_CONTROL_BLOCK;
    z_owned_publisher_t *pub = &publishers[publisher_count];
    if (z_declare_publisher(session, pub, z_view_keyexpr_loan(&ke), &opts) != Z_OK) return NULL;
    publisher_count++;
    return z_publisher_loan(pub);
}

// 1 once `pub` matches a subscriber, 0 when none did in PEER_WAIT_MS. main refuses -M in a build without
// Z_FEATURE_MATCHING, so the second arm is never reached there.
static int wait_for_match(const z_loaned_publisher_t *pub) {
#if Z_FEATURE_MATCHING == 1
    for (unsigned waited = 0; waited < PEER_WAIT_MS && !terminated; waited += 10) {
        z_matching_status_t status;
        if (z_publisher_get_matching_status(pub, &status) == Z_OK && status.matching) return 1;
        sleep_ms(10);
    }
    return 0;
#else
    (void)pub;
    return 0;
#endif
}

// The client side's publisher on `key`, ready for its first counted put, the same in both arms. As
// upstream's z_pub_thr does ("Timer for sub to prepare"), the server side's declarations are given
// SUB_PREPARE_MS after the open before the publisher is declared; then a peer is waited for, and with -M
// a matching subscriber. A zenoh-pico publisher does not send a put while it knows of no subscriber (its
// write filter), and returns success for it, so a loop started before the declaration arrived counts puts
// that went nowhere. NULL, with the reason printed, when the publisher is not ready.
static const z_loaned_publisher_t *client_publisher(const z_loaned_session_t *session, const struct options *o,
                                                    const char *key) {
    sleep_ms(SUB_PREPARE_MS);
    const z_loaned_publisher_t *pub = declare_publisher(session, key, o->drop);
    if (pub == NULL) {
        printf("perf_probe %s: unable to declare the publisher\n", o->role);
        return NULL;
    }
    if (!wait_for_peer(session)) {
        printf("perf_probe %s: no peer in %d ms\n", o->role, PEER_WAIT_MS);
        return NULL;
    }
    if (o->match && !wait_for_match(pub)) {
        printf("perf_probe %s: no subscriber matched the publisher in %d ms\n", o->role, PEER_WAIT_MS);
        return NULL;
    }
    return pub;
}

static int declare_subscriber(const z_loaned_session_t *session, const char *key,
                              void (*callback)(z_loaned_sample_t *, void *), void *context) {
    z_view_keyexpr_t ke;
    if (z_view_keyexpr_from_str(&ke, key) != Z_OK) return -1;
    z_owned_closure_sample_t closure;
    z_closure_sample(&closure, callback, drop_nothing, context);
    return z_declare_background_subscriber(session, z_view_keyexpr_loan(&ke), z_closure_sample_move(&closure),
                                           NULL) == Z_OK
               ? 0
               : -1;
}

static uint64_t sequence_of(const z_loaned_sample_t *sample) {
    uint8_t head[SEQ_BYTES] = {0};
    z_bytes_reader_t reader = z_bytes_get_reader(z_sample_payload(sample));
    z_bytes_reader_read(&reader, head, sizeof head);
    uint64_t seq;
    memcpy(&seq, head, sizeof seq);
    return seq;
}

// ---------------------------------------------------------------------------------------------------------
// pong
// ---------------------------------------------------------------------------------------------------------

static struct {
    const z_loaned_session_t *session;
    const z_loaned_publisher_t *pub;
    int batching;
    _Atomic uint64_t answered;
    _Atomic uint64_t first_cpu_ns;
    _Atomic uint64_t stop_cpu_ns;
    _Atomic int stopped;
} pong_state;

static void on_ping(z_loaned_sample_t *sample, void *context) {
    (void)context;
    if (atomic_load_explicit(&pong_state.answered, memory_order_relaxed) == 0) {
        uint64_t expected = 0;
        atomic_compare_exchange_strong(&pong_state.first_cpu_ns, &expected, cpu_ns());
    }
    z_owned_bytes_t payload;
    z_bytes_clone(&payload, z_sample_payload(sample));
    if (pong_state.batching) batch_start(pong_state.session);
    z_publisher_put(pong_state.pub, z_bytes_move(&payload), NULL);
    if (pong_state.batching) batch_stop(pong_state.session);
    atomic_fetch_add_explicit(&pong_state.answered, 1, memory_order_relaxed);
}

static void on_stop(z_loaned_sample_t *sample, void *context) {
    (void)sample;
    (void)context;
    // The time first and the flag after it: the main thread reads the time once it sees the flag.
    uint64_t expected = 0;
    if (atomic_compare_exchange_strong(&pong_state.stop_cpu_ns, &expected, cpu_ns())) {
        atomic_store(&pong_state.stopped, 1);
    }
}

static int run_pong(const z_loaned_session_t *session, const struct options *o) {
    pong_state.session = session;
    pong_state.pub = declare_publisher(session, KEY_PONG, o->drop);
    pong_state.batching = o->batching;
    if (pong_state.pub == NULL) {
        printf("perf_probe pong: unable to declare the publisher\n");
        return 1;
    }
    if (declare_subscriber(session, KEY_PING, on_ping, NULL) != 0 ||
        declare_subscriber(session, KEY_STOP, on_stop, NULL) != 0) {
        printf("perf_probe pong: unable to declare the subscribers\n");
        return 1;
    }
    while (!terminated && !atomic_load(&pong_state.stopped)) sleep_ms(5);
    int by_stop = atomic_load(&pong_state.stopped);
    uint64_t end = by_stop ? atomic_load(&pong_state.stop_cpu_ns) : cpu_ns();
    uint64_t start = atomic_load(&pong_state.first_cpu_ns);
    printf("perf_probe pong answered=%llu cpu_ns=%llu stopped_by=%s\n",
           (unsigned long long)atomic_load(&pong_state.answered),
           (unsigned long long)(start > 0 && end > start ? end - start : 0), by_stop ? "stop" : "signal");
    fflush(stdout);
    return 0;
}

// ---------------------------------------------------------------------------------------------------------
// ping
// ---------------------------------------------------------------------------------------------------------

static _Atomic uint64_t last_answer;

static void on_pong(z_loaned_sample_t *sample, void *context) {
    (void)context;
    atomic_store_explicit(&last_answer, sequence_of(sample), memory_order_release);
}

static int compare_u64(const void *a, const void *b) {
    const uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

// The nearest-rank percentile of `n` sorted values: the smallest value with at least p percent at or below it.
static uint64_t nearest_rank(const uint64_t *sorted, size_t n, unsigned p) {
    size_t rank = (size_t)(((uint64_t)p * n + 99U) / 100U);
    if (rank < 1) rank = 1;
    return sorted[rank - 1];
}

// One round trip of `seq`: its time in nanoseconds, or 0 when no answer came in `timeout_ns`.
static uint64_t round_trip(const z_loaned_session_t *session, const z_loaned_publisher_t *pub, uint8_t *buf,
                           const struct options *o, uint64_t seq, uint64_t timeout_ns) {
    memcpy(buf, &seq, sizeof seq);
    z_owned_bytes_t payload;
    if (z_bytes_copy_from_buf(&payload, buf, o->size) != Z_OK) return 0;
    const uint64_t t0 = now_ns();
    if (o->batching) batch_start(session);
    z_result_t rc = z_publisher_put(pub, z_bytes_move(&payload), NULL);
    if (o->batching) batch_stop(session);
    if (rc != Z_OK) return 0;
    for (unsigned spin = 0;; spin++) {
        if (atomic_load_explicit(&last_answer, memory_order_acquire) == seq) return now_ns() - t0;
        if ((spin & 255U) == 0 && now_ns() - t0 > timeout_ns) return 0;
    }
}

static int run_ping(const z_loaned_session_t *session, const struct options *o) {
    // The answers' subscriber first, so its declaration is on its way while the publisher is prepared.
    if (declare_subscriber(session, KEY_PONG, on_pong, NULL) != 0) {
        printf("perf_probe ping: unable to declare the subscriber\n");
        return 1;
    }
    const z_loaned_publisher_t *pub = client_publisher(session, o, KEY_PING);
    if (pub == NULL) return 1;
    const z_loaned_publisher_t *stop = declare_publisher(session, KEY_STOP, 0);
    if (stop == NULL) {
        printf("perf_probe ping: unable to declare the stop publisher\n");
        return 1;
    }
    uint8_t *buf = malloc(o->size);
    uint64_t *rtt = malloc(sizeof *rtt * (o->pings > 0 ? o->pings : 1));
    if (buf == NULL || rtt == NULL) {
        printf("perf_probe ping: out of memory\n");
        return 1;
    }
    memset(buf, 1, o->size);
    const uint64_t timeout_ns = (uint64_t)o->timeout_ms * 1000000ULL;
    uint64_t seq = 0, all = 0;
    const uint64_t cpu0 = cpu_ns();
    const uint64_t warm_end = now_ns() + (uint64_t)o->warmup_ms * 1000000ULL;
    while (now_ns() < warm_end && !terminated) {
        if (round_trip(session, pub, buf, o, ++seq, timeout_ns) > 0) all++;
    }
    size_t counted = 0;
    unsigned lost = 0;
    int aborted = 0;
    for (unsigned i = 0; i < o->pings && !terminated; i++) {
        uint64_t t = round_trip(session, pub, buf, o, ++seq, timeout_ns);
        if (t > 0) {
            rtt[counted++] = t;
            all++;
        } else if (++lost > o->pings / 10U) {
            aborted = 1;
            break;
        }
    }
    const uint64_t cpu1 = cpu_ns();
    uint64_t p50 = 0, p90 = 0, p99 = 0, lo = 0, hi = 0, mean = 0;
    if (counted > 0) {
        qsort(rtt, counted, sizeof *rtt, compare_u64);
        uint64_t sum = 0;
        for (size_t i = 0; i < counted; i++) sum += rtt[i];
        p50 = nearest_rank(rtt, counted, 50);
        p90 = nearest_rank(rtt, counted, 90);
        p99 = nearest_rank(rtt, counted, 99);
        lo = rtt[0];
        hi = rtt[counted - 1];
        mean = sum / counted;
    }
    printf("perf_probe ping round_trips=%zu lost=%u aborted=%d p50_ns=%llu p90_ns=%llu p99_ns=%llu min_ns=%llu "
           "max_ns=%llu mean_ns=%llu all_round_trips=%llu cpu_ns=%llu\n",
           counted, lost, aborted, (unsigned long long)p50, (unsigned long long)p90, (unsigned long long)p99,
           (unsigned long long)lo, (unsigned long long)hi, (unsigned long long)mean, (unsigned long long)all,
           (unsigned long long)(cpu1 - cpu0));
    fflush(stdout);
    // Three stops, apart: a datagram transport may lose one.
    for (int i = 0; i < 3; i++) {
        z_owned_bytes_t payload;
        z_bytes_copy_from_buf(&payload, buf, SEQ_BYTES);
        z_publisher_put(stop, z_bytes_move(&payload), NULL);
        sleep_ms(20);
    }
    free(rtt);
    free(buf);
    return 0;
}

// ---------------------------------------------------------------------------------------------------------
// sub
// ---------------------------------------------------------------------------------------------------------

static _Atomic uint64_t received_count;
static _Atomic uint64_t received_bytes;

static void on_thr(z_loaned_sample_t *sample, void *context) {
    (void)context;
    atomic_fetch_add_explicit(&received_bytes, z_bytes_len(z_sample_payload(sample)), memory_order_relaxed);
    atomic_fetch_add_explicit(&received_count, 1, memory_order_relaxed);
}

static int run_sub(const z_loaned_session_t *session, const struct options *o) {
    if (declare_subscriber(session, KEY_THR, on_thr, NULL) != 0) {
        printf("perf_probe sub: unable to declare the subscriber\n");
        return 1;
    }
    // The first sample starts the clock; a publisher that never came leaves no window to print.
    while (!terminated && atomic_load_explicit(&received_count, memory_order_relaxed) == 0) sleep_ms(1);
    if (!terminated) sleep_ms(o->warmup_ms);
    if (!terminated) {
        const uint64_t n0 = atomic_load(&received_count), b0 = atomic_load(&received_bytes);
        const uint64_t t0 = now_ns(), c0 = cpu_ns();
        sleep_ms(o->seconds * 1000U);
        const uint64_t n1 = atomic_load(&received_count), b1 = atomic_load(&received_bytes);
        const uint64_t t1 = now_ns(), c1 = cpu_ns();
        if (!terminated) {
            printf("perf_probe sub received=%llu bytes=%llu window_ns=%llu cpu_ns=%llu start_ns=%llu end_ns=%llu\n",
                   (unsigned long long)(n1 - n0), (unsigned long long)(b1 - b0), (unsigned long long)(t1 - t0),
                   (unsigned long long)(c1 - c0), (unsigned long long)t0, (unsigned long long)t1);
            fflush(stdout);
        }
    }
    while (!terminated) sleep_ms(5);
    printf("perf_probe sub total=%llu\n", (unsigned long long)atomic_load(&received_count));
    fflush(stdout);
    return 0;
}

// ---------------------------------------------------------------------------------------------------------
// pub
// ---------------------------------------------------------------------------------------------------------

static int run_pub(const z_loaned_session_t *session, const struct options *o) {
    const z_loaned_publisher_t *loaned = client_publisher(session, o, KEY_THR);
    if (loaned == NULL) return 1;
    uint8_t *buf = malloc(o->size);
    if (buf == NULL) {
        printf("perf_probe pub: out of memory\n");
        return 1;
    }
    memset(buf, 1, o->size);
    z_owned_bytes_t payload;
    if (z_bytes_copy_from_buf(&payload, buf, o->size) != Z_OK) {
        printf("perf_probe pub: unable to make the payload\n");
        return 1;
    }
    unsigned long long sent = 0, failed = 0;
    const uint64_t t0 = now_ns(), c0 = cpu_ns(), end = t0 + (uint64_t)o->seconds * 1000000000ULL;
    uint64_t t1 = t0;
    if (o->batching) batch_start(session);
    for (unsigned i = 0; !terminated; i++) {
        if ((i & 63U) == 0 && (t1 = now_ns()) >= end) break;
        z_owned_bytes_t p;
        z_bytes_clone(&p, z_bytes_loan(&payload));
        if (z_publisher_put(loaned, z_bytes_move(&p), NULL) == Z_OK) {
            sent++;
        } else {
            failed++;
        }
    }
    if (o->batching) batch_stop(session);
    const uint64_t c1 = cpu_ns();
    t1 = now_ns();
    printf("perf_probe pub sent=%llu failed=%llu elapsed_ns=%llu cpu_ns=%llu start_ns=%llu end_ns=%llu\n", sent,
           failed, (unsigned long long)(t1 - t0), (unsigned long long)(c1 - c0), (unsigned long long)t0,
           (unsigned long long)t1);
    fflush(stdout);
    z_bytes_drop(z_bytes_move(&payload));
    free(buf);
    return 0;
}

// ---------------------------------------------------------------------------------------------------------

int main(int argc, char **argv) {
    if (argc < 2) return usage();
    struct options o = {argv[1], 8, 20000, 3000, 100, 5, 0, 0, 0, NULL};
    z_owned_config_t config;
    z_config_default(&config);
    int opt;
    // The role is the first word; the options follow it, read as a command line of their own.
    while ((opt = getopt(argc - 1, argv + 1, "m:l:e:s:n:w:o:t:bdMT:")) != -1) {
        switch (opt) {
            case 'm':
                zp_config_insert(z_config_loan_mut(&config), Z_CONFIG_MODE_KEY, optarg);
                break;
            case 'l':
                zp_config_insert(z_config_loan_mut(&config), Z_CONFIG_LISTEN_KEY, optarg);
                break;
            case 'e':
                zp_config_insert(z_config_loan_mut(&config), Z_CONFIG_CONNECT_KEY, optarg);
                break;
            case 's':
                o.size = (size_t)strtoul(optarg, NULL, 10);
                break;
            case 'n':
                o.pings = (unsigned)strtoul(optarg, NULL, 10);
                break;
            case 'w':
                o.warmup_ms = (unsigned)strtoul(optarg, NULL, 10);
                break;
            case 'o':
                o.timeout_ms = (unsigned)strtoul(optarg, NULL, 10);
                break;
            case 't':
                o.seconds = (unsigned)strtoul(optarg, NULL, 10);
                break;
            case 'b':
                o.batching = 1;
                break;
            case 'd':
                o.drop = 1;
                break;
            case 'M':
                o.match = 1;
                break;
            case 'T':
                o.transport_name = optarg;
                break;
            default:
                return usage();
        }
    }
    const int ping = strcmp(o.role, "ping") == 0, pong = strcmp(o.role, "pong") == 0;
    const int pub = strcmp(o.role, "pub") == 0, sub = strcmp(o.role, "sub") == 0;
    if (!ping && !pong && !pub && !sub) return usage();
    if ((ping || pub) && o.size < SEQ_BYTES) {
        fprintf(stderr, "perf_probe: a payload is at least %d bytes (the sequence number)\n", SEQ_BYTES);
        return 2;
    }
#if Z_FEATURE_BATCHING != 1
    if (o.batching) {
        fprintf(stderr, "perf_probe: this library is built without Z_FEATURE_BATCHING, so -b has no window\n");
        return 2;
    }
#endif
#if Z_FEATURE_MATCHING != 1
    if (o.match) {
        fprintf(stderr, "perf_probe: this library is built without Z_FEATURE_MATCHING, so -M cannot be asked\n");
        return 2;
    }
#endif
    if (o.transport_name != NULL) {
#ifdef PERF_PROGRAM_TRANSPORT
        if (pt_attach(&config, o.transport_name) != 0) {
            printf("perf_probe %s: unable to attach the program's transport\n", o.role);
            return 1;
        }
#else
        fprintf(stderr, "perf_probe: -T needs a build with PERF_PROGRAM_TRANSPORT (wz only)\n");
        return 2;
#endif
    }

    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = on_terminate;
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGINT, &action, NULL);

    z_owned_session_t session;
    z_result_t opened = z_open(&session, z_config_move(&config), NULL);
    if (opened != Z_OK) {
        printf("perf_probe %s: unable to open the session (%d)\n", o.role, (int)opened);
        return 1;
    }
    const z_loaned_session_t *loaned = z_session_loan(&session);
    int rc = ping ? run_ping(loaned, &o) : pong ? run_pong(loaned, &o) : pub ? run_pub(loaned, &o) : run_sub(loaned, &o);
    // Closed first, so no callback runs while its publisher is dropped.
    z_close(z_session_loan_mut(&session), NULL);
    for (int i = 0; i < publisher_count; i++) z_publisher_drop(z_publisher_move(&publishers[i]));
    z_session_drop(z_session_move(&session));
#ifdef PERF_PROGRAM_TRANSPORT
    if (o.transport_name != NULL) wz_ext_transport_drop(wz_ext_transport_move(&pt.transport));
#endif
    return rc;
}

#else
int main(void) {
    printf("perf_probe: this zenoh-pico is built without publication, subscription or the multi-thread arm\n");
    return 2;
}
#endif
