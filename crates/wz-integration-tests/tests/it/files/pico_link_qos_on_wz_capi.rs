// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a pico program's QoS settings do on a link that is full, measured on wz's pico drop-in
//! with the real zenoh-pico as the control.
//!
//! ## The harness, and why it sits on the system's sockets
//!
//! One C program (`PROBE_SRC`) is compiled twice from the same text: against the real
//! `libzenohpico.so` and against wz's `libwz_capi_pico.so`, both through the reference header arm.
//! A run starts two processes of one build, a subscriber that listens and a publisher that dials,
//! and the publisher's link goes through a relay in this test process. The relay is what injects
//! the fault, so the control and the subject see the same fault from the same code: a transport
//! the program supplies (`wz_ext_transport_*`) is a wz door that zenoh-pico does not have, and a
//! fault injected there could not be given to the control at all.
//!
//! The control runs first in every test. A control that fails says the harness (or this host)
//! cannot carry the measurement, and nothing about wz; only a control that passes makes the
//! subject's verdict a statement about wz.
//!
//! ## Congestion control on a full stream
//!
//! zenoh defines the two strategies by what a message meets in a node whose queue is full:
//! `Drop` "may drop the message", `Block` "will wait for queue to progress"
//! (`commons/zenoh-protocol/src/core/mod.rs` @
//! `When transmitting a message in a node with a full queue, the node may drop the message.`).
//! A blocking message that finds no room within `wait_before_close` closes the transport
//! (`commons/zenoh-config/src/defaults.rs` @ `wait_before_close: 5000000,`), so every stall here
//! is released well inside five seconds.
//!
//! The relay stops reading what the publisher sends, so its socket and the relay's fill and the
//! link is full. The probe's filler thread then puts `Block` samples until one of them stays in
//! the call for 300 ms: the link is full and `Block` waits. While it waits the main thread puts
//! `Drop` samples for a second; each must return promptly and they must not all arrive. Then
//! the relay reads again, and every `Block` sample must arrive, in order.
//!
//! zenoh-pico implements `Drop` as a try-lock of the transmit mutex
//! (`vendor/zenoh-pico/src/transport/common/tx.c` @
//! `ret = _z_transport_tx_mutex_lock(ztc, cong_ctrl == Z_CONGESTION_CONTROL_BLOCK);`), so a
//! dropping put returns at once while another thread is in a blocking send, and a client's
//! socket is a blocking one, so a blocking put waits in the send. That is the configuration in
//! which its congestion control holds, and the control runs it. A pico PEER takes the peers'
//! mutex unconditionally first (`vendor/zenoh-pico/src/transport/common/tx.c` @
//! `_z_transport_peer_mutex_lock(ztc);`) and makes its socket non-blocking
//! (`vendor/zenoh-pico/src/transport/manager.c` @
//! `_Z_SET_IF_OK(ret, _z_socket_set_blocking(_z_link_get_socket(zl), false));`), and a stream
//! write that takes part of a frame fails the send (`vendor/zenoh-pico/src/link/link.c` @
//! `if (link_is_streamed && wb != n) {`): on a full link a peer's `Block` does not wait. The
//! pico peer run is therefore printed as the reference of that limit and not held; wz is held to
//! the definition in both modes.
//!
//! A red of the subject means: `full` false, a `Block` put did not wait on a full link; a long
//! `Drop` put, a dropping put waited for the link; every `Drop` sample delivered, nothing was
//! dropped; a `Block` sample missing, out of order or failed, the waiting put did not deliver.
//!
//! The probe's environment is held to the reference header arm (`PicoHeaderArm::MultiThreaded`),
//! whose wz build is the crate's default one.

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use wz_integration_tests::common::{
    compile_pico_source, zenoh_pico_include_dirs, zenoh_pico_library_dir, ChildGuard, PicoHeaderArm,
};

/// The probe, one source for both libraries. `argv`: `pub|sub <mode> listen|connect <endpoint>`.
///
/// It answers one line per command on stdin, after printing `ready` once its entities are
/// declared. Four streams, each with its own key and its own sequence numbers (the first eight
/// payload bytes, little endian): `drop` and `block` (8 KiB, reliable, the two congestion
/// controls), `rel` (64 B, reliable, an advanced publisher with sample-miss detection, read by
/// an advanced subscriber with a miss listener) and `be` (64 B, best effort).
///
/// Publisher commands: `match <stream> <ms>`, `peer <ms>`, `put <stream> <count> <interval_us>`,
/// `fill <ms>` (a thread puts `block` samples until one stays in the call for 300 ms),
/// `drop <ms> <interval_us>` (`drop` samples for that long), `unfill <ms>` (stop the filler).
/// Subscriber commands: `peer <ms>`, `report`. Both: `quit`.
const PROBE_SRC: &str = r##"
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "zenoh-pico.h"

#if !defined(Z_FEATURE_UNSTABLE_API) || Z_FEATURE_ADVANCED_PUBLICATION != 1 || \
    Z_FEATURE_ADVANCED_SUBSCRIPTION != 1 || Z_FEATURE_MATCHING != 1 || Z_FEATURE_MULTI_THREAD != 1
#error "the link probe needs the unstable API, the advanced plane, matching and the multi-threaded arm"
#endif

#define STREAMS 4
#define DROP_S 0
#define BLOCK_S 1
#define REL_S 2
#define BE_S 3
#define BIG_PAYLOAD 8192
#define SMALL_PAYLOAD 64
/* A blocking put that has been in the call this long is waiting for the link. */
#define FULL_US 300000ULL
#define SLOW_US 100000ULL

static const char *const STREAM_KEY[STREAMS] = {"qos/cc/drop", "qos/cc/block", "qos/rel", "qos/be"};
static const char *const STREAM_NAME[STREAMS] = {"drop", "block", "rel", "be"};
static const size_t STREAM_PAYLOAD[STREAMS] = {BIG_PAYLOAD, BIG_PAYLOAD, SMALL_PAYLOAD, SMALL_PAYLOAD};

static z_owned_session_t session;
static const z_loaned_session_t *zs = NULL;

static unsigned long long now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000ULL + (unsigned long long)ts.tv_nsec / 1000ULL;
}

static void sleep_us(unsigned long long us) {
    struct timespec nap = {(time_t)(us / 1000000ULL), (long)(us % 1000000ULL) * 1000L};
    while (nanosleep(&nap, &nap) != 0 && errno == EINTR) {
    }
}

static int stream_of(const char *name) {
    for (int i = 0; i < STREAMS; i++) {
        if (strcmp(name, STREAM_NAME[i]) == 0) {
            return i;
        }
    }
    return -1;
}

/* ---- the receiving side ---- */

typedef struct {
    unsigned long long received;
    long long first;
    long long last;
    unsigned long long disorder;
    unsigned long long gaps;
    long long last_gap_at;
} rx_t;

static pthread_mutex_t rx_lock = PTHREAD_MUTEX_INITIALIZER;
static rx_t rx[STREAMS];
static unsigned long long missed_total = 0;
static unsigned long long miss_events = 0;

static void record(int stream, long long seq) {
    pthread_mutex_lock(&rx_lock);
    rx_t *r = &rx[stream];
    r->received++;
    if (r->first < 0) {
        r->first = seq;
    }
    if (r->last >= 0 && seq <= r->last) {
        r->disorder++;
    } else {
        if (r->last >= 0 && seq > r->last + 1) {
            r->gaps++;
            r->last_gap_at = seq;
        }
        r->last = seq;
    }
    pthread_mutex_unlock(&rx_lock);
}

static void on_sample(z_loaned_sample_t *sample, void *context) {
    int stream = (int)(intptr_t)context;
    z_owned_slice_t slice;
    if (z_bytes_to_slice(z_sample_payload(sample), &slice) != Z_OK) {
        return;
    }
    const z_loaned_slice_t *view = z_slice_loan(&slice);
    const uint8_t *data = z_slice_data(view);
    if (data != NULL && z_slice_len(view) >= 8) {
        unsigned long long seq = 0;
        for (int i = 0; i < 8; i++) {
            seq |= (unsigned long long)data[i] << (8 * i);
        }
        record(stream, (long long)seq);
    }
    z_slice_drop(z_slice_move(&slice));
}

static void on_miss(const ze_miss_t *miss, void *context) {
    (void)context;
    pthread_mutex_lock(&rx_lock);
    missed_total += miss->nb;
    miss_events++;
    pthread_mutex_unlock(&rx_lock);
}

static z_owned_subscriber_t subs[STREAMS];
static int sub_declared[STREAMS];
static ze_owned_advanced_subscriber_t rel_sub;
static int rel_sub_declared = 0;

static int declare_subscribers(void) {
    for (int i = 0; i < STREAMS; i++) {
        z_view_keyexpr_t ke;
        if (z_view_keyexpr_from_str(&ke, STREAM_KEY[i]) != Z_OK) {
            return -1;
        }
        z_owned_closure_sample_t closure;
        z_closure_sample(&closure, on_sample, NULL, (void *)(intptr_t)i);
        if (i == REL_S) {
            ze_advanced_subscriber_options_t opts;
            ze_advanced_subscriber_options_default(&opts);
            if (ze_declare_advanced_subscriber(zs, &rel_sub, z_view_keyexpr_loan(&ke), z_closure_sample_move(&closure),
                                               &opts) != Z_OK) {
                return -1;
            }
            rel_sub_declared = 1;
            ze_owned_closure_miss_t miss;
            ze_closure_miss(&miss, on_miss, NULL, NULL);
            if (ze_advanced_subscriber_declare_background_sample_miss_listener(ze_advanced_subscriber_loan(&rel_sub),
                                                                               ze_closure_miss_move(&miss)) != Z_OK) {
                return -1;
            }
        } else {
            if (z_declare_subscriber(zs, &subs[i], z_view_keyexpr_loan(&ke), z_closure_sample_move(&closure), NULL) !=
                Z_OK) {
                return -1;
            }
            sub_declared[i] = 1;
        }
    }
    return 0;
}

static void report(void) {
    rx_t copy[STREAMS];
    pthread_mutex_lock(&rx_lock);
    memcpy(copy, rx, sizeof copy);
    unsigned long long missed = missed_total;
    unsigned long long events = miss_events;
    pthread_mutex_unlock(&rx_lock);
    for (int i = 0; i < STREAMS; i++) {
        printf("stream %s received=%llu first=%lld last=%lld disorder=%llu gaps=%llu last_gap_at=%lld\n", STREAM_NAME[i],
               copy[i].received, copy[i].first, copy[i].last, copy[i].disorder, copy[i].gaps, copy[i].last_gap_at);
    }
    printf("missed total=%llu events=%llu\n", missed, events);
    printf("end\n");
}

/* ---- the sending side ---- */

static z_owned_publisher_t pubs[STREAMS];
static int pub_declared[STREAMS];
static ze_owned_advanced_publisher_t rel_pub;
static int rel_pub_declared = 0;
static unsigned long long next_seq[STREAMS];

static int declare_publishers(void) {
    for (int i = 0; i < STREAMS; i++) {
        z_view_keyexpr_t ke;
        if (z_view_keyexpr_from_str(&ke, STREAM_KEY[i]) != Z_OK) {
            return -1;
        }
        if (i == REL_S) {
            ze_advanced_publisher_options_t opts;
            ze_advanced_publisher_options_default(&opts);
            opts.publisher_options.congestion_control = Z_CONGESTION_CONTROL_DROP;
            opts.publisher_options.reliability = Z_RELIABILITY_RELIABLE;
            ze_advanced_publisher_sample_miss_detection_options_default(&opts.sample_miss_detection);
            opts.sample_miss_detection.is_enabled = true;
            if (ze_declare_advanced_publisher(zs, &rel_pub, z_view_keyexpr_loan(&ke), &opts) != Z_OK) {
                return -1;
            }
            rel_pub_declared = 1;
        } else {
            z_publisher_options_t opts;
            z_publisher_options_default(&opts);
            opts.congestion_control = i == BLOCK_S ? Z_CONGESTION_CONTROL_BLOCK : Z_CONGESTION_CONTROL_DROP;
            opts.reliability = i == BE_S ? Z_RELIABILITY_BEST_EFFORT : Z_RELIABILITY_RELIABLE;
            if (z_declare_publisher(zs, &pubs[i], z_view_keyexpr_loan(&ke), &opts) != Z_OK) {
                return -1;
            }
            pub_declared[i] = 1;
        }
    }
    return 0;
}

static z_result_t put_one(int stream, unsigned long long seq) {
    uint8_t buf[BIG_PAYLOAD];
    size_t len = STREAM_PAYLOAD[stream];
    memset(buf, 0x5a, len);
    for (int i = 0; i < 8; i++) {
        buf[i] = (uint8_t)(seq >> (8 * i));
    }
    z_owned_bytes_t payload;
    z_result_t rc = z_bytes_copy_from_buf(&payload, buf, len);
    if (rc != Z_OK) {
        return rc;
    }
    if (stream == REL_S) {
        return ze_advanced_publisher_put(ze_advanced_publisher_loan(&rel_pub), z_bytes_move(&payload), NULL);
    }
    return z_publisher_put(z_publisher_loan(&pubs[stream]), z_bytes_move(&payload), NULL);
}

static void count_peer(const z_id_t *id, void *context) {
    (void)id;
    (*(int *)context)++;
}

static int wait_peer(unsigned long long timeout_ms) {
    unsigned long long deadline = now_us() + timeout_ms * 1000ULL;
    do {
        int peers = 0;
        z_owned_closure_zid_t closure;
        z_closure_zid(&closure, count_peer, NULL, &peers);
        z_info_peers_zid(zs, z_closure_zid_move(&closure));
        if (peers > 0) {
            return 1;
        }
        sleep_us(10000);
    } while (now_us() < deadline);
    return 0;
}

static int wait_match(int stream, unsigned long long timeout_ms) {
    if (stream < 0 || stream == REL_S || !pub_declared[stream]) {
        return 0;
    }
    unsigned long long deadline = now_us() + timeout_ms * 1000ULL;
    do {
        z_matching_status_t status;
        if (z_publisher_get_matching_status(z_publisher_loan(&pubs[stream]), &status) == Z_OK && status.matching) {
            return 1;
        }
        sleep_us(10000);
    } while (now_us() < deadline);
    return 0;
}

static void put_many(int stream, unsigned long long count, unsigned long long interval_us) {
    unsigned long long ok = 0, err = 0, max = 0;
    for (unsigned long long i = 0; i < count; i++) {
        unsigned long long start = now_us();
        z_result_t rc = put_one(stream, next_seq[stream]++);
        unsigned long long took = now_us() - start;
        if (rc == Z_OK) {
            ok++;
        } else {
            err++;
        }
        if (took > max) {
            max = took;
        }
        if (interval_us > 0 && i + 1 < count) {
            sleep_us(interval_us);
        }
    }
    printf("put %s sent=%llu ok=%llu err=%llu max_us=%llu next=%llu\n", STREAM_NAME[stream], count, ok, err, max,
           next_seq[stream]);
}

/* The filler: blocking puts on `block`, one after another, until told to stop. */
static atomic_int filler_stop;
static atomic_int filler_running;
static atomic_int filler_done;
static atomic_ullong filler_since;
static atomic_ullong filler_started;
static atomic_ullong filler_ok;
static atomic_ullong filler_err;
static atomic_ullong filler_max;
static pthread_t filler;

static void *filler_main(void *arg) {
    (void)arg;
    while (!atomic_load(&filler_stop)) {
        unsigned long long seq = next_seq[BLOCK_S]++;
        unsigned long long start = now_us();
        atomic_store(&filler_since, start);
        atomic_fetch_add(&filler_started, 1ULL);
        z_result_t rc = put_one(BLOCK_S, seq);
        unsigned long long took = now_us() - start;
        atomic_store(&filler_since, 0ULL);
        if (rc == Z_OK) {
            atomic_fetch_add(&filler_ok, 1ULL);
        } else {
            atomic_fetch_add(&filler_err, 1ULL);
            sleep_us(200);
        }
        if (took > atomic_load(&filler_max)) {
            atomic_store(&filler_max, took);
        }
    }
    atomic_store(&filler_done, 1);
    return NULL;
}

static void fill(unsigned long long timeout_ms) {
    if (atomic_load(&filler_running) || !pub_declared[BLOCK_S]) {
        printf("error fill cannot start\n");
        return;
    }
    atomic_store(&filler_stop, 0);
    atomic_store(&filler_done, 0);
    atomic_store(&filler_since, 0ULL);
    atomic_store(&filler_started, 0ULL);
    atomic_store(&filler_ok, 0ULL);
    atomic_store(&filler_err, 0ULL);
    atomic_store(&filler_max, 0ULL);
    if (pthread_create(&filler, NULL, filler_main, NULL) != 0) {
        printf("error fill thread\n");
        return;
    }
    atomic_store(&filler_running, 1);
    unsigned long long start = now_us();
    unsigned long long deadline = start + timeout_ms * 1000ULL;
    int full = 0;
    for (;;) {
        unsigned long long since = atomic_load(&filler_since);
        unsigned long long now = now_us();
        if (since != 0 && now > since && now - since >= FULL_US) {
            full = 1;
            break;
        }
        if (now >= deadline) {
            break;
        }
        sleep_us(1000);
    }
    printf("fill full=%d after_ms=%llu started=%llu ok=%llu err=%llu\n", full, (now_us() - start) / 1000ULL,
           (unsigned long long)atomic_load(&filler_started), (unsigned long long)atomic_load(&filler_ok),
           (unsigned long long)atomic_load(&filler_err));
}

static void drop_for(unsigned long long duration_ms, unsigned long long interval_us) {
    unsigned long long sent = 0, ok = 0, err = 0, max = 0, slow = 0;
    unsigned long long deadline = now_us() + duration_ms * 1000ULL;
    while (now_us() < deadline) {
        unsigned long long start = now_us();
        z_result_t rc = put_one(DROP_S, next_seq[DROP_S]++);
        unsigned long long took = now_us() - start;
        sent++;
        if (rc == Z_OK) {
            ok++;
        } else {
            err++;
        }
        if (took > max) {
            max = took;
        }
        if (took > SLOW_US) {
            slow++;
        }
        if (interval_us > 0) {
            sleep_us(interval_us);
        }
    }
    printf("drop sent=%llu ok=%llu err=%llu max_us=%llu slow=%llu next=%llu\n", sent, ok, err, max, slow,
           next_seq[DROP_S]);
}

static void unfill(unsigned long long timeout_ms) {
    if (!atomic_load(&filler_running)) {
        printf("error unfill idle\n");
        return;
    }
    atomic_store(&filler_stop, 1);
    unsigned long long deadline = now_us() + timeout_ms * 1000ULL;
    while (!atomic_load(&filler_done) && now_us() < deadline) {
        sleep_us(1000);
    }
    int done = atomic_load(&filler_done);
    if (done) {
        pthread_join(filler, NULL);
        atomic_store(&filler_running, 0);
    }
    printf("unfill done=%d started=%llu ok=%llu err=%llu max_us=%llu next=%llu\n", done,
           (unsigned long long)atomic_load(&filler_started), (unsigned long long)atomic_load(&filler_ok),
           (unsigned long long)atomic_load(&filler_err), (unsigned long long)atomic_load(&filler_max),
           done ? next_seq[BLOCK_S] : 0ULL);
}

/* ---- the command loop ---- */

static void serve(int is_pub) {
    char line[256];
    printf("ready\n");
    while (fgets(line, sizeof line, stdin) != NULL) {
        char cmd[32] = {0};
        char word[32] = {0};
        unsigned long long a = 0, b = 0;
        int n = sscanf(line, "%31s %31s %llu %llu", cmd, word, &a, &b);
        if (n < 1) {
            continue;
        }
        unsigned long long first = n >= 2 ? strtoull(word, NULL, 10) : 0ULL;
        if (strcmp(cmd, "quit") == 0) {
            return;
        } else if (strcmp(cmd, "peer") == 0 && n >= 2) {
            printf("peer %d\n", wait_peer(first));
        } else if (!is_pub && strcmp(cmd, "report") == 0) {
            report();
        } else if (is_pub && strcmp(cmd, "match") == 0 && n >= 3) {
            printf("match %s %d\n", word, wait_match(stream_of(word), a));
        } else if (is_pub && strcmp(cmd, "put") == 0 && n >= 4 && stream_of(word) >= 0) {
            int stream = stream_of(word);
            if (stream == BLOCK_S && atomic_load(&filler_running)) {
                printf("error put block while the filler runs\n");
            } else {
                put_many(stream, a, b);
            }
        } else if (is_pub && strcmp(cmd, "fill") == 0 && n >= 2) {
            fill(first);
        } else if (is_pub && strcmp(cmd, "drop") == 0 && n >= 3) {
            drop_for(first, a);
        } else if (is_pub && strcmp(cmd, "unfill") == 0 && n >= 2) {
            unfill(first);
        } else {
            printf("error unknown %s\n", cmd);
        }
    }
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc != 5 || (strcmp(argv[1], "pub") != 0 && strcmp(argv[1], "sub") != 0)) {
        fprintf(stderr, "usage: %s pub|sub <mode> listen|connect <endpoint>\n", argv[0]);
        return 2;
    }
    int is_pub = strcmp(argv[1], "pub") == 0;
    for (int i = 0; i < STREAMS; i++) {
        rx[i].first = -1;
        rx[i].last = -1;
        rx[i].last_gap_at = -1;
    }
    z_owned_config_t config;
    z_config_default(&config);
    zp_config_insert(z_config_loan_mut(&config), Z_CONFIG_MODE_KEY, argv[2]);
    zp_config_insert(z_config_loan_mut(&config),
                     strcmp(argv[3], "listen") == 0 ? Z_CONFIG_LISTEN_KEY : Z_CONFIG_CONNECT_KEY, argv[4]);
    z_result_t opened = z_open(&session, z_config_move(&config), NULL);
    if (opened != Z_OK) {
        printf("error open %d\n", (int)opened);
        return 1;
    }
    zs = z_session_loan(&session);
    if ((is_pub ? declare_publishers() : declare_subscribers()) != 0) {
        printf("error declare\n");
        fflush(stdout);
        _exit(1);
    }
    serve(is_pub);
    if (atomic_load(&filler_running) && !atomic_load(&filler_done)) {
        /* A put still inside the library: nothing it uses may be dropped under it. */
        printf("bye unclean\n");
        fflush(stdout);
        _exit(3);
    }
    if (atomic_load(&filler_running)) {
        pthread_join(filler, NULL);
    }
    for (int i = 0; i < STREAMS; i++) {
        if (pub_declared[i]) {
            z_publisher_drop(z_publisher_move(&pubs[i]));
        }
        if (sub_declared[i]) {
            z_subscriber_drop(z_subscriber_move(&subs[i]));
        }
    }
    if (rel_pub_declared) {
        ze_advanced_publisher_drop(ze_advanced_publisher_move(&rel_pub));
    }
    if (rel_sub_declared) {
        ze_advanced_subscriber_drop(ze_advanced_subscriber_move(&rel_sub));
    }
    z_close(z_session_loan_mut(&session), NULL);
    z_session_drop(z_session_move(&session));
    printf("bye\n");
    return 0;
}
"##;

/// How long a `Drop` put may take on a full link and still count as having returned. Upstream's
/// `wait_before_drop` is one millisecond; this leaves the scheduler a quarter of a second.
const DROP_RETURNS_WITHIN_US: u64 = 250_000;

/// How long the waiting `Block` put must have waited: it entered the call at least 300 ms before
/// the filler reported the link full, and the `Drop` phase that follows lasts `DROP_PHASE_MS`.
const BLOCK_WAITED_AT_LEAST_US: u64 = 1_000_000;

/// How long the publisher puts `Drop` samples while the link is full.
const DROP_PHASE_MS: u64 = 1_000;

/// The pause between two of those puts.
const DROP_INTERVAL_US: u64 = 1_000;

/// How many lines of a probe's stderr a failure quotes.
const STDERR_TAIL: usize = 60;

/// The two builds of the probe, and the directory that holds them.
struct Probes {
    _dir: tempfile::TempDir,
    pico: PathBuf,
    wz: PathBuf,
}

impl Probes {
    /// Compile the probe against the real zenoh-pico and against wz's drop-in, through the same
    /// header arm. A probe that does not build is a hard failure, never a skip.
    fn build() -> Self {
        let dir = tempfile::tempdir().expect("a directory for the probe");
        let src = dir.path().join("link_qos_probe.c");
        std::fs::write(&src, PROBE_SRC).expect("write the probe");
        let pico = compile_pico_source(
            &src,
            dir.path(),
            &zenoh_pico_include_dirs(),
            &zenoh_pico_library_dir(),
            "zenohpico",
        )
        .unwrap_or_else(|diag| {
            panic!("the probe does not build against the real zenoh-pico\n{diag}")
        });
        let arm = PicoHeaderArm::MultiThreaded;
        let cdylib = arm.wz_cdylib();
        let wz = compile_pico_source(
            &src,
            dir.path(),
            &arm.include_dirs(),
            cdylib.parent().expect("the cdylib has a directory"),
            "wz_capi_pico",
        )
        .unwrap_or_else(|diag| panic!("the probe does not build against wz's drop-in\n{diag}"));
        Self {
            _dir: dir,
            pico,
            wz,
        }
    }
}

/// One running probe: its stdin, the lines of its stdout as they come, and the tail of its stderr.
struct Probe {
    label: String,
    guard: ChildGuard,
    stdin: ChildStdin,
    lines: Receiver<String>,
    transcript: Arc<Mutex<Vec<String>>>,
    stderr: Arc<Mutex<VecDeque<String>>>,
}

impl Probe {
    /// Start `exe` with `args` and return once it has printed `ready`.
    fn spawn(exe: &Path, args: &[&str], label: String) -> Result<Self, String> {
        let mut child = Command::new(exe)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("{label}: cannot start {}: {e}", exe.display()))?;
        let stdin = child.stdin.take().expect("a piped stdin");
        let stdout = child.stdout.take().expect("a piped stdout");
        let stderr = child.stderr.take().expect("a piped stderr");
        let (tx, lines) = channel();
        let transcript = Arc::new(Mutex::new(Vec::new()));
        let kept = Arc::clone(&transcript);
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                kept.lock().expect("the transcript lock").push(line.clone());
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let tail = Arc::new(Mutex::new(VecDeque::new()));
        let kept = Arc::clone(&tail);
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                let mut tail = kept.lock().expect("the stderr lock");
                if tail.len() == STDERR_TAIL {
                    tail.pop_front();
                }
                tail.push_back(line);
            }
        });
        let mut probe = Self {
            label: label.clone(),
            guard: ChildGuard::wrap(label, child),
            stdin,
            lines,
            transcript,
            stderr: tail,
        };
        probe.wait_for("ready", Duration::from_secs(30))?;
        Ok(probe)
    }

    /// Why this probe failed, with what it printed.
    fn failure(&self, why: &str) -> String {
        let transcript = self.transcript.lock().expect("the transcript lock");
        let from = transcript.len().saturating_sub(40);
        let stderr = self.stderr.lock().expect("the stderr lock");
        format!(
            "{}: {why}\n--- its last stdout lines ---\n{}\n--- its last stderr lines ---\n{}",
            self.label,
            transcript[from..].join("\n"),
            stderr.iter().cloned().collect::<Vec<_>>().join("\n")
        )
    }

    fn send(&mut self, command: &str) -> Result<(), String> {
        writeln!(self.stdin, "{command}")
            .and_then(|()| self.stdin.flush())
            .map_err(|e| self.failure(&format!("cannot be told `{command}`: {e}")))
    }

    /// The next line that starts with `prefix`, within `within`. A line that starts with `error`
    /// ends the wait.
    fn wait_for(&mut self, prefix: &str, within: Duration) -> Result<String, String> {
        let deadline = Instant::now() + within;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(line) if line.starts_with(prefix) => return Ok(line),
                Ok(line) if line.starts_with("error") => {
                    return Err(
                        self.failure(&format!("answered `{line}` where `{prefix}` was awaited"))
                    )
                }
                Ok(_) => {}
                Err(RecvTimeoutError::Timeout) => {
                    return Err(
                        self.failure(&format!("printed no `{prefix}` line within {within:?}"))
                    )
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(self.failure(&format!("ended before printing `{prefix}`")))
                }
            }
        }
    }

    fn ask(&mut self, command: &str, prefix: &str, within: Duration) -> Result<String, String> {
        self.send(command)?;
        self.wait_for(prefix, within)
    }

    /// What the subscriber has received so far.
    fn report(&mut self) -> Result<Report, String> {
        self.send("report")?;
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut lines = Vec::new();
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(line) if line == "end" => break,
                Ok(line) => lines.push(line),
                Err(_) => return Err(self.failure("did not finish its report")),
            }
        }
        Report::parse(&lines).map_err(|why| self.failure(&why))
    }

    /// Ask the probe to end, and end it if it does not within five seconds.
    fn quit(mut self) {
        let _ = writeln!(self.stdin, "quit").and_then(|()| self.stdin.flush());
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if matches!(self.guard.child_mut().try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// `key=value` out of a line of the probe's.
fn field<T: std::str::FromStr>(line: &str, key: &str) -> Option<T> {
    line.split_whitespace()
        .find_map(|word| word.strip_prefix(key)?.strip_prefix('=')?.parse().ok())
}

fn need<T: std::str::FromStr>(line: &str, key: &str) -> Result<T, String> {
    field(line, key).ok_or_else(|| format!("`{line}` carries no `{key}=`"))
}

/// What a subscriber received on one stream.
#[derive(Clone, Copy, Debug, Default)]
struct Rx {
    received: u64,
    last: i64,
    /// Samples whose number was not above the last one received: a duplicate or a reorder.
    disorder: u64,
}

#[derive(Clone, Debug, Default)]
struct Report {
    drop: Rx,
    block: Rx,
}

impl Report {
    fn parse(lines: &[String]) -> Result<Self, String> {
        let mut report = Self::default();
        for line in lines {
            let Some(rest) = line.strip_prefix("stream ") else {
                continue;
            };
            let rx = Rx {
                received: need(line, "received")?,
                last: need(line, "last")?,
                disorder: need(line, "disorder")?,
            };
            match rest.split_whitespace().next() {
                Some("drop") => report.drop = rx,
                Some("block") => report.block = rx,
                Some("rel" | "be") => {}
                _ => return Err(format!("a report line of no stream: `{line}`")),
            }
        }
        Ok(report)
    }

    /// Everything counted, so a report that moved is told from one that did not.
    fn total(&self) -> u64 {
        self.drop.received + self.block.received
    }
}

/// Read the subscriber until `done` holds, or until nothing it counts has moved for three seconds,
/// or `within` has passed; the last report either way.
fn settle(
    sub: &mut Probe,
    done: impl Fn(&Report) -> bool,
    within: Duration,
) -> Result<Report, String> {
    let start = Instant::now();
    let mut last = sub.report()?;
    let mut moved = Instant::now();
    loop {
        if done(&last) || start.elapsed() >= within || moved.elapsed() >= Duration::from_secs(3) {
            return Ok(last);
        }
        std::thread::sleep(Duration::from_millis(200));
        let now = sub.report()?;
        if now.total() != last.total() {
            moved = Instant::now();
        }
        last = now;
    }
}

/// Read the subscriber until `done` holds; an error when it does not within `within`.
fn wait_until(
    sub: &mut Probe,
    done: impl Fn(&Report) -> bool,
    within: Duration,
) -> Result<Report, String> {
    let deadline = Instant::now() + within;
    loop {
        let report = sub.report()?;
        if done(&report) {
            return Ok(report);
        }
        if Instant::now() >= deadline {
            return Err(format!("the subscriber's report stayed at {report:?}"));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// A relay between a dialler and a listener on the loopback: every connection it accepts is
/// carried to `upstream`. It can stop reading what the dialler sends (the link fills, as one to a
/// receiver that does not read does) and cut every connection it carries (both ends see it close).
struct StreamProxy {
    port: u16,
    shared: Arc<ProxyShared>,
    acceptor: Option<JoinHandle<()>>,
}

struct ProxyShared {
    upstream: u16,
    stalled: AtomicBool,
    stop: AtomicBool,
    accepted: AtomicUsize,
    /// A handle on each socket of each connection carried, for the cut.
    live: Mutex<Vec<TcpStream>>,
}

impl StreamProxy {
    fn start(upstream: u16) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind the relay");
        listener
            .set_nonblocking(true)
            .expect("a relay listener that can be polled");
        let port = listener.local_addr().expect("the relay's address").port();
        let shared = Arc::new(ProxyShared {
            upstream,
            stalled: AtomicBool::new(false),
            stop: AtomicBool::new(false),
            accepted: AtomicUsize::new(0),
            live: Mutex::new(Vec::new()),
        });
        let acceptor = {
            let shared = Arc::clone(&shared);
            std::thread::spawn(move || accept_loop(&listener, &shared))
        };
        Self {
            port,
            shared,
            acceptor: Some(acceptor),
        }
    }

    /// Stop (or resume) reading what the dialler sends.
    fn stall(&self, stalled: bool) {
        self.shared.stalled.store(stalled, Ordering::SeqCst);
    }
}

impl Drop for StreamProxy {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        for socket in self.shared.live.lock().expect("the relay lock").drain(..) {
            let _ = socket.shutdown(Shutdown::Both);
        }
        if let Some(acceptor) = self.acceptor.take() {
            let _ = acceptor.join();
        }
    }
}

fn accept_loop(listener: &TcpListener, shared: &Arc<ProxyShared>) {
    while !shared.stop.load(Ordering::SeqCst) {
        let client = match listener.accept() {
            Ok((client, _)) => client,
            Err(_) => {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
        };
        if client.set_nonblocking(false).is_err() {
            continue;
        }
        // A dial while the listener is not there is closed, as the listener's host would.
        let Ok(server) = TcpStream::connect((Ipv4Addr::LOCALHOST, shared.upstream)) else {
            continue;
        };
        let _ = client.set_nodelay(true);
        let _ = server.set_nodelay(true);
        let clones = (
            client.try_clone(),
            server.try_clone(),
            client.try_clone(),
            server.try_clone(),
        );
        let (Ok(client_keep), Ok(server_keep), Ok(client_tx), Ok(server_tx)) = clones else {
            continue;
        };
        shared
            .live
            .lock()
            .expect("the relay lock")
            .extend([client_keep, server_keep]);
        shared.accepted.fetch_add(1, Ordering::SeqCst);
        let up = Arc::clone(shared);
        std::thread::spawn(move || pump(client, server_tx, &up, true));
        let down = Arc::clone(shared);
        std::thread::spawn(move || pump(server, client_tx, &down, false));
    }
}

/// Carry bytes from `from` to `to` until either closes. The dialler's direction is the one the
/// stall stops: while it holds, nothing is read from the dialler.
fn pump(mut from: TcpStream, mut to: TcpStream, shared: &ProxyShared, stallable: bool) {
    if from
        .set_read_timeout(Some(Duration::from_millis(20)))
        .is_err()
    {
        return;
    }
    let mut buf = [0u8; 64 * 1024];
    while !shared.stop.load(Ordering::SeqCst) {
        if stallable && shared.stalled.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(5));
            continue;
        }
        match from.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if to.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) => {}
            Err(_) => break,
        }
    }
    let _ = to.shutdown(Shutdown::Write);
}

/// What one congestion run measured, on one library in one mode.
#[derive(Debug, Default)]
struct Congestion {
    run: String,
    /// A `Block` put stayed in the call for 300 ms while the relay read nothing.
    full: bool,
    fill_after_ms: u64,
    drop_sent: u64,
    drop_ok: u64,
    drop_max_us: u64,
    /// `Drop` samples of the full-link phase that reached the subscriber.
    drop_delivered: u64,
    drop_disorder: u64,
    /// The filler ended once the link drained.
    unfilled: bool,
    block_ok: u64,
    block_err: u64,
    block_max_us: u64,
    block_next: u64,
    /// The filler's `Block` samples that reached the subscriber.
    block_delivered: u64,
    block_last: i64,
    block_disorder: u64,
}

/// A subscriber that listens and a publisher in `mode` that dials it through the relay; the
/// relay stops reading, the publisher fills the link with `Block` puts and puts `Drop` samples
/// while it is full, and the relay reads again.
fn congestion_run(exe: &Path, library: &str, mode: &str) -> Result<Congestion, String> {
    let run = format!("{library} {mode}");
    let sub_port = wz_runtime_tokio_test_support::free_port();
    let mut sub = Probe::spawn(
        exe,
        &[
            "sub",
            "peer",
            "listen",
            &format!("tcp/127.0.0.1:{sub_port}"),
        ],
        format!("{run} subscriber"),
    )?;
    let proxy = StreamProxy::start(sub_port);
    let mut publisher = Probe::spawn(
        exe,
        &[
            "pub",
            mode,
            "connect",
            &format!("tcp/127.0.0.1:{}", proxy.port),
        ],
        format!("{run} publisher"),
    )?;
    for stream in ["drop", "block"] {
        let line = publisher.ask(
            &format!("match {stream} 15000"),
            "match",
            Duration::from_secs(20),
        )?;
        if !line.ends_with(" 1") {
            return Err(format!(
                "{run}: the {stream} publisher never matched the subscriber (`{line}`)"
            ));
        }
    }
    publisher.ask("put drop 1 0", "put drop", Duration::from_secs(10))?;
    publisher.ask("put block 1 0", "put block", Duration::from_secs(10))?;
    let warm = wait_until(
        &mut sub,
        |r| r.drop.received >= 1 && r.block.received >= 1,
        Duration::from_secs(10),
    )
    .map_err(|e| format!("{run}: a put of each publisher did not cross the open link: {e}"))?;

    proxy.stall(true);
    let fill = publisher.ask("fill 10000", "fill", Duration::from_secs(20))?;
    publisher.send(&format!("drop {DROP_PHASE_MS} {DROP_INTERVAL_US}"))?;
    // The stall ends once the phase is over, or two seconds past its end when a `Drop` put does
    // not return: such a put then reports how long it waited instead of hanging the run.
    let early = publisher.wait_for("drop", Duration::from_millis(DROP_PHASE_MS + 2_000));
    proxy.stall(false);
    let dropped = match early {
        Ok(line) => line,
        Err(_) => publisher.wait_for("drop", Duration::from_secs(20))?,
    };
    let unfill = publisher.ask("unfill 15000", "unfill", Duration::from_secs(20))?;
    let block_next: u64 = need(&unfill, "next")?;
    let wanted_last = i64::try_from(block_next).unwrap_or(i64::MAX) - 1;
    let report = settle(
        &mut sub,
        |r| r.block.last >= wanted_last,
        Duration::from_secs(20),
    )?;
    let outcome = Congestion {
        run,
        full: field::<u8>(&fill, "full") == Some(1),
        fill_after_ms: need(&fill, "after_ms")?,
        drop_sent: need(&dropped, "sent")?,
        drop_ok: need(&dropped, "ok")?,
        drop_max_us: need(&dropped, "max_us")?,
        drop_delivered: report.drop.received.saturating_sub(warm.drop.received),
        drop_disorder: report.drop.disorder,
        unfilled: field::<u8>(&unfill, "done") == Some(1),
        block_ok: need(&unfill, "ok")?,
        block_err: need(&unfill, "err")?,
        block_max_us: need(&unfill, "max_us")?,
        block_next,
        block_delivered: report.block.received.saturating_sub(warm.block.received),
        block_last: report.block.last,
        block_disorder: report.block.disorder,
    };
    publisher.quit();
    sub.quit();
    Ok(outcome)
}

/// Each way `o` departs from zenoh's definition of the two strategies on a full link.
fn congestion_findings(o: &Congestion) -> Vec<String> {
    let mut found = Vec::new();
    if !o.full {
        found.push(format!(
            "no Block put stayed in the call for 300 ms within {} ms of the relay stopping: \
             Block did not wait for the full link",
            o.fill_after_ms
        ));
    }
    if o.drop_sent == 0 {
        found.push("no Drop put was made while the link was full".to_owned());
    }
    if o.drop_max_us >= DROP_RETURNS_WITHIN_US {
        found.push(format!(
            "a Drop put took {} ms on the full link: it waited for room instead of dropping",
            o.drop_max_us / 1_000
        ));
    }
    if o.drop_sent > 0 && o.drop_delivered >= o.drop_sent {
        found.push(format!(
            "all {} Drop samples put while the link was full were delivered ({} puts answered \
             Z_OK): none was dropped",
            o.drop_sent, o.drop_ok
        ));
    }
    if o.drop_disorder != 0 {
        found.push(format!(
            "{} Drop samples arrived out of order or twice",
            o.drop_disorder
        ));
    }
    if !o.unfilled {
        found.push("the filler's Block put never returned after the link drained".to_owned());
    }
    if o.block_err != 0 {
        found.push(format!("{} Block puts failed", o.block_err));
    }
    if o.block_max_us < BLOCK_WAITED_AT_LEAST_US {
        found.push(format!(
            "the longest Block put took {} ms: none waited out the full link",
            o.block_max_us / 1_000
        ));
    }
    if o.block_delivered != o.block_ok
        || o.block_last + 1 != i64::try_from(o.block_next).unwrap_or(i64::MAX)
    {
        found.push(format!(
            "{} of {} Block samples arrived, the last numbered {} of {}: a waiting put did \
             not deliver",
            o.block_delivered,
            o.block_ok,
            o.block_last,
            o.block_next.saturating_sub(1)
        ));
    }
    if o.block_disorder != 0 {
        found.push(format!(
            "{} Block samples arrived out of order or twice",
            o.block_disorder
        ));
    }
    found
}

fn assert_congestion_holds(o: &Congestion, role: &str) {
    let found = congestion_findings(o);
    assert!(
        found.is_empty(),
        "{role} ({}): congestion control departs from zenoh's definition on a full link:\n  {}\n{o:#?}",
        o.run,
        found.join("\n  ")
    );
}

/// The control: zenoh-pico in client mode, the configuration in which its congestion control
/// holds. A failure here is the harness's or the host's.
fn congestion_control_run(probes: &Probes) {
    let control = congestion_run(&probes.pico, "zenoh-pico", "client").unwrap_or_else(|e| {
        panic!(
            "CONTROL: the real zenoh-pico in client mode could not be measured, so this host or \
             the harness cannot carry the measurement and nothing is said about wz:\n{e}"
        )
    });
    println!("control: {control:#?}");
    assert_congestion_holds(
        &control,
        "CONTROL, the real zenoh-pico in client mode (a red here is the harness's or the \
         host's, not wz's)",
    );
}

/// A client's `Drop` returns and is not delivered on a full link, and its `Block` waits and
/// delivers: on the real zenoh-pico first, then on wz.
#[test]
#[ignore = "runs real zenoh-pico and wz processes through a stalling relay; Layer S runs via \
            --ignored"]
fn link_qos_drop_and_block_on_a_full_stream_in_client_mode() {
    let probes = Probes::build();
    congestion_control_run(&probes);
    let subject = congestion_run(&probes.wz, "wz", "client").unwrap_or_else(|e| panic!("wz: {e}"));
    println!("subject: {subject:#?}");
    assert_congestion_holds(&subject, "wz");
}

/// A peer's `Drop` returns and is not delivered on a full link, and its `Block` waits and
/// delivers, on wz. The control is the client run of the real zenoh-pico, because a pico peer
/// does not hold the definition on a full link; that run is printed as the reference.
#[test]
#[ignore = "runs real zenoh-pico and wz processes through a stalling relay; Layer S runs via \
            --ignored"]
fn link_qos_drop_and_block_on_a_full_stream_in_peer_mode() {
    let probes = Probes::build();
    congestion_control_run(&probes);
    match congestion_run(&probes.pico, "zenoh-pico", "peer") {
        Ok(reference) => println!(
            "reference, the real zenoh-pico in peer mode (not held): {:?}\n{reference:#?}",
            congestion_findings(&reference)
        ),
        Err(e) => println!("reference, the real zenoh-pico in peer mode (not held), ended: {e}"),
    }
    let subject = congestion_run(&probes.wz, "wz", "peer").unwrap_or_else(|e| panic!("wz: {e}"));
    println!("subject: {subject:#?}");
    assert_congestion_holds(&subject, "wz");
}
