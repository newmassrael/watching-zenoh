// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `transport/link/tx/queue/allocation/mode` and `transport/link/rx/buffer_size`, read off the
//! heap of the program a session runs in: one C program, compiled once, linked against wz's
//! cdylib and against the real `libzenohc.so`, run per document as a peer that dials a peer of
//! the same library in a process of its own.
//!
//! Neither key moves a byte on the wire. Each decides what a link holds of its host: WHEN the
//! batches of its transmit queue are allocated, and HOW MANY receive buffers it keeps. So the
//! observation is extended to the heap rather than the keys being left unwitnessed.
//!
//! ## Upstream's rules
//!
//! `init` fills every priority's refill ring with its queue size's worth of batches when the
//! link's pipeline is made (`io/zenoh-transport/src/common/pipeline.rs` @
//! `if *config.queue_alloc.mode() == QueueAllocMode::Init {`), and the stage that serialises
//! messages allocates a batch only while fewer than the queue size have been made
//! (`io/zenoh-transport/src/common/pipeline.rs` @
//! `None if self.batch_allocs < self.batch_config.0 => {`): under `init` never again, under
//! `lazy` the first time a lane wants one. A batch is one block of the link's batch size
//! (`io/zenoh-transport/src/common/batch.rs` @
//! `buffer: BBuf::with_capacity(config.mtu as usize),`).
//!
//! The receive task of a link pools `rx_buffer_size / mtu` buffers, at least one
//! (`io/zenoh-transport/src/unicast/universal/link.rs` @ `let mut n = rx_buffer_size / mtu;`),
//! each a zeroed block of the batch size made when the task starts
//! (`io/zenoh-transport/src/unicast/universal/link.rs` @
//! `let pool = RecyclingObjectPool::new(n, move || vec![0_u8; mtu].into_boxed_slice());`). A
//! read that finds the pool dry takes a buffer that does not go back
//! (`io/zenoh-transport/src/unicast/universal/link.rs` @
//! `pool.try_take().unwrap_or_else(|| pool.alloc())`, and
//! `commons/zenoh-sync/src/object_pool.rs` @ `pub fn alloc(&self) -> RecyclingObject<T> {`), so
//! what the key decides is how many buffers the link KEEPS.
//!
//! ## The observation
//!
//! The program defines `malloc`, `calloc`, `realloc`, `free`, `posix_memalign` and
//! `aligned_alloc` itself. A program's own symbols come first in the dynamic linker's search, so
//! the library linked beside it calls them for every block it takes, the same way under both
//! builds; each forwards to glibc's allocator under its exported `__libc_*` name, so nothing is
//! allocated differently. The definitions note each block whose size is inside a window the
//! harness hands the program, and when it is freed. The program prints, at each phase, how many
//! such blocks have been MADE since the window was armed and how many are LIVE.
//!
//! The phases are points the program waits to be quiet at: `open` after the session is up,
//! `declared` once its publisher matches the far node's subscriber (or its subscriber is
//! declared and its "go" publisher matches), and then `burst` after it has put `BURST` samples or
//! `received` after it has heard the far node's `BURST`. Only the dialling program is observed:
//! the far node runs in a process of its own, so every block counted is the observed session's.
//!
//! ## The normalisations, each with its reason
//!
//! - A block is batch-sized when it is at least the link's batch and at most `FRAMING` bytes
//!   wider. Upstream allocates the batch exactly; wz keeps a stream frame's prefix in the batch's
//!   own block, so a buffer it builds a frame in is the batch and two bytes, one it keeps spare
//!   the batch and eight, and one it reads into the batch and four.
//! - A size that is a power of two is not counted: it is the capacity a doubling buffer
//!   reaches, and no batch buffer of either library is one at the sizes these documents give.
//! - The allocation documents STATE the batch size (`STATED_BATCH`). Unstated, upstream's TCP
//!   link sizes its batch to a multiple of half the connection's MSS
//!   (`io/zenoh-links/zenoh-link-tcp/src/unicast.rs` @
//!   `let mss = socket.mss().unwrap_or(mtu as u32) / 2;`), a number of the host and not of the
//!   document, and the window would have to be wide enough to admit unrelated blocks between the
//!   phases this leg differences.
//! - The receive documents come in two families, because the divisor of `rx_buffer_size` is the
//!   link's negotiated batch and a leg that kept the batch at its default could not tell that
//!   divisor from the widest batch. One family leaves the batch size at its default; its window
//!   is every size from just over half the widest batch, the least a TCP link of upstream's can
//!   settle on, to the widest batch and its framing, and its control asks only that the larger
//!   size keep more, as the host's MSS decides the batch. The other states `STATED_BATCH`; its
//!   window is that batch and its framing, and its control asks for upstream's own arithmetic,
//!   `rx_buffer_size / batch` of each document.
//! - The receive documents state `allocation/mode: "init"`. The transmit queue's batches, which
//!   are inside the same window, are then all made at the open in a number the queue sizes fix,
//!   so the difference between the two receive documents is the receive pool alone.
//! - Relations are compared, not totals: a difference between two documents in the same phase
//!   (each counts the batch-sized blocks both documents allocate alike, and the difference does
//!   not), or between two phases of one run. Receive buffers are compared LIVE at a quiet point,
//!   when every buffer a dry pool lent out has gone; how many of those a burst took depends on
//!   scheduling, so it is not compared.
//! - Each document runs `RUNS` times on each library. The reference must agree with itself
//!   before it adjudicates wz's: a relation that moves between two runs of the real library is
//!   one this machine cannot measure.

use std::io::{BufRead, BufReader, Lines};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use wz_integration_tests::bounded::{BoundedChild as _, BoundedOutput as _};
use wz_integration_tests::common::{
    assert_zenoh_c_arm_pairing, compile_zenoh_c_example, wz_capi_c_cdylib, zenoh_c_oracle,
    zenoh_c_shared_library, PortReservation,
};

/// The oracle, or `None` with a LOUD note naming what to do about it.
fn oracle_or_note() -> Option<PathBuf> {
    match zenoh_c_oracle() {
        Some((include, _libdir, _examples)) => Some(include),
        None => {
            eprintln!(
                "skip: the zenoh-c ORACLE is absent. This leg needs zenoh-c's headers \
                 and libzenohc.so (default prefix ~/.local, override WZ_ZENOH_C_PREFIX). \
                 Layer C1cc with WZ_C1CC_REQUIRE=1 fails instead of skipping."
            );
            None
        }
    }
}

/// How many samples a burst carries, out of the observed session or into it.
const BURST: usize = 4_000;

/// How many times each document is run on each library.
const RUNS: usize = 2;

/// The batch size the allocation documents state: below the least batch upstream's TCP link
/// settles on, so the link's batch is this number on any host, and neither a power of two nor a
/// size near one.
const STATED_BATCH: usize = 20_000;

/// The widest batch, upstream's default `transport/link/tx/batch_size`, and the unit the receive
/// documents state `transport/link/rx/buffer_size` in.
const WIDEST_BATCH: usize = 65_535;

/// The most bytes an implementation keeps beside a batch in the batch's own block.
const FRAMING: usize = 8;

/// The IPv4 and TCP headers upstream's TCP link takes off the widest batch before it rounds the
/// rest to half the MSS: half of what is left, plus one, is the least batch it can settle on.
const TCP_IPV4_HEADERS: usize = 40;

/// The sizes the program counts as a batch, both ends inclusive.
#[derive(Debug, Clone, Copy)]
struct Window {
    low: usize,
    high: usize,
}

/// A batch of the size the allocation documents and the stated receive documents give.
const STATED_BATCH_WINDOW: Window = Window {
    low: STATED_BATCH,
    high: STATED_BATCH + FRAMING,
};

/// A batch of any size a default TCP link of either library settles on.
const DEFAULT_BATCH_WINDOW: Window = Window {
    low: (WIDEST_BATCH - TCP_IPV4_HEADERS) / 2 + 1,
    high: WIDEST_BATCH + FRAMING,
};

/// The smaller receive document's `rx/buffer_size`, in widest batches.
const FEW_BUFFERS: usize = 2;

/// The larger receive document's `rx/buffer_size`, in widest batches: three times the smaller.
const MANY_BUFFERS: usize = 6;

const PROBE: &str = r#"#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "zenoh.h"

/* ---- The allocation observer ---------------------------------------------------------------
   The program's own allocator entry points, which the dynamic linker binds the linked library's
   calls to before glibc's. Each forwards to glibc under its exported name and notes the blocks
   whose size is inside [window_low, window_high], skipping powers of two. A noted block is kept
   in an open-addressed table of its addresses until it is freed; a slot once used stays used
   (GONE), so a lookup never stops early on a slot a concurrent free emptied. */
extern void *__libc_malloc(size_t size);
extern void *__libc_calloc(size_t count, size_t size);
extern void *__libc_realloc(void *block, size_t size);
extern void __libc_free(void *block);
extern void *__libc_memalign(size_t alignment, size_t size);

#define SLOTS ((size_t)1 << 16)
#define GONE ((uintptr_t)1)

static _Atomic uintptr_t slots[SLOTS];
static atomic_size_t window_low;
static atomic_size_t window_high;
static atomic_long made;
static atomic_long freed;
static atomic_int overflowed;
static atomic_int noting;

static size_t slot_of(uintptr_t block) {
    return (size_t)((((uint64_t)block >> 4) * UINT64_C(0x9E3779B97F4A7C15)) >> 48);
}

static bool in_window(size_t size) {
    size_t high = atomic_load_explicit(&window_high, memory_order_relaxed);
    size_t low = atomic_load_explicit(&window_low, memory_order_relaxed);
    return high != 0 && size >= low && size <= high && (size & (size - 1)) != 0;
}

static void note_made(void *block, size_t size) {
    if (block == NULL || !in_window(size)) { return; }
    uintptr_t key = (uintptr_t)block;
    size_t at = slot_of(key);
    for (size_t i = 0; i < SLOTS; i++) {
        uintptr_t empty = 0;
        if (atomic_compare_exchange_strong(&slots[(at + i) & (SLOTS - 1)], &empty, key)) {
            atomic_store(&noting, 1);
            atomic_fetch_add(&made, 1);
            return;
        }
    }
    atomic_store(&overflowed, 1);
}

static void note_freed(void *block) {
    if (block == NULL || atomic_load(&noting) == 0) { return; }
    uintptr_t key = (uintptr_t)block;
    size_t at = slot_of(key);
    for (size_t i = 0; i < SLOTS; i++) {
        _Atomic uintptr_t *slot = &slots[(at + i) & (SLOTS - 1)];
        uintptr_t seen = atomic_load(slot);
        if (seen == 0) { return; }
        if (seen == key && atomic_compare_exchange_strong(slot, &seen, GONE)) {
            atomic_fetch_add(&freed, 1);
            return;
        }
    }
}

void *malloc(size_t size) {
    void *block = __libc_malloc(size);
    note_made(block, size);
    return block;
}

void *calloc(size_t count, size_t size) {
    void *block = __libc_calloc(count, size);
    /* glibc refuses a product that overflows, so a block means the product is its size. */
    if (block != NULL) { note_made(block, count * size); }
    return block;
}

void *realloc(void *block, size_t size) {
    void *moved = __libc_realloc(block, size);
    /* A failed resize leaves the old block in place; a resize to nothing frees it. */
    if (block != NULL && (moved != NULL || size == 0)) { note_freed(block); }
    note_made(moved, size);
    return moved;
}

void free(void *block) {
    note_freed(block);
    __libc_free(block);
}

int posix_memalign(void **out, size_t alignment, size_t size) {
    if (alignment == 0 || alignment % sizeof(void *) != 0 || (alignment & (alignment - 1)) != 0) {
        return EINVAL;
    }
    void *block = __libc_memalign(alignment, size);
    if (block == NULL) { return ENOMEM; }
    note_made(block, size);
    *out = block;
    return 0;
}

void *aligned_alloc(size_t alignment, size_t size) {
    void *block = __libc_memalign(alignment, size);
    note_made(block, size);
    return block;
}

static void phase(const char *name) {
    long m = atomic_load(&made);
    long f = atomic_load(&freed);
    printf("phase=%s made=%ld live=%ld overflow=%d\n", name, m, m - f, atomic_load(&overflowed));
    fflush(stdout);
}

/* ---- The sessions ------------------------------------------------------------------------- */
#define BURST_KEY "wz/link_resources/burst"
#define GO_KEY "wz/link_resources/go"
/* Long enough for a session's own traffic after a step to have ended. */
#define SETTLE_MS 500
/* Long enough for a burst put with BLOCK to have left the queue. */
#define DRAIN_MS 1000

static atomic_int heard;
static atomic_int go;

static void on_heard(struct z_loaned_sample_t *sample, void *context) {
    (void)sample;
    (void)context;
    atomic_fetch_add(&heard, 1);
}

static void on_go(struct z_loaned_sample_t *sample, void *context) {
    (void)sample;
    (void)context;
    atomic_store(&go, 1);
}

static int insert(z_owned_config_t *config, const char *key, const char *value) {
    z_result_t rc = zc_config_insert_json5(z_config_loan_mut(config), key, value);
    if (rc != Z_OK) { printf("config %s=%s rc=%d\n", key, value, (int)rc); }
    return rc == Z_OK ? 0 : -1;
}

/* A peer with `endpoint` under `role`, and the `pairs` key/value pairs of `stated` laid over the
   default configuration. A peer that dials states an empty listener list, so it binds nothing
   and its one link is the one it dials. */
static int open_node(z_owned_session_t *session, const char *role, const char *endpoint,
                     int pairs, char **stated) {
    z_owned_config_t config;
    if (z_config_default(&config) != Z_OK) { return -100; }
    char endpoints[256];
    snprintf(endpoints, sizeof endpoints, "[\"%s\"]", endpoint);
    bool dials = strcmp(role, "connect/endpoints") == 0;
    if (insert(&config, "mode", "\"peer\"") != 0
        || insert(&config, "scouting/multicast/enabled", "false") != 0
        || insert(&config, role, endpoints) != 0
        || (dials && insert(&config, "listen/endpoints", "[]") != 0)) {
        z_drop(z_move(config));
        return -101;
    }
    for (int i = 0; i < pairs; i++) {
        if (insert(&config, stated[2 * i], stated[2 * i + 1]) != 0) {
            z_drop(z_move(config));
            return -102;
        }
    }
    return z_open(session, z_move(config), NULL);
}

/* BLOCK, so a put waits for a batch rather than being dropped without one. */
static z_result_t declare_blocking_publisher(const z_loaned_session_t *session,
                                             z_owned_publisher_t *publisher, const char *key) {
    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, key);
    z_publisher_options_t options;
    z_publisher_options_default(&options);
    options.congestion_control = Z_CONGESTION_CONTROL_BLOCK;
    return z_declare_publisher(session, publisher, z_loan(ke), &options);
}

static z_result_t put_one(const z_loaned_publisher_t *publisher) {
    z_owned_bytes_t payload;
    z_bytes_from_static_str(&payload, "r");
    return z_publisher_put(publisher, z_move(payload), NULL);
}

static int wait_matched(const z_loaned_publisher_t *publisher, int bound_ms) {
    for (int waited = 0; waited <= bound_ms; waited += 20) {
        z_matching_status_t status;
        if (z_publisher_get_matching_status(publisher, &status) == Z_OK && status.matching) {
            return 1;
        }
        z_sleep_ms(20);
    }
    return 0;
}

/* Whether standard input has reached its end, waiting for it at most `timeout_ms`. */
static bool stdin_closed(int timeout_ms) {
    struct pollfd fd = {.fd = 0, .events = POLLIN, .revents = 0};
    if (poll(&fd, 1, timeout_ms) <= 0) { return false; }
    char sink[64];
    ssize_t n = read(0, sink, sizeof sink);
    return n == 0 || (n < 0 && errno != EINTR);
}

/* The far node: a peer that listens, and either hears the burst (`far-sub`) or puts it once the
   dialling session says go (`far-pub`). It lives until its standard input closes. */
static int run_far(const char *role, const char *endpoint, int burst) {
    bool publishes = strcmp(role, "far-pub") == 0;
    z_owned_session_t session;
    int rc = open_node(&session, "listen/endpoints", endpoint, 0, NULL);
    if (rc != Z_OK) {
        printf("ready=%d\n", rc);
        return 1;
    }
    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, publishes ? GO_KEY : BURST_KEY);
    z_owned_closure_sample_t callback;
    z_closure(&callback, publishes ? on_go : on_heard, NULL, NULL);
    z_owned_subscriber_t subscriber;
    rc = z_declare_subscriber(z_loan(session), &subscriber, z_loan(ke), z_move(callback), NULL);
    z_owned_publisher_t publisher;
    if (rc == Z_OK && publishes) {
        rc = declare_blocking_publisher(z_loan(session), &publisher, BURST_KEY);
    }
    printf("ready=%d\n", rc);
    if (rc != Z_OK) { return 1; }
    bool sent = false;
    while (!stdin_closed(20)) {
        if (publishes && !sent && atomic_load(&go) != 0) {
            int matched = wait_matched(z_loan(publisher), 5000);
            int refused = 0;
            for (int i = 0; i < burst; i++) { refused += put_one(z_loan(publisher)) != Z_OK; }
            printf("sent=%d matched=%d refused=%d\n", burst, matched, refused);
            sent = true;
        }
    }
    printf("heard=%d\n", atomic_load(&heard));
    if (publishes) { z_drop(z_move(publisher)); }
    z_drop(z_move(subscriber));
    z_drop(z_move(session));
    return 0;
}

/* The observed node: a peer that dials the far node with the stated keys, and puts the burst
   (`tx`) or receives it (`rx`), printing its batch-sized blocks at each phase. */
static int run_observed(bool receives, const char *endpoint, int burst, int pairs,
                        char **stated) {
    z_owned_session_t session;
    int rc = open_node(&session, "connect/endpoints", endpoint, pairs, stated);
    printf("open=%d\n", rc);
    if (rc != Z_OK) { return 1; }
    z_sleep_ms(SETTLE_MS);
    phase("open");

    z_owned_subscriber_t subscriber;
    z_owned_publisher_t publisher;
    if (receives) {
        z_view_keyexpr_t ke;
        z_view_keyexpr_from_str(&ke, BURST_KEY);
        z_owned_closure_sample_t callback;
        z_closure(&callback, on_heard, NULL, NULL);
        rc = z_declare_subscriber(z_loan(session), &subscriber, z_loan(ke), z_move(callback),
                                  NULL);
        if (rc == Z_OK) { rc = declare_blocking_publisher(z_loan(session), &publisher, GO_KEY); }
    } else {
        rc = declare_blocking_publisher(z_loan(session), &publisher, BURST_KEY);
    }
    printf("declared=%d\n", rc);
    if (rc != Z_OK) { return 1; }
    printf("matched=%d\n", wait_matched(z_loan(publisher), 10000));
    z_sleep_ms(SETTLE_MS);
    phase("declared");

    if (receives) {
        rc = put_one(z_loan(publisher));
        for (int i = 0; i < 1500 && atomic_load(&heard) < burst; i++) { z_sleep_ms(20); }
        printf("go=%d heard=%d\n", rc, atomic_load(&heard));
        z_sleep_ms(SETTLE_MS);
        phase("received");
    } else {
        int refused = 0;
        for (int i = 0; i < burst; i++) { refused += put_one(z_loan(publisher)) != Z_OK; }
        z_sleep_ms(DRAIN_MS);
        printf("refused=%d\n", refused);
        phase("burst");
    }

    z_drop(z_move(publisher));
    if (receives) { z_drop(z_move(subscriber)); }
    z_drop(z_move(session));
    printf("done\n");
    return 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc >= 4 && (strcmp(argv[1], "far-sub") == 0 || strcmp(argv[1], "far-pub") == 0)) {
        return run_far(argv[1], argv[2], atoi(argv[3]));
    }
    if (argc >= 6 && (argc - 6) % 2 == 0
        && (strcmp(argv[1], "tx") == 0 || strcmp(argv[1], "rx") == 0)) {
        atomic_store(&window_low, (size_t)strtoull(argv[3], NULL, 10));
        atomic_store(&window_high, (size_t)strtoull(argv[4], NULL, 10));
        return run_observed(strcmp(argv[1], "rx") == 0, argv[2], atoi(argv[5]), (argc - 6) / 2,
                            argv + 6);
    }
    fprintf(stderr,
            "usage: probe far-sub|far-pub <listen-endpoint> <burst>\n"
            "       probe tx|rx <connect-endpoint> <low> <high> <burst> [<key> <json5>]...\n");
    return 2;
}
"#;

/// The probe linked against one library, and the directory the library is in.
struct Arm {
    name: &'static str,
    exe: PathBuf,
    libdir: PathBuf,
}

/// The probe linked against each library, with the directory that holds the builds.
struct Arms {
    reference: Arm,
    wz: Arm,
    _dir: tempfile::TempDir,
}

/// Compile the probe once per library.
fn build_both_arms(include: &Path) -> Arms {
    let dir = tempfile::tempdir().expect("tempdir for the compiled probes");
    let src_dir = dir.path().join("src");
    std::fs::create_dir_all(&src_dir).expect("probe source dir");
    std::fs::write(src_dir.join("wz_link_resources.c"), PROBE).expect("write the probe source");

    let lib = wz_capi_c_cdylib();
    let wz_libdir = lib.parent().expect("cdylib has a parent").to_path_buf();
    let on_wz = compile_zenoh_c_example(
        "wz_link_resources",
        dir.path(),
        include,
        &src_dir,
        &wz_libdir,
        "wz_capi_c",
    )
    .unwrap_or_else(|diag| {
        panic!("the link resources probe does NOT link against wz's cdylib.\n{diag}")
    });

    let reference = zenoh_c_shared_library().expect("the oracle resolved above");
    let ref_libdir = reference
        .parent()
        .expect("libzenohc.so has a parent")
        .to_path_buf();
    let ref_dir = dir.path().join("reference");
    std::fs::create_dir_all(&ref_dir).expect("reference build dir");
    let on_ref = compile_zenoh_c_example(
        "wz_link_resources",
        &ref_dir,
        include,
        &src_dir,
        &ref_libdir,
        "zenohc",
    )
    .unwrap_or_else(|diag| {
        panic!("the link resources probe does not link against the REAL libzenohc.so\n{diag}")
    });

    Arms {
        reference: Arm {
            name: "libzenohc",
            exe: on_ref,
            libdir: ref_libdir,
        },
        wz: Arm {
            name: "wz",
            exe: on_wz,
            libdir: wz_libdir,
        },
        _dir: dir,
    }
}

/// Which way the burst crosses the observed session's link.
#[derive(Debug, Clone, Copy)]
enum Role {
    /// The observed session puts the burst to a far subscriber.
    Puts,
    /// The far node puts the burst to the observed session's subscriber.
    Receives,
}

impl Role {
    fn observed(self) -> &'static str {
        match self {
            Role::Puts => "tx",
            Role::Receives => "rx",
        }
    }

    fn far(self) -> &'static str {
        match self {
            Role::Puts => "far-sub",
            Role::Receives => "far-pub",
        }
    }

    fn last_phase(self) -> &'static str {
        match self {
            Role::Puts => "burst",
            Role::Receives => "received",
        }
    }
}

/// The far node, read line by line, alive until its standard input is closed.
struct Far {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Lines<BufReader<ChildStdout>>,
}

impl Far {
    fn start(arm: &Arm, role: Role, endpoint: &str) -> Self {
        let burst = BURST.to_string();
        let mut child = Command::new(&arm.exe)
            .args([role.far(), endpoint, burst.as_str()])
            .env("LD_LIBRARY_PATH", &arm.libdir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|why| panic!("spawn the far node {}: {why}", arm.exe.display()));
        let stdin = child.stdin.take();
        let lines = BufReader::new(child.stdout.take().expect("piped stdout")).lines();
        Self {
            child,
            stdin,
            lines,
        }
    }

    /// The far node's first line, which it prints once it listens and has declared its
    /// entities: `ready=0`, or the code of what failed.
    fn ready(&mut self) -> String {
        self.lines
            .next()
            .map(|line| line.expect("read the far node's stdout"))
            .unwrap_or_default()
    }

    /// Close the far node's standard input, which ends it, and return what it printed after
    /// its first line.
    fn finish(mut self) -> String {
        drop(self.stdin.take());
        let rest: Vec<String> = self
            .lines
            .by_ref()
            .map(|line| line.expect("read the far node's stdout"))
            .collect();
        self.child.wait_bounded().expect("the far node ends");
        rest.join("\n")
    }
}

/// The batch-sized blocks the observed program had made since the window was armed, and how
/// many of them were live, at one phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Heap {
    made: i64,
    live: i64,
}

/// One run's heap at each of its phases.
#[derive(Debug, Clone, Copy)]
struct Reading {
    open: Heap,
    declared: Heap,
    /// After the burst: `burst` when the session put it, `received` when it heard it.
    after: Heap,
}

/// The heap a `phase=<name>` line of `stdout` reports.
fn heap_at(stdout: &str, phase: &str, context: &str) -> Heap {
    let prefix = format!("phase={phase} ");
    let line = stdout
        .lines()
        .find(|line| line.starts_with(&prefix))
        .unwrap_or_else(|| panic!("no `{prefix}` line in {context}"));
    let field = |name: &str| -> i64 {
        line.split_whitespace()
            .find_map(|word| word.strip_prefix(name))
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| panic!("`{line}` has no `{name}` in {context}"))
    };
    assert_eq!(
        field("overflow="),
        0,
        "the observer's table of blocks overflowed, so its counts are not the heap's: {context}"
    );
    Heap {
        made: field("made="),
        live: field("live="),
    }
}

/// Run the observed program on `arm` with `document` laid over its configuration, against a far
/// node of the same library, counting the blocks inside `window`.
fn observe(arm: &Arm, role: Role, window: Window, document: &[(&str, String)]) -> Reading {
    let reservation = PortReservation::pick();
    let endpoint = format!("tcp/127.0.0.1:{}", reservation.port());
    let mut far = Far::start(arm, role, &endpoint);
    let ready = far.ready();
    drop(reservation);
    if ready != "ready=0" {
        let rest = far.finish();
        panic!(
            "the far node on {} did not come up: `{ready}`\n{rest}",
            arm.name
        );
    }

    let mut args = vec![
        role.observed().to_owned(),
        endpoint,
        window.low.to_string(),
        window.high.to_string(),
        BURST.to_string(),
    ];
    for (key, value) in document {
        args.push((*key).to_owned());
        args.push(value.clone());
    }
    let out = Command::new(&arm.exe)
        .args(&args)
        .env("LD_LIBRARY_PATH", &arm.libdir)
        .output_bounded()
        .unwrap_or_else(|why| panic!("spawn {}: {why}", arm.exe.display()));
    let far_said = far.finish();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let context = format!(
        "{} {} with {document:?}:\n--- observed program ---\n{stdout}{}\n\
         --- far node ---\n{far_said}",
        arm.name,
        role.observed(),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.status.success() && stdout.contains("done"),
        "the observed program exited {}: {context}",
        out.status
    );
    assert!(
        stdout.contains("matched=1"),
        "the observed session's publisher never matched the far node, so the burst did not \
         cross the link: {context}"
    );
    // The burst crossed the link whole, so the phase after it read the burst's blocks and not
    // a remnant of it.
    let crossed = match role {
        Role::Puts => far_said.contains(&format!("heard={BURST}")),
        Role::Receives => stdout.contains(&format!("heard={BURST}")),
    };
    assert!(crossed, "the burst did not cross the link whole: {context}");

    Reading {
        open: heap_at(&stdout, "open", &context),
        declared: heap_at(&stdout, "declared", &context),
        after: heap_at(&stdout, role.last_phase(), &context),
    }
}

/// The allocation documents: the stated batch size and the mode.
fn allocation_document(mode: &str) -> Vec<(&'static str, String)> {
    vec![
        ("transport/link/tx/batch_size", STATED_BATCH.to_string()),
        (
            "transport/link/tx/queue/allocation/mode",
            format!("\"{mode}\""),
        ),
    ]
}

/// The `data` queue's size the wider `init` document states, against upstream's default of 2
/// (`DEFAULT_CONFIG.json5` @ `data: 2`).
const WIDE_DATA_QUEUE: i64 = 6;
/// The batches the wider queue holds beyond the default one.
const DATA_QUEUE_STEP: i64 = WIDE_DATA_QUEUE - 2;

/// The `init` document with a wider `data` queue: an `init` queue fills its refill ring with
/// one batch per slot of its size when the link is made
/// (`io/zenoh-transport/src/common/pipeline.rs` @ `for _ in 0..*num {`), so the two `init`
/// documents differ at the open by the step and by nothing else.
fn wide_init_document() -> Vec<(&'static str, String)> {
    let mut document = allocation_document("init");
    document.push((
        "transport/link/tx/queue/size/data",
        WIDE_DATA_QUEUE.to_string(),
    ));
    document
}

/// One run of each allocation document.
#[derive(Debug, Clone, Copy)]
struct ModePair {
    init: Reading,
    wide_init: Reading,
    lazy: Reading,
}

impl ModePair {
    /// The batches the `init` program has made at the open beyond the `lazy` one's. How many
    /// the `lazy` one has made by then depends on scheduling (a lane that wants a batch while
    /// fewer than its queue's size exist makes one: `pipeline.rs` @
    /// `None if self.batch_allocs < self.batch_config.0`), on libzenohc as on wz, so only its
    /// sign is part of the rule.
    fn ahead(&self) -> i64 {
        self.init.open.made - self.lazy.open.made
    }

    /// The batches the wider `init` document has made at the open beyond the default one's: the
    /// queue's arithmetic, the same on every run of either library.
    fn queue_step(&self) -> i64 {
        self.wide_init.open.made - self.init.open.made
    }

    /// The batches the `init` program makes after its open, through the declaration and the
    /// burst.
    fn init_after_open(&self) -> i64 {
        self.init.after.made - self.init.open.made
    }

    /// The batches the `lazy` program makes while the burst crosses.
    fn lazy_on_traffic(&self) -> i64 {
        self.lazy.after.made - self.lazy.declared.made
    }

    /// Whether the run shows upstream's rule: `init` makes its batches at the open and none after
    /// it, and `lazy` makes fewer at the open and some when the burst wants them.
    fn shows_the_rule(&self) -> bool {
        self.ahead() > 0 && self.init_after_open() == 0 && self.lazy_on_traffic() >= 1
    }
}

fn mode_pairs(arm: &Arm) -> Vec<ModePair> {
    (0..RUNS)
        .map(|_| ModePair {
            init: observe(
                arm,
                Role::Puts,
                STATED_BATCH_WINDOW,
                &allocation_document("init"),
            ),
            wide_init: observe(arm, Role::Puts, STATED_BATCH_WINDOW, &wide_init_document()),
            lazy: observe(
                arm,
                Role::Puts,
                STATED_BATCH_WINDOW,
                &allocation_document("lazy"),
            ),
        })
        .collect()
}

// wz-proves: none -- a config key's effect on when a link allocates batches, claimed for no atom
/// A session whose `transport/link/tx/queue/allocation/mode` is `init` allocates its queue's
/// batches when its link is made, one per slot of the queue's size, and none after, and one
/// whose mode is `lazy` allocates fewer then and some when traffic wants them, on wz as on
/// libzenohc. The count compared exactly is the init queue's arithmetic (a wider `data` queue
/// makes its extra slots at the open); how many a lazy queue has made by the open depends on
/// scheduling on both libraries, so of that only the rule is compared.
#[test]
#[ignore = "opens sessions and reads a zenoh-c oracle; run by run-ci Layer C1cc \
            (which builds the matching ABI arm this needs)"]
fn an_init_queue_allocates_its_batches_at_the_open_and_a_lazy_one_on_traffic_on_wz_and_libzenohc() {
    let Some(include) = oracle_or_note() else {
        return;
    };
    assert_zenoh_c_arm_pairing(&include);
    let arms = build_both_arms(&include);

    let reference = mode_pairs(&arms.reference);
    for (run, pair) in reference.iter().enumerate() {
        eprintln!(
            "libzenohc run {run}: queue step {} ahead {} init after open {} lazy on traffic {} \
             ({pair:?})",
            pair.queue_step(),
            pair.ahead(),
            pair.init_after_open(),
            pair.lazy_on_traffic()
        );
        assert!(
            pair.shows_the_rule(),
            "run {run} of the REFERENCE does not show upstream's allocation rule ({pair:?}), so \
             this machine's libzenohc cannot adjudicate wz's"
        );
        assert_eq!(
            pair.queue_step(),
            DATA_QUEUE_STEP,
            "run {run} of the REFERENCE: a data queue {DATA_QUEUE_STEP} slots wider made a \
             different number of batches at the open ({pair:?}), so this machine's libzenohc \
             does not show the init arithmetic it is asked to adjudicate"
        );
    }

    let mut failures: Vec<String> = Vec::new();
    for (run, pair) in mode_pairs(&arms.wz).iter().enumerate() {
        eprintln!(
            "wz run {run}: queue step {} ahead {} init after open {} lazy on traffic {} \
             ({pair:?})",
            pair.queue_step(),
            pair.ahead(),
            pair.init_after_open(),
            pair.lazy_on_traffic()
        );
        if pair.queue_step() != DATA_QUEUE_STEP {
            failures.push(format!(
                "run {run}: a data queue {DATA_QUEUE_STEP} slots wider made {} more batches at \
                 the open, where libzenohc's made {DATA_QUEUE_STEP}",
                pair.queue_step()
            ));
        }
        if pair.ahead() <= 0 {
            failures.push(format!(
                "run {run}: an init queue made {} batches at the open beyond a lazy one's, where \
                 libzenohc's made more",
                pair.ahead()
            ));
        }
        if pair.init_after_open() != 0 {
            failures.push(format!(
                "run {run}: an init queue made {} batches after its open, where libzenohc's made \
                 none",
                pair.init_after_open()
            ));
        }
        if pair.lazy_on_traffic() < 1 {
            failures.push(format!(
                "run {run}: a lazy queue made no batch while the burst crossed, where libzenohc's \
                 made at least one"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "wz's C ABI and libzenohc allocate a link's batches differently for the same mode:\n{}",
        failures.join("\n")
    );
}

/// One family of receive documents: the batch size they state, if any, and the window a buffer
/// of that batch falls in.
#[derive(Debug, Clone, Copy)]
struct ReceiveFamily {
    name: &'static str,
    stated_batch: Option<usize>,
    window: Window,
}

/// The default batch, which the host's MSS decides, and a batch the documents state, which
/// grades the divisor of `rx_buffer_size`.
const RECEIVE_FAMILIES: [ReceiveFamily; 2] = [
    ReceiveFamily {
        name: "at the default batch size",
        stated_batch: None,
        window: DEFAULT_BATCH_WINDOW,
    },
    ReceiveFamily {
        name: "at a stated batch size",
        stated_batch: Some(STATED_BATCH),
        window: STATED_BATCH_WINDOW,
    },
];

impl ReceiveFamily {
    /// The document with `rx/buffer_size` of `batches` widest batches, the transmit queue's
    /// batches made at the open so they are the same in both, and the family's batch size.
    fn document(self, batches: usize) -> Vec<(&'static str, String)> {
        let mut document = vec![
            (
                "transport/link/tx/queue/allocation/mode",
                "\"init\"".to_owned(),
            ),
            (
                "transport/link/rx/buffer_size",
                (batches * WIDEST_BATCH).to_string(),
            ),
        ];
        if let Some(batch) = self.stated_batch {
            document.push(("transport/link/tx/batch_size", batch.to_string()));
        }
        document
    }

    /// Upstream's own count of the buffers the larger document keeps beyond the smaller one's,
    /// where the document fixes the link's batch: `rx_buffer_size / batch` of each
    /// (`io/zenoh-transport/src/unicast/universal/link.rs` @ `let mut n = rx_buffer_size / mtu;`).
    /// `None` at the default, where the host's MSS decides the batch.
    fn upstream_count(self) -> Option<i64> {
        self.stated_batch.map(|batch| {
            let kept = |batches: usize| ((batches * WIDEST_BATCH) / batch).max(1);
            (kept(MANY_BUFFERS) - kept(FEW_BUFFERS)) as i64
        })
    }
}

/// One run of each receive document.
#[derive(Debug, Clone, Copy)]
struct BufferPair {
    few: Reading,
    many: Reading,
}

impl BufferPair {
    /// The receive buffers the larger document keeps beyond the smaller one's once the link is
    /// up.
    fn kept_at_open(&self) -> i64 {
        self.many.open.live - self.few.open.live
    }

    /// The same, once the burst has been heard and the link is quiet again.
    fn kept_after_the_burst(&self) -> i64 {
        self.many.after.live - self.few.after.live
    }

    /// Whether the run shows upstream's rule for `family`: the larger size keeps more buffers,
    /// as many more as upstream's arithmetic gives where the document fixes the batch, and
    /// keeps them through the traffic.
    fn shows_the_rule(&self, family: ReceiveFamily) -> bool {
        let counted = match family.upstream_count() {
            Some(count) => self.kept_at_open() == count,
            None => true,
        };
        counted && self.kept_at_open() > 0 && self.kept_after_the_burst() == self.kept_at_open()
    }
}

fn buffer_pairs(arm: &Arm, family: ReceiveFamily) -> Vec<BufferPair> {
    (0..RUNS)
        .map(|_| BufferPair {
            few: observe(
                arm,
                Role::Receives,
                family.window,
                &family.document(FEW_BUFFERS),
            ),
            many: observe(
                arm,
                Role::Receives,
                family.window,
                &family.document(MANY_BUFFERS),
            ),
        })
        .collect()
}

// wz-proves: none -- a config key's effect on the receive buffers a link keeps, claimed for no atom
/// A session whose `transport/link/rx/buffer_size` is larger keeps more receive buffers on its
/// link, from its open and through a burst it hears, by the same count on wz and libzenohc, at
/// the default batch size and at a stated one, where the count is the size divided by the
/// link's batch.
#[test]
#[ignore = "opens sessions and reads a zenoh-c oracle; run by run-ci Layer C1cc \
            (which builds the matching ABI arm this needs)"]
fn a_larger_rx_buffer_size_keeps_more_receive_buffers_on_wz_and_libzenohc() {
    let Some(include) = oracle_or_note() else {
        return;
    };
    assert_zenoh_c_arm_pairing(&include);
    let arms = build_both_arms(&include);

    let mut failures: Vec<String> = Vec::new();
    for family in RECEIVE_FAMILIES {
        let name = family.name;
        let reference = buffer_pairs(&arms.reference, family);
        for (run, pair) in reference.iter().enumerate() {
            eprintln!(
                "{name}, libzenohc run {run}: kept at open {} kept after the burst {} ({pair:?})",
                pair.kept_at_open(),
                pair.kept_after_the_burst()
            );
            assert!(
                pair.shows_the_rule(family),
                "{name}, run {run} of the REFERENCE does not keep the receive buffers upstream's \
                 rule gives the larger size (expected {:?} more, {pair:?}), so this machine's \
                 libzenohc cannot adjudicate wz's",
                family.upstream_count()
            );
        }
        let kept = reference[0].kept_at_open();
        assert!(
            reference.iter().all(|pair| pair.kept_at_open() == kept),
            "{name}, the REFERENCE's buffers kept differ between its runs ({reference:?}), so \
             the count is not one this machine can measure"
        );

        for (run, pair) in buffer_pairs(&arms.wz, family).iter().enumerate() {
            eprintln!(
                "{name}, wz run {run}: kept at open {} kept after the burst {} ({pair:?})",
                pair.kept_at_open(),
                pair.kept_after_the_burst()
            );
            if pair.kept_at_open() != kept {
                failures.push(format!(
                    "{name}, run {run}: {} buffers beyond the smaller size's kept at the open, \
                     where libzenohc kept {kept}",
                    pair.kept_at_open()
                ));
            }
            if pair.kept_after_the_burst() != kept {
                failures.push(format!(
                    "{name}, run {run}: {} buffers beyond the smaller size's kept after the \
                     burst, where libzenohc kept {kept}",
                    pair.kept_after_the_burst()
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "wz's C ABI and libzenohc keep a different number of receive buffers for the same \
         rx/buffer_size:\n{}",
        failures.join("\n")
    );
}
