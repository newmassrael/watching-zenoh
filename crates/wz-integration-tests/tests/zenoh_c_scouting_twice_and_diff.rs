// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.27 `api-compat-c` -- a session that SCOUTS: `z_open` of a config that states no endpoint
//! and leaves multicast scouting on, on wz and on the real `libzenohc.so`.
//!
//! A default config is what every shipped example uses without `-e`, and zenoh's answer to it
//! is to look for peers and routers on the multicast group and connect to what it finds. This
//! tree refused the open outright, so a program that called `z_open` on a default config could
//! not run at all.
//!
//! The same file holds the other direction, a node that is FOUND (R3071): what it says when a
//! Scout asks for its role, read by the real library's `z_scout`, and whether a real node that is
//! told nothing finds it and connects.
//!
//! A third (R3074) is GOSSIP: how two peers that each connected to a third come to dial each
//! other, with multicast scouting off so that nothing else can introduce them. Its rows are at the
//! end of the file.
//!
//! ## What was measured before anything was built
//!
//! One C program linked to each library, on a multicast group of its own so it meets only the
//! nodes this file starts:
//!
//! - a peer and a client with no endpoint find a ROUTER and open in about ten milliseconds,
//!   and every node then hears every sender (the router routes between them);
//! - a client that finds nobody fails its open with `-4` after `scouting/timeout` (3 s by
//!   default), and a peer that finds nobody opens after `scouting/delay` (500 ms);
//! - two peers with default configs find each other, in either start order, each hearing the
//!   other.
//!
//! ## What is compared
//!
//! The ROW a node prints (its open result, who it heard from, duplicates), asserted first on the
//! real library against the row measured. The TIME an open took is compared as a bound and not
//! as a number: it is the thing scouting exists to make short, and the two libraries do not take
//! the same milliseconds.
//!
//! The group is the only thing isolating these nodes from the rest of the host, so each row has
//! one of its own.

use std::io::{BufRead, BufReader, Lines};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};

use wz_integration_tests::common::{
    assert_zenoh_c_arm_pairing, compile_zenoh_c_example, wz_capi_c_cdylib, zenoh_c_oracle,
    zenoh_c_shared_library, PortReservation,
};

/// A node: it opens a session of the given mode on the endpoints stated (a port of 0 states none)
/// with multicast scouting LEFT ON, on the group named; subscribes to the key; publishes a
/// numbered sample under its own tag every 200 ms for the given seconds; and prints what it saw.
/// Arguments: mode, listen port, connect port, key, seconds, tag, group, delay ms, timeout ms.
///
/// Its first line is `open=<rc> ms=<how long z_open took>`. After the window it prints
/// `declare=<rc> senders=<tags heard, sorted> dups=<samples that arrived twice>`.
const NODE: &str = r#"#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "zenoh.h"

#define MAX_SEEN 4096
#define MAX_SENDERS 16

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static char g_seen[MAX_SEEN][40];
static int g_seen_n = 0;
static char g_senders[MAX_SENDERS][16];
static int g_senders_n = 0;
static int g_dups = 0;

static void on_sample(z_loaned_sample_t* sample, void* arg) {
    (void)arg;
    z_owned_string_t s;
    z_bytes_to_string(z_sample_payload(sample), &s);
    char text[40];
    size_t n = z_string_len(z_loan(s));
    if (n >= sizeof text) n = sizeof text - 1;
    memcpy(text, z_string_data(z_loan(s)), n);
    text[n] = 0;
    z_drop(z_move(s));
    char* colon = strchr(text, ':');
    if (!colon) return;
    char tag[16];
    size_t tl = (size_t)(colon - text);
    if (tl >= sizeof tag) tl = sizeof tag - 1;
    memcpy(tag, text, tl);
    tag[tl] = 0;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < g_seen_n; i++) {
        if (strcmp(g_seen[i], text) == 0) { g_dups++; pthread_mutex_unlock(&g_mu); return; }
    }
    if (g_seen_n < MAX_SEEN) strcpy(g_seen[g_seen_n++], text);
    int known = 0;
    for (int i = 0; i < g_senders_n; i++) if (strcmp(g_senders[i], tag) == 0) known = 1;
    if (!known && g_senders_n < MAX_SENDERS) strcpy(g_senders[g_senders_n++], tag);
    pthread_mutex_unlock(&g_mu);
}

static int by_name(const void* a, const void* b) { return strcmp((const char*)a, (const char*)b); }

static void insert(z_owned_config_t* c, const char* k, const char* v) {
    zc_config_insert_json5(z_loan_mut(*c), k, v);
}

/* How many peers the session holds a link to, read the way `z_info_peers_zid` lists them. */
static int g_zids = 0;
static void count_zid(const z_id_t* id, void* arg) { (void)id; (void)arg; g_zids++; }
static void noop_drop(void* arg) { (void)arg; }
static int peers_of(const z_loaned_session_t* session) {
    z_owned_closure_zid_t cb;
    z_closure(&cb, count_zid, noop_drop, NULL);
    g_zids = 0;
    z_info_peers_zid(session, z_move(cb));
    return g_zids;
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 10) return 2;
    const char* mode = argv[1];
    int lport = atoi(argv[2]);
    int cport = atoi(argv[3]);
    const char* key = argv[4];
    int secs = atoi(argv[5]);
    const char* tag = argv[6];
    const char* group = argv[7];
    const char* delay = argv[8];
    const char* timeout = argv[9];
    char buf[128];

    z_owned_config_t config;
    z_config_default(&config);
    snprintf(buf, sizeof buf, "\"%s\"", mode);
    insert(&config, Z_CONFIG_MODE_KEY, buf);
    snprintf(buf, sizeof buf, "\"%s\"", group);
    /* The key as the config document spells it, as the other probes of this tree do: the
       header's macro for it is a name wz does not carry, and a probe that spelled it would
       read as a claim that it does. */
    insert(&config, "scouting/multicast/address", buf);
    insert(&config, Z_CONFIG_SCOUTING_DELAY_KEY, delay);
    insert(&config, Z_CONFIG_SCOUTING_TIMEOUT_KEY, timeout);
    /* Two knobs the answering rows turn, as text in the environment: whether the node ANSWERS a
       Scout (`scouting/multicast/listen`), and the host its listener binds. */
    if (getenv("SCOUT_LISTEN")) insert(&config, "scouting/multicast/listen", getenv("SCOUT_LISTEN"));
    /* A listen list the config STATES, empty: it suppresses the listener a peer binds by default. */
    if (getenv("LISTEN_EMPTY")) insert(&config, "listen/endpoints", "[]");
    /* Multicast scouting off, for the rows that ask what gossip alone introduces. */
    if (getenv("SCOUTING_OFF")) insert(&config, "scouting/multicast/enabled", "false");
    /* The gossip keys a row sets on ONE node of a trio, each as the json5 value the key takes,
       and the node's own id (the tie-break `greater-zid` compares). */
    if (getenv("GOSSIP_ENABLED")) insert(&config, "scouting/gossip/enabled", getenv("GOSSIP_ENABLED"));
    if (getenv("GOSSIP_AUTOCONNECT")) insert(&config, "scouting/gossip/autoconnect", getenv("GOSSIP_AUTOCONNECT"));
    if (getenv("GOSSIP_TARGET")) insert(&config, "scouting/gossip/target", getenv("GOSSIP_TARGET"));
    if (getenv("GOSSIP_STRATEGY")) insert(&config, "scouting/gossip/autoconnect_strategy", getenv("GOSSIP_STRATEGY"));
    if (getenv("NODE_ID")) insert(&config, "id", getenv("NODE_ID"));
    /* The whole `listen/endpoints` list as the json5 array the row writes, and `listen/exit_on_failure`:
       what a row sets when it needs more than the one listener the arguments can state. */
    if (getenv("LISTEN_ENDPOINTS")) insert(&config, Z_CONFIG_LISTEN_KEY, getenv("LISTEN_ENDPOINTS"));
    if (getenv("LISTEN_EXIT")) insert(&config, "listen/exit_on_failure", getenv("LISTEN_EXIT"));
    /* The bind phase's budget in milliseconds and its retry block as the json5 object it takes. */
    if (getenv("LISTEN_TIMEOUT")) insert(&config, "listen/timeout_ms", getenv("LISTEN_TIMEOUT"));
    if (getenv("LISTEN_RETRY")) insert(&config, "listen/retry", getenv("LISTEN_RETRY"));
    if (lport) {
        const char* host = getenv("LISTEN_HOST") ? getenv("LISTEN_HOST") : "127.0.0.1";
        snprintf(buf, sizeof buf, "[\"tcp/%s:%d\"]", host, lport);
        insert(&config, Z_CONFIG_LISTEN_KEY, buf);
    }
    if (cport) {
        snprintf(buf, sizeof buf, "[\"tcp/127.0.0.1:%d\"]", cport);
        insert(&config, Z_CONFIG_CONNECT_KEY, buf);
    }

    z_owned_session_t s;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int rc = z_open(&s, z_move(config), NULL);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("open=%d ms=%ld\n", rc,
           (long)((t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000));
    if (rc < 0) return 0;

    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, key);
    z_owned_closure_sample_t cb;
    z_closure(&cb, on_sample, NULL, NULL);
    z_owned_subscriber_t sub;
    int drc = z_declare_subscriber(z_loan(s), &sub, z_loan(ke), z_move(cb), NULL);

    /* Read half way through the window and not at its end: at the end the nodes are closing, and
       a node that closes first takes its links with it before the others count them. */
    int peers_mid = -1;
    for (int seq = 0; seq < secs * 5; seq++) {
        if (seq == secs * 5 / 2) peers_mid = peers_of(z_loan(s));
        char body[40];
        snprintf(body, sizeof body, "%s:%d", tag, seq);
        z_owned_bytes_t payload;
        z_bytes_copy_from_str(&payload, body);
        z_put(z_loan(s), z_loan(ke), z_move(payload), NULL);
        usleep(200 * 1000);
    }
    usleep(500 * 1000);

    pthread_mutex_lock(&g_mu);
    qsort(g_senders, (size_t)g_senders_n, sizeof g_senders[0], by_name);
    printf("declare=%d senders=", drc);
    for (int i = 0; i < g_senders_n; i++) printf("%s%s", i ? "," : "", g_senders[i]);
    printf(" dups=%d", g_dups);
    if (getenv("PEERS_MID")) printf(" peers=%d", peers_mid);
    printf("\n");
    pthread_mutex_unlock(&g_mu);
    z_drop(z_move(sub));
    z_drop(z_move(s));
    return 0;
}
"#;

/// The ASKER of the rows that ask whether a node is FOUND: `z_scout` on a group, printing every
/// Hello that answers as `hello whatami=<role> locators=[a, b]`. It is always linked to the real
/// library, so a node under test is read by the library whose reading is the standard and no
/// answer is graded by wz's own parser. The zid is not printed: two libraries never agree on it.
const PROBE: &str = r#"#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "zenoh.h"

static int g_n = 0;

static void on_hello(z_loaned_hello_t* hello, void* arg) {
    (void)arg;
    z_view_string_t w;
    z_whatami_to_view_string(z_hello_whatami(hello), &w);
    printf("hello whatami=%.*s locators=[", (int)z_string_len(z_loan(w)), z_string_data(z_loan(w)));
    z_owned_string_array_t locs;
    z_hello_locators(hello, &locs);
    const z_loaned_string_array_t* l = z_loan(locs);
    for (unsigned i = 0; i < z_string_array_len(l); i++) {
        const z_loaned_string_t* s = z_string_array_get(l, i);
        printf("%s%.*s", i ? ", " : "", (int)z_string_len(s), z_string_data(s));
    }
    printf("]\n");
    z_string_array_drop(z_move(locs));
    g_n++;
}

static void on_drop(void* arg) { (void)arg; }

/* argv: group "a.b.c.d:port", what-mask (1 router, 2 peer, 4 client), timeout in ms. */
int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 4) return 2;
    z_owned_config_t config;
    z_config_default(&config);
    char buf[128];
    snprintf(buf, sizeof buf, "\"%s\"", argv[1]);
    zc_config_insert_json5(z_loan_mut(config), "scouting/multicast/address", buf);
    z_scout_options_t opts;
    z_scout_options_default(&opts);
    opts.what = (enum z_what_t)atoi(argv[2]);
    opts.timeout_ms = (uint64_t)atoi(argv[3]);
    z_owned_closure_hello_t closure;
    z_closure(&closure, on_hello, on_drop, NULL);
    int rc = z_scout(z_move(config), z_move(closure), &opts);
    usleep(300 * 1000);
    printf("scout rc=%d\n", rc);
    return 0;
}
"#;

/// A group of this file's own, one per row: the default group is shared with every zenoh node on
/// the host, and these rows are to meet only the nodes they start.
fn next_group() -> String {
    static NEXT: AtomicU16 = AtomicU16::new(7500);
    format!("224.0.0.231:{}", NEXT.fetch_add(1, Ordering::SeqCst))
}

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

struct Built {
    exe: PathBuf,
    libdir: PathBuf,
}

struct Programs {
    _work: tempfile::TempDir,
    reference: Built,
    wz: Built,
    /// The asker of the rows that read a node's Hello: `PROBE`, linked to the real library.
    probe: Built,
}

fn compile(
    name: &str,
    source_dir: &Path,
    out: &Path,
    include: &Path,
    libdir: &Path,
    link: &str,
) -> Built {
    std::fs::create_dir_all(out).expect("build dir");
    let exe = compile_zenoh_c_example(name, out, include, source_dir, libdir, link)
        .unwrap_or_else(|d| panic!("the `{name}` program does not link against `{link}`\n{d}"));
    Built {
        exe,
        libdir: libdir.to_path_buf(),
    }
}

fn programs() -> Option<Programs> {
    let include = oracle_or_note()?;
    assert_zenoh_c_arm_pairing(&include);
    let work = tempfile::tempdir().expect("tempdir for the compiled programs");
    let src = work.path().join("src");
    std::fs::create_dir_all(&src).expect("source dir");
    std::fs::write(src.join("scout_node.c"), NODE).expect("write the source");
    std::fs::write(src.join("hello_probe.c"), PROBE).expect("write the probe source");

    let reference_lib = zenoh_c_shared_library().expect("the oracle resolved above");
    let reference_dir = reference_lib.parent().expect("libzenohc.so has a parent");
    let wz_lib = wz_capi_c_cdylib();
    let wz_dir = wz_lib.parent().expect("cdylib has a parent");
    let reference = compile(
        "scout_node",
        &src,
        &work.path().join("zenohc"),
        &include,
        reference_dir,
        "zenohc",
    );
    let wz = compile(
        "scout_node",
        &src,
        &work.path().join("wz_capi_c"),
        &include,
        wz_dir,
        "wz_capi_c",
    );
    let probe = compile(
        "hello_probe",
        &src,
        &work.path().join("probe"),
        &include,
        reference_dir,
        "zenohc",
    );
    Some(Programs {
        _work: work,
        reference,
        wz,
        probe,
    })
}

/// What a node is told.
struct Spec<'a> {
    mode: &'a str,
    listen: u16,
    connect: u16,
    key: &'a str,
    secs: u32,
    tag: &'a str,
    group: &'a str,
    delay_ms: u32,
    timeout_ms: u32,
}

/// One running node, read line by line.
struct Node {
    child: Child,
    lines: Lines<BufReader<ChildStdout>>,
}

/// What a finished node printed: its open line without the time, how long the open took, and the
/// rest.
struct Outcome {
    /// `open=<rc>` followed by what the node printed after, as one row.
    row: String,
    /// How long `z_open` took, in milliseconds.
    open_ms: u64,
}

impl Node {
    fn start(built: &Built, spec: &Spec<'_>) -> Self {
        Self::start_with(built, spec, &[])
    }

    /// [`Self::start`] with environment variables the node program reads (`SCOUT_LISTEN`,
    /// `LISTEN_HOST`).
    fn start_with(built: &Built, spec: &Spec<'_>, env: &[(&str, &str)]) -> Self {
        let mut child = Command::new(&built.exe)
            .envs(env.iter().copied())
            .args([
                spec.mode,
                &spec.listen.to_string(),
                &spec.connect.to_string(),
                spec.key,
                &spec.secs.to_string(),
                spec.tag,
                spec.group,
                &spec.delay_ms.to_string(),
                &spec.timeout_ms.to_string(),
            ])
            .env("LD_LIBRARY_PATH", &built.libdir)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn the node");
        let lines = BufReader::new(child.stdout.take().expect("piped stdout")).lines();
        Self { child, lines }
    }

    /// The node's open line, `open=<rc> ms=<n>`.
    fn opened(&mut self) -> String {
        let line = self
            .lines
            .next()
            .expect("the node prints an open line")
            .expect("read the node's stdout");
        assert!(
            line.starts_with("open="),
            "the first line is the open: {line}"
        );
        line
    }

    /// Everything after the open line, to the node's end.
    fn finish(mut self, open_line: String) -> Outcome {
        let (open, ms) = open_line
            .split_once(" ms=")
            .expect("the open line carries its time");
        let rest: Vec<String> = self
            .lines
            .by_ref()
            .map(|line| line.expect("read the node's stdout"))
            .collect();
        self.child.wait().expect("the node ends");
        Outcome {
            row: std::iter::once(open.to_owned())
                .chain(rest)
                .collect::<Vec<_>>()
                .join(" | "),
            open_ms: ms.parse().expect("the open time is a number"),
        }
    }
}

/// The row a node that found nobody and heard only itself prints.
const ALONE: &str = "open=0 | declare=0 senders=Y dups=0";

/// A node under test finds a ROUTER by scouting: the router listens on a port and answers
/// Scouts, the node states no endpoint. Returns the node's outcome and the router's.
fn find_a_router(y: &Built, reference: &Built, y_mode: &str, key: &str) -> (Outcome, Outcome) {
    let group = next_group();
    let reservation = PortReservation::pick();
    let port = reservation.port();
    let mut router = Node::start(
        reference,
        &Spec {
            mode: "router",
            listen: port,
            connect: 0,
            key,
            secs: 8,
            tag: "R",
            group: &group,
            delay_ms: 500,
            timeout_ms: 3000,
        },
    );
    let router_open = router.opened();
    drop(reservation);
    let mut node = Node::start(
        y,
        &Spec {
            mode: y_mode,
            listen: 0,
            connect: 0,
            key,
            secs: 5,
            tag: "Y",
            group: &group,
            delay_ms: 500,
            timeout_ms: 3000,
        },
    );
    let node_open = node.opened();
    (node.finish(node_open), router.finish(router_open))
}

/// THE GATE, finding a router: a peer and a client that are told nothing connect to the router
/// that answers their Scout, open quickly, and hear the router and are heard by it.
// wz-proves: api-compat-c zenoh-c->wz partial
#[test]
#[ignore = "reads a zenoh-c oracle; run by run-ci Layer C1cc (which builds the matching \
            ABI arm this needs)"]
fn a_node_with_no_endpoint_finds_a_router_by_scouting_identically_on_wz_and_libzenohc() {
    let Some(programs) = programs() else {
        return;
    };
    for (n, mode) in ["peer", "client"].into_iter().enumerate() {
        let key = format!("wz/scouting/router/{n}");
        let expect = "open=0 | declare=0 senders=R,Y dups=0";
        let (oracle, oracle_router) =
            find_a_router(&programs.reference, &programs.reference, mode, &key);
        assert_eq!(
            (oracle.row.as_str(), oracle_router.row.as_str()),
            (expect, expect),
            "the REAL library's rows for a {mode} that finds a router are not what this file \
             expects"
        );
        assert!(
            oracle.open_ms < 400,
            "the real {mode}'s open took {} ms: scouting is what makes it short",
            oracle.open_ms
        );
        let (wz, wz_router) = find_a_router(&programs.wz, &programs.reference, mode, &key);
        assert_eq!(
            (wz.row.as_str(), wz_router.row.as_str()),
            (expect, expect),
            "§5.27 api-compat-c: a wz {mode} with no endpoint does not find the router the way \
             the real library's does"
        );
        assert!(
            wz.open_ms < 400,
            "a wz {mode} found its router but its open took {} ms (the real library's took {} ms)",
            wz.open_ms,
            oracle.open_ms
        );
    }
}

/// THE GATE, an endpoint of its own: a peer whose configured endpoint is live opens at once,
/// scouting or not. The open's scouting window belongs to the endpoints it was told; it is a
/// peer with NONE that waits out `scouting/delay` for the first node it finds. (Measured: 10 ms
/// on the real library; a first wz draft added a window for scouting beside the endpoint and
/// took 508.)
// wz-proves: api-compat-c zenoh-c->wz partial
#[test]
#[ignore = "reads a zenoh-c oracle; run by run-ci Layer C1cc (which builds the matching \
            ABI arm this needs)"]
fn a_peer_with_a_live_endpoint_opens_at_once_though_it_scouts_on_wz_and_libzenohc() {
    let Some(programs) = programs() else {
        return;
    };
    let run = |built: &Built, key: &str| -> Outcome {
        let group = next_group();
        let reservation = PortReservation::pick();
        let port = reservation.port();
        let mut listener = Node::start(
            &programs.reference,
            &Spec {
                mode: "peer",
                listen: port,
                connect: 0,
                key,
                secs: 4,
                tag: "L",
                group: &group,
                delay_ms: 500,
                timeout_ms: 3000,
            },
        );
        let listening = listener.opened();
        drop(reservation);
        let mut node = Node::start(
            built,
            &Spec {
                mode: "peer",
                listen: 0,
                connect: port,
                key,
                secs: 2,
                tag: "Y",
                group: &group,
                delay_ms: 500,
                timeout_ms: 3000,
            },
        );
        let opened = node.opened();
        let outcome = node.finish(opened);
        listener.finish(listening);
        outcome
    };
    let expect = "open=0 | declare=0 senders=L,Y dups=0";
    let oracle = run(&programs.reference, "wz/scouting/endpoint/0");
    assert_eq!(
        oracle.row, expect,
        "the REAL library's row for a peer with a live endpoint"
    );
    assert!(
        oracle.open_ms < 300,
        "the real peer's open took {} ms",
        oracle.open_ms
    );
    let wz = run(&programs.wz, "wz/scouting/endpoint/1");
    assert_eq!(
        wz.row, expect,
        "§5.27 api-compat-c: a wz peer with a live endpoint hears differently"
    );
    assert!(
        wz.open_ms < 300,
        "a wz peer with a live endpoint and scouting on took {} ms to open (the real library's \
         took {} ms): it waited for a scouted connection it was not owed",
        wz.open_ms,
        oracle.open_ms
    );
}

/// One node that is told nothing, on a group nobody else is on.
fn alone(built: &Built, mode: &str, key: &str, delay_ms: u32, timeout_ms: u32) -> Outcome {
    let group = next_group();
    let mut node = Node::start(
        built,
        &Spec {
            mode,
            listen: 0,
            connect: 0,
            key,
            secs: 1,
            tag: "Y",
            group: &group,
            delay_ms,
            timeout_ms,
        },
    );
    let open = node.opened();
    node.finish(open)
}

/// THE GATE, finding nobody: a peer opens once its scouting delay has passed and a client fails
/// its open once its scouting timeout has, with the same codes on both libraries.
// wz-proves: api-compat-c zenoh-c->wz partial
#[test]
#[ignore = "reads a zenoh-c oracle; run by run-ci Layer C1cc (which builds the matching \
            ABI arm this needs)"]
fn a_node_that_scouts_and_finds_nobody_opens_or_fails_identically_on_wz_and_libzenohc() {
    let Some(programs) = programs() else {
        return;
    };
    for (n, (mode, row, at_least, below)) in [
        ("peer", ALONE, 250u64, 2_500u64),
        ("client", "open=-4", 900, 3_500),
    ]
    .into_iter()
    .enumerate()
    {
        let key = format!("wz/scouting/alone/{n}");
        let oracle = alone(&programs.reference, mode, &key, 300, 1000);
        assert_eq!(oracle.row, row, "the REAL library's row for a lone {mode}");
        assert!(
            (at_least..below).contains(&oracle.open_ms),
            "the real {mode}'s open took {} ms, outside [{at_least}, {below})",
            oracle.open_ms
        );
        let wz = alone(&programs.wz, mode, &key, 300, 1000);
        assert_eq!(
            wz.row, oracle.row,
            "§5.27 api-compat-c: a lone wz {mode} that scouts does not answer as the real one does"
        );
        assert!(
            (at_least..below).contains(&wz.open_ms),
            "a lone wz {mode}'s open took {} ms, outside [{at_least}, {below}): the real library's \
             took {} ms",
            wz.open_ms,
            oracle.open_ms
        );
    }
}

/// Two peers with default configs on one group, `x` real and `y` the node under test, started in
/// the order given. Returns `y`'s outcome and `x`'s.
fn two_peers(y: &Built, reference: &Built, y_first: bool, key: &str) -> (Outcome, Outcome) {
    let group = next_group();
    let (node_y, node_x);
    if y_first {
        let mut a = Node::start(y, &peer_spec(key, "Y", &group));
        let open_a = a.opened();
        let mut b = Node::start(reference, &peer_spec(key, "X", &group));
        let open_b = b.opened();
        node_y = a.finish(open_a);
        node_x = b.finish(open_b);
    } else {
        let mut b = Node::start(reference, &peer_spec(key, "X", &group));
        let open_b = b.opened();
        let mut a = Node::start(y, &peer_spec(key, "Y", &group));
        let open_a = a.opened();
        node_x = b.finish(open_b);
        node_y = a.finish(open_a);
    }
    (node_y, node_x)
}

/// A peer that is told nothing, on `group`, publishing for eight seconds.
fn peer_spec<'a>(key: &'a str, tag: &'a str, group: &'a str) -> Spec<'a> {
    Spec {
        mode: "peer",
        listen: 0,
        connect: 0,
        key,
        secs: 8,
        tag,
        group,
        delay_ms: 500,
        timeout_ms: 3000,
    }
}

/// THE GATE, finding a peer: two peers with default configs find each other in either start
/// order, and each hears the other.
// wz-proves: api-compat-c zenoh-c->wz partial
#[test]
#[ignore = "reads a zenoh-c oracle; run by run-ci Layer C1cc (which builds the matching \
            ABI arm this needs)"]
fn two_peers_that_scout_find_each_other_identically_on_wz_and_libzenohc() {
    let Some(programs) = programs() else {
        return;
    };
    let expect = "open=0 | declare=0 senders=X,Y dups=0";
    for (n, y_first) in [false, true].into_iter().enumerate() {
        let key = format!("wz/scouting/peers/{n}");
        let (oracle_y, oracle_x) =
            two_peers(&programs.reference, &programs.reference, y_first, &key);
        assert_eq!(
            (oracle_y.row.as_str(), oracle_x.row.as_str()),
            (expect, expect),
            "the REAL library's rows for two scouting peers (the tested one first: {y_first}) are \
             not what this file expects"
        );
        let (wz_y, wz_x) = two_peers(&programs.wz, &programs.reference, y_first, &key);
        assert_eq!(
            (wz_y.row.as_str(), wz_x.row.as_str()),
            (expect, expect),
            "§5.27 api-compat-c: a wz peer (started first: {y_first}) and a real peer that scout \
             do not find each other the way two real peers do"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// The other direction: a node that is FOUND. R3071.
// ---------------------------------------------------------------------------------------------

/// How long after a node's open it is asked, and how long the asker waits for answers: long enough
/// for every interface's Scout to be answered, short enough that a node that answers nobody is
/// known to within two seconds.
const ASK_TIMEOUT_MS: &str = "1500";

/// The Hello lines the real library's `z_scout` reads off `group` for roles `what` (1 router,
/// 2 peer, 4 client), with each locator's PORT replaced by `PORT`, sorted and without
/// repetition. Every interface a node is reachable by answers the asker's Scout once, so the same
/// line comes back more than once; the SET is the answer.
///
/// `sort_each` sorts the locators WITHIN a line as well. A node's several listeners of one
/// protocol are kept in a hash map upstream (`ListenersUnicastIP`), so the order its Hello names
/// them in is a hash order, and the real library names the same two listeners in either order from
/// one run to the next. A row that reads such a node compares them as a set. The order within a
/// line stays a thing the other rows compare, as it is for the addresses of one wildcard listener.
fn hellos(probe: &Built, group: &str, what: u8, sort_each: bool) -> Vec<String> {
    hellos_within(probe, group, what, sort_each, ASK_TIMEOUT_MS)
}

/// [`hellos`] with a window of its own, in milliseconds. A row that asks twice to tell what a
/// node says before an event from what it says after keeps each window short, so that neither
/// reaches across the event.
fn hellos_within(
    probe: &Built,
    group: &str,
    what: u8,
    sort_each: bool,
    window_ms: &str,
) -> Vec<String> {
    let output = Command::new(&probe.exe)
        .args([group, &what.to_string(), window_ms])
        .env("LD_LIBRARY_PATH", &probe.libdir)
        .stderr(Stdio::null())
        .output()
        .expect("run the scouting probe");
    let mut lines: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| line.starts_with("hello "))
        .map(|line| {
            let (head, list) = line
                .split_once("locators=[")
                .expect("a hello line carries its locators");
            let list = list.trim_end_matches(']');
            let mut ported: Vec<String> = list
                .split(", ")
                .filter(|locator| !locator.is_empty())
                .map(|locator| match locator.rsplit_once(':') {
                    Some((host, _port)) => format!("{host}:PORT"),
                    None => locator.to_owned(),
                })
                .collect();
            if sort_each {
                ported.sort();
            }
            format!("{head}locators=[{}]", ported.join(", "))
        })
        .collect();
    lines.sort();
    lines.dedup();
    lines
}

/// What a node looks like to be found. Each carries what the real library measured.
#[derive(Clone, Copy, Debug)]
enum Shape {
    /// A peer listening on loopback: its Hello names that address.
    PeerOnLoopback,
    /// A peer bound to `0.0.0.0`: its Hello names the host's own addresses and no loopback one, to
    /// an asker that is not on loopback.
    PeerOnTheWildcard,
    /// A peer told not to answer (`scouting/multicast/listen: false`): nobody finds it.
    PeerToldNotToAnswer,
    /// A peer whose config says nothing about `listen/endpoints`: it binds `tcp/[::]:0` of its own,
    /// and its Hello names the host's addresses at the port the kernel gave, as a peer bound to the
    /// wildcard does (R3071).
    PeerWithNoListener,
    /// A peer whose config STATES an empty `listen/endpoints`: it binds nothing, and its Hello
    /// names nothing.
    PeerListenStatedEmpty,
    /// A peer whose config states TWO listeners on loopback addresses of their own: its Hello names
    /// both. The ORDER is not part of the answer: upstream keeps a protocol's listeners in a hash
    /// map, and the real library names the same two in either order from one run to the next
    /// (observed both), so this row compares the locators as a set (R3076, corrected R3077).
    PeerOnTwoListeners,
    /// A peer whose only listener binds in the BACKGROUND, a port that is taken when it opens and
    /// let go 0.7 s later (`listen/timeout_ms: -1` with `listen/exit_on_failure: false`): asked
    /// before the bind its Hello names nothing, and asked after it names the listener (R3089).
    PeerBoundLate,
    /// A client connected to a peer, with a listener of its own: its Hello names the listener.
    ClientConnectedWithAListener,
    /// A client connected to a peer, with no listener: it answers with no locator.
    ClientConnectedWithNone,
    /// A client that is still SEARCHING for a node to connect to: it answers nobody, because
    /// upstream starts its responder only after `connect_first`.
    ClientStillSearching,
}

impl Shape {
    /// The role mask the asker names.
    fn what(self) -> u8 {
        match self {
            Shape::PeerOnLoopback | Shape::PeerToldNotToAnswer | Shape::PeerOnTwoListeners => 7,
            Shape::PeerOnTheWildcard
            | Shape::PeerWithNoListener
            | Shape::PeerListenStatedEmpty
            | Shape::PeerBoundLate => 2,
            Shape::ClientConnectedWithAListener
            | Shape::ClientConnectedWithNone
            | Shape::ClientStillSearching => 4,
        }
    }
}

/// Start a node of `shape` built as `built`, ask its group, and return what the real library's
/// `z_scout` reads off it.
fn hellos_of(built: &Built, reference: &Built, probe: &Built, shape: Shape) -> Vec<String> {
    let group = next_group();
    let key = "wz/scouting/found";
    // A port picked and released at once: the reservation is not reentrant, so a row that needs two
    // takes them one after the other.
    let free_port = || {
        let reservation = PortReservation::pick();
        let port = reservation.port();
        drop(reservation);
        port
    };
    let spec = |mode, listen, connect| Spec {
        mode,
        listen,
        connect,
        key,
        secs: 6,
        tag: "A",
        group: &group,
        delay_ms: 500,
        timeout_ms: 3000,
    };
    match shape {
        Shape::PeerOnLoopback
        | Shape::PeerOnTheWildcard
        | Shape::PeerToldNotToAnswer
        | Shape::PeerWithNoListener
        | Shape::PeerListenStatedEmpty
        | Shape::PeerOnTwoListeners => {
            // The two listeners' addresses differ in HOST, so that the order the Hello names them
            // in is a thing the row can tell (the probe's output has its ports made the same).
            let two = format!(
                "[\"tcp/127.0.0.1:{}\",\"tcp/127.0.0.2:{}\"]",
                free_port(),
                free_port()
            );
            let env: Vec<(&str, &str)> = match shape {
                Shape::PeerOnTheWildcard => vec![("LISTEN_HOST", "0.0.0.0")],
                Shape::PeerToldNotToAnswer => vec![("SCOUT_LISTEN", "false")],
                Shape::PeerListenStatedEmpty => vec![("LISTEN_EMPTY", "1")],
                Shape::PeerOnTwoListeners => vec![("LISTEN_ENDPOINTS", two.as_str())],
                _ => vec![],
            };
            // Three shapes state no port of their own: two bind what a peer binds or nothing, and
            // the third states its listeners whole.
            let listen = match shape {
                Shape::PeerWithNoListener
                | Shape::PeerListenStatedEmpty
                | Shape::PeerOnTwoListeners => 0,
                _ => free_port(),
            };
            let mut node = Node::start_with(built, &spec("peer", listen, 0), &env);
            let opened = node.opened();
            let found = hellos(
                probe,
                &group,
                shape.what(),
                matches!(shape, Shape::PeerOnTwoListeners),
            );
            node.finish(opened);
            found
        }
        Shape::PeerBoundLate => {
            // The one port is taken by this test and let go by a thread of its own 0.7 s after
            // the node starts; the node retries it every second from the start, so it binds at
            // about 1 s. Asked at about 0.6 s and again at 2.5 s, both with a short window, the
            // node is read before the bind and after it, and the two answers are one set.
            let port = free_port();
            let taken = TcpListener::bind(("127.0.0.1", port)).expect("the port is free to take");
            let listen = format!("[\"tcp/127.0.0.1:{port}\"]");
            let started = std::time::Instant::now();
            let released = std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(700));
                drop(taken);
            });
            let mut node = Node::start_with(
                built,
                &spec("peer", 0, 0),
                &[
                    ("LISTEN_ENDPOINTS", listen.as_str()),
                    ("LISTEN_TIMEOUT", "-1"),
                    ("LISTEN_EXIT", "false"),
                ],
            );
            let opened = node.opened();
            let wait_until = |at_ms: u64| {
                let at = std::time::Duration::from_millis(at_ms);
                std::thread::sleep(at.saturating_sub(started.elapsed()));
            };
            wait_until(600);
            let mut found = hellos_within(probe, &group, shape.what(), false, "400");
            wait_until(2500);
            found.extend(hellos_within(probe, &group, shape.what(), false, "400"));
            found.sort();
            found.dedup();
            node.finish(opened);
            released.join().expect("the thread that lets the port go");
            found
        }
        Shape::ClientConnectedWithAListener | Shape::ClientConnectedWithNone => {
            // The peer the client connects to is the real library's, so the only thing that
            // differs between the two rows of a pair is the client.
            let peer_port = free_port();
            let mut peer = Node::start(
                reference,
                &Spec {
                    tag: "L",
                    ..spec("peer", peer_port, 0)
                },
            );
            let peer_opened = peer.opened();
            let listen = match shape {
                Shape::ClientConnectedWithAListener => free_port(),
                _ => 0,
            };
            let mut node = Node::start(built, &spec("client", listen, peer_port));
            let opened = node.opened();
            let found = hellos(probe, &group, shape.what(), false);
            node.finish(opened);
            peer.finish(peer_opened);
            found
        }
        Shape::ClientStillSearching => {
            // Nothing for it to find: the group is its own, so the search runs its three seconds
            // and the asker comes in the middle of it.
            let mut node = Node::start(built, &spec("client", free_port(), 0));
            std::thread::sleep(std::time::Duration::from_millis(1200));
            let found = hellos(probe, &group, shape.what(), false);
            let opened = node.opened();
            assert!(
                opened.starts_with("open=-4"),
                "a client that finds nobody fails its open: {opened}"
            );
            node.finish(opened);
            found
        }
    }
}

/// THE GATE, being found: what a node says when a Scout asks for its role, read by the real
/// library's `z_scout`, is what the real library's own node says. The Hello carries the node's
/// role and the locators it is reached at, and a node that is not to answer, or does not yet,
/// is silent.
///
/// Measured first, one row each, then built: a peer on loopback names that address; a peer on the
/// wildcard names its host's addresses (global IPv6, public IPv4, link-local IPv6, private IPv4,
/// in that order) and no loopback to a neighbour; a client names its listener or no locator at
/// all; a peer asked for routers only does not answer; and a client that is still searching
/// answers nobody (upstream spawns its responder after `connect_first`). A peer whose config says
/// nothing about `listen/endpoints` binds `tcp/[::]:0` and names the host's addresses at the port
/// it got, and one that STATES an empty list binds nothing and names nothing (R3071).
// wz-proves: api-compat-c zenoh-c->wz partial
#[test]
#[ignore = "reads a zenoh-c oracle; run by run-ci Layer C1cc (which builds the matching \
            ABI arm this needs)"]
fn a_node_answers_a_scout_with_the_hello_the_real_library_sends_on_wz_and_libzenohc() {
    let Some(programs) = programs() else {
        return;
    };
    let loopback_peer = ["hello whatami=peer locators=[tcp/127.0.0.1:PORT]"];
    let loopback_client = ["hello whatami=client locators=[tcp/127.0.0.1:PORT]"];
    let no_locator_client = ["hello whatami=client locators=[]"];
    let no_locator_peer = ["hello whatami=peer locators=[]"];
    let two_listeners_peer =
        ["hello whatami=peer locators=[tcp/127.0.0.1:PORT, tcp/127.0.0.2:PORT]"];
    // R3089 -- before the background bind it names nothing, after it the listener.
    let bound_late_peer = [
        "hello whatami=peer locators=[]",
        "hello whatami=peer locators=[tcp/127.0.0.1:PORT]",
    ];
    for (shape, expected) in [
        (Shape::PeerOnLoopback, Some(&loopback_peer[..])),
        (Shape::PeerOnTheWildcard, None),
        (Shape::PeerWithNoListener, None),
        (Shape::PeerListenStatedEmpty, Some(&no_locator_peer[..])),
        // R3076 -- both listeners, as a set: the order the Hello names them in is a hash order.
        (Shape::PeerOnTwoListeners, Some(&two_listeners_peer[..])),
        (Shape::PeerBoundLate, Some(&bound_late_peer[..])),
        (Shape::PeerToldNotToAnswer, Some(&[][..])),
        (
            Shape::ClientConnectedWithAListener,
            Some(&loopback_client[..]),
        ),
        (Shape::ClientConnectedWithNone, Some(&no_locator_client[..])),
        (Shape::ClientStillSearching, Some(&[][..])),
    ] {
        let oracle = hellos_of(
            &programs.reference,
            &programs.reference,
            &programs.probe,
            shape,
        );
        match expected {
            Some(rows) => assert_eq!(
                oracle, rows,
                "the REAL library's Hello for {shape:?} is not what this file expects"
            ),
            // The wildcard row names the host's own addresses, so what is fixed is its SHAPE:
            // one peer Hello of IPv4 and IPv6 locators and not one of them on loopback.
            None => {
                assert_eq!(oracle.len(), 1, "one Hello for {shape:?}: {oracle:?}");
                assert!(
                    oracle[0].starts_with("hello whatami=peer locators=[tcp/")
                        && !oracle[0].contains("127.0.0.1")
                        && !oracle[0].contains("[::1]")
                        && !oracle[0].contains("locators=[]"),
                    "the real wildcard Hello is the host's own non-loopback addresses: {oracle:?}"
                );
            }
        }
        let wz = hellos_of(&programs.wz, &programs.reference, &programs.probe, shape);
        assert_eq!(
            wz, oracle,
            "§5.27 api-compat-c: a wz node of shape {shape:?} does not answer a Scout with the \
             Hello the real library's does"
        );
    }
}

/// A real node with no endpoint at all finds a node of `built`, which listens on loopback, and the
/// two hear each other. `finder_mode` is the real node's role.
fn real_finds(
    built: &Built,
    reference: &Built,
    finder_mode: &str,
    key: &str,
    stated_listener: bool,
) -> (Outcome, Outcome) {
    let group = next_group();
    let reservation = PortReservation::pick();
    let port = reservation.port();
    drop(reservation);
    // A found node that states no listener binds one of its own, as a peer does by default, and
    // names it in its Hello; the finder dials what the Hello names.
    let listen = if stated_listener { port } else { 0 };
    let mut found = Node::start(
        built,
        &Spec {
            mode: "peer",
            listen,
            connect: 0,
            key,
            secs: 8,
            tag: "F",
            group: &group,
            delay_ms: 500,
            timeout_ms: 3000,
        },
    );
    let found_open = found.opened();
    let mut finder = Node::start(
        reference,
        &Spec {
            mode: finder_mode,
            listen: 0,
            connect: 0,
            key,
            secs: 4,
            tag: "Y",
            group: &group,
            delay_ms: 500,
            timeout_ms: 3000,
        },
    );
    let finder_open = finder.opened();
    (finder.finish(finder_open), found.finish(found_open))
}

/// THE GATE, being dialled: a real node that is told nothing finds a node that listens, by
/// scouting, connects to the locator in its Hello, and the two hear each other.
///
/// A real node's open is bounded as the real library's is, client and peer alike: that is what
/// scouting is for. (A real PEER's open against a wz node ran out `scouting/delay` before R3073,
/// 506 ms against 10, because the wz node did not end what it sent with the initial interest's
/// Final; the row that isolates that is
/// `a_real_peer_that_dials_a_node_opens_at_once_identically_on_wz_and_libzenohc`.)
// wz-proves: api-compat-c zenoh-c->wz partial
#[test]
#[ignore = "reads a zenoh-c oracle; run by run-ci Layer C1cc (which builds the matching \
            ABI arm this needs)"]
fn a_real_node_that_scouts_finds_a_listening_node_identically_on_wz_and_libzenohc() {
    let Some(programs) = programs() else {
        return;
    };
    let expect = "open=0 | declare=0 senders=F,Y dups=0";
    // The found node states a loopback listener, or states none and binds its own (R3071).
    for (n, (mode, stated)) in [
        ("client", true),
        ("peer", true),
        ("client", false),
        ("peer", false),
    ]
    .into_iter()
    .enumerate()
    {
        let key = format!("wz/scouting/dialled/{n}");
        let (oracle_finder, oracle_found) =
            real_finds(&programs.reference, &programs.reference, mode, &key, stated);
        assert_eq!(
            (oracle_finder.row.as_str(), oracle_found.row.as_str()),
            (expect, expect),
            "the REAL library's rows for a {mode} that finds a peer (listener stated: {stated}) \
             are not what this file expects"
        );
        let (wz_finder, wz_found) =
            real_finds(&programs.wz, &programs.reference, mode, &key, stated);
        assert_eq!(
            (wz_finder.row.as_str(), wz_found.row.as_str()),
            (expect, expect),
            "§5.27 api-compat-c: a real {mode} that scouts does not find and hear a wz node \
             (listener stated: {stated}) the way it does a real one"
        );
        // A real node's open against a wz node is as short as against a real one, client and peer
        // alike. A peer's is not short because it was found: it is short because the wz node ends
        // what it sends with the initial interest's Final (R3073), which is what a zenoh peer's
        // open waits for, and before that it ran out `scouting/delay` (506 ms against 10).
        assert!(
            oracle_finder.open_ms < 400 && wz_finder.open_ms < 400,
            "a real {mode}'s open took {} ms against a wz node (the real node's: {} ms)",
            wz_finder.open_ms,
            oracle_finder.open_ms
        );
    }
}

/// A real peer that DIALS a node at an endpoint it is told, `connect` stated and scouting on, opens
/// at once and the two hear each other, whichever library the node is.
///
/// The row that isolates the Final: nothing was scouted, so the only thing between the real
/// peer's open and its return is what the other end sends it on connecting. Against a real peer
/// that is ten milliseconds (MEASURED 10, 11 and 20 on three runs) and against a wz peer, before
/// R3073, 506: the real library's own log says why, "Scouting delay elapsed before start
/// conditions are met", where against a real peer it says "Terminating peer connector" on the
/// `declare_final{interest_id=0}` it received.
// wz-proves: api-compat-c zenoh-c->wz partial
#[test]
#[ignore = "reads a zenoh-c oracle; run by run-ci Layer C1cc (which builds the matching \
            ABI arm this needs)"]
fn a_real_peer_that_dials_a_node_opens_at_once_identically_on_wz_and_libzenohc() {
    let Some(programs) = programs() else {
        return;
    };
    let expect = "open=0 | declare=0 senders=F,Y dups=0";
    let run = |built: &Built, key: &str| -> (Outcome, Outcome) {
        let group = next_group();
        let reservation = PortReservation::pick();
        let port = reservation.port();
        drop(reservation);
        let mut found = Node::start(
            built,
            &Spec {
                mode: "peer",
                listen: port,
                connect: 0,
                key,
                secs: 6,
                tag: "F",
                group: &group,
                delay_ms: 500,
                timeout_ms: 3000,
            },
        );
        let found_open = found.opened();
        let mut dialler = Node::start(
            &programs.reference,
            &Spec {
                mode: "peer",
                listen: 0,
                connect: port,
                key,
                secs: 3,
                tag: "Y",
                group: &group,
                delay_ms: 500,
                timeout_ms: 3000,
            },
        );
        let dialler_open = dialler.opened();
        (dialler.finish(dialler_open), found.finish(found_open))
    };
    let (oracle_dialler, oracle_found) = run(&programs.reference, "wz/scouting/dial/0");
    assert_eq!(
        (oracle_dialler.row.as_str(), oracle_found.row.as_str()),
        (expect, expect),
        "the REAL library's rows for a peer that dials a real peer are not what this file expects"
    );
    assert!(
        oracle_dialler.open_ms < 400,
        "the real peer's open against a real peer took {} ms",
        oracle_dialler.open_ms
    );
    let (wz_dialler, wz_found) = run(&programs.wz, "wz/scouting/dial/1");
    assert_eq!(
        (wz_dialler.row.as_str(), wz_found.row.as_str()),
        (expect, expect),
        "§5.27 api-compat-c: a real peer that dials a wz peer does not hear it the way it hears a \
         real one"
    );
    assert!(
        wz_dialler.open_ms < 400,
        "a real peer's open against a wz peer took {} ms (against a real peer: {} ms): the wz peer \
         did not end its declarations with the initial interest's Final, so the open ran out \
         `scouting/delay`",
        wz_dialler.open_ms,
        oracle_dialler.open_ms
    );
}

// ---------------------------------------------------------------------------------------------
// Gossip: two peers that each reached a third come to dial each other. R3074.
// ---------------------------------------------------------------------------------------------

/// A hub and two leaves, multicast scouting OFF on all three: the hub listens, each leaf connects
/// to the hub and to nothing else, and each leaf's listener is its own (`listener` says whether it
/// has one). What can introduce the leaves to each other is gossip, and only that: with
/// scouting off nothing else tells them the other exists.
///
/// Each node publishes and subscribes on `key`; `senders` is who a node heard, and a leaf hears the
/// other leaf only through a link of their own, because a peer does not route what it hears from
/// one peer to another. `peers` is how many peers each node held a link to half way through its
/// window.
///
/// The outcomes come back as `[hub, b, c]`.
fn trio(
    hub: &Built,
    b: &Built,
    c: &Built,
    key: &str,
    b_listens: bool,
    c_listens: bool,
) -> [Outcome; 3] {
    trio_with([hub, b, c], [&[], &[], &[]], key, b_listens, c_listens)
}

/// [`trio`] with environment of its own for each of the three nodes (`[hub, b, c]`), which is how
/// a gossip key is set on ONE of them: the node program turns `GOSSIP_ENABLED`,
/// `GOSSIP_AUTOCONNECT`, `GOSSIP_TARGET`, `GOSSIP_STRATEGY` and `NODE_ID` into the config key
/// each names.
fn trio_with(
    libs: [&Built; 3],
    extra: [&[(&'static str, &'static str)]; 3],
    key: &str,
    b_listens: bool,
    c_listens: bool,
) -> [Outcome; 3] {
    let [hub, b, c] = libs;
    let group = next_group();
    let reservation = PortReservation::pick();
    let port = reservation.port();
    drop(reservation);
    let spec = |tag, secs, listen, connect| Spec {
        mode: "peer",
        listen,
        connect,
        key,
        secs,
        tag,
        group: &group,
        delay_ms: 500,
        timeout_ms: 3000,
    };
    let env_of = |listens: bool,
                  own: &[(&'static str, &'static str)]|
     -> Vec<(&'static str, &'static str)> {
        let mut env = vec![("SCOUTING_OFF", "1"), ("PEERS_MID", "1")];
        if !listens {
            env.push(("LISTEN_EMPTY", "1"));
        }
        env.extend_from_slice(own);
        env
    };
    let mut hub = Node::start_with(hub, &spec("A", 6, port, 0), &env_of(true, extra[0]));
    let hub_open = hub.opened();
    let mut b = Node::start_with(b, &spec("B", 4, 0, port), &env_of(b_listens, extra[1]));
    let b_open = b.opened();
    let mut c = Node::start_with(c, &spec("C", 4, 0, port), &env_of(c_listens, extra[2]));
    let c_open = c.opened();
    [hub.finish(hub_open), b.finish(b_open), c.finish(c_open)]
}

/// The libraries of a trio's three nodes, as the row's placements name them: the real library
/// first, then wz in one place and in all of them.
fn placements(programs: &Programs) -> [(&'static str, [&Built; 3]); 5] {
    let (r, w) = (&programs.reference, &programs.wz);
    [
        ("the real library everywhere", [r, r, r]),
        ("a wz hub", [w, r, r]),
        ("a wz leaf B", [r, w, r]),
        ("a wz leaf C", [r, r, w]),
        ("wz everywhere", [w, w, w]),
    ]
}

/// THE GATE, gossip: two leaves of a hub are introduced to each other, and one dials the other.
///
/// A leaf that has a listener tells the hub where it is when it connects, and the hub tells the
/// other leaf, which dials it. Here only one leaf (B) can be dialled, so only one dial is made
/// and the two never dial each other at once, which the real library does not resolve either: two
/// leaves that BOTH listen are introduced to each other twice, and MEASURED over twelve runs on the
/// real library and on wz alike, nine ended connected, one ended with a link one leaf could not
/// use and two ended with none. That race is upstream's own and is not what this row compares.
///
/// Every node holds two peers and hears all three senders, whichever library any one of them is:
/// the hub's introduction is read by a leaf of the other library, and a leaf of one library
/// dials a leaf of the other.
// wz-proves: api-compat-c zenoh-c->wz partial
#[test]
#[ignore = "reads a zenoh-c oracle; run by run-ci Layer C1cc (which builds the matching \
            ABI arm this needs)"]
fn two_leaves_of_a_hub_are_introduced_identically_on_wz_and_libzenohc() {
    let Some(programs) = programs() else {
        return;
    };
    let expect = "open=0 | declare=0 senders=A,B,C dups=0 peers=2";
    for (n, (name, [hub, b, c])) in placements(&programs).into_iter().enumerate() {
        let key = format!("wz/gossip/introduced/{n}");
        let rows = trio(hub, b, c, &key, true, false);
        let rows = rows.map(|outcome| outcome.row);
        let got = rows.each_ref().map(String::as_str);
        let message = if n == 0 {
            "the REAL library's rows for two leaves of a hub, one of them dialable, are not what \
             this file expects"
                .to_owned()
        } else {
            format!(
                "§5.27 api-compat-c: two leaves of a hub are not introduced the way they are by \
                 the real library ({name}); the rows are the hub's, then the dialable leaf's and \
                 the leaf with no listener's"
            )
        };
        assert_eq!(got, [expect; 3], "{message}");
    }
}

/// THE CONTROL of the row above: leaves with no listener are not introduced.
///
/// Neither can be dialled, so neither is told of the other as a node to dial, and with scouting
/// off nothing else introduces them: each hears the hub and itself and no one else, and holds one
/// peer. It is what makes the row above a measurement of the introduction and not of some other
/// path between the leaves, on the real library and on wz both.
// wz-proves: api-compat-c zenoh-c->wz partial
#[test]
#[ignore = "reads a zenoh-c oracle; run by run-ci Layer C1cc (which builds the matching \
            ABI arm this needs)"]
fn leaves_that_cannot_be_dialled_are_not_introduced_identically_on_wz_and_libzenohc() {
    let Some(programs) = programs() else {
        return;
    };
    let expect = [
        "open=0 | declare=0 senders=A,B,C dups=0 peers=2",
        "open=0 | declare=0 senders=A,B dups=0 peers=1",
        "open=0 | declare=0 senders=A,C dups=0 peers=1",
    ];
    for (n, (name, [hub, b, c])) in placements(&programs).into_iter().enumerate() {
        let key = format!("wz/gossip/not-introduced/{n}");
        let rows = trio(hub, b, c, &key, false, false);
        let rows = rows.map(|outcome| outcome.row);
        let got = rows.each_ref().map(String::as_str);
        assert_eq!(
            got,
            expect,
            "{}",
            if n == 0 {
                "the REAL library's rows for two leaves with no listener are not what this file \
                 expects"
                    .to_owned()
            } else {
                format!(
                    "§5.27 api-compat-c: leaves with no listener meet ({name}), which the real \
                     library does not let them do with nobody to tell them where each other is"
                )
            }
        );
    }
}

// ---------------------------------------------------------------------------------------------
// The gossip keys: what a C session does with them. R3075.
// ---------------------------------------------------------------------------------------------

/// One node's environment, as the node program reads it: a gossip key's json5 value, or an id.
type NodeEnv = &'static [(&'static str, &'static str)];

/// What a trio prints when the two leaves met, all three holding two peers and hearing all three
/// senders, and when they did not: each leaf heard the hub and itself and holds one peer.
const MET: [&str; 3] = [
    "open=0 | declare=0 senders=A,B,C dups=0 peers=2",
    "open=0 | declare=0 senders=A,B,C dups=0 peers=2",
    "open=0 | declare=0 senders=A,B,C dups=0 peers=2",
];
const APART: [&str; 3] = [
    "open=0 | declare=0 senders=A,B,C dups=0 peers=2",
    "open=0 | declare=0 senders=A,B dups=0 peers=1",
    "open=0 | declare=0 senders=A,C dups=0 peers=1",
];

/// One setting of a gossip key on one node of a trio (`env` is `[hub, b, c]`), and whether the
/// leaves still meet under it. Leaf B has a listener and leaf C has none, so the only dial there
/// can be is C's to B, which is what a key on C changes and a key on B or the hub changes by
/// what it lets them tell C.
struct Setting {
    what: &'static str,
    env: [NodeEnv; 3],
    met: bool,
}

/// Every setting is run twice, the real library on all three nodes first and asserted against what
/// MEASURED on it, then with the node that carries the key on wz and the other two real. A setting
/// that is red on the first run is a wrong measurement and says so; one that is red on the second
/// is a wz node that does not read the key the way the real library does.
fn run_settings(programs: &Programs, family: &str, settings: &[Setting]) {
    for (n, setting) in settings.iter().enumerate() {
        let key = format!("wz/gossip/keys/{family}/{n}");
        let expect = if setting.met { MET } else { APART };
        let (r, w) = (&programs.reference, &programs.wz);
        let real = trio_with([r, r, r], setting.env, &key, true, false);
        let real = real.map(|outcome| outcome.row);
        assert_eq!(
            real.each_ref().map(String::as_str),
            expect,
            "the REAL library's rows for `{}` are not what this file expects",
            setting.what
        );
        // The node under test is the one that carries the setting; a setting on two nodes (the
        // strategy rows give B and C an id each) puts both of them on wz.
        let libs = [0usize, 1, 2].map(|i| if setting.env[i].is_empty() { r } else { w });
        let got = trio_with(libs, setting.env, &format!("{key}/wz"), true, false);
        let got = got.map(|outcome| outcome.row);
        assert_eq!(
            got.each_ref().map(String::as_str),
            expect,
            "§5.27 api-compat-c: with `{}` on a wz node the leaves do not do what they do on the \
             real library; the rows are the hub's, then the dialable leaf's and the other's",
            setting.what
        );
    }
}

const OFF: NodeEnv = &[("GOSSIP_ENABLED", "false")];
const NO_AUTOCONNECT: NodeEnv = &[("GOSSIP_AUTOCONNECT", "{router:[],peer:[],client:[]}")];
const NO_TARGET: NodeEnv = &[("GOSSIP_TARGET", "{router:[],peer:[]}")];

/// THE GATE, `scouting/gossip/enabled`: a node told not to gossip sends no topology and takes in
/// none, so with it off on the hub, on the leaf that listens or on the leaf that dials, the leaves
/// are not introduced.
// wz-proves: api-compat-c zenoh-c->wz partial
#[test]
#[ignore = "reads a zenoh-c oracle; run by run-ci Layer C1cc (which builds the matching \
            ABI arm this needs)"]
fn a_node_told_not_to_gossip_introduces_no_one_identically_on_wz_and_libzenohc() {
    let Some(programs) = programs() else {
        return;
    };
    run_settings(
        &programs,
        "enabled",
        &[
            Setting {
                what: "gossip off on the hub",
                env: [OFF, &[], &[]],
                met: false,
            },
            Setting {
                what: "gossip off on the leaf that listens",
                env: [&[], OFF, &[]],
                met: false,
            },
            Setting {
                what: "gossip off on the leaf that dials",
                env: [&[], &[], OFF],
                met: false,
            },
        ],
    );
}

/// THE GATE, `scouting/gossip/autoconnect` and `target`: the first is whom a node DIALS when it is
/// told of one and the second whom it TELLS. A leaf that dials nobody does not meet the other; a
/// hub or a listening leaf that dials nobody changes nothing, since neither had a dial to make; a
/// hub or a listening leaf that tells nobody introduces no one, and a dialling leaf that tells
/// nobody still hears of the other and dials it.
// wz-proves: api-compat-c zenoh-c->wz partial
#[test]
#[ignore = "reads a zenoh-c oracle; run by run-ci Layer C1cc (which builds the matching \
            ABI arm this needs)"]
fn a_nodes_autoconnect_and_target_decide_whom_it_dials_and_tells_identically_on_wz_and_libzenohc() {
    let Some(programs) = programs() else {
        return;
    };
    run_settings(
        &programs,
        "reach",
        &[
            Setting {
                what: "autoconnect empty on the leaf that dials",
                env: [&[], &[], NO_AUTOCONNECT],
                met: false,
            },
            Setting {
                what: "autoconnect empty on the hub",
                env: [NO_AUTOCONNECT, &[], &[]],
                met: true,
            },
            Setting {
                what: "autoconnect empty on the leaf that listens",
                env: [&[], NO_AUTOCONNECT, &[]],
                met: true,
            },
            Setting {
                what: "target empty on the hub",
                env: [NO_TARGET, &[], &[]],
                met: false,
            },
            Setting {
                what: "target empty on the leaf that listens",
                env: [&[], NO_TARGET, &[]],
                met: false,
            },
            Setting {
                what: "target empty on the leaf that dials",
                env: [&[], &[], NO_TARGET],
                met: true,
            },
        ],
    );
}

/// THE GATE, `scouting/gossip/autoconnect_strategy`: under `greater-zid` only the node whose id
/// is the greater dials, so the leaf that dials reaches the other when its id is the greater and
/// does not when it is the lesser; `always` dials either way.
// wz-proves: api-compat-c zenoh-c->wz partial
#[test]
#[ignore = "reads a zenoh-c oracle; run by run-ci Layer C1cc (which builds the matching \
            ABI arm this needs)"]
fn the_autoconnect_strategy_decides_which_end_dials_identically_on_wz_and_libzenohc() {
    let Some(programs) = programs() else {
        return;
    };
    const GREATER: &str = "{router:\"greater-zid\",peer:\"greater-zid\",client:\"greater-zid\"}";
    const ALWAYS: &str = "{router:\"always\",peer:\"always\",client:\"always\"}";
    run_settings(
        &programs,
        "strategy",
        &[
            Setting {
                what: "greater-zid, the dialling leaf's id the greater",
                env: [
                    &[],
                    &[("NODE_ID", "\"2\"")],
                    &[("NODE_ID", "\"3\""), ("GOSSIP_STRATEGY", GREATER)],
                ],
                met: true,
            },
            Setting {
                what: "greater-zid, the dialling leaf's id the lesser",
                env: [
                    &[],
                    &[("NODE_ID", "\"3\"")],
                    &[("NODE_ID", "\"2\""), ("GOSSIP_STRATEGY", GREATER)],
                ],
                met: false,
            },
            Setting {
                what: "always, the dialling leaf's id the lesser",
                env: [
                    &[],
                    &[("NODE_ID", "\"3\"")],
                    &[("NODE_ID", "\"2\""), ("GOSSIP_STRATEGY", ALWAYS)],
                ],
                met: true,
            },
        ],
    );
}

/// THE GATE, a target that names `client`: the open of a peer whose gossip target includes the
/// role is REFUSED, `-4`, by the real library (`"client" is not allowed as gossip target`), and by
/// wz; a target that names only routers and peers opens, as does one that is empty.
// wz-proves: api-compat-c zenoh-c->wz partial
#[test]
#[ignore = "reads a zenoh-c oracle; run by run-ci Layer C1cc (which builds the matching \
            ABI arm this needs)"]
fn a_gossip_target_that_names_clients_fails_the_open_identically_on_wz_and_libzenohc() {
    let Some(programs) = programs() else {
        return;
    };
    let open_of = |built: &Built, key: &str, target: &'static str| -> String {
        let group = next_group();
        let mut node = Node::start_with(
            built,
            &Spec {
                mode: "peer",
                listen: 0,
                connect: 0,
                key,
                secs: 1,
                tag: "Y",
                group: &group,
                delay_ms: 500,
                timeout_ms: 3000,
            },
            &[("SCOUTING_OFF", "1"), ("GOSSIP_TARGET", target)],
        );
        let open = node.opened();
        let outcome = node.finish(open);
        outcome
            .row
            .split(" | ")
            .next()
            .unwrap_or_default()
            .to_owned()
    };
    for (n, (target, want)) in [
        (r#"{peer:["client"]}"#, "open=-4"),
        (r#"{router:["router"],peer:["router","client"]}"#, "open=-4"),
        (r#"{peer:["router","peer"]}"#, "open=0"),
        ("{peer:[]}", "open=0"),
    ]
    .into_iter()
    .enumerate()
    {
        let key = format!("wz/gossip/target-client/{n}");
        let real = open_of(&programs.reference, &key, target);
        assert_eq!(
            real, want,
            "the REAL library's open under the target `{target}` is not what this file expects"
        );
        let wz = open_of(&programs.wz, &key, target);
        assert_eq!(
            wz, want,
            "§5.27 api-compat-c: a wz peer's open under the gossip target `{target}` is not the \
             real library's"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// The listen set: every endpoint a node states is bound, and a bind that fails is the open's
// failure unless the config says to go on. R3076.
// ---------------------------------------------------------------------------------------------

/// A port picked and released at once, for an endpoint a row states and then binds itself.
fn a_free_port() -> u16 {
    let reservation = PortReservation::pick();
    let port = reservation.port();
    drop(reservation);
    port
}

/// The endpoints of a `listen/endpoints` list on loopback, as the json5 array the node program
/// takes.
fn loopback_endpoints(ports: &[u16]) -> String {
    let each: Vec<String> = ports
        .iter()
        .map(|port| format!("\"tcp/127.0.0.1:{port}\""))
        .collect();
    format!("[{}]", each.join(","))
}

/// A hub built as `hub` that states `listen` and whatever else `hub_extra` sets, and one leaf of
/// `leaf` for each port in `leaf_ports`, each connecting to its port and listening on nothing.
/// Scouting is off, so a leaf reaches the hub only by the endpoint it was given. The outcomes come
/// back hub first, then the leaves in the order of their ports, tagged `B`, `C`.
fn hub_and_leaves(
    hub: &Built,
    leaf: &Built,
    key: &str,
    listen: &str,
    hub_extra: &[(&str, &str)],
    leaf_ports: &[u16],
) -> Vec<Outcome> {
    let group = next_group();
    let spec = |tag, secs, connect| Spec {
        mode: "peer",
        listen: 0,
        connect,
        key,
        secs,
        tag,
        group: &group,
        delay_ms: 500,
        timeout_ms: 3000,
    };
    let mut hub_env = vec![
        ("SCOUTING_OFF", "1"),
        ("PEERS_MID", "1"),
        ("LISTEN_ENDPOINTS", listen),
    ];
    hub_env.extend_from_slice(hub_extra);
    let hub_secs = if leaf_ports.is_empty() { 2 } else { 6 };
    let mut hub = Node::start_with(hub, &spec("A", hub_secs, 0), &hub_env);
    let hub_open = hub.opened();
    let leaves: Vec<(Node, String)> = leaf_ports
        .iter()
        .zip(["B", "C"])
        .map(|(port, tag)| {
            let mut node = Node::start_with(
                leaf,
                &spec(tag, 4, *port),
                &[
                    ("SCOUTING_OFF", "1"),
                    ("PEERS_MID", "1"),
                    ("LISTEN_EMPTY", "1"),
                ],
            );
            let open = node.opened();
            (node, open)
        })
        .collect();
    let mut outcomes = vec![hub.finish(hub_open)];
    outcomes.extend(leaves.into_iter().map(|(node, open)| node.finish(open)));
    outcomes
}

/// What `z_open` returned on a peer that states `listen` and `extra`, as the row's `open=<rc>`.
fn open_code_of(built: &Built, key: &str, listen: &str, extra: &[(&str, &str)]) -> String {
    let group = next_group();
    let mut env = vec![("SCOUTING_OFF", "1"), ("LISTEN_ENDPOINTS", listen)];
    env.extend_from_slice(extra);
    let mut node = Node::start_with(
        built,
        &Spec {
            mode: "peer",
            listen: 0,
            connect: 0,
            key,
            secs: 1,
            tag: "Y",
            group: &group,
            delay_ms: 500,
            timeout_ms: 3000,
        },
        &env,
    );
    let open = node.opened();
    let outcome = node.finish(open);
    outcome
        .row
        .split(" | ")
        .next()
        .unwrap_or_default()
        .to_owned()
}

/// THE GATE, the listen set: a peer that states two endpoints is reached at BOTH.
///
/// One leaf connects to each endpoint, with scouting off and no listener of its own, so a leaf
/// that is not told where the hub is has no way to it. The hub holds both links, and each leaf
/// holds one and hears the hub and itself and not the other leaf, which neither can dial: on the
/// real library, and on wz only if every endpoint of the list is bound and not only the first.
// wz-proves: api-compat-c zenoh-c->wz partial
#[test]
#[ignore = "reads a zenoh-c oracle; run by run-ci Layer C1cc (which builds the matching \
            ABI arm this needs)"]
fn a_peer_that_states_two_listeners_is_reached_at_both_identically_on_wz_and_libzenohc() {
    let Some(programs) = programs() else {
        return;
    };
    for (n, (name, hub)) in [
        ("the real library", &programs.reference),
        ("wz", &programs.wz),
    ]
    .into_iter()
    .enumerate()
    {
        let ports = [a_free_port(), a_free_port()];
        let key = format!("wz/listen-set/reach/{n}");
        let rows = hub_and_leaves(
            hub,
            &programs.reference,
            &key,
            &loopback_endpoints(&ports),
            &[],
            &ports,
        );
        let rows: Vec<&str> = rows.iter().map(|outcome| outcome.row.as_str()).collect();
        assert_eq!(
            rows,
            APART,
            "{}",
            if n == 0 {
                "the REAL library's rows for a peer with two listeners are not what this file \
                 expects"
                    .to_owned()
            } else {
                format!(
                    "§5.27 api-compat-c: a {name} peer that states two listeners is not reached \
                     at both, as the real library is"
                )
            }
        );
    }
}

/// One row of the table of opens: what `z_open` returns for a peer that states `listen` and the
/// settings `extra` (the node program's environment), as the row `open=<rc>`.
struct OpenRow<'a> {
    what: &'a str,
    listen: String,
    extra: &'a [(&'a str, &'a str)],
    want: &'a str,
}

/// One row of the table of skips: the ports a hub states as its `listen`, the ports a leaf is
/// started for (one leaf for each), and the rows the hub and then each leaf print.
struct SkipRow<'a> {
    what: &'a str,
    ports: Vec<u16>,
    leaves: &'a [u16],
    want: &'a [&'a str],
}

/// THE GATE, `listen/exit_on_failure`: an endpoint that cannot be bound fails the open, `-4`, by
/// default and when the key says `true`, whichever of the endpoints it is and whatever is bound
/// before it, on the real library and on wz.
// wz-proves: api-compat-c zenoh-c->wz partial
#[test]
#[ignore = "reads a zenoh-c oracle; run by run-ci Layer C1cc (which builds the matching \
            ABI arm this needs)"]
fn a_listener_that_cannot_bind_fails_the_open_identically_on_wz_and_libzenohc() {
    let Some(programs) = programs() else {
        return;
    };
    let taken = TcpListener::bind("127.0.0.1:0").expect("a port to hold");
    let taken_port = taken.local_addr().expect("the held port").port();
    let also_taken = TcpListener::bind("127.0.0.1:0").expect("a second port to hold");
    let also_taken_port = also_taken.local_addr().expect("the held port").port();
    let free = a_free_port();
    let rows = [
        OpenRow {
            what: "the taken endpoint second, by default",
            listen: loopback_endpoints(&[free, taken_port]),
            extra: &[],
            want: "open=-4",
        },
        OpenRow {
            what: "the taken endpoint first, by default",
            listen: loopback_endpoints(&[taken_port, free]),
            extra: &[],
            want: "open=-4",
        },
        OpenRow {
            what: "every endpoint taken, by default",
            listen: loopback_endpoints(&[taken_port, also_taken_port]),
            extra: &[],
            want: "open=-4",
        },
        OpenRow {
            what: "the taken endpoint second, the key `true`",
            listen: loopback_endpoints(&[free, taken_port]),
            extra: &[("LISTEN_EXIT", "true")],
            want: "open=-4",
        },
        OpenRow {
            what: "a free endpoint alone, by default",
            listen: loopback_endpoints(&[free]),
            extra: &[],
            want: "open=0",
        },
    ];
    for (n, row) in rows.iter().enumerate() {
        let (what, want) = (row.what, row.want);
        let key = format!("wz/listen-set/exit/{n}");
        let real = open_code_of(&programs.reference, &key, &row.listen, row.extra);
        assert_eq!(
            real, want,
            "the REAL library's open with {what} is not what this file expects"
        );
        let wz = open_code_of(&programs.wz, &key, &row.listen, row.extra);
        assert_eq!(
            wz, want,
            "§5.27 api-compat-c: a wz peer's open with {what} is not the real library's"
        );
    }
}

/// THE GATE, `listen/exit_on_failure: false`: the endpoints that cannot be bound are skipped, the
/// open succeeds, and the ones that could be bound accept, on the real library and on wz.
///
/// A leaf of the free endpoint reaches the hub whichever side of the list the taken endpoint is
/// on, and a hub whose every endpoint is taken opens and listens on nothing.
// wz-proves: api-compat-c zenoh-c->wz partial
#[test]
#[ignore = "reads a zenoh-c oracle; run by run-ci Layer C1cc (which builds the matching \
            ABI arm this needs)"]
fn a_listener_that_cannot_bind_is_skipped_when_told_to_identically_on_wz_and_libzenohc() {
    let Some(programs) = programs() else {
        return;
    };
    let taken = TcpListener::bind("127.0.0.1:0").expect("a port to hold");
    let taken_port = taken.local_addr().expect("the held port").port();
    let also_taken = TcpListener::bind("127.0.0.1:0").expect("a second port to hold");
    let also_taken_port = also_taken.local_addr().expect("the held port").port();
    let off = [("LISTEN_EXIT", "false")];
    let one_leaf = [
        "open=0 | declare=0 senders=A,B dups=0 peers=1",
        "open=0 | declare=0 senders=A,B dups=0 peers=1",
    ];
    let alone = ["open=0 | declare=0 senders=A dups=0 peers=0"];
    for (n, (hub_name, hub)) in [
        ("the real library", &programs.reference),
        ("wz", &programs.wz),
    ]
    .into_iter()
    .enumerate()
    {
        let free = a_free_port();
        let rows = [
            SkipRow {
                what: "the taken endpoint second",
                ports: vec![free, taken_port],
                leaves: &[free],
                want: &one_leaf,
            },
            SkipRow {
                what: "the taken endpoint first",
                ports: vec![taken_port, free],
                leaves: &[free],
                want: &one_leaf,
            },
            SkipRow {
                what: "every endpoint taken",
                ports: vec![taken_port, also_taken_port],
                leaves: &[],
                want: &alone,
            },
        ];
        for (m, row) in rows.iter().enumerate() {
            let (what, want) = (row.what, row.want);
            let key = format!("wz/listen-set/skip/{n}/{m}");
            let got = hub_and_leaves(
                hub,
                &programs.reference,
                &key,
                &loopback_endpoints(&row.ports),
                &off,
                row.leaves,
            );
            let got: Vec<&str> = got.iter().map(|outcome| outcome.row.as_str()).collect();
            assert_eq!(
                got,
                want,
                "{}",
                if n == 0 {
                    format!(
                        "the REAL library's rows with {what}, `listen/exit_on_failure: false`, \
                         are not what this file expects"
                    )
                } else {
                    format!(
                        "§5.27 api-compat-c: a {hub_name} peer with {what} and \
                         `listen/exit_on_failure: false` is not what the real library is"
                    )
                }
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The bind phase: how long and how often an endpoint that cannot be bound is tried. R3089.
// ---------------------------------------------------------------------------------------------

/// One row of the table of bind budgets: what is done to the one port a peer states as its
/// listener, the settings the peer is given, and what the open and the listener do.
struct BudgetRow<'a> {
    what: &'a str,
    /// How long after the node starts the port is let go, or `None` for a port that stays taken.
    freed_after_ms: Option<u64>,
    extra: &'a [(&'a str, &'a str)],
    /// The bounds `z_open` returns inside, in milliseconds, whichever library it is.
    open_within_ms: (u64, u64),
    /// What the node prints, then what a leaf started well after the port is let go prints, or
    /// `None` for a row that starts no leaf.
    hub: &'a str,
    leaf: Option<&'a str>,
}

/// The node and its leaf, as [`BudgetRow`] sets them up. The port is taken by this test and let go
/// by a thread of its own at the instant the row names, counted from the node's start; a leaf
/// connects to the port 1.7 s in, after the real library's first retry (1 s) has bound it.
fn budget_run(
    hub: &Built,
    leaf: &Built,
    key: &str,
    row: &BudgetRow<'_>,
) -> (Outcome, Option<Outcome>) {
    let group = next_group();
    let port = a_free_port();
    let taken = TcpListener::bind(("127.0.0.1", port)).expect("the port is free to take");
    let listen = loopback_endpoints(&[port]);
    let mut env = vec![
        ("SCOUTING_OFF", "1"),
        ("PEERS_MID", "1"),
        ("LISTEN_ENDPOINTS", listen.as_str()),
    ];
    env.extend_from_slice(row.extra);
    let started = std::time::Instant::now();
    let (held, released) = match row.freed_after_ms {
        Some(after) => (
            None,
            Some(std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(after));
                drop(taken);
            })),
        ),
        None => (Some(taken), None),
    };
    let spec = |tag, secs, connect| Spec {
        mode: "peer",
        listen: 0,
        connect,
        key,
        secs,
        tag,
        group: &group,
        delay_ms: 500,
        timeout_ms: 3000,
    };
    let mut node = Node::start_with(
        hub,
        &spec("A", if row.leaf.is_some() { 6 } else { 2 }, 0),
        &env,
    );
    let opened = node.opened();
    let started_leaf = row.leaf.map(|_| {
        let wait = std::time::Duration::from_millis(1700).saturating_sub(started.elapsed());
        std::thread::sleep(wait);
        let mut leaf_node = Node::start_with(
            leaf,
            &spec("B", 3, port),
            &[
                ("SCOUTING_OFF", "1"),
                ("PEERS_MID", "1"),
                ("LISTEN_EMPTY", "1"),
            ],
        );
        let leaf_opened = leaf_node.opened();
        (leaf_node, leaf_opened)
    });
    let hub_outcome = node.finish(opened);
    let leaf_outcome = started_leaf.map(|(leaf_node, opened)| leaf_node.finish(opened));
    if let Some(thread) = released {
        thread.join().expect("the thread that lets the port go");
    }
    drop(held);
    (hub_outcome, leaf_outcome)
}

/// THE GATE, the bind phase: an endpoint that cannot be bound is tried again, on the `listen/retry`
/// schedule, when `listen/timeout_ms` is not zero.
///
/// With `exit_on_failure` true (the default) the open is HELD UP until the endpoint binds, and
/// fails with -4 when the budget is spent first; with it false the open returns at once and the
/// endpoint is bound in the background, to be reached once it is. A budget of zero, the shipped
/// default, tries once. MEASURED on the real library: a port let go 0.7 s in is bound at the first
/// retry, 1 s, and the open returns then, or, with a retry schedule of 200 ms doubling, at 1.4 s.
// wz-proves: api-compat-c zenoh-c->wz partial
#[test]
#[ignore = "reads a zenoh-c oracle; run by run-ci Layer C1cc (which builds the matching \
            ABI arm this needs)"]
fn a_bind_that_fails_is_tried_again_inside_its_budget_identically_on_wz_and_libzenohc() {
    let Some(programs) = programs() else {
        return;
    };
    const ALONE: &str = "open=0 | declare=0 senders=A dups=0 peers=0";
    const REACHED: &str = "open=0 | declare=0 senders=A,B dups=0 peers=1";
    const QUICK: &[(&str, &str)] = &[(
        "LISTEN_RETRY",
        "{period_init_ms:200,period_max_ms:2000,period_increase_factor:2}",
    )];
    let rows = [
        BudgetRow {
            what: "a port let go at 0.7 s, a budget of 3 s, the default schedule",
            freed_after_ms: Some(700),
            extra: &[("LISTEN_TIMEOUT", "3000")],
            open_within_ms: (900, 2500),
            hub: ALONE,
            leaf: None,
        },
        BudgetRow {
            what: "a port that stays taken, a budget of 0.6 s",
            freed_after_ms: None,
            extra: &[("LISTEN_TIMEOUT", "600")],
            open_within_ms: (500, 1500),
            hub: "open=-4",
            leaf: None,
        },
        BudgetRow {
            what: "a port that stays taken, a budget of 0.6 s, exit_on_failure false",
            freed_after_ms: None,
            extra: &[("LISTEN_TIMEOUT", "600"), ("LISTEN_EXIT", "false")],
            open_within_ms: (0, 500),
            hub: ALONE,
            leaf: None,
        },
        BudgetRow {
            what: "a port let go at 0.7 s, no bound on the budget, exit_on_failure false",
            freed_after_ms: Some(700),
            extra: &[("LISTEN_TIMEOUT", "-1"), ("LISTEN_EXIT", "false")],
            open_within_ms: (0, 500),
            hub: REACHED,
            leaf: Some(REACHED),
        },
        BudgetRow {
            what: "a port let go at 0.7 s, no bound on the budget, exit_on_failure true",
            freed_after_ms: Some(700),
            extra: &[("LISTEN_TIMEOUT", "-1")],
            open_within_ms: (900, 2500),
            hub: REACHED,
            leaf: Some(REACHED),
        },
        BudgetRow {
            what: "a port let go at 0.7 s, a budget of 5 s, a schedule of 200 ms doubling",
            freed_after_ms: Some(700),
            extra: &[("LISTEN_TIMEOUT", "5000"), QUICK[0]],
            open_within_ms: (1250, 1900),
            hub: ALONE,
            leaf: None,
        },
        BudgetRow {
            what: "a port let go at 0.7 s and the shipped budget of zero",
            freed_after_ms: Some(700),
            extra: &[],
            open_within_ms: (0, 500),
            hub: "open=-4",
            leaf: None,
        },
    ];
    for (n, row) in rows.iter().enumerate() {
        for (library, hub, is_real) in [
            ("the real library", &programs.reference, true),
            ("wz", &programs.wz, false),
        ] {
            let key = format!("wz/listen-set/budget/{n}/{}", u8::from(is_real));
            let (hub_outcome, leaf_outcome) = budget_run(hub, &programs.reference, &key, row);
            let who = if is_real {
                String::from("the REAL library's")
            } else {
                format!("§5.27 api-compat-c: a {library} peer's")
            };
            assert_eq!(
                hub_outcome.row, row.hub,
                "{who} node with {} is not what this file expects",
                row.what
            );
            let (lowest, highest) = row.open_within_ms;
            assert!(
                (lowest..=highest).contains(&hub_outcome.open_ms),
                "{who} open took {} ms with {}, outside {lowest}..={highest}",
                hub_outcome.open_ms,
                row.what
            );
            assert_eq!(
                leaf_outcome.as_ref().map(|outcome| outcome.row.as_str()),
                row.leaf,
                "{who} leaf, started after the port was let go, with {}",
                row.what
            );
        }
    }
}

/// A hub whose only listener binds in the BACKGROUND, a node B that dials the hub once it has and
/// also listens, and a node C that dials B alone, all three with scouting off. The three nodes are
/// returned as `[hub, b, c]`.
///
/// The hub's port is taken by this test and let go 0.7 s after the hub starts; the hub's listener
/// is bound at its first retry, about 1 s in, B starts at 1.5 s and C at 2.8 s. C knows no address
/// but B's, so it can reach the hub only if B tells it where the hub is: B was told by the hub, at
/// its own bootstrap, and the address the hub tells is one of the listeners it holds then.
fn late_hub_line(hub: &Built, b: &Built, c: &Built, key: &str) -> [Outcome; 3] {
    let group = next_group();
    let (port_hub, port_b) = (a_free_port(), a_free_port());
    let taken = TcpListener::bind(("127.0.0.1", port_hub)).expect("the port is free to take");
    let hub_listens = loopback_endpoints(&[port_hub]);
    let started = std::time::Instant::now();
    let released = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(700));
        drop(taken);
    });
    let spec = |tag, secs, listen, connect| Spec {
        mode: "peer",
        listen,
        connect,
        key,
        secs,
        tag,
        group: &group,
        delay_ms: 500,
        timeout_ms: 3000,
    };
    let wait_until = |at_ms: u64| {
        let at = std::time::Duration::from_millis(at_ms);
        std::thread::sleep(at.saturating_sub(started.elapsed()));
    };
    let mut hub_node = Node::start_with(
        hub,
        &spec("A", 9, 0, 0),
        &[
            ("SCOUTING_OFF", "1"),
            ("PEERS_MID", "1"),
            ("LISTEN_ENDPOINTS", hub_listens.as_str()),
            ("LISTEN_TIMEOUT", "-1"),
            ("LISTEN_EXIT", "false"),
        ],
    );
    let hub_open = hub_node.opened();
    wait_until(1500);
    let mut b_node = Node::start_with(
        b,
        &spec("B", 7, port_b, port_hub),
        &[("SCOUTING_OFF", "1"), ("PEERS_MID", "1")],
    );
    let b_open = b_node.opened();
    wait_until(2800);
    let mut c_node = Node::start_with(
        c,
        &spec("C", 5, 0, port_b),
        &[
            ("SCOUTING_OFF", "1"),
            ("PEERS_MID", "1"),
            ("LISTEN_EMPTY", "1"),
        ],
    );
    let c_open = c_node.opened();
    let outcomes = [
        hub_node.finish(hub_open),
        b_node.finish(b_open),
        c_node.finish(c_open),
    ];
    released.join().expect("the thread that lets the port go");
    outcomes
}

/// THE GATE, gossip of a listener bound late: a node that dials a hub only after the hub's
/// background bind is told where the hub is, and tells it on to a node that dials it, so a third
/// node reaches the hub by an address it was never given.
///
/// Every node ends up holding two peers and hearing all three senders: C dialled B alone and
/// found the hub from B's gossip. The row asserts the real library's rows first, and then the
/// same line with a wz hub, the node whose listener binds late.
// wz-proves: api-compat-c zenoh-c->wz partial
#[test]
#[ignore = "reads a zenoh-c oracle; run by run-ci Layer C1cc (which builds the matching \
            ABI arm this needs)"]
fn a_listener_bound_late_is_gossiped_to_a_node_that_dials_its_neighbour_on_wz_and_libzenohc() {
    let Some(programs) = programs() else {
        return;
    };
    let (r, w) = (&programs.reference, &programs.wz);
    for (n, (name, [hub, b, c])) in [
        ("the real library everywhere", [r, r, r]),
        ("a wz hub", [w, r, r]),
    ]
    .into_iter()
    .enumerate()
    {
        let key = format!("wz/gossip/late-hub/{n}");
        let rows = late_hub_line(hub, b, c, &key).map(|outcome| outcome.row);
        let got = rows.each_ref().map(String::as_str);
        assert_eq!(
            got,
            MET,
            "{}",
            if n == 0 {
                String::from(
                    "the REAL library's rows for a hub whose listener binds late are not what \
                     this file expects",
                )
            } else {
                format!(
                    "§5.27 api-compat-c: a node that dials the neighbour of a hub whose listener \
                     bound late does not find the hub, as it does on the real library ({name}); \
                     the rows are the hub's, then B's and C's"
                )
            }
        );
    }
}
