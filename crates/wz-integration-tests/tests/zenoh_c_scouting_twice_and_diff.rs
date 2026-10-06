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
    if (lport) {
        snprintf(buf, sizeof buf, "[\"tcp/127.0.0.1:%d\"]", lport);
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

    for (int seq = 0; seq < secs * 5; seq++) {
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
    printf(" dups=%d\n", g_dups);
    pthread_mutex_unlock(&g_mu);
    z_drop(z_move(sub));
    z_drop(z_move(s));
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
}

fn compile(source_dir: &Path, out: &Path, include: &Path, libdir: &Path, link: &str) -> Built {
    std::fs::create_dir_all(out).expect("build dir");
    let exe = compile_zenoh_c_example("scout_node", out, include, source_dir, libdir, link)
        .unwrap_or_else(|d| panic!("the node program does not link against `{link}`\n{d}"));
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

    let reference_lib = zenoh_c_shared_library().expect("the oracle resolved above");
    let reference_dir = reference_lib.parent().expect("libzenohc.so has a parent");
    let wz_lib = wz_capi_c_cdylib();
    let wz_dir = wz_lib.parent().expect("cdylib has a parent");
    let reference = compile(
        &src,
        &work.path().join("zenohc"),
        &include,
        reference_dir,
        "zenohc",
    );
    let wz = compile(
        &src,
        &work.path().join("wz_capi_c"),
        &include,
        wz_dir,
        "wz_capi_c",
    );
    Some(Programs {
        _work: work,
        reference,
        wz,
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
        let mut child = Command::new(&built.exe)
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
