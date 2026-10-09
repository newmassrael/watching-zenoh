// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.27 `api-compat-c` -- the ROLES of a session: what `z_open` makes of the endpoints a config
//! states, on wz and on the real `libzenohc.so`.
//!
//! zenoh starts a node by role. A peer or router binds its listeners, then connects to its
//! peers, then (with multicast scouting on) scouts; a client binds its listeners, then connects to
//! ONE peer, and with scouting off and nothing to connect to it bails. `z_open` of this tree drove
//! one role per session, so three configs a program for zenoh-c writes without a thought were
//! refused: no endpoint at all, a `listen` beside a `connect`, and (by the same code) a client
//! stated with both.
//!
//! ## What was measured before anything was built
//!
//! One C program, linked to each library, with multicast scouting off:
//!
//! - a peer or a router with NO endpoint opens (`open=0`) and delivers to its own subscriber;
//! - a client with no endpoint, and a client with only a `listen`, fail the open with `-4`
//!   (zenoh's `start_client`: "No peer specified and multicast scouting deactivated!"). wz
//!   answered `-1` for the first and opened the second as a listener;
//! - a peer that lists a `connect` endpoint nobody listens on opens (`open=0`, after the start
//!   window), as does one that only listens: both already matched;
//! - a peer that listens on `Y` and dials `X`, with a third node dialling `Y`, hears all three
//!   nodes' samples, and the same stated as a CLIENT hears only the node it dialled: a client's
//!   routing owns exactly one face, so the listener is bound and serves nothing;
//! - two peers that each listen and dial the other keep ONE link: every sample arrives once. wz,
//!   once it could open them, held two faces to one node and delivered every sample twice
//!   (30 duplicates over six seconds).
//!
//! ## What this does not compare
//!
//! `z_info_peers_zid` is not compared: on the REAL library one side of a mutual dial reports one
//! peer and the other none, from one run to the next, so it is not a thing two libraries agree on.
//! Neither are the counts of samples, which depend on who connected first.
//!
//! The rows are the intersection of what both libraries do with multicast scouting OFF. A config
//! with scouting on and no endpoint still opens on the real library and is refused here, and
//! that is the one gap this file does not close.

use std::io::{BufRead, BufReader, Lines};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};

use wz_integration_tests::bounded::BoundedChild as _;
use wz_integration_tests::common::{
    assert_zenoh_c_arm_pairing, compile_zenoh_c_example, wz_capi_c_cdylib, zenoh_c_oracle,
    zenoh_c_shared_library, PortReservation,
};

/// A node: it opens a session of the given mode on the endpoints stated (a port of 0 states none),
/// subscribes to the key, publishes a numbered sample under its own tag every 200 ms for the
/// given number of seconds, and prints what it saw. Arguments: mode, listen port, connect port,
/// key, seconds, tag.
///
/// Its first line is always `open=<rc>`. After the window it prints `declare=<rc> senders=<tags
/// heard, sorted> dups=<samples that arrived more than once>`.
const NODE: &str = r#"#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
    if (argc < 7) return 2;
    const char* mode = argv[1];
    int lport = atoi(argv[2]);
    int cport = atoi(argv[3]);
    const char* key = argv[4];
    int secs = atoi(argv[5]);
    const char* tag = argv[6];
    char buf[128];

    z_owned_config_t config;
    z_config_default(&config);
    insert(&config, Z_CONFIG_MULTICAST_SCOUTING_KEY, "false");
    snprintf(buf, sizeof buf, "\"%s\"", mode);
    insert(&config, Z_CONFIG_MODE_KEY, buf);
    if (lport) {
        snprintf(buf, sizeof buf, "[\"tcp/127.0.0.1:%d\"]", lport);
        insert(&config, Z_CONFIG_LISTEN_KEY, buf);
    }
    if (cport) {
        snprintf(buf, sizeof buf, "[\"tcp/127.0.0.1:%d\"]", cport);
        insert(&config, Z_CONFIG_CONNECT_KEY, buf);
    }

    z_owned_session_t s;
    int rc = z_open(&s, z_move(config), NULL);
    printf("open=%d\n", rc);
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

/// What a node that opened alone, or beside peers it never reached, prints: it hears only itself.
const ALONE: &str = "open=0 | declare=0 senders=N dups=0";

/// What a failed open prints: the real library's `Z_ENETWORK`.
const REFUSED: &str = "open=-4";

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

/// One program compiled against one library: the executable and the directory its library is in.
struct Built {
    exe: PathBuf,
    libdir: PathBuf,
}

/// The node program linked to each library.
struct Programs {
    /// Held so the executables outlive the test.
    _work: tempfile::TempDir,
    reference: Built,
    wz: Built,
}

fn compile(source_dir: &Path, out: &Path, include: &Path, libdir: &Path, link: &str) -> Built {
    std::fs::create_dir_all(out).expect("build dir");
    let exe = compile_zenoh_c_example("role_node", out, include, source_dir, libdir, link)
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
    std::fs::write(src.join("role_node.c"), NODE).expect("write the source");

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

/// What a node is told: its mode, the endpoints it states (a port of 0 states none), the key it
/// publishes and subscribes on, how many seconds it publishes for, and the tag its samples carry.
struct Spec<'a> {
    mode: &'a str,
    listen: u16,
    connect: u16,
    key: &'a str,
    secs: u32,
    tag: &'a str,
}

/// One running node, read line by line.
struct Node {
    child: Child,
    lines: Lines<BufReader<ChildStdout>>,
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
            ])
            .env("LD_LIBRARY_PATH", &built.libdir)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn the node");
        let lines = BufReader::new(child.stdout.take().expect("piped stdout")).lines();
        Self { child, lines }
    }

    /// The node's `open=` line, which is the first thing it prints and which it prints once its
    /// listener, if it has one, is bound.
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

    /// Everything the node prints after its open line, to its end.
    fn finish(mut self) -> Vec<String> {
        let rest = self
            .lines
            .by_ref()
            .map(|line| line.expect("read the node's stdout"))
            .collect();
        self.child.wait_bounded().expect("the node ends");
        rest
    }
}

/// One node's whole output as one row: its open line, then what it printed after.
fn row(open: String, rest: Vec<String>) -> String {
    std::iter::once(open)
        .chain(rest)
        .collect::<Vec<_>>()
        .join(" | ")
}

/// One session alone: the endpoints a config can state, and what each library makes of them.
struct Alone {
    name: &'static str,
    mode: &'static str,
    listens: bool,
    /// Dials a port nobody listens on.
    dials: bool,
    /// What the REAL library prints. Asserted first, so a row that drifts on the oracle's side is
    /// seen as that and not as wz failing.
    expect: &'static str,
}

fn alone_rows() -> Vec<Alone> {
    vec![
        Alone {
            name: "a peer with no endpoint opens alone",
            mode: "peer",
            listens: false,
            dials: false,
            expect: ALONE,
        },
        Alone {
            name: "a router with no endpoint opens alone",
            mode: "router",
            listens: false,
            dials: false,
            expect: ALONE,
        },
        Alone {
            name: "a client with no endpoint fails its open",
            mode: "client",
            listens: false,
            dials: false,
            expect: REFUSED,
        },
        Alone {
            name: "a client with only a listener fails its open",
            mode: "client",
            listens: true,
            dials: false,
            expect: REFUSED,
        },
        Alone {
            name: "a peer that only listens opens",
            mode: "peer",
            listens: true,
            dials: false,
            expect: ALONE,
        },
        Alone {
            name: "a peer whose connect endpoint nobody listens on opens",
            mode: "peer",
            listens: false,
            dials: true,
            expect: ALONE,
        },
        Alone {
            name: "a client whose connect endpoint nobody listens on fails its open",
            mode: "client",
            listens: false,
            dials: true,
            expect: REFUSED,
        },
    ]
}

/// One row on one library.
fn run_alone(built: &Built, spec: &Alone, n: usize) -> String {
    let (reservation, refused_port) = PortReservation::pick_pair();
    let key = format!("wz/roles/alone/{n}");
    let mut node = Node::start(
        built,
        &Spec {
            mode: spec.mode,
            listen: if spec.listens { reservation.port() } else { 0 },
            connect: if spec.dials { refused_port } else { 0 },
            key: &key,
            secs: 1,
            tag: "N",
        },
    );
    let open = node.opened();
    drop(reservation);
    row(open, node.finish())
}

/// THE GATE, no peer: the endpoints a config states, or does not, decide whether `z_open` answers,
/// and with which code, identically on wz and on the real library.
// wz-proves: api-compat-c zenoh-c->wz partial
#[test]
#[ignore = "reads a zenoh-c oracle; run by run-ci Layer C1cc (which builds the matching \
            ABI arm this needs)"]
fn a_session_opens_on_the_endpoints_its_config_states_identically_on_wz_and_libzenohc() {
    let Some(programs) = programs() else {
        return;
    };
    let mut disagreements = Vec::new();
    for (n, spec) in alone_rows().iter().enumerate() {
        let oracle = run_alone(&programs.reference, spec, n);
        assert_eq!(
            oracle, spec.expect,
            "the REAL library's row for `{}` is not what this file expects",
            spec.name
        );
        let wz = run_alone(&programs.wz, spec, n);
        if wz != oracle {
            disagreements.push(format!(
                "{}:\n  libzenohc {oracle}\n  wz        {wz}",
                spec.name
            ));
        }
    }
    assert!(
        disagreements.is_empty(),
        "§5.27 api-compat-c: wz opens differently from libzenohc on {} of {} rows:\n{}",
        disagreements.len(),
        alone_rows().len(),
        disagreements.join("\n")
    );
}

/// The topology: `X` listens, `Y` (the node under test) listens and dials `X`, and `Z` dials `Y`.
/// Only `Y` is built against the library being measured; `X` and `Z` are the real library's on
/// both rows, so what is compared is what `Y` makes of the two sides it is reached from. Returns
/// `Y`'s row.
fn dual_topology(y: &Built, reference: &Built, y_mode: &str, key: &str) -> String {
    let reservation = PortReservation::pick();
    let x_port = reservation.port();
    let mut x = Node::start(
        reference,
        &Spec {
            mode: "peer",
            listen: x_port,
            connect: 0,
            key,
            secs: 8,
            tag: "X",
        },
    );
    x.opened();
    drop(reservation);

    let reservation = PortReservation::pick();
    let y_port = reservation.port();
    let mut node = Node::start(
        y,
        &Spec {
            mode: y_mode,
            listen: y_port,
            connect: x_port,
            key,
            secs: 6,
            tag: "Y",
        },
    );
    let open = node.opened();
    drop(reservation);

    let mut z = Node::start(
        reference,
        &Spec {
            mode: "peer",
            listen: 0,
            connect: y_port,
            key,
            secs: 7,
            tag: "Z",
        },
    );
    z.opened();

    let row = row(open, node.finish());
    x.finish();
    z.finish();
    row
}

/// THE GATE, one node in both roles: a peer that listens and dials hears the node it dialled and
/// the node that dialled it, and a client stated the same way hears only the node it dialled.
// wz-proves: api-compat-c zenoh-c->wz partial
#[test]
#[ignore = "reads a zenoh-c oracle; run by run-ci Layer C1cc (which builds the matching \
            ABI arm this needs)"]
fn a_node_that_listens_and_dials_is_reached_from_both_sides_identically_on_wz_and_libzenohc() {
    let Some(programs) = programs() else {
        return;
    };
    for (n, (mode, expect)) in [
        ("peer", "open=0 | declare=0 senders=X,Y,Z dups=0"),
        ("client", "open=0 | declare=0 senders=X,Y dups=0"),
    ]
    .into_iter()
    .enumerate()
    {
        let key = format!("wz/roles/dual/{n}");
        let oracle = dual_topology(&programs.reference, &programs.reference, mode, &key);
        assert_eq!(
            oracle, expect,
            "the REAL library's row for a {mode} that listens and dials is not what this file expects"
        );
        let wz = dual_topology(&programs.wz, &programs.reference, mode, &key);
        assert_eq!(
            wz, oracle,
            "§5.27 api-compat-c: a {mode} that listens and dials hears something other than the \
             real library's does\n  libzenohc {oracle}\n  wz        {wz}"
        );
    }
}

/// Two peers that each listen on their own port and dial the other's. Returns both rows.
fn mutual_dial(a: &Built, b: &Built, key: &str) -> (String, String) {
    let (reservation, b_port) = PortReservation::pick_pair();
    let a_port = reservation.port();
    let mut node_a = Node::start(
        a,
        &Spec {
            mode: "peer",
            listen: a_port,
            connect: b_port,
            key,
            secs: 5,
            tag: "A",
        },
    );
    let mut node_b = Node::start(
        b,
        &Spec {
            mode: "peer",
            listen: b_port,
            connect: a_port,
            key,
            secs: 5,
            tag: "B",
        },
    );
    let open_a = node_a.opened();
    let open_b = node_b.opened();
    drop(reservation);
    (row(open_a, node_a.finish()), row(open_b, node_b.finish()))
}

/// THE GATE, one link per node: two peers that each listen and dial the other hear each other's
/// samples ONCE, in every pairing of the two libraries.
// wz-proves: api-compat-c zenoh-c->wz partial
#[test]
#[ignore = "reads a zenoh-c oracle; run by run-ci Layer C1cc (which builds the matching \
            ABI arm this needs)"]
fn two_peers_that_dial_each_other_keep_one_link_identically_on_wz_and_libzenohc() {
    let Some(programs) = programs() else {
        return;
    };
    let expect = (
        "open=0 | declare=0 senders=A,B dups=0".to_owned(),
        "open=0 | declare=0 senders=A,B dups=0".to_owned(),
    );
    let oracle = mutual_dial(
        &programs.reference,
        &programs.reference,
        "wz/roles/mutual/0",
    );
    assert_eq!(
        oracle, expect,
        "the REAL library's rows for two peers that dial each other are not what this file expects"
    );
    for (n, (a, b, what)) in [
        (&programs.wz, &programs.wz, "wz and wz"),
        (&programs.wz, &programs.reference, "wz and libzenohc"),
        (&programs.reference, &programs.wz, "libzenohc and wz"),
    ]
    .into_iter()
    .enumerate()
    {
        let key = format!("wz/roles/mutual/{}", n + 1);
        let got = mutual_dial(a, b, &key);
        assert_eq!(
            got, oracle,
            "§5.27 api-compat-c: two peers ({what}) that dial each other do not keep one link \
             the way two real peers do\n  libzenohc {oracle:?}\n  this pair {got:?}"
        );
    }
}
