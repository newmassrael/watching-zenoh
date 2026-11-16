// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `aggregation/subscribers` and `aggregation/publishers`: the key expressions a session
//! declares its subscribers and its publishers UNDER, on wz and on the real `libzenohc.so`.
//!
//! ## What upstream does with the two lists
//!
//! A subscriber whose key the first listed aggregate includes is declared as that aggregate,
//! once, and every later subscriber under it shares the declaration
//! (`zenoh/src/api/session.rs` @ `.aggregated_subscribers`). A publisher does the same with the
//! subscribers interest it sends at declare time
//! (`zenoh/src/api/session.rs` @ `.aggregated_publishers`). So a node with two subscribers and two
//! publishers under one aggregate each puts ONE declaration and ONE interest on its link where
//! it would otherwise put two of each.
//!
//! ## The observer, and why it is a zenohd
//!
//! What the lists change is what the node's neighbour holds for it, which no API of the node
//! itself reports. A zenohd router reports exactly that: its admin space answers one key per
//! resource its clients subscribe on (`zenoh/src/net/runtime/adminspace.rs` @
//! `add_handler!("subscriber", "**", subscribers_data);`) and one per resource their publishers
//! ask subscribers of (`zenoh/src/net/runtime/adminspace.rs` @
//! `add_handler!("publisher", "**", publishers_data);`), the second read off the interests the
//! client sent (`zenoh/src/net/routing/hat/broker/pubsub.rs` @
//! `fn sourced_publishers(&self, tables: &TablesData) -> HashMap<Arc<Resource>, Sources> {`).
//!
//! One C program, compiled against each library, opens a CLIENT of that router from one config
//! document, declares two subscribers on `wz/agg/s/one` and `wz/agg/s/two` and two publishers on
//! `wz/agg/p/one` and `wz/agg/p/two`, and holds them. The same program built against the REAL
//! library then asks the router's admin space which keys it holds, so the asking side is the same
//! on both rows and only the node under it changes. The real library's answer is asserted first,
//! for the document with the list and for the one without it (the control), and wz's answer is
//! then held to it.

use std::io::{BufRead, BufReader, Lines};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::time::Duration;

use wz_integration_tests::bounded::BoundedChild as _;
use wz_integration_tests::common::{
    assert_zenoh_c_arm_pairing, compile_zenoh_c_example, spawn_zenohd_on_ephemeral_tcp,
    wz_capi_c_cdylib, zenoh_c_oracle, zenoh_c_shared_library,
};

/// The program, in two modes.
///
/// `node <port> <subscriber aggregates> <publisher aggregates> <seconds>` opens a client of the
/// router at `tcp/127.0.0.1:<port>`, states each aggregate list that is not `-` as the JSON5 value
/// of its key, declares the two subscribers and the two publishers, prints `open=<rc> cfg=<rc>`
/// and `declared=<rc>`, and holds them for the given seconds.
///
/// `ask <port> <selector> <marker>` opens a client of the same router, gets the selector, and
/// prints `get=<rc> keys=<k1>,<k2>` with the part of each reply key after `<marker>` that begins
/// with `wz/`, sorted: the router's own admin entries are not the subject.
const AGGREGATION_NODE: &str = r#"#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "zenoh.h"

#define MAX_KEYS 64

static const char* SUBSCRIBED[2] = {"wz/agg/s/one", "wz/agg/s/two"};
static const char* PUBLISHED[2] = {"wz/agg/p/one", "wz/agg/p/two"};

static int first(int kept, int next) { return kept != 0 ? kept : next; }

static int insert(z_owned_config_t* c, const char* k, const char* v) {
    return zc_config_insert_json5(z_loan_mut(*c), k, v);
}

static int client_of(z_owned_config_t* c, const char* port) {
    char buf[64];
    z_config_default(c);
    int rc = insert(c, Z_CONFIG_MULTICAST_SCOUTING_KEY, "false");
    rc = first(rc, insert(c, Z_CONFIG_MODE_KEY, "\"client\""));
    snprintf(buf, sizeof buf, "[\"tcp/127.0.0.1:%s\"]", port);
    return first(rc, insert(c, Z_CONFIG_CONNECT_KEY, buf));
}

static void on_sample(z_loaned_sample_t* sample, void* arg) {
    (void)sample;
    (void)arg;
}

static int node(char** argv) {
    z_owned_config_t config;
    int cfg = client_of(&config, argv[2]);
    if (strcmp(argv[3], "-") != 0) cfg = first(cfg, insert(&config, "aggregation/subscribers", argv[3]));
    if (strcmp(argv[4], "-") != 0) cfg = first(cfg, insert(&config, "aggregation/publishers", argv[4]));
    int secs = atoi(argv[5]);

    z_owned_session_t s;
    int rc = z_open(&s, z_move(config), NULL);
    printf("open=%d cfg=%d\n", rc, cfg);
    if (rc < 0) return 0;

    z_owned_subscriber_t subs[2];
    z_owned_publisher_t pubs[2];
    int declared = 0;
    for (int i = 0; i < 2; i++) {
        z_view_keyexpr_t ke;
        z_view_keyexpr_from_str(&ke, SUBSCRIBED[i]);
        z_owned_closure_sample_t cb;
        z_closure(&cb, on_sample, NULL, NULL);
        declared = first(declared, z_declare_subscriber(z_loan(s), &subs[i], z_loan(ke), z_move(cb), NULL));
    }
    for (int i = 0; i < 2; i++) {
        z_view_keyexpr_t ke;
        z_view_keyexpr_from_str(&ke, PUBLISHED[i]);
        declared = first(declared, z_declare_publisher(z_loan(s), &pubs[i], z_loan(ke), NULL));
    }
    printf("declared=%d\n", declared);
    sleep((unsigned)secs);
    for (int i = 0; i < 2; i++) {
        z_drop(z_move(subs[i]));
        z_drop(z_move(pubs[i]));
    }
    z_drop(z_move(s));
    return 0;
}

static int by_name(const void* a, const void* b) { return strcmp((const char*)a, (const char*)b); }

static int ask(char** argv) {
    z_owned_config_t config;
    int cfg = client_of(&config, argv[2]);
    const char* selector = argv[3];
    const char* marker = argv[4];

    z_owned_session_t s;
    int rc = z_open(&s, z_move(config), NULL);
    if (rc < 0) {
        printf("open=%d cfg=%d\n", rc, cfg);
        return 0;
    }
    z_view_keyexpr_t ke;
    int got = z_view_keyexpr_from_str(&ke, selector);
    z_owned_fifo_handler_reply_t handler;
    z_owned_closure_reply_t closure;
    z_fifo_channel_reply_new(&closure, &handler, MAX_KEYS);
    z_get_options_t opts;
    z_get_options_default(&opts);
    opts.timeout_ms = 5000;
    got = first(got, z_get(z_loan(s), z_loan(ke), NULL, z_move(closure), &opts));

    static char keys[MAX_KEYS][128];
    int n = 0;
    z_owned_reply_t reply;
    while (z_recv(z_loan(handler), &reply) == Z_OK) {
        if (z_reply_is_ok(z_loan(reply))) {
            const z_loaned_sample_t* sample = z_reply_ok(z_loan(reply));
            z_view_string_t k;
            z_keyexpr_as_view_string(z_sample_keyexpr(sample), &k);
            char text[256];
            size_t len = z_string_len(z_loan(k));
            if (len >= sizeof text) len = sizeof text - 1;
            memcpy(text, z_string_data(z_loan(k)), len);
            text[len] = 0;
            const char* at = strstr(text, marker);
            if (at != NULL && n < MAX_KEYS) {
                at += strlen(marker);
                if (strncmp(at, "wz/", 3) == 0) {
                    snprintf(keys[n], sizeof keys[n], "%s", at);
                    n++;
                }
            }
        }
        z_drop(z_move(reply));
    }
    qsort(keys, (size_t)n, sizeof keys[0], by_name);
    printf("get=%d keys=", got);
    for (int i = 0; i < n; i++) printf("%s%s", i ? "," : "", keys[i]);
    printf("\n");
    z_drop(z_move(handler));
    z_drop(z_move(s));
    return 0;
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc == 6 && strcmp(argv[1], "node") == 0) return node(argv);
    if (argc == 5 && strcmp(argv[1], "ask") == 0) return ask(argv);
    return 2;
}
"#;

/// The subscriber aggregate the document with `aggregation/subscribers` states.
const SUBSCRIBER_AGGREGATES: &str = r#"["wz/agg/s/**"]"#;
/// The publisher aggregate the document with `aggregation/publishers` states.
const PUBLISHER_AGGREGATES: &str = r#"["wz/agg/p/**"]"#;

/// What the router holds for the node's subscribers, as the asking program prints it.
const SUBSCRIBERS_EACH: &str = "get=0 keys=wz/agg/s/one,wz/agg/s/two";
const SUBSCRIBERS_AGGREGATED: &str = "get=0 keys=wz/agg/s/**";
/// What the router holds for the node's publishers' interests.
const PUBLISHERS_EACH: &str = "get=0 keys=wz/agg/p/one,wz/agg/p/two";
const PUBLISHERS_AGGREGATED: &str = "get=0 keys=wz/agg/p/**";

/// The node's own two lines: it opened on its document and declared all four entities.
const NODE_OPENED: &str = "open=0 cfg=0 | declared=0";

/// How long the node holds its entities: past the settle and both questions.
const HOLD_SECS: u32 = 20;
/// How long the router gets to take the node's declarations before it is asked.
const SETTLE: Duration = Duration::from_millis(1500);

/// The oracle, or `None` with a LOUD note naming what to do about it.
fn oracle_or_note() -> Option<PathBuf> {
    match zenoh_c_oracle() {
        Some((include, _libdir, _examples)) => Some(include),
        None => {
            eprintln!(
                "skip: the zenoh-c ORACLE is absent. This leg needs zenoh-c's headers \
                 and libzenohc.so (default prefix ~/.local, override WZ_ZENOH_C_PREFIX). \
                 Layer C1cd with WZ_C1CD_REQUIRE=1 fails instead of skipping."
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

/// The program linked to each library.
struct Programs {
    /// Held so the executables outlive the test.
    _work: tempfile::TempDir,
    reference: Built,
    wz: Built,
}

fn compile(source_dir: &Path, out: &Path, include: &Path, libdir: &Path, link: &str) -> Built {
    std::fs::create_dir_all(out).expect("build dir");
    let exe = compile_zenoh_c_example("aggregation_node", out, include, source_dir, libdir, link)
        .unwrap_or_else(|d| panic!("the aggregation program does not link against `{link}`\n{d}"));
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
    std::fs::write(src.join("aggregation_node.c"), AGGREGATION_NODE).expect("write the source");

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

/// A running copy of the program, read line by line.
struct Running {
    child: Child,
    lines: Lines<BufReader<ChildStdout>>,
}

impl Running {
    fn start(built: &Built, args: &[&str]) -> Self {
        let mut child = Command::new(&built.exe)
            .args(args)
            .env("LD_LIBRARY_PATH", &built.libdir)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn the aggregation program");
        let lines = BufReader::new(child.stdout.take().expect("piped stdout")).lines();
        Self { child, lines }
    }

    /// The next line the program prints, or `<ended>` when it printed nothing more.
    fn line(&mut self) -> String {
        match self.lines.next() {
            Some(line) => line.expect("read the program's stdout"),
            None => String::from("<ended>"),
        }
    }

    fn stop(mut self) {
        let _ = self.child.kill();
        self.child.wait_bounded().expect("the program ends");
    }

    fn finish(mut self) -> String {
        let line = self.line();
        self.child.wait_bounded().expect("the program ends");
        line
    }
}

/// The aggregate lists a document states: `None` leaves the key out.
#[derive(Clone, Copy)]
struct Document {
    subscribers: Option<&'static str>,
    publishers: Option<&'static str>,
}

/// What one node, opened on `document`, leaves a router holding: its own two lines, then the
/// router's subscriber keys and publisher keys as the REAL library's program reads them.
#[derive(Debug, PartialEq, Eq)]
struct Held {
    node: String,
    subscribers: String,
    publishers: String,
}

fn held_by_router(node: &Built, asker: &Built, document: Document) -> Held {
    let (mut router, port) = spawn_zenohd_on_ephemeral_tcp(|| {
        tempfile::tempfile().expect("zenohd handshake probe stderr")
    });
    let port = port.to_string();
    let mut running = Running::start(
        node,
        &[
            "node",
            &port,
            document.subscribers.unwrap_or("-"),
            document.publishers.unwrap_or("-"),
            &HOLD_SECS.to_string(),
        ],
    );
    let opened = running.line();
    let declared = running.line();
    std::thread::sleep(SETTLE);
    let ask = |selector: &str, marker: &str| {
        Running::start(asker, &["ask", &port, selector, marker]).finish()
    };
    let subscribers = ask("@/*/router/subscriber/**", "/subscriber/");
    let publishers = ask("@/*/router/publisher/**", "/publisher/");
    running.stop();
    let _ = router.child_mut().kill();
    let _ = router.child_mut().wait_bounded();
    Held {
        node: format!("{opened} | {declared}"),
        subscribers,
        publishers,
    }
}

/// One document and what the REAL library's node leaves the router holding for it.
struct Row {
    name: &'static str,
    document: Document,
    expect_subscribers: &'static str,
    expect_publishers: &'static str,
}

/// Every row on the real library first, its answer held to the row, then on wz, held to the real
/// library's answer.
fn diff_rows(rows: &[Row]) {
    let Some(programs) = programs() else {
        return;
    };
    let mut disagreements = Vec::new();
    for row in rows {
        let oracle = held_by_router(&programs.reference, &programs.reference, row.document);
        assert_eq!(
            oracle,
            Held {
                node: NODE_OPENED.to_owned(),
                subscribers: row.expect_subscribers.to_owned(),
                publishers: row.expect_publishers.to_owned(),
            },
            "the REAL library's row for `{}` is not what this file expects",
            row.name
        );
        let wz = held_by_router(&programs.wz, &programs.reference, row.document);
        if wz != oracle {
            disagreements.push(format!(
                "{}:\n  libzenohc {oracle:?}\n  wz        {wz:?}",
                row.name
            ));
        }
    }
    assert!(
        disagreements.is_empty(),
        "a node declares under its aggregates differently from libzenohc on {} of {} rows:\n{}",
        disagreements.len(),
        rows.len(),
        disagreements.join("\n")
    );
}

/// `aggregation/subscribers`: two subscribers under one listed aggregate leave the router holding
/// the aggregate alone, where the same node with no list leaves it holding both keys, on wz as on
/// the real library.
// wz-proves: api-compat-c zenoh-c->wz partial
#[test]
#[ignore = "compiles a C program against libzenohc and wz-capi-c and spawns a real zenohd; \
            needs the machine-local zenoh-c oracle; run-ci Layer C1cd drives it"]
fn subscribers_under_a_listed_aggregate_are_declared_as_it_identically_on_wz_and_libzenohc() {
    diff_rows(&[
        Row {
            name: "no aggregate: each subscriber is declared on its own key",
            document: Document {
                subscribers: None,
                publishers: None,
            },
            expect_subscribers: SUBSCRIBERS_EACH,
            expect_publishers: PUBLISHERS_EACH,
        },
        Row {
            name: "aggregation/subscribers: both are declared as the aggregate, once",
            document: Document {
                subscribers: Some(SUBSCRIBER_AGGREGATES),
                publishers: None,
            },
            expect_subscribers: SUBSCRIBERS_AGGREGATED,
            expect_publishers: PUBLISHERS_EACH,
        },
    ]);
}

/// `aggregation/publishers`: two publishers under one listed aggregate leave the router holding
/// one subscribers interest on the aggregate, where the same node with no list leaves it holding
/// one per key, on wz as on the real library.
// wz-proves: api-compat-c zenoh-c->wz partial
#[test]
#[ignore = "compiles a C program against libzenohc and wz-capi-c and spawns a real zenohd; \
            needs the machine-local zenoh-c oracle; run-ci Layer C1cd drives it"]
fn publishers_under_a_listed_aggregate_ask_as_it_identically_on_wz_and_libzenohc() {
    diff_rows(&[
        Row {
            name: "no aggregate: each publisher asks on its own key",
            document: Document {
                subscribers: None,
                publishers: None,
            },
            expect_subscribers: SUBSCRIBERS_EACH,
            expect_publishers: PUBLISHERS_EACH,
        },
        Row {
            name: "aggregation/publishers: both ask as the aggregate, once",
            document: Document {
                subscribers: None,
                publishers: Some(PUBLISHER_AGGREGATES),
            },
            expect_subscribers: SUBSCRIBERS_EACH,
            expect_publishers: PUBLISHERS_AGGREGATED,
        },
    ]);
}
