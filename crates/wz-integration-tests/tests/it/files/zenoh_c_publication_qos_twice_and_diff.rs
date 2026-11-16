// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `qos/publication`: the QoS a session gives the puts and publishers on the keys a rule names,
//! over what the API asked for, on wz and on the real `libzenohc.so`.
//!
//! ## What upstream does with the list
//!
//! A put and a declared publisher look their key up in the rules, and the first rule whose key
//! expressions include it overwrites the priority, the congestion control and the express flag
//! the call carried (`zenoh/src/api/builders/publisher.rs` @
//! `pub(crate) fn apply_qos_overwrites(self) -> Self {`): a put when it is made
//! (`zenoh/src/api/builders/publisher.rs` @
//! `self.publisher = self.publisher.apply_qos_overwrites();`), a publisher when it is declared
//! (`zenoh/src/api/builders/publisher.rs` @ `self = self.apply_qos_overwrites();`). The three
//! travel in the QoS extension of each push, so the subscriber on the far side reads them off
//! every sample.
//!
//! ## The rows
//!
//! One C program, compiled against each library. The SUBSCRIBER is always the real library's: a
//! peer that listens and prints, for each key it heard, the priority, congestion control and
//! express flag of its samples. The PUTTER, built against the library under test, dials it from
//! one config document and, with the API's defaults, puts on `wz/qos/ruled/put`, puts through a
//! publisher declared on `wz/qos/ruled/pub`, and puts on `wz/qos/plain/put`. The document either
//! states a rule for `wz/qos/ruled/**` or states none (the control). The real library's rows are
//! asserted first; wz's are then held to them.

use std::io::{BufRead, BufReader, Lines};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};

use wz_integration_tests::bounded::BoundedChild as _;
use wz_integration_tests::common::{
    assert_zenoh_c_arm_pairing, compile_zenoh_c_example, wz_capi_c_cdylib, zenoh_c_oracle,
    zenoh_c_shared_library, PortReservation,
};

/// The program, in two modes.
///
/// `sub <listen port> <seconds>` opens a peer that listens on `tcp/127.0.0.1:<port>`, subscribes
/// to `wz/qos/**`, prints `open=<rc> declare=<rc>`, and after the given seconds prints `seen=` and
/// one `<key> prio=<p> cc=<c> express=<0|1>` entry per distinct sample shape, sorted and joined by
/// `;`.
///
/// `put <connect port> <rule 0|1> <seconds>` opens a peer that dials `tcp/127.0.0.1:<port>`,
/// stating the `qos/publication` rule when the second argument is 1, prints
/// `open=<rc> cfg=<rc>`, declares a publisher with default options, and every 200 ms for the given
/// seconds makes its three default puts.
const QOS_NODE: &str = r#"#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "zenoh.h"

#define MAX_SEEN 32

static const char* RULE =
    "[{\"key_exprs\":[\"wz/qos/ruled/**\"],"
    "\"config\":{\"priority\":\"interactive_high\",\"congestion_control\":\"block\",\"express\":true}}]";

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static char g_seen[MAX_SEEN][128];
static int g_seen_n = 0;

static int first(int kept, int next) { return kept != 0 ? kept : next; }

static int insert(z_owned_config_t* c, const char* k, const char* v) {
    return zc_config_insert_json5(z_loan_mut(*c), k, v);
}

static const char* priority_name(enum z_priority_t p) {
    switch (p) {
        case Z_PRIORITY_REAL_TIME: return "real_time";
        case Z_PRIORITY_INTERACTIVE_HIGH: return "interactive_high";
        case Z_PRIORITY_INTERACTIVE_LOW: return "interactive_low";
        case Z_PRIORITY_DATA_HIGH: return "data_high";
        case Z_PRIORITY_DATA: return "data";
        case Z_PRIORITY_DATA_LOW: return "data_low";
        case Z_PRIORITY_BACKGROUND: return "background";
        default: return "other";
    }
}

static const char* congestion_name(enum z_congestion_control_t c) {
    switch (c) {
        case Z_CONGESTION_CONTROL_BLOCK: return "block";
        case Z_CONGESTION_CONTROL_DROP: return "drop";
        default: return "other";
    }
}

static void on_sample(z_loaned_sample_t* sample, void* arg) {
    (void)arg;
    z_view_string_t k;
    z_keyexpr_as_view_string(z_sample_keyexpr(sample), &k);
    char line[128];
    snprintf(line, sizeof line, "%.*s prio=%s cc=%s express=%d",
             (int)z_string_len(z_loan(k)), z_string_data(z_loan(k)),
             priority_name(z_sample_priority(sample)),
             congestion_name(z_sample_congestion_control(sample)),
             z_sample_express(sample) ? 1 : 0);
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < g_seen_n; i++) {
        if (strcmp(g_seen[i], line) == 0) {
            pthread_mutex_unlock(&g_mu);
            return;
        }
    }
    if (g_seen_n < MAX_SEEN) snprintf(g_seen[g_seen_n++], sizeof g_seen[0], "%s", line);
    pthread_mutex_unlock(&g_mu);
}

static int by_name(const void* a, const void* b) { return strcmp((const char*)a, (const char*)b); }

static int peer_of(z_owned_config_t* c, const char* key, const char* port) {
    char buf[64];
    z_config_default(c);
    int rc = insert(c, Z_CONFIG_MULTICAST_SCOUTING_KEY, "false");
    rc = first(rc, insert(c, Z_CONFIG_MODE_KEY, "\"peer\""));
    snprintf(buf, sizeof buf, "[\"tcp/127.0.0.1:%s\"]", port);
    return first(rc, insert(c, key, buf));
}

static int sub(char** argv) {
    z_owned_config_t config;
    peer_of(&config, Z_CONFIG_LISTEN_KEY, argv[2]);
    int secs = atoi(argv[3]);
    z_owned_session_t s;
    int rc = z_open(&s, z_move(config), NULL);
    if (rc < 0) {
        printf("open=%d declare=-\n", rc);
        return 0;
    }
    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, "wz/qos/**");
    z_owned_closure_sample_t cb;
    z_closure(&cb, on_sample, NULL, NULL);
    z_owned_subscriber_t subscriber;
    int drc = z_declare_subscriber(z_loan(s), &subscriber, z_loan(ke), z_move(cb), NULL);
    printf("open=%d declare=%d\n", rc, drc);
    sleep((unsigned)secs);
    pthread_mutex_lock(&g_mu);
    qsort(g_seen, (size_t)g_seen_n, sizeof g_seen[0], by_name);
    printf("seen=");
    for (int i = 0; i < g_seen_n; i++) printf("%s%s", i ? ";" : "", g_seen[i]);
    printf("\n");
    pthread_mutex_unlock(&g_mu);
    z_drop(z_move(subscriber));
    z_drop(z_move(s));
    return 0;
}

static void put_text(const z_loaned_session_t* s, const char* key) {
    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, key);
    z_owned_bytes_t payload;
    z_bytes_copy_from_str(&payload, "qos");
    z_put(s, z_loan(ke), z_move(payload), NULL);
}

static int put(char** argv) {
    z_owned_config_t config;
    int cfg = peer_of(&config, Z_CONFIG_CONNECT_KEY, argv[2]);
    if (strcmp(argv[3], "1") == 0) cfg = first(cfg, insert(&config, "qos/publication", RULE));
    int secs = atoi(argv[4]);
    z_owned_session_t s;
    int rc = z_open(&s, z_move(config), NULL);
    printf("open=%d cfg=%d\n", rc, cfg);
    if (rc < 0) return 0;
    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, "wz/qos/ruled/pub");
    z_owned_publisher_t publisher;
    z_declare_publisher(z_loan(s), &publisher, z_loan(ke), NULL);
    sleep(1);
    for (int i = 0; i < secs * 5; i++) {
        put_text(z_loan(s), "wz/qos/ruled/put");
        z_owned_bytes_t payload;
        z_bytes_copy_from_str(&payload, "qos");
        z_publisher_put(z_loan(publisher), z_move(payload), NULL);
        put_text(z_loan(s), "wz/qos/plain/put");
        usleep(200 * 1000);
    }
    z_drop(z_move(publisher));
    z_drop(z_move(s));
    return 0;
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc == 4 && strcmp(argv[1], "sub") == 0) return sub(argv);
    if (argc == 5 && strcmp(argv[1], "put") == 0) return put(argv);
    return 2;
}
"#;

/// What the real library's subscriber sees from a putter with no rule: the API's defaults on
/// every key.
const UNRULED: &str = "seen=wz/qos/plain/put prio=data cc=drop express=0;\
                       wz/qos/ruled/pub prio=data cc=drop express=0;\
                       wz/qos/ruled/put prio=data cc=drop express=0";

/// What it sees from a putter whose document states the rule: the rule's three values on both
/// keys the rule names, by put and by publisher, and the defaults on the key it does not.
const RULED: &str = "seen=wz/qos/plain/put prio=data cc=drop express=0;\
                     wz/qos/ruled/pub prio=interactive_high cc=block express=1;\
                     wz/qos/ruled/put prio=interactive_high cc=block express=1";

/// The subscriber's own open line, and the putter's.
const SUBSCRIBED: &str = "open=0 declare=0";
const PUTTER_OPENED: &str = "open=0 cfg=0";

/// How long the putter puts, and how long the subscriber listens: past the putter's whole run.
const PUT_SECS: u32 = 3;
const LISTEN_SECS: u32 = 7;

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
    let exe = compile_zenoh_c_example("qos_node", out, include, source_dir, libdir, link)
        .unwrap_or_else(|d| panic!("the QoS program does not link against `{link}`\n{d}"));
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
    std::fs::write(src.join("qos_node.c"), QOS_NODE).expect("write the source");

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
            .expect("spawn the QoS program");
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

    /// Everything the program prints from here to its end, as one row.
    fn finish(mut self) -> String {
        let rest: Vec<String> = self
            .lines
            .by_ref()
            .map(|line| line.expect("read the program's stdout"))
            .collect();
        self.child.wait_bounded().expect("the program ends");
        rest.join(" | ")
    }
}

/// What the real library's subscriber reports of a putter built against `putter`, whose document
/// states the rule or not: the subscriber's open line, the putter's, and what was seen.
fn observed(subscriber: &Built, putter: &Built, rule: bool) -> (String, String, String) {
    let reservation = PortReservation::pick();
    let port = reservation.port().to_string();
    let mut listening = Running::start(subscriber, &["sub", &port, &LISTEN_SECS.to_string()]);
    let subscribed = listening.line();
    drop(reservation);
    let putting = Running::start(
        putter,
        &[
            "put",
            &port,
            if rule { "1" } else { "0" },
            &PUT_SECS.to_string(),
        ],
    );
    let putter_row = putting.finish();
    let seen = listening.finish();
    (subscribed, putter_row, seen)
}

/// `qos/publication`: a rule's priority, congestion control and express flag reach the far
/// subscriber on every put and publisher under its keys, and nothing else changes, on wz as on the
/// real library.
// wz-proves: api-compat-c zenoh-c->wz partial
#[test]
#[ignore = "compiles a C program against libzenohc and wz-capi-c and runs it on loopback; \
            needs the machine-local zenoh-c oracle; run-ci Layer C1cd drives it"]
fn a_publication_rule_overwrites_the_qos_of_its_keys_identically_on_wz_and_libzenohc() {
    let Some(programs) = programs() else {
        return;
    };
    let mut disagreements = Vec::new();
    for (rule, expect) in [(false, UNRULED), (true, RULED)] {
        let oracle = observed(&programs.reference, &programs.reference, rule);
        assert_eq!(
            oracle,
            (
                SUBSCRIBED.to_owned(),
                PUTTER_OPENED.to_owned(),
                expect.to_owned()
            ),
            "the REAL library's row for a putter {} the rule is not what this file expects",
            if rule { "with" } else { "without" }
        );
        let wz = observed(&programs.reference, &programs.wz, rule);
        if wz != oracle {
            disagreements.push(format!(
                "a putter {} the rule:\n  libzenohc {oracle:?}\n  wz        {wz:?}",
                if rule { "with" } else { "without" }
            ));
        }
    }
    assert!(
        disagreements.is_empty(),
        "a session applies qos/publication differently from libzenohc:\n{}",
        disagreements.join("\n")
    );
}
