// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.27 `api-compat-c` -- what `ze_declare_advanced_publisher` answers, and whether the
//! publisher it declares works, on wz's cdylib as on the real `libzenohc.so`: one C program,
//! compiled once, linked twice, stdout diffed.
//!
//! ## Why this exists
//!
//! An advanced publisher declared with a CACHE and NO miss detection was DEAD on wz and said
//! nothing. That is the configuration `z_advanced_pub.c`'s own comment names as the alternative to
//! miss detection, and it sequences by timestamp, which upstream's declaration refuses on a node
//! that holds no clock. wz never gave a C session a clock (the `timestamping` config was read by
//! the reader and ignored by the node, and the cdylib was built without the clock), refused the
//! declaration on every session, and the refusal was dropped by a best-effort fan-out: the declare
//! returned success and the publisher put to nobody. It was found by putting a chunk through the
//! publisher and receiving nothing; the same program with miss detection, or with the cache off,
//! delivered.
//!
//! Measuring the real library found the other half. Its refusal is `Z_EGENERIC` and is exactly
//! "a cache with no miss detection while timestamping is off"; every other configuration is
//! accepted, and with the key set all of them are. A second defect of the same shape sat beside it:
//! the in-process plane refused a declaration WITH a heartbeat, on a precondition (a tokio runtime
//! on the declaring thread) that stopped being true when the beacon moved onto the process's own
//! runtime, so an advanced publisher and subscriber of ONE session heard nothing in any
//! configuration that had a heartbeat.
//!
//! ## What is compared
//!
//! The return code of the declaration for each of fourteen configurations (seven option shapes,
//! with and without the timestamp key), and whether a subscriber of the SAME session hears three
//! puts, for a publisher with a cache and a heartbeat, one with a heartbeat only, and a plain one;
//! and, against the full publisher, for a subscriber with periodic recovery, with heartbeat
//! recovery, with history, and with history and recovery together.
//!
//! The subscriber's shapes are there because the second defect had a sibling: a subscriber with
//! history or periodic recovery was declared on the in-process plane, which has no wire, with a
//! startup GET whose remote Final could never arrive (history: every live sample was held for it)
//! and, for periodic recovery, behind the same stale off-runtime refusal the publisher had. Both
//! heard nothing while the declare said success.

use std::path::{Path, PathBuf};
use std::process::Command;

use wz_integration_tests::bounded::BoundedOutput as _;
use wz_integration_tests::common::{
    assert_zenoh_c_arm_pairing, compile_zenoh_c_example, wz_capi_c_cdylib, zenoh_c_oracle,
    zenoh_c_shared_library,
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

/// The return code of `ze_declare_advanced_publisher` for each configuration, with timestamping set
/// or not, on a session that listens (so wz can open) and dials nobody.
const DECLARE_TABLE: &str = r#"#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zenoh.h"

static int declare(int ts, int cache, int miss, int detection, int use_null_options) {
    z_owned_config_t config;
    z_config_default(&config);
    zc_config_insert_json5(z_loan_mut(config), Z_CONFIG_MULTICAST_SCOUTING_KEY, "false");
    zc_config_insert_json5(z_loan_mut(config), Z_CONFIG_LISTEN_KEY, "[\"tcp/127.0.0.1:0\"]");
    if (ts) { zc_config_insert_json5(z_loan_mut(config), Z_CONFIG_ADD_TIMESTAMP_KEY, "true"); }
    z_owned_session_t s;
    if (z_open(&s, z_move(config), NULL) < 0) { return 1000; }
    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, "demo/example/adv");
    ze_owned_advanced_publisher_t pub;
    int rc;
    if (use_null_options) {
        rc = ze_declare_advanced_publisher(z_loan(s), &pub, z_loan(ke), NULL);
    } else {
        ze_advanced_publisher_options_t opts;
        ze_advanced_publisher_options_default(&opts);
        if (cache) { ze_advanced_publisher_cache_options_default(&opts.cache); }
        if (miss) {
            ze_advanced_publisher_sample_miss_detection_options_default(&opts.sample_miss_detection);
            opts.sample_miss_detection.heartbeat_period_ms = 500;
            opts.sample_miss_detection.heartbeat_mode = ZE_ADVANCED_PUBLISHER_HEARTBEAT_MODE_PERIODIC;
        }
        opts.publisher_detection = detection ? true : false;
        rc = ze_declare_advanced_publisher(z_loan(s), &pub, z_loan(ke), &opts);
    }
    if (rc == 0) { z_drop(z_move(pub)); }
    z_drop(z_move(s));
    return rc;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    for (int ts = 0; ts <= 1; ts++) {
        printf("ts=%d null_options  rc=%d\n", ts, declare(ts, 0, 0, 0, 1));
        printf("ts=%d no_features   rc=%d\n", ts, declare(ts, 0, 0, 0, 0));
        printf("ts=%d cache         rc=%d\n", ts, declare(ts, 1, 0, 0, 0));
        printf("ts=%d miss          rc=%d\n", ts, declare(ts, 0, 1, 0, 0));
        printf("ts=%d detection     rc=%d\n", ts, declare(ts, 0, 0, 1, 0));
        printf("ts=%d cache+miss    rc=%d\n", ts, declare(ts, 1, 1, 0, 0));
        printf("ts=%d cache+detect  rc=%d\n", ts, declare(ts, 1, 0, 1, 0));
    }
    printf("done\n");
    return 0;
}
"#;

/// Whether a node holds a clock follows its ROLE and its config, and a cache with no miss
/// detection is the declaration that asks. Arguments: the role (`peer` or `router`), the timestamp
/// key (`unset`, `true` or `false`) and how it is spelled (`add`, the key a C program names, or
/// `nested`, the document form `{"<role>": <value>}` under `timestamping/enabled`).
const CLOCK_BY_ROLE: &str = r#"#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zenoh.h"

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc != 4) { return 2; }
    z_owned_config_t config;
    z_config_default(&config);
    zc_config_insert_json5(z_loan_mut(config), Z_CONFIG_MULTICAST_SCOUTING_KEY, "false");
    zc_config_insert_json5(z_loan_mut(config), Z_CONFIG_LISTEN_KEY, "[\"tcp/127.0.0.1:0\"]");
    char quoted[32];
    snprintf(quoted, sizeof quoted, "\"%s\"", argv[1]);
    zc_config_insert_json5(z_loan_mut(config), Z_CONFIG_MODE_KEY, quoted);
    if (strcmp(argv[2], "unset") != 0) {
        if (strcmp(argv[3], "add") == 0) {
            zc_config_insert_json5(z_loan_mut(config), Z_CONFIG_ADD_TIMESTAMP_KEY, argv[2]);
        } else {
            char doc[64];
            snprintf(doc, sizeof doc, "{\"%s\": %s}", argv[1], argv[2]);
            zc_config_insert_json5(z_loan_mut(config), "timestamping/enabled", doc);
        }
    }
    z_owned_session_t s;
    int orc = z_open(&s, z_move(config), NULL);
    if (orc < 0) { printf("%s/%s/%s: open=%d\n", argv[1], argv[2], argv[3], orc); return 0; }
    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, "demo/example/adv");
    ze_owned_advanced_publisher_t pub;
    ze_advanced_publisher_options_t opts;
    ze_advanced_publisher_options_default(&opts);
    ze_advanced_publisher_cache_options_default(&opts.cache);
    int rc = ze_declare_advanced_publisher(z_loan(s), &pub, z_loan(ke), &opts);
    printf("%s/%s/%s: open=0 declare=%d\n", argv[1], argv[2], argv[3], rc);
    return 0;
}
"#;

/// An advanced publisher and an advanced subscriber on ONE session, no peer: does the subscriber
/// hear the puts? Argument: `cache` (a cache and a heartbeat), `miss` (a heartbeat only) or
/// `plain`. The timestamp key is set, so every configuration is acceptable on both libraries.
const SAME_SESSION: &str = r#"#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zenoh.h"

static volatile int got = 0;
static void on_sample(z_loaned_sample_t *sample, void *arg) { (void)sample; (void)arg; got = got + 1; }

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc != 3) { return 2; }
    int cache = strcmp(argv[1], "cache") == 0;
    int heartbeat = strcmp(argv[1], "plain") != 0;
    int hist = strcmp(argv[2], "history") == 0 || strcmp(argv[2], "all") == 0;
    int periodic = strcmp(argv[2], "periodic") == 0 || strcmp(argv[2], "all") == 0;
    int hb = strcmp(argv[2], "heartbeat") == 0;
    z_owned_config_t config;
    z_config_default(&config);
    zc_config_insert_json5(z_loan_mut(config), Z_CONFIG_MULTICAST_SCOUTING_KEY, "false");
    /* a session needs an endpoint to open on wz (see the note in the test) */
    zc_config_insert_json5(z_loan_mut(config), Z_CONFIG_LISTEN_KEY, "[\"tcp/127.0.0.1:0\"]");
    zc_config_insert_json5(z_loan_mut(config), Z_CONFIG_ADD_TIMESTAMP_KEY, "true");
    z_owned_session_t s;
    if (z_open(&s, z_move(config), NULL) < 0) { printf("open failed\n"); return 1; }
    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, "demo/example/local");

    z_owned_closure_sample_t cb;
    z_closure(&cb, on_sample, NULL, NULL);
    ze_owned_advanced_subscriber_t sub;
    ze_advanced_subscriber_options_t sopts;
    ze_advanced_subscriber_options_default(&sopts);
    if (hist) {
        sopts.history.is_enabled = true;
        sopts.history.detect_late_publishers = true;
    }
    if (periodic || hb) {
        sopts.recovery.is_enabled = true;
        sopts.recovery.last_sample_miss_detection.is_enabled = true;
        sopts.recovery.last_sample_miss_detection.periodic_queries_period_ms = periodic ? 500 : 0;
    }
    int src =ze_declare_advanced_subscriber(z_loan(s), &sub, z_loan(ke), z_move(cb), &sopts);

    ze_owned_advanced_publisher_t pub;
    ze_advanced_publisher_options_t opts;
    ze_advanced_publisher_options_default(&opts);
    if (cache) {
        ze_advanced_publisher_cache_options_default(&opts.cache);
        opts.publisher_detection = true;
    }
    if (heartbeat) {
        ze_advanced_publisher_sample_miss_detection_options_default(&opts.sample_miss_detection);
        opts.sample_miss_detection.heartbeat_period_ms = 500;
        opts.sample_miss_detection.heartbeat_mode = ZE_ADVANCED_PUBLISHER_HEARTBEAT_MODE_PERIODIC;
    }
    int prc = ze_declare_advanced_publisher(z_loan(s), &pub, z_loan(ke), &opts);
    for (int i = 0; i < 3; i++) {
        z_owned_bytes_t payload;
        z_bytes_copy_from_str(&payload, "hello");
        ze_advanced_publisher_put_options_t popts;
        ze_advanced_publisher_put_options_default(&popts);
        ze_advanced_publisher_put(z_loan(pub), z_move(payload), &popts);
    }
    z_sleep_ms(800);
    printf("%s/%s: sub_declare=%d pub_declare=%d received=%d\n", argv[1], argv[2], src, prc, got);
    return 0;
}
"#;

/// Compile `source` once per library and return the two executables with their library dirs:
/// `(wz exe, wz libdir, reference exe, reference libdir)`.
fn compile_both(
    name: &str,
    source: &str,
    include: &Path,
) -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir for the compiled probes");
    let src_dir = dir.path().join("src");
    std::fs::create_dir_all(&src_dir).expect("probe source dir");
    std::fs::write(src_dir.join(format!("{name}.c")), source).expect("write the probe source");

    let lib = wz_capi_c_cdylib();
    let wz_libdir = lib.parent().expect("cdylib has a parent").to_path_buf();
    let on_wz = compile_zenoh_c_example(
        name,
        dir.path(),
        include,
        &src_dir,
        &wz_libdir,
        "wz_capi_c",
    )
    .unwrap_or_else(|diag| {
        panic!("§5.27 api-compat-c: the {name} probe does NOT link against wz's cdylib.\n{diag}")
    });

    let reference = zenoh_c_shared_library().expect("the oracle resolved above");
    let libdir_ref = reference
        .parent()
        .expect("libzenohc.so has a parent")
        .to_path_buf();
    let ref_dir = dir.path().join("reference");
    std::fs::create_dir_all(&ref_dir).expect("reference build dir");
    let on_ref = compile_zenoh_c_example(name, &ref_dir, include, &src_dir, &libdir_ref, "zenohc")
        .unwrap_or_else(|diag| {
            panic!("the {name} probe does not link against the REAL libzenohc.so\n{diag}")
        });
    (dir, on_wz, wz_libdir, on_ref, libdir_ref)
}

/// Run `exe` and return its stdout, asserting it exited zero.
fn run(exe: &Path, libdir: &Path, args: &[&str], arm: &str) -> String {
    let out = Command::new(exe)
        .args(args)
        .env("LD_LIBRARY_PATH", libdir)
        .output_bounded()
        .unwrap_or_else(|why| panic!("spawn {}: {why}", exe.display()));
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "the {arm} arm of {} exited {:?}\n{stdout}",
        exe.display(),
        out.status.code()
    );
    stdout
}

/// The rows a probe's subject prints, without a tracing line the real library may write.
fn rows(stdout: &str) -> Vec<&str> {
    stdout
        .lines()
        .filter(|l| l.starts_with("ts=") || l.starts_with("done") || l.contains(": sub_declare="))
        .collect()
}

fn needs_the_shm_oracle(include: &Path) -> bool {
    let configure = std::fs::read_to_string(include.join("zenoh_configure.h")).unwrap_or_default();
    let defines = |name: &str| {
        configure
            .lines()
            .any(|l| l.trim() == format!("#define {name}"))
    };
    !(defines("Z_FEATURE_UNSTABLE_API") && defines("Z_FEATURE_SHARED_MEMORY"))
}

/// THE GATE, the declaration: every configuration is answered with the same code on wz and on
/// libzenohc, and the refusals are exactly the two that put a cache on a node with no clock.
// wz-proves: api-compat-c zenoh-c->wz partial
#[test]
#[ignore = "reads a zenoh-c oracle; run by run-ci Layer C1cc (which builds the matching \
            ABI arm this needs)"]
fn an_advanced_publisher_declaration_is_answered_with_the_same_code_on_wz_and_libzenohc() {
    let Some(include) = oracle_or_note() else {
        return;
    };
    if needs_the_shm_oracle(&include) {
        eprintln!(
            "skip: this zenoh-c oracle is built without Z_FEATURE_SHARED_MEMORY and \
             Z_FEATURE_UNSTABLE_API, where the advanced publisher this reads is not declared."
        );
        return;
    }
    assert_zenoh_c_arm_pairing(&include);
    let (_dir, on_wz, wz_libdir, on_ref, libdir_ref) =
        compile_both("wz_adv_declare", DECLARE_TABLE, &include);
    let wz_stdout = run(&on_wz, &wz_libdir, &[], "wz");
    let ref_stdout = run(&on_ref, &libdir_ref, &[], "reference");
    let (wz_rows, ref_rows) = (rows(&wz_stdout), rows(&ref_stdout));

    // The ORACLE first: two identical tables diff clean, and a reference that refused nothing would
    // make the equality below say nothing about the rule this leg is for.
    let refused: Vec<&&str> = ref_rows.iter().filter(|r| r.ends_with("rc=-128")).collect();
    assert_eq!(
        refused,
        [&"ts=0 cache         rc=-128", &"ts=0 cache+detect  rc=-128"],
        "the reference did not refuse exactly the two configurations that put a cache on a node \
         that holds no clock, so the rule this leg compares against is not what it assumes:\n{ref_stdout}"
    );
    assert!(
        ref_rows
            .iter()
            .filter(|r| r.starts_with("ts=1"))
            .all(|r| r.ends_with("rc=0")),
        "the reference refused a declaration with timestamping on:\n{ref_stdout}"
    );
    assert_eq!(
        ref_rows.len(),
        15,
        "the table has fourteen rows and a done line:\n{ref_stdout}"
    );

    assert_eq!(
        wz_rows, ref_rows,
        "§5.27 api-compat-c: wz's C ABI and libzenohc answer an advanced publisher's declaration \
         differently.\n--- wz ---\n{wz_stdout}--- libzenohc ---\n{ref_stdout}"
    );
}

/// THE GATE, the clock: which nodes hold one. A peer holds none unless the config says so, a router
/// holds one unless the config says not, and the config's `false` wins over a router's default,
/// spelled either way. Five of the nine rows are refusals, so a wz that gave every node a clock, or
/// none, differs from the real library in the rows that are not the same.
// wz-proves: api-compat-c zenoh-c->wz partial
#[test]
#[ignore = "reads a zenoh-c oracle; run by run-ci Layer C1cc (which builds the matching \
            ABI arm this needs)"]
fn a_nodes_clock_follows_its_role_and_its_config_on_wz_and_libzenohc() {
    let Some(include) = oracle_or_note() else {
        return;
    };
    if needs_the_shm_oracle(&include) {
        eprintln!(
            "skip: this zenoh-c oracle is built without Z_FEATURE_SHARED_MEMORY and \
             Z_FEATURE_UNSTABLE_API, where the advanced publisher this reads is not declared."
        );
        return;
    }
    assert_zenoh_c_arm_pairing(&include);
    let (_dir, on_wz, wz_libdir, on_ref, libdir_ref) =
        compile_both("wz_adv_clock_role", CLOCK_BY_ROLE, &include);
    let combos = [
        ("peer", "unset", "add"),
        ("peer", "true", "add"),
        ("peer", "true", "nested"),
        ("peer", "false", "add"),
        ("peer", "false", "nested"),
        ("router", "unset", "add"),
        ("router", "true", "add"),
        ("router", "false", "add"),
        ("router", "false", "nested"),
    ];
    let mut refused = Vec::new();
    for (role, value, spelling) in combos {
        let args = [role, value, spelling];
        let wz_stdout = run(&on_wz, &wz_libdir, &args, "wz");
        let ref_stdout = run(&on_ref, &libdir_ref, &args, "reference");
        let (wz_rows, ref_rows) = (clock_rows(&wz_stdout), clock_rows(&ref_stdout));
        assert_eq!(
            ref_rows.len(),
            1,
            "the reference printed no row for {args:?}:\n{ref_stdout}"
        );
        if ref_rows[0].ends_with("declare=-128") {
            refused.push(format!("{role}/{value}/{spelling}"));
        }
        assert_eq!(
            wz_rows, ref_rows,
            "§5.27 api-compat-c: {args:?}: a node's clock follows its role and config differently \
             on wz's C ABI and on libzenohc.\n--- wz ---\n{wz_stdout}--- libzenohc ---\n{ref_stdout}"
        );
    }
    // The ORACLE: a reference that refused nothing, or everything, would make the equality above
    // say nothing about the rule this leg is for.
    assert_eq!(
        refused,
        [
            "peer/unset/add",
            "peer/false/add",
            "peer/false/nested",
            "router/false/add",
            "router/false/nested"
        ],
        "the reference did not refuse exactly the nodes that hold no clock"
    );
}

/// The rows [`CLOCK_BY_ROLE`] prints.
fn clock_rows(stdout: &str) -> Vec<&str> {
    stdout.lines().filter(|l| l.contains(": open=")).collect()
}

/// THE GATE, the publisher: a subscriber of the publisher's own session hears the puts on wz as on
/// libzenohc, in the three configurations that differ in what the publisher spawns and keeps.
// wz-proves: api-compat-c zenoh-c->wz partial
#[test]
#[ignore = "reads a zenoh-c oracle; run by run-ci Layer C1cc (which builds the matching \
            ABI arm this needs)"]
fn an_advanced_subscriber_of_the_publishers_own_session_hears_it_on_wz_and_libzenohc() {
    let Some(include) = oracle_or_note() else {
        return;
    };
    if needs_the_shm_oracle(&include) {
        eprintln!(
            "skip: this zenoh-c oracle is built without Z_FEATURE_SHARED_MEMORY and \
             Z_FEATURE_UNSTABLE_API, where the advanced pub/sub this reads is not declared."
        );
        return;
    }
    assert_zenoh_c_arm_pairing(&include);
    let (_dir, on_wz, wz_libdir, on_ref, libdir_ref) =
        compile_both("wz_adv_local", SAME_SESSION, &include);
    // The publisher's shape against a plain subscriber, then the subscriber's shapes against the
    // full publisher: the two axes vary one at a time, so a row that goes red names its axis.
    let combos = [
        ("cache", "plain"),
        ("miss", "plain"),
        ("plain", "plain"),
        ("cache", "periodic"),
        ("cache", "heartbeat"),
        ("cache", "history"),
        ("cache", "all"),
    ];
    for (publisher, subscriber) in combos {
        let mode = format!("{publisher}/{subscriber}");
        let args = [publisher, subscriber];
        let wz_stdout = run(&on_wz, &wz_libdir, &args, "wz");
        let ref_stdout = run(&on_ref, &libdir_ref, &args, "reference");
        let expected = format!("{mode}: sub_declare=0 pub_declare=0 received=3");
        assert_eq!(
            rows(&ref_stdout),
            [expected.as_str()],
            "the reference's subscriber did not hear all three puts of the `{mode}` publisher, so \
             the comparison below says nothing about it:\n{ref_stdout}"
        );
        assert_eq!(
            rows(&wz_stdout),
            rows(&ref_stdout),
            "§5.27 api-compat-c: `{mode}`: the subscriber of the advanced publisher's own session \
             heard it differently on wz's C ABI and on libzenohc.\n--- wz ---\n{wz_stdout}--- \
             libzenohc ---\n{ref_stdout}"
        );
    }
}
