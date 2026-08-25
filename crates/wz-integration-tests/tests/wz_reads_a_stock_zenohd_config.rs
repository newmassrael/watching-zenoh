// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y842 — the READ direction of the stock-zenoh config surface, judged by
//! a REAL zenohd 1.5.0.
//!
//! `zenoh_config_emit_zenohd_interop` (R311y579) settles the WRITE half: a
//! config wz emitted is one zenohd reads back the way wz meant. This file is
//! its inverse and the one that bears on replacement, because an operator
//! replacing a zenoh node does not need wz to write a config — they already
//! have one. Until R311y842 that file was an input to nothing: every wz
//! setting arrived as a bespoke flag.
//!
//! Four legs, each answering a different question, and none of them
//! answerable inside wz:
//!
//! 1. [`wz_reads_the_same_values_out_of_a_config_that_zenohd_does`] — THE
//!    DIFFERENTIAL ORACLE. One hand-written JSON5 file is handed to both
//!    implementations. zenohd prints its own resolved config; wz ingests the
//!    same bytes; the two are compared KEY BY KEY at the same paths. A unit
//!    test can only show wz read the file the way wz meant to, which is
//!    self-consistency; this shows wz read it the way ZENOH does. The
//!    comparison is against zenoh's RESOLVED tree, so a key wz reads at the
//!    wrong path does not merely go missing — it reads zenoh's default where
//!    the operator's value should be, which is the silent failure this leg
//!    exists to catch.
//! 2. [`the_upstream_config_surface_zenohd_resolves_is_enumerated_and_accounted_for`]
//!    — THE CENSUS, and it starts from UPSTREAM rather than from wz. Every
//!    other coverage gate in this tree begins at a wz atom and asks whether it
//!    is proven; none begins at zenoh's own surface and asks whether wz has
//!    anything corresponding. Here the denominator is zenohd's own resolved
//!    config — 111 leaf keys, obtained by execution, not by parsing a document
//!    — and every one is either honoured or named in the pinned unhonoured
//!    SET. A zenoh version that adds a key makes this RED, which is the point:
//!    the surface is allowed to grow, silently growing is not.
//! 3. [`a_wz_node_configured_only_by_a_stock_zenoh_config_reaches_a_real_zenohd`]
//!    — THE DROP-IN. `wz-ap-demo --config <file>` and nothing else: the
//!    endpoint exists in no argv, no env var and no default, only in the
//!    operator's file. The port is reserved at random per run, so a wz that
//!    read the key but not its VALUE cannot pass by dialling something it
//!    already knew.
//! 4. [`a_config_key_zenohd_refuses_is_one_wz_refuses_too`] — THE ACCEPTANCE
//!    BOUNDARY, and the leg that CHANGED the design rather than confirming it.
//!    The first cut of the reader accepted any key it did not model and merely
//!    reported it; handing the same file to a real zenohd showed that zenoh
//!    REFUSES an unknown field outright. Accepting it is the worse drop-in
//!    failure of the two: a typo the operator's old node caught would run
//!    silently under wz with the setting never applied. wz's boundary is now
//!    zenoh's — a key zenoh knows is reported, a key it does not is refused.
//!
//! `#[ignore]` (binary-dep e2e): needs `target/zenohd/zenohd` (set
//! `WZ_ZENOHD_BIN` or run `scripts/build-zenohd.sh`), and leg 3 additionally
//! needs a `wz-ap-demo` built with `--features zenoh-config`. A missing
//! prereq PANICS with the build line rather than skipping: a leg that skips
//! green is one Layer A4 goes on counting as executed.

use std::fs::File;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::time::Duration;

use tempfile::NamedTempFile;

use wz_codecs::whatami::WhatAmI;
use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, wait_for_substring, wz_ap_demo_binary, zenohd_binary,
    ChildGuard, PortReservation,
};
use wz_runtime_tokio::zenoh_config::{
    default_listen_endpoint, ZenohNodeConfig, CONFIG_KEYS_PROVEN_ON_THE_WIRE, DAEMON_DEFAULT_MODE,
    DEEPENABLE_UPSTREAM_KEYS, HONOURED_CONFIG_KEYS, LIBRARY_DEFAULT_MODE,
    UNHONOURED_UPSTREAM_CONFIG_KEYS,
};
use wz_runtime_tokio_test_support::zenoh_interop_session_init_params;
use wz_session_core::dissect::{dissect_transport_message, FieldValue};
use wz_session_core::handshake_encode::encode_init;
use wz_session_core::json5::{self, Json5Value};
use wz_session_core::lease::lease_from_wire;

/// zenohd prints its resolved config on this line before doing anything else.
const RESOLVED_CONF_MARKER: &str = "Initial conf:";

/// zenohd's own line for the thing a DIALLER depends on: the listener is up.
///
/// R2091 — separate from [`RESOLVED_CONF_MARKER`] because the two are not the
/// same event and the drop-in leg was gated on the wrong one. Measured on this
/// tree: a TCP connect issued 0.1 ms after `Initial conf:` is REFUSED, and the
/// port becomes connectable **34 ms later** — so a leg that spawns a dialler on
/// the conf line races a bind that has not happened, and loses. That leg had
/// been red on this machine at HEAD, four runs out of four, with a diagnosis
/// ("never established a session") that named no cause. The other legs here
/// only READ the resolved config out of that line and are correct to wait on
/// it; only a leg that connects needs this one.
///
/// Upstream's text, quoted from `zenoh/src/net/runtime/orchestrator.rs:586` in
/// the pinned checkout (`tracing::info!("Zenoh can be reached at: {}", locator)`).
const LISTENER_UP_MARKER: &str = "Zenoh can be reached at:";

/// How long to wait for zenohd to print its resolved config.
const STARTUP_BUDGET: Duration = Duration::from_secs(30);

/// How long to wait for the demo to reach steady state over a loopback TCP
/// link. Deliberately tight: a generous deadline is how a leg comes to be
/// satisfied by something other than the thing under test.
const DEMO_BUDGET: Duration = Duration::from_secs(20);

/// The line the demo logs once its session is open.
const DEMO_ESTABLISHED: &str = "session Established";

/// The operator's file. Deliberately written the way a hand-maintained config
/// is — comments, a bare key, a single-quoted string, a trailing comma — so
/// the leg exercises the JSON5 the reference documents rather than the strict
/// JSON wz's own emitter happens to produce.
///
/// Every value is chosen AWAY from zenoh's default (batch_size 4096 vs 65535,
/// lease 8000 vs 10000, max_links 3 vs 1, qos off vs on, compression on vs
/// off, timestamping on vs off, adminspace write on vs off), so the two
/// implementations cannot agree by both landing on a default.
fn operator_config(port: u16) -> String {
    format!(
        r#"/// The deployment's own zenoh config, as it sits on disk.
{{
  mode: 'router',                       // single-quoted, JSON5
  id: "a1b2c3d4",
  namespace: "demo/ns",
  queries_default_timeout: 11000,
  routing: {{ interests: {{ timeout: 9000 }} }},
  listen: {{
    endpoints: ["tcp/127.0.0.1:{port}",],   /* trailing comma */
  }},
  scouting: {{ multicast: {{ enabled: false }}, timeout: 2500 }},
  timestamping: {{ enabled: true }},
  adminspace: {{ enabled: true, permissions: {{ read: true, write: true }} }},
  transport: {{
    unicast: {{
      max_links: 3,
      lowlatency: false,
      qos: {{ enabled: false }},
      compression: {{ enabled: true }},
    }},
    multicast: {{ qos: {{ enabled: true }} }},
    shared_memory: {{ enabled: false }},
    link: {{
      tls: {{
        root_ca_certificate: "/etc/wz/ca.pem",
        listen_certificate: "/etc/wz/server.pem",
        listen_private_key: "/etc/wz/server.key",
      }},
      tx: {{ batch_size: 4096, lease: 8000, threads: 8 }},
    }},
  }},
  // Keys zenoh knows and wz does not honour, present the way they are in a
  // real file: the ingest must REPORT these, not refuse them and not swallow
  // them. R311y844 removed `queries_default_timeout` from HERE rather than
  // from the top of the file: it is honoured now, and a real zenohd refuses a
  // DUPLICATE field as flatly as an unknown one ("duplicate field
  // `queries_default_timeout`"), which is how the doubled key was found.
  metadata: {{ name: 'strawberry' }},
}}
"#
    )
}

/// The same file with ONE key neither implementation knows. Used by the
/// acceptance-boundary leg, where both are required to refuse it.
fn operator_config_with_a_typo(port: u16) -> String {
    operator_config(port).replace("queries_default_timeout:", "queries_defualt_timeout:")
}

/// The census config: enough to start a node and NOTHING optional.
///
/// The surface a resolved config exposes is a function of the config it was
/// given, which is a real property rather than an inconvenience — several
/// upstream keys are opaque SUBTREES that serialise as one `null` leaf when
/// unset and as their own contents when filled in. Measured: the census run
/// against [`operator_config`] reported `metadata/name` where the canonical
/// surface has `metadata`, because that fixture fills the subtree in. So the
/// denominator has to come from a config that fills in nothing, or the census
/// would be measuring the fixture.
fn census_config(port: u16) -> String {
    format!(
        r#"{{
  mode: "peer",
  listen: {{ endpoints: ["tcp/127.0.0.1:{port}"] }},
  scouting: {{ multicast: {{ enabled: false }} }},
}}
"#
    )
}

/// Write `json5` where zenohd can read it.
///
/// The `.json5` SUFFIX is load-bearing: zenoh dispatches its config parser on
/// the file EXTENSION and panics on a file without one.
fn staged_config(json5: &str) -> NamedTempFile {
    let mut file = tempfile::Builder::new()
        .suffix(".json5")
        .tempfile()
        .expect("config tempfile");
    file.write_all(json5.as_bytes()).expect("write config");
    file.flush().expect("flush config");
    file
}

/// Spawn zenohd on `config_path` and nothing else — the config file is the
/// sole input, which is the claim under test. `--rest-http-port none` is the
/// one exception, because the REST plugin binds a fixed default port that two
/// concurrent zenohds would collide on for reasons unrelated to the config.
fn spawn_on_config(label: &'static str, config_path: &std::path::Path) -> (ChildGuard, File) {
    let capture = tempfile::tempfile().expect("tempfile for zenohd output");
    let out = capture.try_clone().expect("dup zenohd stdout handle");
    let err = capture.try_clone().expect("dup zenohd stderr handle");
    let mut command = Command::new(zenohd_binary());
    command
        .arg("-c")
        .arg(config_path)
        .arg("--rest-http-port")
        .arg("none")
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err));
    (
        ChildGuard::wrap(label, command.spawn().expect("spawn zenohd")),
        capture,
    )
}

/// zenoh's OWN resolved config, parsed with wz's own JSON5 reader.
///
/// Using wz's reader on zenoh's output is deliberate rather than convenient:
/// the same parser has to survive a document it did not write, produced by the
/// implementation being replaced.
fn resolved_config_of(captured: &str) -> Json5Value {
    let line = captured
        .lines()
        .find(|l| l.contains(RESOLVED_CONF_MARKER))
        .unwrap_or_else(|| panic!("zenohd printed no {RESOLVED_CONF_MARKER} line\n{captured}"));
    let (_, body) = line
        .split_once(RESOLVED_CONF_MARKER)
        .expect("the marker is in the line");
    json5::parse(body.trim())
        .unwrap_or_else(|e| panic!("wz cannot read zenohd's own resolved config: {e}\n{body}"))
}

/// One resolved value in the spelling wz's own side renders it in, so the two
/// are literally comparable.
///
/// R2073 — extracted from the differential leg below rather than copied for the
/// silence leg. Two renderers would be two opinions about how a number or an
/// array is spelled, and the whole point of both legs is that one side's answer
/// is compared to the other's without a translation step in between.
fn render_resolved(value: &Json5Value) -> String {
    match value {
        Json5Value::Bool(b) => b.to_string(),
        Json5Value::Number(n) => n.clone(),
        Json5Value::String(s) => format!("\"{s}\""),
        Json5Value::Array(items) => {
            let joined: Vec<String> = items
                .iter()
                .map(|i| match i {
                    Json5Value::String(s) => format!("\"{s}\""),
                    other => format!("{other:?}"),
                })
                .collect();
            format!("[{}]", joined.join(","))
        }
        other => format!("{other:?}"),
    }
}

// wz-proves: none -- for the reason its emit-direction sibling
// (zenoh_config_emit_zenohd_interop) records: `zenoh-config-emit` is not an
// inventory atom, so A4-1 would reject the name, and registering one is a round
// with its own F=/P=/C= reason rather than a side effect of this file. zenohd
// genuinely adjudicates wz here -- it resolves the same bytes and wz is compared
// against its answer -- which is the foreign-witness shape, minus the registration.
#[test]
#[ignore = "binary-dep e2e: needs target/zenohd/zenohd (scripts/build-zenohd.sh)"]
fn wz_reads_the_same_values_out_of_a_config_that_zenohd_does() {
    let reservation = PortReservation::pick();
    let port = reservation.port();
    let source = operator_config(port);

    // wz reads the file. This happens BEFORE zenohd is started, so nothing
    // about the running node can have informed it.
    let ingest = ZenohNodeConfig::from_json5(&source)
        .unwrap_or_else(|e| panic!("wz cannot read the operator's config: {e}\n{source}"));

    let file = staged_config(&source);
    drop(reservation);
    let (guard, mut capture) = spawn_on_config("zenohd (operator config)", file.path());
    let captured = wait_for_substring(&mut capture, RESOLVED_CONF_MARKER, STARTUP_BUDGET)
        .unwrap_or_else(|e| panic!("zenohd never printed its resolved config: {e}\n{source}"));
    let resolved = resolved_config_of(&captured);

    // What wz made of each honoured key, in the resolved tree's own spelling,
    // so the two sides are literally comparable.
    let wz = &ingest.config;
    let admin = wz.adminspace.expect("the fixture enables adminspace");
    let expected: Vec<(&str, String)> = vec![
        ("mode", format!("\"{}\"", wz.mode.to_str())),
        (
            "listen/endpoints",
            format!("[\"{}\"]", wz.listen.join("\",\"")),
        ),
        (
            "scouting/multicast/enabled",
            wz.multicast_scouting.to_string(),
        ),
        ("timestamping/enabled", wz.timestamping.to_string()),
        ("transport/unicast/max_links", wz.max_links.to_string()),
        ("transport/unicast/lowlatency", wz.lowlatency.to_string()),
        ("transport/unicast/qos/enabled", wz.qos.to_string()),
        (
            "transport/unicast/compression/enabled",
            wz.compression.to_string(),
        ),
        ("transport/link/tx/batch_size", wz.batch_size.to_string()),
        ("transport/link/tx/lease", wz.lease_ms.to_string()),
        ("adminspace/enabled", String::from("true")),
        ("adminspace/permissions/read", admin.read.to_string()),
        ("adminspace/permissions/write", admin.write.to_string()),
        // R311y844 — the ten keys wz already acted on and could not be told.
        // These are the rows that make the promotion a MEASUREMENT: a key wz
        // reads at the wrong path reads zenoh's default here rather than going
        // missing, which is the silent failure this leg exists to catch.
        ("id", format!("\"{}\"", wz.id.clone().unwrap_or_default())),
        (
            "namespace",
            format!("\"{}\"", wz.namespace.clone().unwrap_or_default()),
        ),
        (
            "queries_default_timeout",
            wz.queries_default_timeout_ms
                .expect("the fixture names it")
                .to_string(),
        ),
        (
            "routing/interests/timeout",
            wz.interests_timeout_ms
                .expect("the fixture names it")
                .to_string(),
        ),
        (
            "scouting/timeout",
            wz.scouting_timeout_ms
                .expect("the fixture names it")
                .to_string(),
        ),
        (
            "transport/multicast/qos/enabled",
            wz.multicast_qos.to_string(),
        ),
        (
            "transport/shared_memory/enabled",
            wz.shared_memory.to_string(),
        ),
        (
            "transport/link/tls/root_ca_certificate",
            format!("\"{}\"", wz.tls_root_ca.clone().unwrap_or_default()),
        ),
        (
            "transport/link/tls/listen_certificate",
            format!(
                "\"{}\"",
                wz.tls_listen_certificate.clone().unwrap_or_default()
            ),
        ),
        (
            "transport/link/tls/listen_private_key",
            format!(
                "\"{}\"",
                wz.tls_listen_private_key.clone().unwrap_or_default()
            ),
        ),
    ];

    for (path, wz_says) in &expected {
        let zenoh_says = resolved
            .get(path)
            .unwrap_or_else(|| panic!("zenohd's resolved config has no {path}\n{captured}"));
        let rendered = render_resolved(zenoh_says);
        assert_eq!(
            &rendered, wz_says,
            "{path}: zenohd resolved {rendered}, wz read {wz_says}\nsource:\n{source}"
        );
    }

    // `connect/endpoints` is the one honoured key the fixture leaves out, and
    // BOTH sides have to agree it is empty — a reader that invented a value
    // here would be as wrong as one that dropped a real one.
    assert!(wz.connect.is_empty());
    assert_eq!(
        resolved.get("connect/endpoints"),
        Some(&Json5Value::Array(Vec::new()))
    );

    // The keys the file carries that wz has no opinion about must have been
    // REPORTED, not silently dropped — and zenohd must have honoured them,
    // which is what makes them wz's gap rather than a bad fixture.
    // R311y844 — `queries_default_timeout` left this list because wz honours it
    // now; it was never a key wz could not act on (`--query-timeout-ms` has
    // carried it for rounds), only one the reader had not been taught.
    assert_eq!(
        ingest.ignored,
        vec!["metadata/name", "transport/link/tx/threads"]
    );
    assert_eq!(
        resolved.get("transport/link/tx/threads"),
        Some(&Json5Value::Number(String::from("8"))),
        "the fixture's unhonoured key is one zenohd itself applied"
    );

    drop(guard);
}

// wz-proves: none -- same registration gap as the differential leg above.
/// R2073 (open-debt item 216) — what each implementation falls back to when the
/// operator's file says NOTHING, key by key.
///
/// ## Why the differential leg above cannot ask this
///
/// Its fixture moves EVERY value away from a default on purpose, so the two
/// implementations cannot agree by both landing on one. That is the right shape
/// for "did wz read what zenohd read", and it is structurally blind to the
/// question underneath it: a drop-in is handed a file that omits most keys, and
/// what the node then does is decided by whichever default each side carries.
/// Two readers can agree on every stated byte and still describe two different
/// nodes. `ZenohNodeConfig::default`'s own doc makes exactly this promise —
/// "zenoh's own defaults for the subset this struct covers, so a caller that
/// overrides one field is not silently redefining the other ten" — and until
/// this leg nothing measured it.
///
/// ## What is comparable, and what would be a category error
///
/// Only the fields that answer with a VALUE for a silent file are claims about
/// what the node does. The `Option` fields are not: `None` there means "the file
/// gave no instruction", which is a record of the DOCUMENT, while zenohd's tree
/// is a RESOLUTION. Comparing the two would be comparing different kinds of
/// statement, and `adminspace` is the trap that makes it concrete — wz's `None`
/// is documented as leaving the block out, while a real zenohd resolves
/// `adminspace/enabled: true`. That pair is pinned below as what it is, rather
/// than asserted as an equality it was never meant to satisfy.
///
/// ## The oracle's own blind spot, named rather than left implicit
///
/// A key a real zenohd resolves to `null` is one the tree has no answer for,
/// and upstream's actual default for it lives in its config crate instead.
/// MEASURED this round rather than assumed: `timestamping/enabled` resolves to
/// `null` under BOTH `mode: "peer"` and `mode: "router"`, while upstream's
/// declared default is per-whatami (`DEFAULT_CONFIG.json5:206`,
/// `{ router: true, peer: false, client: false }`, read at the pinned
/// checkout). wz carries a flat `bool` there, so it agrees with a peer and
/// differs from a ROUTER, and no resolved tree can ever show that. Those keys
/// are listed below so a green run cannot be read as coverage of them.
#[test]
#[ignore = "binary-dep e2e: needs target/zenohd/zenohd (scripts/build-zenohd.sh)"]
fn the_defaults_each_implementation_falls_back_to_are_pinned_against_a_real_zenohd() {
    // The three keys the census fixture states. Everything else in the upstream
    // surface is silent in it, which is this leg's premise and is asserted
    // below rather than trusted.
    const STATED: &[&str] = &["mode", "listen/endpoints", "scouting/multicast/enabled"];

    // Keys a real zenohd resolves to `null` for a silent file: the tree has no
    // answer, so this leg deliberately does NOT compare them, and says so.
    const THE_TREE_ANSWERS_NULL: &[&str] = &[
        "id",
        "namespace",
        "queries_default_timeout",
        "routing/interests/timeout",
        "scouting/timeout",
        "transport/link/tls/root_ca_certificate",
        "transport/link/tls/listen_certificate",
        "transport/link/tls/listen_private_key",
        "scouting/multicast/address",
        "scouting/multicast/interface",
        "scouting/multicast/ttl",
        "scouting/multicast/listen",
        "connect/retry",
        // The two where wz DOES carry a flat default and upstream's is a
        // function of `mode`. See this leg's doc: not a gap in the fixture, a
        // limit of the oracle.
        "timestamping/enabled",
        "routing/peer/mode",
    ];

    // `adminspace` is a BLOCK on wz's side and three resolved leaves on
    // zenohd's, so the two are different kinds of statement rather than two
    // answers to one question.
    const A_BLOCK_ON_ONE_SIDE_AND_LEAVES_ON_THE_OTHER: &[&str] = &[
        "adminspace/enabled",
        "adminspace/permissions/read",
        "adminspace/permissions/write",
    ];

    let reservation = PortReservation::pick();
    let port = reservation.port();
    let source = census_config(port);

    let ingest = ZenohNodeConfig::from_json5(&source)
        .unwrap_or_else(|e| panic!("wz cannot read the census config: {e}\n{source}"));

    // ANTI-VACUITY: the whole leg is about SILENCE, so a fixture that had grown
    // a key would quietly narrow it. The premise is asserted, not assumed.
    let mut named = ingest.named.clone();
    named.sort_unstable();
    let mut stated = STATED.to_vec();
    stated.sort_unstable();
    assert_eq!(
        named, stated,
        "the census fixture must state these keys and no others, or this leg is \
         measuring the fixture instead of the defaults\n{source}"
    );

    let file = staged_config(&source);
    drop(reservation);
    let (guard, mut capture) = spawn_on_config("zenohd (silent config)", file.path());
    let captured = wait_for_substring(&mut capture, RESOLVED_CONF_MARKER, STARTUP_BUDGET)
        .unwrap_or_else(|e| panic!("zenohd never printed its resolved config: {e}\n{source}"));
    let resolved = resolved_config_of(&captured);

    // Every key where wz's struct answers with a value for a silent file, in
    // the resolved tree's own spelling.
    let wz = &ingest.config;
    let claims: Vec<(&str, String)> = vec![
        ("connect/endpoints", String::from("[]")),
        ("transport/unicast/max_links", wz.max_links.to_string()),
        ("transport/unicast/lowlatency", wz.lowlatency.to_string()),
        ("transport/unicast/qos/enabled", wz.qos.to_string()),
        (
            "transport/unicast/compression/enabled",
            wz.compression.to_string(),
        ),
        ("transport/link/tx/batch_size", wz.batch_size.to_string()),
        ("transport/link/tx/lease", wz.lease_ms.to_string()),
        (
            "transport/multicast/qos/enabled",
            wz.multicast_qos.to_string(),
        ),
        (
            "transport/shared_memory/enabled",
            wz.shared_memory.to_string(),
        ),
    ];
    assert!(wz.connect.is_empty(), "the fixture states no connect list");

    for (path, wz_says) in &claims {
        let zenoh_says = resolved
            .get(path)
            .unwrap_or_else(|| panic!("zenohd's resolved config has no {path}\n{captured}"));
        // A key that STARTED resolving to null upstream would turn this row
        // into a comparison against nothing, which is the direction that reads
        // as coverage while measuring none.
        assert_ne!(
            zenoh_says,
            &Json5Value::Null,
            "{path} used to resolve to a value and now resolves to null; it \
             belongs in THE_TREE_ANSWERS_NULL, not here\n{captured}"
        );
        assert_eq!(
            &render_resolved(zenoh_says),
            wz_says,
            "{path}: a file that never mentions it starts a zenohd with {} and \
             a wz node with {wz_says} — two different nodes, and nothing said \
             so\n{captured}",
            render_resolved(zenoh_says),
        );
    }

    for path in THE_TREE_ANSWERS_NULL {
        assert_eq!(
            resolved.get(path),
            Some(&Json5Value::Null),
            "{path} is listed as one the tree cannot answer and a real zenohd \
             now resolves it; move it into the compared set\n{captured}"
        );
    }

    // The pair that is two kinds of statement, stated as that.
    assert!(
        wz.adminspace.is_none(),
        "wz's default leaves the block out — `None` is the document, not a \
         resolution"
    );
    assert_eq!(
        resolved.get("adminspace/enabled"),
        Some(&Json5Value::Bool(true)),
        "a real zenohd gives a silent file an ENABLED adminspace; wz's reader \
         has nothing to hand on\n{captured}"
    );
    assert_eq!(
        resolved.get("adminspace/permissions/read"),
        Some(&Json5Value::Bool(true)),
        "{captured}"
    );
    assert_eq!(
        resolved.get("adminspace/permissions/write"),
        Some(&Json5Value::Bool(false)),
        "{captured}"
    );

    // EXHAUSTIVE: every honoured key is in exactly one class. A key added to
    // the surface without a decision about its silent default reds here, which
    // is the only thing keeping this leg from going quietly narrow.
    let mut accounted: Vec<&str> = STATED
        .iter()
        .copied()
        .chain(claims.iter().map(|(k, _)| *k))
        .chain(THE_TREE_ANSWERS_NULL.iter().copied())
        .chain(A_BLOCK_ON_ONE_SIDE_AND_LEAVES_ON_THE_OTHER.iter().copied())
        .collect();
    accounted.sort_unstable();
    let before = accounted.len();
    accounted.dedup();
    assert_eq!(
        before,
        accounted.len(),
        "a key is accounted for twice: {accounted:?}"
    );
    let mut honoured: Vec<&str> = HONOURED_CONFIG_KEYS.to_vec();
    honoured.sort_unstable();
    assert_eq!(
        accounted, honoured,
        "every honoured key needs a decision about what wz falls back to when \
         the file is silent — compared, or named as one the tree cannot answer"
    );

    drop(guard);
}

// wz-proves: none -- same registration gap as the differential leg above.
/// R2076 (open-debt item 197) — the acceptance boundary, measured case by case
/// against a real zenohd instead of described.
///
/// ## What LEG 3 already covers, and what it cannot
///
/// `a_config_key_zenohd_refuses_is_one_wz_refuses_too` pins ONE shape: an
/// unknown key at the TOP level. Item 197's complaint is a level down — wz's
/// `upstream_knows` accepts anything BELOW a key it knows, while zenoh's own
/// derives carry `deny_unknown_fields`. The item recorded that as prose and
/// noted "no test tells the two apart today"; this leg is that test.
///
/// ## The measurement corrected BOTH sides of the record
///
/// Run this round against zenohd v1.5.0, not inferred: most nested typos ARE
/// refused (`transport.link.tls.root_ca_certificat`, `scouting.multicast.addres`,
/// `transport.link.tx.batch_siz`, and a bogus field inside `qos.network`,
/// `access_control.policies`, `downsampling`, `aggregation`, `low_pass_filter`).
/// Three subtrees are genuinely opaque and start anyway: `connect.retry`,
/// `plugins`, `metadata`. So item 197's "zenoh refuses nested typos too" was
/// right in general and wrong about `connect.retry`, while the code comment that
/// measured `connect.retry` was right about it and read as a general rule. The
/// truth is a THREE-entry exception list, and it is a fact about zenoh that only
/// zenoh can be asked.
///
/// ## Why the rows below both agree and disagree, and why that is the finding
///
/// wz's prefix rule is mostly neutralised downstream: a typo under an HONOURED
/// key reaches a typed reader that refuses it anyway, so the two implementations
/// land in the same place by different routes. Where nothing type-checks — a
/// typo under an UNHONOURED key, which wz never reads — the prefix rule is the
/// only thing looking, and it says yes while zenohd refuses to start. That is
/// the leak, stated as a pinned SET rather than a count so that TIGHTENING the
/// boundary (the next round's work) fails here too, and cannot quietly widen the
/// refusals onto a config zenohd accepts.
#[test]
#[ignore = "binary-dep e2e: needs target/zenohd/zenohd (scripts/build-zenohd.sh)"]
fn the_acceptance_boundary_is_measured_against_zenohd_case_by_case() {
    /// (label, the fragment added to an otherwise minimal config,
    ///  does a real zenohd START on it, does wz's reader ACCEPT it,
    ///  and when zenohd refuses — the REASON its message must carry)
    ///
    /// A row where the two booleans differ is a recorded divergence, not a
    /// passing grade. They are here so the set cannot change unnoticed.
    ///
    /// R2077 added the fifth column, and it is the fix for this leg's own first
    /// defect: a row can refuse for a reason that has nothing to do with its
    /// label and still look green. "zenohd said no" is not the measurement —
    /// "zenohd said no BECAUSE of the thing this row is about" is. Accepting
    /// rows carry an empty reason and never reach the check.
    const BOUNDARY: &[(&str, &str, bool, bool, &str)] = &[
        // Both refuse: the shape LEG 3 already pins, kept here as the control
        // that this table's zenohd half is not answering "yes" to everything.
        (
            "top-level unknown",
            "bogus_top: 1",
            false,
            false,
            "unknown field `bogus_top`",
        ),
        // Both refuse: a near-miss under an honoured key. wz gets there through
        // its typed reader rather than through the boundary, which is why the
        // prefix rule is invisible in this row.
        (
            "honoured leaf, typo'd sibling",
            r#"transport: { link: { tx: { batch_siz: 4096 } } }"#,
            false,
            false,
            "unknown field `batch_siz`",
        ),
        // Both refuse: R2075's mode-table field check does this one, and
        // upstream answers `unknown field "rooter", expected one of "router",
        // "peer", "client"`.
        //
        // R2077 — this row used to put the table on `listen.endpoints`, which the
        // base document ALREADY states. zenohd then refused it for
        // `duplicate field "listen"` and the row passed while measuring
        // something other than its own label. `connect` is a key the base does
        // not state, and the collision guard below is what now keeps that class
        // from coming back.
        (
            "mode table, typo'd mode name",
            r#"connect: { endpoints: { rooter: ["tcp/127.0.0.1:1"] } }"#,
            false,
            false,
            "unknown field `rooter`",
        ),
        // Both ACCEPT: the three subtrees upstream does not validate inside.
        (
            "opaque subtree: connect.retry",
            r#"connect: { retry: { period_init_mss: 250 } }"#,
            true,
            true,
            "",
        ),
        (
            "opaque subtree: plugins",
            r#"plugins: { rest: { http_port: 8000 } }"#,
            true,
            true,
            "",
        ),
        (
            "opaque subtree: metadata",
            r#"metadata: { name: "strawberry" }"#,
            true,
            true,
            "",
        ),
        // THE DIVERGENCE: a typo BELOW an unhonoured key. Nothing in wz reads
        // it, so nothing type-checks it, and the prefix rule is the only
        // judgement there is.
        (
            "unhonoured leaf, deepened",
            r#"access_control: { enabled: { xyz: true } }"#,
            false,
            false,
            "invalid type: map, expected a boolean",
        ),
        (
            "unhonoured leaf, deepened (auth)",
            r#"transport: { auth: { usrpwd: { user: { xyz: 1 } } } }"#,
            false,
            false,
            "invalid type: map, expected a string",
        ),
        // R2078 — the controls that make the tightening safe, and the reason the
        // exception list is measured rather than guessed: each of these deepens
        // BELOW a key the surface names, and a real zenohd starts on all three.
        // A boundary that refused them would stop a working deployment, which is
        // the worse half of this trade.
        (
            "deepenable: a mode table on an unhonoured key",
            r#"connect: { timeout_ms: { router: 1000, peer: 2000 } }"#,
            true,
            true,
            "",
        ),
        (
            "deepenable: a table of tables",
            r#"scouting: { multicast: { enabled: false },
                           gossip: { autoconnect_strategy: { peer: { to_router: "always" } } } }"#,
            true,
            true,
            "",
        ),
    ];

    /// The rows where the two implementations DISAGREE, by label.
    ///
    /// R2078 emptied it: the two rows that were here are the divergence R2076
    /// measured and this round closed. The constant STAYS, and stays asserted
    /// against the table, so a new divergence has to be declared rather than
    /// noticed.
    const DIVERGES: &[&str] = &[];

    // ── ANTI-VACUITY ────────────────────────────────────────────────────
    // A table that agreed everywhere would read as "the boundary matches" while
    // measuring nothing, and one that disagreed everywhere would mean the
    // fixture is broken rather than the boundary.
    let declared: Vec<&str> = BOUNDARY
        .iter()
        .filter(|(_, _, z, w, _)| z != w)
        .map(|(label, _, _, _, _)| *label)
        .collect();
    assert_eq!(
        declared, DIVERGES,
        "the pinned divergence set no longer matches the table"
    );
    // R2078 — the divergence set is empty now, so the anti-vacuity check moved to
    // the ORACLE: the table must still make a real zenohd both start and refuse.
    // A fixture that had drifted into all-accepting would agree with wz
    // everywhere and measure nothing, which is the shape an empty DIVERGES could
    // otherwise hide.
    assert!(
        BOUNDARY.iter().any(|(_, _, z, _, _)| *z) && BOUNDARY.iter().any(|(_, _, z, _, _)| !*z),
        "the table must exercise BOTH of zenohd's verdicts"
    );
    // R2077 — a refusing row without a reason would be back to "zenohd said no"
    // as the whole measurement, which is the defect this column exists to close.
    for (label, _, zenohd_starts, _, reason) in BOUNDARY {
        assert_eq!(
            reason.is_empty(),
            *zenohd_starts,
            "{label}: a row zenohd refuses needs the reason it refuses FOR, and a \
             row it accepts must not claim one"
        );
    }

    for (label, fragment, zenohd_starts, wz_accepts, reason) in BOUNDARY {
        let reservation = PortReservation::pick();
        let port = reservation.port();
        // R2078 — a row whose subject IS `scouting` has to supply the whole
        // block, because JSON5 has no way to add a field to an object stated
        // above and the collision guard (rightly) refuses a second one. Such a
        // row therefore owes the multicast-off the base would have given it,
        // and is required to carry it rather than trusted to.
        let owns_scouting = fragment.trim_start().starts_with("scouting");
        if owns_scouting {
            assert!(
                fragment.contains("enabled: false"),
                "{label}: a row that supplies its own `scouting` block must keep \
                 multicast off, or the node chatters on the group"
            );
        }
        let base_scouting = if owns_scouting {
            ""
        } else {
            "scouting: { multicast: { enabled: false } },"
        };
        let source = format!(
            r#"{{
  mode: "peer",
  listen: {{ endpoints: ["tcp/127.0.0.1:{port}"] }},
  {base_scouting}
  {fragment}
}}
"#
        );

        // R2077 — THE COLLISION GUARD, and it exists because this leg shipped
        // with a row that did not measure its own label. The base document
        // states `mode`, `listen` and `scouting`; a fragment that re-states one
        // of them produces a document zenohd refuses for `duplicate field`,
        // which is a refusal for the wrong reason and looks exactly like the
        // right one from the outside. Parsing with wz's own reader and counting
        // top-level names is the check that catches it, whatever the fragment
        // spells.
        let parsed = json5::parse(&source)
            .unwrap_or_else(|e| panic!("{label}: the fixture is not JSON5: {e:?}\n{source}"));
        let Json5Value::Object(entries) = &parsed else {
            panic!("{label}: the fixture is not an object\n{source}")
        };
        let mut names: Vec<&str> = entries.iter().map(|(k, _)| k.as_str()).collect();
        names.sort_unstable();
        let stated = names.len();
        names.dedup();
        assert_eq!(
            stated,
            names.len(),
            "{label}: the fragment re-states a key the base document already \
             has. zenohd refuses such a file for `duplicate field`, so this row \
             would pass on a refusal that has nothing to do with what it \
             claims\n{source}"
        );

        // wz first, and its verdict is read as accept/refuse only -- what it
        // made of the values is every other leg's question.
        let wz = ZenohNodeConfig::from_json5(&source);
        assert_eq!(
            wz.is_ok(),
            *wz_accepts,
            "{label}: wz {} it\n{source}{}",
            if wz.is_ok() { "accepted" } else { "refused" },
            match &wz {
                Ok(_) => String::new(),
                Err(e) => format!("{e:?}"),
            }
        );

        let file = staged_config(&source);
        drop(reservation);
        let (mut guard, mut capture) = spawn_on_config("zenohd (boundary)", file.path());
        if *zenohd_starts {
            wait_for_substring(&mut capture, RESOLVED_CONF_MARKER, STARTUP_BUDGET)
                .unwrap_or_else(|e| panic!("{label}: zenohd was expected to start: {e}\n{source}"));
        } else {
            // The REASON first: a refusal for some other cause is what this
            // leg's own first version accepted as proof.
            wait_for_substring(&mut capture, reason, STARTUP_BUDGET).unwrap_or_else(|e| {
                panic!(
                    "{label}: zenohd refused (or hung), but never for the stated \
                     reason `{reason}`: {e}\n{source}"
                )
            });
            let status = exits_within(&mut guard, STARTUP_BUDGET).unwrap_or_else(|| {
                panic!("{label}: zenohd printed the refusal and is still running\n{source}")
            });
            assert!(
                !status.success(),
                "{label}: zenohd exited SUCCESSFULLY on a config it should refuse\n{source}"
            );
        }
        drop(guard);
    }
}

/// Build one JSON5 document from `(slash path, value)` pairs, MERGING shared
/// prefixes.
///
/// R2079 — string concatenation cannot do this, and that is not a style point:
/// two pairs under `scouting` emitted separately produce two `scouting` objects,
/// which a real zenohd refuses for `duplicate field` — the trap R2077 paid a
/// round for. Merging is what lets a sweep put its subject beside the
/// multicast-off every row needs, whatever the subject's path.
fn json5_document(pairs: &[(&str, &str)]) -> String {
    fn emit(depth: usize, rows: &[(Vec<&str>, &str)]) -> String {
        let mut out = String::from("{ ");
        let mut i = 0;
        let mut first = true;
        while i < rows.len() {
            let head = rows[i].0[depth];
            let mut j = i;
            while j < rows.len() && rows[j].0[depth] == head {
                j += 1;
            }
            if !first {
                out.push_str(", ");
            }
            first = false;
            out.push_str(head);
            out.push_str(": ");
            if rows[i].0.len() == depth + 1 {
                assert_eq!(
                    j - i,
                    1,
                    "`{}` is both a leaf and a prefix in the same document",
                    rows[i].0.join("/")
                );
                out.push_str(rows[i].1);
            } else {
                out.push_str(&emit(depth + 1, &rows[i..j]));
            }
            i = j;
        }
        out.push_str(" }");
        out
    }
    let mut rows: Vec<(Vec<&str>, &str)> = pairs
        .iter()
        .map(|(p, v)| (p.split('/').collect::<Vec<_>>(), *v))
        .collect();
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    emit(0, &rows)
}

/// Wait up to `budget` for a child to exit, returning its status.
///
/// R2076 — the refusal witness for the boundary leg. A text marker cannot serve
/// here: zenohd refuses an unknown key with "unknown field" and a mistyped SHAPE
/// with an "invalid type" message, so a leg that knew only one of them would
/// read the other as a hang and blame the wrong thing. The exit is the fact
/// both refusals share.
fn exits_within(guard: &mut ChildGuard, budget: Duration) -> Option<std::process::ExitStatus> {
    let deadline = std::time::Instant::now() + budget;
    loop {
        match guard.child_mut().try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {}
            Err(_) => return None,
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

// wz-proves: none -- same registration gap as the differential leg above.
/// R2082 (open-debt item 211) — the config's transport value on the WIRE, and
/// the discriminator the drop-in leg structurally cannot have.
///
/// ## What LEG 4 proves, and the one line that says it is not enough
///
/// LEG 4 stands a node up from the file alone and requires a real zenohd to open
/// a session with it. Item 211's complaint is that this cannot separate honoured
/// from dropped, "because a discarded value opens a session just as well" — so
/// that leg passes whether `transport/link/tx/batch_size` reached the bytes or
/// was thrown away, and nothing else was looking. The chain was witnessed as far
/// as `SessionInitParams`; the last hop, into the InitSyn, was not.
///
/// ## No new public surface, because the item was right to refuse one
///
/// The round that filed 211 declined to re-export `handshake_encode` for a test
/// and said so. Nothing is exported here either: this tree's own DISSECTOR reads
/// `batch_size` out of an InitSyn, and the analyzer plane is exactly the right
/// oracle for "did my configuration reach the bytes". The listener is the test's
/// own, so the frame read is the frame the demo actually wrote — a length prefix
/// and a payload, the shape `StreamEnvelope` puts on a streamed link.
///
/// ## The discriminator is the SECOND run
///
/// One run cannot tell a honoured value from a default that happens to agree
/// with it. Two files differing ONLY in `batch_size`, and the dissected number
/// has to move with them: a dropped key gives the same number twice, which is
/// precisely the failure this leg exists to catch.
#[test]
#[ignore = "binary-dep e2e: needs wz-ap-demo built with `--features zenoh-config`"]
fn every_key_proven_on_the_wire_is_in_the_frame_a_zenohd_would_receive() {
    /// (key, the fragment for run A, its expected wire spelling,
    ///       the fragment for run B, its expected wire spelling)
    ///
    /// R2083 — two runs per key, and BOTH numbers checked. One run cannot
    /// separate a honoured value from a default that happens to agree with it;
    /// two runs that agree with each OTHER are what a dropped key looks like.
    const FIXTURES: &[(&str, &str, &str, &str, &str)] = &[
        (
            "transport/link/tx/batch_size",
            "transport: { link: { tx: { batch_size: 4096 } } }",
            "4096",
            "transport: { link: { tx: { batch_size: 8192 } } }",
            "8192",
        ),
        (
            "id",
            r#"id: "a1b2c3d4""#,
            "a1b2c3d4",
            r#"id: "0f1e2d3c""#,
            "0f1e2d3c",
        ),
        // R2085 (item 505) — the first key read out of a frame BEYOND the
        // InitSyn. Both values are deliberately not whole seconds: the OPEN
        // carries a unit flag, and a pair that could be sent either way would
        // let a unit bug pass. The reported number is normalised through
        // `lease_from_wire`, so what is compared is milliseconds either way.
        (
            "transport/link/tx/lease",
            "transport: { link: { tx: { lease: 7500 } } }",
            "7500",
            "transport: { link: { tx: { lease: 3300 } } }",
            "3300",
        ),
        // R2086 — the three transport CAPABILITIES, settled by whether the
        // InitSyn offers the extension at all. `true` has to produce the ext and
        // `false` has to produce nothing; a build that offered them
        // unconditionally would give the same answer twice and red.
        // ⚠ The lowlatency row states `qos: { enabled: false }` ITSELF. zenoh's
        // own rule is that the two are mutually exclusive, and wz enforces it at
        // ingest, so a row that only asked for lowlatency was REFUSED outright --
        // the demo never dialled and the leg blamed the build. Same shape as the
        // scouting collision R2078 met: when a row's claim needs a neighbouring
        // key held down, the row owns that too rather than leaning on a default.
        (
            "transport/unicast/lowlatency",
            "transport: { unicast: { lowlatency: true, qos: { enabled: false } } }",
            "offered",
            "transport: { unicast: { lowlatency: false, qos: { enabled: false } } }",
            "absent",
        ),
        (
            "transport/unicast/compression/enabled",
            "transport: { unicast: { compression: { enabled: true } } }",
            "offered",
            "transport: { unicast: { compression: { enabled: false } } }",
            "absent",
        ),
        // R2087 (open-debt item 506) — the THIRD capability, and the one that
        // took a wire sink to earn its row. R2086 measured this key true AND
        // false and got `["patch"]` both times: `initiator_offer` (runner.rs)
        // took `lowlatency` / `compression` / `shm` and no qos argument at all,
        // so the honoured key reached a flag nothing read.
        // ⚠ The row states `lowlatency: false` ITSELF, for the same reason the
        // lowlatency row states `qos: { enabled: false }` — the two are mutually
        // exclusive upstream and wz refuses the pair at ingest, so a row that
        // leaned on a default would be refused outright the moment the default
        // moved.
        (
            "transport/unicast/qos/enabled",
            "transport: { unicast: { qos: { enabled: true }, lowlatency: false } }",
            "offered",
            "transport: { unicast: { qos: { enabled: false }, lowlatency: false } }",
            "absent",
        ),
        // R2095 (open-debt item 513) — the FOURTH capability on the
        // `initiator_offer` seam, and the reason it is here is the item's own
        // instruction: the leg used to stop at the first failure, so `qos`,
        // `compression` and `shm` were left UNMEASURED when `lowlatency` died,
        // and unmeasured must not be read as passed. `shm` was worse than
        // unmeasured — it had no row at all, so nothing would ever have asked.
        //
        // ⚠ It is read by extension IDENTITY, not by name; see `wire_reading`.
        (
            "transport/shared_memory/enabled",
            "transport: { shared_memory: { enabled: true } }",
            "offered",
            "transport: { shared_memory: { enabled: false } }",
            "absent",
        ),
    ];

    // The POPULATION is the constant, so a key declared wire-proven without a
    // fixture here reds rather than going unasked — and a fixture for a key the
    // constant no longer claims reds too.
    let mut named: Vec<&str> = FIXTURES.iter().map(|(k, ..)| *k).collect();
    named.sort_unstable();
    let mut declared: Vec<&str> = CONFIG_KEYS_PROVEN_ON_THE_WIRE.to_vec();
    declared.sort_unstable();
    assert_eq!(
        named, declared,
        "every key declared proven on the wire needs a pair of files this leg \
         can hand the demo"
    );

    // R2096 (open-debt item 516) — every fixture is asked in every ARM, and
    // every answer is COLLECTED rather than asserted where it is read.
    //
    // Both halves of that sentence were the item's. Until R2095 the leg ran one
    // run-mode (`mode: "client"`, the single-session initiator) and `assert_eq!`
    // on the spot, so when 511 sent a `mode: "peer"` document to the peer MESH
    // the leg died on the FIRST capability — `lowlatency` — and left `qos`,
    // `compression` and `shm` unmeasured. Three keys that share a seam with the
    // one that failed read, from the outside, exactly like three keys that
    // passed. Collecting means the report names every key that is wrong in every
    // mode it is wrong in, which is what makes a mutation here attributable.
    //
    // The modes are also the CONTROL PAIR. They exercise wz's two dial paths
    // — `Role::Initiator` and `peer_loop` — from the same file, so a wiring that
    // exists on one and not the other shows up as a run-mode-shaped column of
    // failures rather than as one dead leg.
    //
    // R2096 (open-debt item 516) added the SECOND axis, `--max-links`, and its
    // control is in this same sweep for exactly the reason the run-mode axis
    // needed one. `peer_loop` has TWO dial paths inside it — `dial_face` on a
    // single link and `dial_face_multilink` when the aggregation budget is
    // above 1 — and until R2096 only the first carried a `SessionOffer`. So a
    // node offered `lowlatency` at `--max-links 1` and offered nothing at
    // `--max-links 2`, from the same document. One arm cannot see that: it is a
    // DIFFERENCE between two arms, which is why both are asked here and why a
    // mutation that unwires the aggregating entrypoint reds one column and
    // leaves the other green.
    let mut failures: Vec<String> = Vec::new();
    for (mode, max_links) in ARMS {
        for (key, frag_a, want_a, frag_b, want_b) in FIXTURES {
            let arm = ArmLabel(*mode, *max_links);
            let got_a = handshake_field_from_a_config(key, frag_a, *mode, *max_links);
            let got_b = handshake_field_from_a_config(key, frag_b, *mode, *max_links);
            if got_a != *want_a {
                failures.push(format!(
                    "{arm} {key}: the handshake carried {got_a} where the file said {want_a}"
                ));
            }
            if got_b != *want_b {
                failures.push(format!(
                    "{arm} {key}: the handshake carried {got_b} where the file said {want_b}"
                ));
            }
            if got_a == got_b {
                failures.push(format!(
                    "{arm} {key}: the wire value did not move with the file, \
                     so the file is not what set it"
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} of the {} readings this leg takes disagree with the file that \
         produced them:\n  {}",
        failures.len(),
        FIXTURES.len() * ARMS.len() * 3,
        failures.join("\n  ")
    );
}

/// The (run-mode, `--max-links`) arms every fixture is asked in.
///
/// R2096 (open-debt item 516). `None` means the flag is not passed at all,
/// which is not laziness — it is what those two run-modes DO with it:
///
/// * `Client` is `--connect`, the one-shot `Role::Initiator`. `main` parses
///   `--max-links` only in the `--peer` arm, so there is no aggregation path
///   here for the flag to select.
/// * `RouterHat` builds its `FaceSources` with `max_links: 1` hard-coded
///   (`runner.rs`, and its comment says why: router-tier aggregation is
///   unwired). Passing a number would read as a claim this arm measures the
///   aggregating path, and it does not.
///
/// `PeerMesh` carries BOTH numbers, and passes the flag EXPLICITLY at 1 as well
/// as at 2 so the only difference between the control and the arm under
/// judgement is the number itself — not whether a flag was present.
const ARMS: &[(RunMode, Option<usize>)] = &[
    (RunMode::Client, None),
    (RunMode::PeerMesh, Some(1)),
    (RunMode::PeerMesh, Some(2)),
    (RunMode::RouterHat, None),
];

/// How one arm is named in a failure line: the run-mode plus its link budget.
///
/// A `{mode:?}` alone was enough while the run-mode was the only axis. With two
/// arms sharing `PeerMesh` it is not — a report naming the mode twice with
/// different verdicts is unreadable, and the whole point of the max-links axis
/// is that its two columns are told apart.
struct ArmLabel(RunMode, Option<usize>);

impl std::fmt::Display for ArmLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.1 {
            Some(n) => write!(f, "{:?}[--max-links {n}]", self.0),
            None => write!(f, "{:?}", self.0),
        }
    }
}

/// Which run-mode a fixture's document brings up — and therefore WHICH of wz's
/// two dial paths wrote the frame under judgement.
///
/// R2095 (open-debt item 513) added the axis. It is not a variation for its own
/// sake: the two arms reach different code, and the item exists because one of
/// them reached no [`SessionOffer`](wz_runtime_tokio::session_open::SessionOffer)
/// at all.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RunMode {
    /// `mode: "client"` — a stock zenoh client never listens, so the document's
    /// `connect` list selects `--connect`: the demo's ONE-SHOT
    /// `Role::Initiator`, which builds its offer in `runner::initiator_offer`.
    ///
    /// This is the arm that was green throughout the item's life, and it is the
    /// CONTROL: a mutation that unwires the mesh must leave it green, or what
    /// the mesh arm measures is not specific to the mesh.
    Client,
    /// `mode: "peer"` — the peer MESH. The document names no `listen`, so
    /// `default_listen_endpoint(Peer)` supplies `tcp/[::]:0` and the run-mode is
    /// `--peer`, whose dials go through `peer_loop`.
    ///
    /// This arm is the whole of what item 513 is about. Before R2095 it carried
    /// `batch_size`, `id` and `lease` — the `SessionInitParams` values — and NO
    /// capability extension whatever, because `peer_loop`'s dial went out
    /// through the bare open.
    PeerMesh,
    /// `mode: "router"` — the router hat, `--router-hat`, the OTHER caller of
    /// `peer_loop`.
    ///
    /// Item 513 named both mesh run-modes, so measuring one would have left the
    /// other's wiring a claim. It is a distinct arm and not a rename of
    /// [`Self::PeerMesh`]: the two are built from different `main` branches
    /// (`RouterHatOpts` vs `PeerOpts`) and either could carry the offer while
    /// the other did not.
    ///
    /// ⚠ Unlike the other two this document NAMES its `listen`, because
    /// `default_listen_endpoint(Router)` is upstream's `tcp/[::]:7447` — a fixed
    /// port, which in a test is a collision waiting for a second run. Naming
    /// `tcp/127.0.0.1:0` keeps the arm ephemeral. What is under judgement is the
    /// frame this node DIALS out, so the address it binds is scaffolding.
    RouterHat,
}

/// Run the demo configured ONLY by a file that names `key`, and return what its
/// handshake actually carried for that key.
///
/// The listener is this test's own socket, so what is read is what the demo
/// wrote. The 2-byte little-endian length prefix is `StreamEnvelope`'s
/// (`stream_link.rs`), and the payload behind it is handed to the dissector
/// rather than to a hand-rolled reader — a second opinion about the frame
/// layout is the last thing a leg about wire fidelity should carry.
///
/// R2085 (open-debt item 505) reaches PAST the first frame. A key announced in
/// the OPEN rather than the INIT — `lease` is the one 211 named — is invisible
/// to a listener that never answers, because the demo has no reason to proceed.
/// So for those keys this speaks the one frame it has to: an InitAck built by
/// `handshake_encode::encode_init`, wz's own production encoder. That keeps the
/// instrument made of this tree's codec at BOTH ends, adds no public surface,
/// and leaves the thing under judgement where it was — the bytes the demo sent.
fn handshake_field_from_a_config(
    key: &str,
    fragment: &str,
    run_mode: RunMode,
    max_links: Option<usize>,
) -> String {
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback acceptor");
    let port = listener
        .local_addr()
        .expect("the acceptor has an address")
        .port();
    // R2091b (open-debt item 511) pinned this to `client` and said why; R2095
    // (item 513) makes it a PARAMETER, which is the whole shape of the fix.
    //
    // The history is worth keeping. It said `peer` until the round that made
    // `mode` select the run-mode, and it worked only because a peer document
    // with no listen endpoint USED to expand to `--connect`, the single-session
    // initiator. It expands to the peer MESH now, which is what a stock peer is
    // — and the mesh's dial built no `SessionOffer` at all, so the three
    // capability keys stopped reaching the InitSyn. Measured here, by this leg:
    // `transport/unicast/lowlatency` came back `absent` where the file said
    // `offered`. Item 511 pinned the fixture to the run-mode it could still
    // measure and filed the gap as 513 rather than papering over it.
    //
    // R2095 wired `peer_loop`'s dial and accept sites to a `SessionOffer` and
    // this leg is what holds that wiring: `PeerMesh` asks the SAME files of the
    // mesh path, and `Client` stays as the control that says a mesh failure is
    // the mesh's.
    //
    // ⚠ `PeerMesh` deliberately names NO `listen`. A binding mode whose document
    // names an empty listen list selects no run-mode at all (`args.rs`), so
    // spelling one here would swap the arm under test for a node that never
    // dials. Leaving it unnamed is what lets `default_listen_endpoint(Peer)`
    // supply `tcp/[::]:0`, which is upstream's own default for the mode.
    // `RouterHat` names one for the opposite reason — see that variant's doc.
    let (mode, listen) = match run_mode {
        RunMode::Client => ("client", ""),
        RunMode::PeerMesh => ("peer", ""),
        RunMode::RouterHat => (
            "router",
            "  listen: { endpoints: [\"tcp/127.0.0.1:0\"] },\n",
        ),
    };
    let source = format!(
        r#"{{
  mode: "{mode}",
{listen}  connect: {{ endpoints: ["tcp/127.0.0.1:{port}"] }},
  scouting: {{ multicast: {{ enabled: false }} }},
  {fragment},
}}
"#
    );
    let file = staged_config(&source);

    // R2095 (open-debt item 507's discipline, applied here) — the child's stderr
    // is PIPED, not discarded.
    //
    // It used to be `Stdio::null()`, and that is exactly the shape 507 is about:
    // when the demo refuses a document — a mode this build has no feature for, a
    // key it will not take — it says so on stderr and exits, and a leg that
    // dropped the pipe could report only "the demo never dialled". The run-mode
    // axis makes that reachable in a new way (`mode: "peer"` needs
    // `routing-peer`, `mode: "router"` needs `router-hat-router`), so the reason
    // has to survive to the failure message.
    // R2096 (open-debt item 516) — the aggregation budget rides ARGV, not the
    // document, and that is deliberate.
    //
    // `transport/unicast/max_links` IS a honoured config key, so the file could
    // carry it — but every fixture fragment already opens its own `transport`
    // object, and a document with two of them is the `duplicate field` refusal
    // R2077 met on `listen`. Typing the flag is not a workaround for that: the
    // expansion treats an argv-typed flag as authoritative and withholds the
    // file's value (`args.rs`, `decide_pair`), which is the documented override
    // path. What is under judgement here is still only what the FILE's
    // capability keys reached; the arm decides which of wz's dial paths carried
    // them.
    let mut cmd = Command::new(&demo);
    cmd.arg("--config")
        .arg(file.path())
        .arg("--key")
        .arg("demo/wire");
    if let Some(n) = max_links {
        cmd.arg("--max-links").arg(n.to_string());
    }
    let mut child = cmd
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn wz-ap-demo");
    // Drained on a thread so a demo that fills the pipe buffer is not blocked by
    // this test's own read schedule. The receiver is read only on the failure
    // paths below, where it is the whole point.
    let stderr = child.stderr.take().expect("the child's stderr is piped");
    let (stderr_tx, stderr_rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        let mut text = String::new();
        let mut stderr = stderr;
        let _ = std::io::Read::read_to_string(&mut stderr, &mut text);
        let _ = stderr_tx.send(text);
    });
    let drained = move || {
        stderr_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap_or_else(|_| String::from("<the child's stderr did not close>"))
    };
    let mut guard = ChildGuard::wrap("wz-ap-demo (wire batch)", child);

    // R2083 — accept with a DEADLINE. `TcpListener::accept` blocks forever, and
    // a test that waits forever does not fail: it takes the whole job's budget
    // with it. That is not hypothetical — R2082's leg reached Layer E through a
    // missing skip token, met a demo built without `zenoh-config` (which exits
    // on `--config`), and the hosted `demo-spawning e2e` job was CANCELLED on
    // its budget rather than reporting anything. The token is fixed above; this
    // is the half that makes the leg safe wherever it runs.
    listener
        .set_nonblocking(true)
        .expect("a listener that can be polled");
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let (mut stream, _) = loop {
        match listener.accept() {
            Ok(pair) => break pair,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // R2095 — ask whether the child is still ALIVE before asking
                // whether the deadline has passed. A demo that exited on the
                // first line of `main` will never dial, and waiting the full 20s
                // to say so turns one refused document into 20 seconds of the
                // job's budget per fixture. `try_wait` is the cheap question;
                // the stderr it exited with is the answer the message needs.
                if let Ok(Some(status)) = guard.child_mut().try_wait() {
                    panic!(
                        "the demo exited ({status}) before dialling the \
                         acceptor:\n{}\n{source}",
                        drained()
                    );
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "the demo never dialled the acceptor, and it is still \
                     running. Built without `zenoh-config` it exits on \
                     `--config` and never connects, which is what this deadline \
                     exists to say out loud\n{}\n{source}",
                    drained()
                );
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("the acceptor could not accept: {e}\n{source}"),
        }
    };
    stream
        .set_nonblocking(false)
        .expect("blocking reads on the accepted stream");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .expect("a read deadline");

    let payload = read_stream_frame(&mut stream, &source, "the demo's first frame");

    let (frame, reading) = wire_reading(key);
    let wire_name = reading.field();
    let payload = match frame {
        HandshakeFrame::InitSyn => payload,
        HandshakeFrame::OpenSyn => {
            // The InitSyn is not what is being read here, but it is still the
            // frame that has to have arrived: answering an OPEN with an INIT|ACK
            // would leave the next read waiting on a peer that had already given
            // up, and the deadline would then blame the wrong thing.
            let init = dissect_transport_message(&payload, 0).unwrap_or_else(|e| {
                panic!("wz cannot dissect the demo's first frame: {e:?}\n{source}")
            });
            assert!(
                init.find("batch_size").is_some(),
                "the first frame is not an InitSyn, so the OPEN this leg wants \
                 will never be sent\n{init:?}"
            );

            // An honest InitAck, built by THIS TREE'S OWN encoder. Nothing is
            // exported to make it: `handshake_encode::encode_init` is already
            // public, which is what open-debt 505 had not checked when it listed
            // "a new observation surface" and "a hand-rolled accept FSM" as the
            // only two routes to the OPEN. The acceptor here is an INSTRUMENT --
            // what is judged is still only what the DEMO wrote.
            let mut params = zenoh_interop_session_init_params(WhatAmI::Router, vec![0x0a; 4]);
            params.cookie = vec![0xc0, 0x0c, 0x1e, 0x00];
            let ack = encode_init(&params, true, &[], None)
                .unwrap_or_else(|e| panic!("wz cannot encode its own InitAck: {e:?}"));
            let len = u16::try_from(ack.len()).expect("an InitAck fits a 2-byte prefix");
            stream
                .write_all(&len.to_le_bytes())
                .and_then(|()| stream.write_all(&ack))
                .unwrap_or_else(|e| panic!("could not answer the InitSyn: {e}\n{source}"));
            read_stream_frame(&mut stream, &source, "the demo's OPEN")
        }
    };
    drop(guard);

    let field = dissect_transport_message(&payload, 0)
        .unwrap_or_else(|e| panic!("wz cannot dissect the frame it asked for: {e:?}\n{source}"));

    // R2086 — a key can be settled by a field that is either THERE or NOT, with
    // no value to read. The four transport capabilities the demo offers ride the
    // InitSyn as UNIT extensions (`ext_name.rs`: `qos` 0x1, `multi_link` 0x4,
    // `low_latency` 0x5, `compression` 0x6): a UNIT ext carries no payload, so
    // its PRESENCE is the whole announcement. Reporting that as a value keeps the
    // sweep's contract intact -- two runs must still disagree -- without pretending
    // to read a number that is not on the wire.
    if let Reading::Presence(name) = reading {
        // ⚠ NOT `field.find(name)`. The dissector does not name an extension's
        // field after the extension: it emits a field CALLED `ext_name` whose
        // VALUE is the name (`dissect.rs:742`), because an ext entry's identity
        // is its id and the name is a reading of that id. `find` would have
        // returned None for every extension that exists, which is a green
        // "absent" for the wrong reason -- and both runs would have agreed, so
        // only the two-run rule would have caught it.
        let offered = ext_names(&field);
        // The verdict stays canonical so the sweep can compare it; the list goes
        // to stderr, where a round asking "why is this absent" reads it under
        // `--nocapture` instead of re-deriving it.
        eprintln!("wire {key}: the InitSyn offered {offered:?}");
        return if offered.iter().any(|n| n == name) {
            "offered".to_string()
        } else {
            "absent".to_string()
        };
    }

    match field.find(wire_name).map(|f| &f.value) {
        Some(FieldValue::Uint(v)) if wire_name == "lease" => {
            // The lease's UNIT is on the wire, in the OPEN's `t` flag: set means
            // seconds. Reporting the raw number would make a leg about wire
            // fidelity depend on which unit the encoder happened to choose, so
            // the flag is read and the value normalised back to milliseconds by
            // the same `lease_from_wire` the receiving side uses.
            let in_seconds = matches!(
                field.find("t").map(|f| &f.value),
                Some(FieldValue::Flag(true))
            );
            lease_from_wire(in_seconds, *v).to_string()
        }
        Some(FieldValue::Uint(v)) => v.to_string(),
        Some(FieldValue::Bytes(b)) => b.iter().map(|byte| format!("{byte:02x}")).collect(),
        other => panic!("the frame carries no {wire_name}: {other:?}\n{field:?}"),
    }
}

/// Which handshake frame a wire-proven key rides in, and the dissector's own
/// name for it there.
///
/// A key whose wire spelling this leg cannot read is refused LOUDLY rather than
/// reported as a miss: adding a name to `CONFIG_KEYS_PROVEN_ON_THE_WIRE` is a
/// claim that something reads it, and this is where that claim is kept.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum HandshakeFrame {
    InitSyn,
    OpenSyn,
}

/// Every extension NAME the dissector could read in this frame, in order.
///
/// An ext entry is identified on the wire by its id; `ext_name` is the
/// dissector's READING of that id, carried as a `Label` field beside it. So the
/// question "was this capability offered" is a scan for that label's value, and
/// it has to visit every entry -- `Field::find` stops at the first match, and
/// what is wanted here is the whole chain.
fn ext_names(field: &wz_session_core::dissect::Field) -> Vec<String> {
    fn walk(f: &wz_session_core::dissect::Field, out: &mut Vec<String>) {
        if f.name == "ext_name" {
            if let FieldValue::Label(name) = &f.value {
                out.push(name.to_string());
            }
        }
        if let FieldValue::Nested(children) = &f.value {
            for child in children {
                walk(child, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(field, &mut out);
    out
}

/// How a key's effect shows up in its frame: as a field carrying a VALUE, or as
/// a field that is simply present or missing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Reading {
    Value(&'static str),
    Presence(&'static str),
}

impl Reading {
    fn field(self) -> &'static str {
        match self {
            Self::Value(name) | Self::Presence(name) => name,
        }
    }
}

fn wire_reading(key: &str) -> (HandshakeFrame, Reading) {
    use HandshakeFrame::{InitSyn, OpenSyn};
    match key {
        "transport/link/tx/batch_size" => (InitSyn, Reading::Value("batch_size")),
        "id" => (InitSyn, Reading::Value("zid")),
        "transport/link/tx/lease" => (OpenSyn, Reading::Value("lease")),
        "transport/unicast/lowlatency" => (InitSyn, Reading::Presence("low_latency")),
        "transport/unicast/compression/enabled" => (InitSyn, Reading::Presence("compression")),
        "transport/unicast/qos/enabled" => (InitSyn, Reading::Presence("qos")),
        // R2095 — the FOURTH capability on the `initiator_offer` seam, and the
        // one item 513 named as unmeasured. Its Init form is
        // `extshm::SHM_INIT_EXT_HEADER` = 0x42 (ZBuf `0x40` | id `0x2`), which
        // is the identity `crate::ext_name`'s `Init` table already spells `shm`
        // — so it reads by NAME like its three siblings.
        //
        // ⚠ That was MEASURED here, not assumed, and the assumption it replaced
        // was wrong. R2095 first wrote this row as a read by `(id, encoding)`
        // on the strength of R311y505's sentence that "wz offers a UNIT at the
        // same numeric id (header 0x02)", which is true of
        // `extshm::shm_unit_ext` and NOT of the Init offer this leg reads. The
        // leg reported the frame's actual ext identities and it was `(2, 2)` —
        // ZBuf. Two rows in the same module, one sentence about them.
        "transport/shared_memory/enabled" => (InitSyn, Reading::Presence("shm")),
        other => panic!("{other} is declared wire-proven and this leg cannot read it"),
    }
}

/// One `StreamEnvelope` frame: a 2-byte little-endian length and its payload
/// (`stream_link.rs`). `what` names the frame so a short read blames the read
/// that was actually being attempted.
fn read_stream_frame(stream: &mut std::net::TcpStream, source: &str, what: &str) -> Vec<u8> {
    let mut prefix = [0u8; 2];
    stream
        .read_exact(&mut prefix)
        .unwrap_or_else(|e| panic!("no length prefix for {what}: {e}\n{source}"));
    let len = u16::from_le_bytes(prefix) as usize;
    assert!(len > 0, "a zero-length frame is not {what}\n{source}");
    let mut payload = vec![0u8; len];
    stream
        .read_exact(&mut payload)
        .unwrap_or_else(|e| panic!("{what} was short of its own prefix: {e}\n{source}"));
    payload
}

// wz-proves: none -- same registration gap as the leg above.
/// R2079 (open-debt item 502) — EVERY key wz lets deepen is asked of a real
/// zenohd, not three of them.
///
/// ## Why a sweep and not more rows
///
/// R2078 widened the acceptance boundary's exception list to sixteen keys, each
/// verified once by hand, and R2076's leg then re-asked THREE of them. The other
/// thirteen were a claim about zenoh that nothing checked, and the failure
/// direction is the bad one: a key wrongly on the list makes wz accept a typo,
/// while a key wrongly OFF it makes wz refuse a file a real zenohd starts on and
/// the operator hears only "it will not start".
///
/// ⛔ That is not hypothetical — it had already happened. Sweeping the WHOLE
/// surface against zenohd (and not re-reading the list) found `listen/retry`
/// missing: `connect/retry`'s twin, opaque for the same reason, and R2078
/// enumerated the mode-dependent keys carefully while never looking for a second
/// opaque subtree. This leg is what would have caught it.
///
/// ## The values are legal on purpose
///
/// Six probes in the round that built this list came back "refused" and were
/// DEAD — four on `duplicate field` because a fixture restated its own base key,
/// two on a wrong value shape (`autoconnect` takes an ARRAY,
/// `DEFAULT_CONFIG.json5:146-149`). So each row here carries a value upstream
/// documents, the document is MERGED rather than concatenated, and a row that
/// stops meaning what it says shows up as zenohd refusing to start.
#[test]
#[ignore = "binary-dep e2e: needs target/zenohd/zenohd (scripts/build-zenohd.sh)"]
fn every_key_wz_lets_deepen_is_one_a_real_zenohd_deepens_too() {
    /// (key, a deeper value upstream documents for it)
    ///
    /// `listen/endpoints` takes the ROUTER row deliberately: this node is a
    /// peer, so it binds nothing and the leg cannot collide with a port.
    const LEGAL: &[(&str, &str)] = &[
        ("connect/endpoints", r#"{ router: ["tcp/127.0.0.1:1"] }"#),
        ("connect/exit_on_failure", "{ router: true }"),
        ("connect/retry", "{ period_init_ms: 250 }"),
        ("connect/timeout_ms", "{ router: 1000 }"),
        ("listen/endpoints", "{ router: [] }"),
        ("listen/exit_on_failure", "{ router: true }"),
        ("listen/retry", "{ period_init_ms: 250 }"),
        ("listen/timeout_ms", "{ router: 1000 }"),
        ("metadata", r#"{ name: "strawberry" }"#),
        ("plugins", "{ rest: { zzz_unknown: 1 } }"),
        ("scouting/gossip/autoconnect", "{ router: [] }"),
        (
            "scouting/gossip/autoconnect_strategy",
            r#"{ peer: { to_router: "always" } }"#,
        ),
        ("scouting/gossip/target", r#"{ router: ["router"] }"#),
        ("scouting/multicast/autoconnect", "{ router: [] }"),
        (
            "scouting/multicast/autoconnect_strategy",
            r#"{ peer: { to_router: "always" } }"#,
        ),
        ("scouting/multicast/listen", "{ router: true }"),
        ("timestamping/enabled", "{ router: true }"),
    ];

    // ── EXHAUSTIVE ──────────────────────────────────────────────────────
    // The population is the CONSTANT, so a key added to it without a measured
    // value reds here rather than going unasked.
    let mut named: Vec<&str> = LEGAL.iter().map(|(k, _)| *k).collect();
    named.sort_unstable();
    let mut declared: Vec<&str> = DEEPENABLE_UPSTREAM_KEYS.to_vec();
    declared.sort_unstable();
    assert_eq!(
        named, declared,
        "every key the reader lets deepen needs a value this leg can hand a \
         real zenohd"
    );

    for (key, value) in LEGAL {
        let source = json5_document(&[
            ("mode", "\"peer\""),
            ("scouting/multicast/enabled", "false"),
            (key, value),
        ]);

        // wz first: nothing about the running node can have informed it.
        ZenohNodeConfig::from_json5(&source).unwrap_or_else(|e| {
            panic!("{key}: wz refuses a shape it declares deepenable: {e:?}\n{source}")
        });

        let file = staged_config(&source);
        let (guard, mut capture) = spawn_on_config("zenohd (deepenable)", file.path());
        wait_for_substring(&mut capture, RESOLVED_CONF_MARKER, STARTUP_BUDGET).unwrap_or_else(
            |e| {
                panic!(
                    "{key}: wz lets this deepen and a real zenohd does not start on \
                     it — an operator's legal file would be refused by wz for the \
                     opposite reason, or accepted by wz and refused by zenohd: \
                     {e}\n{source}"
                )
            },
        );
        drop(guard);
    }
}

// wz-proves: none -- same registration gap as the leg above.
/// R2075 (open-debt item 499) — upstream's MODE-DEPENDENT spelling, on the key
/// where refusing it is fatal rather than merely partial.
///
/// `listen.endpoints` is `ModeDependentValue<Vec<EndPoint>>` upstream
/// (`commons/zenoh-config/src/lib.rs`, read at the pinned checkout), so a file
/// may give it as a `{ router, peer, client }` table and each node takes its own
/// row. wz's reader accepted only the plain list and answered the table with
/// `WrongType` — which is not a missing feature but a node that does not start,
/// on one of the two most ordinary keys a config has.
///
/// The two halves are ONE leg on purpose. A unit test can show wz resolving the
/// table; only a real zenohd can show that the table MEANS what wz now takes it
/// to mean, and it shows it by BINDING — two nodes of different modes, reading
/// the same bytes, landing on different ports. Each mode also asserts the OTHER
/// row was not bound, because "it came up somewhere" is what a reader that
/// flattened the table would also produce.
#[test]
#[ignore = "binary-dep e2e: needs target/zenohd/zenohd (scripts/build-zenohd.sh)"]
fn a_mode_dependent_endpoint_table_binds_the_same_row_for_zenohd_and_for_wz() {
    /// zenohd's own line for the endpoint it actually reached the network on.
    const REACHABLE: &str = "Zenoh can be reached at: ";

    // `pick_pair` and not two `pick`s: the reservation mutex is non-reentrant,
    // and the pair form is what guarantees the two ports differ.
    let (reservation, peer_port) = PortReservation::pick_pair();
    let router_port = reservation.port();
    let template = format!(
        r#"{{
  mode: "MODE",
  listen: {{ endpoints: {{ router: ["tcp/127.0.0.1:{router_port}"],
                           peer:   ["tcp/127.0.0.1:{peer_port}"] }} }},
  scouting: {{ multicast: {{ enabled: false }} }},
}}
"#
    );
    drop(reservation);

    for (mode, mine, theirs) in [
        ("router", router_port, peer_port),
        ("peer", peer_port, router_port),
    ] {
        let source = template.replace("MODE", mode);

        // wz reads the file BEFORE zenohd is started, so nothing about the
        // running node can have informed it.
        let ingest = ZenohNodeConfig::from_json5(&source).unwrap_or_else(|e| {
            panic!("{mode}: wz cannot read the table spelling: {e:?}\n{source}")
        });
        assert_eq!(
            ingest.config.listen,
            vec![format!("tcp/127.0.0.1:{mine}")],
            "{mode}: wz resolved the wrong row\n{source}"
        );

        let file = staged_config(&source);
        let (guard, mut capture) = spawn_on_config("zenohd (mode table)", file.path());
        let captured = wait_for_substring(&mut capture, REACHABLE, STARTUP_BUDGET)
            .unwrap_or_else(|e| panic!("{mode}: zenohd never came up: {e}\n{source}"));
        let line = captured
            .lines()
            .find(|l| l.contains(REACHABLE))
            .expect("the marker is in the capture");
        assert!(
            line.contains(&format!("tcp/127.0.0.1:{mine}")),
            "{mode}: zenohd bound something other than its own row: {line}"
        );
        assert!(
            !line.contains(&format!("tcp/127.0.0.1:{theirs}")),
            "{mode}: zenohd bound the other mode's row too, so the table is not \
             a per-mode selection after all: {line}"
        );
        drop(guard);
    }
}

// wz-proves: none -- same registration gap as the leg above.
#[test]
#[ignore = "binary-dep e2e: needs target/zenohd/zenohd (scripts/build-zenohd.sh)"]
fn a_config_key_zenohd_refuses_is_one_wz_refuses_too() {
    // THE ACCEPTANCE BOUNDARY, and it is the design this round MEASURED rather
    // than chose. The first cut accepted any unknown key and merely reported
    // it; a real zenohd handed the same file refuses to start. Accepting it
    // would be the worse drop-in failure: a typo the operator's OLD node
    // caught would silently run under wz with the setting never applied.
    let reservation = PortReservation::pick();
    let port = reservation.port();
    let source = operator_config_with_a_typo(port);

    let err =
        ZenohNodeConfig::from_json5(&source).expect_err("wz accepted a key stock zenoh refuses");
    assert!(
        format!("{err}").contains("queries_defualt_timeout"),
        "wz refused the file but not for the typo: {err}"
    );

    let file = staged_config(&source);
    drop(reservation);
    let (guard, mut capture) = spawn_on_config("zenohd (typo config)", file.path());
    // zenohd EXITS on a bad config, so the witness is its refusal, not a
    // resolved-config line. Waiting for the refusal text (rather than for the
    // process to die) keeps the leg from passing on any other kind of death.
    let captured = wait_for_substring(&mut capture, "unknown field", STARTUP_BUDGET)
        .unwrap_or_else(|e| panic!("zenohd did not refuse the typo: {e}\n{source}"));
    assert!(
        captured.contains("queries_defualt_timeout"),
        "zenohd refused for some other reason\n{captured}"
    );

    drop(guard);
}

// wz-proves: none -- same registration gap as the leg above.
#[test]
#[ignore = "binary-dep e2e: needs target/zenohd/zenohd (scripts/build-zenohd.sh)"]
fn the_upstream_config_surface_zenohd_resolves_is_enumerated_and_accounted_for() {
    let reservation = PortReservation::pick();
    let port = reservation.port();
    let source = census_config(port);
    let file = staged_config(&source);
    drop(reservation);
    let (guard, mut capture) = spawn_on_config("zenohd (surface census)", file.path());
    let captured = wait_for_substring(&mut capture, RESOLVED_CONF_MARKER, STARTUP_BUDGET)
        .unwrap_or_else(|e| panic!("zenohd never printed its resolved config: {e}"));

    // THE DENOMINATOR IS UPSTREAM'S, OBTAINED BY EXECUTION. Not
    // DEFAULT_CONFIG.json5 (which documents a subset and comments most of it
    // out) and not a wz-side list: zenoh serialises its whole `Config` here,
    // so this is the surface a replacement has to face.
    let upstream = resolved_config_of(&captured).leaf_paths();

    let honoured: Vec<&String> = upstream
        .iter()
        .filter(|p| HONOURED_CONFIG_KEYS.contains(&p.as_str()))
        .collect();
    let unhonoured: Vec<&str> = upstream
        .iter()
        .filter(|p| !HONOURED_CONFIG_KEYS.contains(&p.as_str()))
        .map(String::as_str)
        .collect();

    // Every key wz claims to honour must actually be IN the upstream surface —
    // a honoured key upstream does not have is wz reading a path that no zenoh
    // config will ever carry.
    let missing: Vec<&&str> = HONOURED_CONFIG_KEYS
        .iter()
        .filter(|k| !upstream.iter().any(|p| p == *k))
        .collect();
    assert!(
        missing.is_empty(),
        "wz honours keys a real zenohd does not resolve: {missing:?}"
    );

    // The SET, not the count. A key added upstream, or one wz starts honouring,
    // reds here and has to be classified in the round that moved it. The
    // expected list lives in the LIBRARY (it is what `from_json5` accepts) and
    // is adjudicated here: wz declares, a running zenohd judges.
    assert_eq!(
        unhonoured, UNHONOURED_UPSTREAM_CONFIG_KEYS,
        "the upstream config surface moved"
    );
    assert_eq!(
        honoured.len() + unhonoured.len(),
        upstream.len(),
        "the partition lost a key"
    );

    drop(guard);
}

// wz-proves: none -- same registration gap as the legs above.
#[test]
#[ignore = "binary-dep e2e: needs target/zenohd/zenohd and a wz-ap-demo built \
            with --features zenoh-config"]
fn a_wz_node_configured_only_by_a_stock_zenoh_config_reaches_a_real_zenohd() {
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);

    let reservation = PortReservation::pick();
    let port = reservation.port();
    // The ROUTER's file names a listen endpoint; the wz node's file names the
    // same endpoint to connect to. The port exists in no argv and no default:
    // a wz that read the key but not its value cannot pass this by dialling
    // something it already knew.
    let router_source = operator_config(port);
    let router_file = staged_config(&router_source);
    // R311y843 — the wz node's file carries the two HANDSHAKE values as well as
    // the endpoint, both moved away from the demo's own (4096 vs 65535, 3000 vs
    // 10000), plus the compression offer. Until this round the file's endpoint
    // was the only thing that reached the node, so this leg adjudicated the
    // topology half of a drop-in and nothing about the wire; these three now
    // reach the InitSyn/OpenSyn a REAL zenohd reads, and a value zenoh will not
    // open on reds here rather than in an operator's deployment.
    let client_source = format!(
        r#"/// The wz node's own config -- the same file an operator would have
/// handed to a zenoh client.
{{
  mode: "client",
  // R311y849 — `retry` sits beside the endpoints it paces, and like the four
  // multicast leaves below it is named here BECAUSE it must reach nothing in
  // this invocation. Its precondition is a run mode that owns a connect LIST
  // (`--peer` / `--router-hat`); a client dials one endpoint through `--connect`
  // and its reconnect supervisor is a different substrate with a different
  // declared parity target, so an expansion that emitted `--connect-retry` here
  // would hand a valid stock config to a binary with no parse for it.
  connect: {{
    endpoints: ["tcp/127.0.0.1:{port}"],
    retry: {{ period_init_ms: 1000, period_max_ms: 4000, period_increase_factor: 2 }},
  }},
  // R311y846 — the four `multicast` leaves are named here BECAUSE they must
  // reach nothing in this invocation, which is the half the unit tests cannot
  // put in front of the binary. Each carries a command-line precondition this
  // node does not meet (the socket three need `--scout` or `--scout-listen`;
  // the answering one needs `--peer` and a feature this lane does not build),
  // so an expansion that emitted any of them would hand a VALID operator config
  // to a binary that exits(2) — the exact failure R311y844 measured and this
  // fixture exists to keep measuring. Values are upstream's own defaults, and
  // `listen: false` matches the `enabled: false` above: a client that dials an
  // endpoint is not on the group in either direction.
  scouting: {{
    multicast: {{
      enabled: false,
      address: "224.0.0.224:7446",
      interface: "auto",
      ttl: 1,
      listen: false,
    }},
    timeout: 2500,
  }},
  transport: {{
    unicast: {{
      max_links: 2,
      lowlatency: false,
      qos: {{ enabled: true }},
      compression: {{ enabled: true }},
    }},
    multicast: {{ qos: {{ enabled: true }} }},
    shared_memory: {{ enabled: false }},
    link: {{
      tls: {{
        root_ca_certificate: "/etc/wz/ca.pem",
        listen_certificate: "/etc/wz/server.pem",
        listen_private_key: "/etc/wz/server.key",
      }},
      tx: {{ batch_size: 4096, lease: 3000 }},
    }},
  }},
  // R311y844 — this file now names EVERY honoured key, which turns this leg
  // into the gate for a class the unit tests are structurally blind to: they
  // check the argv the expansion BUILDS, and the failure mode is an argv the
  // demo REFUSES. Four of the flags exit(2) when a precondition is unmet
  // (`--scout-timeout-ms requires --scout`, `--query-timeout-ms requires
  // --query`, and two that need a cargo feature), and the round's first cut
  // emitted them unconditionally — measured, by running this binary and
  // getting `--scout-timeout-ms requires --scout` and rc=2 out of a VALID
  // stock config. The expansion withholds them now, and this fixture is what
  // notices if it stops.
  //
  // The unhonoured keys stay out on purpose: they are reported, and this leg
  // is about the ones wz claims to apply.
  id: "a1b2c3d4",
  namespace: "demo/ns",
  timestamping: {{ enabled: true }},
  queries_default_timeout: 11000,
  // R2065 — `peer/mode` joins the EXISTING `routing` block rather than opening
  // a second one. The first cut added its own `routing: {{ … }}` earlier in the
  // file and this later object silently won, so `interests/timeout` was named
  // and `peer/mode` was not: in JSON5 a duplicate key reads as a MISSING key,
  // and this leg is what caught it.
  //
  // Named for the same reason as the multicast leaves above — it must reach
  // NOTHING here. The expansion emits `--peer-mode` only for `peer-to-peer`,
  // and this says `linkstate`, which is upstream's default and what an absent
  // flag already means; a client dialling one endpoint has no discovery plane
  // to switch.
  routing: {{ interests: {{ timeout: 9000 }}, peer: {{ mode: "linkstate" }} }},
  adminspace: {{ enabled: true, permissions: {{ read: true, write: false }} }},
}}
"#
    );
    // R311y844 — COVERAGE, so the gate above cannot silently narrow: a
    // twenty-fifth honoured key that this fixture does not name would never be
    // put in front of the binary, and the leg would go on passing while the
    // class it now covers reopened.
    let client_ingest = ZenohNodeConfig::from_json5(&client_source)
        .unwrap_or_else(|e| panic!("the drop-in fixture is not readable: {e}\n{client_source}"));
    let mut fixture_names = client_ingest.named.clone();
    // `listen/endpoints` is the ONE honoured key this leg's role forbids, the
    // mirror of the exception the oracle leg makes for `connect/endpoints`: a
    // client that also listens expands to `--listen` instead of `--connect`,
    // which is a different node from the one this leg is about. Named here
    // rather than left as a silent shortfall.
    let mut every_honoured: Vec<&str> = HONOURED_CONFIG_KEYS
        .iter()
        .copied()
        .filter(|k| *k != "listen/endpoints")
        .collect();
    fixture_names.sort_unstable();
    every_honoured.sort_unstable();
    assert_eq!(
        fixture_names, every_honoured,
        "the drop-in fixture must name every honoured key a connecting client \
         can carry, so every flag the expansion can emit is one this binary is \
         asked to accept"
    );

    let client_file = staged_config(&client_source);
    drop(reservation);

    let (router, mut router_capture) =
        spawn_on_config("zenohd (drop-in target)", router_file.path());
    wait_for_substring(&mut router_capture, RESOLVED_CONF_MARKER, STARTUP_BUDGET)
        .unwrap_or_else(|e| panic!("zenohd never came up: {e}"));
    // R2091 — and then for the LISTENER, which is a later event. The demo below
    // dials once and exits on a refusal, so gating it on the conf line put a
    // 34 ms hole between "zenohd said something" and "zenohd can be reached",
    // which this machine lost every time. See [`LISTENER_UP_MARKER`].
    wait_for_substring(&mut router_capture, LISTENER_UP_MARKER, STARTUP_BUDGET)
        .unwrap_or_else(|e| panic!("zenohd printed its config but never bound a listener: {e}"));

    let capture = tempfile::tempfile().expect("tempfile for demo output");
    let out = capture.try_clone().expect("dup demo stdout handle");
    let err = capture.try_clone().expect("dup demo stderr handle");
    let mut command = Command::new(&demo);
    // `--config` and the payload flags ONLY. No `--connect`: if the endpoint
    // were also on the command line this leg would not distinguish a wz that
    // read the file from one that ignored it.
    command
        .arg("--config")
        .arg(client_file.path())
        .arg("--publish")
        .arg("demo/config/dropin")
        .arg("--value")
        .arg("configured-by-the-operators-own-file")
        .env("RUST_LOG", "info")
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err));
    let demo_guard = ChildGuard::wrap(
        "wz-ap-demo (--config)",
        command.spawn().expect("spawn wz-ap-demo"),
    );

    let mut demo_capture = capture;
    let seen = wait_for_substring(&mut demo_capture, DEMO_ESTABLISHED, DEMO_BUDGET);
    if let Err(e) = &seen {
        // PANIC, never skip: a build without the feature must fail the lane
        // rather than pass it quietly.
        let so_far = wz_integration_tests::common::read_captured(&mut demo_capture);
        assert!(
            !so_far.contains("--config requires the `zenoh-config` feature"),
            "this lane's wz-ap-demo was built without the feature under test; \
             rebuild with `cargo build -p wz-ap-demo --features zenoh-config`"
        );
        panic!("wz-ap-demo never established a session from the config file alone: {e}\n{so_far}");
    }
    let seen = seen.expect("checked above");
    // The endpoint came out of the file and nowhere else, so the expansion has
    // to name it: this is what separates "the demo connected" from "the demo
    // connected TO WHAT THE FILE SAID".
    assert!(
        seen.contains(&format!("tcp/127.0.0.1:{port}")),
        "the demo's own report does not name the endpoint the file carried\n{seen}"
    );
    // R2081 (open-debt item 208) — the report is THREE lines now, and this leg
    // asserts all three because it is the only place the SHIPPING binary's own
    // words are read. The old single `honoured` line said what the reader took
    // and nothing about what this node does with it; a key with no sink here
    // printed under the same word as one that reached a flag, so an operator
    // asking "did my setting take effect" had to diff it against `argv +=`
    // themselves.
    for line in ["READ ", "APPLIED ", "READ BUT NOT APPLIED "] {
        assert!(
            seen.contains(line),
            "the demo's report is missing its `{line}` line\n{seen}"
        );
    }
    // And the split is a real partition, not a relabelling: `timestamping/enabled`
    // has no sink in this binary, so it must appear on the READ-BUT-NOT-APPLIED
    // line and NOT on the APPLIED one. Read off the lines themselves, because a
    // report that printed the same list twice would satisfy the check above.
    let applied_line = seen
        .lines()
        .find(|l| l.contains("APPLIED [") && !l.contains("NOT APPLIED"))
        .unwrap_or_else(|| panic!("no APPLIED line in the demo's report\n{seen}"));
    assert!(
        !applied_line.contains("timestamping/enabled"),
        "a key with no sink in this build was reported as applied\n{applied_line}"
    );
    let not_applied_line = seen
        .lines()
        .find(|l| l.contains("READ BUT NOT APPLIED"))
        .expect("checked above");
    assert!(
        not_applied_line.contains("timestamping/enabled"),
        "the key with no sink is not named as unapplied\n{not_applied_line}"
    );
    // R311y843 — the SHIPPING binary's own account of what the file became.
    // The `argv +=` line is where a dropped key is visibly absent. Asserted here
    // rather than only in the unit test because that test calls the expansion
    // directly, and this is the binary an operator runs, in a process a real
    // zenohd opened a session with.
    for expected in [
        "--batch-size",
        "4096",
        "--lease-ms",
        "3000",
        "--compression",
    ] {
        assert!(
            seen.contains(expected),
            "the demo's expansion report does not carry {expected}, so the \
             file's transport values reached the report and not the argv\n{seen}"
        );
    }

    drop(demo_guard);
    drop(router);
}

/// R311y849 — LEG 5: the schedule the file carried is the schedule the node
/// RUNS.
///
/// The four legs above stop at the boundary: they show that wz reads the same
/// values zenohd does, that every upstream leaf is accounted for, and that a
/// node started from the file alone reaches a real zenohd. None of them shows a
/// honoured value CHANGING what the process does — and `connect/retry` is
/// exactly the key where that gap matters, because a schedule the reader
/// ingests and nothing consumes looks identical, from the config report, to one
/// in force. Measured before the fix: the `--peer` arm accepted
/// `--connect-retry` and dropped it, malformed values included, so the key
/// could have been declared honoured while pacing nothing.
///
/// The witness is the ATTEMPT COUNT in a fixed window, and the control is the
/// same file with the retry block deleted. Two runs of one binary differing in
/// one block: if the count does not move, the file reached nothing, whatever
/// the config report says. Counts rather than inter-arrival gaps, because the
/// gap between two log lines is a scheduler artefact under load while a count
/// over seconds is not.
///
/// No zenohd here, deliberately: the target port has NOTHING on it. A refused
/// dial is the observable, and providing a listener would remove it.
// wz-proves: none -- and for a DIFFERENT reason from the four legs above,
// which is why it is stated rather than pointed at them. Those adjudicate wz
// against a real zenohd and lack only a registered atom name. This leg has no
// foreign adjudicator at all: what it compares is two runs of wz's OWN binary
// differing in one config block, over a port nothing listens on. That is a
// self-differential and a foreign-witness count must not absorb it. Layer A4
// reded on this leg's silence (2026-08-18) rather than on a wrong claim, which
// is the gate working -- an interop corpus test that declares nothing makes the
// proof number quietly optimistic.
#[test]
#[ignore = "binary-dep e2e: needs wz-ap-demo[+zenoh-config,+routing-peer,\
            +router-connect-reconcile]; runs via --ignored"]
// R311y851 — the fn carries `zenohd` because Layer C0's naming obligation is
// about the FILE's family, not about which binaries this one leg happens to
// need. libtest's `--skip` matches the function name, so a leg in a
// zenohd-family file whose name lacks the token is a leg Layer E's default
// sweep RUNS, against whatever binaries that lane built -- and Layer Z, which
// owns this file and expects five, would still be the lane that meant to run
// it. Hosted C0 has been red on this since the leg landed.
fn the_retry_schedule_a_stock_zenohd_config_carries_is_the_one_the_node_runs() {
    let demo = wz_ap_demo_binary();
    // A demo predating this round has no peer-arm parse for the schedule at
    // all, so a stale one reproduces the exact failure this leg detects.
    assert_demo_binary_newer_than_sources(&demo);

    // Both runs dial THIS, and nothing ever listens on it.
    let dead = PortReservation::pick();
    let dead_port = dead.port();
    drop(dead);

    // `period_max_ms` equals `period_init_ms` and the factor is 1, so the
    // schedule is a flat 300ms and the growth arithmetic cannot muddy the
    // comparison.
    let tight = attempts_in_window(
        &demo,
        &format!(
            r#"{{
  mode: "peer",
  listen: {{ endpoints: ["tcp/127.0.0.1:0"] }},
  connect: {{
    endpoints: ["tcp/127.0.0.1:{dead_port}"],
    retry: {{ period_init_ms: 300, period_max_ms: 300, period_increase_factor: 1 }},
  }},
  scouting: {{ multicast: {{ enabled: false }} }},
}}
"#
        ),
    );

    // THE CONTROL — the same file, one block removed. Its cadence is zenoh's
    // own default (1s, then 2s, then 4s), which is what wz ran for every
    // invocation before this round.
    let default_paced = attempts_in_window(
        &demo,
        &format!(
            r#"{{
  mode: "peer",
  listen: {{ endpoints: ["tcp/127.0.0.1:0"] }},
  connect: {{ endpoints: ["tcp/127.0.0.1:{dead_port}"] }},
  scouting: {{ multicast: {{ enabled: false }} }},
}}
"#
        ),
    );

    // Vacuity guard: a run that never dialled at all would satisfy any
    // "fewer than" comparison. Both arms must have actually tried.
    assert!(
        default_paced >= 2,
        "the control never re-dialled ({default_paced} attempt(s)); the leg is \
         measuring a node that did not run, not a schedule"
    );
    // The bound is deliberately loose. Over a 6s window a flat 300ms schedule
    // is ~20 attempts and zenoh's default is 3, so a 3x margin separates them
    // by more than any plausible scheduling jitter while asserting nothing
    // about a number this test does not own.
    assert!(
        tight >= default_paced * 3,
        "the file's 300ms schedule produced {tight} attempt(s) against the \
         control's {default_paced}: the config reached the report and not the \
         re-dial loop"
    );
}

/// Start `wz-ap-demo --config <file>` — the DROP-IN invocation, with no role
/// and no schedule typed — and count the dial attempts it logs in a fixed
/// window.
///
/// The argv is the point. Everything this leg varies arrives through the file,
/// which is what an operator replacing a zenoh node actually has.
fn attempts_in_window(demo: &std::path::Path, source: &str) -> usize {
    const WINDOW: Duration = Duration::from_secs(6);
    // R311y851 — a node has to have STARTED before its cadence exists. Startup
    // on a loaded CI runner is seconds, and a window timed from `spawn` spends
    // them: the control arm came back with ONE attempt on hosted (2026-08-18)
    // against three on the dev box, and the leg's own vacuity guard called that
    // "a node that did not run" — which was exactly right and named the wrong
    // subject. Generous, because this bound is not what the leg measures; it
    // only has to be longer than any plausible start.
    const STARTUP: Duration = Duration::from_secs(30);
    const POLL: Duration = Duration::from_millis(50);
    const FAILED_DIAL: &str = "FAILED (peer";

    let file = staged_config(source);
    let capture = tempfile::tempfile().expect("tempfile for demo output");
    let out = capture.try_clone().expect("dup demo stdout handle");
    let err = capture.try_clone().expect("dup demo stderr handle");
    let mut command = Command::new(demo);
    command
        .arg("--config")
        .arg(file.path())
        .env("RUST_LOG", "info")
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err));
    let guard = ChildGuard::wrap(
        "wz-ap-demo (--config, re-dial cadence)",
        command.spawn().expect("spawn wz-ap-demo"),
    );

    // The window opens on the FIRST dial, so both arms are measured over the
    // same six seconds OF CADENCE rather than over six seconds that begin with
    // however long this host took to link and boot a binary.
    // `read_captured` reads by `pread`, so polling it does not move the offset
    // the child is appending at — the same property the shared-offset test in
    // `common` pins.
    let mut capture = capture;

    // R311y851 — THE THIRD FEATURE GUARD, and it is the one this leg was
    // missing. The demo prints its own feature set at startup, so the build is
    // readable rather than assumed.
    //
    // Measured on 2026-08-18, at this lane's exact feature set: the peer arm
    // dials each configured address ONCE and never again, whatever schedule the
    // file carries, because the loop that re-dials a desired peer lives behind
    // `router-connect-reconcile` (`accept_loop.rs:1645-1659` — with neither that
    // feature nor `transport-multilink` the policy is discarded, and
    // `transport-multilink` alone paces link RE-ADDS rather than a peer that
    // never connected). The admin config still renders zenoh's 1s/4s/2.0, so the
    // node reports a cadence it does not run. Without this guard the leg reads
    // that as one attempt and the vacuity assertion blames "a node that did not
    // run", which is the right complaint about the wrong subject and cost a
    // hosted red to attribute.
    let deadline = std::time::Instant::now() + STARTUP;
    loop {
        let logged = wz_integration_tests::common::read_captured(&mut capture);
        if let Some(line) = logged.lines().find(|l| l.contains("BUILD FEATURES")) {
            assert!(
                line.contains("router-connect-reconcile"),
                "this lane's wz-ap-demo cannot RE-dial at all -- the peer arm's \
                 re-dial loop is behind `router-connect-reconcile` and this build \
                 has: {line}\nRebuild with that feature; a cadence cannot be \
                 measured on a node that dials once."
            );
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the demo printed no BUILD FEATURES line in {}s",
            STARTUP.as_secs()
        );
        std::thread::sleep(POLL);
    }

    let deadline = std::time::Instant::now() + STARTUP;
    let mut waited = Duration::ZERO;
    loop {
        if wz_integration_tests::common::read_captured(&mut capture).contains(FAILED_DIAL) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no dial attempt in {}s; the node never reached its connect list, \
             so there is no cadence here to measure",
            STARTUP.as_secs()
        );
        std::thread::sleep(POLL);
        waited += POLL;
    }
    // Recorded rather than discarded: if this is ever large it is the fact that
    // explains a surprising count, and a number nobody printed cannot do that.
    eprintln!("first dial after ~{}ms of startup", waited.as_millis());

    std::thread::sleep(WINDOW);
    drop(guard);

    let logged = wz_integration_tests::common::read_captured(&mut capture);
    // PANIC rather than return 0: a build without either feature would
    // otherwise read as "this schedule never re-dialled", which is the same
    // number a broken schedule produces.
    assert!(
        !logged.contains("--config requires the `zenoh-config` feature"),
        "this lane's wz-ap-demo was built without the feature under test; \
         rebuild with `cargo build -p wz-ap-demo --features zenoh-config`"
    );
    assert!(
        !logged.contains("--peer requires the `routing-peer` feature"),
        "this lane's wz-ap-demo cannot run the peer arm; rebuild with \
         `cargo build -p wz-ap-demo --features routing-peer`"
    );
    logged.matches(FAILED_DIAL).count()
}

// wz-proves: none -- same registration gap as the legs above.
/// R2091b (open-debt item 511) — LEG 11: THE ENDPOINT A NODE BINDS WHEN ITS
/// DOCUMENT NAMES NONE, adjudicated by the implementation that would bind it.
///
/// wz's `--config` expansion materialises [`default_listen_endpoint`] for a
/// document that names no `listen/endpoints`, which is what makes a stock
/// `{ mode: "router", connect: [..] }` come up as a ROUTER instead of as a
/// client. That constant is an UPSTREAM fact, and a constant quoted out of a
/// checkout is a fact about a file somebody read once; a running zenohd
/// resolving the same document is the fact itself.
///
/// ## Why the RESOLVED CONFIG and not the listener
///
/// A router's default is port 7447 — a real, fixed port. A leg that proved this
/// by reading `Zenoh can be reached at:` would bind it, and would then fail on
/// any machine where something else already had it: an upstream-agreement claim
/// turned into a port-availability claim, which is the class this very file paid
/// for one round ago. zenohd renders the WHOLE mode table into its
/// `Initial conf:` line whatever mode it is in (measured, both ways), so the
/// answer is there without a socket.
///
/// ## The client row is an ABSENCE, and it is the sharp one
///
/// Upstream's table has `router` and `peer` entries and no `client` entry, and
/// that absence is the instruction: a zenoh client never listens. wz encodes it
/// as `None`, and the pairing is asserted in both directions here — a table that
/// grew a `client` row, or a wz that started returning an address for one, is
/// the same divergence seen from either end.
///
/// R2095 — the name carries `zenohd` because this FILE's basename declares that
/// family and Layer C0's skip-token obligation matches on the FUNCTION name.
/// R2092 landed it as `the_endpoint_a_node_binds_when_its_document_names_none_is_upstreams_own`,
/// which reads well and is invisible to `--skip zenohd`: Layer E's default sweep
/// would RUN a leg that needs a zenohd it does not build. Paid here rather than
/// carried, because it is the same file this round rewrites and it is what stops
/// Layer C0 from reaching any gate behind it.
#[test]
#[ignore = "binary-dep e2e: needs target/zenohd/zenohd (scripts/build-zenohd.sh)"]
fn zenohd_and_wz_agree_on_the_endpoint_a_node_binds_when_its_document_names_none() {
    // Names NO listen key at all, which is the whole precondition: a document
    // that named one — an empty list included — would suppress the default on
    // both sides, and this leg would be measuring nothing.
    let source = String::from(
        r#"{ mode: "peer",
             connect: { endpoints: ["tcp/127.0.0.1:1"] },
             scouting: { multicast: { enabled: false } } }"#,
    );
    let ingest = ZenohNodeConfig::from_json5(&source)
        .unwrap_or_else(|e| panic!("wz cannot read the fixture: {e}\n{source}"));
    assert!(
        !ingest.named.contains(&"listen/endpoints"),
        "the fixture names the key, so nothing here reaches a default: {:?}",
        ingest.named
    );

    let file = staged_config(&source);
    let (guard, mut capture) = spawn_on_config("zenohd (no listen key)", file.path());
    let captured = wait_for_substring(&mut capture, RESOLVED_CONF_MARKER, STARTUP_BUDGET)
        .unwrap_or_else(|e| panic!("zenohd never printed its resolved config: {e}\n{source}"));
    let resolved = resolved_config_of(&captured);

    // `Json5Value::Object` is an ordered Vec of pairs, not a map — the reader
    // keeps document order on purpose — so a field is a search.
    fn field<'a>(fields: &'a [(String, Json5Value)], name: &str) -> Option<&'a Json5Value> {
        fields.iter().find(|(k, _)| k == name).map(|(_, v)| v)
    }

    let Json5Value::Object(root) = &resolved else {
        panic!("zenohd's resolved config is not an object");
    };
    let Some(Json5Value::Object(listen)) = field(root, "listen") else {
        panic!("zenohd's resolved config carries no `listen` object\n{captured}");
    };
    let Some(Json5Value::Object(table)) = field(listen, "endpoints") else {
        panic!(
            "zenohd resolved `listen.endpoints` to something other than the mode \
             table this leg reads: {:?}",
            field(listen, "endpoints")
        );
    };

    for (mode, row) in [(WhatAmI::Router, "router"), (WhatAmI::Peer, "peer")] {
        let Some(Json5Value::Array(items)) = field(table, row) else {
            panic!("upstream's default table has no `{row}` row: {table:?}");
        };
        let Some(Json5Value::String(upstream)) = items.first() else {
            panic!("upstream's `{row}` default is not an endpoint string: {items:?}");
        };
        assert_eq!(
            default_listen_endpoint(mode).map(String::from),
            Some(upstream.clone()),
            "wz binds a different address than a stock {row} does when the \
             document names none"
        );
    }

    // The absence, both ways.
    assert!(
        field(table, "client").is_none(),
        "upstream's default table grew a `client` row, so \"a zenoh client never \
         listens\" is no longer what its absence says: {table:?}"
    );
    assert_eq!(
        default_listen_endpoint(WhatAmI::Client),
        None,
        "wz would bind an address for a client that upstream never gives one"
    );

    drop(guard);
}

/// Upstream's own statement of what an omitted key resolves to, installed
/// beside the binary it was built from (`scripts/build-zenohd.sh`).
///
/// R2109 (open-debt item 514) — DERIVED from the zenohd path rather than read
/// off a machine-local checkout path, for the reason the register's own
/// pointers keep going stale: a path written down once is a fact about the
/// machine that wrote it. The document travels with the oracle provisioning, so
/// a tree that has a zenohd built from SOURCE has it and one that took the
/// crates.io path has neither -- the same split the storage-manager cdylib and
/// the example oracles already have (the published crates carry no copy of it;
/// it lives at the repo root).
fn upstream_default_config_document() -> String {
    let zenohd = zenohd_binary();
    let path = zenohd
        .parent()
        .unwrap_or_else(|| panic!("zenohd at {} has no parent dir", zenohd.display()))
        .join("DEFAULT_CONFIG.json5");
    // PANIC, never a fallback: an expectation that reverts to a constant when
    // its oracle is missing is not an expectation, it IS the constant. A run
    // that cannot reach upstream's document has to say so.
    std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "upstream's DEFAULT_CONFIG.json5 is not at {} ({e}); it is installed \
             beside zenohd by `scripts/build-zenohd.sh` from a SOURCE tree -- \
             re-provision with ZENOHD_ALLOW_CLONE=1, or point ZENOHD_SRC at a \
             zenoh checkout",
            path.display()
        )
    })
}

/// The role a TOP-LEVEL `mode` names in an upstream document, or `None` when
/// the document states none.
///
/// Parsed, never matched. `DEFAULT_CONFIG.json5` carries four uncommented
/// `mode:` keys -- the top-level one plus `routing.peer.mode` and two
/// `shm`/`tls` `mode: "lazy"` -- and zenohd's own resolved config carries
/// three, so a pattern over either text answers a different question than this
/// does. R2083 paid for exactly that shape once, counting quoted words inside a
/// comment as keys.
fn top_level_mode_of(document: &str) -> Option<WhatAmI> {
    let Json5Value::Object(root) = json5::parse(document)
        .unwrap_or_else(|e| panic!("wz cannot read upstream's own reference document: {e}"))
    else {
        panic!("upstream's reference document is not an object");
    };
    let (_, value) = root.iter().find(|(k, _)| k == "mode")?;
    let Json5Value::String(name) = value else {
        panic!("upstream's top-level `mode` is not a string: {value:?}");
    };
    Some(
        [WhatAmI::Router, WhatAmI::Peer, WhatAmI::Client]
            .into_iter()
            .find(|w| w.to_str() == name)
            .unwrap_or_else(|| panic!("upstream's top-level `mode` is {name:?}")),
    )
}

// wz-proves: none -- same registration gap as the legs above.
/// R2109 (open-debt item 514) — LEG 12: WHAT A DOCUMENT THAT NAMES NO `mode`
/// MEANS, asked of BOTH upstream readers that read it.
///
/// The other eleven legs here grade a value the operator WROTE. This one grades
/// a SILENCE, and `mode` is the only key whose silence upstream resolves two
/// different ways:
///
/// * the zenoh LIBRARY resolves an absent `mode` through `zenoh-config`'s
///   `defaults::mode`, which `DEFAULT_CONFIG.json5` states as the uncommented
///   `mode: "peer"` near the top of the file. That document is the oracle for
///   this half, DERIVED here rather than transcribed;
/// * `zenohd` overwrites the absence with `WhatAmI::Router` before it builds a
///   runtime. That half is measured by handing a real zenohd the SAME bytes and
///   reading the mode out of its own resolved config -- LEG 11's argument, for
///   LEG 11's reason: a constant quoted out of a checkout is a fact about a
///   file somebody read once.
///
/// So a mode-less file deploys a ROUTER on zenohd and a PEER here, and until
/// this round nothing measured that and nothing said it. wz KEEPS the library
/// reading -- `wz-ap-demo` is a library node, which is what R2092 settled --
/// and what this leg pins is that the reading is upstream's, that the daemon's
/// is the other one, and that the shipping binary says both out loud.
///
/// ## Why the whole chain is ONE leg
///
/// Four assertions that could be four tests, and splitting them would dissolve
/// the claim: "wz reads it as peer" is true of a wz that hardcoded peer,
/// "upstream says peer" is true of a document nobody consulted, "a real zenohd
/// says router" is true of a divergence nobody reports, and "the report has a
/// line" is true of a line that names the wrong roles. The finding is the
/// CONJUNCTION, and one fixture string handed to all three implementations is
/// what makes it one.
///
/// The name carries `zenohd` because Layer C0's skip-token obligation matches
/// on the FUNCTION name and Layer E's default sweep provisions no router.
#[test]
#[ignore = "binary-dep e2e: needs target/zenohd/zenohd + its DEFAULT_CONFIG.json5 (scripts/build-zenohd.sh)"]
fn zenohd_reads_an_unstated_mode_as_router_where_wz_takes_the_library_default() {
    // (1) THE UPSTREAM DERIVATION. There is no literal `peer` on this side of
    // the comparison: a document stating no top-level `mode` FAILS here rather
    // than yielding one, which is what stops this leg from grading a constant
    // against itself.
    let reference = upstream_default_config_document();
    let library_default = top_level_mode_of(&reference).unwrap_or_else(|| {
        panic!(
            "upstream's DEFAULT_CONFIG.json5 states no top-level `mode`, so this \
             leg has no derived expectation to grade wz against"
        )
    });
    assert_eq!(
        LIBRARY_DEFAULT_MODE,
        library_default,
        "wz reads a document's silence about `mode` as `{}` while upstream's own \
         reference document gives an unset `mode` as `{}`",
        LIBRARY_DEFAULT_MODE.to_str(),
        library_default.to_str()
    );

    // (2) WZ, on a document that names no `mode` at all. The endpoint is there
    // so the file describes a deployable node rather than an empty object;
    // nothing in it speaks to the run-mode.
    let source = String::from(
        r#"{ listen: { endpoints: ["tcp/127.0.0.1:0"] },
             scouting: { multicast: { enabled: false } } }"#,
    );
    let ingest = ZenohNodeConfig::from_json5(&source)
        .unwrap_or_else(|e| panic!("wz cannot read the fixture: {e}\n{source}"));
    assert!(
        !ingest.named.contains(&"mode"),
        "the fixture names the key, so there is no silence here to grade: {:?}",
        ingest.named
    );
    assert_eq!(
        ingest.config.mode, library_default,
        "wz came up in a run-mode upstream's own document does not give an unset \
         `mode`"
    );
    let unstated = ingest
        .mode_left_unstated()
        .expect("a document that names no `mode` left it unstated");
    assert_eq!(unstated.read_as, library_default);

    // (3) THE DAEMON, on the SAME bytes. Read out of zenohd's resolved config
    // rather than off its wire role, for LEG 11's reason: a router's default is
    // port 7447, and proving the role by connecting would turn an
    // upstream-agreement claim into a port-availability one.
    let file = staged_config(&source);
    let (guard, mut capture) = spawn_on_config("zenohd (no mode key)", file.path());
    let captured = wait_for_substring(&mut capture, RESOLVED_CONF_MARKER, STARTUP_BUDGET)
        .unwrap_or_else(|e| panic!("zenohd never printed its resolved config: {e}\n{source}"));
    let resolved = resolved_config_of(&captured);
    let Json5Value::Object(root) = &resolved else {
        panic!("zenohd's resolved config is not an object");
    };
    let (_, daemon_value) = root
        .iter()
        .find(|(k, _)| k == "mode")
        .unwrap_or_else(|| panic!("zenohd resolved no top-level `mode` at all\n{captured}"));
    let Json5Value::String(daemon_mode) = daemon_value else {
        panic!("zenohd resolved `mode` to something that is not a role: {daemon_value:?}");
    };
    let daemon_mode = daemon_mode.clone();
    drop(guard);
    assert_eq!(
        daemon_mode.as_str(),
        DAEMON_DEFAULT_MODE.to_str(),
        "a real zenohd resolved this mode-less document to a role other than the \
         one `DAEMON_DEFAULT_MODE` tells operators it takes"
    );
    // THE DIVERGENCE ITSELF, asserted rather than assumed. Were upstream ever to
    // make the two readings agree, every line this round added would be telling
    // operators about a difference that no longer exists -- and BOTH assertions
    // above would still pass.
    assert_ne!(
        daemon_mode.as_str(),
        library_default.to_str(),
        "the daemon and the library now read a silent `mode` the same way, so \
         item 514's divergence is gone and the report should stop claiming it"
    );

    // (4) AND THE SHIPPING BINARY SAYS SO. The verdict above lives in a library
    // this leg links; what an operator gets is what `main` prints, and the two
    // are only the same while something reads them together.
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let demo_capture = tempfile::tempfile().expect("tempfile for demo output");
    let out = demo_capture.try_clone().expect("dup demo stdout handle");
    let err = demo_capture.try_clone().expect("dup demo stderr handle");
    let mut command = Command::new(&demo);
    command
        .arg("--config")
        .arg(file.path())
        .env("RUST_LOG", "info")
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err));
    // Spawned and dropped, never waited on: this node binds and stays up, so a
    // witness that waited for it to exit would hang. The whole config report is
    // written BEFORE any run-mode dispatch, which is what makes reading it here
    // safe whatever this build can or cannot run.
    let demo_guard = ChildGuard::wrap(
        "wz-ap-demo (--config, unstated mode)",
        command.spawn().expect("spawn wz-ap-demo"),
    );
    let mut demo_capture = demo_capture;
    let seen = wait_for_substring(&mut demo_capture, "MODE UNSTATED", DEMO_BUDGET);
    if let Err(e) = &seen {
        let so_far = wz_integration_tests::common::read_captured(&mut demo_capture);
        // PANIC, never skip: a build without the feature must fail the lane
        // rather than pass it quietly.
        assert!(
            !so_far.contains("--config requires the `zenoh-config` feature"),
            "this lane's wz-ap-demo was built without the feature under test; \
             rebuild with `cargo build -p wz-ap-demo --features zenoh-config`"
        );
        panic!("the demo's report never named the mode it was not given: {e}\n{so_far}");
    }
    let seen = seen.expect("checked above");
    drop(demo_guard);
    let line = seen
        .lines()
        .find(|l| l.contains("MODE UNSTATED"))
        .expect("checked above");
    // BOTH roles on the one line. Naming only wz's own would report this node's
    // behaviour, which the `argv +=` line already carries; the fact an operator
    // migrating off a daemon needs is the OTHER reading.
    for role in [library_default.to_str(), daemon_mode.as_str()] {
        assert!(
            line.contains(role),
            "the operator's line does not name `{role}`\n{line}"
        );
    }
    // And the run-mode it actually selected is the library reading, so the line
    // and the argv cannot disagree.
    let expected_flag = match library_default {
        WhatAmI::Router => "--router-hat",
        WhatAmI::Peer => "--peer",
        WhatAmI::Client => "--connect",
    };
    assert!(
        seen.contains(&format!("argv += [\"{expected_flag}\"")),
        "the expansion selected a run-mode other than the one its own report \
         names\n{seen}"
    );
}
