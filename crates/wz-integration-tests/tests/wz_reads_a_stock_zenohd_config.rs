// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

use tempfile::NamedTempFile;

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, wait_for_substring, wz_ap_demo_binary, zenohd_binary,
    ChildGuard, PortReservation,
};
use wz_runtime_tokio::zenoh_config::{
    ZenohNodeConfig, HONOURED_CONFIG_KEYS, UNHONOURED_UPSTREAM_CONFIG_KEYS,
};
use wz_session_core::json5::{self, Json5Value};

/// zenohd prints its resolved config on this line before doing anything else.
const RESOLVED_CONF_MARKER: &str = "Initial conf:";

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
            true,
            "invalid type: map, expected a boolean",
        ),
        (
            "unhonoured leaf, deepened (auth)",
            r#"transport: { auth: { usrpwd: { user: { xyz: 1 } } } }"#,
            false,
            true,
            "invalid type: map, expected a string",
        ),
    ];

    /// The rows where the two implementations DISAGREE, by label. Pinned as a
    /// SET: closing one without shrinking this list fails, and opening a new one
    /// fails too.
    const DIVERGES: &[&str] = &[
        "unhonoured leaf, deepened",
        "unhonoured leaf, deepened (auth)",
    ];

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
    assert!(
        BOUNDARY.iter().any(|(_, _, z, w, _)| z == w) && !DIVERGES.is_empty(),
        "the table must carry both agreements and divergences"
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
        let source = format!(
            r#"{{
  mode: "peer",
  listen: {{ endpoints: ["tcp/127.0.0.1:{port}"] }},
  scouting: {{ multicast: {{ enabled: false }} }},
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
    assert!(
        seen.contains("honoured"),
        "the demo did not report what it took from the file\n{seen}"
    );
    // R311y843 — the SHIPPING binary's own account of what the file became.
    // A key the reader ingests and the demo then drops still prints under
    // `honoured`, which is the defect this round removed; the `argv +=` line is
    // where a dropped key is visibly absent. Asserted here rather than only in
    // the unit test because that test calls the expansion directly, and this is
    // the binary an operator runs, in a process a real zenohd opened a session
    // with.
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
