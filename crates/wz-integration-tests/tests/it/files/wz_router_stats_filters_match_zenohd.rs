// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `stats/filters` — one config document handed to a zenohd built with zenoh's
//! `stats` feature and to a wz router-hat, the same payloads put to each, and
//! the per-key payload family each router's metrics leg serves compared.
//!
//! # What upstream does with the key
//!
//! The router's tables build a key tree from the filter list
//! (`zenoh/src/net/routing/dispatcher/tables.rs` @ `config.stats.filters().iter().map(|f| &*f.key),`),
//! and every payload a face receives is counted again under each filter its key
//! expression intersects (`commons/zenoh-stats/src/keys.rs` @ `.intersecting_nodes(keyexpr)`),
//! observed before routing, so a payload no subscriber asked for is counted too
//! (`zenoh/src/net/routing/dispatcher/pubsub.rs` @ `payload_observer.observe_payload(zenoh_stats::Rx, src_face, msg);`).
//! The counts are served on `@/<zid>/router/metrics` as the histogram family
//! `<dir>_network_message_payload_per_key`, one series per filter that holds a
//! count, labelled with the filter's own text
//! (`commons/zenoh-stats/src/keys.rs` @ `.encode_family(&(LabelsSetRef(labels), &[("key", key)] as &[_]))?`).
//! A filter nothing met writes no series, and a payload under no filter is
//! counted in the plain payload family only. All of it exists only under
//! `stats`: without it the metrics leg serves the build-info document
//! (`zenoh/src/net/runtime/adminspace.rs` @ `#[cfg(not(feature = "stats"))]`),
//! which is why the stock oracle cannot be the control and the stats build is.
//!
//! # The observable, and why it is normalised
//!
//! Each router is asked with `compression=false` (upstream gzips the document
//! by default: `zenoh/src/net/runtime/adminspace.rs` @ `if query.parameters().get("compression") != Some("false") {`),
//! with the per-transport and per-link partitions off and without descriptors.
//! The two documents are not compared byte for byte, and cannot be:
//!
//! - upstream writes its series in hash-map order and wz in sorted order, and
//!   the place of `le` among a bucket's labels is the encoder's;
//! - every family other than the per-key one counts each router's own traffic,
//!   and the two routers do not carry the same traffic (zenohd's readiness probe,
//!   each router's own admin replies);
//! - the payload byte sums are a claim about payload size, which is not this
//!   key's subject.
//!
//! What IS compared is every `_count` sample of the per-key family, read as its
//! metric name, its whole label set (the zid included, which the document pins
//! for both) and its value. That is the per-key family as a reader of the
//! metrics sees it: which filters appear, under which labels, counting what.
//!
//! # The control comes first
//!
//! The filters are `demo/a/**`, `demo/*/x` and `demo/none/**`, and the puts land
//! on `demo/a/x` (two filters), `demo/a/y` and `demo/b/x` (one each) and
//! `other/y` (none). Upstream must count two puts under each of the first two
//! filters, received, and write no series for the third: that is asserted on
//! zenohd's document before wz's is read, so a control that counts nothing, or
//! counts every put under every filter, stops the test before wz is judged.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write as _;
use std::process::{Command, Stdio};
use std::time::Duration;

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, read_captured, spawn_on_ephemeral_port,
    spawn_zenohd_dialer_on_ephemeral_tcp, wait_for_capture_alive, wait_for_substring,
    wait_for_zenohd_handshake_ready, wz_ap_demo_binary, wz_e2e_admin_probe_binary,
    zenohd_stats_binary, ChildGuard,
};

/// The zid the document gives both routers, as zenoh prints it, so the admin
/// root of each is known before it starts.
const ZID: &str = "a1b2c3d4";

/// The document both routers are started on. The router role and the listen
/// endpoint select wz's router-hat run-mode; zenohd is a router whatever the
/// file says.
const DOCUMENT: &str = r#"{
  mode: "router",
  id: "a1b2c3d4",
  listen: { endpoints: ["tcp/127.0.0.1:0"] },
  scouting: { multicast: { enabled: false } },
  stats: {
    filters: [
      { key: "demo/a/**" },
      { key: "demo/*/x" },
      { key: "demo/none/**" },
    ],
  },
}
"#;

/// The keys the probe puts under, in order: one met by two filters, two met by
/// one filter each, and one met by none.
const PUTS: [&str; 4] = ["demo/a/x", "demo/a/y", "demo/b/x", "other/y"];

/// What upstream must count, per (direction, message, filter): the control.
const EXPECTED: [(&str, &str, &str, u64); 2] =
    [("rx", "put", "demo/*/x", 2), ("rx", "put", "demo/a/**", 2)];

/// The metrics GET's parameters, as both routers read them.
const METRICS_PARAMETERS: &str =
    "compression=false;per_transport=false;per_link=false;descriptors=false";

/// The line wz's router-hat prints once bound, and the one it prints once its
/// admin legs are hosted.
const LISTEN_MARKER: &str = "router-hat: listening on 127.0.0.1:";
const ADMIN_MARKER: &str = "adminspace router legs hosted at ";

/// How long the probe's whole script may take; the probe bounds each step
/// itself and logs it, so a timeout here is a process that never finished.
const SCRIPT_TIMEOUT: Duration = Duration::from_secs(30);

/// The two per-key families, one per direction.
const PER_KEY_FAMILIES: [(&str, &str); 2] = [
    ("rx", "zenoh_rx_network_message_payload_per_key"),
    ("tx", "zenoh_tx_network_message_payload_per_key"),
];

/// One sample line of an OpenMetrics document.
#[derive(Debug)]
struct Sample {
    name: String,
    labels: BTreeMap<String, String>,
    value: f64,
}

/// `name{label="value",...} value`, label values unescaped. `None` for any
/// other shape, which the caller turns into a failure for a line it expected
/// to read.
fn parse_sample(line: &str) -> Option<Sample> {
    let open = line.find('{')?;
    let name = line[..open].to_string();
    let mut labels = BTreeMap::new();
    let mut rest = &line[open + 1..];
    loop {
        if let Some(after) = rest.strip_prefix('}') {
            rest = after;
            break;
        }
        let eq = rest.find("=\"")?;
        let label = rest[..eq].to_string();
        let quoted = &rest[eq + 2..];
        let mut value = String::new();
        let mut chars = quoted.char_indices();
        let end = loop {
            let (at, c) = chars.next()?;
            match c {
                '\\' => {
                    let (_, escaped) = chars.next()?;
                    value.push(if escaped == 'n' { '\n' } else { escaped });
                }
                '"' => break at + 1,
                other => value.push(other),
            }
        };
        labels.insert(label, value);
        rest = &quoted[end..];
        rest = rest.strip_prefix(',').unwrap_or(rest);
    }
    let value = rest.split_whitespace().next()?.parse::<f64>().ok()?;
    Some(Sample {
        name,
        labels,
        value,
    })
}

/// A per-key `_count` series: its metric name and its whole label set.
type Series = (String, BTreeMap<String, String>);

/// Every `_count` sample of the two per-key families in `body`, by series. A
/// line of those families that does not read as a sample fails here rather
/// than being dropped from the comparison.
fn per_key_counts(body: &[String]) -> BTreeMap<Series, u64> {
    let mut out = BTreeMap::new();
    for line in body {
        let in_family = PER_KEY_FAMILIES
            .iter()
            .any(|(_, family)| line.starts_with(family));
        if !in_family {
            continue;
        }
        let sample =
            parse_sample(line).unwrap_or_else(|| panic!("a per-key line does not parse: {line}"));
        if !sample.name.ends_with("_count")
            || sample.name.contains("_per_transport")
            || sample.name.contains("_per_link")
        {
            continue;
        }
        let previous = out.insert((sample.name, sample.labels), sample.value as u64);
        assert!(
            previous.is_none(),
            "a per-key series is written twice: {line}"
        );
    }
    out
}

/// `counts` reduced to (direction, message, filter) -> count.
fn by_filter(counts: &BTreeMap<Series, u64>) -> BTreeMap<(String, String, String), u64> {
    counts
        .iter()
        .map(|((name, labels), count)| {
            let direction = PER_KEY_FAMILIES
                .iter()
                .find(|(_, family)| name.starts_with(family))
                .map(|(direction, _)| direction.to_string())
                .unwrap_or_default();
            let label = |which: &str| labels.get(which).cloned().unwrap_or_default();
            ((direction, label("message"), label("key")), *count)
        })
        .collect()
}

/// The admin probe against the router at `port`: every put of [`PUTS`], then
/// one GET of `root`'s metrics, on one session. Returns the GET's body lines,
/// or panics with the probe's log and the host's, when the caller holds it.
fn puts_then_metrics(port: u16, root: &str, host_log: Option<&mut File>) -> Vec<String> {
    let selector = format!("{root}/metrics?{METRICS_PARAMETERS}");
    let mut args = vec![String::from("--connect"), format!("127.0.0.1:{port}")];
    for key in PUTS {
        args.push(String::from("--put"));
        args.push(format!("{key}=1"));
    }
    args.push(String::from("--get"));
    args.push(selector.clone());
    let steps = PUTS.len() + 1;

    let stderr = tempfile::tempfile().expect("tempfile for the probe's stderr");
    let writer = stderr.try_clone().expect("dup the probe's stderr handle");
    let mut reader = stderr;
    let mut probe = ChildGuard::wrap(
        "wz-e2e-admin-probe (puts, then one metrics GET)",
        Command::new(wz_e2e_admin_probe_binary())
            .args(args)
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(writer))
            .spawn()
            .expect("spawn wz-e2e-admin-probe"),
    );
    let out = match wait_for_substring(
        &mut reader,
        &format!("SCRIPT COMPLETE steps={steps}"),
        SCRIPT_TIMEOUT,
    ) {
        Ok(c) => c,
        Err(c) => {
            let host =
                host_log.map_or_else(|| String::from("(held by the spawn helper)"), read_captured);
            let _ = probe.child_mut().kill();
            let _ = probe.child_mut().wait();
            panic!("the probe never finished\n--- probe ---\n{c}\n--- host ---\n{host}");
        }
    };
    let _ = probe.child_mut().kill();
    let _ = probe.child_mut().wait();
    assert!(
        out.contains(&format!("STEP {steps} GET '{selector}' FINAL replies=1")),
        "the metrics GET is answered once\n--- probe ---\n{out}"
    );
    let marker = format!("STEP {steps} BODY #1 ");
    out.lines()
        .filter_map(|l| {
            l.split_once(marker.as_str())
                .map(|(_, rest)| rest.to_string())
        })
        .collect()
}

/// The document written where both routers can read it; the readers dispatch
/// on the `.json5` suffix.
fn staged_document() -> tempfile::NamedTempFile {
    let mut file = tempfile::Builder::new()
        .suffix(".json5")
        .tempfile()
        .expect("config tempfile");
    file.write_all(DOCUMENT.as_bytes()).expect("write config");
    file.flush().expect("flush config");
    file
}

/// The upstream side: the stats-built zenohd on the document, its per-key
/// counts after the puts.
fn zenohd_counts(config: &str) -> BTreeMap<Series, u64> {
    let (mut router, port) = spawn_zenohd_dialer_on_ephemeral_tcp(
        &zenohd_stats_binary(),
        "zenohd built with stats (the upstream control)",
        None,
        &[],
        Some(config),
    );
    wait_for_zenohd_handshake_ready(&format!("127.0.0.1:{port}"), || {
        tempfile::tempfile().expect("tempfile for the readiness probe's stderr")
    });
    let body = puts_then_metrics(port, &format!("@/{ZID}/router"), None);
    let _ = router.child_mut().kill();
    let _ = router.child_mut().wait();
    assert!(
        body.iter()
            .any(|l| l.starts_with("zenoh_transports_opened{")),
        "the oracle answered without a stats registry, so it was built without \
         zenoh's `stats` feature:\n{}",
        body.join("\n")
    );
    per_key_counts(&body)
}

/// The wz side: a router-hat started on the document alone, its per-key counts
/// after the same puts.
fn wz_counts(config: &str) -> BTreeMap<Series, u64> {
    let demo = wz_ap_demo_binary();
    let (mut router, mut log, port) = spawn_on_ephemeral_port(
        &demo,
        &["--config", config],
        LISTEN_MARKER,
        "wz-ap-demo router-hat (started on the same document)",
        tempfile::tempfile().expect("tempfile for the router's stderr"),
    );
    let root = wait_for_capture_alive(
        router.child_mut(),
        &mut log,
        Duration::from_secs(10),
        "hosting its admin legs",
        |captured| {
            captured
                .lines()
                .find_map(|l| l.split_once(ADMIN_MARKER))
                .and_then(|(_, rest)| rest.split_whitespace().next())
                .and_then(|k| k.strip_suffix("/**"))
                .map(str::to_string)
        },
    )
    .unwrap_or_else(|e| panic!("the router-hat never hosted its admin legs: {e}"));
    let body = puts_then_metrics(port, &root, Some(&mut log));
    let _ = router.child_mut().kill();
    let _ = router.child_mut().wait();
    per_key_counts(&body)
}

// wz-proves: none -- the per-key payload family is a counter the router keeps, and `transport-stats` is excluded from the cross-impl denominator as foreign-unobservable
#[test]
#[ignore = "binary-dep e2e (zenohd built with stats + wz-ap-demo --features adminspace-router-linkstate,adminspace-metrics,wz/transport-stats,zenoh-config + wz-e2e-admin-probe); Layer Z runs via --ignored"]
fn a_router_counts_payloads_under_the_stats_filters_they_meet_as_zenohd_does() {
    // The reader first, on lines whose answer is written here: a reader that
    // returned nothing would make both sides equal and empty.
    let read = parse_sample(
        r#"zenoh_rx_network_message_payload_per_key_bytes_count{local_id="a1",key="demo/*/x",message="put"} 2"#,
    )
    .expect("a count line reads");
    assert_eq!(read.labels.get("key").map(String::as_str), Some("demo/*/x"));
    assert_eq!(read.value as u64, 2);
    let escaped =
        parse_sample(r#"m_bucket{le="1.0",key="a\"b,c"} 3"#).expect("a bucket line reads");
    assert_eq!(
        escaped.labels.get("key").map(String::as_str),
        Some("a\"b,c")
    );
    assert_eq!(escaped.labels.get("le").map(String::as_str), Some("1.0"));
    assert!(parse_sample("# EOF").is_none());

    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let document = staged_document();
    let config = document
        .path()
        .to_str()
        .expect("the config path is UTF-8")
        .to_string();

    // The positive control: upstream counts each put under the filters it
    // meets, received, and writes no series for the filter nothing met.
    let upstream = zenohd_counts(&config);
    let expected: BTreeMap<(String, String, String), u64> = EXPECTED
        .iter()
        .map(|(direction, message, key, count)| {
            (
                (direction.to_string(), message.to_string(), key.to_string()),
                *count,
            )
        })
        .collect();
    assert_eq!(
        by_filter(&upstream),
        expected,
        "the stats-built zenohd does not count the puts under the filters they \
         meet, so it cannot be the control:\n{upstream:#?}"
    );

    // wz on the same document and the same puts: the same series, each with the
    // same labels and the same count.
    let wz = wz_counts(&config);
    assert_eq!(
        wz, upstream,
        "wz's per-key payload family differs from zenohd's for the same document \
         and the same puts"
    );
}
