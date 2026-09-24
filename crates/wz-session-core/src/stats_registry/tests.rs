// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

use super::*;
use alloc::string::ToString as _;

/// What the pinned `zenoh-stats` wrote for the event sequences in
/// `oracles/zenoh-stats-golden`, each block's samples sorted.
const GOLDEN: &str = include_str!("zenoh_1_10_1.golden");

/// One scenario of the golden: its title line and its document.
fn golden_scenarios() -> Vec<(&'static str, &'static str)> {
    let mut out = Vec::new();
    let mut rest = GOLDEN;
    while let Some(start) = rest.find("===== S") {
        let after = &rest[start + "===== ".len()..];
        let title_end = after.find('\n').expect("a scenario title ends its line");
        let title = &after[..title_end];
        let body_start = title_end + 1;
        let body_len = after[body_start..]
            .find("===== END\n")
            .expect("every scenario is closed by an END line");
        out.push((title, &after[body_start..body_start + body_len]));
        rest = &after[body_start + body_len..];
    }
    out
}

/// The same canonical form `zenoh_stats_golden.py` stores: every `#` line in
/// place, the sample lines between two of them sorted.
fn normalise(doc: &str) -> String {
    let mut out = String::new();
    let mut samples: Vec<&str> = Vec::new();
    let flush = |samples: &mut Vec<&str>, out: &mut String| {
        samples.sort_unstable();
        for line in samples.drain(..) {
            out.push_str(line);
            out.push('\n');
        }
    };
    for line in doc.lines() {
        if line.starts_with('#') {
            flush(&mut samples, &mut out);
            out.push_str(line);
            out.push('\n');
        } else {
            samples.push(line);
        }
    }
    flush(&mut samples, &mut out);
    out
}

/// The pin's per-key histograms close with `le="18446744073709553000.0"`
/// where every other histogram closes with `le="+Inf"`.
const PIN_PER_KEY_TOP_BUCKET: &str = "le=\"18446744073709553000.0\"";

/// Apply the ONE named divergence to a pin document and say how many lines it
/// touched.
///
/// Upstream's per-key histogram stores its top bound as `u64::MAX` and hands
/// `u64::MAX as f64` to the encoder
/// (`commons/zenoh-stats/src/keys.rs` @ `buckets.iter().map(|(b, c)| (*b as f64, *c)).collect(),`),
/// while the encoder writes `+Inf` only for `f64::MAX` — which the plain
/// histogram maps its top bound to deliberately
/// (`commons/zenoh-stats/src/histogram.rs` @ `fn bound_to_f64(b: u64) -> f64 {`)
/// and the per-key one does not. So the pin's per-key histograms have no `+Inf` bucket, which
/// OpenMetrics requires of every histogram. wz writes `+Inf`, as the plain
/// histogram does — the same stance R2414 took on the pin's stray byte after
/// `# EOF`: a defect that makes the document invalid is not fidelity.
fn apply_named_divergences(pin: &str) -> (String, usize) {
    let mut touched = 0;
    let mut out = String::new();
    for line in pin.lines() {
        if line.contains("_per_key_") && line.contains(PIN_PER_KEY_TOP_BUCKET) {
            out.push_str(&line.replace(PIN_PER_KEY_TOP_BUCKET, "le=\"+Inf\""));
            touched += 1;
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    (normalise(&out), touched)
}

/// The query a scenario title names, read by the same `key=value` words the
/// generator prints.
fn query_of(title: &str) -> MetricsQuery {
    let flag = |key: &str| -> bool {
        let needle = alloc::format!("{key}=");
        let at = title.find(&needle).expect("the title names every flag");
        title[at + needle.len()..].starts_with("true")
    };
    MetricsQuery {
        per_transport: flag("per_transport"),
        per_link: flag("per_link"),
        disconnected: flag("disconnected"),
        per_key: flag("per_key"),
    }
}

fn tcp_link() -> LinkLabels {
    LinkLabels::new("tcp/127.0.0.1:7447", "tcp/127.0.0.1:50000")
}

fn udp_link() -> LinkLabels {
    LinkLabels::new("udp/10.0.0.1:7447", "udp/10.0.0.2:7447")
}

/// S2's events: one unicast transport over one tcp link, every family touched.
fn s2() -> (StatsRegistry, StatsTransportId) {
    let mut registry = StatsRegistry::new("a1b2", WhatAmI::Router, "v1");
    let transport = registry.open_unicast_transport("c3d4", WhatAmI::Peer, None);
    let link = tcp_link();
    registry.open_link(transport, &link);
    let metrics = registry.transport_mut(transport).expect("just opened");
    metrics.inc_bytes(StatsDirection::Tx, &link, 100);
    metrics.inc_bytes(StatsDirection::Rx, &link, 50);
    metrics.inc_transport_message(StatsDirection::Tx, &link, 2);
    for _ in 0..2 {
        metrics.inc_network_message(
            StatsDirection::Tx,
            &link,
            Priority::Data,
            MessageLabel::Put,
            false,
        );
    }
    metrics.inc_network_message(
        StatsDirection::Rx,
        &link,
        Priority::RealTime,
        MessageLabel::Put,
        false,
    );
    for size in [40, 2000] {
        metrics.observe_network_message_payload(
            StatsDirection::Tx,
            StatSpace::User,
            Priority::Data,
            MessageLabel::Put,
            false,
            size,
            [],
        );
    }
    metrics.observe_network_message_dropped_payload(
        StatsDirection::Rx,
        Priority::Data,
        MessageLabel::Put,
        None,
        ReasonLabel::AccessControl,
        5,
    );
    // Upstream's congestion drop is the LINK's, so it carries the protocol, but
    // it is recorded against the transport (no link partition).
    metrics.observe_network_message_dropped_payload(
        StatsDirection::Tx,
        Priority::Background,
        MessageLabel::Put,
        Some("tcp"),
        ReasonLabel::Congestion,
        9,
    );
    registry.inc_resource_declared(ResourceLabel::Subscriber, LocalityLabel::Local);
    (registry, transport)
}

/// S3's events, continuing S2: a second transport over udp, then the first
/// one's link and the transport close.
fn s3() -> StatsRegistry {
    let (mut registry, first) = s2();
    let second = registry.open_unicast_transport("e5f6", WhatAmI::Client, Some("cn1"));
    let link = udp_link();
    registry.open_link(second, &link);
    let metrics = registry.transport_mut(second).expect("just opened");
    metrics.inc_bytes(StatsDirection::Tx, &link, 7);
    metrics.inc_network_message(
        StatsDirection::Tx,
        &link,
        Priority::Data,
        MessageLabel::Put,
        false,
    );
    registry.close_link(first, &tcp_link());
    registry.close_transport(first, 0);
    registry
}

/// S4's events: a multicast group and one peer seen on it.
fn s4() -> StatsRegistry {
    let mut registry = StatsRegistry::new("a1b2", WhatAmI::Peer, "v1");
    let group = registry.open_multicast_transport("udp/224.0.0.224:7446");
    let link = LinkLabels::new("udp/10.0.0.1:7446", "udp/224.0.0.224:7446");
    registry.open_link(group, &link);
    registry
        .transport_mut(group)
        .expect("just opened")
        .inc_bytes(StatsDirection::Tx, &link, 11);
    let peer = registry.open_multicast_peer("aa", WhatAmI::Peer, "udp/224.0.0.224:7446");
    registry.open_link(peer, &link);
    registry
        .transport_mut(peer)
        .expect("just opened")
        .inc_bytes(StatsDirection::Rx, &link, 13);
    registry
}

/// S5's events: one payload matched by two configured keys.
fn s5() -> StatsRegistry {
    let mut registry = StatsRegistry::new("a1b2", WhatAmI::Router, "v1");
    let transport = registry.open_unicast_transport("c3d4", WhatAmI::Peer, None);
    registry
        .transport_mut(transport)
        .expect("just opened")
        .observe_network_message_payload(
            StatsDirection::Rx,
            StatSpace::User,
            Priority::Data,
            MessageLabel::Put,
            false,
            64,
            ["a/**", "a/b"],
        );
    registry
}

/// The wz twin of each generator scenario, by the title's leading word.
fn twin(title: &str) -> StatsRegistry {
    match title.split(' ').next().expect("a title has a first word") {
        "S1" => StatsRegistry::new("a1b2", WhatAmI::Router, "v1"),
        "S2" => s2().0,
        "S3" => s3(),
        "S4" => s4(),
        "S5" => s5(),
        other => panic!("golden scenario {other} has no wz twin: add one beside the generator's"),
    }
}

/// THE PARITY WITNESS: for every scenario the pinned `zenoh-stats` was run on,
/// the same events on this registry write the same document — the same
/// descriptors in the same order, and the same samples in each block.
///
/// The population is the GOLDEN's scenario list, not a list here, and an empty
/// one fails: a golden that stopped yielding scenarios would otherwise pass by
/// comparing nothing.
#[test]
fn every_golden_scenario_is_written_as_the_pin_writes_it() {
    let scenarios = golden_scenarios();
    assert_eq!(
        scenarios.len(),
        7,
        "the golden's scenario count moved; a new scenario needs a wz twin and this pin moves with it"
    );
    let mut divergent_lines = 0;
    for (title, pin) in scenarios {
        let (expected, touched) = apply_named_divergences(pin);
        divergent_lines += touched;
        let mut ours = String::new();
        twin(title).encode_metrics(&mut ours, query_of(title));
        let ours = normalise(&ours);
        if ours != expected {
            let first = ours
                .lines()
                .zip(expected.lines())
                .position(|(a, b)| a != b)
                .unwrap_or(ours.lines().count().min(expected.lines().count()));
            panic!(
                "scenario `{title}` differs from the pin at line {first}:\n  pin: {:?}\n  wz:  {:?}",
                expected.lines().nth(first),
                ours.lines().nth(first)
            );
        }
    }
    // The divergence is counted, not assumed: S5's two keys, each once in the
    // aggregate block and once in the per-transport block. If the pin ever
    // writes `+Inf` there, this count drops and the divergence is gone.
    assert_eq!(
        divergent_lines, 4,
        "the pin's per-key top bucket moved; re-read the per-key collection named on apply_named_divergences"
    );
}

/// A transport disconnected for more than the delay is RETIRED: its
/// transport-level counts join the aggregate with no transport labels, and
/// counts still held under one of its links are dropped, as upstream's
/// collection drops them. At exactly the delay it is not yet retired.
#[test]
fn a_retired_transport_keeps_its_transport_counts_and_loses_its_link_counts() {
    let mut registry = StatsRegistry::new("a1b2", WhatAmI::Router, "v1");
    let transport = registry.open_unicast_transport("c3d4", WhatAmI::Peer, None);
    let link = tcp_link();
    registry.open_link(transport, &link);
    let metrics = registry.transport_mut(transport).expect("just opened");
    metrics.inc_bytes(StatsDirection::Tx, &link, 100);
    metrics.observe_network_message_payload(
        StatsDirection::Tx,
        StatSpace::User,
        Priority::Data,
        MessageLabel::Put,
        false,
        40,
        [],
    );
    // The link is NOT closed first, so its byte count is still link-scoped.
    registry.close_transport(transport, 1_000);

    let query = MetricsQuery::default();
    let payload_sum = "zenoh_tx_network_message_payload_bytes_sum{local_id=\"a1b2\",local_whatami=\"router\",space=\"user\",priority=\"data\",message=\"put\",shm=\"false\"} 40.0";

    registry.collect_garbage(1_000 + GARBAGE_COLLECTION_DELAY_MS);
    let mut doc = String::new();
    registry.encode_metrics(&mut doc, query);
    assert!(
        !doc.contains(payload_sum),
        "at exactly the delay the transport is still disconnected-not-retired, so skipped:\n{doc}"
    );

    registry.collect_garbage(1_001 + GARBAGE_COLLECTION_DELAY_MS);
    let mut doc = String::new();
    registry.encode_metrics(&mut doc, query);
    assert!(
        doc.contains(payload_sum),
        "past the delay the transport-level payload count is retired INTO the aggregate:\n{doc}"
    );
    assert!(
        !doc.contains("zenoh_tx_bytes_total"),
        "a count still under a link when its transport is retired is dropped:\n{doc}"
    );
    assert!(
        !doc.contains("remote_zid=\"c3d4\""),
        "a retired transport has no partition of its own:\n{doc}"
    );
}

/// The four parameters with upstream's polarities: three default ON and are
/// turned off only by the literal `false`, one defaults OFF and is turned on
/// only by the literal `true`. A key given without a value (`Some("")`) changes
/// nothing.
#[test]
fn query_parameters_follow_upstreams_polarities() {
    assert_eq!(
        MetricsQuery::from_parameters(|_| None),
        MetricsQuery::default()
    );
    let bare = MetricsQuery::from_parameters(|_| Some(""));
    assert_eq!(bare, MetricsQuery::default());
    let all_false = MetricsQuery::from_parameters(|_| Some("false"));
    assert_eq!(
        all_false,
        MetricsQuery {
            per_transport: false,
            per_link: false,
            disconnected: false,
            per_key: false,
        }
    );
    let all_true = MetricsQuery::from_parameters(|_| Some("true"));
    assert_eq!(
        all_true,
        MetricsQuery {
            per_transport: true,
            per_link: true,
            disconnected: true,
            per_key: true,
        }
    );
}

/// A scheme upstream does not list is not a protocol: the label is the whole
/// remote locator, one series per remote end.
#[test]
fn an_unlisted_scheme_labels_the_series_with_the_whole_locator() {
    assert_eq!(tcp_link().protocol(), "tcp");
    assert_eq!(
        LinkLabels::new("unixsock-stream//tmp/a", "unixsock-stream//tmp/b").protocol(),
        "unixsock-stream"
    );
    let odd = LinkLabels::new("bt/00:11", "bt/22:33");
    assert_eq!(odd.protocol(), "bt/22:33");
}

/// Floats as `dtoa` spells them. Every expectation here was MEASURED from
/// `dtoa` 1.0.11 (the pin's `prometheus-client` dependency), including the
/// rounding of a value past 2^53.
///
/// ⚠ Not claimed: at `u64::MAX` the two disagree in the last digit — `dtoa`
/// wrote `18446744073709553000.0` where Rust's shortest round-trip writes
/// `…552000.0`. A payload sum of 18 exabytes is the only place that shows.
#[test]
fn integers_are_written_as_the_pins_float_encoder_writes_them() {
    let measured: [(u64, &str); 10] = [
        (0, "0.0"),
        (1, "1.0"),
        (2040, "2040.0"),
        (1 << 30, "1073741824.0"),
        (999_999_999_999_999, "999999999999999.0"),
        (9_999_999_999_999_999, "10000000000000000.0"),
        (12_345_678_901_234_567, "12345678901234568.0"),
        (100_000_000_000_000_000, "100000000000000000.0"),
        (1 << 53, "9007199254740992.0"),
        ((1 << 53) + 1, "9007199254740992.0"),
    ];
    for (value, spelled) in measured {
        assert_eq!(Float(value).to_string(), spelled, "{value}");
    }
}

/// A label value that would break the document is escaped; any other is
/// written as upstream writes it.
#[test]
fn label_values_are_escaped_only_where_the_format_requires() {
    let mut out = String::new();
    push_label_value("tcp/[::1]:7447", &mut out);
    assert_eq!(out, "tcp/[::1]:7447");
    let mut out = String::new();
    push_label_value("a\"b\\c\nd", &mut out);
    assert_eq!(out, "a\\\"b\\\\c\\nd");
}

/// Closing a link folds its counts into the transport: the per-link block
/// loses the link while the aggregate and the per-transport partition keep the
/// count — S3's first transport shows the same with the transport closed too.
#[test]
fn closing_a_link_moves_its_counts_to_the_transport() {
    let mut registry = StatsRegistry::new("a1b2", WhatAmI::Router, "v1");
    let transport = registry.open_unicast_transport("c3d4", WhatAmI::Peer, None);
    let link = tcp_link();
    registry.open_link(transport, &link);
    registry
        .transport_mut(transport)
        .expect("just opened")
        .inc_bytes(StatsDirection::Tx, &link, 100);
    registry.close_link(transport, &link);

    let mut doc = String::new();
    registry.encode_metrics(&mut doc, MetricsQuery::default());
    assert!(doc.contains(
        "zenoh_tx_bytes_total{local_id=\"a1b2\",local_whatami=\"router\",protocol=\"tcp\"} 100\n"
    ));
    assert!(doc.contains(",disconnected=\"false\"} 100\n"), "{doc}");
    assert!(
        !doc.contains("zenoh_tx_per_link_bytes"),
        "no link-scoped cell is left, so no per-link block is written:\n{doc}"
    );
    assert!(
        doc.contains(
            "zenoh_links_opened{local_id=\"a1b2\",local_whatami=\"router\",protocol=\"tcp\"} 0\n"
        ),
        "the gauge's series stays at zero rather than disappearing:\n{doc}"
    );
}
