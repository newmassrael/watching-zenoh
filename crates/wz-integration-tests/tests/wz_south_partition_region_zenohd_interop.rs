// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The region a router puts a remote in, when the router PARTITIONS its south:
//! `wz_session_core::region_partition` against zenohd's own answers, and the
//! `gateway/south` value both are given, read by wz's reader.
//!
//! zenohd logs, at debug level, what it decided for each remote it accepts
//! (`zenoh/src/net/runtime/region.rs` @ `pub(crate) fn compute_region_of(` and
//! `pub(crate) fn compute_transient_bound_of(`, both `#[tracing::instrument(.., ret)]`).
//! This file starts a zenohd router with a `gateway.south` list of subregions,
//! connects wz nodes of every role with chosen zids, reads those decisions out of
//! its log, and requires wz's pure function, given the same partition and the
//! same remote, to answer the same: the same region, the same bound, and a
//! refusal exactly where zenohd refuses, with zenohd's own words.
//!
//! The partition is ONE text: zenohd reads it from its config file, and wz reads
//! it with `wz_runtime_tokio::zenoh_config::gateway_south_of`. So the reader is
//! inside the comparison, and a zid a rule names is matched against the bytes the
//! remote sends for it on the wire — the two meet only if the reader turns zenoh's
//! hex into the same bytes zenoh does.
//!
//! The reader is also compared on its own: a table of `gateway/south` values,
//! each one started under zenohd, must be accepted by wz exactly where zenohd
//! starts and refused exactly where zenohd refuses to load the file.
//!
//! The last two legs turn it around: an in-process wz ROUTER session whose own
//! south is partitioned announces the bound its rule gives zenohd on its
//! OpenSyn, and zenohd's logged decision for wz is the arm of its match that
//! reads an announced bound, against a control that announces nothing.
//!
//! ## What it reaches, and what it cannot
//!
//! The demo probes are nodes on the `auto` preset (no wz node reads the key
//! yet), so they announce no `RemoteBound` and every probe takes the arms of the
//! pin's match where the remote announced nothing: the auto table, "our rule
//! puts it south", and "our rule puts it north, which the auto table must agree
//! with", the last of which zenohd REFUSES for a client below a router. Of the
//! arms that need the remote to announce a bound, the in-process legs reach
//! "the remote calls us south"; the others are covered by unit tests only. The
//! `interfaces` and `region_names` filter fields are unit tests only as well: a
//! loopback probe has one interface and a wz node announces no region name.
//!
//! The probes are three partitions: three rules whose order, negation and
//! role set all matter; an empty list, which puts everyone north; and one rule
//! that matches everyone.

use std::fs::File;
use std::io::Write as _;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use wz_integration_tests::common::{
    read_captured, wait_for_tcp_accept_alive, wz_ap_demo_binary, zenohd_binary, ChildGuard,
    PortReservation, ZENOHD_TCP_ACCEPT_BUDGET,
};
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session_open::{
    initiate_and_open_session_with_staging, DialedLink, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::zenoh_config::gateway_south_of;
use wz_runtime_tokio_test_support::zenoh_interop_session_init_params;
use wz_session_core::extbound::{Bound, Region};
use wz_session_core::region_partition::{
    region_of, transient_bound_of, RemoteFacts, SouthPartition,
};
use wz_session_core::transport_mode::SessionOffer;
use wz_session_core::zid_hex::zenoh_hex_to_zid;
use wz_session_core::WhatAmI;

/// One remote the router is connected to: its zid as zenoh spells it, which is
/// what both the demo's `--zid` and a rule's `zids` take.
struct Probe {
    zid: &'static str,
    mode: WhatAmI,
}

const PROBES: [Probe; 4] = [
    Probe {
        zid: "a1b2c3d4",
        mode: WhatAmI::Peer,
    },
    Probe {
        zid: "b1b2c3d4",
        mode: WhatAmI::Peer,
    },
    Probe {
        zid: "c1b2c3d4",
        mode: WhatAmI::Client,
    },
    Probe {
        zid: "d1b2c3d4",
        mode: WhatAmI::Router,
    },
];

/// Subregion 0 is the first peer by zid, 1 is every peer, 2 is every node that is
/// not a client. A remote matching 0 matches 1 as well, so the first match wins
/// is load-bearing; 2 is a negation.
const THREE_RULES: &str = r#"[
    { filters: [ { zids: ["a1b2c3d4"] } ] },
    { filters: [ { modes: ["peer"] } ] },
    { filters: [ { modes: ["client"], negated: true } ] }
]"#;

/// An empty list: no subregion, so every remote is north.
const NO_SUBREGION: &str = "[]";

/// One subregion with no filters, which matches everyone.
const ONE_OPEN_SUBREGION: &str = "[ {} ]";

/// The partition wz reads from `text`, the value zenohd is given.
fn partition_of(text: &str) -> SouthPartition {
    let value = wz_session_core::json5::parse(text).expect("the partition text is JSON5");
    gateway_south_of(&value).expect("wz reads the partition zenohd is given")
}

/// zenohd's `Debug` text of a region.
fn render_region(region: Region) -> String {
    match region {
        Region::North => "North".to_string(),
        Region::Local => "Local".to_string(),
        Region::South { id, mode } => format!(
            "South {{ id: {id}, mode: {} }}",
            match mode {
                WhatAmI::Router => "Router",
                WhatAmI::Peer => "Peer",
                WhatAmI::Client => "Client",
            }
        ),
    }
}

fn render_bound(bound: Bound) -> &'static str {
    match bound {
        Bound::North => "North",
        Bound::South => "South",
    }
}

/// What zenohd decided for `zid`, as `(compute_transient_bound_of, compute_region_of)`
/// return texts, read from its log with the colour codes taken off.
fn decisions_in(log: &str, zid: &str) -> (Option<String>, Option<String>) {
    let mut bound = None;
    let mut region = None;
    for line in log.lines() {
        let line = strip_ansi(line);
        if !line.contains(&format!("peer.zid={zid} ")) {
            continue;
        }
        let Some(ret) = line
            .split_once("return=")
            .map(|(_, r)| r.trim().to_string())
        else {
            continue;
        };
        if line.contains("compute_transient_bound_of") {
            bound.get_or_insert(ret);
        } else if line.contains("compute_region_of") {
            region.get_or_insert(ret);
        }
    }
    (bound, region)
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for n in chars.by_ref() {
                if n == 'm' {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// A zenohd router config whose `gateway.south` is `south`, verbatim.
fn zenohd_config(tcp: u16, south: &str) -> tempfile::NamedTempFile {
    let mut config = tempfile::Builder::new()
        .suffix(".json5")
        .tempfile()
        .expect("zenohd config file");
    write!(
        config,
        "{{ mode: \"router\", listen: {{ endpoints: [\"tcp/127.0.0.1:{tcp}\"] }}, \
         scouting: {{ multicast: {{ enabled: false }} }}, \
         gateway: {{ south: {south} }} }}"
    )
    .expect("write zenohd config");
    config
}

/// Start a zenohd router with `south` as its south and every probe connected to
/// it; return what it decided for each, as its own log words it.
fn run(south: &str) -> Vec<(Option<String>, Option<String>)> {
    let port = PortReservation::pick();
    let tcp = port.port();
    let config = zenohd_config(tcp, south);
    let log = tempfile::tempfile().expect("zenohd log");
    let mut log_reader: File = log.try_clone().expect("dup log handle");
    let mut zenohd = ChildGuard::wrap(
        "zenohd (reference router)",
        Command::new(zenohd_binary())
            .arg("-c")
            .arg(config.path())
            .args(["--rest-http-port", "none"])
            .env("RUST_LOG", "zenoh=debug")
            .stdout(Stdio::from(log.try_clone().expect("dup log handle")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("spawn zenohd"),
    );
    if let Err(e) = wait_for_tcp_accept_alive(zenohd.child_mut(), tcp, ZENOHD_TCP_ACCEPT_BUDGET) {
        panic!("zenohd (reference router): {e}");
    }
    let dial = format!("127.0.0.1:{tcp}");
    let demo = wz_ap_demo_binary();

    let mut results = Vec::new();
    for probe in &PROBES {
        let mut command = Command::new(&demo);
        match probe.mode {
            WhatAmI::Peer => command.args(["--peer", "127.0.0.1:0", "--key", "demo/x"]),
            WhatAmI::Router => command.args(["--router-hat", "127.0.0.1:0"]),
            WhatAmI::Client => command.args(["--key", "demo/x"]),
        };
        command
            .args(["--zid", probe.zid, "--connect", &dial])
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut node = ChildGuard::wrap("wz probe", command.spawn().expect("spawn the wz probe"));
        // zenohd logs both decisions when it accepts the session, so wait for the
        // second of them; a remote it refuses logs its refusal in the same place.
        let deadline = Instant::now() + Duration::from_secs(15);
        let decided = loop {
            let text = read_captured(&mut log_reader);
            let (bound, region) = decisions_in(&text, probe.zid);
            if bound.is_some() && region.is_some() {
                break (bound, region);
            }
            if Instant::now() >= deadline {
                panic!(
                    "zenohd never logged a decision for the {} probe {}\n--- zenohd log ---\n{}",
                    probe.mode.to_str(),
                    probe.zid,
                    strip_ansi(&text)
                );
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        let _ = node.child_mut().kill();
        let _ = node.child_mut().wait();
        results.push(decided);
    }
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();
    results
}

/// The bytes a probe's zid travels as: zenoh's hex is a number, sent
/// little-endian.
fn wire_zid(probe: &Probe) -> Vec<u8> {
    zenoh_hex_to_zid(probe.zid).expect("a probe zid is a valid zenoh zid")
}

/// What the router knows of a probe: the zid it sends, its role, no region name
/// (a wz node announces none), and one link on the loopback interface.
fn facts_of<'a>(probe: &Probe, wire: &'a [u8]) -> RemoteFacts<'a> {
    RemoteFacts {
        zid: wire,
        whatami: probe.mode,
        region_name: None,
        interfaces: &["lo"],
    }
}

/// wz's answers for a probe: `compute_transient_bound_of` and `compute_region_of`,
/// worded as zenohd's `Debug` of the same results is.
fn wz_answers(partition: &SouthPartition, probe: &Probe) -> (String, String) {
    let wire = wire_zid(probe);
    let facts = facts_of(probe, &wire);
    let bound = match transient_bound_of(WhatAmI::Router, partition, &facts) {
        Ok(Some(b)) => format!("Ok(Some({}))", render_bound(b)),
        Ok(None) => "Ok(None)".to_string(),
        Err(e) => format!("Err({e}"),
    };
    let region = match region_of(WhatAmI::Router, partition, &facts, None) {
        Ok((r, b)) => format!("Ok(({}, {}))", render_region(r), render_bound(b)),
        Err(e) => format!("Err({e}"),
    };
    (bound, region)
}

/// Each decision zenohd logged equals wz's. A refusal is compared up to the pin's
/// own message, since zenohd appends the source location it was raised at.
fn assert_agrees(label: &str, south: &str) {
    let partition = partition_of(south);
    let theirs = run(south);
    for (probe, (bound, region)) in PROBES.iter().zip(theirs) {
        let (wz_bound, wz_region) = wz_answers(&partition, probe);
        let who = format!("{label}: the {} probe {}", probe.mode.to_str(), probe.zid);
        let same = |ours: &str, theirs: &str| {
            if ours.starts_with("Err(") {
                theirs.starts_with(ours)
            } else {
                ours == theirs
            }
        };
        let bound = bound.expect("a bound decision was read");
        let region = region.expect("a region decision was read");
        assert!(
            same(&wz_bound, &bound),
            "{who}: the announced bound is {bound} at zenohd and {wz_bound} at wz"
        );
        assert!(
            same(&wz_region, &region),
            "{who}: the region is {region} at zenohd and {wz_region} at wz"
        );
    }
}

/// The calibration is the table itself: a probe whose answer is a subregion, one
/// the first rule wins, one a negated rule places, and one zenohd refuses.
// wz-proves: none -- a differential of wz's pure region function and its reader of
// the key against zenohd's logged decisions; nothing a wz node does on the wire yet.
#[test]
#[ignore = "binary-dep e2e (zenohd + wz-ap-demo --features router-hat-router); Layer Z runs via --ignored"]
fn wz_region_decisions_match_zenohds_for_three_ordered_rules() {
    let partition = partition_of(THREE_RULES);
    // The cases the table is built to reach, so a change that stopped reaching
    // them would not leave the comparison below green by agreeing about nothing.
    let at = |i: usize| {
        let wire = wire_zid(&PROBES[i]);
        region_of(
            WhatAmI::Router,
            &partition,
            &facts_of(&PROBES[i], &wire),
            None,
        )
    };
    assert_eq!(
        at(0),
        Ok((
            Region::South {
                id: 0,
                mode: WhatAmI::Peer
            },
            Bound::North
        )),
        "the first rule wins over the second"
    );
    assert_eq!(
        at(1),
        Ok((
            Region::South {
                id: 1,
                mode: WhatAmI::Peer
            },
            Bound::North
        ))
    );
    assert!(
        at(2).is_err(),
        "a client no rule places is refused below a router"
    );
    assert_eq!(
        at(3),
        Ok((
            Region::South {
                id: 2,
                mode: WhatAmI::Router
            },
            Bound::North
        )),
        "the negated rule places a router"
    );
    assert_agrees("three rules", THREE_RULES);
}

/// An empty list puts every remote north, which a router refuses for a peer or a
/// client (the auto table would put them south) and accepts for a router.
// wz-proves: none -- a differential of wz's pure region function and its reader of
// the key against zenohd's logged decisions; nothing a wz node does on the wire yet.
#[test]
#[ignore = "binary-dep e2e (zenohd + wz-ap-demo --features router-hat-router); Layer Z runs via --ignored"]
fn wz_region_decisions_match_zenohds_for_an_empty_rule_list() {
    assert_agrees("no subregion", NO_SUBREGION);
}

/// One rule that matches everyone: every remote lands in subregion 0, in its own
/// mode.
// wz-proves: none -- a differential of wz's pure region function and its reader of
// the key against zenohd's logged decisions; nothing a wz node does on the wire yet.
#[test]
#[ignore = "binary-dep e2e (zenohd + wz-ap-demo --features router-hat-router); Layer Z runs via --ignored"]
fn wz_region_decisions_match_zenohds_for_one_open_rule() {
    assert_agrees("one open subregion", ONE_OPEN_SUBREGION);
}

/// `gateway/south` values the pinned zenohd STARTS on. A measurement, and the
/// test re-measures it every run: a value whose zenohd verdict changed reds here
/// before wz's reader is compared to it.
const SOUTH_VALUES_ZENOHD_STARTS_ON: &[&str] = &[
    // The preset, and the spellings serde's untagged enum admits for it.
    r#""auto""#,
    "null",
    "{ auto: null }",
    // A list of subregions, and serde's positional form of one.
    "[]",
    "[ {} ]",
    "[ { filters: null } ]",
    "[ { filters: [] } ]",
    "[ [ [ {} ] ] ]",
    // A filter, and serde's positional form of one: four or five fields.
    "[ { filters: [ {} ] } ]",
    r#"[ { filters: [ [ ["peer"], null, null, null ] ] } ]"#,
    r#"[ { filters: [ [ ["peer"], null, null, null, true ] ] } ]"#,
    // Each field.
    "[ { filters: [ { modes: [] } ] } ]",
    r#"[ { filters: [ { modes: ["peer", "router"] } ] } ]"#,
    r#"[ { filters: [ { modes: ["peer", "peer"] } ] } ]"#,
    r#"[ { filters: [ { zids: ["a1b2"] } ] } ]"#,
    r#"[ { filters: [ { zids: ["+1"] } ] } ]"#,
    r#"[ { filters: [ { zids: ["ffffffffffffffffffffffffffffffff"] } ] } ]"#,
    r#"[ { filters: [ { interfaces: ["lo"] } ] } ]"#,
    r#"[ { filters: [ { interfaces: [""] } ] } ]"#,
    r#"[ { filters: [ { region_names: ["east"] } ] } ]"#,
    r#"[ { filters: [ { region_names: ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"] } ] } ]"#,
    "[ { filters: [ { negated: true } ] } ]",
    "[ { filters: [ { modes: null, interfaces: null, zids: null, region_names: null } ] } ]",
];

/// `gateway/south` values the pinned zenohd REFUSES to load, measured as above.
const SOUTH_VALUES_ZENOHD_REFUSES: &[&str] = &[
    r#""Auto""#,
    "{}",
    "{ auto: {} }",
    "{ auto: null, x: 1 }",
    "7",
    "[ [] ]",
    "[ [ null, 1 ] ]",
    "[ null ]",
    "[ { foo: 1 } ]",
    "[ { filters: [], filters: [] } ]",
    r#"[ { filters: { modes: ["peer"] } } ]"#,
    "[ { filters: [ null ] } ]",
    r#"[ { filters: [ [ ["peer"], null, null ] ] } ]"#,
    r#"[ { filters: [ [ ["peer"], null, null, null, true, 1 ] ] } ]"#,
    "[ { filters: [ { bogus: 1 } ] } ]",
    r#"[ { filters: [ { modes: ["peer"], modes: ["router"] } ] } ]"#,
    r#"[ { filters: [ { modes: "peer" } ] } ]"#,
    r#"[ { filters: [ { modes: ["Peer"] } ] } ]"#,
    "[ { filters: [ { zids: [] } ] } ]",
    r#"[ { filters: [ { zids: ["ABC"] } ] } ]"#,
    r#"[ { filters: [ { zids: ["0a"] } ] } ]"#,
    r#"[ { filters: [ { zids: ["100000000000000000000000000000000"] } ] } ]"#,
    "[ { filters: [ { interfaces: [] } ] } ]",
    "[ { filters: [ { interfaces: [1] } ] } ]",
    r#"[ { filters: [ { region_names: ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"] } ] } ]"#,
    "[ { filters: [ { region_names: [] } ] } ]",
    r#"[ { filters: [ { region_names: [""] } ] } ]"#,
    "[ { filters: [ { negated: null } ] } ]",
    r#"[ { filters: [ { negated: "yes" } ] } ]"#,
];

/// Whether zenohd starts on a router config whose `gateway.south` is `south`:
/// `true` once it listens, `false` when it exits refusing to load the file. Any
/// other exit is not an answer about the value, and fails the test.
fn zenohd_starts_on(south: &str) -> bool {
    let port = PortReservation::pick();
    let tcp = port.port();
    let config = zenohd_config(tcp, south);
    let log = tempfile::tempfile().expect("zenohd log");
    let mut log_reader: File = log.try_clone().expect("dup log handle");
    let mut zenohd = ChildGuard::wrap(
        "zenohd (reference config reader)",
        Command::new(zenohd_binary())
            .arg("-c")
            .arg(config.path())
            .args(["--rest-http-port", "none"])
            .stdout(Stdio::from(log.try_clone().expect("dup log handle")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("spawn zenohd"),
    );
    let started = wait_for_tcp_accept_alive(zenohd.child_mut(), tcp, ZENOHD_TCP_ACCEPT_BUDGET);
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();
    match started {
        Ok(()) => true,
        Err(why) => {
            let text = strip_ansi(&read_captured(&mut log_reader));
            assert!(
                text.contains("Failed to load config file"),
                "zenohd did not start on {south} for a reason other than the config: \
                 {why}\n--- zenohd log ---\n{text}"
            );
            false
        }
    }
}

/// wz's reader accepts exactly the `gateway/south` values the pinned zenohd
/// starts on. The table spans every shape the value can take, every field's
/// refusals, and the positional and tagged spellings serde admits, which a
/// reader written from the field list alone would refuse.
// wz-proves: none -- a differential of wz's reader of the key against zenohd's
// own config loading; no wz node reads the key yet.
#[test]
#[ignore = "binary-dep e2e (zenohd); Layer Z runs via --ignored"]
fn wz_reads_the_gateway_south_values_zenohd_starts_on() {
    let table = SOUTH_VALUES_ZENOHD_STARTS_ON
        .iter()
        .map(|south| (south, true))
        .chain(
            SOUTH_VALUES_ZENOHD_REFUSES
                .iter()
                .map(|south| (south, false)),
        );
    let mut disagreements = Vec::new();
    for (south, measured) in table {
        let zenohd = zenohd_starts_on(south);
        assert_eq!(
            zenohd, measured,
            "zenohd's verdict on {south} is not the one this table records"
        );
        let value = wz_session_core::json5::parse(south).expect("each value is JSON5");
        let wz = gateway_south_of(&value);
        if wz.is_ok() != zenohd {
            disagreements.push(format!("{south}: zenohd starts {zenohd}, wz reads {wz:?}"));
        }
    }
    assert!(
        disagreements.is_empty(),
        "wz's reader and zenohd disagree:\n{}",
        disagreements.join("\n")
    );
}

// ── the bound wz announces on its Open, as zenohd reads it ──

/// The zid of the in-process wz router, as zenoh spells it.
const WZ_ROUTER_ZID: &str = "e1b2c3d4";

/// The step a session's open loop may take before it gives up.
const OPEN_ITER_CAP: usize = 4096;

/// Start a zenohd router on the `auto` preset, open an in-process wz ROUTER
/// session to it with its south partitioned as `south`, and return what zenohd
/// decided for wz (`compute_region_of`'s return text) and the bound wz
/// announced on its OpenSyn.
async fn zenohd_places_a_wz_router(south: &str) -> (String, Option<Bound>) {
    let port = PortReservation::pick();
    let tcp = port.port();
    let config = zenohd_config(tcp, r#""auto""#);
    let log = tempfile::tempfile().expect("zenohd log");
    let mut log_reader: File = log.try_clone().expect("dup log handle");
    let mut zenohd = ChildGuard::wrap(
        "zenohd (reference router)",
        Command::new(zenohd_binary())
            .arg("-c")
            .arg(config.path())
            .args(["--rest-http-port", "none"])
            .env("RUST_LOG", "zenoh=debug")
            .stdout(Stdio::from(log.try_clone().expect("dup log handle")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("spawn zenohd"),
    );
    if let Err(e) = wait_for_tcp_accept_alive(zenohd.child_mut(), tcp, ZENOHD_TCP_ACCEPT_BUDGET) {
        panic!("zenohd (reference router): {e}");
    }

    let partition = partition_of(south);
    let params = zenoh_interop_session_init_params(
        WhatAmI::Router,
        zenoh_hex_to_zid(WZ_ROUTER_ZID).expect("a valid zid"),
    );
    let stream = TcpStream::connect(("127.0.0.1", tcp))
        .await
        .expect("wz dials zenohd");
    let opened = initiate_and_open_session_with_staging(
        DialedLink::Tcp(stream),
        params,
        SessionOffer::universal(),
        // Before the first wire byte, as a node sets it on every session it opens.
        move |actions| {
            actions.set_south_partition(partition);
            Ok(())
        },
        TokioTime::new(),
        Some(OPEN_ITER_CAP),
        DEFAULT_OPEN_TICK_MS,
    )
    .await
    .unwrap_or_else(|e| panic!("wz did not open a session to zenohd: {e:?}"));
    let announced = opened.actions.local_remote_bound();

    let deadline = Instant::now() + Duration::from_secs(15);
    let region = loop {
        let text = read_captured(&mut log_reader);
        if let (_, Some(region)) = decisions_in(&text, WZ_ROUTER_ZID) {
            break region;
        }
        if Instant::now() >= deadline {
            panic!(
                "zenohd never logged a region for wz\n--- zenohd log ---\n{}",
                strip_ansi(&text)
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    drop(opened);
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait();
    (region, announced)
}

/// What zenohd's own rule makes of a remote router that announced `bound`, as
/// wz's region function words it: zenohd is a router on the `auto` preset.
fn zenohd_should_decide(bound: Option<Bound>) -> String {
    let wire = zenoh_hex_to_zid(WZ_ROUTER_ZID).expect("a valid zid");
    let facts = RemoteFacts {
        zid: &wire,
        whatami: WhatAmI::Router,
        region_name: None,
        interfaces: &["lo"],
    };
    match region_of(WhatAmI::Router, &SouthPartition::Auto, &facts, bound) {
        Ok((r, b)) => format!("Ok(({}, {}))", render_region(r), render_bound(b)),
        Err(e) => format!("Err({e}"),
    }
}

/// THE CLAIM: a wz router whose rule puts zenohd in its south announces SOUTH on
/// its OpenSyn, and zenohd, reading it, places wz in its NORTH with wz as its
/// gateway (`compute_region_of` @ `(None, Some(Bound::South)) => Ok((Region::North, Bound::South)),`).
/// Without the announcement two routers on the `auto` preset are peers of one
/// north region, which the control below shows.
// wz-proves: none -- the Open's bound announcement read by zenohd; no wz node is
// configured with a partition yet, so this is no atom's claim.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenohd); Layer Z runs via --ignored"]
async fn zenohd_places_a_wz_router_that_calls_it_south_below_wz() {
    let (region, announced) = zenohd_places_a_wz_router(ONE_OPEN_SUBREGION).await;
    assert_eq!(announced, Some(Bound::South), "wz announced south");
    assert_eq!(region, "Ok((North, South))", "zenohd read the announcement");
    assert_eq!(region, zenohd_should_decide(announced));
}

/// THE CONTROL: the same wz router on the `auto` preset announces nothing, and
/// zenohd places it as one router of its north region.
// wz-proves: none -- harness control for the leg above.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenohd); Layer Z runs via --ignored"]
async fn zenohd_places_a_wz_router_that_announces_nothing_beside_it() {
    let (region, announced) = zenohd_places_a_wz_router(r#""auto""#).await;
    assert_eq!(
        announced, None,
        "a node on the auto preset announces nothing"
    );
    assert_eq!(region, "Ok((North, North))");
    assert_eq!(region, zenohd_should_decide(announced));
}
