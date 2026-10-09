// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The region a router puts a remote in, when the router PARTITIONS its south:
//! `wz_session_core::region_partition` against zenohd's own answers.
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
//! The partition is ONE value, rendered into zenohd's config by this file, so the
//! two sides are given the same rules and not two spellings of them.
//!
//! ## What it reaches, and what it cannot
//!
//! A wz node announces no `RemoteBound` on its Open, so every probe takes the
//! arms of the pin's match where the remote announced nothing: the auto table,
//! "our rule puts it south", and "our rule puts it north, which the auto table
//! must agree with", the last of which zenohd REFUSES for a client below a router.
//! The arms that need the remote to announce a bound are covered by unit tests
//! only; they are reachable against zenohd once wz sends the extension. The
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

use wz_codecs::whatami::WhatAmIMatcher;
use wz_integration_tests::common::{
    read_captured, wait_for_tcp_accept_alive, wz_ap_demo_binary, zenohd_binary, ChildGuard,
    PortReservation, ZENOHD_TCP_ACCEPT_BUDGET,
};
use wz_session_core::extbound::{Bound, Region};
use wz_session_core::region_partition::{
    region_of, transient_bound_of, RegionFilter, RemoteFacts, SouthPartition, SouthSubregion,
};
use wz_session_core::WhatAmI;

const ZID_PEER_A: [u8; 4] = [0xa1, 0xb2, 0xc3, 0xd4];
const ZID_PEER_B: [u8; 4] = [0xb1, 0xb2, 0xc3, 0xd4];
const ZID_CLIENT: [u8; 4] = [0xc1, 0xb2, 0xc3, 0xd4];
const ZID_ROUTER: [u8; 4] = [0xd1, 0xb2, 0xc3, 0xd4];

/// One remote the router is connected to.
struct Probe {
    zid: [u8; 4],
    mode: WhatAmI,
}

const PROBES: [Probe; 4] = [
    Probe {
        zid: ZID_PEER_A,
        mode: WhatAmI::Peer,
    },
    Probe {
        zid: ZID_PEER_B,
        mode: WhatAmI::Peer,
    },
    Probe {
        zid: ZID_CLIENT,
        mode: WhatAmI::Client,
    },
    Probe {
        zid: ZID_ROUTER,
        mode: WhatAmI::Router,
    },
];

fn hex(zid: &[u8]) -> String {
    zid.iter().map(|b| format!("{b:02x}")).collect()
}

fn by_zid(zid: &[u8]) -> RegionFilter {
    RegionFilter {
        zids: Some(vec![zid.to_vec()]),
        ..RegionFilter::default()
    }
}

fn by_modes(modes: WhatAmIMatcher, negated: bool) -> RegionFilter {
    RegionFilter {
        modes: Some(modes),
        negated,
        ..RegionFilter::default()
    }
}

/// Subregion 0 is one peer by zid, 1 is every peer, 2 is every node that is not
/// a client. A remote matching 0 matches 1 as well, so the first match wins is
/// load-bearing; 2 is a negation.
fn three_rules() -> SouthPartition {
    SouthPartition::Custom(vec![
        SouthSubregion {
            filters: Some(vec![by_zid(&ZID_PEER_A)]),
        },
        SouthSubregion {
            filters: Some(vec![by_modes(WhatAmIMatcher::empty().peer(), false)]),
        },
        SouthSubregion {
            filters: Some(vec![by_modes(WhatAmIMatcher::empty().client(), true)]),
        },
    ])
}

/// An empty list: no subregion, so every remote is north.
fn no_subregion() -> SouthPartition {
    SouthPartition::Custom(vec![])
}

/// One subregion with no filters, which matches everyone.
fn one_open_subregion() -> SouthPartition {
    SouthPartition::Custom(vec![SouthSubregion { filters: None }])
}

/// The partition as zenohd's config spells it.
fn render_south(partition: &SouthPartition) -> String {
    match partition {
        SouthPartition::Auto => "\"auto\"".to_string(),
        SouthPartition::Custom(subregions) => {
            let one = |s: &SouthSubregion| match &s.filters {
                None => "{}".to_string(),
                Some(filters) => {
                    let each = |f: &RegionFilter| {
                        let mut fields = Vec::new();
                        if let Some(zids) = &f.zids {
                            let zids: Vec<String> =
                                zids.iter().map(|z| format!("\"{}\"", hex(z))).collect();
                            fields.push(format!("zids: [{}]", zids.join(",")));
                        }
                        if let Some(modes) = &f.modes {
                            let modes: Vec<String> =
                                [WhatAmI::Router, WhatAmI::Peer, WhatAmI::Client]
                                    .into_iter()
                                    .filter(|m| modes.matches(*m))
                                    .map(|m| format!("\"{}\"", m.to_str()))
                                    .collect();
                            fields.push(format!("modes: [{}]", modes.join(",")));
                        }
                        if let Some(names) = &f.interfaces {
                            let names: Vec<String> =
                                names.iter().map(|n| format!("\"{n}\"")).collect();
                            fields.push(format!("interfaces: [{}]", names.join(",")));
                        }
                        if let Some(names) = &f.region_names {
                            let names: Vec<String> =
                                names.iter().map(|n| format!("\"{n}\"")).collect();
                            fields.push(format!("region_names: [{}]", names.join(",")));
                        }
                        fields.push(format!("negated: {}", f.negated));
                        format!("{{{}}}", fields.join(", "))
                    };
                    let filters: Vec<String> = filters.iter().map(each).collect();
                    format!("{{ filters: [{}] }}", filters.join(", "))
                }
            };
            let all: Vec<String> = subregions.iter().map(one).collect();
            format!("[{}]", all.join(", "))
        }
    }
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
fn decisions_in(log: &str, zid: &[u8]) -> (Option<String>, Option<String>) {
    let short = hex(zid);
    let mut bound = None;
    let mut region = None;
    for line in log.lines() {
        let line = strip_ansi(line);
        if !line.contains(&format!("peer.zid={short} ")) {
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

/// Start a zenohd router with `partition` as its south and every probe connected
/// to it; return what it decided for each, as its own log words it.
fn run(partition: &SouthPartition) -> Vec<(Option<String>, Option<String>)> {
    let port = PortReservation::pick();
    let tcp = port.port();
    let mut config = tempfile::Builder::new()
        .suffix(".json5")
        .tempfile()
        .expect("zenohd config file");
    write!(
        config,
        "{{ mode: \"router\", listen: {{ endpoints: [\"tcp/127.0.0.1:{tcp}\"] }}, \
         scouting: {{ multicast: {{ enabled: false }} }}, \
         gateway: {{ south: {} }} }}",
        render_south(partition)
    )
    .expect("write zenohd config");
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
        let zid = hex(&probe.zid);
        let mut command = Command::new(&demo);
        match probe.mode {
            WhatAmI::Peer => command.args(["--peer", "127.0.0.1:0", "--key", "demo/x"]),
            WhatAmI::Router => command.args(["--router-hat", "127.0.0.1:0"]),
            WhatAmI::Client => command.args(["--key", "demo/x"]),
        };
        command
            .args(["--zid", &zid, "--connect", &dial])
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut node = ChildGuard::wrap("wz probe", command.spawn().expect("spawn the wz probe"));
        // zenohd logs both decisions when it accepts the session, so wait for the
        // second of them; a remote it refuses logs its refusal in the same place.
        let deadline = Instant::now() + Duration::from_secs(15);
        let decided = loop {
            let text = read_captured(&mut log_reader);
            let (bound, region) = decisions_in(&text, &probe.zid);
            if bound.is_some() && region.is_some() {
                break (bound, region);
            }
            if Instant::now() >= deadline {
                panic!(
                    "zenohd never logged a decision for the {} probe {zid}\n--- zenohd log ---\n{}",
                    probe.mode.to_str(),
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

/// What the router knows of a probe: its zid and role, no region name (a wz node
/// announces none), and one link on the loopback interface.
fn facts_of(probe: &Probe) -> RemoteFacts<'_> {
    RemoteFacts {
        zid: &probe.zid,
        whatami: probe.mode,
        region_name: None,
        interfaces: &["lo"],
    }
}

/// wz's answers for a probe: `compute_transient_bound_of` and `compute_region_of`,
/// worded as zenohd's `Debug` of the same results is.
fn wz_answers(partition: &SouthPartition, probe: &Probe) -> (String, String) {
    let facts = facts_of(probe);
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
fn assert_agrees(label: &str, partition: &SouthPartition) {
    let theirs = run(partition);
    for (probe, (bound, region)) in PROBES.iter().zip(theirs) {
        let (wz_bound, wz_region) = wz_answers(partition, probe);
        let who = format!(
            "{label}: the {} probe {}",
            probe.mode.to_str(),
            hex(&probe.zid)
        );
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
// wz-proves: none -- a differential of wz's pure region function against zenohd's
// logged decisions; nothing a wz node does on the wire yet.
#[test]
#[ignore = "binary-dep e2e (zenohd + wz-ap-demo --features router-hat-router); Layer Z runs via --ignored"]
fn wz_region_decisions_match_zenohds_for_three_ordered_rules() {
    let partition = three_rules();
    // The cases the table is built to reach, so a change that stopped reaching
    // them would not leave the comparison below green by agreeing about nothing.
    let at = |i: usize| region_of(WhatAmI::Router, &partition, &facts_of(&PROBES[i]), None);
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
    assert_agrees("three rules", &partition);
}

/// An empty list puts every remote north, which a router refuses for a peer or a
/// client (the auto table would put them south) and accepts for a router.
// wz-proves: none -- a differential of wz's pure region function against zenohd's
// logged decisions; nothing a wz node does on the wire yet.
#[test]
#[ignore = "binary-dep e2e (zenohd + wz-ap-demo --features router-hat-router); Layer Z runs via --ignored"]
fn wz_region_decisions_match_zenohds_for_an_empty_rule_list() {
    assert_agrees("no subregion", &no_subregion());
}

/// One rule that matches everyone: every remote lands in subregion 0, in its own
/// mode.
// wz-proves: none -- a differential of wz's pure region function against zenohd's
// logged decisions; nothing a wz node does on the wire yet.
#[test]
#[ignore = "binary-dep e2e (zenohd + wz-ap-demo --features router-hat-router); Layer Z runs via --ignored"]
fn wz_region_decisions_match_zenohds_for_one_open_rule() {
    assert_agrees("one open subregion", &one_open_subregion());
}
