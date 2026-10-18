// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `routing/router/linkstate/transport_weights` read from a config FILE and
//! shown on the wire between two real router-hat processes.
//!
//! The in-process tests of the router forwarder prove that a weight handed to
//! `update_router_link_weights` rides the flooded link-state entry. They start
//! from the setter, so they cannot tell whether the file reaches the setter at
//! all: the reader, the expansion onto `--router-link-weight`, the run-mode's
//! parse and the install before the first face registers are four hops no frame
//! was ever read across.
//!
//! This file is that instrument. Two `--router-hat` nodes are joined through a
//! recording relay; the node that listens is described by a file alone (its
//! zid, its role, its listen address and the weight all come from the
//! document), and the link-state entry it writes onto the link is dissected
//! with the tree's own dissector.
//!
//! * the file names the peer's zid with a weight: the listener's own entry
//!   carries the per-link weight list, holding that weight;
//! * the same file without the key: the entry carries NO weight list, which is
//!   upstream's rule that the list is written only when some weight is not the
//!   default (`zenoh/src/net/protocol/network.rs` @ `make_link_state`);
//! * the file names a zid that is not the peer's: again no weight list, so the
//!   weight is attached to a link by the zid it names and not applied to
//!   whichever link exists.
//!
//! The file selects the run-mode (`mode: "router"` plus a listen endpoint), and
//! that is deliberate rather than convenient: a `--router-hat` typed beside the
//! file makes the expansion decline the key as "not the role these endpoints
//! select", so only a file-selected router carries it.
//!
//! The tests are `#[ignore]` (binary-dep e2e) and need a `wz-ap-demo` built
//! with `--features zenoh-config,router-hat-router`.

use std::io::Write;
use std::time::Duration;

use tempfile::NamedTempFile;

use wz_capture::Dissection;
use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, graceful_terminate, read_captured,
    spawn_on_ephemeral_port, wait_for_substring, wz_ap_demo_binary,
};
use wz_integration_tests::wire_tap::{synthesise_pcap, tap_proxy, Recording};
use wz_session_core::dissect::{dissect_transport_message, Field, FieldValue};
use wz_session_core::zid_hex::zid_to_zenoh_hex;

/// The configured router's zid, as zenoh prints it. Pinned by the file's `id`.
const CONFIGURED_ZID: &str = "a1b2c3d4";
/// The other router's zid, pinned on its command line.
const PEER_ZID: &str = "b1b2c3d4";
/// A zid no node in the pair carries.
const STRANGER_ZID: &str = "d1d2d3d4";
/// Away from the unset weight and from anything a default could produce.
const CONFIGURED_WEIGHT: u64 = 777;

/// The listen marker both router-hat nodes print once bound.
const LISTEN_MARKER: &str = "router-hat: listening on 127.0.0.1:";
/// The dialling router's own statement that the pair has converged.
const CONVERGED: &str = "router-hat: routers-net converged (2 node(s))";

/// The synthesised ports the recording is wrapped in. The listener's is the
/// lesser, so `wz_capture` names the listener's half `Direction::A`; checked
/// where it is used.
const TAP_LISTENER_PORT: u16 = 7447;
const TAP_DIALER_PORT: u16 = 40001;

/// What one link-state entry on the wire says, reduced to the fields this file
/// judges.
#[derive(Debug)]
struct Flooded {
    /// The entry's zid as zenoh prints it, when the entry carries one.
    zid: Option<String>,
    /// The neighbour ids the entry advertises, in wire order.
    links: Vec<u64>,
    /// The per-link weight list, when the entry carries one.
    weights: Option<Vec<u64>>,
}

/// The document describing the listening router. `@ROUTING@` is replaced by
/// the `routing` block under test, or by nothing for the control.
const DOCUMENT: &str = r#"{
  mode: "router",
  id: "a1b2c3d4",
  listen: { endpoints: ["tcp/127.0.0.1:0"] },
  scouting: { multicast: { enabled: false } },
  @ROUTING@
}
"#;

/// A `routing` block weighting the link to `dst_zid`. The weight is UNQUOTED
/// and the zid lowercase without a leading zero, the spelling a real zenohd
/// loads.
fn weight_block(dst_zid: &str) -> String {
    format!(
        "routing: {{ router: {{ linkstate: {{ transport_weights: [ \
         {{ dst_zid: \"{dst_zid}\", weight: {CONFIGURED_WEIGHT} }}, ] }} }} }},"
    )
}

/// Write `json5` where the demo can read it; the reader dispatches on the
/// `.json5` suffix.
fn staged_config(json5: &str) -> NamedTempFile {
    let mut file = tempfile::Builder::new()
        .suffix(".json5")
        .tempfile()
        .expect("config tempfile");
    file.write_all(json5.as_bytes()).expect("write config");
    file.flush().expect("flush config");
    file
}

/// A direct child by name. Not `Field::find`, which is depth-first and would
/// answer with a field of a nested entry.
fn own_child<'a>(field: &'a Field, name: &str) -> Option<&'a Field> {
    match &field.value {
        FieldValue::Nested(children) => children.iter().find(|c| c.name == name),
        _ => None,
    }
}

/// The unsigned members of a group, in order.
fn uints(group: &Field) -> Vec<u64> {
    match &group.value {
        FieldValue::Nested(children) => children
            .iter()
            .filter_map(|f| match f.value {
                FieldValue::Uint(n) => Some(n),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Every `linkstate_entry` under `field`, reduced.
fn collect_entries(field: &Field, out: &mut Vec<Flooded>) {
    if field.name == "linkstate_entry" {
        out.push(Flooded {
            zid: match own_child(field, "zid").map(|f| &f.value) {
                Some(FieldValue::Zid(bytes)) => Some(zid_to_zenoh_hex(bytes)),
                _ => None,
            },
            links: own_child(field, "links").map(uints).unwrap_or_default(),
            weights: own_child(field, "weights").map(uints),
        });
        return;
    }
    if let FieldValue::Nested(children) = &field.value {
        for child in children {
            collect_entries(child, out);
        }
    }
}

/// The link-state entries the LISTENER wrote, in wire order.
///
/// The recording goes through the analyzer's own reassembly and framing, so
/// neither is this file's. Only the listener's half is read: the entry under
/// judgement is the one the configured node floods, and the other router's
/// entries are the control's subject, not the subject's.
fn entries_written_by_the_listener(recording: &Recording) -> Vec<Flooded> {
    let segments = recording.lock().expect("recording lock").clone();
    assert!(
        !segments.is_empty(),
        "the relay recorded nothing: the second router never dialled through it"
    );
    let pcap = synthesise_pcap(&segments, TAP_DIALER_PORT, TAP_LISTENER_PORT);
    let Ok(dissection) = Dissection::from_pcap(&pcap) else {
        panic!("the recording does not open as a capture");
    };
    let flows = dissection.flows();
    let flow = flows
        .first()
        .expect("the recording holds no TCP flow to read");
    assert_eq!(
        (flow.flow.low.port, flow.flow.high.port),
        (u32::from(TAP_LISTENER_PORT), u32::from(TAP_DIALER_PORT)),
        "the synthesised ports decide which half is Direction::A"
    );
    let mut out = Vec::new();
    for frame in flow.frames.iter() {
        if frame.direction != wz_session_core::passive::Direction::A {
            continue;
        }
        let Ok(bytes) = flow.message_bytes(frame) else {
            continue;
        };
        let Ok(walked) = dissect_transport_message(bytes, 0) else {
            continue;
        };
        collect_entries(&walked, &mut out);
    }
    out
}

/// What one pair run left behind.
struct PairRun {
    /// The listener's stderr, which carries the demo's own report of what the
    /// file became.
    listener_stderr: String,
    /// Every entry the listener wrote onto the link.
    entries: Vec<Flooded>,
}

impl PairRun {
    /// The listener's own entries, recognised by the zid the FILE pinned.
    fn own_entries(&self) -> Vec<&Flooded> {
        self.entries
            .iter()
            .filter(|e| e.zid.as_deref() == Some(CONFIGURED_ZID))
            .collect()
    }
}

/// Bring up the pair with `routing_block` in the listener's document and read
/// what the listener flooded to its neighbour.
///
/// ```text
///   [router listening, configured by FILE] <-- [relay] <-- [router dialling]
/// ```
fn run_the_pair(routing_block: &str) -> PairRun {
    let demo = wz_ap_demo_binary();
    // The demo is the subject: a build older than the weight expansion reads as
    // "wz ignores the key" and sends the diagnosis to the wrong layer.
    assert_demo_binary_newer_than_sources(&demo);

    let document = DOCUMENT.replace("@ROUTING@", routing_block);
    let config = staged_config(&document);
    let config_path = config
        .path()
        .to_str()
        .expect("the config path is UTF-8")
        .to_owned();

    let (mut listener, mut listener_err, listener_port) = spawn_on_ephemeral_port(
        &demo,
        &["--config", &config_path],
        LISTEN_MARKER,
        "router-hat (configured by a file)",
        tempfile::tempfile().expect("tempfile for the listener's stderr"),
    );
    let (relay_port, recording) = tap_proxy(listener_port);
    let relay_target = format!("127.0.0.1:{relay_port}");
    let (mut dialer, mut dialer_err, _dialer_port) = spawn_on_ephemeral_port(
        &demo,
        &[
            "--router-hat",
            "127.0.0.1:0",
            "--zid",
            PEER_ZID,
            "--connect",
            &relay_target,
        ],
        LISTEN_MARKER,
        "router-hat (dialling through the relay)",
        tempfile::tempfile().expect("tempfile for the dialler's stderr"),
    );

    // The listener writes its entry when it registers the dialler's face, and
    // the dialler converges only after reading it, so by this line the entry
    // under judgement is already in the recording.
    let converged = wait_for_substring(&mut dialer_err, CONVERGED, Duration::from_secs(20));

    graceful_terminate(dialer.child_mut(), Duration::from_secs(5));
    graceful_terminate(listener.child_mut(), Duration::from_secs(5));
    let listener_stderr = read_captured(&mut listener_err);
    let dialer_stderr = read_captured(&mut dialer_err);
    eprintln!("--- listener stderr ---\n{listener_stderr}");
    eprintln!("--- dialler stderr ---\n{dialer_stderr}");

    converged.unwrap_or_else(|c| {
        panic!(
            "the dialling router never converged within 20s, so the pair formed \
             no router link and nothing here was measured\n--- dialler \
             stderr ---\n{c}\n--- listener stderr ---\n{listener_stderr}\n{document}"
        )
    });
    PairRun {
        listener_stderr,
        entries: entries_written_by_the_listener(&recording),
    }
}

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features zenoh-config,router-hat-router)"]
fn wz_router_hat_link_weight_from_a_config_file_rides_the_flooded_linkstate() {
    let run = run_the_pair(&weight_block(PEER_ZID));

    // The node came up on the file's words: the expansion carried the row onto
    // the flag and the run-mode installed it before any face registered.
    assert!(
        run.listener_stderr.contains(&format!(
            "\"--router-link-weight\", \"{PEER_ZID}={CONFIGURED_WEIGHT}\""
        )),
        "the expansion did not carry the file's weight onto \
         --router-link-weight\n{}",
        run.listener_stderr
    );
    assert!(
        run.listener_stderr
            .contains("router-hat: 1 configured link weight(s) applied"),
        "the run-mode did not install the weight\n{}",
        run.listener_stderr
    );

    let own = run.own_entries();
    assert!(
        !own.is_empty(),
        "the listener flooded no entry naming its own zid {CONFIGURED_ZID}, so \
         nothing was measured: {:#?}",
        run.entries
    );
    // The peer is the listener's only neighbour, so the one link the entry
    // advertises is the one to the zid the file named, and the weight list
    // holds the configured weight at that slot.
    assert!(
        own.iter()
            .any(|e| e.links.len() == 1 && e.weights.as_deref() == Some(&[CONFIGURED_WEIGHT][..])),
        "no entry the listener flooded carries the configured weight \
         {CONFIGURED_WEIGHT} on its one link: {own:#?}"
    );
    // And no entry carries a weight the file did not say.
    assert!(
        own.iter()
            .filter_map(|e| e.weights.as_ref())
            .all(|w| w.as_slice() == [CONFIGURED_WEIGHT]),
        "an entry carried a weight other than the configured one: {own:#?}"
    );
}

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features zenoh-config,router-hat-router)"]
fn wz_router_hat_without_the_link_weight_key_floods_no_weight() {
    let run = run_the_pair("");

    assert!(
        !run.listener_stderr.contains("--router-link-weight"),
        "a file without the key must expand to no weight flag\n{}",
        run.listener_stderr
    );
    let own = run.own_entries();
    // The control is only a control if the link was advertised at all: without
    // this, an entry that never listed its neighbour would pass the next
    // assertion for the wrong reason.
    assert!(
        own.iter().any(|e| e.links.len() == 1),
        "the listener never advertised its link to the peer, so the absence of \
         a weight list measures nothing: {:#?}",
        run.entries
    );
    assert!(
        own.iter().all(|e| e.weights.is_none()),
        "an entry carried a weight list although no weight was configured: {own:#?}"
    );
}

#[test]
#[ignore = "binary-dep e2e (wz-ap-demo --features zenoh-config,router-hat-router)"]
fn wz_router_hat_link_weight_naming_another_zid_floods_no_weight() {
    let run = run_the_pair(&weight_block(STRANGER_ZID));

    // The weight WAS read and installed: only its destination is not a
    // neighbour, which is what separates this arm from the absent-key control.
    assert!(
        run.listener_stderr
            .contains("router-hat: 1 configured link weight(s) applied"),
        "the run-mode did not install the weight\n{}",
        run.listener_stderr
    );
    let own = run.own_entries();
    assert!(
        own.iter().any(|e| e.links.len() == 1),
        "the listener never advertised its link to the peer, so the absence of \
         a weight list measures nothing: {:#?}",
        run.entries
    );
    assert!(
        own.iter().all(|e| e.weights.is_none()),
        "a weight naming {STRANGER_ZID} rode the link to {PEER_ZID}: {own:#?}"
    );
}
