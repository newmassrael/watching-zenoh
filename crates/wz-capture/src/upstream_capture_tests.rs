// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A multicast group of stock zenohd, read through the field document: every
//! sender's Frame SNs are judged on the ring and from the start its JOIN states.
//!
//! The capture is `captures/upstream/zenoh-1-10-0-udp-multicast.pcap`, two
//! eclipse/zenoh 1.10.0 peers on one UDP multicast group and 30 PUTs, which
//! `captures/upstream/README.md` describes. Upstream wrote every byte of it, so
//! a JOIN reading and a frame encoding that agreed with each other in this tree
//! and not with upstream would fail here; a capture of wz talking to wz cannot
//! tell that apart.
//!
//! The ring of these JOINs is the default one, as it is in every JOIN stock
//! zenohd sends (`io/zenoh-transport/src/multicast/link.rs` @ `resolution: Resolution::default(),`).
//! A JOIN that states another ring, which only another implementation sends, is
//! held in `wz-session-core` (`passive::join_ring_tests`).

use alloc::string::String;
use alloc::vec::Vec;

use wz_session_core::json5::{self, Json5Value};

use crate::fields_json::fields_json;
use crate::Dissection;

const CAPTURE: &str = "zenoh-1-10-0-udp-multicast.pcap";

fn capture() -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../captures/upstream")
        .join(CAPTURE);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn get<'a>(value: &'a Json5Value, key: &str) -> Option<&'a Json5Value> {
    match value {
        Json5Value::Object(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
        _ => None,
    }
}

fn word(value: Option<&Json5Value>) -> Option<&str> {
    match value? {
        Json5Value::String(s) => Some(s),
        _ => None,
    }
}

fn number(value: Option<&Json5Value>) -> Option<u64> {
    match value? {
        Json5Value::Number(n) => n.parse().ok(),
        _ => None,
    }
}

/// A row's `sn`: its verdict, and `missing` when it is a gap.
struct Sn {
    verdict: String,
    missing: Option<u64>,
}

/// One message row: its transport message, and its `sn` when it carries one.
struct Row {
    message: String,
    sn: Option<Sn>,
}

/// One datagram flow of the document, as the claim reads it.
struct Flow {
    sn_mask: Option<u64>,
    rows: Vec<Row>,
}

impl Flow {
    /// The rows from the flow's first JOIN on.
    fn rows_since_first_join(&self) -> &[Row] {
        let first = self
            .rows
            .iter()
            .position(|row| row.message == "Join")
            .expect("every sender of the group sends a JOIN");
        &self.rows[first..]
    }

    fn verdicts_after_join(&self) -> impl Iterator<Item = &Sn> {
        self.rows_since_first_join()
            .iter()
            .filter_map(|row| row.sn.as_ref())
    }

    fn missing(&self) -> u64 {
        self.verdicts_after_join().filter_map(|sn| sn.missing).sum()
    }
}

/// The datagram flows of the field document of `bytes`.
fn flows(bytes: &[u8]) -> Vec<Flow> {
    let d = Dissection::from_capture(bytes).expect("the capture reads");
    let doc = fields_json(&d, bytes, None, None);
    let value = json5::parse(&doc).expect("the document is JSON");
    let Some(Json5Value::Array(flows)) = get(&value, "datagram_flows") else {
        panic!("the document has datagram flows");
    };
    flows
        .iter()
        .map(|flow| {
            let context = get(flow, "context").expect("a flow has a context");
            let Some(Json5Value::Array(messages)) = get(flow, "messages") else {
                panic!("a flow lists its messages");
            };
            let rows = messages
                .iter()
                .map(|row| {
                    let message = word(get(row, "fields").and_then(|f| get(f, "name")))
                        .unwrap_or("")
                        .into();
                    let sn = match get(row, "sn") {
                        Some(sn @ Json5Value::Object(_)) => Some(Sn {
                            verdict: word(get(sn, "verdict")).expect("a verdict").into(),
                            missing: number(get(sn, "missing")),
                        }),
                        _ => None,
                    };
                    Row { message, sn }
                })
                .collect();
            Flow {
                sn_mask: number(get(context, "sn_mask")),
                rows,
            }
        })
        .collect()
}

/// The capture with the `nth` datagram that carries a FRAME taken out: a data
/// frame lost on the wire, after the sender's JOIN.
fn without_frame(bytes: &[u8], nth: usize) -> Vec<u8> {
    let file = crate::pcap::parse(bytes).expect("a classic pcap");
    // Ethernet, IPv4 without options, UDP: the zenoh message is at 42.
    const PAYLOAD: usize = 14 + 20 + 8;
    let frame_mid = |data: &[u8]| {
        data.get(PAYLOAD)
            .is_some_and(|h| h & 0x1f == wz_session_core::wire_const::T_MID_FRAME)
    };
    let mut frames = 0;
    let kept: Vec<(u32, u32, &[u8])> = file
        .packets
        .iter()
        .filter(|p| {
            if !frame_mid(&p.data) {
                return true;
            }
            frames += 1;
            frames != nth
        })
        .map(|p| (p.ts_secs, p.ts_frac, p.data.as_slice()))
        .collect();
    assert_eq!(
        kept.len(),
        file.packets.len() - 1,
        "one frame was taken out"
    );
    crate::pcap::write(file.link_type, &kept)
}

/// As captured: both senders' rings are the JOIN's, every frame after a JOIN is
/// judged, and the group lost nothing.
#[test]
fn every_frame_of_a_stock_multicast_group_is_judged_on_its_joins_ring() {
    let flows = flows(&capture());
    assert_eq!(flows.len(), 2, "one flow per sender toward the group");
    let mut judged = 0;
    for flow in &flows {
        assert_eq!(
            flow.sn_mask,
            Some(wz_session_core::sn::mask_from_res(2)),
            "an S-clear JOIN states the default ring"
        );
        for sn in flow.verdicts_after_join() {
            assert_ne!(
                sn.verdict, "without_resolution",
                "a frame after the JOIN has a ring"
            );
            judged += 1;
        }
        assert_eq!(flow.missing(), 0, "a docker bridge loses nothing");
    }
    assert_eq!(judged, 30, "the 30 PUTs, each in its own frame");
}

/// The claim's own test: one data frame taken out after the JOIN is one SN
/// missing, and still no frame after the JOIN is without a ring.
///
/// The first frame is in the set because only the JOIN's `next_sn` can count
/// it: with the first frame read taken as the baseline, its loss is invisible.
#[test]
fn a_frame_lost_from_a_stock_multicast_group_is_counted_once() {
    for nth in [1, 15, 29] {
        let flows = flows(&without_frame(&capture(), nth));
        let missing: u64 = flows.iter().map(Flow::missing).sum();
        assert_eq!(missing, 1, "frame {nth} of 30 taken out");
        for flow in &flows {
            assert!(
                flow.verdicts_after_join()
                    .all(|sn| sn.verdict != "without_resolution"),
                "frame {nth} taken out"
            );
        }
        let gaps = flows
            .iter()
            .flat_map(Flow::verdicts_after_join)
            .filter(|sn| sn.verdict == "gap")
            .count();
        assert_eq!(gaps, 1, "frame {nth} taken out");
    }
}

/// The last frame lost is counted by no verdict: no frame follows it, and the
/// sender's next JOIN, whose `next_sn` is past it, moves nothing for a sender
/// already known, as it moves nothing in upstream's receiver
/// (`io/zenoh-transport/src/multicast/rx.rs` @ `pub(super) fn handle_join_from_peer(`).
/// Pinned so that a reading which starts counting it is a decision that moves
/// this test, not a drift.
#[test]
fn the_last_frame_lost_before_a_periodic_join_is_not_counted() {
    let flows = flows(&without_frame(&capture(), 30));
    assert_eq!(flows.iter().map(Flow::missing).sum::<u64>(), 0);
    let publisher = flows
        .iter()
        .find(|f| f.rows.iter().any(|row| row.sn.is_some()))
        .expect("one sender sent the PUTs");
    let last_frame = publisher.rows.iter().rposition(|row| row.sn.is_some());
    let last_join = publisher.rows.iter().rposition(|row| row.message == "Join");
    assert!(
        last_join > last_frame,
        "a JOIN of the sender follows its last frame in the capture"
    );
}
