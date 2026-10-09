// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The transport build door, held against an independent oracle, against the
//! dissector, and against itself.
//!
//! Four kinds of evidence, and they do not share a source:
//!
//! * `wz-session-wire-fixtures`, whose bytes are laid by hand per the
//!   zenoh-pico transport layout and which the door never calls: every message
//!   it can build, built here from the same inputs, must be the same bytes;
//! * the dissector (`dissect_transport_message`, the reader behind
//!   `wz_dissect_transport_message`): every built message reads back to the
//!   fields the description gave;
//! * the report read against the bytes: a field replaced using only the report
//!   changes that field and no other;
//! * the classification table read against the generated codecs' own field
//!   lists and against everything the dissector emits.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use wz_session_core::dissect::{dissect_transport_message, Field, FieldValue};
use wz_session_core::json5::{self, Json5Value};
use wz_session_core::transport_compose::{vle_range, vle_width, Framing};
use wz_session_wire_fixtures as oracle;

use crate::doc_revision::{
    key_set, TRANSPORT_BUILD, TRANSPORT_BUILD_R1_FAMILIES, TRANSPORT_BUILD_R1_KEYS,
};
use crate::e2e_profile::DocError;
use crate::transport_build::{build, BuildError, Built, RESOLUTION_WORDS};
use crate::transport_build_json::build_document;
use crate::transport_layout::{
    classified_alias_names, classified_leaf_names, layout, Encoding, Kind, RelativeTo, Row, LEAVES,
};

// ---------------------------------------------------------------- helpers

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn built(description: &str, framing: Framing) -> Built {
    match build(description, framing) {
        Ok(b) => b,
        Err(e) => panic!("{description} was refused: {e:?}"),
    }
}

fn body_of(description: &str) -> Vec<u8> {
    built(description, Framing::Datagram).body
}

fn row<'a>(b: &'a Built, name: &str) -> &'a Row {
    b.layout
        .iter()
        .find(|r| r.name == name)
        .unwrap_or_else(|| panic!("no row `{name}` in {:?}", names(b)))
}

fn names(b: &Built) -> Vec<&str> {
    b.layout.iter().map(|r| r.name.as_str()).collect()
}

/// The refusal of a description that must be refused, as (path, reason).
fn refused(description: &str) -> (String, String) {
    match build(description, Framing::TcpStream) {
        Err(BuildError::Description(DocError::Invalid { path, reason })) => (path, reason),
        Err(BuildError::Description(DocError::Syntax { offset, expected })) => {
            (format!("@{offset}"), expected.to_string())
        }
        other => panic!("{description} should be refused at a place, got {other:?}"),
    }
}

/// Every document the corpus builds, in every framing: the population the
/// carries gate in `fields_json` measures the three families against.
pub(crate) fn documents_for_the_carries_gate() -> Vec<String> {
    let mut docs = Vec::new();
    for case in corpus() {
        for framing in Framing::ALL {
            docs.push(build_document(&case.json, framing));
        }
    }
    docs
}

// ----------------------------------------------------------------- corpus

/// What a dissection must read.
#[derive(Clone, Debug)]
enum Want {
    Uint(u64),
    Flag(bool),
    Bits(u64),
    Label(&'static str),
    /// The bytes under the field's span.
    Bytes(Vec<u8>),
}

struct Case {
    label: String,
    json: String,
    wants: Vec<(&'static str, Want)>,
    ring: Option<u64>,
}

fn case(
    label: impl Into<String>,
    json: impl Into<String>,
    wants: Vec<(&'static str, Want)>,
) -> Case {
    Case {
        label: label.into(),
        json: json.into(),
        wants,
        ring: None,
    }
}

const ZID4: [u8; 4] = [0xB0, 0xB1, 0xB2, 0xB3];

fn corpus() -> Vec<Case> {
    use Want::*;
    let mut v: Vec<Case> = Vec::new();

    // INIT, both roles, with and without the size parameters and the chain.
    v.push(case(
        "init_syn minimal",
        r#"{"message":"init_syn","version":5,"whatami":"peer","zid":"b0b1b2b3"}"#,
        vec![
            ("version", Uint(5)),
            ("whatami", Bits(1)),
            ("zid_len", Bits(4)),
            ("zid", Bytes(ZID4.to_vec())),
            ("a", Flag(false)),
            ("s", Flag(false)),
            ("z", Flag(false)),
        ],
    ));
    let zid16: Vec<u8> = (1..=16).collect();
    v.push(case(
        "init_syn sized with extensions",
        format!(
            r#"{{"message":"init_syn","version":5,"whatami":"client","zid":"{}",
               "resolution":{{"frame_sn":"32bit","request_id":"16bit"}},"batch_size":8192,
               "extensions":[{{"id":1,"unit":true}},{{"id":7,"z64":1}},
                             {{"id":8,"zbuf":"6162"}},{{"id":3,"mandatory":true,"zbuf":""}}]}}"#,
            hex(&zid16)
        ),
        vec![
            ("whatami", Bits(2)),
            ("zid_len", Bits(16)),
            ("zid", Bytes(zid16)),
            ("sn_res_frame_sn", Label("32bit")),
            ("sn_res_request_id", Label("16bit")),
            ("batch_size", Uint(8192)),
            ("s", Flag(true)),
            ("z", Flag(true)),
        ],
    ));
    v.push(case(
        "init_syn reserved whatami",
        r#"{"message":"init_syn","version":0,"whatami":3,"zid":"ff"}"#,
        vec![("whatami", Bits(3)), ("zid_len", Bits(1))],
    ));
    v.push(case(
        "init_syn zero batch size",
        r#"{"message":"init_syn","version":5,"whatami":"router","zid":"01",
           "resolution":{"frame_sn":"8bit","request_id":"8bit"},"batch_size":0}"#,
        vec![("batch_size", Uint(0)), ("whatami", Bits(0))],
    ));
    v.push(case(
        "init_ack empty cookie",
        r#"{"message":"init_ack","version":5,"whatami":"peer","zid":"a0a1a2a3","cookie":""}"#,
        vec![
            ("a", Flag(true)),
            ("cookie_len", Uint(0)),
            ("cookie", Bytes(vec![])),
        ],
    ));
    let cookie200: Vec<u8> = (0..200u8).collect();
    v.push(case(
        "init_ack long cookie",
        format!(
            r#"{{"message":"init_ack","version":5,"whatami":"peer","zid":"a0a1a2a3",
               "resolution":{{"frame_sn":"64bit","request_id":"64bit"}},"batch_size":65535,
               "cookie":"{}","extensions":[{{"id":7,"z64":300}}]}}"#,
            hex(&cookie200)
        ),
        vec![
            ("a", Flag(true)),
            ("s", Flag(true)),
            ("z", Flag(true)),
            ("cookie_len", Uint(200)),
            ("cookie", Bytes(cookie200)),
            ("batch_size", Uint(65_535)),
        ],
    ));

    // OPEN, both roles, the lease in each unit.
    v.push(case(
        "open_syn derived lease unit",
        r#"{"message":"open_syn","lease_ms":10000,"initial_sn":5,"cookie":"aabb"}"#,
        vec![
            ("a", Flag(false)),
            ("t", Flag(true)),
            ("lease", Uint(10)),
            ("initial_sn", Uint(5)),
            ("cookie_len", Uint(2)),
            ("cookie", Bytes(vec![0xAA, 0xBB])),
        ],
    ));
    v.push(case(
        "open_syn lease in milliseconds",
        r#"{"message":"open_syn","lease_ms":10000,"lease_unit":"ms","initial_sn":0,"cookie":""}"#,
        vec![("t", Flag(false)), ("lease", Uint(10_000))],
    ));
    let mut ringed = case(
        "open_syn on a 16bit ring",
        r#"{"message":"open_syn","lease_ms":1500,"initial_sn":16383,"sn_resolution":"16bit",
           "cookie":"01","extensions":[{"id":4,"zbuf":"cafe"},{"id":5,"unit":true}]}"#,
        vec![
            ("t", Flag(false)),
            ("lease", Uint(1500)),
            ("initial_sn", Uint(16_383)),
            ("z", Flag(true)),
        ],
    );
    ringed.ring = Some(16_383);
    v.push(ringed);
    v.push(case(
        "open_ack with a chain",
        r#"{"message":"open_ack","lease_ms":0,"initial_sn":1,"extensions":[{"id":7,"z64":9}]}"#,
        vec![
            ("a", Flag(true)),
            ("lease", Uint(0)),
            ("initial_sn", Uint(1)),
        ],
    ));

    // FRAME: the channel, every priority, the payload, the SN across VLE widths.
    for reliable in [false, true] {
        v.push(case(
            format!("frame reliable={reliable}"),
            format!(r#"{{"message":"frame","reliable":{reliable},"sn":5}}"#),
            vec![("r", Flag(reliable)), ("sn", Uint(5)), ("z", Flag(false))],
        ));
    }
    for priority in 0..=7u64 {
        v.push(case(
            format!("frame priority {priority}"),
            format!(
                r#"{{"message":"frame","reliable":true,"sn":9,"priority":{priority},"payload":"deadbeef"}}"#
            ),
            vec![
                ("z", Flag(true)),
                ("sn", Uint(9)),
                ("value", Uint(priority)),
            ],
        ));
    }
    for sn in [
        0u64,
        127,
        128,
        16_383,
        16_384,
        (1 << 56) - 1,
        1 << 56,
        1 << 63,
        u64::MAX,
    ] {
        v.push(case(
            format!("frame sn {sn}"),
            format!(
                r#"{{"message":"frame","reliable":false,"sn":{},"payload":"00"}}"#,
                quoted(sn)
            ),
            vec![("sn", Uint(sn))],
        ));
    }

    // FRAGMENT: every flag, the markers, the priority.
    for flags in 0..16u8 {
        for priority in [None, Some(2u64)] {
            let (reliable, more, first, drop_marker) = (
                flags & 1 != 0,
                flags & 2 != 0,
                flags & 4 != 0,
                flags & 8 != 0,
            );
            let prio = priority
                .map(|p| format!(r#","priority":{p}"#))
                .unwrap_or_default();
            let mut wants = vec![
                ("r", Flag(reliable)),
                ("m", Flag(more)),
                ("sn", Uint(300)),
                ("payload", Bytes(vec![0xDE, 0xAD])),
            ];
            let chain = first || drop_marker || priority.is_some();
            wants.push(("z", Flag(chain)));
            v.push(case(
                format!("fragment {flags:04b} {priority:?}"),
                format!(
                    r#"{{"message":"fragment","reliable":{reliable},"more":{more},"sn":300,
                       "first":{first},"drop":{drop_marker}{prio},"payload":"dead"}}"#
                ),
                wants,
            ));
        }
    }

    v.push(case(
        "keep_alive",
        r#"{"message":"keep_alive"}"#,
        vec![("z", Flag(false))],
    ));
    for session in [false, true] {
        for reason in [0u64, 7, 255] {
            v.push(case(
                format!("close session={session} reason={reason}"),
                format!(r#"{{"message":"close","reason":{reason},"session":{session}}}"#),
                vec![("s", Flag(session)), ("reason", Uint(reason))],
            ));
        }
    }
    v
}

/// A `u64` as a JSON integer cell this door reads: the number, or a decimal
/// string past 2^53.
fn quoted(v: u64) -> String {
    if v > (1 << 53) {
        format!("\"{v}\"")
    } else {
        v.to_string()
    }
}

fn read<'a>(root: &'a Field, name: &str) -> &'a Field {
    root.find(name)
        .unwrap_or_else(|| panic!("the dissection has no `{name}`"))
}

// ------------------------------------------------- 1. the independent oracle

/// Every message `wz-session-wire-fixtures` builds, built through the door from
/// the same inputs. The oracle is laid by hand and the door never calls it, so
/// equal bytes are two readings of the format agreeing.
#[test]
fn the_door_builds_the_bytes_the_independent_oracle_lays() {
    let cookie = [0xC0, 0xC1, 0xC2];
    let same = |label: &str, description: String, oracle: Vec<u8>| {
        assert_eq!(
            hex(&body_of(&description)),
            hex(&oracle),
            "{label}: {description}"
        );
    };
    same(
        "initsyn",
        r#"{"message":"init_syn","version":5,"whatami":"peer","zid":"b0b1b2b3",
           "resolution":{"frame_sn":"8bit","request_id":"8bit"},"batch_size":0}"#
            .into(),
        oracle::craft_initsyn_wire(),
    );
    same(
        "initack",
        format!(
            r#"{{"message":"init_ack","version":5,"whatami":"peer","zid":"a0a1a2a3",
               "resolution":{{"frame_sn":"8bit","request_id":"8bit"}},"batch_size":0,
               "cookie":"{}"}}"#,
            hex(&cookie)
        ),
        oracle::craft_initack_wire(&cookie),
    );
    // The caps: the oracle's byte is `(seq & 3) | ((req & 3) << 2)`.
    for sn_res in [0x00u8, 0x01, 0x06, 0x0F] {
        let word = |code: u8| RESOLUTION_WORDS[(code & 3) as usize];
        same(
            "initack with caps",
            format!(
                r#"{{"message":"init_ack","version":5,"whatami":"peer","zid":"a0a1a2a3",
                   "resolution":{{"frame_sn":"{}","request_id":"{}"}},"batch_size":4660,
                   "cookie":"{}"}}"#,
                word(sn_res),
                word(sn_res >> 2),
                hex(&cookie)
            ),
            oracle::craft_initack_wire_with_caps(&cookie, sn_res, 0x1234),
        );
    }
    for level in [0u8, 1, 2, 100] {
        same(
            "initack with patch",
            format!(
                r#"{{"message":"init_ack","version":5,"whatami":"peer","zid":"a0a1a2a3",
                   "resolution":{{"frame_sn":"8bit","request_id":"8bit"}},"batch_size":0,
                   "cookie":"{}","extensions":[{{"id":7,"z64":{level}}}]}}"#,
                hex(&cookie)
            ),
            oracle::craft_initack_wire_with_patch(&cookie, level),
        );
        same(
            "initsyn with patch",
            format!(
                r#"{{"message":"init_syn","version":5,"whatami":"peer","zid":"b0b1b2b3",
                   "resolution":{{"frame_sn":"8bit","request_id":"8bit"}},"batch_size":0,
                   "extensions":[{{"id":7,"z64":{level}}}]}}"#
            ),
            oracle::craft_initsyn_wire_with_patch(level),
        );
    }
    for region in [&b"north"[..], b"", b"\xff\xfe not utf-8"] {
        same(
            "initsyn with region",
            format!(
                r#"{{"message":"init_syn","version":5,"whatami":"peer","zid":"b0b1b2b3",
                   "resolution":{{"frame_sn":"8bit","request_id":"8bit"}},"batch_size":0,
                   "extensions":[{{"id":8,"zbuf":"{}"}}]}}"#,
                hex(region)
            ),
            oracle::craft_initsyn_wire_with_region(region),
        );
    }
    same(
        "initsyn as client",
        r#"{"message":"init_syn","version":5,"whatami":"client","zid":"b0b1b2b3",
           "resolution":{"frame_sn":"8bit","request_id":"8bit"},"batch_size":0}"#
            .into(),
        oracle::craft_initsyn_wire_as_client(),
    );

    // OPEN. The oracle writes the lease in MILLISECONDS (parent flags 0x00) and
    // a derived lease of 0 is written in SECONDS (`T` set), so the oracle's
    // bytes are asked for by naming the unit. That is the one place the two
    // legitimately differ, and the difference is exactly the `T` flag: see
    // `a_derived_lease_unit_differs_from_the_oracle_only_in_the_t_flag`.
    same(
        "opensyn",
        format!(
            r#"{{"message":"open_syn","lease_ms":0,"lease_unit":"ms","initial_sn":0,"cookie":"{}"}}"#,
            hex(&cookie)
        ),
        oracle::craft_opensyn_wire(&cookie),
    );
    for value in [0u64, 1, 127, 128, 300, 70_000] {
        same(
            "opensyn with remote bound",
            format!(
                r#"{{"message":"open_syn","lease_ms":0,"lease_unit":"ms","initial_sn":0,
                   "cookie":"{}","extensions":[{{"id":7,"z64":{value}}}]}}"#,
                hex(&cookie)
            ),
            oracle::craft_opensyn_wire_with_remote_bound(&cookie, value),
        );
    }
    for sn in [0u64, 1, 127] {
        same(
            "openack",
            format!(r#"{{"message":"open_ack","lease_ms":0,"lease_unit":"ms","initial_sn":{sn}}}"#),
            oracle::craft_openack_wire(sn),
        );
    }

    // FRAME and FRAGMENT.
    for reliable in [false, true] {
        for sn in [0u64, 5, 127] {
            same(
                "frame",
                format!(r#"{{"message":"frame","reliable":{reliable},"sn":{sn}}}"#),
                oracle::craft_frame_wire(sn, reliable),
            );
            for priority in 0..8u8 {
                same(
                    "frame with priority",
                    format!(
                        r#"{{"message":"frame","reliable":{reliable},"sn":{sn},"priority":{priority}}}"#
                    ),
                    oracle::craft_frame_wire_with_priority(sn, reliable, priority),
                );
            }
        }
        for more in [false, true] {
            let payload = [0xDE, 0xAD, 0xBE];
            same(
                "fragment",
                format!(
                    r#"{{"message":"fragment","reliable":{reliable},"more":{more},"sn":9,
                       "payload":"{}"}}"#,
                    hex(&payload)
                ),
                oracle::craft_fragment_wire(reliable, more, 9, &payload),
            );
            for priority in 0..8u8 {
                same(
                    "fragment with priority",
                    format!(
                        r#"{{"message":"fragment","reliable":{reliable},"more":{more},"sn":9,
                           "priority":{priority},"payload":"{}"}}"#,
                        hex(&payload)
                    ),
                    oracle::craft_fragment_wire_with_priority(
                        reliable, more, 9, priority, &payload,
                    ),
                );
            }
        }
    }
}

/// The oracle has no Close, no KeepAlive and no Fragment marker, so those are
/// held against bytes typed from the upstream header rules: Close is
/// `[0x20 S | 0x03][reason]`, KeepAlive `[0x04]`, and a Fragment's `First`
/// marker is the extension header `0x02` (id 2, unit, not mandatory) behind a
/// header with `Z` set (flags: `commons/zenoh-protocol/src/transport/close.rs` @
/// `pub const S: u8 = 1 << 5;`; `commons/zenoh-protocol/src/transport/fragment.rs`
/// @ `pub type First = zextunit!(0x2, false);`).
#[test]
fn the_messages_the_oracle_lacks_are_the_bytes_the_upstream_headers_give() {
    assert_eq!(
        body_of(r#"{"message":"close","reason":2,"session":true}"#),
        [0x23, 0x02]
    );
    assert_eq!(
        body_of(r#"{"message":"close","reason":2,"session":false}"#),
        [0x03, 0x02]
    );
    assert_eq!(body_of(r#"{"message":"keep_alive"}"#), [0x04]);
    // R | M | Z | MID 6 = 0xE6, VLE sn 5, First (0x02), the payload.
    assert_eq!(
        body_of(
            r#"{"message":"fragment","reliable":true,"more":true,"sn":5,"first":true,
               "payload":"dead"}"#
        ),
        [0xE6, 0x05, 0x02, 0xDE, 0xAD]
    );
    // Drop alone is id 3: 0xE6 -> header with Z, then 0x03.
    assert_eq!(
        body_of(
            r#"{"message":"fragment","reliable":true,"more":true,"sn":5,"drop":true,
               "payload":""}"#
        ),
        [0xE6, 0x05, 0x03]
    );
    // QoS (0x31 | Z on the ext header because First follows), then First.
    assert_eq!(
        body_of(
            r#"{"message":"fragment","reliable":false,"more":false,"sn":1,"priority":4,
               "first":true,"payload":""}"#
        ),
        [0x86, 0x01, 0xB1, 0x04, 0x02]
    );
}

#[test]
fn a_derived_lease_unit_differs_from_the_oracle_only_in_the_t_flag() {
    let cookie = [0xAA];
    let derived = body_of(&format!(
        r#"{{"message":"open_syn","lease_ms":0,"initial_sn":0,"cookie":"{}"}}"#,
        hex(&cookie)
    ));
    let oracle_bytes = oracle::craft_opensyn_wire(&cookie);
    assert_eq!(derived.len(), oracle_bytes.len());
    assert_eq!(
        derived[0] ^ oracle_bytes[0],
        0x40,
        "the T flag, and no other bit"
    );
    assert_eq!(derived[1..], oracle_bytes[1..]);
}

// -------------------------------------------------------- 2. the round trip

fn check_wants(label: &str, body: &[u8], wants: &[(&'static str, Want)]) {
    let root = dissect_transport_message(body, 0).expect("the built body dissects");
    for (name, want) in wants {
        let field = read(&root, name);
        match (want, &field.value) {
            (Want::Uint(v), FieldValue::Uint(got)) => assert_eq!(got, v, "{label}: {name}"),
            (Want::Flag(v), FieldValue::Flag(got)) => assert_eq!(got, v, "{label}: {name}"),
            (Want::Bits(v), FieldValue::Bits(got)) => assert_eq!(got, v, "{label}: {name}"),
            (Want::Label(v), FieldValue::Label(got)) => assert_eq!(got, v, "{label}: {name}"),
            (Want::Bytes(v), _) => assert_eq!(
                &body[field.span.start..field.span.end],
                &v[..],
                "{label}: {name}"
            ),
            (want, got) => panic!("{label}: {name} wanted {want:?}, read {got:?}"),
        }
    }
}

/// Every built unit dissects back through the reader behind
/// `wz_dissect_transport_message` to the fields the description gave, in every
/// framing, and the unit is the prefix then the body.
#[test]
fn every_built_unit_reads_back_to_the_callers_fields() {
    for case in corpus() {
        for framing in Framing::ALL {
            let b = built(&case.json, framing);
            check_wants(&case.label, &b.body, &case.wants);
            let prefix = framing.prefix_bytes();
            assert_eq!(b.prefix_bytes, prefix, "{}", case.label);
            assert_eq!(b.unit.len(), prefix + b.body.len(), "{}", case.label);
            assert_eq!(&b.unit[prefix..], &b.body[..], "{}", case.label);
            let announced = match prefix {
                0 => b.body.len() as u64,
                2 => u64::from(u16::from_le_bytes([b.unit[0], b.unit[1]])),
                4 => u64::from(u32::from_le_bytes([
                    b.unit[0], b.unit[1], b.unit[2], b.unit[3],
                ])),
                other => panic!("a prefix of {other}"),
            };
            assert_eq!(announced, b.body.len() as u64, "{}", case.label);
        }
    }
}

/// The three framings of one description differ in the prefix and nowhere else.
#[test]
fn the_framings_differ_only_in_the_prefix() {
    let json = r#"{"message":"frame","reliable":true,"sn":5,"payload":"0102030405"}"#;
    let datagram = built(json, Framing::Datagram);
    let tcp = built(json, Framing::TcpStream);
    let low = built(json, Framing::LowLatencyStream);
    assert_eq!(datagram.unit, datagram.body);
    assert_eq!(tcp.body, datagram.body);
    assert_eq!(low.body, datagram.body);
    let len = datagram.body.len() as u8;
    assert_eq!(&tcp.unit[..2], &[len, 0]);
    assert_eq!(&low.unit[..4], &[len, 0, 0, 0]);
}

// ------------------------------------------------------- 3. the negative arm

#[test]
fn a_value_that_does_not_fit_its_field_is_refused_at_its_key() {
    let at = |description: &str, path: &str, needle: &str| {
        let (got, reason) = refused(description);
        assert_eq!(got, path, "{description}: {reason}");
        assert!(
            reason.contains(needle),
            "{description}: `{reason}` lacks `{needle}`"
        );
    };
    let init = |extra: &str| {
        format!(r#"{{"message":"init_syn","version":5,"whatami":"peer","zid":"b0b1b2b3"{extra}}}"#)
    };
    at(&init("").replace("\"b0b1b2b3\"", "\"\""), "/zid", "0 bytes");
    at(
        &init("").replace("b0b1b2b3", &"aa".repeat(17)),
        "/zid",
        "17 bytes",
    );
    assert!(build(
        &init("").replace("b0b1b2b3", &"aa".repeat(16)),
        Framing::Datagram
    )
    .is_ok());
    at(
        &init("").replace("\"peer\"", "4"),
        "/whatami",
        "largest value is 3",
    );
    at(
        &init("").replace("\"peer\"", "\"coordinator\""),
        "/whatami",
        "not a role",
    );
    at(
        &init("").replace("\"version\":5", "\"version\":256"),
        "/version",
        "largest value is 255",
    );
    at(
        &init(r#","resolution":{"frame_sn":"8bit","request_id":"8bit"},"batch_size":65536"#),
        "/batch_size",
        "largest value is 65535",
    );
    at(
        &init(r#","resolution":{"frame_sn":"7bit","request_id":"8bit"},"batch_size":1"#),
        "/resolution/frame_sn",
        "not a resolution",
    );
    at(
        &init(r#","resolution":{"frame_sn":"8bit","request_id":"8bit"}"#),
        "/resolution",
        "travel together",
    );
    at(
        &init(r#","batch_size":4"#),
        "/batch_size",
        "travel together",
    );
    at(&init(r#","cookie":"aa""#), "/cookie", "unknown key");
    at(
        &init(r#","extensions":[{"id":16,"unit":true}]"#),
        "/extensions/0/id",
        "0 to 15",
    );
    at(
        &init(r#","extensions":[{"id":1,"unit":true},{"id":2}]"#),
        "/extensions/1",
        "exactly one body",
    );
    at(
        &init(r#","extensions":[{"id":1,"unit":true,"z64":1}]"#),
        "/extensions/0",
        "exactly one body",
    );
    at(
        &init(r#","extensions":[{"id":1,"unit":false}]"#),
        "/extensions/0/unit",
        "no body",
    );
    let nine = r#"{"id":1,"unit":true},"#.repeat(9);
    at(
        &init(&format!(
            r#","extensions":[{}]"#,
            nine.trim_end_matches(',')
        )),
        "/extensions",
        "9 extensions",
    );
    at(
        &init(r#","extensions":[{"id":3,"zbuf":"abc"}]"#),
        "/extensions/0/zbuf",
        "pairs",
    );
    at(
        &init(r#","extensions":[{"id":3,"zbuf":"zz"}]"#),
        "/extensions/0/zbuf",
        "not hexadecimal",
    );

    // Sequence numbers against the ring the caller names.
    let frame =
        |sn: &str, ring: &str| format!(r#"{{"message":"frame","reliable":true,"sn":{sn}{ring}}}"#);
    for (word, max) in [
        ("8bit", 127u64),
        ("16bit", 16_383),
        ("32bit", 268_435_455),
        ("64bit", (1u64 << 63) - 1),
    ] {
        let ring = format!(r#","sn_resolution":"{word}""#);
        assert!(
            build(&frame(&quoted(max), &ring), Framing::Datagram).is_ok(),
            "{word}: the ring's own maximum is written"
        );
        at(
            &frame(&quoted(max + 1), &ring),
            "/sn",
            &format!("outside the {word} ring"),
        );
    }
    at(
        &frame("1", r#","sn_resolution":"9bit""#),
        "/sn_resolution",
        "not a resolution",
    );
    at(
        r#"{"message":"open_ack","lease_ms":0,"initial_sn":128,"sn_resolution":"8bit"}"#,
        "/initial_sn",
        "at most 127",
    );
    // Without a ring any u64 is written, and one past u64 is not a u64.
    assert!(build(&frame(&quoted(u64::MAX), ""), Framing::Datagram).is_ok());
    at(
        &frame("18446744073709551616", ""),
        "/sn",
        "does not fit in 64 bits",
    );
    at(&frame("-1", ""), "/sn", "not a plain unsigned");

    at(
        r#"{"message":"frame","reliable":true,"sn":1,"priority":8}"#,
        "/priority",
        "largest value is 7",
    );
    at(
        r#"{"message":"close","reason":256,"session":true}"#,
        "/reason",
        "largest value is 255",
    );
    at(
        r#"{"message":"close","reason":1}"#,
        "",
        "`session` is required",
    );
    at(
        r#"{"message":"open_syn","lease_ms":1500,"lease_unit":"s","initial_sn":0,"cookie":""}"#,
        "/lease_unit",
        "whole number of seconds",
    );
    at(
        r#"{"message":"open_syn","lease_ms":1,"lease_unit":"h","initial_sn":0,"cookie":""}"#,
        "/lease_unit",
        "not a lease unit",
    );
    at(
        r#"{"message":"open_ack","lease_ms":1,"initial_sn":0,"cookie":""}"#,
        "/cookie",
        "unknown key",
    );
    at(
        r#"{"message":"open_syn","lease_ms":1,"initial_sn":0}"#,
        "",
        "`cookie` is required",
    );
    at(r#"{"message":"join"}"#, "/message", "later work");
    at(r#"{"message":"oam"}"#, "/message", "later work");
    at(r#"{"message":"scout"}"#, "/message", "names no message");
    at(r#"{"message":7}"#, "/message", "expected a string");
    at(r#"[]"#, "", "expected an object");
    at(
        r#"{"message":"keep_alive","reason":1}"#,
        "/reason",
        "unknown key",
    );
    at(
        r#"{"message":"frame","reliable":"yes","sn":1}"#,
        "/reliable",
        "expected true or false",
    );
    at(
        r#"{"message":"frame","reliable":true,"sn":1,"payload":"0g"}"#,
        "/payload",
        "not hexadecimal",
    );
    let (offset, _) = refused("{\"message\":");
    assert!(
        offset.starts_with('@'),
        "text that is not JSON is refused by byte: {offset}"
    );
}

/// A body that does not fit the framing is refused as such, with no description
/// position (the description is fine), and the other framings still build it.
#[test]
fn a_body_longer_than_the_prefix_holds_is_refused_by_the_framing() {
    let big = "ab".repeat(65_536);
    let json = format!(r#"{{"message":"frame","reliable":true,"sn":1,"payload":"{big}"}}"#);
    assert!(matches!(
        build(&json, Framing::TcpStream),
        Err(BuildError::Unit(why)) if why.contains("65535")
    ));
    assert!(build(&json, Framing::LowLatencyStream).is_ok());
    assert!(build(&json, Framing::Datagram).is_ok());
    let doc = build_document(&json, Framing::TcpStream);
    assert!(doc.contains("\"ok\":false"), "{doc}");
    assert!(!doc.contains("description_path"), "{doc}");
}

// --------------------------------------------- 4. the report reproduces bytes

/// The place a row's bytes are in a unit.
fn at_of(b: &Built, row: &Row) -> usize {
    match row.relative_to {
        RelativeTo::Unit => row.offset,
        RelativeTo::Body => b.prefix_bytes + row.offset,
    }
}

/// A VLE of `value` in exactly `width` bytes, written as a caller holding only
/// the report would: seven bits at a time, the ninth byte raw.
fn vle_in(width: usize, mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    for _ in 0..width - 1 {
        out.push((value & 0x7F) as u8 | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
    out
}

/// The unit with `row` replaced by `new`, using only what the report says: the
/// offset, the width, the encoding and the bit mask.
fn replaced(b: &Built, row: &Row, new: u64) -> Vec<u8> {
    let mut unit = b.unit.clone();
    let at = at_of(b, row);
    match (row.bit_mask, row.encoding) {
        (Some(mask), _) => {
            let shift = mask.trailing_zeros();
            unit[at] = (unit[at] & !mask) | (((new as u8) << shift) & mask);
        }
        (None, Encoding::Fixed) => {
            unit[at..at + row.width].copy_from_slice(&new.to_le_bytes()[..row.width]);
        }
        (None, Encoding::Vle) => {
            unit[at..at + row.width].copy_from_slice(&vle_in(row.width, new));
        }
    }
    unit
}

fn shape(rows: &[Row]) -> Vec<(&str, usize, usize, Kind)> {
    rows.iter()
        .map(|r| (r.name.as_str(), r.offset, r.width, r.kind))
        .collect()
}

/// Replace every numeric row of every built message with another value that
/// keeps its width, using only the report: the bytes outside the row are
/// untouched, and the message reads back with that one field changed. A row
/// whose value decides how the REST of the message is read (a flag that says a
/// part follows, a length, the message id, an extension's encoding) may change
/// the reading of the rest, and is then required to be one of those.
#[test]
fn a_replacement_made_from_the_report_alone_changes_only_that_field() {
    let mut replaced_rows = 0usize;
    let mut structural = 0usize;
    for case in corpus() {
        for framing in Framing::ALL {
            let b = built(&case.json, framing);
            for r in &b.layout {
                let Some(current) = r.value else { continue };
                let (min, max) = (r.min.expect("min"), r.max.expect("max"));
                let new = if current != max { max } else { min };
                if new == current {
                    continue; // a one-valued field has nothing to change to
                }
                let unit = replaced(&b, r, new);

                // (1) Only the row's own bits moved.
                let at = at_of(&b, r);
                for (i, (was, now)) in b.unit.iter().zip(&unit).enumerate() {
                    let inside = i >= at && i < at + r.width;
                    if !inside {
                        assert_eq!(was, now, "{}: `{}` moved byte {i}", case.label, r.name);
                    } else if let (Some(mask), true) = (r.bit_mask, i == at) {
                        assert_eq!(
                            was & !mask,
                            now & !mask,
                            "{}: `{}` moved other bits",
                            case.label,
                            r.name
                        );
                    }
                }

                // (2) The report of the replaced unit: the prefix is read from
                // the unit like everything else, so replacing it changes the
                // row and nothing else.
                replaced_rows += 1;
                let reread = layout(&unit, framing, case.ring);
                let same_shape = reread
                    .as_ref()
                    .map(|rows| shape(rows) == shape(&b.layout))
                    .unwrap_or(false);
                if same_shape {
                    let rows = reread.expect("checked");
                    for (before, after) in b.layout.iter().zip(&rows) {
                        if before.name == r.name {
                            // For a bit-field the reading is the dissector's,
                            // and `stored` is the number written.
                            assert_eq!(
                                after.stored.or(after.value),
                                Some(new),
                                "{}: `{}` should read back as {new}",
                                case.label,
                                r.name
                            );
                        } else if before.carrier.as_ref() == r.carrier.as_ref()
                            && before.carrier.is_some()
                            && before.bit_mask != r.bit_mask
                        {
                            // A sibling bit-field of the same byte keeps its bits.
                            assert_eq!(
                                before.stored, after.stored,
                                "{}: `{}`",
                                case.label, before.name
                            );
                        } else if before.carrier.as_deref() == Some(r.name.as_str())
                            || r.carrier.as_deref() == Some(before.name.as_str())
                        {
                            // The byte and the bit-fields in it are one thing
                            // seen twice: replacing either moves the other.
                        } else if before.carrier.is_none() && before.value.is_some() {
                            assert_eq!(
                                before.value, after.value,
                                "{}: replacing `{}` changed `{}`",
                                case.label, r.name, before.name
                            );
                        }
                    }
                } else {
                    structural += 1;
                    // A byte that carries bit-fields holds, among them, the
                    // ones that decide the shape.
                    let carries_fields = b
                        .layout
                        .iter()
                        .any(|x| x.carrier.as_deref() == Some(r.name.as_str()));
                    let allowed = carries_fields
                        || matches!(r.kind, Kind::Length | Kind::Flag)
                        || r.name == "mid"
                        || r.name.ends_with("encoding");
                    assert!(
                        allowed,
                        "{}: replacing `{}` ({:?}) changed the shape of the message",
                        case.label, r.name, r.kind
                    );
                }
            }
        }
    }
    assert!(
        replaced_rows > 2_000,
        "only {replaced_rows} replacements ran"
    );
    assert!(
        structural > 100,
        "only {structural} structural replacements ran"
    );
}

/// The prefix row is read from the unit's own bytes, so a prefix that disagrees
/// with its body is reported as it stands and not as it should be.
#[test]
fn the_prefix_row_reports_the_prefix_on_the_wire() {
    let b = built(
        r#"{"message":"frame","reliable":true,"sn":5,"payload":"dead"}"#,
        Framing::TcpStream,
    );
    assert_eq!(row(&b, "unit_length").value, Some(b.body.len() as u64));
    let mut unit = b.unit.clone();
    unit[0] = 0x12;
    unit[1] = 0x34;
    let rows = layout(&unit, Framing::TcpStream, None).expect("a damaged prefix still reads");
    let announced = rows.iter().find(|r| r.name == "unit_length").expect("row");
    assert_eq!(announced.value, Some(0x3412));
    assert_eq!(announced.measures.as_deref(), Some("body"));
    // And a unit too short for its prefix cannot be reported at all.
    assert!(matches!(
        layout(&[0x01], Framing::LowLatencyStream, None),
        Err(crate::transport_layout::LayoutError::Unreadable(_))
    ));
}

/// A byte string is replaced by bytes of the same width the same way, and the
/// row after it does not move.
#[test]
fn a_byte_string_is_replaced_in_place_by_the_reported_width() {
    let b = built(
        r#"{"message":"init_ack","version":5,"whatami":"peer","zid":"a0a1a2a3","cookie":"aabbcc"}"#,
        Framing::TcpStream,
    );
    let cookie = row(&b, "cookie");
    assert_eq!((cookie.offset, cookie.width), (b.body.len() - 3, 3));
    let mut unit = b.unit.clone();
    let at = b.prefix_bytes + cookie.offset;
    unit[at..at + cookie.width].copy_from_slice(&[1, 2, 3]);
    let after = layout(&unit, Framing::TcpStream, None).expect("layout");
    assert_eq!(shape(&after), shape(&b.layout));
    assert_eq!(&unit[at..], &[1, 2, 3]);
}

// ----------------------------------------------- 5. what the report says

fn tree_json_spans(body: &[u8]) -> Vec<(String, usize, usize)> {
    let root = dissect_transport_message(body, 0).expect("dissects");
    let mut out = Vec::new();
    fn walk(f: &Field, out: &mut Vec<(String, usize, usize)>) {
        out.push((f.name.to_string(), f.span.start, f.span.end));
        if let FieldValue::Nested(children) = &f.value {
            for c in children {
                walk(c, out);
            }
        }
    }
    walk(&root, &mut out);
    out
}

/// The report's offsets are the dissector's: every byte-owning top-level row
/// has the span the tree gives its field.
#[test]
fn the_reports_offsets_are_the_dissectors_spans() {
    for case in corpus() {
        let b = built(&case.json, Framing::TcpStream);
        let spans = tree_json_spans(&b.body);
        for r in b
            .layout
            .iter()
            .filter(|r| r.relative_to == RelativeTo::Body)
        {
            if r.name.contains('[') || r.name.ends_with("_reserved") {
                continue;
            }
            let hit = spans
                .iter()
                .any(|(n, s, e)| *n == r.name && *s == r.offset && *e == r.offset + r.width);
            assert!(
                hit,
                "{}: `{}` is not a span of the tree: {spans:?}",
                case.label, r.name
            );
        }
    }
}

#[test]
fn rows_have_unique_names_and_tile_the_body() {
    for case in corpus() {
        for framing in Framing::ALL {
            let b = built(&case.json, framing);
            let mut seen: Vec<&str> = Vec::new();
            for r in &b.layout {
                assert!(
                    !seen.contains(&r.name.as_str()),
                    "{}: `{}` twice",
                    case.label,
                    r.name
                );
                seen.push(&r.name);
            }
            let mut next = 0;
            for r in b
                .layout
                .iter()
                .filter(|r| r.relative_to == RelativeTo::Body && r.carrier.is_none())
            {
                assert_eq!(r.offset, next, "{}: `{}`", case.label, r.name);
                next += r.width;
            }
            assert_eq!(next, b.body.len(), "{}", case.label);
            assert_eq!(
                b.layout.first().map(|r| r.relative_to),
                Some(if framing == Framing::Datagram {
                    RelativeTo::Body
                } else {
                    RelativeTo::Unit
                }),
                "{}",
                case.label
            );
        }
    }
}

/// The range a VLE row says keeps its width, against the buckets of the format
/// written out from its definition and not asked of the codec: a VLE takes seven
/// bits per byte, so `w` bytes hold `2^(7(w-1))` to `2^(7w) - 1`, except that the
/// ninth byte carries eight bits and ends at the top of a `u64`
/// (`commons/zenoh-codec/src/core/zint.rs` @ `const fn vle_len(x: u64) -> usize {`).
/// The report must say exactly
/// that for a sequence number of each width, and the value at each end must
/// build to that width while one past the top builds to the next.
#[test]
fn a_vle_row_says_the_range_that_keeps_its_width() {
    for width in 1..=9usize {
        let lo: u64 = if width == 1 {
            0
        } else {
            1u64 << (7 * (width - 1))
        };
        let hi: u64 = if width == 9 {
            u64::MAX
        } else {
            (1u64 << (7 * width)) - 1
        };
        for sn in [lo, hi] {
            let b = built(
                &format!(
                    r#"{{"message":"frame","reliable":true,"sn":{}}}"#,
                    quoted(sn)
                ),
                Framing::Datagram,
            );
            let r = row(&b, "sn");
            assert_eq!(r.width, width, "sn {sn}");
            assert_eq!((r.min, r.max), (Some(lo), Some(hi)), "sn {sn}");
        }
        if width < 9 {
            let b = built(
                &format!(
                    r#"{{"message":"frame","reliable":true,"sn":{}}}"#,
                    quoted(hi + 1)
                ),
                Framing::Datagram,
            );
            assert_eq!(
                row(&b, "sn").width,
                width + 1,
                "one past the top of {width}"
            );
        }
    }
}

/// Offsets typed by hand from the wire format, for a Frame with a QoS
/// extension: they are the same ones the report derives.
#[test]
fn the_offsets_of_a_frame_follow_the_vle_width_of_its_sn() {
    for (sn, width) in [(5u64, 1usize), (300, 2), (1 << 20, 3), (u64::MAX, 9)] {
        let b = built(
            &format!(
                r#"{{"message":"frame","reliable":true,"sn":{},"priority":3,"payload":"dead"}}"#,
                quoted(sn)
            ),
            Framing::TcpStream,
        );
        let r = |name: &str| (row(&b, name).offset, row(&b, name).width);
        assert_eq!(r("header"), (0, 1));
        assert_eq!(r("sn"), (1, width));
        assert_eq!(r("extensions[0].header"), (1 + width, 1));
        assert_eq!(r("extensions[0].value"), (2 + width, 1));
        assert_eq!(r("payload"), (3 + width, 2));
        let sn_row = row(&b, "sn");
        assert_eq!(sn_row.encoding, Encoding::Vle);
        assert_eq!(sn_row.kind, Kind::SequenceNumber);
        assert_eq!(vle_width(sn), width);
        let (lo, hi) = vle_range(width).expect("a width");
        assert_eq!((sn_row.min, sn_row.max), (Some(lo), Some(hi)));
    }
}

/// The reserved bits are the complement of what the message's fields own, per
/// message: this is the table the format has (INIT's `cbyte` and `sn_res` in
/// `commons/zenoh-protocol/src/transport/init.rs` @ `|zid_len|x|x|wai|`, the
/// header flags in `commons/zenoh-protocol/src/transport/frame.rs` @
/// `pub const R: u8 = 1 << 5;`, and the reserved bits of Close and KeepAlive in
/// `commons/zenoh-protocol/src/transport/keepalive.rs` @
/// `// pub const X: u8 = 1 << 6; // 0x40       Reserved`).
#[test]
fn the_reserved_bits_are_what_no_field_of_the_message_owns() {
    let reserved = |json: &str| -> Vec<(String, u8)> {
        built(json, Framing::Datagram)
            .layout
            .iter()
            .filter(|r| r.kind == Kind::Reserved)
            .map(|r| (r.name.clone(), r.bit_mask.expect("mask")))
            .collect()
    };
    let none: Vec<(String, u8)> = vec![];
    assert_eq!(
        reserved(r#"{"message":"frame","reliable":true,"sn":1}"#),
        vec![("header_reserved".to_string(), 0x40)]
    );
    assert_eq!(
        reserved(r#"{"message":"fragment","reliable":true,"more":false,"sn":1}"#),
        none
    );
    assert_eq!(
        reserved(r#"{"message":"close","reason":0,"session":true}"#),
        vec![("header_reserved".to_string(), 0x40)]
    );
    assert_eq!(
        reserved(r#"{"message":"keep_alive"}"#),
        vec![("header_reserved".to_string(), 0x60)]
    );
    assert_eq!(
        reserved(r#"{"message":"open_syn","lease_ms":1,"initial_sn":0,"cookie":""}"#),
        none
    );
    assert_eq!(
        reserved(
            r#"{"message":"init_syn","version":5,"whatami":"peer","zid":"01",
               "resolution":{"frame_sn":"8bit","request_id":"8bit"},"batch_size":1}"#
        ),
        vec![
            ("cbyte_reserved".to_string(), 0x0C),
            ("sn_res_reserved".to_string(), 0xF0)
        ]
    );
    // And the extension header owns all eight bits.
    assert_eq!(
        reserved(
            r#"{"message":"open_ack","lease_ms":1,"initial_sn":0,"extensions":[{"id":1,"unit":true}]}"#
        ),
        none
    );
}

/// `zid_len` stores the length minus one, and says so.
#[test]
fn a_length_held_in_bits_reports_what_is_stored_beside_what_it_reads_as() {
    let b = built(
        r#"{"message":"init_syn","version":5,"whatami":"peer","zid":"01020304"}"#,
        Framing::Datagram,
    );
    let zid_len = row(&b, "zid_len");
    assert_eq!(zid_len.kind, Kind::Length);
    assert_eq!((zid_len.value, zid_len.stored), (Some(4), Some(3)));
    assert_eq!(zid_len.bit_mask, Some(0xF0));
    assert_eq!(zid_len.carrier.as_deref(), Some("cbyte"));
    assert_eq!(zid_len.measures.as_deref(), Some("zid"));
    assert_eq!((zid_len.min, zid_len.max), (Some(0), Some(15)));
}

#[test]
fn a_length_names_what_it_counts() {
    let b = built(
        r#"{"message":"init_ack","version":5,"whatami":"peer","zid":"01","cookie":"aabb",
           "extensions":[{"id":8,"zbuf":"6162"}]}"#,
        Framing::TcpStream,
    );
    assert_eq!(row(&b, "unit_length").measures.as_deref(), Some("body"));
    assert_eq!(row(&b, "cookie_len").measures.as_deref(), Some("cookie"));
    assert_eq!(
        row(&b, "extensions[0].value_len").measures.as_deref(),
        Some("extensions[0].value")
    );
    let lengths: Vec<&str> = b
        .layout
        .iter()
        .filter(|r| r.kind == Kind::Length)
        .map(|r| r.name.as_str())
        .collect();
    assert_eq!(
        lengths,
        [
            "unit_length",
            "zid_len",
            "cookie_len",
            "extensions[0].value_len"
        ]
    );
}

/// Question 2 of the claim: the resolution bounds the sequence numbers, and so
/// the widest their VLE can become; nothing else in a transport message changes
/// width with it.
#[test]
fn the_resolution_bounds_the_vle_width_of_each_sequence_number() {
    for (word, max, widest) in [
        ("8bit", 127u64, 1usize),
        ("16bit", 16_383, 2),
        ("32bit", 268_435_455, 4),
        ("64bit", (1 << 63) - 1, 9),
    ] {
        for json in [
            format!(r#"{{"message":"frame","reliable":true,"sn":0,"sn_resolution":"{word}"}}"#),
            format!(
                r#"{{"message":"fragment","reliable":true,"more":false,"sn":0,"sn_resolution":"{word}"}}"#
            ),
            format!(
                r#"{{"message":"open_ack","lease_ms":0,"initial_sn":0,"sn_resolution":"{word}"}}"#
            ),
        ] {
            let b = built(&json, Framing::Datagram);
            let rows: Vec<&Row> = b
                .layout
                .iter()
                .filter(|r| r.kind == Kind::SequenceNumber)
                .collect();
            assert_eq!(rows.len(), 1, "{json}");
            assert_eq!(rows[0].ring_max, Some(max), "{json}");
            assert_eq!(rows[0].ring_max_width, Some(widest), "{json}");
            // Every other row is blind to the ring.
            assert!(
                b.layout
                    .iter()
                    .filter(|r| r.kind != Kind::SequenceNumber)
                    .all(|r| r.ring_max.is_none() && r.ring_max_width.is_none()),
                "{json}"
            );
        }
    }
    // Without a ring the report does not invent one.
    let b = built(
        r#"{"message":"frame","reliable":true,"sn":0}"#,
        Framing::Datagram,
    );
    assert_eq!(row(&b, "sn").ring_max, None);
}

/// An INIT's own `resolution` is a field of the message, not the context of a
/// sequence number: it does not bound anything in the INIT.
#[test]
fn an_inits_resolution_is_a_field_and_not_a_ring() {
    let b = built(
        r#"{"message":"init_syn","version":5,"whatami":"peer","zid":"01",
           "resolution":{"frame_sn":"16bit","request_id":"32bit"},"batch_size":9}"#,
        Framing::Datagram,
    );
    assert!(b.layout.iter().all(|r| r.ring_max.is_none()));
    let frame = row(&b, "sn_res_frame_sn");
    let request = row(&b, "sn_res_request_id");
    assert_eq!((frame.bit_mask, frame.stored), (Some(0x03), Some(1)));
    assert_eq!((request.bit_mask, request.stored), (Some(0x0C), Some(2)));
}

// ------------------------------------------------ 6. the table is held

/// The generated codecs' field names, read out of the generated sources.
fn codec_fields(source: &str, strukt: &str) -> Vec<String> {
    let head = format!("pub struct {strukt}");
    let start = source.find(&head).unwrap_or_else(|| panic!("no `{head}`"));
    let open = source[start..].find('{').expect("a body") + start;
    let close = source[open..].find("\n}").expect("an end") + open;
    source[open..close]
        .lines()
        .filter_map(|l| l.trim().strip_prefix("pub "))
        .filter_map(|l| l.split(':').next())
        .map(|n| n.trim().to_string())
        .collect()
}

/// Every field of every codec the door writes through has a row in the
/// classification table, under its own name or a declared rename, and the kind
/// the name implies: a `*len` field is a length, an `sn` is a sequence number.
#[test]
fn the_kind_table_covers_every_field_of_the_generated_codecs() {
    let codecs: [(&str, &str, &str); 8] = [
        (
            include_str!("../../../out/wz-codecs/init_body.rs"),
            "InitBody",
            "init_body",
        ),
        (
            include_str!("../../../out/wz-codecs/open_body.rs"),
            "OpenBody",
            "open_body",
        ),
        (
            include_str!("../../../out/wz-codecs/close.rs"),
            "Close",
            "close",
        ),
        (
            include_str!("../../../out/wz-codecs/frame.rs"),
            "Frame",
            "frame",
        ),
        (
            include_str!("../../../out/wz-codecs/fragment.rs"),
            "Fragment",
            "fragment",
        ),
        (
            include_str!("../../../out/wz-codecs/stream_envelope.rs"),
            "StreamEnvelope",
            "stream_envelope",
        ),
        (
            include_str!("../../../out/wz-codecs/ext_zbuf.rs"),
            "ExtZbuf",
            "ext_zbuf",
        ),
        (
            include_str!("../../../out/wz-codecs/ext_zint.rs"),
            "ExtZint",
            "ext_zint",
        ),
    ];
    // A codec field that is carried by a differently named row, and the row.
    // `payload_len` is the stream prefix, a row of the unit and not of the body;
    // an `ExtEntry`'s `header` is the entry's header row.
    let renames: [(&str, &str); 1] = [("payload_len", "unit_length")];
    let mut covered = 0usize;
    for (source, strukt, file) in codecs {
        let fields = codec_fields(source, strukt);
        assert!(!fields.is_empty(), "{file}: no fields read");
        for field in fields {
            let name = renames
                .iter()
                .find(|(f, _)| *f == field)
                .map(|(_, to)| *to)
                .unwrap_or(field.as_str());
            if name == "unit_length" {
                // The prefix row is not in the leaf table: it is built from the
                // framing. Its kind is the one the name implies.
                let b = built(r#"{"message":"keep_alive"}"#, Framing::TcpStream);
                assert_eq!(row(&b, "unit_length").kind, Kind::Length);
                covered += 1;
                continue;
            }
            let spec = LEAVES
                .iter()
                .find(|l| l.name == name)
                .unwrap_or_else(|| panic!("{file}.{field} has no row in the classification table"));
            if name.ends_with("len") {
                assert_eq!(spec.kind, Kind::Length, "{file}.{field}");
            }
            if name == "sn" || name.ends_with("_sn") {
                assert_eq!(spec.kind, Kind::SequenceNumber, "{file}.{field}");
                assert_eq!(spec.encoding, Encoding::Vle, "{file}.{field}");
            }
            covered += 1;
        }
    }
    assert!(covered >= 18, "only {covered} codec fields were checked");
    // And the extension entry's own header is a leaf the table classifies.
    assert!(codec_fields(
        include_str!("../../../out/wz-codecs/ext_entry.rs"),
        "ExtEntry"
    )
    .contains(&"header".to_string()));
}

/// Held against the dissector from the other side: every leaf and every
/// bit-field name in the table is produced by some message of the corpus, and
/// every row the corpus produces is a name the table holds.
#[test]
fn the_table_and_the_corpus_hold_each_other() {
    fn strip(name: &str) -> &str {
        name.rsplit('.').next().unwrap_or(name)
    }
    let mut leaf_rows: Vec<String> = Vec::new();
    let mut alias_rows: Vec<String> = Vec::new();
    for case in corpus() {
        let b = built(&case.json, Framing::TcpStream);
        for r in &b.layout {
            if r.name == "unit_length" {
                continue;
            }
            let name = strip(&r.name).to_string();
            if r.kind == Kind::Reserved {
                continue;
            }
            if r.carrier.is_some() {
                alias_rows.push(name);
            } else {
                leaf_rows.push(name);
            }
        }
    }
    for set in [&mut leaf_rows, &mut alias_rows] {
        set.sort();
        set.dedup();
    }
    let mut leaves: Vec<String> = classified_leaf_names()
        .iter()
        .map(|s| s.to_string())
        .collect();
    leaves.sort();
    assert_eq!(
        leaf_rows, leaves,
        "leaf names the corpus produces vs the table"
    );
    let mut aliases: Vec<String> = classified_alias_names()
        .iter()
        .map(|s| s.to_string())
        .collect();
    aliases.sort();
    assert_eq!(
        alias_rows, aliases,
        "bit-field names the corpus produces vs the table"
    );
}

/// What the dissector emits at the header of an extension entry beyond the four
/// bit-fields is a READING of the body or a name, and is the only thing the
/// report skips: nothing else the walker emits is dropped.
#[test]
fn nothing_the_walker_emits_is_dropped_but_readings_of_an_extension_body() {
    for case in corpus() {
        let b = built(&case.json, Framing::Datagram);
        let root = dissect_transport_message(&b.body, 0).expect("dissects");
        let FieldValue::Nested(top) = &root.value else {
            panic!("a message is a group")
        };
        let mut dropped: Vec<String> = Vec::new();
        for child in top {
            let accounted = b.layout.iter().any(|r| r.name == child.name.as_ref())
                || matches!(child.name.as_ref(), "extensions");
            if !accounted {
                dropped.push(child.name.to_string());
            }
        }
        assert!(
            dropped.is_empty(),
            "{}: the report drops {dropped:?}",
            case.label
        );
        for child in top.iter().filter(|c| c.name == "extensions") {
            let FieldValue::Nested(entries) = &child.value else {
                continue;
            };
            for (i, entry) in entries.iter().enumerate() {
                let FieldValue::Nested(parts) = &entry.value else {
                    continue;
                };
                let header_span = parts.first().expect("a header").span;
                for part in parts {
                    let accounted = b
                        .layout
                        .iter()
                        .any(|r| r.name == format!("extensions[{i}].{}", part.name));
                    let is_reading = part.span != header_span && !accounted
                        || (part.name == "ext_name" && part.span == header_span);
                    assert!(
                        accounted || is_reading || matches!(part.value, FieldValue::Nested(_)),
                        "{}: extension {i} part `{}` is neither a row nor a reading",
                        case.label,
                        part.name
                    );
                }
            }
        }
    }
}

// --------------------------------------- 7. the closed vocabularies, walked

#[test]
fn the_closed_vocabularies_are_walked_and_declared() {
    use crate::doc_revision::newest;
    let words = |names: Vec<&'static str>| -> Vec<String> {
        let mut v: Vec<String> = names.into_iter().map(String::from).collect();
        v.sort();
        v
    };
    let shape = newest(TRANSPORT_BUILD).expect("declared");
    assert_eq!(shape.revision, 1);
    assert_eq!(shape.families.len(), TRANSPORT_BUILD_R1_FAMILIES.len());
    for (key, walked) in [
        ("kind", Kind::names()),
        ("encoding", Encoding::names()),
        ("relative_to", RelativeTo::names()),
    ] {
        let declared: Vec<String> = shape
            .families
            .iter()
            .find(|f| f.key == key)
            .unwrap_or_else(|| panic!("no family `{key}`"))
            .values
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(declared, words(walked), "{TRANSPORT_BUILD}.{key}");
    }

    // Every word is used by some row of the corpus, and no row uses another.
    let mut kinds: Vec<&str> = Vec::new();
    let mut encodings: Vec<&str> = Vec::new();
    let mut origins: Vec<&str> = Vec::new();
    for case in corpus() {
        for framing in Framing::ALL {
            for r in &built(&case.json, framing).layout {
                kinds.push(r.kind.word());
                encodings.push(r.encoding.word());
                origins.push(r.relative_to.word());
            }
        }
    }
    for (used, walked) in [
        (&mut kinds, Kind::names()),
        (&mut encodings, Encoding::names()),
        (&mut origins, RelativeTo::names()),
    ] {
        used.sort_unstable();
        used.dedup();
        let mut want = walked;
        want.sort_unstable();
        assert_eq!(*used, want);
    }
}

/// The vocabulary of resolution words is the dissector's own spelling.
#[test]
fn the_resolution_words_are_the_dissectors() {
    for (code, word) in RESOLUTION_WORDS.iter().enumerate() {
        let b = body_of(&format!(
            r#"{{"message":"init_syn","version":5,"whatami":"peer","zid":"01",
               "resolution":{{"frame_sn":"{word}","request_id":"{word}"}},"batch_size":1}}"#
        ));
        let root = dissect_transport_message(&b, 0).expect("dissects");
        assert_eq!(
            read(&root, "sn_res_frame_sn").value,
            FieldValue::Label((*word).into()),
            "code {code}"
        );
        assert_eq!(
            read(&root, "sn_res_request_id").value,
            FieldValue::Label((*word).into())
        );
    }
}

// ------------------------------------------------------ 8. the document

fn row_keys(doc: &str) -> Vec<Vec<String>> {
    let Json5Value::Object(top) = json5::parse(doc).expect("the document is JSON") else {
        panic!("a document is an object")
    };
    let Some((_, Json5Value::Array(rows))) = top.iter().find(|(k, _)| k == "layout") else {
        return Vec::new();
    };
    rows.iter()
        .map(|r| match r {
            Json5Value::Object(entries) => entries.iter().map(|(k, _)| k.clone()).collect(),
            other => panic!("a row is an object: {other:?}"),
        })
        .collect()
}

#[test]
fn the_documents_use_exactly_the_keys_the_registry_pins() {
    let mut keys: Vec<&str> = Vec::new();
    let mut docs: Vec<String> = Vec::new();
    for case in corpus() {
        docs.push(build_document(&case.json, Framing::TcpStream));
    }
    for broken in [
        "{\"message\":",
        r#"{"message":"frame","reliable":true,"sn":999,"sn_resolution":"8bit"}"#,
        r#"{"message":"scout"}"#,
    ] {
        docs.push(build_document(broken, Framing::Datagram));
    }
    let huge = format!(
        r#"{{"message":"frame","reliable":true,"sn":1,"payload":"{}"}}"#,
        "00".repeat(70_000)
    );
    docs.push(build_document(&huge, Framing::TcpStream));
    for doc in &docs {
        keys.extend(key_set(doc));
    }
    keys.sort_unstable();
    keys.dedup();
    assert_eq!(keys, TRANSPORT_BUILD_R1_KEYS, "{TRANSPORT_BUILD}");
    for doc in &docs {
        assert!(
            doc.starts_with(r#"{"document":{"name":"transport_build","revision":1}"#),
            "{doc}"
        );
    }
}

/// One shape for every row: the same fifteen keys in the same order, whatever
/// the row is, so a consumer never asks which kind of row it has before it
/// reads a key.
#[test]
fn every_row_has_every_key() {
    const ROW_KEYS: [&str; 15] = [
        "name",
        "kind",
        "offset",
        "width",
        "relative_to",
        "encoding",
        "value",
        "min",
        "max",
        "bit_mask",
        "carrier",
        "stored",
        "measures",
        "ring_max",
        "ring_max_width",
    ];
    let mut rows = 0usize;
    for case in corpus() {
        for framing in Framing::ALL {
            for keys in row_keys(&build_document(&case.json, framing)) {
                assert_eq!(keys, ROW_KEYS, "{}", case.label);
                rows += 1;
            }
        }
    }
    assert!(rows > 2_000, "{rows} rows");
}

/// The integer rule: a cell that can reach 2^53 is a number below it and a
/// decimal string beyond it.
#[test]
fn a_cell_past_two_to_the_fifty_third_is_a_string() {
    let small = build_document(
        r#"{"message":"frame","reliable":true,"sn":5}"#,
        Framing::Datagram,
    );
    assert!(small.contains(r#""name":"sn","kind":"sequence_number","offset":1,"width":1,"relative_to":"body","encoding":"vle","value":5,"min":0,"max":127"#), "{small}");
    let big = build_document(
        &format!(
            r#"{{"message":"frame","reliable":true,"sn":"{}"}}"#,
            u64::MAX
        ),
        Framing::Datagram,
    );
    assert!(
        big.contains(
            r#""width":9,"relative_to":"body","encoding":"vle","value":"18446744073709551615","min":"72057594037927936","max":"18446744073709551615""#
        ),
        "{big}"
    );
    let ring = build_document(
        r#"{"message":"frame","reliable":true,"sn":1,"sn_resolution":"64bit"}"#,
        Framing::Datagram,
    );
    assert!(
        ring.contains(r#""ring_max":"9223372036854775807","ring_max_width":9"#),
        "{ring}"
    );
}

#[test]
fn a_refusal_names_its_place_and_a_success_names_none() {
    let doc = build_document(
        r#"{"message":"frame","reliable":true,"sn":300,"sn_resolution":"8bit"}"#,
        Framing::Datagram,
    );
    assert!(
        doc.contains(r#""ok":false,"description_path":"/sn","reason":"#),
        "{doc}"
    );
    assert!(!doc.contains("\"layout\""), "{doc}");
    let ok = build_document(r#"{"message":"keep_alive"}"#, Framing::Datagram);
    assert!(ok.contains("\"ok\":true"), "{ok}");
    assert!(!ok.contains("description_"), "{ok}");
    assert!(ok.contains(r#""unit":"04","body":"04""#), "{ok}");
    let text = build_document("{\"message\":", Framing::Datagram);
    assert!(text.contains("\"description_offset\":"), "{text}");
}
