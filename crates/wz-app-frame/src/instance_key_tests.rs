// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Model tests of the instance keys, on a SYNTHETIC schema and frame profile.
//!
//! Every payload is laid by hand, field tag by field tag, and not by a writer
//! of this workspace: the keyer's reading of a field is checked against a
//! second reading of the wire format. The field names, numbers, values and the
//! profile are made up and unlike any deployment's.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::e2e_frame::Values;
use crate::e2e_profile::{DocError, Profile};
use crate::e2e_receiver::{Keying, Receiver, Status};
use crate::e2e_stream_sender::{SenderOptions, StreamSender};
use crate::instance_key::{
    judge, protect, Counts, Dropped, JudgeError, Judged, KeyValue, KeyedFrame, Keyer, LastOutcome,
    LastValues, Limits, NewError, ProtectError, RecordError, Refusal, Report, StorageTooSmall,
    DEFAULT_REPORT_INTERVAL_MS,
};
use crate::proto_schema::ProtoFile;

const SAMPLE: &str = r#"
syntax = "proto3";
package syn.keyed;

enum Lane {
  LANE_NONE = 0;
  LANE_WEST = 3;
  LANE_EAST = 8;
}

message Spot {
  Lane lane = 1;
  optional uint32 slot = 2;
}

message Sample {
  optional uint32 zone = 1;
  Lane lane = 2;
  Spot spot = 3;
  sint32 shift = 4;
  string tag = 5;
  repeated uint32 many = 6;
  bool flag = 7;
  bytes blob = 8;
  double level = 9;
  uint32 plain = 10;
  oneof pick {
    uint32 picked = 11;
  }
}
"#;

const OLD: &str = r#"
syntax = "proto2";
message Old {
  optional int32 code = 1;
}
"#;

/// A two-byte CRC first, the length, a cell whose one part is the sender, and
/// a one-byte counter last.
const PROFILE: &str = r#"{
  "name": "syn-keyed",
  "fields": [
    {"name": "crc", "bytes": 2},
    {"name": "length", "bytes": 2},
    {"name": "cell", "bytes": 2, "split": [{"name": "sender", "lsb": 0, "width": 16}]},
    {"name": "counter", "bytes": 1}
  ],
  "crc": {"field": "crc", "width": 16, "poly": "0x8BB7", "init": "0x0000",
          "refin": false, "refout": false, "xorout": "0x0000",
          "cover": ["length", "cell", "counter", "@payload"]},
  "length": {"field": "length", "counts": "frame"},
  "counter": {"field": "counter", "max_gap": 3, "timeout_ms": 100},
  "cell": {"field": "cell", "sender": "sender"}
}"#;

const HEADER: usize = 7;

const LIMITS: Limits = Limits {
    fields: 2,
    instances: 32,
};

fn files() -> [ProtoFile<'static>; 2] {
    [
        ProtoFile {
            name: "sample.proto",
            text: SAMPLE.as_bytes(),
        },
        ProtoFile {
            name: "old.proto",
            text: OLD.as_bytes(),
        },
    ]
}

fn keyer(description: &str) -> Keyer {
    Keyer::new(&files(), description, LIMITS).unwrap_or_else(|e| panic!("{e}\n{description}"))
}

fn refused(description: &str, limits: Limits) -> NewError {
    match Keyer::new(&files(), description, limits) {
        Ok(_) => panic!("a keyer was made of {description}"),
        Err(e) => e,
    }
}

fn refused_at(description: &str) -> String {
    match refused(description, LIMITS) {
        NewError::Description(DocError::Invalid { path, .. }) => path,
        other => panic!("refused as {other:?}, not at a place: {description}"),
    }
}

// ---- the wire, by hand ---------------------------------------------------

fn varint(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn put_varint(out: &mut Vec<u8>, number: u64, v: u64) {
    varint(number << 3, out);
    varint(v, out);
}

fn put_len(out: &mut Vec<u8>, number: u64, bytes: &[u8]) {
    varint((number << 3) | 2, out);
    varint(bytes.len() as u64, out);
    out.extend_from_slice(bytes);
}

fn zigzag32(v: i32) -> u64 {
    u64::from(((v << 1) ^ (v >> 31)) as u32)
}

fn zone_lane(zone: u64, lane: u64) -> Vec<u8> {
    let mut out = Vec::new();
    put_varint(&mut out, 1, zone);
    put_varint(&mut out, 2, lane);
    out
}

fn zone_only(zone: u64) -> Vec<u8> {
    let mut out = Vec::new();
    put_varint(&mut out, 1, zone);
    out
}

const ZONE_LANE: &str = r#"{
  "message": "syn.keyed.Sample",
  "fields": [
    {"path": "zone", "values": [5, 9, 40]},
    {"path": "lane", "values": [3, 8]}
  ]
}"#;

// ---- the index -----------------------------------------------------------

#[test]
fn every_combination_of_two_fields_is_its_place_in_the_product_row_major() {
    let mut k = keyer(ZONE_LANE);
    assert_eq!(k.instances(), 6);
    assert_eq!(k.fields(), 2);
    assert_eq!(k.message_name(), "syn.keyed.Sample");
    for (zi, zone) in [5u64, 9, 40].into_iter().enumerate() {
        for (li, lane) in [3u64, 8].into_iter().enumerate() {
            let want = zi * 2 + li;
            assert_eq!(
                k.index(&zone_lane(zone, lane), 0),
                Ok(want),
                "{zone} {lane}"
            );
            assert_eq!(
                k.values_of(want),
                Some(vec![
                    &KeyValue::Integer(i128::from(zone)),
                    &KeyValue::Integer(i128::from(lane))
                ])
            );
        }
    }
    assert_eq!(k.values_of(6), None);
    assert_eq!(k.counts(), Counts::default());
}

#[test]
fn the_order_of_the_product_is_the_descriptions_and_not_the_wires() {
    let k = keyer(
        r#"{"message": "syn.keyed.Sample", "fields": [
            {"path": "lane", "values": [8, 3]},
            {"path": "zone", "values": [5, 9, 40]}]}"#,
    );
    // Lane first, listed east before west; the payload writes the zone first.
    assert_eq!(k.instance_of(&zone_lane(5, 8)), Ok(0));
    assert_eq!(k.instance_of(&zone_lane(40, 8)), Ok(2));
    assert_eq!(k.instance_of(&zone_lane(5, 3)), Ok(3));
    assert_eq!(k.instance_of(&zone_lane(40, 3)), Ok(5));
}

#[test]
fn the_last_occurrence_of_a_field_is_its_value() {
    let k = keyer(ZONE_LANE);
    let mut payload = zone_lane(5, 3);
    put_varint(&mut payload, 1, 40);
    assert_eq!(k.instance_of(&payload), Ok(4));
}

#[test]
fn a_value_outside_the_list_is_dropped_counted_and_reported_at_a_bounded_rate() {
    let mut k = keyer(
        r#"{"message": "syn.keyed.Sample", "report_interval_ms": 100,
            "fields": [{"path": "zone", "values": [5, 9]}]}"#,
    );
    assert_eq!(k.report_interval_ms(), 100);
    let outside = zone_only(6);
    let dropped = |report: Option<u64>| Dropped {
        refusal: OUTSIDE,
        report: report.map(|dropped| Report {
            dropped,
            latest: OUTSIDE,
        }),
    };
    // The first drop is reported at once; the next within the interval is held.
    assert_eq!(k.index(&outside, 1_000), Err(dropped(Some(1))));
    assert_eq!(k.index(&outside, 1_010), Err(dropped(None)));
    // A sample in the list in between is indexed and reports nothing.
    assert_eq!(k.index(&zone_only(9), 1_050), Ok(1));
    // Once the interval has passed, the drop carries the ones held with it.
    assert_eq!(k.index(&outside, 1_100), Err(dropped(Some(2))));
    assert_eq!(k.flush(1_150), None, "nothing is held");
    // A drop of another reason is held the same way, and the report names it
    // as the latest.
    assert_eq!(
        k.index(&[0x08], 1_150),
        Err(Dropped {
            refusal: Refusal::Undecodable,
            report: None
        })
    );
    assert_eq!(k.flush(1_199), None, "the interval has not passed");
    assert_eq!(
        k.flush(1_200),
        Some(Report {
            dropped: 1,
            latest: Refusal::Undecodable
        })
    );
    assert_eq!(k.flush(5_000), None);
    assert_eq!(
        k.counts(),
        Counts {
            undecodable: 1,
            absent: 0,
            not_listed: 3,
        }
    );
}

const OUTSIDE: Refusal = Refusal::NotListed { field: 0 };

#[test]
fn a_clock_that_steps_back_starts_the_interval_again() {
    let mut k = keyer(
        r#"{"message": "syn.keyed.Sample", "report_interval_ms": 100,
            "fields": [{"path": "zone", "values": [5]}]}"#,
    );
    let outside = zone_only(6);
    assert!(k.index(&outside, 5_000).unwrap_err().report.is_some());
    assert_eq!(k.index(&outside, 10).unwrap_err().report, None);
    assert_eq!(k.flush(109), None);
    assert_eq!(
        k.flush(110),
        Some(Report {
            dropped: 1,
            latest: OUTSIDE
        })
    );
}

#[test]
fn an_interval_of_zero_reports_every_drop_and_the_default_is_stated() {
    let mut every = keyer(
        r#"{"message": "syn.keyed.Sample", "report_interval_ms": 0,
            "fields": [{"path": "zone", "values": [5]}]}"#,
    );
    for t in [0u64, 0, 1] {
        assert_eq!(
            every.index(&zone_only(6), t).unwrap_err().report,
            Some(Report {
                dropped: 1,
                latest: OUTSIDE
            })
        );
    }
    let default =
        keyer(r#"{"message": "syn.keyed.Sample", "fields": [{"path": "zone", "values": [5]}]}"#);
    assert_eq!(default.report_interval_ms(), DEFAULT_REPORT_INTERVAL_MS);
}

#[test]
fn an_absent_field_with_presence_is_refused_and_one_without_reads_as_its_default() {
    let mut k = keyer(ZONE_LANE);
    let mut lane_only = Vec::new();
    put_varint(&mut lane_only, 2, 3);
    // `zone` is `optional`: absent is a fact.
    assert_eq!(
        k.index(&lane_only, 0).unwrap_err().refusal,
        Refusal::Absent { field: 0 }
    );
    // `lane` has no presence: absent reads as 0, which this list does not hold.
    assert_eq!(
        k.index(&zone_only(9), 0).unwrap_err().refusal,
        Refusal::NotListed { field: 1 }
    );
    assert_eq!(
        k.counts(),
        Counts {
            undecodable: 0,
            absent: 1,
            not_listed: 1,
        }
    );
    let with_zero = keyer(
        r#"{"message": "syn.keyed.Sample", "fields": [
            {"path": "zone", "values": [5, 9]},
            {"path": "lane", "values": [3, 0]}]}"#,
    );
    assert_eq!(with_zero.instance_of(&zone_only(9)), Ok(3));
    // A string without presence reads as the empty string.
    let tag = keyer(
        r#"{"message": "syn.keyed.Sample", "fields": [{"path": "tag", "values": ["up", ""]}]}"#,
    );
    assert_eq!(tag.instance_of(&zone_only(9)), Ok(1));
}

#[test]
fn a_member_of_a_oneof_and_a_proto2_field_have_presence() {
    let picked = keyer(
        r#"{"message": "syn.keyed.Sample", "fields": [{"path": "picked", "values": [0, 4]}]}"#,
    );
    assert_eq!(
        picked.instance_of(&zone_only(5)),
        Err(Refusal::Absent { field: 0 })
    );
    let mut zero = Vec::new();
    put_varint(&mut zero, 11, 0);
    assert_eq!(picked.instance_of(&zero), Ok(0));

    let old = keyer(r#"{"message": "Old", "fields": [{"path": "code", "values": [0, -7]}]}"#);
    assert_eq!(old.instance_of(&[]), Err(Refusal::Absent { field: 0 }));
    let mut minus_seven = Vec::new();
    // An `int32` is written sign-extended to ten bytes.
    put_varint(&mut minus_seven, 1, (-7i64) as u64);
    assert_eq!(old.instance_of(&minus_seven), Ok(1));
}

#[test]
fn a_field_inside_a_message_field_is_read_through_its_holder_and_merged() {
    let k = keyer(
        r#"{"message": "syn.keyed.Sample", "fields": [{"path": "spot.lane", "values": [3, 8]}]}"#,
    );
    let spot = |lane: Option<u64>, slot: Option<u64>| {
        let mut inner = Vec::new();
        if let Some(lane) = lane {
            put_varint(&mut inner, 1, lane);
        }
        if let Some(slot) = slot {
            put_varint(&mut inner, 2, slot);
        }
        inner
    };
    let mut payload = Vec::new();
    put_len(&mut payload, 3, &spot(Some(8), None));
    assert_eq!(k.instance_of(&payload), Ok(1));
    // No holder: absent, whatever the leaf's own presence.
    assert_eq!(
        k.instance_of(&zone_only(5)),
        Err(Refusal::Absent { field: 0 })
    );
    // Two occurrences of the holder are one message: the lane of the first
    // stands when the second does not write one.
    let mut merged = Vec::new();
    put_len(&mut merged, 3, &spot(Some(3), None));
    put_len(&mut merged, 3, &spot(None, Some(2)));
    assert_eq!(k.instance_of(&merged), Ok(0));
    // A holder without the leaf: the lane reads as 0, not listed.
    let mut empty = Vec::new();
    put_len(&mut empty, 3, &spot(None, Some(2)));
    assert_eq!(k.instance_of(&empty), Err(Refusal::NotListed { field: 0 }));

    let slot = keyer(
        r#"{"message": "syn.keyed.Sample", "fields": [{"path": "spot.slot", "values": [2]}]}"#,
    );
    assert_eq!(slot.instance_of(&empty), Ok(0));
    assert_eq!(
        slot.instance_of(&payload),
        Err(Refusal::Absent { field: 0 })
    );
}

#[test]
fn a_string_and_a_signed_field_are_keyed_by_value() {
    let k = keyer(
        r#"{"message": "syn.keyed.Sample", "fields": [
            {"path": "tag", "values": ["north", "south"]},
            {"path": "shift", "values": [-2, {"range": [-1, 1]}, 0x10]}]}"#,
    );
    assert_eq!(k.instances(), 10);
    let payload = |tag: &str, shift: i32| {
        let mut out = Vec::new();
        put_len(&mut out, 5, tag.as_bytes());
        put_varint(&mut out, 4, zigzag32(shift));
        out
    };
    assert_eq!(k.instance_of(&payload("north", -2)), Ok(0));
    assert_eq!(k.instance_of(&payload("north", 1)), Ok(3));
    assert_eq!(k.instance_of(&payload("south", 16)), Ok(9));
    assert_eq!(
        k.instance_of(&payload("South", 0)),
        Err(Refusal::NotListed { field: 0 })
    );
    assert_eq!(
        k.instance_of(&payload("south", 2)),
        Err(Refusal::NotListed { field: 1 })
    );
    assert_eq!(
        k.values_of(9),
        Some(vec![
            &KeyValue::Text(String::from("south")),
            &KeyValue::Integer(16)
        ])
    );
}

#[test]
fn a_payload_that_is_not_a_message_of_the_schema_is_dropped_as_such() {
    let mut k = keyer(ZONE_LANE);
    // A tag with no value after it.
    assert_eq!(
        k.index(&[0x08], 0).unwrap_err().refusal,
        Refusal::Undecodable
    );
    assert_eq!(k.counts().undecodable, 1);
}

// ---- refusals of the description -----------------------------------------

#[test]
fn the_description_is_refused_at_the_place_it_is_wrong() {
    let one = |path: &str, values: &str| {
        format!(
            r#"{{"message": "syn.keyed.Sample", "fields": [{{"path": "{path}", "values": {values}}}]}}"#
        )
    };
    assert_eq!(
        refused_at(
            r#"{"message": "syn.keyed.Nothing", "fields": [{"path": "zone", "values": [1]}]}"#
        ),
        "/message"
    );
    assert_eq!(
        refused_at(r#"{"message": "syn.keyed.Lane", "fields": [{"path": "zone", "values": [1]}]}"#),
        "/message"
    );
    for bad in [
        "nothing",
        "many",
        "flag",
        "blob",
        "level",
        "spot",
        "zone.slot",
        "spot..lane",
        "",
    ] {
        assert_eq!(refused_at(&one(bad, "[1]")), "/fields/0/path", "{bad}");
    }
    assert_eq!(refused_at(&one("zone", "[-1]")), "/fields/0/values/0");
    assert_eq!(
        refused_at(&one("zone", "[0x100000000]")),
        "/fields/0/values/0"
    );
    assert_eq!(refused_at(&one("zone", "[1, \"2\"]")), "/fields/0/values/1");
    assert_eq!(refused_at(&one("zone", "[1.5]")), "/fields/0/values/0");
    assert_eq!(refused_at(&one("tag", "[\"a\", 2]")), "/fields/0/values/1");
    assert_eq!(refused_at(&one("zone", "[5, 5]")), "/fields/0/values/1");
    assert_eq!(
        refused_at(&one("zone", r#"[4, {"range": [3, 5]}]"#)),
        "/fields/0/values/1"
    );
    assert_eq!(
        refused_at(&one("zone", r#"[{"range": [5, 3]}]"#)),
        "/fields/0/values/0/range"
    );
    assert_eq!(
        refused_at(&one("zone", r#"[{"range": [5]}]"#)),
        "/fields/0/values/0/range"
    );
    assert_eq!(
        refused_at(&one("zone", r#"[{"range": [0, 1], "step": 2}]"#)),
        "/fields/0/values/0/step"
    );
    assert_eq!(refused_at(&one("zone", "[]")), "/fields/0/values");
    assert_eq!(
        refused_at(r#"{"message": "syn.keyed.Sample", "fields": []}"#),
        "/fields"
    );
    assert_eq!(
        refused_at(
            r#"{"message": "syn.keyed.Sample", "fields": [{"path": "zone", "valuez": [1]}]}"#
        ),
        "/fields/0/valuez"
    );
    assert_eq!(
        refused_at(r#"{"message": "syn.keyed.Sample", "keys": [], "fields": []}"#),
        "/keys"
    );
    assert_eq!(
        refused_at(
            r#"{"message": "syn.keyed.Sample", "report_interval_ms": -1,
                "fields": [{"path": "zone", "values": [1]}]}"#
        ),
        "/report_interval_ms"
    );
}

#[test]
fn the_builds_limits_and_the_schema_are_refused_by_name() {
    let three = r#"{"message": "syn.keyed.Sample", "fields": [
        {"path": "zone", "values": [1]},
        {"path": "lane", "values": [3]},
        {"path": "tag", "values": ["a"]}]}"#;
    assert_eq!(
        refused(three, LIMITS),
        NewError::TooManyFields {
            fields: 3,
            limit: 2
        }
    );
    let small = Limits {
        fields: 2,
        instances: 4,
    };
    assert_eq!(
        refused(ZONE_LANE, small),
        NewError::TooManyInstances { limit: 4 }
    );
    // A range wider than the limit is refused before it is written out.
    assert_eq!(
        refused(
            r#"{"message": "syn.keyed.Sample", "fields": [
                {"path": "plain", "values": [{"range": [0, 4294967295]}]}]}"#,
            LIMITS
        ),
        NewError::TooManyInstances { limit: 32 }
    );
    let broken = [ProtoFile {
        name: "broken.proto",
        text: b"message {",
    }];
    assert!(matches!(
        Keyer::new(&broken, ZONE_LANE, LIMITS),
        Err(NewError::Schema(_))
    ));
}

// ---- the last values -----------------------------------------------------

#[test]
fn the_last_value_of_each_instance_is_kept_in_the_callers_storage() {
    let mut last = LastValues::new(vec![0u8; 8], 2, 4).expect("room for two of four");
    assert_eq!((last.instances(), last.capacity()), (2, 4));
    assert_eq!(last.last(0), None);
    last.record(0, b"ab").expect("fits");
    last.record(1, b"wxyz").expect("fits");
    assert_eq!(last.last(0), Some(&b"ab"[..]));
    assert_eq!(last.last(1), Some(&b"wxyz"[..]));
    last.record(0, b"").expect("an empty value is a value");
    assert_eq!(last.last(0), Some(&b""[..]));
    assert_eq!(
        last.record(1, b"12345"),
        Err(RecordError::TooLong {
            len: 5,
            capacity: 4
        })
    );
    assert_eq!(
        last.last(1),
        Some(&b"wxyz"[..]),
        "a refused value keeps the one before"
    );
    assert_eq!(
        last.record(2, b"a"),
        Err(RecordError::NoSuchInstance {
            instance: 2,
            instances: 2
        })
    );
    assert_eq!(last.last(2), None);

    let mut borrowed = [0u8; 3];
    let mut on_slice = LastValues::new(&mut borrowed[..], 3, 1).expect("three of one");
    on_slice.record(2, b"q").expect("fits");
    assert_eq!(on_slice.last(2), Some(&b"q"[..]));

    assert_eq!(
        LastValues::new(vec![0u8; 7], 2, 4).unwrap_err(),
        StorageTooSmall {
            needed: Some(8),
            given: 7
        }
    );
    assert_eq!(
        LastValues::new(Vec::<u8>::new(), usize::MAX, 2).unwrap_err(),
        StorageTooSmall {
            needed: None,
            given: 0
        }
    );
}

// ---- the streams of the protection ---------------------------------------

fn profile() -> Profile {
    Profile::parse(PROFILE).expect("the synthetic profile is valid")
}

fn values() -> Values {
    Values::new().parts("cell", &[("sender", 0x2E1)])
}

fn sender(streams: usize) -> StreamSender {
    StreamSender::new(
        profile(),
        values(),
        SenderOptions {
            streams,
            ..SenderOptions::default()
        },
    )
    .expect("the sender is made")
}

fn receiver(keying: Keying) -> Receiver {
    Receiver::new(profile(), &values(), keying, None, 8).expect("the receiver is made")
}

/// No last values: the receiver's verdicts alone.
fn no_last() -> Option<&'static mut LastValues<Vec<u8>>> {
    None
}

const TWO_ZONES: &str =
    r#"{"message": "syn.keyed.Sample", "fields": [{"path": "zone", "values": [5, 9]}]}"#;

fn built(frame: KeyedFrame) -> (usize, Vec<u8>, u64) {
    match frame {
        KeyedFrame::Built { instance, frame } => (instance, frame.bytes, frame.counter),
        KeyedFrame::Dropped(d) => panic!("dropped: {d:?}"),
    }
}

#[test]
fn the_sender_counts_each_instance_on_its_own_stream() {
    let mut k = keyer(TWO_ZONES);
    let mut tx = sender(2);
    let counter = |k: &mut Keyer, tx: &mut StreamSender, zone: u64| {
        built(protect(k, tx, &zone_only(zone), 0).expect("protected")).2
    };
    assert_eq!(counter(&mut k, &mut tx, 5), 0);
    assert_eq!(counter(&mut k, &mut tx, 9), 0);
    assert_eq!(counter(&mut k, &mut tx, 5), 1);
    // A payload of no instance builds nothing and consumes no counter value.
    assert!(matches!(
        protect(&mut k, &mut tx, &zone_only(7), 0),
        Ok(KeyedFrame::Dropped(Dropped {
            refusal: Refusal::NotListed { field: 0 },
            ..
        }))
    ));
    assert_eq!(counter(&mut k, &mut tx, 5), 2);
    assert_eq!(counter(&mut k, &mut tx, 9), 1);
    assert_eq!(k.counts().not_listed, 1);

    let mut narrow = sender(1);
    assert!(matches!(
        protect(&mut k, &mut narrow, &zone_only(5), 0),
        Err(ProtectError::TooFewStreams {
            streams: 1,
            instances: 2
        })
    ));
}

#[test]
fn the_receiver_judges_each_instance_in_its_own_stream_and_keeps_its_last_value() {
    let mut tx_keyer = keyer(TWO_ZONES);
    let mut rx_keyer = keyer(TWO_ZONES);
    let mut tx = sender(2);
    let mut rx = receiver(Keying::Indexed { streams: 2 });
    let mut last = LastValues::new(vec![0u8; 2 * 8], 2, 8).expect("room");
    let mut frame_of = |zone: u64| {
        built(protect(&mut tx_keyer, &mut tx, &zone_only(zone), 0).expect("protected")).1
    };
    let five = [frame_of(5), frame_of(5), frame_of(5)];
    let nine = [frame_of(9), frame_of(9)];

    let mut judged =
        |frame: &[u8], now: u64| match judge(&mut rx_keyer, &mut rx, Some(&mut last), frame, now)
            .expect("judged")
        {
            Judged::Instance {
                instance,
                verdict,
                last,
            } => (instance, verdict.status, verdict.stream, last),
            Judged::Dropped(d) => panic!("dropped: {d:?}"),
        };
    // Interleaved, each instance is its own baseline and its own next frame;
    // judged in one stream, the second instance's first counter would be a
    // repetition of the first's.
    assert_eq!(
        judged(&five[0][..], 0),
        (0, Status::First, Some(0), LastOutcome::Recorded)
    );
    assert_eq!(
        judged(&nine[0][..], 1),
        (1, Status::First, Some(1), LastOutcome::Recorded)
    );
    assert_eq!(
        judged(&five[1][..], 2),
        (0, Status::Ok, Some(0), LastOutcome::Recorded)
    );
    assert_eq!(
        judged(&nine[1][..], 3),
        (1, Status::Ok, Some(1), LastOutcome::Recorded)
    );
    // A frame that is not intact is judged in its instance and changes nothing.
    let mut broken = five[2].clone();
    broken[0] ^= 0xFF;
    assert_eq!(
        judged(&broken[..], 4),
        (0, Status::Integrity, Some(0), LastOutcome::NotIntact)
    );
    assert_eq!(
        judged(&five[2][..], 5),
        (0, Status::Ok, Some(0), LastOutcome::Recorded)
    );
    assert_eq!(last.last(0), Some(&five[2][HEADER..]));
    assert_eq!(last.last(1), Some(&nine[1][HEADER..]));
}

#[test]
fn a_frame_of_no_instance_is_dropped_and_not_judged() {
    let mut tx_keyer = keyer(
        r#"{"message": "syn.keyed.Sample", "fields": [{"path": "zone", "values": [5, 9, 7]}]}"#,
    );
    let mut rx_keyer = keyer(TWO_ZONES);
    let mut tx = sender(3);
    let mut rx = receiver(Keying::Indexed { streams: 2 });
    let mut frame_of = |zone: u64| {
        built(protect(&mut tx_keyer, &mut tx, &zone_only(zone), 0).expect("protected")).1
    };
    let first = frame_of(5);
    let outside = frame_of(7);
    let second = frame_of(5);
    let status = |judged: Judged| match judged {
        Judged::Instance { verdict, .. } => Some(verdict.status),
        Judged::Dropped(_) => None,
    };
    assert_eq!(
        status(judge(&mut rx_keyer, &mut rx, no_last(), &first, 0).expect("judged")),
        Some(Status::First)
    );
    assert_eq!(
        judge(&mut rx_keyer, &mut rx, no_last(), &outside, 1).expect("judged"),
        Judged::Dropped(Dropped {
            refusal: OUTSIDE,
            report: Some(Report {
                dropped: 1,
                latest: OUTSIDE
            }),
        })
    );
    match judge(&mut rx_keyer, &mut rx, no_last(), &second, 2).expect("judged") {
        Judged::Instance { verdict, last, .. } => {
            // The counter stepped by one from the frame before the dropped one.
            assert_eq!((verdict.status, verdict.step), (Status::Ok, Some(1)));
            assert_eq!(last, LastOutcome::NotKept);
        }
        Judged::Dropped(d) => panic!("dropped: {d:?}"),
    }
    assert!(matches!(
        judge(&mut rx_keyer, &mut rx, no_last(), &first[..HEADER - 1], 3),
        Ok(Judged::Dropped(Dropped {
            refusal: Refusal::Undecodable,
            ..
        }))
    ));
    assert_eq!(
        rx_keyer.counts(),
        Counts {
            undecodable: 1,
            absent: 0,
            not_listed: 1,
        }
    );
}

#[test]
fn instance_keys_and_sender_slots_are_exclusive_on_one_message() {
    let mut k = keyer(TWO_ZONES);
    let mut tx = sender(2);
    let frame = built(protect(&mut k, &mut tx, &zone_only(5), 0).expect("protected")).1;

    let mut by_sender = receiver(Keying::Senders {
        slots: 2,
        bound: None,
    });
    assert_eq!(
        judge(&mut k, &mut by_sender, no_last(), &frame, 0),
        Err(JudgeError::SenderKeyed)
    );
    let mut narrow = receiver(Keying::Indexed { streams: 1 });
    assert_eq!(
        judge(&mut k, &mut narrow, no_last(), &frame, 0),
        Err(JudgeError::TooFewStreams {
            streams: 1,
            instances: 2
        })
    );
    let mut rx = receiver(Keying::Indexed { streams: 2 });
    let mut one = LastValues::new(vec![0u8; 8], 1, 8).expect("room for one");
    assert_eq!(
        judge(&mut k, &mut rx, Some(&mut one), &frame, 0),
        Err(JudgeError::TooFewLastValues {
            kept: 1,
            instances: 2
        })
    );
    // None of the refusals counted the frame as a drop.
    assert_eq!(k.counts(), Counts::default());
}

#[test]
fn a_payload_longer_than_an_instances_room_keeps_the_value_before() {
    let mut tx_keyer = keyer(TWO_ZONES);
    let mut rx_keyer = keyer(TWO_ZONES);
    let mut tx = sender(2);
    let mut rx = receiver(Keying::Indexed { streams: 2 });
    let mut last = LastValues::new(vec![0u8; 2 * 2], 2, 2).expect("room");
    let short = built(protect(&mut tx_keyer, &mut tx, &zone_only(5), 0).expect("protected")).1;
    let mut long_payload = zone_only(5);
    put_varint(&mut long_payload, 10, 300);
    let long = built(protect(&mut tx_keyer, &mut tx, &long_payload, 0).expect("protected")).1;
    let outcome = |judged: Judged| match judged {
        Judged::Instance { last, .. } => last,
        Judged::Dropped(d) => panic!("dropped: {d:?}"),
    };
    assert_eq!(
        outcome(judge(&mut rx_keyer, &mut rx, Some(&mut last), &short, 0).expect("judged")),
        LastOutcome::Recorded
    );
    assert_eq!(
        outcome(judge(&mut rx_keyer, &mut rx, Some(&mut last), &long, 1).expect("judged")),
        LastOutcome::TooLong {
            len: long_payload.len(),
            capacity: 2
        }
    );
    assert_eq!(last.last(0), Some(&zone_only(5)[..]));
}
