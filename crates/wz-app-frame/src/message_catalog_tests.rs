// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Model tests of the message catalog reader on SYNTHETIC catalogs: what it reads, the sender,
//! receiver and supervision rows it makes against those made by hand from the same values, the
//! generator's tables of the same file against the reader's resolved form, the schema the
//! generator interprets against the reader's members and refusal words, and the corpus of refused
//! catalogs both judges run.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use wz_session_core::json5::{self, Json5Value};

use crate::e2e_frame::Values;
use crate::e2e_profile::Profile;
use crate::e2e_receiver::{Keying, Receiver, Status, Verdict};
use crate::e2e_stream_sender::{SenderOptions, StreamSender};
use crate::message_catalog::{Catalog, HandleError, RefusalKind, StreamRow, SHAPES};
use crate::message_catalog_table::{
    Limits, MessageRow, NodeRow, ProtectionRow, SupervisionRow, Table,
};

const SYNTHETIC: &str = include_str!("../catalog/synthetic.json5");
const CORPUS: &str = include_str!("../catalog/refusals.json5");
const SCHEMA: &str = include_str!("../../../deploy/message-catalog.schema.json");

// The generator's tables of `SYNTHETIC`, with the test it writes beside them.
include!("../catalog/synthetic_tables.rs");

use catalog_tables::{CATALOG, LIMITS};

const NORTH: usize = 0;
const SOUTH: usize = 1;
const POSE: usize = 0;
const MAP: usize = 1;

fn synthetic() -> Catalog {
    match Catalog::parse(SYNTHETIC, LIMITS) {
        Ok(catalog) => catalog,
        Err(refusal) => panic!("the synthetic catalog is refused: {refusal}"),
    }
}

/// The values a program would hand the e2e doors for the pose message by hand, for the node at
/// `address`.
fn hand_values(address: u64) -> Values {
    Values::parse(&format!(
        r#"{{"ident": {{"group": 21, "msg": 300}}, "cell": {{"kind": 6}}, "@address": {address}}}"#
    ))
    .expect("valid values")
}

fn hand_profile(catalog: &Catalog) -> Profile {
    Profile::parse(&catalog.e2e_profiles()[0].text()).expect("valid profile")
}

#[test]
fn the_synthetic_catalog_is_read_as_written() {
    let catalog = synthetic();
    let names: Vec<&str> = catalog.nodes().iter().map(|n| n.name.as_str()).collect();
    assert_eq!(names, ["north", "south"]);
    assert_eq!(catalog.nodes()[NORTH].address, Some(0x0007_A100));
    assert_eq!(catalog.nodes()[SOUTH].address, Some(0x0007_B200));
    assert_eq!(catalog.e2e_profiles().len(), 1);
    assert_eq!(catalog.segment_profiles().len(), 1);
    assert_eq!(catalog.supervision_start_delay_ms(), 750);
    assert_eq!(catalog.find_key_expr("demo/catalog/pose"), Some(POSE));
    assert_eq!(catalog.find_id(402), Some(MAP));
    assert_eq!(catalog.find_id(403), None);
    assert_eq!(catalog.node_index("south"), Some(SOUTH));

    let pose = &catalog.messages()[POSE];
    assert_eq!(pose.id, 401);
    assert_eq!(pose.publishers, [NORTH]);
    assert_eq!(pose.subscribers, [SOUTH]);
    assert_eq!(pose.period_ms, Some(40));
    assert_eq!(pose.protection.as_ref().map(|p| p.profile), Some(0));
    assert_eq!(
        pose.supervision.map(|s| (s.factor, s.awaited)),
        Some((4, true))
    );
    assert_eq!(pose.replay_depth, None);
    assert_eq!(pose.segment_profile, None);

    let map = &catalog.messages()[MAP];
    assert_eq!(map.key_expr, "demo/catalog/map");
    assert_eq!(
        map.period_ms, None,
        "a message with no period is an event message"
    );
    assert!(map.protection.is_none());
    assert_eq!(map.replay_depth, Some(6));
    assert_eq!(map.segment_profile, Some(0));
    assert!(catalog.segment_profile(0).is_ok());
}

#[test]
fn the_generated_tables_are_the_readers_resolved_form() {
    let from_table = match Catalog::from_table(&CATALOG, LIMITS) {
        Ok(catalog) => catalog,
        Err(refusal) => panic!("the generated tables are refused: {refusal}"),
    };
    assert_eq!(from_table, synthetic());
}

#[test]
fn a_sender_from_the_catalog_builds_the_frames_one_made_by_hand_builds() {
    let catalog = synthetic();
    let address = catalog.nodes()[NORTH].address.expect("stated");
    let mut by_hand = StreamSender::new(
        hand_profile(&catalog),
        hand_values(address),
        SenderOptions::default(),
    )
    .expect("made by hand");
    let mut from_catalog = catalog
        .sender(POSE, NORTH, SenderOptions::default())
        .expect("made from the catalog");
    let payloads: [&[u8]; 4] = [b"\x01\x02\x03", b"", b"\x01\x02\x03", b"\x7f"];
    for payload in payloads {
        let a = by_hand.protect(0, payload).expect("protects");
        let b = from_catalog.protect(0, payload).expect("protects");
        assert_eq!(a.bytes, b.bytes);
        assert_eq!(a.counter, b.counter);
    }
}

#[test]
fn a_receiver_from_the_catalog_judges_as_one_made_by_hand() {
    let catalog = synthetic();
    let mut sender = catalog
        .sender(POSE, NORTH, SenderOptions::default())
        .expect("made from the catalog");
    let frames: Vec<Vec<u8>> = (0u8..3)
        .map(|n| sender.protect(0, &[n, n]).expect("protects").bytes)
        .collect();
    let south = catalog.nodes()[SOUTH].address.expect("stated");
    let mut by_hand = Receiver::new(
        hand_profile(&catalog),
        &hand_values(south),
        Keying::Indexed { streams: 1 },
        None,
        LIMITS.sender_slots,
    )
    .expect("made by hand");
    let mut from_catalog = catalog
        .receiver(POSE, SOUTH, LIMITS.sender_slots)
        .expect("made from the catalog");
    let mut damaged = frames[2].clone();
    let last = damaged.len() - 1;
    damaged[last] ^= 0x40;
    let sequence: [(&[u8], u64); 5] = [
        (frames[0].as_slice(), 0),
        (frames[1].as_slice(), 40),
        (frames[1].as_slice(), 80),
        (damaged.as_slice(), 120),
        (frames[2].as_slice(), 160),
    ];
    let mut statuses = Vec::new();
    for (frame, now) in sequence {
        let a: Verdict = by_hand.receive(0, frame, now).expect("judged");
        let b: Verdict = from_catalog.receive(0, frame, now).expect("judged");
        assert_eq!(a, b);
        statuses.push(b.status);
    }
    assert_eq!(
        statuses,
        [
            Status::First,
            Status::Ok,
            Status::Repeated,
            Status::Integrity,
            Status::Ok
        ]
    );
}

#[test]
fn the_supervision_rows_are_the_period_the_factor_and_the_publisher() {
    let catalog = synthetic();
    let rows = catalog.supervision_rows(POSE, SOUTH).expect("supervised");
    assert_eq!(
        rows,
        [StreamRow {
            period_ms: 40,
            factor: 4,
            sender: NORTH as u32,
            awaited: true,
        }]
    );
}

#[test]
fn a_handle_the_entry_does_not_give_is_refused_by_name() {
    let catalog = synthetic();
    let options = SenderOptions::default();
    let slots = LIMITS.sender_slots;
    assert_eq!(
        catalog.sender(POSE, SOUTH, options).unwrap_err(),
        HandleError::NotPublisher
    );
    assert_eq!(
        catalog.receiver(POSE, NORTH, slots).unwrap_err(),
        HandleError::NotSubscriber
    );
    assert_eq!(
        catalog.sender(MAP, SOUTH, options).unwrap_err(),
        HandleError::Unprotected
    );
    assert_eq!(
        catalog.receiver(MAP, NORTH, slots).unwrap_err(),
        HandleError::Unprotected
    );
    assert_eq!(
        catalog.supervision_rows(MAP, NORTH).unwrap_err(),
        HandleError::NotSupervised
    );
    assert_eq!(
        catalog.supervision_rows(POSE, NORTH).unwrap_err(),
        HandleError::NotSubscriber
    );
    assert_eq!(
        catalog.sender(9, NORTH, options).unwrap_err(),
        HandleError::NoSuchMessage
    );
    assert_eq!(
        catalog.sender(POSE, 9, options).unwrap_err(),
        HandleError::NoSuchNode
    );
}

/// Two publishers whose sender identities the profile derives from their addresses, bound to a
/// receiver's slots by the catalog, and a third node that receives and supervises.
const SENDERS: &str = r#"{
  nodes: [{name: 'east', address: '0x300'}, {name: 'west', address: '0x600'}, {name: 'hub'}],
  e2e_profiles: {
    q: {name: 'q',
        fields: [{name: 'crc', bytes: 1}, {name: 'counter', bytes: 1}, {name: 'length', bytes: 1},
                 {name: 'cell', bytes: 2,
                  split: [{name: 'kind', lsb: 12, width: 4},
                          {name: 'sender', lsb: 0, width: 12,
                           derive: {from: 'address', mask: '0xF00', xor: '0x9'}}]}],
        crc: {field: 'crc', width: 8, poly: '0x2F', init: '0xFF', refin: false, refout: false,
              xorout: '0x00', cover: ['counter', 'length', 'cell', '@payload']},
        length: {field: 'length', counts: 'frame'},
        counter: {field: 'counter', max_gap: 2, timeout_ms: 100},
        cell: {field: 'cell', kind: 'kind', sender: 'sender'}},
  },
  messages: [{key_expr: 'demo/two', id: 7, publishers: ['east', 'west'], subscribers: ['hub'],
              period_ms: 25, protection: {profile: 'q', values: {cell: {kind: 3}}},
              senders: [{node: 'east', id: '0x309'}, {node: 'west', id: '0x609'}],
              supervision: {factor: 2, awaited: false}}],
}"#;

#[test]
fn listed_senders_bind_the_receivers_slots_and_give_a_row_each() {
    let catalog = Catalog::parse(SENDERS, LIMITS).expect("accepted");
    let (east, west, hub) = (0, 1, 2);
    let mut from_catalog = catalog.receiver(0, hub, LIMITS.sender_slots).expect("made");
    let mut by_hand = Receiver::new(
        Profile::parse(&catalog.e2e_profiles()[0].text()).expect("valid"),
        &Values::parse(r#"{"cell": {"kind": 3}}"#).expect("valid"),
        Keying::Senders {
            slots: 2,
            bound: Some(vec![0x309, 0x609]),
        },
        None,
        LIMITS.sender_slots,
    )
    .expect("made by hand");
    let mut from_east = catalog
        .sender(0, east, SenderOptions::default())
        .expect("made");
    let mut from_west = catalog
        .sender(0, west, SenderOptions::default())
        .expect("made");
    let frames = [
        from_west.protect(0, b"w").expect("protects").bytes,
        from_east.protect(0, b"e").expect("protects").bytes,
        from_west.protect(0, b"w").expect("protects").bytes,
    ];
    let mut streams = Vec::new();
    for (n, frame) in frames.iter().enumerate() {
        let a = by_hand.receive(0, frame, n as u64).expect("judged");
        let b = from_catalog.receive(0, frame, n as u64).expect("judged");
        assert_eq!(a, b);
        streams.push(b.stream);
    }
    assert_eq!(
        streams,
        [Some(1), Some(0), Some(1)],
        "each sender in its bound slot"
    );

    let row = |sender: u32| StreamRow {
        period_ms: 25,
        factor: 2,
        sender,
        awaited: false,
    };
    assert_eq!(
        catalog.supervision_rows(0, hub).expect("supervised"),
        [row(east as u32), row(west as u32)],
        "one row per sender, in slot order, each with the sender's node"
    );
}

#[test]
fn a_catalog_over_the_builds_message_limit_is_refused() {
    let tight = Limits {
        messages: 1,
        ..LIMITS
    };
    let refusal = Catalog::parse(SYNTHETIC, tight).unwrap_err();
    assert_eq!(refusal.kind, RefusalKind::TooManyMessages);
    assert_eq!(refusal.path, "/messages");
}

#[test]
fn a_table_that_numbers_a_node_it_does_not_have_is_refused() {
    const NODES: &[NodeRow] = &[NodeRow {
        name: "only",
        address: None,
    }];
    const MESSAGES: &[MessageRow] = &[MessageRow {
        key_expr: "demo/x",
        id: 1,
        publishers: &[0],
        subscribers: &[3],
        period_ms: Some(10),
        protection: None,
        senders: &[],
        instance_key: &[],
        replay_depth: None,
        supervision: Some(SupervisionRow {
            factor: 2,
            awaited: true,
        }),
        segment_profile: None,
    }];
    let table = Table {
        nodes: NODES,
        e2e_profiles: &[],
        segment_profiles: &[],
        supervision_start_delay_ms: 0,
        messages: MESSAGES,
    };
    let refusal = Catalog::from_table(&table, LIMITS).unwrap_err();
    assert_eq!(refusal.kind, RefusalKind::UnknownNode);
    assert_eq!(refusal.path, "/messages/0/subscribers/0");

    const PROTECTED: &[MessageRow] = &[MessageRow {
        protection: Some(ProtectionRow {
            profile: 0,
            values: "{}",
        }),
        subscribers: &[],
        ..MESSAGES[0]
    }];
    let table = Table {
        messages: PROTECTED,
        ..table
    };
    let refusal = Catalog::from_table(&table, LIMITS).unwrap_err();
    assert_eq!(refusal.kind, RefusalKind::UnknownE2eProfile);
    assert_eq!(refusal.path, "/messages/0/protection/profile");
}

fn member<'a>(value: &'a Json5Value, key: &str) -> &'a Json5Value {
    value
        .get(key)
        .unwrap_or_else(|| panic!("the member `{key}` is there"))
}

fn keys(value: &Json5Value) -> Vec<&str> {
    match value {
        Json5Value::Object(entries) => entries.iter().map(|(k, _)| k.as_str()).collect(),
        other => panic!("expected an object, found {other:?}"),
    }
}

fn strings(value: &Json5Value) -> Vec<&str> {
    match value {
        Json5Value::Array(items) => items
            .iter()
            .map(|item| match item {
                Json5Value::String(s) => s.as_str(),
                other => panic!("expected a string, found {other:?}"),
            })
            .collect(),
        other => panic!("expected an array, found {other:?}"),
    }
}

#[test]
fn the_schema_states_the_readers_members_and_refusals() {
    let schema = json5::parse(SCHEMA).expect("the schema is JSON");
    let defs = member(&schema, "$defs");
    for (def, members, required) in SHAPES {
        let shape = member(defs, def);
        assert_eq!(
            keys(member(shape, "properties")),
            members,
            "the members of `{def}`"
        );
        assert_eq!(
            strings(member(shape, "required")),
            required,
            "the required members of `{def}`"
        );
    }
    let words: Vec<&str> = RefusalKind::ALL.iter().map(|k| k.word()).collect();
    assert_eq!(keys(member(&schema, "x-wz-refusals")), words);
    for word in strings(member(&schema, "x-wz-reader-only")) {
        assert!(words.contains(&word), "`{word}` is a refusal");
    }
}

fn limits_of(value: Option<&Json5Value>, base: Limits) -> Limits {
    let Some(value) = value else {
        return base;
    };
    let read = |key: &str, default: usize| match value.get(key) {
        Some(Json5Value::Number(text)) => text.parse().expect("a count"),
        _ => default,
    };
    Limits {
        messages: read("messages", base.messages),
        replay_depth_max: read("replay_depth_max", base.replay_depth_max),
        sender_slots: read("sender_slots", base.sender_slots),
    }
}

fn text_of(value: &Json5Value) -> String {
    match value {
        Json5Value::String(text) => text.clone(),
        other => panic!("expected a string, found {other:?}"),
    }
}

#[test]
fn every_refused_catalog_of_the_corpus_is_refused_by_its_name_at_its_place() {
    let corpus = json5::parse(CORPUS).expect("the corpus is JSON5");
    let base = limits_of(corpus.get("limits"), LIMITS);
    let Some(Json5Value::Array(accepted)) = corpus.get("accepted") else {
        panic!("the corpus lists accepted catalogs");
    };
    for (i, catalog) in accepted.iter().enumerate() {
        if let Err(refusal) = Catalog::parse(&catalog.to_json5_text(), base) {
            panic!("accepted catalog {i} is refused: {refusal}");
        }
    }
    let Some(Json5Value::Array(cases)) = corpus.get("cases") else {
        panic!("the corpus lists cases");
    };
    let mut failures: Vec<String> = Vec::new();
    let mut covered: Vec<&str> = Vec::new();
    for (i, case) in cases.iter().enumerate() {
        let want = text_of(member(case, "refusal"));
        let place = text_of(member(case, "at"));
        let limits = limits_of(case.get("limits"), base);
        let text = match case.get("text") {
            Some(text) => text_of(text),
            None => member(case, "catalog").to_json5_text(),
        };
        match Catalog::parse(&text, limits) {
            Ok(_) => failures.push(format!("case {i} ({want}): accepted")),
            Err(refusal) if refusal.kind.word() != want || refusal.path != place => {
                failures.push(format!(
                    "case {i}: expected {want} at `{place}`, got {refusal}"
                ));
            }
            Err(refusal) => covered.push(refusal.kind.word()),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    for kind in RefusalKind::ALL {
        assert!(
            covered.contains(&kind.word()),
            "no case of the corpus is refused as {}",
            kind.word()
        );
    }
}
