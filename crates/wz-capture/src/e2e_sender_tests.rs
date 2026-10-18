// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Tests of the sending side that keeps a message's counter ([`crate::e2e_sender`]).
//!
//! The reference for every frame is the STATELESS door, [`wrap_document`], asked
//! for the same counter written into the values text: a sender that built a
//! frame by any other road than the one writer would be a second opinion about
//! the header, and the two would disagree where nobody was looking.

use alloc::format;
use alloc::string::String;

use crate::e2e_json::wrap_document;
use crate::e2e_sender::{Rollover, Sender};

/// A made-up profile whose counter is ONE byte wide, so the largest value is
/// 255 and the end of the counter is a few calls away.
const TINY: &str = r#"{
  "name": "tiny",
  "fields": [
    {"name": "crc", "bytes": 4},
    {"name": "length", "bytes": 2},
    {"name": "counter", "bytes": 1}
  ],
  "crc": {"field": "crc", "width": 32, "poly": "0xF4ACFB13", "init": "0xFFFFFFFF",
          "refin": true, "refout": true, "xorout": "0xFFFFFFFF",
          "cover": ["length", "@payload", "counter"]},
  "length": {"field": "length", "counts": "frame"},
  "counter": {"field": "counter", "max_gap": 10, "timeout_ms": 1000}
}"#;

/// The values text of a frame the CALLER numbers: what the stateless door takes.
fn stated(counter: u64) -> String {
    format!(r#"{{"counter": {counter}}}"#)
}

fn built(document: &str) -> bool {
    document.contains("\"ok\":true")
}

#[test]
fn every_frame_is_the_stateless_doors_frame_for_the_counter_it_carries() {
    let mut sender = Sender::new(TINY, 7, Rollover::Refuse).expect("a profile");
    for sent in 7..11 {
        let got = sender.wrap("{}", b"abc");
        assert!(built(&got), "{got}");
        assert_eq!(got, wrap_document(TINY, &stated(sent), b"abc"));
    }
    assert_eq!(sender.next(), Some(11), "one step per frame built");
}

#[test]
fn a_frame_the_text_refuses_consumes_no_value() {
    let mut sender = Sender::new(TINY, 7, Rollover::Refuse).expect("a profile");
    let refused = sender.wrap(r#"{"nope": 1}"#, b"");
    assert!(!built(&refused), "a field the profile lacks: {refused}");
    let not_json = sender.wrap("{\"counter\":", b"");
    assert!(!built(&not_json), "{not_json}");
    assert_eq!(sender.next(), Some(7), "nothing was consumed");

    let got = sender.wrap("{}", b"");
    assert_eq!(got, wrap_document(TINY, &stated(7), b""), "the same value");
    assert_eq!(sender.next(), Some(8));
}

#[test]
fn a_text_that_states_the_counter_is_refused_at_the_counter() {
    let mut sender = Sender::new(TINY, 7, Rollover::Refuse).expect("a profile");
    let got = sender.wrap(&stated(1), b"");
    assert!(!built(&got), "{got}");
    assert!(got.contains("\"values_path\":\"/counter\""), "{got}");
    assert_eq!(sender.next(), Some(7), "nothing was consumed");
}

#[test]
fn the_largest_value_is_sent_once_and_the_next_frame_is_refused_without_wrapping() {
    let mut sender = Sender::new(TINY, 254, Rollover::Refuse).expect("a profile");
    assert_eq!(sender.counter_max(), 255);
    assert_eq!(sender.counter_field(), "counter");

    assert_eq!(
        sender.wrap("{}", b""),
        wrap_document(TINY, &stated(254), b"")
    );
    assert_eq!(
        sender.wrap("{}", b""),
        wrap_document(TINY, &stated(255), b"")
    );
    assert_eq!(sender.next(), None, "the end of the counter");

    for _ in 0..2 {
        let got = sender.wrap("{}", b"");
        assert!(!built(&got), "{got}");
        assert!(
            got.contains("`counter`") && got.contains("largest value, 255"),
            "the reason names the field and the value: {got}"
        );
        assert_eq!(sender.next(), None, "a refusal moves nothing");
    }

    sender.set(3);
    assert_eq!(sender.wrap("{}", b""), wrap_document(TINY, &stated(3), b""));
}

#[test]
fn a_sender_that_wraps_counts_on_from_zero_when_it_is_told_to() {
    let mut sender = Sender::new(TINY, 255, Rollover::Wrap).expect("a profile");
    assert_eq!(
        sender.wrap("{}", b""),
        wrap_document(TINY, &stated(255), b"")
    );
    assert_eq!(sender.next(), Some(0));
    assert_eq!(sender.wrap("{}", b""), wrap_document(TINY, &stated(0), b""));
}

#[test]
fn a_start_value_past_the_field_is_refused_by_the_frame_and_stays_put() {
    let mut sender = Sender::new(TINY, 300, Rollover::Refuse).expect("a profile");
    let got = sender.wrap("{}", b"");
    assert!(!built(&got), "{got}");
    assert!(got.contains("\"values_path\":\"/counter\""), "{got}");
    assert_eq!(sender.next(), Some(300), "nothing was consumed");
}

#[test]
fn a_body_described_in_the_text_is_built_around_the_senders_counter() {
    let body = r#""@body": {"files": [{"name": "t.proto",
        "text": "syntax = \"proto3\"; package t; message M { int32 x = 1; }"}],
        "message": "t.M", "values": {"x": 5}}"#;
    let mut sender = Sender::new(TINY, 9, Rollover::Refuse).expect("a profile");
    let got = sender.wrap(&format!("{{{body}}}"), b"");
    assert!(built(&got), "{got}");
    assert_eq!(
        got,
        wrap_document(TINY, &format!("{{\"counter\": 9, {body}}}"), b"")
    );
    assert_eq!(sender.next(), Some(10));
}

#[test]
fn a_profile_that_is_not_one_is_refused_when_the_sender_is_made() {
    let refusal = Sender::new("{}", 0, Rollover::Refuse).expect_err("not a profile");
    assert!(refusal.contains("\"ok\":false"), "{refusal}");
    assert!(refusal.contains("\"profile_path\""), "{refusal}");
    assert_eq!(
        refusal,
        wrap_document("{}", "{}", b""),
        "the door's own words"
    );
}

#[test]
fn the_default_policy_is_to_refuse() {
    assert_eq!(Rollover::default(), Rollover::Refuse);
}
