// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Tests of [`crate::segment_sender`], on the synthetic profile of
//! [`crate::segment_profile_tests`]. Two oracles the sender does not share
//! code with: the piece builder that computes its CRC from the model's
//! parameters directly, and the reader and ledger that join pieces.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::e2e_profile::DocError;
use crate::segment_chain::{Carrier, KeyRef, SegmentLedger};
use crate::segment_profile_tests::{demo_piece, demo_profile, DEMO};
use crate::segment_sender::{Refusal, Rollover, SegmentSender, Split, SplitError};

const ORIGIN: u16 = 0x0102;
const VALUES: &str = r#"{"origin":"0x0102"}"#;

fn sender(first: u64, rollover: Rollover) -> SegmentSender {
    SegmentSender::new(DEMO, VALUES, first, rollover).expect("a sender")
}

fn message(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 + 3) as u8).collect()
}

/// Every piece of one split, in order.
fn pieces(s: &mut SegmentSender, msg: &[u8], chunk: usize) -> (Split, Vec<Vec<u8>>) {
    let mut out = Vec::new();
    let split = s
        .split::<()>(msg, chunk, |p| {
            out.push(p.to_vec());
            Ok(())
        })
        .expect("a split");
    (split, out)
}

fn values_refusal(text: &str) -> (String, String) {
    match SegmentSender::new(DEMO, text, 1, Rollover::Refuse) {
        Err(Refusal::Values(DocError::Invalid { path, reason })) => (path, reason),
        other => panic!("expected a values refusal for {text}, got {other:?}"),
    }
}

#[test]
fn every_piece_is_byte_for_byte_the_one_built_from_the_model() {
    let msg = message(30);
    let mut s = sender(7, Rollover::Refuse);
    let (split, got) = pieces(&mut s, &msg, 8);
    assert_eq!(
        split,
        Split {
            transfer: 7,
            pieces: 4
        }
    );
    let want: Vec<Vec<u8>> = msg
        .chunks(8)
        .enumerate()
        .map(|(i, c)| demo_piece(ORIGIN, 7, 30, (i * 8) as u32, c))
        .collect();
    assert_eq!(got, want);
}

#[test]
fn the_reader_joins_what_the_sender_wrote() {
    let profile = demo_profile();
    let msg = message(100);
    let mut s = sender(1, Rollover::Refuse);
    for chunk in [1, 7, 33, 99, 100, 4096] {
        let (split, got) = pieces(&mut s, &msg, chunk);
        assert_eq!(split.pieces, msg.len().div_ceil(chunk));
        let mut ledger = SegmentLedger::new();
        let mut joined = None;
        for (i, bytes) in got.iter().enumerate() {
            let piece = profile.recognise(bytes).expect("a piece");
            assert!(piece.crc.is_some_and(|c| c.matches()), "chunk {chunk}");
            let v = ledger.receive(
                &profile,
                &piece,
                0,
                Some(true),
                KeyRef::Resolved("demo/large".into()),
                Carrier::Push,
            );
            assert_eq!(v.unjoined, None, "chunk {chunk} piece {i}");
            if i + 1 < got.len() {
                assert!(v.joined.is_none());
            } else {
                joined = v.joined;
            }
        }
        assert_eq!(joined.as_deref(), Some(&msg[..]), "chunk {chunk}");
    }
}

#[test]
fn a_message_no_longer_than_a_chunk_is_one_piece_with_its_header() {
    let msg = message(5);
    let (split, got) = pieces(&mut sender(3, Rollover::Refuse), &msg, 5);
    assert_eq!(split.pieces, 1);
    assert_eq!(got, [demo_piece(ORIGIN, 3, 5, 0, &msg)]);
}

#[test]
fn each_message_carries_the_next_number() {
    let mut s = sender(10, Rollover::Refuse);
    for want in 10..13 {
        let (split, got) = pieces(&mut s, &message(9), 4);
        assert_eq!(split.transfer, want);
        assert!(got.iter().all(|p| p[4] == want as u8));
    }
    assert_eq!(s.next(), Some(13));
    s.set(40);
    assert_eq!(pieces(&mut s, &message(9), 4).0.transfer, 40);
}

#[test]
fn the_number_is_refused_past_its_largest_value_by_default() {
    let mut s = sender(254, Rollover::Refuse);
    assert_eq!(s.transfer_max(), 255);
    assert_eq!(pieces(&mut s, &message(3), 8).0.transfer, 254);
    assert_eq!(pieces(&mut s, &message(3), 8).0.transfer, 255);
    assert_eq!(s.next(), None);
    let mut emitted = 0;
    let refused = s.split::<()>(&message(3), 8, |_| {
        emitted += 1;
        Ok(())
    });
    assert_eq!(
        refused,
        Err(SplitError::Refused(Refusal::Spent {
            field: "number".into(),
            max: 255
        }))
    );
    assert_eq!(emitted, 0);
    s.set(1);
    assert_eq!(pieces(&mut s, &message(3), 8).0.transfer, 1);
}

#[test]
fn a_restarting_sender_goes_back_to_its_first_number() {
    let mut s = sender(1, Rollover::Restart);
    s.set(255);
    assert_eq!(pieces(&mut s, &message(3), 8).0.transfer, 255);
    assert_eq!(s.next(), Some(1), "back to the first number, never 0");
}

#[test]
fn a_refused_message_emits_nothing_and_consumes_no_number() {
    let mut s = sender(5, Rollover::Refuse);
    let cases: [(Vec<u8>, usize, Refusal); 3] = [
        (Vec::new(), 4, Refusal::EmptyMessage),
        (message(4), 0, Refusal::ZeroChunk),
        (
            message(4097),
            512,
            Refusal::PastTotalMax {
                len: 4097,
                max: 4096,
            },
        ),
    ];
    for (msg, chunk, want) in cases {
        let r = s.split::<()>(&msg, chunk, |_| panic!("nothing is emitted"));
        assert_eq!(r, Err(SplitError::Refused(want)));
        assert_eq!(s.next(), Some(5));
    }
    s.set(256);
    let r = s.split::<()>(&message(4), 4, |_| panic!("nothing is emitted"));
    assert_eq!(
        r,
        Err(SplitError::Refused(Refusal::DoesNotFit {
            field: "number".into(),
            value: 256,
            max: 255
        }))
    );
    assert_eq!(s.next(), Some(256));
}

#[test]
fn an_emitter_that_fails_has_consumed_the_number() {
    let mut s = sender(9, Rollover::Refuse);
    let mut calls = 0;
    let r = s.split(&message(20), 8, |_| {
        calls += 1;
        if calls == 2 {
            Err("link down")
        } else {
            Ok(())
        }
    });
    assert_eq!(
        r,
        Err(SplitError::Emit {
            error: "link down",
            transfer: 9,
            sent: 1,
            pieces: 3
        })
    );
    assert_eq!(s.next(), Some(10));
}

#[test]
fn the_values_state_exactly_the_callers_fields() {
    let (path, reason) = values_refusal("{}");
    assert_eq!(path, "/origin");
    assert!(reason.contains("not stated"), "{reason}");
    for field in ["mark", "number", "size", "at", "check"] {
        let text = alloc::format!(r#"{{"origin":1,"{field}":1}}"#);
        let (path, reason) = values_refusal(&text);
        assert_eq!(path, alloc::format!("/{field}"));
        assert!(reason.contains("cannot be stated"), "{field}: {reason}");
    }
    let (path, reason) = values_refusal(r#"{"origin":1,"colour":1}"#);
    assert_eq!(path, "/colour");
    assert!(reason.contains("no field"), "{reason}");
    let (path, reason) = values_refusal(r#"{"origin":"0x10000"}"#);
    assert_eq!(path, "/origin");
    assert!(reason.contains("does not fit"), "{reason}");
    let (path, _) = values_refusal(r#"{"origin":1,"origin":2}"#);
    assert_eq!(path, "/origin");
    let (path, _) = values_refusal("[1]");
    assert_eq!(path, "");
}

#[test]
fn a_profile_that_is_not_one_is_refused_as_the_profile() {
    let r = SegmentSender::new(r#"{"name":"x"}"#, VALUES, 1, Rollover::Refuse);
    let Err(refusal) = r else { panic!("refused") };
    assert!(matches!(refusal, Refusal::Profile(_)));
    assert!(refusal.to_string().starts_with("profile "), "{refusal}");
}

/// A profile with no CRC, a free field that is not a stream field, and a total
/// field too narrow for its `total_max`: the free field is the caller's, and a
/// message whose length does not fit is refused before any piece.
#[test]
fn a_free_field_is_the_callers_and_a_narrow_total_is_judged_per_message() {
    const PLAIN: &str = concat!(
        r#"{"name":"plain","segments":{"fields":["#,
        r#"{"name":"mark","bytes":1,"equals":"0x7E"},"#,
        r#"{"name":"tag","bytes":2},"#,
        r#"{"name":"n","bytes":1},"#,
        r#"{"name":"size","bytes":1},"#,
        r#"{"name":"at","bytes":2,"order":"little"}],"#,
        r#""transfer":"n","total":"size","offset":"at","total_max":1000}}"#
    );
    let mut s =
        SegmentSender::new(PLAIN, r#"{"tag":"0xBEEF"}"#, 2, Rollover::Refuse).expect("a sender");
    let (_, got) = pieces(&mut s, &message(5), 3);
    assert_eq!(got[0], [0x7E, 0xBE, 0xEF, 2, 5, 0, 0, 3, 10, 17]);
    assert_eq!(got[1], [0x7E, 0xBE, 0xEF, 2, 5, 3, 0, 24, 31]);
    let r = s.split::<()>(&message(256), 64, |_| panic!("nothing is emitted"));
    assert_eq!(
        r,
        Err(SplitError::Refused(Refusal::DoesNotFit {
            field: "size".into(),
            value: 256,
            max: 255
        }))
    );
    assert_eq!(s.next(), Some(3));
}
