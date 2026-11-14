// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Tests of [`crate::segment_chain`], on the synthetic profile of
//! [`crate::segment_profile_tests`].

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use crate::segment_chain::{
    Carrier, Ended, Ending, KeyRef, Place, SegmentLedger, Unjoined, Verdict,
};
use crate::segment_profile::{Misplaced, SegmentProfile};
use crate::segment_profile_tests::{demo_piece, demo_profile};

const MESSAGE: &[u8] = b"0123456789AB";

fn key() -> KeyRef {
    KeyRef::Resolved(String::from("demo/large"))
}

/// Feed one piece of the 12-byte [`MESSAGE`] (origin 1, transfer `number`).
fn feed(
    ledger: &mut SegmentLedger,
    profile: &SegmentProfile,
    number: u8,
    range: core::ops::Range<usize>,
) -> Verdict {
    feed_on(ledger, profile, key(), 1, number, range)
}

fn feed_on(
    ledger: &mut SegmentLedger,
    profile: &SegmentProfile,
    key: KeyRef,
    origin: u16,
    number: u8,
    range: core::ops::Range<usize>,
) -> Verdict {
    feed_carried(ledger, profile, Carrier::Push, key, (origin, number), range)
}

/// [`feed_on`], carried by `carrier`; `transfer` is the origin and the
/// transfer number.
fn feed_carried(
    ledger: &mut SegmentLedger,
    profile: &SegmentProfile,
    carrier: Carrier,
    key: KeyRef,
    transfer: (u16, u8),
    range: core::ops::Range<usize>,
) -> Verdict {
    let (origin, number) = transfer;
    let bytes = demo_piece(
        origin,
        number,
        MESSAGE.len() as u32,
        range.start as u32,
        &MESSAGE[range],
    );
    let piece = profile.recognise(&bytes).expect("a piece");
    ledger.receive(profile, &piece, 0, Some(true), key, carrier)
}

#[test]
fn pieces_in_order_join_into_the_message_on_the_closing_one() {
    let (p, mut l) = (demo_profile(), SegmentLedger::new());
    let a = feed(&mut l, &p, 1, 0..4);
    assert_eq!(a.place, Some(Place::First));
    assert_eq!(a.missing, Vec::new());
    assert!(a.joined.is_none());
    assert_eq!(l.held(), MESSAGE.len(), "the open transfer holds its whole");
    let b = feed(&mut l, &p, 1, 4..8);
    assert_eq!(b.place, Some(Place::Continuing));
    let c = feed(&mut l, &p, 1, 8..12);
    assert_eq!(c.place, Some(Place::Closing));
    assert_eq!(c.joined.as_deref(), Some(MESSAGE));
    assert!(!c.out_of_order && !c.overlap);
    assert_eq!(l.held(), 0, "a completed transfer holds nothing");
}

#[test]
fn a_piece_that_is_the_whole_message_is_whole() {
    let (p, mut l) = (demo_profile(), SegmentLedger::new());
    let v = feed(&mut l, &p, 1, 0..12);
    assert_eq!(v.place, Some(Place::Whole));
    assert_eq!(v.joined.as_deref(), Some(MESSAGE));
}

#[test]
fn a_gap_is_listed_until_filled_and_the_filler_is_out_of_order() {
    let (p, mut l) = (demo_profile(), SegmentLedger::new());
    let _ = feed(&mut l, &p, 1, 0..4);
    let c = feed(&mut l, &p, 1, 8..12);
    assert_eq!(c.missing, [(4, 8)]);
    assert!(!c.out_of_order, "it starts past everything received");
    let b = feed(&mut l, &p, 1, 4..8);
    assert!(b.out_of_order, "it lies behind a piece that arrived first");
    assert_eq!(b.place, Some(Place::Closing));
    assert_eq!(b.missing, Vec::new());
    assert_eq!(b.joined.as_deref(), Some(MESSAGE));
}

#[test]
fn a_first_piece_that_is_not_at_the_start_lists_what_is_missing_before_it() {
    let (p, mut l) = (demo_profile(), SegmentLedger::new());
    let v = feed(&mut l, &p, 1, 4..8);
    assert_eq!(v.place, Some(Place::First));
    assert_eq!(v.missing, [(0, 4)]);
}

#[test]
fn an_overlapping_piece_says_so_and_the_first_copy_wins() {
    let (p, mut l) = (demo_profile(), SegmentLedger::new());
    let _ = feed(&mut l, &p, 1, 0..6);
    // A piece claiming bytes 4..8 with different contents for 4..6.
    let mut altered = MESSAGE.to_vec();
    altered[4] = b'x';
    altered[5] = b'y';
    let bytes = demo_piece(1, 1, 12, 4, &altered[4..8]);
    let piece = p.recognise(&bytes).expect("a piece");
    let v = l.receive(&p, &piece, 0, Some(true), key(), Carrier::Push);
    assert!(v.overlap && !v.out_of_order, "{v:?}");
    let last = feed(&mut l, &p, 1, 8..12);
    assert_eq!(
        last.joined.as_deref(),
        Some(MESSAGE),
        "the first copy of 4..6"
    );
}

#[test]
fn a_new_transfer_number_ends_the_previous_one_and_says_how_far_it_got() {
    let (p, mut l) = (demo_profile(), SegmentLedger::new());
    let _ = feed(&mut l, &p, 1, 0..4);
    let _ = feed(&mut l, &p, 1, 8..12);
    let v = feed(&mut l, &p, 2, 0..4);
    assert_eq!(v.place, Some(Place::First));
    assert_eq!(
        v.ended,
        [Ended {
            transfer: 1,
            total: 12,
            received: 8,
            ending: Ending::Superseded
        }]
    );
    // A completed transfer ends nothing a reader is told about.
    let _ = feed(&mut l, &p, 2, 4..12);
    let w = feed(&mut l, &p, 3, 0..4);
    assert_eq!(w.ended, Vec::new());
}

#[test]
fn a_piece_with_a_wrong_crc_joins_nothing_and_moves_no_state() {
    let (p, mut l) = (demo_profile(), SegmentLedger::new());
    let _ = feed(&mut l, &p, 1, 0..4);
    let mut bytes = demo_piece(1, 1, 12, 4, &MESSAGE[4..8]);
    *bytes.last_mut().expect("a chunk") ^= 0x01;
    let piece = p.recognise(&bytes).expect("still a piece");
    let v = l.receive(&p, &piece, 0, Some(true), key(), Carrier::Push);
    assert_eq!((v.unjoined, v.place), (Some(Unjoined::CrcMismatch), None));
    // The transfer still misses 4..8: the damaged copy filled nothing.
    let c = feed(&mut l, &p, 1, 8..12);
    assert_eq!(c.missing, [(4, 8)]);
}

#[test]
fn a_piece_that_cannot_be_placed_or_disagrees_on_the_total_joins_nothing() {
    let (p, mut l) = (demo_profile(), SegmentLedger::new());
    let bytes = demo_piece(1, 1, 4, 2, b"abc");
    let piece = p.recognise(&bytes).expect("a piece");
    let v = l.receive(&p, &piece, 0, Some(true), key(), Carrier::Push);
    assert_eq!(v.unjoined, Some(Unjoined::Misplaced(Misplaced::PastTotal)));
    let _ = feed(&mut l, &p, 1, 0..4);
    let bytes = demo_piece(1, 1, 20, 4, b"abcd");
    let piece = p.recognise(&bytes).expect("a piece");
    let v = l.receive(&p, &piece, 0, Some(true), key(), Carrier::Push);
    assert_eq!(v.unjoined, Some(Unjoined::TotalDisagrees));
}

#[test]
fn a_piece_after_its_transfer_completed_is_after_closing() {
    let (p, mut l) = (demo_profile(), SegmentLedger::new());
    let _ = feed(&mut l, &p, 1, 0..12);
    let v = feed(&mut l, &p, 1, 4..8);
    assert_eq!(v.place, Some(Place::AfterClosing));
    assert!(v.joined.is_none());
}

#[test]
fn streams_are_kept_apart_by_origin_key_and_suffix() {
    let (p, mut l) = (demo_profile(), SegmentLedger::new());
    let by_id = |suffix: Option<&str>| KeyRef::Unresolved {
        id: 7,
        suffix: suffix.map(Box::from),
    };
    // Four streams, each sent its first half: none ends another.
    for (k, origin) in [
        (key(), 1u16),
        (key(), 2),
        (by_id(None), 1),
        (by_id(Some("/@history")), 1),
    ] {
        let v = feed_on(&mut l, &p, k, origin, 1, 0..6);
        assert_eq!((v.place, v.ended.len()), (Some(Place::First), 0));
    }
    // And each closes on its own second half.
    for (k, origin) in [(by_id(Some("/@history")), 1u16), (key(), 2)] {
        let v = feed_on(&mut l, &p, k, origin, 1, 6..12);
        assert_eq!(v.place, Some(Place::Closing));
    }
}

/// A responder numbers the transfers of its replies apart from its live ones,
/// and anew for each query, so the live stream and the replies to two queries
/// carry the same transfer number at once. Interleaved, each joins its own
/// message and ends none of the others.
#[test]
fn the_live_stream_and_each_querys_replies_are_three_streams() {
    let (p, mut l) = (demo_profile(), SegmentLedger::new());
    let carriers = [
        Carrier::Push,
        Carrier::Reply { request: 1 },
        Carrier::Reply { request: 2 },
    ];
    for range in [0..4, 4..8] {
        for carrier in carriers {
            let v = feed_carried(&mut l, &p, carrier, key(), (1, 1), range.clone());
            assert_eq!(v.ended, Vec::new(), "{carrier:?} ended another stream");
            assert!(v.unjoined.is_none() && v.joined.is_none(), "{carrier:?}");
        }
    }
    for carrier in carriers {
        let v = feed_carried(&mut l, &p, carrier, key(), (1, 1), 8..12);
        assert_eq!(v.place, Some(Place::Closing), "{carrier:?}");
        assert_eq!(v.joined.as_deref(), Some(MESSAGE), "{carrier:?}");
    }
}

/// A reply piece is placed by the rules a published one is: a first piece not
/// at the start lists what is missing before it, a new transfer number ends
/// the unjoined one, and a piece that cannot be placed says why in the same
/// word.
#[test]
fn a_reply_piece_is_judged_by_the_rules_a_published_piece_is() {
    let p = demo_profile();
    for carrier in [Carrier::Push, Carrier::Reply { request: 9 }] {
        let mut l = SegmentLedger::new();
        let v = feed_carried(&mut l, &p, carrier, key(), (1, 1), 4..8);
        assert_eq!(v.place, Some(Place::First), "{carrier:?}");
        assert_eq!(v.missing, [(0, 4)], "{carrier:?}");
        let w = feed_carried(&mut l, &p, carrier, key(), (1, 2), 0..4);
        assert_eq!(w.ended.len(), 1, "{carrier:?}");
        assert_eq!(w.ended[0].received, 4, "{carrier:?}");
        let bytes = demo_piece(1, 3, 4, 2, b"abc");
        let piece = p.recognise(&bytes).expect("a piece");
        let x = l.receive(&p, &piece, 0, Some(true), key(), carrier);
        assert_eq!(
            x.unjoined,
            Some(Unjoined::Misplaced(Misplaced::PastTotal)),
            "{carrier:?}"
        );
    }
}

#[test]
fn the_bound_on_held_bytes_ends_the_least_recently_fed_transfer() {
    let p = demo_profile();
    let mut l = SegmentLedger::with_bound(2 * MESSAGE.len());
    let _ = feed_on(&mut l, &p, key(), 1, 1, 0..4);
    let _ = feed_on(&mut l, &p, key(), 2, 1, 0..4);
    let _ = feed_on(&mut l, &p, key(), 1, 1, 4..8);
    // A third open transfer does not fit: origin 2 was fed least recently.
    let v = feed_on(&mut l, &p, key(), 3, 1, 0..4);
    assert_eq!(
        v.ended,
        [Ended {
            transfer: 1,
            total: 12,
            received: 4,
            ending: Ending::Evicted
        }]
    );
    assert_eq!((l.evicted(), l.held()), (1, 2 * MESSAGE.len()));
    // Origin 1 is still being joined.
    let w = feed_on(&mut l, &p, key(), 1, 1, 8..12);
    assert_eq!(w.place, Some(Place::Closing));
}

/// A query's final lets go of its reply streams and of nothing else: the
/// stream count returns to what it was before the query, a completed reply
/// transfer leaves without a word, an open one is ended `closed` with what it
/// had received, and the bytes it held are given back. A piece of the query
/// after its final starts a stream afresh.
#[test]
fn a_final_ends_its_querys_replies_and_nothing_else() {
    let (p, mut l) = (demo_profile(), SegmentLedger::new());
    let live = feed_carried(&mut l, &p, Carrier::Push, key(), (1, 1), 0..4);
    assert_eq!(live.place, Some(Place::First));
    let before = l.streams();
    let other = Carrier::Reply { request: 2 };
    let _ = feed_carried(&mut l, &p, other, key(), (1, 1), 0..4);
    let asked = Carrier::Reply { request: 1 };
    // Two streams of the one query: one completes, one stays open.
    let _ = feed_carried(&mut l, &p, asked, key(), (1, 1), 0..12);
    let _ = feed_carried(&mut l, &p, asked, key(), (2, 1), 0..4);
    assert_eq!(l.streams(), before + 3);
    let held = l.held();
    let ended = l.close(0, Some(true), 1);
    assert_eq!(
        ended,
        [Ended {
            transfer: 1,
            total: 12,
            received: 4,
            ending: Ending::Closed
        }]
    );
    assert_eq!(l.streams(), before + 1, "the other query's stream stays");
    assert_eq!(l.held(), held - MESSAGE.len());
    // Another list or direction names other streams: nothing to close.
    assert_eq!(l.close(1, Some(true), 2), Vec::new());
    assert_eq!(l.close(0, Some(false), 2), Vec::new());
    assert_eq!(l.streams(), before + 1);
    // The live stream and the other query go on.
    let w = feed_carried(&mut l, &p, Carrier::Push, key(), (1, 1), 4..12);
    assert_eq!(w.place, Some(Place::Closing));
    let x = feed_carried(&mut l, &p, other, key(), (1, 1), 4..12);
    assert_eq!(x.place, Some(Place::Closing));
    // A late piece of the closed query begins again.
    let y = feed_carried(&mut l, &p, asked, key(), (1, 1), 4..8);
    assert_eq!((y.place, y.ended.len()), (Some(Place::First), 0));
}

#[cfg(feature = "dissect")]
#[test]
fn a_kept_verdict_is_recalled_by_its_row_and_forgotten_with_it() {
    let (p, mut l) = (demo_profile(), SegmentLedger::new());
    let v = feed(&mut l, &p, 1, 0..12);
    l.remember(0, 5, 0, &v);
    l.remember(0, 9, 0, &v);
    assert_eq!(l.recall(0, 5, 0), Some(v.clone()));
    assert_eq!(l.recall(0, 5, 1), None);
    l.forget_before(0, 6);
    assert_eq!(l.recall(0, 5, 0), None);
    assert_eq!(l.recall(0, 9, 0), Some(v));
}
