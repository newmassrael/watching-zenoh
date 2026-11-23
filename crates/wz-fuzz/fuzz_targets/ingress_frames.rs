// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The bytes a peer sends into a session, read as a session reads them, with no session around
//! them: each unit is walked message by message, a Frame's records are walked owned and lent, and
//! each Fragment is handed to a reassembly Router, whose completed chains are walked again.
//!
//! Input: two bytes of arguments, then the units (`wz_fuzz_ingress_common::units`).
//!
//! | byte | argument |
//! |------|----------|
//! | 0    | bit 0: the Router lends a completed chain (`ingest_lending`) rather than borrowing it; bit 1: the Fragment chain markers are honoured; bits 2-3: the sequence-number resolution |
//! | 1    | the largest message a chain may reach, in steps of 64 bytes; 0 for the slot's whole size |
//!
//! Held beside not crashing:
//!
//! - a participant's read of a message (`parse_inbound_consuming`) takes what an observer's read
//!   takes, the same number of bytes, and so does the read over a unit that can be shared, whose
//!   Frame payload then lies inside that unit;
//! - every walk of a Frame's records (strict, best-effort, of a rejoined chain, of a lowlatency
//!   unit) states spans and a halt that lie inside the payload and account for every byte, the
//!   strict walk refuses exactly the payloads the best-effort walk halts on with a codec error,
//!   and a lowlatency unit is at most one record;
//! - a record the owned walk and the lent codec both read takes the same bytes in each, and each
//!   lent record holds its round trip (`wz_fuzz::records`);
//! - the Router delivers a chain exactly when it answers `Reassembled`, the chain ends with the
//!   fragment that completed it and is no longer than the bound, and its slots are each either
//!   free or holding a chain after every call.

#![no_main]

use libfuzzer_sys::fuzz_target;
use wz_codecs::wire_const::T_MID_JOIN;
use wz_fuzz::records::lent_records;
use wz_fuzz::Reader;
use wz_fuzz_ingress_common::units;
use wz_session_core::inbound::{
    parse_inbound_consuming, parse_inbound_consuming_in, parse_inbound_observed, InboundFrame,
};
use wz_session_core::link::RxBytes;
use wz_session_core::network_message::{
    parse_frame_payload, parse_frame_payload_best_effort, parse_lowlatency_payload_best_effort,
    parse_reassembled_payload_best_effort, BatchHalt, BatchParse, NetworkMessage,
};
use wz_session_core::reassembly_dispatch::{
    Fragment, IngestOutcome, ReassemblyConfig, ReassemblyDispatcher,
};
use wz_session_core::sn::mask_from_res;

/// The Router's slots and the bytes each holds: few, so a peer that opens chains it never ends
/// fills them within one input.
const SLOTS: usize = 4;
const CAP: usize = 4096;
type Router = ReassemblyDispatcher<SLOTS, CAP>;

/// The peer every fragment is keyed by, and the chains it may hold open at once.
const PEER: &[u8] = &[0xB0, 0xB1, 0xB2, 0xB3];
const QUOTA: u16 = 2;
/// How long a chain may stay open, and how far the clock moves between two units: a chain left
/// open over ten units is swept.
const TIMEOUT_MS: u64 = 1_000;
const UNIT_MS: u64 = 100;

fuzz_target!(|data: &[u8]| {
    let mut r = Reader::new(data);
    let flags = r.u8();
    let bound = r.u8();
    let lend = flags & 1 != 0;
    let markers = flags & 2 != 0;
    let mask = mask_from_res((flags >> 2) & 3);
    let max = match bound {
        0 => usize::MAX,
        steps => usize::from(steps) * 64,
    };
    let mut router = Router::new(
        ReassemblyConfig::new(QUOTA, TIMEOUT_MS)
            .with_fragmentation_markers(markers)
            .with_max_message_bytes(max),
    );
    let mut now_ms = 0;
    for unit in units(r.rest()) {
        read_unit(unit, &mut router, mask, now_ms, lend);
        let _ = router.sweep(now_ms);
        holds_every_slot(&router);
        now_ms += UNIT_MS;
    }
});

/// Read `unit` as a session's receive reads a batch: one transport message after another, a
/// Frame's records up to the next transport message, a Fragment into the Router.
fn read_unit(unit: &[u8], router: &mut Router, mask: u64, now_ms: u64, lend: bool) {
    let mut at = 0;
    while at < unit.len() {
        let rest = &unit[at..];
        let Some((message, used)) = read_message(rest) else {
            return;
        };
        match &message {
            InboundFrame::Frame { payload, .. } => {
                assert!(
                    payload.len() <= rest.len(),
                    "a Frame's payload is a part of its unit"
                );
                let Some(next) = walk_frame(payload) else {
                    return;
                };
                at += rest.len() - payload.len() + next;
            }
            InboundFrame::Fragment {
                reliable,
                sn,
                more,
                payload,
                priority,
                markers,
                ..
            } => {
                let fragment = Fragment {
                    peer_key: PEER,
                    reliable: *reliable,
                    sn: *sn,
                    more: u8::from(*more),
                    payload,
                    priority: *priority,
                    markers: *markers,
                };
                ingest(router, fragment, mask, now_ms, lend);
                return;
            }
            _ => {
                // A length this build cannot know for the message ends the unit.
                if used == 0 {
                    return;
                }
                at += used;
            }
        }
    }
}

/// The message at the front of `rest`, read by a participant, held to the observer's read and
/// to the read over a unit that can be shared.
fn read_message(rest: &[u8]) -> Option<(InboundFrame, usize)> {
    let observed = parse_inbound_observed(rest);
    let read = parse_inbound_consuming(rest).ok()?;
    let Ok((_, seen)) = observed else {
        panic!("a participant read a message an observer refuses");
    };
    assert_eq!(
        read.1, seen,
        "the participant and the observer read different lengths"
    );
    assert!(read.1 <= rest.len(), "a read takes no more than its unit");

    let shared = RxBytes::lend(rest.to_vec());
    let Ok((lent, lent_used)) = parse_inbound_consuming_in(&shared) else {
        panic!("the read over a shared unit refused a message the copying read takes");
    };
    assert_eq!(
        lent_used, read.1,
        "the shared and the copying reads read different lengths"
    );
    if let InboundFrame::Frame { payload, .. } = &lent {
        if !payload.is_empty() {
            let unit = shared.as_slice().as_ptr_range();
            let lies = payload.as_slice().as_ptr_range();
            assert!(
                unit.start <= lies.start && lies.end <= unit.end,
                "a Frame read over a shared unit lies inside that unit"
            );
        }
    }
    Some(read)
}

/// Walk a Frame's records every way a reader walks them, and answer where the next transport
/// message of the batch begins in `payload`, or `None` when the records reach its end or the
/// walk halted.
fn walk_frame(payload: &[u8]) -> Option<usize> {
    let batch = parse_frame_payload_best_effort(payload);
    accounts_for_its_bytes(payload, &batch);
    if let Some(next) = batch.next_message_at {
        assert!(
            payload[next] & 0x1F <= T_MID_JOIN,
            "a Frame's records end where a transport message begins"
        );
    }

    // Both walks go front to back, so the owned record a lent one is compared with is found by
    // moving forward only.
    let mut owned = batch.spans.iter().zip(&batch.messages).peekable();
    lent_records(payload, |at, len| {
        while owned.next_if(|((start, _), _)| *start < at).is_some() {}
        if let Some(&(&(start, owned_len), message)) = owned.peek() {
            if start == at && !matches!(message, NetworkMessage::Unknown { .. }) {
                assert_eq!(
                    owned_len, len,
                    "the record at {at}: the owned walk and the lent codec read different lengths"
                );
            }
        }
    });

    let whole = parse_reassembled_payload_best_effort(payload);
    accounts_for_its_bytes(payload, &whole);
    let codec_halt = matches!(whole.halt, Some(BatchHalt::CodecError { .. }));
    match parse_frame_payload(payload) {
        Ok(messages) => {
            assert!(
                !codec_halt,
                "the strict walk took a payload the best-effort walk halts on"
            );
            assert_eq!(
                messages.len(),
                whole.messages.len(),
                "the strict and the best-effort walks read different records"
            );
        }
        Err(_) => assert!(
            codec_halt,
            "the strict walk refused a payload the best-effort walk reads whole"
        ),
    }

    let lean = parse_lowlatency_payload_best_effort(payload);
    accounts_for_its_bytes(payload, &lean);
    assert!(lean.messages.len() <= 1, "a lowlatency unit is one record");

    batch.next_message_at
}

/// The spans of `batch` lie in `payload` in order, one for each record, and with its halt and
/// its next message they account for every byte of it.
fn accounts_for_its_bytes(payload: &[u8], batch: &BatchParse) {
    assert_eq!(
        batch.spans.len(),
        batch.messages.len(),
        "a walk states one span for each record"
    );
    // A record that decodes to more than one message states its span once for each.
    let mut end = 0;
    let mut previous = None;
    for &span in &batch.spans {
        let (at, len) = span;
        if previous != Some(span) {
            assert!(at >= end, "the spans of a walk are in order and apart");
        }
        end = at
            .checked_add(len)
            .filter(|&reach| reach <= payload.len())
            .expect("a span lies inside its payload");
        previous = Some(span);
    }
    match &batch.halt {
        Some(halt) => {
            assert!(
                halt.offset() <= payload.len(),
                "a walk halts inside its payload"
            );
            assert_eq!(
                batch.unparsed_bytes,
                payload.len() - halt.offset(),
                "what a halted walk leaves is the rest from its halt"
            );
            assert!(
                batch.next_message_at.is_none(),
                "a halted walk names no next message"
            );
        }
        None => {
            assert_eq!(batch.unparsed_bytes, 0, "a whole walk leaves nothing");
            assert_eq!(
                end,
                batch.next_message_at.unwrap_or(payload.len()),
                "a whole walk's records reach its end or its next message"
            );
        }
    }
}

/// Hand `fragment` to the Router, each way it delivers a chain, and hold the delivery.
fn ingest(router: &mut Router, fragment: Fragment<'_>, mask: u64, now_ms: u64, lend: bool) {
    let last = fragment.payload;
    let bound = router.max_message_bytes();
    let mut delivered = 0u32;
    let mut check = |chain: &[u8]| {
        delivered += 1;
        assert!(chain.len() <= bound, "a chain is no longer than its bound");
        assert!(
            chain.ends_with(last),
            "a chain ends with the fragment that completed it"
        );
        let whole = parse_reassembled_payload_best_effort(chain);
        accounts_for_its_bytes(chain, &whole);
        lent_records(chain, |_, _| {});
    };
    let outcome = if lend {
        router.ingest_lending(fragment, mask, now_ms, |chain| check(chain.as_slice()))
    } else {
        router.ingest(fragment, mask, now_ms, &mut check)
    };
    assert_eq!(
        delivered,
        u32::from(outcome == IngestOutcome::Reassembled),
        "a chain is delivered exactly when the Router answers Reassembled ({outcome:?})"
    );
    holds_every_slot(router);
}

/// Every slot of the Router is either free or holding a chain: a chain handle is neither leaked
/// nor given back twice.
fn holds_every_slot(router: &Router) {
    assert_eq!(
        router.staging_available() + router.active_chains(),
        SLOTS,
        "every slot is free or holds a chain"
    );
}
