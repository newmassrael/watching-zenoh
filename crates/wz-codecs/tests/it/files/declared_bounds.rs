// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A length a frame states past the protocol's bound of its field is refused at
//! decode with `LengthOutOfRange`, before a byte of it is held, by every form a
//! wz node reads the field in: lent, the node's deployment and the heap. The two
//! fields whose length is a count of their own rather than a nibble are the
//! subject, a timestamp's identity and a locator. Upstream's codec refuses both
//! (`commons/zenoh-codec/src/core/timestamp.rs` @ `uhlc::ID::MAX_SIZE`,
//! `commons/zenoh-codec/src/core/locator.rs` @ `Zenoh080Bounded::<u8>::new()`).
//!
//! The frame at the bound is the control: without it a refusal could come from
//! a check that fires on every frame.

#![cfg(feature = "alloc")]

use sce_forge_runtime::codec::CodecError;
use wz_codecs::locator::{Locator, LocatorOwned};
use wz_codecs::node::Node;
use wz_codecs::timestamp::{Timestamp, TimestampOwned};
use wz_codecs::{Heap, SceCursor};

/// What one form answers for a frame: the length it read, or its refusal.
type Answer = Result<usize, CodecError>;

const PAST_BOUND: Answer = Err(CodecError::LengthOutOfRange);

/// A timestamp of time 1 whose identity is `n` bytes, `n` stated in the VLE
/// length the field is read by (one byte for every `n` here).
fn timestamp_frame(n: u8) -> Vec<u8> {
    let mut frame = vec![0x01, n];
    frame.extend(1..=n);
    frame
}

/// The identity length each form reads out of `frame`, in the order lent, node,
/// heap.
fn timestamp_answers(frame: &[u8]) -> Vec<Answer> {
    vec![
        Timestamp::decode(&mut SceCursor::new(frame)).map(|t| t.zid.as_bytes().into_inner().len()),
        TimestampOwned::<Node>::decode(&mut SceCursor::new(frame))
            .map(|t| t.zid.as_bytes().into_inner().len()),
        TimestampOwned::<Heap>::decode(&mut SceCursor::new(frame))
            .map(|t| t.zid.as_bytes().into_inner().len()),
    ]
}

/// A locator of `n` ASCII bytes, `n` stated as a VLE.
fn locator_frame(n: usize) -> Vec<u8> {
    let mut frame = Vec::new();
    let mut len = n;
    while len >= 0x80 {
        frame.push((len as u8 & 0x7F) | 0x80);
        len >>= 7;
    }
    frame.push(len as u8);
    frame.resize(frame.len() + n, b'a');
    frame
}

/// The locator length each form reads out of `frame`, in the order lent, node,
/// heap.
fn locator_answers(frame: &[u8]) -> Vec<Answer> {
    vec![
        Locator::decode(&mut SceCursor::new(frame)).map(|l| l.locator.as_text().into_inner().len()),
        LocatorOwned::<Node>::decode(&mut SceCursor::new(frame))
            .map(|l| l.locator.as_text().into_inner().len()),
        LocatorOwned::<Heap>::decode(&mut SceCursor::new(frame))
            .map(|l| l.locator.as_text().into_inner().len()),
    ]
}

#[test]
fn a_timestamp_identity_of_sixteen_bytes_is_read_by_every_form() {
    let read: Answer = Ok(16);
    assert_eq!(timestamp_answers(&timestamp_frame(16)), [read; 3]);
}

#[test]
fn a_timestamp_identity_of_seventeen_bytes_is_refused_by_every_form() {
    assert_eq!(timestamp_answers(&timestamp_frame(17)), [PAST_BOUND; 3]);
}

/// At the bound the frame is sound everywhere; the node holds a locator only to
/// the capacity its deployment gives it (`deploy/codec_node.yaml`), so it alone
/// answers the capacity, and only after reading the frame whole.
#[test]
fn a_locator_at_its_bound_is_read_and_only_the_node_answers_its_capacity() {
    let capacity = wz_codecs::locator::MAX_LOCATOR_LEN;
    let read: Answer = Ok(capacity);
    assert_eq!(locator_answers(&locator_frame(capacity)), [read; 3]);
    let at_bound: [Answer; 3] = [Ok(255), Err(CodecError::CapacityExceeded), Ok(255)];
    assert_eq!(locator_answers(&locator_frame(255)), at_bound);
}

#[test]
fn a_locator_past_its_bound_is_refused_by_every_form_before_its_capacity() {
    assert_eq!(locator_answers(&locator_frame(256)), [PAST_BOUND; 3]);
}
