// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The batch of a compressing session as its document reads and writes it: the
//! batch header byte, then the payload to the end of the unit.
//!
//! Each batch is laid out as upstream lays it out
//! (`io/zenoh-transport/src/common/batch.rs` @ `let _ = writer.write_u8(h.as_u8());`):
//! the header with the compression flag in bit 0, then the payload.

#![cfg(feature = "alloc")]

use wz_codecs::compressed_batch::{CompressedBatchOwned, CompressedBatchView};
use wz_codecs::node::Node;
use wz_codecs::{Heap, SceCursor};

/// A batch shipped as it is: the flag clear, then two KeepAlives.
const PLAIN: [u8; 3] = [0x00, 0x04, 0x04];

/// A batch whose payload is an LZ4 block: the flag set, then the block's bytes,
/// which the document holds as bytes.
const COMPRESSED: [u8; 5] = [0x01, 0x30, 0xAA, 0xBB, 0xCC];

/// Decodes `frame` with `$decode` and asserts every byte was consumed.
macro_rules! read_whole {
    ($decode:expr, $frame:expr) => {{
        let frame: &[u8] = $frame;
        let mut cursor = SceCursor::new(frame);
        let value = $decode(&mut cursor).expect("the frame decodes");
        assert_eq!(cursor.remaining(), 0, "the frame was read whole");
        value
    }};
}

#[test]
fn a_plain_batch_reads_its_messages_as_the_payload() {
    let view = read_whole!(CompressedBatchView::decode, &PLAIN);
    assert!(!view.compression(), "the flag is clear");
    assert_eq!(view.payload.into_inner(), &PLAIN[1..]);
    assert_eq!(view.encode_to_vec(), PLAIN);
}

#[test]
fn a_compressed_batch_reads_its_block_as_the_payload() {
    let view = read_whole!(CompressedBatchView::decode, &COMPRESSED);
    assert!(view.compression(), "the flag is set");
    assert_eq!(view.payload.into_inner(), &COMPRESSED[1..]);
    assert_eq!(view.encode_to_vec(), COMPRESSED);
}

/// A unit with no header byte is no batch.
#[test]
fn an_empty_unit_is_refused() {
    assert!(CompressedBatchView::decode(&mut SceCursor::new(&[])).is_err());
}

#[test]
fn every_form_writes_a_batch_back_as_it_read_it() {
    for frame in [&PLAIN[..], &COMPRESSED[..]] {
        let node = read_whole!(CompressedBatchOwned::<Node>::decode, frame);
        assert_eq!(node.encode_to_vec(), frame);
        let heap = read_whole!(CompressedBatchOwned::<Heap>::decode, frame);
        assert_eq!(heap.encode_to_vec(), frame);
    }
}
