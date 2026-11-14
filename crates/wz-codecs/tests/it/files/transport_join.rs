// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The whole transport Join as its document reads and writes it: the header,
//! the body, and the extension chain the header's Z flag announces.
//!
//! Each frame is laid out as upstream's codec lays it out
//! (`commons/zenoh-codec/src/transport/join.rs` @
//! `impl<W> WCodec<&Join, &mut W> for Zenoh080`): the header, the version,
//! `(zid length - 1) << 4 | whatami`, the zid, with S the resolution byte and
//! the batch size little-endian, the lease, the two next SNs, then the chain.

#![cfg(all(feature = "alloc", feature = "codec-join"))]

use wz_codecs::node::Node;
use wz_codecs::transport_join::{TransportJoinOwned, TransportJoinView};
use wz_codecs::{Heap, SceCursor};

/// A Join with T (lease in seconds), S and Z: a peer with zid `AA BB`,
/// resolution byte `0x0A`, batch size 65535, lease 10, next SNs 5 and 6, and
/// the patch level 1 in its chain.
const JOIN_FULL: [u8; 13] = [
    0xE7, 0x09, 0x11, 0xAA, 0xBB, 0x0A, 0xFF, 0xFF, 0x0A, 0x05, 0x06, 0x27, 0x01,
];

/// The same peer's Join with T alone: no size parameters, no chain.
const JOIN_MINIMAL: [u8; 8] = [0x27, 0x09, 0x11, 0xAA, 0xBB, 0x0A, 0x05, 0x06];

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
fn a_full_join_reads_its_size_parameters_and_its_chain() {
    let view = read_whole!(TransportJoinView::decode, &JOIN_FULL);
    assert_eq!(view.header, 0xE7);
    assert_eq!(view.body.zid.as_bytes().into_inner(), &[0xAA, 0xBB][..]);
    let size = view.body.s.expect("S is set");
    assert_eq!((size.sn_res, size.batch_size), (0x0A, 0xFFFF));
    assert_eq!(view.body.lease, 10, "the lease as the wire carries it");
    assert_eq!(
        (view.body.next_sn_reliable, view.body.next_sn_best_effort),
        (5, 6)
    );
    let chain: Vec<u8> = view
        .extensions
        .as_ref()
        .map(|list| list.inner().iter())
        .into_iter()
        .flatten()
        .map(|entry| entry.header)
        .collect();
    assert_eq!(chain, [0x27u8]);
    assert_eq!(view.encode_to_vec(), JOIN_FULL);
}

#[test]
fn a_minimal_join_reads_no_size_parameters_and_no_chain() {
    let view = read_whole!(TransportJoinView::decode, &JOIN_MINIMAL);
    assert_eq!(view.header, 0x27);
    assert!(view.body.s.is_none(), "S is clear");
    assert!(view.extensions.is_none(), "Z is clear");
    assert_eq!(view.encode_to_vec(), JOIN_MINIMAL);
}

#[test]
fn every_form_writes_a_join_back_as_it_read_it() {
    for frame in [&JOIN_FULL[..], &JOIN_MINIMAL[..]] {
        let node = read_whole!(TransportJoinOwned::<Node>::decode, frame);
        assert_eq!(node.encode_to_vec(), frame);
        let heap = read_whole!(TransportJoinOwned::<Heap>::decode, frame);
        assert_eq!(heap.encode_to_vec(), frame);
    }
}
