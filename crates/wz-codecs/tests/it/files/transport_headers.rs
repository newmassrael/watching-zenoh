// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The headers of a transport Frame and a transport Fragment as their documents
//! read and write them: the header byte, the SN, and the extension chain the
//! header's Z flag announces, and nothing of the payload after them.
//!
//! Every frame below is laid out as upstream's codec lays the header out
//! (`commons/zenoh-codec/src/transport/frame.rs` @
//! `impl<W> WCodec<&FrameHeader, &mut W> for Zenoh080`, and `fragment.rs`
//! beside it), followed by payload bytes the header must leave unread: the
//! QoS extension is `0x31` (z64, mandatory) with the priority as its value,
//! a Fragment's First and Drop markers are the units `0x02` and `0x03`.

#![cfg(all(feature = "alloc", feature = "codec-frame", feature = "codec-fragment"))]

use wz_codecs::node::Node;
use wz_codecs::transport_fragment_header::{
    TransportFragmentHeaderOwned, TransportFragmentHeaderView,
};
use wz_codecs::transport_frame_header::{TransportFrameHeaderOwned, TransportFrameHeaderView};
use wz_codecs::{Heap, SceCursor};

/// Payload bytes after a header: two network-message ids, which the header
/// must not read.
const PAYLOAD: [u8; 2] = [0x1D, 0x1E];

/// A reliable Frame of SN 5 with no chain.
const FRAME_PLAIN: [u8; 2] = [0x25, 0x05];

/// A best-effort Frame of SN 300 (a two-byte VLE) with the QoS extension of
/// priority 2.
const FRAME_QOS: [u8; 5] = [0x85, 0xAC, 0x02, 0x31, 0x02];

/// A reliable Fragment with more to follow, SN 300, and the chain QoS
/// priority 2, First, Drop.
const FRAGMENT_FIRST: [u8; 7] = [0xE6, 0xAC, 0x02, 0xB1, 0x02, 0x82, 0x03];

/// The last Fragment of a best-effort message, SN 0, no chain.
const FRAGMENT_LAST: [u8; 2] = [0x06, 0x00];

fn with_payload(header: &[u8]) -> Vec<u8> {
    let mut unit = header.to_vec();
    unit.extend_from_slice(&PAYLOAD);
    unit
}

/// The headers of the entries a view's chain yields, none when Z is clear.
macro_rules! chain_headers {
    ($view:expr) => {
        $view
            .extensions
            .as_ref()
            .map(|list| list.inner().iter())
            .into_iter()
            .flatten()
            .map(|entry| entry.header)
            .collect::<Vec<u8>>()
    };
}

/// Decodes the header at the front of `unit` with `$decode` and asserts the
/// payload after it was left unread.
macro_rules! read_header {
    ($decode:expr, $unit:expr) => {{
        let unit: &[u8] = $unit;
        let mut cursor = SceCursor::new(unit);
        let value = $decode(&mut cursor).expect("the header decodes");
        assert_eq!(cursor.remaining(), PAYLOAD.len(), "the payload is left");
        value
    }};
}

#[test]
fn a_frame_header_reads_its_flag_its_sn_and_its_chain_and_leaves_the_payload() {
    let plain = with_payload(&FRAME_PLAIN);
    let view = read_header!(TransportFrameHeaderView::decode, &plain);
    assert_eq!(view.header, 0x25, "R set, Z clear");
    assert_eq!(view.sn, 5);
    assert!(view.extensions.is_none());
    assert_eq!(view.encode_to_vec(), FRAME_PLAIN);

    let qos = with_payload(&FRAME_QOS);
    let view = read_header!(TransportFrameHeaderView::decode, &qos);
    assert_eq!(view.header, 0x85, "R clear, Z set");
    assert_eq!(view.sn, 300);
    assert_eq!(chain_headers!(view), [0x31u8]);
    assert_eq!(view.encode_to_vec(), FRAME_QOS);

    for (header, unit) in [(&FRAME_PLAIN[..], &plain), (&FRAME_QOS[..], &qos)] {
        let node = read_header!(TransportFrameHeaderOwned::<Node>::decode, unit);
        assert_eq!(node.encode_to_vec(), header);
        let heap = read_header!(TransportFrameHeaderOwned::<Heap>::decode, unit);
        assert_eq!(heap.encode_to_vec(), header);
    }
}

#[test]
fn a_fragment_header_reads_its_flags_its_sn_and_its_markers() {
    let first = with_payload(&FRAGMENT_FIRST);
    let view = read_header!(TransportFragmentHeaderView::decode, &first);
    assert_eq!(view.header, 0xE6, "R, M and Z set");
    assert_eq!(view.sn, 300);
    assert_eq!(chain_headers!(view), [0xB1u8, 0x82, 0x03]);
    assert_eq!(view.encode_to_vec(), FRAGMENT_FIRST);

    let last = with_payload(&FRAGMENT_LAST);
    let view = read_header!(TransportFragmentHeaderView::decode, &last);
    assert_eq!(
        view.header, 0x06,
        "no flag: best effort, the last, no chain"
    );
    assert_eq!(view.sn, 0);
    assert!(view.extensions.is_none());
    assert_eq!(view.encode_to_vec(), FRAGMENT_LAST);

    for (header, unit) in [(&FRAGMENT_FIRST[..], &first), (&FRAGMENT_LAST[..], &last)] {
        let node = read_header!(TransportFragmentHeaderOwned::<Node>::decode, unit);
        assert_eq!(node.encode_to_vec(), header);
        let heap = read_header!(TransportFragmentHeaderOwned::<Heap>::decode, unit);
        assert_eq!(heap.encode_to_vec(), header);
    }
}

/// A header cut inside its SN or inside its chain is refused.
#[test]
fn a_header_cut_short_is_refused() {
    for cut in 1..FRAGMENT_FIRST.len() {
        let mut cursor = SceCursor::new(&FRAGMENT_FIRST[..cut]);
        assert!(
            TransportFragmentHeaderView::decode(&mut cursor).is_err(),
            "{cut} of {} bytes",
            FRAGMENT_FIRST.len()
        );
    }
    let mut cursor = SceCursor::new(&FRAME_QOS[..3]);
    assert!(TransportFrameHeaderView::decode(&mut cursor).is_err());
}
