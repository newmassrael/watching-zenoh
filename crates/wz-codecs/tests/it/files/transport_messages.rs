// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The whole transport messages of the handshake (Init, Open, Close,
//! KeepAlive) as their documents read and write them: the header byte, the
//! body, and the extension chain the header's Z flag announces.
//!
//! Every frame below is laid out as upstream's codec lays it out
//! (`commons/zenoh-codec/src/transport/init.rs` @
//! `impl<W> WCodec<&InitSyn, &mut W> for Zenoh080`, and the `open.rs`,
//! `close.rs` and `keepalive.rs` beside it): the header, then the body, then
//! each extension as `id | M(0x10) | enc<<5 | Z(0x80)` followed by its body by
//! encoding, the last entry with Z clear. Each frame is read by the view, by
//! the node's deployment and by the heap; each form must consume every byte,
//! say what the frame says, and write the same bytes back.

#![cfg(all(
    feature = "alloc",
    feature = "codec-init-body",
    feature = "codec-open-body",
    feature = "codec-close",
    feature = "codec-keep-alive"
))]

use sce_forge_runtime::codec::CodecError;
use wz_codecs::node::Node;
use wz_codecs::transport_close::{TransportCloseOwned, TransportCloseView};
use wz_codecs::transport_init::{TransportInitOwned, TransportInitView};
use wz_codecs::transport_keep_alive::{TransportKeepAliveOwned, TransportKeepAliveView};
use wz_codecs::transport_open::{TransportOpenOwned, TransportOpenView};
use wz_codecs::{Heap, SceCursor};

/// An InitSyn from a peer with a four-byte zid and the size parameters, and
/// no extension: header `S`, version 0x09, `cbyte` = (zid length - 1) << 4 |
/// peer, the zid, the resolution byte and the batch size little-endian.
const INIT_SYN: [u8; 10] = [0x41, 0x09, 0x31, 0x11, 0x22, 0x33, 0x44, 0x0A, 0xFF, 0xFF];

/// An InitAck from a router with a two-byte zid, the size parameters, a
/// three-byte cookie, and a chain of two entries: the QoS unit (id 0x1, Z
/// set) and the patch level as a z64 (id 0x7, value 1).
const INIT_ACK: [u8; 15] = [
    0xE1, 0x09, 0x10, 0xAA, 0xBB, 0x0A, 0x00, 0x08, 0x03, 0x01, 0x02, 0x03, 0x81, 0x27, 0x01,
];

/// An OpenSyn with a lease in seconds (T), lease 10, initial SN 0x1234 as a
/// two-byte VLE, and a three-byte cookie.
const OPEN_SYN: [u8; 8] = [0x42, 0x0A, 0xB4, 0x24, 0x03, 0xC0, 0xFF, 0xEE];

/// An OpenAck with a lease of 1500 ms (T clear), initial SN 0, no cookie,
/// and one entry: the patch level, a z64 of value 1.
const OPEN_ACK: [u8; 6] = [0xA2, 0xDC, 0x0B, 0x00, 0x27, 0x01];

/// A session Close (S) with reason 0x05 and no chain.
const CLOSE_SESSION: [u8; 2] = [0x23, 0x05];

/// A link-only Close with reason 0x00 and one entry no Close declares: id 0x9
/// as a ZBuf of two bytes.
const CLOSE_LINK_WITH_EXT: [u8; 6] = [0x83, 0x00, 0x49, 0x02, 0xDE, 0xAD];

/// A KeepAlive with no chain.
const KEEP_ALIVE: [u8; 1] = [0x04];

/// A KeepAlive with one unit entry of id 0x5 and the mandatory bit set. The
/// decode reads it; whether a participant admits it is judged one layer up.
const KEEP_ALIVE_WITH_MANDATORY: [u8; 2] = [0x84, 0x15];

/// The headers of the entries a view's chain yields, in order: none when the
/// header's Z flag is clear.
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

/// Decodes `frame` with `$decode`, asserts every byte was consumed, and
/// returns the value.
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
fn an_init_syn_without_a_chain_reads_and_writes_as_upstream_lays_it_out() {
    let view = read_whole!(TransportInitView::decode, &INIT_SYN);
    assert_eq!(view.header, 0x41);
    assert_eq!(view.body.version, 0x09);
    assert_eq!(view.body.cbyte, 0x31);
    assert_eq!(
        view.body.zid.as_bytes().into_inner(),
        &[0x11, 0x22, 0x33, 0x44][..]
    );
    let size = view
        .body
        .s
        .expect("S is set, so the size parameters are read");
    assert_eq!((size.sn_res, size.batch_size), (0x0A, 0xFFFF));
    assert!(view.body.cookie.is_none(), "an InitSyn carries no cookie");
    assert!(view.extensions.is_none(), "Z is clear");
    assert_eq!(view.encode_to_vec(), INIT_SYN);

    let node = read_whole!(TransportInitOwned::<Node>::decode, &INIT_SYN);
    assert_eq!(node.encode_to_vec(), INIT_SYN);
    let heap = read_whole!(TransportInitOwned::<Heap>::decode, &INIT_SYN);
    assert_eq!(heap.encode_to_vec(), INIT_SYN);
}

#[test]
fn an_init_ack_with_a_cookie_and_a_chain_reads_and_writes_as_upstream_lays_it_out() {
    let view = read_whole!(TransportInitView::decode, &INIT_ACK);
    assert_eq!(view.header, 0xE1);
    assert_eq!(view.body.cbyte, 0x10);
    assert_eq!(view.body.zid.as_bytes().into_inner(), &[0xAA, 0xBB][..]);
    let size = view.body.s.expect("S is set");
    assert_eq!((size.sn_res, size.batch_size), (0x0A, 0x0800));
    assert_eq!(
        view.body
            .cookie
            .as_ref()
            .map(|cookie| cookie.as_bytes().into_inner()),
        Some(&[0x01, 0x02, 0x03][..]),
        "A is set, so the cookie is read"
    );
    assert_eq!(chain_headers!(view), [0x81u8, 0x27]);
    assert_eq!(view.encode_to_vec(), INIT_ACK);

    let node = read_whole!(TransportInitOwned::<Node>::decode, &INIT_ACK);
    assert_eq!(node.encode_to_vec(), INIT_ACK);
    let heap = read_whole!(TransportInitOwned::<Heap>::decode, &INIT_ACK);
    assert_eq!(heap.encode_to_vec(), INIT_ACK);
}

#[test]
fn an_open_syn_reads_its_cookie_and_keeps_the_lease_unit_flag() {
    let view = read_whole!(TransportOpenView::decode, &OPEN_SYN);
    assert_eq!(view.header, 0x42, "T stays on the header as the wire says");
    assert_eq!(view.body.lease, 10, "the lease as the wire carries it");
    assert_eq!(view.body.initial_sn, 0x1234);
    assert_eq!(
        view.body
            .cookie
            .as_ref()
            .map(|cookie| cookie.as_bytes().into_inner()),
        Some(&[0xC0, 0xFF, 0xEE][..]),
        "A is clear, so the cookie is read"
    );
    assert!(view.extensions.is_none());
    assert_eq!(view.encode_to_vec(), OPEN_SYN);

    let node = read_whole!(TransportOpenOwned::<Node>::decode, &OPEN_SYN);
    assert_eq!(node.encode_to_vec(), OPEN_SYN);
    let heap = read_whole!(TransportOpenOwned::<Heap>::decode, &OPEN_SYN);
    assert_eq!(heap.encode_to_vec(), OPEN_SYN);
}

#[test]
fn an_open_ack_reads_no_cookie_and_its_chain() {
    let view = read_whole!(TransportOpenView::decode, &OPEN_ACK);
    assert_eq!(view.header, 0xA2);
    assert_eq!(view.body.lease, 1500);
    assert_eq!(view.body.initial_sn, 0);
    assert!(view.body.cookie.is_none(), "A is set, so no cookie is read");
    assert_eq!(chain_headers!(view), [0x27u8]);
    assert_eq!(view.encode_to_vec(), OPEN_ACK);

    let node = read_whole!(TransportOpenOwned::<Node>::decode, &OPEN_ACK);
    assert_eq!(node.encode_to_vec(), OPEN_ACK);
    let heap = read_whole!(TransportOpenOwned::<Heap>::decode, &OPEN_ACK);
    assert_eq!(heap.encode_to_vec(), OPEN_ACK);
}

#[test]
fn a_close_reads_its_scope_its_reason_and_an_undeclared_entry() {
    let session = read_whole!(TransportCloseView::decode, &CLOSE_SESSION);
    assert_eq!(session.header, 0x23, "S: the whole session");
    assert_eq!(session.body.reason, 0x05);
    assert!(session.extensions.is_none());
    assert_eq!(session.encode_to_vec(), CLOSE_SESSION);

    let link = read_whole!(TransportCloseView::decode, &CLOSE_LINK_WITH_EXT);
    assert_eq!(link.header, 0x83, "S clear: the link only; Z set");
    assert_eq!(link.body.reason, 0x00);
    assert_eq!(chain_headers!(link), [0x49u8]);
    assert_eq!(link.encode_to_vec(), CLOSE_LINK_WITH_EXT);

    for frame in [&CLOSE_SESSION[..], &CLOSE_LINK_WITH_EXT[..]] {
        let node = read_whole!(TransportCloseOwned::<Node>::decode, frame);
        assert_eq!(node.encode_to_vec(), frame);
        let heap = read_whole!(TransportCloseOwned::<Heap>::decode, frame);
        assert_eq!(heap.encode_to_vec(), frame);
    }
}

#[test]
fn a_keep_alive_reads_an_empty_body_and_a_mandatory_entry() {
    let bare = read_whole!(TransportKeepAliveView::decode, &KEEP_ALIVE);
    assert_eq!(bare.header, 0x04);
    assert!(bare.extensions.is_none());
    assert_eq!(bare.encode_to_vec(), KEEP_ALIVE);

    let marked = read_whole!(TransportKeepAliveView::decode, &KEEP_ALIVE_WITH_MANDATORY);
    assert_eq!(marked.header, 0x84);
    assert_eq!(chain_headers!(marked), [0x15u8]);
    assert_eq!(marked.encode_to_vec(), KEEP_ALIVE_WITH_MANDATORY);

    for frame in [&KEEP_ALIVE[..], &KEEP_ALIVE_WITH_MANDATORY[..]] {
        let node = read_whole!(TransportKeepAliveOwned::<Node>::decode, frame);
        assert_eq!(node.encode_to_vec(), frame);
        let heap = read_whole!(TransportKeepAliveOwned::<Heap>::decode, frame);
        assert_eq!(heap.encode_to_vec(), frame);
    }
}

/// A chain whose last entry still has Z set ends with the frame: the decode
/// asks for more bytes rather than reading past the message.
#[test]
fn a_chain_that_never_ends_asks_for_more_bytes() {
    // A KeepAlive announcing a chain whose only entry announces another.
    let open_ended = [0x84, 0x81];
    let mut cursor = SceCursor::new(&open_ended);
    assert_eq!(
        TransportKeepAliveView::decode(&mut cursor).err(),
        Some(CodecError::NeedMoreBytes)
    );
}

/// A header that announces a chain with no byte after it is refused the same
/// way, and so is an Init whose body stops inside the zid.
#[test]
fn a_frame_cut_short_is_refused() {
    let mut cursor = SceCursor::new(&[0x81]);
    assert!(TransportInitView::decode(&mut cursor).is_err());
    let mut cursor = SceCursor::new(&INIT_SYN[..5]);
    assert!(TransportInitView::decode(&mut cursor).is_err());
}

/// Eight entries are what a node holds of a transport chain; a ninth is read
/// by the view, which holds no list, and refused by the node's deployment as
/// past its capacity, while the heap holds it.
#[test]
fn a_ninth_entry_is_past_the_node_capacity_and_not_past_the_view() {
    let mut frame = vec![0x84];
    frame.extend([0x81u8; 8]);
    frame.push(0x01);
    let view = read_whole!(TransportKeepAliveView::decode, &frame);
    assert_eq!(chain_headers!(view).len(), 9);
    assert_eq!(
        TransportKeepAliveOwned::<Node>::decode(&mut SceCursor::new(&frame)).err(),
        Some(CodecError::CapacityExceeded)
    );
    let heap = read_whole!(TransportKeepAliveOwned::<Heap>::decode, &frame);
    assert_eq!(heap.encode_to_vec(), frame);
}
