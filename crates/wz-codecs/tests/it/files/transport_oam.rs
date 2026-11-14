// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The whole transport OAM as its document reads and writes it: the header,
//! the id, the extension chain the header's Z flag announces, and the body
//! whose encoding the header names.
//!
//! Each frame is laid out as upstream's codec lays it out
//! (`commons/zenoh-codec/src/transport/oam.rs` @
//! `impl<W> WCodec<&Oam, &mut W> for Zenoh080`): the header with the body's
//! encoding in bits 5 and 6, the id, the chain, then the body.

#![cfg(feature = "alloc")]

use wz_codecs::node::Node;
use wz_codecs::transport_oam::{TransportOamOwned, TransportOamView, TransportOamViewVariant};
use wz_codecs::{Heap, SceCursor};

/// An OAM of id 42 with no body.
const OAM_UNIT: [u8; 2] = [0x00, 0x2A];

/// An OAM of id 2 with the z64 body 9 and its QoS extension (a mandatory z64
/// of id 1, value 7) in its chain.
const OAM_Z64_WITH_QOS: [u8; 5] = [0xA0, 0x02, 0x31, 0x07, 0x09];

/// An OAM of id 129, two VLE bytes, with the ZBuf body `DE AD BE`.
const OAM_ZBUF: [u8; 7] = [0x40, 0x81, 0x01, 0x03, 0xDE, 0xAD, 0xBE];

/// An OAM whose header names the reserved encoding `0b11`.
const OAM_RESERVED: [u8; 2] = [0x60, 0x01];

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
fn an_oam_with_no_body_reads_its_id() {
    let view = read_whole!(TransportOamView::decode, &OAM_UNIT);
    assert_eq!((view.mid(), view.enc(), view.id), (0x00, 0, 42));
    assert!(view.extensions.is_none(), "Z is clear");
    assert!(matches!(
        view.body,
        TransportOamViewVariant::CodecZenohExtUnit(_)
    ));
    assert_eq!(view.encode_to_vec(), OAM_UNIT);
}

#[test]
fn an_oam_reads_its_chain_before_its_body() {
    let view = read_whole!(TransportOamView::decode, &OAM_Z64_WITH_QOS);
    assert_eq!((view.enc(), view.id), (1, 2));
    let chain: Vec<u8> = view
        .extensions
        .as_ref()
        .map(|list| list.inner().iter())
        .into_iter()
        .flatten()
        .map(|entry| entry.header)
        .collect();
    assert_eq!(
        chain,
        [0x31u8],
        "the QoS entry, not the body, follows the id"
    );
    match &view.body {
        TransportOamViewVariant::CodecZenohExtZint(body) => assert_eq!(body.value, 9),
        other => panic!("a z64 body, not {other:?}"),
    }
    assert_eq!(view.encode_to_vec(), OAM_Z64_WITH_QOS);
}

#[test]
fn an_oam_reads_a_zbuf_body_and_a_wide_id() {
    let view = read_whole!(TransportOamView::decode, &OAM_ZBUF);
    assert_eq!((view.enc(), view.id), (2, 129));
    match &view.body {
        TransportOamViewVariant::CodecZenohExtZbuf(body) => {
            assert_eq!(body.value.into_inner(), &[0xDE, 0xAD, 0xBE][..])
        }
        other => panic!("a ZBuf body, not {other:?}"),
    }
    assert_eq!(view.encode_to_vec(), OAM_ZBUF);
}

/// The reserved encoding reaches the default arm, which reads no body: the
/// refusal upstream makes is its reader's, one layer up.
#[test]
fn the_reserved_encoding_reaches_the_default_arm() {
    let view = read_whole!(TransportOamView::decode, &OAM_RESERVED);
    assert_eq!(view.enc(), 3);
    assert!(matches!(view.body, TransportOamViewVariant::Default { .. }));
}

#[test]
fn every_form_writes_an_oam_back_as_it_read_it() {
    for frame in [&OAM_UNIT[..], &OAM_Z64_WITH_QOS[..], &OAM_ZBUF[..]] {
        let node = read_whole!(TransportOamOwned::<Node>::decode, frame);
        assert_eq!(node.encode_to_vec(), frame);
        let heap = read_whole!(TransportOamOwned::<Heap>::decode, frame);
        assert_eq!(heap.encode_to_vec(), frame);
    }
}
