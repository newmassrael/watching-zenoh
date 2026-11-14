// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The transport messages of the handshake as this crate writes and reads them
//! (`handshake_encode`, `inbound`), held to the documents that state each whole
//! message (`sources/codecs/transport_{init,open,close,keep_alive}.scxml`).
//!
//! Two directions, for every message:
//!
//! - what an encoder here writes, the document's view reads whole and writes
//!   back byte for byte, and it reads the same header flags, body and chain
//!   the decoder here reads out of the same bytes;
//! - a frame laid out as upstream lays it out (`commons/zenoh-codec/src/transport/init.rs`
//!   @ `impl<W> WCodec<&InitSyn, &mut W> for Zenoh080`, and the `open.rs`,
//!   `close.rs` and `keepalive.rs` beside it) is what an encoder here writes
//!   for the same values, and the decoder here and the view read it alike.
//!
//! The one difference between the two readers is the bound on a chain: the
//! decoder here refuses a chain of more than `MAX_EXT_CHAIN_DEPTH` entries,
//! and the view, which holds no list, reads it. A decoder built on the view
//! keeps the bound by counting what it walks; the last test holds that.

use alloc::vec;
use alloc::vec::Vec;

use sce_forge_runtime::codec::SceCursor;
use wz_codecs::transport_close::TransportCloseView;
use wz_codecs::transport_init::TransportInitView;
use wz_codecs::transport_keep_alive::TransportKeepAliveView;
use wz_codecs::transport_open::TransportOpenView;
use wz_codecs::whatami::WhatAmI;
use wz_codecs::wire_const;

use crate::ext_chain::ChainHeaders;
use crate::handshake_encode::{encode_close, encode_init, encode_keep_alive, encode_open};
use crate::inbound::{parse_inbound, InboundFrame};
use crate::parse_error::{InboundParseError, MAX_EXT_CHAIN_DEPTH};
use crate::session_init_params::{cookie_bytes, zid_bytes, SessionInitParams};
use crate::transport_profile::{ExtEntryOwned, ExtEntryOwnedVariant};

/// The InitAck of `wz-codecs`' `transport_messages` test: a router with zid
/// `AA BB`, resolution byte `0x0A`, batch size 2048, cookie `01 02 03`, and the
/// QoS unit and the patch level 1 in its chain.
const UPSTREAM_INIT_ACK: [u8; 15] = [
    0xE1, 0x09, 0x10, 0xAA, 0xBB, 0x0A, 0x00, 0x08, 0x03, 0x01, 0x02, 0x03, 0x81, 0x27, 0x01,
];

/// The OpenSyn of the same test: lease 10 s, initial SN 0x1234, cookie `C0 FF EE`.
const UPSTREAM_OPEN_SYN: [u8; 8] = [0x42, 0x0A, 0xB4, 0x24, 0x03, 0xC0, 0xFF, 0xEE];

/// The OpenAck of the same test: lease 1500 ms, initial SN 0, the patch level 1.
const UPSTREAM_OPEN_ACK: [u8; 6] = [0xA2, 0xDC, 0x0B, 0x00, 0x27, 0x01];

/// A link-only Close with reason 0 and an entry of id 0x9 no Close declares.
const UPSTREAM_CLOSE_WITH_EXT: [u8; 6] = [0x83, 0x00, 0x49, 0x02, 0xDE, 0xAD];

/// A KeepAlive with one unit entry of id 0x5 and the mandatory bit set.
const UPSTREAM_KEEP_ALIVE_WITH_EXT: [u8; 2] = [0x84, 0x15];

fn init_params(whatami: WhatAmI, zid: &[u8], lease_ms: u64) -> SessionInitParams {
    SessionInitParams {
        whatami,
        zid: zid_bytes(zid),
        // 0x0A on the wire: `seq_num_res | req_id_res << 2`.
        seq_num_res: 2,
        req_id_res: 2,
        batch_size: 2048,
        lease_ms,
        keep_alive: crate::session_init_params::KeepAliveConf::default(),
        initial_sn: 0x1234,
        cookie: cookie_bytes(&[0x01, 0x02, 0x03]),
        tx_queue: crate::session_init_params::TxQueueConf::default(),
        link_rx: crate::session_init_params::LinkRxConf::default(),
        cookie_signing_key: crate::signing_key::SigningKey::new(vec![0xAB; 32])
            .expect("32-byte test key"),
    }
}

fn unit(header: u8) -> ExtEntryOwned {
    ExtEntryOwned {
        header,
        body: ExtEntryOwnedVariant::CodecZenohExtUnit(wz_codecs::ext_unit::ExtUnit {}),
    }
}

/// The chains every encoder is driven with: none, one entry, and two entries
/// of two encodings, so the continuation flag is set on one entry and cleared
/// on the last.
fn chains() -> [Vec<ExtEntryOwned>; 3] {
    [
        Vec::new(),
        vec![crate::extpatch::encode_patch_ext_at(1)],
        vec![unit(0x01), crate::extpatch::encode_patch_ext_at(1)],
    ]
}

/// The headers of the entries a view's chain yields, none when its header's Z
/// flag is clear.
macro_rules! view_chain_headers {
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
        let value = $decode(&mut cursor).expect("the document reads the frame");
        assert_eq!(cursor.remaining(), 0, "the document read the frame whole");
        value
    }};
}

/// The decoder here and the view of `transport_init` read `wire` alike, and
/// the view writes it back unchanged.
fn assert_init_read_alike(wire: &[u8]) {
    let view = read_whole!(TransportInitView::decode, wire);
    assert_eq!(view.encode_to_vec(), wire, "the view writes the frame back");
    match parse_inbound(wire) {
        Ok(InboundFrame::Init {
            is_ack,
            has_ext,
            body,
            extensions,
        }) => {
            assert_eq!(is_ack, view.header & wire_const::FLAG_T_INIT_A != 0);
            assert_eq!(has_ext, view.extensions.is_some());
            assert_eq!(body.encode_to_vec(), view.body.encode_to_vec());
            assert_eq!(
                extensions.chain_headers().collect::<Vec<u8>>(),
                view_chain_headers!(view)
            );
        }
        Ok(_) => panic!("the decoder here read another message"),
        Err(refused) => panic!("the decoder here refused the frame: {refused:?}"),
    }
}

/// [`assert_init_read_alike`] for `transport_open`. The decoder here hands the
/// lease over in milliseconds, so the view's wire value is projected the same
/// way before the two are compared.
fn assert_open_read_alike(wire: &[u8]) {
    let view = read_whole!(TransportOpenView::decode, wire);
    assert_eq!(view.encode_to_vec(), wire, "the view writes the frame back");
    match parse_inbound(wire) {
        Ok(InboundFrame::Open {
            is_ack,
            has_ext,
            body,
            extensions,
        }) => {
            assert_eq!(is_ack, view.header & wire_const::FLAG_T_OPEN_A != 0);
            assert_eq!(has_ext, view.extensions.is_some());
            assert_eq!(
                body.lease,
                crate::lease::lease_from_wire(
                    view.header & wire_const::FLAG_T_OPEN_T != 0,
                    view.body.lease
                )
            );
            assert_eq!(body.initial_sn, view.body.initial_sn);
            assert_eq!(
                body.cookie.as_ref().map(|c| c.as_bytes().into_inner()),
                view.body.cookie.as_ref().map(|c| c.as_bytes().into_inner())
            );
            assert_eq!(
                extensions.chain_headers().collect::<Vec<u8>>(),
                view_chain_headers!(view)
            );
        }
        Ok(_) => panic!("the decoder here read another message"),
        Err(refused) => panic!("the decoder here refused the frame: {refused:?}"),
    }
}

/// [`assert_init_read_alike`] for `transport_close`.
fn assert_close_read_alike(wire: &[u8]) {
    let view = read_whole!(TransportCloseView::decode, wire);
    assert_eq!(view.encode_to_vec(), wire, "the view writes the frame back");
    match parse_inbound(wire) {
        Ok(InboundFrame::Close {
            reason,
            session,
            has_ext,
            extensions,
        }) => {
            assert_eq!(reason, view.body.reason);
            assert_eq!(session, view.header & wire_const::FLAG_T_CLOSE_S != 0);
            assert_eq!(has_ext, view.extensions.is_some());
            assert_eq!(
                extensions.chain_headers().collect::<Vec<u8>>(),
                view_chain_headers!(view)
            );
        }
        Ok(_) => panic!("the decoder here read another message"),
        Err(refused) => panic!("the decoder here refused the frame: {refused:?}"),
    }
}

/// [`assert_init_read_alike`] for `transport_keep_alive`.
fn assert_keep_alive_read_alike(wire: &[u8]) {
    let view = read_whole!(TransportKeepAliveView::decode, wire);
    assert_eq!(view.encode_to_vec(), wire, "the view writes the frame back");
    match parse_inbound(wire) {
        Ok(InboundFrame::KeepAlive {
            has_ext,
            extensions,
        }) => {
            assert_eq!(has_ext, view.extensions.is_some());
            assert_eq!(
                extensions.chain_headers().collect::<Vec<u8>>(),
                view_chain_headers!(view)
            );
        }
        Ok(_) => panic!("the decoder here read another message"),
        Err(refused) => panic!("the decoder here refused the frame: {refused:?}"),
    }
}

#[test]
fn every_init_written_here_is_the_init_the_document_reads() {
    for whatami in [WhatAmI::Router, WhatAmI::Peer, WhatAmI::Client] {
        for zid in [&[0x01][..], &[0xAA, 0xBB][..], &[0x5C; 16][..]] {
            let params = init_params(whatami, zid, 10_000);
            for chain in chains() {
                for is_ack in [false, true] {
                    for cookie in [None, Some(&[0x77u8; 9][..])] {
                        let wire = encode_init(&params, is_ack, &chain, cookie).expect("encodes");
                        assert_init_read_alike(&wire);
                    }
                }
            }
        }
    }
}

#[test]
fn the_init_written_here_for_upstreams_values_is_upstreams_frame() {
    let params = init_params(WhatAmI::Router, &[0xAA, 0xBB], 10_000);
    let chain = [unit(0x01), crate::extpatch::encode_patch_ext_at(1)];
    let wire = encode_init(&params, true, &chain, None).expect("encodes");
    assert_eq!(wire, UPSTREAM_INIT_ACK);
    assert_init_read_alike(&UPSTREAM_INIT_ACK);
}

#[test]
fn every_open_written_here_is_the_open_the_document_reads() {
    // A whole-second lease rides the wire in seconds with T set; another in
    // milliseconds with T clear.
    for lease_ms in [10_000, 1_500] {
        let params = init_params(WhatAmI::Peer, &[0x01, 0x02], lease_ms);
        for chain in chains() {
            for is_ack in [false, true] {
                for cookie in [None, Some(&[0x77u8; 9][..])] {
                    let wire = encode_open(&params, is_ack, cookie, &chain).expect("encodes");
                    assert_open_read_alike(&wire);
                }
            }
        }
    }
}

#[test]
fn the_opens_written_here_for_upstreams_values_are_upstreams_frames() {
    let syn = encode_open(
        &init_params(WhatAmI::Peer, &[0x01], 10_000),
        false,
        Some(&[0xC0, 0xFF, 0xEE][..]),
        &[],
    )
    .expect("encodes");
    assert_eq!(syn, UPSTREAM_OPEN_SYN);
    assert_open_read_alike(&UPSTREAM_OPEN_SYN);

    let mut ack_params = init_params(WhatAmI::Peer, &[0x01], 1_500);
    ack_params.initial_sn = 0;
    let ack = encode_open(
        &ack_params,
        true,
        None,
        &[crate::extpatch::encode_patch_ext_at(1)],
    )
    .expect("encodes");
    assert_eq!(ack, UPSTREAM_OPEN_ACK);
    assert_open_read_alike(&UPSTREAM_OPEN_ACK);
}

#[test]
fn every_close_written_here_is_the_close_the_document_reads() {
    for reason in [0x00, 0x05, 0x07, 0xFF] {
        for session in [false, true] {
            let wire = encode_close(reason, session);
            assert_eq!(
                wire,
                [wire_const::T_MID_CLOSE | (u8::from(session) << 5), reason]
            );
            assert_close_read_alike(&wire);
        }
    }
    assert_close_read_alike(&UPSTREAM_CLOSE_WITH_EXT);
}

#[test]
fn the_multicast_close_written_into_a_slice_is_the_close_the_document_reads() {
    let mut slot = [0u8; 4];
    let used = crate::handshake_encode::encode_multicast_close_into_slice(&mut slot)
        .expect("two bytes fit");
    assert_eq!(
        &slot[..used],
        crate::handshake_encode::encode_multicast_close()
    );
    assert_close_read_alike(&slot[..used]);
}

#[test]
fn the_keep_alive_written_here_is_the_keep_alive_the_document_reads() {
    assert_keep_alive_read_alike(&encode_keep_alive());
    assert_keep_alive_read_alike(&UPSTREAM_KEEP_ALIVE_WITH_EXT);
}

/// A frame cut inside its body or its chain is refused by both readers.
#[test]
fn a_frame_cut_short_is_refused_by_both_readers() {
    let init = encode_init(
        &init_params(WhatAmI::Peer, &[0x01, 0x02], 10_000),
        true,
        &chains()[2],
        None,
    )
    .expect("encodes");
    for cut in 1..init.len() {
        let short = &init[..cut];
        assert!(
            TransportInitView::decode(&mut SceCursor::new(short)).is_err(),
            "the view refuses {cut} of {} bytes",
            init.len()
        );
        assert!(
            parse_inbound(short).is_err(),
            "the decoder here refuses {cut} of {} bytes",
            init.len()
        );
    }
}

/// A chain one entry past what the decoder here reads is refused by it and read
/// by the view; a decoder built on the view keeps the bound by counting what it
/// walks, and at the bound both read the chain.
#[test]
fn a_chain_past_the_bound_is_refused_here_and_read_by_the_view() {
    // Entries of id 0xC, which no build reads, so a build that keeps only the
    // entries it reads holds none of them and is judged by the count alone.
    let keep_alive_with = |entries: usize| {
        let mut wire = vec![wire_const::T_MID_KEEP_ALIVE | 0x80];
        wire.resize(entries, 0x8C);
        wire.push(0x0C);
        wire
    };

    let at_bound = keep_alive_with(MAX_EXT_CHAIN_DEPTH);
    assert_keep_alive_read_alike(&at_bound);

    let past = keep_alive_with(MAX_EXT_CHAIN_DEPTH + 1);
    let view = read_whole!(TransportKeepAliveView::decode, &past);
    assert_eq!(view_chain_headers!(view).len(), MAX_EXT_CHAIN_DEPTH + 1);
    assert!(matches!(
        parse_inbound(&past),
        Err(InboundParseError::ExtChainOverflow)
    ));
}
