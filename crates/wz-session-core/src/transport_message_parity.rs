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
//! Both readers read a chain to the entry whose `Z` flag is clear, whatever its
//! length; the last test holds that.
//!
//! The transport OAM, which no node here writes, is held in the second
//! direction alone (`transport_oam.scxml`, `commons/zenoh-codec/src/transport/oam.rs`
//! @ `impl<W> WCodec<&Oam, &mut W> for Zenoh080`), with the one refusal the
//! document leaves to its reader: the reserved body encoding.

use alloc::vec;
use alloc::vec::Vec;

use sce_forge_runtime::codec::SceCursor;
use wz_codecs::transport_close::TransportCloseView;
use wz_codecs::transport_init::TransportInitView;
use wz_codecs::transport_keep_alive::TransportKeepAliveView;
use wz_codecs::transport_oam::{TransportOamView, TransportOamViewVariant};
use wz_codecs::transport_open::TransportOpenView;
use wz_codecs::whatami::WhatAmI;
use wz_codecs::wire_const;

use crate::ext_chain::ChainHeaders;
use crate::handshake_encode::{encode_close, encode_init, encode_keep_alive, encode_open};
use crate::inbound::{parse_inbound, InboundFrame};
use crate::parse_error::InboundParseError;
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

/// Transport OAMs: id 42 with no body; id 2 with the z64 body 9 and the QoS
/// extension (a mandatory z64 of id 1, value 7) between the id and the body;
/// the two-byte id 129 with the ZBuf body `DE AD BE`.
const UPSTREAM_OAMS: [&[u8]; 3] = [
    &[0x00, 0x2A],
    &[0xA0, 0x02, 0x31, 0x07, 0x09],
    &[0x40, 0x81, 0x01, 0x03, 0xDE, 0xAD, 0xBE],
];

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
        tx_queue: crate::session_init_params::TxQueueConf::of_snapshot(
            &crate::policy::SessionPolicy::defaults(),
            &crate::limits::SessionLimits::BUILD,
        ),
        link_rx: crate::session_init_params::LinkRxConf::default(),
        cookie_signing_key: crate::signing_key::SigningKey::new(vec![0xAB; 32])
            .expect("32-byte test key"),
        policy: crate::policy::SessionPolicy::defaults(),
        limits: crate::limits::SessionLimits::BUILD,
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

/// The decoder here read the chain of a message of `mid` as the view did: every
/// entry's header where the decoder keeps the whole chain, and the admission
/// rule's verdict in every build, which on `session-slot` is all the decoder
/// keeps of an entry it does not read.
fn assert_chain_read_alike<C: ChainHeaders + ?Sized>(mid: u8, chain: &C, view_headers: &[u8]) {
    use crate::ext_admit::{judge_ext_chain, ExtCarrier};
    assert_eq!(
        judge_ext_chain(ExtCarrier::Transport(mid), chain.chain_headers()),
        judge_ext_chain(ExtCarrier::Transport(mid), view_headers.iter().copied()),
        "the two readers judge the chain alike"
    );
    #[cfg(not(feature = "session-slot"))]
    assert_eq!(chain.chain_headers().collect::<Vec<u8>>(), view_headers);
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
            assert_chain_read_alike(
                wire_const::T_MID_INIT,
                &extensions,
                &view_chain_headers!(view),
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
            assert_chain_read_alike(
                wire_const::T_MID_OPEN,
                &extensions,
                &view_chain_headers!(view),
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
            assert_chain_read_alike(
                wire_const::T_MID_CLOSE,
                &extensions,
                &view_chain_headers!(view),
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
            assert_chain_read_alike(
                wire_const::T_MID_KEEP_ALIVE,
                &extensions,
                &view_chain_headers!(view),
            );
        }
        Ok(_) => panic!("the decoder here read another message"),
        Err(refused) => panic!("the decoder here refused the frame: {refused:?}"),
    }
}

/// [`assert_init_read_alike`] for `transport_oam`: the id the decoder here
/// projects onto upstream's 16 bits, the encoding, the body by that encoding,
/// and the chain read between the id and the body.
fn assert_oam_read_alike(wire: &[u8]) {
    let view = read_whole!(TransportOamView::decode, wire);
    assert_eq!(view.encode_to_vec(), wire, "the view writes the frame back");
    let (view_value, view_body) = match &view.body {
        TransportOamViewVariant::CodecZenohExtUnit(_) => (0, Vec::new()),
        TransportOamViewVariant::CodecZenohExtZint(body) => (body.value, Vec::new()),
        TransportOamViewVariant::CodecZenohExtZbuf(body) => (0, body.value.into_inner().to_vec()),
        TransportOamViewVariant::Default { .. } => panic!("the reserved encoding is refused"),
    };
    match parse_inbound(wire) {
        Ok(InboundFrame::Oam {
            id,
            encoding,
            value,
            body,
            has_ext,
            extensions,
        }) => {
            assert_eq!(id, wire_const::oam_id_from_wire(view.id));
            assert_eq!(encoding, view.enc());
            assert_eq!((value, body), (view_value, view_body));
            assert_eq!(has_ext, view.extensions.is_some());
            assert_eq!(
                extensions.iter().map(|e| e.header).collect::<Vec<u8>>(),
                view_chain_headers!(view)
            );
        }
        Ok(_) => panic!("the decoder here read another message"),
        Err(refused) => panic!("the decoder here refused the frame: {refused:?}"),
    }
}

#[test]
fn every_upstream_oam_is_read_alike_here_and_by_the_document() {
    for wire in UPSTREAM_OAMS {
        assert_oam_read_alike(wire);
    }
}

/// The reserved body encoding reaches the document's default arm, which reads
/// no body, and is refused here as upstream refuses it
/// (`commons/zenoh-codec/src/transport/oam.rs` @ `_ => return Err(DidntRead),`).
#[test]
fn an_oam_of_the_reserved_encoding_is_refused_here_and_read_by_the_view() {
    let wire = [0x60, 0x01];
    let view = read_whole!(TransportOamView::decode, &wire);
    assert_eq!(view.enc(), 3);
    assert!(matches!(view.body, TransportOamViewVariant::Default { .. }));
    assert!(matches!(
        parse_inbound(&wire),
        Err(InboundParseError::ReservedEncoding)
    ));
}

/// An OAM cut inside its id, its chain or its body is refused by both readers.
#[test]
fn an_oam_cut_short_is_refused_by_both_readers() {
    for wire in UPSTREAM_OAMS {
        for cut in 1..wire.len() {
            let short = &wire[..cut];
            assert!(
                TransportOamView::decode(&mut SceCursor::new(short)).is_err(),
                "the view refuses {cut} of {} bytes",
                wire.len()
            );
            assert!(
                parse_inbound(short).is_err(),
                "the decoder here refuses {cut} of {} bytes",
                wire.len()
            );
        }
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

/// A terminated chain is read to its end by the decoder here and by the view,
/// whatever its length, as zenoh reads it
/// (`commons/zenoh-codec/src/transport/keepalive.rs` @
/// `extension::skip_all(reader, "Unknown KeepAlive ext")?;`, a loop with no
/// count in `commons/zenoh-codec/src/common/extension.rs` @ `while has_ext {`);
/// an unterminated one is refused by both.
#[test]
fn a_chain_of_any_length_is_read_here_as_the_view_reads_it() {
    // Entries of id 0xC, which no build reads, so a build that keeps only the
    // entries it reads holds none of them; `last` is the final entry's header.
    let keep_alive_with = |entries: usize, last: u8| {
        let mut wire = vec![wire_const::T_MID_KEEP_ALIVE | 0x80];
        wire.resize(entries, 0x8C);
        wire.push(last);
        wire
    };

    for entries in [1, 8, 9, 40] {
        let wire = keep_alive_with(entries, 0x0C);
        assert_keep_alive_read_alike(&wire);
        let view = read_whole!(TransportKeepAliveView::decode, &wire);
        assert_eq!(view_chain_headers!(view).len(), entries);
    }

    let unterminated = keep_alive_with(9, 0x8C);
    assert!(TransportKeepAliveView::decode(&mut SceCursor::new(&unterminated)).is_err());
    assert!(parse_inbound(&unterminated).is_err());
}

/// An entry the admission rule refuses is found wherever it lies in a chain,
/// however many entries no build reads come before it: a KeepAlive declares no
/// mandatory extension, so a mandatory entry ninth in its chain refuses it on
/// every build, the one that keeps only what it reads included.
#[test]
fn a_refused_entry_past_eight_others_is_judged() {
    use crate::ext_admit::ExtAdmission;
    // Eight entries of id 0xC, then the same id with the mandatory bit set.
    let mut wire = vec![wire_const::T_MID_KEEP_ALIVE | 0x80];
    wire.resize(9, 0x8C);
    wire.push(0x1C);
    assert_keep_alive_read_alike(&wire);
    let frame = parse_inbound(&wire).expect("the chain is read");
    assert_eq!(
        frame.ext_admission(),
        ExtAdmission::UnknownMandatory { eid: 0x1C }
    );

    // CONTROL: without the mandatory bit the same chain is admissible.
    *wire.last_mut().expect("a chain") = 0x0C;
    let frame = parse_inbound(&wire).expect("the chain is read");
    assert_eq!(frame.ext_admission(), ExtAdmission::Admissible);
}

/// A build that keeps one entry for each extension it reads refuses a chain
/// that repeats one past the entries it holds: the one refusal of a chain that
/// is not about its wire.
#[cfg(feature = "session-slot")]
#[test]
fn a_slot_build_refuses_a_chain_repeating_an_extension_it_reads() {
    let patch = crate::extpatch::encode_patch_ext_at(1).header & !0x80;
    let mut wire = vec![wire_const::T_MID_KEEP_ALIVE | 0x80];
    for _ in 0..crate::ext_chain::RECEIVED_EXT_KINDS {
        wire.extend_from_slice(&[patch | 0x80, 0x01]);
    }
    wire.extend_from_slice(&[patch, 0x01]);
    assert_eq!(
        parse_inbound(&wire).err(),
        Some(InboundParseError::ExtChainOverflow)
    );
}
