// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The scouting messages as this crate writes and reads them
//! (`scout_responder::hello_datagram`, `scouting_message::parse_scouting`,
//! `scouting_host::decode_scouted_hello`), held to the documents that state each
//! whole message (`sources/codecs/scouting_{scout,hello}.scxml`).
//!
//! What a writer here writes, the document's view reads whole and writes back
//! byte for byte, and it reads the same header flags, body and chain the readers
//! here read out of the same bytes; a frame laid out as upstream lays it out
//! (`commons/zenoh-codec/src/scouting/scout.rs` @
//! `impl<W> WCodec<&Scout, &mut W> for Zenoh080`, and `hello.rs` beside it) is
//! read alike by both. The Scout a node sends is held to upstream's bytes by
//! `scout_emit_stages_framed_datagram` in `wz-runtime-tokio`.

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use sce_forge_runtime::codec::SceCursor;
use wz_codecs::scouting_hello::ScoutingHelloView;
use wz_codecs::scouting_scout::ScoutingScoutView;
use wz_codecs::whatami::WhatAmI;
use wz_codecs::wire_const;

use crate::scout_responder::{hello_datagram, ResponderIdentity};
use crate::scouting_message::{parse_scouting, ScoutingFrame};

/// Scouts as upstream lays them out: one looking for routers and peers with
/// the zid `AA BB`, and one looking for clients with no zid and a unit
/// extension of id 0xC in its chain.
const UPSTREAM_SCOUTS: [&[u8]; 2] = [&[0x01, 0x09, 0x1B, 0xAA, 0xBB], &[0x81, 0x09, 0x04, 0x0C]];

/// A Hello from a router with the one-byte zid `01` and no locator list.
const UPSTREAM_HELLO_BARE: [u8; 4] = [0x02, 0x09, 0x00, 0x01];

/// A Hello from a peer with the zid `AA BB`, the locator `tcp/1.2.3.4:7447`,
/// and an entry of id 0x9 in its chain.
fn upstream_hello_with_locator() -> Vec<u8> {
    let mut frame = vec![0xA2, 0x09, 0x11, 0xAA, 0xBB, 0x01, 0x10];
    frame.extend_from_slice(b"tcp/1.2.3.4:7447");
    frame.push(0x09);
    frame
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

/// The view of `wire` and [`parse_scouting`] read the same Scout out of it.
fn assert_scout_read_alike(wire: &[u8]) {
    let view = read_whole!(ScoutingScoutView::decode, wire);
    assert_eq!(view.encode_to_vec(), wire, "the view writes the frame back");
    match parse_scouting(wire) {
        Ok(ScoutingFrame::Scout {
            has_ext,
            body,
            extensions,
        }) => {
            assert_eq!(body.version, view.body.version);
            assert_eq!(body.cbyte, view.body.cbyte);
            match (body.zid.as_ref(), view.body.zid) {
                (None, None) => {}
                (Some(held), Some(read)) => assert_eq!(&held[..], read.into_inner()),
                _ => panic!("the two readers disagree about the zid"),
            }
            assert_eq!(has_ext, view.extensions.is_some());
            assert_eq!(
                extensions.iter().map(|e| e.header).collect::<Vec<u8>>(),
                view_chain_headers!(view)
            );
        }
        Ok(other) => panic!("the decoder here read {other:?}"),
        Err(refused) => panic!("the decoder here refused the frame: {refused:?}"),
    }
}

/// The locators the view of a Hello reads, in order.
fn view_locators(view: &ScoutingHelloView<'_>) -> Vec<String> {
    view.body
        .locators
        .as_ref()
        .map(|list| list.inner().iter())
        .into_iter()
        .flatten()
        .map(|locator| locator.locator.into_inner().to_string())
        .collect()
}

/// The view of `wire` and the readers here read the same Hello out of it.
fn assert_hello_read_alike(wire: &[u8]) {
    let view = read_whole!(ScoutingHelloView::decode, wire);
    assert_eq!(view.encode_to_vec(), wire, "the view writes the frame back");
    match parse_scouting(wire) {
        Ok(ScoutingFrame::Hello {
            has_ext,
            body,
            extensions,
        }) => {
            assert_eq!(body.version, view.body.version);
            assert_eq!(body.cbyte, view.body.cbyte);
            assert_eq!(&body.zid[..], view.body.zid.into_inner());
            assert_eq!(
                body.locators.as_ref().map(|list| list.len()),
                view.body.locators.as_ref().map(|list| list.inner().len())
            );
            assert_eq!(has_ext, view.extensions.is_some());
            assert_eq!(
                extensions.iter().map(|e| e.header).collect::<Vec<u8>>(),
                view_chain_headers!(view)
            );
        }
        Ok(other) => panic!("the decoder here read {other:?}"),
        Err(refused) => panic!("the decoder here refused the frame: {refused:?}"),
    }
    #[cfg(all(feature = "scouting-active", target_has_atomic = "ptr"))]
    {
        let scouted = crate::scouting_host::decode_scouted_hello(wire).expect("a Hello");
        assert_eq!(scouted.version, view.body.version);
        assert_eq!(scouted.zid, view.body.zid.into_inner());
        assert_eq!(scouted.locators, view_locators(&view));
    }
}

#[test]
fn every_upstream_scout_is_read_alike_here_and_by_the_document() {
    for wire in UPSTREAM_SCOUTS {
        assert_scout_read_alike(wire);
    }
}

#[test]
fn every_upstream_hello_is_read_alike_here_and_by_the_document() {
    assert_hello_read_alike(&UPSTREAM_HELLO_BARE);
    assert_hello_read_alike(&upstream_hello_with_locator());
}

/// Every Hello a responder here writes is the Hello its document reads, for
/// every role, the shortest, a middling and the longest zid, and no, one and
/// two locators: the role, the zid and the list are the identity's, and `L` is
/// set exactly when a list is written.
#[test]
fn every_hello_written_here_is_the_hello_the_document_reads() {
    let lists: [&[&str]; 3] = [
        &[],
        &["tcp/1.2.3.4:7447"],
        &["tcp/1.2.3.4:7447", "udp/[::1]:7447"],
    ];
    let mut compared = 0usize;
    for whatami in [WhatAmI::Router, WhatAmI::Peer, WhatAmI::Client] {
        for zid in [&[0x01][..], &[0xAA, 0xBB][..], &[0x5C; 16][..]] {
            for list in lists {
                let identity = ResponderIdentity::try_new(
                    whatami,
                    zid.to_vec(),
                    list.iter().map(|l| l.to_string()).collect(),
                )
                .expect("a well-formed identity");
                let wire = hello_datagram(&identity).expect("an identity spells a Hello");
                assert_hello_read_alike(&wire);
                let view = read_whole!(ScoutingHelloView::decode, &wire);
                assert_eq!(view.mid(), wire_const::S_MID_HELLO);
                assert_eq!(view.body.version, wire_const::PROTOCOL_VERSION);
                assert_eq!(view.body.whatami(), whatami.to_wire());
                assert_eq!(view.body.zid.into_inner(), zid);
                assert_eq!(view.l(), !list.is_empty());
                assert_eq!(view_locators(&view), list);
                assert!(view.extensions.is_none(), "a Hello here carries no chain");
                compared += 1;
            }
        }
    }
    assert_eq!(compared, 3 * 3 * 3);
}

/// A frame cut inside its body or its chain is refused by both readers.
#[test]
fn a_scouting_frame_cut_short_is_refused_by_both_readers() {
    let hello = upstream_hello_with_locator();
    for wire in [UPSTREAM_SCOUTS[0], UPSTREAM_SCOUTS[1], &hello[..]] {
        for cut in 1..wire.len() {
            let short = &wire[..cut];
            let view_refuses = if wire[0] & 0x1f == wire_const::S_MID_SCOUT {
                ScoutingScoutView::decode(&mut SceCursor::new(short)).is_err()
            } else {
                ScoutingHelloView::decode(&mut SceCursor::new(short)).is_err()
            };
            assert!(
                view_refuses,
                "the view refuses {cut} of {} bytes",
                wire.len()
            );
            assert!(
                parse_scouting(short).is_err(),
                "the decoder here refuses {cut} of {} bytes",
                wire.len()
            );
        }
    }
}

/// A terminated chain is read to its end by the readers here and by the view,
/// whatever its length, as upstream reads it
/// (`commons/zenoh-codec/src/scouting/scout.rs` @ `while has_extensions {`); a chain
/// whose last entry still announces a next is refused by both.
#[test]
fn a_scouting_chain_of_any_length_is_read_alike_and_an_unterminated_one_is_refused() {
    let scout_with = |entries: usize| {
        let mut wire = vec![wire_const::S_MID_SCOUT | 0x80, 0x09, 0x03];
        wire.resize(3 + entries - 1, 0x8C);
        wire.push(0x0C);
        wire
    };
    for entries in [1, 8, 9, 40] {
        let wire = scout_with(entries);
        assert_scout_read_alike(&wire);
        let view = read_whole!(ScoutingScoutView::decode, &wire);
        assert_eq!(view_chain_headers!(view).len(), entries);
    }
    let mut unterminated = scout_with(9);
    *unterminated.last_mut().expect("a chain") = 0x8C;
    assert!(ScoutingScoutView::decode(&mut SceCursor::new(&unterminated)).is_err());
    assert!(parse_scouting(&unterminated).is_err());
}
