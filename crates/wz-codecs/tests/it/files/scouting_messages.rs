// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The whole scouting Scout and Hello as their documents read and write them:
//! the header, the body, and the extension chain the header's Z flag
//! announces.
//!
//! Each frame is laid out as upstream's codec lays it out
//! (`commons/zenoh-codec/src/scouting/scout.rs` @
//! `impl<W> WCodec<&Scout, &mut W> for Zenoh080`, and `hello.rs` @
//! `impl<W> WCodec<&HelloProto, &mut W> for Zenoh080`): the header, the
//! version, the flags byte with the zid's length less one in its high nibble,
//! the zid, and for a Hello with L the locators, each a length and its text.

#![cfg(all(feature = "alloc", feature = "codec-scout", feature = "codec-hello"))]

use wz_codecs::node::Node;
use wz_codecs::scouting_hello::{ScoutingHelloOwned, ScoutingHelloView};
use wz_codecs::scouting_scout::{ScoutingScoutOwned, ScoutingScoutView};
use wz_codecs::{Heap, SceCursor};

/// A Scout looking for routers and peers (`what` 0b011), with I and the zid
/// `AA BB`.
const SCOUT_WITH_ZID: [u8; 5] = [0x01, 0x09, 0x1B, 0xAA, 0xBB];

/// A Scout looking for clients (`what` 0b100), with no zid and one unit
/// extension of id 0xC in its chain.
const SCOUT_WITH_EXT: [u8; 4] = [0x81, 0x09, 0x04, 0x0C];

/// A Hello from a router with the one-byte zid `01` and no locator list.
const HELLO_BARE: [u8; 4] = [0x02, 0x09, 0x00, 0x01];

/// A Hello from a peer with the zid `AA BB` and the one locator
/// `tcp/1.2.3.4:7447`: L set, a count of 1, then the locator's length and text.
fn hello_with_locator() -> Vec<u8> {
    let mut frame = vec![0x22, 0x09, 0x11, 0xAA, 0xBB, 0x01, 0x10];
    frame.extend_from_slice(b"tcp/1.2.3.4:7447");
    frame
}

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

/// The headers of the entries a view's chain yields.
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

#[test]
fn a_scout_reads_its_zid_and_no_chain() {
    let view = read_whole!(ScoutingScoutView::decode, &SCOUT_WITH_ZID);
    assert_eq!(view.mid(), 0x01);
    assert_eq!(view.body.what(), 0x03);
    assert_eq!(
        view.body.zid.map(|zid| zid.into_inner()),
        Some(&[0xAA, 0xBB][..])
    );
    assert!(view.extensions.is_none(), "Z is clear");
    assert_eq!(view.encode_to_vec(), SCOUT_WITH_ZID);
}

#[test]
fn a_scout_reads_no_zid_and_its_chain() {
    let view = read_whole!(ScoutingScoutView::decode, &SCOUT_WITH_EXT);
    assert_eq!(view.body.what(), 0x04);
    assert!(view.body.zid.is_none(), "I is clear");
    assert_eq!(chain_headers!(view), [0x0Cu8]);
    assert_eq!(view.encode_to_vec(), SCOUT_WITH_EXT);
}

#[test]
fn a_hello_reads_its_locators_under_l() {
    let frame = hello_with_locator();
    let view = read_whole!(ScoutingHelloView::decode, &frame);
    assert_eq!((view.mid(), view.l()), (0x02, true));
    assert_eq!(view.body.zid.into_inner(), &[0xAA, 0xBB][..]);
    let locators: Vec<&str> = view
        .body
        .locators
        .as_ref()
        .map(|list| list.inner().iter())
        .into_iter()
        .flatten()
        .map(|locator| locator.locator.into_inner())
        .collect();
    assert_eq!(locators, ["tcp/1.2.3.4:7447"]);
    assert_eq!(view.encode_to_vec(), frame);
}

#[test]
fn a_hello_without_l_reads_no_list() {
    let view = read_whole!(ScoutingHelloView::decode, &HELLO_BARE);
    assert!(!view.l(), "L is clear");
    assert!(view.body.locators.is_none());
    assert!(view.extensions.is_none());
    assert_eq!(view.encode_to_vec(), HELLO_BARE);
}

#[test]
fn every_form_writes_a_scouting_message_back_as_it_read_it() {
    for frame in [&SCOUT_WITH_ZID[..], &SCOUT_WITH_EXT[..]] {
        let node = read_whole!(ScoutingScoutOwned::<Node>::decode, frame);
        assert_eq!(node.encode_to_vec(), frame);
        let heap = read_whole!(ScoutingScoutOwned::<Heap>::decode, frame);
        assert_eq!(heap.encode_to_vec(), frame);
    }
    let with_locator = hello_with_locator();
    for frame in [&HELLO_BARE[..], &with_locator[..]] {
        let node = read_whole!(ScoutingHelloOwned::<Node>::decode, frame);
        assert_eq!(node.encode_to_vec(), frame);
        let heap = read_whole!(ScoutingHelloOwned::<Heap>::decode, frame);
        assert_eq!(heap.encode_to_vec(), frame);
    }
}
