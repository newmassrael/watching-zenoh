// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Byte-parity gate for the P4 linkstate-peer topology codecs
//! (`linkstate` / `linkstate_list`, R311qm). Oracle wire vectors are
//! derived directly from the zenoh `Zenoh080Routing` codec
//! (`zenoh/src/net/codec/linkstate.rs:33-182`): an options flag byte,
//! then `psid` / `sn` VLE, the optional self-length-prefixed `zid`
//! (`commons/zenoh-codec/src/core/zenohid.rs:36` = VLE len + bytes), an
//! optional `whatami` u8, an optional `[Locator]` list (VLE count + each
//! locator per `core/locator.rs:57-65`), and a `links` list (VLE count +
//! count VLE u64). The H/WGT `link_weights` extension is the deferred
//! atom (b2) — these vectors all carry H=0, the default-config zenoh
//! wire (link weights are opt-in `TransportWeight` config).
//!
//! Each vector is decoded field-by-field and re-encoded; the round-trip
//! must reproduce the source bytes exactly, pinning the wire layout
//! against the zenoh reference.

#![cfg(feature = "codec-linkstate")]

use sce_forge_runtime::codec::SceCursor;
use wz_codecs::linkstate::Linkstate;
use wz_codecs::linkstate_list::LinkstateList;

/// Rich LinkState exercising P (zid) + W (whatami) + L (locators) +
/// the links list. H=0.
///
///   07                         options = PID|WAI|LOC (0x01|0x02|0x04)
///   2A                         psid = 42
///   07                         sn = 7
///   03 01 02 03                zid_len = 3, zid = [01 02 03]
///   02                         whatami = 2 (peer)
///   01                         num_locators = 1
///   12 "tcp/127.0.0.1:7447"    locator_len = 18 + 18 UTF-8 bytes
///   02 05 09                   links_len = 2, links = [5, 9]
const RICH: [u8; 31] = [
    0x07, 0x2A, 0x07, 0x03, 0x01, 0x02, 0x03, 0x02, 0x01, 0x12, 0x74, 0x63, 0x70, 0x2F, 0x31, 0x32,
    0x37, 0x2E, 0x30, 0x2E, 0x30, 0x2E, 0x31, 0x3A, 0x37, 0x34, 0x34, 0x37, 0x02, 0x05, 0x09,
];

/// Minimal LinkState: every option clear, empty links.
///
///   00          options = 0
///   01          psid = 1
///   00          sn = 0
///   00          links_len = 0
const MIN: [u8; 4] = [0x00, 0x01, 0x00, 0x00];

#[test]
fn rich_linkstate_round_trips_byte_exact() {
    let mut cursor = SceCursor::new(&RICH);
    let ls = Linkstate::decode(&mut cursor).expect("decode rich LinkState");

    assert_eq!(ls.options, 0x07, "options = P|W|L");
    assert_eq!(ls.psid, 42);
    assert_eq!(ls.sn, 7);
    assert_eq!(ls.zid_len, Some(3));
    assert_eq!(ls.zid, Some(&[0x01u8, 0x02, 0x03][..]));
    assert_eq!(ls.whatami, Some(2));
    assert_eq!(ls.num_locators, Some(1));
    let locs = ls.locators.as_ref().expect("L set => locators present");
    assert_eq!(locs.len(), 1);
    assert_eq!(locs[0].locator, "tcp/127.0.0.1:7447");
    assert_eq!(ls.links_len, 2);
    assert_eq!(ls.links.len(), 2);
    assert_eq!(ls.links[0].psid, 5);
    assert_eq!(ls.links[1].psid, 9);

    let wire = ls.encode_to_vec();
    assert_eq!(wire, RICH, "encode(decode(RICH)) must be byte-identical");
}

#[test]
fn minimal_linkstate_round_trips_byte_exact() {
    let mut cursor = SceCursor::new(&MIN);
    let ls = Linkstate::decode(&mut cursor).expect("decode minimal LinkState");

    assert_eq!(ls.options, 0x00);
    assert_eq!(ls.psid, 1);
    assert_eq!(ls.sn, 0);
    assert_eq!(ls.zid_len, None, "P clear => no zid length");
    assert_eq!(ls.zid, None);
    assert_eq!(ls.whatami, None, "W clear => no whatami");
    assert_eq!(ls.num_locators, None, "L clear => no locator count");
    assert!(ls.locators.is_none(), "L clear => no locators");
    assert_eq!(ls.links_len, 0);
    assert_eq!(ls.links.len(), 0);

    let wire = ls.encode_to_vec();
    assert_eq!(wire, MIN, "encode(decode(MIN)) must be byte-identical");
}

#[test]
fn linkstate_list_round_trips_byte_exact() {
    // num_link_states = 2, then [MIN, RICH] back to back.
    let mut list_wire: Vec<u8> = Vec::with_capacity(1 + MIN.len() + RICH.len());
    list_wire.push(0x02);
    list_wire.extend_from_slice(&MIN);
    list_wire.extend_from_slice(&RICH);

    let mut cursor = SceCursor::new(&list_wire);
    let lst = LinkstateList::decode(&mut cursor).expect("decode LinkStateList");

    assert_eq!(lst.num_link_states, 2);
    assert_eq!(lst.link_states.len(), 2);
    // entry 0 = minimal, entry 1 = rich
    assert_eq!(lst.link_states[0].psid, 1);
    assert_eq!(lst.link_states[0].links.len(), 0);
    assert_eq!(lst.link_states[1].psid, 42);
    assert_eq!(lst.link_states[1].links.len(), 2);
    assert_eq!(lst.link_states[1].links[1].psid, 9);

    let wire = lst.encode_to_vec();
    assert_eq!(
        wire, list_wire,
        "encode(decode(list)) must be byte-identical"
    );
}
