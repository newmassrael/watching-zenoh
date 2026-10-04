// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Which Put extension selects the sliced payload layout: the shared-memory
//! marker by its whole identity, and nothing that only shares its 4-bit id.
//!
//! A Put lays its payload out as a length and bytes, or, when its extension
//! chain carries the shared-memory marker, as a count of slices. Upstream
//! tells an extension apart by its header without the continuation flag
//! (`iext::eid`: id, mandatory bit, encoding), and the marker is the one value
//! `0x12`. The codec used to read the 4-bit id alone, so any id-2 extension
//! selected the sliced layout here and was an unknown extension there. These
//! tests feed the wire bytes that tell the two readings apart.
//!
//! Every Put below starts with header `0x81` (Put, extension chain follows),
//! then a chain, then a payload in whichever layout the chain selects. An
//! entry's header is `id | M(0x10) | enc<<5 | Z(0x80)`; the continuation flag
//! `Z` is set on every entry but the last, which is why the marker is `0x12`
//! at the end of a chain and `0x92` before another entry.

use sce_forge_runtime::codec::SceCursor;
use wz_codecs::msg_put::MsgPut;

/// A one-slice sliced payload: count 1, kind RAW, length 1, one byte.
const SLICED: [u8; 4] = [0x01, 0x00, 0x01, 0xAB];
/// A plain payload: length 1, one byte.
const PLAIN: [u8; 2] = [0x01, 0xAB];

/// Decodes `wire` and returns it with whether it read the sliced layout.
/// Refuses a decode that leaves bytes behind: a wrong layout choice shows
/// there too, since the two layouts are not the same length.
fn decode(wire: &[u8]) -> (MsgPut<'_>, bool) {
    let mut cursor = SceCursor::new(wire);
    let put = MsgPut::decode(&mut cursor).expect("the Put decodes");
    assert_eq!(cursor.remaining(), 0, "the Put consumed every byte");
    let sliced = put.slices.is_some();
    assert_eq!(
        sliced,
        put.slice_count.is_some(),
        "the sliced pair is present or absent together"
    );
    assert_eq!(
        !sliced,
        put.payload.is_some() && put.payload_len.is_some(),
        "exactly one layout's fields are present"
    );
    (put, sliced)
}

fn put(chain: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut wire = vec![0x81];
    wire.extend_from_slice(chain);
    wire.extend_from_slice(payload);
    wire
}

#[test]
fn the_marker_last_in_the_chain_selects_the_sliced_layout() {
    let wire = put(&[0x12], &SLICED);
    let (decoded, sliced) = decode(&wire);
    assert!(sliced, "0x12 is the marker");
    assert_eq!(decoded.slice_count, Some(1));
    assert_eq!(decoded.slices.as_ref().expect("slices")[0].bytes, [0xAB]);
}

#[test]
fn the_marker_before_another_entry_selects_the_sliced_layout() {
    // 0x92 is the marker with its continuation flag set; 0x05 is an unrelated
    // unit extension that ends the chain.
    let wire = put(&[0x92, 0x05], &SLICED);
    let (_, sliced) = decode(&wire);
    assert!(
        sliced,
        "the marker keeps its identity when it is not the last entry"
    );
}

#[test]
fn an_extension_of_the_markers_id_but_not_its_identity_leaves_the_plain_layout() {
    // Each of these has id 2 and is NOT the marker: the mandatory bit clear
    // (0x02), another encoding (0x22 and 0x42 are optional zint and zbuf, 0x32
    // is mandatory zint), and the same again before another entry (0x82).
    let cases: [(&str, &[u8]); 5] = [
        ("optional unit 0x02", &[0x02]),
        ("optional zint 0x22", &[0x22, 0x00]),
        ("mandatory zint 0x32", &[0x32, 0x00]),
        ("optional zbuf 0x42", &[0x42, 0x00]),
        ("optional unit before another entry 0x82", &[0x82, 0x05]),
    ];
    for (name, chain) in cases {
        let wire = put(chain, &PLAIN);
        let (decoded, sliced) = decode(&wire);
        assert!(
            !sliced,
            "{name}: shares only the 4-bit id, so it is not the marker"
        );
        assert_eq!(decoded.payload, Some(&[0xAB][..]), "{name}");
    }
}

#[test]
fn a_chain_without_the_marker_leaves_the_plain_layout() {
    let wire = put(&[0x05], &PLAIN);
    let (_, sliced) = decode(&wire);
    assert!(!sliced);
}

#[test]
fn both_layouts_re_encode_to_the_bytes_they_were_read_from() {
    // The encoder evaluates the same identity over the entries it was given, so
    // a Put read in either layout writes back byte for byte, and one that the
    // decoder read in the plain layout is not refused as a mismatch.
    for (chain, payload) in [
        (&[0x12][..], &SLICED[..]),
        (&[0x92, 0x05][..], &SLICED[..]),
        (&[0x02][..], &PLAIN[..]),
        (&[0x32, 0x00][..], &PLAIN[..]),
        (&[0x82, 0x05][..], &PLAIN[..]),
    ] {
        let wire = put(chain, payload);
        let (decoded, _) = decode(&wire);
        let again = decoded
            .encode_to_vec()
            .unwrap_or_else(|e| panic!("chain {chain:02x?} re-encodes: {e:?}"));
        assert_eq!(again, wire, "chain {chain:02x?} round-trips");
    }
}
