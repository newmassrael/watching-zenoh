// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Which Query extension is the shared-memory marker: the one header byte
//! upstream reads it by, and nothing that only shares its 4-bit id.
//!
//! A Query lays its value extension out as a length and bytes, or, when the
//! extension just before it is the shared-memory marker, as a length, an
//! encoding and a count of slices. Upstream tells the marker by the header
//! without its continuation flag (`iext::eid`: id, mandatory bit, encoding), and
//! the marker is the one value `0x04`: a UNIT extension, id 4, not mandatory
//! (`commons/zenoh-protocol/src/zenoh/query.rs` @
//! `pub type QueryBodyType = crate::zenoh::ext::ValueType<{ ZExtZBuf::<0x03>::id(false) }, 0x04>;`
//! and `commons/zenoh-codec/src/zenoh/mod.rs` @
//! `let ext_shm = if iext::eid(self.header) == SID {`). The codec used to read
//! the 4-bit id alone, so the entry after ANY id-4 extension (a mandatory unit,
//! a zint, a zbuf) was read in the sliced layout here and was a plain value
//! there: the id-4 extension is an unknown extension to upstream, which skips it
//! (`commons/zenoh-codec/src/zenoh/query.rs` @ `let (u, ext) = extension::read(reader, "Query", ext)?;`).
//! The dissector walks the same chain by the same rule and is held to it in
//! `wz-session-core`'s `dissect` tests.
//!
//! Every Query below starts with header `0x83` (Query, extension chain
//! follows), then a chain, with the value extension `0x43` (ZBuf, id 3, not
//! mandatory) last. An entry's header is `id | M(0x10) | enc<<5 | Z(0x80)`; the
//! continuation flag is set on every entry but the last, which is why the marker
//! is the byte `0x84` in front of the value.
//!
//! One more difference is NOT about layout and is not decided here: with the
//! mandatory bit set (`0x14`, `0x34`, `0x54`) upstream refuses the whole Query
//! as carrying an unknown mandatory extension, where this codec reads the entry
//! and the value.

use sce_forge_runtime::codec::SceCursor;
use wz_codecs::query::Query;
use wz_codecs::query_ext_entry::QueryExtEntryVariant;

/// The value extension of a plain value: header `0x43`, declared length 2, then
/// the encoding byte and one payload byte.
const PLAIN_VALUE: [u8; 4] = [0x43, 0x02, 0x00, 0xAB];
/// The value extension of a sliced value: header `0x43`, declared length 5, an
/// encoding byte, then one slice (count 1, kind RAW, length 1, one byte).
const SLICED_VALUE: [u8; 7] = [0x43, 0x05, 0x00, 0x01, 0x00, 0x01, 0xAB];

fn query(chain: &[u8], value: &[u8]) -> Vec<u8> {
    let mut wire = vec![0x83];
    wire.extend_from_slice(chain);
    wire.extend_from_slice(value);
    wire
}

/// Decodes `wire` and returns whether its LAST entry (the value extension) was
/// read in the sliced layout. Refuses a decode that leaves bytes behind: a wrong
/// layout choice shows there too, since the layouts are not the same length.
fn value_is_sliced(wire: &[u8]) -> bool {
    let mut cursor = SceCursor::new(wire);
    let decoded = Query::decode(&mut cursor).expect("the Query decodes");
    assert_eq!(cursor.remaining(), 0, "the Query consumed every byte");
    let entries = decoded.extensions.as_ref().expect("the chain is present");
    let last = entries.last().expect("the chain has an entry");
    assert_eq!(last.header, 0x43, "the last entry is the value extension");
    let QueryExtEntryVariant::CodecZenohQueryValueZbuf(value) = &last.body else {
        panic!("the value extension is a ZBuf entry");
    };
    let sliced = value.slices.is_some();
    assert_eq!(
        sliced,
        value.encoding.is_some() && value.slice_count.is_some(),
        "the sliced fields are present or absent together"
    );
    assert_eq!(
        !sliced,
        value.value.is_some(),
        "exactly one layout's fields are present"
    );
    sliced
}

#[test]
fn the_marker_before_the_value_selects_the_sliced_layout() {
    // 0x84 is the marker with its continuation flag set.
    let wire = query(&[0x84], &SLICED_VALUE);
    assert!(value_is_sliced(&wire), "0x84 is the marker");
}

#[test]
fn an_extension_of_the_markers_id_but_not_its_identity_leaves_the_plain_layout() {
    // Each of these has id 4 and is NOT the marker: the mandatory bit set
    // (0x94 unit, 0xB4 zint, 0xD4 zbuf), another encoding with the mandatory
    // bit clear (0xA4 zint, 0xC4 zbuf). Each carries the body its encoding
    // needs, a zint 0 or a zbuf of length 0.
    let cases: [(&str, &[u8]); 5] = [
        ("mandatory unit 0x94", &[0x94]),
        ("optional zint 0xA4", &[0xA4, 0x00]),
        ("mandatory zint 0xB4", &[0xB4, 0x00]),
        ("optional zbuf 0xC4", &[0xC4, 0x00]),
        ("mandatory zbuf 0xD4", &[0xD4, 0x00]),
    ];
    for (name, chain) in cases {
        let wire = query(chain, &PLAIN_VALUE);
        assert!(
            !value_is_sliced(&wire),
            "{name}: shares only the 4-bit id, so it is not the marker"
        );
    }
}

#[test]
fn a_value_with_nothing_before_it_leaves_the_plain_layout() {
    assert!(!value_is_sliced(&query(&[], &PLAIN_VALUE)));
    // An unrelated unit extension (id 5) before it is not the marker either.
    assert!(!value_is_sliced(&query(&[0x85], &PLAIN_VALUE)));
}

#[test]
fn both_layouts_re_encode_to_the_bytes_they_were_read_from() {
    // The encoder walks the same identity over the entries it was given, so a
    // Query read in either layout writes back byte for byte.
    for (chain, value) in [
        (&[0x84][..], &SLICED_VALUE[..]),
        (&[0x94][..], &PLAIN_VALUE[..]),
        (&[0xA4, 0x00][..], &PLAIN_VALUE[..]),
        (&[0xC4, 0x00][..], &PLAIN_VALUE[..]),
        (&[][..], &PLAIN_VALUE[..]),
    ] {
        let wire = query(chain, value);
        let mut cursor = SceCursor::new(&wire);
        let decoded = Query::decode(&mut cursor).expect("the Query decodes");
        let again = decoded.encode_to_vec();
        assert_eq!(again, wire, "chain {chain:02x?} round-trips");
    }
}
