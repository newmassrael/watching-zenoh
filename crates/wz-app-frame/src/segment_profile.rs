// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A SEGMENT PROFILE: the description of the header an application puts in
//! front of each piece when it splits one message of its own over several
//! samples published on one key, and what a reader and a writer do with it per
//! sample.
//!
//! The profile itself (its data model, the description it is read from and
//! every refusal of that description) is read once, when a node is handed it,
//! and is `wz-app-schema`'s (`segment_profile`), built for size; it is
//! re-exported here at the paths it had. What runs per sample is this module's:
//! [`recognise`] reads a payload as a piece, [`crc_over`] takes the CRC of a
//! piece in the profile's cover order, and [`place`] says where a piece sits in
//! its whole.

use alloc::vec::Vec;

pub use wz_app_schema::segment_profile::*;

use crate::e2e_crc::Digest;

/// Read `payload` as a piece of `profile`, or `None` when it is not one.
///
/// What makes a payload a piece is the `equals` fields, and the CRC only when
/// there are none: a damaged piece of a known stream is a fact worth reporting,
/// so where marks exist the CRC is a verdict on the piece, not a condition.
pub fn recognise<'p>(profile: &SegmentProfile, payload: &'p [u8]) -> Option<Piece<'p>> {
    let header_bytes = profile.header_bytes();
    let header = payload.get(..header_bytes)?;
    let fields = profile.fields();
    let mut values = Vec::with_capacity(fields.len());
    for field in fields {
        let value = field.read(header);
        if field.equals.is_some_and(|wanted| wanted != value) {
            return None;
        }
        values.push(value);
    }
    let chunk = &payload[header_bytes..];
    let crc = profile.crc().map(|spec| CrcReading {
        stated: values[spec.field],
        computed: crc_over(profile, spec, header, chunk),
    });
    let fixed = fields.iter().any(|f| f.equals.is_some());
    if !fixed && !crc.is_some_and(|c| c.matches()) {
        return None;
    }
    Some(Piece { values, chunk, crc })
}

/// The CRC `spec` computes over `header` and `chunk`, fed in the order its
/// `cover` lists. The one place that order is applied: a reader checks a
/// piece with it and [`crate::segment_sender`] writes a piece's CRC with it.
pub fn crc_over(profile: &SegmentProfile, spec: &CrcSpec, header: &[u8], chunk: &[u8]) -> u64 {
    let fields = profile.fields();
    let mut digest = Digest::start(&spec.engine);
    for cover in &spec.cover {
        match cover {
            Cover::Field(i) => {
                let f = &fields[*i];
                digest.update(&header[f.offset..f.offset + f.bytes]);
            }
            Cover::Chunk => digest.update(chunk),
        }
    }
    digest.finish()
}

/// Where `piece` sits in its whole under `profile`: `(total, offset)`, or
/// why it cannot sit anywhere.
pub fn place(profile: &SegmentProfile, piece: &Piece<'_>) -> Result<(u64, u64), Misplaced> {
    let total = piece.values[profile.total()];
    let offset = piece.values[profile.offset()];
    if total == 0 {
        return Err(Misplaced::EmptyTotal);
    }
    if total > profile.total_max() {
        return Err(Misplaced::TotalPastMax);
    }
    if piece.chunk.is_empty() {
        return Err(Misplaced::EmptyChunk);
    }
    let end = offset.checked_add(piece.chunk.len() as u64);
    if end.is_none_or(|end| end > total) {
        return Err(Misplaced::PastTotal);
    }
    Ok((total, offset))
}

/// A SYNTHETIC segment profile and a builder of its pieces, for the capture
/// crate's tests and for the fixtures other crates' tests build captures from.
///
/// Deliberately unlike any deployed header: a big-endian mark, a little-endian
/// stream value, a one-byte transfer number, three-byte little-endian size and
/// offset, and a big-endian CRC-16 over everything but itself, chunk last.
///
/// Behind `fixtures` alone: no test of this crate builds a piece, and a
/// `cfg(test)` arm would not reach the crates whose tests do.
#[cfg(feature = "fixtures")]
pub mod synthetic {
    use alloc::vec::Vec;

    use crate::e2e_crc::{Crc, CrcParams, Digest};

    /// The profile's name.
    pub const NAME: &str = "demo-split";

    /// The profile description, on one line as a declaration needs it.
    pub const PROFILE: &str = concat!(
        r#"{"name":"demo-split","segments":{"fields":["#,
        r#"{"name":"mark","bytes":2,"equals":"0xA5C3"},"#,
        r#"{"name":"origin","bytes":2,"order":"little"},"#,
        r#"{"name":"number","bytes":1},"#,
        r#"{"name":"size","bytes":3,"order":"little"},"#,
        r#"{"name":"at","bytes":3,"order":"little"},"#,
        r#"{"name":"check","bytes":2}],"#,
        r#""crc":{"field":"check","width":16,"poly":"0x8005","init":"0x0000","#,
        r#""refin":true,"refout":true,"xorout":"0x0000","#,
        r#""cover":["mark","origin","number","size","at","@chunk"]},"#,
        r#""stream":["origin"],"transfer":"number","total":"size","offset":"at","#,
        r#""total_max":4096}}"#
    );

    /// How many bytes the header spans.
    pub const HEADER_BYTES: usize = 13;

    /// One piece: `chunk` at `at` of a whole of `size` bytes, transfer
    /// `number` of stream `origin`. Its CRC is computed from the model's
    /// parameters directly, not by the reader under test.
    pub fn piece(origin: u16, number: u8, size: u32, at: u32, chunk: &[u8]) -> Vec<u8> {
        let mut covered = Vec::new();
        covered.extend_from_slice(&0xA5C3u16.to_be_bytes());
        covered.extend_from_slice(&origin.to_le_bytes());
        covered.push(number);
        covered.extend_from_slice(&size.to_le_bytes()[..3]);
        covered.extend_from_slice(&at.to_le_bytes()[..3]);
        let crc = Crc::new(CrcParams {
            width: 16,
            poly: 0x8005,
            init: 0,
            refin: true,
            refout: true,
            xorout: 0,
        })
        .expect("a valid CRC model");
        let mut digest = Digest::start(&crc);
        digest.update(&covered);
        digest.update(chunk);
        let check = digest.finish() as u16;
        let mut out = covered;
        out.extend_from_slice(&check.to_be_bytes());
        out.extend_from_slice(chunk);
        out
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::String;

    use super::{Cover, Field, Order, SegmentProfile};
    use crate::e2e_profile::DocError;

    /// Every byte distinct and the top bit set, so a byte out of place or a
    /// sign carried down shows.
    const VALUE: u64 = 0x8877_6655_4433_2211;

    fn field(bytes: usize, order: Order) -> Field {
        Field {
            name: String::from("f"),
            bytes,
            offset: 1,
            order,
            equals: None,
        }
    }

    /// A segment profile whose CRC object is `crc`, every other part valid.
    fn with_crc(crc: &str) -> String {
        alloc::format!(
            concat!(
                r#"{{"name":"t","segments":{{"fields":["#,
                r#"{{"name":"mark","bytes":2,"equals":"0xA5C3"}},"#,
                r#"{{"name":"number","bytes":1}},"#,
                r#"{{"name":"size","bytes":2}},"#,
                r#"{{"name":"at","bytes":2}},"#,
                r#"{{"name":"check","bytes":2}}],"#,
                r#""crc":{},"transfer":"number","total":"size","offset":"at","#,
                r#""total_max":4096}}}}"#
            ),
            crc
        )
    }

    fn crc(field: &str, width: u8, cover: &str) -> String {
        alloc::format!(
            r#"{{"field":"{field}","width":{width},"poly":"0x8005","init":"0x0000","refin":true,"refout":true,"xorout":"0x0000","cover":{cover}}}"#
        )
    }

    fn refused(text: &str) -> (String, String) {
        match SegmentProfile::parse(text) {
            Err(DocError::Invalid { path, reason }) => (path, reason),
            other => panic!("expected a refusal with a place, got {other:?}"),
        }
    }

    #[test]
    fn the_crc_object_is_read_with_the_chunk_word_and_refused_at_its_place() {
        let profile =
            SegmentProfile::parse(&with_crc(&crc("check", 16, r#"["@chunk","mark","size"]"#)))
                .expect("a valid profile");
        let spec = profile.crc().expect("the profile has a CRC");
        assert_eq!(spec.field, 4);
        assert_eq!(spec.cover, [Cover::Chunk, Cover::Field(0), Cover::Field(2)]);

        let cases: [(String, &str, &str); 7] = [
            (
                crc("nope", 16, r#"["@chunk"]"#),
                "/segments/crc/field",
                "no field is called `nope`",
            ),
            (
                crc("mark", 16, r#"["@chunk"]"#),
                "/segments/crc/field",
                "the crc field `mark` holds a fixed value (`equals`): it holds the result",
            ),
            (
                crc("check", 32, r#"["@chunk"]"#),
                "/segments/crc/field",
                "the crc field `check` is 16 bits wide, narrower than the 32-bit CRC",
            ),
            (
                crc("check", 16, "[]"),
                "/segments/crc/cover",
                "the cover list is empty: the CRC would take no input",
            ),
            (
                crc("check", 16, r#"["mark","check"]"#),
                "/segments/crc/cover/1",
                "the crc field `check` is never covered: it holds the result",
            ),
            (
                crc("check", 16, r#"["@chunk","@chunk"]"#),
                "/segments/crc/cover/1",
                "`@chunk` is covered twice",
            ),
            (
                crc("check", 16, r#"["@payload"]"#),
                "/segments/crc/cover/0",
                "no field is called `@payload`",
            ),
        ];
        for (object, path, reason) in cases {
            assert_eq!(
                refused(&with_crc(&object)),
                (String::from(path), String::from(reason)),
                "{object}"
            );
        }
    }

    #[test]
    fn a_field_writes_its_bytes_in_its_order_and_reads_them_back() {
        for order in [Order::Big, Order::Little] {
            for width in 1..=8usize {
                let f = field(width, order);
                let mut header = [0xEEu8; 10];
                f.write(&mut header, VALUE);
                for (i, &byte) in header[1..1 + width].iter().enumerate() {
                    let shift = match order {
                        Order::Big => 8 * (width - 1 - i),
                        Order::Little => 8 * i,
                    };
                    assert_eq!(
                        byte,
                        (VALUE >> shift) as u8,
                        "{order:?} width {width} byte {i}"
                    );
                }
                assert_eq!(
                    header[0], 0xEE,
                    "{order:?} width {width} wrote before the field"
                );
                assert!(
                    header[1 + width..].iter().all(|&b| b == 0xEE),
                    "{order:?} width {width} wrote past the field"
                );
                assert_eq!(
                    f.read(&header),
                    VALUE & f.max_value(),
                    "{order:?} width {width}"
                );
            }
        }
    }
}
