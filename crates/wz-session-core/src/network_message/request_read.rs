// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The reader of a Request read where its frame lies, in a build that reads the Put and the Del a
//! Request carries (`request-put-del`): the record as the codec's view
//! (`wz_codecs::request::RequestView`) and the verdict of the extension admission rule on its
//! chains, read in one pass. The key, the chains and the Put or the Del are read by the readers a
//! Push and a Reply are read with (`super::body_read`), so the program holds one reader of a Put
//! body whichever record carries it; the envelope is read here, and a Query by the codec's own
//! reader. A build without `request-put-del` reads a Request by the codec's reader, which holds no
//! Put body reader there.
//!
//! What it reads, and how it refuses what it does not, is the generated
//! `RequestView::decode_into`'s, error for error, and its verdict is the one the rule gives the
//! view it reads: the Request's own chain, then its body's. The tests hold it to both over every
//! shape a Request takes and over damaged and cut bytes.

use sce_forge_runtime::codec::{CodecError, SceCursor};
use wz_codecs::msg_del::MsgDelView;
use wz_codecs::msg_put::MsgPutView;
use wz_codecs::query::QueryView;
use wz_codecs::request::{RequestUnknownTag, RequestView, RequestViewVariant};

use super::body_read::{self, InPlace, Judge, FLAG_Z, TAG_DEL, TAG_PUT};
use crate::ext_admit::{ExtAdmission, ExtCarrier, NetworkEnvelope, ZenohBody};

/// The body's tag of a Request, the low five bits of its header: a Query.
const TAG_QUERY: u8 = 0x03;

/// The Request at the cursor, read into `out`, and the verdict on its chains: its own, then its
/// body's. The cursor is past the record on success; on an error `out` is not to be read.
pub(super) fn read_request_view<'f>(
    cursor: &mut SceCursor<'f>,
    out: &mut RequestView<'f>,
) -> Result<ExtAdmission, CodecError> {
    let header = body_read::byte(cursor)?;
    out.rid = cursor.read_vle_u32()?;
    body_read::read_key(cursor, header, &mut out.keyexpr.body)?;
    let mut own = Judge::new(ExtCarrier::Network(NetworkEnvelope::Request));
    out.extensions = if header & FLAG_Z != 0 {
        Some(body_read::read_chain(cursor, &mut own, &mut InPlace, None)?)
    } else {
        None
    };
    out.header = header;
    let tag = cursor.peek_u8()? & 0x1f;
    // The Query reader writes the whole of a Query, so a binding that holds a Query's arm already
    // (a view's default does) is read into as it is.
    if !(tag == TAG_QUERY && matches!(out.body, RequestViewVariant::CodecZenohQuery(_))) {
        out.body = match tag {
            TAG_QUERY => RequestViewVariant::CodecZenohQuery(QueryView::default()),
            TAG_PUT => RequestViewVariant::CodecZenohMsgPut(MsgPutView::default()),
            TAG_DEL => RequestViewVariant::CodecZenohMsgDel(MsgDelView::default()),
            // A tag no arm names: the default arm, whose body is read as a Query's. Five bits that
            // are not an arm's are always such a tag.
            other => RequestViewVariant::Default {
                tag: RequestUnknownTag::new(other).ok_or(CodecError::UndeclaredEnumValue)?,
                body: QueryView::default(),
            },
        };
    }
    let body = match &mut out.body {
        RequestViewVariant::CodecZenohMsgPut(put) => {
            body_read::read_put(cursor, put, &mut InPlace)?
        }
        RequestViewVariant::CodecZenohMsgDel(del) => {
            body_read::read_del(cursor, del, &mut InPlace)?
        }
        RequestViewVariant::CodecZenohQuery(query)
        | RequestViewVariant::Default { body: query, .. } => {
            QueryView::decode_into(cursor, query)?;
            super::judge_entries(
                ExtCarrier::Zenoh(ZenohBody::Query),
                query
                    .extensions
                    .as_ref()
                    .map(|chain| crate::ext_view::walked(Some(chain))),
            )
        }
    };
    Ok(super::then_judge(own.verdict, || body))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the reader reads from `bytes`: the view, how far it read and the verdict.
    fn reading(bytes: &[u8]) -> Result<(RequestView<'_>, usize, ExtAdmission), CodecError> {
        let mut cursor = SceCursor::new(bytes);
        let mut view = RequestView::default();
        let admission = read_request_view(&mut cursor, &mut view)?;
        Ok((view, bytes.len() - cursor.remaining(), admission))
    }

    /// What the generated codec reads from `bytes` and the verdict the rule gives the view it
    /// reads, walking each chain where it lies: the reading the reader is held to.
    fn through_the_codec(
        bytes: &[u8],
    ) -> Result<(RequestView<'_>, usize, ExtAdmission), CodecError> {
        let mut cursor = SceCursor::new(bytes);
        let mut view = RequestView::default();
        RequestView::decode_into(&mut cursor, &mut view)?;
        let admission = super::super::request_view_admission(&view);
        Ok((view, bytes.len() - cursor.remaining(), admission))
    }

    /// The reader against the codec over `bytes`: the same view, the same end, the same verdict,
    /// or the same error.
    fn agree(bytes: &[u8], case: &dyn core::fmt::Debug) {
        assert_eq!(reading(bytes), through_the_codec(bytes), "{case:?}");
    }

    /// The envelopes a Request takes, written byte by byte: no flag; `M` and `N` with a request
    /// id of two bytes and a suffix; `Z` with the QoS; a mandatory entry no Request declares.
    fn envelopes() -> [alloc::vec::Vec<u8>; 4] {
        [
            alloc::vec![0x1cu8, 1, 3],
            alloc::vec![0x7cu8, 0x81, 0x01, 5, 2, b'a', b'b'],
            alloc::vec![0x9cu8, 7, 0, 0x21, 0x1a],
            alloc::vec![0x9cu8, 1, 1, 0x1e],
        ]
    }

    /// The bodies a Request carries: a Query bare, with a consolidation mode, with parameters, with
    /// both; a body tag no arm names, read as a Query, bare and with a consolidation mode; and the
    /// Put and Del bodies a Push carries: a Put of three bytes, of 129, with a timestamp and an
    /// encoding with a schema, with a chain of its own, a shared-memory Put, a Del (bare, with a
    /// timestamp, with a chain), and a Put's and a Del's chain with a mandatory entry neither
    /// declares.
    fn bodies() -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
        alloc::vec![
            alloc::vec![0x03u8],
            alloc::vec![0x23u8, 1],
            alloc::vec![0x43u8, 3, b'a', b'=', b'1'],
            alloc::vec![0x63u8, 2, 0],
            alloc::vec![0x04u8],
            alloc::vec![0x24u8, 1],
            alloc::vec![0x01u8, 3, b'a', b'b', b'c'],
            [&[0x01u8, 0x81, 0x01][..], &[7u8; 129][..]].concat(),
            alloc::vec![0x61u8, 0x85, 0x01, 2, 0xaa, 0xbb, 0x03, 3, b'a', b'b', b'c', 1, b'p'],
            alloc::vec![0x81u8, 0x85, 0x44, 2, 9, 9, 3, b'a', b'b', b'c'],
            alloc::vec![0x81u8, 0x12, 1, 0, 2, 1, 2],
            alloc::vec![0x02u8],
            alloc::vec![0x22u8, 5, 1, 0xee],
            alloc::vec![0x82u8, 0x05],
            alloc::vec![0x81u8, 0x1e, 0],
            alloc::vec![0x82u8, 0x1e],
        ]
    }

    /// Every shape a Request takes: each envelope with a bare Query, and the first envelope with
    /// each body.
    fn shapes() -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
        let envelopes = envelopes();
        let bodies = bodies();
        let mut out = alloc::vec::Vec::new();
        for envelope in &envelopes {
            out.push([&envelope[..], &bodies[0][..]].concat());
        }
        for body in &bodies[1..] {
            out.push([&envelopes[0][..], &body[..]].concat());
        }
        out
    }

    /// Over every shape, the reader reads what the codec reads and judges it as the rule judges the
    /// codec's view: the same view, the same end, the same verdict; and with another record behind
    /// it, as a frame holds them, the same. Turned red by a reader that reads a field the codec
    /// does not, or judges a chain by another carrier's rule (the Request's `Judge::new` in
    /// `read_request_view`).
    #[test]
    fn every_shape_reads_as_the_codec_reads_it() {
        let behind = [0x1cu8, 3, 1, 0x01, 1, b'n'];
        let mut refused = 0usize;
        for shape in shapes() {
            let read = reading(&shape);
            assert!(read.is_ok(), "{shape:02x?}: {read:?}");
            agree(&shape, &shape);
            assert_eq!(read.as_ref().map(|r| r.1), Ok(shape.len()), "{shape:02x?}");
            if read.is_ok_and(|r| r.2.refusal().is_some()) {
                refused += 1;
            }
            let frame = [&shape[..], &behind[..]].concat();
            agree(&frame, &frame);
        }
        assert!(
            refused >= 3,
            "the corpus holds chains the rule refuses: {refused}"
        );
    }

    /// A binding that held a Request read before is read into as it is, and reads each Request as
    /// a fresh binding does. Turned red by a reader that leaves a field of the envelope or of its
    /// body as the record read before left it.
    #[test]
    fn a_request_read_into_a_binding_that_held_one_reads_as_into_a_fresh_one() {
        let all = shapes();
        for first in &all {
            for second in &all {
                let mut view = RequestView::default();
                let read = read_request_view(&mut SceCursor::new(first), &mut view);
                assert!(read.is_ok(), "{first:02x?}: {read:?}");
                let again = read_request_view(&mut SceCursor::new(second), &mut view)
                    .map(|verdict| (view.clone(), verdict));
                let fresh = reading(second).map(|(view, _, verdict)| (view, verdict));
                assert_eq!(again, fresh, "{first:02x?} then {second:02x?}");
            }
        }
    }

    /// Cut anywhere, a Request is refused with the codec's error, and with any one byte changed to
    /// any value, the reader answers what the codec and the rule answer: the same reading, or the
    /// same error.
    #[test]
    fn a_cut_or_damaged_request_reads_as_the_codec_reads_it() {
        let mut compared = 0usize;
        for shape in shapes() {
            for length in 0..shape.len() {
                agree(&shape[..length], &(&shape, "cut at", length));
            }
            for position in 0..shape.len() {
                for value in 0..=255u8 {
                    let mut bytes = shape.clone();
                    bytes[position] = value;
                    agree(&bytes, &(&shape, "byte", position, value));
                    compared += 1;
                }
            }
        }
        assert!(compared > 10_000, "{compared}");
    }
}
