// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The reader of a Response read where its frame lies: the record as the codec's view
//! (`wz_codecs::response::ResponseView`) and the verdict of the extension admission rule on its
//! chains, read in one pass. The key, the chains and the Put or the Del a Reply carries are read by
//! the readers a Push and a Request are read with (`super::body_read`), so the program holds one
//! reader of a Put body whichever record carries it; the envelope and the Reply's own header are
//! read here, and an Err by the codec's own reader.
//!
//! What it reads, and how it refuses what it does not, is the generated
//! `ResponseView::decode_into`'s, error for error, and its verdict is the one the rule gives the
//! view it reads: the Response's own chain, then a Reply's own before its body's, or an Err's. The
//! tests hold it to both over every shape a Response takes and over damaged and cut bytes.

use sce_forge_runtime::codec::{CodecError, SceCursor};
use wz_codecs::err::ErrView;
use wz_codecs::msg_del::MsgDelView;
use wz_codecs::msg_put::MsgPutView;
use wz_codecs::reply::{ReplyUnknownTag, ReplyView, ReplyViewVariant};
use wz_codecs::response::{ResponseUnknownTag, ResponseView, ResponseViewVariant};

use super::body_read::{self, InPlace, Judge, FLAG_Z, TAG_DEL, TAG_PUT};
use crate::ext_admit::{ExtAdmission, ExtCarrier, NetworkEnvelope, ZenohBody};

/// The body's tag of a Response, the low five bits of its header: a Reply.
const TAG_REPLY: u8 = 0x04;
/// The body's tag of a Response: an Err.
const TAG_ERR: u8 = 0x05;
/// The Reply's `C` flag: a consolidation mode follows its header.
const REPLY_FLAG_C: u8 = 0x20;

/// The Response at the cursor, read into `out`, and the verdict on its chains: its own, then its
/// body's. The cursor is past the record on success; on an error `out` is not to be read.
pub(super) fn read_response_view<'f>(
    cursor: &mut SceCursor<'f>,
    out: &mut ResponseView<'f>,
) -> Result<ExtAdmission, CodecError> {
    let header = body_read::byte(cursor)?;
    out.request_id = cursor.read_vle_u32()?;
    body_read::read_key(cursor, header, &mut out.keyexpr.body)?;
    let mut own = Judge::new(ExtCarrier::Network(NetworkEnvelope::Response));
    out.extensions = if header & FLAG_Z != 0 {
        Some(body_read::read_chain(cursor, &mut own, &mut InPlace, None)?)
    } else {
        None
    };
    out.header = header;
    let tag = cursor.peek_u8()? & 0x1f;
    // The Reply reader writes every field of a Reply, so a binding that holds a Reply's arm
    // already (a view's default does) is read into as it is.
    if !(tag == TAG_REPLY && matches!(out.body, ResponseViewVariant::CodecZenohReply(_))) {
        out.body = match tag {
            TAG_REPLY => ResponseViewVariant::CodecZenohReply(ReplyView::default()),
            TAG_ERR => ResponseViewVariant::CodecZenohErr(ErrView::default()),
            // A tag no arm names: the default arm, whose body is read as a Reply's. Five bits that
            // are not an arm's are always such a tag.
            other => ResponseViewVariant::Default {
                tag: ResponseUnknownTag::new(other).ok_or(CodecError::UndeclaredEnumValue)?,
                body: ReplyView::default(),
            },
        };
    }
    let body = match &mut out.body {
        ResponseViewVariant::CodecZenohReply(reply)
        | ResponseViewVariant::Default { body: reply, .. } => read_reply(cursor, reply)?,
        ResponseViewVariant::CodecZenohErr(err) => {
            ErrView::decode_into(cursor, err)?;
            crate::ext_admit::judge_entries(
                ExtCarrier::Zenoh(ZenohBody::Err),
                err.extensions
                    .as_ref()
                    .map(|chain| crate::ext_view::walked(Some(chain))),
            )
        }
    };
    Ok(crate::ext_admit::then_judge(own.verdict, || body))
}

/// The Reply at the cursor, read into `reply`, and the verdict on its chains: its own, then its
/// body's.
#[inline(always)]
fn read_reply<'f>(
    cursor: &mut SceCursor<'f>,
    reply: &mut ReplyView<'f>,
) -> Result<ExtAdmission, CodecError> {
    let header = body_read::byte(cursor)?;
    reply.consolidation = if header & REPLY_FLAG_C != 0 {
        Some(body_read::vle_u64(cursor)?)
    } else {
        None
    };
    let mut own = Judge::new(ExtCarrier::Zenoh(ZenohBody::Reply));
    reply.extensions = if header & FLAG_Z != 0 {
        Some(body_read::read_chain(cursor, &mut own, &mut InPlace, None)?)
    } else {
        None
    };
    reply.header = header;
    let tag = cursor.peek_u8()? & 0x1f;
    // The Put reader writes every field of a Put's body, as on a Push.
    if !(tag == TAG_PUT && matches!(reply.body, ReplyViewVariant::CodecZenohMsgPut(_))) {
        reply.body = match tag {
            TAG_PUT => ReplyViewVariant::CodecZenohMsgPut(MsgPutView::default()),
            TAG_DEL => ReplyViewVariant::CodecZenohMsgDel(MsgDelView::default()),
            // A tag no arm names: the default arm, whose body is read as a Put's.
            other => ReplyViewVariant::Default {
                tag: ReplyUnknownTag::new(other).ok_or(CodecError::UndeclaredEnumValue)?,
                body: MsgPutView::default(),
            },
        };
    }
    let body = match &mut reply.body {
        ReplyViewVariant::CodecZenohMsgPut(put) | ReplyViewVariant::Default { body: put, .. } => {
            body_read::read_put(cursor, put, &mut InPlace)?
        }
        ReplyViewVariant::CodecZenohMsgDel(del) => body_read::read_del(cursor, del, &mut InPlace)?,
    };
    Ok(crate::ext_admit::then_judge(own.verdict, || body))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the reader reads from `bytes`: the view, how far it read and the verdict.
    fn reading(bytes: &[u8]) -> Result<(ResponseView<'_>, usize, ExtAdmission), CodecError> {
        let mut cursor = SceCursor::new(bytes);
        let mut view = ResponseView::default();
        let admission = read_response_view(&mut cursor, &mut view)?;
        Ok((view, bytes.len() - cursor.remaining(), admission))
    }

    /// What the generated codec reads from `bytes` and the verdict the rule gives the view it
    /// reads, walking each chain where it lies: the reading the reader is held to.
    fn through_the_codec(
        bytes: &[u8],
    ) -> Result<(ResponseView<'_>, usize, ExtAdmission), CodecError> {
        let mut cursor = SceCursor::new(bytes);
        let mut view = ResponseView::default();
        ResponseView::decode_into(&mut cursor, &mut view)?;
        let admission = super::super::response_view_admission(&view);
        Ok((view, bytes.len() - cursor.remaining(), admission))
    }

    /// The reader against the codec over `bytes`: the same view, the same end, the same verdict,
    /// or the same error.
    fn agree(bytes: &[u8], case: &dyn core::fmt::Debug) {
        assert_eq!(reading(bytes), through_the_codec(bytes), "{case:?}");
    }

    /// A Response: the envelope `envelope` (its header, request id, key and chain), then `body`.
    fn response(envelope: &[u8], body: &[u8]) -> alloc::vec::Vec<u8> {
        [envelope, body].concat()
    }

    /// The envelopes a Response takes, written byte by byte: no flag; `M` and `N` with a request
    /// id of two bytes and a suffix; `Z` with the QoS; the QoS twice; a mandatory entry no
    /// Response declares.
    fn envelopes() -> [alloc::vec::Vec<u8>; 5] {
        [
            alloc::vec![0x1bu8, 1, 3],
            alloc::vec![0x7bu8, 0x81, 0x01, 5, 2, b'a', b'b'],
            alloc::vec![0x9bu8, 7, 0, 0x21, 0x1a],
            alloc::vec![0x9bu8, 2, 1, 0xa1, 0x05, 0x21, 0x1a],
            alloc::vec![0x9bu8, 1, 1, 0x1e],
        ]
    }

    /// The headers a Reply takes: bare; with a consolidation mode; with a chain of a unit entry no
    /// Reply declares and no participant refuses; with both, the chain a mandatory entry no Reply
    /// declares.
    fn replies() -> [alloc::vec::Vec<u8>; 4] {
        [
            alloc::vec![0x04u8],
            alloc::vec![0x24u8, 2],
            alloc::vec![0x84u8, 0x05],
            alloc::vec![0xa4u8, 1, 0x1f],
        ]
    }

    /// The bodies a Reply carries, the ones a Push carries: a Put of three bytes, of 129, with a
    /// timestamp and an encoding with a schema, with a chain of its own, a shared-memory Put (the
    /// marker alone, and after another entry), a Del (bare, with a timestamp, with a chain), a body
    /// tag no arm names, a Put's chain that repeats its extensions, and a Put's and a Del's chain
    /// with a mandatory entry neither declares.
    fn bodies() -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
        alloc::vec![
            alloc::vec![0x01u8, 3, b'a', b'b', b'c'],
            [&[0x01u8, 0x81, 0x01][..], &[7u8; 129][..]].concat(),
            alloc::vec![0x61u8, 0x85, 0x01, 2, 0xaa, 0xbb, 0x03, 3, b'a', b'b', b'c', 1, b'p'],
            alloc::vec![0x81u8, 0x85, 0x44, 2, 9, 9, 3, b'a', b'b', b'c'],
            alloc::vec![0x81u8, 0x12, 1, 0, 2, 1, 2],
            alloc::vec![0x81u8, 0x85, 0x12, 2, 0, 1, 7, 3, 0],
            alloc::vec![0x02u8],
            alloc::vec![0x22u8, 5, 1, 0xee],
            alloc::vec![0x82u8, 0x05],
            alloc::vec![0x05u8, 1, b'z'],
            alloc::vec![
                0x81u8, 0xc1, 5, 0x10, 0xa0, 1, 1, 1, 0xc3, 1, b'f', 0xc1, 5, 0x10, 0xa0, 2, 2, 2,
                0x43, 1, b'l', 2, b'x', b'y'
            ],
            alloc::vec![0x81u8, 0x1e, 0],
            alloc::vec![0x82u8, 0x1e],
        ]
    }

    /// The Err bodies a Response carries: a payload alone; an encoding and an empty payload; a
    /// chain of a source info; a chain of a mandatory entry no Err declares.
    fn errs() -> [alloc::vec::Vec<u8>; 4] {
        [
            alloc::vec![0x05u8, 2, b'e', b'r'],
            alloc::vec![0x45u8, 0x02, 0],
            alloc::vec![0x85u8, 0x41, 5, 0x10, 0xa0, 1, 1, 1, 1, b'e'],
            alloc::vec![0x85u8, 0x1f, 0],
        ]
    }

    /// Every shape a Response takes: each envelope with a bare Reply of a Put, the first envelope
    /// with each Reply header and with a bare Reply of each body, each Err, and a body tag no arm
    /// of a Response names, whose header is read as a Reply's (bare with a Put, and with a
    /// consolidation mode and a Del).
    fn shapes() -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
        let envelopes = envelopes();
        let replies = replies();
        let bodies = bodies();
        let plain = &bodies[0];
        let mut out = alloc::vec::Vec::new();
        for envelope in &envelopes {
            out.push(response(envelope, &[&replies[0][..], &plain[..]].concat()));
        }
        for reply in &replies[1..] {
            out.push(response(&envelopes[0], &[&reply[..], &plain[..]].concat()));
        }
        for body in &bodies[1..] {
            out.push(response(
                &envelopes[0],
                &[&replies[0][..], &body[..]].concat(),
            ));
        }
        for err in &errs() {
            out.push(response(&envelopes[0], err));
            out.push(response(&envelopes[2], err));
        }
        out.push(response(&envelopes[0], &[0x06u8, 0x01, 1, b'd']));
        out.push(response(&envelopes[1], &[0x26u8, 2, 0x02]));
        out
    }

    /// Over every shape, the reader reads what the codec reads and judges it as the rule judges the
    /// codec's view: the same view, the same end, the same verdict; and with another record behind
    /// it, as a frame holds them, the same. Turned red by a reader that reads a field the codec
    /// does not, or judges a chain by another carrier's rule (the Reply's `Judge::new` in
    /// `read_reply`).
    #[test]
    fn every_shape_reads_as_the_codec_reads_it() {
        let behind = [0x1bu8, 3, 1, 0x04, 0x01, 1, b'n'];
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
            refused >= 4,
            "the corpus holds chains the rule refuses: {refused}"
        );
    }

    /// A binding that held a Response read before is read into as it is, and reads each Response as
    /// a fresh binding does. Turned red by a reader that leaves a field of the envelope, the Reply
    /// or its body as the record read before left it.
    #[test]
    fn a_response_read_into_a_binding_that_held_one_reads_as_into_a_fresh_one() {
        let all = shapes();
        for first in &all {
            for second in &all {
                let mut view = ResponseView::default();
                let read = read_response_view(&mut SceCursor::new(first), &mut view);
                assert!(read.is_ok(), "{first:02x?}: {read:?}");
                let again = read_response_view(&mut SceCursor::new(second), &mut view)
                    .map(|verdict| (view.clone(), verdict));
                let fresh = reading(second).map(|(view, _, verdict)| (view, verdict));
                assert_eq!(again, fresh, "{first:02x?} then {second:02x?}");
            }
        }
    }

    /// Cut anywhere, a Response is refused with the codec's error, and with any one byte changed to
    /// any value, the reader answers what the codec and the rule answer: the same reading, or the
    /// same error.
    #[test]
    fn a_cut_or_damaged_response_reads_as_the_codec_reads_it() {
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

    /// A Reply's Put is read by the reader of a Push's body: the Put a Reply carries and the Put a
    /// Push carries, of the same bytes, read to the same view, the body tag no arm names included.
    /// Turned red by a Reply whose body is read by a reader of its own that reads the Put apart.
    #[cfg(all(feature = "codec-push", any(feature = "alloc", feature = "rx-push")))]
    #[test]
    fn a_reply_s_put_reads_as_a_push_s_put_of_the_same_bytes() {
        for body in bodies() {
            if body[0] & 0x1f == TAG_DEL {
                continue;
            }
            let reply = response(&envelopes()[0], &[&[0x04u8][..], &body[..]].concat());
            let push = [&[0x1du8, 3][..], &body[..]].concat();
            let (read, _, _) = reading(&reply).expect("the Reply reads");
            let ResponseViewVariant::CodecZenohReply(ReplyView { body: replied, .. }) = &read.body
            else {
                panic!("a Reply: {reply:02x?}");
            };
            let mut view = wz_codecs::push::PushView::default();
            super::super::push_read::read_push_view(
                &mut SceCursor::new(&push),
                &mut view,
                &mut super::super::push_read::Lending,
            )
            .expect("the Push reads");
            let (pushed, replied) = match (&view.body, replied) {
                (
                    wz_codecs::push::PushViewVariant::CodecZenohMsgPut(pushed),
                    ReplyViewVariant::CodecZenohMsgPut(replied),
                )
                | (
                    wz_codecs::push::PushViewVariant::Default { body: pushed, .. },
                    ReplyViewVariant::Default { body: replied, .. },
                ) => (pushed, replied),
                other => panic!("the same arm: {other:?}"),
            };
            assert_eq!(pushed, replied, "{body:02x?}");
        }
    }
}
