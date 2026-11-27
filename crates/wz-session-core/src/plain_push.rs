// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The lane of a data stream: a frame every record of which is a plain `Put`, kept as the places
//! of each record's parts in the frame rather than as an owned message per record.
//!
//! A plain Put is a `Push` whose own chain is the QoS extension alone, or none, and whose body is
//! a `Put` with no timestamp, no encoding and no chain of its own: the record a publisher that
//! sends the same small message many times sends. Each record is read by the one reader of a Push
//! (`network_message::push_read`), so the lane reads what the generated codec reads and refuses
//! what it refuses; of the reading it keeps the key's id and mapping, the places of the suffix
//! and the payload, and the QoS byte. A frame that holds any other record, or bytes the reader
//! refuses, is not read here at all: the owned parse reads it, so a frame's records are never
//! split between the two.
//!
//! Places are `u32` offsets into the frame, so a record is twenty-odd bytes that outlive the
//! borrow and a frame's records are one small vector.

#[cfg(all(feature = "alloc", feature = "codec-push"))]
use crate::network_message::{body_read, push_read};
#[cfg(all(feature = "alloc", feature = "codec-push"))]
use sce_forge_runtime::codec::SceCursor;

/// The QoS extension's header: identity `0x1`, not mandatory, a VLE (`Z64`) body, and the `Z`
/// bit clear, which is what makes it the last of its chain.
#[cfg(all(feature = "alloc", feature = "codec-push"))]
const QOS_EXT_HEADER: u8 = 0x21;
/// The Put header with no timestamp, no encoding and no extension.
#[cfg(all(feature = "alloc", feature = "codec-push"))]
const PLAIN_PUT_HEADER: u8 = 0x01;

/// One plain `Put` read where it lies: where its key and payload are, not copies of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlainPut {
    /// The key's id: `0` is the literal key, which the suffix then carries whole.
    pub id: crate::wire_id::ExprId,
    /// The id is in the sender's mapping (the `M` flag), as every id a peer declared is.
    pub sender_mapping: bool,
    /// The key suffix, as a `start..end` of the buffer; `None` when there is none.
    pub suffix: Option<(u32, u32)>,
    /// The payload, as a `start..end` of the buffer.
    pub payload: (u32, u32),
    /// The QoS byte, when the record carries the extension.
    pub qos: Option<u8>,
    /// This record names the SAME key as the record before it in its frame: the same id in the
    /// same mapping, and either no suffix on both or the same bytes. `read_plain_puts` (with
    /// `alloc`) sets it as it reads, from the record's prefix when that repeats the one before it,
    /// so the layers that follow it (the key's composition, its match against the subscribers, a
    /// subscriber's list of keys) need not compare the same text again for every message of a
    /// stream. `false` for the first record of a frame and for a record read alone.
    pub repeats_key: bool,
}

/// One plain Put as the lane keeps it, with the bytes of its suffix, which the next record's are
/// compared with, and where the part of it that does not depend on the payload ends.
#[cfg(all(feature = "alloc", feature = "codec-push"))]
struct Read<'f> {
    put: PlainPut,
    suffix: Option<&'f [u8]>,
    /// Everything up to and including the Put header: the Push header, the key and the QoS
    /// extension. What follows is the payload's length and the payload.
    prefix_end: usize,
}

/// Where `part`, a slice of `frame`, lies in it.
#[cfg(all(feature = "alloc", feature = "codec-push"))]
fn place(frame: &[u8], part: &[u8]) -> Option<(u32, u32)> {
    let start = (part.as_ptr() as usize).checked_sub(frame.as_ptr() as usize)?;
    let end = start.checked_add(part.len())?;
    Some((u32::try_from(start).ok()?, u32::try_from(end).ok()?))
}

/// How far `cursor`, which runs over `frame`, has read.
#[cfg(all(feature = "alloc", feature = "codec-push"))]
fn read_to(frame: &[u8], cursor: &SceCursor<'_>) -> usize {
    frame.len().saturating_sub(cursor.remaining())
}

/// The plain Put at the cursor, which runs over `frame`, read past; `None` when the record there
/// is any other or bytes the reader refuses, and the cursor is then not to be read on.
///
/// The envelope is the Push reader's (`push_read::read_envelope`). Its verdict is the rule's on
/// the QoS extension alone, which no participant refuses (the tests hold it so), and a record
/// that carries any other extension is declined. The body of a plain Put is its header and its
/// payload, which the reader's payload part reads (`body_read::read_payload`).
#[cfg(all(feature = "alloc", feature = "codec-push"))]
#[inline]
fn read_plain_put<'f>(frame: &'f [u8], cursor: &mut SceCursor<'f>) -> Option<Read<'f>> {
    use wz_codecs::ext_entry::ExtEntryViewVariant;
    use wz_codecs::wireexpr::WireexprViewVariant;
    // The reader reads a record its caller dispatched by its MID.
    if cursor.peek_u8().ok()? & 0x1f != wz_codecs::wire_const::N_MID_PUSH {
        return None;
    }
    let mut view = wz_codecs::push::PushView::default();
    push_read::read_envelope(cursor, &mut view, &mut push_read::Lending).ok()?;
    let qos = match &view.extensions {
        None => None,
        Some(chain) if chain.inner().len() == 1 => {
            let entry = chain.inner().iter().next()?;
            if entry.header != QOS_EXT_HEADER {
                return None;
            }
            // The encoding the header names is the one the codec reads a number in.
            let ExtEntryViewVariant::CodecZenohExtZint(value) = entry.body else {
                return None;
            };
            // The QoS byte is the low byte of the extension's value, as `extract_qos` reads it.
            Some(value.value as u8)
        }
        Some(_) => return None,
    };
    if cursor.peek_u8().ok()? != PLAIN_PUT_HEADER {
        return None;
    }
    cursor.advance(1).ok()?;
    let prefix_end = read_to(frame, cursor);
    let (_, payload) = body_read::read_payload(cursor).ok()?;
    let (id, sender_mapping, suffix) = match &view.keyexpr.body {
        WireexprViewVariant::WireexprLocal(key) => (
            key.id,
            true,
            key.suffix.map(|text| text.into_inner().as_bytes()),
        ),
        WireexprViewVariant::WireexprNonlocal(key) => (
            key.id,
            false,
            key.suffix.map(|text| text.into_inner().as_bytes()),
        ),
    };
    let suffix_place = match suffix {
        Some(bytes) => Some(place(frame, bytes)?),
        None => None,
    };
    Some(Read {
        put: PlainPut {
            id,
            sender_mapping,
            suffix: suffix_place,
            payload: place(frame, payload)?,
            qos,
            repeats_key: false,
        },
        suffix,
        prefix_end,
    })
}

/// Whether two slices of one length hold the same bytes, for the few bytes a record's prefix
/// is: two loads that overlap each compare the first and the last bytes of the slice at the
/// width its length allows, which is the whole of it without a call to the C library's
/// `memcmp` (whose call, setup and dispatch cost more than the comparison of fourteen bytes).
/// A longer slice is the library's.
#[cfg(all(feature = "alloc", feature = "codec-push"))]
#[inline(always)]
fn equal_short(a: &[u8], b: &[u8]) -> bool {
    debug_assert_eq!(a.len(), b.len());
    // Each arm reads only widths its lengths admit, so no read below is `None`.
    let head4 = |s: &[u8]| s.first_chunk::<4>().map(|w| u32::from_ne_bytes(*w));
    let tail4 = |s: &[u8]| s.last_chunk::<4>().map(|w| u32::from_ne_bytes(*w));
    let head8 = |s: &[u8]| s.first_chunk::<8>().map(|w| u64::from_ne_bytes(*w));
    let tail8 = |s: &[u8]| s.last_chunk::<8>().map(|w| u64::from_ne_bytes(*w));
    let head16 = |s: &[u8]| s.first_chunk::<16>().map(|w| u128::from_ne_bytes(*w));
    let tail16 = |s: &[u8]| s.last_chunk::<16>().map(|w| u128::from_ne_bytes(*w));
    match a.len() {
        0 => true,
        // The first, the second (none for one byte) and the last: every byte of three.
        1..=3 => a.first() == b.first() && a.get(1) == b.get(1) && a.last() == b.last(),
        4..=7 => head4(a) == head4(b) && tail4(a) == tail4(b),
        8..=16 => head8(a) == head8(b) && tail8(a) == tail8(b),
        17..=32 => head16(a) == head16(b) && tail16(a) == tail16(b),
        _ => a == b,
    }
}

/// Every record of a frame's batch as a plain `Put`, or `None` when ANY of them is not
/// (and when the batch holds none): all or nothing, so a frame is read by one reader
/// and the order of its records is never split between two.
///
/// One allocation for the whole frame, sized by its first record, which is what a
/// stream's frame of equal messages needs.
#[cfg(all(feature = "alloc", feature = "codec-push"))]
pub fn read_plain_puts(buf: &[u8]) -> Option<alloc::vec::Vec<PlainPut>> {
    let mut puts = alloc::vec::Vec::new();
    let mut cursor = SceCursor::new(buf);
    // The record just read, whose key the next one may repeat: its reading, where it starts, the
    // length of its fixed prefix (the bytes of the Push header, the key, the QoS extension and
    // the Put header) and the bytes of its suffix.
    let mut before: Option<(PlainPut, usize, usize, Option<&[u8]>)> = None;
    while cursor.remaining() > 0 {
        let at = read_to(buf, &cursor);
        // A stream's records differ in their payload and nothing else, so a record that
        // starts with the same prefix bytes as the one before it is read as that one was:
        // the reading of those bytes is a function of the bytes alone. What is left to read
        // is the payload.
        if let Some((last, start, prefix_len, last_suffix)) = before {
            let now = at.checked_add(prefix_len).and_then(|to| buf.get(at..to));
            let then = start
                .checked_add(prefix_len)
                .and_then(|to| buf.get(start..to));
            let same_prefix = match (now, then) {
                (Some(now), Some(then)) => equal_short(now, then),
                _ => false,
            };
            if same_prefix {
                cursor.advance(prefix_len).ok()?;
                let (_, payload) = body_read::read_payload(&mut cursor).ok()?;
                // The suffix lies at the same distance from the start of the record.
                let moved = |range: (u32, u32)| {
                    let to_at = |position: u32| {
                        u32::try_from((position as usize).checked_sub(start)?.checked_add(at)?).ok()
                    };
                    Some((to_at(range.0)?, to_at(range.1)?))
                };
                let suffix = match last.suffix {
                    Some(range) => Some(moved(range)?),
                    None => None,
                };
                let put = PlainPut {
                    suffix,
                    payload: place(buf, payload)?,
                    repeats_key: true,
                    ..last
                };
                // The same bytes as the suffix before, which is all a comparison reads of them.
                before = Some((put, at, prefix_len, last_suffix));
                puts.push(put);
                continue;
            }
        }
        let read = read_plain_put(buf, &mut cursor)?;
        let mut put = read.put;
        put.repeats_key = before.is_some_and(|(last, _, _, last_suffix)| {
            last.id == put.id
                && last.sender_mapping == put.sender_mapping
                && last_suffix == read.suffix
        });
        // A record read at `at` ends, and its prefix ends, at or past `at`.
        before = Some((put, at, read.prefix_end.saturating_sub(at), read.suffix));
        if puts.capacity() == 0 {
            // Records of the size the first one is: its bytes, and the header around them.
            let width = read_to(buf, &cursor).saturating_sub(at).max(1);
            let records = buf.len().checked_div(width).unwrap_or(1);
            puts.reserve_exact(records.clamp(1, 4096));
        }
        puts.push(put);
    }
    if puts.is_empty() {
        None
    } else {
        Some(puts)
    }
}

#[cfg(all(test, feature = "alloc", feature = "codec-push"))]
mod tests {
    use super::*;
    use wz_codecs::lent::{Push, PushVariant, WireexprVariant};

    /// The plain Put at the start of `bytes`, read alone, and where it ends.
    fn read_one(bytes: &[u8]) -> Option<(PlainPut, usize)> {
        let mut cursor = SceCursor::new(bytes);
        let read = read_plain_put(bytes, &mut cursor)?;
        Some((read.put, bytes.len() - cursor.remaining()))
    }

    /// The id, whether the mapping is the sender's, the suffix, the payload, the QoS byte and
    /// the length of the record: what the generated codec reads out of one.
    type CodecRead = (
        crate::wire_id::ExprId,
        bool,
        Option<alloc::string::String>,
        alloc::vec::Vec<u8>,
        Option<u8>,
        usize,
    );

    /// What the generated codec reads out of `bytes` for a record this reader accepts: the key
    /// parts, the payload and the QoS byte, in the same shape.
    fn through_the_codec(bytes: &[u8]) -> Option<CodecRead> {
        let mut cursor = SceCursor::new(bytes);
        let push = Push::decode(&mut cursor).ok()?;
        let (id, suffix, mapping) = match &push.keyexpr.body {
            WireexprVariant::WireexprLocal(local) => (
                local.id,
                local
                    .suffix
                    .map(|s| alloc::string::String::from(s.into_inner())),
                true,
            ),
            WireexprVariant::WireexprNonlocal(non) => (
                non.id,
                non.suffix
                    .map(|s| alloc::string::String::from(s.into_inner())),
                false,
            ),
        };
        let PushVariant::CodecZenohMsgPut(put) = &push.body else {
            return None;
        };
        // The QoS the owned parse delivers: the last entry of its identity.
        let qos = push
            .extensions
            .as_ref()
            .and_then(|chain| crate::sample::extract_qos_in(chain.iter()))
            .map(|qos| qos.raw);
        Some((
            id,
            mapping,
            suffix,
            match &put.extensions_has_0x12 {
                wz_codecs::msg_put::MsgPutExtensionsHas0x12::NotHas0x12 { payload, .. } => {
                    payload.into_inner().to_vec()
                }
                wz_codecs::msg_put::MsgPutExtensionsHas0x12::Has0x12 { .. } => {
                    alloc::vec::Vec::new()
                }
            },
            qos,
            bytes.len() - cursor.remaining(),
        ))
    }

    fn encode(push: &Push<'_>) -> alloc::vec::Vec<u8> {
        let mut out = alloc::vec::Vec::new();
        push.encode(&mut sce_forge_runtime::codec::VecSink::new(&mut out))
            .expect("a Vec grows");
        out
    }

    /// Every plain Put the publishers here send, in the shapes a stream has (literal and
    /// aliased, with and without a suffix, with and without QoS), reads as the generated
    /// codec reads it: the same key parts, the same payload, the same QoS byte, and the
    /// same end.
    #[test]
    fn where_it_accepts_it_reads_what_the_codec_reads() {
        let mut accepted = 0usize;
        for id in [0u16, 1, 7, 127, 128, 300, 16_383, 16_384, 65_535] {
            for suffix in [
                None,
                Some("a"),
                Some("test/thr"),
                Some("a/long/key/suffix/x"),
            ] {
                if id == 0 && suffix.is_none() {
                    continue;
                }
                for qos in [None, Some(0x1au8), Some(0x05), Some(0xff)] {
                    for payload in [&b""[..], &b"x"[..], &[7u8; 127][..], &[9u8; 300][..]] {
                        let push = match qos {
                            Some(raw) => crate::lent_push::put_with_qos(
                                id,
                                suffix,
                                payload,
                                crate::sample::QosLevel::from_raw(raw),
                            ),
                            None => crate::lent_push::put_with_qos(
                                id,
                                suffix,
                                payload,
                                crate::sample::QosLevel::DEFAULT,
                            ),
                        }
                        .expect("within the bounds");
                        let bytes = encode(&push);
                        let (plain, end) = read_one(&bytes)
                            .unwrap_or_else(|| panic!("id {id} suffix {suffix:?} qos {qos:?}"));
                        let (cid, cmapping, csuffix, cpayload, cqos, cend) =
                            through_the_codec(&bytes).expect("the codec reads it");
                        assert_eq!(plain.id, cid);
                        assert_eq!(plain.sender_mapping, cmapping);
                        assert_eq!(
                            plain.suffix.map(|(from, to)| {
                                alloc::string::String::from(
                                    core::str::from_utf8(&bytes[from as usize..to as usize])
                                        .unwrap(),
                                )
                            }),
                            csuffix
                        );
                        assert_eq!(
                            &bytes[plain.payload.0 as usize..plain.payload.1 as usize],
                            &cpayload[..]
                        );
                        // A DEFAULT QoS byte rides no extension, and no extension reads None.
                        assert_eq!(plain.qos, cqos);
                        assert_eq!(end, cend);
                        accepted += 1;
                    }
                }
            }
        }
        assert!(accepted > 400, "the corpus is not empty: {accepted}");
    }

    /// Where the generated codec reads something this reader does not accept, the answer is
    /// `None`, never a different reading: every record below is valid to the codec and is
    /// not a plain Put (a timestamp, an encoding, an unknown or second extension, a Del, a
    /// different message), so the reader steps aside.
    #[test]
    fn what_is_not_a_plain_put_is_left_to_the_codec() {
        // Written byte by byte, so the control carries the QoS extension in a build without
        // `pubsub-qos` too: Push header with `Z`, id 3, the extension (`0x21`, value `0x1a`),
        // the Put header, a length of three, the payload.
        let plain = alloc::vec![
            0x9du8,
            3,
            QOS_EXT_HEADER,
            0x1a,
            PLAIN_PUT_HEADER,
            3,
            b'a',
            b'b',
            b'c'
        ];
        let (read, end) = read_one(&plain).expect("the control is plain");
        assert_eq!((read.id, read.qos, end), (3, Some(0x1a), plain.len()));
        assert_eq!(
            through_the_codec(&plain).expect("the codec reads the control"),
            (3, false, None, b"abc".to_vec(), Some(0x1a), plain.len())
        );

        // The Put carries a timestamp (T flag) or an encoding (E flag).
        for flag in [0x20u8, 0x40, 0x80] {
            let mut put = encode(
                &crate::lent_push::put_with_qos(3, None, b"abc", crate::sample::QosLevel::DEFAULT)
                    .expect("within the bounds"),
            );
            let at = put.iter().position(|b| *b == PLAIN_PUT_HEADER).unwrap();
            put[at] |= flag;
            assert!(read_one(&put).is_none(), "put flag {flag:#04x}");
        }
        // A Del body, and a message that is not a Push.
        let mut del = plain.clone();
        let at = del.len() - 3 - 1 - 1;
        del[at] = 0x02;
        assert!(read_one(&del).is_none());
        let mut other = plain.clone();
        other[0] = (other[0] & !0x1f) | 0x1b;
        assert!(read_one(&other).is_none());
        // An extension that is not the QoS: another identity, a second one behind it.
        let mut foreign = plain.clone();
        let ext = foreign.iter().position(|b| *b == QOS_EXT_HEADER).unwrap();
        foreign[ext] = 0x22;
        assert!(read_one(&foreign).is_none());
        let mut chained = plain.clone();
        chained[ext] |= 0x80;
        assert!(read_one(&chained).is_none());
        // A suffix that is not UTF-8, and a length that runs past the buffer.
        let mut bad = encode(
            &crate::lent_push::put_with_qos(0, Some("ab"), b"x", crate::sample::QosLevel::DEFAULT)
                .expect("within the bounds"),
        );
        bad[2] = 0xff;
        assert!(read_one(&bad).is_none());
        let truncated = &plain[..plain.len() - 1];
        assert!(read_one(truncated).is_none());
        assert!(read_one(&[]).is_none());
    }

    /// A Push whose chain carries the QoS twice is declined by the lane, which reads a chain of
    /// the QoS alone, and is left to the owned parse, which reads the last entry as upstream's
    /// decoder assigns each one it meets (`commons/zenoh-codec/src/network/push.rs` @
    /// `ext_qos = q;`). Turned red by a codec reading that keeps the first entry.
    #[test]
    fn a_repeated_qos_is_left_to_the_codec_which_reads_the_last() {
        // Push header with `Z`, id 3, the QoS (`0x21` with the chain flag, value `0x05`), the
        // QoS again (`0x21`, value `0x1a`), the Put header, a length of three, the payload.
        let twice = alloc::vec![
            0x9du8,
            3,
            QOS_EXT_HEADER | 0x80,
            0x05,
            QOS_EXT_HEADER,
            0x1a,
            PLAIN_PUT_HEADER,
            3,
            b'a',
            b'b',
            b'c'
        ];
        assert!(
            read_one(&twice).is_none(),
            "a chain of two is not a plain Put"
        );
        assert_eq!(
            through_the_codec(&twice).expect("the codec reads it"),
            (3, false, None, b"abc".to_vec(), Some(0x1a), twice.len())
        );
    }

    /// A suffix as long as a key holds reads, and one byte longer is declined here as the codec
    /// refuses it (`LengthOutOfRange`): a reader that took it would hand on a key the codec
    /// never delivers.
    #[test]
    fn a_suffix_longer_than_a_key_holds_is_declined_as_the_codec_refuses_it() {
        let record = |length: usize, vle: &[u8]| {
            // Push with `N`: the literal key, whole in the suffix.
            let mut out = alloc::vec![0x3du8, 0];
            out.extend_from_slice(vle);
            out.resize(out.len() + length, b'a');
            out.extend_from_slice(&[PLAIN_PUT_HEADER, 1, b'x']);
            out
        };
        let longest = record(65_535, &[0xff, 0xff, 0x03]);
        let (plain, end) = read_one(&longest).expect("the longest suffix reads");
        assert_eq!((plain.suffix, end), (Some((5, 5 + 65_535)), longest.len()));
        assert!(through_the_codec(&longest).is_some());

        let longer = record(65_536, &[0x80, 0x80, 0x04]);
        assert!(read_one(&longer).is_none());
        assert!(through_the_codec(&longer).is_none());
    }

    /// The widest id an `ExprId` holds reads, and the next one is declined here and refused
    /// by the codec: a VLE of `65_535` (`ff ff 03`) and of `65_536` (`80 80 04`).
    #[test]
    fn an_id_wider_than_an_expr_id_is_declined_as_the_codec_refuses_it() {
        let record = |id: [u8; 3]| {
            alloc::vec![
                0x5du8, // Push, M and no N: the peer's id, no suffix, no extension
                id[0],
                id[1],
                id[2],
                PLAIN_PUT_HEADER,
                1,
                b'x'
            ]
        };
        let widest = record([0xff, 0xff, 0x03]);
        let (plain, end) = read_one(&widest).expect("the widest id reads");
        assert_eq!((plain.id, end), (u16::MAX, widest.len()));
        assert_eq!(
            through_the_codec(&widest).map(|read| read.0),
            Some(u16::MAX)
        );

        let wider = record([0x80, 0x80, 0x04]);
        assert!(read_one(&wider).is_none());
        assert!(through_the_codec(&wider).is_none());
    }

    /// An id padded past its value's length reads as the codec reads it, in three bytes, in four
    /// and in nine: the reader of a Push takes a ZInt of any length, as upstream does, so a
    /// stream whose sender pads its ids stays on the lane.
    #[test]
    fn a_padded_id_reads_as_the_codec_reads_it() {
        let record = |id: &[u8]| {
            let mut out = alloc::vec![0x5du8];
            out.extend_from_slice(id);
            out.extend_from_slice(&[PLAIN_PUT_HEADER, 1, b'x']);
            out
        };
        let cases: [(&[u8], crate::wire_id::ExprId); 3] = [
            (&[0x85, 0x80, 0x00], 5),
            (&[0x85, 0x80, 0x80, 0x00], 5),
            (
                &[0xff, 0xff, 0x83, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00],
                u16::MAX,
            ),
        ];
        for (id, value) in cases {
            let bytes = record(id);
            let (plain, end) = read_one(&bytes).unwrap_or_else(|| panic!("{bytes:02x?}"));
            assert_eq!((plain.id, end), (value, bytes.len()));
            assert_eq!(through_the_codec(&bytes).map(|read| read.0), Some(value));
        }
    }

    /// The reader against the codec over damaged bytes: one byte of a valid record changed to
    /// every value. Where the reader accepts the result it reads the same key, payload, QoS
    /// and end as the codec does (the codec may accept things the reader declines, which is
    /// fine; the reader accepting something the codec reads differently is the failure).
    #[test]
    fn a_damaged_record_is_never_read_differently() {
        let seeds = [
            encode(
                &crate::lent_push::put_with_qos(
                    5,
                    None,
                    b"payload!",
                    crate::sample::QosLevel::from_raw(0x1a),
                )
                .expect("within the bounds"),
            ),
            encode(
                &crate::lent_push::put_with_qos(
                    0,
                    Some("test/thr"),
                    b"12345678",
                    crate::sample::QosLevel::DEFAULT,
                )
                .expect("within the bounds"),
            ),
            encode(
                &crate::lent_push::put_with_qos(
                    300,
                    Some("tail"),
                    &[1u8; 200],
                    crate::sample::QosLevel::from_raw(0x11),
                )
                .expect("within the bounds"),
            ),
        ];
        let mut agreed = 0usize;
        for seed in &seeds {
            for position in 0..seed.len() {
                for value in 0..=255u8 {
                    let mut bytes = seed.clone();
                    bytes[position] = value;
                    if let Some((plain, end)) = read_one(&bytes) {
                        let (cid, cmapping, csuffix, cpayload, cqos, cend) =
                            through_the_codec(&bytes).unwrap_or_else(|| {
                                panic!("the reader accepted what the codec refuses: byte {position} = {value:#04x}")
                            });
                        assert_eq!(plain.id, cid, "byte {position} = {value:#04x}");
                        assert_eq!(plain.sender_mapping, cmapping);
                        assert_eq!(
                            plain
                                .suffix
                                .map(|(from, to)| bytes[from as usize..to as usize].to_vec()),
                            csuffix.map(|text| text.into_bytes())
                        );
                        assert_eq!(
                            &bytes[plain.payload.0 as usize..plain.payload.1 as usize],
                            &cpayload[..]
                        );
                        assert_eq!(plain.qos, cqos, "byte {position} = {value:#04x}");
                        assert_eq!(end, cend);
                        agreed += 1;
                    }
                }
            }
        }
        assert!(
            agreed > 100,
            "the damaged corpus exercised the reader: {agreed}"
        );
    }

    /// A frame's batch is read whole or not at all: every record of equal messages comes
    /// back in wire order, and one record that is not a plain Put (here a keep-alive-sized
    /// record of another message, a Put with an encoding, a truncated tail) turns the
    /// whole batch over to the codec, with the plain records before it unread.
    #[test]
    fn a_batch_is_read_whole_or_not_at_all() {
        // Z-less records, byte by byte: id 3 and a payload of `n`, as a stream sends.
        let record = |tag: u8| {
            alloc::vec![
                0x5du8, // Push, M and no N: the peer's id, no suffix, no extension
                3,
                PLAIN_PUT_HEADER,
                1,
                tag
            ]
        };
        let mut batch = alloc::vec::Vec::new();
        for tag in 0..40u8 {
            batch.extend_from_slice(&record(tag));
        }
        let puts = read_plain_puts(&batch).expect("a batch of plain puts");
        assert_eq!(puts.len(), 40);
        for (index, put) in puts.iter().enumerate() {
            assert_eq!(put.id, 3);
            assert!(put.sender_mapping);
            assert_eq!(batch[put.payload.0 as usize], index as u8);
            assert_eq!(
                put.repeats_key,
                index != 0,
                "every record of the batch names the key of the one before it, bar the first"
            );
        }

        let mut mixed = batch.clone();
        mixed.extend_from_slice(&[0x5d, 3, PLAIN_PUT_HEADER | 0x40, 0, 1, 7]);
        assert!(
            read_plain_puts(&mixed).is_none(),
            "an encoding on the last put"
        );
        let mut cut = batch.clone();
        cut.pop();
        assert!(read_plain_puts(&cut).is_none(), "a truncated tail");
        assert!(
            read_plain_puts(&[]).is_none(),
            "an empty batch is the codec's"
        );
    }

    /// The short comparison says what `==` says: for every length across the width bands, equal
    /// slices, and slices that differ in any one byte, in any one bit.
    #[test]
    fn the_short_comparison_agrees_with_slice_equality() {
        for len in 0..=40usize {
            let a: alloc::vec::Vec<u8> = (0..len)
                .map(|i| (i as u8).wrapping_mul(37) ^ 0x5a)
                .collect();
            assert!(equal_short(&a, &a.clone()), "equal, length {len}");
            for position in 0..len {
                for bit in 0..8 {
                    let mut b = a.clone();
                    b[position] ^= 1 << bit;
                    assert_eq!(
                        equal_short(&a, &b),
                        a == b,
                        "length {len}, byte {position}, bit {bit}"
                    );
                    assert!(!equal_short(&a, &b), "a differing byte is seen");
                }
            }
        }
    }

    /// The batch as one record at a time through the reader that has no memory of the record
    /// before it, with `repeats_key` set by comparing the key's bytes: what a batch reader that
    /// reuses a record's reading must give back, field for field.
    fn read_one_by_one(buf: &[u8]) -> Option<alloc::vec::Vec<PlainPut>> {
        let mut out: alloc::vec::Vec<PlainPut> = alloc::vec::Vec::new();
        let mut cursor = SceCursor::new(buf);
        while cursor.remaining() > 0 {
            let mut put = read_plain_put(buf, &mut cursor)?.put;
            let key = |p: &PlainPut| p.suffix.map(|(a, b)| buf[a as usize..b as usize].to_vec());
            put.repeats_key = out.last().is_some_and(|last| {
                last.id == put.id
                    && last.sender_mapping == put.sender_mapping
                    && key(last) == key(&put)
            });
            out.push(put);
        }
        if out.is_empty() {
            None
        } else {
            Some(out)
        }
    }

    /// A batch whose records share a prefix is read as the records one at a time are read,
    /// whatever sits between the runs of equal prefixes: another key, another id, a suffix of
    /// the same length and other bytes, another QoS, a QoS where there was none, a payload
    /// length of one byte and of two, an empty payload; and a record cut short anywhere in a
    /// run turns the batch over to the codec exactly as it does without the shortcut.
    #[test]
    fn a_batch_that_reuses_a_prefix_reads_as_one_record_at_a_time_reads() {
        let qos = |raw: u8| crate::sample::QosLevel::from_raw(raw);
        let none = crate::sample::QosLevel::DEFAULT;
        let one = |id: crate::wire_id::ExprId, suffix: Option<&str>, payload: &[u8], q| {
            encode(
                &crate::lent_push::put_with_qos(id, suffix, payload, q).expect("within the bounds"),
            )
        };
        let runs: alloc::vec::Vec<alloc::vec::Vec<alloc::vec::Vec<u8>>> = alloc::vec![
            // A stream of one literal key with a QoS, then the same key with another QoS.
            (0..6u8)
                .map(|i| one(0, Some("test/thr"), &[i; 8], qos(0x1a)))
                .collect(),
            (0..3u8)
                .map(|i| one(0, Some("test/thr"), &[i; 8], qos(0x05)))
                .collect(),
            // The same length of suffix, other bytes.
            (0..3u8)
                .map(|i| one(0, Some("test/thx"), &[i; 8], qos(0x05)))
                .collect(),
            // An aliased key, with and without a suffix.
            (0..4u8).map(|i| one(7, None, &[i; 3], none)).collect(),
            (0..4u8)
                .map(|i| one(7, Some("/s"), &[i; 3], none))
                .collect(),
            // Another id, a long payload (a two-byte length), an empty payload.
            (0..3u8).map(|i| one(300, None, &[i; 200], none)).collect(),
            (0..3u8).map(|_| one(300, None, &[], none)).collect(),
            // Back to the first key.
            (0..2u8)
                .map(|i| one(0, Some("test/thr"), &[i; 1], qos(0x1a)))
                .collect(),
        ];
        let mut batch = alloc::vec::Vec::new();
        for run in &runs {
            for record in run {
                batch.extend_from_slice(record);
            }
        }
        let expected = read_one_by_one(&batch).expect("every record is plain");
        let got = read_plain_puts(&batch).expect("every record is plain");
        assert_eq!(got, expected, "the whole batch");
        assert!(
            got.iter().filter(|p| p.repeats_key).count() > 20,
            "the batch exercised the shortcut"
        );

        // Cut the batch at every length: the same answer as without the shortcut, and for a
        // cut inside a record that answer is none.
        for length in 0..batch.len() {
            assert_eq!(
                read_plain_puts(&batch[..length]),
                read_one_by_one(&batch[..length]),
                "cut at {length}"
            );
        }
        // A byte of the batch damaged: the same answer as without the shortcut.
        for position in 0..batch.len() {
            for value in [0u8, 0x01, 0x1d, 0x21, 0x41, 0x5d, 0x7f, 0x80, 0xff] {
                let mut damaged = batch.clone();
                damaged[position] = value;
                assert_eq!(
                    read_plain_puts(&damaged),
                    read_one_by_one(&damaged),
                    "byte {position} = {value:#04x}"
                );
            }
        }
    }

    /// The one extension a plain Put carries is one a participant takes whatever it says: what
    /// lets the lane hand a plain Put over without the verdict the owned parse judges each record
    /// by.
    #[test]
    fn the_extension_a_plain_put_carries_is_never_refused() {
        use crate::ext_admit::{judge_ext_chain, ExtCarrier, NetworkEnvelope};
        assert!(
            judge_ext_chain(ExtCarrier::Network(NetworkEnvelope::Push), [QOS_EXT_HEADER])
                .refusal()
                .is_none()
        );
    }
}
