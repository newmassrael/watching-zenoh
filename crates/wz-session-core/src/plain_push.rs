// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A strict reader of the one record a data stream is made of: a `Push` that carries a
//! `Put` with nothing on it but, at most, the QoS byte.
//!
//! The generated codec reads any `Push`, and what it hands back (a borrowed view, which
//! the heap profile then copies into an owned message, a box and a string and an extension
//! list) is built for generality: a publisher that sends the same small message a million
//! times pays for all of it each time. This reader recognises the shape a stream has and
//! nothing else. For that shape it returns the key's parts and the payload's range,
//! read where they lie, with no allocation and a few dozen instructions; for anything
//! else it answers `None` and the caller reads the record with the generated codec, as it
//! always did. So it never has to be right about a record it does not accept, and the one
//! requirement on it is the one the tests state: where it accepts, it reads what the
//! generated codec reads.
//!
//! The shape, as the generated `Push`, `Wireexpr`, `WireexprLocal`, `ExtEntry` and `MsgPut`
//! decode it:
//!
//! - the Push header: MID `0x1d`, the `N` flag (a suffix follows the id), the `M` flag
//!   (the id is in the SENDER's mapping, not ours) and the `Z` flag (an extension chain
//!   follows the key);
//! - the key: `id` as a VLE, and with `N` a VLE length and that many bytes of UTF-8;
//! - with `Z`, exactly one extension, the QoS: header `0x21` (identity 1, not mandatory,
//!   a VLE body), no further extension after it;
//! - the body: the Put header `0x01` (no timestamp, no encoding, no extension), a VLE length
//!   and that many payload bytes.
//!
//! Positions are `u32` offsets into the buffer the record was read from, so a record is
//! twenty-odd bytes that outlive the borrow and a frame's records are one small vector.

/// The Push header's MID.
const PUSH_MID: u8 = 0x1d;
/// `N`: a key suffix follows the id.
const FLAG_N: u8 = 0x20;
/// `M`: the id names a key in the sender's mapping.
const FLAG_M: u8 = 0x40;
/// `Z`: an extension chain follows the key.
const FLAG_Z: u8 = 0x80;
/// The QoS extension's header: identity `0x1`, not mandatory, a VLE (`Z64`) body, and the
/// `Z` bit clear, which is what makes it the last of its chain.
const QOS_EXT_HEADER: u8 = 0x21;
/// The Put header with no timestamp, no encoding and no extension.
const PLAIN_PUT_HEADER: u8 = 0x01;

/// One plain `Put` read where it lies: where its key and payload are, not copies of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlainPut {
    /// The key's id: `0` is the literal key, which the suffix then carries whole.
    pub id: u64,
    /// The id is in the sender's mapping (the `M` flag), as every id a peer declared is.
    pub sender_mapping: bool,
    /// The key suffix, as a `start..end` of the buffer; `None` when there is none.
    pub suffix: Option<(u32, u32)>,
    /// The payload, as a `start..end` of the buffer.
    pub payload: (u32, u32),
    /// The QoS byte, when the record carries the extension.
    pub qos: Option<u8>,
}

/// Read a VLE (zenoh `ZInt`) at `*at`, advancing it. The codec's rule: up to nine bytes,
/// seven data bits each with the high bit saying another follows, and the ninth byte
/// carrying eight data bits.
#[inline]
fn vle(buf: &[u8], at: &mut usize) -> Option<u64> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    for step in 0..9 {
        let byte = *buf.get(*at)?;
        *at += 1;
        if step == 8 {
            return Some(value | (u64::from(byte) << shift));
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
        shift += 7;
    }
    None
}

/// Read the plain `Put` that starts at `buf[at]`, and where it ends, or `None` when what
/// is there is anything else: another message, an extension this reader does not know, a
/// timestamp, an encoding, a sliced payload, a suffix that is not UTF-8, a length past the
/// end of the buffer.
///
/// `None` is not an error: the caller reads the record with the generated codec, which
/// decides whether it is one.
#[inline]
pub fn read_plain_put(buf: &[u8], at: usize) -> Option<(PlainPut, usize)> {
    read_plain_put_after(buf, at, None)
}

/// [`read_plain_put`] for a record that follows one whose suffix bytes were `known_utf8`:
/// a suffix of the same bytes is not checked again. A stream's records carry one key, and
/// checking it once per frame rather than once per record is what keeps the check off the
/// per-message cost; the bytes are equal, so the answer is.
#[inline]
fn read_plain_put_after(
    buf: &[u8],
    at: usize,
    known_utf8: Option<&[u8]>,
) -> Option<(PlainPut, usize)> {
    let mut cursor = at;
    let header = *buf.get(cursor)?;
    cursor += 1;
    if header & 0x1f != PUSH_MID {
        return None;
    }
    let id = vle(buf, &mut cursor)?;
    let suffix = if header & FLAG_N != 0 {
        let length = usize::try_from(vle(buf, &mut cursor)?).ok()?;
        let end = cursor.checked_add(length)?;
        let bytes = buf.get(cursor..end)?;
        // The codec refuses a suffix that is not UTF-8; this reader does not accept it.
        if known_utf8 != Some(bytes) {
            core::str::from_utf8(bytes).ok()?;
        }
        let range = (u32::try_from(cursor).ok()?, u32::try_from(end).ok()?);
        cursor = end;
        Some(range)
    } else {
        None
    };
    let qos = if header & FLAG_Z != 0 {
        if *buf.get(cursor)? != QOS_EXT_HEADER {
            return None;
        }
        cursor += 1;
        let value = vle(buf, &mut cursor)?;
        // The QoS byte is the low byte of the extension's value, as `extract_qos` reads it.
        Some(value as u8)
    } else {
        None
    };
    if *buf.get(cursor)? != PLAIN_PUT_HEADER {
        return None;
    }
    cursor += 1;
    let length = usize::try_from(vle(buf, &mut cursor)?).ok()?;
    let end = cursor.checked_add(length)?;
    buf.get(cursor..end)?;
    let payload = (u32::try_from(cursor).ok()?, u32::try_from(end).ok()?);
    Some((
        PlainPut {
            id,
            sender_mapping: header & FLAG_M != 0,
            suffix,
            payload,
            qos,
        },
        end,
    ))
}

/// Every record of a frame's batch as a plain `Put`, or `None` when ANY of them is not
/// (and when the batch holds none): all or nothing, so a frame is read by one reader
/// and the order of its records is never split between two.
///
/// One allocation for the whole frame, sized by its first record, which is what a
/// stream's frame of equal messages needs.
#[cfg(feature = "alloc")]
pub fn read_plain_puts(buf: &[u8]) -> Option<alloc::vec::Vec<PlainPut>> {
    let mut puts = alloc::vec::Vec::new();
    let mut at = 0usize;
    // The suffix of the record just read, which the next one may repeat.
    let mut previous: Option<&[u8]> = None;
    while at < buf.len() {
        let (put, end) = read_plain_put_after(buf, at, previous)?;
        previous = put
            .suffix
            .map(|(from, to)| &buf[from as usize..to as usize])
            .or(previous);
        if puts.capacity() == 0 {
            // Records of the size the first one is: its bytes, and the header around them.
            let width = (end - at).max(1);
            puts.reserve_exact((buf.len() / width).clamp(1, 4096));
        }
        puts.push(put);
        at = end;
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
    use sce_forge_runtime::codec::SceCursor;
    use wz_codecs::push::{Push, PushVariant};
    use wz_codecs::wireexpr::WireexprVariant;

    /// The id, whether the mapping is the sender's, the suffix, the payload, the QoS byte and
    /// the length of the record: what the generated codec reads out of one.
    type CodecRead = (
        u64,
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
                local.suffix.map(alloc::string::String::from),
                true,
            ),
            WireexprVariant::WireexprNonlocal(non) => {
                (non.id, non.suffix.map(alloc::string::String::from), false)
            }
        };
        let PushVariant::CodecZenohMsgPut(put) = &push.body else {
            return None;
        };
        let qos = push.extensions.as_ref().and_then(|chain| {
            chain
                .iter()
                .find(|ext| ext.header & 0x7f == 0x21)
                .and_then(|ext| match &ext.body {
                    wz_codecs::ext_entry::ExtEntryVariant::CodecZenohExtZint(z) => {
                        Some(z.value as u8)
                    }
                    _ => None,
                })
        });
        Some((
            id,
            mapping,
            suffix,
            put.payload.map(<[u8]>::to_vec).unwrap_or_default(),
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
        for id in [0u64, 1, 7, 127, 128, 300, 16_383, 16_384, 65_535] {
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
                        };
                        let bytes = encode(&push);
                        let (plain, end) = read_plain_put(&bytes, 0)
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
        let (read, end) = read_plain_put(&plain, 0).expect("the control is plain");
        assert_eq!((read.id, read.qos, end), (3, Some(0x1a), plain.len()));
        assert_eq!(
            through_the_codec(&plain).expect("the codec reads the control"),
            (3, false, None, b"abc".to_vec(), Some(0x1a), plain.len())
        );

        // The Put carries a timestamp (T flag) or an encoding (E flag).
        for flag in [0x20u8, 0x40, 0x80] {
            let mut put = encode(&crate::lent_push::put_with_qos(
                3,
                None,
                b"abc",
                crate::sample::QosLevel::DEFAULT,
            ));
            let at = put.iter().position(|b| *b == PLAIN_PUT_HEADER).unwrap();
            put[at] |= flag;
            assert!(read_plain_put(&put, 0).is_none(), "put flag {flag:#04x}");
        }
        // A Del body, and a message that is not a Push.
        let mut del = plain.clone();
        let at = del.len() - 3 - 1 - 1;
        del[at] = 0x02;
        assert!(read_plain_put(&del, 0).is_none());
        let mut other = plain.clone();
        other[0] = (other[0] & !0x1f) | 0x1b;
        assert!(read_plain_put(&other, 0).is_none());
        // An extension that is not the QoS: another identity, a second one behind it.
        let mut foreign = plain.clone();
        let ext = foreign.iter().position(|b| *b == QOS_EXT_HEADER).unwrap();
        foreign[ext] = 0x22;
        assert!(read_plain_put(&foreign, 0).is_none());
        let mut chained = plain.clone();
        chained[ext] |= 0x80;
        assert!(read_plain_put(&chained, 0).is_none());
        // A suffix that is not UTF-8, and a length that runs past the buffer.
        let mut bad = encode(&crate::lent_push::put_with_qos(
            0,
            Some("ab"),
            b"x",
            crate::sample::QosLevel::DEFAULT,
        ));
        bad[2] = 0xff;
        assert!(read_plain_put(&bad, 0).is_none());
        let truncated = &plain[..plain.len() - 1];
        assert!(read_plain_put(truncated, 0).is_none());
        assert!(read_plain_put(&[], 0).is_none());
    }

    /// The reader against the codec over damaged bytes: one byte of a valid record changed to
    /// every value. Where the reader accepts the result it reads the same key, payload, QoS
    /// and end as the codec does (the codec may accept things the reader declines, which is
    /// fine; the reader accepting something the codec reads differently is the failure).
    #[test]
    fn a_damaged_record_is_never_read_differently() {
        let seeds = [
            encode(&crate::lent_push::put_with_qos(
                5,
                None,
                b"payload!",
                crate::sample::QosLevel::from_raw(0x1a),
            )),
            encode(&crate::lent_push::put_with_qos(
                0,
                Some("test/thr"),
                b"12345678",
                crate::sample::QosLevel::DEFAULT,
            )),
            encode(&crate::lent_push::put_with_qos(
                300,
                Some("tail"),
                &[1u8; 200],
                crate::sample::QosLevel::from_raw(0x11),
            )),
        ];
        let mut agreed = 0usize;
        for seed in &seeds {
            for position in 0..seed.len() {
                for value in 0..=255u8 {
                    let mut bytes = seed.clone();
                    bytes[position] = value;
                    if let Some((plain, end)) = read_plain_put(&bytes, 0) {
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
}
