// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The readers of the parts of a zenoh body that more than one record carries: the body of a Put
//! or a Del, which a Push, a Reply and a Request carry alike, the key every one of them names, an
//! extension chain judged as it is decoded, and the numbers and bytes those are made of. The
//! readers of a Push (`super::push_read`), a Response (`super::response_read`) and a Request
//! (`super::request_read`) read their parts here, so the program holds one reader of a Put body
//! however many records carry one.
//!
//! What each reads, and how it refuses what it does not, is the generated codec's, error for
//! error: the tests of each record's reader hold it to the codec over every shape the record takes
//! and over damaged and cut bytes. A number of one byte, which nearly every id and length a stream
//! carries is, is read inline; a chain is decoded once and judged as it is decoded, not walked
//! again for the verdict; and the body of a Put and the body of a tag no arm names, which the codec
//! reads as a Put, are one body of code. What it shares with every other reader it calls: an
//! extension entry (`ExtEntryView::decode`, which every walk of a chain decodes), a timestamp, an
//! encoding, a shared-memory slice, a Del body, and a number longer than a byte.
//!
//! Each entry of a chain and each slice it decodes goes to a sink (`EntrySink`) as it is decoded,
//! the record's reader saying what it keeps of them.

use sce_forge_runtime::codec::{Bounded, Chain, CodecError, ListView, SceCursor, Without};
use wz_codecs::encoding::EncodingView;
use wz_codecs::ext_entry::{ExtEntryView, ExtEntryWalk};
use wz_codecs::msg_del::MsgDelView;
use wz_codecs::msg_put::{MsgPutExtensionsHas0x12, MsgPutExtensionsHas0x12Key, MsgPutView};
use wz_codecs::timestamp::TimestampView;
use wz_codecs::wireexpr::WireexprViewVariant;
use wz_codecs::zbuf_slice::ZbufSliceView;

use crate::ext_admit::{ExtAdmission, ExtCarrier, ZenohBody};

/// The `N` flag of the header of a record that names a key: a key suffix follows the id.
const FLAG_N: u8 = 0x20;
/// The `M` flag of the header of a record that names a key: the id is in the sender's mapping,
/// the codec's `WireexprLocal` arm.
const FLAG_M: u8 = 0x40;
/// The `Z` flag of a record's or a body's header: an extension chain follows.
pub(super) const FLAG_Z: u8 = 0x80;
/// The Put's `T` flag: a timestamp follows its header.
const PUT_FLAG_T: u8 = 0x20;
/// The Put's `E` flag: an encoding follows the timestamp.
const PUT_FLAG_E: u8 = 0x40;
/// The body's tag, the low five bits of its header: a Put.
pub(super) const TAG_PUT: u8 = 0x01;
/// The body's tag: a Del.
pub(super) const TAG_DEL: u8 = 0x02;
/// The low seven bits of the shared-memory marker's header: a Put whose chain carries it lays
/// its payload out as slices.
const SHM_MARKER: u8 = 0x12;
/// The longest key suffix the codec reads (`WireexprLocal` and `WireexprNonlocal`).
const SUFFIX_MAX: u64 = 65_535;
/// The longest inline payload the codec reads (`MsgPut`).
const PAYLOAD_MAX: u64 = 4_294_967_295;

/// The next byte, read past.
#[inline(always)]
pub(super) fn byte(cursor: &mut SceCursor<'_>) -> Result<u8, CodecError> {
    let byte = cursor.peek_u8()?;
    cursor.advance(1)?;
    Ok(byte)
}

/// A `vle_u64` field: one byte read here, any longer number by the runtime's reader, which
/// answers for it what the codec answers.
#[inline(always)]
pub(super) fn vle_u64(cursor: &mut SceCursor<'_>) -> Result<u64, CodecError> {
    match cursor.peek_u8() {
        Ok(byte) if byte & 0x80 == 0 => {
            cursor.advance(1)?;
            Ok(u64::from(byte))
        }
        _ => cursor.read_vle_u64(),
    }
}

/// A `vle_u16` field, as `vle_u64` reads one.
#[inline(always)]
fn vle_u16(cursor: &mut SceCursor<'_>) -> Result<u16, CodecError> {
    match cursor.peek_u8() {
        Ok(byte) if byte & 0x80 == 0 => {
            cursor.advance(1)?;
            Ok(u16::from(byte))
        }
        _ => cursor.read_vle_u16(),
    }
}

/// Where a reader puts what it decodes of a record's lists, each part once, in the order of the
/// wire: the entries of the record's own chains (a Push's, a Request's, a Response's and its
/// Reply's), the entries of its Put's chain with the place of that chain's first shared-memory
/// marker, the Put's slices, and the entries of its Del's chain.
pub(crate) trait EntrySink<'f> {
    /// The next entry of a chain of the record's own, a chain with no shared-memory marker.
    fn push_entry(&mut self, entry: &ExtEntryView<'f>) -> Result<(), CodecError>;
    /// The next entry of the Put's chain other than its first shared-memory marker.
    fn put_entry(&mut self, entry: &ExtEntryView<'f>) -> Result<(), CodecError>;
    /// The Put chain's first shared-memory marker, after the entries before it: the codec holds
    /// it as the place it stands among the others, not as one of them.
    fn put_marker(&mut self);
    /// The next slice of a Put whose payload is laid out as slices.
    fn slice(&mut self, slice: &ZbufSliceView<'f>) -> Result<(), CodecError>;
    /// The next entry of a Del's chain, as the rule judges it: a chain the rule refuses is
    /// handed over up to the entry it refuses.
    fn del_entry(&mut self, _entry: &ExtEntryView<'f>) {}
}

/// The sink of the readers of a Request and a Response, which keep nothing of a chain: the
/// delivery of a lent query or reply walks the chains it reads where they lie. A type of its own,
/// so the instances of the chain and Put readers those readers call are theirs, and the ones the
/// walks of a Push call keep the callers they have.
#[cfg(any(
    all(
        feature = "codec-frame",
        feature = "codec-request",
        feature = "request-put-del",
        any(
            test,
            feature = "session-unicast",
            all(feature = "session-multicast", not(feature = "alloc"))
        )
    ),
    all(
        feature = "codec-frame",
        feature = "codec-response",
        any(
            all(
                feature = "alloc",
                any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
            ),
            feature = "rx-response"
        ),
        any(
            test,
            feature = "session-unicast",
            all(feature = "session-multicast", not(feature = "alloc"))
        )
    )
))]
pub(super) struct InPlace;

#[cfg(any(
    all(
        feature = "codec-frame",
        feature = "codec-request",
        feature = "request-put-del",
        any(
            test,
            feature = "session-unicast",
            all(feature = "session-multicast", not(feature = "alloc"))
        )
    ),
    all(
        feature = "codec-frame",
        feature = "codec-response",
        any(
            all(
                feature = "alloc",
                any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
            ),
            feature = "rx-response"
        ),
        any(
            test,
            feature = "session-unicast",
            all(feature = "session-multicast", not(feature = "alloc"))
        )
    )
))]
impl<'f> EntrySink<'f> for InPlace {
    #[inline(always)]
    fn push_entry(&mut self, _entry: &ExtEntryView<'f>) -> Result<(), CodecError> {
        Ok(())
    }

    #[inline(always)]
    fn put_entry(&mut self, _entry: &ExtEntryView<'f>) -> Result<(), CodecError> {
        Ok(())
    }

    #[inline(always)]
    fn put_marker(&mut self) {}

    #[inline(always)]
    fn slice(&mut self, _slice: &ZbufSliceView<'f>) -> Result<(), CodecError> {
        Ok(())
    }
}

/// The admission rule over a chain read one entry at a time: what
/// [`judge_ext_entries`](crate::ext_admit::judge_ext_entries) answers for the whole chain, its
/// first offender, without a second walk of the chain to find it. Each entry goes through the
/// rule's inline screen and, when the screen cannot pass it, the rule's one body
/// (`crate::ext_admit::judge_one`), so the reader links no copy of the rule of its own. The
/// carriers it judges are always named, so a chain read through is admissible.
pub(super) struct Judge {
    carrier: ExtCarrier,
    /// The first offender of the entries judged so far, or `Admissible`.
    pub(super) verdict: ExtAdmission,
}

impl Judge {
    /// The rule of `carrier`, before any entry is judged.
    pub(super) fn new(carrier: ExtCarrier) -> Self {
        Self {
            carrier,
            verdict: ExtAdmission::Admissible,
        }
    }

    /// The next entry: its header, and the body of an extension the carrier declares.
    fn entry(&mut self, entry: &ExtEntryView<'_>) {
        if self.verdict == ExtAdmission::Admissible {
            self.verdict = crate::ext_admit::judge_one(self.carrier, entry)
                .unwrap_or(ExtAdmission::Admissible);
        }
    }

    /// The shared-memory marker a Put holds as a place: a unit, judged by its header alone.
    fn marker(&mut self) {
        if self.verdict == ExtAdmission::Admissible {
            self.verdict = crate::ext_admit::judge_one_header(
                self.carrier,
                MsgPutExtensionsHas0x12Key::named().header,
            )
            .unwrap_or(ExtAdmission::Admissible);
        }
    }
}

/// The extension chain at the cursor, to the entry whose `Z` flag is clear, as the list the
/// codec's view holds it as: the bytes from its first entry to the end of the frame, and how many
/// entries it has. Each entry is judged in order, and each entry goes to `sink` as it is
/// decoded. A Put's chain (`shm`) is judged with the shared-memory marker's own header at the
/// place of its first entry of that kind, as the rule reads a Put that holds the marker as a
/// place, and says whether it carried one; a chain of the record's own is one with no `shm`.
pub(super) fn read_chain<'f, S: EntrySink<'f>>(
    cursor: &mut SceCursor<'f>,
    judge: &mut Judge,
    sink: &mut S,
    mut shm: Option<&mut bool>,
) -> Result<Bounded<ListView<'f, ExtEntryWalk, 0>, { usize::MAX }, 1>, CodecError> {
    let rest = cursor.peek_slice(cursor.remaining())?;
    let mut count: u32 = 0;
    loop {
        let entry = ExtEntryView::decode(cursor)?;
        match shm.as_deref_mut() {
            Some(seen) if !*seen && entry.header & 0x7f == SHM_MARKER => {
                *seen = true;
                judge.marker();
                sink.put_marker();
            }
            Some(_) => {
                judge.entry(&entry);
                sink.put_entry(&entry)?;
            }
            None => {
                judge.entry(&entry);
                sink.push_entry(&entry)?;
            }
        }
        // An entry is a byte at least, so no frame holds `u32::MAX` of them.
        count = count.saturating_add(1);
        if !entry.z() {
            break;
        }
    }
    Bounded::new(ListView::new(rest, count, [])).ok_or(CodecError::TooManyElements)
}

/// The key of a record whose header is `header` (a Push, a Request and a Response place its flags
/// alike): its id, and with `N` its suffix, in the arm its `M` flag names. Held in place in each
/// record's reader, so the walk of a Push reads its key with no call whichever reader reads one
/// too.
#[inline(always)]
pub(super) fn read_key<'f>(
    cursor: &mut SceCursor<'f>,
    header: u8,
    out: &mut WireexprViewVariant<'f>,
) -> Result<(), CodecError> {
    let id = vle_u16(cursor)?;
    let (suffix_len, suffix) = if header & FLAG_N != 0 {
        let length = vle_u64(cursor)?;
        if length > SUFFIX_MAX {
            return Err(CodecError::LengthOutOfRange);
        }
        // At most `SUFFIX_MAX`, which every `usize` holds.
        let length_bytes = length as usize;
        let text = core::str::from_utf8(cursor.peek_slice(length_bytes)?)
            .map_err(|_| CodecError::InvalidUtf8)?;
        cursor.advance(length_bytes)?;
        (
            Some(length),
            Some(Bounded::new(text).ok_or(CodecError::LengthOutOfRange)?),
        )
    } else {
        (None, None)
    };
    *out = if header & FLAG_M != 0 {
        WireexprViewVariant::WireexprLocal(wz_codecs::wireexpr_local::WireexprLocal {
            id,
            suffix_len,
            suffix,
        })
    } else {
        WireexprViewVariant::WireexprNonlocal(wz_codecs::wireexpr_nonlocal::WireexprNonlocal {
            id,
            suffix_len,
            suffix,
        })
    };
    Ok(())
}

/// The Put body at the cursor, read into `put`, and the verdict on its chain: the body a Push, a
/// Reply and a Request carry alike, and the arm a body tag no arm names is read as. The entries of
/// its chain and its slices go to `sink` as they are decoded.
pub(super) fn read_put<'f, S: EntrySink<'f>>(
    cursor: &mut SceCursor<'f>,
    put: &mut MsgPutView<'f>,
    sink: &mut S,
) -> Result<ExtAdmission, CodecError> {
    let header = byte(cursor)?;
    if header & PUT_FLAG_T != 0 {
        TimestampView::decode_into(cursor, put.timestamp.insert(TimestampView::default()))?;
    } else {
        put.timestamp = None;
    }
    if header & PUT_FLAG_E != 0 {
        EncodingView::decode_into(cursor, put.encoding.insert(EncodingView::default()))?;
    } else {
        put.encoding = None;
    }
    let mut judge = Judge::new(ExtCarrier::Zenoh(ZenohBody::Put));
    let mut sliced = false;
    let extensions = if header & FLAG_Z != 0 {
        Some(read_chain(cursor, &mut judge, sink, Some(&mut sliced))?)
    } else {
        None
    };
    if sliced {
        let count = cursor.read_vle_u32()?;
        let rest = cursor.peek_slice(cursor.remaining())?;
        for _ in 0..count {
            let slice = ZbufSliceView::decode(cursor)?;
            sink.slice(&slice)?;
        }
        let slices =
            Bounded::new(ListView::new(rest, count, [])).ok_or(CodecError::TooManyElements)?;
        // The marker was found in the chain, so there is one, and it holds an entry of its kind.
        let chain = extensions.ok_or(CodecError::PresentIfMismatch)?;
        put.extensions_has_0x12 = MsgPutExtensionsHas0x12::Has0x12 {
            extensions: sce_forge_runtime::codec::place_first_in::<
                _,
                MsgPutExtensionsHas0x12Key,
                { usize::MAX },
            >(chain.into_inner())
            .map_err(|_| CodecError::PresentIfMismatch)?,
            slices,
        };
        put.payload_len = None;
        put.slice_count = Some(count);
    } else {
        let (length, payload) = read_payload(cursor)?;
        // A chain with no marker is one the arm with an inline payload holds.
        let extensions = match extensions {
            Some(chain) => Some(
                Chain::new(Without::whole(chain.into_inner()))
                    .ok_or(CodecError::PresentIfMismatch)?,
            ),
            None => None,
        };
        put.extensions_has_0x12 = MsgPutExtensionsHas0x12::NotHas0x12 {
            extensions,
            payload: Bounded::new(payload).ok_or(CodecError::LengthOutOfRange)?,
        };
        put.payload_len = Some(length);
        put.slice_count = None;
    }
    put.header = header;
    Ok(judge.verdict)
}

/// The payload of a Put that carries it inline: its length, and that many bytes, where they lie.
#[inline(always)]
pub(crate) fn read_payload<'f>(cursor: &mut SceCursor<'f>) -> Result<(u64, &'f [u8]), CodecError> {
    let length = vle_u64(cursor)?;
    if length > PAYLOAD_MAX {
        return Err(CodecError::LengthOutOfRange);
    }
    let length_bytes = usize::try_from(length).map_err(|_| CodecError::NeedMoreBytes)?;
    let payload = cursor.peek_slice(length_bytes)?;
    cursor.advance(length_bytes)?;
    Ok((length, payload))
}

/// The Del body at the cursor, read into `del`, and the verdict on its chain: the body a Push, a
/// Reply and a Request carry alike. The codec's Del reader decodes the chain; the one walk of it
/// is the rule's, which hands each entry to `sink` as it judges it.
#[inline(always)]
pub(super) fn read_del<'f, S: EntrySink<'f>>(
    cursor: &mut SceCursor<'f>,
    del: &mut MsgDelView<'f>,
    sink: &mut S,
) -> Result<ExtAdmission, CodecError> {
    MsgDelView::decode_into(cursor, del)?;
    Ok(super::judge_entries(
        ExtCarrier::Zenoh(ZenohBody::Del),
        del.extensions.as_ref().map(|chain| {
            crate::ext_view::walked(Some(chain)).inspect(|entry| sink.del_entry(entry))
        }),
    ))
}
