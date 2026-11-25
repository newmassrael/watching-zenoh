// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The one reader of a Push: the record as the codec's view (`wz_codecs::push::PushView`) and
//! the verdict of the extension admission rule on its chains, read in one pass. Every walk that
//! reads a Push reads it here: the walks that lend a record where its frame lies (`lend_push`),
//! the owned parse (`decode_one_record`), which projects the view into its owned message, and the
//! lane of a data stream (`crate::plain_push`), which keeps of a plain Put the places of its parts.
//!
//! What it reads, and how it refuses what it does not, is the generated `PushView::decode`'s,
//! error for error, and its verdict is the one the rule gives the view it reads (the Push's own
//! chain, then its body's); the tests hold it to both over every shape a Push takes and over
//! damaged and cut bytes. It reads the envelope, the key and the Put body itself: a number of one
//! byte, which nearly every id and length a stream carries is, is read inline; a chain is decoded
//! once and judged as it is decoded, not walked again for the verdict; and the body of a Put and
//! the body of a tag no arm names, which the codec reads as a Put, are one body of code. What it
//! shares with every other reader it calls: an extension entry (`ExtEntryView::decode`, which
//! every walk of a chain decodes), a timestamp, an encoding, a shared-memory slice, a Del body,
//! and a number longer than a byte.
//!
//! Each entry of a chain and each slice it decodes goes to a sink (`EntrySink`) as it is decoded.
//! A walk that lends the view keeps nothing there (`Lending`), and its reading compiles to the
//! reader alone; the owned parse builds its record's lists there (`read_push_owned`), so the
//! record is filled from the one decode of each entry and not from a second walk of the view. A
//! build without an allocator has no owned parse, and links the lending reading alone.

use sce_forge_runtime::codec::{Bounded, Chain, CodecError, ListView, SceCursor, Without};
use wz_codecs::encoding::EncodingView;
use wz_codecs::ext_entry::{ExtEntryView, ExtEntryWalk};
use wz_codecs::msg_del::MsgDelView;
use wz_codecs::msg_put::{MsgPutExtensionsHas0x12, MsgPutExtensionsHas0x12Key, MsgPutView};
use wz_codecs::push::{PushUnknownTag, PushView, PushViewVariant};
use wz_codecs::timestamp::TimestampView;
use wz_codecs::wireexpr::WireexprViewVariant;
use wz_codecs::zbuf_slice::ZbufSliceView;

#[cfg(feature = "alloc")]
use sce_forge_runtime::codec::{Entries, HoldsList, Placed, SceList};
#[cfg(feature = "alloc")]
use wz_codecs::ext_entry::ExtEntryOwned;
#[cfg(feature = "alloc")]
use wz_codecs::msg_put::{MsgPutExtensionsField, MsgPutIn, MsgPutSlicesField};
#[cfg(feature = "alloc")]
use wz_codecs::push::{PushExtensionsField, PushIn, PushVariantIn};
#[cfg(feature = "alloc")]
use wz_codecs::zbuf_slice::ZbufSliceOwned;

use crate::ext_admit::{ExtAdmission, ExtCarrier, NetworkEnvelope, ZenohBody};

/// The Push's `N` flag: a key suffix follows the id.
const FLAG_N: u8 = 0x20;
/// The Push's `M` flag: the id is in the sender's mapping, the codec's `WireexprLocal` arm.
const FLAG_M: u8 = 0x40;
/// The `Z` flag of a Push's or a Put's header: an extension chain follows.
const FLAG_Z: u8 = 0x80;
/// The Put's `T` flag: a timestamp follows its header.
const PUT_FLAG_T: u8 = 0x20;
/// The Put's `E` flag: an encoding follows the timestamp.
const PUT_FLAG_E: u8 = 0x40;
/// The body's tag, the low five bits of its header: a Put.
const TAG_PUT: u8 = 0x01;
/// The body's tag: a Del.
const TAG_DEL: u8 = 0x02;
/// The low seven bits of the shared-memory marker's header: a Put whose chain carries it lays
/// its payload out as slices.
const SHM_MARKER: u8 = 0x12;
/// The longest key suffix the codec reads (`WireexprLocal` and `WireexprNonlocal`).
const SUFFIX_MAX: u64 = 65_535;
/// The longest inline payload the codec reads (`MsgPut`).
const PAYLOAD_MAX: u64 = 4_294_967_295;

/// The next byte, read past.
#[inline(always)]
fn byte(cursor: &mut SceCursor<'_>) -> Result<u8, CodecError> {
    let byte = cursor.peek_u8()?;
    cursor.advance(1)?;
    Ok(byte)
}

/// A `vle_u64` field: one byte read here, any longer number by the runtime's reader, which
/// answers for it what the codec answers.
#[inline(always)]
fn vle_u64(cursor: &mut SceCursor<'_>) -> Result<u64, CodecError> {
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

/// Where the reader puts what it decodes of a Push's lists, each part once, in the order of the
/// wire: the entries of the Push's own chain, the entries of its Put's chain with the place of
/// that chain's first shared-memory marker, and the Put's slices.
pub(crate) trait EntrySink<'f> {
    /// The next entry of the Push's own chain.
    fn push_entry(&mut self, entry: &ExtEntryView<'f>) -> Result<(), CodecError>;
    /// The next entry of the Put's chain other than its first shared-memory marker.
    fn put_entry(&mut self, entry: &ExtEntryView<'f>) -> Result<(), CodecError>;
    /// The Put chain's first shared-memory marker, after the entries before it: the codec holds
    /// it as the place it stands among the others, not as one of them.
    fn put_marker(&mut self);
    /// The next slice of a Put whose payload is laid out as slices.
    fn slice(&mut self, slice: &ZbufSliceView<'f>) -> Result<(), CodecError>;
}

/// The sink of a walk that lends the view: it keeps nothing, the view holding each list as the
/// bytes it lies in.
pub(crate) struct Lending;

impl<'f> EntrySink<'f> for Lending {
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
/// [`judge_ext_chain`](crate::ext_admit::judge_ext_chain) answers for the whole chain, its first
/// offender, without a second walk of the chain to find it.
struct Judge {
    carrier: ExtCarrier,
    verdict: ExtAdmission,
}

impl Judge {
    fn new(carrier: ExtCarrier) -> Self {
        Self {
            carrier,
            verdict: ExtAdmission::Admissible,
        }
    }

    /// The next entry's header.
    fn header(&mut self, header: u8) {
        if self.verdict == ExtAdmission::Admissible {
            self.verdict = crate::ext_admit::judge_ext_chain(self.carrier, [header]);
        }
    }
}

/// The extension chain at the cursor, to the entry whose `Z` flag is clear, as the list the
/// codec's view holds it as: the bytes from its first entry to the end of the frame, and how many
/// entries it has. Each entry's header is judged in order, and each entry goes to `sink` as it is
/// decoded. A Put's chain (`shm`) is judged with the shared-memory marker's own header at the
/// place of its first entry of that kind, as the rule reads a Put that holds the marker as a
/// place, and says whether it carried one; the Push's own chain is the one with no `shm`.
fn read_chain<'f, S: EntrySink<'f>>(
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
                judge.header(MsgPutExtensionsHas0x12Key::named().header);
                sink.put_marker();
            }
            Some(_) => {
                judge.header(entry.header);
                sink.put_entry(&entry)?;
            }
            None => {
                judge.header(entry.header);
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

/// The Push at the cursor, read into `out`, and the verdict on its chains: its own, then its
/// body's. Each entry of a chain and each slice goes to `sink` as it is decoded. The cursor is
/// past the record on success; on an error neither `out` nor `sink` is to be read.
pub(super) fn read_push_view<'f, S: EntrySink<'f>>(
    cursor: &mut SceCursor<'f>,
    out: &mut PushView<'f>,
    sink: &mut S,
) -> Result<ExtAdmission, CodecError> {
    let own = read_envelope(cursor, out, sink)?;
    read_body(cursor, out, sink, own)
}

/// The envelope of the Push at the cursor, read into `out`: its header, its key and its own
/// chain, and the verdict on that chain. The cursor is at the body's header after it. The plain
/// lane reads the envelope alone: what it keeps of a record's prefix ends at that header, and the
/// body of a plain Put is the header and the payload `read_payload` reads.
#[inline(always)]
pub(crate) fn read_envelope<'f, S: EntrySink<'f>>(
    cursor: &mut SceCursor<'f>,
    out: &mut PushView<'f>,
    sink: &mut S,
) -> Result<ExtAdmission, CodecError> {
    let header = byte(cursor)?;
    read_key(cursor, header, &mut out.keyexpr.body)?;
    let mut own = Judge::new(ExtCarrier::Network(NetworkEnvelope::Push));
    out.extensions = if header & FLAG_Z != 0 {
        Some(read_chain(cursor, &mut own, sink, None)?)
    } else {
        None
    };
    out.header = header;
    Ok(own.verdict)
}

/// The body of the Push whose envelope `read_envelope` read into `out` with the verdict
/// `own`, read into `out`, and the verdict on the record's chains: `own`, then the body's.
#[inline(always)]
fn read_body<'f, S: EntrySink<'f>>(
    cursor: &mut SceCursor<'f>,
    out: &mut PushView<'f>,
    sink: &mut S,
    own: ExtAdmission,
) -> Result<ExtAdmission, CodecError> {
    let tag = cursor.peek_u8()? & 0x1f;
    out.body = match tag {
        TAG_PUT => PushViewVariant::CodecZenohMsgPut(MsgPutView::default()),
        TAG_DEL => PushViewVariant::CodecZenohMsgDel(MsgDelView::default()),
        // A tag no arm names: the default arm, whose body is read as a Put's. Five bits that are
        // not an arm's are always such a tag.
        other => PushViewVariant::Default {
            tag: PushUnknownTag::new(other).ok_or(CodecError::UndeclaredEnumValue)?,
            body: MsgPutView::default(),
        },
    };
    let body = match &mut out.body {
        PushViewVariant::CodecZenohMsgPut(put) | PushViewVariant::Default { body: put, .. } => {
            read_put(cursor, put, sink)?
        }
        PushViewVariant::CodecZenohMsgDel(del) => {
            MsgDelView::decode_into(cursor, del)?;
            super::judge_headers(
                ExtCarrier::Zenoh(ZenohBody::Del),
                del.extensions
                    .as_ref()
                    .map(|chain| crate::ext_view::walked(Some(chain)).map(|e| e.header)),
            )
        }
    };
    Ok(super::then_judge(own, || body))
}

/// The key of a Push whose header is `header`: its id, and with `N` its suffix, in the arm its
/// `M` flag names.
fn read_key<'f>(
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

/// The Put body at the cursor, read into `put`, and the verdict on its chain. The entries of its
/// chain and its slices go to `sink` as they are decoded.
fn read_put<'f, S: EntrySink<'f>>(
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

/// The lent record at the heap's capacity, which the owned parse projects its owned message from.
#[cfg(feature = "alloc")]
type Kept<'f> = super::LentHeap<'f>;

/// A list of `Kept`'s field `F`, of the entries `T`.
#[cfg(feature = "alloc")]
type KeptList<'f, F, T> = <Kept<'f> as HoldsList<F>>::List<T>;

/// The Push at the cursor, read into `out`, the record the owned parse projects its owned
/// message from, and the verdict on its chains, as `read_push_view` reads them. Each entry of the
/// Push's chain and of its Put's, and each slice, is built into the record's lists as the reader
/// decodes it. A Del's chain is the codec's Del reader's, and is built from the view's walk of it.
#[cfg(feature = "alloc")]
pub(super) fn read_push_owned<'f>(
    cursor: &mut SceCursor<'f>,
    out: &mut PushIn<Kept<'f>>,
) -> Result<ExtAdmission, CodecError> {
    let mut view = PushView::default();
    let mut kept = Owning::default();
    let verdict = read_push_view(cursor, &mut view, &mut kept)?;
    kept.fill(&view, out)?;
    Ok(verdict)
}

/// The sink of the owned parse: the entries of the Push's own chain, and what its Put's body keeps.
#[cfg(feature = "alloc")]
#[derive(Default)]
struct Owning<'f> {
    push: KeptList<'f, PushExtensionsField, ExtEntryOwned<Kept<'f>>>,
    put: PutKept<'f>,
}

/// What the owned parse keeps of a Put's body: the entries of its chain other than its first
/// shared-memory marker, the marker's place among them, and its slices.
#[cfg(feature = "alloc")]
#[derive(Default)]
struct PutKept<'f> {
    chain: KeptList<'f, MsgPutExtensionsField, ExtEntryOwned<Kept<'f>>>,
    marker: usize,
    slices: KeptList<'f, MsgPutSlicesField, ZbufSliceOwned<Kept<'f>>>,
}

/// `list` with one more entry, built where it is held by `build`.
#[cfg(feature = "alloc")]
fn push_built<T: Default, L: SceList<T>>(
    list: &mut L,
    build: impl FnOnce(&mut T) -> Result<(), CodecError>,
) -> Result<(), CodecError> {
    list.try_push(T::default())?;
    if let Some(slot) = list.last_mut() {
        build(slot)?;
    }
    Ok(())
}

#[cfg(feature = "alloc")]
impl<'f> EntrySink<'f> for Owning<'f> {
    fn push_entry(&mut self, entry: &ExtEntryView<'f>) -> Result<(), CodecError> {
        push_built(&mut self.push, |slot: &mut ExtEntryOwned<Kept<'f>>| {
            entry.into_builder(slot)
        })
    }

    fn put_entry(&mut self, entry: &ExtEntryView<'f>) -> Result<(), CodecError> {
        push_built(&mut self.put.chain, |slot: &mut ExtEntryOwned<Kept<'f>>| {
            entry.into_builder(slot)
        })
    }

    fn put_marker(&mut self) {
        self.put.marker = self.put.chain.entry_count();
    }

    fn slice(&mut self, slice: &ZbufSliceView<'f>) -> Result<(), CodecError> {
        push_built(
            &mut self.put.slices,
            |slot: &mut ZbufSliceOwned<Kept<'f>>| slice.into_builder(slot),
        )
    }
}

#[cfg(feature = "alloc")]
impl<'f> Owning<'f> {
    /// `out` filled with what `view`, the reading these lists were kept from, says: every field
    /// the view holds, and each list from what was kept of it.
    fn fill(self, view: &PushView<'f>, out: &mut PushIn<Kept<'f>>) -> Result<(), CodecError> {
        let Self { push, put } = self;
        out.header = view.header;
        view.keyexpr.into_builder(&mut out.keyexpr)?;
        out.extensions = if view.extensions.is_some() {
            Some(Bounded::new(push).ok_or(CodecError::TooManyElements)?)
        } else {
            None
        };
        match &view.body {
            PushViewVariant::CodecZenohMsgPut(body) => {
                out.body = PushVariantIn::CodecZenohMsgPut(Default::default());
                if let PushVariantIn::CodecZenohMsgPut(record) = &mut out.body {
                    put.fill(body, record)?;
                }
            }
            PushViewVariant::Default { tag, body } => {
                out.body = PushVariantIn::Default {
                    tag: *tag,
                    body: Default::default(),
                };
                if let PushVariantIn::Default { body: record, .. } = &mut out.body {
                    put.fill(body, record)?;
                }
            }
            PushViewVariant::CodecZenohMsgDel(body) => {
                out.body = PushVariantIn::CodecZenohMsgDel(Default::default());
                if let PushVariantIn::CodecZenohMsgDel(record) = &mut out.body {
                    body.into_builder(record)?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(feature = "alloc")]
impl<'f> PutKept<'f> {
    /// `out` filled with what `view`, the Put these lists were kept from, says: its arm by the
    /// shared-memory marker, as the view's, with the chain and the slices kept of it.
    fn fill(self, view: &MsgPutView<'f>, out: &mut MsgPutIn<Kept<'f>>) -> Result<(), CodecError> {
        out.header = view.header;
        match &view.timestamp {
            Some(timestamp) => timestamp.into_builder(out.timestamp.insert(Default::default()))?,
            None => out.timestamp = None,
        }
        match &view.encoding {
            Some(encoding) => encoding.into_builder(out.encoding.insert(Default::default()))?,
            None => out.encoding = None,
        }
        out.extensions_has_0x12 = match &view.extensions_has_0x12 {
            MsgPutExtensionsHas0x12::Has0x12 { .. } => MsgPutExtensionsHas0x12::Has0x12 {
                extensions: Placed::new(self.chain, self.marker)
                    .ok_or(CodecError::PresentIfMismatch)?,
                slices: Bounded::new(self.slices).ok_or(CodecError::TooManyElements)?,
            },
            MsgPutExtensionsHas0x12::NotHas0x12 {
                extensions,
                payload,
            } => MsgPutExtensionsHas0x12::NotHas0x12 {
                extensions: if extensions.is_some() {
                    Some(Chain::new(self.chain).ok_or(CodecError::PresentIfMismatch)?)
                } else {
                    None
                },
                payload: *payload,
            },
        };
        out.payload_len = view.payload_len;
        out.slice_count = view.slice_count;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::{judge_headers, judge_put_view, then_judge};
    use super::*;

    /// What the reader reads from `bytes`: the view, how far it read and the verdict.
    fn reading(bytes: &[u8]) -> Result<(PushView<'_>, usize, ExtAdmission), CodecError> {
        let mut cursor = SceCursor::new(bytes);
        let mut view = PushView::default();
        let admission = read_push_view(&mut cursor, &mut view, &mut Lending)?;
        Ok((view, bytes.len() - cursor.remaining(), admission))
    }

    /// What the owned read makes of `bytes`: the record at the heap's capacity its sink built as
    /// the reader decoded each entry, how far it read and the verdict.
    #[cfg(feature = "alloc")]
    fn kept(bytes: &[u8]) -> Result<(PushIn<Kept<'_>>, usize, ExtAdmission), CodecError> {
        let mut cursor = SceCursor::new(bytes);
        let mut record = PushIn::default();
        let admission = read_push_owned(&mut cursor, &mut record)?;
        Ok((record, bytes.len() - cursor.remaining(), admission))
    }

    /// What the generated codec decodes `bytes` to at the heap's capacity, with how far the
    /// codec's view reads and the verdict the rule gives it: the reading the owned read is held to.
    #[cfg(feature = "alloc")]
    fn kept_through_the_codec(
        bytes: &[u8],
    ) -> Result<(PushIn<Kept<'_>>, usize, ExtAdmission), CodecError> {
        let (_, consumed, admission) = through_the_codec(bytes)?;
        let record = PushIn::<Kept<'_>>::decode(&mut SceCursor::new(bytes))?;
        Ok((record, consumed, admission))
    }

    /// What the generated codec reads from `bytes` and the verdict the rule gives the view it
    /// reads, walking each chain where it lies: the reading the reader is held to.
    fn through_the_codec(bytes: &[u8]) -> Result<(PushView<'_>, usize, ExtAdmission), CodecError> {
        let mut cursor = SceCursor::new(bytes);
        let view = PushView::decode(&mut cursor)?;
        let consumed = bytes.len() - cursor.remaining();
        let admission = then_judge(
            judge_headers(
                ExtCarrier::Network(NetworkEnvelope::Push),
                view.extensions
                    .as_ref()
                    .map(|chain| crate::ext_view::walked(Some(chain)).map(|e| e.header)),
            ),
            || match &view.body {
                PushViewVariant::CodecZenohMsgPut(put)
                | PushViewVariant::Default { body: put, .. } => judge_put_view(put),
                PushViewVariant::CodecZenohMsgDel(del) => judge_headers(
                    ExtCarrier::Zenoh(ZenohBody::Del),
                    del.extensions
                        .as_ref()
                        .map(|chain| crate::ext_view::walked(Some(chain)).map(|e| e.header)),
                ),
            },
        );
        Ok((view, consumed, admission))
    }

    /// What the owned parse makes of `bytes`, whose first record is a Push: the owned Push its one
    /// record dispatch (`decode_one_record`) builds, how far it read, and the verdict it judged as
    /// it read the chains.
    #[cfg(feature = "alloc")]
    fn owned(
        bytes: &[u8],
    ) -> Result<
        (
            wz_codecs::push::PushOwned<super::super::WireStorage>,
            usize,
            ExtAdmission,
        ),
        CodecError,
    > {
        let mut cursor = SceCursor::new(bytes);
        let mut out = alloc::vec::Vec::new();
        let decoded =
            super::super::decode_one_record(&mut cursor, &mut out, super::super::NO_ORIGIN)?;
        let consumed = bytes.len() - cursor.remaining();
        let super::super::Decoded::Judged(verdict) = decoded else {
            panic!("a Push is judged as it is read: {decoded:?}");
        };
        match out.pop() {
            Some(super::super::NetworkMessage::Push(push)) if out.is_empty() => {
                Ok((*push, consumed, verdict))
            }
            other => panic!("one Push is decoded: {other:?}"),
        }
    }

    /// What the generated codec decodes `bytes` to at the heap's capacity and projects into the
    /// owned Push, how far it read, and the verdict the owned message's own judge gives it: the
    /// reading the owned parse is held to.
    #[cfg(feature = "alloc")]
    fn owned_through_the_codec(
        bytes: &[u8],
    ) -> Result<
        (
            wz_codecs::push::PushOwned<super::super::WireStorage>,
            usize,
            ExtAdmission,
        ),
        CodecError,
    > {
        let mut cursor = SceCursor::new(bytes);
        let push = wz_codecs::push::PushIn::<super::super::LentHeap<'_>>::decode(&mut cursor)?;
        let consumed = bytes.len() - cursor.remaining();
        let owned = push.try_into_owned_in::<super::super::WireStorage>()?;
        let verdict = super::super::NetworkMessage::Push(alloc::boxed::Box::new(owned.clone()))
            .ext_admission();
        Ok((owned, consumed, verdict))
    }

    /// What the plain lane is held to over a frame: the codec's reading of each record, every one a
    /// Push whose own chain is the QoS entry alone or none and whose body is a Put with no
    /// timestamp, encoding or chain, kept as the places of its parts, each said to repeat the key
    /// of the record before it when its id, its mapping and its suffix's bytes are that record's;
    /// `None` when any record is another, or the codec refuses one, and for an empty frame.
    #[cfg(feature = "alloc")]
    fn plain_through_the_codec(
        frame: &[u8],
    ) -> Option<alloc::vec::Vec<crate::plain_push::PlainPut>> {
        use wz_codecs::ext_entry::ExtEntryViewVariant;
        let place = |part: &[u8]| {
            let start = part.as_ptr() as usize - frame.as_ptr() as usize;
            (start as u32, (start + part.len()) as u32)
        };
        let mut cursor = SceCursor::new(frame);
        let mut puts: alloc::vec::Vec<crate::plain_push::PlainPut> = alloc::vec::Vec::new();
        let mut last_suffix: Option<&[u8]> = None;
        while cursor.remaining() > 0 {
            if cursor.peek_u8().ok()? & 0x1f != wz_codecs::wire_const::N_MID_PUSH {
                return None;
            }
            let view = PushView::decode(&mut cursor).ok()?;
            let qos = match &view.extensions {
                None => None,
                Some(chain) => {
                    let mut entries = crate::ext_view::walked(Some(chain));
                    let entry = entries.next()?;
                    if entries.next().is_some() || entry.header != 0x21 {
                        return None;
                    }
                    match entry.body {
                        ExtEntryViewVariant::CodecZenohExtZint(value) => Some(value.value as u8),
                        _ => return None,
                    }
                }
            };
            let PushViewVariant::CodecZenohMsgPut(put) = &view.body else {
                return None;
            };
            let MsgPutExtensionsHas0x12::NotHas0x12 { payload, .. } = &put.extensions_has_0x12
            else {
                return None;
            };
            if put.header != 0x01 {
                return None;
            }
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
            let repeats_key = puts.last().is_some_and(|last| {
                last.id == id && last.sender_mapping == sender_mapping && last_suffix == suffix
            });
            puts.push(crate::plain_push::PlainPut {
                id,
                sender_mapping,
                suffix: suffix.map(place),
                payload: place(payload.into_inner()),
                qos,
                repeats_key,
            });
            last_suffix = suffix;
        }
        if puts.is_empty() {
            None
        } else {
            Some(puts)
        }
    }

    /// The reader with each sink against the codec over `bytes`: the lending reading against the
    /// codec's view, and with an allocator the owned read's record against the codec's decode at
    /// the heap's capacity; with an allocator also the owned parse against the codec's owned
    /// decode where the first record is a Push (the verdict it judged as it read against the owned
    /// message's own), and the plain lane over the whole of `bytes` as a frame against the codec's
    /// reading of each record: what each case below is held to.
    fn agree(bytes: &[u8], case: &dyn core::fmt::Debug) {
        assert_eq!(reading(bytes), through_the_codec(bytes), "{case:?}");
        #[cfg(feature = "alloc")]
        {
            assert_eq!(kept(bytes), kept_through_the_codec(bytes), "{case:?}");
            if bytes
                .first()
                .is_some_and(|header| header & 0x1f == wz_codecs::wire_const::N_MID_PUSH)
            {
                assert_eq!(owned(bytes), owned_through_the_codec(bytes), "{case:?}");
            }
            assert_eq!(
                crate::plain_push::read_plain_puts(bytes),
                plain_through_the_codec(bytes),
                "{case:?}"
            );
        }
    }

    /// Every shape a Push takes, written byte by byte: a plain Put with and without the QoS
    /// extension, a key in either mapping with and without a suffix, a chain of several entries,
    /// a Put with a timestamp and an encoding, a Put's own chain, a shared-memory Put (the marker
    /// first and after another entry), a Del (bare, with a timestamp, with a chain), a body tag
    /// no arm names, and chains the rule refuses on the Push and on the Put.
    fn shapes() -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
        let mut literal = alloc::vec![0xbdu8, 0, 8];
        literal.extend_from_slice(b"test/thr");
        literal.extend_from_slice(&[0xa1, 0x1a, 0x03, 0x01, 2, b'x', b'y']);
        alloc::vec![
            // `Z`, id 3 in our mapping, the QoS extension, a Put of three bytes.
            alloc::vec![0x9du8, 3, 0x21, 0x1a, 0x01, 3, b'a', b'b', b'c'],
            // No extension, a two-byte id, a payload whose length is two bytes.
            [&[0x1du8, 0xac, 0x02, 0x01, 0x81, 0x01][..], &[7u8; 129][..]].concat(),
            // `M` and `N`: the sender's id 5 and a suffix, an empty payload.
            alloc::vec![0x7du8, 5, 2, b'a', b'b', 0x01, 0],
            // The literal key in the suffix, a chain of the QoS and a unit entry.
            literal,
            // A Put with a timestamp (a two-byte time, a zid of two) and an encoding with a schema.
            alloc::vec![
                0x1du8, 7, 0x61, 0x85, 0x01, 2, 0xaa, 0xbb, 0x03, 3, b'a', b'b', b'c', 1, b'p'
            ],
            // A Put's own chain: a unit entry and a ZBuf entry of two bytes.
            alloc::vec![0x1du8, 1, 0x81, 0x85, 0x44, 2, 9, 9, 3, b'a', b'b', b'c'],
            // A shared-memory Put: the marker alone, one slice of two bytes.
            alloc::vec![0x1du8, 1, 0x81, 0x12, 1, 0, 2, 1, 2],
            // The marker after a unit entry, two slices.
            alloc::vec![0x1du8, 1, 0x81, 0x85, 0x12, 2, 0, 1, 7, 3, 0],
            // A Del, bare, with a timestamp, and with a chain.
            alloc::vec![0x1du8, 2, 0x02],
            alloc::vec![0x1du8, 2, 0x22, 5, 1, 0xee],
            alloc::vec![0x1du8, 2, 0x82, 0x05],
            // A body tag no arm names, read as a Put's body.
            alloc::vec![0x1du8, 4, 0x05, 1, b'z'],
            // A mandatory entry no Push declares, and the reserved encoding, on the Push's chain.
            alloc::vec![0x9du8, 1, 0x1f, 0x01, 0],
            alloc::vec![0x9du8, 1, 0x61, 0x01, 0],
            // A mandatory entry no Put declares, on the Put's chain; and one on each chain.
            alloc::vec![0x1du8, 1, 0x81, 0x1e, 0],
            alloc::vec![0x9du8, 1, 0x1f, 0x81, 0x1e, 0],
        ]
    }

    /// Over every shape, the reader reads what the codec reads and judges it as the rule judges
    /// the codec's view: the same view, the same end, the same verdict; the owned parse decodes it
    /// as the codec's owned decode does, and the plain lane keeps of it what the codec reads; and
    /// with other records around it, as a frame holds them, the same.
    #[test]
    fn every_shape_reads_as_the_codec_reads_it() {
        let behind = [0x9du8, 3, 0x21, 0x1a, 0x01, 1, b'n'];
        let mut refused = 0usize;
        #[cfg(feature = "alloc")]
        let mut plain = 0usize;
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
            // A run of the same record around another, as a stream's frame holds them: the plain
            // lane reads a record whose prefix repeats the one before it from that one's reading.
            let run = [&shape[..], &shape[..], &behind[..], &behind[..], &shape[..]].concat();
            agree(&run, &run);
            #[cfg(feature = "alloc")]
            if crate::plain_push::read_plain_puts(&run).is_some() {
                plain += 1;
            }
        }
        assert!(
            refused >= 3,
            "the corpus holds chains the rule refuses: {refused}"
        );
        #[cfg(feature = "alloc")]
        assert!(plain >= 3, "the corpus holds frames of plain Puts: {plain}");
    }

    /// Cut anywhere, a record is refused with the codec's error, and with any one byte changed to
    /// any value, the reader answers what the codec and the rule answer, and the owned parse what
    /// the codec's owned decode answers: the same reading, or the same error.
    #[test]
    fn a_cut_or_damaged_record_reads_as_the_codec_reads_it() {
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

    /// The edges of what the key holds, each read as the codec reads it, by the reader and by the
    /// owned parse: an id of the widest value and one past it, an id padded to nine bytes, a suffix
    /// of the longest length and one past it, and a suffix that is not UTF-8.
    #[test]
    fn the_key_s_edges_read_as_the_codec_reads_them() {
        let id = |vle: &[u8]| [&[0x1du8][..], vle, &[0x01, 0][..]].concat();
        let suffix = |length: usize, vle: &[u8], fill: u8| {
            let mut out = alloc::vec![0x3du8, 0];
            out.extend_from_slice(vle);
            out.resize(out.len() + length, fill);
            out.extend_from_slice(&[0x01, 0]);
            out
        };
        let cases = [
            id(&[0xff, 0xff, 0x03]),
            id(&[0x80, 0x80, 0x04]),
            id(&[0x85, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00]),
            suffix(65_535, &[0xff, 0xff, 0x03], b'a'),
            suffix(65_536, &[0x80, 0x80, 0x04], b'a'),
            suffix(2, &[2], 0xff),
        ];
        let answers: alloc::vec::Vec<_> =
            cases.iter().map(|case| reading(case.as_slice())).collect();
        for (case, answer) in cases.iter().zip(&answers) {
            assert_eq!(*answer, through_the_codec(case));
            agree(case, &case.len());
        }
        assert!(answers[0].is_ok() && answers[2].is_ok() && answers[3].is_ok());
        assert_eq!(
            answers[1].as_ref().err(),
            Some(&CodecError::VleWidthOverflow)
        );
        assert_eq!(
            answers[4].as_ref().err(),
            Some(&CodecError::LengthOutOfRange)
        );
        assert_eq!(answers[5].as_ref().err(), Some(&CodecError::InvalidUtf8));
    }
}
