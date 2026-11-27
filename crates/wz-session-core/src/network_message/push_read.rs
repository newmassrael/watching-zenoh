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
//! damaged and cut bytes. It reads the envelope here, and the key and the body by the readers a
//! Reply's body is read with too (`super::body_read`), so a Put is read by one body of code
//! whichever record carries it.
//!
//! Each entry of a chain and each slice it decodes goes to a sink (`EntrySink`) as it is decoded.
//! A walk that lends the record keeps there the entries its delivery reads (`PushExts`), so the
//! delivery walks no chain again; the plain lane keeps nothing (`Lending`); the owned parse
//! builds its record's lists there (`read_push_owned`), so the record is filled from the one
//! decode of each entry and not from a second walk of the view. A build without an allocator has
//! no owned parse, and links the lending reading alone.

use sce_forge_runtime::codec::{CodecError, SceCursor};
use wz_codecs::ext_entry::ExtEntryView;
use wz_codecs::msg_del::MsgDelView;
use wz_codecs::msg_put::MsgPutView;
use wz_codecs::push::{PushUnknownTag, PushView, PushViewVariant};
use wz_codecs::zbuf_slice::ZbufSliceView;

#[cfg(feature = "alloc")]
use sce_forge_runtime::codec::{Bounded, Chain, Entries, HoldsList, Placed, SceList};
#[cfg(feature = "alloc")]
use wz_codecs::ext_entry::ExtEntryOwned;
#[cfg(any(test, feature = "alloc"))]
use wz_codecs::msg_put::MsgPutExtensionsHas0x12;
#[cfg(feature = "alloc")]
use wz_codecs::msg_put::{MsgPutExtensionsField, MsgPutIn, MsgPutSlicesField};
#[cfg(feature = "alloc")]
use wz_codecs::push::{PushExtensionsField, PushIn, PushVariantIn};
#[cfg(feature = "alloc")]
use wz_codecs::zbuf_slice::ZbufSliceOwned;

use super::body_read::{self, EntrySink, Judge, FLAG_Z, TAG_DEL, TAG_PUT};
use super::PushExts;
use crate::ext_admit::{ExtAdmission, ExtCarrier, NetworkEnvelope};

/// The sink of a reading that keeps nothing, the view holding each list as the bytes it lies in:
/// the plain lane's.
#[cfg(any(test, feature = "alloc"))]
pub(crate) struct Lending;

#[cfg(any(test, feature = "alloc"))]
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

/// The sink of a walk that lends the record: of the entries it is handed, the ones the delivery
/// of a lent Push reads, each the last of its identity, as a later entry of an identity replaces
/// an earlier one ([`crate::ext_view::last_by_eid`]).
impl<'f> EntrySink<'f> for PushExts<'f> {
    #[inline(always)]
    fn push_entry(&mut self, entry: &ExtEntryView<'f>) -> Result<(), CodecError> {
        let eid = crate::ext_header::ext_eid(entry.header);
        #[cfg(feature = "pubsub-qos")]
        if eid == crate::ext_header::network_eid::QOS {
            self.qos = Some(entry.clone());
        }
        #[cfg(feature = "pubsub-ts-stack")]
        if eid == crate::ext_header::ext_eid(crate::ts_stack::TS_STACK_EXT_HEADER) {
            self.ts_stack = true;
        }
        #[cfg(not(any(feature = "pubsub-qos", feature = "pubsub-ts-stack")))]
        let _ = eid;
        Ok(())
    }

    #[inline(always)]
    fn put_entry(&mut self, entry: &ExtEntryView<'f>) -> Result<(), CodecError> {
        self.body_entry(entry, crate::ext_header::body_eid::PUT_ATTACHMENT);
        Ok(())
    }

    #[inline(always)]
    fn put_marker(&mut self) {}

    #[inline(always)]
    fn slice(&mut self, _slice: &ZbufSliceView<'f>) -> Result<(), CodecError> {
        Ok(())
    }

    #[inline(always)]
    fn del_entry(&mut self, entry: &ExtEntryView<'f>) {
        self.body_entry(entry, crate::ext_header::body_eid::DEL_ATTACHMENT);
    }
}

impl<'f> PushExts<'f> {
    /// The next entry of the body's chain, whose attachment is of the identity `attachment`.
    /// Read only by this sink's walk, so unread in the builds that read no Push lent, as
    /// [`PushExts`] itself is (the same condition).
    #[cfg_attr(
        not(all(
            any(
                all(
                    feature = "alloc",
                    any(test, not(feature = "rx-lent-control"), feature = "routing-namespace")
                ),
                feature = "rx-push"
            ),
            any(
                test,
                feature = "session-unicast",
                all(feature = "session-multicast", not(feature = "alloc"))
            ),
            feature = "storage-profile",
            any(feature = "pubsub-put", feature = "pubsub-delete")
        )),
        allow(dead_code)
    )]
    #[inline(always)]
    fn body_entry(&mut self, entry: &ExtEntryView<'f>, attachment: u8) {
        let eid = crate::ext_header::ext_eid(entry.header);
        #[cfg(feature = "pubsub-attachment")]
        if eid == attachment {
            self.attachment = Some(entry.clone());
        }
        #[cfg(feature = "pubsub-source-info")]
        if eid == crate::ext_header::body_eid::SOURCE_INFO {
            self.source_info = Some(entry.clone());
        }
        #[cfg(not(feature = "pubsub-attachment"))]
        let _ = attachment;
        #[cfg(not(any(feature = "pubsub-attachment", feature = "pubsub-source-info")))]
        let _ = eid;
    }
}

/// The Push at the cursor, read into `out`, and the verdict on its chains: its own, then its
/// body's. Each entry of a chain and each slice goes to `sink` as it is decoded. The cursor is
/// past the record on success; on an error neither `out` nor `sink` is to be read.
pub(crate) fn read_push_view<'f, S: EntrySink<'f>>(
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
/// body of a plain Put is the header and the payload `body_read::read_payload` reads.
#[inline(always)]
pub(crate) fn read_envelope<'f, S: EntrySink<'f>>(
    cursor: &mut SceCursor<'f>,
    out: &mut PushView<'f>,
    sink: &mut S,
) -> Result<ExtAdmission, CodecError> {
    let header = body_read::byte(cursor)?;
    body_read::read_key(cursor, header, &mut out.keyexpr.body)?;
    let mut own = Judge::new(ExtCarrier::Network(NetworkEnvelope::Push));
    out.extensions = if header & FLAG_Z != 0 {
        Some(body_read::read_chain(cursor, &mut own, sink, None)?)
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
    // The Put reader writes every field of a Put's body, so a binding that holds a Put's arm
    // already (a view's default does) is read into as it is.
    if !(tag == TAG_PUT && matches!(out.body, PushViewVariant::CodecZenohMsgPut(_))) {
        out.body = match tag {
            TAG_PUT => PushViewVariant::CodecZenohMsgPut(MsgPutView::default()),
            TAG_DEL => PushViewVariant::CodecZenohMsgDel(MsgDelView::default()),
            // A tag no arm names: the default arm, whose body is read as a Put's. Five bits that
            // are not an arm's are always such a tag.
            other => PushViewVariant::Default {
                tag: PushUnknownTag::new(other).ok_or(CodecError::UndeclaredEnumValue)?,
                body: MsgPutView::default(),
            },
        };
    }
    let body = match &mut out.body {
        PushViewVariant::CodecZenohMsgPut(put) | PushViewVariant::Default { body: put, .. } => {
            body_read::read_put(cursor, put, sink)?
        }
        PushViewVariant::CodecZenohMsgDel(del) => body_read::read_del(cursor, del, sink)?,
    };
    Ok(crate::ext_admit::then_judge(own, || body))
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
    use super::super::judge_put_view;
    use super::*;
    use crate::ext_admit::ZenohBody;
    use sce_forge_runtime::codec::{ListView, Without};
    use wz_codecs::ext_entry::ExtEntryWalk;
    #[cfg(feature = "alloc")]
    use wz_codecs::wireexpr::WireexprViewVariant;

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
        let admission = crate::ext_admit::then_judge(
            crate::ext_admit::judge_entries(
                ExtCarrier::Network(NetworkEnvelope::Push),
                view.extensions
                    .as_ref()
                    .map(|chain| crate::ext_view::walked(Some(chain))),
            ),
            || match &view.body {
                PushViewVariant::CodecZenohMsgPut(put)
                | PushViewVariant::Default { body: put, .. } => judge_put_view(put),
                PushViewVariant::CodecZenohMsgDel(del) => crate::ext_admit::judge_entries(
                    ExtCarrier::Zenoh(ZenohBody::Del),
                    del.extensions
                        .as_ref()
                        .map(|chain| crate::ext_view::walked(Some(chain))),
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

    /// What a test compares of the extensions a delivery reads: the QoS entry and whether a
    /// timestamp stack is carried, of the Push's own chain; the attachment and the source-info
    /// entries of its body's. `None` and `false` where the build keeps none.
    #[derive(Debug, PartialEq)]
    struct DeliveryExts<'f> {
        qos: Option<ExtEntryView<'f>>,
        ts_stack: bool,
        attachment: Option<ExtEntryView<'f>>,
        source_info: Option<ExtEntryView<'f>>,
    }

    /// The entries of a body's chain other than the shared-memory marker, walked from the frame
    /// they lie in, for as long as the frame. A function of its own because the trait's method,
    /// handed to `Option::map` by path, is asked for every borrow of the list at once, which holds
    /// the list to outlive all of them and the frame with it.
    fn entries_of<'f>(
        rest: &Without<ListView<'f, ExtEntryWalk, 0>>,
    ) -> impl Iterator<Item = ExtEntryView<'f>> {
        sce_forge_runtime::codec::Entries::entries(rest)
    }

    impl<'f> DeliveryExts<'f> {
        /// What the reader kept in `exts` as it decoded each entry.
        fn kept(exts: &PushExts<'f>) -> Self {
            #[cfg(not(any(
                feature = "pubsub-qos",
                feature = "pubsub-ts-stack",
                feature = "pubsub-attachment",
                feature = "pubsub-source-info"
            )))]
            let _ = exts;
            Self {
                #[cfg(feature = "pubsub-qos")]
                qos: exts.qos.clone(),
                #[cfg(not(feature = "pubsub-qos"))]
                qos: None,
                #[cfg(feature = "pubsub-ts-stack")]
                ts_stack: exts.ts_stack,
                #[cfg(not(feature = "pubsub-ts-stack"))]
                ts_stack: false,
                #[cfg(feature = "pubsub-attachment")]
                attachment: exts.attachment.clone(),
                #[cfg(not(feature = "pubsub-attachment"))]
                attachment: None,
                #[cfg(feature = "pubsub-source-info")]
                source_info: exts.source_info.clone(),
                #[cfg(not(feature = "pubsub-source-info"))]
                source_info: None,
            }
        }

        /// What walks of `view`'s chains after the reading find: the last entry of each identity.
        fn walked(view: &PushView<'f>) -> Self {
            use crate::ext_header::{body_eid, network_eid};
            use crate::ext_view::{last_by_eid_in, walked};
            let own = || walked(view.extensions.as_ref());
            #[cfg(feature = "pubsub-ts-stack")]
            let ts_stack = last_by_eid_in(
                own(),
                crate::ext_header::ext_eid(crate::ts_stack::TS_STACK_EXT_HEADER),
            )
            .is_some();
            #[cfg(not(feature = "pubsub-ts-stack"))]
            let ts_stack = false;
            let (attachment, source_info) = match &view.body {
                PushViewVariant::CodecZenohMsgPut(put)
                | PushViewVariant::Default { body: put, .. } => {
                    // The entries other than the shared-memory marker, which the reader hands
                    // over as a place and not as an entry.
                    let chain = match &put.extensions_has_0x12 {
                        MsgPutExtensionsHas0x12::Has0x12 { extensions, .. } => {
                            Some(extensions.rest())
                        }
                        MsgPutExtensionsHas0x12::NotHas0x12 { extensions, .. } => {
                            extensions.as_ref().map(|chain| chain.inner())
                        }
                    };
                    let body = || crate::ext_view::walked_from(chain.map(entries_of));
                    (
                        last_by_eid_in(body(), body_eid::PUT_ATTACHMENT),
                        last_by_eid_in(body(), body_eid::SOURCE_INFO),
                    )
                }
                PushViewVariant::CodecZenohMsgDel(del) => {
                    let body = || walked(del.extensions.as_ref());
                    (
                        last_by_eid_in(body(), body_eid::DEL_ATTACHMENT),
                        last_by_eid_in(body(), body_eid::SOURCE_INFO),
                    )
                }
            };
            Self {
                qos: last_by_eid_in(own(), network_eid::QOS)
                    .filter(|_| cfg!(feature = "pubsub-qos")),
                ts_stack,
                attachment: attachment.filter(|_| cfg!(feature = "pubsub-attachment")),
                source_info: source_info.filter(|_| cfg!(feature = "pubsub-source-info")),
            }
        }
    }

    /// The extensions a delivery reads of the Push `bytes` begin with, as the reader kept them and
    /// as walks of its view's chains find them; `None` for bytes the reader refuses, and for a Del
    /// the rule refuses, whose chain is handed over only up to the entry it refuses.
    fn delivery_exts(bytes: &[u8]) -> Option<(DeliveryExts<'_>, DeliveryExts<'_>)> {
        let mut view = PushView::default();
        let mut exts = PushExts::default();
        let verdict = read_push_view(&mut SceCursor::new(bytes), &mut view, &mut exts).ok()?;
        if verdict.refusal().is_some() && matches!(view.body, PushViewVariant::CodecZenohMsgDel(_))
        {
            return None;
        }
        Some((DeliveryExts::kept(&exts), DeliveryExts::walked(&view)))
    }

    /// The reader with each sink against the codec over `bytes`: the lending reading against the
    /// codec's view, and with an allocator the owned read's record against the codec's decode at
    /// the heap's capacity; with an allocator also the owned parse against the codec's owned
    /// decode where the first record is a Push (the verdict it judged as it read against the owned
    /// message's own), and the plain lane over the whole of `bytes` as a frame against the codec's
    /// reading of each record: what each case below is held to.
    fn agree(bytes: &[u8], case: &dyn core::fmt::Debug) {
        assert_eq!(reading(bytes), through_the_codec(bytes), "{case:?}");
        if let Some((kept, walked)) = delivery_exts(bytes) {
            assert_eq!(kept, walked, "{case:?}");
        }
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
            // The QoS twice on the Push's chain; a Put's and a Del's chains that repeat their
            // extensions.
            repeated_qos(),
            repeated_put_exts(),
            repeated_del_exts(),
            // A mandatory entry no Push declares, and the reserved encoding, on the Push's chain.
            alloc::vec![0x9du8, 1, 0x1f, 0x01, 0],
            alloc::vec![0x9du8, 1, 0x61, 0x01, 0],
            // A mandatory entry no Put declares, on the Put's chain; and one on each chain.
            alloc::vec![0x1du8, 1, 0x81, 0x1e, 0],
            alloc::vec![0x9du8, 1, 0x1f, 0x81, 0x1e, 0],
        ]
    }

    /// A Push whose own chain carries the QoS twice, `0x05` then `0x1a`, and a Put of one byte.
    fn repeated_qos() -> alloc::vec::Vec<u8> {
        alloc::vec![0x9du8, 1, 0xa1, 0x05, 0x21, 0x1a, 0x01, 1, b'q']
    }

    /// A Put whose chain carries the source info of the zid `[0xA0, 1]`, the attachment `f`, the
    /// source info of the zid `[0xA0, 2]` and the attachment `l`, in that order.
    fn repeated_put_exts() -> alloc::vec::Vec<u8> {
        alloc::vec![
            0x1du8, 1, 0x81, 0xc1, 5, 0x10, 0xa0, 1, 1, 1, 0xc3, 1, b'f', 0xc1, 5, 0x10, 0xa0, 2,
            2, 2, 0x43, 1, b'l', 2, b'x', b'y'
        ]
    }

    /// A Del whose chain carries its attachment `a`, the source info of the zid `[0xA0, 1]`, a
    /// Put's attachment `p` and its own attachment `b`, in that order.
    fn repeated_del_exts() -> alloc::vec::Vec<u8> {
        alloc::vec![
            0x1du8, 1, 0x82, 0xc2, 1, b'a', 0xc1, 5, 0x10, 0xa0, 1, 1, 1, 0xc3, 1, b'p', 0x42, 1,
            b'b'
        ]
    }

    /// The extensions a delivery reads are kept as the reader decodes each entry, each the last of
    /// its identity: of two QoS entries the second, of a Put's repeated attachment and source info
    /// the last, and of a Del's attachments its own last one and not a Put's. Turned red by a sink
    /// that keeps the first entry of an identity, or reads a Del's attachment by the Put's
    /// identity.
    #[test]
    fn the_extensions_a_delivery_reads_are_the_last_of_their_identity() {
        use crate::ext_view::ExtEntryView as _;
        /// What the reader kept of `bytes`, which the walks of its chains find too.
        fn read(bytes: &[u8]) -> DeliveryExts<'_> {
            let (kept, walked) = delivery_exts(bytes).expect("the reader reads it and admits it");
            assert_eq!(kept, walked, "{bytes:02x?}");
            kept
        }
        let qos = repeated_qos();
        let kept = read(&qos);
        assert_eq!(
            kept.qos.as_ref().and_then(|e| e.zint()),
            cfg!(feature = "pubsub-qos").then_some(0x1a),
            "the second QoS entry"
        );
        let put = repeated_put_exts();
        let kept = read(&put);
        assert_eq!(
            kept.attachment.as_ref().and_then(|e| e.plain_zbuf()),
            cfg!(feature = "pubsub-attachment").then_some(&b"l"[..]),
            "the Put's last attachment"
        );
        assert_eq!(
            kept.source_info.as_ref().and_then(|e| e.plain_zbuf()),
            cfg!(feature = "pubsub-source-info").then_some(&[0x10u8, 0xa0, 2, 2, 2][..]),
            "the Put's last source info"
        );
        let del = repeated_del_exts();
        let kept = read(&del);
        assert_eq!(
            kept.attachment.as_ref().and_then(|e| e.plain_zbuf()),
            cfg!(feature = "pubsub-attachment").then_some(&b"b"[..]),
            "the Del's own last attachment, not the Put's"
        );
        assert_eq!(
            kept.source_info.as_ref().and_then(|e| e.plain_zbuf()),
            cfg!(feature = "pubsub-source-info").then_some(&[0x10u8, 0xa0, 1, 1, 1][..]),
            "the Del's source info"
        );
        assert!(!kept.ts_stack, "no record here carries a timestamp stack");
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

    /// A binding that held a Push read before is read into as it is, and reads each Push as a
    /// fresh binding does: every field of a Put's body is written, so the arm it holds already is
    /// not filled from a default first. Turned red by a Put reader that leaves a field of the body
    /// read before.
    #[test]
    fn a_push_read_into_a_binding_that_held_one_reads_as_into_a_fresh_one() {
        let all = shapes();
        for first in &all {
            for second in &all {
                let mut view = PushView::default();
                let read = read_push_view(&mut SceCursor::new(first), &mut view, &mut Lending);
                assert!(read.is_ok(), "{first:02x?}: {read:?}");
                let again = read_push_view(&mut SceCursor::new(second), &mut view, &mut Lending)
                    .map(|verdict| (view.clone(), verdict));
                let fresh = reading(second).map(|(view, _, verdict)| (view, verdict));
                assert_eq!(again, fresh, "{first:02x?} then {second:02x?}");
            }
        }
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

    /// The reader reports the first offence of a chain, as the rule over the codec's view does, a
    /// body its reader refuses included. Turned red by a judge that lets a later entry's verdict
    /// replace an earlier refusal, or that hands the rule an entry's header without its body.
    #[test]
    fn the_first_offence_of_a_chain_and_a_refused_body_are_reported() {
        let verdict = |bytes: &[u8]| reading(bytes).map(|(_, _, admission)| admission);
        // A mandatory unit no Push declares, then the reserved encoding, on the Push's own chain.
        let first = [0x9du8, 1, 0x9f, 0x61, 0x01, 0];
        assert_eq!(
            verdict(&first),
            Ok(ExtAdmission::UnknownMandatory { eid: 0x1f })
        );
        // A timestamp whose zid is zero, which its reader refuses, and one whose zid is not.
        let zero = [0x9du8, 1, 0x42, 3, 0x05, 0x01, 0x00, 0x01, 0];
        assert_eq!(verdict(&zero), Ok(ExtAdmission::MalformedExt { eid: 0x42 }));
        let good = [0x9du8, 1, 0x42, 3, 0x05, 0x01, 0x01, 0x01, 0];
        assert_eq!(verdict(&good), Ok(ExtAdmission::Admissible));
        for case in [&first[..], &zero[..], &good[..]] {
            assert_eq!(reading(case), through_the_codec(case), "{case:?}");
        }
    }
}
