// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The payload of a Put body: two wire layouts, and the one rule that picks.
//!
//! A Put lays its payload out one of two ways, and nothing in any header says
//! which. Without the shared-memory marker in its extension chain the payload
//! is a length and that many bytes. With the marker (`Shm`, body extension id
//! 0x2) it is a count of slices followed by that many elements, each a kind, a
//! length and bytes: upstream's sliced layout, written when the Put carries a
//! shared-memory buffer (`commons/zenoh-codec/src/zenoh/put.rs` @
//! `let codec = Zenoh080Sliced::<u32>::new(ext_shm.is_some());`).
//!
//! `msg_put.scxml` states both and gates them on the chain
//! (`extensions.has(0x2)`), so [`MsgPutOwned`](wz_codecs::msg_put::MsgPutOwned)
//! carries four fields for one payload: `payload_len` and `payload` for the
//! first layout, `slice_count` and `slices` for the second. Exactly one pair is
//! present. Reading or building those four by hand at every site is how the two
//! layouts drift apart, so this module is the one place that knows the rule and
//! every other site goes through it. The encoder refuses a Put whose chain and
//! payload disagree (`CodecError::PresentIfMismatch`), which is the backstop and
//! not the plan.
//!
//! What this module does NOT do is touch a shared-memory segment. A slice of
//! kind [`SLICE_KIND_SHM_PTR`] carries a serialized descriptor, and turning a
//! descriptor into bytes needs the platform's resolver
//! (`wz-runtime-tokio::shm_provider`); [`collect_payload`] takes it as a
//! closure so this crate stays the no_std half.

use alloc::vec::Vec;

use sce_forge_runtime::codec::{CodecError, CodecStorage, SceByteBuf, SceList};
use wz_codecs::msg_put::MsgPutOwned;
use wz_codecs::zbuf_slice::ZbufSliceOwned;

/// A slice whose bytes are payload bytes, as an unsliced Put would carry them
/// (`commons/zenoh-codec/src/core/zbuf.rs` @ `const RAW: u8 = 0;`).
pub const SLICE_KIND_RAW: u16 = 0;

/// A slice whose bytes are a serialized shared-memory buffer descriptor, not
/// payload (`commons/zenoh-codec/src/core/zbuf.rs` @ `const SHM_PTR: u8 = 1;`).
pub const SLICE_KIND_SHM_PTR: u16 = 1;

/// How one Put carries its payload.
#[derive(Debug)]
pub enum PutPayload<'a, S: CodecStorage> {
    /// A length-prefixed byte string: the layout of a Put without the marker.
    Inline(&'a [u8]),
    /// A list of slices: the layout of a Put that carries the marker.
    Sliced(&'a [ZbufSliceOwned<S>]),
}

/// The layout `put` carries. A Put with neither pair populated reads as an empty
/// inline payload, which is what a decoder gives for a zero-length one.
pub fn layout<S: CodecStorage>(put: &MsgPutOwned<S>) -> PutPayload<'_, S> {
    match put.slices.as_ref() {
        Some(slices) => PutPayload::Sliced(SceList::as_slice(slices)),
        None => PutPayload::Inline(
            put.payload
                .as_ref()
                .map_or(&[], |p| SceByteBuf::as_slice(p)),
        ),
    }
}

/// The payload bytes of a Put that uses the inline layout, or `None` for one
/// that is sliced. A caller that has no meaning for a slice (a statistic over
/// payload sizes, a display of the first bytes) asks this and treats `None` as
/// "not plain bytes" rather than guessing at the descriptor.
pub fn inline_bytes<S: CodecStorage>(put: &MsgPutOwned<S>) -> Option<&[u8]> {
    match layout(put) {
        PutPayload::Inline(b) => Some(b),
        PutPayload::Sliced(_) => None,
    }
}

/// Whether `put` uses the sliced layout.
pub fn is_sliced<S: CodecStorage>(put: &MsgPutOwned<S>) -> bool {
    put.slices.is_some()
}

/// A Put that carries `bytes` in the inline layout.
///
/// The header is the bare Put header and every optional field is absent: a
/// caller that needs a timestamp, an encoding or extensions names them and takes
/// the payload fields from here with `..inline(bytes)?`, so no site spells the
/// four payload fields by hand.
pub fn inline<S: CodecStorage>(bytes: &[u8]) -> Result<MsgPutOwned<S>, CodecError> {
    Ok(MsgPutOwned {
        header: 0x01,
        timestamp: None,
        encoding: None,
        extensions: None,
        payload_len: Some(bytes.len() as u64),
        payload: Some(<S::Bytes<256> as SceByteBuf>::from_slice(bytes)?),
        slice_count: None,
        slices: None,
    })
}

/// A Put that carries one shared-memory slice whose bytes are `descriptor`, the
/// serialized buffer descriptor, in the sliced layout.
///
/// The caller owns the other half of the rule: the chain of a sliced Put must
/// carry the marker (`extshm::encode_shm_marker_ext`), because the marker is
/// what the receiver reads to know the payload is sliced.
pub fn shm<S: CodecStorage>(descriptor: &[u8]) -> Result<MsgPutOwned<S>, CodecError> {
    let mut slices = <S::List<ZbufSliceOwned<S>, 4> as SceList<ZbufSliceOwned<S>>>::empty();
    slices.try_push(ZbufSliceOwned {
        kind: SLICE_KIND_SHM_PTR,
        len: descriptor.len() as u64,
        bytes: <S::Bytes<256> as SceByteBuf>::from_slice(descriptor)?,
    })?;
    Ok(MsgPutOwned {
        header: 0x01,
        timestamp: None,
        encoding: None,
        extensions: None,
        payload_len: None,
        payload: None,
        slice_count: Some(1),
        slices: Some(slices),
    })
}

/// Why the payload of a received Put could not be assembled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadFault {
    /// A slice has a kind this node does not know. Upstream defines two; a third
    /// is a peer speaking something newer, and guessing at its bytes would hand
    /// the application data that is not its payload.
    UnknownKind(u16),
    /// A shared-memory slice's descriptor did not resolve: a stale or foreign
    /// segment, no resolver installed, or a descriptor that does not parse.
    Unresolved,
}

/// The bytes a received Put delivers: the inline payload as it is, or the
/// slices in order, a RAW slice contributing its bytes and a shared-memory slice
/// contributing what `resolve` returns for its descriptor.
///
/// This is what upstream's receiver does with a ZBuf of mixed slices: each
/// shared-memory slice becomes the buffer it names, and the payload reads as
/// their concatenation.
pub fn collect_payload<S: CodecStorage>(
    put: &MsgPutOwned<S>,
    mut resolve: impl FnMut(&[u8]) -> Option<Vec<u8>>,
) -> Result<Vec<u8>, PayloadFault> {
    match layout(put) {
        PutPayload::Inline(bytes) => Ok(bytes.to_vec()),
        PutPayload::Sliced(slices) => {
            let mut out = Vec::new();
            for slice in slices {
                let bytes = SceByteBuf::as_slice(&slice.bytes);
                match slice.kind {
                    SLICE_KIND_RAW => out.extend_from_slice(bytes),
                    SLICE_KIND_SHM_PTR => {
                        let resolved = resolve(bytes).ok_or(PayloadFault::Unresolved)?;
                        out.extend_from_slice(&resolved);
                    }
                    other => return Err(PayloadFault::UnknownKind(other)),
                }
            }
            Ok(out)
        }
    }
}

// The witnesses build the marker extension, which lives behind `transport-shm`.
#[cfg(all(test, feature = "transport-shm"))]
mod tests {
    use super::*;
    use sce_forge_runtime::codec::SceCursor;
    use wz_codecs::ext_entry::ExtEntryOwned;
    use wz_codecs::msg_put::MsgPut;

    type Heap = sce_forge_runtime::codec::Heap;

    /// A chain holding the one extension the shared-memory marker is.
    fn marker_chain() -> <Heap as CodecStorage>::List<ExtEntryOwned<Heap>, 16> {
        let mut chain = <<Heap as CodecStorage>::List<ExtEntryOwned<Heap>, 16> as SceList<
            ExtEntryOwned<Heap>,
        >>::empty();
        chain
            .try_push(crate::extshm::encode_shm_marker_ext())
            .expect("one extension fits");
        chain
    }

    /// The shared-memory Put an upstream `z_pub_shm` publisher sent, as it was
    /// read off the wire: the Put header with the extension flag, one unit
    /// extension with id 0x2 and the mandatory bit, then the sliced payload —
    /// one slice, kind SHM_PTR, a six-byte descriptor. wz used to read the
    /// slice count as a payload length and the kind as a payload byte, and the
    /// descriptor as the next message.
    const UPSTREAM_SHM_PUT: [u8; 12] = [
        0x81, // header: mid 0x01, Z
        0x12, // extension: id 0x2, M, unit
        0x01, // slice_count
        0x01, // kind: SHM_PTR
        0x06, // len
        0x35, 0xCA, 0xC3, 0x01, 0x00, 0x00, // descriptor, four VLEs
        0x00,
    ];

    fn decode(bytes: &[u8]) -> Result<MsgPutOwned<Heap>, CodecError> {
        let mut cursor = SceCursor::new(bytes);
        MsgPut::decode(&mut cursor)?.try_into_owned_in::<Heap>()
    }

    #[test]
    fn an_upstream_shm_put_reads_as_one_shm_slice() {
        // The trailing zero is the next message's byte; the Put ends before it.
        let put = decode(&UPSTREAM_SHM_PUT[..11]).expect("the sliced layout decodes");
        assert!(
            is_sliced(&put),
            "the marker in the chain selects the slices"
        );
        assert_eq!(put.payload_len, None, "the inline pair is absent");
        match layout(&put) {
            PutPayload::Sliced(slices) => {
                assert_eq!(slices.len(), 1);
                assert_eq!(slices[0].kind, SLICE_KIND_SHM_PTR);
                assert_eq!(
                    SceByteBuf::as_slice(&slices[0].bytes),
                    &[0x35, 0xCA, 0xC3, 0x01, 0x00, 0x00]
                );
            }
            PutPayload::Inline(_) => panic!("the Put is sliced"),
        }
    }

    #[test]
    fn a_put_without_the_marker_stays_inline() {
        let put = decode(&[0x01, 0x03, b'a', b'b', b'c']).expect("the inline layout decodes");
        assert!(!is_sliced(&put));
        assert_eq!(inline_bytes(&put), Some(&b"abc"[..]));
    }

    #[test]
    fn the_shm_builder_writes_what_upstream_wrote() {
        let descriptor = [0x35, 0xCA, 0xC3, 0x01, 0x00, 0x00];
        let mut put = shm::<Heap>(&descriptor).expect("one slice fits");
        put.header |= 0x80;
        put.extensions = Some(marker_chain());
        let wire = put
            .try_as_borrowed()
            .expect("the slices fit the borrowed view")
            .encode_to_vec()
            .expect("a consistent Put encodes");
        assert_eq!(wire, &UPSTREAM_SHM_PUT[..11]);
    }

    #[test]
    fn an_encoder_refuses_a_chain_and_a_payload_that_disagree() {
        // The marker is in the chain but the payload is the inline pair.
        let mut put = inline::<Heap>(b"abc").expect("inline fits");
        put.header |= 0x80;
        put.extensions = Some(marker_chain());
        assert!(
            put.try_as_borrowed()
                .expect("the inline pair fits the borrowed view")
                .encode_to_vec()
                .is_err(),
            "a chain that says slices follow and a payload that is plain bytes are \
             two descriptions of one wire"
        );
    }

    #[test]
    fn slices_concatenate_in_order_and_an_unknown_kind_is_refused() {
        let mut put = shm::<Heap>(&[0x01]).expect("one slice fits");
        let raw = ZbufSliceOwned::<Heap> {
            kind: SLICE_KIND_RAW,
            len: 2,
            bytes: <<Heap as CodecStorage>::Bytes<256> as SceByteBuf>::from_slice(b"hi")
                .expect("two bytes fit"),
        };
        let slices = put.slices.as_mut().expect("shm() populates the slices");
        slices.try_push(raw).expect("a second slice fits");
        let got = collect_payload(&put, |d| {
            assert_eq!(d, &[0x01], "the resolver sees the descriptor bytes");
            Some(b"SHM".to_vec())
        })
        .expect("both slices resolve");
        assert_eq!(got, b"SHMhi");

        let unresolved = collect_payload(&put, |_| None);
        assert_eq!(unresolved, Err(PayloadFault::Unresolved));

        let mut odd = shm::<Heap>(&[0x01]).expect("one slice fits");
        odd.slices
            .as_mut()
            .expect("populated")
            .try_push(ZbufSliceOwned::<Heap> {
                kind: 7,
                len: 0,
                bytes: <<Heap as CodecStorage>::Bytes<256> as SceByteBuf>::from_slice(&[])
                    .expect("empty fits"),
            })
            .expect("a second slice fits");
        assert_eq!(
            collect_payload(&odd, |_| Some(Vec::new())),
            Err(PayloadFault::UnknownKind(7))
        );
    }
}
