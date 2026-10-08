// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The payload of a Put body: two wire layouts, and the one rule that picks.
//!
//! A Put lays its payload out one of two ways, and nothing in any header says
//! which. Without the shared-memory marker in its extension chain the payload
//! is a length and that many bytes. With the marker (`Shm`, body extension id
//! 0x2, mandatory, unit: the identity `0x12`) it is a count of slices followed
//! by that many elements, each a kind, a length and bytes: upstream's sliced
//! layout, written when the Put carries a shared-memory buffer
//! (`commons/zenoh-codec/src/zenoh/put.rs` @
//! `let codec = Zenoh080Sliced::<u32>::new(ext_shm.is_some());`).
//!
//! `msg_put.scxml` states both and gates them on the chain
//! (`extensions.has(0x12)`, over each entry's header without its continuation
//! flag, which is upstream's `eid`; an extension that shares only the 4-bit id
//! is not the marker and leaves the first layout),
//! so [`MsgPutOwned`](wz_codecs::msg_put::MsgPutOwned)
//! carries four fields for one payload: `payload_len` and `payload` for the
//! first layout, `slice_count` and `slices` for the second. Exactly one pair is
//! present. Reading or building those four by hand at every site is how the two
//! layouts drift apart, so this module is the one place that knows the rule and
//! every other site goes through it. The encoder refuses a Put whose chain and
//! payload disagree (`CodecError::PresentIfMismatch`), which is the backstop and
//! not the plan.
//!
//! What this module does NOT do is touch a shared-memory segment. A slice of
//! kind [`SLICE_KIND_SHM_PTR`](crate::put_payload::SLICE_KIND_SHM_PTR) carries
//! a serialized descriptor, and turning a descriptor into bytes needs the
//! platform's resolver (`wz-runtime-tokio::shm_provider`);
//! [`collect_payload`](crate::put_payload::collect_payload) takes it as a
//! closure so this crate stays the no_std half.

use alloc::vec::Vec;

use sce_forge_runtime::codec::{CodecError, CodecStorage, SceByteBuf, SceList};
use wz_codecs::msg_put::MsgPutOwned;
use wz_codecs::zbuf_slice::ZbufSliceOwned;

/// A slice whose bytes are payload bytes, as an unsliced Put would carry them
/// (`commons/zenoh-codec/src/core/zbuf.rs` @ `const RAW: u8 = 0;`).
pub const SLICE_KIND_RAW: u8 = 0;

/// A slice whose bytes are a serialized shared-memory buffer descriptor, not
/// payload (`commons/zenoh-codec/src/core/zbuf.rs` @ `const SHM_PTR: u8 = 1;`).
pub const SLICE_KIND_SHM_PTR: u8 = 1;

/// How many slices one Put holds: the capacity `msg_put.scxml` gives its
/// `slices` repeat (`max-count="4"`). A count past it is refused by the codec
/// after the element that does not fit has been read, and the dissector, which
/// must refuse the same input, reads this to say where.
pub const MAX_SLICES: usize = 4;

/// The kind of a slice as upstream reads it. The wire carries a varint up to
/// 32 bits wide, which the codec keeps whole; upstream keeps its low byte
/// (`commons/zenoh-codec/src/core/zbuf.rs` @
/// `let kind: u8 = self.codec.read(&mut *reader)?;`), so a kind of `0x101` is
/// a shared-memory slice there and is one here.
pub const fn slice_kind(wire: u32) -> u8 {
    wire as u8
}

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

/// How many payload bytes `put` carries, as upstream's statistics count them:
/// the length of the ZBuf the receiver would hold. An inline payload is its
/// bytes; a RAW slice is its bytes; a shared-memory slice is the length of the
/// buffer its descriptor names, because that buffer, not the descriptor, is
/// what the receiver holds. The descriptor is read, never resolved, so this
/// costs no segment access. A descriptor that does not parse, or a slice kind
/// this node does not know, contributes nothing: there is no length to report
/// for bytes that cannot be read.
pub fn payload_len<S: CodecStorage>(put: &MsgPutOwned<S>) -> usize {
    match layout(put) {
        PutPayload::Inline(bytes) => bytes.len(),
        PutPayload::Sliced(slices) => slices_len(slices),
    }
}

/// How many payload bytes a list of slices carries, counted as [`payload_len`]
/// counts a sliced Put's. A Query's value in the sliced layout is the same list
/// of slices and is counted by the same rule (R3044).
pub fn slices_len<S: CodecStorage>(slices: &[ZbufSliceOwned<S>]) -> usize {
    slices
        .iter()
        .map(|slice| {
            let bytes = SceByteBuf::as_slice(&slice.bytes);
            match slice_kind(slice.kind) {
                SLICE_KIND_RAW => bytes.len(),
                SLICE_KIND_SHM_PTR => shm_slice_len(bytes),
                _ => 0,
            }
        })
        .sum()
}

/// The buffer length a shared-memory slice's descriptor names, or `0` when the
/// descriptor does not parse. Without `transport-shm` this node has no reader
/// for descriptors, and such a slice is dropped before any size is asked.
#[cfg(feature = "transport-shm")]
fn shm_slice_len(descriptor: &[u8]) -> usize {
    crate::extshm::decode_shm_descriptor(descriptor).map_or(0, |d| d.data_len as usize)
}

#[cfg(not(feature = "transport-shm"))]
fn shm_slice_len(_descriptor: &[u8]) -> usize {
    0
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
    Ok(MsgPutOwned {
        header: 0x01,
        timestamp: None,
        encoding: None,
        extensions: None,
        payload_len: None,
        payload: None,
        slice_count: Some(1),
        slices: Some(shm_slices::<S>(descriptor)?),
    })
}

/// The list of slices that carries one shared-memory buffer: a single slice of
/// kind `SHM_PTR` whose bytes are `descriptor`. A Put's payload and the value of a
/// Query are the same list on the wire (`Zenoh080Sliced`), so both take it from
/// here and no site spells a slice by hand (R3048).
pub fn shm_slices<S: CodecStorage>(
    descriptor: &[u8],
) -> Result<S::List<ZbufSliceOwned<S>, 4>, CodecError> {
    let mut slices = <S::List<ZbufSliceOwned<S>, 4> as SceList<ZbufSliceOwned<S>>>::empty();
    slices.try_push(ZbufSliceOwned {
        kind: u32::from(SLICE_KIND_SHM_PTR),
        len: descriptor.len() as u64,
        bytes: <S::Bytes<256> as SceByteBuf>::from_slice(descriptor)?,
    })?;
    Ok(slices)
}

/// Why the payload of a received Put could not be assembled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadFault {
    /// A slice has a kind this node does not know. Upstream defines two; a third
    /// is a peer speaking something newer, and guessing at its bytes would hand
    /// the application data that is not its payload.
    UnknownKind(u8),
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
    resolve: impl FnMut(&[u8]) -> Option<Vec<u8>>,
) -> Result<Vec<u8>, PayloadFault> {
    match layout(put) {
        PutPayload::Inline(bytes) => Ok(bytes.to_vec()),
        PutPayload::Sliced(slices) => collect_slices(slices, resolve),
    }
}

/// The bytes of a list of slices, each a RAW slice contributing its bytes and a
/// shared-memory slice contributing what `resolve` returns for its descriptor.
///
/// R3044 -- split out of [`collect_payload`] because a Put is not the only place
/// upstream writes a payload as slices: the value of a query is the same list
/// after the same marker, and what a slice is owed does not depend on which
/// message it arrived in.
pub fn collect_slices<S: CodecStorage>(
    slices: &[ZbufSliceOwned<S>],
    resolve: impl FnMut(&[u8]) -> Option<Vec<u8>>,
) -> Result<Vec<u8>, PayloadFault> {
    Ok(match walk_slices(slices, resolve, Vec::as_slice)? {
        Walked::Whole(bytes) | Walked::Joined(bytes) => bytes,
    })
}

/// [`collect_slices`] whose result is the shareable type: a list that is ONE shared-memory
/// slice is returned as the buffer `resolve` gave back, a resolver that keeps the segment
/// mapped handing the application the page and not a copy of it, and the reference the
/// descriptor carried goes back when the last range of it drops (R3061). Several slices,
/// or a raw one, are joined into a buffer of their own, as [`collect_wire_payload`] does
/// for a Put.
///
/// The value of a query was the one list of slices this module collected only as bytes,
/// so a queryable that was sent a chunk was handed a copy of it; upstream hands it the
/// buffer.
pub fn collect_slices_shared<S: CodecStorage>(
    slices: &[ZbufSliceOwned<S>],
    resolve: impl FnMut(&[u8]) -> Option<crate::link::RxBytes>,
) -> Result<crate::link::RxBytes, PayloadFault> {
    Ok(
        match walk_slices(slices, resolve, crate::link::RxBytes::as_slice)? {
            Walked::Whole(bytes) => bytes,
            Walked::Joined(bytes) => crate::link::RxBytes::from(bytes),
        },
    )
}

/// What a walk of a list of slices produced.
enum Walked<R> {
    /// The list was ONE shared-memory slice, and this is what its descriptor
    /// resolved to, handed on as it is: a resolver that returns a view of the
    /// segment is not copied out of here.
    Whole(R),
    /// More than one slice, or a RAW one: the bytes of each, in order, in a buffer
    /// of their own. Joining slices is a new buffer and is the copy upstream's
    /// `ZBuf` avoids by holding the slices apart, which a contiguous payload
    /// cannot.
    Joined(Vec<u8>),
}

/// The walk every collector of slices shares, so what a slice is owed is one rule
/// and not one per return type (R3049). `view` reads the bytes out of what a
/// resolver returned.
///
/// The FIRST fault is the one reported, but the walk goes on after it:
/// R3038 -- the resolver of a shared-memory slice gives back the reference the
/// sender took for this receiver, so a slice that is never offered to it is a
/// reference nobody releases. Upstream maps every slice of a message when it
/// arrives and drops them all with the message, whether or not the message is then
/// delivered.
fn walk_slices<S: CodecStorage, R>(
    slices: &[ZbufSliceOwned<S>],
    mut resolve: impl FnMut(&[u8]) -> Option<R>,
    view: impl Fn(&R) -> &[u8],
) -> Result<Walked<R>, PayloadFault> {
    let mut joined = Vec::new();
    let mut whole = None;
    let mut fault = None;
    let only_one = slices.len() == 1;
    for slice in slices {
        let bytes = SceByteBuf::as_slice(&slice.bytes);
        match slice_kind(slice.kind) {
            SLICE_KIND_RAW => {
                if fault.is_none() {
                    joined.extend_from_slice(bytes);
                }
            }
            SLICE_KIND_SHM_PTR => match resolve(bytes) {
                Some(resolved) => {
                    if fault.is_none() {
                        if only_one {
                            whole = Some(resolved);
                        } else {
                            joined.extend_from_slice(view(&resolved));
                        }
                    }
                }
                None => {
                    fault.get_or_insert(PayloadFault::Unresolved);
                }
            },
            other => {
                fault.get_or_insert(PayloadFault::UnknownKind(other));
            }
        }
    }
    match (fault, whole) {
        (Some(fault), _) => Err(fault),
        (None, Some(whole)) => Ok(Walked::Whole(whole)),
        (None, None) => Ok(Walked::Joined(joined)),
    }
}

/// [`collect_payload`] for a Put the receive path decoded, returning the bytes as
/// a value that can stay shared.
///
/// A Put in the inline layout holds its payload as a field of the wire profile
/// ([`WireStorage`](crate::wire::WireStorage)), which on an AP build is a range of
/// the frame it was decoded from; that field IS what the sample should hold, so
/// it is handed on as it is (a second reference to the frame's storage, no copy).
/// A sliced Put has to be assembled from its slices, which is a new buffer and the
/// same copy [`collect_payload`] makes. Off `rx-shared-bytes` there is no sharing
/// and this is [`collect_payload`] moved into the shareable type.
///
/// R3049 -- `resolve` returns the bytes a descriptor names as the shareable type
/// too, so a Put whose payload is ONE shared-memory buffer is delivered as the
/// buffer the resolver returned: a resolver that keeps the segment mapped and
/// returns a range of it hands the application the page and not a copy of it, and
/// the reference the descriptor carried goes back when the last range of it
/// drops. Several slices are still joined into a buffer of their own.
pub fn collect_wire_payload(
    put: &MsgPutOwned<crate::wire::WireStorage>,
    resolve: impl FnMut(&[u8]) -> Option<crate::link::RxBytes>,
) -> Result<crate::link::RxBytes, PayloadFault> {
    #[cfg(feature = "rx-shared-bytes")]
    if put.slices.is_none() {
        return Ok(match put.payload.as_ref() {
            Some(field) => field.as_rx_bytes().clone(),
            None => crate::link::RxBytes::from(Vec::new()),
        });
    }
    match layout(put) {
        PutPayload::Inline(bytes) => Ok(crate::link::RxBytes::from(bytes.to_vec())),
        PutPayload::Sliced(slices) => Ok(
            match walk_slices(slices, resolve, crate::link::RxBytes::as_slice)? {
                Walked::Whole(bytes) => bytes,
                Walked::Joined(bytes) => crate::link::RxBytes::from(bytes),
            },
        ),
    }
}

/// What a node that FORWARDS a Put makes of one shared-memory slice of it, for one peer.
#[cfg(feature = "transport-shm")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Relayed {
    /// The peer reads shared memory: the slice stays a descriptor, and these are its serialized
    /// bytes. They are the descriptor of the reference taken for THIS peer, which is the received
    /// one only when the chunk is the same.
    Descriptor(Vec<u8>),
    /// The peer cannot read the chunk: the slice becomes these payload bytes.
    Bytes(Vec<u8>),
}

/// Why a Put could not be forwarded to a peer.
#[cfg(feature = "transport-shm")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayFault {
    /// A shared-memory slice the forwarder holds no chunk for (stale, foreign, or never held).
    /// Upstream drops such a message at the receiving transport; nothing is sent in its place.
    Unrelayable,
    /// A slice of a kind this node does not know.
    UnknownKind(u8),
    /// The forwarded payload does not fit the storage of the wire profile.
    Unrepresentable,
}

/// Re-express the shared-memory slices of a Put for ONE peer, in place: upstream's
/// `map_to_partner` (`io/zenoh-transport/src/common/shm/interop.rs` @ `fn map_to_partner<`),
/// which a router runs on every message for every link it sends it on.
///
/// `decide` is offered the descriptor bytes of EACH shared-memory slice, in order, exactly once,
/// whatever became of the slices before it (see `walk_slices` for why: a decision may take a
/// reference, and a slice that is never offered is a reference nobody gives back). It answers
/// [`Relayed::Descriptor`] to send the slice on as a descriptor and [`Relayed::Bytes`] to send
/// what the chunk holds, and `None` for a slice it holds nothing for, which fails the whole Put
/// and leaves it untouched.
///
/// When no shared-memory slice is left, the Put is not sliced any more and is rewritten as the
/// plain layout (a length and bytes) with the marker out of its extension chain: a peer that
/// cannot read shared memory is never sent the marker, because its reader would take the first
/// bytes of the payload for a count of slices. The chain keeps its other entries, with the
/// continuation flags renormalised over what is left, and a chain that is empty is absent and
/// takes the Put header's `Z` flag with it.
#[cfg(feature = "transport-shm")]
pub fn relay_shm_slices(
    put: &mut MsgPutOwned<crate::wire::WireStorage>,
    mut decide: impl FnMut(&[u8]) -> Option<Relayed>,
) -> Result<(), RelayFault> {
    let Some(slices) = put.slices.as_ref() else {
        return Ok(());
    };
    let mut remade: Vec<(u8, Vec<u8>)> = Vec::new();
    let mut fault = None;
    for slice in SceList::as_slice(slices) {
        let bytes = SceByteBuf::as_slice(&slice.bytes);
        match slice_kind(slice.kind) {
            SLICE_KIND_RAW => remade.push((SLICE_KIND_RAW, bytes.to_vec())),
            SLICE_KIND_SHM_PTR => match decide(bytes) {
                Some(Relayed::Descriptor(descriptor)) => {
                    remade.push((SLICE_KIND_SHM_PTR, descriptor));
                }
                Some(Relayed::Bytes(payload)) => remade.push((SLICE_KIND_RAW, payload)),
                None => {
                    fault.get_or_insert(RelayFault::Unrelayable);
                }
            },
            other => {
                fault.get_or_insert(RelayFault::UnknownKind(other));
            }
        }
    }
    if let Some(fault) = fault {
        return Err(fault);
    }
    let unrepresentable = |_| RelayFault::Unrepresentable;
    if remade.iter().any(|(kind, _)| *kind == SLICE_KIND_SHM_PTR) {
        type Slices = <crate::wire::WireStorage as CodecStorage>::List<
            ZbufSliceOwned<crate::wire::WireStorage>,
            4,
        >;
        let mut list = <Slices as SceList<_>>::empty();
        for (kind, bytes) in &remade {
            list.try_push(ZbufSliceOwned {
                kind: u32::from(*kind),
                len: bytes.len() as u64,
                bytes: crate::wire::wire_bytes(bytes).map_err(unrepresentable)?,
            })
            .map_err(unrepresentable)?;
        }
        put.slice_count = Some(remade.len() as u32);
        put.slices = Some(list);
        return Ok(());
    }
    let joined: Vec<u8> = remade.into_iter().flat_map(|(_, bytes)| bytes).collect();
    put.payload_len = Some(joined.len() as u64);
    put.payload = Some(crate::wire::wire_bytes(&joined).map_err(unrepresentable)?);
    put.slice_count = None;
    put.slices = None;
    remove_shm_marker(put).map_err(unrepresentable)
}

/// Take the shared-memory marker out of a Put's extension chain, renormalise the continuation
/// flags over the entries that are left, and drop the chain, and the header's `Z` flag, when
/// nothing is left. A Put without the marker is left as it is.
#[cfg(feature = "transport-shm")]
fn remove_shm_marker(put: &mut MsgPutOwned<crate::wire::WireStorage>) -> Result<(), CodecError> {
    let Some(chain) = put.extensions.as_ref() else {
        return Ok(());
    };
    let marker =
        crate::ext_header::ext_eid(crate::extshm::SHM_BODY_EXT_ID | crate::ext_header::EXT_FLAG_M);
    let mut kept: Vec<_> = SceList::as_slice(chain)
        .iter()
        .filter(|entry| crate::ext_header::ext_eid(entry.header) != marker)
        .cloned()
        .collect();
    if kept.len() == SceList::as_slice(chain).len() {
        return Ok(());
    }
    if kept.is_empty() {
        put.extensions = None;
        put.header &= !crate::ext_header::EXT_FLAG_Z;
        return Ok(());
    }
    crate::ext_nodeid::apply_chain_z_bits(&mut kept);
    type Chain = <crate::wire::WireStorage as CodecStorage>::List<
        wz_codecs::ext_entry::ExtEntryOwned<crate::wire::WireStorage>,
        16,
    >;
    let mut list = <Chain as SceList<_>>::empty();
    for entry in kept {
        list.try_push(entry)?;
    }
    put.extensions = Some(list);
    Ok(())
}

/// The priority band a received message was sent at, as the index of the handoff
/// counter a shared-memory sender names for it: the QoS extension's low three bits,
/// and the default priority when the message carries none, which is how upstream
/// reads `ext_qos.get_priority()` for the same purpose.
///
/// Independent of the `pubsub-qos` projection on purpose: that feature decides
/// whether a SAMPLE carries a QoS, and an acknowledgement owed to the sender does
/// not depend on whether anyone here reads the QoS. It is read from the message's
/// OWN extension chain, which is the push's for a push and the response's for a
/// reply, so one function serves both.
pub fn priority_band<S: CodecStorage>(
    extensions: &[wz_codecs::ext_entry::ExtEntryOwned<S>],
) -> usize {
    crate::sample::extract_qos(extensions)
        .map_or(crate::qos::Priority::DEFAULT, |qos| qos.priority())
        .wire_byte() as usize
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
                assert_eq!(slice_kind(slices[0].kind), SLICE_KIND_SHM_PTR);
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
            kind: u32::from(SLICE_KIND_RAW),
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

    /// R3038 -- a slice that fails does not hide the slices after it from the
    /// resolver. The resolver of a shared-memory slice gives back the reference the
    /// sender took for this receiver, so every descriptor of a message must be
    /// offered to it once, as upstream's receiver maps every slice of a message
    /// before it decides anything about delivery. The fault reported is still the
    /// FIRST one.
    #[test]
    fn every_shm_slice_reaches_the_resolver_after_one_fails() {
        use alloc::vec;

        let mut put = shm::<Heap>(&[0x01]).expect("one slice fits");
        let slices = put.slices.as_mut().expect("shm() populates the slices");
        for descriptor in [&[0x02u8][..], &[0x03u8][..]] {
            slices
                .try_push(ZbufSliceOwned::<Heap> {
                    kind: u32::from(SLICE_KIND_SHM_PTR),
                    len: 1,
                    bytes: <<Heap as CodecStorage>::Bytes<256> as SceByteBuf>::from_slice(
                        descriptor,
                    )
                    .expect("one byte fits"),
                })
                .expect("a further slice fits");
        }

        // The FIRST of three fails; the other two must still be offered.
        let mut offered = Vec::new();
        let result = collect_payload(&put, |d| {
            offered.push(d.to_vec());
            if d == [0x01] {
                None
            } else {
                Some(b"x".to_vec())
            }
        });
        assert_eq!(result, Err(PayloadFault::Unresolved));
        assert_eq!(
            offered,
            [vec![0x01], vec![0x02], vec![0x03]],
            "every shared-memory slice reached the resolver, in order"
        );

        // An unknown kind in the middle: the fault is ITS, and the shared-memory
        // slice behind it is still offered.
        let mut odd = shm::<Heap>(&[0x09]).expect("one slice fits");
        let slices = odd.slices.as_mut().expect("populated");
        slices
            .try_push(ZbufSliceOwned::<Heap> {
                kind: 7,
                len: 0,
                bytes: <<Heap as CodecStorage>::Bytes<256> as SceByteBuf>::from_slice(&[])
                    .expect("empty fits"),
            })
            .expect("fits");
        slices
            .try_push(ZbufSliceOwned::<Heap> {
                kind: u32::from(SLICE_KIND_SHM_PTR),
                len: 1,
                bytes: <<Heap as CodecStorage>::Bytes<256> as SceByteBuf>::from_slice(&[0x0a])
                    .expect("one byte fits"),
            })
            .expect("fits");
        let mut offered = Vec::new();
        let result = collect_payload(&odd, |d| {
            offered.push(d.to_vec());
            Some(Vec::new())
        });
        assert_eq!(result, Err(PayloadFault::UnknownKind(7)));
        assert_eq!(
            offered,
            [vec![0x09], vec![0x0a]],
            "the shared-memory slice behind the odd one was offered"
        );
    }

    /// Upstream reads the kind as a bounded-u32 varint and keeps its low byte,
    /// so `0x101` is a shared-memory slice there (`let kind: u8 = ...`). The
    /// codec keeps the whole 32 bits and the host takes the low byte, which
    /// must give the same answer; a varint wider than 32 bits is refused by
    /// the codec as upstream's bounded read refuses it.
    #[test]
    fn a_kind_is_its_low_byte_as_upstream_reads_it() {
        assert_eq!(slice_kind(0x101), SLICE_KIND_SHM_PTR);
        assert_eq!(slice_kind(0x100), SLICE_KIND_RAW);
        // header with the marker, one slice, kind 0x81 0x02 (= 0x101), len 1,
        // one descriptor byte.
        let wire = [0x81, 0x12, 0x01, 0x81, 0x02, 0x01, 0x35];
        let put = decode(&wire).expect("a 32-bit kind decodes");
        match layout(&put) {
            PutPayload::Sliced(slices) => {
                assert_eq!(slices[0].kind, 0x101);
                assert_eq!(slice_kind(slices[0].kind), SLICE_KIND_SHM_PTR);
            }
            PutPayload::Inline(_) => panic!("the Put is sliced"),
        }
        // A kind needing 33 bits (five varint bytes, top group 0x10) is
        // refused by the bounded read, not truncated.
        let wide = [0x81, 0x12, 0x01, 0x80, 0x80, 0x80, 0x80, 0x10, 0x01, 0x35];
        assert!(decode(&wide).is_err());
    }

    /// The statistics size of a Put is the length of the buffer the receiver
    /// holds: for a shared-memory slice that is the length its descriptor
    /// names (the first varint of the upstream descriptor, `0x35`, is 53), not
    /// the six bytes of descriptor.
    #[test]
    fn payload_len_counts_the_buffer_a_slice_names_not_its_descriptor() {
        let inline_put = decode(&[0x01, 0x03, b'a', b'b', b'c']).expect("inline decodes");
        assert_eq!(payload_len(&inline_put), 3);

        let shm_put = decode(&UPSTREAM_SHM_PUT[..11]).expect("the sliced layout decodes");
        assert_eq!(payload_len(&shm_put), 53);

        let mut mixed = shm::<Heap>(&[0x35, 0xCA, 0xC3, 0x01, 0x00, 0x00]).expect("one slice");
        mixed
            .slices
            .as_mut()
            .expect("shm() populates the slices")
            .try_push(ZbufSliceOwned::<Heap> {
                kind: u32::from(SLICE_KIND_RAW),
                len: 2,
                bytes: <<Heap as CodecStorage>::Bytes<256> as SceByteBuf>::from_slice(b"hi")
                    .expect("two bytes fit"),
            })
            .expect("a second slice fits");
        assert_eq!(payload_len(&mixed), 55, "the slices add up in the receiver");

        let garbage = shm::<Heap>(&[0x80]).expect("one slice fits");
        assert_eq!(
            payload_len(&garbage),
            0,
            "a descriptor that does not parse has no length to report"
        );
    }
}

// The relay rewrites the Put of the wire profile, so these build it in that storage.
#[cfg(all(test, feature = "transport-shm"))]
mod relay_tests {
    use super::*;
    use crate::wire::WireStorage;
    use alloc::vec;
    use wz_codecs::ext_entry::{ExtEntryOwned, ExtEntryOwnedVariant};
    use wz_codecs::ext_unit::ExtUnit;

    type Chain = <WireStorage as CodecStorage>::List<ExtEntryOwned<WireStorage>, 16>;

    fn slice(kind: u8, bytes: &[u8]) -> ZbufSliceOwned<WireStorage> {
        ZbufSliceOwned {
            kind: u32::from(kind),
            len: bytes.len() as u64,
            bytes: crate::wire::wire_bytes(bytes).expect("fits"),
        }
    }

    /// A Put as a router receives one: sliced, with the marker the only entry of its chain.
    fn received(slices: &[(u8, &[u8])]) -> MsgPutOwned<WireStorage> {
        let mut put = shm::<WireStorage>(slices[0].1).expect("one slice fits");
        let list = put.slices.as_mut().expect("populated");
        // `shm` made the first slice SHM_PTR; make it what the caller said.
        *list = <<WireStorage as CodecStorage>::List<ZbufSliceOwned<WireStorage>, 4> as SceList<
            _,
        >>::empty();
        for (kind, bytes) in slices {
            list.try_push(slice(*kind, bytes)).expect("a slice fits");
        }
        put.slice_count = Some(slices.len() as u32);
        put.header |= 0x80;
        let mut chain = <Chain as SceList<_>>::empty();
        chain
            .try_push(crate::extshm::encode_shm_marker_ext())
            .expect("fits");
        put.extensions = Some(chain);
        put
    }

    fn sliced(put: &MsgPutOwned<WireStorage>) -> Vec<(u8, Vec<u8>)> {
        match layout(put) {
            PutPayload::Sliced(slices) => slices
                .iter()
                .map(|s| (slice_kind(s.kind), SceByteBuf::as_slice(&s.bytes).to_vec()))
                .collect(),
            PutPayload::Inline(_) => panic!("the Put is not sliced"),
        }
    }

    #[test]
    fn a_descriptor_kept_leaves_the_put_sliced_and_marked() {
        let mut put = received(&[(SLICE_KIND_SHM_PTR, &[1, 2, 3])]);
        relay_shm_slices(&mut put, |descriptor| {
            assert_eq!(descriptor, [1, 2, 3], "the slice is offered as it came");
            Some(Relayed::Descriptor(vec![9, 9]))
        })
        .expect("relayed");
        assert_eq!(
            sliced(&put),
            [(SLICE_KIND_SHM_PTR, vec![9, 9])],
            "the descriptor of the reference taken for THIS peer"
        );
        assert!(crate::extshm::body_has_shm_marker(SceList::as_slice(
            put.extensions.as_ref().expect("the chain stays")
        )));
        assert_ne!(put.header & 0x80, 0, "the chain still needs its Z flag");
        assert_eq!(
            put.slices.as_ref().map(|s| SceList::as_slice(s)[0].len),
            Some(2)
        );
    }

    #[test]
    fn bytes_for_the_only_slice_make_the_plain_layout_without_the_marker() {
        let mut put = received(&[(SLICE_KIND_SHM_PTR, &[1, 2, 3])]);
        relay_shm_slices(&mut put, |_| Some(Relayed::Bytes(b"payload".to_vec()))).expect("relayed");
        assert!(!is_sliced(&put), "no shared-memory slice is left");
        assert_eq!(inline_bytes(&put), Some(&b"payload"[..]));
        assert_eq!(put.payload_len, Some(7));
        assert_eq!(put.slice_count, None);
        assert!(put.extensions.is_none(), "an empty chain is an absent one");
        assert_eq!(put.header & 0x80, 0, "and it takes the Z flag with it");
        assert_eq!(
            put,
            inline::<WireStorage>(b"payload").expect("inline fits"),
            "exactly the Put the plain builder makes, field for field"
        );
    }

    #[test]
    fn the_other_extensions_survive_with_the_continuation_flag_renormalised() {
        let mut put = received(&[(SLICE_KIND_SHM_PTR, &[1])]);
        let other = ExtEntryOwned::<WireStorage> {
            header: 0x04 | crate::ext_header::EXT_FLAG_Z,
            body: ExtEntryOwnedVariant::CodecZenohExtUnit(ExtUnit::default()),
        };
        let mut chain = <Chain as SceList<_>>::empty();
        chain.try_push(other).expect("fits");
        chain
            .try_push(crate::extshm::encode_shm_marker_ext())
            .expect("fits");
        put.extensions = Some(chain);
        relay_shm_slices(&mut put, |_| Some(Relayed::Bytes(vec![7]))).expect("relayed");
        let left = SceList::as_slice(put.extensions.as_ref().expect("one entry is left"));
        assert_eq!(left.len(), 1);
        assert_eq!(
            left[0].header, 0x04,
            "the entry that is now last ends the chain: its continuation flag is gone"
        );
        assert_ne!(
            put.header & 0x80,
            0,
            "a chain that remains keeps the Z flag"
        );
        assert!(!crate::extshm::body_has_shm_marker(left));
    }

    #[test]
    fn slices_that_become_bytes_join_in_order_around_a_raw_one() {
        let mut put = received(&[
            (SLICE_KIND_SHM_PTR, &[1]),
            (SLICE_KIND_RAW, b"hi"),
            (SLICE_KIND_SHM_PTR, &[2]),
        ]);
        relay_shm_slices(&mut put, |d| {
            Some(Relayed::Bytes(if d == [1] {
                b"A".to_vec()
            } else {
                b"B".to_vec()
            }))
        })
        .expect("relayed");
        assert_eq!(inline_bytes(&put), Some(&b"AhiB"[..]));
    }

    #[test]
    fn one_kept_and_one_sent_as_bytes_stays_sliced_with_a_raw_slice() {
        let mut put = received(&[(SLICE_KIND_SHM_PTR, &[1]), (SLICE_KIND_SHM_PTR, &[2])]);
        relay_shm_slices(&mut put, |d| {
            Some(if d == [1] {
                Relayed::Descriptor(vec![8])
            } else {
                Relayed::Bytes(b"raw".to_vec())
            })
        })
        .expect("relayed");
        assert_eq!(
            sliced(&put),
            [
                (SLICE_KIND_SHM_PTR, vec![8]),
                (SLICE_KIND_RAW, b"raw".to_vec())
            ]
        );
        assert_eq!(put.slice_count, Some(2));
        assert!(crate::extshm::body_has_shm_marker(SceList::as_slice(
            put.extensions
                .as_ref()
                .expect("a descriptor is left, so is the marker")
        )));
    }

    /// A slice the forwarder holds nothing for fails the whole Put and leaves it as it was, and
    /// every slice behind it is still offered, because a decision may take a reference.
    #[test]
    fn a_refused_slice_fails_the_put_untouched_and_every_slice_is_offered() {
        let mut put = received(&[
            (SLICE_KIND_SHM_PTR, &[1]),
            (SLICE_KIND_SHM_PTR, &[2]),
            (SLICE_KIND_SHM_PTR, &[3]),
        ]);
        let before = put.clone();
        let mut offered = Vec::new();
        let result = relay_shm_slices(&mut put, |d| {
            offered.push(d.to_vec());
            (d != [1]).then(|| Relayed::Bytes(vec![0]))
        });
        assert_eq!(result, Err(RelayFault::Unrelayable));
        assert_eq!(offered, [vec![1], vec![2], vec![3]]);
        assert_eq!(put, before, "nothing was rewritten");
    }

    #[test]
    fn an_unknown_kind_fails_the_put_and_the_slice_behind_it_is_still_offered() {
        let mut put = received(&[(7, &[]), (SLICE_KIND_SHM_PTR, &[2])]);
        let before = put.clone();
        let mut offered = Vec::new();
        let result = relay_shm_slices(&mut put, |d| {
            offered.push(d.to_vec());
            Some(Relayed::Bytes(vec![0]))
        });
        assert_eq!(result, Err(RelayFault::UnknownKind(7)));
        assert_eq!(offered, [vec![2]]);
        assert_eq!(put, before);
    }

    #[test]
    fn an_inline_put_is_offered_to_no_one() {
        let mut put = inline::<WireStorage>(b"abc").expect("inline fits");
        let before = put.clone();
        relay_shm_slices(&mut put, |_| {
            panic!("an inline Put has no slice to decide on")
        })
        .expect("nothing to do");
        assert_eq!(put, before);
    }
}
