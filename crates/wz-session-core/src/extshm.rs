// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! SSOT for the wz shared-memory (SHM) DESCRIPTOR + the Put-body `ext_shm`
//! marker (`transport-shm`) — the no_std half of the scoped same-host SHM
//! transport.
//!
//! zenoh sends an SHM payload zero-copy by putting a DESCRIPTOR on the wire
//! (`commons/zenoh-codec/src/core/shm.rs:65-82` `ShmBufInfo`: data_len + a
//! `MetadataDescriptor{id,index}` + generation) in place of the payload bytes,
//! and tags the Put body with a UNIT `ext_shm` extension
//! (`commons/zenoh-protocol/src/zenoh/put.rs:73` `Shm = zextunit!(0x2, true)` —
//! body ext id 0x2, the MANDATORY bit set so a non-SHM peer rejects rather than
//! mis-reads the descriptor as data). The receiver mmaps the segment and reads
//! the payload directly from /dev/shm
//! (`io/zenoh-transport/src/common/shm/interop.rs` @ `fn supports_protocol`;
//! 1.10.0 replaced the flat `zenoh-transport/src/shm.rs` @ REMOVED
//! with `common/shm/`).
//!
//! This module is the no_std SHM machinery: the descriptor type + its VLE codec,
//! the 0x2 Put-body marker codec, and the [`ShmResolver`](crate::extshm::ShmResolver)
//! trait seam. The actual
//! POSIX segment (create / mmap / open) is `std` (mmap = libc), so it lives in
//! `wz-runtime-tokio::shm_provider` behind this trait — the same no_std-core /
//! AP-runtime split as the tls / quic config. R2862 — the descriptor is
//! upstream's four-field `ShmBufInfo`, addressing a header slot in a metadata
//! segment rather than a data segment directly (see
//! [`ShmDescriptor`](crate::extshm::ShmDescriptor)). The
//! receiver still copies the bytes out of the mmap into the owned Sample payload
//! (wz's Sample is an owned `Vec`, so the wire is zero-copy but the local Sample
//! is a single copy off the shared page — the bounded scoped characteristic).
//!
//! R3a lands the codec + trait (inert: `is_shm` is always false, so nothing is
//! emitted / resolved on the wire); the live TX swap, the RX resolver wiring, and
//! the Z_EXT_SHM 0x2 ESTABLISHMENT challenge handshake (a DIFFERENT 0x2 — the
//! init/open ext space, not this body ext space) are R3b.

use alloc::vec::Vec;
use wz_codecs::ext_entry::{ExtEntryOwned, ExtEntryOwnedVariant};
use wz_codecs::ext_unit::ExtUnit;

use crate::ext_header::EXT_FLAG_M;
use crate::vle::{encode_vle_u64_into, read_vle_u64};
#[cfg(feature = "session-extshm")]
use sce_forge_runtime::codec::CodecError;
use sce_forge_runtime::codec::CodecStorage;
#[cfg(feature = "session-extshm")]
use wz_codecs::ext_zbuf::ExtZbufOwned;

/// The Put-body `ext_shm` marker id — zenoh `put.rs:73` `zextunit!(0x2, true)`.
/// Body ext id 0x2 (the Put / Del network-message body ext space, where wz also
/// carries 0x1 source_info + 0x3 attachment — 0x2 was unoccupied). DISTINCT from
/// the establishment 0x2 Shm ext (the Init / Open id space); a body ext and an
/// establishment ext share the numeric value but never the carrier.
/// R311y597 — derives from the unconditional table rather than restating the
/// value, because the dissector needs the same id from a build that does not
/// select `transport-shm`.
pub const SHM_BODY_EXT_ID: u8 = crate::ext_header::body_ext_id::SHM;

/// The wire stand-in for an SHM-backed payload: upstream's `ShmBufInfo`
/// (`commons/zenoh-shm/src/lib.rs` @ `pub struct ShmBufInfo {`).
///
/// R2862 — FOUR fields, as upstream writes them. Until this round wz put a
/// single `segment_id` where upstream puts a `MetadataDescriptor{id, index}`,
/// so its descriptor was THREE varints against upstream's four: a zenoh
/// receiver read wz's segment id as the metadata segment id, wz's generation as
/// the slot index, and ran out of bytes. SHM ESTABLISHMENT interoperated while
/// the PAYLOAD could not, and the atom's "no pool / watchdog / generation"
/// residual was downstream of that missing metadata layer.
///
/// * `data_len` — the payload's bytes (upstream `NonZeroUsize`, so 0 is not a
///   descriptor);
/// * `metadata_id` / `metadata_index` — the metadata SEGMENT and the header
///   slot within it (`commons/zenoh-shm/src/metadata/descriptor.rs` @
///   `pub type MetadataSegmentID = u16;`), where the chunk's data segment,
///   offset and length actually live;
/// * `generation` — the slot's generation when the buffer was sent; a receiver
///   that finds another in the header refuses, because the slot was reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShmDescriptor {
    pub data_len: u32,
    pub metadata_id: u16,
    pub metadata_index: u16,
    pub generation: u32,
}

/// Encode the descriptor as the Put payload stand-in, in upstream's field
/// order (`commons/zenoh-codec/src/core/shm.rs` @
/// `impl<W> WCodec<&ShmBufInfo, &mut W> for Zenoh080`): `VLE(data_len) ++
/// VLE(metadata.id) ++ VLE(metadata.index) ++ VLE(generation)`. Uses the
/// [`crate::vle`] SSOT, which is upstream's integer codec.
pub fn encode_shm_descriptor(d: &ShmDescriptor) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    encode_vle_u64_into(&mut out, d.data_len as u64);
    encode_vle_u64_into(&mut out, d.metadata_id as u64);
    encode_vle_u64_into(&mut out, d.metadata_index as u64);
    encode_vle_u64_into(&mut out, d.generation as u64);
    out
}

/// Decode a descriptor from a Put payload field that carried the `ext_shm`
/// marker. `None` on truncation, on a `data_len` of 0 (upstream reads it as a
/// `NonZeroUsize` and refuses 0), or on a value past its field's width — a
/// malformed peer, which the caller rejects.
pub fn decode_shm_descriptor(bytes: &[u8]) -> Option<ShmDescriptor> {
    let (data_len, n0) = read_vle_u64(bytes)?;
    let (metadata_id, n1) = read_vle_u64(bytes.get(n0..)?)?;
    let (metadata_index, n2) = read_vle_u64(bytes.get(n0 + n1..)?)?;
    let (generation, _n3) = read_vle_u64(bytes.get(n0 + n1 + n2..)?)?;
    if data_len == 0 {
        return None;
    }
    Some(ShmDescriptor {
        data_len: u32::try_from(data_len).ok()?,
        metadata_id: u16::try_from(metadata_id).ok()?,
        metadata_index: u16::try_from(metadata_index).ok()?,
        generation: u32::try_from(generation).ok()?,
    })
}

/// Build the Put-body `ext_shm` UNIT marker (header `0x02 | M` — zenoh sets the
/// MANDATORY bit, `put.rs:73 zextunit!(0x2, true)`, so a peer that does not
/// understand SHM rejects the Put rather than reading the descriptor as payload).
/// The surrounding body-ext codec applies the chain-continuation `Z` bit.
pub fn encode_shm_marker_ext<S: CodecStorage>() -> ExtEntryOwned<S> {
    ExtEntryOwned {
        header: SHM_BODY_EXT_ID | EXT_FLAG_M,
        body: ExtEntryOwnedVariant::CodecZenohExtUnit(ExtUnit::default()),
    }
}

/// `true` iff a Put body ext chain carries the `ext_shm` marker — the RX signal
/// that the payload field is a descriptor to resolve (not raw bytes). Detects by
/// id (the [`crate::unit_ext`] mechanism), so the marker's M bit is ignored.
/// Reads any entry kind a chain can hold: the Put's generic entry and the
/// Query's own (R3044).
pub fn body_has_shm_marker<E: crate::ext_view::ExtEntryView>(extensions: &[E]) -> bool {
    crate::unit_ext::chain_has_ext_eid(extensions, SHM_BODY_EXT_ID | EXT_FLAG_M)
}

/// The Z_EXT_SHM ESTABLISHMENT ext id (on Init / Open) — a DISTINCT carrier from
/// the body marker above though it shares the numeric 0x2 (zenoh's establishment
/// Shm ext space, `transport/init.rs`'s `pub type Shm`). This UNIT form is wz's
/// own SCOPED capability ext — offer / reflect / `&=`, the lowlatency /
/// compression pattern — and it is what a deploy with NO authenticator installed
/// speaks. No M bit (a non-SHM peer drops the offer silently).
///
/// ⚠ It is NOT the extension a conforming zenoh sends. That one is the ZBuf
/// challenge-response below, which additionally proves both peers can MAP each
/// other's segment; wz has spoken it since R311y507 and R2240 re-based it on
/// 1.10.0. The two live at the same 4-bit id and are told apart by the ENCODING
/// bits, which is why every match here goes through
/// [`crate::ext_header::ext_eid`] and never the id field.
///
/// (This paragraph said "NOT zenoh's ZBuf-on-Init / z64-on-Open
/// challenge-response … a disclosed deferral" until R2240. Both halves had gone
/// stale: the deferral was paid off at R311y507, and 1.10.0 made the Open phase
/// a ZBuf too, so "z64-on-Open" named a shape that no longer exists anywhere.)
#[cfg(feature = "session-extshm")]
pub const SHM_ESTABLISHMENT_EXT_ID: u8 = crate::ext_header::establishment_ext_id::SHM;

/// Build the establishment SHM capability offer (the UNIT ext on Init / Open,
/// the [`crate::unit_ext`] mechanism at the SHM establishment id).
#[cfg(feature = "session-extshm")]
pub fn encode_shm_establishment_ext() -> ExtEntryOwned {
    crate::unit_ext::encode_unit_ext(SHM_ESTABLISHMENT_EXT_ID)
}

/// Project the peer's SHM capability from an Init / Open ext chain — ANDed against
/// the local offer to finalize `is_shm` (zenoh `is_shm &= other.is_some()`).
#[cfg(feature = "session-extshm")]
pub fn peer_offered_shm(extensions: &[ExtEntryOwned]) -> bool {
    crate::unit_ext::chain_has_ext_eid(extensions, SHM_ESTABLISHMENT_EXT_ID)
}

// ---------------------------------------------------------------------------
// session-extshm (R311y507, re-based on zenoh 1.10.0 by R2240) — zenoh's
// ZBuf-on-Init AND ZBuf-on-Open CHALLENGE-RESPONSE. The wire half; the POSIX
// auth segment behind it is `std` and lives in
// `wz-runtime-tokio::shm_auth_segment`, reached through [`ShmAuthenticator`].
// ---------------------------------------------------------------------------

/// The encoded header both establishment `Shm` extensions carry — id `0x2` with
/// the ZBuf encoding bits. `transport/init.rs` and `transport/open.rs` BOTH
/// declare `pub type Shm = zextzbuf!(0x2, false)` at 1.10.0, so there is one
/// header here and not two.
///
/// R2240 collapsed the pair. Until 1.10.0 the Open phase was `zextz64!`, and
/// this module carried a second constant for it; the two are now the same byte
/// and what separates an Init `Shm` from an Open `Shm` is the MESSAGE CARRYING
/// IT, not the header. wz already keeps those apart structurally — the four
/// `ExtChainRole` slots are four distinct stores — so the collapse costs no
/// discrimination. It does mean a reader must not conclude "Init" from the
/// header alone.
///
/// Still a DIFFERENT extension from the UNIT offer at the same 4-bit id, which
/// is why matching goes through [`crate::ext_header::ext_eid`] rather than the
/// id field (R311y505 measured wz reading one as the other).
#[cfg(feature = "session-extshm")]
pub const SHM_ZBUF_EXT_HEADER: u8 = SHM_ESTABLISHMENT_EXT_ID | crate::ext_header::EXT_ENC_ZBUF;

/// The number of priority bands a `PerPriority` counter block carries — zenoh
/// `Priority::NUM`, which upstream computes as `1 + MIN - MAX` over an enum
/// running `Control = 0 ..= Background = 7`.
///
/// ⚠ ALIASED to [`crate::qos::Priority::NUM`] rather than re-derived. This
/// constant spelled that expression out as `1 + 7 - 0`, which is a SECOND
/// derivation of a fact the crate already owns three modules over — the
/// conduit arrays, the Join QoS reader and the dissect band table all size
/// themselves from `Priority::NUM`, so a band count that drifted here would
/// disagree with them silently. One fact, one place. (`qos` is an
/// unconditional module, so the alias costs this cfg nothing.)
#[cfg(feature = "session-extshm")]
pub const SHM_PRIORITY_BANDS: usize = crate::qos::Priority::NUM;

/// R3065 -- how many protocol ids an auth segment can list: the length of the `protocols`
/// array in upstream's `ShmTransportMetadata`
/// (`io/zenoh-transport/src/unicast/establishment/ext/shm/segment.rs` @ `protocols: [ProtocolID; 256],`).
#[cfg(feature = "session-extshm")]
pub const SHM_PROTOCOL_SLOTS: usize = 256;

/// R3065 -- more protocols than an auth segment has slots for.
#[cfg(feature = "session-extshm")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TooManyShmProtocols {
    /// How many distinct ids were asked for.
    pub asked: usize,
}

/// R3065 -- the shared-memory protocols a session's READER can resolve a buffer of: what its auth
/// segment lists, and so what a peer's sender is allowed to send it as a descriptor (see
/// [`ShmAuthenticator::open_peer_protocols`]). `0` is upstream's POSIX protocol.
///
/// A fixed array and not a `Vec` because it travels in [`crate::transport_mode::SessionOffer`],
/// which is `Copy` and is copied through every open path, dial, accept, peer and redial alike:
/// carrying the list THERE is what makes every path advertise the list of the session's own
/// reader, where a separate argument would have to be threaded through each of them. The capacity
/// is the wire's own (256), so no storage a peer could express is refused here that upstream takes.
#[cfg(feature = "session-extshm")]
#[derive(Clone, Copy, Debug)]
pub struct ShmProtocolList {
    len: u16,
    ids: [u32; SHM_PROTOCOL_SLOTS],
}

#[cfg(feature = "session-extshm")]
impl ShmProtocolList {
    /// The default reader's list: POSIX, and nothing else.
    pub const POSIX_ONLY: Self = Self {
        len: 1,
        ids: [0; SHM_PROTOCOL_SLOTS],
    };

    /// The list of exactly `ids`, in the order given, a repeated id kept once. `Err` when there
    /// are more distinct ids than the segment has slots.
    pub fn new(ids: &[u32]) -> Result<Self, TooManyShmProtocols> {
        let mut list = Self {
            len: 0,
            ids: [0; SHM_PROTOCOL_SLOTS],
        };
        for &id in ids {
            if list.as_slice().contains(&id) {
                continue;
            }
            let slot = usize::from(list.len);
            if slot == SHM_PROTOCOL_SLOTS {
                return Err(TooManyShmProtocols { asked: ids.len() });
            }
            list.ids[slot] = id;
            list.len += 1;
        }
        Ok(list)
    }

    /// The ids, in order.
    pub fn as_slice(&self) -> &[u32] {
        &self.ids[..usize::from(self.len)]
    }
}

#[cfg(feature = "session-extshm")]
impl Default for ShmProtocolList {
    fn default() -> Self {
        Self::POSIX_ONLY
    }
}

/// Equal when they list the same ids in the same order: the slots past `len` are not part of the
/// value, and a derived comparison would read them.
#[cfg(feature = "session-extshm")]
impl PartialEq for ShmProtocolList {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

#[cfg(feature = "session-extshm")]
impl Eq for ShmProtocolList {}

/// zenoh's `HandoffCounterIds` (`HandoffConfig<ShmCounterID>`) — the SHM
/// back-pressure counter block that 1.10.0 added to BOTH Open-phase messages.
///
/// A node that operates a handoff as a sender (R3110, [`ShmTxHandoff`]) declares
/// [`Self::PerPriority`] with the counters it leased; a node whose authenticator
/// operates none declares [`Self::Disabled`], which is the arm upstream itself picks
/// for a `BestEffort` link and which its `RxHandoffChannel::new_rx` accepts without
/// touching a counter. That is a truthful declaration rather than a shortcut: naming
/// indices into a counter array it never counts would be the claim that is false.
#[cfg(feature = "session-extshm")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShmHandoffCounters {
    /// Wire byte `0x00` and nothing after it.
    Disabled,
    /// Wire byte `0x01` then one `ShmCounterID` per band, in band order.
    PerPriority([u16; SHM_PRIORITY_BANDS]),
}

/// Encode the InitSyn `Shm` body — zenoh's `InitSyn { alice_segment }`, a bare
/// segment id. `AuthSegmentID` is a `u32` and zenoh's codec writes every
/// unsigned integer as the SAME u64 VLE (`zint.rs` `uint_impl!(u32)` delegates
/// to `write(writer, x as u64)`), so this is one VLE and nothing else.
#[cfg(feature = "session-extshm")]
pub fn encode_shm_init_syn_body(alice_segment: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(5);
    encode_vle_u64_into(&mut out, alice_segment as u64);
    out
}

/// Decode the InitSyn `Shm` body. `None` on truncation or a value past `u32`
/// (zenoh reads it into an `AuthSegmentID`, so a wider value is malformed).
#[cfg(feature = "session-extshm")]
pub fn decode_shm_init_syn_body(bytes: &[u8]) -> Option<u32> {
    let (segment, _n) = read_vle_u64(bytes)?;
    u32::try_from(segment).ok()
}

/// Encode the InitAck `Shm` body — zenoh's `InitAck { alice_challenge,
/// bob_segment }`, in that field order. The challenge is the value the ACCEPTOR
/// read out of the INITIATOR's segment, which is what proves it could map it.
#[cfg(feature = "session-extshm")]
pub fn encode_shm_init_ack_body(alice_challenge: u64, bob_segment: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(14);
    encode_vle_u64_into(&mut out, alice_challenge);
    encode_vle_u64_into(&mut out, bob_segment as u64);
    out
}

/// Decode the InitAck `Shm` body into `(alice_challenge, bob_segment)`.
#[cfg(feature = "session-extshm")]
pub fn decode_shm_init_ack_body(bytes: &[u8]) -> Option<(u64, u32)> {
    let (challenge, n0) = read_vle_u64(bytes)?;
    let (segment, _n1) = read_vle_u64(bytes.get(n0..)?)?;
    Some((challenge, u32::try_from(segment).ok()?))
}

/// Encode a [`ShmHandoffCounters`] exactly as zenoh's `WCodec` for
/// `HandoffCounterIds` does: a STATUS BYTE, then the per-band ids when it is
/// `1`.
///
/// The status is written by `WCodec<u8>`, which is `writer.write_u8` — a RAW
/// byte, not a VLE. For `0` and `1` the two encodings coincide, so this cannot
/// be caught by a round-trip against ourselves; it is written raw because that
/// is what the peer's READER consumes.
///
/// Each id is a `ShmCounterID` (`u16`), and zenoh routes every unsigned integer
/// except `u8` through `uint_impl!`, which widens to `u64` and writes the same
/// VLE — so an id is one VLE, not two fixed bytes.
#[cfg(feature = "session-extshm")]
fn encode_shm_handoff_counters(out: &mut Vec<u8>, counters: ShmHandoffCounters) {
    match counters {
        ShmHandoffCounters::Disabled => out.push(0),
        ShmHandoffCounters::PerPriority(ids) => {
            out.push(1);
            for id in ids {
                encode_vle_u64_into(out, id as u64);
            }
        }
    }
}

/// Decode a [`ShmHandoffCounters`], returning it and the bytes consumed.
///
/// A status byte that is neither `0` nor `1` is NOT "assume disabled": upstream
/// treats every non-zero as `PerPrio` and then reads a full band block, so a
/// reader that guessed would desynchronise from the peer rather than disagree
/// with it. Anything that does not decode into a whole block is `None`.
#[cfg(feature = "session-extshm")]
fn decode_shm_handoff_counters(bytes: &[u8]) -> Option<(ShmHandoffCounters, usize)> {
    let (&status, rest) = bytes.split_first()?;
    if status == 0 {
        return Some((ShmHandoffCounters::Disabled, 1));
    }
    let mut ids = [0u16; SHM_PRIORITY_BANDS];
    let mut used = 1;
    for slot in ids.iter_mut() {
        let (v, n) = read_vle_u64(rest.get(used - 1..)?)?;
        *slot = u16::try_from(v).ok()?;
        used += n;
    }
    Some((ShmHandoffCounters::PerPriority(ids), used))
}

/// Encode the OpenSyn `Shm` body — zenoh's `OpenSyn { bob_challenge,
/// alice_counters }`, in that field order. The challenge is the value the
/// INITIATOR read out of the ACCEPTOR's segment.
#[cfg(feature = "session-extshm")]
pub fn encode_shm_open_syn_body(bob_challenge: u64, counters: ShmHandoffCounters) -> Vec<u8> {
    let mut out = Vec::with_capacity(10);
    encode_vle_u64_into(&mut out, bob_challenge);
    encode_shm_handoff_counters(&mut out, counters);
    out
}

/// Decode the OpenSyn `Shm` body into `(bob_challenge, alice_counters)`.
#[cfg(feature = "session-extshm")]
pub fn decode_shm_open_syn_body(bytes: &[u8]) -> Option<(u64, ShmHandoffCounters)> {
    let (challenge, n0) = read_vle_u64(bytes)?;
    let (counters, _n1) = decode_shm_handoff_counters(bytes.get(n0..)?)?;
    Some((challenge, counters))
}

/// Encode the OpenAck `Shm` body — zenoh's `OpenAck { bob_counters }`, which is
/// the counter block and NOTHING else.
///
/// ⚠ 1.10.0 removed the literal `1` the 1.5.0 acceptor sent here, and with it
/// the only explicit "I accepted your echo" signal on the wire. See
/// [`ShmAuthDispatch::recv_open_ack`].
#[cfg(feature = "session-extshm")]
pub fn encode_shm_open_ack_body(counters: ShmHandoffCounters) -> Vec<u8> {
    let mut out = Vec::with_capacity(1);
    encode_shm_handoff_counters(&mut out, counters);
    out
}

/// Decode the OpenAck `Shm` body into the peer's counter block.
#[cfg(feature = "session-extshm")]
pub fn decode_shm_open_ack_body(bytes: &[u8]) -> Option<ShmHandoffCounters> {
    decode_shm_handoff_counters(bytes).map(|(c, _)| c)
}

/// Wrap an establishment body in the `Shm` ZBuf ext entry (header `0x42`).
/// Fallible only because the owned ZBuf copy re-checks its inline capacity, the
/// same bound decode enforces.
///
/// ONE encoder for both phases, because 1.10.0 gives both the same header; the
/// caller picks the phase by which `ExtChainRole` slot it stages into.
#[cfg(feature = "session-extshm")]
pub fn encode_shm_zbuf_ext(body: &[u8]) -> Result<ExtEntryOwned, CodecError> {
    Ok(ExtEntryOwned {
        header: SHM_ZBUF_EXT_HEADER,
        body: ExtEntryOwnedVariant::CodecZenohExtZbuf(ExtZbufOwned {
            value_len: body.len() as u64,
            value: crate::codec_owned::owned_bytes(body)?,
        }),
    })
}

/// Read the `Shm` ZBuf body out of an ext chain, matching on the full extension
/// IDENTITY so wz's own UNIT offer at the same id is never mistaken for it.
/// Which PHASE the body belongs to is decided by which chain was passed in.
#[cfg(feature = "session-extshm")]
pub fn peer_shm_zbuf_body(extensions: &[ExtEntryOwned]) -> Option<&[u8]> {
    extensions
        .iter()
        .find(|e| crate::ext_header::ext_eid(e.header) == SHM_ZBUF_EXT_HEADER)
        .and_then(|e| match &e.body {
            ExtEntryOwnedVariant::CodecZenohExtZbuf(z) => Some(z.value.as_slice()),
            _ => None,
        })
}

/// The no_std/std seam for the SHM AUTH SEGMENT — the half of the
/// challenge-response that has to touch the operating system.
///
/// zenoh's proof is not a token exchange: each peer publishes a real POSIX
/// shared-memory segment holding a random challenge, and answering with that
/// challenge is what demonstrates the answerer could MAP the segment — i.e. that
/// the two processes genuinely share memory, rather than merely both claiming
/// to. Everything above this trait is wire format; everything behind it is
/// `shm_open` + `mmap`, which is why it is injected from the AP runtime
/// (`wz-runtime-tokio::shm_auth_segment`) exactly as [`ShmResolver`] is.
#[cfg(feature = "session-extshm")]
pub trait ShmAuthenticator {
    /// This node's own segment id — what goes on the wire so the peer can open
    /// it (zenoh `AuthUnicast::id()`).
    fn local_segment_id(&self) -> u32;

    /// The challenge stored in this node's own segment, to be compared against
    /// what the peer echoes back (zenoh `validate_challenge`).
    fn local_challenge(&self) -> u64;

    /// Open the peer's segment by id and read its challenge. `None` when the
    /// segment cannot be mapped or its version does not match — both of which
    /// zenoh treats as "no SHM", NOT as a handshake error, so the session
    /// continues without shared memory.
    fn open_peer_challenge(&self, segment_id: u32) -> Option<u64>;

    /// R3040 -- open the peer's handoff counters: the peer's auth segment
    /// (`peer_segment`, the id it published at establishment) mapped so that its
    /// counters can be written, and the counter ids it named for each priority,
    /// in priority order. `None` when the segment cannot be mapped or names a
    /// counter outside its array, which upstream treats as "no handoff on this
    /// link" and carries on (`recv_open_ack` logs `Handoff channel creation
    /// error` and returns `Ok(())`).
    ///
    /// Defaults to `None`, an authenticator that cannot write a peer's counters:
    /// the session then runs exactly as before, a receiver that never
    /// acknowledges.
    fn open_peer_handoff(
        &self,
        peer_segment: u32,
        counters: &[u16; SHM_PRIORITY_BANDS],
    ) -> Option<alloc::boxed::Box<dyn ShmHandoff>> {
        let _ = (peer_segment, counters);
        None
    }

    /// R3110 -- this node's own handoff as a SENDER: the counters it names in its Open messages
    /// and keeps the chunks it sends confirmed against. Defaults to `None`, an authenticator that
    /// operates none, which declares the counter block as `Disabled` and keeps nothing: the node
    /// then delivers to a receiver that attaches within the validator's window and to no later
    /// one.
    fn tx_handoff(&self) -> Option<alloc::sync::Arc<dyn ShmTxHandoff>> {
        None
    }

    /// R3065 -- the protocol ids the peer's segment advertises: the shared-memory protocols its
    /// reader can resolve a buffer of. A sender sends a buffer's descriptor only to a peer that
    /// lists the buffer's protocol and sends its bytes to one that does not (upstream's
    /// `io/zenoh-transport/src/common/shm/interop.rs` @ `fn supports_protocol(`, read off the
    /// same list).
    ///
    /// `None` when the list cannot be read, which a sender takes as "unknown" and does not act
    /// on: the descriptor goes out as it did before this was asked. That is the default, an
    /// authenticator that cannot read a peer's list.
    fn open_peer_protocols(&self, segment_id: u32) -> Option<alloc::vec::Vec<u32>> {
        let _ = segment_id;
        None
    }
}

/// The no_std/std seam: an SHM-backed Put's descriptor is resolved to its bytes
/// by an AP-injected resolver (the `std` mmap-open lives in
/// `wz-runtime-tokio::shm_provider`, behind this trait). `None` when the segment
/// cannot be opened / mapped (a stale or foreign descriptor — the caller drops
/// the Sample). Used on the RX path (R3b wires it onto the subscriber registry).
pub trait ShmResolver {
    /// Open the descriptor's segment and copy its `length` bytes out (the bounded
    /// scoped copy off the shared page into an owned buffer). A payload that is
    /// delivered to the application is read through [`Self::resolve_shared`]
    /// instead, which leaves the bytes on the page; this copy is what a message
    /// that is not delivered as one buffer is joined from.
    ///
    /// R3038 -- THE CONTRACT INCLUDES THE RELEASE. A descriptor is sent with one
    /// reference taken for its receiver, as upstream's sender takes it when it
    /// serializes the buffer, and the receiver gives it back when it lets go of
    /// the buffer. This call is where wz's receiver lets go: an implementation
    /// that reads a chunk it was sent must give back that reference exactly once
    /// on every way out, including a read that fails once the descriptor is known
    /// to be this receiver's, because a reference nobody gives back keeps the
    /// sender's chunk out of its pool for good. A descriptor that is not this
    /// receiver's (a slot that has since been reclaimed) is not released.
    fn resolve(&self, descriptor: &ShmDescriptor) -> Option<Vec<u8>>;

    /// [`Self::resolve`] returning the bytes as the shareable type, so an
    /// implementation that keeps the segment mapped can hand them up where they
    /// are (R3049). The contract on the reference changes with it and only in WHEN:
    /// it is given back exactly once on every way out, and the way out of a read
    /// that succeeded is the drop of the last range of the bytes returned, because
    /// the page must stay the sender's, unreclaimed, for as long as anything reads
    /// it. The default copies and gives the reference back before it returns, which
    /// is the same contract with the last drop already past.
    fn resolve_shared(&self, descriptor: &ShmDescriptor) -> Option<crate::link::RxBytes> {
        self.resolve(descriptor).map(crate::link::RxBytes::from)
    }

    /// The chunk a received descriptor names, held as a buffer a message can be sent from AGAIN:
    /// what a node that forwards a message keeps of it while it routes, as upstream's router
    /// keeps the mapped buffer of the message it relays
    /// (`io/zenoh-transport/src/common/shm/interop.rs` @ `pub fn map_zmsg_to_shmbuf(`).
    ///
    /// The contract on the reference is [`Self::resolve_shared`]'s: the descriptor carried one
    /// reference taken for this receiver, the handle owns it, and it goes back exactly once, when
    /// the last clone of the handle drops. Every reservation taken from the handle
    /// ([`ShmSendHandle::reserve_for_receiver`]) is a reference of its own on top of it, so a
    /// relay to N peers leaves the chunk with N references and the handle's drop gives back the
    /// one it was sent.
    ///
    /// `None` when the descriptor cannot be held (a stale or foreign segment, a protocol this
    /// node does not read) and for a resolver that cannot relay, which is the default.
    fn hold(&self, descriptor: &ShmDescriptor) -> Option<ShmSendHandle> {
        let _ = descriptor;
        None
    }
}

/// The chunks a forwarding node holds while it routes ONE message, as the faces it routes to
/// see them.
///
/// A face that is handed a message whose payload is a descriptor asks this for the chunk the
/// descriptor names, and then sends it as the descriptor with a reference of its own if its peer
/// can read shared memory, or as the bytes if it cannot. Nothing is held outside a routing pass,
/// so a descriptor that reaches a face with no pass open is answered `None` and its message is
/// not sent.
pub trait ShmRelayHolds: Send + Sync {
    /// The chunk `descriptor` names, if the pass in progress holds it.
    fn held(&self, descriptor: &ShmDescriptor) -> Option<ShmSendHandle>;
}

/// R3062 -- the SENDING end of a shared-memory payload: a buffer some owner of a segment holds,
/// that a message can be sent from as its descriptor. The seam beside [`ShmResolver`], which is
/// where a received descriptor is read; this is where a sent one is made. The session core knows
/// the descriptor's bytes and the rules of the wire, and nothing about the segment, so what a
/// reply or any later message carries is this and not a runtime type.
///
/// A message that carries one is sent as the descriptor to a peer that negotiated shared memory
/// and as [`Self::bytes`] to one that did not, and delivered to a receiver of the SAME session as
/// [`Self::receiver_view`], so the three never disagree about what the payload is.
pub trait ShmSendBuffer: Send + Sync {
    /// The bytes the buffer holds: what a peer that cannot map the segment is sent.
    fn bytes(&self) -> &[u8];

    /// R3065 -- the shared-memory protocol the buffer's chunk belongs to: the id its provider's
    /// backend reports and its header carries, which a receiver reads the chunk through. A peer
    /// is sent the descriptor only if its segment lists this protocol (see
    /// [`ShmAuthenticator::open_peer_protocols`]); every other peer is sent [`Self::bytes`].
    /// `0` is upstream's POSIX protocol.
    fn protocol(&self) -> u32;

    /// The buffer as a holder in this process sees it, for a receiver of the session that
    /// sent it: a range of the shared page holding a reference of its own, which goes back
    /// when the view drops. `None` when the page cannot be viewed.
    fn receiver_view(&self) -> Option<crate::link::RxBytes>;

    /// Take the reference one REMOTE receiver will release and return the reservation that
    /// carries it. Taken before the descriptor is built, so the chunk cannot be reclaimed
    /// between the two; given back if the reservation drops without [`ShmReservation::commit`],
    /// because the frame did not build or the send refused. The reservation owns what it
    /// needs, so it may outlive the handle it was taken from.
    fn reserve_for_receiver(self: alloc::sync::Arc<Self>) -> alloc::boxed::Box<dyn ShmReservation>;
}

/// The reference [`ShmSendBuffer::reserve_for_receiver`] took, and the descriptor naming it.
pub trait ShmReservation: Send {
    /// The descriptor this reference is for.
    fn descriptor(&self) -> ShmDescriptor;

    /// The frame carrying the descriptor has been handed to the link: the receiver now owns the
    /// reference and releases it when it lets go. A reservation dropped any other way gives the
    /// reference back.
    fn commit(self: alloc::boxed::Box<Self>);
}

/// A shared handle to a [`ShmSendBuffer`] that can sit in a staged message: cloneable, printable,
/// and equal to itself and to nothing else, because two handles are the same payload exactly
/// when they are the same buffer.
#[derive(Clone)]
pub struct ShmSendHandle(alloc::sync::Arc<dyn ShmSendBuffer>);

impl ShmSendHandle {
    /// Wrap a buffer.
    pub fn new(buffer: alloc::sync::Arc<dyn ShmSendBuffer>) -> Self {
        Self(buffer)
    }

    /// The bytes the buffer holds.
    pub fn bytes(&self) -> &[u8] {
        self.0.bytes()
    }

    /// The buffer's shared-memory protocol; see [`ShmSendBuffer::protocol`].
    pub fn protocol(&self) -> u32 {
        self.0.protocol()
    }

    /// The buffer as a receiver of this session holds it; see [`ShmSendBuffer::receiver_view`].
    pub fn receiver_view(&self) -> Option<crate::link::RxBytes> {
        self.0.receiver_view()
    }

    /// Take the reference a remote receiver will release; see
    /// [`ShmSendBuffer::reserve_for_receiver`].
    pub fn reserve_for_receiver(&self) -> alloc::boxed::Box<dyn ShmReservation> {
        self.0.clone().reserve_for_receiver()
    }
}

impl core::fmt::Debug for ShmSendHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ShmSendHandle")
            .field("len", &self.0.bytes().len())
            .finish()
    }
}

impl PartialEq for ShmSendHandle {
    fn eq(&self, other: &Self) -> bool {
        alloc::sync::Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for ShmSendHandle {}

/// R3040 -- the RECEIVING end of zenoh's SHM handoff counters.
///
/// A zenoh sender that puts a shared-memory buffer on a reliable link keeps a
/// hard reference to it, which keeps the buffer's watchdog bit confirmed, until
/// its receiver says the buffer has arrived. "Says" is one decrement of a
/// counter in the SENDER's auth segment, one counter per priority, whose ids the
/// sender names in its Open message
/// (`io/zenoh-transport/src/unicast/establishment/ext/shm/handoff.rs` @
/// `pub fn on_rx(&self, priority: Priority) {`), called once per shared-memory
/// slice of every received message at
/// `io/zenoh-transport/src/common/shm/interop.rs` @ `handoff.on_rx(priority);`.
///
/// A receiver that never decrements leaves every buffer the sender ever sent it
/// pinned and confirmed for the life of the transport, which is what wz was until
/// this trait existed (MEASURED: the sender's counter climbed one per put and
/// never came down, and its chunks stayed confirmed for as long as the process
/// ran).
///
/// `band` is the priority's wire value, `0..=7`. An implementation maps it to
/// the counter the sender named for that priority and gives one back, and does
/// nothing for a band it holds no counter for.
pub trait ShmHandoff: Send + Sync {
    /// One shared-memory slice of a message of priority `band` has been received.
    fn on_rx(&self, band: usize);
}

/// R3110 -- the SENDING half of the handoff: the counters a node names in its Open messages for
/// the peer to lower, and the confirmation it keeps of each buffer it sends until the peer has
/// (`io/zenoh-transport/src/unicast/establishment/ext/shm/handoff.rs` @ `pub struct TxHandoff {`).
///
/// A buffer's owner lets go of it the moment it has been sent, and the chunk's watchdog bit is
/// confirmed only while somebody holds it: with nobody left a validator invalidates the chunk
/// within its 100 ms window, and a receiver that attaches later finds `Buffer is invalidated`
/// and drops the message. Upstream's sender keeps a hard reference to every buffer it sends,
/// which keeps the bit confirmed, until the receiver lowers the counter it named for that
/// priority; a node that keeps nothing delivers to a receiver that is quick and loses messages
/// to one that is late (MEASURED: a subscriber stopped for a second was handed nothing).
#[cfg(feature = "session-extshm")]
pub trait ShmTxHandoff: Send + Sync {
    /// The counter ids this node names for each priority band, in band order: what its Open
    /// messages declare.
    fn counters(&self) -> [u16; SHM_PRIORITY_BANDS];

    /// Forget everything a previous peer was owed and zero the counters: a new establishment is
    /// a new peer, and a count left from the last would never come down.
    fn reset(&self);

    /// Open a transaction for ONE message of priority `band`.
    fn begin(&self, band: usize) -> alloc::boxed::Box<dyn ShmTxTransaction>;
}

/// One message's worth of [`ShmTxHandoff`]: every shared-memory slice of it is declared, and the
/// message is then either sent, which keeps what was taken until the peer acknowledges, or not,
/// which gives it all back. Dropping a transaction is the second.
#[cfg(feature = "session-extshm")]
pub trait ShmTxTransaction: Send {
    /// One shared-memory slice is being sent: `descriptor` is its serialized descriptor.
    ///
    /// EVERY slice is declared, whether or not the node can keep the chunk it names confirmed,
    /// because the receiver lowers the counter once per slice it maps and a slice that was sent
    /// and not counted would take the counter below zero.
    fn on_tx(&mut self, descriptor: &[u8]);

    /// The message left: keep what was taken until the peer acknowledges it.
    fn commit(self: alloc::boxed::Box<Self>);
}

/// Test double for the SENDING side (R3062): a buffer a message can be sent from, that counts the
/// references taken for receivers and what became of each, so a test reads whether the reference
/// of a frame that left was kept and the reference of a frame that did not was given back.
///
/// Gated by the union of its users' gates and by nothing wider: under `-D warnings` an item
/// nobody reads is an error, and the two users (the staged-reply tests of `query`, and the local
/// projection test of `reply`) each read every item, so the module exists exactly when one of
/// them does.
#[cfg(all(
    test,
    feature = "query-queryable",
    any(
        all(feature = "codec-response", feature = "codec-frame"),
        feature = "rx-shared-bytes"
    )
))]
pub(crate) mod send_test_support {
    use super::{ShmDescriptor, ShmReservation, ShmSendBuffer};
    use std::boxed::Box;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::vec::Vec;

    /// What happened to the references the buffer reserved.
    #[derive(Default)]
    pub(crate) struct Reservations {
        pub(crate) taken: AtomicUsize,
        pub(crate) committed: AtomicUsize,
        pub(crate) returned: AtomicUsize,
    }

    impl Reservations {
        pub(crate) fn counts(&self) -> (usize, usize, usize) {
            (
                self.taken.load(Ordering::SeqCst),
                self.committed.load(Ordering::SeqCst),
                self.returned.load(Ordering::SeqCst),
            )
        }
    }

    /// A buffer whose bytes live in storage the test keeps, so a receiver view can be told from
    /// a copy by the address of its bytes.
    pub(crate) struct FakeSendBuffer {
        pub(crate) storage: Arc<Vec<u8>>,
        pub(crate) reservations: Arc<Reservations>,
        /// The protocol the buffer reports: `0`, upstream's POSIX, unless a test asks for another.
        pub(crate) protocol: u32,
    }

    impl FakeSendBuffer {
        pub(crate) fn new(bytes: &[u8]) -> (Arc<Self>, Arc<Reservations>) {
            Self::with_protocol(bytes, 0)
        }

        /// [`Self::new`] for a buffer of a protocol other than POSIX.
        pub(crate) fn with_protocol(bytes: &[u8], protocol: u32) -> (Arc<Self>, Arc<Reservations>) {
            let reservations = Arc::new(Reservations::default());
            let buffer = Arc::new(Self {
                storage: Arc::new(bytes.to_vec()),
                reservations: reservations.clone(),
                protocol,
            });
            (buffer, reservations)
        }

        /// The descriptor every reservation of this buffer names.
        pub(crate) fn descriptor() -> ShmDescriptor {
            ShmDescriptor {
                data_len: 11,
                metadata_id: 7,
                metadata_index: 3,
                generation: 5,
            }
        }
    }

    impl ShmSendBuffer for FakeSendBuffer {
        fn bytes(&self) -> &[u8] {
            &self.storage
        }

        fn protocol(&self) -> u32 {
            self.protocol
        }

        fn receiver_view(&self) -> Option<crate::link::RxBytes> {
            #[cfg(feature = "rx-shared-bytes")]
            {
                let storage: Arc<dyn crate::link::RxStorage> = self.storage.clone();
                crate::link::RxBytes::shared(storage, 0..self.storage.len())
            }
            #[cfg(not(feature = "rx-shared-bytes"))]
            {
                Some(crate::link::RxBytes::from(self.storage.to_vec()))
            }
        }

        fn reserve_for_receiver(self: Arc<Self>) -> Box<dyn ShmReservation> {
            self.reservations.taken.fetch_add(1, Ordering::SeqCst);
            Box::new(FakeReservation {
                reservations: self.reservations.clone(),
                committed: false,
            })
        }
    }

    struct FakeReservation {
        reservations: Arc<Reservations>,
        committed: bool,
    }

    impl ShmReservation for FakeReservation {
        fn descriptor(&self) -> ShmDescriptor {
            FakeSendBuffer::descriptor()
        }

        fn commit(mut self: Box<Self>) {
            self.committed = true;
            self.reservations.committed.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl Drop for FakeReservation {
        fn drop(&mut self) {
            if !self.committed {
                self.reservations.returned.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
}

/// Test doubles for the receive side, shared by every registry that un-swaps a
/// payload so that what one asserts about acknowledgement is the same thing the
/// others assert.
#[cfg(all(
    test,
    feature = "pubsub-put",
    any(feature = "codec-push", feature = "codec-response")
))]
pub(crate) mod test_support {
    use super::{ShmDescriptor, ShmHandoff, ShmResolver};
    use alloc::vec::Vec;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// A [`ShmHandoff`] that records the band of every slice it is told about, so a
    /// test reads what the receive path acknowledged and at which priority.
    pub(crate) struct RecordingHandoff(pub(crate) Arc<Mutex<Vec<usize>>>);

    impl ShmHandoff for RecordingHandoff {
        fn on_rx(&self, band: usize) {
            self.0.lock().expect("bands").push(band);
        }
    }

    /// A resolver that always resolves, so a test isolates what the handoff does
    /// from whether a descriptor resolves.
    pub(crate) struct AlwaysResolves;

    impl ShmResolver for AlwaysResolves {
        fn resolve(&self, _descriptor: &ShmDescriptor) -> Option<Vec<u8>> {
            Some(b"payload".to_vec())
        }
    }

    /// A resolver that hands up a range of storage IT KEEPS, so a test reads
    /// whether what the application was delivered is that storage or a copy of it:
    /// the address of the bytes is the storage's own, and a copy has another.
    #[cfg(feature = "rx-shared-bytes")]
    pub(crate) struct LendsStorage(pub(crate) Arc<Vec<u8>>);

    #[cfg(feature = "rx-shared-bytes")]
    impl ShmResolver for LendsStorage {
        fn resolve(&self, _descriptor: &ShmDescriptor) -> Option<Vec<u8>> {
            Some(self.0.to_vec())
        }

        fn resolve_shared(&self, _descriptor: &ShmDescriptor) -> Option<crate::link::RxBytes> {
            let storage: Arc<dyn crate::link::RxStorage> = self.0.clone();
            crate::link::RxBytes::shared(storage, 0..self.0.len())
        }
    }

    /// A resolver that resolves and COUNTS the descriptors it is asked about, so a
    /// test reads how many slices were read, which is how many references were
    /// given back to the sender.
    pub(crate) struct CountingResolver(pub(crate) Arc<AtomicUsize>);

    impl ShmResolver for CountingResolver {
        fn resolve(&self, _descriptor: &ShmDescriptor) -> Option<Vec<u8>> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Some(b"payload".to_vec())
        }
    }
}

/// The receive side of shared memory, in ONE place: what a session knows about the
/// peer's shared-memory capability, the means of reading and of acknowledging what
/// it sends, and the un-swap itself.
///
/// R3042 -- upstream does this once, for every network message that carries a
/// payload (`io/zenoh-transport/src/common/shm/interop.rs` @
/// `pub fn map_zmsg_to_shmbuf(`: the Put of a push, the value of a query, the
/// payload of a reply and of an error), before any of them is routed. wz had it
/// inside the subscriber registry and so for a push only, which left a reply whose
/// slice names a segment dropped unread and unacknowledged: its sender kept the
/// buffer, confirmed, until the transport ended, and a getter that asked past the
/// size of its peer's pool stopped being answered at all. Each registry that
/// receives a payload now holds one of these, and the session keeps them in step.
///
/// The state is restamped per iteration where the capability is concerned (see
/// [`Self::set_negotiated`]) and installed once where the means are (the resolver
/// at bring-up, the handoff per establishment).
#[derive(Default)]
pub struct ShmReceiveState {
    /// R311y516 -- the LIVE negotiated capability of the session that feeds this
    /// state, restamped on every dispatch iteration. It is the RX-side enforcement
    /// gate and wz's counterpart of zenoh's `if self.config.shm.is_some()` guard
    /// around `map_zmsg_to_shmbuf` (`io/zenoh-transport/src/unicast/universal/rx.rs`
    /// @ `if let Some(shm_context) = &self.shm_context {`): before it the un-swap
    /// consulted only the body's marker, so a peer that had NOT negotiated shared
    /// memory could name a `/dev/shm` segment and have this node map it.
    ///
    /// Defaults to `false` and is restamped, not snapshotted, on purpose:
    /// `negotiate_shm_against_peer` is a monotonic `&=`, so a reconnect can only
    /// drive the capability DOWN and a construction-time snapshot would go stale in
    /// the fail-OPEN direction. A multicast registry is never stamped and so stays
    /// fail-closed.
    negotiated: bool,
    /// The AP-injected resolver that maps a descriptor's segment off `/dev/shm` (the
    /// no_std/std seam; the implementation is
    /// `wz-runtime-tokio::shm_provider::PosixShmResolver`). `None` until bring-up
    /// installs it; a descriptor arriving with none installed drops. Shared, so one
    /// resolver serves every registry of a session.
    resolver: Option<alloc::sync::Arc<dyn ShmResolver + Send + Sync>>,
    /// R3040 -- the means of acknowledging the peer's slices: one decrement of the
    /// counter the peer named for the message's priority, per slice. A sender keeps
    /// a hard reference to every buffer it sends, which keeps it confirmed, until
    /// this is called for it. `None` when the peer named no counters, which
    /// upstream does for a best-effort link.
    handoff: Option<alloc::sync::Arc<dyn ShmHandoff>>,
    /// Messages dropped because a descriptor arrived on a session that never
    /// negotiated shared memory: the peer named a segment it had no right to name
    /// (or the state was never stamped), and the segment was deliberately not
    /// opened.
    unnegotiated_drops: u64,
    /// Messages dropped because a descriptor could not be resolved, or a slice had a
    /// kind this node does not know. Silent on the data path, observable here so a
    /// missing resolver is a readable counter and not a mystery of vanishing
    /// payloads.
    unresolved_drops: u64,
}

impl ShmReceiveState {
    /// Install the resolver. Shared, so the session hands the same one to every
    /// registry that receives a payload.
    pub fn set_resolver(&mut self, resolver: alloc::sync::Arc<dyn ShmResolver + Send + Sync>) {
        self.resolver = Some(resolver);
    }

    /// Restamp the LIVE negotiated capability of the session feeding this state.
    pub fn set_negotiated(&mut self, negotiated: bool) {
        self.negotiated = negotiated;
    }

    /// Install or withdraw the means of acknowledging the peer's slices. `None`
    /// withdraws, which a new establishment does first, so a registry never writes
    /// the counters of a peer the session has moved on from.
    pub fn set_handoff(&mut self, handoff: Option<alloc::sync::Arc<dyn ShmHandoff>>) {
        self.handoff = handoff;
    }

    /// Whether the un-swap will currently honour a descriptor.
    pub fn negotiated(&self) -> bool {
        self.negotiated
    }

    /// Whether a handoff is installed.
    pub fn has_handoff(&self) -> bool {
        self.handoff.is_some()
    }

    /// Messages dropped for want of a negotiated capability.
    pub fn unnegotiated_drops(&self) -> u64 {
        self.unnegotiated_drops
    }

    /// Messages dropped because a descriptor did not resolve.
    pub fn unresolved_drops(&self) -> u64 {
        self.unresolved_drops
    }

    /// The un-swap of a sliced Put: refuse it when shared memory was never
    /// negotiated, otherwise read every slice through the resolver and acknowledge
    /// each to the handoff at `band`. `None` is a counted drop; `Some` is the
    /// assembled payload.
    ///
    /// Every slice is read and acknowledged whether or not the message is then
    /// delivered, which is what lets a caller use this for a message routing
    /// refuses: what a slice is owed does not depend on whether the message goes
    /// anywhere.
    #[cfg(all(
        feature = "alloc",
        any(feature = "codec-push", feature = "codec-response")
    ))]
    pub fn unswap_put(
        &mut self,
        put: &wz_codecs::msg_put::MsgPutOwned<crate::wire::WireStorage>,
        band: usize,
    ) -> Option<crate::link::RxBytes> {
        // R311y516 -- ENFORCE the negotiation before opening anything. wz honoured
        // only the body's marker, so a peer that never negotiated shared memory
        // could name a segment and have this node map it. Drop and COUNT instead:
        // delivering the raw descriptor bytes as if they were the payload would
        // hand the application a few bytes of struct in place of its data, which is
        // worse than a counted drop.
        if !self.negotiated {
            self.unnegotiated_drops += 1;
            return None;
        }
        let (resolver, handoff) = (self.resolver.as_deref(), self.handoff.as_deref());
        match crate::put_payload::collect_wire_payload(put, |descriptor| {
            read_and_acknowledge(resolver, handoff, band, descriptor, |resolver, d| {
                resolver.resolve_shared(d)
            })
        }) {
            Ok(bytes) => Some(bytes),
            Err(_) => {
                // An unresolvable descriptor (no resolver, or a stale or foreign
                // segment) or a slice kind this node does not know: drop the
                // message, but COUNT it so the misconfiguration is observable.
                self.unresolved_drops += 1;
                None
            }
        }
    }

    /// The un-swap of a LIST OF SLICES that is not a Put's payload: the value of a
    /// query, which upstream writes as the same list after the same marker. The
    /// same rules as [`Self::unswap_put`]: refused and counted when shared memory
    /// was never negotiated, every slice read and acknowledged at `band` whether
    /// or not the message is then delivered, `None` a counted drop and `Some` the
    /// bytes the slices held, in order.
    ///
    /// R3061 -- the bytes are returned as the shareable type, read through
    /// [`ShmResolver::resolve_shared`] like a Put's, so a value that is ONE shared-memory
    /// slice reaches the queryable as the page it lies on and not as a copy.
    #[cfg(all(
        feature = "alloc",
        any(
            feature = "codec-push",
            feature = "codec-response",
            feature = "codec-request"
        )
    ))]
    pub fn unswap_slices(
        &mut self,
        slices: &[wz_codecs::zbuf_slice::ZbufSliceOwned<crate::wire::WireStorage>],
        band: usize,
    ) -> Option<crate::link::RxBytes> {
        if !self.negotiated {
            self.unnegotiated_drops += 1;
            return None;
        }
        let (resolver, handoff) = (self.resolver.as_deref(), self.handoff.as_deref());
        match crate::put_payload::collect_slices_shared(slices, |descriptor| {
            read_and_acknowledge(resolver, handoff, band, descriptor, |resolver, d| {
                resolver.resolve_shared(d)
            })
        }) {
            Ok(bytes) => Some(bytes),
            Err(_) => {
                self.unresolved_drops += 1;
                None
            }
        }
    }
}

/// Read one shared-memory slice through `resolver` and acknowledge it to
/// `handoff` at `band`.
///
/// R3040 -- ONE acknowledgement per shared-memory slice, at the message's
/// priority, whether or not the slice then resolves, and AFTER the attempt to
/// read it: upstream maps the slice, which attaches to the buffer's watchdog
/// first, and only then calls `handoff.on_rx(priority)` for it, for every
/// `ShmPtr` slice and whatever the mapping returned
/// (`io/zenoh-transport/src/common/shm/interop.rs` @
/// `handoff.on_rx(priority);`). The order matters: the sender drops its own
/// hold on the buffer once it is acknowledged, and a receiver that
/// acknowledged first would leave a window in which nobody confirmed it. The
/// sender's counter counts slices SENT, so a slice that is not acknowledged
/// is a buffer its sender pins and keeps confirmed until the transport ends.
/// The slice walk offers every such slice to its closure exactly once, which
/// is what makes this the place to count them.
#[cfg(all(
    feature = "alloc",
    any(
        feature = "codec-push",
        feature = "codec-response",
        feature = "codec-request"
    )
))]
fn read_and_acknowledge<R>(
    resolver: Option<&(dyn ShmResolver + Send + Sync)>,
    handoff: Option<&dyn ShmHandoff>,
    band: usize,
    descriptor: &[u8],
    read: impl FnOnce(&(dyn ShmResolver + Send + Sync), &ShmDescriptor) -> Option<R>,
) -> Option<R> {
    let resolved = decode_shm_descriptor(descriptor)
        .and_then(|d| resolver.and_then(|resolver| read(resolver, &d)));
    if let Some(handoff) = handoff {
        handoff.on_rx(band);
    }
    resolved
}

/// Why a SHM challenge-response step refused. Only ONE of zenoh's arms is an
/// error; every other failure degrades to "no shared memory" and lets the
/// session continue, which is deliberate and asymmetric upstream.
#[cfg(feature = "session-extshm")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShmAuthError {
    /// The initiator's InitSyn carried an `Shm` ext whose body does not decode.
    /// zenoh `recv_init_syn` `bail!`s here (`ext/shm.rs`), aborting the
    /// handshake, while the initiator's own `recv_init_ack` merely traces and
    /// returns `Ok(None)` on the same class of failure. The asymmetry is
    /// upstream's: a malformed challenge aimed at an ACCEPTOR is an attack
    /// surface, a malformed answer to an initiator is just a peer that will not
    /// get SHM.
    MalformedInitSyn,
}

/// The SHM establishment challenge-response state machine — zenoh's `ShmFsm`
/// (`io/zenoh-transport/src/unicast/establishment/ext/shm/auth.rs`
/// @ `pub(crate) struct ShmFsm`; 1.10.0 split the old single
/// `ext/shm.rs` @ REMOVED into
/// `ext/shm/{mod,auth,handoff,segment}.rs`) as a plain
/// dispatch object, so the four steps can be driven and TESTED without a socket
/// or a session.
///
/// The exchange, and what each step actually proves:
///
/// 1. **InitSyn** — the initiator publishes its own segment ID.
/// 2. **InitAck** — the acceptor opens that segment, reads the challenge inside,
///    and sends it back ALONGSIDE its own segment ID. Echoing the challenge is
///    the proof it could map the initiator's memory.
/// 3. **OpenSyn** — the initiator checks the echo against its own challenge,
///    then opens the acceptor's segment and answers with ITS challenge.
/// 4. **OpenAck** — the acceptor answers with its handoff counter block.
///    ⚠ 1.10.0 removed the literal `1` the 1.5.0 acceptor confirmed with, so
///    this message no longer carries "I accepted your echo" — see
///    [`ShmAuthDispatch::recv_open_ack`] for what is left to assert.
///
/// So each side proves map-ability to the other, and neither is taken on trust.
/// A node with no authenticator installed emits nothing at all (zenoh's
/// `auth_shm: None` arm), which is byte-identical to a peer that does no SHM.
#[cfg(feature = "session-extshm")]
pub struct ShmAuthDispatch {
    authenticator: Option<alloc::boxed::Box<dyn ShmAuthenticator + Send + Sync>>,
    /// The challenge read out of the PEER's segment: the value this node echoes
    /// on OpenSyn (initiator) after mapping the acceptor's segment. `None` until
    /// a peer segment has been successfully opened.
    peer_challenge: Option<u64>,
    /// R3040 -- the id of the PEER's segment, kept alongside its challenge: the
    /// handoff counters the peer names in its Open message live in that segment,
    /// so the segment the challenge was read from is the one to write. Set only
    /// when the challenge was read, cleared with it.
    peer_segment: Option<u32>,
    /// R3065 -- the protocol ids the peer's segment lists, read when the segment was recorded.
    /// `None` is "unknown" (no authenticator, no segment, or one this node cannot read a list
    /// from), and an unknown list admits every protocol, which is what a session did before the
    /// list was read.
    peer_protocols: Option<Vec<u32>>,
    /// R3040 -- the means of acknowledging the peer's shared-memory slices, opened
    /// from the counter block in its Open message. `None` when the peer named no
    /// counters, named bad ones, or this node's authenticator cannot write them.
    handoff: Option<alloc::boxed::Box<dyn ShmHandoff>>,
    /// Whether `handoff` has changed since the registry last took it, a change
    /// being a new one OR the loss of the last. The holder that acts on it takes
    /// it once per establishment rather than asking every message.
    handoff_changed: bool,
    /// R3111 -- whether this establishment declared the sender's counters (`PerPriority`) and
    /// not `Disabled`. Only a declared block is lowered by the peer, so only a declared block may
    /// be counted and kept against: a node that kept chunks against a block it declared
    /// `Disabled` would hold them until the session ends, for nobody lowers a counter it was
    /// never told of. Written by the Open messages, which take `&self`.
    tx_declared: core::cell::Cell<bool>,
}

#[cfg(feature = "session-extshm")]
impl Default for ShmAuthDispatch {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(feature = "session-extshm")]
impl core::fmt::Debug for ShmAuthDispatch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The trait object has no Debug bound, and its contents are a segment id
        // plus a secret; report only whether one is installed.
        f.debug_struct("ShmAuthDispatch")
            .field("installed", &self.authenticator.is_some())
            .field("peer_challenge_known", &self.peer_challenge.is_some())
            .field("handoff_open", &self.handoff.is_some())
            .finish()
    }
}

#[cfg(feature = "session-extshm")]
impl ShmAuthDispatch {
    /// The no-SHM dispatch: emits nothing, accepts nothing. zenoh's
    /// `auth_shm: None` (`manager.rs:293`), which is what a build without the
    /// shared-memory feature — or a deploy that did not enable it — carries.
    pub fn empty() -> Self {
        Self {
            authenticator: None,
            peer_challenge: None,
            peer_segment: None,
            peer_protocols: None,
            handoff: None,
            handoff_changed: false,
            tx_declared: core::cell::Cell::new(false),
        }
    }

    /// Install this node's authenticator (its own published segment plus the
    /// ability to map a peer's). Once installed, the four steps below start
    /// emitting.
    pub fn install(authenticator: alloc::boxed::Box<dyn ShmAuthenticator + Send + Sync>) -> Self {
        Self {
            authenticator: Some(authenticator),
            peer_challenge: None,
            peer_segment: None,
            peer_protocols: None,
            handoff: None,
            handoff_changed: false,
            tx_declared: core::cell::Cell::new(false),
        }
    }

    /// R3040 -- forget the peer's segment and any handoff opened from it: a new
    /// establishment is a new peer, and an acknowledgement written to the last
    /// one's counters would corrupt a segment that is no longer in play.
    fn forget_peer(&mut self) {
        self.peer_challenge = None;
        self.peer_segment = None;
        self.peer_protocols = None;
        self.set_handoff(None);
        // R3111 -- the counters declared to the last peer are not declared to this one.
        self.tx_declared.set(false);
    }

    /// R3065 -- record the peer's segment with the challenge read out of it, and the protocol
    /// list that segment carries. Both sites that learn the peer's segment (the acceptor on the
    /// InitSyn, the initiator on the InitAck) record it through here, so the list is read
    /// exactly when the segment is kept and never for a segment this node could not map.
    fn record_peer(&mut self, segment: u32) {
        self.peer_segment = self.peer_challenge.map(|_| segment);
        self.peer_protocols = match (self.authenticator.as_ref(), self.peer_segment) {
            (Some(a), Some(segment)) => a.open_peer_protocols(segment),
            _ => None,
        };
    }

    /// R3065 -- whether a buffer of `protocol` may be sent to this peer as its descriptor. A peer
    /// whose list is known and does not name the protocol cannot resolve the descriptor, so the
    /// buffer is sent as its bytes; a peer whose list is unknown is sent the descriptor as before.
    pub fn peer_supports_protocol(&self, protocol: u32) -> bool {
        self.peer_protocols
            .as_ref()
            .map_or(true, |list| list.contains(&protocol))
    }

    fn set_handoff(&mut self, handoff: Option<alloc::boxed::Box<dyn ShmHandoff>>) {
        self.handoff = handoff;
        self.handoff_changed = true;
    }

    /// R3040 -- open the handoff for the counter block the peer named, once the
    /// peer's segment is known. A block that names no counters (`Disabled`, which
    /// is what upstream sends for a best-effort link) opens none.
    fn open_handoff(&mut self, counters: ShmHandoffCounters) {
        let ShmHandoffCounters::PerPriority(ids) = counters else {
            self.set_handoff(None);
            return;
        };
        let handoff = match (self.authenticator.as_ref(), self.peer_segment) {
            (Some(a), Some(segment)) => a.open_peer_handoff(segment, &ids),
            _ => None,
        };
        self.set_handoff(handoff);
    }

    /// R3040 -- what changed in the acknowledging handoff since the last call.
    ///
    /// `None` when nothing changed. `Some(Some(h))` is a new handoff, to be put
    /// where the received slices are counted, and `Some(None)` is the loss of the
    /// old one, to be taken away from there, so a registry never keeps writing the
    /// counters of a peer this session has moved on from. Taking it moves the
    /// handoff out: there is one holder.
    pub fn take_handoff_update(&mut self) -> Option<Option<alloc::boxed::Box<dyn ShmHandoff>>> {
        if !self.handoff_changed {
            return None;
        }
        self.handoff_changed = false;
        Some(self.handoff.take())
    }

    /// Acknowledge ONE received shared-memory slice of priority `band` through the handoff this
    /// dispatch still holds, and do nothing when it holds none.
    ///
    /// A forwarder is the caller: it has no registry to take the handoff
    /// ([`Self::take_handoff_update`] moves it out, so there is one holder), and the slices it
    /// routes are still owed their acknowledgement. When a registry HAS taken it the dispatch
    /// holds none, and this writes nothing, so a slice is never acknowledged twice.
    pub fn acknowledge(&self, band: usize) {
        if let Some(handoff) = self.handoff.as_deref() {
            handoff.on_rx(band);
        }
    }

    /// Whether an authenticator is installed — i.e. whether this node can take
    /// part in the exchange at all.
    pub fn is_installed(&self) -> bool {
        self.authenticator.is_some()
    }

    /// Step 1, INITIATOR: publish our segment id. zenoh `send_init_syn`.
    pub fn send_init_syn(&self) -> Option<ExtEntryOwned> {
        let a = self.authenticator.as_ref()?;
        encode_shm_zbuf_ext(&encode_shm_init_syn_body(a.local_segment_id())).ok()
    }

    /// Step 2a, ACCEPTOR: open the initiator's segment and remember the
    /// challenge found inside. zenoh `recv_init_syn`.
    ///
    /// `Ok(())` with nothing remembered covers both "the peer sent no `Shm`"
    /// and "its segment could not be mapped" — upstream returns `Ok(None)` for
    /// both, so the session continues without SHM. A body that does not DECODE
    /// is the one hard error ([`ShmAuthError::MalformedInitSyn`]).
    pub fn recv_init_syn(&mut self, extensions: &[ExtEntryOwned]) -> Result<(), ShmAuthError> {
        self.forget_peer();
        let Some(a) = self.authenticator.as_ref() else {
            return Ok(());
        };
        let Some(body) = peer_shm_zbuf_body(extensions) else {
            return Ok(());
        };
        let alice_segment = decode_shm_init_syn_body(body).ok_or(ShmAuthError::MalformedInitSyn)?;
        self.peer_challenge = a.open_peer_challenge(alice_segment);
        // The segment is kept only with the challenge read out of it: a peer whose
        // memory this node could not map has no counters this node could write.
        self.record_peer(alice_segment);
        Ok(())
    }

    /// Step 2b, ACCEPTOR: answer with the initiator's own challenge plus our
    /// segment id. zenoh `send_init_ack`, which emits NOTHING when
    /// `recv_init_syn` produced no segment — so a peer whose memory we could not
    /// map simply never sees an `Shm` ext back.
    pub fn send_init_ack(&self) -> Option<ExtEntryOwned> {
        let a = self.authenticator.as_ref()?;
        let alice_challenge = self.peer_challenge?;
        encode_shm_zbuf_ext(&encode_shm_init_ack_body(
            alice_challenge,
            a.local_segment_id(),
        ))
        .ok()
    }

    /// Step 3a, INITIATOR: check that the acceptor echoed OUR challenge, then
    /// map ITS segment. zenoh `recv_init_ack`.
    ///
    /// `false` — never an error — for every failure: no ext, a body that does
    /// not decode, a challenge that does not match ours, or a segment we cannot
    /// map. All four mean the same thing to upstream (`Ok(None)`), and all four
    /// leave the session up without shared memory.
    pub fn recv_init_ack(&mut self, extensions: &[ExtEntryOwned]) -> bool {
        self.forget_peer();
        let Some(a) = self.authenticator.as_ref() else {
            return false;
        };
        let Some(body) = peer_shm_zbuf_body(extensions) else {
            return false;
        };
        let Some((alice_challenge, bob_segment)) = decode_shm_init_ack_body(body) else {
            return false;
        };
        // THE CHECK: the acceptor could only know this by mapping our segment.
        if alice_challenge != a.local_challenge() {
            return false;
        }
        self.peer_challenge = a.open_peer_challenge(bob_segment);
        self.record_peer(bob_segment);
        self.peer_challenge.is_some()
    }

    /// Step 3b, INITIATOR: answer with the challenge we read out of the
    /// acceptor's segment, plus our counter block. zenoh `send_open_syn`.
    ///
    /// R3111 -- `reliable` is whether the link the message leaves on is reliable, as upstream
    /// passes it (`io/zenoh-transport/src/unicast/establishment/open.rs` @
    /// `.send_open_syn(link.link.is_reliable().into())`).
    pub fn send_open_syn(&self, reliable: bool) -> Option<ExtEntryOwned> {
        self.authenticator.as_ref()?;
        encode_shm_zbuf_ext(&encode_shm_open_syn_body(
            self.peer_challenge?,
            self.declared_counters(reliable),
        ))
        .ok()
    }

    /// R3110 -- the counter block this node names in an Open message: its own transmit counters
    /// when the authenticator operates a handoff, `Disabled` when it does not.
    ///
    /// R3111 -- and `Disabled` on a link that is not reliable, whatever the authenticator
    /// operates, as upstream does (`io/zenoh-transport/src/unicast/establishment/ext/shm/handoff.rs`
    /// @ `Reliability::BestEffort => Self::Disabled,`): a datagram that is lost is never
    /// acknowledged, so a counter declared on such a link is never lowered and the chunk kept
    /// against it would be kept until the session ends. Nothing is leased to a link that gets
    /// none, and [`Self::tx_handoff`] then answers `None`.
    ///
    /// Declaring them zeroes them and forgets what a previous peer was owed, because the block
    /// is the start of an establishment and the peer it is declared to is a new one.
    fn declared_counters(&self, reliable: bool) -> ShmHandoffCounters {
        let handoff = self
            .authenticator
            .as_ref()
            .filter(|_| reliable)
            .and_then(|a| a.tx_handoff());
        self.tx_declared.set(handoff.is_some());
        match handoff {
            Some(tx) => {
                tx.reset();
                ShmHandoffCounters::PerPriority(tx.counters())
            }
            None => ShmHandoffCounters::Disabled,
        }
    }

    /// R3110 -- this node's handoff as a sender, for the send path to open a transaction on.
    ///
    /// R3111 -- `Some` only while the last Open message this node sent DECLARED the counters:
    /// before it, and after one that declared `Disabled`, there is no peer to lower them.
    pub fn tx_handoff(&self) -> Option<alloc::sync::Arc<dyn ShmTxHandoff>> {
        if !self.tx_declared.get() {
            return None;
        }
        self.authenticator.as_ref()?.tx_handoff()
    }

    /// Step 4a, ACCEPTOR: check the initiator echoed OUR challenge. zenoh
    /// `recv_open_syn`, whose `self.inner.validate(open_syn.bob_challenge, ..)`
    /// is the same comparison. `true` here is what keeps the accept side's flag.
    ///
    /// A body that does not parse as `challenge ++ counters` is refused, because a
    /// peer whose counter block we could not read is a peer we did not
    /// understand — not one whose challenge half we may use anyway.
    ///
    /// R3040 -- the counter block is no longer discarded. It is the initiator's
    /// own transmit counters, which this node must lower once for every
    /// shared-memory slice it receives, so once the echo of our challenge has
    /// checked out the handoff is opened from it. A peer that failed the echo gets
    /// none: nothing it names is written.
    pub fn recv_open_syn(&mut self, extensions: &[ExtEntryOwned]) -> bool {
        let Some(a) = self.authenticator.as_ref() else {
            return false;
        };
        let Some(body) = peer_shm_zbuf_body(extensions) else {
            return false;
        };
        let Some((bob_challenge, counters)) = decode_shm_open_syn_body(body) else {
            return false;
        };
        if bob_challenge != a.local_challenge() {
            return false;
        }
        self.open_handoff(counters);
        true
    }

    /// Step 4b, ACCEPTOR: send our counter block. zenoh `send_open_ack`.
    ///
    /// ⚠ Upstream sends this UNCONDITIONALLY once the extension is engaged —
    /// it does not consult whether `recv_open_syn` validated. wz keeps the
    /// `negotiated` gate, which is STRICTER than upstream and safe in the only
    /// direction that matters: a wz acceptor that refused the echo stays
    /// silent, so a peer cannot read our ack as agreement we never gave.
    ///
    /// R3111 -- `reliable` is whether the link is reliable, as upstream passes it
    /// (`io/zenoh-transport/src/unicast/establishment/accept.rs` @
    /// `.send_open_ack(self.link.link.is_reliable().into())`).
    pub fn send_open_ack(&self, negotiated: bool, reliable: bool) -> Option<ExtEntryOwned> {
        self.authenticator.as_ref()?;
        if !negotiated {
            return None;
        }
        encode_shm_zbuf_ext(&encode_shm_open_ack_body(self.declared_counters(reliable))).ok()
    }

    /// Step 4c, INITIATOR: the acceptor's OpenAck.
    ///
    /// ⚠ THIS IS WHERE 1.10.0 TOOK A SIGNAL AWAY. The 1.5.0 acceptor sent the
    /// literal `1` here and `recv_open_ack` refused anything else, so the ack
    /// was an explicit "I accepted your echo". 1.10.0's OpenAck carries only
    /// the counter block, and upstream's own `recv_open_ack` does no more than
    /// decode it — the initiator's SHM was already decided at InitAck, by
    /// whether it could map the acceptor's segment and the acceptor echoed the
    /// initiator's challenge.
    ///
    /// So the strongest thing this can now assert is PRESENCE plus a body that
    /// decodes. That is weaker than 1.5.0 and it is upstream's own strength.
    /// It does not open a hole for a correct wz: reaching here means
    /// `recv_init_ack` already validated the acceptor's echo of OUR challenge
    /// and read the acceptor's challenge out of its segment, so the OpenSyn we
    /// sent is right by construction and an acceptor that refused it would have
    /// to be refusing a correct echo.
    ///
    /// R3040 -- the counter block it carries is the acceptor's transmit counters,
    /// and the handoff is opened from it, in the acceptor's segment that
    /// `recv_init_ack` already mapped and checked.
    pub fn recv_open_ack(&mut self, extensions: &[ExtEntryOwned]) -> bool {
        if self.authenticator.is_none() {
            return false;
        }
        let Some(body) = peer_shm_zbuf_body(extensions) else {
            return false;
        };
        let Some(counters) = decode_shm_open_ack_body(body) else {
            return false;
        };
        self.open_handoff(counters);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The descriptor round-trips across VLE 1-byte / multi-byte field widths,
    /// including each field at the top of its width.
    #[test]
    fn descriptor_round_trips() {
        for d in [
            ShmDescriptor {
                data_len: 1,
                metadata_id: 0,
                metadata_index: 0,
                generation: 0,
            },
            ShmDescriptor {
                data_len: 63,
                metadata_id: 7,
                metadata_index: 200,
                generation: 1,
            },
            ShmDescriptor {
                data_len: 1 << 20,
                metadata_id: u16::MAX,
                metadata_index: u16::MAX,
                generation: u32::MAX,
            },
        ] {
            let wire = encode_shm_descriptor(&d);
            assert_eq!(decode_shm_descriptor(&wire), Some(d));
        }
    }

    /// R2862 — the BYTES upstream's `ShmBufInfo` codec writes: four varints in
    /// the order data_len, metadata id, metadata index, generation. Asserted
    /// as bytes, with values chosen so no two fields are equal, because a
    /// round-trip alone passes a codec that swaps two fields on both sides.
    #[test]
    fn descriptor_bytes_are_upstreams_four_varints_in_order() {
        let wire = encode_shm_descriptor(&ShmDescriptor {
            data_len: 300,
            metadata_id: 5,
            metadata_index: 9,
            generation: 2,
        });
        // 300 = 0xAC 0x02 in LEB128; the rest are one byte each.
        assert_eq!(wire, [0xAC, 0x02, 0x05, 0x09, 0x02]);
    }

    /// A truncated descriptor decodes to `None` (no panic) — the malformed-peer
    /// guard — and so does the THREE-varint form wz used to send, which is
    /// what a zenoh receiver would have been handed.
    #[test]
    fn truncated_descriptor_is_rejected() {
        let wire = encode_shm_descriptor(&ShmDescriptor {
            data_len: 4096,
            metadata_id: 0xAB,
            metadata_index: 0xCD,
            generation: 0,
        });
        assert_eq!(decode_shm_descriptor(&wire[..1]), None);
        assert_eq!(decode_shm_descriptor(&wire[..wire.len() - 1]), None);
    }

    /// Upstream reads `data_len` as a `NonZeroUsize`, so a 0 is refused rather
    /// than decoded as an empty payload; and a metadata id or index past `u16`
    /// is refused rather than truncated onto another slot.
    #[test]
    fn a_zero_length_or_an_oversized_slot_is_refused() {
        assert_eq!(decode_shm_descriptor(&[0x00, 0x01, 0x01, 0x00]), None);
        let mut too_wide = Vec::new();
        encode_vle_u64_into(&mut too_wide, 4);
        encode_vle_u64_into(&mut too_wide, 1 << 16);
        encode_vle_u64_into(&mut too_wide, 0);
        encode_vle_u64_into(&mut too_wide, 0);
        assert_eq!(decode_shm_descriptor(&too_wide), None);
    }

    /// The marker header byte is `0x02 | 0x10` (UNIT enc | id 0x02 | MANDATORY) —
    /// the shape zenoh emits for `put::ext::Shm`.
    #[test]
    fn marker_header_is_unit_id_two_mandatory() {
        let ext = encode_shm_marker_ext::<crate::wire::WireStorage>();
        assert_eq!(
            ext.header, 0x12,
            "UNIT (0x00) | SHM_BODY_EXT_ID (0x02) | M (0x10)"
        );
        assert_eq!(ext.ext_id(), SHM_BODY_EXT_ID);
        assert_eq!(
            ext.as_borrowed().encode_to_vec().len(),
            1,
            "a unit ext is one byte"
        );
    }

    /// `body_has_shm_marker` finds 0x2 and is not confused by the sibling body
    /// exts (0x1 source_info, 0x3 attachment).
    #[test]
    fn marker_detected_and_not_confused_with_siblings() {
        assert!(body_has_shm_marker(&[encode_shm_marker_ext::<
            crate::wire::WireStorage,
        >()]));
        assert!(!body_has_shm_marker::<crate::wire::parts::ExtEntryOwned>(
            &[]
        ));
        let source_info: ExtEntryOwned = ExtEntryOwned {
            header: 0x01,
            body: ExtEntryOwnedVariant::CodecZenohExtUnit(ExtUnit::default()),
        };
        let attachment: ExtEntryOwned = ExtEntryOwned {
            header: 0x03,
            body: ExtEntryOwnedVariant::CodecZenohExtUnit(ExtUnit::default()),
        };
        assert!(!body_has_shm_marker(&[source_info, attachment]));
    }

    // -----------------------------------------------------------------------
    // session-extshm (R311y507) — the challenge-response wire shapes.
    // -----------------------------------------------------------------------

    #[cfg(feature = "session-extshm")]
    mod challenge_response {
        use super::super::*;
        use alloc::vec;

        /// The two establishment headers are DISTINCT extensions at one id, and
        /// neither is wz's UNIT offer. This is the property R311y505 was written
        /// for, restated for the forms this round adds.
        ///
        /// R2240 INVERTED this test rather than deleting it. Its old form
        /// asserted THREE distinct forms and was right for 1.5.0, where the
        /// Open phase was `zextz64!` and carried its own header `0x22`. At
        /// 1.10.0 `init.rs` and `open.rs` both declare
        /// `pub type Shm = zextzbuf!(0x2, false)`, so there are TWO headers and
        /// the third distinction moved OUT of the byte and INTO the carrier.
        /// Asserting three would now be asserting something upstream does not
        /// do; what has to be pinned instead is that the collapse costs no
        /// discrimination, which is the second half below.
        #[test]
        fn two_forms_at_id_two_are_distinct_and_the_carrier_separates_the_third() {
            assert_eq!(SHM_ZBUF_EXT_HEADER, 0x42, "ZBuf enc (0x40) | id 0x2");
            assert_eq!(encode_shm_establishment_ext().header, 0x02, "UNIT | id 0x2");

            // The ZBuf form is not read as the unit offer, and vice versa.
            let init = encode_shm_zbuf_ext(&encode_shm_init_syn_body(7)).expect("fits");
            let init_header = init.header;
            assert!(!peer_offered_shm(core::slice::from_ref(&init)));
            assert_eq!(
                peer_shm_zbuf_body(&[init]).map(<[u8]>::to_vec),
                Some(vec![7])
            );
            let unit = encode_shm_establishment_ext();
            assert_eq!(peer_shm_zbuf_body(core::slice::from_ref(&unit)), None);
            assert!(peer_offered_shm(&[unit]));

            // THE COLLAPSE, stated as the property it has to keep: an Init body
            // and an Open body now carry the SAME header, so the reader cannot
            // tell them apart — and must not try. What tells them apart is which
            // chain they arrive in, and the four `ExtChainRole` slots are four
            // distinct stores. Pinned here as a byte-level equality so that a
            // future round which re-splits the headers has to come through this
            // test rather than past it.
            let open = encode_shm_zbuf_ext(&encode_shm_open_ack_body(ShmHandoffCounters::Disabled))
                .expect("fits");
            assert_eq!(open.header, init_header, "one header, both phases");
            assert!(!peer_offered_shm(core::slice::from_ref(&open)));
        }

        /// The InitSyn body is ONE VLE and nothing else — zenoh writes the bare
        /// `AuthSegmentID`, and its codec sends every unsigned integer through
        /// the same u64 VLE, so a `u32` id is not zero-padded to four bytes.
        #[test]
        fn init_syn_body_is_a_single_vle_segment_id() {
            assert_eq!(encode_shm_init_syn_body(0), vec![0x00]);
            assert_eq!(encode_shm_init_syn_body(127), vec![0x7F]);
            // 300 = 0xAC 0x02 (the 2-byte VLE boundary).
            assert_eq!(encode_shm_init_syn_body(300), vec![0xAC, 0x02]);
            for id in [0u32, 1, 127, 128, 300, 65_535, u32::MAX] {
                assert_eq!(
                    decode_shm_init_syn_body(&encode_shm_init_syn_body(id)),
                    Some(id),
                    "round trip for {id}"
                );
            }
            assert_eq!(decode_shm_init_syn_body(&[]), None, "truncated");
        }

        /// The InitAck body is `challenge` THEN `segment`, in zenoh's field
        /// order. Order is the whole content of this test: both fields are VLEs,
        /// so a swap is silent on the wire and only shows up as a peer that
        /// cannot validate the challenge.
        #[test]
        fn init_ack_body_is_challenge_then_segment() {
            // A challenge whose VLE is longer than the segment's, so a swapped
            // encoder produces a DIFFERENT byte string rather than a coincidence.
            let body = encode_shm_init_ack_body(300, 7);
            assert_eq!(body, vec![0xAC, 0x02, 0x07]);
            assert_eq!(decode_shm_init_ack_body(&body), Some((300, 7)));

            // Full-width values, including a challenge in the top half of u64
            // (a real one is a random u64, so this is the common case).
            for (c, seg) in [(0u64, 0u32), (1, 1), (u64::MAX, u32::MAX), (1 << 63, 5)] {
                assert_eq!(
                    decode_shm_init_ack_body(&encode_shm_init_ack_body(c, seg)),
                    Some((c, seg)),
                    "round trip for ({c}, {seg})"
                );
            }
            assert_eq!(decode_shm_init_ack_body(&[0xAC]), None, "truncated");
        }

        /// The Open-phase bodies round-trip, and the counter block's STATUS BYTE
        /// is a raw byte with a full band block behind `1`.
        ///
        /// R2240 replaced `open_phase_carries_a_bare_z64_challenge`, which
        /// pinned the 1.5.0 shape (one z64: the challenge, or the literal `1`).
        /// Both halves of that are gone — the encoding and the literal — so the
        /// test pins what took their place.
        #[test]
        fn open_phase_carries_a_challenge_and_a_counter_block() {
            // The alias is checked against upstream's OWN number here, which is
            // the point of keeping this line after the constant stopped
            // spelling the expression out: `Priority::NUM` drifting would
            // resize the counter block on the wire, and this is where that
            // shows up.
            assert_eq!(
                SHM_PRIORITY_BANDS, 8,
                "zenoh Priority::NUM = 1 + MIN(Background=7) - MAX(Control=0)"
            );

            // Disabled is ONE raw byte after the challenge's VLE, so the whole
            // OpenSyn for a 300-challenge is exactly three bytes.
            assert_eq!(
                encode_shm_open_syn_body(300, ShmHandoffCounters::Disabled),
                vec![0xAC, 0x02, 0x00]
            );
            assert_eq!(
                encode_shm_open_ack_body(ShmHandoffCounters::Disabled),
                vec![0x00]
            );

            for v in [0u64, 1, 300, u64::MAX] {
                for c in [
                    ShmHandoffCounters::Disabled,
                    ShmHandoffCounters::PerPriority([0, 1, 127, 128, 300, 2809, 65535, 7]),
                ] {
                    assert_eq!(
                        decode_shm_open_syn_body(&encode_shm_open_syn_body(v, c)),
                        Some((v, c)),
                        "OpenSyn round trip for ({v}, {c:?})"
                    );
                    assert_eq!(
                        decode_shm_open_ack_body(&encode_shm_open_ack_body(c)),
                        Some(c),
                        "OpenAck round trip for {c:?}"
                    );
                }
            }

            // An empty body, and a PerPrio block cut short, are both refused —
            // a partial band block must not read as a shorter one.
            assert_eq!(decode_shm_open_syn_body(&[]), None);
            assert_eq!(decode_shm_open_ack_body(&[]), None);
            let short = encode_shm_open_ack_body(ShmHandoffCounters::PerPriority([1; 8]));
            assert_eq!(decode_shm_open_ack_body(&short[..short.len() - 1]), None);

            // A challenge with no counter block at all is refused: that is the
            // 1.5.0 OpenSyn, and a peer still sending it is not a peer we can
            // read.
            assert_eq!(decode_shm_open_syn_body(&[0xAC, 0x02]), None);
        }
    }

    /// A [`ShmAuthenticator`] over an in-memory map of published segments, so
    /// the FSM can be driven both ways INCLUDING the "peer segment cannot be
    /// mapped" arm — which a test using the real /dev/shm could only reach by
    /// racing an unlink.
    #[cfg(feature = "session-extshm")]
    #[derive(Clone)]
    struct FakeAuth {
        id: u32,
        challenge: u64,
        /// What THIS node can see: (segment id -> challenge). A peer's segment
        /// missing from here is a segment this node cannot map.
        visible: alloc::vec::Vec<(u32, u64)>,
    }

    #[cfg(feature = "session-extshm")]
    impl super::ShmAuthenticator for FakeAuth {
        fn local_segment_id(&self) -> u32 {
            self.id
        }
        fn local_challenge(&self) -> u64 {
            self.challenge
        }
        fn open_peer_challenge(&self, segment_id: u32) -> Option<u64> {
            self.visible
                .iter()
                .find(|(i, _)| *i == segment_id)
                .map(|(_, c)| *c)
        }
    }

    #[cfg(feature = "session-extshm")]
    mod fsm {
        use super::super::*;
        use super::FakeAuth;
        use alloc::boxed::Box;
        use alloc::vec;

        const ALICE_ID: u32 = 11;
        const ALICE_CHALLENGE: u64 = 0xA11CE_u64;
        const BOB_ID: u32 = 22;
        const BOB_CHALLENGE: u64 = 0xB0B_u64;

        /// Both sides can map each other — the mutually-visible case.
        /// An OpenSyn ext carrying `challenge` and an empty counter block — the
        /// shape a conforming 1.10.0 peer sends, so a test that forges one
        /// forges the WHOLE message rather than the half it cares about.
        fn open_syn_ext(challenge: u64) -> ExtEntryOwned {
            encode_shm_zbuf_ext(&encode_shm_open_syn_body(
                challenge,
                ShmHandoffCounters::Disabled,
            ))
            .expect("fits")
        }

        fn pair() -> (ShmAuthDispatch, ShmAuthDispatch) {
            let alice = FakeAuth {
                id: ALICE_ID,
                challenge: ALICE_CHALLENGE,
                visible: vec![(BOB_ID, BOB_CHALLENGE)],
            };
            let bob = FakeAuth {
                id: BOB_ID,
                challenge: BOB_CHALLENGE,
                visible: vec![(ALICE_ID, ALICE_CHALLENGE)],
            };
            (
                ShmAuthDispatch::install(Box::new(alice)),
                ShmAuthDispatch::install(Box::new(bob)),
            )
        }

        /// Drive the whole four-message exchange between two dispatches, feeding
        /// each side's emitted ext to the other exactly as the wire would.
        /// Returns `(initiator_negotiated, acceptor_negotiated)`.
        fn drive(alice: &mut ShmAuthDispatch, bob: &mut ShmAuthDispatch) -> (bool, bool) {
            let init_syn: alloc::vec::Vec<_> = alice.send_init_syn().into_iter().collect();
            bob.recv_init_syn(&init_syn).expect("well-formed InitSyn");
            let init_ack: alloc::vec::Vec<_> = bob.send_init_ack().into_iter().collect();
            // The initiator's InitAck result is not the verdict: it only says
            // it could map bob's segment. Its own flag is set at OpenAck.
            let _ = alice.recv_init_ack(&init_ack);
            let open_syn: alloc::vec::Vec<_> = alice.send_open_syn(true).into_iter().collect();
            let bob_ok = bob.recv_open_syn(&open_syn);
            let open_ack: alloc::vec::Vec<_> =
                bob.send_open_ack(bob_ok, true).into_iter().collect();
            (alice.recv_open_ack(&open_ack), bob_ok)
        }

        use std::sync::{Arc, Mutex};

        /// The bands a [`ShmHandoff`] was told about, shared with the test.
        type Bands = Arc<Mutex<vec::Vec<usize>>>;

        /// Each time an authenticator was asked to open a peer's counters: which
        /// peer segment, and which counter ids it named.
        type OpenedLog = Arc<Mutex<vec::Vec<(u32, [u16; SHM_PRIORITY_BANDS])>>>;

        /// Every band a [`ShmHandoff`] built by [`HandoffAuth`] was told about.
        struct BandLog(Bands);

        impl ShmHandoff for BandLog {
            fn on_rx(&self, band: usize) {
                self.0.lock().expect("bands").push(band);
            }
        }

        /// A [`FakeAuth`] that can open a peer's counters, and remembers each time
        /// it was asked to: which peer segment and which counter ids.
        #[derive(Clone)]
        struct HandoffAuth {
            inner: FakeAuth,
            opened: OpenedLog,
            bands: Bands,
        }

        impl ShmAuthenticator for HandoffAuth {
            fn local_segment_id(&self) -> u32 {
                self.inner.local_segment_id()
            }
            fn local_challenge(&self) -> u64 {
                self.inner.local_challenge()
            }
            fn open_peer_challenge(&self, segment_id: u32) -> Option<u64> {
                self.inner.open_peer_challenge(segment_id)
            }
            fn open_peer_handoff(
                &self,
                peer_segment: u32,
                counters: &[u16; SHM_PRIORITY_BANDS],
            ) -> Option<Box<dyn ShmHandoff>> {
                self.opened
                    .lock()
                    .expect("opened")
                    .push((peer_segment, *counters));
                Some(Box::new(BandLog(self.bands.clone())))
            }
        }

        /// R3065 -- a [`FakeAuth`] that can read the protocol list of a peer's segment: the list
        /// each visible segment advertises, by segment id. A segment with no entry here is one
        /// whose list this node cannot read, which the dispatch takes as unknown.
        #[derive(Clone)]
        struct ListedAuth {
            inner: FakeAuth,
            lists: vec::Vec<(u32, vec::Vec<u32>)>,
        }

        impl ShmAuthenticator for ListedAuth {
            fn local_segment_id(&self) -> u32 {
                self.inner.local_segment_id()
            }
            fn local_challenge(&self) -> u64 {
                self.inner.local_challenge()
            }
            fn open_peer_challenge(&self, segment_id: u32) -> Option<u64> {
                self.inner.open_peer_challenge(segment_id)
            }
            fn open_peer_protocols(&self, segment_id: u32) -> Option<vec::Vec<u32>> {
                self.lists
                    .iter()
                    .find(|(id, _)| *id == segment_id)
                    .map(|(_, list)| list.clone())
            }
        }

        /// A dispatch whose peer is `(ALICE_ID or BOB_ID, challenge)` and advertises `list`.
        fn listed_node(
            id: u32,
            challenge: u64,
            peer: (u32, u64),
            list: Option<vec::Vec<u32>>,
        ) -> ShmAuthDispatch {
            ShmAuthDispatch::install(Box::new(ListedAuth {
                inner: FakeAuth {
                    id,
                    challenge,
                    visible: vec![peer],
                },
                lists: list.map(|l| vec![(peer.0, l)]).unwrap_or_default(),
            }))
        }

        /// R3065 -- THE PEER'S LIST IS READ WHEN ITS SEGMENT IS RECORDED, on both roles: the
        /// initiator reads the acceptor's on the InitAck and the acceptor the initiator's on the
        /// InitSyn. A protocol the list names is admitted and one it does not is not, and the two
        /// roles hold different lists because they hold different peers.
        #[test]
        fn each_role_reads_the_list_of_the_segment_it_maps() {
            let mut alice = listed_node(
                ALICE_ID,
                ALICE_CHALLENGE,
                (BOB_ID, BOB_CHALLENGE),
                Some(vec![0, 100500]),
            );
            let mut bob = listed_node(
                BOB_ID,
                BOB_CHALLENGE,
                (ALICE_ID, ALICE_CHALLENGE),
                Some(vec![0]),
            );
            let (a, b) = drive(&mut alice, &mut bob);
            assert!(a && b, "the handshake itself completes");
            // Alice's peer is Bob; its list names 0 and 100500.
            assert!(alice.peer_supports_protocol(0));
            assert!(alice.peer_supports_protocol(100500));
            assert!(!alice.peer_supports_protocol(7));
            // Bob's peer is Alice; its list names 0 only.
            assert!(bob.peer_supports_protocol(0));
            assert!(
                !bob.peer_supports_protocol(100500),
                "a peer whose reader has no client for the protocol cannot be sent its descriptor"
            );
        }

        /// R3065 -- an UNKNOWN list admits everything. A peer whose list cannot be read is not a
        /// peer with an empty one: withholding every descriptor from it would turn a reader this
        /// node cannot inspect into one that gets nothing, which is not what it was before.
        #[test]
        fn an_unreadable_list_admits_every_protocol() {
            let mut alice = listed_node(ALICE_ID, ALICE_CHALLENGE, (BOB_ID, BOB_CHALLENGE), None);
            let mut bob = listed_node(BOB_ID, BOB_CHALLENGE, (ALICE_ID, ALICE_CHALLENGE), None);
            let (a, b) = drive(&mut alice, &mut bob);
            assert!(a && b);
            assert!(alice.peer_supports_protocol(0));
            assert!(alice.peer_supports_protocol(100500));
            // A dispatch that never met a peer is unknown too.
            assert!(ShmAuthDispatch::empty().peer_supports_protocol(100500));
        }

        /// R3065 -- a new establishment is a new peer: the list of the last one is forgotten with
        /// its segment, so a node never filters by a peer it has moved on from.
        #[test]
        fn a_new_establishment_forgets_the_last_peers_list() {
            let mut bob = listed_node(
                BOB_ID,
                BOB_CHALLENGE,
                (ALICE_ID, ALICE_CHALLENGE),
                Some(vec![0]),
            );
            let mut alice = listed_node(ALICE_ID, ALICE_CHALLENGE, (BOB_ID, BOB_CHALLENGE), None);
            let _ = drive(&mut alice, &mut bob);
            assert!(!bob.peer_supports_protocol(100500));
            // A fresh InitSyn from a peer this node cannot map: nothing is kept.
            let stranger = encode_shm_zbuf_ext(&encode_shm_init_syn_body(9999)).expect("fits");
            bob.recv_init_syn(&[stranger]).expect("well-formed");
            assert!(
                bob.peer_supports_protocol(100500),
                "the old peer's list must not outlive its segment"
            );
        }

        /// One counter id per band, distinct, so a test that opened the wrong
        /// block or read it in the wrong order cannot pass by coincidence.
        const COUNTERS: [u16; SHM_PRIORITY_BANDS] = [40, 41, 42, 43, 44, 45, 46, 47];

        /// A dispatch for the node under test, with the log of what it opened.
        fn handoff_node(
            id: u32,
            challenge: u64,
            peer: (u32, u64),
        ) -> (ShmAuthDispatch, OpenedLog, Bands) {
            let opened = Arc::new(Mutex::new(vec![]));
            let bands = Arc::new(Mutex::new(vec![]));
            let auth = HandoffAuth {
                inner: FakeAuth {
                    id,
                    challenge,
                    visible: vec![peer],
                },
                opened: opened.clone(),
                bands: bands.clone(),
            };
            (ShmAuthDispatch::install(Box::new(auth)), opened, bands)
        }

        /// The initiator's InitSyn, taken by an ACCEPTOR that can see its segment.
        fn accept_init_syn(bob: &mut ShmAuthDispatch) {
            let (alice, _, _) = handoff_node(ALICE_ID, ALICE_CHALLENGE, (BOB_ID, BOB_CHALLENGE));
            let init_syn: vec::Vec<_> = alice.send_init_syn().into_iter().collect();
            bob.recv_init_syn(&init_syn).expect("well-formed InitSyn");
        }

        /// R3040 -- THE ACCEPTOR'S HANDOFF: the counters in the initiator's OpenSyn
        /// are the initiator's transmit counters, so they are opened in the
        /// INITIATOR'S segment, once its echo of our challenge has checked out, and
        /// the object it yields reaches the registry exactly once.
        #[test]
        fn an_acceptor_opens_the_handoff_from_the_initiators_open_syn() {
            let (mut bob, opened, bands) =
                handoff_node(BOB_ID, BOB_CHALLENGE, (ALICE_ID, ALICE_CHALLENGE));
            accept_init_syn(&mut bob);
            let open_syn = encode_shm_zbuf_ext(&encode_shm_open_syn_body(
                BOB_CHALLENGE,
                ShmHandoffCounters::PerPriority(COUNTERS),
            ))
            .expect("fits");

            assert!(bob.recv_open_syn(&[open_syn]));
            assert_eq!(
                *opened.lock().expect("opened"),
                [(ALICE_ID, COUNTERS)],
                "the initiator's segment, and the ids it named, in band order"
            );

            let update = bob.take_handoff_update();
            let handoff = update
                .expect("a handoff changed")
                .expect("and it is a new handoff");
            handoff.on_rx(5);
            assert_eq!(*bands.lock().expect("bands"), [5], "it is the one opened");
            assert!(bob.take_handoff_update().is_none(), "taken once");
        }

        /// R3040 -- an echo of the WRONG challenge opens nothing: the peer has not
        /// shown it could map our segment, so nothing it names is written.
        #[test]
        fn a_failed_echo_opens_no_handoff() {
            let (mut bob, opened, _bands) =
                handoff_node(BOB_ID, BOB_CHALLENGE, (ALICE_ID, ALICE_CHALLENGE));
            accept_init_syn(&mut bob);
            let forged = encode_shm_zbuf_ext(&encode_shm_open_syn_body(
                BOB_CHALLENGE ^ 1,
                ShmHandoffCounters::PerPriority(COUNTERS),
            ))
            .expect("fits");
            assert!(!bob.recv_open_syn(&[forged]));
            assert!(opened.lock().expect("opened").is_empty());
        }

        /// R3040 -- a counter block that names no counters opens none, which is what
        /// a zenoh sender says for a best-effort link.
        #[test]
        fn a_disabled_counter_block_opens_no_handoff() {
            let (mut bob, opened, _bands) =
                handoff_node(BOB_ID, BOB_CHALLENGE, (ALICE_ID, ALICE_CHALLENGE));
            accept_init_syn(&mut bob);
            let open_syn = encode_shm_zbuf_ext(&encode_shm_open_syn_body(
                BOB_CHALLENGE,
                ShmHandoffCounters::Disabled,
            ))
            .expect("fits");
            assert!(bob.recv_open_syn(&[open_syn]), "the proof still stands");
            assert!(opened.lock().expect("opened").is_empty());
            assert_eq!(
                bob.take_handoff_update().map(|u| u.is_none()),
                Some(true),
                "and the registry is told there is none"
            );
        }

        /// R3040 -- THE INITIATOR'S HANDOFF: the counters in the acceptor's OpenAck
        /// are the ACCEPTOR'S transmit counters, opened in the acceptor's segment
        /// that InitAck mapped.
        #[test]
        fn an_initiator_opens_the_handoff_from_the_acceptors_open_ack() {
            let (mut alice, opened, bands) =
                handoff_node(ALICE_ID, ALICE_CHALLENGE, (BOB_ID, BOB_CHALLENGE));
            let (mut bob, _, _) = handoff_node(BOB_ID, BOB_CHALLENGE, (ALICE_ID, ALICE_CHALLENGE));
            let init_syn: vec::Vec<_> = alice.send_init_syn().into_iter().collect();
            bob.recv_init_syn(&init_syn).expect("well-formed InitSyn");
            let init_ack: vec::Vec<_> = bob.send_init_ack().into_iter().collect();
            assert!(alice.recv_init_ack(&init_ack));

            let open_ack = encode_shm_zbuf_ext(&encode_shm_open_ack_body(
                ShmHandoffCounters::PerPriority(COUNTERS),
            ))
            .expect("fits");
            assert!(alice.recv_open_ack(&[open_ack]));
            assert_eq!(*opened.lock().expect("opened"), [(BOB_ID, COUNTERS)]);

            let handoff = alice
                .take_handoff_update()
                .expect("a handoff changed")
                .expect("and it is a new handoff");
            handoff.on_rx(2);
            assert_eq!(*bands.lock().expect("bands"), [2]);
        }

        // ---- the node as a SENDER (R3110) --------------------------------------------------

        /// The counters a [`TxAuth`] leased, distinct from the ones a peer names in the tests above
        /// so a block read from the wrong side cannot pass.
        const LEASED: [u16; SHM_PRIORITY_BANDS] = [900, 901, 902, 903, 904, 905, 906, 907];

        /// A transmit handoff that names [`LEASED`] and counts the times it was reset.
        struct LeasedHandoff {
            resets: Arc<Mutex<usize>>,
        }

        impl ShmTxHandoff for LeasedHandoff {
            fn counters(&self) -> [u16; SHM_PRIORITY_BANDS] {
                LEASED
            }
            fn reset(&self) {
                *self.resets.lock().expect("resets") += 1;
            }
            fn begin(&self, _band: usize) -> Box<dyn ShmTxTransaction> {
                unreachable!("these tests declare counters and send nothing")
            }
        }

        /// A [`FakeAuth`] that operates a handoff as a sender.
        #[derive(Clone)]
        struct TxAuth {
            inner: FakeAuth,
            resets: Arc<Mutex<usize>>,
        }

        impl ShmAuthenticator for TxAuth {
            fn local_segment_id(&self) -> u32 {
                self.inner.local_segment_id()
            }
            fn local_challenge(&self) -> u64 {
                self.inner.local_challenge()
            }
            fn open_peer_challenge(&self, segment_id: u32) -> Option<u64> {
                self.inner.open_peer_challenge(segment_id)
            }
            fn tx_handoff(&self) -> Option<Arc<dyn ShmTxHandoff>> {
                Some(Arc::new(LeasedHandoff {
                    resets: self.resets.clone(),
                }))
            }
        }

        fn tx_node(
            id: u32,
            challenge: u64,
            peer: (u32, u64),
        ) -> (ShmAuthDispatch, Arc<Mutex<usize>>) {
            let resets = Arc::new(Mutex::new(0));
            let auth = TxAuth {
                inner: FakeAuth {
                    id,
                    challenge,
                    visible: vec![peer],
                },
                resets: resets.clone(),
            };
            (ShmAuthDispatch::install(Box::new(auth)), resets)
        }

        /// R3110 -- THE INITIATOR'S OPEN SYN names the counters its authenticator leased, in band
        /// order, and zeroes them first: the block is the start of an establishment with a new
        /// peer.
        #[test]
        fn an_open_syn_declares_the_counters_the_authenticator_leased() {
            let (mut alice, resets) = tx_node(ALICE_ID, ALICE_CHALLENGE, (BOB_ID, BOB_CHALLENGE));
            let (mut bob, _, _) = handoff_node(BOB_ID, BOB_CHALLENGE, (ALICE_ID, ALICE_CHALLENGE));
            let init_syn: vec::Vec<_> = alice.send_init_syn().into_iter().collect();
            bob.recv_init_syn(&init_syn).expect("well-formed InitSyn");
            let init_ack: vec::Vec<_> = bob.send_init_ack().into_iter().collect();
            assert!(alice.recv_init_ack(&init_ack));

            assert!(
                alice.tx_handoff().is_none(),
                "nothing is declared before an Open message, so nothing is kept against"
            );
            let open_syn = alice
                .send_open_syn(true)
                .expect("the initiator sends an OpenSyn");
            let body = peer_shm_zbuf_body(core::slice::from_ref(&open_syn)).expect("a body");
            let (challenge, counters) = decode_shm_open_syn_body(body).expect("a counter block");
            assert_eq!(challenge, BOB_CHALLENGE, "the echo is unchanged");
            assert_eq!(counters, ShmHandoffCounters::PerPriority(LEASED));
            assert_eq!(
                *resets.lock().expect("resets"),
                1,
                "and the counters were zeroed once"
            );
            assert!(
                alice.tx_handoff().is_some(),
                "and the send path may keep against them"
            );
        }

        /// R3110 -- THE ACCEPTOR'S OPEN ACK names them too.
        #[test]
        fn an_open_ack_declares_the_counters_the_authenticator_leased() {
            let (bob, resets) = tx_node(BOB_ID, BOB_CHALLENGE, (ALICE_ID, ALICE_CHALLENGE));
            let open_ack = bob
                .send_open_ack(true, true)
                .expect("the acceptor acknowledges");
            let body = peer_shm_zbuf_body(core::slice::from_ref(&open_ack)).expect("a body");
            assert_eq!(
                decode_shm_open_ack_body(body),
                Some(ShmHandoffCounters::PerPriority(LEASED))
            );
            assert_eq!(*resets.lock().expect("resets"), 1);
            assert!(bob.tx_handoff().is_some());
        }

        /// R3111 -- ON A LINK THAT IS NOT RELIABLE both Open messages declare the block
        /// `Disabled` whatever the authenticator operates, lease and zero nothing, and leave the
        /// send path no handoff to keep against: a datagram that is lost is never acknowledged, so
        /// a counter declared on such a link is never lowered. Upstream does the same for a
        /// best-effort link.
        #[test]
        fn a_link_that_is_not_reliable_declares_the_counter_block_disabled_and_keeps_nothing() {
            let (mut alice, alice_resets) =
                tx_node(ALICE_ID, ALICE_CHALLENGE, (BOB_ID, BOB_CHALLENGE));
            let (mut bob, _, _) = handoff_node(BOB_ID, BOB_CHALLENGE, (ALICE_ID, ALICE_CHALLENGE));
            let init_syn: vec::Vec<_> = alice.send_init_syn().into_iter().collect();
            bob.recv_init_syn(&init_syn).expect("well-formed InitSyn");
            let init_ack: vec::Vec<_> = bob.send_init_ack().into_iter().collect();
            assert!(alice.recv_init_ack(&init_ack));
            let open_syn = alice
                .send_open_syn(false)
                .expect("the initiator still sends an OpenSyn");
            let body = peer_shm_zbuf_body(core::slice::from_ref(&open_syn)).expect("a body");
            let (challenge, counters) = decode_shm_open_syn_body(body).expect("a counter block");
            assert_eq!(challenge, BOB_CHALLENGE, "the echo is unchanged");
            assert_eq!(counters, ShmHandoffCounters::Disabled);
            assert_eq!(*alice_resets.lock().expect("resets"), 0, "nothing zeroed");
            assert!(alice.tx_handoff().is_none(), "and nothing kept against");

            let (acceptor, acceptor_resets) =
                tx_node(BOB_ID, BOB_CHALLENGE, (ALICE_ID, ALICE_CHALLENGE));
            let open_ack = acceptor
                .send_open_ack(true, false)
                .expect("the acceptor still acknowledges");
            let body = peer_shm_zbuf_body(core::slice::from_ref(&open_ack)).expect("a body");
            assert_eq!(
                decode_shm_open_ack_body(body),
                Some(ShmHandoffCounters::Disabled)
            );
            assert_eq!(*acceptor_resets.lock().expect("resets"), 0);
            assert!(acceptor.tx_handoff().is_none());
        }

        /// R3111 -- the declaration is per establishment, and the last one decides what the send
        /// path may keep against: counters declared and then a block declared `Disabled` on a
        /// link that is not reliable withdraw the handoff, or chunks would be kept against
        /// counters the peer was never told of.
        #[test]
        fn a_declaration_of_disabled_withdraws_the_handoff_a_declaration_of_counters_gave() {
            let (node, _) = tx_node(BOB_ID, BOB_CHALLENGE, (ALICE_ID, ALICE_CHALLENGE));
            assert!(node.tx_handoff().is_none(), "nothing is declared yet");
            node.send_open_ack(true, true).expect("a reliable link");
            assert!(node.tx_handoff().is_some());
            node.send_open_ack(true, false).expect("a link that is not");
            assert!(node.tx_handoff().is_none());
        }

        /// R3110 -- an authenticator that operates no handoff declares the block `Disabled`, which
        /// is what it declared before the handoff existed and what upstream accepts.
        #[test]
        fn an_authenticator_without_a_handoff_declares_the_counter_block_disabled() {
            let (bob, _, _) = handoff_node(BOB_ID, BOB_CHALLENGE, (ALICE_ID, ALICE_CHALLENGE));
            let open_ack = bob
                .send_open_ack(true, true)
                .expect("the acceptor acknowledges");
            let body = peer_shm_zbuf_body(core::slice::from_ref(&open_ack)).expect("a body");
            assert_eq!(
                decode_shm_open_ack_body(body),
                Some(ShmHandoffCounters::Disabled)
            );
            assert!(bob.tx_handoff().is_none());
        }

        /// R3040 -- a NEW establishment withdraws the old handoff: the registry is
        /// told it has none, so it cannot write the counters of a peer the session
        /// has moved on from.
        #[test]
        fn a_new_establishment_withdraws_the_old_handoff() {
            let (mut bob, _opened, _bands) =
                handoff_node(BOB_ID, BOB_CHALLENGE, (ALICE_ID, ALICE_CHALLENGE));
            accept_init_syn(&mut bob);
            let open_syn = encode_shm_zbuf_ext(&encode_shm_open_syn_body(
                BOB_CHALLENGE,
                ShmHandoffCounters::PerPriority(COUNTERS),
            ))
            .expect("fits");
            assert!(bob.recv_open_syn(&[open_syn]));
            assert!(matches!(bob.take_handoff_update(), Some(Some(_))));

            accept_init_syn(&mut bob);
            assert!(
                matches!(bob.take_handoff_update(), Some(None)),
                "the next peer starts with no handoff, and the registry hears it"
            );
        }

        /// R3040 -- an authenticator that cannot open a peer's counters (the
        /// default) leaves the session running exactly as it did: negotiated, with
        /// no handoff.
        #[test]
        fn an_authenticator_that_cannot_open_counters_still_negotiates() {
            let (alice, mut bob) = pair();
            let init_syn: vec::Vec<_> = alice.send_init_syn().into_iter().collect();
            bob.recv_init_syn(&init_syn).expect("well-formed InitSyn");
            // A real counter block, to an authenticator that keeps the default
            // `open_peer_handoff`: it is declined, and the proof is not.
            let open_syn = encode_shm_zbuf_ext(&encode_shm_open_syn_body(
                BOB_CHALLENGE,
                ShmHandoffCounters::PerPriority(COUNTERS),
            ))
            .expect("fits");
            assert!(
                bob.recv_open_syn(&[open_syn]),
                "the session still negotiates"
            );
            assert!(
                matches!(bob.take_handoff_update(), Some(None)),
                "with no handoff to acknowledge through"
            );
        }

        /// The happy path: both sides finish NEGOTIATED, and each one's flag was
        /// set by an echo only the other could have produced.
        #[test]
        fn a_mutually_mappable_pair_negotiates_shm() {
            let (mut alice, mut bob) = pair();
            assert_eq!(drive(&mut alice, &mut bob), (true, true));
        }

        /// The ACCEPTOR cannot map the initiator's segment (same-host claim,
        /// different namespace / already unlinked). It then sends NO `Shm` back
        /// at all, so the initiator gets nothing to validate and both ends up
        /// without SHM — with the session otherwise intact.
        #[test]
        fn an_unmappable_initiator_segment_yields_no_shm_on_both_sides() {
            let alice = FakeAuth {
                id: ALICE_ID,
                challenge: ALICE_CHALLENGE,
                visible: vec![(BOB_ID, BOB_CHALLENGE)],
            };
            let bob = FakeAuth {
                id: BOB_ID,
                challenge: BOB_CHALLENGE,
                visible: vec![], // cannot see alice
            };
            let mut alice = ShmAuthDispatch::install(Box::new(alice));
            let mut bob = ShmAuthDispatch::install(Box::new(bob));
            assert!(bob.send_init_ack().is_none(), "nothing to echo");
            assert_eq!(drive(&mut alice, &mut bob), (false, false));
        }

        /// The reverse blindness: the ACCEPTOR maps fine, the INITIATOR cannot
        /// map the acceptor's segment. The initiator has nothing to answer with,
        /// so the acceptor's own check fails and neither side negotiates.
        #[test]
        fn an_unmappable_acceptor_segment_yields_no_shm_on_both_sides() {
            let alice = FakeAuth {
                id: ALICE_ID,
                challenge: ALICE_CHALLENGE,
                visible: vec![], // cannot see bob
            };
            let bob = FakeAuth {
                id: BOB_ID,
                challenge: BOB_CHALLENGE,
                visible: vec![(ALICE_ID, ALICE_CHALLENGE)],
            };
            let mut alice = ShmAuthDispatch::install(Box::new(alice));
            let mut bob = ShmAuthDispatch::install(Box::new(bob));
            assert_eq!(drive(&mut alice, &mut bob), (false, false));
            assert!(
                alice.send_open_syn(true).is_none(),
                "no challenge to answer with"
            );
        }

        /// THE POINT OF THE WHOLE EXCHANGE: a peer that merely CLAIMS shared
        /// memory — well-formed messages, plausible ids, but a challenge it did
        /// not read out of our segment — is refused. Without this, the protocol
        /// would be a capability flag with extra steps.
        #[test]
        fn a_peer_that_guesses_the_challenge_is_refused() {
            let (mut alice, _) = pair();
            let init_syn: alloc::vec::Vec<_> = alice.send_init_syn().into_iter().collect();
            assert!(!init_syn.is_empty());

            // A forged InitAck: correct SHAPE, correct bob segment, WRONG echo.
            let forged =
                encode_shm_zbuf_ext(&encode_shm_init_ack_body(ALICE_CHALLENGE ^ 1, BOB_ID))
                    .expect("fits");
            assert!(
                !alice.recv_init_ack(&[forged]),
                "an echo that is not our challenge proves nothing"
            );
            assert!(alice.send_open_syn(true).is_none());

            // And the acceptor side refuses a forged OpenSyn the same way.
            let (_, mut bob) = pair();
            assert!(
                !bob.recv_open_syn(&[open_syn_ext(BOB_CHALLENGE ^ 1)]),
                "a wrong echo on OpenSyn must not negotiate"
            );
            assert!(bob.recv_open_syn(&[open_syn_ext(BOB_CHALLENGE)]));
        }

        /// The acceptor's ack is a COUNTER BLOCK, and the initiator accepts a
        /// present, well-formed one — no more, because 1.10.0 left no more on
        /// the wire.
        ///
        /// R2240 replaced `the_open_ack_must_be_the_literal_one`, whose whole
        /// subject (the literal `1`, and `recv_open_ack` refusing anything
        /// else) upstream deleted. What can still be pinned, and is:
        ///   * ABSENCE is refused — the arm that keeps a peer doing no SHM from
        ///     being read as agreement;
        ///   * a MALFORMED body is refused — the arm that replaces "wrong
        ///     value", and the only discrimination the new shape affords;
        ///   * wz's acceptor stays SILENT when it did not negotiate, which is
        ///     stricter than upstream's unconditional `send_open_ack`.
        #[test]
        fn the_open_ack_is_a_counter_block_and_absence_is_refused() {
            let (mut alice, bob) = pair();
            assert!(
                bob.send_open_ack(false, true).is_none(),
                "not negotiated, no ack"
            );
            let ack = bob.send_open_ack(true, true).expect("negotiated");
            assert!(alice.recv_open_ack(core::slice::from_ref(&ack)));
            assert!(!alice.recv_open_ack(&[]), "absence is not agreement");
            // A PerPrio block cut one byte short: present, right header, and
            // still refused.
            let full = encode_shm_open_ack_body(ShmHandoffCounters::PerPriority([1; 8]));
            let truncated = encode_shm_zbuf_ext(&full[..full.len() - 1]).expect("fits");
            assert!(!alice.recv_open_ack(&[truncated]));
            // ...and the 1.5.0 ack, a bare z64 `1`, no longer parses as one:
            // its body is a single byte that the counter reader sees as a
            // PerPrio status with no block behind it.
            let legacy = encode_shm_zbuf_ext(&[0x01]).expect("fits");
            assert!(!alice.recv_open_ack(&[legacy]));
        }

        /// A node with no authenticator emits NOTHING and negotiates nothing —
        /// zenoh's `auth_shm: None` arm, byte-identical to a peer that does no
        /// SHM at all.
        #[test]
        fn an_empty_dispatch_is_inert() {
            let mut empty = ShmAuthDispatch::empty();
            assert!(!empty.is_installed());
            assert!(empty.send_init_syn().is_none());
            assert!(empty.send_init_ack().is_none());
            assert!(empty.send_open_syn(true).is_none());
            assert!(empty.send_open_ack(true, true).is_none());

            // ...and it ignores a fully valid peer exchange rather than half-
            // completing one.
            let (mut alice, _) = pair();
            assert_eq!(drive(&mut alice, &mut empty), (false, false));
        }

        /// A malformed InitSyn body is the ONE hard error: zenoh `bail!`s there
        /// while every other failure degrades. Pinned so the asymmetry cannot be
        /// "tidied" into uniform degradation.
        #[test]
        fn a_malformed_init_syn_is_the_one_hard_error() {
            let (_, mut bob) = pair();
            // An `Shm` ZBuf whose body is an empty (truncated) VLE.
            let bad = encode_shm_zbuf_ext(&[]).expect("fits");
            assert_eq!(
                bob.recv_init_syn(&[bad]),
                Err(ShmAuthError::MalformedInitSyn)
            );
            // Whereas the initiator's mirror of the same class merely says no.
            let (mut alice, _) = pair();
            assert!(!alice.recv_init_ack(&[encode_shm_zbuf_ext(&[]).expect("fits")]));
        }
    }
}
