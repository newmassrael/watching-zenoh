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
//! 1.10.0 replaced the flat `zenoh-transport/src/shm.rs` with `common/shm/`).
//!
//! This module is the no_std SHM machinery: the descriptor type + its VLE codec,
//! the 0x2 Put-body marker codec, and the [`ShmResolver`] trait seam. The actual
//! POSIX segment (create / mmap / open) is `std` (mmap = libc), so it lives in
//! `wz-runtime-tokio::shm_provider` behind this trait — the same no_std-core /
//! AP-runtime split as the tls / quic config. SCOPED: wz collapses zenoh's
//! `MetadataDescriptor{id:u16, index:u16}` (a slot within a watchdog metadata
//! segment) to a single `segment_id` (one segment per payload, no pool), and the
//! receiver copies the bytes out of the mmap into the owned Sample payload (wz's
//! Sample is an owned `Vec`, so the wire is zero-copy but the local Sample is a
//! single copy off the shared page — the bounded scoped characteristic).
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

/// The scoped wz SHM descriptor: the wire stand-in for an SHM-backed payload. A
/// `segment_id` (the POSIX shm object name the receiver re-opens), the payload
/// `length`, and a `generation` (zenoh's buffer version; always 0 in the scoped
/// one-segment-per-payload model — reserved for an R3b+ pool).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShmDescriptor {
    pub segment_id: u32,
    pub length: u32,
    pub generation: u32,
}

/// Encode the descriptor as the Put payload stand-in: `VLE(length) ++
/// VLE(segment_id) ++ VLE(generation)`, the field order mirroring zenoh's
/// `ShmBufInfo` write (data_len first). Uses the [`crate::vle`] SSOT.
pub fn encode_shm_descriptor(d: &ShmDescriptor) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    encode_vle_u64_into(&mut out, d.length as u64);
    encode_vle_u64_into(&mut out, d.segment_id as u64);
    encode_vle_u64_into(&mut out, d.generation as u64);
    out
}

/// Decode a descriptor from a Put payload field that carried the `ext_shm`
/// marker. `None` on truncation or a value past `u32` (a malformed peer — the
/// caller rejects).
pub fn decode_shm_descriptor(bytes: &[u8]) -> Option<ShmDescriptor> {
    let (length, n0) = read_vle_u64(bytes)?;
    let (segment_id, n1) = read_vle_u64(bytes.get(n0..)?)?;
    let (generation, _n2) = read_vle_u64(bytes.get(n0 + n1..)?)?;
    Some(ShmDescriptor {
        segment_id: u32::try_from(segment_id).ok()?,
        length: u32::try_from(length).ok()?,
        generation: u32::try_from(generation).ok()?,
    })
}

/// Build the Put-body `ext_shm` UNIT marker (header `0x02 | M` — zenoh sets the
/// MANDATORY bit, `put.rs:73 zextunit!(0x2, true)`, so a peer that does not
/// understand SHM rejects the Put rather than reading the descriptor as payload).
/// The surrounding body-ext codec applies the chain-continuation `Z` bit.
pub fn encode_shm_marker_ext() -> ExtEntryOwned {
    ExtEntryOwned {
        header: SHM_BODY_EXT_ID | EXT_FLAG_M,
        body: ExtEntryOwnedVariant::CodecZenohExtUnit(ExtUnit::default()),
    }
}

/// `true` iff a Put body ext chain carries the `ext_shm` marker — the RX signal
/// that the payload field is a descriptor to resolve (not raw bytes). Detects by
/// id (the [`crate::unit_ext`] mechanism), so the marker's M bit is ignored.
pub fn body_has_shm_marker(extensions: &[ExtEntryOwned]) -> bool {
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

/// zenoh's `HandoffCounterIds` (`HandoffConfig<ShmCounterID>`) — the SHM
/// back-pressure counter block that 1.10.0 added to BOTH Open-phase messages.
///
/// wz declares [`Self::Disabled`], which is the arm upstream itself picks for a
/// `BestEffort` link and which its `RxHandoffChannel::new_rx` accepts without
/// touching a counter. That is a truthful declaration rather than a shortcut:
/// wz operates no handoff counters, so naming indices into a counter array it
/// never decrements would be the claim that is false.
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
}

/// The no_std/std seam: an SHM-backed Put's descriptor is resolved to its bytes
/// by an AP-injected resolver (the `std` mmap-open lives in
/// `wz-runtime-tokio::shm_provider`, behind this trait). `None` when the segment
/// cannot be opened / mapped (a stale or foreign descriptor — the caller drops
/// the Sample). Used on the RX path (R3b wires it onto the subscriber registry).
pub trait ShmResolver {
    /// Open the descriptor's segment and copy its `length` bytes out (the bounded
    /// scoped copy off the shared page into wz's owned Sample payload).
    fn resolve(&self, descriptor: &ShmDescriptor) -> Option<Vec<u8>>;
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
/// @ `pub(crate) struct ShmFsm`; 1.10.0 split the old single `ext/shm.rs` into
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
        }
    }

    /// Install this node's authenticator (its own published segment plus the
    /// ability to map a peer's). Once installed, the four steps below start
    /// emitting.
    pub fn install(authenticator: alloc::boxed::Box<dyn ShmAuthenticator + Send + Sync>) -> Self {
        Self {
            authenticator: Some(authenticator),
            peer_challenge: None,
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
        self.peer_challenge = None;
        let Some(a) = self.authenticator.as_ref() else {
            return Ok(());
        };
        let Some(body) = peer_shm_zbuf_body(extensions) else {
            return Ok(());
        };
        let alice_segment = decode_shm_init_syn_body(body).ok_or(ShmAuthError::MalformedInitSyn)?;
        self.peer_challenge = a.open_peer_challenge(alice_segment);
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
        self.peer_challenge = None;
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
        self.peer_challenge.is_some()
    }

    /// Step 3b, INITIATOR: answer with the challenge we read out of the
    /// acceptor's segment, plus our counter block. zenoh `send_open_syn`.
    pub fn send_open_syn(&self) -> Option<ExtEntryOwned> {
        self.authenticator.as_ref()?;
        encode_shm_zbuf_ext(&encode_shm_open_syn_body(
            self.peer_challenge?,
            ShmHandoffCounters::Disabled,
        ))
        .ok()
    }

    /// Step 4a, ACCEPTOR: check the initiator echoed OUR challenge. zenoh
    /// `recv_open_syn`, whose `self.inner.validate(open_syn.bob_challenge, ..)`
    /// is the same comparison. `true` here is what keeps the accept side's flag.
    ///
    /// The counter block is decoded and DISCARDED rather than ignored: a body
    /// that does not parse as `challenge ++ counters` is refused, because a
    /// peer whose counter block we could not read is a peer we did not
    /// understand — not one whose challenge half we may use anyway.
    pub fn recv_open_syn(&self, extensions: &[ExtEntryOwned]) -> bool {
        let Some(a) = self.authenticator.as_ref() else {
            return false;
        };
        let Some(body) = peer_shm_zbuf_body(extensions) else {
            return false;
        };
        let Some((bob_challenge, _counters)) = decode_shm_open_syn_body(body) else {
            return false;
        };
        bob_challenge == a.local_challenge()
    }

    /// Step 4b, ACCEPTOR: send our counter block. zenoh `send_open_ack`.
    ///
    /// ⚠ Upstream sends this UNCONDITIONALLY once the extension is engaged —
    /// it does not consult whether `recv_open_syn` validated. wz keeps the
    /// `negotiated` gate, which is STRICTER than upstream and safe in the only
    /// direction that matters: a wz acceptor that refused the echo stays
    /// silent, so a peer cannot read our ack as agreement we never gave.
    pub fn send_open_ack(&self, negotiated: bool) -> Option<ExtEntryOwned> {
        self.authenticator.as_ref()?;
        if !negotiated {
            return None;
        }
        encode_shm_zbuf_ext(&encode_shm_open_ack_body(ShmHandoffCounters::Disabled)).ok()
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
    pub fn recv_open_ack(&self, extensions: &[ExtEntryOwned]) -> bool {
        if self.authenticator.is_none() {
            return false;
        }
        let Some(body) = peer_shm_zbuf_body(extensions) else {
            return false;
        };
        decode_shm_open_ack_body(body).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The descriptor round-trips across VLE 1-byte / multi-byte field widths.
    #[test]
    fn descriptor_round_trips() {
        for d in [
            ShmDescriptor {
                segment_id: 0,
                length: 0,
                generation: 0,
            },
            ShmDescriptor {
                segment_id: 7,
                length: 63,
                generation: 1,
            },
            ShmDescriptor {
                segment_id: 0xDEAD_BEEF,
                length: 1 << 20,
                generation: 0,
            },
        ] {
            let wire = encode_shm_descriptor(&d);
            assert_eq!(decode_shm_descriptor(&wire), Some(d));
        }
    }

    /// A truncated descriptor decodes to `None` (no panic) — the malformed-peer
    /// guard.
    #[test]
    fn truncated_descriptor_is_rejected() {
        let wire = encode_shm_descriptor(&ShmDescriptor {
            segment_id: 0xABCD,
            length: 4096,
            generation: 0,
        });
        assert_eq!(decode_shm_descriptor(&wire[..1]), None);
    }

    /// The marker header byte is `0x02 | 0x10` (UNIT enc | id 0x02 | MANDATORY) —
    /// the shape zenoh emits for `put::ext::Shm`.
    #[test]
    fn marker_header_is_unit_id_two_mandatory() {
        let ext = encode_shm_marker_ext();
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
        assert!(body_has_shm_marker(&[encode_shm_marker_ext()]));
        assert!(!body_has_shm_marker(&[]));
        let source_info = ExtEntryOwned {
            header: 0x01,
            body: ExtEntryOwnedVariant::CodecZenohExtUnit(ExtUnit::default()),
        };
        let attachment = ExtEntryOwned {
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
            let open_syn: alloc::vec::Vec<_> = alice.send_open_syn().into_iter().collect();
            let bob_ok = bob.recv_open_syn(&open_syn);
            let open_ack: alloc::vec::Vec<_> = bob.send_open_ack(bob_ok).into_iter().collect();
            (alice.recv_open_ack(&open_ack), bob_ok)
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
                alice.send_open_syn().is_none(),
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
            assert!(alice.send_open_syn().is_none());

            // And the acceptor side refuses a forged OpenSyn the same way.
            let (_, bob) = pair();
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
            let (alice, bob) = pair();
            assert!(bob.send_open_ack(false).is_none(), "not negotiated, no ack");
            let ack = bob.send_open_ack(true).expect("negotiated");
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
            assert!(empty.send_open_syn().is_none());
            assert!(empty.send_open_ack(true).is_none());

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
