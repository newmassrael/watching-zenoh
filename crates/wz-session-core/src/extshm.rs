// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//! the payload directly from /dev/shm (`io/zenoh-transport/src/shm.rs:149-163`).
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
pub const SHM_BODY_EXT_ID: u8 = 0x02;

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
/// Shm ext space, `commons/zenoh-protocol/src/transport/init.rs:149`). SCOPED: wz
/// negotiates SHM with a UNIT capability ext (offer / reflect / `&=`, the
/// lowlatency / compression pattern), NOT zenoh's ZBuf-on-Init / z64-on-Open
/// CHALLENGE-RESPONSE (which additionally proves both peers can MAP each other's
/// segment). The challenge-response + cross-impl are a disclosed deferral — for
/// same-host trusted peers the capability AND-merge correctly gates the data
/// path. No M bit (a non-SHM peer drops the offer silently).
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
// session-extshm (R311y507) — zenoh's ZBuf-on-Init / z64-on-Open CHALLENGE-
// RESPONSE. The wire half; the POSIX auth segment behind it is `std` and lives
// in `wz-runtime-tokio::shm_auth_segment`, reached through [`ShmAuthenticator`].
// ---------------------------------------------------------------------------

/// The encoded header of `init::ext::Shm` — `zextzbuf!(0x2, false)`
/// (`transport/init.rs:152`), i.e. id `0x2` with the ZBuf encoding bits. A
/// DIFFERENT extension from the UNIT offer at the same 4-bit id, which is the
/// whole point of matching on [`crate::ext_header::ext_eid`] rather than the id
/// field (R311y505 measured wz reading one as the other).
#[cfg(feature = "session-extshm")]
pub const SHM_INIT_EXT_HEADER: u8 = SHM_ESTABLISHMENT_EXT_ID | crate::ext_header::EXT_ENC_ZBUF;

/// The encoded header of `open::ext::Shm` — `zextz64!(0x2, false)`. The Open
/// phase carries a bare challenge (initiator) or the literal `1` (acceptor), so
/// it is a z64 rather than a ZBuf.
#[cfg(feature = "session-extshm")]
pub const SHM_OPEN_EXT_HEADER: u8 = SHM_ESTABLISHMENT_EXT_ID | crate::ext_header::EXT_ENC_Z64;

/// The value the acceptor puts in its OpenAck `Shm` ext to confirm the
/// negotiation — zenoh `send_open_ack`: `Some(open::ext::Shm::new(1))`, and
/// `recv_open_ack` rejects anything else (`if ext.value != 1`).
#[cfg(feature = "session-extshm")]
pub const SHM_OPEN_ACK_VALUE: u64 = 1;

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

/// Wrap an Init-phase body in the `init::ext::Shm` ZBuf ext entry (header
/// `0x42`). Fallible only because the owned ZBuf copy re-checks its inline
/// capacity, the same bound decode enforces.
#[cfg(feature = "session-extshm")]
pub fn encode_shm_init_ext(body: &[u8]) -> Result<ExtEntryOwned, CodecError> {
    Ok(ExtEntryOwned {
        header: SHM_INIT_EXT_HEADER,
        body: ExtEntryOwnedVariant::CodecZenohExtZbuf(ExtZbufOwned {
            value_len: body.len() as u64,
            value: crate::codec_owned::owned_bytes(body)?,
        }),
    })
}

/// Read the `init::ext::Shm` ZBuf body out of an Init ext chain, matching on the
/// full extension IDENTITY so wz's own UNIT offer at the same id is never
/// mistaken for it.
#[cfg(feature = "session-extshm")]
pub fn peer_shm_init_body(extensions: &[ExtEntryOwned]) -> Option<&[u8]> {
    extensions
        .iter()
        .find(|e| crate::ext_header::ext_eid(e.header) == SHM_INIT_EXT_HEADER)
        .and_then(|e| match &e.body {
            ExtEntryOwnedVariant::CodecZenohExtZbuf(z) => Some(z.value.as_slice()),
            _ => None,
        })
}

/// Build the Open-phase `open::ext::Shm` z64 ext (header `0x22`) carrying
/// `value` — the peer's challenge on OpenSyn, [`SHM_OPEN_ACK_VALUE`] on OpenAck.
#[cfg(feature = "session-extshm")]
pub fn encode_shm_open_ext(value: u64) -> ExtEntryOwned {
    use wz_codecs::ext_zint::ExtZint;
    ExtEntryOwned {
        header: SHM_OPEN_EXT_HEADER,
        body: ExtEntryOwnedVariant::CodecZenohExtZint(ExtZint { value }),
    }
}

/// Read the `open::ext::Shm` z64 value out of an Open ext chain.
#[cfg(feature = "session-extshm")]
pub fn peer_shm_open_value(extensions: &[ExtEntryOwned]) -> Option<u64> {
    extensions
        .iter()
        .find(|e| crate::ext_header::ext_eid(e.header) == SHM_OPEN_EXT_HEADER)
        .and_then(|e| match &e.body {
            ExtEntryOwnedVariant::CodecZenohExtZint(z) => Some(z.value),
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
/// (`io/zenoh-transport/src/unicast/establishment/ext/shm.rs`) as a plain
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
/// 4. **OpenAck** — the acceptor checks that second echo and confirms with the
///    literal `1`.
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
        encode_shm_init_ext(&encode_shm_init_syn_body(a.local_segment_id())).ok()
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
        let Some(body) = peer_shm_init_body(extensions) else {
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
        encode_shm_init_ext(&encode_shm_init_ack_body(
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
        let Some(body) = peer_shm_init_body(extensions) else {
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
    /// acceptor's segment. zenoh `send_open_syn`.
    pub fn send_open_syn(&self) -> Option<ExtEntryOwned> {
        self.authenticator.as_ref()?;
        Some(encode_shm_open_ext(self.peer_challenge?))
    }

    /// Step 4a, ACCEPTOR: check the initiator echoed OUR challenge. zenoh
    /// `recv_open_syn`; `true` here is what sets `negotiated_to_use_shm` on the
    /// accept side.
    pub fn recv_open_syn(&self, extensions: &[ExtEntryOwned]) -> bool {
        let Some(a) = self.authenticator.as_ref() else {
            return false;
        };
        peer_shm_open_value(extensions) == Some(a.local_challenge())
    }

    /// Step 4b, ACCEPTOR: confirm with the literal `1`, and only when the
    /// exchange actually completed. zenoh `send_open_ack`.
    pub fn send_open_ack(&self, negotiated: bool) -> Option<ExtEntryOwned> {
        self.authenticator.as_ref()?;
        negotiated.then(|| encode_shm_open_ext(SHM_OPEN_ACK_VALUE))
    }

    /// Step 4c, INITIATOR: the acceptor's confirmation. zenoh `recv_open_ack`
    /// accepts ONLY the literal `1` (`if ext.value != 1`), so this is where the
    /// open side finally sets its own flag.
    pub fn recv_open_ack(&self, extensions: &[ExtEntryOwned]) -> bool {
        self.authenticator.is_some() && peer_shm_open_value(extensions) == Some(SHM_OPEN_ACK_VALUE)
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
        #[test]
        fn the_three_forms_at_id_two_are_distinct() {
            assert_eq!(SHM_INIT_EXT_HEADER, 0x42, "ZBuf enc (0x40) | id 0x2");
            assert_eq!(SHM_OPEN_EXT_HEADER, 0x22, "Z64 enc (0x20) | id 0x2");
            assert_eq!(encode_shm_establishment_ext().header, 0x02, "UNIT | id 0x2");

            // The ZBuf form is not read as the unit offer, nor as the z64 form.
            let init = encode_shm_init_ext(&encode_shm_init_syn_body(7)).expect("fits");
            assert!(!peer_offered_shm(core::slice::from_ref(&init)));
            assert_eq!(peer_shm_open_value(core::slice::from_ref(&init)), None);
            assert_eq!(
                peer_shm_init_body(&[init]).map(<[u8]>::to_vec),
                Some(vec![7])
            );

            // ...and the z64 form is not read as either of the other two.
            let open = encode_shm_open_ext(SHM_OPEN_ACK_VALUE);
            assert!(!peer_offered_shm(core::slice::from_ref(&open)));
            assert_eq!(peer_shm_init_body(core::slice::from_ref(&open)), None);
            assert_eq!(peer_shm_open_value(&[open]), Some(1));
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

        /// The Open-phase value round-trips, and the OpenAck constant is the
        /// literal `1` zenoh checks for (`recv_open_ack`: `if ext.value != 1`).
        #[test]
        fn open_phase_carries_a_bare_z64_challenge() {
            assert_eq!(SHM_OPEN_ACK_VALUE, 1);
            for v in [0u64, 1, 300, u64::MAX] {
                assert_eq!(peer_shm_open_value(&[encode_shm_open_ext(v)]), Some(v));
            }
            assert_eq!(peer_shm_open_value(&[]), None);
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
                encode_shm_init_ext(&encode_shm_init_ack_body(ALICE_CHALLENGE ^ 1, BOB_ID))
                    .expect("fits");
            assert!(
                !alice.recv_init_ack(&[forged]),
                "an echo that is not our challenge proves nothing"
            );
            assert!(alice.send_open_syn().is_none());

            // And the acceptor side refuses a forged OpenSyn the same way.
            let (_, bob) = pair();
            assert!(
                !bob.recv_open_syn(&[encode_shm_open_ext(BOB_CHALLENGE ^ 1)]),
                "a wrong echo on OpenSyn must not negotiate"
            );
            assert!(bob.recv_open_syn(&[encode_shm_open_ext(BOB_CHALLENGE)]));
        }

        /// The acceptor confirms with the literal 1 and the initiator accepts
        /// ONLY that (zenoh `recv_open_ack`: `if ext.value != 1`). A peer that
        /// echoes something else — including our own challenge — is refused.
        #[test]
        fn the_open_ack_must_be_the_literal_one() {
            let (alice, bob) = pair();
            assert!(bob.send_open_ack(false).is_none(), "not negotiated, no ack");
            let ack = bob.send_open_ack(true).expect("negotiated");
            assert!(alice.recv_open_ack(core::slice::from_ref(&ack)));
            assert!(!alice.recv_open_ack(&[encode_shm_open_ext(0)]));
            assert!(!alice.recv_open_ack(&[encode_shm_open_ext(ALICE_CHALLENGE)]));
            assert!(!alice.recv_open_ack(&[]));
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
            let bad = encode_shm_init_ext(&[]).expect("fits");
            assert_eq!(
                bob.recv_init_syn(&[bad]),
                Err(ShmAuthError::MalformedInitSyn)
            );
            // Whereas the initiator's mirror of the same class merely says no.
            let (mut alice, _) = pair();
            assert!(!alice.recv_init_ack(&[encode_shm_init_ext(&[]).expect("fits")]));
        }
    }
}
