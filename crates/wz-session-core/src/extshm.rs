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
pub const SHM_ESTABLISHMENT_EXT_ID: u8 = 0x02;

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
}
