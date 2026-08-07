// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! SSOT for the Z_EXT_QOS establishment extension wire shape (`transport-qos`).
//!
//! zenoh negotiates the QoS transport (per-(priority,reliability) SN conduits)
//! via ext id `0x1` on the Init transport message, in ONE of two mutually
//! exclusive forms (`commons/zenoh-protocol/src/transport/init.rs:146-147`):
//!   - `pub type QoS = zextunit!(0x1, false)` — the presence-only UNIT form a
//!     peer with QoS enabled but NO per-link priority/reliability metadata sends;
//!   - `pub type QoSLink = zextz64!(0x1, false)` — the z64 form a peer with
//!     `#priorities=` / `#reliability=` endpoint metadata sends (the packed
//!     priority-range + reliability), NEVER alongside the unit.
//! Both mean `is_qos = true`; only the absence of BOTH is `NoQoS`
//! (`io/zenoh-transport/src/unicast/establishment/ext/qos.rs`
//! `try_from_exts`). The capability is negotiated by AND of both sides — if
//! EITHER peer is `NoQoS` the result is `NoQoS` (the `else { NoQoS }` arm in
//! `recv_init_syn` / `recv_init_ack`).
//!
//! wz EMITS the presence-only UNIT form (`0x1`, ENC_UNIT, no body — byte-
//! identical to what a default `qos`-on zenohd sends). wz DECODE tolerates BOTH:
//! [`peer_offered_qos`] matches ext id `0x1` regardless of the encoding nibble
//! (`ext_id() = header & 0x0F` masks ENC_Z64 `0x20` and the M bit off), so a
//! priority-configured zenohd advertising `QoSLink` is correctly read as
//! `is_qos = true` and its z64 body is length-skipped by the generic
//! `crate::ext_chain::decode_ext_chain` (no Init ext-chain desync). The
//! `QoSLink` PRIORITY-RANGE semantics (the per-link `select` config) are
//! deferred to the wz<->zenohd priority-range interop follow-on (S4); here
//! `is_qos` decides only "per-priority conduits: `Priority::NUM` vs 1".
//!
//! This module is the codec LAYER only — the `(0x1, ENC_UNIT, empty body)`
//! envelope on Init, plus the presence projector the establishment demux
//! (`crate::drive::dispatch_link_event`) feeds the inbound ext chain into. The
//! per-session `is_qos` state, the offer staging into the Init role ext chains,
//! the `&=` merge, and the QoS conduit / Frame `ext_qos` data path live in
//! [`crate::session_actions`] / [`crate::drive`]. It mirrors the
//! [`crate::extlowlatency`] precedent (a distinct establishment ext on the same
//! Init carrier, its own SSOT because QoS is a distinct id-`0x1` slot).
//!
//! QoS exclusivity: zenoh forbids `is_qos && is_lowlatency`
//! (`io/zenoh-transport/src/unicast/manager.rs:264`
//! `bail!("'qos' and 'lowlatency' options are incompatible")`). The guard lives
//! at the offer-injection point (`SessionLinkActions::set_qos_offer` refuses the
//! QoS offer when a lowlatency offer is already staged), NOT in this codec.

use wz_codecs::ext_entry::ExtEntryOwned;

use crate::unit_ext::{chain_has_ext_eid, encode_unit_ext};

/// Z_EXT_QOS ext id on the Init establishment message — zenoh
/// `init.rs:146-147` `zextunit!(0x1, false)` (unit) XOR `zextz64!(0x1, false)`
/// (link). The establishment messages have their own ext id space (0x1 QoS,
/// 0x2 Shm, 0x3 Auth, 0x4 MultiLink, 0x5 LowLatency, 0x6 Compression,
/// 0x7 Patch).
pub const QOS_EXT_ID: u8 = crate::ext_header::establishment_ext_id::QOS;

/// Build the Z_EXT_QOS `ExtEntry`: the presence-only UNIT marker wz advertises
/// (the [`crate::unit_ext`] mechanism at the QoS id). zenoh
/// `State::QoS { priorities: None, reliability: None } -> Some(QoS::new())` =
/// `zextunit!(0x1)`; the surrounding [`crate::ext_chain::encode_ext_chain`]
/// applies the chain-continuation `Z` bit. wz never emits `QoSLink` (the z64
/// priority-range form) — it carries no per-link endpoint metadata yet (S4).
pub fn encode_qos_ext() -> ExtEntryOwned {
    encode_unit_ext(QOS_EXT_ID)
}

/// Project the peer's QoS capability from an establishment ext chain: `true`
/// iff the chain carries EITHER `zextunit!(0x1)` (header `0x01`) or
/// `zextz64!(0x1)` (`QoSLink`, header `0x21`). The merge side
/// (`SessionLinkActions::negotiate_qos_against_peer`) ANDs this against the local
/// offer, reproducing zenoh's "both sides QoS or NoQoS" (`is_qos &= peer_offered`).
///
/// R311y505 — the two forms are now named EXPLICITLY. They used to be accepted as
/// a side effect of matching on the 4-bit id field alone, which is a different
/// claim: it accepts anything at id 0x1 in any encoding, present or future. Here
/// the acceptance is deliberate and bounded, because zenoh's QoS genuinely IS a
/// dual ext whose two forms both mean "this peer does QoS"
/// (`transport/init.rs:147-148`, unit XOR z64 with superset/subset containment).
///
/// That reasoning does NOT generalise, which is why the loose match had to go:
/// zenoh's `Shm` at id 0x2 is a ZBuf CHALLENGE, not a second spelling of a
/// capability marker, and reading it as one made wz negotiate SHM with a peer
/// that had issued a challenge wz cannot answer (measured against a real
/// `zenohd --features shared-memory`).
pub fn peer_offered_qos(extensions: &[ExtEntryOwned]) -> bool {
    chain_has_ext_eid(extensions, QOS_EXT_ID)
        || chain_has_ext_eid(extensions, QOS_EXT_ID | crate::ext_header::EXT_ENC_Z64)
}

// ---------------------------------------------------------------------------
// session-extqos (R311y506) — the z64 `QoSLink` form: per-link priority-range +
// reliability metadata, and the directional containment that negotiates it.
// ---------------------------------------------------------------------------

/// The encoded header of `init::ext::QoSLink` — `zextz64!(0x1, false)`, i.e.
/// id `0x1` with the Z64 encoding bits and no mandatory flag. Distinct from the
/// unit `QoS` header (`0x01`) in the ENCODING bits, which is exactly what makes
/// them two different extensions sharing one id field (see
/// [`crate::unit_ext::chain_has_ext_eid`]).
#[cfg(feature = "session-extqos")]
pub const QOS_LINK_EXT_HEADER: u8 = QOS_EXT_ID | crate::ext_header::EXT_ENC_Z64;

/// The per-link QoS metadata a peer advertises in the `QoSLink` body — the
/// payload half of zenoh's `State::QoS { priorities, reliability }`
/// (`io/zenoh-transport/src/unicast/establishment/ext/qos.rs`).
///
/// The NoQoS/QoS discriminator itself is NOT duplicated here: wz already keeps
/// it as `SessionLinkActions::is_qos`, so this type carries only what the z64
/// body adds. Both fields `None` is the state the presence-only UNIT ext
/// encodes; either field `Some` is what forces the z64 form.
#[cfg(feature = "session-extqos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QosLinkState {
    /// The inclusive priority band this link serves (zenoh endpoint metadata
    /// `prio=start-end`). `None` = no band declared: the peer accepts whatever
    /// band the other side declares.
    pub priorities: Option<crate::session_actions::LinkPriorityRange>,
    /// The reliability class this link serves (zenoh endpoint metadata
    /// `rel=0|1`). `None` = undeclared.
    pub reliability: Option<crate::reliability::Reliability>,
}

/// What an inbound Init ext chain says about the peer's QoS establishment state
/// — the wz mirror of zenoh's `State` enum, returned by
/// [`peer_qos_ext_state`].
#[cfg(feature = "session-extqos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerQos {
    /// Neither `QoS` nor `QoSLink` is present — zenoh `State::NoQoS`.
    NoQoS,
    /// One of the two forms is present; the metadata is the z64 body's (both
    /// `None` for the unit form).
    QoS(QosLinkState),
}

/// Why a `QoSLink` negotiation was refused. Each variant is one of zenoh's own
/// `zerror!` bail-outs in `establishment/ext/qos.rs`; every one of them aborts
/// the handshake upstream, so wz tears the session down rather than silently
/// degrading to a band neither side agreed to.
#[cfg(feature = "session-extqos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QosLinkError {
    /// Both `QoS` (unit) and `QoSLink` (z64) present on one chain — zenoh
    /// "Extensions QoS and QoSOptimized cannot both be enabled at once".
    BothForms,
    /// The z64 body is not a valid `State` encoding: a reserved tag, or a
    /// priority byte outside `0..=7` (zenoh `Priority::try_from` error /
    /// `zerror!("invalid QoS")`).
    InvalidValue,
    /// Acceptor side: the initiator's `PriorityRange` is not a SUBSET of mine
    /// — zenoh "The PriorityRange received in InitSyn is not a subset of my
    /// PriorityRange".
    PriorityRangeNotSubset,
    /// Initiator side: the acceptor's `PriorityRange` is not a SUPERSET of mine
    /// — zenoh "The PriorityRange received in InitAck is not a superset of my
    /// PriorityRange".
    PriorityRangeNotSuperset,
    /// Both sides declared a reliability and they differ — zenoh "The
    /// Reliability received in Init{Syn,Ack} doesn't match my Reliability".
    ReliabilityMismatch,
}

/// Pack a QoS state into the `QoSLink` z64 body — byte-for-byte zenoh
/// `State::to_u64` (`ext/qos.rs`), whose three low bits discriminate:
/// `0b000` NoQoS · `0b001` QoS with no metadata · bit 1 = a priority range is
/// present (bytes at shifts 3 and 11) · bit 2 = a reliability is present (bit
/// at shift 19).
#[cfg(feature = "session-extqos")]
pub fn qos_state_to_u64(state: &QosLinkState) -> u64 {
    if state.reliability.is_none() && state.priorities.is_none() {
        return 0b001_u64;
    }
    let mut value = 0b000_u64;
    if let Some(priorities) = state.priorities {
        value |= 0b010_u64;
        value |= (priorities.start().wire_byte() as u64) << 3;
        value |= (priorities.end().wire_byte() as u64) << (3 + 8);
    }
    if let Some(reliability) = state.reliability {
        value |= 0b100_u64;
        // zenoh `(bool::from(*reliability) as u64) << 19`, and its `From<Reliability>
        // for bool` is `Reliable => true` — the same 0/1 the wz enum's discriminant
        // already is (`BestEffort = 0, Reliable = 1`).
        value |= (reliability as u8 as u64) << (3 + 8 + 8);
    }
    value
}

/// Strict wire-byte -> [`Priority`](crate::qos::Priority): `None` above 7.
///
/// Deliberately NOT [`crate::qos::Priority::from_wire`], which CLAMPS an
/// out-of-range byte to DEFAULT. Clamping is right on the Frame path (a 3-bit
/// field cannot overflow, so the arm is unreachable there), but here the field
/// is a full BYTE and zenoh rejects an out-of-range one outright
/// (`Priority::try_from(..)?` inside `try_from_u64`). Clamping would silently
/// negotiate a band the peer never offered.
#[cfg(feature = "session-extqos")]
fn priority_try_from_wire(byte: u8) -> Option<crate::qos::Priority> {
    (byte < crate::qos::Priority::NUM as u8).then(|| crate::qos::Priority::from_wire(byte))
}

/// Unpack a `QoSLink` z64 body — the inverse of [`qos_state_to_u64`] and a
/// mirror of zenoh `State::try_from_u64`, INCLUDING its reject arm (a value
/// whose tag bits are neither `0b000`, `0b001`, nor tag-carrying is an error,
/// not a tolerated unknown).
#[cfg(feature = "session-extqos")]
pub fn qos_state_try_from_u64(value: u64) -> Result<PeerQos, QosLinkError> {
    match value {
        0b000_u64 => Ok(PeerQos::NoQoS),
        0b001_u64 => Ok(PeerQos::QoS(QosLinkState::default())),
        value if value & 0b110_u64 != 0 => {
            let tag = value & 0b111_u64;
            let priorities = if tag & 0b010_u64 != 0 {
                let start = priority_try_from_wire(((value >> 3) & 0xff) as u8)
                    .ok_or(QosLinkError::InvalidValue)?;
                let end = priority_try_from_wire(((value >> (3 + 8)) & 0xff) as u8)
                    .ok_or(QosLinkError::InvalidValue)?;
                Some(crate::session_actions::LinkPriorityRange::new(start, end))
            } else {
                None
            };
            let reliability = if tag & 0b100_u64 != 0 {
                let bit = ((value >> (3 + 8 + 8)) & 0x1) as u8 == 1;
                Some(crate::reliability::Reliability::from_reliable_bool(bit))
            } else {
                None
            };
            Ok(PeerQos::QoS(QosLinkState {
                priorities,
                reliability,
            }))
        }
        _ => Err(QosLinkError::InvalidValue),
    }
}

/// Build the `QoSLink` ext entry (`zextz64!(0x1)`, header `0x21`) carrying
/// `value` — zenoh `init::ext::QoSLink::new(state.to_u64())`.
#[cfg(feature = "session-extqos")]
pub fn encode_qos_link_ext(value: u64) -> ExtEntryOwned {
    use wz_codecs::ext_entry::ExtEntryOwnedVariant;
    use wz_codecs::ext_zint::ExtZint;
    ExtEntryOwned {
        header: QOS_LINK_EXT_HEADER,
        body: ExtEntryOwnedVariant::CodecZenohExtZint(ExtZint { value }),
    }
}

/// The single "which QoS ext does this session emit?" seam — zenoh
/// `State::to_exts`, which returns `(Some(QoS), None)` for bare QoS and
/// `(None, Some(QoSLink))` the moment EITHER metadata field is set, never both.
/// Keeping the choice in one function is what makes the exclusivity structural
/// rather than a rule two call sites have to remember.
#[cfg(feature = "session-extqos")]
pub fn encode_qos_ext_for(state: &QosLinkState) -> ExtEntryOwned {
    if state.priorities.is_none() && state.reliability.is_none() {
        encode_qos_ext()
    } else {
        encode_qos_link_ext(qos_state_to_u64(state))
    }
}

/// Project an inbound Init ext chain into the peer's QoS establishment state —
/// zenoh `State::try_from_exts`. Both forms present is the one hard error;
/// neither present is `NoQoS`.
#[cfg(feature = "session-extqos")]
pub fn peer_qos_ext_state(extensions: &[ExtEntryOwned]) -> Result<PeerQos, QosLinkError> {
    use wz_codecs::ext_entry::ExtEntryOwnedVariant;
    let unit = chain_has_ext_eid(extensions, QOS_EXT_ID);
    let link = extensions
        .iter()
        .find(|e| crate::ext_header::ext_eid(e.header) == QOS_LINK_EXT_HEADER);
    match (unit, link) {
        (true, Some(_)) => Err(QosLinkError::BothForms),
        (true, None) => Ok(PeerQos::QoS(QosLinkState::default())),
        (false, Some(entry)) => match &entry.body {
            ExtEntryOwnedVariant::CodecZenohExtZint(z) => qos_state_try_from_u64(z.value),
            // The header says Z64 but the decoded body is not a zint: a
            // malformed entry, not a capability offer.
            _ => Err(QosLinkError::InvalidValue),
        },
        (false, None) => Ok(PeerQos::NoQoS),
    }
}

/// The shared half of both merges: reliability must MATCH when both sides
/// declare one, and an undeclared side inherits the other's.
#[cfg(feature = "session-extqos")]
fn merge_reliability(
    mine: Option<crate::reliability::Reliability>,
    theirs: Option<crate::reliability::Reliability>,
) -> Result<Option<crate::reliability::Reliability>, QosLinkError> {
    match (mine, theirs) {
        (None, r) | (r, None) => Ok(r),
        (Some(a), Some(b)) if a == b => Ok(Some(a)),
        _ => Err(QosLinkError::ReliabilityMismatch),
    }
}

/// ACCEPTOR merge (zenoh `AcceptFsm::recv_init_syn`): the initiator's band must
/// be a SUBSET of mine, and the negotiated band is the initiator's (the
/// narrower one). An undeclared side inherits the other's band.
#[cfg(feature = "session-extqos")]
pub fn merge_qos_link_init_syn(
    mine: &QosLinkState,
    theirs: &QosLinkState,
) -> Result<QosLinkState, QosLinkError> {
    let priorities = match (mine.priorities, theirs.priorities) {
        (None, p) | (p, None) => p,
        (Some(mine), Some(theirs)) => {
            if mine.includes(&theirs) {
                Some(theirs)
            } else {
                return Err(QosLinkError::PriorityRangeNotSubset);
            }
        }
    };
    Ok(QosLinkState {
        priorities,
        reliability: merge_reliability(mine.reliability, theirs.reliability)?,
    })
}

/// INITIATOR merge (zenoh `OpenFsm::recv_init_ack`): the acceptor's band must
/// be a SUPERSET of mine, and the negotiated band stays MINE. The direction is
/// the mirror image of [`merge_qos_link_init_syn`] — the narrower side always
/// wins, it is just a different side each time.
#[cfg(feature = "session-extqos")]
pub fn merge_qos_link_init_ack(
    mine: &QosLinkState,
    theirs: &QosLinkState,
) -> Result<QosLinkState, QosLinkError> {
    let priorities = match (mine.priorities, theirs.priorities) {
        (None, p) | (p, None) => p,
        (Some(mine_range), Some(theirs_range)) => {
            if theirs_range.includes(&mine_range) {
                Some(mine_range)
            } else {
                return Err(QosLinkError::PriorityRangeNotSuperset);
            }
        }
    };
    Ok(QosLinkState {
        priorities,
        reliability: merge_reliability(mine.reliability, theirs.reliability)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unit_ext::encode_unit_ext;
    use wz_codecs::ext_entry::{ExtEntryOwned, ExtEntryOwnedVariant};
    use wz_codecs::ext_zint::ExtZint;

    /// Locks the on-the-wire header byte (`0x01` = UNIT encoding | id 0x01, no
    /// M, Z patched by the chain codec) — the shape zenoh emits for the
    /// presence-only `init::ext::QoS`.
    #[test]
    fn qos_ext_header_is_unit_id_one() {
        let ext = encode_qos_ext();
        assert_eq!(ext.header, 0x01, "UNIT enc (0x00) | QOS_EXT_ID (0x01)");
        assert_eq!(ext.ext_id(), QOS_EXT_ID);
    }

    /// The encoded entry is exactly ONE byte (the header) — the presence-only
    /// unit ext carries no body, the defining property of `zextunit!`.
    #[test]
    fn qos_ext_encodes_to_a_single_byte() {
        assert_eq!(encode_qos_ext().as_borrowed().encode_to_vec().len(), 1);
    }

    /// A chain carrying the unit QoS ext projects to `true`.
    #[test]
    fn peer_offer_detected_for_the_unit_form() {
        assert!(peer_offered_qos(&[encode_qos_ext()]));
    }

    /// RANK-2 faithfulness: a priority-configured zenohd sends `QoSLink` (a z64
    /// at id 0x1, header `0x21` = id 0x1 | ENC_Z64 0x20), NOT the unit.
    /// `peer_offered_qos` must STILL read it as QoS (else wz mis-negotiates
    /// NoQoS against a QoS peer). The z64 body's range meaning is deferred (S4);
    /// only the presence at id 0x1 matters here.
    #[test]
    fn peer_offer_detected_for_the_z64_qoslink_form() {
        let qos_link = ExtEntryOwned {
            header: 0x21, // id 0x1 | ENC_Z64 (0x20)
            body: ExtEntryOwnedVariant::CodecZenohExtZint(ExtZint::default()),
        };
        assert_eq!(qos_link.ext_id(), QOS_EXT_ID, "the low nibble is the id");
        assert!(
            peer_offered_qos(&[qos_link]),
            "QoSLink (z64) at id 0x1 is is_qos=true, same as the unit form"
        );
    }

    /// An empty chain, or one carrying only a FOREIGN establishment ext (a 0x05
    /// LowLatency-shaped unit entry), projects to `false` — QoS is not confused
    /// with a neighbour in the id space.
    #[test]
    fn peer_offer_absent_without_the_ext() {
        assert!(!peer_offered_qos(&[]));
        assert!(!peer_offered_qos(&[encode_unit_ext(0x05)]));
    }

    // -----------------------------------------------------------------------
    // session-extqos (R311y506) — the z64 `QoSLink` body + the containment.
    // -----------------------------------------------------------------------

    #[cfg(feature = "session-extqos")]
    mod qos_link {
        use super::super::*;
        use crate::qos::Priority;
        use crate::reliability::Reliability;
        use crate::session_actions::LinkPriorityRange;

        fn band(a: Priority, b: Priority) -> LinkPriorityRange {
            LinkPriorityRange::new(a, b)
        }

        fn state(
            priorities: Option<LinkPriorityRange>,
            reliability: Option<Reliability>,
        ) -> QosLinkState {
            QosLinkState {
                priorities,
                reliability,
            }
        }

        /// The five `to_u64` states of zenoh's own doc comment, each pinned to
        /// the EXACT u64 upstream produces. These are the wire bytes a real
        /// zenohd parses, so a drift here is a cross-impl defect, not a style
        /// question.
        ///
        /// Hand-computed from `State::to_u64` (`ext/qos.rs`): tag bit 1 = a
        /// priority range at shifts 3 and 11; tag bit 2 = a reliability bit at
        /// shift 19.
        #[test]
        fn to_u64_matches_zenohs_five_states() {
            // 2. QoS on, no metadata -> the bare `0b001` marker.
            assert_eq!(qos_state_to_u64(&state(None, None)), 0b001);

            // 3. priority range only: RealTime(1)..=DataHigh(4)
            //    = 0b010 | (1 << 3) | (4 << 11) = 2 + 8 + 8192 = 8202.
            assert_eq!(
                qos_state_to_u64(&state(
                    Some(band(Priority::RealTime, Priority::DataHigh)),
                    None
                )),
                0b010 | (1 << 3) | (4 << 11)
            );

            // 4. reliability only: Reliable -> bit 1 at shift 19.
            assert_eq!(
                qos_state_to_u64(&state(None, Some(Reliability::Reliable))),
                0b100 | (1 << 19)
            );
            // BestEffort is the ZERO bit — the tag still marks it present, which
            // is the whole reason the tag exists (0 is a value, not an absence).
            assert_eq!(
                qos_state_to_u64(&state(None, Some(Reliability::BestEffort))),
                0b100
            );

            // 5. both. Control is priority 0, so its `(0 << 3)` term is written
            //    out in the comment rather than the expression — clippy rejects
            //    the identity shift, and dropping it silently would hide WHICH
            //    field occupies bits 3..=10.
            assert_eq!(
                qos_state_to_u64(&state(
                    Some(band(Priority::Control, Priority::Background)),
                    Some(Reliability::Reliable)
                )),
                // 0b110 | (Control=0 << 3) | (Background=7 << 11) | (Reliable=1 << 19)
                0b110 | (7 << 11) | (1 << 19)
            );
        }

        /// `try_from_u64` inverts `to_u64` over every representable state — the
        /// round-trip that keeps the two halves from drifting independently.
        #[test]
        fn u64_round_trips_over_every_state() {
            let priorities = [
                None,
                Some(band(Priority::Control, Priority::Background)),
                Some(band(Priority::RealTime, Priority::DataHigh)),
                Some(band(Priority::Data, Priority::Data)),
            ];
            let reliabilities = [
                None,
                Some(Reliability::Reliable),
                Some(Reliability::BestEffort),
            ];
            for p in priorities {
                for r in reliabilities {
                    let s = state(p, r);
                    let encoded = qos_state_to_u64(&s);
                    match qos_state_try_from_u64(encoded) {
                        Ok(PeerQos::QoS(back)) => assert_eq!(back, s, "round trip for {s:?}"),
                        other => panic!("expected QoS for {s:?}, got {other:?}"),
                    }
                }
            }
        }

        /// `0b000` is NoQoS, and a value whose tag bits are neither `0b000`,
        /// `0b001`, nor tag-carrying is an ERROR — zenoh's `_ => Err(zerror!(
        /// "invalid QoS"))` arm. Tolerating it would negotiate a band off a
        /// body wz did not understand.
        #[test]
        fn zero_is_no_qos_and_a_reserved_tag_is_refused() {
            assert_eq!(qos_state_try_from_u64(0), Ok(PeerQos::NoQoS));
            // tag 0b001 with junk in the high bits: not the bare marker, and no
            // tag bit set -> reserved.
            assert_eq!(
                qos_state_try_from_u64(0b1_0000_0001),
                Err(QosLinkError::InvalidValue)
            );
        }

        /// A priority byte above 7 is REFUSED, not clamped. The field is a full
        /// byte on the wire while `Priority` has 8 values, so this is reachable
        /// from a malformed peer; zenoh errors via `Priority::try_from(..)?`.
        /// Clamping (what `Priority::from_wire` does, correctly, on the 3-bit
        /// Frame field) would negotiate a band the peer never offered.
        #[test]
        fn an_out_of_range_priority_byte_is_refused_not_clamped() {
            // tag 0b010 (priority range present) with start = 9.
            let bad = 0b010_u64 | (9_u64 << 3) | (7_u64 << 11);
            assert_eq!(qos_state_try_from_u64(bad), Err(QosLinkError::InvalidValue));
            // and the same for the END byte.
            let bad_end = 0b010_u64 | (1_u64 << 3) | (8_u64 << 11);
            assert_eq!(
                qos_state_try_from_u64(bad_end),
                Err(QosLinkError::InvalidValue)
            );
        }

        /// The emit choice is structural: no metadata -> the UNIT form (header
        /// `0x01`, one byte); any metadata -> the z64 form (header `0x21`).
        /// zenoh `State::to_exts` never returns both.
        #[test]
        fn the_emitted_form_follows_the_metadata() {
            let unit = encode_qos_ext_for(&state(None, None));
            assert_eq!(unit.header, 0x01);
            assert_eq!(unit.as_borrowed().encode_to_vec().len(), 1);

            let link = encode_qos_ext_for(&state(
                Some(band(Priority::RealTime, Priority::DataHigh)),
                None,
            ));
            assert_eq!(link.header, QOS_LINK_EXT_HEADER);
            assert_eq!(link.header, 0x21, "id 0x1 | ENC_Z64 0x20");
            assert!(
                link.as_borrowed().encode_to_vec().len() > 1,
                "z64 has a body"
            );

            // reliability alone is enough to force the z64 form.
            assert_eq!(
                encode_qos_ext_for(&state(None, Some(Reliability::BestEffort))).header,
                QOS_LINK_EXT_HEADER
            );
        }

        /// `peer_qos_ext_state` is zenoh `try_from_exts`: neither form is
        /// NoQoS, the unit form is metadata-less QoS, the z64 form decodes its
        /// body, and BOTH at once is the one hard error.
        #[test]
        fn peer_state_projects_the_three_cases_and_refuses_both() {
            assert_eq!(peer_qos_ext_state(&[]), Ok(PeerQos::NoQoS));
            assert_eq!(
                peer_qos_ext_state(&[encode_qos_ext()]),
                Ok(PeerQos::QoS(QosLinkState::default()))
            );

            let s = state(Some(band(Priority::RealTime, Priority::DataHigh)), None);
            assert_eq!(
                peer_qos_ext_state(&[encode_qos_link_ext(qos_state_to_u64(&s))]),
                Ok(PeerQos::QoS(s))
            );

            assert_eq!(
                peer_qos_ext_state(&[encode_qos_ext(), encode_qos_link_ext(0b001)]),
                Err(QosLinkError::BothForms)
            );
        }

        /// ACCEPTOR containment (zenoh `recv_init_syn`): the initiator's band
        /// must be a SUBSET of mine, and the NEGOTIATED band is the initiator's.
        /// The refusal arm is the half that makes this a claim about zenoh's
        /// rule rather than a restatement of "it merged".
        #[test]
        fn acceptor_requires_a_subset_and_adopts_it() {
            let mine = state(Some(band(Priority::Control, Priority::Background)), None);
            let theirs = state(Some(band(Priority::RealTime, Priority::DataHigh)), None);
            assert_eq!(
                merge_qos_link_init_syn(&mine, &theirs),
                Ok(theirs),
                "the narrower initiator band wins"
            );

            // Reversed: a WIDER initiator band is refused.
            assert_eq!(
                merge_qos_link_init_syn(&theirs, &mine),
                Err(QosLinkError::PriorityRangeNotSubset)
            );

            // An undeclared side inherits the other's band, in both directions.
            assert_eq!(
                merge_qos_link_init_syn(&state(None, None), &theirs),
                Ok(theirs)
            );
            assert_eq!(
                merge_qos_link_init_syn(&theirs, &state(None, None)),
                Ok(theirs)
            );
        }

        /// INITIATOR containment (zenoh `recv_init_ack`): the mirror image —
        /// the acceptor's band must be a SUPERSET of mine and MINE survives.
        /// Pinned as its own test because a symmetric implementation would pass
        /// the acceptor test above and still be wrong here.
        #[test]
        fn initiator_requires_a_superset_and_keeps_its_own() {
            let mine = state(Some(band(Priority::RealTime, Priority::DataHigh)), None);
            let theirs = state(Some(band(Priority::Control, Priority::Background)), None);
            assert_eq!(
                merge_qos_link_init_ack(&mine, &theirs),
                Ok(mine),
                "my narrower band survives"
            );
            assert_eq!(
                merge_qos_link_init_ack(&theirs, &mine),
                Err(QosLinkError::PriorityRangeNotSuperset)
            );
        }

        /// Reliability negotiates by EQUALITY, not containment, in both
        /// directions: an undeclared side inherits, a disagreement aborts.
        #[test]
        fn reliability_must_match_when_both_declare_one() {
            let rel = state(None, Some(Reliability::Reliable));
            let best = state(None, Some(Reliability::BestEffort));
            let none = state(None, None);

            assert_eq!(merge_qos_link_init_syn(&rel, &rel), Ok(rel));
            assert_eq!(merge_qos_link_init_syn(&none, &best), Ok(best));
            assert_eq!(merge_qos_link_init_ack(&best, &none), Ok(best));
            assert_eq!(
                merge_qos_link_init_syn(&rel, &best),
                Err(QosLinkError::ReliabilityMismatch)
            );
            assert_eq!(
                merge_qos_link_init_ack(&rel, &best),
                Err(QosLinkError::ReliabilityMismatch)
            );
        }
    }
}
