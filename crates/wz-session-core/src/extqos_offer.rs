// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What an Init extension chain OFFERS for QoS, read the way upstream reads it,
//! in every build.
//!
//! `extqos` owns the QoS extension's wire shape and its negotiation, and it is
//! gated on `transport-qos` because it is the half that SENDS and NEGOTIATES.
//! An observer implements none of that: the passive session folds both Inits of
//! a handshake it only watches, in a build (`dissect`) that selects no QoS
//! feature. So the READING lives here, ungated, for the reason
//! `ext_header::establishment_ext_id` is ungated and `extpatch` is: an observer
//! must read what its own build could not negotiate. `extqos` reads through this
//! module too, so a participant and an observer cannot disagree about what a
//! chain offers (they did: the observer counted a QoS offer only in its unit
//! form, and the participant counted the z64 form whatever its body said).
//!
//! # One extension id, two forms, one state
//!
//! Upstream declares two extensions on the id `0x1`, told apart by their
//! encoding bits, so the extension's IDENTITY (the header minus the chain flag)
//! is what is matched, never the 4-bit id:
//!
//! `commons/zenoh-protocol/src/transport/init.rs` @ `pub type QoS = zextunit!(0x1, false);`
//! `commons/zenoh-protocol/src/transport/init.rs` @ `pub type QoSLink = zextz64!(0x1, false);`
//!
//! and decides which one it sends from the state it holds. A state with neither
//! a priority band nor a reliability class is the unit form (header `0x01`, no
//! body); a state with either is the z64 `QoSLink` (header `0x21`) whose body is
//! the packed state; and no QoS at all is NO extension:
//!
//! `io/zenoh-transport/src/unicast/establishment/ext/qos.rs` @ `fn to_exts(&self) -> (Option<init::ext::QoS>, Option<init::ext::QoSLink>) {`
//!
//! The reader maps what it finds back to the same state. This is the whole of
//! the rule, and every row of it is a line upstream:
//!
//! | the chain carries | the state | upstream |
//! |---|---|---|
//! | neither form | no QoS | `(None, None) => Ok(State::NoQoS),` |
//! | the unit form | QoS, no band, no class | `(Some(_), None) => Ok(State::QoS {` |
//! | `QoSLink`, body `0` | NO QoS | `0b000_u64 => Ok(State::NoQoS),` |
//! | `QoSLink`, body `1` | QoS, no band, no class | `0b001_u64 => Ok(State::QoS {` |
//! | `QoSLink`, body with bit 1 or bit 2 set | QoS with the band and class its tag bits announce | `value if value & 0b110_u64 != 0 => {` |
//! | `QoSLink`, any other body | refused | `_ => Err(zerror!("invalid QoS").into()),` |
//! | `QoSLink` with a priority byte above 7 | refused | `Priority::try_from(((value >> 3) & 0xff) as u8)?` |
//! | both forms | refused | `"Extensions QoS and QoSOptimized cannot both be enabled at once"` |
//!
//! `io/zenoh-transport/src/unicast/establishment/ext/qos.rs` @ `(None, Some(qos)) => State::try_from_u64(qos.value),`
//!
//! A body of `0` is therefore NOT an offer, though its header is the z64 one: a
//! chain is not read as QoS because an entry sits at the id. Upstream itself
//! never writes a `QoSLink` body of `0` or `1` (a state with a band or a class
//! has a tag bit set, and one with neither is the unit form), so those two are
//! what a sender other than upstream writes, and they are read as upstream
//! would read them.
//!
//! # What the session's `qos` is
//!
//! Each side keeps its own state and, on the Init it receives, drops to no QoS
//! unless BOTH were QoS:
//!
//! `io/zenoh-transport/src/unicast/establishment/ext/qos.rs` @ `*state_self = State::NoQoS.into();`
//!
//! and the acceptor answers with its merged state, so the InitAck carries no
//! QoS extension exactly when the session has none:
//!
//! `io/zenoh-transport/src/unicast/establishment/accept.rs` @ `.send_init_ack(&state.transport.ext_qos)`
//!
//! The session therefore has QoS exactly when BOTH Inits offer it, in either
//! form and in any combination of forms. The combinations are not exotic: a
//! dialler whose endpoint carries no metadata sends the unit form, and an
//! acceptor whose endpoint does answers with `QoSLink`, because the merged
//! state keeps its band.
//!
//! What this module does NOT judge is whether the exchange SUCCEEDED. A band the
//! acceptor's own band does not contain, or two different reliability classes,
//! abort the handshake upstream; an observer does not hold the acceptor's own
//! configuration, so a pair of offers that upstream would refuse on those
//! grounds still reads as QoS here, and such a session never opens.

use wz_codecs::ext_entry::{ExtEntryOwned, ExtEntryOwnedVariant};

use crate::accept_state::QosAcceptState;
use crate::ext_header::{establishment_ext_id as est_ext, ext_eid, EXT_ENC_Z64};
use crate::qos::Priority;
use crate::reliability::Reliability;

/// The header of the unit form, `init::ext::QoS`: id `0x1`, unit encoding, not
/// mandatory.
const QOS_UNIT_HEADER: u8 = est_ext::QOS;

/// The header of the z64 form, `init::ext::QoSLink`: id `0x1`, z64 encoding,
/// not mandatory.
const QOS_LINK_HEADER: u8 = est_ext::QOS | EXT_ENC_Z64;

/// Why a chain's QoS extension is not a state at all. Each is one of upstream's
/// own `zerror!` bail-outs in `try_from_exts` / `try_from_u64`, and each aborts
/// the handshake there: an observer reads a chain carrying one as NOT offering
/// QoS, which is the only answer that claims no agreement nobody could reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QosOfferError {
    /// Both the unit form and the `QoSLink` form are present on one chain.
    BothForms,
    /// The `QoSLink` body is not a valid state: a tag outside the five upstream
    /// defines, or a priority byte above 7.
    InvalidValue,
}

/// Strict wire-byte to [`Priority`]: `None` above 7.
///
/// Deliberately NOT `Priority::from_wire`, which CLAMPS an out-of-range byte to
/// the default. Clamping is right on the Frame path (a 3-bit field cannot
/// overflow, so the arm is unreachable there), but a `QoSLink` priority is a
/// full BYTE and upstream rejects an out-of-range one outright. Clamping would
/// read a band the peer never offered.
pub(crate) fn priority_try_from_wire(byte: u8) -> Option<Priority> {
    (byte < Priority::NUM as u8).then(|| Priority::from_wire(byte))
}

/// Read a `QoSLink` z64 body as upstream's `State::try_from_u64` does.
///
/// The three low bits are the tag: `0b000` is no QoS, `0b001` is QoS with no
/// band and no class, and bit 1 / bit 2 announce a priority band (a byte at
/// shift 3 and another at shift 11) and a reliability class (one bit at shift
/// 19). A band is returned lowest priority value first, whichever way the peer
/// wrote it.
pub fn state_from_link_body(value: u64) -> Result<QosAcceptState, QosOfferError> {
    match value {
        0b000_u64 => Ok(QosAcceptState::NoQos),
        0b001_u64 => Ok(QosAcceptState::BARE),
        value if value & 0b110_u64 != 0 => {
            let tag = value & 0b111_u64;
            let priorities = if tag & 0b010_u64 != 0 {
                let start = priority_try_from_wire(((value >> 3) & 0xff) as u8)
                    .ok_or(QosOfferError::InvalidValue)?;
                let end = priority_try_from_wire(((value >> (3 + 8)) & 0xff) as u8)
                    .ok_or(QosOfferError::InvalidValue)?;
                Some(if start <= end {
                    (start, end)
                } else {
                    (end, start)
                })
            } else {
                None
            };
            let reliability = if tag & 0b100_u64 != 0 {
                let bit = ((value >> (3 + 8 + 8)) & 0x1) as u8 == 1;
                Some(Reliability::from_reliable_bool(bit))
            } else {
                None
            };
            Ok(QosAcceptState::Qos {
                priorities,
                reliability,
            })
        }
        _ => Err(QosOfferError::InvalidValue),
    }
}

/// Read the QoS state an Init ext chain carries, as upstream's
/// `State::try_from_exts` does.
///
/// A repeated `QoSLink` is read the way upstream's decoder does, by the LAST
/// one (its loop assigns each entry it meets):
///
/// `commons/zenoh-codec/src/transport/init.rs` @ `ext_qos_link = Some(q);`
///
/// An entry at the id with a different identity (a mandatory flag, a ZBuf
/// body) is neither form and is not read.
pub fn state_from_exts(extensions: &[ExtEntryOwned]) -> Result<QosAcceptState, QosOfferError> {
    let unit = extensions
        .iter()
        .any(|e| ext_eid(e.header) == QOS_UNIT_HEADER);
    let link = extensions
        .iter()
        .rev()
        .find(|e| ext_eid(e.header) == QOS_LINK_HEADER);
    match (unit, link) {
        (true, Some(_)) => Err(QosOfferError::BothForms),
        (true, None) => Ok(QosAcceptState::BARE),
        (false, Some(entry)) => match &entry.body {
            ExtEntryOwnedVariant::CodecZenohExtZint(z) => state_from_link_body(z.value),
            // The header says z64 but the decoded body is not a zint: a
            // malformed entry, not an offer.
            _ => Err(QosOfferError::InvalidValue),
        },
        (false, None) => Ok(QosAcceptState::NoQos),
    }
}

/// Whether an Init ext chain offers QoS: it carries a state that is QoS.
///
/// The one question a session's `qos` is the `&=` of, for a participant
/// merging the peer's offer into its own and for an observer folding both
/// Inits of a handshake it watches. A chain upstream would refuse offers
/// nothing.
pub fn offers_qos(extensions: &[ExtEntryOwned]) -> bool {
    state_from_exts(extensions).is_ok_and(|state| state.negotiated())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wz_codecs::ext_unit::ExtUnit;
    use wz_codecs::ext_zint::ExtZint;

    fn unit() -> ExtEntryOwned {
        ExtEntryOwned {
            header: 0x01,
            body: ExtEntryOwnedVariant::CodecZenohExtUnit(ExtUnit::default()),
        }
    }

    fn link(value: u64) -> ExtEntryOwned {
        ExtEntryOwned {
            header: 0x21,
            body: ExtEntryOwnedVariant::CodecZenohExtZint(ExtZint { value }),
        }
    }

    fn band(a: Priority, b: Priority) -> Option<(Priority, Priority)> {
        Some((a, b))
    }

    /// EVERY ROW OF THE TABLE IN THE MODULE DOC, each against the value upstream
    /// computes. The bodies are written out from `State::try_from_u64` (tag in
    /// the three low bits, the band's bytes at shifts 3 and 11, the class bit at
    /// shift 19), not produced by this crate's encoder, so a drift in the
    /// encoder cannot move the expectation with it.
    #[test]
    fn a_link_body_reads_as_upstreams_try_from_u64_reads_it() {
        use QosAcceptState::{NoQos, Qos};
        let rows: [(u64, Result<QosAcceptState, QosOfferError>); 11] = [
            (0, Ok(NoQos)),
            (1, Ok(QosAcceptState::BARE)),
            // A band alone: RealTime(1)..=DataHigh(4).
            (
                0b010 | (1 << 3) | (4 << 11),
                Ok(Qos {
                    priorities: band(Priority::RealTime, Priority::DataHigh),
                    reliability: None,
                }),
            ),
            // A class alone: reliable is the bit at shift 19.
            (
                0b100 | (1 << 19),
                Ok(Qos {
                    priorities: None,
                    reliability: Some(Reliability::Reliable),
                }),
            ),
            // A class alone, best effort: the tag still marks it present, which
            // is why a tag exists (0 is a value, not an absence).
            (
                0b100,
                Ok(Qos {
                    priorities: None,
                    reliability: Some(Reliability::BestEffort),
                }),
            ),
            // Both.
            (
                0b110 | (7 << 11) | (1 << 19),
                Ok(Qos {
                    priorities: band(Priority::Control, Priority::Background),
                    reliability: Some(Reliability::Reliable),
                }),
            ),
            // A mid-range band with a class, the body of an endpoint written
            // `prio=2-5;rel=1`: InteractiveHigh(2)..=Data(5), reliable.
            (
                0b110 | (2 << 3) | (5 << 11) | (1 << 19),
                Ok(Qos {
                    priorities: band(Priority::InteractiveHigh, Priority::Data),
                    reliability: Some(Reliability::Reliable),
                }),
            ),
            // A band written backwards is read lowest value first.
            (
                0b010 | (4 << 3) | (1 << 11),
                Ok(Qos {
                    priorities: band(Priority::RealTime, Priority::DataHigh),
                    reliability: None,
                }),
            ),
            // No tag bit, and not 0 or 1: the reserved arm.
            (0b1000, Err(QosOfferError::InvalidValue)),
            // A priority byte above 7, in either position.
            (
                0b010 | (9 << 3) | (7 << 11),
                Err(QosOfferError::InvalidValue),
            ),
            (
                0b010 | (1 << 3) | (8 << 11),
                Err(QosOfferError::InvalidValue),
            ),
        ];
        for (body, expected) in rows {
            assert_eq!(state_from_link_body(body), expected, "body {body:#b}");
        }
    }

    /// WHETHER A CHAIN OFFERS QOS, over every combination of the two forms and
    /// the bodies the previous test classified. The unit form and a `QoSLink`
    /// that is QoS agree; a `QoSLink` of body `0` is not an offer although its
    /// header is.
    #[test]
    fn a_chain_offers_qos_when_upstream_reads_it_as_qos() {
        let tagged = 0b010 | (1 << 3) | (4 << 11);
        assert!(!offers_qos(&[]), "neither form");
        assert!(offers_qos(&[unit()]), "the unit form");
        assert!(offers_qos(&[link(tagged)]), "a QoSLink carrying a band");
        assert!(
            offers_qos(&[link(0b100)]),
            "a QoSLink carrying a class alone"
        );
        assert!(offers_qos(&[link(1)]), "a QoSLink of the bare tag");
        assert!(
            !offers_qos(&[link(0)]),
            "a QoSLink of body 0 is upstream's NoQoS"
        );
        // Refused chains offer nothing.
        assert!(!offers_qos(&[unit(), link(tagged)]), "both forms");
        assert!(!offers_qos(&[link(0b1000)]), "a reserved tag");
        assert!(
            !offers_qos(&[link(0b010 | (9 << 3))]),
            "a priority byte above 7"
        );
    }

    /// THE CHAIN READ IS UPSTREAM'S `try_from_exts`, arm for arm, and the
    /// chain's other entries and the position of the QoS one do not matter.
    #[test]
    fn a_chain_is_read_arm_for_arm() {
        let tagged = 0b010 | (1 << 3) | (4 << 11);
        let with_band = QosAcceptState::Qos {
            priorities: band(Priority::RealTime, Priority::DataHigh),
            reliability: None,
        };
        assert_eq!(state_from_exts(&[]), Ok(QosAcceptState::NoQos));
        assert_eq!(state_from_exts(&[unit()]), Ok(QosAcceptState::BARE));
        assert_eq!(state_from_exts(&[link(tagged)]), Ok(with_band));
        assert_eq!(
            state_from_exts(&[unit(), link(tagged)]),
            Err(QosOfferError::BothForms)
        );
        // A neighbour at another id, before and after.
        let other = ExtEntryOwned {
            header: 0x07 | EXT_ENC_Z64,
            body: ExtEntryOwnedVariant::CodecZenohExtZint(ExtZint { value: 1 }),
        };
        assert_eq!(
            state_from_exts(&[other.clone(), link(tagged), other]),
            Ok(with_band)
        );
        // The LAST QoSLink is the one upstream's decoder keeps.
        assert_eq!(
            state_from_exts(&[link(0), link(tagged)]),
            Ok(with_band),
            "a later entry replaces an earlier one"
        );
        assert_eq!(
            state_from_exts(&[link(tagged), link(0)]),
            Ok(QosAcceptState::NoQos),
            "and a later zero body replaces a band"
        );
    }

    /// AN ENTRY AT THE ID WITH ANOTHER IDENTITY IS NOT A QOS OFFER: a ZBuf body
    /// (`0x41`) and a mandatory unit (`0x11`) are neither of upstream's two
    /// forms, and its decoder does not read them as one.
    #[test]
    fn another_identity_at_the_id_is_not_an_offer() {
        let zbuf = ExtEntryOwned {
            header: 0x41,
            body: ExtEntryOwnedVariant::CodecZenohExtUnit(ExtUnit::default()),
        };
        let mandatory = ExtEntryOwned {
            header: 0x11,
            body: ExtEntryOwnedVariant::CodecZenohExtUnit(ExtUnit::default()),
        };
        assert!(!offers_qos(&[zbuf]));
        assert!(!offers_qos(&[mandatory]));
    }

    /// The chain flag is not part of an entry's identity: a QoS entry that is
    /// not last in its chain is the same offer.
    #[test]
    fn the_chain_flag_does_not_change_an_offer() {
        let mut chained_unit = unit();
        chained_unit.header |= crate::ext_header::EXT_FLAG_Z;
        let mut chained_link = link(0b100);
        chained_link.header |= crate::ext_header::EXT_FLAG_Z;
        assert!(offers_qos(&[chained_unit]));
        assert!(offers_qos(&[chained_link]));
    }
}
