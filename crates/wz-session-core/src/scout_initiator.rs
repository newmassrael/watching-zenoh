// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2334 — the INITIATOR's verdict on a datagram that reached it during a
//! scouting window but advanced nothing.
//!
//! The twin of [`crate::scout_responder`], and the split is the same one that
//! module documents: the rule lives here (pure — no clock, no socket, no
//! interior mutability), the sockets live in the runtime half
//! (`wz_runtime_tokio::scouting_glue`). It earns the same thing: every reason a
//! scouting datagram is discarded is decidable, and therefore testable, on a
//! host with no network at all.
//!
//! # The defect this exists for
//!
//! The `scouting-active` atom carried this residual: *"wz drops a non-Hello
//! scouting datagram silently at the MID filter where pico logs
//! `_Z_ERR_MESSAGE_UNEXPECTED`"*. It understated the shape. The initiator had
//! **two** silent drops, not one — the MID filter, and a Hello-MID datagram
//! whose decode failed — while the RESPONDER half has reported its reason in a
//! typed [`crate::scout_responder::ScoutIgnored`] since it was written. The two
//! halves of one pair disagreed about whether a discarded datagram is worth
//! naming.
//!
//! Upstream names both. `__z_scout_loop` logs `"Scouting loop received
//! malformed message"` when `_z_scouting_message_decode` fails, and its
//! `default:` arm logs `_Z_ERR_MESSAGE_UNEXPECTED` /
//! `"Scouting loop received unexpected message"` for a MID that is not a Hello
//! (`vendor/zenoh-pico/src/session/scout.c`, the `while` over the window).
//!
//! # Why this is NOT [`crate::scout_responder::ScoutIgnored`]
//!
//! That enum reads a QUESTION; this one reads an ANSWER, and the two disagree
//! about the same bytes. A Scout from another node is, to the responder, the
//! thing it exists to serve; to an initiator it is somebody else's question and
//! no answer to ours. Reusing `NotAScout` for it would have put a misleading
//! word on the one line a reader consults when discovery mysteriously found
//! nothing. Two directions, two vocabularies — the duplication of the two
//! shared spellings (`Undecodable`, `SelfEcho`) is the point at which they
//! genuinely mean the same thing.
//!
//! # Where wz can see more than pico can
//!
//! Two of the four verdicts are wz-specific, and both are DELIBERATE
//! divergences rather than gaps:
//!
//! * [`ScoutRxIgnored::SelfEcho`](crate::scout_initiator::ScoutRxIgnored::SelfEcho)
//!   — wz's scouting socket sets
//!   `set_multicast_loop_v4(true)` on purpose, so its own Scout comes back to
//!   it. Nothing in `vendor/zenoh-pico` sets that option, so pico never
//!   observes its own question and has no arm for it. Reporting it at pico's
//!   ERROR severity would fire once per cycle on a datagram wz asked for.
//! * [`ScoutRxIgnored::ForeignScout`](crate::scout_initiator::ScoutRxIgnored::ForeignScout)
//!   — pico's `default:` arm cannot tell
//!   another node's Scout from a MID it does not know, because it does not
//!   compare the zid. wz can, and a second node scouting the same group is
//!   ORDINARY rather than anomalous.
//!
//! Both are still RECORDED. The severity a host logs them at is the host's
//! business; whether they happened is this crate's.

use crate::scouting_message::{parse_scouting, ScoutingFrame};

/// Why a datagram observed during a scouting window advanced nothing.
///
/// Every variant is REACHABLE from [`classify_ignored_scout_rx`] — see that
/// function's own tests, which construct one datagram per variant. A verdict no
/// input can produce is a verdict no test can fail on, so it would not be
/// carried here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScoutRxIgnored {
    /// The bytes did not decode in the scouting namespace, or carried the
    /// Hello MID and the cycle's own decoder refused them.
    ///
    /// Upstream's `"Scouting loop received malformed message"`.
    Undecodable,
    /// Our own Scout, looped back by `IP_MULTICAST_LOOP`. Expected on every
    /// cycle, because wz asks for the loopback; see the module doc.
    SelfEcho,
    /// Another node's Scout: a question, not an answer to ours. Ordinary on a
    /// shared group.
    ForeignScout,
    /// A scouting-namespace datagram whose MID is neither Scout nor Hello.
    ///
    /// Upstream's `default:` arm — `_Z_ERR_MESSAGE_UNEXPECTED`. Carries the MID
    /// so a report can say WHICH, the way
    /// [`ScoutIgnored::WhatMismatch`](crate::scout_responder::ScoutIgnored::WhatMismatch)
    /// carries the mask it refused.
    UnknownMid {
        /// The datagram header's low 5 bits.
        mid: u8,
    },
}

/// Read one datagram the initiator did NOT take as this cycle's Hello, and say
/// why.
///
/// `zid` is this node's own scouting zid ([`crate::scout_params::ScoutParams`]'s
/// field), which is what makes [`ScoutRxIgnored::SelfEcho`] decidable at all —
/// the same gate, on the same field, that
/// [`answer_scout`](crate::scout_responder::answer_scout) applies for the same
/// reason.
///
/// # Precondition, and why it is not an `unreachable!`
///
/// The caller has already decided this datagram is not a Hello it can use, so a
/// `Hello` frame arriving here means the namespace parser accepted bytes the
/// cycle's own Hello decoder refused. That is reported as
/// [`ScoutRxIgnored::Undecodable`] — which is what it is — rather than as a
/// panic. A scouting group is UNTRUSTED input: a disagreement between two
/// decoders is a thing a stranger can provoke, and provoking a panic must not
/// be one of the things it buys.
pub fn classify_ignored_scout_rx(zid: &[u8], datagram: &[u8]) -> ScoutRxIgnored {
    match parse_scouting(datagram) {
        Err(_) => ScoutRxIgnored::Undecodable,
        Ok(ScoutingFrame::Scout { body, .. }) => match body.zid.as_ref() {
            Some(seen) if seen.as_ref() == zid => ScoutRxIgnored::SelfEcho,
            _ => ScoutRxIgnored::ForeignScout,
        },
        Ok(ScoutingFrame::Unknown { mid }) => ScoutRxIgnored::UnknownMid { mid },
        // See "Precondition" above: the caller's own Hello decoder refused it.
        Ok(_) => ScoutRxIgnored::Undecodable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    const OUR_ZID: &[u8] = &[0xAA, 0xBB, 0xCC, 0xDD];
    const THEIR_ZID: &[u8] = &[0x11, 0x22, 0x33, 0x44];

    /// A framed Scout carrying `zid`, built through the CODEC rather than by
    /// hand.
    ///
    /// Hand-assembling the bytes is what the first draft of this test did, and
    /// it silently produced a Scout with NO zid: the id rides an `I` flag as
    /// well as the `zid_len_m1` nibble, so bytes that look right decode to
    /// `zid: None` and every self-echo reads as a stranger. The encoder is the
    /// only thing that knows the whole shape — the same reason
    /// `scout_responder`'s own fixture builds its Scouts this way.
    fn scout_datagram(zid: &[u8]) -> Vec<u8> {
        use wz_codecs::scout::Scout;

        let mut scout = Scout::new();
        scout.version = 0x09;
        scout.set_what(0x03);
        scout.set_i(true);
        scout.set_zid_len_m1((zid.len() - 1) as u8);
        scout.zid = Some(zid);
        let mut wire = vec![crate::wire_const::S_MID_SCOUT];
        wire.extend_from_slice(&scout.encode_to_vec());
        wire
    }

    /// The fixture's own precondition. If this ever stops holding, every
    /// verdict below degenerates to `ForeignScout` and the discriminator
    /// between the two Scout arms would silently stop discriminating.
    #[test]
    fn the_fixture_really_carries_a_zid() {
        match parse_scouting(&scout_datagram(OUR_ZID)) {
            Ok(ScoutingFrame::Scout { body, .. }) => assert_eq!(
                body.zid.as_ref().map(|z| z.as_ref().to_vec()),
                Some(OUR_ZID.to_vec()),
            ),
            other => panic!("fixture must decode as a Scout, got {other:?}"),
        }
    }

    /// Our own question, back from `IP_MULTICAST_LOOP`. The variant exists
    /// because wz asks for the loopback and pico does not; see the module doc.
    #[test]
    fn our_own_looped_back_scout_is_a_self_echo() {
        assert_eq!(
            classify_ignored_scout_rx(OUR_ZID, &scout_datagram(OUR_ZID)),
            ScoutRxIgnored::SelfEcho,
        );
    }

    /// DISCRIMINATOR for the arm above: the identical datagram shape with a
    /// DIFFERENT zid must not read as our echo. Without this the self-echo test
    /// would pass on a classifier that answered `SelfEcho` for every Scout.
    #[test]
    fn another_nodes_scout_is_foreign_not_our_echo() {
        assert_eq!(
            classify_ignored_scout_rx(OUR_ZID, &scout_datagram(THEIR_ZID)),
            ScoutRxIgnored::ForeignScout,
        );
    }

    /// Upstream's `default:` arm. The MID rides the verdict so a report can
    /// name it.
    #[test]
    fn a_mid_outside_the_scouting_namespace_is_unknown_and_names_itself() {
        // 0x1E is neither S_MID_SCOUT nor S_MID_HELLO.
        assert_eq!(
            classify_ignored_scout_rx(OUR_ZID, &[0x1E, 0x00, 0x00]),
            ScoutRxIgnored::UnknownMid { mid: 0x1E },
        );
    }

    /// Upstream's `"malformed message"`. A Scout MID with nothing behind it
    /// cannot decode.
    #[test]
    fn a_truncated_scout_is_undecodable() {
        assert_eq!(
            classify_ignored_scout_rx(OUR_ZID, &[crate::wire_const::S_MID_SCOUT]),
            ScoutRxIgnored::Undecodable,
        );
    }

    /// An EMPTY datagram has no header at all. Pinned because the parser's
    /// first act is to read one byte, and a classifier that indexed instead of
    /// asking would panic on input a stranger can send.
    #[test]
    fn an_empty_datagram_is_undecodable_and_does_not_panic() {
        assert_eq!(
            classify_ignored_scout_rx(OUR_ZID, &[]),
            ScoutRxIgnored::Undecodable,
        );
    }
}
