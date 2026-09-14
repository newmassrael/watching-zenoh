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
    /// R2610 — a well-formed Hello that advertised NO address, declined by an
    /// exit-on-first window: a peer that answered with nothing to dial.
    ///
    /// Upstream's `_Z_NO_DATA_PROCESSED` — see [`hello_advances_window`] for
    /// the rule and both references it is read from. The window does not end on
    /// it, so it is neither a discovery nor a silent drop, which is exactly the
    /// gap this verdict fills.
    LocatorlessHello,
}

/// Does this Hello ADVANCE the cycle that observed it, or is it a peer with
/// nothing to dial that a still-searching window must keep looking past?
///
/// # The rule, and that both references hold it
///
/// A Hello advertising no locator gives an initiator nothing to connect to.
/// Upstream declines it in the arm that would otherwise CLOSE the search, and
/// keeps it in the arm that is only collecting:
///
/// * zenoh-pico returns `_Z_NO_DATA_PROCESSED` before recording it, but ONLY
///   under `exit_on_first` — `vendor/zenoh-pico/src/session/scout.c` @
///   `if ((locator_count == 0) && exit_on_first) {`. Its window break is driven
///   by whether a hello was RECORDED (the same file, `} else if (exit_on_first
///   && (*hellos != NULL)) {`), so declining to record IS declining to end the
///   window. The survey arm records it, which is why the mode is a parameter
///   here rather than a constant.
/// * zenoh does the same thing in its own vocabulary: its scout callback
///   returns `Loop::Continue` for a locator-less Hello and only `Loop::Break`
///   once a hello's locators produce a connection —
///   `zenoh/src/net/runtime/orchestrator.rs` @ `if !hello.locators.is_empty() {`.
///
/// # Why it is a FUNCTION, and in this crate
///
/// The consequence of getting it wrong is not cosmetic: the exit-on-first arm
/// is the SESSION-OPEN scout, and the group it listens on is untrusted. A rule
/// spelled inline in the runtime's drive loop would be decidable only with a
/// socket, so the case that matters — one stranger's empty answer ending
/// everybody's discovery — would be testable only in an environment-dependent
/// lane. Here it is a pure predicate over the two quantities that decide it.
pub fn hello_advances_window(exit_on_first: bool, locator_count: usize) -> bool {
    !(exit_on_first && locator_count == 0)
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
/// The caller has already decided this datagram is not a Hello it can use, and
/// a `Hello` frame arriving here therefore means ONE of two things. Either it
/// advertised no address and the cycle declined it by the exit-on-first rule
/// ([`hello_advances_window`]) — [`ScoutRxIgnored::LocatorlessHello`] — or the
/// namespace parser accepted bytes the cycle's own Hello decoder refused, which
/// is reported as [`ScoutRxIgnored::Undecodable`] rather than as a panic. A
/// scouting group is UNTRUSTED input: a disagreement between two decoders is a
/// thing a stranger can provoke, and provoking a panic must not be one of the
/// things it buys.
///
/// The two are told apart by the locator count and nothing else, so this stays
/// a pure function of the bytes: the mode is not a parameter because a
/// locator-less Hello only ever REACHES here from the arm that declines it.
pub fn classify_ignored_scout_rx(zid: &[u8], datagram: &[u8]) -> ScoutRxIgnored {
    match parse_scouting(datagram) {
        Err(_) => ScoutRxIgnored::Undecodable,
        Ok(ScoutingFrame::Scout { body, .. }) => match body.zid.as_ref() {
            Some(seen) if seen.as_ref() == zid => ScoutRxIgnored::SelfEcho,
            _ => ScoutRxIgnored::ForeignScout,
        },
        Ok(ScoutingFrame::Unknown { mid }) => ScoutRxIgnored::UnknownMid { mid },
        // R2610 — a Hello the cycle COULD read and still declined; see the
        // precondition above. The L flag clear and an empty list are the same
        // statement, so the decoded list is what is counted.
        Ok(ScoutingFrame::Hello { ref body, .. })
            if body.locators.as_ref().map_or(0, |locs| locs.len()) == 0 =>
        {
            ScoutRxIgnored::LocatorlessHello
        }
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

    /// R2610 — a framed Hello advertising `locators`, built through the CODEC
    /// for the reason [`scout_datagram`] is: the header's L flag and the body's
    /// locator list are two spellings of one fact, and bytes that disagree
    /// decode to a shape no window ever observes.
    fn hello_datagram(locators: &[&str]) -> Vec<u8> {
        use wz_codecs::hello::HelloOwned;
        use wz_codecs::locator::LocatorOwned;

        const ZID: &[u8] = &[0x07, 0x08];
        let l_flag = u8::from(!locators.is_empty());
        let owned: HelloOwned = HelloOwned {
            version: 0x09,
            // whatami=router | zid_len_m1 << 4, the layout `scout_responder`
            // reads back.
            cbyte: 0x01 | (((ZID.len() as u8) - 1) << 4),
            zid: crate::codec_owned::owned_bytes(ZID).unwrap(),
            num_locators: (!locators.is_empty()).then_some(locators.len() as u64),
            locators: (!locators.is_empty()).then(|| {
                locators
                    .iter()
                    .map(|l| LocatorOwned {
                        locator_len: l.len() as u64,
                        locator: crate::codec_owned::owned_string(l).unwrap(),
                    })
                    .collect()
            }),
        };
        let body = owned
            .try_as_borrowed()
            .expect("borrowed projection of owned Hello")
            .encode_to_vec(l_flag);

        let mut wire = vec![if l_flag == 1 {
            crate::wire_const::S_MID_HELLO | crate::wire_const::FLAG_S_HELLO_L
        } else {
            crate::wire_const::S_MID_HELLO
        }];
        wire.extend_from_slice(&body);
        wire
    }

    /// R2610 — a peer that answered with no address is NOT a malformed message.
    ///
    /// The distinction is the verdict's whole reason to exist: before it, the
    /// only Hello arm here was the decoder-disagreement one, so the exit-on-first
    /// rule could not decline a Hello without reporting a stranger's well-formed
    /// answer as corrupt.
    #[test]
    fn a_locator_less_hello_is_a_peer_with_nothing_to_dial_not_a_malformed_message() {
        assert_eq!(
            classify_ignored_scout_rx(OUR_ZID, &hello_datagram(&[])),
            ScoutRxIgnored::LocatorlessHello,
        );
    }

    /// DISCRIMINATOR for the arm above: a Hello that DOES carry a locator can
    /// only reach this function through the precondition's other door, and must
    /// still read as the decoder disagreement it is. Without this the verdict
    /// would pass on a classifier that called every Hello locator-less.
    #[test]
    fn a_hello_that_carries_a_locator_reaching_here_is_a_decoder_disagreement() {
        assert_eq!(
            classify_ignored_scout_rx(OUR_ZID, &hello_datagram(&["udp/127.0.0.1:7447"])),
            ScoutRxIgnored::Undecodable,
        );
    }

    /// R2610 — the rule itself, as its truth table. Three of the four inputs
    /// must ADVANCE: upstream declines a locator-less Hello only in the arm
    /// that would otherwise stop searching, and records it in the arm that is
    /// only collecting (`vendor/zenoh-pico/src/session/scout.c` @
    /// `if ((locator_count == 0) && exit_on_first) {`). A predicate that read
    /// the locator count alone would pass every test above and silently drop a
    /// survey's locator-less peers, which is a record upstream keeps.
    #[test]
    fn only_an_exit_on_first_cycle_declines_a_locator_less_hello() {
        assert!(!hello_advances_window(true, 0));
        assert!(hello_advances_window(true, 1));
        assert!(hello_advances_window(false, 0));
        assert!(hello_advances_window(false, 2));
    }
}
