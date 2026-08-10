// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Scouting-message decode SSOT — the namespace [`crate::inbound`] is NOT.
//!
//! zenoh carries two disjoint message-ID namespaces over the wire, and they
//! COLLIDE numerically: `S_MID_SCOUT` is `0x01` and so is `T_MID_INIT`;
//! `S_MID_HELLO` is `0x02` and so is `T_MID_OPEN`
//! (`wz_codecs::wire_const`). Which namespace a byte belongs to is decided by
//! the link that carried it, not by the byte — so a decoder handed the wrong
//! namespace does not fail, it MISREADS, and a misread is worse than an
//! un-read because every downstream assertion still holds.
//!
//! [`parse_scouting`] is the other half of that pair: it decodes one datagram
//! in the SCOUTING namespace, exactly as [`crate::inbound::parse_inbound`]
//! decodes one in the transport namespace. Neither can be reached from the
//! other's dispatch, which is the point — the caller states which namespace it
//! observed, and stating it wrong is a caller bug rather than a silent
//! reinterpretation inside a shared `match`.
//!
//! # The envelope
//!
//! One header byte carrying `(flags << 5) | mid`, then the body, then a
//! Z-flag-gated extension chain — the same shape the transport envelope has,
//! and pico decodes it in exactly that order
//! (`_z_scouting_message_decode_na`, `src/protocol/codec/message.c:724-761`:
//! header, `switch (mid)`, then `_z_msg_ext_skip_non_mandatories` when
//! `_Z_MSG_EXT_FLAG_Z` is set). The bodies themselves carry no header of their
//! own; SCOUT reads none of the header's flag bits and HELLO reads one
//! (`FLAG_S_HELLO_L`, the locator list).

#[cfg(any(feature = "codec-scout", feature = "codec-hello"))]
use alloc::vec::Vec;

use crate::parse_error::InboundParseError;

#[cfg(any(feature = "codec-scout", feature = "codec-hello"))]
use crate::ext_chain::decode_ext_chain;
#[cfg(any(feature = "codec-scout", feature = "codec-hello"))]
use sce_forge_runtime::codec::SceCursor;
#[cfg(any(feature = "codec-scout", feature = "codec-hello"))]
use wz_codecs::ext_entry::ExtEntryOwned;
#[cfg(any(feature = "codec-scout", feature = "codec-hello"))]
use wz_codecs::wire_const;

#[cfg(feature = "codec-hello")]
use wz_codecs::hello::{Hello, HelloOwned};
#[cfg(feature = "codec-scout")]
use wz_codecs::scout::{Scout, ScoutOwned};

/// One decoded scouting message.
///
/// Deliberately a SEPARATE type from [`crate::inbound::InboundFrame`] rather
/// than two more variants on it. The two namespaces are disjoint upstream —
/// pico models them as `_z_scouting_message_t` and `_z_transport_message_t`,
/// decoded by different functions — and folding them into one enum would make
/// `InboundFrame::Scout` constructible from a transport dispatch, which is the
/// exact confusion this module exists to make unrepresentable.
///
/// `Debug` alone, for the same reason [`crate::inbound::InboundFrame`] carries
/// only `Debug`: the bodies are codegen'd `*Owned` mirrors whose derive set is
/// SCE's and whose tree is read-only from this workspace, and `ExtEntryOwned`
/// is not `Eq`. Tests discriminate with `matches!` rather than `==`.
#[derive(Debug)]
pub enum ScoutingFrame {
    /// A SCOUT: someone asking who is out there.
    #[cfg(feature = "codec-scout")]
    Scout {
        /// The header's Z flag — an extension chain followed the body.
        has_ext: bool,
        /// The decoded body: protocol version, the `what` interest mask, and
        /// the optional zid of the asker.
        body: ScoutOwned,
        /// The chain, decoded when `has_ext`.
        extensions: Vec<ExtEntryOwned>,
    },
    /// A HELLO: someone answering, with their zid and how to reach them.
    #[cfg(feature = "codec-hello")]
    Hello {
        /// The header's Z flag.
        has_ext: bool,
        /// The decoded body: version, whatami, zid, and — when the header's
        /// `FLAG_S_HELLO_L` was set — the locator list.
        body: HelloOwned,
        /// The chain, decoded when `has_ext`.
        extensions: Vec<ExtEntryOwned>,
    },
    /// A MID that is not in the scouting namespace.
    ///
    /// Reported rather than mapped onto the transport namespace: `0x07` here
    /// is NOT a Join, it is a scouting message this build cannot name, and
    /// saying so is the whole difference between an un-read and a misread.
    Unknown {
        /// The MID byte, masked out of the header.
        mid: u8,
    },
}

/// Decode one datagram observed on a SCOUTING link.
///
/// The caller asserts the namespace by choosing this function over
/// [`crate::inbound::parse_inbound`]. For a passive observer the sound
/// discriminator is the DESTINATION: a multicast destination carrying MID
/// `0x01` / `0x02` cannot be an Init / Open, because a multicast transport has
/// no handshake at all — pico's own multicast receive path drops both with
/// "multicast transports are not expected to handle INIT messages"
/// (`src/transport/multicast/rx.c:493-504`).
pub fn parse_scouting(bytes: &[u8]) -> Result<ScoutingFrame, InboundParseError> {
    let header = *bytes.first().ok_or(InboundParseError::Empty)?;
    let mid = header & 0x1F;
    match mid {
        #[cfg(feature = "codec-scout")]
        wire_const::S_MID_SCOUT => {
            let mut cursor = SceCursor::new(&bytes[1..]);
            let body = Scout::decode(&mut cursor)?.try_into_owned()?;
            let has_ext = (header & wire_const::FLAG_T_Z) != 0;
            let extensions = if has_ext {
                decode_ext_chain(&mut cursor)?
            } else {
                Vec::new()
            };
            Ok(ScoutingFrame::Scout {
                has_ext,
                body,
                extensions,
            })
        }
        #[cfg(feature = "codec-hello")]
        wire_const::S_MID_HELLO => {
            let mut cursor = SceCursor::new(&bytes[1..]);
            // The locator list is present-if-gated on the header's L bit, so
            // the flag is an INPUT to the body decode rather than something
            // read back off it — the same shape `Open`'s T bit has.
            let l = u8::from((header & wire_const::FLAG_S_HELLO_L) != 0);
            let body = Hello::decode(&mut cursor, l)?.try_into_owned()?;
            let has_ext = (header & wire_const::FLAG_T_Z) != 0;
            let extensions = if has_ext {
                decode_ext_chain(&mut cursor)?
            } else {
                Vec::new()
            };
            Ok(ScoutingFrame::Hello {
                has_ext,
                body,
                extensions,
            })
        }
        other => Ok(ScoutingFrame::Unknown { mid: other }),
    }
}

impl ScoutingFrame {
    /// R311y630d — what a conforming PARTICIPANT must do with this frame's
    /// extension chain, the scouting twin of
    /// [`crate::inbound::InboundFrame::ext_admission`].
    ///
    /// It carries the whole reason [`crate::ext_admit::ExtCarrier`] exists.
    /// SCOUT is MID `0x01` and so is INIT, and the two have DIFFERENT
    /// extension spaces: `zenoh-protocol-1.5.0/src/scouting/{scout,hello}.rs`
    /// declare no `mod ext` at all, while `transport/init.rs` declares eight.
    /// Judging a SCOUT against INIT's table would admit an extension nothing
    /// in the scouting namespace defines — a confident wrong answer, which is
    /// exactly what `the_two_namespaces_collide_on_the_same_byte` in this
    /// module has asserted the shape of since R311y607.
    ///
    /// pico agrees that the space is empty by construction:
    /// `_z_scouting_message_decode_na` ends in
    /// `_z_msg_ext_skip_non_mandatories` (`src/protocol/codec/message.c:756`),
    /// which refuses every mandatory entry without exception.
    pub fn ext_admission(&self) -> crate::ext_admit::ExtAdmission {
        use crate::ext_admit::{judge_ext_chain, ExtAdmission, ExtCarrier};
        #[cfg(any(feature = "codec-scout", feature = "codec-hello"))]
        fn judge(mid: u8, entries: &[ExtEntryOwned]) -> ExtAdmission {
            judge_ext_chain(ExtCarrier::Scouting(mid), entries.iter().map(|e| e.header))
        }
        match self {
            #[cfg(feature = "codec-scout")]
            ScoutingFrame::Scout { extensions, .. } => judge(wire_const::S_MID_SCOUT, extensions),
            #[cfg(feature = "codec-hello")]
            ScoutingFrame::Hello { extensions, .. } => judge(wire_const::S_MID_HELLO, extensions),
            ScoutingFrame::Unknown { .. } => ExtAdmission::Unjudged,
        }
    }

    /// R311y668 (§1.2a) — what this scouting message IS, in one word, the
    /// scouting twin of [`crate::inbound::InboundFrame::kind_name`].
    ///
    /// Needed for the same reason the transport one is and by the same caller:
    /// R311y668 gave the analyzer's flow listing its datagram rows, and a
    /// scouting-only capture's content is entirely in this namespace — so
    /// without a name here the rows that finally appeared would have said only
    /// how many.
    ///
    /// The names deliberately do NOT collide with the transport namespace's,
    /// and that is the whole point of the two enums being separate: a listing
    /// showing `Scout` and one showing `Init` are showing byte `0x01` read two
    /// different ways, and a reader must be able to tell which.
    pub fn kind_name(&self) -> &'static str {
        match self {
            #[cfg(feature = "codec-scout")]
            ScoutingFrame::Scout { .. } => "Scout",
            #[cfg(feature = "codec-hello")]
            ScoutingFrame::Hello { .. } => "Hello",
            ScoutingFrame::Unknown { .. } => "Unknown",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole reason this module exists, stated as an assertion: the two
    /// namespaces disagree on what byte `0x01` means, so a decoder that reads
    /// one with the other's dispatch produces a confident wrong answer.
    #[test]
    fn the_two_namespaces_collide_on_the_same_byte() {
        assert_eq!(
            wire_const::S_MID_SCOUT,
            wire_const::T_MID_INIT,
            "SCOUT and INIT share a MID; that is why the link decides"
        );
        assert_eq!(
            wire_const::S_MID_HELLO,
            wire_const::T_MID_OPEN,
            "HELLO and OPEN share a MID"
        );
    }

    #[cfg(feature = "codec-scout")]
    fn scout_wire(flags: u8) -> alloc::vec::Vec<u8> {
        let mut scout = Scout::new();
        scout.version = 0x09;
        scout.set_what(0x03);
        scout.set_i(true);
        scout.set_zid_len_m1(3);
        scout.zid = Some(&[0xAA, 0xBB, 0xCC, 0xDD]);
        let mut wire = alloc::vec![wire_const::S_MID_SCOUT | flags];
        wire.extend_from_slice(&scout.encode_to_vec());
        wire
    }

    #[cfg(feature = "codec-scout")]
    #[test]
    fn a_scout_decodes_through_the_scouting_namespace() {
        let wire = scout_wire(0);
        match parse_scouting(&wire).expect("a well-formed SCOUT must decode") {
            ScoutingFrame::Scout {
                has_ext,
                body,
                extensions,
            } => {
                assert!(!has_ext);
                assert!(extensions.is_empty());
                assert_eq!(body.version, 0x09);
                assert_eq!(body.what(), 0x03);
                assert!(body.i(), "the zid-present bit must survive the decode");
            }
            other => panic!("SCOUT decoded as {other:?}"),
        }
    }

    /// The NEGATIVE arm, and the one that would have caught the defect this
    /// module fixes: the same bytes read through the TRANSPORT namespace do
    /// not fail — they come back as a confident `Init`. A test that only
    /// asserted the positive arm would pass on a build that still misroutes.
    #[cfg(all(feature = "codec-scout", feature = "codec-init-body"))]
    #[test]
    fn the_same_bytes_read_as_transport_are_a_confident_init() {
        let wire = scout_wire(0);
        let misread = crate::inbound::parse_inbound(&wire)
            .expect("this is the defect: it does not fail, it misreads");
        assert!(
            matches!(misread, crate::inbound::InboundFrame::Init { .. }),
            "a SCOUT read in the transport namespace comes back as Init, not \
             as an error: {misread:?}"
        );
    }

    #[cfg(feature = "codec-hello")]
    #[test]
    fn a_hello_without_locators_decodes() {
        let mut hello = Hello::new();
        hello.version = 0x09;
        hello.set_whatami(0x01);
        hello.set_zid_len_m1(3);
        hello.zid = &[1, 2, 3, 4];
        let mut wire = alloc::vec![wire_const::S_MID_HELLO];
        wire.extend_from_slice(&hello.encode_to_vec(0));
        match parse_scouting(&wire).expect("a well-formed HELLO must decode") {
            ScoutingFrame::Hello { body, .. } => {
                assert_eq!(body.version, 0x09);
                assert_eq!(body.whatami(), 0x01);
            }
            other => panic!("HELLO decoded as {other:?}"),
        }
    }

    /// A JOIN's MID means nothing in this namespace, and the answer is a NAME
    /// for the gap rather than a decode of the wrong message.
    #[test]
    fn a_transport_mid_is_unknown_here_rather_than_decoded() {
        let wire = [0x07u8, 0, 0, 0];
        let decoded = parse_scouting(&wire).expect("an unknown MID is not an error");
        assert!(
            matches!(decoded, ScoutingFrame::Unknown { mid: 0x07 }),
            "a JOIN's MID must be NAMED as unknown here, not decoded: {decoded:?}"
        );
    }

    #[test]
    fn an_empty_datagram_is_rejected_rather_than_defaulted() {
        assert!(matches!(parse_scouting(&[]), Err(InboundParseError::Empty)));
    }
}

// ── R311y668 (§1.2a) — the scouting NAME, pinned the same way the transport one
//    is (`crate::inbound::kind_name_tests`). The collision is the reason it needs
//    its own pin: `S_MID_SCOUT` and `T_MID_INIT` are the same byte, so a listing
//    that printed `Init` for a scouting datagram would be a confident wrong
//    answer rather than an absent one. ──
#[cfg(test)]
mod kind_name_tests {
    use super::*;
    use alloc::vec::Vec;

    /// Every variant this build can reach, as (wire, expected name), over real
    /// `parse_scouting` decodes.
    fn reachable() -> Vec<(Vec<u8>, &'static str)> {
        let mut cases: Vec<(Vec<u8>, &'static str)> = Vec::new();

        #[cfg(feature = "codec-scout")]
        {
            let mut scout = wz_codecs::scout::Scout::new();
            scout.version = 0x09;
            scout.set_what(0x03);
            scout.set_i(true);
            scout.set_zid_len_m1(3);
            scout.zid = Some(&[0x11, 0x22, 0x33, 0x44]);
            let mut wire = alloc::vec![wire_const::S_MID_SCOUT];
            wire.extend_from_slice(&scout.encode_to_vec());
            cases.push((wire, "Scout"));
        }

        #[cfg(feature = "codec-hello")]
        {
            let mut hello = wz_codecs::hello::Hello::new();
            hello.version = 0x09;
            hello.set_whatami(0x01);
            hello.set_zid_len_m1(3);
            hello.zid = &[0xA0, 0xA1, 0xA2, 0xA3];
            let mut wire = alloc::vec![wire_const::S_MID_HELLO];
            wire.extend_from_slice(&hello.encode_to_vec(0));
            cases.push((wire, "Hello"));
        }

        // A MID in neither scouting slot. Ungated, so a build with no scouting
        // codec at all still has a case and this vector is never empty.
        cases.push((alloc::vec![0x1F], "Unknown"));
        cases
    }

    /// The set this build must reach, stated independently of the vector — the
    /// R311y634 rule, and the same guard the transport pin needed after a
    /// default-feature build made its vector a single ungated case.
    // `vec![]` cannot express this: every element is `#[cfg]`-gated, and a macro
    // literal has no place to put the attribute. The lint is reading the shape and
    // not the reason.
    #[allow(clippy::vec_init_then_push)]
    fn expected_names() -> Vec<&'static str> {
        let mut want: Vec<&'static str> = Vec::new();
        #[cfg(feature = "codec-scout")]
        want.push("Scout");
        #[cfg(feature = "codec-hello")]
        want.push("Hello");
        want.push("Unknown");
        want
    }

    #[test]
    fn the_fixture_vector_reaches_every_scouting_variant_this_build_has() {
        let got: Vec<&'static str> = reachable().into_iter().map(|(_, n)| n).collect();
        for want in expected_names() {
            assert!(
                got.contains(&want),
                "`{want}` is a variant this build compiles and no fixture \
                 reaches it, so nothing checks its name: {got:?}"
            );
        }
    }

    #[test]
    fn every_reachable_scouting_variant_is_named_by_its_own_identifier() {
        for (wire, expected) in reachable() {
            let frame = parse_scouting(&wire).expect("the fixture wire decodes");
            assert_eq!(
                frame.kind_name(),
                expected,
                "wire {wire:02X?} decoded to {frame:?}, whose name must be \
                 `{expected}`"
            );
        }
    }

    /// THE ONE THAT MATTERS HERE: no scouting name may collide with a transport
    /// name. Byte `0x01` is a SCOUT on the scouting group and an INIT on a
    /// session link, and a listing whose two namespaces shared a word would make
    /// those two events indistinguishable in the one place a reader looks.
    #[cfg(all(feature = "codec-scout", feature = "codec-init-body"))]
    #[test]
    fn no_scouting_name_collides_with_a_transport_name() {
        let scouting: Vec<&'static str> = reachable()
            .into_iter()
            .map(|(_, n)| n)
            // `Unknown` is deliberately shared: both enums have an
            // un-nameable-MID arm and it means the same thing in each.
            .filter(|n| *n != "Unknown")
            .collect();
        for name in scouting {
            let transport =
                crate::inbound::parse_inbound(&[wire_const::T_MID_INIT, 0x09, 0x01, 0xAA])
                    .expect("the init wire decodes");
            assert_ne!(
                name,
                transport.kind_name(),
                "a scouting message and a transport message must not print the \
                 same word for the same byte"
            );
        }
    }
}
