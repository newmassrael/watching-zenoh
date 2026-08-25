// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The MANDATORY-extension admission rule — what a conforming PARTICIPANT must
//! refuse, as distinct from what a decoder can read.
//!
//! ## Why this module exists
//!
//! R311y630 (§14.1). The driving oracle's first honest run found 27
//! disagreements between wz and the real `libzenohpico.so` over a generated
//! 1536-string corpus, and eighteen of them are ONE mechanism: the extension
//! chain carries an entry whose `M` bit is set and whose identity the message's
//! extension space does not define. Both upstream implementations refuse the
//! whole message on that; wz read the entry, named the frame, and carried on.
//!
//! That is the entire point of the `M` bit. zenoh
//! (`zenoh-codec-1.5.0/src/common/extension.rs:27-42`, `read_inner`) logs the
//! unknown extension and returns `DidntRead` when `u.is_mandatory()`;
//! zenoh-pico (`src/protocol/codec/ext.c`, `_z_msg_ext_skip_non_mandatory` ->
//! `_z_msg_ext_unknown_error`) returns
//! `_Z_ERR_MESSAGE_EXTENSION_MANDATORY_AND_UNKNOWN`. A sender marks an
//! extension mandatory precisely to say "process this or drop the message", so
//! a receiver that ignores it acts on a message it has provably not understood.
//!
//! ## Why it is a separate module and not a rejection inside the decoder
//!
//! wz decodes for two consumers with opposite obligations, and this workspace
//! has settled that tension the same way four times (`Frame`'s `priority`,
//! `Fragment`'s `markers`, a JOIN on a unicast session, an `Unknown` MID): the
//! decode reads whatever the peer sent, and whether the message is ADMISSIBLE
//! is decided one layer up. An analyzer reading a capture must still see the
//! extension — reporting "this frame carries a mandatory extension nobody
//! implements" is the single most useful thing it can say about it — while a
//! participant must refuse. Folding the refusal into `decode_ext_chain` would
//! delete the analyzer's answer to buy the participant's.
//!
//! So the rule lives here as a PREDICATE over header bytes, the participant
//! seam ([`crate::inbound::inbound_to_fsm_event`]) consults it, and the decode
//! is unchanged.
//!
//! ## Why header bytes rather than decoded entries
//!
//! The rule reads the header byte and nothing else — id, `M`, and encoding are
//! all in it, and the body is irrelevant to admission. Taking an iterator of
//! `u8` keeps this module unconditional (no codec feature, no storage-profile
//! generic) so every consumer reaches one copy of the rule, including builds
//! whose codec set cannot construct an `ExtEntryOwned` at all.

use crate::ext_header::{ext_eid, EXT_FLAG_M};
use wz_codecs::wire_const;

/// What a conforming PARTICIPANT must do with a decoded extension chain.
///
/// Three answers rather than two, for the reason the driving oracle already
/// had to learn once: "this build cannot judge" is not "this is fine". A
/// reach limit reported as admission is how an observer's blind spot becomes
/// a participant's accepted message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtAdmission {
    /// Every mandatory extension in the chain is one this message's space
    /// defines. A participant may act on the message.
    Admissible,
    /// The chain carries a mandatory extension the message's space does not
    /// define. A participant MUST refuse the whole message; `eid` is the
    /// extension identity (`id | M | enc`, zenoh `iext::eid`) that forced it.
    UnknownMandatory { eid: u8 },
    /// This build has no extension space for that message id, so it has
    /// nothing to judge the chain against. The analyzer's reach limit, not a
    /// verdict about the wire.
    Unjudged,
}

/// WHICH NAMESPACE a message id was read from.
///
/// R311y630d — the id alone is not enough, and this workspace already wrote
/// down why in a different place: "an id is only meaningful together with the
/// carrier it was read from" ([`crate::ext_header::body_ext_id`]). The same
/// hazard is here one level up. `0x01` is `T_MID_INIT` in the transport
/// namespace and `S_MID_SCOUT` in the scouting one, `0x02` is `T_MID_OPEN` and
/// `S_MID_HELLO`, and the two have DIFFERENT extension spaces — INIT declares
/// eight, SCOUT declares none. A bare `u8` key would have silently answered
/// the transport question for a scouting message.
///
/// Making the namespace part of the key means that mistake cannot be written,
/// which is the difference between a rule that is right today and one that
/// stays right when the next namespace arrives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtCarrier {
    /// A transport message, keyed by its `T_MID_*`.
    Transport(u8),
    /// A scouting message (SCOUT / HELLO), keyed by its `S_MID_*`.
    Scouting(u8),
}

/// The MANDATORY extensions each transport message's space defines, as
/// extension IDENTITIES (`id | M | enc` — zenoh `iext::eid`, matched with
/// [`ext_eid`]).
///
/// Only the mandatory ones are listed, and that is a deliberate narrowing
/// rather than an omission: a non-mandatory extension a receiver does not
/// recognise is SKIPPED by both upstreams and by wz, so listing it here would
/// add a line the rule below can never read. Every entry in these tables is
/// load-bearing — it is the difference between a message being admitted and
/// refused.
///
/// `None` means this build cannot name the message, so it has no space to
/// judge against ([`ExtAdmission::Unjudged`]).
///
/// Values are zenoh 1.5.0's own declarations, and the encoding bits are part
/// of the identity (R311y505):
///
/// - INIT (`zenoh-protocol-1.5.0/src/transport/init.rs`, `mod ext`) declares
///   QoS / QoSLink / Shm / Auth / MultiLink / LowLatency / Compression / Patch
///   and every one of them is `zextX!(_, false)` — NONE is mandatory.
/// - OPEN (`transport/open.rs`, `mod ext`) — same, all seven non-mandatory.
/// - CLOSE (`transport/close.rs`) and KEEP_ALIVE (`transport/keepalive.rs`)
///   declare no `mod ext` at all: their spaces are empty, so ANY mandatory
///   extension on one is unknown.
/// - OAM (`transport/oam.rs`) — `QoS = zextz64!(0x1, true)`, the SAME identity
///   byte the data plane's is, which is why it shares the row below.
/// - FRAME (`transport/frame.rs`) — `QoS = zextz64!(0x1, true)`, the one
///   mandatory transport extension in the data plane.
/// - FRAGMENT (`transport/fragment.rs`) — the same mandatory `QoS`, plus
///   `First` / `Drop` which are `zextunit!(_, false)`.
/// - JOIN (`transport/join.rs`) — `QoS = zextzbuf!(0x1, true)` and
///   `Shm = zextzbuf!(0x2, true)`, both mandatory.
/// - SCOUT (`zenoh-protocol-1.5.0/src/scouting/scout.rs`) and HELLO
///   (`scouting/hello.rs`) declare no `mod ext` AT ALL, so the scouting
///   namespace's space is empty and any mandatory extension on one is unknown.
///   pico agrees by construction: `_z_scouting_message_decode_na`
///   (`src/protocol/codec/message.c:756`) ends in
///   `_z_msg_ext_skip_non_mandatories`, which refuses every mandatory entry.
pub fn mandatory_ext_space(carrier: ExtCarrier) -> Option<&'static [u8]> {
    /// `zextz64!(0x1, true)` = id 1 | `FLAG_M` | `ENC_Z64`. Transport OAM
    /// declares the identical identity (`transport/oam.rs`), so the two
    /// carriers below share this constant rather than each getting a name.
    const FRAME_QOS: u8 = 0x01 | EXT_FLAG_M | crate::ext_header::EXT_ENC_Z64;
    /// `zextzbuf!(0x1, true)` = id 1 | `FLAG_M` | `ENC_ZBUF`. Also
    /// zenoh-pico's `_Z_MSG_EXT_ID_JOIN_QOS`
    /// (`include/zenoh-pico/protocol/ext.h:46`), which is the same byte.
    const JOIN_QOS: u8 = 0x01 | EXT_FLAG_M | crate::ext_header::EXT_ENC_ZBUF;
    /// `zextzbuf!(0x2, true)`.
    const JOIN_SHM: u8 = 0x02 | EXT_FLAG_M | crate::ext_header::EXT_ENC_ZBUF;

    match carrier {
        ExtCarrier::Transport(
            wire_const::T_MID_INIT
            | wire_const::T_MID_OPEN
            | wire_const::T_MID_CLOSE
            | wire_const::T_MID_KEEP_ALIVE,
        ) => Some(&[]),
        ExtCarrier::Transport(
            wire_const::T_MID_OAM | wire_const::T_MID_FRAME | wire_const::T_MID_FRAGMENT,
        ) => Some(&[FRAME_QOS]),
        ExtCarrier::Transport(wire_const::T_MID_JOIN) => Some(&[JOIN_QOS, JOIN_SHM]),
        ExtCarrier::Scouting(wire_const::S_MID_SCOUT | wire_const::S_MID_HELLO) => Some(&[]),
        _ => None,
    }
}

/// Judge a decoded extension chain for the message named by `carrier`.
///
/// `headers` is the raw header byte of each entry in chain order. The
/// chain-continuation `Z` bit is not part of an extension's identity and is
/// masked off by [`ext_eid`], so a chain's LAST entry and the same extension
/// in the middle of one judge identically.
///
/// Reports the FIRST offending entry, matching both upstreams: zenoh's
/// `skip_all` loop and pico's `_z_msg_ext_decode_iter` both abort at the first
/// unknown mandatory extension rather than surveying the rest.
pub fn judge_ext_chain(carrier: ExtCarrier, headers: impl IntoIterator<Item = u8>) -> ExtAdmission {
    let Some(space) = mandatory_ext_space(carrier) else {
        return ExtAdmission::Unjudged;
    };
    for header in headers {
        let eid = ext_eid(header);
        if (eid & EXT_FLAG_M) != 0 && !space.contains(&eid) {
            return ExtAdmission::UnknownMandatory { eid };
        }
    }
    ExtAdmission::Admissible
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rule's whole job, on the message space that has NO mandatory
    /// extension at all: a `KEEP_ALIVE` whose chain carries one must be
    /// refused, and the same chain without the `M` bit must not be.
    ///
    /// The negative arm is the discriminating one — a predicate that answered
    /// `UnknownMandatory` for every unrecognised extension would pass the
    /// first assertion while refusing the non-mandatory chains zenoh and pico
    /// both skip, and this workspace's own `ext_qos` / `ext_tstamp` emits ride
    /// exactly those.
    #[test]
    fn a_mandatory_unknown_extension_is_refused_and_a_non_mandatory_one_is_not() {
        // id 0x4, UNIT encoding, M set, chain terminator.
        assert_eq!(
            judge_ext_chain(ExtCarrier::Transport(wire_const::T_MID_KEEP_ALIVE), [0x14]),
            ExtAdmission::UnknownMandatory { eid: 0x14 }
        );
        // The same extension without the mandatory marker.
        assert_eq!(
            judge_ext_chain(ExtCarrier::Transport(wire_const::T_MID_KEEP_ALIVE), [0x04]),
            ExtAdmission::Admissible
        );
    }

    /// The `Z` bit is not part of the identity: the offending extension is
    /// found whether it terminates the chain or continues it, and the reported
    /// `eid` is the same byte both times.
    #[test]
    fn the_chain_continuation_bit_is_not_part_of_the_identity() {
        assert_eq!(
            judge_ext_chain(
                ExtCarrier::Transport(wire_const::T_MID_OPEN),
                [0x94u8, 0x00]
            ),
            ExtAdmission::UnknownMandatory { eid: 0x14 }
        );
    }

    /// The data plane's one mandatory extension is UNDERSTOOD, so a Frame
    /// carrying it is admissible — and the identical id with a different
    /// ENCODING is a different extension and is not.
    ///
    /// The second arm is why the table stores identities rather than id
    /// fields: `0x11` and `0x31` share the id column, and admitting on the id
    /// alone would accept an extension nothing in this workspace can read.
    #[test]
    fn the_frame_qos_extension_is_understood_but_only_at_its_own_encoding() {
        assert_eq!(
            judge_ext_chain(ExtCarrier::Transport(wire_const::T_MID_FRAME), [0x31]),
            ExtAdmission::Admissible
        );
        assert_eq!(
            judge_ext_chain(ExtCarrier::Transport(wire_const::T_MID_FRAME), [0x11]),
            ExtAdmission::UnknownMandatory { eid: 0x11 }
        );
    }

    /// Transport OAM (MID 0x00) declares exactly one mandatory extension
    /// upstream — `ext::QoS = zextz64!(0x1, true)`
    /// (`zenoh-protocol/src/transport/oam.rs`), the same identity byte the
    /// data plane's is — so its chain is JUDGEABLE. A carrier missing from the
    /// table answers `Unjudged`, and this message's whole purpose is to carry
    /// operations traffic a participant is expected to act on: an observer
    /// that cannot judge its chain reports a reach limit where a verdict
    /// exists.
    #[test]
    fn transport_oam_declares_a_judgeable_mandatory_extension_space() {
        assert_eq!(
            judge_ext_chain(ExtCarrier::Transport(wire_const::T_MID_OAM), [0x31]),
            ExtAdmission::Admissible
        );
        // The discriminating leg: while the carrier is absent from the table
        // BOTH of these answer `Unjudged`, so only a refusal separates a
        // judged space from an unreached one.
        assert_eq!(
            judge_ext_chain(ExtCarrier::Transport(wire_const::T_MID_OAM), [0x14]),
            ExtAdmission::UnknownMandatory { eid: 0x14 }
        );
    }

    /// A message id this build cannot name yields NO verdict. The value of the
    /// distinction is that `Unjudged` can never be mistaken for `Admissible`
    /// by a caller that matches exhaustively.
    #[test]
    fn an_unnameable_message_is_unjudged_rather_than_admissible() {
        assert_eq!(
            judge_ext_chain(ExtCarrier::Transport(0x1F), [0x14]),
            ExtAdmission::Unjudged
        );
    }

    /// The FIRST offender is the one reported, like both upstreams' abort.
    #[test]
    fn the_first_offending_extension_is_the_one_reported() {
        assert_eq!(
            judge_ext_chain(
                ExtCarrier::Transport(wire_const::T_MID_INIT),
                [0x95u8, 0x96, 0x17]
            ),
            ExtAdmission::UnknownMandatory { eid: 0x15 }
        );
    }

    /// An empty chain is admissible on every space, including the empty ones.
    #[test]
    fn an_empty_chain_is_admissible() {
        for mid in [
            ExtCarrier::Transport(wire_const::T_MID_INIT),
            ExtCarrier::Transport(wire_const::T_MID_CLOSE),
            ExtCarrier::Transport(wire_const::T_MID_FRAME),
            ExtCarrier::Transport(wire_const::T_MID_JOIN),
            ExtCarrier::Scouting(wire_const::S_MID_SCOUT),
        ] {
            assert_eq!(judge_ext_chain(mid, []), ExtAdmission::Admissible);
        }
    }
}
