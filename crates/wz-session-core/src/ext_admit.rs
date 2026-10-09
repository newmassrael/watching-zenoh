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
    /// A network message's own chain: the envelope of a `Push`, a `Request`...
    Network(NetworkEnvelope),
    /// The chain of one declaration inside a `Declare`.
    Declaration(DeclarationKind),
    /// The chain of a zenoh body: a `Put`, a `Del`, a `Query`, a `Reply`, an `Err`.
    Zenoh(ZenohBody),
}

/// The network messages whose OWN extension chain is judged. Named, and not keyed
/// by `N_MID_*`, because those constants are gated on the codec that decodes the
/// message and an observer judges a chain whatever it was built with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkEnvelope {
    /// `Push`.
    Push,
    /// `Request`.
    Request,
    /// `Response`.
    Response,
    /// `ResponseFinal`.
    ResponseFinal,
    /// `Interest`.
    Interest,
    /// `Declare`.
    Declare,
    /// The network `OAM`.
    Oam,
}

/// The declarations a `Declare` carries, each with a chain of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeclarationKind {
    /// `DeclareKeyExpr`.
    KeyExpr,
    /// `UndeclareKeyExpr`.
    UndeclKeyExpr,
    /// `DeclareSubscriber`.
    Subscriber,
    /// `UndeclareSubscriber`.
    UndeclSubscriber,
    /// `DeclareQueryable`.
    Queryable,
    /// `UndeclareQueryable`.
    UndeclQueryable,
    /// `DeclareToken`.
    Token,
    /// `UndeclareToken`.
    UndeclToken,
    /// `DeclareFinal`.
    Final,
}

/// The zenoh bodies that carry a chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZenohBody {
    /// `Put`.
    Put,
    /// `Del`.
    Del,
    /// `Query`.
    Query,
    /// `Reply`, whose own chain is the one beside its Put or Del.
    Reply,
    /// `Err`.
    Err,
}

/// The extensions the reader of the message named by `carrier` declares, as
/// [`crate::ext_name`]'s rows for that message: the one table of what each
/// carrier declares, which names an extension for a reader and, here, decides
/// whether a MANDATORY one is understood.
///
/// DERIVED rather than kept beside that table. This module used to hold
/// its own list of the mandatory identities per transport message, a second
/// copy of rows [`crate::ext_name`] already spells one `zext*!` declaration at
/// a time; extending the rule to the network messages and the zenoh bodies
/// would have made it a second copy of most of that table. A row is matched by
/// its whole identity (`id | M | enc`, zenoh `iext::eid`), so a mandatory
/// extension is understood exactly when the carrier declares that identity,
/// and a declared id in another shape is not.
///
/// `Some(&[])` is a message whose reader declares no extension at all, so any
/// mandatory one on it is unknown. `None` means this build cannot name the
/// message, so it has no space to judge against ([`ExtAdmission::Unjudged`]).
///
/// The declarations it comes to, with the encoding bits part of the identity
/// (R311y505):
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
/// - The NETWORK messages: `Push` and `Declare` and `Interest` define
///   the node id (`zextz64!(0x3, true)`, `0x33`) and `Request` that and the target
///   (`zextz64!(0x4, true)`, `0x34`); `Response`, `ResponseFinal` and the network
///   `OAM` define no mandatory extension. A DECLARATION defines none either,
///   except the three `Undeclare*` that carry the wire expression
///   (`zextzbuf!(0x0f, true)`, `0x5F`). The ZENOH bodies define the shared-memory
///   marker (`zextunit!(0x2, true)`, `0x12`) on `Put` and `Err` and nothing
///   mandatory on `Del`, `Query` (whose marker `0x04` is not mandatory) or
///   `Reply`. Each of these is one of the `::ID =>` arms of the message's
///   reader in `commons/zenoh-codec`, kept because it is declared mandatory;
///   the `Put` and `Err` marker is read only in a build with shared memory,
///   which `reads_mandatory` below says.
/// - SCOUT (`zenoh-protocol-1.5.0/src/scouting/scout.rs`) and HELLO
///   (`scouting/hello.rs`) declare no `mod ext` AT ALL, so the scouting
///   namespace's space is empty and any mandatory extension on one is unknown.
///   pico agrees by construction: `_z_scouting_message_decode_na`
///   (`src/protocol/codec/message.c:756`) ends in
///   `_z_msg_ext_skip_non_mandatories`, which refuses every mandatory entry.
pub fn declared_extensions(carrier: ExtCarrier) -> Option<&'static [(u8, bool, u8, &'static str)]> {
    use crate::ext_name::{rows, ExtCarrier as Named};
    let named = match carrier {
        ExtCarrier::Transport(wire_const::T_MID_INIT) => Named::Init,
        ExtCarrier::Transport(wire_const::T_MID_OPEN) => Named::Open,
        ExtCarrier::Transport(wire_const::T_MID_CLOSE | wire_const::T_MID_KEEP_ALIVE) => {
            Named::TransportPlain
        }
        ExtCarrier::Transport(wire_const::T_MID_OAM) => Named::TransportOam,
        ExtCarrier::Transport(wire_const::T_MID_FRAME) => Named::Frame,
        ExtCarrier::Transport(wire_const::T_MID_FRAGMENT) => Named::Fragment,
        ExtCarrier::Transport(wire_const::T_MID_JOIN) => Named::Join,
        // The scouting messages and four of the declarations read no extension
        // (`extension::skip_all`, or `extension::skip` with no arm before it), so
        // no row of the naming table stands for them.
        ExtCarrier::Scouting(wire_const::S_MID_SCOUT | wire_const::S_MID_HELLO)
        | ExtCarrier::Declaration(
            DeclarationKind::KeyExpr
            | DeclarationKind::UndeclKeyExpr
            | DeclarationKind::Subscriber
            | DeclarationKind::Token
            | DeclarationKind::Final,
        ) => return Some(&[]),
        ExtCarrier::Network(NetworkEnvelope::Push) => Named::Push,
        ExtCarrier::Network(NetworkEnvelope::Request) => Named::Request,
        ExtCarrier::Network(NetworkEnvelope::Response) => Named::Response,
        ExtCarrier::Network(NetworkEnvelope::ResponseFinal) => Named::ResponseFinal,
        ExtCarrier::Network(NetworkEnvelope::Interest) => Named::Interest,
        ExtCarrier::Network(NetworkEnvelope::Declare) => Named::Declare,
        ExtCarrier::Network(NetworkEnvelope::Oam) => Named::NetworkOam,
        ExtCarrier::Declaration(
            DeclarationKind::UndeclSubscriber
            | DeclarationKind::UndeclQueryable
            | DeclarationKind::UndeclToken,
        ) => Named::DeclareCommon,
        ExtCarrier::Declaration(DeclarationKind::Queryable) => Named::DeclareQueryable,
        ExtCarrier::Zenoh(ZenohBody::Put) => Named::Put,
        ExtCarrier::Zenoh(ZenohBody::Del) => Named::Del,
        ExtCarrier::Zenoh(ZenohBody::Query) => Named::Query,
        ExtCarrier::Zenoh(ZenohBody::Reply) => Named::Reply,
        ExtCarrier::Zenoh(ZenohBody::Err) => Named::Err,
        ExtCarrier::Transport(_) | ExtCarrier::Scouting(_) => return None,
    };
    Some(rows(named))
}

/// Whether THIS build's participant reads the mandatory extension `eid` on the
/// message `carrier` names, whose reader declares `declared`.
///
/// Declared is not always enough, and the one exception is upstream's own: the
/// reader arm for the shared-memory marker of a `Put` and an `Err` is compiled
/// only with the `shared-memory` feature (`commons/zenoh-codec/src/zenoh/put.rs`
/// @ `ext::Shm::ID => {`, behind `#[cfg(feature = "shared-memory")]`, and the
/// same in `commons/zenoh-codec/src/zenoh/err.rs` @ `ext::Shm::ID => {`), and a
/// default build leaves that feature out. Such a reader
/// refuses the marked message as carrying an unknown mandatory extension, which
/// is the marker's whole purpose: a receiver that cannot map the segment must
/// not read the descriptor in the payload slot as data. wz reads the marker in
/// a build with `transport-shm`, and refuses it in one without, as upstream's
/// default build does.
fn reads_mandatory(
    carrier: ExtCarrier,
    declared: &[(u8, bool, u8, &'static str)],
    eid: u8,
) -> bool {
    let is_declared = declared
        .iter()
        .any(|row| crate::ext_name::row_eid(row) == eid);
    let compiled_in = match carrier {
        ExtCarrier::Zenoh(ZenohBody::Put | ZenohBody::Err) => {
            eid != crate::ext_header::body_eid::SHM || cfg!(feature = "transport-shm")
        }
        _ => true,
    };
    is_declared && compiled_in
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
    let Some(declared) = declared_extensions(carrier) else {
        return ExtAdmission::Unjudged;
    };
    for header in headers {
        let eid = ext_eid(header);
        if (eid & EXT_FLAG_M) != 0 && !reads_mandatory(carrier, declared, eid) {
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

    /// Every carrier admits EXACTLY the mandatory identities its reader
    /// declares, and refuses every other header with the M bit set, the reserved
    /// encoding included. The admitted bytes are literals read from the
    /// declarations, on purpose: the rule derives them from the naming table, and
    /// a test that derived them the same way would only prove the derivation
    /// agrees with itself.
    ///
    /// The shared-memory marker of a `Put` and an `Err` (`0x12`) is admitted only
    /// in a build that reads it, as upstream's reader arm for it is compiled only
    /// with its `shared-memory` feature (`commons/zenoh-codec/src/zenoh/put.rs` @
    /// `ext::Shm::ID => {`).
    #[test]
    fn every_carrier_admits_exactly_the_mandatory_identities_its_reader_declares() {
        use DeclarationKind as K;
        use NetworkEnvelope as N;
        use ZenohBody as Z;
        let shm: &[u8] = if cfg!(feature = "transport-shm") {
            &[0x12]
        } else {
            &[]
        };
        let cases: [(ExtCarrier, &[u8]); 31] = [
            (ExtCarrier::Transport(wire_const::T_MID_INIT), &[]),
            (ExtCarrier::Transport(wire_const::T_MID_OPEN), &[]),
            (ExtCarrier::Transport(wire_const::T_MID_CLOSE), &[]),
            (ExtCarrier::Transport(wire_const::T_MID_KEEP_ALIVE), &[]),
            (ExtCarrier::Transport(wire_const::T_MID_OAM), &[0x31]),
            (ExtCarrier::Transport(wire_const::T_MID_FRAME), &[0x31]),
            (ExtCarrier::Transport(wire_const::T_MID_FRAGMENT), &[0x31]),
            (ExtCarrier::Transport(wire_const::T_MID_JOIN), &[0x51, 0x52]),
            (ExtCarrier::Scouting(wire_const::S_MID_SCOUT), &[]),
            (ExtCarrier::Scouting(wire_const::S_MID_HELLO), &[]),
            (ExtCarrier::Network(N::Push), &[0x33]),
            (ExtCarrier::Network(N::Request), &[0x33, 0x34]),
            (ExtCarrier::Network(N::Response), &[]),
            (ExtCarrier::Network(N::ResponseFinal), &[]),
            (ExtCarrier::Network(N::Interest), &[0x33]),
            (ExtCarrier::Network(N::Declare), &[0x33]),
            (ExtCarrier::Network(N::Oam), &[]),
            (ExtCarrier::Declaration(K::KeyExpr), &[]),
            (ExtCarrier::Declaration(K::UndeclKeyExpr), &[]),
            (ExtCarrier::Declaration(K::Subscriber), &[]),
            (ExtCarrier::Declaration(K::UndeclSubscriber), &[0x5F]),
            (ExtCarrier::Declaration(K::Queryable), &[]),
            (ExtCarrier::Declaration(K::UndeclQueryable), &[0x5F]),
            (ExtCarrier::Declaration(K::Token), &[]),
            (ExtCarrier::Declaration(K::UndeclToken), &[0x5F]),
            (ExtCarrier::Declaration(K::Final), &[]),
            (ExtCarrier::Zenoh(Z::Put), shm),
            (ExtCarrier::Zenoh(Z::Del), &[]),
            (ExtCarrier::Zenoh(Z::Query), &[]),
            (ExtCarrier::Zenoh(Z::Reply), &[]),
            (ExtCarrier::Zenoh(Z::Err), shm),
        ];
        for (carrier, admitted) in cases {
            for eid in (0u8..0x80).filter(|h| h & EXT_FLAG_M != 0) {
                let want = if admitted.contains(&eid) {
                    ExtAdmission::Admissible
                } else {
                    ExtAdmission::UnknownMandatory { eid }
                };
                assert_eq!(
                    judge_ext_chain(carrier, [eid]),
                    want,
                    "{carrier:?}: {eid:#04x}"
                );
            }
        }
    }
}
