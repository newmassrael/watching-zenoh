// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
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
//! ## The reserved encoding, refused here for the same reason
//!
//! An entry whose encoding bits are `0b11` has no body shape. zenoh 1.10.2's
//! reader of an extension it does not declare answers it with `DidntRead`
//! before it looks at the `M` bit
//! (`commons/zenoh-codec/src/common/extension.rs` @ `let body = match self.header & iext::ENC_MASK {`),
//! and no declared extension has that encoding, so every chain reader refuses
//! the whole message whatever the `M` bit says. The chain decode reads such an
//! entry as a unit (`sources/codecs/ext_entry.scxml`, the default arm), because
//! the analyzer must still show it; the refusal is
//! [`ExtAdmission::ReservedEncoding`](crate::ext_admit::ExtAdmission::ReservedEncoding), one
//! layer up, like the mandatory one.
//! zenoh-pico reads the same entry as a body-less one and accepts the message
//! (`_z_msg_ext_unknown_body_decode`, its `default:` arm): the two presets
//! disagree, and this rule follows zenoh 1.10.2.
//!
//! ## Why header bytes rather than decoded entries
//!
//! The rule reads the header byte and nothing else — id, `M`, and encoding are
//! all in it, and the body is irrelevant to admission. Taking an iterator of
//! `u8` keeps this module unconditional (no codec feature, no storage-profile
//! generic) so every consumer reaches one copy of the rule, including builds
//! whose codec set cannot construct an `ExtEntryOwned` at all.
//!
//! ## A declared extension whose body its reader refuses
//!
//! One refusal is not in the header. zenoh 1.10.2 reads each extension a network
//! message or a zenoh body declares with that extension's own typed reader, as the
//! chain walk meets it, and propagates what the reader refuses with `?`: a Push
//! whose timestamp names the zid zero, a Request whose target is `3`, a Put whose
//! source info is cut short is refused whole, exactly as one that does not decode
//! (`commons/zenoh-codec/src/network/push.rs` @
//! `let (t, ext): (ext::TimestampType, bool) = eodec.read(&mut *reader)?;`). The
//! refusal is of EVERY entry the reader meets, not the one a reader of the chain
//! then keeps: an earlier entry the last one supersedes is read, and refused, all
//! the same. wz's chain decode reads an entry by its encoding alone (a ZInt, a
//! length and bytes), so such an entry decodes; the readers of the chain used to
//! read it as absent, which acted on a message upstream never delivers.
//!
//! [`judge_ext_entries`] judges the entries of a network or zenoh-body chain,
//! headers and bodies, in chain order, and answers
//! [`ExtAdmission::MalformedExt`] for a body the declared extension's reader
//! refuses. The participant seams that judge a chain by its headers judge those
//! chains by their entries instead, so the held, the lent and the walked forms of
//! a message refuse the same bodies. A transport chain keeps the header rule: its
//! bodies are the handshake's to read.

use crate::ext_header::{ext_eid, EXT_ENC_MASK, EXT_FLAG_M};
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
    /// The chain carries an entry whose encoding is the reserved `0b11`, which
    /// has no body shape. A participant MUST refuse the whole message, whatever
    /// the entry's `M` bit says; `eid` is the entry's identity.
    ReservedEncoding { eid: u8 },
    /// The chain carries an extension the message declares whose body the
    /// declared extension's own reader refuses ([`judge_ext_entries`]). A
    /// participant MUST refuse the whole message, as upstream's decoder does; `eid`
    /// is the entry's identity.
    MalformedExt { eid: u8 },
    /// This build has no extension space for that message id, so it has
    /// nothing to judge the chain against. The analyzer's reach limit, not a
    /// verdict about the wire.
    Unjudged,
}

impl ExtAdmission {
    /// Whether a conforming participant must refuse the whole message.
    ///
    /// The one place a caller asks it, so that a refusal added to this enum is
    /// a refusal at every seam rather than at the seams that matched it by name.
    pub const fn is_refusal(self) -> bool {
        matches!(
            self,
            Self::UnknownMandatory { .. }
                | Self::ReservedEncoding { .. }
                | Self::MalformedExt { .. }
        )
    }

    /// The parse error a participant reports its refusal as, or `None` for a
    /// message it may act on (`Admissible`) or cannot judge (`Unjudged`).
    pub const fn refusal(self) -> Option<crate::parse_error::InboundParseError> {
        use crate::parse_error::InboundParseError;
        match self {
            Self::UnknownMandatory { eid } => Some(InboundParseError::UnknownMandatoryExt { eid }),
            Self::ReservedEncoding { eid } => Some(InboundParseError::ReservedExtEncoding { eid }),
            Self::MalformedExt { eid } => Some(InboundParseError::MalformedExt { eid }),
            Self::Admissible | Self::Unjudged => None,
        }
    }
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
    Some(match space(carrier)? {
        Space::ReadsNone => &[],
        Space::Named(named) => crate::ext_name::rows(named),
    })
}

/// [`declared_extensions`] as identities only (`id | M | enc`, zenoh
/// `iext::eid`), which is all the admission rule compares.
///
/// The rule reads these rather than the rows so that an image which admits but
/// never names an extension does not link the naming table's strings
/// ([`crate::ext_name::identities`] says what that cost). The two answer from
/// one private `space` lookup and one table, so they cannot disagree about a
/// carrier.
pub fn declared_identities(carrier: ExtCarrier) -> Option<&'static [u8]> {
    Some(match space(carrier)? {
        Space::ReadsNone => &[],
        Space::Named(named) => crate::ext_name::identities(named),
    })
}

/// Where the declarations of the message `carrier` names are written down.
enum Space {
    /// Its reader reads no extension, so no row of the naming table stands
    /// for it.
    ReadsNone,
    /// Its reader's declarations are the naming table's rows for this carrier.
    Named(crate::ext_name::ExtCarrier),
}

/// The one mapping from a message to its declarations, which
/// [`declared_extensions`] and [`declared_identities`] both read. `None` is a
/// message this build cannot name.
fn space(carrier: ExtCarrier) -> Option<Space> {
    use crate::ext_name::ExtCarrier as Named;
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
        ) => return Some(Space::ReadsNone),
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
    Some(Space::Named(named))
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
fn reads_mandatory(carrier: ExtCarrier, declared: &[u8], eid: u8) -> bool {
    let is_declared = declared.contains(&eid);
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
///
/// An entry with the reserved encoding is judged before its `M` bit, in
/// upstream's order: its reader fails on the encoding while it reads the body,
/// and only a body that was read is asked whether it is mandatory.
pub fn judge_ext_chain(carrier: ExtCarrier, headers: impl IntoIterator<Item = u8>) -> ExtAdmission {
    let Some(declared) = declared_identities(carrier) else {
        return ExtAdmission::Unjudged;
    };
    for header in headers {
        if let Some(refusal) = judge_header(carrier, declared, header) {
            return refusal;
        }
    }
    ExtAdmission::Admissible
}

/// The verdict on one entry's header, `None` for one a participant may read on past: the rule
/// [`judge_ext_chain`] applies to each header and [`judge_ext_entries`] to each entry.
fn judge_header(carrier: ExtCarrier, declared: &[u8], header: u8) -> Option<ExtAdmission> {
    let eid = ext_eid(header);
    if (eid & EXT_ENC_MASK) == EXT_ENC_MASK {
        return Some(ExtAdmission::ReservedEncoding { eid });
    }
    if (eid & EXT_FLAG_M) != 0 && !reads_mandatory(carrier, declared, eid) {
        return Some(ExtAdmission::UnknownMandatory { eid });
    }
    None
}

/// Judge the ENTRIES of a decoded network or zenoh-body chain for the message named by
/// `carrier`: each entry's header by the rule [`judge_ext_chain`] applies, and then the body of
/// an extension the message declares by what that extension's reader refuses
/// ([`ExtAdmission::MalformedExt`]), in chain order, the first offender reported. Upstream reads
/// the chain one entry at a time, the unknown ones by their header and the declared ones by their
/// typed reader, and stops at the first it refuses, so whichever offence comes first is the one
/// its decoder fails on.
///
/// `entries` is the chain held (a slice's references) or walked where its frame lies (entries by
/// value). An entry whose body this build holds as something other than plain bytes (a Query's
/// value after a shared-memory marker, a list of slices) is judged by its header alone: the chain
/// decode read its structure, and its reader is the shared-memory one.
pub fn judge_ext_entries<E: crate::ext_view::ExtEntryView>(
    carrier: ExtCarrier,
    entries: impl IntoIterator<Item = E>,
) -> ExtAdmission {
    let Some(declared) = declared_identities(carrier) else {
        return ExtAdmission::Unjudged;
    };
    for entry in entries {
        if let Some(refusal) = judge_header(carrier, declared, entry.header()) {
            return refusal;
        }
        let eid = entry.eid();
        if body_rule(carrier, eid).is_some_and(|rule| !body_reads(rule, &entry)) {
            return ExtAdmission::MalformedExt { eid };
        }
    }
    ExtAdmission::Admissible
}

/// How upstream's reader of a declared extension reads its body, for the extensions whose reader
/// can refuse one. Every other declared extension is read by a reader that cannot: a QoS, a node
/// id, a budget, a timeout and a queryable's info take any ZInt (`ext.into()`, `as u32`), an
/// attachment any bytes (`reader.read_zbuf(h.len)`), and a marker has no body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyRule {
    /// A `TimestampType` (`commons/zenoh-codec/src/network/mod.rs` @
    /// `let timestamp: uhlc::Timestamp = self.codec.read(&mut *reader)?;`): a ZInt time, a ZInt
    /// length of at most sixteen and that many bytes of an id that is not zero
    /// (`commons/zenoh-codec/src/core/timestamp.rs` @
    /// `let id = uhlc::ID::try_from(&id[..size]).map_err(|_| DidntRead)?;`).
    Timestamp,
    /// A `TsStackType` (`commons/zenoh-codec/src/network/timestamp_stack.rs` @
    /// `let ts_stack: TimestampStack = self.codec.read(&mut *reader)?;`): flags that are not zero,
    /// a count of at most `MAX_STACK_SIZE` (255) and that many interceptions, each a flags byte
    /// and a length-prefixed run of bytes.
    TsStack,
    /// A Request's `QueryTarget` (`commons/zenoh-codec/src/network/request.rs` @
    /// `_ => return Err(DidntRead),`): `0`, `1` or `2`.
    QueryTarget,
    /// An `EntityGlobalIdType`, a Response's responder (`commons/zenoh-codec/src/network/mod.rs`
    /// @ `RCodec<(ext::EntityGlobalIdType<{ ID }>, bool), &mut R>`): a flags byte whose high
    /// nibble is the zid's length less one, a zid that is not zero
    /// (`commons/zenoh-codec/src/core/zenohid.rs` @
    /// `ZenohIdProto::try_from(&id[..self.length]).map_err(|_| DidntRead)`), and a ZInt entity id
    /// of at most 32 bits.
    EntityGlobalId,
    /// An undeclaration's `WireExprType` (`commons/zenoh-codec/src/network/declare.rs` @
    /// `String::from_utf8(buff).map_err(|_| DidntRead)?`): a flags byte, a ZInt scope of at most
    /// 16 bits (`ExprLen`), and, when the flags say a suffix follows, the rest of the body as
    /// UTF-8.
    WireExpr,
    /// A `SourceInfoType` (`commons/zenoh-codec/src/zenoh/mod.rs` @
    /// `RCodec<(ext::SourceInfoType<{ ID }>, bool), &mut R>`): the entity id of
    /// [`Self::EntityGlobalId`] and a ZInt sequence number of at most 32 bits.
    SourceInfo,
    /// A Query's value read as bytes (`commons/zenoh-codec/src/zenoh/mod.rs` @
    /// `let Some(len) = header.len.checked_sub(start - end) else {`): an `Encoding` that fits the
    /// body, a ZInt id of at most 32 bits and, when its low bit says so, a schema of at most 255
    /// bytes (`commons/zenoh-codec/src/core/encoding.rs` @
    /// `let zodec = Zenoh080Bounded::<u8>::new();`).
    QueryValue,
}

/// The reader that reads the extension `eid` on the message `carrier` names, when that reader
/// can refuse a body ([`BodyRule`]). Every pair is a row of the naming table
/// ([`declared_identities`]); the test `every_body_rule_is_of_a_declared_extension` holds them
/// to it.
fn body_rule(carrier: ExtCarrier, eid: u8) -> Option<BodyRule> {
    use crate::ext_header::{body_eid, ext_identity, network_eid, EXT_ENC_Z64, EXT_ENC_ZBUF};
    use DeclarationKind as K;
    use NetworkEnvelope as N;
    use ZenohBody as Z;
    // `pub type Timestamp = zextzbuf!(0x2, false);` on every network message.
    const TIMESTAMP: u8 = ext_identity(0x2, false, EXT_ENC_ZBUF);
    // `pub type TsStack = zextzbuf!(0x7, false);` on a Push, a Request and a Response.
    const TS_STACK: u8 = ext_identity(0x7, false, EXT_ENC_ZBUF);
    // `pub type Target = zextz64!(0x4, true);` on a Request.
    const TARGET: u8 = ext_identity(0x4, true, EXT_ENC_Z64);
    // `pub type WireExprExt = zextzbuf!(0x0f, true);` on the three undeclarations that carry it.
    const WIRE_EXPR: u8 = ext_identity(0x0f, true, EXT_ENC_ZBUF);
    let rule = match (carrier, eid) {
        (ExtCarrier::Network(_), TIMESTAMP) => BodyRule::Timestamp,
        (ExtCarrier::Network(N::Push | N::Request | N::Response), TS_STACK) => BodyRule::TsStack,
        (ExtCarrier::Network(N::Request), TARGET) => BodyRule::QueryTarget,
        (ExtCarrier::Network(N::Response), network_eid::RESPONDER) => BodyRule::EntityGlobalId,
        (
            ExtCarrier::Declaration(K::UndeclSubscriber | K::UndeclQueryable | K::UndeclToken),
            WIRE_EXPR,
        ) => BodyRule::WireExpr,
        (ExtCarrier::Zenoh(Z::Put | Z::Del | Z::Query | Z::Err), body_eid::SOURCE_INFO) => {
            BodyRule::SourceInfo
        }
        (ExtCarrier::Zenoh(Z::Query), body_eid::QUERY_VALUE) => BodyRule::QueryValue,
        _ => return None,
    };
    Some(rule)
}

/// Whether the reader `rule` names reads `entry`'s body. A body this build holds as something
/// other than the encoding the rule reads (no ZInt for a ZInt rule, no plain bytes for a ZBuf
/// one) is not this reader's to judge, and reads.
///
/// Upstream's readers of a timestamp, a responder, a source info and a timestamp stack read their
/// fields from the message's reader after the extension's length, not from the bytes the length
/// covers; wz reads the fields from those bytes, so fields that run past the length are refused
/// here where upstream would read on into what follows them, and bytes the fields leave over are
/// read past here where upstream would read them as the next extension. Both are a sender that
/// wrote a length its fields do not have.
fn body_reads<E: crate::ext_view::ExtEntryView>(rule: BodyRule, entry: &E) -> bool {
    if rule == BodyRule::QueryTarget {
        return entry.zint().is_none_or(|target| target <= 2);
    }
    let Some(body) = entry.plain_zbuf() else {
        return true;
    };
    let mut cursor = sce_forge_runtime::codec::SceCursor::new(body);
    let read = match rule {
        BodyRule::Timestamp => read_timestamp(&mut cursor),
        BodyRule::TsStack => read_ts_stack(&mut cursor),
        BodyRule::EntityGlobalId => read_entity_global_id(&mut cursor),
        BodyRule::WireExpr => read_wire_expr(&mut cursor),
        BodyRule::SourceInfo => {
            read_entity_global_id(&mut cursor).and_then(|()| read_u32(&mut cursor))
        }
        BodyRule::QueryValue => read_encoding(&mut cursor),
        BodyRule::QueryTarget => Some(()),
    };
    read.is_some()
}

/// One byte.
fn read_u8(cursor: &mut sce_forge_runtime::codec::SceCursor<'_>) -> Option<u8> {
    let byte = cursor.peek_u8().ok()?;
    cursor.advance(1).ok()?;
    Some(byte)
}

/// `len` bytes.
fn read_bytes<'a>(
    cursor: &mut sce_forge_runtime::codec::SceCursor<'a>,
    len: usize,
) -> Option<&'a [u8]> {
    let bytes = cursor.peek_slice(len).ok()?;
    cursor.advance(len).ok()?;
    Some(bytes)
}

/// A ZInt length, as upstream reads a `usize`.
fn read_len(cursor: &mut sce_forge_runtime::codec::SceCursor<'_>) -> Option<usize> {
    usize::try_from(cursor.read_vle_u64().ok()?).ok()
}

/// A ZInt of at most 32 bits, as upstream reads a `u32`.
fn read_u32(cursor: &mut sce_forge_runtime::codec::SceCursor<'_>) -> Option<()> {
    cursor.read_vle_u32().ok().map(|_| ())
}

/// `len` bytes of a zid: one to sixteen of them, not all zero, as upstream's `ZenohIdProto` and
/// `uhlc::ID` take them (`crate::session_zid::SessionZid::new` holds the same rule).
fn read_zid(cursor: &mut sce_forge_runtime::codec::SceCursor<'_>, len: usize) -> Option<()> {
    crate::session_zid::SessionZid::new(read_bytes(cursor, len)?)
        .ok()
        .map(|_| ())
}

/// [`BodyRule::Timestamp`].
fn read_timestamp(cursor: &mut sce_forge_runtime::codec::SceCursor<'_>) -> Option<()> {
    cursor.read_vle_u64().ok()?;
    let size = read_len(cursor)?;
    if size > crate::session_zid::ZID_MAX {
        return None;
    }
    read_zid(cursor, size)
}

/// [`BodyRule::TsStack`].
fn read_ts_stack(cursor: &mut sce_forge_runtime::codec::SceCursor<'_>) -> Option<()> {
    /// `commons/zenoh-protocol/src/network/timestamp_stack.rs` @
    /// `pub const MAX_STACK_SIZE: usize = 255;`.
    const MAX_STACK_SIZE: usize = 255;
    if read_u8(cursor)? == 0 {
        return None;
    }
    let count = read_len(cursor)?;
    if count > MAX_STACK_SIZE {
        return None;
    }
    for _ in 0..count {
        read_u8(cursor)?;
        let len = read_len(cursor)?;
        read_bytes(cursor, len)?;
    }
    Some(())
}

/// [`BodyRule::EntityGlobalId`].
fn read_entity_global_id(cursor: &mut sce_forge_runtime::codec::SceCursor<'_>) -> Option<()> {
    let flags = read_u8(cursor)?;
    read_zid(cursor, usize::from(flags >> 4).saturating_add(1))?;
    read_u32(cursor)
}

/// [`BodyRule::WireExpr`].
fn read_wire_expr(cursor: &mut sce_forge_runtime::codec::SceCursor<'_>) -> Option<()> {
    let flags = read_u8(cursor)?;
    cursor.read_vle_u16().ok()?;
    if flags & 0x01 != 0 {
        let rest = cursor.remaining();
        core::str::from_utf8(read_bytes(cursor, rest)?).ok()?;
    }
    Some(())
}

/// [`BodyRule::QueryValue`]: the encoding; the payload is the rest of the body.
fn read_encoding(cursor: &mut sce_forge_runtime::codec::SceCursor<'_>) -> Option<()> {
    let id = cursor.read_vle_u32().ok()?;
    if id & 0x01 != 0 {
        let len = read_len(cursor)?;
        if len > usize::from(u8::MAX) {
            return None;
        }
        read_bytes(cursor, len)?;
    }
    Some(())
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

    /// The reserved encoding is refused on every judged carrier, with the `M`
    /// bit clear as well as set, and before an unknown mandatory entry that
    /// precedes nothing: zenoh's reader fails on the encoding while it reads
    /// the body (`commons/zenoh-codec/src/common/extension.rs` @ `let body = match self.header & iext::ENC_MASK {`).
    /// The `M`-clear leg is the one that was admitted before.
    #[test]
    fn the_reserved_encoding_is_refused_whatever_the_mandatory_bit_says() {
        let carriers = [
            ExtCarrier::Transport(wire_const::T_MID_INIT),
            ExtCarrier::Transport(wire_const::T_MID_KEEP_ALIVE),
            ExtCarrier::Transport(wire_const::T_MID_FRAME),
            ExtCarrier::Scouting(wire_const::S_MID_SCOUT),
            ExtCarrier::Network(NetworkEnvelope::Push),
            ExtCarrier::Declaration(DeclarationKind::Final),
            ExtCarrier::Zenoh(ZenohBody::Reply),
        ];
        for carrier in carriers {
            for id in 0u8..16 {
                for m in [0u8, EXT_FLAG_M] {
                    let eid = id | m | EXT_ENC_MASK;
                    for z in [0u8, crate::ext_header::EXT_FLAG_Z] {
                        let verdict = judge_ext_chain(carrier, [eid | z]);
                        assert_eq!(
                            verdict,
                            ExtAdmission::ReservedEncoding { eid },
                            "{carrier:?} {eid:#04x}"
                        );
                        assert!(verdict.is_refusal());
                    }
                }
            }
        }
        // Behind an admissible entry it is still the one reported.
        assert_eq!(
            judge_ext_chain(
                ExtCarrier::Transport(wire_const::T_MID_INIT),
                [0x81u8, 0x6F]
            ),
            ExtAdmission::ReservedEncoding { eid: 0x6F }
        );
        // The three encodings that have a body are not refused for it.
        for enc in [0x00u8, 0x20, 0x40] {
            assert_eq!(
                judge_ext_chain(
                    ExtCarrier::Transport(wire_const::T_MID_KEEP_ALIVE),
                    [0x0F | enc]
                ),
                ExtAdmission::Admissible
            );
        }
        // A carrier this build cannot name is still unjudged.
        assert_eq!(
            judge_ext_chain(ExtCarrier::Transport(0x1F), [0x6F]),
            ExtAdmission::Unjudged
        );
    }

    /// Each verdict maps to the refusal it is reported as, and the two that a
    /// participant may proceed past map to none.
    #[test]
    fn each_refusal_is_reported_as_its_own_parse_error() {
        use crate::parse_error::InboundParseError as E;
        assert_eq!(
            ExtAdmission::UnknownMandatory { eid: 0x14 }.refusal(),
            Some(E::UnknownMandatoryExt { eid: 0x14 })
        );
        assert_eq!(
            ExtAdmission::ReservedEncoding { eid: 0x6F }.refusal(),
            Some(E::ReservedExtEncoding { eid: 0x6F })
        );
        assert_eq!(
            ExtAdmission::MalformedExt { eid: 0x41 }.refusal(),
            Some(E::MalformedExt { eid: 0x41 })
        );
        assert!(ExtAdmission::MalformedExt { eid: 0x41 }.is_refusal());
        assert_eq!(ExtAdmission::Admissible.refusal(), None);
        assert_eq!(ExtAdmission::Unjudged.refusal(), None);
        assert!(!ExtAdmission::Admissible.is_refusal());
        assert!(!ExtAdmission::Unjudged.is_refusal());
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
                let want = if eid & EXT_ENC_MASK == EXT_ENC_MASK {
                    ExtAdmission::ReservedEncoding { eid }
                } else if admitted.contains(&eid) {
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

    /// An entry as a reader of a chain sees it, made of its header and the body this build holds:
    /// the rule asks nothing else, so the tests need no storage profile to build one.
    struct Entry {
        header: u8,
        zint: Option<u64>,
        zbuf: Option<&'static [u8]>,
    }

    impl crate::ext_view::ExtEntryView for Entry {
        fn header(&self) -> u8 {
            self.header
        }

        fn ext_id(&self) -> u8 {
            self.header & 0x0F
        }

        fn enc(&self) -> u8 {
            (self.header >> 5) & 0x03
        }

        fn plain_zbuf(&self) -> Option<&[u8]> {
            self.zbuf
        }

        fn zint(&self) -> Option<u64> {
            self.zint
        }
    }

    fn zbuf(header: u8, body: &'static [u8]) -> Entry {
        Entry {
            header,
            zint: None,
            zbuf: Some(body),
        }
    }

    fn zint(header: u8, value: u64) -> Entry {
        Entry {
            header,
            zint: Some(value),
            zbuf: None,
        }
    }

    fn unit(header: u8) -> Entry {
        Entry {
            header,
            zint: None,
            zbuf: None,
        }
    }

    /// The carriers a network message or a zenoh body names, each with a chain of its own.
    fn network_carriers() -> [ExtCarrier; 21] {
        use DeclarationKind as K;
        use NetworkEnvelope as N;
        use ZenohBody as Z;
        [
            ExtCarrier::Network(N::Push),
            ExtCarrier::Network(N::Request),
            ExtCarrier::Network(N::Response),
            ExtCarrier::Network(N::ResponseFinal),
            ExtCarrier::Network(N::Interest),
            ExtCarrier::Network(N::Declare),
            ExtCarrier::Network(N::Oam),
            ExtCarrier::Declaration(K::KeyExpr),
            ExtCarrier::Declaration(K::UndeclKeyExpr),
            ExtCarrier::Declaration(K::Subscriber),
            ExtCarrier::Declaration(K::UndeclSubscriber),
            ExtCarrier::Declaration(K::Queryable),
            ExtCarrier::Declaration(K::UndeclQueryable),
            ExtCarrier::Declaration(K::Token),
            ExtCarrier::Declaration(K::UndeclToken),
            ExtCarrier::Declaration(K::Final),
            ExtCarrier::Zenoh(Z::Put),
            ExtCarrier::Zenoh(Z::Del),
            ExtCarrier::Zenoh(Z::Query),
            ExtCarrier::Zenoh(Z::Reply),
            ExtCarrier::Zenoh(Z::Err),
        ]
    }

    /// A body is judged only for an extension its message declares: upstream reads any other
    /// one as unknown, by its header, and never asks its body. Each rule is also the one its row
    /// names, so a rule moved to the wrong identity fails here and not on the wire.
    #[test]
    fn every_body_rule_is_of_a_declared_extension() {
        use DeclarationKind as K;
        use NetworkEnvelope as N;
        use ZenohBody as Z;
        for carrier in network_carriers() {
            let declared = declared_identities(carrier).expect("a named carrier");
            for eid in 0u8..0x80 {
                if body_rule(carrier, eid).is_some() {
                    assert!(declared.contains(&eid), "{carrier:?}: {eid:#04x}");
                }
            }
        }
        let rows = [
            (ExtCarrier::Network(N::Push), 0x42, BodyRule::Timestamp),
            (ExtCarrier::Network(N::Oam), 0x42, BodyRule::Timestamp),
            (
                ExtCarrier::Network(N::ResponseFinal),
                0x42,
                BodyRule::Timestamp,
            ),
            (ExtCarrier::Network(N::Push), 0x47, BodyRule::TsStack),
            (ExtCarrier::Network(N::Response), 0x47, BodyRule::TsStack),
            (ExtCarrier::Network(N::Request), 0x34, BodyRule::QueryTarget),
            (
                ExtCarrier::Network(N::Response),
                0x43,
                BodyRule::EntityGlobalId,
            ),
            (
                ExtCarrier::Declaration(K::UndeclToken),
                0x5F,
                BodyRule::WireExpr,
            ),
            (ExtCarrier::Zenoh(Z::Del), 0x41, BodyRule::SourceInfo),
            (ExtCarrier::Zenoh(Z::Err), 0x41, BodyRule::SourceInfo),
            (ExtCarrier::Zenoh(Z::Query), 0x43, BodyRule::QueryValue),
        ];
        for (carrier, eid, rule) in rows {
            assert_eq!(
                body_rule(carrier, eid),
                Some(rule),
                "{carrier:?}: {eid:#04x}"
            );
        }
        // The same identity on another message is another extension: a Put's attachment is a
        // run of any bytes, and an Interest carries no timestamp stack.
        assert_eq!(body_rule(ExtCarrier::Zenoh(Z::Put), 0x43), None);
        assert_eq!(body_rule(ExtCarrier::Network(N::Interest), 0x47), None);
    }

    /// Each reader that can refuse a body refuses the bodies upstream's refuses, and reads the
    /// ones it reads. Every malformed body is a structurally whole entry, which the chain decode
    /// reads: only its reader can tell.
    #[test]
    fn each_declared_reader_refuses_the_bodies_upstreams_refuses() {
        use DeclarationKind as K;
        use NetworkEnvelope as N;
        use ZenohBody as Z;
        let push = ExtCarrier::Network(N::Push);
        let cases: [(ExtCarrier, Entry, bool); 20] = [
            // A timestamp: a time, a length, an id of that length that is not zero.
            (push, zbuf(0x42, &[0x05, 0x01, 0x01]), true),
            (push, zbuf(0x42, &[0x05, 0x01, 0x00]), false),
            (push, zbuf(0x42, &[0x05, 0x00]), false),
            (push, zbuf(0x42, &[0x05, 0x02, 0x01]), false),
            (
                push,
                zbuf(
                    0x42,
                    &[
                        0x05, 0x11, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                    ],
                ),
                false,
            ),
            // A timestamp stack: flags that are not zero, then its interceptions.
            (push, zbuf(0x47, &[0x01, 0x01, 0x02, 0x01, 0xAA]), true),
            (push, zbuf(0x47, &[0x00, 0x00]), false),
            (push, zbuf(0x47, &[0x01, 0x01, 0x02, 0x02, 0xAA]), false),
            // A Request's target: 0, 1 or 2.
            (ExtCarrier::Network(N::Request), zint(0x34, 2), true),
            (ExtCarrier::Network(N::Request), zint(0x34, 3), false),
            // A responder: a zid that is not zero and a 32-bit entity id.
            (
                ExtCarrier::Network(N::Response),
                zbuf(0x43, &[0x00, 0x01, 0x07]),
                true,
            ),
            (
                ExtCarrier::Network(N::Response),
                zbuf(0x43, &[0x00, 0x00, 0x07]),
                false,
            ),
            (
                ExtCarrier::Network(N::Response),
                zbuf(0x43, &[0x00, 0x01, 0x80, 0x80, 0x80, 0x80, 0x10]),
                false,
            ),
            // An undeclaration's key: a 16-bit scope and a suffix that is UTF-8.
            (
                ExtCarrier::Declaration(K::UndeclSubscriber),
                zbuf(0x5F, &[0x01, 0x00, b'a']),
                true,
            ),
            (
                ExtCarrier::Declaration(K::UndeclSubscriber),
                zbuf(0x5F, &[0x01, 0x00, 0xFF]),
                false,
            ),
            (
                ExtCarrier::Declaration(K::UndeclQueryable),
                zbuf(0x5F, &[0x00, 0x80, 0x80, 0x04]),
                false,
            ),
            // A source info: a zid, an entity id and a sequence number.
            (
                ExtCarrier::Zenoh(Z::Put),
                zbuf(0x41, &[0x00, 0x01, 0x02, 0x03]),
                true,
            ),
            (
                ExtCarrier::Zenoh(Z::Put),
                zbuf(0x41, &[0x00, 0x01, 0x02]),
                false,
            ),
            // A Query's value: an encoding whose schema fits the body, then the payload.
            (ExtCarrier::Zenoh(Z::Query), zbuf(0x43, &[0x00, b'p']), true),
            (
                ExtCarrier::Zenoh(Z::Query),
                zbuf(0x43, &[0x01, 0x05, b'a']),
                false,
            ),
        ];
        for (carrier, entry, reads) in cases {
            let eid = ext_eid(entry.header);
            let want = if reads {
                ExtAdmission::Admissible
            } else {
                ExtAdmission::MalformedExt { eid }
            };
            assert_eq!(
                judge_ext_entries(carrier, [entry]),
                want,
                "{carrier:?}: {eid:#04x}"
            );
        }
    }

    /// Upstream reads every entry of a chain with its reader, the ones a later entry supersedes
    /// included, so a malformed entry the reader of the chain would not keep still refuses the
    /// message; and the first offence in chain order, of the header or of the body, is the one
    /// reported, as upstream's decoder stops at it.
    #[test]
    fn every_entry_is_judged_and_the_first_offence_is_reported() {
        use ZenohBody as Z;
        let del = ExtCarrier::Zenoh(Z::Del);
        let good: &'static [u8] = &[0x00, 0x01, 0x02, 0x03];
        let bad: &'static [u8] = &[0x00, 0x01, 0x02];
        assert_eq!(
            judge_ext_entries(del, [zbuf(0xC1, bad), zbuf(0x41, good)]),
            ExtAdmission::MalformedExt { eid: 0x41 },
            "a superseded entry is read all the same"
        );
        assert_eq!(
            judge_ext_entries(del, [zbuf(0xC1, good), zbuf(0x41, bad)]),
            ExtAdmission::MalformedExt { eid: 0x41 },
            "the last one is read"
        );
        assert_eq!(
            judge_ext_entries(del, [zbuf(0xC1, good), zbuf(0x41, good)]),
            ExtAdmission::Admissible
        );
        assert_eq!(
            judge_ext_entries(del, [unit(0x94), zbuf(0x41, bad)]),
            ExtAdmission::UnknownMandatory { eid: 0x14 }
        );
        assert_eq!(
            judge_ext_entries(del, [zbuf(0xC1, bad), unit(0x14)]),
            ExtAdmission::MalformedExt { eid: 0x41 }
        );
    }

    /// A body is asked of the extension it belongs to and of nothing that looks like it: an
    /// attachment of any bytes, an identity the message does not declare, and an entry whose body
    /// this build holds as something other than the bytes the rule reads.
    #[test]
    fn a_body_is_judged_only_by_its_own_extensions_reader() {
        use NetworkEnvelope as N;
        use ZenohBody as Z;
        // A Del's attachment (`0x42`) is any bytes.
        assert_eq!(
            judge_ext_entries(ExtCarrier::Zenoh(Z::Del), [zbuf(0x42, &[0xFF])]),
            ExtAdmission::Admissible
        );
        // A Push's `0x22` is not its timestamp: unknown, not mandatory, skipped by its header.
        assert_eq!(
            judge_ext_entries(ExtCarrier::Network(N::Push), [zint(0x22, 0)]),
            ExtAdmission::Admissible
        );
        // A Query's value after a shared-memory marker is a list of slices, not bytes.
        assert_eq!(
            judge_ext_entries(ExtCarrier::Zenoh(Z::Query), [unit(0x84), unit(0x43)]),
            ExtAdmission::Admissible
        );
        // A carrier this build cannot name is still unjudged.
        assert_eq!(
            judge_ext_entries(ExtCarrier::Transport(0x1F), [zbuf(0x42, &[])]),
            ExtAdmission::Unjudged
        );
    }

    /// The header rule is the one [`judge_ext_chain`] applies: the entries of a chain are judged
    /// by it before their bodies are read.
    #[test]
    fn the_entries_of_a_chain_are_judged_by_the_header_rule_first() {
        use NetworkEnvelope as N;
        for header in 0u8..=0xFF {
            let carrier = ExtCarrier::Network(N::Push);
            let by_header = judge_ext_chain(carrier, [header]);
            if by_header.is_refusal() {
                assert_eq!(judge_ext_entries(carrier, [unit(header)]), by_header);
            }
        }
    }
}
