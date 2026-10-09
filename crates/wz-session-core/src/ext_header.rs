// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! SSOT for the zenoh `iext` extension-header vocabulary — the spec-frozen
//! encoding-marker bits and the id-field accessor shared by every extension
//! codec (transport-message exts, the node-id ext, the Z_EXT_AUTH inner method
//! chain).
//!
//! These are protocol constants (zenoh
//! `commons/zenoh-protocol/src/common/extension.rs` @ `pub mod iext`),
//! feature-INDEPENDENT, so they live in an UNCONDITIONAL module rather
//! than under a codec gate. Previously the vocabulary lived only in
//! [`crate::ext_nodeid`] (gated on `codec-push` / `-declare` / `-request`),
//! which forced every gated-out consumer (the `session-extauth` auth dispatch +
//! codec) to re-derive `0x20` / `0x40` / `header & 0x0F` locally — three copies
//! of one frozen fact. This module is that single home; `ext_nodeid` re-exports
//! from here for its existing callers' paths.

/// Mandatory flag, zenoh `iext::FLAG_M` (bit 4): a peer that does not understand
/// a mandatory ext must reject the message.
pub const EXT_FLAG_M: u8 = 0x10;

/// `Unit` encoding, zenoh `iext::ENC_UNIT` (bits 5-6 = `0b00`): the ext has no
/// body at all — its PRESENCE is the whole message.
///
/// Zero, so it is never needed to BUILD a header; it exists to be compared
/// against, which is the case [`EXT_ENC_MASK`] serves and which a reader that
/// wrote `header & EXT_ENC_MASK == 0` would state less clearly.
pub const EXT_ENC_UNIT: u8 = 0x00;

/// `Z64` encoding, zenoh `iext::ENC_Z64` (bits 5-6 = `0b01`): the ext body is a
/// `zint`.
pub const EXT_ENC_Z64: u8 = 0x20;

/// `ZBuf` encoding, zenoh `iext::ENC_ZBUF` (bits 5-6 = `0b10`): the ext body is a
/// length-prefixed byte buffer.
pub const EXT_ENC_ZBUF: u8 = 0x40;

/// The two encoding bits, zenoh `iext::ENC_MASK`.
pub const EXT_ENC_MASK: u8 = 0x60;

/// Chain-continuation flag, zenoh `iext::FLAG_Z` (bit 7): another ext entry
/// follows THIS one in the chain.
pub const EXT_FLAG_Z: u8 = 0x80;

/// The extension id field (bits 0-3) of a header byte — zenoh `iext::mid`,
/// dropping the mandatory / encoding / chain flags.
pub const fn ext_id(header: u8) -> u8 {
    header & 0x0F
}

/// The extension IDENTITY — zenoh `iext::eid`, the header with only the
/// chain-continuation flag dropped, so the ENCODING bits and the mandatory bit
/// are PART OF IT (`common/extension.rs`: `pub const fn eid(header: u8) -> u8 {
/// header & !FLAG_Z }`).
///
/// R311y505 — this is the distinction [`ext_id`] above is NOT, and conflating the
/// two is a cross-impl defect this round measured on the wire. zenoh's id field is
/// four bits, so two DIFFERENT extensions may share it and be told apart by their
/// encoding; zenoh does that deliberately (`QoS = zextunit!(0x1, false)` beside
/// `QoSLink = zextz64!(0x1, false)`,
/// `commons/zenoh-protocol/src/transport/init.rs`
/// @ `pub type QoSLink = zextz64!(0x1, false)`, and
/// `init::ext::Shm = zextzbuf!(0x2, false)` beside wz's own UNIT offer at 0x2).
/// Matching a capability by `ext_id` alone therefore accepts a peer's UNRELATED
/// extension as an offer: a real `zenohd --features shared-memory` dialling wz
/// made `is_shm` negotiate TRUE off its `Shm` ZBuf, and wz would then have put SHM
/// descriptors on a wire whose peer had agreed to no such thing.
///
/// Use this for "is capability X offered"; use [`ext_id`] only when you genuinely
/// want the 4-bit id field (a codec reading the id column).
pub const fn ext_eid(header: u8) -> u8 {
    header & !EXT_FLAG_Z
}

/// Is this extension MANDATORY — zenoh `iext::is_mandatory`, the `FLAG_M` bit.
///
/// A separate accessor rather than an open-coded `& EXT_FLAG_M` for the reason
/// [`ext_id`] is one: this bit sits INSIDE the byte a careless reader treats as
/// "the id", and folding it in is a live defect class rather than a
/// hypothetical. The dissection field layer did exactly that — it reported
/// `header & 0x1F` under the name `ext_id`, so every mandatory extension came
/// out 0x10 too high and the one whose entire job is to say "these bytes are
/// not the payload" (`zenoh::put::ext::Shm`, `zextunit!(0x2, true)`) went
/// unrecognised on real traffic.
pub const fn ext_mandatory(header: u8) -> bool {
    (header & EXT_FLAG_M) != 0
}

/// R311y578 — the ESTABLISHMENT (Init / Open) extension id space, as one
/// table.
///
/// The seven ids below were already written down verbatim, as PROSE, in the
/// module docs of `extqos` / `extshm` / `extauth` / `extmultilink` /
/// `extlowlatency` / `extcompression` / `extpatch` ("0x1 QoS, 0x2 Shm, 0x3
/// Auth, 0x4 MultiLink, 0x5 LowLatency, 0x6 Compression, 0x7 Patch"). Each of
/// those modules keeps its OWN named constant + its zenoh citation — the
/// discoverable per-capability SSOT — and now derives its value from here, so
/// the id space is a machine-checkable table rather than seven copies of a
/// sentence.
///
/// The table lives in this UNCONDITIONAL module for a reason a per-capability
/// constant cannot serve: each of those modules is gated on the feature that
/// IMPLEMENTS its capability, and an OBSERVER must read ids whose capability
/// its own build does not implement. A dissector reading a foreign session
/// still has to recognise the `0x5` on the wire to know the flow reframes to a
/// 4-byte prefix, whether or not this build could ever negotiate lowlatency.
///
/// Ids are the 4-bit id FIELD. Match with [`ext_eid`], not with these values
/// alone: the encoding bits are part of an extension's identity (R311y505).
pub mod establishment_ext_id {
    /// `init::ext::QoS` — `zextunit!(0x1, false)`; also the id of the z64
    /// `QoSLink`, which is a DIFFERENT extension sharing the id field.
    pub const QOS: u8 = 0x01;
    /// `init::ext::Shm` — `zextzbuf!(0x2, false)`; wz additionally offers a
    /// UNIT form on the same id.
    pub const SHM: u8 = 0x02;
    /// `init::ext::Auth` — the Z_EXT_AUTH carrier.
    pub const AUTH: u8 = 0x03;
    /// `init::ext::MultiLink`.
    pub const MULTILINK: u8 = 0x04;
    /// `init::ext::LowLatency` / `open::ext::LowLatency` —
    /// `zextunit!(0x5, false)`. Presence on BOTH sides reframes the stream to
    /// a 4-byte LE length prefix once established.
    pub const LOWLATENCY: u8 = 0x05;
    /// `init::ext::Compression` — `zextunit!(0x6, false)`. Presence on both
    /// sides wraps every post-establishment batch body.
    pub const COMPRESSION: u8 = 0x06;
    /// `_Z_MSG_EXT_ID_INIT_PATCH` — the z64 protocol patch LEVEL.
    pub const PATCH: u8 = 0x07;
    /// R2437 — `init::ext::RegionName` — `zextzbuf!(0x8, false)`, a node's
    /// region identity, carried on BOTH InitSyn and InitAck.
    ///
    /// ADDED BY THE PIN. This extension does not exist at zenoh 1.5.0 (the
    /// establishment `ext/` directory there holds auth, compression, lowlatency,
    /// multilink, patch, qos and shm and nothing else); 1.10.0 adds it, which is
    /// how a grade taken at 1.5.0 goes stale by upstream GROWING rather than by
    /// upstream moving.
    ///
    /// wz RECOGNISES it and does not IMPLEMENT it: it is listed here so
    /// `ext_chain::reject_unknown_mandatory_ext` does not read a stock
    /// 1.10.0 peer's announcement as an unknown extension, and so the id cannot
    /// be handed to a future wz extension. Recognising is what upstream does at
    /// the codec layer too — it has a real handler, so this id never reaches its
    /// unknown-extension path. Being non-mandatory, the two treatments cannot
    /// diverge for any peer that follows the spec; the listing is what keeps
    /// that true for one that does not.
    pub const REGION_NAME: u8 = 0x08;
}

/// R2437 — the establishment ext ids wz RECOGNISES, as a derived set rather
/// than a typed list.
///
/// Built from the constants above so a new id cannot be added to the table and
/// forgotten here — the failure that would make
/// `ext_chain::reject_unknown_mandatory_ext` refuse an extension wz
/// itself speaks.
///
/// Recognised may be WIDER than implemented, because the question this set
/// answers is "does wz know what this id means" and not "does wz act on it" —
/// which is what the unknown-extension rule turns on.
///
/// ⚠ R2539 — `REGION_NAME` used to be this note's standing EXAMPLE of the gap
/// ("in this set and wz implements nothing for it"). It is not one any more:
/// [`crate::extregion`] emits it, reads the peer's, and refuses a malformed
/// value. Every id in this set is now implemented; the widening is a property
/// the set is ALLOWED, not one it currently exercises, and a future id may use
/// it again.
pub const ESTABLISHMENT_EXT_IDS: [u8; 8] = [
    establishment_ext_id::QOS,
    establishment_ext_id::SHM,
    establishment_ext_id::AUTH,
    establishment_ext_id::MULTILINK,
    establishment_ext_id::LOWLATENCY,
    establishment_ext_id::COMPRESSION,
    establishment_ext_id::PATCH,
    establishment_ext_id::REGION_NAME,
];

/// Ext ids in the ZENOH-BODY space — the chain that rides a `Put` / `Del` /
/// `Query` / `Reply` / `Err` body, which is a DIFFERENT carrier from
/// [`establishment_ext_id`] above. The two spaces reuse numeric values freely
/// (`0x2` is `Shm` in both, and they are not the same extension), so an id is
/// only meaningful together with the carrier it was read from.
///
/// R311y597 — this module exists for the same reason the establishment table
/// does, and the SHM id is the case that forced it. `extshm` is gated on
/// `transport-shm` and `dissect` on `dissect`; they are INDEPENDENT features,
/// so a dissector that reached into `extshm` for the id would fail to compile
/// in every observer build that does not also implement SHM. An observer must
/// recognise ids whose capability it cannot itself perform — that is the whole
/// asymmetry between reading a wire and speaking it.
pub mod body_ext_id {
    /// `zenoh::put::ext::Shm` — `zextunit!(0x2, true)`, the MANDATORY-bit UNIT
    /// marker meaning the payload slot holds a DESCRIPTOR rather than the
    /// data. The bytes it stands in for never traverse the network.
    pub const SHM: u8 = 0x02;

    /// R311y637 (§1.1w) — `zenoh::query::ext::QueryBody`, the ZBUF ext that
    /// carries a `Query`'s VALUE:
    /// `ValueType<{ ZExtZBuf::<0x03>::id(false) }, 0x04>`
    /// (`zenoh-protocol-1.5.0/src/zenoh/query.rs:104`).
    ///
    /// A `Query`'s payload is not a decoded field of the message the way a
    /// `Put`'s is — it rides here, which is why a reader that only looks at
    /// the message body finds nothing and must not conclude there is nothing.
    ///
    /// ## The id is only meaningful WITH ITS CARRIER, and this is the case
    /// that proves it
    ///
    /// `0x03` in the body space is `QueryBody` on a `Query` and `Attachment`
    /// on a `Put` (`put.rs:78`, and it is
    /// [`ATTACHMENT_EXT_ID_PUSH`](crate::attachment::ATTACHMENT_EXT_ID_PUSH)
    /// here). The same number, two extensions, one space. The module header
    /// above states the rule against the ESTABLISHMENT space; this pair states
    /// it WITHIN the body space, which is the sharper and easier-to-miss form.
    /// Upstream's own numbering per carrier, read rather than remembered:
    /// Put `{sinfo 0x1, shm 0x2, attachment 0x3}`, Del `{sinfo 0x1,
    /// attachment 0x2}`, Query `{sinfo 0x1, body 0x3, attachment 0x5}`.
    pub const QUERY_BODY: u8 = 0x03;

    /// R3045 — the marker that comes before a `Query`'s value when the value is
    /// a list of slices and not a run of bytes: the second parameter of the same
    /// `ValueType<{ ZExtZBuf::<0x03>::id(false) }, 0x04>` that names
    /// [`QUERY_BODY`], a UNIT extension whose header is `0x04` and, with the
    /// value after it, `0x84`. It has no mandatory bit, which a `Put`'s marker
    /// ([`SHM`], `0x02` and mandatory) does, so the two are different
    /// identities and a reader of one must not look for the other.
    pub const QUERY_SHM: u8 = 0x04;

    /// R2825 — the three ATTACHMENT ids, one per carrier, moved here from
    /// `crate::attachment` (which names them from this table). They were gated
    /// on `attachment-bytes`, the feature that lets an application SEND an
    /// attachment; the stats classifier must SIZE one in every build, because
    /// upstream's payload size includes it
    /// (`commons/zenoh-protocol/src/network/push.rs` @ `p.payload.len() + p.ext_attachment.as_ref().map_or(0, |a| a.buffer.len())`).
    /// That is this module's rule — recognising an id is not the capability
    /// it names.
    ///
    /// A `Put` body's attachment: `zextzbuf!(0x3, false)`, the same number as
    /// [`QUERY_BODY`] on another carrier.
    pub const PUT_ATTACHMENT: u8 = 0x03;
    /// A `Del` body's attachment: `0x2`, NOT the Put's `0x3` — the reason is
    /// written on `crate::attachment::ATTACHMENT_EXT_ID_DEL`.
    pub const DEL_ATTACHMENT: u8 = 0x02;
    /// A `Query` body's attachment: `0x5`.
    pub const QUERY_ATTACHMENT: u8 = 0x05;

    /// The source-info extension every data body carries under the same id:
    /// `zextzbuf!(0x1, false)` on `Put`, `Del`, `Query` and `Err`.
    pub const SOURCE_INFO: u8 = 0x01;
}

/// An extension's IDENTITY as upstream composes it: `iext::id(id, mandatory,
/// encoding)` (`commons/zenoh-protocol/src/common/extension.rs` @
/// `pub(super) const fn id(id: u8, mandatory: bool, encoding: u8) -> u8 {`).
///
/// This is the value a reader compares [`ext_eid`] of a received header against,
/// and the header (without the chain flag) a writer emits. Every
/// `zextunit!` / `zextz64!` / `zextzbuf!` declaration upstream is one call of it,
/// so the identity constants below are derived with it rather than typed as a
/// byte, which keeps the three facts (id, mandatory bit, encoding) legible.
pub const fn ext_identity(id: u8, mandatory: bool, encoding: u8) -> u8 {
    let mut identity = (id & 0x0F) | encoding;
    if mandatory {
        identity |= EXT_FLAG_M;
    }
    identity
}

/// The IDENTITIES of the extensions on the data bodies (`Put`, `Del`, `Query`),
/// as [`ext_eid`] of their header reads them.
///
/// R3171 — [`body_ext_id`] holds the 4-bit id FIELD, which is what an extension
/// is BUILT from and not what it is TOLD APART by. Upstream tells a received
/// extension apart by [`ext_eid`] (`commons/zenoh-codec/src/zenoh/put.rs` @
/// `Ok(match iext::eid(ext) {`, and the same match in `del.rs` and `query.rs`),
/// so two extensions that share an id and differ in the mandatory bit or the
/// encoding are DIFFERENT extensions there, and the one that is not declared is
/// an unknown extension. A reader here that compared the id field alone took
/// the look-alike for the declared extension. Compare against these.
pub mod body_eid {
    use super::{ext_identity, EXT_ENC_UNIT, EXT_ENC_ZBUF};

    /// `zextzbuf!(0x1, false)`: `0x41`, on `Put`, `Del`, `Query` and `Err`.
    pub const SOURCE_INFO: u8 = ext_identity(super::body_ext_id::SOURCE_INFO, false, EXT_ENC_ZBUF);
    /// A `Put`'s attachment, `zextzbuf!(0x3, false)`: `0x43`.
    pub const PUT_ATTACHMENT: u8 =
        ext_identity(super::body_ext_id::PUT_ATTACHMENT, false, EXT_ENC_ZBUF);
    /// A `Del`'s attachment, `zextzbuf!(0x2, false)`: `0x42`.
    pub const DEL_ATTACHMENT: u8 =
        ext_identity(super::body_ext_id::DEL_ATTACHMENT, false, EXT_ENC_ZBUF);
    /// A `Query`'s attachment, `zextzbuf!(0x5, false)`: `0x45`.
    pub const QUERY_ATTACHMENT: u8 =
        ext_identity(super::body_ext_id::QUERY_ATTACHMENT, false, EXT_ENC_ZBUF);
    /// A `Query`'s value, `ZExtZBuf::<0x03>::id(false)`: `0x43`.
    pub const QUERY_VALUE: u8 = ext_identity(super::body_ext_id::QUERY_BODY, false, EXT_ENC_ZBUF);
    /// The marker before a `Query`'s sliced value, the raw `0x04` upstream names
    /// as the second parameter of its `ValueType`: a unit extension, not
    /// mandatory.
    pub const QUERY_SHM: u8 = ext_identity(super::body_ext_id::QUERY_SHM, false, EXT_ENC_UNIT);
}

/// The IDENTITIES of the extensions on the NETWORK messages and the transport
/// messages that carry a ZInt priority, for the readers that pick one out of a
/// received chain. See [`body_eid`] for why an identity and not an id.
pub mod network_eid {
    use super::{ext_identity, EXT_ENC_Z64};

    /// The network QoS, `zextz64!(0x1, false)`: `0x21`, on `Push`, `Request`,
    /// `Response`, `Declare`, `Interest` and the network `OAM`
    /// (`commons/zenoh-protocol/src/network/push.rs` @
    /// `pub type QoS = zextz64!(0x1, false);`).
    pub const QOS: u8 = ext_identity(0x1, false, EXT_ENC_Z64);

    /// The transport QoS on `Frame` and `Fragment`, `zextz64!(0x1, true)`:
    /// `0x31`, MANDATORY where the network one is not
    /// (`commons/zenoh-protocol/src/transport/frame.rs` @
    /// `pub type QoS = zextz64!(0x1, true);`).
    pub const TRANSPORT_QOS: u8 = ext_identity(0x1, true, EXT_ENC_Z64);
}

/// Every header that has the 4-bit id of `identity` and is not `identity`: the
/// extensions a reader that compares the id field alone would take for it.
///
/// It is the population of the look-alike rows of the identity tests, so a test
/// names the extension it reads and gets the whole family it must refuse, instead
/// of a hand-picked few, and it is public because those tests live in the crates
/// that read chains (`wz-capture` among them) as well as in this one.
///
/// Encodings 0..=3 (the fourth is reserved but still a header a peer can send)
/// and both values of the mandatory bit, without the chain flag: 7 headers.
pub fn lookalike_headers(identity: u8) -> impl Iterator<Item = u8> {
    let id = ext_id(identity);
    let own = ext_eid(identity);
    (0u8..4)
        .flat_map(move |enc| [0u8, EXT_FLAG_M].map(move |m| id | (enc << 5) | m))
        .filter(move |header| *header != own)
}

#[cfg(test)]
mod identity_tests {
    use super::*;

    /// The identities are the bytes upstream's declarations compose, written here
    /// as literals on purpose: a constant built from `ext_identity` and compared
    /// with the same call would only prove the call agrees with itself.
    /// `scripts/lib/ext_identity_gate.py` binds the same constants to the pinned
    /// source, so the literals and the declarations cannot drift apart unseen.
    #[test]
    fn the_identities_are_the_bytes_upstream_declares() {
        assert_eq!(body_eid::SOURCE_INFO, 0x41);
        assert_eq!(body_eid::PUT_ATTACHMENT, 0x43);
        assert_eq!(body_eid::DEL_ATTACHMENT, 0x42);
        assert_eq!(body_eid::QUERY_ATTACHMENT, 0x45);
        assert_eq!(body_eid::QUERY_VALUE, 0x43);
        assert_eq!(body_eid::QUERY_SHM, 0x04);
        assert_eq!(network_eid::QOS, 0x21);
        assert_eq!(network_eid::TRANSPORT_QOS, 0x31);
    }

    /// The look-alike family of an identity is the other seven headers of its
    /// id, and never the identity itself or anything with another id.
    #[test]
    fn the_lookalike_family_is_the_seven_other_headers_of_the_id() {
        let family: alloc::vec::Vec<u8> = lookalike_headers(0x43).collect();
        assert_eq!(family.len(), 7);
        assert!(!family.contains(&0x43));
        assert!(family.contains(&0x53), "the mandatory ZBuf");
        assert!(family.contains(&0x03), "the unit");
        assert!(family.iter().all(|h| ext_id(*h) == 0x3));
        // The chain flag is no part of an identity: `0xC3` is the identity `0x43`.
        let chained: alloc::vec::Vec<u8> = lookalike_headers(0xC3).collect();
        assert_eq!(family, chained);
    }
}
