// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! SSOT for the zenoh `iext` extension-header vocabulary — the spec-frozen
//! encoding-marker bits and the id-field accessor shared by every extension
//! codec (transport-message exts, the node-id ext, the Z_EXT_AUTH inner method
//! chain).
//!
//! These are protocol constants (zenoh `commons/zenoh-protocol/src/common.rs`
//! `iext`), feature-INDEPENDENT, so they live in an UNCONDITIONAL module rather
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
/// `QoSLink = zextz64!(0x1, false)`, `transport/init.rs:147-148`, and
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
}

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
}
