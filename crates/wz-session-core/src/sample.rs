// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R222 / R225 — application-layer `Sample` type for subscriber callbacks.
//!
//! Mirrors zenoh-pico's `_z_sample_t` (`vendor/zenoh-pico/include/zenoh-pico/
//! net/sample.h` 38-48) — the decoded view of a Push that subscribers
//! actually want to consume. R222 introduced the type with the three
//! load-bearing fields (`keyexpr` / `kind` / `payload`); R225 completes
//! the parity surface by adding the remaining six fields (`timestamp` /
//! `encoding` / `qos` / `attachment` / `source_info` / `reliability`).
//!
//! The struct stays `#[non_exhaustive]` so external crates construct via
//! [`Sample::new_put`] / [`Sample::new_del`] plus optional `with_*`
//! setters. Intra-crate code (`dispatch_push` in `pubsub`) uses the
//! struct-literal form directly, which is unaffected by `non_exhaustive`.
//!
//! Field origin per zenoh-pico baseline:
//!
//! * `timestamp` — body-level T flag inline (zenoh-pico `_Z_FLAG_Z_P_T` /
//!   `_Z_FLAG_Z_D_T`). The codec-side `MsgPut` / `MsgDel` struct already
//!   decodes this; the dispatcher projects through [`TimestampHint`]
//!   (a wz-owned wrap of the codec struct so `Sample` carries
//!   `Clone`/`Debug`/`PartialEq` derives the codec layer omits).
//! * `encoding` — body-level E flag inline on Put only (zenoh-pico
//!   `_Z_FLAG_Z_P_E`). `MsgPut` decodes this; Del has no wire-level
//!   encoding so `Sample::encoding` stays `None` for Del kinds.
//!   Projected through [`EncodingHint`] for the same wrap rationale
//!   as `TimestampHint`.
//! * `qos` — Push outer extension `_Z_MSG_EXT_ENC_ZINT | 0x01` (zenoh-pico
//!   `src/protocol/codec/network.c` 70-93 `_z_push_decode_ext_cb`).
//!   Dispatcher walks `Push.extensions`; the ZInt value is the raw QoS
//!   byte (priority / congestion / express packed; surfaced as
//!   [`QosLevel::raw`]).
//! * `attachment` — body-level extension `_Z_MSG_EXT_ENC_ZBUF | 0x03`
//!   (zenoh-pico `src/protocol/codec/message.c` 314-322
//!   `_z_push_body_decode_extensions`). Dispatcher walks the matching
//!   body's extension chain (`MsgPut.extensions` for Put,
//!   `MsgDel.extensions` for Del).
//! * `source_info` — body-level extension `_Z_MSG_EXT_ENC_ZBUF | 0x01`
//!   (same callback; case 309-313). The ZBuf payload is the serialized
//!   `_z_source_info_t`: a header byte whose high nibble is `(zidlen-1)`
//!   followed by `zidlen` bytes of zid + a VLE-encoded `eid` + a
//!   VLE-encoded `source_sn` (`src/protocol/codec/message.c` 196-231
//!   `_z_source_info_decode`).
//! * `reliability` — transport-layer setting, NOT wire-extracted.
//!   zenoh-pico fills this from the link/transport context when the rx
//!   path calls `_z_trigger_push` (`src/session/push.c` 25-39). wz's
//!   `dispatch_push` does not yet have a transport-context handle, so
//!   R225 fills the zenoh-pico default ([`Reliability::Reliable`]) and
//!   leaves the transport wire-up as an R226+ carry.
//!
//! The dispatcher (`pubsub::SubscriberRegistry::dispatch_push`) calls
//! [`extract_qos`], [`extract_attachment`], and [`extract_source_info`]
//! to project the relevant extension entries into the typed fields.

use alloc::string::String;
use alloc::vec::Vec;

use crate::vle::read_vle_u64;

#[cfg(test)]
use wz_codecs::ext_entry::{ExtEntry, ExtEntryVariant};
use wz_codecs::ext_entry::{ExtEntryOwned, ExtEntryOwnedVariant};

/// Application-level mirror of [`wz_codecs::timestamp::Timestamp`].
///
/// SCE-emitted codec structs intentionally derive only `Default` so the
/// codec layer can stay generation-policy-uniform (`Clone` / `Debug` /
/// `PartialEq` are application surfaces, not codec ones — see
/// `crates/wz-runtime-tokio/src/reply.rs` ~286-305 for the established
/// wz pattern of wrapping codec struct values into wz-owned mirrors).
/// `TimestampHint` is the same shape as the codec `Timestamp` (NTP64
/// time word + Zenoh ID bytes) but wz-owned, so it carries the
/// `Clone`/`Debug`/`PartialEq` derives a `Sample` field reasonably
/// needs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct TimestampHint {
    /// NTP64 time word. zenoh-pico mirror: `_z_timestamp_t._time`.
    pub time: u64,
    /// Zenoh ID prefix bytes (variable length per the wire `zid_len`
    /// VLE; the codec stores exactly the on-wire byte count, no
    /// 16-byte right-pad). zenoh-pico mirror: `_z_timestamp_t._id`.
    pub zid: Vec<u8>,
}

impl TimestampHint {
    /// Project a decoded codec [`wz_codecs::timestamp::Timestamp`]
    /// into a wz-owned [`TimestampHint`].
    pub fn from_codec(ts: &wz_codecs::timestamp::TimestampOwned) -> Self {
        Self {
            time: ts.time,
            // SCE pin 7a94d084a (W3) stores the codec owned mirror as a
            // no-alloc bounded `heapless::Vec<u8, 16>`; this AP-side hint
            // retains an alloc `Vec<u8>` (Decision 2: AP retention is
            // alloc), so copy out of the bounded buffer at the boundary.
            zid: ts.zid.as_slice().to_vec(),
        }
    }

    /// R233 — inverse of [`from_codec`]: produce a fresh codec
    /// [`wz_codecs::timestamp::Timestamp`] from a wz-side hint so
    /// the publish wire branch can attach a caller-set timestamp to
    /// an outbound `MsgPut`/`MsgDel`. Mirrors the same byte-level
    /// shape (NTP64 `time` word + variable-length `zid` prefix).
    pub fn to_codec(&self) -> wz_codecs::timestamp::Timestamp<'_> {
        wz_codecs::timestamp::Timestamp {
            time: self.time,
            zid_len: self.zid.len() as u64,
            zid: &self.zid,
        }
    }
}

/// The uhlc-faithful ordering key for a timestamp: `(time, zid-as-16-byte
/// little-endian array)`. The SSOT every `alloc` consumer compares on —
/// the storage newer-wins gate ([`timestamp_strictly_newer`]), the storage
/// version-list sort ([`crate::storage_history`]), and (R311y73+) the
/// ext-pubsub advanced-subscriber timestamped-dedup path — so one place
/// encodes uhlc's `Timestamp` `Ord` contract. R311y73 lifted it here next
/// to its subject [`TimestampHint`] out of the `storage-backend`-gated
/// `storage_state` (the `crate::zid_hex` precedent: a shared recipe must
/// not be trapped behind one consumer's feature gate).
///
/// uhlc's `Timestamp` derives `Ord` over `(time: NTP64, id: ID)`
/// (`uhlc-0.8.1/src/timestamp.rs:33-38`), and `ID` is a `[u8; 16]`
/// (`#[repr(transparent)]`, `id.rs:56-59`) holding the id's FULL
/// little-endian bytes, zero-padded — so uhlc compares the whole 16-byte
/// array. wz's wire/[`TimestampHint`] `zid` is the same LE bytes but
/// length-TRIMMED (zenoh-pico `_z_id_len` drops trailing zero high bytes).
/// Comparing the trimmed `Vec`s lexicographically diverges from uhlc for a
/// non-canonically-encoded zid (a peer's, or a carelessly chosen
/// `local_zid`): the dropped high bytes are NOT guaranteed zero in general,
/// so a shorter zid is not always uhlc-less-than a longer one. Zero-padding
/// both to the full 16-byte array before comparison reproduces uhlc's
/// answer exactly (the trimmed bytes are the LE prefix; the pad supplies
/// the zero high bytes uhlc compares against). A zid longer than 16 (a
/// malformed input) is truncated to 16 — uhlc ids are exactly 16 bytes.
pub(crate) fn timestamp_order_key(ts: &TimestampHint) -> (u64, [u8; 16]) {
    (ts.time, crate::zid_hex::zid_to_le_array(&ts.zid))
}

/// Whether timestamp `a` is *strictly newer* than `b`, by the uhlc
/// `Timestamp` `Ord` semantic — `(time, 16-byte LE id)` lexicographic (see
/// [`timestamp_order_key`]). The single comparison the storage newer-wins
/// gate keys off.
pub fn timestamp_strictly_newer(a: &TimestampHint, b: &TimestampHint) -> bool {
    timestamp_order_key(a) > timestamp_order_key(b)
}

/// Application-level mirror of [`wz_codecs::encoding::Encoding`].
///
/// Same `Clone`-vs-codec rationale as [`TimestampHint`]. The wz wrapper
/// preserves the zenoh-pico `_z_encoding_t` semantic decomposition: a
/// VLE-packed id word whose low bit gates an optional UTF-8 schema
/// string.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct EncodingHint {
    /// VLE-encoded id word. The low bit (`packed_id & 0x1`) signals
    /// whether a schema string follows on the wire. zenoh-pico mirror:
    /// `_z_encoding_t._id` (packed shape per RFC §5.B `encoding`
    /// codec).
    pub packed_id: u32,
    /// Optional UTF-8 schema string. Present iff the codec decoded a
    /// non-empty schema (i.e. `packed_id & 0x1 == 1` and the inline
    /// `<u8;z16>` block parsed).
    pub schema: Option<String>,
}

impl EncodingHint {
    /// Project a decoded codec [`wz_codecs::encoding::Encoding`] into
    /// a wz-owned [`EncodingHint`].
    pub fn from_codec(encoding: &wz_codecs::encoding::EncodingOwned) -> Self {
        Self {
            packed_id: encoding.packed_id,
            // W3 (SCE 7a94d084a): the codec owned mirror's schema is a
            // bounded `heapless::String<128>`; copy it into this AP hint's
            // alloc `Option<String>` at the projection boundary.
            schema: encoding.schema.as_ref().map(|s| String::from(s.as_str())),
        }
    }

    /// R233 — inverse of [`from_codec`]: produce a fresh codec
    /// [`wz_codecs::encoding::Encoding`] from a wz-side hint so the
    /// publish wire branch can attach a caller-set encoding to an
    /// outbound `MsgPut`. The codec `Encoding` decides whether to
    /// emit a schema string based on `packed_id & 0x1` and a
    /// non-empty `schema`; the hint preserves both fields verbatim.
    pub fn to_codec(&self) -> wz_codecs::encoding::Encoding<'_> {
        let schema_len = self.schema.as_ref().map(|s| s.len() as u64);
        wz_codecs::encoding::Encoding {
            packed_id: self.packed_id,
            schema_len,
            schema: self.schema.as_deref(),
        }
    }
}

// R311gb-2 — `SampleKind` hoisted to the unconditional `crate::sample_kind`
// module so the no-alloc `sink::SampleView` accessor contract can name it on
// every profile. Re-exported here so existing `crate::sample::SampleKind`
// paths (and this module's `Sample` field type) are unaffected.
pub use crate::sample_kind::SampleKind;

/// QoS metadata extracted from the Push outer extension chain.
///
/// zenoh-pico mirror: `_z_qos_t { uint8_t _val; }`
/// (`vendor/zenoh-pico/include/zenoh-pico/protocol/core.h` 193-195) — a
/// single byte carrying priority (3-bit) + congestion control (1-bit) +
/// express (1-bit) packed alongside reserved bits. The raw byte is
/// preserved so future helpers can surface individual bit fields without
/// the dispatcher committing to a particular decomposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct QosLevel {
    /// Raw QoS byte (zenoh-pico `_z_qos_t._val`).
    pub raw: u8,
}

impl QosLevel {
    /// Construct from the raw QoS byte (typically `(ExtZint.value as u8)`
    /// after the dispatcher has located the matching `ExtEntry`).
    pub fn from_raw(raw: u8) -> Self {
        Self { raw }
    }

    /// Express flag (zenoh-pico `_Z_N_QOS_IS_EXPRESS_FLAG = 1 << 4`,
    /// `vendor/zenoh-pico/include/zenoh-pico/protocol/definitions/network.h`
    /// 82).
    pub fn is_express(&self) -> bool {
        (self.raw & (1 << 4)) != 0
    }

    /// R311y226 — pack a typed `(priority, congestion, express)` triple
    /// into the single QoS byte. The SOLE packer for the
    /// `_z_n_qos_create` bit layout
    /// (`vendor/zenoh-pico/include/zenoh-pico/protocol/definitions/network.h`
    /// 84-89): `priority` in the low 3 bits, `nodrop`
    /// (`congestion == Block`) at bit 3, `express` at bit 4. zenoh
    /// `QoSType::new` packs the identical layout
    /// (`commons/zenoh-protocol/src/network/mod.rs`).
    /// [`crate::request_build::RequestQueryBuilder::request_qos_typed`]
    /// delegates here so the layout lives once (no drift between the
    /// Push-side and Request-side QoS setters).
    pub const fn from_parts(
        priority: crate::qos::Priority,
        congestion: crate::qos::CongestionControl,
        express: bool,
    ) -> Self {
        Self {
            raw: priority.wire_byte() | (congestion.wire_bit() << 3) | ((express as u8) << 4),
        }
    }

    /// R311y226 — the wire-DEFAULT QoS byte: priority `Data` (5),
    /// `Drop` congestion, no express, so `raw == 0x05`
    /// (`_Z_N_QOS_DEFAULT._val = 5`,
    /// `vendor/zenoh-pico/src/protocol/definitions/network.c` 22). The
    /// named sentinel the Push outer-ext encoder suppresses against
    /// (`build_push_outer_extensions`) — NOT the derived
    /// [`QosLevel::default`] (`raw 0` = `Control`), which would mis-gate
    /// a genuine DEFAULT publish.
    pub const DEFAULT: QosLevel = Self::from_parts(
        crate::qos::Priority::DEFAULT,
        crate::qos::CongestionControl::Drop,
        false,
    );

    /// R311y226 — decode the priority sub-field (low 3 bits) into the
    /// typed [`crate::qos::Priority`]. The unpack twin of
    /// [`Self::from_parts`]; mirrors zenoh-pico `_z_n_qos_get_priority`
    /// (`network.h` 90-92) which masks `& 0x07` with NO Control guard,
    /// so a `Control` (0) band surfaces as-is (pico-faithful; zenoh-Rust
    /// instead collapses `Control` to `Data` at its app-`Priority`
    /// boundary — a NAMED divergence, wz mirrors pico here).
    pub const fn priority(&self) -> crate::qos::Priority {
        crate::qos::Priority::from_wire(self.raw & 0x07)
    }
}

/// Source identification for a Sample.
///
/// zenoh-pico mirror:
/// `_z_source_info_t { _z_entity_global_id_t _source_id; uint32_t _source_sn; }`
/// where `_z_entity_global_id_t = { _z_id_t zid; uint32_t eid; }` and
/// `_z_id_t` is a 16-byte Zenoh identifier (right-zero-padded when the
/// effective length is shorter; the wire transmits only the prefix).
///
/// R231 — `zid_len` carries the effective prefix length (1..=16) so the
/// wire-form `(zidlen - 1)` header nibble round-trips and self-echo
/// dedup can compare against an arbitrary-length `own_zid` without
/// ambiguity (a 4-byte own_zid coincidentally matching the first 4
/// bytes of an 8-byte peer zid would otherwise false-positive). The
/// `Default` impl produces `zid_len = 0` as a sentinel for "no source
/// info" — any value outside `1..=16` should be treated by consumers
/// as an absence-of-source, not a 0-byte zid.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub struct SourceInfo {
    /// Source Zenoh ID, right-zero-padded to 16 bytes. zenoh-pico
    /// mirror: `_z_id_t.id[16]`. Only the first `zid_len` bytes are
    /// semantically meaningful.
    pub zid: [u8; 16],
    /// Effective length of `zid` in bytes (1..=16 for a valid record;
    /// 0 marks the `Default::default()` sentinel). Mirrors the wire
    /// header's `(zidlen - 1)` high nibble via `zid_len = nibble + 1`.
    pub zid_len: u8,
    /// Source entity ID. zenoh-pico mirror: `_z_entity_global_id_t.eid`.
    pub eid: u32,
    /// Source sequence number. zenoh-pico mirror:
    /// `_z_source_info_t._source_sn`.
    pub sn: u32,
}

impl SourceInfo {
    /// Construct a `SourceInfo` from a variable-length zid prefix plus
    /// the entity id + sequence number. Right-zero-pads the zid into
    /// the fixed 16-byte buffer and records the effective length.
    ///
    /// Panics if `zid_bytes.len()` is outside `1..=16` (the zenoh-pico
    /// `_Z_ID_LENGTH = 16` wire constraint matches the high-nibble
    /// `(zidlen - 1)` encoding range).
    pub fn new(zid_bytes: &[u8], eid: u32, sn: u32) -> Self {
        assert!(
            (1..=16).contains(&zid_bytes.len()),
            "SourceInfo::new requires zid length 1..=16 \
             (zenoh-pico _Z_ID_LENGTH wire constraint)"
        );
        let mut zid = [0u8; 16];
        zid[..zid_bytes.len()].copy_from_slice(zid_bytes);
        Self {
            zid,
            zid_len: zid_bytes.len() as u8,
            eid,
            sn,
        }
    }

    /// Borrow the meaningful zid prefix (the first `zid_len` bytes of
    /// the padded buffer). Returns an empty slice when `zid_len` is
    /// outside the valid `1..=16` range (i.e. the `Default::default()`
    /// sentinel or an invalid record) so callers performing equality
    /// checks against an `own_zid` slice cannot accidentally match the
    /// all-zero default.
    pub fn zid_prefix(&self) -> &[u8] {
        let len = self.zid_len as usize;
        if (1..=16).contains(&len) {
            &self.zid[..len]
        } else {
            &[]
        }
    }
}

// R226 — Reliability was hoisted to the crate root so the outbound
// driver hint (session_glue::send_*) and the inbound Sample
// classification share a single typed surface. Re-export keeps the
// sample-module path stable for callers that already imported through
// here.
pub use crate::reliability::Reliability;

/// Application-layer view of a single inbound Push record.
///
/// Constructed by [`crate::pubsub::SubscriberRegistry::dispatch_push`]
/// from the decoded `Push` + the registry's peer keyexpr table + the
/// matching body's extension chain. Handed to user-registered callbacks
/// by reference.
///
/// The struct is `#[non_exhaustive]` — future rounds can refine the
/// surface without breaking external callers that read existing fields
/// (R311y226 added [`Sample::priority`], a typed [`crate::qos::Priority`]
/// derived from the `QosLevel` qos ext). External construction is via
/// [`Sample::new_put`] / [`Sample::new_del`] plus optional `with_*`
/// setters; intra-crate `dispatch_push` builds the full literal.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Sample {
    /// Resolved keyexpr literal. The peer DECLARE table lookup +
    /// optional suffix concatenation has already been applied by the
    /// dispatcher, so callers see the same string a peer's
    /// `Declare(DeclKexpr)` carries on the wire.
    pub keyexpr: String,
    /// Whether this sample is data ([`SampleKind::Put`]) or a key
    /// deletion ([`SampleKind::Del`]).
    pub kind: SampleKind,
    /// Payload bytes for Put samples; empty `Vec<u8>` for Del.
    pub payload: Vec<u8>,
    /// Body-level timestamp (zenoh-pico `_z_m_push_commons_t._timestamp`,
    /// gated by `_Z_FLAG_Z_P_T` for Put / `_Z_FLAG_Z_D_T` for Del).
    /// `None` when the wire bit was clear. The hint mirrors the codec
    /// timestamp shape with wz-owned `Clone`/`Debug`/`PartialEq`
    /// derives — see [`TimestampHint`] for the wrap rationale.
    pub timestamp: Option<TimestampHint>,
    /// Body-level encoding (zenoh-pico `_z_msg_put_t._encoding`, gated
    /// by `_Z_FLAG_Z_P_E`). `None` on the wire-clear case and on every
    /// Del sample (Del bodies do not carry encoding). The hint mirrors
    /// the codec encoding shape with wz-owned derives — see
    /// [`EncodingHint`] for the wrap rationale.
    pub encoding: Option<EncodingHint>,
    /// QoS extracted from the Push outer extension chain (zenoh-pico
    /// `_Z_MSG_EXT_ENC_ZINT | 0x01`). `None` when no matching extension
    /// was present.
    pub qos: Option<QosLevel>,
    /// Body-level attachment blob (zenoh-pico
    /// `_Z_MSG_EXT_ENC_ZBUF | 0x03` extension). `None` when no matching
    /// extension was present.
    pub attachment: Option<Vec<u8>>,
    /// Body-level source identification (zenoh-pico
    /// `_Z_MSG_EXT_ENC_ZBUF | 0x01` extension). `None` when no matching
    /// extension was present or the ZBuf payload failed source-info
    /// parsing (truncated header / VLE overflow).
    pub source_info: Option<SourceInfo>,
    /// Reliability classification from the link/transport layer.
    /// Defaults to [`Reliability::Reliable`] (zenoh-pico
    /// `Z_RELIABILITY_DEFAULT`); transport-context wire-up is an
    /// R226+ follow-up.
    pub reliability: Reliability,
}

// R311gb-2 — `Sample` is the AP (`alloc`) projection of the
// `sink::SampleView` delivery contract. The subscriber registry dispatches
// an owned `Sample` to a `SampleSink` as `&self as &dyn SampleView`, so the
// borrowed-accessor reads cost nothing (no copy, no third sample type).
impl crate::sink::SampleView for Sample {
    fn keyexpr(&self) -> &str {
        &self.keyexpr
    }
    fn payload(&self) -> &[u8] {
        &self.payload
    }
    fn kind(&self) -> SampleKind {
        self.kind
    }
    fn reliability(&self) -> Reliability {
        self.reliability
    }
    // R311gb-2b — AP keeps full-fidelity field access through the seam:
    // override every `alloc`-gated rich accessor so a subscriber reading
    // `&dyn SampleView` sees the same QoS / attachment / timestamp /
    // encoding / source-info the owned `Sample` projection carries.
    fn qos(&self) -> Option<QosLevel> {
        self.qos
    }
    fn attachment(&self) -> Option<&[u8]> {
        self.attachment.as_deref()
    }
    fn timestamp(&self) -> Option<&TimestampHint> {
        self.timestamp.as_ref()
    }
    fn encoding(&self) -> Option<&EncodingHint> {
        self.encoding.as_ref()
    }
    fn source_info(&self) -> Option<&SourceInfo> {
        self.source_info.as_ref()
    }
}

impl Sample {
    /// R311gb-2b — materialize a borrowed [`SampleView`](crate::sink::SampleView)
    /// into an owned retention `Sample` (the AP retention form). Copies
    /// every field the view exposes; a view carrying no rich metadata
    /// (the loose-bytes / loopback [`BorrowedSample`](crate::sink::BorrowedSample))
    /// yields `None` for the optional fields via the trait's default
    /// accessors. The inverse of dispatching `&Sample as &dyn SampleView`:
    /// use it when a subscriber must own the sample past the delivery
    /// call (buffering, deferred processing) rather than read-and-drop.
    pub fn from_view(view: &dyn crate::sink::SampleView) -> Self {
        let mut sample = match view.kind() {
            SampleKind::Put => Self::new_put(view.keyexpr(), view.payload().to_vec()),
            SampleKind::Del => Self::new_del(view.keyexpr()),
        };
        sample.reliability = view.reliability();
        sample.timestamp = view.timestamp().cloned();
        sample.encoding = view.encoding().cloned();
        sample.qos = view.qos();
        sample.attachment = view.attachment().map(<[u8]>::to_vec);
        sample.source_info = view.source_info().cloned();
        sample
    }

    /// Construct a `Sample` carrying Put-kind data with default
    /// (`None` / `Reliable`) metadata fields. Chain `with_*` setters to
    /// attach decoded extension values.
    pub fn new_put(keyexpr: impl Into<String>, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            keyexpr: keyexpr.into(),
            kind: SampleKind::Put,
            payload: payload.into(),
            timestamp: None,
            encoding: None,
            qos: None,
            attachment: None,
            source_info: None,
            reliability: Reliability::default(),
        }
    }

    /// Construct a `Sample` carrying Del-kind notification. Payload
    /// is always empty for Del; metadata fields default to `None` /
    /// `Reliable`.
    pub fn new_del(keyexpr: impl Into<String>) -> Self {
        Self {
            keyexpr: keyexpr.into(),
            kind: SampleKind::Del,
            payload: Vec::new(),
            timestamp: None,
            encoding: None,
            qos: None,
            attachment: None,
            source_info: None,
            reliability: Reliability::default(),
        }
    }

    /// Attach a body-level timestamp.
    pub fn with_timestamp(mut self, ts: TimestampHint) -> Self {
        self.timestamp = Some(ts);
        self
    }

    /// Attach a body-level encoding. Semantically valid for Put only;
    /// Del callers may still call this but the wire decoder never
    /// produces a Del with encoding (and the parity contract reflects
    /// that — Del-with-encoding is a wire-shape that the protocol does
    /// not define).
    pub fn with_encoding(mut self, encoding: EncodingHint) -> Self {
        self.encoding = Some(encoding);
        self
    }

    /// Attach an outer-level QoS value.
    pub fn with_qos(mut self, qos: QosLevel) -> Self {
        self.qos = Some(qos);
        self
    }

    /// Attach a body-level attachment blob.
    pub fn with_attachment(mut self, attachment: impl Into<Vec<u8>>) -> Self {
        self.attachment = Some(attachment.into());
        self
    }

    /// Attach a body-level source identification.
    pub fn with_source_info(mut self, source_info: SourceInfo) -> Self {
        self.source_info = Some(source_info);
        self
    }

    /// Set the reliability classification. Most callers leave the
    /// `Reliable` default; the setter exists so transport-context
    /// wire-up (R226+) can attach the link-layer value at dispatch
    /// time.
    pub fn with_reliability(mut self, reliability: Reliability) -> Self {
        self.reliability = reliability;
        self
    }

    /// R311y226 — the transport priority the publisher stamped on this
    /// sample, decoded from the Push outer QoS ext ([`QosLevel`]). The
    /// app-observable priority, mirroring zenoh `Sample::priority()`
    /// (`zenoh/src/api/sample.rs`) and zenoh-pico `z_sample_priority`
    /// (`src/api/api.c` 1261) — both read the PER-MESSAGE Push qos, NOT
    /// the transport frame conduit band. `Priority::DEFAULT` (`Data`)
    /// when the sample carries no QoS ext: a plain publish (the encoder
    /// suppresses the DEFAULT byte), or an `off`-subset build where the
    /// ext is neither emitted nor decoded. Always present on `Sample`
    /// (not `pubsub-*`-gated; `crate::qos::Priority` is no_std / always
    /// compiled), matching [`Self::reliability`]'s unconditional access.
    pub fn priority(&self) -> crate::qos::Priority {
        self.qos
            .map_or(crate::qos::Priority::DEFAULT, |q| q.priority())
    }
}

/// Walk an ExtEntry chain and project the first QoS ext into a
/// [`QosLevel`]. The matching predicate mirrors zenoh-pico's
/// `_Z_EXT_FULL_ID(extension->_header)` switch in
/// `_z_push_decode_ext_cb` (`vendor/zenoh-pico/src/protocol/codec/
/// network.c` 70-93): `ext_id == 0x01` AND `enc == ENC_ZINT (0b01)`.
///
/// Returns `None` when no extension in the chain has the matching
/// `(ext_id, enc)` combination, or when the matching extension's body
/// variant is unexpectedly not `ExtZint` (which the wire decoder
/// would only produce if the upstream catalog drifted).
pub fn extract_qos(extensions: &[ExtEntryOwned]) -> Option<QosLevel> {
    const QOS_EXT_ID: u8 = 0x01;
    const ENC_ZINT: u8 = 0x01;
    for ext in extensions {
        if ext.ext_id() == QOS_EXT_ID && ext.enc() == ENC_ZINT {
            if let ExtEntryOwnedVariant::CodecZenohExtZint(z) = &ext.body {
                return Some(QosLevel::from_raw(z.value as u8));
            }
        }
    }
    None
}

// The attachment ext-chain predicate moved to the `crate::attachment`
// SSOT module (`decode_attachment_ext`) so the Push (this module) and
// Query (`crate::query`) decode paths share one wire predicate. The Push
// dispatch in `crate::pubsub` calls `decode_attachment_ext(.., PUSH)`.

/// Walk an ExtEntry chain and project the first source-info ext into a
/// [`SourceInfo`]. Predicate mirrors zenoh-pico's
/// `_z_push_body_decode_extensions` case at line 309-313: `ext_id ==
/// 0x01` AND `enc == ENC_ZBUF (0b10)`. The ZBuf payload is then parsed
/// per `_z_source_info_decode` (`vendor/zenoh-pico/src/protocol/codec/
/// message.c` 196-231):
///
/// 1. 1 byte header — high nibble carries `(zidlen - 1)`; low nibble
///    reserved.
/// 2. `zidlen` bytes of zid (right-padded into the 16-byte buffer).
/// 3. VLE-encoded `eid` (rejected when overflow to u32).
/// 4. VLE-encoded `sn` (rejected when overflow to u32).
///
/// Returns `None` on missing extension, on a non-`ExtZbuf` body
/// variant for the matching tuple, or on any parse failure (truncation
/// / overflow / impossible `zidlen`).
pub fn extract_source_info(extensions: &[ExtEntryOwned]) -> Option<SourceInfo> {
    const SOURCE_INFO_EXT_ID: u8 = 0x01;
    const ENC_ZBUF: u8 = 0x02;
    for ext in extensions {
        if ext.ext_id() == SOURCE_INFO_EXT_ID && ext.enc() == ENC_ZBUF {
            if let ExtEntryOwnedVariant::CodecZenohExtZbuf(z) = &ext.body {
                return decode_source_info_payload(&z.value);
            }
        }
    }
    None
}

/// Decode the ZBuf payload of a source-info extension into a typed
/// [`SourceInfo`]. Exposed `pub(crate)` so the dispatcher can call it
/// directly when it already holds the slice; external callers route
/// through [`extract_source_info`].
fn decode_source_info_payload(bytes: &[u8]) -> Option<SourceInfo> {
    if bytes.is_empty() {
        return None;
    }
    let header = bytes[0];
    let zidlen = ((header >> 4) as usize) + 1;
    // zidlen ranges 1..=16 because the header's high nibble is 4 bits.
    if zidlen > 16 || bytes.len() < 1 + zidlen {
        return None;
    }
    let mut zid = [0u8; 16];
    zid[..zidlen].copy_from_slice(&bytes[1..1 + zidlen]);
    let rest = &bytes[1 + zidlen..];
    let (eid_val, eid_consumed) = read_vle_u64(rest)?;
    if eid_val > u32::MAX as u64 {
        return None;
    }
    let (sn_val, _) = read_vle_u64(rest.get(eid_consumed..)?)?;
    if sn_val > u32::MAX as u64 {
        return None;
    }
    Some(SourceInfo {
        zid,
        zid_len: zidlen as u8,
        eid: eid_val as u32,
        sn: sn_val as u32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn sample_kind_numeric_repr_matches_zenoh_pico() {
        // zenoh-pico constants.h:
        //   Z_SAMPLE_KIND_PUT = 0
        //   Z_SAMPLE_KIND_DELETE = 1
        assert_eq!(SampleKind::Put as u8, 0);
        assert_eq!(SampleKind::Del as u8, 1);
    }

    #[test]
    fn new_put_carries_keyexpr_and_payload_and_defaults() {
        let sample = Sample::new_put("home/temp", b"23.5".to_vec());
        assert_eq!(sample.keyexpr, "home/temp");
        assert_eq!(sample.kind, SampleKind::Put);
        assert_eq!(sample.payload, b"23.5");
        assert!(sample.timestamp.is_none());
        assert!(sample.encoding.is_none());
        assert!(sample.qos.is_none());
        assert!(sample.attachment.is_none());
        assert!(sample.source_info.is_none());
        assert_eq!(sample.reliability, Reliability::Reliable);
    }

    #[test]
    fn new_del_carries_empty_payload_and_defaults() {
        let sample = Sample::new_del("home/temp");
        assert_eq!(sample.keyexpr, "home/temp");
        assert_eq!(sample.kind, SampleKind::Del);
        assert!(sample.payload.is_empty());
        assert!(sample.timestamp.is_none());
        assert!(sample.encoding.is_none());
        assert!(sample.qos.is_none());
        assert!(sample.attachment.is_none());
        assert!(sample.source_info.is_none());
        assert_eq!(sample.reliability, Reliability::Reliable);
    }

    #[test]
    fn reliability_default_matches_zenoh_pico() {
        // zenoh-pico Z_RELIABILITY_DEFAULT = Z_RELIABILITY_RELIABLE.
        assert_eq!(Reliability::default(), Reliability::Reliable);
        assert_eq!(Reliability::Reliable as u8, 1);
        assert_eq!(Reliability::BestEffort as u8, 0);
    }

    #[test]
    fn with_setters_chain_through_metadata_fields() {
        let sample = Sample::new_put("topic/a", b"data".to_vec())
            .with_timestamp(TimestampHint {
                time: 0x1234_5678_9ABC_DEF0,
                zid: vec![0x11, 0x22, 0x33],
            })
            .with_encoding(EncodingHint {
                packed_id: 5,
                schema: Some("application/json".into()),
            })
            .with_qos(QosLevel::from_raw(0b0001_1010))
            .with_attachment(b"meta".to_vec())
            .with_source_info(SourceInfo::new(&[1u8; 16], 7, 42))
            .with_reliability(Reliability::BestEffort);
        let ts = sample.timestamp.unwrap();
        assert_eq!(ts.time, 0x1234_5678_9ABC_DEF0);
        assert_eq!(ts.zid, vec![0x11, 0x22, 0x33]);
        let enc = sample.encoding.unwrap();
        assert_eq!(enc.packed_id, 5);
        assert_eq!(enc.schema.as_deref(), Some("application/json"));
        assert_eq!(sample.qos.unwrap().raw, 0b0001_1010);
        assert_eq!(sample.attachment.unwrap(), b"meta");
        let si = sample.source_info.unwrap();
        assert_eq!(si.zid, [1u8; 16]);
        assert_eq!(si.zid_len, 16);
        assert_eq!(si.zid_prefix(), &[1u8; 16][..]);
        assert_eq!(si.eid, 7);
        assert_eq!(si.sn, 42);
        assert_eq!(sample.reliability, Reliability::BestEffort);
    }

    #[test]
    fn source_info_new_pads_zid_and_records_length() {
        // R231 — variable-length zid (1..=16) is right-zero-padded
        // into the fixed [u8; 16] buffer; zid_len carries the
        // effective prefix length so dedup comparisons stay
        // unambiguous (4-byte own_zid vs 8-byte peer that happens to
        // share the first 4 bytes must NOT match).
        let info = SourceInfo::new(&[0xAA, 0xBB, 0xCC, 0xDD], 7, 42);
        assert_eq!(info.zid_len, 4);
        assert_eq!(info.zid_prefix(), &[0xAA, 0xBB, 0xCC, 0xDD][..]);
        // Padding bytes are zero past the effective length.
        assert!(info.zid[4..].iter().all(|&b| b == 0));
        assert_eq!(info.eid, 7);
        assert_eq!(info.sn, 42);
    }

    #[test]
    fn source_info_zid_prefix_returns_empty_for_default_sentinel() {
        // R231 — the derived Default has zid_len = 0 which is outside
        // the valid 1..=16 range. zid_prefix() must return an empty
        // slice for the sentinel so equality checks against any
        // non-empty own_zid cannot accidentally match the zero default.
        let info = SourceInfo::default();
        assert_eq!(info.zid_len, 0);
        assert!(info.zid_prefix().is_empty());
    }

    #[test]
    fn source_info_zid_prefix_returns_empty_when_len_out_of_range() {
        // R231 — defensive: a malformed record (zid_len > 16) must
        // not panic-index into the buffer. zid_prefix() filters it
        // out by returning empty.
        let info = SourceInfo {
            zid: [0xFFu8; 16],
            zid_len: 99,
            eid: 0,
            sn: 0,
        };
        assert!(info.zid_prefix().is_empty());
    }

    #[test]
    #[should_panic(expected = "SourceInfo::new requires zid length 1..=16")]
    fn source_info_new_panics_on_zero_length_zid() {
        let _ = SourceInfo::new(&[], 0, 0);
    }

    #[test]
    #[should_panic(expected = "SourceInfo::new requires zid length 1..=16")]
    fn source_info_new_panics_on_17_byte_zid() {
        let _ = SourceInfo::new(&[0u8; 17], 0, 0);
    }

    #[test]
    fn source_info_decode_round_trips_zid_len_through_wire_form() {
        // R231 — the decode path now records zid_len from the wire
        // header's `(zidlen - 1)` high nibble. A 3-byte zid encodes
        // as header `(3-1) << 4 = 0x20`, followed by 3 zid bytes,
        // then VLE eid + sn.
        let mut bytes = vec![0x20]; // (3-1) << 4 = 0x20, low nibble 0
        bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE]);
        bytes.push(0x05); // VLE eid = 5
        bytes.push(0x07); // VLE sn = 7
        let info = decode_source_info_payload(&bytes).expect("decode");
        assert_eq!(info.zid_len, 3);
        assert_eq!(info.zid_prefix(), &[0xDE, 0xAD, 0xBE][..]);
        // Padding past zid_len is zero.
        assert!(info.zid[3..].iter().all(|&b| b == 0));
        assert_eq!(info.eid, 5);
        assert_eq!(info.sn, 7);
    }

    #[test]
    fn timestamp_hint_from_codec_round_trips_fields() {
        let codec = wz_codecs::timestamp::TimestampOwned {
            time: 0xDEAD_BEEF,
            zid_len: 4,
            zid: crate::codec_owned::owned_bytes(&[1, 2, 3, 4]).unwrap(),
        };
        let hint = TimestampHint::from_codec(&codec);
        assert_eq!(hint.time, 0xDEAD_BEEF);
        assert_eq!(hint.zid, vec![1, 2, 3, 4]);
    }

    #[test]
    fn encoding_hint_from_codec_round_trips_fields() {
        let codec = wz_codecs::encoding::EncodingOwned {
            packed_id: 0x1234,
            schema_len: Some(4),
            schema: Some(crate::codec_owned::owned_string("text").unwrap()),
        };
        let hint = EncodingHint::from_codec(&codec);
        assert_eq!(hint.packed_id, 0x1234);
        assert_eq!(hint.schema.as_deref(), Some("text"));
    }

    #[test]
    fn encoding_hint_from_codec_preserves_absent_schema() {
        let codec = wz_codecs::encoding::EncodingOwned {
            packed_id: 0x4000,
            schema_len: None,
            schema: None,
        };
        let hint = EncodingHint::from_codec(&codec);
        assert_eq!(hint.packed_id, 0x4000);
        assert!(hint.schema.is_none());
    }

    #[test]
    fn qos_level_express_flag_matches_zenoh_pico_bit_position() {
        // zenoh-pico _Z_N_QOS_IS_EXPRESS_FLAG = 1 << 4 = 0x10.
        assert!(QosLevel::from_raw(0b0001_0000).is_express());
        assert!(QosLevel::from_raw(0b1111_1111).is_express());
        assert!(!QosLevel::from_raw(0b0000_0000).is_express());
        assert!(!QosLevel::from_raw(0b1110_1111).is_express());
    }

    #[test]
    fn qos_level_from_parts_packs_zenoh_pico_layout() {
        // _z_n_qos_create (network.h:84-89): priority(low 3) | nodrop<<3 | express<<4.
        // RealTime(1) + express + Drop -> 0b0001_0001 = 0x11.
        assert_eq!(
            QosLevel::from_parts(
                crate::qos::Priority::RealTime,
                crate::qos::CongestionControl::Drop,
                true
            )
            .raw,
            0b0001_0001
        );
        // Data(5) + Block(nodrop=1) + no-express -> 0b0000_1101 = 0x0D.
        assert_eq!(
            QosLevel::from_parts(
                crate::qos::Priority::Data,
                crate::qos::CongestionControl::Block,
                false
            )
            .raw,
            0b0000_1101
        );
        // The DEFAULT sentinel is the Data byte (5), NOT the derived
        // QosLevel::default() (raw 0 = Control) — the encoder gates on this.
        assert_eq!(QosLevel::DEFAULT.raw, 0x05);
        assert_ne!(QosLevel::DEFAULT, QosLevel::default());
    }

    #[test]
    fn qos_level_priority_masks_low_three_bits() {
        // express(bit4) + RealTime(1) = 0x11; priority() must mask & 0x07 so a
        // set express bit does not corrupt the decoded priority.
        assert_eq!(
            QosLevel::from_raw(0x11).priority(),
            crate::qos::Priority::RealTime
        );
        assert_eq!(
            QosLevel::from_raw(0xFF).priority(),
            crate::qos::Priority::Background
        );
        // from_parts / priority round-trip across bands (express set to prove masking).
        for p in [
            crate::qos::Priority::Control,
            crate::qos::Priority::RealTime,
            crate::qos::Priority::Data,
            crate::qos::Priority::Background,
        ] {
            assert_eq!(
                QosLevel::from_parts(p, crate::qos::CongestionControl::Drop, true).priority(),
                p
            );
        }
    }

    #[test]
    fn sample_priority_derives_from_qos_ext_else_default() {
        let s = Sample::new_put("k", b"v".to_vec()).with_qos(QosLevel::from_parts(
            crate::qos::Priority::InteractiveHigh,
            crate::qos::CongestionControl::Drop,
            false,
        ));
        assert_eq!(s.priority(), crate::qos::Priority::InteractiveHigh);
        // No qos ext -> DEFAULT (Data), mirroring a plain publish / off-subset.
        assert_eq!(
            Sample::new_put("k", b"v".to_vec()).priority(),
            crate::qos::Priority::DEFAULT
        );
    }

    #[test]
    fn sample_clone_preserves_all_metadata() {
        let original = Sample::new_put("topic/b", b"v1".to_vec())
            .with_qos(QosLevel::from_raw(0xAA))
            .with_attachment(b"att".to_vec())
            .with_reliability(Reliability::BestEffort);
        let clone = original.clone();
        assert_eq!(clone.keyexpr, "topic/b");
        assert_eq!(clone.payload, b"v1");
        assert_eq!(clone.qos.unwrap().raw, 0xAA);
        assert_eq!(clone.attachment.unwrap(), b"att");
        assert_eq!(clone.reliability, Reliability::BestEffort);
    }

    // ─── extract_qos ────────────────────────────────────────────────

    #[test]
    fn extract_qos_returns_none_on_empty_chain() {
        assert!(extract_qos(&[]).is_none());
    }

    #[test]
    fn extract_qos_returns_none_when_no_matching_ext_id() {
        // ext with ext_id=2 enc=ZInt should not match QoS predicate.
        let mut ext = ExtEntry::new();
        ext.set_ext_id(0x02);
        ext.set_enc(0x01);
        if let ExtEntryVariant::CodecZenohExtZint(z) = &mut ext.body {
            z.value = 0xCC;
        }
        assert!(extract_qos(&[ext.try_into_owned().unwrap()]).is_none());
    }

    #[test]
    fn extract_qos_projects_first_matching_zint() {
        let mut ext = ExtEntry::new();
        ext.set_ext_id(0x01);
        ext.set_enc(0x01);
        ext.body = ExtEntryVariant::CodecZenohExtZint(wz_codecs::ext_zint::ExtZint { value: 0xBE });
        let qos = extract_qos(&[ext.try_into_owned().unwrap()]).unwrap();
        assert_eq!(qos.raw, 0xBE);
    }

    // attachment decode predicate tests moved with the helper to
    // `crate::attachment` (push/query round-trip + carrier discrimination).

    // ─── extract_source_info ───────────────────────────────────────

    #[test]
    fn extract_source_info_decodes_full_payload() {
        // Wire: 1 byte header (zidlen-1 in high nibble, here 4 → zidlen
        // 5) + 5 zid bytes + VLE eid (single-byte 7) + VLE sn
        // (single-byte 42).
        let mut payload = vec![0x40u8]; // (5 - 1) << 4 = 0x40
        payload.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
        payload.push(7);
        payload.push(42);
        let mut ext = ExtEntry::new();
        ext.set_ext_id(0x01);
        ext.set_enc(0x02);
        ext.body = ExtEntryVariant::CodecZenohExtZbuf(wz_codecs::ext_zbuf::ExtZbuf {
            value_len: payload.len() as u64,
            value: &payload,
        });
        let si = extract_source_info(&[ext.try_into_owned().unwrap()]).unwrap();
        let mut expected_zid = [0u8; 16];
        expected_zid[..5].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
        assert_eq!(si.zid, expected_zid);
        // R231 — zid_len records the effective wire-header prefix length.
        assert_eq!(si.zid_len, 5);
        assert_eq!(si.zid_prefix(), &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE][..]);
        assert_eq!(si.eid, 7);
        assert_eq!(si.sn, 42);
    }

    #[test]
    fn extract_source_info_returns_none_on_truncated_zid_window() {
        let mut ext = ExtEntry::new();
        ext.set_ext_id(0x01);
        ext.set_enc(0x02);
        // header says zidlen 16, but payload only has 1 byte.
        ext.body = ExtEntryVariant::CodecZenohExtZbuf(wz_codecs::ext_zbuf::ExtZbuf {
            value_len: 1,
            value: &[0xF0u8],
        });
        assert!(extract_source_info(&[ext.try_into_owned().unwrap()]).is_none());
    }

    #[test]
    fn extract_source_info_returns_none_on_empty_payload() {
        let mut ext = ExtEntry::new();
        ext.set_ext_id(0x01);
        ext.set_enc(0x02);
        ext.body = ExtEntryVariant::CodecZenohExtZbuf(wz_codecs::ext_zbuf::ExtZbuf {
            value_len: 0,
            value: &[],
        });
        assert!(extract_source_info(&[ext.try_into_owned().unwrap()]).is_none());
    }

    #[test]
    fn extract_source_info_decodes_multibyte_vle_fields() {
        // zidlen 1 + 1 zid byte + VLE eid 200 (2 bytes: 0xC8 0x01) +
        // VLE sn 16384 (3 bytes: 0x80 0x80 0x01).
        let payload: Vec<u8> = vec![
            0x00, // (1-1) << 4 = 0
            0x99, // zid byte
            0xC8, 0x01, // VLE 200
            0x80, 0x80, 0x01, // VLE 16384
        ];
        let mut ext = ExtEntry::new();
        ext.set_ext_id(0x01);
        ext.set_enc(0x02);
        ext.body = ExtEntryVariant::CodecZenohExtZbuf(wz_codecs::ext_zbuf::ExtZbuf {
            value_len: payload.len() as u64,
            value: &payload,
        });
        let si = extract_source_info(&[ext.try_into_owned().unwrap()]).unwrap();
        let mut expected_zid = [0u8; 16];
        expected_zid[0] = 0x99;
        assert_eq!(si.zid, expected_zid);
        assert_eq!(si.eid, 200);
        assert_eq!(si.sn, 16384);
    }
}
