// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311nb (Level B, B5b-2b tail — publish SSOT convergence) — the
//! TRANSPORT-AGNOSTIC publish value surface, split out of the
//! `transport-unicast`-gated [`publisher`](super::publisher) cluster.
//!
//! [`PublishOptions`], [`PublishError`], and the loopback Sample assembly
//! `build_loopback_sample` are the primitives the unified
//! [`Session::publish`](super::Session::publish) consumes on EVERY transport
//! (the remote leg builds a `NetworkMessage::Push` and routes it through the
//! transport-dispatch send seam
//! [`Session::send_network_message`](super::Session::send_network_message);
//! the loopback leg reads only the observer + deferred-fire queue). None of
//! the three names the unicast action bundle, so they are not unicast-coupled
//! — they were over-gated only because the literal `publish` previously lived
//! in the `transport-unicast` impl block. This module gives them their honest
//! (ungated) home so a multicast-only build reaches the same single `publish`
//! SSOT, replacing the prior multicast-specific `publish(k, v)` (R311mo/mp).
//!
//! The genuinely-unicast publish surface stays in
//! [`publisher`](super::publisher): the [`Publisher`](super::Publisher) /
//! [`PublisherAliased`](super::PublisherAliased) handles, the aliased
//! keyexpr-mapping path ([`Session::publish_aliased`](super::Session::publish_aliased)
//! / `publish_aliased_auto`), and [`PublishAliasError`](super::PublishAliasError)
//! — the aliased forms resolve the unicast outbound mapping table, which a
//! handshake-free multicast session has no analogue of.

use crate::locality::Locality;
use crate::sample::{EncodingHint, QosLevel, Reliability, SampleKind, SourceInfo, TimestampHint};
// R311y-item3 — `Priority` is the transport conduit band + the QoS byte's
// priority sub-field. Ungated import: the always-compiled `priority_band`
// accessor below reads it on every profile (the `with_priority` setter is
// `pubsub-priority`-gated, but the derived-band read is not).
use wz_session_core::qos::Priority;
// `build_loopback_sample` is the sole `Sample` consumer here, so the import
// follows its `pubsub-allow-loop` gate (the loopback leg).
#[cfg(feature = "pubsub-allow-loop")]
use crate::sample::Sample;
// R311nb — `PushMetadata` imported from its real home
// `wz_session_core::metadata` (ungated), NOT the `transport-unicast`-gated
// `session_glue` re-export path: `push_metadata` is `codec-push`-gated and
// must compile on a multicast-only build with the Push codec.
#[cfg(feature = "codec-push")]
use wz_session_core::metadata::PushMetadata;
// R311nb — `SendWireError` likewise imported from its ungated real home
// (`session_glue::SendWireError` is the same type behind a unicast-gated path).
use wz_session_core::send_wire_error::SendWireError;

/// Options bundle for [`Session::publish`](super::Session::publish). Carries
/// the locality routing predicate (`allowed_destination`), the reliability
/// hint for the wire frame and the loopback `Sample.reliability` field,
/// and the [`SampleKind`] discriminator that selects Put vs Del
/// dispatch.
///
/// Construct via [`PublishOptions::put`] / [`PublishOptions::del`]
/// plus optional `with_*` setters; defaults to a Put publish that
/// fans both branches (`Locality::Any`) with `Reliability::Reliable`
/// matching zenoh-pico's `Z_RELIABILITY_DEFAULT`.
///
/// Future-additive: this struct is `#[non_exhaustive]` so later rounds
/// can add metadata fields without breaking external callers. The five
/// R229+ metadata fields (`qos`, `attachment`, `timestamp`, `encoding`,
/// `source_info`) have since landed (R232/R233) and ARE carried on the
/// wire — the remote leg routes them through
/// `build_push_literal_with_meta`, each foreign-proven wz->pico
/// (encoding R311y207 / timestamp y208 / attachment y209 / qos
/// y240+y242 / source_info y243). Construct through the builder API
/// rather than struct-literal so the future-additive contract holds.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct PublishOptions {
    /// Publisher-side locality predicate (zenoh-pico
    /// `allowed_destination` parameter to `_z_write`). `Any` routes
    /// to both wire and loopback branches; `Remote` to wire only;
    /// `SessionLocal` to loopback only. Default: `Any`.
    pub allowed_destination: Locality,
    /// Link-layer reliability hint propagated to (a) the wire frame's
    /// reliable-flag (zenoh-pico `FLAG_T_FRAME_R`) and (b) the
    /// loopback `Sample.reliability` field.
    pub reliability: Reliability,
    /// Sample discriminator. `Put` carries the caller payload; `Del`
    /// carries an empty payload (the keyexpr is the entire payload).
    /// Default: `Put`.
    pub kind: SampleKind,
    /// R232 — body-level timestamp propagated to subscribers via
    /// `Sample.timestamp`. On the loopback branch the value lands
    /// verbatim. On the wire branch (R233) it encodes into the
    /// `MsgPut`/`MsgDel` body (`gated_timestamp_field`, gated
    /// `pubsub-timestamp`; the header T-flag `0x20` rides with it) and
    /// is foreign-decoded — R311y208 proves a real zenoh-pico
    /// `z_sub_attachment` reads it (`wz_timestamp_to_pico_zsub`).
    /// `None` (default) means no timestamp attached.
    pub timestamp: Option<TimestampHint>,
    /// R232 — body-level encoding propagated to Put-kind subscribers
    /// via `Sample.encoding`. Del-kind ignores this field (zenoh-pico
    /// `_z_msg_del_t` has no encoding slot). Wire-side propagation is
    /// built (R233, `gated_encoding_field` on the Put body, gated
    /// `pubsub-encoding`) and foreign-proven — R311y207
    /// (`wz_encoding_to_pico_zsub`, `text/plain` decoded by pico);
    /// loopback honours it from R232.
    pub encoding: Option<EncodingHint>,
    /// R232 — body-level source identification propagated to
    /// `Sample.source_info`. Cooperates with the R231 self-echo dedup:
    /// when the dispatcher fires on a wire-arrived Push whose
    /// `source_info.zid` matches the session's own zid, the dedup
    /// suppresses the duplicate fire so a `Locality::Any` publish only
    /// invokes any-locality subscribers once. Wire-side propagation is
    /// built (R233, body ext `0x01` via `build_body_extensions`, gated
    /// `pubsub-source-info`; an empty zid prefix emits no ext) and
    /// foreign-proven on BOTH the Put and Del kinds — R311y243
    /// (`wz_source_info_to_pico_zsub`, a Put; pico decodes the
    /// (zid, eid, sn) triple and `z_sample_source_info` surfaces
    /// `eid: 66 sn: 153`) and R311y246 (`wz_del_source_info_to_pico_zsub`,
    /// a Delete decoded with `with kind: 1` + `eid: 44 sn: 55`; the field
    /// feeds `del()` publishes via `build_msg_del_with_meta`). The pico
    /// getter is `Z_FEATURE_UNSTABLE_API`-gated, which the CLI build now
    /// enables. The wz-internal unit test
    /// `build_msg_put_with_meta_attaches_source_info_ext_and_sets_z_flag`
    /// still pins the byte layout. Loopback honours it from R232.
    pub source_info: Option<SourceInfo>,
    /// R232 — body-level attachment blob propagated to
    /// `Sample.attachment`. Wire-side propagation is built (R233, body
    /// ext `0x03` via `build_body_extensions`, gated `pubsub-attachment`)
    /// and foreign-proven — R311y209 (`wz_attachment_to_pico_zsub`,
    /// ze_serializer kv-pairs decoded by pico); loopback honours it
    /// from R232.
    pub attachment: Option<Vec<u8>>,
    /// R232 — outer-level QoS metadata propagated to `Sample.qos`.
    /// zenoh-pico mirror: the Push outer `_Z_MSG_EXT_ENC_ZINT | 0x01`
    /// extension carrying priority + congestion-control + express
    /// packed into one byte. Wire-side propagation is built (R233,
    /// `build_push_outer_extensions`, gated on any of `pubsub-priority`
    /// / `pubsub-congestion-control` / `pubsub-express`; the ext is
    /// suppressed when the byte equals `QosLevel::DEFAULT`). All three
    /// sub-fields are foreign-proven: PRIORITY — R311y240
    /// (`wz_priority_to_pico_zsub`, pico `z_sample_priority`);
    /// CONGESTION + EXPRESS — R311y242
    /// (`wz_qos_congestion_express_to_pico_zsub`, pico
    /// `z_sample_congestion_control` / `z_sample_express`). Loopback
    /// honours all three from R232.
    pub qos: Option<QosLevel>,
}

impl PublishOptions {
    /// Default Put-kind options: `allowed_destination = Any`,
    /// `reliability = Reliable`.
    pub fn put() -> Self {
        Self::default()
    }

    /// Default Del-kind options: `allowed_destination = Any`,
    /// `reliability = Reliable`, `kind = Del`. The payload argument
    /// to [`Session::publish`](super::Session::publish) is ignored for
    /// Del kind (zenoh-pico `_z_n_msg_make_push_del` does not carry
    /// payload).
    pub fn del() -> Self {
        Self {
            kind: SampleKind::Del,
            ..Self::default()
        }
    }

    /// Pin the publisher-side locality predicate.
    pub fn with_locality(mut self, locality: Locality) -> Self {
        self.allowed_destination = locality;
        self
    }

    /// Pin the reliability hint.
    pub fn with_reliability(mut self, reliability: Reliability) -> Self {
        self.reliability = reliability;
        self
    }

    /// Pin the Sample kind.
    pub fn with_kind(mut self, kind: SampleKind) -> Self {
        self.kind = kind;
        self
    }

    /// R232 — attach a body-level timestamp. The loopback branch
    /// propagates this into `Sample.timestamp` for the subscriber
    /// callback; the wire branch encodes it into the Put/Del body
    /// (R233, foreign-proven R311y208).
    // R311fx — gated on `pubsub-timestamp` (wire-data helper, mirrors
    // `with_attachment`): the send-side encode elides the timestamp when
    // the feature is off, so offering the setter would silently drop it.
    // The `timestamp` field stays (struct stability); only the populator
    // gates.
    #[cfg(feature = "pubsub-timestamp")]
    pub fn with_timestamp(mut self, timestamp: TimestampHint) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    /// R232 — attach a body-level encoding (Put kind only; Del kind
    /// ignores the field per zenoh-pico `_z_msg_del_t` layout).
    ///
    /// Gated on `pubsub-encoding` (wire-data helper, mirrors
    /// `with_timestamp` / `with_attachment`): the send-side encode
    /// (`gated_encoding_field` in build_msg_put_with_meta) omits the
    /// inline encoding field + `_Z_FLAG_Z_P_E` header bit when the
    /// feature is off, so offering the setter would silently drop it.
    /// The `encoding` field stays (struct stability); only the
    /// populator gates.
    #[cfg(feature = "pubsub-encoding")]
    pub fn with_encoding(mut self, encoding: EncodingHint) -> Self {
        self.encoding = Some(encoding);
        self
    }

    /// R232 — attach a body-level source identification. Pairs with
    /// the R231 self-echo dedup: when the wire receives a publish
    /// whose `source_info.zid` matches the session's own zid, the
    /// dispatch suppresses to avoid double-firing local subscribers
    /// in mesh / router-echo topologies.
    ///
    /// Gated on `pubsub-source-info` (wire-data helper, mirrors
    /// `with_attachment` / `with_timestamp`): the send-side encode
    /// (`build_body_extensions`) omits the source_info ext when the
    /// feature is off, so offering the setter would silently drop it.
    /// The `source_info` field stays (struct stability); only the
    /// populator gates.
    #[cfg(feature = "pubsub-source-info")]
    pub fn with_source_info(mut self, source_info: SourceInfo) -> Self {
        self.source_info = Some(source_info);
        self
    }

    /// R232 — attach a body-level attachment blob. Gated on
    /// `pubsub-attachment` (wire-data helper): without it the wire +
    /// loopback encode paths carry no attachment, so offering the setter
    /// would silently drop the blob. The `attachment` field itself stays
    /// (struct stability); only the populator gates.
    #[cfg(feature = "pubsub-attachment")]
    pub fn with_attachment(mut self, attachment: Vec<u8>) -> Self {
        self.attachment = Some(attachment);
        self
    }

    /// R232 — attach outer-level QoS metadata (priority / congestion
    /// control / express byte). Mirrors zenoh-pico's
    /// `_Z_MSG_EXT_ENC_ZINT | 0x01` Push outer extension.
    ///
    /// Gated on any of the three QoS-byte features (`pubsub-priority` /
    /// `pubsub-congestion-control` / `pubsub-express`) — the single
    /// outer-ext byte packs all three, so any one of them composes the
    /// `build_push_outer_extensions` encode path. With none of them on,
    /// the send-side emits no QoS ext (and the subscriber-side decode is
    /// gated on the same `any(...)`), so offering the setter would
    /// silently drop the byte. The `qos` field stays (struct stability);
    /// only the populator gates.
    #[cfg(any(
        feature = "pubsub-priority",
        feature = "pubsub-congestion-control",
        feature = "pubsub-express"
    ))]
    pub fn with_qos(mut self, qos: QosLevel) -> Self {
        self.qos = Some(qos);
        self
    }

    /// R311y-item3 — set the typed [`Priority`] as the SINGLE priority source
    /// for the publish. Merges `p` into the priority sub-field (low 3 bits) of
    /// the packed QoS byte, PRESERVING any congestion (bit 3) / express (bit 4)
    /// bits a prior [`with_qos`](Self::with_qos) attached. This one value then
    /// drives EVERY leg — the app-observable Push qos ext + loopback
    /// `Sample.priority` (via `qos`, R232/R311y226) AND the transport frame
    /// conduit band ([`Session::publish`](super::Session::publish) reads it back
    /// through [`priority_band`](Self::priority_band), R311y232) — closing the
    /// y226/y232 two-input split where a caller had to set `with_qos` AND call
    /// `publish_qos` with matching bands. One `with_priority` cannot diverge,
    /// mirroring zenoh's single `QoSType` (`resolve_put`) and the already-unified
    /// peer path [`LinkstateForwarder::publish_qos`](crate::linkstate_forward).
    ///
    /// Gated on `pubsub-priority` (the priority-observability feature). Without
    /// it the priority sub-field cannot ride the wire, so a transport-qos-only
    /// build drives the conduit band via
    /// [`Session::publish_qos`](super::Session::publish_qos) instead.
    #[cfg(feature = "pubsub-priority")]
    pub fn with_priority(mut self, p: Priority) -> Self {
        // Preserve the congestion (bit 3) + express (bit 4) bits from any prior
        // `with_qos`; when unset, base off the wire-DEFAULT byte
        // (`QosLevel::DEFAULT` = 0x05 = Data / Drop / no-express) so the
        // non-priority bits match a DEFAULT publish. `& !0x07` clears the low 3
        // priority bits before OR-ing the new band's `wire_byte()`.
        let base = self.qos.map(|q| q.raw).unwrap_or(QosLevel::DEFAULT.raw);
        self.qos = Some(QosLevel::from_raw((base & !0x07) | p.wire_byte()));
        self
    }

    /// R311y-item3 — the transport frame conduit band derived from the SINGLE
    /// priority source [`qos`](Self::qos): the priority sub-field of the packed
    /// byte, or [`Priority::DEFAULT`] when no QoS was attached.
    /// [`Session::publish`](super::Session::publish) /
    /// [`publish_aliased`](super::Session::publish_aliased) /
    /// [`publish_shm`](super::Session::publish_shm) read this back so a
    /// `with_priority` (or raw `with_qos`) publish rides the matching
    /// per-priority conduit — the SAME value the app observes via
    /// `Sample.priority`, never a second source.
    ///
    /// Ungated: it reads only the always-present `qos` field plus the no_std
    /// value types [`QosLevel::priority`] / [`Priority`], so it compiles on every
    /// profile. A build without the `transport-qos` conduit split clamps the
    /// band back to DEFAULT downstream, so deriving it here is inert there.
    pub(super) fn priority_band(&self) -> Priority {
        self.qos.map(|q| q.priority()).unwrap_or(Priority::DEFAULT)
    }

    /// Translate [`Reliability`] into the bool flag the legacy
    /// `send_push_*` outbound API expects (it predates the typed
    /// enum). Exposed inside the crate so
    /// [`Session::publish`](super::Session::publish) does the
    /// conversion in exactly one place.
    ///
    /// W3 — `codec-push`-gated: the sole callers are the
    /// `codec-push`-gated remote legs of
    /// [`Session::publish`](super::Session::publish) /
    /// [`Session::publish_aliased`](super::Session::publish_aliased), so
    /// the helper is dead weight on a build without the Push codec.
    #[cfg(feature = "codec-push")]
    pub(super) fn reliable_bool(&self) -> bool {
        matches!(self.reliability, Reliability::Reliable)
    }

    /// R233 — extract the wire-encoder-facing metadata bundle from a
    /// PublishOptions instance so [`Session::publish`](super::Session::publish)
    /// can hand it to the Push builder without the lower module learning
    /// about [`Locality`] / [`Reliability`] / [`SampleKind`] (those stay
    /// on the dispatch-time surface). Clones each owned slot — the
    /// expected publish path performs one extraction per publish
    /// call so the allocation cost is amortised against the wire
    /// frame's existing copies.
    ///
    /// W3 — `codec-push`-gated for the same reason as
    /// [`Self::reliable_bool`]: only the gated remote legs consume it.
    #[cfg(feature = "codec-push")]
    pub(super) fn push_metadata(&self) -> PushMetadata {
        PushMetadata {
            timestamp: self.timestamp.clone(),
            encoding: self.encoding.clone(),
            source_info: self.source_info.clone(),
            attachment: self.attachment.clone(),
            qos: self.qos,
        }
    }
}

/// W3 (SCE pin 7a94d084a) — typed reject from the literal /
/// direct-aliased publish path
/// ([`Session::publish`](super::Session::publish) /
/// [`Session::publish_aliased`](super::Session::publish_aliased) and the
/// [`Publisher`](super::Publisher) handles). These
/// paths do not resolve the outbound mapping table (so they cannot
/// produce `UnknownMapping`), and their remote leg is
/// `codec-push`-gated (a build without the Push codec elides the leg
/// and runs loopback only — never an error), so the single failure
/// mode is a caller-data overflow of the declared bounded-codec
/// capacity. Distinct from
/// [`PublishAliasError`](super::PublishAliasError) (ISP): the
/// auto-resolving [`Session::publish_aliased_auto`](super::Session::publish_aliased_auto)
/// keeps the richer `UnknownMapping` surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishError {
    /// The payload or keyexpr exceeded the declared bounded-codec
    /// capacity while being copied into the no-alloc owned Push
    /// mirror — the same bound the decode path enforces. No wire bytes
    /// were emitted.
    ExceedsCapacity,
    /// F2 — the transport is not currently accepting data sends (link
    /// released or reconnecting; Established not re-entered). No wire
    /// bytes were emitted; retry after the session re-establishes
    /// (zenoh-pico `_Z_ERR_TRANSPORT_NOT_AVAILABLE` parity).
    TransportUnavailable,
    /// B5b-2b (R311nc) — an ALIASED publish (`publish_aliased{,_auto}`,
    /// which resolves the unicast outbound keyexpr-mapping table) was
    /// attempted on a session whose transport is not unicast. A multicast
    /// session has no outbound mapping table; the `Session::actions()`
    /// projection rejects with `SendWireError::UnsupportedVariant`,
    /// surfaced here. No wire bytes were emitted. The transport-agnostic
    /// literal [`Session::publish`](crate::session::Session::publish) does
    /// NOT raise this — it routes through the send seam and runs on either
    /// transport; only the unicast-mapping aliased path does.
    RequiresUnicast,
}

impl std::fmt::Display for PublishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PublishError::ExceedsCapacity => write!(
                f,
                "PublishError: payload or keyexpr exceeded the declared codec \
                 capacity; the Push was not emitted"
            ),
            PublishError::TransportUnavailable => write!(
                f,
                "PublishError: transport not available (link released or \
                 reconnecting); the Push was not emitted — retry after the \
                 session re-establishes"
            ),
            PublishError::RequiresUnicast => write!(
                f,
                "PublishError: aliased publish requires a unicast transport \
                 (no outbound keyexpr-mapping table on a multicast session); \
                 the Push was not emitted"
            ),
        }
    }
}

impl std::error::Error for PublishError {}

impl From<SendWireError> for PublishError {
    fn from(e: SendWireError) -> Self {
        match e {
            SendWireError::Codec(_) => PublishError::ExceedsCapacity,
            // `Session::publish` / `publish_aliased` only invoke the
            // send_push_* path inside a `#[cfg(feature = "codec-push")]`
            // block, where the Push codec is present; the send therefore
            // never reports `FeatureDisabled` to this conversion. The
            // guard documents that compile-time invariant (and trips a
            // future regression that ungates the leg).
            SendWireError::FeatureDisabled => {
                unreachable!("publish remote leg is codec-push-gated")
            }
            SendWireError::TransportUnavailable => PublishError::TransportUnavailable,
            SendWireError::UnsupportedVariant => PublishError::RequiresUnicast,
        }
    }
}

/// R232 — shared loopback Sample assembly for
/// [`Session::publish`](super::Session::publish) and
/// [`Session::publish_aliased`](super::Session::publish_aliased).
/// Constructs a Put or Del Sample on the
/// supplied keyexpr + payload, threads every metadata field the caller
/// attached to [`PublishOptions`] via `with_*` setters, and leaves the
/// Del-encoding slot empty (zenoh-pico `_z_msg_del_t` carries no
/// encoding so the loopback parity mirrors that wire constraint).
///
/// Keeps the metadata-threading rules in one place so a future R232
/// follow-up that adjusts the propagation policy (e.g. validating QoS
/// bits or trimming an over-long attachment) only edits this function.
#[cfg(feature = "pubsub-allow-loop")]
pub(super) fn build_loopback_sample(
    keyexpr: &str,
    payload: &[u8],
    opts: &PublishOptions,
) -> Sample {
    let mut sample = match opts.kind {
        SampleKind::Put => Sample::new_put(keyexpr, payload.to_vec()),
        SampleKind::Del => Sample::new_del(keyexpr),
    };
    sample = sample.with_reliability(opts.reliability);
    if let Some(ts) = opts.timestamp.clone() {
        sample = sample.with_timestamp(ts);
    }
    // Encoding is Put-only on the wire; mirror the constraint on
    // loopback so a caller mis-attaching encoding to a Del kind sees
    // the same "encoding=None" the wire path would project.
    if opts.kind == SampleKind::Put {
        if let Some(enc) = opts.encoding.clone() {
            sample = sample.with_encoding(enc);
        }
    }
    if let Some(si) = opts.source_info.clone() {
        sample = sample.with_source_info(si);
    }
    if let Some(att) = opts.attachment.clone() {
        sample = sample.with_attachment(att);
    }
    if let Some(qos) = opts.qos {
        sample = sample.with_qos(qos);
    }
    sample
}
