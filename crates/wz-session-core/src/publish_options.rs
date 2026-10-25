// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What one publish asks for, independent of the engine that sends it:
//! [`PublishOptions`](crate::publish_options::PublishOptions), the facts a plain Put is sent from
//! ([`PlainPutParams`](crate::publish_options::PlainPutParams)), and the typed refusal
//! ([`PublishError`](crate::publish_options::PublishError)).
//!
//! ## Why it lives here
//!
//! Every field is a type of this crate (locality, reliability, sample kind, timestamp, encoding,
//! source info, attachment, QoS), and every derivation below (the conduit band, the reliable flag,
//! the wire metadata bundle) reads only those. It lived in `wz-runtime-tokio`'s session module,
//! the first engine that published, and moved down when the pico C ABI over the cooperative
//! engine (`docs/capi-pico-on-coop-engine.md`) had to describe a publish without the tokio engine.
//! `wz-runtime-tokio` re-exports these types, so its own paths are unchanged; what stays there is
//! the loopback leg, which is that engine's.
//!
//! ## The gates are this crate's own
//!
//! Each metadata field reaches the wire only when its feature is composed (`pubsub-timestamp`,
//! `pubsub-encoding`, `pubsub-source-info`, `pubsub-attachment`, `pubsub-qos`), and the plain-put
//! lane exists only with `codec-push` and without `transport-stats` and `routing-namespace`. Those
//! are features of this crate; the runtime's features of the same names forward to them, so the
//! answer in a tokio build is the answer it always was.

use alloc::vec::Vec;

use crate::locality::Locality;
use crate::metadata::PushMetadata;
#[cfg(feature = "pubsub-qos")]
use crate::qos::CongestionControl;
use crate::qos::Priority;
use crate::sample::{EncodingHint, QosLevel, Reliability, SampleKind, SourceInfo, TimestampHint};
use crate::send_wire_error::SendWireError;

/// Options bundle for a publish. Carries the locality routing predicate
/// (`allowed_destination`), the reliability and the [`SampleKind`] discriminator that selects Put
/// vs Del dispatch.
///
/// Construct via [`PublishOptions::put`] / [`PublishOptions::del`] plus optional `with_*`
/// setters; defaults to a Put publish that fans both branches (`Locality::Any`) with
/// `Reliability::Reliable` matching zenoh-pico's `Z_RELIABILITY_DEFAULT`.
///
/// Future-additive: this struct is `#[non_exhaustive]` so later rounds can add metadata fields
/// without breaking external callers. The five R229+ metadata fields (`qos`, `attachment`,
/// `timestamp`, `encoding`, `source_info`) have since landed (R232/R233) and ARE carried on the
/// wire — the remote leg routes them through `build_push_literal_with_meta`, each foreign-proven
/// wz->pico (encoding R311y207 / timestamp y208 / attachment y209 / qos y240+y242 / source_info
/// y243). Construct through the builder API rather than struct-literal so the future-additive
/// contract holds.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct PublishOptions {
    /// Publisher-side locality predicate (zenoh-pico `allowed_destination` parameter to
    /// `_z_write`). `Any` routes to both wire and loopback branches; `Remote` to wire only;
    /// `SessionLocal` to loopback only. Default: `Any`.
    pub allowed_destination: Locality,
    /// Link-layer reliability hint propagated to (a) the wire frame's reliable-flag (zenoh-pico
    /// `FLAG_T_FRAME_R`) and (b) the loopback `Sample.reliability` field.
    pub reliability: Reliability,
    /// Sample discriminator. `Put` carries the caller payload; `Del` carries an empty payload
    /// (the keyexpr is the entire payload). Default: `Put`.
    pub kind: SampleKind,
    /// R232 — body-level timestamp propagated to subscribers via `Sample.timestamp`. On the
    /// loopback branch the value lands verbatim. On the wire branch (R233) it encodes into the
    /// `MsgPut`/`MsgDel` body (`gated_timestamp_field`, gated `pubsub-timestamp`; the header
    /// T-flag `0x20` rides with it) and is foreign-decoded — R311y208 proves a real zenoh-pico
    /// `z_sub_attachment` reads it (`wz_timestamp_to_pico_zsub`). `None` (default) means no
    /// timestamp attached.
    pub timestamp: Option<TimestampHint>,
    /// R232 — body-level encoding propagated to Put-kind subscribers via `Sample.encoding`.
    /// Del-kind ignores this field (zenoh-pico `_z_msg_del_t` has no encoding slot). Wire-side
    /// propagation is built (R233, `gated_encoding_field` on the Put body, gated
    /// `pubsub-encoding`) and foreign-proven — R311y207 (`wz_encoding_to_pico_zsub`,
    /// `text/plain` decoded by pico); loopback honours it from R232.
    pub encoding: Option<EncodingHint>,
    /// R232 — body-level source identification propagated to `Sample.source_info`. Cooperates
    /// with the R231 self-echo dedup: when the dispatcher fires on a wire-arrived Push whose
    /// `source_info.zid` matches the session's own zid, the dedup suppresses the duplicate fire so
    /// a `Locality::Any` publish only invokes any-locality subscribers once. Wire-side propagation
    /// is built (R233, body ext `0x01` via `build_body_extensions`, gated `pubsub-source-info`;
    /// an empty zid prefix emits no ext) and foreign-proven on BOTH the Put and Del kinds —
    /// R311y243 (`wz_source_info_to_pico_zsub`, a Put; pico decodes the (zid, eid, sn) triple and
    /// `z_sample_source_info` surfaces `eid: 66 sn: 153`) and R311y246
    /// (`wz_del_source_info_to_pico_zsub`, a Delete decoded with `with kind: 1` +
    /// `eid: 44 sn: 55`; the field feeds `del()` publishes via `build_msg_del_with_meta`). The
    /// pico getter is `Z_FEATURE_UNSTABLE_API`-gated, which the CLI build now enables. The
    /// wz-internal unit test `build_msg_put_with_meta_attaches_source_info_ext_and_sets_z_flag`
    /// still pins the byte layout. Loopback honours it from R232.
    pub source_info: Option<SourceInfo>,
    /// R232 — body-level attachment blob propagated to `Sample.attachment`. Wire-side
    /// propagation is built (R233, via `build_body_extensions`, gated `pubsub-attachment`) at the
    /// ext id of the body that carries it — `0x03` for the `put()` arm, `0x02` for the `del()`
    /// one, which is R2370's repair; this field feeds BOTH, so the single id this comment used to
    /// name was wrong for one of them and foreign-proven — R311y209
    /// (`wz_attachment_to_pico_zsub`, ze_serializer kv-pairs decoded by pico); loopback honours
    /// it from R232.
    pub attachment: Option<Vec<u8>>,
    /// R232 — outer-level QoS metadata propagated to `Sample.qos`. zenoh-pico mirror: the Push
    /// outer `_Z_MSG_EXT_ENC_ZINT | 0x01` extension carrying priority + congestion-control +
    /// express packed into one byte. Wire-side propagation is built (R233,
    /// `build_push_outer_extensions`, gated on `pubsub-qos`; the ext is suppressed when the byte
    /// equals `QosLevel::DEFAULT`). All three sub-fields are foreign-proven: PRIORITY — R311y240
    /// (`wz_priority_to_pico_zsub`, pico `z_sample_priority`); CONGESTION + EXPRESS — R311y242
    /// (`wz_qos_congestion_express_to_pico_zsub`, pico `z_sample_congestion_control` /
    /// `z_sample_express`). Loopback honours all three from R232.
    pub qos: Option<QosLevel>,
}

impl PublishOptions {
    /// Default Put-kind options: `allowed_destination = Any`, `reliability = Reliable`.
    pub fn put() -> Self {
        Self::default()
    }

    /// Default Del-kind options: `allowed_destination = Any`, `reliability = Reliable`,
    /// `kind = Del`. The payload argument to a publish is ignored for Del kind (zenoh-pico
    /// `_z_n_msg_make_push_del` does not carry payload).
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

    /// R232 — attach a body-level timestamp. The loopback branch propagates this into
    /// `Sample.timestamp` for the subscriber callback; the wire branch encodes it into the
    /// Put/Del body (R233, foreign-proven R311y208).
    // R311fx — gated on `pubsub-timestamp` (wire-data helper, mirrors `with_attachment`): the
    // send-side encode elides the timestamp when the feature is off, so offering the setter would
    // silently drop it. The `timestamp` field stays (struct stability); only the populator gates.
    #[cfg(feature = "pubsub-timestamp")]
    pub fn with_timestamp(mut self, timestamp: TimestampHint) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    /// R232 — attach a body-level encoding (Put kind only; Del kind ignores the field per
    /// zenoh-pico `_z_msg_del_t` layout).
    ///
    /// Gated on `pubsub-encoding` (wire-data helper, mirrors `with_timestamp` /
    /// `with_attachment`): the send-side encode (`gated_encoding_field` in
    /// build_msg_put_with_meta) omits the inline encoding field + `_Z_FLAG_Z_P_E` header bit when
    /// the feature is off, so offering the setter would silently drop it. The `encoding` field
    /// stays (struct stability); only the populator gates.
    #[cfg(feature = "pubsub-encoding")]
    pub fn with_encoding(mut self, encoding: EncodingHint) -> Self {
        self.encoding = Some(encoding);
        self
    }

    /// R232 — attach a body-level source identification. Pairs with the R231 self-echo dedup:
    /// when the wire receives a publish whose `source_info.zid` matches the session's own zid,
    /// the dispatch suppresses to avoid double-firing local subscribers in mesh / router-echo
    /// topologies.
    ///
    /// Gated on `pubsub-source-info` (wire-data helper, mirrors `with_attachment` /
    /// `with_timestamp`): the send-side encode (`build_body_extensions`) omits the source_info
    /// ext when the feature is off, so offering the setter would silently drop it. The
    /// `source_info` field stays (struct stability); only the populator gates.
    #[cfg(feature = "pubsub-source-info")]
    pub fn with_source_info(mut self, source_info: SourceInfo) -> Self {
        self.source_info = Some(source_info);
        self
    }

    /// R232 — attach a body-level attachment blob. Gated on `pubsub-attachment` (wire-data
    /// helper): without it the wire + loopback encode paths carry no attachment, so offering the
    /// setter would silently drop the blob. The `attachment` field itself stays (struct
    /// stability); only the populator gates.
    #[cfg(feature = "pubsub-attachment")]
    pub fn with_attachment(mut self, attachment: Vec<u8>) -> Self {
        self.attachment = Some(attachment);
        self
    }

    /// R232 — attach outer-level QoS metadata (priority / congestion control / express byte).
    /// Mirrors zenoh-pico's `_Z_MSG_EXT_ENC_ZINT | 0x01` Push outer extension.
    ///
    /// R311y307 — gated on `pubsub-qos`, the ONE compile unit for the Push QoS ext: the single
    /// outer-ext byte packs priority / congestion / express, so they compose together or not at
    /// all. Feature-off, the send-side emits no QoS ext and the subscriber-side decode projects
    /// `Sample.qos = None`, so offering the setter would silently drop the byte. The `qos` field
    /// stays (struct stability); only the populator gates.
    ///
    /// Before y307 this was gated on the UNION `any(pubsub-priority, pubsub-congestion-control,
    /// pubsub-express)` while each sibling's per-field setter gated on itself — so composing any
    /// ONE of the three handed the caller this whole-byte setter and put all three sub-fields on
    /// the wire, falsifying each sibling's "without it the sub-field cannot ride the wire" claim
    /// in every mixed subset.
    #[cfg(feature = "pubsub-qos")]
    pub fn with_qos(mut self, qos: QosLevel) -> Self {
        self.qos = Some(qos);
        self
    }

    /// R311y-item3 — set the typed [`Priority`] as the SINGLE priority source for the publish.
    /// Merges `p` into the priority sub-field (low 3 bits) of the packed QoS byte, PRESERVING any
    /// congestion (bit 3) / express (bit 4) bits a prior [`with_qos`](Self::with_qos) attached.
    /// This one value then drives EVERY leg — the app-observable Push qos ext + loopback
    /// `Sample.priority` (via `qos`, R232/R311y226) AND the transport frame conduit band (the
    /// engine reads it back through [`priority_band`](Self::priority_band), R311y232) — closing
    /// the y226/y232 two-input split where a caller had to set `with_qos` AND call `publish_qos`
    /// with matching bands. One `with_priority` cannot diverge, mirroring zenoh's single
    /// `QoSType` (`resolve_put`) and the already-unified peer path
    /// (`LinkstateForwarder::publish_qos` in `wz-runtime-tokio`).
    ///
    /// R311y307 — gated on `pubsub-qos` (the QoS-ext compile unit), NOT on a per-field
    /// `pubsub-priority` gate. The three sub-fields share ONE packed byte, one ext, one encode
    /// gate and one decode gate, and the app-facing `Sample` carries a single `Option<QosLevel>`
    /// in which a per-field "absent" is unrepresentable — so priority is not separately
    /// gateable. `pubsub-priority` survives as an ALIAS composing `pubsub-qos` (catalog atom,
    /// reserved + FOUNDATIONAL); this setter is its runtime knob.
    ///
    /// The pre-y307 doc claimed "without `pubsub-priority` the priority sub-field cannot ride
    /// the wire". That was FALSE in every mixed subset: [`with_qos`](Self::with_qos) gated on the
    /// sibling UNION and [`QosLevel::from_parts`] is ungated, so composing `pubsub-express` alone
    /// was enough to put priority bits on the wire. Without `pubsub-qos` the claim is now
    /// structurally true — there is no QoS encode path at all.
    ///
    /// A `pubsub-qos`-off build still drives the transport conduit band (the tokio engine's
    /// `Session::publish_qos`): the band is the independent `transport-qos` axis (`sn.rs`
    /// per-priority `RxSn` conduits), deliberately NOT gated here.
    ///
    /// R311y255 — the bit surgery moved to [`QosLevel::with_priority`]: this setter open-coded the
    /// `& !0x07` priority mask, which quietly falsified [`QosLevel::from_parts`]'s "the layout
    /// lives once" claim. It now merges through the SSOT, and its congestion / express siblings
    /// below do the same.
    #[cfg(feature = "pubsub-qos")]
    pub fn with_priority(mut self, p: Priority) -> Self {
        self.qos = Some(self.qos_base().with_priority(p));
        self
    }

    /// R311y255 — set the typed [`CongestionControl`] for the publish, merging it into the
    /// `nodrop` bit (3) of the packed QoS byte and PRESERVING any priority / express bits a prior
    /// setter attached. The congestion sibling of [`with_priority`](Self::with_priority): both
    /// ride the SAME single outer-ext byte, and congestion is already foreign-proven end-to-end —
    /// R311y242 (`wz_qos_congestion_express_to_pico_zsub`) has a real zenoh-pico subscriber decode
    /// it off the wire.
    ///
    /// Before y255 this knob existed on the WIRE and was proven, but had no typed entry point: a
    /// caller wanting `Block` had to hand-assemble the whole byte via
    /// `with_qos(QosLevel::from_parts(..))`, which forces them to restate the priority and express
    /// they did not want to change. That asymmetry (a typed `with_priority` but no typed
    /// congestion / express) is what this closes.
    ///
    /// R311y307 — gated on `pubsub-qos`, the shared QoS-ext compile unit (see
    /// [`with_priority`](Self::with_priority) for why the three sub-fields are not separately
    /// gateable). `pubsub-congestion-control` survives as an alias composing it. The pre-y307
    /// "without it the bit cannot ride the wire" claim was false in mixed subsets.
    #[cfg(feature = "pubsub-qos")]
    pub fn with_congestion_control(mut self, c: CongestionControl) -> Self {
        self.qos = Some(self.qos_base().with_congestion(c));
        self
    }

    /// R311y255 — set the express flag for the publish, merging it into bit 4 of the packed QoS
    /// byte and PRESERVING any priority / congestion bits. The express sibling of
    /// [`with_priority`](Self::with_priority) /
    /// [`with_congestion_control`](Self::with_congestion_control); also foreign-proven by
    /// R311y242.
    ///
    /// R311y307 — gated on `pubsub-qos`, the shared QoS-ext compile unit (see
    /// [`with_priority`](Self::with_priority)); `pubsub-express` survives as an alias composing
    /// it.
    #[cfg(feature = "pubsub-qos")]
    pub fn with_express(mut self, express: bool) -> Self {
        self.qos = Some(self.qos_base().with_express(express));
        self
    }

    /// R311y255 — the base byte the three per-field QoS setters merge into: the QoS already
    /// attached by a prior setter, else the wire-DEFAULT ([`QosLevel::DEFAULT`] = 0x05 = Data /
    /// Drop / no-express) so the sub-fields the caller did NOT set match a DEFAULT publish rather
    /// than a zeroed `Control`-priority byte (`QosLevel::default()`, raw 0 — the trap R311y226
    /// named).
    ///
    /// Gated on the union of the three, matching the setters that call it.
    #[cfg(feature = "pubsub-qos")]
    fn qos_base(&self) -> QosLevel {
        self.qos.unwrap_or(QosLevel::DEFAULT)
    }

    /// R311y-item3 — the transport frame conduit band derived from the SINGLE priority source
    /// [`qos`](Self::qos): the priority sub-field of the packed byte, or [`Priority::DEFAULT`]
    /// when no QoS was attached. An engine reads this back so a `with_priority` (or raw
    /// `with_qos`) publish rides the matching per-priority conduit — the SAME value the app
    /// observes via `Sample.priority`, never a second source.
    ///
    /// Ungated: it reads only the always-present `qos` field plus the no_std value types
    /// [`QosLevel::priority`] / [`Priority`], so it compiles on every profile. A build without
    /// the `transport-qos` conduit split clamps the band back to DEFAULT downstream, so deriving it
    /// here is inert there.
    pub fn priority_band(&self) -> Priority {
        self.qos.map(|q| q.priority()).unwrap_or(Priority::DEFAULT)
    }

    /// Translate [`Reliability`] into the bool flag the `send_push_*` outbound API expects (it
    /// predates the typed enum), so an engine does the conversion in exactly one place.
    pub fn reliable_bool(&self) -> bool {
        matches!(self.reliability, Reliability::Reliable)
    }

    /// R233 — extract the wire-encoder-facing metadata bundle so an engine can hand it to the
    /// Push builder without the lower module learning about [`Locality`] / [`Reliability`] /
    /// [`SampleKind`] (those stay on the dispatch-time surface). Clones each owned slot — the
    /// expected publish path performs one extraction per publish call so the allocation cost is
    /// amortised against the wire frame's existing copies.
    ///
    /// R311y309 — every field is threaded through its OWN gate. The wire ENCODER already drops
    /// an un-composed field at its SSOT gate-point, so gating here is redundant for the bytes —
    /// but NOT for `qos`, and that is the point. [`PushMetadata`] is itself a consumer surface:
    /// `PushMetadata::is_express` reads the copied `qos` UNGATED, and the tokio engine feeds it to
    /// `send_network_message_qos`, where the `transport-batching` seam drains the open batch
    /// window immediately. So with `pubsub-qos` OFF, a `qos` written through the pub field
    /// produced NO wire QoS byte (correct) yet still changed the Frame count and SN sequence on
    /// the wire (wrong) — a wire-observable effect of an un-composed feature.
    ///
    /// The bundle is also what an engine's loopback leg surfaces, so the loopback carries
    /// exactly the fields the wire would compose (R311y308).
    ///
    /// `priority_band` deliberately still reads `self.qos` ungated — that is the independent
    /// `transport-qos` conduit axis (R311y307), whose real gate is the runtime-negotiated
    /// `is_qos()`, not a compile feature.
    pub fn push_metadata(&self) -> PushMetadata {
        PushMetadata {
            timestamp: gated_timestamp(self.timestamp.clone()),
            encoding: gated_encoding(self.encoding.clone()),
            source_info: gated_source_info(self.source_info.clone()),
            attachment: gated_attachment(self.attachment.clone()),
            qos: gated_qos(self.qos),
        }
    }

    /// The sample a publish on `keyexpr` of `payload` delivers to the session's OWN subscribers
    /// (`vendor/zenoh-pico/src/session/loopback.c` @ `_z_session_deliver_push_locally`):
    /// a Put or a Del on the key, with every metadata field the options carry. Shared by every
    /// engine's loopback leg, so the loopback carries what the wire would compose and no
    /// engine decides it for itself.
    ///
    /// Every field flows through its feature gate, read through [`Self::push_metadata`], the
    /// bundle the wire leg reads, so the two legs cannot gate a field differently (R311y308).
    /// Encoding is Put-only on the wire (a Del has no slot for it, as zenoh-pico's
    /// `_z_msg_del_t` has none), so a Del's loopback sample has none either.
    #[cfg(feature = "alloc")]
    pub fn loopback_sample(&self, keyexpr: &str, payload: &[u8]) -> crate::sample::Sample {
        use crate::sample::Sample;
        let mut sample = match self.kind {
            SampleKind::Put => Sample::new_put(keyexpr, payload.to_vec()),
            SampleKind::Del => Sample::new_del(keyexpr),
        };
        sample = sample.with_reliability(self.reliability);
        let meta = self.push_metadata();
        if let Some(timestamp) = meta.timestamp {
            sample = sample.with_timestamp(timestamp);
        }
        if self.kind == SampleKind::Put {
            if let Some(encoding) = meta.encoding {
                sample = sample.with_encoding(encoding);
            }
        }
        if let Some(source_info) = meta.source_info {
            sample = sample.with_source_info(source_info);
        }
        if let Some(attachment) = meta.attachment {
            sample = sample.with_attachment(attachment);
        }
        if let Some(qos) = meta.qos {
            sample = sample.with_qos(qos);
        }
        sample
    }

    /// What a Put needs to be sent when it is plain apart from its QoS, worked out once: a holder
    /// of options that stay the same for a stream of messages (a declared publisher) keeps the
    /// answer and sends each message with the engine's plain declared publish, without cloning
    /// these options and reading them again per message.
    ///
    /// `None` when the options are not a plain Put (a Del, a timestamp, an encoding, a source, an
    /// attachment), which then take the general publish. The answer holds the same facts the
    /// general publish derives from the options (`reliable_bool`, the express flag,
    /// `priority_band`), by the same code.
    ///
    /// Also `None` in a build that does not send a plain Put from borrowed bytes (it counts or
    /// rewrites the owned message, or has no Push codec): the build's one answer, so a caller
    /// never asks which features are on. A build that can ENFORCE an egress policy is not one of
    /// those: whether a put is judged is a fact about the session that sends it (the tokio
    /// engine's `Session::plain_put_lane_open`), not about the build, and answering `None` here
    /// for every such build made merely being able to enforce cost every session the fast send.
    pub fn plain_put_params(&self) -> Option<PlainPutParams> {
        #[cfg(all(
            feature = "codec-push",
            not(feature = "transport-stats"),
            not(feature = "routing-namespace")
        ))]
        {
            if self.kind != SampleKind::Put {
                return None;
            }
            let meta = self.push_metadata();
            if !meta.is_plain_apart_from_qos() {
                return None;
            }
            Some(PlainPutParams {
                destination: self.allowed_destination,
                qos: meta.qos,
                reliable: self.reliable_bool(),
                express: meta.is_express(),
                priority: self.priority_band(),
            })
        }
        #[cfg(not(all(
            feature = "codec-push",
            not(feature = "transport-stats"),
            not(feature = "routing-namespace")
        )))]
        {
            None
        }
    }
}

/// The facts a plain Put is sent from ([`PublishOptions::plain_put_params`]).
#[derive(Debug, Clone, Copy)]
pub struct PlainPutParams {
    /// Where the Put may go: the wire, this session's own subscribers, or both.
    pub destination: Locality,
    /// The QoS byte it carries, when it carries one.
    pub qos: Option<QosLevel>,
    /// The frame's reliability flag.
    pub reliable: bool,
    /// Whether it drains the open batch after it is sent.
    pub express: bool,
    /// The priority conduit it rides.
    pub priority: Priority,
}

/// W3 (SCE pin 7a94d084a) — typed reject from the literal / direct-aliased publish path (the
/// tokio engine's `Session::publish` / `Session::publish_aliased` and its `Publisher` handles).
/// These paths do not resolve the outbound mapping table (so they cannot produce
/// `UnknownMapping`), and their remote leg is `codec-push`-gated (a build without the Push codec
/// elides the leg and runs loopback only — never an error), so the single failure mode is a
/// caller-data overflow of the declared bounded-codec capacity. Distinct from that engine's
/// `PublishAliasError` (ISP): its auto-resolving `Session::publish_aliased_auto` keeps the richer
/// `UnknownMapping` surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishError {
    /// The payload or keyexpr exceeded the declared bounded-codec capacity while being copied
    /// into the no-alloc owned Push mirror — the same bound the decode path enforces — or, on
    /// the lend-only profile, the frame is past the link's budget and there is no heap to build
    /// its fragments in. No wire bytes were emitted.
    ExceedsCapacity,
    /// F2 — the transport is not currently accepting data sends (link released or reconnecting;
    /// Established not re-entered) or, on the lend-only profile, the link lent no slot to build
    /// the frame in. No wire bytes were emitted; retry after the session re-establishes or the
    /// pool refills (zenoh-pico `_Z_ERR_TRANSPORT_NOT_AVAILABLE` parity).
    TransportUnavailable,
    /// B5b-2b (R311nc) — an ALIASED publish (`publish_aliased{,_auto}`, which resolves the
    /// unicast outbound keyexpr-mapping table) was attempted on a session whose transport is not
    /// unicast. A multicast session has no outbound mapping table; the `Session::actions()`
    /// projection rejects with `SendWireError::UnsupportedVariant`, surfaced here. No wire bytes
    /// were emitted. The transport-agnostic literal `Session::publish` does NOT raise this — it
    /// routes through the send seam and runs on either transport; only the unicast-mapping
    /// aliased path does.
    RequiresUnicast,
    /// R2238 (open-debt item 580) — the session's finite fragment TX budget ran out while this
    /// publish's `T_MID_FRAGMENT` chain was being emitted, so the message was ABANDONED.
    ///
    /// ⚠ Deliberately NOT folded into [`Self::ExceedsCapacity`], which the two size bounds share
    /// because both mean "too large to send; NO WIRE BYTES EMITTED". This one breaks that second
    /// half: when the budget ran out part-way, fragments ARE on the wire and a `0x3 Drop` stop
    /// fragment followed them telling the peer to discard the prefix. A caller that read this as
    /// `ExceedsCapacity` would believe nothing left the host and could not distinguish "resend the
    /// same bytes once there is budget" (true here) from "this message can never be sent as-is"
    /// (true there).
    FragmentChainAbandoned,
}

impl core::fmt::Display for PublishError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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
            PublishError::FragmentChainAbandoned => write!(
                f,
                "PublishError: the session's fragment TX budget ran out while \
                 emitting this Push's chain, so it was abandoned — any \
                 fragments already on the wire were followed by a 0x3 Drop \
                 stop fragment; resend once the budget is refilled"
            ),
        }
    }
}

impl core::error::Error for PublishError {}

impl From<SendWireError> for PublishError {
    fn from(e: SendWireError) -> Self {
        match e {
            SendWireError::Codec(_) => PublishError::ExceedsCapacity,
            // An engine invokes its send_push_* path only inside a `codec-push`-gated block,
            // where the Push codec is present; the send therefore never reports
            // `FeatureDisabled` to this conversion. The guard documents that compile-time
            // invariant (and trips a future regression that ungates the leg).
            SendWireError::FeatureDisabled => {
                unreachable!("publish remote leg is codec-push-gated")
            }
            SendWireError::TransportUnavailable => PublishError::TransportUnavailable,
            SendWireError::UnsupportedVariant => PublishError::RequiresUnicast,
            // Both mean "too large to send; no wire bytes emitted" — one bound is the codec's,
            // the other the reassembly slot's.
            SendWireError::ExceedsReassemblyCap => PublishError::ExceedsCapacity,
            // R2238 — kept SEPARATE from the two above precisely because the "no wire bytes
            // emitted" half does not hold; see `PublishError::FragmentChainAbandoned`.
            SendWireError::FragmentTxBudgetExhausted => PublishError::FragmentChainAbandoned,
            // The lend-only profile's refusal: the link refused the frame before it was built,
            // so no bytes were emitted, and the session counted the cause (`tx_refusals`). It
            // folds into the two classes this type already distinguishes, as the codec's and
            // the reassembly slot's bounds do above, rather than adding a variant that only one
            // feature of this crate defines: an engine in another crate matches this type
            // exhaustively and cannot name that feature. A dry pool and a gone writer are
            // moments the same send may get past (the pool refills, the session re-establishes);
            // a frame past the link's budget is a message that can never be sent as it is.
            #[cfg(feature = "tx-lend-only")]
            SendWireError::LinkRefused(cause) => match cause {
                crate::link::LinkDropCause::NoTxSlot | crate::link::LinkDropCause::WriterGone => {
                    PublishError::TransportUnavailable
                }
                crate::link::LinkDropCause::Oversize => PublishError::ExceedsCapacity,
            },
        }
    }
}

/// R311y308 / R311y309 — the per-field metadata gates [`PublishOptions::push_metadata`] threads
/// each field through. Each returns the staged value only when the SAME feature the wire path
/// gates is composed, else `None`.
///
/// The parity is per-FEATURE, not per-CONTENT: a `SessionLocal` publish surfaces the same fields
/// a `Remote` one would COMPOSE, but not necessarily the same values. The wire encoder
/// additionally suppresses a DEFAULT QoS byte (`build_push_outer_extensions`, mirroring pico's
/// `has_qos_ext`), so a staged `QosLevel::DEFAULT` surfaces as `Some(DEFAULT)` on loopback and
/// `None` through a wire round-trip.
///
/// Mirrors the Reply-side idiom (`crate::reply::loopback_put_attachment` /
/// `loopback_put_encoding`). Before R311y308 the loopback copied all five metadata fields
/// UNGATED, so with e.g. `pubsub-timestamp` off a `PublishOptions.timestamp` written through the
/// pub field (the gated `with_timestamp` setter is absent, but `#[non_exhaustive]` blocks only
/// struct-literal construction, not field assignment) reached the loopback `Sample` — falsifying
/// the manifest's "Feature-off: nothing is set nor written". R311y309 then routed the wire leg's
/// bundle through the same gates, which is what makes the inert claim true for both legs; the
/// wire encoder's three SSOT points (`gated_timestamp_field` / `gated_encoding_field` /
/// `build_body_extensions`) remain the byte-level backstop.
macro_rules! metadata_gated {
    ($name:ident, $feat:literal, $ty:ty) => {
        fn $name(v: Option<$ty>) -> Option<$ty> {
            #[cfg(feature = $feat)]
            {
                v
            }
            #[cfg(not(feature = $feat))]
            {
                let _ = v;
                None
            }
        }
    };
}

metadata_gated!(gated_timestamp, "pubsub-timestamp", TimestampHint);
metadata_gated!(gated_encoding, "pubsub-encoding", EncodingHint);
metadata_gated!(gated_source_info, "pubsub-source-info", SourceInfo);
metadata_gated!(gated_attachment, "pubsub-attachment", Vec<u8>);
metadata_gated!(gated_qos, "pubsub-qos", QosLevel);
