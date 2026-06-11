// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Publisher handle cluster split out of `session/mod.rs` (pure
//! refactor): [`PublishOptions`], the [`Publisher`] /
//! [`PublisherAliased`] handles, [`PublishError`],
//! [`PublishAliasError`], and the shared `build_loopback_sample`
//! helper. The parent module re-exports the public types via
//! `pub use publisher::*;` so the path
//! `wz_runtime_tokio::session::Publisher` etc. is unchanged.

use super::*;

/// Options bundle for [`Session::publish`]. Carries the locality
/// routing predicate (`allowed_destination`), the reliability hint
/// for the wire frame and the loopback `Sample.reliability` field,
/// and the [`SampleKind`] discriminator that selects Put vs Del
/// dispatch.
///
/// Construct via [`PublishOptions::put`] / [`PublishOptions::del`]
/// plus optional `with_*` setters; defaults to a Put publish that
/// fans both branches (`Locality::Any`) with `Reliability::Reliable`
/// matching zenoh-pico's `Z_RELIABILITY_DEFAULT`.
///
/// Future-additive: this struct is `#[non_exhaustive]` so R229+ can
/// add metadata fields (`qos`, `attachment`, `timestamp`, `encoding`,
/// `source_info`) without breaking external callers when the wire-side
/// `send_push_literal` learns to accept them. Construct through the
/// builder API rather than struct-literal so the future-additive
/// contract holds.
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
    /// loopback `Sample.reliability` field. Default: `Reliable`.
    pub reliability: Reliability,
    /// Sample discriminator. `Put` carries the caller payload; `Del`
    /// carries an empty payload (the keyexpr is the entire payload).
    /// Default: `Put`.
    pub kind: SampleKind,
    /// R232 — body-level timestamp propagated to subscribers via
    /// `Sample.timestamp`. On the loopback branch the value lands
    /// verbatim. On the wire branch the value will encode into the
    /// `MsgPut`/`MsgDel` body (R233 carry — current wire branch drops
    /// this field). `None` (default) means no timestamp attached.
    pub timestamp: Option<TimestampHint>,
    /// R232 — body-level encoding propagated to Put-kind subscribers
    /// via `Sample.encoding`. Del-kind ignores this field (zenoh-pico
    /// `_z_msg_del_t` has no encoding slot). Wire-side propagation is
    /// the R233 carry; loopback honours it from R232.
    pub encoding: Option<EncodingHint>,
    /// R232 — body-level source identification propagated to
    /// `Sample.source_info`. Cooperates with the R231 self-echo dedup:
    /// when the dispatcher fires on a wire-arrived Push whose
    /// `source_info.zid` matches the session's own zid, the dedup
    /// suppresses the duplicate fire so a `Locality::Any` publish only
    /// invokes any-locality subscribers once. Wire-side propagation is
    /// the R233 carry; loopback honours it from R232.
    pub source_info: Option<SourceInfo>,
    /// R232 — body-level attachment blob propagated to
    /// `Sample.attachment`. Wire-side propagation is the R233 carry;
    /// loopback honours it from R232.
    pub attachment: Option<Vec<u8>>,
    /// R232 — outer-level QoS metadata propagated to `Sample.qos`.
    /// zenoh-pico mirror: the Push outer `_Z_MSG_EXT_ENC_ZINT | 0x01`
    /// extension carrying priority + congestion-control + express
    /// packed into one byte. Wire-side propagation is the R233 carry;
    /// loopback honours it from R232.
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
    /// to [`Session::publish`] is ignored for Del kind (zenoh-pico
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

    /// R232 — attach a body-level timestamp. The loopback branch
    /// propagates this into `Sample.timestamp` for the subscriber
    /// callback. Wire-side propagation lands in R233.
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

    /// Translate [`Reliability`] into the bool flag the legacy
    /// `send_push_*` outbound API expects (it predates the typed
    /// enum). Exposed inside the crate so [`Session::publish`] does
    /// the conversion in exactly one place.
    ///
    /// W3 — `codec-push`-gated: the sole callers are the
    /// `codec-push`-gated remote legs of [`Session::publish`] /
    /// [`Session::publish_aliased`], so the helper is dead weight on a
    /// build without the Push codec.
    #[cfg(feature = "codec-push")]
    pub(super) fn reliable_bool(&self) -> bool {
        matches!(self.reliability, Reliability::Reliable)
    }

    /// R233 — extract the wire-encoder-facing metadata bundle from a
    /// PublishOptions instance so [`Session::publish`] can hand it
    /// to [`crate::session_glue::SessionLinkActions::send_push_with_meta_literal`]
    /// without the lower module learning about
    /// [`Locality`] / [`Reliability`] / [`SampleKind`] (those stay
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

/// R244 — reusable publish target with pre-set keyexpr + options.
/// Pub-side mirror of [`Querier`]. A caller declares the publisher
/// once ([`Session::declare_publisher`]) and emits repeated
/// outbound `Push` records through [`Self::put`] / [`Self::delete`]
/// without restating the keyexpr or options on every call.
///
/// `Clone` is cheap (Arc-backed Session + value-clone of
/// PublishOptions). Background tasks can hold per-task Publisher
/// clones; all clones share the same observer + actions handle so
/// loopback dispatches still reach the main drive_session loop.
///
/// `#[non_exhaustive]`. Construct only through
/// [`Session::declare_publisher`].
///
/// Mirrors zenoh-pico's `z_publisher_t`
/// (`vendor/zenoh-pico/include/zenoh-pico/api/types.h`) with
/// `z_declare_publisher` + `z_publisher_put` + `z_publisher_delete`.
// R311cs — R267 helper cascade. Manual Clone impl mirrors Querier
// pattern (no derive auto-added R: Clone bound on Runtime).
#[non_exhaustive]
pub struct Publisher<R: SessionRuntime = TokioRuntime, T: TimeSource = TokioTime> {
    pub(super) session: Session<R, T>,
    pub(super) keyexpr: String,
    pub(super) options: PublishOptions,
}

impl<R: SessionRuntime, T: TimeSource> Clone for Publisher<R, T> {
    fn clone(&self) -> Self {
        Self {
            session: self.session.clone(),
            keyexpr: self.keyexpr.clone(),
            options: self.options.clone(),
        }
    }
}

impl<R: SessionRuntime, T: TimeSource> Publisher<R, T> {
    /// Borrow the declared keyexpr.
    pub fn keyexpr(&self) -> &str {
        &self.keyexpr
    }

    /// Borrow the declared options.
    pub fn options(&self) -> &PublishOptions {
        &self.options
    }

    /// Emit one outbound Put through the declared keyexpr + options.
    /// Returns the loopback fire count (number of matching local
    /// subscribers that fired), matching [`Session::publish`]'s
    /// return contract.
    ///
    /// Per-call `opts.kind` is overridden to [`SampleKind::Put`] —
    /// the declared options retain the caller's reliability /
    /// locality / metadata choices; only the discriminator that
    /// selects put vs delete is overridden by the call shape.
    pub fn put(&self, payload: &[u8]) -> Result<usize, PublishError> {
        let mut opts = self.options.clone();
        opts.kind = SampleKind::Put;
        self.session.publish(&self.keyexpr, payload, opts)
    }

    /// Emit one outbound Del (delete-keyexpr signal) through the
    /// declared keyexpr + options. Payload is the empty slice (Del
    /// kind carries none on the wire — `MsgDel` body has no payload
    /// slot per zenoh-pico `_z_msg_del_t`).
    ///
    /// Per-call `opts.kind` is overridden to [`SampleKind::Del`].
    pub fn delete(&self) -> Result<usize, PublishError> {
        let mut opts = self.options.clone();
        opts.kind = SampleKind::Del;
        self.session.publish(&self.keyexpr, &[], opts)
    }

    /// R290 — pub-side mirror of [`Querier::get_matching_status`].
    /// Mirror of zenoh-pico's `z_publisher_get_matching_status`
    /// (`vendor/zenoh-pico/src/api/api.c`): returns a
    /// [`MatchingStatus`] whose `matching` field is `true` iff at
    /// least one peer has currently declared a subscriber whose
    /// keyexpr matches the publisher's keyexpr.
    ///
    /// Consults
    /// [`crate::declare::RemoteSubscriberRegistry::has_matching`]
    /// inside the session's observer (the registry tracks the
    /// `{peer_decl_id -> resolved keyexpr}` membership maintained
    /// by the drive_session loop dispatch of inbound
    /// `Declare(DeclSubscriber)` / `Declare(UndeclSubscriber)`
    /// records). Lock contention is the single observer mutex held
    /// briefly to consult the membership; no wire frame is emitted.
    ///
    /// Match algorithm is the same bidirectional asymmetric pattern-
    /// match approximation used by [`Querier::get_matching_status`]
    /// — see that doc-comment for the boundary description and the
    /// R291 honest-intersection carry.
    ///
    /// R310.5c — the method signature is always visible whenever
    /// `Publisher` exists (always, since `Publisher` has no cfg
    /// gate), preserving zenoh-cpp API parity. The body branches on
    /// `feature = "declare-subscriber"`: when the
    /// `RemoteSubscriberRegistry` observer field is elided (the
    /// feature is off), the method conservatively returns
    /// `MatchingStatus { matching: false }` rather than disappearing
    /// from the surface. R310 previously gated the entire signature
    /// on `declare-subscriber`, which broke the zenoh-cpp parity
    /// (consumers had to themselves cfg-gate every call site).
    pub fn get_matching_status(&self) -> MatchingStatus {
        // R311dd — observer access via R::with_mutex_mut closure form.
        #[cfg(feature = "declare-subscriber")]
        let matching = R::with_mutex_mut(&self.session.observer, |obs| {
            obs.remote_subscribers.has_matching(&self.keyexpr)
        });
        #[cfg(not(feature = "declare-subscriber"))]
        let matching = false;
        MatchingStatus { matching }
    }

    /// R311kh — callback counterpart of [`Self::get_matching_status`]
    /// (zenoh-pico `z_publisher_declare_matching_listener`,
    /// `Z_FEATURE_MATCHING`): `callback` fires on every matching-status
    /// TRANSITION of this publisher's keyexpr against the remote
    /// subscriber set — a remote `DeclSubscriber` whose keyexpr starts
    /// intersecting flips it `true`, the matching `UndeclSubscriber`
    /// flips it back. Registration itself never fires (pico
    /// transition-only; poll [`Self::get_matching_status`] for the
    /// current value, which also seeds the watch baseline).
    ///
    /// R311kz — DEFERRED FIRE (the F-6 fix; supersedes the R311kj
    /// callback constraint): the registry-installed sink only STAGES
    /// the transition onto the session's deferred-fire queue, and the
    /// drive loop's [`Session::drain_deferred_fires`] runs `callback`
    /// AFTER the observer lock drops. The callback may therefore call
    /// any observer-locking session API — `get_matching_status`,
    /// declares, further listener registration, even its own handle's
    /// `undeclare` — without self-deadlocking. Transitions arrive in
    /// stage order; a transition staged before `undeclare` but drained
    /// after it is suppressed. A custom drive closure that dispatches
    /// this session's observer directly must pair each dispatch with a
    /// `drain_deferred_fires()` call or deferred listeners starve.
    ///
    /// R310.5c / R311g1 — the signature is always visible; the body
    /// rejects typed (`Err(FeatureDisabled)`) when `session-matching`
    /// or the backing `declare-subscriber` registry is off.
    pub fn declare_matching_listener(
        &self,
        callback: impl FnMut(MatchingStatus) + Send + 'static,
    ) -> Result<MatchingListener<R, T>, MatchingListenerError> {
        #[cfg(all(feature = "session-matching", feature = "declare-subscriber"))]
        {
            use super::matching_listener::{BoxedMatchingCallback, MatchingListenerCell};
            let erased: BoxedMatchingCallback = Box::new(callback);
            let cell: MatchingListenerCell<R> =
                wz_session_core::deferred_fire::DeferredListenerCell::new(erased);
            let queue = self.session.fires.clone();
            let cell_for_sink = cell.clone();
            let sink = wz_session_core::declare::matching::BoxedMatchingSink::new(move |m| {
                let cell = cell_for_sink.clone();
                queue.stage(Box::new(move || {
                    cell.invoke(|cb| cb(MatchingStatus { matching: m }));
                }));
            });
            let id = R::with_mutex_mut(&self.session.observer, |obs| {
                obs.remote_subscribers
                    .declare_matching_listener(&self.keyexpr, sink)
            });
            Ok(MatchingListener {
                session: self.session.clone(),
                id,
                scope: MatchingScope::RemoteSubscribers,
                cell,
            })
        }
        #[cfg(not(all(feature = "session-matching", feature = "declare-subscriber")))]
        {
            let _ = callback;
            Err(MatchingListenerError::FeatureDisabled)
        }
    }
}

/// R244 — aliased-keyexpr counterpart of [`Publisher`]. Holds
/// `(mapping_id, inline_suffix, options)` so subsequent [`Self::put`]
/// / [`Self::delete`] calls route through
/// [`Session::publish_aliased_auto`] which resolves the loopback
/// literal through the outbound mapping table.
///
/// Returns `Err(PublishAliasError::UnknownMapping(id))` from
/// [`Self::put`] / [`Self::delete`] when the declared mapping id
/// was never registered (or was retracted via
/// [`SessionLinkActions::send_undeclare_kexpr`]). Mirror of
/// [`QuerierAliased`] on the pub side.
///
/// `#[non_exhaustive]`. Construct only through
/// [`Session::declare_publisher_aliased`].
// R311cs — R267 helper cascade. Manual Clone impl mirrors Querier
// pattern (no derive auto-added R: Clone bound on Runtime).
#[non_exhaustive]
pub struct PublisherAliased<R: SessionRuntime = TokioRuntime, T: TimeSource = TokioTime> {
    pub(super) session: Session<R, T>,
    pub(super) mapping_id: u64,
    pub(super) inline_suffix: Option<String>,
    pub(super) options: PublishOptions,
}

impl<R: SessionRuntime, T: TimeSource> Clone for PublisherAliased<R, T> {
    fn clone(&self) -> Self {
        Self {
            session: self.session.clone(),
            mapping_id: self.mapping_id,
            inline_suffix: self.inline_suffix.clone(),
            options: self.options.clone(),
        }
    }
}

impl<R: SessionRuntime, T: TimeSource> PublisherAliased<R, T> {
    /// The declared mapping id.
    pub fn mapping_id(&self) -> u64 {
        self.mapping_id
    }

    /// The optional inline suffix (composite-aliased keyexpr).
    pub fn inline_suffix(&self) -> Option<&str> {
        self.inline_suffix.as_deref()
    }

    /// Borrow the declared options.
    pub fn options(&self) -> &PublishOptions {
        &self.options
    }

    /// Emit one outbound Put through the aliased mapping. Returns
    /// `Err(PublishAliasError::UnknownMapping(id))` when the declared
    /// `mapping_id` is no longer present on the outbound mapping
    /// table — neither wire nor loopback branch fires.
    pub fn put(&self, payload: &[u8]) -> Result<usize, PublishAliasError> {
        let mut opts = self.options.clone();
        opts.kind = SampleKind::Put;
        self.session.publish_aliased_auto(
            self.mapping_id,
            self.inline_suffix.as_deref(),
            payload,
            opts,
        )
    }

    /// Emit one outbound Del through the aliased mapping. Returns
    /// `Err(PublishAliasError::UnknownMapping(id))` on mapping
    /// absence per [`Self::put`]'s contract.
    pub fn delete(&self) -> Result<usize, PublishAliasError> {
        let mut opts = self.options.clone();
        opts.kind = SampleKind::Del;
        self.session
            .publish_aliased_auto(self.mapping_id, self.inline_suffix.as_deref(), &[], opts)
    }

    /// R290 — aliased-keyexpr counterpart of
    /// [`Publisher::get_matching_status`]. Mirrors
    /// [`QuerierAliased::get_matching_status`] on the pub side:
    /// resolves the declared `mapping_id` through the outbound
    /// keyexpr table, composes the optional `inline_suffix` to the
    /// effective keyexpr, and consults
    /// [`crate::declare::RemoteSubscriberRegistry::has_matching`].
    /// Returns `Err(PublishAliasError::UnknownMapping(id))` when
    /// the declared `mapping_id` is not present on the outbound
    /// mapping table — same contract as [`Self::put`] /
    /// [`Self::delete`], mirroring the declare-before-publish
    /// invariant for the matching-status consult path.
    ///
    /// R310.5c — same shape pattern as
    /// [`Publisher::get_matching_status`] /
    /// [`QuerierAliased::get_matching_status`]: signature always
    /// visible, body branches on `feature = "declare-subscriber"`.
    /// The `UnknownMapping(id)` validation always fires (callers
    /// still see the declare-before-publish invariant); only the
    /// actual registry consult is skipped when the feature is off,
    /// yielding `Ok(MatchingStatus { matching: false })` on the
    /// success path.
    pub fn get_matching_status(&self) -> Result<MatchingStatus, PublishAliasError> {
        let base = self
            .session
            .actions()
            .resolve_outbound_mapping(self.mapping_id)
            .ok_or(PublishAliasError::UnknownMapping(self.mapping_id))?;
        let _effective_keyexpr = match self.inline_suffix.as_deref() {
            None => base,
            Some(s) => {
                let mut composed = base;
                composed.push_str(s);
                composed
            }
        };
        // R311dd — observer access via R::with_mutex_mut closure form.
        #[cfg(feature = "declare-subscriber")]
        let matching = R::with_mutex_mut(&self.session.observer, |obs| {
            obs.remote_subscribers.has_matching(&_effective_keyexpr)
        });
        #[cfg(not(feature = "declare-subscriber"))]
        let matching = false;
        Ok(MatchingStatus { matching })
    }
}

/// R234 — typed error returned by
/// [`Session::publish_aliased_auto`] when the requested mapping id
/// was never declared on this session's outbound link (or was
/// retracted via [`SessionLinkActions::send_undeclare_kexpr`]). The
/// caller's contract is "declare before publish"; this enum names
/// the violation explicitly so a buggy caller does not silently
/// emit wire frames the peer will reject + run loopback on a
/// guessed literal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishAliasError {
    /// No prior `send_declare_keyexpr` registered this id on the
    /// outbound mapping table (or a later `send_undeclare_kexpr`
    /// retracted it). The wrapped value is the offending mapping id.
    UnknownMapping(u64),
    /// W3 (SCE pin 7a94d084a) — the payload or resolved keyexpr
    /// exceeded the declared bounded-codec capacity while being copied
    /// into the no-alloc owned Push mirror, so no wire bytes were
    /// emitted (projected from the underlying [`PublishError`]).
    ExceedsCapacity,
    /// F2 — the transport is not currently accepting data sends (link
    /// released or reconnecting; Established not re-entered); projected
    /// from the underlying [`PublishError::TransportUnavailable`].
    TransportUnavailable,
}

impl std::fmt::Display for PublishAliasError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PublishAliasError::UnknownMapping(id) => write!(
                f,
                "PublishAliasError: mapping id {id} not present in outbound table; \
                 call SessionLinkActions::send_declare_keyexpr({id}, …) first"
            ),
            PublishAliasError::ExceedsCapacity => write!(
                f,
                "PublishAliasError: payload or keyexpr exceeded the declared codec \
                 capacity; the Push was not emitted"
            ),
            PublishAliasError::TransportUnavailable => write!(
                f,
                "PublishAliasError: transport not available (link released or \
                 reconnecting); the Push was not emitted — retry after the \
                 session re-establishes"
            ),
        }
    }
}

impl std::error::Error for PublishAliasError {}

impl From<PublishError> for PublishAliasError {
    fn from(e: PublishError) -> Self {
        match e {
            PublishError::ExceedsCapacity => PublishAliasError::ExceedsCapacity,
            PublishError::TransportUnavailable => PublishAliasError::TransportUnavailable,
        }
    }
}

/// W3 (SCE pin 7a94d084a) — typed reject from the literal /
/// direct-aliased publish path ([`Session::publish`] /
/// [`Session::publish_aliased`] and the [`Publisher`] handles). These
/// paths do not resolve the outbound mapping table (so they cannot
/// produce `UnknownMapping`), and their remote leg is
/// `codec-push`-gated (a build without the Push codec elides the leg
/// and runs loopback only — never an error), so the single failure
/// mode is a caller-data overflow of the declared bounded-codec
/// capacity. Distinct from [`PublishAliasError`] (ISP): the
/// auto-resolving [`Session::publish_aliased_auto`] keeps the richer
/// `UnknownMapping` surface.
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
        }
    }
}

/// R232 — shared loopback Sample assembly for [`Session::publish`] and
/// [`Session::publish_aliased`]. Constructs a Put or Del Sample on the
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
