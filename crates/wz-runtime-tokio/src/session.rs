// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R228 — application-level [`Session`] bundle.
//!
//! [`Session`] owns the outbound action handle ([`SessionLinkActions`])
//! and a shared reference to the inbound observer
//! ([`ApplicationLayerObserver`]) so a single [`Session::publish`] call
//! routes through both the wire-side codec and the in-process
//! subscriber loopback. Mirrors zenoh-pico's `_z_session_t`, which
//! similarly owns both the transport handle and the local subscription
//! table (`vendor/zenoh-pico/include/zenoh-pico/net/session.h` 172,
//! `vendor/zenoh-pico/src/net/primitives.c::_z_write` 170-205 fans the
//! outbound publish across `allows_remote()` / `allows_local()` from a
//! single entry point).
//!
//! ## Scope (R228 minimum-viable)
//!
//! * [`Session::publish`] handles literal-keyexpr Put + Del. Aliased
//!   (`mapping_id != 0`) publish is an R229 carry — the symmetric
//!   counterpart to [`crate::session_glue::SessionLinkActions::send_push_aliased`]
//!   will land as `publish_aliased` once a use case surfaces.
//! * [`PublishOptions`] carries the three load-bearing knobs
//!   (`allowed_destination`, `reliability`, `kind`). The remaining
//!   five [`crate::sample::Sample`] body fields (`qos`, `attachment`,
//!   `timestamp`, `encoding`, `source_info`) are R229+ carries —
//!   the wire path's `send_push_literal` currently does not accept
//!   them either, so propagating them through `Session::publish`
//!   would surface an asymmetry between the wire branch (loses the
//!   metadata) and the loopback branch (preserves it).
//! * `Session` is a NEW public surface introduced in parallel with
//!   the legacy direct-`SessionLinkActions` + direct-`ApplicationLayerObserver`
//!   pattern that `wz-ap-demo` and the integration suite still use.
//!   R230+ carry: migrate `wz-ap-demo` to `Session` and route every
//!   subscriber registration through `Session::observer().lock()`
//!   instead of directly on `observer.subscribers`.
//!
//! ## Locking discipline
//!
//! The observer is wrapped in [`std::sync::Mutex`] (not
//! [`tokio::sync::Mutex`]) because the loopback branch runs the
//! subscriber callbacks synchronously — exactly the semantic of a
//! locally-published Sample under zenoh-pico's
//! `_z_session_deliver_push_locally`
//! (`vendor/zenoh-pico/src/session/loopback.c` 70-100) which fires
//! the subscription callbacks in-line under the session lock. A
//! `tokio::sync::Mutex` would force `publish` to be `async`, which
//! would in turn force callers to be `async`, propagating a
//! coloring change for no measurable benefit — the lock window is
//! the time it takes to walk the subscriber table once.
//!
//! ## Wire / loopback symmetry today (R228) vs zenoh-pico
//!
//! zenoh-pico's `_z_write` constructs the same [`crate::sample::Sample`]-
//! shaped record once and routes both branches off the same record.
//! wz at R228 constructs the wire-side `Push` via the legacy
//! `send_push_literal` / `send_push_del_literal` builders AND
//! constructs the loopback-side `Sample` via the `new_put` / `new_del`
//! builder — two separate constructions. R229+ candidate: unify the
//! construction so both branches read the same source struct (an
//! intermediate `PublishRecord` that the wire side encodes and the
//! loopback side projects to `Sample`).

use std::sync::{Arc, Mutex};

use crate::locality::Locality;
use crate::observer::ApplicationLayerObserver;
use crate::sample::{
    EncodingHint, QosLevel, Reliability, Sample, SampleKind, SourceInfo, TimestampHint,
};
use crate::session_glue::{PushMetadata, SessionLinkActions};

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
    pub fn with_timestamp(mut self, timestamp: TimestampHint) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    /// R232 — attach a body-level encoding (Put kind only; Del kind
    /// ignores the field per zenoh-pico `_z_msg_del_t` layout).
    pub fn with_encoding(mut self, encoding: EncodingHint) -> Self {
        self.encoding = Some(encoding);
        self
    }

    /// R232 — attach a body-level source identification. Pairs with
    /// the R231 self-echo dedup: when the wire receives a publish
    /// whose `source_info.zid` matches the session's own zid, the
    /// dispatch suppresses to avoid double-firing local subscribers
    /// in mesh / router-echo topologies.
    pub fn with_source_info(mut self, source_info: SourceInfo) -> Self {
        self.source_info = Some(source_info);
        self
    }

    /// R232 — attach a body-level attachment blob.
    pub fn with_attachment(mut self, attachment: Vec<u8>) -> Self {
        self.attachment = Some(attachment);
        self
    }

    /// R232 — attach outer-level QoS metadata (priority / congestion
    /// control / express byte). Mirrors zenoh-pico's
    /// `_Z_MSG_EXT_ENC_ZINT | 0x01` Push outer extension.
    pub fn with_qos(mut self, qos: QosLevel) -> Self {
        self.qos = Some(qos);
        self
    }

    /// Translate [`Reliability`] into the bool flag the legacy
    /// `send_push_*` outbound API expects (it predates the typed
    /// enum). Exposed inside the crate so [`Session::publish`] does
    /// the conversion in exactly one place.
    fn reliable_bool(&self) -> bool {
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
    fn push_metadata(&self) -> PushMetadata {
        PushMetadata {
            timestamp: self.timestamp.clone(),
            encoding: self.encoding.clone(),
            source_info: self.source_info.clone(),
            attachment: self.attachment.clone(),
            qos: self.qos,
        }
    }
}

/// Application-level session bundle. Owns the outbound action handle
/// plus a shared reference to the inbound observer so a single call
/// to [`Session::publish`] routes both branches per the
/// `allowed_destination` predicate on [`PublishOptions`].
///
/// See module-level docs for the wire / loopback symmetry contract,
/// the locking discipline, and the R228 → R229+ carry map.
pub struct Session {
    /// Outbound action handle. Cloned `Arc` — multiple `Session`s
    /// can share the same actions if the application binds several
    /// publish surfaces to the same physical session.
    actions: Arc<SessionLinkActions>,
    /// Inbound observer wrapped in [`Mutex`] so [`Session::publish`]'s
    /// loopback branch can borrow the subscriber registry through
    /// the same handle the main dispatch loop uses.
    observer: Arc<Mutex<ApplicationLayerObserver>>,
}

impl Session {
    /// Construct a new session bundle from existing handles.
    /// `actions` typically comes from
    /// [`SessionLinkActions::new`](crate::session_glue::SessionLinkActions::new);
    /// `observer` is a freshly-wrapped
    /// [`ApplicationLayerObserver::new`](crate::observer::ApplicationLayerObserver::new).
    pub fn new(
        actions: Arc<SessionLinkActions>,
        observer: Arc<Mutex<ApplicationLayerObserver>>,
    ) -> Self {
        Self { actions, observer }
    }

    /// Borrow the outbound action handle. Useful when the caller
    /// needs to invoke non-publish methods like `send_declare_*` or
    /// `send_request_query` directly on the actions surface.
    pub fn actions(&self) -> &Arc<SessionLinkActions> {
        &self.actions
    }

    /// Borrow the observer handle. Application code registers
    /// callbacks on the contained registries through this — typically
    /// `session.observer().lock().unwrap().subscribers.register(...)`.
    pub fn observer(&self) -> &Arc<Mutex<ApplicationLayerObserver>> {
        &self.observer
    }

    /// R231 — forward this session's own zid (1..=16 bytes) to the
    /// inbound subscriber registry so wire-arrived self-echoes (a
    /// `Locality::Any` publish that the network routes back to its
    /// publisher) are recognised by
    /// [`crate::pubsub::SubscriberRegistry::dispatch_push`] and
    /// suppressed before the local callback fires a second time.
    ///
    /// Returns `true` when the registry accepted the install,
    /// `false` when `zid.len()` was outside `1..=16` (the wire-form
    /// `_z_id_t` range) — an invalid length is a hard reject so a
    /// buggy caller cannot accidentally silence dedup with a
    /// length-0 or length-17 input.
    ///
    /// Production deployment path: the session-FSM open handshake
    /// settles with both peers' zids known
    /// (`SessionInitParams.zid` is the local zid passed into
    /// outbound `InitSyn`; the peer's zid lands in
    /// [`crate::session_glue::SessionLinkActions::inbound_peer_zid`]).
    /// Once the handshake completes, the application calls this
    /// method with the local zid and the dedup activates. The
    /// auto-wire from a session-FSM completion event is an R232+
    /// carry — today the wiring is caller-driven so the surface
    /// stays additive (no breakage to callers that never enable
    /// dedup; the absence remains a safe default).
    pub fn set_own_zid(&self, zid: Vec<u8>) -> bool {
        let mut observer = self
            .observer
            .lock()
            .expect("ApplicationLayerObserver mutex poisoned");
        observer.subscribers.set_own_zid(zid)
    }

    /// R231 — release the previously-installed own zid (paired with
    /// [`Session::set_own_zid`]). After clear, every wire-arrived
    /// Push fires its matching subscribers; the self-echo guard
    /// stays disabled until a fresh `set_own_zid` install. Useful
    /// in session re-init / close scenarios where the prior zid
    /// must not bleed into a new session's dispatch state.
    pub fn clear_own_zid(&self) {
        let mut observer = self
            .observer
            .lock()
            .expect("ApplicationLayerObserver mutex poisoned");
        observer.subscribers.clear_own_zid();
    }

    /// Publish a literal-keyexpr Sample. Routes both branches per
    /// `opts.allowed_destination`:
    ///
    /// * [`Locality::allows_remote`] → wire send via
    ///   [`SessionLinkActions::send_push_literal`] (Put) or
    ///   [`SessionLinkActions::send_push_del_literal`] (Del). The
    ///   `payload` is ignored on Del kind.
    /// * [`Locality::allows_local`] → loopback dispatch via
    ///   [`crate::pubsub::SubscriberRegistry::local_publish`] with a
    ///   newly-built [`Sample`] carrying `keyexpr` / `payload` /
    ///   `opts.kind` / `opts.reliability` plus every metadata field
    ///   the caller attached via `opts.with_*` (R232 — timestamp /
    ///   encoding / source_info / attachment / qos).
    ///
    /// Returns the number of subscriber callbacks the loopback branch
    /// fired (0 if `allows_local()` is false OR no subscribers match
    /// the keyexpr). Wire-branch outcomes are not reported through
    /// this return value — fire-and-forget per
    /// [`SessionLinkActions::send_push_literal`]'s shape.
    ///
    /// ## R233 — wire-side metadata parity
    ///
    /// The wire branch routes through
    /// [`SessionLinkActions::send_push_with_meta_literal`] /
    /// [`SessionLinkActions::send_push_del_with_meta_literal`],
    /// threading every caller-set [`PublishOptions`] metadata field
    /// (timestamp, encoding, source_info, attachment, qos) onto the
    /// outbound `MsgPut`/`MsgDel` so the peer's
    /// `_z_trigger_subscriptions_impl` projects the same
    /// `_z_sample_t` shape the loopback branch projects in-process.
    /// Encoding is dropped silently for Del kind (mirrors
    /// `_z_msg_del_t`'s missing encoding slot); the loopback path
    /// applies the same projection in
    /// [`build_loopback_sample`].
    ///
    /// Mirrors zenoh-pico's `_z_write` `vendor/zenoh-pico/src/net/primitives.c`
    /// 170-205: wire branch under `allows_remote()`, loopback branch
    /// under `allows_local()`. Both branches run when
    /// `Locality::Any` (the default) and the publisher's intent is
    /// "fan to every receiver, in-process and remote".
    pub fn publish(
        &self,
        keyexpr: &str,
        payload: &[u8],
        opts: PublishOptions,
    ) -> usize {
        let reliable = opts.reliable_bool();
        if opts.allowed_destination.allows_remote() {
            let meta = opts.push_metadata();
            match opts.kind {
                SampleKind::Put => {
                    self.actions
                        .send_push_with_meta_literal(keyexpr, payload, reliable, &meta);
                }
                SampleKind::Del => {
                    self.actions
                        .send_push_del_with_meta_literal(keyexpr, reliable, &meta);
                }
            }
        }
        if opts.allowed_destination.allows_local() {
            let sample = build_loopback_sample(keyexpr, payload, &opts);
            self.observer
                .lock()
                .expect("Session observer mutex poisoned — a subscriber callback panicked")
                .subscribers
                .local_publish(&sample)
        } else {
            0
        }
    }

    /// R229 — aliased-keyexpr counterpart of [`Session::publish`].
    /// Routes the wire branch through
    /// [`SessionLinkActions::send_push_aliased`] (Put) or
    /// [`SessionLinkActions::send_push_del_aliased`] (Del) so the
    /// peer resolves the keyexpr through its inbound mapping table
    /// (populated by an earlier
    /// [`SessionLinkActions::send_declare_keyexpr`] from this side),
    /// and routes the loopback branch through the same
    /// [`crate::pubsub::SubscriberRegistry::local_publish`] as
    /// [`Session::publish`] using `loopback_keyexpr` as the resolved
    /// literal form.
    ///
    /// `inline_suffix = None` emits a pure-aliased Push (the declared
    /// literal is the full keyexpr). `inline_suffix = Some(s)` emits
    /// a composite Push (declared prefix + `s`) — the wire branch
    /// passes the pair through to the peer as-is; the loopback branch
    /// trusts `loopback_keyexpr` to already be the resolved form
    /// (typically `<declared prefix> + s`).
    ///
    /// ## Caller precondition
    ///
    /// `loopback_keyexpr` MUST equal the literal form the peer would
    /// resolve `(mapping_id, inline_suffix)` to through its inbound
    /// mapping table. Typical usage:
    ///
    /// 1. `session.actions().send_declare_keyexpr(7, "home/temp")` —
    ///    registers `7 -> "home/temp"` on the peer.
    /// 2. `session.publish_aliased(7, None, "home/temp", payload, opts)`
    ///    — wire carries `(id=7, suffix=None)`; loopback fires on the
    ///    literal `"home/temp"`.
    /// 3. `session.publish_aliased(7, Some("/kitchen"), "home/temp/kitchen", payload, opts)`
    ///    — wire carries `(id=7, suffix="/kitchen")`; loopback fires
    ///    on `"home/temp/kitchen"`.
    ///
    /// A wz-side outbound mapping table that auto-resolves the
    /// `loopback_keyexpr` from `(mapping_id, inline_suffix)` is an
    /// R230+ carry; until that lands, the caller's assertion is the
    /// single source of truth for the loopback literal.
    ///
    /// Returns the number of loopback subscriber callbacks that
    /// fired, same as [`Session::publish`].
    ///
    /// Mirrors zenoh-pico's `_z_write` with a `_z_declared_keyexpr_t`
    /// carrying both the aliased pair and the resolved literal —
    /// zenoh-pico embeds both forms in one type
    /// (`vendor/zenoh-pico/include/zenoh-pico/session/resource.h`),
    /// the wz R229 surface separates them for now since wz lacks the
    /// outbound mapping table that would produce them as a pair.
    pub fn publish_aliased(
        &self,
        mapping_id: u64,
        inline_suffix: Option<&str>,
        loopback_keyexpr: &str,
        payload: &[u8],
        opts: PublishOptions,
    ) -> usize {
        let reliable = opts.reliable_bool();
        if opts.allowed_destination.allows_remote() {
            let meta = opts.push_metadata();
            match opts.kind {
                SampleKind::Put => {
                    self.actions.send_push_with_meta_aliased(
                        mapping_id,
                        inline_suffix,
                        payload,
                        reliable,
                        &meta,
                    );
                }
                SampleKind::Del => {
                    self.actions.send_push_del_with_meta_aliased(
                        mapping_id,
                        inline_suffix,
                        reliable,
                        &meta,
                    );
                }
            }
        }
        if opts.allowed_destination.allows_local() {
            let sample = build_loopback_sample(loopback_keyexpr, payload, &opts);
            self.observer
                .lock()
                .expect("Session observer mutex poisoned — a subscriber callback panicked")
                .subscribers
                .local_publish(&sample)
        } else {
            0
        }
    }

    /// R234 — auto-resolved counterpart of [`Self::publish_aliased`].
    /// Looks up `mapping_id` in the outbound keyexpr table populated
    /// by prior
    /// [`SessionLinkActions::send_declare_keyexpr`] calls, composes
    /// with `inline_suffix` per the same rule as the caller-asserted
    /// form (`id != 0, suffix = None` → declared literal; `id != 0,
    /// suffix = Some(s)` → declared literal + `s`), then routes both
    /// wire and loopback branches without the caller restating the
    /// resolved literal. Mirrors zenoh-pico's
    /// `_z_session_t._local_resources` lookup on the publish path
    /// (`_z_write` → `_z_resource_get_by_id`), retiring the R229
    /// caller-asserted `loopback_keyexpr` workaround on this surface.
    ///
    /// Returns `Err(PublishAliasError::UnknownMapping(id))` when no
    /// prior `send_declare_keyexpr` registered `mapping_id` OR when
    /// a subsequent `send_undeclare_kexpr` retracted it. In the
    /// error case NEITHER branch fires — sending a wire Push with an
    /// id the peer cannot resolve would also fail there, and
    /// running the loopback branch on a guess at the literal would
    /// silently mis-deliver. The caller treats `Err` as a contract
    /// violation (declare-before-publish ordering bug) and either
    /// re-declares the mapping or falls back to
    /// [`Self::publish_aliased`] with an explicit loopback literal.
    pub fn publish_aliased_auto(
        &self,
        mapping_id: u64,
        inline_suffix: Option<&str>,
        payload: &[u8],
        opts: PublishOptions,
    ) -> Result<usize, PublishAliasError> {
        let base = self
            .actions
            .resolve_outbound_mapping(mapping_id)
            .ok_or(PublishAliasError::UnknownMapping(mapping_id))?;
        let loopback_keyexpr = match inline_suffix {
            None => base,
            Some(s) => {
                let mut composed = base;
                composed.push_str(s);
                composed
            }
        };
        Ok(self.publish_aliased(mapping_id, inline_suffix, &loopback_keyexpr, payload, opts))
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
}

impl std::fmt::Display for PublishAliasError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PublishAliasError::UnknownMapping(id) => write!(
                f,
                "PublishAliasError: mapping id {id} not present in outbound table; \
                 call SessionLinkActions::send_declare_keyexpr({id}, …) first"
            ),
        }
    }
}

impl std::error::Error for PublishAliasError {}

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
fn build_loopback_sample(keyexpr: &str, payload: &[u8], opts: &PublishOptions) -> Sample {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observer::ApplicationLayerObserver;
    use crate::session_glue::{BoxedLinkDriver, SessionInitParams, SigningKey};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Captures every outbound wire send so tests can assert wire
    /// branch fires only when `allows_remote()` holds. Mirrors the
    /// `RecordingDriver` shape already used by session_glue tests.
    struct RecordingDriver {
        frames: Mutex<Vec<(Vec<u8>, Reliability)>>,
    }

    impl RecordingDriver {
        fn new() -> Self {
            Self {
                frames: Mutex::new(Vec::new()),
            }
        }

        fn frame_count(&self) -> usize {
            self.frames.lock().unwrap().len()
        }

        fn frame_reliability(&self, idx: usize) -> Reliability {
            self.frames.lock().unwrap()[idx].1
        }
    }

    impl BoxedLinkDriver for RecordingDriver {
        fn send_blocking(&self, bytes: &[u8], r: Reliability) {
            self.frames.lock().unwrap().push((bytes.to_vec(), r));
        }
        fn open_blocking(&self) {}
        fn close_blocking(&self) {}
    }

    fn fixture_params() -> SessionInitParams {
        SessionInitParams {
            version: 0x09,
            whatami: 0x02,
            zid: vec![0x01, 0x02, 0x03, 0x04],
            seq_num_res: 2,
            req_id_res: 2,
            batch_size: 65535,
            lease: 10_000,
            lease_in_seconds: false,
            initial_sn: 1,
            cookie: Vec::new(),
            cookie_signing_key: SigningKey::new(vec![0xAB; 32])
                .expect("32-byte demo key satisfies the >=32 invariant"),
        }
    }

    /// Convenience constructor that returns a (Session,
    /// driver_handle) pair so tests can assert against both the
    /// outbound wire branch (via the driver) and the loopback branch
    /// (via the observer borrowed off the session).
    fn build_session() -> (Session, Arc<RecordingDriver>) {
        let driver = Arc::new(RecordingDriver::new());
        let actions = SessionLinkActions::new(driver.clone(), fixture_params());
        let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
        (Session::new(actions, observer), driver)
    }

    #[test]
    fn publish_options_default_is_put_any_reliable() {
        let opts = PublishOptions::default();
        assert_eq!(opts.kind, SampleKind::Put);
        assert_eq!(opts.allowed_destination, Locality::Any);
        assert_eq!(opts.reliability, Reliability::Reliable);
    }

    #[test]
    fn publish_options_put_and_del_constructors() {
        let put = PublishOptions::put();
        assert_eq!(put.kind, SampleKind::Put);
        let del = PublishOptions::del();
        assert_eq!(del.kind, SampleKind::Del);
    }

    #[test]
    fn publish_options_with_setters_chain() {
        let opts = PublishOptions::put()
            .with_locality(Locality::SessionLocal)
            .with_reliability(Reliability::BestEffort)
            .with_kind(SampleKind::Del);
        assert_eq!(opts.allowed_destination, Locality::SessionLocal);
        assert_eq!(opts.reliability, Reliability::BestEffort);
        assert_eq!(opts.kind, SampleKind::Del);
    }

    #[test]
    fn publish_locality_any_fires_wire_and_loopback() {
        let (session, driver) = build_session();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .register("home/temp", move |_sample| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            });

        let fired = session.publish("home/temp", b"22.5", PublishOptions::put());
        assert_eq!(fired, 1, "Locality::Any fires loopback subscriber");
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert_eq!(
            driver.frame_count(),
            1,
            "Locality::Any also fires wire branch (one frame on the driver)"
        );
    }

    #[test]
    fn publish_locality_remote_fires_wire_only() {
        let (session, driver) = build_session();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .register("home/temp", move |_sample| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            });

        let opts = PublishOptions::put().with_locality(Locality::Remote);
        let fired = session.publish("home/temp", b"22.5", opts);
        assert_eq!(
            fired, 0,
            "Locality::Remote suppresses loopback branch entirely"
        );
        assert_eq!(counter.load(Ordering::SeqCst), 0);
        assert_eq!(
            driver.frame_count(),
            1,
            "wire branch still fires under allows_remote()"
        );
    }

    #[test]
    fn publish_locality_session_local_fires_loopback_only() {
        let (session, driver) = build_session();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .register("home/temp", move |_sample| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            });

        let opts = PublishOptions::put().with_locality(Locality::SessionLocal);
        let fired = session.publish("home/temp", b"22.5", opts);
        assert_eq!(fired, 1, "loopback branch fires the Any-default subscriber");
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert_eq!(
            driver.frame_count(),
            0,
            "wire branch is suppressed under Locality::SessionLocal"
        );
    }

    #[test]
    fn publish_loopback_sample_carries_options_reliability_and_kind() {
        let (session, _driver) = build_session();
        let captured = Arc::new(Mutex::new(None::<Sample>));
        let captured_clone = captured.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .register("home/temp", move |sample| {
                *captured_clone.lock().unwrap() = Some(sample.clone());
            });

        let opts = PublishOptions::put()
            .with_locality(Locality::SessionLocal)
            .with_reliability(Reliability::BestEffort);
        let fired = session.publish("home/temp", b"22.5", opts);
        assert_eq!(fired, 1);
        let observed = captured.lock().unwrap().clone().expect("callback fired");
        assert_eq!(observed.keyexpr, "home/temp");
        assert_eq!(observed.kind, SampleKind::Put);
        assert_eq!(observed.payload, b"22.5");
        assert_eq!(
            observed.reliability,
            Reliability::BestEffort,
            "PublishOptions.reliability propagates into Sample.reliability"
        );
    }

    #[test]
    fn publish_del_kind_routes_to_del_loopback_with_empty_payload() {
        let (session, _driver) = build_session();
        let captured = Arc::new(Mutex::new(None::<(SampleKind, Vec<u8>)>));
        let captured_clone = captured.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .register("home/temp", move |sample| {
                *captured_clone.lock().unwrap() =
                    Some((sample.kind, sample.payload.clone()));
            });

        let opts = PublishOptions::del().with_locality(Locality::SessionLocal);
        // Payload argument is ignored for Del kind — the Sample observed
        // by the subscriber carries an empty payload regardless.
        let fired = session.publish("home/temp", b"ignored", opts);
        assert_eq!(fired, 1);
        let (kind, payload) = captured.lock().unwrap().clone().expect("fired");
        assert_eq!(kind, SampleKind::Del);
        assert!(payload.is_empty(), "Del Sample carries no payload");
    }

    #[test]
    fn publish_reliability_propagates_to_wire_frame_flag() {
        let (session, driver) = build_session();
        let opts = PublishOptions::put()
            .with_locality(Locality::Remote)
            .with_reliability(Reliability::BestEffort);
        session.publish("home/temp", b"x", opts);
        assert_eq!(driver.frame_count(), 1);
        assert_eq!(
            driver.frame_reliability(0),
            Reliability::BestEffort,
            "PublishOptions.reliability sets the wire-frame reliability hint"
        );

        let opts = PublishOptions::put()
            .with_locality(Locality::Remote)
            .with_reliability(Reliability::Reliable);
        session.publish("home/temp", b"x", opts);
        assert_eq!(driver.frame_count(), 2);
        assert_eq!(driver.frame_reliability(1), Reliability::Reliable);
    }

    #[test]
    fn publish_with_no_subscribers_returns_zero_on_loopback() {
        let (session, _driver) = build_session();
        let opts = PublishOptions::put().with_locality(Locality::SessionLocal);
        let fired = session.publish("home/temp", b"x", opts);
        assert_eq!(
            fired, 0,
            "empty registry yields zero fired subscribers without panic"
        );
    }

    #[test]
    fn publish_locality_remote_only_returns_zero_even_with_matching_subscriber() {
        let (session, _driver) = build_session();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .register("home/temp", move |_sample| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            });

        let opts = PublishOptions::put().with_locality(Locality::Remote);
        let fired = session.publish("home/temp", b"x", opts);
        assert_eq!(
            fired, 0,
            "Locality::Remote never enters the loopback branch, so fired count is always 0"
        );
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn publish_returns_multi_subscriber_fired_count() {
        let (session, _driver) = build_session();
        let hits_a = Arc::new(AtomicUsize::new(0));
        let hits_b = Arc::new(AtomicUsize::new(0));
        {
            let clone = hits_a.clone();
            session
                .observer()
                .lock()
                .unwrap()
                .subscribers
                .register("home/temp", move |_sample| {
                    clone.fetch_add(1, Ordering::SeqCst);
                });
        }
        {
            let clone = hits_b.clone();
            session
                .observer()
                .lock()
                .unwrap()
                .subscribers
                .register("home/*", move |_sample| {
                    clone.fetch_add(1, Ordering::SeqCst);
                });
        }

        let opts = PublishOptions::put().with_locality(Locality::SessionLocal);
        let fired = session.publish("home/temp", b"22.5", opts);
        assert_eq!(fired, 2, "both matching subscribers fire on loopback");
        assert_eq!(hits_a.load(Ordering::SeqCst), 1);
        assert_eq!(hits_b.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn publish_locality_session_local_skips_remote_subscribers() {
        // Mixed locality on the same keyexpr — Session::publish with
        // SessionLocal routes only to loopback (no wire), and only
        // SessionLocal + Any subscribers fire on that branch. The
        // Remote subscriber is silent because its allows_local() is
        // false.
        let (session, driver) = build_session();
        let any_hits = Arc::new(AtomicUsize::new(0));
        let local_hits = Arc::new(AtomicUsize::new(0));
        let remote_hits = Arc::new(AtomicUsize::new(0));
        {
            let clone = any_hits.clone();
            session
                .observer()
                .lock()
                .unwrap()
                .subscribers
                .register_with_locality("home/temp", Locality::Any, move |_sample| {
                    clone.fetch_add(1, Ordering::SeqCst);
                });
        }
        {
            let clone = local_hits.clone();
            session
                .observer()
                .lock()
                .unwrap()
                .subscribers
                .register_with_locality(
                    "home/temp",
                    Locality::SessionLocal,
                    move |_sample| {
                        clone.fetch_add(1, Ordering::SeqCst);
                    },
                );
        }
        {
            let clone = remote_hits.clone();
            session
                .observer()
                .lock()
                .unwrap()
                .subscribers
                .register_with_locality(
                    "home/temp",
                    Locality::Remote,
                    move |_sample| {
                        clone.fetch_add(1, Ordering::SeqCst);
                    },
                );
        }

        let opts = PublishOptions::put().with_locality(Locality::SessionLocal);
        let fired = session.publish("home/temp", b"22.5", opts);
        assert_eq!(
            fired, 2,
            "Session::publish(SessionLocal) fires Any + SessionLocal, suppresses Remote"
        );
        assert_eq!(any_hits.load(Ordering::SeqCst), 1);
        assert_eq!(local_hits.load(Ordering::SeqCst), 1);
        assert_eq!(remote_hits.load(Ordering::SeqCst), 0);
        assert_eq!(
            driver.frame_count(),
            0,
            "Locality::SessionLocal suppresses the wire branch"
        );
    }

    // ── R229 publish_aliased (mapping-id keyexpr) ──

    #[test]
    fn publish_aliased_locality_any_fires_wire_and_loopback() {
        let (session, driver) = build_session();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .register("home/temp", move |_sample| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            });

        // Caller has previously (in prod) called send_declare_keyexpr(7,
        // "home/temp"); the loopback_keyexpr argument restates that
        // resolved form so loopback fires on "home/temp" even though
        // the wire side carries only mapping_id = 7.
        let fired = session.publish_aliased(
            7,
            None,
            "home/temp",
            b"22.5",
            PublishOptions::put(),
        );
        assert_eq!(fired, 1, "loopback fires on resolved literal");
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert_eq!(
            driver.frame_count(),
            1,
            "wire branch emits one aliased Push frame"
        );
    }

    #[test]
    fn publish_aliased_locality_remote_fires_wire_only() {
        let (session, driver) = build_session();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .register("home/temp", move |_sample| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            });

        let opts = PublishOptions::put().with_locality(Locality::Remote);
        let fired = session.publish_aliased(7, None, "home/temp", b"22.5", opts);
        assert_eq!(fired, 0);
        assert_eq!(counter.load(Ordering::SeqCst), 0);
        assert_eq!(driver.frame_count(), 1);
    }

    #[test]
    fn publish_aliased_locality_session_local_fires_loopback_only() {
        let (session, driver) = build_session();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .register("home/temp", move |_sample| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            });

        let opts = PublishOptions::put().with_locality(Locality::SessionLocal);
        let fired = session.publish_aliased(7, None, "home/temp", b"22.5", opts);
        assert_eq!(fired, 1);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert_eq!(
            driver.frame_count(),
            0,
            "SessionLocal suppresses the wire-aliased branch"
        );
    }

    #[test]
    fn publish_aliased_del_kind_routes_to_del_aliased_with_empty_payload() {
        let (session, driver) = build_session();
        let captured = Arc::new(Mutex::new(None::<(SampleKind, Vec<u8>, String)>));
        let captured_clone = captured.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .register("home/temp", move |sample| {
                *captured_clone.lock().unwrap() = Some((
                    sample.kind,
                    sample.payload.clone(),
                    sample.keyexpr.clone(),
                ));
            });

        let opts = PublishOptions::del();
        let fired = session.publish_aliased(7, None, "home/temp", b"ignored", opts);
        assert_eq!(fired, 1);
        let (kind, payload, keyexpr) =
            captured.lock().unwrap().clone().expect("fired");
        assert_eq!(kind, SampleKind::Del);
        assert!(payload.is_empty(), "Del Sample carries no payload");
        assert_eq!(keyexpr, "home/temp", "loopback uses resolved literal");
        assert_eq!(driver.frame_count(), 1, "send_push_del_aliased fired once");
    }

    #[test]
    fn publish_aliased_reliability_propagates_to_wire_and_sample() {
        let (session, driver) = build_session();
        let captured = Arc::new(Mutex::new(None::<Reliability>));
        let captured_clone = captured.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .register("home/temp", move |sample| {
                *captured_clone.lock().unwrap() = Some(sample.reliability);
            });

        let opts = PublishOptions::put().with_reliability(Reliability::BestEffort);
        let fired = session.publish_aliased(7, None, "home/temp", b"x", opts);
        assert_eq!(fired, 1);
        assert_eq!(
            *captured.lock().unwrap(),
            Some(Reliability::BestEffort),
            "Sample.reliability mirrors opts.reliability"
        );
        assert_eq!(driver.frame_count(), 1);
        assert_eq!(
            driver.frame_reliability(0),
            Reliability::BestEffort,
            "wire-frame reliability mirrors opts.reliability"
        );
    }

    #[test]
    fn publish_aliased_inline_suffix_passes_through_to_wire() {
        // The wire builder appends the inline suffix to the
        // mapping-id-prefixed Push; the loopback branch uses
        // `loopback_keyexpr` verbatim and does not auto-concatenate.
        // This test pins the contract: caller is responsible for the
        // loopback literal even when an inline suffix is present.
        let (session, driver) = build_session();
        let captured = Arc::new(Mutex::new(None::<String>));
        let captured_clone = captured.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .register("home/temp/kitchen", move |sample| {
                *captured_clone.lock().unwrap() = Some(sample.keyexpr.clone());
            });

        let fired = session.publish_aliased(
            7,
            Some("/kitchen"),
            "home/temp/kitchen",
            b"x",
            PublishOptions::put(),
        );
        assert_eq!(fired, 1);
        assert_eq!(
            *captured.lock().unwrap(),
            Some(String::from("home/temp/kitchen")),
            "loopback keyexpr is the caller-resolved literal"
        );
        assert_eq!(driver.frame_count(), 1, "wire send fires once");
    }

    #[test]
    fn publish_aliased_returns_zero_with_no_loopback_subscriber() {
        let (session, driver) = build_session();
        let opts = PublishOptions::put().with_locality(Locality::SessionLocal);
        let fired =
            session.publish_aliased(7, None, "home/temp", b"x", opts);
        assert_eq!(fired, 0, "empty registry yields zero fired callbacks");
        assert_eq!(
            driver.frame_count(),
            0,
            "SessionLocal locality still suppresses wire branch"
        );
    }

    #[test]
    fn publish_aliased_loopback_independent_of_wire_keyexpr_form() {
        // Pathological-but-instructive contract assertion: the
        // loopback_keyexpr argument is structurally independent of the
        // (mapping_id, inline_suffix) wire-side pair. Production
        // callers will pass the matching resolved form, but the
        // mechanism does not enforce equivalence — that responsibility
        // sits with the caller per the documented precondition.
        let (session, _driver) = build_session();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .register("intentionally_decoupled", move |_sample| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            });

        let fired = session.publish_aliased(
            42,
            Some("/whatever"),
            "intentionally_decoupled",
            b"x",
            PublishOptions::put().with_locality(Locality::SessionLocal),
        );
        assert_eq!(
            fired, 1,
            "loopback fires on the caller-asserted literal regardless of the wire pair"
        );
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn publish_aliased_mixed_locality_isolation_matches_publish_literal() {
        // Symmetric to publish_locality_session_local_skips_remote_subscribers:
        // mixed Any + SessionLocal + Remote subscribers on the loopback
        // literal, publish_aliased with SessionLocal fires Any +
        // SessionLocal, suppresses Remote, no wire frame.
        let (session, driver) = build_session();
        let any_hits = Arc::new(AtomicUsize::new(0));
        let local_hits = Arc::new(AtomicUsize::new(0));
        let remote_hits = Arc::new(AtomicUsize::new(0));
        {
            let clone = any_hits.clone();
            session
                .observer()
                .lock()
                .unwrap()
                .subscribers
                .register_with_locality(
                    "home/temp",
                    Locality::Any,
                    move |_s| {
                        clone.fetch_add(1, Ordering::SeqCst);
                    },
                );
        }
        {
            let clone = local_hits.clone();
            session
                .observer()
                .lock()
                .unwrap()
                .subscribers
                .register_with_locality(
                    "home/temp",
                    Locality::SessionLocal,
                    move |_s| {
                        clone.fetch_add(1, Ordering::SeqCst);
                    },
                );
        }
        {
            let clone = remote_hits.clone();
            session
                .observer()
                .lock()
                .unwrap()
                .subscribers
                .register_with_locality(
                    "home/temp",
                    Locality::Remote,
                    move |_s| {
                        clone.fetch_add(1, Ordering::SeqCst);
                    },
                );
        }

        let opts = PublishOptions::put().with_locality(Locality::SessionLocal);
        let fired = session.publish_aliased(7, None, "home/temp", b"x", opts);
        assert_eq!(fired, 2);
        assert_eq!(any_hits.load(Ordering::SeqCst), 1);
        assert_eq!(local_hits.load(Ordering::SeqCst), 1);
        assert_eq!(remote_hits.load(Ordering::SeqCst), 0);
        assert_eq!(driver.frame_count(), 0);
    }

    // ── R231 own_zid forwarding ──

    #[test]
    fn set_own_zid_forwards_to_subscriber_registry() {
        // Session::set_own_zid is a thin forwarder onto
        // observer.subscribers.set_own_zid. This pins the wiring so a
        // future refactor that splits the observer mutex or renames
        // the subscriber field surfaces here as a compile / runtime
        // error rather than silently disabling the dedup.
        let (session, _driver) = build_session();
        assert!(
            session
                .observer()
                .lock()
                .unwrap()
                .subscribers
                .own_zid()
                .is_none(),
            "fresh session has no own_zid installed"
        );

        let zid = vec![0x01, 0x02, 0x03, 0x04];
        assert!(session.set_own_zid(zid.clone()));
        assert_eq!(
            session
                .observer()
                .lock()
                .unwrap()
                .subscribers
                .own_zid(),
            Some(&zid[..])
        );
    }

    #[test]
    fn set_own_zid_rejects_invalid_length_without_mutating_registry() {
        // Length-0 and length-17 inputs must be rejected (return
        // false) AND must not mutate the registry's slot. Silent
        // accept of length 0 would store an empty own_zid that
        // could match an empty source_info.zid_prefix() — breaking
        // the cautious-default contract from the registry layer.
        let (session, _driver) = build_session();
        let initial = vec![0x42];
        assert!(session.set_own_zid(initial.clone()));

        assert!(!session.set_own_zid(vec![]));
        assert_eq!(
            session
                .observer()
                .lock()
                .unwrap()
                .subscribers
                .own_zid(),
            Some(&initial[..]),
            "rejected length-0 install must not mutate previously-installed zid"
        );

        assert!(!session.set_own_zid(vec![0u8; 17]));
        assert_eq!(
            session
                .observer()
                .lock()
                .unwrap()
                .subscribers
                .own_zid(),
            Some(&initial[..]),
            "rejected length-17 install must not mutate previously-installed zid"
        );
    }

    #[test]
    fn clear_own_zid_forwards_to_subscriber_registry() {
        let (session, _driver) = build_session();
        assert!(session.set_own_zid(vec![0x09, 0x08, 0x07, 0x06]));
        assert!(
            session
                .observer()
                .lock()
                .unwrap()
                .subscribers
                .own_zid()
                .is_some()
        );

        session.clear_own_zid();
        assert!(
            session
                .observer()
                .lock()
                .unwrap()
                .subscribers
                .own_zid()
                .is_none(),
            "Session::clear_own_zid must forward the release down to the registry"
        );
    }

    // ── R232 PublishOptions metadata propagation ──

    /// Capture every sample fired through the loopback path so the
    /// metadata-propagation tests can assert against the projected
    /// Sample without racing the subscriber callback.
    fn record_loopback_samples(session: &Session, pattern: &str) -> Arc<Mutex<Vec<Sample>>> {
        let captured = Arc::new(Mutex::new(Vec::<Sample>::new()));
        let captured_clone = captured.clone();
        session
            .observer()
            .lock()
            .unwrap()
            .subscribers
            .register(pattern, move |s| {
                captured_clone.lock().unwrap().push(s.clone());
            });
        captured
    }

    #[test]
    fn publish_options_with_metadata_setters_chain() {
        // Builder ergonomics: every R232 with_* setter is chainable
        // and pins exactly the field it names, leaving the other
        // four metadata slots untouched.
        let opts = PublishOptions::put()
            .with_timestamp(TimestampHint {
                time: 0x1122_3344_5566_7788,
                zid: vec![0xAA, 0xBB],
            })
            .with_encoding(EncodingHint {
                packed_id: 13,
                schema: Some("application/json".into()),
            })
            .with_source_info(SourceInfo::new(&[0x01, 0x02, 0x03, 0x04], 7, 42))
            .with_attachment(b"meta".to_vec())
            .with_qos(QosLevel::from_raw(0b0001_1010));
        let ts = opts.timestamp.as_ref().unwrap();
        assert_eq!(ts.time, 0x1122_3344_5566_7788);
        assert_eq!(ts.zid, vec![0xAA, 0xBB]);
        let enc = opts.encoding.as_ref().unwrap();
        assert_eq!(enc.packed_id, 13);
        assert_eq!(enc.schema.as_deref(), Some("application/json"));
        let si = opts.source_info.as_ref().unwrap();
        assert_eq!(si.zid_len, 4);
        assert_eq!(si.eid, 7);
        assert_eq!(si.sn, 42);
        assert_eq!(opts.attachment.as_deref(), Some(&b"meta"[..]));
        assert_eq!(opts.qos.unwrap().raw, 0b0001_1010);
    }

    #[test]
    fn publish_loopback_propagates_timestamp_to_sample() {
        let (session, _driver) = build_session();
        let captured = record_loopback_samples(&session, "home/temp");

        let opts = PublishOptions::put()
            .with_locality(Locality::SessionLocal)
            .with_timestamp(TimestampHint {
                time: 0xDEAD_BEEF,
                zid: vec![1, 2, 3],
            });
        let fired = session.publish("home/temp", b"22.5", opts);
        assert_eq!(fired, 1);

        let s = captured.lock().unwrap();
        let ts = s[0].timestamp.as_ref().unwrap();
        assert_eq!(ts.time, 0xDEAD_BEEF);
        assert_eq!(ts.zid, vec![1, 2, 3]);
    }

    #[test]
    fn publish_loopback_propagates_encoding_to_put_sample() {
        let (session, _driver) = build_session();
        let captured = record_loopback_samples(&session, "home/temp");

        let opts = PublishOptions::put()
            .with_locality(Locality::SessionLocal)
            .with_encoding(EncodingHint {
                packed_id: 5,
                schema: Some("text/plain".into()),
            });
        session.publish("home/temp", b"22.5", opts);

        let s = captured.lock().unwrap();
        let enc = s[0].encoding.as_ref().unwrap();
        assert_eq!(enc.packed_id, 5);
        assert_eq!(enc.schema.as_deref(), Some("text/plain"));
    }

    #[test]
    fn publish_loopback_omits_encoding_for_del_kind_even_when_opts_supplied() {
        // Mirror zenoh-pico's wire constraint: _z_msg_del_t has no
        // encoding field. The wire-arrival dispatch projects Del with
        // encoding=None unconditionally; the loopback path must
        // match so caller code that mistakenly attaches encoding to
        // a Del publish sees the same projection on either origin.
        let (session, _driver) = build_session();
        let captured = record_loopback_samples(&session, "home/temp");

        let opts = PublishOptions::del()
            .with_locality(Locality::SessionLocal)
            .with_encoding(EncodingHint {
                packed_id: 5,
                schema: None,
            });
        session.publish("home/temp", b"", opts);

        let s = captured.lock().unwrap();
        assert_eq!(s[0].kind, SampleKind::Del);
        assert!(
            s[0].encoding.is_none(),
            "Del kind must drop encoding on loopback to mirror wire-arrival projection"
        );
    }

    #[test]
    fn publish_loopback_propagates_source_info_to_sample() {
        let (session, _driver) = build_session();
        let captured = record_loopback_samples(&session, "home/temp");

        let si = SourceInfo::new(&[0xDE, 0xAD, 0xBE, 0xEF], 7, 42);
        let opts = PublishOptions::put()
            .with_locality(Locality::SessionLocal)
            .with_source_info(si.clone());
        session.publish("home/temp", b"22.5", opts);

        let s = captured.lock().unwrap();
        let got = s[0].source_info.as_ref().unwrap();
        assert_eq!(got.zid_len, 4);
        assert_eq!(got.zid_prefix(), &[0xDE, 0xAD, 0xBE, 0xEF][..]);
        assert_eq!(got.eid, 7);
        assert_eq!(got.sn, 42);
    }

    #[test]
    fn publish_loopback_propagates_attachment_to_sample() {
        let (session, _driver) = build_session();
        let captured = record_loopback_samples(&session, "home/temp");

        let opts = PublishOptions::put()
            .with_locality(Locality::SessionLocal)
            .with_attachment(b"attach-payload".to_vec());
        session.publish("home/temp", b"22.5", opts);

        let s = captured.lock().unwrap();
        assert_eq!(s[0].attachment.as_deref(), Some(&b"attach-payload"[..]));
    }

    #[test]
    fn publish_loopback_propagates_qos_to_sample() {
        let (session, _driver) = build_session();
        let captured = record_loopback_samples(&session, "home/temp");

        let opts = PublishOptions::put()
            .with_locality(Locality::SessionLocal)
            .with_qos(QosLevel::from_raw(0b0001_1010));
        session.publish("home/temp", b"22.5", opts);

        let s = captured.lock().unwrap();
        assert_eq!(s[0].qos.unwrap().raw, 0b0001_1010);
        assert!(
            s[0].qos.unwrap().is_express(),
            "raw bit 4 set must surface through is_express()"
        );
    }

    #[test]
    fn publish_loopback_propagates_all_metadata_in_one_chain() {
        // Composition: every R232 metadata field set together must
        // surface together on the projected Sample, in the same
        // shape the wire-arrival dispatcher produces. Mirrors what a
        // production caller does on a metadata-rich publish.
        let (session, _driver) = build_session();
        let captured = record_loopback_samples(&session, "home/temp");

        let opts = PublishOptions::put()
            .with_locality(Locality::SessionLocal)
            .with_reliability(Reliability::BestEffort)
            .with_timestamp(TimestampHint {
                time: 0x0102_0304,
                zid: vec![0x11],
            })
            .with_encoding(EncodingHint {
                packed_id: 9,
                schema: None,
            })
            .with_source_info(SourceInfo::new(&[0xAA, 0xBB], 1, 2))
            .with_attachment(vec![0xCC, 0xDD])
            .with_qos(QosLevel::from_raw(0x10));
        session.publish("home/temp", b"payload", opts);

        let s = captured.lock().unwrap();
        let got = &s[0];
        assert_eq!(got.keyexpr, "home/temp");
        assert_eq!(got.kind, SampleKind::Put);
        assert_eq!(got.payload, b"payload");
        assert_eq!(got.reliability, Reliability::BestEffort);
        assert_eq!(got.timestamp.as_ref().unwrap().time, 0x0102_0304);
        assert_eq!(got.encoding.as_ref().unwrap().packed_id, 9);
        assert_eq!(got.source_info.as_ref().unwrap().eid, 1);
        assert_eq!(got.attachment.as_deref(), Some(&[0xCC, 0xDD][..]));
        assert_eq!(got.qos.unwrap().raw, 0x10);
    }

    // ── R234 publish_aliased_auto (outbound mapping table) ──

    #[test]
    fn publish_aliased_auto_resolves_loopback_from_outbound_table() {
        let (session, driver) = build_session();
        let captured = record_loopback_samples(&session, "home/temp");

        // Declare 7 → "home/temp", then publish_aliased_auto without
        // restating the literal — the table lookup feeds loopback.
        session.actions().send_declare_keyexpr(7, "home/temp");
        let fired = session
            .publish_aliased_auto(7, None, b"22.5", PublishOptions::put())
            .expect("declared mapping resolves cleanly");
        assert_eq!(fired, 1, "loopback fires on resolved literal");

        let s = captured.lock().unwrap();
        assert_eq!(s[0].keyexpr, "home/temp");
        // Wire branch fired too: declare frame + push frame = 2.
        assert_eq!(
            driver.frame_count(),
            2,
            "declare frame then aliased push frame on the wire"
        );
    }

    #[test]
    fn publish_aliased_auto_composes_inline_suffix_with_table_base() {
        // Composition rule: declared prefix + inline_suffix forms the
        // loopback literal. Mirrors the manual publish_aliased path
        // where the caller would have asserted the composition by
        // hand.
        let (session, _driver) = build_session();
        let captured = record_loopback_samples(&session, "home/**");

        session.actions().send_declare_keyexpr(7, "home");
        let fired = session
            .publish_aliased_auto(7, Some("/temp/kitchen"), b"22.5", PublishOptions::put())
            .expect("declared mapping resolves");
        assert_eq!(fired, 1);

        let s = captured.lock().unwrap();
        assert_eq!(s[0].keyexpr, "home/temp/kitchen");
    }

    #[test]
    fn publish_aliased_auto_returns_unknown_mapping_when_never_declared() {
        // Mapping id 42 was never declared on this session. The
        // typed error path fires; neither wire nor loopback emit.
        let (session, driver) = build_session();
        let captured = record_loopback_samples(&session, "home/**");

        let err = session
            .publish_aliased_auto(42, None, b"x", PublishOptions::put())
            .expect_err("undeclared mapping must error out");
        assert_eq!(err, PublishAliasError::UnknownMapping(42));

        assert!(
            captured.lock().unwrap().is_empty(),
            "loopback must not fire on the error path"
        );
        assert_eq!(
            driver.frame_count(),
            0,
            "wire must not emit on the error path"
        );
    }

    #[test]
    fn publish_aliased_auto_returns_unknown_mapping_after_undeclare() {
        // The error path fires whether the id was never declared OR
        // was declared and then retracted. Both share the same
        // "table lookup returned None" failure mode.
        let (session, _driver) = build_session();

        session.actions().send_declare_keyexpr(7, "home/temp");
        // First publish OK.
        session
            .publish_aliased_auto(7, None, b"a", PublishOptions::put())
            .expect("first publish succeeds after declare");

        // Retract the mapping.
        session.actions().send_undeclare_kexpr(7);

        // Second publish fails typed.
        let err = session
            .publish_aliased_auto(7, None, b"b", PublishOptions::put())
            .expect_err("retracted mapping must error out");
        assert_eq!(err, PublishAliasError::UnknownMapping(7));
    }

    #[test]
    fn publish_aliased_auto_error_display_names_the_violating_id() {
        // Display impl must surface the id so a logged error line is
        // diagnosable without reflection.
        let err = PublishAliasError::UnknownMapping(123);
        let s = err.to_string();
        assert!(s.contains("123"), "error message must contain the mapping id");
        assert!(
            s.contains("send_declare_keyexpr"),
            "error message hints at the remediation API"
        );
    }

    #[test]
    fn publish_aliased_loopback_propagates_metadata_to_sample() {
        // Parity check: publish_aliased's loopback branch shares the
        // same build_loopback_sample helper as publish, so metadata
        // must flow identically. This pins the shared-helper contract
        // — a future refactor that splits the helper or re-implements
        // either path independently surfaces here.
        let (session, _driver) = build_session();
        let captured = record_loopback_samples(&session, "home/temp");

        let opts = PublishOptions::put()
            .with_locality(Locality::SessionLocal)
            .with_timestamp(TimestampHint {
                time: 0xAABB_CCDD,
                zid: vec![0x42],
            })
            .with_attachment(b"aliased-meta".to_vec());
        let fired = session.publish_aliased(7, None, "home/temp", b"x", opts);
        assert_eq!(fired, 1);

        let s = captured.lock().unwrap();
        assert_eq!(s[0].timestamp.as_ref().unwrap().time, 0xAABB_CCDD);
        assert_eq!(s[0].attachment.as_deref(), Some(&b"aliased-meta"[..]));
    }
}
