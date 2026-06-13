// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The `transport-unicast` publisher handle cluster: the [`Publisher`] /
//! [`PublisherAliased`] handles and [`PublishAliasError`]. The parent
//! module re-exports the public types via `pub use publisher::*;` so the
//! path `wz_runtime_tokio::session::Publisher` etc. is unchanged.
//!
//! R311nb (Level B, B5b-2b tail) — the transport-AGNOSTIC publish value
//! surface ([`PublishOptions`], [`PublishError`], `build_loopback_sample`)
//! moved to [`publish_common`](super::publish_common) so the unified
//! [`Session::publish`](super::Session::publish) reaches them on every
//! transport. What stays here is genuinely unicast: the aliased handle
//! resolves the unicast outbound keyexpr-mapping table
//! (`actions().resolve_outbound_mapping`), which a handshake-free multicast
//! session has no analogue of, so the whole module keeps its
//! `transport-unicast` gate.

use super::*;

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
    pub(super) session: Session<R, T, Unicast>,
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
                    cell.invoke(move |cb| cb(MatchingStatus { matching: m }));
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
    pub(super) session: Session<R, T, Unicast>,
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
    /// B5b-2b (R311nc) — the aliased publish surface (which resolves the
    /// unicast outbound keyexpr-mapping table) was used on a session whose
    /// transport is not unicast. A multicast session has no mapping table;
    /// the `Session::actions()` projection rejects. No wire bytes were
    /// emitted.
    RequiresUnicast,
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
            PublishAliasError::RequiresUnicast => write!(
                f,
                "PublishAliasError: aliased publish requires a unicast transport; \
                 this session holds a multicast transport (no outbound keyexpr- \
                 mapping table); the Push was not emitted"
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
            PublishError::RequiresUnicast => PublishAliasError::RequiresUnicast,
        }
    }
}
