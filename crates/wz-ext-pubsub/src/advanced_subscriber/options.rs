// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What an advanced subscriber is asked for: its options, the recovery and history configuration
//! inside them, the detection token, and how a host that declares keys names each of its
//! entities on the wire.
//!
//! None of this reads a clock, spawns a task or names a session, which is why it is the first of
//! the subscriber to live here: a host builds the options and hands them to whichever engine runs
//! the subscriber.

use std::sync::Arc;
#[cfg(feature = "advanced-recovery")]
use std::time::Duration;

use wz_session_core::declare_form::RetractionKey;
use wz_session_core::locality::Locality;

/// Retransmission (gap-recovery) configuration
/// (`AdvancedSubscriberOptions::with_recovery`). Mirror of zenoh-ext
/// `RecoveryConfig` (advanced_subscriber.rs:91-134): it carries ONLY the
/// retransmission triggers. The sample-driven `_sn`-range recovery GET is implied
/// by recovering at all (`RecoveryConfig::default()`); [`Self::periodic_queries`] +
/// [`Self::heartbeat`] add the periodic / beacon triggers. The GET locality + GET
/// timeout + the (independent) startup history live on [`AdvancedSubscriberOptions`],
/// NOT here — zenoh keeps `.recovery()` and `.history()` SEPARATE so
/// history-without-retransmission is representable (R311y91, review M1).
/// R2617 — THE PAIR IS NOW UNREPRESENTABLE, not merely unwise.
///
/// `periodic_queries` and `heartbeat` are two triggers for the same recovery
/// GET, and upstream makes choosing both a TYPE error rather than a validation:
/// `zenoh-ext/src/advanced_subscriber.rs` @ `pub struct RecoveryConfig<const CONFIGURED: bool = true> {`
/// with both setters living on @ `impl RecoveryConfig<false> {` and each
/// returning `RecoveryConfig<true>`, so the second call has no method to reach.
/// wz carried a plain struct with public fields, so the invalid pair was
/// constructible here and unrepresentable there.
///
/// THIS IS NOT A TIDINESS CHANGE. Upstream's heartbeat handler relies on the
/// exclusion as a load-bearing invariant, and says so at the line that spawns
/// the periodic task for a newly-seen source: `zenoh-ext/src/advanced_subscriber.rs` @ `// NOTE: API does not allow both heartbeat and periodic_queries`.
/// Porting that handler's guard onto a tree where both CAN be set would be
/// inheriting an invariant this crate does not hold, which is why the type
/// moves first and the guard follows it.
///
/// THE FIELDS ARE PRIVATE, and that is the half that does the work.
/// `#[non_exhaustive]` stops an external crate writing a struct LITERAL but not
/// assigning to a field of a value it already holds -- which is exactly what
/// both C ABIs were doing. Each setter also CLEARS the other trigger, mirroring
/// upstream, so even the in-crate path cannot leave both set.
///
/// `new()` is generic over the flag on purpose: `RecoveryConfig::new()` in a
/// position wanting the default `true` infers it and stays sample-driven, while
/// `RecoveryConfig::new().with_heartbeat()` infers `false` because that is the
/// only parameter for which the method exists. That is upstream's own
/// inference trick, and it is why no caller of the builder form had to change.
#[cfg(feature = "advanced-recovery")]
#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub struct RecoveryConfig<const CONFIGURED: bool = true> {
    /// R311y83 — when `Some(period)`, a background task re-asks every known
    /// source `_sn=last+1..` every `period`, catching a lost LAST sample that
    /// no further live sample would trigger sample-driven recovery for (zenoh's
    /// `RecoveryConfig::periodic_queries`, advanced_subscriber.rs:111-116 + the
    /// `PeriodicQuery` TimedEvent :580-643). `None` (default) = sample-driven
    /// recovery only. NB enabling this starts a periodic job at declare time,
    /// which the host runs: a task of the process's `Application` runtime on the
    /// tokio runtime (R3064: the caller need not be inside a tokio runtime
    /// context), a step of the session on the cooperative engine.
    periodic_queries: Option<Duration>,
    /// R311y84 — when `true`, declare a second subscriber on
    /// `<key_expr>/@adv/pub/**` that decodes each publisher's last-sn heartbeat
    /// beacon (`z_deserialize::<u32>`) and issues a BOUNDED `_sn=last+1..hb`
    /// recovery GET when the beacon reports samples past `last_delivered` (zenoh
    /// heartbeat subscriber, advanced_subscriber.rs:1045-1149). Catches a lost
    /// last sample like the periodic trigger, but driven by the publisher's
    /// beacon instead of a local timer (the producer beacon is the separate
    /// `ext-pubsub-sample-miss-detection` atom). `false` (default) = off.
    heartbeat: bool,
    /// R2621 — how long a source's ordering state survives unheard-from before
    /// the retention sweep reclaims it. `None` means
    /// [`Self::RETENTION_PERIOD_DEFAULT`], upstream's own 1h.
    retention_period: Option<Duration>,
}

#[cfg(feature = "advanced-recovery")]
impl<const CONFIGURED: bool> RecoveryConfig<CONFIGURED> {
    /// R2621 — upstream's own default, `zenoh-ext/src/advanced_subscriber.rs`
    /// @ `const RETENTION_PERIOD_DEFAULT: Duration = Duration::from_secs(3600);`.
    /// Hours rather than milliseconds, which is what makes a full-scan sweep an
    /// acceptable trade against upstream's LRU.
    pub const RETENTION_PERIOD_DEFAULT: Duration = Duration::from_secs(3600);

    /// Sample-driven recovery (no periodic / heartbeat trigger).
    ///
    /// Generic over the flag so both spellings keep working: used directly it
    /// infers the default `true` and is a complete, trigger-less config; used
    /// as the receiver of a `with_*` call it infers `false`, because that is
    /// the only parameter for which those methods exist.
    pub fn new() -> Self {
        Self::default()
    }

    /// The configured periodic re-ask period, if that trigger was chosen.
    ///
    /// An accessor rather than a public field (R2617): a public field is
    /// assignable from another crate even under `#[non_exhaustive]`, which is
    /// how both C ABIs used to set a trigger and is precisely the hole the
    /// typestate exists to close.
    pub fn periodic_queries(&self) -> Option<Duration> {
        self.periodic_queries
    }

    /// Whether the heartbeat trigger was chosen.
    pub fn heartbeat(&self) -> bool {
        self.heartbeat
    }

    /// R2621 — how long a source's ordering state survives without being heard
    /// from, upstream's
    /// `zenoh-ext/src/advanced_subscriber.rs` @ `pub fn retention_period(mut self, period: Duration) -> RecoveryConfig<CONFIGURED> {`.
    ///
    /// On the GENERIC impl rather than the `<false>` one, exactly as upstream
    /// places it: retention is orthogonal to WHICH trigger was chosen, so it
    /// must remain settable after a trigger has moved the type to `<true>`.
    pub fn with_retention_period(mut self, period: Duration) -> Self {
        self.retention_period = Some(period);
        self
    }

    /// The configured retention period, or [`Self::RETENTION_PERIOD_DEFAULT`].
    pub fn retention_period(&self) -> Duration {
        self.retention_period
            .unwrap_or(Self::RETENTION_PERIOD_DEFAULT)
    }
}

#[cfg(feature = "advanced-recovery")]
impl RecoveryConfig<false> {
    /// Enable the periodic recovery trigger with the given re-ask period.
    /// The host needs a way to run a periodic job at declare time.
    ///
    /// CLEARS the heartbeat trigger, exactly as upstream's does
    /// (`zenoh-ext/src/advanced_subscriber.rs` @ `pub fn periodic_queries(self, period: Duration) -> RecoveryConfig<true> {`,
    /// whose body writes `heartbeat: false`). Returning `RecoveryConfig<true>`
    /// is what removes the other setter from the value's type.
    pub fn with_periodic_queries(self, period: Duration) -> RecoveryConfig<true> {
        RecoveryConfig {
            periodic_queries: Some(period),
            heartbeat: false,
            // R2621 — carried across the typestate transition, as upstream
            // carries it (`retention_period: self.retention_period`): choosing a
            // trigger must not silently reset an orthogonal setting.
            retention_period: self.retention_period,
        }
    }

    /// Enable the heartbeat recovery trigger.
    ///
    /// CLEARS the periodic trigger, mirroring
    /// `zenoh-ext/src/advanced_subscriber.rs` @ `pub fn heartbeat(self) -> RecoveryConfig<true> {`.
    pub fn with_heartbeat(self) -> RecoveryConfig<true> {
        RecoveryConfig {
            periodic_queries: None,
            heartbeat: true,
            retention_period: self.retention_period,
        }
    }
}

/// Options for a configured advanced subscriber
/// (`AdvancedSubscriber::declare_with_options` of the host). Mirror of the zenoh-ext
/// `AdvancedSubscriberBuilder` knobs wz implements: the (independent) retransmission
/// and startup-history configs, the shared GET locality, and the shared GET timeout.
/// zenoh exposes `.recovery()` / `.history()` as SEPARATE builder methods
/// (advanced_subscriber.rs:261/287), so [`Self::recovery`] and [`Self::history`] are
/// independent `Option`s — a `history`-only subscriber (no retransmission) is
/// representable (R311y91, review M1: the prior `RecoveryConfig`-carries-everything
/// shape made history-without-retransmission unrepresentable).
///
/// R311y826 — no longer `Copy`: [`Self::subscriber_detection`] carries a
/// caller-supplied key expression and so owns a `String`. `Clone` stays.
///
/// R2819 — IN EVERY ADVANCED-SUBSCRIBER BUILD, not behind
/// `ext-pubsub-advanced-recovery`. Upstream's builder offers
/// `zenoh-ext/src/advanced_subscriber.rs` @ `pub fn subscriber_detection(mut self) -> Self {`
/// and @ `pub fn allowed_origin(mut self, origin: Locality) -> Self {` on every
/// advanced subscriber, independent of @ `pub fn recovery(mut self, conf: RecoveryConfig) -> Self {`;
/// here both were reachable only with recovery compiled in, because the whole
/// options type was. Now the type and those two knobs are unconditional, and
/// each remaining field carries the gate of the machinery that reads it:
/// `recovery`, `get_locality` and `query_timeout` configure GETs, which only a
/// recovery build issues; `history` configures the history GET.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct AdvancedSubscriberOptions {
    /// Retransmission (gap recovery). `None` (default) = no recovery: a forward gap
    /// reports a `Miss` and delivers past the hole. `Some` enables the reorder
    /// buffer + the sample-driven `_sn`-range recovery GET (+ the periodic /
    /// heartbeat triggers the [`RecoveryConfig`] selects). Mirror of zenoh
    /// `.recovery()`.
    #[cfg(feature = "advanced-recovery")]
    pub recovery: Option<RecoveryConfig>,
    /// Startup history query. `None` (default) = no history. `Some` issues a
    /// `<key_expr>/@adv/**` GET on declare so a LATE JOINER recovers the publishers'
    /// cached history. INDEPENDENT of [`Self::recovery`] (zenoh `.history()` is a
    /// separate builder method): history-without-retransmission is valid.
    #[cfg(feature = "advanced-history")]
    pub history: Option<HistoryConfig>,
    /// The live (+ heartbeat) subscription's origin: which publishers' samples this
    /// subscriber accepts. `Any` (default) accepts wire + loopback; `SessionLocal`
    /// loopback only; `Remote` wire only. Faithful to zenoh's `conf.origin` /
    /// `AdvancedSubscriberBuilder::allowed_origin` (advanced_subscriber.rs:141/249).
    /// INDEPENDENT of [`Self::get_locality`] — zenoh keeps the sub origin and the GET
    /// axis separate (R311y96 split them after the review found the prior single
    /// `allowed_destination` knob conflated the two orthogonal concepts).
    pub allowed_origin: Locality,
    /// The recovery / history GET destination locality. `Any` (default) fans the GET
    /// to a remote publisher's `@adv` cache AND the local loopback; `SessionLocal`
    /// pins it to loopback (single-host composition — a loopback-only GET completes
    /// synchronously without the deadline sweep). wz models the GET reach as a
    /// `Locality`; zenoh hardwires the GET destination to `Any`. `Any` is the
    /// zenoh-faithful default; the `SessionLocal` pin is a wz single-host
    /// superset.
    ///
    /// R2505 — THIS PARAGRAPH USED TO SAY the GET axis upstream exposes is
    /// `query_target: QueryTarget`, "a DIFFERENT axis wz does not model here".
    /// Half of that is still true and half is now false, so both halves are
    /// stated rather than the sentence quietly deleted:
    /// · STILL TRUE — `Locality` and `QueryTarget` are different axes, and wz
    ///   still exposes no `query_target` KNOB on `AdvancedSubscriberOptions`.
    /// · NO LONGER TRUE — wz does not model the axis, but it now SENDS it:
    ///   `issue_recovery_get` pins `QueryTarget::All` on every recovery and
    ///   history GET. Not exposing a knob is an API choice; sending no target
    ///   ext was a WIRE consequence, because an absent ext reads back as
    ///   BestMatching and one queryable then answers a history GET.
    /// ⚠ The old sentence also carried two upstream coordinates,
    /// `advanced_subscriber.rs:143/638`, and BOTH were rot: at the 1.10.0 pin
    /// :143 is the tail of a `retention_period` builder and :638 is inside the
    /// `max_history_depth == 1` fast path. The field and its default are at
    /// `zenoh-ext/src/advanced_subscriber.rs` @ `pub(crate) query_target: QueryTarget,`
    /// and @ `query_target: QueryTarget::All,` — anchored, because a corrected
    /// number rots again at the next pin bump.
    #[cfg(feature = "advanced-recovery")]
    pub get_locality: Locality,
    /// Timeout applied to BOTH the recovery + history GETs (zenoh's builder
    /// `query_timeout`, shared by history + retransmission; default 10s). A
    /// no-answerer GET (no `@adv` cache replies) would otherwise wait on a peer
    /// `Final` that never arrives; the non-zero timeout lets the reply registry's
    /// deadline sweep fire the synthetic `Final` so `State::finish_recovery` /
    /// `State::finish_history` run (R311y89, review C3). Converted by
    /// `recovery_query_timeout_ms`.
    #[cfg(feature = "advanced-recovery")]
    pub query_timeout: Duration,
    /// Make this subscriber DETECTABLE: declare a liveliness token on
    /// `<key_expr>/@adv/sub/<zid>/<eid>/[meta|_]` so a third party can see the
    /// subscriber exists (zenoh `.subscriber_detection()`,
    /// advanced_subscriber.rs:292-309; zenoh-pico's `_has_token` / `_token`,
    /// advanced_subscriber.h:118-119).
    ///
    /// `None` (default) declares no token, matching BOTH references (zenoh's
    /// builder starts at `liveliness: false`, advanced_subscriber.rs:164) —
    /// the token is extra wire traffic that only an observer wants. This
    /// differs from wz's `AdvancedPublisherOptions::publisher_detection`,
    /// which defaults `true` because wz's OWN recovery plane consumes the
    /// `@adv/pub` token; nothing in wz consumes `@adv/sub`, and neither
    /// reference consumes it either — `KE_SUB` is `pub use`d for third parties
    /// and read nowhere inside zenoh or pico.
    pub subscriber_detection: Option<SubscriberDetection>,
    /// How a host that declares keys names each entity on the wire. `None`
    /// (default) declares every entity on its literal key, which is what a
    /// runtime session does; see [`DeclarationForms`].
    pub forms: Option<FormsHandle>,
}

/// Detection configuration ([`AdvancedSubscriberOptions::with_subscriber_detection`]).
///
/// R2815 — it carries no zid any more. It held the caller's `local_zid`
/// because wz's `Session` had no zid getter, so a detection token could be
/// named with a zid other than its session's. The token is now named with the
/// subscriber's own `AdvancedSubscriber::id`, which reads the session's zid.
///
/// R2819 — in every advanced-subscriber build; see [`AdvancedSubscriberOptions`].
#[derive(Clone, Debug, Default)]
pub struct SubscriberDetection {
    /// A key expression appended to the detection token's key expression to
    /// convey application metadata (zenoh
    /// `.subscriber_detection_metadata()`, advanced_subscriber.rs:299-309).
    ///
    /// `None` puts the concrete `_` chunk there instead — NOT an empty chunk.
    /// Both references do this deliberately: zenoh's own comment calls it a
    /// workaround for a routing matching bug, and a wildcard-tailed observer
    /// query stops matching without it.
    pub metadata: Option<String>,
}

impl SubscriberDetection {
    /// Detectable, with no metadata chunk.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a metadata key expression to the token's key expression.
    pub fn with_metadata(mut self, meta: impl Into<String>) -> Self {
        self.metadata = Some(meta.into());
        self
    }
}

/// How ONE entity of an advanced subscriber is named on the wire, and what keeps
/// that name valid for as long as the entity stands.
///
/// An advanced subscriber is four plain entities — the subscription, a
/// heartbeat subscription, a late-publisher liveliness subscription and a
/// detection token — and a host that declares KEYS (a C session's resource
/// table) names each of them differently from the literal this crate would
/// announce: a declared id and the rest of the key, a retraction that names the
/// key, and a declaration that has to outlive the entity and go right after it.
/// The runtime cannot know any of that, so it asks ([`DeclarationForms`]) and
/// declares the entity the way it is told.
///
/// [`Self::literal`] is what the runtime does on its own.
#[derive(Clone, Default)]
pub struct EntityForm {
    /// The declaration the wire names, `0` for the literal key.
    mapping_id: u64,
    /// What follows the declared prefix; `None` when it covers the whole key.
    suffix: Option<String>,
    /// The key a subscriber's retraction names beside its id, when it names one.
    retraction: Option<RetractionKey>,
    /// Whether a TOKEN's retraction names its key beside its id.
    names_key_on_retraction: bool,
    /// What keeps the declaration alive; let go of AFTER the entity is.
    keeps: Option<Arc<dyn Send + Sync>>,
}

impl EntityForm {
    /// The key itself, announced literally, retracted by id alone.
    pub fn literal() -> Self {
        Self::default()
    }

    /// Declaration `mapping_id` followed by `suffix`.
    pub fn aliased(mapping_id: u64, suffix: Option<String>) -> Self {
        Self {
            mapping_id,
            suffix,
            ..Self::default()
        }
    }

    /// Make a subscriber's retraction name `key` beside its id.
    pub fn with_retraction_naming(mut self, key: Option<RetractionKey>) -> Self {
        self.retraction = key;
        self
    }

    /// Make a token's retraction name its own key beside its id.
    pub fn with_token_retraction_naming_the_key(mut self, on: bool) -> Self {
        self.names_key_on_retraction = on;
        self
    }

    /// Hold `anchor` for as long as the entity declared in this form stands.
    pub fn keeping(mut self, anchor: Arc<dyn Send + Sync>) -> Self {
        self.keeps = Some(anchor);
        self
    }

    /// Whether the entity is announced on the literal key.
    pub fn is_literal(&self) -> bool {
        self.mapping_id == 0
    }

    /// The declaration the wire names, `0` for the literal key.
    pub fn mapping_id(&self) -> u64 {
        self.mapping_id
    }

    /// What follows the declared prefix; `None` when it covers the whole key.
    pub fn suffix(&self) -> Option<&str> {
        self.suffix.as_deref()
    }

    /// The key a subscriber's retraction names beside its id, when it names one.
    pub fn retraction(&self) -> Option<&RetractionKey> {
        self.retraction.as_ref()
    }

    /// Whether a TOKEN's retraction names its key beside its id.
    pub fn names_key_on_retraction(&self) -> bool {
        self.names_key_on_retraction
    }

    /// What keeps the declaration alive, to be let go of AFTER the entity.
    pub fn kept(&self) -> Option<&Arc<dyn Send + Sync>> {
        self.keeps.as_ref()
    }
}

impl std::fmt::Debug for EntityForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EntityForm")
            .field("mapping_id", &self.mapping_id)
            .field("suffix", &self.suffix)
            .field("retraction", &self.retraction)
            .field("names_key_on_retraction", &self.names_key_on_retraction)
            .field("keeps", &self.keeps.is_some())
            .finish()
    }
}

/// What a host that declares keys tells an advanced subscriber about how each of
/// its entities is named — see [`EntityForm`].
///
/// Each method is called ONCE PER DECLARATION OF THAT ENTITY, in the order the
/// subscriber declares them, and is the moment the host declares the key the
/// entity will be named by. An advanced subscriber declared on a session with
/// several faces is declared once per face, so a host is expected to answer the
/// same question the same way: the first answer declares, the later ones reuse.
///
/// Every default is the literal form, so a host overrides only what it names.
pub trait DeclarationForms: Send + Sync {
    /// The identity the subscriber reports and names its detection token with,
    /// when it is not the plain subscription's own. A host with ONE identity for
    /// a subscriber that is declared on many faces supplies it here; `None`
    /// keeps the per-declaration id.
    fn entity_id(&self) -> Option<u32> {
        None
    }

    /// The live subscription on `keyexpr`.
    fn subscriber(&self, _keyexpr: &str) -> EntityForm {
        EntityForm::literal()
    }

    /// The late-publisher liveliness subscription on `keyexpr`.
    fn late_publishers(&self, _keyexpr: &str) -> EntityForm {
        EntityForm::literal()
    }

    /// The heartbeat subscription on `keyexpr`.
    fn heartbeat(&self, _keyexpr: &str) -> EntityForm {
        EntityForm::literal()
    }

    /// The detection token on `keyexpr`.
    fn token(&self, _keyexpr: &str) -> EntityForm {
        EntityForm::literal()
    }

    /// Take over an entity's declaration when the subscriber runs in the
    /// background: its handle is gone and nothing is left to let go of the
    /// declaration after the entity, so the host keeps it until its own end.
    fn retain(&self, _anchor: Arc<dyn Send + Sync>) {}
}

/// A host's [`DeclarationForms`], shareable and printable, for
/// [`AdvancedSubscriberOptions::forms`].
#[derive(Clone)]
pub struct FormsHandle(Arc<dyn DeclarationForms>);

impl FormsHandle {
    /// Wrap `forms`.
    pub fn new(forms: Arc<dyn DeclarationForms>) -> Self {
        Self(forms)
    }

    /// The host's answers.
    pub fn forms(&self) -> &dyn DeclarationForms {
        &*self.0
    }
}

impl std::fmt::Debug for FormsHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FormsHandle")
    }
}

impl Default for AdvancedSubscriberOptions {
    fn default() -> Self {
        Self {
            #[cfg(feature = "advanced-recovery")]
            recovery: None,
            #[cfg(feature = "advanced-history")]
            history: None,
            allowed_origin: Locality::Any,
            #[cfg(feature = "advanced-recovery")]
            get_locality: Locality::Any,
            #[cfg(feature = "advanced-recovery")]
            query_timeout: Duration::from_secs(10),
            subscriber_detection: None,
            forms: None,
        }
    }
}

impl AdvancedSubscriberOptions {
    /// Default options: no recovery, no history, `Any` sub origin + GET locality,
    /// 10s GET timeout.
    pub fn new() -> Self {
        Self::default()
    }

    /// Allow this subscriber to be detected through liveliness (zenoh
    /// `.subscriber_detection()` + `.subscriber_detection_metadata()`, which
    /// [`SubscriberDetection`] carries as one value): declares a token on
    /// `<key_expr>/@adv/sub/<zid>/<eid>/[meta|_]`.
    pub fn with_subscriber_detection(mut self, detection: SubscriberDetection) -> Self {
        self.subscriber_detection = Some(detection);
        self
    }

    /// Name each entity the way `forms` says — see [`DeclarationForms`].
    pub fn with_declaration_forms(mut self, forms: Arc<dyn DeclarationForms>) -> Self {
        self.forms = Some(FormsHandle::new(forms));
        self
    }

    /// Enable retransmission (gap recovery) with the given [`RecoveryConfig`]
    /// (zenoh `.recovery()`).
    #[cfg(feature = "advanced-recovery")]
    pub fn with_recovery(mut self, recovery: RecoveryConfig) -> Self {
        self.recovery = Some(recovery);
        self
    }

    /// Enable the startup history query with the given [`HistoryConfig`]
    /// (zenoh `.history()`). Independent of [`Self::with_recovery`].
    #[cfg(feature = "advanced-history")]
    pub fn with_history(mut self, history: HistoryConfig) -> Self {
        self.history = Some(history);
        self
    }

    /// Pin the live (+ heartbeat) subscription's origin (zenoh `allowed_origin`;
    /// e.g. `Remote` to ignore loopback echoes).
    pub fn with_allowed_origin(mut self, origin: Locality) -> Self {
        self.allowed_origin = origin;
        self
    }

    /// Pin the recovery + history GET destination locality (e.g. `SessionLocal` for
    /// a single-host loopback composition; `Any` is the zenoh-faithful default).
    #[cfg(feature = "advanced-recovery")]
    pub fn with_get_locality(mut self, locality: Locality) -> Self {
        self.get_locality = locality;
        self
    }

    /// Pin the recovery + history GET timeout (zenoh `.query_timeout()`). Converted
    /// to the `QueryOptions::with_timeout_ms` value by `recovery_query_timeout_ms`,
    /// clamped to `>= 1` ms. R311y326 — the clamp no longer prevents a wedge (a `0`
    /// now resolves to the platform default, not never-expire); it pins that a
    /// recovery GET carries ITS configured timeout rather than silently inheriting
    /// the 10s default. See `recovery_query_timeout_ms`.
    #[cfg(feature = "advanced-recovery")]
    pub fn with_query_timeout(mut self, query_timeout: Duration) -> Self {
        self.query_timeout = query_timeout;
        self
    }
}

/// Startup-history configuration ([`AdvancedSubscriberOptions::with_history`]).
/// Mirror of zenoh-ext `HistoryConfig` (advanced_subscriber.rs:54-89). R311y86
/// builds the `max_samples` (`_max`) cap; R311y98 the `max_age` age filter
/// (`_time`); R311y100 the `detect_late_publishers` liveliness trigger — the
/// full zenoh `HistoryConfig` surface.
#[cfg(feature = "advanced-history")]
#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub struct HistoryConfig {
    /// `Some(N)` caps the startup history GET to the newest `N` samples per
    /// source (the `_max=N` selector); `None` recovers the publishers' whole
    /// caches (zenoh `HistoryConfig::max_samples`).
    pub sample_depth: Option<usize>,
    /// `Some(secs)` bounds the startup history GET to samples no older than
    /// `secs` seconds (the `_time=[now(-secs)..]` selector); `None` applies no
    /// age bound (zenoh `HistoryConfig::max_age`). Composes with `sample_depth`
    /// — both selectors ride the one GET.
    pub max_age: Option<f64>,
    /// `true` declares a liveliness subscriber on `<ke>/@adv/pub/**` so a
    /// publisher appearing AFTER this subscriber joined (its `@adv` liveliness
    /// token Put) triggers a per-publisher history GET — recovering its cache
    /// the way the startup GET recovered the publishers present at declare time
    /// (zenoh `HistoryConfig::detect_late_publishers`). The `_max` / `_time`
    /// bounds above ride the per-publisher GET too.
    pub detect_late_publishers: bool,
}

#[cfg(feature = "advanced-history")]
impl HistoryConfig {
    /// History with no cap (recover each publisher's whole cache).
    pub fn new() -> Self {
        Self::default()
    }

    /// Cap the startup history GET to the newest `depth` samples per source
    /// (the `_max` selector).
    pub fn max_samples(mut self, depth: usize) -> Self {
        self.sample_depth = Some(depth);
        self
    }

    /// Bound the startup history GET to samples no older than `seconds`
    /// (the `_time=[now(-seconds)..]` selector; zenoh `HistoryConfig::max_age`).
    /// `seconds` must be non-negative — a negative age has no meaning for a
    /// "no older than" window and would render the malformed `now(--Ns)` form
    /// (the lower-bound emit negates it). Asserted in debug builds.
    pub fn max_age(mut self, seconds: f64) -> Self {
        debug_assert!(
            seconds >= 0.0,
            "HistoryConfig::max_age must be non-negative, got {seconds}"
        );
        self.max_age = Some(seconds);
        self
    }

    /// Enable late-publisher detection (zenoh
    /// `HistoryConfig::detect_late_publishers`): recover the history of a
    /// publisher that appears AFTER this subscriber joined.
    pub fn detect_late_publishers(mut self) -> Self {
        self.detect_late_publishers = true;
        self
    }
}
