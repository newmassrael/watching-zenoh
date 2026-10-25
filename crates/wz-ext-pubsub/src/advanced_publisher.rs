// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y69 — `ext-pubsub-advanced-publisher` (§5.25): a publisher that
//! stamps a per-sample `SourceInfo` sequence number, retains its samples
//! in a [`CacheStore`] for recovery, and announces its existence with
//! an `@adv` liveliness token.
//!
//! The wz mirror of zenoh-ext `advanced_publisher.rs`. On each
//! [`AdvancedPublisherOn::put`] it (1) reads-and-increments a per-publisher
//! sequence counter and stamps it onto the wire sample's `SourceInfo`
//! (`(zid, eid, sn)`), (2) stamps a timestamp, (3) publishes, and (4)
//! pushes the sample into its cache ring. A subscriber detects the
//! publisher via the liveliness token on
//! `<key_expr>/@adv/pub/<zid>/<eid|uhlc>/_` and recovers missed samples by
//! `get`-ing the cache there with an `_sn` range (the
//! `ext-pubsub-advanced-recovery` round).
//!
//! The composition is written once, here, over a plane ([`AdvancedPublisherPlane`]): what is
//! validated, in what order the four entities are declared and retracted, what a put stamps and
//! retains, what a beacon says. A host supplies the four declarations, the sends, and the timer the
//! beacon runs on: a runtime session is one such host (the plain declarations, in the tokio
//! runtime), a C session another (its entities on one shared key table), and the cooperative
//! engine a third. Nothing here spawns a task, reads a clock or holds a socket.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use wz_node_time::node_clock::NodeHlc;
use wz_node_time::timestamp_source::FallbackStamp;
use wz_session_core::locality::Locality;
use wz_session_core::publish_options::{PublishError, PublishOptions};
use wz_session_core::qos::{CongestionControl, Priority};
use wz_session_core::reliability::Reliability;
use wz_session_core::sample::{SampleKind, SourceInfo};
use wz_session_core::zid_hex::zid_to_zenoh_hex;

#[cfg(feature = "ext-pubsub-sample-miss-detection")]
use wz_session_core::serde_codec::z_serialize;

use crate::advanced_cache::{CacheConfig, CacheStore, CachedSample, Retained};

/// How an advanced publisher tags its samples for downstream detection /
/// recovery. Mirror of zenoh-ext `Sequencing` (advanced_publisher.rs:55-59).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sequencing {
    /// No per-sample tag (a plain publisher with the `@adv` decorations).
    None,
    /// Tag the timestamp only (the `uhlc` discriminator in the `@adv` KE).
    Timestamp,
    /// Tag a per-publisher monotonic sequence number into `SourceInfo`
    /// (the recovery-capable mode; the `<eid>` discriminator in the KE).
    SequenceNumber,
}

/// Heartbeat (last-sample-miss-detection) configuration. Mirror of zenoh-ext
/// `MissDetectionConfig` (advanced_publisher.rs:66-104). `heartbeat` /
/// `sporadic_heartbeat` are mutually exclusive (the last one wins); both set the
/// `(period, sporadic)` state-publisher tuple. Always present (signature-stable);
/// the beacon-emit timer is `ext-pubsub-sample-miss-detection`-gated, so the
/// option is a documented no-op when the feature is off.
#[derive(Clone, Copy, Debug, Default)]
pub struct MissDetectionConfig {
    /// `Some((period, sporadic))` enables the heartbeat beacon: every `period`
    /// the publisher emits its last published sn. `sporadic = false` emits every
    /// period regardless; `true` emits only when the sn advanced since the last
    /// beacon (zenoh advanced_publisher.rs:385-419).
    state_publisher: Option<(Duration, bool)>,
}

impl MissDetectionConfig {
    /// Periodic heartbeat: emit the last sn every `period` (zenoh
    /// `MissDetectionConfig::heartbeat`).
    pub fn heartbeat(mut self, period: Duration) -> Self {
        self.state_publisher = Some((period, false));
        self
    }

    /// Sporadic heartbeat: emit the last sn every `period` but only when it
    /// changed since the last beacon (zenoh `sporadic_heartbeat`).
    pub fn sporadic_heartbeat(mut self, period: Duration) -> Self {
        self.state_publisher = Some((period, true));
        self
    }
}

/// R311y562 — per-put value metadata for [`AdvancedPublisherOn::put_with`].
///
/// Deliberately just the two fields upstream lets a caller set on an advanced
/// put. `ze_advanced_publisher_put` takes the caller's whole
/// `ze_advanced_publisher_put_options_t` and then overwrites
/// `put_options.timestamp` and `put_options.source_info` with the publisher's
/// own sequencing values before publishing
/// (`vendor/zenoh-pico/src/api/advanced_publisher.c:396-407`) — so on this
/// publisher those two are not caller-settable anywhere, and modelling them
/// here would advertise a knob whose value is discarded one line later.
///
/// `#[non_exhaustive]`, matching [`AdvancedPublisherOptions`]: the QoS trio
/// (priority / congestion control / express) also rides upstream's struct and
/// is a later round's wiring, which must not break a struct literal here.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct AdvancedPutOptions {
    /// The value's encoding — the inner `MsgPut` E-flag. Rides both the wire
    /// publish and the cache entry, so a recovered sample renders identically.
    pub encoding: Option<wz_session_core::sample::EncodingHint>,
    /// An opaque attachment side-band — the inner body ext id 0x03. Put-only
    /// on the wire, so there is no delete-side counterpart.
    pub attachment: Option<Vec<u8>>,
}

impl AdvancedPutOptions {
    /// Set the value encoding.
    pub fn with_encoding(mut self, encoding: wz_session_core::sample::EncodingHint) -> Self {
        self.encoding = Some(encoding);
        self
    }
    /// Set the attachment side-band.
    pub fn with_attachment(mut self, attachment: impl Into<Vec<u8>>) -> Self {
        self.attachment = Some(attachment.into());
        self
    }
}

/// Construction options for an advanced publisher.
///
/// R311y93 (review S3) — `#[non_exhaustive]` for additive-field stability (the
/// sibling advanced-subscriber options and [`AdvancedPublisherError`] carry it
/// too): a future option field cannot break a downstream struct-literal
/// construction. External callers build from [`Default`] plus the public fields;
/// in-crate construction is unaffected.
/// R2619 — NO LONGER `Copy`: [`Self::publisher_detection_metadata`] is a
/// caller-supplied key expression and so owns a `String`. This is the same
/// trade the subscriber's options made at R311y826 for the same field on the
/// subscriber side, and it is recorded here so the two read alike. `Clone`
/// stays.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct AdvancedPublisherOptions {
    /// Per-sample tagging mode.
    pub sequencing: Sequencing,
    /// When `Some`, retain published samples in a cache of this depth for
    /// recovery / history (declares the `@adv` cache queryable).
    pub cache: Option<CacheConfig>,
    /// When `true`, declare the `@adv` liveliness token so subscribers can
    /// detect this publisher (zenoh `publisher_detection`).
    pub publisher_detection: bool,
    /// R311y85 — last-sample-miss-detection: when its `state_publisher` is set,
    /// start the heartbeat beacon on the plane's timer. Requires `SequenceNumber`
    /// sequencing and the `ext-pubsub-sample-miss-detection` feature (a documented
    /// no-op otherwise). Where the timer runs is the plane's: the tokio runtime
    /// runs it on the process's own `net` runtime, as upstream's does, so the
    /// declaring thread need not be inside a tokio runtime (R3064).
    pub sample_miss_detection: MissDetectionConfig,
    /// R2618 — the publisher-side locality predicate, upstream's
    /// `zenoh-ext/src/advanced_publisher.rs` @ `pub fn allowed_destination(mut self, destination: Locality) -> Self {`.
    pub allowed_destination: Locality,
    /// R2618 — the link-layer reliability hint, upstream's
    /// `zenoh-ext/src/advanced_publisher.rs` @ `pub fn reliability(self, reliability: Reliability) -> Self {`.
    pub reliability: Reliability,
    /// R2618 — the outer QoS priority, upstream's
    /// `zenoh-ext/src/advanced_publisher.rs` @ `fn priority(self, priority: Priority) -> Self {`.
    ///
    /// A DOCUMENTED NO-OP without the `pubsub-qos` feature, exactly as
    /// `sample_miss_detection` is without its own: the setter this folds into
    /// is gated, and `ext-pubsub-advanced-publisher` does not compose it. The
    /// field is ungated so a struct literal keeps compiling either way, which
    /// is the same shape [`AdvancedPutOptions`]'s encoding / attachment take.
    pub priority: Priority,
    /// R2618 — congestion control, upstream's
    /// `zenoh-ext/src/advanced_publisher.rs` @ `fn congestion_control(self, congestion_control: CongestionControl) -> Self {`.
    /// `pubsub-qos`-gated in effect, as [`Self::priority`] documents.
    pub congestion_control: CongestionControl,
    /// R2618 — the express (no-batching) bit, upstream's
    /// `zenoh-ext/src/advanced_publisher.rs` @ `fn express(self, is_express: bool) -> Self {`.
    /// `pubsub-qos`-gated in effect, as [`Self::priority`] documents.
    pub express: bool,
    /// R2619 — application metadata carried in the publisher's `@adv` key
    /// expression, upstream's
    /// `zenoh-ext/src/advanced_publisher.rs` @ `pub fn publisher_detection_metadata<TryIntoKeyExpr>(mut self, meta: TryIntoKeyExpr) -> Self`.
    ///
    /// `None` (default) keeps the `_` routing-workaround chunk this publisher
    /// always emitted. A value SUBSTITUTES for that chunk and may be
    /// multi-chunk, matching the subscriber side's long-standing shape.
    ///
    /// ⚠ A value makes the derived `@adv` expression depend on caller input, so
    /// it is validated at declare time: a chunk that would not survive
    /// canonisation is refused as
    /// [`AdvancedPublisherError::InvalidAdvKeyexpr`] rather than put on the
    /// wire. That check already guarded this expression; this field is the
    /// first thing that gives it a subject.
    pub publisher_detection_metadata: Option<String>,
}

/// R2618 — the five wire knobs an advanced publisher carries, folded onto
/// EVERY publish it makes through ONE function.
///
/// The fold is a type rather than a chain repeated at each call site because
/// there are two of them -- the Put and the Del -- and they have already drifted
/// once on exactly this axis: the Del site documents that it deliberately omits
/// the encoding / attachment chain, which is correct for those two and would be
/// wrong for these five. QoS, locality and reliability are properties of the
/// PUBLISHER, so a Del must carry them as a Put does; keeping them in one place
/// is what stops the next edit applying them to one arm only.
#[derive(Clone, Copy, Debug)]
struct WireQos {
    allowed_destination: Locality,
    reliability: Reliability,
    #[cfg_attr(not(feature = "pubsub-qos"), allow(dead_code))]
    priority: Priority,
    #[cfg_attr(not(feature = "pubsub-qos"), allow(dead_code))]
    congestion_control: CongestionControl,
    #[cfg_attr(not(feature = "pubsub-qos"), allow(dead_code))]
    express: bool,
}

impl WireQos {
    fn from_options(options: &AdvancedPublisherOptions) -> Self {
        Self {
            allowed_destination: options.allowed_destination,
            reliability: options.reliability,
            priority: options.priority,
            congestion_control: options.congestion_control,
            express: options.express,
        }
    }

    /// Fold these knobs onto a publish. Each gated call sits behind the gate of
    /// the SETTER it calls, which is the discipline the encoding / attachment
    /// folds in this file already record paying for: an ungated call compiles
    /// under this crate's default features and breaks the `wz` facade's
    /// `--features ext-pubsub-advanced-publisher` build.
    fn apply(&self, opts: PublishOptions) -> PublishOptions {
        let opts = opts
            .with_locality(self.allowed_destination)
            .with_reliability(self.reliability);
        // ⚠ THE QOS FOLD IS CONDITIONAL, AND THE CONTROL IS WHY. Applied
        // unconditionally it ATTACHES a qos byte where a bare `put()` carries
        // none: measured, a default advanced publisher went from `None` to
        // `Some(5)` -- `Priority::DEFAULT` written out explicitly. In this tree
        // an ABSENT qos already MEANS the defaults ("No QoS attached -> DEFAULT
        // conduit band (byte-identical to a pre-QoS send)", the sibling pin in
        // the tokio session's tests), so writing them is not a no-op on the wire: it
        // adds an extension every default publisher would suddenly emit.
        //
        // So the byte is attached only when one of the three actually departs
        // from the wire default. That is what makes "a default config publishes
        // what it published before" true rather than merely claimed, and the
        // second arm of the witness grades exactly this.
        #[cfg(feature = "pubsub-qos")]
        let opts = if self.priority != Priority::DEFAULT
            || self.congestion_control != CongestionControl::Drop
            || self.express
        {
            opts.with_priority(self.priority)
                .with_congestion_control(self.congestion_control)
                .with_express(self.express)
        } else {
            opts
        };
        opts
    }
}

impl Default for AdvancedPublisherOptions {
    fn default() -> Self {
        Self {
            sequencing: Sequencing::SequenceNumber,
            cache: Some(CacheConfig::default()),
            publisher_detection: true,
            sample_miss_detection: MissDetectionConfig::default(),
            // R2618 — the five defaults are the PUBLISH path's own, not a
            // second opinion about them: `PublishOptions::put()` starts at
            // these values, so an `AdvancedPublisherOptions::default()`
            // publishes byte-identically to before this round.
            allowed_destination: Locality::default(),
            reliability: Reliability::default(),
            // `Priority` and `CongestionControl` implement no `Default` — they
            // carry NAMED wire defaults instead, and those names are what the
            // publish path means by "unset": `Priority::DEFAULT` is `Data`
            // (`Z_PRIORITY_DEFAULT`) and `Z_CONGESTION_CONTROL_DEFAULT` is
            // `Drop`. Spelling them rather than reaching for a derive is the
            // point: a `Default` impl on those enums would be a SECOND opinion
            // about a value the wire already fixes.
            priority: Priority::DEFAULT,
            congestion_control: CongestionControl::Drop,
            express: false,
            publisher_detection_metadata: None,
        }
    }
}

/// A refusal a plane gave for one of the entities it declares, in the plane's own terms.
///
/// The composition does not know what a plane's declarations can fail with: a runtime session's are
/// its queryable and token errors, a C session's a pico result code. The plane boxes its own error
/// and the composite reports it unchanged, so the cause is readable and nothing about it is
/// flattened to a string.
#[derive(Debug)]
pub struct PlaneError(Box<dyn std::error::Error + Send + Sync + 'static>);

impl PlaneError {
    /// Wrap a plane's own error.
    pub fn new(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self(Box::new(error))
    }

    /// The error the plane gave.
    pub fn cause(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
        &*self.0
    }
}

impl std::fmt::Display for PlaneError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for PlaneError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.0)
    }
}

/// Why declaring an advanced publisher failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum AdvancedPublisherError {
    /// `local_zid` was empty or longer than 16 bytes (the `SourceInfo`
    /// wire constraint).
    InvalidZid,
    /// The cache queryable declaration was rejected.
    Cache(PlaneError),
    /// The `@adv` liveliness token declaration was rejected.
    Token(PlaneError),
    /// R2485 — [`Sequencing::Timestamp`] was asked for on a node that does not
    /// stamp, so the timestamps this publisher's downstream de-duplication
    /// keys on would not come from an HLC at all.
    ///
    /// Upstream refuses the same construction rather than degrading it:
    /// `zenoh-ext/src/advanced_publisher.rs` @ `if conf.session.hlc().is_none() {`
    /// guards a `bail!` naming the `timestamping` setting. wz models the same
    /// absence — [`NodeHlc`] holds an `Option` and answers
    /// [`is_stamping`](NodeHlc::is_stamping) `false` for a
    /// role whose `timestamping.enabled` entry is off — so the state upstream
    /// refuses to build on is reachable here and gets the same answer.
    ///
    /// The alternative wz used to take was silent: `FallbackStamp` would hand
    /// out wall-clock stamps and the `@adv` keyexpr would still advertise the
    /// `uhlc` discriminator, so a subscriber de-duplicating on those timestamps
    /// was told they were HLC-quality when they were not.
    TimestampingDisabled,
    /// R2559 — the derived `@adv` key expression is not safe to put on the
    /// wire: it either does not parse as a key expression, or it carries the
    /// R299 bug-3 shape that zenoh-pico's canonizer aborts on (a peer
    /// application that canonizes or joins the received key, not the receive
    /// path itself — see the witness test for the measured caller set).
    ///
    /// Upstream cannot reach this state at all. Its suffix is assembled from
    /// already-validated `KeyExpr` values by `Div`
    /// (`zenoh-ext/src/advanced_publisher.rs` @ `let suffix = KE_ADV_PREFIX / KE_PUB / &id.zid().into_keyexpr();`),
    /// so the derived expression is well-formed BY CONSTRUCTION and the only
    /// construction-time failure left for it to propagate is the declaration
    /// itself. wz takes the base as `impl Into<String>`, so the invalid state is
    /// representable here and has to be refused somewhere.
    ///
    /// ⚠ IT USED TO BE REFUSED ONLY BY A CONFIGURATION ACCIDENT, which is the
    /// measurement that put this variant here. The DECLARE seam gates what it
    /// is handed
    /// (`crates/wz-session-core/src/session_actions.rs` @ `check_outbound_keyexpr_pico_safe(suffix)?;`),
    /// so the cache queryable and the liveliness token both refused. The beacon
    /// is a PUSH, and no `send_push_*` seam carries that gate — so with
    /// detection off and a heartbeat on, the SAME base string declared `Ok`,
    /// published `Ok`, and answered `true` from
    /// [`AdvancedPublisherOn::emit_heartbeat_once`]. Two configurations of one
    /// publisher gave two answers about one string, and the beacon-only arm gave
    /// the wrong one silently.
    ///
    /// ⚠ MEASURED, because the obvious reading is wrong: that beacon publish was
    /// not failing and having its error dropped. There was no error. A session's
    /// publish answers `Ok` on an ill-formed keyexpr, so the beacon put a
    /// non-expression on the wire and no caller could learn it.
    InvalidAdvKeyexpr(wz_session_core::keyexpr_canon::OutboundKeyexprError),
    /// The plane the publisher was declared on could not declare one of its
    /// entities, for a reason of its own — a key table out of ids, say. The
    /// plane names the reason; a runtime session never raises this.
    Plane(String),
}

/// A plain publisher a plane declared for an advanced one, with the entity id it
/// reports.
pub struct DeclaredPublisher<H> {
    /// The plane's handle: dropping it retracts the publisher.
    pub handle: H,
    /// The publisher's entity id — the `eid` half of its `(zid, eid)` global id,
    /// stamped into every sample's `SourceInfo` and rendered into the `@adv`
    /// key.
    pub eid: u32,
}

/// A chunk of shared memory an advanced publisher puts: its bytes, for a peer that did not
/// negotiate shared memory, and the handle a descriptor is sent from, for one that did.
///
/// The composition writes a chunk put exactly as it writes a bytes put (the same sequence number,
/// the same stamping, the same QoS), so what a chunk IS belongs to the runtime that maps segments
/// and the composite only asks for these two things of it. A plane that holds the concrete type
/// gets it back through [`Self::into_any`].
#[cfg(feature = "transport-shm")]
pub trait ShmChunk: Send + Sync + 'static {
    /// The chunk's bytes, read in place.
    fn bytes(&self) -> &[u8];

    /// The handle the sample is cached by and the descriptor is sent from: the chunk stays
    /// allocated for as long as the handle is held.
    fn send_handle(self: Arc<Self>) -> wz_session_core::extshm::ShmSendHandle;

    /// The concrete value behind the trait object, for a plane that sends a descriptor.
    fn into_any(self: Arc<Self>) -> Arc<dyn std::any::Any + Send + Sync>;
}

/// WHERE an advanced publisher lives: what declares its entities and what
/// carries its samples.
///
/// An advanced publisher is a composition — a plain publisher, a cache queryable,
/// a liveliness token and a beacon publisher — and each of those four is
/// declared differently by the host that owns the session. On a runtime
/// session they are the plain declarations; on a C
/// session they are the planes of one shared key table, each announced under a
/// declared key id and retracted in the order the reference library retracts
/// them. The composition itself — what is validated, in what order the four are
/// declared, what each put stamps and retains, what a beacon says — is the same
/// on both, so it is written once, in [`AdvancedPublisherOn`], and a host
/// supplies only the four declarations, the sends and the timer.
///
/// Every handle a plane returns retracts its entity when dropped. The composite
/// fixes the ORDER those drops run in ([`AdvancedPublisherOn`]'s field order), so
/// a plane does not have to.
pub trait AdvancedPublisherPlane: Send + Sync + 'static {
    /// The plain publisher the advanced one wraps.
    type Publisher: Send + 'static;
    /// The cache queryable.
    type Queryable: Send + 'static;
    /// The `@adv` liveliness token.
    type Token: Send + 'static;
    /// The publisher the heartbeat beacon is sent on.
    type Beacon: Send + Sync + 'static;
    /// What keeps the beacon's period running: dropping it stops the timer, and the composite drops
    /// it before it retracts the beacon's publisher. A plane without a timer (or a build without
    /// miss detection) uses `()`.
    type Timer: Send + 'static;

    /// The node's HLC, which stamps every sample.
    fn node_hlc(&self) -> &NodeHlc;

    /// Whether this host has a clock to stamp timestamps from — the
    /// precondition of timestamp sequencing (R2485). A runtime session has one
    /// when its node's HLC exists, which is zenoh's own rule; a host whose
    /// timestamps never depended on that says so.
    fn stamps(&self) -> bool {
        self.node_hlc().is_stamping()
    }

    /// Declare the plain publisher on `keyexpr`. The wire knobs in `options` are
    /// the advanced publisher's own, folded the way its puts carry them.
    fn declare_publisher(
        &self,
        keyexpr: &str,
        options: PublishOptions,
    ) -> Result<DeclaredPublisher<Self::Publisher>, AdvancedPublisherError>;

    /// Declare the cache queryable on the `@adv` key, answering out of `store`.
    ///
    /// The plane asks the store for as many handlers as it has peers to answer
    /// ([`CacheStore::query_handler`], given the clock the plane reads wall time from): each is a
    /// fresh closure over the same ring.
    fn declare_cache_queryable(
        &self,
        keyexpr: &str,
        store: &CacheStore,
    ) -> Result<Self::Queryable, AdvancedPublisherError>;

    /// Declare the `@adv` liveliness token.
    fn declare_token(&self, keyexpr: &str) -> Result<Self::Token, AdvancedPublisherError>;

    /// Declare the publisher the heartbeat beacon is sent on, `sporadic` saying
    /// which arm it belongs to.
    fn declare_beacon(
        &self,
        keyexpr: &str,
        sporadic: bool,
    ) -> Result<Self::Beacon, AdvancedPublisherError>;

    /// Run `tick` every `period`, until it answers `false` or the returned timer is dropped.
    ///
    /// The beacon's decision, whether it is due and what it says, is the composite's; the timer is
    /// the host's, because a clock and a way to wait are the host's. A tokio runtime sleeps on its
    /// own clock in a task of the process's `net` runtime, and the cooperative engine runs the tick
    /// from the step that moves its session. `period` is at least a millisecond: the composite
    /// clamps it, so a timer need not guard against a spin.
    fn start_beacon_timer(
        &self,
        period: Duration,
        tick: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Self::Timer;

    /// Send one sample on the publisher's key. The byte count is what the
    /// session reports; a plane that held the sample back (a closed write
    /// filter) answers `Ok(0)`, which is a put with no recipient and not an
    /// error.
    fn publish(
        &self,
        publisher: &Self::Publisher,
        keyexpr: &str,
        payload: &[u8],
        options: PublishOptions,
    ) -> Result<usize, PublishError>;

    /// R3063 -- send one sample whose payload is a CHUNK of shared memory: the descriptor to a peer
    /// that negotiated shared memory, the bytes to one that did not, and the chunk to a subscriber of
    /// this very session, which is what a plane that can map the segment owes.
    ///
    /// The default sends the chunk's BYTES through [`Self::publish`], which is every plane's
    /// correct answer when it cannot carry a descriptor (the pico plane has no segment to map), and
    /// loses nothing but the saving.
    #[cfg(feature = "transport-shm")]
    fn publish_shm(
        &self,
        publisher: &Self::Publisher,
        keyexpr: &str,
        payload: &Arc<dyn ShmChunk>,
        options: PublishOptions,
    ) -> Result<usize, PublishError> {
        self.publish(publisher, keyexpr, payload.bytes(), options)
    }

    /// Send one heartbeat beacon, on `beacon` when the publisher declared one
    /// and on the key itself when it did not (an on-demand beacon from a
    /// publisher with no heartbeat configured). A failure is non-fatal: the next
    /// tick re-sends.
    fn publish_beacon(
        &self,
        beacon: Option<&Self::Beacon>,
        keyexpr: &str,
        payload: &[u8],
        sporadic: bool,
    );

    /// What a cached sample keeps alive so the publisher's key stays declared
    /// while the ring holds it — [`Retained`]. `None` for a plane whose key is
    /// not a declaration.
    fn retained_key(&self, publisher: &Self::Publisher) -> Option<Retained>;
}

/// What one put publishes (R3063): bytes, or a chunk of shared memory. Private, because the public
/// surface is the two methods that build it ([`AdvancedPublisherOn::put_with`],
/// `AdvancedPublisherOn::put_shm_with`), and a third spelling of "what a sample is" would be a
/// third place to keep stamping in step.
enum SamplePayload<'a> {
    Bytes(&'a [u8]),
    #[cfg(feature = "transport-shm")]
    Chunk(&'a Arc<dyn ShmChunk>),
}

/// The cache queryable and the ring it answers from.
///
/// The queryable is listed first so it retracts first, and the ring — whose
/// samples may still keep the publisher's key declared — goes after it.
struct DeclaredCache<P: AdvancedPublisherPlane> {
    _queryable: P::Queryable,
    store: CacheStore,
}

/// The heartbeat beacon: the timer is listed first so it is stopped before the
/// publisher it sends on is retracted.
#[cfg(feature = "ext-pubsub-sample-miss-detection")]
struct DeclaredBeacon<P: AdvancedPublisherPlane> {
    _timer: P::Timer,
    _publisher: Arc<P::Beacon>,
}

/// A live advanced publisher on a [`AdvancedPublisherPlane`]. Owns the wrapped
/// publisher, the (optional) cache, liveliness token and beacon (RAII: dropping
/// it tears them down) and the per-publisher sequence counter.
pub struct AdvancedPublisherOn<P: AdvancedPublisherPlane> {
    // ⚠ THE FIELD ORDER IS THE TEARDOWN ORDER, and it is the reference
    // library's: zenoh-pico retracts the publisher, then the token, then the
    // beacon's publisher, then the cache
    // (`vendor/zenoh-pico/src/api/advanced_publisher.c` @
    // `z_result_t _ze_undeclare_advanced_publisher_clear(_ze_advanced_publisher_t *pub) {`),
    // and rust drops fields in the order they are declared. A host that declares
    // key ids makes the order visible to a peer, because each entity's key goes
    // when its last holder does.
    /// R2619 — THE PLAIN PUBLISHER THIS ONE WRAPS, and the reason it is a field
    /// rather than a set of re-implemented methods: upstream's advanced
    /// publisher IS a wrapper, `zenoh-ext/src/advanced_publisher.rs` @ `pub struct AdvancedPublisher<'a> {`
    /// holding a `Publisher`, and every surface this round adds delegates to it
    /// there — `zenoh-ext/src/advanced_publisher.rs` @ `self.publisher.matching_status()`.
    ///
    /// Declared FIRST, as upstream declares it: the `@adv` entities and the
    /// identity the sequence numbers carry are all derived from it.
    ///
    /// IT IS NOT PUBLISHED THROUGH, and that difference is stated rather than
    /// hidden: wz's `Publisher::put` carries the publisher's FIXED options,
    /// while an advanced put varies timestamp / source_info / encoding /
    /// attachment per sample, so the sends still go through the plane's
    /// `publish`. What holding it buys is the state the matching surface READS —
    /// declaring it is what registers this session's SUBSCRIBERS Interest for
    /// the keyexpr (R2577), so before this round an advanced publisher's
    /// matching status would have consulted a registry nobody had asked the
    /// neighbour to fill. That is the SAME defect R2577 closed for the plain
    /// publisher, and it reached here because this handle was not made of one.
    ///
    /// Built with THIS publisher's folded wire options on purpose: the matching
    /// poll gates on the publisher's own `locality`, so a delegate carrying
    /// different options would answer about a publisher that does not exist.
    publisher: P::Publisher,
    _token: Option<P::Token>,
    /// R311y85 — the heartbeat beacon (the plane's timer plus the publisher it
    /// sends on), `Some` only when `MissDetectionConfig` set a
    /// `state_publisher` + sequencing is on.
    #[cfg(feature = "ext-pubsub-sample-miss-detection")]
    beacon: Option<DeclaredBeacon<P>>,
    cache: Option<DeclaredCache<P>>,
    keyexpr: String,
    zid: Vec<u8>,
    eid: u32,
    seqnum: Option<Arc<AtomicU32>>,
    stamp: FallbackStamp,
    /// R2618 — the publisher's wire knobs, applied to every Put and Del it
    /// makes. See [`WireQos`] for why this is one value rather than a chain at
    /// each site.
    qos: WireQos,
    /// R311y85 — the publisher's `@adv` KE, retained so the heartbeat-beacon
    /// emit (the timer's tick + the `emit_heartbeat_once` seam) can publish on it.
    #[cfg(feature = "ext-pubsub-sample-miss-detection")]
    adv_keyexpr: String,
    /// R2558 — which beacon ARM this publisher is, retained because
    /// [`Self::emit_heartbeat_once`] must publish with the SAME options the
    /// timer does. The sporadic arm blocks under congestion and the periodic
    /// arm does not ([`heartbeat_publish_options`]), so an on-demand beacon
    /// that ignored the arm would be a second opinion about the same publisher.
    #[cfg(feature = "ext-pubsub-sample-miss-detection")]
    heartbeat_sporadic: bool,
    plane: Arc<P>,
}

impl<P: AdvancedPublisherPlane> AdvancedPublisherOn<P> {
    /// Declare an advanced publisher on `plane`.
    ///
    /// The order is the reference library's
    /// (`vendor/zenoh-pico/src/api/advanced_publisher.c` @
    /// `z_result_t ze_declare_advanced_publisher(const z_loaned_session_t *zs, ze_owned_advanced_publisher_t *pub,`):
    /// the plain publisher first, then the cache queryable, the liveliness token
    /// and the beacon's publisher. Everything that can be refused without a
    /// declaration is refused BEFORE the first one, so a refusal does not put a
    /// publisher on the wire only to retract it.
    pub fn declare_on(
        plane: Arc<P>,
        keyexpr: impl Into<String>,
        options: AdvancedPublisherOptions,
        local_zid: Vec<u8>,
    ) -> Result<Self, AdvancedPublisherError> {
        if local_zid.is_empty() || local_zid.len() > 16 {
            return Err(AdvancedPublisherError::InvalidZid);
        }

        // R2558 — ASKING FOR MISS DETECTION *IS* ASKING FOR SEQUENCE NUMBERS,
        // and until now wz let a caller state otherwise and then quietly did
        // nothing.
        //
        // Upstream has NO sequencing knob: `Sequencing` is `pub(crate)` there
        // and the field is private, so the mode is never a user choice at all —
        // it is DERIVED from what was requested.
        // `zenoh-ext/src/advanced_publisher.rs` @ `pub fn sample_miss_detection(mut self, config: MissDetectionConfig) -> Self {`
        // assigns `Sequencing::SequenceNumber` as its FIRST statement, and
        // `zenoh-ext/src/advanced_publisher.rs` @ `pub fn cache(mut self, config: CacheConfig) -> Self {`
        // raises `None` to `Timestamp` the same way. The invalid pair is
        // unrepresentable there by construction.
        //
        // wz exposes the knob (a superset, and its own three sequencing modes
        // are real), so the pair IS representable here — which is why the
        // request has to win somewhere. It wins HERE rather than in a setter
        // because the fields are `pub`: a setter can be bypassed by a struct
        // literal or a later assignment, and this is the one point every caller
        // passes through, the C API included.
        //
        // ⚠ THE OLD BEHAVIOUR WAS THE WORST OF THE THREE OPTIONS. It did not
        // refuse and it did not honour: `heartbeat_spawn_params` gates on
        // `(state_publisher, sequencing)` and simply yielded `None`, so the
        // publisher declared fine, published fine, and never beaconed — a
        // caller who asked for miss detection got silence, with nothing to read
        // it off. A documented no-op is a representable invalid state.
        #[cfg(feature = "ext-pubsub-sample-miss-detection")]
        let options = {
            let mut options = options;
            if options.sample_miss_detection.state_publisher.is_some() {
                options.sequencing = Sequencing::SequenceNumber;
            }
            options
        };

        // R2485 — refuse `Sequencing::Timestamp` on a node that does not stamp,
        // which is upstream's own precondition
        // (`zenoh-ext/src/advanced_publisher.rs` @ `if conf.session.hlc().is_none() {`).
        // Checked here, beside the other preconditions and BEFORE the cache /
        // token declarations, so a refusal never leaves a half-declared
        // publisher to roll back. See [`AdvancedPublisherError::TimestampingDisabled`]
        // for why degrading to the wall clock is worse than refusing.
        if options.sequencing == Sequencing::Timestamp && !plane.stamps() {
            return Err(AdvancedPublisherError::TimestampingDisabled);
        }

        // R3064 -- there is no off-runtime precondition here, and the one R311y90
        // put here was false from R2366 on. The heartbeat beacon was a bare
        // `tokio::spawn`, which PANICS without a runtime, so a declare off one was
        // refused with a variant of its own; R2366 moved the beacon onto the
        // process's `net` runtime, as upstream spawns the same task, and nothing
        // the declare does asks the calling thread for a runtime any more. What
        // survived was a refusal of a declaration that would have worked, and on a
        // C session that is the ordinary case: the in-process plane is declared
        // from the C application thread, the refusal was swallowed by the
        // best-effort fan-out, and the publisher beaconed to nobody and put to
        // nobody while the declare reported success.
        let keyexpr = keyexpr.into();

        // `@adv/pub/<zid>/<eid|uhlc>/_` — the detection + recovery suffix
        // (zenoh advanced_publisher.rs:317-329). The `<eid>` discriminator
        // marks sequence-number sequencing; `uhlc` marks timestamp/none. The
        // KE shape is the shared `@adv` SSOT ([`crate::advanced_ke`]).
        // R2552 — the timestamped spelling comes from the `@adv` SSOT rather
        // than from a literal here: the subscriber must read the same chunk
        // this writes, and two independent literals are how one wire
        // vocabulary drifts into two.
        //
        // A function of the entity id rather than a value, because the id is
        // the wrapped publisher's and does not exist until that is declared —
        // while the check below has to run before anything is. The id is the
        // `<eid>` chunk's digits and cannot change whether the expression parses,
        // so the check reads it with id 0 and the declarations read the real one.
        let adv_keyexpr_for = |eid: u32| {
            let discriminator = match options.sequencing {
                Sequencing::SequenceNumber => eid.to_string(),
                Sequencing::Timestamp | Sequencing::None => {
                    crate::advanced_ke::KE_ADV_UHLC.to_string()
                }
            };
            crate::advanced_ke::publisher_adv_ke(
                &keyexpr,
                &zid_to_zenoh_hex(&local_zid),
                &discriminator,
                options.publisher_detection_metadata.as_deref(),
            )
        };

        // R2559 — THE DERIVED `@adv` EXPRESSION HAS TO PARSE AS A KEY
        // EXPRESSION, and this is the one place that can say so for every
        // configuration at once.
        //
        // Upstream never needs the check: its suffix is `Div`-composed from
        // values that are already `KeyExpr`, so the derived expression is
        // well-formed by construction and the only thing its constructor has
        // left to propagate is the beacon publisher's own declaration
        // (`zenoh-ext/src/advanced_publisher.rs` @ `let publisher = conf.session.declare_publisher(&key_expr / &suffix).wait()?;`).
        // wz takes the base as `impl Into<String>`, so the ill-formed state is
        // representable here — and a representable invalid state has to be
        // refused, not discovered later.
        //
        // ⚠ WHAT WAS MEASURED, because the shape is the whole argument for
        // putting the check HERE rather than on the beacon: the refusal already
        // existed, but it belonged to an unrelated option. `declare_token`
        // validates its own input, so `publisher_detection: true` on
        // `demo/foo?bar` was refused at declare — while the same base with
        // detection off and a heartbeat on returned `Ok`, put `Ok`, and answered
        // `true` from `emit_heartbeat_once`. One string, two configurations, two
        // answers, and the silent one is the arm this atom is about.
        //
        // ⚠ AND THE SILENCE IS NOT WHERE IT LOOKS. The `let _ =` on the beacon
        // publish is not swallowing an error: MEASURED, that publish returns
        // `Ok` on an ill-formed keyexpr, because no `send_push_*` seam validates
        // one — only the DECLARE seam does. So there was nothing to swallow, and
        // no amount of checking the beacon's own result would have found this.
        //
        // THE PREDICATE IS THE DECLARE SEAM'S OWN FUNCTION, and the first draft
        // of this check got that wrong in a way worth recording, because the
        // comment asserted a binding the code did not have. It called
        // `canonize_keyexpr` and claimed to be "the same predicate
        // `declare_token` refuses through". It is not: the seam refuses through
        // `check_outbound_keyexpr_pico_safe`
        // (`crates/wz-session-core/src/session_actions.rs` @ `check_outbound_keyexpr_pico_safe(suffix)?;`),
        // which is canon PLUS the R299 bug-3 family — the `**` + literal + `*`
        // shape pico's canonizer aborts on. Canon alone ACCEPTS that shape,
        // because the shape IS canonical; that is the whole reason the seam
        // needs a second arm and a canon-only check cannot stand in for it.
        //
        // MEASURED, on `demo/**/c/*`: the beacon-only arm declared `Ok` while
        // the detection arm refused with
        // `PicoBugThreeFamily { offending_chunk: "*" }`. So the very defect this
        // check exists to remove — one string, two configurations, two answers —
        // survived the first draft inside a narrower and WORSE band, where the
        // beacon does not merely put a non-expression on the wire but one whose
        // canonizer a pico application aborts on (the witness test records the
        // measured caller set — no receive path reaches it). A predicate that is a subset of the
        // one it claims to match is not a second opinion; it is the same
        // disagreement with a smaller domain.
        //
        // Calling the seam's own function is what makes "the two legs cannot
        // drift apart" true rather than asserted. Its OUTPUT is nothing — it
        // answers pass/fail and rewrites nothing — which is also what this site
        // needs: the wire path emits the suffix verbatim, so canonizing here
        // would silently rewrite a keyexpr the caller and the subscriber both
        // spell the other way.
        //
        // Placed before the FIRST declaration, the wrapped publisher's included,
        // so a refusal never leaves a half-declared publisher to roll back — the
        // same ordering rule the `TimestampingDisabled` precondition above is
        // placed by. That costs nothing the old order
        // bought: it burnt an entity id on a refusal, and this burns none.
        wz_session_core::keyexpr_canon::check_outbound_keyexpr_pico_safe(&adv_keyexpr_for(0))
            .map_err(AdvancedPublisherError::InvalidAdvKeyexpr)?;

        // R2619 — the wrapped publisher, FIRST, with the same folded options the
        // sends carry. Its entity id is this publisher's identity.
        let qos = WireQos::from_options(&options);
        let DeclaredPublisher {
            handle: publisher,
            eid,
        } = plane.declare_publisher(&keyexpr, qos.apply(PublishOptions::put()))?;
        let adv_keyexpr = adv_keyexpr_for(eid);

        let cache = match options.cache {
            Some(config) => {
                let store = CacheStore::new(config);
                let queryable = plane.declare_cache_queryable(&adv_keyexpr, &store)?;
                Some(DeclaredCache {
                    _queryable: queryable,
                    store,
                })
            }
            None => None,
        };

        let token = if options.publisher_detection {
            Some(plane.declare_token(&adv_keyexpr)?)
        } else {
            None
        };

        let seqnum = match options.sequencing {
            Sequencing::SequenceNumber => Some(Arc::new(AtomicU32::new(0))),
            Sequencing::Timestamp | Sequencing::None => None,
        };

        // R311y85 — the heartbeat beacon: every `period`, publish the last
        // published sn (`z_serialize::<u32>(seqnum-1)`) on the `@adv` KE so a
        // heartbeat-recovering subscriber can detect + recover a lost last
        // sample (zenoh advanced_publisher.rs:373-419). Needs the `SequenceNumber`
        // seqnum (no seqnum -> no beacon); sporadic emits only when the sn
        // advanced. The plane runs the period and calls the tick, which is thin
        // glue over the deterministic `emit_heartbeat`.
        #[cfg(feature = "ext-pubsub-sample-miss-detection")]
        let beacon = match heartbeat_spawn_params(&options).zip(seqnum.as_ref()) {
            // `zip(seqnum.as_ref())`: `heartbeat_spawn_params` already requires
            // `SequenceNumber`, so `seqnum` is `Some` whenever it returns `Some` —
            // the zip never drops a configured beacon, it just pairs the params with
            // the counter without an unwrap.
            Some(((period, sporadic), seqnum)) => {
                // The beacon's own publisher is declared AFTER the token, as the
                // reference library declares it; the timer that drives it is
                // started only once it stands.
                let publisher = Arc::new(plane.declare_beacon(&adv_keyexpr, sporadic)?);
                // Weakly, so the timer never holds the publisher past its own
                // teardown: the publisher's retraction is a peer-visible event
                // and runs when the handle drops, not when a stopped timer's
                // next tick is polled.
                let hb_publisher = Arc::downgrade(&publisher);
                let hb_plane = Arc::clone(&plane);
                let hb_keyexpr = adv_keyexpr.clone();
                let hb_seqnum = Arc::clone(seqnum);
                let last_emitted = AtomicU32::new(0);
                // R311y87 (review C4) — clamp to >=1ms: a sub-ms Duration
                // truncates to 0, turning the beacon loop into a busy spin.
                let period_ms = (period.as_millis() as u64).max(1);
                let tick: Arc<dyn Fn() -> bool + Send + Sync> = Arc::new(move || {
                    let Some(publisher) = hb_publisher.upgrade() else {
                        // The publisher is gone: the timer is told to stop.
                        return false;
                    };
                    let sn = hb_seqnum.load(Ordering::Relaxed);
                    // Non-sporadic emits every tick (emit_heartbeat skips
                    // sn==0); sporadic only when the sn advanced.
                    if should_emit_heartbeat(sporadic, sn, last_emitted.load(Ordering::Relaxed))
                        && emit_heartbeat(&*hb_plane, Some(&*publisher), &hb_keyexpr, sn, sporadic)
                    {
                        last_emitted.store(sn, Ordering::Relaxed);
                    }
                    true
                });
                Some(DeclaredBeacon::<P> {
                    _timer: plane.start_beacon_timer(Duration::from_millis(period_ms), tick),
                    _publisher: publisher,
                })
            }
            None => None,
        };

        // adv_keyexpr is consumed by the cache / token declarations + (feature-on)
        // the struct; explicitly drop it on the feature-off path so the
        // cache-None + detection-false combination does not warn unused.
        #[cfg(not(feature = "ext-pubsub-sample-miss-detection"))]
        let _ = adv_keyexpr;

        Ok(Self {
            publisher,
            _token: token,
            #[cfg(feature = "ext-pubsub-sample-miss-detection")]
            beacon,
            cache,
            keyexpr,
            eid,
            seqnum,
            // R311y450 — the §5.18 clock is BORROWED from the session (an Arc
            // bump), not constructed here. Building one from `local_zid` is what
            // made this site and the storage service's the two same-`uhlc::ID`
            // clocks the round removed.
            stamp: FallbackStamp::new(local_zid.clone(), plane.node_hlc().clone()),
            zid: local_zid,
            qos,
            #[cfg(feature = "ext-pubsub-sample-miss-detection")]
            adv_keyexpr,
            #[cfg(feature = "ext-pubsub-sample-miss-detection")]
            heartbeat_sporadic: heartbeat_spawn_params(&options)
                .map(|(_, sporadic)| sporadic)
                .unwrap_or(false),
            plane,
        })
    }

    /// Publish `payload` with no value metadata — [`Self::put_with`] under
    /// [`AdvancedPutOptions::default`]. Returns the session's publish byte
    /// count.
    pub fn put(&self, payload: &[u8]) -> Result<usize, PublishError> {
        self.put_with(payload, AdvancedPutOptions::default())
    }

    /// R311y562 — publish `payload` carrying a value `encoding` and/or an
    /// opaque `attachment`, stamping the next `SourceInfo` sequence number
    /// (in `SequenceNumber` mode) + a timestamp, and retaining the sample —
    /// metadata included — in the cache.
    ///
    /// These are exactly the two fields upstream's advanced put lets a caller
    /// set. `ze_advanced_publisher_put` copies the caller's options and then
    /// OVERWRITES `put_options.timestamp` and `put_options.source_info` with
    /// the publisher's own sequencing values
    /// (`vendor/zenoh-pico/src/api/advanced_publisher.c:402-407`), so those two
    /// are the publisher's to own and are deliberately NOT parameters here —
    /// letting a caller supply an `sn` would break the miss-detection contract
    /// the shared counter exists to hold. Encoding and attachment pass straight
    /// through to `_z_publisher_put_impl`, which is handed `pub->_cache`, so
    /// upstream's cache retains them with the sample.
    pub fn put_with(
        &self,
        payload: &[u8],
        options: AdvancedPutOptions,
    ) -> Result<usize, PublishError> {
        self.put_sample(SamplePayload::Bytes(payload), options)
    }

    /// R3063 -- [`Self::put_with`] for a payload that is a CHUNK of shared memory: the same
    /// stamping, the same sequence number, the same QoS, and the sample goes out through the plane's
    /// shared-memory send ([`AdvancedPublisherPlane::publish_shm`]) and is cached as the chunk, not as
    /// a copy of its bytes, so a recovery reply replays it as shared memory too.
    #[cfg(feature = "transport-shm")]
    pub fn put_shm_with(
        &self,
        payload: &Arc<dyn ShmChunk>,
        options: AdvancedPutOptions,
    ) -> Result<usize, PublishError> {
        self.put_sample(SamplePayload::Chunk(payload), options)
    }

    /// The one body of [`Self::put_with`] and `put_shm_with`: what a put stamps and
    /// retains is written once, so a chunk and bytes cannot be sequenced differently.
    fn put_sample(
        &self,
        payload: SamplePayload<'_>,
        options: AdvancedPutOptions,
    ) -> Result<usize, PublishError> {
        // fetch_add returns the pre-increment value, so the first sample
        // carries sn=0 (zenoh advanced_publisher.rs:490-501).
        let sn = self
            .seqnum
            .as_ref()
            .map(|counter| counter.fetch_add(1, Ordering::Relaxed));
        let timestamp = self.stamp.stamp();

        // Construct the SourceInfo ONCE (SSOT): the same `(zid, eid, sn)` rides
        // BOTH the wire publish (pubsub-source-info) AND the cache ring, so a
        // recovery reply re-stamps the identical identity the live sample
        // carried. zenoh caches the whole `Sample` with its `SourceInfo`; this
        // mirrors that without the prior dual source_sn-vs-SourceInfo::new
        // construction. `None` under timestamp / no sequencing.
        let source_info = sn.map(|sn| SourceInfo::new(&self.zid, self.eid, sn));

        let mut opts = self
            .qos
            .apply(PublishOptions::put())
            .with_timestamp(timestamp.clone());
        if let Some(si) = &source_info {
            opts = opts.with_source_info(si.clone());
        }
        // The SSOT discipline the source_info already followed, extended to the
        // value metadata: the SAME encoding / attachment ride the wire publish
        // AND the cache entry, so a recovered sample cannot render differently
        // from the live one it replaces.
        //
        // Each fold sits behind the gate of the SETTER it calls —
        // `PublishOptions::with_encoding` is `pubsub-encoding` and
        // `with_attachment` is `pubsub-attachment`, and
        // `ext-pubsub-advanced-publisher` composes NEITHER (it pulls
        // `pubsub-put` / `-source-info` / `-timestamp` only). An ungated call
        // therefore compiled under this crate's default features and broke the
        // `wz` facade's `--features ext-pubsub-advanced-publisher` build, which
        // is the narrow set Layer C1aq builds. The ring below stays ungated on
        // purpose: it retains what it was given regardless, and the wire
        // emission is the codec's decision — the same split
        // `advanced_cache`'s source_info already follows.
        #[cfg(feature = "pubsub-encoding")]
        if let Some(enc) = &options.encoding {
            opts = opts.with_encoding(enc.clone());
        }
        #[cfg(feature = "pubsub-attachment")]
        if let Some(att) = &options.attachment {
            opts = opts.with_attachment(att.clone());
        }
        let written = match &payload {
            SamplePayload::Bytes(bytes) => {
                self.plane
                    .publish(&self.publisher, &self.keyexpr, bytes, opts)?
            }
            #[cfg(feature = "transport-shm")]
            SamplePayload::Chunk(chunk) => {
                self.plane
                    .publish_shm(&self.publisher, &self.keyexpr, chunk, opts)?
            }
        };

        if let Some(cache) = &self.cache {
            let sample = match &payload {
                SamplePayload::Bytes(bytes) => CachedSample::new(
                    self.keyexpr.clone(),
                    bytes.to_vec(),
                    source_info,
                    timestamp,
                    SampleKind::Put,
                ),
                #[cfg(feature = "transport-shm")]
                SamplePayload::Chunk(chunk) => CachedSample::new(
                    self.keyexpr.clone(),
                    Vec::new(),
                    source_info,
                    timestamp,
                    SampleKind::Put,
                )
                .with_shared(Some(Arc::clone(chunk).send_handle())),
            };
            cache.store.cache_sample(
                sample
                    .with_encoding(options.encoding)
                    .with_attachment(options.attachment)
                    .keeping(self.plane.retained_key(&self.publisher)),
            );
        }
        Ok(written)
    }

    /// Publish a DELETE on this publisher's keyexpr, stamping the same
    /// `(zid, eid, sn)` + timestamp a [`Self::put`] would (R311y559).
    ///
    /// The sequence number is drawn from the SAME counter as `put`, which is
    /// what keeps a subscriber's miss detection correct across a mixed stream:
    /// a Del that skipped the counter would leave a permanent apparent gap.
    ///
    /// R311y561 — the Del IS cached now, closing the divergence R311y559
    /// shipped. [`CachedSample`] carries the sample KIND, so the ring retains
    /// the retraction and the cache's answer (`crate::advanced_cache`) replays it
    /// on the Del arm (`ReplyOut::reply_keyed_del_sourced`).
    /// The old behaviour — skip the cache — was the right call only while a
    /// cached Del would have come back as a Put and resurrected the deleted key
    /// on a recovering subscriber; with the kind stored that failure mode is
    /// gone, and a recovering subscriber now sees the retraction it missed.
    pub fn delete(&self) -> Result<usize, PublishError> {
        let sn = self
            .seqnum
            .as_ref()
            .map(|counter| counter.fetch_add(1, Ordering::Relaxed));
        let timestamp = self.stamp.stamp();
        let source_info = sn.map(|sn| SourceInfo::new(&self.zid, self.eid, sn));

        // R2618 — the SAME fold as the Put arm. The encoding / attachment chain
        // is deliberately absent here (a Del body carries neither ext), but QoS,
        // locality and reliability are properties of the PUBLISHER and a Del
        // carries them exactly as a Put does.
        let mut opts = self
            .qos
            .apply(PublishOptions::put())
            .with_kind(SampleKind::Del)
            .with_timestamp(timestamp.clone());
        if let Some(si) = &source_info {
            opts = opts.with_source_info(si.clone());
        }
        let written = self
            .plane
            .publish(&self.publisher, &self.keyexpr, &[], opts)?;

        if let Some(cache) = &self.cache {
            // No `with_encoding` / `with_attachment` chain: a Del body carries
            // neither ext on the wire (`has_attachment` is `_is_put && ..`, and
            // the encoding is read only in the `_is_put` branch —
            // `message.c:263,269-276`), and upstream's
            // `ze_advanced_publisher_delete_options_t` has no slot for either.
            // The absence is structural, not an omission.
            cache.store.cache_sample(
                CachedSample::new(
                    self.keyexpr.clone(),
                    Vec::new(),
                    source_info,
                    timestamp,
                    SampleKind::Del,
                )
                .keeping(self.plane.retained_key(&self.publisher)),
            );
        }
        Ok(written)
    }

    /// The publisher's allocated entity id (test / introspection seam).
    pub fn eid(&self) -> u32 {
        self.eid
    }

    /// The wrapped plain publisher, as the plane declared it. A host that hands
    /// the publisher's key out (a C program's `ze_advanced_publisher_keyexpr`)
    /// reads it from here.
    pub fn publisher(&self) -> &P::Publisher {
        &self.publisher
    }

    /// Borrow the cache's ring, if one was declared (test / recovery seam).
    pub fn cache(&self) -> Option<&CacheStore> {
        self.cache.as_ref().map(|cache| &cache.store)
    }

    /// R2619 — this publisher's key expression, upstream's
    /// `zenoh-ext/src/advanced_publisher.rs` @ `pub fn key_expr(&self) -> &KeyExpr<'a> {`.
    ///
    /// Spelled `keyexpr` rather than `key_expr` to match the plain
    /// publisher's `keyexpr` this crate already exposes: parity with upstream
    /// is about the surface EXISTING, and inventing a second spelling for the
    /// same concept inside one crate would be the worse divergence.
    pub fn keyexpr(&self) -> &str {
        &self.keyexpr
    }

    /// R2619 — this publisher's global identity, `(zid, eid)`, upstream's
    /// `zenoh-ext/src/advanced_publisher.rs` @ `pub fn id(&self) -> EntityGlobalId {`.
    ///
    /// The clause this closes said "wz's whole identity surface is the bare
    /// `u32`" — the eid was allocated and then unreachable. It is returned with
    /// the zid because that is what makes it GLOBAL: upstream's
    /// `EntityGlobalId` is exactly the pair, and it is the same pair this
    /// publisher already stamps into every sample's `SourceInfo`, so a
    /// subscriber that reads a sample's origin and a caller that asks the
    /// publisher who it is now get the same answer by construction.
    pub fn id(&self) -> (&[u8], u32) {
        (&self.zid, self.eid)
    }

    /// R2619 — undeclare this publisher, upstream's
    /// `zenoh-ext/src/advanced_publisher.rs` @ `pub fn undeclare(self) -> PublisherUndeclaration<'a> {`.
    ///
    /// CONSUMING AND INFALLIBLE, which is wz's shape for the same guarantee
    /// rather than a weaker one. Every piece of this publisher's wire state is
    /// already RAII — the `@adv` cache queryable, the liveliness token, the
    /// heartbeat timer and the wrapped publisher's own matching Interest each
    /// retract on drop — so the teardown upstream awaits through a resolvable
    /// is, here, what running `Drop` does. What the method adds over letting the
    /// binding fall out of scope is that the caller can say WHEN, and say it at
    /// a point the compiler checks: after `undeclare()` the handle is gone, so
    /// a later `put` is a type error rather than a publish onto a retracted
    /// declaration.
    pub fn undeclare(self) {
        // Explicit rather than implicit: `drop(self)` is the operation, and
        // naming it is what distinguishes this from a function that forgot to
        // do anything. The RAII members listed above are what actually retract.
        drop(self);
    }
}

#[cfg(feature = "ext-pubsub-sample-miss-detection")]
impl<P: AdvancedPublisherPlane> AdvancedPublisherOn<P> {
    /// Emit ONE heartbeat beacon now — the publisher's last published sn on its
    /// `@adv` KE — the deterministic core the timer's tick runs. Returns
    /// whether a beacon was emitted (`false` if nothing has been published yet,
    /// or this is a non-`SequenceNumber` publisher). Both an on-demand trigger
    /// (a wz superset over zenoh's timer-only beacon) and the test seam over the
    /// same path the timer drives.
    pub fn emit_heartbeat_once(&self) -> bool {
        match self.seqnum.as_ref() {
            Some(seqnum) => emit_heartbeat(
                &*self.plane,
                self.beacon.as_ref().map(|beacon| &*beacon._publisher),
                &self.adv_keyexpr,
                seqnum.load(Ordering::Relaxed),
                self.heartbeat_sporadic,
            ),
            None => false,
        }
    }
}

/// R311y96 (review-arbiter LOW) — the heartbeat-beacon SPAWN decision SSOT:
/// `Some((period, sporadic))` iff a `state_publisher` is configured AND sequencing
/// is `SequenceNumber` (so a seqnum counter for the beacon exists). Both the
/// fail-fast guard (`.is_some()`) and the actual timer start
/// (`.zip(seqnum).map(...)`) gate on this ONE predicate, so the precondition cannot
/// drift between the guard and the start arm (previously hand-mirrored twice).
#[cfg(feature = "ext-pubsub-sample-miss-detection")]
fn heartbeat_spawn_params(options: &AdvancedPublisherOptions) -> Option<(Duration, bool)> {
    match (
        options.sample_miss_detection.state_publisher,
        options.sequencing,
    ) {
        (Some(period_sporadic), Sequencing::SequenceNumber) => Some(period_sporadic),
        _ => None,
    }
}

/// R311y93 (review V1) — the sporadic-heartbeat emit gate, a pure deterministic
/// seam so the timer's decision is unit-testable (previously the
/// `!sporadic || sn > last_emitted` check was only compiled inside the background
/// task, never asserted). A non-sporadic beacon emits every tick (always `true`);
/// a sporadic beacon emits only when the put-count `sn` ADVANCED past
/// `last_emitted` (zenoh `sporadic_heartbeat`, advanced_publisher.rs:385-419).
/// The `sn == 0` "nothing published" case is filtered separately by
/// [`emit_heartbeat`].
#[cfg(feature = "ext-pubsub-sample-miss-detection")]
fn should_emit_heartbeat(sporadic: bool, sn: u32, last_emitted: u32) -> bool {
    !sporadic || sn > last_emitted
}

/// R311y85 — publish ONE heartbeat beacon: the last published sn
/// (`z_serialize::<u32>(seqnum_now - 1)`; the counter is the NEXT sn) on the
/// `@adv` KE. Returns `false` (no beacon) when nothing has been published yet
/// (`seqnum_now == 0`). A publish error (e.g. a torn-down link) is non-fatal —
/// the next tick re-emits (zenoh advanced_publisher.rs:392-394).
#[cfg(feature = "ext-pubsub-sample-miss-detection")]
fn emit_heartbeat<P: AdvancedPublisherPlane>(
    plane: &P,
    beacon: Option<&P::Beacon>,
    adv_keyexpr: &str,
    seqnum_now: u32,
    sporadic: bool,
) -> bool {
    if seqnum_now == 0 {
        return false;
    }
    let payload = z_serialize::<u32>(&(seqnum_now - 1));
    plane.publish_beacon(beacon, adv_keyexpr, &payload, sporadic);
    true
}

/// R2558 — the beacon's publish options, and the two arms differ.
///
/// Upstream declares the SPORADIC arm's beacon publisher with
/// `zenoh-ext/src/advanced_publisher.rs` @ `.congestion_control(CongestionControl::Block)`
/// and the periodic arm's with none at all — that call occurs exactly ONCE in
/// the file, on the sporadic side — and its own doc says so:
/// `zenoh-ext/src/advanced_publisher.rs` @ `/// Each period, the last published sample's sequence number is sent with [`CongestionControl::Block`]`.
///
/// THE ASYMMETRY IS THE POINT AND IT IS NOT ARBITRARY. A sporadic beacon fires
/// only when the sequence number MOVED, so each emission is the sole carrier of
/// that advance: dropping it under congestion loses the very edge the beacon
/// exists to announce, and the next tick will not re-send it because nothing
/// moved again. A periodic beacon re-states the same number every period, so a
/// dropped one is repaired by the next tick and blocking the publisher would
/// buy latency for nothing.
///
/// Gated on `pubsub-qos`, which is the compile unit
/// `PublishOptions::with_congestion_control` lives in: a
/// build without it has no way to say Block at all. The periodic arm needs
/// nothing either way, so the ungated path is already correct for it — which is
/// why the gate costs this function no correctness, only the ability to ask.
#[cfg(feature = "ext-pubsub-sample-miss-detection")]
pub fn heartbeat_publish_options(sporadic: bool) -> PublishOptions {
    let opts = PublishOptions::put();
    #[cfg(feature = "pubsub-qos")]
    if sporadic {
        return opts.with_congestion_control(CongestionControl::Block);
    }
    let _ = sporadic;
    opts
}

#[cfg(test)]
mod tests;
