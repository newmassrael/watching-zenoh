// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The pico C session as the plane an advanced publisher lives on.
//!
//! zenoh-pico builds its advanced publisher out of its own primitives: a plain
//! publisher, a cache queryable, a liveliness token and, for the heartbeat, a
//! second plain publisher (`vendor/zenoh-pico/src/api/advanced_publisher.c` @
//! `z_result_t ze_declare_advanced_publisher(const z_loaned_session_t *zs, ze_owned_advanced_publisher_t *pub,`).
//! Each of those is an ordinary pico declaration — a key declared and named on
//! the wire by its id, a write filter on the publishers, a retraction that names
//! the key — so what an advanced publisher puts on the wire is what four
//! ordinary entities put there, and that is what this plane makes it.
//!
//! The composition itself is [`AdvancedPublisherOn`]: what is validated, in what
//! order the four are declared, what a put stamps and retains, what a beacon
//! says. This file is only the four declarations and the sends, each one the
//! same function the plain C entry point of that entity calls, so the two cannot
//! describe one entity two ways.
//!
//! [`AdvancedPublisherOn`]: wz_ext_pubsub::advanced_publisher::AdvancedPublisherOn

use alloc::sync::Arc;
use core::time::Duration;

use wz_capi_port::{QueryHolder, QueryableSink, SessionEngine, Ticker, WireKey};
use wz_ext_pubsub::advanced_cache::{CacheBytes, CacheConfig, CacheStore, Retained};
use wz_ext_pubsub::advanced_publisher::{
    AdvancedPublisherError, AdvancedPublisherPlane, DeclaredPublisher,
};
use wz_node_time::node_clock::NodeHlc;
use wz_session_core::publish_options::{PublishError, PublishOptions};
use wz_session_core::query_sink::{QueryView, ReplyOut};
use wz_session_core::reliability::Reliability;
use wz_session_core::sample::SampleKind;

use crate::liveliness::TokenState;
use crate::prelude::*;
use crate::pubsub::{PlainPublisher, PublisherQos};
use crate::query::PlainQueryable;
use crate::result::{ZResult, Z_ERR_TRANSPORT_TX_FAILED, Z_OK};
use crate::write_filter::PicoSession;

/// The plane of one pico session.
pub(crate) struct PicoPlane {
    /// The session, whose own clock ([`crate::session_ext::PicoSessionExt::new`]) proposes the
    /// plane's stamps and whose times then order them ([`AdvancedPublisherPlane::order_stamp`]).
    session: PicoSession,
    /// What the advanced publisher's own publisher is declared with: the
    /// `publisher_options` the program embedded in its advanced options, which
    /// pico hands to the `z_declare_publisher` that builds it. The heartbeat
    /// publisher is not declared with them: pico declares it with the defaults
    /// (`vendor/zenoh-pico/src/api/advanced_publisher.c` @
    /// `z_publisher_options_default(&heatbeat_opts);`).
    declared: PublisherQos,
}

impl PicoPlane {
    /// The plane of `session`, whose advanced publisher's publisher is declared
    /// with `declared`.
    pub(crate) fn new(session: PicoSession, declared: PublisherQos) -> Self {
        Self { session, declared }
    }

    /// What the plane names a failed declaration: the entity, and the code the door that declares
    /// it gave.
    fn refusal(entity: &'static str, code: ZResult) -> AdvancedPublisherError {
        AdvancedPublisherError::Plane { entity, code }
    }
}

/// The ring a session's caches keep their samples in, holding the session's engine so the ring
/// stands for as long as a cache in it does.
struct SessionCacheBytes(crate::session::EngineHold);

impl CacheBytes for SessionCacheBytes {
    fn with_bytes(&self, with: &mut dyn FnMut(&mut [u8])) {
        match SessionEngine::cache_bytes(&*self.0) {
            Some(ring) => ring.with_cache_bytes(with),
            // An engine that keeps no ring is never asked for one: its caches keep their samples
            // on the heap (`PicoPlane::cache_store`).
            None => with(&mut []),
        }
    }
}

/// Give `options` what every plain publish of this ABI carries: reliable, and the
/// destination a pico put takes by default.
///
/// That destination is `Locality::Remote` without `local-subscriber`, because a
/// pico session's own put is not delivered to its own subscribers by default
/// (`Z_FEATURE_LOCAL_SUBSCRIBER` is 0), and `Any` with it, as this crate's plain
/// put has it ([`crate::pubsub`]'s `put_options`). An advanced publisher that took
/// the composite's own `Any` regardless would deliver in-process where the plain
/// publisher it wraps does not. A publish through a publisher then takes that
/// publisher's own destination ([`crate::pubsub::PublisherQos`]).
fn pico_publish(options: &mut PublishOptions<'_>) {
    options.reliability = Reliability::Reliable;
    options.allowed_destination = crate::locality::default_locality!("local-subscriber");
}

/// What a heartbeat beacon is sent with, on its publisher or on the key: a plain put of this ABI.
fn beacon_options() -> PublishOptions<'static> {
    let mut options = PublishOptions::default();
    pico_publish(&mut options);
    options.kind = SampleKind::Put;
    options
}

impl AdvancedPublisherPlane for PicoPlane {
    type Publisher = PlainPublisher;
    type Queryable = PlainQueryable;
    type Token = TokenState;
    type Beacon = PlainPublisher;
    /// The engine's periodic job, which is its own to run: a task of the runtime on the tokio
    /// engine, a step of the session on the cooperative one. `None` from an engine with no
    /// periodic jobs, whose publisher then declares and sends no heartbeat. The job names the
    /// engine as the session holds it, so a build that reaches its engine as its own type makes no
    /// table of the engine's periodic jobs for it.
    type Timer = Option<Ticker<crate::session::EngineHold>>;

    fn node_hlc(&self) -> &NodeHlc {
        &self.session.hlc
    }

    fn start_beacon_timer(
        &self,
        period: Duration,
        tick: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Option<Ticker<crate::session::EngineHold>> {
        // A period under a millisecond is raised to one by the engine, as the composite does.
        let period_ms = u64::try_from(period.as_millis()).unwrap_or(u64::MAX);
        Ticker::start_on(self.session.engine.clone(), period_ms, tick).ok()
    }

    /// Always: a pico session stamps from its own clock and zid with no
    /// configuration to consult (`vendor/zenoh-pico/src/api/api.c` @
    /// `z_result_t z_timestamp_new(`), where zenoh's node clock exists only when
    /// `timestamping` is enabled for the node's role. A cache without miss
    /// detection sequences by timestamp, so refusing it here would refuse a
    /// program pico runs.
    fn stamps(&self) -> bool {
        true
    }

    /// The session's next time, as pico's advanced publisher stamps each sample with the
    /// session's `z_timestamp_new` (`vendor/zenoh-pico/src/api/advanced_publisher.c` @
    /// `_Z_CLEAN_RETURN_IF_ERR(z_timestamp_new(timestamp, &sess_rc), _z_session_rc_drop(&sess_rc));`):
    /// a sample's time and a program's are one strictly increasing sequence of the session, and a
    /// session with no time left refuses the sample as pico refuses the put.
    fn order_stamp(&self, proposed: u64) -> Result<u64, PublishError> {
        self.session.time.order_data_stamp(proposed)
    }

    fn declare_publisher(
        &self,
        keyexpr: &str,
        _options: PublishOptions,
    ) -> Result<DeclaredPublisher<PlainPublisher>, AdvancedPublisherError> {
        // The QoS the program declared the composite with, and not the
        // `PublishOptions` the composite folds its own knobs into: those reach the
        // publisher as the options of each put, and the publisher's declared QoS
        // is what it sends with (`PlainPublisher::publish`).
        // The composite keeps its declared QoS for each publisher it declares, so the encoding is
        // kept again in a slot of its own for this one.
        let declared = self
            .declared
            .try_clone()
            .ok_or_else(|| Self::refusal("publisher", crate::result::Z_ERR_SYSTEM_OUT_OF_MEMORY))?;
        let publisher = PlainPublisher::declare(&self.session, keyexpr, declared)
            .map_err(|code| Self::refusal("publisher", code))?;
        Ok(DeclaredPublisher {
            eid: publisher.entity_id(),
            handle: publisher,
        })
    }

    fn declare_cache_queryable(
        &self,
        keyexpr: &str,
        store: &CacheStore,
    ) -> Result<PlainQueryable, AdvancedPublisherError> {
        // One handler for the queryable, kept in its row: it needs no face's session, as a reply
        // goes out on the query's own.
        let answer = store.query_handler_reading(
            wz_node_time::timestamp_source::wall_clock_ntp64,
            time_number,
        );
        let sink = QueryableSink::shared(
            move |query: &dyn QueryView, out: &mut dyn ReplyOut, _face: &dyn QueryHolder| {
                answer(query, out)
            },
        );
        // INCOMPLETE, which is the only honest answer a bounded ring can give
        // (R2556, the tokio runtime's `AdvancedCache::declare` answers the same).
        PlainQueryable::declare(&self.session, keyexpr, None, false, sink)
            .map_err(|code| Self::refusal("cache queryable", code))
    }

    /// In the session's ring of cached samples when the session keeps one (the cooperative engine,
    /// which reserved it at its open), so a put takes no memory; a ring that holds no record
    /// refuses the cache. On the heap on an engine that keeps none.
    fn cache_store(&self, config: CacheConfig) -> Result<CacheStore, AdvancedPublisherError> {
        if SessionEngine::cache_bytes(&*self.session.engine).is_none() {
            return Ok(CacheStore::new(config));
        }
        CacheStore::in_ring(
            config,
            Box::new(SessionCacheBytes(crate::session::EngineHold::clone(
                &self.session.engine,
            ))),
        )
        .ok_or(AdvancedPublisherError::CacheRingUnavailable)
    }

    fn declare_token(&self, keyexpr: &str) -> Result<TokenState, AdvancedPublisherError> {
        TokenState::declare(&self.session, keyexpr, None)
            .map_err(|code| Self::refusal("liveliness token", code))
    }

    fn declare_beacon(
        &self,
        keyexpr: &str,
        _sporadic: bool,
    ) -> Result<PlainPublisher, AdvancedPublisherError> {
        PlainPublisher::declare(&self.session, keyexpr, PublisherQos::pico_default())
            .map_err(|code| Self::refusal("beacon publisher", code))
    }

    fn publish(
        &self,
        publisher: &PlainPublisher,
        _keyexpr: &str,
        payload: &[u8],
        options: PublishOptions,
    ) -> Result<usize, PublishError> {
        // The publisher sends on its own key, in its own declared form, through
        // its own write filter: the same call `z_publisher_put` makes. The byte
        // count the runtime reports is the number of peers a put reached, which
        // a filter that held the sample back makes 0 — a put with no recipient,
        // and `Z_OK`.
        // Bound again so the options' borrow may be as short as the publisher's.
        let mut options = options;
        pico_publish(&mut options);
        match publisher.publish(payload, Some(&mut options)) {
            code if code == Z_OK => Ok(payload.len()),
            // Dropped behind a held conduit: the same drop, so the advanced put answers it as
            // the plain one does.
            code if code == Z_ERR_TRANSPORT_TX_FAILED => Err(PublishError::HeldConduit),
            _ => Err(PublishError::ExceedsCapacity),
        }
    }

    /// Through the beacon publisher, as pico's heartbeat task does, so the beacon is held back
    /// while nothing subscribes to it.
    fn send_beacon(beacon: &PlainPublisher, _keyexpr: &str, payload: &[u8], _sporadic: bool) {
        let mut options = beacon_options();
        let _ = beacon.publish(payload, Some(&mut options));
    }

    /// An on-demand beacon from a publisher that declared none: on the key itself.
    fn publish_beacon(&self, keyexpr: &str, payload: &[u8], _sporadic: bool) {
        let _ = self.session.engine.publish_on_wire_all(
            keyexpr,
            &WireKey::literal(),
            payload,
            &beacon_options(),
        );
    }

    fn retained_key(&self, publisher: &PlainPublisher) -> Option<Retained> {
        // The cached sample holds a reference to the key it was published on, as
        // pico's does (`_z_declared_keyexpr_copy` in `_z_sample_copy_data`), so
        // the key stays declared until the ring lets the sample go. A key whose declaration's
        // count has no room keeps nothing, as a plane whose key is not a declaration does.
        Some(Retained::new(Arc::new(publisher.key_copy().ok()?)))
    }
}

/// The number of a `_time` selector, read by the C library's own reader, as zenoh-pico reads it
/// (`strtod`), from the literal wz's grammar admitted and wrote with no radix character: the
/// library links no float reader of its own.
#[cfg(unix)]
fn time_number(text: &str) -> Result<f64, wz_session_core::time_range::FloatError> {
    use wz_session_core::time_range::{decimal_text, Decimal, DECIMAL_TEXT};
    let mut written = [0u8; DECIMAL_TEXT];
    match decimal_text(text, &mut written)? {
        Decimal::Read(value) => Ok(value),
        // SAFETY: `decimal_text` wrote a number in `written` and a NUL after it, so the reader
        // reads inside the array.
        Decimal::Written(_) => {
            Ok(unsafe { libc::strtod(written.as_ptr().cast(), core::ptr::null_mut()) })
        }
    }
}

/// A host whose C library's reader is not named here reads with core's.
#[cfg(not(unix))]
use wz_session_core::time_range::core_float as time_number;

/// The C library's reader reads a `_time` number as core's does, and refuses what core refuses.
/// Turned red by a literal handed to the reader in another form than the one it reads, or a
/// grammar the platform reader admits more of.
#[cfg(all(test, unix))]
mod time_number_tests {
    use wz_session_core::time_range::core_float;

    #[test]
    fn the_c_librarys_reader_reads_a_time_as_core_does() {
        for text in [
            "30",
            "1.5",
            "-0.25",
            "2.5e-3",
            "1e400",
            "4.9e-324",
            "0.30000000000000004",
            "123456789012345678901234567890123456789012345678901234567890",
            "inf",
            "nan",
            "",
            "1,5",
            "0x10",
            " 1",
        ] {
            match (super::time_number(text), core_float(text)) {
                (Ok(a), Ok(b)) => assert!(
                    a.to_bits() == b.to_bits() || (a.is_nan() && b.is_nan()),
                    "{text:?}: {a} against {b}"
                ),
                (a, b) => assert_eq!(a.map(f64::to_bits), b.map(f64::to_bits), "{text:?}"),
            }
        }
    }
}

#[cfg(test)]
mod timer_tests {
    use core::any::TypeId;

    use super::*;

    /// A refused declaration names its entity and the code its door gave, with no text made for
    /// it. Turned red by a refusal that loses the door's code.
    #[test]
    fn a_refusal_names_the_entity_and_the_doors_code() {
        assert!(matches!(
            PicoPlane::refusal("cache queryable", crate::result::Z_ERR_SYSTEM_OUT_OF_MEMORY),
            AdvancedPublisherError::Plane {
                entity: "cache queryable",
                code: crate::result::Z_ERR_SYSTEM_OUT_OF_MEMORY,
            }
        ));
    }

    /// The heartbeat's job holds the session's engine as the session does, not as the port's
    /// object of periodic jobs, so no table of the engine's jobs is made for it.
    #[test]
    fn the_beacon_timer_holds_the_engine_as_the_session_does() {
        assert_eq!(
            TypeId::of::<<PicoPlane as AdvancedPublisherPlane>::Timer>(),
            TypeId::of::<Option<Ticker<crate::session::EngineHold>>>()
        );
        assert_ne!(
            TypeId::of::<<PicoPlane as AdvancedPublisherPlane>::Timer>(),
            TypeId::of::<Option<Ticker>>()
        );
    }
}

/// A library without the node clock (`advanced-node-clock`, off in the zenoh-pico preset) holds
/// none for its sessions: an advanced publisher proposes the system clock's time, which the
/// session's times then order, as zenoh-pico's publisher stamps with `z_timestamp_new`, and a
/// `trusted-only` policy has no clock to hold back. The tokio engine holds the clock whatever is
/// named, and a registrable clock brings its own, so the case is the cooperative engine's alone.
#[cfg(all(
    test,
    not(feature = "advanced-node-clock"),
    not(feature = "clock-source"),
    not(feature = "engine-tokio")
))]
mod no_node_clock_tests {
    use wz_node_time::node_clock::{DataStamp, NodeHlc, TimestampingEnabled};
    use wz_session_core::policy::SessionPolicy;
    use wz_session_core::WhatAmI;

    /// The session's clock, as its open builds it, is no clock: it takes no memory, stamps
    /// nothing, and tells the publisher to fall back to the system clock. Turned red by the node
    /// clock left in `advanced` (the manifest's `wz-node-time/time-hlc`).
    #[test]
    fn a_session_without_the_node_clock_stamps_from_the_system_clock() {
        let hlc = NodeHlc::for_node_by(
            &[0x11; 16],
            WhatAmI::Peer,
            TimestampingEnabled::all(true),
            &SessionPolicy::defaults(),
            &wz_session_core::limits::RuntimeLimits::BUILD,
        );
        assert_eq!(core::mem::size_of::<NodeHlc>(), 0);
        assert!(!hlc.is_stamping());
        assert_eq!(hlc.data_stamp(), DataStamp::NoClock);
    }
}

#[cfg(all(test, feature = "engine-tokio"))]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    use wz_capi_core::faces::SharedSession;
    use wz_capi_core::runtime::runtime_impl::TokioTime;
    use wz_ext_pubsub::advanced_publisher::{AdvancedPublisherOn, AdvancedPublisherOptions};
    use wz_node_time::node_clock::TimestampingEnabled;
    use wz_node_time::timestamp_source::SystemEpoch;
    use wz_session_core::WhatAmI;

    use crate::last_timestamp::SessionTime;

    /// The heartbeat's timer on this plane is the ENGINE's periodic job: the tick runs every
    /// period while the handle the plane returns is held, and the job ends with the handle. The
    /// count after the drop, and again some periods later, is what says it ended and did not
    /// merely go quiet. (The beacon itself is not the witness: a pico publisher holds a put back
    /// while no peer subscribes, which a session with no peer never has.)
    #[test]
    fn the_beacon_timer_is_the_engines_periodic_job_and_ends_with_its_handle() {
        let shared = Arc::new(
            SharedSession::new(
                TokioTime::new(),
                [0x11; 16].into(),
                wz_session_core::policy::SessionPolicy::defaults(),
            )
            .expect("test host entropy"),
        );
        let plane = PicoPlane::new(
            PicoSession {
                engine: shared.as_engine(),
                mode: WhatAmI::Peer,
                hlc: NodeHlc::default(),
                time: crate::last_timestamp::SessionTime::new(),
            },
            PublisherQos::pico_default(),
        );
        let ticks = Arc::new(AtomicUsize::new(0));
        let count = ticks.clone();
        let timer = plane.start_beacon_timer(
            Duration::from_millis(20),
            Arc::new(move || {
                count.fetch_add(1, Ordering::SeqCst);
                true
            }),
        );
        assert!(timer.is_some(), "the tokio engine runs periodic jobs");

        let deadline = Instant::now() + Duration::from_secs(5);
        while ticks.load(Ordering::SeqCst) < 3 {
            assert!(Instant::now() < deadline, "no third tick in 5 s");
            std::thread::sleep(Duration::from_millis(5));
        }

        drop(timer);
        std::thread::sleep(Duration::from_millis(60));
        let after = ticks.load(Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(120));
        assert_eq!(
            ticks.load(Ordering::SeqCst),
            after,
            "six periods after the drop it had ticked no more"
        );
    }

    const ZID: [u8; 16] = [0x11; 16];

    /// The session's node clock, under the `trusted-only` policy (`true`) or `always` (`false`).
    fn node_clock(trusted_only: bool) -> NodeHlc {
        NodeHlc::for_node_over_source_by(
            &ZID,
            WhatAmI::Peer,
            TimestampingEnabled::all(true),
            SystemEpoch,
            &wz_session_core::policy::SessionPolicy::defaults(),
            &wz_session_core::limits::RuntimeLimits::BUILD,
        )
        .with_trusted_only_stamping(trusted_only)
    }

    /// An advanced publisher with no cache and no detection on a pico plane of a session with no
    /// peer, whose node clock is `hlc` and whose times are `time`. The session is returned so it
    /// outlives the publisher.
    fn publisher_over(
        hlc: &NodeHlc,
        time: &SessionTime,
    ) -> (Arc<SharedSession>, AdvancedPublisherOn<PicoPlane>) {
        let shared = Arc::new(
            SharedSession::new(
                TokioTime::new(),
                ZID.into(),
                wz_session_core::policy::SessionPolicy::defaults(),
            )
            .expect("test host entropy"),
        );
        let plane = PicoPlane::new(
            PicoSession {
                engine: shared.as_engine(),
                mode: WhatAmI::Peer,
                hlc: hlc.clone(),
                time: time.clone(),
            },
            PublisherQos::pico_default(),
        );
        // The options are non-exhaustive, so they are built from their default and set.
        let mut options = AdvancedPublisherOptions::default();
        options.cache = None;
        options.publisher_detection = false;
        let publisher = AdvancedPublisherOn::declare_on(plane, "demo/pico/ts", options, ZID.into())
            .expect("the declaration is accepted");
        (shared, publisher)
    }

    /// With the policy off, the default and upstream's, a sample is stamped through the session's
    /// last time given: the next time the session gives is after it.
    #[test]
    fn with_the_policy_off_a_sample_takes_the_sessions_next_time() {
        let hlc = node_clock(false);
        let time = SessionTime::new().learned_by(hlc.clone());
        let (_shared, publisher) = publisher_over(&hlc, &time);
        assert!(
            publisher.put(b"x").is_ok(),
            "a put with no peer is not refused"
        );
        let next = time.give(0).expect("time left");
        assert!(
            next >> 32 > 1_700_000_000,
            "the sample's time, the node clock's over the system clock, is the last given: {}",
            next >> 32
        );
    }

    /// A session that already gave the greatest time there is refuses the sample.
    #[test]
    fn a_session_with_no_time_left_refuses_a_put_and_a_delete() {
        let hlc = node_clock(false);
        let time = SessionTime::new().learned_by(hlc.clone());
        assert_eq!(time.give(u64::MAX), Some(u64::MAX));
        let (_shared, publisher) = publisher_over(&hlc, &time);
        assert_eq!(publisher.put(b"x"), Err(PublishError::TimestampExhausted));
        assert_eq!(publisher.delete(), Err(PublishError::TimestampExhausted));
    }

    /// `trusted-only` refuses a sample until the host reports the clock synchronised, and takes
    /// no time from the session for it; after the report the sample goes out.
    #[test]
    fn a_trusted_only_session_refuses_a_sample_until_its_clock_is_trusted() {
        let hlc = node_clock(true);
        let time = SessionTime::new().learned_by(hlc.clone());
        let (_shared, publisher) = publisher_over(&hlc, &time);
        assert_eq!(publisher.put(b"x"), Err(PublishError::ClockUntrusted));
        assert_eq!(publisher.delete(), Err(PublishError::ClockUntrusted));
        assert_eq!(time.give(0), Some(1), "the refused samples took no time");

        assert!(hlc.report_sync_acquired());
        assert!(
            publisher.put(b"x").is_ok(),
            "a trusted clock stamps the sample"
        );
        assert!(
            time.give(0).expect("time left") > 2,
            "the sample took a time"
        );
    }
}
