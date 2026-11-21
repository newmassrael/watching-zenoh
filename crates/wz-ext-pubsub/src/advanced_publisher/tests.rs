use super::*;

/// A plane that records, in order, what the composite asks of it and what
/// it lets go of — so the ORDER the composite declares its entities in and
/// retracts them in is read off a witness and not off the code.
struct RecordingPlane {
    events: Arc<std::sync::Mutex<Vec<String>>>,
    /// `stamps` as the plane answers it, so a test can refuse timestamps
    /// without a node clock.
    stamps: bool,
    /// The ticks the composite handed the plane's timer, so a test can be the clock.
    ticks: std::sync::Mutex<Vec<Arc<dyn Fn() -> bool + Send + Sync>>>,
    /// The next word `order_stamp` answers, counting up, for a plane that orders the stamps of
    /// its session itself; `None` carries the proposal, as the default does. The word
    /// `u64::MAX` is refused, as a session with no time left refuses it.
    order_from: Option<std::sync::atomic::AtomicU64>,
    /// The time word and the sequence number of each sample sent, in order.
    stamped: std::sync::Mutex<Vec<(Option<u64>, Option<u32>)>>,
    /// The node clock the plane answers with; `NodeHlc::disabled()` unless a test gives one.
    node: NodeHlc,
}

/// A handle that writes its own name when it is dropped.
struct Named {
    events: Arc<std::sync::Mutex<Vec<String>>>,
    name: &'static str,
}

impl Drop for Named {
    fn drop(&mut self) {
        self.events
            .lock()
            .unwrap()
            .push(format!("drop {}", self.name));
    }
}

impl RecordingPlane {
    fn new(stamps: bool) -> Self {
        Self {
            events: Arc::new(std::sync::Mutex::new(Vec::new())),
            stamps,
            ticks: std::sync::Mutex::new(Vec::new()),
            order_from: None,
            stamped: std::sync::Mutex::new(Vec::new()),
            node: NodeHlc::disabled(),
        }
    }

    /// A plane that orders its session's stamps itself, from `word` up.
    fn ordering_from(word: u64) -> Self {
        Self {
            order_from: Some(std::sync::atomic::AtomicU64::new(word)),
            ..Self::new(true)
        }
    }

    /// A plane over the node clock `node`.
    fn over_node(node: NodeHlc) -> Self {
        Self {
            node,
            ..Self::new(true)
        }
    }

    /// The time word and sequence number of each sample sent, in order.
    fn stamped(&self) -> Vec<(Option<u64>, Option<u32>)> {
        self.stamped.lock().unwrap().clone()
    }

    fn handle(&self, name: &'static str) -> Named {
        self.events.lock().unwrap().push(format!("declare {name}"));
        Named {
            events: Arc::clone(&self.events),
            name,
        }
    }

    fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }

    /// Run the beacon's tick once, as the plane's timer would at the end of a period.
    #[cfg(feature = "ext-pubsub-sample-miss-detection")]
    fn tick(&self) -> bool {
        let tick = Arc::clone(
            self.ticks
                .lock()
                .unwrap()
                .last()
                .expect("a timer was started"),
        );
        tick()
    }
}

impl AdvancedPublisherPlane for RecordingPlane {
    type Publisher = Named;
    type Queryable = Named;
    type Token = Named;
    type Beacon = Named;
    type Timer = Named;

    fn node_hlc(&self) -> &NodeHlc {
        // The plane's one clock, held for its life: a fresh clock per call would be the
        // duplicate-`ID` defect the node clock exists to remove.
        &self.node
    }

    fn stamps(&self) -> bool {
        self.stamps
    }

    fn order_stamp(&self, proposed: u64) -> Result<u64, PublishError> {
        match &self.order_from {
            Some(next) => match next.fetch_add(1, Ordering::SeqCst) {
                u64::MAX => Err(PublishError::TimestampExhausted),
                word => Ok(word),
            },
            None => Ok(proposed),
        }
    }

    fn declare_publisher(
        &self,
        _keyexpr: &str,
        _options: PublishOptions,
    ) -> Result<DeclaredPublisher<Named>, AdvancedPublisherError> {
        Ok(DeclaredPublisher {
            handle: self.handle("publisher"),
            eid: 7,
        })
    }

    fn declare_cache_queryable(
        &self,
        keyexpr: &str,
        _store: &CacheStore,
    ) -> Result<Named, AdvancedPublisherError> {
        self.events.lock().unwrap().push(format!("on {keyexpr}"));
        Ok(self.handle("cache"))
    }

    fn declare_token(&self, keyexpr: &str) -> Result<Named, AdvancedPublisherError> {
        self.events.lock().unwrap().push(format!("on {keyexpr}"));
        Ok(self.handle("token"))
    }

    fn declare_beacon(
        &self,
        _keyexpr: &str,
        _sporadic: bool,
    ) -> Result<Named, AdvancedPublisherError> {
        Ok(self.handle("beacon"))
    }

    fn start_beacon_timer(
        &self,
        period: Duration,
        tick: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Named {
        assert!(
            period >= Duration::from_millis(1),
            "the composite hands the timer a period it cannot spin on"
        );
        self.ticks.lock().unwrap().push(tick);
        self.handle("timer")
    }

    fn publish(
        &self,
        _publisher: &Named,
        _keyexpr: &str,
        payload: &[u8],
        options: PublishOptions,
    ) -> Result<usize, PublishError> {
        self.events.lock().unwrap().push(String::from("publish"));
        self.stamped.lock().unwrap().push((
            options.timestamp.map(|timestamp| timestamp.time),
            options.source_info.map(|source| source.sn),
        ));
        Ok(payload.len())
    }

    fn publish_beacon(
        &self,
        _beacon: Option<&Named>,
        _keyexpr: &str,
        payload: &[u8],
        sporadic: bool,
    ) {
        self.events
            .lock()
            .unwrap()
            .push(format!("beacon {payload:02x?} sporadic={sporadic}"));
    }

    fn retained_key(&self, _publisher: &Named) -> Option<Retained> {
        Some(Retained::new(Arc::new(Named {
            events: Arc::clone(&self.events),
            name: "retained key",
        })))
    }
}

/// The composition is the reference library's, in both directions: the plain
/// publisher first and then the cache, the token; retracted in the order the
/// reference retracts them (`_ze_undeclare_advanced_publisher_clear`) — the
/// publisher, the token, and the cache LAST, after which the ring lets go of
/// the samples whose key it kept. A host that declares key ids shows the
/// order to a peer, so it is asserted here and not left to the field order
/// of a struct.
#[test]
fn a_plane_sees_the_entities_declared_and_retracted_in_the_reference_order() {
    let plane = Arc::new(RecordingPlane::new(true));
    let options = AdvancedPublisherOptions {
        cache: Some(CacheConfig::default()),
        publisher_detection: true,
        ..AdvancedPublisherOptions::default()
    };
    let publisher = AdvancedPublisherOn::declare_on(
        Arc::clone(&plane),
        "demo/order",
        options,
        SessionZid::from([0x01]),
    )
    .expect("the declaration is accepted");
    publisher.put(b"x").expect("a put is accepted");
    drop(publisher);

    let adv = format!("on demo/order/@adv/pub/{}/7/_", zid_to_zenoh_hex(&[0x01]));
    assert_eq!(
        plane.events(),
        [
            "declare publisher".to_string(),
            adv.clone(),
            "declare cache".to_string(),
            adv,
            "declare token".to_string(),
            "publish".to_string(),
            "drop publisher".to_string(),
            "drop token".to_string(),
            "drop cache".to_string(),
            // The ring goes with the cache, and the sample in it keeps the
            // publisher's key until it does.
            "drop retained key".to_string(),
        ],
        "the plane was not asked in the reference library's order"
    );
}

/// The beacon's publisher is declared AFTER the token and retracted between
/// the token and the cache, and the timer that drives it is started once the
/// publisher stands and stopped before it is retracted.
#[cfg(feature = "ext-pubsub-sample-miss-detection")]
#[test]
fn a_plane_sees_the_beacon_publisher_declared_after_the_token_and_retracted_before_the_cache() {
    let plane = Arc::new(RecordingPlane::new(true));
    let options = AdvancedPublisherOptions {
        cache: Some(CacheConfig::default()),
        publisher_detection: true,
        sample_miss_detection: MissDetectionConfig::default().heartbeat(Duration::from_secs(3600)),
        ..AdvancedPublisherOptions::default()
    };
    let publisher = AdvancedPublisherOn::declare_on(
        Arc::clone(&plane),
        "demo/order",
        options,
        SessionZid::from([0x01]),
    )
    .expect("the declaration is accepted");
    drop(publisher);

    let declared: Vec<String> = plane
        .events()
        .into_iter()
        .filter(|e| !e.starts_with("on "))
        .collect();
    assert_eq!(
        declared,
        [
            "declare publisher",
            "declare cache",
            "declare token",
            "declare beacon",
            "declare timer",
            "drop publisher",
            "drop token",
            "drop timer",
            "drop beacon",
            "drop cache",
        ],
        "the beacon's publisher was not declared and retracted where the reference does, \
         or its timer was not stopped before the publisher it sends on"
    );
}

/// The plane's timer calls the composite's tick, and the tick is the beacon's whole decision: a
/// periodic beacon says the last sequence number every period, a sporadic one only when it moved,
/// and neither says anything before a first put. The tick answers `false` once the publisher is
/// gone, which is how a timer that outlives it is told to stop.
#[cfg(feature = "ext-pubsub-sample-miss-detection")]
#[test]
fn the_tick_is_the_beacons_decision_and_ends_with_the_publisher() {
    let beacons = |plane: &RecordingPlane| -> Vec<String> {
        plane
            .events()
            .into_iter()
            .filter(|e| e.starts_with("beacon "))
            .collect()
    };
    let declare = |sporadic: bool| {
        let plane = Arc::new(RecordingPlane::new(true));
        let config = MissDetectionConfig::default();
        let config = if sporadic {
            config.sporadic_heartbeat(Duration::from_secs(1))
        } else {
            config.heartbeat(Duration::from_secs(1))
        };
        let publisher = AdvancedPublisherOn::declare_on(
            Arc::clone(&plane),
            "demo/beacon",
            AdvancedPublisherOptions {
                cache: None,
                publisher_detection: false,
                sample_miss_detection: config,
                ..AdvancedPublisherOptions::default()
            },
            SessionZid::from([0x01]),
        )
        .expect("the declaration is accepted");
        (plane, publisher)
    };

    // Periodic: nothing before a first put, then the last sn (the counter less one) every tick.
    let (plane, publisher) = declare(false);
    assert!(plane.tick());
    assert!(
        beacons(&plane).is_empty(),
        "nothing has been published, so there is nothing to announce"
    );
    publisher.put(b"a").unwrap();
    publisher.put(b"b").unwrap();
    assert!(plane.tick());
    assert!(plane.tick());
    assert_eq!(
        beacons(&plane).len(),
        2,
        "a periodic beacon repeats the same number every tick"
    );
    assert!(
        beacons(&plane)
            .iter()
            .all(|b| b == &beacons(&plane)[0] && b.ends_with("sporadic=false")),
        "and says the same thing each time: {:?}",
        beacons(&plane)
    );

    // The tick ends with the publisher.
    drop(publisher);
    assert!(
        !plane.tick(),
        "a tick after the publisher went answers false, so the timer stops"
    );

    // Sporadic: only when the number moved.
    let (plane, publisher) = declare(true);
    publisher.put(b"a").unwrap();
    assert!(plane.tick());
    assert!(plane.tick());
    assert_eq!(
        beacons(&plane).len(),
        1,
        "an unmoved number is not repeated"
    );
    publisher.put(b"b").unwrap();
    assert!(plane.tick());
    assert_eq!(beacons(&plane).len(), 2, "a moved one is announced");
    assert!(beacons(&plane)[1].ends_with("sporadic=true"));
}

/// A plane that cannot stamp refuses timestamp sequencing and one that can
/// accepts it, whatever the node clock says: the precondition is the
/// PLANE's, which is what lets a host with its own clock answer for itself.
#[test]
fn timestamp_sequencing_follows_the_planes_answer_and_not_the_node_clock() {
    let options = AdvancedPublisherOptions {
        sequencing: Sequencing::Timestamp,
        cache: None,
        publisher_detection: false,
        ..AdvancedPublisherOptions::default()
    };
    assert!(
        matches!(
            AdvancedPublisherOn::declare_on(
                Arc::new(RecordingPlane::new(false)),
                "demo/ts",
                options.clone(),
                SessionZid::from([0x01]),
            ),
            Err(AdvancedPublisherError::TimestampingDisabled)
        ),
        "a plane that cannot stamp must refuse timestamp sequencing"
    );
    assert!(
        AdvancedPublisherOn::declare_on(
            Arc::new(RecordingPlane::new(true)),
            "demo/ts",
            options,
            SessionZid::from([0x01]),
        )
        .is_ok(),
        "a plane that stamps must accept it with no node clock at all"
    );
}

/// A plane that orders its session's stamps itself is what a Put and a Del carry: the
/// composite asks it for every sample, and sends the word it answers rather than the node
/// clock's proposal (here the wall clock, the plane having no node clock).
#[test]
fn a_put_and_a_delete_carry_the_time_the_plane_orders() {
    let plane = Arc::new(RecordingPlane::ordering_from(42));
    let options = AdvancedPublisherOptions {
        cache: None,
        publisher_detection: false,
        ..AdvancedPublisherOptions::default()
    };
    let publisher = AdvancedPublisherOn::declare_on(
        Arc::clone(&plane),
        "demo/ordered",
        options,
        SessionZid::from([0x01]),
    )
    .expect("the declaration is accepted");
    publisher.put(b"x").expect("a put is accepted");
    publisher.delete().expect("a delete is accepted");
    assert_eq!(plane.stamped(), [(Some(42), Some(0)), (Some(43), Some(1))]);
}

/// A plane that does not order stamps carries the node clock's proposal as it is.
#[test]
fn a_plane_that_orders_nothing_carries_the_proposal() {
    let plane = Arc::new(RecordingPlane::new(true));
    let publisher = declare_plain(&plane, "demo/proposed");
    publisher.put(b"x").expect("a put is accepted");
    let stamped = plane.stamped();
    assert_eq!(stamped.len(), 1);
    let time = stamped[0].0.expect("an advanced put is stamped");
    assert!(
        time >> 32 > 1_700_000_000,
        "the wall clock's seconds, the plane having no node clock: {}",
        time >> 32
    );
}

/// An advanced publisher on `plane` with no cache and no detection, sequenced by number.
fn declare_plain(plane: &Arc<RecordingPlane>, key: &str) -> AdvancedPublisherOn<RecordingPlane> {
    let options = AdvancedPublisherOptions {
        cache: None,
        publisher_detection: false,
        ..AdvancedPublisherOptions::default()
    };
    AdvancedPublisherOn::declare_on(Arc::clone(plane), key, options, SessionZid::from([0x01]))
        .expect("the declaration is accepted")
}

/// A session with no time left refuses the sample, as zenoh-pico refuses the put whose
/// `z_timestamp_new` failed: nothing is sent, and the refused sample takes no sequence number,
/// so the next one is not reported to a subscriber as a miss.
#[test]
fn a_session_with_no_time_left_refuses_the_sample_and_takes_no_sequence_number() {
    let plane = Arc::new(RecordingPlane::ordering_from(u64::MAX - 1));
    let publisher = declare_plain(&plane, "demo/exhausted");
    publisher.put(b"x").expect("the last time there is");
    assert_eq!(publisher.put(b"y"), Err(PublishError::TimestampExhausted));
    // The test plane's counter has wrapped to 0: the next sample is given a time again.
    publisher.delete().expect("the plane gives a time again");
    assert_eq!(
        plane.stamped(),
        [(Some(u64::MAX - 1), Some(0)), (Some(0), Some(1))],
        "the refused put sent nothing and took no sequence number"
    );
}

/// A node clock under the `trusted-only` policy (`true`) or `always` (`false`).
fn node_clock(trusted_only: bool) -> NodeHlc {
    NodeHlc::for_node_over_source_by(
        &[0x01],
        wz_session_core::WhatAmI::Peer,
        wz_node_time::node_clock::TimestampingEnabled::all(true),
        wz_node_time::timestamp_source::SystemEpoch,
        &wz_session_core::policy::SessionPolicy::defaults(),
        &wz_session_core::limits::RuntimeLimits::BUILD,
    )
    .with_trusted_only_stamping(trusted_only)
}

/// `trusted-only` stamps no data with a clock that is not trusted, and an advanced publisher's
/// sample cannot go out without a time: it is refused, nothing is sent, and no sequence number is
/// taken. Once the host reports the clock synchronised the sample carries the clock's time.
#[test]
fn a_trusted_only_node_refuses_a_sample_until_its_clock_is_trusted() {
    let plane = Arc::new(RecordingPlane::over_node(node_clock(true)));
    let publisher = declare_plain(&plane, "demo/untrusted");
    assert_eq!(publisher.put(b"x"), Err(PublishError::ClockUntrusted));
    assert_eq!(publisher.delete(), Err(PublishError::ClockUntrusted));
    assert!(plane.stamped().is_empty(), "nothing went out");

    assert!(plane.node.report_sync_acquired());
    publisher
        .put(b"x")
        .expect("a trusted clock stamps the sample");
    let stamped = plane.stamped();
    assert_eq!(stamped.len(), 1);
    assert_eq!(stamped[0].1, Some(0), "the refused samples took no number");
    let time = stamped[0].0.expect("the sample carries a time");
    assert!(
        time >> 32 > 1_700_000_000,
        "the node clock's time, over the system clock: {}",
        time >> 32
    );
}

/// With the policy off (`always`, the default and what upstream does) a node's clock stamps every
/// sample whatever its standing.
#[test]
fn with_the_policy_off_every_sample_carries_the_node_clocks_time() {
    let plane = Arc::new(RecordingPlane::over_node(node_clock(false)));
    let publisher = declare_plain(&plane, "demo/always");
    publisher
        .put(b"x")
        .expect("stamped with the clock as it stands");
    publisher.delete().expect("and a delete too");
    let stamped = plane.stamped();
    assert_eq!(stamped.len(), 2);
    let (first, second) = (stamped[0].0.unwrap(), stamped[1].0.unwrap());
    assert!(second > first, "one clock: {first} then {second}");
}

/// R311y93 (review V1) — the sporadic-heartbeat emit gate. Non-sporadic emits
/// every tick regardless of sn movement; sporadic emits only when the put-count
/// advanced past `last_emitted`, so a stalled publisher (sn unchanged) stops
/// re-beaconing. Previously this decision was only compiled inside the spawn
/// loop, never asserted.
/// R2558 — the beacon's congestion asymmetry, as a PAIR so the asymmetry
/// itself is what is asserted rather than one arm's value.
///
/// Upstream blocks on the SPORADIC arm only — that
/// `.congestion_control(CongestionControl::Block)` occurs exactly once in
/// its advanced publisher and it is on that side. A test that pinned just
/// the sporadic arm would pass equally on a build that blocked BOTH, which
/// would be a different (and wrong) publisher: the periodic beacon restates
/// the same number every tick, so blocking it buys latency for nothing.
///
/// This asserts the pure decision function both ways. ⚠ WHAT IT DOES NOT
/// REACH, stated rather than implied: it pins the DECISION, not the wiring
/// that carries `sporadic` from the spawn params and from
/// `heartbeat_sporadic` into it. No fixture in this module reads an emitted
/// frame's QoS back, so that hop is currently unwitnessed.
#[cfg(all(feature = "ext-pubsub-sample-miss-detection", feature = "pubsub-qos"))]
#[test]
fn only_the_sporadic_beacon_blocks_under_congestion() {
    use wz_session_core::qos::CongestionControl;

    let sporadic = heartbeat_publish_options(true);
    assert_eq!(
        sporadic
            .qos
            .expect("the sporadic arm names a QoS")
            .congestion(),
        CongestionControl::Block,
        "a sporadic beacon fires only when the sn MOVED, so each emission is \
         the sole carrier of that advance and must not be dropped"
    );

    let periodic = heartbeat_publish_options(false);
    assert!(
        periodic
            .qos
            .map(|q| q.congestion() != CongestionControl::Block)
            .unwrap_or(true),
        "a periodic beacon restates the same sn every tick, so a dropped one \
         is repaired by the next: blocking it is latency for nothing, and \
         upstream does not"
    );
}

#[cfg(feature = "ext-pubsub-sample-miss-detection")]
#[test]
fn should_emit_heartbeat_gates_sporadic_on_advance() {
    // Non-sporadic: always emit (every period), even at an unchanged sn.
    assert!(should_emit_heartbeat(false, 0, 0));
    assert!(should_emit_heartbeat(false, 5, 5));
    assert!(should_emit_heartbeat(false, 3, 7));
    // Sporadic: emit only when sn advanced past last_emitted.
    assert!(should_emit_heartbeat(true, 5, 3), "advanced -> emit");
    assert!(!should_emit_heartbeat(true, 3, 3), "unchanged -> skip");
    assert!(!should_emit_heartbeat(true, 2, 3), "behind -> skip");
    assert!(
        !should_emit_heartbeat(true, 0, 0),
        "nothing published -> skip"
    );
}

/// The five publisher knobs reach the publish options, and a
/// DEFAULT config still publishes exactly what it did before they existed.
///
/// Upstream carries these on its advanced-publisher builder
/// (`zenoh-ext/src/advanced_publisher.rs` @ `pub fn allowed_destination(mut self, destination: Locality) -> Self {`
/// and its four siblings) where `AdvancedPublisherOptions` carried four
/// fields and none of them, which the atom's clause (2) called structural.
///
/// THE SECOND ARM IS THE CONTROL AND IT GRADES A CLAIM THIS ROUND MAKES IN
/// PROSE: the new defaults are the publish path's own, so a default-built
/// publisher emits what it emitted before. Asserting the folded options
/// equal a bare `PublishOptions::put()` is what stops that sentence being
/// decoration -- if any default were a second opinion about a wire value,
/// this arm fails rather than the claim quietly being false.
#[test]
fn the_publisher_knobs_reach_the_publish_options_and_default_changes_nothing() {
    // ARM 1: non-default knobs all land.
    let opts = AdvancedPublisherOptions {
        allowed_destination: Locality::SessionLocal,
        reliability: Reliability::BestEffort,
        priority: Priority::InteractiveHigh,
        congestion_control: CongestionControl::Block,
        express: true,
        ..AdvancedPublisherOptions::default()
    };
    let folded = WireQos::from_options(&opts).apply(PublishOptions::put());
    assert_eq!(folded.allowed_destination, Locality::SessionLocal);
    assert_eq!(folded.reliability, Reliability::BestEffort);
    #[cfg(feature = "pubsub-qos")]
    {
        let q = folded.qos.expect("the QoS knobs attach a qos byte");
        assert_eq!(q.priority(), Priority::InteractiveHigh);
        assert!(q.is_express(), "express rides the qos byte");
        assert_eq!(q.raw & (1 << 3), 1 << 3, "Block sets the nodrop bit");
    }

    // ARM 2 (CONTROL): the DEFAULT config folds to a bare put().
    let base = PublishOptions::put();
    let unchanged =
        WireQos::from_options(&AdvancedPublisherOptions::default()).apply(PublishOptions::put());
    assert_eq!(
        unchanged.allowed_destination, base.allowed_destination,
        "a default advanced publisher must not move the locality"
    );
    assert_eq!(
        unchanged.reliability, base.reliability,
        "a default advanced publisher must not move the reliability"
    );
    #[cfg(feature = "pubsub-qos")]
    assert_eq!(
        unchanged.qos.map(|q| q.raw),
        base.qos.map(|q| q.raw),
        "a default advanced publisher must not move the qos byte -- and \
         that includes not ATTACHING one where a bare put() has none, \
         which is the way this could regress silently"
    );
}
