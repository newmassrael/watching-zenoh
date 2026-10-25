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
        }
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
        // A fresh clock per call would be the duplicate-`ID` defect the node
        // clock exists to remove; one static disabled clock is the honest
        // "this plane has none".
        static DISABLED: std::sync::OnceLock<NodeHlc> = std::sync::OnceLock::new();
        DISABLED.get_or_init(NodeHlc::disabled)
    }

    fn stamps(&self) -> bool {
        self.stamps
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
        _options: PublishOptions,
    ) -> Result<usize, PublishError> {
        self.events.lock().unwrap().push(String::from("publish"));
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
    let publisher =
        AdvancedPublisherOn::declare_on(Arc::clone(&plane), "demo/order", options, vec![0x01])
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
    let publisher =
        AdvancedPublisherOn::declare_on(Arc::clone(&plane), "demo/order", options, vec![0x01])
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
            vec![0x01],
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
                vec![0x01],
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
            vec![0x01],
        )
        .is_ok(),
        "a plane that stamps must accept it with no node clock at all"
    );
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
