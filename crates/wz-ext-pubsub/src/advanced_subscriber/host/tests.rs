// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The host against a scripted engine: an engine that records what is declared of it, hands the
//! test the callbacks it was given and lets the test say when a get's legs end. What the machine
//! decides is tested without an engine ([`super::super::state`]); what is tested here is what the
//! host does with it: the entities and the order they are declared and retracted in, the get each
//! trigger issues, what ends a get, and what a teardown stops.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use wz_capi_port::cancellation::CancellableFan;
use wz_capi_port::{
    FanoutError, FilterId, FilterPlane, FilteredPut, LivelinessSink, MatchId, MatchingSink, QblId,
    ReplyCallback, SessionEngine, SubId, SubscriberSink, Tick, TickerId, TokenId, WireKey,
};
use wz_session_core::declare::liveliness_sample::{LivelinessSample, LivelinessSampleKind};
use wz_session_core::declare_form::{InterestForm, RetractionKey};
use wz_session_core::link::RxBytes;
use wz_session_core::locality::Locality;
use wz_session_core::publish_options::{PlainPutParams, PublishOptions};
use wz_session_core::query_options::QueryOptions;
use wz_session_core::reply::{InboundReply, InboundReplyBody};
use wz_session_core::sample::{Sample, SourceInfo};
use wz_session_core::serde_codec::z_serialize;
use wz_session_core::zid_hex::zid_to_zenoh_hex;

use super::super::options::{
    AdvancedSubscriberOptions, DeclarationForms, EntityForm, HistoryConfig, RecoveryConfig,
    SubscriberDetection,
};
use super::{EngineSubscriber, HostError};

/// The zid the scripted session has, as the port hands it: padded to 16 bytes.
const ZID: [u8; 4] = [0xAB, 0xCD, 0xEF, 0x01];

/// What a subscription's sink mints.
type SampleFn = Box<dyn FnMut(&dyn wz_session_core::sink::SampleView) + Send>;

/// A subscriber with what its callbacks collected: the payloads delivered and the sizes of the
/// holes reported.
type Recorded = (EngineSubscriber, Arc<Mutex<Vec<u8>>>, Arc<Mutex<Vec<u32>>>);

/// One get the engine was asked: where, with what parameters, and the legs it minted.
struct GetRecord {
    keyexpr: String,
    parameters: String,
    destination: Locality,
    legs: Vec<Arc<Mutex<Option<ReplyCallback>>>>,
}

/// An engine that records and hands over.
#[derive(Default)]
struct Script {
    next: AtomicU64,
    now: AtomicU64,
    closed: AtomicBool,
    /// Whether the engine runs periodic jobs.
    no_tickers: AtomicBool,
    /// How many legs a get is issued as.
    legs: Mutex<usize>,
    /// What was declared and retracted, in order.
    events: Mutex<Vec<String>>,
    subscriptions: Mutex<Vec<(SubId, String, WireKey, SubscriberSink)>>,
    liveliness: Mutex<Vec<(SubId, String, bool, LivelinessSink)>>,
    gets: Mutex<Vec<GetRecord>>,
    tickers: Mutex<Vec<(TickerId, u64, Tick)>>,
}

impl Script {
    fn new(legs: usize) -> Arc<Self> {
        let script = Self::default();
        *script.legs.lock().unwrap() = legs;
        script.next.store(100, Ordering::SeqCst);
        Arc::new(script)
    }

    fn event(&self, what: impl Into<String>) {
        self.events.lock().unwrap().push(what.into());
    }

    fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }

    /// The `n`th subscription's callback, minted as the engine would for a face.
    fn callback(&self, n: usize) -> SampleFn {
        let sink = Arc::clone(&self.subscriptions.lock().unwrap()[n].3);
        sink()
    }

    fn get_count(&self) -> usize {
        self.gets.lock().unwrap().len()
    }

    /// Feed a reply to leg `leg` of get `get`, if it is still there.
    fn reply(&self, get: usize, leg: usize, reply: &InboundReply) {
        let slot = Arc::clone(&self.gets.lock().unwrap()[get].legs[leg]);
        let mut guard = slot.lock().unwrap();
        if let Some(callback) = guard.as_mut() {
            callback(reply);
        }
    }

    /// End leg `leg` of get `get`: the engine drops its callback.
    fn end_leg(&self, get: usize, leg: usize) {
        let slot = Arc::clone(&self.gets.lock().unwrap()[get].legs[leg]);
        let callback = slot.lock().unwrap().take();
        drop(callback);
    }
}

impl SessionEngine for Script {
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
    fn zid(&self) -> [u8; 16] {
        let mut zid = [0u8; 16];
        zid[..ZID.len()].copy_from_slice(&ZID);
        zid
    }
    fn now_ms(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }
    fn next_entity_id(&self) -> u64 {
        self.next.fetch_add(1, Ordering::SeqCst)
    }
    fn peer_identities(&self) -> Vec<(Vec<u8>, u8)> {
        Vec::new()
    }
    fn has_router_peer(&self) -> bool {
        false
    }
    fn publish_on_wire_all(
        &self,
        _keyexpr: &str,
        _wire: &WireKey,
        _payload: &[u8],
        _opts: &PublishOptions,
    ) -> Result<usize, FanoutError> {
        Ok(0)
    }
    fn declare_subscriber_on_wire(
        &self,
        keyexpr: String,
        wire: WireKey,
        _allowed_origin: Locality,
        _retraction: Option<RetractionKey>,
        sink: SubscriberSink,
    ) -> SubId {
        let id = self.next_entity_id();
        self.event(format!("declare subscriber {keyexpr}"));
        self.subscriptions
            .lock()
            .unwrap()
            .push((id, keyexpr, wire, sink));
        id
    }
    fn undeclare_subscriber(&self, id: SubId) {
        let known = self
            .subscriptions
            .lock()
            .unwrap()
            .iter()
            .find(|s| s.0 == id)
            .map(|s| s.1.clone())
            .or_else(|| {
                self.liveliness
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|s| s.0 == id)
                    .map(|s| s.1.clone())
            });
        self.event(format!("retract {}", known.unwrap_or_default()));
    }
    fn acquire_keyexpr(&self, _keyexpr: String) -> Option<u64> {
        None
    }
    fn release_keyexpr(&self, _mapping_id: u64) {}
    fn keyexpr_declarations(&self) -> Vec<(u64, String)> {
        Vec::new()
    }
    fn declare_matching_listener(
        &self,
        _plane: FilterPlane,
        _keyexpr: String,
        _sink: MatchingSink,
        _count_local: bool,
    ) -> MatchId {
        0
    }
    fn undeclare_matching_listener(&self, _id: MatchId) {}
    fn declare_write_filter(
        &self,
        _plane: FilterPlane,
        _keyexpr: String,
        _wire: &WireKey,
        _ask: Option<InterestForm>,
        _count_local: bool,
    ) -> FilterId {
        0
    }
    fn write_filter_active(&self, _id: FilterId) -> bool {
        false
    }
    fn write_filter_holds_back(&self, _id: FilterId) -> bool {
        false
    }
    fn undeclare_write_filter(&self, _id: FilterId) {}
    fn put_plain_filtered(
        &self,
        _filter: FilterId,
        _keyexpr: &str,
        _mapping_id: u64,
        _payload: &[u8],
        _params: &PlainPutParams,
    ) -> FilteredPut {
        FilteredPut::NotPlain
    }
    fn batch_start_all(&self) -> usize {
        0
    }
    fn batch_flush_all(&self) -> usize {
        0
    }
    fn batch_stop_all(&self) -> usize {
        0
    }
    fn declare_liveliness_token_on_wire(
        &self,
        keyexpr: String,
        _wire: WireKey,
        _retraction: Option<RetractionKey>,
    ) -> Option<TokenId> {
        let id = self.next_entity_id();
        self.event(format!("declare token {keyexpr}"));
        Some(id)
    }
    fn undeclare_liveliness_token(&self, _id: TokenId) {
        self.event("retract token");
    }
    fn declare_liveliness_subscriber_on_wire(
        &self,
        keyexpr: String,
        _wire: WireKey,
        history: bool,
        sink: LivelinessSink,
    ) -> Option<SubId> {
        let id = self.next_entity_id();
        self.event(format!("declare liveliness {keyexpr}"));
        self.liveliness
            .lock()
            .unwrap()
            .push((id, keyexpr, history, sink));
        Some(id)
    }
    fn get_on_wire(
        &self,
        keyexpr: &str,
        _wire: &WireKey,
        opts: &QueryOptions,
        fan: Option<&CancellableFan>,
        leg: &mut dyn FnMut() -> ReplyCallback,
    ) -> Option<usize> {
        let mut legs = Vec::new();
        for _ in 0..*self.legs.lock().unwrap() {
            let slot = Arc::new(Mutex::new(Some(leg())));
            if let Some(fan) = fan {
                // What a cancelled get undoes: the engine forgets the leg, dropping its callback.
                let undo = Arc::clone(&slot);
                fan.record(move || {
                    let callback = undo.lock().unwrap().take();
                    drop(callback);
                });
            }
            legs.push(slot);
        }
        let count = legs.len();
        self.event(format!("get {keyexpr}"));
        self.gets.lock().unwrap().push(GetRecord {
            keyexpr: keyexpr.to_owned(),
            parameters: String::from_utf8(opts.parameters.clone().unwrap_or_default())
                .expect("parameters are text"),
            destination: opts.allowed_destination,
            legs,
        });
        Some(count)
    }
    fn start_ticker(&self, period_ms: u64, tick: Tick) -> Option<TickerId> {
        if self.no_tickers.load(Ordering::SeqCst) {
            return None;
        }
        let id = self.next_entity_id();
        self.event(format!("start ticker {period_ms}"));
        self.tickers.lock().unwrap().push((id, period_ms, tick));
        Some(id)
    }
    fn stop_ticker(&self, _id: TickerId) {
        self.event("stop ticker");
    }
    fn declare_queryable_on_wire(
        &self,
        _keyexpr: String,
        _wire: WireKey,
        _complete: bool,
        _allowed_origin: Locality,
        _retraction: Option<RetractionKey>,
        _sink: wz_capi_port::QueryableSink,
    ) -> Option<QblId> {
        None
    }
}

fn engine(script: &Arc<Script>) -> Arc<dyn SessionEngine> {
    let engine: Arc<dyn SessionEngine> = script.clone();
    engine
}

/// A sample on `demo/data` from the publisher `(ZID of 0x02, eid 7)` with sequence number `sn`.
fn sample(sn: u32, v: u8) -> Sample {
    let mut sample = Sample::new_put("demo/data", vec![v]);
    sample.source_info = Some(SourceInfo::new(&[0x02], 7, sn));
    sample
}

/// A recovery reply from the cache, carrying the source identity that re-keys it.
fn reply(sn: u32, v: u8) -> InboundReply {
    InboundReply {
        rid: 1,
        keyexpr_literal: "demo/data".into(),
        body: InboundReplyBody::Put {
            payload: RxBytes::from(vec![v]),
            attachment: None,
            encoding: None,
            source_info: Some(SourceInfo::new(&[0x02], 7, sn)),
            timestamp: None,
        },
        responder: None,
        qos: None,
        stamp: Default::default(),
    }
}

/// A subscriber that records what it delivers and what it misses.
fn recording(script: &Arc<Script>, options: AdvancedSubscriberOptions) -> Recorded {
    let delivered = Arc::new(Mutex::new(Vec::new()));
    let misses = Arc::new(Mutex::new(Vec::new()));
    let d = Arc::clone(&delivered);
    let m = Arc::clone(&misses);
    let subscriber = EngineSubscriber::declare_with_miss_listener(
        &engine(script),
        "demo/data",
        options,
        move |s: Sample| d.lock().unwrap().push(s.payload[0]),
        move |miss| m.lock().unwrap().push(miss.nb()),
    )
    .expect("the subscriber declares on the scripted engine");
    (subscriber, delivered, misses)
}

fn publisher_hex() -> String {
    zid_to_zenoh_hex(&[0x02])
}

/// A plain subscriber is one subscription: samples deliver in order, a forward gap is reported
/// and delivered past, and the session's zid is the identity trimmed of its padding.
#[test]
fn a_plain_subscriber_orders_reports_a_miss_and_is_named_by_the_trimmed_zid() {
    let script = Script::new(1);
    let (subscriber, delivered, misses) = recording(&script, AdvancedSubscriberOptions::new());
    assert_eq!(script.events(), ["declare subscriber demo/data"]);
    assert_eq!(
        subscriber.id().zid(),
        ZID,
        "the 16 padded bytes are trimmed"
    );
    assert_eq!(subscriber.keyexpr(), "demo/data");

    let mut callback = script.callback(0);
    callback(&sample(0, 10));
    callback(&sample(1, 11));
    callback(&sample(1, 99)); // a duplicate
    callback(&sample(4, 14)); // a forward gap of two
    assert_eq!(*delivered.lock().unwrap(), [10, 11, 14]);
    assert_eq!(*misses.lock().unwrap(), [2]);
    assert_eq!(script.get_count(), 0, "no recovery was asked for");
}

/// A recovering subscriber that sees a gap asks the publisher's cache for the range, buffers what
/// arrived past the hole, and delivers it in order when the get is over.
#[test]
fn a_gap_asks_the_cache_and_the_get_ends_with_the_last_leg() {
    let script = Script::new(2);
    let options = AdvancedSubscriberOptions::new()
        .with_recovery(RecoveryConfig::new())
        .with_get_locality(Locality::SessionLocal)
        .with_query_timeout(Duration::from_millis(250));
    let (subscriber, delivered, misses) = recording(&script, options);

    let mut callback = script.callback(0);
    callback(&sample(0, 10));
    callback(&sample(3, 13));
    assert_eq!(*delivered.lock().unwrap(), [10], "sn 3 waits for the hole");
    assert_eq!(script.get_count(), 1);
    {
        let gets = script.gets.lock().unwrap();
        assert_eq!(
            gets[0].keyexpr,
            crate::advanced_ke::recovery_get_ke("demo/data", &publisher_hex(), 7)
        );
        assert_eq!(gets[0].parameters, "_sn=1..;_anyke");
        assert_eq!(gets[0].destination, Locality::SessionLocal);
        assert_eq!(gets[0].legs.len(), 2);
    }

    // The first leg answers sn 1 and ends: sn 2 is still missing and the get is not over, so
    // nothing is given up on and sn 3 is still held.
    script.reply(0, 0, &reply(1, 11));
    script.end_leg(0, 0);
    assert_eq!(*delivered.lock().unwrap(), [10, 11]);
    assert!(misses.lock().unwrap().is_empty());

    // The last leg ends: the get is over, so sn 2 is a miss and what was held delivers.
    script.end_leg(0, 1);
    assert_eq!(*delivered.lock().unwrap(), [10, 11, 13]);
    assert_eq!(*misses.lock().unwrap(), [1]);
    drop(subscriber);
}

/// A reply keyed outside the subscription is refused here, though `_anyke` invited it.
#[test]
fn a_reply_outside_the_subscription_is_dropped() {
    let script = Script::new(1);
    let options = AdvancedSubscriberOptions::new().with_recovery(RecoveryConfig::new());
    let (_subscriber, delivered, _misses) = recording(&script, options);
    let mut callback = script.callback(0);
    callback(&sample(0, 10));
    callback(&sample(2, 12));

    let mut stray = reply(1, 11);
    stray.keyexpr_literal = "other/key".into();
    script.reply(0, 0, &stray);
    script.end_leg(0, 0);
    assert_eq!(
        *delivered.lock().unwrap(),
        [10, 12],
        "the stray reply did not fill the hole: sn 2 delivered past it"
    );
}

/// A get no leg was issued for ends at once, after the call returned: the hole is reported and
/// what was buffered delivers.
#[test]
fn a_get_with_no_leg_ends_at_once() {
    let script = Script::new(0);
    let options = AdvancedSubscriberOptions::new().with_recovery(RecoveryConfig::new());
    let (_subscriber, delivered, misses) = recording(&script, options);
    let mut callback = script.callback(0);
    callback(&sample(0, 10));
    callback(&sample(2, 12));
    assert_eq!(script.get_count(), 1);
    assert_eq!(*delivered.lock().unwrap(), [10, 12]);
    assert_eq!(*misses.lock().unwrap(), [1]);
}

/// Dropping the subscriber retracts the subscription, cancels the get in flight and delivers
/// nothing more: the callback the application gave may be freed the moment the handle is.
#[test]
fn a_teardown_cancels_the_get_and_the_ending_legs_deliver_nothing() {
    let script = Script::new(1);
    let options = AdvancedSubscriberOptions::new().with_recovery(RecoveryConfig::new());
    let (subscriber, delivered, misses) = recording(&script, options);
    let mut callback = script.callback(0);
    callback(&sample(0, 10));
    callback(&sample(2, 12));
    assert_eq!(script.get_count(), 1);

    drop(subscriber);
    assert_eq!(*delivered.lock().unwrap(), [10], "sn 2 was never flushed");
    assert!(misses.lock().unwrap().is_empty());
    // The engine's leg callback was dropped by the cancellation, and a late sample is refused.
    assert!(script.gets.lock().unwrap()[0].legs[0]
        .lock()
        .unwrap()
        .is_none());
    callback(&sample(3, 13));
    assert_eq!(*delivered.lock().unwrap(), [10]);
    assert_eq!(
        script.events(),
        [
            "declare subscriber demo/data".to_owned(),
            "start ticker 3600000".to_owned(),
            format!(
                "get {}",
                crate::advanced_ke::recovery_get_ke("demo/data", &publisher_hex(), 7)
            ),
            "retract demo/data".to_owned(),
            "stop ticker".to_owned(),
        ]
    );
}

/// A heartbeat beacon ahead of what was delivered asks for the bounded range.
#[test]
fn a_heartbeat_beacon_ahead_of_the_stream_asks_for_the_bounded_range() {
    let script = Script::new(1);
    let options =
        AdvancedSubscriberOptions::new().with_recovery(RecoveryConfig::new().with_heartbeat());
    let (subscriber, delivered, _misses) = recording(&script, options);
    assert!(subscriber.heartbeat_channel_is_live());
    assert_eq!(
        script.events(),
        [
            "declare subscriber demo/data",
            "start ticker 3600000",
            "declare subscriber demo/data/@adv/pub/**"
        ]
    );

    let mut live = script.callback(0);
    live(&sample(0, 10));
    live(&sample(1, 11));

    let mut beacon = Sample::new_put(
        format!("demo/data/@adv/pub/{}/7/_", publisher_hex()),
        z_serialize::<u32>(&4),
    );
    beacon.source_info = None;
    let mut heartbeat = script.callback(1);
    heartbeat(&beacon);
    assert_eq!(script.get_count(), 1);
    assert_eq!(script.gets.lock().unwrap()[0].parameters, "_sn=2..4;_anyke");
    script.reply(0, 0, &reply(2, 12));
    script.reply(0, 0, &reply(3, 13));
    script.reply(0, 0, &reply(4, 14));
    script.end_leg(0, 0);
    assert_eq!(*delivered.lock().unwrap(), [10, 11, 12, 13, 14]);

    // A beacon at or behind the stream asks for nothing.
    heartbeat(&beacon);
    assert_eq!(script.get_count(), 1);
}

/// The retention sweep and the periodic re-ask are jobs of the engine, and what the tick does is
/// the machine's: the re-ask for each quiet source, the sweep of the ones nobody heard from.
#[test]
fn the_periodic_jobs_run_on_the_engine_and_stop_with_the_subscriber() {
    let script = Script::new(1);
    let options = AdvancedSubscriberOptions::new().with_recovery(
        RecoveryConfig::new()
            .with_periodic_queries(Duration::from_millis(500))
            .with_retention_period(Duration::from_secs(60)),
    );
    let (subscriber, delivered, _misses) = recording(&script, options);
    assert_eq!(
        script.events(),
        [
            "declare subscriber demo/data",
            "start ticker 60000",
            "start ticker 500"
        ]
    );

    let mut live = script.callback(0);
    live(&sample(0, 10));
    let (_, period, periodic) = script.tickers.lock().unwrap()[1].clone();
    assert_eq!(period, 500);
    assert!(periodic(), "the job goes on");
    assert_eq!(script.get_count(), 1);
    assert_eq!(script.gets.lock().unwrap()[0].parameters, "_sn=1..;_anyke");
    script.reply(0, 0, &reply(1, 11));
    script.end_leg(0, 0);
    assert_eq!(*delivered.lock().unwrap(), [10, 11]);

    // The sweep reads the engine's clock: far enough on, the quiet source is dropped, and the
    // next sample from it is a first one again.
    let (_, _, retention) = script.tickers.lock().unwrap()[0].clone();
    script.now.store(10 * 60 * 1000, Ordering::SeqCst);
    assert!(retention());
    live(&sample(7, 17));
    assert_eq!(*delivered.lock().unwrap(), [10, 11, 17]);

    drop(subscriber);
    let events = script.events();
    assert_eq!(events.iter().filter(|e| *e == "stop ticker").count(), 2);
    // The jobs end by themselves once what they work on is gone.
    assert!(!periodic());
    assert!(!retention());
}

/// A subscriber that wants a periodic job on an engine that runs none is refused, not left
/// without the job.
#[test]
fn an_engine_without_periodic_jobs_refuses_a_periodic_subscriber() {
    let script = Script::new(1);
    script.no_tickers.store(true, Ordering::SeqCst);
    let options = AdvancedSubscriberOptions::new().with_recovery(RecoveryConfig::new());
    let refused = EngineSubscriber::declare(&engine(&script), "demo/data", options, |_| {});
    assert!(matches!(refused, Err(HostError::Refused(_))));
    // What was declared before the refusal is retracted.
    assert_eq!(
        script.events(),
        ["declare subscriber demo/data", "retract demo/data"]
    );
}

/// The startup get is issued after the live subscription, holds the live samples until it ends,
/// and delivers the history first.
#[test]
fn the_startup_get_holds_live_samples_until_the_history_is_in() {
    let script = Script::new(1);
    let options = AdvancedSubscriberOptions::new()
        .with_recovery(RecoveryConfig::new())
        .with_history(HistoryConfig::new().max_samples(8));
    let (_subscriber, delivered, _misses) = recording(&script, options);
    assert_eq!(
        script.events()[..3],
        [
            "declare subscriber demo/data",
            "start ticker 3600000",
            "get demo/data/@adv/**"
        ]
    );
    assert_eq!(script.gets.lock().unwrap()[0].parameters, "_max=8;_anyke");

    let mut live = script.callback(0);
    live(&sample(2, 12));
    assert!(
        delivered.lock().unwrap().is_empty(),
        "held while the history is out"
    );
    script.reply(0, 0, &reply(0, 10));
    script.reply(0, 0, &reply(1, 11));
    script.end_leg(0, 0);
    assert_eq!(*delivered.lock().unwrap(), [10, 11, 12]);
}

/// A publisher that appears after the subscriber joined has its cache recovered, through the
/// liveliness subscription that replays the tokens already alive.
#[test]
fn a_late_publisher_has_its_cache_recovered() {
    let script = Script::new(1);
    let options = AdvancedSubscriberOptions::new()
        .with_recovery(RecoveryConfig::new())
        .with_history(HistoryConfig::new().detect_late_publishers());
    let (_subscriber, delivered, _misses) = recording(&script, options);
    assert_eq!(
        script.liveliness.lock().unwrap()[0].1,
        "demo/data/@adv/pub/**"
    );
    assert!(
        script.liveliness.lock().unwrap()[0].2,
        "the tokens alive are replayed"
    );

    // The startup get ends with nothing; then a publisher's token arrives.
    script.end_leg(0, 0);
    let token = format!("demo/data/@adv/pub/{}/7/_", publisher_hex());
    let sink = Arc::clone(&script.liveliness.lock().unwrap()[0].3);
    let mut on_token = sink();
    on_token(LivelinessSample {
        kind: LivelinessSampleKind::Put,
        keyexpr: &token,
        token_id: 1,
    });
    assert_eq!(script.get_count(), 2);
    assert_eq!(
        script.gets.lock().unwrap()[1].keyexpr,
        crate::advanced_ke::recovery_get_ke("demo/data", &publisher_hex(), 7)
    );
    script.reply(1, 0, &reply(0, 10));
    script.reply(1, 0, &reply(1, 11));
    script.end_leg(1, 0);
    assert_eq!(*delivered.lock().unwrap(), [10, 11]);

    // The same token again while it is in no get asks again; a departure asks nothing.
    on_token(LivelinessSample {
        kind: LivelinessSampleKind::Delete,
        keyexpr: &token,
        token_id: 1,
    });
    assert_eq!(script.get_count(), 2);
}

/// The detection token is declared last, named with the subscriber's own identity, and the
/// entities retract in the tokio runtime's order.
#[test]
fn the_detection_token_is_last_and_the_entities_retract_in_order() {
    let script = Script::new(1);
    let options = AdvancedSubscriberOptions::new()
        .with_recovery(RecoveryConfig::new().with_heartbeat())
        .with_history(HistoryConfig::new().detect_late_publishers())
        .with_subscriber_detection(SubscriberDetection::new());
    let (subscriber, _delivered, _misses) = recording(&script, options);
    let id = subscriber.id();
    let token = crate::advanced_ke::subscriber_adv_ke(
        "demo/data",
        &zid_to_zenoh_hex(id.zid()),
        id.eid(),
        None,
    );
    let declared = script.events();
    assert_eq!(declared.last().unwrap(), &format!("declare token {token}"));
    assert_eq!(
        declared
            .iter()
            .position(|e| e == "declare liveliness demo/data/@adv/pub/**")
            .unwrap()
            + 1,
        declared
            .iter()
            .position(|e| e == "declare subscriber demo/data/@adv/pub/**")
            .unwrap(),
        "the heartbeat subscription follows the late-publisher one"
    );

    script.events.lock().unwrap().clear();
    drop(subscriber);
    assert_eq!(
        script.events(),
        [
            "retract demo/data",
            "stop ticker",
            "retract demo/data/@adv/pub/**",
            "retract demo/data/@adv/pub/**",
            "retract token"
        ],
        "the subscription, the retention job, the two liveliness-order subscriptions, the token"
    );
}

/// In the background nothing is retracted and nothing is stopped, and the host's names are
/// handed back to it.
#[test]
fn a_background_subscriber_retracts_nothing() {
    #[derive(Default)]
    struct Forms {
        retained: Mutex<usize>,
    }
    impl DeclarationForms for Forms {
        fn entity_id(&self) -> Option<u32> {
            Some(77)
        }
        fn subscriber(&self, _keyexpr: &str) -> EntityForm {
            EntityForm::aliased(5, Some("/data".into())).keeping(Arc::new(()))
        }
        fn retain(&self, _anchor: Arc<dyn Send + Sync>) {
            *self.retained.lock().unwrap() += 1;
        }
    }
    let forms = Arc::new(Forms::default());
    let script = Script::new(1);
    let options = AdvancedSubscriberOptions::new()
        .with_recovery(RecoveryConfig::new())
        .with_declaration_forms(forms.clone());
    let (subscriber, _delivered, _misses) = recording(&script, options);
    assert_eq!(
        subscriber.id().eid(),
        77,
        "the host's identity is the subscriber's"
    );
    {
        let subscriptions = script.subscriptions.lock().unwrap();
        assert_eq!(subscriptions[0].2.mapping_id, 5, "named as the host said");
        assert_eq!(subscriptions[0].2.suffix.as_deref(), Some("/data"));
    }
    script.events.lock().unwrap().clear();
    subscriber.background();
    assert_eq!(script.events(), Vec::<String>::new());
    assert_eq!(
        *forms.retained.lock().unwrap(),
        1,
        "the name went back to its host"
    );
}

/// What is refused before anything is declared.
#[test]
fn what_is_refused_declares_nothing() {
    let script = Script::new(1);
    let declare = |options: AdvancedSubscriberOptions| {
        EngineSubscriber::declare(&engine(&script), "demo/data", options, |_| {}).map(|_| ())
    };
    assert_eq!(
        declare(AdvancedSubscriberOptions::new().with_history(HistoryConfig::new().max_samples(0))),
        Err(HostError::HistoryBoundZero {
            knob: "max_samples"
        })
    );
    assert_eq!(
        declare(AdvancedSubscriberOptions::new().with_history(HistoryConfig::new().max_age(0.0))),
        Err(HostError::HistoryBoundZero { knob: "max_age" })
    );
    script.closed.store(true, Ordering::SeqCst);
    assert!(matches!(
        declare(AdvancedSubscriberOptions::new()),
        Err(HostError::Refused(_))
    ));
    assert!(script.events().is_empty());
}
