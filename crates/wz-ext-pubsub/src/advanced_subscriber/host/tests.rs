// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The host against a scripted engine: an engine that records what is declared of it, hands the
//! test the callbacks it was given and lets the test say when a get's legs end. What the machine
//! decides is tested without an engine ([`super::super::state`]); what is tested here is what the
//! host does with it: the entities and the order they are declared and retracted in, the get each
//! trigger issues, what ends a get, and what a teardown stops.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use wz_capi_port::cancellation::{CancellableFan, FanCanceller, FanKey, TokenRef};
use wz_capi_port::{
    BatchStep, FanoutError, FilterId, FilterPlane, FilteredPut, LivelinessSink, MatchId,
    MatchingSink, QblId, Refusal, ReplyCallback, SessionEngine, SubId, SubscriberSink, Tick,
    TickerId, TokenId, WireKey,
};
use wz_session_core::declare::liveliness_sample::{LivelinessSample, LivelinessSampleKind};
use wz_session_core::declare_form::{InterestAsk, RetractionKey};
use wz_session_core::link::RxBytes;
use wz_session_core::locality::Locality;
use wz_session_core::publish_options::{PlainPutParams, PublishOptions};
use wz_session_core::query_options::{QueryOptions, QueryOptionsOf};
use wz_session_core::reply::{InboundReply, InboundReplyBody};
use wz_session_core::sample::{Sample, SourceInfo};
use wz_session_core::serde_codec::z_serialize;
use wz_session_core::session_zid::SessionZid;
use wz_session_core::zid_hex::zid_to_zenoh_hex;

use super::super::options::{
    AdvancedSubscriberOptions, DeclarationForms, EntityForm, HistoryConfig, RecoveryConfig,
    SubscriberDetection,
};
use super::super::state::{Delivery, MissHandlers, State};
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
    /// The key of the fan that cancels the get, when a token can.
    fan: Option<FanKey>,
}

/// An engine that records and hands over.
#[derive(Default)]
struct Script {
    /// The script itself, as the fans it is attached to reach it.
    this: Weak<Script>,
    next: AtomicU64,
    now: AtomicU64,
    closed: AtomicBool,
    /// Whether the engine runs periodic jobs.
    no_tickers: AtomicBool,
    /// Whether the session has handed out every declaration id, so a subscription is refused.
    ids_spent: AtomicBool,
    /// How many legs a get is issued as.
    legs: Mutex<usize>,
    /// What was declared and retracted, in order.
    events: Mutex<Vec<String>>,
    subscriptions: Mutex<Vec<(SubId, String, WireKey, Arc<SubscriberSink>)>>,
    liveliness: Mutex<Vec<(SubId, String, bool, Arc<LivelinessSink>)>>,
    gets: Mutex<Vec<GetRecord>>,
    tickers: Mutex<Vec<(TickerId, u64, Tick)>>,
}

impl Script {
    fn new(legs: usize) -> Arc<Self> {
        Arc::new_cyclic(|this| {
            let script = Self {
                this: Weak::clone(this),
                ..Self::default()
            };
            *script.legs.lock().unwrap() = legs;
            script.next.store(100, Ordering::SeqCst);
            script
        })
    }

    /// The next id the script hands out, for every kind it records.
    fn take_id(&self) -> u64 {
        self.next.fetch_add(1, Ordering::SeqCst)
    }

    fn event(&self, what: impl Into<String>) {
        self.events.lock().unwrap().push(what.into());
    }

    fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }

    /// The `n`th subscription's callback, called as an engine calls it.
    fn callback(&self, n: usize) -> SampleFn {
        let sink = Arc::clone(&self.subscriptions.lock().unwrap()[n].3);
        Box::new(move |sample: &dyn wz_session_core::sink::SampleView| sink.call(sample))
    }

    fn get_count(&self) -> usize {
        self.gets.lock().unwrap().len()
    }

    /// Feed a reply to leg `leg` of get `get`, if it is still there.
    fn reply(&self, get: usize, leg: usize, reply: &InboundReply) {
        let slot = Arc::clone(&self.gets.lock().unwrap()[get].legs[leg]);
        let guard = slot.lock().unwrap();
        if let Some(callback) = guard.as_ref() {
            callback.call(reply);
        }
    }

    /// End leg `leg` of get `get`: the engine drops its callback.
    fn end_leg(&self, get: usize, leg: usize) {
        let slot = Arc::clone(&self.gets.lock().unwrap()[get].legs[leg]);
        let callback = slot.lock().unwrap().take();
        drop(callback);
    }
}

impl wz_capi_port::KeyHolds for Script {
    fn release_keyexpr(&self, _mapping_id: wz_session_core::wire_id::ExprId) {}

    // The script declares no key (`acquire_keyexpr` above), so no hold reaches here.
    fn retain_keyexpr(&self, _mapping_id: wz_session_core::wire_id::ExprId) {}
}

impl wz_capi_port::Tickers for Script {
    fn start_ticker(&self, period_ms: u64, tick: Tick) -> Result<TickerId, Refusal> {
        if self.no_tickers.load(Ordering::SeqCst) {
            return Err(Refusal::NotBuilt);
        }
        let id = self.take_id();
        self.event(format!("start ticker {period_ms}"));
        self.tickers.lock().unwrap().push((id, period_ms, tick));
        Ok(id)
    }
    fn stop_ticker(&self, _id: TickerId) {
        self.event("stop ticker");
    }
}

/// What a cancelled get undoes: the script forgets each leg of the gets the fan tagged, dropping
/// its callback, after letting go of its own lock.
impl FanCanceller for Script {
    fn cancel_fan(&self, key: FanKey) {
        let forgotten: Vec<ReplyCallback> = self
            .gets
            .lock()
            .unwrap()
            .iter()
            .filter(|get| get.fan == Some(key))
            .flat_map(|get| {
                get.legs
                    .iter()
                    .filter_map(|slot| slot.lock().unwrap().take())
            })
            .collect();
        drop(forgotten);
    }
}

impl SessionEngine for Script {
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
    fn session_zid(&self) -> SessionZid {
        ZID.into()
    }
    fn now_ms(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }
    fn next_entity_id(&self) -> Option<u32> {
        u32::try_from(self.take_id()).ok()
    }
    fn next_peer(&self, _from: u64) -> Option<(u64, wz_capi_port::PeerIdentity)> {
        None
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
        keyexpr: &str,
        wire: WireKey,
        _allowed_origin: Locality,
        _retraction: Option<RetractionKey>,
        sink: SubscriberSink,
    ) -> Result<SubId, Refusal> {
        if self.ids_spent.load(Ordering::SeqCst) {
            return Err(Refusal::NoEntityId);
        }
        let id = self.next_entity_id().ok_or(Refusal::NoEntityId)?;
        self.event(format!("declare subscriber {keyexpr}"));
        self.subscriptions
            .lock()
            .unwrap()
            .push((id, keyexpr.to_owned(), wire, Arc::new(sink)));
        Ok(id)
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
    fn acquire_keyexpr(&self, _keyexpr: &str) -> Result<wz_session_core::wire_id::ExprId, Refusal> {
        Err(Refusal::NotBuilt)
    }
    fn declare_matching_listener(
        &self,
        _plane: FilterPlane,
        _keyexpr: &str,
        _sink: MatchingSink,
        _count_local: bool,
    ) -> Result<MatchId, Refusal> {
        Ok(0)
    }
    fn undeclare_matching_listener(&self, _id: MatchId) {}
    fn declare_write_filter(
        &self,
        _plane: FilterPlane,
        _keyexpr: &str,
        _wire: &WireKey,
        _ask: Option<InterestAsk<'_>>,
        _count_local: bool,
    ) -> Result<FilterId, Refusal> {
        Ok(0)
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
        _mapping_id: wz_session_core::wire_id::ExprId,
        _payload: &[u8],
        _params: &PlainPutParams,
    ) -> FilteredPut {
        FilteredPut::NotPlain
    }
    fn keep_write_filter_plain(
        &self,
        _filter: FilterId,
        _plain: Option<(PlainPutParams, wz_session_core::wire_id::ExprId)>,
    ) {
    }
    fn publish_filtered(
        &self,
        _filter: FilterId,
        keyexpr: &str,
        wire: &WireKey,
        payload: &[u8],
        opts: Option<&PublishOptions>,
    ) -> FilteredPut {
        match opts {
            Some(opts) => FilteredPut::Sent(self.publish_on_wire_all(keyexpr, wire, payload, opts)),
            None => FilteredPut::NotPlain,
        }
    }
    fn batch_all(&self, _step: BatchStep) -> usize {
        0
    }
    fn declare_liveliness_token_on_wire(
        &self,
        keyexpr: &str,
        _wire: WireKey,
        _retraction: Option<RetractionKey>,
    ) -> Result<TokenId, Refusal> {
        let id = self.next_entity_id().ok_or(Refusal::NoEntityId)?;
        self.event(format!("declare token {keyexpr}"));
        Ok(id)
    }
    fn undeclare_liveliness_token(&self, _id: TokenId) {
        self.event("retract token");
    }
    fn declare_liveliness_subscriber_on_wire(
        &self,
        keyexpr: &str,
        _wire: WireKey,
        history: bool,
        sink: LivelinessSink,
    ) -> Result<SubId, Refusal> {
        let id = self.next_entity_id().ok_or(Refusal::NoEntityId)?;
        self.event(format!("declare liveliness {keyexpr}"));
        self.liveliness
            .lock()
            .unwrap()
            .push((id, keyexpr.to_owned(), history, Arc::new(sink)));
        Ok(id)
    }
    fn get_on_wire(
        &self,
        keyexpr: &str,
        _wire: &WireKey,
        opts: &QueryOptionsOf<'_>,
        fan: Option<&CancellableFan>,
        leg: &mut dyn FnMut() -> ReplyCallback,
    ) -> Result<usize, Refusal> {
        // The script is what ends the legs a cancelled fan tagged, as an engine is.
        let tag = match fan {
            Some(fan) => {
                let canceller: Weak<dyn FanCanceller> = Weak::<Script>::clone(&self.this);
                if !fan.attach(&canceller) {
                    return Ok(0);
                }
                Some(fan.key())
            }
            None => None,
        };
        let mut legs = Vec::new();
        for _ in 0..*self.legs.lock().unwrap() {
            legs.push(Arc::new(Mutex::new(Some(leg()))));
        }
        let count = legs.len();
        self.event(format!("get {keyexpr}"));
        self.gets.lock().unwrap().push(GetRecord {
            keyexpr: keyexpr.to_owned(),
            parameters: String::from_utf8(opts.parameters.as_deref().unwrap_or_default().to_vec())
                .expect("parameters are text"),
            destination: opts.allowed_destination,
            legs,
            fan: tag,
        });
        Ok(count)
    }
    fn declare_queryable_on_wire(
        &self,
        _keyexpr: &str,
        _wire: WireKey,
        _complete: bool,
        _allowed_origin: Locality,
        _retraction: Option<RetractionKey>,
        _sink: wz_capi_port::QueryableSink,
    ) -> Result<QblId, Refusal> {
        Err(Refusal::NotBuilt)
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
        move |s: Delivery<'_>| d.lock().unwrap().push(s.view().payload()[0]),
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

/// An engine named by its own type hosts the same subscriber as the port's object does: the same
/// entities and jobs declared, and the same retracted when it is dropped.
#[test]
fn an_engine_of_its_own_type_hosts_the_subscriber_as_the_port_object_does() {
    let options = || {
        AdvancedSubscriberOptions::new().with_recovery(
            RecoveryConfig::new()
                .with_periodic_queries(Duration::from_millis(500))
                .with_retention_period(Duration::from_secs(60)),
        )
    };
    let concrete = Script::new(1);
    let subscriber: EngineSubscriber<Script> =
        EngineSubscriber::declare(&concrete, "demo/data", options(), |_| {})
            .expect("the subscriber declares on the scripted engine as its own type");
    drop(subscriber);
    let object = Script::new(1);
    let (subscriber, _delivered, _misses) = recording(&object, options());
    drop(subscriber);
    assert_eq!(concrete.events(), object.events());
    assert_eq!(
        concrete
            .events()
            .iter()
            .filter(|e| *e == "stop ticker")
            .count(),
        2
    );
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
    sink.call(LivelinessSample {
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
    sink.call(LivelinessSample {
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

/// A session with no declaration id left refuses the subscription, and the subscriber is
/// refused with it rather than left without its live subscription.
#[test]
fn a_session_with_no_id_left_refuses_the_subscriber() {
    let script = Script::new(1);
    script.ids_spent.store(true, Ordering::SeqCst);
    let refused = EngineSubscriber::declare(
        &engine(&script),
        "demo/data",
        AdvancedSubscriberOptions::new(),
        |_| {},
    )
    .map(|_| ());
    assert_eq!(refused, Err(HostError::IdsExhausted));
    assert!(script.events().is_empty(), "nothing was declared");
    assert!(script.subscriptions.lock().unwrap().is_empty());
}

/// With no host identity, a subscriber reports its subscription's id as its entity id, the last
/// one an engine hands out included: the id is the one its declaration carries, of the width an
/// identity holds.
#[test]
fn a_subscriber_without_a_host_identity_reports_its_subscription_id() {
    let id = super::identity_of(ZID.into(), u32::MAX, None);
    assert_eq!((id.zid(), id.eid()), (&ZID[..], u32::MAX));
}

/// A subscriber's identity is its engine's zid as the handshake carries it, read from the
/// engine and not from the padded form a C ABI's id holds.
#[test]
fn a_subscriber_is_named_by_its_engines_session_zid() {
    let script = Script::new(1);
    let declared = EngineSubscriber::declare(
        &engine(&script),
        "demo/data",
        AdvancedSubscriberOptions::new(),
        |_| {},
    )
    .expect("the scripted engine declares");
    assert_eq!(declared.id().zid(), &ZID[..]);
}

// ---------------------------------------------------------------------------------------------
// What asking a get and subscribing take of the heap. The crate's other lib tests run beside these
// on libtest's other threads and allocate as they please; the count is of the thread a test runs
// on (a thread-local cell the allocator bumps), and a window opens and closes on that thread with
// nothing handed to another in between, so what the others allocate never reaches it.

/// Counts the allocations made BY THE CURRENT THREAD.
struct CountingAllocator;

thread_local! {
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

// SAFETY: every call forwards to `System` unchanged; the only addition is a bump of a thread-local
// cell without a destructor, which neither allocates nor unwinds.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
        // SAFETY: the caller's contract, forwarded.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
        // SAFETY: the caller's contract, forwarded.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
        // SAFETY: the caller's contract, forwarded.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller's contract, forwarded.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static COUNTING: CountingAllocator = CountingAllocator;

fn allocations() -> usize {
    ALLOCATIONS.with(Cell::get)
}

/// A subscriber's shared part on the scripted engine with its startup get counted in flight,
/// recording what it delivers into `delivered`.
fn shared_on(
    script: &Arc<Script>,
    delivered: &Arc<Mutex<Vec<u8>>>,
) -> Arc<super::Shared<dyn SessionEngine>> {
    shared_on_key(script, delivered, "demo/data")
}

/// [`shared_on`] subscribing to `base`.
fn shared_on_key(
    script: &Arc<Script>,
    delivered: &Arc<Mutex<Vec<u8>>>,
    base: &str,
) -> Arc<super::Shared<dyn SessionEngine>> {
    let d = Arc::clone(delivered);
    let state = State::new(
        Box::new(move |s: Delivery<'_>| d.lock().unwrap().push(s.view().payload()[0])),
        MissHandlers::default(),
    )
    .with_retransmission(true)
    .with_history(1, usize::MAX);
    Arc::new(super::Shared::new(
        Arc::downgrade(&engine(script)),
        state,
        base.into(),
        Locality::SessionLocal,
        1_000,
    ))
}

/// A get's slot, its fan's registration, its legs, a reply keyed outside the subscription and
/// the get's end take no memory: the end frees the slot, drops the fan from the token and lets go
/// of every count of the subscriber the legs held.
#[test]
fn a_get_its_legs_and_its_end_take_no_memory() {
    let script = Script::new(1);
    let delivered = Arc::new(Mutex::new(Vec::new()));
    let shared = shared_on(&script, &delivered);
    let outside = InboundReply {
        keyexpr_literal: "other/data".into(),
        ..reply(0, 10)
    };

    let before = allocations();
    let slot = shared
        .claim()
        .expect("a subscriber with no get has a free slot");
    // SAFETY: the slot was taken just above, in `shared`'s table, and no leg of it is out.
    let fan = unsafe { slot.open(&shared, super::Finish::History) };
    // SAFETY: the token lies in `shared`, which outlives the get; the fan lies in its slot.
    let registered = unsafe { fan.register(TokenRef::placed(&shared.token)) };
    // SAFETY: this test is the issuer and holds the get until its release below.
    let legs = unsafe { [slot.leg(&shared), slot.leg(&shared)] };
    legs[0].call(&outside);
    let active = shared.token.active();
    // SAFETY: the issuer lets go of its hold once, here.
    unsafe { slot.release() };
    drop(legs);
    let during = allocations() - before;

    assert!(registered, "a token not cancelling takes the fan");
    assert_eq!(active, 1, "the fan stands on the token while the get does");
    assert_eq!(during, 0, "asking and ending a get allocates nothing");
    assert_eq!(shared.token.active(), 0, "the get's end dropped its fan");
    assert_eq!(
        Arc::strong_count(&shared),
        1,
        "every leg let go of the subscriber"
    );
    assert!(
        shared
            .gets
            .iter()
            .all(|slot| !slot.taken.load(Ordering::SeqCst)),
        "the slot is free for the next get"
    );
    assert!(
        delivered.lock().unwrap().is_empty(),
        "a reply keyed outside is dropped"
    );
}

/// The subscriber's own subscription callback is made over a count of it and takes no memory;
/// the engine letting the callback go lets the count go.
#[test]
fn the_subscribers_own_callback_takes_no_memory_and_holds_it() {
    let script = Script::new(1);
    let delivered = Arc::new(Mutex::new(Vec::new()));
    let shared = shared_on(&script, &delivered);

    let before = allocations();
    let sink = super::own_sink(&shared, super::on_live::<dyn SessionEngine>);
    let during = allocations() - before;

    assert_eq!(during, 0, "the callback allocates nothing");
    assert_eq!(
        Arc::strong_count(&shared),
        2,
        "the callback holds the subscriber"
    );
    drop(sink);
    assert_eq!(
        Arc::strong_count(&shared),
        1,
        "its drop let the subscriber go"
    );
}

/// With every slot holding a get, a get asked is over before it starts: nothing is asked of the
/// engine and its end runs at once, which hands on what the history held back.
#[test]
fn a_get_past_the_sessions_bound_ends_at_once() {
    let script = Script::new(1);
    let delivered = Arc::new(Mutex::new(Vec::new()));
    let shared = shared_on(&script, &delivered);
    assert!(
        shared.lock().handle_live(&sample(0, 10), 1).is_none(),
        "a live sample during the history asks nothing"
    );
    assert!(
        delivered.lock().unwrap().is_empty(),
        "a live sample is held while the history is in flight"
    );
    while shared.claim().is_some() {}

    super::issue_get(
        &shared,
        "demo/data/@adv/**",
        &QueryOptions::get(),
        super::Finish::History,
    );

    assert_eq!(script.get_count(), 0, "no get is asked of the engine");
    assert_eq!(
        *delivered.lock().unwrap(),
        [10],
        "the history's end handed on what it held"
    );
}

/// The parameters of a history get are written where the caller keeps them and lent to the get's
/// options with the reply-keyexpr-any flag, which the get writes after them: nothing is allocated,
/// and the get sends the selector the owned spelling builds.
#[test]
fn a_history_gets_parameters_are_lent_and_take_no_memory() {
    let script = Script::new(1);
    let delivered = Arc::new(Mutex::new(Vec::new()));
    let shared = shared_on(&script, &delivered);

    let before = allocations();
    let parameters = super::GetParameters::history(Some(4), Some(1.5));
    let opts = super::get_options(&shared, &parameters);
    let parts = opts.query_parts();
    let lent = (
        parts.parameters.as_ptr(),
        parts.parameters.len(),
        parts.anyke,
    );
    let during = allocations() - before;

    assert_eq!(during, 0, "the parameters and the options allocate nothing");
    assert_eq!(
        lent,
        (
            parameters.as_bytes().as_ptr(),
            parameters.as_bytes().len(),
            true
        ),
        "the get reads the caller's bytes and writes the flag after them"
    );
    assert_eq!(
        opts.sent_parameters().as_deref(),
        Some(crate::advanced_subscriber::plans::history_selector(Some(4), Some(1.5)).as_bytes()),
    );
}

/// The keys of a history get and of a source's get are written where the issuer keeps them: no
/// memory is taken, and each is the text the owned spelling builds.
#[test]
fn a_gets_key_is_written_in_place_and_takes_no_memory() {
    let before = allocations();
    let history = super::history_key("demo/data");
    let recovery = super::recovery_key("demo/data", &[0x02], 7);
    let during = allocations() - before;

    assert_eq!(during, 0, "writing a get's key allocates nothing");
    assert_eq!(
        history.finish().ok(),
        Some(crate::advanced_ke::history_get_ke("demo/data").as_str())
    );
    assert_eq!(
        recovery.finish().ok(),
        Some(crate::advanced_ke::recovery_get_ke("demo/data", &publisher_hex(), 7).as_str())
    );
}

/// A subscription whose history key is longer than any key a session stores asks no get: the
/// get is over before it starts, which hands on what the history held back.
#[test]
fn a_history_get_whose_key_does_not_fit_ends_at_once() {
    let script = Script::new(1);
    let delivered = Arc::new(Mutex::new(Vec::new()));
    let base = "k".repeat(wz_session_core::caps::MAX_KEYEXPR_BYTES);
    let shared = shared_on_key(&script, &delivered, &base);
    let mut live = sample(0, 10);
    live.keyexpr = base.clone();
    assert!(
        shared.lock().handle_live(&live, 1).is_none(),
        "a live sample during the history asks nothing"
    );
    assert!(
        delivered.lock().unwrap().is_empty(),
        "a live sample is held while the history is in flight"
    );

    super::issue_history_query(&shared, None, None);

    assert_eq!(script.get_count(), 0, "no get is asked of the engine");
    assert_eq!(
        *delivered.lock().unwrap(),
        [10],
        "the history's end handed on what it held"
    );
}
