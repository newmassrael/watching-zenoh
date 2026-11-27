// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The host against a scripted engine: an engine that records what is declared of it, hands the
//! test the callbacks it was given and lets the test say when a get's legs end. What the machine
//! decides is tested without an engine ([`super::super::state`]); what is tested here is what the
//! host does with it: the entities and the order they are declared and retracted in, the get each
//! trigger issues, what ends a get, and what a teardown stops.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use wz_capi_port::cancellation::{CancellableFan, Canceller, FanCanceller, FanKey, TokenRef};
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
    AdvancedSubscriberOptions, DeclarationForms, EntityForm, FormsHandle, HistoryConfig, Kept,
    RecoveryConfig, SubscriberDetection,
};
use super::super::state::{Delivery, Miss, MissHandlers, OnSample, State};
use super::{EngineSubscriber, HostError, LentCore, SubscriberCore};
use crate::test_alloc::allocations;
use wz_capi_port::lodge::{Lodging, Strong};

/// The zid the scripted session has, as the port hands it: padded to 16 bytes.
const ZID: [u8; 4] = [0xAB, 0xCD, 0xEF, 0x01];

/// What a subscription's sink mints.
type SampleFn = Box<dyn FnMut(&dyn wz_session_core::sink::SampleView) + Send>;

/// A subscriber with what its callbacks collected: the payloads delivered and the sizes of the
/// holes reported.
type Recorded = (EngineSubscriber, Arc<Mutex<Vec<u8>>>, Arc<Mutex<Vec<u32>>>);

/// One subscription the engine declared: its id, its keyexpr, its key on the wire and its sink.
type SubscriptionRecord = (SubId, String, WireKey, Arc<SubscriberSink>);

/// One liveliness subscription the engine declared: its id, its keyexpr, whether it asked for the
/// tokens already alive, and its sink.
type LivelinessRecord = (SubId, String, bool, Arc<LivelinessSink>);

/// One get the engine was asked: where, with what parameters, and the legs it minted.
struct GetRecord {
    keyexpr: String,
    /// The parameters as the get sends them, the reply-keyexpr-any flag included.
    parameters: String,
    /// The parameters the host stated, which the flag rides beside rather than in.
    stated: String,
    destination: Locality,
    legs: Vec<Arc<Mutex<Option<ReplyCallback>>>>,
    /// The key of the fan that cancels the get, when a token can.
    fan: Option<FanKey>,
}

/// An engine that records and hands over.
#[derive(Default)]
struct Script {
    /// What the fans it is attached to reach the script by.
    canceller: Option<&'static ScriptCanceller>,
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
    subscriptions: Mutex<Vec<SubscriptionRecord>>,
    liveliness: Mutex<Vec<LivelinessRecord>>,
    gets: Mutex<Vec<GetRecord>>,
    tickers: Mutex<Vec<(TickerId, u64, Tick)>>,
}

impl Script {
    fn new(legs: usize) -> Arc<Self> {
        Arc::new_cyclic(|this| {
            let script = Self {
                // One for the script's life, left to the process: a fan's canceller stands for
                // the whole process, and this one reaches nothing once the script is gone.
                canceller: Some(Box::leak(Box::new(ScriptCanceller(Weak::clone(this))))),
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
    fn release_keyexpr(&self, _row: wz_session_core::session_tables::KeyexprHandle) {}

    // The script declares no key (`acquire_keyexpr` above), so no hold reaches here.
    fn retain_keyexpr(
        &self,
        _row: wz_session_core::session_tables::KeyexprHandle,
    ) -> Result<(), wz_capi_port::HoldRefused> {
        Err(wz_capi_port::HoldRefused::Gone)
    }

    // The script declares no key, so no row is its.
    fn declared_prefix(
        &self,
        _row: wz_session_core::session_tables::KeyexprHandle,
        _key: &str,
    ) -> Option<(wz_session_core::wire_id::ExprId, usize)> {
        None
    }
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

/// The script as a fan's canceller reaches it: while it stands.
struct ScriptCanceller(Weak<Script>);

impl FanCanceller for ScriptCanceller {
    fn cancel_fan(&self, key: FanKey) {
        if let Some(script) = self.0.upgrade() {
            script.cancel_fan(key);
        }
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
    ) -> Result<wz_capi_port::Declared<SubId>, Refusal> {
        if self.ids_spent.load(Ordering::SeqCst) {
            return Err(Refusal::NoEntityId);
        }
        let id = self.next_entity_id().ok_or(Refusal::NoEntityId)?;
        self.event(format!("declare subscriber {keyexpr}"));
        // The script's record keeps the text in a buffer of its own, which stays where it is when
        // the records move.
        let key = keyexpr.to_owned();
        let lent = wz_capi_port::KeyView::literal(&key);
        self.subscriptions
            .lock()
            .unwrap()
            .push((id, key, wire, Arc::new(sink)));
        Ok(wz_capi_port::Declared { id, key: lent })
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
    fn acquire_keyexpr(&self, _keyexpr: &str) -> Result<wz_capi_port::KeyHold, Refusal> {
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
    fn declare_filter_matching_listener(
        &self,
        _filter: FilterId,
        _sink: MatchingSink,
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
    ) -> Result<wz_capi_port::Declared<FilterId>, Refusal> {
        // The script keeps no write filter's key.
        Ok(wz_capi_port::Declared {
            id: 0,
            key: wz_capi_port::KeyView::ABSENT,
        })
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
        _declared: wz_session_core::session_tables::KeyexprRef,
        _payload: &[u8],
        _params: &PlainPutParams,
    ) -> FilteredPut {
        FilteredPut::NotPlain
    }
    fn keep_write_filter_plain(
        &self,
        _filter: FilterId,
        _plain: Option<(PlainPutParams, wz_session_core::session_tables::KeyexprRef)>,
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
    ) -> Result<wz_capi_port::Declared<SubId>, Refusal> {
        let id = self.next_entity_id().ok_or(Refusal::NoEntityId)?;
        self.event(format!("declare liveliness {keyexpr}"));
        let key = keyexpr.to_owned();
        let lent = wz_capi_port::KeyView::literal(&key);
        self.liveliness
            .lock()
            .unwrap()
            .push((id, key, history, Arc::new(sink)));
        Ok(wz_capi_port::Declared { id, key: lent })
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
                let canceller = self.canceller.expect("made by `Script::new`");
                if !fan.attach(Canceller::Static(canceller)) {
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
            parameters: String::from_utf8(opts.sent_parameters().unwrap_or_default().into_owned())
                .expect("parameters are text"),
            stated: String::from_utf8(opts.parameters.as_deref().unwrap_or_default().to_vec())
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
    ) -> Result<wz_capi_port::Declared<QblId>, Refusal> {
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

/// Whether this build sweeps the sources that went away (`advanced-retention`), and so starts the
/// retention job beside what a test asks for.
fn sweeps() -> bool {
    cfg!(feature = "advanced-retention")
}

/// The events of `events` this build records: each one marked as the retention job's (`true`) is
/// left out of a build that starts no such job.
fn events_of(events: &[(bool, &str)]) -> Vec<String> {
    events
        .iter()
        .filter(|(retention, _)| !retention || sweeps())
        .map(|(_, event)| (*event).to_owned())
        .collect()
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
        assert_eq!(
            gets[0].parameters, "_sn=1..;_anyke",
            "the get sends the range and the reply-keyexpr-any flag after it"
        );
        assert_eq!(
            gets[0].stated, "_sn=1..",
            "the flag is not copied into the stated bytes"
        );
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
    let get = format!(
        "get {}",
        crate::advanced_ke::recovery_get_ke("demo/data", &publisher_hex(), 7)
    );
    assert_eq!(
        script.events(),
        events_of(&[
            (false, "declare subscriber demo/data"),
            (true, "start ticker 3600000"),
            (false, get.as_str()),
            (false, "retract demo/data"),
            (true, "stop ticker"),
        ])
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
        events_of(&[
            (false, "declare subscriber demo/data"),
            (true, "start ticker 3600000"),
            (false, "declare subscriber demo/data/@adv/pub/**"),
        ])
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
/// the machine's: the re-ask for each quiet source, the sweep of the ones nobody heard from. A
/// build without the sweep (`advanced-retention`) starts the re-ask alone and keeps the quiet
/// source, so its next sample past a gap asks for what it missed. Turned red, in the build without
/// the sweep, by a retention job started there.
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
        events_of(&[
            (false, "declare subscriber demo/data"),
            (true, "start ticker 60000"),
            (false, "start ticker 500"),
        ])
    );

    let mut live = script.callback(0);
    live(&sample(0, 10));
    let (_, period, periodic) = script
        .tickers
        .lock()
        .unwrap()
        .last()
        .expect("the re-ask is started")
        .clone();
    assert_eq!(period, 500);
    assert!(periodic(), "the job goes on");
    assert_eq!(script.get_count(), 1);
    assert_eq!(script.gets.lock().unwrap()[0].parameters, "_sn=1..;_anyke");
    script.reply(0, 0, &reply(1, 11));
    script.end_leg(0, 0);
    assert_eq!(*delivered.lock().unwrap(), [10, 11]);

    // The sweep reads the engine's clock: far enough on, the quiet source is dropped, and the
    // next sample from it is a first one again. Without the sweep the source is kept, and the
    // sample past its gap is held while its cache is asked.
    let retention = sweeps().then(|| script.tickers.lock().unwrap()[0].2.clone());
    script.now.store(10 * 60 * 1000, Ordering::SeqCst);
    if let Some(retention) = &retention {
        assert!(retention());
    }
    live(&sample(7, 17));
    if sweeps() {
        assert_eq!(*delivered.lock().unwrap(), [10, 11, 17]);
    } else {
        assert_eq!(*delivered.lock().unwrap(), [10, 11]);
        assert_eq!(script.get_count(), 2, "the kept source asks for its gap");
    }

    drop(subscriber);
    let events = script.events();
    assert_eq!(
        events.iter().filter(|e| *e == "stop ticker").count(),
        if sweeps() { 2 } else { 1 }
    );
    // The jobs end by themselves once what they work on is gone.
    assert!(!periodic());
    if let Some(retention) = &retention {
        assert!(!retention());
    }
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
    let subscriber: EngineSubscriber<Arc<Script>> =
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
        if sweeps() { 2 } else { 1 }
    );
}

/// A subscriber that wants a periodic job on an engine that runs none is refused, not left
/// without the job.
#[test]
fn an_engine_without_periodic_jobs_refuses_a_periodic_subscriber() {
    let script = Script::new(1);
    script.no_tickers.store(true, Ordering::SeqCst);
    let options = AdvancedSubscriberOptions::new()
        .with_recovery(RecoveryConfig::new().with_periodic_queries(Duration::from_millis(500)));
    let refused = EngineSubscriber::declare(&engine(&script), "demo/data", options, |_| {});
    assert!(matches!(refused, Err(HostError::Refused(_))));
    // What was declared before the refusal is retracted.
    assert_eq!(
        script.events(),
        ["declare subscriber demo/data", "retract demo/data"]
    );
}

/// A build without the sweep of the sources that went away (`advanced-retention`, off in the
/// zenoh-pico preset) starts no retention job: a recovering subscriber that asks for no periodic
/// re-ask is declared on an engine that runs no periodic jobs. Turned red by the retention job's
/// start compiled into that build (`EngineSubscriber::declare_over`).
#[cfg(not(feature = "advanced-retention"))]
#[test]
fn a_build_without_the_sweep_starts_no_retention_job() {
    let script = Script::new(1);
    script.no_tickers.store(true, Ordering::SeqCst);
    let options = AdvancedSubscriberOptions::new()
        .with_recovery(RecoveryConfig::new().with_retention_period(Duration::from_secs(60)));
    let (subscriber, _delivered, _misses) = recording(&script, options);
    assert_eq!(script.events(), ["declare subscriber demo/data"]);
    drop(subscriber);
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
    let declared = events_of(&[
        (false, "declare subscriber demo/data"),
        (true, "start ticker 3600000"),
        (false, "get demo/data/@adv/**"),
    ]);
    assert_eq!(script.events()[..declared.len()], declared[..]);
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
        events_of(&[
            (false, "retract demo/data"),
            (true, "stop ticker"),
            (false, "retract demo/data/@adv/pub/**"),
            (false, "retract demo/data/@adv/pub/**"),
            (false, "retract token"),
        ]),
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
            EntityForm::aliased(5, Some("/data".into())).keeping(Kept::shared(Arc::new(())))
        }
        fn retain(&self, _anchor: Kept) {
            *self.retained.lock().unwrap() += 1;
        }
    }
    let forms = Arc::new(Forms::default());
    let script = Script::new(1);
    let options = AdvancedSubscriberOptions::new()
        .with_recovery(RecoveryConfig::new())
        .with_declaration_forms(FormsHandle::new(forms.clone()));
    let (subscriber, _delivered, _misses) = recording(&script, options);
    assert_eq!(
        subscriber.id().eid(),
        77,
        "the host's identity is the subscriber's"
    );
    {
        let subscriptions = script.subscriptions.lock().unwrap();
        let (_, keyexpr, wire, _) = &subscriptions[0];
        assert_eq!(
            wire.names_in(keyexpr),
            (5, Some("/data")),
            "named as the host said"
        );
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

/// A subscriber whose shared part the heap has no room for is refused as that, and the callback it
/// was handed is let go of with the refusal. Turned red by a declaration that answers the heap's
/// refusal by ending the program, or that keeps the callback past it.
#[test]
fn a_subscriber_the_heap_has_no_room_for_is_refused() {
    let script = Script::new(1);
    let engine = engine(&script);
    let held = Arc::new(());
    let in_callback = Arc::clone(&held);
    let shared = core::alloc::Layout::new::<
        core::mem::MaybeUninit<Lodging<super::Shared<Arc<dyn SessionEngine>>>>,
    >();
    let refused = crate::test_alloc::refusing(shared, || {
        EngineSubscriber::declare(
            &engine,
            "demo/data",
            AdvancedSubscriberOptions::new(),
            move |_| assert!(Arc::strong_count(&in_callback) > 0),
        )
    });
    assert_eq!(refused.err(), Some(HostError::NoRoom));
    assert_eq!(Arc::strong_count(&held), 1, "the callback was let go of");
    let declared = EngineSubscriber::declare(
        &engine,
        "demo/data",
        AdvancedSubscriberOptions::new(),
        |_| {},
    );
    assert!(declared.is_ok(), "CONTROL: a heap with room declares it");
}

// ---------------------------------------------------------------------------------------------
// What asking a get and subscribing take of the heap. The crate's other lib tests run beside these
// on libtest's other threads and allocate as they please; the count is of the thread a test runs
// on (a thread-local cell the allocator bumps), and a window opens and closes on that thread with
// nothing handed to another in between, so what the others allocate never reaches it
// (`crate::test_alloc`).
/// A subscriber's shared part on the scripted engine with its startup get counted in flight,
/// recording what it delivers into `delivered`.
fn shared_on(
    script: &Arc<Script>,
    delivered: &Arc<Mutex<Vec<u8>>>,
) -> Strong<super::Shared<Arc<dyn SessionEngine>>> {
    shared_on_key(script, delivered, "demo/data")
}

/// [`shared_on`] subscribing to `base`.
fn shared_on_key(
    script: &Arc<Script>,
    delivered: &Arc<Mutex<Vec<u8>>>,
    base: &str,
) -> Strong<super::Shared<Arc<dyn SessionEngine>>> {
    let d = Arc::clone(delivered);
    let on_sample = OnSample::boxed(Box::new(move |s: Delivery<'_>| {
        d.lock().unwrap().push(s.view().payload()[0])
    }));
    let handle = Arc::downgrade(&engine(script));
    let base_keyexpr = super::fixed_key(base).expect("a key a session stores");
    let make = |place: core::ptr::NonNull<super::Shared<Arc<dyn SessionEngine>>>| {
        // SAFETY: the place is the box's, valid for one `Shared`, holding none, never moved.
        unsafe {
            super::Shared::write_in(
                place,
                handle,
                // Written in its lock as the host writes it: retransmitting, the startup get in
                // flight, no bound on the samples held back for it.
                |cell| {
                    State::write_in(
                        cell,
                        on_sample,
                        MissHandlers::default(),
                        true,
                        1,
                        usize::MAX,
                    )
                },
                base_keyexpr,
                Locality::SessionLocal,
                1_000,
            );
        }
    };
    // SAFETY: `make` makes the whole shared part in the place it is handed.
    unsafe { Strong::try_boxed_in(make) }.expect("the test's heap")
}

/// Every row of a subscriber's table of gets is written free and empty, and each is claimed
/// once: a claim past the table's last row is refused.
#[test]
fn every_row_of_the_table_of_gets_is_written_free() {
    let script = Script::new(1);
    let delivered = Arc::new(Mutex::new(Vec::new()));
    let shared = shared_on(&script, &delivered);

    for slot in shared.gets.iter() {
        assert!(!slot.taken.load(Ordering::SeqCst), "a row is free");
        assert_eq!(
            slot.holders.load(Ordering::SeqCst),
            0,
            "a row has no holder"
        );
        // SAFETY: no row is taken, so nothing writes a row while it is read.
        let empty = unsafe {
            (*slot.owner.get()).is_null()
                && (*slot.finish.get()).is_none()
                && (*slot.fan.get()).is_none()
        };
        assert!(empty, "a row names no subscriber, no end and no fan");
    }
    let mut claimed = 0usize;
    while shared.claim().is_some() {
        claimed += 1;
    }
    assert_eq!(
        claimed,
        wz_session_core::caps::MAX_PENDING_QUERIES,
        "each row is claimed once"
    );
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
        Strong::strong_count(&shared),
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
    let sink = super::own_sink(&shared, super::on_live::<Arc<dyn SessionEngine>>);
    let during = allocations() - before;

    assert_eq!(during, 0, "the callback allocates nothing");
    assert_eq!(
        Strong::strong_count(&shared),
        2,
        "the callback holds the subscriber"
    );
    drop(sink);
    assert_eq!(
        Strong::strong_count(&shared),
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
    let parameters = super::GetParameters::history(Some(4), Some(Duration::from_millis(1_500)));
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
        Some(
            crate::advanced_subscriber::plans::history_selector(
                Some(4),
                Some(Duration::from_millis(1_500))
            )
            .as_bytes()
        ),
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

/// What the lent callbacks of a machine saw.
#[derive(Default)]
struct Seen {
    samples: AtomicU64,
    last: AtomicU64,
    missed: AtomicU64,
    dropped: AtomicU64,
}

/// # Safety
/// `context` is a live `Seen`.
unsafe fn seen_sample(context: *mut core::ffi::c_void, sample: Delivery<'_>) {
    // SAFETY: the caller's.
    let seen = unsafe { &*context.cast_const().cast::<Seen>() };
    seen.samples.fetch_add(1, Ordering::SeqCst);
    seen.last
        .store(u64::from(sample.view().payload()[0]), Ordering::SeqCst);
}

/// # Safety
/// As [`seen_sample`]'s.
unsafe fn seen_miss(context: *mut core::ffi::c_void, miss: Miss) {
    // SAFETY: the caller's.
    let seen = unsafe { &*context.cast_const().cast::<Seen>() };
    seen.missed
        .fetch_add(u64::from(miss.nb()), Ordering::SeqCst);
}

/// # Safety
/// As [`seen_sample`]'s.
unsafe fn seen_drop(context: *mut core::ffi::c_void) {
    // SAFETY: the caller's.
    let seen = unsafe { &*context.cast_const().cast::<Seen>() };
    seen.dropped.fetch_add(1, Ordering::SeqCst);
}

/// A machine whose sample callback and first miss listener are lent takes no memory for them: it
/// calls each through its context, the lent listener hears a miss before one registered after it,
/// retracting the lent listener lets its context go, and dropping the machine lets the sample
/// callback's go, each once.
#[test]
fn lent_callbacks_take_no_memory_and_are_let_go_once() {
    let seen = Seen::default();
    let context = core::ptr::from_ref(&seen)
        .cast_mut()
        .cast::<core::ffi::c_void>();
    let registered = Arc::new(Mutex::new(Vec::new()));

    let before = allocations();
    // SAFETY: `seen` outlives the machine, and every call is made on this thread.
    let mut state = unsafe {
        State::delivering_to(
            OnSample::lent(seen_sample, context, Some(seen_drop)),
            MissHandlers::lent(seen_miss, context, Some(seen_drop)),
        )
    };
    let during = allocations() - before;
    assert_eq!(during, 0, "lent callbacks allocate nothing");

    let r = Arc::clone(&registered);
    let second = state.miss_handlers().register(Box::new(move |miss: Miss| {
        r.lock().unwrap().push(miss.nb());
    }));
    assert_ne!(second, 0, "the lent listener keeps its own id");
    assert!(state.handle_live(&sample(0, 10), 1).is_none());
    assert!(state.handle_live(&sample(2, 12), 2).is_none());
    assert_eq!(
        seen.samples.load(Ordering::SeqCst),
        2,
        "both samples delivered"
    );
    assert_eq!(seen.last.load(Ordering::SeqCst), 12);
    assert_eq!(
        seen.missed.load(Ordering::SeqCst),
        1,
        "the lent listener heard the hole"
    );
    assert_eq!(
        *registered.lock().unwrap(),
        [1],
        "and so did the registered one"
    );

    state.miss_handlers().unregister(0);
    assert_eq!(
        seen.dropped.load(Ordering::SeqCst),
        1,
        "retracting it let it go"
    );
    assert!(state.handle_live(&sample(4, 14), 3).is_none());
    assert_eq!(
        seen.missed.load(Ordering::SeqCst),
        1,
        "a retracted listener hears nothing"
    );
    assert_eq!(*registered.lock().unwrap(), [1, 1]);

    drop(state);
    assert_eq!(
        seen.dropped.load(Ordering::SeqCst),
        2,
        "the machine's drop let the sink go"
    );
}

/// A subscriber's key is kept inline in its shared part, so making the part takes no memory for
/// it; a key longer than a session stores is refused before anything is declared.
#[test]
fn a_subscribers_key_is_kept_inline_and_one_too_long_is_refused() {
    let before = allocations();
    let key = super::fixed_key("demo/data");
    let during = allocations() - before;
    assert_eq!(during, 0, "keeping the key allocates nothing");
    assert_eq!(key.map(|key| key.prefix() == "demo/data"), Some(true));

    let script = Script::new(1);
    let long = "k".repeat(wz_session_core::caps::MAX_KEYEXPR_BYTES + 1);
    let refused = EngineSubscriber::declare(
        &engine(&script),
        long.as_str(),
        AdvancedSubscriberOptions::new(),
        |_| {},
    );
    assert!(matches!(refused, Err(HostError::Refused(_))));
    assert!(script.events().is_empty(), "nothing was declared");
}

/// Counts each call of a place's give-back in the `AtomicU64` the context names.
///
/// # Safety
/// `context` is a live `AtomicU64`.
unsafe fn count_given_back(context: *mut core::ffi::c_void) {
    // SAFETY: the caller's.
    unsafe { &*context.cast_const().cast::<AtomicU64>() }.fetch_add(1, Ordering::SeqCst);
}

/// The context [`count_given_back`] counts into.
fn given_back_into(given: &AtomicU64) -> *mut core::ffi::c_void {
    core::ptr::from_ref(given)
        .cast_mut()
        .cast::<core::ffi::c_void>()
}

/// Forms lodged where their host put them, and the names an entity's form keeps through a lodged
/// count, are handed around, read and let go of with no memory taken, and the forms' place goes
/// back once, after the last copy of the handle and the last name.
///
/// # Control
///
/// A handle that boxes the forms (`FormsHandle::new(Arc::new(..))`) counts an allocation; a name
/// whose copy takes no count gives the place back early, which reds the second assertion.
#[test]
fn lodged_forms_and_kept_names_take_no_memory() {
    struct Lodged;
    impl DeclarationForms for Lodged {}
    let given = AtomicU64::new(0);
    let mut place = Lodging::<Lodged>::vacant();

    let before = allocations();
    // SAFETY: `place` is free and outlives every count; `given` outlives the give-back.
    let forms = unsafe {
        Strong::lodge(
            core::ptr::NonNull::from(&mut place),
            Lodged,
            count_given_back,
            given_back_into(&given),
        )
    };
    let name = Kept::lodged(forms.clone());
    let handle = FormsHandle::lodged(forms);
    let copy = handle.clone();
    let form = copy.forms().subscriber("demo/data").keeping(name.clone());
    let wire = super::wire_of(&form);
    drop((handle, copy, name, form));
    let during = allocations() - before;
    let given_while_named = given.load(Ordering::SeqCst);
    drop(wire);

    assert_eq!(
        during, 0,
        "the handle, its copies and the kept names allocate nothing"
    );
    assert_eq!(
        given_while_named, 0,
        "the key's kept name still holds the forms"
    );
    assert_eq!(
        given.load(Ordering::SeqCst),
        1,
        "the last name gave the place back, once"
    );
}

/// A form whose suffix lies in what it keeps hands each key made from it that suffix lent, not
/// copied: making one key and another of the same form, as each declaration on the form does, takes
/// no memory.
///
/// # Control
///
/// A key made with the suffix copied (`WireKey::aliased` over `to_owned`) counts an allocation
/// and points elsewhere, which reds both assertions.
#[test]
fn a_kept_suffix_is_lent_to_the_key_and_takes_no_memory() {
    let text: Arc<String> = Arc::new(String::from("demo/data/rest"));
    let rest = text.get("demo/data".len()..).expect("the rest of the key");
    let kept = Kept::shared(text.clone());
    let before = allocations();
    // SAFETY: `rest` lies in the string `kept` counts, which nothing changes.
    let form = unsafe { EntityForm::aliased_in(9, rest, kept) };
    let wire = super::wire_of(&form);
    let copy = super::wire_of(&form);
    let during = allocations() - before;

    assert_eq!(during, 0, "two keys of one form allocate nothing");
    assert_eq!(
        wire.names_in("demo/data/rest").1.map(str::as_ptr),
        Some(rest.as_ptr()),
        "lent, not copied"
    );
    assert_eq!(copy.names_in("demo/data/rest"), (9, Some("/rest")));
}

/// A value lodged in a place its maker lends takes no memory, nor do its counts: the last count
/// of the value drops it once, a weak count keeps the place and upgrades no more once the value is
/// gone, and the place is given back once, with the last count of either kind.
#[test]
fn a_value_lodged_in_a_lent_place_takes_no_memory_and_goes_back_once() {
    struct Dropped<'a>(&'a AtomicU64);
    impl Drop for Dropped<'_> {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let drops = AtomicU64::new(0);
    let given = AtomicU64::new(0);
    let mut place = Lodging::<Dropped<'_>>::vacant();

    let before = allocations();
    // SAFETY: `place` is free and outlives every count; `given` outlives the give-back.
    let strong = unsafe {
        Strong::lodge(
            core::ptr::NonNull::from(&mut place),
            Dropped(&drops),
            count_given_back,
            given_back_into(&given),
        )
    };
    let raw = Strong::into_raw(strong.clone());
    let weak = Strong::downgrade(&strong);
    let upgraded = weak.upgrade();
    let during = allocations() - before;

    assert_eq!(during, 0, "lodging and counting allocate nothing");
    assert_eq!(Strong::strong_count(&strong), 3);
    drop(upgraded);
    // SAFETY: `raw` is the count `into_raw` gave up above, taken back once.
    drop(unsafe { Strong::<Dropped<'_>>::from_raw(raw) });
    assert_eq!(
        drops.load(Ordering::SeqCst),
        0,
        "a count still holds the value"
    );
    drop(strong);
    assert_eq!(
        drops.load(Ordering::SeqCst),
        1,
        "the last count drops it once"
    );
    assert_eq!(
        given.load(Ordering::SeqCst),
        0,
        "the weak count keeps the place"
    );
    assert!(
        weak.upgrade().is_none(),
        "a value gone is not counted again"
    );
    drop(weak);
    assert_eq!(given.load(Ordering::SeqCst), 1, "the place goes back once");
}

/// A subscriber whose shared part is lodged in a place its host lends gives the place back once,
/// after the last of its handle, the engine's callbacks and jobs, and a miss listener's weak count
/// let go of it; one refused before the part is made gives it back at once, with nothing declared.
#[test]
fn a_subscriber_lodged_in_a_lent_core_gives_it_back_once_after_its_last_holder() {
    let options = || {
        AdvancedSubscriberOptions::new()
            .with_history(HistoryConfig::new().detect_late_publishers())
            .with_recovery(
                RecoveryConfig::new()
                    .with_periodic_queries(Duration::from_millis(500))
                    .with_retention_period(Duration::from_secs(60)),
            )
    };
    let given = AtomicU64::new(0);
    let mut core = SubscriberCore::<Arc<dyn SessionEngine>>::vacant();
    let script = Script::new(1);
    // SAFETY: `core` is free and outlives the subscriber and every holder of its part; `given`
    // outlives the give-back.
    let lent = unsafe {
        LentCore::new(
            core::ptr::NonNull::from(&mut core),
            count_given_back,
            given_back_into(&given),
        )
    };
    let subscriber = EngineSubscriber::declare_in(
        &engine(&script),
        "demo/data",
        options(),
        OnSample::boxed(Box::new(|_: Delivery<'_>| {})),
        MissHandlers::default(),
        lent,
    )
    .expect("the subscriber declares in the lent place");
    let listener = subscriber.sample_miss_listener(|_| {});
    drop(subscriber);
    assert_eq!(
        given.load(Ordering::SeqCst),
        0,
        "the engine's callbacks and jobs still hold the part"
    );
    drop(script);
    assert_eq!(
        given.load(Ordering::SeqCst),
        0,
        "the listener's weak count keeps the place"
    );
    drop(listener);
    assert_eq!(given.load(Ordering::SeqCst), 1, "the place goes back once");

    let refused_back = AtomicU64::new(0);
    let mut refused_core = SubscriberCore::<Arc<dyn SessionEngine>>::vacant();
    let script = Script::new(1);
    // SAFETY: as above.
    let lent = unsafe {
        LentCore::new(
            core::ptr::NonNull::from(&mut refused_core),
            count_given_back,
            given_back_into(&refused_back),
        )
    };
    let refused = EngineSubscriber::declare_in(
        &engine(&script),
        "demo/data",
        AdvancedSubscriberOptions::new().with_history(HistoryConfig::new().max_samples(0)),
        OnSample::boxed(Box::new(|_: Delivery<'_>| {})),
        MissHandlers::default(),
        lent,
    );
    assert!(matches!(refused, Err(HostError::HistoryBoundZero { .. })));
    assert_eq!(refused_back.load(Ordering::SeqCst), 1, "given back at once");
    assert!(script.events().is_empty(), "nothing was declared");
}

/// The late-publisher subscription's callback is the engine's plain form over a count of the
/// subscriber, so declaring it takes no closure of its own, and the engine letting it go lets go
/// of the count.
#[test]
fn the_late_publisher_callback_is_a_count_of_the_subscriber() {
    let script = Script::new(1);
    let options = AdvancedSubscriberOptions::new()
        .with_history(HistoryConfig::new().detect_late_publishers());
    let subscriber = EngineSubscriber::declare(&engine(&script), "demo/data", options, |_| {})
        .expect("a late-publisher subscriber declares");
    let held = Strong::strong_count(&subscriber.shared);
    let sink = script.liveliness.lock().unwrap().remove(0).3;
    assert!(
        matches!(*sink, LivelinessSink::Plain(_)),
        "the callback is the plain form, which allocates no closure"
    );
    drop(sink);
    assert_eq!(
        Strong::strong_count(&subscriber.shared),
        held - 1,
        "letting the callback go let go of its count"
    );
}
