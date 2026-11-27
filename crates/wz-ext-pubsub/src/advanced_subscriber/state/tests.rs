// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The machine against no session: each test drives [`State`] directly and reads what it
//! delivered, what it reported and what it asked for. The clock is an argument, so a test
//! chooses the instant.

use super::*;

#[cfg(feature = "advanced-recovery")]
use std::sync::Arc;
#[cfg(feature = "advanced-recovery")]
use std::sync::Mutex;
#[cfg(feature = "advanced-retention")]
use std::time::Duration;
#[cfg(feature = "advanced-recovery")]
use wz_session_core::sample::SourceInfo;

/// The host's reading of the clock, for a test that does not care when.
#[cfg(feature = "advanced-recovery")]
const NOW: u64 = 1_000;

/// The [`Miss`] a source of `zid`/`eid` reports for `nb` skipped samples.
#[cfg(feature = "advanced-recovery")]
fn miss_of(zid: &[u8], eid: u32, nb: u32) -> Miss {
    Miss {
        source: EntityGlobalId::new(zid, eid).expect("a 1..=16-byte test zid"),
        nb,
    }
}

/// The key of the sequenced source `zid`/`eid`.
#[cfg(feature = "advanced-recovery")]
fn src(zid: &[u8], eid: u32) -> EntityGlobalId {
    EntityGlobalId::new(zid, eid).expect("a 1..=16-byte test zid")
}

/// The key of the timestamped source `zid`.
#[cfg(feature = "advanced-history")]
fn ts_src(zid: &[u8]) -> TimestampZid {
    TimestampZid::new(zid).expect("an at most 16-byte test zid")
}

/// A registry holding ONE listener that records into `sink` — the shape
/// the state-machine tests below drive [`State`] with directly.
#[cfg(feature = "advanced-recovery")]
fn recording_miss_handlers(sink: Arc<Mutex<Vec<Miss>>>) -> MissHandlers {
    let mut handlers = MissHandlers::default();
    handlers.register(Box::new(move |miss| sink.lock().unwrap().push(miss)));
    handlers
}

/// A machine configured the way a host configures one: `retransmission` says whether a forward
/// gap buffers and asks, `global_pending_queries` how many history gets are in flight at the
/// start, `max_history_depth` the ceiling of the pending buffers. The history arguments are
/// ignored by a build without history, which has neither.
#[cfg(feature = "advanced-recovery")]
fn machine(
    on_sample: Box<dyn FnMut(Sample) + Send>,
    miss_handlers: MissHandlers,
    retransmission: bool,
    global_pending_queries: usize,
    max_history_depth: usize,
) -> State {
    let state =
        State::new(owned_samples(on_sample), miss_handlers).with_retransmission(retransmission);
    #[cfg(feature = "advanced-history")]
    let state = state.with_history(global_pending_queries, max_history_depth);
    #[cfg(not(feature = "advanced-history"))]
    let _ = (global_pending_queries, max_history_depth);
    state
}

/// A machine that discards what it delivers.
#[cfg(feature = "advanced-recovery")]
fn silent(retransmission: bool) -> State {
    machine(
        Box::new(|_| {}),
        MissHandlers::default(),
        retransmission,
        0,
        usize::MAX,
    )
}

/// A source state that has delivered up to `last_delivered`.
#[cfg(feature = "advanced-recovery")]
fn source_at(last_delivered: Option<u32>) -> SourceState {
    let mut state = SourceState::new(NOW);
    state.last_delivered = last_delivered;
    state
}

/// A put on `demo/data` carrying `SourceInfo(zid 0x02, eid 7, sn)` and one payload byte.
#[cfg(feature = "advanced-recovery")]
fn sequenced(sn: u32, v: u8) -> Sample {
    let mut s = Sample::new_put("demo/data", vec![v]);
    s.source_info = Some(SourceInfo::new(&[0x02], 7, sn));
    s
}

/// A put on `demo/data` carrying a timestamp (the id `0x02`) and no source info: the
/// timestamped shape.
#[cfg(feature = "advanced-history")]
fn timestamped(time: u64, v: u8) -> Sample {
    let mut s = Sample::new_put("demo/data", vec![v]);
    s.timestamp = Some(wz_session_core::sample::TimestampHint::new(time, &[0x02u8]).unwrap());
    s
}

/// R311y82 state-machine unit test (recovery core, no session): a live
/// forward gap BUFFERS instead of delivering + asks for a recovery GET;
/// when the recovered sample fills the hole, the buffer drains in order
/// with no miss. Drives [`State`] directly so the buffer / drain logic is
/// exercised without the query plane (the host's composed loopback test
/// covers the genuine GET).
#[cfg(feature = "advanced-recovery")]
#[test]
fn recovery_buffers_forward_gap_and_drains_when_filled() {
    let delivered = Arc::new(Mutex::new(Vec::<u8>::new()));
    let misses = Arc::new(Mutex::new(Vec::<Miss>::new()));
    let d = Arc::clone(&delivered);
    let m = Arc::clone(&misses);
    let mut state = machine(
        Box::new(move |s: Sample| d.lock().unwrap().push(s.payload[0])),
        recording_miss_handlers(m),
        true,
        0,
        usize::MAX,
    );
    let key = (vec![0x02u8], 7u32);

    // Live 0,1 in order — no recovery request.
    assert!(state.ingest(sequenced(0, 0xA0), true, NOW).is_none());
    assert!(state.ingest(sequenced(1, 0xA1), true, NOW).is_none());
    // Live gap at 2: sn 3 arrives. retransmission -> buffer + request GET.
    let req = state
        .ingest(sequenced(3, 0xA3), true, NOW)
        .expect("a forward gap with retransmission requests recovery");
    assert_eq!(
        (req.zid.clone(), req.eid),
        key,
        "GET targets the gapped source"
    );
    assert_eq!(req.from_sn, 2, "GET starts at last_delivered+1 = 2");
    assert_eq!(
        *delivered.lock().unwrap(),
        vec![0xA0, 0xA1],
        "sn 3 buffered, not delivered while the hole is open"
    );

    // The recovery GET returns sn 2 — drains 2 then the buffered 3.
    let _ = state.ingest(sequenced(2, 0xA2), false, NOW);
    state.finish_recovery(&key);
    assert_eq!(
        *delivered.lock().unwrap(),
        vec![0xA0, 0xA1, 0xA2, 0xA3],
        "the recovered sn 2 fills the hole; the buffered sn 3 drains in order"
    );
    assert!(
        misses.lock().unwrap().is_empty(),
        "the recovery filled the hole -> no Miss"
    );
}

/// A registry lent one listener at declaration makes no map of listeners: a miss is the one call
/// to the lent listener, and the map is made by the first registration, whose listener hears a
/// miss after the lent one. Turned red by a map made with the registry (`MissHandlers::lent`),
/// which a host whose listeners are its own would then link, or by the lent listener fired after
/// the registered ones.
#[test]
fn a_lent_listener_alone_makes_no_map_and_is_heard_first() {
    type Log = std::sync::Mutex<Vec<(u8, u32)>>;
    unsafe fn heard(context: *mut c_void, miss: Miss) {
        // SAFETY: the context is the test's log, which outlives the registry.
        let log = unsafe { &*context.cast::<Log>() };
        log.lock().unwrap().push((0, miss.nb()));
    }
    let log = std::sync::Arc::new(Log::new(Vec::new()));
    let context = std::sync::Arc::as_ptr(&log).cast_mut().cast::<c_void>();
    // SAFETY: `heard` reads the log, which outlives the registry, from any thread, and nothing is
    // let go of.
    let mut handlers = unsafe { MissHandlers::lent(heard, context, None) };
    assert!(!handlers.holds_a_map());
    let source = EntityGlobalId::new(&[0x02], 7).expect("a one-byte zid");
    handlers.fire(Miss::for_test(source, 2));
    assert_eq!(*log.lock().unwrap(), [(0, 2)]);

    let registered = std::sync::Arc::clone(&log);
    let id = handlers.register(Box::new(move |miss: Miss| {
        registered.lock().unwrap().push((1, miss.nb()));
    }));
    assert!(handlers.holds_a_map());
    handlers.fire(Miss::for_test(source, 3));
    assert_eq!(*log.lock().unwrap(), [(0, 2), (0, 3), (1, 3)]);

    handlers.unregister(id);
    handlers.unregister(0);
    handlers.fire(Miss::for_test(source, 4));
    assert_eq!(
        log.lock().unwrap().len(),
        3,
        "both listeners were retracted"
    );
}

/// A state written in its place is the one the builder makes, whatever the place held before: a
/// live sample is held back while the history get it was told of is out, a forward gap asks for
/// its range, and both go on in order once their gets end. The place is filled with ones first,
/// so a field `State::write_in` left unwritten (the span samples are held back in, above all) is
/// read as it was left. Turned red by a field written at another value than the builder's.
#[cfg(feature = "advanced-history")]
#[test]
fn a_state_written_in_its_place_is_the_one_the_builder_makes() {
    let delivered = Arc::new(Mutex::new(Vec::<u8>::new()));
    let d = Arc::clone(&delivered);
    let mut place = Box::<State>::new_uninit();
    // SAFETY: the place is the box's, valid for writes of a `State`, and holds no state yet.
    unsafe {
        place
            .as_mut_ptr()
            .cast::<u8>()
            .write_bytes(0xFF, core::mem::size_of::<State>());
    }
    let state = State::write_in(
        &mut place,
        OnSample::boxed(owned_samples(Box::new(move |s: Sample| {
            d.lock().unwrap().push(s.payload[0])
        }))),
        MissHandlers::default(),
        true,
        1,
        usize::MAX,
    );
    assert!(state.ingest(sequenced(0, 0xA0), true, NOW).is_none());
    assert!(
        delivered.lock().unwrap().is_empty(),
        "held while the history get is out"
    );
    state.finish_history();
    assert_eq!(*delivered.lock().unwrap(), [0xA0]);
    let request = state
        .ingest(sequenced(2, 0xA2), true, NOW)
        .expect("a forward gap asks for its range");
    assert_eq!(request.from_sn, 1);
    let _ = state.ingest(sequenced(1, 0xA1), false, NOW);
    state.finish_recovery(&(vec![0x02u8], 7u32));
    assert_eq!(*delivered.lock().unwrap(), [0xA0, 0xA1, 0xA2]);
    // SAFETY: the state was written in the place above, and is dropped once, here.
    unsafe { place.assume_init_drop() };
}

/// R311y82 state-machine unit test: a hole the recovery GET does NOT fill
/// surfaces a [`Miss`] at flush, and the buffered sample past it is still
/// delivered (zenoh `flush_sequenced_source` miss arm).
#[cfg(feature = "advanced-recovery")]
#[test]
fn recovery_flush_reports_miss_for_unfilled_hole() {
    let delivered = Arc::new(Mutex::new(Vec::<u8>::new()));
    let misses = Arc::new(Mutex::new(Vec::<Miss>::new()));
    let d = Arc::clone(&delivered);
    let m = Arc::clone(&misses);
    let mut state = machine(
        Box::new(move |s: Sample| d.lock().unwrap().push(s.payload[0])),
        recording_miss_handlers(m),
        true,
        0,
        usize::MAX,
    );
    let key = (vec![0x02u8], 7u32);

    let _ = state.ingest(sequenced(0, 0xB0), true, NOW);
    // Gap at 1: sn 2 buffered, GET requested for _sn=1..
    let req = state
        .ingest(sequenced(2, 0xB2), true, NOW)
        .expect("gap requests recovery");
    assert_eq!(req.from_sn, 1);
    // The GET finalises with NOTHING for sn 1 (the cache never had it).
    state.finish_recovery(&key);
    assert_eq!(
        *delivered.lock().unwrap(),
        vec![0xB0, 0xB2],
        "the unfillable hole is skipped; the buffered sn 2 still delivers"
    );
    assert_eq!(
        misses.lock().unwrap().clone(),
        vec![miss_of(&[0x02], 7, 1)],
        "the unfilled hole surfaces one Miss(nb=1) at flush"
    );
}

/// R311y83 periodic-trigger unit (no session): `periodic_requests` re-asks
/// every retransmission source `_sn=last+1..` once, marking each with a GET
/// in flight so a second tick is a no-op until the GET finalises.
#[cfg(feature = "advanced-recovery")]
#[test]
fn periodic_requests_reask_each_source_once() {
    let mut state = silent(true);
    state.sequenced.insert(src(&[0x01], 1), source_at(Some(4)));
    state.sequenced.insert(src(&[0x02], 2), source_at(Some(0)));

    let mut reqs = state.periodic_requests();
    reqs.sort_by_key(|r| r.eid);
    assert_eq!(reqs.len(), 2);
    assert_eq!(
        (reqs[0].zid.clone(), reqs[0].eid, reqs[0].from_sn),
        (vec![0x01], 1, 5),
        "source A re-asks from last_delivered(4)+1"
    );
    assert_eq!(
        (reqs[1].zid.clone(), reqs[1].eid, reqs[1].from_sn),
        (vec![0x02], 2, 1),
        "source B re-asks from last_delivered(0)+1"
    );
    assert!(
        state.periodic_requests().is_empty(),
        "a GET is now in flight per source -> no re-ask until it finalises"
    );

    // Retransmission OFF -> the periodic trigger is inert.
    let mut plain = silent(false);
    plain.sequenced.insert(src(&[0x01], 1), source_at(Some(0)));
    assert!(
        plain.periodic_requests().is_empty(),
        "no retransmission -> periodic_requests is a no-op"
    );
}

/// A machine asks for its sources in the order it met them: a source takes the first free row of
/// its table, and the re-ask walks the rows in order, so a run is reproducible and needs no
/// entropy.
#[cfg(feature = "advanced-recovery")]
#[test]
fn periodic_requests_come_in_the_order_the_sources_were_met() {
    let mut state = silent(true);
    let met = caps::MAX_ADVANCED_SOURCES.min(32);
    for eid in 0..met {
        let eid = u8::try_from(eid).expect("at most 32 sources");
        let key = src(&[0x01, eid], u32::from(eid));
        state.sequenced.insert(key, source_at(Some(0)));
    }
    let asked: Vec<u32> = state
        .periodic_requests()
        .into_iter()
        .map(|r| r.eid)
        .collect();
    let expected: Vec<u32> = (0..met)
        .map(|eid| u32::try_from(eid).expect("at most 32 sources"))
        .collect();
    assert_eq!(asked, expected, "one re-ask per source, in the order met");
}

/// R311y84 heartbeat-trigger unit (no session): a beacon ahead of
/// `last_delivered` requests a BOUNDED `_sn=last+1..hb` GET once; a beacon
/// at-or-behind `last_delivered`, or one while a GET is in flight, is a
/// no-op; retransmission-off is inert.
#[cfg(feature = "advanced-recovery")]
#[test]
fn handle_heartbeat_requests_bounded_get_when_ahead() {
    let mut state = silent(true);
    let key = (vec![0x09u8], 4u32);
    state
        .sequenced
        .insert(src(&key.0, key.1), source_at(Some(1)));

    // Beacon last sn = 4 > last_delivered 1 -> bounded _sn=2..4.
    let req = state
        .handle_heartbeat(key.0.clone(), key.1, 4, NOW)
        .expect("a beacon ahead of last_delivered requests recovery");
    assert_eq!((req.from_sn, req.to_sn), (2, Some(4)));
    // A GET is now in flight -> a second beacon is a no-op.
    assert!(state
        .handle_heartbeat(key.0.clone(), key.1, 5, NOW)
        .is_none());
    // A caught-up beacon (<= last_delivered) on a fresh source is a no-op.
    state
        .sequenced
        .get_mut(&src(&key.0, key.1))
        .unwrap()
        .1
        .pending_queries = 0;
    assert!(state
        .handle_heartbeat(key.0.clone(), key.1, 1, NOW)
        .is_none());

    let mut plain = silent(false);
    assert!(
        plain.handle_heartbeat(vec![0x01], 1, 9, NOW).is_none(),
        "no retransmission -> heartbeat is inert"
    );
}

/// R2621 — the retention sweep reclaims a quiet source, SPARES a live one,
/// and leaves a recently-heard one alone.
///
/// wz reclaimed neither source map: they grew one entry per distinct source
/// ever seen, for the life of the subscriber, where upstream bounds them by
/// a retention period (`zenoh-ext/src/advanced_subscriber.rs`
/// @ `async fn gc_task(statesref: Weak<Mutex<State>>, retention_period: Duration) {`).
///
/// THE MIDDLE ARM IS WHY THE FLAG COULD NOT SHIP SEPARATELY: a sweep without
/// `alive` reclaims a publisher that is still there, destroying its
/// `last_delivered`, and the next sample from it reads as a gap. The third
/// arm is the anti-vacuity control — without it "reclaims a quiet source" is
/// equally consistent with a sweep that empties the map unconditionally.
#[cfg(feature = "advanced-retention")]
#[test]
fn the_retention_sweep_reclaims_only_quiet_sources_that_no_token_calls_live() {
    let mut state = silent(true);

    let retention = Duration::from_secs(60);
    let now: u64 = 1_000_000;
    let long_ago = now - 600_000;
    let quiet = src(&[0xAA], 1);
    let live = src(&[0xBB], 1);
    let recent = src(&[0xCC], 1);

    state.sequenced.insert(quiet, SourceState::new(now));
    state.sequenced.get_mut(&quiet).unwrap().1.retention = Retention {
        latest_access_ms: long_ago,
        alive: false,
    };
    state.sequenced.insert(live, SourceState::new(now));
    state.sequenced.get_mut(&live).unwrap().1.retention = Retention {
        latest_access_ms: long_ago,
        alive: true,
    };
    // Recently heard from: a state is stamped with the reading it was created at.
    state.sequenced.insert(recent, SourceState::new(now));

    let reclaimed = state.reclaim_expired_sources(now, retention);

    assert_eq!(
        reclaimed, 1,
        "exactly the quiet, token-less source is dropped"
    );
    assert!(
        !state.sequenced.contains_key(&quiet),
        "a source nothing has heard from and no token calls live is reclaimed"
    );
    assert!(
        state.sequenced.contains_key(&live),
        "a LIVE publisher must survive being quiet, or its last_delivered is \
         lost and its next sample reads as a gap"
    );
    assert!(
        state.sequenced.contains_key(&recent),
        "a recently-heard source is not swept at all"
    );
    assert!(
        state.sequenced[&live].retention.latest_access_ms >= now,
        "sparing a live source also REFRESHES its access, so it is not \
         re-examined every tick for the rest of the session"
    );
}

/// R2617 — a beacon from a publisher this subscriber has NEVER SEEN is
/// skipped while a GLOBAL pull is in flight, and only then.
///
/// Upstream takes that arm only for a source it just inserted
/// (`zenoh-ext/src/advanced_subscriber.rs` @ `if states.global_pending_queries > 0 {`),
/// because the startup history GET is already fetching that publisher in
/// full; a per-source `_sn=last+1..hb` GET on top of it asks for the same
/// samples twice.
///
/// THREE ARMS, and the last two are the control. "New source + global pull
/// -> skipped" alone is equally consistent with a guard that skips every
/// heartbeat while a pull runs, or with one that skips every new source —
/// both of which would be worse defects than the gap being closed. So a
/// KNOWN source under the same in-flight pull must still recover, and a new
/// source with NO pull in flight must still recover.
#[cfg(feature = "advanced-history")]
#[test]
fn a_beacon_from_a_new_source_is_skipped_only_while_a_global_pull_is_running() {
    let new_state = |global: usize| {
        machine(
            Box::new(|_| {}),
            MissHandlers::default(),
            true,
            global,
            usize::MAX,
        )
    };

    // THE SUBJECT: never-seen source, global pull running -> skipped.
    let mut pulling = new_state(1);
    assert!(
        pulling.handle_heartbeat(vec![0x0Au8], 7, 5, NOW).is_none(),
        "a beacon from a publisher the global query is already pulling must \
         not raise a second, redundant per-source GET"
    );
    // ...and the source is REMEMBERED anyway, or the next beacon would look
    // new all over again and the skip would repeat forever.
    assert!(
        pulling.sequenced.contains_key(&src(&[0x0A], 7)),
        "the skipped source must still be recorded, as upstream records it \
         before deciding"
    );

    // CONTROL A: same in-flight pull, but a source already KNOWN -> recovers.
    let mut known = new_state(1);
    known.sequenced.insert(src(&[0x0B], 7), source_at(Some(1)));
    let req = known
        .handle_heartbeat(vec![0x0Bu8], 7, 5, NOW)
        .expect("the guard is about NEW sources only; a known one still recovers");
    assert_eq!((req.from_sn, req.to_sn), (2, Some(5)));

    // CONTROL B: never-seen source, NO global pull -> recovers.
    let mut idle = new_state(0);
    let req = idle
        .handle_heartbeat(vec![0x0Cu8], 7, 5, NOW)
        .expect("with no global pull in flight a new source must recover normally");
    assert_eq!((req.from_sn, req.to_sn), (0, Some(5)));
}

/// R311y86 history-gating unit (no session): while `history_pending`, a
/// sample BUFFERS instead of delivering; `finish_history` flushes the
/// buffer oldest-first so the (older) history delivers in order.
#[cfg(feature = "advanced-history")]
#[test]
fn history_pending_buffers_then_flushes_in_order() {
    let delivered = Arc::new(Mutex::new(Vec::<u8>::new()));
    let d = Arc::clone(&delivered);
    let mut state = machine(
        Box::new(move |s: Sample| d.lock().unwrap().push(s.payload[0])),
        MissHandlers::default(),
        true,
        1,
        usize::MAX,
    );

    // History in flight -> the recovered history buffers, nothing delivers.
    let _ = state.ingest(sequenced(0, 0xA0), false, NOW);
    let _ = state.ingest(sequenced(1, 0xA1), false, NOW);
    assert!(
        delivered.lock().unwrap().is_empty(),
        "samples buffer while the history GET is in flight"
    );
    // History completes -> flush oldest-first.
    state.finish_history();
    assert_eq!(
        *delivered.lock().unwrap(),
        vec![0xA0, 0xA1],
        "the buffered history flushes in order on completion"
    );
}

/// R2555 — the TIMESTAMPED twin of the test above, and this atom's last
/// residual made witnessable.
///
/// It asserts the property that matters and that ordering alone cannot
/// give: a sample arriving LIVE while the startup history GET is in flight
/// must not overtake the OLDER samples that GET is about to return. Feed
/// the newer instant first, then the older two, and the delivered order is
/// the CLOCK's, not the arrival order — which is only possible if the live
/// one was held.
///
/// ⚠ The discriminator is the delivered VECTOR, never the buffer's length:
/// a buffer that held the sample and then dropped it would satisfy "nothing
/// delivered early" exactly as well, and lose it. The R2503 sequenced pair
/// above records the same rule for the same reason.
///
/// ⚠⚠ WITHOUT THE BUFFER this test does not merely fail, it fails in the
/// specific way the residual described: the live sample delivers first and
/// the two older ones are then DROPPED by the strictly-newer test, so the
/// subscriber loses history it successfully recovered. That is the measured
/// red the control probe produces.
#[cfg(feature = "advanced-history")]
#[test]
fn a_live_timestamped_sample_waits_for_the_history_it_would_overtake() {
    let delivered = Arc::new(Mutex::new(Vec::<u8>::new()));
    let d = Arc::clone(&delivered);
    let mut state = machine(
        Box::new(move |s: Sample| d.lock().unwrap().push(s.payload[0])),
        MissHandlers::default(),
        true,
        1,
        usize::MAX,
    );
    // No source_info: the timestamped shape. One timestamp-id throughout,
    // so the state is the same one and the order is the clock's.

    // The LIVE sample arrives first and is the NEWEST.
    let _ = state.ingest(timestamped(300, 0xC3), true, NOW);
    assert!(
        delivered.lock().unwrap().is_empty(),
        "a timestamped sample waits while the history GET is in flight"
    );
    // The history GET then returns two OLDER samples, out of order.
    let _ = state.ingest(timestamped(200, 0xC2), false, NOW);
    let _ = state.ingest(timestamped(100, 0xC1), false, NOW);
    assert!(
        delivered.lock().unwrap().is_empty(),
        "recovered timestamped samples buffer too, so the drain can order them"
    );

    state.finish_history();
    assert_eq!(
        *delivered.lock().unwrap(),
        vec![0xC1, 0xC2, 0xC3],
        "the buffer drains by CLOCK order, not arrival order: the live \
         sample that arrived first is delivered last because it is newest"
    );
}

/// R2555 — TWO global history GETs outstanding at once, which is the
/// scenario a `bool` could not represent and the reason the flag became a
/// count in the commit before the third liveliness arm.
///
/// The startup GET is in flight when an unidentified publisher's token
/// opens a SECOND global slot. The first completion must NOT release the
/// buffers, because the second GET is still returning samples that may be
/// older than what is held — under a flag it would have, and the
/// strictly-newer test would then have discarded exactly those older
/// samples. So the assertion between the two completions is the whole
/// test: nothing delivered YET.
///
/// ⚠ It drives `State` directly rather than through a session, because the
/// property is about the COUNT and a loopback GET completes synchronously —
/// which is precisely the arrangement in which two GETs are never
/// concurrent, and so the arrangement that cannot grade this.
#[cfg(feature = "advanced-history")]
#[test]
fn a_second_global_get_holds_the_buffers_the_first_would_have_released() {
    let delivered = Arc::new(Mutex::new(Vec::<u8>::new()));
    let d = Arc::clone(&delivered);
    let mut state = machine(
        Box::new(move |s: Sample| d.lock().unwrap().push(s.payload[0])),
        MissHandlers::default(),
        true,
        // The startup GET, exactly as a host sets it.
        1,
        usize::MAX,
    );

    // An unidentified publisher's token opens a SECOND global slot.
    state.open_global_history_slot();
    assert_eq!(state.global_pending_queries, 2);

    let _ = state.ingest(timestamped(300, 0xC3), true, NOW);
    assert!(
        delivered.lock().unwrap().is_empty(),
        "buffered, as expected"
    );

    // FIRST completion. A `bool` would be cleared here and everything held
    // would be released while the second GET is still answering.
    state.finish_history();
    assert_eq!(state.global_pending_queries, 1);
    assert!(
        delivered.lock().unwrap().is_empty(),
        "the first of two global GETs must NOT release the buffers"
    );

    // The second GET returns an OLDER sample -- the one a premature flush
    // would have made undeliverable, because 300 would already be the
    // newest delivered and 100 is not strictly newer than it.
    let _ = state.ingest(timestamped(100, 0xC1), false, NOW);

    // SECOND completion: now the buffers drain, in clock order.
    state.finish_history();
    assert_eq!(state.global_pending_queries, 0);
    assert_eq!(
        *delivered.lock().unwrap(),
        vec![0xC1, 0xC3],
        "both drain in clock order once the LAST global GET completes"
    );
}

/// R2555 — the depth bound on the timestamped buffer, as a PAIR that
/// differs only in the bound and is fed the identical samples.
///
/// `max_history_depth == 1` is upstream's escape hatch, not a degenerate
/// case to leave untested: that build must deliver LIVE rather than buffer,
/// because a buffer of one can hold nothing reordering would help. The
/// unbounded arm is the control that proves the difference is the bound and
/// not the samples.
#[cfg(feature = "advanced-history")]
#[test]
fn a_depth_of_one_delivers_live_where_an_unbounded_buffer_reorders() {
    let feed = |depth: usize| {
        let delivered = Arc::new(Mutex::new(Vec::<u8>::new()));
        let d = Arc::clone(&delivered);
        let mut state = machine(
            Box::new(move |s: Sample| d.lock().unwrap().push(s.payload[0])),
            MissHandlers::default(),
            true,
            1,
            depth,
        );
        let _ = state.ingest(timestamped(300, 0xC3), true, NOW);
        let _ = state.ingest(timestamped(100, 0xC1), false, NOW);
        state.finish_history();
        let out = delivered.lock().unwrap().clone();
        out
    };

    assert_eq!(
        feed(1),
        vec![0xC3],
        "at depth 1 the live sample delivers immediately, and the older \
         recovered one is then correctly dropped as not strictly newer"
    );
    assert_eq!(
        feed(usize::MAX),
        vec![0xC1, 0xC3],
        "unbounded, both are held and drain in clock order — the same two \
         samples, so the bound is what differs"
    );
}

/// R2503 clause (4), the HISTORY arm — a PAIR that differs only in the
/// bound, fed the identical two samples.
///
/// ⚠ The delivered vector is the discriminator, never the buffer's length:
/// a bounded buffer that DROPPED the oldest would satisfy any length
/// assertion and lose a sample silently, which is the one outcome
/// upstream's delivering spill exists to prevent.
/// ⚠⚠ Upstream inserts FIRST and then spills, so with `depth = 2` the
/// spill fires on the SECOND sample, and `deliver_and_flush` then drains
/// the contiguous successor with it. Traced by hand before it was written
/// down — the first draft of this case asserted a third sample and would
/// have described a mechanism the code does not have.
#[cfg(feature = "advanced-history")]
#[test]
fn a_bounded_history_buffer_spills_the_oldest_and_delivers_it() {
    let feed = |depth: usize| {
        let delivered = Arc::new(Mutex::new(Vec::<u8>::new()));
        let d = Arc::clone(&delivered);
        let mut state = machine(
            Box::new(move |s: Sample| d.lock().unwrap().push(s.payload[0])),
            MissHandlers::default(),
            true,
            1,
            depth,
        );
        let _ = state.ingest(sequenced(0, 0xA0), false, NOW);
        let _ = state.ingest(sequenced(1, 0xA1), false, NOW);
        let got = delivered.lock().unwrap().clone();
        got
    };

    assert_eq!(
        feed(2),
        vec![0xA0, 0xA1],
        "at the ceiling the oldest is DELIVERED (and its contiguous \
         successor drained with it), not dropped"
    );
    // ANTI-VACUITY: the same two samples, no bound. Without this arm
    // "the buffer is bounded" and "the test never filled it" look
    // identical -- the population-of-zero shape this tree keeps meeting.
    // `usize::MAX` is also upstream's own default when the user set no
    // `max_samples`, so this pins the unbounded case as a BEHAVIOUR.
    assert!(
        feed(usize::MAX).is_empty(),
        "with no bound the whole history waits for finish_history"
    );
}

/// R2503 clause (4), the FORWARD-GAP arm — the site the residual clause
/// did NOT name.
///
/// The clause spoke only of the history arm, and a build that trusted it
/// would have left this one unbounded; upstream guards BOTH inserts. Same
/// pair shape: identical samples, only the bound differs.
#[cfg(feature = "advanced-history")]
#[test]
fn a_bounded_gap_buffer_spills_the_oldest_and_delivers_it() {
    let feed = |depth: usize| {
        let delivered = Arc::new(Mutex::new(Vec::<u8>::new()));
        let d = Arc::clone(&delivered);
        let mut state = machine(
            Box::new(move |s: Sample| d.lock().unwrap().push(s.payload[0])),
            MissHandlers::default(),
            true,
            // NOT the history arm: this exercises the `if retransmission`
            // insert, which compiles with the history feature off.
            0,
            depth,
        );
        let _ = state.ingest(sequenced(0, 0xA0), false, NOW);
        // Forward gaps: 2 and 3 buffer while 1 is missing.
        let _ = state.ingest(sequenced(2, 0xA2), false, NOW);
        let _ = state.ingest(sequenced(3, 0xA3), false, NOW);
        let got = delivered.lock().unwrap().clone();
        got
    };

    assert_eq!(
        feed(2),
        vec![0xA0, 0xA2, 0xA3],
        "the gap buffer honours the SAME ceiling, delivering the oldest \
         held sample rather than growing without bound"
    );
    assert_eq!(
        feed(usize::MAX),
        vec![0xA0],
        "unbounded, the gap holds 2 and 3 for the recovery GET to \
         back-fill -- which is what makes the bounded arm above a finding"
    );
}

/// R311y87 (review C2) regression: a per-source recovery GET that completes
/// WHILE the startup history GET is still in flight must NOT flush — flushing
/// advances `last_delivered`, after which an older-sn history reply is
/// silently dropped. The flush is deferred to `finish_history`. Without the
/// `!history_pending` gate, delivered would be `[0xA1]` (sn 0 LOST); with it,
/// `[0xA0, 0xA1]`.
#[cfg(feature = "advanced-history")]
#[test]
fn recovery_completing_mid_history_defers_flush() {
    let delivered = Arc::new(Mutex::new(Vec::<u8>::new()));
    let d = Arc::clone(&delivered);
    let mut state = machine(
        Box::new(move |s: Sample| d.lock().unwrap().push(s.payload[0])),
        MissHandlers::default(),
        true,
        1,
        usize::MAX,
    );
    let key = (vec![0x02u8], 7u32);
    // A per-source recovery GET is in flight (pending_queries=1) and has
    // buffered sn 1, while the startup history GET is also in flight.
    let mut source = SourceState::new(NOW);
    source.pending_queries = 1;
    state.sequenced.insert(src(&key.0, key.1), source);
    let (slot, _) = state.sequenced.get_mut(&src(&key.0, key.1)).unwrap();
    let ring = state.pending.ring();
    assert!(
        ring.is_some_and(|mut ring| ring.place(sequenced_owner(slot), &sequenced(1, 0xA1))),
        "the ring holds sn 1"
    );

    // The recovery GET completes mid-history -> must NOT flush.
    state.finish_recovery(&key);
    assert!(
        delivered.lock().unwrap().is_empty(),
        "no flush while history is pending (a flush would lose later history)"
    );
    // An older history reply (sn 0) arrives -> buffered (history-gated).
    let _ = state.ingest(sequenced(0, 0xA0), false, NOW);
    // History completes -> flush 0,1 in order; sn 0 was NOT lost.
    state.finish_history();
    assert_eq!(
        *delivered.lock().unwrap(),
        vec![0xA0, 0xA1],
        "the deferred flush delivers 0,1 in order; the mid-history recovery did not lose sn 0"
    );
}

/// R311y100 — handle_late_publisher opens exactly one recovery slot per
/// source and no-ops while a GET is in flight (avoids piling up concurrent
/// per-publisher GETs); independent of `retransmission` (a history trigger).
#[cfg(feature = "advanced-history")]
#[test]
fn handle_late_publisher_opens_one_slot_per_source() {
    // late-pub detection is NOT a retransmission concern
    let mut state = silent(false);
    let zid = vec![0x09u8];
    // First detection opens a slot.
    assert!(state.handle_late_publisher(zid.clone(), 4, NOW));
    assert_eq!(state.sequenced[&src(&zid, 4)].pending_queries, 1);
    // A second detection while the GET is in flight is a no-op.
    assert!(!state.handle_late_publisher(zid.clone(), 4, NOW));
    assert_eq!(state.sequenced[&src(&zid, 4)].pending_queries, 1);
    // A distinct publisher gets its own slot.
    assert!(state.handle_late_publisher(zid.clone(), 5, NOW));
    assert_eq!(state.sequenced[&src(&zid, 5)].pending_queries, 1);
}

/// R2553 — the TIMESTAMPED trigger's own slot arithmetic, and the property
/// the sequenced test above cannot state: the two maps are INDEPENDENT.
///
/// A `uhlc` token and a numeric-entity token from the same zid are two
/// different publishers, and their slots must not alias — otherwise a
/// sequenced GET in flight would suppress the timestamped one for the same
/// node, which is a delivery loss with no symptom. The third assertion is
/// therefore the load-bearing one.
#[cfg(feature = "advanced-history")]
#[test]
fn handle_late_timestamped_publisher_opens_one_slot_per_zid() {
    let mut state = silent(false);
    let zid = vec![0x09u8];
    let other = vec![0x0Au8];

    // First detection opens a slot; a second while it is in flight does not.
    assert!(state.handle_late_timestamped_publisher(zid.clone(), NOW));
    assert_eq!(state.timestamped[&ts_src(&zid)].pending_queries, 1);
    assert!(!state.handle_late_timestamped_publisher(zid.clone(), NOW));
    assert_eq!(state.timestamped[&ts_src(&zid)].pending_queries, 1);

    // A SEQUENCED publisher on the SAME zid is a different source: its slot
    // is opened independently and leaves the timestamped one untouched.
    assert!(state.handle_late_publisher(zid.clone(), 4, NOW));
    assert_eq!(state.sequenced[&src(&zid, 4)].pending_queries, 1);
    assert_eq!(state.timestamped[&ts_src(&zid)].pending_queries, 1);

    // A distinct zid gets its own slot.
    assert!(state.handle_late_timestamped_publisher(other.clone(), NOW));
    assert_eq!(state.timestamped[&ts_src(&other)].pending_queries, 1);

    // The GET's terminal Final closes the slot, re-opening the gate.
    state.finish_timestamped_recovery(&zid);
    assert_eq!(state.timestamped[&ts_src(&zid)].pending_queries, 0);
    assert!(state.handle_late_timestamped_publisher(zid.clone(), NOW));
    assert_eq!(state.timestamped[&ts_src(&zid)].pending_queries, 1);
}

/// The in-flight count of a source is 0 or 1 however often its publisher is met again, which
/// is what lets a `u32` hold what upstream counts in a `u64`.
#[cfg(feature = "advanced-history")]
#[test]
fn a_source_has_at_most_one_get_in_flight() {
    let mut state = silent(false);
    let zid = vec![0x0Bu8];
    for _ in 0..1_000 {
        state.handle_late_publisher(zid.clone(), 4, NOW);
        state.handle_late_timestamped_publisher(zid.clone(), NOW);
    }
    assert_eq!(state.sequenced[&src(&zid, 4)].pending_queries, 1);
    assert_eq!(state.timestamped[&ts_src(&zid)].pending_queries, 1);
}

/// What the machine hands its callback, recorded as whether it was lent and its payload byte.
#[cfg(feature = "advanced-recovery")]
fn lent_recording(record: Arc<Mutex<Vec<(bool, u8)>>>) -> Box<dyn FnMut(Delivery<'_>) + Send> {
    Box::new(move |delivery: Delivery<'_>| {
        let lent = matches!(delivery, Delivery::Lent(_));
        let byte = delivery.view().payload()[0];
        record.lock().unwrap().push((lent, byte));
    })
}

/// A live sample the machine delivers as it arrives is handed on as the view the session lent,
/// so nothing of it is copied: an unsequenced one and the first of a sequenced source alike.
#[cfg(feature = "advanced-recovery")]
#[test]
fn a_live_sample_delivered_as_it_arrives_is_lent_not_copied() {
    let record = Arc::new(Mutex::new(Vec::new()));
    let mut state = State::new(lent_recording(Arc::clone(&record)), MissHandlers::default());
    let plain = Sample::new_put("demo/data", vec![0xA0]);
    assert!(state.handle_live(&plain, NOW).is_none());
    assert!(state.handle_live(&sequenced(0, 0xA1), NOW).is_none());
    assert!(state.handle_live(&sequenced(1, 0xA2), NOW).is_none());
    assert_eq!(
        *record.lock().unwrap(),
        vec![(true, 0xA0), (true, 0xA1), (true, 0xA2)]
    );
}

/// A live sample the machine must keep past the call (a history get is in flight) is written
/// once into the subscriber's ring and handed on lent from its record when the ring drains, so
/// holding it takes no memory.
#[cfg(feature = "advanced-history")]
#[test]
fn a_sample_the_machine_held_is_handed_on_lent_from_its_ring() {
    let record = Arc::new(Mutex::new(Vec::new()));
    let mut state = State::new(lent_recording(Arc::clone(&record)), MissHandlers::default())
        .with_history(1, usize::MAX);
    assert!(state.handle_live(&sequenced(0, 0xB0), NOW).is_none());
    assert!(
        record.lock().unwrap().is_empty(),
        "held while the history get is in flight"
    );
    state.finish_history();
    assert_eq!(*record.lock().unwrap(), vec![(true, 0xB0)]);
}

/// A recovered sample the machine hands on at once is read where its reply lies, not copied.
#[cfg(feature = "advanced-recovery")]
#[test]
fn a_recovered_sample_handed_on_at_once_is_lent() {
    let record = Arc::new(Mutex::new(Vec::new()));
    let mut state = State::new(lent_recording(Arc::clone(&record)), MissHandlers::default());
    assert!(state.handle_recovered(&sequenced(0, 0xC0), NOW).is_none());
    assert_eq!(*record.lock().unwrap(), vec![(true, 0xC0)]);
}

/// A put on `demo/data` from the publisher `eid` of zid `0x02`, numbered `sn`, carrying
/// `payload`.
#[cfg(feature = "advanced-recovery")]
fn from_publisher(eid: u32, sn: u32, payload: Vec<u8>) -> Sample {
    let mut s = Sample::new_put("demo/data", payload);
    s.source_info = Some(SourceInfo::new(&[0x02], eid, sn));
    s
}

/// A source met while every row is taken takes the row of the idle source met longest ago, and
/// the others keep theirs; while every row is busy (a get in flight), the new source's sample is
/// delivered as it came and takes no row.
///
/// # Control
///
/// A table that took the row met most recently (`max_by_key` for `min_by_key` in
/// `Sources::entry`) lets source 0 go, which reds the second assertion; one that took a busy row
/// reds the last two.
#[cfg(feature = "advanced-recovery")]
#[test]
fn a_new_source_takes_the_row_of_the_idle_one_met_longest_ago() {
    let rows = u32::try_from(caps::MAX_ADVANCED_SOURCES).expect("a table of a u32 of rows");
    assert!(rows >= 2, "the test meets two sources at least");
    let delivered = Arc::new(Mutex::new(Vec::<u32>::new()));
    let d = Arc::clone(&delivered);
    let mut state = machine(
        Box::new(move |s: Sample| d.lock().unwrap().push(s.source_info.unwrap().eid)),
        MissHandlers::default(),
        true,
        0,
        usize::MAX,
    );
    for eid in 0..rows {
        assert!(state
            .handle_recovered(&from_publisher(eid, 0, vec![0]), NOW)
            .is_none());
    }
    // Source 0 is met again, so source 1 is the one met longest ago.
    assert!(state
        .handle_recovered(&from_publisher(0, 1, vec![0]), NOW)
        .is_none());
    assert!(state
        .handle_recovered(&from_publisher(rows, 0, vec![0]), NOW)
        .is_none());
    assert!(state.sequenced.contains_key(&src(&[0x02], rows)));
    assert!(
        state.sequenced.contains_key(&src(&[0x02], 0)),
        "the source met again keeps its row"
    );
    assert!(
        !state.sequenced.contains_key(&src(&[0x02], 1)),
        "the source met longest ago gave its row"
    );

    // Every row busy: a new source has none, and its sample still goes on.
    for (_, _, source) in state.sequenced.iter_mut() {
        source.pending_queries = 1;
    }
    delivered.lock().unwrap().clear();
    assert!(state
        .handle_recovered(&from_publisher(rows + 1, 0, vec![0]), NOW)
        .is_none());
    assert_eq!(*delivered.lock().unwrap(), vec![rows + 1]);
    assert!(
        !state.sequenced.contains_key(&src(&[0x02], rows + 1)),
        "no busy row is taken"
    );
}

/// A gap's samples are held in the subscriber's ring until one finds no room; then what the
/// source holds goes on first, in order, with the hole given up reported, and then that sample:
/// the ring's bound gives up the wait and never a sample or its order.
///
/// # Control
///
/// Dropping the sample that found no room (no `out.deliver(sample)` in `hold_sequenced`) leaves
/// one sequence number out of the delivered run; delivering it before the held ones (no
/// `flush_sequenced` first) breaks the order. Either reds the run's assertion.
#[cfg(feature = "advanced-recovery")]
#[test]
fn a_gap_sample_the_ring_has_no_room_for_goes_on_after_what_is_held() {
    let delivered = Arc::new(Mutex::new(Vec::<u32>::new()));
    let misses = Arc::new(Mutex::new(Vec::new()));
    let d = Arc::clone(&delivered);
    let mut state = machine(
        Box::new(move |s: Sample| d.lock().unwrap().push(s.source_info.unwrap().sn)),
        recording_miss_handlers(Arc::clone(&misses)),
        true,
        0,
        usize::MAX,
    );
    // Each record is longer than 400 bytes, so this many cannot all be held.
    let last = u32::try_from(caps::ADVANCED_SUBSCRIBER_PENDING_BYTES / 400 + 2)
        .expect("a ring of a u32 of records");
    assert!(state
        .handle_recovered(&from_publisher(7, 0, vec![0; 400]), NOW)
        .is_none());
    assert!(state
        .handle_recovered(&from_publisher(7, 2, vec![0; 400]), NOW)
        .is_none());
    assert_eq!(
        *delivered.lock().unwrap(),
        vec![0],
        "sn 2 is held while sn 1 is missing"
    );
    for sn in 3..=last {
        assert!(state
            .handle_recovered(&from_publisher(7, sn, vec![0; 400]), NOW)
            .is_none());
    }
    let run: Vec<u32> = core::iter::once(0).chain(2..=last).collect();
    assert_eq!(
        *delivered.lock().unwrap(),
        run,
        "every sample goes on, in order, once the ring is full"
    );
    assert_eq!(*misses.lock().unwrap(), vec![miss_of(&[0x02], 7, 1)]);
}

/// Meeting a new source, holding a gap's samples back and handing them on once the hole is
/// filled take no memory: the source's row is in the subscriber's table and the samples are
/// records of its ring, lent to the callback where they lie.
///
/// # Control
///
/// A source table that allocates its first row (a hashed map) or a buffer that copies a held
/// sample out (`Sample::from_view`) reds the count.
#[cfg(feature = "advanced-recovery")]
#[test]
fn a_new_source_and_the_samples_it_holds_back_take_no_memory() {
    let record = Arc::new(Mutex::new(Vec::with_capacity(8)));
    let mut state = State::new(lent_recording(Arc::clone(&record)), MissHandlers::default())
        .with_retransmission(true);
    let samples: Vec<Sample> = [0u32, 2, 3, 1]
        .iter()
        .map(|&sn| from_publisher(9, sn, vec![u8::try_from(sn).unwrap()]))
        .collect();

    let before = crate::test_alloc::allocations();
    for sample in &samples {
        assert!(state.handle_recovered(sample, NOW).is_none());
    }
    let during = crate::test_alloc::allocations() - before;

    assert_eq!(
        *record.lock().unwrap(),
        vec![(true, 0), (true, 1), (true, 2), (true, 3)],
        "sn 2 and 3 waited for sn 1, and went on lent from the ring"
    );
    assert_eq!(during, 0, "the row and the held samples took no memory");
}

/// A timestamped sample held back while a history get is in flight, and the drain that hands it
/// on, take no memory either.
///
/// # Control
///
/// A timestamped buffer that copies the sample out (`Delivery::into_sample`) reds the count.
#[cfg(feature = "advanced-history")]
#[test]
fn a_timestamped_sample_held_for_the_history_takes_no_memory() {
    let record = Arc::new(Mutex::new(Vec::with_capacity(8)));
    let mut state = State::new(lent_recording(Arc::clone(&record)), MissHandlers::default())
        .with_history(1, usize::MAX);
    let late = timestamped(300, 0xC3);
    let early = timestamped(100, 0xC1);

    let before = crate::test_alloc::allocations();
    assert!(state.handle_live(&late, NOW).is_none());
    assert!(state.handle_recovered(&early, NOW).is_none());
    state.finish_history();
    let during = crate::test_alloc::allocations() - before;

    assert_eq!(*record.lock().unwrap(), vec![(true, 0xC1), (true, 0xC3)]);
    assert_eq!(during, 0, "the row and the held samples took no memory");
}

/// The state's lock is handed out while healthy, and refused with the state's own message once a
/// panic of its holder poisoned it, as `std`'s `expect` refused it. Turned red by a `lock_state`
/// that hands a poisoned lock out or panics with another message.
#[cfg(feature = "std")]
#[test]
fn a_state_lock_its_holder_panicked_in_is_refused_with_the_state_message() {
    let lock = std::sync::Arc::new(StateLock::new(State::new(
        owned_samples(|_| {}),
        MissHandlers::default(),
    )));
    drop(lock_state(&lock));
    let holder = {
        let lock = std::sync::Arc::clone(&lock);
        std::thread::spawn(move || {
            let _guard = lock_state(&lock);
            panic!("the holder panics with the state locked");
        })
    };
    assert!(holder.join().is_err(), "the holder panicked");
    let refused = std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| {
        drop(lock_state(&lock));
    }));
    let payload = refused.expect_err("a poisoned state lock is refused");
    assert_eq!(
        payload.downcast_ref::<String>().map(String::as_str),
        Some(STATE_POISONED)
    );
}
