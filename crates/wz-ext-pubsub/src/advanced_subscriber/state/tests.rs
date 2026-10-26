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
#[cfg(feature = "advanced-recovery")]
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
    let state = State::new(on_sample, miss_handlers).with_retransmission(retransmission);
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
    s.timestamp = Some(wz_session_core::sample::TimestampHint {
        time,
        zid: vec![0x02u8],
    });
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
    state
        .sequenced
        .insert((vec![0x01u8], 1u32), source_at(Some(4)));
    state
        .sequenced
        .insert((vec![0x02u8], 2u32), source_at(Some(0)));

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
    plain
        .sequenced
        .insert((vec![0x01u8], 1u32), source_at(Some(0)));
    assert!(
        plain.periodic_requests().is_empty(),
        "no retransmission -> periodic_requests is a no-op"
    );
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
    state.sequenced.insert(key.clone(), source_at(Some(1)));

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
    state.sequenced.get_mut(&key).unwrap().pending_queries = 0;
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
#[cfg(feature = "advanced-recovery")]
#[test]
fn the_retention_sweep_reclaims_only_quiet_sources_that_no_token_calls_live() {
    let mut state = silent(true);

    let retention = Duration::from_secs(60);
    let now: u64 = 1_000_000;
    let long_ago = now - 600_000;
    let quiet = (vec![0xAAu8], 1u32);
    let live = (vec![0xBBu8], 1u32);
    let recent = (vec![0xCCu8], 1u32);

    state.sequenced.insert(quiet.clone(), SourceState::new(now));
    state.sequenced.get_mut(&quiet).unwrap().retention = Retention {
        latest_access_ms: long_ago,
        alive: false,
    };
    state.sequenced.insert(live.clone(), SourceState::new(now));
    state.sequenced.get_mut(&live).unwrap().retention = Retention {
        latest_access_ms: long_ago,
        alive: true,
    };
    // Recently heard from: a state is stamped with the reading it was created at.
    state
        .sequenced
        .insert(recent.clone(), SourceState::new(now));

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
        pulling.sequenced.contains_key(&(vec![0x0Au8], 7)),
        "the skipped source must still be recorded, as upstream records it \
         before deciding"
    );

    // CONTROL A: same in-flight pull, but a source already KNOWN -> recovers.
    let mut known = new_state(1);
    known
        .sequenced
        .insert((vec![0x0Bu8], 7), source_at(Some(1)));
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
    let mut buffered = BTreeMap::new();
    buffered.insert(1u32, sequenced(1, 0xA1));
    let mut source = SourceState::new(NOW);
    source.pending_samples = buffered;
    source.pending_queries = 1;
    state.sequenced.insert(key.clone(), source);

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
    assert_eq!(state.sequenced[&(zid.clone(), 4)].pending_queries, 1);
    // A second detection while the GET is in flight is a no-op.
    assert!(!state.handle_late_publisher(zid.clone(), 4, NOW));
    assert_eq!(state.sequenced[&(zid.clone(), 4)].pending_queries, 1);
    // A distinct publisher gets its own slot.
    assert!(state.handle_late_publisher(zid.clone(), 5, NOW));
    assert_eq!(state.sequenced[&(zid, 5)].pending_queries, 1);
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
    assert_eq!(state.timestamped[&zid].pending_queries, 1);
    assert!(!state.handle_late_timestamped_publisher(zid.clone(), NOW));
    assert_eq!(state.timestamped[&zid].pending_queries, 1);

    // A SEQUENCED publisher on the SAME zid is a different source: its slot
    // is opened independently and leaves the timestamped one untouched.
    assert!(state.handle_late_publisher(zid.clone(), 4, NOW));
    assert_eq!(state.sequenced[&(zid.clone(), 4)].pending_queries, 1);
    assert_eq!(state.timestamped[&zid].pending_queries, 1);

    // A distinct zid gets its own slot.
    assert!(state.handle_late_timestamped_publisher(other.clone(), NOW));
    assert_eq!(state.timestamped[&other].pending_queries, 1);

    // The GET's terminal Final closes the slot, re-opening the gate.
    state.finish_timestamped_recovery(&zid);
    assert_eq!(state.timestamped[&zid].pending_queries, 0);
    assert!(state.handle_late_timestamped_publisher(zid.clone(), NOW));
    assert_eq!(state.timestamped[&zid].pending_queries, 1);
}
