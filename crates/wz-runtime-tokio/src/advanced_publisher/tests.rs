// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What only a runtime session can witness of the advanced publisher: its declarations, its
//! loopback recovery through a real `session.query`, the frames it leaves on a link, and the
//! beacon task on the process's `net` runtime. What the composite decides on its own (the order
//! of declaration and retraction, the beacon's tick, the knobs) is witnessed against a recording
//! plane in `wz-ext-pubsub`.

use super::*;
use crate::advanced_cache::CacheConfig;

/// An [`AdvancedPublisherOptions`] written the way a struct literal with a `..default()` tail
/// is: the type is `#[non_exhaustive]` and lives in `wz-ext-pubsub`, so a literal cannot name it
/// from here, and each field is set on the default instead.
macro_rules! adv_options {
    ($($field:ident : $value:expr,)* ..AdvancedPublisherOptions::default()) => {{
        #[allow(unused_mut)]
        let mut options = AdvancedPublisherOptions::default();
        $(options.$field = $value;)*
        options
    }};
}

/// R311y833 — the options an `@adv` recovery GET must carry, and the reason
/// these three tests share one constructor rather than spelling
/// `QueryOptions::get()` inline.
///
/// The GET is asked under `<ke>/@adv/**` and the cache answers under the
/// CACHED SAMPLE'S OWN key (`demo/data`), which does not intersect it. That
/// is precisely the case `_anyke` exists for, and production already carries
/// it unconditionally — `advanced_subscriber::history_selector` returns the
/// bare `"_anyke"` even with no other knobs (R311y442). These tests
/// hand-rolled the GET without it, so before y833 they asserted a delivery
/// that neither zenoh (`zenoh/src/api/session.rs:2847`) nor zenoh-pico
/// (`vendor/zenoh-pico/src/session/query.c:121`) performs. The acceptance
/// gate made that visible; the tests were what was wrong, not the cache.
///
/// Written as the `parameters` field rather than through
/// `QueryOptions::with_accept_replies` deliberately: that setter is
/// `query-selector-parameters`-gated, and adding that gate to these tests
/// would change WHICH LANES RUN THEM for a reason orthogonal to what they
/// prove. The value itself comes from the same
/// [`wz_session_core::selector_params::anyke_params`] SSOT the production
/// selector is built from, so the two cannot drift.
///
/// R311y836 — the SAME class again, one axis over, and the same remedy.
/// These three tests ask the cache for a RING and assert they get all of it;
/// they named no consolidation mode, and y836 made the unnamed mode resolve
/// to LATEST (`zenoh/src/api/session.rs:2250`), which collapses a ring to one
/// sample per keyexpr. MEASURED: all three went red together, e.g.
/// `left: [("demo/data", [2])]` against `right: [("demo/data", [0]),
/// ("demo/data", [1]), ("demo/data", [2])]`. Once more the TEST was what
/// diverged from production, not the cache — the real advanced subscriber
/// pins `None` on every one of its recovery / history GETs, as zenoh-ext
/// (`zenoh-ext/src/advanced_subscriber.rs` @ `global_pending_queries`, at every
/// site that issues one) and
/// zenoh-pico (`vendor/zenoh-pico/src/api/advanced_subscriber.c:915`) do.
/// Set as the FIELD for the same lane-preserving reason as `parameters`
/// above; with `query-consolidation` off the field is inert, because
/// `effective_consolidation` hard-returns `None` there.
#[cfg(feature = "query-get")]
fn adv_recovery_get_options() -> crate::session::QueryOptions {
    use crate::session::QueryOptions;
    use wz_session_core::locality::Locality;

    let mut opts = QueryOptions::get().with_allowed_destination(Locality::SessionLocal);
    opts.parameters = Some(wz_session_core::selector_params::anyke_params(&[]).into_bytes());
    opts.consolidation = Some(wz_session_core::query_mode::ConsolidationMode::None);
    opts
}

/// Composed session-API loopback e2e (a real `session.query` through
/// the declared queryable, NOT a kernel-proxy — though SessionLocal
/// dispatch stays in-process and does NOT traverse the Push/Response
/// wire codec, so this is "session-API loopback", not "wire-level"):
/// an `AdvancedPublisher` with a cache publishes three sequenced
/// samples, then a loopback `session.query` over the `@adv` namespace
/// fires the cache queryable inline and recovers all three. Proves
/// publisher -> cache_sample -> queryable -> get composition.
#[cfg(feature = "query-get")]
#[test]
fn published_samples_recover_via_loopback_cache_query() {
    use std::sync::Mutex;

    use crate::observer::ApplicationLayerObserver;
    use crate::reply_sink::ReplyView;
    use crate::runtime_impl::TokioTime;
    use crate::session::TokioSession;

    let (actions, _driver) = crate::test_fixtures::recording_actions();
    let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
    let clock = Arc::new(TokioTime::new());
    let session = TokioSession::new(actions, observer, clock);

    // SequenceNumber sequencing + a cache deep enough to hold all three.
    let options = adv_options! {
        sequencing: Sequencing::SequenceNumber,
        cache: Some(CacheConfig {
            max_samples: 8,
            ..CacheConfig::default()
        }),
        publisher_detection: true,
        sample_miss_detection: MissDetectionConfig::default(),
        ..AdvancedPublisherOptions::default()
    };
    let publisher = AdvancedPublisher::declare(&session, "demo/data", options, vec![0x01])
        .expect("advanced publisher declares against the test link");

    for v in 0u8..3 {
        publisher
            .put(&[v])
            .expect("advanced put publishes + caches");
    }
    assert_eq!(
        publisher.cache().map(|c| c.len()),
        Some(3),
        "the cache retained all three sequenced samples"
    );

    // The loopback GET goes over `demo/data/@adv/**`, which is exactly what
    // `advanced_ke::history_get_ke` builds and what a real advanced
    // SUBSCRIBER puts on the wire.
    //
    // R311y543 — it used to be `demo/data/**`, and that stopped covering the
    // cache queryable when the @verbatim rule landed. The change is the rule
    // working rather than a regression: `@adv` is zenoh's ADMIN namespace and
    // a `**` does not reach into it (`zenoh-keyexpr` classical.rs:65-72), so
    // upstream's own `demo/data/**` would not have found this cache either.
    // A user GET reaching a router's internal namespace was the same defect
    // this round found on the SUBSCRIBE side, measured against the real
    // `libzenohc.so`.
    let replies = Arc::new(Mutex::new(Vec::<(String, Vec<u8>)>::new()));
    let rec = Arc::clone(&replies);
    session
        .query(
            "demo/data/@adv/**",
            adv_recovery_get_options(),
            move |reply: &dyn ReplyView| {
                rec.lock()
                    .expect("reply recorder poisoned")
                    .push((reply.keyexpr().to_string(), reply.payload().to_vec()));
            },
            |_rid| {},
        )
        .expect("loopback query fires the cache queryable inline");

    let mut got = replies.lock().expect("reply recorder poisoned").clone();
    got.sort();
    assert_eq!(
        got,
        vec![
            ("demo/data".to_string(), vec![0]),
            ("demo/data".to_string(), vec![1]),
            ("demo/data".to_string(), vec![2]),
        ],
        "the loopback query recovered all three cached samples under their original key"
    );
}

/// R3063 -- an advanced put of a CHUNK of shared memory: on a face that negotiated shared memory
/// the sample goes out as the chunk's descriptor and not its bytes, with the sequence number a
/// bytes put would carry; on one that did not, as bytes. The reference count on the chunk's slot
/// is what a descriptor that left must have raised and a sample sent as bytes must not have.
#[cfg(all(feature = "transport-shm", feature = "session-extshm"))]
#[test]
fn an_advanced_put_of_a_chunk_goes_as_the_descriptor_to_a_face_that_negotiated() {
    use crate::observer::ApplicationLayerObserver;
    use crate::runtime_impl::TokioTime;
    use crate::session::TokioSession;
    use crate::shm_provider::{reference_state, ReferenceState, ShmBackedPayload};
    use wz_session_core::extshm::encode_shm_descriptor;

    const VALUE: &[u8] = b"an advanced sample in shared memory";
    let contains =
        |haystack: &[u8], needle: &[u8]| haystack.windows(needle.len()).any(|w| w == needle);

    for negotiated in [true, false] {
        let (actions, driver) = crate::test_fixtures::recording_actions();
        actions.set_shm_offer(true);
        actions.negotiate_shm_against_peer(negotiated);
        let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
        let session = TokioSession::new(actions, observer, Arc::new(TokioTime::new()));
        let options = adv_options! {
            sequencing: Sequencing::SequenceNumber,
            cache: Some(CacheConfig::default()),
            ..AdvancedPublisherOptions::default()
        };
        let publisher = AdvancedPublisher::declare(&session, "demo/data", options, vec![0x01])
            .expect("advanced publisher declares against the test link");
        let mut held = ShmBackedPayload::alloc(VALUE.len()).expect("alloc a sample buffer");
        held.write(VALUE);
        let chunk = Arc::new(held);
        let descriptor = chunk.descriptor();
        let before = driver.frame_count();

        publisher
            .put_shm_with(&chunk, AdvancedPutOptions::default())
            .expect("the advanced put of a chunk publishes");

        let frame = driver.frame_bytes(driver.frame_count() - 1);
        assert!(driver.frame_count() > before, "the put left a frame");
        if negotiated {
            assert!(
                contains(&frame, &encode_shm_descriptor(&descriptor)),
                "the chunk's descriptor is on the wire of a face that negotiated shared memory"
            );
            assert!(
                !contains(&frame, VALUE),
                "and its bytes are not: the sample went as a reference to the segment"
            );
            assert_eq!(
                reference_state(&descriptor),
                Some(ReferenceState::Held(2)),
                "the owner's reference and the one its receiver will release"
            );
        } else {
            assert!(
                contains(&frame, VALUE),
                "a face that did not negotiate is sent bytes"
            );
            assert!(!contains(&frame, &encode_shm_descriptor(&descriptor)));
            assert_eq!(reference_state(&descriptor), Some(ReferenceState::Held(1)));
        }
    }
}

/// R3063 -- the cache keeps a chunk AS the chunk, and a recovery reply replays it as shared
/// memory: a requester of the same session is handed the chunk, not a copy of its bytes. The
/// handle count is the structural witness that the ring holds the buffer itself (a copy would
/// leave the caller's the only one), and the bytes put beside it is the control that the count
/// can stay put.
#[cfg(all(feature = "query-get", feature = "transport-shm"))]
#[test]
fn a_chunk_put_is_cached_as_the_chunk_and_recovered_as_shared_memory() {
    use std::sync::Mutex;

    use crate::observer::ApplicationLayerObserver;
    use crate::reply_sink::ReplyView;
    use crate::runtime_impl::TokioTime;
    use crate::session::TokioSession;
    use crate::shm_provider::ShmBackedPayload;

    let (actions, _driver) = crate::test_fixtures::recording_actions();
    let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
    let session = TokioSession::new(actions, observer, Arc::new(TokioTime::new()));
    let options = adv_options! {
        sequencing: Sequencing::SequenceNumber,
        cache: Some(CacheConfig {
            max_samples: 8,
            ..CacheConfig::default()
        }),
        ..AdvancedPublisherOptions::default()
    };
    let publisher = AdvancedPublisher::declare(&session, "demo/data", options, vec![0x01])
        .expect("advanced publisher declares against the test link");
    let mut held = ShmBackedPayload::alloc(5).expect("alloc a sample buffer");
    held.write(b"chunk");
    let chunk = Arc::new(held);
    assert_eq!(Arc::strong_count(&chunk), 1);

    publisher
        .put_shm_with(&chunk, AdvancedPutOptions::default())
        .expect("the advanced put of a chunk publishes and caches");
    publisher.put(b"bytes").expect("a bytes put beside it");

    assert_eq!(
        Arc::strong_count(&chunk),
        2,
        "the ring holds the buffer itself: a copy of its bytes would leave this handle alone"
    );
    let seen = Arc::new(Mutex::new(Vec::<(Vec<u8>, bool)>::new()));
    let rec = Arc::clone(&seen);
    session
        .query(
            "demo/data/@adv/**",
            adv_recovery_get_options(),
            move |reply: &dyn ReplyView| {
                rec.lock().expect("reply recorder poisoned").push((
                    reply.payload().to_vec(),
                    reply
                        .payload_shared()
                        .is_some_and(|bytes| bytes.is_shared_memory()),
                ));
            },
            |_rid| {},
        )
        .expect("loopback query fires the cache queryable inline");

    let mut got = seen.lock().expect("reply recorder poisoned").clone();
    got.sort();
    assert_eq!(
        got,
        vec![(b"bytes".to_vec(), false), (b"chunk".to_vec(), true)],
        "the cached chunk is recovered as shared memory and the cached bytes as bytes"
    );
}

/// R311y561 — `delete()` RETAINS the retraction in the cache, and a loopback
/// recovery GET gets it back as a **Del** reply carrying its own sn.
///
/// R311y559 shipped `delete()` deliberately skipping the cache, because a
/// ring with no sample kind could only have replayed the Del as a Put —
/// resurrecting the deleted key on any recovering subscriber. `CachedSample`
/// carries the kind now, so the reason is gone and the retraction is
/// retained like any other sample.
///
/// Two things are asserted that a payload-only check would miss. The reply
/// KIND, because a Del and an empty Put have the same (empty) payload and
/// only the kind tells a subscriber whether the key still holds a value. And
/// the ring DEPTH plus the recovered sn set, because the delete draws from
/// the same sequence counter as `put` — a Del that skipped the counter, or
/// one dropped from the ring, leaves a permanent apparent gap that a
/// gap-detecting subscriber re-asks for forever.
#[cfg(feature = "query-get")]
#[test]
fn deleted_sample_is_cached_and_recovers_as_a_del_reply() {
    use std::sync::Mutex;

    use crate::observer::ApplicationLayerObserver;
    use crate::reply_sink::{ReplyKind, ReplyView};
    use crate::runtime_impl::TokioTime;
    use crate::session::TokioSession;

    let (actions, _driver) = crate::test_fixtures::recording_actions();
    let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
    let clock = Arc::new(TokioTime::new());
    let session = TokioSession::new(actions, observer, clock);

    let options = adv_options! {
        sequencing: Sequencing::SequenceNumber,
        cache: Some(CacheConfig {
            max_samples: 8,
            ..CacheConfig::default()
        }),
        publisher_detection: true,
        sample_miss_detection: MissDetectionConfig::default(),
        ..AdvancedPublisherOptions::default()
    };
    let publisher = AdvancedPublisher::declare(&session, "demo/data", options, vec![0x01])
        .expect("advanced publisher declares against the test link");

    // put(sn 0), put(sn 1), delete(sn 2), put(sn 3) — one mixed stream.
    publisher.put(&[0]).expect("advanced put");
    publisher.put(&[1]).expect("advanced put");
    publisher.delete().expect("advanced delete");
    publisher.put(&[3]).expect("advanced put");

    assert_eq!(
        publisher.cache().map(|c| c.len()),
        Some(4),
        "the DELETE is retained alongside the three puts (3 before y561)"
    );

    /// One recorded reply: its kind, its concrete key, its payload, and the
    /// `sn` off its source_info (`None` when the build emits no
    /// `reply-source-info` — see the assertions below).
    type RecordedReply = (ReplyKind, String, Vec<u8>, Option<u32>);

    let replies: Arc<Mutex<Vec<RecordedReply>>> = Arc::new(Mutex::new(Vec::new()));
    let rec = Arc::clone(&replies);
    session
        .query(
            "demo/data/@adv/**",
            adv_recovery_get_options(),
            move |reply: &dyn ReplyView| {
                rec.lock().expect("reply recorder poisoned").push((
                    reply.kind(),
                    reply.keyexpr().to_string(),
                    reply.payload().to_vec(),
                    reply.source_info().map(|si| si.sn),
                ));
            },
            |_rid| {},
        )
        .expect("loopback query fires the cache queryable inline");

    let got = replies.lock().expect("reply recorder poisoned").clone();
    // The cache replies oldest-first, so ring order IS reply order and no
    // sort is needed — which also keeps this arm meaningful on a build that
    // emits no source_info to sort by.
    let shapes: Vec<(ReplyKind, String, Vec<u8>)> = got
        .iter()
        .map(|(k, ke, p, _)| (*k, ke.clone(), p.clone()))
        .collect();
    assert_eq!(
        shapes,
        vec![
            (ReplyKind::Put, "demo/data".to_string(), vec![0]),
            (ReplyKind::Put, "demo/data".to_string(), vec![1]),
            (ReplyKind::Del, "demo/data".to_string(), Vec::new()),
            (ReplyKind::Put, "demo/data".to_string(), vec![3]),
        ],
        "the delete comes back as a Del reply under its own key, in ring \
         order between the puts around it"
    );

    // The sn sequence needs the source_info ext on the wire, which the codec
    // gates `reply-source-info` — composed by `ext-pubsub-advanced-recovery`
    // (Cargo.toml), NOT by advanced-cache alone. Without it the recovery
    // reply is deliberately source_info-free (pico-faithful), so asserting
    // the sequence unconditionally would fail a lane that is behaving
    // correctly. This is the arm that pins the DELETE occupying sn 2: a Del
    // that skipped the shared counter would leave a permanent apparent gap.
    #[cfg(feature = "ext-pubsub-advanced-recovery")]
    {
        let sns: Vec<Option<u32>> = got.iter().map(|(_, _, _, sn)| *sn).collect();
        assert_eq!(
            sns,
            vec![Some(0), Some(1), Some(2), Some(3)],
            "an unbroken 0..=3 sequence with the DELETE at sn 2 — the delete \
             draws from the same counter as put"
        );
    }
}

/// R311y562 — a sample published with an ENCODING and an ATTACHMENT comes
/// back through the recovery path carrying both.
///
/// This is the end-to-end arm of the y561 residual, and it is deliberately
/// driven through the whole chain — `put_with` -> `PublishOptions` ->
/// `CachedSample` -> `answer_from_ring` -> the reply -> `ReplyView` — rather
/// than asserted on the ring, because the ring was never the only place the
/// two fields could be lost: before this round `answer_from_ring` had no
/// attachment slot to pass them through even if the ring had held them.
/// A unit test on `CachedSample` would have been green with the wire half
/// still broken.
///
/// The negative arm (sn 1, published by plain `put`) is what makes the
/// positive one a claim: it pins that the accessors report absence as
/// `None` rather than defaulting, so `Some(..)` on sn 0 cannot be an
/// artifact of the reader.
#[cfg(all(feature = "query-get", feature = "pubsub-encoding"))]
#[test]
fn published_encoding_and_attachment_survive_recovery() {
    use std::sync::Mutex;

    use crate::observer::ApplicationLayerObserver;
    use crate::reply_sink::ReplyView;
    use crate::runtime_impl::TokioTime;
    use crate::session::TokioSession;
    use wz_session_core::sample::EncodingHint;

    let (actions, _driver) = crate::test_fixtures::recording_actions();
    let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
    let clock = Arc::new(TokioTime::new());
    let session = TokioSession::new(actions, observer, clock);

    let options = adv_options! {
        sequencing: Sequencing::SequenceNumber,
        cache: Some(CacheConfig {
            max_samples: 8,
            ..CacheConfig::default()
        }),
        publisher_detection: true,
        sample_miss_detection: MissDetectionConfig::default(),
        ..AdvancedPublisherOptions::default()
    };
    let publisher = AdvancedPublisher::declare(&session, "demo/data", options, vec![0x01])
        .expect("advanced publisher declares against the test link");

    // sn 0 carries both metadata fields; sn 1 carries neither.
    publisher
        .put_with(
            &[0xAA],
            AdvancedPutOptions::default()
                .with_encoding(EncodingHint {
                    packed_id: 0x0B,
                    schema: None,
                })
                .with_attachment(b"side-band".to_vec()),
        )
        .expect("advanced put with metadata");
    publisher.put(&[0xBB]).expect("advanced put");

    /// One recorded reply: `(payload, encoding packed_id, attachment)`.
    type RecordedMeta = (Vec<u8>, Option<u32>, Option<Vec<u8>>);

    let replies: Arc<Mutex<Vec<RecordedMeta>>> = Arc::new(Mutex::new(Vec::new()));
    let rec = Arc::clone(&replies);
    session
        .query(
            "demo/data/@adv/**",
            adv_recovery_get_options(),
            move |reply: &dyn ReplyView| {
                rec.lock().expect("reply recorder poisoned").push((
                    reply.payload().to_vec(),
                    reply.put_encoding().map(|(id, _schema)| id),
                    reply.attachment().map(<[u8]>::to_vec),
                ));
            },
            |_rid| {},
        )
        .expect("loopback query fires the cache queryable inline");

    let got = replies.lock().expect("reply recorder poisoned").clone();
    assert_eq!(
        got[0],
        (vec![0xAA], Some(0x0B), Some(b"side-band".to_vec())),
        "the recovered sample carries the encoding and the attachment it \
         was published with",
    );
    assert_eq!(
        got[1],
        (vec![0xBB], None, None),
        "a sample published without either reports both absent — the \
         accessors do not manufacture a default",
    );
}

/// R311y562 — the LIVE half of `AdvancedPublisherOn::put_with`: the
/// encoding and attachment reach a subscriber on the ordinary publish path,
/// not only the recovery one.
///
/// This test exists because a damage probe said it had to. Deleting the
/// wire-side fold in `put_with` — the two `opts.with_encoding` /
/// `with_attachment` lines — left
/// `published_encoding_and_attachment_survive_recovery` GREEN, because that
/// test reads the reply the CACHE answers and the cache is populated from
/// the options directly. Two folds, one witness: the live half was
/// unpinned, and a future edit could have deleted it silently. Now each
/// fold has a test that reds when it goes.
#[cfg(all(feature = "declare-subscriber", feature = "pubsub-allow-loop"))]
#[test]
fn put_with_metadata_reaches_a_live_subscriber() {
    use std::sync::Mutex;

    use crate::observer::ApplicationLayerObserver;
    use crate::runtime_impl::TokioTime;
    use crate::session::{SubscribeOptions, TokioSession};
    use wz_session_core::sample::EncodingHint;
    use wz_session_core::sink::SampleView;

    let (actions, _driver) = crate::test_fixtures::recording_actions();
    let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
    let clock = Arc::new(TokioTime::new());
    let session = TokioSession::new(actions, observer, clock);

    /// One live sample: `(payload, encoding packed_id, attachment)`.
    type LiveSample = (Vec<u8>, Option<u32>, Option<Vec<u8>>);

    let seen: Arc<Mutex<Vec<LiveSample>>> = Arc::new(Mutex::new(Vec::new()));
    let s = Arc::clone(&seen);
    let _rec = session
        .declare_subscriber(
            "demo/data",
            SubscribeOptions::default(),
            move |v: &dyn SampleView| {
                s.lock().expect("live recorder poisoned").push((
                    v.payload().to_vec(),
                    v.encoding().map(|e| e.packed_id),
                    v.attachment().map(<[u8]>::to_vec),
                ));
            },
        )
        .expect("live recorder subscribes");

    let publisher = AdvancedPublisher::declare(
        &session,
        "demo/data",
        AdvancedPublisherOptions::default(),
        vec![0x09],
    )
    .expect("advanced publisher declares");

    publisher
        .put_with(
            &[0xAA],
            AdvancedPutOptions::default()
                .with_encoding(EncodingHint {
                    packed_id: 0x0B,
                    schema: None,
                })
                .with_attachment(b"side-band".to_vec()),
        )
        .expect("advanced put with metadata");
    publisher.put(&[0xBB]).expect("advanced put");

    let got = seen.lock().expect("live recorder poisoned").clone();
    assert_eq!(
        got,
        vec![
            (vec![0xAA], Some(0x0B), Some(b"side-band".to_vec())),
            (vec![0xBB], None, None),
        ],
        "the live sample carries the metadata put_with was given, and a \
         plain put carries neither",
    );
}

/// R311y85 — the heartbeat beacon emits the publisher's last published sn on
/// its `@adv` KE. A plain subscriber on the `@adv/pub/**` namespace records
/// beacons; `emit_heartbeat_once` (the deterministic core the timer loops)
/// publishes one, and its payload decodes to `last_sn` (= seqnum-1). The
/// publisher is declared WITHOUT a heartbeat period (no background task -> no
/// tokio runtime needed); the on-demand seam drives the same emit.
#[cfg(all(
    feature = "ext-pubsub-sample-miss-detection",
    feature = "declare-subscriber",
    feature = "pubsub-allow-loop"
))]
#[test]
fn heartbeat_beacon_emits_last_sn_on_adv_ke() {
    use std::sync::Mutex;

    use crate::observer::ApplicationLayerObserver;
    use crate::runtime_impl::TokioTime;
    use crate::session::{SubscribeOptions, TokioSession};
    use wz_session_core::serde_codec::z_deserialize;
    use wz_session_core::sink::SampleView;

    let (actions, _driver) = crate::test_fixtures::recording_actions();
    let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
    let clock = Arc::new(TokioTime::new());
    let session = TokioSession::new(actions, observer, clock);

    let beacons = Arc::new(Mutex::new(Vec::<(String, Vec<u8>)>::new()));
    let b = Arc::clone(&beacons);
    let _hb_rec = session
        .declare_subscriber(
            "demo/data/@adv/pub/**",
            SubscribeOptions::default(),
            move |v: &dyn SampleView| {
                b.lock()
                    .unwrap()
                    .push((v.keyexpr().to_string(), v.payload().to_vec()))
            },
        )
        .expect("beacon recorder subscribes");

    let publisher = AdvancedPublisher::declare(
        &session,
        "demo/data",
        AdvancedPublisherOptions::default(),
        vec![0x09],
    )
    .expect("advanced publisher declares");

    // Nothing published yet -> no beacon.
    assert!(
        !publisher.emit_heartbeat_once(),
        "no beacon before any sample is published"
    );
    for v in 0u8..3 {
        publisher.put(&[v]).expect("advanced put");
    }
    // seqnum = 3 -> last published sn = 2.
    assert!(publisher.emit_heartbeat_once(), "beacon emitted after puts");

    let got = beacons.lock().unwrap().clone();
    let last = got.last().expect("a beacon was recorded");
    assert!(
        last.0.starts_with("demo/data/@adv/pub/"),
        "beacon published on the @adv KE, got {}",
        last.0
    );
    assert_eq!(
        z_deserialize::<u32>(&last.1).unwrap(),
        2,
        "the beacon carries the last published sn = 2"
    );
}

/// R311y85 composed PRODUCER->CONSUMER heartbeat recovery e2e: a real
/// producer's beacon drives a real consumer's recovery. The publisher
/// publishes 0,1,2 (cached) BEFORE the subscriber exists, so the
/// heartbeat-recovering subscriber is a LATE JOINER that genuinely missed
/// them live (last_delivered = None — a faithful in-loopback model of loss).
/// The producer's beacon (last sn = 2) fires the consumer's heartbeat sub ->
/// a bounded `_sn=0..2` GET -> the cache refills the whole stream. Co-compiles
/// the producer (sample-miss-detection) + consumer (advanced-recovery) atoms.
#[cfg(all(
    feature = "ext-pubsub-sample-miss-detection",
    feature = "ext-pubsub-advanced-recovery",
    feature = "pubsub-allow-loop"
))]
#[test]
fn composed_producer_beacon_drives_late_joiner_recovery() {
    use std::sync::Mutex;

    use crate::advanced_subscriber::{
        AdvancedSubscriber, AdvancedSubscriberOptions, Miss, RecoveryConfig,
    };
    use crate::observer::ApplicationLayerObserver;
    use crate::runtime_impl::TokioTime;
    use crate::session::TokioSession;
    use wz_session_core::locality::Locality;
    use wz_session_core::sample::Sample;

    let (actions, _driver) = crate::test_fixtures::recording_actions();
    let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
    let clock = Arc::new(TokioTime::new());
    let session = TokioSession::new(actions, observer, clock);

    // A real publisher with a cache deep enough to hold the whole stream
    // (the Default cache depth is 1) + miss-detection. Publish 0,1,2 BEFORE
    // the subscriber exists -> it never saw them live.
    let publisher = AdvancedPublisher::declare(
        &session,
        "demo/data",
        adv_options! {
            sequencing: Sequencing::SequenceNumber,
            cache: Some(CacheConfig {
                max_samples: 8,
                ..CacheConfig::default()
            }),
            publisher_detection: true,
            sample_miss_detection: MissDetectionConfig::default(),
            ..AdvancedPublisherOptions::default()
        },
        vec![0x09],
    )
    .expect("advanced publisher declares");
    publisher.put(&[0xA0]).expect("put 0");
    publisher.put(&[0xA1]).expect("put 1");
    publisher.put(&[0xA2]).expect("put 2"); // cache {0,1,2}, seqnum = 3

    let delivered = Arc::new(Mutex::new(Vec::<u8>::new()));
    let misses = Arc::new(Mutex::new(0usize));
    let d = Arc::clone(&delivered);
    let m = Arc::clone(&misses);
    let _sub = AdvancedSubscriber::declare_with_options_and_miss_listener(
        &session,
        "demo/data",
        AdvancedSubscriberOptions::new()
            .with_recovery(RecoveryConfig::new().with_heartbeat())
            .with_get_locality(Locality::SessionLocal),
        move |sample: Sample| d.lock().unwrap().push(sample.payload[0]),
        move |_miss: Miss| *m.lock().unwrap() += 1,
    )
    .expect("late-joiner heartbeat-recovering subscriber declares");

    // The producer's heartbeat beacon (last sn = 2) -> the consumer's
    // heartbeat sub -> bounded _sn=0..2 GET (last_delivered None) -> refill.
    assert!(publisher.emit_heartbeat_once(), "producer beacon emitted");

    assert_eq!(
        *delivered.lock().unwrap(),
        vec![0xA0, 0xA1, 0xA2],
        "the late joiner recovered the full cached stream via the producer's beacon"
    );
    assert_eq!(
        *misses.lock().unwrap(),
        0,
        "the beacon-driven recovery filled every hole -> no Miss"
    );
}

/// R311y87 (review C1) regression: a degenerate `max_samples == 0` cache must
/// not hang on push. Pre-fix `while ring.len() >= 0 { pop_front }` spins
/// forever (the empty-ring pop never reduces len) while holding the ring
/// mutex; the `if`-evict bounds it at one. The test COMPLETING is the proof
/// of no-hang; the retained count is the zenoh-faithful degenerate 1.
#[test]
fn cache_max_samples_zero_does_not_hang() {
    use crate::observer::ApplicationLayerObserver;
    use crate::runtime_impl::TokioTime;
    use crate::session::TokioSession;

    let (actions, _driver) = crate::test_fixtures::recording_actions();
    let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
    let clock = Arc::new(TokioTime::new());
    let session = TokioSession::new(actions, observer, clock);

    let publisher = AdvancedPublisher::declare(
        &session,
        "demo/data",
        adv_options! {
            sequencing: Sequencing::SequenceNumber,
            cache: Some(CacheConfig {
                max_samples: 0,
                ..CacheConfig::default()
            }),
            publisher_detection: true,
            sample_miss_detection: MissDetectionConfig::default(),
            ..AdvancedPublisherOptions::default()
        },
        vec![0x01],
    )
    .expect("advanced publisher declares");
    for v in 0u8..3 {
        publisher
            .put(&[v])
            .expect("put into a 0-depth cache must not hang");
    }
    assert_eq!(
        publisher.cache().map(|c| c.len()),
        Some(1),
        "a 0-depth cache degenerately retains exactly one (if-evict, zenoh-faithful)"
    );
}

/// Whether a frame beyond `after` reaches the link within a few seconds. The beacon is a
/// task on the process's own `net` runtime, so its emission is a thing that happens on
/// ANOTHER thread, and the only honest way to ask whether it did is to look for its frame.
#[cfg(feature = "ext-pubsub-sample-miss-detection")]
fn a_frame_follows(driver: &crate::test_fixtures::RecordingLinkDriver, after: usize) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while driver.frame_count() <= after && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    driver.frame_count() > after
}

/// R3064 -- declaring an advanced publisher with a heartbeat beacon OFF a tokio runtime
/// DECLARES, and the beacon is emitted. This `#[test]` runs outside any runtime.
///
/// R311y90 asserted the opposite (a refusal with a variant of its own) because the beacon
/// was a bare `tokio::spawn`, which panics without a runtime. R2366 moved the task onto the
/// process's `net` runtime, as upstream spawns it, and the refusal outlived its reason: a C
/// program declares from its own thread, which is never inside one, so the in-process plane
/// of a C session refused a declaration upstream accepts, and the refusal was swallowed. The
/// witness that the claim is TRUE is the frame: a declaration that returned `Ok` and
/// spawned nothing would pass an assertion on the result alone.
#[cfg(feature = "ext-pubsub-sample-miss-detection")]
#[test]
fn declare_with_heartbeat_off_runtime_declares_and_beacons() {
    use std::time::Duration;

    use crate::observer::ApplicationLayerObserver;
    use crate::runtime_impl::TokioTime;
    use crate::session::TokioSession;

    let (actions, driver) = crate::test_fixtures::recording_actions();
    let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
    let clock = Arc::new(TokioTime::new());
    let session = TokioSession::new(actions, observer, clock);

    let publisher = AdvancedPublisher::declare(
        &session,
        "demo/data",
        adv_options! {
            sequencing: Sequencing::SequenceNumber,
            cache: None,
            publisher_detection: false,
            sample_miss_detection: MissDetectionConfig::default()
                .heartbeat(Duration::from_millis(50)),
            ..AdvancedPublisherOptions::default()
        },
        vec![0x09],
    )
    .expect("a heartbeat declares off a tokio runtime: the beacon needs none");
    // The beacon states the last sequence number, and says nothing before there is one.
    publisher.put(b"sample").expect("the first put publishes");
    let after_put = driver.frame_count();
    assert!(
        a_frame_follows(&driver, after_put),
        "the beacon was never emitted: the declaration returned Ok and spawned nothing"
    );
}

/// R2558 — ASKING FOR MISS DETECTION SETS THE SEQUENCING, witnessed
/// through behaviour rather than by reading the field back.
///
/// A caller who asks for a heartbeat while naming `Sequencing::None` used
/// to get a publisher that declared fine, published fine and NEVER
/// BEACONED: `heartbeat_spawn_params` gates on `(state_publisher,
/// sequencing)` and yielded `None`, so nothing spawned and nothing said so.
/// Upstream cannot reach that state at all — its `sample_miss_detection`
/// builder assigns `Sequencing::SequenceNumber` as its first statement and
/// its `Sequencing` is `pub(crate)`, so the mode is never a user choice.
///
/// THE DISCRIMINATOR IS THE BEACON ITSELF. Until R3064 it was the spawn
/// attempt (off a tokio runtime a beacon spawn failed with `NoRuntime`, so
/// "did the request win?" was observable without waiting on a timer), but
/// that refusal was a precondition R2366 had already made false, and the
/// test above says why it went. A publisher whose request lost declares Ok
/// and emits no beacon, so the frame is the thing to look for, and the wait
/// is the price of looking at a task on another runtime.
///
/// `Sequencing::None` and not `Timestamp` on purpose: `Timestamp` carries
/// its own precondition (`TimestampingDisabled` on a non-stamping node), so
/// it could fail for a reason that has nothing to do with this coercion.
#[cfg(feature = "ext-pubsub-sample-miss-detection")]
#[test]
fn a_miss_detection_request_overrides_the_sequencing_the_caller_named() {
    use std::time::Duration;

    use crate::observer::ApplicationLayerObserver;
    use crate::runtime_impl::TokioTime;
    use crate::session::TokioSession;

    let (actions, driver) = crate::test_fixtures::recording_actions();
    let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
    let clock = Arc::new(TokioTime::new());
    let session = TokioSession::new(actions, observer, clock);

    let publisher = AdvancedPublisher::declare(
        &session,
        "demo/data",
        adv_options! {
            // The caller names the mode that CANNOT carry miss detection.
            sequencing: Sequencing::None,
            cache: None,
            publisher_detection: false,
            sample_miss_detection: MissDetectionConfig::default()
                .heartbeat(Duration::from_millis(50)),
            ..AdvancedPublisherOptions::default()
        },
        vec![0x09],
    )
    .expect("the declaration is valid whichever sequencing the caller named");
    publisher.put(b"sample").expect("the first put publishes");
    let after_put = driver.frame_count();
    assert!(
        a_frame_follows(&driver, after_put),
        "the miss-detection request must win over the named sequencing, so a beacon IS \
         emitted; before R2558 this declared Ok and silently never beaconed"
    );
}

/// R2559 — an ill-formed derived `@adv` expression is refused AT DECLARE,
/// and the verdict is the same whichever decorations the publisher asked
/// for.
///
/// THE DEFECT THIS PINS WAS A DISAGREEMENT, NOT AN ABSENCE, and that is why
/// the assertion is a pair. wz already refused `demo/foo?bar` when
/// `publisher_detection` was on, because `declare_token` validates what it
/// is handed. With detection off and a heartbeat on — the configuration
/// THIS atom is about — the same base was MEASURED to declare `Ok`, to
/// `put` `Ok`, and to answer `true` from `emit_heartbeat_once` while every
/// beacon was dropped by `let _ = session.publish(..)`. One string, two
/// configurations, two answers, and the wrong one was the silent one.
///
/// So what is asserted is the AGREEMENT. A test that pinned only the
/// beacon-only arm would pass just as well on a build that had moved the
/// disagreement rather than removed it.
///
/// The three bases violate the chunk grammar three different ways, so what
/// refuses them is the seam's own checker rather than one hard-coded
/// character. A fourth case below is CANONICAL and still unsafe, which is
/// what pins the checker's identity rather than merely its effect.
#[cfg(feature = "ext-pubsub-sample-miss-detection")]
#[tokio::test]
async fn an_ill_formed_adv_keyexpr_is_refused_at_declare_in_every_configuration() {
    use std::time::Duration;

    use crate::observer::ApplicationLayerObserver;
    use crate::runtime_impl::TokioTime;
    use crate::session::TokioSession;

    let (actions, _driver) = crate::test_fixtures::recording_actions();
    let session = TokioSession::new(
        actions,
        Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new())),
        Arc::new(TokioTime::new()),
    );

    // No cache and no token: on this arm NOTHING else looks at the derived
    // expression, which is exactly what made the old silence possible.
    let beacon_only = || {
        adv_options! {
            sequencing: Sequencing::SequenceNumber,
            cache: None,
            publisher_detection: false,
            sample_miss_detection: MissDetectionConfig::default().heartbeat(Duration::from_millis(100)),
            ..AdvancedPublisherOptions::default()
        }
    };
    // The arm that already refused, kept as the comparison rather than
    // assumed: it is the half of the pair that gives the other one a
    // subject.
    let detection_on = || {
        adv_options! {
            sequencing: Sequencing::SequenceNumber,
            cache: None,
            publisher_detection: true,
            sample_miss_detection: MissDetectionConfig::default(),
            ..AdvancedPublisherOptions::default()
        }
    };

    for base in ["demo/foo?bar", "demo//data", "demo/data/"] {
        assert!(
            matches!(
                AdvancedPublisher::declare(&session, base, beacon_only(), vec![0x09u8]),
                Err(AdvancedPublisherError::InvalidAdvKeyexpr(_))
            ),
            "a beacon-only publisher on {base:?} must be refused at declare; \
             before R2559 it declared Ok and then beaconed into nothing for \
             the life of the process"
        );
        assert!(
            AdvancedPublisher::declare(&session, base, detection_on(), vec![0x09u8]).is_err(),
            "the detection-on arm must keep refusing {base:?} — the two \
             configurations are being asked about ONE string"
        );
    }

    // ANTI-VACUITY 1: a well-formed base still declares BOTH ways round, so
    // the refusal is about the expression and not about beaconing (or about
    // detection).
    assert!(
        AdvancedPublisher::declare(&session, "demo/data", beacon_only(), vec![0x09u8]).is_ok(),
        "a well-formed base stays declarable on the beacon-only arm"
    );
    assert!(
        AdvancedPublisher::declare(&session, "demo/data", detection_on(), vec![0x09u8]).is_ok(),
        "a well-formed base stays declarable on the detection arm"
    );

    // THE ARM THAT CAUGHT THIS CHECK'S OWN FIRST DRAFT, and the reason it is
    // a separate case rather than a fourth string in the loop above: it is
    // CANONICAL. `demo/**/c/*` parses fine, so a canon-only predicate
    // accepts it — and MEASURED, the first draft of this check did exactly
    // that while the detection arm refused with
    // `PicoBugThreeFamily { offending_chunk: "*" }`. The defect this test
    // exists to pin had survived inside a narrower band.
    //
    // ⚠ WHAT THAT BAND COSTS IS STATED AS MEASURED, NOT AS THE SCARIER
    // VERSION. The first draft of THIS COMMENT said such a keyexpr "aborts a
    // pico peer", which overstates it. `assert(false)` sits inside
    // `vendor/zenoh-pico/src/session/keyexpr.c` @ `zp_keyexpr_canon_status_t _z_keyexpr_canonize(char *start, size_t *len) {`,
    // and every caller of that function is an application-facing API entry
    // (`z_keyexpr_canonize`, its null-terminated twin, the two
    // `*_autocanonize` constructors, and `z_keyexpr_join`). NO receive path
    // calls it. So arrival alone does not abort: the peer aborts when its
    // APPLICATION canonizes or joins the keyexpr it was handed, which is an
    // ordinary thing for an application to do with a key it received.
    //
    // It is asserted BOTH WAYS for the same reason as the loop: what must
    // hold is the agreement, not either arm's value.
    for opts in [beacon_only(), detection_on()] {
        assert!(
            AdvancedPublisher::declare(&session, "demo/**/c/*", opts, vec![0x09u8]).is_err(),
            "a base carrying the R299 bug-3 shape must be refused in EVERY \
             configuration: it is canonical, so only the seam's own \
             `check_outbound_keyexpr_pico_safe` catches it, and wz must not \
             emit a shape whose canonizer a peer application aborts on"
        );
    }

    // ANTI-VACUITY 2 — THE BOUNDARY, which a population of well-formed and
    // ill-formed bases alone would never grade: the predicate is "parses",
    // NOT "is already canonical". MEASURED: `canonize_keyexpr("demo/$*/data")`
    // answers `Ok("demo/*/data")`, so input != canon while the grammar
    // holds, and `declare_token` accepts that base today. Tightening this
    // check to an equality would refuse it here and diverge the two legs
    // again, in the opposite direction from the defect above.
    //
    // ⚠ ASSERTED ON BOTH ARMS ON PURPOSE. The claim above is about what the
    // DECLARE seam accepts, so testing only the beacon arm would leave that
    // half INFERRED — and it WAS inferred, from a sibling input
    // (`demo/$*$*/data`, which collapses to this one) rather than from this
    // string. The second arm is what makes "the two legs agree here too" a
    // measurement instead.
    for opts in [beacon_only(), detection_on()] {
        assert!(
            AdvancedPublisher::declare(&session, "demo/$*/data", opts, vec![0x09u8]).is_ok(),
            "a valid-but-non-canonical base stays declarable in EVERY \
             configuration: the wire suffix is emitted verbatim, so \
             canonizing it here would rewrite a keyexpr the caller and the \
             subscriber both spell the other way"
        );
    }
}

/// R2485 — build a session whose node clock is on or off, by the ONE input
/// that decides it: the role `timestamping.enabled` is resolved against.
/// zenoh's shipped default is `{ router: true, peer: false, client: false }`,
/// so the role IS the switch and neither arm has to reach past the public
/// constructor to set it.
fn session_with_role(whatami: wz_codecs::whatami::WhatAmI) -> crate::session::TokioSession {
    use crate::observer::ApplicationLayerObserver;
    use crate::runtime_impl::TokioTime;
    use crate::session::TokioSession;

    let mut params = wz_runtime_tokio_test_support::fixture_session_init_params();
    params.whatami = whatami;
    let (actions, _driver) = crate::test_fixtures::recording_actions_with_params(params);
    TokioSession::new(
        actions,
        Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new())),
        Arc::new(TokioTime::new()),
    )
}

/// R2619 — publisher-detection metadata reaches the `@adv` key expression,
/// and a chunk that would not survive the wire is REFUSED rather than sent.
///
/// wz hardcoded the `_` chunk where upstream offers
/// `zenoh-ext/src/advanced_publisher.rs` @ `pub fn publisher_detection_metadata<TryIntoKeyExpr>(mut self, meta: TryIntoKeyExpr) -> Self`.
/// The subscriber side of this crate has taken a `meta` since it was
/// written, so the publisher was the odd one out.
///
/// THE REFUSAL ARM IS THE ONE THAT MATTERS. Until this field existed the
/// derived expression was well-formed BY CONSTRUCTION — every chunk was a
/// validated base, a fixed literal, or hex — so the declare path's
/// canonisation check guarded something that could not fail. Giving a
/// caller a chunk removes that guarantee, and the second arm is what proves
/// the check now has a subject instead of being decoration.
#[test]
fn publisher_detection_metadata_rides_the_adv_keyexpr_and_a_bad_chunk_is_refused() {
    use crate::observer::ApplicationLayerObserver;
    use crate::runtime_impl::TokioTime;
    use crate::session::TokioSession;

    let new_session = || {
        let (actions, _driver) = crate::test_fixtures::recording_actions();
        let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
        let clock = Arc::new(TokioTime::new());
        (TokioSession::new(actions, observer, clock), _driver)
    };
    let opts = |meta: Option<&str>| {
        adv_options! {
            cache: None,
            publisher_detection: false,
            publisher_detection_metadata: meta.map(str::to_owned),
            ..AdvancedPublisherOptions::default()
        }
    };

    // ARM 1 + its CONTROL, at the derivation itself: the meta SUBSTITUTES
    // for the `_` chunk, and without it the chunk is still `_`. The pair is
    // what makes arm 1 about the metadata rather than about any tail.
    let with_meta =
        wz_ext_pubsub::advanced_ke::publisher_adv_ke("demo/data", "07", "1", Some("room/kitchen"));
    assert!(
        with_meta.ends_with("/room/kitchen"),
        "the meta replaces the `_` chunk; got {with_meta}"
    );
    let without = wz_ext_pubsub::advanced_ke::publisher_adv_ke("demo/data", "07", "1", None);
    assert!(
        without.ends_with("/_"),
        "without metadata the routing-workaround chunk stands; got {without}"
    );

    // ...and a well-formed chunk still DECLARES, so arm 2's refusal is
    // about the chunk rather than about the field existing.
    let (session, _d) = new_session();
    AdvancedPublisher::declare(
        &session,
        "demo/data",
        opts(Some("room/kitchen")),
        vec![0x07],
    )
    .expect("a well-formed meta chunk declares");

    // ARM 2: a chunk that cannot go on the wire is REFUSED at declare.
    let (session, _d) = new_session();
    assert!(
        matches!(
            AdvancedPublisher::declare(&session, "demo/data", opts(Some("bad?chunk")), vec![0x07]),
            Err(AdvancedPublisherError::InvalidAdvKeyexpr(_))
        ),
        "a caller chunk that breaks the derived expression must be refused, \
         not published"
    );
}

/// R2619 — the publisher-handle surface upstream exposes and wz did not:
/// identity, key expression, matching status, and an undeclare.
///
/// THE LOAD-BEARING ASSERTION IS THE MATCHING ONE, and it is not about the
/// method existing. Declaring the wrapped publisher is what asks the
/// neighbour for the matching subscriber declarations (R2577); before this
/// round an advanced publisher asked NOTHING, so a status poll read a
/// registry nobody had filled. The arm below pins that the delegate was
/// really declared, by observing the Interest the declare put on the wire —
/// a test that only called the method would pass on a handle that asked
/// nobody, which is exactly the state this round found.
///
/// `id()` is asserted against the SAME `(zid, eid)` the publisher stamps
/// into a sample's `SourceInfo`, because a global id that disagreed with
/// the origin its own samples carry would be a second identity rather than
/// an accessor.
#[test]
fn the_publisher_surface_reports_identity_and_asks_for_matching_declarations() {
    use crate::observer::ApplicationLayerObserver;
    use crate::runtime_impl::TokioTime;
    use crate::session::TokioSession;

    let (actions, _driver) = crate::test_fixtures::recording_actions();
    let observer = Arc::new(crate::sync::PlainMutex::new(ApplicationLayerObserver::new()));
    let clock = Arc::new(TokioTime::new());
    let session = TokioSession::new(actions, observer, clock);

    let publisher = AdvancedPublisher::declare(
        &session,
        "demo/data",
        adv_options! {
            cache: None,
            publisher_detection: false,
            ..AdvancedPublisherOptions::default()
        },
        vec![0x07],
    )
    .expect("advanced publisher declares against the test link");

    // IDENTITY: the keyexpr and the (zid, eid) pair are reachable at all.
    assert_eq!(publisher.keyexpr(), "demo/data");
    let (zid, eid) = publisher.id();
    assert_eq!(
        zid,
        &[0x07u8][..],
        "the id carries the zid it was declared with"
    );

    // ...and the eid AGREES with what its samples stamp as their origin.
    publisher.put(b"x").expect("advanced put publishes");
    assert_eq!(
        eid,
        publisher.eid(),
        "id()'s eid is the one SourceInfo carries, not a second identity"
    );

    // MATCHING: the delegate really ASKED. The id is read out of the
    // SESSION's own interest table, which holds one only because declaring
    // the wrapped publisher took a reference on this keyexpr's SUBSCRIBERS
    // Interest (R2577). This is the assertion that a handle asking nobody
    // would fail -- calling `get_matching_status()` and discarding it would
    // not, which is the state this round found.
    #[cfg(all(feature = "session-matching", feature = "declare-interest"))]
    {
        assert!(
            session
                .matching_interest_id(
                    crate::session::MatchingPlane::Subscribers,
                    publisher.keyexpr(),
                )
                .is_some(),
            "declaring an advanced publisher must take a reference on the \
             SUBSCRIBERS Interest for its keyexpr, or its matching status \
             reads a registry nobody was asked to fill"
        );
        let _ = publisher.get_matching_status();
    }

    // UNDECLARE consumes the handle; after it the interest reference is
    // released, which is the observable half of the teardown.
    publisher.undeclare();
    #[cfg(all(feature = "session-matching", feature = "declare-interest"))]
    assert!(
        session
            .matching_interest_id(crate::session::MatchingPlane::Subscribers, "demo/data")
            .is_none(),
        "undeclare drops the wrapped publisher, so the last reference on \
         the Interest goes with it"
    );
}

/// R2485 — upstream refuses to construct an advanced publisher whose
/// sequencing is `Timestamp` when the session has no HLC
/// (`zenoh-ext/src/advanced_publisher.rs` @ `if conf.session.hlc().is_none() {`),
/// and wz now answers the same on the state it models identically.
///
/// THE ARMS ARE THE POINT. A refusal test alone would pass on a build that
/// refused EVERYTHING, so the two arms beside it are what give this one a
/// subject: the same request succeeds on a stamping node, and the sequencing
/// upstream's own default carries (`None` — its builder promotes to
/// `Timestamp` only when a cache is attached) still succeeds on the
/// non-stamping one. That second arm is not decoration: wz's C ABI used to
/// hand `Timestamp` to every publisher declared with default options, so
/// without it this precondition would have refused the whole C surface.
#[test]
fn timestamp_sequencing_is_refused_on_a_node_that_does_not_stamp() {
    use wz_codecs::whatami::WhatAmI;

    let opts = |named| {
        adv_options! {
            sequencing: named,
            cache: None,
            publisher_detection: false,
            sample_miss_detection: MissDetectionConfig::default(),
            ..AdvancedPublisherOptions::default()
        }
    };

    // A Peer does not stamp under zenoh's shipped default.
    let peer = session_with_role(WhatAmI::Peer);
    assert!(
        !peer.node_hlc().is_stamping(),
        "the fixture's premise: a Peer resolves timestamping.enabled to false"
    );
    assert!(
        matches!(
            AdvancedPublisher::declare(&peer, "demo/ts", opts(Sequencing::Timestamp), vec![1]),
            Err(AdvancedPublisherError::TimestampingDisabled)
        ),
        "Timestamp sequencing on a non-stamping node is refused, not degraded"
    );

    // ANTI-VACUITY 1: the same request on a node that DOES stamp is accepted,
    // so the refusal is about the clock and not about the sequencing mode.
    //
    // ⚠ GATED ON `time-hlc`, AND MEASURED RATHER THAN ASSUMED: without that
    // feature `NodeHlc::is_stamping` answers false for EVERY role, so this
    // arm's premise ("a Router stamps") is not merely unproven there, it is
    // FALSE -- the first draft of this test asserted it unconditionally and
    // went red on exactly that line while the two arms below passed. On such
    // a build "Timestamp is never accepted" is the honest behaviour, and the
    // `Sequencing::None` arm below is what keeps the refusal from being
    // blanket.
    #[cfg(feature = "time-hlc")]
    {
        let router = session_with_role(WhatAmI::Router);
        assert!(
            router.node_hlc().is_stamping(),
            "the fixture's premise: a Router resolves timestamping.enabled to true"
        );
        assert!(
            AdvancedPublisher::declare(&router, "demo/ts", opts(Sequencing::Timestamp), vec![1])
                .is_ok(),
            "a stamping node accepts Timestamp sequencing"
        );
    }

    // ANTI-VACUITY 2: upstream's own default sequencing still declares on the
    // non-stamping node, which is what keeps the C ABI's NULL-options path
    // alive.
    assert!(
        AdvancedPublisher::declare(&peer, "demo/none", opts(Sequencing::None), vec![1]).is_ok(),
        "Sequencing::None needs no clock and must stay declarable"
    );
}
