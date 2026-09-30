// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! An advanced subscriber is declared on a face however that face arrives, and
//! names itself the same on all of them.
//!
//! A C program declares an advanced subscriber and a peer is connected to the
//! session either BEFORE (the declaration goes out when the session declares it)
//! or AFTER (the registry replays it when the face comes up). The subscriber is
//! a sequence of entities — a subscription, a history query, late-publisher and
//! heartbeat subscriptions, a detection token — and the pico ABI declares a key
//! for each of them as it goes, which takes the very registry lock the replay
//! runs under. Both arrivals therefore have to declare OUTSIDE that lock, and
//! both have to name the detection token with the ONE identity the C handle
//! reports, which a replay (a different plain subscription id on every face)
//! has no reason to reproduce by itself.
//!
//! ## What is measured
//!
//! The far end is a wz-native peer that asks for the liveliness tokens under
//! one prefix, current ones included, and reports each token it is told about:
//!
//! - the subscriber declared BEFORE the peer dialled arrives, through the
//!   replay, as a token under `<key>/@adv/sub/<zid>/<eid>/_`;
//! - the one declared AFTER arrives the same way, through the live declaration;
//! - in both, `<eid>` is the id `ze_advanced_subscriber_id` reports, and the two
//!   subscribers' ids differ;
//! - undeclaring either retracts its token.
//!
//! A deadlock in either path shows as the peer never hearing the token, which is
//! why every wait below has a budget and a message naming what it waited for.
//!
//! ## What keeps the assertions non-vacuous
//!
//! Each token is asserted to ARRIVE before its identity is compared, and the
//! two subscribers are compared against each other as well as against their own
//! handles: a token that named the face's own plain subscription id would agree
//! with neither.

use std::ffi::{c_void, CString};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use wz_capi_pico::liveliness::{z_liveliness_declare_token, z_owned_liveliness_token_t};

use wz_capi_pico::advanced::{
    ze_advanced_subscriber_loan, ze_advanced_subscriber_move,
    ze_advanced_subscriber_options_default, ze_advanced_subscriber_options_t,
    ze_declare_advanced_subscriber, ze_owned_advanced_subscriber_t,
    ze_undeclare_advanced_subscriber,
};
use wz_capi_pico::{
    z_close, z_closure_sample, z_closure_sample_move, z_config_default, z_config_loan_mut,
    z_config_move, z_loaned_sample_t, z_open, z_owned_closure_sample_t, z_owned_config_t,
    z_owned_session_t, z_session_drop, z_session_loan, z_session_loan_mut, z_session_move,
    z_view_keyexpr_from_str, z_view_keyexpr_loan, z_view_keyexpr_t, ze_advanced_subscriber_id,
    zp_config_insert, Z_CONFIG_LISTEN_KEY, Z_OK,
};

use wz_runtime_tokio::declare::LivelinessSampleKind;
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{LivelinessSubscriberOptions, TokioSession};
use wz_runtime_tokio::session_glue::{
    drive_session_until_terminal, IterationEvent, SessionInitParams, SessionTimeouts, SigningKey,
    WhatAmI,
};
use wz_runtime_tokio::session_open::{
    dial_endpoint, initiate_and_open_session, DialConfig, OpenedSessionParts, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::sync::Mutex as WzMutex;
use wz_runtime_tokio_test_support::free_port;

const PREFIX: &str = "demo/forms";
const PLAIN: &str = "demo/forms/plain";
const REPLAYED: &str = "demo/forms/replayed";
const LIVE: &str = "demo/forms/live";
const FILLER: &str = "demo/forms/filler";

/// What the native peer was told about a liveliness token.
type Heard = (LivelinessSampleKind, String);

unsafe extern "C" fn on_sample(_sample: *const z_loaned_sample_t, _ctx: *mut c_void) {}

fn init_params(whatami: WhatAmI) -> SessionInitParams {
    let mut zid = vec![0u8; 16];
    getrandom::getrandom(&mut zid).expect("OS entropy");
    SessionInitParams {
        version: 0x09,
        whatami,
        zid,
        seq_num_res: 2,
        req_id_res: 2,
        batch_size: 65535,
        lease_ms: 10_000,
        initial_sn: 0,
        cookie: Vec::new(),
        tx_queue: wz_runtime_tokio::session_glue::TxQueueConf::default(),
        cookie_signing_key: SigningKey::new(vec![0xAB; 32]).expect("32-byte key"),
    }
}

/// A wz-native peer that dials the C listener, asks for the tokens under
/// [`PREFIX`] — the plain ones and the detection ones (current ones too, so a
/// token declared before it arrived is told to it) — reports what it hears, and
/// drives until told to stop.
fn native_peer(
    endpoint: String,
    heard: mpsc::Sender<Heard>,
    ready: mpsc::Sender<()>,
    stop: Arc<tokio::sync::Notify>,
) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    rt.block_on(async move {
        let clock = TokioTime::new();
        let dialed = dial_endpoint(&endpoint, &DialConfig::default())
            .await
            .expect("dial the C listener");
        let opened = initiate_and_open_session(
            dialed,
            init_params(WhatAmI::Client),
            clock,
            None,
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("handshake with the C listener");
        let OpenedSessionParts {
            mut engine,
            actions,
            inbound,
            writer_handle,
            ..
        } = opened.into_parts();

        let observer = Arc::new(WzMutex::new(ApplicationLayerObserver::new()));
        let session = TokioSession::new(actions.clone(), observer, Arc::new(clock));
        // Two subscriptions, because a `**` never matches a verbatim chunk (one
        // that opens with `@`): the detection tokens are under `@adv/sub`, and a
        // pattern that does not spell it out cannot see them.
        let _tokens: Vec<_> = [format!("{PREFIX}/*"), format!("{PREFIX}/*/@adv/sub/**")]
            .into_iter()
            .map(|pattern| {
                let heard = heard.clone();
                session
                    .declare_liveliness_subscriber(
                        pattern,
                        LivelinessSubscriberOptions::new().with_history(true),
                        move |sample| {
                            let _ = heard.send((sample.kind, sample.keyexpr.to_owned()));
                        },
                    )
                    .expect("declare the native liveliness subscriber")
            })
            .collect();

        let mut driver = inbound;
        let timeouts = SessionTimeouts::spec_defaults();
        let dispatch_session = session.clone();
        let mut dispatch =
            |event: IterationEvent<'_>| dispatch_session.dispatch_iteration_event(event);
        let _ = ready.send(());

        let pump = drive_session_until_terminal(
            &mut driver,
            &actions,
            &mut engine,
            None,
            &clock,
            &timeouts,
            &mut dispatch,
        );
        tokio::select! {
            _ = pump => {}
            _ = stop.notified() => {}
            _ = tokio::time::sleep(Duration::from_secs(60)) => {}
        }
        drop(writer_handle);
    });
}

/// # Safety
/// The returned session must be closed and dropped by the caller.
unsafe fn open_c_listener(port: u16) -> z_owned_session_t {
    let listen = CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    assert_eq!(
        zp_config_insert(
            z_config_loan_mut(&mut cfg),
            Z_CONFIG_LISTEN_KEY,
            listen.as_ptr()
        ),
        Z_OK
    );
    let mut zs: z_owned_session_t = std::mem::zeroed();
    assert_eq!(
        z_open(&mut zs, z_config_move(&mut cfg), std::ptr::null()),
        Z_OK
    );
    zs
}

/// Declare an advanced subscriber on `key` with every option that makes pico
/// declare an entity: history, late-publisher detection, heartbeat recovery and
/// detection. Returns the handle and the eid it reports.
///
/// # Safety
/// `zs` must be a live session.
unsafe fn declare_full(zs: &z_owned_session_t, key: &str) -> (ze_owned_advanced_subscriber_t, u32) {
    let key = CString::new(key).unwrap();
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, key.as_ptr()), Z_OK);

    let mut options: ze_advanced_subscriber_options_t = std::mem::zeroed();
    ze_advanced_subscriber_options_default(&mut options);
    options.history.is_enabled = true;
    options.history.detect_late_publishers = true;
    options.history.max_samples = 2;
    options.recovery.is_enabled = true;
    options.recovery.last_sample_miss_detection.is_enabled = true;
    options
        .recovery
        .last_sample_miss_detection
        .periodic_queries_period_ms = 0;
    options.subscriber_detection = true;

    let mut closure: z_owned_closure_sample_t = std::mem::zeroed();
    z_closure_sample(&mut closure, Some(on_sample), None, std::ptr::null_mut());
    let mut subscriber: ze_owned_advanced_subscriber_t = std::mem::zeroed();
    assert_eq!(
        ze_declare_advanced_subscriber(
            z_session_loan(zs),
            &mut subscriber,
            z_view_keyexpr_loan(&ke),
            z_closure_sample_move(&mut closure),
            &mut options,
        ),
        Z_OK,
        "the advanced subscriber on {key:?} was not declared"
    );
    let eid = ze_advanced_subscriber_id(ze_advanced_subscriber_loan(&subscriber)).eid;
    (subscriber, eid)
}

/// Declare an advanced subscriber on `key` with default options: a live
/// subscription and nothing else, so it declares no token.
///
/// # Safety
/// `zs` must be a live session.
unsafe fn declare_quiet(zs: &z_owned_session_t, key: &str) -> ze_owned_advanced_subscriber_t {
    let key = CString::new(key).unwrap();
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, key.as_ptr()), Z_OK);
    let mut options: ze_advanced_subscriber_options_t = std::mem::zeroed();
    ze_advanced_subscriber_options_default(&mut options);
    options.history.is_enabled = false;
    options.recovery.is_enabled = false;
    let mut closure: z_owned_closure_sample_t = std::mem::zeroed();
    z_closure_sample(&mut closure, Some(on_sample), None, std::ptr::null_mut());
    let mut subscriber: ze_owned_advanced_subscriber_t = std::mem::zeroed();
    assert_eq!(
        ze_declare_advanced_subscriber(
            z_session_loan(zs),
            &mut subscriber,
            z_view_keyexpr_loan(&ke),
            z_closure_sample_move(&mut closure),
            &mut options,
        ),
        Z_OK,
        "the quiet advanced subscriber on {key:?} was not declared"
    );
    subscriber
}

/// Wait for the peer to hear something `matches`, keeping everything it hears
/// for the failure message. `None` when the budget runs out.
fn hear(
    rx: &mpsc::Receiver<Heard>,
    log: &mut Vec<Heard>,
    budget: Duration,
    matches: impl Fn(&Heard) -> bool,
) -> Option<Heard> {
    let deadline = Instant::now() + budget;
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        match rx.recv_timeout(left) {
            Ok(heard) => {
                log.push(heard.clone());
                if matches(&heard) {
                    return Some(heard);
                }
            }
            Err(_) => return None,
        }
    }
    None
}

/// The `<eid>` of a detection token's key under `base`, when it is one:
/// `<base>/@adv/sub/<zid>/<eid>/_`.
fn detection_eid(base: &str, key: &str) -> Option<u32> {
    let tail = key.strip_prefix(base)?.strip_prefix("/@adv/sub/")?;
    let mut parts = tail.split('/');
    let _zid = parts.next()?;
    let eid = parts.next()?.parse().ok()?;
    (parts.next()? == "_" && parts.next().is_none()).then_some(eid)
}

/// One subscriber on a listening session and a native peer that dials it, the
/// subscriber declared before the peer dials (`declare_before_dial`, arriving
/// through the replay) or after it is connected (arriving through the live
/// declaration).
fn scenario(declare_before_dial: bool) {
    let (key, arrival) = if declare_before_dial {
        (REPLAYED, "replay onto the new face")
    } else {
        (LIVE, "live declaration on a face that is already up")
    };
    let port = free_port();
    let mut session = unsafe { open_c_listener(port) };

    // THE HARNESS'S OWN WITNESS: an ordinary token, declared before the peer
    // arrives, is told to it. Without this the silence of a failing replay below
    // could be the harness's (a peer that is never told of current tokens)
    // rather than the subscriber's.
    let plain_key = CString::new(PLAIN).unwrap();
    let mut plain_ke: z_view_keyexpr_t = unsafe { std::mem::zeroed() };
    let mut plain_token: z_owned_liveliness_token_t = unsafe { std::mem::zeroed() };
    unsafe {
        assert_eq!(
            z_view_keyexpr_from_str(&mut plain_ke, plain_key.as_ptr()),
            Z_OK
        );
        assert_eq!(
            z_liveliness_declare_token(
                z_session_loan(&session),
                &mut plain_token,
                z_view_keyexpr_loan(&plain_ke),
                std::ptr::null(),
            ),
            Z_OK
        );
    }

    // A subscriber that declares nothing of its own, made first, so the one under
    // test is not the session's first and its registry id is not the small number
    // a face's own first ids happen to be.
    let filler = unsafe { declare_quiet(&session, FILLER) };

    // Declared with NO peer connected, the registry records the subscriber and
    // replays it when the face comes up.
    let before = declare_before_dial.then(|| unsafe { declare_full(&session, key) });

    let (heard_tx, heard_rx) = mpsc::channel::<Heard>();
    let (ready_tx, ready_rx) = mpsc::channel::<()>();
    let stop = Arc::new(tokio::sync::Notify::new());
    let peer = {
        let stop = stop.clone();
        let endpoint = format!("tcp/127.0.0.1:{port}");
        std::thread::spawn(move || native_peer(endpoint, heard_tx, ready_tx, stop))
    };
    ready_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the native peer never reached Established");

    let mut log: Vec<Heard> = Vec::new();
    let show = |log: &Vec<Heard>| format!("{log:?}");

    assert!(
        hear(
            &heard_rx,
            &mut log,
            Duration::from_secs(10),
            |(kind, key)| { *kind == LivelinessSampleKind::Put && key == PLAIN }
        )
        .is_some(),
        "the peer was never told of an ordinary token declared before it arrived, so \
         this harness cannot hear a current token and the replay below would be silent \
         whatever the subscriber did. heard: {}",
        show(&log)
    );

    let (mut subscriber, eid) = before.unwrap_or_else(|| unsafe { declare_full(&session, key) });

    // THE ARRIVAL. The detection token is told to the peer.
    let token = hear(
        &heard_rx,
        &mut log,
        Duration::from_secs(10),
        |(kind, heard)| *kind == LivelinessSampleKind::Put && detection_eid(key, heard).is_some(),
    )
    .unwrap_or_else(|| {
        panic!(
            "the subscriber was never announced to the peer by its {arrival}: no detection \
             token reached it. heard: {}",
            show(&log)
        )
    });
    assert_eq!(
        detection_eid(key, &token.1),
        Some(eid),
        "the token names an identity other than the one the subscriber's handle reports \
         ({arrival}), so one subscriber is two things to two observers: {}",
        show(&log)
    );

    // Its retraction reaches the peer.
    unsafe {
        assert_eq!(
            ze_undeclare_advanced_subscriber(ze_advanced_subscriber_move(&mut subscriber)),
            Z_OK
        );
    }
    assert!(
        hear(
            &heard_rx,
            &mut log,
            Duration::from_secs(10),
            |(kind, heard)| { *kind == LivelinessSampleKind::Delete && *heard == token.1 }
        )
        .is_some(),
        "undeclaring the subscriber did not retract its token ({arrival}). heard: {}",
        show(&log)
    );

    stop.notify_one();
    peer.join().expect("native peer thread panicked");
    let mut filler = filler;
    unsafe {
        assert_eq!(
            ze_undeclare_advanced_subscriber(ze_advanced_subscriber_move(&mut filler)),
            Z_OK
        );
        z_close(z_session_loan_mut(&mut session), std::ptr::null());
        z_session_drop(z_session_move(&mut session));
    }
}

/// A subscriber declared before its peer connects is announced to it, by the
/// replay, under the identity its handle reports.
#[test]
fn an_advanced_subscriber_declared_before_its_peer_connects_is_announced_by_its_identity() {
    scenario(true);
}

/// The same for one declared after the peer is connected.
#[test]
fn an_advanced_subscriber_declared_after_its_peer_connects_is_announced_by_its_identity() {
    scenario(false);
}
