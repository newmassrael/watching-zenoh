// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! The replay cache through the C doors (`wz_ext_replay_publisher_*`,
//! `wz_ext_replay_subscriber_*`): three pico sessions in one process over loopback, a subscriber
//! that listens and two publishers that dial it at different times.
//!
//! What is held, in the build the test runs in: a publisher's ring reaches the subscriber, frame
//! by frame and in the order it was sent, as replies judged by the subscriber's receiver and
//! flagged as replays, and a live frame after them is flagged live; a second publisher that
//! appears later is asked in a round of its own, and what the first answers again (when the
//! session's `targeted-query` policy is off, so a get asks every publisher) is dropped as a
//! duplicate or stale rather than handed on; an empty cache answers the final alone and the
//! round goes live; the doors refuse what they cannot do by name. The files run alike under both
//! values of `replay-reply-shape`: under `segmented` every frame, answered or put, crosses as the
//! pieces of a synthetic segment profile and the subscriber joins them before it judges, so what
//! is handed on is the same. The order of each policy's two
//! values is held by the model tests of `wz-session-core` (`replay_subscriber`,
//! `replay_publisher`); here the build's own values are read and asserted. The profile is
//! synthetic.

#![cfg(all(feature = "replay-cache", feature = "engine-tokio", feature = "peer"))]

use std::ffi::{c_void, CStr, CString};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wz_app_frame::e2e_frame::{build, Values};
use wz_app_frame::e2e_profile::Profile;
use wz_capi_pico::e2e_receiver::{
    wz_ext_e2e_receiver_move, wz_ext_e2e_receiver_new, wz_ext_owned_e2e_receiver_t,
    WZ_EXT_E2E_FIRST, WZ_EXT_E2E_OK,
};
use wz_capi_pico::replay_publisher::*;
use wz_capi_pico::replay_subscriber::*;
use wz_capi_pico::result::{Z_EINVAL, Z_ERR_CONFIG_INVALID_VALUE, Z_ERR_INVALID};
use wz_capi_pico::{
    z_close, z_config_default, z_config_loan_mut, z_config_move, z_declare_publisher, z_open,
    z_owned_config_t, z_owned_publisher_t, z_owned_session_t, z_publisher_loan, z_publisher_move,
    z_session_drop, z_session_loan, z_session_loan_mut, z_session_move, z_undeclare_publisher,
    z_view_keyexpr_from_str, z_view_keyexpr_loan, z_view_keyexpr_t, zp_config_insert,
    Z_CONFIG_CONNECT_KEY, Z_CONFIG_LISTEN_KEY, Z_OK,
};
use wz_runtime_tokio_test_support::free_port;
use wz_session_core::policy::SessionPolicy;

const KEY: &CStr = c"demo/replay/one";
const SUFFIX: &CStr = c"/replay-ask";
const BARRIER: Duration = Duration::from_secs(10);
const DEPTH: u32 = 8;

/// A 32-bit CRC first on the wire, a two-byte counter and a length: synthetic.
const PROFILE: &str = r#"{
  "name": "replay-door",
  "fields": [
    {"name": "crc", "bytes": 4},
    {"name": "counter", "bytes": 2},
    {"name": "length", "bytes": 2}
  ],
  "crc": {"field": "crc", "width": 32, "poly": "0x1EDC6F41", "init": "0xFFFFFFFF",
          "refin": true, "refout": true, "xorout": "0xFFFFFFFF",
          "cover": ["counter", "length", "@payload"]},
  "length": {"field": "length", "counts": "frame"},
  "counter": {"field": "counter", "max_gap": 3, "timeout_ms": 60000}
}"#;

/// The pieces a frame is cut into under the build's `replay-reply-shape = segmented`, read by
/// nothing under `frame-per-sample`: a mark, a stream field and two-byte number, total and place,
/// synthetic. A frame of [`frame`] is eleven bytes, so it is three pieces of [`CHUNK`].
const SEGMENTS: &str = r#"{"name":"replay-door-pieces","segments":{"fields":[
  {"name":"mark","bytes":1,"equals":"0x7E"},
  {"name":"source","bytes":2},
  {"name":"seq","bytes":2},
  {"name":"whole","bytes":2},
  {"name":"pos","bytes":2}],
  "stream":["source"],"transfer":"seq","total":"whole","offset":"pos","total_max":1024}}"#;
const SEGMENT_VALUES: &str = r#"{"source": 9}"#;
const CHUNK: usize = 4;

fn frame(counter: u64) -> Vec<u8> {
    let profile = Profile::parse(PROFILE).expect("valid");
    let payload = [counter as u8 ^ 0x5c; 3];
    build(&profile, &Values::new().whole("counter", counter), &payload)
        .expect("builds")
        .bytes
}

/// One sample the program was handed.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Got {
    from_replay: bool,
    judged: bool,
    counter: u64,
    status: u8,
    zid_len: u8,
}

type Seen = Arc<Mutex<Vec<Got>>>;

unsafe extern "C" fn on_sample(context: *mut c_void, sample: *const wz_ext_replay_sample_t) {
    let seen = &*context.cast_const().cast::<Seen>();
    let sample = &*sample;
    seen.lock().unwrap().push(Got {
        from_replay: sample.from_replay == 1,
        judged: sample.judged == 1,
        counter: sample.verdict.counter,
        status: sample.verdict.status,
        zid_len: sample.zid_len,
    });
}

unsafe extern "C" fn on_drop(context: *mut c_void) {
    drop(Box::from_raw(context.cast::<Seen>()));
}

unsafe fn open(key: u8, endpoint: &CStr) -> z_owned_session_t {
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    assert_eq!(
        zp_config_insert(z_config_loan_mut(&mut cfg), key, endpoint.as_ptr()),
        Z_OK
    );
    let mut session: z_owned_session_t = std::mem::zeroed();
    assert_eq!(
        z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()),
        Z_OK
    );
    session
}

unsafe fn close(session: &mut z_owned_session_t) {
    z_close(z_session_loan_mut(session), std::ptr::null());
    z_session_drop(z_session_move(session));
}

unsafe fn view(text: &CStr) -> z_view_keyexpr_t {
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, text.as_ptr()), Z_OK);
    ke
}

/// A publishing peer: its session, its publisher on [`KEY`], its cache and the cache's storage.
struct Peer {
    session: z_owned_session_t,
    publisher: z_owned_publisher_t,
    cache: wz_ext_owned_replay_publisher_t,
    _storage: Vec<u8>,
}

impl Peer {
    unsafe fn dial(endpoint: &CStr) -> Self {
        Self::on(open(Z_CONFIG_CONNECT_KEY, endpoint))
    }

    /// A publishing peer on `session`, which it closes when it finishes.
    unsafe fn on(session: z_owned_session_t) -> Self {
        let ke = view(KEY);
        let mut publisher: z_owned_publisher_t = std::mem::zeroed();
        assert_eq!(
            z_declare_publisher(
                z_session_loan(&session),
                &mut publisher,
                z_view_keyexpr_loan(&ke),
                std::ptr::null(),
            ),
            Z_OK
        );
        let shape = wz_ext_replay_shape_t {
            frame_max: 64,
            depth: DEPTH,
            instances: 1,
        };
        let size = wz_ext_replay_publisher_storage_size(&shape);
        assert!(size > 0);
        let mut storage = vec![0u8; size];
        let mut cache: wz_ext_owned_replay_publisher_t = std::mem::zeroed();
        assert_eq!(
            wz_ext_replay_publisher_new(
                &mut cache,
                z_session_loan(&session),
                z_publisher_loan(&publisher),
                storage.as_mut_ptr(),
                storage.len(),
                &shape,
                std::ptr::null_mut(),
            ),
            Z_OK
        );
        Self {
            session,
            publisher,
            cache,
            _storage: storage,
        }
    }

    unsafe fn record(&self, counter: u64, time_ms: u64) {
        let bytes = frame(counter);
        assert_eq!(
            wz_ext_replay_publisher_record(
                wz_ext_replay_publisher_loan(&self.cache),
                0,
                time_ms,
                bytes.as_ptr(),
                bytes.len(),
            ),
            Z_OK
        );
    }

    /// Serve, with the segment profile the build's `segmented` reads and `frame-per-sample` does
    /// not.
    unsafe fn serve(&self) {
        let ke = view(KEY);
        let profile = CString::new(SEGMENTS).unwrap();
        let values = CString::new(SEGMENT_VALUES).unwrap();
        let mut options: wz_ext_replay_serve_options_t = std::mem::zeroed();
        wz_ext_replay_serve_options_default(&mut options);
        options.segment_profile = profile.as_ptr();
        options.segment_values = values.as_ptr();
        options.first_transfer = 1;
        options.chunk_bytes = CHUNK;
        assert_eq!(
            wz_ext_replay_publisher_serve(
                wz_ext_replay_publisher_loan(&self.cache),
                z_view_keyexpr_loan(&ke),
                SUFFIX.as_ptr(),
                &options,
                std::ptr::null_mut(),
            ),
            Z_OK
        );
    }

    unsafe fn finish(mut self) {
        wz_ext_replay_publisher_drop(wz_ext_replay_publisher_move(&mut self.cache));
        z_undeclare_publisher(z_publisher_move(&mut self.publisher));
        close(&mut self.session);
    }
}

/// The subscriber's side: its session, its replay subscriber and what it was handed.
struct Listener {
    session: z_owned_session_t,
    subscriber: wz_ext_owned_replay_subscriber_t,
    seen: Seen,
    _slots: Vec<wz_ext_replay_publisher_slot_t>,
    _held: Vec<u8>,
}

impl Listener {
    unsafe fn listen(endpoint: &CStr) -> Self {
        Self::on(open(Z_CONFIG_LISTEN_KEY, endpoint))
    }

    /// The subscriber's side on `session`, which it closes when it finishes.
    unsafe fn on(session: z_owned_session_t) -> Self {
        let profile = CString::new(PROFILE).unwrap();
        let mut receiver: wz_ext_owned_e2e_receiver_t = std::mem::zeroed();
        assert_eq!(
            wz_ext_e2e_receiver_new(
                &mut receiver,
                profile.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null_mut(),
            ),
            Z_OK
        );
        let mut slots: Vec<wz_ext_replay_publisher_slot_t> = vec![std::mem::zeroed(); 4];
        let held_cell = 64;
        let mut held = vec![0u8; 8 * (4 + held_cell)];
        let mut options: wz_ext_replay_subscriber_options_t = std::mem::zeroed();
        wz_ext_replay_subscriber_options_default(&mut options);
        options.slots = slots.as_mut_ptr();
        options.slot_count = slots.len();
        options.held = held.as_mut_ptr();
        options.held_len = held.len();
        options.held_cell = held_cell;
        options.depth = DEPTH as usize;
        options.progress_ms = 3000;
        options.round_ms = 9000;
        let segments = CString::new(SEGMENTS).unwrap();
        options.segment_profile = segments.as_ptr();
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let context = Box::into_raw(Box::new(seen.clone())).cast::<c_void>();
        let ke = view(KEY);
        let mut subscriber: wz_ext_owned_replay_subscriber_t = std::mem::zeroed();
        assert_eq!(
            wz_ext_replay_subscriber_new(
                &mut subscriber,
                z_session_loan(&session),
                z_view_keyexpr_loan(&ke),
                SUFFIX.as_ptr(),
                wz_ext_e2e_receiver_move(&mut receiver),
                &options,
                Some(on_sample),
                Some(on_drop),
                context,
            ),
            Z_OK
        );
        assert!(wz_ext_internal_replay_subscriber_check(&subscriber));
        Self {
            session,
            subscriber,
            seen,
            _slots: slots,
            _held: held,
        }
    }

    unsafe fn phase(&self) -> u8 {
        wz_ext_replay_subscriber_phase(wz_ext_replay_subscriber_loan(&self.subscriber))
    }

    unsafe fn counts(&self) -> wz_ext_replay_subscriber_counts_t {
        let mut counts = wz_ext_replay_subscriber_counts_t::default();
        assert_eq!(
            wz_ext_replay_subscriber_counts(
                wz_ext_replay_subscriber_loan(&self.subscriber),
                &mut counts
            ),
            Z_OK
        );
        counts
    }

    /// Poll until `done` holds of what was handed on, and give it; fails, naming what came, when
    /// it does not before the barrier.
    unsafe fn wait(&self, what: &str, done: impl Fn(&[Got]) -> bool) -> Vec<Got> {
        let deadline = Instant::now() + BARRIER;
        loop {
            assert_eq!(
                wz_ext_replay_subscriber_poll(wz_ext_replay_subscriber_loan(&self.subscriber)),
                Z_OK
            );
            let got = self.seen.lock().unwrap().clone();
            if done(&got) {
                return got;
            }
            assert!(Instant::now() < deadline, "{what}: got {got:?}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    unsafe fn finish(mut self) {
        wz_ext_replay_subscriber_drop(wz_ext_replay_subscriber_move(&mut self.subscriber));
        assert!(!wz_ext_internal_replay_subscriber_check(&self.subscriber));
        close(&mut self.session);
    }
}

fn replays(got: &[Got]) -> Vec<u64> {
    got.iter()
        .filter(|g| g.from_replay)
        .map(|g| g.counter)
        .collect()
}

#[test]
fn a_late_subscriber_is_answered_each_publishers_ring_and_then_its_live_frames() {
    let policy = SessionPolicy::from_build();
    let port = free_port();
    let endpoint = CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    // SAFETY: fresh configs, sessions and handles, each released before the test ends; the
    // subscriber's context is freed once by its drop.
    unsafe {
        let listener = Listener::listen(&endpoint);
        assert_eq!(listener.phase(), WZ_EXT_REPLAY_ROUND_IDLE);

        // The first publisher sent three frames before anyone asked, then serves.
        let first = Peer::dial(&endpoint);
        first.record(1, 10);
        first.record(2, 20);
        first.record(3, 30);
        first.serve();
        let got = listener.wait("the first ring", |got| replays(got).len() >= 3);
        assert_eq!(replays(&got), vec![1, 2, 3], "oldest first");
        assert!(got.iter().all(|g| g.judged && g.zid_len > 0));
        assert_eq!(got[0].status, WZ_EXT_E2E_FIRST);
        assert_eq!(got[1].status, WZ_EXT_E2E_OK);
        assert_eq!(got[2].status, WZ_EXT_E2E_OK);
        listener.wait("the round over", |_| {
            listener.phase() == WZ_EXT_REPLAY_ROUND_LIVE
        });

        // A live frame after the replay is handed on as live, judged after it.
        let live = frame(4);
        let mut dispatch = u8::MAX;
        assert_eq!(
            wz_ext_replay_publisher_put(
                wz_ext_replay_publisher_loan(&first.cache),
                0,
                40,
                live.as_ptr(),
                live.len(),
                WZ_EXT_REPLAY_SEND_EVENT,
                &mut dispatch,
            ),
            Z_OK
        );
        assert_eq!(dispatch, WZ_EXT_REPLAY_SENT, "no answer is being served");
        let got = listener.wait("the live frame", |got| got.len() >= 4);
        assert_eq!(
            got[3],
            Got {
                from_replay: false,
                judged: true,
                counter: 4,
                status: WZ_EXT_E2E_OK,
                zid_len: 0,
            }
        );

        // A second publisher appears later and is asked in a round of its own.
        let second = Peer::dial(&endpoint);
        second.record(5, 50);
        second.record(6, 60);
        second.serve();
        let got = listener.wait("the second ring", |got| replays(got).len() >= 5);
        assert_eq!(replays(&got), vec![1, 2, 3, 5, 6]);
        listener.wait("the second round over", |_| {
            listener.phase() == WZ_EXT_REPLAY_ROUND_LIVE
        });
        let counts = listener.counts();
        if policy.targeted_query() {
            assert_eq!(
                counts.duplicates + counts.stale,
                0,
                "a get addressed to the second publisher asks only it"
            );
        } else {
            assert_eq!(
                counts.duplicates + counts.stale,
                4,
                "the first answers its four frames again, and the judge has passed them all"
            );
        }
        assert_eq!(counts.late_replies, 0);
        assert_eq!(counts.abandoned, 0);
        assert_eq!(
            listener.seen.lock().unwrap().len(),
            6,
            "nothing was handed on twice"
        );

        let mut served = wz_ext_replay_publisher_counts_t::default();
        assert_eq!(
            wz_ext_replay_publisher_counts(wz_ext_replay_publisher_loan(&first.cache), &mut served),
            Z_OK
        );
        assert_eq!(served.recorded, 4, "three recorded, one put");
        assert!(served.answers >= 1);

        listener.finish();
        first.finish();
        second.finish();
    }
}

/// The other order: the publisher serves first, the subscriber's session dials it, and the
/// replay subscriber is made only once the link has been up long enough for the queryable's
/// declaration to have arrived. The declaration watch tells what the link already holds, so the
/// publisher is asked all the same.
#[test]
fn a_subscriber_made_after_its_publisher_appeared_still_asks_it() {
    let port = free_port();
    let endpoint = CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    // SAFETY: as the test above.
    unsafe {
        let early = Peer::on(open(Z_CONFIG_LISTEN_KEY, &endpoint));
        early.record(7, 70);
        early.record(8, 80);
        early.serve();
        let session = open(Z_CONFIG_CONNECT_KEY, &endpoint);
        // Past the link's initial declarations: the queryable is held when the watch is made.
        std::thread::sleep(Duration::from_millis(500));
        let listener = Listener::on(session);
        let got = listener.wait("the ring of a publisher that appeared first", |got| {
            replays(got).len() >= 2
        });
        assert_eq!(replays(&got), vec![7, 8]);
        assert_eq!(got[0].status, WZ_EXT_E2E_FIRST);
        listener.wait("the round over", |_| {
            listener.phase() == WZ_EXT_REPLAY_ROUND_LIVE
        });
        listener.finish();
        early.finish();
    }
}

#[test]
fn an_empty_cache_answers_the_final_alone_and_the_round_goes_live() {
    let port = free_port();
    let endpoint = CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    // SAFETY: as the test above.
    unsafe {
        let listener = Listener::listen(&endpoint);
        let only = Peer::dial(&endpoint);
        only.serve();
        listener.wait("the round over", |_| {
            listener.phase() == WZ_EXT_REPLAY_ROUND_LIVE
        });
        assert!(listener.seen.lock().unwrap().is_empty());
        assert_eq!(
            wz_ext_replay_publisher_phase(wz_ext_replay_publisher_loan(&only.cache)),
            WZ_EXT_REPLAY_SERVING_IDLE,
            "the answer is over and nothing was held"
        );
        listener.finish();
        only.finish();
    }
}

#[test]
fn the_publisher_doors_refuse_by_name() {
    let port = free_port();
    let endpoint = CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    // SAFETY: as the test above.
    unsafe {
        let mut listener_session = open(Z_CONFIG_LISTEN_KEY, &endpoint);
        let peer = Peer::dial(&endpoint);
        let loan = wz_ext_replay_publisher_loan(&peer.cache);
        let long = [0u8; 65];
        assert_eq!(
            wz_ext_replay_publisher_record(loan, 0, 0, long.as_ptr(), long.len()),
            Z_EINVAL,
            "longer than frame_max"
        );
        let one = frame(1);
        assert_eq!(
            wz_ext_replay_publisher_record(loan, 1, 0, one.as_ptr(), one.len()),
            Z_EINVAL,
            "no such instance"
        );
        assert_eq!(
            wz_ext_replay_publisher_put(
                loan,
                0,
                0,
                one.as_ptr(),
                one.len(),
                7,
                std::ptr::null_mut()
            ),
            Z_EINVAL,
            "no such kind"
        );
        let ke = view(KEY);
        assert_eq!(
            wz_ext_replay_publisher_serve(
                loan,
                z_view_keyexpr_loan(&ke),
                c"//empty".as_ptr(),
                std::ptr::null(),
                std::ptr::null_mut(),
            ),
            Z_ERR_INVALID,
            "an empty chunk is no key expression"
        );
        peer.serve();
        assert_eq!(
            wz_ext_replay_publisher_serve(
                loan,
                z_view_keyexpr_loan(&ke),
                SUFFIX.as_ptr(),
                std::ptr::null(),
                std::ptr::null_mut(),
            ),
            Z_EINVAL,
            "a cache serves once"
        );

        let shape = wz_ext_replay_shape_t {
            frame_max: 8,
            depth: 2,
            instances: 1,
        };
        let mut short = vec![0u8; wz_ext_replay_publisher_storage_size(&shape) - 1];
        let mut refused: wz_ext_owned_replay_publisher_t = std::mem::zeroed();
        assert_eq!(
            wz_ext_replay_publisher_new(
                &mut refused,
                z_session_loan(&peer.session),
                z_publisher_loan(&peer.publisher),
                short.as_mut_ptr(),
                short.len(),
                &shape,
                std::ptr::null_mut(),
            ),
            Z_ERR_CONFIG_INVALID_VALUE
        );
        assert!(!wz_ext_internal_replay_publisher_check(&refused));

        peer.finish();
        close(&mut listener_session);
    }
}

/// What the replay doors read of a session they read through the extension interface: the
/// session's own snapshot of the build's policies, the querier's bound and the replay depth's,
/// open and then closed.
#[test]
fn the_core_reports_a_session_s_facts_through_the_extension_interface() {
    use wz_capi_pico::ext_interface::{
        wz_ext_interface_session_facts, wz_ext_session_facts_t, WZ_EXT_REPLAY_LIVE_DELIVER,
        WZ_EXT_REPLAY_LIVE_HOLD_BACK, WZ_EXT_REPLAY_SHAPE_FRAME_PER_SAMPLE,
        WZ_EXT_REPLAY_SHAPE_SEGMENTED,
    };
    use wz_session_core::policy::{ReplayLiveBeforeAnswer, ReplayReplyShape};

    let policy = SessionPolicy::from_build();
    let port = free_port();
    let endpoint = CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    let size = std::mem::size_of::<wz_ext_session_facts_t>();
    // SAFETY: one session of this library, read while it is held and dropped at the end.
    unsafe {
        let mut session = open(Z_CONFIG_LISTEN_KEY, &endpoint);
        let mut facts: wz_ext_session_facts_t = std::mem::zeroed();
        facts.struct_size = size as u32;
        assert_eq!(
            wz_ext_interface_session_facts(z_session_loan(&session), &mut facts),
            Z_OK
        );
        assert_eq!(facts.struct_size as usize, size);
        assert_eq!(facts.closed, 0);
        let shape = match policy.replay_reply_shape() {
            ReplayReplyShape::FramePerSample => WZ_EXT_REPLAY_SHAPE_FRAME_PER_SAMPLE,
            ReplayReplyShape::Segmented => WZ_EXT_REPLAY_SHAPE_SEGMENTED,
        };
        assert_eq!(facts.replay_reply_shape, shape);
        assert_eq!(
            facts.replay_serve_holds_sends,
            u8::from(policy.replay_serve_holds_sends())
        );
        let live = match policy.replay_live_before_answer() {
            ReplayLiveBeforeAnswer::Deliver => WZ_EXT_REPLAY_LIVE_DELIVER,
            ReplayLiveBeforeAnswer::HoldBack => WZ_EXT_REPLAY_LIVE_HOLD_BACK,
        };
        assert_eq!(facts.replay_live_before_answer, live);
        assert_eq!(facts.targeted_query, u8::from(policy.targeted_query()));
        assert_eq!(
            facts.querier_max_pending_queries,
            wz_session_core::caps::QUERIER_MAX_PENDING_QUERIES
        );
        assert_eq!(
            facts.replay_depth_max,
            wz_session_core::caps::REPLAY_DEPTH_MAX
        );

        z_close(z_session_loan_mut(&mut session), std::ptr::null());
        assert_eq!(
            wz_ext_interface_session_facts(z_session_loan(&session), &mut facts),
            Z_OK
        );
        assert_eq!(facts.closed, 1, "a closed session is answered too");
        z_session_drop(z_session_move(&mut session));
    }
}
