// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! The build without the `peer` feature opens a client session to a node that listens, publishes
//! to it and hears from it, answers its queries and asks it queries, holds liveliness tokens,
//! hears the node's and asks it which are alive.
//!
//! Such a build cannot listen, so the node it dials is the `hold_a_listener` example of the
//! FULL build, run as a process. The two are built by two invocations (a feature set is one per
//! build), which is why the example's path is a named input. The client is either engine's, so
//! the test is run once for each:
//!
//! ```text
//! cargo build --release -p wz-capi-pico --example hold_a_listener
//! WZ_PICO_LISTENER_BIN=$PWD/target/release/examples/hold_a_listener \
//!     cargo test --release -p wz-capi-pico --no-default-features \
//!     --features engine-coop,link-udp,query,queryable,liveliness-get \
//!     --test client_only_dials_a_listener
//! ```
//!
//! and again with `engine-tokio` in place of `engine-coop`, and each without `queryable`. Layer
//! C1co runs the four (`scripts/run-ci.sh`).
//!
//! A missing example is a failure and not a skip: a test that passes by not running would say a
//! stripped build connects when nothing has shown it.
#![cfg(not(feature = "peer"))]

use std::collections::BTreeSet;
use std::ffi::{c_void, CStr, CString};
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[cfg(not(feature = "multi-thread"))]
use wz_capi_pico::zp_read;
use wz_capi_pico::{
    z_bytes_copy_from_str, z_bytes_move, z_close, z_closure_sample, z_closure_sample_move,
    z_config_default, z_config_loan_mut, z_config_move, z_declare_subscriber,
    z_keyexpr_as_view_string, z_loaned_sample_t, z_open, z_owned_config_t, z_owned_session_t,
    z_owned_subscriber_t, z_put, z_sample_keyexpr, z_session_drop, z_session_loan,
    z_session_loan_mut, z_session_move, z_string_data, z_string_len, z_subscriber_move,
    z_undeclare_subscriber, z_view_keyexpr_from_str, z_view_keyexpr_loan, z_view_keyexpr_t,
    z_view_string_loan, z_view_string_t, zp_config_insert, Z_CONFIG_CONNECT_KEY, Z_OK,
};
use wz_runtime_tokio_test_support::free_port;

struct SetCtx {
    seen: Arc<Mutex<BTreeSet<String>>>,
}

unsafe extern "C" fn on_sample_record_keyexpr(sample: *const z_loaned_sample_t, ctx: *mut c_void) {
    let ctx = &*(ctx as *const SetCtx);
    let mut view: z_view_string_t = std::mem::zeroed();
    if z_keyexpr_as_view_string(z_sample_keyexpr(sample), &mut view) != Z_OK {
        return;
    }
    let string = z_view_string_loan(&view);
    let (data, len) = (z_string_data(string), z_string_len(string));
    if data.is_null() {
        return;
    }
    if let Ok(key) = std::str::from_utf8(std::slice::from_raw_parts(data as *const u8, len)) {
        ctx.seen.lock().unwrap().insert(key.to_owned());
    }
}

unsafe extern "C" fn on_drop_set(ctx: *mut c_void) {
    drop(Box::from_raw(ctx as *mut SetCtx));
}

/// The example of the full build, from `WZ_PICO_LISTENER_BIN` or beside this test's own binary.
fn listener_binary() -> std::path::PathBuf {
    if let Ok(path) = std::env::var("WZ_PICO_LISTENER_BIN") {
        return path.into();
    }
    let test = std::env::current_exe().expect("the path of this test");
    let profile_dir = test
        .parent()
        .and_then(|deps| deps.parent())
        .expect("target/<profile>/deps/<test>");
    profile_dir.join("examples").join("hold_a_listener")
}

/// The listener process, killed when dropped, and the lines it prints.
struct Listener {
    child: Child,
    lines: Receiver<String>,
}

impl Listener {
    fn start(port: u16) -> Self {
        let binary = listener_binary();
        assert!(
            binary.is_file(),
            "{} is missing: build it with `cargo build --release -p wz-capi-pico --example \
             hold_a_listener` (the full build) and name it in WZ_PICO_LISTENER_BIN",
            binary.display()
        );
        let mut child = Command::new(&binary)
            .arg(port.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("the listener starts");
        let stdout = child.stdout.take().expect("a piped stdout");
        let (tx, lines) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let this = Self { child, lines };
        this.wait_for("READY");
        this
    }

    /// Read lines until one equals `wanted`, for at most ten seconds.
    fn wait_for(&self, wanted: &str) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while let Some(left) = deadline.checked_duration_since(Instant::now()) {
            match self.lines.recv_timeout(left) {
                Ok(line) if line == wanted => return,
                Ok(_) => {}
                Err(_) => break,
            }
        }
        panic!("the listener never printed {wanted:?}");
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        // Closing its standard input is how the example ends; killing is the fallback.
        drop(self.child.stdin.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

unsafe fn put(session: &z_owned_session_t, key: &CStr, payload: &CStr) {
    let mut ke: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut ke, key.as_ptr()), Z_OK);
    let mut buf = std::mem::zeroed();
    assert_eq!(z_bytes_copy_from_str(&mut buf, payload.as_ptr()), Z_OK);
    assert_eq!(
        z_put(
            z_session_loan(session),
            z_view_keyexpr_loan(&ke),
            z_bytes_move(&mut buf),
            std::ptr::null(),
        ),
        Z_OK
    );
}

#[test]
fn a_client_only_build_publishes_to_a_listener_and_hears_from_it() {
    let port = free_port();
    let listener = Listener::start(port);
    let seen = Arc::new(Mutex::new(BTreeSet::new()));
    // SAFETY: a fresh config, session and subscriber, all released before the function returns.
    unsafe {
        // A client-only build opens a client session to a listener.
        let mut session = open_to(port);

        let ctx = Box::into_raw(Box::new(SetCtx { seen: seen.clone() })) as *mut c_void;
        let mut closure = std::mem::zeroed();
        assert_eq!(
            z_closure_sample(
                &mut closure,
                Some(on_sample_record_keyexpr),
                Some(on_drop_set),
                ctx
            ),
            Z_OK
        );
        let mut ke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut ke, c"demo/**".as_ptr()), Z_OK);
        let mut sub: z_owned_subscriber_t = std::mem::zeroed();
        assert_eq!(
            z_declare_subscriber(
                z_session_loan(&session),
                &mut sub,
                z_view_keyexpr_loan(&ke),
                z_closure_sample_move(&mut closure),
                std::ptr::null(),
            ),
            Z_OK
        );

        // Publish until the listener has heard it, and wait until it has been heard from. In
        // pico's single-threaded arm the program advances its session itself, with `zp_read`,
        // as pico's own single-threaded examples do: the cooperative engine reads nothing
        // between two calls, and the tokio engine, which reads on its own runtime, answers it
        // at once.
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut heard_from_listener = false;
        while Instant::now() < deadline {
            #[cfg(not(feature = "multi-thread"))]
            assert_eq!(
                zp_read(z_session_loan(&session), std::ptr::null()),
                Z_OK,
                "the session is open"
            );
            put(&session, c"demo/from-client", c"payload");
            heard_from_listener = seen.lock().unwrap().contains("demo/from-listener");
            if heard_from_listener {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        // And the listener reports the client's publication.
        listener.wait_for("heard demo/from-client");

        z_undeclare_subscriber(z_subscriber_move(&mut sub));
        z_close(z_session_loan_mut(&mut session), std::ptr::null());
        z_session_drop(z_session_move(&mut session));
        assert!(
            heard_from_listener,
            "the client never heard the listener's publication"
        );
    }
}

/// Open a client session to the listener on `port`.
unsafe fn open_to(port: u16) -> z_owned_session_t {
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    let endpoint = CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    assert_eq!(
        zp_config_insert(
            z_config_loan_mut(&mut cfg),
            Z_CONFIG_CONNECT_KEY,
            endpoint.as_ptr()
        ),
        Z_OK
    );
    let mut session: z_owned_session_t = std::mem::zeroed();
    assert_eq!(
        z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()),
        Z_OK
    );
    session
}

/// Step the session for `span`, in the single-threaded arm; the read task steps it otherwise.
#[cfg(any(
    feature = "query",
    feature = "queryable",
    feature = "liveliness",
    feature = "connectivity"
))]
unsafe fn step_for(session: &z_owned_session_t, span: Duration) {
    #[cfg(feature = "multi-thread")]
    let _ = session;
    let end = Instant::now() + span;
    while Instant::now() < end {
        #[cfg(not(feature = "multi-thread"))]
        assert_eq!(zp_read(z_session_loan(session), std::ptr::null()), Z_OK);
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// The answering end of a query in the build that cannot listen: the listener asks, the client's
/// queryable answers at once and keeps the query, answers again later from the program's own
/// thread, and the query ends only when the program lets go of the copy it kept. The CONTROL is
/// the order the listener prints: the late reply before the end, and no end while the copy is kept.
#[cfg(feature = "queryable")]
mod answering {
    use super::*;
    use wz_capi_pico::{
        z_closure_query, z_closure_query_move, z_declare_queryable, z_loaned_query_t,
        z_owned_query_t, z_owned_queryable_t, z_query_clone, z_query_drop, z_query_keyexpr,
        z_query_loan, z_query_move, z_query_reply, z_queryable_move, z_undeclare_queryable,
    };

    impl Listener {
        /// Have the listener ask a query on `key`; it prints `reply <payload>` and `done <key>`.
        pub(super) fn ask(&mut self, key: &str) {
            use std::io::Write;
            let stdin = self.child.stdin.as_mut().expect("a piped stdin");
            writeln!(stdin, "get {key}").expect("the listener reads its input");
            stdin.flush().expect("the listener reads its input");
        }
    }

    /// The copy of the query the callback kept, for the test to answer and drop later.
    struct Kept(Mutex<Option<z_owned_query_t>>);

    // SAFETY: the kept query is an owned handle this crate's ABI hands to any thread, as pico's
    // `z_query_take_from_loaned` does; it is reached through the mutex alone.
    unsafe impl Send for Kept {}
    unsafe impl Sync for Kept {}

    unsafe fn reply(query: *const z_loaned_query_t, payload: &CStr) {
        let mut bytes = std::mem::zeroed();
        assert_eq!(z_bytes_copy_from_str(&mut bytes, payload.as_ptr()), Z_OK);
        assert_eq!(
            z_query_reply(
                query,
                z_query_keyexpr(query),
                z_bytes_move(&mut bytes),
                std::ptr::null()
            ),
            Z_OK
        );
    }

    unsafe extern "C" fn on_query(query: *const z_loaned_query_t, ctx: *mut c_void) {
        let kept = &*(ctx as *const Kept);
        reply(query, c"now");
        let mut copy: z_owned_query_t = std::mem::zeroed();
        assert_eq!(z_query_clone(&mut copy, query), Z_OK);
        *kept.0.lock().unwrap() = Some(copy);
    }

    unsafe extern "C" fn on_query_drop(ctx: *mut c_void) {
        drop(Arc::from_raw(ctx as *const Kept));
    }

    #[test]
    fn a_client_only_build_answers_a_listeners_query_and_ends_it_when_let_go() {
        let port = free_port();
        let mut listener = Listener::start(port);
        // SAFETY: a fresh config, session and queryable, all released before the function returns.
        unsafe {
            let mut session = open_to(port);

            let kept = Arc::new(Kept(Mutex::new(None)));
            let mut closure = std::mem::zeroed();
            assert_eq!(
                z_closure_query(
                    &mut closure,
                    Some(on_query),
                    Some(on_query_drop),
                    Arc::into_raw(kept.clone()) as *mut c_void
                ),
                Z_OK
            );
            let mut ke: z_view_keyexpr_t = std::mem::zeroed();
            assert_eq!(
                z_view_keyexpr_from_str(&mut ke, c"demo/q/**".as_ptr()),
                Z_OK
            );
            let mut queryable: z_owned_queryable_t = std::mem::zeroed();
            assert_eq!(
                z_declare_queryable(
                    z_session_loan(&session),
                    &mut queryable,
                    z_view_keyexpr_loan(&ke),
                    z_closure_query_move(&mut closure),
                    std::ptr::null(),
                ),
                Z_OK
            );
            // The declaration reaches the listener before it asks.
            step_for(&session, Duration::from_millis(300));
            listener.ask("demo/q/x");
            let deadline = Instant::now() + Duration::from_secs(10);
            while kept.0.lock().unwrap().is_none() {
                assert!(
                    Instant::now() < deadline,
                    "the query never reached the queryable"
                );
                step_for(&session, Duration::from_millis(20));
            }
            listener.wait_for("reply now");
            step_for(&session, Duration::from_millis(300));
            let printed: Vec<String> = listener.lines.try_iter().collect();
            assert!(
                printed.iter().all(|line| !line.starts_with("done")),
                "CONTROL: the query does not end while the program keeps it; the listener \
                 printed {printed:?}"
            );

            let mut copy = kept.0.lock().unwrap().take().expect("the kept query");
            reply(z_query_loan(&copy), c"later");
            listener.wait_for("reply later");
            z_query_drop(z_query_move(&mut copy));
            listener.wait_for("done demo/q/x");

            z_undeclare_queryable(z_queryable_move(&mut queryable));
            z_close(z_session_loan_mut(&mut session), std::ptr::null());
            z_session_drop(z_session_move(&mut session));
        }
    }
}

/// The asking end of a query in the build that cannot listen: the client asks the listener,
/// whose queryable answers, and the get ends when the listener's Final comes, as the drop of the
/// reply closure. The CONTROL is a key nobody answers: that get ends too, with no reply.
#[cfg(feature = "query")]
mod asking {
    use super::*;
    use wz_capi_pico::matching::{
        z_closure_matching_status, z_closure_matching_status_move, z_matching_status_t,
        z_owned_closure_matching_status_t,
    };
    use wz_capi_pico::{
        z_bytes_to_slice, z_closure_reply, z_closure_reply_move, z_declare_querier, z_get,
        z_loaned_reply_t, z_moved_closure_reply_t, z_owned_closure_reply_t, z_owned_querier_t,
        z_owned_slice_t, z_querier_declare_background_matching_listener, z_querier_get,
        z_querier_get_matching_status, z_querier_loan, z_querier_move, z_querier_options_default,
        z_querier_options_t, z_query_target_t, z_reply_is_ok, z_reply_ok, z_sample_payload,
        z_slice_data, z_slice_drop, z_slice_len, z_slice_loan, z_slice_move, z_undeclare_querier,
        ZResult, Z_QUERY_TARGET_ALL_COMPLETE, Z_QUERY_TARGET_BEST_MATCHING,
    };

    /// What a get's closure saw: each reply's payload (`err` for an error reply), and whether
    /// the closure has been dropped.
    #[derive(Default)]
    struct Asked {
        replies: Vec<String>,
        done: bool,
    }

    unsafe extern "C" fn on_reply(reply: *mut z_loaned_reply_t, ctx: *mut c_void) {
        let asked = &*(ctx as *const Mutex<Asked>);
        if !z_reply_is_ok(reply) {
            asked.lock().unwrap().replies.push("err".to_owned());
            return;
        }
        let mut slice: z_owned_slice_t = std::mem::zeroed();
        assert_eq!(
            z_bytes_to_slice(z_sample_payload(z_reply_ok(reply)), &mut slice),
            Z_OK
        );
        let loaned = z_slice_loan(&slice);
        let bytes = std::slice::from_raw_parts(z_slice_data(loaned), z_slice_len(loaned));
        asked
            .lock()
            .unwrap()
            .replies
            .push(String::from_utf8_lossy(bytes).into_owned());
        z_slice_drop(z_slice_move(&mut slice));
    }

    unsafe extern "C" fn on_reply_drop(ctx: *mut c_void) {
        let asked = Arc::from_raw(ctx as *const Mutex<Asked>);
        asked.lock().unwrap().done = true;
    }

    /// Issue a get through `issue`, which is handed the moved reply closure, and step the
    /// session until the get has ended: what it saw.
    pub(super) unsafe fn asked(
        session: &z_owned_session_t,
        what: &str,
        issue: impl FnOnce(*mut z_moved_closure_reply_t) -> ZResult,
    ) -> Vec<String> {
        let asked = Arc::new(Mutex::new(Asked::default()));
        let mut closure: z_owned_closure_reply_t = std::mem::zeroed();
        assert_eq!(
            z_closure_reply(
                &mut closure,
                Some(on_reply),
                Some(on_reply_drop),
                Arc::into_raw(asked.clone()) as *mut c_void
            ),
            Z_OK
        );
        assert_eq!(issue(z_closure_reply_move(&mut closure)), Z_OK);
        let deadline = Instant::now() + Duration::from_secs(10);
        while !asked.lock().unwrap().done {
            assert!(Instant::now() < deadline, "the get {what} never ended");
            step_for(session, Duration::from_millis(20));
        }
        let replies = std::mem::take(&mut asked.lock().unwrap().replies);
        replies
    }

    /// Ask a get on `key` and step the session until it has ended: what it saw.
    unsafe fn ask(session: &z_owned_session_t, key: &CStr) -> Vec<String> {
        let mut ke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut ke, key.as_ptr()), Z_OK);
        asked(session, &format!("on {key:?}"), |closure| {
            z_get(
                z_session_loan(session),
                z_view_keyexpr_loan(&ke),
                std::ptr::null(),
                closure,
                std::ptr::null_mut(),
            )
        })
    }

    /// Declare a querier on `key` with `target`.
    pub(super) unsafe fn querier(
        session: &z_owned_session_t,
        key: &CStr,
        target: z_query_target_t,
    ) -> z_owned_querier_t {
        let mut ke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut ke, key.as_ptr()), Z_OK);
        let mut options: z_querier_options_t = std::mem::zeroed();
        z_querier_options_default(&mut options);
        options.target = target;
        let mut querier: z_owned_querier_t = std::mem::zeroed();
        assert_eq!(
            z_declare_querier(
                z_session_loan(session),
                &mut querier,
                z_view_keyexpr_loan(&ke),
                &mut options,
            ),
            Z_OK
        );
        querier
    }

    /// Ask a get through `querier` and step the session until it has ended: what it saw.
    unsafe fn ask_through(session: &z_owned_session_t, querier: &z_owned_querier_t) -> Vec<String> {
        asked(session, "through the querier", |closure| {
            z_querier_get(
                z_querier_loan(querier),
                std::ptr::null(),
                closure,
                std::ptr::null_mut(),
            )
        })
    }

    /// Whether `querier` matches, by its poll.
    pub(super) unsafe fn matches(querier: &z_owned_querier_t) -> bool {
        let mut status = z_matching_status_t { matching: false };
        assert_eq!(
            z_querier_get_matching_status(z_querier_loan(querier), &mut status),
            Z_OK
        );
        status.matching
    }

    /// What a matching listener was told, and whether its closure has been dropped.
    #[derive(Default)]
    struct Heard {
        told: Vec<bool>,
        dropped: bool,
    }

    unsafe extern "C" fn on_status(status: *const z_matching_status_t, ctx: *mut c_void) {
        let heard = &*(ctx as *const Mutex<Heard>);
        heard.lock().unwrap().told.push((*status).matching);
    }

    unsafe extern "C" fn on_status_drop(ctx: *mut c_void) {
        let heard = Arc::from_raw(ctx as *const Mutex<Heard>);
        heard.lock().unwrap().dropped = true;
    }

    /// A querier asks the listener's queryable, which its write filter and its matching listener
    /// both see; a querier that targets ALL_COMPLETE matches nothing there, because the
    /// listener's queryable is not complete, and its get ends at once, sending nothing. The
    /// matching listener goes with its querier.
    #[test]
    fn a_client_only_build_asks_through_a_querier_its_matching_says_is_answered() {
        let port = free_port();
        let _listener = Listener::start(port);
        // SAFETY: a fresh config and session, released before the function returns.
        unsafe {
            let mut session = open_to(port);
            // The querier that counts complete queryables alone is declared first, so the
            // declarations that reach the other have reached it too.
            let mut complete = querier(&session, c"demo/listener/a", Z_QUERY_TARGET_ALL_COMPLETE);
            let mut best = querier(&session, c"demo/listener/a", Z_QUERY_TARGET_BEST_MATCHING);
            let listen = |querier: &z_owned_querier_t| {
                let heard = Arc::new(Mutex::new(Heard::default()));
                let mut closure: z_owned_closure_matching_status_t = std::mem::zeroed();
                assert_eq!(
                    z_closure_matching_status(
                        &mut closure,
                        Some(on_status),
                        Some(on_status_drop),
                        Arc::into_raw(heard.clone()) as *mut c_void
                    ),
                    Z_OK
                );
                assert_eq!(
                    z_querier_declare_background_matching_listener(
                        z_querier_loan(querier),
                        z_closure_matching_status_move(&mut closure)
                    ),
                    Z_OK
                );
                heard
            };
            let heard_complete = listen(&complete);
            let heard = listen(&best);

            let deadline = Instant::now() + Duration::from_secs(10);
            while !(matches(&best) && heard.lock().unwrap().told == [true]) {
                assert!(
                    Instant::now() < deadline,
                    "the querier never matched the listener's queryable"
                );
                step_for(&session, Duration::from_millis(20));
            }
            assert_eq!(ask_through(&session, &best), vec!["listened"]);

            assert!(
                !matches(&complete),
                "CONTROL: the listener's queryable is not complete"
            );
            assert!(
                heard_complete.lock().unwrap().told.is_empty(),
                "and the listener on that querier counts what its filter counts"
            );
            assert_eq!(
                ask_through(&session, &complete),
                Vec::<String>::new(),
                "a querier nothing matches sends nothing, and its get ends"
            );

            assert!(!heard.lock().unwrap().dropped);
            assert_eq!(z_undeclare_querier(z_querier_move(&mut best)), Z_OK);
            assert!(
                heard.lock().unwrap().dropped,
                "the background listener goes with its querier"
            );
            assert_eq!(z_undeclare_querier(z_querier_move(&mut complete)), Z_OK);
            assert!(heard_complete.lock().unwrap().dropped);
            z_close(z_session_loan_mut(&mut session), std::ptr::null());
            z_session_drop(z_session_move(&mut session));
        }
    }

    #[test]
    fn a_client_only_build_asks_a_listeners_queryable_and_the_final_ends_the_get() {
        let port = free_port();
        let _listener = Listener::start(port);
        // SAFETY: a fresh config and session, released before the function returns.
        unsafe {
            let mut session = open_to(port);
            assert_eq!(ask(&session, c"demo/listener/a"), vec!["listened"]);
            assert_eq!(
                ask(&session, c"demo/nobody/a"),
                Vec::<String>::new(),
                "CONTROL: a get nobody answers ends with the Final alone"
            );
            z_close(z_session_loan_mut(&mut session), std::ptr::null());
            z_session_drop(z_session_move(&mut session));
        }
    }
}

/// Delivery of the session's own get to its own queryables in the build that cannot listen: a get
/// made for the session alone is answered by the queryable the session declared, with no peer
/// declaring any, and a querier matches while that queryable stands and no more once it is gone.
#[cfg(all(feature = "query", feature = "queryable", feature = "local-queryable"))]
mod local_query {
    use super::asking::{asked, matches, querier};
    use super::*;
    use wz_capi_pico::locality::Z_LOCALITY_SESSION_LOCAL;
    use wz_capi_pico::{
        z_closure_query, z_closure_query_move, z_declare_queryable, z_get, z_get_options_default,
        z_get_options_t, z_loaned_query_t, z_owned_queryable_t, z_querier_move, z_query_keyexpr,
        z_query_reply, z_queryable_move, z_undeclare_querier, z_undeclare_queryable,
        Z_QUERY_TARGET_BEST_MATCHING,
    };

    unsafe extern "C" fn on_query(query: *const z_loaned_query_t, _ctx: *mut c_void) {
        let mut bytes = std::mem::zeroed();
        assert_eq!(z_bytes_copy_from_str(&mut bytes, c"mine".as_ptr()), Z_OK);
        assert_eq!(
            z_query_reply(
                query,
                z_query_keyexpr(query),
                z_bytes_move(&mut bytes),
                std::ptr::null()
            ),
            Z_OK
        );
    }

    /// Ask a get on `key` for the session alone and step until it has ended: what it saw.
    unsafe fn ask_locally(session: &z_owned_session_t, key: &CStr) -> Vec<String> {
        let mut ke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut ke, key.as_ptr()), Z_OK);
        let mut options: z_get_options_t = std::mem::zeroed();
        z_get_options_default(&mut options);
        options.allowed_destination = Z_LOCALITY_SESSION_LOCAL;
        asked(session, "for the session alone", |closure| {
            z_get(
                z_session_loan(session),
                z_view_keyexpr_loan(&ke),
                std::ptr::null(),
                closure,
                &mut options,
            )
        })
    }

    #[test]
    fn a_client_only_build_answers_its_own_get_with_its_own_queryable() {
        let port = free_port();
        let _listener = Listener::start(port);
        // SAFETY: a fresh config, session, querier and queryable, all released before the
        // function returns.
        unsafe {
            let mut session = open_to(port);
            let mut asker = querier(&session, c"lq/only/x", Z_QUERY_TARGET_BEST_MATCHING);
            assert!(
                !matches(&asker),
                "CONTROL: nothing answers the key yet, and no peer ever will"
            );
            assert_eq!(
                ask_locally(&session, c"lq/only/x"),
                Vec::<String>::new(),
                "CONTROL: a get for the session alone with no queryable ends with no reply"
            );

            let mut closure = std::mem::zeroed();
            assert_eq!(
                z_closure_query(&mut closure, Some(on_query), None, std::ptr::null_mut()),
                Z_OK
            );
            let mut ke: z_view_keyexpr_t = std::mem::zeroed();
            assert_eq!(
                z_view_keyexpr_from_str(&mut ke, c"lq/only/**".as_ptr()),
                Z_OK
            );
            let mut queryable: z_owned_queryable_t = std::mem::zeroed();
            assert_eq!(
                z_declare_queryable(
                    z_session_loan(&session),
                    &mut queryable,
                    z_view_keyexpr_loan(&ke),
                    z_closure_query_move(&mut closure),
                    std::ptr::null(),
                ),
                Z_OK
            );
            assert!(matches(&asker), "the session's own queryable matches");
            assert_eq!(ask_locally(&session, c"lq/only/x"), vec!["mine"]);

            assert_eq!(
                z_undeclare_queryable(z_queryable_move(&mut queryable)),
                Z_OK
            );
            assert!(!matches(&asker), "and matches no more once it is gone");
            assert_eq!(
                ask_locally(&session, c"lq/only/x"),
                Vec::<String>::new(),
                "a retracted queryable answers nothing"
            );

            assert_eq!(z_undeclare_querier(z_querier_move(&mut asker)), Z_OK);
            z_close(z_session_loan_mut(&mut session), std::ptr::null());
            z_session_drop(z_session_move(&mut session));
        }
    }
}

/// The admin space in the build that cannot listen: the session serves pico's documents to the
/// listener that asks, the session document naming the session's role and the locator it was
/// opened on and the peers document the listener itself. The CONTROL is the same query after the
/// admin space is stopped: the listener's get ends with no reply.
#[cfg(feature = "admin-space")]
mod admin {
    use super::*;
    use wz_capi_pico::admin_space::{zp_start_admin_space, zp_stop_admin_space};

    /// Every reply the listener printed for the query it asked, once it printed `done`, with the
    /// session stepped meanwhile.
    unsafe fn replies(session: &z_owned_session_t, listener: &Listener, key: &str) -> Vec<String> {
        let mut replies = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            assert!(Instant::now() < deadline, "the query on {key} never ended");
            step_for(session, Duration::from_millis(20));
            while let Ok(line) = listener.lines.try_recv() {
                if let Some(payload) = line.strip_prefix("reply ") {
                    replies.push(payload.to_owned());
                } else if line == format!("done {key}") {
                    return replies;
                }
            }
        }
    }

    #[test]
    fn a_client_only_build_serves_its_admin_space_to_a_listener() {
        let port = free_port();
        let mut listener = Listener::start(port);
        // SAFETY: a fresh config and session, released before the function returns.
        unsafe {
            let mut session = open_to(port);
            assert_eq!(zp_start_admin_space(z_session_loan_mut(&mut session)), Z_OK);
            assert_eq!(
                zp_start_admin_space(z_session_loan_mut(&mut session)),
                Z_OK,
                "a second start declares nothing more"
            );
            // The declaration reaches the listener before it asks.
            step_for(&session, Duration::from_millis(300));

            listener.ask("@/*/pico/session");
            let docs = replies(&session, &listener, "@/*/pico/session");
            assert_eq!(docs.len(), 1, "{docs:?}");
            assert!(docs[0].contains("\"whatami\":\"client\""), "{}", docs[0]);
            assert!(docs[0].contains("\"type\":\"unicast\""), "{}", docs[0]);
            assert!(
                docs[0].contains(&format!("\"address\":\"127.0.0.1:{port}\"")),
                "the locator the session was opened on: {}",
                docs[0]
            );

            let peers = "@/*/pico/session/transports/0/peers";
            listener.ask(peers);
            let docs = replies(&session, &listener, peers);
            assert_eq!(docs.len(), 1, "{docs:?}");
            assert!(
                docs[0].starts_with("[{\"zid\":\""),
                "the one peer is the listener: {}",
                docs[0]
            );

            assert_eq!(zp_stop_admin_space(z_session_loan_mut(&mut session)), Z_OK);
            step_for(&session, Duration::from_millis(300));
            listener.ask("@/*/pico/session");
            assert_eq!(
                replies(&session, &listener, "@/*/pico/session"),
                Vec::<String>::new(),
                "CONTROL: a stopped admin space answers nothing"
            );

            z_close(z_session_loan_mut(&mut session), std::ptr::null());
            z_session_drop(z_session_move(&mut session));
        }
    }
}

/// The connectivity plane in the build that cannot listen: the session lists the listener as its
/// one transport, with one streamed link under it, and a listener declared with history is told
/// of it as an arrival and then of its departure when the listener goes away. The CONTROL is the
/// listing after the departure: no transport stands.
#[cfg(feature = "connectivity")]
mod connected {
    use super::*;
    use wz_capi_pico::connectivity::{
        z_closure_link, z_closure_link_move, z_closure_transport, z_closure_transport_event,
        z_closure_transport_event_move, z_closure_transport_move,
        z_declare_background_transport_events_listener, z_info_links, z_info_transports,
        z_loaned_link_t, z_loaned_transport_event_t, z_loaned_transport_t, z_owned_closure_link_t,
        z_owned_closure_transport_event_t, z_owned_closure_transport_t,
        z_transport_events_listener_options_default, z_transport_events_listener_options_t,
    };
    use wz_capi_pico::{Z_SAMPLE_KIND_DELETE, Z_SAMPLE_KIND_PUT};

    /// What the closures saw: each transport listed as `(zid, is_multicast)`, each link as
    /// `(mtu, is_streamed)`, each event's kind.
    #[derive(Default)]
    struct Seen {
        transports: Vec<([u8; 16], bool)>,
        links: Vec<(u16, bool)>,
        events: Vec<u8>,
    }

    unsafe extern "C" fn on_transport(transport: *mut z_loaned_transport_t, ctx: *mut c_void) {
        let seen = &*(ctx as *const Mutex<Seen>);
        seen.lock()
            .unwrap()
            .transports
            .push(((*transport).zid.id, (*transport).is_multicast));
    }

    unsafe extern "C" fn on_link(link: *mut z_loaned_link_t, ctx: *mut c_void) {
        let seen = &*(ctx as *const Mutex<Seen>);
        seen.lock()
            .unwrap()
            .links
            .push(((*link).mtu, (*link).is_streamed));
    }

    unsafe extern "C" fn on_event(event: *mut z_loaned_transport_event_t, ctx: *mut c_void) {
        let seen = &*(ctx as *const Mutex<Seen>);
        seen.lock().unwrap().events.push((*event).kind as u8);
    }

    /// The transports the session lists now.
    unsafe fn listed(
        session: &z_owned_session_t,
        seen: &'static Mutex<Seen>,
    ) -> Vec<([u8; 16], bool)> {
        seen.lock().unwrap().transports.clear();
        let mut closure: z_owned_closure_transport_t = std::mem::zeroed();
        assert_eq!(
            z_closure_transport(
                &mut closure,
                Some(on_transport),
                None,
                seen as *const Mutex<Seen> as *mut c_void
            ),
            Z_OK
        );
        assert_eq!(
            z_info_transports(
                z_session_loan(session),
                z_closure_transport_move(&mut closure)
            ),
            Z_OK
        );
        let listed = std::mem::take(&mut seen.lock().unwrap().transports);
        listed
    }

    #[test]
    fn a_client_only_build_lists_its_listener_as_a_transport_and_hears_it_leave() {
        let port = free_port();
        let mut listener = Listener::start(port);
        let seen: &'static Mutex<Seen> = Box::leak(Box::default());
        // SAFETY: a fresh config and session, released before the function returns; the record
        // is leaked, so it outlives every callback.
        unsafe {
            let mut session = open_to(port);

            let transports = listed(&session, seen);
            assert_eq!(transports.len(), 1, "one link, one transport");
            assert_ne!(transports[0].0, [0; 16], "it names its peer");
            assert!(!transports[0].1, "a unicast transport");

            let mut closure: z_owned_closure_link_t = std::mem::zeroed();
            assert_eq!(
                z_closure_link(
                    &mut closure,
                    Some(on_link),
                    None,
                    seen as *const Mutex<Seen> as *mut c_void
                ),
                Z_OK
            );
            assert_eq!(
                z_info_links(
                    z_session_loan(&session),
                    z_closure_link_move(&mut closure),
                    std::ptr::null_mut()
                ),
                Z_OK
            );
            {
                let seen = seen.lock().unwrap();
                assert_eq!(seen.links.len(), 1, "one link under the transport");
                assert!(seen.links[0].0 > 0, "a negotiated outbound budget");
                assert!(seen.links[0].1, "a TCP link is streamed");
            }

            let mut closure: z_owned_closure_transport_event_t = std::mem::zeroed();
            assert_eq!(
                z_closure_transport_event(
                    &mut closure,
                    Some(on_event),
                    None,
                    seen as *const Mutex<Seen> as *mut c_void
                ),
                Z_OK
            );
            let mut options: z_transport_events_listener_options_t = std::mem::zeroed();
            z_transport_events_listener_options_default(&mut options);
            options.history = true;
            assert_eq!(
                z_declare_background_transport_events_listener(
                    z_session_loan(&session),
                    z_closure_transport_event_move(&mut closure),
                    &options
                ),
                Z_OK
            );
            assert_eq!(
                seen.lock().unwrap().events,
                [Z_SAMPLE_KIND_PUT as u8],
                "the listener with history is told of the transport that stands"
            );

            let _ = listener.child.kill();
            let deadline = Instant::now() + Duration::from_secs(10);
            while seen.lock().unwrap().events.len() < 2 {
                assert!(
                    Instant::now() < deadline,
                    "the transport's departure was never told"
                );
                step_for(&session, Duration::from_millis(20));
            }
            assert_eq!(
                seen.lock().unwrap().events,
                [Z_SAMPLE_KIND_PUT as u8, Z_SAMPLE_KIND_DELETE as u8]
            );
            assert!(
                listed(&session, seen).is_empty(),
                "CONTROL: no transport stands once its peer is gone"
            );

            z_close(z_session_loan_mut(&mut session), std::ptr::null());
            z_session_drop(z_session_move(&mut session));
        }
    }
}

/// The liveliness plane in the build that cannot listen: the client's token is seen by the
/// listener and its drop too, and the client's liveliness subscribers hear the listener's tokens
/// come and go; the one that asked for history is also told the token alive when it asked.
#[cfg(feature = "liveliness")]
mod living {
    use super::*;
    use wz_capi_pico::liveliness::{
        z_liveliness_declare_subscriber, z_liveliness_declare_token,
        z_liveliness_subscriber_options_t, z_liveliness_token_drop, z_liveliness_token_move,
        z_owned_liveliness_token_t,
    };
    use wz_capi_pico::{z_sample_kind, Z_SAMPLE_KIND_PUT};

    impl Listener {
        /// Give the listener a line of input (`token <key>`, `untoken <key>`).
        fn tell(&mut self, line: &str) {
            use std::io::Write;
            let stdin = self.child.stdin.as_mut().expect("a piped stdin");
            writeln!(stdin, "{line}").expect("the listener reads its input");
            stdin.flush().expect("the listener reads its input");
        }
    }

    /// What a liveliness subscriber heard, as the listener prints it: `alive <key>` and
    /// `dropped <key>`.
    type Heard = Arc<Mutex<Vec<String>>>;

    unsafe extern "C" fn on_token(sample: *const z_loaned_sample_t, ctx: *mut c_void) {
        let heard = &*(ctx as *const Mutex<Vec<String>>);
        let mut view: z_view_string_t = std::mem::zeroed();
        if z_keyexpr_as_view_string(z_sample_keyexpr(sample), &mut view) != Z_OK {
            return;
        }
        let string = z_view_string_loan(&view);
        let bytes =
            std::slice::from_raw_parts(z_string_data(string) as *const u8, z_string_len(string));
        let key = String::from_utf8_lossy(bytes);
        let event = if z_sample_kind(sample) == Z_SAMPLE_KIND_PUT {
            format!("alive {key}")
        } else {
            format!("dropped {key}")
        };
        heard.lock().unwrap().push(event);
    }

    unsafe extern "C" fn on_token_drop(ctx: *mut c_void) {
        drop(Arc::from_raw(ctx as *const Mutex<Vec<String>>));
    }

    /// Subscribe to the tokens on `key`, with `history` as given.
    unsafe fn subscribe(
        session: &z_owned_session_t,
        key: &CStr,
        history: bool,
    ) -> (z_owned_subscriber_t, Heard) {
        let heard: Heard = Arc::default();
        let mut closure = std::mem::zeroed();
        assert_eq!(
            z_closure_sample(
                &mut closure,
                Some(on_token),
                Some(on_token_drop),
                Arc::into_raw(heard.clone()) as *mut c_void
            ),
            Z_OK
        );
        let mut ke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut ke, key.as_ptr()), Z_OK);
        let mut options = z_liveliness_subscriber_options_t { history };
        let mut sub: z_owned_subscriber_t = std::mem::zeroed();
        assert_eq!(
            z_liveliness_declare_subscriber(
                z_session_loan(session),
                &mut sub,
                z_view_keyexpr_loan(&ke),
                z_closure_sample_move(&mut closure),
                &mut options,
            ),
            Z_OK
        );
        (sub, heard)
    }

    /// Step the session until `done` holds, for at most ten seconds.
    unsafe fn step_until(session: &z_owned_session_t, what: &str, done: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !done() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            step_for(session, Duration::from_millis(20));
        }
    }

    #[test]
    fn a_client_only_build_holds_a_token_and_hears_the_listeners() {
        let port = free_port();
        let mut listener = Listener::start(port);
        // SAFETY: a fresh config and session, released before the function returns.
        unsafe {
            let mut session = open_to(port);
            let (mut history_sub, history) = subscribe(&session, c"demo/listener/**", true);
            step_until(&session, "the history to be told", || {
                *history.lock().unwrap() == ["alive demo/listener/alive"]
            });
            // Only now, so the listener's token is alive before it subscribes however the listener
            // told the session of it (it also announces its tokens to a new peer unasked).
            let (mut future_sub, future) = subscribe(&session, c"demo/listener/**", false);

            let mut ke: z_view_keyexpr_t = std::mem::zeroed();
            assert_eq!(
                z_view_keyexpr_from_str(&mut ke, c"demo/client/alive".as_ptr()),
                Z_OK
            );
            let mut token: z_owned_liveliness_token_t = std::mem::zeroed();
            assert_eq!(
                z_liveliness_declare_token(
                    z_session_loan(&session),
                    &mut token,
                    z_view_keyexpr_loan(&ke),
                    std::ptr::null(),
                ),
                Z_OK
            );
            listener.wait_for("alive demo/client/alive");
            z_liveliness_token_drop(z_liveliness_token_move(&mut token));
            listener.wait_for("dropped demo/client/alive");

            listener.tell("token demo/listener/more");
            step_until(&session, "the new token to reach both", || {
                history.lock().unwrap().last().map(String::as_str)
                    == Some("alive demo/listener/more")
                    && future.lock().unwrap().last().map(String::as_str)
                        == Some("alive demo/listener/more")
            });
            assert_eq!(
                *future.lock().unwrap(),
                ["alive demo/listener/more"],
                "CONTROL: the subscriber that asked no history was told no token alive before it"
            );
            listener.tell("untoken demo/listener/more");
            step_until(&session, "its drop to reach both", || {
                history.lock().unwrap().last().map(String::as_str)
                    == Some("dropped demo/listener/more")
                    && future.lock().unwrap().last().map(String::as_str)
                        == Some("dropped demo/listener/more")
            });

            assert_eq!(
                z_undeclare_subscriber(z_subscriber_move(&mut history_sub)),
                Z_OK
            );
            assert_eq!(
                z_undeclare_subscriber(z_subscriber_move(&mut future_sub)),
                Z_OK
            );
            z_close(z_session_loan_mut(&mut session), std::ptr::null());
            z_session_drop(z_session_move(&mut session));
        }
    }
}

/// The liveliness get in the build that cannot listen: the client asks which tokens are alive,
/// the listener answers with the ones it holds and its DeclFinal ends the get.
#[cfg(feature = "liveliness-get")]
mod snapshot {
    use super::*;
    use wz_capi_pico::liveliness::{
        z_liveliness_get, z_liveliness_get_options_default, z_liveliness_get_options_t,
    };
    use wz_capi_pico::{
        z_closure_reply, z_closure_reply_move, z_loaned_reply_t, z_owned_closure_reply_t,
        z_reply_is_ok, z_reply_ok,
    };

    impl Listener {
        /// Give the listener a line of input (`token <key>`).
        fn declare(&mut self, key: &str) {
            use std::io::Write;
            let stdin = self.child.stdin.as_mut().expect("a piped stdin");
            writeln!(stdin, "token {key}").expect("the listener reads its input");
            stdin.flush().expect("the listener reads its input");
        }
    }

    /// What a snapshot's closure saw: the key of each token (`err` for an error reply), and
    /// whether the closure has been dropped.
    #[derive(Default)]
    struct Alive {
        keys: Vec<String>,
        done: bool,
    }

    unsafe extern "C" fn on_token(reply: *mut z_loaned_reply_t, ctx: *mut c_void) {
        let alive = &*(ctx as *const Mutex<Alive>);
        if !z_reply_is_ok(reply) {
            alive.lock().unwrap().keys.push("err".to_owned());
            return;
        }
        let mut view: z_view_string_t = std::mem::zeroed();
        assert_eq!(
            z_keyexpr_as_view_string(z_sample_keyexpr(z_reply_ok(reply)), &mut view),
            Z_OK
        );
        let string = z_view_string_loan(&view);
        let bytes =
            std::slice::from_raw_parts(z_string_data(string) as *const u8, z_string_len(string));
        alive
            .lock()
            .unwrap()
            .keys
            .push(String::from_utf8_lossy(bytes).into_owned());
    }

    unsafe extern "C" fn on_done(ctx: *mut c_void) {
        let alive = Arc::from_raw(ctx as *const Mutex<Alive>);
        alive.lock().unwrap().done = true;
    }

    /// Ask which tokens are alive on `key` and step the session until the snapshot has ended:
    /// their keys, sorted.
    unsafe fn alive_on(session: &z_owned_session_t, key: &CStr) -> Vec<String> {
        let alive = Arc::new(Mutex::new(Alive::default()));
        let mut closure: z_owned_closure_reply_t = std::mem::zeroed();
        assert_eq!(
            z_closure_reply(
                &mut closure,
                Some(on_token),
                Some(on_done),
                Arc::into_raw(alive.clone()) as *mut c_void
            ),
            Z_OK
        );
        let mut ke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut ke, key.as_ptr()), Z_OK);
        let mut options: z_liveliness_get_options_t = std::mem::zeroed();
        assert_eq!(z_liveliness_get_options_default(&mut options), Z_OK);
        assert_eq!(
            z_liveliness_get(
                z_session_loan(session),
                z_view_keyexpr_loan(&ke),
                z_closure_reply_move(&mut closure),
                &mut options,
            ),
            Z_OK
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        while !alive.lock().unwrap().done {
            assert!(
                Instant::now() < deadline,
                "the snapshot on {key:?} never ended"
            );
            step_for(session, Duration::from_millis(20));
        }
        let mut keys = std::mem::take(&mut alive.lock().unwrap().keys);
        keys.sort();
        keys
    }

    #[test]
    fn a_client_only_build_asks_the_listeners_tokens_alive() {
        let port = free_port();
        let mut listener = Listener::start(port);
        // SAFETY: a fresh config and session, released before the function returns.
        unsafe {
            let mut session = open_to(port);
            assert_eq!(
                alive_on(&session, c"demo/listener/**"),
                ["demo/listener/alive"]
            );
            assert_eq!(
                alive_on(&session, c"demo/nobody/**"),
                Vec::<String>::new(),
                "CONTROL: a key nothing is alive on ends with the DeclFinal alone"
            );

            // A token the listener declares after the first snapshot: the answer is the ones
            // alive when asked, so it is asked again until the new one is in.
            listener.declare("demo/listener/more");
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let keys = alive_on(&session, c"demo/listener/**");
                if keys == ["demo/listener/alive", "demo/listener/more"] {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "the new token never came back: {keys:?}"
                );
            }
            z_close(z_session_loan_mut(&mut session), std::ptr::null());
            z_session_drop(z_session_move(&mut session));
        }
    }
}

/// The unstable API in the build that cannot listen: an entity's global id names its session and
/// is its own among the session's, and a get honours a cancellation token, refusing one already
/// cancelled and answering as it does without one for one that is not.
#[cfg(all(feature = "unstable-api", feature = "query"))]
mod unstable {
    use super::*;
    use wz_capi_pico::cancellation::{
        z_cancellation_token_cancel, z_cancellation_token_loan_mut, z_cancellation_token_move,
        z_cancellation_token_new, z_owned_cancellation_token_t,
    };
    use wz_capi_pico::entity::{z_entity_global_id_eid, z_entity_global_id_zid};
    use wz_capi_pico::result::Z_ERR_CANCELLED;
    use wz_capi_pico::zid::z_info_zid;
    use wz_capi_pico::{
        z_closure_reply, z_closure_reply_move, z_declare_publisher, z_get, z_get_options_default,
        z_get_options_t, z_loaned_reply_t, z_owned_closure_reply_t, z_owned_publisher_t,
        z_publisher_id, z_publisher_loan, z_publisher_move, z_reply_is_ok, z_session_id,
        z_undeclare_publisher,
    };

    /// What a get's closure saw: how many replies came, and whether it has been dropped.
    #[derive(Default)]
    struct Seen {
        replies: usize,
        done: bool,
    }

    unsafe extern "C" fn on_reply(reply: *mut z_loaned_reply_t, ctx: *mut c_void) {
        let seen = &*(ctx as *const Mutex<Seen>);
        if z_reply_is_ok(reply) {
            seen.lock().unwrap().replies += 1;
        }
    }

    unsafe extern "C" fn on_drop(ctx: *mut c_void) {
        let seen = Arc::from_raw(ctx as *const Mutex<Seen>);
        seen.lock().unwrap().done = true;
    }

    /// Issue a get on `key` carrying `token`, and step until its closure is dropped: the call's
    /// answer, the replies it saw, and whether the closure was dropped.
    unsafe fn get_with(
        session: &z_owned_session_t,
        key: &CStr,
        token: &mut z_owned_cancellation_token_t,
    ) -> (i8, usize, bool) {
        let seen = Arc::new(Mutex::new(Seen::default()));
        let mut closure: z_owned_closure_reply_t = std::mem::zeroed();
        assert_eq!(
            z_closure_reply(
                &mut closure,
                Some(on_reply),
                Some(on_drop),
                Arc::into_raw(seen.clone()) as *mut c_void
            ),
            Z_OK
        );
        let mut ke: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut ke, key.as_ptr()), Z_OK);
        let mut options: z_get_options_t = std::mem::zeroed();
        z_get_options_default(&mut options);
        options.cancellation_token = z_cancellation_token_move(token);
        let answer = z_get(
            z_session_loan(session),
            z_view_keyexpr_loan(&ke),
            std::ptr::null(),
            z_closure_reply_move(&mut closure),
            &mut options,
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        while !seen.lock().unwrap().done {
            assert!(Instant::now() < deadline, "the get on {key:?} never ended");
            step_for(session, Duration::from_millis(20));
        }
        let seen = seen.lock().unwrap();
        (answer, seen.replies, seen.done)
    }

    #[test]
    fn a_client_only_build_names_its_entities_and_honours_a_cancellation_token() {
        let port = free_port();
        let _listener = Listener::start(port);
        // SAFETY: a fresh config and session, released before the function returns.
        unsafe {
            let mut session = open_to(port);
            let zid = z_info_zid(z_session_loan(&session));

            // A global id names the session, and an entity's eid is not the session's.
            let mut ke: z_view_keyexpr_t = std::mem::zeroed();
            assert_eq!(
                z_view_keyexpr_from_str(&mut ke, c"demo/ids/p".as_ptr()),
                Z_OK
            );
            let mut publisher: z_owned_publisher_t = std::mem::zeroed();
            assert_eq!(
                z_declare_publisher(
                    z_session_loan(&session),
                    &mut publisher,
                    z_view_keyexpr_loan(&ke),
                    std::ptr::null_mut()
                ),
                Z_OK
            );
            let session_id = z_session_id(z_session_loan(&session));
            let publisher_id = z_publisher_id(z_publisher_loan(&publisher));
            assert_eq!(z_entity_global_id_zid(&session_id).id, zid.id);
            assert_eq!(z_entity_global_id_zid(&publisher_id).id, zid.id);
            assert_ne!(
                z_entity_global_id_eid(&publisher_id),
                z_entity_global_id_eid(&session_id),
                "an entity's eid is not its session's"
            );
            assert_eq!(
                z_undeclare_publisher(z_publisher_move(&mut publisher)),
                Z_OK
            );

            // A token cancelled before the call refuses it, and its closure is still dropped.
            let mut cancelled: z_owned_cancellation_token_t = std::mem::zeroed();
            assert_eq!(z_cancellation_token_new(&mut cancelled), Z_OK);
            assert_eq!(
                z_cancellation_token_cancel(z_cancellation_token_loan_mut(&mut cancelled)),
                Z_OK
            );
            let (answer, replies, done) = get_with(&session, c"demo/listener/a", &mut cancelled);
            assert_eq!(answer, Z_ERR_CANCELLED);
            assert!(
                done && replies == 0,
                "refused: nothing sent, closure dropped"
            );

            // A token nobody cancels is carried, and the get answers as it does without one.
            let mut live: z_owned_cancellation_token_t = std::mem::zeroed();
            assert_eq!(z_cancellation_token_new(&mut live), Z_OK);
            let (answer, replies, _) = get_with(&session, c"demo/listener/a", &mut live);
            assert_eq!(answer, Z_OK);
            assert_eq!(replies, 1, "the listener's queryable answered");

            z_close(z_session_loan_mut(&mut session), std::ptr::null());
            z_session_drop(z_session_move(&mut session));
        }
    }
}

/// Delivery to the session's own subscribers in the build that cannot listen: with no peer
/// subscribing to the key, a publisher matches while the session has a subscriber of its own,
/// and a put reaches that subscriber before the call returns; once it is gone the publisher
/// matches nothing and the put reaches nobody.
#[cfg(feature = "local-subscriber")]
mod local {
    use super::*;
    use wz_capi_pico::matching::{z_matching_status_t, z_publisher_get_matching_status};
    use wz_capi_pico::{
        z_declare_publisher, z_owned_publisher_t, z_publisher_loan, z_publisher_move,
        z_publisher_put, z_undeclare_publisher,
    };

    unsafe extern "C" fn on_sample_count(_sample: *const z_loaned_sample_t, ctx: *mut c_void) {
        let count = &*(ctx as *const std::sync::atomic::AtomicUsize);
        count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    /// Whether `publisher` matches.
    unsafe fn matches(publisher: &z_owned_publisher_t) -> bool {
        let mut status = z_matching_status_t { matching: false };
        assert_eq!(
            z_publisher_get_matching_status(z_publisher_loan(publisher), &mut status),
            Z_OK
        );
        status.matching
    }

    #[test]
    fn a_client_only_build_delivers_a_put_to_its_own_subscriber() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let port = free_port();
        let _listener = Listener::start(port);
        let count: &'static AtomicUsize = Box::leak(Box::default());
        // SAFETY: a fresh config and session, released before the function returns; the counter
        // is leaked, so it outlives every callback.
        unsafe {
            let mut session = open_to(port);
            // A key the listener does not subscribe to: nothing remote matches it.
            let mut ke: z_view_keyexpr_t = std::mem::zeroed();
            assert_eq!(
                z_view_keyexpr_from_str(&mut ke, c"local/only/x".as_ptr()),
                Z_OK
            );
            let mut publisher: z_owned_publisher_t = std::mem::zeroed();
            assert_eq!(
                z_declare_publisher(
                    z_session_loan(&session),
                    &mut publisher,
                    z_view_keyexpr_loan(&ke),
                    std::ptr::null_mut()
                ),
                Z_OK
            );
            assert!(
                !matches(&publisher),
                "CONTROL: nothing subscribes to the key yet"
            );

            let mut closure = std::mem::zeroed();
            assert_eq!(
                z_closure_sample(
                    &mut closure,
                    Some(on_sample_count),
                    None,
                    count as *const AtomicUsize as *mut c_void
                ),
                Z_OK
            );
            let mut own: z_view_keyexpr_t = std::mem::zeroed();
            assert_eq!(
                z_view_keyexpr_from_str(&mut own, c"local/only/**".as_ptr()),
                Z_OK
            );
            let mut sub: z_owned_subscriber_t = std::mem::zeroed();
            assert_eq!(
                z_declare_subscriber(
                    z_session_loan(&session),
                    &mut sub,
                    z_view_keyexpr_loan(&own),
                    z_closure_sample_move(&mut closure),
                    std::ptr::null(),
                ),
                Z_OK
            );
            assert!(matches(&publisher), "the session's own subscriber matches");

            let mut payload = std::mem::zeroed();
            assert_eq!(z_bytes_copy_from_str(&mut payload, c"v".as_ptr()), Z_OK);
            assert_eq!(
                z_publisher_put(
                    z_publisher_loan(&publisher),
                    z_bytes_move(&mut payload),
                    std::ptr::null()
                ),
                Z_OK
            );
            assert_eq!(
                count.load(Ordering::SeqCst),
                1,
                "the subscriber was handed the put before the call returned"
            );
            put(&session, c"local/only/y", c"w");
            assert_eq!(
                count.load(Ordering::SeqCst),
                2,
                "a session put does the same"
            );

            assert_eq!(z_undeclare_subscriber(z_subscriber_move(&mut sub)), Z_OK);
            assert!(!matches(&publisher), "and matches no more once it is gone");
            put(&session, c"local/only/z", c"x");
            assert_eq!(
                count.load(Ordering::SeqCst),
                2,
                "a retracted subscriber hears nothing"
            );

            assert_eq!(
                z_undeclare_publisher(z_publisher_move(&mut publisher)),
                Z_OK
            );
            z_close(z_session_loan_mut(&mut session), std::ptr::null());
            z_session_drop(z_session_move(&mut session));
        }
    }
}

/// The advanced plane in the build that cannot listen, on either engine: an advanced publisher
/// that keeps a cache and an advanced subscriber that asks for its history, in one session whose
/// own puts and gets reach its own subscribers and queryables.
///
/// The subscriber is declared AFTER the publisher has put, so what it receives of those puts it
/// receives from the publisher's cache: the startup get the subscriber's host issues through the
/// engine's port, answered by the cache queryable the publisher's plane declared through the same
/// port. A put after the subscriber is declared then arrives live, and the order of all four is
/// the order they were put in. Neither engine is named here: the same host runs on both, which is
/// what this test is for.
#[cfg(all(
    feature = "advanced",
    feature = "local-subscriber",
    feature = "local-queryable"
))]
mod advanced {
    use super::*;
    use wz_capi_pico::advanced::{
        ze_advanced_publisher_loan, ze_advanced_publisher_move,
        ze_advanced_publisher_options_default, ze_advanced_publisher_options_t,
        ze_advanced_publisher_put, ze_advanced_subscriber_move,
        ze_advanced_subscriber_options_default, ze_advanced_subscriber_options_t,
        ze_declare_advanced_publisher, ze_declare_advanced_subscriber,
        ze_owned_advanced_publisher_t, ze_owned_advanced_subscriber_t,
        ze_undeclare_advanced_publisher, ze_undeclare_advanced_subscriber,
    };
    use wz_capi_pico::{
        z_bytes_to_string, z_owned_string_t, z_sample_payload, z_string_drop, z_string_loan,
        z_string_move,
    };

    struct Payloads(Mutex<Vec<String>>);

    unsafe extern "C" fn on_sample_record_payload(
        sample: *const z_loaned_sample_t,
        ctx: *mut c_void,
    ) {
        let payloads = &*(ctx as *const Payloads);
        let mut text: z_owned_string_t = std::mem::zeroed();
        if z_bytes_to_string(z_sample_payload(sample), &mut text) != Z_OK {
            return;
        }
        let string = z_string_loan(&text);
        let bytes =
            std::slice::from_raw_parts(z_string_data(string) as *const u8, z_string_len(string));
        payloads
            .0
            .lock()
            .unwrap()
            .push(String::from_utf8_lossy(bytes).into_owned());
        z_string_drop(z_string_move(&mut text));
    }

    unsafe extern "C" fn on_drop_payloads(ctx: *mut c_void) {
        drop(Arc::from_raw(ctx as *const Payloads));
    }

    unsafe fn advanced_put(publisher: &ze_owned_advanced_publisher_t, payload: &CStr) {
        let mut buf = std::mem::zeroed();
        assert_eq!(z_bytes_copy_from_str(&mut buf, payload.as_ptr()), Z_OK);
        assert_eq!(
            ze_advanced_publisher_put(
                ze_advanced_publisher_loan(publisher),
                z_bytes_move(&mut buf),
                std::ptr::null_mut(),
            ),
            Z_OK
        );
    }

    /// Step the session until `payloads` holds `count`, for at most ten seconds.
    unsafe fn wait_for(session: &z_owned_session_t, payloads: &Payloads, count: usize) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while payloads.0.lock().unwrap().len() < count && Instant::now() < deadline {
            step_for(session, Duration::from_millis(20));
        }
    }

    #[test]
    fn an_advanced_subscriber_is_handed_a_publishers_cache_and_then_its_live_puts_in_order() {
        let port = free_port();
        let _listener = Listener::start(port);
        let payloads = Arc::new(Payloads(Mutex::new(Vec::new())));
        // SAFETY: a fresh session, publisher and subscriber, all released before the function
        // returns; the closure's context is an `Arc` reference its drop callback releases.
        unsafe {
            let mut session = open_to(port);

            let mut ke: z_view_keyexpr_t = std::mem::zeroed();
            assert_eq!(z_view_keyexpr_from_str(&mut ke, c"demo/adv".as_ptr()), Z_OK);

            let mut publisher_options: ze_advanced_publisher_options_t = std::mem::zeroed();
            ze_advanced_publisher_options_default(&mut publisher_options);
            publisher_options.cache.is_enabled = true;
            publisher_options.cache.max_samples = 8;
            // Sequence numbers, which is what a subscriber orders and recovers by.
            publisher_options.sample_miss_detection.is_enabled = true;
            let mut publisher: ze_owned_advanced_publisher_t = std::mem::zeroed();
            assert_eq!(
                ze_declare_advanced_publisher(
                    z_session_loan(&session),
                    &mut publisher,
                    z_view_keyexpr_loan(&ke),
                    &publisher_options,
                ),
                Z_OK,
                "the advanced publisher was not declared"
            );
            for payload in [c"one", c"two", c"three"] {
                advanced_put(&publisher, payload);
            }
            step_for(&session, Duration::from_millis(100));

            let mut options: ze_advanced_subscriber_options_t = std::mem::zeroed();
            ze_advanced_subscriber_options_default(&mut options);
            options.history.is_enabled = true;
            options.history.max_samples = 8;
            options.recovery.is_enabled = true;
            let mut closure = std::mem::zeroed();
            assert_eq!(
                z_closure_sample(
                    &mut closure,
                    Some(on_sample_record_payload),
                    Some(on_drop_payloads),
                    Arc::into_raw(payloads.clone()) as *mut c_void,
                ),
                Z_OK
            );
            let mut subscriber: ze_owned_advanced_subscriber_t = std::mem::zeroed();
            assert_eq!(
                ze_declare_advanced_subscriber(
                    z_session_loan(&session),
                    &mut subscriber,
                    z_view_keyexpr_loan(&ke),
                    z_closure_sample_move(&mut closure),
                    &mut options,
                ),
                Z_OK,
                "the advanced subscriber was not declared"
            );

            wait_for(&session, &payloads, 3);
            assert_eq!(
                *payloads.0.lock().unwrap(),
                ["one", "two", "three"],
                "the history the publisher's cache gave, in the order it was put"
            );

            advanced_put(&publisher, c"four");
            wait_for(&session, &payloads, 4);
            assert_eq!(
                *payloads.0.lock().unwrap(),
                ["one", "two", "three", "four"],
                "a put after the declaration arrives live, behind the history"
            );

            assert_eq!(
                ze_undeclare_advanced_subscriber(ze_advanced_subscriber_move(&mut subscriber)),
                Z_OK
            );
            advanced_put(&publisher, c"five");
            step_for(&session, Duration::from_millis(100));
            assert_eq!(
                payloads.0.lock().unwrap().len(),
                4,
                "an undeclared subscriber hears nothing"
            );
            assert_eq!(
                ze_undeclare_advanced_publisher(ze_advanced_publisher_move(&mut publisher)),
                Z_OK
            );
            z_close(z_session_loan_mut(&mut session), std::ptr::null());
            z_session_drop(z_session_move(&mut session));
        }
    }
}
