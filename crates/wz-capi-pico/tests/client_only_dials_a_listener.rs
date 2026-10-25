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
#[cfg(any(feature = "query", feature = "queryable", feature = "liveliness"))]
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
        fn ask(&mut self, key: &str) {
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
    unsafe fn asked(
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
    unsafe fn querier(
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
    unsafe fn matches(querier: &z_owned_querier_t) -> bool {
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
