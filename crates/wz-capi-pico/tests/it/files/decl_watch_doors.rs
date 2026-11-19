// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! The declaration watch driven through the C doors (`wz_ext_decl_watch_declare`,
//! `wz_ext_decl_watch_drop`): two peers over loopback, one that listens and watches and one that
//! dials it and declares.
//!
//! What is held: each watch is told the declaration of its own kind of entity with the key and
//! the declaring peer's zenoh id (with `remote-declaration-watch`; an unknown peer without it),
//! and the undeclaration under the same id; with `declarations-synced-event` each watch is told
//! once per establishment that the peer has sent what it held, and never without it; a dropped
//! watch has run the program's drop and is told nothing more; a refused or closed watch runs the
//! program's drop on its own.

#![cfg(all(
    feature = "engine-tokio",
    feature = "peer",
    feature = "queryable",
    feature = "liveliness",
    any(
        feature = "remote-declaration-watch",
        feature = "declarations-synced-event"
    )
))]

use std::ffi::{c_void, CStr, CString};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wz_capi_pico::decl_watch::{
    wz_ext_decl_event_t, wz_ext_decl_watch_declare, wz_ext_decl_watch_drop,
    wz_ext_owned_decl_watch_t, WZ_EXT_DECL_DECLARED, WZ_EXT_DECL_QUERYABLE, WZ_EXT_DECL_SUBSCRIBER,
    WZ_EXT_DECL_SYNCED, WZ_EXT_DECL_TOKEN, WZ_EXT_DECL_UNDECLARED,
};
use wz_capi_pico::liveliness::{
    z_liveliness_declare_token, z_liveliness_token_move, z_liveliness_undeclare_token,
    z_owned_liveliness_token_t,
};
use wz_capi_pico::result::{Z_ERR_INVALID, Z_ERR_SESSION_CLOSED};
use wz_capi_pico::zid::z_info_zid;
use wz_capi_pico::{
    z_close, z_closure_query, z_closure_query_move, z_closure_sample, z_closure_sample_move,
    z_config_default, z_config_loan_mut, z_config_move, z_declare_queryable, z_declare_subscriber,
    z_loaned_query_t, z_loaned_sample_t, z_open, z_owned_config_t, z_owned_queryable_t,
    z_owned_session_t, z_owned_subscriber_t, z_queryable_move, z_session_drop, z_session_loan,
    z_session_loan_mut, z_session_move, z_subscriber_move, z_undeclare_queryable,
    z_undeclare_subscriber, z_view_keyexpr_from_str, z_view_keyexpr_loan, z_view_keyexpr_t,
    zp_config_insert, Z_CONFIG_CONNECT_KEY, Z_CONFIG_LISTEN_KEY, Z_CONFIG_MODE_KEY, Z_OK,
};
use wz_runtime_tokio_test_support::free_port;

/// How long any wait below gives the property before it is called unmet.
const BARRIER: Duration = Duration::from_secs(10);

/// One event as the callback read it, copied out of the call.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Seen {
    kind: u8,
    entity: u8,
    id: u64,
    key: Option<String>,
    zid_len: u8,
    zid: [u8; 16],
}

/// What a watch's callback and drop write into.
#[derive(Clone, Default)]
struct Log {
    seen: Arc<Mutex<Vec<Seen>>>,
    drops: Arc<AtomicUsize>,
}

impl Log {
    fn events(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    fn of_kind(&self, kind: u8) -> Vec<Seen> {
        self.events()
            .into_iter()
            .filter(|e| e.kind == kind)
            .collect()
    }

    /// The declaration of `key`, once one has been told.
    fn declared(&self, key: &str) -> Option<Seen> {
        self.of_kind(WZ_EXT_DECL_DECLARED)
            .into_iter()
            .find(|e| e.key.as_deref() == Some(key))
    }

    fn undeclared(&self, id: u64) -> Option<Seen> {
        self.of_kind(WZ_EXT_DECL_UNDECLARED)
            .into_iter()
            .find(|e| e.id == id)
    }

    fn drops(&self) -> usize {
        self.drops.load(Ordering::SeqCst)
    }
}

unsafe extern "C" fn on_event(context: *mut c_void, event: *const wz_ext_decl_event_t) {
    let log = &*(context as *const Log);
    let event = &*event;
    let key = if event.keyexpr.is_null() {
        None
    } else {
        let bytes = std::slice::from_raw_parts(event.keyexpr.cast::<u8>(), event.keyexpr_len);
        Some(String::from_utf8_lossy(bytes).into_owned())
    };
    log.seen.lock().unwrap().push(Seen {
        kind: event.kind,
        entity: event.entity,
        id: event.id,
        key,
        zid_len: event.zid_len,
        zid: event.zid,
    });
}

unsafe extern "C" fn on_drop(context: *mut c_void) {
    let log = Box::from_raw(context as *mut Log);
    log.drops.fetch_add(1, Ordering::SeqCst);
}

unsafe extern "C" fn on_sample(_sample: *const z_loaned_sample_t, _context: *mut c_void) {}
unsafe extern "C" fn on_query(_query: *const z_loaned_query_t, _context: *mut c_void) {}

/// A context the doors take: the log's handles, boxed for `on_drop` to free.
fn context_of(log: &Log) -> *mut c_void {
    Box::into_raw(Box::new(log.clone())).cast::<c_void>()
}

/// Declare a watch of `entity` on `session` into a fresh handle, and the code the door answered.
unsafe fn watch(
    session: &z_owned_session_t,
    entity: u8,
    log: &Log,
) -> (wz_ext_owned_decl_watch_t, i8) {
    let mut watch: wz_ext_owned_decl_watch_t = std::mem::zeroed();
    let rc = wz_ext_decl_watch_declare(
        z_session_loan(session),
        &mut watch,
        entity,
        Some(on_event),
        Some(on_drop),
        context_of(log),
    );
    (watch, rc)
}

unsafe fn open(entries: &[(u8, &CStr)]) -> z_owned_session_t {
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    for (key, value) in entries {
        assert_eq!(
            zp_config_insert(z_config_loan_mut(&mut cfg), *key, value.as_ptr()),
            Z_OK
        );
    }
    let mut session: z_owned_session_t = std::mem::zeroed();
    assert_eq!(
        z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()),
        Z_OK
    );
    session
}

/// A peer that dials `endpoint`: a peer, so that it ends what it replays to the listener with the
/// end of its initial declarations, as two peers do.
unsafe fn open_declarer(endpoint: &CStr) -> z_owned_session_t {
    open(&[
        (Z_CONFIG_CONNECT_KEY, endpoint),
        (Z_CONFIG_MODE_KEY, c"peer"),
    ])
}

unsafe fn close(session: &mut z_owned_session_t) {
    z_close(z_session_loan_mut(session), std::ptr::null());
    z_session_drop(z_session_move(session));
}

unsafe fn keyexpr(key: &CStr) -> z_view_keyexpr_t {
    let mut view: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut view, key.as_ptr()), Z_OK);
    view
}

/// Poll `holds` until it does or [`BARRIER`] has passed.
fn until(what: &str, mut holds: impl FnMut() -> bool) {
    let deadline = Instant::now() + BARRIER;
    while !holds() {
        assert!(Instant::now() < deadline, "never: {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// The three entities a peer declares, one of each kind a watch is of.
struct Declared {
    subscriber: z_owned_subscriber_t,
    queryable: z_owned_queryable_t,
    token: z_owned_liveliness_token_t,
}

unsafe fn declare_all(session: &z_owned_session_t) -> Declared {
    let mut subscriber: z_owned_subscriber_t = std::mem::zeroed();
    let mut sample_closure = std::mem::zeroed();
    assert_eq!(
        z_closure_sample(
            &mut sample_closure,
            Some(on_sample),
            None,
            std::ptr::null_mut()
        ),
        Z_OK
    );
    let sub_key = keyexpr(c"demo/watch/sub");
    assert_eq!(
        z_declare_subscriber(
            z_session_loan(session),
            &mut subscriber,
            z_view_keyexpr_loan(&sub_key),
            z_closure_sample_move(&mut sample_closure),
            std::ptr::null(),
        ),
        Z_OK
    );

    let mut queryable: z_owned_queryable_t = std::mem::zeroed();
    let mut query_closure = std::mem::zeroed();
    assert_eq!(
        z_closure_query(
            &mut query_closure,
            Some(on_query),
            None,
            std::ptr::null_mut()
        ),
        Z_OK
    );
    let qbl_key = keyexpr(c"demo/watch/qbl");
    assert_eq!(
        z_declare_queryable(
            z_session_loan(session),
            &mut queryable,
            z_view_keyexpr_loan(&qbl_key),
            z_closure_query_move(&mut query_closure),
            std::ptr::null(),
        ),
        Z_OK
    );

    let mut token: z_owned_liveliness_token_t = std::mem::zeroed();
    let tok_key = keyexpr(c"demo/watch/tok");
    assert_eq!(
        z_liveliness_declare_token(
            z_session_loan(session),
            &mut token,
            z_view_keyexpr_loan(&tok_key),
            std::ptr::null(),
        ),
        Z_OK
    );
    Declared {
        subscriber,
        queryable,
        token,
    }
}

/// Each watch is told its own kind of entity as the peer declares and retracts it, named by the
/// peer that declared it, and the end of the peer's initial declarations once per establishment.
#[test]
fn a_watch_hears_its_kind_declared_and_undeclared_by_the_peer_that_declared_it() {
    let synced_built = cfg!(feature = "declarations-synced-event");
    let peer_built = cfg!(feature = "remote-declaration-watch");
    let port = free_port();
    let endpoint = CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    // SAFETY: fresh configs, sessions and handles, each closed or dropped before the test ends;
    // every context is a box `on_drop` frees once.
    unsafe {
        let mut watcher = open(&[(Z_CONFIG_LISTEN_KEY, endpoint.as_c_str())]);
        let logs = [Log::default(), Log::default(), Log::default()];
        let kinds = [
            (WZ_EXT_DECL_SUBSCRIBER, "demo/watch/sub"),
            (WZ_EXT_DECL_QUERYABLE, "demo/watch/qbl"),
            (WZ_EXT_DECL_TOKEN, "demo/watch/tok"),
        ];
        let mut watches = Vec::new();
        for ((entity, _), log) in kinds.iter().zip(&logs) {
            let (handle, rc) = watch(&watcher, *entity, log);
            assert_eq!(rc, Z_OK, "the watch of entity {entity} is declared");
            watches.push(handle);
        }

        // The peer dials after the watches are declared, so each hears it from its first message.
        let mut declarer = open_declarer(&endpoint);
        let declarer_zid = z_info_zid(z_session_loan(&declarer)).id;
        if synced_built {
            for log in &logs {
                until(
                    "each watch is told the peer's initial declarations are final",
                    || !log.of_kind(WZ_EXT_DECL_SYNCED).is_empty(),
                );
            }
        }

        let mut declared = declare_all(&declarer);
        for ((entity, key), log) in kinds.iter().zip(&logs) {
            until(
                &format!("the watch of {key} is told its declaration"),
                || log.declared(key).is_some(),
            );
            let seen = log.declared(key).unwrap();
            assert_eq!(seen.entity, *entity, "the record says what the watch is of");
            assert!(seen.key.as_deref().is_some_and(|k| k == *key));
            if peer_built {
                assert!(seen.zid_len > 0, "the peer is named: {seen:?}");
                assert_eq!(
                    seen.zid, declarer_zid,
                    "by the zenoh id of the session that declared"
                );
            } else {
                assert_eq!(
                    seen.zid_len, 0,
                    "without the capability the peer is not named"
                );
                assert_eq!(seen.zid, [0u8; 16]);
            }
        }
        // Every kind has been told to its own watch by now, so a watch told another kind's
        // declaration would show it here.
        for ((entity, key), log) in kinds.iter().zip(&logs) {
            for (_, other) in kinds.iter().filter(|(e, _)| e != entity) {
                assert!(
                    log.declared(other).is_none(),
                    "the watch of {key} was told of {other}"
                );
            }
        }

        z_undeclare_subscriber(z_subscriber_move(&mut declared.subscriber));
        z_undeclare_queryable(z_queryable_move(&mut declared.queryable));
        z_liveliness_undeclare_token(z_liveliness_token_move(&mut declared.token));
        for ((_, key), log) in kinds.iter().zip(&logs) {
            let id = log.declared(key).unwrap().id;
            until(
                &format!("the watch of {key} is told its undeclaration"),
                || log.undeclared(id).is_some(),
            );
            let seen = log.undeclared(id).unwrap();
            assert_eq!(seen.key, None, "an undeclaration names no key");
            if peer_built {
                assert_eq!(seen.zid, declarer_zid);
            } else {
                assert_eq!(seen.zid_len, 0);
            }
        }

        // A second establishment: the first peer leaves and another dials. With the capability
        // each watch is told the end of its initial declarations once more, named by the new
        // peer; without it, never.
        close(&mut declarer);
        let mut second = open_declarer(&endpoint);
        let second_zid = z_info_zid(z_session_loan(&second)).id;
        if synced_built {
            for log in &logs {
                until(
                    "each watch is told the second peer's declarations are final",
                    || log.of_kind(WZ_EXT_DECL_SYNCED).len() >= 2,
                );
            }
            // Settle: a third would come only from a repeated final, which is not told.
            std::thread::sleep(Duration::from_millis(300));
            for log in &logs {
                let synced = log.of_kind(WZ_EXT_DECL_SYNCED);
                assert_eq!(synced.len(), 2, "once per establishment: {synced:?}");
                assert!(synced.iter().all(|e| e.id == 0 && e.key.is_none()));
                if peer_built {
                    assert_eq!(synced[0].zid, declarer_zid);
                    assert_eq!(synced[1].zid, second_zid);
                }
            }
        } else {
            std::thread::sleep(Duration::from_millis(300));
            for log in &logs {
                assert!(
                    log.of_kind(WZ_EXT_DECL_SYNCED).is_empty(),
                    "a build without declarations-synced-event tells no sync"
                );
            }
        }

        // Dropped, a watch has run the program's drop once by the time the call returns, and is
        // told nothing of what the peer declares after.
        for (handle, log) in watches.iter_mut().zip(&logs) {
            assert_eq!(log.drops(), 0);
            wz_ext_decl_watch_drop(handle);
            assert_eq!(log.drops(), 1, "the drop ran before the door returned");
            wz_ext_decl_watch_drop(handle);
            assert_eq!(
                log.drops(),
                1,
                "a dropped watch is empty and drops nothing again"
            );
        }
        let told = logs
            .iter()
            .map(|log| log.events().len())
            .collect::<Vec<_>>();
        let mut after = declare_all(&second);
        std::thread::sleep(Duration::from_millis(500));
        assert_eq!(
            logs.iter()
                .map(|log| log.events().len())
                .collect::<Vec<_>>(),
            told,
            "a dropped watch is told nothing"
        );

        z_undeclare_subscriber(z_subscriber_move(&mut after.subscriber));
        z_undeclare_queryable(z_queryable_move(&mut after.queryable));
        z_liveliness_undeclare_token(z_liveliness_token_move(&mut after.token));
        close(&mut second);
        close(&mut watcher);
    }
}

/// A watch of subscribers or queryables declared after the peer's declarations arrived is told
/// them first, as declarations of the peer that holds them, each once, and then the peer's
/// retraction of the same id: the order a watch declared before the link would have heard.
#[test]
fn a_watch_declared_after_the_peer_declared_is_told_what_the_peer_holds_first() {
    let peer_built = cfg!(feature = "remote-declaration-watch");
    let port = free_port();
    let endpoint = CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    // SAFETY: as the test above.
    unsafe {
        let mut watcher = open(&[(Z_CONFIG_LISTEN_KEY, endpoint.as_c_str())]);
        // The witness: a watch declared before the link, which says when the declarations have
        // arrived, so the watches declared after are declared after them.
        let witness = Log::default();
        let (mut witness_watch, rc) = watch(&watcher, WZ_EXT_DECL_QUERYABLE, &witness);
        assert_eq!(rc, Z_OK);
        let mut declarer = open_declarer(&endpoint);
        let declarer_zid = z_info_zid(z_session_loan(&declarer)).id;
        let mut declared = declare_all(&declarer);
        until("the witness hears the queryable", || {
            witness.declared("demo/watch/qbl").is_some()
        });
        // The subscriber travels the same link ahead of the queryable, so it has arrived too.

        let late = [
            (WZ_EXT_DECL_SUBSCRIBER, "demo/watch/sub", Log::default()),
            (WZ_EXT_DECL_QUERYABLE, "demo/watch/qbl", Log::default()),
        ];
        let mut watches = Vec::new();
        for (entity, _, log) in &late {
            let (handle, rc) = watch(&watcher, *entity, log);
            assert_eq!(rc, Z_OK);
            watches.push(handle);
        }
        for (entity, key, log) in &late {
            until(&format!("the late watch of {key} is told it"), || {
                log.declared(key).is_some()
            });
            let seen = log.declared(key).unwrap();
            assert_eq!(seen.entity, *entity);
            if peer_built {
                assert_eq!(seen.zid, declarer_zid, "named by the peer that holds it");
            }
        }
        let held_id = late[1].2.declared("demo/watch/qbl").unwrap().id;
        assert_eq!(
            held_id,
            witness.declared("demo/watch/qbl").unwrap().id,
            "the id the peer declared it under, as the live watch heard it"
        );

        z_undeclare_subscriber(z_subscriber_move(&mut declared.subscriber));
        z_undeclare_queryable(z_queryable_move(&mut declared.queryable));
        z_liveliness_undeclare_token(z_liveliness_token_move(&mut declared.token));
        for (_, key, log) in &late {
            let id = log.declared(key).unwrap().id;
            until(
                &format!("the late watch of {key} is told its retraction"),
                || log.undeclared(id).is_some(),
            );
            let events = log.events();
            let at_declared = events
                .iter()
                .position(|e| e.kind == WZ_EXT_DECL_DECLARED && e.id == id);
            let at_undeclared = events
                .iter()
                .position(|e| e.kind == WZ_EXT_DECL_UNDECLARED && e.id == id);
            assert!(
                at_declared < at_undeclared,
                "held first, then live: {events:?}"
            );
            assert_eq!(
                events
                    .iter()
                    .filter(|e| e.kind == WZ_EXT_DECL_DECLARED && e.id == id)
                    .count(),
                1,
                "told once"
            );
        }

        for handle in &mut watches {
            wz_ext_decl_watch_drop(handle);
        }
        wz_ext_decl_watch_drop(&mut witness_watch);
        close(&mut declarer);
        close(&mut watcher);
    }
}

/// A watch of no kind is refused before anything is held, a closed session refuses one, and a
/// watch the session's close released runs its drop at the close; each runs the program's drop
/// once.
#[test]
fn a_refused_watch_and_a_closed_session_run_the_programs_drop_once() {
    let port = free_port();
    let endpoint = CString::new(format!("tcp/127.0.0.1:{port}")).unwrap();
    // SAFETY: as the test above.
    unsafe {
        let mut session = open(&[(Z_CONFIG_LISTEN_KEY, endpoint.as_c_str())]);

        let refused = Log::default();
        let (handle, rc) = watch(&session, 3, &refused);
        assert_eq!(
            rc, Z_ERR_INVALID,
            "an entity code that is none of the three"
        );
        assert!(handle._val.is_null(), "a refused watch is left empty");
        assert_eq!(
            refused.drops(),
            1,
            "and its context was dropped before the door returned"
        );

        let held = Log::default();
        let (mut live, rc) = watch(&session, WZ_EXT_DECL_SUBSCRIBER, &held);
        assert_eq!(rc, Z_OK);
        assert_eq!(held.drops(), 0, "a declared watch holds its context");

        z_close(z_session_loan_mut(&mut session), std::ptr::null());
        assert_eq!(held.drops(), 1, "the close let go of the watch's context");
        wz_ext_decl_watch_drop(&mut live);
        assert_eq!(
            held.drops(),
            1,
            "and the drop after it has nothing left to drop"
        );

        let late = Log::default();
        let (_, rc) = watch(&session, WZ_EXT_DECL_TOKEN, &late);
        assert_eq!(rc, Z_ERR_SESSION_CLOSED, "a closed session takes no watch");
        assert_eq!(late.drops(), 1);

        z_session_drop(z_session_move(&mut session));
    }
}
