// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#![cfg(all(
    feature = "storage-mgr-multi-storage-host",
    feature = "query-get",
    feature = "query-reply",
    feature = "transport-unicast",
    feature = "transport-link-tcp"
))]

//! The storage manager as a consumer outside this crate reaches it: a
//! [`RuntimeStorageManager`] hosts a named storage on a session, the storage
//! captures a put a PEER sends over a real link and answers that peer's query
//! with it, and the manager ends it by name.
//!
//! The manager's own tests (`storage_manager_service::tests`) drive it from
//! inside the crate on a recording session. This one goes through the public
//! path, `wz_runtime_tokio::storage_manager_service`, the way a host does, over a
//! loopback TCP link between two opened sessions: the storage's capture
//! subscriber and answering queryable are declared on the hosting session, and
//! the put and the query arrive from the other end of the link. What the peer
//! reads back is the storage's own answer, the behaviour a storage exists for.
//!
//! Polling on the condition (a reply carries the value), not a fixed settle
//! sleep, and the put and the query are re-sent each poll: the test needs the
//! storage's declarations to have reached the peer before either counts, and it
//! does not race that propagation. Once the storage holds the value the
//! condition is monotonic.

use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use tokio::net::TcpListener;

use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{PublishOptions, QueryOptions, TokioSession};
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{
    accept_and_open_session, connect_and_open_session, DialConfig, DialedLink, DEFAULT_OPEN_TICK_MS,
};
use wz_runtime_tokio::storage_manager_service::RuntimeStorageManager;
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::locator::parse_any_locator;
use wz_session_core::reply_sink::ReplyView;
use wz_session_core::session_timeouts::SessionTimeouts;
use wz_session_core::storage_config::StorageConfig;
use wz_storage::storage_volume::MemoryVolume;

const ITER_CAP: usize = 64;
const STORAGE: &str = "s1";
const STORAGE_KEYEXPR: &str = "demo/**";
const DATA_KEY: &str = "demo/x";
const DATA_VALUE: &[u8] = b"value-x-put-by-the-peer";

/// A storage the manager hosts on one session captures a put the peer session
/// sends over a loopback TCP link and answers the peer's query with it, and
/// `remove_storage` ends it by name.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_storage_the_manager_hosts_answers_a_peer_with_its_put_and_ends_by_name() {
    let zid_host = vec![0x0A; 4];
    let zid_peer = vec![0x0B; 4];

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let host_open = {
        let zid_host = zid_host.clone();
        async move {
            let (stream, _peer) = listener.accept().await.expect("accept");
            let mut params = fixture_session_init_params();
            params.zid = zid_host;
            accept_and_open_session(
                DialedLink::Tcp(stream),
                params,
                TokioTime::new(),
                Some(ITER_CAP),
                DEFAULT_OPEN_TICK_MS,
            )
            .await
            .expect("the hosting session (acceptor) reaches Established")
        }
    };
    let peer_open = async move {
        let locator = parse_any_locator(&format!("tcp/{addr}")).expect("parse loopback locator");
        let mut params = fixture_session_init_params();
        params.zid = zid_peer;
        connect_and_open_session(
            locator,
            params,
            &DialConfig::default(),
            TokioTime::new(),
            Some(ITER_CAP),
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        .expect("the peer session (initiator) reaches Established")
    };
    let (mut opened_host, mut opened_peer) = tokio::join!(host_open, peer_open);
    let timeouts = SessionTimeouts::spec_defaults();

    // ── The host: a manager with the memory volume hosts one named storage.
    let host = TokioSession::new(
        opened_host.actions.clone(),
        Arc::new(wz_runtime_tokio::sync::PlainMutex::new(
            ApplicationLayerObserver::new(),
        )),
        Arc::new(opened_host.clock),
    );
    let mut manager = RuntimeStorageManager::new();
    manager.register_volume("mem", Box::new(MemoryVolume));
    manager
        .add_storage(
            &host,
            &StorageConfig::new(STORAGE, STORAGE_KEYEXPR, "mem"),
            zid_host.clone(),
        )
        .expect("the manager hosts the storage on the memory volume");
    assert_eq!(manager.storage_names().collect::<Vec<_>>(), vec![STORAGE]);
    assert!(
        manager.storage(STORAGE).is_some(),
        "the hosted storage is held by its name"
    );
    let host_drive = host.clone();
    let drive_host = drive_session_until_terminal(
        &mut opened_host.inbound,
        &opened_host.actions,
        &mut opened_host.engine,
        None,
        &opened_host.clock,
        &timeouts,
        move |event| host_drive.dispatch_iteration_event(event),
    );

    // ── The peer: publishes under the storage's key space.
    let peer = TokioSession::new(
        opened_peer.actions.clone(),
        Arc::new(wz_runtime_tokio::sync::PlainMutex::new(
            ApplicationLayerObserver::new(),
        )),
        Arc::new(opened_peer.clock),
    );
    let peer_drive = peer.clone();
    let drive_peer = drive_session_until_terminal(
        &mut opened_peer.inbound,
        &opened_peer.actions,
        &mut opened_peer.engine,
        None,
        &opened_peer.clock,
        &timeouts,
        move |event| peer_drive.dispatch_iteration_event(event),
    );

    let replies: Arc<StdMutex<Vec<Vec<u8>>>> = Arc::new(StdMutex::new(Vec::new()));
    let scenario = {
        let replies = replies.clone();
        async move {
            // Every query handle is held, so a pending query is not torn down.
            let mut handles = Vec::new();
            for _ in 0..120 {
                peer.publish(DATA_KEY, DATA_VALUE, PublishOptions::put())
                    .expect("the peer's put is accepted");
                let replies_cb = replies.clone();
                if let Ok(handle) = peer.query(
                    DATA_KEY,
                    QueryOptions::get(),
                    move |view: &dyn ReplyView| {
                        replies_cb.lock().unwrap().push(view.payload().to_vec());
                    },
                    |_rid: u64| {},
                ) {
                    handles.push(handle);
                }
                for _ in 0..4 {
                    if replies
                        .lock()
                        .unwrap()
                        .iter()
                        .any(|p| p.as_slice() == DATA_VALUE)
                    {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            }
            panic!("the hosted storage never answered with the peer's put within the ~12s budget");
        }
    };
    tokio::select! {
        _ = drive_host => panic!("the hosting session's drive loop ended unexpectedly"),
        _ = drive_peer => panic!("the peer session's drive loop ended unexpectedly"),
        _ = scenario => {}
    }

    // ── Every reply the peer read is the storage's answer: the value it put.
    assert!(
        replies
            .lock()
            .unwrap()
            .iter()
            .all(|p| p.as_slice() == DATA_VALUE),
        "no reply carried anything but the stored value"
    );

    // ── The manager ends the storage by name; a second removal finds nothing.
    assert!(
        manager.remove_storage(STORAGE),
        "a hosted storage is removed"
    );
    assert!(manager.storage(STORAGE).is_none(), "gone after removal");
    assert!(
        !manager.remove_storage(STORAGE),
        "removing an absent storage reports false"
    );
    assert!(manager.is_empty());
}
