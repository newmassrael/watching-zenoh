// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y210 — REVERSE FOREIGN-INTEROP Put METADATA: a real zenoh-pico
//! `z_pub_attachment` client publishes a `Put` carrying all three body-metadata
//! dimensions at once, and a watching-zenoh subscriber DECODES each off the
//! delivered `Sample`. This is the reverse of the wz->pico legs (R311y207
//! encoding / R311y208 timestamp / R311y209 attachment): there wz was the
//! emitter and pico the decoder; here pico is the emitter and wz the decoder.
//!
//! ## What pico emits (z_pub_attachment.c:76-126)
//!
//! One `z_publisher_put` per iteration with:
//!   - attachment: a `ze_serializer` kv-sequence `[("source","C"),("index",N)]`
//!     (lines 109-117) — the exact wire form wz's `serialize_kv_attachment`
//!     produces, here decoded back by `deserialize_kv_attachment`.
//!   - encoding: `zenoh/string;utf8` (line 120). `zenoh/string` is pico
//!     encoding id 1 (`vendor/zenoh-pico/src/api/encoding.c:36`
//!     `ENCODING_CONSTANT_MACRO(ZENOH_STRING, ..., 1)`), and the wz wire form
//!     is `packed_id = id << 1 | schema_bit`, so a schema-bearing id-1 encoding
//!     is `packed_id = (1 << 1) | 1 = 3` with `schema = "utf8"`. This exercises
//!     wz's encoding-WITH-schema decode, which the schemaless text/plain of
//!     R311y207 did not.
//!   - timestamp: a real ntp64 from `z_timestamp_new` (lines 90-91,124). The
//!     value is pico's clock (non-deterministic), so the assertion is presence.
//!
//! Running with `-n 1` makes pico publish exactly once (idx=0, so the index
//! value is the deterministic "0") then close, so the wz drive loop reaches a
//! terminal state after the single Put — the same one-shot-close pattern the
//! sibling `wz_reassembles_pico_fragment_tx.rs` relies on (by TCP ordering the
//! Put is processed before the peer-close in the same loop, race-free).
//!
//! ## Why one test covers all three
//!
//! `z_pub_attachment` bundles attachment + encoding + timestamp on a single
//! Put, so one delivered `Sample` proves the whole reverse metadata track. The
//! wz-side field readback (impossible to get from a pico SUBSCRIBER, which is
//! why the wz->pico legs needed pico's stdout) is exactly what makes wz-as-
//! decoder assertable here.

use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use tokio::net::TcpListener;

use wz_integration_tests::common::{zenoh_pico_cli_binary, ChildGuard};
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::runtime_impl::TokioTime;
use wz_runtime_tokio::session::{SubscribeOptions, TokioSession};
use wz_runtime_tokio::session_glue::drive_session_until_terminal;
use wz_runtime_tokio::session_open::{accept_and_open_session, DialedLink, DEFAULT_OPEN_TICK_MS};
use wz_runtime_tokio::sync::Mutex;
use wz_runtime_tokio_test_support::fixture_session_init_params;
use wz_session_core::attachment::deserialize_kv_attachment;
use wz_session_core::sample::EncodingHint;
use wz_session_core::session_timeouts::SessionTimeouts;

const ITER_CAP: usize = 4096;
const KEYEXPR: &str = "demo/att";
// zenoh/string = pico encoding id 1; wire packed_id = id << 1 | schema_bit.
const ZENOH_STRING_WITH_SCHEMA_PACKED_ID: u32 = 3;

/// Metadata decoded from the single delivered Sample.
#[derive(Default)]
struct CapturedMeta {
    keyexpr_ok: bool,
    attachment_pairs: Option<Vec<(Vec<u8>, Vec<u8>)>>,
    encoding: Option<EncodingHint>,
    timestamp_present: bool,
    fired: usize,
}

// wz-proves: pubsub-attachment pico->wz
// wz-proves: attachment-bytes pico->wz
// wz-proves: pubsub-encoding pico->wz partial
// wz-proves: pubsub-timestamp pico->wz partial
// wz-proves: pubsub-put pico->wz
// wz-proves: declare-subscriber wz->pico
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "binary-dep e2e (zenoh-pico CLI z_pub_attachment); Layer E runs via --ignored"]
async fn wz_sub_decodes_pico_pub_attachment_metadata() {
    let z_pub_attachment = zenoh_pico_cli_binary("z_pub_attachment");

    // wz acceptor binds first so pico's client dial lands in the listen
    // backlog and `accept()` resolves it.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind wz acceptor");
    let addr = listener.local_addr().expect("local_addr");

    // Foreign initiator: zenoh-pico z_pub_attachment in client mode, ONE Put
    // (`-n 1` -> idx=0) then close. It declares a publisher, sleeps 1s, Puts
    // (attachment + encoding + timestamp), and exits.
    let mut z_pub_child = ChildGuard::wrap(
        "z_pub_attachment (zenoh-pico initiator)",
        Command::new(&z_pub_attachment)
            .args([
                "-k",
                KEYEXPR,
                "-e",
                &format!("tcp/{addr}"),
                "-m",
                "client",
                "-n",
                "1",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn zenoh-pico z_pub_attachment"),
    );

    // wz acceptor handshake (default batch — a small metadata Put does not
    // fragment). Same accept path the fragment interop test uses.
    let (stream, _peer) = listener.accept().await.expect("accept pico client");
    let params = fixture_session_init_params();
    let mut opened = accept_and_open_session(
        DialedLink::Tcp(stream),
        params,
        TokioTime::new(),
        Some(ITER_CAP),
        DEFAULT_OPEN_TICK_MS,
    )
    .await
    .expect("wz acceptor reaches Established against the pico z_pub_attachment client");

    // wz subscriber decodes each metadata field off the delivered Sample. The
    // subscription is declared through the full `TokioSession` (NOT a bare
    // local `observer.subscribers.register`) so its `Declare(DeclSubscriber)`
    // ships on the wire. pico's `z_pub_attachment` calls `z_declare_publisher`,
    // which arms a write-filter (`_z_write_filter_create`, api.c:1423) that
    // SUPPRESSES the Put — `z_publisher_put` gates on `!_z_write_filter_active`
    // (api.c:1525) — until pico observes a matching subscriber declaration
    // (filtering.c:199-208). A local-only register never emits that
    // declaration, so pico would filter every Put and nothing is delivered
    // (correct zenoh matching-optimisation, not a wz bug — `z_put` carries no
    // such filter, which is why the sibling fragment-RX e2e needs none). The
    // remote-declare drive shape mirrors `namespace_matching_e2e.rs`.
    //
    // Two preconditions this test depends on (both hard-fail to fired=0, never
    // a false pass, if violated):
    //   - EXACT keyexpr: pico's CLIENT write-filter interest is AGGREGATE and
    //     matches via `_z_keyexpr_equals` (filtering.c:234 / interest.c:274),
    //     so the subscriber must name the IDENTICAL literal `demo/att`; a
    //     wildcard would not open the filter.
    //   - pico MULTI-THREAD: relies on pico built with `Z_FEATURE_MULTI_THREAD`
    //     (the CMake default) so pico's background read task processes the wz
    //     `Declare(DeclSubscriber)` during the publisher's 1s pre-put sleep,
    //     opening the filter before the Put.
    let captured = Arc::new(StdMutex::new(CapturedMeta::default()));
    let session = TokioSession::new(
        opened.actions.clone(),
        Arc::new(Mutex::new(ApplicationLayerObserver::new())),
        Arc::new(opened.clock),
    );
    // Bound to a named `_subscriber` (NOT `_`) so the RAII handle stays alive
    // through the drive; a `_`-drop would emit `Declare(UndeclSubscriber)`
    // immediately and re-arm pico's filter before the Put.
    let _subscriber = {
        let captured = captured.clone();
        session
            .declare_subscriber(KEYEXPR, SubscribeOptions::default(), move |sample| {
                let mut c = captured.lock().unwrap();
                c.keyexpr_ok = sample.keyexpr() == KEYEXPR;
                c.attachment_pairs = sample.attachment().and_then(deserialize_kv_attachment);
                c.encoding = sample.encoding().cloned();
                c.timestamp_present = sample.timestamp().is_some();
                c.fired += 1;
            })
            .expect("wz declares the demo/att subscriber (emits Declare(DeclSubscriber))")
    };

    // Continuous drive (None) until the session terminates (pico's one-shot
    // `-n 1` closes after the single Put). A 12s cap guards a stuck pico.
    let timeouts = SessionTimeouts::spec_defaults();
    let session_drive = session.clone();
    let drive = drive_session_until_terminal(
        &mut opened.inbound,
        &opened.actions,
        &mut opened.engine,
        None,
        &opened.clock,
        &timeouts,
        move |event| session_drive.dispatch_iteration_event(event),
    );

    tokio::select! {
        _ = drive => {}
        _ = tokio::time::sleep(Duration::from_secs(12)) => {
            panic!(
                "wz drive did not terminate within 12s — pico z_pub_attachment never published+closed?\n\
                 (if delivery never fired, a plain wz acceptor may not be routing the pico client's \
                 declared-publisher Put to the local subscriber)"
            )
        }
    }

    let _ = z_pub_child.child_mut().kill();
    let _ = z_pub_child.child_mut().wait();

    let c = captured.lock().unwrap();
    assert_eq!(
        c.fired, 1,
        "exactly one Sample delivered from pico's single (-n 1) Put"
    );
    assert!(
        c.keyexpr_ok,
        "the delivered Sample carries the published keyexpr"
    );
    assert_eq!(
        c.attachment_pairs.as_deref(),
        Some(
            &[
                (b"source".to_vec(), b"C".to_vec()),
                (b"index".to_vec(), b"0".to_vec())
            ][..]
        ),
        "wz deserialize_kv_attachment recovers pico's ze_serializer kv-pairs \
         [(source,C),(index,0)] (idx=0 from -n 1)"
    );
    let enc = c
        .encoding
        .as_ref()
        .expect("the zenoh/string;utf8 encoding must decode off the wire (None = dropped)");
    assert_eq!(
        enc.packed_id, ZENOH_STRING_WITH_SCHEMA_PACKED_ID,
        "zenoh/string (id 1) with a schema -> packed_id (1<<1)|1 = 3"
    );
    assert_eq!(
        enc.schema.as_deref(),
        Some("utf8"),
        "the schema suffix ;utf8 must decode as the EncodingHint schema string"
    );
    assert!(
        c.timestamp_present,
        "pico's z_timestamp_new ntp64 must surface as Some on the delivered Sample"
    );
}
