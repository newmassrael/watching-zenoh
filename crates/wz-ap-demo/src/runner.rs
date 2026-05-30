// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// wz-ap-demo — demo orchestration entry point + helper sub-fns.
//
// R287 — extracted from `main.rs` as Phase 3 of the R281 module
// decomposition carry. `run_demo` is the orchestration entry point
// the binary's `fn main` invokes after argv parsing; this module
// decomposes the original 683-line body into a thin assembly +
// six private sub-fns (R230 §5.P inventory pattern):
//
//   * `establish_link` — TCP setup; Acceptor binds + accepts,
//     Initiator dials.
//   * `link_pipeline::wire_tcp_stream` (R311ev) — stream split +
//     writer task spawn + `TcpReadDriver` / `TcpWriteDriver`
//     construction, consumed from the library (was the demo-local
//     `wire_link_pipeline` before R311ev lifted it into wz-runtime-tokio).
//   * `install_observer_callbacks` — remote-* registry + reply
//     registry installs that run before drive_session starts.
//   * `install_session_handles` — local subscriber / queryable /
//     liveliness-subscriber RAII handle registration (Session
//     declare_* API).
//   * `activate_role` — FSM role-start event dispatch
//     (`InboundStart` vs `OutboundStart` + `LinkOpened`).
//   * `spawn_background_tasks` — declare / query / publisher task
//     spawn + the optional `LivelinessToken` oneshot return path.
//
// Behaviour is identical to the pre-R287 inlined version. The
// teardown sequence after drive_session ends (sweep abort ->
// tasks join -> LivelinessToken drop -> Close emit -> actions
// drop -> writer drain) was retained inline in R287 because the
// R284 ordering invariant was load-bearing and only doc-enforced.
// R292 lifts the entire seven-step sequence into the sibling
// `teardown` module as a typestate sequence wrapper
// (TeardownInitial -> TasksJoined -> TokenDropped -> CloseEmitted
// -> ActionsDropped -> WriterDrained); the canonical chain is
// the only path from drive_session exit to a returned
// `WriterDrained`, so a hypothetical reorder is now rejected at
// compile time instead of at e2e time
// (`wz_liveliness_subscriber_round_trip_against_wz_acceptor`).

use std::io;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
// R311at — JoinHandle types migrate from raw `tokio::task::JoinHandle`
// to wz's [`TokioJoinHandle`], the trait-wrapped form returned by
// `<TokioRuntime as Runtime>::spawn`. The wrapper exposes the same
// `.abort()` + Future shape but yields `Result<T, RuntimeError>` on
// `.await` (instead of `Result<T, tokio::task::JoinError>`), keeping
// the ap-demo binary boundary on the trait surface that
// `wz-runtime-lwip` / `wz-runtime-embassy` will eventually populate
// — the reference binary therefore models the per-profile swap shape
// that downstream consumers inherit. R311at also replaces every
// `tokio::spawn(fut)` call with `TokioRuntime.spawn(fut)`; the
// concrete TokioRuntime instance is a unit struct so each call site
// pays zero runtime cost. teardown.rs migrates the same field types
// in lockstep so the typestate handoff stays type-uniform.
use wz::runtime_core::Runtime;
use wz::runtime_core::TimeSource;
use wz::runtime_tokio::declare::{LivelinessSample, LivelinessSampleKind};
use wz::runtime_tokio::observer::ApplicationLayerObserver;
use wz::runtime_tokio::reply::InboundReplyBody;
use wz::runtime_tokio::runtime_impl::TokioTime;
use wz::runtime_tokio::runtime_impl::{TokioJoinHandle, TokioRuntime};
use wz::runtime_tokio::session::{
    LivelinessSubscriber, LivelinessSubscriberOptions, LivelinessToken, Queryable,
    QueryableOptions, Session, SubscribeOptions, Subscriber,
};
use wz::runtime_tokio::session_glue::{
    drive_session_until_terminal, IterationEvent, SessionLinkActions,
};
use wz::runtime_tokio::session_open::{
    accept_and_open_session, initiate_and_open_session, DialedLink, OpenedSession,
    DEFAULT_OPEN_TICK_MS,
};
use wz::runtime_tokio::sync::Mutex;

use crate::args::{
    demo_session_init_params, DeclareEmitSpec, PushOperation, QueryRoleSpec, RemoteLogSpec,
    ReplyConsumerSpec, Role,
};
use crate::shutdown::shutdown_signal;
use crate::tasks::{declare_task, publisher_task, query_task, QUERY_RID};
use crate::teardown;

/// RAII keepers for the local Session-level declarations
/// ([`Subscriber`], [`LivelinessSubscriber`], [`Queryable`]). Held
/// at `run_demo` scope so each handle's `Drop` fires after the
/// drive_session loop ends — the RAII contract emits the matching
/// `Undecl*` wire frame at drop time, and dropping these handles
/// BEFORE `actions` is itself dropped guarantees the writer task
/// is still draining the outbound channel when the retraction
/// frame is enqueued.
struct SessionHandles {
    _subscriber: Option<Subscriber>,
    _liveliness_subscriber: Option<LivelinessSubscriber>,
    _queryable: Option<Queryable>,
}

/// Background-task handles + the optional [`LivelinessToken`] return
/// channel produced by [`spawn_background_tasks`]. `run_demo`
/// collects these to drive teardown: each task gets a 200ms
/// timeout-join window after drive_session ends, then the
/// LivelinessToken (if any) is received from `token_rx` and dropped
/// (RAII; emits `Declare(UndeclToken)` on the wire).
struct SpawnedTasks {
    publisher_handle: Option<TokioJoinHandle<()>>,
    query_handle: Option<TokioJoinHandle<()>>,
    declare_handle: Option<TokioJoinHandle<()>>,
    token_rx: Option<oneshot::Receiver<LivelinessToken>>,
}

/// Step 1 — TCP setup. Acceptor binds + accepts; Initiator dials.
/// Both paths return the same `TcpStream` value, after which the
/// FSM-driving code is role-agnostic except for the initial
/// role-start event dispatch (see [`activate_role`]).
///
/// R121f — this binary does NOT implement TCP retry / connect
/// timeout tuning beyond the kernel default; production callers
/// that need either compose around a `tokio::time::timeout`. The
/// address must resolve (DNS or numeric) — any
/// `TcpStream::connect` error is surfaced through the `io::Result`
/// return so the binary's exit code reflects the cause.
async fn establish_link(role: &Role) -> io::Result<TcpStream> {
    match role {
        Role::Acceptor { listen } => {
            let listener = TcpListener::bind(listen).await?;
            log::info!("wz-ap-demo: listening on {}", listener.local_addr()?);
            let (stream, peer) = listener.accept().await?;
            log::info!("wz-ap-demo: accepted peer {peer}");
            Ok(stream)
        }
        Role::Initiator { connect } => {
            let stream = TcpStream::connect(connect).await?;
            log::info!("wz-ap-demo: connected to {}", stream.peer_addr()?);
            Ok(stream)
        }
    }
}

/// Step 3 — install the observer-side callbacks that run BEFORE
/// `drive_session` starts: the three Remote* registries + the
/// ReplyRegistry pending-entry for the outbound Query (when the
/// caller asked for `--on-query-reply-log` / `--on-query-final-log`).
/// The local Session-side handles (Subscriber / Queryable /
/// LivelinessSubscriber) belong to [`install_session_handles`]; that
/// split keeps each sub-fn focused on one registry layer.
///
/// R235 — `observer` is `Arc<Mutex<ApplicationLayerObserver>>`. The
/// callback installs in this function run inside one lock scope so
/// the init phase incurs a single lock+drop; the drive_session
/// loop and any background `Session::publish` callers take the lock
/// on each dispatch / loopback fire (mutex contention is negligible
/// — the critical section is the per-event fan-out which is
/// already the serial bottleneck in the registry model).
///
/// R263 — `query_timeout_ms > 0` computes an absolute deadline
/// against the shared `session_clock` so the R264 sweep_task (in
/// the drive loop) can compare epoch-compatibly. `timeout_ms == 0`
/// registers with `None`, preserving pre-R263 behaviour.
fn install_observer_callbacks(
    observer: &Arc<Mutex<ApplicationLayerObserver>>,
    query_spec: Option<&str>,
    remote_log_spec: &RemoteLogSpec,
    reply_log_spec: &ReplyConsumerSpec,
    session_clock: TokioTime,
) {
    let mut observer_lock = observer.lock().expect("observer mutex poisoned");

    // R307.5 — every observer-callback log line below routes through
    // `log::info!` (env_logger) rather than `eprintln!` so that all
    // stderr writes flow through a SINGLE writer + lock discipline.
    // Pre-R307.5, the wz-ap-demo binary mixed `eprintln!` (direct
    // stderr) with `log::info!` (env_logger) writes; an empirically
    // observed ~5% Layer E flake (e.g. R307 30-trial measurement at
    // trial 19) traced to a stderr-interleave between the
    // LIVELINESS-SAMPLE callback's `eprintln!` and a concurrent
    // env_logger record, producing a line like
    // `wz-ap-demo: LIVELINESS SAMPLE wz-ap-demo: LIVELINESS SAMPLE DELETE ...`
    // that defeated the integration tests' substring search. Routing
    // every callback log line through `log::info!` collapses both
    // writers onto the same env_logger Mutex<BufferWriter> + the
    // env_logger record format `[<ts> INFO <module>] <message>` is a
    // strict superset of the prior bare line — integration test
    // substring searches still match because the original text appears
    // verbatim after the env_logger prefix.
    if remote_log_spec.on_remote_subscriber {
        observer_lock
            .remote_subscribers
            .on_subscriber_declared(|decl, resolved| {
                log::info!(
                    "wz-ap-demo: REMOTE SUBSCRIBER DECLARED id={} keyexpr='{}'",
                    decl.id,
                    resolved,
                );
            });
        observer_lock
            .remote_subscribers
            .on_subscriber_undeclared(|undecl| {
                log::info!("wz-ap-demo: REMOTE SUBSCRIBER UNDECLARED id={}", undecl.id);
            });
    }
    if remote_log_spec.on_remote_queryable {
        observer_lock
            .remote_queryables
            .on_queryable_declared(|decl, resolved| {
                log::info!(
                    "wz-ap-demo: REMOTE QUERYABLE DECLARED id={} keyexpr='{}'",
                    decl.id,
                    resolved,
                );
            });
        observer_lock
            .remote_queryables
            .on_queryable_undeclared(|undecl| {
                log::info!("wz-ap-demo: REMOTE QUERYABLE UNDECLARED id={}", undecl.id);
            });
    }
    if query_spec.is_some() && (reply_log_spec.on_query_reply || reply_log_spec.on_query_final) {
        let on_reply = reply_log_spec.on_query_reply;
        let on_final = reply_log_spec.on_query_final;
        let deadline_ms = (reply_log_spec.query_timeout_ms > 0)
            .then(|| session_clock.now_monotonic_ms() + reply_log_spec.query_timeout_ms as u64);
        observer_lock.replies.register(
            QUERY_RID,
            // R239 — wz-ap-demo issues an outbound Request(Query)
            // via SessionLinkActions::send_request_query (wire-
            // only, no loopback fan), so the pending entry expects
            // exactly one Final from the peer.
            1,
            deadline_ms,
            move |reply| {
                if !on_reply {
                    return;
                }
                let body_text = match &reply.body {
                    InboundReplyBody::Put { payload } => {
                        format!("Put payload={:?}", String::from_utf8_lossy(payload))
                    }
                    InboundReplyBody::Del => "Del".to_string(),
                    InboundReplyBody::Err { encoding, payload } => format!(
                        "Err encoding={:?} payload={:?}",
                        encoding,
                        String::from_utf8_lossy(payload),
                    ),
                };
                log::info!(
                    "wz-ap-demo: REPLY RECEIVED rid={} keyexpr='{}' body={}",
                    reply.rid,
                    reply.keyexpr_literal,
                    body_text,
                );
            },
            move |rid| {
                if !on_final {
                    return;
                }
                log::info!("wz-ap-demo: FINAL RECEIVED rid={rid}");
            },
        );
    }
    if remote_log_spec.on_remote_liveliness {
        observer_lock
            .liveliness
            .on_token_declared(|decl, resolved| {
                log::info!(
                    "wz-ap-demo: REMOTE TOKEN DECLARED id={} keyexpr='{}'",
                    decl.id,
                    resolved,
                );
            });
        observer_lock.liveliness.on_token_undeclared(|undecl| {
            log::info!("wz-ap-demo: REMOTE TOKEN UNDECLARED id={}", undecl.id);
        });
    }
    // observer_lock drops here; subsequent users (drive_session
    // dispatch closure, Session::publish loopback branch) re-lock
    // per-event.
}

/// Step 4 (Session-handle half) — register the local subscriber /
/// queryable / liveliness-subscriber via the
/// `Session::declare_subscriber` / `declare_queryable` /
/// `declare_liveliness_subscriber` RAII handle API (R245 / R246 /
/// R280 surface). Handles are bundled into [`SessionHandles`]
/// because `run_demo` needs to keep all three alive until after the
/// drive_session loop ends — early Drop would unregister the
/// callback or emit the retraction wire frame too soon.
///
/// R249 timing rationale: `drive_session` has not yet started at
/// this call site, so the registration ordering requirement
/// ("register before drive_session starts so z_put echo during
/// handshake routes through the subscriber") from the R121c-3
/// observation is preserved.
///
/// R283 — the outbound Interest emit during
/// `declare_liveliness_subscriber` is best-effort against the
/// pre-Established state; the wz session FSM holds the wire emit
/// until Established for the same SN-window reason as
/// `send_declare_*`, so a buffered Interest can race the Establish
/// transition without dropping. The R283 Established gate landed
/// on `declare_liveliness_subscriber_aliased` only; the non-aliased
/// entry point used here remains best-effort. Uniform extension of
/// the gate across the non-aliased declare_* surface is the R284
/// carry.
fn install_session_handles(
    session: &Session,
    key: Option<String>,
    liveliness_subscriber_keyexpr: Option<&str>,
    queryable_spec: Option<(String, String)>,
) -> SessionHandles {
    let subscriber = key.map(|filter| {
        let key_for_callback = filter.clone();
        session.declare_subscriber(filter, SubscribeOptions::default(), move |sample| {
            // R222 — Sample carries the resolved keyexpr literal +
            // the SampleKind discriminant + payload bytes directly,
            // so the prior `match push.keyexpr.body` + tagged-union
            // arm extraction is no longer required at the call site.
            log::info!(
                "wz-ap-demo: SUBSCRIBER FIRED filter='{}' keyexpr='{}' kind={:?} payload_len={}",
                key_for_callback,
                sample.keyexpr,
                sample.kind,
                sample.payload.len(),
            );
        })
    });

    let liveliness_subscriber = liveliness_subscriber_keyexpr.map(|filter| {
        let owned_filter = filter.to_string();
        let key_for_callback = owned_filter.clone();
        // R311q — declare_liveliness_subscriber now returns
        // `Result<LivelinessSubscriber, LivelinessSubscriberAliasError>`
        // for surface parity with the aliased entry point. wz-ap-demo
        // builds with default features (liveliness-subscriber ON), so
        // the only Err variant the caller can hit here is
        // `FeatureDisabled` — impossible on this build. `.expect` is
        // the textbook shape because a panic at this site would
        // indicate a default-features misconfiguration, which is a
        // build-system bug rather than a runtime condition.
        session
            .declare_liveliness_subscriber(
                owned_filter,
                LivelinessSubscriberOptions::default(),
                move |sample: LivelinessSample<'_>| {
                    let kind_str = match sample.kind {
                        LivelinessSampleKind::Put => "PUT",
                        LivelinessSampleKind::Delete => "DELETE",
                    };
                    log::info!(
                        "wz-ap-demo: LIVELINESS SAMPLE {} filter='{}' keyexpr='{}' token_id={}",
                        kind_str,
                        key_for_callback,
                        sample.keyexpr,
                        sample.token_id,
                    );
                },
            )
            .expect("liveliness-subscriber feature is ON in wz-ap-demo default build")
    });

    let queryable = queryable_spec.map(|(pattern, reply_text)| {
        let pattern_for_callback = pattern.clone();
        let reply_text_for_callback = reply_text.clone();
        // R311r — declare_queryable now returns Result + callback
        // signature uses (&QueryEvent, &mut ReplyEmitter). wz-ap-demo
        // builds with default features so the only Err here is
        // FeatureDisabled (impossible on this build); .expect is the
        // textbook shape per the R311 signature-stability principle.
        session
            .declare_queryable(
                pattern,
                QueryableOptions::default(),
                move |_event, responder| {
                    responder.reply(reply_text_for_callback.as_bytes());
                    log::info!(
                        "wz-ap-demo: QUERYABLE FIRED pattern='{}' rid={} keyexpr='{}' reply='{}'",
                        pattern_for_callback,
                        responder.rid(),
                        responder.keyexpr_literal(),
                        reply_text_for_callback,
                    );
                },
            )
            .expect("query-queryable feature is ON in wz-ap-demo default build")
    });

    SessionHandles {
        _subscriber: subscriber,
        _liveliness_subscriber: liveliness_subscriber,
        _queryable: queryable,
    }
}

/// Step 4a — spawn the three Established-gated background tasks
/// (publisher / query / declare). The actual gate-wait + emission
/// bodies live in [`crate::tasks`]; this function decides which
/// tasks to spawn based on the per-CLI specs and wires up the
/// shared `session_clock` (R263 epoch invariant).
///
/// R277 — when the caller requested `--declare-token <keyexpr>`,
/// allocate a `oneshot::channel::<LivelinessToken>` so `declare_task`
/// can hand the resulting RAII handle back to `run_demo`. Holding
/// the token at `run_demo` scope is the textbook cross-task
/// lifetime — the peer keeps the liveliness declaration alive for
/// as long as this demo holds the handle, and the explicit drop in
/// the teardown phase guarantees the retraction frame is enqueued
/// while the writer task is still draining (R277 + R278 + R284
/// ordering invariant).
fn spawn_background_tasks(
    session: &Session,
    actions: &Arc<SessionLinkActions>,
    publisher_spec: Option<(String, PushOperation, Option<u64>)>,
    query_spec: Option<String>,
    declare_spec: DeclareEmitSpec,
    session_clock: TokioTime,
) -> SpawnedTasks {
    let publisher_handle = publisher_spec.map(|(keyexpr, operation, declare_id)| {
        let session_for_publisher = session.clone();
        TokioRuntime.spawn(publisher_task(
            session_for_publisher,
            keyexpr,
            operation,
            declare_id,
            session_clock,
        ))
    });

    let query_handle = query_spec.map(|keyexpr| {
        let actions_for_query = actions.clone();
        TokioRuntime.spawn(query_task(actions_for_query, keyexpr, session_clock))
    });

    let has_declares = declare_spec.subscriber_keyexpr.is_some()
        || declare_spec.queryable_keyexpr.is_some()
        || declare_spec.token_keyexpr.is_some();
    let (token_tx, token_rx) = if declare_spec.token_keyexpr.is_some() {
        let (tx, rx) = oneshot::channel::<LivelinessToken>();
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };
    let declare_handle = if has_declares {
        let session_for_declare = session.clone();
        Some(TokioRuntime.spawn(declare_task(
            session_for_declare,
            declare_spec,
            session_clock,
            token_tx,
        )))
    } else {
        None
    };

    SpawnedTasks {
        publisher_handle,
        query_handle,
        declare_handle,
        token_rx,
    }
}

/// Demo orchestration entry point. Invoked by `fn main` after argv
/// parsing has been validated and the spec bundles
/// ([`DeclareEmitSpec`], [`RemoteLogSpec`], [`ReplyConsumerSpec`],
/// [`QueryRoleSpec`]) have been assembled. The body is a thin
/// assembly of the six sub-fns above plus the drive_session loop
/// and the R292 teardown typestate chain.
///
/// Teardown ordering invariant (R277 + R278 + R284, compile-time
/// enforced by the `teardown` module since R292). After
/// drive_session_until_terminal returns or shutdown_signal fires,
/// the seven-step teardown runs as the `TeardownInitial ->
/// TasksJoined -> TokenDropped -> CloseEmitted -> ActionsDropped
/// -> WriterDrained` typestate chain. Each step consumes its
/// predecessor by value, so the only path from `TeardownInitial`
/// to `WriterDrained` is the canonical order; per-step rationale
/// (sweep abort, 200ms task join, LivelinessToken Drop emits
/// UndeclToken before the Close frame so the peer observes the
/// retraction before the teardown handshake, Arc drop drains the
/// writer-task sender clones, 50ms tail drain) lives in the
/// per-state doc-comments in `crate::teardown`.
///
/// Reverse order of the UndeclToken / Close steps regresses
/// `wz_liveliness_subscriber_round_trip_against_wz_acceptor` (peer
/// terminates on Close before processing the trailing UndeclToken);
/// the typestate signature makes that reorder a type error.
pub(crate) async fn run_demo(
    role: Role,
    key: Option<String>,
    publisher_spec: Option<(String, PushOperation, Option<u64>)>,
    query_role_spec: QueryRoleSpec,
    declare_spec: DeclareEmitSpec,
    remote_log_spec: RemoteLogSpec,
    reply_log_spec: ReplyConsumerSpec,
) -> io::Result<()> {
    let QueryRoleSpec {
        queryable: queryable_spec,
        query: query_spec,
    } = query_role_spec;

    // ── Step 1: TCP setup (Acceptor binds + accepts, Initiator dials).
    let stream = establish_link(&role).await?;

    // ── Step 2: open the session to Established via the library open
    //          helpers (R311fc). The handshake phase is wall-clock bounded
    //          by the SCXML handshake timers — Initiator init_ack/open_ack
    //          (2s) + link.open_timeout (5s); Acceptor
    //          accepting.inactivity_timeout (1s) — so a peer that connects
    //          then stalls no longer hangs the binary: the helper's tick pump
    //          fires the deadline and returns an OpenError instead of looping
    //          forever (the pre-R311fc inline drive had no tick pump on the
    //          handshake). Production wall-clock path: `None` iteration cap +
    //          DEFAULT_OPEN_TICK_MS. The returned OpenedSession owns the same
    //          wiring the demo previously built inline (split link pipeline +
    //          Lua-bound FSM engine + actions); steps 3-5 thread its fields
    //          into the steady-state machinery instead of constructing them.
    //
    // R294/R263 — `session_clock` is the single shared monotonic epoch passed
    // into the open helper (which threads it into SessionLinkActions),
    // install_observer_callbacks, Session::new, drive_session_until_terminal,
    // and sweep_task. TokioTime is Copy, so the OpenedSession's returned clock
    // is the same epoch; the demo keeps using its own `session_clock` binding
    // (clock: _) — load-bearing for the R261 register-time deadline_ms vs
    // sweep-time now_ms comparison.
    let session_clock = TokioTime::new();
    let params = demo_session_init_params(&role);
    let OpenedSession {
        mut engine,
        actions,
        inbound,
        writer_handle,
        clock: _,
    } = match &role {
        Role::Acceptor { .. } => {
            accept_and_open_session(
                DialedLink::Tcp(stream),
                params,
                session_clock,
                None,
                DEFAULT_OPEN_TICK_MS,
            )
            .await
        }
        Role::Initiator { .. } => {
            initiate_and_open_session(
                DialedLink::Tcp(stream),
                params,
                session_clock,
                None,
                DEFAULT_OPEN_TICK_MS,
            )
            .await
        }
    }
    .map_err(|e| io::Error::other(format!("wz-ap-demo: session open failed: {e:?}")))?;
    log::info!("wz-ap-demo: session Established; entering steady state");

    // ── Step 3: observer-side registry callbacks. The handshake exchanged no
    //          application frames, so wiring the observer here — after
    //          Established — drops nothing.
    //
    // R121k-7-refactor: the six per-domain registries (subscribers /
    // queryables / remote_subscribers / remote_queryables / liveliness /
    // replies) plus the queryable side's pending-reply + pending-final
    // staging buffers are wrapped in a single ApplicationLayerObserver. A
    // single observer.dispatch call inside the drive_session loop fans each
    // IterationEvent into every registry + drains staged outbound records.
    // R235 — `observer` is `Arc<Mutex<ApplicationLayerObserver>>`; the drive
    // loop and any background `Session::publish` take the lock per dispatch.
    let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    install_observer_callbacks(
        &observer,
        query_spec.as_deref(),
        &remote_log_spec,
        &reply_log_spec,
        session_clock,
    );

    // ── Step 4: bundle actions + observer into a Session and spawn the
    //          Established-gated background tasks. Each task polls
    //          `record_established_at` (already > 0 here) then emits, so
    //          spawning post-Established simply skips the gate wait.
    // R311cw — Session::new takes `Arc<T>` clock; wrapping the shared
    // `session_clock` keeps the monotonic epoch load-bearing for the R261
    // register-time deadline_ms vs sweep-time now_ms comparison.
    let session = Session::new(actions.clone(), observer.clone(), Arc::new(session_clock));

    let _handles = install_session_handles(
        &session,
        key,
        declare_spec.liveliness_subscriber_keyexpr.as_deref(),
        queryable_spec,
    );

    let SpawnedTasks {
        publisher_handle,
        query_handle,
        declare_handle,
        token_rx,
    } = spawn_background_tasks(
        &session,
        &actions,
        publisher_spec,
        query_spec,
        declare_spec,
        session_clock,
    );

    // ── Step 5: drive the session FSM through the steady state until
    //          terminal. The open helper already reached Established; this
    //          continues from there, dispatching inbound application frames.
    //
    // R235 — observer relocks per dispatch; a loopback `Session::publish`
    // callback does NOT deadlock because `local_publish` releases the
    // registry borrow before invoking the user callback, so contention is
    // only between this loop and background `Session::publish` calls, which
    // serialize naturally on the mutex without livelock.
    log::info!("wz-ap-demo: driving session FSM");
    let mut driver = inbound;
    let observer_for_dispatch = observer.clone();

    // R264 — sweep_task is a dedicated `TimeSource::sleep`-driven
    // ticker that fires `ReplyRegistry::sweep_timed_out` at the
    // `--sweep-cadence-ms` interval (R270; default 100 ms preserves
    // the pre-R270 hardcoded cadence) as a peer task to
    // `drive_session_until_terminal`. The sweep runs here rather
    // than inside the drive_session loop because
    // `poll_and_dispatch_one` is NOT cancel-safe for length-prefixed
    // link drivers such as the `TcpReadDriver` from `link_pipeline`
    // (cancellation between the u16 length read and the payload
    // read drops captured bytes). Clamping the drive_session loop's
    // sleep arm to the sweep cadence would cancel the in-flight
    // poll once per tick; running the sweep as a peer task means
    // the drive_session loop's poll future runs to completion
    // without competing select arms.
    let sweep_clock = session_clock;
    let observer_for_sweep = observer.clone();
    let sweep_cadence_ms = u64::from(reply_log_spec.sweep_cadence_ms);
    let sweep_task = TokioRuntime.spawn(async move {
        loop {
            sweep_clock.sleep(sweep_cadence_ms).await;
            // Lock the observer for the minimum window: a single
            // sweep call. Holding the lock across an await would
            // serialise this task against drive_session's inbound
            // dispatch (also holds observer.lock()).
            let mut obs = match observer_for_sweep.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            let _ = obs.replies.sweep_timed_out(sweep_clock.now_monotonic_ms());
        }
    });

    // R278 — race `drive_session_until_terminal` against the
    // graceful-shutdown signal. Three completion paths:
    //   1. FSM reaches terminal naturally (peer Close received, max
    //      iters hit, lease timeout, etc.) → outcome = Some(...)
    //   2. SIGTERM / SIGINT arrives → outcome = None; drive_session
    //      future is dropped mid-iteration (cancel-safe — the engine
    //      lives in run_demo's stack, not inside the future).
    //   3. (Future) administrative shutdown via in-process channel
    //      → same Future-drop semantics as (2).
    let outcome = tokio::select! {
        o = drive_session_until_terminal(
            &mut driver,
            &actions,
            &mut engine,
            Some(10_000),
            &session_clock,
            |event: IterationEvent<'_>| {
                log::debug!("wz-ap-demo: iteration event = {event:?}");
                observer_for_dispatch
                    .lock()
                    .expect("observer mutex poisoned by panic in subscriber callback")
                    .dispatch(event, &actions);
            },
        ) => Some(o),
        _ = shutdown_signal() => {
            log::info!(
                "wz-ap-demo: shutdown signal received; halting drive_session \
                 (writer task remains alive to drain Close + UndeclToken + tail frames)"
            );
            None
        }
    };
    match &outcome {
        Some(o) => log::info!("wz-ap-demo: session ended: {o:?}"),
        None => log::info!(
            "wz-ap-demo: session cancelled by graceful-shutdown signal; \
             Close(Generic) enqueues after UndeclToken in the writer drain"
        ),
    }
    log::info!("wz-ap-demo: action trace = {:?}", actions.trace_snapshot());

    // R292 — seven-step teardown invariant lifted from inline
    // doc-comment to a typestate chain. The fluent sequence below
    // is the only path from drive_session exit to a returned
    // `WriterDrained`; reordering becomes a type error rather than
    // a runtime regression surfaced by
    // `wz_liveliness_subscriber_round_trip_against_wz_acceptor`.
    // Per-step rationale (sweep abort, 200ms task join,
    // LivelinessToken Drop -> UndeclToken on writer channel, Close
    // frame after UndeclToken, Arc-drop drains writer-task sender
    // clones, 50ms tail drain) lives in `crate::teardown`.
    let _: teardown::WriterDrained = teardown::TeardownInitial {
        sweep_task,
        publisher_handle,
        query_handle,
        declare_handle,
        token_rx,
        actions,
        writer_handle,
        was_cancelled: outcome.is_none(),
        clock: session_clock,
    }
    .abort_sweep_join_tasks()
    .await
    .drop_liveliness_token()
    .await
    .emit_close_if_cancelled()
    .drop_actions()
    .drain_writer()
    .await;

    Ok(())
}
