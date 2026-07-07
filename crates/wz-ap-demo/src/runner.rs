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
//   * `establish_link` — link setup; both roles delegate to the
//     library session-open seam (Acceptor -> accept_endpoint,
//     Initiator -> dial_endpoint).
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
//   * `spawn_background_tasks` — query / publisher / liveliness-get
//     task spawn (R311ot: declares + the LivelinessToken are emitted
//     synchronously pre-drive in `run_demo`, not via a background task
//     + oneshot).
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
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

// R311at — JoinHandle types migrate from raw `tokio::task::JoinHandle`
// to wz's [`TokioJoinHandle`], the trait-wrapped form returned by
// `<TokioRuntime as Runtime>::spawn`. The wrapper exposes the same
// `.abort()` + Future shape but yields `Result<T, RuntimeError>` on
// `.await` (instead of `Result<T, tokio::task::JoinError>`), keeping
// the ap-demo binary boundary on the trait surface that
// `wz-runtime-coop` / `wz-runtime-embassy` will eventually populate
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
use wz::runtime_tokio::reconnect::{
    reconnect_endpoint, ReconnectDriveOutcome, ReconnectPolicy, ReconnectTeardown,
    ReconnectingSession,
};
use wz::runtime_tokio::reply_sink::ReplyKind;
use wz::runtime_tokio::runtime_impl::TokioTime;
use wz::runtime_tokio::runtime_impl::{TokioJoinHandle, TokioRuntime};
use wz::runtime_tokio::session::{
    LivelinessOptions, LivelinessSubscriber, LivelinessSubscriberOptions, LivelinessToken,
    Queryable, QueryableOptions, SubscribeOptions, Subscriber, TokioSession,
};
use wz::runtime_tokio::session_glue::{
    drive_session_until_terminal, IterationEvent, SessionLinkActions, SessionTimeouts,
};
use wz::runtime_tokio::session_open::{
    accept_and_open_session, accept_endpoint, dial_endpoint, initiate_and_open_session, DialConfig,
    DialedLink, OpenedSession, DEFAULT_OPEN_TICK_MS,
};
use wz::runtime_tokio::sync::Mutex;

use crate::args::{
    demo_session_init_params, DeclareEmitSpec, PushOperation, QueryRoleSpec, RemoteLogSpec,
    ReplyConsumerSpec, Role,
};
use crate::shutdown::shutdown_signal;
use crate::tasks::{liveliness_get_task, publisher_task, query_task, QUERY_RID};
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

/// Background-task handles produced by [`spawn_background_tasks`].
/// `run_demo` collects these for teardown: each task gets a 200ms
/// timeout-join window after drive_session ends. (R311ot — the
/// LivelinessToken is no longer returned here; it is declared
/// synchronously pre-drive in `run_demo` and threaded directly into
/// the teardown chain, so its RAII Drop still emits
/// `Declare(UndeclToken)` ahead of Close.)
struct SpawnedTasks {
    publisher_handle: Option<TokioJoinHandle<()>>,
    query_handle: Option<TokioJoinHandle<()>>,
    liveliness_get_handle: Option<TokioJoinHandle<()>>,
}

/// Step 1 — link setup. Both roles delegate to the library session-open
/// seam (Acceptor -> [`accept_endpoint`], Initiator -> [`dial_endpoint`]).
/// Both paths return a [`DialedLink`] the role-agnostic open helpers
/// consume, after which the FSM-driving code is role-agnostic except
/// for the initial role-start event dispatch (see [`activate_role`]).
///
/// R121f — this binary does NOT implement connect retry / timeout
/// tuning beyond the kernel default; production callers that need
/// either compose around a `tokio::time::timeout`. Any dial error is
/// surfaced through the `io::Result` return so the binary's exit code
/// reflects the cause.
///
/// R311pm — the Initiator dial delegates wholesale to the library dial
/// seam [`dial_endpoint`], the single home of "turn a `--connect`
/// string into a [`DialedLink`]". The demo no longer re-assembles the
/// parse + dial + error-map the library already owns, and the prior
/// `connect.contains('/')` heuristic is gone: that heuristic forked a
/// bare `HOST:PORT` (std-resolver dial, DNS-capable) away from a
/// `tcp/...` form (numeric-only locator parse), so a `tcp/hostname`
/// silently failed where a bare `hostname` worked. The seam dissolves
/// the fork into one decision — a scheme'd numeric/serial locator dials
/// via `dial_locator`; a scheme-less `HOST:PORT` or a `tcp/HOST` DNS
/// hostname dials via the std resolver — so a hostname behaves the same
/// with or without the explicit `tcp/` scheme. A `ws/...` locator opens
/// a WebSocket session only when the `ws` feature forwards
/// `transport-link-ws`; without it the seam surfaces a typed
/// `Unsupported` io error rather than mis-dialing.
///
/// R311pu — the Acceptor arm delegates to the library accept seam
/// [`accept_endpoint`] (symmetric to the Initiator's [`dial_endpoint`]),
/// dissolving the prior inline `TcpListener::bind` + `accept` re-assembly into
/// the same seam the dial side uses: `accept_endpoint` classifies `--listen`
/// through the shared `plan_endpoint` classifier, then `accept_locator` binds +
/// accepts.
///
/// STATED ASYMMETRY (R311pq, still true at the DEMO level): `accept_locator`
/// wires `Tcp` and leaves `ws/` / `tls/` as typed-`Unsupported` extension
/// points — NOT dead code, the same shape `dial_locator`'s non-tcp arms carry.
/// A wz WS/TLS ACCEPTOR implementation stays unwired because there is no
/// cross-impl WS/TLS DIALER to verify it against (zenoh-pico has no native WS,
/// emscripten-only; the Layer Z WS legs run wz as the WS Initiator against
/// zenohd's `ws/` listener). The `accept_ws` / `accept_tls` primitives exist in
/// the library, so wiring them is a one-arm change when a verified caller lands
/// (R63 concrete-impls-land-alongside-real-callers) — the demo dials, not
/// accepts, those transports today.
async fn establish_link(role: &Role) -> io::Result<DialedLink> {
    match role {
        Role::Acceptor { listen } => {
            // R311pu/pv — delegate to the library accept seam (symmetric to the
            // Initiator's dial_endpoint), dissolving the inline TcpListener::bind.
            // accept_bound logs the "listening on" / "accepted peer" lines the
            // round-trip test waits on. No "over {transport}" line here: unlike
            // the Initiator (which can dial ws/tls/udp, so it logs which
            // transport opened), accept_locator only ever yields Tcp today, so
            // that line would be a tautology — it returns if a non-tcp acceptor
            // ever wires in.
            accept_endpoint(listen).await
        }
        Role::Initiator { connect, .. } => {
            // R311pw — `reconnect` is ignored here: `establish_link` runs the
            // one-shot dial only. The reconnect-Initiator lifecycle dials inside
            // the supervisor (which re-dials on loss), so `run_demo` routes it
            // away from `establish_link` entirely (it never reaches this arm).
            let dialed = dial_endpoint(connect, &DialConfig::default()).await?;
            // R311po — log WHICH transport was dialed (the DialedLink variant
            // name). This is the WS legs' witness that a `ws/...` --connect
            // really opened a WebSocket link, not a silent TCP fallback.
            log::info!(
                "wz-ap-demo: connected to {connect} over {} transport",
                dialed.transport_name()
            );
            Ok(dialed)
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
            .on_subscriber_declared(|decl| {
                log::info!(
                    "wz-ap-demo: REMOTE SUBSCRIBER DECLARED id={} keyexpr='{}'",
                    decl.id(),
                    decl.keyexpr(),
                );
            });
        observer_lock
            .remote_subscribers
            .on_subscriber_undeclared(|id| {
                log::info!("wz-ap-demo: REMOTE SUBSCRIBER UNDECLARED id={id}");
            });
    }
    if remote_log_spec.on_remote_queryable {
        observer_lock
            .remote_queryables
            .on_queryable_declared(|decl| {
                log::info!(
                    "wz-ap-demo: REMOTE QUERYABLE DECLARED id={} keyexpr='{}'",
                    decl.id(),
                    decl.keyexpr(),
                );
            });
        observer_lock
            .remote_queryables
            .on_queryable_undeclared(|id| {
                log::info!("wz-ap-demo: REMOTE QUERYABLE UNDECLARED id={id}");
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
                let body_text = match reply.kind() {
                    ReplyKind::Put => {
                        format!("Put payload={:?}", String::from_utf8_lossy(reply.payload()))
                    }
                    ReplyKind::Del => "Del".to_string(),
                    ReplyKind::Err => format!(
                        "Err encoding={:?} payload={:?}",
                        reply.err_encoding(),
                        String::from_utf8_lossy(reply.payload()),
                    ),
                };
                log::info!(
                    "wz-ap-demo: REPLY RECEIVED rid={} keyexpr='{}' body={}",
                    reply.rid(),
                    reply.keyexpr(),
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
        observer_lock.liveliness.on_token_declared(|decl| {
            log::info!(
                "wz-ap-demo: REMOTE TOKEN DECLARED id={} keyexpr='{}'",
                decl.id(),
                decl.keyexpr(),
            );
        });
        observer_lock.liveliness.on_token_undeclared(|id| {
            log::info!("wz-ap-demo: REMOTE TOKEN UNDECLARED id={id}");
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
    session: &TokioSession,
    key: Option<String>,
    liveliness_subscriber_keyexpr: Option<&str>,
    liveliness_subscriber_history: bool,
    queryable_spec: Option<(String, String)>,
) -> SessionHandles {
    let subscriber = key.and_then(|filter| {
        let key_for_callback = filter.clone();
        // R311ou — `--key` now declares a ROUTED subscriber: register the local
        // callback AND emit `Declare(DeclSubscriber)` so a router (e.g. zenohd)
        // routes matching Pushes back to this session. The keyexpr was
        // R300-validated at argv parse time (main.rs adds --key to the eager
        // outbound gate), so the only residual reject here is an over-capacity
        // keyexpr / transport-down — log and skip rather than abort the demo
        // (a rejected declare rolls back its local registration, so `None` is
        // the correct "no subscriber" outcome).
        let declared = session.declare_subscriber(
            filter.clone(),
            SubscribeOptions::default(),
            move |sample| {
                // R311gb-2b — the registry delivers `&dyn SampleView` (the
                // sink seam accessor contract); read keyexpr / kind /
                // payload through the accessor methods. R222 had already
                // collapsed the prior `match push.keyexpr.body` tagged-union
                // arm extraction, so the call site stays a flat read.
                log::info!(
                    "wz-ap-demo: SUBSCRIBER FIRED filter='{}' keyexpr='{}' kind={:?} payload_len={}",
                    key_for_callback,
                    sample.keyexpr(),
                    sample.kind(),
                    sample.payload().len(),
                );
            },
        );
        match declared {
            Ok(sub) => {
                log::info!(
                    "wz-ap-demo: DECLARED ROUTED SUBSCRIBER id={} keyexpr='{filter}'",
                    sub.id().as_u64(),
                );
                Some(sub)
            }
            Err(e) => {
                log::warn!("wz-ap-demo: SUBSCRIBER declare rejected for keyexpr='{filter}': {e}");
                None
            }
        }
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
        // R311ph — `#[non_exhaustive]` LivelinessSubscriberOptions can't be
        // built with literal syntax outside its crate; set the public `history`
        // field on the default instead. `history = true` (--liveliness-subscribe-history)
        // makes the subscriber order-independent of token declare time.
        let mut liveliness_options = LivelinessSubscriberOptions::default();
        liveliness_options.history = liveliness_subscriber_history;
        session
            .declare_liveliness_subscriber(
                owned_filter,
                liveliness_options,
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

    let queryable = queryable_spec.and_then(|(pattern, reply_text)| {
        let pattern_for_callback = pattern.clone();
        let pattern_for_log = pattern.clone();
        let reply_text_for_callback = reply_text.clone();
        // R311ow — `--queryable` now declares a ROUTED queryable: register the
        // local reply callback AND emit `Declare(DeclQueryable)` so a router
        // (e.g. zenohd) routes matching Query requests to this session. The
        // keyexpr was R300-validated at argv parse time (main.rs adds
        // --queryable to the eager outbound gate), so the only residual reject
        // here is an over-capacity keyexpr / transport-down — log and skip
        // rather than abort the demo (a rejected declare rolls back its local
        // registration, so `None` is the correct "no queryable" outcome).
        //
        // R311gb-3b — declare_queryable hands the handler the seam contracts
        // (&dyn QueryView, &mut dyn ReplyOut); rid + keyexpr are read from the
        // query (QueryView is their SSOT) rather than the reply sink.
        let declared = session.declare_queryable(
            pattern,
            QueryableOptions::default(),
            move |query, responder| {
                responder.reply(reply_text_for_callback.as_bytes());
                log::info!(
                    "wz-ap-demo: QUERYABLE FIRED pattern='{}' rid={} keyexpr='{}' reply='{}'",
                    pattern_for_callback,
                    query.rid(),
                    query.keyexpr(),
                    reply_text_for_callback,
                );
            },
        );
        match declared {
            Ok(q) => {
                log::info!(
                    "wz-ap-demo: DECLARED ROUTED QUERYABLE id={} keyexpr='{pattern_for_log}'",
                    q.id().as_u64(),
                );
                Some(q)
            }
            Err(e) => {
                log::warn!(
                    "wz-ap-demo: QUERYABLE declare rejected for keyexpr='{pattern_for_log}': {e}"
                );
                None
            }
        }
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
    session: &TokioSession,
    actions: &Arc<SessionLinkActions>,
    publisher_spec: Option<(String, PushOperation, Option<u64>)>,
    query_spec: Option<String>,
    liveliness_get_spec: Option<String>,
    session_clock: TokioTime,
    long_lived: bool,
) -> SpawnedTasks {
    let publisher_handle = publisher_spec.map(|(keyexpr, operation, declare_id)| {
        let session_for_publisher = session.clone();
        TokioRuntime.spawn(publisher_task(
            session_for_publisher,
            keyexpr,
            operation,
            declare_id,
            session_clock,
            long_lived,
        ))
    });

    let query_handle = query_spec.map(|keyexpr| {
        let actions_for_query = actions.clone();
        TokioRuntime.spawn(query_task(actions_for_query, keyexpr, session_clock))
    });

    let liveliness_get_handle = liveliness_get_spec.map(|keyexpr| {
        let session_for_get = session.clone();
        TokioRuntime.spawn(liveliness_get_task(session_for_get, keyexpr, session_clock))
    });

    // R311ot — no declare_task: all outbound declares (subscriber / queryable /
    // token) are emitted synchronously pre-drive in `run_demo`, so there is no
    // longer a background declare task to spawn.
    SpawnedTasks {
        publisher_handle,
        query_handle,
        liveliness_get_handle,
    }
}

/// R311pw — the demo's session-drive source, forked by lifecycle mode.
/// `OneShot` (Acceptor, or Initiator without `--reconnect`) drives the FSM
/// once to terminal; `Reconnect` (Initiator `--reconnect`) drives the
/// long-lived [`ReconnectingSession`] supervisor, which re-dials + replays the
/// declaration cache on link loss. Both expose the surviving
/// [`SessionLinkActions`] bundle that the steady-state machinery
/// (observer / session / handles / tasks / sweep) and the R292 teardown chain
/// are built over, so only the OPEN and the DRIVE fork — the ~250 lines
/// between them stay mode-agnostic.
///
/// Both variants are boxed: `OpenedSession` embeds the FSM engine (≥256 bytes)
/// and `ReconnectingSession` embeds a whole `OpenedSession` plus more, so an
/// unboxed enum would carry the larger variant's footprint on every value
/// (clippy `large_enum_variant`); boxing keeps `DriveSource` pointer-sized.
enum DriveSource {
    OneShot(Box<OpenedSession>),
    Reconnect(Box<ReconnectingSession>),
}

impl DriveSource {
    /// The surviving actions bundle — the half both modes build the
    /// steady-state Session / handles / tasks over (and the teardown drops).
    fn actions(&self) -> &Arc<SessionLinkActions> {
        match self {
            DriveSource::OneShot(opened) => &opened.actions,
            DriveSource::Reconnect(recon) => recon.actions(),
        }
    }
}

/// R311py — race a drive future against the graceful-shutdown signal: the SSOT
/// for the demo's shutdown-cancel semantics, shared by both [`DriveSource`]
/// arms (the open fork's `actions()` SSOT extended to the drive fork's cancel
/// shell). Returns `Some(outcome)` when the drive terminated on its own, `None`
/// when shutdown cancelled it — dropping the drive future mid-iteration, which
/// is cancel-safe on teardown: the engine/driver live in the caller's frame
/// (not the future), and on shutdown the link is torn down so a dropped partial
/// read loses nothing. `noun` names the drive in the cancel log. The writer
/// task stays alive past cancellation so the R292 teardown can drain Close +
/// UndeclToken + tail frames.
async fn race_against_shutdown<O>(
    drive: impl std::future::Future<Output = O>,
    noun: &str,
) -> Option<O> {
    tokio::select! {
        o = drive => Some(o),
        _ = shutdown_signal() => {
            log::info!(
                "wz-ap-demo: shutdown signal received; halting {noun} \
                 (writer task remains alive to drain Close + UndeclToken + tail frames)"
            );
            None
        }
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
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_demo(
    role: Role,
    key: Option<String>,
    publisher_spec: Option<(String, PushOperation, Option<u64>)>,
    query_role_spec: QueryRoleSpec,
    declare_spec: DeclareEmitSpec,
    remote_log_spec: RemoteLogSpec,
    reply_log_spec: ReplyConsumerSpec,
    zid_override: Option<Vec<u8>>,
) -> io::Result<()> {
    let QueryRoleSpec {
        queryable: queryable_spec,
        query: query_spec,
        liveliness_get: liveliness_get_spec,
    } = query_role_spec;

    // ── Step 1+2: link setup + open, FORKED by lifecycle mode (R311pw).
    //          Acceptor and one-shot Initiator dial/accept ONCE via
    //          establish_link, then open via the library helpers (R311fc).
    //          The reconnect Initiator (`--connect --reconnect`) instead hands
    //          its `--connect` locator to `open_session_with_reconnect`, which
    //          OWNS the dial (it re-dials + replays the declaration cache on
    //          link loss), so it skips establish_link. Both yield a
    //          `DriveSource` exposing the surviving actions bundle steps 3-5
    //          build over.
    //
    //          Handshake is wall-clock bounded by the SCXML handshake timers
    //          (Initiator init_ack/open_ack 2s + link.open_timeout 5s; Acceptor
    //          accepting.inactivity_timeout 1s); production cap = None +
    //          DEFAULT_OPEN_TICK_MS.
    //
    // R294/R263 — `session_clock` is the single shared monotonic epoch threaded
    // into the open helper, install_observer_callbacks, Session::new, the drive
    // loop, and sweep_task (TokioTime is Copy, so every copy is the same epoch).
    let session_clock = TokioTime::new();
    let mut params = demo_session_init_params(role.node_kind());
    // `--zid <hex>` override: give this session node a DISTINCT identity so it can
    // coexist with another session node inside a router mesh (the mesh graph keys
    // on zid; the hardcoded demo zid would collide). No override -> the default.
    if let Some(zid) = zid_override {
        params.zid = zid;
    }
    // R311q1 — the long-lived (reconnect) lifecycle drives a PERIODIC publisher
    // that re-arms emission across reconnects (data-plane continuity past a
    // sever), vs the default one-shot finite burst. Derived from the role so
    // "an acceptor publishes long-lived" stays unrepresentable (the reconnect
    // flag lives only on the Initiator variant).
    let long_lived = matches!(
        &role,
        Role::Initiator {
            reconnect: true,
            ..
        }
    );
    let drive_src = match &role {
        // R311pw — reconnect Initiator: the supervisor owns the dial. Reuse the
        // library `plan_endpoint` connect-string classifier (scheme-less `tcp/`
        // convenience included), then narrow to the reconnectable subset via
        // `ReconnectLocator::try_from` (a `serial/...` --connect is rejected
        // here with NotReconnectable — pico AUTO_RECONNECT is IP-family only).
        Role::Initiator {
            connect,
            reconnect: true,
        } => {
            // R311py — one library seam owns the `--connect` string →
            // ReconnectingSession orchestration (parse + narrow-to-reconnectable
            // + supervised open), symmetric with the one-shot `dial_endpoint`.
            // Long-lived lifecycle: per-connection cap = None (run until the
            // shutdown signal cancels the drive future); pico-default retry
            // policy. Cert-free transports take DialConfig::default; a `tls/`
            // reconnect would thread its config here (out of demo scope). A
            // non-reconnectable `--connect` (serial/...) surfaces as a typed
            // OpenError::NotReconnectable inside the {e:?}.
            let recon = reconnect_endpoint(
                connect,
                params,
                DialConfig::default(),
                session_clock,
                ReconnectPolicy::default(),
                None,
                DEFAULT_OPEN_TICK_MS,
            )
            .await
            .map_err(|e| {
                io::Error::other(format!("wz-ap-demo: reconnect session open failed: {e:?}"))
            })?;
            log::info!(
                "wz-ap-demo: reconnect-supervised session Established (--reconnect); \
                 link loss re-dials + replays declarations"
            );
            DriveSource::Reconnect(Box::new(recon))
        }
        // Acceptor + one-shot Initiator: dial/accept once, open one-shot.
        _ => {
            let dialed = establish_link(&role).await?;
            let opened = match &role {
                Role::Acceptor { .. } => {
                    accept_and_open_session(
                        dialed,
                        params,
                        session_clock,
                        None,
                        DEFAULT_OPEN_TICK_MS,
                    )
                    .await
                }
                Role::Initiator { .. } => {
                    initiate_and_open_session(
                        dialed,
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
            DriveSource::OneShot(Box::new(opened))
        }
    };
    let actions = drive_src.actions().clone();

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
    let session = TokioSession::new(actions.clone(), observer.clone(), Arc::new(session_clock));

    let _handles = install_session_handles(
        &session,
        key,
        declare_spec.liveliness_subscriber_keyexpr.as_deref(),
        declare_spec.liveliness_subscriber_history,
        queryable_spec,
    );

    // R311ot / R311oy — declare the outbound liveliness TOKEN SYNCHRONOUSLY in
    // this pre-drive registration phase, BEFORE `drive_session_until_terminal`
    // serves any inbound frame (the R249 register-before-serve rule). The
    // subscriber + queryable declares moved to `install_session_handles` in
    // R311oy: `--key` / `--queryable` declare a ROUTED subscriber / queryable
    // through the real `Session::declare_{subscriber, queryable}` path (R311ou /
    // R311ow), retiring the low-level `send_declare_{subscriber, queryable}`
    // raw-emit hooks; only the token's pre-drive declare remains here. It (a)
    // closes the `wz_liveliness_get_round_trip` ordering race by construction —
    // a peer's CURRENT liveliness-get always finds the token in the
    // LocalTokenRegistry — and (b) the background `declare_task` stays retired
    // (the session is already Established here). The token's RAII
    // `LivelinessToken` is held to teardown (its Drop emits `Declare(UndeclToken)`,
    // ordered ahead of Close by the teardown chain).
    let token: Option<LivelinessToken> = match declare_spec.token_keyexpr.as_deref() {
        Some(keyexpr) => {
            match session.declare_token(keyexpr.to_string(), LivelinessOptions::default()) {
                Ok(t) => {
                    log::info!(
                        "wz-ap-demo: DECLARED TOKEN id={id} keyexpr='{keyexpr}'",
                        id = t.id()
                    );
                    Some(t)
                }
                Err(e) => {
                    log::warn!("wz-ap-demo: TOKEN DECLARE rejected for keyexpr='{keyexpr}': {e}");
                    None
                }
            }
        }
        None => None,
    };

    let SpawnedTasks {
        publisher_handle,
        query_handle,
        liveliness_get_handle,
    } = spawn_background_tasks(
        &session,
        &actions,
        publisher_spec,
        query_spec,
        liveliness_get_spec,
        session_clock,
        long_lived,
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

    // gc-3 carry #2 — wire the LIVE application switchboard. Register the
    // demo's keyexpr -> domain-event rows (from wz-ap-demo-app's sidecar) onto
    // the observer's switchboard registry, and construct the application
    // statechart engine. An inbound Push on a mapped keyexpr fans out to this
    // engine via `observer.dispatch_switchboard` in the drive loop below — the
    // first time an external peer's published sample drives a real SCE
    // application machine end to end (vs the session FSM the demo always ran).
    #[cfg(feature = "switchboard")]
    {
        let mut obs = observer.lock().expect("observer mutex poisoned");
        wz_ap_demo_app::register_bindings(&mut obs.switchboard);
        log::info!(
            "wz-ap-demo: switchboard registered (demo/sensor/temp value, \
             demo/sensor/reset signal); app machine = sensor_monitor"
        );
    }
    #[cfg(feature = "switchboard")]
    let mut app_engine = wz_ap_demo_app::new_engine();

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
    let actions_for_sweep = actions.clone();
    let session_for_sweep = session.clone();
    let sweep_cadence_ms = u64::from(reply_log_spec.sweep_cadence_ms);
    let sweep_task = TokioRuntime.spawn(async move {
        loop {
            sweep_clock.sleep(sweep_cadence_ms).await;
            // Lock the observer for the minimum window: a single
            // sweep call. Holding the lock across an await would
            // serialise this task against drive_session's inbound
            // dispatch (also holds observer.lock()).
            {
                let mut obs = match observer_for_sweep.lock() {
                    Ok(g) => g,
                    Err(poisoned) => poisoned.into_inner(),
                };
                let now_ms = sweep_clock.now_monotonic_ms();
                let _ = obs.replies.sweep_timed_out(now_ms);
                // F3 — the liveliness-get pending table has the same
                // deadline contract as the reply registry (registered with
                // an absolute timeout, swept here so an unanswered get
                // cannot leak its slot); previously documented but unwired.
                // R311ka — drain the staged reconnect-cache prunes in the
                // SAME lock window (the registry's airtight-capacity
                // contract: every staging site drains where it stages; a
                // deferred drain could overflow the staging across
                // un-flushed ticks and permanently re-leak a cache entry).
                let _ = obs.liveliness_gets.sweep_timed_out(now_ms);
                for interest_id in obs.liveliness_gets.take_finalized() {
                    actions_for_sweep.prune_liveliness_get_interest(interest_id);
                }
            }
            // R311lg — the reply sweep's timed-out on_final fires are
            // STAGED by the deferred reply sinks; drain them now that
            // the observer lock is released (the F-6 drain pairing —
            // every dispatch-like site pairs with a drain). Overlap
            // with the drive loop's drain is lossless (cell backlog).
            session_for_sweep.drain_deferred_fires();
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
    // Bound to a `let` (not an inline `&…::spec_defaults()`) so the borrow
    // outlives the `tokio::select!` future (E0716: a temporary would drop
    // before the select polls the future).
    let session_timeouts = SessionTimeouts::spec_defaults();
    // R311ld — the Session dispatch SSOT pairs the observer dispatch
    // with the deferred-fire drain (the F-6 contract) in one call; the
    // switchboard fan rides the `_with` under-lock hook so it shares
    // the same lock scope as before.
    let session_for_dispatch = session.clone();
    // R311pw — the per-iteration dispatch is built ONCE as a `FnMut` and passed
    // by `&mut` into whichever drive arm runs (a `&mut F` is itself `FnMut`),
    // so the one-shot and reconnect paths share one dispatch body rather than
    // cloning the switchboard fan. The body is unchanged from the pre-fork
    // inline closure (R311ld SSOT dispatch + gc-3 switchboard fan).
    let mut dispatch = |event: IterationEvent<'_>| {
        log::debug!("wz-ap-demo: iteration event = {event:?}");
        // R311ld — the SSOT fans the event into the per-domain
        // registries + flushes staged outbound records, then
        // drains the deferred-fire queue after the lock drops.
        session_for_dispatch.dispatch_iteration_event_with(event, |obs| {
            // gc-3 carry #2 — also fan an inbound Push through the
            // switchboard into the application engine, under the
            // SAME lock scope as the registry fan. IterationEvent
            // is Copy, so the same event drives both. The value
            // injector decodes the wire payload (temp_payload
            // codec) into the typed _event.data; a signal row
            // (reset) injects an empty _event.data. A matched row
            // advances the app machine, which we then step + log.
            #[cfg(feature = "switchboard")]
            {
                let fired = {
                    let mut injector = wz_ap_demo_app::SensorMonitorInjector::new(&mut app_engine);
                    obs.dispatch_switchboard(event, &mut injector)
                };
                if fired > 0 {
                    app_engine.step();
                    log::info!(
                        "wz-ap-demo: APP SWITCHBOARD FIRED fired={fired} \
                         app_state={:?}",
                        app_engine.get_current_state()
                    );
                }
            }
            #[cfg(not(feature = "switchboard"))]
            let _ = obs;
        });
    };

    // R311pw — drive FORK. Both arms race the drive against the graceful
    // shutdown signal via the SAME select!-drop cancel path; each yields the
    // `(was_cancelled, writer_handle)` the shared R292 teardown consumes.
    let (was_cancelled, writer_handle) = match drive_src {
        // One-shot (Acceptor / non-reconnect Initiator): drive the FSM once to
        // terminal. The engine + inbound half live in this stack frame (not
        // inside the future), so the shutdown select!-drop is cancel-safe.
        DriveSource::OneShot(opened) => {
            let OpenedSession {
                mut engine,
                inbound,
                writer_handle,
                ..
            } = *opened;
            let mut driver = inbound;
            let outcome = race_against_shutdown(
                drive_session_until_terminal(
                    &mut driver,
                    &actions,
                    &mut engine,
                    Some(10_000),
                    &session_clock,
                    &session_timeouts,
                    &mut dispatch,
                ),
                "drive_session",
            )
            .await;
            match &outcome {
                Some(o) => log::info!("wz-ap-demo: session ended: {o:?}"),
                None => log::info!(
                    "wz-ap-demo: session cancelled by graceful-shutdown signal; \
                     Close(Generic) enqueues after UndeclToken in the writer drain"
                ),
            }
            (outcome.is_none(), writer_handle)
        }
        // Reconnect Initiator (`--reconnect`): the supervisor re-dials + replays
        // the declaration cache on link loss, so the FSM reaching terminal does
        // NOT end the demo — it runs the long-lived lifecycle until the shutdown
        // signal cancels the drive future (`stop` stays false; shutdown is the
        // select!-drop, the same cancel path the one-shot uses). A `GaveUp`
        // (reconnect retries exhausted) also surfaces here as a natural end.
        DriveSource::Reconnect(mut recon) => {
            // `stop` stays false: the demo's reconnect lifecycle ends only via
            // the shutdown select!-drop (below) or a GaveUp; it never sets the
            // stop flag (that is the in-process caller-stop path the library
            // tests exercise). per-connection cap = None = long-lived.
            let stop = AtomicBool::new(false);
            let outcome = race_against_shutdown(
                recon.drive(&session_timeouts, &stop, None, &mut dispatch),
                "reconnect supervisor",
            )
            .await;
            match &outcome {
                Some(ReconnectDriveOutcome::Stopped) => {
                    log::info!("wz-ap-demo: reconnect drive stopped")
                }
                Some(ReconnectDriveOutcome::GaveUp { attempts, last }) => log::info!(
                    "wz-ap-demo: reconnect supervisor gave up after {attempts} attempt(s): {last:?}"
                ),
                Some(ReconnectDriveOutcome::IterationLimit) => {
                    log::info!("wz-ap-demo: reconnect drive hit per-connection iteration limit")
                }
                None => log::info!(
                    "wz-ap-demo: reconnect session cancelled by graceful-shutdown signal; \
                     Close(Generic) enqueues after UndeclToken in the writer drain (reconnects={})",
                    recon.reconnects()
                ),
            }
            // R311py — unwrap the supervisor into the teardown handles. `actions`
            // is discarded (we already hold our own clone from
            // drive_src.actions() above); the last-established connection's
            // writer feeds the R292 chain. On a GaveUp the returned writer is the
            // prior, already-closed link — a degenerate (immediately-returning)
            // drain, correct for an abandoned session with no live peer (see
            // ReconnectingSession::into_teardown).
            let ReconnectTeardown {
                actions: _,
                writer_handle,
            } = recon.into_teardown();
            (outcome.is_none(), writer_handle)
        }
    };
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
        liveliness_get_handle,
        token,
        actions,
        writer_handle,
        was_cancelled,
        clock: session_clock,
    }
    .abort_sweep_join_tasks()
    .await
    .drop_liveliness_token()
    .emit_close_if_cancelled()
    .drop_actions()
    .drain_writer()
    .await;

    Ok(())
}

/// R311qi — format a face's remote peer zid as lowercase hex for the multi-peer
/// face logs (zid is the routing identity learned at handshake; `?` if the
/// handshake did not surface it). Shared by the router and peer face observers.
#[cfg(any(feature = "routing-router", feature = "routing-peer"))]
fn zid_hex(zid: Option<&[u8]>) -> String {
    // Wire-order lowercase per-byte hex (same rendering as `Zid::Display`, but NOT
    // via it): this helper is compiled for routing-ROUTER too, where the routing
    // `Zid` (a routing-peer-only re-export) is absent — so it formats the bytes
    // directly rather than coupling a router-mode log helper to the peer-mode type.
    match zid {
        Some(bytes) => bytes.iter().map(|b| format!("{b:02x}")).collect(),
        None => "?".to_string(),
    }
}

/// The shared face-lifecycle observer for the multi-peer run-modes — one log line
/// per `AcceptEvent`, prefixed with the caller's `node_label` (`"router"` /
/// `"peer"` / `"router-hat"`). Extracted (rule-of-three) from the byte-identical
/// four-arm match `run_router`, `run_peer`, and `run_router_hat` would otherwise
/// each carry; only the prefix differed. Passed as `|event| log_face_event("...",
/// event)` to `accept_loop` / `peer_loop`.
#[cfg(any(feature = "routing-router", feature = "routing-peer"))]
fn log_face_event(node_label: &str, event: &wz::runtime_tokio::accept_loop::AcceptEvent) {
    use wz::runtime_tokio::accept_loop::AcceptEvent;
    match event {
        AcceptEvent::FaceUp(face) => log::info!(
            "wz-ap-demo {node_label}: face {} UP (peer {}, zid {})",
            face.id.0,
            face.peer,
            zid_hex(face.peer_zid.as_deref())
        ),
        AcceptEvent::FaceDown(face, outcome) => log::info!(
            "wz-ap-demo {node_label}: face {} DOWN (peer {}, {outcome:?})",
            face.id.0,
            face.peer
        ),
        AcceptEvent::FaceFailed { id, peer, cause } => log::warn!(
            "wz-ap-demo {node_label}: face {} FAILED (peer {peer}, {cause:?})",
            id.0
        ),
        AcceptEvent::AcceptError(e) => {
            log::warn!("wz-ap-demo {node_label}: accept error (continuing): {e}")
        }
    }
}

/// R311qa — multi-peer ROUTER mode: bind once and hold N concurrent peer faces
/// (the `routing-router` foundation), distinct from the one-shot `--listen`
/// Acceptor. Binds the `--router` endpoint, then runs the library
/// [`accept_loop`](wz::runtime_tokio::accept_loop) — every inbound peer is
/// brought to Established and held as a *face* until it closes — logging each
/// face up/down so the live hold set is observable. With the `routing-routes`
/// feature the held faces become *routes*: a [`RoutingForwarder`](wz::runtime_tokio::routing_forward::RoutingForwarder)
/// forwards a Put received on one face to every other face that declared a
/// matching subscriber (the data-plane atom). Without it (`routing-router`
/// alone) the loop is the accept-and-hold transport foundation — faces are
/// held but route nothing between them.
///
/// Runs until the graceful-shutdown signal (SIGTERM / SIGINT, the same
/// [`shutdown_signal`] the single-session drive races), then reports how many
/// peers were served and the high-water concurrency. The node identity is the
/// Acceptor params (whatami Peer) — the well-tested accept direction; a true
/// `WhatAmI::Router` wire value is a later refinement, not part of this atom.
#[cfg(feature = "routing-router")]
pub(crate) async fn run_router(listen: &str) -> io::Result<()> {
    use crate::args::NodeKind;
    use wz::runtime_tokio::accept_loop::{accept_loop, AcceptEvent};
    use wz::runtime_tokio::session_open::bind_endpoint;

    let listener = bind_endpoint(listen).await?;
    let local = listener.local_addr()?;
    #[cfg(feature = "routing-routes")]
    log::info!(
        "wz-ap-demo router: listening on {local}; holding N concurrent peer \
         faces and FORWARDING Puts to matching subscribers (routing-routes)"
    );
    #[cfg(not(feature = "routing-routes"))]
    log::info!(
        "wz-ap-demo router: listening on {local}; holding N concurrent peer \
         faces (routing-router foundation, no forwarding)"
    );

    let params = demo_session_init_params(NodeKind::Router);

    // The forwarding seam: with `routing-routes` the router routes Puts between
    // faces ([`RoutingForwarder`]); without it the accept-and-hold foundation
    // holds faces but routes nothing ([`NoOpForwarder`]).
    #[cfg(feature = "routing-routes")]
    let forwarder = wz::runtime_tokio::routing_forward::RoutingForwarder::new();
    #[cfg(not(feature = "routing-routes"))]
    let forwarder = wz::runtime_tokio::accept_loop::NoOpForwarder;

    let summary = accept_loop(
        listener,
        params,
        TokioTime::new(),
        DEFAULT_OPEN_TICK_MS,
        shutdown_signal(),
        |event: &AcceptEvent| log_face_event("router", event),
        &forwarder,
    )
    .await;

    // R311qj — `route_computations()` is logged here as a genuine cache-
    // effectiveness ops signal (cumulative route scans; low relative to
    // `forwarded` = good cache reuse), giving the `RouteTable`'s miss counter a
    // production reader rather than a test-only one.
    #[cfg(feature = "routing-routes")]
    log::info!(
        "wz-ap-demo router: shutdown; served {} peer(s), peak {} concurrent \
         face(s), forwarded {} sample(s), computed {} route(s)",
        summary.established,
        summary.peak_concurrent,
        forwarder.forwarded(),
        forwarder.route_computations()
    );
    #[cfg(not(feature = "routing-routes"))]
    log::info!(
        "wz-ap-demo router: shutdown; served {} peer(s), peak {} concurrent face(s)",
        summary.established,
        summary.peak_concurrent
    );
    Ok(())
}

/// R311qg — peer-MESH mode: bind once, DIAL each configured peer, and accept
/// inbound — holding both directions' faces (the `routing-peer` foundation,
/// hold-only). The dial+accept generalisation of [`run_router`]: where a router
/// only accepts, a peer also dials out to form a mesh. Binds `listen`, parses the
/// `dial_targets` (TCP socket addresses for this atom), then runs the library
/// [`peer_loop`](wz::runtime_tokio::accept_loop::peer_loop) with a
/// [`LinkstateForwarder`](wz::runtime_tokio::linkstate_forward::LinkstateForwarder)
/// (R311rb / c3d-3): each held face feeds a linkstate-peer topology graph, the
/// peer periodically floods its own link-state so neighbours converge, and an
/// inbound link-state is re-flooded onward (transitive mesh propagation). Each
/// face up/down is logged so the live hold set is observable; the shutdown
/// summary reports the dialed / accepted split, high-water concurrency, and the
/// link-state ingest count.
///
/// Runs until the graceful-shutdown signal (SIGTERM / SIGINT). The node identity
/// is whatami Peer (`NodeKind::Peer` maps to 0x02) — which is genuinely correct
/// for a peer (unlike the router, whose 0x02 is a documented stand-in for a true
/// WhatAmI::Router); the well-tested accept / initiate directions drive it.
/// R311y47 — the per-peer behaviour knobs (CLI-derived), bundled into one
/// parameter so the peer entry points stay within the argument-count limit
/// (Introduce-Parameter-Object; the repo's `SessionDriveConfig` retired the same
/// `clippy::too_many_arguments` allow). Consistent with [`crate::InterceptorOpts`].
#[cfg(feature = "routing-peer")]
pub(crate) struct PeerOpts {
    pub publish_key: Option<String>,
    pub subscribe_key: Option<String>,
    pub unsubscribe_after_data: bool,
    pub autoconnect: bool,
    pub config_queryable: bool,
    /// R311y48 (§5.23 Phase 3b) — host a config-WRITE subscriber on
    /// `@/<zid>/peer/config/**` so a remote PUT reconfigures this peer's live
    /// forwarder (the `--config-writable` opt-in). HOSTS the surface; whether an
    /// arriving write is applied is [`config_write_permit`](Self::config_write_permit).
    pub config_writable: bool,
    /// R311y51 (§5.23 `adminspace-write`) — grant the `permissions.write` gate so
    /// a received config-WRITE is APPLIED. Default-deny (zenoh `PermissionsConf`
    /// `write:false`): under the `adminspace-write` cfg a PUT is DENIED without
    /// this; with the gate compiled out every PUT applies. Orthogonal to
    /// [`config_writable`](Self::config_writable) — host vs permit.
    pub config_write_permit: bool,
    /// R311y48 — originate a Put to this key each app tick carrying
    /// [`put_payload`](Self::put_payload) (the wire driver for a config-write
    /// PUT). Inert unless both are set.
    pub put_key: Option<String>,
    /// R311y48 — the payload bytes the [`put_key`](Self::put_key) Put carries.
    pub put_payload: Option<String>,
}

#[cfg(feature = "routing-peer")]
pub(crate) async fn run_peer(
    listen: &str,
    dial_targets: &[String],
    opts: &PeerOpts,
    interceptors: &crate::InterceptorOpts,
) -> io::Result<()> {
    // Destructure into the same local names + types the body uses (the Options as
    // `Option<&str>`), so the bundle is purely a signature change.
    let publish_key = opts.publish_key.as_deref();
    let subscribe_key = opts.subscribe_key.as_deref();
    let unsubscribe_after_data = opts.unsubscribe_after_data;
    let autoconnect = opts.autoconnect;
    let config_queryable = opts.config_queryable;
    let config_writable = opts.config_writable;
    let config_write_permit = opts.config_write_permit;
    let put_key = opts.put_key.as_deref();
    let put_payload = opts.put_payload.as_deref();
    use crate::args::NodeKind;
    use std::time::Duration;
    use wz::runtime_tokio::accept_loop::{peer_loop, AcceptEvent, FaceSources};
    use wz::runtime_tokio::linkstate_forward::{
        default_autoconnect_matcher, AclConfig, AclFlow, AclMessage, AclPolicy, AclRule,
        AutoConnect, AutoConnectStrategy, DownsamplingRule, InterceptorConfig, LinkstateForwarder,
        LowPassRule, Permission, SubjectSelector, WhatAmI, Zid,
    };
    use wz::runtime_tokio::session_open::bind_endpoint;

    // Per-peer routing zid = this 2-byte prefix + the listen port (derived
    // below). The mesh routing graph keys on the zid, so two peers MUST NOT
    // share one; the prefix keeps the demo's derived zids in a recognisable
    // range. (The periodic self-flood cadence now lives in the
    // LinkstateForwarder itself — R311rf, on the FaceForwarder seam — so this
    // demo no longer owns a flood timer.)
    const PEER_ZID_PREFIX: u16 = 0x7072;
    // Cadence of the DEMO APPLICATION driver (not the protocol flood): a
    // `--publish` peer originates a data Put each tick, and every peer observes
    // its received-data count. Fast enough to publish soon after convergence.
    const APP_TICK_MS: u64 = 250;

    let listener = bind_endpoint(listen).await?;
    let local = listener.local_addr()?;

    // Parse the outbound dial targets — TCP socket addresses for this atom (the
    // accept side is also TCP-only). A malformed target fails fast rather than
    // silently dropping a mesh link.
    let mut dials = Vec::with_capacity(dial_targets.len());
    for target in dial_targets {
        match target.parse::<std::net::SocketAddr>() {
            Ok(addr) => dials.push(addr),
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("wz-ap-demo peer: invalid --connect dial target {target:?}: {e}"),
                ));
            }
        }
    }

    log::info!(
        "wz-ap-demo peer: listening on {local}; dialing {} configured peer(s), \
         holding both directions' faces and forwarding mesh data along the \
         linkstate spanning tree{}",
        dials.len(),
        match (publish_key.is_some(), subscribe_key.is_some()) {
            (true, true) => " (publishing + subscribing)",
            (true, false) => " (publishing)",
            (false, true) => " (subscribing)",
            (false, false) => "",
        }
    );

    let mut params = demo_session_init_params(NodeKind::Peer);
    // R311rc (c3d-4) — derive a DISTINCT zid per peer from its listen port.
    // The mesh routing graph keys on the zid, so two peers MUST NOT share one
    // (the demo's single hardcoded 0x01020304 would collide — a node would
    // ingest a remote link-state under its OWN zid). Production supplies a
    // real per-process zid; the demo derives a deterministic distinct one.
    let port = local.port();
    params.zid = vec![
        (PEER_ZID_PREFIX >> 8) as u8,
        (PEER_ZID_PREFIX & 0xff) as u8,
        (port >> 8) as u8,
        (port & 0xff) as u8,
    ];

    // R311rb/rf — the peer maintains a linkstate-peer routing graph: each held
    // face feeds the topology graph ([`LinkstateForwarder`]), which floods its
    // own link-state on its OWN periodic tick and bootstraps each new neighbour
    // at face-up, so the mesh converges for every peer_loop caller (the flood
    // is on the FaceForwarder seam now, not a hand-rolled select here).
    // `WhatAmI::Peer` is this node's role; `params.zid` is its id. `new` takes a
    // `Zid`; the self zid is this node's own (trusted) identity, so the
    // infallible `Zid::from_slice` is the right boundary ctor (a wire zid would
    // use the validating `Zid::try_from`). Borrows `params.zid`, leaving it owned
    // by `params` to pass on to peer_loop below.
    let forwarder = LinkstateForwarder::new(Zid::from_slice(&params.zid), WhatAmI::Peer);
    // Advertise this peer's listen address as its dial locator BEFORE the first
    // face registers, so self's first FULL flood already carries it. A neighbour
    // then learns where to reach this peer (the discovery data — what a future
    // gossip/autoconnect step dials). `local` is the bound TCP endpoint; the
    // zenoh locator form is `tcp/<addr>`.
    //
    // An unspecified bind (0.0.0.0 / [::], the deploy default) is NOT a dialable
    // address: advertising `tcp/0.0.0.0:<port>` hands a peer a locator it cannot
    // connect to. zenoh expands an unspecified bind to the host's concrete
    // interface addresses (`io/zenoh-link-commons/src/listener.rs:115-145`);
    // until wz mirrors that, advertise nothing rather than a bogus locator —
    // topology still converges, only the (not-yet-consumed) dial hint is withheld.
    let self_locators: Vec<String> = if local.ip().is_unspecified() {
        log::warn!(
            "listen address {local} is unspecified (bind-all); advertising no dial \
             locator (interface expansion is a tracked follow-up)"
        );
        Vec::new()
    } else {
        vec![format!("tcp/{local}")]
    };
    // Clone so `self_locators` survives for the §5.23 admin handler below (the
    // forwarder-hosted admin's `local_data` advertises the same dial locators).
    forwarder.set_self_locators(self_locators.clone());

    // §5.16 interceptor pipeline — assemble ONE InterceptorConfig from the
    // opt-in flags and install it via the single config seam (the wz mirror of
    // zenoh's interceptor_factories(config)), in zenoh's fixed factory order.
    // Absent every flag the config is empty and both chains stay empty (access
    // control disabled, every message admitted).
    let mut interceptor_config = InterceptorConfig::default();

    // R311y48 — the deny-policy SSOT: build the allow-default ACL that denies one
    // keyexpr across the data AND query planes, both flows, for every subject (the
    // smallest real ACL). BOTH the startup `--acl-deny` flag AND the runtime
    // config-write drain (`@/<zid>/peer/config/acl-deny`) build their policy here,
    // so the two paths produce byte-identical rules from one definition (the
    // §5.16 rule set is not duplicated across setup and reconfigure). A rule per
    // FLOW (a rule carries a single flow): the keyexpr is denied BOTH on ingress (a
    // neighbour cannot push/subscribe/query/declare-a-queryable/reply on it through
    // us) and on egress (we never relay it out, nor originate it toward a peer).
    let acl_deny_policy = |deny_keyexpr: &str| -> AclPolicy {
        let deny_rule = |flow| AclRule {
            subject: SubjectSelector::Any,
            key_exprs: vec![deny_keyexpr.to_owned()],
            messages: vec![
                AclMessage::Put,
                AclMessage::Delete,
                AclMessage::DeclareSubscriber,
                // The query plane (R311ud): denying K also blocks querying it,
                // declaring a queryable for it, and replying on it.
                AclMessage::Query,
                AclMessage::DeclareQueryable,
                AclMessage::Reply,
            ],
            flow,
            permission: Permission::Deny,
        };
        AclPolicy::new(AclConfig {
            default_permission: Permission::Allow,
            rules: vec![deny_rule(AclFlow::Ingress), deny_rule(AclFlow::Egress)],
        })
    };

    // `--acl-deny <keyexpr>`: opt this peer into §5.16 access control at STARTUP —
    // both dropped (not relayed onward), the wz analogue of a router carrying an
    // IngressAclEnforcer. (The same deny is also reachable at RUNTIME via a remote
    // config-write under `--config-writable`, below.)
    if let Some(deny_keyexpr) = interceptors.acl_deny.as_deref() {
        log::info!("wz-ap-demo peer: access control enabled (--acl-deny {deny_keyexpr})");
        interceptor_config.acl = Some(acl_deny_policy(deny_keyexpr));
    }

    // `--downsample <keyexpr>`: opt this peer into §5.16 downsampling (QoS) — the
    // rate-limit sibling of the ACL on the SAME interceptor chain. Data on the
    // keyexpr is admitted at most once per 500 ms; faster ones are dropped. Off
    // by default. Composes with `--acl-deny` (both run on the chain, both flows).
    if let Some(downsample_keyexpr) = interceptors.downsample.as_deref() {
        log::info!(
            "wz-ap-demo peer: downsampling enabled (--downsample {downsample_keyexpr} @ 500ms)"
        );
        interceptor_config.downsampling = vec![DownsamplingRule {
            key_exprs: vec![downsample_keyexpr.to_owned()],
            min_interval: Duration::from_millis(500),
        }];
    }

    // `--max-payload <bytes>`: opt into §5.16 access-quota (a per-key payload-size
    // cap, zenoh low_pass) on EVERY keyexpr — a Put larger than the limit is
    // dropped. The third interceptor kind on the chain. Off by default; a
    // non-numeric value is ignored with a warning.
    if let Some(max_payload) = interceptors.max_payload.as_deref() {
        match max_payload.parse::<usize>() {
            Ok(max_payload_size) => {
                log::info!("wz-ap-demo peer: low-pass enabled (--max-payload {max_payload_size}B)");
                interceptor_config.low_pass = vec![LowPassRule {
                    key_exprs: vec!["**".to_owned()],
                    max_payload_size,
                }];
            }
            Err(_) => log::warn!(
                "wz-ap-demo peer: --max-payload '{max_payload}' is not a byte count; ignored"
            ),
        }
    }

    // R311y41/y43 — the interceptor install routes deploy-opts -> WzConfig ->
    // forwarder through the typed config, now via the `InterceptorSink` TRAIT SEAM
    // (R311y43: WzConfig drives an abstract sink, decoupled from the concrete
    // LinkstateForwarder — the same seam a runtime reconfigure re-uses, so setup
    // and runtime share ONE code path). The startup log shows the read-at-open
    // mirror.
    //
    // R311y45 (§5.23 Phase 2b) — the node's config SSOT is now a SHARED
    // `Rc<RefCell<WzConfig>>` (single-task node, so Rc/RefCell not Arc/Mutex). The
    // forwarder-drive installs from it; under `--config-queryable` the
    // forwarder-hosted admin handler reads the SAME instance per query. ONE
    // WzConfig both drives the forwarder AND answers the admin GET — the runtime
    // composition the y42 finding asked for, now STRUCTURALLY closed (one Rc, two
    // surfaces; the Phase-1 deferred sharing primitive lands here with the admin
    // handler as its genuine 2nd holder). CAVEAT: `to_admin_json` serves only the
    // READ-AT-OPEN fields (batch/lease/whatami), handshake-fixed — so a GET cannot
    // OBSERVE a runtime change and the single-instance-ness is a structural
    // property, not a wire-observable one. Live-reconfigure-over-wire visibility
    // (interceptor config in the JSON) is a deferred §5.23 layer.
    let wz_config = std::rc::Rc::new(std::cell::RefCell::new(
        wz::runtime_tokio::config::WzConfig::from_init_params(&params)
            .with_interceptors(interceptor_config),
    ));
    {
        let cfg = wz_config.borrow();
        log::info!(
            "wz-ap-demo peer config (read-at-open): {}",
            cfg.to_admin_json()
        );
        cfg.install_interceptors(&forwarder);
    }

    // R311y48 (§5.23 Phase 3b) — the config-write INTENT slot. A remote PUT to
    // `.../config/acl-deny` parses to a deny keyexpr that the config-write
    // subscriber handler stashes HERE (wire -> intent); the app-tick loop DRAINS
    // and applies it (intent -> reconfigure). The split is structural: the handler
    // is stored INSIDE the forwarder, so it cannot also hold `&forwarder` to drive
    // the reconfigure (an Rc cycle / borrow conflict); the apply therefore happens
    // at the composition root (run_peer), which owns BOTH the shared WzConfig and
    // `&forwarder`. This keeps the forwarder decoupled from WzConfig — the whole
    // point of the R311y43 `InterceptorSink` seam — and the subscriber handler
    // signature unchanged (`FnMut(&dyn SampleView)`, no interceptor-sink param a
    // plain data subscriber would never use).
    let pending_acl_deny: std::rc::Rc<std::cell::RefCell<Option<String>>> =
        std::rc::Rc::new(std::cell::RefCell::new(None));

    // `--config-queryable`: §5.23 Phase 2b — host this peer's adminspace on the
    // forwarder. A querier's GET for `@/<zid>/peer/config` routes to A's
    // forward_request, finds no remote queryable (the admin key is self-unique),
    // self-dispatches (R311y44) to this handler, which reads the shared WzConfig
    // (its read-at-open mirror) per query and replies via the `answer_admin_query`
    // SSOT (the SAME answerer `Session::declare_adminspace` uses). The reply unwinds
    // to the querier. `sessions[]` is empty — the live forwarder-faces enumeration
    // is a documented deferral; the config GET (the §5.23 headline) does not need it.
    if config_queryable {
        use wz::runtime_tokio::adminspace::{
            admin_config_key, admin_queryable_key, answer_admin_query, AdminAnswerCtx,
        };
        use wz::runtime_tokio::query_sink::{QueryView, ReplyOut};
        use wz::runtime_tokio::zid_hex::zid_to_zenoh_hex;
        let zid_hex = zid_to_zenoh_hex(&params.zid);
        // SSOT-derive the role from the same `params.whatami` the config body's
        // `to_admin_json` serializes — a literal would risk the admin keyexpr /
        // reply-key role diverging from the served `"whatami"` if the role changed.
        let whatami_str = params.whatami.to_str();
        let version = env!("CARGO_PKG_VERSION").to_string();
        let locators = self_locators;
        let queryable_key = admin_queryable_key(&zid_hex, whatami_str);
        let config_key = admin_config_key(&zid_hex, whatami_str);
        let shared = wz_config.clone();
        let handler = move |view: &dyn QueryView, out: &mut dyn ReplyOut| {
            let config_json = shared.borrow().to_admin_json();
            let ctx = AdminAnswerCtx {
                zid_hex: &zid_hex,
                whatami: whatami_str,
                version: &version,
                locators: &locators,
                read: true,
            };
            answer_admin_query(view, out, &ctx, &[], &config_json);
        };
        match forwarder.register_local_queryable(&queryable_key, true, Box::new(handler)) {
            Ok(_) => {
                log::info!("wz-ap-demo peer: adminspace config GET at {config_key}");
            }
            Err(e) => {
                log::warn!("wz-ap-demo peer: adminspace registration failed: {e:?}");
            }
        }
    }

    // `--config-writable`: §5.23 Phase 3b — host this peer's config-WRITE
    // subscriber on `@/<zid>/peer/config/**` (zenoh's write-only config subscriber
    // pattern, adminspace.rs:350-353). A remote PUT to a config sub-key floods to
    // this node (the subscriber interest routes it here), and the R311y46
    // dispatch_local_subscribers fires this handler — the Push-plane twin of the
    // y44 self-query dispatch the config GET uses. The handler does wire->intent
    // ONLY (parse + stash the deny keyexpr into `pending_acl_deny`); the app-tick
    // loop applies it (intent->reconfigure), where `&forwarder` is reachable.
    if config_writable {
        use wz::runtime_tokio::admin_write_permit;
        use wz::runtime_tokio::adminspace::{
            admin_config_key, admin_config_write_key, parse_admin_config_write, AdminConfigWrite,
            AdminConfigWriteOutcome, AdminSpacePermissions,
        };
        use wz::runtime_tokio::sink::SampleView;
        use wz::runtime_tokio::zid_hex::zid_to_zenoh_hex;
        let zid_hex = zid_to_zenoh_hex(&params.zid);
        let whatami_str = params.whatami.to_str();
        let write_key = admin_config_write_key(&zid_hex, whatami_str);
        // The `@/<zid>/peer/config/` prefix a PUT key's config sub-key hangs under
        // (`admin_config_key` + the separating slash) — stripped to recover the
        // sub-key the handler routes on.
        let write_prefix = {
            let mut p = admin_config_key(&zid_hex, whatami_str);
            p.push('/');
            p
        };
        // R311y51/y52 (§5.23 adminspace-write) — the `permissions.write` gate, the
        // write-side mirror of the adminspace-read GET gate. `--config-writable`
        // HOSTS the write subscriber; `--config-write-permit` PERMITS the writes it
        // receives (two orthogonal controls — the write analogue of
        // declare_adminspace vs declare_adminspace_with_permissions). The embedder's
        // permission struct is built from the flag (read stays permissive); the
        // library `admin_write_permit` (the adminspace-write cfg site) resolves the
        // effective permit — under the gate it reads `permissions.write` (default-deny,
        // zenoh PermissionsConf write:false), with the gate compiled out it is `true`
        // (apply-all, the pre-y51 behavior). The resolved value then flows through the
        // feature-independent parse_admin_config_write SSOT.
        let permissions = AdminSpacePermissions {
            write: config_write_permit,
            ..Default::default()
        };
        let write_permitted = admin_write_permit(&permissions);
        let pending = pending_acl_deny.clone();
        let handler = move |sample: &dyn SampleView| {
            // Gate (permissions.write) + decode via the wz-session-core SSOT, the
            // write-side counterpart of answer_admin_query.
            match parse_admin_config_write(
                &write_prefix,
                sample.keyexpr(),
                sample.payload(),
                write_permitted,
            ) {
                AdminConfigWriteOutcome::Apply(AdminConfigWrite::AclDeny(deny_kx)) => {
                    log::info!("wz-ap-demo peer: config-write received acl-deny {deny_kx}");
                    *pending.borrow_mut() = Some(deny_kx);
                }
                // permissions.write=false — zenoh logs this at error (adminspace.rs:397).
                AdminConfigWriteOutcome::Denied => log::error!(
                    "wz-ap-demo peer: config-write DENIED \
                     (adminspace.permissions.write=false; grant with --config-write-permit); \
                     ignored {}",
                    sample.keyexpr()
                ),
                AdminConfigWriteOutcome::Malformed => {
                    log::warn!("wz-ap-demo peer: config-write acl-deny with empty payload; ignored")
                }
                // The full json5/json-pointer config engine is a deferred §5.23 layer.
                AdminConfigWriteOutcome::UnknownKey(key) => log::warn!(
                    "wz-ap-demo peer: config-write unknown key '{key}' (only 'acl-deny' is \
                     recognized; the full json5 config engine is a deferred §5.23 layer); ignored"
                ),
                // The bare `.../config` GET key the `/**` subscriber also matches.
                AdminConfigWriteOutcome::NotAWrite => {}
            }
        };
        match forwarder.register_local_subscriber(&write_key, Box::new(handler)) {
            Ok(_) => {
                log::info!("wz-ap-demo peer: adminspace config WRITE at {write_key}");
            }
            Err(e) => {
                log::warn!("wz-ap-demo peer: adminspace config-write registration failed: {e:?}");
            }
        }
    }

    // `--autoconnect`: opt this peer into gossip-autoconnect. The role matcher is
    // the per-local-whatami SSOT default (a Peer dials discovered routers/peers);
    // `GreaterZid` is the double-dial tie-break (of a mutually-discovering pair,
    // only the greater-zid end dials — and the establishment dedup drops any
    // redundant link that still races through). The forwarder then emits a
    // dial-intent for each admitted discovered peer, and the loop dials it. Absent
    // the flag, `dial_intents` is `None` and the peer dials only its static
    // `--connect` targets (the prior behaviour exactly).
    let dial_intents = autoconnect.then(|| {
        log::info!("wz-ap-demo peer: gossip-autoconnect enabled (--autoconnect)");
        let policy = AutoConnect::new(
            Zid::from_slice(&params.zid),
            default_autoconnect_matcher(WhatAmI::Peer),
            AutoConnectStrategy::GreaterZid,
        );
        forwarder.enable_autoconnect(policy)
    });

    let loop_fut = peer_loop(
        FaceSources {
            listener,
            dial_targets: dials,
            dial_intents,
            // A peer node hosts no router multicast ingress plane.
            mcast_ingress: None,
            mcast_members: None,
            mcast_group_subs: None,
        },
        params,
        TokioTime::new(),
        DEFAULT_OPEN_TICK_MS,
        shutdown_signal(),
        |event: &AcceptEvent| log_face_event("peer", event),
        &forwarder,
    );
    tokio::pin!(loop_fut);

    // R311ri (c3c e2e) — a DEMO APPLICATION driver, distinct from the protocol
    // flood (which lives on the FaceForwarder seam, R311rf): on each tick a
    // `--publish` peer ORIGINATES a data Put into the mesh (flooded along its
    // own spanning tree by the forwarder), and EVERY peer observes how many
    // data Pushes it has received, logging the first rise so the e2e witnesses
    // multi-hop delivery. The topology self-flood is NOT here — only the demo's
    // application I/O (publish + observe). The peer loop still drives the flood.
    let mut app_tick = tokio::time::interval(Duration::from_millis(APP_TICK_MS));
    let mut last_data_seen = 0usize;
    let mut announced_interest = false;
    let mut announced_withdrawal = false;
    let mut declared = false;
    let mut undeclared = false;
    // High-water mark of the topology-graph node count, sampled each tick. The
    // shutdown summary reports THIS, not the live `node_count()`: teardown
    // deregisters every face, and a face-down now GC-prunes the nodes it
    // detached (c3c-3 D3 remove_detached_nodes), so the live graph collapses
    // toward self during shutdown. The peak is the meaningful convergence
    // witness — "this peer's graph held N peers once it had converged" — which
    // is what the e2e asserts on (it must read the converged size, not the
    // mid-teardown remnant).
    let mut peak_nodes = 0usize;
    // High-water mark of the MUTUAL-edge count, sampled each tick — the
    // reciprocal-link witness distinct from `peak_nodes`. An edge forms only
    // when a neighbour's INGESTED link-state advertises a link back to self
    // (`LinkstateForwarder::edge_count`), so `peak_edges > 0` proves this peer
    // ingested a FULL-LINKSTATE flood (self-entry `links={self}`), not merely a
    // gossip self-announcement (which bumps `ingested`/`peak_nodes` but carries
    // no reciprocal link → no edge). Sampled at the tick because teardown prunes
    // edges (remove_link), same rationale as `peak_nodes`.
    let mut peak_edges = 0usize;
    // Fires the in-run reciprocal-link witness once, on the positive edge of
    // `edge_count` first rising — the settle barrier an e2e waits on before it
    // graceful-terminates (post-ingest, eliminating the face-UP race).
    let mut announced_reciprocal = false;
    // Fires the in-run ingest witness once, on the positive edge of `ingested`
    // first rising — the post-ingest settle barrier for a peer whose neighbour
    // floods a NODE-only link-state (a gossip `peer_to_peer` peer: `ingested`
    // rises but no reciprocal edge forms, so `announced_reciprocal` never trips).
    let mut announced_ingest = false;
    // R311y48 (§5.23 Phase 3b) — config-write apply state: the deny keyexpr last
    // applied (so a repeated PUT of the same value reconfigures + logs ONCE, not
    // per tick — idempotent), and the high-water interceptor-drop count for the
    // in-run drop witness.
    let mut last_applied_deny: Option<String> = None;
    let mut last_dropped = 0usize;
    // Fires the in-run client-queryable HOSTING witness once, on the positive edge
    // of `client_qabls_seen` first rising — a peer that ingested a co-attached
    // client's DeclareQueryable into `client_qabls` (the R311y177 hosting plane).
    // IN-TICK, not the shutdown block: `client_qabls_seen()` is a LIVE count that the
    // client's pre-shutdown face-down zeroes (deregister drains client_qabls), so a
    // shutdown-latched read would miss it — the log line must be written while the
    // client is still attached so it survives in the captured stderr.
    let mut announced_client_qabl = false;
    let summary = loop {
        tokio::select! {
            done = &mut loop_fut => break done,
            _ = app_tick.tick() => {
                peak_nodes = peak_nodes.max(forwarder.node_count());
                peak_edges = peak_edges.max(forwarder.edge_count());
                // Ingest witness: this peer decoded a neighbour's link-state flood
                // (the wire control-plane arrived). Logged once, on the positive
                // edge — the post-ingest settle a topology e2e waits on regardless
                // of whether the flood carried a reciprocal link (so a gossip-mode
                // neighbour, which never trips the edge witness below, still has a
                // deterministic barrier).
                if !announced_ingest && forwarder.ingested() > 0 {
                    announced_ingest = true;
                    log::info!(
                        "wz-ap-demo peer: ingested neighbour link-state ({} so far)",
                        forwarder.ingested()
                    );
                }
                // Reciprocal-link witness: a MUTUAL edge appears only once an
                // ingested neighbour flood advertised a link back to self. Logged
                // once, on the positive edge — the deterministic post-ingest signal
                // a full-linkstate federation e2e settles on (and the discriminator
                // a gossip-mode peer never trips: its self-flood carries no links).
                if !announced_reciprocal && forwarder.edge_count() > 0 {
                    announced_reciprocal = true;
                    log::info!(
                        "wz-ap-demo peer: reciprocal mesh link confirmed ({} edge(s))",
                        forwarder.edge_count()
                    );
                }
                // Client-queryable HOSTING witness: this peer ingested a co-attached
                // client's DeclareQueryable into `client_qabls` (the R311y177 hosting
                // plane) and self-advertised it into the mesh. Logged once, on the
                // positive edge — the mid-run barrier a cross-impl e2e gates the
                // QUERIER's spawn on, so a query flies only after this peer provably
                // hosts the client queryable. In-tick, not shutdown-latched:
                // `client_qabls_seen()` is a live count the client's teardown
                // face-down zeroes (mirror of the reciprocal/ingest positive edges).
                if !announced_client_qabl && forwarder.client_qabls_seen() > 0 {
                    announced_client_qabl = true;
                    log::info!(
                        "wz-ap-demo peer: learned a client queryable ({} queryable(s))",
                        forwarder.client_qabls_seen()
                    );
                }
                // c3c-3 debt A2 — a `--subscribe` peer declares its interest ONCE.
                // pubsub_tree_change (re_advertise_subscriptions on each tree
                // recompute) re-floods the subscription to peers that join later,
                // so the prior per-tick re-declare workaround is no longer needed.
                // c3c-3 debt A1 — `--unsubscribe-after-data` flips to RETRACTING
                // once the round-trip is confirmed (data received), also once: the
                // undeclare floods the source tree withdrawing this peer's interest
                // at each hop. Self-coordinating, so no timing window is assumed (a
                // peer that joins after the retraction never held the interest, so
                // a retraction needs no re-advertise).
                if let Some(key) = subscribe_key {
                    if unsubscribe_after_data && forwarder.data_seen() > 0 {
                        if !undeclared {
                            undeclared = true;
                            let _ = forwarder.undeclare_subscription(key);
                        }
                    } else if !declared {
                        declared = true;
                        let _ = forwarder.declare_subscription(key);
                    }
                }
                if let Some(key) = publish_key {
                    let _ = forwarder.publish(key, b"wz-mesh-data");
                    // Witness the subscription-filtered route: the publisher only
                    // forwards once it has LEARNED an interested subscriber (the
                    // declaration flooded back to it). Logged once, when interest
                    // first arrives — proof the propagation reached the publisher.
                    let interested_now = !forwarder.interested(key).is_empty();
                    if !announced_interest && interested_now {
                        announced_interest = true;
                        log::info!(
                            "wz-ap-demo peer: publisher learned subscriber interest ({} peer(s))",
                            forwarder.interested(key).len()
                        );
                    } else if announced_interest && !announced_withdrawal && !interested_now {
                        // c3c-3 debt A1 — the retraction reached the publisher: a
                        // learned interest is now gone (non-empty -> empty). A
                        // POSITIVE transition witness (not a flaky non-receipt),
                        // proof the UndeclareSubscriber propagated the full path.
                        announced_withdrawal = true;
                        log::info!(
                            "wz-ap-demo peer: publisher subscriber interest withdrawn"
                        );
                    }
                }
                // R311y48 — the wire driver for a config-write PUT: originate a Put
                // to `--put-key` carrying the `--put-payload` bytes each tick (vs
                // `--publish`'s fixed marker). A remote node uses this to PUT another
                // peer's `@/<A>/peer/config/acl-deny` with the keyexpr to deny.
                if let (Some(k), Some(v)) = (put_key, put_payload) {
                    let _ = forwarder.publish(k, v.as_bytes());
                }
                // R311y48 — apply a pending config-write: a remote PUT to
                // `.../config/acl-deny` stashed a deny keyexpr; drain it and
                // reconfigure the LIVE forwarder (the Phase-1 InterceptorSink drive),
                // MERGING it into the current interceptor config so the write changes
                // only the ACL slice (the `interceptors()` getter is the read leg).
                // Idempotent: re-applied only when the deny keyexpr CHANGES, so a
                // per-tick PUT of the same value is a no-op and the witness logs once.
                // Drain on its own line so the `RefCell` borrow is released BEFORE the
                // apply body (which re-borrows wz_config) — no nested-borrow fragility.
                let drained = pending_acl_deny.borrow_mut().take();
                if let Some(deny_kx) = drained {
                    if last_applied_deny.as_deref() != Some(deny_kx.as_str()) {
                        let mut merged = wz_config.borrow().interceptors().clone();
                        merged.acl = Some(acl_deny_policy(&deny_kx));
                        wz_config
                            .borrow_mut()
                            .reconfigure_interceptors(merged, &forwarder);
                        log::info!(
                            "wz-ap-demo peer: config reconfigured — now denying {deny_kx}"
                        );
                        last_applied_deny = Some(deny_kx);
                    }
                }
                let seen = forwarder.data_seen();
                if seen > last_data_seen {
                    last_data_seen = seen;
                    log::info!("wz-ap-demo peer: received mesh data ({seen} push(es))");
                }
                // R311y48 — the interceptor-drop witness: a positive-edge log when
                // the forwarder's drop count rises (an ACL/downsample/low-pass drop).
                // After a config-write deny takes effect, the next denied message
                // bumps this — the in-run proof the runtime reconfigure flipped the
                // live verdict.
                let dropped = forwarder.interceptor_dropped();
                if dropped > last_dropped {
                    last_dropped = dropped;
                    log::info!("wz-ap-demo peer: interceptor dropped ({dropped} message(s))");
                }
            }
        }
    };

    log::info!(
        "wz-ap-demo peer: shutdown; dialed {}, accepted {}, served {} peer(s), \
         peak {} concurrent face(s), ingested {} link-state(s), \
         peak {} node(s) in topology graph, {} graph edge(s), {} data push(es) received",
        summary.dialed,
        summary.accepted,
        summary.established,
        summary.peak_concurrent,
        forwarder.ingested(),
        peak_nodes.max(forwarder.node_count()),
        peak_edges.max(forwarder.edge_count()),
        forwarder.data_seen()
    );
    // Convergence witness the e2e asserts on: emitted ONLY when this peer
    // actually INGESTED a neighbour's link-state flood — proof topology
    // converged over the wire, not just that a face was held. The register-time
    // bootstrap delivers a neighbour's state at face-up, so a connected mesh
    // has ingested >= 1 by shutdown.
    if forwarder.ingested() > 0 {
        log::info!(
            "wz-ap-demo peer: learned mesh topology (ingested {} link-state(s), peak {} node(s) in graph)",
            forwarder.ingested(),
            peak_nodes.max(forwarder.node_count())
        );
    }
    // Reciprocal-link witness (the FULL-LINKSTATE discriminator): emitted ONLY
    // when this peer's graph gained a MUTUAL edge — a neighbour's ingested flood
    // advertised a link back to self. A gossip (`peer_to_peer`) neighbour bumps
    // `ingested` (its self-announcement decodes) but its self-entry carries no
    // links, so no edge forms and this witness stays absent. Thus a full-linkstate
    // peer federation emits BOTH "learned mesh topology" AND this line, while a
    // gossip peer emits ONLY the former — the load-bearing distinction between
    // `routing/peer/mode=linkstate` and the default `peer_to_peer`. Deterministic
    // at shutdown (peak-sampled), mirroring the `learned mesh topology` gate.
    if peak_edges.max(forwarder.edge_count()) > 0 {
        log::info!(
            "wz-ap-demo peer: confirmed reciprocal mesh link ({} edge(s) in graph)",
            peak_edges.max(forwarder.edge_count())
        );
    }
    // Data-reception witness — a DETERMINISTIC shutdown counterpart to the
    // in-run app-tick log (R311rj): a peer that received mesh data emits this
    // unconditionally at shutdown, so a test need not race the 250 ms app-tick
    // (the in-run log may not fire between the last reception and SIGTERM).
    // Mirrors the `learned mesh topology` gate on `ingested > 0`.
    if forwarder.data_seen() > 0 {
        log::info!(
            "wz-ap-demo peer: received mesh data ({} push(es))",
            forwarder.data_seen()
        );
    }
    // FUTURE-push witnesses (R311y158) — the peer-tier counterparts of the router-hat
    // `pushed a future subscriber/queryable` logs, emitted unconditionally on >0 at
    // shutdown (latched, so a test need not race the 250 ms app-tick) so a peer-mode
    // pub/querier-before-decl cross-impl e2e (a named follow-up) can gate on the
    // proactive push that deactivated a co-attached client's write-filter.
    if forwarder.future_pushes_seen() > 0 {
        log::info!(
            "wz-ap-demo peer: pushed a future subscriber ({} push(es))",
            forwarder.future_pushes_seen()
        );
    }
    if forwarder.future_qabl_pushes_seen() > 0 {
        log::info!(
            "wz-ap-demo peer: pushed a future queryable ({} push(es))",
            forwarder.future_qabl_pushes_seen()
        );
    }
    // Co-attached CLIENT-sub witness (R311y163 / D4) — the peer-tier twin of the
    // router-hat `learned a client sub` barrier, emitted unconditionally on >0 at
    // shutdown (latched, from `client_subs_seen()` state, so a test need not race the
    // 250 ms app-tick) so a peer-mode cross-impl e2e (the strong #3-a, a foreign pico
    // z_sub CLIENT of this peer) can gate on the client subscription being installed
    // in `client_subs` and advertised into the mesh under self's zid.
    if forwarder.client_subs_seen() > 0 {
        log::info!(
            "wz-ap-demo peer: learned a client sub ({} sub(s))",
            forwarder.client_subs_seen()
        );
    }
    // Subscription-interest witnesses — the DETERMINISTIC shutdown counterparts to
    // the in-run app-tick logs, emitted from STATE unconditionally at shutdown so a
    // test need not race the 250 ms app-tick (mirrors the `received mesh data` /
    // `learned mesh topology` shutdown witnesses). A publisher whose interest set is
    // now NON-empty LEARNED a subscriber; one that saw a learned interest go away
    // (`announced_interest` ever true AND the set now empty) WITHDREW. The learned
    // latch hardens the 2-router federation e2e, whose subscription half propagates
    // across a router hop (R311y128 design-panel A robustness note).
    if let Some(key) = publish_key {
        if !forwarder.interested(key).is_empty() {
            log::info!(
                "wz-ap-demo peer: publisher learned subscriber interest ({} peer(s))",
                forwarder.interested(key).len()
            );
        } else if announced_interest {
            log::info!("wz-ap-demo peer: publisher subscriber interest withdrawn");
        }
    }
    // R311y48 (§5.23 Phase 3b) — the interceptor-drop witness, DETERMINISTIC
    // shutdown counterpart to the in-run app-tick log: a peer whose forwarder
    // dropped any message (the wire-observable proof a runtime config-write deny
    // took effect on the LIVE forwarder) emits this unconditionally at shutdown, so
    // a test need not race the 250 ms app-tick. A non-zero count on a peer that was
    // admitting data BEFORE the PUT is the "forwarded, then DROPPED" flip.
    if forwarder.interceptor_dropped() > 0 {
        log::info!(
            "wz-ap-demo peer: interceptor dropped ({} message(s))",
            forwarder.interceptor_dropped()
        );
    }
    Ok(())
}

/// P4 §5.21 ACTIVATION — router-hat MODE (`--router-hat <listen>`): the first wz
/// run-mode to present a TRUE wire [`WhatAmI::Router`] and drive the dual-mesh
/// [`RouterForwarder`](wz::runtime_tokio::router_forward::RouterForwarder) (the
/// zenoh `hat/router` port) over real transport. The dial+accept
/// [`peer_loop`](wz::runtime_tokio::accept_loop::peer_loop) generalisation of
/// [`run_router`]: like the peer-mesh [`run_peer`] it binds `listen`, dials each
/// `dial_targets` (a ROUTER dialing another router for federation — ACTIVATION-4),
/// and holds both directions' faces; unlike the peer it announces Router, drives
/// the router forwarder, and hosts NO local publisher / subscriber / interceptors
/// / autoconnect / locators (a pure router forwards, it does not originate). The
/// forwarder partitions each held face into `routers_net` (a Router neighbour) or
/// `linkstatepeers_net` (a Peer) by the handshake role, converging both meshes on
/// the [`FaceForwarder`](wz::runtime_tokio::accept_loop::FaceForwarder) tick that
/// `peer_loop` drives.
///
/// The application driver here only OBSERVES the forwarder for the e2e witnesses
/// (a pure router runs no application I/O): per-tier convergence (a positive-edge
/// log once a mesh learns its first neighbour), data transit (the first Push that
/// crossed this router), and the deterministic shutdown counterparts (so a test
/// asserts on teardown output without racing the 250 ms tick). Runs until the
/// graceful-shutdown signal (SIGTERM / SIGINT).
#[cfg(feature = "router-hat-router")]
pub(crate) async fn run_router_hat(listen: &str, dial_targets: &[String]) -> io::Result<()> {
    use crate::args::NodeKind;
    use std::time::Duration;
    use wz::runtime_tokio::accept_loop::{peer_loop, AcceptEvent, FaceSources};
    use wz::runtime_tokio::linkstate_forward::Zid;
    use wz::runtime_tokio::router_forward::RouterForwarder;
    use wz::runtime_tokio::session_open::bind_endpoint;

    // Distinct 2-byte zid prefix ("rh") so a router-hat node and a peer bound to
    // the same port still derive DIFFERENT routing zids: RouterForwarder dedups
    // faces by zid (`dedups_faces_by_zid`), and two mesh nodes sharing a zid would
    // silently drop one's face and never converge. Ports differ across the harness
    // nodes anyway, so the distinct prefix is belt-and-suspenders + keeps the
    // router-hat's derived zids in a recognisable range (peers use 0x7072).
    const ROUTER_HAT_ZID_PREFIX: u16 = 0x7268;
    // Cadence of the OBSERVE-only application driver (a pure router originates no
    // data); matches the peer's so the witnesses log promptly after convergence.
    const APP_TICK_MS: u64 = 250;

    let listener = bind_endpoint(listen).await?;
    let local = listener.local_addr()?;

    // Parse the outbound dial targets (empty for a listen-only router; non-empty
    // for router-to-router federation, ACTIVATION-4). A malformed target fails
    // fast rather than silently dropping a mesh link — the run_peer discipline.
    let mut dials = Vec::with_capacity(dial_targets.len());
    for target in dial_targets {
        match target.parse::<std::net::SocketAddr>() {
            Ok(addr) => dials.push(addr),
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("wz-ap-demo router-hat: invalid --connect dial target {target:?}: {e}"),
                ));
            }
        }
    }

    log::info!(
        "wz-ap-demo router-hat: listening on {local}; dialing {} configured \
         router(s), presenting WhatAmI::Router and forwarding across the router \
         and peer meshes (dual-tier RouterForwarder)",
        dials.len()
    );

    let mut params = demo_session_init_params(NodeKind::RouterHat);
    // A DISTINCT routing zid per node (the run_peer discipline), derived from the
    // listen port so the demo's zids never collide — the mesh graph keys on it.
    let port = local.port();
    params.zid = vec![
        (ROUTER_HAT_ZID_PREFIX >> 8) as u8,
        (ROUTER_HAT_ZID_PREFIX & 0xff) as u8,
        (port >> 8) as u8,
        (port & 0xff) as u8,
    ];

    // The dual-mesh router forwarder. Self is a WhatAmI::Router in BOTH meshes
    // (the ctor seeds both nets with Router); its zid is this node's own trusted
    // identity, so the infallible boundary ctor is right (a wire zid would use the
    // validating `Zid::try_from`). No set_self_locators (a pure router advertises
    // no dial hint — topology still converges over the accepted/dialed faces), no
    // interceptors (admit-all), no autoconnect (dial only the configured set).
    let forwarder = RouterForwarder::new(Zid::from_slice(&params.zid));

    // R311y188 — router-multicast-faces slice 3: the EGRESS run-mode host. A
    // router built with `router-multicast-faces` attaches a data-plane multicast
    // group as a TX egress face (zenoh `new_transport_multicast` -> McastMux into
    // `mcast_groups`, router.rs:181): `spawn_router_mcast_egress` binds the group
    // socket + drives the loop on a SEPARATE task and returns its `Send` sender,
    // which the forwarder holds via `attach_mcast_group`. A routed Push then
    // egresses to the group at the `route_push` tail. The group address is the
    // demo default (a configurable group is a later concern — the demo hardcodes
    // its zid prefix + tick cadence the same way). The `mcast_faces` INGRESS plane
    // is the deferred milestone.
    #[cfg(feature = "router-multicast-faces")]
    {
        use std::net::Ipv4Addr;
        // The demo's default data-plane router multicast group. Distinct port from
        // scouting (7446/7447) + the loopback e2e tests (7449/7450/7451).
        const MCAST_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 225);
        const MCAST_PORT: u16 = 7452;
        let mcast_tx = wz::runtime_tokio::multicast_glue::spawn_router_mcast_egress(
            MCAST_GROUP,
            MCAST_PORT,
            params.zid.clone(),
        );
        forwarder.attach_mcast_group(mcast_tx);
        log::info!(
            "wz-ap-demo router-hat: multicast egress group {MCAST_GROUP}:{MCAST_PORT} \
             attached (router-multicast-faces); routed Push forwards to the group"
        );
    }

    // R311y194 — router-multicast-faces INGRESS slice (I1): the router also JOINs
    // the group (RX) so a real multicast peer's Put routes to the router's unicast
    // subscribers. `spawn_router_mcast_ingress` binds+joins on a SEPARATE task and
    // returns the channel of received Pushes; peer_loop folds each into the `!Send`
    // forwarder (`route_mcast_ingress`, echo-guarded off the groups). Egress (above)
    // + ingress share the router's single zid, so the RX self-zid gate
    // (`multicast_rx.rs:97`) drops this node's own loopback — no self-delivery. The
    // per-peer `mcast_faces` plane + mcast-peer declarations are the deferred I3
    // milestone; ingress is LITERAL-only here.
    #[cfg(feature = "router-multicast-faces")]
    let (mcast_ingress, mcast_members, mcast_group_subs) = {
        use std::net::Ipv4Addr;
        // The demo default data-plane router multicast group (same as the egress
        // group above — the router is one bidirectional member).
        const MCAST_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 225);
        const MCAST_PORT: u16 = 7452;
        // I3b — the ingress loop returns the received-Push channel and the on-group
        // ROUTER member relay (the Designated-Router election candidates that keep
        // the group egress + mcast-ingress federation loop-safe). S2 adds the third
        // channel: the group-SUBSCRIBER keyexpr aggregate, advertised into the mesh
        // so a mesh-side publisher reaches an on-group subscriber (reachability).
        let (rx, members_rx, group_subs_rx) =
            wz::runtime_tokio::multicast_glue::spawn_router_mcast_ingress(
                MCAST_GROUP,
                MCAST_PORT,
                params.zid.clone(),
            );
        log::info!(
            "wz-ap-demo router-hat: multicast ingress group {MCAST_GROUP}:{MCAST_PORT} \
             joined (router-multicast-faces); received Push routes to unicast subscribers"
        );
        (Some(rx), Some(members_rx), Some(group_subs_rx))
    };
    #[cfg(not(feature = "router-multicast-faces"))]
    let (mcast_ingress, mcast_members, mcast_group_subs) = (None, None, None);

    let loop_fut = peer_loop(
        FaceSources {
            listener,
            dial_targets: dials,
            // No gossip-autoconnect on a router (zenoh: routers are reached via
            // configured links, `default_autoconnect_matcher(Router)` is empty) —
            // so no dial-intent stream, exactly run_peer's `--autoconnect`-off arm.
            dial_intents: None,
            mcast_ingress,
            mcast_members,
            mcast_group_subs,
        },
        params,
        TokioTime::new(),
        DEFAULT_OPEN_TICK_MS,
        shutdown_signal(),
        |event: &AcceptEvent| log_face_event("router-hat", event),
        &forwarder,
    );
    tokio::pin!(loop_fut);

    // OBSERVE-only application driver: a pure router hosts no publisher/subscriber,
    // so the tick samples the dual-mesh convergence + transit for the e2e
    // witnesses. The topology flood + spanning-tree recompute + query-timeout reap
    // run on the FaceForwarder seam (peer_loop drives the tick), NOT here.
    let mut app_tick = tokio::time::interval(Duration::from_millis(APP_TICK_MS));
    // High-water node counts per tier (teardown collapses the live graphs toward
    // self, so the peak is the meaningful converged-size witness — the run_peer
    // peak_nodes discipline, per net).
    let mut peak_routers = 0usize;
    let mut peak_peers = 0usize;
    // Per-tier convergence high-water announced so far (self alone = 1). A log
    // fires each time a tier reaches a NEW high (self + each newly-learned
    // neighbour), so the trace steps through convergence (2 node(s), then 3, ...)
    // rather than latching at the first >= 2 and hiding later joins. A single
    // router never sees a Router neighbour, so the routers-net line stays silent
    // until federation (ACTIVATION-4). NOTE: these in-run logs are a convergence
    // TRACE — a test that needs a SPECIFIC converged size asserts the deterministic
    // shutdown-summary peak below (which cannot race the tick), not this edge.
    let mut last_announced_peers = 1usize;
    let mut last_announced_routers = 1usize;
    let mut last_data_seen = 0usize;
    let mut last_queries_seen = 0usize;
    let mut announced_queryable = false;
    let mut announced_client_sub = false;
    let mut announced_mesh_sub = false;
    let mut announced_future_push = false;
    let mut announced_future_qabl_push = false;
    #[cfg(feature = "routing-token-tables")]
    let mut announced_future_token_push = false;
    // I3c one-shot latches (mcast-ingress DR plane).
    #[cfg(feature = "router-multicast-faces")]
    let mut announced_mcast_members = false;
    #[cfg(feature = "router-multicast-faces")]
    let mut announced_mcast_federated = false;
    #[cfg(feature = "router-multicast-faces")]
    let mut announced_mcast_suppressed = false;
    let summary = loop {
        tokio::select! {
            done = &mut loop_fut => break done,
            _ = app_tick.tick() => {
                let routers = forwarder.routers_net_node_count();
                let peers = forwarder.linkstatepeers_net_node_count();
                peak_routers = peak_routers.max(routers);
                peak_peers = peak_peers.max(peers);
                if peers > last_announced_peers {
                    last_announced_peers = peers;
                    log::info!("wz-ap-demo router-hat: peers-net converged ({peers} node(s))");
                }
                if routers > last_announced_routers {
                    last_announced_routers = routers;
                    log::info!("wz-ap-demo router-hat: routers-net converged ({routers} node(s))");
                }
                // Transit witness: a Push crossed this router. The peers know only
                // THIS router's address (no autoconnect), so a rise proves the data
                // plane routed THROUGH here — not around it.
                let seen = forwarder.data_seen();
                if seen > last_data_seen {
                    last_data_seen = seen;
                    log::info!("wz-ap-demo router-hat: forwarded mesh data ({seen} push(es))");
                }
                // Query transit witness: a Request(Query) crossed this router. With no
                // autoconnect the querier reaches the queryable only THROUGH the router
                // mesh, so a rise proves this router routed the query — the query-plane
                // twin of the data transit witness above (the 2-router query-federation
                // e2e asserts it on BOTH routers to pin the cross-mesh transit).
                let queries = forwarder.queries_seen();
                if queries > last_queries_seen {
                    last_queries_seen = queries;
                    log::info!("wz-ap-demo router-hat: routed a query ({queries} request(s))");
                }
                // Query-plane READINESS witness (barrier for the query e2e): fires
                // ONCE when this router has ingested its first queryable's
                // DeclareQueryable, so a test can gate a query ISSUER's spawn on R
                // provably knowing the queryable — turning the one-shot-query e2e
                // into a barrier instead of racing declare-propagation.
                if !announced_queryable && forwarder.queryables_seen() > 0 {
                    announced_queryable = true;
                    log::info!("wz-ap-demo router-hat: learned a queryable");
                }
                // Data-plane READINESS witness (barrier for the pico cross-impl e2e):
                // fires ONCE when this router has installed a client's DeclareSubscriber
                // in client_subs, so a test can gate a PUBLISHER's spawn on R provably
                // holding the subscription — a router-confirmed barrier instead of
                // covering the declare-propagation race with a Put burst (the data-plane
                // twin of the "learned a queryable" query-readiness witness above).
                if !announced_client_sub && forwarder.client_subs_seen() > 0 {
                    announced_client_sub = true;
                    log::info!("wz-ap-demo router-hat: learned a client sub");
                }
                // REVERSE-data READINESS witness (barrier for the reverse leg):
                // fires ONCE when this router has INGESTED a peer router's (e.g.
                // zenohd's) DeclareSubscriber off the mesh, so a test can gate a
                // PUBLISHER-behind-wz spawn on R provably holding the remote
                // subscription — the write-filter interest a pico publisher sends
                // is answered non-empty only once wz holds a matching sub here
                // (the mesh twin of the "learned a client sub" data-plane witness).
                if !announced_mesh_sub && forwarder.mesh_subs_seen() > 0 {
                    announced_mesh_sub = true;
                    log::info!("wz-ap-demo router-hat: learned a mesh sub");
                }
                // I3c mcast-ingress DR witnesses (router-multicast-faces): the
                // on-group ROUTER member relay + the two DR-gate arms. The
                // membership witness is the loop-safety BARRIER a two-router e2e
                // waits on (each router has the OTHER in its DR candidate set before
                // any Put arrives, killing the startup double-DR transient); the
                // federated/suppressed pair is the deterministic single-bridge proof
                // (exactly ONE of two group-sharing routers federates a keyexpr).
                #[cfg(feature = "router-multicast-faces")]
                {
                    if !announced_mcast_members && forwarder.mcast_member_peak() >= 1 {
                        announced_mcast_members = true;
                        log::info!(
                            "wz-ap-demo router-hat: on-group router members converged ({})",
                            forwarder.mcast_member_peak()
                        );
                    }
                    if !announced_mcast_federated && forwarder.mcast_ingress_federated() > 0 {
                        announced_mcast_federated = true;
                        log::info!(
                            "wz-ap-demo router-hat: federated a mcast-ingress push into the mesh (DR)"
                        );
                    }
                    if !announced_mcast_suppressed && forwarder.mcast_ingress_suppressed() > 0 {
                        announced_mcast_suppressed = true;
                        log::info!(
                            "wz-ap-demo router-hat: suppressed a mcast-ingress federation (not DR)"
                        );
                    }
                }
                // FUTURE-push witness (barrier-free discriminator for the
                // pub-before-sub reverse leg): fires ONCE when this router has
                // PROACTIVELY pushed an unsolicited DeclareSubscriber to a CLIENT
                // face whose FUTURE interest predated the subscription (y146
                // push_future_subscription). A publisher that declared BEFORE any
                // subscriber has its write-filter deactivated ONLY by this push;
                // asserting it distinguishes the FUTURE push from a raced CURRENT
                // interest dump (both otherwise silent).
                if !announced_future_push && forwarder.future_pushes_seen() > 0 {
                    announced_future_push = true;
                    log::info!("wz-ap-demo router-hat: pushed a future subscriber");
                }
                // FUTURE-push QUERY-plane twin (barrier-free discriminator for the
                // querier-before-queryable leg): fires ONCE when this router has
                // PROACTIVELY pushed an unsolicited DeclareQueryable to a CLIENT face
                // whose FUTURE queryable interest predated the queryable (y150
                // push_future_queryable). A querier that declared BEFORE any queryable
                // has its write-filter deactivated ONLY by this push; asserting it
                // distinguishes the FUTURE push from a raced CURRENT interest dump.
                if !announced_future_qabl_push && forwarder.future_qabl_pushes_seen() > 0 {
                    announced_future_qabl_push = true;
                    log::info!("wz-ap-demo router-hat: pushed a future queryable");
                }
                // FUTURE-push LIVELINESS-TOKEN twin (§5.21 routing-token-tables,
                // barrier-free discriminator for the token cross-impl leg): fires
                // ONCE when this router has PROACTIVELY pushed an unsolicited
                // DeclareToken to a CLIENT face whose FUTURE token interest predated
                // the token (slice-4 push_future_token). A liveliness subscriber that
                // declared BEFORE any token receives the token ONLY via this push
                // (a FUTURE-only interest has no CURRENT dump to race), so asserting
                // it proves the delivery was the proactive push, not a raced dump.
                #[cfg(feature = "routing-token-tables")]
                if !announced_future_token_push && forwarder.future_token_pushes_seen() > 0 {
                    announced_future_token_push = true;
                    log::info!("wz-ap-demo router-hat: pushed a future token");
                }
            }
        }
    };

    log::info!(
        "wz-ap-demo router-hat: shutdown; dialed {}, accepted {}, served {} \
         peer(s), peak {} concurrent face(s), ingested {} link-state(s), peak \
         routers-net {} node(s), peak peers-net {} node(s), {} data push(es) \
         forwarded",
        summary.dialed,
        summary.accepted,
        summary.established,
        summary.peak_concurrent,
        forwarder.ingested(),
        peak_routers,
        peak_peers,
        forwarder.data_seen()
    );
    // Deterministic shutdown witnesses (the run_peer counterparts): a router that
    // INGESTED a neighbour's link-state converged over the wire, and one that
    // FORWARDED any Push carried transit — both emitted unconditionally at
    // teardown so a test need not race the 250 ms app tick.
    if forwarder.ingested() > 0 {
        log::info!(
            "wz-ap-demo router-hat: learned mesh topology (ingested {} \
             link-state(s), peak routers-net {} node(s), peak peers-net {} node(s))",
            forwarder.ingested(),
            peak_routers,
            peak_peers
        );
    }
    if forwarder.data_seen() > 0 {
        log::info!(
            "wz-ap-demo router-hat: forwarded mesh data ({} push(es))",
            forwarder.data_seen()
        );
    }
    // The query-plane transit counterpart (latched, emitted unconditionally on >0 at
    // teardown so a test need not race the app tick) — a router that ROUTED any Query
    // carried query transit, the proof the 2-router query-federation e2e asserts on
    // both routers.
    if forwarder.queries_seen() > 0 {
        log::info!(
            "wz-ap-demo router-hat: routed a query ({} request(s))",
            forwarder.queries_seen()
        );
    }
    // FUTURE-push counterpart (latched, emitted unconditionally on >0 at teardown
    // so a test need not race the 250 ms app tick) — the y146 proactive-push proof
    // the pub-before-sub reverse leg asserts.
    if forwarder.future_pushes_seen() > 0 {
        log::info!(
            "wz-ap-demo router-hat: pushed a future subscriber ({} push(es))",
            forwarder.future_pushes_seen()
        );
    }
    // FUTURE-push QUERY-plane counterpart (latched, emitted unconditionally on >0 at
    // teardown so a test need not race the 250 ms app tick) — the y150 proactive qabl
    // push proof the querier-before-queryable leg asserts.
    if forwarder.future_qabl_pushes_seen() > 0 {
        log::info!(
            "wz-ap-demo router-hat: pushed a future queryable ({} push(es))",
            forwarder.future_qabl_pushes_seen()
        );
    }
    // FUTURE-push LIVELINESS-TOKEN counterpart (latched, emitted unconditionally on
    // >0 at teardown so a test need not race the 250 ms app tick) — the slice-4
    // proactive token-push proof the token cross-impl leg asserts.
    #[cfg(feature = "routing-token-tables")]
    if forwarder.future_token_pushes_seen() > 0 {
        log::info!(
            "wz-ap-demo router-hat: pushed a future token ({} push(es))",
            forwarder.future_token_pushes_seen()
        );
    }
    // I3c mcast-ingress DR witnesses, LATCHED at teardown (emitted unconditionally
    // on a non-zero peak / count so a test never races the 250 ms app tick). The
    // peak member count proves the JOIN->relay->set chain ran; the federated /
    // suppressed pair is the deterministic single-bridge loop-safety proof.
    #[cfg(feature = "router-multicast-faces")]
    {
        if forwarder.mcast_member_peak() > 0 {
            log::info!(
                "wz-ap-demo router-hat: peak on-group router members {}",
                forwarder.mcast_member_peak()
            );
        }
        if forwarder.mcast_ingress_federated() > 0 {
            log::info!("wz-ap-demo router-hat: federated a mcast-ingress push into the mesh (DR)");
        }
        if forwarder.mcast_ingress_suppressed() > 0 {
            log::info!("wz-ap-demo router-hat: suppressed a mcast-ingress federation (not DR)");
        }
    }
    Ok(())
}
