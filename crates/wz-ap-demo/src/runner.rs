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
    let params = demo_session_init_params(role.node_kind());
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
        |event: &AcceptEvent| match event {
            AcceptEvent::FaceUp(face) => {
                log::info!(
                    "wz-ap-demo router: face {} UP (peer {}, zid {})",
                    face.id.0,
                    face.peer,
                    zid_hex(face.peer_zid.as_deref())
                )
            }
            AcceptEvent::FaceDown(face, outcome) => log::info!(
                "wz-ap-demo router: face {} DOWN (peer {}, {outcome:?})",
                face.id.0,
                face.peer
            ),
            AcceptEvent::FaceFailed { id, peer, cause } => log::warn!(
                "wz-ap-demo router: face {} FAILED (peer {peer}, {cause:?})",
                id.0
            ),
            AcceptEvent::AcceptError(e) => {
                log::warn!("wz-ap-demo router: accept error (continuing): {e}")
            }
        },
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
#[cfg(feature = "routing-peer")]
pub(crate) async fn run_peer(
    listen: &str,
    dial_targets: &[String],
    publish_key: Option<&str>,
    subscribe_key: Option<&str>,
    unsubscribe_after_data: bool,
) -> io::Result<()> {
    use crate::args::NodeKind;
    use std::time::Duration;
    use wz::runtime_tokio::accept_loop::{peer_loop, AcceptEvent, FaceSources};
    use wz::runtime_tokio::linkstate_forward::{LinkstateForwarder, WhatAmI, Zid};
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
    forwarder.set_self_locators(self_locators);

    let loop_fut = peer_loop(
        FaceSources {
            listener,
            dial_targets: dials,
        },
        params,
        TokioTime::new(),
        DEFAULT_OPEN_TICK_MS,
        shutdown_signal(),
        |event: &AcceptEvent| match event {
            AcceptEvent::FaceUp(face) => {
                log::info!(
                    "wz-ap-demo peer: face {} UP (peer {}, zid {})",
                    face.id.0,
                    face.peer,
                    zid_hex(face.peer_zid.as_deref())
                )
            }
            AcceptEvent::FaceDown(face, outcome) => log::info!(
                "wz-ap-demo peer: face {} DOWN (peer {}, {outcome:?})",
                face.id.0,
                face.peer
            ),
            AcceptEvent::FaceFailed { id, peer, cause } => log::warn!(
                "wz-ap-demo peer: face {} FAILED (peer {peer}, {cause:?})",
                id.0
            ),
            AcceptEvent::AcceptError(e) => {
                log::warn!("wz-ap-demo peer: accept error (continuing): {e}")
            }
        },
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
    let summary = loop {
        tokio::select! {
            done = &mut loop_fut => break done,
            _ = app_tick.tick() => {
                peak_nodes = peak_nodes.max(forwarder.node_count());
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
                let seen = forwarder.data_seen();
                if seen > last_data_seen {
                    last_data_seen = seen;
                    log::info!("wz-ap-demo peer: received mesh data ({seen} push(es))");
                }
            }
        }
    };

    log::info!(
        "wz-ap-demo peer: shutdown; dialed {}, accepted {}, served {} peer(s), \
         peak {} concurrent face(s), ingested {} link-state(s), \
         peak {} node(s) in topology graph, {} data push(es) received",
        summary.dialed,
        summary.accepted,
        summary.established,
        summary.peak_concurrent,
        forwarder.ingested(),
        peak_nodes.max(forwarder.node_count()),
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
    // Subscription-withdrawal witness — the DETERMINISTIC shutdown counterpart to
    // the in-run app-tick log (c3c-3 debt A1 / rem-2): a publisher that LEARNED an
    // interested subscriber and then saw that interest go away emits this from
    // STATE (`announced_interest` ever true AND the interest set now empty),
    // unconditionally at shutdown, so a test need not race the 250 ms app-tick.
    // Mirrors the `received mesh data` / `learned mesh topology` shutdown witnesses.
    if let Some(key) = publish_key {
        if announced_interest && forwarder.interested(key).is_empty() {
            log::info!("wz-ap-demo peer: publisher subscriber interest withdrawn");
        }
    }
    Ok(())
}
