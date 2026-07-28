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
#[cfg(feature = "advanced")]
use wz::runtime_tokio::advanced_subscriber::{
    AdvancedSubscriber, AdvancedSubscriberOptions, HistoryConfig,
};
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
    MatchingListener, PublishOptions, Publisher, Queryable, QueryableOptions, SubscribeOptions,
    Subscriber, TokioSession,
};
use wz::runtime_tokio::session_glue::{
    drive_session_until_terminal, IterationEvent, SessionInitParams, SessionLinkActions,
    SessionTimeouts,
};
use wz::runtime_tokio::session_open::{
    accept_and_open_session, accept_endpoint, dial_endpoint, initiate_and_open_session_with_offer,
    AcceptConfig, DialConfig, DialedLink, OpenError, OpenedSession, SessionOffer,
    DEFAULT_OPEN_TICK_MS,
};
use wz::runtime_tokio::sync::Mutex;

#[cfg(feature = "scouting-active")]
use crate::args::DEMO_PROTO_VERSION;
use crate::args::{
    demo_session_init_params, DeclareEmitSpec, LivelinessGetSpec, PublisherSpec, QueryRoleSpec,
    RemoteLogSpec, ReplyConsumerSpec, Role,
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
    /// R311y347 — `--matching-log`'s publisher + its matching listener. Held here
    /// for a reason the other handles do not have: the listener must OUTLIVE the
    /// publisher_task's burst. The remote's `UndeclSubscriber` — the `false`
    /// edge — arrives AFTER the burst it responded to, so a listener scoped to
    /// the burst would see only half the transition pair. The publisher is kept
    /// alongside it because dropping it would take the listener's keyexpr with it.
    _publisher: Option<Publisher>,
    _matching_listener: Option<MatchingListener>,
    /// R311y442 — `--advanced-subscribe`'s [`AdvancedSubscriber`]. Held for the
    /// same RAII reason as the plain `_subscriber`: dropping it undeclares the
    /// live subscription, and with it the reorder state the history replies feed.
    #[cfg(feature = "advanced")]
    _advanced_subscriber: Option<AdvancedSubscriber>,
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
    /// R311y442 — `--advanced-publish`'s task. Unlike its three siblings this one
    /// is DELIBERATELY non-terminating: it holds the AdvancedPublisher (and with
    /// it the cache queryable + `@adv` token) open past its burst, because the
    /// window a late subscriber queries is exactly the window after publishing
    /// stops.
    ///
    /// Review follow-up (R311y442, REVIEWER 3): it is kept OUT of the teardown
    /// join set on purpose — a task that never returns would burn the 200ms
    /// window for nothing — but it must still be ABORTED before teardown emits
    /// Close. Dropping the handle does NOT cancel the task
    /// ([`TokioJoinHandle`] mirrors tokio, where `abort` is opt-in), so the
    /// publisher would otherwise outlive `drop_actions()` and enqueue its
    /// cache-queryable + token undeclares onto a closed writer channel, where
    /// they are dropped with a WARN. A foreign advanced subscriber would then
    /// never see the token DELETE, only the link drop.
    #[cfg(feature = "advanced")]
    advanced_publisher_handle: Option<TokioJoinHandle<()>>,
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
/// R311y365/y366 — build the [`DialConfig`] for a one-shot `--connect`. Cert-free
/// transports (tcp/ws/udp/unixsock) take [`DialConfig::default`]; a cert transport
/// threads its `--<scheme>-ca <path>` root-CA PEM into the matching `DialConfig`
/// slot (verifying the server cert chains to that root AND its SAN matches
/// `localhost`). The connect ADDRESS (`<scheme>/127.0.0.1:port`) and the VERIFIED
/// NAME (`localhost`) are decoupled — dial by IP, verify by name — so one
/// self-signed `localhost` cert needs no IP SAN (see `TlsDialConfig::from_ca_pem`
/// / `QuicDialConfig::from_ca_pem`). Each cert transport is applied by its own
/// feature-gated helper, so a new cert transport is one added `apply_*` call — no
/// combinatorial cfg on this function.
fn build_dial_config(tls_ca: &Option<String>, quic_ca: &Option<String>) -> io::Result<DialConfig> {
    let cfg = DialConfig::default();
    let cfg = apply_tls_ca(cfg, tls_ca)?;
    let cfg = apply_quic_ca(cfg, quic_ca)?;
    Ok(cfg)
}

/// Thread the `--tls-ca` root-CA into `DialConfig.tls` — a `tls/...` dial verifies
/// the peer's server cert against it (server name `localhost`). No-op when no
/// `--tls-ca` was given.
#[cfg(feature = "tls")]
fn apply_tls_ca(cfg: DialConfig, tls_ca: &Option<String>) -> io::Result<DialConfig> {
    use wz::runtime_tokio::session_open::TlsDialConfig;
    use wz::runtime_tokio::tls_config::read_pem_file;
    match tls_ca {
        Some(path) => {
            let ca_pem = read_pem_file(path)?;
            let tls = TlsDialConfig::from_ca_pem(&ca_pem, "localhost")?;
            Ok(cfg.with_tls(tls))
        }
        None => Ok(cfg),
    }
}

/// The `tls`-less build: a `tls/...` dial surfaces the runtime's typed
/// `Unsupported` at [`dial_endpoint`], so `--tls-ca` is inert (the field is
/// feature-uniform on [`Role`], only its USE is gated).
#[cfg(not(feature = "tls"))]
fn apply_tls_ca(cfg: DialConfig, _tls_ca: &Option<String>) -> io::Result<DialConfig> {
    Ok(cfg)
}

/// R311y406 — the four `--<scheme>-cert` / `--<scheme>-key` PEM paths a mesh listen
/// PRESENTS, as ONE named bundle. Used by [`run_router_hat`] (whose positional arg
/// list is already long, so a named bundle both keeps it under the argument-count
/// lint AND rules out a cert/key or tls/quic transposition at the call site).
/// `Default` (all `None`) is the cert-free bind; [`Self::build`] threads them via
/// [`build_accept_config`]. (`run_peer` carries the same four inside [`PeerOpts`];
/// `run_router` passes them positionally — each caller's existing arg style.)
#[cfg(feature = "router-hat-router")]
#[derive(Default)]
pub(crate) struct AcceptCertPaths {
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub quic_cert: Option<String>,
    pub quic_key: Option<String>,
}

#[cfg(feature = "router-hat-router")]
impl AcceptCertPaths {
    fn build(&self) -> io::Result<AcceptConfig> {
        build_accept_config(
            &self.tls_cert,
            &self.tls_key,
            &self.quic_cert,
            &self.quic_key,
        )
    }
}

/// R311y375/y401 — build the [`AcceptConfig`] for a one-shot `--listen`, the accept
/// mirror of [`build_dial_config`]. Cert-free acceptors (tcp/ws/udp) take
/// [`AcceptConfig::default`]; a cert acceptor threads its `--<scheme>-cert` +
/// `--<scheme>-key` PEM (the cert it PRESENTS) into the matching slot. Each cert
/// transport is applied by its own feature-gated helper, so a new cert acceptor is
/// one added `apply_*` call — no combinatorial cfg on this function (the accept
/// mirror of [`build_dial_config`]'s `apply_tls_ca` / `apply_quic_ca` composition).
fn build_accept_config(
    tls_cert: &Option<String>,
    tls_key: &Option<String>,
    quic_cert: &Option<String>,
    quic_key: &Option<String>,
) -> io::Result<AcceptConfig> {
    let cfg = AcceptConfig::default();
    let cfg = apply_tls_accept(cfg, tls_cert, tls_key)?;
    let cfg = apply_quic_accept(cfg, quic_cert, quic_key)?;
    Ok(cfg)
}

/// Thread the `--tls-cert` / `--tls-key` PEM into `AcceptConfig.tls` — the cert a
/// `tls/...` acceptor PRESENTS. Both-or-neither; neither leaves the cert-free
/// default. The accept mirror of [`apply_tls_ca`].
#[cfg(feature = "tls")]
fn apply_tls_accept(
    cfg: AcceptConfig,
    tls_cert: &Option<String>,
    tls_key: &Option<String>,
) -> io::Result<AcceptConfig> {
    use wz::runtime_tokio::session_open::TlsAcceptConfig;
    use wz::runtime_tokio::tls_config::read_pem_file;
    match (tls_cert, tls_key) {
        (Some(cert_path), Some(key_path)) => {
            let cert_pem = read_pem_file(cert_path)?;
            let key_pem = read_pem_file(key_path)?;
            let tls = TlsAcceptConfig::from_cert_key_pem(&cert_pem, &key_pem)?;
            Ok(cfg.with_tls(tls))
        }
        (None, None) => Ok(cfg),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a tls/... --listen needs BOTH --tls-cert and --tls-key",
        )),
    }
}

/// The `tls`-less build: a `tls/...` --listen surfaces the runtime's typed
/// `Unsupported` at [`accept_endpoint`], so `--tls-cert` / `--tls-key` are inert
/// (feature-uniform on [`Role::Acceptor`], only their USE is gated).
#[cfg(not(feature = "tls"))]
fn apply_tls_accept(
    cfg: AcceptConfig,
    _tls_cert: &Option<String>,
    _tls_key: &Option<String>,
) -> io::Result<AcceptConfig> {
    Ok(cfg)
}

/// Thread the `--quic-cert` / `--quic-key` PEM into `AcceptConfig.quic` — the cert a
/// `quic/...` acceptor PRESENTS (a SEPARATE server config from tls: TLS-1.3 + ALPN
/// hq-29, not interchangeable). Both-or-neither, the QUIC twin of
/// [`apply_tls_accept`] and the accept mirror of [`apply_quic_ca`]. R311y401.
#[cfg(feature = "quic")]
fn apply_quic_accept(
    cfg: AcceptConfig,
    quic_cert: &Option<String>,
    quic_key: &Option<String>,
) -> io::Result<AcceptConfig> {
    use wz::runtime_tokio::session_open::QuicAcceptConfig;
    use wz::runtime_tokio::tls_config::read_pem_file;
    match (quic_cert, quic_key) {
        (Some(cert_path), Some(key_path)) => {
            let cert_pem = read_pem_file(cert_path)?;
            let key_pem = read_pem_file(key_path)?;
            let quic = QuicAcceptConfig::from_cert_key_pem(&cert_pem, &key_pem)?;
            Ok(cfg.with_quic(quic))
        }
        (None, None) => Ok(cfg),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a quic/... --listen needs BOTH --quic-cert and --quic-key",
        )),
    }
}

/// The `quic`-less build: a `quic/...` --listen surfaces the runtime's typed
/// `Unsupported` at [`accept_endpoint`], so `--quic-cert` / `--quic-key` are inert.
#[cfg(not(feature = "quic"))]
fn apply_quic_accept(
    cfg: AcceptConfig,
    _quic_cert: &Option<String>,
    _quic_key: &Option<String>,
) -> io::Result<AcceptConfig> {
    Ok(cfg)
}

/// Thread the `--quic-ca` root-CA into `DialConfig.quic` — a `quic/...` dial
/// verifies the peer's server cert against it (server name `localhost`), the QUIC
/// sibling of [`apply_tls_ca`]. No-op when no `--quic-ca` was given.
#[cfg(feature = "quic")]
fn apply_quic_ca(cfg: DialConfig, quic_ca: &Option<String>) -> io::Result<DialConfig> {
    use wz::runtime_tokio::session_open::QuicDialConfig;
    use wz::runtime_tokio::tls_config::read_pem_file;
    match quic_ca {
        Some(path) => {
            let ca_pem = read_pem_file(path)?;
            let quic = QuicDialConfig::from_ca_pem(&ca_pem, "localhost")?;
            Ok(cfg.with_quic(quic))
        }
        None => Ok(cfg),
    }
}

/// The `quic`-less build: a `quic/...` dial surfaces the runtime's typed
/// `Unsupported` at [`dial_endpoint`], so `--quic-ca` is inert.
#[cfg(not(feature = "quic"))]
fn apply_quic_ca(cfg: DialConfig, _quic_ca: &Option<String>) -> io::Result<DialConfig> {
    Ok(cfg)
}

/// R311y428 — the default zenoh scouting group. `224.0.0.224:7446` is
/// `Z_CONFIG_MULTICAST_LOCATOR_DEFAULT` in zenoh-pico
/// (`include/zenoh-pico/config.h.in`) and the `scouting/multicast/address`
/// default in zenoh (DEFAULT_CONFIG.json5), so a `--scout` demo reaches BOTH
/// foreign implementations without being told where to look — which is the
/// point of a discovery mode. Not a CLI knob: an address the peers do not share
/// discovers nothing, and zenoh exposes the override in its config, not its
/// scouting API.
#[cfg(feature = "scouting-active")]
const SCOUT_GROUP: std::net::Ipv4Addr = std::net::Ipv4Addr::new(224, 0, 0, 224);
#[cfg(feature = "scouting-active")]
const SCOUT_PORT: u16 = 7446;

/// The WhatAmI bitmask the Scout asks for: `ROUTER (0x01) | PEER (0x02)`. The
/// demo's `--scout` path becomes an Initiator, which announces
/// [`wz::runtime_tokio::session_glue::WhatAmI::Client`] on its own InitSyn, and
/// a client looks for routers and peers — zenoh's own
/// `scouting/multicast/autoconnect.client` default is `"router|peer"`
/// (DEFAULT_CONFIG.json5). A responder answers only when the mask matches its
/// own whatami (zenoh orchestrator.rs:1155 `what.matches(self.whatami())`), so
/// this value is load-bearing: drop the ROUTER bit and a zenohd stays silent.
#[cfg(feature = "scouting-active")]
const SCOUT_WHAT: u8 = 0x03;

/// One scouting CYCLE: emit a Scout, then accept a Hello for this long
/// (`ScoutParams::timeout_ms`, docs/scouting-fsm.md §2.5 default).
#[cfg(feature = "scouting-active")]
const SCOUT_CYCLE_MS: u64 = 1000;

/// Scheduler tick for the drive loop's select cadence. The Hello races this via
/// `poll_event`, so it bounds only how promptly the WINDOW expiry is noticed,
/// never the discovery latency.
#[cfg(feature = "scouting-active")]
const SCOUT_TICK_MS: u64 = 50;

/// R311y428 — resolve an Initiator's session locator by ACTIVE multicast
/// scouting: join `224.0.0.224:7446`, emit a Scout, and return the first
/// locator a peer's Hello advertises. The active-mode counterpart of the static
/// bypass (`scout_static::synth_static_locators`, which returns the configured
/// `--connect` locators verbatim, docs/scouting-fsm.md §2.4.3) — both are
/// pre-session locator resolution, and everything downstream of the returned
/// string is the ordinary Initiator path.
///
/// WHY THIS REPEATS THE CYCLE. [`drive_scouting_until_resolved`] is ONE cycle by
/// construction (one Scout, one `timeout_ms` window, exit on the first Hello) —
/// the shape of zenoh-pico's `__z_scout_loop`
/// (`vendor/zenoh-pico/src/session/scout.c:57`, which sends the wbuf once and
/// then reads for `period`). A single cycle races a responder that has not
/// finished joining the group: the Scout is a datagram, nothing retransmits it,
/// and the peer's later readiness cannot recover it. zenoh's own scouting
/// answers this by REPEATING — `Runtime::scout` loops the send forever with an
/// exponential backoff while receiving concurrently
/// (zenoh orchestrator.rs:848-877) — so repetition is the upstream shape, not a
/// harness workaround. What is deliberately NOT mirrored is the exponential
/// backoff: zenoh's loop is an unbounded background task where widening the
/// gap saves chatter over hours, whereas this one is a bounded startup budget
/// (default [`DEFAULT_SCOUT_BUDGET_MS`]) where a constant cycle just spends the
/// budget evenly.
///
/// The engine is built ONCE and re-driven: `drive_scouting_until_resolved`
/// calls `Engine::initialize` on entry, so each pass re-enters the FSM at
/// `Idle` and the trace counters accumulate across cycles (the log below
/// reports them, so a multi-cycle discovery is visible as such).
#[cfg(feature = "scouting-active")]
pub(crate) async fn scout_for_peer_locator(zid: Vec<u8>, budget_ms: u64) -> io::Result<String> {
    use wz::runtime_tokio::scouting_glue::{
        drive_scouting_until_resolved, new_scouting_engine, ScoutOutcome, ScoutParams,
        ScoutingActions,
    };
    use wz::runtime_tokio::UdpDriver;

    let mut driver = UdpDriver::bind_multicast_v4(SCOUT_GROUP, SCOUT_PORT)
        .await
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "wz-ap-demo: --scout could not join the scouting group \
                     {SCOUT_GROUP}:{SCOUT_PORT}: {e}"
                ),
            )
        })?;
    // The Scout announces the identity this node will open its session with, so
    // a responder logging the scouter sees the same zid the InitSyn then
    // carries. `--zid` therefore reaches here, not only the session params.
    let actions = ScoutingActions::new(ScoutParams {
        version: DEMO_PROTO_VERSION,
        what: SCOUT_WHAT,
        zid,
        timeout_ms: SCOUT_CYCLE_MS,
    });
    let mut engine = new_scouting_engine(&actions);
    let clock = TokioTime::new();
    let started_ms = clock.now_monotonic_ms();

    log::info!(
        "wz-ap-demo: active multicast scouting on {SCOUT_GROUP}:{SCOUT_PORT} \
         (what=0x{SCOUT_WHAT:02x}, {SCOUT_CYCLE_MS}ms window, {budget_ms}ms budget)"
    );
    loop {
        // `max_iters = None` is the production form (the bound exists for
        // tests): the window itself terminates the cycle, so an unbounded
        // select cannot hang.
        let outcome = drive_scouting_until_resolved(
            &mut driver,
            &actions,
            &mut engine,
            &clock,
            None,
            SCOUT_TICK_MS,
        )
        .await;
        let trace = actions.trace_snapshot();
        match outcome {
            ScoutOutcome::Discovered(locator) => {
                // THE WITNESS. This locator was decoded out of a peer's Hello by
                // `record_hello_and_emit`; there is no other producer of a
                // `Discovered`, so the line cannot be printed by a build that
                // merely parsed the flag. Logging the dispatch counters beside
                // it binds the claim to the FSM's own actions.
                log::info!(
                    "wz-ap-demo: scouted peer locator {locator} \
                     (scout_emit={}, record_hello={})",
                    trace.scout_emit,
                    trace.record_hello
                );
                return Ok(locator);
            }
            ScoutOutcome::TimedOut => {
                if clock.now_monotonic_ms().saturating_sub(started_ms) >= budget_ms {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "wz-ap-demo: --scout found no peer on {SCOUT_GROUP}:{SCOUT_PORT} \
                             within {budget_ms}ms ({} Scout(s) emitted, {} Hello(s) recorded)",
                            trace.scout_emit, trace.record_hello
                        ),
                    ));
                }
                log::info!(
                    "wz-ap-demo: scout window elapsed with no Hello; re-scouting \
                     (scout_emit={})",
                    trace.scout_emit
                );
            }
            // The scouting LINK died (not the window): retrying on a dead
            // driver would just spin, so this ends the budget immediately.
            ScoutOutcome::LinkLost(cause) => {
                return Err(io::Error::other(format!(
                    "wz-ap-demo: --scout lost the scouting link: {cause:?}"
                )));
            }
            // Unreachable with `max_iters = None`, and reported rather than
            // silently retried so a future bound cannot turn into a spin.
            ScoutOutcome::IterationLimit => {
                return Err(io::Error::other(
                    "wz-ap-demo: --scout hit an iteration limit it does not set",
                ));
            }
        }
    }
}

async fn establish_link(role: &Role) -> io::Result<DialedLink> {
    match role {
        Role::Acceptor {
            listen,
            tls_cert,
            tls_key,
            quic_cert,
            quic_key,
        } => {
            // R311pu/pv — delegate to the library accept seam (symmetric to the
            // Initiator's dial_endpoint), dissolving the inline TcpListener::bind.
            // accept_bound logs the "listening on" / "accepted peer" lines the
            // round-trip test waits on. R311y375/y401 — a `tls/...` / `quic/...`
            // --listen threads its `--<scheme>-cert` / `--<scheme>-key` into the
            // matching `AcceptConfig` server-cert slot (the accept mirror of the
            // Initiator's `--<scheme>-ca` -> DialConfig); every cert-free acceptor
            // (tcp/ws/udp) takes the default.
            let accept_cfg = build_accept_config(tls_cert, tls_key, quic_cert, quic_key)?;
            accept_endpoint(listen, &accept_cfg).await
        }
        Role::Initiator {
            connect,
            tls_ca,
            quic_ca,
            ..
        } => {
            // R311pw — `reconnect` is ignored here: `establish_link` runs the
            // one-shot dial only. The reconnect-Initiator lifecycle dials inside
            // the supervisor (which re-dials on loss), so `run_demo` routes it
            // away from `establish_link` entirely (it never reaches this arm).
            // R311y365/y366 — a `tls/...` / `quic/...` --connect threads its
            // `--tls-ca` / `--quic-ca` root-CA into the matching `DialConfig` slot;
            // every cert-free transport takes the default.
            let dial_cfg = build_dial_config(tls_ca, quic_ca)?;
            let dialed = dial_endpoint(connect, &dial_cfg).await?;
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
    declare_spec: &DeclareEmitSpec,
    queryable_spec: Option<(String, String)>,
    matching_publisher_keyexpr: Option<&str>,
) -> SessionHandles {
    // R311y442 — the four declare-side knobs arrive as the `DeclareEmitSpec`
    // bundle rather than as four positional arguments. `--advanced-subscribe` +
    // `--history-max` would have pushed this signature to eight parameters; the
    // bundle is the shape the rest of the file already uses (`PublisherSpec`,
    // `QueryRoleSpec`, `RemoteLogSpec`) and it takes the count DOWN, not up.
    let liveliness_subscriber_keyexpr = declare_spec.liveliness_subscriber_keyexpr.as_deref();
    let liveliness_subscriber_history = declare_spec.liveliness_subscriber_history;
    let advanced_subscriber_keyexpr = declare_spec.advanced_subscriber_keyexpr.as_deref();
    #[cfg_attr(not(feature = "advanced"), allow(unused_variables))]
    let advanced_history_max = declare_spec.advanced_history_max;
    #[cfg_attr(not(feature = "advanced"), allow(unused_variables))]
    let advanced_history_max_age = declare_spec.advanced_history_max_age;
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

    // R311y347 — `--matching-log`. Installed PRE-DRIVE, which is load-bearing
    // rather than tidy: `declare_matching_listener` is TRANSITION-only (pico
    // parity — registration never fires), so a listener installed after the
    // remote's `DeclSubscriber` has already been dispatched would miss the very
    // edge it exists to observe and report nothing, silently.
    let (publisher, matching_listener) = match matching_publisher_keyexpr {
        Some(keyexpr) => {
            let publisher = session.declare_publisher(keyexpr, PublishOptions::default());
            let keyexpr_for_log = keyexpr.to_string();
            match publisher.declare_matching_listener(move |status| {
                log::info!(
                    "wz-ap-demo: MATCHING STATUS keyexpr='{keyexpr_for_log}' matching={}",
                    status.matching,
                );
            }) {
                Ok(listener) => {
                    log::info!(
                        "wz-ap-demo: DECLARED MATCHING LISTENER keyexpr='{keyexpr}' \
                         (transition-only; a remote Decl/UndeclSubscriber drives each edge)"
                    );
                    (Some(publisher), Some(listener))
                }
                // The `session-matching`-OFF arm. Loud on purpose: this is the
                // anti-vacuity twin, and a test that greps for MATCHING STATUS
                // must be able to tell "the feature is off" from "the transition
                // never happened".
                Err(e) => {
                    log::warn!(
                        "wz-ap-demo: MATCHING LISTENER declare rejected for \
                         keyexpr='{keyexpr}': {e:?}"
                    );
                    (Some(publisher), None)
                }
            }
        }
        None => (None, None),
    };

    // R311y442 — `--advanced-subscribe`. Declared PRE-DRIVE for a reason the
    // plain subscriber does not have: the startup history GET goes out as part of
    // the declare, so declaring it after drive_session started would race the very
    // publishers whose cache it exists to drain.
    #[cfg(feature = "advanced")]
    let advanced_subscriber = advanced_subscriber_keyexpr.map(|filter| {
        let owned_filter = filter.to_string();
        let key_for_sample = owned_filter.clone();
        let key_for_miss = owned_filter.clone();
        let mut history = HistoryConfig::new();
        if let Some(max) = advanced_history_max {
            history = history.max_samples(max);
        }
        if let Some(age) = advanced_history_max_age {
            history = history.max_age(age);
        }
        let options = AdvancedSubscriberOptions::new().with_history(history);
        let declared = AdvancedSubscriber::declare_with_options(
            session,
            owned_filter,
            options,
            move |sample| {
                // The payload is logged as text, not just a length: the history
                // assertion is a BYTE-EXACTNESS claim about what a foreign
                // zenoh-ext cache replayed, and a length alone cannot carry it.
                log::info!(
                    "wz-ap-demo: ADVANCED SAMPLE filter='{}' keyexpr='{}' payload='{}'",
                    key_for_sample,
                    sample.keyexpr,
                    String::from_utf8_lossy(&sample.payload),
                );
            },
            move |miss| {
                log::info!(
                    "wz-ap-demo: ADVANCED MISS filter='{key_for_miss}' missed={}",
                    miss.nb,
                );
            },
        );
        match declared {
            Ok(sub) => {
                log::info!(
                    "wz-ap-demo: DECLARED ADVANCED SUBSCRIBER keyexpr='{filter}' \
                     history_max={advanced_history_max:?} \
                     history_max_age={advanced_history_max_age:?}"
                );
                Some(sub)
            }
            Err(e) => {
                log::warn!(
                    "wz-ap-demo: ADVANCED SUBSCRIBER declare rejected for keyexpr='{filter}': {e:?}"
                );
                None
            }
        }
    });

    // The `advanced`-OFF arm. Loud for the same reason as the matching-listener
    // twin above: a leg that greps for ADVANCED SAMPLE must be able to tell "the
    // demo was built without the feature" from "the history replies never came",
    // and those two are the exact pair this round exists to distinguish.
    #[cfg(not(feature = "advanced"))]
    if let Some(filter) = advanced_subscriber_keyexpr {
        log::warn!(
            "wz-ap-demo: --advanced-subscribe='{filter}' is INERT (built without \
             the `advanced` feature); no history GET will be issued \
             (ignored: history_max={advanced_history_max:?} \
             history_max_age={advanced_history_max_age:?})"
        );
    }

    SessionHandles {
        _subscriber: subscriber,
        _liveliness_subscriber: liveliness_subscriber,
        _queryable: queryable,
        _publisher: publisher,
        _matching_listener: matching_listener,
        #[cfg(feature = "advanced")]
        _advanced_subscriber: advanced_subscriber.flatten(),
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
/// R311y442 — the four per-task specs, bundled. `--advanced-publish` would have
/// been the eighth positional argument to [`spawn_background_tasks`]; grouping
/// the specs that already travel together takes the signature DOWN to five and
/// matches how the declare side is already passed (one [`DeclareEmitSpec`]).
struct BackgroundTaskSpecs {
    publisher: Option<PublisherSpec>,
    query: Option<String>,
    liveliness_get: Option<LivelinessGetSpec>,
    advanced_publish: Option<crate::args::AdvancedPublishSpec>,
}

fn spawn_background_tasks(
    session: &TokioSession,
    actions: &Arc<SessionLinkActions>,
    specs: BackgroundTaskSpecs,
    session_clock: TokioTime,
    long_lived: bool,
) -> SpawnedTasks {
    let BackgroundTaskSpecs {
        publisher: publisher_spec,
        query: query_spec,
        liveliness_get: liveliness_get_spec,
        advanced_publish: advanced_publish_spec,
    } = specs;
    let publisher_handle = publisher_spec.map(|spec| {
        let session_for_publisher = session.clone();
        TokioRuntime.spawn(publisher_task(
            session_for_publisher,
            spec,
            session_clock,
            long_lived,
        ))
    });

    let query_handle = query_spec.map(|keyexpr| {
        let actions_for_query = actions.clone();
        TokioRuntime.spawn(query_task(actions_for_query, keyexpr, session_clock))
    });

    let liveliness_get_handle = liveliness_get_spec.map(|spec| {
        let session_for_get = session.clone();
        TokioRuntime.spawn(liveliness_get_task(session_for_get, spec, session_clock))
    });

    // R311y442 — the advanced publisher declares INSIDE its task (the heartbeat
    // beacon needs a live runtime), so unlike the other declares it cannot move
    // pre-drive into `install_session_handles`.
    #[cfg(feature = "advanced")]
    let advanced_publisher_handle = advanced_publish_spec.map(|spec| {
        let session_for_advanced = session.clone();
        TokioRuntime.spawn(crate::tasks::advanced_publisher_task(
            session_for_advanced,
            spec,
            session_clock,
        ))
    });
    // The `advanced`-OFF arm, loud for the same reason as the subscriber twin.
    #[cfg(not(feature = "advanced"))]
    if let Some(spec) = advanced_publish_spec {
        log::warn!(
            "wz-ap-demo: --advanced-publish='{}' is INERT (built without the \
             `advanced` feature); no cache will be declared. Also ignored: \
             value='{}' count={} cache_max={:?} interval_ms={} zid={:02x?}",
            spec.keyexpr,
            spec.value,
            spec.count,
            spec.cache_max,
            spec.interval_ms,
            spec.zid,
        );
    }

    // R311ot — no declare_task: all outbound declares (subscriber / queryable /
    // token) are emitted synchronously pre-drive in `run_demo`, so there is no
    // longer a background declare task to spawn.
    SpawnedTasks {
        publisher_handle,
        query_handle,
        liveliness_get_handle,
        #[cfg(feature = "advanced")]
        advanced_publisher_handle,
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

/// R311y435 — build the Initiator's [`SessionOffer`] from the presence flags.
///
/// This function is where the demo's "a flag whose atom was not built is INERT"
/// contract lives, and it is the ONLY place it lives. `args.rs` keeps the CLI
/// surface feature-uniform on purpose — the same flags parse in every build — so
/// a capability this binary cannot provide must be dropped from the offer HERE,
/// before the library sees it. The library layer is deliberately strict about
/// the same input (`SessionLinkActions::apply_offer` returns
/// `UnsupportedCapability` rather than downgrading), because a library caller who
/// asked for a wire form and did not get it has no CLI banner to warn them.
///
/// R311y435 also DELETED the `--lowlatency --compression` rejection this
/// replaced. R311y434 had already established the pair is legal upstream — on a
/// lean link the negotiated wrap is inert, in wz as in zenoh — and left the
/// rejection standing only because `session_open` had one entrypoint per MODE
/// and none staged both offers. `initiate_and_open_session_with_offer` takes the
/// SET, so that reason is gone and the guard went with it.
fn initiator_offer(
    #[allow(unused)] lowlatency: bool,
    #[allow(unused)] compression: bool,
) -> SessionOffer {
    #[allow(unused_mut)]
    let mut offer = SessionOffer::universal();
    #[cfg(feature = "transport-lowlatency")]
    if lowlatency {
        offer = offer.with_mode(wz::runtime_tokio::session_open::TransportMode::LowLatency);
    }
    #[cfg(feature = "session-extcompression")]
    if compression {
        offer = offer.with_compression(true);
    }
    offer
}

/// Open a one-shot Initiator session with `offer` staged.
///
/// One call for every combination: the per-mode match this replaced could not
/// express two offers at once, which is exactly why the demo used to reject
/// `--lowlatency --compression`.
async fn open_initiator_with_offer(
    offer: SessionOffer,
    dialed: DialedLink,
    params: SessionInitParams,
    clock: TokioTime,
) -> Result<OpenedSession, OpenError> {
    initiate_and_open_session_with_offer(dialed, params, offer, clock, None, DEFAULT_OPEN_TICK_MS)
        .await
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
///
/// R311y435 — this doc block is RE-BOUND, not new. R311y433 inserted
/// `enum InitiatorOffer` between it and `run_demo`, silently making it the
/// enum's doc; removing that enum here would have deleted the teardown
/// invariant along with it. The insertion-strands-attributes hazard is only
/// visible in the rendered docs, never at the diff.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_demo(
    role: Role,
    key: Option<String>,
    publisher_spec: Option<PublisherSpec>,
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
            ..
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
                    // R311y372 / R311y433 — an Initiator with `--lowlatency` or
                    // `--compression` OFFERS that mode's establishment ext on the
                    // InitSyn (`initiate_and_open_session_with_*` ->
                    // `set_*_offer(true)`), so a peer that also offers it negotiates
                    // it: lowlatency drops the Frame(sn) wrapper, compression lz4-
                    // wraps every post-establishment batch. `main.rs` rejects the
                    // pair, so the classification below is total. The per-mode
                    // atom gating (and the inert-flag fallback for a build without
                    // the atom) lives in `open_initiator_with_offer`.
                    let offer = match &role {
                        Role::Initiator {
                            lowlatency,
                            compression,
                            ..
                        } => initiator_offer(*lowlatency, *compression),
                        _ => SessionOffer::universal(),
                    };
                    open_initiator_with_offer(offer, dialed, params, session_clock).await
                }
            }
            .map_err(|e| io::Error::other(format!("wz-ap-demo: session open failed: {e:?}")))?;
            // R311y369 — an Initiator with `--namespace <prefix>` installs the
            // keyexpr namespace on the freshly-opened session, so every outbound
            // publish keyexpr is prefixed `<prefix>/<key>` on the wire. Applied
            // ONLY on the one-shot open (reconnect is out of demo scope, like the
            // cert dial config); the field is feature-uniform, only its USE is
            // gated on the `namespace` feature.
            #[cfg(feature = "namespace")]
            if let Role::Initiator {
                namespace: Some(ns),
                ..
            } = &role
            {
                use wz::runtime_tokio::keyexpr_prefix::OwnedNonWildKeyExpr;
                let prefix = OwnedNonWildKeyExpr::new(ns).map_err(|e| {
                    io::Error::other(format!("wz-ap-demo: invalid --namespace {ns:?}: {e:?}"))
                })?;
                opened.actions.set_namespace(prefix);
                log::info!("wz-ap-demo: namespace '{ns}' installed (outbound keyexprs prefixed)");
            }
            // R311y372 — WITNESS the negotiated lowlatency capability: `&=`-merged
            // against the peer's InitAck ext, so `true` here means the peer (a
            // zenohd with `transport/unicast/lowlatency` on, or a wz peer) offered
            // Z_EXT_LOWLATENCY back and the established session runs the lean
            // (Frame-less) data path. The Layer Z cross-impl leg greps this line.
            #[cfg(feature = "transport-lowlatency")]
            if matches!(
                &role,
                Role::Initiator {
                    lowlatency: true,
                    ..
                }
            ) {
                log::info!(
                    "wz-ap-demo: lowlatency negotiated = {}",
                    opened.actions.is_lowlatency()
                );
            }
            // R311y433 — WITNESS the negotiated compression capability: `&=`-merged
            // against the peer's InitAck ext, so `true` here means the peer (a
            // zenohd with `transport/unicast/compression/enabled` on, or a wz peer)
            // offered Z_EXT_COMPRESSION back and every post-establishment batch on
            // this session goes out lz4-wrapped `[BatchHeader][payload]`. The
            // Layer Z cross-impl leg greps this line, in both polarities.
            #[cfg(feature = "session-extcompression")]
            if matches!(
                &role,
                Role::Initiator {
                    compression: true,
                    ..
                }
            ) {
                log::info!(
                    "wz-ap-demo: compression negotiated = {}",
                    opened.actions.is_compression()
                );
                // R311y435 — WITNESS the SECOND half of the R311y434 split, which
                // the line above cannot express. `is_compression()` reports what
                // the handshake NEGOTIATED; `compresses_batches()` reports whether
                // the lz4 wrap is APPLIED, and on a lean link those disagree by
                // design (upstream's lean tx never touches `WBatch`, so the
                // negotiated ext is inert there). Without this line a composed
                // `--lowlatency --compression` session is indistinguishable, from
                // the outside, from the pre-y434 build that wrapped a wire no
                // zenoh peer can read: both log `negotiated = true`. This is the
                // line the composed Layer Z leg reads, and its `false` against the
                // twin's `true` is the whole cross-impl claim.
                log::info!(
                    "wz-ap-demo: batch compression active = {}",
                    opened.actions.compresses_batches()
                );
            }
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

    // Read the matching knob BEFORE `publisher_spec` moves into spawn_tasks.
    let matching_publisher_keyexpr: Option<&str> = publisher_spec
        .as_ref()
        .filter(|spec| spec.matching_log)
        .map(|spec| spec.keyexpr.as_str());

    let _handles = install_session_handles(
        &session,
        key,
        &declare_spec,
        queryable_spec,
        matching_publisher_keyexpr,
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
        // R311y442 — held to the end of `run_demo` scope on purpose: dropping the
        // handle would abort the task and take the `@adv` cache with it, closing
        // the very window a foreign subscriber queries.
        #[cfg(feature = "advanced")]
            advanced_publisher_handle: _advanced_publisher_handle,
    } = spawn_background_tasks(
        &session,
        &actions,
        BackgroundTaskSpecs {
            publisher: publisher_spec,
            query: query_spec,
            liveliness_get: liveliness_get_spec,
            advanced_publish: declare_spec.advanced_publish,
        },
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
    // R311y442 review (REVIEWER 3, finding 5) — abort the non-terminating
    // advanced-publisher task FIRST, so dropping its `AdvancedPublisher` emits the
    // `@adv` cache-queryable + liveliness-token undeclares while the writer is
    // still draining. This is the same R284 step-4 ordering the LivelinessToken
    // already relies on; without it the frames are enqueued after `drop_actions()`
    // and discarded ("dropping frame" WARN, measured 2 per run).
    #[cfg(feature = "advanced")]
    if let Some(handle) = _advanced_publisher_handle {
        handle.abort();
    }

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
        // R311y213 (transport-multilink) — a second+ physical link aggregated onto
        // an existing session (the demo-owned witness that N-link aggregation
        // actually happened; a joined link never fires FaceUp, so this is the only
        // event a caller sees for the join). Present only under transport-multilink.
        #[cfg(feature = "transport-multilink")]
        AcceptEvent::LinkAggregated {
            peer_zid,
            live_links,
        } => log::info!(
            "wz-ap-demo {node_label}: link AGGREGATED to zid {} (live links now {live_links})",
            zid_hex(Some(peer_zid.as_slice()))
        ),
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
pub(crate) async fn run_router(
    listen: &str,
    tls_cert: &Option<String>,
    tls_key: &Option<String>,
    quic_cert: &Option<String>,
    quic_key: &Option<String>,
) -> io::Result<()> {
    run_router_until(
        listen,
        tls_cert,
        tls_key,
        quic_cert,
        quic_key,
        shutdown_signal(),
    )
    .await
}

/// The testable inner of [`run_router`] (CALLER fail-fast slice) — takes the
/// shutdown as a parameter so a unit test can inject an immediately-ready future
/// and witness the bind-time mesh-capability reject WITHOUT hanging on the real
/// SIGTERM/SIGINT signal. [`run_router`] is the production wrapper that passes
/// [`shutdown_signal`].
#[cfg(feature = "routing-router")]
async fn run_router_until(
    listen: &str,
    tls_cert: &Option<String>,
    tls_key: &Option<String>,
    quic_cert: &Option<String>,
    quic_key: &Option<String>,
    shutdown: impl std::future::Future<Output = ()>,
) -> io::Result<()> {
    use crate::args::NodeKind;
    use wz::runtime_tokio::accept_loop::{accept_loop, AcceptEvent};
    use wz::runtime_tokio::session_open::bind_endpoint_with_config;

    // R311y405 — thread the `--<scheme>-cert` / `--<scheme>-key` into the bind's
    // AcceptConfig (the SAME build_accept_config the one-shot `--listen` Acceptor
    // uses), so a `--router tls/...` / `--router quic/...` presents its server cert.
    // Was `bind_endpoint(listen)` (a cert-free `AcceptConfig::default()`), which made
    // `bind_locator` reject a tls/quic router listen at cert-absence -- the follow-up
    // `bind_endpoint`'s own doc named. A cert-free transport (tcp/ws/udp) still binds
    // (its cert slots stay None).
    let accept_cfg = build_accept_config(tls_cert, tls_key, quic_cert, quic_key)?;
    let listener = bind_endpoint_with_config(listen, &accept_cfg).await?;
    // CALLER fail-fast (mesh accept loop): the router holds N faces off ONE
    // listener, so a NON-mesh-capable acceptor (one that could not feed a
    // multi-accept loop) is rejected at bind with a clear error instead of
    // "listening" yet holding 0 faces. The BIND-time twin of the loop's runtime
    // backstop (`AcceptedLink::supports_mesh_multi_peer`, the `Step::Accepted`
    // arm). Since R311y404 EVERY acceptor (quic included, via its deferred-handshake
    // split) is mesh-capable, so this guard rejects no shipped transport today -- it
    // stays as defensive code, live only for a future non-mesh acceptor.
    if !listener.supports_mesh_multi_peer() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "wz-ap-demo router: --listen {listen:?} bound a {} listener whose acceptor is \
                 single-connection (not multi-peer) — the mesh router cannot hold faces on it; \
                 use a stream/datagram transport (tcp/ws/tls/unixsock/vsock/udp)",
                listener.transport_name()
            ),
        ));
    }
    let local = listener.local_addr_display()?;
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
        shutdown,
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
/// R311y220 (transport-qos) — the QoS band a `--publish` peer originates its data
/// Puts at, selected by `--express-high` / `--low`. Maps to the `(priority, express)`
/// pair [`LinkstateForwarder::publish_qos`](wz::runtime_tokio::linkstate_forward)
/// threads to the transport: on an aggregated QoS multilink session
/// (`--max-links > 1 --qos`) the priority pins the Put onto the per-face band link
/// (`select_link`), so qos priority-band link SELECTION becomes reachable from the
/// demo binary. Absent -> plain `publish` (DEFAULT = Data, the LOW band). NOTE: this
/// couples priority + express into one CLI shorthand (it cannot express e.g.
/// RealTime-non-express) — the two flags are the reachability driver, not the full
/// orthogonal QoS surface.
#[cfg(feature = "transport-qos")]
#[derive(Clone, Copy, Debug)]
pub(crate) enum PublishBand {
    /// `--express-high`: RealTime (the highest APPLICATION priority; the HIGH band
    /// `[Control..=InteractiveLow]`) with the express batch-flush hint.
    ExpressHigh,
    /// `--low`: Background (the lowest priority; the LOW band
    /// `[DataHigh..=Background]`), non-express.
    Low,
}

#[cfg(feature = "transport-qos")]
impl PublishBand {
    /// The `(priority, express)` pair [`publish_qos`](wz::runtime_tokio::linkstate_forward)
    /// consumes. RealTime(1) sits in the even-FaceId HIGH band and Background(7) in the
    /// odd-FaceId LOW band (`accept_loop::multilink_priority_range`), so the two select
    /// DISTINCT aggregated links; DEFAULT (Data=5) also lands in the LOW band, so only
    /// `ExpressHigh` routes onto the HIGH-band link the plain-publish path never carries
    /// data on.
    fn priority_express(self) -> (wz::runtime_tokio::qos::Priority, bool) {
        use wz::runtime_tokio::qos::Priority;
        match self {
            PublishBand::ExpressHigh => (Priority::RealTime, true),
            PublishBand::Low => (Priority::Background, false),
        }
    }
}

/// The gossip-autoconnect tie-break, named at module scope so [`PeerOpts`] can
/// carry it (the rest of the facade surface is imported inside `run_peer_mode`).
#[cfg(feature = "routing-peer")]
pub(crate) use wz::runtime_tokio::linkstate_forward::AutoConnectStrategy;

#[cfg(feature = "routing-peer")]
pub(crate) struct PeerOpts {
    pub publish_key: Option<String>,
    pub subscribe_key: Option<String>,
    pub unsubscribe_after_data: bool,
    /// Gossip-autoconnect opt-in AND its tie-break, in one field so the two
    /// cannot disagree: `None` = the peer dials only its static `--connect`
    /// targets; `Some(strategy)` = `--autoconnect` with the
    /// `--autoconnect-strategy` the caller chose (default
    /// [`AutoConnectStrategy::Always`], which is zenoh's default too). A
    /// separate `bool` + strategy pair would let "off, but with a strategy"
    /// be constructed; this shape makes that unrepresentable.
    pub autoconnect: Option<AutoConnectStrategy>,
    /// zenoh `routing.peer.mode` as zenoh itself represents it internally: `true`
    /// = `"linkstate"`, `false` = zenoh's default `"peer_to_peer"` gossip. Set
    /// from `--peer-mode`. It is a SUBSYSTEM-wide setting — every peer AND router
    /// of the mesh must agree — so it is a deploy decision, not a per-run tweak.
    pub full_linkstate: bool,
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
    /// R311y276 (§5.23 `adminspace-read`) — DENY the `permissions.read` GET gate on
    /// the [`config_queryable`](Self::config_queryable) host (`--no-admin-read`).
    /// Under the `adminspace-read` cfg a denied host answers nothing (only the
    /// terminating Final); the value is resolved through
    /// [`admin_read_permit`](wz::runtime_tokio::admin_read_permit), so with the gate
    /// compiled out it is a no-op (permissive read). The read-side mirror of
    /// [`config_write_permit`](Self::config_write_permit).
    pub no_admin_read: bool,
    /// R311y48 — originate a Put to this key each app tick carrying
    /// [`put_payload`](Self::put_payload) (the wire driver for a config-write
    /// PUT). Inert unless both are set.
    pub put_key: Option<String>,
    /// R311y48 — the payload bytes the [`put_key`](Self::put_key) Put carries.
    pub put_payload: Option<String>,
    /// R311y397 (Slice B) — pin this peer's routing zid (`--zid <hex>`) instead of
    /// deriving it from the listen port, mirroring [`run_router_hat`]'s override.
    /// REQUIRED for a non-IP listen (unixpipe / unixsock / vsock has no port to
    /// derive a distinct mesh-graph zid from); an IP listen keeps the port-derived
    /// fallback when this is `None`.
    pub zid_override: Option<Vec<u8>>,
    /// R311y213 (transport-multilink) — the aggregated-link budget for this peer
    /// (`--max-links`, the `unicast.max_links` analogue). `1` = single-link; `> 1`
    /// aggregates that many physical links to a peer zid into ONE logical session.
    /// Present only under `transport-multilink`; `run_peer` routes it through the
    /// shared [`WzConfig`](wz::runtime_tokio::config::WzConfig) into
    /// `FaceSources.max_links`.
    #[cfg(feature = "transport-multilink")]
    pub max_links: usize,
    /// R311y218 (transport-qos) — offer the QoS transport on this peer's aggregated
    /// links (`--qos`). Routed through [`WzConfig::with_qos`] into `FaceSources.qos`.
    #[cfg(feature = "transport-qos")]
    pub qos: bool,
    /// R311y220 (transport-qos) — the QoS band `--express-high` / `--low` select for
    /// the `--publish` origination (`None` = plain DEFAULT publish). Effective only on
    /// an aggregated QoS multilink session; a no-op band otherwise (the `is_qos()`
    /// clamp forces the effective priority back to DEFAULT downstream).
    #[cfg(feature = "transport-qos")]
    pub publish_band: Option<PublishBand>,
    /// R311y406 — the server cert a `--peer tls/...` / `--peer quic/...` PRESENTS
    /// (`--tls-cert`/`--tls-key`, `--quic-cert`/`--quic-key`), threaded into the
    /// bind's `AcceptConfig` exactly as the one-shot `--listen` and `--router`
    /// (R311y405) do. `None` (cert-free tcp/ws/udp) keeps the default bind. Both
    /// slots of a pair are required together (enforced by `build_accept_config`).
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub quic_cert: Option<String>,
    pub quic_key: Option<String>,
}

#[cfg(feature = "routing-peer")]
pub(crate) async fn run_peer(
    listen: &str,
    dial_targets: &[String],
    opts: &PeerOpts,
    interceptors: &crate::InterceptorOpts,
) -> io::Result<()> {
    run_peer_until(listen, dial_targets, opts, interceptors, shutdown_signal()).await
}

/// The testable inner of [`run_peer`] (R311y406) — takes the shutdown as a parameter
/// so a unit test can inject an immediately-ready future and witness the bind (e.g. a
/// cert-threaded `--peer quic/` ADMIT) WITHOUT hanging on the real SIGTERM/SIGINT
/// signal. [`run_peer`] is the production wrapper that passes [`shutdown_signal`]. The
/// peer twin of [`run_router_until`].
#[cfg(feature = "routing-peer")]
async fn run_peer_until(
    listen: &str,
    dial_targets: &[String],
    opts: &PeerOpts,
    interceptors: &crate::InterceptorOpts,
    shutdown: impl std::future::Future<Output = ()>,
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
    let no_admin_read = opts.no_admin_read;
    let put_key = opts.put_key.as_deref();
    let put_payload = opts.put_payload.as_deref();
    // R311y397 — pin this peer's routing zid (`--zid`) instead of deriving it from
    // the listen port; owned (not borrowed) because the derivation below consumes it.
    let zid_override = opts.zid_override.clone();
    #[cfg(feature = "transport-multilink")]
    let max_links = opts.max_links;
    #[cfg(feature = "transport-qos")]
    let qos = opts.qos;
    #[cfg(feature = "transport-qos")]
    let publish_band = opts.publish_band;
    use crate::args::NodeKind;
    use std::time::Duration;
    use wz::runtime_tokio::accept_loop::{peer_loop, AcceptEvent, FaceSources};
    use wz::runtime_tokio::linkstate_forward::{
        default_autoconnect_matcher, AclConfig, AclFlow, AclMessage, AclPolicy, AclRule,
        AutoConnect, DownsamplingRule, InterceptorConfig, LinkstateForwarder, LowPassRule,
        Permission, SubjectSelector, WhatAmI, Zid,
    };
    use wz::runtime_tokio::session_open::bind_endpoint_with_config;

    // Per-peer routing zid = an explicit `--zid` when given, else this 2-byte prefix
    // + the listen port (derived below; R311y397 — the `--zid` override, when
    // present, bypasses this prefix entirely, and a non-IP listen REQUIRES it). The
    // mesh routing graph keys on the zid, so two peers MUST NOT share one; the prefix
    // keeps the demo's derived zids in a recognisable range. (The periodic
    // self-flood cadence now lives in the
    // LinkstateForwarder itself — R311rf, on the FaceForwarder seam — so this
    // demo no longer owns a flood timer.)
    const PEER_ZID_PREFIX: u16 = 0x7072;
    // Cadence of the DEMO APPLICATION driver (not the protocol flood): a
    // `--publish` peer originates a data Put each tick, and every peer observes
    // its received-data count. Fast enough to publish soon after convergence.
    const APP_TICK_MS: u64 = 250;

    // R311y406 — thread the peer's server cert (PeerOpts.{tls,quic}_cert/key) into
    // the bind's AcceptConfig via the SAME build_accept_config the one-shot `--listen`
    // and `--router` (R311y405) use, so a `--peer tls/...` / `--peer quic/...` presents
    // its cert (was bind_endpoint's cert-free default -> cert-absence reject). A
    // cert-free transport (tcp/ws/udp) keeps its None slots and binds unchanged.
    let accept_cfg = build_accept_config(
        &opts.tls_cert,
        &opts.tls_key,
        &opts.quic_cert,
        &opts.quic_key,
    )?;
    let listener = bind_endpoint_with_config(listen, &accept_cfg).await?;
    // Non-IP-safe addressing (R311y397, mirroring run_router_hat's R311y396 seam):
    // the "listening on" log + the self dial locator render from the per-variant
    // display (`local_addr_display`, total over every transport), and the
    // port-derived zid fallback applies ONLY when the listener has an IP
    // `SocketAddr`. A non-IP listen (unixpipe / unixsock / vsock) has no port to
    // derive a distinct routing zid from, so it REQUIRES an explicit `--zid` (the
    // zenoh-faithful config-id; the port derivation is a demo IP-only convenience).
    // `local_addr()` is the IP accessor that errors for the non-IP families, so it
    // is taken as an `Option`, never `?`-propagated.
    let local_display = listener.local_addr_display()?;
    let local_ip: Option<std::net::SocketAddr> = listener.local_addr().ok();

    // This peer's DISTINCT routing zid (the mesh routing graph keys on it, so two
    // peers MUST NOT share one). Computed BEFORE the "listening on" log so a non-IP
    // listen without `--zid` fails fast rather than announcing a listen it will not
    // serve. An explicit `--zid` override WINS for ANY transport; absent it, an IP
    // listener derives a distinct zid from its listen port (deterministic,
    // collision-free across the demo's ephemeral ports); a non-IP listen must supply
    // `--zid`.
    let node_zid: Vec<u8> = match zid_override {
        Some(zid) => zid,
        None => match local_ip {
            Some(addr) => {
                let port = addr.port();
                vec![
                    (PEER_ZID_PREFIX >> 8) as u8,
                    (PEER_ZID_PREFIX & 0xff) as u8,
                    (port >> 8) as u8,
                    (port & 0xff) as u8,
                ]
            }
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "wz-ap-demo peer: --peer {listen:?} is a non-IP transport \
                         (unixpipe / unixsock / vsock) with no listen port to derive a \
                         distinct routing zid from; pass an explicit --zid <hex>"
                    ),
                ));
            }
        },
    };

    // Parse the outbound dial targets — TCP socket addresses for this atom. Only the
    // DIAL side is TCP-only; the LISTEN side is transport-general (unixpipe-capable as
    // of R311y397, above). A malformed target fails fast rather than silently dropping
    // a mesh link.
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
        "wz-ap-demo peer: listening on {local_display}; dialing {} configured peer(s), \
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
    // R311rc (c3d-4) — a DISTINCT zid per peer (the mesh routing graph keys on it,
    // so two peers MUST NOT share one; the demo's single hardcoded 0x01020304 would
    // collide — a node would ingest a remote link-state under its OWN zid).
    // Production supplies a real per-process zid; the demo pins `--zid` or derives a
    // deterministic distinct one from the listen port (R311y397 computed `node_zid`
    // above, so a non-IP listen already fail-fasted on a missing `--zid`).
    params.zid = node_zid;

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
    // `--peer-mode` (zenoh `routing.peer.mode`). Set BEFORE any face registers,
    // because the mode governs how the very first inbound flood is ingested; a
    // node that learned one flood in the wrong mode has already mis-shaped its
    // graph. Default `linkstate` — see the flag's doc for why wz does not adopt
    // zenoh's `peer_to_peer` default here.
    forwarder.set_full_linkstate(opts.full_linkstate);
    // Advertise this peer's listen address as its dial locator BEFORE the first
    // face registers, so self's first FULL flood already carries it. A neighbour
    // then learns where to reach this peer (the discovery data — what a future
    // gossip/autoconnect step dials). The locator scheme is the listener's ACTUAL
    // `transport_name()` (R311y397 — no longer a `tcp/` hardcode), so a `ws/`/`tls/`/
    // `udp/` or non-IP `unixpipe/` listen advertises a faithful dial string.
    //
    // An unspecified IP bind (0.0.0.0 / [::], the deploy default) is NOT a dialable
    // address: advertising `tcp/0.0.0.0:<port>` hands a peer a locator it cannot
    // connect to. zenoh expands an unspecified bind to the host's concrete
    // interface addresses (`io/zenoh-link-commons/src/listener.rs:115-145`);
    // until wz mirrors that, advertise nothing rather than a bogus locator —
    // topology still converges, only the (not-yet-consumed) dial hint is withheld.
    // A non-IP listen (unixpipe / …) has no wildcard bind, so it advertises its
    // scheme+path unconditionally (the R311y396 run_router_hat discipline).
    let self_locators: Vec<String> = match local_ip {
        Some(addr) if !addr.ip().is_unspecified() => {
            vec![format!("{}/{}", listener.transport_name(), addr)]
        }
        Some(addr) => {
            log::warn!(
                "listen address {addr} is unspecified (bind-all); advertising no dial \
                 locator (interface expansion is a tracked follow-up)"
            );
            Vec::new()
        }
        None => vec![format!("{}/{}", listener.transport_name(), local_display)],
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
    let cfg = wz::runtime_tokio::config::WzConfig::from_init_params(&params)
        .with_interceptors(interceptor_config);
    // R311y213 — route --max-links through the shared WzConfig (the config SSOT) so
    // the ONE instance handed to BOTH the aggregation loop (below, via
    // FaceSources.max_links) AND the --config-queryable admin handler is the single
    // budget source — never a config-vs-reality desync (the shared instance is
    // structural; to_admin_json does not yet render max_links). Shadowing (not a
    // `mut` binding) keeps the non-multilink build free of an unused_mut under
    // warnings=deny.
    #[cfg(feature = "transport-multilink")]
    let cfg = cfg.with_max_links(max_links);
    #[cfg(feature = "transport-qos")]
    let cfg = cfg.with_qos(qos);
    let wz_config = std::rc::Rc::new(std::cell::RefCell::new(cfg));
    {
        let cfg = wz_config.borrow();
        log::info!(
            "wz-ap-demo peer config (read-at-open): {}",
            cfg.to_admin_json()
        );
        cfg.install_interceptors(&forwarder);
    }
    // R311y213 — echo the effective aggregation budget. `to_admin_json` above omits
    // max_links (it renders acl/read-at-open fields only), so this is the operator's
    // confirmation that --max-links took effect: `> 1` aggregates N links per peer
    // into one logical session, `1` is the single-link path.
    #[cfg(feature = "transport-multilink")]
    log::info!(
        "wz-ap-demo peer: transport-multilink max_links = {max_links} ({})",
        if max_links > 1 {
            "aggregating"
        } else {
            "single-link"
        }
    );

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

    // §5.23 adminspace-introspection-handlers — the per-query materialization of the
    // subs/queryables this node knows that the admin GET on
    // `@/<zid>/peer/{subscriber,queryable}/**` replies from. The `--config-queryable`
    // handler is stored INSIDE the forwarder (it cannot hold `&forwarder`, the
    // pending_acl_deny rationale above), so the app-tick loop below — which DOES hold
    // `&forwarder` — re-snapshots this shared buffer from
    // `forwarder.subscriptions()/queryables()` each tick (a FULL
    // re-materialization from the live interest table, never an incremental drifting
    // side-table), and the handler reads it. Always allocated (`AdminDeclaration` is
    // always-compiled, like `AdminSession`); refreshed ONLY under the feature, so a
    // feature-off build leaves it empty and the introspection reply legs compile out.
    let introspection: std::rc::Rc<
        std::cell::RefCell<Vec<wz::runtime_tokio::adminspace::AdminDeclaration>>,
    > = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));

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
        // The introspection buffer the app-tick re-snapshots; the handler reads the
        // node's own declared subs/qabls from it per query (empty when the feature is
        // off — never refreshed — so the reply legs stay inert).
        let introspection_h = introspection.clone();
        // R311y276 (§5.23 adminspace-read) — resolve the GET permit through the
        // library admin_read_permit cfg site (the read-side mirror of the
        // config-write host's admin_write_permit): --no-admin-read ->
        // permissions.read=false -> under the adminspace-read cfg the handler answers
        // nothing (answer_admin_query returns on !ctx.read, only the Final unwinds);
        // with the gate compiled out it stays permissive (value ignored). Computed
        // ONCE and captured by the per-GET closure.
        let admin_read = wz::runtime_tokio::admin_read_permit(
            &wz::runtime_tokio::adminspace::AdminSpacePermissions {
                read: !no_admin_read,
                ..Default::default()
            },
        );
        log::info!("wz-ap-demo peer: adminspace read permit = {admin_read}");
        let handler = move |view: &dyn QueryView, out: &mut dyn ReplyOut| {
            let config_json = shared.borrow().to_admin_json();
            let ctx = AdminAnswerCtx {
                zid_hex: &zid_hex,
                whatami: whatami_str,
                version: &version,
                locators: &locators,
                read: admin_read,
            };
            // R311y237 — the node's compiled-in plugin registry (wz-native subsystem
            // set; e.g. storage_manager under `storage-backend`). Empty without the
            // feature so the answerer's `plugins` param stays signature-stable.
            #[cfg(feature = "adminspace-plugins-handlers")]
            let plugins = wz::runtime_tokio::compiled_plugins(&version);
            #[cfg(not(feature = "adminspace-plugins-handlers"))]
            let plugins: Vec<wz::runtime_tokio::adminspace::AdminPlugin> = Vec::new();
            answer_admin_query(
                view,
                out,
                &ctx,
                &[],
                &introspection_h.borrow(),
                &plugins,
                &config_json,
            );
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
                // R311y239 — the storage config-hotreload intents (AddStorage / RemoveStorage,
                // decoded only under adminspace-config-hotreload) are recognized but this demo
                // peer hosts no RuntimeStorageManager: the storage-hosting demo run-mode is a
                // deferred follow-up (run_peer is forwarder-based, no single Session for
                // add_storage), so log + ignore rather than apply. The arm is always compiled
                // (the variants are always present) even when the parse never produces them.
                AdminConfigWriteOutcome::Apply(other) => log::warn!(
                    "wz-ap-demo peer: config-write storage intent {other:?} decoded but this \
                     demo build hosts no storage manager (the storage config-hotreload run-mode \
                     is a deferred follow-up); ignored"
                ),
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
    // the TIE-BREAK now comes from `--autoconnect-strategy` and defaults to
    // `Always`, which is what zenoh defaults to (`DEFAULT_CONFIG.json5`
    // `autoconnect_strategy: { peer: { to_router: "always", to_peer: "always" } }`).
    // R311y431 — it used to be hardcoded to `GreaterZid`, so a deploy could not
    // express zenoh's own default at all; `GreaterZid` is still reachable, and is
    // the double-dial tie-break (of a mutually-discovering pair, only the
    // greater-zid end dials). The forwarder then emits a dial-intent for each
    // admitted discovered peer, and the loop dials it. Absent the flag,
    // `dial_intents` is `None` and the peer dials only its static `--connect`
    // targets (the prior behaviour exactly).
    let dial_intents = autoconnect.map(|strategy| {
        log::info!(
            "wz-ap-demo peer: gossip-autoconnect enabled (--autoconnect, strategy {})",
            match strategy {
                AutoConnectStrategy::Always => "always",
                AutoConnectStrategy::GreaterZid => "greater-zid",
            }
        );
        let policy = AutoConnect::new(
            Zid::from_slice(&params.zid),
            default_autoconnect_matcher(WhatAmI::Peer),
            strategy,
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
            // The runtime connect-list reconcile is a router-hat affordance
            // (`--router-hat --connect-after`); a plain peer node does not host it.
            reconcile: None,
            // R311y213 — the aggregation budget, routed from --max-links through the
            // shared WzConfig (the config SSOT, so the loop and the admin GET agree).
            // `1` = single-link (byte-identical to pre-multilink); `> 1` aggregates
            // that many physical links to a peer zid into ONE logical session.
            #[cfg(feature = "transport-multilink")]
            max_links: wz_config.borrow().max_links,
            // R311y218 — FaceSources.qos is gated transport-multilink (a plain bool),
            // but WzConfig.qos is gated transport-qos, so bridge with an inner
            // cfg-expr: the demo offers qos on its aggregated links iff `--qos` set.
            #[cfg(feature = "transport-multilink")]
            qos: {
                #[cfg(feature = "transport-qos")]
                {
                    wz_config.borrow().qos
                }
                #[cfg(not(feature = "transport-qos"))]
                {
                    false
                }
            },
        },
        params,
        TokioTime::new(),
        DEFAULT_OPEN_TICK_MS,
        shutdown,
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
    // R311y220 — one-shot latch so the qos-prioritized origination witness logs ONCE
    // (like `announced_interest`), proving the `--express-high` / `--low` flag actually
    // drove the `publish_qos` branch rather than the DEFAULT `publish` fall-through.
    #[cfg(feature = "transport-qos")]
    let mut announced_qos_publish = false;
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
                        // A deterministic barrier for an admin-introspection querier:
                        // the sub is now in `forwarder.subs`, and the introspection
                        // buffer is re-snapshotted at the end of THIS tick (below), so a
                        // querier that waits on this log is guaranteed the admin view
                        // already lists it.
                        log::info!("wz-ap-demo peer: declared subscriber {key}");
                    }
                }
                // §5.23 adminspace-introspection-handlers — re-snapshot the subs/qabls
                // this node knows into the admin introspection buffer each tick (a FULL
                // re-materialization from the live interest table, never an incremental
                // side-table). Ordered AFTER the declare above so the same tick that
                // declares the --key subscriber also publishes it to the admin view. The
                // queryable buffer is non-empty even here: `--config-queryable`
                // registered the admin queryable itself (self-sourced), which
                // `queryables()` lists — zenoh likewise self-lists its adminspace
                // queryable. Each entity's source zids become the `peers` bucket of its
                // admin `Sources` body (a peer-tier interest table's sources are peers).
                #[cfg(feature = "adminspace-introspection-handlers")]
                {
                    use wz::runtime_tokio::adminspace::{
                        AdminDeclaration, AdminEntityKind, AdminSources,
                    };
                    let sources = |peers: Vec<String>| AdminSources {
                        routers: Vec::new(),
                        peers,
                        clients: Vec::new(),
                    };
                    let mut buf = introspection.borrow_mut();
                    buf.clear();
                    buf.extend(forwarder.subscriptions().into_iter().map(|(keyexpr, zids)| {
                        AdminDeclaration {
                            kind: AdminEntityKind::Subscriber,
                            keyexpr,
                            sources: sources(zids),
                        }
                    }));
                    buf.extend(forwarder.queryables().into_iter().map(|(keyexpr, zids)| {
                        AdminDeclaration {
                            kind: AdminEntityKind::Queryable,
                            keyexpr,
                            sources: sources(zids),
                        }
                    }));
                }
                if let Some(key) = publish_key {
                    // R311y220 — a `--express-high` / `--low` peer originates its Put
                    // at the selected QoS band via `publish_qos` (making qos
                    // priority-band link selection reachable from the binary); with no
                    // band flag it takes the plain DEFAULT `publish` (byte-identical to
                    // the pre-y220 path). On a non-QoS session the band is a downstream
                    // no-op (the `is_qos()` clamp forces DEFAULT).
                    #[cfg(feature = "transport-qos")]
                    match publish_band {
                        Some(band) => {
                            let (pri, express) = band.priority_express();
                            let _ = forwarder.publish_qos(key, b"wz-mesh-data", pri, express);
                            // Positive, once-only witness that the qos-prioritized
                            // origination path was taken (the e2e asserts this so the
                            // test cannot pass trivially via the DEFAULT `publish`).
                            if !announced_qos_publish {
                                announced_qos_publish = true;
                                log::info!(
                                    "wz-ap-demo peer: originating {band:?} Put via publish_qos \
                                     (priority {pri:?}, express {express})"
                                );
                            }
                        }
                        None => {
                            let _ = forwarder.publish(key, b"wz-mesh-data");
                        }
                    }
                    #[cfg(not(feature = "transport-qos"))]
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
    // R311y423 — the GOSSIP-AUTOCONNECT witness (`scouting-autoconnect`), and it
    // is deliberately NOT `summary.dialed > 0`: that counter is bumped by the
    // static `--connect` seed and by reconcile too, so it would be green on a node
    // autoconnect never moved. `gossip_dialed` is incremented in exactly one place
    // — the `Step::Dial` arm, reached only through a DialIntent the forwarder emits
    // after the autoconnect policy admits a peer it discovered in a link-state
    // flood. So this line means: this peer learned a peer it was never configured
    // with, and dialed it. Latched at shutdown like the witnesses around it.
    if summary.gossip_dialed > 0 {
        log::info!(
            "wz-ap-demo peer: autoconnected to gossip-discovered peer(s) ({} dial(s))",
            summary.gossip_dialed
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
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_router_hat(
    listen: &str,
    dial_targets: &[String],
    connect_after: Option<(u64, Vec<String>)>,
    multicast_qos: bool,
    zid_override: Option<Vec<u8>>,
    cert_paths: &AcceptCertPaths,
) -> io::Result<()> {
    run_router_hat_until(
        listen,
        dial_targets,
        connect_after,
        multicast_qos,
        zid_override,
        cert_paths,
        shutdown_signal(),
    )
    .await
}

/// The testable inner of [`run_router_hat`] (R311y406) — takes the shutdown as a
/// parameter so a unit test can inject an immediately-ready future and witness the
/// bind (e.g. a cert-threaded `--router-hat quic/` ADMIT) WITHOUT hanging on the real
/// SIGTERM/SIGINT signal. [`run_router_hat`] is the production wrapper that passes
/// [`shutdown_signal`]. The router-hat twin of [`run_router_until`] / [`run_peer_until`].
#[cfg(feature = "router-hat-router")]
#[allow(clippy::too_many_arguments)]
async fn run_router_hat_until(
    listen: &str,
    dial_targets: &[String],
    connect_after: Option<(u64, Vec<String>)>,
    // R311y232 (transport-qos ACTIVATION) — offer the per-priority multicast QoS
    // conduit on the router's data-plane group (the `--multicast-qos` demo flag).
    // Consumed only by the `router-multicast-faces` egress/ingress spawns below;
    // a build without that face has no group to offer QoS on. Plain `bool` (not
    // `transport-qos`-gated) so the run-mode signature stays feature-stable — the
    // caller passes `false` when `transport-qos` is off.
    multicast_qos: bool,
    // Optional `--zid <hex>` override: pin this router's routing zid instead of
    // deriving it from the ephemeral listen port. The mesh MASTER election (HRW over
    // shared_nodes) keys on zid, so a deterministic zid makes a federation e2e's
    // master choice reproducible — a port-derived zid varies per run (flaky).
    zid_override: Option<Vec<u8>>,
    // R311y406 — the server cert a `--router-hat tls/...` / `quic/...` presents.
    cert_paths: &AcceptCertPaths,
    shutdown: impl std::future::Future<Output = ()>,
) -> io::Result<()> {
    use crate::args::NodeKind;
    #[cfg(not(feature = "router-multicast-faces"))]
    let _ = multicast_qos;
    use std::time::Duration;
    use wz::runtime_tokio::accept_loop::{peer_loop, AcceptEvent, FaceSources};
    use wz::runtime_tokio::linkstate_forward::Zid;
    use wz::runtime_tokio::router_forward::RouterForwarder;
    use wz::runtime_tokio::session_open::bind_endpoint_with_config;

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

    // R311y406 — thread the router-hat's server cert (--tls-cert/--quic-cert) into the
    // bind's AcceptConfig via the shared build_accept_config, so a `--router-hat tls/`
    // / `--router-hat quic/` presents its cert (was bind_endpoint's cert-free default).
    let accept_cfg = cert_paths.build()?;
    let listener = bind_endpoint_with_config(listen, &accept_cfg).await?;
    // Non-IP-safe addressing (R311y396): the log line + the adminspace `local_data`
    // dial locator render from the per-variant display (`local_addr_display`, total
    // over every transport), and the port-derived zid fallback applies ONLY when the
    // listener has an IP `SocketAddr`. A non-IP listen (unixpipe / unixsock / vsock)
    // has no port to derive a distinct routing zid from, so it REQUIRES an explicit
    // `--zid` (the zenoh-faithful config-id; the port derivation is a demo IP-only
    // convenience). `local_addr()` is the IP accessor that errors for the non-IP
    // families, so it is taken as an `Option`, never `?`-propagated (the R311y392
    // multi-client unixpipe acceptor already makes such a listen mesh-capable).
    let local_display = listener.local_addr_display()?;
    let local_ip: Option<std::net::SocketAddr> = listener.local_addr().ok();

    // The node's DISTINCT routing zid (the run_peer discipline) — the mesh graph
    // keys on it (RouterForwarder dedups faces by zid). Computed BEFORE the
    // "listening on" log so a non-IP listen without `--zid` fails fast rather than
    // announcing a listen it will not serve. An explicit `--zid` override WINS for
    // ANY transport (deterministic mesh master election). Absent it, derive a
    // distinct zid from the listen port — but only an IP listener HAS a port; a
    // non-IP (unixpipe / …) listen must supply `--zid`.
    let node_zid: Vec<u8> = match zid_override {
        Some(zid) => zid,
        None => match local_ip {
            Some(addr) => {
                let port = addr.port();
                vec![
                    (ROUTER_HAT_ZID_PREFIX >> 8) as u8,
                    (ROUTER_HAT_ZID_PREFIX & 0xff) as u8,
                    (port >> 8) as u8,
                    (port & 0xff) as u8,
                ]
            }
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "wz-ap-demo router-hat: --router-hat {listen:?} is a non-IP \
                         transport (unixpipe / unixsock / vsock) with no listen port to \
                         derive a distinct routing zid from; pass an explicit --zid <hex>"
                    ),
                ));
            }
        },
    };

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

    // The runtime connect-list reconcile affordance (`router-connect-reconcile`):
    // `--connect-after <ms>:<addr>[,<addr>...]` schedules a runtime ADD of the
    // listed connect endpoints `<ms>` after the mesh comes up — the operator-driven
    // trigger that mirrors zenoh re-reading `connect/endpoints` on a config change
    // and `update_peers`-dialing the newly-listed members. Parsed to `SocketAddr`
    // here (the same numeric-TCP scope + fail-fast as the static dials above).
    #[cfg(feature = "router-connect-reconcile")]
    let connect_after_addrs: Option<(u64, Vec<std::net::SocketAddr>)> = match connect_after {
        Some((ms, targets)) => {
            let mut addrs = Vec::with_capacity(targets.len());
            for t in &targets {
                match t.parse::<std::net::SocketAddr>() {
                    Ok(a) => addrs.push(a),
                    Err(e) => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!(
                                "wz-ap-demo router-hat: invalid --connect-after target {t:?}: {e}"
                            ),
                        ));
                    }
                }
            }
            Some((ms, addrs))
        }
        None => None,
    };
    #[cfg(not(feature = "router-connect-reconcile"))]
    let _ = connect_after;

    log::info!(
        "wz-ap-demo router-hat: listening on {local_display}; dialing {} configured \
         router(s), presenting WhatAmI::Router and forwarding across the router \
         and peer meshes (dual-tier RouterForwarder)",
        dials.len()
    );

    let mut params = demo_session_init_params(NodeKind::RouterHat);
    params.zid = node_zid;

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
            multicast_qos,
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
                multicast_qos,
            );
        log::info!(
            "wz-ap-demo router-hat: multicast ingress group {MCAST_GROUP}:{MCAST_PORT} \
             joined (router-multicast-faces); received Push routes to unicast subscribers"
        );
        (Some(rx), Some(members_rx), Some(group_subs_rx))
    };
    #[cfg(not(feature = "router-multicast-faces"))]
    let (mcast_ingress, mcast_members, mcast_group_subs) = (None, None, None);

    // The runtime connect-list reconcile channel (`router-connect-reconcile`): the
    // loop drains `FaceSources::reconcile`; the host holds the sender and fires it
    // from the app-tick once the `--connect-after` deadline elapses. Compute the
    // one-shot schedule (deadline + the NEW full desired set = the initial dials
    // PLUS the added endpoints) BEFORE `dials` moves into `FaceSources` — the loop's
    // add-dedup skips the already-dialed initials and slice-2 redial reads the full
    // set as the desired gate. Created only when the feature is compiled.
    #[cfg(feature = "router-connect-reconcile")]
    let (reconcile_tx, reconcile_rx) =
        tokio::sync::mpsc::unbounded_channel::<Vec<std::net::SocketAddr>>();
    #[cfg(feature = "router-connect-reconcile")]
    let reconcile_schedule: Option<(tokio::time::Instant, Vec<std::net::SocketAddr>)> =
        connect_after_addrs.map(|(ms, mut addrs)| {
            let mut full = dials.clone();
            full.append(&mut addrs);
            (
                tokio::time::Instant::now() + Duration::from_millis(ms),
                full,
            )
        });
    #[cfg(feature = "router-connect-reconcile")]
    let reconcile = Some(reconcile_rx);
    #[cfg(not(feature = "router-connect-reconcile"))]
    let reconcile: Option<wz::runtime_tokio::accept_loop::ReconcileReceiver> = None;

    // §5.23 adminspace-router-linkstate — host the router's built-in admin
    // queryable on `@/<zid>/router/**`. The self-sourced qabl is advertised into
    // BOTH meshes at register time (+ re-advertised to late joiners via the derive
    // fold), so a GET from a DIRECTLY-attached OR a REMOTE (cross-node) querier
    // routes to this router, self-dispatches at the route_request empty-route tail,
    // and this handler renders LIVE from the two link-state nets per query:
    // `linkstate/routers` + `route/successor/**` from `routers_net`,
    // `linkstate/peers` from `linkstatepeers_net` (the wz mirror of zenoh's
    // routers_linkstate_data / peers_linkstate_data / route_successor,
    // net/runtime/adminspace.rs:741-919). Root `local_data` (self identity + the
    // listen locator) rides the shared `answer_admin_query` SSOT; the router's
    // `sessions[]` transport table, its config surface (replies "{}"), and its
    // per-tier sub/qabl introspection are NAMED deferrals.
    #[cfg(feature = "adminspace-router-linkstate")]
    {
        use wz::runtime_tokio::adminspace::{
            admin_queryable_key, answer_admin_query, answer_router_admin_query, AdminAnswerCtx,
            AdminRouterCtx,
        };
        use wz::runtime_tokio::query_sink::{QueryView, ReplyOut};
        use wz::runtime_tokio::zid_hex::zid_to_zenoh_hex;
        let zid_hex = zid_to_zenoh_hex(&params.zid);
        // SSOT-derive the role from `params.whatami` (= "router"), as run_peer does.
        let whatami_str = params.whatami.to_str();
        let version = env!("CARGO_PKG_VERSION").to_string();
        // The admin `local_data` dial locator: the router sets no forwarder
        // self-locator, but its listen address is a faithful `local_data` locator
        // (withheld on an unspecified IP bind, the run_peer discipline). The scheme
        // is `transport_name()` in BOTH arms — an IP listen is `tcp/`/`ws/`/`tls/`/
        // `udp/` by its actual transport (not hardcoded tcp), a non-IP listen is
        // its scheme+path (`unixpipe/<base>`, the same string a client `--connect`s
        // — advertised rather than withheld since it has no wildcard bind).
        let locators: Vec<String> = match local_ip {
            Some(addr) if !addr.ip().is_unspecified() => {
                vec![format!("{}/{}", listener.transport_name(), addr)]
            }
            Some(_) => Vec::new(),
            None => vec![format!("{}/{}", listener.transport_name(), local_display)],
        };
        let queryable_key = admin_queryable_key(&zid_hex, whatami_str);
        let routers_view = forwarder.routers_net_view();
        let peers_view = forwarder.peers_net_view();
        let handler = move |view: &dyn QueryView, out: &mut dyn ReplyOut| {
            // Root local_data / config / metrics via the shared SSOT (config "{}" +
            // sessions[] empty are named deferrals on the pure router).
            let ctx = AdminAnswerCtx {
                zid_hex: &zid_hex,
                whatami: whatami_str,
                version: &version,
                locators: &locators,
                read: true,
            };
            // R311y237 — the router node's compiled-in plugin registry.
            #[cfg(feature = "adminspace-plugins-handlers")]
            let plugins = wz::runtime_tokio::compiled_plugins(&version);
            #[cfg(not(feature = "adminspace-plugins-handlers"))]
            let plugins: Vec<wz::runtime_tokio::adminspace::AdminPlugin> = Vec::new();
            answer_admin_query(view, out, &ctx, &[], &[], &plugins, "{}");
            // The ROUTER-tier legs, rendered LIVE from the two nets per GET.
            let routers_dot = routers_view.dot();
            let peers_dot = peers_view.dot();
            let successors = routers_view.route_successors_hex();
            let rctx = AdminRouterCtx {
                zid_hex: &zid_hex,
                whatami: whatami_str,
                routers_dot: Some(&routers_dot),
                peers_dot: Some(&peers_dot),
                successors: &successors,
                read: true,
            };
            answer_router_admin_query(view, out, &rctx);
        };
        forwarder.register_local_queryable(&queryable_key, true, Box::new(handler));
        log::info!(
            "wz-ap-demo router-hat: adminspace router legs hosted at {queryable_key} \
             (linkstate/routers, linkstate/peers, route/successor)"
        );
    }

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
            reconcile,
            // A router-hat holds ONE link per peer; router-tier aggregation is
            // unwired (zenoh's unicast.max_links applies to routers too, but wz's
            // multilink demo path is the --peer mesh mode, run_peer).
            #[cfg(feature = "transport-multilink")]
            max_links: 1,
            #[cfg(feature = "transport-multilink")]
            qos: false,
        },
        params,
        TokioTime::new(),
        DEFAULT_OPEN_TICK_MS,
        shutdown,
        |event: &AcceptEvent| log_face_event("router-hat", event),
        &forwarder,
    );
    tokio::pin!(loop_fut);

    // OBSERVE-only application driver: a pure router hosts no publisher/subscriber,
    // so the tick samples the dual-mesh convergence + transit for the e2e
    // witnesses. The topology flood + spanning-tree recompute + query-timeout reap
    // run on the FaceForwarder seam (peer_loop drives the tick), NOT here.
    let mut app_tick = tokio::time::interval(Duration::from_millis(APP_TICK_MS));
    // One-shot latch for the `--connect-after` reconcile fire (below).
    #[cfg(feature = "router-connect-reconcile")]
    let mut reconcile_fired = false;
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
    let mut last_deferred_client = 0usize;
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
    // S3 sub-plane reachability barrier latch.
    #[cfg(feature = "router-multicast-faces")]
    let mut announced_mcast_group_subs = false;
    // R311y411 — ingest-witness latch, the router-hat twin of the peer loop's
    // `announced_ingest`. See its use below for why the router tier needs one.
    let mut announced_ingest = false;
    let summary = loop {
        tokio::select! {
            done = &mut loop_fut => break done,
            _ = app_tick.tick() => {
                // `--connect-after` reconcile fire: once the deadline elapses, send
                // the NEW full desired connect-set on the reconcile channel; the loop
                // dials the added endpoint(s) (add-dedup skips the initial dials). One
                // shot, latched. Fires within one app-tick of the deadline — the test
                // gates on the resulting FaceUp event, not on the exact instant.
                #[cfg(feature = "router-connect-reconcile")]
                if let Some((deadline, full_set)) = reconcile_schedule.as_ref() {
                    if !reconcile_fired && tokio::time::Instant::now() >= *deadline {
                        reconcile_fired = true;
                        log::info!(
                            "wz-ap-demo router-hat: --connect-after fired; reconciling \
                             connect-list to {} endpoint(s)",
                            full_set.len()
                        );
                        let _ = reconcile_tx.send(full_set.clone());
                    }
                }
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
                // R311y411 — INGEST witness, mirroring the peer loop's (this loop had
                // none). `routers-net converged` above rises on `add_link` from the
                // INIT-derived zid+whatami, i.e. it is HANDSHAKE-satisfiable and says
                // nothing about the link-state WIRE. But the shutdown summary's
                // `learned mesh topology` is gated on `forwarder.ingested() > 0`, which
                // only rises inside `ingest_inbound_linkstate_tier` — a real
                // `LinkStateList` decode. A topology e2e that settles on convergence
                // and then terminates can therefore race the flood and lose a witness
                // it already earned. This is the deterministic post-ingest barrier that
                // closes that window, and it matters most on an UNRELIABLE link
                // (quic-datagram), where a missed flood is never retransmitted.
                if !announced_ingest && forwarder.ingested() > 0 {
                    announced_ingest = true;
                    log::info!(
                        "wz-ap-demo router-hat: ingested neighbour link-state ({} so far)",
                        forwarder.ingested()
                    );
                }
                // Transit witness: a Push crossed this router. The peers know only
                // THIS router's address (no autoconnect), so a rise proves the data
                // plane routed THROUGH here — not around it.
                let seen = forwarder.data_seen();
                if seen > last_data_seen {
                    last_data_seen = seen;
                    log::info!("wz-ap-demo router-hat: forwarded mesh data ({seen} push(es))");
                }
                // C4 double-delivery guard transit witness: this router was
                // NON-master for a keyexpr its client subscribes and DEFERRED the
                // duplicate peer/client-source copy (the master's bridged
                // router-source copy delivers exactly once). A rise proves the
                // non-master block-3 gate fired — the non-master corner's positive
                // observable (a broken guard never defers, and double-delivers).
                let deferred = forwarder.deferred_client_delivery_seen();
                if deferred > last_deferred_client {
                    last_deferred_client = deferred;
                    log::info!(
                        "wz-ap-demo router-hat: deferred a non-master client delivery \
                         ({deferred} suppressed)"
                    );
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
                    // S3 reachability BARRIER: fires ONCE when this router has
                    // INGESTED an on-group subscriber's DeclareSubscriber and
                    // ADVERTISED it into the unicast mesh. A cross-impl test gates a
                    // mesh-side PUBLISHER's readiness on this — the router provably
                    // holds + advertised the on-group sub before the Put, so the Put
                    // routes toward the router and egresses to the group (resolving
                    // reachability limit (a)). The sub-plane twin of the members barrier.
                    if !announced_mcast_group_subs && forwarder.group_subs_advertised_peak() >= 1 {
                        announced_mcast_group_subs = true;
                        log::info!(
                            "wz-ap-demo router-hat: advertised on-group subscriber(s) into the mesh ({})",
                            forwarder.group_subs_advertised_peak()
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

/// R311y282 — the `volume_id` the storage-host maps its hosted storages onto,
/// per the operator's `--storage-host-dir` choice: a durable `"fs"` when a dir
/// is given AND the `storage-backend-filesystem` backend is compiled, else the
/// volatile default `"mem"`. Zenoh-faithful: the storage VOLUME is a HOST /
/// deployment concern (a config-file / CLI choice), NOT a client wire selection
/// — zenoh storages are configured on the router, not picked over a live
/// connection. So `--storage-host-dir` is the operator declaring "this host's
/// storages are durable", not a per-`storage-add` wire field (that wire field is
/// the deferred §5.23 follow-up, `adminspace.rs` `parse_storage_add_payload`).
///
/// Gated on `adminspace-config-hotreload` — its only caller is the storage-host
/// run-mode (`run_storage_host`, same gate); on a build without it the fn would
/// be dead code (`-D warnings` reject).
#[cfg(feature = "adminspace-config-hotreload")]
fn storage_host_volume_id(dir: Option<&str>) -> &'static str {
    match dir {
        #[cfg(feature = "storage-backend-filesystem")]
        Some(_) => "fs",
        _ => "mem",
    }
}

/// R311y277 (§5.23 `adminspace-config-hotreload` ACTIVATION) — the storage-HOSTING
/// run-mode (`--storage-host <listen>`): the config-diff-driven storage lifecycle
/// driven END-TO-END over the wire by a stock zenoh-pico client. A pico `z_put`
/// `@/<zid>/peer/config/storage-add <name>:<keyexpr>` live-spawns a
/// [`RuntimeStorageManager`](wz::runtime_tokio::storage_manager_service::RuntimeStorageManager)-hosted
/// storage, and a subsequent pico `z_get` `@/<zid>/peer/plugins/**` then reports
/// `storage_manager` state `Started` (`Loaded` before); `storage-del <name>`
/// reverses it. This is the ACTIVE-FLIP run-mode the y239 forward reserved: the
/// demo forwarder hosts ([`run_peer`]) are forwarder-based with no single Session
/// for `add_storage`, so this net-new mode hosts a per-client Session instead.
///
/// ## Multi-accept loop (why)
///
/// A stock pico `z_put` and `z_get` are SEPARATE one-shot processes, each opening
/// its own unicast session; a single unicast Session is 1:1 and cannot serve the
/// four sequential clients (add / get / del / get). So the host binds ONCE
/// ([`bind_endpoint`](wz::runtime_tokio::session_open::bind_endpoint)) then loops:
/// accept one client
/// ([`accept_bound_on`](wz::runtime_tokio::session_open::accept_bound_on)) -> open a
/// [`TokioSession`] -> declare the two admin handlers on it -> drive it to terminal
/// (the client disconnects when its one-shot exits) -> drop the session ->
/// re-accept. State that must persist across client sessions is HOISTED above the
/// loop.
///
/// ## The Send+'static handler bound forces Arc-shared state
///
/// [`Session::declare_queryable`] / [`Session::declare_subscriber`] callbacks are
/// `Send + 'static` (session/mod.rs), but the manager is NOT `Send` (the storage
/// `Volume` trait carries no `Send` bound). So the manager CANNOT be captured by a
/// handler — it stays task-local in the drive-loop dispatch closure (which has no
/// `Send` bound). The GET handler captures only `storage_started: Arc<AtomicBool>`
/// (+ owned admin-key Strings); the write handler captures only `pending:
/// Arc<Mutex<Vec<AdminConfigWrite>>>` (+ owned Strings). This is why [`run_peer`]'s
/// `Rc<RefCell<>>` forwarder handlers are NOT reused here — an `Rc` capture would be
/// a `cannot be sent between threads` compile error on the Session declare path.
///
/// ## The "zombie storage" bound (NAMED)
///
/// A storage is spawned via `add_storage(&session, ..)` on the TRANSIENT z_put
/// client Session. When that pico process exits and the session is dropped at end
/// of the accept-loop iteration, the hosted `StorageService` SURVIVES: the manager
/// is hoisted and the service holds `Arc` clones of the session's observer + actions
/// (its RAII `Subscriber` / `Queryable` handles), and dead-link undeclare emits are
/// swallowed. So the storage keeps the manager NON-EMPTY (`storage_started` stays
/// true -> a later client's plugins GET reports `Started`), but it is a ZOMBIE:
/// STATE-OBSERVABLE, not data-serving across the session boundary. This is
/// sufficient for the plugins-STATE witness (which reads `!manager.is_empty()`) and
/// MUST NOT be read as a claim that the storage serves cross-connection data.
#[cfg(feature = "adminspace-config-hotreload")]
pub(crate) async fn run_storage_host(listen: &str, storage_dir: Option<String>) -> io::Result<()> {
    use std::sync::atomic::Ordering::Relaxed;

    use wz::runtime_tokio::adminspace::{
        admin_config_key, admin_config_write_key, admin_queryable_key, answer_admin_query,
        parse_admin_config_write, AdminAnswerCtx, AdminConfigWrite, AdminConfigWriteOutcome,
    };
    use wz::runtime_tokio::compiled_plugins_dyn;
    use wz::runtime_tokio::config::WzConfig;
    use wz::runtime_tokio::query_sink::{QueryView, ReplyOut};
    use wz::runtime_tokio::session_open::{accept_bound_on, bind_endpoint};
    use wz::runtime_tokio::sink::SampleView;
    use wz::runtime_tokio::storage_manager_service::RuntimeStorageManager;
    use wz::runtime_tokio::storage_volume::MemoryVolume;
    use wz::runtime_tokio::zid_hex::zid_to_zenoh_hex;

    use crate::args::NodeKind;

    let session_clock = TokioTime::new();
    let params = demo_session_init_params(NodeKind::StorageHost);
    // The pico witness scrapes ONE zid across all four sequential client sessions,
    // so the host zid must be STABLE across accept-loop iterations. The demo's fixed
    // Peer zid is that stable identity; there is exactly one storage host, so the
    // per-port zid derivation `run_peer` needs (mesh-graph collision avoidance) does
    // not apply here — a fixed zid is both correct and simpler.
    let node_zid = params.zid.clone();
    let zid_hex = zid_to_zenoh_hex(&node_zid);
    let whatami_str = params.whatami.to_str();

    // R311y376 — bind_endpoint now yields a scheme-keyed BoundListener; the
    // storage-host sequential seam (accept_bound_on) is tcp-only, so project to a
    // TcpListener via into_tcp (a non-tcp storage-host --listen surfaces the same
    // Unsupported it did before). The display string is read before the projection.
    let bound = bind_endpoint(listen).await?;
    let local = bound.local_addr_display()?;
    let listener = bound.into_tcp()?;

    // The admin keys this host serves (SSOT-derived from the same zid/whatami).
    let queryable_key = admin_queryable_key(&zid_hex, whatami_str); // @/<zid>/peer/**
    let config_key = admin_config_key(&zid_hex, whatami_str); // @/<zid>/peer/config
    let write_key = admin_config_write_key(&zid_hex, whatami_str); // @/<zid>/peer/config/**
                                                                   // The `@/<zid>/peer/config/` prefix a config-write PUT's sub-key hangs under.
    let write_prefix = {
        let mut p = admin_config_key(&zid_hex, whatami_str);
        p.push('/');
        p
    };
    // The read-at-open config mirror the admin `config` leg answers from — built once
    // from the handshake params (the witness reads only the plugins leg, but the
    // answerer serves the whole admin surface, so it needs a config body).
    let config_json = WzConfig::from_init_params(&params).to_admin_json();
    let version = env!("CARGO_PKG_VERSION").to_string();
    let locators = vec![format!("tcp/{local}")];

    // ── State HOISTED above the accept loop (persists across client Sessions) ──
    // The manager is TASK-LOCAL: captured only by the (non-Send) dispatch closure,
    // never by a (Send+'static) Session handler. `RuntimeStorageManager` is not
    // `Send` (the storage `Volume` trait carries no `Send` bound), so this placement
    // is load-bearing, not incidental. R/T are inferred from the `add_storage(&session,
    // ..)` call below (TokioSession's TokioRuntime / TokioTime).
    let mut manager = RuntimeStorageManager::new();
    manager.register_volume("mem", Box::new(MemoryVolume));
    // R311y282 — the operator's durability choice. `--storage-host-dir <dir>` ALSO
    // registers a durable FilesystemVolume under "fs" and maps every hosted storage
    // onto it (zenoh-faithful: the storage VOLUME is a host/deployment concern, not a
    // client wire field). Without the dir (or without the fs backend feature) storages
    // stay on the volatile "mem" volume — the pre-y282 behavior, unchanged.
    let hosted_volume_id = storage_host_volume_id(storage_dir.as_deref());
    #[cfg(feature = "storage-backend-filesystem")]
    if let Some(ref dir) = storage_dir {
        use wz::runtime_tokio::filesystem_storage::FilesystemVolume;
        manager.register_volume("fs", Box::new(FilesystemVolume::new(dir.clone())));
        log::info!(
            "wz-ap-demo storage-host: durable filesystem volume 'fs' rooted at {dir} \
             (hosted storages persist across a host restart)"
        );
    }
    #[cfg(not(feature = "storage-backend-filesystem"))]
    if storage_dir.is_some() {
        log::warn!(
            "wz-ap-demo storage-host: --storage-host-dir ignored (build without the \
             `storage-backend-filesystem` feature); storages are volatile"
        );
    }
    // The flag the GET handler reads; shared with the Send+'static handler via Arc.
    let storage_started = Arc::new(AtomicBool::new(false));
    // The intent stash the config-write handler fills, drained + applied in the
    // dispatch closure. A std `Mutex` (Send + Sync), NOT the wz `sync::Mutex` aliased
    // at the top of this module — the buffer crosses the Send+'static handler boundary.
    let pending: Arc<std::sync::Mutex<Vec<AdminConfigWrite>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));

    log::info!(
        "wz-ap-demo storage-host: listening on {local}; config WRITE at {write_key} \
         (storage-add/-del live-spawn a RuntimeStorageManager storage; a plugins GET \
         reports storage_manager Started when one is live)"
    );
    // The dedicated readiness barrier the witness scrapes for the admin root key —
    // emitted AFTER bind + all keys are computed, so a client cannot race the host.
    log::info!("wz-ap-demo storage-host: adminspace config GET at {config_key}");

    // The accept loop serves until the process is killed (the witness SIGKILLs the
    // host via ChildGuard) or a graceful-shutdown signal arrives (Ctrl-C / SIGTERM),
    // handled via the same `race_against_shutdown` SSOT the one-shot demo uses.
    loop {
        let dialed =
            match race_against_shutdown(accept_bound_on(&listener), "storage-host accept").await {
                Some(Ok(d)) => d,
                Some(Err(e)) => {
                    log::warn!("wz-ap-demo storage-host: accept failed: {e}; re-accepting");
                    continue;
                }
                None => break, // graceful shutdown while idle
            };
        let opened = match accept_and_open_session(
            dialed,
            params.clone(),
            session_clock,
            None,
            DEFAULT_OPEN_TICK_MS,
        )
        .await
        {
            Ok(o) => o,
            Err(e) => {
                log::warn!("wz-ap-demo storage-host: session open failed: {e:?}; re-accepting");
                continue;
            }
        };
        log::info!("wz-ap-demo storage-host: client session Established");

        let actions = opened.actions.clone();
        let session = TokioSession::new(
            actions.clone(),
            Arc::new(Mutex::new(ApplicationLayerObserver::new())),
            Arc::new(session_clock),
        );

        // ── admin GET queryable (Send+'static: captures storage_started + Strings) ──
        // Mirrors run_peer's --config-queryable handler (runner.rs answer path) but
        // swaps compiled_plugins -> compiled_plugins_dyn(&version, storage_started) so
        // the plugins leg reports Started iff a storage is live. read:true (constraint:
        // AdminAnswerCtx.read must be set; this host is permissive-read).
        let get_started = storage_started.clone();
        let get_zid = zid_hex.clone();
        let get_version = version.clone();
        let get_locators = locators.clone();
        let get_config = config_json.clone();
        let _admin_queryable: Option<Queryable> = match session.declare_queryable(
            queryable_key.clone(),
            QueryableOptions::default(),
            move |view: &dyn QueryView, out: &mut dyn ReplyOut| {
                let ctx = AdminAnswerCtx {
                    zid_hex: &get_zid,
                    whatami: whatami_str,
                    version: &get_version,
                    locators: &get_locators,
                    read: true,
                };
                // The DYNAMIC registry: storage_manager is Started when a storage is
                // live (!manager.is_empty(), reflected into storage_started), Loaded
                // otherwise. This is what binds the witness to REAL add_storage.
                let plugins = compiled_plugins_dyn(&get_version, get_started.load(Relaxed));
                answer_admin_query(view, out, &ctx, &[], &[], &plugins, &get_config);
            },
        ) {
            Ok(q) => Some(q),
            Err(e) => {
                log::warn!("wz-ap-demo storage-host: admin queryable declare rejected: {e:?}");
                None
            }
        };

        // ── config-WRITE subscriber (Send+'static: captures pending + Strings) ──
        // Mirrors run_peer's --config-writable handler (runner.rs write path). Writes
        // are PERMITTED unconditionally in this mode (permit = true), so the witness
        // needs no extra flag. wire -> intent ONLY: the apply (add_storage /
        // remove_storage) happens in the dispatch closure, which owns &mut manager.
        let sub_pending = pending.clone();
        let sub_prefix = write_prefix.clone();
        let _config_write_sub: Option<Subscriber> = match session.declare_subscriber(
            write_key.clone(),
            SubscribeOptions::default(),
            move |sample: &dyn SampleView| {
                match parse_admin_config_write(
                    &sub_prefix,
                    sample.keyexpr(),
                    sample.payload(),
                    true, // permit — this run-mode grants config-write for the witness
                ) {
                    AdminConfigWriteOutcome::Apply(intent) => {
                        log::info!(
                            "wz-ap-demo storage-host: config-write intent stashed: {intent:?}"
                        );
                        sub_pending
                            .lock()
                            .expect("storage-host pending mutex poisoned")
                            .push(intent);
                    }
                    // permit is true here, so Denied is unreachable; handled for
                    // completeness (the outcome enum is feature-independent).
                    AdminConfigWriteOutcome::Denied => {}
                    AdminConfigWriteOutcome::Malformed => log::warn!(
                        "wz-ap-demo storage-host: config-write malformed payload; ignored"
                    ),
                    AdminConfigWriteOutcome::UnknownKey(k) => log::warn!(
                        "wz-ap-demo storage-host: config-write unknown key '{k}'; ignored"
                    ),
                    AdminConfigWriteOutcome::NotAWrite => {}
                }
            },
        ) {
            Ok(s) => Some(s),
            Err(e) => {
                log::warn!(
                    "wz-ap-demo storage-host: config-write subscriber declare rejected: {e}"
                );
                None
            }
        };

        // ── the per-iteration dispatch closure ──
        // Fires the session's handlers, THEN drains + applies the stashed storage
        // intents. add_storage / remove_storage run AFTER
        // `dispatch_iteration_event_with` RETURNS (observer lock released), NOT inside
        // its under_lock closure — the latter forbids observer re-entry (add_storage's
        // declare_subscriber/-queryable re-lock the observer, a deadlock). The closure
        // captures &mut manager (non-Send is OK: drive_session_until_terminal's dispatch
        // bound is bare `FnMut`, no Send), the per-client session clone, the Arcs, and
        // node_zid.
        let session_for_dispatch = session.clone();
        let dispatch_pending = pending.clone();
        let dispatch_started = storage_started.clone();
        let dispatch_zid = node_zid.clone();
        // The operator-chosen host volume every AddStorage is mapped onto (Copy).
        let dispatch_volume_id = hosted_volume_id;
        let mut dispatch =
            |event: IterationEvent<'_>| {
                // Fires the admin GET queryable + config-write subscriber; the config-write
                // handler stashes any AddStorage/RemoveStorage intent into `pending`. This
                // call also flushes staged replies + drains the deferred ResponseFinal
                // fires (session/mod.rs), so the querier's terminating Final is sent.
                session_for_dispatch.dispatch_iteration_event_with(event, |_obs| {});
                // Drain the stashed intents and apply them to the hoisted manager. Copied
                // out first so the pending lock is released before the (potentially
                // re-entrant-to-the-observer) add_storage runs.
                let drained: Vec<AdminConfigWrite> = {
                    let mut guard = dispatch_pending
                        .lock()
                        .expect("storage-host pending mutex poisoned");
                    guard.drain(..).collect()
                };
                for intent in &drained {
                    match intent {
                        AdminConfigWrite::AddStorage { name, .. } => {
                            match intent.to_storage_config() {
                                Some(mut cfg) => {
                                    // Map the storage onto the operator-chosen host
                                    // volume: durable "fs" under --storage-host-dir,
                                    // else the wire default "mem". The wire always
                                    // encodes volume_id="mem" (explicit client volume
                                    // selection is the deferred §5.23 follow-up), so the
                                    // HOST's flag is what decides durability.
                                    cfg.volume_id = dispatch_volume_id.to_string();
                                    match manager.add_storage(
                                        &session_for_dispatch,
                                        &cfg,
                                        dispatch_zid.clone(),
                                    ) {
                                        Ok(()) => log::info!(
                                    "wz-ap-demo storage-host: spawned live storage '{name}' \
                                     — storage_manager Started"
                                ),
                                        Err(e) => log::warn!(
                                    "wz-ap-demo storage-host: add_storage '{name}' failed: {e}"
                                ),
                                    }
                                }
                                None => log::warn!(
                                    "wz-ap-demo storage-host: AddStorage intent produced no \
                             StorageConfig; ignored"
                                ),
                            }
                        }
                        AdminConfigWrite::RemoveStorage(name) => {
                            if manager.remove_storage(name) {
                                log::info!(
                                "wz-ap-demo storage-host: despawned '{name}' — storage_manager {}",
                                if manager.is_empty() { "Loaded" } else { "Started" }
                            );
                            } else {
                                log::warn!(
                                    "wz-ap-demo storage-host: remove_storage '{name}' — \
                                 no such storage"
                                );
                            }
                        }
                        // Not a storage intent; this run-mode hosts no interceptor chain.
                        AdminConfigWrite::AclDeny(_) => log::warn!(
                            "wz-ap-demo storage-host: acl-deny config-write ignored \
                         (this mode hosts no interceptor chain)"
                        ),
                    }
                }
                // Reflect the LIVE storage state the GET handler reads. Binding to
                // !manager.is_empty() ties the witness to REAL add_storage / remove_storage
                // — never a bare bool flip that would report Started without a live storage
                // (an OVER-CLAIM this design forbids).
                dispatch_started.store(!manager.is_empty(), Relaxed);
            };

        // Drive this client session to terminal (it ends when the pico one-shot
        // disconnects). The engine + inbound half live in this stack frame (not inside
        // the future), so the shutdown select!-drop stays cancel-safe (run_demo's
        // OneShot-arm shape). `None` max_iters = run until the client terminates.
        let OpenedSession {
            mut engine,
            inbound,
            writer_handle,
            ..
        } = opened;
        let mut driver = inbound;
        let session_timeouts = SessionTimeouts::spec_defaults();
        let outcome = race_against_shutdown(
            drive_session_until_terminal(
                &mut driver,
                &actions,
                &mut engine,
                None,
                &session_clock,
                &session_timeouts,
                &mut dispatch,
            ),
            "storage-host drive",
        )
        .await;

        // Stop this client's writer task before re-accepting. It would NOT exit on its
        // own: any zombie StorageService the manager kept holds an `Arc` clone of this
        // session's actions (a live channel sender), so the writer's channel never
        // closes — abort it explicitly to avoid one lingering task per client.
        writer_handle.abort();
        match outcome {
            Some(o) => log::info!("wz-ap-demo storage-host: client session ended: {o:?}"),
            None => {
                log::info!("wz-ap-demo storage-host: graceful shutdown");
                break;
            }
        }
        // `dispatch` (and its &mut manager borrow), `session`, `actions`, and the RAII
        // `_admin_queryable` / `_config_write_sub` handles drop here at scope end. The
        // HOISTED manager (and any storage it holds) survives — the NAMED zombie bound.
    }
    Ok(())
}

#[cfg(all(test, feature = "adminspace-config-hotreload"))]
mod storage_host_volume_tests {
    use super::storage_host_volume_id;

    #[test]
    fn dir_selects_fs_when_feature_on_else_mem() {
        // No dir -> always the volatile default.
        assert_eq!(storage_host_volume_id(None), "mem");
        // A dir -> durable "fs" iff the fs backend is compiled; otherwise the
        // flag is inert (the host warns) and storages stay volatile.
        #[cfg(feature = "storage-backend-filesystem")]
        assert_eq!(storage_host_volume_id(Some("/tmp/wz-store")), "fs");
        #[cfg(not(feature = "storage-backend-filesystem"))]
        assert_eq!(storage_host_volume_id(Some("/tmp/wz-store")), "mem");
    }
}

#[cfg(all(
    test,
    feature = "routing-router",
    feature = "transport-link-unixpipe",
    target_os = "linux"
))]
mod caller_failfast_tests {
    use super::run_router_until;

    /// R311y392 — the once-`reject` discriminator flipped to ACCEPT: `run_router`
    /// (via its testable inner `run_router_until`) now ADMITS a `--listen
    /// unixpipe/..` at bind. The multi-client acceptor makes a unixpipe listener
    /// mesh-capable, so the bind-time guard no longer rejects it; the router binds,
    /// enters the accept loop, and (with the injected immediately-ready shutdown)
    /// returns `Ok(())`. Replaces the retired
    /// `run_router_rejects_a_unixpipe_listen_at_bind` (R311y390), whose `expect_err`
    /// the flip broke.
    ///
    /// RED reproduction (proof this binds to the flipped guard, not the vehicle):
    /// RESTORE the rejection — make `BoundListener::supports_mesh_multi_peer` return
    /// `false` for `Unixpipe` again -> `run_router_until` returns `Err(Unsupported)`
    /// -> this `expect` panics. The injected `std::future::ready(())` makes the
    /// GREEN path a clean immediate return rather than a SIGTERM-wait hang.
    #[tokio::test]
    async fn run_router_accepts_a_unixpipe_listen_at_bind() {
        let base = std::env::temp_dir()
            .join(format!(
                "wz-ap-demo-router-multiclient-{}",
                std::process::id()
            ))
            .to_string_lossy()
            .into_owned();
        // Pre-clean any stale FIFO node from a crashed prior run (no-flaky).
        let _ = std::fs::remove_file(format!("{base}_uplink"));

        let listen = format!("unixpipe/{base}");
        // R311y405 — a cert-free unixpipe listen: all four cert slots are `&None`
        // (the run_router_until signature grew a tls/quic cert-path quartet).
        run_router_until(&listen, &None, &None, &None, &None, std::future::ready(()))
            .await
            .expect("the mesh router admits a multi-client unixpipe --listen (R311y392)");

        // The acceptor's teardown unlinks the base request node; best-effort here.
        let _ = std::fs::remove_file(format!("{base}_uplink"));
    }
}

#[cfg(all(test, feature = "routing-router", feature = "quic"))]
mod router_quic_cert_tests {
    use super::run_router_until;

    /// R311y405 — the `--router quic/` cert-threading discriminator: the mesh router
    /// now ADMITS a `quic/...` --listen WHEN its `--quic-cert` / `--quic-key` are
    /// threaded. Was rejected at bind cert-absence — `run_router` bound with a
    /// cert-free `AcceptConfig::default()` (via `bind_endpoint`), the follow-up
    /// `bind_endpoint`'s own doc named. Now `run_router_until` builds the AcceptConfig
    /// from the cert paths (the SAME `build_accept_config` the one-shot `--listen`
    /// uses) + `bind_endpoint_with_config`, so a cert-bearing quic listen binds; the
    /// injected immediately-ready shutdown makes the accept loop return `Ok`. The QUIC
    /// twin of `run_router_accepts_a_unixpipe_listen_at_bind`.
    ///
    /// RED reproduction (proof it binds to the cert-threading seam, not the vehicle):
    /// RESTORE `bind_endpoint(listen)` (the cert-free default) in `run_router_until`
    /// -> `bind_locator` rejects the quic listen at cert-absence -> `run_router_until`
    /// returns `Err(Unsupported)` -> this `expect` panics.
    ///
    /// NON-FLAKY: a fresh self-signed `localhost` cert is written to a process-unique
    /// temp path, `quic/127.0.0.1:0` binds an OS-chosen port, and the `ready(())`
    /// shutdown returns the loop WITHOUT awaiting a peer — no network round-trip
    /// races. Cert files are removed after the bind (best-effort, like the unixpipe
    /// sibling's FIFO cleanup). [[feedback-no-flaky-ever]]
    #[tokio::test]
    async fn run_router_admits_a_quic_listen_with_cert_at_bind() {
        use wz_runtime_tokio_test_support::localhost_cert_key_pem;
        let (cert_pem, key_pem) = localhost_cert_key_pem();
        let dir = std::env::temp_dir();
        let pid = std::process::id();
        let cert_path = dir
            .join(format!("wz-ap-demo-router-quic-cert-{pid}.pem"))
            .to_string_lossy()
            .into_owned();
        let key_path = dir
            .join(format!("wz-ap-demo-router-quic-key-{pid}.pem"))
            .to_string_lossy()
            .into_owned();
        std::fs::write(&cert_path, cert_pem.as_bytes()).expect("write cert pem");
        std::fs::write(&key_path, key_pem.as_bytes()).expect("write key pem");

        let result = run_router_until(
            "quic/127.0.0.1:0",
            &None,
            &None,
            &Some(cert_path.clone()),
            &Some(key_path.clone()),
            std::future::ready(()),
        )
        .await;

        // Best-effort cleanup BEFORE the assert, so a bind failure still unlinks.
        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&key_path);
        result.expect("the mesh router admits a quic --listen with --quic-cert (R311y405)");
    }
}

#[cfg(all(test, feature = "router-hat-router", feature = "quic"))]
mod router_hat_quic_cert_tests {
    use super::{run_router_hat_until, AcceptCertPaths};

    /// R311y406 — the `--router-hat quic/` cert-threading discriminator: run_router_hat
    /// (via its testable inner run_router_hat_until) now ADMITS a quic listen when the
    /// AcceptCertPaths bundle carries --quic-cert/--quic-key (was rejected at bind
    /// cert-absence). The router-hat twin of run_peer_admits / run_router_admits. The
    /// injected immediately-ready shutdown returns peer_loop WITHOUT a peer, so no
    /// handshake round-trip races.
    ///
    /// RED reproduction: RESTORE a cert-free bind in run_router_hat_until
    /// (`AcceptCertPaths::default().build()` or bind_endpoint) -> cert-absence -> the
    /// expect panics. NON-FLAKY: pid-unique temp cert, quic/127.0.0.1:0 OS port,
    /// ready() shutdown. [[feedback-no-flaky-ever]]
    #[tokio::test]
    async fn run_router_hat_admits_a_quic_listen_with_cert_at_bind() {
        use wz_runtime_tokio_test_support::localhost_cert_key_pem;
        let (cert_pem, key_pem) = localhost_cert_key_pem();
        let dir = std::env::temp_dir();
        let pid = std::process::id();
        let cert_path = dir
            .join(format!("wz-ap-demo-rh-quic-cert-{pid}.pem"))
            .to_string_lossy()
            .into_owned();
        let key_path = dir
            .join(format!("wz-ap-demo-rh-quic-key-{pid}.pem"))
            .to_string_lossy()
            .into_owned();
        std::fs::write(&cert_path, cert_pem.as_bytes()).expect("write cert pem");
        std::fs::write(&key_path, key_pem.as_bytes()).expect("write key pem");

        let cert_paths = AcceptCertPaths {
            tls_cert: None,
            tls_key: None,
            quic_cert: Some(cert_path.clone()),
            quic_key: Some(key_path.clone()),
        };
        let result = run_router_hat_until(
            "quic/127.0.0.1:0",
            &[],
            None,
            false,
            None,
            &cert_paths,
            std::future::ready(()),
        )
        .await;

        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&key_path);
        result
            .expect("the router-hat admits a quic --router-hat listen with --quic-cert (R311y406)");
    }
}

#[cfg(all(
    test,
    feature = "router-hat-router",
    feature = "transport-link-unixpipe",
    target_os = "linux"
))]
mod router_hat_failfast_tests {
    use super::run_router_hat;

    /// R311y396 — a non-IP unixpipe `--router-hat` listen WITHOUT `--zid` fails fast:
    /// `run_router_hat` binds the listener, then returns `Err(InvalidInput)` because a
    /// unixpipe listen has no port to derive a distinct routing zid from and no
    /// `zid_override` was supplied. The message names `--zid` (the R311y396 fix),
    /// distinguishing it from the pre-R311y396 `local_addr()?` reject ("a unixpipe
    /// listener has no IP SocketAddr"), so this unit binds to the product-code seam,
    /// not just to "some error". The `None` zid_override makes the fn return BEFORE
    /// `peer_loop` (the Err is raised at zid derivation), so this is a clean
    /// non-hanging unit test — no SIGTERM injection needed.
    ///
    /// RED reproduction (proof it binds to the R311y396 seam, not the vehicle):
    /// RESTORE `let local = listener.local_addr()?;` at the top of `run_router_hat`
    /// -> the fn errors with "no IP SocketAddr" (no "--zid" substring) -> the
    /// substring assert below fails.
    #[tokio::test]
    async fn run_router_hat_without_zid_on_a_unixpipe_listen_fails_fast() {
        let base = std::env::temp_dir()
            .join(format!("wz-ap-demo-rh-failfast-{}", std::process::id()))
            .to_string_lossy()
            .into_owned();
        // Pre-clean any stale FIFO node from a crashed prior run (no-flaky).
        let _ = std::fs::remove_file(format!("{base}_uplink"));

        let listen = format!("unixpipe/{base}");
        // R311y406 — cert-free unixpipe: the AcceptCertPaths quartet is all-None.
        let err = run_router_hat(
            &listen,
            &[],
            None,
            false,
            None,
            &super::AcceptCertPaths::default(),
        )
        .await
        .expect_err("a non-IP unixpipe --router-hat without --zid must fail fast");
        assert!(
            err.to_string().contains("--zid"),
            "the fail-fast must name --zid (the R311y396 fix), got: {err}"
        );

        // bind_endpoint created the request node; its acceptor Drop unlinks it, but
        // SIGKILL-safe best-effort cleanup here too (mirrors the sibling test).
        let _ = std::fs::remove_file(format!("{base}_uplink"));
    }
}

#[cfg(all(test, feature = "routing-peer", feature = "quic"))]
mod peer_quic_cert_tests {
    use super::{run_peer_until, PeerOpts};
    use crate::InterceptorOpts;

    /// R311y406 — the `--peer quic/` cert-threading discriminator: run_peer (via its
    /// testable inner run_peer_until) now ADMITS a quic listen when PeerOpts carries
    /// --quic-cert/--quic-key (was rejected at bind cert-absence, run_peer having bound
    /// cert-free via bind_endpoint). The QUIC/peer twin of
    /// run_router_admits_a_quic_listen_with_cert_at_bind (R311y405). The injected
    /// immediately-ready shutdown returns peer_loop WITHOUT a peer connecting, so there
    /// is no handshake round-trip to race (a bind-only witness).
    ///
    /// RED reproduction: RESTORE a cert-free bind in run_peer_until
    /// (bind_endpoint_with_config with AcceptConfig::default) -> bind_locator rejects
    /// the quic listen at cert-absence -> run_peer_until returns Err -> this expect
    /// panics. NON-FLAKY: pid-unique temp cert, quic/127.0.0.1:0 OS port, ready()
    /// shutdown. [[feedback-no-flaky-ever]]
    #[tokio::test]
    async fn run_peer_admits_a_quic_listen_with_cert_at_bind() {
        use wz_runtime_tokio_test_support::localhost_cert_key_pem;
        let (cert_pem, key_pem) = localhost_cert_key_pem();
        let dir = std::env::temp_dir();
        let pid = std::process::id();
        let cert_path = dir
            .join(format!("wz-ap-demo-peer-quic-cert-{pid}.pem"))
            .to_string_lossy()
            .into_owned();
        let key_path = dir
            .join(format!("wz-ap-demo-peer-quic-key-{pid}.pem"))
            .to_string_lossy()
            .into_owned();
        std::fs::write(&cert_path, cert_pem.as_bytes()).expect("write cert pem");
        std::fs::write(&key_path, key_pem.as_bytes()).expect("write key pem");

        let opts = PeerOpts {
            publish_key: None,
            subscribe_key: None,
            unsubscribe_after_data: false,
            autoconnect: None,
            full_linkstate: true,
            config_queryable: false,
            config_writable: false,
            config_write_permit: false,
            no_admin_read: false,
            put_key: None,
            put_payload: None,
            zid_override: None,
            #[cfg(feature = "transport-multilink")]
            max_links: 1,
            #[cfg(feature = "transport-qos")]
            qos: false,
            #[cfg(feature = "transport-qos")]
            publish_band: None,
            tls_cert: None,
            tls_key: None,
            quic_cert: Some(cert_path.clone()),
            quic_key: Some(key_path.clone()),
        };
        let interceptors = InterceptorOpts {
            acl_deny: None,
            downsample: None,
            max_payload: None,
        };

        let result = run_peer_until(
            "quic/127.0.0.1:0",
            &[],
            &opts,
            &interceptors,
            std::future::ready(()),
        )
        .await;

        // Best-effort cleanup BEFORE the assert (a bind failure still unlinks).
        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&key_path);
        result.expect("the mesh peer admits a quic --peer listen with --quic-cert (R311y406)");
    }
}

#[cfg(all(
    test,
    feature = "routing-peer",
    feature = "transport-link-unixpipe",
    target_os = "linux"
))]
mod peer_failfast_tests {
    use super::{run_peer, PeerOpts};
    use crate::InterceptorOpts;

    /// R311y397 — a non-IP unixpipe `--peer` listen WITHOUT `--zid` fails fast:
    /// `run_peer` binds the listener, then returns `Err(InvalidInput)` because a
    /// unixpipe listen has no port to derive a distinct routing zid from and no
    /// `zid_override` was supplied. The message names `--zid` (the R311y397 fix),
    /// distinguishing it from the pre-R311y397 `local_addr()?` reject ("a unixpipe
    /// listener has no IP SocketAddr"), so this unit binds to the product-code seam,
    /// not just to "some error". The `None` zid_override makes the fn return BEFORE
    /// `peer_loop` (the Err is raised at zid derivation), so this is a clean
    /// non-hanging unit test — no SIGTERM injection needed. The sibling of
    /// `router_hat_failfast_tests` (R311y396) on the peer run-mode.
    ///
    /// RED reproduction (proof it binds to the R311y397 seam, not the vehicle):
    /// RESTORE `let local = listener.local_addr()?;` at the top of `run_peer` -> the
    /// fn errors with "no IP SocketAddr" (no "--zid" substring) -> the substring
    /// assert below fails.
    #[tokio::test]
    async fn run_peer_without_zid_on_a_unixpipe_listen_fails_fast() {
        let base = std::env::temp_dir()
            .join(format!("wz-ap-demo-peer-failfast-{}", std::process::id()))
            .to_string_lossy()
            .into_owned();
        // Pre-clean any stale FIFO node from a crashed prior run (no-flaky).
        let _ = std::fs::remove_file(format!("{base}_uplink"));

        // A minimal peer opts bundle — every application knob off; the fail-fast
        // fires at zid derivation, BEFORE any opts field is consumed. The cfg-gated
        // fields are set only under their feature (mirrors main.rs's construction).
        let opts = PeerOpts {
            publish_key: None,
            subscribe_key: None,
            unsubscribe_after_data: false,
            autoconnect: None,
            full_linkstate: true,
            config_queryable: false,
            config_writable: false,
            config_write_permit: false,
            no_admin_read: false,
            put_key: None,
            put_payload: None,
            zid_override: None,
            #[cfg(feature = "transport-multilink")]
            max_links: 1,
            #[cfg(feature = "transport-qos")]
            qos: false,
            #[cfg(feature = "transport-qos")]
            publish_band: None,
            tls_cert: None,
            tls_key: None,
            quic_cert: None,
            quic_key: None,
        };
        let interceptors = InterceptorOpts {
            acl_deny: None,
            downsample: None,
            max_payload: None,
        };

        let listen = format!("unixpipe/{base}");
        let err = run_peer(&listen, &[], &opts, &interceptors)
            .await
            .expect_err("a non-IP unixpipe --peer without --zid must fail fast");
        assert!(
            err.to_string().contains("--zid"),
            "the fail-fast must name --zid (the R311y397 fix), got: {err}"
        );

        // bind_endpoint created the request node; its acceptor Drop unlinks it, but
        // SIGKILL-safe best-effort cleanup here too (mirrors the sibling test).
        let _ = std::fs::remove_file(format!("{base}_uplink"));
    }
}
