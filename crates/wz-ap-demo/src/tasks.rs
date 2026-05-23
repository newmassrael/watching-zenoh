// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// wz-ap-demo — Established-gated background emit tasks.
//
// R286 — extracted from `main.rs` as part of Phase 2 module
// decomposition (the R281 carry). Pure code-move, no behaviour
// change. Holds the three async tasks the demo spawns once the
// session FSM has handshake-completed:
//
//   * `declare_task` — emits the `--declare-subscriber/queryable/
//     token` keyexprs once each, in deterministic order; hands the
//     RAII [`LivelinessToken`] back to `run_demo` via a oneshot so
//     `Drop` lands at run_demo scope (graceful UndeclToken on
//     teardown);
//   * `query_task` — single-shot `Request(Query)` emit on the
//     `--query` keyexpr;
//   * `publisher_task` — multi-copy burst emit for `--publish` /
//     `--delete`, with optional pre-burst R121g DECLARE preamble.
//
// All three are generic over `T: TimeSource + Send + 'static` (the
// R253-R255 leaf-first migration); the demo monomorphises with
// [`wz_runtime_tokio::runtime_impl::TokioTime`] at the
// `tokio::spawn` call site in `run_demo`. The timing constants are
// per-task and kept module-private — `run_demo` does not configure
// them at runtime.

use std::sync::Arc;

use tokio::sync::oneshot;

use wz_runtime_core::TimeSource;
use wz_runtime_tokio::sample::SampleKind;
use wz_runtime_tokio::session::{
    LivelinessOptions, LivelinessToken, PublishAliasError, PublishOptions, Session,
};
use wz_runtime_tokio::session_glue::SessionLinkActions;
use wz_runtime_tokio::Reliability;

use crate::args::{DeclareEmitSpec, PushOperation};

/// R121e — publisher task body. Waits for the session FSM to
/// reach the Established state (signalled by
/// `trace.record_established_at > 0`, the role-agnostic
/// `Established.onentry` script-action counter; this fires on
/// both the acceptor side after `send_open_ack` AND on the
/// initiator side after the peer's `OpenAck` arrives — R121f
/// refactor unified the gate so the publisher works in both
/// modes without role-aware branching). Then emits a fixed
/// number of `Push` frames spaced at a fixed cadence so a z_sub
/// peer can observe at least one in steady state.
///
/// Why multi-copy emission (`PUBLISHER_BURST_COUNT`): zenoh-pico's
/// `z_sub` declares its subscription AFTER the handshake
/// completes (the DECLARE[DeclSubscriber] arrives in the first
/// Frame after the peer's OpenSyn). If wz-ap-demo emits the
/// Push BEFORE that DECLARE lands, z_sub's local matcher has
/// nothing to compare against and drops the message. Sending a
/// short burst spaced at the configured cadence makes the
/// integration test robust against this 1-frame race window
/// without needing to peek into the inbound stream for
/// `DeclSubscriber` arrival.
///
/// Why a synchronous trace-counter poll (not a `tokio::sync`
/// primitive): `SessionLinkActions` does not currently expose an
/// "Established" event channel, and the trace counter is already
/// authoritative for the handshake-side script-action dispatch.
/// A short 50ms poll cadence keeps the cold-start latency
/// bounded to one polling interval (~50ms) while staying
/// allocation-free. A future round can swap this for a
/// `tokio::sync::Notify`-based path once a `SessionLinkActions`
/// signal slot for Established lands (R121e carry).
const PUBLISHER_HANDSHAKE_POLL_INTERVAL_MS: u64 = 50;
const PUBLISHER_HANDSHAKE_TIMEOUT_MS: u64 = 5_000;
const PUBLISHER_BURST_COUNT: usize = 5;
const PUBLISHER_BURST_INTERVAL_MS: u64 = 200;

/// R121j-5c-e2e-demo — single-shot query emit task. Mirrors
/// [`publisher_task`]'s timing gate: wait for the role-agnostic
/// `record_established_at` counter to fire, then send exactly one
/// `Request(Query)` on `keyexpr` (literal form, `mapping_id = 0`,
/// `rid = 1`). The peer's queryable registry produces zero or more
/// `Response(Reply)` frames followed by exactly one `ResponseFinal`
/// terminating the chain; this task does not currently consume
/// the inbound Reply chain (no application-side z_get adapter
/// yet — R121j-6 carry). The demo binary's purpose here is to
/// drive the OUTBOUND Query path so a paired wz-ap-demo --queryable
/// peer can fire its callback on the matched keyexpr.
const QUERY_HANDSHAKE_POLL_INTERVAL_MS: u64 = 50;
const QUERY_HANDSHAKE_TIMEOUT_MS: u64 = 5_000;
/// Exposed pub(crate) because `run_demo`'s ReplyRegistry register
/// site (the on_query_reply / on_query_final binding plus the R263
/// deadline + R264 sweep_task wiring) keys on the same rid that
/// [`query_task`] emits on the wire. Keeping the constant single-
/// sourced here means a future round that changes the rid (e.g. to
/// a per-process counter) lands one edit and both sides follow.
pub(crate) const QUERY_RID: u64 = 1;

/// R121k-5 — declare emit task. Bundles the three optional
/// `--declare-*` keyexprs into one Established-gated batch so the
/// peer sees Sub/Queryable/Token declares in deterministic order
/// (subscriber → queryable → token). Each declare goes on the
/// reliable channel — zenoh-pico's `_z_session_recv_declaration`
/// requires the declare to land before any dependent message that
/// would alias the declared id.
///
/// Hard-coded ids:
///   subscriber  = 1001
///   queryable   = 2001
///   token       = auto-allocated by SessionLinkActions::alloc_next_token_id
///                 (first call returns 0; R277 migration to LivelinessToken)
/// Ids are picked per-kind so a wire-capture or integration test can
/// distinguish at a glance which kind a given declare body belongs
/// to. Production deployments would source sub / queryable ids from a
/// per-session counter (the wz-ap-demo binary is intentionally minimal
/// here for those arms); token already routes through the
/// per-session counter via Session::declare_token at R277.
const DECLARE_SUBSCRIBER_ID: u64 = 1001;
const DECLARE_QUERYABLE_ID: u64 = 2001;
// R277 — DECLARE_TOKEN_ID retired. The token branch routes through
// `Session::declare_token` (RAII LivelinessToken handle) which
// allocates ids via `SessionLinkActions::alloc_next_token_id`. The
// first auto-allocated id in this demo is 0 (the per-session
// counter starts at 0 and uses `fetch_add(1, Relaxed)`).
const DECLARE_HANDSHAKE_POLL_INTERVAL_MS: u64 = 50;
const DECLARE_HANDSHAKE_TIMEOUT_MS: u64 = 5_000;
const DECLARE_INTER_EMIT_MS: u64 = 100;

/// R253 — first leaf caller migration: this function previously
/// reached for `tokio::time::sleep` directly; the three sleep sites
/// now go through the [`TimeSource`] trait (concrete impl supplied
/// by the caller, currently
/// [`wz_runtime_tokio::runtime_impl::TokioTime`] but swappable for
/// an MCU profile's TimeSource without touching this function body).
/// The `T: TimeSource + Send + 'static` generic parameter is
/// monomorphised at the `tokio::spawn(declare_task(.., TokioTime::new()))`
/// call site in `run_demo`.
///
/// R255 — deadline math is now u64-ms based (option (b) from the
/// R254 carry): `deadline_ms = clock.now_monotonic_ms() +
/// TIMEOUT_MS`; each loop iteration compares the current monotonic
/// reading against the deadline. MCU-friendlier than the prior
/// `std::time::Instant::now() + Duration::from_millis(MS)` pattern
/// because no_std targets have no `Instant` type. The trait surface
/// stays unchanged — same `now_monotonic_ms()` everyone already had.
///
/// R277 — takes [`Session`] (not `Arc<SessionLinkActions>`) so the
/// token branch can route through [`Session::declare_token`] for the
/// `LivelinessToken` RAII handle. The handle is moved back to
/// `run_demo` via `token_tx` (oneshot) so its `Drop` — which emits
/// `Declare(UndeclToken)` on the wire — fires at `run_demo` scope,
/// not at this task's stack-frame end. Sub / queryable arms still
/// route through `session.actions()` because no `Session`-level
/// handle API exists for them yet (R245/R246 covered subscriber +
/// queryable but only with same-process callback wiring; the
/// declare-time wire emit still goes through `SessionLinkActions`).
///
/// Shutdown semantics: end-to-end UndeclToken emission requires
/// graceful unwinding of `run_demo` (FSM hits terminal OR R278
/// `shutdown_signal()` arm of the `tokio::select!` fires).
/// Signal-driven shutdown was wired in R278 — sending SIGTERM /
/// SIGINT to wz-ap-demo now drops the held LivelinessToken (RAII)
/// before drop(actions), so the peer observes the
/// `Declare(UndeclToken)` retraction frame ahead of the connection
/// EOF. The integration test
/// `wz_remote_declare_round_trip_against_wz_initiator` exercises
/// the graceful path against the acceptor and asserts
/// `REMOTE TOKEN UNDECLARED id=0` in initiator stderr.
/// SIGKILL still bypasses Rust `Drop` entirely; under that path
/// the peer only sees connection EOF.
pub(crate) async fn declare_task<T>(
    session: Session,
    spec: DeclareEmitSpec,
    clock: T,
    token_tx: Option<oneshot::Sender<LivelinessToken>>,
) where
    T: TimeSource + Send + 'static,
{
    let actions = session.actions();
    let deadline_ms = clock.now_monotonic_ms() + DECLARE_HANDSHAKE_TIMEOUT_MS;
    loop {
        if actions.trace_snapshot().record_established_at > 0 {
            break;
        }
        if clock.now_monotonic_ms() >= deadline_ms {
            log::warn!(
                "wz-ap-demo: declare_task gave up waiting for Established \
                 after {DECLARE_HANDSHAKE_TIMEOUT_MS}ms (record_established_at \
                 never fired)"
            );
            return;
        }
        clock.sleep(DECLARE_HANDSHAKE_POLL_INTERVAL_MS).await;
    }
    if let Some(keyexpr) = spec.subscriber_keyexpr.as_deref() {
        // R300 — the outbound DECLARE gate rejects malformed or
        // pico-SIGABRT-prone keyexprs pre-emit. The demo treats
        // a rejected user-supplied keyexpr as a CLI input error:
        // log + bail this task, do not panic.
        if let Err(e) =
            actions.send_declare_subscriber(DECLARE_SUBSCRIBER_ID, /*mapping_id=*/ 0, Some(keyexpr))
        {
            log::warn!(
                "wz-ap-demo: SUBSCRIBER DECLARE rejected for keyexpr='{keyexpr}': {e}"
            );
            eprintln!(
                "wz-ap-demo: SUBSCRIBER DECLARE rejected for keyexpr='{keyexpr}': {e}"
            );
            return;
        }
        eprintln!("wz-ap-demo: DECLARED SUBSCRIBER id={DECLARE_SUBSCRIBER_ID} keyexpr='{keyexpr}'");
        clock.sleep(DECLARE_INTER_EMIT_MS).await;
    }
    if let Some(keyexpr) = spec.queryable_keyexpr.as_deref() {
        if let Err(e) =
            actions.send_declare_queryable(DECLARE_QUERYABLE_ID, /*mapping_id=*/ 0, Some(keyexpr))
        {
            log::warn!(
                "wz-ap-demo: QUERYABLE DECLARE rejected for keyexpr='{keyexpr}': {e}"
            );
            eprintln!(
                "wz-ap-demo: QUERYABLE DECLARE rejected for keyexpr='{keyexpr}': {e}"
            );
            return;
        }
        eprintln!("wz-ap-demo: DECLARED QUERYABLE id={DECLARE_QUERYABLE_ID} keyexpr='{keyexpr}'");
        clock.sleep(DECLARE_INTER_EMIT_MS).await;
    }
    if let Some(keyexpr) = spec.token_keyexpr.as_deref() {
        let token = match session.declare_token(keyexpr.to_string(), LivelinessOptions::default()) {
            Ok(t) => t,
            Err(e) => {
                log::warn!(
                    "wz-ap-demo: TOKEN DECLARE rejected for keyexpr='{keyexpr}': {e}"
                );
                eprintln!(
                    "wz-ap-demo: TOKEN DECLARE rejected for keyexpr='{keyexpr}': {e}"
                );
                return;
            }
        };
        eprintln!(
            "wz-ap-demo: DECLARED TOKEN id={id} keyexpr='{keyexpr}'",
            id = token.id()
        );
        if let Some(tx) = token_tx {
            // Hand the LivelinessToken back to run_demo. If the
            // receiver was already dropped (e.g. run_demo bailed
            // before this gate fired), tx.send returns Err and
            // the token drops here — same `Declare(UndeclToken)`
            // is emitted, just immediately after the DeclToken.
            let _ = tx.send(token);
        }
        // else: no oneshot was created (spec.token_keyexpr was
        // None at spawn time), but we reached this arm because
        // it became Some between then and now. Cannot happen
        // with the current spawn-site invariants — token_tx is
        // Some IFF spec.token_keyexpr was Some at spawn — but
        // the else branch keeps the code total: token drops here
        // emitting UndeclToken back-to-back with DeclToken,
        // signalling the keyexpr surface transition only.
    }
}

/// R254 — `clock: T` generic + 1 sleep site migrated to
/// [`TimeSource::sleep`], continuing the R253 leaf-first cadence.
/// R255 — deadline math also migrated to u64 ms (option (b) from
/// R254 carry); `std::time::Instant` is no longer referenced here.
pub(crate) async fn query_task<T>(actions: Arc<SessionLinkActions>, keyexpr: String, clock: T)
where
    T: TimeSource + Send + 'static,
{
    let deadline_ms = clock.now_monotonic_ms() + QUERY_HANDSHAKE_TIMEOUT_MS;
    loop {
        if actions.trace_snapshot().record_established_at > 0 {
            break;
        }
        if clock.now_monotonic_ms() >= deadline_ms {
            log::warn!(
                "wz-ap-demo: query_task gave up waiting for Established \
                 after {QUERY_HANDSHAKE_TIMEOUT_MS}ms (record_established_at \
                 never fired)"
            );
            return;
        }
        clock.sleep(QUERY_HANDSHAKE_POLL_INTERVAL_MS).await;
    }
    log::info!(
        "wz-ap-demo: query_task observed Established; emitting Query \
         on keyexpr='{keyexpr}' rid={QUERY_RID}"
    );
    actions.send_request_query(QUERY_RID, /*mapping_id=*/ 0, Some(&keyexpr));
    eprintln!("wz-ap-demo: QUERY EMITTED keyexpr='{keyexpr}' rid={QUERY_RID}");
}

/// R254 — `clock: T` generic + 3 sleep sites migrated to
/// [`TimeSource::sleep`] (handshake-poll, post-DECLARE drain, burst
/// cadence). Continues R253 leaf-first migration.
/// R255 — deadline math also migrated to u64 ms (option (b) from
/// R254 carry); `std::time::Instant` is no longer referenced in this
/// function.
pub(crate) async fn publisher_task<T>(
    session: Session,
    keyexpr: String,
    operation: PushOperation,
    declare_id: Option<u64>,
    clock: T,
) where
    T: TimeSource + Send + 'static,
{
    // R235 — borrow the outbound actions handle for `trace_snapshot`
    // (Established gate polling) + `send_declare_keyexpr` (the
    // pre-burst R121g declare preamble). Push emission itself routes
    // through `Session::publish` / `publish_aliased_auto` which keep
    // the loopback branch live so a co-located subscriber on the
    // publish keyexpr fires in-process without crossing the wire.
    let actions = session.actions();

    // ── Step 1: wait for Established. Both acceptor and initiator
    //           reach Established on the same `record_established_at`
    //           script-action that fires on `Established.onentry`
    //           in `session_fsm_unicast.scxml`. R121e used the
    //           acceptor-specific `send_open_ack` counter; R121f
    //           refactor unified the gate so the publisher works
    //           in both roles. The counter signals:
    //             - acceptor side: after sending OpenAck (the
    //               last handshake script-action AND the
    //               transition into Established);
    //             - initiator side: after the peer's OpenAck
    //               arrives (`OpenAckReceived` event drives the
    //               SentOpenSyn → Established transition).
    //           Polling `record_established_at` is therefore
    //           role-agnostic; the publisher does not need to
    //           know whether wz dialed out or accepted in.
    //           Bail with a warn on timeout — the publisher had
    //           no opportunity to emit; the drive_session loop
    //           is responsible for the failure mode (lease
    //           expiry, framing error, etc.).
    let deadline_ms = clock.now_monotonic_ms() + PUBLISHER_HANDSHAKE_TIMEOUT_MS;
    loop {
        if actions.trace_snapshot().record_established_at > 0 {
            break;
        }
        if clock.now_monotonic_ms() >= deadline_ms {
            log::warn!(
                "wz-ap-demo: publisher_task gave up waiting for Established \
                 after {PUBLISHER_HANDSHAKE_TIMEOUT_MS}ms (record_established_at \
                 never fired)"
            );
            return;
        }
        clock.sleep(PUBLISHER_HANDSHAKE_POLL_INTERVAL_MS).await;
    }
    match &operation {
        PushOperation::Put { value } => log::info!(
            "wz-ap-demo: publisher_task observed Established; emitting {PUBLISHER_BURST_COUNT} Put Pushes \
             on keyexpr='{keyexpr}' value='{value}'"
        ),
        PushOperation::Delete => log::info!(
            "wz-ap-demo: publisher_task observed Established; emitting {PUBLISHER_BURST_COUNT} Del Pushes \
             on keyexpr='{keyexpr}' (R219 MsgDel body, no payload)"
        ),
    }

    // ── Step 2 (R121g): if --declare-id was supplied, send a
    //           Frame[Declare(DeclKexpr(id, suffix=keyexpr))] once
    //           so the peer's keyexpr table maps `id -> keyexpr`.
    //           Subsequent Pushes carry only `id` (and an empty
    //           suffix), which the peer resolves via the populated
    //           table. The DECLARE is reliable to guarantee
    //           ordering on the reliable channel — the SN window
    //           preserves "DECLARE before any dependent Push" on
    //           the peer side.
    //
    //           R234 — `send_declare_keyexpr` also registers
    //           `mapping_id -> keyexpr` in this session's outbound
    //           mapping table, so the subsequent
    //           `Session::publish_aliased_auto(mapping_id, None, …)`
    //           resolves the loopback literal without the caller
    //           restating it.
    if let Some(mapping_id) = declare_id {
        // R300 — see declare_task above for the gate rationale.
        if let Err(e) = actions.send_declare_keyexpr(mapping_id, &keyexpr) {
            log::warn!(
                "wz-ap-demo: PUBLISHER DECLARE rejected for keyexpr='{keyexpr}' \
                 mapping_id={mapping_id}: {e}"
            );
            eprintln!(
                "wz-ap-demo: PUBLISHER DECLARE rejected for keyexpr='{keyexpr}' \
                 mapping_id={mapping_id}: {e}"
            );
            return;
        }
        eprintln!("wz-ap-demo: PUBLISHER DECLARED keyexpr='{keyexpr}' mapping_id={mapping_id}");
        // Small drain pause so the DECLARE bytes reach the peer's
        // session-FSM dispatch (and populate the keyexpr table)
        // before the first aliased Push fires on the same channel.
        // The mpsc-channel + writer-task topology preserves
        // application-order on the wire, but the peer's receive
        // task is independent of our writer — a brief pause makes
        // the test less reliant on scheduling fairness.
        clock.sleep(PUBLISHER_BURST_INTERVAL_MS).await;
    }

    // ── Step 3: emit the burst. Each iteration composes a
    //           `PublishOptions` carrying `SampleKind::Put` or
    //           `SampleKind::Del` and `Reliability::Reliable` (the
    //           pre-R235 direct-action calls passed `reliable=true`
    //           explicitly; the default `Locality::Any` keeps the
    //           wire branch firing while also enabling the loopback
    //           branch). `Session::publish_aliased_auto` looks up
    //           the mapping id in the outbound table (populated by
    //           the Step 2 declare); if the table is missing the id
    //           — caller contract violation — neither branch fires
    //           and the iteration logs a hard error instead of
    //           silently mis-delivering.
    //
    //           R235 — co-located subscriber semantics: when a
    //           subscriber on `keyexpr` is registered on the SAME
    //           process (`--key foo` + `--publish foo` in this
    //           demo), the loopback branch fires the local
    //           callback in addition to the wire send; the
    //           `loopback_fired` counter in the log line records the
    //           number of local callbacks invoked per iteration so a
    //           test fixture can distinguish loopback vs wire fans.
    for i in 0..PUBLISHER_BURST_COUNT {
        let mut opts = PublishOptions::default().with_reliability(Reliability::Reliable);
        let (kind_tag, payload): (&str, &[u8]) = match &operation {
            PushOperation::Put { value } => {
                opts.kind = SampleKind::Put;
                ("PUT", value.as_bytes())
            }
            PushOperation::Delete => {
                opts.kind = SampleKind::Del;
                ("DEL", &[])
            }
        };
        let dispatch_outcome: Result<(usize, &'static str), PublishAliasError> = match declare_id {
            Some(mapping_id) => session
                .publish_aliased_auto(mapping_id, None, payload, opts)
                .map(|fired| (fired, "aliased")),
            None => Ok((session.publish(&keyexpr, payload, opts), "literal")),
        };
        match dispatch_outcome {
            Ok((loopback_fired, mode)) => {
                eprintln!(
                    "wz-ap-demo: PUBLISHER EMITTED kind={kind_tag} mode={mode} \
                     keyexpr='{keyexpr}' declare_id={declare_id:?} payload_len={payload_len} \
                     idx={i} loopback_fired={loopback_fired}",
                    payload_len = payload.len(),
                );
            }
            Err(PublishAliasError::UnknownMapping(id)) => {
                // R234 contract: publisher_task called
                // `send_declare_keyexpr` in Step 2 before entering
                // this loop, so an UnknownMapping here means the
                // mapping was either never registered (Step 2 took
                // the None branch yet the publisher still asked for
                // aliased dispatch — wiring bug) or was retracted
                // by a concurrent `send_undeclare_kexpr`. Log hard
                // and skip the iteration so the burst still
                // terminates; the test fixture distinguishes this
                // line from the EMITTED line.
                log::error!(
                    "wz-ap-demo: publisher_task UnknownMapping id={id} on idx={i} — \
                     declare-before-publish contract violated; skipping this iteration"
                );
            }
        }
        // Cadence pause between emissions (not after the last
        // one — the run_demo cleanup gives the writer a brief
        // drain window).
        if i + 1 < PUBLISHER_BURST_COUNT {
            clock.sleep(PUBLISHER_BURST_INTERVAL_MS).await;
        }
    }
    log::info!("wz-ap-demo: publisher_task finished emission burst");
}
