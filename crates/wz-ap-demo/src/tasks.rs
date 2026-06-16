// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// wz-ap-demo — Established-gated background emit tasks.
//
// R286 — extracted from `main.rs` as part of Phase 2 module
// decomposition (the R281 carry). Pure code-move, no behaviour
// change. Holds the async emit tasks the demo spawns once the
// session FSM has handshake-completed:
//
//   * (R311ot — the former `declare_task` was retired: all outbound
//     declares now emit SYNCHRONOUSLY pre-drive in `run_demo` so the
//     R249 register-before-serve rule applies to every declared kind
//     and no background declare task is spawned);
//   * `query_task` — single-shot `Request(Query)` emit on the
//     `--query` keyexpr;
//   * `publisher_task` — multi-copy burst emit for `--publish` /
//     `--delete`, with optional pre-burst R121g DECLARE preamble.
//
// All three are generic over `T: TimeSource + Send + 'static` (the
// R253-R255 leaf-first migration); the demo monomorphises with
// [`wz::runtime_tokio::runtime_impl::TokioTime`] at the
// `tokio::spawn` call site in `run_demo`. The timing constants are
// per-task and kept module-private — `run_demo` does not configure
// them at runtime.

use std::sync::Arc;

use wz::runtime_core::TimeSource;
use wz::runtime_tokio::reply_sink::ReplyView;
use wz::runtime_tokio::sample::SampleKind;
use wz::runtime_tokio::session::{
    LivelinessGetOptions, PublishAliasError, PublishOptions, TokioSession,
};
use wz::runtime_tokio::session_glue::SessionLinkActions;
use wz::runtime_tokio::Reliability;

use crate::args::PushOperation;

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
        if actions.is_established() {
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
    actions
        .send_request_query(QUERY_RID, /*mapping_id=*/ 0, Some(&keyexpr))
        .expect("demo query keyexpr is a fixed short literal, within codec bounds");
    log::info!("wz-ap-demo: QUERY EMITTED keyexpr='{keyexpr}' rid={QUERY_RID}");
}

/// liveliness-get — single-shot snapshot task. Mirrors
/// [`query_task`]'s Established gate, then issues one
/// [`Session::liveliness_get`] on `keyexpr`. The peer's
/// `LocalTokenRegistry` (a wz acceptor with `--declare-token`)
/// replies with one `Declare(DeclToken)` per matching live token
/// (logged as `LIVELINESS GET REPLY`) terminated by one
/// `Declare(DeclFinal)` (logged as `LIVELINESS GET FINAL`). Unlike
/// [`query_task`] this task DOES consume the inbound reply chain —
/// `liveliness_get` registers the pending get + its callbacks
/// internally — so it takes a [`Session`] (not bare
/// `SessionLinkActions`). The Established gate is mandatory here: the
/// surface enforces [`crate::Session::is_established`] (a one-shot get
/// emitted mid-handshake is discarded by the peer), so the task must
/// not call before the gate fires.
pub(crate) async fn liveliness_get_task<T>(session: TokioSession, keyexpr: String, clock: T)
where
    T: TimeSource + Send + 'static,
{
    // R311nf — `session` is `TokioSession` (= `Session<_,_,Unicast>`);
    // `actions()` is infallible on the unicast typestate.
    let actions = session.actions();
    let deadline_ms = clock.now_monotonic_ms() + QUERY_HANDSHAKE_TIMEOUT_MS;
    loop {
        if actions.is_established() {
            break;
        }
        if clock.now_monotonic_ms() >= deadline_ms {
            log::warn!(
                "wz-ap-demo: liveliness_get_task gave up waiting for Established \
                 after {QUERY_HANDSHAKE_TIMEOUT_MS}ms (record_established_at \
                 never fired)"
            );
            return;
        }
        clock.sleep(QUERY_HANDSHAKE_POLL_INTERVAL_MS).await;
    }
    log::info!(
        "wz-ap-demo: liveliness_get_task observed Established; emitting CURRENT \
         liveliness Interest on keyexpr='{keyexpr}'"
    );
    let key_for_reply = keyexpr.clone();
    let result = session.liveliness_get(
        keyexpr.clone(),
        LivelinessGetOptions::default(),
        move |reply: &dyn ReplyView| {
            log::info!(
                "wz-ap-demo: LIVELINESS GET REPLY filter='{}' keyexpr='{}'",
                key_for_reply,
                reply.keyexpr(),
            );
        },
        move |interest_id: u64| {
            log::info!("wz-ap-demo: LIVELINESS GET FINAL interest_id={interest_id}");
        },
    );
    match result {
        Ok(()) => log::info!("wz-ap-demo: LIVELINESS GET EMITTED keyexpr='{keyexpr}'"),
        Err(e) => log::warn!("wz-ap-demo: liveliness_get failed: {e}"),
    }
}

/// R254 — `clock: T` generic + 3 sleep sites migrated to
/// [`TimeSource::sleep`] (handshake-poll, post-DECLARE drain, burst
/// cadence). Continues R253 leaf-first migration.
/// R255 — deadline math also migrated to u64 ms (option (b) from
/// R254 carry); `std::time::Instant` is no longer referenced in this
/// function.
pub(crate) async fn publisher_task<T>(
    session: TokioSession,
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
    // R311nf — `session` is `TokioSession` (= `Session<_,_,Unicast>`);
    // `actions()` is infallible — the type system statically guarantees
    // the unicast action bundle exists (multicast is a separate type).
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
        if actions.is_established() {
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
        // R300 — the outbound DECLARE gate (cf. run_demo's pre-drive declares).
        // R307.5 — drop the duplicate `eprintln!` on the error path
        // (already covered by `log::warn!`) and route the success
        // line through `log::info!` so all stderr writes share the
        // env_logger lock.
        if let Err(e) = actions.send_declare_keyexpr(mapping_id, &keyexpr) {
            log::warn!(
                "wz-ap-demo: PUBLISHER DECLARE rejected for keyexpr='{keyexpr}' \
                 mapping_id={mapping_id}: {e}"
            );
            return;
        }
        log::info!("wz-ap-demo: PUBLISHER DECLARED keyexpr='{keyexpr}' mapping_id={mapping_id}");
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
            None => session
                .publish(&keyexpr, payload, opts)
                .map(|fired| (fired, "literal"))
                .map_err(PublishAliasError::from),
        };
        match dispatch_outcome {
            Ok((loopback_fired, mode)) => {
                log::info!(
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
            // W3 — the publish build can now also reject when caller
            // data overflows the declared codec capacity (a no-emit
            // reject); log and skip the iteration so the burst still
            // terminates.
            Err(e @ PublishAliasError::ExceedsCapacity) => {
                log::error!(
                    "wz-ap-demo: publisher_task publish rejected on idx={i}: {e}; \
                     skipping this iteration"
                );
            }
            // F2 — a publish inside a reconnect window rejects typed
            // (transport gate closed until Established re-entry); log and
            // skip so the burst still terminates — the next iterations
            // succeed once the supervisor re-establishes.
            Err(e @ PublishAliasError::TransportUnavailable) => {
                log::warn!(
                    "wz-ap-demo: publisher_task publish rejected on idx={i}: {e}; \
                     skipping this iteration"
                );
            }
            // B5b-2b / R311nf — an aliased publish on a non-unicast transport
            // rejects typed. `publisher_task` takes a `TokioSession` (=
            // `Session<_,_,Unicast>`), so a multicast transport is excluded at
            // the type level and this arm is unreachable in the demo; the
            // exhaustive match keeps it, logged + skipped uniformly.
            Err(e @ PublishAliasError::RequiresUnicast) => {
                log::warn!(
                    "wz-ap-demo: publisher_task publish rejected on idx={i}: {e}; \
                     skipping this iteration"
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
