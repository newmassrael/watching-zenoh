// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
use wz::runtime_tokio::session_glue::{QueryMetadata, SessionLinkActions};
use wz::runtime_tokio::Reliability;

use crate::args::{LivelinessGetSpec, PublisherSpec, PushOperation};

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
///
/// R311y481 — the emit moved from `send_request_query` to
/// `send_request_query_with_meta` so `--query-params` / `--query-attachment` can
/// ride the Query body. The no-flag path is byte-UNCHANGED: an empty
/// `QueryMetadata` is pinned to produce the identical frame
/// (`send_request_query_with_meta_empty_emits_same_bytes_as_no_meta`,
/// session_glue.rs), so every pre-existing Layer E fixture that greps this
/// task's wire output keeps passing without a fixture edit.
pub(crate) async fn query_task<T>(
    actions: Arc<SessionLinkActions>,
    spec: crate::args::QueryEmitSpec,
    clock: T,
) where
    T: TimeSource + Send + 'static,
{
    let crate::args::QueryEmitSpec {
        keyexpr,
        parameters,
        attachment,
        after_ms,
    } = spec;
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
    // R311y481 — the ordering hold, logged as a BRACKET for the reason
    // `liveliness_get_task`'s twin states: a fixture that waits on a foreign
    // queryable's decode must be able to prove the wait happened, or a green run
    // could equally mean the Query fired at t=0 and got lucky. That is not
    // hypothetical here -- a hand run with no hold passed exactly that way.
    if let Some(ms) = after_ms {
        log::info!(
            "wz-ap-demo: query_task holding the Query {ms}ms after Established \
             (--query-after-ms), leaving the peer time to declare its queryable"
        );
        clock.sleep(ms).await;
        log::info!("wz-ap-demo: query_task hold elapsed after {ms}ms");
    }
    log::info!(
        "wz-ap-demo: query_task observed Established; emitting Query \
         on keyexpr='{keyexpr}' rid={QUERY_RID}"
    );
    // R311y481 — the attachment is encoded HERE rather than at argv parse time so
    // the kv-pair wire form has a single producer: `serialize_kv_attachment` is
    // the same SSOT the push-side `z_sub_attachment` witness uses, and pico's
    // deserializer reads the leading sequence count, so a second encoder would be
    // a second place for that count to drift.
    #[cfg(feature = "query-attachment")]
    let attachment_blob = attachment.as_ref().map(|pairs| {
        let borrowed: Vec<(&[u8], &[u8])> = pairs
            .iter()
            .map(|(k, v)| (k.as_bytes(), v.as_bytes()))
            .collect();
        wz::runtime_tokio::attachment::serialize_kv_attachment(&borrowed)
    });
    // The OFF arm is LOUD rather than silent, for the reason the `advanced`-OFF
    // arms in runner.rs state: a fixture that greps pico's `with attachment:`
    // line must be able to tell "built without the attachment plane" from "wz
    // attached and the foreign decode failed". A silent `None` here would read as
    // the second when it was the first.
    #[cfg(not(feature = "query-attachment"))]
    let attachment_blob: Option<Vec<u8>> = {
        if let Some(pairs) = attachment.as_ref() {
            log::warn!(
                "wz-ap-demo: --query-attachment={pairs:?} is INERT (built without the \
                 `query-attachment` feature); the Query carries no attachment ext"
            );
        }
        None
    };
    let meta = QueryMetadata {
        parameters: parameters.as_ref().map(|p| p.as_bytes().to_vec()),
        attachment: attachment_blob,
        ..Default::default()
    };
    actions
        .send_request_query_with_meta(QUERY_RID, /*mapping_id=*/ 0, Some(&keyexpr), &meta)
        .expect("demo query keyexpr is a fixed short literal, within codec bounds");
    log::info!(
        "wz-ap-demo: QUERY EMITTED keyexpr='{keyexpr}' rid={QUERY_RID} params={:?} \
         attachment_pairs={}",
        parameters,
        attachment.as_ref().map_or(0, |p| p.len()),
    );
}

/// R311y445 — `--group-join`: join a zenoh-ext GROUP as a member and hold the
/// membership open so a foreign group peer can observe it.
///
/// Declared INSIDE a task, like [`advanced_publisher_task`] and for the same
/// reason: `Group::join` spawns the lease watchdog (and the keep-alive beacon
/// for `Auto` liveliness), so it requires a live tokio runtime.
///
/// The group is HELD rather than returned. Dropping it undeclares the member's
/// event subscriber and per-member queryable and stops the keep-alive, which is
/// precisely the state a foreign peer's view is supposed to reflect -- so the
/// task parks instead of completing, and the fixture terminates the process.
#[cfg(feature = "group")]
pub(crate) async fn group_join_task<T>(
    session: TokioSession,
    spec: crate::args::GroupJoinSpec,
    clock: T,
) where
    T: TimeSource + Send + 'static,
{
    use wz::runtime_tokio::group::{Group, GroupOptions, Member};

    let actions = session.actions();
    let deadline_ms = clock.now_monotonic_ms() + QUERY_HANDSHAKE_TIMEOUT_MS;
    loop {
        if actions.is_established() {
            break;
        }
        if clock.now_monotonic_ms() >= deadline_ms {
            log::warn!(
                "wz-ap-demo: group_join_task gave up waiting for Established \
                 after {QUERY_HANDSHAKE_TIMEOUT_MS}ms"
            );
            return;
        }
        clock.sleep(QUERY_HANDSHAKE_POLL_INTERVAL_MS).await;
    }

    let mut member = Member::new(spec.member_id.clone());
    if let Some(secs) = spec.lease_secs {
        member = member.lease(core::time::Duration::from_secs(secs));
    }
    let group = match Group::join(
        &session,
        spec.group.clone(),
        member,
        GroupOptions::default(),
    ) {
        Ok(g) => g,
        Err(e) => {
            // A wildcard group or member id lands here. Logged rather than
            // swallowed: "the foreign peer never saw us" and "we never joined"
            // are the two readings a fixture has to tell apart.
            log::warn!(
                "wz-ap-demo: GROUP JOIN rejected group='{}' member_id='{}': {e:?}",
                spec.group,
                spec.member_id
            );
            return;
        }
    };
    log::info!(
        "wz-ap-demo: JOINED GROUP group='{}' member_id='{}' lease_secs={:?} view_size={}",
        spec.group,
        spec.member_id,
        spec.lease_secs,
        group.size(),
    );

    // Hold the membership. See the doc comment: dropping `group` would retract
    // exactly what the foreign peer is being asked to observe.
    loop {
        clock.sleep(1_000).await;
    }
}

/// R311y442 — `--advanced-publish`: declare a wz [`AdvancedPublisher`] with a
/// sample cache and emit a burst into it, then hold the session open so the
/// cache keeps answering.
///
/// This is the ANSWERING half of the advanced-pubsub plane, and it needs its own
/// task for a reason the plain `--publish` burst does not have: the `@adv` cache
/// only has value AFTER the burst, when a late-joining subscriber asks for the
/// samples it missed. So the task publishes and then deliberately stays alive
/// rather than completing — the proof is what a foreign subscriber can still
/// retrieve once the publishing is over.
///
/// Declared INSIDE the task rather than pre-drive with the other handles because
/// [`AdvancedPublisher::declare`] spawns the heartbeat beacon and therefore
/// requires a live tokio runtime; the Established gate below is the same poll
/// [`query_task`] uses.
#[cfg(feature = "advanced")]
pub(crate) async fn advanced_publisher_task<T>(
    session: TokioSession,
    spec: crate::args::AdvancedPublishSpec,
    clock: T,
) where
    T: TimeSource + Send + 'static,
{
    use wz::runtime_tokio::advanced_cache::CacheConfig;
    use wz::runtime_tokio::advanced_publisher::{AdvancedPublisher, AdvancedPublisherOptions};

    let actions = session.actions();
    let deadline_ms = clock.now_monotonic_ms() + QUERY_HANDSHAKE_TIMEOUT_MS;
    loop {
        if actions.is_established() {
            break;
        }
        if clock.now_monotonic_ms() >= deadline_ms {
            log::warn!(
                "wz-ap-demo: advanced_publisher_task gave up waiting for Established \
                 after {QUERY_HANDSHAKE_TIMEOUT_MS}ms"
            );
            return;
        }
        clock.sleep(QUERY_HANDSHAKE_POLL_INTERVAL_MS).await;
    }

    let mut options = AdvancedPublisherOptions::default();
    if let Some(max_samples) = spec.cache_max {
        options.cache = Some(CacheConfig { max_samples });
    }
    // R311y444 — arm the last-sn heartbeat BEACON. `AdvancedPublisherOptions`
    // defaults to `Sequencing::SequenceNumber` (`advanced_publisher.rs:116`),
    // which the beacon REQUIRES: `heartbeat_spawn_params` returns `None` for any
    // other sequencing (`:397-404`) and the beacon task is simply never spawned.
    //
    // R311y444-review (REVIEWERS 1 and 3, independently) — an earlier version of
    // this comment claimed that coupling was "asserted at declare time by the log
    // line below". IT IS NOT: the log reports `heartbeat_ms`, never `sequencing`,
    // so if the default ever flipped, both the log and the fixture's
    // `heartbeat_ms=Some(..)` guard would still pass while no beacon was emitted.
    // The thing that would catch it is leg 7 going red, which is a real gate but
    // not the one the comment named.
    if let Some(period_ms) = spec.heartbeat_ms {
        options.sample_miss_detection =
            wz::runtime_tokio::advanced_publisher::MissDetectionConfig::default()
                .heartbeat(core::time::Duration::from_millis(period_ms));
    }
    let publisher =
        match AdvancedPublisher::declare(&session, spec.keyexpr.clone(), options, spec.zid.clone())
        {
            Ok(p) => p,
            Err(e) => {
                log::warn!(
                    "wz-ap-demo: ADVANCED PUBLISHER declare rejected for keyexpr='{}': {e:?}",
                    spec.keyexpr
                );
                return;
            }
        };
    log::info!(
        "wz-ap-demo: DECLARED ADVANCED PUBLISHER keyexpr='{}' cache_max={:?} count={} \
         heartbeat_ms={:?}",
        spec.keyexpr,
        spec.cache_max,
        spec.count,
        spec.heartbeat_ms,
    );

    for idx in 0..spec.count {
        // The `[{idx:4}] {value}` shape mirrors upstream's own `z_advanced_pub`
        // so a mixed-direction fixture reads the two publishers the same way.
        let payload = format!("[{idx:4}] {}", spec.value);
        match publisher.put(payload.as_bytes()) {
            Ok(_) => log::info!(
                "wz-ap-demo: ADVANCED PUT keyexpr='{}' payload='{payload}'",
                spec.keyexpr
            ),
            Err(e) => log::warn!("wz-ap-demo: ADVANCED PUT failed: {e:?}"),
        }
        clock.sleep(spec.interval_ms).await;
    }
    log::info!(
        "wz-ap-demo: ADVANCED BURST COMPLETE keyexpr='{}' count={}; cache now serving",
        spec.keyexpr,
        spec.count,
    );

    // Hold the publisher (and with it the cache queryable + the `@adv` liveliness
    // token) alive. Dropping it here would undeclare the very cache a late
    // subscriber is about to query, which is precisely the window under test.
    // The demo process is terminated by its fixture, as every Layer Z leg is.
    loop {
        clock.sleep(1_000).await;
    }
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
/// R311y353 — `spec.after_ms` holds the get that long AFTER Established, which is
/// the ordering a foreign token holder needs. See [`LivelinessGetSpec::after_ms`]
/// for why no other knob produces it and why it is not cfg-gated.
pub(crate) async fn liveliness_get_task<T>(session: TokioSession, spec: LivelinessGetSpec, clock: T)
where
    T: TimeSource + Send + 'static,
{
    let LivelinessGetSpec { keyexpr, after_ms } = spec;
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
    // R311y353 — the ordering hold. It is logged as a BRACKET (this line, then
    // the emit line below) rather than slept silently: a fixture that waits on
    // a reply must be able to prove the wait actually happened, or a green run
    // could equally mean the get fired at t=0 and got lucky.
    if let Some(ms) = after_ms {
        log::info!(
            "wz-ap-demo: liveliness_get_task holding the get {ms}ms after Established \
             (--liveliness-get-after-ms), leaving the peer time to declare"
        );
        clock.sleep(ms).await;
        log::info!("wz-ap-demo: liveliness_get_task hold elapsed after {ms}ms");
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
        // R311y575 — `liveliness_get` now answers with the interest id it
        // registered under (the id `cancel_pending_liveliness_get` takes), so the
        // emit log names it: the FINAL log above already prints the same id, and
        // a pair that does not match is a correlation bug this line makes
        // visible.
        Ok(interest_id) => log::info!(
            "wz-ap-demo: LIVELINESS GET EMITTED keyexpr='{keyexpr}' interest_id={interest_id}"
        ),
        Err(e) => log::warn!("wz-ap-demo: liveliness_get failed: {e}"),
    }
}

/// R254 — `clock: T` generic + 3 sleep sites migrated to
/// [`TimeSource::sleep`] (handshake-poll, post-DECLARE drain, burst
/// cadence). Continues R253 leaf-first migration.
/// R255 — deadline math also migrated to u64 ms (option (b) from
/// R254 carry); `std::time::Instant` is no longer referenced in this
/// function.
/// R311y345 — `--publish-after-ms`: hold the burst for `<ms>` AFTER Established,
/// leaving the session deliberately IDLE. It exists so a foreign peer can
/// witness `transport-keepalive`: a zenoh peer expires a silent line after the
/// adopted lease, so a Push that still lands beyond it proves wz's KeepAlive
/// held the session open — and the peer's own lease timer, not any wz assertion,
/// is the thing that would have failed. No other demo knob can produce that
/// ordering: the default burst fires immediately (5 x 200ms) and `--reconnect`'s
/// long-lived mode publishes on a cadence, so neither is ever idle.
///
/// Deliberately NOT cfg-gated on `transport-keepalive`. It is a pure ordering
/// delay -- inert when the feature is off, and it MUST stay inert, because the
/// keepalive-OFF build is exactly the anti-vacuity arm the proof rests on: it
/// has to reach the same code path and lose the session.
pub(crate) async fn publisher_task<T>(
    session: TokioSession,
    spec: PublisherSpec,
    clock: T,
    long_lived: bool,
) where
    T: TimeSource + Send + 'static,
{
    // Destructured once, here: the task body below predates the spec struct and
    // reads these as locals. Taking the bundle rather than eight positional
    // arguments is also what keeps two `Option<u64>` from sitting side by side
    // at the call site.
    let PublisherSpec {
        keyexpr,
        operation,
        declare_id,
        publish_after_ms,
        batch,
        // `--matching-log` is consumed by install_session_handles, PRE-DRIVE and
        // at run_demo scope: the listener has to outlive this task's burst to
        // witness the remote's Undeclare. Named-and-ignored rather than dropped
        // from the bundle, so a future field cannot silently land in this task.
        matching_log: _,
    } = spec;
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
    // R311y345 — the deliberate idle window. It sits AFTER the Established gate
    // and BEFORE the burst, so the line is silent for exactly `<ms>` while both
    // peers' lease timers run. The log line is the test's observation point for
    // "the idle actually happened" -- without it a burst that fired early would
    // still look like a pass.
    if let Some(ms) = publish_after_ms {
        log::info!(
            "wz-ap-demo: publisher_task holding the burst {ms}ms after Established \
             (--publish-after-ms); the session is idle for this window"
        );
        clock.sleep(ms).await;
        log::info!("wz-ap-demo: publisher_task idle window elapsed; emitting now");
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

    // ── Long-lived (reconnect) periodic publisher: re-arm emission across
    //           reconnects so a peer the supervisor re-dials after a sever
    //           observes FRESH Pushes (DATA-plane continuity — the actual point
    //           of a long-lived `--reconnect` client), not only the replayed
    //           declarations (control plane). Each cycle (re-)waits for
    //           Established (a reconnect window can exceed one poll), emits one
    //           Push, then pauses one cadence; a publish inside the reconnect
    //           window rejects `TransportUnavailable` and is skipped, and the
    //           next cycle resumes once the supervisor re-establishes. The loop
    //           stops on the SAME graceful-shutdown signal the drive loop races,
    //           so the publisher's `session` clone drops BEFORE run_demo's
    //           teardown drops `actions` — preserving the writer last-sender
    //           invariant (crate::teardown). The default (non-reconnect) path
    //           runs the finite burst below instead.
    if long_lived {
        log::info!(
            "wz-ap-demo: publisher_task entering long-lived periodic mode (--reconnect); \
             re-arms per (re)Established, stops on graceful-shutdown signal"
        );
        let shutdown = crate::shutdown::shutdown_signal();
        tokio::pin!(shutdown);
        let mut declared = false;
        let mut idx = 0usize;
        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown => {
                    log::info!(
                        "wz-ap-demo: publisher_task stopping on graceful-shutdown signal \
                         after {idx} long-lived emit(s)"
                    );
                    break;
                }
                () = publish_cycle(
                    &session, &keyexpr, &operation, declare_id, &mut declared, idx, &clock,
                ) => {
                    idx += 1;
                }
            }
        }
        return;
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

    // ── R311y345 — `--batch`: open a TX batching window around the burst
    //           (`zp_start_batching` parity). Every send is then ABSORBED into
    //           one open T_MID_FRAME until the flush below, so the burst's
    //           `PUBLISHER_BURST_COUNT` Pushes ride ONE frame as a message
    //           chain rather than one frame each. The cadence between them is
    //           irrelevant while the window is open — nothing drains the buffer
    //           but a flush, a conduit change, or an MTU overflow.
    //
    //           That absorption is what makes the foreign proof possible AND
    //           what makes it honest: with the window open the burst CANNOT go
    //           out as separate frames, so a peer that surfaces every Push has
    //           necessarily walked a multi-message frame to its end. The two log
    //           lines are the test's evidence that the window really covered the
    //           burst -- without them a green would not distinguish this from
    //           the ordinary one-frame-per-Push path.
    if batch {
        match actions.batch_start() {
            Ok(()) => log::info!(
                "wz-ap-demo: publisher_task opened a TX batch window (--batch); \
                 the next {PUBLISHER_BURST_COUNT} Pushes ride ONE frame"
            ),
            Err(e) => {
                log::warn!("wz-ap-demo: --batch rejected: {e}");
                return;
            }
        }
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
        emit_one_push(&session, &keyexpr, &operation, declare_id, i);
        // Cadence pause between emissions (not after the last
        // one — the run_demo cleanup gives the writer a brief
        // drain window).
        if i + 1 < PUBLISHER_BURST_COUNT {
            clock.sleep(PUBLISHER_BURST_INTERVAL_MS).await;
        }
    }
    // R311y345 — close the window and drain (`zp_batch_stop` parity). Until this
    // returns, NOTHING of the burst has reached the wire: it is all sitting in
    // the one open frame. Stop rather than flush, because the burst is over and
    // an open window would then absorb the teardown's own emits.
    if batch {
        match actions.batch_stop() {
            Ok(()) => log::info!(
                "wz-ap-demo: publisher_task closed the TX batch window; \
                 {PUBLISHER_BURST_COUNT} Pushes flushed as ONE frame"
            ),
            Err(e) => log::warn!("wz-ap-demo: batch_stop rejected: {e}"),
        }
    }
    log::info!("wz-ap-demo: publisher_task finished emission burst");
}

/// R311q1 — emit ONE Push (Put or Del; literal or DECLARE-aliased) on the
/// publisher's keyexpr and log the outcome. Extracted so the finite one-shot
/// burst and the long-lived (reconnect) periodic loop dispatch through ONE
/// site — in particular the four `PublishAliasError` arms (an earlier round
/// duplicated this match in each loop). `idx` is the per-emission counter the
/// log surfaces (burst index in one-shot mode, cumulative cycle count in
/// long-lived mode).
fn emit_one_push(
    session: &TokioSession,
    keyexpr: &str,
    operation: &PushOperation,
    declare_id: Option<u64>,
    idx: usize,
) {
    let mut opts = PublishOptions::default().with_reliability(Reliability::Reliable);
    let (kind_tag, payload): (&str, &[u8]) = match operation {
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
            .publish(keyexpr, payload, opts)
            .map(|fired| (fired, "literal"))
            .map_err(PublishAliasError::from),
    };
    match dispatch_outcome {
        Ok((loopback_fired, mode)) => {
            log::info!(
                "wz-ap-demo: PUBLISHER EMITTED kind={kind_tag} mode={mode} \
                 keyexpr='{keyexpr}' declare_id={declare_id:?} payload_len={payload_len} \
                 idx={idx} loopback_fired={loopback_fired}",
                payload_len = payload.len(),
            );
        }
        Err(PublishAliasError::UnknownMapping(id)) => {
            // R234 contract: the aliased path requires a prior
            // `send_declare_keyexpr`; an UnknownMapping means the mapping was
            // never registered (caller wiring bug) or was retracted / lost on a
            // reconnect (the per-connection keyexpr table is not in the
            // declaration-replay set). Log hard and skip so emission continues.
            log::error!(
                "wz-ap-demo: publisher_task UnknownMapping id={id} on idx={idx} — \
                 declare-before-publish contract violated; skipping this iteration"
            );
        }
        // W3 — the publish build can reject when caller data overflows the
        // declared codec capacity (a no-emit reject); log and skip.
        Err(e @ PublishAliasError::ExceedsCapacity) => {
            log::error!(
                "wz-ap-demo: publisher_task publish rejected on idx={idx}: {e}; \
                 skipping this iteration"
            );
        }
        // F2 — a publish inside a reconnect window rejects typed (transport gate
        // closed until Established re-entry); log and skip — the next cycle
        // succeeds once the supervisor re-establishes. In long-lived mode this
        // arm is the EXPECTED path during a sever, not an error.
        Err(e @ PublishAliasError::TransportUnavailable) => {
            log::warn!(
                "wz-ap-demo: publisher_task publish rejected on idx={idx}: {e}; \
                 skipping this iteration (reconnect window — the next cycle \
                 retries once the supervisor re-establishes)"
            );
        }
        // B5b-2b / R311nf — an aliased publish on a non-unicast transport
        // rejects typed. `publisher_task` takes a `TokioSession` (=
        // `Session<_,_,Unicast>`), so a multicast transport is excluded at the
        // type level and this arm is unreachable in the demo; the exhaustive
        // match keeps it, logged + skipped uniformly.
        Err(e @ PublishAliasError::RequiresUnicast) => {
            log::warn!(
                "wz-ap-demo: publisher_task publish rejected on idx={idx}: {e}; \
                 skipping this iteration"
            );
        }
    }
}

/// R311q1 — one long-lived publish cycle for the reconnect periodic publisher:
/// (re-)wait for Established (the reconnect window may exceed one poll), then
/// emit one Push + a cadence pause. Returning per cycle lets the caller's
/// `select!` interleave the graceful-shutdown arm between cycles AND cancel
/// mid-cycle (the future is dropped at a sleep `.await`, cancel-safe — the emit
/// itself is synchronous, never half-sent). When `--declare-id` is supplied the
/// aliased keyexpr mapping is declared once on first Established (`declared`) and
/// re-sent on any post-reconnect face by the `session-reconnect` declaration
/// replay set (`replay_declarations`), so the aliased path survives a reconnect;
/// the demo's DEFAULT reconnect showcase passes no `--declare-id`
/// (`declare_id = None` -> literal path).
async fn publish_cycle<T>(
    session: &TokioSession,
    keyexpr: &str,
    operation: &PushOperation,
    declare_id: Option<u64>,
    declared: &mut bool,
    idx: usize,
    clock: &T,
) where
    T: TimeSource,
{
    while !session.actions().is_established() {
        clock.sleep(PUBLISHER_HANDSHAKE_POLL_INTERVAL_MS).await;
    }
    if let Some(mapping_id) = declare_id {
        if !*declared {
            if session
                .actions()
                .send_declare_keyexpr(mapping_id, keyexpr)
                .is_ok()
            {
                *declared = true;
            }
            clock.sleep(PUBLISHER_BURST_INTERVAL_MS).await;
        }
    }
    emit_one_push(session, keyexpr, operation, declare_id, idx);
    clock.sleep(PUBLISHER_BURST_INTERVAL_MS).await;
}
