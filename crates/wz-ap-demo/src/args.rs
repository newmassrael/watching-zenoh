// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// wz-ap-demo — CLI argument parsing + spec-type bundles.
//
// R285 — extracted from `main.rs` as part of Phase 1 module
// decomposition (the R281 carry). Pure code-move, no behaviour
// change. Holds:
//
//   * `Role` — `--listen` vs `--connect` discriminator;
//   * `PushOperation` — publisher_task dispatch shape (Put vs Del);
//   * `parse_pair` — argv lookup helper used by `main`;
//   * `demo_session_init_params` — role-conditional zenoh-pico
//     interop parameter block (per-role `whatami`, version,
//     resolutions, etc.);
//   * Four spec bundles (`DeclareEmitSpec`, `RemoteLogSpec`,
//     `ReplyConsumerSpec`, `QueryRoleSpec`) that ferry argv-derived
//     state from `main` into `run_demo` without inflating the
//     latter's argument list past clippy::too_many_arguments.

use wz::runtime_tokio::session_glue::{SessionInitParams, SigningKey};

/// R121f — session role select. `--listen` lands here as
/// `Acceptor`; `--connect` lands as `Initiator`. The two roles
/// drive different role-start FSM events (`InboundStart` vs
/// `OutboundStart` + `LinkOpened`) and different TCP setup
/// paths (bind+accept vs dial), but share the rest of the
/// session-FSM + outbound-publisher + inbound-subscriber wiring.
pub(crate) enum Role {
    Acceptor { listen: String },
    Initiator { connect: String },
}

/// R219 — publisher-task operation kind. `Put` carries the
/// application payload (`--value <text>`); `Delete` is payload-
/// less (zenoh-pico's `z_delete` wire form: `MsgDel` body, no
/// `payload_len`/`payload` fields). The same publisher_task drives
/// both shapes — Established-gating, optional `DECLARE` preamble,
/// and the BURST_COUNT emission loop are invariant; only the
/// inner action call (`send_push_literal`/`_aliased` vs
/// `send_push_del_literal`/`_aliased`) differs at the dispatch
/// site.
#[derive(Clone, Debug)]
pub(crate) enum PushOperation {
    Put { value: String },
    Delete,
}

pub(crate) fn parse_pair(args: &[String], flag: &str) -> Option<String> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == flag {
            return it.next().cloned();
        }
    }
    None
}

// R121d interop-tuned session params. Values aligned to
// zenoh-pico 1.5.0 defaults so the AP demo can complete a real
// session handshake against `z_put -m client`:
//
//   - `version = 0x09` matches `Z_PROTO_VERSION` in
//     zenoh-pico/include/zenoh-pico/config.h.in:190. The earlier
//     0x05 value (carried from the R121b MVP) was tolerated by
//     unicast but is one revision behind; matching the upstream
//     constant is the textbook interop default.
//   - `seq_num_res = 2` / `req_id_res = 2` match
//     `Z_SN_RESOLUTION` / `Z_REQ_RESOLUTION` (both 0x02) in the
//     same config header. The earlier `0` value resolved to an
//     8-bit SN window (`_z_sn_max(0) = 127`,
//     zenoh-pico/src/transport/utils.c:24-29), which would have
//     wrapped sequence numbers within a few frames.
//   - `batch_size = 65535` lets zenoh-pico cap to its own
//     `Z_BATCH_UNICAST_SIZE` (2048 in the bundled CLI build per
//     target/zenoh-pico-build/CMakeCache.txt). The earlier `0`
//     value crashed zenoh-pico inside `__unsafe_z_prepare_wbuf`
//     because the negotiation in
//     zenoh-pico/src/transport/unicast/transport.c:135-136
//     takes `min(own, peer)` and a zero-sized wbuf segfaults on
//     the first `_z_wbuf_put` (this was the R121d immediate
//     crash root cause).
//
// R121f — `whatami` is now role-conditional. zenoh-pico's
// production-tested handshake pattern is `Client → Peer/Router`
// (e.g. `z_put -m client` → wz-ap-demo --listen), AND `Peer →
// Peer-with-listen-locator` is fragile in zenoh-pico 1.5.0
// without prior multicast scouting (peer-peer over unicast TCP
// only is not the well-trodden path upstream). The R121f
// initiator path therefore announces `Client` (wire whatami =
// `(0x04 >> 1) & 0x03 = 0x02`) so a zenoh-pico
// `-m peer -l <locator>` listener accepts it via the same
// well-tested code path that R121c/d exercised in reverse
// (`z_put -m client` → wz acceptor).
//
// The acceptor side keeps `whatami = Peer (0x02)` from R121b/c/d
// — the existing R121c/e tests rely on this. Splitting the
// constant on role honours both directions.
//
// `lease = 10s`, `zid = 4-byte demo constant` carry from R121b
// unchanged. Production AP deployment will source these from
// deploy.yaml once the topology-schema migration (R123b-pre
// carry) lands.
pub(crate) fn demo_session_init_params(role: &Role) -> SessionInitParams {
    let whatami_api = match role {
        Role::Acceptor { .. } => 0x02,  // Peer — R121b/c/d/e baseline
        Role::Initiator { .. } => 0x04, // Client — R121f initiator path
    };
    SessionInitParams {
        version: 0x09,
        whatami: whatami_api,
        zid: vec![0x01, 0x02, 0x03, 0x04],
        seq_num_res: 2,
        req_id_res: 2,
        batch_size: 65535,
        lease: 10_000,
        lease_in_seconds: false,
        initial_sn: 0,
        cookie: Vec::new(),
        // Demo signing key — 32 bytes of 0xAB. Production deployment
        // MUST supply real per-process entropy via
        // `SigningKey::new_random()` once deploy.yaml carries the
        // cookie_signing_key source.
        cookie_signing_key: SigningKey::new(vec![0xAB; 32])
            .expect("32-byte demo key satisfies >= 32 invariant"),
    }
}

/// R121k-5 — bundle of `--declare-subscriber/queryable/token`
/// keyexprs the demo emits once the session reaches Established.
/// Each `Option<String>` is the keyexpr literal; the id is hard-coded
/// to a per-kind sentinel (1001 / 2001 / 3001) so a paired
/// integration test can assert on the wire shape without an extra
/// CLI knob. Production deployments source ids from a per-session
/// counter the same way as send_declare_keyexpr / publisher mapping.
pub(crate) struct DeclareEmitSpec {
    pub(crate) subscriber_keyexpr: Option<String>,
    pub(crate) queryable_keyexpr: Option<String>,
    pub(crate) token_keyexpr: Option<String>,
    /// R280 — optional `--liveliness-subscribe <keyexpr>` payload.
    /// When `Some`, the demo calls
    /// [`wz::runtime_tokio::session::Session::declare_liveliness_subscriber`]
    /// once before the drive_session loop starts; the returned RAII
    /// handle lives at `run_demo` scope so `Drop` emits
    /// `Interest(Final)` when the demo terminates. Separate from
    /// `token_keyexpr` (which declares a
    /// [`wz::runtime_tokio::session::LivelinessToken`] on the
    /// peer-facing side) because a single demo instance can act as
    /// token publisher + token subscriber simultaneously on a wz↔wz
    /// round-trip.
    pub(crate) liveliness_subscriber_keyexpr: Option<String>,
}

/// R121k-5 — bool flag bundle for the three Remote* registry log
/// callbacks. Each `true` installs a callback that prints a
/// stderr line on the matching inbound Declare arm so an integration
/// test fixture can grep for the expected line shape.
pub(crate) struct RemoteLogSpec {
    pub(crate) on_remote_subscriber: bool,
    pub(crate) on_remote_queryable: bool,
    pub(crate) on_remote_liveliness: bool,
}

/// R121j-6-e2e — bool flag bundle for the initiator-side
/// ReplyRegistry log callbacks. Both flags require --query (the rid
/// the registry binds to is the rid of the outbound Query this demo
/// emits); the validation in `main` rejects mis-wired argv before
/// this struct is constructed. Each `true` installs a callback that
/// prints a stderr line on the matching inbound record so an
/// integration test fixture can grep for the expected line shape.
pub(crate) struct ReplyConsumerSpec {
    pub(crate) on_query_reply: bool,
    pub(crate) on_query_final: bool,
    /// R263 — pending-entry deadline (ms) propagated to the
    /// observer.replies.register call below. Value 0 means "no
    /// timeout" (deadline_ms = None at register; pre-R263 behaviour
    /// preserved). Value > 0 means "compute deadline_ms =
    /// session_clock.now_monotonic_ms() + query_timeout_ms" so the
    /// R264 sweep_task surfaces on_final within that wall-clock
    /// budget when no Final arrives.
    pub(crate) query_timeout_ms: u32,
    /// R270 — sweep_task tick period (ms). Lower values tighten
    /// the bound on `on_final`'s post-deadline wall-time at the cost
    /// of more wake-ups. Must be > 0 (the main-side parser rejects
    /// 0 explicitly so this struct field can stay an unwrapped u32).
    /// The pre-R270 hardcoded value (100 ms) is the default the
    /// parser supplies when `--sweep-cadence-ms` is absent, so
    /// every existing wz-ap-demo invocation retains identical
    /// behaviour.
    pub(crate) sweep_cadence_ms: u32,
}

/// R121j-6-e2e — bundle of the Q/R role config. Carries the
/// queryable side (--queryable + --reply pair) and the z_get side
/// (--query) so a single demo can act as queryable, z_get, both, or
/// neither. Kept distinct from the publisher / subscriber / declare
/// configs because the wire-side dispatch tables (QueryableRegistry,
/// ReplyRegistry) live in a different module than the pubsub one.
/// R121j-5c-e2e-demo carried (--queryable, --reply, --query) on
/// separate run_demo parameters; R121j-6-e2e consolidates them so
/// run_demo's clippy::too_many_arguments threshold stays satisfied
/// with the new reply_log_spec.
pub(crate) struct QueryRoleSpec {
    pub(crate) queryable: Option<(String, String)>,
    pub(crate) query: Option<String>,
}
