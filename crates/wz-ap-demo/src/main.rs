// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// wz-ap-demo — AP MVP demo binary entry point.
//
// R121b: functional round. Wires the session FSM + DECLARE
// subscriber + msg_put inbound dispatch end-to-end against an
// external zenoh-pico peer over real TCP.
//
// R121e (this round): bidirectional pubsub. Adds publisher-side
// emission so the binary can drive zenoh-pico's `z_sub` (in
// addition to the R121b/c/d subscriber-side reception that
// already round-trips against `z_put`). The publisher path
// composes the existing wz-codecs `Push` + `Frame` envelopes via
// `wz_runtime_tokio::session_glue::{build_push_literal,
// encode_frame_with_push}` and dispatches through the same
// `OutboundWriteDriver` mpsc channel that the FSM script-actions
// use for the handshake outbound — no nested `block_on` (R121d
// constraint preserved).
//
// CLI shape (R121b base, R121e --publish/--value, R121f --connect):
//
//   wz-ap-demo (--listen <addr> | --connect <addr>)
//              [--key <keyexpr>]
//              [--publish <keyexpr> --value <text>]
//
//   --listen   server-side TCP bind address (acceptor mode;
//              e.g. 127.0.0.1:7447). Binds + accepts one peer,
//              then drives the session FSM with `InboundStart`.
//   --connect  remote TCP peer address (initiator mode;
//              e.g. 127.0.0.1:7447). Dials the peer, then drives
//              the session FSM with `OutboundStart` + `LinkOpened`
//              so wz emits the first `InitSyn` and walks the
//              4-way handshake from the dialing side.
//              Exactly one of --listen / --connect is required;
//              the two modes are mutually exclusive (a single
//              demo invocation acts as either acceptor OR
//              initiator, never both).
//   --key      DECLARE subscriber keyexpr (e.g. demo/example).
//              Each Push whose keyexpr matches this pattern fires
//              the demo callback (prints to stderr).
//              Optional — when omitted, no subscriber callback is
//              registered and inbound Pushes are silently dropped.
//   --publish  Publisher keyexpr literal (e.g. demo/test).
//              When present, the demo spawns a publisher task that
//              waits for the session FSM to reach Established
//              (role-agnostic `record_established_at` counter,
//              fires on both acceptor and initiator sides), then
//              emits N copies of the Push at a fixed cadence so a
//              z_sub peer can observe one (z_sub uses
//              `while(1) sleep(1)` so any single copy is enough;
//              the multi-copy emission absorbs tail-latency /
//              declare-subscriber timing variance).
//              Requires --value.
//   --value    Publisher payload text. Required when --publish is
//              present; ignored otherwise.
//
// At least one of {--key, --publish} must be supplied — running
// the demo with neither makes the session FSM advance but
// generates no observable AP-layer behaviour.
//
// Bidirectional TCP wiring (the architecturally non-trivial bit):
//
//   `drive_session_until_terminal` borrows the inbound driver as
//   `&mut LinkDriver` while `SessionLinkActions` holds the outbound
//   driver as `Arc<dyn BoxedLinkDriver>`. A single TcpStream cannot
//   satisfy both shapes simultaneously, so the demo splits the
//   accepted TcpStream into owned read + write halves (Tokio's
//   `TcpStream::into_split`) and threads them as two cooperating
//   drivers:
//
//     InboundReadDriver { reader: OwnedReadHalf }
//       impls `LinkDriver` — `poll_event` reads one Zenoh stream
//       envelope (u16 LE length prefix + payload), `send`/`open`/
//       `close` are no-ops (the inbound side never emits outbound
//       bytes).
//
//     OutboundWriteDriver { tx: mpsc::UnboundedSender<Vec<u8>> }
//       impls `BoxedLinkDriver` — `send_blocking` enqueues the
//       transport-message bytes onto an unbounded mpsc channel.
//       A dedicated async **writer task** (spawned in
//       `run_demo`) owns the `OwnedWriteHalf` and drains the
//       channel, writing the Zenoh stream envelope (u16 LE length
//       prefix + payload) for each enqueued frame. This avoids
//       the `Handle::block_on` reentrancy panic that would fire if
//       `send_blocking` blocked on async TCP writes from a future
//       being driven by the same runtime — `drive_session_until_
//       terminal` polls inbound asynchronously, then the FSM's
//       script-action handlers (e.g. `send_init_ack_with_cookie`)
//       fire synchronously on the same task; nested `block_on` is
//       not permitted. The channel is the textbook decoupling.
//       Channel-send is sync + non-blocking; the writer task
//       handles flush + ordering. Frame ordering is preserved
//       because there is exactly one writer task per outbound
//       channel.
//
//   Both halves wrap the same TcpStream so peer reads see what we
//   send and peer writes reach our poll_event. The split lets each
//   side own its half exclusively, satisfying both the `&mut
//   LinkDriver` and `Arc<dyn BoxedLinkDriver>` shape constraints.

use std::env;
use std::io;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sce_rust_lua::LuaEngine;
use sce_rust_runtime::{Engine, IScriptEngine};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use wz_runtime_tokio::observer::ApplicationLayerObserver;
use wz_runtime_tokio::reply::InboundReplyBody;
use wz_runtime_tokio::sample::SampleKind;
use wz_runtime_tokio::session::{PublishAliasError, PublishOptions, Session};
use wz_runtime_tokio::session_fsm_unicast::SessionFsmUnicastPolicy;
use wz_runtime_tokio::session_glue::{
    drive_session_until_terminal, install_session_actions, BoxedLinkDriver, IterationEvent,
    SessionInitParams, SessionLinkActions, SigningKey,
};
use wz_runtime_tokio::{LinkDriver, LinkEvent, LostCause, Reliability, RxFrame, TxFrame};

const ABOUT: &str = concat!(
    "wz-ap-demo ",
    env!("CARGO_PKG_VERSION"),
    " — AP MVP demo binary",
);

/// R121f — session role select. `--listen` lands here as
/// `Acceptor`; `--connect` lands as `Initiator`. The two roles
/// drive different role-start FSM events (`InboundStart` vs
/// `OutboundStart` + `LinkOpened`) and different TCP setup
/// paths (bind+accept vs dial), but share the rest of the
/// session-FSM + outbound-publisher + inbound-subscriber wiring.
enum Role {
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
enum PushOperation {
    Put { value: String },
    Delete,
}

fn print_usage() {
    eprintln!("{ABOUT}");
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("    wz-ap-demo (--listen <addr> | --connect <addr>)");
    eprintln!("               [--key <keyexpr>]");
    eprintln!("               [--publish <keyexpr> --value <text>]");
    eprintln!("               [--delete <keyexpr>]");
    eprintln!("               [--queryable <keyexpr> --reply <text>]");
    eprintln!("               [--query <keyexpr>]");
    eprintln!("               [--declare-subscriber <keyexpr>]");
    eprintln!("               [--declare-queryable <keyexpr>]");
    eprintln!("               [--declare-token <keyexpr>]");
    eprintln!("               [--on-remote-subscriber-log]");
    eprintln!("               [--on-remote-queryable-log]");
    eprintln!("               [--on-remote-liveliness-log]");
    eprintln!("               [--on-query-reply-log]");
    eprintln!("               [--on-query-final-log]");
    eprintln!();
    eprintln!("OPTIONS:");
    eprintln!("    --listen <addr>          acceptor mode (e.g. 127.0.0.1:7447)");
    eprintln!("    --connect <addr>         initiator mode (e.g. 127.0.0.1:7447)");
    eprintln!("    --key <keyexpr>          DECLARE subscriber keyexpr (e.g. demo/example)");
    eprintln!("    --publish <keyexpr>      publisher keyexpr literal (e.g. demo/test)");
    eprintln!("    --value <text>           publisher payload text (required with --publish)");
    eprintln!("    --delete <keyexpr>       delete-keyexpr publisher (R219 MsgDel body)");
    eprintln!("                             mutually exclusive with --publish; no --value");
    eprintln!("    --queryable <keyexpr>    register a queryable for the given pattern;");
    eprintln!("                             each inbound Request(Query) whose keyexpr matches");
    eprintln!("                             fires a callback that emits one Reply via --reply");
    eprintln!("    --reply <text>           reply payload for the registered queryable");
    eprintln!("                             (required with --queryable)");
    eprintln!("    --query <keyexpr>        send a single Request(Query) on this keyexpr");
    eprintln!("                             literal once the session reaches Established");
    eprintln!("    --declare-subscriber <keyexpr>");
    eprintln!("                             send a single Declare(DeclSubscriber) on this");
    eprintln!("                             keyexpr literal once the session reaches Established");
    eprintln!("    --declare-queryable <keyexpr>");
    eprintln!("                             send a single Declare(DeclQueryable) on this");
    eprintln!("                             keyexpr literal once the session reaches Established");
    eprintln!("    --declare-token <keyexpr>");
    eprintln!("                             send a single Declare(DeclToken) on this keyexpr");
    eprintln!("                             literal once the session reaches Established");
    eprintln!("    --on-remote-subscriber-log");
    eprintln!("                             install a RemoteSubscriberRegistry callback that");
    eprintln!("                             logs 'REMOTE SUBSCRIBER DECLARED' on inbound");
    eprintln!("                             Declare(DeclSubscriber); paired with");
    eprintln!("                             'REMOTE SUBSCRIBER UNDECLARED' on UndeclSubscriber");
    eprintln!("    --on-remote-queryable-log");
    eprintln!("                             liveliness-equivalent for the queryable side");
    eprintln!("    --on-remote-liveliness-log");
    eprintln!("                             liveliness-equivalent for the DeclToken side");
    eprintln!("    --on-query-reply-log     install a ReplyRegistry callback that logs");
    eprintln!("                             'REPLY RECEIVED' on each inbound");
    eprintln!("                             Response(Reply|Err) for the --query rid");
    eprintln!("                             (requires --query)");
    eprintln!("    --on-query-final-log     install a ReplyRegistry on_final callback that");
    eprintln!("                             logs 'FINAL RECEIVED' when the matching");
    eprintln!("                             ResponseFinal terminates the reply chain");
    eprintln!("                             (requires --query)");
    eprintln!("    --help, -h               print this help and exit");
    eprintln!();
    eprintln!("Exactly one of --listen / --connect is required.");
    eprintln!("At least one of --key / --publish / --delete / --queryable / --query / --declare-*");
    eprintln!("/ --on-remote-* must be supplied.");
}

fn parse_pair(args: &[String], flag: &str) -> Option<String> {
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
fn demo_session_init_params(role: &Role) -> SessionInitParams {
    let whatami_api = match role {
        Role::Acceptor { .. } => 0x02, // Peer — R121b/c/d/e baseline
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

/// Inbound half of the bidirectional split — owns the read half of
/// the accepted TcpStream and implements [`LinkDriver`] with
/// poll_event reading one Zenoh stream envelope (u16 LE length
/// prefix + payload, mirroring zenoh-pico's
/// `_z_link_recv_t_msg_cap_flow_stream`).
///
/// The send/open/close methods are no-ops because the inbound side
/// never emits outbound bytes — the FSM's outbound path is wired
/// through `OutboundWriteDriver` (`BoxedLinkDriver` shape) held by
/// `SessionLinkActions`.
struct InboundReadDriver {
    reader: OwnedReadHalf,
}

impl LinkDriver for InboundReadDriver {
    async fn open(&mut self) -> io::Result<()> {
        // Stream already opened by TcpListener::accept; the FSM's
        // outbound side calls open_blocking on OutboundWriteDriver
        // (which is also a no-op since accept established the
        // connection). Inbound open is therefore unconditionally Ok.
        Ok(())
    }

    async fn send(
        &mut self,
        _frame: &TxFrame<'_>,
        _reliability: Reliability,
    ) -> io::Result<()> {
        // Inbound driver never sends — the FSM's script-actions
        // dispatch outbound via the OutboundWriteDriver Arc captured
        // by SessionLinkActions. Surface as NotConnected so any
        // accidental invocation fails loud rather than silently
        // swallowing.
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "InboundReadDriver does not send; outbound goes via OutboundWriteDriver",
        ))
    }

    async fn close(&mut self) -> io::Result<()> {
        // Drop happens on the read half independently of the write
        // half close. No explicit shutdown needed.
        Ok(())
    }

    async fn poll_event(&mut self) -> LinkEvent {
        let mut len_buf = [0u8; 2];
        match self.reader.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return LinkEvent::Lost {
                    cause: LostCause::PeerClosed,
                };
            }
            Err(_) => {
                return LinkEvent::Lost {
                    cause: LostCause::OsError,
                };
            }
        }
        let len = u16::from_le_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        match self.reader.read_exact(&mut buf).await {
            Ok(_) => {
                log::debug!(
                    "wz-ap-demo: inbound frame len={} bytes={:02x?}",
                    len, buf
                );
                LinkEvent::Rx(RxFrame { bytes: buf })
            }
            Err(_) => LinkEvent::Lost {
                cause: LostCause::PeerClosed,
            },
        }
    }
}

/// Outbound half of the bidirectional split — holds an
/// `mpsc::UnboundedSender<Vec<u8>>` whose receiver is owned by a
/// dedicated writer task spawned in [`run_demo`]. Implements
/// [`BoxedLinkDriver`] so [`SessionLinkActions::new`]'s
/// `Arc<dyn BoxedLinkDriver>` slot is satisfied.
///
/// `send_blocking` enqueues the transport-message bytes
/// synchronously (channel send is non-blocking and has no
/// `block_on`), which is the architecturally required shape: the
/// FSM script-action handlers (e.g. `send_init_ack_with_cookie`)
/// fire from the synchronous portion of [`drive_session_until_terminal`],
/// and that loop is itself a future driven by the same Tokio
/// runtime. A `Handle::block_on` from inside such a future would
/// fail the "Cannot start a runtime from within a runtime"
/// reentrancy check; the channel decoupling keeps the
/// sync-from-async boundary clean.
///
/// Frame ordering is preserved because the channel is single-
/// producer-single-consumer in the demo (one Lua engine drives
/// one writer task) and `mpsc` preserves enqueue order.
struct OutboundWriteDriver {
    tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl BoxedLinkDriver for OutboundWriteDriver {
    fn send_blocking(&self, bytes: &[u8], _reliability: Reliability) {
        if bytes.len() > u16::MAX as usize {
            // Frame oversize: drop with a warn rather than overflow
            // the u16 length prefix. zenoh-pico's
            // `Z_BATCH_UNICAST_SIZE` ceiling is 65535, so a frame
            // larger than this is a wz-side encoder bug — surface
            // loudly.
            log::warn!(
                "wz-ap-demo: outbound frame {} bytes > 65535; dropping",
                bytes.len()
            );
            return;
        }
        if let Err(e) = self.tx.send(bytes.to_vec()) {
            log::warn!("wz-ap-demo: outbound channel closed; dropping frame ({e})");
        }
    }

    fn open_blocking(&self) {
        // TcpListener::accept already returned an established
        // stream; open is a no-op on this driver shape.
    }

    fn close_blocking(&self) {
        // The writer task is owned by `run_demo`'s scope and exits
        // when every Sender clone is dropped (after run_demo
        // returns). Explicit per-frame shutdown from the FSM's
        // `release_link` would race against in-flight enqueues;
        // letting the receiver-drop signal terminate the task is
        // the textbook channel idiom.
    }
}

/// Async writer task. Owns the [`OwnedWriteHalf`] and drains the
/// outbound channel one frame at a time, writing each frame's
/// Zenoh stream envelope (u16 LE length prefix + payload) and
/// flushing. Exits when every [`OutboundWriteDriver`] clone has
/// dropped (i.e. the receiver returns `None`) or when a write
/// fails (logged + bail).
async fn writer_task(
    mut writer: OwnedWriteHalf,
    mut rx: mpsc::UnboundedReceiver<Vec<u8>>,
) {
    while let Some(payload) = rx.recv().await {
        // Defensive: send_blocking already rejects oversize frames,
        // but assert here in case a future caller bypasses that
        // check.
        let len = match u16::try_from(payload.len()) {
            Ok(n) => n,
            Err(_) => {
                log::warn!(
                    "wz-ap-demo: writer_task received oversize frame ({} bytes); dropping",
                    payload.len()
                );
                continue;
            }
        };
        if let Err(e) = writer.write_all(&len.to_le_bytes()).await {
            log::warn!("wz-ap-demo: write length prefix failed: {e}; closing");
            return;
        }
        if let Err(e) = writer.write_all(&payload).await {
            log::warn!("wz-ap-demo: write payload failed: {e}; closing");
            return;
        }
        if let Err(e) = writer.flush().await {
            log::warn!("wz-ap-demo: flush failed: {e}; closing");
            return;
        }
    }
    // Channel closed → shut down the write half cleanly so the peer
    // observes EOF rather than RST.
    let _ = writer.shutdown().await;
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let rest = &args[1..];

    if rest.is_empty() || rest.iter().any(|a| a == "--help" || a == "-h") {
        print_usage();
        return ExitCode::SUCCESS;
    }

    // R121f — exactly one of --listen / --connect must be supplied.
    // The demo's session FSM role-start is hard-coded to one or
    // the other (Acceptor calls InboundStart on listen; Initiator
    // calls OutboundStart + LinkOpened on connect) — there is no
    // self-loopback configuration that would justify both.
    let listen_opt = parse_pair(rest, "--listen");
    let connect_opt = parse_pair(rest, "--connect");
    let role: Role = match (listen_opt, connect_opt) {
        (Some(addr), None) => Role::Acceptor { listen: addr },
        (None, Some(addr)) => Role::Initiator { connect: addr },
        (Some(_), Some(_)) => {
            eprintln!("wz-ap-demo: --listen and --connect are mutually exclusive");
            eprintln!();
            print_usage();
            return ExitCode::from(2);
        }
        (None, None) => {
            eprintln!("wz-ap-demo: exactly one of --listen / --connect is required");
            eprintln!();
            print_usage();
            return ExitCode::from(2);
        }
    };

    // R121e — the demo accepts subscriber-only, publisher-only,
    // OR both. The argument-validation matrix:
    //
    //   --key alone                       → subscriber mode (R121d).
    //   --publish + --value (no --key)    → publisher mode (R121e).
    //   --key + --publish + --value       → bidirectional mode
    //                                       (useful for loopback /
    //                                       echo scenarios).
    //   none of the above                 → reject (exit 2) — running
    //                                       the demo with no AP-layer
    //                                       behaviour does nothing
    //                                       observable.
    //   --publish without --value         → reject (exit 2) — the
    //                                       payload is mandatory once
    //                                       a publisher key is set.
    let key_opt = parse_pair(rest, "--key");
    let publish_opt = parse_pair(rest, "--publish");
    let value_opt = parse_pair(rest, "--value");
    // R219 — `--delete <keyexpr>` opts the demo into the
    // delete-keyexpr publisher mode: each burst tick emits a
    // `Frame[Push(MsgDel)]` instead of `Frame[Push(MsgPut(payload))]`.
    // Mutually exclusive with --publish (the two are distinct
    // application semantics; a publisher emits either Puts or
    // Deletes, not both, on a single run).
    let delete_opt = parse_pair(rest, "--delete");
    // R121g — `--declare-id <N>` opts the publisher into the
    // DECLARE-aliased path: send one `Declare(DeclKexpr(N, suffix))`
    // before the burst, then emit aliased Pushes carrying only
    // `id=N`. Defaults to None (literal-keyexpr path, R121e shape).
    // R219 — meaningful when EITHER --publish OR --delete is set.
    let declare_id_opt = parse_pair(rest, "--declare-id");
    // R121j-5c-e2e-demo — queryable / query CLI surface.
    // --queryable + --reply registers an inbound Request(Query) callback
    // that emits one Put-form Reply with the --reply payload. --query
    // emits a single outbound Request(Query) on the given keyexpr once
    // the session reaches Established (mirror of --publish timing
    // gate). Both are independent of --key / --publish; one demo
    // instance can act simultaneously as publisher + queryable + query
    // emitter if the corresponding argv combination is supplied.
    let queryable_opt = parse_pair(rest, "--queryable");
    let reply_opt = parse_pair(rest, "--reply");
    let query_opt = parse_pair(rest, "--query");
    // R121k-5 — declare emit + remote-declare callback CLI surface.
    let declare_subscriber_opt = parse_pair(rest, "--declare-subscriber");
    let declare_queryable_opt = parse_pair(rest, "--declare-queryable");
    let declare_token_opt = parse_pair(rest, "--declare-token");
    let on_remote_sub_log = rest.iter().any(|a| a == "--on-remote-subscriber-log");
    let on_remote_q_log = rest.iter().any(|a| a == "--on-remote-queryable-log");
    let on_remote_l_log = rest.iter().any(|a| a == "--on-remote-liveliness-log");
    // R121j-6-e2e — initiator-side ReplyRegistry log flags. Both
    // require --query (the rid is bound to the outbound Query the
    // demo emits; without that there is no z_get to consume replies
    // for). Reject explicitly so a mis-wired argv (`--on-query-reply-log`
    // on a queryable-side process) surfaces here rather than silently
    // installing an unreachable callback.
    let on_query_reply_log = rest.iter().any(|a| a == "--on-query-reply-log");
    let on_query_final_log = rest.iter().any(|a| a == "--on-query-final-log");
    if key_opt.is_none()
        && publish_opt.is_none()
        && delete_opt.is_none()
        && queryable_opt.is_none()
        && query_opt.is_none()
        && declare_subscriber_opt.is_none()
        && declare_queryable_opt.is_none()
        && declare_token_opt.is_none()
        && !on_remote_sub_log
        && !on_remote_q_log
        && !on_remote_l_log
    {
        eprintln!(
            "wz-ap-demo: at least one of --key / --publish / --delete / --queryable / --query / \
             --declare-* / --on-remote-* must be supplied",
        );
        eprintln!();
        print_usage();
        return ExitCode::from(2);
    }
    if publish_opt.is_some() && value_opt.is_none() {
        eprintln!("wz-ap-demo: --publish requires --value");
        eprintln!();
        print_usage();
        return ExitCode::from(2);
    }
    if publish_opt.is_none() && value_opt.is_some() {
        eprintln!("wz-ap-demo: --value is only meaningful with --publish (rejected to surface mis-wired argv)");
        eprintln!();
        print_usage();
        return ExitCode::from(2);
    }
    // R219 — --delete and --publish are distinct publisher modes; a
    // single run emits either Puts (Put payloads via --value) or
    // Deletes (no payload). Mixing both on one run does not match
    // any real-world application surface and would complicate
    // publisher_task's dispatch — reject explicitly here.
    if publish_opt.is_some() && delete_opt.is_some() {
        eprintln!("wz-ap-demo: --publish and --delete are mutually exclusive (pick one publisher mode per run)");
        eprintln!();
        print_usage();
        return ExitCode::from(2);
    }
    if delete_opt.is_some() && value_opt.is_some() {
        eprintln!("wz-ap-demo: --delete does not accept --value (MsgDel carries no payload — rejected to surface mis-wired argv)");
        eprintln!();
        print_usage();
        return ExitCode::from(2);
    }
    if declare_id_opt.is_some() && publish_opt.is_none() && delete_opt.is_none() {
        eprintln!("wz-ap-demo: --declare-id is only meaningful with --publish or --delete");
        eprintln!();
        print_usage();
        return ExitCode::from(2);
    }
    if queryable_opt.is_some() && reply_opt.is_none() {
        eprintln!("wz-ap-demo: --queryable requires --reply");
        eprintln!();
        print_usage();
        return ExitCode::from(2);
    }
    if queryable_opt.is_none() && reply_opt.is_some() {
        eprintln!(
            "wz-ap-demo: --reply is only meaningful with --queryable (rejected to surface mis-wired argv)",
        );
        eprintln!();
        print_usage();
        return ExitCode::from(2);
    }
    if (on_query_reply_log || on_query_final_log) && query_opt.is_none() {
        eprintln!(
            "wz-ap-demo: --on-query-reply-log / --on-query-final-log require --query \
             (the ReplyRegistry binds to the rid of the outbound Query this demo emits)",
        );
        eprintln!();
        print_usage();
        return ExitCode::from(2);
    }
    let declare_id_parsed: Option<u64> = match declare_id_opt {
        Some(s) => match s.parse::<u64>() {
            Ok(0) => {
                eprintln!("wz-ap-demo: --declare-id must be non-zero (0 is the literal-keyexpr sentinel)");
                return ExitCode::from(2);
            }
            Ok(n) => Some(n),
            Err(e) => {
                eprintln!("wz-ap-demo: --declare-id must be a positive integer ({e})");
                return ExitCode::from(2);
            }
        },
        None => None,
    };
    // R219 — publisher_spec carries both Put and Delete modes through
    // a single channel into publisher_task. Put requires --value
    // (validated above); Delete carries no payload.
    let publisher_spec: Option<(String, PushOperation, Option<u64>)> =
        match (publish_opt, value_opt, delete_opt) {
            (Some(k), Some(v), None) => {
                Some((k, PushOperation::Put { value: v }, declare_id_parsed))
            }
            (None, None, Some(k)) => Some((k, PushOperation::Delete, declare_id_parsed)),
            _ => None,
        };
    let queryable_spec: Option<(String, String)> = match (queryable_opt, reply_opt) {
        (Some(p), Some(r)) => Some((p, r)),
        _ => None,
    };
    let query_spec: Option<String> = query_opt;

    // env_logger reads RUST_LOG (defaults to off). The integration
    // test fixture (R121c) sets RUST_LOG=info to surface subscriber-
    // dispatch / session-FSM transitions in the child stderr capture.
    env_logger::Builder::from_env(env_logger::Env::default().filter_or("RUST_LOG", "info"))
        .init();

    eprintln!("{ABOUT}");
    match &role {
        Role::Acceptor { listen } => log::info!("listen  = {listen}"),
        Role::Initiator { connect } => log::info!("connect = {connect}"),
    }
    if let Some(k) = &key_opt {
        log::info!("key     = {k}");
    }
    if let Some((k, op, id)) = &publisher_spec {
        match op {
            PushOperation::Put { value } => {
                log::info!("publish = {k}");
                log::info!("value   = {value}");
            }
            PushOperation::Delete => {
                log::info!("delete  = {k} (R219 Del-mode, no payload)");
            }
        }
        if let Some(n) = id {
            log::info!("declare-id = {n} (R121g DECLARE-aliased mode)");
        }
    }
    if let Some((p, r)) = &queryable_spec {
        log::info!("queryable = {p}");
        log::info!("reply     = {r}");
    }
    if let Some(q) = &query_spec {
        log::info!("query   = {q}");
    }
    if let Some(d) = &declare_subscriber_opt {
        log::info!("declare-subscriber = {d}");
    }
    if let Some(d) = &declare_queryable_opt {
        log::info!("declare-queryable = {d}");
    }
    if let Some(d) = &declare_token_opt {
        log::info!("declare-token = {d}");
    }
    if on_remote_sub_log {
        log::info!("on-remote-subscriber-log = true");
    }
    if on_remote_q_log {
        log::info!("on-remote-queryable-log = true");
    }
    if on_remote_l_log {
        log::info!("on-remote-liveliness-log = true");
    }
    if on_query_reply_log {
        log::info!("on-query-reply-log = true");
    }
    if on_query_final_log {
        log::info!("on-query-final-log = true");
    }

    // Build the multi-thread runtime explicitly — OutboundWriteDriver
    // (mirroring TokioLinkDriverAdapter's contract) requires this
    // flavor so block_on doesn't deadlock on the current-thread
    // worker.
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_io()
        .enable_time()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("wz-ap-demo: tokio runtime build failed: {e}");
            return ExitCode::from(1);
        }
    };

    let declare_spec = DeclareEmitSpec {
        subscriber_keyexpr: declare_subscriber_opt,
        queryable_keyexpr: declare_queryable_opt,
        token_keyexpr: declare_token_opt,
    };
    let remote_log_spec = RemoteLogSpec {
        on_remote_subscriber: on_remote_sub_log,
        on_remote_queryable: on_remote_q_log,
        on_remote_liveliness: on_remote_l_log,
    };
    let reply_log_spec = ReplyConsumerSpec {
        on_query_reply: on_query_reply_log,
        on_query_final: on_query_final_log,
    };
    let query_role_spec = QueryRoleSpec {
        queryable: queryable_spec,
        query: query_spec,
    };
    let outcome = runtime.block_on(async move {
        run_demo(
            role,
            key_opt,
            publisher_spec,
            query_role_spec,
            declare_spec,
            remote_log_spec,
            reply_log_spec,
        )
        .await
    });
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("wz-ap-demo: {e}");
            ExitCode::from(1)
        }
    }
}

/// R121k-5 — bundle of `--declare-subscriber/queryable/token`
/// keyexprs the demo emits once the session reaches Established.
/// Each `Option<String>` is the keyexpr literal; the id is hard-coded
/// to a per-kind sentinel (1001 / 2001 / 3001) so a paired
/// integration test can assert on the wire shape without an extra
/// CLI knob. Production deployments source ids from a per-session
/// counter the same way as send_declare_keyexpr / publisher mapping.
struct DeclareEmitSpec {
    subscriber_keyexpr: Option<String>,
    queryable_keyexpr: Option<String>,
    token_keyexpr: Option<String>,
}

/// R121k-5 — bool flag bundle for the three Remote* registry log
/// callbacks. Each `true` installs a callback that prints a
/// stderr line on the matching inbound Declare arm so an integration
/// test fixture can grep for the expected line shape.
struct RemoteLogSpec {
    on_remote_subscriber: bool,
    on_remote_queryable: bool,
    on_remote_liveliness: bool,
}

/// R121j-6-e2e — bool flag bundle for the initiator-side
/// ReplyRegistry log callbacks. Both flags require --query (the rid
/// the registry binds to is the rid of the outbound Query this demo
/// emits); the validation in `main` rejects mis-wired argv before
/// this struct is constructed. Each `true` installs a callback that
/// prints a stderr line on the matching inbound record so an
/// integration test fixture can grep for the expected line shape.
struct ReplyConsumerSpec {
    on_query_reply: bool,
    on_query_final: bool,
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
struct QueryRoleSpec {
    queryable: Option<(String, String)>,
    query: Option<String>,
}

async fn run_demo(
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
    // ── Step 1: TCP setup. Acceptor binds + accepts; Initiator
    //           dials. Both paths land at the same `TcpStream`
    //           value below, after which the FSM-driving code is
    //           role-agnostic except for the initial event
    //           dispatch (Step 4b).
    let stream = match &role {
        Role::Acceptor { listen } => {
            let listener = TcpListener::bind(listen).await?;
            log::info!("wz-ap-demo: listening on {}", listener.local_addr()?);
            let (s, peer) = listener.accept().await?;
            log::info!("wz-ap-demo: accepted peer {peer}");
            s
        }
        Role::Initiator { connect } => {
            // R121f — dial the configured peer. Note: this binary
            // does NOT implement TCP retry / connect timeout
            // tuning beyond the kernel default; production callers
            // that need either compose around a `tokio::time::timeout`.
            // The address must resolve (DNS or numeric) — we surface
            // any TcpStream::connect error up through the io::Result
            // return so the binary's exit code reflects the cause.
            let s = TcpStream::connect(connect).await?;
            log::info!("wz-ap-demo: connected to {}", s.peer_addr()?);
            s
        }
    };

    // ── Step 2: split the TcpStream into owned read + write halves
    //          + spawn a dedicated writer task so the FSM's sync
    //          script-action handlers can enqueue outbound frames
    //          without nesting `block_on` inside the runtime that
    //          is driving the inbound poll loop. The writer task
    //          owns the `OwnedWriteHalf`; the FSM-facing
    //          `OutboundWriteDriver` holds only the sender.
    let (reader, writer) = stream.into_split();
    let inbound = InboundReadDriver { reader };
    let (outbound_tx, outbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let writer_handle = tokio::spawn(writer_task(writer, outbound_rx));
    let outbound = Arc::new(OutboundWriteDriver { tx: outbound_tx });

    // ── Step 3: subscriber registry — register the --key callback
    //          BEFORE drive_session starts so any Push that arrives
    //          during handshake (zenoh-pico's z_put echo) routes
    //          through the registered subscriber. The callback prints
    //          payload metadata to stderr; R121c integration test
    //          greps stderr for the expected line shape.
    //          R121e: --key is now optional (publisher-only mode
    //          skips the subscriber registration).
    //
    // R121k-7-refactor: the six per-domain registries
    // (subscribers / queryables / remote_subscribers / remote_queryables /
    // liveliness / replies) plus the queryable side's pending-reply +
    // pending-final staging buffers are now wrapped in a single
    // ApplicationLayerObserver. Application code registers callbacks
    // on each contained registry directly (observer.subscribers.register
    // etc.) and a single observer.dispatch call inside the
    // drive_session loop fans the IterationEvent into every registry +
    // drains the staged outbound records through the action layer.
    //
    // R235 — observer is now wrapped in `Arc<Mutex<>>` so the
    // application can hand the same observer to the drive_session
    // dispatch closure AND to a Session bundle whose loopback branch
    // (`Session::publish`) needs to reach the subscriber registry.
    // The 11 callback installs below run inside one lock scope so the
    // init phase incurs a single lock+drop; the drive_session loop and
    // any background `Session::publish` callers take the lock on each
    // dispatch / loopback fire (mutex contention is negligible — the
    // critical section is the per-event fan-out which is already the
    // serial bottleneck in the registry model).
    let observer = Arc::new(Mutex::new(ApplicationLayerObserver::new()));
    {
        let mut observer_lock = observer.lock().expect("observer mutex poisoned");
        if let Some(ref k) = key {
            let key_for_callback = k.clone();
            observer_lock.subscribers.register(k.clone(), move |sample| {
                // R222 — Sample carries the resolved keyexpr literal +
                // the SampleKind discriminant + payload bytes directly,
                // so the prior `match push.keyexpr.body` + tagged-union
                // arm extraction is no longer required at the call site.
                eprintln!(
                    "wz-ap-demo: SUBSCRIBER FIRED filter='{}' keyexpr='{}' kind={:?} payload_len={}",
                    key_for_callback,
                    sample.keyexpr,
                    sample.kind,
                    sample.payload.len(),
                );
            });
        }

        // R121j-5c-e2e-demo — queryable callback. The observer's
        // dispatch fans inbound Request(Query) records into this
        // registry automatically; we just install the callback that
        // emits one Reply per match + logs `QUERYABLE FIRED`.
        if let Some((pattern, reply_text)) = queryable_spec.as_ref() {
            let pattern_for_callback = pattern.clone();
            let reply_text_for_callback = reply_text.clone();
            observer_lock
                .queryables
                .register(pattern.clone(), move |_query, responder| {
                    responder.send_reply(reply_text_for_callback.as_bytes());
                    eprintln!(
                        "wz-ap-demo: QUERYABLE FIRED pattern='{}' rid={} keyexpr='{}' reply='{}'",
                        pattern_for_callback,
                        responder.rid(),
                        responder.keyexpr_literal(),
                        reply_text_for_callback,
                    );
                });
        }

        // R121k-5 — Remote* registry callbacks. Each tracks the peer's
        // outbound Declare(Decl*|Undecl*) records and fires user-installed
        // callbacks on resolved keyexprs. Production deployments wire
        // metrics or route-table updates here instead of stderr logging.
        if remote_log_spec.on_remote_subscriber {
            observer_lock
                .remote_subscribers
                .on_subscriber_declared(|decl, resolved| {
                    eprintln!(
                        "wz-ap-demo: REMOTE SUBSCRIBER DECLARED id={} keyexpr='{}'",
                        decl.id, resolved,
                    );
                });
            observer_lock
                .remote_subscribers
                .on_subscriber_undeclared(|undecl| {
                    eprintln!("wz-ap-demo: REMOTE SUBSCRIBER UNDECLARED id={}", undecl.id);
                });
        }
        if remote_log_spec.on_remote_queryable {
            observer_lock
                .remote_queryables
                .on_queryable_declared(|decl, resolved| {
                    eprintln!(
                        "wz-ap-demo: REMOTE QUERYABLE DECLARED id={} keyexpr='{}'",
                        decl.id, resolved,
                    );
                });
            observer_lock
                .remote_queryables
                .on_queryable_undeclared(|undecl| {
                    eprintln!("wz-ap-demo: REMOTE QUERYABLE UNDECLARED id={}", undecl.id);
                });
        }
        // R121j-6-e2e — z_get-side ReplyRegistry. Registered BEFORE
        // the outbound Query goes out so the inbound Reply chain has
        // a pending entry to dispatch to (the registry drops silently
        // when a Reply arrives for an unknown rid; the alternative —
        // register after send_request_query fires inside query_task
        // — would race against the peer's first Reply on a fast
        // loopback). Both callbacks log a stderr line so the paired
        // integration test fixture can grep for the expected line
        // shape; the on_final callback also receives the rid the
        // registry auto-drops on.
        if query_spec.is_some()
            && (reply_log_spec.on_query_reply || reply_log_spec.on_query_final)
        {
            let on_reply = reply_log_spec.on_query_reply;
            let on_final = reply_log_spec.on_query_final;
            observer_lock.replies.register(
                QUERY_RID,
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
                    eprintln!(
                        "wz-ap-demo: REPLY RECEIVED rid={} keyexpr='{}' body={}",
                        reply.rid, reply.keyexpr_literal, body_text,
                    );
                },
                move |rid| {
                    if !on_final {
                        return;
                    }
                    eprintln!("wz-ap-demo: FINAL RECEIVED rid={rid}");
                },
            );
        }

        if remote_log_spec.on_remote_liveliness {
            observer_lock
                .liveliness
                .on_token_declared(|decl, resolved| {
                    eprintln!(
                        "wz-ap-demo: REMOTE TOKEN DECLARED id={} keyexpr='{}'",
                        decl.id, resolved,
                    );
                });
            observer_lock
                .liveliness
                .on_token_undeclared(|undecl| {
                    eprintln!("wz-ap-demo: REMOTE TOKEN UNDECLARED id={}", undecl.id);
                });
        }
        // observer_lock drops here; subsequent users (drive_session
        // dispatch closure, Session::publish loopback branch) re-lock
        // per-event.
    }

    // ── Step 4: session FSM + Lua engine + actions. Production
    //          callers MUST source SessionInitParams from
    //          deploy.yaml; the demo uses fixed MVP values per the
    //          `demo_session_init_params()` constant block.
    let params = demo_session_init_params(&role);
    let actions = SessionLinkActions::new(outbound, params);
    let script_engine: Arc<dyn IScriptEngine> = Arc::new(LuaEngine::new());
    install_session_actions(actions.clone(), &script_engine);

    let mut engine: Engine<SessionFsmUnicastPolicy> =
        Engine::new(SessionFsmUnicastPolicy::new(script_engine));
    engine.initialize();

    // R235 — bundle the outbound actions handle and the inbound
    // observer into a single `Session`. Background tasks (publisher,
    // declare emitter, query emitter) take their own cheap clone of
    // the bundle; each clone shares the same `Arc<SessionLinkActions>`
    // and the same `Arc<Mutex<ApplicationLayerObserver>>`, so
    // `session.publish` / `publish_aliased_auto` from any task fans
    // through to the loopback subscriber registry while the
    // drive_session loop's `observer.dispatch` is observing inbound
    // wire frames on the same registry.
    let session = Session::new(actions.clone(), observer.clone());

    // ── Step 4a (R121e): spawn the publisher task BEFORE the
    //                    drive_session loop so the task can wait on
    //                    the handshake's send_open_ack trace counter
    //                    concurrently with the loop's inbound poll.
    //                    R235 — the task now receives a `Session`
    //                    clone instead of a bare
    //                    `Arc<SessionLinkActions>`, so it can route
    //                    Put/Del Pushes through `Session::publish`
    //                    (literal keyexpr) or
    //                    `Session::publish_aliased_auto` (when
    //                    `--declare-id` is supplied). The bundle
    //                    keeps the loopback branch live so a
    //                    self-`--key` co-located subscriber will fire
    //                    on the local Push without crossing the wire.
    let publisher_handle = publisher_spec
        .as_ref()
        .map(|(keyexpr, operation, declare_id)| {
            let session_for_publisher = session.clone();
            let keyexpr = keyexpr.clone();
            let operation = operation.clone();
            let declare_id = *declare_id;
            tokio::spawn(publisher_task(
                session_for_publisher,
                keyexpr,
                operation,
                declare_id,
            ))
        });

    // R121j-5c-e2e-demo — query_task spawn (initiator-style: emit a
    // single outbound Request(Query) once the session reaches
    // Established). Same Established gate as publisher_task — the
    // role-agnostic `record_established_at` counter fires on both
    // acceptor and initiator sides. rid is hard-coded to 1 for the
    // demo; production callers will source unique rids from a per-
    // session counter once a z_get adapter lands (carry).
    let query_handle = query_spec.as_ref().map(|keyexpr| {
        let actions_for_query = actions.clone();
        let keyexpr = keyexpr.clone();
        tokio::spawn(query_task(actions_for_query, keyexpr))
    });

    // R121k-5 — declare emit task. Bundles all three optional
    // `--declare-*` keyexprs into one task so a single Established
    // gate covers the whole batch. Each declare emits via
    // SessionLinkActions.send_declare_* on the reliable channel; the
    // SN-window ordering matches what zenoh-pico's
    // _z_session_recv_declaration expects (one declare per frame,
    // reliable channel, peer registers id -> keyexpr before any
    // dependent message).
    let has_declares = declare_spec.subscriber_keyexpr.is_some()
        || declare_spec.queryable_keyexpr.is_some()
        || declare_spec.token_keyexpr.is_some();
    let declare_handle = if has_declares {
        let actions_for_declare = actions.clone();
        Some(tokio::spawn(declare_task(actions_for_declare, declare_spec)))
    } else {
        None
    };

    // ── Step 4b: activate the session FSM role. The
    //          `session_fsm_unicast.scxml` starts in `Init` and
    //          offers two role-selection transitions
    //          (`outbound.start` → LinkOpening,
    //          `inbound.start` → Accepting); the driver loop does
    //          NOT synthesize either side — the production caller
    //          dispatches the relevant role event after the socket
    //          is established. Without this dispatch the FSM stays
    //          in `Init` and silently drops the first inbound
    //          frame.
    //
    //          R121d acceptor path: `InboundStart` lands the FSM
    //          in `Accepting.AwaitingInitSyn` before the first
    //          inbound `InitSyn` frame arrives. Mirrors the pattern
    //          asserted by `session_fsm_accepting_path.rs::r78_*`.
    //
    //          R121f initiator path: `OutboundStart` lands the
    //          FSM in `LinkOpening` (fires `link_driver_open`
    //          which is a no-op on the OutboundWriteDriver since
    //          TCP is already connected); then `LinkOpened` lands
    //          it in `SentInitSyn` which fires `send_init_syn` —
    //          our first wire byte goes out here. Mirrors the
    //          pattern asserted by
    //          `session_fsm_real_tcp.rs::r60_fsm_drives_real_tcp_loopback`
    //          (`OutboundStart` + `LinkOpened` in sequence).
    use wz_runtime_tokio::session_fsm_unicast::SessionFsmUnicastEvent as E;
    match &role {
        Role::Acceptor { .. } => {
            engine.process_event(E::InboundStart);
        }
        Role::Initiator { .. } => {
            engine.process_event(E::OutboundStart);
            engine.process_event(E::LinkOpened);
        }
    }

    // ── Step 5: drive the session FSM until terminal. The
    //          ApplicationLayerObserver's dispatch fans the
    //          IterationEvent into every contained registry +
    //          drains the queryable side's pending replies / finals
    //          through the action layer. Cap iterations at a
    //          generous bound — a hung peer would otherwise leave
    //          the demo blocking forever. R121k-7-refactor collapsed
    //          the 8-line fan-out + drain block into the single
    //          observer.dispatch call below; the per-iteration trace
    //          stays at debug level so `RUST_LOG=info` production
    //          runs are not noisy on every Push frame.
    //
    // R235 — observer is `Arc<Mutex<ApplicationLayerObserver>>` so
    // each iteration relocks per dispatch. A `Session::publish`
    // callback that fires synchronously from a subscriber (loopback
    // re-publish) does NOT deadlock because `local_publish` releases
    // the registry borrow before invoking the user callback —
    // contention is therefore only between this loop and background
    // task `Session::publish` calls, which serialize naturally on the
    // mutex without livelock.
    log::info!("wz-ap-demo: driving session FSM");
    let mut driver = inbound;
    let observer_for_dispatch = observer.clone();
    let outcome = drive_session_until_terminal(
        &mut driver,
        &actions,
        &mut engine,
        Some(10_000),
        |event: IterationEvent<'_>| {
            log::debug!("wz-ap-demo: iteration event = {event:?}");
            observer_for_dispatch
                .lock()
                .expect("observer mutex poisoned by panic in subscriber callback")
                .dispatch(event, &actions);
        },
    )
    .await;
    log::info!("wz-ap-demo: session ended: {outcome:?}");
    log::info!("wz-ap-demo: action trace = {:?}", actions.trace_snapshot());

    // R121e — give the publisher task a brief window to finish
    // its emission loop before tearing down. The drive_session
    // loop typically returns when the peer closes (z_sub stays
    // connected forever, so in that case the loop hits the
    // `max_iters` cap after most Pushes have already been
    // emitted; in the integration-test flow the test process
    // SIGKILLs the binary once the gate fires, so the publisher
    // task does not need to complete on its own). The
    // 200ms ceiling absorbs the publisher's normal emission
    // tail (1 Push, 200ms spacing window not yet elapsed); a
    // wedged publisher is dropped here rather than blocking
    // shutdown indefinitely.
    if let Some(handle) = publisher_handle {
        let _ = tokio::time::timeout(Duration::from_millis(200), handle).await;
    }
    if let Some(handle) = query_handle {
        let _ = tokio::time::timeout(Duration::from_millis(200), handle).await;
    }
    if let Some(handle) = declare_handle {
        let _ = tokio::time::timeout(Duration::from_millis(200), handle).await;
    }

    // Drop the FSM-side sender so the writer task observes the
    // channel close and exits cleanly. `actions` holds another
    // clone through the BoxedLinkDriver, so dropping `actions`
    // explicitly is the textbook signal — every Sender clone must
    // drop for `rx.recv()` in the writer task to return `None`.
    drop(actions);
    // Give the writer task a brief window to drain any tail frame
    // (e.g. a Close frame the FSM enqueued during the final
    // transition) before we return and the runtime shuts down.
    let _ = tokio::time::timeout(Duration::from_millis(50), writer_handle).await;
    Ok(())
}

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
const QUERY_RID: u64 = 1;

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
///   token       = 3001
/// Ids are picked per-kind so a wire-capture or integration test can
/// distinguish at a glance which kind a given declare body belongs
/// to. Production deployments would source ids from a per-session
/// counter (the wz-ap-demo binary is intentionally minimal here).
const DECLARE_SUBSCRIBER_ID: u64 = 1001;
const DECLARE_QUERYABLE_ID: u64 = 2001;
const DECLARE_TOKEN_ID: u64 = 3001;
const DECLARE_HANDSHAKE_POLL_INTERVAL_MS: u64 = 50;
const DECLARE_HANDSHAKE_TIMEOUT_MS: u64 = 5_000;
const DECLARE_INTER_EMIT_MS: u64 = 100;

async fn declare_task(
    actions: Arc<wz_runtime_tokio::session_glue::SessionLinkActions>,
    spec: DeclareEmitSpec,
) {
    let deadline = std::time::Instant::now()
        + Duration::from_millis(DECLARE_HANDSHAKE_TIMEOUT_MS);
    loop {
        if actions.trace_snapshot().record_established_at > 0 {
            break;
        }
        if std::time::Instant::now() >= deadline {
            log::warn!(
                "wz-ap-demo: declare_task gave up waiting for Established \
                 after {DECLARE_HANDSHAKE_TIMEOUT_MS}ms (record_established_at \
                 never fired)"
            );
            return;
        }
        tokio::time::sleep(Duration::from_millis(DECLARE_HANDSHAKE_POLL_INTERVAL_MS)).await;
    }
    if let Some(keyexpr) = spec.subscriber_keyexpr.as_deref() {
        actions.send_declare_subscriber(DECLARE_SUBSCRIBER_ID, /*mapping_id=*/ 0, Some(keyexpr));
        eprintln!(
            "wz-ap-demo: DECLARED SUBSCRIBER id={DECLARE_SUBSCRIBER_ID} keyexpr='{keyexpr}'"
        );
        tokio::time::sleep(Duration::from_millis(DECLARE_INTER_EMIT_MS)).await;
    }
    if let Some(keyexpr) = spec.queryable_keyexpr.as_deref() {
        actions.send_declare_queryable(DECLARE_QUERYABLE_ID, /*mapping_id=*/ 0, Some(keyexpr));
        eprintln!(
            "wz-ap-demo: DECLARED QUERYABLE id={DECLARE_QUERYABLE_ID} keyexpr='{keyexpr}'"
        );
        tokio::time::sleep(Duration::from_millis(DECLARE_INTER_EMIT_MS)).await;
    }
    if let Some(keyexpr) = spec.token_keyexpr.as_deref() {
        actions.send_declare_token(DECLARE_TOKEN_ID, /*mapping_id=*/ 0, Some(keyexpr));
        eprintln!(
            "wz-ap-demo: DECLARED TOKEN id={DECLARE_TOKEN_ID} keyexpr='{keyexpr}'"
        );
    }
}

async fn query_task(
    actions: Arc<wz_runtime_tokio::session_glue::SessionLinkActions>,
    keyexpr: String,
) {
    let deadline = std::time::Instant::now()
        + Duration::from_millis(QUERY_HANDSHAKE_TIMEOUT_MS);
    loop {
        if actions.trace_snapshot().record_established_at > 0 {
            break;
        }
        if std::time::Instant::now() >= deadline {
            log::warn!(
                "wz-ap-demo: query_task gave up waiting for Established \
                 after {QUERY_HANDSHAKE_TIMEOUT_MS}ms (record_established_at \
                 never fired)"
            );
            return;
        }
        tokio::time::sleep(Duration::from_millis(QUERY_HANDSHAKE_POLL_INTERVAL_MS)).await;
    }
    log::info!(
        "wz-ap-demo: query_task observed Established; emitting Query \
         on keyexpr='{keyexpr}' rid={QUERY_RID}"
    );
    actions.send_request_query(QUERY_RID, /*mapping_id=*/ 0, Some(&keyexpr));
    eprintln!(
        "wz-ap-demo: QUERY EMITTED keyexpr='{keyexpr}' rid={QUERY_RID}"
    );
}

async fn publisher_task(
    session: Session,
    keyexpr: String,
    operation: PushOperation,
    declare_id: Option<u64>,
) {
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
    let deadline = std::time::Instant::now()
        + Duration::from_millis(PUBLISHER_HANDSHAKE_TIMEOUT_MS);
    loop {
        if actions.trace_snapshot().record_established_at > 0 {
            break;
        }
        if std::time::Instant::now() >= deadline {
            log::warn!(
                "wz-ap-demo: publisher_task gave up waiting for Established \
                 after {PUBLISHER_HANDSHAKE_TIMEOUT_MS}ms (record_established_at \
                 never fired)"
            );
            return;
        }
        tokio::time::sleep(Duration::from_millis(PUBLISHER_HANDSHAKE_POLL_INTERVAL_MS)).await;
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
        actions.send_declare_keyexpr(mapping_id, &keyexpr);
        eprintln!(
            "wz-ap-demo: PUBLISHER DECLARED keyexpr='{keyexpr}' mapping_id={mapping_id}"
        );
        // Small drain pause so the DECLARE bytes reach the peer's
        // session-FSM dispatch (and populate the keyexpr table)
        // before the first aliased Push fires on the same channel.
        // The mpsc-channel + writer-task topology preserves
        // application-order on the wire, but the peer's receive
        // task is independent of our writer — a brief pause makes
        // the test less reliant on scheduling fairness.
        tokio::time::sleep(Duration::from_millis(PUBLISHER_BURST_INTERVAL_MS)).await;
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
            tokio::time::sleep(Duration::from_millis(PUBLISHER_BURST_INTERVAL_MS)).await;
        }
    }
    log::info!("wz-ap-demo: publisher_task finished emission burst");
}
