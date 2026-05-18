// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// wz-ap-demo — AP MVP demo binary entry point.
//
// R121b: functional round. Wires the session FSM + DECLARE
// subscriber + msg_put inbound dispatch end-to-end against an
// external zenoh-pico peer over real TCP.
//
// CLI shape (locked at R121a; consumed here + by R121c integration
// test fixtures):
//
//   wz-ap-demo --listen <tcp_addr> --key <keyexpr>
//
//   --listen   server-side TCP bind address (e.g. 127.0.0.1:7447).
//              The binary binds + accepts one peer, then drives
//              the session FSM until terminal state.
//   --key      DECLARE subscriber keyexpr (e.g. demo/example).
//              Each Push whose keyexpr matches this pattern fires
//              the demo callback (prints to stderr).
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
use std::sync::Arc;
use std::time::Duration;

use sce_rust_lua::LuaEngine;
use sce_rust_runtime::{Engine, IScriptEngine};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use wz_codecs::wireexpr::WireexprVariant;
use wz_runtime_tokio::pubsub::SubscriberRegistry;
use wz_runtime_tokio::session_fsm_unicast::SessionFsmUnicastPolicy;
use wz_runtime_tokio::session_glue::{
    drive_session_until_terminal, install_session_actions, BoxedLinkDriver,
    SessionInitParams, SessionLinkActions, SigningKey,
};
use wz_runtime_tokio::{LinkDriver, LinkEvent, LostCause, Reliability, RxFrame, TxFrame};

const ABOUT: &str = concat!(
    "wz-ap-demo ",
    env!("CARGO_PKG_VERSION"),
    " — AP MVP demo binary",
);

fn print_usage() {
    eprintln!("{ABOUT}");
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("    wz-ap-demo --listen <tcp_addr> --key <keyexpr>");
    eprintln!();
    eprintln!("OPTIONS:");
    eprintln!("    --listen <tcp_addr>   server-side TCP bind address (e.g. 127.0.0.1:7447)");
    eprintln!("    --key <keyexpr>       DECLARE subscriber keyexpr (e.g. demo/example)");
    eprintln!("    --help, -h            print this help and exit");
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
// `whatami = 0x02 (Peer)`, `lease = 10s`, `zid = 4-byte demo
// constant` carry from R121b unchanged. Production AP deployment
// will source these from deploy.yaml once the topology-schema
// migration (R123b-pre carry) lands.
fn demo_session_init_params() -> SessionInitParams {
    SessionInitParams {
        version: 0x09,
        whatami: 0x02, // Peer
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
            Ok(_) => LinkEvent::Rx(RxFrame { bytes: buf }),
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

    let listen = match parse_pair(rest, "--listen") {
        Some(v) => v,
        None => {
            eprintln!("wz-ap-demo: --listen is required");
            eprintln!();
            print_usage();
            return ExitCode::from(2);
        }
    };
    let key = match parse_pair(rest, "--key") {
        Some(v) => v,
        None => {
            eprintln!("wz-ap-demo: --key is required");
            eprintln!();
            print_usage();
            return ExitCode::from(2);
        }
    };

    // env_logger reads RUST_LOG (defaults to off). The integration
    // test fixture (R121c) sets RUST_LOG=info to surface subscriber-
    // dispatch / session-FSM transitions in the child stderr capture.
    env_logger::Builder::from_env(env_logger::Env::default().filter_or("RUST_LOG", "info"))
        .init();

    eprintln!("{ABOUT}");
    log::info!("listen = {listen}");
    log::info!("key    = {key}");

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

    let outcome = runtime.block_on(async move { run_demo(listen, key).await });
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("wz-ap-demo: {e}");
            ExitCode::from(1)
        }
    }
}

async fn run_demo(listen: String, key: String) -> io::Result<()> {
    // ── Step 1: bind + accept one peer ─────────────────────────
    let listener = TcpListener::bind(&listen).await?;
    log::info!("wz-ap-demo: listening on {}", listener.local_addr()?);
    let (stream, peer) = listener.accept().await?;
    log::info!("wz-ap-demo: accepted peer {peer}");

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
    let mut registry = SubscriberRegistry::new();
    let key_for_callback = key.clone();
    registry.register(key.clone(), move |push| {
        // R125c2: keyexpr is a tagged-union; extract id+suffix from
        // whichever arm the dispatcher selected for stderr logging.
        let (mid, suffix) = match &push.keyexpr.body {
            WireexprVariant::WireexprLocal(arm) => (arm.id, arm.suffix.clone()),
            WireexprVariant::WireexprNonlocal(arm) => (arm.id, arm.suffix.clone()),
        };
        eprintln!(
            "wz-ap-demo: SUBSCRIBER FIRED key='{}' wireexpr_id={} suffix={:?}",
            key_for_callback, mid, suffix
        );
    });

    // ── Step 4: session FSM + Lua engine + actions. Production
    //          callers MUST source SessionInitParams from
    //          deploy.yaml; the demo uses fixed MVP values per the
    //          `demo_session_init_params()` constant block.
    let params = demo_session_init_params();
    let actions = SessionLinkActions::new(outbound, params);
    let script_engine: Arc<dyn IScriptEngine> = Arc::new(LuaEngine::new());
    install_session_actions(actions.clone(), &script_engine);

    let mut engine: Engine<SessionFsmUnicastPolicy> =
        Engine::new(SessionFsmUnicastPolicy::new(script_engine));
    engine.initialize();

    // ── Step 4b: activate the listener role on the session FSM.
    //          `session_fsm_unicast.scxml` starts in `Init` and offers
    //          two role-selection transitions (`outbound.start` →
    //          LinkOpening, `inbound.start` → Accepting); the driver
    //          loop does NOT synthesize either side — the production
    //          caller dispatches the relevant role event after the
    //          socket is established. The wz-ap-demo binary is purely
    //          the acceptor (it called `listener.accept().await`
    //          above), so InboundStart fires here to land the FSM in
    //          `Accepting.AwaitingInitSyn` before the first inbound
    //          frame arrives. Without this, the FSM stays in `Init`
    //          and silently drops `init_syn.received`, which is the
    //          textbook root cause for an external initiator's
    //          "Unable to open session" report (the `init_syn.received`
    //          transition only exists inside `Accepting`).
    //          Matches the pattern asserted by
    //          `session_fsm_accepting_path.rs::r78_*`.
    engine.process_event(
        wz_runtime_tokio::session_fsm_unicast::SessionFsmUnicastEvent::InboundStart,
    );

    // ── Step 5: drive the session FSM until terminal. The observer
    //          callback routes IterationEvent::Poll(FramePayload {
    //          messages, .. }) through the subscriber registry so
    //          Push records reach the registered --key callback.
    //          Cap iterations at a generous bound — a hung peer
    //          would otherwise leave the demo blocking forever.
    log::info!("wz-ap-demo: driving session FSM");
    let mut driver = inbound;
    let outcome = drive_session_until_terminal(
        &mut driver,
        &actions,
        &mut engine,
        Some(10_000),
        |event| {
            // Per-iteration trace stays at `debug` so an
            // `RUST_LOG=info` production run does not flood the
            // log on every Push frame. The integration test sets
            // `RUST_LOG=info` and asserts only on the SUBSCRIBER
            // FIRED line emitted by the registered callback, so
            // hiding this trace behind `debug` does not regress
            // the test surface.
            log::debug!("wz-ap-demo: iteration event = {event:?}");
            registry.dispatch_iteration_event(event)
        },
    )
    .await;
    log::info!("wz-ap-demo: session ended: {outcome:?}");
    log::info!("wz-ap-demo: action trace = {:?}", actions.trace_snapshot());

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
