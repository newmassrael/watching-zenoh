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
//       impls `LinkDriver` — `poll_event` reads one 4-byte BE
//       length-prefixed frame, `send`/`open`/`close` are no-ops
//       (the inbound side never emits outbound bytes).
//
//     OutboundWriteDriver { writer: Arc<TokioMutex<OwnedWriteHalf>> }
//       impls `BoxedLinkDriver` — `send_blocking` block_on-locks
//       the writer mutex and writes a 4-byte BE length prefix +
//       payload, mirroring `TcpDriver::send` framing verbatim so
//       the wire shape is identical to the bundled `TcpDriver`.
//
//   Both halves wrap the same TcpStream so peer reads see what we
//   send and peer writes reach our poll_event. The split lets each
//   side own its half exclusively, satisfying both the `&mut
//   LinkDriver` and `Arc<dyn BoxedLinkDriver>` shape constraints
//   without any custom Mutex around the full driver.

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
use tokio::sync::Mutex as TokioMutex;
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

// R121b session params: MVP-fixed values mirroring the test-support
// fixture's zenoh-default shape (whatami=Peer, version=0x05,
// lease=10s, deterministic ZID). Production AP deployment will
// source these from deploy.yaml once the topology-schema migration
// (R123b-pre carry) lands.
fn demo_session_init_params() -> SessionInitParams {
    SessionInitParams {
        version: 0x05,
        whatami: 0x02, // Peer
        zid: vec![0x01, 0x02, 0x03, 0x04],
        seq_num_res: 0,
        req_id_res: 0,
        batch_size: 0,
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
/// poll_event reading one 4-byte BE length-prefixed frame.
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
        let mut len_buf = [0u8; 4];
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
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        match self.reader.read_exact(&mut buf).await {
            Ok(_) => LinkEvent::Rx(RxFrame { bytes: buf }),
            Err(_) => LinkEvent::Lost {
                cause: LostCause::PeerClosed,
            },
        }
    }
}

/// Outbound half of the bidirectional split — holds an Arc-shared
/// Tokio Mutex over the accepted TcpStream's write half and
/// implements [`BoxedLinkDriver`] so [`SessionLinkActions::new`]'s
/// `Arc<dyn BoxedLinkDriver>` slot is satisfied without consuming
/// the read half.
///
/// `send_blocking` uses the captured tokio runtime handle's
/// `block_on` to bridge from the sync `BoxedLinkDriver` contract
/// (the Lua closures inside `SessionLinkActions` are sync) to the
/// async TCP write. The handle MUST point at a multi-thread
/// runtime so block_on doesn't deadlock — TokioLinkDriverAdapter
/// makes the same assertion at construction; this driver follows
/// the same contract.
struct OutboundWriteDriver {
    writer: Arc<TokioMutex<OwnedWriteHalf>>,
    handle: tokio::runtime::Handle,
}

impl BoxedLinkDriver for OutboundWriteDriver {
    fn send_blocking(&self, bytes: &[u8], _reliability: Reliability) {
        let writer = self.writer.clone();
        let owned_bytes = bytes.to_vec();
        let result: io::Result<()> = self.handle.block_on(async move {
            let mut w = writer.lock().await;
            let len: u32 = owned_bytes
                .len()
                .try_into()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame > 4 GiB"))?;
            w.write_all(&len.to_be_bytes()).await?;
            w.write_all(&owned_bytes).await?;
            w.flush().await?;
            Ok(())
        });
        if let Err(e) = result {
            log::warn!("wz-ap-demo: outbound send failed: {e}");
        }
    }

    fn open_blocking(&self) {
        // TcpListener::accept already returned an established
        // stream; open is a no-op on this driver shape.
    }

    fn close_blocking(&self) {
        let writer = self.writer.clone();
        let _ = self.handle.block_on(async move {
            let mut w = writer.lock().await;
            w.shutdown().await
        });
    }
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
    //          so inbound (drive_session) and outbound (FSM script-
    //          actions) can own their half exclusively without any
    //          Mutex around the full driver. The write half goes
    //          behind an Arc<TokioMutex> so multiple script-action
    //          dispatches serialize their `send_blocking` calls.
    let (reader, writer) = stream.into_split();
    let inbound = InboundReadDriver { reader };
    let outbound = Arc::new(OutboundWriteDriver {
        writer: Arc::new(TokioMutex::new(writer)),
        handle: tokio::runtime::Handle::current(),
    });

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
        |event| registry.dispatch_iteration_event(event),
    )
    .await;
    log::info!("wz-ap-demo: session ended: {outcome:?}");

    // Give the runtime a moment to drain any tail outbound write
    // before shutdown collapses the writer mutex.
    tokio::time::sleep(Duration::from_millis(10)).await;
    Ok(())
}
