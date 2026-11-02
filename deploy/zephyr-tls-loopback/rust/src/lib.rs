// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! zephyr-tls-loopback (Rust staticlib) -- the witness that a node on Zephyr's own sockets accepts
//! a secure channel and learns the zid of the key its peer proved (decision D12 of
//! `docs/session-lifecycle-intent.md`; the admin node that binds the verbs needs a link whose
//! peer is proven, and until this image no listener had been run on the target).
//!
//! One thread plays both ends over the loopback interface of one image, because the channel keeps
//! one arena with no lock and so two ends of it cannot run on two threads. The listener is
//! `TlsListener<ZephyrTcpListener>` and the dial is `TlsDial<ZephyrTcpDial>`, the two the admin
//! node's secure side is made of; what makes one thread enough is that the dial waits for its
//! peer by `wait_readable`, and this image's dial socket takes a step of the listener there
//! ([`SteppingSocket`]), as a node's own loop would take it between its passes. Neither end is
//! changed by that: the handshake each runs is the one it runs against a router.
//!
//! What is held, in order:
//!
//! 1. A peer that is no secure channel (a plain connection that sends junk) is taken off the port
//!    and not served: the listener yields no stream for it, and its peer reads the end of the
//!    stream.
//! 2. A listener that has just dropped such a peer still takes a real one: the handshake
//!    completes, and the stream each end holds names the zid of the OTHER end's key
//!    ([`StreamSocket::peer_credential_zid`]), the two zids being different.
//! 3. The stream is a stream: a message crosses it each way, over the sockets, as TLS records.
//! 4. A listener that served a connection, closed it first and went is replaced by one on the same
//!    port that binds at once (`SO_REUSEADDR`).
#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use core::cell::{Cell, RefCell};
use core::ffi::c_int;

use wz::runtime_zephyr::glue::{log, log_line, yield_us};
use wz::runtime_zephyr::net::ZephyrNetError;
use wz::runtime_zephyr::stream::{ZephyrTcpDial, ZephyrTcpListener, ZephyrTcpSocket};
use wz_runtime_coop::session_drive::LinkOpenError;
use wz_runtime_coop::stream_link::{StreamDial, StreamListen, StreamSocket};
use wz_tls_mbedtls::channel::{start_on_platform_arena, IdentitySlot, Zid};
use wz_tls_mbedtls::stream::{AcceptBudget, HandshakeBudget, TlsDial, TlsListener, TlsStream};

// The allocator over the kernel heap, the critical section over the kernel IRQ lock and the panic
// handler: the glue every wz Zephyr image carries, written once in the profile crate.
wz::runtime_zephyr::zephyr_image!();

/// The board's `CONFIG_SYS_CLOCK_TICKS_PER_SEC`, as this build was configured.
const TICK_HZ: u32 = wz::runtime_zephyr::tick_hz_from_build!();
/// The loopback address both ends use.
const LOOPBACK: [u8; 4] = [127, 0, 0, 1];
/// The port the listener takes secure channels on.
const PORT: u16 = 7470;
/// The port the restart check listens on twice.
const RESTART_PORT: u16 = 7471;
/// The longest the listener lets one inbound handshake take.
const ACCEPT_TIMEOUT_MS: u64 = 20_000;
/// Passes of the listener the witness gives a connection to be taken or dropped, 5 ms apart.
const PASSES: u32 = 4_000;

static SERVER_IDENTITY: IdentitySlot = IdentitySlot::new();
static CLIENT_IDENTITY: IdentitySlot = IdentitySlot::new();

/// Milliseconds on the kernel's monotonic tick: the clock the listener's deadline reads.
fn clock_ms() -> u64 {
    // SAFETY: reads the kernel's tick counter; no preconditions.
    let ticks = unsafe { zephyr_sys::sys_clock_tick_get() };
    u64::try_from(ticks).unwrap_or(0).saturating_mul(1000) / u64::from(TICK_HZ)
}

fn hex(zid: &Zid) -> String {
    zid.iter().map(|b| format!("{b:02x}")).collect()
}

/// The listening end: the listener of secure channels, and the stream it has completed, once it
/// has.
struct Server {
    listener: TlsListener<ZephyrTcpListener>,
    accepted: RefCell<Option<TlsStream<ZephyrTcpSocket>>>,
    /// The last failure the listener reported, which no later pass mends.
    failure: Cell<Option<LinkOpenError>>,
    /// How many passes the listener has had, for the witness to report.
    passes: Cell<u32>,
}

impl Server {
    /// One pass of the node's loop for the listener: a connection that waits is looked at, and a
    /// handshake in progress advances. Does nothing once a stream has been accepted.
    fn step(&self) {
        if self.accepted.borrow().is_some() {
            return;
        }
        self.passes.set(self.passes.get().saturating_add(1));
        match self.listener.accept() {
            Ok(Some(stream)) => *self.accepted.borrow_mut() = Some(stream),
            Ok(None) => {}
            Err(e) => self.failure.set(Some(e)),
        }
    }
}

/// The dial's stream, whose wait for its peer gives the listener a pass first: the one thread is
/// both ends, so the end that waits is the end that must let the other move.
struct SteppingSocket {
    inner: ZephyrTcpSocket,
    server: &'static Server,
}

impl StreamSocket for SteppingSocket {
    type Error = ZephyrNetError;

    fn local(&self) -> ([u8; 4], u16) {
        self.inner.local()
    }

    fn peer(&self) -> ([u8; 4], u16) {
        self.inner.peer()
    }

    fn send_parts(&self, parts: &[&[u8]]) -> Result<(), ZephyrNetError> {
        self.inner.send_parts(parts)
    }

    fn wait_readable(&self, timeout_ms: c_int) {
        self.server.step();
        self.inner.wait_readable(timeout_ms);
    }

    fn try_read(&self, buf: &mut [u8]) -> Result<Option<usize>, ZephyrNetError> {
        self.inner.try_read(buf)
    }

    fn shutdown(&self) {
        self.inner.shutdown();
    }
}

/// Zephyr's TCP connect, whose streams step the listener while they wait.
#[derive(Clone, Copy)]
struct SteppingDial {
    server: &'static Server,
}

impl StreamDial for SteppingDial {
    type Stream = SteppingSocket;

    fn dial(&self, addr: [u8; 4], port: u16) -> Result<SteppingSocket, LinkOpenError> {
        match ZephyrTcpSocket::connect(addr, port) {
            Ok(inner) => Ok(SteppingSocket {
                inner,
                server: self.server,
            }),
            Err(e) => {
                log_line(format!("wz: the dial's connect failed: {e:?}"));
                Err(match e {
                    ZephyrNetError::Socket(_) => LinkOpenError::Exhausted,
                    _ => LinkOpenError::Refused,
                })
            }
        }
    }
}

/// Read `into.len()` bytes from `stream`, waiting up to the witness's passes. The wait is the
/// stream's own, so a dial's stream gives the listener its pass there.
fn read_exactly<S: StreamSocket>(stream: &S, into: &mut [u8]) -> bool {
    let mut got = 0;
    for _ in 0..PASSES {
        if got == into.len() {
            return true;
        }
        stream.wait_readable(5);
        match stream.try_read(&mut into[got..]) {
            Ok(Some(0)) | Err(_) => return false,
            Ok(Some(n)) => got += n,
            Ok(None) => {}
        }
    }
    got == into.len()
}

/// Entry point the Zephyr C `main()` calls. Returns 0 on PASS.
#[no_mangle]
pub extern "C" fn wz_app_main() -> i32 {
    log(c"wz: secure listener over Zephyr's own sockets starting");
    if start_on_platform_arena().is_err() {
        log(c"wz: FAIL - the secure channel could not start");
        return 1;
    }
    let (Ok(server_id), Ok(client_id)) = (
        SERVER_IDENTITY.generate(c"CN=wz-zephyr-listener"),
        CLIENT_IDENTITY.generate(c"CN=wz-zephyr-dialler"),
    ) else {
        log(c"wz: FAIL - an end could not make its identity");
        return 1;
    };
    let (server_zid, client_zid) = (server_id.zid(), client_id.zid());
    log_line(format!("wz: listener key names zid {}", hex(&server_zid)));
    log_line(format!("wz: dialler key names zid {}", hex(&client_zid)));
    if server_zid == client_zid {
        log(c"wz: FAIL - two keys named one zid");
        return 1;
    }

    let Ok(port) = ZephyrTcpListener::listen(LOOPBACK, PORT, 2) else {
        log(c"wz: FAIL - listen on 127.0.0.1:7470");
        return 1;
    };
    let accepting = TlsDial::new(ZephyrTcpDial, server_id).with_accept(AcceptBudget {
        clock: clock_ms,
        timeout_ms: ACCEPT_TIMEOUT_MS,
    });
    let Ok(listener) = accepting.listener(port) else {
        log(c"wz: FAIL - the listener could not take secure channels");
        return 1;
    };
    let server: &'static Server = Box::leak(Box::new(Server {
        listener,
        accepted: RefCell::new(None),
        failure: Cell::new(None),
        passes: Cell::new(0),
    }));

    // 1. A peer that is no secure channel is not served.
    let Ok(junk) = ZephyrTcpSocket::connect(LOOPBACK, PORT) else {
        log(c"wz: FAIL - a plain connection to the listener was not taken");
        return 1;
    };
    if junk.send_parts(&[&[0xde; 64]]).is_err() {
        log(c"wz: FAIL - the plain connection could not send");
        return 1;
    }
    let mut ended = false;
    let mut scratch = [0u8; 16];
    for _ in 0..PASSES {
        server.step();
        yield_us(5_000);
        // The listener drops what it does not serve, and its peer reads the end of the stream.
        if matches!(junk.try_read(&mut scratch), Ok(Some(0))) {
            ended = true;
            break;
        }
    }
    if server.accepted.borrow().is_some() {
        log(c"wz: FAIL - the listener served a peer that is no secure channel");
        return 1;
    }
    if !ended {
        log(c"wz: FAIL - the listener kept a peer that is no secure channel");
        return 1;
    }
    log(c"wz: a plain connection was dropped and no stream was served for it");
    drop(junk);

    // 2. A real peer is still taken, and each end names the other's key.
    let dialling = TlsDial::new(SteppingDial { server }, client_id).with_budget(HandshakeBudget {
        wait_ms: 5,
        waits: PASSES,
    });
    let client = match dialling.dial(LOOPBACK, PORT) {
        Ok(stream) => stream,
        Err(e) => {
            log_line(format!(
                "wz: FAIL - the dial did not complete the handshake: {e:?}; the listener last said {:?}, after {} passes, and holds a stream: {}",
                server.failure.get(),
                server.passes.get(),
                server.accepted.borrow().is_some(),
            ));
            return 1;
        }
    };
    for _ in 0..PASSES {
        if server.accepted.borrow().is_some() {
            break;
        }
        server.step();
        yield_us(5_000);
    }
    let accepted = server.accepted.borrow_mut().take();
    let Some(served) = accepted else {
        log(c"wz: FAIL - the listener yielded no stream for the handshake");
        return 1;
    };
    if client.peer_credential_zid() != Some(server_zid) {
        log(c"wz: FAIL - the dial's stream does not name the listener's key");
        return 1;
    }
    if served.peer_credential_zid() != Some(client_zid) {
        log(c"wz: FAIL - the accepted stream does not name the dialler's key");
        return 1;
    }
    log(c"wz: each end names the zid of the other end's key");
    if served.peer().0 != LOOPBACK {
        log(c"wz: FAIL - the accepted stream does not know its peer's address");
        return 1;
    }

    // 3. The stream carries a message each way.
    if client.send_parts(&[b"ping"]).is_err() {
        log(c"wz: FAIL - the dial could not send");
        return 1;
    }
    let mut ping = [0u8; 4];
    if !read_exactly(&served, &mut ping) || &ping != b"ping" {
        log(c"wz: FAIL - the listener did not read what the dial sent");
        return 1;
    }
    if served.send_parts(&[b"pong"]).is_err() {
        log(c"wz: FAIL - the listener could not send");
        return 1;
    }
    let mut pong = [0u8; 4];
    if !read_exactly(&client, &mut pong) || &pong != b"pong" {
        log(c"wz: FAIL - the dial did not read what the listener sent");
        return 1;
    }
    log(c"wz: a message crossed the secure channel each way");
    drop((client, served));

    // 4. A node restarted on its port takes it again. The end that closes first keeps the
    //    connection (TIME_WAIT), here the listener's side, and `SO_REUSEADDR` is what lets the
    //    next listener bind the port while it does.
    if !restart_takes_the_port() {
        return 1;
    }
    0
}

/// A listener serves one connection, closes it first and goes; a listener on the same port
/// binds at once.
fn restart_takes_the_port() -> bool {
    let first = match ZephyrTcpListener::listen(LOOPBACK, RESTART_PORT, 1) {
        Ok(first) => first,
        Err(e) => {
            log_line(format!("wz: FAIL - listen on the restart port: {e:?}"));
            return false;
        }
    };
    let peer = match ZephyrTcpSocket::connect(LOOPBACK, RESTART_PORT) {
        Ok(peer) => peer,
        Err(e) => {
            log_line(format!("wz: FAIL - the restart port took no connection: {e:?}"));
            return false;
        }
    };
    let mut taken = None;
    for _ in 0..PASSES {
        if let Ok(Some(stream)) = first.accept() {
            taken = Some(stream);
            break;
        }
        yield_us(5_000);
    }
    let Some(stream) = taken else {
        log(c"wz: FAIL - the restart port's listener did not take the connection");
        return false;
    };
    // The listener's side closes first, and then the listener goes.
    drop(stream);
    drop(first);
    drop(peer);
    yield_us(50_000);
    match ZephyrTcpListener::listen(LOOPBACK, RESTART_PORT, 1) {
        Ok(_) => {
            log(c"wz: a listener restarted on its port took it again");
            true
        }
        Err(e) => {
            log_line(format!(
                "wz: FAIL - a listener restarted on its port could not bind it: {e:?}"
            ));
            false
        }
    }
}
