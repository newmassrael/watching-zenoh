// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The node's secure channel (`--features tls`): the fixed-memory profile's TLS 1.3 with mutual
//! authentication (decision D9 of `docs/session-lifecycle-intent.md`), from `wz-tls-mbedtls`.
//!
//! At start the node generates its identity, a P-256 key in the PSA key store and a certificate
//! self-signed over it, and prints the certificate as PEM: what the router's operator pins (a
//! zenoh router's `root_ca_certificate`). The node's zid is the one its key names (decision D1),
//! so a peer that reads the key can bind the zid to it. A `tls/` dial connects over TCP and
//! completes the handshake before the session sees a byte; a `tls/` listener ([`listener`])
//! completes it before the session is made, with the same mutual authentication, so a node that
//! opens a session to this one is known by the zid its key names. Every allocation of the channel
//! comes from the arena the node starts it on, and none from a heap.

use wz_runtime_coop::ip_stack::IpStack;
use wz_runtime_coop::ClockSource;
use wz_runtime_posix::net::PosixUdpSocket;
use wz_runtime_posix::stream::{PosixTcpDial, PosixTcpListener};
use wz_runtime_posix::PosixClock;
use wz_session_core::byte_cells::ByteSource;
use wz_tls_mbedtls::channel::{Arena, Identity, IdentitySlot};
use wz_tls_mbedtls::stream::{AcceptBudget, TlsDial, TlsListener};

/// Bytes of the arena one secure session takes at its peak: the kit measured about 22 KB (Round
/// 3495, with 16 KiB to receive a record and 1,500 B to send one), and this is that with room.
pub const SESSION_BYTES: usize = 32 * 1024;

/// Bytes of the arena beside the sessions': the identity, and the room a node of one session has
/// always had (its arena was 64 KiB, one session and this).
pub const IDENTITY_BYTES: usize = 32 * 1024;

/// Bytes of the arena of a node that holds `sessions` secure sessions at once. The arena's peak is
/// what a budget is set from; a node that holds more sessions than its arena was sized for is
/// refused a handshake when the arena runs out, and says so.
pub const fn arena_bytes(sessions: usize) -> usize {
    IDENTITY_BYTES + sessions * SESSION_BYTES
}

/// Every allocation the channel of `host-slot-node` makes: it dials one router.
static ARENA: Arena<{ arena_bytes(1) }> = Arena::new();

/// The node's identity, for the program.
static IDENTITY: IdentitySlot = IdentitySlot::new();

/// The longest the listener lets one inbound handshake take, in milliseconds: a host completes a
/// P-256 handshake in milliseconds, and a connection that says nothing for this long is closed so
/// its row is free for the next.
const ACCEPT_TIMEOUT_MS: u64 = 10_000;

/// The host's sockets as a stack that also dials `tls/`.
pub type Stack = IpStack<PosixUdpSocket, PosixTcpDial, TlsDial<PosixTcpDial>>;

/// Start the channel on the arena of `host-slot-node` and make the node's identity.
pub fn identity() -> Result<&'static Identity, &'static str> {
    identity_on(&ARENA)
}

/// Start the channel on `arena` and make the node's identity: a node that holds more than one
/// secure session sizes its own ([`arena_bytes`]).
pub fn identity_on<const N: usize>(
    arena: &'static Arena<N>,
) -> Result<&'static Identity, &'static str> {
    arena
        .start()
        .map_err(|_| "wz: FAIL - the secure channel could not start")?;
    IDENTITY
        .generate(c"CN=wz-host-slot-node")
        .map_err(|_| "wz: FAIL - the node could not make its identity")
}

/// The stack of a node at `local` whose links take their buffers from `rx` and `tx`, and whose
/// `tls/` links present `identity`.
pub fn stack(
    local: [u8; 4],
    rx: &'static dyn ByteSource,
    tx: &'static dyn ByteSource,
    identity: &'static Identity,
) -> Stack {
    IpStack::new(local, rx, tx, PosixTcpDial).with_tls(TlsDial::new(PosixTcpDial, identity))
}

/// Milliseconds on the host's monotonic clock: what the listener's handshake deadline reads.
fn clock_ms() -> u64 {
    PosixClock::default().now_us() / 1000
}

/// The secure channel's server side over `port`: each connection it takes is a TLS 1.3 handshake
/// that presents `identity` and requires the peer's certificate, completed (or refused) within
/// [`ACCEPT_TIMEOUT_MS`] before the session sees a byte. The session's acceptor is the stack's
/// (`IpStack::tls_acceptor`).
pub fn listener(
    port: PosixTcpListener,
    identity: &'static Identity,
) -> Result<TlsListener<PosixTcpListener>, &'static str> {
    TlsDial::new(PosixTcpDial, identity)
        .with_accept(AcceptBudget {
            clock: clock_ms,
            timeout_ms: ACCEPT_TIMEOUT_MS,
        })
        .listener(port)
        .map_err(|_| "wz: FAIL - the node's listener could not take secure channels")
}
