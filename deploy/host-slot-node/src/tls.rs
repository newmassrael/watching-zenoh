// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The node's secure channel (`--features tls`): the fixed-memory profile's TLS 1.3 with mutual
//! authentication (decision D9 of `docs/session-lifecycle-intent.md`), from `wz-tls-mbedtls`.
//!
//! At start the node generates its identity, a P-256 key in the PSA key store and a certificate
//! self-signed over it, and prints the certificate as PEM: what the router's operator pins (a
//! zenoh router's `root_ca_certificate`). The node's zid is the one its key names (decision D1),
//! so a peer that reads the key can bind the zid to it. A `tls/` dial connects over TCP and
//! completes the handshake before the session sees a byte; every allocation of the channel comes
//! from [`ARENA`], and none from a heap.

use wz_runtime_coop::ip_stack::IpStack;
use wz_runtime_posix::net::PosixUdpSocket;
use wz_runtime_posix::stream::PosixTcpDial;
use wz_session_core::byte_cells::ByteSource;
use wz_tls_mbedtls::channel::{Arena, Identity, IdentitySlot};
use wz_tls_mbedtls::stream::TlsDial;

/// Bytes of the channel's arena: one session at its peak (about 22 KB per session on the kit,
/// Round 3495, with 16 KiB to receive a record and 1,500 B to send one) and the identity, with
/// room to spare. The arena's peak is what a budget is set from.
const ARENA_BYTES: usize = 64 * 1024;

/// Every allocation the channel makes.
static ARENA: Arena<ARENA_BYTES> = Arena::new();

/// The node's identity, for the program.
static IDENTITY: IdentitySlot = IdentitySlot::new();

/// The host's sockets as a stack that also dials `tls/`.
pub type Stack = IpStack<PosixUdpSocket, PosixTcpDial, TlsDial<PosixTcpDial>>;

/// Start the channel on its arena and make the node's identity.
pub fn identity() -> Result<&'static Identity, &'static str> {
    ARENA
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
