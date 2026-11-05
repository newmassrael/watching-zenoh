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

use core::ffi::CStr;

use wz_runtime_coop::ip_stack::IpStack;
use wz_runtime_coop::ClockSource;
use wz_runtime_posix::file;
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

/// The longest certificate chain a provisioned identity may be, PEM: the node's own certificate
/// and its intermediates.
pub const CHAIN_PEM_BYTES: usize = 8 * 1024;

/// The longest private key a provisioned identity may be, PEM.
pub const KEY_PEM_BYTES: usize = 4 * 1024;

/// Start the channel on `arena` and take the node's identity from the files it was provisioned
/// with: `chain`, its certificate (and intermediates), and `key`, the certificate's private key,
/// both PEM. The key is read only when its owner alone may read it, and the text of it is wiped
/// once the channel holds it. A node told to be one identity that cannot be it stops, with the
/// file and the reason, and never becomes another.
///
/// Out of line, for the stack: the two texts are on this frame only while they are parsed.
#[inline(never)]
pub fn identity_from_files<const N: usize>(
    arena: &'static Arena<N>,
    chain: &CStr,
    key: &CStr,
    say: impl FnOnce(&CStr, &'static str),
) -> Option<&'static Identity> {
    if arena.start().is_err() {
        say(
            c"the secure channel's arena",
            "the secure channel could not start",
        );
        return None;
    }
    let mut chain_text = [0u8; CHAIN_PEM_BYTES];
    let chain_pem = match file::read_into(chain, &mut chain_text) {
        Ok(text) => text,
        Err(why) => {
            say(chain, why.reason());
            return None;
        }
    };
    let mut key_text = [0u8; KEY_PEM_BYTES];
    let identity = match file::read_secret(key, &mut key_text) {
        Ok(key_pem) => IDENTITY
            .from_pem(chain_pem, key_pem)
            .map_err(|_| "it is not the private key of the certificate, or either does not parse"),
        Err(why) => Err(why.reason()),
    };
    // The key's text is the device's secret: it does not stay on the stack once the channel holds
    // its own copy, or once it was refused.
    for byte in key_text.iter_mut() {
        // SAFETY: a live, writable byte of this frame; volatile so the wipe is not elided.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    match identity {
        Ok(identity) => Some(identity),
        Err(why) => {
            say(key, why);
            None
        }
    }
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
