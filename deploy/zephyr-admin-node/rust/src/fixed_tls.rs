// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The fixed client's secure channel (`tls`, `CONFIG_WZ_TLS`): the fixed-memory profile's TLS 1.3
//! with mutual authentication (decision D9 of `docs/session-lifecycle-intent.md`), from
//! `wz-tls-mbedtls` over Zephyr's TCP (`wz_runtime_zephyr::stream`).
//!
//! At start the node generates its identity, a P-256 key in the PSA key store and a certificate
//! self-signed over it, and prints the certificate as PEM: what the router's operator pins. The
//! node's zid is the one its key names (decision D1), in place of the one the board derives from
//! its MAC. The channel's memory is the arena Zephyr gives Mbed TLS at boot
//! (`CONFIG_MBEDTLS_HEAP_SIZE`), and its C side (`wz_tls.c`) is compiled by the image's CMake
//! against Zephyr's own Mbed TLS.

use core::ffi::CStr;

use wz::runtime_zephyr::net::ZephyrUdpSocket;
use wz::runtime_zephyr::stream::ZephyrTcpDial;
use wz_runtime_coop::ip_stack::IpStack;
use wz_session_core::byte_cells::ByteSource;
use wz_tls_mbedtls::channel::{start_on_platform_arena, Identity, IdentitySlot};
use wz_tls_mbedtls::stream::TlsDial;

/// The node's identity, for the program.
static IDENTITY: IdentitySlot = IdentitySlot::new();

/// Zephyr's sockets as a stack that also dials `tls/`.
pub type Stack = IpStack<ZephyrUdpSocket, ZephyrTcpDial, TlsDial<ZephyrTcpDial>>;

/// Start the channel on the arena Zephyr gave Mbed TLS and make the node's identity.
pub fn identity() -> Result<&'static Identity, &'static CStr> {
    start_on_platform_arena().map_err(|_| c"wz: FAIL - the secure channel could not start")?;
    IDENTITY
        .generate(c"CN=wz-zephyr-client")
        .map_err(|_| c"wz: FAIL - the node could not make its identity")
}

/// The stack of a node at `address` whose links take their buffers from `rx` and `tx`, and whose
/// `tls/` links present `identity`.
pub fn stack(
    address: [u8; 4],
    rx: &'static dyn ByteSource,
    tx: &'static dyn ByteSource,
    identity: &'static Identity,
) -> Stack {
    IpStack::new(address, rx, tx, ZephyrTcpDial).with_tls(TlsDial::new(ZephyrTcpDial, identity))
}
