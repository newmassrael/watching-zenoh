// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

#![no_std]

//! wz-session-mcu — the MCU session shell, written once for every network stack.
//!
//! The tier above the cooperative runtime ([`wz_runtime_coop`]) and the
//! runtime-agnostic session SSOT ([`wz_session_core`]), below whichever network
//! stack a board has. It holds what a node does with sessions that is not about
//! the wire under them:
//!
//! - [`app_layer`] — the application layer a session is driven with: the
//!   `on_event` that dispatches to an `ApplicationLayerObserver` and drains its
//!   staged output through the session's own send path.
//! - [`admin_host`] (`adminspace-write`) — the node hosts upstream's
//!   `connect/endpoints` config write.
//! - [`admin_status`] (`adminspace-core`) — the node answers upstream's admin GET.
//! - [`connect_manager`] (`adminspace-write`) — the node holds a session with every
//!   endpoint its control names and re-dials the ones that drop.
//! - [`dial`] (`adminspace-write`) — the dialer that opens a written
//!   `udp/<ipv4>:<port>` as an initiator session.
//! - [`admin_node`] (both) — those pieces as one thing a firmware ticks, and
//!   the acceptor session a host reaches the node on.
//!
//! ## Why a crate of its own, and what it is generic over
//!
//! These modules were `wz-session-lwip`'s. They name no lwIP type but four lines
//! that open a socket, and a board whose network is Zephyr's own sockets (the
//! profile zenoh-pico's Zephyr port takes) cannot carry the lwIP crate, whose
//! build compiles lwIP's C sources, to run an admin node. So the four lines
//! became [`wz_runtime_coop::session_drive::SessionLinks`] — a link that accepts
//! on a port, a link that dials an address — and the shell is generic over it.
//! lwIP supplies its links from `wz-session-lwip`, Zephyr from
//! `wz-runtime-zephyr`, and the shell's own tests from [`memory`], which is
//! neither.
//!
//! The crate depends on no link crate, for the reason the runtime tier does not:
//! a shell that named a stack would be that stack's shell.

extern crate alloc;

// Host tests: the shell's synchronization is `critical_section`, whose std
// implementation the dev-dependency supplies. A production `#![no_std]` build
// never pulls std.
#[cfg(test)]
extern crate std;

// R2827 — the application layer attached to the session drive.
pub mod app_layer;
// R2828 (§5.23 `adminspace-write`) — the node hosts upstream's
// `connect/endpoints` config write on that application layer.
#[cfg(feature = "adminspace-write")]
pub mod admin_host;
// R2830 — the node keeps a session with every endpoint the control names and
// re-dials on upstream's retry schedule; the dialling is behind a trait.
#[cfg(feature = "adminspace-write")]
pub mod connect_manager;
// R2831 — the dialer: a written `udp/<ipv4>:<port>` becomes an initiator
// session on the firmware's task set, over whichever stack opens the link.
#[cfg(feature = "adminspace-write")]
pub mod dial;
// R2829 (§5.23 `adminspace-core`) — the node answers upstream's admin GET
// through the shared answerer, on the same application layer.
#[cfg(feature = "adminspace-core")]
pub mod admin_status;
// R2837 — the node a host reaches and reconfigures at runtime: listen, the
// write subscriber, the status queryable and the dial manager, ticked as one.
#[cfg(all(feature = "adminspace-core", feature = "adminspace-write"))]
pub mod admin_node;
// An in-memory network for the shell's tests, and for a sibling crate's that
// wants a peer no stack owns.
#[cfg(any(test, feature = "test-support"))]
pub mod memory;
