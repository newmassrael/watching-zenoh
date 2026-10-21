// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
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
//! - `admin_fixed` (`adminspace-core` and `session-slot`) — the same admin GET with
//!   no allocator: the node's state in fixed rows, its reply built in a bounded
//!   arena.
//! - [`connect_manager`] (`adminspace-write`) — the node holds a session with every
//!   endpoint its control names and re-dials the ones that drop.
//! - `dial` (`adminspace-write`) — the dialer that opens a written
//!   `udp/<ipv4>:<port>` as an initiator session. Under `session-slot` only the
//!   endpoint parser is here: the dialer that opens the link is the stack's
//!   (`wz-session-lwip`'s `slot_node`), over the tables the image declared.
//! - `admin_node` (both, absent under `session-slot`) — those pieces as one
//!   thing a firmware ticks, and
//!   the acceptor session a host reaches the node on. Its slot-profile form is
//!   `wz-session-lwip`'s `slot_node`.
//!
//! ## Why a crate of its own, and what it is generic over
//!
//! These modules were `wz-session-lwip`'s. They name no lwIP type but four lines
//! that open a socket, and a board whose network is Zephyr's own sockets (the
//! profile zenoh-pico's Zephyr port takes) cannot carry the lwIP crate, whose
//! build compiles lwIP's C sources, to run an admin node. So the four lines
//! became `wz_runtime_coop::session_drive::SessionLinks` — a link that accepts
//! on a port, a link that dials an address — and the shell is generic over it.
//! lwIP supplies its links from `wz-session-lwip`, Zephyr from
//! `wz-runtime-zephyr`, and the shell's own tests from `memory`, which is
//! neither.
//!
//! The crate depends on no link crate, for the reason the runtime tier does not:
//! a shell that named a stack would be that stack's shell.

// Fixed-memory step S9c -- under `session-slot` the crate does not link `alloc` at
// all, so a use that creeps back into the slot profile is a compile error and not a
// silent allocation (the rule `wz-link-lwip` keeps under `static-link-storage`). The
// tests keep it: their sessions, sinks and fixtures are host code.
#[cfg(any(not(feature = "session-slot"), test))]
extern crate alloc;

// Host tests: the shell's synchronization is `critical_section`, whose std
// implementation the dev-dependency supplies. A production `#![no_std]` build
// never pulls std.
#[cfg(test)]
extern crate std;

// R2827 — the application layer attached to the session drive.
pub mod app_layer;
// R311lt — the multicast group session's drive loop, pump and slot table, over
// whichever stack carries the group (`GroupTransport`). It was
// `wz-session-lwip`'s and named lwIP's types for what it needs of a stack.
#[cfg(feature = "transport-multicast")]
pub mod group_drive;
// R2828 (§5.23 `adminspace-write`) — the node hosts upstream's
// `connect/endpoints` config write on that application layer.
#[cfg(feature = "adminspace-write")]
pub mod admin_host;
// How a node of the slot profile opens a session out of the tables its image declared,
// written once over whichever stack carries it (`SlotStack`). It was `wz-session-lwip`'s
// and named lwIP's driver, pump link and socket pool for what it needs of a stack.
#[cfg(feature = "session-slot")]
pub mod slot_host;
// R2830 — the node keeps a session with every endpoint the control names and
// re-dials on upstream's retry schedule; the dialling is behind a trait.
#[cfg(feature = "dial")]
pub mod connect_manager;
// R2831 — the dialer: a written `udp/<ipv4>:<port>` becomes an initiator
// session on the firmware's task set, over whichever stack opens the link.
#[cfg(feature = "dial")]
pub mod dial;
// A node that is a client of a router and answers queries: the dialer over a fixed list of
// endpoints, an observer for the application's queryables and subscribers, and their
// declarations sent on every session as it establishes.
#[cfg(all(feature = "client-node", not(feature = "session-slot")))]
pub mod client_node;
// R2829 (§5.23 `adminspace-core`) — the node answers upstream's admin GET
// through the shared answerer, on the same application layer.
#[cfg(feature = "adminspace-fixed")]
pub mod admin_status;
// S9b — the same admin GET with no allocator: the node's state in fixed rows, the
// reply built in a bounded arena and staged in the session's own stage.
#[cfg(all(feature = "adminspace-fixed", feature = "session-slot"))]
pub mod admin_fixed;
// R2837 — the node a host reaches and reconfigures at runtime: listen, the
// write subscriber, the status queryable and the dial manager, ticked as one.
#[cfg(all(
    feature = "adminspace-core",
    feature = "adminspace-write",
    not(feature = "session-slot")
))]
pub mod admin_node;
// An in-memory network for the shell's tests, and for a sibling crate's that
// wants a peer no stack owns.
#[cfg(all(any(test, feature = "test-support"), not(feature = "session-slot")))]
pub mod memory;
