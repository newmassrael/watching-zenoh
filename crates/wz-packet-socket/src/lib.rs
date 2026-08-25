// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Round 1998 (item 470) — Linux packet I/O: an `AF_PACKET` socket, the raweth
//! (L2) link driven over it, and the capture TAP built on the same read.
//!
//! ## Why this is a crate
//!
//! Both modules were in `wz-runtime-tokio` and neither uses `tokio` — MEASURED
//! rather than assumed: `tokio|async|await` matches nothing in either file
//! outside one line of doc text. They lived there because that crate already
//! had `std` and `libc`, which is a reason to put a file somewhere and not a
//! reason to keep it there.
//!
//! What that placement cost is item 470. `tokio` is a MANDATORY dependency of
//! `wz-runtime-tokio`, so [`wz-analyze`] — a passive file reader that depends
//! on no runtime at all — could not reach the tap without pulling a
//! multi-thread runtime and the whole session stack behind it. The tap was
//! therefore a capability with tests and NO caller, which is the shape this
//! workspace pays for most often.
//!
//! The obvious relocation is refused by the target's own contract: `wz-capture`
//! is `#![no_std]` with zero third-party dependencies and says in writing that
//! it must keep building for the MCU profiles. A socket is exactly what that
//! crate is not allowed to hold.
//!
//! Neither the async runtime nor the `no_std` dissector, then — which leaves
//! what a Linux socket layer was all along.
//!
//! ## Linux only, and that is a compile-time fact
//!
//! `AF_PACKET`, `SIOCGIFINDEX` and `SCM_TIMESTAMP` are Linux interfaces, and
//! pico's own raweth link is Linux-only for the same reason. Both modules are
//! gated on `target_os = "linux"` rather than failing at run time on a host
//! that could never have worked.
//!
//! [`wz-analyze`]: https://docs.rs/wz-analyze

/// The raweth (L2) link's TRANSPORT: an `AF_PACKET` socket, and the
/// [`RawEthIo`](raweth_socket::RawEthIo) seam that lets the framing above it be
/// driven without `CAP_NET_RAW`. Framing SSOT is
/// [`wz_session_core::raweth_link`].
#[cfg(target_os = "linux")]
pub mod raweth_socket;

/// R311y594 (B1) — the LIVE capture source: an `AF_PACKET` tap feeding the same
/// `wz_capture::Dissection` a pcap file does, with the KERNEL's timestamp as
/// the observer's clock. Privileged — see the module docs for what it
/// deliberately is not.
#[cfg(all(feature = "tap", target_os = "linux"))]
pub mod live_capture;
