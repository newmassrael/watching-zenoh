// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

#![no_std]
// The whole crate is gated on `lwip_real_build` (set by build.rs from the
// lwip-sys `DEP_LWIP_LWIP_REAL_BUILD` metadata). Without it — a cross build
// with no `WZ_LWIP_PORT` — `wz-link-lwip` is an empty crate, so the
// `LwipUdpSocket` this crate binds does not exist; the gate collapses the
// body to nothing rather than failing to resolve the type. Mirrors the
// identical crate-level gate in `wz-link-lwip`.
#![cfg(lwip_real_build)]

//! wz-session-lwip — Phase W MCU session shell (Stage 4b).
//!
//! The integration tier above the §5.P runtime ([`wz_runtime_coop`]) and
//! the §5.C link ([`wz_link_lwip`]) tiers, binding them to the
//! runtime-agnostic session SSOT ([`wz_session_core`]). The MCU analog of
//! `wz_runtime_tokio::session_glue`'s drive loop + link-driver adapter:
//!
//! - [`driver::LwipUdpDriver`] — the MCU [`wz_session_core::link::BoxedLinkDriver`]
//!   adapter over a shared [`wz_link_lwip::LwipUdpSocket`]. The genuinely
//!   MCU-specific piece (the AP `TokioLinkDriverAdapter` is async).
//! - [`session_drive::run_session`] — the synchronous, `tokio::select!`-free
//!   drive loop. Loop STRUCTURE only: every drive-loop primitive
//!   (`dispatch_link_event` / `report_outcome_reassembling` /
//!   `check_lease_deadline` / `new_session_engine` / `HandshakeDeadlineTracker`)
//!   is shared with the AP loop in [`wz_session_core`], so there is no logic
//!   duplication across the AP / MCU profiles.
//!
//! ## Why a dedicated crate (not in wz-runtime-coop)
//!
//! The §5.P runtime tier ([`wz_runtime_coop`]) is deliberately link-agnostic
//! (its Cargo manifest documents this). Housing the drive loop there would
//! make the runtime tier depend on the link tier, regressing the MCU
//! runtime/link split. The AP `wz-runtime-tokio` bundles runtime + link +
//! session-drive only because tokio provides both the runtime and the async
//! socket I/O — a co-location of convenience, not the tier-correct shape.
//! This crate is what that session-drive layer is when the tiers are kept
//! clean; the end-state is a symmetric future `wz-session-tokio`.

extern crate alloc;

// lwIP under NO_SYS=1 keeps process-global state and `lwip_init` is not
// re-entrant; the host test harness serializes against it. Production
// `#![no_std]` builds never pull std (cfg(test)-only).
#[cfg(test)]
extern crate std;

pub mod driver;
// R311lt — the MCU multicast drive loop (no_std mirror of the AP
// wz-runtime-tokio multicast_glue), gated on the transport-multicast capability.
#[cfg(feature = "transport-multicast")]
pub mod multicast_drive;
pub mod session_drive;

pub use driver::LwipUdpDriver;
pub use session_drive::{run_session, SessionDriveConfig, SessionRole};
