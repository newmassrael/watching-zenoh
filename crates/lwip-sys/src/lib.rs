// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

#![cfg_attr(target_os = "none", no_std)]

//! lwip-sys — FFI bindings to vendored lwIP 2.2.1 (NO_SYS=1 + UDP minimal).
//!
//! R311az-1 walking skeleton: host build proves the cc::Build +
//! bindgen pipeline works on x86_64-linux with the in-crate
//! `port/include/{lwipopts.h, arch/cc.h}` NO_SYS configuration. The
//! emitted bindings cover the 6 raw `udp_*` functions + pbuf + netif
//! lifecycle subset that wz-link-lwip (R311az-2) consumes.
//!
//! ## Cross-compile (deploy crate responsibility)
//!
//! lwip-sys ships only the host-side build (Layer G.4-alloc-link does
//! NOT cross-compile this crate). Per R311az-pre D7, the MCU deploy
//! crate vendors its own lwipopts.h + arch/cc.h via `-I` paths
//! ordered before this crate's `port/include`, plus the cross-
//! compiled liblwip.a built by the deploy build system. The Rust
//! bindings stay binary-compatible across host + target because the
//! ABI of the allowlisted symbols is fixed by lwIP's public headers.
//!
//! ## Safety
//!
//! All bound functions are `unsafe extern "C" fn`. Pointer arguments
//! must be valid for the lifetime of the call; struct layouts match
//! the lwIP headers via bindgen. wz-link-lwip (R311az-2) provides the
//! safe Rust wrapper that maintains lifetime + aliasing invariants.

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(deref_nullptr)]
#![allow(unsafe_op_in_unsafe_fn)]
#![allow(clippy::all)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

// lwIP host-build port: sys_now().
//
// lwIP's timeouts.c references `sys_now()` (u32 msec-since-start) as
// an unconditional extern even in NO_SYS=1 mode — the timer machinery
// needs a monotonic clock source from the port. On bare-metal MCU
// builds the deploy crate provides this against a hardware timer; for
// the host build (where lwip-sys is compiled at all — see
// `target_os != "none"`) lwip-sys provides its own impl backed by
// std::time::Instant so cargo test / examples link cleanly.
//
// The `cfg(not(target_os = "none"))` guard scopes the impl to hosted
// platforms (linux / macos / windows). Cross-compile targets such as
// thumbv7em-none-eabihf set `target_os = "none"` and rely on the
// deploy crate to define sys_now itself — preserving R311az-pre D7's
// "netif + clock + driver belong to deploy" tier separation.
#[cfg(not(target_os = "none"))]
mod host_port {
    use std::sync::OnceLock;
    use std::time::Instant;

    fn epoch() -> &'static Instant {
        static EPOCH: OnceLock<Instant> = OnceLock::new();
        EPOCH.get_or_init(Instant::now)
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn sys_now() -> u32 {
        epoch().elapsed().as_millis() as u32
    }
}

#[cfg(test)]
mod smoke {
    //! R311az-1 smoke: lwIP init + udp_new + udp_remove round-trip.
    //!
    //! Proves the cc::Build static lib + bindgen FFI surface link
    //! cleanly. Does NOT exercise wire I/O — that lives in
    //! wz-link-lwip + wz-integration-tests (R311az-2 + Layer 3).

    use super::*;

    #[test]
    fn lwip_init_and_udp_new_remove() {
        unsafe {
            lwip_init();
            let pcb = udp_new();
            assert!(!pcb.is_null(), "udp_new returned NULL");
            udp_remove(pcb);
        }
    }
}
