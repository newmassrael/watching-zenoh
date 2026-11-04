// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
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

/// What the tests share: lwIP keeps its state in globals and is not thread-safe, and a second
/// `lwip_init` adds the loopback netif again (an assertion in lwIP). The tests of this crate take
/// the gate, and the first of them initialises lwIP.
#[cfg(test)]
mod serial {
    use std::sync::{Mutex, MutexGuard, Once};

    static GATE: Mutex<()> = Mutex::new(());
    static INIT: Once = Once::new();

    pub fn lwip() -> MutexGuard<'static, ()> {
        let guard = GATE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        // SAFETY: the gate is held, so no other thread is inside lwIP, and `Once` runs this once.
        INIT.call_once(|| unsafe { super::lwip_init() });
        guard
    }
}

/// The `tcp` feature, run: a connection over the loopback netif through lwIP's raw TCP API,
/// driven by the same explicit poll a `NO_SYS` node runs (`netif_poll_all`, `sys_check_timeouts`).
/// It proves the TCP sources are in the library, built with the port's own options, and that the
/// bound functions do what the stream link will ask of them: listen, accept, connect, send, receive,
/// acknowledge what was received, and close from both ends.
#[cfg(all(test, feature = "tcp"))]
mod tcp_smoke {
    use super::*;
    use core::ffi::c_void;

    const PORT: u16 = 47_117;

    struct Shared {
        connected: bool,
        accepted: *mut tcp_pcb,
        server_got: Vec<u8>,
        client_got: Vec<u8>,
        server_saw_end: bool,
    }

    /// The bytes of a received chain, and the receive window handed back for them.
    unsafe fn take(tpcb: *mut tcp_pcb, p: *mut pbuf) -> Vec<u8> {
        let len = (*p).tot_len;
        let mut bytes = vec![0u8; usize::from(len)];
        pbuf_copy_partial(p, bytes.as_mut_ptr().cast(), len, 0);
        tcp_recved(tpcb, len);
        pbuf_free(p);
        bytes
    }

    unsafe fn send(tpcb: *mut tcp_pcb, bytes: &[u8]) {
        // TCP_WRITE_FLAG_COPY: the bytes are copied, so the slice need not outlive the call.
        assert_eq!(
            tcp_write(tpcb, bytes.as_ptr().cast(), bytes.len() as u16, 1),
            0
        );
        assert_eq!(tcp_output(tpcb), 0);
    }

    unsafe extern "C" fn on_accept(arg: *mut c_void, new: *mut tcp_pcb, _err: err_t) -> err_t {
        let shared = &mut *arg.cast::<Shared>();
        shared.accepted = new;
        tcp_arg(new, arg);
        tcp_recv(new, Some(on_server_recv));
        0
    }

    unsafe extern "C" fn on_server_recv(
        arg: *mut c_void,
        tpcb: *mut tcp_pcb,
        p: *mut pbuf,
        _err: err_t,
    ) -> err_t {
        let shared = &mut *arg.cast::<Shared>();
        if p.is_null() {
            shared.server_saw_end = true;
            tcp_close(tpcb);
            return 0;
        }
        shared.server_got.extend(take(tpcb, p));
        send(tpcb, b"pong");
        0
    }

    unsafe extern "C" fn on_connected(arg: *mut c_void, tpcb: *mut tcp_pcb, _err: err_t) -> err_t {
        (*arg.cast::<Shared>()).connected = true;
        send(tpcb, b"ping");
        0
    }

    unsafe extern "C" fn on_client_recv(
        arg: *mut c_void,
        tpcb: *mut tcp_pcb,
        p: *mut pbuf,
        _err: err_t,
    ) -> err_t {
        let shared = &mut *arg.cast::<Shared>();
        if p.is_null() {
            return 0;
        }
        shared.client_got.extend(take(tpcb, p));
        // Got the answer: end this side of the connection.
        tcp_close(tpcb);
        0
    }

    #[test]
    fn a_connection_over_loopback_carries_bytes_both_ways_and_closes() {
        let _lwip = crate::serial::lwip();
        let mut shared = Box::new(Shared {
            connected: false,
            accepted: core::ptr::null_mut(),
            server_got: Vec::new(),
            client_got: Vec::new(),
            server_saw_end: false,
        });
        let arg: *mut c_void = (&mut *shared as *mut Shared).cast();
        unsafe {
            let listener = tcp_new();
            assert!(!listener.is_null(), "tcp_new returned NULL");
            assert_eq!(tcp_bind(listener, core::ptr::null(), PORT), 0);
            let listener = tcp_listen_with_backlog(listener, 1);
            assert!(!listener.is_null(), "tcp_listen found no memory");
            tcp_arg(listener, arg);
            tcp_accept(listener, Some(on_accept));

            let client = tcp_new();
            assert!(!client.is_null());
            tcp_arg(client, arg);
            tcp_recv(client, Some(on_client_recv));
            let loopback = ip_addr_t {
                addr: u32::from_ne_bytes([127, 0, 0, 1]),
            };
            assert_eq!(tcp_connect(client, &loopback, PORT, Some(on_connected)), 0);

            // The explicit poll of a NO_SYS node: frames the loopback netif queued, then timers.
            for _ in 0..2_000 {
                netif_poll_all();
                sys_check_timeouts();
                // The client closes after the answer (lwIP drops its callbacks then), so the end
                // that is seen is the server's.
                if shared.server_saw_end {
                    break;
                }
            }
        }
        assert!(shared.connected, "the connect completed");
        assert!(!shared.accepted.is_null(), "the listener accepted it");
        assert_eq!(
            shared.server_got, b"ping",
            "the server received the request"
        );
        assert_eq!(shared.client_got, b"pong", "the client received the answer");
        assert!(shared.server_saw_end, "the server saw the client close");
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
        let _lwip = crate::serial::lwip();
        unsafe {
            let pcb = udp_new();
            assert!(!pcb.is_null(), "udp_new returned NULL");
            udp_remove(pcb);
        }
    }
}
