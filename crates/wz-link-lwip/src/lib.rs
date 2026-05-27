// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

#![no_std]
// R311az-3b-ii — crate-level real-build gate.
//
// The `lwip_real_build` cfg is set by this crate's build.rs based on
// `DEP_LWIP_LWIP_REAL_BUILD` (re-exposed by lwip-sys's `links =
// "lwip"` metadata). lwip-sys emits the value as:
//
//   - host build:                     lwip_real_build set (=1)
//   - cross + WZ_LWIP_PORT set:       lwip_real_build set (=1)
//   - cross + WZ_LWIP_PORT unset:     lwip_real_build NOT set (=0)
//
// When unset, the entire crate body collapses to an empty rlib so
// downstreams (wz facade with `runtime-lwip`) can compile on bare-
// metal targets without a deploy port; the visible link tier on
// such builds is empty, but `cargo check` / `cargo build` succeed.
// When set, the real `LwipLink` + `LwipUdpSocket` are exposed and
// reference the real lwip-sys FFI symbols.
//
// Replaces R311az-3a's `cfg(not(target_os = "none"))` gate: cross +
// WZ_LWIP_PORT now exercises this crate end-to-end (preset-cortex-
// m4-default truthfulness full closure path).
#![cfg(lwip_real_build)]

//! wz-link-lwip — Phase W §5.C link tier; lwIP raw UDP API wrap.
//!
//! R311az-2 surface: [`LwipLink`] owns top-level `lwip_init` + the
//! loopback netif lifecycle; [`LwipUdpSocket`] wraps one `udp_pcb`
//! and bridges the raw-API recv callback into a bounded
//! `heapless::spsc::Queue<Datagram, 8>` per R311az-pre D4.
//!
//! ## Lifecycle expectations
//!
//! - `LwipLink::init()` calls `lwip_init` once per process. Multiple
//!   `LwipLink::init` calls are idempotent in the sense that
//!   `lwip_init` is safe to call twice (it re-runs the module inits;
//!   stats counters reset), but production deploys instantiate one
//!   `LwipLink` at boot and keep it alive for the lifetime of the
//!   binary.
//! - `LwipUdpSocket::bind(&link, port)` allocates a `Pin<Box<Inner>>`,
//!   creates the `udp_pcb`, binds to `IP_ADDR_ANY:port`, and registers
//!   the recv callback with the Inner's pinned address as the
//!   callback's `recv_arg`. Drop reverses the registration before
//!   removing the pcb so the dangling-arg window never opens.
//!
//! ## Callback safety (R311az-pre D4 + D5)
//!
//! The lwIP `udp_recv` callback runs in main-loop / ISR context on
//! the MCU; on the host smoke it runs synchronously inside
//! `netif_poll_all()` invoked from the test thread. In both cases
//! the model is single-threaded cooperative: the application thread
//! is not concurrently borrowing `&mut Inner` while the callback
//! mutates it. The unsafe cast `(arg as *mut Inner) -> &mut Inner`
//! is therefore well-formed under the NO_SYS=1 invariant.

extern crate alloc;

use alloc::boxed::Box;
use core::ffi::c_void;
use core::marker::PhantomPinned;
use core::pin::Pin;
use core::ptr::NonNull;
use heapless::spsc::Queue;
use heapless::Vec;

use lwip_sys::{
    err_enum_t_ERR_OK, ip_addr_t, lwip_init, netif_poll_all, pbuf, pbuf_alloc, pbuf_copy_partial,
    pbuf_free, pbuf_layer_PBUF_TRANSPORT, pbuf_take, pbuf_type_PBUF_RAM, sys_check_timeouts, u16_t,
    udp_bind, udp_new, udp_pcb, udp_recv, udp_remove, udp_sendto,
};

/// Maximum UDP datagram payload captured per receive (R311az-pre D4
/// per-link bounded shape). Sized to the standard 1500-byte Ethernet
/// MTU minus IP+UDP overhead, rounded up to a power of two for
/// `heapless::Vec` alignment friendliness.
pub const MAX_DATAGRAM: usize = 1500;

/// Default per-socket receive queue depth (R311az-pre D4: overflow
/// drops with a counter on `LwipUdpSocket::rx_drop_count`). The
/// eight-slot depth matches the lwipopts.h `MEMP_NUM_PBUF` value so
/// the queue and the pbuf pool can't deadlock each other under
/// sustained back-pressure. R311bq promoted from private to public
/// so deploys with tighter SRAM budgets can instantiate
/// `LwipUdpSocket<N, Q>` with a smaller `Q`.
pub const RX_QUEUE_DEPTH: usize = 8;

/// A received UDP datagram captured by the recv callback and routed
/// to the application via `LwipUdpSocket::try_recv`.
///
/// R311bq made the payload capacity a const generic so deploys with a
/// 16 KB SRAM budget (microbit / nrf51-class) can shrink the in-queue
/// footprint by picking a smaller `N`. The default `N = MAX_DATAGRAM`
/// (1500) preserves the R311az-2 public surface for callers that do
/// not name the generic.
#[derive(Debug, Clone)]
pub struct Datagram<const N: usize = MAX_DATAGRAM> {
    /// Payload bytes (length up to `N`).
    pub data: Vec<u8, N>,
    /// Source IPv4 address as lwIP stores it (network byte order in
    /// memory; treat as opaque u32 + format via `Ipv4Addr::from(...)`
    /// or by manual byte extraction).
    pub src_addr: u32,
    /// Source UDP port in host byte order.
    pub src_port: u16,
}

/// Errors that surface from the link layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkError {
    /// `udp_new` returned NULL — out of `MEMP_NUM_UDP_PCB`.
    PcbExhausted,
    /// `udp_bind` returned a non-OK lwIP err_t.
    BindFailed(i8),
    /// `udp_sendto` returned a non-OK lwIP err_t.
    SendFailed(i8),
    /// pbuf allocation failure on the TX path.
    PbufAlloc,
}

/// Top-level link handle. Owns the `lwip_init` + netif state for the
/// process; one instance per deploy. Drop is a no-op at R311az-2
/// because lwIP has no "deinit" entry point; the process exit reclaims.
pub struct LwipLink {
    _no_send_sync: core::marker::PhantomData<*mut ()>,
}

impl LwipLink {
    /// Initialise lwIP. Calls `lwip_init` and lets `netif_init` set
    /// up the loopback netif (LWIP_HAVE_LOOPIF + LWIP_NETIF_LOOPBACK
    /// in lwipopts.h). After this returns, `127.0.0.1` is routable.
    ///
    /// # Safety / re-entry
    ///
    /// Calling `init()` twice from a single thread is safe (lwIP's
    /// `lwip_init` is idempotent in the sense that it re-runs each
    /// module's init; counters reset). Concurrent calls from
    /// different threads are NOT supported — the NO_SYS=1 build is
    /// single-threaded by contract.
    pub fn init() -> Self {
        // SAFETY: lwip_init is C-level idempotent under NO_SYS=1; the
        // call sequence has no external preconditions.
        unsafe { lwip_init() };
        Self {
            _no_send_sync: core::marker::PhantomData,
        }
    }

    /// Drain the loopback netif's output queue into the ip_input
    /// path. Required after every TX to localhost for the recv
    /// callback to actually fire (LWIP_NETIF_LOOPBACK_MULTITHREADING=0
    /// defers the input on the sender thread).
    pub fn poll_loopback(&self) {
        // SAFETY: netif_poll_all walks lwIP's static loop_netif state;
        // no aliasing borrow exists in this single-thread model.
        unsafe { netif_poll_all() };
    }

    /// Pump expired lwIP timers (ARP retransmit, TCP slow timer, etc.).
    /// UDP-only configurations still need this if any timer-driven
    /// module is enabled (LWIP_ARP + LWIP_ICMP in our lwipopts).
    pub fn check_timeouts(&self) {
        // SAFETY: sys_check_timeouts walks lwIP's static timer list.
        unsafe { sys_check_timeouts() };
    }
}

// Inner state shared between the recv callback and the application
// thread. Pinned via Pin<Box<Inner<N, Q>>> on the LwipUdpSocket; the
// callback receives a `*mut Inner<N, Q>` as the udp_pcb's `recv_arg`.
// R311bq: const-generic over the datagram payload capacity `N` and the
// rx queue slot count `Q` so deploys can shrink the in-queue footprint
// when SRAM is tight (microbit 16 KB picks `<128, 2>` ~= 280 bytes
// versus the default `<1500, 8>` ~= 12 KB).
struct Inner<const N: usize, const Q: usize> {
    pcb: NonNull<udp_pcb>,
    rx_queue: Queue<Datagram<N>, Q>,
    rx_drops: u32,
    _pin: PhantomPinned,
}

// Inner is referenced only by the lwIP single-thread cooperative
// model; the raw-pointer field rules out automatic Send/Sync. We
// keep the marker explicit for clarity.
unsafe impl<const N: usize, const Q: usize> Send for Inner<N, Q> {}

/// A UDP socket wrapping a single lwIP `udp_pcb`. Owns its receive
/// queue via `Pin<Box<Inner<N, Q>>>`; Drop unregisters the callback
/// before removing the pcb.
///
/// R311bq parameters:
/// - `N` — per-datagram payload capacity in bytes. Default
///   [`MAX_DATAGRAM`] (1500 — Ethernet MTU minus IP+UDP). Slim deploys
///   pick a smaller `N` to match the application's known payload size.
/// - `Q` — receive queue slot count. Default [`RX_QUEUE_DEPTH`] (8 —
///   matches lwipopts.h `MEMP_NUM_PBUF`). Slim deploys with single-
///   inflight echo semantics pick `Q = 1` or `Q = 2`.
///
/// The default `LwipUdpSocket` (no turbofish) keeps the R311az-2 shape
/// for code that does not need to slim the footprint.
pub struct LwipUdpSocket<const N: usize = MAX_DATAGRAM, const Q: usize = RX_QUEUE_DEPTH> {
    inner: Pin<Box<Inner<N, Q>>>,
}

unsafe extern "C" fn recv_thunk<const N: usize, const Q: usize>(
    arg: *mut c_void,
    _pcb: *mut udp_pcb,
    p: *mut pbuf,
    addr: *const ip_addr_t,
    port: u16_t,
) {
    // SAFETY: `arg` is the same `*mut Inner<N, Q>` we passed to
    // udp_recv when binding; Inner is `Pin<Box<...>>`-stable and the
    // NO_SYS=1 cooperative model guarantees no concurrent borrow. Each
    // (N, Q) monomorphisation gets its own fn pointer; lwIP receives
    // the correct one because `bind` passes `recv_thunk::<N, Q>`.
    let inner = unsafe { &mut *(arg as *mut Inner<N, Q>) };

    if p.is_null() {
        return;
    }

    // lwIP doc note: `addr` may point into the pbuf chain, so read it
    // BEFORE we copy + free the pbuf. The IPv4 word is a plain u32
    // and is copied by value here.
    let src_addr = if addr.is_null() {
        0
    } else {
        // SAFETY: addr non-null and points to a valid ip_addr_t while
        // p is live; we copy the u32 by value.
        unsafe { (*addr).addr }
    };

    // SAFETY: pbuf 'p' is owned by the callback per lwIP contract;
    // tot_len is the total chained payload length in bytes.
    let len = unsafe { (*p).tot_len as usize };
    let copy_len = core::cmp::min(len, N);
    let mut data: Vec<u8, N> = Vec::new();
    if data.resize_default(copy_len).is_ok() {
        // SAFETY: data has `copy_len` initialised bytes;
        // pbuf_copy_partial writes exactly that many.
        unsafe {
            pbuf_copy_partial(p, data.as_mut_ptr() as *mut c_void, copy_len as u16, 0);
        }
    }
    // SAFETY: caller-owned pbuf; we always free exactly once.
    unsafe {
        pbuf_free(p);
    }

    let datagram = Datagram::<N> {
        data,
        src_addr,
        src_port: port,
    };
    if inner.rx_queue.enqueue(datagram).is_err() {
        inner.rx_drops = inner.rx_drops.saturating_add(1);
    }
}

impl<const N: usize, const Q: usize> LwipUdpSocket<N, Q> {
    /// Bind a fresh UDP pcb to `IP_ADDR_ANY:port`. Registers the recv
    /// callback so incoming datagrams enqueue into the per-socket
    /// receive queue.
    ///
    /// # Errors
    ///
    /// - [`LinkError::PcbExhausted`] if `udp_new` returns NULL
    ///   (`MEMP_NUM_UDP_PCB` exhausted; bump the pool in lwipopts.h).
    /// - [`LinkError::BindFailed`] if `udp_bind` rejects the port
    ///   (e.g. already in use within the lwIP stack).
    pub fn bind(_link: &LwipLink, port: u16) -> Result<Self, LinkError> {
        let mut inner: Pin<Box<Inner<N, Q>>> = Box::pin(Inner {
            pcb: NonNull::dangling(),
            rx_queue: Queue::new(),
            rx_drops: 0,
            _pin: PhantomPinned,
        });

        // SAFETY: udp_new is a no-arg allocator from MEMP_NUM_UDP_PCB.
        let pcb_raw = unsafe { udp_new() };
        let Some(pcb) = NonNull::new(pcb_raw) else {
            return Err(LinkError::PcbExhausted);
        };

        // IPv4 ANY = 0.0.0.0 (network order is the same all-zeros).
        let any: ip_addr_t = ip_addr_t { addr: 0 };
        // SAFETY: pcb is valid, &any lifetime spans the call.
        let bind_err = unsafe { udp_bind(pcb.as_ptr(), &any, port) };
        if bind_err as core::ffi::c_int != err_enum_t_ERR_OK {
            // SAFETY: pcb was freshly allocated; remove releases it.
            unsafe { udp_remove(pcb.as_ptr()) };
            return Err(LinkError::BindFailed(bind_err));
        }

        // Wire the recv callback. We pin the Inner first so the arg
        // ptr is stable, then take its raw address.
        // SAFETY: Inner is pinned; we mutate only the pcb field.
        let inner_mut = unsafe { Pin::get_unchecked_mut(inner.as_mut()) };
        inner_mut.pcb = pcb;
        let arg = inner_mut as *mut Inner<N, Q> as *mut c_void;
        // SAFETY: pcb valid, callback fn valid, arg valid for inner's
        // lifetime. The monomorphised `recv_thunk::<N, Q>` matches the
        // `Inner<N, Q>` cast inside the callback.
        unsafe { udp_recv(pcb.as_ptr(), Some(recv_thunk::<N, Q>), arg) };

        Ok(Self { inner })
    }

    /// Send a datagram to `dst_addr:dst_port`. `dst_addr` is treated
    /// as already in network byte order (matching lwIP's
    /// `ip4_addr_t::addr` shape). For convenience constructors see
    /// [`ipv4_addr_loopback`] and [`ipv4_addr_from_octets`].
    pub fn send_to(
        &mut self,
        dst_addr: u32,
        dst_port: u16,
        payload: &[u8],
    ) -> Result<(), LinkError> {
        let len = payload.len().min(N) as u16;
        // SAFETY: pbuf_alloc returns owned pbuf chain or null.
        let p = unsafe { pbuf_alloc(pbuf_layer_PBUF_TRANSPORT, len, pbuf_type_PBUF_RAM) };
        if p.is_null() {
            return Err(LinkError::PbufAlloc);
        }

        // SAFETY: p valid + capacity `len`; payload ptr valid + len.
        let take_err = unsafe { pbuf_take(p, payload.as_ptr() as *const c_void, len) };
        if take_err as core::ffi::c_int != err_enum_t_ERR_OK {
            // SAFETY: free the pbuf we just allocated.
            unsafe { pbuf_free(p) };
            return Err(LinkError::SendFailed(take_err));
        }

        let dst: ip_addr_t = ip_addr_t { addr: dst_addr };
        // SAFETY: pcb valid (Inner owns it), p valid, &dst lifetime spans call.
        let send_err = unsafe { udp_sendto(self.inner.pcb.as_ptr(), p, &dst, dst_port) };
        // pbuf is freed by udp_sendto on success; only free on err.
        if send_err as core::ffi::c_int != err_enum_t_ERR_OK {
            // SAFETY: free the pbuf the stack didn't take ownership of.
            unsafe { pbuf_free(p) };
            return Err(LinkError::SendFailed(send_err));
        }
        Ok(())
    }

    /// Non-blocking dequeue from the per-socket receive queue. Returns
    /// `None` if no datagram has arrived since the last call (callers
    /// must drive the lwIP input path via `LwipLink::poll_loopback`
    /// or — on the MCU — netif RX driver callbacks before re-trying).
    pub fn try_recv(&mut self) -> Option<Datagram<N>> {
        // SAFETY: Pin<Box<Inner<N, Q>>> stable; mutable borrow scoped
        // here.
        let inner = unsafe { Pin::get_unchecked_mut(self.inner.as_mut()) };
        inner.rx_queue.dequeue()
    }

    /// Number of datagrams dropped because the receive queue was full
    /// when the callback fired. R311az-pre D4 overflow accounting.
    pub fn rx_drop_count(&self) -> u32 {
        self.inner.rx_drops
    }
}

impl<const N: usize, const Q: usize> Drop for LwipUdpSocket<N, Q> {
    fn drop(&mut self) {
        // Order: clear callback before removing pcb so a packet
        // arriving mid-drop doesn't dispatch into a free'd Inner.
        // SAFETY: pcb valid; clearing recv with None+null is the lwIP
        // documented teardown sequence.
        unsafe {
            udp_recv(self.inner.pcb.as_ptr(), None, core::ptr::null_mut());
            udp_remove(self.inner.pcb.as_ptr());
        }
    }
}

/// Build a lwIP `ip4_addr_t::addr` u32 from a `[a, b, c, d]` IPv4
/// dotted-quad. The output is in lwIP's network byte order so it can
/// be passed straight to `LwipUdpSocket::send_to`.
#[inline]
pub fn ipv4_addr_from_octets(octets: [u8; 4]) -> u32 {
    u32::from_le_bytes(octets)
}

/// 127.0.0.1 as a lwIP-native u32 word.
#[inline]
pub fn ipv4_addr_loopback() -> u32 {
    ipv4_addr_from_octets([127, 0, 0, 1])
}

#[cfg(test)]
mod smoke {
    //! R311az-2 host smoke: bind a UDP socket to a port, send a
    //! datagram to 127.0.0.1 on the same port, drain the loopback
    //! netif, and verify the recv callback delivers the datagram into
    //! the per-socket queue.
    //!
    //! This proves the four R311az-pre D-decisions that R311az-2
    //! lands: D2 raw udp_* API, D3 lwip-sys FFI surface, D4 mpsc
    //! bridge with overflow drop, D5 cooperative poll-driven recv.

    extern crate std;
    use super::*;

    #[test]
    fn loopback_echo_one_packet() {
        let link = LwipLink::init();
        let port: u16 = 12345;
        // R311bq: `LwipUdpSocket` (no turbofish) resolves to the
        // default generic args `<MAX_DATAGRAM, RX_QUEUE_DEPTH>`.
        let mut sock: LwipUdpSocket = LwipUdpSocket::bind(&link, port).expect("bind ANY:12345");

        let payload: &[u8] = b"hello-r311az-2";
        sock.send_to(ipv4_addr_loopback(), port, payload)
            .expect("send_to 127.0.0.1");
        // Drain the loopback netif's output queue into ip_input.
        link.poll_loopback();
        link.check_timeouts();

        let dg = sock.try_recv().expect("expected one datagram");
        std::assert_eq!(&dg.data[..], payload);
        std::assert_eq!(dg.src_port, port);
        std::assert_eq!(dg.src_addr, ipv4_addr_loopback());
        std::assert_eq!(sock.rx_drop_count(), 0);
    }
}
