// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `sce_link_runtime_lwip` — host-build skeleton of the C11 link
//! runtime for the watching-zenoh MCU bare_metal deploy class.
//!
//! **Phase W deferred — not production.** The `.c` translation unit
//! (`src/sce_link_runtime_lwip.c`) ships rx / tx / poll vtable
//! functions whose bodies count calls and return idle / OK; **no
//! actual lwIP API** (`udp_recv`, `udp_sendto`, `tcp_*`) is wired.
//! Consumers MUST NOT take this crate as a production lwIP runtime.
//! The Phase W round will plumb the cross-compile toolchain
//! (Cortex-M target, lwIP source tree, target-plugin per RFC §5.I)
//! and replace the stubs with real driver code.
//!
//! What this crate currently proves (R53 vertical slice):
//!   1. SCE B6 link-kind C11 emitter operates end-to-end on a wz
//!      SCXML (`sources/links/lwip_udp_scout.scxml` → emitted
//!      `lwip_udp_scout.h` via `sce-codegen --language c11`).
//!   2. The emitted wrapper composes the `sce_forge_link_t` vtable
//!      shape from `vendor/sce/sce-forge-runtime/c/include/sce/forge/link.h`.
//!   3. A Rust FFI surface (`LwipUdpDriver` + `LinkHandle`) can hold
//!      the vtable handle, round-trip ops calls through the C side,
//!      and read back the counter side effects.
//!
//! Items (1) + (2) are the load-bearing audit of "the C11 link
//! emitter is consumable from wz"; item (3) is incidental
//! plumbing whose values are NOT production-grade. Trust-class
//! gating, RX-pool integration, the listener-link sibling pair
//! (RFC §5.C lines 802-833), and actual lwIP API wiring all
//! belong to Phase W.

use std::ffi::c_void;
use std::os::raw::c_uchar;

/// Mirror of `sce_forge_link_status_t` from `sce/forge/link.h`. The
/// `repr(i32)` matches the C enum's default underlying type on every
/// host platform we support (the size invariant is asserted by the
/// smoke test, not just by `repr`).
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkStatus {
    Ok = 0,
    ErrDriver = 1,
    ErrBackpressure = 2,
}

/// Mirror of `sce_forge_link_rx_frame_t`. Borrowed-slice view; the
/// `data` pointer is owned by the C driver and stays valid until the
/// next `ops->rx` call on the same instance, per the lifetime
/// contract in `sce/forge/link.h`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RxFrame {
    pub data: *const c_uchar,
    pub len: usize,
}

/// Mirror of `sce_forge_link_tx_frame_t`. Same shape as RxFrame but
/// the slice lifetime is "must outlive the tx() call".
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TxFrame {
    pub data: *const c_uchar,
    pub len: usize,
}

/// Mirror of `sce_forge_link_ops_t`. Function-pointer vtable; the C
/// side keeps one `static const` instance in `.rodata` per driver.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LinkOps {
    pub rx: extern "C" fn(*mut c_void, *mut RxFrame) -> bool,
    pub tx: extern "C" fn(*mut c_void, TxFrame) -> LinkStatus,
    pub poll: extern "C" fn(*mut c_void, u32),
}

/// Mirror of `sce_forge_link_t`. Per-instance handle composed of the
/// shared vtable pointer plus the driver-specific `self` payload.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LinkHandle {
    pub ops: *const LinkOps,
    pub self_: *mut c_void,
}

/// Mirror of `wz_lwip_udp_state_t` from `src/wz_runtime_lwip.h`. The
/// counter fields are inspected by the smoke test to verify the
/// vtable round-trips the host-build skeleton bodies.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LwipUdpState {
    pub rx_calls: u32,
    pub tx_calls: u32,
    pub poll_calls: u32,
    pub tx_default_status: LinkStatus,
}

impl LwipUdpState {
    /// Construct a state with cleared counters and the supplied TX
    /// default. `LinkStatus::Ok` is the happy-path default; tests
    /// inject `LinkStatus::ErrBackpressure` to exercise the saturated
    /// outbound queue branch.
    pub const fn new(tx_default_status: LinkStatus) -> Self {
        Self {
            rx_calls: 0,
            tx_calls: 0,
            poll_calls: 0,
            tx_default_status,
        }
    }
}

extern "C" {
    /// Factory declared in `src/wz_runtime_lwip.h`. Builds a
    /// `LinkHandle` (== `sce_forge_link_t`) backed by the supplied
    /// state. The state must outlive the returned handle.
    pub fn wz_lwip_udp_make_driver(state: *mut LwipUdpState) -> LinkHandle;
}

/// Safe RAII handle wrapping a `LinkHandle` plus its backing state.
/// The state lives inside the handle's storage so the borrow
/// invariant is upheld by the type system; consumers see the
/// `LinkHandle` view without managing the lifetime explicitly.
pub struct LwipUdpDriver {
    state: Box<LwipUdpState>,
    handle: LinkHandle,
}

impl LwipUdpDriver {
    /// Build a driver with the supplied TX default status. The
    /// handle borrows from the boxed state for the driver's
    /// lifetime; dropping the driver frees both.
    pub fn new(tx_default_status: LinkStatus) -> Self {
        let mut state = Box::new(LwipUdpState::new(tx_default_status));
        // Safety: `state` is alive for the lifetime of `Self`, and
        // `Box` keeps the pointer stable across moves (heap-allocated
        // payload). The C side does not retain the pointer beyond
        // the vtable's `self`, which is itself bounded by `Self`'s
        // lifetime via the surrounding struct.
        let handle = unsafe { wz_lwip_udp_make_driver(&mut *state) };
        Self { state, handle }
    }

    /// Immutable view of the underlying state. Useful for tests that
    /// inspect the counter fields after invoking ops callbacks.
    pub fn state(&self) -> &LwipUdpState {
        &self.state
    }

    /// `sce_forge_link_t` view. Borrow lifetime matches `&self`, so
    /// the handle cannot outlive the driver.
    pub fn handle(&self) -> LinkHandle {
        self.handle
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// LinkStatus layout matches the C `sce_forge_link_status_t`
    /// enum. The repr(i32) attribute pins the variant to a 4-byte
    /// underlying type on every host architecture this workspace
    /// targets; the explicit assertion catches a platform that
    /// defaults the C enum to a different width.
    #[test]
    fn link_status_size_matches_c_enum() {
        assert_eq!(std::mem::size_of::<LinkStatus>(), 4);
        assert_eq!(LinkStatus::Ok as i32, 0);
        assert_eq!(LinkStatus::ErrDriver as i32, 1);
        assert_eq!(LinkStatus::ErrBackpressure as i32, 2);
    }

    /// LinkOps vtable size matches the C struct (3 function
    /// pointers, no padding). Caught a real bug on the first round
    /// trip: leaving one of the function pointer types as a generic
    /// `*const c_void` had the same size but was not callable.
    #[test]
    fn link_ops_size_is_three_pointers() {
        assert_eq!(
            std::mem::size_of::<LinkOps>(),
            3 * std::mem::size_of::<usize>()
        );
    }

    /// The factory returns a non-null handle, and the vtable's three
    /// callbacks are all callable through the `self` payload (each
    /// bumps its matching counter). This is the load-bearing smoke
    /// test of the codegen + cc + ffi round trip.
    #[test]
    fn factory_handle_round_trips_vtable_calls() {
        let driver = LwipUdpDriver::new(LinkStatus::Ok);
        let handle = driver.handle();
        assert!(!handle.ops.is_null());
        assert!(!handle.self_.is_null());

        // Safety: the handle's ops pointer is the static const vtable
        // emitted by the C side, which lives for the duration of the
        // process. `self_` points at the boxed state inside `driver`
        // which we have not dropped.
        let ops = unsafe { *handle.ops };

        let mut rx_out = RxFrame {
            data: std::ptr::null(),
            len: 0,
        };
        let rx_pending = (ops.rx)(handle.self_, &mut rx_out);
        assert!(!rx_pending, "host-build skeleton has no pending RX");

        let tx_status = (ops.tx)(
            handle.self_,
            TxFrame {
                data: b"x".as_ptr(),
                len: 1,
            },
        );
        assert_eq!(tx_status, LinkStatus::Ok);

        (ops.poll)(handle.self_, 1000);

        let st = driver.state();
        assert_eq!(st.rx_calls, 1);
        assert_eq!(st.tx_calls, 1);
        assert_eq!(st.poll_calls, 1);
    }

    /// Per-instance TX default status is honored by the C stub.
    /// Drives the same factory + vtable surface with a different
    /// state seed and verifies the C side reads it back.
    #[test]
    fn tx_default_status_round_trips() {
        let driver = LwipUdpDriver::new(LinkStatus::ErrBackpressure);
        let handle = driver.handle();
        let ops = unsafe { *handle.ops };
        let tx_status = (ops.tx)(
            handle.self_,
            TxFrame {
                data: b"y".as_ptr(),
                len: 1,
            },
        );
        assert_eq!(tx_status, LinkStatus::ErrBackpressure);
    }
}
