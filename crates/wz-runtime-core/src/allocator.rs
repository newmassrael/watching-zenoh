// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Allocator trait — no_std-friendly heap provider.

use core::alloc::Layout;
use core::ptr::NonNull;

/// Heap-allocation contract for the runtime services tier.
///
/// Distinct from `core::alloc::GlobalAlloc` (the global #\[global_allocator\]
/// hook) and from the unstable `core::alloc::Allocator` (a higher-level
/// API not yet on stable). The reasons for a wz-local trait:
///
/// 1. **Stability**: `core::alloc::Allocator` is nightly-only. wz pins
///    MSRV = 1.75 stable; a stable-trait surface for buffer-pool
///    allocators is the goal here.
/// 2. **Layout-fail propagation**: `core::alloc::GlobalAlloc::alloc`
///    returns a raw `*mut u8` whose null sentinel is the only failure
///    signal; `Option<NonNull<u8>>` makes the failure shape explicit
///    and matches the wz pattern of "no panicking allocator on MCU"
///    (failure is observable, not infallible).
/// 3. **Buffer-pool readiness**: §5.P motivates an Allocator trait so
///    a future round can swap the heap source for a fixed-pool / TLSF
///    allocator on MCU profiles without changing call-sites. The
///    trait method set is minimal here to keep room for that pivot.
///
/// ## Phase W scope
///
/// R251 (this round) ships the trait skeleton with two methods. The
/// crate does not yet provide a concrete impl — that lands alongside
/// the first MCU profile work (Phase W lwIP / embassy round). For the
/// AP profile, the std `GlobalAlloc` is sufficient; wz upper layers
/// continue using `Box` / `Vec` directly until R252+ reparameterises
/// them. No NOP impl is provided per the R63 anti-stub rule — the
/// trait exists so the contract is visible; the first caller that
/// needs it will land the first impl.
///
/// ## Safety
///
/// The `dealloc` method is `unsafe` because the caller must uphold:
/// - `ptr` came from a prior `alloc(layout)` call on the SAME
///   allocator instance (no cross-allocator pointer mixing).
/// - The `layout` parameter on `dealloc` matches the `layout` used
///   on the original `alloc` (size + alignment, exact).
/// - No use-after-free (Rust's ownership system prevents this on the
///   `&mut T` side, but raw pointer flows must respect it manually).
///
/// `alloc` is safe to call; the impl is responsible for thread-safety
/// internally (the trait bounds `Send + Sync`).
pub trait Allocator: Send + Sync {
    /// Allocate `layout.size()` bytes aligned to `layout.align()`.
    /// Returns `None` on out-of-memory; the caller must handle the
    /// failure (MCU profiles surface this back through SCE wire-
    /// budget enforcement paths). The returned pointer is non-null
    /// and uninitialised; the caller MUST not read from it before
    /// writing.
    fn alloc(&self, layout: Layout) -> Option<NonNull<u8>>;

    /// Deallocate the pointer obtained from a prior matching
    /// [`Self::alloc`] call.
    ///
    /// # Safety
    ///
    /// See the trait-level Safety doc.
    unsafe fn dealloc(&self, ptr: NonNull<u8>, layout: Layout);
}
