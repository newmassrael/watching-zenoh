// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The pico C ABI's library: the exports are `wz-capi-pico`'s, and this crate adds what a program
//! without `std` needs from its last Rust crate (`abi::c_library_runtime!`). In the tokio engine's
//! build that is nothing, as that library links `std`.
//!
//! The library is without `std` in every build that does not unwind, which is every profile it
//! ships with (`capi-nostd`, `capi-small`: `panic = "abort"`). A stable toolchain builds no
//! unwinding artifact without `std` (its personality routine is a lang item only a nightly one
//! defines), so under a profile that unwinds (`dev`, `test`, `release`, `ship`: the workspace's
//! own build and lint of this crate) it links `std`, whose allocator, panic handler and
//! personality routine stand in for the macro's, and the ABI crate's code is compiled as it ships.

#![cfg_attr(panic = "abort", no_std)]

// Named, not only reached through the macro, so the ABI crate and its exports are linked in the
// build whose macro expands to nothing.
extern crate abi;

// `std`'s runtime is linked where the library unwinds, and two panic handlers are refused.
#[cfg(panic = "abort")]
abi::c_library_runtime!();
