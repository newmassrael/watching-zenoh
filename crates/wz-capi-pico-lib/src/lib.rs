// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The pico C ABI's library: the exports are `wz-capi-pico`'s, and this crate adds what a program
//! without `std` needs from its last Rust crate (`abi::c_library_runtime!`). In the tokio engine's
//! build that is nothing, as that library links `std`.

#![no_std]

// Named, not only reached through the macro, so the ABI crate and its exports are linked in the
// build whose macro expands to nothing.
extern crate abi;

abi::c_library_runtime!();
