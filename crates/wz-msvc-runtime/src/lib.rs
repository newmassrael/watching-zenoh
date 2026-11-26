// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The C runtime an MSVC-target library without `std` links in Visual Studio's place.
//!
//! On `x86_64-pc-windows-msvc` and `i686-pc-windows-msvc` the compiler's own code calls what it
//! expects of the C runtime: the memory functions (`memcpy`, `memmove`, `memset`, `memcmp`) and
//! `strlen`, which `core` reads a C string with, the stack probe `__chkstk`, the `_fltused`
//! marker an object that uses floating point names, the DLL's entry `_DllMainCRTStartup`, the
//! language handler `__CxxFrameHandler3` the prebuilt `core`'s unwind tables name, and on x86 the
//! 64-bit division helpers. The toolchain's `compiler_builtins` defines none of them for these
//! targets, where they are the C runtime's: the link of the pico C library with the toolchain's
//! linker and no library of Visual Studio leaves these names unresolved and no other. This crate
//! defines them, so that library links without Visual Studio and imports no C runtime DLL.
//!
//! It is linked by a library without `std` alone (`wz-capi-pico-lib` in a build that does not
//! unwind): a program with `std` links the C runtime, whose entry also starts that runtime, and two
//! definitions of a name would meet. The labels are in `symbols`; the functions they reach are Rust
//! functions under Rust names, which the tests call on any x86 host.
//!
//! `no_builtins`: the copy and fill loops below would otherwise be read by the compiler as the very
//! functions they implement, and call them.

#![no_std]
#![no_builtins]

#[cfg(test)]
extern crate std;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod mem;

#[cfg(target_arch = "x86")]
pub mod div64;

#[cfg(all(
    windows,
    target_env = "msvc",
    any(target_arch = "x86", target_arch = "x86_64")
))]
mod symbols;

#[cfg(all(test, any(target_arch = "x86", target_arch = "x86_64")))]
mod tests;

#[cfg(all(
    windows,
    target_env = "msvc",
    not(any(target_arch = "x86", target_arch = "x86_64"))
))]
compile_error!(
    "wz-msvc-runtime has the C runtime of the x86 and x64 MSVC targets: another MSVC target needs \
     its own memory functions, stack probe and helpers here before a library without std links"
);
