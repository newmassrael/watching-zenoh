// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The width of pico's C enums in the structs a C program allocates.
//!
//! A pico option struct holds its congestion control, priority, reliability, locality, target,
//! consolidation and scouting fields as C enums, and a C enum is as wide as the target's C ABI makes
//! it: an `int` on a host, and on an Arm core without an operating system (the AAPCS, which the
//! toolchain of a Zephyr image follows with short enums and records as `Tag_ABI_enum_size: small`)
//! the smallest integer that holds every value, one byte for each of pico's. A field typed `c_int`
//! there makes this crate's struct wider than the program's: a default written over the program's
//! storage runs into its neighbours, and a read takes bytes that are not the field's.
//!
//! The width is read from the compiler, which lays out a `repr(C)` enum as the target's C ABI does,
//! and not stated per target, so a target is right here when rustc knows its ABI.

use core::ffi::c_int;

/// What a C enum of a width is in Rust, for each width a C ABI gives one.
pub trait CEnumWidth {
    /// An enum whose values are all non-negative.
    type Unsigned;
    /// An enum with a negative value.
    type Signed;
}

impl CEnumWidth for [(); 1] {
    type Unsigned = u8;
    type Signed = i8;
}

impl CEnumWidth for [(); 2] {
    type Unsigned = u16;
    type Signed = i16;
}

impl CEnumWidth for [(); 4] {
    type Unsigned = c_int;
    type Signed = c_int;
}

/// The range of pico's enums with no negative value: each of them fits 0 to 7.
#[allow(dead_code)]
#[repr(C)]
enum UnsignedProbe {
    Low = 0,
    High = 7,
}

/// The range of pico's one enum with a negative value (`Z_CONSOLIDATION_MODE_AUTO` is -1).
#[allow(dead_code)]
#[repr(C)]
enum SignedProbe {
    Low = -1,
    High = 7,
}

/// A field of one of pico's enums whose values are all non-negative, as wide as the C ABI makes it.
pub type PicoEnum = <[(); core::mem::size_of::<UnsignedProbe>()] as CEnumWidth>::Unsigned;

/// A field of pico's enum with a negative value, as wide as the C ABI makes it.
pub type PicoSignedEnum = <[(); core::mem::size_of::<SignedProbe>()] as CEnumWidth>::Signed;

// An Arm core without an operating system lays pico's enums out in one byte. A compiler that read
// that ABI otherwise would give the structs a width the program's are not, so it stops the build.
const _: () = assert!(
    !cfg!(all(target_arch = "arm", target_os = "none"))
        || (core::mem::size_of::<PicoEnum>() == 1 && core::mem::size_of::<PicoSignedEnum>() == 1),
    "the AAPCS lays out a small C enum in one byte, and this compiler's repr(C) does not"
);

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn a_pico_enum_field_is_as_wide_as_the_targets_c_enum() {
        assert_eq!(size_of::<PicoEnum>(), size_of::<UnsignedProbe>());
        assert_eq!(size_of::<PicoSignedEnum>(), size_of::<SignedProbe>());
        // A host's C ABI gives a small enum an int, as pico's host builds lay out their structs.
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        {
            assert_eq!(size_of::<PicoEnum>(), size_of::<c_int>());
            assert_eq!(size_of::<PicoSignedEnum>(), size_of::<c_int>());
        }
        let auto: PicoSignedEnum = -1;
        assert!(auto < 0, "the signed enum holds pico's AUTO");
    }
}
