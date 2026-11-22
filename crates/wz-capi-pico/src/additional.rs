// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `wz_ext_additional_interface`: the version of the extension interface the doors of the
//! additional features were built against, and whether the core they run over answers one they
//! run on.
//!
//! The doors are one library with the core in the default build and a library of their own in
//! the split one (`docs/capi-pico-additional-library.md`). In the split build the two may come
//! from different builds, so a program can ask the doors which interface they need: this door
//! writes it and compares it with what the core answers (`wz_ext_interface_version`). The same
//! comparison is made by the system's loader for the major version, because this door calls the
//! function named by it (`wz_ext_interface_major_1`), so a library built apart is not loaded
//! over a core of another major version at all.

use core::mem::size_of;

use crate::ext_interface::{
    wz_ext_interface_major_1, wz_ext_interface_version, wz_ext_interface_version_t,
    WZ_EXT_INTERFACE_MAJOR, WZ_EXT_INTERFACE_MINOR,
};
use crate::ffi::guarded;
use crate::result::{ZResult, WZ_EXT_ERR_UNSUPPORTED, Z_EINVAL, Z_ERR_NULL, Z_OK};

/// Write the version of the extension interface the doors of the additional features were built
/// against into `out`, whose `struct_size` the caller has set, and compare it with the core's.
///
/// Returns `Z_OK` when the core answers the same major version and the same or a later minor
/// one; `WZ_EXT_ERR_UNSUPPORTED` when it does not, with `out` written all the same, so the
/// program can say which version was needed. `Z_ERR_NULL` for a null `out`; `Z_EINVAL` when
/// `struct_size` is smaller than the struct of this version, and nothing is written.
///
/// # Safety
/// `out` is null or valid and writable for `struct_size` bytes.
#[no_mangle]
pub unsafe extern "C" fn wz_ext_additional_interface(
    out: *mut wz_ext_interface_version_t,
) -> ZResult {
    guarded(|| {
        if out.is_null() {
            return Z_ERR_NULL;
        }
        let size = size_of::<wz_ext_interface_version_t>();
        if !usize::try_from((*out).struct_size).is_ok_and(|stated| stated >= size) {
            return Z_EINVAL;
        }
        // The struct is 8 bytes.
        let written = size as u32;
        *out = wz_ext_interface_version_t {
            struct_size: written,
            major: WZ_EXT_INTERFACE_MAJOR,
            minor: WZ_EXT_INTERFACE_MINOR,
        };
        let mut answered = wz_ext_interface_version_t {
            struct_size: written,
            major: 0,
            minor: 0,
        };
        let code = wz_ext_interface_version(&mut answered);
        if code != Z_OK {
            return code;
        }
        let needed = (WZ_EXT_INTERFACE_MAJOR, WZ_EXT_INTERFACE_MINOR);
        if wz_ext_interface_major_1() != WZ_EXT_INTERFACE_MAJOR
            || !runs_on(needed, (answered.major, answered.minor))
        {
            return WZ_EXT_ERR_UNSUPPORTED;
        }
        Z_OK
    })
}

/// The rows the process's runtime lends each machine a door makes, as the core reports them
/// (`wz_ext_interface_runtime_facts`), for the door that makes one: from then on the process's
/// limits are taken.
#[cfg(any(feature = "e2e-supervision", feature = "message-catalog"))]
pub(crate) fn runtime_facts() -> Result<crate::ext_interface::wz_ext_runtime_facts_t, ZResult> {
    use crate::ext_interface::{wz_ext_interface_runtime_facts, wz_ext_runtime_facts_t};

    // SAFETY: the struct is integers alone, for which every byte pattern is a value.
    let mut facts: wz_ext_runtime_facts_t = unsafe { core::mem::zeroed() };
    // The struct is a few dozen bytes.
    facts.struct_size = size_of::<wz_ext_runtime_facts_t>() as u32;
    // SAFETY: a local the door may write, its size stated.
    match unsafe { wz_ext_interface_runtime_facts(&mut facts) } {
        Z_OK => Ok(facts),
        code => Err(code),
    }
}

/// Whether doors built against the interface version `needed` (major, minor) run over a core that
/// answers `answered`: the same major version, and the same minor version or a later one.
fn runs_on(needed: (u16, u16), answered: (u16, u16)) -> bool {
    answered.0 == needed.0 && answered.1 >= needed.1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_doors_run_over_the_core_they_were_built_with() {
        let mut needed = wz_ext_interface_version_t {
            struct_size: 8,
            major: 9,
            minor: 9,
        };
        // SAFETY: a local the door may write.
        assert_eq!(unsafe { wz_ext_additional_interface(&mut needed) }, Z_OK);
        assert_eq!(
            needed,
            wz_ext_interface_version_t {
                struct_size: 8,
                major: WZ_EXT_INTERFACE_MAJOR,
                minor: WZ_EXT_INTERFACE_MINOR,
            }
        );
    }

    #[test]
    fn a_core_of_the_same_major_and_no_older_minor_version_is_one_the_doors_run_on() {
        assert!(runs_on((1, 0), (1, 0)));
        assert!(
            runs_on((1, 2), (1, 3)),
            "a later minor version adds, so it runs"
        );
        assert!(
            !runs_on((1, 2), (1, 1)),
            "an older minor version lacks what was added"
        );
        assert!(!runs_on((1, 0), (2, 0)), "another major version is refused");
        assert!(!runs_on((2, 0), (1, 9)), "another major version is refused");
    }

    #[test]
    fn no_struct_and_a_struct_too_small_are_refused_and_nothing_is_written() {
        let stale = wz_ext_interface_version_t {
            struct_size: 7,
            major: 9,
            minor: 9,
        };
        let mut needed = stale;
        // SAFETY: a local the door may write, and a null pointer.
        unsafe {
            assert_eq!(wz_ext_additional_interface(&mut needed), Z_EINVAL);
            assert_eq!(
                wz_ext_additional_interface(core::ptr::null_mut()),
                Z_ERR_NULL
            );
        }
        assert_eq!(needed, stale);
    }

    #[test]
    fn a_later_caller_s_larger_struct_is_told_how_much_was_written() {
        #[repr(C)]
        struct Later {
            version: wz_ext_interface_version_t,
            added: u32,
        }
        let mut later = Later {
            version: wz_ext_interface_version_t {
                struct_size: size_of::<Later>() as u32,
                major: 0,
                minor: 0,
            },
            added: 0x5eed_5eed,
        };
        // SAFETY: the caller's struct is writable for the size it states.
        assert_eq!(
            unsafe { wz_ext_additional_interface(&mut later.version) },
            Z_OK
        );
        assert_eq!(later.version.struct_size, 8);
        assert_eq!(
            later.added, 0x5eed_5eed,
            "a field this version has not is untouched"
        );
    }
}
