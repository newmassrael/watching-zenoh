// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The SONAME of the pico C library (`wz_cdylib_build` holds the reason and the platform rule), and
//! on an MSVC target linked by the toolchain's own linker the import libraries of the system
//! libraries its graph names, so the DLL links without Visual Studio or a Windows SDK. It runs
//! again, and so the library is linked again, when a linker script a link of it reads changes.

use wz_cdylib_build::{Import, SystemLibrary};

/// The system libraries a crate of the library's graph names by `#[link(name = ...)]` rather than
/// importing by DLL name, with what the graph calls of each: `getrandom` 0.2 (the session id of the
/// SCE runtime, the library's own random fill) names `bcrypt` for `BCryptGenRandom` and
/// `advapi32` for `SystemFunction036` (`RtlGenRandom`) in its Windows source (`src/windows.rs`).
/// Every other system call of the graph names its DLL itself (`windows-sys`, `raw-dylib`), and the
/// package's check of the DLL's imports (`scripts/lib/pico_windows_package.py`) refuses a DLL this
/// list and those do not account for.
const NAMED_SYSTEM_LIBRARIES: &[SystemLibrary] = &[
    SystemLibrary {
        name: "bcrypt",
        dll: "bcrypt.dll",
        functions: &[Import {
            name: "BCryptGenRandom",
            stack_bytes: 16,
        }],
    },
    SystemLibrary {
        name: "advapi32",
        dll: "advapi32.dll",
        functions: &[Import {
            name: "SystemFunction036",
            stack_bytes: 8,
        }],
    },
];

/// The linker scripts a link of the library may read, from this package's directory
/// (`crates/.cargo/capi-discard-unwind-tables.toml`, `crates/.cargo/capi-run-text.toml`): the
/// compiler hands a script to the linker by its path and cargo tracks no file it did not compile,
/// so a script written again, a new run-text list, would leave the library linked by the old one.
const LINK_SCRIPTS: &[&str] = &[
    "../wz-capi-pico/link/discard-unwind-tables.ld",
    "../wz-capi-pico/link/run-text.ld",
];

fn main() {
    wz_cdylib_build::emit_soname("wz_capi_pico");
    wz_cdylib_build::emit_link_without_sdk(NAMED_SYSTEM_LIBRARIES);
    for script in LINK_SCRIPTS {
        println!("cargo:rerun-if-changed={script}");
    }
}
