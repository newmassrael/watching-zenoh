// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

// Which zenoh-pico platform macro, and which extra clang arguments, a cargo
// TARGET needs for bindgen.
//
// zenoh-pico's `system/common/platform.h` selects its platform header on one of
// the `ZENOH_<PLATFORM>` macros, and CMake defines the right one while it
// configures the C library. bindgen runs clang over the raw headers and never
// sees CMake's definitions, so the build script re-derives the macro from the
// cargo TARGET. This is that derivation, as a module of the crate and not as
// build-script-only code for the reason `cmake_cache` gives: a build script's
// logic is not compiled by `cargo test`, so a decision that lived only there
// could not be tested. `build.rs` includes this file.
//
// Plain `//` comments throughout, because `include!` does not take inner doc
// comments.

/// The platform macro bindgen has to define for `target`, or `None` for a target
/// this crate has no mapping for (which the build script turns into an error
/// that names the target).
pub fn platform_definition(target: &str) -> Option<&'static str> {
    if target.contains("linux") {
        Some("ZENOH_LINUX")
    } else if target.contains("apple-darwin") {
        Some("ZENOH_MACOS")
    } else if target.contains("windows") {
        // `cmake/platforms/windows.cmake` defines it for the library build; bindgen
        // needs it for the same header selection. Added when a hosted Windows run
        // got past the CMake step and the build script stopped on this branch.
        Some("ZENOH_WINDOWS")
    } else {
        None
    }
}

/// Extra clang arguments the pico headers of `target` need beyond the platform
/// macro.
///
/// Windows: pico's `system/platform/windows.h` defines an inline function named
/// `__asm__`, which is an ordinary identifier to MSVC (the compiler pico's own
/// Windows build uses) and a keyword to clang, the compiler bindgen runs. Under
/// the MSVC target clang reports "expected identifier or '('" for it, and bindgen
/// treats an error diagnostic as fatal. The name is rewritten for the parse only,
/// by the preprocessor, to one that does not collide; nothing this crate binds
/// calls that function.
pub fn extra_clang_args(target: &str) -> &'static [&'static str] {
    if target.contains("windows") {
        &["-D__asm__=wz_pico_unused_asm"]
    } else {
        &[]
    }
}

#[cfg(test)]
mod platform_map_tests {
    use super::*;

    #[test]
    fn every_target_this_workspace_builds_on_has_a_platform_macro() {
        for (target, want) in [
            ("x86_64-unknown-linux-gnu", "ZENOH_LINUX"),
            ("aarch64-unknown-linux-gnu", "ZENOH_LINUX"),
            ("aarch64-apple-darwin", "ZENOH_MACOS"),
            ("x86_64-apple-darwin", "ZENOH_MACOS"),
            ("x86_64-pc-windows-msvc", "ZENOH_WINDOWS"),
            ("x86_64-pc-windows-gnu", "ZENOH_WINDOWS"),
        ] {
            assert_eq!(platform_definition(target), Some(want), "{target}");
        }
    }

    #[test]
    fn a_target_with_no_mapping_is_none_and_not_a_guess() {
        assert_eq!(platform_definition("wasm32-unknown-unknown"), None);
        assert_eq!(platform_definition(""), None);
    }

    /// Only Windows needs the rename, and the rename must leave the keyword's own
    /// spelling out of the replacement: a replacement that still contained
    /// `__asm__` would make the macro expand to the keyword again.
    #[test]
    fn only_windows_gets_the_asm_rename_and_it_removes_the_keyword() {
        assert!(extra_clang_args("x86_64-unknown-linux-gnu").is_empty());
        assert!(extra_clang_args("aarch64-apple-darwin").is_empty());
        let windows = extra_clang_args("x86_64-pc-windows-msvc");
        assert_eq!(windows.len(), 1);
        let (name, replacement) = windows[0]
            .strip_prefix("-D")
            .and_then(|d| d.split_once('='))
            .expect("a -DNAME=VALUE argument");
        assert_eq!(name, "__asm__");
        assert!(!replacement.contains("__asm__"), "{replacement}");
    }
}
