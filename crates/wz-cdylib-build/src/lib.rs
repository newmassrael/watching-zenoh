// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2103 (open-debt item 521) — give a `cdylib` target its SONAME.
//!
//! # The defect this closes
//!
//! Cargo emits a `cdylib` with no `DT_SONAME`. The ELF rule is then that the
//! linker records, in the CONSUMER's `DT_NEEDED`, whatever string it used to
//! find the library — and when the consumer links by PATH, that string is the
//! path. Measured on this tree before the fix:
//!
//! ```text
//! $ cc probe.c /home/…/crates/target/release/libwz_capi_dissect.so -o probe
//! $ readelf -d probe | grep NEEDED
//!   (NEEDED)  Shared library: [/home/…/crates/target/release/libwz_capi_dissect.so]
//! ```
//!
//! That consumer cannot ship what it built. An absolute `DT_NEEDED` is not a
//! search key: the dynamic linker OPENS it, so `RPATH`, `$ORIGIN` and
//! `LD_LIBRARY_PATH` are never consulted, and the binary runs only on a machine
//! that has this build tree at this path. Linking by path is not an exotic
//! consumer either — it is what `target_link_libraries(app /abs/path/lib.so)`
//! generates, which is the ordinary CMake way to consume a prebuilt `.so`.
//!
//! With a SONAME the linker records the SONAME instead, and every one of those
//! search mechanisms works again.
//!
//! # Why this is a crate and not five copies of [`emit_soname`]
//!
//! Five crates in this workspace emit a `cdylib`. The only judgement in the
//! whole helper is [`SONAME_TARGET_OS`] — which platforms take `-soname` — and
//! a judgement duplicated five times is one that will be corrected in fewer
//! than five places. `wz-codegen-build` is the same shape and was created for
//! the same reason, out of three build scripts rather than five.
//!
//! # What is NOT checked here
//!
//! A build script cannot see whether the name it was handed is the name cargo
//! will actually give the artifact: there is no environment variable for the
//! lib TARGET name, only [`CARGO_PKG_NAME`]. So the name is an explicit
//! argument, deliberately, and the agreement between it and the file on disk is
//! `scripts/lib/cdylib_soname_gate.py`'s job — that gate derives the cdylib
//! crates from cargo metadata and reads the SONAME back out of the linked
//! artifact with `readelf`. A helper that guessed and a gate that read the
//! guess would be one statement checked against itself.
//!
//! [`CARGO_PKG_NAME`]: https://doc.rust-lang.org/cargo/reference/environment-variables.html

/// The target operating systems whose linker takes `-Wl,-soname` — i.e. the
/// ones whose shared objects are ELF.
///
/// Anything else is a silent no-op rather than a failure. A `cdylib` crate that
/// is cross-compiled to a platform with a different shared-object format has no
/// defect to fix here, and passing `-soname` to a linker that does not know it
/// turns a supported build into a link error. Mach-O's `-install_name` is the
/// nearest equivalent and is deliberately NOT emitted: nothing in this
/// workspace builds for it, and an untested link argument is a liability rather
/// than a courtesy.
pub const SONAME_TARGET_OS: &[&str] = &[
    "android",
    "dragonfly",
    "freebsd",
    "fuchsia",
    "haiku",
    "illumos",
    "linux",
    "netbsd",
    "openbsd",
    "redox",
    "solaris",
];

/// Emit the link argument that gives this crate's `cdylib` a SONAME of
/// `lib<lib_name>.so`.
///
/// `lib_name` is the crate's LIB TARGET name (the `[lib] name` key, or the
/// package name with `-` replaced by `_` when that key is absent) — i.e. the
/// stem cargo will use for the artifact, without the `lib` prefix or the `.so`
/// suffix. Call it from the `fn main` of the crate's `build.rs`:
///
/// ```no_run
/// wz_cdylib_build::emit_soname("wz_capi_dissect");
/// ```
///
/// (The `fn main` wrapper is left out because clippy's `needless_doctest_main`
/// reds on it and rustdoc supplies one anyway — the five real callers in this
/// workspace are what show the whole file.)
///
/// `cargo:rustc-cdylib-link-arg` is used rather than `rustc-link-arg` because
/// it applies to the `cdylib` target ALONE. Three of the five callers also
/// build an `rlib`, and every one of them is compiled into Rust test binaries
/// and into the `wz` facade; a link argument that reached those would be
/// putting a shared-object name on an executable.
///
/// # Panics
///
/// If `lib_name` is empty, or contains a path separator, `"lib"`-prefix or
/// `.so` suffix that says the caller passed a FILE NAME rather than a target
/// name. A SONAME is baked into every consumer that links the artifact, so a
/// malformed one is worth failing the build over rather than shipping.
pub fn emit_soname(lib_name: &str) {
    assert!(!lib_name.is_empty(), "wz-cdylib-build: empty lib name");
    assert!(
        !lib_name.contains('/') && !lib_name.contains('\\'),
        "wz-cdylib-build: `{lib_name}` looks like a path; pass the lib TARGET name",
    );
    assert!(
        !lib_name.starts_with("lib") && !lib_name.ends_with(".so"),
        "wz-cdylib-build: `{lib_name}` looks like a file name; pass the lib TARGET \
         name, without the `lib` prefix and the `.so` suffix this adds",
    );

    // The caller's build.rs is the only input; without this, cargo re-runs the
    // script whenever any file in the package changes, which is the default and
    // is more than this needs.
    println!("cargo:rerun-if-changed=build.rs");

    // The TARGET os, not the host: a build script is compiled for the host, so
    // `cfg!(target_os = ..)` here would answer about the wrong machine.
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_OS");
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if SONAME_TARGET_OS.contains(&target_os.as_str()) {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,lib{lib_name}.so");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The list is a JUDGEMENT, and the one thing a reader of a build script
    /// cannot check by running it. Pinned as a SET rather than a count: adding
    /// a platform is an edit here, and losing one silently is what this stops.
    #[test]
    fn the_elf_platforms_are_the_ones_named() {
        assert!(
            SONAME_TARGET_OS.contains(&"linux"),
            "linux is the whole point"
        );
        assert!(
            !SONAME_TARGET_OS.contains(&"macos") && !SONAME_TARGET_OS.contains(&"ios"),
            "Mach-O takes -install_name, not -soname; emitting -soname there is a link error",
        );
        assert!(
            !SONAME_TARGET_OS.contains(&"windows"),
            "PE has no SONAME; emitting one there is a link error",
        );
        let mut sorted = SONAME_TARGET_OS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            SONAME_TARGET_OS.len(),
            "the platform list has a duplicate",
        );
    }

    /// A file name where a target name belongs would produce
    /// `liblibwz_capi_c.so.so`, which links and is wrong — the failure mode
    /// worth a panic rather than a warning, because the string is copied into
    /// every consumer.
    #[test]
    fn a_file_name_is_refused_where_a_target_name_belongs() {
        for bad in ["libwz_capi_c", "wz_capi_c.so", "libwz_capi_c.so"] {
            let caught = std::panic::catch_unwind(|| emit_soname(bad));
            assert!(caught.is_err(), "`{bad}` should have been refused");
        }
        let caught = std::panic::catch_unwind(|| emit_soname("out/wz_capi_c"));
        assert!(caught.is_err(), "a path should have been refused");
        let caught = std::panic::catch_unwind(|| emit_soname(""));
        assert!(caught.is_err(), "an empty name should have been refused");
    }
}
