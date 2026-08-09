// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

// R311y608 — when a CMake build directory must be thrown away rather than
// reused.
//
// # The defect this exists for
//
// CMake reacts to a changed compiler by DELETING its cache and re-running
// configure — and the re-run does not carry the `-D` definitions the first one
// was given. Every flag `build.rs` set evaporates and the project's own
// defaults take their place. Measured on this tree's pinned zenoh-pico by
// configuring one directory twice, changing only `CMAKE_C_COMPILER`:
//
// | variable | asked for | after the wipe |
// |---|---|---|
// | `BUILD_SHARED_LIBS` | `OFF` | `ON` |
// | `BUILD_EXAMPLES` | `OFF` | `ON` |
// | `BUILD_TESTING` | `OFF` | `ON` |
// | `CMAKE_INSTALL_PREFIX` | `$OUT_DIR` | `/usr/local` |
//
// The install prefix is the dangerous one. `cmake --build --target install`
// then writes `libzenohpico.so` into `/usr/local/lib` — a SYSTEM directory
// this crate has no business touching. Where that is not writable the build
// fails with a permission error that names neither the compiler nor the cache
// (this is how it presented: run-ci Layer M, unrunnable, and the reported
// cause was "permission denied"). Where it IS writable — a container running
// as root, a developer who owns `/usr/local` — it SUCCEEDS, silently
// installing a shared library outside the build tree and linking against a
// configuration nobody asked for. The quiet outcome is the worse one.
//
// # Why the compiler changes at all
//
// cargo reuses one `OUT_DIR` across rebuilds of the same unit, so the cmake
// build directory persists. The compiler the `cc` crate resolves does not: it
// honours `PATH`, and a `ccache` shim entering or leaving `PATH` flips it
// between `/usr/bin/cc` and `/usr/lib/ccache/cc`. Nothing about the source
// tree changes, so nothing warns.
//
// # Why a pre-check and not a post-check
//
// The wipe happens INSIDE the configure step. Before it the cache is still
// the good one, so an inspection of what is on disk cannot predict it — the
// only signal available in advance is the compiler this run is about to use
// against the compiler the cache was built with. That comparison is the whole
// of [`cache_is_stale`].

/// The value CMake recorded for `name` in a `CMakeCache.txt`, if any.
///
/// A cache entry is `NAME:TYPE=VALUE`, and the TYPE varies for the same
/// variable between runs — this tree has observed `CMAKE_C_COMPILER` written
/// as both `STRING` and `UNINITIALIZED` — so the type is matched as "anything
/// up to the `=`" rather than enumerated. Comment lines (`//` and `#`) are
/// skipped, because a cache's header prose mentions variable names.
pub fn cache_value<'a>(cache: &'a str, name: &str) -> Option<&'a str> {
    cache.lines().find_map(|line| {
        let line = line.trim();
        if line.starts_with("//") || line.starts_with('#') {
            return None;
        }
        let rest = line.strip_prefix(name)?;
        // The next character must start the TYPE field, or this is a longer
        // variable that merely begins with the same letters.
        let rest = rest.strip_prefix(':')?;
        let (_ty, value) = rest.split_once('=')?;
        Some(value)
    })
}

/// Must the build directory holding `cache` be discarded before configuring
/// it with `compiler` and `install_prefix`?
///
/// # Two arms, and neither one alone is enough
///
/// **The TRIGGER** — a different `CMAKE_C_COMPILER`. This is what makes CMake
/// wipe the cache, so catching it is what PREVENTS the damage. It cannot
/// repair anything: by the time a directory has been wiped its recorded
/// compiler is the new one, and this arm sees a cache that agrees with it.
///
/// **The EVIDENCE** — an `CMAKE_INSTALL_PREFIX` that is not ours. A cache this
/// crate configured always records the `OUT_DIR` prefix it was handed, so a
/// cache saying anything else (`/usr/local`, after a wipe) was not configured
/// by us and its every other variable is equally untrustworthy. This arm
/// REPAIRS a directory that was already poisoned — including one poisoned
/// before this guard existed, which is not a hypothetical: it is the state
/// this tree was in when the guard was written. It cannot prevent anything,
/// because the wipe happens inside the very configure step it would run after.
///
/// So: one arm stops it happening, the other stops it being permanent.
///
/// Both are compared as exact strings rather than by canonicalising paths.
/// What CMake compares — and therefore what decides whether it wipes — is the
/// literal it was handed against the literal it stored; canonicalising would
/// answer a different question from the one CMake asks, and `/usr/bin/cc` and
/// `/usr/lib/ccache/cc` resolve through symlinks toward the same real binary.
///
/// Every unreadable answer means KEEP, and the asymmetry is deliberate: a
/// variable that was never recorded is not evidence of anything, while
/// discarding on uncertainty would rebuild the whole of zenoh-pico on every
/// invocation.
pub fn cache_is_stale(cache: &str, compiler: &str, install_prefix: &str) -> bool {
    differs(cache_value(cache, "CMAKE_C_COMPILER"), compiler)
        || differs(cache_value(cache, "CMAKE_INSTALL_PREFIX"), install_prefix)
}

/// Does a recorded cache value contradict what this build will pass?
/// Absent and empty both answer `false` — see [`cache_is_stale`].
fn differs(recorded: Option<&str>, want: &str) -> bool {
    matches!(recorded, Some(r) if !r.is_empty() && r != want)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A cache as CMake writes it, trimmed to the entries that matter.
    fn cache(compiler_entry: &str) -> String {
        format!(
            "# This is the CMakeCache file.\n\
             // The C compiler\n\
             {compiler_entry}\n\
             BUILD_SHARED_LIBS:BOOL=OFF\n\
             CMAKE_INSTALL_PREFIX:PATH=/tmp/out\n"
        )
    }

    #[test]
    fn a_value_is_read_whatever_type_cmake_gave_it() {
        // Both spellings are real: this tree's build directories carry
        // `STRING` and `UNINITIALIZED` for the same variable.
        for entry in [
            "CMAKE_C_COMPILER:STRING=/usr/bin/cc",
            "CMAKE_C_COMPILER:UNINITIALIZED=/usr/bin/cc",
            "CMAKE_C_COMPILER:FILEPATH=/usr/bin/cc",
        ] {
            assert_eq!(
                cache_value(&cache(entry), "CMAKE_C_COMPILER"),
                Some("/usr/bin/cc"),
                "{entry}"
            );
        }
    }

    /// A variable that merely starts with the same letters is not the one
    /// asked for. `CMAKE_C_COMPILER_AR` sits next to `CMAKE_C_COMPILER` in
    /// every real cache, so a prefix match would read the wrong line whenever
    /// the two happen to be ordered that way.
    #[test]
    fn a_longer_name_with_the_same_prefix_is_not_a_match() {
        let c = "CMAKE_C_COMPILER_AR:FILEPATH=/usr/bin/gcc-ar\n\
                 CMAKE_C_COMPILER:STRING=/usr/bin/cc\n";
        assert_eq!(cache_value(c, "CMAKE_C_COMPILER"), Some("/usr/bin/cc"));
    }

    /// The header prose of a real cache names variables in comments.
    #[test]
    fn a_comment_mentioning_the_name_is_not_a_value() {
        let c = "// CMAKE_C_COMPILER:STRING=/wrong\n\
                 CMAKE_C_COMPILER:STRING=/usr/bin/cc\n";
        assert_eq!(cache_value(c, "CMAKE_C_COMPILER"), Some("/usr/bin/cc"));
    }

    /// THE TRIGGER ARM: the flip that wipes the cache is detected BEFORE it
    /// wipes anything.
    ///
    /// `/usr/bin/cc` -> `/usr/lib/ccache/cc` is the exact transition observed
    /// here, produced by nothing more than a `ccache` shim entering `PATH`.
    #[test]
    fn a_changed_compiler_makes_the_cache_stale() {
        let c = cache("CMAKE_C_COMPILER:STRING=/usr/bin/cc");
        assert!(cache_is_stale(&c, "/usr/lib/ccache/cc", "/tmp/out"));
        assert!(
            !cache_is_stale(&c, "/usr/bin/cc", "/tmp/out"),
            "same compiler and same prefix: keep it"
        );
    }

    /// THE EVIDENCE ARM: a directory that was ALREADY wiped is repaired.
    ///
    /// This is the state a poisoned tree is in, and the trigger arm is blind
    /// to it — after a wipe the recorded compiler IS the current one, so only
    /// the install prefix still testifies. Without this arm such a directory
    /// fails forever, because every later run agrees with its compiler and
    /// reuses the cache that sends the install to /usr/local.
    #[test]
    fn a_cache_that_installs_somewhere_else_is_not_ours() {
        let wiped = "CMAKE_C_COMPILER:STRING=/usr/lib/ccache/cc\n\
                     BUILD_SHARED_LIBS:BOOL=ON\n\
                     CMAKE_INSTALL_PREFIX:PATH=/usr/local\n";
        assert!(
            cache_is_stale(wiped, "/usr/lib/ccache/cc", "/tmp/out"),
            "the compiler agrees; the prefix is what gives it away"
        );
    }

    /// The NEGATIVE arms: neither absence nor emptiness may throw a good build
    /// directory away. A guard that discarded on "I do not know" would force a
    /// full zenoh-pico rebuild on every invocation.
    #[test]
    fn an_unrecorded_value_is_not_a_reason_to_discard() {
        let no_entry = "BUILD_SHARED_LIBS:BOOL=OFF\n";
        assert!(!cache_is_stale(no_entry, "/usr/bin/cc", "/tmp/out"));
        let empty = cache("CMAKE_C_COMPILER:STRING=");
        assert!(!cache_is_stale(&empty, "/usr/bin/cc", "/tmp/out"));
    }
}
