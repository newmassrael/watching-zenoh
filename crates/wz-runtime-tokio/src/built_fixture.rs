// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The one door a unit test goes through to ask for a fixture that is a BUILD
//! ARTIFACT of another workspace member -- the example plugin and volume
//! cdylibs the dynamic-loading hosts are tested against.
//!
//! # Why this exists (open-debt item 776)
//!
//! Those tests each began with `let Some(so) = require_example() else {
//! return; }`, and `require_example()` printed `skip: ... not built` and
//! yielded `None` when the library was absent. A plain `cargo test` of the crate
//! therefore reports every one of them as PASSED on a tree where none of them ran:
//! the pass and the skip differ only in `finished in 0.00s`. R2675 re-created a
//! regression on purpose to check its new witness, got a PASS, and read it as
//! "repaired" until a build of the library turned it red.
//!
//! A skip cannot simply be a failure. `cargo test --workspace` and a developer's
//! first run both have trees where the library is not built, and nothing there
//! owes it. What can be said is WHO owes it: the lane that builds the library and
//! then runs these tests (Layer C1bp, Layer C1bv). So the owner of the fixture
//! turns the skip into a failure for the length of its own run, by setting
//! `WZ_EXAMPLE_CDYLIB_REQUIRE` -- the same `WZ_*_REQUIRE` convention every other
//! oracle-dependent lane in this repository uses.
//!
//! `scripts/lib/silent_skip_gate.py` is the population half: every skip in a test
//! that runs by default must reach such a variable, the variable must be armed by
//! a lane, and a helper that returns `None` must say so.

use std::path::PathBuf;

/// What the door does with one fixture, decided by two facts alone.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// The fixture is built: run the test.
    Run,
    /// Absent and nobody owes it: say so and step over the test.
    Skip,
    /// Absent and the lane that owns it declared it required: the test fails.
    Fail,
}

/// The decision, separate from the environment read so each arm can be asserted
/// without touching process state shared by concurrently running tests.
pub(crate) fn verdict(present: bool, required: bool) -> Verdict {
    match (present, required) {
        (true, _) => Verdict::Run,
        (false, false) => Verdict::Skip,
        (false, true) => Verdict::Fail,
    }
}

/// `target/debug/lib<stem>.so` (`.dylib` on macOS) of the workspace this crate
/// belongs to -- where `cargo build -p <member>` puts a cdylib with no profile
/// or target-dir override, which is how every lane here builds it.
pub(crate) fn cdylib(stem: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.push("target");
    p.push("debug");
    p.push(format!(
        "lib{stem}.{}",
        if cfg!(target_os = "macos") {
            "dylib"
        } else {
            "so"
        }
    ));
    p
}

/// `path` when the fixture is built; otherwise a LOUD skip, or a panic when the
/// running lane set `WZ_EXAMPLE_CDYLIB_REQUIRE` to a non-empty value.
pub(crate) fn built_or_skip(path: PathBuf, build_hint: &str) -> Option<PathBuf> {
    let required = std::env::var("WZ_EXAMPLE_CDYLIB_REQUIRE").is_ok_and(|v| !v.is_empty());
    match verdict(path.exists(), required) {
        Verdict::Run => Some(path),
        Verdict::Skip => {
            eprintln!(
                "skip: {} not built -- {build_hint}; set WZ_EXAMPLE_CDYLIB_REQUIRE=1 to make \
                 this a failure",
                path.display()
            );
            None
        }
        Verdict::Fail => panic!(
            "{} is not built, and WZ_EXAMPLE_CDYLIB_REQUIRE is set: the lane that owns this \
             fixture did not provide it, so a pass here would have proved nothing -- {build_hint}",
            path.display()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_built_fixture_runs_whether_or_not_it_is_required() {
        assert_eq!(verdict(true, false), Verdict::Run);
        assert_eq!(verdict(true, true), Verdict::Run);
    }

    #[test]
    fn an_absent_fixture_nobody_owes_is_skipped_and_one_a_lane_owes_fails() {
        assert_eq!(verdict(false, false), Verdict::Skip);
        assert_eq!(
            verdict(false, true),
            Verdict::Fail,
            "the whole point of the door: a required fixture's absence must not read as a pass"
        );
    }

    #[test]
    fn the_cdylib_path_names_the_library_the_workspace_builds() {
        let p = cdylib("wz_plugin_example");
        let name = p.file_name().and_then(|n| n.to_str()).expect("a file name");
        assert!(
            name.starts_with("libwz_plugin_example.")
                && (name.ends_with(".so") || name.ends_with(".dylib")),
            "got {name}"
        );
        assert!(p.starts_with(PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap()));
    }
}
