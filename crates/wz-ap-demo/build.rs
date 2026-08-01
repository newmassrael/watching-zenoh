// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// wz-ap-demo — generates the `BUILD FEATURES` self-report from the manifest.
//
// R311y489. The report existed since R311y482 and was load-bearing from the day
// it landed: every AP-full fixture asserts it BEFORE any wire wait, because each
// feature-set-specific lane writes the same `target/debug/wz-ap-demo` path and a
// fixture that needs a different set otherwise drives the wrong binary silently.
//
// It was a HAND-MAINTAINED `push_if!` list, and by the time this round measured
// it, it had drifted: `adminspace-read`, `routing-router-hat` and
// `storage-backend-filesystem` were declared features of this crate that the
// report never mentioned, as were the preset keys that name which binary this
// even is. That is worse than no report. `usage.rs` promised in its own doc that
// "a key absent from the list is a flag that will be rejected or run INERT" — so
// a missing key does not merely omit, it ASSERTS the opposite of the truth, to
// the one reader (a failing fixture) who has no other way to check.
//
// The fix is not a longer list. Both halves are derived here so the two cannot
// disagree:
//
//   - the KEY SET comes from this crate's own `[features]` table, so a feature
//     added to Cargo.toml is reported without anyone remembering to;
//   - the ON/OFF answer comes from cargo's `CARGO_FEATURE_<KEY>` env vars, which
//     are the build's own record of what it enabled.
//
// And the loop is closed in the direction that would otherwise stay silent: a
// `CARGO_FEATURE_*` that this file's manifest scan did NOT account for FAILS the
// build (see `main`). Without that check a manifest the scanner mis-parses would
// go back to under-reporting quietly, which is the exact failure being retired.

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::Path;

/// Every key declared in the manifest's `[features]` table, in declaration order.
///
/// Deliberately a scan rather than a TOML dependency: a build script that parses
/// its own manifest needs the KEY NAMES only, and the shape it must recognise is
/// fixed by this file's sibling — an unindented `name = ...` at the top level of
/// the `[features]` table. Anything this misses is caught by the reverse check in
/// `main`, so the scan cannot be wrong and quiet at the same time.
fn feature_keys(manifest: &str) -> Vec<String> {
    let mut keys = Vec::new();
    let mut in_features = false;
    for line in manifest.lines() {
        if line.starts_with('[') {
            in_features = line.trim_end().starts_with("[features]");
            continue;
        }
        if !in_features {
            continue;
        }
        // Continuation lines of a multi-line array are indented; comments and
        // blanks carry no key.
        if line.starts_with(char::is_whitespace) {
            continue;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((name, _)) = line.split_once('=') else {
            continue;
        };
        let name = name.trim();
        if !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            keys.push(name.to_string());
        }
    }
    keys
}

/// The env var cargo sets for `key` when that feature is enabled.
fn env_name(key: &str) -> String {
    format!("CARGO_FEATURE_{}", key.to_uppercase().replace('-', "_"))
}

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR");
    let manifest_path = Path::new(&manifest_dir).join("Cargo.toml");
    println!("cargo:rerun-if-changed=Cargo.toml");

    let manifest = fs::read_to_string(&manifest_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", manifest_path.display()));
    let keys = feature_keys(&manifest);
    assert!(
        !keys.is_empty(),
        "wz-ap-demo build.rs: found no [features] keys in {} — the manifest scan \
         is broken, and shipping an empty BUILD FEATURES report would be worse \
         than shipping none",
        manifest_path.display()
    );

    let declared: BTreeSet<String> = keys.iter().map(|k| env_name(k)).collect();
    let mut enabled: Vec<&String> = Vec::new();
    for key in &keys {
        if env::var_os(env_name(key)).is_some() {
            enabled.push(key);
        }
    }

    // THE CHECK THAT MAKES THE REPORT TRUSTWORTHY. Cargo's own `CARGO_FEATURE_*`
    // set is the ground truth for what is on; if it contains something the
    // manifest scan above never produced a key for, the report is incomplete —
    // exactly the R311y482-era failure. Fail the build with the offending var
    // named, rather than emit a report that quietly omits it.
    for (var, _) in env::vars() {
        if var.starts_with("CARGO_FEATURE_") && !declared.contains(&var) {
            panic!(
                "wz-ap-demo build.rs: cargo enabled `{var}`, but the [features] scan of \
                 {} produced no key for it. The BUILD FEATURES report would silently \
                 omit that feature, which is the drift this generator exists to make \
                 impossible. Fix `feature_keys` (or the manifest formatting) — do not \
                 relax this check.",
                manifest_path.display()
            );
        }
    }

    enabled.sort_unstable();
    let rendered = enabled
        .iter()
        .map(|k| format!("    {k:?},\n"))
        .collect::<String>();
    let generated = format!(
        "// @generated by wz-ap-demo/build.rs — do not edit.\n\
         pub(crate) const BUILD_FEATURES: &[&str] = &[\n{rendered}];\n"
    );

    let out_dir = env::var("OUT_DIR").expect("cargo sets OUT_DIR");
    let out_path = Path::new(&out_dir).join("build_features.rs");
    fs::write(&out_path, generated).unwrap_or_else(|e| panic!("write {}: {e}", out_path.display()));
}
