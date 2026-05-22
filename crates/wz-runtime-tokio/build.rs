// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// wz-runtime-tokio build.rs — R54 entry. Codegens the statechart-kind
// SCXML at `sources/session/session_fsm_unicast.scxml` into
// `$OUT_DIR/session_fsm_unicast_sm.rs`.
//
// Pipeline choice. `sce_build::compile_forge_with_imports` is the
// in-process API for forge-kind SCXMLs (codec / link / algorithm /
// etc.). Statechart-kind SCXMLs route through a different pipeline
// internally (SCXMLParser + analyzer + generator chain) and the
// `sce-codegen generate` CLI command is the public entry that wires
// the chain — `sce_build` does not yet expose an equivalent
// in-process API for the statechart path. The build script therefore
// shells out to the vendored binary, supplying `--workspace-root` so
// the §6.2.6 template-hash anchor embeds the real hash (R53 closure).
//
// The binary must exist at `vendor/sce/target/release/sce-codegen`;
// see `scripts/build-sce.sh`. We fail-fast with a clear remedy when
// it is missing instead of trying to invoke `cargo build` recursively
// from inside the build script (which deadlocks on nested cargo locks
// when the wz workspace is itself in a `cargo build`).

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

const STATECHARTS: &[&str] = &["session_fsm_unicast"];

/// Names every `<script>foo()</script>` body or `cond="..."`
/// reference in `sources/session/session_fsm_unicast.scxml` MUST be
/// registered against the Lua engine in
/// `crates/wz-runtime-tokio/src/session_glue.rs::register_*` family.
///
/// This list is the hand-maintained mirror of
/// `session_glue::REGISTERED_SCRIPT_NAMES`. The build script greps
/// the SCXML for every script-action / cond expression name and
/// asserts the set is exactly this list. A new `<script>foo()</script>`
/// in the SCXML without an `install_session_actions` registration
/// would silently return Nil at runtime; this build-time check
/// converts that silent failure into a compile-time panic.
const EXPECTED_SCRIPT_NAMES: &[&str] = &[
    "link_driver_open",
    "send_init_syn",
    "send_open_syn",
    "send_init_ack_with_cookie",
    "send_open_ack",
    "send_close_frame_with_reason",
    "release_link",
    "enable_rx_tx_regions",
    "record_established_at",
    "start_lease_monitor",
    "stop_lease_monitor",
    "start_keepalive_worker",
    "stop_keepalive_worker",
    "free_pool_slots",
    "set_close_reason_generic",
    "set_close_reason_invalid",
    "set_close_reason_expired",
    "set_close_reason_unresponsive",
    "half_open_cap_available",
    "accept_rate_token",
    "cookie_valid",
];

fn main() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR not set by cargo"));
    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set by cargo"),
    );

    let resource_dir = manifest_dir
        .join("../../sources/session")
        .canonicalize()
        .expect("canonicalize sources/session");

    audit_script_names(&resource_dir);

    let sce_workspace = manifest_dir
        .join("../../vendor/sce")
        .canonicalize()
        .expect("canonicalize vendor/sce");

    let sce_codegen = sce_workspace.join("target/release/sce-codegen");
    if !sce_codegen.exists() {
        panic!(
            "sce-codegen binary not found at {}\n\
             run `scripts/build-sce.sh` from the wz workspace root \
             to build it (vendor pin: see vendor/sce HEAD).",
            sce_codegen.display()
        );
    }

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", resource_dir.display());
    // Rerun when the binary itself is rebuilt — covers `git -C vendor/sce
    // checkout <new-pin>` + `scripts/build-sce.sh` rebuilds during a
    // round where the wz crate sources did not otherwise change.
    println!("cargo:rerun-if-changed={}", sce_codegen.display());

    for stem in STATECHARTS {
        emit_one(stem, &resource_dir, &out_dir, &sce_codegen, &sce_workspace);
    }
}

/// Parse every SCXML in `resource_dir` for `<script>foo()</script>`
/// bodies + `cond="foo() && bar()"` references and confirm the
/// extracted set matches `EXPECTED_SCRIPT_NAMES`. Mismatch (either
/// direction) panics the build — adding a new script body without
/// registering it in `session_glue` would otherwise silently no-op
/// at runtime.
fn audit_script_names(resource_dir: &Path) {
    let mut found = HashSet::new();
    for entry in std::fs::read_dir(resource_dir)
        .unwrap_or_else(|e| panic!("read_dir {}: {e}", resource_dir.display()))
    {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("scxml") {
            continue;
        }
        let content = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));

        // Match every `<script>identifier()</script>` body. The
        // generated SCXML does not parameterise script bodies
        // (every call site is `foo()` with no arguments), so the
        // regex below stays simple — name is `[A-Za-z_][A-Za-z0-9_]*`
        // and the parens are empty.
        for cap in find_script_names(&content) {
            found.insert(cap);
        }
        // Match every `cond="..."` attribute's identifiers — every
        // identifier in a cond is a guard function name we register.
        for cap in find_cond_names(&content) {
            found.insert(cap);
        }
    }

    let expected: HashSet<String> = EXPECTED_SCRIPT_NAMES
        .iter()
        .map(|s| s.to_string())
        .collect();

    let missing_in_expected: Vec<_> = found.difference(&expected).cloned().collect();
    let missing_in_found: Vec<_> = expected.difference(&found).cloned().collect();

    if !missing_in_expected.is_empty() {
        panic!(
            "wz-runtime-tokio build.rs: SCXML references script names not registered in \
             session_glue (build.rs EXPECTED_SCRIPT_NAMES + \
             session_glue::register_*): {missing_in_expected:?}"
        );
    }
    if !missing_in_found.is_empty() {
        panic!(
            "wz-runtime-tokio build.rs: EXPECTED_SCRIPT_NAMES lists names not found in any \
             session SCXML (probable stale registration): {missing_in_found:?}"
        );
    }
}

/// Scan for `<script>...</script>` bodies and return the identifier
/// (the `foo` in `foo()`). Uses a hand-rolled scan rather than a
/// regex dep so build-time cost stays low.
fn find_script_names(content: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = content;
    while let Some(open) = rest.find("<script>") {
        rest = &rest[open + "<script>".len()..];
        let close = match rest.find("</script>") {
            Some(c) => c,
            None => break,
        };
        let body = rest[..close].trim();
        rest = &rest[close..];
        // Body shape: `identifier()`.
        if let Some(paren) = body.find('(') {
            let ident = body[..paren].trim();
            if is_identifier(ident) {
                names.push(ident.to_string());
            }
        }
    }
    names
}

/// Scan for `cond="..."` attributes and pull out every identifier
/// followed by `(`. The session SCXML's cond expressions take the
/// shape `fn1() && fn2()`, so this picks them up cleanly.
fn find_cond_names(content: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = content;
    while let Some(open) = rest.find("cond=\"") {
        rest = &rest[open + "cond=\"".len()..];
        let close = match rest.find('"') {
            Some(c) => c,
            None => break,
        };
        let body = &rest[..close];
        rest = &rest[close + 1..];
        // Walk the body, treating any maximal `[A-Za-z_][A-Za-z0-9_]*`
        // followed by `(` as a function call.
        let bytes = body.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i].is_ascii_alphabetic() || bytes[i] == b'_' {
                let start = i;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                if i < bytes.len() && bytes[i] == b'(' {
                    names.push(body[start..i].to_string());
                }
            } else {
                i += 1;
            }
        }
    }
    names
}

fn is_identifier(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let first = s.as_bytes()[0];
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return false;
    }
    s.as_bytes()
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'_')
}

fn emit_one(
    stem: &str,
    resource_dir: &Path,
    out_dir: &Path,
    sce_codegen: &Path,
    sce_workspace: &Path,
) {
    let scxml_path = resource_dir.join(format!("{stem}.scxml"));

    let status = Command::new(sce_codegen)
        .arg("--workspace-root")
        .arg(sce_workspace)
        .arg("generate")
        .arg("--language")
        .arg("rust")
        .arg("--output-dir")
        .arg(out_dir)
        .arg(&scxml_path)
        .status()
        .unwrap_or_else(|e| panic!("invoke sce-codegen for {stem}: {e}"));

    if !status.success() {
        panic!("sce-codegen generate failed for {stem} (exit {status:?})");
    }

    // R40 carry strip extended for statechart emit — SCE codegen emits
    // a full block of `#![allow(...)]` lints + `#![doc = "SCE-MAP:..."]`
    // marker at file head. None of those inner attributes are legal
    // once the file is `include!()`'d into a module scope. The lib.rs
    // wrapping module restores the lint allows as OUTER attributes
    // attached to `pub mod session_fsm_unicast { ... }`; the SCE-MAP
    // inner is information-redundant with the adjacent `// SCE-MAP:`
    // line as documented in wz-codecs/build.rs.
    let emit_path = out_dir.join(format!("{stem}_sm.rs"));
    let original = std::fs::read_to_string(&emit_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", emit_path.display()));
    let stripped = original
        .lines()
        .filter(|line| {
            let t = line.trim_start();
            // Both `#![...]` attr-style inner forms AND `//!` inner doc
            // comments are illegal at item position inside a `mod` block.
            // The build script strips both; lib.rs restores the lint
            // suppressions as outer attributes on the wrapping module.
            !t.starts_with("#![") && !t.starts_with("//!")
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&emit_path, &stripped)
        .unwrap_or_else(|e| panic!("write {}: {e}", emit_path.display()));
}
