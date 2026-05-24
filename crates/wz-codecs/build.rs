// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// wz-codecs build.rs — in-process codegen of selected
// `sources/codecs/*.scxml` files into `$OUT_DIR/<stem>.rs`.
//
// Invokes sce-build's `compile_forge_with_imports` once per SCXML in
// dependency order (leaves first, composers last); SCE's importer
// resolves cross-codec references against the supplied `base_dir`
// (`sources/codecs/`), so `<sce:import src="X.scxml">` directives
// inside the SCXMLs find their siblings without further wiring.
//
// The output files are picked up by `src/lib.rs` via
// `include!(concat!(env!("OUT_DIR"), "/<stem>.rs"))` inside per-codec
// `mod <stem> { ... }` blocks. The codegen emits `use super::X::Y;`
// references that resolve to sibling modules in `lib.rs`.

use sce_build::{
    compile_forge_with_imports, generator::Language, DocumentLabel, ForgeCompileOptions,
};
use std::path::Path;

/// Codec SCXMLs to compile, in dependency order. Each stem `X` is
/// resolved at `sources/codecs/X.scxml` and emitted as
/// `$OUT_DIR/X.rs`. The leaf codecs (no imports) come first; the
/// composing codecs (msg_put, msg_del) come last so their
/// `<sce:import>` directives have already had their target SCXMLs
/// validated by the importer in this same build.
const CODECS: &[&str] = &[
    // Leaf codecs (no imports) — single-field or empty bodies.
    "timestamp",
    "encoding",
    "ext_unit",
    "ext_zint",
    "ext_zbuf",
    "stream_envelope", // §4.0 streamed-link wire envelope (u16 LE len + payload) — R121h
    "close",           // §4.1 session-close, 1-byte reason — R42 Layer 3 ✓
    "frame",           // §4.2 data-carrying VLE sn + tail payload — R43 Layer 3 ✓
    "fragment",        // §4.2 same shape as frame, distinct MID — R43 ✓
    "scout",           // §3 scouting — cbyte multi-bit pack — R44 Layer 3 ✓
    "init_body",       // §4.1 Init body — parent.S + parent.A gates — R44 ✓
    "open_body",       // §4.1 Open body — parent.A NEGATION gate — R44 ✓
    "join",            // §4.1 Join body — parent.S + multi-VLE — R44 ✓
    "locator",         // §3 hello locator element — R45 (hello dep)
    "keep_alive",      // §4.1 empty body (transport keepalive) — R47 trivial
    "decl_final",      // §5 declare-final leaf — 1-byte header MID 0x1A — R110a
    "undecl_kexpr",    // §5 undecl kexpr leaf — header + id VLE, MID 0x01 — R110b
    "undecl_subscriber", // §5 undecl subscriber leaf — header + id VLE, MID 0x03 — R110d
    "undecl_queryable", // §5 undecl queryable leaf — header + id VLE, MID 0x05 — R110d
    "undecl_token",    // §5 undecl token leaf — header + id VLE, MID 0x07 — R110d
    // Composing codecs
    "hello",             // §3 Hello body — parent.L + repeat<locator> — R45
    "ext_entry",         // imports ext_unit / ext_zint / ext_zbuf
    "ext_envelope",      // imports ext_entry — R67 generic ext chain (RFC §5.B B5-ε)
    "msg_put",           // imports timestamp / encoding / ext_entry
    "msg_del",           // imports timestamp / ext_entry
    "wireexpr_local",    // §5 wireexpr Local arm — R125b leaf; R125c2 dispatched
    "wireexpr_nonlocal", // §5 wireexpr Nonlocal arm — R125b leaf; R125c2 dispatched
    "wireexpr",          // §5 keyexpr fragment — R125c2 B5-ν dispatcher (pin b35dbb66)
    "query",             // §6.2 Query body — header gates + tlv-chain — R47
    "request",           // §5 Z_REQUEST envelope — peek-byte dispatch — R47
    "push",              // §5 Z_PUSH envelope — peek-byte dispatch — R90
    "response_final",    // §5 Z_RESPONSE_FINAL marker — header + rid — R91
    "oam",               // §5 Z_OAM envelope — header.enc variant dispatch — R92
    "interest_body",     // §5 Z_INTEREST inner body — flags + R-gated wireexpr — R94
    "interest",          // §5 Z_INTEREST envelope — header + VLE id + ext-chain — R93/R94
    "reply",             // §6.3 Z_REPLY inner body — C-gated consolidation + put/del peek — R95
    "err",               // §6.3 Z_ERR inner body — E-gated encoding + Z ext + payload — R96
    "response",          // §5 Z_RESPONSE envelope — reply/err peek-byte dispatch — R97
    "decl_kexpr",        // §5 decl kexpr — header + id VLE + wireexpr embed, MID 0x00 — R110b
    "decl_subscriber",   // §5 decl subscriber — _z_decl_commons shape, MID 0x02 — R110c
    "decl_queryable",    // §5 decl queryable — _z_decl_commons shape, MID 0x04 — R110c
    "decl_token",        // §5 decl token — _z_decl_commons shape, MID 0x06 — R110c
    "declare", // §5 Z_DECLARE envelope — header + I-gated id + Z ext + sub-MID variant — R110a
];

// R311a1 — per-codec feature gate. `codec-init-body` / `codec-open-body`
// elide both the build.rs SCXML compile pass and the lib.rs mod include.
// CARGO_FEATURE_<NAME> env vars are set by cargo when the feature is
// active in the resolved build graph for this crate; missing env var
// means the feature is off and the corresponding SCXML must NOT be
// compiled (Footprint honesty: feature-off = zero OUT_DIR artifact +
// zero binary contribution).
fn is_codec_enabled(stem: &str) -> bool {
    match stem {
        "init_body" => std::env::var_os("CARGO_FEATURE_CODEC_INIT_BODY").is_some(),
        "open_body" => std::env::var_os("CARGO_FEATURE_CODEC_OPEN_BODY").is_some(),
        "keep_alive" => std::env::var_os("CARGO_FEATURE_CODEC_KEEP_ALIVE").is_some(),
        "close" => std::env::var_os("CARGO_FEATURE_CODEC_CLOSE").is_some(),
        "scout" => std::env::var_os("CARGO_FEATURE_CODEC_SCOUT").is_some(),
        "hello" => std::env::var_os("CARGO_FEATURE_CODEC_HELLO").is_some(),
        "join" => std::env::var_os("CARGO_FEATURE_CODEC_JOIN").is_some(),
        "response_final" => std::env::var_os("CARGO_FEATURE_CODEC_RESPONSE_FINAL").is_some(),
        "fragment" => std::env::var_os("CARGO_FEATURE_CODEC_FRAGMENT").is_some(),
        "frame" => std::env::var_os("CARGO_FEATURE_CODEC_FRAME").is_some(),
        "push" => std::env::var_os("CARGO_FEATURE_CODEC_PUSH").is_some(),
        // R311i — 9 declare-family stems gated on codec-declare.
        "declare" | "decl_kexpr" | "decl_subscriber" | "decl_queryable" | "decl_token"
        | "decl_final" | "undecl_kexpr" | "undecl_subscriber" | "undecl_queryable"
        | "undecl_token" => std::env::var_os("CARGO_FEATURE_CODEC_DECLARE").is_some(),
        _ => true,
    }
}

fn main() {
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set by cargo");
    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set by cargo");

    // sources/codecs/ relative to crates/wz-codecs/ is ../../sources/codecs.
    let resource_dir = Path::new(&manifest_dir)
        .join("../../sources/codecs")
        .canonicalize()
        .expect("canonicalize sources/codecs");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", resource_dir.display());
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_CODEC_INIT_BODY");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_CODEC_OPEN_BODY");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_CODEC_KEEP_ALIVE");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_CODEC_CLOSE");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_CODEC_SCOUT");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_CODEC_HELLO");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_CODEC_JOIN");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_CODEC_RESPONSE_FINAL");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_CODEC_FRAGMENT");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_CODEC_FRAME");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_CODEC_PUSH");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_CODEC_DECLARE");

    let options = ForgeCompileOptions::default();

    for stem in CODECS {
        if !is_codec_enabled(stem) {
            continue;
        }
        let scxml_path = resource_dir.join(format!("{stem}.scxml"));
        let content = std::fs::read_to_string(&scxml_path)
            .unwrap_or_else(|e| panic!("read {}: {e}", scxml_path.display()));

        let output = compile_forge_with_imports(
            &content,
            DocumentLabel::symmetric(stem),
            Language::Rust,
            &resource_dir,
            &options,
        )
        .unwrap_or_else(|e| panic!("sce-build codegen failed for {stem}: {e}"));

        for (filename, code) in output.files {
            let target = Path::new(&out_dir).join(&filename);
            // SCE-upstream transitional workaround (R40 carry): the
            // codegen template emits `#![doc = "SCE-MAP: stem:line"]`
            // as an inner attribute at line 1 of each generated file.
            // When wz consumes the file via
            // `pub mod X { include!(env!("OUT_DIR")/X.rs); }` the
            // inner attribute lands at item position inside `mod X`
            // — rust then rejects it with E0658 "an inner attribute
            // is not permitted in this context". SCE's own
            // `sce-forge-runtime --features alloc --tests` build hits
            // the same wall (verified R40); the SCE conformance
            // harness's default `cargo build -p sce-forge-runtime`
            // doesn't trigger include!() so SCE never noticed.
            //
            // The SCE-MAP info itself is redundantly emitted on the
            // very next line as a regular `// SCE-MAP: stem:line`
            // comment, so removing the inner-attr line loses ZERO
            // information — only the rustdoc surface that the doc
            // attribute would expose. That rustdoc surface is also
            // emitted as part of the per-struct doc-comments below
            // the strip target, so the net visible-doc-surface change
            // is zero.
            //
            // Proper fix (SCE upstream PR, R41 carry): change
            // `tools/codegen/templates/forge/rust/<kind>.rs.jinja2`
            // to emit `// SCE-MAP: stem:line` (regular comment) or
            // `/// SCE-MAP: stem:line` (outer doc, attached to the
            // first struct) instead of `#![doc = ...]` inner attr.
            // Once SCE ships that, this strip becomes a no-op and
            // can be removed.
            let stripped = code
                .lines()
                .filter(|line| !line.starts_with("#![doc = \"SCE-MAP:"))
                .collect::<Vec<_>>()
                .join("\n");
            std::fs::write(&target, &stripped)
                .unwrap_or_else(|e| panic!("write {}: {e}", target.display()));
        }
    }
}
