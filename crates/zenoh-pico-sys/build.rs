// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// zenoh-pico-sys build.rs — builds vendored zenoh-pico as a static
// C library via the upstream CMakeLists.txt, then generates Rust FFI
// bindings via bindgen for the allowlisted symbols.
//
// Two-stage build:
//
//   1. `cmake::Config::new(vendor/zenoh-pico).build()` invokes
//      `cmake -B build -S vendor/zenoh-pico ...` + `cmake --build build`
//      + `cmake --install`. The install layout puts
//      `libzenohpico.a` under `$OUT_DIR/build/lib/` and headers under
//      `$OUT_DIR/build/include/` (CMake `install()` rule from zenoh-
//      pico's CMakeLists.txt). The `cmake` crate returns `$OUT_DIR/build`
//      as the install prefix; we emit `rustc-link-search=native=...`
//      and `rustc-link-lib=static=zenohpico` for cargo to consume.
//
//   2. `bindgen` parses `vendor/zenoh-pico/include/zenoh-pico.h`
//      (the umbrella header that pulls in everything public), follows
//      `-I` to resolve sub-headers, and emits Rust bindings into
//      `$OUT_DIR/bindings.rs`. The allowlist restricts emission to
//      symbols Layer 3 tests actually use — keeping the bindings
//      surface aligned with the auditable wire-codec set rather than
//      letting compile time / ABI surface grow with every zenoh-pico
//      internal.
//
// Allowlist (R41 walking skeleton minimum):
//   - `_z_id_t`        — zenoh-id 16-byte fixed buffer struct
//   - `_z_id_len`      — counts active bytes (trailing-zeros stripped)
//
// Each subsequent Layer 3 test round expands this allowlist by
// exactly the `_z_*_encode` / `_z_*_decode` functions it consumes —
// see R42+ carry.

use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let zenoh_src = manifest_dir
        .join("../../vendor/zenoh-pico")
        .canonicalize()
        .expect("canonicalize vendor/zenoh-pico");
    let include_dir = zenoh_src.join("include");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Stage 1: CMake build → static libzenohpico.a.
    //
    // Disable upstream test / example / tools targets — they pull in
    // additional source trees and link options unrelated to wire-
    // codec interop. The static-lib + minimal-features build keeps
    // the surface lean.
    let dst = cmake::Config::new(&zenoh_src)
        .define("BUILD_SHARED_LIBS", "OFF")
        .define("BUILD_EXAMPLES", "OFF")
        .define("BUILD_TESTING", "OFF")
        .define("BUILD_TOOLS", "OFF")
        .define("BUILD_INTEGRATION", "OFF")
        .define("PACKAGING", "OFF")
        .build();

    println!("cargo:rustc-link-search=native={}/lib", dst.display());
    println!("cargo:rustc-link-lib=static=zenohpico");

    // Stage 2: bindgen → Rust FFI bindings.
    //
    // zenoh-pico's `zenoh-pico/system/platform.h` includes the
    // CMake-generated `zenoh-pico/config.h`. CMake's `install()` step
    // copies that generated header into `<install-prefix>/include/`
    // (alongside the source-tree headers it ALSO copies). Both paths
    // resolve to identical files post-install. Point bindgen at
    // BOTH so the source-tree `#include`s and the generated
    // `config.h` both resolve.
    let installed_include = dst.join("include");
    // Use the wz-side wrapper header that pulls in zenoh-pico.h
    // (public surface) PLUS the internal protocol headers needed for
    // codec-level Layer 3 byte-compare tests (_z_*_encode + wbuf/
    // zbuf API). The umbrella public header does not transitively
    // include the internal codec headers — Layer 3 needs them
    // explicitly. See wrapper.h.
    let main_header = manifest_dir
        .join("wrapper.h")
        .to_string_lossy()
        .into_owned();
    println!("cargo:rerun-if-changed=wrapper.h");

    // zenoh-pico's `system/common/platform.h` errors out with
    // "Unknown platform" unless ONE of the `ZENOH_<PLATFORM>` macros
    // is defined (see vendor/zenoh-pico/cmake/platforms/*.cmake;
    // CMake selects + defines the matching macro per
    // CMAKE_SYSTEM_NAME at configure time). bindgen runs clang
    // directly on the raw headers and never sees CMake's compile
    // definitions, so we have to re-derive the platform macro from
    // the cargo TARGET env var and pass it as a `-D` clang argument.
    //
    // Mapping (matches `cmake/platforms/<X>.cmake`'s
    // `ZP_PLATFORM_COMPILE_DEFINITIONS`):
    //   x86_64-unknown-linux-gnu  → ZENOH_LINUX
    //   aarch64-unknown-linux-gnu → ZENOH_LINUX
    //   *-apple-darwin            → ZENOH_MACOS
    //   *-windows-*               → (ZENOH_WINDOWS not bound here —
    //                                Windows builds need windows.cmake
    //                                semantics that are out of R41
    //                                scope; will be wired when a wz
    //                                Windows deploy class is needed)
    //
    // The compiler-flavor macro (`ZENOH_COMPILER_GCC` etc.) is also
    // CMake-driven; since clang/clang++ is what bindgen uses
    // internally, pass `ZENOH_COMPILER_CLANG` so any C-side
    // #if-branches reach a consistent set of declarations.
    let target = env::var("TARGET").unwrap_or_default();
    let platform_def = if target.contains("linux") {
        "ZENOH_LINUX"
    } else if target.contains("apple-darwin") {
        "ZENOH_MACOS"
    } else {
        panic!(
            "zenoh-pico-sys: unsupported TARGET `{target}` — add the \
             matching `ZENOH_*` platform macro to build.rs's mapping"
        );
    };

    let bindings = bindgen::Builder::default()
        .header(main_header)
        .clang_arg(format!("-I{}", include_dir.display()))
        .clang_arg(format!("-I{}", installed_include.display()))
        .clang_arg(format!("-D{platform_def}"))
        .clang_arg("-DZENOH_COMPILER_CLANG")
        .clang_arg("-DZENOH_C_STANDARD=11")
        // Allowlist policy — see Cargo.toml + module docstring.
        // Adding a function here without a paired Layer 3 test round
        // is a violation of the "production-level surface, no auto-
        // bind sprawl" gate.
        //
        // R41 (smoke): _z_id_t + _z_id_len.
        // R42 (close codec Layer 3): + wbuf API + close encode.
        .allowlist_type("_z_id_t")
        .allowlist_function("_z_id_len")
        // R42 — close codec Layer 3 byte-compare. The wbuf is
        // zenoh-pico's growable byte-output buffer; we construct one,
        // pass to _z_close_encode, then read raw bytes via the
        // wbuf→zbuf→rptr path.
        .allowlist_type("_z_t_msg_close_t")
        .allowlist_type("_z_wbuf_t")
        .allowlist_type("_z_zbuf_t")
        .allowlist_function("_z_close_encode")
        .allowlist_function("_z_wbuf_make")
        .allowlist_function("_z_wbuf_len")
        .allowlist_function("_z_wbuf_clear")
        .allowlist_function("_z_wbuf_to_zbuf")
        .allowlist_function("_z_zbuf_clear")
        // R43 — frame + fragment Layer 3 byte-compare (VLE primitive
        // validation). Fragment uses _z_slice_t for the payload
        // (zero-cost wrap of a Rust &[u8]); Frame uses _z_zbuf_t* for
        // the payload, constructed via _z_slice_as_zbuf from a
        // _z_slice_t. _z_delete_context_t is the (deleter, context)
        // pair embedded in _z_slice_t — bindgen needs the type so
        // Rust can construct a zero-initialized non-owning slice.
        .allowlist_type("_z_t_msg_frame_t")
        .allowlist_type("_z_t_msg_fragment_t")
        .allowlist_type("_z_slice_t")
        .allowlist_type("_z_delete_context_t")
        .allowlist_function("_z_frame_encode")
        .allowlist_function("_z_fragment_encode")
        .allowlist_function("_z_slice_as_zbuf")
        // R44 — handshake bodies Layer 3 (scout + init + open + join).
        // scout exercises cbyte multi-bit packing without parent
        // flags; init/open/join exercise parent.S / parent.A
        // (positive + NEGATION) gating. Each codec brings a new
        // msg-struct shape (zid as fixed [u8;16], cookie as slice,
        // VLE next_sn chain).
        .allowlist_type("_z_s_msg_scout_t")
        .allowlist_type("_z_t_msg_init_t")
        .allowlist_type("_z_t_msg_open_t")
        .allowlist_type("_z_t_msg_join_t")
        .allowlist_type("z_what_t")
        .allowlist_type("z_whatami_t")
        .allowlist_function("_z_scout_encode")
        .allowlist_function("_z_init_encode")
        .allowlist_function("_z_open_encode")
        .allowlist_function("_z_join_encode")
        // bindgen layout-test surface: pin to `Debug` derivation to
        // unblock test-side equality checks against zenoh-pico's
        // typed shape.
        .derive_debug(true)
        .derive_default(true)
        .generate()
        .expect("bindgen generation");

    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("write bindings.rs");

    // Rerun policy: cargo watches the submodule's source tree so a
    // pin advance (or a local edit during diagnosis) triggers a
    // rebuild.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", include_dir.display());
    println!("cargo:rerun-if-changed={}/src", zenoh_src.display());
    println!(
        "cargo:rerun-if-changed={}/CMakeLists.txt",
        zenoh_src.display()
    );
}
