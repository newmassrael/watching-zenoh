// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// lwip-sys build.rs — statically compiles vendored lwIP 2.2.1 NO_SYS
// source set via cc::Build, then runs bindgen against the public
// headers to emit Rust FFI for the R311az-1 allowlist.
//
// Two stages:
//
//   1. cc::Build: enumerate the NO_SYS-mode lwIP source files
//      (core + ipv4 + netif/ethernet), include vendor/lwip/src/include
//      and a port include dir (lwipopts.h + arch/cc.h). The port
//      include resolves to `lwip-sys/port/include` on host builds and
//      to `$WZ_LWIP_PORT` on cross builds where the deploy crate
//      supplies a bare-metal-friendly port (R311az-3b).
//
//   2. bindgen: parse wrapper.h with the same `-I` paths, emit Rust
//      FFI declarations for the allowlist into $OUT_DIR/bindings.rs.
//      src/lib.rs include!()s the result.
//
// Build modes:
//   - host:                       real build, host port include
//   - cross + WZ_LWIP_PORT set:   real build, deploy-supplied port (R311az-3b)
//   - cross + WZ_LWIP_PORT unset: stub (empty bindings, no liblwip.a) (R311az-3a)

use std::env;
use std::path::PathBuf;

fn main() {
    let target = env::var("TARGET").unwrap_or_default();
    let host = env::var("HOST").unwrap_or_default();
    let wz_lwip_port = env::var("WZ_LWIP_PORT").ok();

    // Bare-metal cross detection. `target_os = "none"` toolchains have
    // no libc/stdio so the host port include cannot satisfy lwIP's
    // platform abstractions. Either the deploy crate supplies its own
    // port via `WZ_LWIP_PORT` (real cross build) or this crate emits an
    // empty bindings.rs and skips the C compile (stub mode).
    let is_cross_bare_metal = target != host
        && (target.ends_with("-none-eabi")
            || target.ends_with("-none-eabihf")
            || target.ends_with("-none-elf"));

    // ─── Stub path: bare-metal cross without a deploy-supplied port ───
    //
    // The stub emits an empty `bindings.rs` and skips both the
    // cc::Build static-lib build AND the `cargo:rustc-link-lib=static
    // =lwip` directive — without the link directive the
    // `links = "lwip"` manifest declaration stays metadata-only and
    // does not trigger an `-l lwip` at final link time. Downstream
    // crates that reference lwip-sys FFI symbols (wz-link-lwip) are
    // gated to non-bare-metal targets via their own crate-level cfg,
    // so the empty surface is never imported.
    if is_cross_bare_metal && wz_lwip_port.is_none() {
        let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
        std::fs::write(
            out_dir.join("bindings.rs"),
            "// R311az-3a/3b cross-compile stub — no FFI symbols emitted.\n\
             // Set WZ_LWIP_PORT=/path/to/deploy/lwip-port to enable the\n\
             // real cross build (R311az-3b deploy-supplied lwipopts.h + arch/cc.h).\n",
        )
        .expect("write stub bindings.rs");
        // R311az-3b-ii — propagate build mode to dependents.
        //
        // `links = "lwip"` exposes `cargo:KEY=VALUE` lines as
        // `DEP_LWIP_<KEY>` env vars in the build.rs of any direct
        // dependent (wz-link-lwip, wz with optional lwip-sys dep). The
        // dependent build.rs converts the metadata into a
        // `cargo:rustc-cfg=lwip_real_build` so consuming crates can
        // gate code blocks on whether the FFI symbols are real or
        // stubbed without re-deriving the WZ_LWIP_PORT + TARGET logic
        // (single source of truth: this build.rs).
        println!("cargo:lwip_real_build=0");
        println!("cargo:rerun-if-env-changed=TARGET");
        println!("cargo:rerun-if-env-changed=WZ_LWIP_PORT");
        return;
    }

    // ─── Real path: host build OR cross + WZ_LWIP_PORT supplied ───
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let lwip_root = manifest_dir
        .join("../../vendor/lwip")
        .canonicalize()
        .expect("canonicalize vendor/lwip — did `git submodule update --init vendor/lwip` run?");
    let lwip_src = lwip_root.join("src");
    let lwip_inc = lwip_src.join("include");
    let host_port_inc = manifest_dir.join("port/include");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // R311az-3b — port include selection.
    //
    // Cross build with a deploy-supplied port: the deploy crate's
    // `WZ_LWIP_PORT` directory must contain `lwipopts.h` (lwIP
    // options) and `arch/cc.h` (compiler/platform abstractions for
    // the target). Validate the path eagerly so a typo surfaces at
    // build configure time rather than as a confusing C preprocessor
    // error a few stages downstream.
    //
    // Host build: in-crate `port/include` ships a glibc-friendly
    // `lwipopts.h` + `arch/cc.h` good enough for the host smoke
    // tests; no override.
    let port_inc: PathBuf = if is_cross_bare_metal {
        let p = PathBuf::from(
            wz_lwip_port
                .as_ref()
                .expect("is_cross_bare_metal branch already verified WZ_LWIP_PORT is set"),
        );
        if !p.is_dir() {
            panic!(
                "WZ_LWIP_PORT={} is not a directory; deploy crate must supply \
                 an include directory containing lwipopts.h + arch/cc.h",
                p.display()
            );
        }
        if !p.join("lwipopts.h").is_file() {
            panic!(
                "WZ_LWIP_PORT={} is missing lwipopts.h; deploy crate must \
                 supply the lwIP options header for the target",
                p.display()
            );
        }
        if !p.join("arch").join("cc.h").is_file() {
            panic!(
                "WZ_LWIP_PORT={} is missing arch/cc.h; deploy crate must \
                 supply the platform abstraction header for the target",
                p.display()
            );
        }
        println!("cargo:rerun-if-changed={}", p.display());
        p
    } else {
        host_port_inc.clone()
    };

    // Stage 1: cc::Build → static liblwip.a.
    //
    // Source set enumeration follows lwIP's own FILES manifest for
    // the NO_SYS=1 + IPv4 + UDP + ARP/ethernet configuration. TCP
    // sources are intentionally excluded (LWIP_TCP=0 in lwipopts.h);
    // including them would link but inflate the static lib. IPv6 and
    // DHCP/AUTOIP/DNS sources are excluded for the same reason.
    //
    // On cross builds cc::Build picks up `arm-none-eabi-gcc` (or the
    // appropriate cross compiler) via the standard `TARGET`-derived
    // tool lookup. If the cross toolchain is not installed the build
    // surfaces a clear cc-crate-level error rather than silently
    // falling back to the host compiler.
    let mut build = cc::Build::new();
    build
        .include(&port_inc)
        .include(&lwip_inc)
        // Silence the harmless warnings that lwIP emits with modern
        // -W flags (it predates many gcc warning families). Each flag
        // resolves to a no-op on toolchains that don't recognise it.
        .flag_if_supported("-Wno-address")
        .flag_if_supported("-Wno-unused-parameter")
        .flag_if_supported("-Wno-unused-but-set-variable")
        .flag_if_supported("-Wno-implicit-fallthrough")
        .flag_if_supported("-Wno-sign-compare")
        .flag_if_supported("-Wno-stringop-truncation");

    let core_files: &[&str] = &[
        // core/ — protocol-independent infrastructure
        "core/def.c",
        "core/inet_chksum.c",
        "core/init.c",
        "core/ip.c",
        "core/mem.c",
        "core/memp.c",
        "core/netif.c",
        "core/pbuf.c",
        "core/sys.c",
        "core/timeouts.c",
        "core/udp.c",
        // core/ipv4/ — IPv4 (DHCP/AUTOIP/DNS sources excluded)
        "core/ipv4/etharp.c",
        "core/ipv4/icmp.c",
        "core/ipv4/ip4.c",
        "core/ipv4/ip4_addr.c",
        "core/ipv4/ip4_frag.c",
        // core/ipv4/igmp.c — multicast membership (R311ir scout RX).
        // Body is #if LWIP_IGMP-gated; with LWIP_IGMP off it compiles to
        // ~empty, so it is safe to list unconditionally across ports.
        "core/ipv4/igmp.c",
        // netif/ — ethernet glue (loopif compiled in via LWIP_NETIF_LOOPBACK)
        "netif/ethernet.c",
    ];
    for f in core_files {
        build.file(lwip_src.join(f));
    }

    build.compile("lwip");

    // Stage 2: bindgen → Rust FFI.
    //
    // The allowlist mirrors R311az-pre's wz-link-lwip surface: 6 raw
    // udp_* fns + pbuf alloc/free/copy + netif lifecycle + sys_check_
    // timeouts (NO_SYS=1 timer pump) + lwip_init.
    let wrapper = manifest_dir.join("wrapper.h");
    println!("cargo:rerun-if-changed={}", wrapper.display());
    println!("cargo:rerun-if-changed={}", host_port_inc.display());
    println!("cargo:rerun-if-changed={}", lwip_inc.display());
    println!("cargo:rerun-if-env-changed=TARGET");
    println!("cargo:rerun-if-env-changed=WZ_LWIP_PORT");

    let mut bindgen_builder = bindgen::Builder::default()
        .header(wrapper.to_str().expect("wrapper.h path utf8"))
        .clang_arg(format!("-I{}", port_inc.display()))
        .clang_arg(format!("-I{}", lwip_inc.display()))
        // Avoid layout tests — bindgen emits #[test]s by default that
        // assume Rust knows the C struct size at compile time; with
        // packed lwIP structs on some configs these can be flaky. The
        // FFI ABI is still respected; only the auto-test is dropped.
        .layout_tests(false)
        // R311az-3b — no_std-compatible bindings.
        //
        // src/lib.rs has `#![cfg_attr(target_os = "none", no_std)]` so
        // the emitted bindings.rs must not reference `::std`. Switch
        // bindgen to emit `::core::option::Option` and pull C-types
        // from `core::ffi::c_*` (rustc 1.64+). The host build still
        // sees the same bindings via core, which is re-exported by
        // std on hosted targets — no host regression.
        .use_core()
        .ctypes_prefix("::core::ffi");

    // R311az-3b — cross-target bindings.
    //
    // libclang resolves layout-dependent typedefs (sizeof(long),
    // pointer width, struct padding) from the active target triple.
    // Without `--target=$TARGET` clang assumes the host triple and
    // emits bindings whose `repr(C)` layouts diverge from the
    // arm-none-eabi gcc compile of the same headers — a silent ABI
    // mismatch that surfaces as memory corruption at runtime. Pass
    // the rustc TARGET through so bindgen and cc see the same triple.
    //
    // R2169 — `--target` ALONE IS NOT ENOUGH, and the half it was missing is
    // the half that says there is no libc. A `-none-eabi` triple does not by
    // itself make clang compile freestanding: `__STDC_HOSTED__` stays 1, so
    // clang's own `stdint.h` runs its `#include_next <stdint.h>` and lands on
    // the HOST's glibc header, which cannot serve a bare-metal ARM target.
    // What surfaced was seven `unknown type name 'uint8_t' ... 'uintptr_t'`
    // errors against `vendor/lwip/src/include/lwip/arch.h` -- a header that is
    // entirely correct, doing `#include <stdint.h>` and using what it asks for.
    //
    // MEASURED 2026-08-28, `cargo build -p lwip-sys --target
    // thumbv7m-none-eabi`, default libclang (`/usr/lib/llvm-22/lib/
    // libclang-22.so.1`, established with `LD_DEBUG=libs` rather than inferred
    // from filenames): 101 without this flag, 0 with it, nothing else changed.
    // The `cc::Build` half never showed it because that half runs
    // `arm-none-eabi-gcc`, which brings newlib's headers with it -- so the two
    // halves of this build script disagreed about what a bare-metal target is,
    // and only the bindgen half was wrong.
    if is_cross_bare_metal {
        bindgen_builder = bindgen_builder
            .clang_arg(format!("--target={}", target))
            .clang_arg("-ffreestanding");
    }

    let bindings = bindgen_builder
        // UDP raw API.
        .allowlist_function("udp_new")
        .allowlist_function("udp_remove")
        .allowlist_function("udp_bind")
        .allowlist_function("udp_connect")
        .allowlist_function("udp_disconnect")
        .allowlist_function("udp_recv")
        .allowlist_function("udp_send")
        .allowlist_function("udp_sendto")
        // IGMP multicast membership (R311ir scout RX). join/leave on
        // IP4_ADDR_ANY apply to every IGMP-capable netif; the udp_pcb
        // bound to the scout port then receives the joined group.
        .allowlist_function("igmp_joingroup")
        .allowlist_function("igmp_leavegroup")
        // pbuf lifecycle (zero-copy buffer chain).
        .allowlist_function("pbuf_alloc")
        .allowlist_function("pbuf_free")
        .allowlist_function("pbuf_take")
        .allowlist_function("pbuf_copy_partial")
        // netif lifecycle (deploy-managed at runtime; R311az-2 uses
        // netif_default ptr for loopback/test).
        .allowlist_function("netif_add_noaddr")
        .allowlist_function("netif_set_default")
        .allowlist_function("netif_set_up")
        // Loopback poll (NO_SYS + LWIP_NETIF_LOOPBACK_MULTITHREADING=0
        // requires explicit poll to drain the loop_netif output queue
        // into ip_input).
        .allowlist_function("netif_poll_all")
        // Loopback netif handle + multicast TX egress selection
        // (R311ir). The host smoke routes multicast TX over the loop
        // netif to exercise scout multicast RX deterministically; real
        // deploys point this at their ethernet netif.
        .allowlist_function("netif_get_loopif")
        .allowlist_function("ip4_set_default_multicast_netif")
        // Top-level init + timer pump.
        .allowlist_function("lwip_init")
        .allowlist_function("sys_check_timeouts")
        // Types referenced by the above.
        .allowlist_type("udp_pcb")
        .allowlist_type("pbuf")
        .allowlist_type("pbuf_type")
        .allowlist_type("pbuf_layer")
        .allowlist_type("ip_addr_t")
        .allowlist_type("ip4_addr_t")
        .allowlist_type("netif")
        .allowlist_type("err_t")
        .allowlist_type("err_enum_t")
        .generate();

    // R2169 — a bindgen failure must not accuse lwIP of a defect that is this
    // BUILD SCRIPT's. `.expect("bindgen lwIP headers")` printed seven
    // `unknown type name 'uint8_t'` errors against
    // `vendor/lwip/src/include/lwip/arch.h`, and that header is correct: it
    // does `#include <stdint.h>` and uses what it asked for. The missing
    // `-ffreestanding` above is what made those types absent, and reading the
    // panic cost a round of auditing headers that had nothing wrong with them.
    //
    // ⚠ THE FIRST DIAGNOSIS WRITTEN HERE WAS WRONG, and it is worth saying so
    // where the next reader is: it blamed a libclang installed without its own
    // freestanding headers, on the strength of a control/treatment pair where
    // `LIBCLANG_PATH=/usr/lib/llvm-19/lib` turned 101 into 0. That directory
    // contains NO libclang at all -- the treatment arm silently fell through to
    // a different library, so the experiment moved a term nobody had named.
    // `LD_DEBUG=libs` then said the default arm loads llvm-22's, whose
    // freestanding headers are present. A pair of runs that differ is not an
    // attribution until the thing that differs has been READ rather than
    // assumed.
    //
    // So the check below is a backstop for the same SYMPTOM arriving from a
    // genuinely broken toolchain, and it states what it does not know.
    let bindings = match bindings {
        Ok(b) => b,
        Err(e) => {
            let msg = e.to_string();
            let missing_c_types = ["uint8_t", "uintptr_t", "size_t", "stddef.h", "stdint.h"]
                .iter()
                .any(|needle| msg.contains(needle));
            if missing_c_types {
                panic!(
                    "bindgen could not parse the lwIP headers, and the errors are \
                     about C's own fixed-width types.\n\
                     \n\
                     THIS IS NOT AN lwIP OR PORT PROBLEM. Under `--target={target}` \
                     there is no libc, so `<stdint.h>` has to come from the \
                     libclang's own freestanding include directory. This crate \
                     already passes `-ffreestanding` for that reason, so if you are \
                     reading this the flag is not reaching clang or that directory \
                     is not there.\n\
                     \n\
                     Check both, in that order: that the `-ffreestanding` above is \
                     still on the cross branch, and that the library `clang-sys` \
                     LOADED -- not the one its filename suggests, run with \
                     `LD_DEBUG=libs` to see it -- has a `lib/clang/<version>/\
                     include/stdint.h` beside it.\n\
                     \n\
                     bindgen's own diagnostics follow.\n{msg}"
                );
            }
            panic!("bindgen lwIP headers: {msg}");
        }
    };

    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("write OUT_DIR/bindings.rs");

    // R311az-3b-ii — propagate real-build mode to dependents. See the
    // stub branch above for the rationale; same metadata key, value
    // `=1` so direct dependents flip `lwip_real_build` on.
    println!("cargo:lwip_real_build=1");
}
