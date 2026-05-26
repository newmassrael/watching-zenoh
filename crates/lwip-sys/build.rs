// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
//      and lwip-sys/port/include (lwipopts.h + arch/cc.h supplied by
//      lwip-sys), compile into static liblwip.a in $OUT_DIR. Cargo
//      consumes via `links = "lwip"` + the standard cc-emitted
//      rustc-link-search.
//
//   2. bindgen: parse wrapper.h with the same `-I` paths, emit Rust
//      FFI declarations for the allowlist into $OUT_DIR/bindings.rs.
//      src/lib.rs include!()s the result.

use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let lwip_root = manifest_dir
        .join("../../vendor/lwip")
        .canonicalize()
        .expect("canonicalize vendor/lwip — did `git submodule update --init vendor/lwip` run?");
    let lwip_src = lwip_root.join("src");
    let lwip_inc = lwip_src.join("include");
    let port_inc = manifest_dir.join("port/include");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Stage 1: cc::Build → static liblwip.a.
    //
    // Source set enumeration follows lwIP's own FILES manifest for
    // the NO_SYS=1 + IPv4 + UDP + ARP/ethernet configuration. TCP
    // sources are intentionally excluded (LWIP_TCP=0 in lwipopts.h);
    // including them would link but inflate the static lib. IPv6 and
    // DHCP/AUTOIP/DNS sources are excluded for the same reason.
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
    println!("cargo:rerun-if-changed={}", port_inc.display());
    println!("cargo:rerun-if-changed={}", lwip_inc.display());

    let bindings = bindgen::Builder::default()
        .header(wrapper.to_str().expect("wrapper.h path utf8"))
        .clang_arg(format!("-I{}", port_inc.display()))
        .clang_arg(format!("-I{}", lwip_inc.display()))
        // Avoid layout tests — bindgen emits #[test]s by default that
        // assume Rust knows the C struct size at compile time; with
        // packed lwIP structs on some configs these can be flaky. The
        // FFI ABI is still respected; only the auto-test is dropped.
        .layout_tests(false)
        // UDP raw API.
        .allowlist_function("udp_new")
        .allowlist_function("udp_remove")
        .allowlist_function("udp_bind")
        .allowlist_function("udp_connect")
        .allowlist_function("udp_disconnect")
        .allowlist_function("udp_recv")
        .allowlist_function("udp_send")
        .allowlist_function("udp_sendto")
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
        .generate()
        .expect("bindgen lwIP headers");

    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("write OUT_DIR/bindings.rs");
}
