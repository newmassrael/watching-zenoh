// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// freertos-sys build.rs — statically compiles the vendored FreeRTOS-Kernel
// V11.1.0 core + the GCC/ARM_CM3 (ARMv7-M / Cortex-M3) port + heap_4 via
// cc::Build. Modelled on lwip-sys/build.rs.
//
// KEY difference from lwip-sys: the lwIP NO_SYS core compiles on the host (x86)
// AND cross. The FreeRTOS ARM_CM3 port is Cortex-M-SPECIFIC (port.c manipulates
// the SysTick/NVIC/PendSV registers + uses ARMv7-M assembly), so it CANNOT
// compile on a host x86 toolchain. freertos-sys therefore only does the real C
// build on a bare-metal cross target; a host build emits no static lib (the
// hand-written FFI decls in src/lib.rs still compile — they are just unresolved
// until a final cross binary links the kernel).
//
// Build modes — mirror lwip-sys's WZ_LWIP_PORT contract EXACTLY: the
// FreeRTOSConfig.h is the CONSUMER's concern (board clock / NVIC prio-bits /
// heap size), NOT this -sys crate's. The crate never bakes a target-specific
// config as a silent default.
//   - host (non-bare-metal):            stub (the ARM_CM3 port is Cortex-M only).
//   - cross + WZ_FREERTOS_CONFIG set:   real build with that deploy-supplied
//                                       config dir (must hold FreeRTOSConfig.h).
//   - cross + WZ_FREERTOS_CONFIG unset: stub (no compile, no static lib).
// A reference config for cross VERIFICATION lives at `port/cross-test/`
// (FreeRTOSConfig.h) and is passed EXPLICITLY via WZ_FREERTOS_CONFIG by the
// Layer G CI lane — exactly as lwip-sys's port/cross-test is passed via
// WZ_LWIP_PORT — never as an implicit default.

use std::env;
use std::path::PathBuf;

fn main() {
    let target = env::var("TARGET").unwrap_or_default();
    let host = env::var("HOST").unwrap_or_default();
    let wz_freertos_config = env::var("WZ_FREERTOS_CONFIG").ok();

    println!("cargo:rerun-if-env-changed=TARGET");
    println!("cargo:rerun-if-env-changed=WZ_FREERTOS_CONFIG");

    // Bare-metal cross detection (the only context the ARM_CM3 port compiles in).
    let is_cross_bare_metal =
        target != host && (target.ends_with("-none-eabi") || target.ends_with("-none-eabihf"));

    // Real build ONLY on bare-metal cross WITH a consumer-supplied config. Host
    // OR cross-without-config => stub: no static lib; `links="freertos"` stays
    // metadata-only (no rustc-link-lib), so no `-l freertos` at final link. The
    // FFI decls in src/lib.rs compile regardless; no consumer links them without
    // supplying the config.
    if !(is_cross_bare_metal && wz_freertos_config.is_some()) {
        println!("cargo:freertos_real_build=0");
        return;
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let kernel = manifest_dir
        .join("../../vendor/freertos-kernel")
        .canonicalize()
        .expect(
            "canonicalize vendor/freertos-kernel — did \
             `git submodule update --init vendor/freertos-kernel` run?",
        );
    let kernel_inc = kernel.join("include");
    let port_dir = kernel.join("portable/GCC/ARM_CM3");
    let heap = kernel.join("portable/MemMang/heap_4.c");

    // Consumer-supplied config dir (presence guaranteed by the guard above).
    // Must contain FreeRTOSConfig.h — the kernel + ARM_CM3 port #include it.
    let config_inc = PathBuf::from(
        wz_freertos_config.expect("guarded: real build implies WZ_FREERTOS_CONFIG is set"),
    );
    if !config_inc.join("FreeRTOSConfig.h").is_file() {
        panic!(
            "WZ_FREERTOS_CONFIG={} is missing FreeRTOSConfig.h \
             (e.g. crates/freertos-sys/port/cross-test for cross verification)",
            config_inc.display()
        );
    }
    println!("cargo:rerun-if-changed={}", config_inc.display());

    let mut build = cc::Build::new();
    build
        .include(&config_inc)
        .include(&kernel_inc)
        .include(&port_dir)
        // The kernel predates several modern -W families; silence the noise.
        .flag_if_supported("-Wno-unused-parameter")
        .flag_if_supported("-Wno-implicit-fallthrough");

    // Core sources for the cooperative single-task profile (configUSE_TIMERS=0,
    // configUSE_EVENT_GROUPS=0, configUSE_STREAM_BUFFERS=0, configUSE_CO_ROUTINES=0
    // in the reference config, so those .c files are omitted).
    for f in ["tasks.c", "list.c", "queue.c"] {
        build.file(kernel.join(f));
    }
    build.file(port_dir.join("port.c"));
    build.file(&heap);

    // cc::Build derives arm-none-eabi-gcc + the -mcpu/-mthumb flags from TARGET
    // (thumbv7m-none-eabi -> Cortex-M3). A missing cross toolchain surfaces as a
    // clear cc-crate error rather than a silent host-compiler fallback.
    build.compile("freertos");

    println!("cargo:freertos_real_build=1");
}
