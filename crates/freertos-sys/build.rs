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
// Config selection (the kernel + port #include "FreeRTOSConfig.h"):
//   - WZ_FREERTOS_CONFIG set:  that directory (deploy-supplied config).
//   - else:                    the in-crate reference port/ (mps2-an385 M3),
//                              so the crate + Layer G cross-compile standalone.

use std::env;
use std::path::PathBuf;

fn main() {
    let target = env::var("TARGET").unwrap_or_default();
    let host = env::var("HOST").unwrap_or_default();

    println!("cargo:rerun-if-env-changed=TARGET");
    println!("cargo:rerun-if-env-changed=WZ_FREERTOS_CONFIG");

    // Bare-metal cross detection (the only context the ARM_CM3 port compiles in).
    let is_cross_bare_metal =
        target != host && (target.ends_with("-none-eabi") || target.ends_with("-none-eabihf"));

    if !is_cross_bare_metal {
        // Host / non-bare-metal: stub. No static lib; the `links="freertos"`
        // declaration stays metadata-only (no rustc-link-lib directive), so it
        // does not trigger `-l freertos` at final link. The FFI decls in
        // src/lib.rs compile regardless; no host consumer links them.
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

    // Config dir: deploy override or the in-crate reference.
    let config_inc: PathBuf = match env::var("WZ_FREERTOS_CONFIG").ok() {
        Some(p) => {
            let p = PathBuf::from(p);
            if !p.join("FreeRTOSConfig.h").is_file() {
                panic!(
                    "WZ_FREERTOS_CONFIG={} is missing FreeRTOSConfig.h",
                    p.display()
                );
            }
            println!("cargo:rerun-if-changed={}", p.display());
            p
        }
        None => manifest_dir.join("port"),
    };
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
