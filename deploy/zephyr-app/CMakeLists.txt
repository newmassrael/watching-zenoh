# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# zephyr-app — Path-B Zephyr application: Zephyr compiles the kernel, cargo
# emits the wz Rust staticlib, and Zephyr's final image link pulls them together
# (the analogue of zephyr-lang-rust's modules/lang/rust/CMakeLists.txt link step,
# but bindgen-free and reusing wz's CoopRuntime SSOT). `west build -b
# qemu_cortex_m3 deploy/zephyr-app` is the single entry point.

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(wz_zephyr_app C)

# ── wz Rust staticlib (cross-built by cargo, linked into the Zephyr image) ──
set(WZ_RUST_DIR    ${CMAKE_CURRENT_SOURCE_DIR}/rust)
set(WZ_RUST_TARGET thumbv7m-none-eabi)
set(WZ_RUST_LIB    ${WZ_RUST_DIR}/target/${WZ_RUST_TARGET}/release/libwz_zephyr_app.a)

# The lwip-sys cross-test port (lwipopts.h + arch/cc.h). Setting WZ_LWIP_PORT
# lights up wz-link-lwip's `lwip_real_build` cfg so the UDP echo compiles; the
# same port the FreeRTOS + bare-metal QEMU lanes use (MEM_SIZE 4 KB, fits the
# 64 KB SoC). CC_<target> pins lwip-sys's `cc` build to the host arm-none-eabi
# toolchain (ARMv7-M soft-float AAPCS) rather than whatever CC Zephyr exports —
# its objects link cleanly with the arm-zephyr-eabi kernel objects (same EABI),
# exactly as the rustc objects already do.
get_filename_component(WZ_REPO_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../.. ABSOLUTE)
set(WZ_LWIP_PORT ${WZ_REPO_ROOT}/crates/lwip-sys/port/cross-test)

# Always-run (ALL + no OUTPUT) so Rust source edits are picked up; cargo's own
# incremental check keeps the no-change case cheap. BYPRODUCTS registers the
# archive as this target's product so ninja can depend on it.
add_custom_target(wz_rust_lib ALL
	BYPRODUCTS ${WZ_RUST_LIB}
	COMMAND ${CMAKE_COMMAND} -E env
	        WZ_LWIP_PORT=${WZ_LWIP_PORT}
	        CC_thumbv7m_none_eabi=arm-none-eabi-gcc
	        cargo build --release --target ${WZ_RUST_TARGET}
	        --manifest-path ${WZ_RUST_DIR}/Cargo.toml
	WORKING_DIRECTORY ${WZ_RUST_DIR}
	COMMENT "cargo build wz Rust staticlib (Zephyr Path B, lwIP echo)"
	USES_TERMINAL
	VERBATIM
)

target_sources(app PRIVATE src/main.c)
add_dependencies(app wz_rust_lib)

# Link the staticlib + force-keep the kernel symbols ONLY the Rust side
# references. libkernel.a is scanned BEFORE the appended librustlib.a, so
# without `--undefined` the linker would drop k_malloc / k_free /
# sys_clock_tick_get (no C caller yet) and the Rust references would then
# dangle as `undefined reference`. This is Zephyr's own idiom (it does the
# same for e.g. _sw_isr_table) — an explicit kernel-symbol contract.
target_link_libraries(app PUBLIC
	${WZ_RUST_LIB}
	-Wl,--undefined=sys_clock_tick_get
	-Wl,--undefined=k_malloc
	-Wl,--undefined=k_free
)
