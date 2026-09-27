# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# zephyr-app — Path-B Zephyr application: Zephyr compiles the kernel, cargo
# emits the wz Rust staticlib, and Zephyr's final image link pulls them together
# (the analogue of zephyr-lang-rust's modules/lang/rust/CMakeLists.txt link step,
# but bindgen-free and reusing wz's CoopRuntime SSOT). `west build -b
# mps2/an385 deploy/zephyr-app` is the single entry point.
#
# R2916 — the board is mps2/an385 (Cortex-M3, 4 MB), where it was
# qemu_cortex_m3 (64 KB of SRAM): the image now carries Zephyr's own net stack
# and sockets, which the smaller board has no room for. It is the machine the
# FreeRTOS image boots on too. lwIP is gone from this build — the profile's
# network seam is Zephyr's sockets (`wz_runtime_zephyr::net`).

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(wz_zephyr_app C)

# ── wz Rust staticlib (cross-built by cargo, linked into the Zephyr image) ──
set(WZ_RUST_DIR    ${CMAKE_CURRENT_SOURCE_DIR}/rust)
set(WZ_RUST_TARGET thumbv7m-none-eabi)
set(WZ_RUST_LIB    ${WZ_RUST_DIR}/target/${WZ_RUST_TARGET}/release/libwz_zephyr_app.a)

# Always-run (ALL + no OUTPUT) so Rust source edits are picked up; cargo's own
# incremental check keeps the no-change case cheap. BYPRODUCTS registers the
# archive as this target's product so ninja can depend on it.
add_custom_target(wz_rust_lib ALL
	BYPRODUCTS ${WZ_RUST_LIB}
	COMMAND cargo build --release --target ${WZ_RUST_TARGET}
	        --manifest-path ${WZ_RUST_DIR}/Cargo.toml
	WORKING_DIRECTORY ${WZ_RUST_DIR}
	COMMENT "cargo build wz Rust staticlib (Zephyr Path B, Zephyr-socket link)"
	USES_TERMINAL
	VERBATIM
)

target_sources(app PRIVATE src/main.c)
add_dependencies(app wz_rust_lib)

# R2918 — the instant the board sets its realtime clock to at boot (src/main.c),
# standing in for an SNTP sync on a board with no RTC: this build's own time,
# in seconds since the Unix epoch, UTC.
string(TIMESTAMP WZ_BOARD_EPOCH_SECS "%s" UTC)
target_compile_definitions(app PRIVATE WZ_BOARD_EPOCH_SECS=${WZ_BOARD_EPOCH_SECS})

# Link the staticlib + force-keep the Zephyr symbols ONLY the Rust side
# references. Zephyr's libraries are scanned BEFORE the appended librustlib.a,
# so without `--undefined` the linker would drop them (no C caller) and the
# Rust references would then dangle as `undefined reference`. This is Zephyr's
# own idiom (it does the same for e.g. _sw_isr_table) — an explicit
# kernel-symbol contract. The second group is the POSIX socket layer the
# profile's network seam calls (`zephyr_sys::socket`).
target_link_libraries(app PUBLIC
	${WZ_RUST_LIB}
	-Wl,--undefined=sys_clock_tick_get
	-Wl,--undefined=k_malloc
	-Wl,--undefined=k_free
	-Wl,--undefined=socket
	-Wl,--undefined=bind
	-Wl,--undefined=sendto
	-Wl,--undefined=recvfrom
	-Wl,--undefined=poll
	-Wl,--undefined=close
)
