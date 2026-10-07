# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# zephyr-app -- Path-B Zephyr application: Zephyr compiles the kernel, cargo
# emits the wz Rust staticlib, and Zephyr's final image link pulls them together
# (the analogue of zephyr-lang-rust's modules/lang/rust/CMakeLists.txt link step,
# but bindgen-free and reusing wz's CoopRuntime SSOT). `west build -b <board>
# deploy/zephyr-app` is the single entry point; the lane's reference board is
# mps2/an385.
#
# R2916 -- the reference board is mps2/an385 (Cortex-M3, 4 MB), where it was
# qemu_cortex_m3 (64 KB of SRAM): the image carries Zephyr's own net stack and
# sockets, which the smaller board has no room for. lwIP is not in this build:
# the profile's network seam is Zephyr's sockets (`wz_runtime_zephyr::net`).
#
# The board is an ARGUMENT. What used to be QEMU constants -- the Rust target
# triple, the tick rate, the random source -- is read from the board's own
# Kconfig by deploy/zephyr-common/wz_zephyr_board.cmake. What only the QEMU
# board needs lives in boards/mps2_an385.conf.

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(wz_zephyr_app C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../zephyr-common/wz_zephyr_board.cmake)

target_sources(app PRIVATE src/main.c)

# The UNDEFINED list is the POSIX socket layer the profile's network seam calls
# (`zephyr_sys::socket`).
wz_zephyr_rust_app(
  RUST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/rust
  LIB      wz_zephyr_app
  UNDEFINED
    socket bind getsockname sendto recvfrom poll close
)
