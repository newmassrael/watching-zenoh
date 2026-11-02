# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# zephyr-admin-loopback -- the witness that an admin node on Zephyr's own sockets takes a secure
# channel and decides its lifecycle verbs by the zid the peer's key proved (decision D12 of
# docs/session-lifecycle-intent.md). Built as zephyr-tls-loopback is: Zephyr compiles the kernel,
# cargo emits the wz Rust staticlib, and Zephyr's final image link pulls them together.
# `west build -b mps2/an385 deploy/zephyr-admin-loopback` is the single entry point; the image runs
# alone under QEMU on the board's loopback interface.

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(wz_zephyr_admin_loopback C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../zephyr-common/wz_zephyr_board.cmake)

target_sources(app PRIVATE src/main.c)

# The channel's C side is compiled here, against Zephyr's own Mbed TLS (the crate is built without
# its `vendored`), exactly as the admin node's `CONFIG_WZ_TLS` and zephyr-tls-loopback do.
set(tls_src ${CMAKE_CURRENT_SOURCE_DIR}/../../crates/wz-tls-mbedtls)
target_sources(app PRIVATE ${tls_src}/csrc/wz_tls.c)
target_include_directories(app PRIVATE ${tls_src}/csrc)
target_include_directories(mbedtls_iface INTERFACE ${tls_src}/config/zephyr)

wz_zephyr_rust_app(
  RUST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/rust
  LIB      wz_zephyr_admin_loopback
  UNDEFINED
    socket bind getsockname sendto recvfrom poll close
    connect send recv getpeername shutdown setsockopt listen accept
    wz_tls_start wz_tls_arena_peak wz_tls_arena_peak_reset
    wz_tls_identity_generate wz_tls_identity_zid wz_tls_identity_cert wz_tls_identity_free
    wz_tls_session_open wz_tls_session_set_io_ctx wz_tls_session_handshake
    wz_tls_session_peer_zid wz_tls_session_suite wz_tls_session_write wz_tls_session_read
    wz_tls_session_pending wz_tls_session_close_notify wz_tls_session_free
)
