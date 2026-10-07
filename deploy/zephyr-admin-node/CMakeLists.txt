# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# zephyr-admin-node -- a wz node a zenoh host reconfigures at runtime, as a Zephyr
# application. Path B, like deploy/zephyr-app: Zephyr compiles the kernel, cargo
# emits the wz Rust staticlib, Zephyr's final image link joins them.
# `west build -b <board> deploy/zephyr-admin-node` is the entry point.
#
# The board is an ARGUMENT. The Rust target triple, the tick rate and the random
# source come from the board's Kconfig (deploy/zephyr-common/wz_zephyr_board.cmake),
# the node's address and identity from the board's network interface at run time
# (Zephyr's stack) or from the board's Kconfig (the lwIP backend, which has no
# Zephyr interface to ask), and the network stack from CONFIG_WZ_NET_BACKEND_*. What
# only one board needs is in boards/<board>.conf.

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(wz_zephyr_admin_node C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../zephyr-common/wz_zephyr_board.cmake)

target_sources(app PRIVATE src/main.c)

set(backend_env "")

if(CONFIG_WZ_NET_BACKEND_ZEPHYR_SOCKETS)
  set(backend_feature net-zephyr-sockets)
  # The POSIX socket layer the sockets seam calls (`zephyr_sys::socket`) and the
  # two board hooks that read the interface (wz_board_hooks.c).
  set(backend_undefined
    socket bind getsockname sendto recvfrom poll close
    wzApplicationGetIpv4Address wzApplicationGetZid)

elseif(CONFIG_WZ_NET_BACKEND_LWIP_MAC)
  set(backend_feature net-lwip-mac)
  set(backend_undefined "")

  if(CONFIG_WZ_MAC_CYT4BF)
    list(APPEND backend_feature mac-cyt4bf)
    # The chip's TRNG is the session's random source (CONFIG_WZ_ENTROPY_BOARD_HOOK,
    # selected by CONFIG_WZ_MAC_CYT4BF): Zephyr has no entropy driver for it, so the
    # PDL's TRNG driver is compiled here, from the module Zephyr already carries.
    set(pdl_src ${ZEPHYR_HAL_INFINEON_MODULE_DIR}/mtb-pdl-cat1/drivers/source)
    target_sources(app PRIVATE
      src/trng_cat1c.c
      ${pdl_src}/cy_crypto_core_trng.c
      ${pdl_src}/cy_crypto_core_hw.c)
    if(CONFIG_WZ_CYT4BF_PINS_T2G_LITE)
      target_sources(app PRIVATE boards/kit_t2g_b_h_lite/eth0_rmii_pins.c)
    else()
      message(FATAL_ERROR "wz: CONFIG_WZ_MAC_CYT4BF needs a pin routing (CONFIG_WZ_CYT4BF_PINS_*).")
    endif()
    list(APPEND backend_undefined wz_board_eth_pins_init wz_board_entropy_fill)
  else()
    message(FATAL_ERROR "wz: the lwIP backend needs a MAC (CONFIG_WZ_MAC_*).")
  endif()

  # lwIP's C is built by the CARGO build (lwip-sys), against this image's port: its
  # options and its compiler shim (lwip-port/). Everything the board states reaches
  # the Rust side through the environment, as compile-time constants, and a build
  # that leaves one unset does not compile.
  if(CONFIG_WZ_CYT4BF_REF_CLOCK_INTERNAL)
    set(ref_clock_divider ${CONFIG_WZ_CYT4BF_REF_CLOCK_DIVIDER})
  else()
    set(ref_clock_divider 0)
  endif()
  list(APPEND backend_env
    WZ_LWIP_PORT=${CMAKE_CURRENT_SOURCE_DIR}/lwip-port
    WZ_MAC_ADDRESS=${CONFIG_WZ_MAC_ADDRESS}
    WZ_STATIC_IPV4=${CONFIG_WZ_STATIC_IPV4}
    WZ_STATIC_NETMASK=${CONFIG_WZ_STATIC_NETMASK}
    WZ_STATIC_GATEWAY=${CONFIG_WZ_STATIC_GATEWAY}
    WZ_LINK_WAIT_MS=${CONFIG_WZ_LINK_WAIT_MS}
    WZ_REF_CLOCK_DIVIDER=${ref_clock_divider})

else()
  message(FATAL_ERROR "wz: no network backend is selected (CONFIG_WZ_NET_BACKEND_*).")
endif()

wz_zephyr_rust_app(
  RUST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/rust
  LIB      wz_zephyr_admin_node
  FEATURES ${backend_feature}
  CARGO_ENV ${backend_env}
  UNDEFINED ${backend_undefined}
)
