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
    # The core clock the image checks at boot is read from the clock registers
    # (CONFIG_WZ_CORE_CLOCK_BOARD_HOOK, selected by CONFIG_WZ_MAC_CYT4BF) through the
    # PDL's sysclk driver, which Zephyr's HAL module already compiles for this family.
    target_sources(app PRIVATE src/clock_cat1c.c)
    if(CONFIG_WZ_CYT4BF_PINS_T2G_LITE)
      target_sources(app PRIVATE boards/kit_t2g_b_h_lite/eth0_rmii_pins.c)
    else()
      message(FATAL_ERROR "wz: CONFIG_WZ_MAC_CYT4BF needs a pin routing (CONFIG_WZ_CYT4BF_PINS_*).")
    endif()
    list(APPEND backend_undefined wz_board_eth_pins_init wz_board_entropy_fill)
    # The SPI master on the MikroBUS socket, which the SPI probe and the 10BASE-T1S
    # interface both use, and not together: both open SCB3. The refusal is made here and
    # not as a Kconfig dependency because an unmet dependency only turns the symbol off
    # with a warning, and the build would go on without the interface. The PDL's SCB
    # SPI and clock drivers are compiled by Zephyr's own HAL module once
    # CONFIG_USE_INFINEON_SPI is on (both select it), so only this image's thin driver
    # and the board's pin routing are added here.
    if(CONFIG_WZ_T2G_SPI_PROBE AND CONFIG_WZ_T1S)
      message(FATAL_ERROR "wz: CONFIG_WZ_T2G_SPI_PROBE and CONFIG_WZ_T1S both open SCB3; "
                          "a build has one of them (the 10BASE-T1S bring-up reads the chip's "
                          "identity itself and logs it).")
    endif()
    if(CONFIG_WZ_T2G_SPI_PROBE OR CONFIG_WZ_T1S)
      target_sources(app PRIVATE src/scb_spi.c)
      if(CONFIG_WZ_CYT4BF_PINS_T2G_LITE)
        target_sources(app PRIVATE boards/kit_t2g_b_h_lite/mikrobus_spi_pins.c)
      else()
        message(FATAL_ERROR "wz: the MikroBUS SPI master needs a pin routing (CONFIG_WZ_CYT4BF_PINS_*).")
      endif()
      list(APPEND backend_undefined
        wz_board_spi_pins_init wz_scb_spi_clock_claim wz_scb_spi_start wz_scb_spi_exchange)
    endif()
    if(CONFIG_WZ_T2G_SPI_PROBE)
      list(APPEND backend_feature spi-probe)
      set(spi_probe_env WZ_SPI_PROBE_HZ=${CONFIG_WZ_SPI_PROBE_HZ})
    else()
      set(spi_probe_env "")
    endif()
    # The 10BASE-T1S interface: the chip's two control lines as the board routes them,
    # beside the SPI master above. What it states (addresses, PLCA, rates) is handed to
    # the Rust side below, after the station address is known.
    if(CONFIG_WZ_T1S)
      list(APPEND backend_feature t1s-lan865x)
      if(CONFIG_WZ_CYT4BF_PINS_T2G_LITE)
        target_sources(app PRIVATE boards/kit_t2g_b_h_lite/mikrobus_t1s_lines.c)
      else()
        message(FATAL_ERROR "wz: CONFIG_WZ_T1S needs a pin routing (CONFIG_WZ_CYT4BF_PINS_*).")
      endif()
      list(APPEND backend_undefined
        wz_board_t1s_lines_init wz_board_t1s_reset_set wz_board_t1s_irq_asserted)
    endif()
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
  # The station address is either given (the build then hands it over, and the
  # Rust side reads it as a constant) or drawn at boot (the build hands over
  # nothing, and the Rust side draws). There is no value a build falls back to: one
  # every build shares is one two boards on a network would both answer to.
  if(CONFIG_WZ_MAC_SOURCE_EXPLICIT)
    if("${CONFIG_WZ_MAC_ADDRESS}" STREQUAL "")
      message(FATAL_ERROR "wz: CONFIG_WZ_MAC_SOURCE_EXPLICIT needs CONFIG_WZ_MAC_ADDRESS, "
                          "an address of its own for this board.")
    endif()
    set(mac_env WZ_MAC_ADDRESS=${CONFIG_WZ_MAC_ADDRESS})
  else()
    set(mac_env "")
  endif()

  # The 10BASE-T1S interface's values, each one the lab's to state: the build refuses an
  # empty or impossible one by name instead of handing the Rust side a number nobody
  # chose. (A Kconfig `int` with no default and no range is empty until it is set; a
  # range would give it the range's lowest value, which is a default by another name.)
  set(t1s_env "")
  if(CONFIG_WZ_T1S)
    if("${CONFIG_WZ_T1S_IPV4}" STREQUAL "")
      message(FATAL_ERROR "wz: CONFIG_WZ_T1S needs CONFIG_WZ_T1S_IPV4, an address of its own "
                          "on the segment (it has no default).")
    endif()
    if(CONFIG_WZ_T1S_PLCA)
      foreach(plca_value IN ITEMS ID COUNT)
        if(NOT "${CONFIG_WZ_T1S_PLCA_NODE_${plca_value}}" MATCHES "^[0-9]+$")
          message(FATAL_ERROR "wz: CONFIG_WZ_T1S_PLCA needs CONFIG_WZ_T1S_PLCA_NODE_${plca_value}, "
                              "a decimal number (it has no default); found "
                              "'${CONFIG_WZ_T1S_PLCA_NODE_${plca_value}}'.")
        endif()
      endforeach()
      if(CONFIG_WZ_T1S_PLCA_NODE_ID GREATER 254)
        message(FATAL_ERROR "wz: CONFIG_WZ_T1S_PLCA_NODE_ID is ${CONFIG_WZ_T1S_PLCA_NODE_ID}; "
                            "0 is the coordinator, 1 to 254 a follower, and 255 means PLCA off "
                            "(CONFIG_WZ_T1S_PLCA=n asks for that).")
      endif()
      if(CONFIG_WZ_T1S_PLCA_NODE_COUNT LESS 1 OR CONFIG_WZ_T1S_PLCA_NODE_COUNT GREATER 255)
        message(FATAL_ERROR "wz: CONFIG_WZ_T1S_PLCA_NODE_COUNT is ${CONFIG_WZ_T1S_PLCA_NODE_COUNT}; "
                            "it is 1 to 255.")
      endif()
      if(NOT CONFIG_WZ_T1S_PLCA_NODE_ID LESS CONFIG_WZ_T1S_PLCA_NODE_COUNT)
        message(FATAL_ERROR "wz: CONFIG_WZ_T1S_PLCA_NODE_COUNT (${CONFIG_WZ_T1S_PLCA_NODE_COUNT}) "
                            "must exceed CONFIG_WZ_T1S_PLCA_NODE_ID (${CONFIG_WZ_T1S_PLCA_NODE_ID}): "
                            "the node count is the highest id on the segment plus one.")
      endif()
      set(t1s_plca_on 1)
      set(t1s_plca_id ${CONFIG_WZ_T1S_PLCA_NODE_ID})
      set(t1s_plca_count ${CONFIG_WZ_T1S_PLCA_NODE_COUNT})
    else()
      set(t1s_plca_on 0)
      set(t1s_plca_id 0)
      set(t1s_plca_count 0)
    endif()
    if(CONFIG_WZ_MAC_SOURCE_EXPLICIT)
      if("${CONFIG_WZ_T1S_MAC_ADDRESS}" STREQUAL "")
        message(FATAL_ERROR "wz: CONFIG_WZ_MAC_SOURCE_EXPLICIT with CONFIG_WZ_T1S needs "
                            "CONFIG_WZ_T1S_MAC_ADDRESS, an address of its own for this interface.")
      endif()
      string(TOLOWER "${CONFIG_WZ_T1S_MAC_ADDRESS}" t1s_mac_lower)
      string(TOLOWER "${CONFIG_WZ_MAC_ADDRESS}" rmii_mac_lower)
      if(t1s_mac_lower STREQUAL rmii_mac_lower)
        message(FATAL_ERROR "wz: CONFIG_WZ_T1S_MAC_ADDRESS is the onboard port's address "
                            "(${CONFIG_WZ_MAC_ADDRESS}); two interfaces of one node need two.")
      endif()
      list(APPEND t1s_env WZ_T1S_MAC_ADDRESS=${CONFIG_WZ_T1S_MAC_ADDRESS})
    endif()
    if(CONFIG_WZ_T1S_RESET_LINE)
      set(t1s_reset_wait_ms ${CONFIG_WZ_T1S_RESET_WAIT_MS})
    else()
      set(t1s_reset_wait_ms 0)
    endif()
    if(CONFIG_WZ_T1S_ACCEPT_ALL_MULTICAST)
      set(t1s_multicast 1)
    else()
      set(t1s_multicast 0)
    endif()
    if(CONFIG_WZ_T1S_BUILD_VALUES_ONLY)
      set(t1s_build_values 1)
    else()
      set(t1s_build_values 0)
    endif()
    list(APPEND t1s_env
      WZ_T1S_BUILD_VALUES=${t1s_build_values}
      WZ_T1S_SPI_HZ=${CONFIG_WZ_T1S_SPI_HZ}
      WZ_T1S_SERVICE_MS=${CONFIG_WZ_T1S_SERVICE_MS}
      WZ_T1S_RESET_WAIT_MS=${t1s_reset_wait_ms}
      WZ_T1S_PLCA_ON=${t1s_plca_on}
      WZ_T1S_PLCA_ID=${t1s_plca_id}
      WZ_T1S_PLCA_COUNT=${t1s_plca_count}
      WZ_T1S_MULTICAST=${t1s_multicast}
      WZ_T1S_IPV4=${CONFIG_WZ_T1S_IPV4}
      WZ_T1S_NETMASK=${CONFIG_WZ_T1S_NETMASK}
      WZ_T1S_GATEWAY=${CONFIG_WZ_T1S_GATEWAY})
  endif()

  list(APPEND backend_env
    WZ_LWIP_PORT=${CMAKE_CURRENT_SOURCE_DIR}/lwip-port
    ${mac_env}
    ${spi_probe_env}
    ${t1s_env}
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
