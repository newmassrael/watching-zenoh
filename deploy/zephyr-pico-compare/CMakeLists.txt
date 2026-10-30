# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# zephyr-pico-compare -- zenoh-pico on the T2G kit, over Zephyr's own network stack and the same
# Ethernet driver (deploy/zephyr-eth-wzmac) the wz admin node's Zephyr-sockets image runs on, so
# that the two can be measured on one controller, one driver and one stack. zenoh-pico is built as
# the Zephyr module its tree is (vendor/zenoh-pico/zephyr); the only wz in the image is the MAC
# crate behind the driver.
# `west build -b kit_t2g_b_h_lite/cyt4bf8cds/m7_0 deploy/zephyr-pico-compare` is the entry point.

cmake_minimum_required(VERSION 3.20.0)
include(${CMAKE_CURRENT_SOURCE_DIR}/../zephyr-eth-wzmac/zeth.cmake)
list(APPEND ZEPHYR_EXTRA_MODULES ${CMAKE_CURRENT_SOURCE_DIR}/../../vendor/zenoh-pico)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(wz_zephyr_pico_compare C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../zephyr-common/wz_zephyr_board.cmake)

# Since 1.10.2 zenoh-pico's Zephyr module takes every feature switch and every value (batch and
# fragment sizes, the lease, the socket timeout, the task limit) from Kconfig and makes its own
# `zenoh-pico/config.h` from them (cmake/feature_config.cmake), so the image states them in
# prj.conf and nothing here makes a header. Up to 1.10.1 the module listed twelve switches and
# the rest came from a configure-only run of the library's CMake on the host, which this file
# carried; the module's Kconfig has no default for a switch, so prj.conf now states the ones the
# library's own default build has on, to keep the image the configuration it was measured as.
zephyr_compile_definitions_ifdef(CONFIG_PICO_COMPARE_DEBUG ZENOH_DEBUG=3)

target_sources(app PRIVATE src/main.c)

if(NOT CONFIG_WZ_ZETH)
  message(FATAL_ERROR "wz: the comparison image has no network without the Ethernet driver "
                      "(the devicetree overlay states its node).")
endif()
wz_zeth_driver()

# The board's pieces the driver calls: the chip's TRNG (the entropy device's source), the clock
# register read, and the pin routing. They are the admin node's, which also compiles them.
set(admin_src ${CMAKE_CURRENT_SOURCE_DIR}/../zephyr-admin-node)
set(pdl_src ${ZEPHYR_HAL_INFINEON_MODULE_DIR}/mtb-pdl-cat1/drivers/source)
target_sources(app PRIVATE
  ${admin_src}/src/trng_cat1c.c
  ${pdl_src}/cy_crypto_core_trng.c
  ${pdl_src}/cy_crypto_core_hw.c
  ${admin_src}/src/clock_cat1c.c)
if(CONFIG_WZ_CYT4BF_PINS_T2G_LITE)
  target_sources(app PRIVATE ${admin_src}/boards/kit_t2g_b_h_lite/eth0_rmii_pins.c)
else()
  message(FATAL_ERROR "wz: CONFIG_WZ_ZETH needs a pin routing (CONFIG_WZ_CYT4BF_PINS_*).")
endif()

wz_zephyr_rust_app(
  RUST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/rust
  LIB      wz_zephyr_pico_compare
  UNDEFINED
    wz_board_eth_pins_init wz_board_entropy_fill
    wz_zeth_open wz_zeth_transmit wz_zeth_receive wz_zeth_poll_link wz_zeth_link_up
)
