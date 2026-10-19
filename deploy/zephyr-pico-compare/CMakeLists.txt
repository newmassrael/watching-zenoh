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

# zenoh-pico's Zephyr module takes its feature switches from Kconfig and everything else
# (batch and fragment sizes, the lease, the socket timeout, the task limit) from a
# `zenoh-pico/config.h` that only the library's own CMake makes. It is made by the library's own
# CMake here, configure-only and on the host, with the switches this build's Kconfig states, so
# that every other value is the library's own default and the header agrees with the module's
# compile definitions (a feature stated twice is stated the same).
set(pico_dir ${CMAKE_CURRENT_SOURCE_DIR}/../../vendor/zenoh-pico)
set(pico_config_dir ${CMAKE_BINARY_DIR}/zenoh-pico-config)
set(pico_switches "")
foreach(feature IN ITEMS
    LINK_SERIAL MULTI_THREAD PUBLICATION SUBSCRIPTION QUERY QUERYABLE RAWETH_TRANSPORT
    LINK_TCP LINK_UDP_UNICAST LINK_UDP_MULTICAST SCOUTING LINK_WS)
  if(CONFIG_ZENOH_PICO_${feature})
    list(APPEND pico_switches -DZ_FEATURE_${feature}=1)
  else()
    list(APPEND pico_switches -DZ_FEATURE_${feature}=0)
  endif()
endforeach()
# The host's own compiler, never the cross compiler of this build: the library's CMake looks for
# threads and the like, which a bare-metal toolchain does not have, and nothing is compiled here.
find_program(pico_host_cc NAMES cc gcc clang NO_CMAKE_FIND_ROOT_PATH REQUIRED)
file(REMOVE_RECURSE ${pico_config_dir})
execute_process(
  COMMAND ${CMAKE_COMMAND} -E env --unset=CC --unset=CFLAGS --unset=LDFLAGS
          ${CMAKE_COMMAND} -S ${pico_dir} -B ${pico_config_dir}
          -DCMAKE_C_COMPILER=${pico_host_cc}
          -DBUILD_EXAMPLES=OFF -DBUILD_TOOLS=OFF -DBUILD_TESTING=OFF -DBUILD_SHARED_LIBS=OFF
          ${pico_switches}
  RESULT_VARIABLE pico_config_rc
  OUTPUT_VARIABLE pico_config_out
  ERROR_VARIABLE pico_config_err)
if(NOT pico_config_rc EQUAL 0)
  message(FATAL_ERROR "wz: zenoh-pico's own configure step failed (${pico_config_rc}):\n"
                      "${pico_config_out}\n${pico_config_err}")
endif()
zephyr_include_directories(${pico_config_dir}/include)
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
