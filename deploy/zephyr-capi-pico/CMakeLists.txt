# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# zephyr-capi-pico -- the pico C ABI on the T2G kit: the zenoh-pico program of the comparison image
# (deploy/zephyr-pico-compare/src/main.c, a queryable answering the admin node's two GETs, which is
# upstream's examples/zephyr/z_queryable.c with its keys and bodies), compiled against zenoh-pico's own
# headers and linked to wz in place of zenoh-pico: `wz-capi-pico` on the cooperative engine over
# Zephyr's sockets (docs/upstream-parity.md section 5a). The network, the driver and the board are
# the comparison image's, so the two are measured on one controller, one driver and one stack, and
# what differs between them is the library under the same program.
# `west build -b kit_t2g_b_h_lite/cyt4bf8cds/m7_0 deploy/zephyr-capi-pico` is the entry point;
# `-DEXTRA_CONF_FILE=overlays/multi_thread.conf` builds pico's multi-threaded arm.

cmake_minimum_required(VERSION 3.20.0)
include(${CMAKE_CURRENT_SOURCE_DIR}/../zephyr-eth-wzmac/zeth.cmake)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(wz_zephyr_capi_pico C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../zephyr-common/wz_zephyr_board.cmake)

# zenoh-pico's headers, with the `zenoh-pico/config.h` its own CMake makes from its switches
# (cmake/feature_config.cmake, which its Zephyr module includes too), and none of its sources: the
# library is wz's staticlib. `scripts/kit-lane.sh --selftest` holds the two lists below to the
# comparison image's CONFIG_ZENOH_PICO_* switches, one by one, and refuses a switch on in one image
# and off in the other. The switches are the comparison image's (its prj.conf, from which the
# planes of the wz client it is compared with were taken), so the program compiles to the same
# header in both images; the multi-threaded arm is this image's Kconfig, and the Rust half is built
# with the matching feature below. The value switches (batch and fragment sizes, the lease, the
# socket timeout) are left to pico's defaults, which are wz-session-core's defaults for the same
# numbers.
set(pico_src ${CMAKE_CURRENT_SOURCE_DIR}/../../vendor/zenoh-pico)
if(NOT EXISTS ${pico_src}/include/zenoh-pico/config.h.in)
  message(FATAL_ERROR "wz: vendor/zenoh-pico is empty; this image compiles against its headers "
                      "(git submodule update --init vendor/zenoh-pico).")
endif()
foreach(on
    Z_FEATURE_QUERYABLE Z_FEATURE_LINK_UDP_UNICAST Z_FEATURE_LIVELINESS Z_FEATURE_INTEREST
    Z_FEATURE_FRAGMENTATION Z_FEATURE_ENCODING_VALUES Z_FEATURE_MULTICAST_TRANSPORT
    Z_FEATURE_UNICAST_TRANSPORT Z_FEATURE_TCP_NODELAY Z_FEATURE_SESSION_CHECK Z_FEATURE_BATCHING
    Z_FEATURE_MATCHING Z_FEATURE_UNICAST_PEER Z_FEATURE_AUTO_RECONNECT Z_FEATURE_SCOUTING)
  set(${on} 1 CACHE STRING "" FORCE)
endforeach()
foreach(off
    Z_FEATURE_PUBLICATION Z_FEATURE_SUBSCRIPTION Z_FEATURE_QUERY
    Z_FEATURE_LINK_TCP Z_FEATURE_LINK_UDP_MULTICAST Z_FEATURE_UNSTABLE_API Z_FEATURE_CONNECTIVITY
    Z_FEATURE_ADVANCED_PUBLICATION Z_FEATURE_ADVANCED_SUBSCRIPTION Z_FEATURE_LOCAL_SUBSCRIBER
    Z_FEATURE_LOCAL_QUERYABLE Z_FEATURE_ADMIN_SPACE Z_FEATURE_RAWETH_TRANSPORT
    Z_FEATURE_MULTICAST_DECLARATIONS Z_FEATURE_LINK_TLS Z_FEATURE_LINK_WS Z_FEATURE_LINK_SERIAL
    Z_FEATURE_LINK_SERIAL_USB Z_FEATURE_LINK_BLUETOOTH Z_FEATURE_RX_CACHE
    Z_FEATURE_BATCH_TX_MUTEX Z_FEATURE_BATCH_PEER_MUTEX)
  set(${off} 0 CACHE STRING "" FORCE)
endforeach()
set(rust_features "")
if(CONFIG_WZ_PICO_ABI_MULTI_THREAD)
  set(Z_FEATURE_MULTI_THREAD 1 CACHE STRING "" FORCE)
  list(APPEND rust_features multi-thread)
else()
  set(Z_FEATURE_MULTI_THREAD 0 CACHE STRING "" FORCE)
endif()
set(ZENOH_PICO_INCLUDEDIR ${pico_src}/include)
include(${pico_src}/cmake/feature_config.cmake)
zephyr_include_directories(${pico_src}/include ${CMAKE_CURRENT_BINARY_DIR}/include)
zephyr_compile_definitions(ZENOH_ZEPHYR)

# The program, verbatim, and the pins that hold the Rust layer to the header it compiles against.
target_sources(app PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../zephyr-pico-compare/src/main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../crates/wz-capi-pico/csrc/pico_layout_pins.c)

if(NOT CONFIG_WZ_ZETH)
  message(FATAL_ERROR "wz: the image has no network without the Ethernet driver "
                      "(the devicetree overlay states its node).")
endif()
if(NOT CONFIG_WZ_OS OR NOT CONFIG_WZ_PICO_OS)
  message(FATAL_ERROR "wz: the pico C ABI without std needs the kernel's answers to its host "
                      "layers (CONFIG_WZ_OS, CONFIG_WZ_PICO_OS).")
endif()
wz_zeth_driver()

# The board's pieces the driver calls, as the comparison image compiles them.
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

# What only the Rust half calls, kept through the image link: the sockets of the cooperative
# engine's links (`wz_runtime_zephyr::net` and `::stream`, both reached from a dial), the board's
# two net hooks, and the MAC behind the driver.
wz_zephyr_rust_app(
  RUST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/rust
  LIB      wz_zephyr_capi_pico
  FEATURES ${rust_features}
  UNDEFINED
    socket bind getsockname sendto recvfrom poll close
    connect send recv getpeername shutdown setsockopt
    wz_net_set_rcvtimeo_ms wz_net_recv_timed_out wz_net_socket_family_refused
    wz_board_eth_pins_init wz_board_entropy_fill
    wz_zeth_open wz_zeth_transmit wz_zeth_receive wz_zeth_poll_link wz_zeth_link_up
)
