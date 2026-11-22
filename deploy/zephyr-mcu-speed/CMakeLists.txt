# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# zephyr-mcu-speed -- the image of the MCU speed matrix (docs/mcu-speed-matrix.md): one program of the
# pico API (src/main.c) that runs one workload per boot, built in two arms on the same board, the same
# kernel and the same network stack, so that what differs between the two images is the library:
#
#   WZ_MCU_SPEED_ARM=P   zenoh-pico, built as the Zephyr module its tree is (vendor/zenoh-pico/zephyr)
#   WZ_MCU_SPEED_ARM=W   the pico C ABI of wz without std on the cooperative engine, the staticlib of
#                        deploy/zephyr-capi-pico/rust, compiled against zenoh-pico's own headers
#
# and in pico's two threading arms (WZ_MCU_SPEED_THREADS=st, the program steps the session; mt, the
# session's own read task does). Both arms take their feature switches from the one list below, so the
# program compiles to the same header in both.
#
#   west build -b mps2/an385 deploy/zephyr-mcu-speed -- -DWZ_MCU_SPEED_ARM=W -DWZ_MCU_SPEED_THREADS=st
#
# scripts/mcu-speed.sh builds the four images and runs them under QEMU.

cmake_minimum_required(VERSION 3.20.0)

set(WZ_MCU_SPEED_ARM "" CACHE STRING "The library under the program: P (zenoh-pico) or W (wz)")
set(WZ_MCU_SPEED_THREADS "st" CACHE STRING "pico's threading arm: st or mt")
if(NOT WZ_MCU_SPEED_ARM MATCHES "^(P|W)$")
  message(FATAL_ERROR "wz: WZ_MCU_SPEED_ARM is P or W, not '${WZ_MCU_SPEED_ARM}'.")
endif()
if(NOT WZ_MCU_SPEED_THREADS MATCHES "^(st|mt)$")
  message(FATAL_ERROR "wz: WZ_MCU_SPEED_THREADS is st or mt, not '${WZ_MCU_SPEED_THREADS}'.")
endif()

set(pico_src ${CMAKE_CURRENT_SOURCE_DIR}/../../vendor/zenoh-pico)
if(NOT EXISTS ${pico_src}/include/zenoh-pico/config.h.in)
  message(FATAL_ERROR "wz: vendor/zenoh-pico is empty; both arms compile against its headers "
                      "(git submodule update --init vendor/zenoh-pico).")
endif()

# The planes of the pico C ABI image (deploy/zephyr-capi-pico), with publication and subscription on,
# which the workloads put and receive through. The wz staticlib carries the queryable, the liveliness
# token and scouting whatever the header says, so they are on here too and the two arms differ in no
# switch. Matching is on because a publisher waits for its subscriber before the first counted put:
# a zenoh-pico publisher that knows of no subscriber returns success for a put it does not send.
set(mcu_speed_on
  Z_FEATURE_PUBLICATION Z_FEATURE_SUBSCRIPTION Z_FEATURE_MATCHING
  Z_FEATURE_QUERYABLE Z_FEATURE_LINK_UDP_UNICAST Z_FEATURE_LIVELINESS Z_FEATURE_INTEREST
  Z_FEATURE_FRAGMENTATION Z_FEATURE_ENCODING_VALUES Z_FEATURE_MULTICAST_TRANSPORT
  Z_FEATURE_UNICAST_TRANSPORT Z_FEATURE_TCP_NODELAY Z_FEATURE_SESSION_CHECK Z_FEATURE_BATCHING
  Z_FEATURE_UNICAST_PEER Z_FEATURE_AUTO_RECONNECT Z_FEATURE_SCOUTING)
set(mcu_speed_off
  Z_FEATURE_QUERY Z_FEATURE_LINK_TCP Z_FEATURE_LINK_UDP_MULTICAST Z_FEATURE_UNSTABLE_API
  Z_FEATURE_CONNECTIVITY Z_FEATURE_ADVANCED_PUBLICATION Z_FEATURE_ADVANCED_SUBSCRIPTION
  Z_FEATURE_LOCAL_SUBSCRIBER Z_FEATURE_LOCAL_QUERYABLE Z_FEATURE_ADMIN_SPACE
  Z_FEATURE_RAWETH_TRANSPORT Z_FEATURE_MULTICAST_DECLARATIONS Z_FEATURE_LINK_TLS Z_FEATURE_LINK_WS
  Z_FEATURE_LINK_SERIAL Z_FEATURE_LINK_SERIAL_USB Z_FEATURE_LINK_BLUETOOTH Z_FEATURE_RX_CACHE
  Z_FEATURE_BATCH_TX_MUTEX Z_FEATURE_BATCH_PEER_MUTEX)
if(WZ_MCU_SPEED_THREADS STREQUAL "mt")
  list(APPEND mcu_speed_on Z_FEATURE_MULTI_THREAD)
else()
  list(APPEND mcu_speed_off Z_FEATURE_MULTI_THREAD)
endif()

# Arm P states the switches as the module's Kconfig symbols (the module maps CONFIG_ZENOH_PICO_<X> to
# Z_FEATURE_<X>), written from the list above into a fragment of this build, so the list is the one
# place they are said. Arm W states the kernel's answers to the engine's operating system.
if(WZ_MCU_SPEED_ARM STREQUAL "P")
  list(APPEND ZEPHYR_EXTRA_MODULES ${pico_src})
  set(switches "CONFIG_ZENOH_PICO=y\n")
  foreach(feature ${mcu_speed_on})
    string(REPLACE Z_FEATURE CONFIG_ZENOH_PICO symbol ${feature})
    string(APPEND switches "${symbol}=y\n")
  endforeach()
  foreach(feature ${mcu_speed_off})
    string(REPLACE Z_FEATURE CONFIG_ZENOH_PICO symbol ${feature})
    string(APPEND switches "${symbol}=n\n")
  endforeach()
  set(switches_conf ${CMAKE_CURRENT_BINARY_DIR}/pico_switches.conf)
  file(WRITE ${switches_conf} "${switches}")
  list(APPEND EXTRA_CONF_FILE ${switches_conf})
else()
  list(APPEND EXTRA_CONF_FILE ${CMAKE_CURRENT_SOURCE_DIR}/arm_w.conf)
endif()

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(wz_zephyr_mcu_speed C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../zephyr-common/wz_zephyr_board.cmake)

target_sources(app PRIVATE src/main.c)

if(WZ_MCU_SPEED_ARM STREQUAL "P")
  if(NOT CONFIG_ZENOH_PICO)
    message(FATAL_ERROR "wz: arm P has no zenoh-pico (CONFIG_ZENOH_PICO is off).")
  endif()
  target_compile_definitions(app PRIVATE MCU_SPEED_ARM_W=0)
else()
  if(NOT CONFIG_WZ_OS OR NOT CONFIG_WZ_PICO_OS)
    message(FATAL_ERROR "wz: the pico C ABI without std needs the kernel's answers to its host "
                        "layers (CONFIG_WZ_OS, CONFIG_WZ_PICO_OS).")
  endif()
  foreach(feature ${mcu_speed_on})
    set(${feature} 1 CACHE STRING "" FORCE)
  endforeach()
  foreach(feature ${mcu_speed_off})
    set(${feature} 0 CACHE STRING "" FORCE)
  endforeach()
  set(rust_features "")
  if(WZ_MCU_SPEED_THREADS STREQUAL "mt")
    list(APPEND rust_features multi-thread)
  endif()
  set(ZENOH_PICO_INCLUDEDIR ${pico_src}/include)
  include(${pico_src}/cmake/feature_config.cmake)
  zephyr_include_directories(${pico_src}/include ${CMAKE_CURRENT_BINARY_DIR}/include)
  zephyr_compile_definitions(ZENOH_ZEPHYR)
  target_compile_definitions(app PRIVATE MCU_SPEED_ARM_W=1)
  # The pins that hold the Rust layer to the header the program compiles against.
  target_sources(app PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../crates/wz-capi-pico/csrc/pico_layout_pins.c)
  # The staticlib without its board's MAC (its default feature): this board's Ethernet is Zephyr's
  # own driver. What only the Rust half calls is the sockets of the engine's links and the board's
  # socket hooks, kept through the image link as the pico C ABI image keeps them.
  wz_zephyr_rust_app(
    RUST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../zephyr-capi-pico/rust
    LIB      wz_zephyr_capi_pico
    NO_DEFAULT_FEATURES
    FEATURES ${rust_features}
    UNDEFINED
      socket bind getsockname sendto recvfrom poll close
      connect send recv getpeername shutdown setsockopt
      ${WZ_SOCKET_HOOKS}
  )
endif()
