# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# The Zephyr drivers over the wz CYT4BF crates (Kconfig.zeth, wz_zeth_driver.c,
# wz_zeth_trng.c, zeth_exports.rs). An application includes this file BEFORE
# `find_package(Zephyr)` so the bindings are on the devicetree's search path, and calls
# `wz_zeth_driver()` after it, once the Kconfig is known.
#
#   include(${CMAKE_CURRENT_SOURCE_DIR}/../zephyr-eth-wzmac/zeth.cmake)
#   find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
#   ...
#   if(CONFIG_WZ_ZETH)
#     wz_zeth_driver()
#   endif()

# This directory holds `dts/bindings/`, which is what the devicetree reads from a root.
list(APPEND DTS_ROOT ${CMAKE_CURRENT_LIST_DIR})

# The C of the drivers, and the board's pieces they call (all of which the application
# compiles, because they are the board's and not the driver's: the pin routing, the PDL's
# TRNG driver, the clock register read). The Rust side is the application's staticlib, which
# includes zeth_exports.rs and names the `wz_zeth_*` symbols for the final link.
function(wz_zeth_driver)
  target_sources(app PRIVATE ${CMAKE_CURRENT_FUNCTION_LIST_DIR}/wz_zeth_driver.c)
  if(CONFIG_WZ_ZETH_TRNG)
    target_sources(app PRIVATE ${CMAKE_CURRENT_FUNCTION_LIST_DIR}/wz_zeth_trng.c)
  endif()
  if(CONFIG_WZ_ZETH_STAMPS)
    target_sources(app PRIVATE ${CMAKE_CURRENT_FUNCTION_LIST_DIR}/wz_zeth_stamps.c)
    target_link_libraries(app PUBLIC -Wl,--wrap=recvfrom -Wl,--wrap=sendto -Wl,--wrap=poll
      -Wl,--wrap=k_malloc -Wl,--wrap=k_free -Wl,--wrap=memcpy
      -Wl,--wrap=z_impl_k_sleep -Wl,--wrap=z_impl_k_usleep -Wl,--wrap=sys_clock_announce_locked)
  endif()
  if(NOT CONFIG_NOCACHE_MEMORY)
    message(FATAL_ERROR "wz: the Ethernet driver's DMA rings are in the non-cacheable "
                        "section, which needs CONFIG_NOCACHE_MEMORY=y.")
  endif()
endfunction()
