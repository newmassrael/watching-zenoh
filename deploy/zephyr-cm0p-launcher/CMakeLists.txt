# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# zephyr-cm0p-launcher -- the image the CM0+ core of a T2G chip runs so that the
# M7_0 core's image can run at the speed it was built for. `west build -b
# kit_t2g_b_h_lite/cyt4bf8cds/m0p deploy/zephyr-cm0p-launcher` is the entry point;
# the board is the kit's CM0+ target, not the M7's. See src/main.c for why this
# image exists and what it does.

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(wz_zephyr_cm0p_launcher C)

# The launcher starts another core and relies on the clock tree this core's
# Zephyr brings up. Built for any other core it would run, find no M7_0 flash
# node (or find one and start the wrong thing), and say nothing useful.
if(NOT CONFIG_CPU_CORTEX_M0PLUS)
  message(FATAL_ERROR
    "zephyr-cm0p-launcher is the CM0+ core's image; board ${BOARD} is not a "
    "CM0+ target (use the board's /m0p variant)")
endif()

# Say, in the build's own words, where this launcher will start the M7_0 core: the
# address of the M7_0 flash partition in the devicetree it was built against (the
# same node src/main.c reads). Layer Qzb compares this line with the address the
# M7_0 image's vector table was actually linked at -- two images that must agree
# on one address, each of which is right about it by its own reading.
dt_nodelabel(wz_cm7_0_flash NODELABEL "flash_m7_0")
if(NOT wz_cm7_0_flash)
  message(FATAL_ERROR "the devicetree has no flash_m7_0 node: this board has no M7_0 partition to start")
endif()
dt_reg_addr(wz_cm7_0_vectors PATH "${wz_cm7_0_flash}")
math(EXPR wz_cm7_0_vectors_hex "${wz_cm7_0_vectors}" OUTPUT_FORMAT HEXADECIMAL)
message(STATUS "wz: CM7_0 vectors ${wz_cm7_0_vectors_hex}")

target_sources(app PRIVATE src/main.c)
