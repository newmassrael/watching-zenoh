# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# zephyr-tls-fit -- the fit of the fixed-memory profile's secure channel (decision D9 of
# docs/session-lifecycle-intent.md), measured on the T2G kit: Mbed TLS on its PSA Crypto line,
# as the Zephyr module the workspace pins, runs a mutual TLS 1.3 handshake between two peers in
# one image, over an in-memory pipe. Each peer's identity is a P-256 key generated in the PSA key
# store and a certificate self-signed over it on the device; each accepts the other by the zid
# derived from the key its certificate carries. The console line says what it cost.
# `west build -b kit_t2g_b_h_lite/cyt4bf8cds/m7_0 deploy/zephyr-tls-fit` is the entry point;
# `scripts/kit-lane.sh` builds, flashes and reads it as the image `zephyr-tls-fit`.

cmake_minimum_required(VERSION 3.20.0)
# The board's TRNG as the entropy device (the devicetree overlay states its node), the same
# source every wz image on the kit draws from.
include(${CMAKE_CURRENT_SOURCE_DIR}/../zephyr-eth-wzmac/zeth.cmake)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(wz_zephyr_tls_fit C)

target_sources(app PRIVATE src/main.c)

# Mbed TLS's user configuration (CONFIG_MBEDTLS_USER_CONFIG_FILE) is found on the include path of
# the libraries that read their configuration, the module's `mbedtls_iface`. It is the channel
# crate's, shared with every Zephyr image that carries the channel.
target_include_directories(mbedtls_iface INTERFACE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../crates/wz-tls-mbedtls/config/zephyr)

if(NOT CONFIG_WZ_ZETH_TRNG)
  message(FATAL_ERROR "wz: the TLS fit image draws its keys from the board's TRNG, and this "
                      "build has no entropy device over it (the overlay states its node).")
endif()
set(admin_src ${CMAKE_CURRENT_SOURCE_DIR}/../zephyr-admin-node)
set(pdl_src ${ZEPHYR_HAL_INFINEON_MODULE_DIR}/mtb-pdl-cat1/drivers/source)
target_sources(app PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../zephyr-eth-wzmac/wz_zeth_trng.c
  ${admin_src}/src/trng_cat1c.c
  ${pdl_src}/cy_crypto_core_trng.c
  ${pdl_src}/cy_crypto_core_hw.c)
