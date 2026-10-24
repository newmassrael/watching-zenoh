#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# Turn a QNX Software Development Platform's environment script into the toolchain variables the
# package entry reads for the two QNX 7.1 aarch64 platforms (docs/target-build-contract.md T2, T3).
#
# SOURCE it, with the SDP's environment script as the argument:
#
#     . scripts/qnx-toolchain-env.sh <sdp>/qnxsdp-env.sh
#
# The toolchain is the caller's (T2): this file selects no SDP and fetches none, and no SDP path is
# recorded in the tree. The SDP's script exports QNX_HOST and QNX_TARGET and puts its compilers on
# PATH; what is left to do is name them for the two triples, which differ only in the network stack
# (io-pkt is aarch64-unknown-nto-qnx710, io-sock is aarch64-unknown-nto-qnx710_iosock) and share one
# compiler:
#
#   * CC, AR and the linker of each triple, as variables of that triple. The linker is `qcc`, the
#     SDP's driver, which rustc's own target specification passes its `-V` selector to;
#   * the standard library of both triples has no prebuilt copy, so a build of either needs a
#     nightly cargo, which the caller puts first, and the entry adds `-Z build-std` for them.
#
# Variables exported: CC_, AR_ and CARGO_TARGET_<TRIPLE>_LINKER for both triples.

if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
    echo "qnx-toolchain-env: usage: . scripts/qnx-toolchain-env.sh <SDP qnxsdp-env.sh>" >&2
    return 1
fi

# shellcheck source=/dev/null
. "$1" > /dev/null || { echo "qnx-toolchain-env: the SDP's environment script failed" >&2; return 1; }

if [ -z "${QNX_HOST:-}" ] || [ -z "${QNX_TARGET:-}" ]; then
    echo "qnx-toolchain-env: the script exported no QNX_HOST or QNX_TARGET: not a QNX SDP" >&2
    return 1
fi

WZ_QNX_GCC=aarch64-unknown-nto-qnx7.1.0-gcc
WZ_QNX_AR=aarch64-unknown-nto-qnx7.1.0-ar
for tool in "$WZ_QNX_GCC" "$WZ_QNX_AR" qcc; do
    if ! command -v "$tool" > /dev/null 2>&1; then
        echo "qnx-toolchain-env: $tool is not on PATH after the SDP's script: not a QNX 7.1 aarch64 SDP" >&2
        return 1
    fi
done

export CC_aarch64_unknown_nto_qnx710="$WZ_QNX_GCC"
export AR_aarch64_unknown_nto_qnx710="$WZ_QNX_AR"
export CARGO_TARGET_AARCH64_UNKNOWN_NTO_QNX710_LINKER=qcc
export CC_aarch64_unknown_nto_qnx710_iosock="$WZ_QNX_GCC"
export AR_aarch64_unknown_nto_qnx710_iosock="$WZ_QNX_AR"
export CARGO_TARGET_AARCH64_UNKNOWN_NTO_QNX710_IOSOCK_LINKER=qcc

unset WZ_QNX_GCC WZ_QNX_AR tool
