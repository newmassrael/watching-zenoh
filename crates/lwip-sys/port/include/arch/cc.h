/* SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * lwip-sys host-build arch/cc.h — compiler shim for x86_64-linux + glibc.
 *
 * lwIP allows the port to override platform diag/assert and any
 * non-standard byte-order helpers. On a modern toolchain (gcc/clang
 * + glibc) almost all macros resolve to the standard library; this
 * header is intentionally minimal.
 *
 * Cross-compile ports (deploy crate) supply their own arch/cc.h and
 * never see this file.
 */

#ifndef LWIP_ARCH_CC_H
#define LWIP_ARCH_CC_H

#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

/* lwIP provides u8_t/u16_t/u32_t types via the standard include path
 * (arch.h pulls in stdint.h when LWIP_NO_STDINT_H is 0).            */
#define LWIP_NO_STDINT_H                0
#define LWIP_NO_INTTYPES_H              0

/* Diagnostic + assertion hooks. */
#define LWIP_PLATFORM_DIAG(x)           do { printf x; } while (0)
#define LWIP_PLATFORM_ASSERT(x)         do { \
    printf("lwIP assert: %s @ %s:%d\n", x, __FILE__, __LINE__); \
    fflush(NULL); abort(); \
} while (0)

/* Random source for non-cryptographic uses (port_rand, ISN, etc.). */
#define LWIP_RAND()                     ((u32_t)rand())

#endif /* LWIP_ARCH_CC_H */
