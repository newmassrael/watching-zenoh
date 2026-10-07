/* SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * arch/cc.h of the Zephyr admin node's lwIP backend.
 *
 * The `lwip-sys` cross-test port's bare-metal compiler shim (no libc headers, so
 * clang's freestanding sysroot and the cross gcc see the same thing), with the
 * two hooks a running node cannot leave as stubs:
 *
 *   - LWIP_RAND, from the board's random source. A constant would hand every
 *     dialled session the same ephemeral port after every boot.
 *   - a failed assertion, which says so on the console and halts.
 *
 * Both are defined by the image's C side (deploy/zephyr-common/wz_board_hooks.c).
 */

#ifndef LWIP_ARCH_CC_H
#define LWIP_ARCH_CC_H

#include <stdint.h>
#include <stddef.h>

#define LWIP_NO_STDINT_H                0

/* POSIX / hosted headers clang's freestanding sysroot does not ship. */
#define LWIP_NO_INTTYPES_H              1
#define LWIP_NO_UNISTD_H                1
#define LWIP_NO_CTYPE_H                 1

extern uint32_t wz_lwip_rand(void);
extern void wz_lwip_assert(const char *what);

#define LWIP_PLATFORM_DIAG(x)           do { } while (0)
#define LWIP_PLATFORM_ASSERT(x)         wz_lwip_assert(x)
#define LWIP_RAND()                     ((u32_t)wz_lwip_rand())

#endif /* LWIP_ARCH_CC_H */
