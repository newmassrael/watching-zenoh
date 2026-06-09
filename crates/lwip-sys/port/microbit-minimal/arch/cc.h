/* SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * lwip-sys microbit-minimal arch/cc.h — bare-metal compiler shim.
 *
 * R311jc. Identical to the cross-test port's arch/cc.h (the compiler
 * abstractions are target-agnostic for the arm-none-eabi NO_SYS build);
 * only the sibling lwipopts.h differs (trimmed static RAM for the nrf51
 * 16 KB budget). Kept as its own file so the microbit port is a complete,
 * self-contained WZ_LWIP_PORT directory.
 */

#ifndef LWIP_ARCH_CC_H
#define LWIP_ARCH_CC_H

#include <stdint.h>
#include <stddef.h>

#define LWIP_NO_STDINT_H                0

#define LWIP_NO_INTTYPES_H              1
#define LWIP_NO_UNISTD_H                1
#define LWIP_NO_CTYPE_H                 1

/* Diagnostic + assertion hooks — empty stubs so arch.h does not
 * auto-include <stdio.h>/<stdlib.h>. */
#define LWIP_PLATFORM_DIAG(x)           do { } while (0)
#define LWIP_PLATFORM_ASSERT(x)         do { for (;;) { } } while (0)

/* Non-cryptographic random source — deterministic stub. */
#define LWIP_RAND()                     ((u32_t)0u)

#endif /* LWIP_ARCH_CC_H */
