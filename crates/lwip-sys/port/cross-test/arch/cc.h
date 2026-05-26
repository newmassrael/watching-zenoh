/* SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * lwip-sys cross-test arch/cc.h — bare-metal compiler shim.
 *
 * R311az-3b validation port. Bare-metal-friendly compiler abstractions
 * for arm-none-eabi / riscv32 toolchains: no `<stdio.h>`, no
 * `<stdlib.h>`, and the platform diag/assert hooks are stubbed so
 * lwIP's `arch.h` does NOT auto-include those headers (it only does
 * so when LWIP_PLATFORM_DIAG / LWIP_PLATFORM_ASSERT are undefined).
 *
 * Production deploys override this with their target's real
 * diag/assert wiring (RTT logger, fault handler, watchdog feed,
 * etc.). The cross-test config is "smallest thing that lets the
 * NO_SYS source set compile under a bare-metal toolchain".
 *
 * `<stdint.h>` is still required (lwIP's arch.h uses uint8_t/16_t/32_t
 * via the standard path; newlib + arm-none-eabi-gcc + libclang
 * `--target=thumb*-none-eabi*` all ship freestanding stdint).
 */

#ifndef LWIP_ARCH_CC_H
#define LWIP_ARCH_CC_H

#include <stdint.h>
#include <stddef.h>

/* lwIP picks up u8_t/u16_t/u32_t from <stdint.h> via arch.h. clang's
 * freestanding sysroot ships <stdint.h>, so the bindgen libclang pass
 * and the arm-none-eabi-gcc compile pass both resolve it identically. */
#define LWIP_NO_STDINT_H                0

/* <limits.h> is part of the C99 freestanding subset (clang ships it);
 * keep it on so INT_MAX is defined for arch.h's SSIZE_MAX fallback. */

/* The following are POSIX / hosted-only headers that clang's
 * freestanding `--target=thumb*-none-eabi*` sysroot does NOT ship
 * (the gcc + newlib hosted path does, but we keep the bindgen view
 * symmetric with a freestanding clang to avoid a sysroot dependency).
 * Tell lwIP not to pull them; arch.h provides minimal fallbacks
 * (private ctype helpers, ssize_t typedef when SSIZE_MAX undef). */
#define LWIP_NO_INTTYPES_H              1
#define LWIP_NO_UNISTD_H                1
#define LWIP_NO_CTYPE_H                 1

/* Diagnostic + assertion hooks — empty stubs so arch.h does not
 * auto-include <stdio.h>/<stdlib.h>. Deploys override with real
 * implementations. */
#define LWIP_PLATFORM_DIAG(x)           do { } while (0)
#define LWIP_PLATFORM_ASSERT(x)         do { for (;;) { } } while (0)

/* Non-cryptographic random source — deterministic stub for the
 * cross-test. Deploys override with a target-side entropy source
 * (RNG peripheral, etc.). */
#define LWIP_RAND()                     ((u32_t)0u)

#endif /* LWIP_ARCH_CC_H */
