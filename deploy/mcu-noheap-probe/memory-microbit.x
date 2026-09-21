/* SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * QEMU `microbit` machine (Cortex-M0, nrf51822) memory layout for the
 * no-heap probe. Selected by build.rs when the target triple is
 * thumbv6m-none-eabi; mps2 family triples (thumbv7m / thumbv7em-
 * none-eabihf) keep using `memory-mps2.x`.
 *
 * Per QEMU's nrf51 machine source (`hw/arm/nrf51_soc.c`) plus the
 * nrf51 reference manual the BBC micro:bit's nrf51822 SoC has:
 *
 *   - 0x00000000 - 0x0003FFFF   FLASH (256 KB; QEMU loads `-kernel`
 *                               here)
 *   - 0x20000000 - 0x20003FFF   SRAM (16 KB; .data + .bss + the
 *                               stack all share this budget)
 *
 * This probe declares NO global allocator, so its working set lives on
 * the stack, not in a heap: the stack is almost all of its RAM. (Until
 * R2776 this header was a copy of the qemu-demo's and described a 4 KB
 * heap this binary does not have.)
 *
 * ## The stack is DECLARED, and it sits BELOW .data/.bss (R2776)
 *
 * The same structure, for the same reason, as
 * `deploy/mcu-session-acceptor/memory-microbit.x`, which records the
 * overflow that made it necessary (open-debt item 805): a stack that
 * outgrows STACK faults below SRAM at the push that does it instead of
 * writing over .bss, a .bss that outgrows RAM fails the link, and the
 * binary checks its measured peak against STACK with `wz_mcu_stack`
 * before it reports PASS.
 *
 * Measured in R2776: .bss 36 bytes, stack peak 8752 bytes. STACK = 12K
 * leaves the stack 3536 bytes over `wz_mcu_stack::MARGIN_BYTES`; RAM = 4K
 * is .bss's share. The boot prints the peak every run — read it there,
 * not here.
 */

MEMORY
{
  FLASH : ORIGIN = 0x00000000, LENGTH = 256K
  STACK : ORIGIN = 0x20000000, LENGTH = 12K
  RAM   : ORIGIN = 0x20003000, LENGTH = 4K
}

_stack_start = ORIGIN(STACK) + LENGTH(STACK);
_stack_end = ORIGIN(STACK);
