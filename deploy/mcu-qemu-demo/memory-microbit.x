/* SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * QEMU `microbit` machine (Cortex-M0, nrf51822) memory layout —
 * R311bm-m0. Selected by build.rs when the target triple is
 * thumbv6m-none-eabi; mps2 family triples (thumbv7m / thumbv7em-
 * none-eabihf) keep using `memory.x`.
 *
 * Per QEMU's nrf51 machine source (`hw/arm/nrf51_soc.c`) plus the
 * nrf51 reference manual the BBC micro:bit's nrf51822 SoC has:
 *
 *   - 0x00000000 - 0x0003FFFF   FLASH (256 KB; QEMU loads `-kernel`
 *                               here)
 *   - 0x20000000 - 0x20003FFF   SRAM (16 KB; .data + .bss + the
 *                               stack all share this budget)
 *
 * 16 KB total RAM is the binding constraint for R311bm-m0. The
 * demo's HEAP_SIZE drops to 4 KB on this target (vs 256 KB on
 * the mps2 family), and the heap is a static inside .bss.
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
 * Measured in R2776: .data + .bss 12076 bytes, stack peak 852 bytes.
 * RAM = 13K leaves .bss 1236 bytes to grow; STACK = 3K leaves the stack
 * far more than `wz_mcu_stack::MARGIN_BYTES`. The boot prints the peak
 * every run — read it there, not here.
 */

MEMORY
{
  FLASH : ORIGIN = 0x00000000, LENGTH = 256K
  STACK : ORIGIN = 0x20000000, LENGTH = 3K
  RAM   : ORIGIN = 0x20000C00, LENGTH = 13K
}

_stack_start = ORIGIN(STACK) + LENGTH(STACK);
_stack_end = ORIGIN(STACK);
