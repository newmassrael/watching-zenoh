/* SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
 *   - 0x20000000 - 0x20003FFF   SRAM (16 KB; .data + .bss + stack
 *                               + cortex-m-rt's HEAP region all
 *                               share this budget)
 *
 * 16 KB total RAM is the binding constraint for R311bm-m0. The
 * demo's HEAP_SIZE drops to 4 KB on this target (vs 256 KB on
 * the mps2 family) and the wz facade composition still has to
 * fit lwIP MEM_SIZE + cortex-m-rt's stack + .data + .bss inside
 * the remaining 12 KB. If that does not fit, the link step
 * surfaces an overflow region error — honest catalog feedback
 * that the current composable-framework preset surface is too
 * heavy for nrf51-class devices and a slim-only-runtime-lwip
 * preset is needed.
 *
 * cortex-m-rt's bundled `link.x` INCLUDEs this file; the
 * MEMORY region names FLASH + RAM are required by the default
 * section layout. Stack grows down from the top of RAM
 * (cortex-m-rt's `_stack_start = ORIGIN(RAM) + LENGTH(RAM)`).
 */

MEMORY
{
  FLASH : ORIGIN = 0x00000000, LENGTH = 256K
  RAM   : ORIGIN = 0x20000000, LENGTH = 16K
}
