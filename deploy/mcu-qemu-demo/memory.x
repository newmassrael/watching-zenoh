/* SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * QEMU `mps2-an385` (Cortex-M3) memory layout — R311be (machine
 * choice corrected R311bf; mps2-an386 is a Cortex-M4 board).
 *
 * Per QEMU's mps2 machine source (`hw/arm/mps2.c`) the Cortex-M3
 * mps2-an385 image runs out of:
 *
 *   - 0x00000000 - 0x003FFFFF   ZBT-SSRAM1 aliased as code memory
 *                               (4 MB; QEMU loads `-kernel` here)
 *   - 0x20000000 - 0x203FFFFF   ZBT-SSRAM2 + 3 mapped as data RAM
 *                               (4 MB; .data + .bss + stack +
 *                               cortex-m-rt's HEAP region)
 *
 * cortex-m-rt's bundled `link.x` INCLUDEs this file at link
 * time; the symbol names FLASH + RAM are required by the
 * default section layout. Stack grows down from the top of RAM
 * (cortex-m-rt's `_stack_start = ORIGIN(RAM) + LENGTH(RAM)`).
 *
 * Sizes are deliberately generous because the QEMU virtual SoC
 * has the headroom and the smoke binary's heap + lwIP pools fit
 * comfortably; a real Cortex-M3 deploy with constrained SRAM
 * would shrink RAM and let cortex-m-rt's heap allocator scale
 * to fit.
 */

MEMORY
{
  FLASH : ORIGIN = 0x00000000, LENGTH = 4M
  RAM   : ORIGIN = 0x20000000, LENGTH = 4M
}
