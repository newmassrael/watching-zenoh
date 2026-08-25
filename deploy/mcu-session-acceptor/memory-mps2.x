/* SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * QEMU mps2 (Cortex-M3 an385 / Cortex-M4 an386 / Cortex-M7 an500) memory
 * layout — Stage 5. All three mps2 machines this bin targets share the same
 * ZBT-SSRAM map (per QEMU's hw/arm/mps2.c):
 *
 *   - 0x00000000 - 0x003FFFFF   ZBT-SSRAM1 aliased as code memory
 *                               (4 MB; QEMU loads `-kernel` here)
 *   - 0x20000000 - 0x203FFFFF   ZBT-SSRAM2 + 3 mapped as data RAM
 *                               (4 MB; .data + .bss + stack + the heap)
 *
 * cortex-m-rt's bundled `link.x` INCLUDEs this file at link time; the
 * symbol names FLASH + RAM are required by the default section layout.
 * Stack grows down from the top of RAM. Sizes are deliberately generous
 * because the QEMU virtual SoC has the headroom and the session stack's
 * heap + lwIP pools fit comfortably; a real constrained-SRAM deploy would
 * shrink RAM and let the heap allocator scale to fit.
 */

MEMORY
{
  FLASH : ORIGIN = 0x00000000, LENGTH = 4M
  RAM   : ORIGIN = 0x20000000, LENGTH = 4M
}
