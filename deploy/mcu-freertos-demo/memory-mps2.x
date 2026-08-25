/* SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * QEMU `mps2-an385` (Cortex-M3) memory layout — FreeRTOS profile (R311y27),
 * identical to deploy/mcu-qemu-demo/memory-mps2.x. cortex-m-rt's bundled
 * link.x INCLUDEs this; FLASH/RAM symbol names are required by the default
 * section layout. The FreeRTOS heap_4 array (configTOTAL_HEAP_SIZE) lives in
 * .bss in RAM; mps2's 4 MB SRAM has ample headroom.
 */

MEMORY
{
  FLASH : ORIGIN = 0x00000000, LENGTH = 4M
  RAM   : ORIGIN = 0x20000000, LENGTH = 4M
}
