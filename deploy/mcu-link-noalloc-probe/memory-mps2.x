/* SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * QEMU mps2 (Cortex-M3 an385 / Cortex-M4 an386 / Cortex-M7 an500) memory
 * layout: 4 MB of code at 0x0, 4 MB of data RAM at 0x20000000 (the same map the
 * other deploy/mcu-* images use). There is no heap in this image: .data, .bss
 * and the stack are all of RAM.
 */

MEMORY
{
  FLASH : ORIGIN = 0x00000000, LENGTH = 4M
  RAM   : ORIGIN = 0x20000000, LENGTH = 4M
}
