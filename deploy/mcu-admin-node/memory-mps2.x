/* SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * QEMU mps2 memory layout, the same map the other mps2 deploys use (QEMU's
 * hw/arm/mps2.c): ZBT-SSRAM1 aliased as code memory at 0x00000000 (QEMU
 * loads `-kernel` there) and ZBT-SSRAM2 + 3 as data RAM at 0x20000000. The
 * LAN9118 this firmware drives sits outside both, in the peripheral space.
 */

MEMORY
{
  FLASH : ORIGIN = 0x00000000, LENGTH = 4M
  RAM   : ORIGIN = 0x20000000, LENGTH = 4M
}
