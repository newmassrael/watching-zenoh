/* SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * QEMU `microbit` machine (Cortex-M0, nrf51822): 256 KB of FLASH at 0x0 and
 * 16 KB of SRAM at 0x20000000, shared by .data, .bss and the stack. This image
 * binds one 128 x 2 socket from a static pool (about 280 bytes) on the
 * microbit-minimal lwIP port, so it fits with room to spare; it is built, and
 * linked, for the allocator proof, and it is not asked to carry a stack budget
 * of its own.
 */

MEMORY
{
  FLASH : ORIGIN = 0x00000000, LENGTH = 256K
  RAM   : ORIGIN = 0x20000000, LENGTH = 16K
}
