/* SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * Memory layout of the FIXED-MEMORY profile on ARMv6-M code (thumbv6m-none-
 * eabi). Selected by build.rs when the target triple is thumbv6m-none-eabi and
 * the `fixed-memory` feature is on; the heap form on that triple keeps
 * memory-microbit.x.
 *
 * This is a LINK MAP, not a board. The profile's tables are sized by the
 * build-wide capacity constants of `wz-session-core`'s `caps` (a keyexpr row is
 * 256 bytes, and the peer tables hold 64 of them), and the slim session socket
 * pool does not change those. Measured on the ARMv6-M build of this image (slim
 * pool, one session): .data + .bss are 41008 bytes at the link of the unmodified
 * 9 KB RAM region of memory-microbit.x, which overflowed it by that much less 9 KB.
 * An nrf51 (16 KB of SRAM) cannot hold them, and no per-deploy limit lowers the
 * constants yet (`caps` says so: the deploy file's limits become a generated
 * capacity profile in a later step). So the image is built here against a map
 * that has the RAM the tables take, which is what the no-allocator link gate
 * needs of it: ARMv6-M code, with the atomics `portable-atomic` polyfills,
 * linked with no allocator. It is not run on QEMU's microbit machine, whose
 * SRAM is 16 KB.
 *
 *   - 0x00000000 - 0x0003FFFF   FLASH (256 KB)
 *   - 0x20000000 - 0x2000FFFF   SRAM (64 KB): the stack at the bottom, as
 *                               memory-microbit.x declares it, then .data and .bss
 *
 * Read the real numbers off the link, not off this comment.
 */

MEMORY
{
  FLASH : ORIGIN = 0x00000000, LENGTH = 256K
  STACK : ORIGIN = 0x20000000, LENGTH = 7K
  RAM   : ORIGIN = 0x20001C00, LENGTH = 57K
}

_stack_start = ORIGIN(STACK) + LENGTH(STACK);
_stack_end = ORIGIN(STACK);
