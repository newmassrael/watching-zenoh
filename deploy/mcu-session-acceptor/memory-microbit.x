/* SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * QEMU `microbit` machine (Cortex-M0, nrf51822) memory layout — the SLIM
 * buffer-pool acceptor variant. Selected by build.rs when the target triple
 * is thumbv6m-none-eabi; the mps2 family triples (thumbv7m / thumbv7em-none-
 * eabihf) keep using memory-mps2.x (4 MB / 4 MB).
 *
 * Per QEMU's nrf51 machine source (hw/arm/nrf51_soc.c) + the nrf51 reference
 * manual the BBC micro:bit's nrf51822 SoC has:
 *
 *   - 0x00000000 - 0x0003FFFF   FLASH (256 KB; QEMU loads `-kernel` here)
 *   - 0x20000000 - 0x20003FFF   SRAM (16 KB; .data + .bss + cortex-m-rt's
 *                               HEAP region + stack all share this budget)
 *
 * 16 KB total RAM is the binding constraint. The thumbv6m build is the
 * `buffer-pool-session-rx-slim` profile: the acceptor session rx socket
 * (4 x 256 ~= 1 KB) + the matching slim reactive-peer socket bring the e2e
 * peak heap to a MEASURED ~3.15 KB (vs ~32 KB on the default 16 x 1536
 * pool). So the 4 KB HEAP_SIZE holds the peak with margin, and lwIP's static
 * MEM_SIZE (~8 KB) + cortex-m-rt's stack + .data + .bss fit the remaining
 * ~12 KB. This is what graduates the Layer Q.4 microbit acceptor lane from
 * build-only to a real on-target boot.
 *
 * cortex-m-rt's bundled `link.x` INCLUDEs this file; the MEMORY region names
 * FLASH + RAM are required by the default section layout. Stack grows down
 * from the top of RAM (`_stack_start = ORIGIN(RAM) + LENGTH(RAM)`).
 */

MEMORY
{
  FLASH : ORIGIN = 0x00000000, LENGTH = 256K
  RAM   : ORIGIN = 0x20000000, LENGTH = 16K
}
