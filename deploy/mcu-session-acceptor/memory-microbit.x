/* SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
 *   - 0x20000000 - 0x20003FFF   SRAM (16 KB; .data + .bss + the stack all
 *                               share this budget)
 *
 * 16 KB total RAM is the binding constraint. The thumbv6m build is the
 * `buffer-pool-session-rx-slim` profile: the acceptor session rx socket
 * (4 x 256 ~= 1 KB) + the matching slim reactive-peer socket keep the e2e
 * heap inside the 4 KB HEAP_SIZE (its high-water measured 3454 bytes in
 * R2776).
 *
 * ## The stack is DECLARED, and it sits BELOW .data/.bss (R2776)
 *
 * Until R2776 this file declared RAM alone, so cortex-m-rt put the stack at
 * the top of it and let it grow down toward .bss with nothing in between.
 * Nothing said how much it could have and nothing measured what it took. It
 * took more: the acceptor's deepest call went 208 bytes past what the layout
 * left above .bss, and the boot passed anyway because what it overwrote was
 * lwIP state nothing on that path read. The push that deepened it faulted
 * (open-debt item 805).
 *
 * So the stack is its own region, at the BOTTOM of SRAM:
 *
 *   - A stack that outgrows STACK leaves SRAM (below 0x20000000) and faults
 *     at the push that does it, instead of writing over a variable.
 *   - .data/.bss that outgrow RAM fail the LINK, instead of shrinking the
 *     stack's room without anyone being told.
 *   - `_stack_end` / `_stack_start` name the region, and the binary checks
 *     its measured peak against that size with `wz_mcu_stack` before it
 *     reports PASS, so every Layer Q run prints the margin.
 *
 * The split is from measurement, not a guess: .data + .bss are 8812 bytes,
 * so RAM = 9K leaves them 404 bytes to grow, and the stack's peak — printed
 * by every boot — must stay `wz_mcu_stack::MARGIN_BYTES` under STACK. Moving
 * the line moves both numbers at once; read them off the boot's verdict line
 * and the link, not off this comment.
 */

MEMORY
{
  FLASH : ORIGIN = 0x00000000, LENGTH = 256K
  STACK : ORIGIN = 0x20000000, LENGTH = 7K
  RAM   : ORIGIN = 0x20001C00, LENGTH = 9K
}

_stack_start = ORIGIN(STACK) + LENGTH(STACK);
_stack_end = ORIGIN(STACK);
