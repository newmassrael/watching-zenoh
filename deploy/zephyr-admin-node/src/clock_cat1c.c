/* SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * The core clock of a CAT1C (T2G) Cortex-M7, read from the chip's registers.
 *
 * This is `wz_board_core_clock_hz`, the board's answer to `wz_core_clock_hz`
 * (deploy/zephyr-common/wz_board_hooks.c selects it with CONFIG_WZ_CORE_CLOCK_BOARD_HOOK).
 * The image is built for the clock in the devicetree (CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC)
 * and Zephyr's clock driver on an M7 returns without bringing the clock tree up: the
 * CM0+ core has to. A tree that was not brought up leaves the M7 at the 8 MHz
 * oscillator, and nothing else says so; the image compares this reading with what it
 * assumes (wz_runtime_zephyr::core_clock) before anything that waits.
 *
 * WHICH clock feeds the core, and the function that computes it, are Infineon's own:
 * the PDL's system file for this core (mtb-template-cat1, cat1c/COMPONENT_CM7/
 * system_cm7.c, SystemCoreClockUpdate) sets SystemCoreClock to
 * Cy_SysClk_ClkFastSrcGetFrequency(0) for CM7_0 and (1) for CM7_1. That function
 * (mtb-pdl-cat1 drivers/source/cy_sysclk_v2.c) divides the frequency of clk_hf[1] by
 * the CPUSS.FAST_<n>_CLOCK_CTL divider, and clk_hf[1] is the root-mux selection, the
 * root divider and, for a PLL path, the PLL's enable bit and its multiplier and
 * dividers: all registers.
 *
 * ONE input is not a register: a PLL path's input is the external crystal, and its
 * frequency is a number the PDL holds, handed out by Cy_SysClk_EcoGetFrequency only
 * while the ECO status register says the crystal is stable. Zephyr's clock driver
 * sets that number on the M7 from the board's configuration (16 MHz, the kit's
 * crystal; clock_control_infineon.c, Cy_SysClk_EcoSetFrequency) before main() runs. A
 * board whose crystal differs from that number reads wrong by the same factor.
 *
 * A path the PDL cannot evaluate yields 0, its own "unknown frequency" (the comment
 * in Cy_SysClk_ClkPathMuxGetFrequency), and 0 is what this returns: the contract of
 * the hook is "0 means the board cannot tell".
 *
 * BUILT and unrun: no register read here has been compared with a bench.
 */

#include <stdint.h>

#include <zephyr/kernel.h>

#include <cy_sysclk.h>

uint32_t wz_board_core_clock_hz(void)
{
#if defined(CONFIG_SOC_XMC7200_CORE_NAME_M7_0)
	return Cy_SysClk_ClkFastSrcGetFrequency(0);
#elif defined(CONFIG_SOC_XMC7200_CORE_NAME_M7_1)
	return Cy_SysClk_ClkFastSrcGetFrequency(1);
#else
	/* Not an M7 core of this family: nothing here knows which clock feeds it. */
	return 0;
#endif
}
