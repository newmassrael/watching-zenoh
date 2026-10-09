/* SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * The two control lines of a 10BASE-T1S expansion board in the MikroBUS socket of
 * KIT_T2G-B-H_LITE (CYT4BF8CDS): the reset line (the chip's RESET_N) and the
 * interrupt line (its IRQ_N). The SPI pins are `mikrobus_spi_pins.c`'s.
 *
 * Which pins the SOCKET puts those two signals on is the KIT's fact, read off its
 * board support package (Apache-2.0), which names the socket's reset pin
 * `CYBSP_MIKROBUS_RST` as P11_2 and its interrupt pin `CYBSP_MIKROBUS_INT` as
 * P17_2, and checked against the PDL's pin table for this device
 * (`gpio_xmc7200_176_teqfp.h`, Apache-2.0), which lists both as GPIO pins of ports
 * 11 and 17. Zephyr's board description for the kit uses no pin of those ports
 * except port 17 pin 0, which is not this one.
 *
 * Whether the expansion board connects its chip to those pins is the BOARD
 * PLUGGED IN's fact, which nothing here can read. A line is therefore only touched
 * when the build was told the board wires it (CONFIG_WZ_T1S_RESET_LINE,
 * CONFIG_WZ_T1S_IRQ_LINE, both off unless stated): a pin of the socket that the
 * expansion board uses for something else is not driven by a guess.
 *
 * What the chip's data sheet (DS60001734F) says of each line:
 *  - RESET_N is active low and must be held low at least 5 us (Table 9-8, trstia);
 *    the caller holds it longer, see wz_board_t1s_reset_set.
 *  - IRQ_N is active low. It is a driven output with an internal pull-up
 *    ("VO-VDDP (PU)", Table 3-3), which the data sheet says a host controller may
 *    still want a 10 kOhm pull-up for; the MCU's own pull-up is enabled here, which
 *    is the same help from the host side and harmless where the board has one.
 *
 * Wiring a different board is a different file beside this one and a different
 * Kconfig choice, not an edit of this one. BUILT, not run: nothing in this file
 * has been on a pin.
 */

#include <stdbool.h>
#include <stdint.h>

#include <cy_gpio.h>

/* What wz_board_t1s_lines_init reports: the lines this build drives or reads. */
#define WZ_T1S_LINE_RESET 0x1U
#define WZ_T1S_LINE_IRQ 0x2U

/* Route the lines the build says are wired, and return which they are. The reset
 * line is set to RELEASED (high) as it is routed, so that routing it is not itself
 * a reset. */
uint32_t wz_board_t1s_lines_init(void)
{
	uint32_t routed = 0;

#ifdef CONFIG_WZ_T1S_RESET_LINE
	Cy_GPIO_Pin_FastInit(P11_2_PORT, P11_2_PIN, CY_GPIO_DM_STRONG_IN_OFF, 1, P11_2_GPIO);
	routed |= WZ_T1S_LINE_RESET;
#endif
#ifdef CONFIG_WZ_T1S_IRQ_LINE
	Cy_GPIO_Pin_FastInit(P17_2_PORT, P17_2_PIN, CY_GPIO_DM_PULLUP, 1, P17_2_GPIO);
	routed |= WZ_T1S_LINE_IRQ;
#endif
	return routed;
}

/* Drive the chip's RESET_N: asserted means low. A no-op when the line is not
 * wired, which the caller has already learned from wz_board_t1s_lines_init. */
void wz_board_t1s_reset_set(bool asserted)
{
#ifdef CONFIG_WZ_T1S_RESET_LINE
	Cy_GPIO_Write(P11_2_PORT, P11_2_PIN, asserted ? 0U : 1U);
#else
	(void)asserted;
#endif
}

/* Whether the chip is asserting IRQ_N (low). False when the line is not wired. */
bool wz_board_t1s_irq_asserted(void)
{
#ifdef CONFIG_WZ_T1S_IRQ_LINE
	return Cy_GPIO_Read(P17_2_PORT, P17_2_PIN) == 0U;
#else
	return false;
#endif
}
