/* SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * ETH0's pins for RMII on KIT_T2G-B-H_LITE (CYT4BF8CDS, 176-pin package).
 *
 * Run before the MAC is touched (`wz_board_eth_pins_init`, called from the Rust
 * side's `mac_cyt4bf::open`). The routing is the PDL's `Cy_GPIO_Pin_FastInit` and
 * the pin/function names are the PDL's own (`devices/COMPONENT_CAT1C/include/
 * gpio_xmc7200_176_teqfp.h`, Apache-2.0): each pin below is one that table lists as
 * an ETH0 function, which is the silicon fact. Which of them the kit uses is the
 * kit's schematic: REF_CLK from the PHY, the RMII data and control pairs, and the
 * management port. RX_ER is not connected on this kit and no pin is routed for it.
 *
 * Drive modes follow the PDL's own GPIO documentation, not a measurement:
 *   - an input the peripheral reads (REF_CLK, RXD0/1, CRS_DV) is Digital High-Z,
 *     input buffer on;
 *   - an output the peripheral drives (TX_EN, TXD0/1, MDC) is Strong, input buffer
 *     off;
 *   - MDIO, which the controller drives and reads, is Strong with the input buffer
 *     on (the kit puts a pull-up on it).
 * Slew rate and drive strength are left at their reset values. All of that is
 * BUILT and unrun: nothing here has been on a CYT4BF.
 *
 * Wiring a different board is a different file beside this one and a different
 * CONFIG_WZ_CYT4BF_PINS_* choice, not an edit of this one.
 */

#include <stdint.h>

#include <cy_gpio.h>

struct wz_eth_pin {
	GPIO_PRT_Type *port;
	uint8_t pin;
	uint32_t drive;
	en_hsiom_sel_t hsiom;
};

int wz_board_eth_pins_init(void)
{
	static const struct wz_eth_pin pins[] = {
		/* management */
		{P3_0_PORT, P3_0_PIN, CY_GPIO_DM_STRONG, P3_0_ETH0_MDIO},
		{P3_1_PORT, P3_1_PIN, CY_GPIO_DM_STRONG_IN_OFF, P3_1_ETH0_MDC},
		/* reference clock from the PHY */
		{P18_0_PORT, P18_0_PIN, CY_GPIO_DM_HIGHZ, P18_0_ETH0_REF_CLK},
		/* transmit: TX_EN and TXD0/1 */
		{P18_1_PORT, P18_1_PIN, CY_GPIO_DM_STRONG_IN_OFF, P18_1_ETH0_TX_CTL},
		{P18_4_PORT, P18_4_PIN, CY_GPIO_DM_STRONG_IN_OFF, P18_4_ETH0_TXD0},
		{P18_5_PORT, P18_5_PIN, CY_GPIO_DM_STRONG_IN_OFF, P18_5_ETH0_TXD1},
		/* receive: RXD0/1 and CRS_DV */
		{P19_0_PORT, P19_0_PIN, CY_GPIO_DM_HIGHZ, P19_0_ETH0_RXD0},
		{P19_1_PORT, P19_1_PIN, CY_GPIO_DM_HIGHZ, P19_1_ETH0_RXD1},
		{P21_5_PORT, P21_5_PIN, CY_GPIO_DM_HIGHZ, P21_5_ETH0_RX_CTL},
	};

	for (unsigned int i = 0; i < sizeof(pins) / sizeof(pins[0]); i++) {
		Cy_GPIO_Pin_FastInit(pins[i].port, pins[i].pin, pins[i].drive, 0, pins[i].hsiom);
	}
	return 0;
}
