/* SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * The MikroBUS socket's SPI on KIT_T2G-B-H_LITE (CYT4BF8CDS): the SCB the socket's
 * four SPI pins are wired to, and those pins routed to it.
 *
 * Which SCB and which pins are the KIT's facts, read off its board support
 * package (which names the MikroBUS SPI as SCB3, MISO P13_0, MOSI P13_1, CLK P13_2
 * and chip select P13_5, on slave select line 2) and checked here against the
 * PDL's pin table for this device (`gpio_xmc7200_176_teqfp.h`, which the device's
 * own header includes; Apache-2.0): each pin below is one that table lists as
 * the SCB3 SPI function it is used for, on the same function number. The kit's
 * schematic and BSP are the authority for the wiring, and this file is not run
 * on silicon: it is BUILT.
 *
 * Drive modes follow the PDL's own GPIO documentation, not a measurement: the
 * line the master reads (MISO) is Digital High-Z with the input buffer on; the
 * lines it drives (MOSI, CLK, SELECT) are Strong with the input buffer off.
 * Slew rate and drive strength stay at their reset values.
 *
 * Wiring a different board is a different file beside this one and a different
 * Kconfig choice, not an edit of this one.
 */

#include <stdint.h>

#include <cy_gpio.h>

/* Route the socket's SPI pins and report which of the SCB's slave select lines
 * carries chip select. Returns 0, and writes the line to `select`. */
int wz_board_spi_pins_init(uint8_t *select)
{
	Cy_GPIO_Pin_FastInit(P13_0_PORT, P13_0_PIN, CY_GPIO_DM_HIGHZ, 0, P13_0_SCB3_SPI_MISO);
	Cy_GPIO_Pin_FastInit(P13_1_PORT, P13_1_PIN, CY_GPIO_DM_STRONG_IN_OFF, 0,
			     P13_1_SCB3_SPI_MOSI);
	Cy_GPIO_Pin_FastInit(P13_2_PORT, P13_2_PIN, CY_GPIO_DM_STRONG_IN_OFF, 0,
			     P13_2_SCB3_SPI_CLK);
	Cy_GPIO_Pin_FastInit(P13_5_PORT, P13_5_PIN, CY_GPIO_DM_STRONG_IN_OFF, 0,
			     P13_5_SCB3_SPI_SELECT2);
	*select = 2;
	return 0;
}
