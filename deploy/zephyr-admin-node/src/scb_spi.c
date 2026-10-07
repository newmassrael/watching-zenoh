/* SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * An SPI master on one SCB block of the CYT4BF, polled, through the PDL.
 *
 * Zephyr's own SPI driver is not an option on this chip in the tree this builds
 * against: its devicetree binding wants an `interrupts` property that the SoC's SCB
 * nodes do not carry (they carry `system-interrupts`). So this is the PDL driver,
 * called directly, and thin: every RULE (how a clock rate becomes a divider and an
 * oversample factor, what an exchange may be) lives in the Rust crate `wz-spi-scb`
 * where it is host-tested, and this file does only what needs the registers.
 *
 * Which SCB, and which of its slave select lines carries chip select, are the
 * BOARD's (the board's own `..._spi_pins.c` routes the pins and names the line); the
 * SCB itself is fixed here as SCB3, the one the kit's MikroBUS socket uses.
 *
 * What it does, in the order a caller uses it:
 *   1. `wz_scb_spi_clock_claim`: find an 8-bit peripheral clock divider nobody has
 *      enabled, connect it to the SCB, enable it dividing by one, and report the
 *      clock that gives, in hertz. The divider is FOUND, not chosen by number: a
 *      number written down here would be right only while no other driver claimed
 *      it, and Zephyr's own drivers claim them at boot.
 *   2. `wz_scb_spi_start`: set the divider to the one the caller computed from that
 *      frequency, configure the SCB as a Motorola SPI master in the mode asked for,
 *      and enable it.
 *   3. `wz_scb_spi_exchange`: one chip-select assertion, `len` bytes out and `len`
 *      bytes in. The whole of `tx` is loaded into the transmit FIFO BEFORE the
 *      clocks run, because the block releases chip select when that FIFO runs dry,
 *      and an exchange that did not fit would be cut in two by a release in the
 *      middle of a frame. The caller has already refused anything longer than the
 *      FIFO; this refuses it again, since it is the one place that knows.
 *
 * BUILT, not run: nothing in this file has been on an SCB. The configuration
 * follows the defaults Zephyr's own PDL SPI driver uses for a master (MISO sampled
 * late, no separation between data elements, chip select active low, MSB first,
 * eight-bit elements), which that driver runs on other chips.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>

#include <zephyr/kernel.h>

#include <cy_scb_spi.h>
#include <cy_sysclk.h>

#define WZ_SCB_BLOCK SCB3
#define WZ_SCB_CLOCK PCLK_SCB3_CLOCK
#define WZ_DIVIDER_TYPE CY_SYSCLK_DIV_8_BIT
/* The most an 8-bit divider divides by. */
#define WZ_DIVIDER_MAX 256U

static bool divider_claimed;
static uint32_t divider_number;

static uint32_t peri_instance(void)
{
	return ((uint32_t)WZ_SCB_CLOCK & PERI_PCLK_INST_NUM_Msk) >> PERI_PCLK_INST_NUM_Pos;
}

static uint32_t peri_group(void)
{
	return ((uint32_t)WZ_SCB_CLOCK & PERI_PCLK_GR_NUM_Msk) >> PERI_PCLK_GR_NUM_Pos;
}

uint32_t wz_scb_spi_clock_claim(void)
{
	if (divider_claimed) {
		return 0;
	}
	const uint32_t count = PERI_PCLK_GR_DIV_8_NR(peri_instance(), peri_group());

	for (uint32_t n = 0; n < count; n++) {
		if (Cy_SysClk_PeriPclkGetDividerEnabled(WZ_SCB_CLOCK, WZ_DIVIDER_TYPE, n)) {
			continue;
		}
		if (Cy_SysClk_PeriPclkAssignDivider(WZ_SCB_CLOCK, WZ_DIVIDER_TYPE, n) !=
		    CY_SYSCLK_SUCCESS) {
			return 0;
		}
		if (Cy_SysClk_PeriPclkSetDivider(WZ_SCB_CLOCK, WZ_DIVIDER_TYPE, n, 0) !=
		    CY_SYSCLK_SUCCESS) {
			return 0;
		}
		if (Cy_SysClk_PeriPclkEnableDivider(WZ_SCB_CLOCK, WZ_DIVIDER_TYPE, n) !=
		    CY_SYSCLK_SUCCESS) {
			return 0;
		}
		divider_number = n;
		divider_claimed = true;
		return Cy_SysClk_PeriPclkGetFrequency(WZ_SCB_CLOCK, WZ_DIVIDER_TYPE, n);
	}
	/* Every divider of the group is in use: nothing to give the SCB. */
	return 0;
}

static cy_en_scb_spi_sclk_mode_t sclk_mode(uint8_t mode)
{
	switch (mode) {
	case 1:
		return CY_SCB_SPI_CPHA1_CPOL0;
	case 2:
		return CY_SCB_SPI_CPHA0_CPOL1;
	case 3:
		return CY_SCB_SPI_CPHA1_CPOL1;
	default:
		return CY_SCB_SPI_CPHA0_CPOL0;
	}
}

int wz_scb_spi_start(uint8_t mode, uint8_t select, uint32_t divider, uint32_t oversample)
{
	if (!divider_claimed || mode > 3 || select > 3 || divider == 0 ||
	    divider > WZ_DIVIDER_MAX) {
		return -EINVAL;
	}

	/* The divider was enabled dividing by one; it is disabled to be changed and
	 * enabled again, as the PDL requires of a divider that is already running. */
	if (Cy_SysClk_PeriPclkDisableDivider(WZ_SCB_CLOCK, WZ_DIVIDER_TYPE, divider_number) !=
		    CY_SYSCLK_SUCCESS ||
	    Cy_SysClk_PeriPclkSetDivider(WZ_SCB_CLOCK, WZ_DIVIDER_TYPE, divider_number,
					 divider - 1U) != CY_SYSCLK_SUCCESS ||
	    Cy_SysClk_PeriPclkEnableDivider(WZ_SCB_CLOCK, WZ_DIVIDER_TYPE, divider_number) !=
		    CY_SYSCLK_SUCCESS) {
		return -EIO;
	}

	const cy_stc_scb_spi_config_t config = {
		.spiMode = CY_SCB_SPI_MASTER,
		.subMode = CY_SCB_SPI_MOTOROLA,
		.sclkMode = sclk_mode(mode),
		.parity = CY_SCB_SPI_PARITY_NONE,
		.dropOnParityError = false,
		.oversample = oversample,
		.rxDataWidth = 8,
		.txDataWidth = 8,
		.enableMsbFirst = true,
		.enableFreeRunSclk = false,
		.enableInputFilter = false,
		.enableMisoLateSample = true,
		/* Chip select stays asserted from the first element to the last, which is
		 * the whole of an exchange. */
		.enableTransferSeperation = false,
		/* Active low on every line. */
		.ssPolarity = 0,
		.ssSetupDelay = false,
		.ssHoldDelay = false,
		.ssInterFrameDelay = false,
		.enableWakeFromSleep = false,
		.rxFifoTriggerLevel = 0,
		.rxFifoIntEnableMask = 0,
		.txFifoTriggerLevel = 0,
		.txFifoIntEnableMask = 0,
		.masterSlaveIntEnableMask = 0,
	};

	/* No context: nothing here uses the PDL's interrupt-driven transfer, only its
	 * FIFO functions, for which it documents a NULL context. */
	if (Cy_SCB_SPI_Init(WZ_SCB_BLOCK, &config, NULL) != CY_SCB_SPI_SUCCESS) {
		return -EIO;
	}
	Cy_SCB_SPI_SetActiveSlaveSelect(WZ_SCB_BLOCK, (cy_en_scb_spi_slave_select_t)select);
	Cy_SCB_SPI_Enable(WZ_SCB_BLOCK);
	return 0;
}

int wz_scb_spi_exchange(const uint8_t *tx, uint8_t *rx, uint32_t len)
{
	if (tx == NULL || rx == NULL || len == 0 || len > Cy_SCB_GetFifoSize(WZ_SCB_BLOCK)) {
		return -EINVAL;
	}

	/* Nothing left from an earlier exchange may answer this one. */
	Cy_SCB_SPI_ClearRxFifo(WZ_SCB_BLOCK);
	Cy_SCB_SPI_ClearTxFifo(WZ_SCB_BLOCK);

	/* Everything in before anything runs; the block starts clocking when the first
	 * element is queued, so a short write is an exchange already cut in two. */
	if (Cy_SCB_SPI_WriteArray(WZ_SCB_BLOCK, (void *)tx, len) != len) {
		Cy_SCB_SPI_ClearTxFifo(WZ_SCB_BLOCK);
		return -ENOSPC;
	}

	uint32_t got = 0;
	const uint32_t started = k_uptime_get_32();

	while (got < len) {
		got += Cy_SCB_SPI_ReadArray(WZ_SCB_BLOCK, rx + got, len - got);
		if (got < len && (k_uptime_get_32() - started) > CONFIG_WZ_SCB_SPI_TIMEOUT_MS) {
			return -ETIMEDOUT;
		}
	}
	while (!Cy_SCB_SPI_IsTxComplete(WZ_SCB_BLOCK)) {
		if ((k_uptime_get_32() - started) > CONFIG_WZ_SCB_SPI_TIMEOUT_MS) {
			return -ETIMEDOUT;
		}
	}
	return 0;
}
