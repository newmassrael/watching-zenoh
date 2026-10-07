/* SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * The random source of a CAT1C (T2G) chip: the true random number generator in its
 * CRYPTO block, through Infineon's PDL (`Cy_Crypto_Core_Trng_Ext`).
 *
 * This is `wz_board_entropy_fill`, the board's answer to the session's secrets
 * (deploy/zephyr-common/wz_board_hooks.c selects it with CONFIG_WZ_ENTROPY_BOARD_HOOK).
 * Zephyr has no entropy driver for these chips, so the build would otherwise refuse
 * the board outright; the TRNG is real hardware, and the PDL's driver for it is the
 * vendor's own. It fills the buffer 32 bits at a time and FAILS the whole fill when
 * the TRNG reports an error, rather than return what the buffer held.
 *
 * BUILT and unrun: nothing here has been on a CYT4BF.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <cy_crypto_core.h>
#include <cy_crypto_core_trng.h>

int wz_board_entropy_fill(void *buf, size_t len)
{
	static bool enabled;
	uint8_t *out = buf;

	if (!enabled) {
		if (Cy_Crypto_Core_Enable(CRYPTO) != CY_CRYPTO_SUCCESS) {
			return -1;
		}
		enabled = true;
	}
	while (len > 0) {
		/* Must be 4-byte aligned. */
		uint32_t word;
		size_t take = len < sizeof(word) ? len : sizeof(word);

		if (Cy_Crypto_Core_Trng_Ext(CRYPTO, 32, &word) != CY_CRYPTO_SUCCESS) {
			return -1;
		}
		memcpy(out, &word, take);
		out += take;
		len -= take;
	}
	return 0;
}
