/* SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * The CYT4BF's TRNG as a Zephyr entropy device.
 *
 * The source is the board's `wz_board_entropy_fill` (the PDL's TRNG driver in the CRYPTO block,
 * src/trng_cat1c.c of the admin node), which fills a buffer and FAILS the whole fill when the
 * TRNG reports an error. This file only gives it the shape Zephyr's random subsystem, its
 * network stack and zenoh-pico draw from (`zephyr,entropy`).
 */

#define DT_DRV_COMPAT wz_cyt4bf_trng

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/device.h>
#include <zephyr/drivers/entropy.h>
#include <zephyr/kernel.h>

extern int wz_board_entropy_fill(void *buf, size_t len);

/* The PDL's TRNG driver keeps one enable flag and one block; callers come from several
 * threads (the network stack, the application), so a fill is not interleaved with another.
 */
static K_MUTEX_DEFINE(trng_lock);

static int trng_get_entropy(const struct device *dev, uint8_t *buffer, uint16_t length)
{
	ARG_UNUSED(dev);

	k_mutex_lock(&trng_lock, K_FOREVER);
	int rc = wz_board_entropy_fill(buffer, length);

	k_mutex_unlock(&trng_lock);
	return rc == 0 ? 0 : -EIO;
}

static DEVICE_API(entropy, trng_api) = {
	.get_entropy = trng_get_entropy,
};

static int trng_init(const struct device *dev)
{
	ARG_UNUSED(dev);
	return 0;
}

#define TRNG_DEFINE(inst)                                                                          \
	DEVICE_DT_INST_DEFINE(inst, trng_init, NULL, NULL, NULL, PRE_KERNEL_1,                     \
			      CONFIG_ENTROPY_INIT_PRIORITY, &trng_api)

DT_INST_FOREACH_STATUS_OKAY(TRNG_DEFINE)
