/* SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * zephyr-admin-node C entry. Zephyr boots and runs `main()` on the main thread,
 * which `main()` hands to the wz Rust staticlib (`wz_app_main`). That call
 * returns only when the node could not start; a running node never returns.
 *
 * The firmware has no verdict of its own. What it is FOR is decided by the host
 * that talks to it, so it prints where it is and who it claims to be
 * (`ZEPHYR-WZ-ADMIN READY <zid> <locator>`, from the Rust side) and runs. The
 * only line this file prints after boot is the failure one.
 *
 * The seams the Rust side calls through (printk, k_msleep, irq_lock, the board's
 * random source and wall clock, its address and identity) are shared by every wz
 * Zephyr image and live in deploy/zephyr-common/wz_board_hooks.c.
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>

/* Implemented in the wz Rust staticlib (libwz_zephyr_admin_node.a). */
extern int wz_app_main(void);

/* wz_board_hooks.c: set the realtime clock to this build's instant. */
extern int wz_board_set_boot_clock(void);

int main(void)
{
	printk("zephyr-admin-node: boot ok; entering wz_app_main\n");

	if (wz_board_set_boot_clock() != 0) {
		printk("ZEPHYR-WZ-ADMIN FAIL rc=-1 (the board could not set its clock)\n");
		return 0;
	}

	int rc = wz_app_main();

	printk("ZEPHYR-WZ-ADMIN FAIL rc=%d\n", rc);
	return 0;
}
