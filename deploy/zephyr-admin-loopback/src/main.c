/* SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * zephyr-admin-loopback C entry: Zephyr boots and runs `main()` on the main thread, and `main()`
 * hands that thread to the wz Rust staticlib (`wz_app_main`), which runs an admin node and the
 * client that dials it over the board's loopback interface. The seams the Rust side calls through
 * are shared by every wz Zephyr image and live in deploy/zephyr-common/wz_board_hooks.c.
 *
 * The verdict is the `ZEPHYR-WZ-ADMIN-TLS PASS` console sentinel under a QEMU timeout.
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>

/* Implemented in the wz Rust staticlib (libwz_zephyr_admin_loopback.a). Returns 0 = PASS. */
extern int wz_app_main(void);

/* wz_board_hooks.c: set the realtime clock to this build's instant. */
extern int wz_board_set_boot_clock(void);

int main(void)
{
	printk("zephyr-admin-loopback: boot ok; entering wz_app_main\n");

	if (wz_board_set_boot_clock() != 0) {
		printk("ZEPHYR-WZ-ADMIN-TLS FAIL rc=-1 (the board could not set its clock)\n");
		return 0;
	}

	int rc = wz_app_main();
	if (rc == 0) {
		printk("ZEPHYR-WZ-ADMIN-TLS PASS\n");
	} else {
		printk("ZEPHYR-WZ-ADMIN-TLS FAIL rc=%d\n", rc);
	}
	return 0;
}
