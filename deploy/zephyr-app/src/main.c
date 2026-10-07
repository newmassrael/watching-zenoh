/* SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * zephyr-app C entry — the Zephyr half of the Path-B integration. Zephyr boots,
 * owns the vector table + the systick, and runs `main()` on the main thread;
 * `main()` hands that thread to the wz Rust staticlib (`wz_app_main`), which
 * hosts CoopRuntime<ZephyrClock> (the cooperative single-task profile).
 *
 * The seams the Rust side calls through (printk, k_msleep, irq_lock, the
 * board's random source and wall clock) are shared by every wz Zephyr image and
 * live in deploy/zephyr-common/wz_board_hooks.c, not here.
 *
 * The CI verdict is the `ZEPHYR-WZ PASS` console sentinel under a QEMU timeout
 * (Zephyr-idiomatic console-regex pass, like twister) — there is no semihosting
 * exit on this board's qemu launch.
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>

/* Implemented in the wz Rust staticlib (libwz_zephyr_app.a). Returns 0 = PASS. */
extern int wz_app_main(void);

/* wz_board_hooks.c: set the realtime clock to this build's instant. */
extern int wz_board_set_boot_clock(void);

int main(void)
{
	printk("zephyr-app: boot ok; entering wz_app_main\n");

	/* The board's clock, set once at boot as an SNTP sync would set it. */
	if (wz_board_set_boot_clock() != 0) {
		printk("ZEPHYR-WZ FAIL rc=-1 (the board could not set its clock)\n");
		return 0;
	}

	int rc = wz_app_main();
	if (rc == 0) {
		printk("ZEPHYR-WZ PASS\n");
	} else {
		printk("ZEPHYR-WZ FAIL rc=%d\n", rc);
	}
	return 0;
}
