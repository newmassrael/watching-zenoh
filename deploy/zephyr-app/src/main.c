/* SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * zephyr-app C entry — the Zephyr half of the Path-B integration. Zephyr boots,
 * owns the vector table + the systick, and runs `main()` on the main thread;
 * `main()` hands that thread to the wz Rust staticlib (`wz_app_main`), which
 * hosts CoopRuntime<ZephyrClock> (the cooperative single-task profile). This C
 * file also supplies the two thin seams the Rust side calls through (it cannot
 * FFI Zephyr's variadic `printk` nor the `static inline` `k_msleep` directly):
 *   - wz_log:      printk("%s\n", msg)
 *   - wz_yield_ms: k_msleep(ms)  (yields the main thread so the tick advances)
 *
 * The CI verdict is the `ZEPHYR-WZ PASS` console sentinel under a QEMU timeout
 * (Zephyr-idiomatic console-regex pass, like twister) — there is no semihosting
 * exit on this board's qemu launch.
 */

#include <zephyr/kernel.h>
#include <zephyr/irq.h>
#include <zephyr/sys/printk.h>

/* Implemented in the wz Rust staticlib (libwz_zephyr_app.a). Returns 0 = PASS. */
extern int wz_app_main(void);

/* Rust -> Zephyr seams (non-variadic, non-inline link targets for the FFI). */
void wz_log(const char *msg)
{
	printk("%s\n", msg);
}

void wz_yield_ms(int ms)
{
	k_msleep(ms);
}

/* critical-section impl seams: irq_lock/irq_unlock are inline (the macro
 * expands to arch_irq_lock()), so the Rust ZephyrCriticalSection routes through
 * these wrappers. The key is the kernel's prior IRQ state. */
unsigned int wz_irq_lock(void)
{
	return irq_lock();
}

void wz_irq_unlock(unsigned int key)
{
	irq_unlock(key);
}

int main(void)
{
	printk("zephyr-app: boot ok; entering wz_app_main\n");
	int rc = wz_app_main();
	if (rc == 0) {
		printk("ZEPHYR-WZ PASS\n");
	} else {
		printk("ZEPHYR-WZ FAIL rc=%d\n", rc);
	}
	return 0;
}
