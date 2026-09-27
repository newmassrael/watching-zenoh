/* SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * zephyr-app C entry — the Zephyr half of the Path-B integration. Zephyr boots,
 * owns the vector table + the systick, and runs `main()` on the main thread;
 * `main()` hands that thread to the wz Rust staticlib (`wz_app_main`), which
 * hosts CoopRuntime<ZephyrClock> (the cooperative single-task profile). This C
 * file also supplies the thin seams the Rust side calls through (it cannot
 * FFI Zephyr's variadic `printk` nor the `static inline` `k_msleep` directly):
 *   - wz_log:      printk("%s\n", msg)
 *   - wz_yield_ms: k_msleep(ms)  (yields the main thread so the tick advances)
 * and, R2918, the board's random source and wall clock (below).
 *
 * The CI verdict is the `ZEPHYR-WZ PASS` console sentinel under a QEMU timeout
 * (Zephyr-idiomatic console-regex pass, like twister) — there is no semihosting
 * exit on this board's qemu launch.
 */

#include <stdint.h>
#include <time.h>

#include <zephyr/kernel.h>
#include <zephyr/irq.h>
#include <zephyr/random/random.h>
#include <zephyr/sys/printk.h>

/* Implemented in the wz Rust staticlib (libwz_zephyr_app.a). Returns 0 = PASS. */
extern int wz_app_main(void);

/* R2918 — the board's two hooks the profile's seams read
 * (`wz_runtime_zephyr::{ZephyrEntropy, ZephyrEpoch}`).
 *
 * ⚠ This board's answers are FIXTURES. QEMU mps2/an385 has no TRNG, so
 * `sys_rand_get` is served by Zephyr's test generator (prj.conf), predictable
 * by construction; and it has no RTC, so `main()` sets the realtime clock to
 * the image's build time before anything reads it, standing in for the SNTP
 * sync a networked board would do. A real board replaces the SOURCES — its
 * TRNG driver, its RTC or SNTP client — not these hooks, and not the profile
 * code that reads them. */
static uint32_t random_draws;

int wzApplicationGetRandom(void *buf, size_t len)
{
	sys_rand_get(buf, len); /* what zenoh-pico's Zephyr port calls */
	random_draws++;
	return 0;
}

unsigned int wz_random_draws(void)
{
	return random_draws;
}

int wzApplicationGetTimeSinceEpoch(uint64_t *secs, uint32_t *nanos)
{
	struct timespec ts;

	/* The read zenoh-pico's Zephyr port makes (`_z_get_time_since_epoch`). */
	if (clock_gettime(CLOCK_REALTIME, &ts) != 0 || ts.tv_sec < 0) {
		return 0;
	}
	*secs = (uint64_t)ts.tv_sec;
	*nanos = (uint32_t)ts.tv_nsec;
	return 1;
}

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

	/* The board's clock, set once at boot as an SNTP sync would set it (see
	 * the hooks above): the build's own instant, from CMakeLists.txt. */
	struct timespec boot = {.tv_sec = WZ_BOARD_EPOCH_SECS, .tv_nsec = 0};

	if (clock_settime(CLOCK_REALTIME, &boot) != 0) {
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
