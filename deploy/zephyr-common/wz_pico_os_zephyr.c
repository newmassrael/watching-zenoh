/* SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * The pico C ABI's host layer on Zephyr (CONFIG_WZ_PICO_OS).
 *
 * `wz-capi-pico` built with `os-zephyr` (crates/wz-capi-pico/src/os/zephyr.rs) answers zenoh-pico's
 * platform exports as pico's own Zephyr backend does (vendor/zenoh-pico/src/system/zephyr/
 * system.c). What the kernel offers only as a system call or an inline is answered here: the
 * sleeps, the random source and a condition variable on the monotonic clock. The rest the Rust
 * half calls directly, and this file pins every size and constant it states for those calls
 * against the headers this image compiles: a kernel or a C library that lays them out otherwise
 * fails this build instead of letting a C program's storage be written past.
 *
 * struct timeval is <sys/time.h>'s, which <time.h> does not complete; pico's own backend includes it
 * for the same type:
 *
 * `vendor/zenoh-pico/src/system/zephyr/system.c` @ `#include <sys/time.h>`
 */

#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/time.h>
#include <time.h>

#include <zephyr/kernel.h>
#include <zephyr/random/random.h>

/* What crates/wz-capi-pico/src/os/zephyr.rs states. */
BUILD_ASSERT(sizeof(time_t) == 8, "the Rust host layer reads a 64-bit time_t");
BUILD_ASSERT(sizeof(long) == 4, "the Rust host layer reads a 32-bit long");
BUILD_ASSERT(sizeof(struct timespec) == 16, "z_clock_t is 16 bytes in the Rust host layer");
BUILD_ASSERT(sizeof(struct timeval) == 16, "z_time_t is 16 bytes in the Rust host layer");
BUILD_ASSERT(offsetof(struct timespec, tv_nsec) == 8, "tv_nsec follows a 64-bit tv_sec");
BUILD_ASSERT(offsetof(struct timeval, tv_usec) == 8, "tv_usec follows a 64-bit tv_sec");
BUILD_ASSERT(sizeof(((struct timespec *)0)->tv_nsec) == 4, "tv_nsec is a 32-bit long");
BUILD_ASSERT(sizeof(((struct timeval *)0)->tv_usec) == 4, "tv_usec is a 32-bit long");
BUILD_ASSERT(CLOCK_REALTIME == 1, "the Rust host layer names CLOCK_REALTIME 1");
BUILD_ASSERT(CLOCK_MONOTONIC == 4, "the Rust host layer names CLOCK_MONOTONIC 4");
BUILD_ASSERT(sizeof(clockid_t) == sizeof(unsigned long), "clockid_t is an unsigned long");
BUILD_ASSERT(sizeof(pthread_mutex_t) == 4, "_z_mutex_t is a 32-bit handle in the Rust layer");
BUILD_ASSERT(sizeof(pthread_cond_t) == 4, "_z_condvar_t is a 32-bit handle in the Rust layer");
BUILD_ASSERT(sizeof(pthread_t) == 4, "_z_task_t is a 32-bit handle in the Rust layer");
BUILD_ASSERT(sizeof(pthread_attr_t) == 12, "z_task_attr_t is 12 bytes in the Rust layer");
BUILD_ASSERT(ETIMEDOUT == 116, "the Rust host layer names ETIMEDOUT 116");

/* The kernel's sleeps answer what is left of one a wake cut short; the caller sleeps that again,
 * as pico's z_sleep_* loop. `k_sleep` answers milliseconds, which a sleep asked in seconds
 * rounds up to seconds here, so the remainder is always in the unit asked. */
int32_t wz_pico_sleep_us(int32_t us)
{
	return k_usleep(us);
}

int32_t wz_pico_sleep_ms(int32_t ms)
{
	return k_msleep(ms);
}

int32_t wz_pico_sleep_s(int32_t s)
{
	int32_t left_ms = k_sleep(K_SECONDS(s));

	return left_ms <= 0 ? 0 : (int32_t)DIV_ROUND_UP(left_ms, MSEC_PER_SEC);
}

/* pico's z_random_fill on Zephyr. */
void wz_pico_random_fill(void *buf, size_t len)
{
	sys_rand_get(buf, len);
}

/* pico's _z_condvar_init on Zephyr: the condvar waits against CLOCK_MONOTONIC, the clock
 * z_clock_now reads, so that an absolute deadline taken from one means the same instant to the
 * other. */
int wz_pico_condvar_init(pthread_cond_t *cv)
{
	pthread_condattr_t attr;
	int rc = pthread_condattr_init(&attr);

	if (rc != 0) {
		return rc;
	}
	rc = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
	if (rc == 0) {
		rc = pthread_cond_init(cv, &attr);
	}
	(void)pthread_condattr_destroy(&attr);
	return rc;
}
