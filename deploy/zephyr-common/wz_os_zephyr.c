/* SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * The operating system an engine runs on, answered by the Zephyr kernel (CONFIG_WZ_OS).
 *
 * `wz-capi-port`'s `os` module (crates/wz-capi-port/src/os.rs) names these functions when it is
 * built without `std`: the mutex a session is stepped under, the calling thread's identity, a
 * thread of the engine's own (zenoh-pico's read task) and a sleep. The mutex is the kernel's
 * blocking `k_mutex`, not a critical section: a session holds it while it reads and dispatches a
 * message, and masking interrupts for that long would hold off the network driver. A thread's
 * stack and its `k_thread` come from the kernel's dynamic thread pool and are given back when the
 * thread is joined.
 */

#include <errno.h>
#include <stdint.h>

#include <zephyr/kernel.h>

void *wz_os_mutex_new(void)
{
	struct k_mutex *mutex = k_malloc(sizeof(*mutex));

	if (mutex != NULL) {
		k_mutex_init(mutex);
	}
	return mutex;
}

void wz_os_mutex_lock(void *mutex)
{
	(void)k_mutex_lock(mutex, K_FOREVER);
}

void wz_os_mutex_unlock(void *mutex)
{
	(void)k_mutex_unlock(mutex);
}

void wz_os_mutex_free(void *mutex)
{
	k_free(mutex);
}

uintptr_t wz_os_thread_current(void)
{
	return (uintptr_t)k_current_get();
}

struct wz_os_thread {
	struct k_thread thread;
	k_thread_stack_t *stack;
	void (*entry)(void *);
	void *arg;
};

static void wz_os_thread_entry(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);
	struct wz_os_thread *t = p1;

	t->entry(t->arg);
}

int wz_os_thread_spawn(void (*entry)(void *), void *arg, uintptr_t *id)
{
	struct wz_os_thread *t = k_malloc(sizeof(*t));

	if (t == NULL) {
		return -ENOMEM;
	}
	t->stack = k_thread_stack_alloc(CONFIG_WZ_OS_THREAD_STACK_SIZE, 0);
	if (t->stack == NULL) {
		k_free(t);
		return -ENOMEM;
	}
	t->entry = entry;
	t->arg = arg;
	k_tid_t tid = k_thread_create(&t->thread, t->stack, CONFIG_WZ_OS_THREAD_STACK_SIZE,
				      wz_os_thread_entry, t, NULL, NULL,
				      CONFIG_WZ_OS_THREAD_PRIORITY, 0, K_NO_WAIT);

	(void)k_thread_name_set(tid, "wz-os");
	*id = (uintptr_t)tid;
	return 0;
}

int wz_os_thread_join(uintptr_t id)
{
	struct wz_os_thread *t = CONTAINER_OF((struct k_thread *)id, struct wz_os_thread, thread);
	int rc = k_thread_join(&t->thread, K_FOREVER);

	if (rc == 0) {
		(void)k_thread_stack_free(t->stack);
		k_free(t);
	}
	return rc;
}

int wz_os_thread_is_finished(uintptr_t id)
{
	/* A join that does not wait answers 0 for a thread that has ended and -EBUSY for one that
	 * runs; it frees nothing, so the thread is still joined once afterwards.
	 */
	return k_thread_join((struct k_thread *)id, K_NO_WAIT) == 0 ? 1 : 0;
}

void wz_os_sleep_ms(uint32_t ms)
{
	k_msleep((int32_t)MIN(ms, (uint32_t)INT32_MAX));
}
