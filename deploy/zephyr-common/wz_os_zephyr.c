/* SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * The operating system an engine runs on, answered by the Zephyr kernel (CONFIG_WZ_OS).
 *
 * `wz-capi-port`'s `os` module (crates/wz-capi-port/src/os.rs) names these functions when it is
 * built without `std`: the mutex a session is stepped under and a condition variable waited on
 * with it, the calling thread's identity, a thread of the engine's own (zenoh-pico's read task)
 * and a sleep. The mutex is the kernel's
 * blocking `k_mutex`, not a critical section: a session holds it while it reads and dispatches a
 * message, and masking interrupts for that long would hold off the network driver.
 *
 * Every kernel object here comes from a pool the image sizes and none from the kernel heap: the
 * mutexes and the condition variables from memory slabs of CONFIG_WZ_OS_MUTEXES and
 * CONFIG_WZ_OS_CONDVARS blocks, a thread's record and its stack from static arrays of
 * CONFIG_WZ_OS_THREADS, as zenoh-pico places its tasks' stacks
 * (`vendor/zenoh-pico/src/system/zephyr/system.c` @
 * `K_THREAD_STACK_ARRAY_DEFINE(thread_stack_area, Z_THREADS_NUM, Z_PTHREAD_STACK_SIZE_DEFAULT);`).
 * A pool with no free block answers as a heap with no room did: NULL, or -ENOMEM, which the
 * engine reports as an allocation that failed. A block is given back when its object is freed,
 * a thread's when it is joined.
 */

#include <errno.h>
#include <stdint.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/atomic.h>

K_MEM_SLAB_DEFINE_STATIC(wz_os_mutexes, sizeof(struct k_mutex), CONFIG_WZ_OS_MUTEXES,
			 __alignof__(struct k_mutex));

K_MEM_SLAB_DEFINE_STATIC(wz_os_condvars, sizeof(struct k_condvar), CONFIG_WZ_OS_CONDVARS,
			 __alignof__(struct k_condvar));

void *wz_os_mutex_new(void)
{
	void *mutex;

	if (k_mem_slab_alloc(&wz_os_mutexes, &mutex, K_NO_WAIT) != 0) {
		return NULL;
	}
	k_mutex_init(mutex);
	return mutex;
}

void wz_os_mutex_lock(void *mutex)
{
	(void)k_mutex_lock(mutex, K_FOREVER);
}

/* 0 once the mutex is this thread's; -EBUSY at once when another thread holds it. */
int wz_os_mutex_try_lock(void *mutex)
{
	return k_mutex_lock(mutex, K_NO_WAIT);
}

void wz_os_mutex_unlock(void *mutex)
{
	(void)k_mutex_unlock(mutex);
}

void wz_os_mutex_free(void *mutex)
{
	k_mem_slab_free(&wz_os_mutexes, mutex);
}

/* The condition variable a C ABI's channels and undeclares wait on, with a mutex above held. */
void *wz_os_condvar_new(void)
{
	void *condvar;

	if (k_mem_slab_alloc(&wz_os_condvars, &condvar, K_NO_WAIT) != 0) {
		return NULL;
	}
	k_condvar_init(condvar);
	return condvar;
}

void wz_os_condvar_wait(void *condvar, void *mutex)
{
	(void)k_condvar_wait(condvar, mutex, K_FOREVER);
}

void wz_os_condvar_notify_one(void *condvar)
{
	(void)k_condvar_signal(condvar);
}

void wz_os_condvar_notify_all(void *condvar)
{
	(void)k_condvar_broadcast(condvar);
}

void wz_os_condvar_free(void *condvar)
{
	k_mem_slab_free(&wz_os_condvars, condvar);
}

uintptr_t wz_os_thread_current(void)
{
	return (uintptr_t)k_current_get();
}

struct wz_os_thread {
	struct k_thread thread;
	void (*entry)(void *);
	void *arg;
};

#if CONFIG_WZ_OS_THREADS > 0

K_THREAD_STACK_ARRAY_DEFINE(wz_os_stacks, CONFIG_WZ_OS_THREADS, CONFIG_WZ_OS_THREAD_STACK_SIZE);
static struct wz_os_thread wz_os_threads[CONFIG_WZ_OS_THREADS];
/* A set bit is a record and its stack that a thread holds until it is joined. */
static ATOMIC_DEFINE(wz_os_threads_taken, CONFIG_WZ_OS_THREADS);

static void wz_os_thread_entry(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);
	struct wz_os_thread *t = p1;

	t->entry(t->arg);
}

int wz_os_thread_spawn(void (*entry)(void *), void *arg, uintptr_t *id)
{
	for (int i = 0; i < CONFIG_WZ_OS_THREADS; i++) {
		if (atomic_test_and_set_bit(wz_os_threads_taken, i)) {
			continue;
		}
		struct wz_os_thread *t = &wz_os_threads[i];

		t->entry = entry;
		t->arg = arg;
		k_tid_t tid = k_thread_create(&t->thread, wz_os_stacks[i],
					      CONFIG_WZ_OS_THREAD_STACK_SIZE, wz_os_thread_entry, t,
					      NULL, NULL, CONFIG_WZ_OS_THREAD_PRIORITY, 0, K_NO_WAIT);

		(void)k_thread_name_set(tid, "wz-os");
		*id = (uintptr_t)tid;
		return 0;
	}
	return -ENOMEM;
}

int wz_os_thread_join(uintptr_t id)
{
	struct wz_os_thread *t = CONTAINER_OF((struct k_thread *)id, struct wz_os_thread, thread);
	int rc = k_thread_join(&t->thread, K_FOREVER);

	if (rc == 0) {
		atomic_clear_bit(wz_os_threads_taken, (int)(t - wz_os_threads));
	}
	return rc;
}

int wz_os_thread_is_finished(uintptr_t id)
{
	/* A join that does not wait answers 0 for a thread that has ended and -EBUSY for one that
	 * runs; it gives nothing back, so the thread is still joined once afterwards.
	 */
	return k_thread_join((struct k_thread *)id, K_NO_WAIT) == 0 ? 1 : 0;
}

#else /* CONFIG_WZ_OS_THREADS == 0: an image that starts no thread of the engine's. */

int wz_os_thread_spawn(void (*entry)(void *), void *arg, uintptr_t *id)
{
	ARG_UNUSED(entry);
	ARG_UNUSED(arg);
	ARG_UNUSED(id);
	return -ENOMEM;
}

int wz_os_thread_join(uintptr_t id)
{
	ARG_UNUSED(id);
	return -EINVAL;
}

int wz_os_thread_is_finished(uintptr_t id)
{
	ARG_UNUSED(id);
	return 1;
}

#endif

void wz_os_sleep_ms(uint32_t ms)
{
	k_msleep((int32_t)MIN(ms, (uint32_t)INT32_MAX));
}
