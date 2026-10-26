/* SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * What an image's memory did, said the same way by every image that is compared
 * (docs/upstream-parity.md step M3, CONFIG_WZ_MEMORY_REPORT).
 *
 * A compare run holds two different programs to the same figures, so the figures
 * cannot come from either program: zenoh-pico's image prints nothing of its memory,
 * and the wz image's own stack line covers its main thread and nothing else, while
 * pico runs a read task and a lease task beside `main`. This thread reads the kernel,
 * which both programs allocate from (`k_malloc`, for pico's `z_malloc` and for the wz
 * image's `ZephyrAllocator` alike) and whose threads both run on:
 *
 *   mem: heap peak <max allocated> of <pool> bytes
 *   mem: stack <thread name> used=<bytes used> size=<bytes reserved>
 *
 * one line for the heap and one for each thread, printed when any figure moved since
 * the last print, so a quiet image prints nothing and a measured run is not paced by
 * a 115200 baud console. The thread runs at the lowest preemptible priority and reads
 * its own stack too: its cost is in the figures, the same on both sides.
 *
 * The kernel's network and work-queue threads are listed with the application's: they
 * are the same in both images only if the two configure the kernel alike, and when they
 * do not, that difference is part of what each image costs.
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/sys/sys_heap.h>

#define WZ_MEMORY_REPORT_THREADS 24

/* The kernel heap `k_malloc` serves (kernel/mempool.c). */
extern struct k_heap _system_heap;

struct seen_stack {
	const struct k_thread *thread;
	size_t used;
};

static struct seen_stack seen[WZ_MEMORY_REPORT_THREADS];
static size_t seen_count;
static bool moved;

static void read_thread(const struct k_thread *thread, void *unused)
{
	ARG_UNUSED(unused);
	size_t unused_bytes = 0;

	if (k_thread_stack_space_get(thread, &unused_bytes) != 0) {
		return;
	}
	size_t used = thread->stack_info.size - unused_bytes;

	for (size_t i = 0; i < seen_count; i++) {
		if (seen[i].thread == thread) {
			if (seen[i].used != used) {
				seen[i].used = used;
				moved = true;
			}
			return;
		}
	}
	if (seen_count < WZ_MEMORY_REPORT_THREADS) {
		seen[seen_count].thread = thread;
		seen[seen_count].used = used;
		seen_count++;
		moved = true;
	}
}

static void print_thread(const struct k_thread *thread, void *unused)
{
	ARG_UNUSED(unused);
	size_t unused_bytes = 0;

	if (k_thread_stack_space_get(thread, &unused_bytes) != 0) {
		return;
	}
	const char *name = k_thread_name_get((k_tid_t)thread);

	/* Each figure is bound to its name with `=`, so the line reads as the report's and as no
	 * sentence: with a word between two values ("%u of %u", "%u size %u") the e2e barrier gate
	 * (scripts/lib/barrier_needle_gate.py) reads a value as any one word and finds the line able
	 * to print another test's barrier text.
	 */
	printk("mem: stack %s used=%u size=%u\n",
	       (name != NULL && name[0] != '\0') ? name : "unnamed",
	       (unsigned int)(thread->stack_info.size - unused_bytes),
	       (unsigned int)thread->stack_info.size);
}

static void wz_memory_report(void *a, void *b, void *c)
{
	ARG_UNUSED(a);
	ARG_UNUSED(b);
	ARG_UNUSED(c);
	size_t heap_peak = SIZE_MAX;

	for (;;) {
		struct sys_memory_stats stats = {0};

		moved = false;
		k_thread_foreach_unlocked(read_thread, NULL);
		if (sys_heap_runtime_stats_get(&_system_heap.heap, &stats) == 0 &&
		    stats.max_allocated_bytes != heap_peak) {
			heap_peak = stats.max_allocated_bytes;
			moved = true;
		}
		if (moved) {
			printk("mem: heap peak %u of %u bytes\n", (unsigned int)heap_peak,
			       (unsigned int)(stats.allocated_bytes + stats.free_bytes));
			k_thread_foreach_unlocked(print_thread, NULL);
		}
		k_sleep(K_MSEC(CONFIG_WZ_MEMORY_REPORT_PERIOD_MS));
	}
}

K_THREAD_DEFINE(wz_memory_report_tid, CONFIG_WZ_MEMORY_REPORT_STACK_SIZE, wz_memory_report, NULL,
		NULL, NULL, K_LOWEST_APPLICATION_THREAD_PRIO, 0, 0);
