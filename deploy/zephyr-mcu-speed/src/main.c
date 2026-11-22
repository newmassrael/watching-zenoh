/* SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * The program of the MCU speed matrix (docs/mcu-speed-matrix.md). It uses only the zenoh-pico C API, so
 * the same source is compiled against zenoh-pico (arm P) and linked to wz's pico C ABI (arm W), and it
 * speaks the protocol of the host matrix's probe (scripts/host-bench/perf_probe.c), which plays the
 * other side on the host: perf/ping and perf/pong carry a sequence number in their first eight bytes,
 * perf/stop ends a pong, and perf/thr carries the throughput samples.
 *
 * One boot runs one cell. The emulator's command line (semihosting SYS_GET_CMDLINE) names it:
 *
 *   mcu-speed <locator> put <size> <puts> 0 0
 *   mcu-speed <locator> sub <size> <window ms> <warm-up ms> 0
 *   mcu-speed <locator> rtt <size> <round trips> <warm-up round trips> <timeout ms>
 *
 * The figures are the kernel's: cycles of its cycle counter, the cycles every thread but the idle
 * thread ran (the network stack's threads and the library's tasks with the program's), and after the
 * workload every thread's stack high-water mark and the kernel heap's peak. The host turns cycles into
 * instructions and time with the emulator's settings, which this program does not know. Nothing is
 * printed while a cell is measured.
 */

#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <zephyr/arch/common/semihost.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/sys/sys_heap.h>

#include <zenoh-pico.h>

#if Z_FEATURE_PUBLICATION != 1 || Z_FEATURE_SUBSCRIPTION != 1 || Z_FEATURE_MATCHING != 1
#error "the speed program puts, subscribes and waits for a match: its image turns those switches on"
#endif

#define KEY_PING "perf/ping"
#define KEY_PONG "perf/pong"
#define KEY_STOP "perf/stop"
#define KEY_THR "perf/thr"
#define SEQ_BYTES 8
#define MAX_PAYLOAD 1024
#define MAX_ROUND_TRIPS 2000
#define OPEN_ATTEMPTS 30
#define MATCH_WAIT_MS 20000
#define FIRST_SAMPLE_WAIT_MS 30000
/* What the network stack's threads still have to send when a put loop ends is the loop's cost too. */
#define SETTLE_MS 200
#define CMDLINE_BYTES 192
#define ARGS 7

/* The kernel heap k_malloc serves, which both libraries allocate from. */
extern struct k_heap _system_heap;

static z_owned_session_t session;

static int fail(const char *why)
{
	printk("MCU-SPEED FAIL why=%s\n", why);
	return -1;
}

/* The arguments of the emulator's command line, split at spaces, in place. */
static char cmdline[CMDLINE_BYTES];

static int read_args(char **argv, int max)
{
	struct {
		char *buf;
		long len;
	} block = {cmdline, (long)sizeof(cmdline) - 1};

	if (semihost_exec(SEMIHOST_GET_CMDLINE, &block) != 0 || block.len < 0 ||
	    block.len >= (long)sizeof(cmdline)) {
		return -1;
	}
	cmdline[block.len] = '\0';
	int argc = 0;
	char *at = cmdline;

	while (*at != '\0') {
		while (*at == ' ') {
			*at++ = '\0';
		}
		if (*at == '\0') {
			break;
		}
		if (argc == max) {
			return -1;
		}
		argv[argc++] = at;
		while (*at != '\0' && *at != ' ') {
			at++;
		}
	}
	return argc;
}

/* The cycles every thread but the idle thread has run since boot. */
static uint64_t busy_cycles(void)
{
	k_thread_runtime_stats_t stats;

	if (k_thread_runtime_stats_all_get(&stats) != 0) {
		return 0;
	}
	return stats.total_cycles;
}

/* One step of a wait: the program steps the session in the single-threaded arm, and the session's
 * own tasks run while the program sleeps in the multi-threaded one.
 */
static void step(void)
{
#if Z_FEATURE_MULTI_THREAD == 1
	k_msleep(1);
#else
	(void)zp_spin_once(z_session_loan(&session));
#endif
}

static void wait_ms(uint32_t ms)
{
	const int64_t until = k_uptime_get() + ms;

	while (k_uptime_get() < until) {
		step();
	}
}

static int open_session(const char *locator)
{
	for (int attempt = 0; attempt < OPEN_ATTEMPTS; attempt++) {
		z_owned_config_t config;

		z_config_default(&config);
		zp_config_insert(z_config_loan_mut(&config), Z_CONFIG_MODE_KEY, "client");
		zp_config_insert(z_config_loan_mut(&config), Z_CONFIG_CONNECT_KEY, locator);
		if (z_open(&session, z_config_move(&config), NULL) == Z_OK) {
			return 0;
		}
		k_sleep(K_SECONDS(1));
	}
	return -1;
}

static int declare_publisher(z_owned_publisher_t *pub, const char *key)
{
	z_view_keyexpr_t ke;
	z_publisher_options_t options;

	if (z_view_keyexpr_from_str(&ke, key) != Z_OK) {
		return -1;
	}
	z_publisher_options_default(&options);
	options.congestion_control = Z_CONGESTION_CONTROL_BLOCK;
	return z_declare_publisher(z_session_loan(&session), pub, z_view_keyexpr_loan(&ke), &options) ==
			       Z_OK
		       ? 0
		       : -1;
}

static void drop_nothing(void *context)
{
	(void)context;
}

static int declare_subscriber(const char *key, void (*callback)(z_loaned_sample_t *, void *))
{
	z_view_keyexpr_t ke;
	z_owned_closure_sample_t closure;

	if (z_view_keyexpr_from_str(&ke, key) != Z_OK) {
		return -1;
	}
	z_closure_sample(&closure, callback, drop_nothing, NULL);
	return z_declare_background_subscriber(z_session_loan(&session), z_view_keyexpr_loan(&ke),
					       z_closure_sample_move(&closure), NULL) == Z_OK
		       ? 0
		       : -1;
}

/* A zenoh-pico publisher that knows of no subscriber returns success for a put it does not send, so
 * no put is counted before the host's subscriber is matched.
 */
static int wait_for_match(const z_loaned_publisher_t *pub)
{
	const int64_t until = k_uptime_get() + MATCH_WAIT_MS;

	while (k_uptime_get() < until) {
		z_matching_status_t status;

		if (z_publisher_get_matching_status(pub, &status) == Z_OK && status.matching) {
			return 0;
		}
		step();
	}
	return -1;
}

static uint8_t buf[MAX_PAYLOAD];

/* ---- put: the program puts, the host's subscriber counts ---------------------------------------- */

static int run_put(uint32_t size, uint32_t count)
{
	z_owned_publisher_t pub;
	z_owned_bytes_t payload;

	if (declare_publisher(&pub, KEY_THR) != 0) {
		return fail("publisher");
	}
	const z_loaned_publisher_t *loaned = z_publisher_loan(&pub);

	if (wait_for_match(loaned) != 0) {
		return fail("no_subscriber_matched");
	}
	memset(buf, 1, size);
	if (z_bytes_copy_from_buf(&payload, buf, size) != Z_OK) {
		return fail("payload");
	}
	printk("MCU-SPEED READY workload=put size=%u\n", size);

	uint32_t sent = 0;
	uint32_t failed = 0;
	const uint64_t busy0 = busy_cycles();
	const uint32_t t0 = k_cycle_get_32();

	for (uint32_t i = 0; i < count; i++) {
		z_owned_bytes_t copy;

		z_bytes_clone(&copy, z_bytes_loan(&payload));
		if (z_publisher_put(loaned, z_bytes_move(&copy), NULL) == Z_OK) {
			sent++;
		} else {
			failed++;
		}
	}
	const uint32_t loop = k_cycle_get_32() - t0;

	k_msleep(SETTLE_MS);
	const uint64_t busy = busy_cycles() - busy0;

	printk("MCU-SPEED RESULT workload=put size=%u sent=%u failed=%u loop_cycles=%u busy_cycles=%llu "
	       "hz=%u\n",
	       size, sent, failed, loop, (unsigned long long)busy, (uint32_t)sys_clock_hw_cycles_per_sec());
	z_bytes_drop(z_bytes_move(&payload));
	return 0;
}

/* ---- sub: the host's publisher puts, the program counts ----------------------------------------- */

static atomic_uint thr_count;
static atomic_uint thr_bytes;

static void on_thr(z_loaned_sample_t *sample, void *context)
{
	(void)context;
	atomic_fetch_add_explicit(&thr_bytes, (unsigned int)z_bytes_len(z_sample_payload(sample)),
				  memory_order_relaxed);
	atomic_fetch_add_explicit(&thr_count, 1U, memory_order_relaxed);
}

static int run_sub(uint32_t size, uint32_t window_ms, uint32_t warm_ms)
{
	if (declare_subscriber(KEY_THR, on_thr) != 0) {
		return fail("subscriber");
	}
	printk("MCU-SPEED READY workload=sub size=%u\n", size);

	const int64_t until = k_uptime_get() + FIRST_SAMPLE_WAIT_MS;

	while (atomic_load(&thr_count) == 0U) {
		if (k_uptime_get() >= until) {
			return fail("no_sample_arrived");
		}
		step();
	}
	wait_ms(warm_ms);

	const unsigned int n0 = atomic_load(&thr_count);
	const unsigned int b0 = atomic_load(&thr_bytes);
	const uint64_t busy0 = busy_cycles();
	const uint32_t t0 = k_cycle_get_32();

	wait_ms(window_ms);

	const uint32_t window = k_cycle_get_32() - t0;
	const uint64_t busy = busy_cycles() - busy0;
	const unsigned int n1 = atomic_load(&thr_count);
	const unsigned int b1 = atomic_load(&thr_bytes);

	/* total says whether a window that took nothing followed a warm-up that did. */
	printk("MCU-SPEED RESULT workload=sub size=%u received=%u bytes=%u window_cycles=%u "
	       "busy_cycles=%llu hz=%u total=%u\n",
	       size, n1 - n0, b1 - b0, window, (unsigned long long)busy,
	       (uint32_t)sys_clock_hw_cycles_per_sec(), n1);
	return 0;
}

/* ---- rtt: the program pings, the host's pong answers -------------------------------------------- */

static atomic_uint last_answer;
static K_SEM_DEFINE(answered, 0, 1);
static uint32_t rtt_cycles[MAX_ROUND_TRIPS];

static void on_pong(z_loaned_sample_t *sample, void *context)
{
	uint8_t head[SEQ_BYTES] = {0};
	uint32_t seq;

	(void)context;
	z_bytes_reader_t reader = z_bytes_get_reader(z_sample_payload(sample));

	(void)z_bytes_reader_read(&reader, head, sizeof(head));
	/* The low word of the probe's little-endian sequence number: a run has far fewer round trips. */
	memcpy(&seq, head, sizeof(seq));
	atomic_store(&last_answer, seq);
	k_sem_give(&answered);
}

/* One round trip of the sequence number, in cycles, or 0 when no answer came within the timeout. */
static uint32_t round_trip(const z_loaned_publisher_t *pub, uint32_t size, uint32_t seq,
			   uint32_t timeout_ms)
{
	const uint64_t wide = seq;
	z_owned_bytes_t payload;

	memcpy(buf, &wide, sizeof(wide));
	if (z_bytes_copy_from_buf(&payload, buf, size) != Z_OK) {
		return 0;
	}
	k_sem_reset(&answered);
	const uint32_t t0 = k_cycle_get_32();

	if (z_publisher_put(pub, z_bytes_move(&payload), NULL) != Z_OK) {
		return 0;
	}
	const int64_t until = k_uptime_get() + timeout_ms;

	while (atomic_load(&last_answer) != seq) {
		if (k_uptime_get() >= until) {
			return 0;
		}
#if Z_FEATURE_MULTI_THREAD == 1
		(void)k_sem_take(&answered, K_MSEC(timeout_ms));
#else
		(void)zp_spin_once(z_session_loan(&session));
#endif
	}
	const uint32_t cycles = k_cycle_get_32() - t0;

	return cycles == 0U ? 1U : cycles;
}

static int compare_u32(const void *a, const void *b)
{
	const uint32_t x = *(const uint32_t *)a;
	const uint32_t y = *(const uint32_t *)b;

	return (x > y) - (x < y);
}

/* The nearest-rank percentile of n sorted values, as the host probe computes it. */
static uint32_t nearest_rank(const uint32_t *sorted, uint32_t n, uint32_t p)
{
	uint32_t rank = (uint32_t)(((uint64_t)p * n + 99U) / 100U);

	if (rank < 1U) {
		rank = 1U;
	}
	return sorted[rank - 1U];
}

static int run_rtt(uint32_t size, uint32_t count, uint32_t warm, uint32_t timeout_ms)
{
	z_owned_publisher_t ping;
	z_owned_publisher_t stop;

	if (count == 0U || count > MAX_ROUND_TRIPS) {
		return fail("round_trips_out_of_range");
	}
	/* The answers' subscriber first, so its declaration is on its way while the publisher is made. */
	if (declare_subscriber(KEY_PONG, on_pong) != 0) {
		return fail("subscriber");
	}
	if (declare_publisher(&ping, KEY_PING) != 0 || declare_publisher(&stop, KEY_STOP) != 0) {
		return fail("publisher");
	}
	const z_loaned_publisher_t *loaned = z_publisher_loan(&ping);

	if (wait_for_match(loaned) != 0) {
		return fail("no_subscriber_matched");
	}
	memset(buf, 1, size);
	printk("MCU-SPEED READY workload=rtt size=%u\n", size);

	uint32_t seq = 0;

	for (uint32_t i = 0; i < warm; i++) {
		(void)round_trip(loaned, size, ++seq, timeout_ms);
	}
	uint32_t counted = 0;
	uint32_t lost = 0;
	uint32_t attempts = 0;
	const uint64_t busy0 = busy_cycles();

	for (uint32_t i = 0; i < count; i++) {
		const uint32_t cycles = round_trip(loaned, size, ++seq, timeout_ms);

		attempts++;
		if (cycles > 0U) {
			rtt_cycles[counted++] = cycles;
		} else if (++lost > count / 10U) {
			break;
		}
	}
	const uint64_t busy = busy_cycles() - busy0;
	uint64_t sum = 0;

	if (counted == 0U) {
		return fail("no_round_trip_answered");
	}
	qsort(rtt_cycles, counted, sizeof(rtt_cycles[0]), compare_u32);
	for (uint32_t i = 0; i < counted; i++) {
		sum += rtt_cycles[i];
	}
	printk("MCU-SPEED RESULT workload=rtt size=%u round_trips=%u lost=%u attempts=%u p50_cycles=%u "
	       "p90_cycles=%u p99_cycles=%u min_cycles=%u max_cycles=%u mean_cycles=%u busy_cycles=%llu "
	       "hz=%u\n",
	       size, counted, lost, attempts, nearest_rank(rtt_cycles, counted, 50U),
	       nearest_rank(rtt_cycles, counted, 90U), nearest_rank(rtt_cycles, counted, 99U),
	       rtt_cycles[0], rtt_cycles[counted - 1U], (uint32_t)(sum / counted),
	       (unsigned long long)busy, (uint32_t)sys_clock_hw_cycles_per_sec());
	/* Three stops, apart: a datagram may be lost. */
	for (int i = 0; i < 3; i++) {
		z_owned_bytes_t payload;

		if (z_bytes_copy_from_buf(&payload, buf, SEQ_BYTES) == Z_OK) {
			(void)z_publisher_put(z_publisher_loan(&stop), z_bytes_move(&payload), NULL);
		}
		wait_ms(20);
	}
	return 0;
}

/* ---- memory ------------------------------------------------------------------------------------- */

static size_t stack_used_sum;

static void stack_of(const struct k_thread *thread, void *unused)
{
	size_t unused_bytes = 0;

	ARG_UNUSED(unused);
	if (k_thread_stack_space_get(thread, &unused_bytes) != 0) {
		return;
	}
	const size_t used = thread->stack_info.size - unused_bytes;
	const char *name = k_thread_name_get((k_tid_t)thread);

	stack_used_sum += used;
	printk("MCU-SPEED STACK thread=%s used=%u size=%u\n",
	       (name != NULL && name[0] != '\0') ? name : "unnamed", (unsigned int)used,
	       (unsigned int)thread->stack_info.size);
}

static void report_memory(void)
{
	struct sys_memory_stats stats = {0};

	stack_used_sum = 0;
	k_thread_foreach_unlocked(stack_of, NULL);
	(void)sys_heap_runtime_stats_get(&_system_heap.heap, &stats);
	printk("MCU-SPEED MEMORY stack_used=%u heap_peak=%u heap_size=%u\n", (unsigned int)stack_used_sum,
	       (unsigned int)stats.max_allocated_bytes,
	       (unsigned int)(stats.allocated_bytes + stats.free_bytes));
}

static int number(const char *text, uint32_t *out)
{
	char *end = NULL;
	const unsigned long value = strtoul(text, &end, 10);

	if (end == text || *end != '\0' || value > UINT32_MAX) {
		return -1;
	}
	*out = (uint32_t)value;
	return 0;
}

int main(void)
{
	char *argv[ARGS];
	uint32_t size;
	uint32_t count;
	uint32_t warm;
	uint32_t timeout_ms;

	printk("MCU-SPEED BOOT arm=%s threads=%s\n", MCU_SPEED_ARM_W ? "W" : "P",
	       Z_FEATURE_MULTI_THREAD == 1 ? "mt" : "st");
	if (read_args(argv, ARGS) != ARGS || number(argv[3], &size) != 0 ||
	    number(argv[4], &count) != 0 || number(argv[5], &warm) != 0 ||
	    number(argv[6], &timeout_ms) != 0) {
		return fail("usage");
	}
	if (size < SEQ_BYTES || size > MAX_PAYLOAD) {
		return fail("size_out_of_range");
	}
	if (open_session(argv[1]) != 0) {
		return fail("open");
	}

	int rc;

	if (strcmp(argv[2], "put") == 0) {
		rc = run_put(size, count);
	} else if (strcmp(argv[2], "sub") == 0) {
		rc = run_sub(size, count, warm);
	} else if (strcmp(argv[2], "rtt") == 0) {
		rc = run_rtt(size, count, warm, timeout_ms);
	} else {
		rc = fail("workload");
	}
	if (rc == 0) {
		report_memory();
		printk("MCU-SPEED DONE\n");
	}
	return 0;
}
