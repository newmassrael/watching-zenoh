/* SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * Where the time of one query goes between the wire and the wire, with the same instrument for
 * every application: the cycle counter read at four places of a query's round trip through the
 * node, and the four gaps told on the console every few hundred queries.
 *
 *   rx   the driver's receive thread has the frame and is about to hand it to the stack
 *   in   the application's recvfrom returned that datagram (the stack's receive path, the
 *        socket's queue and the thread wake-up are between rx and in)
 *   out  the application calls sendto with its reply (the application's own work is between
 *        in and out)
 *   tx   the driver's send has the reply frame and is about to put it on the wire (the stack's
 *        send path is between out and tx)
 *
 * The application is not changed: `recvfrom` and `sendto` are wrapped at link time
 * (`-Wl,--wrap`, zeth.cmake), so a wz node and a zenoh-pico application are measured by the same
 * four stamps. A frame that is not a query (a keep-alive, an ARP) does not complete the
 * sequence and is not counted. CONFIG_WZ_ZETH_STAMPS only; never in a build whose time is
 * being measured by anything else, since a console line is a write to a UART.
 */

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>

struct sockaddr;
typedef unsigned int socklen_t_;

ssize_t __real_recvfrom(int fd, void *buf, size_t len, int flags, struct sockaddr *from,
			socklen_t_ *fromlen);
ssize_t __real_sendto(int fd, const void *buf, size_t len, int flags, const struct sockaddr *to,
		      socklen_t_ tolen);

/* One query in flight. 0 is "not stamped yet" (the counter reads 0 once in 12 s at 350 MHz,
 * which a sample in thousands will not meet; a sample that did is one query uncounted).
 */
static volatile uint32_t t_rx, t_in, t_out;

/* The totals of the queries completed since the last line. */
static uint64_t sum_rx_in, sum_in_out, sum_out_tx, sum_total;
static uint32_t max_in_out;
static uint32_t completed;

#define REPORT_EVERY 500

/* The mean of `n` gaps whose cycle counts add to `sum`, in hundredths of a microsecond. */
static uint32_t centi_us(uint64_t sum, uint32_t hz, uint32_t n)
{
	return (uint32_t)(sum * 100000000ull / hz / n);
}

static void report_buckets(uint32_t n, uint32_t hz);
static void trace_print(void);
static void prof_print(void);

void wz_zeth_stamp_rx(void)
{
	t_rx = k_cycle_get_32() | 1u;
	t_in = 0;
	t_out = 0;
}

void wz_zeth_stamp_tx(void)
{
	uint32_t tx = k_cycle_get_32();
	uint32_t rx = t_rx, in = t_in, out = t_out;

	if (rx == 0 || in == 0 || out == 0) {
		return;
	}
	t_rx = 0;
	t_in = 0;
	t_out = 0;
	prof_print();
	trace_print();
	sum_rx_in += (uint32_t)(in - rx);
	sum_in_out += (uint32_t)(out - in);
	sum_out_tx += (uint32_t)(tx - out);
	sum_total += (uint32_t)(tx - rx);
	if ((uint32_t)(out - in) > max_in_out) {
		max_in_out = (uint32_t)(out - in);
	}
	if (++completed == REPORT_EVERY) {
		uint32_t hz = sys_clock_hw_cycles_per_sec();
		uint32_t n = completed;

		uint32_t a = centi_us(sum_rx_in, hz, n);
		uint32_t b = centi_us(sum_in_out, hz, n);
		uint32_t c = centi_us(sum_out_tx, hz, n);
		uint32_t d = centi_us(sum_total, hz, n);

		printk("wz: stamps: %u queries, mean us: rx->in %u.%02u, in->out %u.%02u "
		       "(max %u), out->tx %u.%02u, rx->tx %u.%02u\n",
		       n, a / 100, a % 100, b / 100, b % 100,
		       (unsigned int)(max_in_out * 1000000ull / hz), c / 100, c % 100,
		       d / 100, d % 100);
		report_buckets(n, hz);
		sum_rx_in = sum_in_out = sum_out_tx = sum_total = 0;
		max_in_out = 0;
		completed = 0;
	}
}

/* What the application does between its recvfrom and its sendto, counted at the calls the whole
 * image makes (wrapped at link time like recvfrom and sendto): the time spent waiting (poll and
 * the sleeps), the heap's calls and the time in them, and the copies. Only calls that START
 * inside the window are counted. Per query the figures are the totals divided by the queries
 * the line is of.
 */
struct bucket {
	uint64_t calls;
	uint64_t cycles;
	uint64_t bytes;
};
static struct bucket b_poll, b_sleep, b_malloc, b_free, b_memcpy;

static inline bool in_window(void)
{
	return t_in != 0 && t_out == 0;
}

/* A profile of the application's part of a query, taken by the firmware itself: the kernel's
 * tick interrupt (every 100 us, with CONFIG_TICKLESS_KERNEL=n) records the program counter it
 * interrupted when, and only when, the application's thread is between its recvfrom and its
 * sendto. The gate and the sample are one instruction stream apart, which an external probe
 * reading the two over SWD cannot say (its reads are not simultaneous, and a profile gated that
 * way was wrong). The samples are printed once, when the buffer is full, and resolved on the
 * host against the image's symbols.
 */
#define PROF_MAX 6000
static uint32_t prof_pc[PROF_MAX];
static uint32_t prof_n;
static volatile bool prof_full;
static bool prof_printed;
static k_tid_t app_thread;

#include <zephyr/spinlock.h>

void __real_sys_clock_announce_locked(int32_t ticks, k_spinlock_key_t key);

/* The kernel's tick interrupt calls this (Zephyr 4.4: the driver's ISR calls
 * `sys_clock_announce_locked`, not `sys_clock_announce`, which is only a wrapper of it).
 */
/* How far a tick gets through the sampler's conditions, so a profile that comes back empty says
 * which condition stopped it.
 */
static uint32_t prof_ticks, prof_in_window, prof_on_app, prof_in_code;

void __wrap_sys_clock_announce_locked(int32_t ticks, k_spinlock_key_t key)
{
	prof_ticks++;
	if (in_window() && prof_n < PROF_MAX) {
		prof_in_window++;
		if (app_thread != NULL && k_current_get() == app_thread) {
			uint32_t psp;

			prof_on_app++;
			__asm volatile("mrs %0, psp" : "=r"(psp));
			/* The frame the hardware pushed for the interrupted thread: r0-r3, r12, lr, pc. */
			uint32_t pc = ((uint32_t *)psp)[6];

			if (pc >= 0x10080000u && pc < 0x10100000u) {
				prof_in_code++;
				prof_pc[prof_n++] = pc;
				if (prof_n == PROF_MAX) {
					prof_full = true;
				}
			}
		}
	}
	__real_sys_clock_announce_locked(ticks, key);
}

static void prof_print(void)
{
	if (!prof_full || prof_printed) {
		return;
	}
	prof_printed = true;
	printk("wz: pcs %u samples\n", prof_n);
	for (uint32_t i = 0; i < prof_n; i += 12) {
		printk("wz: pcs");
		for (uint32_t j = i; j < i + 12 && j < prof_n; j++) {
			printk(" %x", prof_pc[j]);
		}
		printk("\n");
	}
	printk("wz: pcs done\n");
}

static void print_bucket(const char *name, struct bucket *b, uint32_t n, uint32_t hz,
			 bool bytes)
{
	/* Per query: the calls (tenths) and the microseconds (hundredths) they took. */
	uint32_t calls10 = (uint32_t)(b->calls * 10 / n);
	uint32_t us100 = (uint32_t)(b->cycles * 100000000ull / hz / n);

	printk("wz: stamps:   %-6s %u.%u calls, %u.%02u us per query", name, calls10 / 10,
	       calls10 % 10, us100 / 100, us100 % 100);
	if (bytes) {
		printk(", %u bytes", (unsigned int)(b->bytes / n));
	}
	printk("\n");
	b->calls = b->cycles = b->bytes = 0;
}

/* The copies of 128 bytes or more that the window makes, by the address that called the copy and
 * the length: which sites copy, how much, and how often per query. The caller's address is
 * resolved against the image on the host (addr2line), so the instrument names no function.
 */
#define COPY_SITES 64
static struct {
	uint32_t lr;
	uint32_t len;
	uint32_t count;
} copy_sites[COPY_SITES];

static void note_copy(uint32_t lr, size_t len)
{
	if (len < 128) {
		return;
	}
	for (unsigned int i = 0; i < COPY_SITES; i++) {
		if (copy_sites[i].count != 0 && copy_sites[i].lr == lr && copy_sites[i].len == len) {
			copy_sites[i].count++;
			return;
		}
	}
	for (unsigned int i = 0; i < COPY_SITES; i++) {
		if (copy_sites[i].count == 0) {
			copy_sites[i].lr = lr;
			copy_sites[i].len = (uint32_t)len;
			copy_sites[i].count = 1;
			return;
		}
	}
}

static void print_copy_sites(uint32_t n)
{
	for (unsigned int i = 0; i < COPY_SITES; i++) {
		if (copy_sites[i].count != 0) {
			printk("wz: copysite %x %u %u\n", copy_sites[i].lr, copy_sites[i].len,
			       (unsigned int)(copy_sites[i].count * 100 / n));
			copy_sites[i].count = 0;
		}
	}
}

static void report_buckets(uint32_t n, uint32_t hz)
{
	printk("wz: stamps:   sampler ticks %u, in window %u, on the app thread %u, in code %u\n",
	       prof_ticks, prof_in_window, prof_on_app, prof_in_code);
	print_bucket("poll", &b_poll, n, hz, false);
	print_bucket("sleep", &b_sleep, n, hz, false);
	print_bucket("malloc", &b_malloc, n, hz, true);
	print_bucket("free", &b_free, n, hz, false);
	print_bucket("memcpy", &b_memcpy, n, hz, true);
	print_copy_sites(n);
}

struct pollfd;

int __real_poll(struct pollfd *fds, unsigned int nfds, int timeout);
void *__real_k_malloc(size_t size);
void __real_k_free(void *ptr);
void *__real_memcpy(void *dst, const void *src, size_t len);
int32_t __real_z_impl_k_sleep(k_timeout_t timeout);
int32_t __real_z_impl_k_usleep(int32_t us);

int __wrap_poll(struct pollfd *fds, unsigned int nfds, int timeout)
{
	if (!in_window()) {
		return __real_poll(fds, nfds, timeout);
	}
	uint32_t t0 = k_cycle_get_32();
	int rc = __real_poll(fds, nfds, timeout);

	b_poll.calls++;
	b_poll.cycles += (uint32_t)(k_cycle_get_32() - t0);
	return rc;
}

int32_t __wrap_z_impl_k_sleep(k_timeout_t timeout)
{
	if (!in_window()) {
		return __real_z_impl_k_sleep(timeout);
	}
	uint32_t t0 = k_cycle_get_32();
	int32_t rc = __real_z_impl_k_sleep(timeout);

	b_sleep.calls++;
	b_sleep.cycles += (uint32_t)(k_cycle_get_32() - t0);
	return rc;
}

int32_t __wrap_z_impl_k_usleep(int32_t us)
{
	if (!in_window()) {
		return __real_z_impl_k_usleep(us);
	}
	uint32_t t0 = k_cycle_get_32();
	int32_t rc = __real_z_impl_k_usleep(us);

	b_sleep.calls++;
	b_sleep.cycles += (uint32_t)(k_cycle_get_32() - t0);
	return rc;
}

/* One query's allocations told in full, once, to find where they come from: the size and the
 * return addresses (Thumb code addresses) found on the stack above the call, which the host
 * resolves against the image's symbols. The query is the 300th after the line counter last
 * restarted, so the heap and the caches are warm; it is slowed by the console writes, which is
 * why its time is not counted in the means (the window is closed while it prints).
 */
#define TRACE_AT 300
#define TRACE_MAX 48
static struct {
	uint32_t size;
	/* Cycles since the application's recvfrom returned: where in the query's turnaround the
	 * allocation happened.
	 */
	uint32_t at;
	uint32_t chain[10];
} trace[TRACE_MAX];
static uint32_t trace_n;
static bool trace_printed;

static void trace_alloc(size_t size)
{
	if (completed != TRACE_AT || trace_printed || trace_n >= TRACE_MAX) {
		return;
	}
	uintptr_t *sp = (uintptr_t *)__builtin_frame_address(0);
	uint32_t found = 0;

	trace[trace_n].size = (uint32_t)size;
	trace[trace_n].at = (uint32_t)(k_cycle_get_32() - t_in);
	for (uint32_t i = 0; i < 160 && found < 10; i++) {
		uintptr_t v = sp[i];

		if ((v & 1u) && v >= 0x10080000u && v < 0x10100000u) {
			trace[trace_n].chain[found++] = (uint32_t)v;
		}
	}
	for (; found < 10; found++) {
		trace[trace_n].chain[found] = 0;
	}
	trace_n++;
}

static void trace_print(void)
{
	if (completed != TRACE_AT || trace_printed || trace_n == 0) {
		return;
	}
	trace_printed = true;
	for (uint32_t i = 0; i < trace_n; i++) {
		/* Microseconds since the recvfrom, in tenths. */
		uint32_t tenths = (uint32_t)((uint64_t)trace[i].at * 10000000ull /
					     sys_clock_hw_cycles_per_sec());

		printk("wz: alloc %u @%u:", trace[i].size, tenths);
		for (uint32_t c = 0; c < 10 && trace[i].chain[c] != 0; c++) {
			printk(" %x", trace[i].chain[c]);
		}
		printk("\n");
	}
}

void *__wrap_k_malloc(size_t size)
{
	if (!in_window()) {
		return __real_k_malloc(size);
	}
	trace_alloc(size);
	uint32_t t0 = k_cycle_get_32();
	void *p = __real_k_malloc(size);

	b_malloc.calls++;
	b_malloc.bytes += size;
	b_malloc.cycles += (uint32_t)(k_cycle_get_32() - t0);
	return p;
}

void __wrap_k_free(void *ptr)
{
	if (!in_window()) {
		__real_k_free(ptr);
		return;
	}
	uint32_t t0 = k_cycle_get_32();

	__real_k_free(ptr);
	b_free.calls++;
	b_free.cycles += (uint32_t)(k_cycle_get_32() - t0);
}

void *__wrap_memcpy(void *dst, const void *src, size_t len)
{
	if (!in_window()) {
		return __real_memcpy(dst, src, len);
	}
	note_copy((uint32_t)(uintptr_t)__builtin_return_address(0), len);
	uint32_t t0 = k_cycle_get_32();
	void *rc = __real_memcpy(dst, src, len);

	b_memcpy.calls++;
	b_memcpy.bytes += len;
	b_memcpy.cycles += (uint32_t)(k_cycle_get_32() - t0);
	return rc;
}

/* Rust code (and the compiler's own struct moves) call the ARM EABI entry points, not `memcpy`, so
 * the wrap above never sees them: a wz node showed 0.0 copies per query while a quarter of its
 * time was in the copy function. Counted into the same bucket, so the figure is every copy.
 */
void __real___aeabi_memcpy(void *dst, const void *src, size_t len);
void __real___aeabi_memcpy4(void *dst, const void *src, size_t len);
void __real___aeabi_memcpy8(void *dst, const void *src, size_t len);

#define WZ_STAMPS_EABI_COPY(name)                                                                  \
	void __wrap_##name(void *dst, const void *src, size_t len)                                 \
	{                                                                                          \
		if (!in_window()) {                                                                \
			__real_##name(dst, src, len);                                              \
			return;                                                                    \
		}                                                                                  \
		note_copy((uint32_t)(uintptr_t)__builtin_return_address(0), len);                  \
		uint32_t t0 = k_cycle_get_32();                                                    \
                                                                                                   \
		__real_##name(dst, src, len);                                                      \
		b_memcpy.calls++;                                                                  \
		b_memcpy.bytes += len;                                                             \
		b_memcpy.cycles += (uint32_t)(k_cycle_get_32() - t0);                              \
	}

WZ_STAMPS_EABI_COPY(__aeabi_memcpy)
WZ_STAMPS_EABI_COPY(__aeabi_memcpy4)
WZ_STAMPS_EABI_COPY(__aeabi_memcpy8)

ssize_t __wrap_recvfrom(int fd, void *buf, size_t len, int flags, struct sockaddr *from,
			socklen_t_ *fromlen)
{
	ssize_t got = __real_recvfrom(fd, buf, len, flags, from, fromlen);

	if (got > 0 && t_rx != 0) {
		t_in = k_cycle_get_32() | 1u;
		/* The thread that reads the queries is the one the sampler follows. */
		app_thread = k_current_get();
	}
	return got;
}

ssize_t __wrap_sendto(int fd, const void *buf, size_t len, int flags, const struct sockaddr *to,
		      socklen_t_ tolen)
{
	if (t_in != 0 && t_out == 0) {
		t_out = k_cycle_get_32() | 1u;
	}
	return __real_sendto(fd, buf, len, flags, to, tolen);
}
