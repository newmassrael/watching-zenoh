/* SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * The seams every wz Zephyr image reaches Zephyr and its board through.
 *
 * The Rust staticlib cannot call a variadic function (`printk`), a `static
 * inline` (`k_msleep`, `irq_lock`) or a `__syscall` wrapper directly, and a
 * board's random source, wall clock and network address are the board's to
 * answer. All of that lives HERE, once, instead of in each application's
 * `main.c`: an image differs from the next in its workload, not in how it
 * reads its clock. `wz_zephyr_board.cmake` adds this file to the `app` target.
 *
 * Every hook below is answered from Zephyr's own subsystems and the board's
 * Kconfig and devicetree. None is a constant of the firmware, because a
 * constant is right on one board and silently wrong on the next:
 *   - the random source is the board's entropy device, or, on a QEMU board only,
 *     Zephyr's test generator (see wzApplicationGetRandom);
 *   - the wall clock is set at boot from this build's own instant, standing in
 *     for the SNTP sync or RTC a board with network or battery would have;
 *   - the IPv4 address and the zenoh id come from the net stack's interface,
 *     whatever DHCP or Kconfig gave it.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <time.h>

#include <zephyr/kernel.h>
#include <zephyr/irq.h>
#include <zephyr/random/random.h>
#include <zephyr/sys/printk.h>

#if defined(CONFIG_NETWORKING)
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_ip.h>
#endif

#if defined(CONFIG_WZ_ENABLE_CORE_CACHES)
#include <stdbool.h>
#include <cmsis_core.h>
#include <zephyr/cache.h>
#include <zephyr/init.h>
#include <zephyr/linker/linker-defs.h>
#endif

/* ---- Rust -> Zephyr seams (non-variadic, non-inline link targets) ---- */

void wz_log(const char *msg)
{
	printk("%s\n", msg);
}

void wz_yield_ms(int ms)
{
	k_msleep(ms);
}

/* The same give-away of the CPU at the kernel's tick, for a board whose tick is finer
 * than a millisecond. The kernel rounds the sleep up to a whole tick. */
void wz_yield_us(int us)
{
	k_usleep(us);
}

#if defined(CONFIG_WZ_ENABLE_CORE_CACHES)

/* ---- the core's caches ----
 *
 * Zephyr's port of some SoCs leaves the Cortex-M7 caches off although CONFIG_ICACHE and
 * CONFIG_DCACHE are set: other SoC ports call sys_cache_*_enable() in their soc.c and this
 * one (Infineon CAT1C) does not. Read from the running T2G node, SCB->CCR had bits 17 and
 * 16 clear, and the 350 MHz core fetched every instruction from flash.
 *
 * The instruction cache is safe to enable. The data cache is safe only if no memory a bus
 * master reads or writes (the MAC's descriptor rings and buffer pools) is cacheable, and
 * that is a fact about the MPU's regions, not about a Kconfig symbol: so it is read here,
 * and the data cache stays off, with the reason on the console, when it does not hold. */

#if defined(CONFIG_NOCACHE_MEMORY) && defined(CONFIG_ARM_MPU)

/* Whether an ARMv7-M MPU region's TEX/C/B bits make its memory non-cacheable (Normal
 * non-cacheable, Device or Strongly-ordered). Anything this does not recognise as such is
 * reported cacheable. */
static bool wz_mpu_attr_noncacheable(uint32_t rasr)
{
	uint32_t tex = (rasr >> 19) & 0x7;
	uint32_t c = (rasr >> 17) & 0x1;
	uint32_t b = (rasr >> 16) & 0x1;

	if (tex == 0) {
		return c == 0;                  /* Strongly-ordered or shareable Device */
	}
	if (tex == 1 || tex == 2) {
		return c == 0 && b == 0;        /* Normal non-cacheable, non-shareable Device */
	}
	if (tex & 0x4) {
		/* Outer attribute TEX[1:0], inner attribute C:B, both 0 = non-cacheable. */
		return (tex & 0x3) == 0 && c == 0 && b == 0;
	}
	return false;
}

/* Check that every cache line of [start, end) lies in an enabled MPU region whose
 * attributes are non-cacheable, the highest-numbered region covering a line deciding as the
 * hardware does. On failure returns false with the address and the reason. */
static bool wz_range_noncacheable(uintptr_t start, uintptr_t end, uintptr_t *bad_at,
				  const char **why)
{
	uint32_t regions = (MPU->TYPE >> 8) & 0xFF;
	uint32_t rbar[32];
	uint32_t rasr[32];
	unsigned int key = irq_lock();

	if (regions > 32) {
		regions = 32;
	}
	for (uint32_t i = 0; i < regions; i++) {
		MPU->RNR = i;
		rbar[i] = MPU->RBAR;
		rasr[i] = MPU->RASR;
	}
	irq_unlock(key);

	if (!(MPU->CTRL & MPU_CTRL_ENABLE_Msk)) {
		*bad_at = start;
		*why = "the MPU is off, so the default map applies and SRAM is cacheable";
		return false;
	}
	for (uintptr_t a = start & ~(uintptr_t)31; a < end; a += 32) {
		int hit = -1;

		for (uint32_t i = 0; i < regions; i++) {
			uint32_t size_log;
			uint64_t size;
			uint64_t off;

			if (!(rasr[i] & 1)) {
				continue;
			}
			size_log = ((rasr[i] >> 1) & 0x1F) + 1;
			size = (uint64_t)1 << size_log;
			off = (uint64_t)a - (uint64_t)(rbar[i] & ~(uint32_t)0x1F);
			if (off >= size) {
				continue;
			}
			if (size_log >= 8 &&
			    ((rasr[i] >> 8) & (1u << (off >> (size_log - 3)))) != 0) {
				continue;       /* a disabled subregion */
			}
			hit = (int)i;
		}
		if (hit < 0) {
			*bad_at = a;
			*why = "no MPU region covers it, so the default map applies and SRAM is cacheable";
			return false;
		}
		if (!wz_mpu_attr_noncacheable(rasr[hit])) {
			*bad_at = a;
			*why = "the MPU region covering it is cacheable";
			return false;
		}
	}
	return true;
}

#endif /* CONFIG_NOCACHE_MEMORY && CONFIG_ARM_MPU */

static int wz_enable_core_caches(void)
{
	const char *data = "data OFF: this build has no non-cacheable section or no MPU";

#if defined(CONFIG_ICACHE) && !defined(CONFIG_WZ_ICACHE_OFF)
	sys_cache_instr_enable();
#endif
#if defined(CONFIG_DCACHE) && defined(CONFIG_NOCACHE_MEMORY) && defined(CONFIG_ARM_MPU)
	{
		uintptr_t start = (uintptr_t)_nocache_ram_start;
		uintptr_t end = start + (uintptr_t)_nocache_ram_size;
		uintptr_t bad = 0;
		const char *why = "";

		if (wz_range_noncacheable(start, end, &bad, &why)) {
			sys_cache_data_enable();
			printk("wz: caches: instruction on, data on; the non-cacheable section "
			       "0x%08x to 0x%08x is non-cacheable in the MPU\n",
			       (unsigned int)start, (unsigned int)end);
			return 0;
		}
		printk("wz: caches: instruction on, data OFF: 0x%08x of the non-cacheable "
		       "section: %s\n", (unsigned int)bad, why);
		return 0;
	}
#endif
	printk("wz: caches: instruction on, %s\n", data);
	return 0;
}

/* After the MPU's own initialisation, which is what makes the section non-cacheable. */
SYS_INIT(wz_enable_core_caches, PRE_KERNEL_2, 0);

#endif /* CONFIG_WZ_ENABLE_CORE_CACHES */

/* Wait about `us` microseconds. A wait the kernel can sleep through (a tick or
 * more) gives the CPU away; a shorter one is a busy wait, because a sleep would
 * round it up to a whole tick. Drivers that poll a peripheral answering in
 * microseconds (a PHY's management port) need both. */
void wz_delay_us(uint32_t us)
{
	if (us >= USEC_PER_MSEC) {
		k_msleep(us / USEC_PER_MSEC);
	} else if (us > 0) {
		k_busy_wait(us);
	}
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

/* The calling thread's stack: its size, and the bytes at its far end that were never
 * written. The kernel can say so only when it painted the stack at creation
 * (CONFIG_INIT_STACKS) and kept the stack's bounds (CONFIG_THREAD_STACK_INFO); a
 * kernel built without either answers nonzero, and the Rust side reports nothing,
 * which a lane that expects the measurement refuses. A stack that runs out does not
 * fault at its own end, it overwrites the memory below it, so this number is the
 * only warning an image gets. */
int wz_stack_usage(uint32_t *size, uint32_t *unused)
{
#if defined(CONFIG_INIT_STACKS) && defined(CONFIG_THREAD_STACK_INFO)
	size_t not_touched = 0;
	k_tid_t self = k_current_get();

	if (k_thread_stack_space_get(self, &not_touched) != 0) {
		return -1;
	}
	*size = (uint32_t)self->stack_info.size;
	*unused = (uint32_t)not_touched;
	return 0;
#else
	(void)size;
	(void)unused;
	return -1;
#endif
}

/* The clock the core really runs at, in hertz, or 0 when this board cannot tell.
 *
 * An image is built for one core clock (CONFIG_SYS_CLOCK_HW_CYCLES_PER_SEC) and the
 * kernel derives every tick and every busy wait from it without ever asking the
 * silicon. A board that can read the clock from its registers says so with
 * CONFIG_WZ_CORE_CLOCK_BOARD_HOOK and answers in `wz_board_core_clock_hz`; the image
 * compares the two before it waits for anything (wz_runtime_zephyr::core_clock). The
 * QEMU boards have no clock to read and answer 0, which the image takes as "not
 * checked", so their consoles are what they were. */
#if defined(CONFIG_WZ_CORE_CLOCK_BOARD_HOOK)
extern uint32_t wz_board_core_clock_hz(void);

uint32_t wz_core_clock_hz(void)
{
	return wz_board_core_clock_hz();
}
#else
uint32_t wz_core_clock_hz(void)
{
	return 0;
}
#endif

/* ---- the board's random source ----
 *
 * `wzApplicationGetRandom` is what `wz_runtime_zephyr::ZephyrEntropy` calls, and
 * the session draws its cookie nonces and its cookie-signing key through it.
 * Predictable values there are a vulnerability, not a test inconvenience, so
 * the source is chosen by what the build HAS and refused when it has nothing:
 *
 *   1. an entropy device (CONFIG_CSPRNG_ENABLED, set by any entropy driver that
 *      says it is a true source): the cryptographically secure generator,
 *      which reports failure rather than degrade;
 *   2. a board that carries its own TRNG outside Zephyr's driver model
 *      (CONFIG_WZ_ENTROPY_BOARD_HOOK): the board source answers
 *      `wz_board_entropy_fill`, which fails the same way;
 *   3. Zephyr's test generator, on a QEMU board only. It is predictable by
 *      construction and exercises the call without satisfying the contract; Zephyr
 *      itself allows it only for boards whose sole purpose is testing.
 *
 * Anything else does not compile. */
static uint32_t random_draws;

#if defined(CONFIG_CSPRNG_ENABLED)
int wzApplicationGetRandom(void *buf, size_t len)
{
	random_draws++;
	return sys_csrand_get(buf, len);
}
#elif defined(CONFIG_WZ_ENTROPY_BOARD_HOOK)
extern int wz_board_entropy_fill(void *buf, size_t len);

int wzApplicationGetRandom(void *buf, size_t len)
{
	random_draws++;
	return wz_board_entropy_fill(buf, len);
}
#elif defined(CONFIG_TEST_RANDOM_GENERATOR) && defined(CONFIG_QEMU_TARGET)
int wzApplicationGetRandom(void *buf, size_t len)
{
	sys_rand_get(buf, len); /* what zenoh-pico's Zephyr port calls */
	random_draws++;
	return 0;
}
#else
#error "this board has no entropy source the session may draw secrets from: " \
       "enable an entropy driver (CONFIG_ENTROPY_GENERATOR), or select " \
       "CONFIG_WZ_ENTROPY_BOARD_HOOK and supply wz_board_entropy_fill, " \
       "and never CONFIG_TEST_RANDOM_GENERATOR outside a QEMU board"
#endif

unsigned int wz_random_draws(void)
{
	return random_draws;
}

#if defined(CONFIG_WZ_NET_BACKEND_LWIP_MAC)
/* The two hooks lwIP's port for this image (deploy/zephyr-admin-node/lwip-port)
 * calls: `LWIP_RAND()`, from the board's random source rather than a constant (the
 * ephemeral UDP port a dialled session binds is drawn from it), and a failed
 * assertion, which says so on the console and then halts with the CPU yielded. */
uint32_t wz_lwip_rand(void)
{
	uint32_t value = 0;

	(void)wzApplicationGetRandom(&value, sizeof(value));
	return value;
}

void wz_lwip_assert(const char *what)
{
	printk("lwIP assertion failed: %s\n", what);
	for (;;) {
		k_msleep(1000);
	}
}
#endif

/* ---- the board's wall clock ---- */

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

/* Set the realtime clock once at boot, as an SNTP sync would, to the instant
 * this image was built (CMake passes it as WZ_BOARD_EPOCH_SECS). Returns 0 on
 * success. A board with an RTC or a time source replaces this call, not the
 * hook above or the profile code that reads it. */
int wz_board_set_boot_clock(void)
{
	struct timespec boot = {.tv_sec = WZ_BOARD_EPOCH_SECS, .tv_nsec = 0};

	return clock_settime(CLOCK_REALTIME, &boot);
}

#if defined(CONFIG_NETWORKING) && defined(CONFIG_NET_IPV4)

/* ---- the board's network identity, read off Zephyr's interface ---- */

/* The first interface that holds a preferred, non-link-local IPv4 address: the
 * one a node's sessions run on. NULL while none does (DHCP not yet granted). */
static struct net_if *addressed_interface(struct net_in_addr **address)
{
	STRUCT_SECTION_FOREACH(net_if, iface) {
		struct net_in_addr *found =
			net_if_ipv4_get_global_addr(iface, NET_ADDR_PREFERRED);

		if (found != NULL) {
			*address = found;
			return iface;
		}
	}
	return NULL;
}

/* `wz_runtime_zephyr::net::board_ipv4`: write the interface's four octets,
 * most significant first, and return 1; return 0 while it has no address. */
int wzApplicationGetIpv4Address(uint8_t *out)
{
	struct net_in_addr *address = NULL;

	if (addressed_interface(&address) == NULL) {
		return 0;
	}
	memcpy(out, address->s4_addr, 4);
	return 1;
}

/* The node's zenoh id: the link-layer address of the interface its sessions
 * run on, which is unique per NIC and stable across boots. Writes at most `cap`
 * bytes and returns how many (1..=16), or 0 when there is no interface address
 * to derive one from. */
size_t wzApplicationGetZid(uint8_t *out, size_t cap)
{
	struct net_in_addr *address = NULL;
	struct net_if *iface = addressed_interface(&address);
	struct net_linkaddr *link;
	size_t len;

	if (iface == NULL) {
		return 0;
	}
	link = net_if_get_link_addr(iface);
	len = link->len;
	if (len == 0 || len > cap || len > 16) {
		return 0;
	}
	memcpy(out, link->addr, len);
	return len;
}

#endif /* CONFIG_NETWORKING && CONFIG_NET_IPV4 */
