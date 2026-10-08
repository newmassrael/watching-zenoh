/* SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial */
/* SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael */

/*
 * The CM0+ core's image for a T2G chip that runs a wz image on its M7_0 core.
 *
 * On this chip only the CM0+ core starts by itself, and two things the M7_0 core
 * depends on are this core's to do:
 *
 *   - Bring the clock tree up. Zephyr's clock driver does it from the board's
 *     devicetree in a CM0+ build (CONFIG_CLOCK_CONTROL, before main() runs) and
 *     returns without touching it in an M7 build, which expects the tree to be up
 *     at the frequency its devicetree names. An M7 image started by a CM0+ image
 *     that left the tree alone ran at the oscillator's 8 MHz where it was built
 *     for 350 MHz, and its kernel clock ran 44 times slow.
 *   - Start the M7_0 core: point it at its vector table, give it clock and power,
 *     release it from wait.
 *
 * The start sequence follows the order of Infineon's reference function for it
 * (Cy_SysEnableCM7, in the Apache-2.0 device template, which Zephyr does not
 * build) and is written here against the same registers, not copied. Two things
 * differ on purpose. Every wait has a limit measured on the cycle counter, so a
 * core that does not answer is a message and not a hang; and the address of the
 * M7_0 image is not a number in this file: the board's memory partition names the
 * M7_0 flash, both cores' devicetrees include it, and the M7_0 image is linked at
 * the same node, so the two cannot disagree.
 *
 * This image prints NOTHING. The kit's console is SCB0 (the devicetree's uart0) and
 * the M7_0 image it starts owns it: two cores must not share one UART, and on the
 * first run, when both did, the M7 started while this core was still printing its
 * banner and the banner came out cut and garbled. prj.conf therefore turns the
 * console, printk and the serial driver off (the serial driver would configure SCB0
 * and its pins at boot whether or not anything printed). What this image has to
 * say it says in `wz_launcher_status`, a word in its RAM that a debugger reads:
 *
 *   0  running: the image has not reached a verdict (or never got to one)
 *   1  CM7_0 started
 *   2  no M7_0 image was found at the start of its flash partition
 *   3  CM7_0 did not take its power mode within the limit
 *
 * It is zero from reset because the image's RAM is zeroed before main() runs. Its
 * address is in the image's symbol table (`nm zephyr.elf`, name
 * `wz_launcher_status`) and in the linker map. The M7_0 image gives the evidence a
 * console can carry: once it runs it logs the core clock it measured
 * (`wz: core clock N Hz (the image assumes M Hz)`), which is the proof that the
 * clock tree this image brought up is the one the M7 was built for.
 *
 * Claim: this is BUILT. A bench kit has run it and the M7_0 image measured the clock
 * it was built for, but no ledger record exists, so the grade stays BUILT.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>

#include <zephyr/devicetree.h>
#include <zephyr/kernel.h>

#include <soc.h>

/* The launcher's one output, for a debugger. Not static and not in a header: the
 * name is the contract (see the codes in the comment above). */
#define WZ_LAUNCHER_RUNNING        0u
#define WZ_LAUNCHER_STARTED        1u
#define WZ_LAUNCHER_NO_IMAGE       2u
#define WZ_LAUNCHER_POWER_TIMEOUT  3u

volatile uint32_t wz_launcher_status = WZ_LAUNCHER_RUNNING;

/* Where the M7_0 image's vector table is: the start of its flash partition. */
#define CM7_0_VECTORS ((uint32_t)DT_REG_ADDR(DT_NODELABEL(flash_m7_0)))

/* CPUSS.CM7_0_PWR_CTL: the key that opens the power-mode field for writing, and
 * the two modes this sequence uses (3 enabled, 1 held in reset). */
#define PWR_KEY_OPEN    0x05FAu
#define PWR_MODE_RESET  1u
#define PWR_MODE_ENABLED 3u

/* How long a power-mode change may take before it is called failed. The change
 * is a few core clock cycles of handshake; this is generous by orders of
 * magnitude and still short enough that a dead core is noticed. */
#define PWR_DONE_LIMIT_US 10000u

static int wait_power_done(void)
{
	const uint32_t start = k_cycle_get_32();

	while ((CPUSS->CM7_0_STATUS & CPUSS_CM7_0_STATUS_PWR_DONE_Msk) == 0u) {
		if (k_cyc_to_us_floor32(k_cycle_get_32() - start) >= PWR_DONE_LIMIT_US) {
			return -ETIMEDOUT;
		}
	}
	return 0;
}

static int set_power_mode(uint32_t mode)
{
	uint32_t reg = CPUSS->CM7_0_PWR_CTL;

	reg &= ~(CPUSS_CM7_0_PWR_CTL_VECTKEYSTAT_Msk | CPUSS_CM7_0_PWR_CTL_PWR_MODE_Msk);
	reg |= (PWR_KEY_OPEN << CPUSS_CM7_0_PWR_CTL_VECTKEYSTAT_Pos) |
	       (mode << CPUSS_CM7_0_PWR_CTL_PWR_MODE_Pos);
	CPUSS->CM7_0_PWR_CTL = reg;
	return wait_power_done();
}

static int start_cm7_0(uint32_t vectors)
{
	const unsigned int key = irq_lock();
	int rc = 0;
	const uint32_t mode = (CPUSS->CM7_0_PWR_CTL & CPUSS_CM7_0_PWR_CTL_PWR_MODE_Msk) >>
			      CPUSS_CM7_0_PWR_CTL_PWR_MODE_Pos;

	/* A core that is already running (a debugger can have powered it up and held
	 * it) takes a new vector table only from reset. */
	if (mode == PWR_MODE_ENABLED) {
		rc = set_power_mode(PWR_MODE_RESET);
	}
	if (rc == 0) {
		/* CLK_HF1 is what clocks the M7 cores, and it is off until asked for. */
		SRSS->CLK_ROOT_SELECT[1] |= SRSS_CLK_ROOT_SELECT_ENABLE_Msk;
		CPUSS->CM7_0_VECTOR_TABLE_BASE = vectors;
		rc = set_power_mode(PWR_MODE_ENABLED);
	}
	if (rc == 0) {
		CPUSS->CM7_0_CTL &= ~(1u << CPUSS_CM7_0_CTL_CPU_WAIT_Pos);
	}
	irq_unlock(key);
	return rc;
}

/* An erased or unwritten flash reads as all ones (or zeros); a core pointed at it
 * would fault on its first fetch, with nothing to say so. The first two words of
 * a vector table are the initial stack pointer and the reset handler. */
static bool image_present(uint32_t vectors)
{
	const volatile uint32_t *table = (const volatile uint32_t *)vectors;
	const uint32_t sp = table[0];
	const uint32_t reset = table[1];

	return sp != 0u && sp != 0xFFFFFFFFu && reset != 0u && reset != 0xFFFFFFFFu;
}

int main(void)
{
	if (!image_present(CM7_0_VECTORS)) {
		/* Not started: a core pointed at erased flash faults on its first fetch. */
		wz_launcher_status = WZ_LAUNCHER_NO_IMAGE;
		return 0;
	}

	const int rc = start_cm7_0(CM7_0_VECTORS);

	if (rc != 0) {
		wz_launcher_status = WZ_LAUNCHER_POWER_TIMEOUT;
		return rc;
	}
	wz_launcher_status = WZ_LAUNCHER_STARTED;
	return 0;
}
