/* SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * zenoh-pico on the T2G kit: a client of the bench host's router that answers the two GETs the
 * wz admin node answers, with the same keys' shape, the same JSON bodies and the same encoding,
 * so that a GET through the router costs the same bytes whichever of the two sits behind it.
 *
 * The queryables print nothing: a console line on a 115200 baud UART is a hundred times the
 * time of the answer, and the answer is what is measured. The count of GETs answered is
 * printed from the main thread, every ten seconds, and only when it has moved.
 */

#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>

#include <zenoh-pico.h>

/* The identifier the admin node's keys carry, a fixed twelve hex digits, as the node's own are:
 * the keys are as long, and so is every message that names one.
 */
#define NODE_ID "5a1c0ffee001"
#define STATUS_KEY "@/" NODE_ID "/peer/status/connect"
#define CONFIG_KEY "@/" NODE_ID "/peer/config"

/* The bodies the admin node replies with on the same two paths, verbatim. */
static const char STATUS_BODY[] = "{\"endpoints\":[],\"last_write\":null,\"permissions\":{\"write\":true}}";
static const char CONFIG_BODY[] = "{\"adminspace\":{\"permissions\":{\"write\":true}},\"connect\":{\"endpoints\":[]}}";

static atomic_uint answered;

static void query_handler(z_loaned_query_t *query, void *ctx)
{
	const char *body = ctx;
	z_owned_bytes_t payload;
	z_owned_encoding_t encoding;
	z_query_reply_options_t options;

	z_bytes_from_static_str(&payload, body);
	z_query_reply_options_default(&options);
	z_encoding_clone(&encoding, z_encoding_application_json());
	options.encoding = z_move(encoding);
	z_query_reply(query, z_query_keyexpr(query), z_move(payload), &options);
	atomic_fetch_add(&answered, 1);
}

static int declare(const z_loaned_session_t *session, z_owned_queryable_t *queryable,
		   const char *key, const char *body)
{
	z_owned_closure_query_t callback;
	z_view_keyexpr_t keyexpr;

	z_closure(&callback, query_handler, NULL, (void *)body);
	if (z_view_keyexpr_from_str(&keyexpr, key) < 0) {
		return -1;
	}
	return z_declare_queryable(session, queryable, z_loan(keyexpr), z_move(callback), NULL);
}

int main(void)
{
	z_owned_session_t session;

	printk("zephyr-pico-compare: boot ok\n");

	/* The interface has no carrier until the MAC is up and the PHY says so, and no address
	 * until the stack is: try until the router answers.
	 */
	for (unsigned int attempt = 1;; attempt++) {
		z_owned_config_t config;

		z_config_default(&config);
		zp_config_insert(z_loan_mut(config), Z_CONFIG_MODE_KEY, "client");
		zp_config_insert(z_loan_mut(config), Z_CONFIG_CONNECT_KEY, CONFIG_PICO_COMPARE_LOCATOR);
		z_result_t rc = z_open(&session, z_move(config), NULL);

		if (rc >= 0) {
			break;
		}
		/* Before the first query, so the line costs nothing that is measured. */
		printk("zephyr-pico-compare: z_open to %s failed (%d), attempt %u\n",
		       CONFIG_PICO_COMPARE_LOCATOR, (int)rc, attempt);
		k_sleep(K_SECONDS(1));
	}

	z_owned_queryable_t status_queryable;
	z_owned_queryable_t config_queryable;

	if (declare(z_loan(session), &status_queryable, STATUS_KEY, STATUS_BODY) < 0 ||
	    declare(z_loan(session), &config_queryable, CONFIG_KEY, CONFIG_BODY) < 0) {
		printk("ZEPHYR-PICO FAIL the queryables were not declared\n");
		return 0;
	}
	printk("ZEPHYR-PICO READY %s %s\n", NODE_ID, CONFIG_PICO_COMPARE_LOCATOR);

	unsigned int reported = 0;

	for (;;) {
		k_sleep(K_SECONDS(10));
		unsigned int now = atomic_load(&answered);

		if (now != reported) {
			reported = now;
			printk("zephyr-pico-compare: %u GET(s) answered\n", now);
		}
	}
	return 0;
}
