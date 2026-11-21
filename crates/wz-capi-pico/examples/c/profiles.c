/*
 * SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * Pub/sub and query under a policy profile chosen when each session opens.
 *
 * Two sessions over the host's loopback (tcp/): the listening one declares a subscriber and
 * a queryable, the dialling one publishes and asks. The publisher and the queryable both
 * hand over a timestamp of their own (z_timestamp_new), which makes one policy visible to
 * the program: entity-timestamp-opt-in. Under the upstream profile (the policy off, upstream's
 * behaviour) the subscriber and the querier see the timestamp they are sent. With the policy
 * on, an entity takes part in timestamps only when its declaration says so, and a pico
 * declaration has no such option, so neither sees one.
 *
 * The exchange runs three times in one process, against one library, each time with both
 * sessions opened afresh:
 *
 *   1. from configs that state nothing: the build's own defaults. The library's build states
 *      them (WZ_POLICY_ENTITY_TIMESTAMP_OPT_IN when it is built, off unless stated), and the
 *      program reads the same variable to know which answer to expect;
 *   2. from configs handed the document DOC_UPSTREAM (wz_ext_config_document), which names the
 *      upstream profile: the timestamps are seen whatever the build's default;
 *   3. from configs handed DOC_OPT_IN, the upstream profile with the policy stated on in the
 *      document's wz/policies: no timestamp is seen.
 *
 * The listener's config of each document round is also handed documents the library refuses
 * (REFUSED): a policy it does not have, a value the policy does not have, a profile it does not
 * have, text that is no JSON5 object. Each answers _Z_ERR_CONFIG_INVALID_VALUE and leaves the
 * config with the document it held, which the round's answer then shows.
 *
 * Built against the library with the config-document capability.
 */

#define EXAMPLE_NAME "example-profiles"

#include <zenoh-pico.h>

#include "wz_ext.h"

#include "example_common.h"

#define DATA_KEY "example/profiles/data"
#define ASK_KEY "example/profiles/ask"

/* Only the wz member of a document is read: the rest of a zenoh-c program's configuration may sit
 * beside it in the same document, and the mode and locators here are the config's own keys. */
#define DOC_UPSTREAM "{ wz: { profile: \"upstream\" } }"
#define DOC_OPT_IN "{ wz: { profile: \"upstream\", policies: { \"entity-timestamp-opt-in\": \"on\" } } }"

static const char *const REFUSED[] = {
    "{ wz: { policies: { \"no-such-policy\": \"on\" } } }",
    "{ wz: { policies: { \"entity-timestamp-opt-in\": \"sometimes\" } } }",
    "{ wz: { profile: \"no-such-profile\" } }",
    "{ wz: ",
};

static struct {
    ex_counter_t samples;
    volatile int stamped;
} heard;

static struct {
    ex_counter_t replies;
    volatile int done;
    volatile int stamped;
    char payload[64];
} asked;

static z_owned_session_t listener_session;

static void on_sample(z_loaned_sample_t *sample, void *arg) {
    (void)arg;
    char text[64];
    ex_payload_text(z_sample_payload(sample), text, sizeof text);
    if (strcmp(text, "stamped") != 0) return;
    heard.stamped = z_sample_timestamp(sample) != NULL;
    ex_counter_add(&heard.samples, 1);
}

static void on_query(z_loaned_query_t *query, void *arg) {
    (void)arg;
    z_timestamp_t ts;
    z_query_reply_options_t options;
    z_query_reply_options_default(&options);
    if (z_timestamp_new(&ts, z_session_loan(&listener_session)) == Z_OK) options.timestamp = &ts;
    z_owned_bytes_t payload;
    z_bytes_copy_from_str(&payload, "answered");
    z_query_reply(query, z_query_keyexpr(query), z_bytes_move(&payload), &options);
}

static void on_reply(z_loaned_reply_t *reply, void *arg) {
    (void)arg;
    if (!z_reply_is_ok(reply)) return;
    const z_loaned_sample_t *sample = z_reply_ok(reply);
    ex_payload_text(z_sample_payload(sample), asked.payload, sizeof asked.payload);
    asked.stamped = z_sample_timestamp(sample) != NULL;
    ex_counter_add(&asked.replies, 1);
}

static void on_reply_drop(void *arg) {
    (void)arg;
    asked.done = 1;
}

/* Ask until a get is answered or the bound runs out; whether one was. */
static int ask(const z_loaned_session_t *session) {
    for (int attempt = 0; attempt < 15; attempt++) {
        asked.done = 0;
        z_owned_closure_reply_t closure;
        z_closure_reply(&closure, on_reply, on_reply_drop, NULL);
        z_view_keyexpr_t ke;
        z_view_keyexpr_from_str(&ke, ASK_KEY);
        z_get_options_t options;
        z_get_options_default(&options);
        options.timeout_ms = 1000;
        if (z_get(session, z_view_keyexpr_loan(&ke), "", z_closure_reply_move(&closure), &options) != Z_OK) {
            return 0;
        }
        for (int i = 0; i < 500 && !asked.done; i++) z_sleep_ms(10);
        if (ex_counter_get(&asked.replies) > 0) return 1;
    }
    return 0;
}

/* A session that listens on `locator`, or dials it as a client (retried while the listener
 * binds), from a config handed `document` when it is not NULL. With `try_refused`, the config is
 * then handed each REFUSED text, each of which must be refused. */
static z_result_t open_session(z_owned_session_t *session, int dial, const char *locator, const char *document,
                               int try_refused) {
    z_result_t rc = -1;
    for (int attempt = 0; attempt < (dial ? 100 : 1) && rc != Z_OK; attempt++) {
        z_owned_config_t config;
        z_config_default(&config);
        if (dial) {
            zp_config_insert(z_config_loan_mut(&config), Z_CONFIG_MODE_KEY, "client");
            zp_config_insert(z_config_loan_mut(&config), Z_CONFIG_CONNECT_KEY, locator);
        } else {
            zp_config_insert(z_config_loan_mut(&config), Z_CONFIG_LISTEN_KEY, locator);
        }
        if (document != NULL) {
            z_result_t stated = wz_ext_config_document(z_config_loan_mut(&config), document);
            if (stated != Z_OK) {
                z_config_drop(z_config_move(&config));
                return stated;
            }
            for (size_t i = 0; try_refused && i < sizeof REFUSED / sizeof REFUSED[0]; i++) {
                z_result_t refused = wz_ext_config_document(z_config_loan_mut(&config), REFUSED[i]);
                CHECK(refused == _Z_ERR_CONFIG_INVALID_VALUE, "the document %s was not refused (rc %d)", REFUSED[i],
                      (int)refused);
            }
        }
        rc = z_open(session, z_config_move(&config), NULL);
        if (rc != Z_OK && dial) z_sleep_ms(100);
    }
    return rc;
}

/* One exchange between two sessions opened from configs handed `document` (none when NULL),
 * checked against `opt_in`, whether the profile they open under has the policy on. */
static void run_round(const char *what, const char *document, int opt_in) {
    printf("%s: %s: entity-timestamp-opt-in %s\n", EXAMPLE_NAME, what, opt_in ? "on" : "off (upstream)");
    ex_counter_init(&heard.samples);
    ex_counter_init(&asked.replies);
    heard.stamped = 0;
    asked.done = 0;
    asked.stamped = 0;
    asked.payload[0] = '\0';
    char locator[64];
    snprintf(locator, sizeof locator, "tcp/127.0.0.1:%u", ex_port());

    z_result_t rc = open_session(&listener_session, 0, locator, document, document != NULL);
    CHECK(rc == Z_OK, "%s: the listener did not open on %s (rc %d)", what, locator, (int)rc);
    if (rc != Z_OK) {
        ex_counter_drop(&heard.samples);
        ex_counter_drop(&asked.replies);
        return;
    }

    z_owned_closure_sample_t sample_closure;
    z_closure_sample(&sample_closure, on_sample, NULL, NULL);
    z_view_keyexpr_t sub_ke;
    z_view_keyexpr_from_str(&sub_ke, "example/profiles/**");
    z_owned_subscriber_t subscriber;
    CHECK(z_declare_subscriber(z_session_loan(&listener_session), &subscriber, z_view_keyexpr_loan(&sub_ke),
                               z_closure_sample_move(&sample_closure), NULL) == Z_OK,
          "%s: z_declare_subscriber", what);
    z_owned_closure_query_t query_closure;
    z_closure_query(&query_closure, on_query, NULL, NULL);
    z_view_keyexpr_t qbl_ke;
    z_view_keyexpr_from_str(&qbl_ke, ASK_KEY);
    z_owned_queryable_t queryable;
    CHECK(z_declare_queryable(z_session_loan(&listener_session), &queryable, z_view_keyexpr_loan(&qbl_ke),
                              z_closure_query_move(&query_closure), NULL) == Z_OK,
          "%s: z_declare_queryable", what);

    z_owned_session_t dialer;
    rc = open_session(&dialer, 1, locator, document, 0);
    CHECK(rc == Z_OK, "%s: the dialer did not open to %s (rc %d)", what, locator, (int)rc);
    if (rc == Z_OK) {
        /* A put with a timestamp, repeated until the subscriber's declaration has reached
         * this side and one is heard. */
        for (int i = 0; i < 400 && ex_counter_get(&heard.samples) == 0; i++) {
            z_timestamp_t ts;
            z_put_options_t options;
            z_put_options_default(&options);
            if (z_timestamp_new(&ts, z_session_loan(&dialer)) == Z_OK) options.timestamp = &ts;
            ex_put(z_session_loan(&dialer), DATA_KEY, "stamped", &options);
            z_sleep_ms(25);
        }
        CHECK(ex_counter_get(&heard.samples) > 0, "%s: the subscriber was never handed a sample", what);
        if (opt_in) {
            CHECK(!heard.stamped, "%s: under opt-in the subscriber, declared without opting in, saw a timestamp",
                  what);
        } else {
            CHECK(heard.stamped, "%s: under the upstream profile the subscriber did not see the put's timestamp",
                  what);
        }

        CHECK(ask(z_session_loan(&dialer)), "%s: no get was answered", what);
        CHECK(strcmp(asked.payload, "answered") == 0, "%s: the reply was '%s'", what, asked.payload);
        if (opt_in) {
            CHECK(!asked.stamped, "%s: under opt-in the querier saw the reply's timestamp", what);
        } else {
            CHECK(asked.stamped, "%s: under the upstream profile the querier did not see the reply's timestamp",
                  what);
        }
        ex_close(&dialer);
    }

    z_subscriber_drop(z_subscriber_move(&subscriber));
    z_queryable_drop(z_queryable_move(&queryable));
    ex_close(&listener_session);
    ex_counter_drop(&heard.samples);
    ex_counter_drop(&asked.replies);
}

int main(void) {
    const char *stated = getenv("WZ_POLICY_ENTITY_TIMESTAMP_OPT_IN");
    int build_opt_in = stated != NULL && strcmp(stated, "on") == 0;

    run_round("the build's defaults, no document", NULL, build_opt_in);
    run_round("a document naming the upstream profile", DOC_UPSTREAM, 0);
    run_round("a document stating entity-timestamp-opt-in on", DOC_OPT_IN, 1);
    return ex_finish();
}
