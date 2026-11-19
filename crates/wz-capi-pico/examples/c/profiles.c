/*
 * SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * Pub/sub and query/queryable under the policy profile the library was built with.
 *
 * Two sessions over the host's loopback (tcp/): the listening one declares a subscriber and
 * a queryable, the dialling one publishes and asks. The publisher and the queryable both
 * hand over a timestamp of their own (z_timestamp_new), which makes one policy visible to
 * the program: entity-timestamp-opt-in. Under the upstream profile (the policy off, upstream's
 * behaviour) the subscriber and the querier see the timestamp they are sent. Under the
 * profile with the policy on, an entity takes part in timestamps only when its declaration
 * says so, and a pico declaration has no such option, so neither sees one.
 *
 * The profile is chosen when the library is BUILT, through the policy's build default:
 *
 *     WZ_POLICY_ENTITY_TIMESTAMP_OPT_IN=on bash scripts/pico-c-program.sh \
 *         crates/wz-capi-pico/examples/c/profiles.c "..."
 *
 * The program reads the same variable to know which answer to expect, so one source serves
 * both builds. A run-time choice of profile through a config document is a door of the
 * runtime-configuration work; this example does not depend on it.
 */

#define EXAMPLE_NAME "example-profiles"

#include <zenoh-pico.h>

#include "example_common.h"

#define DATA_KEY "example/profiles/data"
#define ASK_KEY "example/profiles/ask"

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

int main(void) {
    const char *stated = getenv("WZ_POLICY_ENTITY_TIMESTAMP_OPT_IN");
    int opt_in = stated != NULL && strcmp(stated, "on") == 0;
    printf("%s: the build's profile: entity-timestamp-opt-in %s\n", EXAMPLE_NAME, opt_in ? "on" : "off (upstream)");

    ex_counter_init(&heard.samples);
    ex_counter_init(&asked.replies);
    char locator[64];
    snprintf(locator, sizeof locator, "tcp/127.0.0.1:%u", ex_port());

    z_result_t rc = ex_open_listener(&listener_session, locator);
    CHECK(rc == Z_OK, "the listener did not open on %s (rc %d)", locator, (int)rc);
    if (rc != Z_OK) return ex_finish();

    z_owned_closure_sample_t sample_closure;
    z_closure_sample(&sample_closure, on_sample, NULL, NULL);
    z_view_keyexpr_t sub_ke;
    z_view_keyexpr_from_str(&sub_ke, "example/profiles/**");
    z_owned_subscriber_t subscriber;
    CHECK(z_declare_subscriber(z_session_loan(&listener_session), &subscriber, z_view_keyexpr_loan(&sub_ke),
                               z_closure_sample_move(&sample_closure), NULL) == Z_OK,
          "z_declare_subscriber");
    z_owned_closure_query_t query_closure;
    z_closure_query(&query_closure, on_query, NULL, NULL);
    z_view_keyexpr_t qbl_ke;
    z_view_keyexpr_from_str(&qbl_ke, ASK_KEY);
    z_owned_queryable_t queryable;
    CHECK(z_declare_queryable(z_session_loan(&listener_session), &queryable, z_view_keyexpr_loan(&qbl_ke),
                              z_closure_query_move(&query_closure), NULL) == Z_OK,
          "z_declare_queryable");

    z_owned_session_t dialer;
    rc = ex_open_dialer(&dialer, locator);
    CHECK(rc == Z_OK, "the dialer did not open to %s (rc %d)", locator, (int)rc);
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
        CHECK(ex_counter_get(&heard.samples) > 0, "the subscriber was never handed a sample");
        if (opt_in) {
            CHECK(!heard.stamped, "under opt-in the subscriber, declared without opting in, saw a timestamp");
        } else {
            CHECK(heard.stamped, "under the upstream profile the subscriber did not see the put's timestamp");
        }

        CHECK(ask(z_session_loan(&dialer)), "no get was answered");
        CHECK(strcmp(asked.payload, "answered") == 0, "the reply was '%s'", asked.payload);
        if (opt_in) {
            CHECK(!asked.stamped, "under opt-in the querier saw the reply's timestamp");
        } else {
            CHECK(asked.stamped, "under the upstream profile the querier did not see the reply's timestamp");
        }
        ex_close(&dialer);
    }

    z_subscriber_drop(z_subscriber_move(&subscriber));
    z_queryable_drop(z_queryable_move(&queryable));
    ex_close(&listener_session);
    ex_counter_drop(&heard.samples);
    ex_counter_drop(&asked.replies);
    return ex_finish();
}
