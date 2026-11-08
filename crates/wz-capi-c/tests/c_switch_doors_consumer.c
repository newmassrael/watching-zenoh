/* SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * The statements of a call beyond the zenoh-c options, made from a REAL C
 * translation unit: the three statement structs, their _default functions and
 * the seven wz_capi_c_*_ext doors, compiled against wz_capi_c.h and linked
 * against the library as a consumer's program is.
 *
 * What the Rust tests of the same doors cannot show, and this can: that the
 * header compiles as C, that every symbol exports under the name it declares,
 * that the structs agree in layout on both sides of the boundary (the offsets
 * are written out here and not taken from the library), and that the code a
 * refusal answers is the one the header defines.
 *
 * The doors are called on a session that is not there (a NULL handle), which
 * each of them answers the way its z_* twin does, so the consumer needs no
 * peer and no network. What it cannot know is the build's policy: a stated
 * value is refused with WZ_CAPI_C_E_POLICY_OFF while its policy is off, and a
 * build that states the policy on takes it past the policy and meets the NULL
 * handle (Z_ENULL). Either is right, and Z_OK, a call that went through a
 * session it never had, is not.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "wz_capi_c.h"

static int failures = 0;

#define CHECK(cond, ...)                                                      \
    do {                                                                      \
        if (!(cond)) {                                                        \
            fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);             \
            fprintf(stderr, __VA_ARGS__);                                     \
            fprintf(stderr, "\n");                                            \
            failures++;                                                       \
        }                                                                     \
    } while (0)

/* A stated value is refused by the policy, or taken past it to the missing
 * handle; never carried out. */
#define STATED(rc) ((rc) == WZ_CAPI_C_E_POLICY_OFF || (rc) == Z_ENULL)

static void check_layout(void) {
    CHECK(sizeof(wz_capi_c_entity_ext_t) == 8, "entity ext size");
    CHECK(offsetof(wz_capi_c_entity_ext_t, link_mask) == 0, "entity link_mask");

    CHECK(sizeof(wz_capi_c_publish_ext_t) == 24, "publish ext size");
    CHECK(offsetof(wz_capi_c_publish_ext_t, link_mask) == 0, "publish link_mask");
    CHECK(offsetof(wz_capi_c_publish_ext_t, attempts) == 8, "publish attempts");
    CHECK(offsetof(wz_capi_c_publish_ext_t, delay_ms) == 12, "publish delay_ms");
    CHECK(offsetof(wz_capi_c_publish_ext_t, all_or_none) == 16, "publish all_or_none");

    /* z_id_t is sixteen bytes at alignment one, so the target follows the
     * flag at once and the struct is padded to its eight-byte member. */
    CHECK(sizeof(z_id_t) == 16, "z_id_t size");
    CHECK(sizeof(wz_capi_c_query_ext_t) == 32, "query ext size");
    CHECK(offsetof(wz_capi_c_query_ext_t, link_mask) == 0, "query link_mask");
    CHECK(offsetof(wz_capi_c_query_ext_t, has_target) == 8, "query has_target");
    CHECK(offsetof(wz_capi_c_query_ext_t, target) == 9, "query target");
}

static void check_codes(void) {
    /* The code is outside zenoh-c's own range and is not any of them. */
    CHECK(WZ_CAPI_C_E_POLICY_OFF == -102, "policy-off code %d", WZ_CAPI_C_E_POLICY_OFF);
    CHECK(WZ_CAPI_C_E_POLICY_OFF != WZ_CAPI_C_E_VALUE_TOO_LARGE, "collides with too-large");
    CHECK(WZ_CAPI_C_E_POLICY_OFF != WZ_CAPI_C_E_FULL, "collides with full");
}

static void check_defaults(void) {
    wz_capi_c_entity_ext_t entity;
    memset(&entity, 0xa5, sizeof entity);
    wz_capi_c_entity_ext_default(&entity);
    CHECK(entity.link_mask == 0, "entity default link_mask");

    wz_capi_c_publish_ext_t publish;
    memset(&publish, 0xa5, sizeof publish);
    wz_capi_c_publish_ext_default(&publish);
    CHECK(publish.link_mask == 0, "publish default link_mask");
    CHECK(publish.attempts == 0, "publish default attempts");
    CHECK(publish.delay_ms == 0, "publish default delay_ms");
    CHECK(publish.all_or_none == 0, "publish default all_or_none");

    wz_capi_c_query_ext_t query;
    memset(&query, 0xa5, sizeof query);
    wz_capi_c_query_ext_default(&query);
    CHECK(query.link_mask == 0, "query default link_mask");
    CHECK(query.has_target == 0, "query default has_target");
    uint8_t zero[16];
    memset(zero, 0, sizeof zero);
    CHECK(memcmp(query.target.id, zero, sizeof zero) == 0, "query default target");

    /* NULL is no write and no fault. */
    wz_capi_c_entity_ext_default(NULL);
    wz_capi_c_publish_ext_default(NULL);
    wz_capi_c_query_ext_default(NULL);
}

static void check_publish_doors(void) {
    wz_capi_c_publish_ext_t none;
    wz_capi_c_publish_ext_default(&none);

    /* Nothing stated: what z_put and z_delete answer for a handle that is not
     * there, whether the pointer is NULL or the default. */
    CHECK(wz_capi_c_put_ext(NULL, NULL, NULL, NULL, NULL) == Z_ENULL, "put, NULL ext");
    CHECK(wz_capi_c_put_ext(NULL, NULL, NULL, NULL, &none) == Z_ENULL, "put, default ext");
    CHECK(wz_capi_c_delete_ext(NULL, NULL, NULL, NULL) == Z_ENULL, "delete, NULL ext");
    CHECK(wz_capi_c_delete_ext(NULL, NULL, NULL, &none) == Z_ENULL, "delete, default ext");

    z_owned_publisher_t publisher;
    memset(&publisher, 0xa5, sizeof publisher);
    CHECK(wz_capi_c_declare_publisher_ext(NULL, &publisher, NULL, NULL, NULL) == Z_ENULL,
          "declare publisher, NULL ext");
    CHECK(!z_internal_publisher_check(&publisher), "a publisher left behind");

    /* Each statement on its own. */
    wz_capi_c_publish_ext_t links = none;
    links.link_mask = 0x6;
    wz_capi_c_publish_ext_t retry = none;
    retry.attempts = 3;
    retry.delay_ms = 20;
    wz_capi_c_publish_ext_t atomic = none;
    atomic.all_or_none = 1;
    const wz_capi_c_publish_ext_t *stated[] = {&links, &retry, &atomic};
    for (size_t i = 0; i < sizeof stated / sizeof stated[0]; i++) {
        z_result_t rc = wz_capi_c_put_ext(NULL, NULL, NULL, NULL, stated[i]);
        CHECK(STATED(rc), "put, statement %zu answered %d", i, rc);
        rc = wz_capi_c_delete_ext(NULL, NULL, NULL, stated[i]);
        CHECK(STATED(rc), "delete, statement %zu answered %d", i, rc);
        memset(&publisher, 0xa5, sizeof publisher);
        rc = wz_capi_c_declare_publisher_ext(NULL, &publisher, NULL, NULL, stated[i]);
        CHECK(STATED(rc), "declare publisher, statement %zu answered %d", i, rc);
        CHECK(!z_internal_publisher_check(&publisher), "a publisher left behind by a refusal");
    }

    /* A retry that is no retry is Z_EINVAL, whatever the build's policy: no
     * pass is zero attempts beside a delay, and more than 255 passes does not
     * fit what a retry holds. */
    wz_capi_c_publish_ext_t no_pass = none;
    no_pass.delay_ms = 5;
    wz_capi_c_publish_ext_t too_many = none;
    too_many.attempts = 256;
    too_many.delay_ms = 1;
    CHECK(wz_capi_c_put_ext(NULL, NULL, NULL, NULL, &too_many) == Z_EINVAL,
          "256 passes is no retry");
    {
        z_result_t rc = wz_capi_c_put_ext(NULL, NULL, NULL, NULL, &no_pass);
        CHECK(rc == Z_EINVAL || rc == WZ_CAPI_C_E_POLICY_OFF, "a delay with no pass answered %d", rc);
    }
}

static void check_query_doors(void) {
    wz_capi_c_query_ext_t none;
    wz_capi_c_query_ext_default(&none);

    z_moved_closure_reply_t reply;
    memset(&reply, 0, sizeof reply);
    CHECK(wz_capi_c_get_ext(NULL, NULL, NULL, &reply, NULL, NULL) == Z_ENULL, "get, NULL ext");
    CHECK(wz_capi_c_get_ext(NULL, NULL, NULL, &reply, NULL, &none) == Z_ENULL, "get, default ext");

    z_owned_querier_t querier;
    memset(&querier, 0xa5, sizeof querier);
    CHECK(wz_capi_c_declare_querier_ext(NULL, &querier, NULL, NULL, NULL) == Z_ENULL,
          "declare querier, NULL ext");
    CHECK(!z_internal_querier_check(&querier), "a querier left behind");

    wz_capi_c_query_ext_t links = none;
    links.link_mask = 0x1;
    wz_capi_c_query_ext_t target = none;
    target.has_target = 1;
    target.target.id[0] = 0xc7;
    target.target.id[1] = 0xd1;
    const wz_capi_c_query_ext_t *stated[] = {&links, &target};
    for (size_t i = 0; i < sizeof stated / sizeof stated[0]; i++) {
        z_result_t rc = wz_capi_c_get_ext(NULL, NULL, NULL, &reply, NULL, stated[i]);
        CHECK(STATED(rc), "get, statement %zu answered %d", i, rc);
        memset(&querier, 0xa5, sizeof querier);
        rc = wz_capi_c_declare_querier_ext(NULL, &querier, NULL, NULL, stated[i]);
        CHECK(STATED(rc), "declare querier, statement %zu answered %d", i, rc);
        CHECK(!z_internal_querier_check(&querier), "a querier left behind by a refusal");
    }

    /* A target that is not read: its bytes are nothing while has_target is 0. */
    wz_capi_c_query_ext_t unread = none;
    unread.target.id[0] = 0xc7;
    CHECK(wz_capi_c_get_ext(NULL, NULL, NULL, &reply, NULL, &unread) == Z_ENULL,
          "an unread target was read");
}

static void check_entity_doors(void) {
    wz_capi_c_entity_ext_t none;
    wz_capi_c_entity_ext_default(&none);
    wz_capi_c_entity_ext_t links;
    links.link_mask = 0x6;

    z_moved_closure_sample_t sample;
    memset(&sample, 0, sizeof sample);
    z_owned_subscriber_t subscriber;
    memset(&subscriber, 0xa5, sizeof subscriber);
    CHECK(wz_capi_c_declare_subscriber_ext(NULL, &subscriber, NULL, &sample, NULL, NULL) == Z_ENULL,
          "declare subscriber, NULL ext");
    CHECK(wz_capi_c_declare_subscriber_ext(NULL, &subscriber, NULL, &sample, NULL, &none) == Z_ENULL,
          "declare subscriber, default ext");
    memset(&subscriber, 0xa5, sizeof subscriber);
    z_result_t rc = wz_capi_c_declare_subscriber_ext(NULL, &subscriber, NULL, &sample, NULL, &links);
    CHECK(STATED(rc), "declare subscriber, links answered %d", rc);
    CHECK(!z_internal_subscriber_check(&subscriber), "a subscriber left behind by a refusal");

    z_moved_closure_query_t query;
    memset(&query, 0, sizeof query);
    z_owned_queryable_t queryable;
    memset(&queryable, 0xa5, sizeof queryable);
    CHECK(wz_capi_c_declare_queryable_ext(NULL, &queryable, NULL, &query, NULL, NULL) == Z_ENULL,
          "declare queryable, NULL ext");
    CHECK(wz_capi_c_declare_queryable_ext(NULL, &queryable, NULL, &query, NULL, &none) == Z_ENULL,
          "declare queryable, default ext");
    memset(&queryable, 0xa5, sizeof queryable);
    rc = wz_capi_c_declare_queryable_ext(NULL, &queryable, NULL, &query, NULL, &links);
    CHECK(STATED(rc), "declare queryable, links answered %d", rc);
    CHECK(!z_internal_queryable_check(&queryable), "a queryable left behind by a refusal");
}

int main(void) {
    CHECK(wz_capi_c_abi_version() == WZ_CAPI_C_ABI_REVISION,
          "the library reports revision %d, the header is %d", (int)wz_capi_c_abi_version(),
          WZ_CAPI_C_ABI_REVISION);
    check_layout();
    check_codes();
    check_defaults();
    check_publish_doors();
    check_query_doors();
    check_entity_doors();
    if (failures != 0) {
        fprintf(stderr, "switch_doors: %d failure(s)\n", failures);
        return 1;
    }
    printf("switch_doors: ok\n");
    return 0;
}
