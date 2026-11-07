/* SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * A node's lifecycle verbs from a client, driven from a REAL C translation
 * unit: wz_capi_c_lifecycle_key and wz_capi_c_lifecycle_read compiled against
 * wz_capi_c.h and linked against the library, as a consumer's program is.
 *
 * What the Rust tests of the same doors cannot show, and this can: that the
 * header compiles as C, that the symbols export under the names it declares,
 * and that the two structs agree in layout on both sides of the boundary. The
 * keys expected here are written out, as scripts/lib/verb_key_vectors.txt
 * writes them, and not taken from the library.
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

static void check_layouts(void) {
    /* Pointers, then a bool, a u64 and a pointer: the Rust struct is repr(C)
     * in the same order. */
    CHECK(offsetof(wz_capi_c_lifecycle_words_t, verb) == 0, "words.verb");
    CHECK(offsetof(wz_capi_c_lifecycle_words_t, has_generation) ==
              4 * sizeof(void *),
          "words.has_generation");
    CHECK(offsetof(wz_capi_c_lifecycle_words_t, generation) ==
              4 * sizeof(void *) + _Alignof(uint64_t),
          "words.generation");
    CHECK(offsetof(wz_capi_c_lifecycle_read_t, verdict) == sizeof(void *),
          "read.verdict");
    CHECK(sizeof(((wz_capi_c_lifecycle_read_t *)0)->zid) == 33, "read.zid");
}

static void check_keys(void) {
    char key[WZ_CAPI_C_LIFECYCLE_KEY_MAX];
    const char *why = "untouched";
    wz_capi_c_lifecycle_words_t close = {.verb = "close", .of = "a1b2",
                                         .about = "c3d4"};
    CHECK(wz_capi_c_lifecycle_key(&close, key, sizeof key, &why) == Z_OK &&
              why == NULL,
          "close made no key");
    CHECK(strcmp(key, "@/a1b2/client/session/close/c3d4") == 0, "close: %s", key);

    wz_capi_c_lifecycle_words_t reset = {.verb = "reset", .of = "a1b2",
                                         .about = "c3d4", .whatami = "router",
                                         .has_generation = true,
                                         .generation = 7};
    CHECK(wz_capi_c_lifecycle_key(&reset, key, sizeof key, &why) == Z_OK,
          "reset made no key");
    CHECK(strcmp(key, "@/a1b2/router/session/reset/7/c3d4") == 0, "reset: %s", key);

    wz_capi_c_lifecycle_words_t passive = {.verb = "open", .of = "a1b2",
                                           .about = "c3d4", .mode = "passive"};
    CHECK(wz_capi_c_lifecycle_key(&passive, key, sizeof key, &why) == Z_OK,
          "passive open made no key");
    CHECK(strcmp(key, "@/a1b2/client/session/open/passive/c3d4") == 0,
          "passive open: %s", key);

    reset.has_generation = false;
    CHECK(wz_capi_c_lifecycle_key(&reset, key, sizeof key, &why) == Z_EINVAL &&
              why != NULL && strcmp(why, "reset-takes-a-generation") == 0,
          "a reset with no generation was not refused with its word");
    CHECK(wz_capi_c_lifecycle_key(NULL, key, sizeof key, &why) == Z_ENULL,
          "a NULL words was not Z_ENULL");
}

static void check_reads(void) {
    wz_capi_c_lifecycle_read_t r;
    const char *closing = "{\"verdict\":\"closing\",\"links\":2}";
    CHECK(wz_capi_c_lifecycle_read((const uint8_t *)closing, strlen(closing), &r) == Z_OK,
          "read closing");
    CHECK(r.kind == WZ_CAPI_C_LIFECYCLE_VERDICT && strcmp(r.verdict, "closing") == 0 &&
              r.has_links && r.links == 2 && r.reason == NULL,
          "closing read as kind %d", (int)r.kind);

    const char *whoami = "{\"zid\":\"a1b2\"}";
    CHECK(wz_capi_c_lifecycle_read((const uint8_t *)whoami, strlen(whoami), &r) == Z_OK &&
              r.kind == WZ_CAPI_C_LIFECYCLE_WHOAMI && strcmp(r.zid, "a1b2") == 0,
          "whoami");

    const char *other = "{\"members\":[]}";
    CHECK(wz_capi_c_lifecycle_read((const uint8_t *)other, strlen(other), &r) == Z_OK &&
              r.kind == WZ_CAPI_C_LIFECYCLE_UNREADABLE && r.verdict == NULL,
          "another document was not unreadable");
    CHECK(wz_capi_c_lifecycle_read(NULL, 0, &r) == Z_OK &&
              r.kind == WZ_CAPI_C_LIFECYCLE_UNREADABLE,
          "no bytes were not unreadable");
}

int main(void) {
    check_layouts();
    check_keys();
    check_reads();
    if (failures != 0) {
        fprintf(stderr, "c_lifecycle_consumer: %d failure(s)\n", failures);
        return 1;
    }
    printf("c_lifecycle_consumer: ok\n");
    return 0;
}
