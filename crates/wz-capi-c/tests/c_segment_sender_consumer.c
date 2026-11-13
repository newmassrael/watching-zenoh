/* SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * The sender of a declared segment profile, driven from a REAL C translation
 * unit: the wz_capi_c_segment_* doors compiled against wz_capi_c.h and linked
 * against the library, as a consumer's program is.
 *
 * What the Rust test of the same doors (tests/it/files/segment_sender_roundtrip.rs)
 * cannot show, and this can: that the header compiles as C, that the symbols
 * export under the names it declares, that the handle, the result struct and
 * the callback type agree on both sides of the boundary, and that a string the
 * library wrote is released by the consumer's own z_string_drop.
 *
 * The expected pieces are written out byte by byte here, not taken from the
 * library: a made-up profile with no CRC, so every byte of every piece is
 * readable off the profile (a fixed mark, a big-endian two-byte field the
 * caller states, a one-byte transfer number, little-endian two-byte size and
 * offset, then the chunk).
 */

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

static const char PROFILE[] =
    "{\"name\":\"plain\",\"segments\":{\"fields\":["
    "{\"name\":\"mark\",\"bytes\":1,\"equals\":\"0x7E\"},"
    "{\"name\":\"tag\",\"bytes\":2},"
    "{\"name\":\"n\",\"bytes\":1},"
    "{\"name\":\"size\",\"bytes\":2,\"order\":\"little\"},"
    "{\"name\":\"at\",\"bytes\":2,\"order\":\"little\"}],"
    "\"transfer\":\"n\",\"total\":\"size\",\"offset\":\"at\",\"total_max\":1000}}";

static const char VALUES[] = "{\"tag\":\"0xBEEF\"}";

/* "abcdefg" in chunks of 3, transfer 5. */
static const uint8_t PIECE0[] = {0x7E, 0xBE, 0xEF, 5, 7, 0, 0, 0, 'a', 'b', 'c'};
static const uint8_t PIECE1[] = {0x7E, 0xBE, 0xEF, 5, 7, 0, 3, 0, 'd', 'e', 'f'};
static const uint8_t PIECE2[] = {0x7E, 0xBE, 0xEF, 5, 7, 0, 6, 0, 'g'};

/* The library's string, copied into `dst` (NUL-terminated, truncated) and then
 * released by THIS program's z_string_drop. Returns the full length. */
static size_t take(z_owned_string_t *s, char *dst, size_t cap) {
    const z_loaned_string_t *loaned = z_string_loan(s);
    size_t len = z_string_len(loaned);
    const char *data = z_string_data(loaned);
    size_t n = len < cap - 1 ? len : cap - 1;
    if (n > 0) {
        memcpy(dst, data, n);
    }
    dst[n] = '\0';
    z_string_drop(z_string_move(s));
    return len;
}

struct collected {
    uint8_t bytes[3][16];
    size_t len[3];
    size_t count;
    size_t stop_at;
};

static z_result_t collect(void *context, const uint8_t *piece, size_t len) {
    struct collected *c = (struct collected *)context;
    if (c->count == c->stop_at) {
        return -77;
    }
    if (c->count < 3 && len <= sizeof c->bytes[0]) {
        memcpy(c->bytes[c->count], piece, len);
        c->len[c->count] = len;
    }
    c->count++;
    return Z_OK;
}

static int same(const struct collected *c, size_t i, const uint8_t *want, size_t want_len) {
    return c->len[i] == want_len && memcmp(c->bytes[i], want, want_len) == 0;
}

int main(void) {
    char why[256];
    z_owned_string_t refusal;

    /* A values text that leaves the caller's field out is refused with the place. */
    wz_capi_c_owned_segment_sender_t refused;
    z_result_t rc = wz_capi_c_segment_sender_new(&refused, PROFILE, "{}", 5,
                                                 WZ_CAPI_C_SEGMENT_ROLLOVER_REFUSE, &refusal);
    take(&refusal, why, sizeof why);
    CHECK(rc == Z_EPARSE, "a values text without `tag` is Z_EPARSE, got %d", rc);
    CHECK(strncmp(why, "values /tag", 11) == 0, "the refusal names the place: %s", why);
    CHECK(!wz_capi_c_internal_segment_sender_check(&refused), "a refused sender is a gravestone");

    wz_capi_c_owned_segment_sender_t sender;
    rc = wz_capi_c_segment_sender_new(&sender, PROFILE, VALUES, 5,
                                      WZ_CAPI_C_SEGMENT_ROLLOVER_RESTART, &refusal);
    take(&refusal, why, sizeof why);
    CHECK(rc == Z_OK, "a sender is made: %s", why);
    CHECK(wz_capi_c_internal_segment_sender_check(&sender), "the slot holds a sender");
    const wz_capi_c_loaned_segment_sender_t *loaned = wz_capi_c_segment_sender_loan(&sender);

    /* Three pieces, each byte as the profile says. */
    struct collected c = {.count = 0, .stop_at = 99};
    wz_capi_c_segment_result_t result;
    const uint8_t message[] = {'a', 'b', 'c', 'd', 'e', 'f', 'g'};
    rc = wz_capi_c_segment_sender_split(loaned, message, sizeof message, 3, collect, &c,
                                        &result, &refusal);
    take(&refusal, why, sizeof why);
    CHECK(rc == Z_OK, "the split went through: %s", why);
    CHECK(result.transfer == 5 && result.pieces == 3 && result.sent == 3,
          "result %llu/%zu/%zu", (unsigned long long)result.transfer, result.pieces, result.sent);
    CHECK(c.count == 3, "three pieces, got %zu", c.count);
    CHECK(same(&c, 0, PIECE0, sizeof PIECE0), "piece 0");
    CHECK(same(&c, 1, PIECE1, sizeof PIECE1), "piece 1");
    CHECK(same(&c, 2, PIECE2, sizeof PIECE2), "piece 2");

    uint64_t next = 0;
    CHECK(wz_capi_c_segment_sender_next(loaned, &next) && next == 6, "next is 6, got %llu",
          (unsigned long long)next);

    /* A refused message uses no number. */
    rc = wz_capi_c_segment_sender_split(loaned, NULL, 0, 3, collect, &c, &result, &refusal);
    take(&refusal, why, sizeof why);
    CHECK(rc == Z_EINVAL && strstr(why, "empty") != NULL, "an empty message: %d %s", rc, why);
    CHECK(wz_capi_c_segment_sender_next(loaned, &next) && next == 6, "still 6");

    /* A callback that stops the split has used the number; its code comes back. */
    struct collected stop = {.count = 0, .stop_at = 1};
    rc = wz_capi_c_segment_sender_split(loaned, message, sizeof message, 3, collect, &stop,
                                        &result, &refusal);
    take(&refusal, why, sizeof why);
    CHECK(rc == -77, "the callback's code comes back, got %d", rc);
    CHECK(result.transfer == 6 && result.pieces == 3 && result.sent == 1, "stopped after one");
    CHECK(wz_capi_c_segment_sender_next(loaned, &next) && next == 7, "the number is used");

    /* The largest number, then back to the first: a restarting sender. */
    CHECK(wz_capi_c_segment_sender_set(loaned, 255) == Z_OK, "set");
    struct collected last = {.count = 0, .stop_at = 99};
    rc = wz_capi_c_segment_sender_split(loaned, message, 1, 3, collect, &last, &result, NULL);
    CHECK(rc == Z_OK && result.transfer == 255, "the largest number is sent");
    CHECK(wz_capi_c_segment_sender_next(loaned, &next) && next == 5, "back to the first, 5");

    wz_capi_c_segment_put_options_t options;
    wz_capi_c_segment_put_options_default(&options);
    CHECK(options.timestamp == NULL, "the default stamps nothing");
    CHECK(wz_capi_c_segment_sender_put(loaned, NULL, message, sizeof message, 3, &options,
                                       NULL, NULL) == Z_ENULL,
          "a null publisher is Z_ENULL");

    wz_capi_c_segment_sender_drop((wz_capi_c_moved_segment_sender_t *)&sender);
    CHECK(!wz_capi_c_internal_segment_sender_check(&sender), "dropped");
    wz_capi_c_segment_sender_drop((wz_capi_c_moved_segment_sender_t *)&sender);
    CHECK(!wz_capi_c_segment_sender_next(NULL, &next), "next(NULL) is false");

    if (failures != 0) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("c_segment_sender_consumer: ok\n");
    return 0;
}
