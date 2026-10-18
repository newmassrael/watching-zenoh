/* SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * The sender of an end-to-end protected message, driven from a REAL C
 * translation unit: the wz_capi_c_e2e_sender_* doors compiled against
 * wz_capi_c.h and linked against the library, as a consumer's program is.
 *
 * What the Rust test of the same doors (tests/e2e_sender_roundtrip.rs) cannot
 * show, and this can: that the header compiles as C, that the symbols export
 * under the names the header declares, that the handle and the string slots
 * agree in size and layout on both sides of the boundary, and that a string
 * written by the library is released by the consumer's own z_string_drop.
 *
 * The expected frames are NOT taken from the library. They were computed
 * independently (a bitwise CRC-32 with the profile's polynomial, checked
 * first against the standard check values 0xCBF43926 for CRC-32 and
 * 0x1697D06A for CRC-32/AUTOSAR), over the covered bytes the profile names in
 * its own order: length, payload, counter. A sender whose frame differed by a
 * byte would fail here rather than agree with itself.
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

/* A made-up profile with a ONE-byte counter, so its end is a few calls away. */
static const char PROFILE[] =
    "{\"name\":\"tiny\","
    "\"fields\":[{\"name\":\"crc\",\"bytes\":4},{\"name\":\"length\",\"bytes\":2},"
    "{\"name\":\"counter\",\"bytes\":1}],"
    "\"crc\":{\"field\":\"crc\",\"width\":32,\"poly\":\"0xF4ACFB13\","
    "\"init\":\"0xFFFFFFFF\",\"refin\":true,\"refout\":true,"
    "\"xorout\":\"0xFFFFFFFF\",\"cover\":[\"length\",\"@payload\",\"counter\"]},"
    "\"length\":{\"field\":\"length\",\"counts\":\"frame\"},"
    "\"counter\":{\"field\":\"counter\",\"max_gap\":10,\"timeout_ms\":1000}}";

/* Frames of payload "abc" at counters 40, 41, 42, 43, computed independently. */
static const char *const GOLDEN[] = {
    "ca14eb63000a28616263",
    "fa91e496000a29616263",
    "ab1ef489000a2a616263",
    "9b9bfb7c000a2b616263",
};

/* Frame of payload "abc" at counter 255 and at 0: the end of a one-byte
 * counter and what a chosen wrap counts on from. Computed the same way. */
static const char GOLDEN_255[] = "16cc75d1000aff616263";
static const char GOLDEN_0[] = "89daa948000a00616263";

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

/* The value of the "frame" member of an e2e_wrap document, or "" when absent. */
static void frame_of(const char *doc, char *dst, size_t cap) {
    const char *key = "\"frame\":\"";
    const char *at = strstr(doc, key);
    size_t i = 0;
    dst[0] = '\0';
    if (at == NULL) {
        return;
    }
    at += strlen(key);
    while (at[i] != '\0' && at[i] != '"' && i + 1 < cap) {
        dst[i] = at[i];
        i++;
    }
    dst[i] = '\0';
}

static wz_capi_c_owned_e2e_sender_t make(uint64_t first,
                                         wz_capi_c_e2e_rollover_t rollover) {
    wz_capi_c_owned_e2e_sender_t sender;
    z_owned_string_t refusal;
    char text[512];
    wz_capi_c_internal_e2e_sender_null(&sender);
    z_internal_string_null(&refusal);
    z_result_t rc =
        wz_capi_c_e2e_sender_new(&sender, PROFILE, first, rollover, &refusal);
    size_t len = take(&refusal, text, sizeof text);
    CHECK(rc == Z_OK, "sender_new returned %d: %s", (int)rc, text);
    CHECK(len == 0, "the refusal is empty on success, got %zu bytes", len);
    CHECK(wz_capi_c_internal_e2e_sender_check(&sender),
          "the handle is live after a successful new");
    return sender;
}

static z_result_t wrap(const wz_capi_c_owned_e2e_sender_t *sender,
                       const char *values, const char *payload, char *doc,
                       size_t cap) {
    z_owned_string_t out;
    z_internal_string_null(&out);
    z_result_t rc = wz_capi_c_e2e_sender_wrap(
        wz_capi_c_e2e_sender_loan(sender), values, (const uint8_t *)payload,
        payload ? strlen(payload) : 0, &out);
    take(&out, doc, cap);
    return rc;
}

static void drop_sender(wz_capi_c_owned_e2e_sender_t *sender) {
    wz_capi_c_e2e_sender_drop((wz_capi_c_moved_e2e_sender_t *)sender);
}

int main(void) {
    char doc[1024];
    char frame[256];
    uint64_t next = 0;

    CHECK(wz_capi_c_abi_version() == WZ_CAPI_C_ABI_REVISION,
          "the library is revision %d, this header is %d",
          (int)wz_capi_c_abi_version(), WZ_CAPI_C_ABI_REVISION);

    /* The handle keeps the counter across calls, and each frame is the
     * independently computed one. */
    wz_capi_c_owned_e2e_sender_t sender = make(40, WZ_CAPI_C_E2E_ROLLOVER_REFUSE);
    for (int i = 0; i < 4; i++) {
        z_result_t rc = wrap(&sender, "{}", "abc", doc, sizeof doc);
        CHECK(rc == Z_OK, "wrap #%d returned %d", i, (int)rc);
        CHECK(strstr(doc, "\"ok\":true") != NULL, "wrap #%d: %s", i, doc);
        frame_of(doc, frame, sizeof frame);
        CHECK(strcmp(frame, GOLDEN[i]) == 0, "wrap #%d frame %s, expected %s", i,
              frame, GOLDEN[i]);
    }
    CHECK(wz_capi_c_e2e_sender_next(wz_capi_c_e2e_sender_loan(&sender), &next),
          "a next value exists");
    CHECK(next == 44, "next is %llu, expected 44", (unsigned long long)next);

    /* A refusal is a document under Z_OK and consumes no value. */
    z_result_t rc = wrap(&sender, "{\"nope\":1}", "", doc, sizeof doc);
    CHECK(rc == Z_OK, "a refused text is a successful diagnosis, got %d", (int)rc);
    CHECK(strstr(doc, "\"ok\":false") != NULL, "refusal document: %s", doc);
    CHECK(wz_capi_c_e2e_sender_next(wz_capi_c_e2e_sender_loan(&sender), &next) &&
              next == 44,
          "a refusal consumed no value, next is %llu", (unsigned long long)next);

    /* set() restores a chosen value. */
    CHECK(wz_capi_c_e2e_sender_set(wz_capi_c_e2e_sender_loan(&sender), 41) == Z_OK,
          "set returns Z_OK");
    rc = wrap(&sender, "{}", "abc", doc, sizeof doc);
    frame_of(doc, frame, sizeof frame);
    CHECK(rc == Z_OK && strcmp(frame, GOLDEN[1]) == 0,
          "after set(41) the frame is %s, expected %s", frame, GOLDEN[1]);

    /* The handle is dropped once and a second drop is harmless. */
    drop_sender(&sender);
    CHECK(!wz_capi_c_internal_e2e_sender_check(&sender),
          "a dropped handle is no longer live");
    drop_sender(&sender);

    /* A profile that is not one is a parse error with the document in
     * `refusal`, and the handle holds a gravestone. */
    {
        wz_capi_c_owned_e2e_sender_t none;
        z_owned_string_t refusal;
        char text[512];
        wz_capi_c_internal_e2e_sender_null(&none);
        z_internal_string_null(&refusal);
        z_result_t prc = wz_capi_c_e2e_sender_new(
            &none, "{}", 0, WZ_CAPI_C_E2E_ROLLOVER_REFUSE, &refusal);
        size_t len = take(&refusal, text, sizeof text);
        CHECK(prc != Z_OK, "a profile that is not one must be refused");
        CHECK(len > 0, "the refusal document is not empty");
        CHECK(!wz_capi_c_internal_e2e_sender_check(&none),
              "a refused constructor leaves a gravestone");
    }

    /* The counter does not wrap by default: the frame that carries the largest
     * value is built, and the next call is refused naming the value. */
    {
        wz_capi_c_owned_e2e_sender_t end = make(255, WZ_CAPI_C_E2E_ROLLOVER_REFUSE);
        z_result_t erc = wrap(&end, "{}", "abc", doc, sizeof doc);
        frame_of(doc, frame, sizeof frame);
        CHECK(erc == Z_OK && strcmp(frame, GOLDEN_255) == 0,
              "the last frame is %s, expected %s", frame, GOLDEN_255);
        CHECK(!wz_capi_c_e2e_sender_next(wz_capi_c_e2e_sender_loan(&end), &next),
              "no next value after the largest");
        erc = wrap(&end, "{}", "abc", doc, sizeof doc);
        CHECK(erc == Z_OK && strstr(doc, "\"ok\":false") != NULL &&
                  strstr(doc, "largest value, 255") != NULL,
              "the refusal names the largest value: %s", doc);
        drop_sender(&end);
    }

    /* Wrapping is a choice made by name, and counts on from zero. */
    {
        wz_capi_c_owned_e2e_sender_t wrapping =
            make(255, WZ_CAPI_C_E2E_ROLLOVER_WRAP);
        (void)wrap(&wrapping, "{}", "abc", doc, sizeof doc);
        z_result_t wrc = wrap(&wrapping, "{}", "abc", doc, sizeof doc);
        frame_of(doc, frame, sizeof frame);
        CHECK(wrc == Z_OK && strcmp(frame, GOLDEN_0) == 0,
              "after the wrap the frame is %s, expected %s", frame, GOLDEN_0);
        drop_sender(&wrapping);
    }

    /* A null handle is not a live one. */
    CHECK(!wz_capi_c_e2e_sender_next(NULL, &next), "next(NULL) is false");

    if (failures != 0) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("c_e2e_sender_consumer: ok\n");
    return 0;
}
