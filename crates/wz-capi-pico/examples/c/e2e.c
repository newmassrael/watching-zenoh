/*
 * SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * End-to-end protection across a session: the publishing side protects each payload with
 * a sender (wz_ext_e2e_sender_*), the subscribing side judges each frame it is handed with
 * a receiver (wz_ext_e2e_receiver_*), both under one profile.
 *
 * The profile is SYNTHETIC, made up for this example and unlike any deployed one: a two-byte
 * counter, a two-byte identifier XORed with a constant, a two-byte length of the whole
 * frame and a CRC-16 over the other three and the payload. The library holds no layout of
 * its own; a deployment hands its profile over the same way.
 *
 * The frames, in the order they are published, and what the receiver says of each:
 *   counter 0              FIRST      the stream's baseline
 *   counter 1, 2           OK         intact, and the next one
 *   counter 3, one payload byte flipped
 *                          INTEGRITY  the CRC fails; the frame moves no state
 *   counter 3              OK         the intact frame the flipped one stood for
 *   counter 3 again        REPEATED   intact, the same counter again
 * Whatever the verdict, the payload is handed on (payload_offset, payload_len), and what
 * the application does with a frame that failed is the program's choice.
 *
 * Built against the library with the e2e-sender and e2e-receiver capabilities.
 */

#define EXAMPLE_NAME "example-e2e"

#include <zenoh-pico.h>

#include "wz_ext.h"

#include "example_common.h"

static const char *const PROFILE =
    "{\"name\": \"example-frame\","
    " \"fields\": ["
    "  {\"name\": \"counter\", \"bytes\": 2},"
    "  {\"name\": \"ident\", \"bytes\": 2, \"xor\": \"0x5A5A\"},"
    "  {\"name\": \"length\", \"bytes\": 2},"
    "  {\"name\": \"crc\", \"bytes\": 2}],"
    " \"crc\": {\"field\": \"crc\", \"width\": 16, \"poly\": \"0x8005\", \"init\": \"0x0000\","
    "          \"refin\": true, \"refout\": true, \"xorout\": \"0x0000\","
    "          \"cover\": [\"counter\", \"ident\", \"length\", \"@payload\"]},"
    " \"length\": {\"field\": \"length\", \"counts\": \"frame\"},"
    " \"counter\": {\"field\": \"counter\", \"max_gap\": 3, \"timeout_ms\": 60000},"
    " \"judge\": {\"ident\": \"ident\", \"length\": true}}";

/* The sender's fixed header values and the identifier the receiver expects. */
static const char *const VALUES = "{\"ident\": 4660}";

#define FRAMES 6
#define PAYLOAD "reading-0042"

static wz_ext_owned_e2e_receiver_t receiver;
static z_clock_t started;

static struct {
    z_owned_mutex_t lock;
    int count;
    uint8_t status[FRAMES];
    uint8_t failed[FRAMES];
    int payload_ok[FRAMES];
} judged;

static ex_counter_t probes;

static void on_sample(z_loaned_sample_t *sample, void *arg) {
    (void)arg;
    z_owned_slice_t slice;
    if (z_bytes_to_slice(z_sample_payload(sample), &slice) != Z_OK) return;
    const uint8_t *data = z_slice_data(z_slice_loan(&slice));
    size_t len = z_slice_len(z_slice_loan(&slice));
    if (len == 5 && memcmp(data, "probe", 5) == 0) {
        ex_counter_add(&probes, 1);
        z_slice_drop(z_slice_move(&slice));
        return;
    }
    wz_ext_e2e_verdict_t verdict;
    uint64_t now_ms = (uint64_t)z_clock_elapsed_ms(&started);
    z_result_t rc = wz_ext_e2e_receiver_judge(wz_ext_e2e_receiver_loan(&receiver), 0, data, len, now_ms, &verdict);
    z_mutex_lock(z_mutex_loan_mut(&judged.lock));
    if (rc == Z_OK && judged.count < FRAMES) {
        int n = judged.count++;
        judged.status[n] = verdict.status;
        judged.failed[n] = verdict.failed;
        judged.payload_ok[n] = verdict.payload_len == strlen(PAYLOAD) &&
                               verdict.payload_offset + verdict.payload_len <= len;
    }
    z_mutex_unlock(z_mutex_loan_mut(&judged.lock));
    z_slice_drop(z_slice_move(&slice));
}

static int judged_count(void) {
    z_mutex_lock(z_mutex_loan_mut(&judged.lock));
    int n = judged.count;
    z_mutex_unlock(z_mutex_loan_mut(&judged.lock));
    return n;
}

/* The refusal a door wrote, printed and dropped; nothing for the null state. */
static void show_refusal(const char *door, z_owned_string_t *refusal) {
    if (!z_internal_string_check(refusal)) return;
    printf("%s: %s refused: %.*s\n", EXAMPLE_NAME, door, (int)z_string_len(z_string_loan(refusal)),
           z_string_data(z_string_loan(refusal)));
    z_string_drop(z_string_move(refusal));
}

static void publish(const z_loaned_session_t *session, const uint8_t *frame, size_t len) {
    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, "example/e2e/frame");
    z_owned_bytes_t payload;
    z_bytes_copy_from_buf(&payload, frame, len);
    z_put(session, z_view_keyexpr_loan(&ke), z_bytes_move(&payload), NULL);
}

int main(void) {
    started = z_clock_now();
    z_mutex_init(&judged.lock);
    ex_counter_init(&probes);

    wz_ext_owned_e2e_sender_t sender;
    z_owned_string_t refusal;
    z_result_t rc = wz_ext_e2e_sender_new(&sender, PROFILE, VALUES, NULL, &refusal);
    show_refusal("wz_ext_e2e_sender_new", &refusal);
    CHECK(rc == Z_OK, "the sender was refused (rc %d)", (int)rc);
    rc = wz_ext_e2e_receiver_new(&receiver, PROFILE, VALUES, NULL, &refusal);
    show_refusal("wz_ext_e2e_receiver_new", &refusal);
    CHECK(rc == Z_OK, "the receiver was refused (rc %d)", (int)rc);
    if (!wz_ext_internal_e2e_sender_check(&sender) || !wz_ext_internal_e2e_receiver_check(&receiver)) {
        return ex_finish();
    }
    const wz_ext_loaned_e2e_sender_t *tx = wz_ext_e2e_sender_loan(&sender);

    /* The refused cases, before anything is sent. A buffer too small takes nothing and
     * consumes no counter; a stream the receiver does not have is no verdict. */
    size_t frame_size = 0;
    CHECK(wz_ext_e2e_sender_frame_size(tx, strlen(PAYLOAD), &frame_size) == Z_OK, "frame_size");
    CHECK(frame_size == strlen(PAYLOAD) + 8, "a frame of this profile is the payload and 8 header bytes, not %zu",
          frame_size);
    uint8_t small[4] = {0};
    size_t written = 0;
    rc = wz_ext_e2e_sender_protect(tx, 0, (const uint8_t *)PAYLOAD, strlen(PAYLOAD), small, sizeof small,
                                   &written, NULL, &refusal);
    show_refusal("wz_ext_e2e_sender_protect", &refusal);
    CHECK(rc == _Z_ERR_OVERFLOW, "a buffer too small for the frame was not refused with _Z_ERR_OVERFLOW (rc %d)",
          (int)rc);
    uint64_t next = 99;
    CHECK(wz_ext_e2e_sender_next(tx, 0, &next) && next == 0, "a refused protect consumed a counter (next %llu)",
          (unsigned long long)next);
    wz_ext_e2e_verdict_t none;
    CHECK(wz_ext_e2e_receiver_judge(wz_ext_e2e_receiver_loan(&receiver), 5, small, sizeof small, 0, &none) ==
              Z_EINVAL,
          "a stream the receiver does not have was judged");

    char locator[64];
    snprintf(locator, sizeof locator, "tcp/127.0.0.1:%u", ex_port());
    z_owned_session_t listener;
    rc = ex_open_listener(&listener, locator);
    CHECK(rc == Z_OK, "the listener did not open on %s (rc %d)", locator, (int)rc);
    if (rc == Z_OK) {
        z_owned_closure_sample_t closure;
        z_closure_sample(&closure, on_sample, NULL, NULL);
        z_view_keyexpr_t ke;
        z_view_keyexpr_from_str(&ke, "example/e2e/**");
        z_owned_subscriber_t subscriber;
        CHECK(z_declare_subscriber(z_session_loan(&listener), &subscriber, z_view_keyexpr_loan(&ke),
                                   z_closure_sample_move(&closure), NULL) == Z_OK,
              "z_declare_subscriber");

        z_owned_session_t dialer;
        rc = ex_open_dialer(&dialer, locator);
        CHECK(rc == Z_OK, "the dialer did not open to %s (rc %d)", locator, (int)rc);
        if (rc == Z_OK) {
            const z_loaned_session_t *s = z_session_loan(&dialer);
            for (int i = 0; i < 400 && ex_counter_get(&probes) == 0; i++) {
                ex_put(s, "example/e2e/probe", "probe", NULL);
                z_sleep_ms(25);
            }
            CHECK(ex_counter_get(&probes) > 0, "the subscriber was never handed a put");

            uint8_t frame[64];
            uint64_t counter = 0;
            for (int n = 0; n < 4; n++) {
                rc = wz_ext_e2e_sender_protect(tx, 0, (const uint8_t *)PAYLOAD, strlen(PAYLOAD), frame,
                                               sizeof frame, &written, &counter, &refusal);
                show_refusal("wz_ext_e2e_sender_protect", &refusal);
                CHECK(rc == Z_OK && counter == (uint64_t)n, "frame %d: rc %d, counter %llu", n, (int)rc,
                      (unsigned long long)counter);
                if (n == 3) {
                    /* The flipped copy goes first, then the frame it stood for, then that
                     * frame again. */
                    uint8_t flipped[64];
                    memcpy(flipped, frame, written);
                    flipped[written - 1] ^= 0x01;
                    publish(s, flipped, written);
                    publish(s, frame, written);
                }
                publish(s, frame, written);
            }
            for (int i = 0; i < 500 && judged_count() < FRAMES; i++) z_sleep_ms(10);
            CHECK(judged_count() == FRAMES, "%d of %d frames were judged", judged_count(), FRAMES);

            static const uint8_t expected[FRAMES] = {WZ_EXT_E2E_FIRST,     WZ_EXT_E2E_OK, WZ_EXT_E2E_OK,
                                                     WZ_EXT_E2E_INTEGRITY, WZ_EXT_E2E_OK, WZ_EXT_E2E_REPEATED};
            z_mutex_lock(z_mutex_loan_mut(&judged.lock));
            for (int n = 0; n < judged.count; n++) {
                CHECK(judged.status[n] == expected[n], "frame %d: status %u, expected %u", n,
                      (unsigned)judged.status[n], (unsigned)expected[n]);
                CHECK(judged.payload_ok[n], "frame %d: the payload view is not the payload", n);
            }
            if (judged.count > 3) {
                CHECK(judged.failed[3] & WZ_EXT_E2E_FAILED_CRC, "the flipped frame did not fail its CRC (failed %u)",
                      (unsigned)judged.failed[3]);
            }
            z_mutex_unlock(z_mutex_loan_mut(&judged.lock));
            ex_close(&dialer);
        }
        z_subscriber_drop(z_subscriber_move(&subscriber));
        ex_close(&listener);
    }

    wz_ext_e2e_sender_drop(wz_ext_e2e_sender_move(&sender));
    wz_ext_e2e_receiver_drop(wz_ext_e2e_receiver_move(&receiver));
    ex_counter_drop(&probes);
    z_mutex_drop(z_mutex_move(&judged.lock));
    return ex_finish();
}
