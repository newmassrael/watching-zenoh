/*
 * SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * History for a subscriber that arrives late: the publisher keeps the last frames it sent of a
 * message in a replay cache (wz_ext_replay_publisher_*), and a subscriber made after them
 * (wz_ext_replay_subscriber_*) is handed that history, oldest first, and then the live frames,
 * in one order.
 *
 * The publishing side, a session that listens on the host's loopback:
 *   - a publisher on example/history/reading; an end-to-end sender that puts a counter and a
 *     CRC in front of each payload, so the subscriber can judge each frame; and a cache of the
 *     last DEPTH frames, over storage the program gives it;
 *   - SENT_BEFORE frames put before anyone subscribes; the cache records each as it is put;
 *   - the cache served: a queryable on the key followed by the program's suffix "/history",
 *     which answers a query with the frames the cache holds, oldest first, then its final.
 * The subscribing side, a session that dials it afterwards:
 *   - a replay subscriber of the key: it subscribes, watches the session's peers for the
 *     cache's queryable, asks it once it appears, and hands the program every frame, the
 *     replies flagged as history, each judged by one receiver of the same profile;
 *   - once the subscriber's round is over (WZ_EXT_REPLAY_ROUND_LIVE), the publisher puts LIVE
 *     more frames.
 *
 * The subscriber is handed the last DEPTH of the frames sent before it came (the cache keeps no
 * more than that), then the live ones: counters SENT_BEFORE - DEPTH to SENT_BEFORE + LIVE - 1,
 * each the next one, the first judged FIRST (the stream's baseline) and every later one OK.
 *
 * Both sessions state the replay-reply-shape policy in their configs (wz_ext_config_policy):
 * frame-per-sample, one reply for each frame the cache holds. It is the build's default and is
 * stated so that a library built with another default runs this example alike. The profile is
 * made up for this example and unlike any deployed one.
 *
 * Built against the library with the replay-cache and e2e-sender capabilities.
 */

#define EXAMPLE_NAME "example-history"

#include <zenoh-pico.h>

#include "wz_ext.h"

#include "example_common.h"

#define KEY "example/history/reading"
#define SUFFIX "/history"
#define DEPTH 8
#define SENT_BEFORE 12
#define LIVE 4
#define HANDED (DEPTH + LIVE)
/* The longest frame the cache keeps: the 8-byte header and a payload of at most 16. */
#define FRAME_MAX 24
#define PUBLISHER_ROWS 4

/* A 32-bit CRC first on the wire, then a two-byte counter and a two-byte length of the frame. */
static const char *const PROFILE =
    "{\"name\": \"example-history-frame\","
    " \"fields\": ["
    "  {\"name\": \"crc\", \"bytes\": 4},"
    "  {\"name\": \"counter\", \"bytes\": 2},"
    "  {\"name\": \"length\", \"bytes\": 2}],"
    " \"crc\": {\"field\": \"crc\", \"width\": 32, \"poly\": \"0x1EDC6F41\", \"init\": \"0xFFFFFFFF\","
    "          \"refin\": true, \"refout\": true, \"xorout\": \"0xFFFFFFFF\","
    "          \"cover\": [\"counter\", \"length\", \"@payload\"]},"
    " \"length\": {\"field\": \"length\", \"counts\": \"frame\"},"
    " \"counter\": {\"field\": \"counter\", \"max_gap\": 3, \"timeout_ms\": 60000}}";

static z_clock_t started;

/* What the subscriber handed the program, in the order it handed it. */
static struct {
    z_owned_mutex_t lock;
    int count;
    int extra;
    int from_replay[HANDED];
    int judged[HANDED];
    uint8_t status[HANDED];
    uint64_t counter[HANDED];
    int payload_ok[HANDED];
    int context_dropped;
} handed;

/* The text the publisher protects as frame `n`'s payload. */
static int payload_of(unsigned long long n, char *out, size_t cap) { return snprintf(out, cap, "reading-%llu", n); }

/* The subscriber's callback: one frame at a time, in the order its receiver judged them, inside
 * the subscriber's lock, so it calls no door of its own subscriber. The frame is valid only for
 * the call. */
static void on_frame(void *context, const wz_ext_replay_sample_t *sample) {
    (void)context;
    z_mutex_lock(z_mutex_loan_mut(&handed.lock));
    if (handed.count < HANDED) {
        int n = handed.count++;
        char expected[32];
        int len = payload_of((unsigned long long)sample->verdict.counter, expected, sizeof expected);
        handed.from_replay[n] = sample->from_replay;
        handed.judged[n] = sample->judged;
        handed.status[n] = sample->verdict.status;
        handed.counter[n] = sample->verdict.counter;
        handed.payload_ok[n] = sample->judged && len > 0 && sample->verdict.payload_len == (size_t)len &&
                               sample->verdict.payload_offset + sample->verdict.payload_len <= sample->len &&
                               memcmp(sample->frame + sample->verdict.payload_offset, expected, (size_t)len) == 0;
    } else {
        handed.extra++;
    }
    z_mutex_unlock(z_mutex_loan_mut(&handed.lock));
}

/* Runs once, when the subscriber lets go of the context it was given. */
static void on_context_drop(void *context) {
    (void)context;
    z_mutex_lock(z_mutex_loan_mut(&handed.lock));
    handed.context_dropped++;
    z_mutex_unlock(z_mutex_loan_mut(&handed.lock));
}

static int handed_count(void) {
    z_mutex_lock(z_mutex_loan_mut(&handed.lock));
    int n = handed.count;
    z_mutex_unlock(z_mutex_loan_mut(&handed.lock));
    return n;
}

/* The refusal a door wrote, printed and dropped; nothing for the null state. */
static void show_refusal(const char *door, z_owned_string_t *refusal) {
    if (!z_internal_string_check(refusal)) return;
    printf("%s: %s refused: %.*s\n", EXAMPLE_NAME, door, (int)z_string_len(z_string_loan(refusal)),
           z_string_data(z_string_loan(refusal)));
    z_string_drop(z_string_move(refusal));
}

/* A session that listens on `locator`, or dials it as a client (retried while the listener
 * binds), with the replay policy this example runs under stated in its config. */
static z_result_t open_session(z_owned_session_t *session, int dial, const char *locator) {
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
        z_result_t stated =
            wz_ext_config_policy(z_config_loan_mut(&config), "replay-reply-shape", "frame-per-sample");
        if (stated != Z_OK) {
            z_config_drop(z_config_move(&config));
            return stated;
        }
        rc = z_open(session, z_config_move(&config), NULL);
        if (rc != Z_OK && dial) z_sleep_ms(100);
    }
    return rc;
}

/* Protect frame `n`'s payload and put it through the cache, which records it first: 1 when the
 * frame carried counter `n` and went out. */
static int publish(const wz_ext_loaned_replay_publisher_t *cache, const wz_ext_loaned_e2e_sender_t *tx,
                   unsigned n) {
    char payload[16];
    int len = payload_of(n, payload, sizeof payload);
    uint8_t frame[FRAME_MAX];
    size_t written = 0;
    uint64_t counter = 0;
    z_owned_string_t refusal;
    z_result_t rc = wz_ext_e2e_sender_protect(tx, 0, (const uint8_t *)payload, (size_t)len, frame, sizeof frame,
                                              &written, &counter, &refusal);
    show_refusal("wz_ext_e2e_sender_protect", &refusal);
    if (rc != Z_OK || counter != n) return 0;
    uint8_t dispatch = 0xFF;
    rc = wz_ext_replay_publisher_put(cache, 0, (uint64_t)z_clock_elapsed_ms(&started), frame, written,
                                     WZ_EXT_REPLAY_SEND_PERIODIC, &dispatch);
    return rc == Z_OK && dispatch == WZ_EXT_REPLAY_SENT;
}

/* Poll `subscriber`, which judges its deadlines, until its round is in `phase` (any, when it is
 * negative) and `count` frames were handed on, or about 10 s pass; whether that came. */
static int poll_until(const wz_ext_loaned_replay_subscriber_t *subscriber, int phase, int count) {
    for (int i = 0; i < 1000; i++) {
        wz_ext_replay_subscriber_poll(subscriber);
        if ((phase < 0 || wz_ext_replay_subscriber_phase(subscriber) == phase) && handed_count() >= count) return 1;
        z_sleep_ms(10);
    }
    return 0;
}

int main(void) {
    started = z_clock_now();
    z_mutex_init(&handed.lock);
    char locator[64];
    snprintf(locator, sizeof locator, "tcp/127.0.0.1:%u", ex_port());
    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, KEY);
    z_owned_string_t refusal;

    /* ---- The publishing side. */
    z_owned_session_t pub_session;
    z_result_t rc = open_session(&pub_session, 0, locator);
    CHECK(rc == Z_OK, "the publishing session did not open on %s (rc %d)", locator, (int)rc);
    if (rc != Z_OK) return ex_finish();
    z_owned_publisher_t publisher;
    rc = z_declare_publisher(z_session_loan(&pub_session), &publisher, z_view_keyexpr_loan(&ke), NULL);
    CHECK(rc == Z_OK, "z_declare_publisher (rc %d)", (int)rc);
    if (rc != Z_OK) {
        ex_close(&pub_session);
        return ex_finish();
    }

    /* The sender has no header value of its own to state: the profile's fields are the CRC,
     * the length and the counter, which it fills in. */
    wz_ext_owned_e2e_sender_t sender;
    rc = wz_ext_e2e_sender_new(&sender, PROFILE, "{}", NULL, &refusal);
    show_refusal("wz_ext_e2e_sender_new", &refusal);
    CHECK(rc == Z_OK, "the sender was refused (rc %d)", (int)rc);

    /* The cache: DEPTH frames of one instance, each at most FRAME_MAX bytes, over storage the
     * program allocates at the size the library states for that shape. */
    wz_ext_replay_shape_t shape;
    shape.frame_max = FRAME_MAX;
    shape.depth = DEPTH;
    shape.instances = 1;
    size_t storage_len = wz_ext_replay_publisher_storage_size(&shape);
    CHECK(storage_len > 0, "the library states no storage size for the cache's shape");
    uint8_t *storage = storage_len > 0 ? (uint8_t *)malloc(storage_len) : NULL;
    wz_ext_owned_replay_publisher_t cache;
    wz_ext_internal_replay_publisher_null(&cache);
    if (storage != NULL) {
        /* Refused by name: storage one byte short of what the shape needs. */
        wz_ext_owned_replay_publisher_t short_cache;
        rc = wz_ext_replay_publisher_new(&short_cache, z_session_loan(&pub_session), z_publisher_loan(&publisher),
                                         storage, storage_len - 1, &shape, &refusal);
        show_refusal("wz_ext_replay_publisher_new", &refusal);
        CHECK(rc == _Z_ERR_CONFIG_INVALID_VALUE && !wz_ext_internal_replay_publisher_check(&short_cache),
              "a cache over storage one byte short was not refused (rc %d)", (int)rc);
        wz_ext_replay_publisher_drop(wz_ext_replay_publisher_move(&short_cache));

        rc = wz_ext_replay_publisher_new(&cache, z_session_loan(&pub_session), z_publisher_loan(&publisher), storage,
                                         storage_len, &shape, &refusal);
        show_refusal("wz_ext_replay_publisher_new", &refusal);
        CHECK(rc == Z_OK, "the cache was refused (rc %d)", (int)rc);
    }

    if (wz_ext_internal_e2e_sender_check(&sender) && wz_ext_internal_replay_publisher_check(&cache)) {
        const wz_ext_loaned_e2e_sender_t *tx = wz_ext_e2e_sender_loan(&sender);
        const wz_ext_loaned_replay_publisher_t *pub_cache = wz_ext_replay_publisher_loan(&cache);

        /* The frames sent before anyone subscribed: nobody hears them, the cache keeps the last
         * DEPTH. */
        for (unsigned n = 0; n < SENT_BEFORE; n++) CHECK(publish(pub_cache, tx, n), "frame %u was not put", n);
        rc = wz_ext_replay_publisher_serve(pub_cache, z_view_keyexpr_loan(&ke), SUFFIX, NULL, &refusal);
        show_refusal("wz_ext_replay_publisher_serve", &refusal);
        CHECK(rc == Z_OK, "the cache does not serve (rc %d)", (int)rc);

        /* ---- The subscribing side, which comes later. */
        z_owned_session_t sub_session;
        rc = open_session(&sub_session, 1, locator);
        CHECK(rc == Z_OK, "the subscribing session did not open to %s (rc %d)", locator, (int)rc);
        if (rc == Z_OK) {
            wz_ext_owned_e2e_receiver_t receiver;
            rc = wz_ext_e2e_receiver_new(&receiver, PROFILE, NULL, NULL, &refusal);
            show_refusal("wz_ext_e2e_receiver_new", &refusal);
            CHECK(rc == Z_OK, "the receiver was refused (rc %d)", (int)rc);

            /* The subscriber's table of publishers, and a store for live frames that arrive
             * while history is still coming, read only under the replay-live-before-answer
             * policy hold-back: both the program's, left to the subscriber while it lives. */
            static wz_ext_replay_publisher_slot_t rows[PUBLISHER_ROWS];
            static uint8_t held[8 * (4 + FRAME_MAX)];
            wz_ext_replay_subscriber_options_t options;
            wz_ext_replay_subscriber_options_default(&options);
            options.slots = rows;
            options.slot_count = PUBLISHER_ROWS;
            options.held = held;
            options.held_len = sizeof held;
            options.held_cell = FRAME_MAX;
            options.depth = DEPTH;
            options.progress_ms = 3000;
            options.round_ms = 9000;
            /* The receiver is taken on every path, and so is the context: on a refusal the
             * receiver is dropped and on_context_drop has run before this returns. */
            wz_ext_owned_replay_subscriber_t subscriber;
            rc = wz_ext_replay_subscriber_new(&subscriber, z_session_loan(&sub_session), z_view_keyexpr_loan(&ke),
                                              SUFFIX, wz_ext_e2e_receiver_move(&receiver), &options, on_frame,
                                              on_context_drop, NULL);
            CHECK(rc == Z_OK, "the replay subscriber was refused (rc %d)", (int)rc);
            if (rc == Z_OK) {
                const wz_ext_loaned_replay_subscriber_t *sub = wz_ext_replay_subscriber_loan(&subscriber);
                /* The round: the cache's queryable appears, it is asked, and its frames are
                 * handed on; then the subscriber is live. */
                CHECK(poll_until(sub, WZ_EXT_REPLAY_ROUND_LIVE, DEPTH),
                      "the round did not end with the history handed on (phase %u, %d frames)",
                      (unsigned)wz_ext_replay_subscriber_phase(sub), handed_count());
                CHECK(handed_count() == DEPTH, "%d frames of history were handed on, not %d", handed_count(),
                      DEPTH);

                for (unsigned n = SENT_BEFORE; n < SENT_BEFORE + LIVE; n++) {
                    CHECK(publish(pub_cache, tx, n), "frame %u was not put", n);
                }
                CHECK(poll_until(sub, -1, HANDED), "%d of %d frames were handed on", handed_count(), HANDED);

                z_mutex_lock(z_mutex_loan_mut(&handed.lock));
                CHECK(handed.count == HANDED && handed.extra == 0, "%d frames were handed on, not %d",
                      handed.count + handed.extra, HANDED);
                for (int n = 0; n < handed.count; n++) {
                    uint64_t expected = (uint64_t)(SENT_BEFORE - DEPTH + n);
                    CHECK(handed.counter[n] == expected, "frame %d carried counter %llu, not %llu", n,
                          (unsigned long long)handed.counter[n], (unsigned long long)expected);
                    CHECK(handed.from_replay[n] == (n < DEPTH), "frame %d is flagged %s", n,
                          handed.from_replay[n] ? "history" : "live");
                    CHECK(handed.judged[n] && handed.status[n] == (n == 0 ? WZ_EXT_E2E_FIRST : WZ_EXT_E2E_OK),
                          "frame %d was judged %u", n, (unsigned)handed.status[n]);
                    CHECK(handed.payload_ok[n], "frame %d does not carry its payload", n);
                }
                z_mutex_unlock(z_mutex_loan_mut(&handed.lock));

                wz_ext_replay_subscriber_counts_t counts;
                memset(&counts, 0, sizeof counts);
                CHECK(wz_ext_replay_subscriber_counts(sub, &counts) == Z_OK, "the subscriber's counts");
                CHECK(counts.duplicates == 0 && counts.stale == 0 && counts.abandoned == 0 &&
                          counts.late_replies == 0,
                      "the subscriber dropped %llu duplicate, %llu stale, %llu late replies and abandoned %llu rounds",
                      (unsigned long long)counts.duplicates, (unsigned long long)counts.stale,
                      (unsigned long long)counts.late_replies, (unsigned long long)counts.abandoned);

                /* Nothing is handed on after the drop returns, and the context's drop has run. */
                wz_ext_replay_subscriber_drop(wz_ext_replay_subscriber_move(&subscriber));
            }
            z_mutex_lock(z_mutex_loan_mut(&handed.lock));
            CHECK(handed.context_dropped == 1, "the subscriber let go of its context %d times, not once",
                  handed.context_dropped);
            z_mutex_unlock(z_mutex_loan_mut(&handed.lock));
            ex_close(&sub_session);
        }

        wz_ext_replay_publisher_counts_t served;
        memset(&served, 0, sizeof served);
        CHECK(wz_ext_replay_publisher_counts(pub_cache, &served) == Z_OK, "the cache's counts");
        CHECK(served.recorded == SENT_BEFORE + LIVE && served.answers >= 1,
              "the cache recorded %llu frames and answered %llu queries",
              (unsigned long long)served.recorded, (unsigned long long)served.answers);
    }

    /* The cache before its publisher and its session; its storage is the program's again once
     * the drop returns. */
    wz_ext_replay_publisher_drop(wz_ext_replay_publisher_move(&cache));
    free(storage);
    wz_ext_e2e_sender_drop(wz_ext_e2e_sender_move(&sender));
    z_undeclare_publisher(z_publisher_move(&publisher));
    ex_close(&pub_session);
    z_mutex_drop(z_mutex_move(&handed.lock));
    return ex_finish();
}
