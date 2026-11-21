/*
 * SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * One scenario of the additional features, run the same over either form of the pico library:
 * the one library (the default build) or the core and the additional library built apart
 * (docs/capi-pico-additional-library.md). The differential test
 * (crates/wz-integration-tests/tests/it/files/pico_additional_split_wire.rs) compiles it against
 * each form, runs it through a recording relay and compares what the two put on the wire.
 *
 *   additional_split_scenario <listen locator> <dial locator>
 *
 * A publishing session listens on the first locator and a subscribing one dials the second (the
 * relay in front of the first). Each session's zenoh id is fixed, so the ids on the wire, and the
 * sequence numbers derived from them, are the same in every run.
 *
 * What it exercises, each across the boundary of the split form:
 *   - the interface version, asked of the core (wz_ext_interface_version) and of the doors
 *     (wz_ext_additional_interface), which agree;
 *   - an end-to-end sender protecting each frame, and a receiver judging it;
 *   - a replay cache over storage the program allocates and frees itself, refused first over
 *     storage one byte short: the refusal is a string the core made, which the program drops with
 *     the core's z_string_drop;
 *   - a replay subscriber that comes later, is handed the cache's history and then live frames.
 *
 * Exit 0 when every check held. The profile is made up for this test and unlike any deployed one.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zenoh-pico.h>

#include "wz_ext.h"

#define NAME "additional-split-scenario"
#define KEY "test/additional/reading"
#define SUFFIX "/history"
#define DEPTH 4
#define SENT_BEFORE 6
#define LIVE 3
#define HANDED (DEPTH + LIVE)
#define FRAME_MAX 24
#define PUBLISHER_ROWS 4

/* Fixed, so that the wire is the same in every run of either form. */
#define PUBLISHER_ZID "5a5a5a5a-0000-4000-8000-000000000001"
#define SUBSCRIBER_ZID "5a5a5a5a-0000-4000-8000-000000000002"

static const char *const PROFILE =
    "{\"name\": \"split-scenario-frame\","
    " \"fields\": ["
    "  {\"name\": \"crc\", \"bytes\": 4},"
    "  {\"name\": \"counter\", \"bytes\": 2},"
    "  {\"name\": \"length\", \"bytes\": 2}],"
    " \"crc\": {\"field\": \"crc\", \"width\": 32, \"poly\": \"0x1EDC6F41\", \"init\": \"0xFFFFFFFF\","
    "          \"refin\": true, \"refout\": true, \"xorout\": \"0xFFFFFFFF\","
    "          \"cover\": [\"counter\", \"length\", \"@payload\"]},"
    " \"length\": {\"field\": \"length\", \"counts\": \"frame\"},"
    " \"counter\": {\"field\": \"counter\", \"max_gap\": 3, \"timeout_ms\": 60000}}";

static int checks = 0;
static int failures = 0;

#define CHECK(cond, ...)                                     \
    do {                                                     \
        checks++;                                            \
        if (!(cond)) {                                       \
            failures++;                                      \
            printf("%s: FAIL at line %d: ", NAME, __LINE__); \
            printf(__VA_ARGS__);                             \
            printf("\n");                                    \
        }                                                    \
    } while (0)

static int finish(void) {
    printf("%s: %d check(s), %d failure(s)\n", NAME, checks, failures);
    return failures == 0 ? 0 : 1;
}

static struct {
    z_owned_mutex_t lock;
    int count;
    int extra;
    int from_replay[HANDED];
    uint8_t status[HANDED];
    uint64_t counter[HANDED];
    int context_dropped;
} handed;

static int payload_of(unsigned long long n, char *out, size_t cap) { return snprintf(out, cap, "value-%llu", n); }

static void on_frame(void *context, const wz_ext_replay_sample_t *sample) {
    (void)context;
    z_mutex_lock(z_mutex_loan_mut(&handed.lock));
    if (handed.count < HANDED) {
        int n = handed.count++;
        handed.from_replay[n] = sample->from_replay;
        handed.status[n] = sample->judged ? sample->verdict.status : 0xFF;
        handed.counter[n] = sample->verdict.counter;
    } else {
        handed.extra++;
    }
    z_mutex_unlock(z_mutex_loan_mut(&handed.lock));
}

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

/* A refusal a door wrote: a string the core made, dropped here with the core's z_string_drop.
 * Whether one was written is returned. */
static int drop_refusal(z_owned_string_t *refusal) {
    if (!z_internal_string_check(refusal)) return 0;
    z_string_drop(z_string_move(refusal));
    return 1;
}

static void close_session(z_owned_session_t *session) {
    z_close(z_session_loan_mut(session), NULL);
    z_session_drop(z_session_move(session));
}

static z_result_t open_session(z_owned_session_t *session, int dial, const char *locator, const char *zid) {
    z_result_t rc = -1;
    for (int attempt = 0; attempt < (dial ? 100 : 1) && rc != Z_OK; attempt++) {
        z_owned_config_t config;
        z_config_default(&config);
        zp_config_insert(z_config_loan_mut(&config), Z_CONFIG_SESSION_ZID_KEY, zid);
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

static int publish(const wz_ext_loaned_replay_publisher_t *cache, const wz_ext_loaned_e2e_sender_t *tx, unsigned n) {
    char payload[16];
    int len = payload_of(n, payload, sizeof payload);
    uint8_t frame[FRAME_MAX];
    size_t written = 0;
    uint64_t counter = 0;
    z_owned_string_t refusal;
    z_result_t rc = wz_ext_e2e_sender_protect(tx, 0, (const uint8_t *)payload, (size_t)len, frame, sizeof frame,
                                              &written, &counter, &refusal);
    drop_refusal(&refusal);
    if (rc != Z_OK || counter != n) return 0;
    uint8_t dispatch = 0xFF;
    /* The frame's number as its time, so the cache orders the same frames the same in every run. */
    rc = wz_ext_replay_publisher_put(cache, 0, (uint64_t)n, frame, written, WZ_EXT_REPLAY_SEND_PERIODIC, &dispatch);
    return rc == Z_OK && dispatch == WZ_EXT_REPLAY_SENT;
}

static int poll_until(const wz_ext_loaned_replay_subscriber_t *subscriber, int phase, int count) {
    for (int i = 0; i < 1000; i++) {
        wz_ext_replay_subscriber_poll(subscriber);
        if ((phase < 0 || wz_ext_replay_subscriber_phase(subscriber) == phase) && handed_count() >= count) return 1;
        z_sleep_ms(10);
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        printf("usage: %s <listen locator> <dial locator>\n", argv[0]);
        return 2;
    }
    const char *listen = argv[1];
    const char *dial = argv[2];
    z_mutex_init(&handed.lock);

    /* ---- The interface: the core's version, and the doors', which run over it. */
    wz_ext_interface_version_t core_version;
    core_version.struct_size = sizeof core_version;
    CHECK(wz_ext_interface_version(&core_version) == Z_OK, "the core did not answer its interface version");
    wz_ext_interface_version_t needed;
    needed.struct_size = sizeof needed;
    CHECK(wz_ext_additional_interface(&needed) == Z_OK, "the doors do not run over this core");
    CHECK(needed.major == core_version.major && needed.minor <= core_version.minor,
          "the doors need %u.%u and the core is %u.%u", (unsigned)needed.major, (unsigned)needed.minor,
          (unsigned)core_version.major, (unsigned)core_version.minor);
    CHECK(wz_ext_interface_major_1() == WZ_EXT_INTERFACE_MAJOR, "the major version's function answers %u",
          (unsigned)wz_ext_interface_major_1());

    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, KEY);
    z_owned_string_t refusal;

    /* ---- The publishing side. */
    z_owned_session_t pub_session;
    z_result_t rc = open_session(&pub_session, 0, listen, PUBLISHER_ZID);
    CHECK(rc == Z_OK, "the publishing session did not open on %s (rc %d)", listen, (int)rc);
    if (rc != Z_OK) return finish();
    z_owned_publisher_t publisher;
    rc = z_declare_publisher(z_session_loan(&pub_session), &publisher, z_view_keyexpr_loan(&ke), NULL);
    CHECK(rc == Z_OK, "z_declare_publisher (rc %d)", (int)rc);
    if (rc != Z_OK) {
        close_session(&pub_session);
        return finish();
    }

    wz_ext_owned_e2e_sender_t sender;
    rc = wz_ext_e2e_sender_new(&sender, PROFILE, "{}", NULL, &refusal);
    drop_refusal(&refusal);
    CHECK(rc == Z_OK, "the sender was refused (rc %d)", (int)rc);

    wz_ext_replay_shape_t shape;
    shape.frame_max = FRAME_MAX;
    shape.depth = DEPTH;
    shape.instances = 1;
    size_t storage_len = wz_ext_replay_publisher_storage_size(&shape);
    CHECK(storage_len > 0, "no storage size for the cache's shape");
    /* The program's storage: allocated and freed here, never by either library. */
    uint8_t *storage = storage_len > 0 ? (uint8_t *)malloc(storage_len) : NULL;
    wz_ext_owned_replay_publisher_t cache;
    wz_ext_internal_replay_publisher_null(&cache);
    if (storage != NULL) {
        wz_ext_owned_replay_publisher_t short_cache;
        rc = wz_ext_replay_publisher_new(&short_cache, z_session_loan(&pub_session), z_publisher_loan(&publisher),
                                         storage, storage_len - 1, &shape, &refusal);
        CHECK(rc == _Z_ERR_CONFIG_INVALID_VALUE, "a cache over storage one byte short was not refused (rc %d)",
              (int)rc);
        CHECK(drop_refusal(&refusal), "the refused cache wrote no refusal");
        wz_ext_replay_publisher_drop(wz_ext_replay_publisher_move(&short_cache));
        rc = wz_ext_replay_publisher_new(&cache, z_session_loan(&pub_session), z_publisher_loan(&publisher), storage,
                                         storage_len, &shape, &refusal);
        drop_refusal(&refusal);
        CHECK(rc == Z_OK, "the cache was refused (rc %d)", (int)rc);
    }

    if (wz_ext_internal_e2e_sender_check(&sender) && wz_ext_internal_replay_publisher_check(&cache)) {
        const wz_ext_loaned_e2e_sender_t *tx = wz_ext_e2e_sender_loan(&sender);
        const wz_ext_loaned_replay_publisher_t *pub_cache = wz_ext_replay_publisher_loan(&cache);
        for (unsigned n = 0; n < SENT_BEFORE; n++) CHECK(publish(pub_cache, tx, n), "frame %u was not put", n);
        rc = wz_ext_replay_publisher_serve(pub_cache, z_view_keyexpr_loan(&ke), SUFFIX, NULL, &refusal);
        drop_refusal(&refusal);
        CHECK(rc == Z_OK, "the cache does not serve (rc %d)", (int)rc);

        /* ---- The subscribing side, which comes later, through the relay. */
        z_owned_session_t sub_session;
        rc = open_session(&sub_session, 1, dial, SUBSCRIBER_ZID);
        CHECK(rc == Z_OK, "the subscribing session did not open to %s (rc %d)", dial, (int)rc);
        if (rc == Z_OK) {
            wz_ext_owned_e2e_receiver_t receiver;
            rc = wz_ext_e2e_receiver_new(&receiver, PROFILE, NULL, NULL, &refusal);
            drop_refusal(&refusal);
            CHECK(rc == Z_OK, "the receiver was refused (rc %d)", (int)rc);
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
            wz_ext_owned_replay_subscriber_t subscriber;
            rc = wz_ext_replay_subscriber_new(&subscriber, z_session_loan(&sub_session), z_view_keyexpr_loan(&ke),
                                              SUFFIX, wz_ext_e2e_receiver_move(&receiver), &options, on_frame,
                                              on_context_drop, NULL);
            CHECK(rc == Z_OK, "the replay subscriber was refused (rc %d)", (int)rc);
            if (rc == Z_OK) {
                const wz_ext_loaned_replay_subscriber_t *sub = wz_ext_replay_subscriber_loan(&subscriber);
                CHECK(poll_until(sub, WZ_EXT_REPLAY_ROUND_LIVE, DEPTH),
                      "the round did not end with the history handed on (phase %u, %d frames)",
                      (unsigned)wz_ext_replay_subscriber_phase(sub), handed_count());
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
                    CHECK(handed.status[n] == (n == 0 ? WZ_EXT_E2E_FIRST : WZ_EXT_E2E_OK), "frame %d was judged %u", n,
                          (unsigned)handed.status[n]);
                }
                z_mutex_unlock(z_mutex_loan_mut(&handed.lock));
                wz_ext_replay_subscriber_drop(wz_ext_replay_subscriber_move(&subscriber));
            }
            z_mutex_lock(z_mutex_loan_mut(&handed.lock));
            CHECK(handed.context_dropped == 1, "the subscriber let go of its context %d times, not once",
                  handed.context_dropped);
            z_mutex_unlock(z_mutex_loan_mut(&handed.lock));
            close_session(&sub_session);
        }
    }

    wz_ext_replay_publisher_drop(wz_ext_replay_publisher_move(&cache));
    free(storage);
    wz_ext_e2e_sender_drop(wz_ext_e2e_sender_move(&sender));
    z_undeclare_publisher(z_publisher_move(&publisher));
    close_session(&pub_session);
    z_mutex_drop(z_mutex_move(&handed.lock));
    return finish();
}
