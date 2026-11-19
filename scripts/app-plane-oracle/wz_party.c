/*
 * SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * wz's party of the application-plane oracle lane (scripts/app-plane-oracle.sh): one side of
 * an exchange of protected frames and replay answers with another implementation's party,
 * over a session on the loopback. The contract, which a deployment's own party speaks too, is
 * docs/app-plane-oracle.md's:
 *
 *   wz_party <role> <check-dir> listen <locator>
 *   wz_party <role> <check-dir> connect <locator> <client|peer>
 *
 * The roles are send and receive (protected frames on a key) and serve and ask (a replay
 * cache and the subscriber that asks it). The check directory holds what the lane wrote for
 * the check (params, plan, the profile and values texts) and the go and stop files the lane
 * creates. What the party did is its standard output, one transcript line at a time; the
 * lane, not the party, judges it against the other implementation's transcript.
 *
 * When the check directory holds key-ids, the session is opened with that dictionary of key
 * ids every node of the deployment shares, and with the key-wire form params states for this
 * party's endpoint. When params says segmented, an e2e sender cuts every frame it puts into
 * the pieces of the segment profile, and the receiver joins them before it judges.
 *
 * Exit status: 0 when the role ran to its end, 1 when it timed out waiting, 2 when it was
 * refused before anything was exchanged (a missing file, a profile the library refused).
 *
 * Built by scripts/pico-c-program.sh against the library with the e2e-sender, e2e-receiver,
 * segment-sender and replay-cache capabilities, and shared-key-ids for a dictionary.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zenoh-pico.h>

#include "wz_ext.h"

/* The key-id doors are in a build with shared-key-ids only. Weak, so the party links against
 * every build and refuses a dictionary by name where the library has none. */
#pragma weak wz_ext_config_key_ids
#pragma weak wz_ext_config_key_wire_form_for

#define MAX_FRAMES 256
#define MAX_PARAMS 32
#define WAIT_MS 30000
#define STEP_MS 10

/* ---- The check directory --------------------------------------------------------------- */

static const char *check_dir;

/* The whole of a file of the check directory, NUL-terminated; NULL when it cannot be read. */
static char *read_file(const char *name) {
    char path[4096];
    snprintf(path, sizeof path, "%s/%s", check_dir, name);
    FILE *f = fopen(path, "rb");
    if (f == NULL) return NULL;
    size_t cap = 4096;
    size_t len = 0;
    char *buf = malloc(cap);
    while (buf != NULL) {
        if (len + 1 >= cap) {
            char *grown = realloc(buf, cap * 2);
            if (grown == NULL) {
                free(buf);
                buf = NULL;
                break;
            }
            buf = grown;
            cap *= 2;
        }
        size_t n = fread(buf + len, 1, cap - len - 1, f);
        if (n == 0) break;
        len += n;
    }
    fclose(f);
    if (buf != NULL) buf[len] = '\0';
    return buf;
}

static int file_exists(const char *name) {
    char path[4096];
    snprintf(path, sizeof path, "%s/%s", check_dir, name);
    FILE *f = fopen(path, "rb");
    if (f == NULL) return 0;
    fclose(f);
    return 1;
}

/* Wait until the lane creates name; 0 when WAIT_MS passed first. */
static int wait_for_file(const char *name) {
    for (int waited = 0; waited < WAIT_MS; waited += STEP_MS) {
        if (file_exists(name)) return 1;
        z_sleep_ms(STEP_MS);
    }
    return file_exists(name);
}

static char *param_names[MAX_PARAMS];
static char *param_values[MAX_PARAMS];
static int param_count;

/* params: one "name value" per line. */
static int read_params(void) {
    char *text = read_file("params");
    if (text == NULL) return 0;
    for (char *line = strtok(text, "\n"); line != NULL && param_count < MAX_PARAMS; line = strtok(NULL, "\n")) {
        char *space = strchr(line, ' ');
        if (space == NULL) continue;
        *space = '\0';
        param_names[param_count] = line;
        param_values[param_count] = space + 1;
        param_count++;
    }
    return 1;
}

static const char *param(const char *name) {
    for (int i = 0; i < param_count; i++) {
        if (strcmp(param_names[i], name) == 0) return param_values[i];
    }
    return NULL;
}

static uint64_t param_u64(const char *name, uint64_t fallback) {
    const char *value = param(name);
    return value == NULL ? fallback : (uint64_t)strtoull(value, NULL, 10);
}

/* The plan: one "<action> <payload hex>" per frame, in the order the frames are built. */
static char plan_action[MAX_FRAMES][16];
static uint8_t *plan_payload[MAX_FRAMES];
static size_t plan_len[MAX_FRAMES];
static size_t plan_count;

static int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int read_plan(void) {
    char *text = read_file("plan");
    if (text == NULL) return 0;
    for (char *line = strtok(text, "\n"); line != NULL; line = strtok(NULL, "\n")) {
        if (plan_count == MAX_FRAMES) return 0;
        char *space = strchr(line, ' ');
        if (space == NULL || (size_t)(space - line) >= sizeof plan_action[0]) return 0;
        memcpy(plan_action[plan_count], line, (size_t)(space - line));
        plan_action[plan_count][space - line] = '\0';
        const char *hex = space + 1;
        size_t digits = strlen(hex);
        if (digits % 2 != 0) return 0;
        uint8_t *bytes = malloc(digits / 2 + 1);
        if (bytes == NULL) return 0;
        for (size_t i = 0; i < digits / 2; i++) {
            int hi = hex_digit(hex[2 * i]);
            int lo = hex_digit(hex[2 * i + 1]);
            if (hi < 0 || lo < 0) return 0;
            bytes[i] = (uint8_t)(hi * 16 + lo);
        }
        plan_payload[plan_count] = bytes;
        plan_len[plan_count] = digits / 2;
        plan_count++;
    }
    return plan_count > 0;
}

/* ---- Transcript ------------------------------------------------------------------------ */

static void print_hex(const uint8_t *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) printf("%02x", bytes[i]);
}

/* Print the refusal and its reason, and give the refused status. */
static int refused(const char *what, z_result_t rc, z_owned_string_t *reason) {
    printf("refused %s (rc %d)", what, (int)rc);
    if (reason != NULL && z_internal_string_check(reason)) {
        printf(": %.*s", (int)z_string_len(z_string_loan(reason)), z_string_data(z_string_loan(reason)));
        z_string_drop(z_string_move(reason));
    }
    printf("\n");
    return 2;
}

/* The lane's class of a verdict: what every implementation's receiver can say of a frame. */
static const char *class_of(uint8_t status) {
    switch (status) {
        case WZ_EXT_E2E_OK:
        case WZ_EXT_E2E_FIRST:
            return "intact";
        case WZ_EXT_E2E_REPEATED:
        case WZ_EXT_E2E_OUT_OF_RANGE:
        case WZ_EXT_E2E_COUNTER_ERROR:
            return "counter";
        case WZ_EXT_E2E_INTEGRITY:
            return "integrity";
        default:
            return "other";
    }
}

/* What arrived, in arrival order, filled on the session's thread. */
static struct {
    z_owned_mutex_t lock;
    size_t count;
    int probe;
    const char *cls[MAX_FRAMES];
    uint8_t *payload[MAX_FRAMES];
    size_t len[MAX_FRAMES];
} seen;

static void seen_add(const char *cls, const uint8_t *payload, size_t len) {
    z_mutex_lock(z_mutex_loan_mut(&seen.lock));
    if (seen.count < MAX_FRAMES) {
        uint8_t *copy = malloc(len == 0 ? 1 : len);
        if (copy != NULL && len > 0) memcpy(copy, payload, len);
        seen.cls[seen.count] = cls;
        seen.payload[seen.count] = copy;
        seen.len[seen.count] = copy == NULL ? 0 : len;
        seen.count++;
    }
    z_mutex_unlock(z_mutex_loan_mut(&seen.lock));
}

static size_t seen_count(void) {
    z_mutex_lock(z_mutex_loan_mut(&seen.lock));
    size_t n = seen.count;
    z_mutex_unlock(z_mutex_loan_mut(&seen.lock));
    return n;
}

static void print_seen(void) {
    z_mutex_lock(z_mutex_loan_mut(&seen.lock));
    for (size_t i = 0; i < seen.count; i++) {
        printf("got %zu %s ", i, seen.cls[i]);
        print_hex(seen.payload[i], seen.len[i]);
        printf("\n");
    }
    z_mutex_unlock(z_mutex_loan_mut(&seen.lock));
}

/* ---- Session --------------------------------------------------------------------------- */

/* The shared key ids, read once: "<id> <key>" per line. The keys point into the text, which
 * is kept for the life of the program. */
static uint16_t *key_ids;
static const char **key_names;
static size_t key_count;
static int key_ids_read;

static int read_key_ids(void) {
    if (key_ids_read) return 0;
    key_ids_read = 1;
    char *text = read_file("key-ids");
    if (text == NULL) return 0;
    size_t lines = 0;
    for (const char *c = text; *c != '\0'; c++) lines += *c == '\n';
    key_ids = malloc((lines + 1) * sizeof *key_ids);
    key_names = malloc((lines + 1) * sizeof *key_names);
    if (key_ids == NULL || key_names == NULL) return refused("key-ids storage", _Z_ERR_GENERIC, NULL);
    for (char *line = strtok(text, "\n"); line != NULL; line = strtok(NULL, "\n")) {
        char *space = strchr(line, ' ');
        if (space == NULL) return refused("key-ids line", _Z_ERR_GENERIC, NULL);
        *space = '\0';
        unsigned long id = strtoul(line, NULL, 10);
        if (id == 0 || id > 0xFFFFu) return refused("key-ids id", _Z_ERR_GENERIC, NULL);
        key_ids[key_count] = (uint16_t)id;
        key_names[key_count] = space + 1;
        key_count++;
    }
    return 0;
}

/* Hand the config the dictionary, and the form params states for this party's endpoint. */
static int configure_keys(z_owned_config_t *config, const char *how, const char *locator) {
    int status = read_key_ids();
    if (status != 0) return status;
    char form_param[32];
    snprintf(form_param, sizeof form_param, "key_form_%s", how);
    const char *form = param(form_param);
    if (key_count > 0) {
        if (wz_ext_config_key_ids == NULL) {
            printf("refused key ids: the library was built without shared-key-ids\n");
            return 2;
        }
        z_result_t rc = wz_ext_config_key_ids(z_config_loan_mut(config), key_ids, key_names, key_count);
        if (rc != Z_OK) return refused("key ids", rc, NULL);
    }
    if (form != NULL) {
        if (wz_ext_config_key_wire_form_for == NULL) {
            printf("refused key wire form: the library was built without shared-key-ids\n");
            return 2;
        }
        z_result_t rc = wz_ext_config_key_wire_form_for(z_config_loan_mut(config), locator, form);
        if (rc != Z_OK) return refused("key wire form", rc, NULL);
    }
    return 0;
}

/* 0 with the session open, or the refused status. A dialling end retries while the listener
 * binds. */
static int open_session(z_owned_session_t *session, const char *how, const char *locator, const char *mode) {
    int listening = strcmp(how, "listen") == 0;
    int attempts = listening ? 1 : 100;
    z_result_t rc = -1;
    for (int attempt = 0; attempt < attempts && rc != Z_OK; attempt++) {
        if (attempt > 0) z_sleep_ms(100);
        z_owned_config_t config;
        z_config_default(&config);
        if (listening) {
            zp_config_insert(z_config_loan_mut(&config), Z_CONFIG_LISTEN_KEY, locator);
        } else {
            zp_config_insert(z_config_loan_mut(&config), Z_CONFIG_MODE_KEY, mode);
            zp_config_insert(z_config_loan_mut(&config), Z_CONFIG_CONNECT_KEY, locator);
        }
        int status = configure_keys(&config, how, locator);
        if (status != 0) {
            z_config_drop(z_config_move(&config));
            return status;
        }
        rc = z_open(session, z_config_move(&config), NULL);
    }
    return rc == Z_OK ? 0 : refused("session", rc, NULL);
}

/* Protect every payload of the plan in order: the frames, their lengths, the longest. */
static uint8_t *frames[MAX_FRAMES];
static size_t frame_len[MAX_FRAMES];

static int protect_plan(const wz_ext_loaned_e2e_sender_t *tx, size_t *longest) {
    *longest = 0;
    for (size_t i = 0; i < plan_count; i++) {
        size_t size = 0;
        z_result_t rc = wz_ext_e2e_sender_frame_size(tx, plan_len[i], &size);
        if (rc != Z_OK) return refused("frame size", rc, NULL);
        frames[i] = malloc(size == 0 ? 1 : size);
        if (frames[i] == NULL) return refused("frame storage", _Z_ERR_GENERIC, NULL);
        z_owned_string_t reason;
        rc = wz_ext_e2e_sender_protect(tx, 0, plan_payload[i], plan_len[i], frames[i], size, &frame_len[i], NULL,
                                       &reason);
        if (rc != Z_OK) return refused("protect", rc, &reason);
        if (frame_len[i] > *longest) *longest = frame_len[i];
        printf("frame %zu ", i);
        print_hex(frames[i], frame_len[i]);
        printf("\n");
    }
    return 0;
}

static int make_sender(wz_ext_owned_e2e_sender_t *sender) {
    char *profile = read_file("profile.json");
    char *values = read_file("values.json");
    if (profile == NULL || values == NULL) return refused("profile.json or values.json", _Z_ERR_GENERIC, NULL);
    wz_ext_e2e_sender_options_t options;
    wz_ext_e2e_sender_options_default(&options);
    options.first_counter = param_u64("first_counter", 0);
    z_owned_string_t reason;
    z_result_t rc = wz_ext_e2e_sender_new(sender, profile, values, &options, &reason);
    free(profile);
    free(values);
    if (rc != Z_OK) return refused("e2e sender", rc, &reason);
    return 0;
}

static int make_receiver(wz_ext_owned_e2e_receiver_t *receiver) {
    char *profile = read_file("profile.json");
    char *values = read_file("values.json");
    if (profile == NULL || values == NULL) return refused("profile.json or values.json", _Z_ERR_GENERIC, NULL);
    z_owned_string_t reason;
    z_result_t rc = wz_ext_e2e_receiver_new(receiver, profile, values, NULL, &reason);
    free(profile);
    free(values);
    if (rc != Z_OK) return refused("e2e receiver", rc, &reason);
    return 0;
}

/* ---- send ------------------------------------------------------------------------------ */

/* Under segmented, every frame put goes out as the pieces this cutter writes, each under the
 * next transfer number; puts_done numbers the puts in the transcript. */
static wz_ext_owned_segment_sender_t live_cutter;
static int live_cut;
static size_t live_chunk;
static size_t puts_done;

typedef struct {
    const z_loaned_publisher_t *publisher;
    size_t put;
    size_t piece;
} live_piece_t;

static z_result_t put_piece(void *context, const uint8_t *piece, size_t len) {
    live_piece_t *at = context;
    printf("piece %zu %zu ", at->put, at->piece);
    print_hex(piece, len);
    printf("\n");
    at->piece++;
    z_owned_bytes_t payload;
    z_bytes_copy_from_buf(&payload, piece, len);
    return z_publisher_put(at->publisher, z_bytes_move(&payload), NULL);
}

static int make_live_cutter(void) {
    char *profile = read_file("segment-profile.json");
    char *values = read_file("segment-values.json");
    live_chunk = (size_t)param_u64("chunk_bytes", 0);
    if (profile == NULL || values == NULL || live_chunk == 0) {
        return refused("segment-profile.json, segment-values.json or chunk_bytes", _Z_ERR_GENERIC, NULL);
    }
    z_owned_string_t reason;
    z_result_t rc = wz_ext_segment_sender_new(&live_cutter, profile, values, param_u64("first_transfer", 0),
                                              WZ_EXT_SEGMENT_ROLLOVER_REFUSE, &reason);
    free(profile);
    free(values);
    if (rc != Z_OK) return refused("segment sender", rc, &reason);
    live_cut = 1;
    return 0;
}

static void put_frame(const z_loaned_publisher_t *publisher, const uint8_t *frame, size_t len) {
    if (live_cut) {
        live_piece_t at = {publisher, puts_done, 0};
        wz_ext_segment_result_t result;
        z_owned_string_t reason;
        z_result_t rc = wz_ext_segment_sender_split(wz_ext_segment_sender_loan(&live_cutter), frame, len, live_chunk,
                                                    put_piece, &at, &result, &reason);
        if (rc != Z_OK) refused("split", rc, &reason);
    } else {
        z_owned_bytes_t payload;
        z_bytes_copy_from_buf(&payload, frame, len);
        z_publisher_put(publisher, z_bytes_move(&payload), NULL);
    }
    puts_done++;
}

static int role_send(const z_loaned_session_t *session, const char *key) {
    wz_ext_owned_e2e_sender_t sender;
    int status = make_sender(&sender);
    if (status != 0) return status;
    size_t longest = 0;
    status = protect_plan(wz_ext_e2e_sender_loan(&sender), &longest);
    wz_ext_e2e_sender_drop(wz_ext_e2e_sender_move(&sender));
    if (status != 0) return status;
    if (param_u64("segmented", 0) != 0) {
        status = make_live_cutter();
        if (status != 0) return status;
    }

    z_view_keyexpr_t ke;
    if (z_view_keyexpr_from_str(&ke, key) != Z_OK) return refused("key", _Z_ERR_GENERIC, NULL);
    char probe_key[1024];
    snprintf(probe_key, sizeof probe_key, "%s/probe", key);
    z_view_keyexpr_t probe_ke;
    if (z_view_keyexpr_from_str(&probe_ke, probe_key) != Z_OK) return refused("probe key", _Z_ERR_GENERIC, NULL);
    z_owned_publisher_t publisher;
    z_result_t rc = z_declare_publisher(session, &publisher, z_view_keyexpr_loan(&ke), NULL);
    if (rc != Z_OK) return refused("publisher", rc, NULL);
    printf("ready\n");

    /* Probes until the lane has seen the receiver hear one: from then on a frame put is a
     * frame the receiver is subscribed to. */
    int go = 0;
    for (int waited = 0; waited < WAIT_MS && !(go = file_exists("go")); waited += 50) {
        z_owned_bytes_t probe;
        z_bytes_copy_from_str(&probe, "probe");
        z_put(session, z_view_keyexpr_loan(&probe_ke), z_bytes_move(&probe), NULL);
        z_sleep_ms(50);
    }
    if (!go) {
        printf("timeout go\n");
        z_undeclare_publisher(z_publisher_move(&publisher));
        return 1;
    }

    const z_loaned_publisher_t *pub = z_publisher_loan(&publisher);
    for (size_t i = 0; i < plan_count; i++) {
        const char *action = plan_action[i];
        if (strcmp(action, "send") == 0) {
            put_frame(pub, frames[i], frame_len[i]);
        } else if (strcmp(action, "twice") == 0) {
            put_frame(pub, frames[i], frame_len[i]);
            put_frame(pub, frames[i], frame_len[i]);
        } else if (strcmp(action, "corrupt") == 0) {
            /* The copy with its last byte XOR 0x01 first, then the frame it stood for. */
            uint8_t *copy = malloc(frame_len[i] == 0 ? 1 : frame_len[i]);
            if (copy != NULL && frame_len[i] > 0) {
                memcpy(copy, frames[i], frame_len[i]);
                copy[frame_len[i] - 1] ^= 0x01;
                put_frame(pub, copy, frame_len[i]);
            }
            free(copy);
            put_frame(pub, frames[i], frame_len[i]);
        } else if (strcmp(action, "hold") != 0) {
            printf("refused plan action %s\n", action);
            z_undeclare_publisher(z_publisher_move(&publisher));
            return 2;
        }
    }
    printf("sent\n");
    int stopped = wait_for_file("stop");
    z_undeclare_publisher(z_publisher_move(&publisher));
    if (live_cut) wz_ext_segment_sender_drop(wz_ext_segment_sender_move(&live_cutter));
    printf(stopped ? "done\n" : "timeout stop\n");
    return stopped ? 0 : 1;
}

/* ---- receive --------------------------------------------------------------------------- */

static wz_ext_owned_e2e_receiver_t receiver;
static z_clock_t started;

static void on_frame(z_loaned_sample_t *sample, void *arg) {
    (void)arg;
    z_owned_slice_t slice;
    if (z_bytes_to_slice(z_sample_payload(sample), &slice) != Z_OK) return;
    const uint8_t *data = z_slice_data(z_slice_loan(&slice));
    size_t len = z_slice_len(z_slice_loan(&slice));
    wz_ext_e2e_verdict_t verdict;
    memset(&verdict, 0, sizeof verdict);
    uint64_t now_ms = (uint64_t)z_clock_elapsed_ms(&started);
    z_result_t rc = wz_ext_e2e_receiver_judge(wz_ext_e2e_receiver_loan(&receiver), 0, data, len, now_ms, &verdict);
    if (rc == Z_OK && verdict.payload_offset + verdict.payload_len <= len) {
        seen_add(class_of(verdict.status), data + verdict.payload_offset, verdict.payload_len);
    } else {
        seen_add("other", data, 0);
    }
    z_slice_drop(z_slice_move(&slice));
}

static void on_probe(z_loaned_sample_t *sample, void *arg) {
    (void)sample;
    (void)arg;
    z_mutex_lock(z_mutex_loan_mut(&seen.lock));
    seen.probe = 1;
    z_mutex_unlock(z_mutex_loan_mut(&seen.lock));
}

static int probe_seen(void) {
    z_mutex_lock(z_mutex_loan_mut(&seen.lock));
    int probe = seen.probe;
    z_mutex_unlock(z_mutex_loan_mut(&seen.lock));
    return probe;
}

/* What a replay subscriber hands on: its replies for the ask role, its live samples (joined
 * from their pieces under segmented) for a receiver of pieces. */
static int record_live;

static void on_replay(void *context, const wz_ext_replay_sample_t *sample) {
    (void)context;
    int wanted = record_live ? sample->from_replay == 0 : sample->from_replay == 1;
    if (!wanted) return;
    if (sample->judged == 1 && sample->verdict.payload_offset + sample->verdict.payload_len <= sample->len) {
        seen_add(class_of(sample->verdict.status), sample->frame + sample->verdict.payload_offset,
                 sample->verdict.payload_len);
    } else {
        seen_add("other", sample->frame, 0);
    }
}

static void on_replay_drop(void *context) { (void)context; }

static wz_ext_replay_publisher_slot_t replay_slots[4];
static uint8_t *held_store;

/* A replay subscriber of keyexpr judging by the receiver, which it takes: the ask role's,
 * and, with record_live, the receiver of pieces, which is the one wz door that joins them. */
static int make_replay_subscriber(const z_loaned_session_t *session, const z_loaned_keyexpr_t *keyexpr, int live,
                                  wz_ext_owned_replay_subscriber_t *subscriber) {
    const char *suffix = param("suffix");
    if (suffix == NULL) return refused("suffix", _Z_ERR_GENERIC, NULL);
    char *segment_profile = NULL;
    if (param_u64("segmented", 0) != 0) {
        segment_profile = read_file("segment-profile.json");
        if (segment_profile == NULL) return refused("segment-profile.json", _Z_ERR_GENERIC, NULL);
    }
    size_t held_cell = (size_t)param_u64("frame_max", 65536);
    size_t held_len = 8 * (4 + held_cell);
    held_store = malloc(held_len);
    if (held_store == NULL) return refused("held store", _Z_ERR_GENERIC, NULL);
    wz_ext_replay_subscriber_options_t options;
    wz_ext_replay_subscriber_options_default(&options);
    options.slots = replay_slots;
    options.slot_count = sizeof replay_slots / sizeof replay_slots[0];
    options.held = held_store;
    options.held_len = held_len;
    options.held_cell = held_cell;
    options.depth = (size_t)param_u64("depth", 1);
    options.progress_ms = 3000;
    options.round_ms = 20000;
    options.segment_profile = segment_profile;
    record_live = live;
    z_result_t rc = wz_ext_replay_subscriber_new(subscriber, session, keyexpr, suffix,
                                                 wz_ext_e2e_receiver_move(&receiver), &options, on_replay,
                                                 on_replay_drop, NULL);
    free(segment_profile);
    if (rc != Z_OK) return refused("replay subscriber", rc, NULL);
    return 0;
}

static int role_receive(const z_loaned_session_t *session, const char *key) {
    int status = make_receiver(&receiver);
    if (status != 0) return status;
    size_t expect = (size_t)param_u64("expect", 0);
    if (expect == 0 || expect > MAX_FRAMES) return refused("expect", _Z_ERR_GENERIC, NULL);
    int pieces = param_u64("segmented", 0) != 0;

    z_view_keyexpr_t ke;
    if (z_view_keyexpr_from_str(&ke, key) != Z_OK) return refused("key", _Z_ERR_GENERIC, NULL);
    char probe_key[1024];
    snprintf(probe_key, sizeof probe_key, "%s/probe", key);
    z_view_keyexpr_t probe_ke;
    if (z_view_keyexpr_from_str(&probe_ke, probe_key) != Z_OK) return refused("probe key", _Z_ERR_GENERIC, NULL);

    /* Whole frames are judged as they arrive; pieces are joined first, by the replay
     * subscriber, on a suffix no cache serves, so it asks nobody and hands on live frames. */
    z_owned_subscriber_t frame_subscriber;
    wz_ext_owned_replay_subscriber_t joiner;
    z_result_t rc;
    if (pieces) {
        status = make_replay_subscriber(session, z_view_keyexpr_loan(&ke), 1, &joiner);
        if (status != 0) return status;
    } else {
        z_owned_closure_sample_t frame_closure;
        z_closure_sample(&frame_closure, on_frame, NULL, NULL);
        rc = z_declare_subscriber(session, &frame_subscriber, z_view_keyexpr_loan(&ke),
                                  z_closure_sample_move(&frame_closure), NULL);
        if (rc != Z_OK) return refused("subscriber", rc, NULL);
    }
    z_owned_closure_sample_t probe_closure;
    z_closure_sample(&probe_closure, on_probe, NULL, NULL);
    z_owned_subscriber_t probe_subscriber;
    rc = z_declare_subscriber(session, &probe_subscriber, z_view_keyexpr_loan(&probe_ke),
                              z_closure_sample_move(&probe_closure), NULL);
    if (rc != Z_OK) {
        if (pieces) {
            wz_ext_replay_subscriber_drop(wz_ext_replay_subscriber_move(&joiner));
        } else {
            z_subscriber_drop(z_subscriber_move(&frame_subscriber));
        }
        return refused("probe subscriber", rc, NULL);
    }
    printf("ready\n");

    int probe_told = 0;
    int waited = 0;
    for (; waited < WAIT_MS && seen_count() < expect; waited += STEP_MS) {
        if (!probe_told && probe_seen()) {
            printf("probe\n");
            probe_told = 1;
        }
        if (pieces) wz_ext_replay_subscriber_poll(wz_ext_replay_subscriber_loan(&joiner));
        z_sleep_ms(STEP_MS);
    }
    z_subscriber_drop(z_subscriber_move(&probe_subscriber));
    if (pieces) {
        wz_ext_replay_subscriber_counts_t counts;
        memset(&counts, 0, sizeof counts);
        wz_ext_replay_subscriber_counts(wz_ext_replay_subscriber_loan(&joiner), &counts);
        wz_ext_replay_subscriber_drop(wz_ext_replay_subscriber_move(&joiner));
        free(held_store);
        printf("counts given_up=%llu unjoined=%llu\n", (unsigned long long)counts.frames_given_up,
               (unsigned long long)counts.unjoined_pieces);
    } else {
        z_subscriber_drop(z_subscriber_move(&frame_subscriber));
        wz_ext_e2e_receiver_drop(wz_ext_e2e_receiver_move(&receiver));
    }
    print_seen();
    if (seen_count() < expect) {
        printf("timeout %zu of %zu\n", seen_count(), expect);
        return 1;
    }
    printf("done\n");
    return 0;
}

/* ---- serve ----------------------------------------------------------------------------- */

typedef struct {
    size_t frame;
    size_t piece;
} piece_place_t;

static z_result_t print_piece(void *context, const uint8_t *piece, size_t len) {
    piece_place_t *place = context;
    printf("piece %zu %zu ", place->frame, place->piece);
    print_hex(piece, len);
    printf("\n");
    place->piece++;
    return Z_OK;
}

/* The pieces each frame is cut into under the check's segment profile, numbered from its
 * first transfer as a first answer numbers them. */
static int print_pieces(const char *segment_profile, const char *segment_values, uint64_t first_transfer,
                        size_t chunk_bytes) {
    wz_ext_owned_segment_sender_t splitter;
    z_owned_string_t reason;
    z_result_t rc = wz_ext_segment_sender_new(&splitter, segment_profile, segment_values, first_transfer,
                                              WZ_EXT_SEGMENT_ROLLOVER_REFUSE, &reason);
    if (rc != Z_OK) return refused("segment sender", rc, &reason);
    int status = 0;
    for (size_t i = 0; i < plan_count && status == 0; i++) {
        piece_place_t place = {i, 0};
        wz_ext_segment_result_t result;
        rc = wz_ext_segment_sender_split(wz_ext_segment_sender_loan(&splitter), frames[i], frame_len[i], chunk_bytes,
                                         print_piece, &place, &result, &reason);
        if (rc != Z_OK) status = refused("split", rc, &reason);
    }
    wz_ext_segment_sender_drop(wz_ext_segment_sender_move(&splitter));
    return status;
}

static int role_serve(const z_loaned_session_t *session, const char *key) {
    const char *suffix = param("suffix");
    if (suffix == NULL) return refused("suffix", _Z_ERR_GENERIC, NULL);
    int segmented = param_u64("segmented", 0) != 0;
    char *segment_profile = NULL;
    char *segment_values = NULL;
    uint64_t first_transfer = param_u64("first_transfer", 0);
    size_t chunk_bytes = (size_t)param_u64("chunk_bytes", 0);
    if (segmented) {
        segment_profile = read_file("segment-profile.json");
        segment_values = read_file("segment-values.json");
        if (segment_profile == NULL || segment_values == NULL || chunk_bytes == 0) {
            return refused("segment-profile.json, segment-values.json or chunk_bytes", _Z_ERR_GENERIC, NULL);
        }
    }

    wz_ext_owned_e2e_sender_t sender;
    int status = make_sender(&sender);
    if (status != 0) return status;
    size_t longest = 0;
    status = protect_plan(wz_ext_e2e_sender_loan(&sender), &longest);
    wz_ext_e2e_sender_drop(wz_ext_e2e_sender_move(&sender));
    if (status != 0) return status;
    if (segmented) {
        status = print_pieces(segment_profile, segment_values, first_transfer, chunk_bytes);
        if (status != 0) return status;
    }

    z_view_keyexpr_t ke;
    if (z_view_keyexpr_from_str(&ke, key) != Z_OK) return refused("key", _Z_ERR_GENERIC, NULL);
    z_owned_publisher_t publisher;
    z_result_t rc = z_declare_publisher(session, &publisher, z_view_keyexpr_loan(&ke), NULL);
    if (rc != Z_OK) return refused("publisher", rc, NULL);

    wz_ext_replay_shape_t shape;
    shape.frame_max = longest == 0 ? 1 : longest;
    shape.depth = (uint32_t)param_u64("depth", plan_count);
    shape.instances = 1;
    size_t storage_len = wz_ext_replay_publisher_storage_size(&shape);
    uint8_t *storage = storage_len == 0 ? NULL : malloc(storage_len);
    if (storage == NULL) {
        z_undeclare_publisher(z_publisher_move(&publisher));
        return refused("replay storage", _Z_ERR_GENERIC, NULL);
    }
    wz_ext_owned_replay_publisher_t cache;
    z_owned_string_t reason;
    rc = wz_ext_replay_publisher_new(&cache, session, z_publisher_loan(&publisher), storage, storage_len, &shape,
                                     &reason);
    if (rc != Z_OK) {
        z_undeclare_publisher(z_publisher_move(&publisher));
        return refused("replay publisher", rc, &reason);
    }
    const wz_ext_loaned_replay_publisher_t *loaned = wz_ext_replay_publisher_loan(&cache);
    for (size_t i = 0; i < plan_count && status == 0; i++) {
        rc = wz_ext_replay_publisher_record(loaned, 0, (uint64_t)(i + 1), frames[i], frame_len[i]);
        if (rc != Z_OK) status = refused("record", rc, NULL);
    }
    if (status == 0) {
        wz_ext_replay_serve_options_t options;
        wz_ext_replay_serve_options_default(&options);
        if (segmented) {
            options.segment_profile = segment_profile;
            options.segment_values = segment_values;
            options.first_transfer = first_transfer;
            options.chunk_bytes = chunk_bytes;
        }
        rc = wz_ext_replay_publisher_serve(loaned, z_view_keyexpr_loan(&ke), suffix, &options, &reason);
        if (rc != Z_OK) status = refused("serve", rc, &reason);
    }
    if (status == 0) {
        printf("ready\n");
        int stopped = wait_for_file("stop");
        wz_ext_replay_publisher_counts_t counts;
        memset(&counts, 0, sizeof counts);
        wz_ext_replay_publisher_counts(loaned, &counts);
        printf("answers %llu\n", (unsigned long long)counts.answers);
        printf(stopped ? "done\n" : "timeout stop\n");
        status = stopped ? 0 : 1;
    }
    wz_ext_replay_publisher_drop(wz_ext_replay_publisher_move(&cache));
    z_undeclare_publisher(z_publisher_move(&publisher));
    free(storage);
    free(segment_profile);
    free(segment_values);
    return status;
}

/* ---- ask ------------------------------------------------------------------------------- */

static const char *round_name(uint8_t phase) {
    switch (phase) {
        case WZ_EXT_REPLAY_ROUND_IDLE:
            return "idle";
        case WZ_EXT_REPLAY_ROUND_ASKING:
            return "asking";
        case WZ_EXT_REPLAY_ROUND_ANSWERING:
            return "answering";
        case WZ_EXT_REPLAY_ROUND_ABANDONED:
            return "abandoned";
        case WZ_EXT_REPLAY_ROUND_LIVE:
            return "live";
        default:
            return "none";
    }
}

static int role_ask(const z_loaned_session_t *session, const char *key) {
    int status = make_receiver(&receiver);
    if (status != 0) return status;
    z_view_keyexpr_t ke;
    if (z_view_keyexpr_from_str(&ke, key) != Z_OK) return refused("key", _Z_ERR_GENERIC, NULL);
    wz_ext_owned_replay_subscriber_t subscriber;
    status = make_replay_subscriber(session, z_view_keyexpr_loan(&ke), 0, &subscriber);
    if (status != 0) return status;
    printf("ready\n");

    const wz_ext_loaned_replay_subscriber_t *loaned = wz_ext_replay_subscriber_loan(&subscriber);
    uint8_t phase = WZ_EXT_REPLAY_ROUND_IDLE;
    for (int waited = 0; waited < WAIT_MS; waited += STEP_MS) {
        wz_ext_replay_subscriber_poll(loaned);
        phase = wz_ext_replay_subscriber_phase(loaned);
        if (phase == WZ_EXT_REPLAY_ROUND_LIVE || phase == WZ_EXT_REPLAY_ROUND_ABANDONED) break;
        z_sleep_ms(STEP_MS);
    }
    wz_ext_replay_subscriber_counts_t counts;
    memset(&counts, 0, sizeof counts);
    wz_ext_replay_subscriber_counts(loaned, &counts);
    wz_ext_replay_subscriber_drop(wz_ext_replay_subscriber_move(&subscriber));
    print_seen();
    printf("round %s\n", round_name(phase));
    printf("counts duplicates=%llu stale=%llu abandoned=%llu given_up=%llu unjoined=%llu\n",
           (unsigned long long)counts.duplicates, (unsigned long long)counts.stale,
           (unsigned long long)counts.abandoned, (unsigned long long)counts.frames_given_up,
           (unsigned long long)counts.unjoined_pieces);
    free(held_store);
    if (phase != WZ_EXT_REPLAY_ROUND_LIVE && phase != WZ_EXT_REPLAY_ROUND_ABANDONED) {
        printf("timeout round\n");
        return 1;
    }
    printf("done\n");
    return 0;
}

/* ---- main ------------------------------------------------------------------------------ */

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc < 5 || (strcmp(argv[3], "connect") == 0 && argc < 6)) {
        fprintf(stderr,
                "usage: %s <send|receive|serve|ask> <check-dir> listen <locator>\n"
                "       %s <send|receive|serve|ask> <check-dir> connect <locator> <client|peer>\n",
                argv[0], argv[0]);
        return 2;
    }
    const char *role = argv[1];
    check_dir = argv[2];
    const char *how = argv[3];
    const char *locator = argv[4];
    const char *mode = argc > 5 ? argv[5] : "client";
    if (strcmp(how, "listen") != 0 && strcmp(how, "connect") != 0) {
        printf("refused endpoint %s\n", how);
        return 2;
    }
    if (!read_params()) return refused("params", _Z_ERR_GENERIC, NULL);
    const char *key = param("key");
    if (key == NULL) return refused("key", _Z_ERR_GENERIC, NULL);
    if (!read_plan()) return refused("plan", _Z_ERR_GENERIC, NULL);
    started = z_clock_now();
    z_mutex_init(&seen.lock);

    z_owned_session_t session;
    int status = open_session(&session, how, locator, mode);
    if (status != 0) return status;
    const z_loaned_session_t *s = z_session_loan(&session);
    if (strcmp(role, "send") == 0) {
        status = role_send(s, key);
    } else if (strcmp(role, "receive") == 0) {
        status = role_receive(s, key);
    } else if (strcmp(role, "serve") == 0) {
        status = role_serve(s, key);
    } else if (strcmp(role, "ask") == 0) {
        status = role_ask(s, key);
    } else {
        printf("refused role %s\n", role);
        status = 2;
    }
    z_close(z_session_loan_mut(&session), NULL);
    z_session_drop(z_session_move(&session));
    return status;
}
