/*
 * SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * A keyed topic: one key expression whose samples are several INSTANCES of one message, told
 * apart by a field of the payload, with the last value of each instance kept.
 *
 * The message is a protobuf message of the program's own .proto text, made up for this
 * example:
 *
 *     message Reading { uint32 sensor = 1; uint32 level = 2; }
 *
 * A KEYER (wz_ext_instance_keyer_*) is made over that text and a description that names
 * `sensor` as the key field with the values 7 and 9: a reading of sensor 7 is instance 0 and
 * one of sensor 9 instance 1, though both are published on the one key expression
 * example/keyed/reading. The instance is never on the wire. The subscribing program hands each
 * payload to the keyer, which reads the key field through the schema and keeps the payload as
 * its instance's last value, in storage the program gives it.
 *
 * The publishing session sends, in order, (sensor, level):
 *     (7, 10) (9, 20) (7, 11) (8, 99) (9, 21) (7, 12)
 * and the subscribing side finds:
 *     instance 0, sensor 7   three readings, the last one level 12
 *     instance 1, sensor 9   two readings, the last one level 21
 *     sensor 8               no instance: the keyer drops it and counts it as a value in no
 *                            list, naming the key field (0, the first of the description)
 * A sample of no instance is the program's to discard; the keyer counts the drops by reason
 * and reports them at the interval the description states.
 *
 * Built against the library with the instance-key capability.
 */

#define EXAMPLE_NAME "example-keyed"

#include <zenoh-pico.h>

#include "wz_ext.h"

#include "example_common.h"

static const char *const SCHEMA =
    "syntax = \"proto3\";\n"
    "package example.keyed;\n"
    "message Reading {\n"
    "  uint32 sensor = 1;\n"
    "  uint32 level = 2;\n"
    "}\n";

static const char *const DESCRIPTION =
    "{\"message\": \"example.keyed.Reading\","
    " \"fields\": [{\"path\": \"sensor\", \"values\": [7, 9]}],"
    " \"report_interval_ms\": 1000}";

/* A description the schema cannot satisfy: the message has no field `room`. */
static const char *const WRONG_DESCRIPTION =
    "{\"message\": \"example.keyed.Reading\","
    " \"fields\": [{\"path\": \"room\", \"values\": [1, 2]}],"
    " \"report_interval_ms\": 1000}";

#define INSTANCES 2
/* The room of one instance's last value: an encoded Reading is at most 12 bytes. */
#define VALUE_ROOM 16
#define READINGS 6

static const uint32_t SENT_SENSOR[READINGS] = {7, 9, 7, 8, 9, 7};
static const uint32_t SENT_LEVEL[READINGS] = {10, 20, 11, 99, 21, 12};

static wz_ext_owned_instance_keyer_t keyer;
static uint8_t last_values[INSTANCES * VALUE_ROOM];
static z_clock_t started;
static ex_counter_t probes;

/* What the subscriber's callback learned of each reading. */
static struct {
    z_owned_mutex_t lock;
    int seen;
    int indexed[INSTANCES];
    int dropped;
    uint8_t drop_status;
    uint32_t drop_field;
    int unexpected;
} keyed;

/* A varint as protobuf writes it; how many bytes it took. */
static size_t put_varint(uint8_t *out, uint32_t value) {
    size_t n = 0;
    while (value >= 0x80) {
        out[n++] = (uint8_t)(value | 0x80);
        value >>= 7;
    }
    out[n++] = (uint8_t)value;
    return n;
}

/* A Reading as protobuf lays it out: field 1, then field 2, each a varint (wire type 0). */
static size_t encode_reading(uint8_t *out, uint32_t sensor, uint32_t level) {
    size_t n = 0;
    out[n++] = (uint8_t)(1 << 3);
    n += put_varint(out + n, sensor);
    out[n++] = (uint8_t)(2 << 3);
    n += put_varint(out + n, level);
    return n;
}

/* The refusal a door wrote, printed and dropped; nothing for the null state. */
static void show_refusal(const char *door, z_owned_string_t *refusal) {
    if (!z_internal_string_check(refusal)) return;
    printf("%s: %s refused: %.*s\n", EXAMPLE_NAME, door, (int)z_string_len(z_string_loan(refusal)),
           z_string_data(z_string_loan(refusal)));
    z_string_drop(z_string_move(refusal));
}

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
    /* Which instance the payload is, read through the schema; an indexed payload becomes its
     * instance's last value. The keyer has a lock of its own, so any thread may call it. */
    wz_ext_instance_key_t key;
    z_result_t rc = wz_ext_instance_keyer_index(wz_ext_instance_keyer_loan(&keyer), data, len,
                                                (uint64_t)z_clock_elapsed_ms(&started), &key);
    z_mutex_lock(z_mutex_loan_mut(&keyed.lock));
    keyed.seen++;
    if (rc != Z_OK) {
        keyed.unexpected++;
    } else if (key.status == WZ_EXT_INSTANCE_KEY_INDEXED) {
        if (key.instance < (size_t)INSTANCES && key.last == WZ_EXT_INSTANCE_KEY_LAST_RECORDED) {
            keyed.indexed[key.instance]++;
        } else {
            keyed.unexpected++;
        }
    } else {
        keyed.dropped++;
        keyed.drop_status = key.status;
        keyed.drop_field = key.field;
    }
    z_mutex_unlock(z_mutex_loan_mut(&keyed.lock));
    z_slice_drop(z_slice_move(&slice));
}

static int seen_count(void) {
    z_mutex_lock(z_mutex_loan_mut(&keyed.lock));
    int n = keyed.seen;
    z_mutex_unlock(z_mutex_loan_mut(&keyed.lock));
    return n;
}

/* Put an encoded Reading on the key every instance shares. */
static void publish(const z_loaned_session_t *session, uint32_t sensor, uint32_t level) {
    uint8_t payload[VALUE_ROOM];
    size_t len = encode_reading(payload, sensor, level);
    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, "example/keyed/reading");
    z_owned_bytes_t bytes;
    z_bytes_copy_from_buf(&bytes, payload, len);
    z_put(session, z_view_keyexpr_loan(&ke), z_bytes_move(&bytes), NULL);
}

/* Whether instance `instance` holds the encoding of (sensor, level) as its last value. */
static int last_is(const wz_ext_loaned_instance_keyer_t *k, size_t instance, uint32_t sensor, uint32_t level) {
    uint8_t expected[VALUE_ROOM];
    size_t expected_len = encode_reading(expected, sensor, level);
    uint8_t value[VALUE_ROOM];
    size_t value_len = 0;
    if (wz_ext_instance_keyer_last(k, instance, value, sizeof value, &value_len) != Z_OK) return 0;
    return value_len == expected_len && memcmp(value, expected, expected_len) == 0;
}

int main(void) {
    started = z_clock_now();
    z_mutex_init(&keyed.lock);
    ex_counter_init(&probes);

    /* The keyer: the program's .proto files (one here; a file another imports is named by
     * the name it is imported by), the description of the key, and the storage of the last
     * values, VALUE_ROOM bytes for each instance, which stays the program's memory. */
    wz_ext_proto_file_t files[1];
    files[0].name = "example_keyed.proto";
    files[0].text = SCHEMA;
    wz_ext_instance_keyer_options_t options;
    wz_ext_instance_keyer_options_default(&options);
    options.storage = last_values;
    options.storage_len = sizeof last_values;
    options.value_capacity = VALUE_ROOM;

    /* Refused by name: a description that names a field the message does not have. */
    wz_ext_owned_instance_keyer_t wrong;
    z_owned_string_t refusal;
    z_result_t rc = wz_ext_instance_keyer_new(&wrong, files, 1, WRONG_DESCRIPTION, &options, &refusal);
    show_refusal("wz_ext_instance_keyer_new", &refusal);
    CHECK(rc == _Z_ERR_CONFIG_INVALID_VALUE, "a description of a field the schema lacks was not refused (rc %d)",
          (int)rc);
    CHECK(!wz_ext_internal_instance_keyer_check(&wrong), "a refused keyer is not the null state");

    rc = wz_ext_instance_keyer_new(&keyer, files, 1, DESCRIPTION, &options, &refusal);
    show_refusal("wz_ext_instance_keyer_new", &refusal);
    CHECK(rc == Z_OK, "the keyer was refused (rc %d)", (int)rc);
    if (!wz_ext_internal_instance_keyer_check(&keyer)) return ex_finish();
    const wz_ext_loaned_instance_keyer_t *k = wz_ext_instance_keyer_loan(&keyer);
    size_t instances = 0;
    CHECK(wz_ext_instance_keyer_instances(k, &instances) == Z_OK && instances == INSTANCES,
          "the keyer makes %zu instances, not %d", instances, INSTANCES);

    /* Before anything arrived: no last value yet, and no instance past the lists. */
    uint8_t value[VALUE_ROOM];
    size_t value_len = 99;
    CHECK(wz_ext_instance_keyer_last(k, 0, value, sizeof value, &value_len) == Z_CHANNEL_NODATA && value_len == 0,
          "instance 0 had a last value before its first reading");
    CHECK(wz_ext_instance_keyer_last(k, INSTANCES, value, sizeof value, &value_len) == Z_EINVAL,
          "an instance the keyer has not was not refused");

    char locator[64];
    snprintf(locator, sizeof locator, "tcp/127.0.0.1:%u", ex_port());
    z_owned_session_t listener;
    rc = ex_open_listener(&listener, locator);
    CHECK(rc == Z_OK, "the listener did not open on %s (rc %d)", locator, (int)rc);
    if (rc == Z_OK) {
        z_owned_closure_sample_t closure;
        z_closure_sample(&closure, on_sample, NULL, NULL);
        z_view_keyexpr_t ke;
        z_view_keyexpr_from_str(&ke, "example/keyed/**");
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
                ex_put(s, "example/keyed/probe", "probe", NULL);
                z_sleep_ms(25);
            }
            CHECK(ex_counter_get(&probes) > 0, "the subscriber was never handed a put");

            for (int n = 0; n < READINGS; n++) publish(s, SENT_SENSOR[n], SENT_LEVEL[n]);
            for (int i = 0; i < 500 && seen_count() < READINGS; i++) z_sleep_ms(10);
            CHECK(seen_count() == READINGS, "%d of %d readings arrived", seen_count(), READINGS);

            z_mutex_lock(z_mutex_loan_mut(&keyed.lock));
            CHECK(keyed.indexed[0] == 3, "instance 0 (sensor 7) was handed %d readings, not 3", keyed.indexed[0]);
            CHECK(keyed.indexed[1] == 2, "instance 1 (sensor 9) was handed %d readings, not 2", keyed.indexed[1]);
            CHECK(keyed.dropped == 1, "%d readings were dropped, not the one of sensor 8", keyed.dropped);
            CHECK(keyed.drop_status == WZ_EXT_INSTANCE_KEY_NOT_LISTED && keyed.drop_field == 0,
                  "the reading of sensor 8 was dropped with status %u field %u, not as a value in no list of field 0",
                  (unsigned)keyed.drop_status, (unsigned)keyed.drop_field);
            CHECK(keyed.unexpected == 0, "%d readings were indexed in a way the example does not expect",
                  keyed.unexpected);
            z_mutex_unlock(z_mutex_loan_mut(&keyed.lock));

            /* The last value of each instance, copied out of the program's storage. */
            CHECK(last_is(k, 0, 7, 12), "the last value of instance 0 is not sensor 7 level 12");
            CHECK(last_is(k, 1, 9, 21), "the last value of instance 1 is not sensor 9 level 21");
            uint64_t undecodable = 99, absent = 99, not_listed = 99;
            CHECK(wz_ext_instance_keyer_counts(k, &undecodable, &absent, &not_listed) == Z_OK, "counts");
            CHECK(undecodable == 0 && absent == 0 && not_listed == 1,
                  "the drops counted are %llu undecodable, %llu absent, %llu not listed, not 0, 0, 1",
                  (unsigned long long)undecodable, (unsigned long long)absent, (unsigned long long)not_listed);
            /* A copy into too little room says how long the value is. */
            value_len = 0;
            CHECK(wz_ext_instance_keyer_last(k, 0, value, 1, &value_len) == _Z_ERR_OVERFLOW && value_len > 1,
                  "a copy into one byte was not refused with the value's length");
            ex_close(&dialer);
        }
        z_subscriber_drop(z_subscriber_move(&subscriber));
        ex_close(&listener);
    }

    /* The storage of the last values is the program's again once the keyer is dropped. */
    wz_ext_instance_keyer_drop(wz_ext_instance_keyer_move(&keyer));
    CHECK(!wz_ext_internal_instance_keyer_check(&keyer), "a dropped keyer is not the null state");
    ex_counter_drop(&probes);
    z_mutex_drop(z_mutex_move(&keyed.lock));
    return ex_finish();
}
