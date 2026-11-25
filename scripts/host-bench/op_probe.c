// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// One OPERATION of the zenoh-pico C API, done a stated number of times spread evenly over a stated time,
// for the instructions one operation costs (scripts/pico-compare.sh opprofile). The same source is built
// once against zenoh-pico and once against libwz_capi_pico, so the two counts are of the libraries.
//
//   op_probe -o OP -m peer (-e ENDPOINT | -l ENDPOINT) [-n COUNT] [-t SECONDS] [-w SECONDS] [-s SIZE]
//            [-k KEY] [-d SECONDS]
//
// OP is one of
//   put          a publisher's put of SIZE bytes (the publisher declared once, before the count);
//   get          a get and the wait for its final notification (the replies are counted);
//   declare-sub  a subscriber declared and undeclared;
//   declare-pub  a publisher declared and undeclared;
//   declare-qbl  a queryable declared and undeclared;
//   open         a configuration made, a session opened to ENDPOINT and closed;
//   none         nothing: the loop alone, whose cost the others carry too;
//   queryable    no count: a queryable on KEY that answers each query with SIZE bytes, for -d SECONDS.
// Every OP but open and queryable opens one session first and waits -w SECONDS (1) for the peer's
// declarations before the count; a key is KEY (thr, which count_sub listens on).
//
// The count is spread over -t SECONDS (10): operation i starts at i * SECONDS / COUNT, and after the last
// the program sleeps to the end of SECONDS, so two runs of different counts take the same time and what a
// session does by the clock (its lease, its keep-alives) is the same in both. The waits sleep: a spin
// would be counted as instructions. Two runs under callgrind then differ by the operations alone. An
// operation that starts a slot or more late is counted in late=, and a run with late operations did not
// keep the time equal. The last line is
//
//   op_probe op=<OP> done=<operations that returned 0> failed=<that did not> late=<n> replies=<n>
//
// or, for queryable, op_probe op=queryable answered=<queries answered>.
//
// The wait of a get and the counters use POSIX threads and C11 atomics, not the library's own mutex and
// condition variable, so the library under test pays for neither. It needs a library of more than one
// thread (Z_FEATURE_MULTI_THREAD 1): a single-threaded one has no task that would read the reply.
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "bench_api.h"

#if Z_FEATURE_MULTI_THREAD == 1 && Z_FEATURE_PUBLICATION == 1 && Z_FEATURE_SUBSCRIPTION == 1 && \
    Z_FEATURE_QUERY == 1 && Z_FEATURE_QUERYABLE == 1

static const char *mode = "peer";
static const char *connect_to = NULL;
static const char *listen_on = NULL;
static const char *keyexpr = "thr";
static size_t size = 8;

static z_owned_session_t session;
static z_view_keyexpr_t key;
static z_owned_publisher_t publisher;
static z_owned_bytes_t payload;
static uint8_t *reply_data;

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t final_seen = PTHREAD_COND_INITIALIZER;
static int final_done;
static _Atomic unsigned long replies;
static _Atomic unsigned long answered;

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void sleep_until(uint64_t target_ns) {
    const struct timespec ts = {(time_t)(target_ns / 1000000000ULL), (long)(target_ns % 1000000000ULL)};
    while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL) == EINTR) {
    }
}

static int make_config(z_owned_config_t *config) {
    z_config_default(config);
    if (BENCH_CONFIG_INSERT(*config, Z_CONFIG_MODE_KEY, mode) < 0 ||
        (connect_to != NULL && BENCH_CONFIG_INSERT(*config, Z_CONFIG_CONNECT_KEY, connect_to) < 0) ||
        (listen_on != NULL && BENCH_CONFIG_INSERT(*config, Z_CONFIG_LISTEN_KEY, listen_on) < 0)) {
        z_drop(z_move(*config));
        return -1;
    }
    return 0;
}

static void free_with_context(void *ptr, void *context) {
    (void)context;
    z_free(ptr);
}

static void on_sample(z_loaned_sample_t *sample, void *context) {
    (void)sample;
    (void)context;
}

static void on_query_ignored(z_loaned_query_t *query, void *context) {
    (void)query;
    (void)context;
}

static void on_query(z_loaned_query_t *query, void *context) {
    (void)context;
    z_owned_bytes_t reply;
    if (z_bytes_copy_from_buf(&reply, reply_data, size) < 0) return;
    if (z_query_reply(query, z_query_keyexpr(query), z_move(reply), NULL) == 0) {
        atomic_fetch_add_explicit(&answered, 1, memory_order_relaxed);
    }
}

static void on_reply(z_loaned_reply_t *reply, void *context) {
    (void)context;
    if (z_reply_is_ok(reply)) atomic_fetch_add_explicit(&replies, 1, memory_order_relaxed);
}

static void on_reply_final(void *context) {
    (void)context;
    pthread_mutex_lock(&lock);
    final_done = 1;
    pthread_cond_signal(&final_seen);
    pthread_mutex_unlock(&lock);
}

static int op_none(void) { return 0; }

static int op_put(void) {
    z_owned_bytes_t p;
    z_bytes_clone(&p, z_loan(payload));
    return z_publisher_put(z_loan(publisher), z_move(p), NULL) == 0 ? 0 : -1;
}

static int op_get(void) {
    z_owned_closure_reply_t callback;
    z_closure(&callback, on_reply, on_reply_final, NULL);
    z_get_options_t options;
    z_get_options_default(&options);
    pthread_mutex_lock(&lock);
    final_done = 0;
    pthread_mutex_unlock(&lock);
    if (z_get(z_loan(session), z_loan(key), "", z_move(callback), &options) < 0) return -1;
    pthread_mutex_lock(&lock);
    while (!final_done) pthread_cond_wait(&final_seen, &lock);
    pthread_mutex_unlock(&lock);
    return 0;
}

static int op_declare_sub(void) {
    z_owned_closure_sample_t callback;
    z_closure(&callback, on_sample, NULL, NULL);
    z_owned_subscriber_t sub;
    if (z_declare_subscriber(z_loan(session), &sub, z_loan(key), z_move(callback), NULL) < 0) return -1;
    return z_undeclare_subscriber(z_move(sub)) == 0 ? 0 : -1;
}

static int op_declare_pub(void) {
    z_publisher_options_t options;
    z_publisher_options_default(&options);
    z_owned_publisher_t pub;
    if (z_declare_publisher(z_loan(session), &pub, z_loan(key), &options) < 0) return -1;
    return z_undeclare_publisher(z_move(pub)) == 0 ? 0 : -1;
}

static int op_declare_qbl(void) {
    z_owned_closure_query_t callback;
    z_closure(&callback, on_query_ignored, NULL, NULL);
    z_owned_queryable_t queryable;
    if (z_declare_queryable(z_loan(session), &queryable, z_loan(key), z_move(callback), NULL) < 0) return -1;
    return z_undeclare_queryable(z_move(queryable)) == 0 ? 0 : -1;
}

static int op_open(void) {
    z_owned_config_t config;
    if (make_config(&config) < 0) return -1;
    z_owned_session_t opened;
    if (z_open(&opened, z_move(config), NULL) < 0) return -1;
    z_drop(z_move(opened));
    return 0;
}

static const struct {
    const char *name;
    int (*run)(void);
} OPS[] = {
    {"none", op_none},
    {"put", op_put},
    {"get", op_get},
    {"declare-sub", op_declare_sub},
    {"declare-pub", op_declare_pub},
    {"declare-qbl", op_declare_qbl},
    {"open", op_open},
};

static int usage(void) {
    fprintf(stderr,
            "usage: op_probe -o OP -m peer (-e ENDPOINT | -l ENDPOINT) [-n COUNT] [-t SECONDS] [-w SECONDS] "
            "[-s SIZE] [-k KEY] [-d SECONDS]\n");
    return 2;
}

int main(int argc, char **argv) {
    const char *op = NULL;
    unsigned long count = 1000;
    unsigned seconds = 10;
    unsigned settle = 1;
    unsigned listen_s = 10;
    int opt;
    while ((opt = getopt(argc, argv, "o:m:e:l:n:t:w:s:k:d:")) != -1) {
        switch (opt) {
            case 'o':
                op = optarg;
                break;
            case 'm':
                mode = optarg;
                break;
            case 'e':
                connect_to = optarg;
                break;
            case 'l':
                listen_on = optarg;
                break;
            case 'n':
                count = strtoul(optarg, NULL, 10);
                break;
            case 't':
                seconds = (unsigned)strtoul(optarg, NULL, 10);
                break;
            case 'w':
                settle = (unsigned)strtoul(optarg, NULL, 10);
                break;
            case 's':
                size = (size_t)strtoul(optarg, NULL, 10);
                break;
            case 'k':
                keyexpr = optarg;
                break;
            case 'd':
                listen_s = (unsigned)strtoul(optarg, NULL, 10);
                break;
            default:
                return usage();
        }
    }
    if (op == NULL || size == 0) return usage();
    int (*run)(void) = NULL;
    for (size_t i = 0; i < sizeof OPS / sizeof OPS[0]; i++) {
        if (strcmp(op, OPS[i].name) == 0) run = OPS[i].run;
    }
    const int serve = strcmp(op, "queryable") == 0;
    if (run == NULL && !serve) return usage();
    if (z_view_keyexpr_from_str(&key, keyexpr) < 0) {
        printf("op_probe: %s is not a key expression\n", keyexpr);
        return 1;
    }

    const int opens = run == op_open;
    if (!opens) {
        z_owned_config_t config;
        if (make_config(&config) < 0 || z_open(&session, z_move(config), NULL) < 0) {
            printf("op_probe: unable to open the session\n");
            return 1;
        }
    }
    if (serve) {
        reply_data = (uint8_t *)malloc(size);
        if (reply_data == NULL) return 1;
        memset(reply_data, 1, size);
        z_owned_closure_query_t callback;
        z_closure(&callback, on_query, NULL, NULL);
        z_owned_queryable_t queryable;
        if (z_declare_queryable(z_loan(session), &queryable, z_loan(key), z_move(callback), NULL) < 0) {
            printf("op_probe: unable to declare the queryable\n");
            return 1;
        }
        sleep(listen_s);
        printf("op_probe op=queryable answered=%lu\n", atomic_load_explicit(&answered, memory_order_relaxed));
        fflush(stdout);
        z_undeclare_queryable(z_move(queryable));
        z_drop(z_move(session));
        free(reply_data);
        return 0;
    }
    if (!opens) sleep(settle);
    if (run == op_put) {
        z_publisher_options_t options;
        z_publisher_options_default(&options);
        if (z_declare_publisher(z_loan(session), &publisher, z_loan(key), &options) < 0) {
            printf("op_probe: unable to declare the publisher\n");
            return 1;
        }
        uint8_t *value = (uint8_t *)z_malloc(size);
        if (value == NULL) return 1;
        memset(value, 1, size);
        z_bytes_from_buf(&payload, value, size, free_with_context, NULL);
    }

    unsigned long done = 0, failed = 0, late = 0;
    const uint64_t span = (uint64_t)seconds * 1000000000ULL;
    const uint64_t slot = count > 0 ? span / count : span;
    const uint64_t t0 = now_ns();
    for (unsigned long i = 0; i < count; i++) {
        const uint64_t target = t0 + span * i / count;
        const uint64_t now = now_ns();
        if (now < target) {
            sleep_until(target);
        } else if (now - target >= slot) {
            late++;
        }
        if (run() == 0) {
            done++;
        } else {
            failed++;
        }
    }
    sleep_until(t0 + span);
    printf("op_probe op=%s done=%lu failed=%lu late=%lu replies=%lu\n", op, done, failed, late,
           atomic_load_explicit(&replies, memory_order_relaxed));
    fflush(stdout);

    if (run == op_put) {
        z_drop(z_move(publisher));
        z_drop(z_move(payload));
    }
    if (!opens) z_drop(z_move(session));
    return 0;
}

#else
int main(void) {
    printf("op_probe: this library is built without one of multi-threading, publication, subscription, query and "
           "queryable\n");
    return 1;
}
#endif
