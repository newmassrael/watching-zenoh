/*
 * SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * What the pico C ABI library without std allocates after a session opens, for Layer C1nh. That
 * library brings its own allocator and panic handler, so no Rust test can link it; this program is
 * built against it (scripts/pico-c-program.sh, WZ_PICO_FORM=nostd) in its single-threaded arm and
 * stands in front of the C library's allocator, which the library's allocator calls. Every
 * allocation the process makes from the open of its session to the end of its rounds is counted,
 * with no warm-up left out: a table that grows once at its first use after open is counted too.
 *
 * One session per process, as two single-threaded sessions that dial each other cannot share a
 * thread, so the program is run twice, as two processes on one port:
 *
 *   pico_no_heap_after_open listen <port>   a listening session on tcp/127.0.0.1:<port> with a
 *                                           subscriber; its rounds are the puts it is handed
 *   pico_no_heap_after_open dial <port>     a client of that session that puts; its rounds are
 *                                           its puts
 *
 * Each role prints one line the gate reads (scripts/lib/no_heap_ratchet_gate.py), and appends it
 * to the file WZ_NO_HEAP_READING names when it is set:
 *
 *   no-heap: <family> allocs=<n> bytes=<b> rounds=<r> windows=1 max_allocs=<n> grown=0
 *
 * One window of every round, so the least and the most are one; nothing is left out of it, so no
 * block is kept outside the count and grown is 0. A C library that is not glibc gives no way in
 * front of its allocator here, and the role prints its family as not-built.
 *
 * Exit status 0 means every check of the role held. Each role gives up after a bound of its own,
 * so a run never hangs its caller.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zenoh-pico.h>

/* The families this program reads, one a role; --declared reads their names from these lines. */
#define NO_HEAP_FAMILY_LISTEN "nostd-subscriber"
#define NO_HEAP_FAMILY_DIAL "nostd-put"

#if defined(__GLIBC__)
/* The C library's own allocator, which the definitions below stand in front of. */
extern void *__libc_malloc(size_t size);
extern void *__libc_calloc(size_t count, size_t size);
extern void *__libc_realloc(void *ptr, size_t size);
extern void *__libc_memalign(size_t alignment, size_t size);

static atomic_int counting;
static atomic_ulong counted_allocs;
static atomic_ulong counted_bytes;

static void count(size_t size) {
    if (atomic_load(&counting)) {
        atomic_fetch_add(&counted_allocs, 1);
        atomic_fetch_add(&counted_bytes, (unsigned long)size);
    }
}

void *malloc(size_t size) {
    count(size);
    return __libc_malloc(size);
}

void *calloc(size_t count_of, size_t size) {
    count(count_of * size);
    return __libc_calloc(count_of, size);
}

/* A block grown or moved is an allocation after open as much as a new one. */
void *realloc(void *ptr, size_t size) {
    if (size > 0) count(size);
    return __libc_realloc(ptr, size);
}

void *memalign(size_t alignment, size_t size) {
    count(size);
    return __libc_memalign(alignment, size);
}

void *aligned_alloc(size_t alignment, size_t size) {
    count(size);
    return __libc_memalign(alignment, size);
}

int posix_memalign(void **out, size_t alignment, size_t size) {
    if (alignment == 0 || (alignment & (alignment - 1)) != 0 || alignment % sizeof(void *) != 0) {
        return EINVAL;
    }
    count(size);
    void *block = __libc_memalign(alignment, size);
    if (block == NULL) return ENOMEM;
    *out = block;
    return 0;
}

#define IN_FRONT_OF_THE_ALLOCATOR 1
#else
#define IN_FRONT_OF_THE_ALLOCATOR 0
#endif

#if Z_FEATURE_MULTI_THREAD == 0 && Z_FEATURE_PUBLICATION == 1 && Z_FEATURE_SUBSCRIPTION == 1

#define PUT_KEY "wz/no-heap/put"
#define PUT_PAYLOAD "no-heap-after-open"
/* The puts the dialler makes, and how many of them the listener counts: fewer, as the first puts
 * may leave before the listener's subscriber reached the dialler's write filter. */
#define PUTS 100
#define RECEIVED 50
/* How long a role may run, how long the listener goes on stepping once no put came, and how long
 * the dialler steps after its last put before it closes. */
#define ROLE_BOUND_MS 60000ul
#define LISTEN_QUIET_MS 3000ul
#define DIAL_TAIL_MS 500ul

static const char *role = "?";
static int checks = 0;
static int failures = 0;

#define CHECK(cond, ...)                                                             \
    do {                                                                             \
        checks++;                                                                    \
        if (!(cond)) {                                                               \
            failures++;                                                              \
            printf("pico-no-heap-after-open %s: FAIL at line %d: ", role, __LINE__); \
            printf(__VA_ARGS__);                                                     \
            printf("\n");                                                            \
        }                                                                            \
    } while (0)

/* One turn of the program's own loop over its session: read what arrived (callbacks run here),
 * keep the lease, and run what is due. A closed session is the loop's end. */
static int step(const z_owned_session_t *s) {
    if (zp_read(z_session_loan(s), NULL) < 0) return 0;
    if (zp_send_keep_alive(z_session_loan(s), NULL) < 0) return 0;
    return zp_spin_once(z_session_loan(s)) ? 1 : 0;
}

static void start_counting(void) {
#if IN_FRONT_OF_THE_ALLOCATOR
    atomic_store(&counting, 1);
#endif
}

/* Stop counting, and print the family's line, appended to the reading when one is named; the
 * line is written after the count ends, as writing it allocates. */
static void report(const char *family, int rounds) {
#if IN_FRONT_OF_THE_ALLOCATOR
    atomic_store(&counting, 0);
    unsigned long allocs = atomic_load(&counted_allocs);
    unsigned long bytes = atomic_load(&counted_bytes);
    char line[160];
    snprintf(line, sizeof line, "no-heap: %s allocs=%lu bytes=%lu rounds=%d windows=1 max_allocs=%lu grown=0",
             family, allocs, bytes, rounds, allocs);
#else
    char line[160];
    (void)rounds;
    snprintf(line, sizeof line, "no-heap: %s not-built", family);
#endif
    printf("%s\n", line);
    const char *path = getenv("WZ_NO_HEAP_READING");
    if (path != NULL && path[0] != '\0') {
        FILE *reading = fopen(path, "a");
        CHECK(reading != NULL, "the reading %s cannot be opened", path);
        if (reading != NULL) {
            fprintf(reading, "%s\n", line);
            fclose(reading);
        }
    }
}

/* ---- the listening role ------------------------------------------------------------------- */

static void on_put(z_loaned_sample_t *sample, void *arg) {
    (void)sample;
    (*(int *)arg)++;
}

static void run_listener(const char *locator) {
    int received = 0;
    z_owned_config_t config;
    z_config_default(&config);
    zp_config_insert(z_config_loan_mut(&config), Z_CONFIG_LISTEN_KEY, locator);
    z_owned_session_t s;
    z_result_t opened = z_open(&s, z_config_move(&config), NULL);
    CHECK(opened == Z_OK, "the listening session did not open on %s (rc %d)", locator, (int)opened);
    if (opened != Z_OK) return;
    start_counting();

    z_view_keyexpr_t put_ke;
    z_view_keyexpr_from_str(&put_ke, PUT_KEY);
    z_owned_closure_sample_t on_sample;
    z_closure_sample(&on_sample, on_put, NULL, &received);
    z_owned_subscriber_t sub;
    z_result_t declared = z_declare_subscriber(z_session_loan(&s), &sub, z_view_keyexpr_loan(&put_ke),
                                               z_closure_sample_move(&on_sample), NULL);

    z_clock_t started = z_clock_now();
    int alive = 1;
    while (alive && received < RECEIVED && z_clock_elapsed_ms(&started) < ROLE_BOUND_MS) {
        alive = step(&s);
    }
    int counted = received;
    report(NO_HEAP_FAMILY_LISTEN, counted);
    CHECK(declared == Z_OK, "z_declare_subscriber (rc %d)", (int)declared);
    CHECK(alive, "the session ended under the program's loop");
    CHECK(counted >= RECEIVED, "the subscriber was handed %d put(s) of %d", counted, RECEIVED);

    /* The dialler's last puts and its close come after the count; the session is stepped until
     * nothing has come for a while, so that it closes after the dialler. */
    z_clock_t quiet_since = z_clock_now();
    int last = received;
    while (alive && z_clock_elapsed_ms(&started) < ROLE_BOUND_MS) {
        if (received != last) {
            last = received;
            quiet_since = z_clock_now();
        } else if (z_clock_elapsed_ms(&quiet_since) >= LISTEN_QUIET_MS) {
            break;
        }
        alive = step(&s);
    }
    if (declared == Z_OK) z_subscriber_drop(z_subscriber_move(&sub));
    CHECK(z_close(z_session_loan_mut(&s), NULL) == Z_OK, "z_close");
    z_session_drop(z_session_move(&s));
}

/* ---- the dialling role -------------------------------------------------------------------- */

static void run_dialer(const char *locator) {
    /* The listener is another process, which may not be listening yet: a refused open is tried
     * again. */
    z_owned_session_t s;
    z_result_t opened = -1;
    for (int attempt = 0; attempt < 100 && opened != Z_OK; attempt++) {
        z_owned_config_t config;
        z_config_default(&config);
        zp_config_insert(z_config_loan_mut(&config), Z_CONFIG_MODE_KEY, "client");
        zp_config_insert(z_config_loan_mut(&config), Z_CONFIG_CONNECT_KEY, locator);
        opened = z_open(&s, z_config_move(&config), NULL);
        if (opened != Z_OK) z_sleep_ms(100);
    }
    CHECK(opened == Z_OK, "the dialling session did not open to %s (rc %d)", locator, (int)opened);
    if (opened != Z_OK) return;
    start_counting();

    z_view_keyexpr_t put_ke;
    z_view_keyexpr_from_str(&put_ke, PUT_KEY);
    int puts = 0;
    int refused = 0;
    z_clock_t started = z_clock_now();
    int alive = 1;
    while (alive && puts + refused < PUTS && z_clock_elapsed_ms(&started) < ROLE_BOUND_MS) {
        z_owned_bytes_t payload;
        z_bytes_copy_from_str(&payload, PUT_PAYLOAD);
        if (z_put(z_session_loan(&s), z_view_keyexpr_loan(&put_ke), z_bytes_move(&payload), NULL) == Z_OK) {
            puts++;
        } else {
            refused++;
        }
        alive = step(&s);
    }
    report(NO_HEAP_FAMILY_DIAL, puts);
    CHECK(alive, "the session ended under the program's loop");
    CHECK(refused == 0, "%d put(s) were refused", refused);
    CHECK(puts == PUTS, "%d put(s) of %d were made", puts, PUTS);

    z_clock_t ended = z_clock_now();
    while (alive && z_clock_elapsed_ms(&ended) < DIAL_TAIL_MS) {
        alive = step(&s);
    }
    CHECK(z_close(z_session_loan_mut(&s), NULL) == Z_OK, "z_close");
    z_session_drop(z_session_move(&s));
}

int main(int argc, char **argv) {
    /* Two processes write to one console: unbuffered, so the lines of each come out whole, and
     * the console takes no buffer from the heap while a count runs. */
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc != 3 || (strcmp(argv[1], "listen") != 0 && strcmp(argv[1], "dial") != 0)) {
        printf("usage: %s listen|dial <port>\n", argv[0]);
        return 2;
    }
    role = argv[1];
    int port = atoi(argv[2]);
    if (port <= 0 || port > 65535) {
        printf("pico-no-heap-after-open: the port '%s' is not one\n", argv[2]);
        return 2;
    }
    char locator[64];
    snprintf(locator, sizeof locator, "tcp/127.0.0.1:%d", port);
    if (strcmp(role, "listen") == 0) {
        run_listener(locator);
    } else {
        run_dialer(locator);
    }
    printf("pico-no-heap-after-open %s: %d check(s), %d failure(s)\n", role, checks, failures);
    return failures == 0 ? 0 : 1;
}

#else
int main(void) {
    printf(
        "pico-no-heap-after-open: the library's header arm is not the single-threaded one with "
        "publication and subscription\n");
    return 2;
}
#endif
