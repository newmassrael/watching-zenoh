/*
 * SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * The POSIX calls zenoh-pico's Unix example programs make beside its API, for MSVC, which has no
 * <unistd.h>: getopt with its four globals, sleep and usleep, and the two calls of <pthread.h> the
 * throughput and latency programs make (pthread_create and pthread_join). Those programs name the
 * thread calls without including <pthread.h> (zenoh-pico's Unix header brings it in), and every one
 * of them includes <unistd.h>, so they are all here.
 *
 * Only scripts/lib/pico_upstream_programs.py puts this directory on the include path, for the
 * programs of examples/unix compiled on Windows; no program of the package or of wz includes it.
 * Everything is static: each program is one translation unit. getopt is the POSIX one without GNU's
 * argument permutation, as the programs' option strings ask for.
 *
 * <windows.h> is included as zenoh-pico's own Windows header includes it (lean, without min and max),
 * so the program's later include of zenoh-pico.h brings in <winsock2.h> without the clash of the old
 * <winsock.h> that a full <windows.h> would have pulled in first.
 */

#ifndef WZ_UPSTREAM_HARNESS_UNISTD_H
#define WZ_UPSTREAM_HARNESS_UNISTD_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <errno.h>
#include <process.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

static char *optarg = NULL;
static int optind = 1;
static int opterr = 1;
static int optopt = 0;
/* Where in argv[optind] the next option letter is: a group such as -ab is read one letter a call. */
static int wz_getopt_at = 1;

static int getopt(int argc, char *const argv[], const char *optstring) {
    const char *spec;
    char letter;
    int quiet = optstring[0] == ':';

    optarg = NULL;
    if (wz_getopt_at == 1) {
        if (optind >= argc || argv[optind] == NULL || argv[optind][0] != '-' || argv[optind][1] == '\0') {
            return -1;
        }
        if (strcmp(argv[optind], "--") == 0) {
            optind++;
            return -1;
        }
    }
    letter = argv[optind][wz_getopt_at];
    spec = letter == ':' ? NULL : strchr(optstring, letter);
    if (spec == NULL) {
        optopt = letter;
        if (opterr && !quiet) {
            fprintf(stderr, "%s: illegal option -- %c\n", argv[0], letter);
        }
        if (argv[optind][++wz_getopt_at] == '\0') {
            optind++;
            wz_getopt_at = 1;
        }
        return '?';
    }
    if (spec[1] != ':') {
        if (argv[optind][++wz_getopt_at] == '\0') {
            optind++;
            wz_getopt_at = 1;
        }
        return letter;
    }
    if (argv[optind][wz_getopt_at + 1] != '\0') {
        optarg = &argv[optind][wz_getopt_at + 1];
        optind++;
    } else if (optind + 1 < argc) {
        optarg = argv[optind + 1];
        optind += 2;
    } else {
        optopt = letter;
        optind++;
        wz_getopt_at = 1;
        if (opterr && !quiet) {
            fprintf(stderr, "%s: option requires an argument -- %c\n", argv[0], letter);
        }
        return quiet ? ':' : '?';
    }
    wz_getopt_at = 1;
    return letter;
}

static unsigned int sleep(unsigned int seconds) {
    Sleep((DWORD)seconds * 1000u);
    return 0;
}

static int usleep(unsigned int microseconds) {
    Sleep((DWORD)((microseconds + 999u) / 1000u));
    return 0;
}

typedef HANDLE pthread_t;

typedef struct {
    void *(*body)(void *);
    void *arg;
} wz_pthread_start_t;

static unsigned __stdcall wz_pthread_trampoline(void *raw) {
    wz_pthread_start_t start = *(wz_pthread_start_t *)raw;
    free(raw);
    (void)start.body(start.arg);
    return 0;
}

static int pthread_create(pthread_t *thread, const void *attr, void *(*body)(void *), void *arg) {
    wz_pthread_start_t *start;
    uintptr_t handle;

    (void)attr;
    start = (wz_pthread_start_t *)malloc(sizeof *start);
    if (start == NULL) {
        return ENOMEM;
    }
    start->body = body;
    start->arg = arg;
    handle = _beginthreadex(NULL, 0, wz_pthread_trampoline, start, 0, NULL);
    if (handle == 0) {
        free(start);
        return EAGAIN;
    }
    *thread = (HANDLE)handle;
    return 0;
}

static int pthread_join(pthread_t thread, void **result) {
    if (WaitForSingleObject(thread, INFINITE) != WAIT_OBJECT_0) {
        return EINVAL;
    }
    CloseHandle(thread);
    if (result != NULL) {
        *result = NULL;
    }
    return 0;
}

#endif /* WZ_UPSTREAM_HARNESS_UNISTD_H */
