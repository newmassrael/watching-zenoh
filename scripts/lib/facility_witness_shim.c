// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// The witness shim of scripts/lib/facility_trace.py (docs/target-build-contract.md T9): an
// LD_PRELOAD library that makes visible to a system-call trace what the trace cannot see itself.
//
// A calendar-time read goes through the vDSO and makes no system call, so the shim marks it. The
// C library's interface listing and name resolution are made of system calls that do not say what
// they are for (a netlink socket, a read of /etc/hosts), so the shim brackets them as a SCOPE and
// the tracer gives what happens inside to the facility the scope names. The C library reads
// /proc/self/maps to find the main thread's stack, which is bracketed the same way.
//
// A mark is a faccessat(2) of a path under /wz-facility-witness/, which exists nowhere: the call
// fails with ENOENT, changes nothing, and is ordered with the thread's other calls in its trace.
// A point mark is made once per process; a scope is marked every time, since what it brackets is
// what it attributes.

#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define MARK_ROOT "/wz-facility-witness/"

static void mark(const char *path) {
    // The answer is always ENOENT and is not the point: the call is.
    if (faccessat(AT_FDCWD, path, F_OK, 0) == 0) {
        return;
    }
}

static void mark_once(atomic_int *done, const char *path) {
    if (!atomic_exchange(done, 1)) {
        mark(path);
    }
}

static atomic_int wall_clock_marked;

static int is_calendar_clock(clockid_t id) {
    return id == CLOCK_REALTIME || id == CLOCK_REALTIME_COARSE || id == CLOCK_TAI;
}

int clock_gettime(clockid_t id, struct timespec *ts) {
    static int (*real)(clockid_t, struct timespec *);
    if (!real) {
        real = (int (*)(clockid_t, struct timespec *))dlsym(RTLD_NEXT, "clock_gettime");
    }
    if (is_calendar_clock(id)) {
        mark_once(&wall_clock_marked, MARK_ROOT "point/wall-clock");
    }
    return real(id, ts);
}

int gettimeofday(struct timeval *restrict tv, void *restrict tz) {
    static int (*real)(struct timeval *restrict, void *restrict);
    if (!real) {
        real = (int (*)(struct timeval *restrict, void *restrict))dlsym(RTLD_NEXT, "gettimeofday");
    }
    mark_once(&wall_clock_marked, MARK_ROOT "point/wall-clock");
    return real(tv, tz);
}

time_t time(time_t *out) {
    static time_t (*real)(time_t *);
    if (!real) {
        real = (time_t(*)(time_t *))dlsym(RTLD_NEXT, "time");
    }
    mark_once(&wall_clock_marked, MARK_ROOT "point/wall-clock");
    return real(out);
}

int getifaddrs(struct ifaddrs **out) {
    static int (*real)(struct ifaddrs **);
    if (!real) {
        real = (int (*)(struct ifaddrs **))dlsym(RTLD_NEXT, "getifaddrs");
    }
    mark(MARK_ROOT "enter/interface-list");
    int rc = real(out);
    mark(MARK_ROOT "leave/interface-list");
    return rc;
}

unsigned int if_nametoindex(const char *name) {
    static unsigned int (*real)(const char *);
    if (!real) {
        real = (unsigned int (*)(const char *))dlsym(RTLD_NEXT, "if_nametoindex");
    }
    mark(MARK_ROOT "enter/interface-list");
    unsigned int index = real(name);
    mark(MARK_ROOT "leave/interface-list");
    return index;
}

char *if_indextoname(unsigned int index, char name[IF_NAMESIZE]) {
    static char *(*real)(unsigned int, char *);
    if (!real) {
        real = (char *(*)(unsigned int, char *))dlsym(RTLD_NEXT, "if_indextoname");
    }
    mark(MARK_ROOT "enter/interface-list");
    char *out = real(index, name);
    mark(MARK_ROOT "leave/interface-list");
    return out;
}

int getaddrinfo(const char *restrict node, const char *restrict service,
                const struct addrinfo *restrict hints, struct addrinfo **restrict res) {
    static int (*real)(const char *restrict, const char *restrict, const struct addrinfo *restrict,
                       struct addrinfo **restrict);
    if (!real) {
        real = (int (*)(const char *restrict, const char *restrict, const struct addrinfo *restrict,
                        struct addrinfo **restrict))dlsym(RTLD_NEXT, "getaddrinfo");
    }
    mark(MARK_ROOT "enter/name-resolution");
    int rc = real(node, service, hints, res);
    mark(MARK_ROOT "leave/name-resolution");
    return rc;
}

int pthread_getattr_np(pthread_t thread, pthread_attr_t *attr) {
    static int (*real)(pthread_t, pthread_attr_t *);
    if (!real) {
        real = (int (*)(pthread_t, pthread_attr_t *))dlsym(RTLD_NEXT, "pthread_getattr_np");
    }
    mark(MARK_ROOT "enter/thread-stack-probe");
    int rc = real(thread, attr);
    mark(MARK_ROOT "leave/thread-stack-probe");
    return rc;
}
