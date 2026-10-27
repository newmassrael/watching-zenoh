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
//
// An interface request (an ioctl whose request is one of the SIOCGIF* family, as a raw link's
// SIOCGIFINDEX) is a system call the trace sees by itself; the shim brackets it too, so that it can
// be denied like the listing it is the other half of.
//
// A scenario can also DENY a facility the shim brackets (WZ_FACILITY_DENY, a comma-separated list
// of facility words): the scope is still marked, so the trace shows the run asked, and the call
// fails as it fails on a device that refuses it (EACCES; EAI_FAIL for a resolution). A run denied a
// facility its configuration does not require has to go on, and one denied a facility it requires
// has to fail: the must analysis, held to a run.

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define MARK_ROOT "/wz-facility-witness/"

// Whether the run's WZ_FACILITY_DENY names `facility`.
static int denied(const char *facility) {
    const char *list = getenv("WZ_FACILITY_DENY");
    size_t want = strlen(facility);
    while (list && *list) {
        const char *end = strchr(list, ',');
        size_t len = end ? (size_t)(end - list) : strlen(list);
        if (len == want && !strncmp(list, facility, want)) {
            return 1;
        }
        list = end ? end + 1 : NULL;
    }
    return 0;
}

static void mark(const char *path) {
    // The answer is always ENOENT and is not the point: the call is. The caller's errno is what the
    // bracketed call left, so the mark leaves it as it found it.
    int saved = errno;
    if (faccessat(AT_FDCWD, path, F_OK, 0) == 0) {
        errno = saved;
        return;
    }
    errno = saved;
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

// A local time reads the zone database (/etc/localtime) inside the C library: that read is the
// calendar's, so the conversion is a scope of `wall-clock` and not a file the program asked for.
struct tm *localtime(const time_t *t) {
    static struct tm *(*real)(const time_t *);
    if (!real) {
        real = (struct tm * (*)(const time_t *)) dlsym(RTLD_NEXT, "localtime");
    }
    mark(MARK_ROOT "enter/wall-clock");
    struct tm *out = real(t);
    mark(MARK_ROOT "leave/wall-clock");
    return out;
}

struct tm *localtime_r(const time_t *restrict t, struct tm *restrict out) {
    static struct tm *(*real)(const time_t *restrict, struct tm *restrict);
    if (!real) {
        real = (struct tm * (*)(const time_t *restrict, struct tm *restrict)) dlsym(RTLD_NEXT, "localtime_r");
    }
    mark(MARK_ROOT "enter/wall-clock");
    struct tm *got = real(t, out);
    mark(MARK_ROOT "leave/wall-clock");
    return got;
}

void tzset(void) {
    static void (*real)(void);
    if (!real) {
        real = (void (*)(void))dlsym(RTLD_NEXT, "tzset");
    }
    mark(MARK_ROOT "enter/wall-clock");
    real();
    mark(MARK_ROOT "leave/wall-clock");
}

int getifaddrs(struct ifaddrs **out) {
    static int (*real)(struct ifaddrs **);
    if (!real) {
        real = (int (*)(struct ifaddrs **))dlsym(RTLD_NEXT, "getifaddrs");
    }
    mark(MARK_ROOT "enter/interface-list");
    if (denied("interface-list")) {
        mark(MARK_ROOT "leave/interface-list");
        errno = EACCES;
        return -1;
    }
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
    if (denied("interface-list")) {
        mark(MARK_ROOT "leave/interface-list");
        errno = EACCES;
        return 0;
    }
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
    if (denied("interface-list")) {
        mark(MARK_ROOT "leave/interface-list");
        errno = EACCES;
        return NULL;
    }
    char *out = real(index, name);
    mark(MARK_ROOT "leave/interface-list");
    return out;
}

// The interface requests of <linux/sockios.h>: every request strace names SIOCGIF*, which is what
// facility_trace.py reads as an interface request when it sees one outside a scope.
static int is_interface_request(unsigned long request) {
    static const unsigned long requests[] = {
        SIOCGIFNAME,    SIOCGIFCONF,  SIOCGIFFLAGS, SIOCGIFADDR,  SIOCGIFDSTADDR, SIOCGIFBRDADDR,
        SIOCGIFNETMASK, SIOCGIFMETRIC, SIOCGIFMEM,  SIOCGIFMTU,   SIOCGIFENCAP,   SIOCGIFHWADDR,
        SIOCGIFSLAVE,   SIOCGIFINDEX, SIOCGIFPFLAGS, SIOCGIFCOUNT, SIOCGIFTXQLEN, SIOCGIFMAP,
    };
    for (size_t i = 0; i < sizeof requests / sizeof requests[0]; i++) {
        if (request == requests[i]) {
            return 1;
        }
    }
    return 0;
}

// Every ioctl takes at most one argument after the request, a pointer or an integer the width of
// one, so it is read and passed on as a pointer, as the C library's own wrappers do.
int ioctl(int fd, unsigned long request, ...) {
    static int (*real)(int, unsigned long, ...);
    if (!real) {
        real = (int (*)(int, unsigned long, ...))dlsym(RTLD_NEXT, "ioctl");
    }
    va_list rest;
    va_start(rest, request);
    void *arg = va_arg(rest, void *);
    va_end(rest);
    if (!is_interface_request(request)) {
        return real(fd, request, arg);
    }
    mark(MARK_ROOT "enter/interface-list");
    if (denied("interface-list")) {
        mark(MARK_ROOT "leave/interface-list");
        errno = EACCES;
        return -1;
    }
    int rc = real(fd, request, arg);
    mark(MARK_ROOT "leave/interface-list");
    return rc;
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
    if (denied("name-resolution")) {
        mark(MARK_ROOT "leave/name-resolution");
        return EAI_FAIL;
    }
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
