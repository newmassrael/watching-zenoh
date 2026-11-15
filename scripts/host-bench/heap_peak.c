// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// The heap a process held at its worst, for the host side of the parity matrix
// (docs/upstream-parity.md section 5b). It is preloaded (LD_PRELOAD) into a program of either arm,
// the original and wz alike, so the two are counted by the same code: both libraries and the
// programs above them allocate through the C library's allocator (no crate of either side installs
// a global allocator of its own), and this file stands in front of it.
//
//   cc -O2 -shared -fPIC -o heap_peak.so heap_peak.c
//   HEAP_PEAK_FILE=<file> LD_PRELOAD=heap_peak.so <program> ...
//
// What it counts: the bytes of every block the program holds, as the allocator gives them
// (`malloc_usable_size`, which is at least what was asked for), summed; the peak of that sum over
// the life of the program, and the number of blocks it obtained. The figures live in <file>, a page
// mapped shared, two little-endian 64-bit words: the peak, then the count. They are written as they
// move and not at exit, because the programs of the matrix are ended by a signal (a subscriber, a
// queryable and a publisher of the throughput pair run until they are stopped), and a signal runs
// no exit handler.
//
// Each program the preload reaches truncates the file when it starts: a launcher that executes the
// program (taskset, stdbuf) leaves the program's figures, not its own.
//
// What it does not count: memory a library maps itself (mmap), thread stacks, and the allocator's
// own overhead and free lists. RSS (getrusage) is the cell that sees those.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <malloc.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

extern void *__libc_malloc(size_t size);
extern void *__libc_calloc(size_t count, size_t size);
extern void *__libc_realloc(void *ptr, size_t size);
extern void __libc_free(void *ptr);
extern void *__libc_memalign(size_t alignment, size_t size);
extern void *__libc_valloc(size_t size);
extern void *__libc_pvalloc(size_t size);

struct figures {
    _Atomic int64_t peak;
    _Atomic int64_t blocks;
};

// Until the constructor maps the file (the loader and the constructors that run before it allocate
// too), the figures are kept here and copied over when the file is mapped.
static struct figures early;
static struct figures *figures = &early;
// What the program holds now. It is not in the file: only the peak is a figure of the run.
static _Atomic int64_t live;

static void account(int64_t delta) {
    const int64_t now = atomic_fetch_add_explicit(&live, delta, memory_order_relaxed) + delta;
    if (delta <= 0) {
        return;
    }
    int64_t seen = atomic_load_explicit(&figures->peak, memory_order_relaxed);
    while (now > seen && !atomic_compare_exchange_weak_explicit(&figures->peak, &seen, now, memory_order_relaxed,
                                                                memory_order_relaxed)) {
    }
}

static void *obtained(void *block) {
    if (block != NULL) {
        atomic_fetch_add_explicit(&figures->blocks, 1, memory_order_relaxed);
        account((int64_t)malloc_usable_size(block));
    }
    return block;
}

void *malloc(size_t size) { return obtained(__libc_malloc(size)); }

void *calloc(size_t count, size_t size) { return obtained(__libc_calloc(count, size)); }

void free(void *block) {
    if (block != NULL) {
        account(-(int64_t)malloc_usable_size(block));
        __libc_free(block);
    }
}

void *realloc(void *block, size_t size) {
    if (block == NULL) {
        return obtained(__libc_realloc(NULL, size));
    }
    const int64_t before = (int64_t)malloc_usable_size(block);
    void *moved = __libc_realloc(block, size);
    if (moved != NULL) {
        account((int64_t)malloc_usable_size(moved) - before);
    } else if (size == 0) {
        // The C library frees the block and returns nothing for a size of zero.
        account(-before);
    }
    // A failed realloc leaves the block where it was: nothing moved.
    return moved;
}

int posix_memalign(void **out, size_t alignment, size_t size) {
    if (alignment % sizeof(void *) != 0 || (alignment & (alignment - 1)) != 0) {
        return EINVAL;
    }
    void *block = obtained(__libc_memalign(alignment, size));
    if (block == NULL) {
        return ENOMEM;
    }
    *out = block;
    return 0;
}

void *aligned_alloc(size_t alignment, size_t size) { return obtained(__libc_memalign(alignment, size)); }

void *memalign(size_t alignment, size_t size) { return obtained(__libc_memalign(alignment, size)); }

void *valloc(size_t size) { return obtained(__libc_valloc(size)); }

void *pvalloc(size_t size) { return obtained(__libc_pvalloc(size)); }

__attribute__((constructor)) static void map_figures(void) {
    const char *path = getenv("HEAP_PEAK_FILE");
    if (path == NULL || *path == '\0') {
        return;
    }
    const int fd = open(path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) {
        return;
    }
    if (ftruncate(fd, (off_t)sizeof(struct figures)) != 0) {
        close(fd);
        return;
    }
    void *page = mmap(NULL, sizeof(struct figures), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (page == MAP_FAILED) {
        return;
    }
    struct figures *mapped = page;
    atomic_store_explicit(&mapped->peak, atomic_load_explicit(&early.peak, memory_order_relaxed),
                          memory_order_relaxed);
    atomic_store_explicit(&mapped->blocks, atomic_load_explicit(&early.blocks, memory_order_relaxed),
                          memory_order_relaxed);
    figures = mapped;
}
