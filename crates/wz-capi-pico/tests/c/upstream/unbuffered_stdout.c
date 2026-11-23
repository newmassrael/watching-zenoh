/*
 * SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * Linked beside every zenoh-pico program scripts/lib/pico_upstream_programs.py runs: the standard
 * output and error of the program are unbuffered from before its main runs.
 *
 * The runner reads what a program printed from a file. The C library buffers a stream that is not
 * a terminal in blocks, and several of zenoh-pico's programs only end when they are stopped (a
 * subscriber, a queryable, a pong), which writes no buffered block out. Unbuffered, every line is in
 * the file when the program prints it, so a stopped program is read as surely as one that returned.
 * The program's own text is not changed; this unit runs at start-up, as a C++ static initializer
 * runs, through the C runtime's own initializer table on MSVC and a constructor elsewhere.
 */

#include <stdio.h>

static void wz_upstream_harness_unbuffered(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

#if defined(_MSC_VER)
/* The C runtime calls every pointer of the .CRT$XCU section before main. The pointer is a global
 * definition so neither the compiler nor the linker drops it as unreferenced. */
#pragma section(".CRT$XCU", read)
__declspec(allocate(".CRT$XCU")) void (*const wz_upstream_harness_unbuffered_at_start)(void) =
    wz_upstream_harness_unbuffered;
#else
__attribute__((constructor)) static void wz_upstream_harness_unbuffered_at_start(void) {
    wz_upstream_harness_unbuffered();
}
#endif
