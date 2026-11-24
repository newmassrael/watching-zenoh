/*
 * SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * Linked beside a zenoh-pico program that starts its own threads with `_z_task_init` and joins them
 * with `_z_task_join` (`tests/z_test_peer_unicast.c`), when scripts/lib/pico_upstream_programs.py
 * builds it against the library under test. The two are zenoh-pico's system layer and not its API:
 * a drop-in for the API owes neither, and wz's does not export them. They are defined here as
 * zenoh-pico's own system layer defines them (`vendor/zenoh-pico/src/system/unix/system.c` and
 * `src/system/windows/system.c`), so the program's text is unchanged. The control links zenoh-pico,
 * which has its own, and does not take this unit.
 */

#include "zenoh-pico.h"

#if Z_FEATURE_MULTI_THREAD == 1

#if defined(_WIN32)

z_result_t _z_task_init(_z_task_t *task, z_task_attr_t *attr, void *(*fun)(void *), void *arg) {
    (void)attr;
    *task = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)fun, arg, 0, NULL);
    return *task != NULL ? _Z_RES_OK : _Z_ERR_GENERIC;
}

z_result_t _z_task_join(_z_task_t *task) {
    WaitForSingleObject(*task, INFINITE);
    return _Z_RES_OK;
}

#else

#include <pthread.h>

z_result_t _z_task_init(_z_task_t *task, z_task_attr_t *attr, void *(*fun)(void *), void *arg) {
    return pthread_create(task, attr, fun, arg) == 0 ? _Z_RES_OK : _Z_ERR_GENERIC;
}

z_result_t _z_task_join(_z_task_t *task) { return pthread_join(*task, NULL) == 0 ? _Z_RES_OK : _Z_ERR_GENERIC; }

#endif

#endif
