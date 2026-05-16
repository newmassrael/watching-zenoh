/* SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * wz_runtime_lwip.h — per-driver factory + state declarations for
 * the watching-zenoh MCU bare_metal link runtime.
 *
 * The SCE B6 link-kind C11 emitter produces a wrapper struct
 * (`<snake>_link_t`) per `<scxml sce:kind="link">` that composes a
 * `sce_forge_link_t` driver handle. The driver handle is opaque to
 * the wrapper — its `ops` vtable and `self` payload live here, in
 * this crate's translation unit. The factory function below builds
 * the driver handle (vtable + per-instance state) the wrapper then
 * receives via `<snake>_link_init`.
 *
 * R53 vertical slice. The state struct and factory exist; their
 * function bodies (in `sce_link_runtime_lwip.c`) are NOP stubs.
 * Actual lwIP API wiring (udp_recv / udp_sendto / etc.) lands when
 * the MCU cross-compile toolchain is plumbed end-to-end (R55+).
 */

#ifndef WZ_RUNTIME_LWIP_H
#define WZ_RUNTIME_LWIP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sce/forge/link.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Per-instance lwIP UDP driver state. The wrapper sees only the
 * `sce_forge_link_t` view; this struct is the underlying `self`
 * that ops callbacks downcast back to. The R53 host-build skeleton
 * keeps every field plain to avoid pulling lwIP headers into the
 * Linux host build; the MCU build will add per-target `pcb` / `pbuf`
 * fields when the cross-compile plumbing lands. */
typedef struct {
    /* Stable counters the smoke tests inspect to verify the contract
     * is wired. Each ops callback bumps the matching counter; this
     * is the only externally visible side effect on the host build. */
    uint32_t rx_calls;
    uint32_t tx_calls;
    uint32_t poll_calls;
    /* TX policy mirrors the codegen-emitted backpressure macro so
     * the stub can return the policy-appropriate status code from
     * `tx()` without the wrapper threading the macro through. */
    sce_forge_link_status_t tx_default_status;
} wz_lwip_udp_state_t;

/* Factory: build a `sce_forge_link_t` view backed by the supplied
 * per-instance state and the runtime's shared `sce_forge_link_ops_t`
 * vtable. The vtable is `static const` inside the .c file (lives in
 * .rodata on MCU per the contract in `sce/forge/link.h`).
 *
 * Caller responsibility (R53 host-build skeleton): supply storage
 * for `state` (static / stack / heap depending on caller class) and
 * keep it alive while the returned handle is in use. The wrapper
 * struct stores the handle by value, so the lifetime invariant is
 * "wrapper must not outlive caller-provided state". */
sce_forge_link_t wz_lwip_udp_make_driver(wz_lwip_udp_state_t *state);

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif /* WZ_RUNTIME_LWIP_H */
