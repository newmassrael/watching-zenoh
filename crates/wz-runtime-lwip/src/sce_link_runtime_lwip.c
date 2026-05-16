/* SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * sce_link_runtime_lwip.c — host-build skeleton of the lwIP UDP
 * driver vtable that satisfies the `sce/forge/link.h` contract.
 *
 * R53 vertical slice. The vtable is shape-correct (rx / tx / poll
 * function pointers wired to bodies that bump a counter and return
 * the contract's idle / OK responses). Real lwIP API wiring lands
 * once the MCU cross-compile path is plumbed; the host build is
 * what the smoke tests cover.
 */

#include "wz_runtime_lwip.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* RX callback. Host-build skeleton: no driver-side pending bytes,
 * so always returns `false` without touching `*out`. Real lwIP impl
 * will pull a `pbuf` from the per-link RX queue and project it into
 * `sce_forge_link_rx_frame_t`. */
static bool wz_lwip_udp_rx(void *self, sce_forge_link_rx_frame_t *out) {
    (void)out;
    wz_lwip_udp_state_t *state = (wz_lwip_udp_state_t *)self;
    state->rx_calls += 1;
    return false;
}

/* TX callback. Host-build skeleton: returns the link's configured
 * default status (OK for happy path; tests can construct a state
 * with BACKPRESSURE to exercise the policy path). Real lwIP impl
 * will call `udp_sendto` with the supplied bytes. */
static sce_forge_link_status_t wz_lwip_udp_tx(void *self, sce_forge_link_tx_frame_t frame) {
    (void)frame;
    wz_lwip_udp_state_t *state = (wz_lwip_udp_state_t *)self;
    state->tx_calls += 1;
    return state->tx_default_status;
}

/* Poll callback. Host-build skeleton: counts and returns. Real lwIP
 * impl will drive the cooperative loop's per-link tick (sys_check_
 * timeouts + queue draining bounded by `deadline_us`). */
static void wz_lwip_udp_poll(void *self, uint32_t deadline_us) {
    (void)deadline_us;
    wz_lwip_udp_state_t *state = (wz_lwip_udp_state_t *)self;
    state->poll_calls += 1;
}

/* Shared const vtable. Per `sce/forge/link.h`, this lives in
 * .rodata; per-instance RAM is just `ops + self` (two pointers). */
static const sce_forge_link_ops_t WZ_LWIP_UDP_OPS = {
    .rx   = wz_lwip_udp_rx,
    .tx   = wz_lwip_udp_tx,
    .poll = wz_lwip_udp_poll,
};

sce_forge_link_t wz_lwip_udp_make_driver(wz_lwip_udp_state_t *state) {
    sce_forge_link_t handle = {
        .ops  = &WZ_LWIP_UDP_OPS,
        .self = state,
    };
    return handle;
}
