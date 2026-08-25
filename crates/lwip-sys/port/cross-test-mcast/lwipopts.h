/* SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * lwip-sys cross-test-mcast lwipopts.h — the cross-test bare-metal NO_SYS port
 * PLUS loopback multicast, so a bare-metal (QEMU / real Cortex-M) multicast
 * build runs a real on-target IGMP-join + multicast-loopback roundtrip.
 *
 * Delta vs the shared `../cross-test/lwipopts.h` (which stays BYTE-IDENTICAL —
 * it feeds 7 CI lanes + the zephyr staticlib, so this port EXTENDS rather than
 * edits it, Open/Closed):
 *   - LWIP_LOOPIF_MULTICAST=1 — the loop netif gains NETIF_FLAG_IGMP so
 *     igmp_joingroup registers the group and ip4_input accepts the looped-back
 *     multicast datagram (without it, ip4_input rejects multicast on loopif).
 *   - LWIP_TESTMODE=1 — exposes netif_get_loopif() so the multicast egress can
 *     be routed over the loop netif (ip4_set_default_multicast_netif); this is
 *     the same pair the HOST port (../include/lwipopts.h) sets.
 *   - runtime-grade pool sizing — cross-test ships compile-check MINIMA; a real
 *     roundtrip holds an in-flight datagram + an IGMP report, so size toward the
 *     host port.
 *
 * SSOT: this file INCLUDES the shared cross-test lwipopts and overrides ONLY the
 * delta above, so the shared bare-metal config has a single source of truth.
 */

#include "../cross-test/lwipopts.h"

/* Loopback multicast: loop_netif gains NETIF_FLAG_IGMP (join registers the
 * group; ip4_input accepts the looped multicast), and netif_get_loopif() is
 * exposed so the multicast TX egress can be routed over the loop netif. */
#define LWIP_LOOPIF_MULTICAST           1
#define LWIP_TESTMODE                   1

/* Runtime-grade pool sizing (override cross-test's compile-check minima). */
#undef MEM_SIZE
#define MEM_SIZE                        16384
#undef MEMP_NUM_PBUF
#define MEMP_NUM_PBUF                   16
#undef PBUF_POOL_SIZE
#define PBUF_POOL_SIZE                  8
/* IGMP report timers + the driver tick + ARP/IP-reass cyclic timers want more
 * than cross-test's compile-check minimum of 4 concurrent sys_timeout slots;
 * match the host port's 8 (completes the "size toward the host port" rationale). */
#undef MEMP_NUM_SYS_TIMEOUT
#define MEMP_NUM_SYS_TIMEOUT            8
