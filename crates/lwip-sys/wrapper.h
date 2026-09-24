/* SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * lwip-sys bindgen umbrella header. Pulls in the public lwIP headers
 * that the allowlist references. Bindgen follows the `-I` paths
 * (vendor/lwip/src/include + lwip-sys/port/include) to resolve the
 * transitive includes.
 *
 * R311az-1 minimum surface: init + netif lifecycle + udp raw API +
 * pbuf + ip4_addr + sys_check_timeouts (NO_SYS=1 timer pump).
 *
 * R311ir: + igmp.h (multicast scouting RX — igmp_joingroup /
 * igmp_leavegroup) + ip4.h (ip4_set_default_multicast_netif).
 */

#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/udp.h"
#include "lwip/pbuf.h"
#include "lwip/timeouts.h"
#include "lwip/ip_addr.h"
#include "lwip/ip4_addr.h"
#include "lwip/ip4.h"
#include "lwip/igmp.h"
#include "lwip/err.h"

/* R2390 — the netif carrier seam, defined in `shim.c` beside the lwIP sources.
 * Declared here so bindgen emits it; both halves are C macros in lwIP, so
 * neither can be reached from Rust (see shim.c for what measured that).
 */
int wz_lwip_any_link_up(void);
void wz_lwip_set_all_links(int up);

/* R2835 — the Ethernet netif seam, defined in `shim.c`: a netif whose MAC is
 * a Rust driver behind `tx`, and the input path for the frames it receives.
 */
typedef int (*wz_ethif_tx_fn)(void *ctx, const u8_t *frame, u16_t len);
struct netif *wz_ethif_add(const u8_t *mac, u32_t ip, u32_t mask, u32_t gw,
                           wz_ethif_tx_fn tx, void *ctx);
int wz_ethif_input(struct netif *n, const u8_t *frame, u16_t len);

/* R2841 — a link's two ends: the routed source address, the bound port. */
u32_t wz_lwip_route_src(u32_t dst);
u16_t wz_lwip_udp_local_port(const struct udp_pcb *pcb);
