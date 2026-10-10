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
/* ARCHITECTURE section 9.1 -- hand a frame to the sender in place, from the pieces
 * of its pbuf chain, and take the chain back when the sender reports it done. */
typedef struct {
    const u8_t *ptr;
    u16_t len;
} wz_ethif_seg;
typedef int (*wz_ethif_tx_gather_fn)(void *ctx, const wz_ethif_seg *segs, u16_t n,
                                     u32_t cookie);
void wz_ethif_set_gather(struct netif *n, wz_ethif_tx_gather_fn gather);
void wz_ethif_tx_done(u32_t cookie);
int wz_ethif_held_count(void);
int wz_ethif_held_refs(u32_t cookie);
/* ARCHITECTURE section 9.2 -- take a received frame lent in place by the MAC, and
 * tell the MAC when lwIP no longer reads it. */
typedef void (*wz_ethif_rx_release_fn)(void *ctx, u32_t cookie);
void wz_ethif_set_rx_release(struct netif *n, wz_ethif_rx_release_fn release);
int wz_ethif_input_loan(struct netif *n, const u8_t *frame, u16_t len, u32_t cookie);
int wz_ethif_rx_held_count(void);
u32_t wz_ethif_rx_loaned_total(void);
/* How many received frames the copying input took, and whether a pbuf is a frame
 * lent in place (which a socket may hold instead of copying). */
u32_t wz_ethif_rx_copied_total(void);
int wz_ethif_rx_is_lent(const struct pbuf *p);
/* Whether `n` is the default route, and the test harness's reset of the table. */
int wz_ethif_is_default(const struct netif *n);
void wz_ethif_remove_all(void);

/* R2841 — a link's two ends: the routed source address, the bound port. */
u32_t wz_lwip_route_src(u32_t dst);
u16_t wz_lwip_udp_local_port(const struct udp_pcb *pcb);

/* ARCHITECTURE section 9.1 — a payload pbuf lent to a sender to write a datagram
 * into, counted so a leak shows. */
struct pbuf *wz_lwip_tx_pbuf_alloc(u16_t len);
void wz_lwip_tx_pbuf_free(struct pbuf *p);
u32_t wz_lwip_tx_pbufs_out(void);
/* ARCHITECTURE section 9.1 -- a pbuf whose memory is one transmit pool slot. The
 * free callback is spelt out rather than named by lwIP's typedef, which a port
 * without custom pbufs does not declare. */
u16_t wz_lwip_tx_slot_capacity(u16_t slot_len);
struct pbuf *wz_lwip_tx_slot_pbuf(void *slot, u16_t slot_len, u16_t len,
                                  void (*free_fn)(struct pbuf *p));
