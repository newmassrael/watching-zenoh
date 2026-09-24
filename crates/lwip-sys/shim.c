/* SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * R2390 — the netif CARRIER seam, in C because it cannot be done in Rust.
 *
 * lwIP reports link state two ways and BOTH are C-only constructs:
 * `netif_is_link_up` is a MACRO over `netif.flags` (lwip/netif.h) and the
 * interface list is walked with the `NETIF_FOREACH` macro, whose expansion
 * differs by port (`netif_list` when `LWIP_SINGLE_NETIF` is 0, `netif_default`
 * when it is 1). Neither survives bindgen.
 *
 * The first attempt walked the struct from Rust -- reading `.flags` and `.next`
 * off the bindgen `netif` -- and gate 2h caught it: in the port a non-default
 * feature build selects, bindgen emits `netif` as an OPAQUE type whose only
 * field is `_address`, so those reads do not compile. That failure is the
 * argument for this file. A Rust-side walk also had to spell `NETIF_FLAG_LINK_UP`
 * as a literal, duplicating an upstream `#define` with nothing to catch a drift;
 * here the macro IS the definition.
 *
 * Compiled by the same `cc::Build` that builds lwIP, so it sees the port's own
 * `lwipopts.h` and the macros expand exactly as they do for lwIP itself.
 */

#include "lwip/netif.h"

/* Non-zero when ANY interface has its carrier up.
 *
 * Zero means every interface is down, which is what a multicast group member
 * experiences as link loss: nothing can leave and nothing can arrive. A
 * disjunction over the whole list rather than a check on one deploy-chosen
 * netif -- a node with a second live interface has not lost its link, and this
 * way the caller needs no handle threaded down to it.
 *
 * An EMPTY list returns zero for the same reason: a node with no netif has no
 * carrier. That is the vacuous arm and not the shape a booted deploy is in --
 * `netif_init()` adds and link-ups the loop netif under `LWIP_HAVE_LOOPIF`,
 * which every port in this tree sets.
 */
int wz_lwip_any_link_up(void) {
    struct netif *n;
    NETIF_FOREACH(n) {
        if (netif_is_link_up(n)) {
            return 1;
        }
    }
    return 0;
}

/* Drive every interface's carrier -- the injector the harness needs.
 *
 * The asymmetry with the reader above is deliberate and is the lwIP contract:
 * the PORT's MAC/PHY driver writes the carrier, wz reads it. A loopback netif
 * has no PHY, so nothing in a host or QEMU run ever drops one on its own, and
 * without an injector the link-loss arm of the multicast drive loop would have
 * no witness at all -- the shape a gate cannot tell from an unreachable arm.
 *
 * Exposed unconditionally rather than behind a build flag because `lwip-sys`
 * has no feature surface; the Rust side is what gates it to `test-support`.
 */
void wz_lwip_set_all_links(int up) {
    struct netif *n;
    NETIF_FOREACH(n) {
        if (up) {
            netif_set_link_up(n);
        } else {
            netif_set_link_down(n);
        }
    }
}

/* R2835 — an ETHERNET netif whose MAC is driven from Rust.
 *
 * lwIP's own template for this is `contrib/examples/ethernetif`: an init
 * callback that fills the netif (name, hwaddr, mtu, flags, `output` =
 * `etharp_output`, `linkoutput` = the driver's send), and an input path that
 * copies a received frame into a pbuf and hands it to `netif->input`, which
 * `netif_add` sets to `ethernet_input`. Every one of those is a struct field
 * or a macro-sized constant, and the bindgen `netif` is OPAQUE in some ports
 * (see the carrier seam above), so the glue is C for the same reason that one
 * is: the lwIP definitions are the SSOT and C is where they can be read.
 *
 * What stays in Rust is the MAC itself — a chip driver behind two callbacks'
 * worth of contract: send one whole frame, and hand whole frames in.
 *
 * Ports with no Ethernet/ARP compile the entry points as refusals, so the
 * symbol set bindgen sees does not depend on the port.
 */
#include <string.h> /* MEMCPY expands to memcpy */

#include "lwip/pbuf.h"
#include "lwip/etharp.h"
#include "netif/ethernet.h"

/* A sender: puts one whole Ethernet frame (no FCS) on the wire. Non-zero on
 * success. */
typedef int (*wz_ethif_tx_fn)(void *ctx, const u8_t *frame, u16_t len);

/* One Ethernet frame without FCS: 14-byte header + a 1500-byte MTU. */
#define WZ_ETHIF_FRAME_MAX 1514

#ifndef WZ_ETHIF_MAX
#define WZ_ETHIF_MAX 2
#endif

#if LWIP_ARP && LWIP_ETHERNET

struct wz_ethif {
    struct netif netif;
    wz_ethif_tx_fn tx;
    void *ctx;
    u8_t mac[ETH_HWADDR_LEN];
};

static struct wz_ethif wz_ethifs[WZ_ETHIF_MAX];
static int wz_ethif_count;
/* lwIP hands `linkoutput` a pbuf CHAIN; the sender takes one flat frame. */
static u8_t wz_ethif_tx_buf[WZ_ETHIF_FRAME_MAX];

static err_t wz_ethif_linkoutput(struct netif *n, struct pbuf *p) {
    struct wz_ethif *e = (struct wz_ethif *)n->state;
    if (p->tot_len > WZ_ETHIF_FRAME_MAX) {
        return ERR_BUF;
    }
    u16_t len = pbuf_copy_partial(p, wz_ethif_tx_buf, p->tot_len, 0);
    return e->tx(e->ctx, wz_ethif_tx_buf, len) ? ERR_OK : ERR_IF;
}

static err_t wz_ethif_init(struct netif *n) {
    struct wz_ethif *e = (struct wz_ethif *)n->state;
    n->name[0] = 'e';
    n->name[1] = 'n';
    n->hwaddr_len = ETH_HWADDR_LEN;
    MEMCPY(n->hwaddr, e->mac, ETH_HWADDR_LEN);
    n->mtu = 1500;
    n->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET;
#if LWIP_IGMP
    n->flags |= NETIF_FLAG_IGMP;
#endif
    n->output = etharp_output;
    n->linkoutput = wz_ethif_linkoutput;
    return ERR_OK;
}

/* Add an Ethernet netif with address `ip` / `mask` / `gw` (lwIP-native, i.e.
 * network-byte-order words), bring it and its carrier up, and make it the
 * default route. `tx(ctx, ..)` sends each frame. NULL when the table is full
 * or lwIP refuses the interface. */
struct netif *wz_ethif_add(const u8_t *mac, u32_t ip, u32_t mask, u32_t gw,
                           wz_ethif_tx_fn tx, void *ctx) {
    if (wz_ethif_count >= WZ_ETHIF_MAX || tx == NULL) {
        return NULL;
    }
    struct wz_ethif *e = &wz_ethifs[wz_ethif_count];
    e->tx = tx;
    e->ctx = ctx;
    MEMCPY(e->mac, mac, ETH_HWADDR_LEN);
    ip4_addr_t a, m, g;
    ip4_addr_set_u32(&a, ip);
    ip4_addr_set_u32(&m, mask);
    ip4_addr_set_u32(&g, gw);
    if (netif_add(&e->netif, &a, &m, &g, e, wz_ethif_init, ethernet_input) == NULL) {
        return NULL;
    }
    wz_ethif_count++;
    netif_set_default(&e->netif);
    netif_set_up(&e->netif);
    netif_set_link_up(&e->netif);
    return &e->netif;
}

/* Hand one received frame (no FCS) to `n`. Non-zero when lwIP took it; zero
 * when it could not be buffered, which is a drop, as on a real NIC. */
int wz_ethif_input(struct netif *n, const u8_t *frame, u16_t len) {
    if (n == NULL || len == 0) {
        return 0;
    }
    struct pbuf *p = pbuf_alloc(PBUF_RAW, len, PBUF_RAM);
    if (p == NULL) {
        return 0;
    }
    if (pbuf_take(p, frame, len) != ERR_OK || n->input(p, n) != ERR_OK) {
        pbuf_free(p);
        return 0;
    }
    return 1;
}

#else /* !(LWIP_ARP && LWIP_ETHERNET) */

struct netif *wz_ethif_add(const u8_t *mac, u32_t ip, u32_t mask, u32_t gw,
                           wz_ethif_tx_fn tx, void *ctx) {
    (void)mac; (void)ip; (void)mask; (void)gw; (void)tx; (void)ctx;
    return NULL;
}

int wz_ethif_input(struct netif *n, const u8_t *frame, u16_t len) {
    (void)n; (void)frame; (void)len;
    return 0;
}

#endif
