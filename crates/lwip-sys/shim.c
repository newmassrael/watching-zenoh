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
/* R2841 — a link's two ends, as upstream's admin space reports them.
 *
 * A UDP pcb bound to any address has no local IP of its own: the address a
 * datagram leaves from is the one of the netif lwIP routes it through. So the
 * source of a link to `dst` is `ip4_route(dst)`'s address, and its port is the
 * pcb's. `netif_ip4_addr` is a macro and `udp_pcb`'s fields are opaque in some
 * ports, which is why both are read here.
 */
#include "lwip/ip4.h"
#include "lwip/udp.h"

/* The address a datagram to `dst` (lwIP-native word) leaves from, or 0 when
 * no interface routes it. */
u32_t wz_lwip_route_src(u32_t dst) {
    ip4_addr_t d;
    ip4_addr_set_u32(&d, dst);
    struct netif *n = ip4_route(&d);
    if (n == NULL) {
        return 0;
    }
    return ip4_addr_get_u32(netif_ip4_addr(n));
}

/* ARCHITECTURE section 9.1 -- the payload pbufs lent to a sender to write a
 * datagram into. Allocated here, and freed here, so a count of the ones still out
 * is exact: a pbuf a sender forgot to give back is a leak on a fixed MCU heap, and
 * on the host port (libc malloc, no lwIP statistics) nothing else would show it. */
static u32_t wz_tx_pbufs_out;

struct pbuf *wz_lwip_tx_pbuf_alloc(u16_t len) {
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, len, PBUF_RAM);
    if (p != NULL) {
        wz_tx_pbufs_out++;
    }
    return p;
}

void wz_lwip_tx_pbuf_free(struct pbuf *p) {
    if (p != NULL) {
        wz_tx_pbufs_out--;
        pbuf_free(p);
    }
}

u32_t wz_lwip_tx_pbufs_out(void) {
    return wz_tx_pbufs_out;
}

/* ARCHITECTURE section 9.1 -- a pbuf whose memory IS one slot of a transmit pool
 * (`sources/network/session_tx_pool_mcu.scxml`, `wz-link-lwip`'s `tx_pool`).
 *
 * The slot is laid out the way lwIP lays out a pbuf of its own heap: the record
 * first, then the room lwIP keeps in front of a transport-layer payload, then the
 * payload. So when lwIP adds the UDP, IPv4 and Ethernet headers it writes them
 * INTO the slot, in front of the payload, and the frame a MAC is handed is one
 * piece inside the slot. The record being at the start of the slot is also what
 * `pbuf_add_header` needs of a pbuf whose data follows its struct (it refuses to
 * move the payload below the end of the struct), and it is how the free callback
 * finds the slot: the pbuf lwIP frees IS the slot's first byte.
 *
 * `free_fn` is called, as for any custom pbuf, when lwIP drops the last reference,
 * which is after a MAC that read the frame in place has said it is done. */
#if LWIP_SUPPORT_CUSTOM_PBUF

#define WZ_TX_SLOT_HEAD LWIP_MEM_ALIGN_SIZE(sizeof(struct pbuf_custom))
#define WZ_TX_SLOT_ROOM (WZ_TX_SLOT_HEAD + LWIP_MEM_ALIGN_SIZE(PBUF_TRANSPORT))

/* How many payload bytes a slot of `slot_len` bytes carries: 0 when it cannot
 * hold the record and the header room. */
u16_t wz_lwip_tx_slot_capacity(u16_t slot_len) {
    return slot_len > WZ_TX_SLOT_ROOM ? (u16_t)(slot_len - WZ_TX_SLOT_ROOM) : 0;
}

/* A pbuf of `len` payload bytes over the slot at `slot`, or NULL when `len` does
 * not fit. `slot` must be aligned for the record (a pool slot is 32-byte aligned)
 * and stay valid, and unchanged except through the pbuf, until `free_fn` runs. */
struct pbuf *wz_lwip_tx_slot_pbuf(void *slot, u16_t slot_len, u16_t len,
                                  void (*free_fn)(struct pbuf *p)) {
    if (slot == NULL || free_fn == NULL || len > wz_lwip_tx_slot_capacity(slot_len)) {
        return NULL;
    }
    struct pbuf_custom *pc = (struct pbuf_custom *)slot;
    pc->custom_free_function = free_fn;
    return pbuf_alloced_custom(PBUF_TRANSPORT, len, PBUF_RAM, pc,
                               (u8_t *)slot + WZ_TX_SLOT_HEAD,
                               (u16_t)(slot_len - WZ_TX_SLOT_HEAD));
}

#else /* !LWIP_SUPPORT_CUSTOM_PBUF */

/* A port without custom pbufs cannot wrap a slot: nothing fits, and a sender
 * falls back to a pbuf of lwIP's own heap. */
u16_t wz_lwip_tx_slot_capacity(u16_t slot_len) {
    (void)slot_len;
    return 0;
}

struct pbuf *wz_lwip_tx_slot_pbuf(void *slot, u16_t slot_len, u16_t len,
                                  void (*free_fn)(struct pbuf *p)) {
    (void)slot; (void)slot_len; (void)len; (void)free_fn;
    return NULL;
}

#endif /* LWIP_SUPPORT_CUSTOM_PBUF */

/* The local port `pcb` is bound to (host order), 0 for no pcb. */
u16_t wz_lwip_udp_local_port(const struct udp_pcb *pcb) {
    return pcb == NULL ? 0 : pcb->local_port;
}

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

/* ARCHITECTURE section 9.1 -- a sender that can read a frame IN PLACE, from the
 * pieces of a pbuf chain, instead of from one flat copy. `segs` are the chain's
 * payloads in order; they stay valid until the sender reports `cookie` done, if
 * it queued them. Returns 0 when it refused the frame, 1 when it SENT it from a
 * copy (the pieces are free again at once), 2 when it QUEUED it to be read in
 * place (the pieces are free only when `wz_ethif_tx_done(cookie)` is called). */
typedef struct {
    const u8_t *ptr;
    u16_t len;
} wz_ethif_seg;
typedef int (*wz_ethif_tx_gather_fn)(void *ctx, const wz_ethif_seg *segs, u16_t n,
                                     u32_t cookie);

/* The most pieces one frame is handed over in, and the most frames held at once. A
 * chain with more pieces, or a table with no free place, is sent through the flat
 * copy below instead, which is always correct. */
#ifndef WZ_ETHIF_SEG_MAX
#define WZ_ETHIF_SEG_MAX 8
#endif
#ifndef WZ_ETHIF_HELD_MAX
#define WZ_ETHIF_HELD_MAX 8
#endif

/* ARCHITECTURE section 9.2 -- a received frame lent by the MAC in place, wrapped
 * in a custom pbuf that points at it. lwIP reads the frame where the controller
 * wrote it; when the last reference to the pbuf is dropped (which may be long
 * after the input call returns, if lwIP parks it in a queue), `release(ctx,
 * cookie)` tells the MAC the buffer is its own again. */
typedef void (*wz_ethif_rx_release_fn)(void *ctx, u32_t cookie);

/* The most lent frames lwIP may hold at once. A frame arriving when they are all
 * out is taken through the copying input instead, which is always correct. */
#ifndef WZ_ETHIF_RX_HELD_MAX
#define WZ_ETHIF_RX_HELD_MAX 8
#endif

#if LWIP_ARP && LWIP_ETHERNET

struct wz_ethif {
    struct netif netif;
    wz_ethif_tx_fn tx;
    wz_ethif_tx_gather_fn tx_gather; /* NULL: every frame goes through `tx` */
    wz_ethif_rx_release_fn rx_release; /* NULL: received frames are copied in */
    void *ctx;
    u8_t mac[ETH_HWADDR_LEN];
};

static struct wz_ethif wz_ethifs[WZ_ETHIF_MAX];
static int wz_ethif_count;
/* lwIP hands `linkoutput` a pbuf CHAIN; the sender takes one flat frame. */
static u8_t wz_ethif_tx_buf[WZ_ETHIF_FRAME_MAX];

/* The chains a sender is reading in place, each held by one reference so lwIP
 * cannot free them until the sender says it is done. The slot number is the
 * cookie the sender reports back. */
static struct pbuf *wz_ethif_held[WZ_ETHIF_HELD_MAX];

static err_t wz_ethif_linkoutput(struct netif *n, struct pbuf *p) {
    struct wz_ethif *e = (struct wz_ethif *)n->state;
    if (p->tot_len > WZ_ETHIF_FRAME_MAX) {
        return ERR_BUF;
    }
    if (e->tx_gather != NULL) {
        wz_ethif_seg segs[WZ_ETHIF_SEG_MAX];
        u16_t count = 0;
        int fits = 1;
        for (struct pbuf *q = p; q != NULL; q = q->next) {
            if (q->len == 0) {
                continue;
            }
            if (count == WZ_ETHIF_SEG_MAX) {
                fits = 0;
                break;
            }
            segs[count].ptr = (const u8_t *)q->payload;
            segs[count].len = q->len;
            count++;
        }
        int slot = -1;
        for (int i = 0; fits && i < WZ_ETHIF_HELD_MAX; i++) {
            if (wz_ethif_held[i] == NULL) {
                slot = i;
                break;
            }
        }
        if (fits && count != 0 && slot >= 0) {
            /* Held BEFORE the sender sees it: it may report the frame done from
             * inside this very call. */
            pbuf_ref(p);
            wz_ethif_held[slot] = p;
            int outcome = e->tx_gather(e->ctx, segs, count, (u32_t)slot);
            if (outcome == 2) {
                return ERR_OK;
            }
            wz_ethif_held[slot] = NULL;
            pbuf_free(p);
            if (outcome == 1) {
                return ERR_OK;
            }
            return ERR_IF;
        }
    }
    u16_t len = pbuf_copy_partial(p, wz_ethif_tx_buf, p->tot_len, 0);
    return e->tx(e->ctx, wz_ethif_tx_buf, len) ? ERR_OK : ERR_IF;
}

/* Let `n` hand frames to its sender in place. For an interface whose sender can
 * (`EthernetMac::transmit_gather`); one that cannot is simply not given this. */
void wz_ethif_set_gather(struct netif *n, wz_ethif_tx_gather_fn gather) {
    if (n != NULL) {
        ((struct wz_ethif *)n->state)->tx_gather = gather;
    }
}

/* The sender no longer reads the chain it queued under `cookie`: give lwIP its
 * reference back. A cookie that names no held chain is ignored. */
void wz_ethif_tx_done(u32_t cookie) {
    if (cookie < WZ_ETHIF_HELD_MAX && wz_ethif_held[cookie] != NULL) {
        struct pbuf *p = wz_ethif_held[cookie];
        wz_ethif_held[cookie] = NULL;
        pbuf_free(p);
    }
}

/* The reference count of the chain held under `cookie`, 0 when none is. For a test
 * to see that the shim's reference is the only thing keeping a chain alive once
 * its sender has let go of it. */
int wz_ethif_held_refs(u32_t cookie) {
    if (cookie < WZ_ETHIF_HELD_MAX && wz_ethif_held[cookie] != NULL) {
        return (int)wz_ethif_held[cookie]->ref;
    }
    return 0;
}

/* How many chains are held right now, for a test to see that nothing leaks. */
int wz_ethif_held_count(void) {
    int held = 0;
    for (int i = 0; i < WZ_ETHIF_HELD_MAX; i++) {
        held += wz_ethif_held[i] != NULL;
    }
    return held;
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
 * network-byte-order words) and bring it and its carrier up. `tx(ctx, ..)`
 * sends each frame. NULL when the table is full or lwIP refuses the interface.
 *
 * THE DEFAULT ROUTE is a statement about a gateway, so only an interface that
 * HAS one can be it, and only while nothing else is: the first interface added
 * with a non-zero `gw` becomes the default route and a later one never moves
 * it. This used to make EVERY added interface the default, which with a single
 * interface is the same thing and with two let the second silently take the
 * route from the first -- the one that was added last winning, whatever
 * gateways they had. An interface with `gw == 0` is on-link only and is never
 * the default route. */
struct netif *wz_ethif_add(const u8_t *mac, u32_t ip, u32_t mask, u32_t gw,
                           wz_ethif_tx_fn tx, void *ctx) {
    if (wz_ethif_count >= WZ_ETHIF_MAX || tx == NULL) {
        return NULL;
    }
    struct wz_ethif *e = &wz_ethifs[wz_ethif_count];
    e->tx = tx;
    e->tx_gather = NULL;
    e->rx_release = NULL;
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
    if (gw != 0 && netif_default == NULL) {
        netif_set_default(&e->netif);
    }
    netif_set_up(&e->netif);
    netif_set_link_up(&e->netif);
    return &e->netif;
}

/* Whether `n` is the default route. */
int wz_ethif_is_default(const struct netif *n) {
    return n != NULL && n == netif_default;
}

/* Take every Ethernet netif this shim added back out of lwIP and empty the
 * table, so the next `wz_ethif_add` starts from nothing.
 *
 * For a test harness, which shares one lwIP across many tests in a process and
 * would otherwise find the table (two entries) and the default route left by
 * whichever test ran first. A firmware never calls it: an interface added to a
 * running node lives as long as the node. */
void wz_ethif_remove_all(void) {
    for (int i = 0; i < wz_ethif_count; i++) {
        netif_set_down(&wz_ethifs[i].netif);
        netif_remove(&wz_ethifs[i].netif);
    }
    wz_ethif_count = 0;
    /* A chain a removed sender never reported done would be held for ever. */
    for (u32_t i = 0; i < WZ_ETHIF_HELD_MAX; i++) {
        wz_ethif_tx_done(i);
    }
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

/* Let `n` take received frames lent in place: `release(ctx, cookie)` is called
 * when lwIP no longer reads a lent frame. One that cannot lend is not given this. */
void wz_ethif_set_rx_release(struct netif *n, wz_ethif_rx_release_fn release) {
    if (n != NULL) {
        ((struct wz_ethif *)n->state)->rx_release = release;
    }
}

#if LWIP_SUPPORT_CUSTOM_PBUF

/* One lent frame lwIP holds. `pc` is first so the pbuf lwIP frees is this
 * record's address, and the record is found from it with a cast. */
struct wz_rx_held {
    struct pbuf_custom pc;
    struct wz_ethif *e;
    u32_t cookie;
    u8_t used;
};

static struct wz_rx_held wz_rx_held[WZ_ETHIF_RX_HELD_MAX];
static u32_t wz_rx_loaned_total;

static void wz_rx_custom_free(struct pbuf *p) {
    struct wz_rx_held *h = (struct wz_rx_held *)p;
    struct wz_ethif *e = h->e;
    u32_t cookie = h->cookie;
    h->used = 0;
    if (e->rx_release != NULL) {
        e->rx_release(e->ctx, cookie);
    }
}

/* Hand one received frame, lent in place at `frame`, to `n` WITHOUT copying it.
 * 1: lwIP took it, and `release` follows when lwIP is done. 0: lwIP refused it
 * (and `release` has already been called: the pbuf was freed). -1: it could not
 * be wrapped (no release callback, no free record, or no custom pbuf support), so
 * nothing was done and the caller takes the copying input. */
int wz_ethif_input_loan(struct netif *n, const u8_t *frame, u16_t len, u32_t cookie) {
    if (n == NULL || len == 0) {
        return -1;
    }
    struct wz_ethif *e = (struct wz_ethif *)n->state;
    if (e->rx_release == NULL) {
        return -1;
    }
    struct wz_rx_held *h = NULL;
    for (int i = 0; i < WZ_ETHIF_RX_HELD_MAX; i++) {
        if (!wz_rx_held[i].used) {
            h = &wz_rx_held[i];
            break;
        }
    }
    if (h == NULL) {
        return -1;
    }
    h->used = 1;
    h->e = e;
    h->cookie = cookie;
    h->pc.custom_free_function = wz_rx_custom_free;
    struct pbuf *p = pbuf_alloced_custom(PBUF_RAW, len, PBUF_REF, &h->pc, (void *)frame, len);
    if (p == NULL) {
        h->used = 0;
        return -1;
    }
    wz_rx_loaned_total++;
    if (n->input(p, n) != ERR_OK) {
        pbuf_free(p);
        return 0;
    }
    return 1;
}

int wz_ethif_rx_held_count(void) {
    int held = 0;
    for (int i = 0; i < WZ_ETHIF_RX_HELD_MAX; i++) {
        held += wz_rx_held[i].used != 0;
    }
    return held;
}

u32_t wz_ethif_rx_loaned_total(void) {
    return wz_rx_loaned_total;
}

#else /* !LWIP_SUPPORT_CUSTOM_PBUF */

int wz_ethif_input_loan(struct netif *n, const u8_t *frame, u16_t len, u32_t cookie) {
    (void)n; (void)frame; (void)len; (void)cookie;
    return -1;
}

int wz_ethif_rx_held_count(void) {
    return 0;
}

u32_t wz_ethif_rx_loaned_total(void) {
    return 0;
}

#endif /* LWIP_SUPPORT_CUSTOM_PBUF */

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

int wz_ethif_is_default(const struct netif *n) {
    (void)n;
    return 0;
}

void wz_ethif_remove_all(void) {}

void wz_ethif_set_gather(struct netif *n, wz_ethif_tx_gather_fn gather) {
    (void)n; (void)gather;
}

void wz_ethif_tx_done(u32_t cookie) {
    (void)cookie;
}

int wz_ethif_held_count(void) {
    return 0;
}

int wz_ethif_held_refs(u32_t cookie) {
    (void)cookie;
    return 0;
}

void wz_ethif_set_rx_release(struct netif *n, wz_ethif_rx_release_fn release) {
    (void)n; (void)release;
}

int wz_ethif_input_loan(struct netif *n, const u8_t *frame, u16_t len, u32_t cookie) {
    (void)n; (void)frame; (void)len; (void)cookie;
    return -1;
}

int wz_ethif_rx_held_count(void) {
    return 0;
}

u32_t wz_ethif_rx_loaned_total(void) {
    return 0;
}

#endif
