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
