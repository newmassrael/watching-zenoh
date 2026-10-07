/* SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * lwIP options of the Zephyr admin node's lwIP backend (the one that runs over a
 * wz Ethernet MAC crate instead of Zephyr's own stack).
 *
 * Selected by the image's CMake through WZ_LWIP_PORT. It starts from the
 * `lwip-sys` cross-test port, which is "sized for the compile-check, not a
 * runtime", and differs in exactly that: pools and heap big enough for an admin
 * node that keeps one accepting session and a few dialled ones on a real wire.
 * Everything else (NO_SYS, UDP only, IPv4, ARP, IGMP, the loopback interface
 * `wz-link-lwip` allowlists) is the cross-test's, for the reason it gives.
 */

#ifndef LWIP_LWIPOPTS_H
#define LWIP_LWIPOPTS_H

/* --- Core mode: no OS, no threads. The node's loop polls lwIP. --- */
#define NO_SYS                          1
#define SYS_LIGHTWEIGHT_PROT            0
#define LWIP_TIMERS                     1

/* --- API layers: raw API only --- */
#define LWIP_NETCONN                    0
#define LWIP_SOCKET                     0
#define LWIP_NETIF_API                  0

/* --- Protocols: UDP over IPv4 on Ethernet --- */
#define LWIP_RAW                        0
#define LWIP_UDP                        1
#define LWIP_TCP                        0
#define LWIP_ICMP                       1
#define LWIP_IPV4                       1
#define LWIP_IPV6                       0
#define LWIP_ARP                        1
#define LWIP_ETHERNET                   1

/* --- Not in this image: the address is the board's Kconfig --- */
#define LWIP_DHCP                       0
#define LWIP_AUTOIP                     0
#define LWIP_DNS                        0
#define LWIP_STATS                      0

/* --- Loopback netif on: wz-link-lwip allowlists `netif_poll_all` --- */
#define LWIP_NETIF_LOOPBACK             1
#define LWIP_HAVE_LOOPIF                1

/* --- Multicast: zenoh scouting and a joined group both need IGMP --- */
#define LWIP_IGMP                       1

/* --- Memory: lwIP's own static pool (no libc malloc) --- */
#define MEM_LIBC_MALLOC                 0
#define MEMP_MEM_MALLOC                 0
#define MEM_ALIGNMENT                   4
/* The heap pbufs for a transmitted datagram come from, and the stack's own
 * bookkeeping. A session's batch is at most 1500 bytes. */
#define MEM_SIZE                        (24 * 1024)

/* --- Pools --- */
/* Received frames arrive in pool pbufs, 592 bytes each by default, so a 1514
 * byte frame is a chain of three. Sixteen frames in flight is 48. */
#define PBUF_POOL_SIZE                  48
#define MEMP_NUM_PBUF                   32
/* One accepting session, a few dialled ones, and the admin node's own. */
#define MEMP_NUM_UDP_PCB                8
#define MEMP_NUM_NETBUF                 0
#define MEMP_NUM_SYS_TIMEOUT            8

/* --- Checksums: software --- */
#define LWIP_CHECKSUM_ON_COPY           0
#define CHECKSUM_GEN_IP                 1
#define CHECKSUM_GEN_UDP                1
#define CHECKSUM_CHECK_IP               1
#define CHECKSUM_CHECK_UDP              1

/* --- Debug off --- */
#define LWIP_DEBUG                      0

#endif /* LWIP_LWIPOPTS_H */
