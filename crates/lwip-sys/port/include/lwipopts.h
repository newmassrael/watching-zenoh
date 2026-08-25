/* SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * lwip-sys default lwipopts.h — NO_SYS=1 + UDP-minimal.
 *
 * R311az-pre D2 ratifies the lwIP raw API surface only; LWIP_SOCKET=0
 * keeps the BSD-socket shim out. R311az-pre D6 ratifies the alloc
 * dependency at the wz-link-lwip layer; here at the C side we use
 * mem_malloc-backed memory rather than a static pool so the host
 * build smoke can exercise long-lived pcbs without sizing a static
 * MEMP_NUM_UDP_PCB pool below realistic counts.
 *
 * Deploy crates (cross-compile to thumbv7em + lwIP target) supply
 * their own lwipopts.h via -I path before this header. Override
 * policy: the in-crate version exists solely so `cargo build -p
 * lwip-sys` on the host succeeds and bindgen has a working config.
 *
 * Layer G.4-alloc-link (R311az-3) does NOT pull this header for the
 * cross-compile lane — the cross build uses the deploy-supplied
 * lwipopts.h. R311az-1 ships only the host build.
 */

#ifndef LWIP_LWIPOPTS_H
#define LWIP_LWIPOPTS_H

/* --- Core mode: no OS, no threads --- */
#define NO_SYS                          1
#define SYS_LIGHTWEIGHT_PROT            0
#define LWIP_TIMERS                     1

/* --- API layers: raw API only --- */
#define LWIP_NETCONN                    0
#define LWIP_SOCKET                     0
#define LWIP_NETIF_API                  0

/* --- Protocols: UDP only at R311az-1 --- */
#define LWIP_RAW                        0
#define LWIP_UDP                        1
#define LWIP_TCP                        0
#define LWIP_ICMP                       1
#define LWIP_IPV4                       1
#define LWIP_IPV6                       0
#define LWIP_ARP                        1
#define LWIP_ETHERNET                   1

/* --- Disabled aux protocols --- */
#define LWIP_DHCP                       0
#define LWIP_AUTOIP                     0
#define LWIP_DNS                        0
#define LWIP_STATS                      0

/* --- Loopback for host smoke tests --- */
#define LWIP_NETIF_LOOPBACK             1
#define LWIP_HAVE_LOOPIF                1

/* --- Multicast scouting (zenoh udp/224.0.0.224:7446 RX) --- */
/* IGMP membership so a udp_pcb can receive multicast scout/hello
 * datagrams — the MCU mirror of the AP std multicast socket. igmp.c
 * provides igmp_joingroup, which wz-link-lwip's
 * LwipLink::join_multicast_group links against. */
#define LWIP_IGMP                       1
/* Make the loopback netif IGMP-capable (netif_loopif_init gates
 * NETIF_FLAG_IGMP on this) so the host smoke exercises multicast RX
 * over loopback; real deploys receive on their ethernet netif. */
#define LWIP_LOOPIF_MULTICAST           1
/* Host-smoke only: exposes netif_get_loopif() (lwIP gates it behind
 * LWIP_TESTMODE && LWIP_HAVE_LOOPIF) so the multicast-RX test can route
 * its TX over the loop netif via ip4_set_default_multicast_netif. Not
 * set on the cross-test / deploy ports — additive test accessor only. */
#define LWIP_TESTMODE                   1

/* --- Memory: libc malloc-backed --- */
#define MEM_LIBC_MALLOC                 1
#define MEMP_MEM_MALLOC                 1
#define MEM_ALIGNMENT                   4
#define MEM_SIZE                        16384

/* --- Pool sizes (small but non-degenerate for host smoke) --- */
#define MEMP_NUM_PBUF                   16
#define MEMP_NUM_UDP_PCB                4
#define MEMP_NUM_NETBUF                 0
#define MEMP_NUM_SYS_TIMEOUT            8
#define PBUF_POOL_SIZE                  8

/* --- Checksum: software --- */
#define LWIP_CHECKSUM_ON_COPY           0
#define CHECKSUM_GEN_IP                 1
#define CHECKSUM_GEN_UDP                1
#define CHECKSUM_CHECK_IP               1
#define CHECKSUM_CHECK_UDP              1

/* --- Debug off by default --- */
#define LWIP_DEBUG                      0

#endif /* LWIP_LWIPOPTS_H */
