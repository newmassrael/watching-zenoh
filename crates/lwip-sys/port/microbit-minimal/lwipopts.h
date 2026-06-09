/* SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * lwip-sys microbit-minimal lwipopts.h — nrf51-class (Cortex-M0, 16 KB
 * SRAM total) constrained NO_SYS + UDP-minimal port.
 *
 * R311jc. The cross-test port (../cross-test/lwipopts.h) is a compile-check
 * config whose ~8 KB of static lwIP RAM (MEM_SIZE 4096 + PBUF_POOL 4 + the
 * memp pools) leaves too little of the microbit's 16 KB SRAM for the MCU
 * acceptor session stack's STACK: the session runtime (SCXML engine + HMAC-
 * SHA256 + codec dispatch) needs ~5-6 KB of stack on ARMv6-M (M0 codegen
 * spills more than the ~1.7 KB measured on M3), and 8 KB lwIP + 4 KB heap
 * left only ~4.2 KB — the stack overflowed into .bss and corrupted lwIP's
 * udp_pcb pool (a HardFault in udp_bind). This port trims the static lwIP
 * footprint to ~5 KB so a ~4 KB heap (measured ~3.15 KB slim peak) and a
 * ~7 KB stack both fit. The cross-test port's own header anticipates this:
 * "Production MCU deploys ship their own lwipopts.h (different MEM_SIZE,
 * pool tuning)". This is that constrained-deploy lwipopts.
 *
 * Selected by the Layer Q.4 microbit acceptor sub-lane via WZ_LWIP_PORT;
 * the mps2 (M3/M4/M7) acceptor lanes + the cross-real G lanes keep the
 * cross-test port (4 MB SRAM, no constraint). Only the values that free
 * SRAM differ from cross-test; the protocol surface (UDP + loopback + ARP
 * + IGMP-for-the-link-symbol) is identical so the same wz-link-lwip FFI
 * resolves.
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

/* --- Protocols: UDP only --- */
#define LWIP_RAW                        0
#define LWIP_UDP                        1
#define LWIP_TCP                        0
#define LWIP_ICMP                       1
#define LWIP_IPV4                       1
#define LWIP_IPV6                       0
#define LWIP_ARP                        1
#define LWIP_ETHERNET                   1

/* --- IP reassembly / fragmentation OFF — this constrained session profile
 * carries only small (<= 256 B) control / handshake frames over loopback;
 * nothing fragments, so the FRAG_PBUF + REASSDATA memp pools are dead RAM. */
#define IP_REASSEMBLY                   0
#define IP_FRAG                         0

/* --- Disabled aux protocols --- */
#define LWIP_DHCP                       0
#define LWIP_AUTOIP                     0
#define LWIP_DNS                        0
#define LWIP_STATS                      0

/* --- Loopback netif kept on: wz-link-lwip allowlists netif_poll_all --- */
#define LWIP_NETIF_LOOPBACK             1
#define LWIP_HAVE_LOOPIF                1

/* --- Multicast (IGMP) kept on so igmp.c defines igmp_joingroup, which
 * wz-link-lwip's LwipLink::join_multicast_group links against (the acceptor
 * never calls it, but the symbol must resolve). Only ~130 B of memp. --- */
#define LWIP_IGMP                       1

/* --- Memory: lwIP's own static pool, TRIMMED for the 16 KB budget --- */
#define MEM_LIBC_MALLOC                 0
#define MEMP_MEM_MALLOC                 0
#define MEM_ALIGNMENT                   4
#define MEM_SIZE                        2048

/* --- Pool sizes trimmed: 3 pbuf-pool slots cover one loopback datagram
 * in flight + headroom; 2 udp_pcbs cover the acceptor session rx + the
 * crafted-peer socket. --- */
#define MEMP_NUM_PBUF                   3
#define MEMP_NUM_UDP_PCB                3
#define MEMP_NUM_NETBUF                 0
#define MEMP_NUM_SYS_TIMEOUT            3
#define PBUF_POOL_SIZE                  3

/* --- Checksum: software --- */
#define LWIP_CHECKSUM_ON_COPY           0
#define CHECKSUM_GEN_IP                 1
#define CHECKSUM_GEN_UDP                1
#define CHECKSUM_CHECK_IP               1
#define CHECKSUM_CHECK_UDP              1

/* --- Debug off --- */
#define LWIP_DEBUG                      0

#endif /* LWIP_LWIPOPTS_H */
