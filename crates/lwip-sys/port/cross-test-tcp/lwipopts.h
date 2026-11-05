/* SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * lwip-sys cross-test-tcp lwipopts.h — the cross-test bare-metal NO_SYS port
 * PLUS the sizing a TCP connection needs at run time, so a bare-metal build
 * (QEMU mps2 or a real Cortex-M) of the node over `tcp/` can hold a session.
 *
 * Delta vs the shared `../cross-test/lwipopts.h` (which stays BYTE-IDENTICAL —
 * it feeds the other cross lanes and the zephyr staticlib, so this port
 * EXTENDS rather than edits it, as `../cross-test-mcast` does):
 *   - the TCP block, when the `tcp` feature of lwip-sys defines LWIP_TCP=1 on
 *     the command line: the segment, the window and the send buffer of an
 *     Ethernet frame, and the control blocks and segments of the connections
 *     the node holds, as `deploy/zephyr-admin-node/lwip-port/lwipopts.h` states
 *     them for the kit (a window a connection's receive ring must hold at
 *     least: `LwipTcpSocket::connect` refuses a ring below it);
 *   - runtime-grade memory and pool sizing — cross-test ships compile-check
 *     MINIMA, and a connection's unacknowledged data (TCP_SND_BUF) is copied
 *     into lwIP's heap while a window of frames waits in the pbuf pool.
 *
 * Selected via
 *
 *   WZ_LWIP_PORT=$(realpath crates/lwip-sys/port/cross-test-tcp) \
 *       cargo build --manifest-path deploy/mcu-admin-node/Cargo.toml ...
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

/* --- Protocols --- */
#define LWIP_RAW                        0
#define LWIP_UDP                        1
/* The `tcp` feature of lwip-sys defines LWIP_TCP=1 on the command line; off, TCP is off. */
#ifndef LWIP_TCP
#define LWIP_TCP                        0
#endif
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

/* --- Loopback netif kept on: wz-link-lwip allowlists netif_poll_all --- */
#define LWIP_NETIF_LOOPBACK             1
#define LWIP_HAVE_LOOPIF                1

/* --- Multicast (IGMP) --- */
#define LWIP_IGMP                       1

/* --- Memory: lwIP's own static pool (no libc malloc) --- */
#define MEM_LIBC_MALLOC                 0
#define MEMP_MEM_MALLOC                 0
#define MEM_ALIGNMENT                   4
/* With TCP, a connection's unacknowledged data (TCP_SND_BUF) is copied into this heap. */
#if LWIP_TCP
#define MEM_SIZE                        (24 * 1024 + 4 * TCP_SND_BUF)
#else
#define MEM_SIZE                        4096
#endif

/* --- Pool sizes --- */
#define MEMP_NUM_PBUF                   32
#define MEMP_NUM_UDP_PCB                8
#define MEMP_NUM_NETBUF                 0
#define MEMP_NUM_SYS_TIMEOUT            8
#define PBUF_POOL_SIZE                  48

/* --- TCP (the node over `tcp/`) --- */
#if LWIP_TCP
/* The largest segment an Ethernet frame carries: 1500 - 20 (IPv4) - 20 (TCP). */
#define TCP_MSS                         1460
/* The window the node advertises, and what a connection's receive ring must hold at least. */
#define TCP_WND                         (2 * TCP_MSS)
#define TCP_SND_BUF                     (2 * TCP_MSS)
/* Connections: one for each session the node holds, one waiting to be taken, and the ones that
 * linger in TIME_WAIT (lwIP reclaims the oldest of those when a new one is needed). */
#define MEMP_NUM_TCP_PCB                6
#define MEMP_NUM_TCP_PCB_LISTEN         1
#define MEMP_NUM_TCP_SEG                16
#endif

/* --- Checksum: software --- */
#define LWIP_CHECKSUM_ON_COPY           0
#define CHECKSUM_GEN_IP                 1
#define CHECKSUM_GEN_UDP                1
#define CHECKSUM_CHECK_IP               1
#define CHECKSUM_CHECK_UDP              1

/* --- Debug off --- */
#define LWIP_DEBUG                      0

#endif /* LWIP_LWIPOPTS_H */
