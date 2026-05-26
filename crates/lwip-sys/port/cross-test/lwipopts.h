/* SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * lwip-sys cross-test lwipopts.h — bare-metal NO_SYS + UDP-minimal.
 *
 * R311az-3b validation port. Selected via
 *
 *   WZ_LWIP_PORT=$(realpath crates/lwip-sys/port/cross-test) \
 *       cargo check --target thumbv7em-none-eabihf -p lwip-sys
 *
 * to prove that the lwIP NO_SYS UDP source set cross-compiles cleanly
 * against an arm-none-eabi / riscv32 toolchain. Production MCU
 * deploys ship their own `lwipopts.h` (different MEM_SIZE, debug
 * settings, pool tuning, ethernet driver hooks); this file is a
 * minimum config sized for the compile-check, not a runtime port.
 *
 * Diff vs the host `port/include/lwipopts.h`:
 *   - MEM_LIBC_MALLOC=0 / MEMP_MEM_MALLOC=0 — bare-metal targets do
 *     not link the glibc malloc family. Use lwIP's own static mem pool.
 *   - LWIP_NETIF_LOOPBACK=0 — the cross-test does not exercise the
 *     loop_netif output queue; dropping it removes the loopif.c source
 *     from the build set without disturbing the UDP-minimal surface.
 *   - MEM_SIZE / pool counts shrunk — compile-check, not runtime sizing.
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

/* --- Protocols: UDP only at R311az --- */
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
#define LWIP_IGMP                       0
#define LWIP_STATS                      0

/* --- No loopback netif on the cross-test --- */
#define LWIP_NETIF_LOOPBACK             0
#define LWIP_HAVE_LOOPIF                0

/* --- Memory: lwIP's own static pool (no libc malloc) --- */
#define MEM_LIBC_MALLOC                 0
#define MEMP_MEM_MALLOC                 0
#define MEM_ALIGNMENT                   4
#define MEM_SIZE                        4096

/* --- Pool sizes (minimum for compile-check) --- */
#define MEMP_NUM_PBUF                   4
#define MEMP_NUM_UDP_PCB                4
#define MEMP_NUM_NETBUF                 0
#define MEMP_NUM_SYS_TIMEOUT            4
#define PBUF_POOL_SIZE                  4

/* --- Checksum: software --- */
#define LWIP_CHECKSUM_ON_COPY           0
#define CHECKSUM_GEN_IP                 1
#define CHECKSUM_GEN_UDP                1
#define CHECKSUM_CHECK_IP               1
#define CHECKSUM_CHECK_UDP              1

/* --- Debug off --- */
#define LWIP_DEBUG                      0

#endif /* LWIP_LWIPOPTS_H */
