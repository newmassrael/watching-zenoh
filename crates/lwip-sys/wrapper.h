/* SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * lwip-sys bindgen umbrella header. Pulls in the public lwIP headers
 * that the allowlist references. Bindgen follows the `-I` paths
 * (vendor/lwip/src/include + lwip-sys/port/include) to resolve the
 * transitive includes.
 *
 * R311az-1 minimum surface: init + netif lifecycle + udp raw API +
 * pbuf + ip4_addr + sys_check_timeouts (NO_SYS=1 timer pump).
 */

#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/udp.h"
#include "lwip/pbuf.h"
#include "lwip/timeouts.h"
#include "lwip/ip_addr.h"
#include "lwip/ip4_addr.h"
#include "lwip/err.h"
