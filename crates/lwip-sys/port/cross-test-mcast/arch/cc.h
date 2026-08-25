/* SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
 * SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
 *
 * lwip-sys cross-test-mcast arch/cc.h — identical bare-metal platform layer to
 * the shared cross-test port; the loopback-multicast port differs ONLY in
 * lwipopts.h, so the arch layer reuses cross-test verbatim (single source of
 * truth). build.rs requires an arch/cc.h file to exist in every WZ_LWIP_PORT
 * dir, so this thin include satisfies that while avoiding a duplicated copy.
 */

#include "../../cross-test/arch/cc.h"
