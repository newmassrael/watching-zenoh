# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# GENERATED from deploy/wz-config.toml by scripts/lib/wz_config.py --emit image-cmake:zephyr-admin-node.
# Do not edit: `wz_config.py --check` fails when this file is stale.

set(wz_axes_features "")
set(wz_axes_no_default_features "")
if(CONFIG_WZ_NET_BACKEND_ZEPHYR_SOCKETS)
  list(APPEND wz_axes_features net-zephyr-sockets)
endif()
if(CONFIG_WZ_NET_BACKEND_LWIP_MAC)
  list(APPEND wz_axes_features net-lwip-mac)
endif()
if(CONFIG_WZ_ROLE_CLIENT AND CONFIG_WZ_STORAGE_HEAP)
  list(APPEND wz_axes_features client-node)
  set(wz_axes_no_default_features NO_DEFAULT_FEATURES)
endif()
if(CONFIG_WZ_ROLE_CLIENT AND CONFIG_WZ_FIXED_MEMORY)
  list(APPEND wz_axes_features fixed-client)
  set(wz_axes_no_default_features NO_DEFAULT_FEATURES)
endif()
if(CONFIG_WZ_NET_BACKEND_LWIP_MAC AND CONFIG_WZ_FIXED_MEMORY)
  list(APPEND wz_axes_features fixed-memory)
  set(wz_axes_no_default_features NO_DEFAULT_FEATURES)
endif()
