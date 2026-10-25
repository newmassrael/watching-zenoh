// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// GENERATED from deploy/wz-config.toml by scripts/lib/wz_config.py --emit rust-limits.
// Do not edit: `wz_config.py --check` fails when this file is stale.

//! The value of each limit as the code reads it: the number the build's environment states
//! as `WZ_LIMIT_<NAME>`, or the declared default when it states none. The names the code uses
//! are bound to these in `caps.rs`, beside the documentation of each.

use super::limit;

pub(super) const MAX_KEYEXPR_BYTES: usize = limit(option_env!("WZ_LIMIT_MAX_KEYEXPR_BYTES"), 256);
pub(super) const MAX_SUBSCRIPTIONS: usize = limit(option_env!("WZ_LIMIT_MAX_SUBSCRIPTIONS"), 16);
pub(super) const MAX_QUERYABLES: usize = limit(option_env!("WZ_LIMIT_MAX_QUERYABLES"), 16);
pub(super) const MAX_PENDING_QUERIES: usize =
    limit(option_env!("WZ_LIMIT_MAX_PENDING_QUERIES"), 16);
pub(super) const MAX_DECL_OBSERVERS: usize = limit(option_env!("WZ_LIMIT_MAX_DECL_OBSERVERS"), 8);
pub(super) const MAX_LIVELINESS_SUBSCRIPTIONS: usize =
    limit(option_env!("WZ_LIMIT_MAX_LIVELINESS_SUBSCRIPTIONS"), 8);
pub(super) const MAX_LOCAL_TOKENS: usize = limit(option_env!("WZ_LIMIT_MAX_LOCAL_TOKENS"), 8);
pub(super) const MAX_PENDING_LIVELINESS_GETS: usize =
    limit(option_env!("WZ_LIMIT_MAX_PENDING_LIVELINESS_GETS"), 8);
pub(super) const MAX_PENDING_DECLARES: usize =
    limit(option_env!("WZ_LIMIT_MAX_PENDING_DECLARES"), 32);
pub(super) const MAX_INBOUND_SUB_INTERESTS: usize =
    limit(option_env!("WZ_LIMIT_MAX_INBOUND_SUB_INTERESTS"), 16);
pub(super) const MAX_PEER_KEYEXPR_ALIASES: usize =
    limit(option_env!("WZ_LIMIT_MAX_PEER_KEYEXPR_ALIASES"), 16);
pub(super) const MAX_REMOTE_DECLS: usize = limit(option_env!("WZ_LIMIT_MAX_REMOTE_DECLS"), 16);
pub(super) const MAX_PENDING_REPLIES: usize = limit(option_env!("WZ_LIMIT_MAX_PENDING_REPLIES"), 8);
pub(super) const MAX_PENDING_FINALS: usize = limit(option_env!("WZ_LIMIT_MAX_PENDING_FINALS"), 8);
pub(super) const MAX_REPLY_PAYLOAD_BYTES: usize =
    limit(option_env!("WZ_LIMIT_MAX_REPLY_PAYLOAD_BYTES"), 1024);
pub(super) const MAX_ADMIN_REPLY_BYTES: usize =
    limit(option_env!("WZ_LIMIT_MAX_ADMIN_REPLY_BYTES"), 1024);
pub(super) const MAX_ADMIN_LOCATORS: usize = limit(option_env!("WZ_LIMIT_MAX_ADMIN_LOCATORS"), 4);
pub(super) const MAX_ADMIN_SESSION_LINKS: usize =
    limit(option_env!("WZ_LIMIT_MAX_ADMIN_SESSION_LINKS"), 2);
pub(super) const MAX_MULTICAST_REPLIES: usize =
    limit(option_env!("WZ_LIMIT_MAX_MULTICAST_REPLIES"), 8);
pub(super) const MAX_TASKS: usize = limit(option_env!("WZ_LIMIT_MAX_TASKS"), 8);
pub(super) const MAX_TIMERS: usize = limit(option_env!("WZ_LIMIT_MAX_TIMERS"), 16);
pub(super) const MAX_LOCATOR_LEN: usize = limit(option_env!("WZ_LIMIT_MAX_LOCATOR_LEN"), 64);
pub(super) const MAX_STATIC_CONNECT: usize = limit(option_env!("WZ_LIMIT_MAX_STATIC_CONNECT"), 8);
pub(super) const QUERIER_MAX_PENDING_QUERIES: usize =
    limit(option_env!("WZ_LIMIT_QUERIER_MAX_PENDING_QUERIES"), 0);
pub(super) const TX_NO_PROGRESS_WINDOW_US: usize =
    limit(option_env!("WZ_LIMIT_TX_NO_PROGRESS_WINDOW_US"), 1000000);
