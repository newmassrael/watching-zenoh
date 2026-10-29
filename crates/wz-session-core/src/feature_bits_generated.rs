// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// GENERATED from deploy/wz-config.toml by scripts/lib/wz_config.py --emit rust-feature-bits.
// Do not edit: `wz_config.py --check` fails when this file is stale.

//! The bit each capability has in the `features` word of a resource snapshot, as the
//! declaration assigns it (`observation_bit`). A bit is assigned once and never moved or reused.

pub(super) const CLOCK_SOURCE: u64 = 1 << 0;
pub(super) const EVENT_RING: u64 = 1 << 1;
pub(super) const SUPERVISION: u64 = 1 << 2;
pub(super) const RESOURCE_SNAPSHOT: u64 = 1 << 3;

pub(super) const NAMES: [(u64, &str); 4] = [
    (CLOCK_SOURCE, "clock-source"),
    (EVENT_RING, "event-ring"),
    (SUPERVISION, "supervision"),
    (RESOURCE_SNAPSHOT, "resource-snapshot"),
];
