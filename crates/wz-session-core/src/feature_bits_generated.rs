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

/// The `features` word of the instruments the CALLING crate was built with: the bit of each
/// capability whose cargo feature is on in that crate (`cfg!` is read where the macro is
/// expanded). The list is the declaration's, so a crate states no list of its own.
#[macro_export]
macro_rules! built_feature_bits {
    () => {{
        // A crate that has no such feature reads it as off; the lint that asks for a feature
        // to be declared is for a typo, and each name here is the declaration's.
        let mut word = 0u64;
        #[allow(unexpected_cfgs)]
        let clock_source = cfg!(feature = "clock-source");
        if clock_source {
            word |= $crate::resource_snapshot::feature_bits::CLOCK_SOURCE;
        }
        #[allow(unexpected_cfgs)]
        let event_ring = cfg!(feature = "event-ring");
        if event_ring {
            word |= $crate::resource_snapshot::feature_bits::EVENT_RING;
        }
        #[allow(unexpected_cfgs)]
        let supervision = cfg!(feature = "supervision");
        if supervision {
            word |= $crate::resource_snapshot::feature_bits::SUPERVISION;
        }
        #[allow(unexpected_cfgs)]
        let resource_snapshot = cfg!(feature = "resource-snapshot");
        if resource_snapshot {
            word |= $crate::resource_snapshot::feature_bits::RESOURCE_SNAPSHOT;
        }
        word
    }};
}
