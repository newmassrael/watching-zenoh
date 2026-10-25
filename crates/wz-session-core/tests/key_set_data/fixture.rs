// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// GENERATED from crates/wz-session-core/tests/key_set_data/fixture.toml by scripts/lib/wz_key_set.py --write.
// Do not edit: `wz_key_set.py --check` fails when this file is stale.

//! The key catalogue of the declaration, as `KeyCatalogue` reads it. A bad table is a build
//! error: `KeyCatalogue::new` checks every property in a `const`.

#![allow(dead_code)]

use wz_session_core::key_catalogue::{EntityId, EntityKind, EntityRow, KeyCatalogue, KeyId};

#[rustfmt::skip]
const KEY_TEXT: &str = concat!(
    "**",
    "**/temp",
    "@/lab/*",
    "@/lab/adv",
    "lab/**",
    "lab/*/hum",
    "lab/alive/node1",
    "lab/alive/node2",
    "lab/ctl/**",
    "lab/ctl/get",
    "lab/ctl/set",
    "lab/doc/*",
    "lab/doc/large",
    "lab/doc/small",
    "lab/sensor/*",
    "lab/sensor/hum",
    "lab/sensor/t$*",
    "lab/sensor/temp",
);

#[rustfmt::skip]
const KEY_ENDS: [u16; 18] = [
    2, 9, 16, 25, 31, 40, 55, 70, 80, 91, 102, 111, 124, 137, 149, 163, 177, 192,
];

#[rustfmt::skip]
const OFFSETS: [u16; 91] = [
    0, 4, 11, 15, 17, 19, 20, 25, 27, 29, 29, 30, 31, 31, 31, 31, 32, 33, 33, 33, 33, 37, 44, 48,
    50, 52, 53, 57, 59, 60, 60, 60, 62, 63, 63, 64, 64, 66, 67, 67, 68, 70, 75, 77, 77, 77, 78, 80,
    82, 82, 82, 83, 86, 88, 88, 88, 88, 92, 95, 96, 96, 96, 98, 100, 101, 101, 101, 103, 105, 106,
    106, 108, 114, 115, 116, 116, 117, 121, 122, 122, 122, 123, 128, 129, 130, 130, 131, 136, 137,
    138, 138,
];

#[rustfmt::skip]
const MEMBERS: [EntityId; 138] = [
    EntityId::new(1), EntityId::new(2), EntityId::new(3), EntityId::new(4), EntityId::new(5),
    EntityId::new(6), EntityId::new(8), EntityId::new(9), EntityId::new(10), EntityId::new(11),
    EntityId::new(12), EntityId::new(13), EntityId::new(14), EntityId::new(15), EntityId::new(16),
    EntityId::new(17), EntityId::new(18), EntityId::new(19), EntityId::new(20), EntityId::new(4),
    EntityId::new(5), EntityId::new(6), EntityId::new(8), EntityId::new(11), EntityId::new(12),
    EntityId::new(13), EntityId::new(14), EntityId::new(17), EntityId::new(18), EntityId::new(0),
    EntityId::new(7), EntityId::new(0), EntityId::new(7), EntityId::new(1), EntityId::new(2),
    EntityId::new(3), EntityId::new(4), EntityId::new(5), EntityId::new(6), EntityId::new(8),
    EntityId::new(9), EntityId::new(10), EntityId::new(11), EntityId::new(12), EntityId::new(13),
    EntityId::new(14), EntityId::new(15), EntityId::new(16), EntityId::new(17), EntityId::new(18),
    EntityId::new(19), EntityId::new(20), EntityId::new(3), EntityId::new(5), EntityId::new(8),
    EntityId::new(9), EntityId::new(11), EntityId::new(13), EntityId::new(14), EntityId::new(17),
    EntityId::new(5), EntityId::new(8), EntityId::new(13), EntityId::new(19), EntityId::new(5),
    EntityId::new(8), EntityId::new(13), EntityId::new(20), EntityId::new(1), EntityId::new(2),
    EntityId::new(5), EntityId::new(6), EntityId::new(8), EntityId::new(9), EntityId::new(10),
    EntityId::new(13), EntityId::new(14), EntityId::new(1), EntityId::new(5), EntityId::new(8),
    EntityId::new(13), EntityId::new(14), EntityId::new(2), EntityId::new(5), EntityId::new(8),
    EntityId::new(10), EntityId::new(13), EntityId::new(14), EntityId::new(5), EntityId::new(6),
    EntityId::new(8), EntityId::new(9), EntityId::new(13), EntityId::new(15), EntityId::new(16),
    EntityId::new(17), EntityId::new(5), EntityId::new(8), EntityId::new(13), EntityId::new(15),
    EntityId::new(17), EntityId::new(5), EntityId::new(8), EntityId::new(13), EntityId::new(16),
    EntityId::new(17), EntityId::new(3), EntityId::new(4), EntityId::new(5), EntityId::new(6),
    EntityId::new(8), EntityId::new(9), EntityId::new(11), EntityId::new(12), EntityId::new(13),
    EntityId::new(18), EntityId::new(3), EntityId::new(5), EntityId::new(8), EntityId::new(9),
    EntityId::new(11), EntityId::new(13), EntityId::new(4), EntityId::new(5), EntityId::new(6),
    EntityId::new(8), EntityId::new(11), EntityId::new(12), EntityId::new(13), EntityId::new(18),
    EntityId::new(4), EntityId::new(5), EntityId::new(6), EntityId::new(8), EntityId::new(11),
    EntityId::new(12), EntityId::new(13), EntityId::new(18),
];

#[rustfmt::skip]
const ENTITIES: [EntityRow; 21] = [
    EntityRow::new(EntityKind::Publisher, KeyId::new(3)),
    EntityRow::new(EntityKind::Publisher, KeyId::new(9)),
    EntityRow::new(EntityKind::Publisher, KeyId::new(10)),
    EntityRow::new(EntityKind::Publisher, KeyId::new(15)),
    EntityRow::new(EntityKind::Publisher, KeyId::new(17)),
    EntityRow::new(EntityKind::Subscriber, KeyId::new(0)),
    EntityRow::new(EntityKind::Subscriber, KeyId::new(1)),
    EntityRow::new(EntityKind::Subscriber, KeyId::new(2)),
    EntityRow::new(EntityKind::Subscriber, KeyId::new(4)),
    EntityRow::new(EntityKind::Subscriber, KeyId::new(5)),
    EntityRow::new(EntityKind::Subscriber, KeyId::new(10)),
    EntityRow::new(EntityKind::Subscriber, KeyId::new(14)),
    EntityRow::new(EntityKind::Subscriber, KeyId::new(16)),
    EntityRow::new(EntityKind::Queryable, KeyId::new(4)),
    EntityRow::new(EntityKind::Queryable, KeyId::new(8)),
    EntityRow::new(EntityKind::Queryable, KeyId::new(12)),
    EntityRow::new(EntityKind::Queryable, KeyId::new(13)),
    EntityRow::new(EntityKind::Querier, KeyId::new(11)),
    EntityRow::new(EntityKind::Querier, KeyId::new(17)),
    EntityRow::new(EntityKind::LivelinessToken, KeyId::new(6)),
    EntityRow::new(EntityKind::LivelinessToken, KeyId::new(7)),
];

pub const CATALOGUE: KeyCatalogue<'static> =
    KeyCatalogue::new(KEY_TEXT, &KEY_ENDS, &OFFSETS, &MEMBERS, &ENTITIES);

/// The declaration as the entities were numbered: row `n` is entity `n`.
#[rustfmt::skip]
pub const DECLARED: [(EntityKind, &str); 21] = [
    (EntityKind::Publisher, "@/lab/adv"),
    (EntityKind::Publisher, "lab/ctl/get"),
    (EntityKind::Publisher, "lab/ctl/set"),
    (EntityKind::Publisher, "lab/sensor/hum"),
    (EntityKind::Publisher, "lab/sensor/temp"),
    (EntityKind::Subscriber, "**"),
    (EntityKind::Subscriber, "**/temp"),
    (EntityKind::Subscriber, "@/lab/*"),
    (EntityKind::Subscriber, "lab/**"),
    (EntityKind::Subscriber, "lab/*/hum"),
    (EntityKind::Subscriber, "lab/ctl/set"),
    (EntityKind::Subscriber, "lab/sensor/*"),
    (EntityKind::Subscriber, "lab/sensor/t$*"),
    (EntityKind::Queryable, "lab/**"),
    (EntityKind::Queryable, "lab/ctl/**"),
    (EntityKind::Queryable, "lab/doc/large"),
    (EntityKind::Queryable, "lab/doc/small"),
    (EntityKind::Querier, "lab/doc/*"),
    (EntityKind::Querier, "lab/sensor/temp"),
    (EntityKind::LivelinessToken, "lab/alive/node1"),
    (EntityKind::LivelinessToken, "lab/alive/node2"),
];
