// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y92 (review S1) — the `@adv` key-expr namespace SSOT shared by the advanced
//! publisher (which CONSTRUCTS the `@adv/pub/<zid>/<disc>/_` KE for its cache /
//! token / heartbeat beacon) and the advanced subscriber (which MATCHES it with the
//! recovery / history / heartbeat-subscriber GETs + the beacon parser). Previously
//! the prefix lived as `advanced_publisher` consts while the subscriber hand-wrote
//! `@adv` / `pub` inline (x4), so the namespace had no single source of truth — a
//! drift on either side would silently break the recovery round-trip. zenoh's
//! analogue is the `KE_ADV_PREFIX` / `KE_EMPTY` consts + the `ke_liveliness`
//! builders (zenoh-ext admin.rs:48/58, advanced_publisher.rs:317-329).

/// The `@adv` namespace prefix (zenoh `KE_ADV_PREFIX`, admin.rs:48).
pub(crate) const KE_ADV_PREFIX: &str = "@adv";

/// The publisher kind chunk under `@adv` (zenoh `pub`): `@adv/pub/...`.
pub(crate) const KE_ADV_PUB: &str = "pub";

/// The trailing empty meta chunk zenoh appends to the `@adv` suffix
/// (`KE_EMPTY = ke!("_")`, zenoh admin.rs:58) "because of a routing matching bug"
/// (advanced_publisher.rs:328-329): the wildcard-tailed detection / recovery queries
/// (`.../@adv/*/<zid>/<eid>/**`) stay matchable through a zenoh router thanks to the
/// concrete `_` chunk. wz mirrors it so the `@adv` namespace is byte-identical.
#[cfg(feature = "ext-pubsub-advanced-publisher")]
pub(crate) const KE_EMPTY: &str = "_";

/// The publisher's own `@adv` KE: `<base>/@adv/pub/<zid_hex>/<discriminator>/_`
/// (the cache queryable + liveliness token + heartbeat-beacon KE). `discriminator`
/// is the `<eid>` (SequenceNumber sequencing) or `uhlc` (timestamp / none) chunk.
/// The subscriber's [`recovery_get_ke`] + [`heartbeat_sub_ke`] are the matching
/// wildcards (zenoh advanced_publisher.rs:317-329).
#[cfg(feature = "ext-pubsub-advanced-publisher")]
pub(crate) fn publisher_adv_ke(base: &str, zid_hex: &str, discriminator: &str) -> String {
    format!("{base}/{KE_ADV_PREFIX}/{KE_ADV_PUB}/{zid_hex}/{discriminator}/{KE_EMPTY}")
}

/// The sample-driven / bounded recovery GET KE: `<base>/@adv/*/<zid_hex>/<eid>/**`.
/// The `*` matches the publisher's `pub` kind chunk and the `**` its trailing `_`
/// meta chunk, so it resolves a specific `(zid, eid)` source's cache (zenoh
/// advanced_subscriber.rs:710-715).
#[cfg(feature = "ext-pubsub-advanced-recovery")]
pub(crate) fn recovery_get_ke(base: &str, zid_hex: &str, eid: u32) -> String {
    format!("{base}/{KE_ADV_PREFIX}/*/{zid_hex}/{eid}/**")
}

/// The startup history GET KE: `<base>/@adv/**` (every cached sample under the
/// `@adv` namespace, across all publishers).
#[cfg(feature = "ext-pubsub-advanced-history")]
pub(crate) fn history_get_ke(base: &str) -> String {
    format!("{base}/{KE_ADV_PREFIX}/**")
}

/// The publisher-detection subscriber KE: `<base>/@adv/pub/**` (the `@adv/pub`
/// namespace covering every publisher). The single SSOT for this KE across its
/// TWO consumers (R311y102 review): the heartbeat-beacon DATA subscriber (which
/// decodes each publisher's last-sn beacon) and the late-publisher LIVELINESS
/// subscriber (which fires on each publisher's `@adv` token Put/Delete).
#[cfg(feature = "ext-pubsub-advanced-recovery")]
pub(crate) fn heartbeat_sub_ke(base: &str) -> String {
    format!("{base}/{KE_ADV_PREFIX}/{KE_ADV_PUB}/**")
}
