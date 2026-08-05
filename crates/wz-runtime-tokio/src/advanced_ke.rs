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

/// `true` when a DERIVED `@adv` keyexpr may go on the wire.
///
/// R311y543. A base keyexpr wz accepts can derive an `@adv` form wz's own
/// outbound gate refuses, and the commonest base in the world is exactly the
/// one that does it: anything ending in `**` derives `<base>/@adv/pub/**`,
/// which is the `** chunk` + literal chunk(s) + `*`-shape chunk shape that
/// SIGABRTs a real zenoh-pico peer's canonizer
/// ([`crate::keyexpr_canon::check_outbound_keyexpr_pico_safe`], R299 bug #3 /
/// R300 gate). Upstream's own `z_advanced_sub.c` defaults to
/// `demo/example/**`.
///
/// So the gate is RIGHT to refuse the derived form — weakening it would put a
/// crashing keyexpr on the wire — and the caller's job is to DEGRADE rather
/// than to fail: the live subscription is the contract, the `@adv` recovery
/// channels are an enhancement. This predicate is where that distinction is
/// made, so the three derived channels cannot answer it differently.
#[cfg(feature = "ext-pubsub-advanced-recovery")]
pub(crate) fn adv_ke_is_outbound_safe(ke: &str) -> bool {
    crate::keyexpr_canon::check_outbound_keyexpr_pico_safe(ke).is_ok()
}

#[cfg(test)]
mod tests {
    /// The fact the degradation rests on, pinned rather than assumed: the
    /// derived heartbeat keyexpr for a `**`-tailed base is refused by wz's own
    /// outbound gate, while the base itself is fine. Before R311y543 the
    /// refusal propagated through `?` and took the LIVE subscription with it,
    /// so an advanced subscriber on `demo/example/**` — upstream's own default
    /// — received nothing at all.
    #[cfg(feature = "ext-pubsub-advanced-recovery")]
    #[test]
    fn a_double_star_base_derives_a_heartbeat_ke_the_outbound_gate_refuses() {
        use super::{adv_ke_is_outbound_safe, heartbeat_sub_ke};
        assert!(
            adv_ke_is_outbound_safe("demo/example/**"),
            "the BASE is accepted; it is only the derived form that is not"
        );
        let derived = heartbeat_sub_ke("demo/example/**");
        assert_eq!(derived, "demo/example/**/@adv/pub/**");
        assert!(
            !adv_ke_is_outbound_safe(&derived),
            "{derived} must be refused — it is the shape that SIGABRTs a real \
             zenoh-pico peer's canonizer"
        );
    }

    /// The other half: an EXACT base derives a safe heartbeat keyexpr, so the
    /// degradation must not fire for it. Without this the fix could be "never
    /// declare a heartbeat subscriber" and the test above would still pass.
    #[cfg(feature = "ext-pubsub-advanced-recovery")]
    #[test]
    fn an_exact_base_derives_a_heartbeat_ke_the_outbound_gate_accepts() {
        use super::{adv_ke_is_outbound_safe, heartbeat_sub_ke};
        let derived = heartbeat_sub_ke("demo/example/thing");
        assert_eq!(derived, "demo/example/thing/@adv/pub/**");
        assert!(adv_ke_is_outbound_safe(&derived));
    }
}
