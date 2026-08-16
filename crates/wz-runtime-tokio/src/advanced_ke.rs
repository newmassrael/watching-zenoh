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

/// The subscriber kind chunk under `@adv` (zenoh `KE_SUB`, admin.rs:56):
/// `@adv/sub/...`. The sibling of [`KE_ADV_PUB`] — a subscriber that opts into
/// detection publishes a liveliness token here so a third party can see it,
/// exactly as a publisher does under `pub`.
///
/// Gated on `-recovery`, not on `-subscriber`, because that is where its only
/// consumer lives: `AdvancedSubscriberOptions` (and so the detection option)
/// is behind the recovery gate today. A recovery-OFF build caught this as
/// dead code under `-D warnings` — the R311y809 / R311y811 reduced-feature
/// class. If the options type is ever lifted to the `-subscriber` level, this
/// gate moves with it.
#[cfg(feature = "ext-pubsub-advanced-recovery")]
pub(crate) const KE_ADV_SUB: &str = "sub";

/// The trailing empty meta chunk zenoh appends to the `@adv` suffix
/// (`KE_EMPTY = ke!("_")`, zenoh admin.rs:58) "because of a routing matching bug"
/// (advanced_publisher.rs:328-329): the wildcard-tailed detection / recovery queries
/// (`.../@adv/*/<zid>/<eid>/**`) stay matchable through a zenoh router thanks to the
/// concrete `_` chunk. wz mirrors it so the `@adv` namespace is byte-identical.
#[cfg(any(
    feature = "ext-pubsub-advanced-publisher",
    feature = "ext-pubsub-advanced-recovery"
))]
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

/// The subscriber's own detection KE:
/// `<base>/@adv/sub/<zid_hex>/<eid>/[<meta>|_]` — the liveliness token a
/// subscriber declares when it opts into being detectable.
///
/// BOTH references build this suffix and they agree chunk for chunk: zenoh-ext
/// `KE_ADV_PREFIX / KE_SUB / zid / eid / [meta | KE_EMPTY]`
/// (advanced_subscriber.rs:1151-1160) and zenoh-pico's
/// `// suffix = KE_ADV_PREFIX / KE_SUB / ZID / EID / [ metadata | KE_EMPTY ]`
/// (advanced_subscriber.c:1651-1655). The trailing `_` when no metadata is
/// given is not cosmetic — it is the same routing-matching workaround
/// [`KE_EMPTY`] documents for the publisher, and zenoh's own comment says so.
///
/// `meta` is a caller-supplied key expression appended to convey application
/// metadata; it may itself be multi-chunk, which is why it substitutes for the
/// single `_` chunk rather than being appended after it.
#[cfg(feature = "ext-pubsub-advanced-recovery")]
pub(crate) fn subscriber_adv_ke(base: &str, zid_hex: &str, eid: u32, meta: Option<&str>) -> String {
    let tail = meta.unwrap_or(KE_EMPTY);
    format!("{base}/{KE_ADV_PREFIX}/{KE_ADV_SUB}/{zid_hex}/{eid}/{tail}")
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
/// R311y543 added this predicate because a base wz accepts could derive an
/// `@adv` form wz's own outbound gate refused, and the commonest base in the
/// world did it: anything ending in `**` derives `<base>/@adv/pub/**`, which the
/// gate read as the zenoh-pico SIGABRT shape (R299 bug #3 / R300). Upstream's
/// own `z_advanced_sub.c` defaults to `demo/example/**`, so the whole recovery
/// plane was off for the default keyexpr.
///
/// R311y544 measured the premise and it was FALSE. Only a chunk of length ONE
/// holds pico's `in_big_wild` window open, and the chunk immediately after the
/// base is always `@adv` — four bytes. Every derived channel of every base wz
/// accepts is therefore safe, pinned by
/// [`tests::no_accepted_base_derives_a_refused_adv_channel`] on the wz side and
/// by `layer3_keyexpr_canon::canon_derived_adv_keyexprs_do_not_abort_pico`
/// against a real `_z_keyexpr_canonize` in a subprocess.
///
/// The predicate STAYS, as a guard rather than as a live degradation: it is one
/// string walk, the failure it protects against is a remote process abort, and a
/// future change to the derivation could reopen the window without anyone
/// noticing. What changed is that its false branch is now an alarm — the caller
/// logs a warning and reports the outcome through
/// `AdvancedSubscriber::heartbeat_channel_is_live` — instead of a silent
/// amputation of the recovery plane.
#[cfg(feature = "ext-pubsub-advanced-recovery")]
pub(crate) fn adv_ke_is_outbound_safe(ke: &str) -> bool {
    crate::keyexpr_canon::check_outbound_keyexpr_pico_safe(ke).is_ok()
}

#[cfg(test)]
mod tests {
    /// R311y544 — this test used to assert the OPPOSITE, and pinned the
    /// premise of R311y543's degradation: that the derived heartbeat keyexpr
    /// for a `**`-tailed base is refused by wz's own outbound gate. The
    /// refusal was a false positive. A subprocess probe of the real
    /// `_z_keyexpr_canonize`
    /// (`layer3_keyexpr_canon::canon_derived_adv_keyexprs_do_not_abort_pico`)
    /// shows every derived `@adv` form canonizing to itself, and the gate has
    /// been narrowed to pico's actual bug window. So a `**`-tailed base — which
    /// is upstream's own `z_advanced_sub.c` default — gets its recovery plane.
    #[cfg(feature = "ext-pubsub-advanced-recovery")]
    #[test]
    fn a_double_star_base_derives_adv_keyexprs_the_outbound_gate_accepts() {
        use super::{adv_ke_is_outbound_safe, heartbeat_sub_ke};
        assert!(adv_ke_is_outbound_safe("demo/example/**"));
        let derived = heartbeat_sub_ke("demo/example/**");
        assert_eq!(derived, "demo/example/**/@adv/pub/**");
        assert!(
            adv_ke_is_outbound_safe(&derived),
            "{derived} is safe on a real zenoh-pico; refusing it silently \
             removed the heartbeat / history / recovery channels"
        );
    }

    /// The structural reason the degradation path is now unreachable for any
    /// base wz itself accepts, stated as a test rather than as a comment: the
    /// chunk immediately after the base is always `@adv`, four bytes, and only
    /// a ONE-byte chunk holds pico's `in_big_wild` window open. So no accepted
    /// base can derive a refused `@adv` channel.
    ///
    /// The predicate stays in the code as a guard — it is cheap, and the
    /// alternative to a wrong answer here is a remote SIGABRT — but this
    /// pins that it is a guard and not a live degradation.
    #[cfg(feature = "ext-pubsub-advanced-recovery")]
    #[test]
    fn no_accepted_base_derives_a_refused_adv_channel() {
        #[cfg(feature = "ext-pubsub-advanced-history")]
        use super::history_get_ke;
        #[cfg(feature = "ext-pubsub-advanced-recovery")]
        use super::recovery_get_ke;
        use super::{adv_ke_is_outbound_safe, heartbeat_sub_ke};

        for base in [
            "demo/example/**",
            "**",
            "a/**",
            "**/a",
            "demo/example/thing",
            "demo/*/thing",
            "a/b/c",
            "**/a/b",
        ] {
            assert!(
                adv_ke_is_outbound_safe(base),
                "fixture base `{base}` must itself be accepted"
            );
            assert!(
                adv_ke_is_outbound_safe(&heartbeat_sub_ke(base)),
                "heartbeat channel refused for base `{base}`"
            );
            #[cfg(feature = "ext-pubsub-advanced-history")]
            assert!(
                adv_ke_is_outbound_safe(&history_get_ke(base)),
                "history channel refused for base `{base}`"
            );
            assert!(
                adv_ke_is_outbound_safe(&recovery_get_ke(base, "a0b1c2d3e4f5", 1)),
                "recovery channel refused for base `{base}`"
            );
        }
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
