// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! WHERE each footprint in [`crate::abi`] comes from, as data a gate can read.
//!
//! ## The class this exists to close
//!
//! [`crate::abi`] carries a SIZE per zenoh-c opaque type, and
//! `scripts/check-capi-c-opaque-arms.sh` measures every one of them against
//! upstream's own generator on all four feature arms. That answers "is the
//! number right". It does not answer "is the number right FOR THE REASON this
//! crate says it is", and the difference is not academic:
//!
//! `REPLY_ERR_SIZE` was `BYTES_SIZE + ENCODING_SIZE`, justified in a comment by
//! upstream's `ReplyError` being `{ ZBytes payload, Encoding encoding }`. At
//! zenoh 1.10.0 that struct grew a THIRD field —
//! `#[cfg(feature = "unstable")] timestamp_stack: Option<TimestampStack>` — so
//! the composition became false on two of the four arms while the comment that
//! stated it stayed. Nothing measured the comment, because a comment is not a
//! predicate. The arms gate caught the resulting SIZE, one pin bump later and
//! two rounds after it started reding hosted CI.
//!
//! ## The two tables, and what each is checked against
//!
//! [`WZ_CAPI_C_ABI_ORIGIN`] names, for every entry of
//! [`crate::abi::layout_names`], the upstream Rust type whose footprint the C
//! type IS — read off `build-resources/opaque-types/src/lib.rs`, which is where
//! zenoh-c itself declares that correspondence. Entries upstream's opaque
//! generator does not describe carry `@transparent` (a struct whose fields are
//! public in `zenoh_commons.h`, measured by the C probe in Layer C1cc) or
//! `@synthetic` (this crate's own alignment rows). Both are claims, not
//! escapes: `scripts/lib/capi_c_abi_provenance.py` fails when a name marked
//! `@transparent` turns out to BE in the generator's table, exactly as it fails
//! when a name claiming an upstream type disagrees with it.
//!
//! [`WZ_CAPI_C_ABI_COMPOSITION`] states, for every type whose footprint MOVES
//! across the four arms, how this crate derives it. The gate evaluates each
//! expression against upstream's four generated tables, and — the half that
//! makes it more than a self-report — DERIVES the population from those same
//! tables, so a moving type with no row here is a failure rather than a
//! silence. That derivation is what would have redded `REPLY_ERR_SIZE` at the
//! pin bump: the type started moving on the unstable axis and its row did not
//! say so.

/// `(C type name, upstream origin)` for every name
/// [`crate::abi::layout_names`] can yield, on any arm.
///
/// The right-hand side is either the upstream Rust type expression, verbatim as
/// `get_opaque_type_data!` spells it, or one of the two `@`-prefixed
/// classifications. The list is the UNION over arms; the per-arm subset is what
/// `layout_names` returns.
pub const WZ_CAPI_C_ABI_ORIGIN: &[(&str, &str)] = &[
    ("z_owned_session_t", "Option<Session>"),
    ("z_owned_bytes_t", "ZBytes"),
    ("z_view_keyexpr_t", "Option<KeyExpr<'static>>"),
    ("z_owned_config_t", "Option<Config>"),
    ("align", "@synthetic"),
    ("z_owned_subscriber_t", "Option<Subscriber<()>>"),
    ("z_owned_string_t", "CSlice"),
    ("z_owned_closure_sample_t", "@transparent"),
    ("z_owned_liveliness_token_t", "Option<LivelinessToken>"),
    ("z_owned_publisher_t", "Option<Publisher<'static>>"),
    ("z_publisher_options_t", "@transparent"),
    ("z_publisher_put_options_t", "@transparent"),
    ("z_owned_encoding_t", "Encoding"),
    ("z_owned_closure_zid_t", "@transparent"),
    ("z_owned_closure_matching_status_t", "@transparent"),
    ("z_id_t", "ZenohId"),
    ("z_id_t/align", "@synthetic"),
    ("z_clock_t", "@transparent"),
    ("z_liveliness_subscriber_options_t", "@transparent"),
    ("z_matching_status_t", "@transparent"),
    ("z_owned_sample_t", "Option<Sample>"),
    ("z_owned_queryable_t", "Option<Queryable<()>>"),
    ("z_owned_querier_t", "Option<Querier>"),
    ("z_owned_query_t", "Option<Query>"),
    ("z_owned_reply_t", "Option<Reply>"),
    ("z_owned_hello_t", "Option<Hello>"),
    ("z_owned_string_array_t", "Vec<CSlice>"),
    ("z_owned_bytes_writer_t", "Option<ZBytesWriter>"),
    ("ze_owned_serializer_t", "Option<zenoh_ext::ZSerializer>"),
    (
        "z_owned_fifo_handler_reply_t",
        "Option<FifoChannelHandler<Reply>>",
    ),
    (
        "z_owned_fifo_handler_query_t",
        "Option<FifoChannelHandler<Query>>",
    ),
    (
        "z_owned_ring_handler_sample_t",
        "Option<RingChannelHandler<Sample>>",
    ),
    (
        "z_owned_mutex_t",
        "Option<(Mutex<()>, Option<MutexGuard<'static, ()>>)>",
    ),
    ("z_owned_condvar_t", "Option<Condvar>"),
    ("z_owned_condvar_t/align", "@synthetic"),
    ("z_loaned_condvar_t", "Condvar"),
    ("z_loaned_condvar_t/align", "@synthetic"),
    ("z_owned_slice_t", "CSlice"),
    ("z_owned_closure_query_t", "@transparent"),
    ("z_owned_closure_reply_t", "@transparent"),
    ("z_owned_closure_hello_t", "@transparent"),
    ("z_bytes_reader_t", "ZBytesReader<'static>"),
    ("z_bytes_slice_iterator_t", "ZBytesSliceIterator<'static>"),
    ("ze_deserializer_t", "zenoh_ext::ZDeserializer<'static>"),
    ("z_get_options_t", "@transparent"),
    ("z_queryable_options_t", "@transparent"),
    ("z_query_reply_options_t", "@transparent"),
    ("z_liveliness_get_options_t", "@transparent"),
    ("z_querier_options_t", "@transparent"),
    ("z_querier_get_options_t", "@transparent"),
    ("z_scout_options_t", "@transparent"),
    ("z_subscriber_options_t", "@transparent"),
    ("z_put_options_t", "@transparent"),
    ("z_delete_options_t", "@transparent"),
    ("z_timestamp_t", "Timestamp"),
    ("z_timestamp_t/align", "@synthetic"),
    ("z_owned_keyexpr_t", "Option<KeyExpr<'static>>"),
    ("z_query_reply_del_options_t", "@transparent"),
    (
        "z_owned_fifo_handler_sample_t",
        "Option<FifoChannelHandler<Sample>>",
    ),
    (
        "z_owned_ring_handler_query_t",
        "Option<RingChannelHandler<Query>>",
    ),
    (
        "z_owned_ring_handler_reply_t",
        "Option<RingChannelHandler<Reply>>",
    ),
    ("z_owned_reply_err_t", "ReplyError"),
    ("z_owned_task_t", "Option<JoinHandle<()>>"),
    ("z_task_attr_t", "@transparent"),
    ("z_query_reply_err_options_t", "@transparent"),
    ("z_publisher_delete_options_t", "@transparent"),
    ("z_query_consolidation_t", "@transparent"),
    ("zc_owned_closure_log_t", "@transparent"),
    ("z_loaned_closure_matching_status_t", "@transparent"),
    ("z_entity_global_id_t", "EntityGlobalId"),
    ("z_entity_global_id_t/align", "@synthetic"),
    ("ze_miss_t", "@transparent"),
    ("ze_owned_closure_miss_t", "@transparent"),
    (
        "ze_owned_advanced_publisher_t",
        "Option<zenoh_ext::AdvancedPublisher<'static>>",
    ),
    (
        "ze_owned_advanced_subscriber_t",
        "Option<zenoh_ext::AdvancedSubscriber<()>>",
    ),
    (
        "ze_owned_sample_miss_listener_t",
        "Option<zenoh_ext::SampleMissListener<()>>",
    ),
    ("ze_advanced_publisher_cache_options_t", "@transparent"),
    (
        "ze_advanced_publisher_sample_miss_detection_options_t",
        "@transparent",
    ),
    ("ze_advanced_publisher_options_t", "@transparent"),
    ("ze_advanced_publisher_put_options_t", "@transparent"),
    ("ze_advanced_subscriber_history_options_t", "@transparent"),
    (
        "ze_advanced_subscriber_last_sample_miss_detection_options_t",
        "@transparent",
    ),
    ("ze_advanced_subscriber_recovery_options_t", "@transparent"),
    ("ze_advanced_subscriber_options_t", "@transparent"),
    ("z_owned_shm_t", "Option<ZShm>"),
    ("z_owned_shm_mut_t", "Option<ZShmMut>"),
    ("z_owned_shm_provider_t", "Option<CDummySHMProvider>"),
    ("z_alloc_alignment_t", "@transparent"),
    ("z_buf_layout_alloc_result_t", "@transparent"),
    ("z_buf_alloc_result_t", "@transparent"),
];

/// How this crate DERIVES each footprint that moves across the four feature
/// arms, as an expression the gate evaluates against upstream's own tables.
///
/// Grammar, `+`-separated terms:
///
/// - `<int>` — a constant byte count that holds on every arm;
/// - `<int>@shm` / `<int>@unstable` — a term added only on arms built with
///   `Z_FEATURE_SHARED_MEMORY` / `Z_FEATURE_UNSTABLE_API`;
/// - `<c type name>` — the footprint of another opaque type, which is how a
///   composition says "this type CONTAINS that one" rather than "these numbers
///   happen to add up".
///
/// The population is DERIVED, not declared: the gate reads upstream's four
/// tables, takes every type this crate declares whose size is not constant
/// across the arms it exists on, and requires a row here for each. A type that
/// starts moving — which is exactly what `ReplyError` did at 1.10.0 — therefore
/// arrives as a missing row rather than as silence.
pub const WZ_CAPI_C_ABI_COMPOSITION: &[(&str, &str)] = &[
    ("z_owned_bytes_t", "32 + 8@shm"),
    ("z_owned_encoding_t", "40 + 8@shm"),
    ("z_owned_publisher_t", "112 + 8@shm"),
    ("z_owned_query_t", "136 + 8@shm"),
    ("z_owned_bytes_writer_t", "56 + 8@shm"),
    // Upstream's serializer wraps a writer at offset 0, so this is a
    // containment rather than a coincidence of two equal numbers.
    ("ze_owned_serializer_t", "z_owned_bytes_writer_t"),
    ("z_owned_sample_t", "184 + 16@shm + 56@unstable"),
    ("z_owned_reply_t", "184 + 16@shm + 80@unstable"),
    // `ReplyError` is `{ ZBytes payload, Encoding encoding }` plus, since
    // zenoh 1.10.0 and only under `unstable`, `Option<TimestampStack>`. The
    // first two terms are the footprints this crate already carries; the third
    // is the field the 1.5.0 -> 1.10.0 move added, and writing it as a term
    // rather than folding it into a literal is what lets the gate say WHICH
    // part of the derivation a future version breaks.
    (
        "z_owned_reply_err_t",
        "z_owned_bytes_t + z_owned_encoding_t + 32@unstable",
    ),
    ("ze_owned_advanced_publisher_t", "240 + 8@shm"),
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Every name this build's layout table yields has an origin row.
    ///
    /// The gate in `scripts/lib/capi_c_abi_provenance.py` checks the table
    /// against UPSTREAM; this checks it against the crate, on the arm cargo is
    /// building, which is the half a Python script reading source text cannot
    /// see (`layout_names` is `#[cfg]`-assembled).
    #[test]
    fn every_layout_name_has_an_origin() {
        let origins: HashSet<&str> = WZ_CAPI_C_ABI_ORIGIN.iter().map(|(n, _)| *n).collect();
        let missing: Vec<&str> = crate::abi::layout_names()
            .into_iter()
            .filter(|n| !origins.contains(n))
            .collect();
        assert!(
            missing.is_empty(),
            "layout names with no WZ_CAPI_C_ABI_ORIGIN row: {missing:?}"
        );
        assert!(
            !crate::abi::layout_names().is_empty(),
            "the layout table is empty, so this test compared nothing"
        );
    }

    /// The origin table names each type once.
    ///
    /// A duplicate row is how a table like this rots quietly: the gate reads
    /// the first and an editor updates the second.
    #[test]
    fn origin_rows_are_unique() {
        let mut seen = HashSet::new();
        for (name, _) in WZ_CAPI_C_ABI_ORIGIN {
            assert!(seen.insert(*name), "duplicate origin row for {name}");
        }
        assert_eq!(seen.len(), WZ_CAPI_C_ABI_ORIGIN.len());
    }

    /// Every composed type is one this crate claims an UPSTREAM origin for.
    ///
    /// Composing a `@transparent` or `@synthetic` row would be deriving a size
    /// from a table upstream's opaque generator does not describe, which the
    /// provenance gate could not then evaluate.
    #[test]
    fn composed_types_have_an_upstream_origin() {
        let upstream: HashSet<&str> = WZ_CAPI_C_ABI_ORIGIN
            .iter()
            .filter(|(_, o)| !o.starts_with('@'))
            .map(|(n, _)| *n)
            .collect();
        assert!(!WZ_CAPI_C_ABI_COMPOSITION.is_empty());
        for (name, expr) in WZ_CAPI_C_ABI_COMPOSITION {
            assert!(
                upstream.contains(name),
                "{name} is composed but has no upstream origin row"
            );
            for term in expr.split('+').map(str::trim) {
                let head = term.split('@').next().unwrap();
                if head.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                    continue;
                }
                assert!(
                    upstream.contains(head),
                    "{name} composes {head}, which has no upstream origin row"
                );
            }
        }
    }
}
