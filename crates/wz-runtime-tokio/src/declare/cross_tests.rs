// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Cross-registry composability tests — exercise the design choice of
//! separate registries (per zenoh-pico's
//! `Z_FEATURE_SUBSCRIPTION` vs `Z_FEATURE_QUERYABLE` split + the
//! distinct liveliness layer) by fanning a single `NetworkMessage`
//! stream through every Remote* registry simultaneously and asserting
//! that each registry sees only its own arms.
//!
//! Lives at the module level (sibling of `subscriber` / `queryable` /
//! `liveliness`) rather than inside any single sub-module because
//! these tests reference all three at once — they don't conceptually
//! belong to any one of the sub-types.

#![cfg(test)]

use super::test_helpers::*;
use super::*;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use wz_codecs::declare::DeclareVariant;

use crate::session_glue::NetworkMessage;

#[test]
fn subscriber_and_queryable_registries_share_a_message_stream() {
    // Both registries scan the same FramePayload.messages slice
    // without seeing each other's arms — type-safe parallel
    // dispatch. Proves the design choice of separate registries
    // (per zenoh-pico's Z_FEATURE_SUBSCRIPTION vs Z_FEATURE_QUERYABLE
    // split) composes cleanly.
    let mut sub_reg = RemoteSubscriberRegistry::new();
    let mut q_reg = RemoteQueryableRegistry::new();
    let sub_count = Arc::new(AtomicUsize::new(0));
    let q_count = Arc::new(AtomicUsize::new(0));
    let s = sub_count.clone();
    let q = q_count.clone();
    sub_reg.on_subscriber_declared(move |_d, _r| {
        s.fetch_add(1, Ordering::SeqCst);
    });
    q_reg.on_queryable_declared(move |_d, _r| {
        q.fetch_add(1, Ordering::SeqCst);
    });

    let messages = vec![
        NetworkMessage::Declare(Box::new(declare_envelope_decl_subscriber(decl_subscriber(
            1,
            0,
            Some("a"),
        )))),
        NetworkMessage::Declare(Box::new(declare_envelope_decl_queryable(decl_queryable(
            2,
            0,
            Some("b"),
        )))),
        NetworkMessage::Declare(Box::new(declare_envelope_decl_subscriber(decl_subscriber(
            3,
            0,
            Some("c"),
        )))),
    ];
    let peer_table = std::collections::HashMap::new();
    sub_reg.dispatch_messages(&messages, &peer_table);
    q_reg.dispatch_messages(&messages, &peer_table);

    assert_eq!(sub_count.load(Ordering::SeqCst), 2);
    assert_eq!(q_count.load(Ordering::SeqCst), 1);
}

#[test]
fn three_registries_share_a_message_stream_independently() {
    // The full R121k surface: subscriber + queryable + liveliness
    // registries fan a single message stream into three type-safe
    // dispatch paths with zero cross-talk.
    let mut sub_reg = RemoteSubscriberRegistry::new();
    let mut q_reg = RemoteQueryableRegistry::new();
    let mut l_reg = LivelinessRegistry::new();
    let s = Arc::new(AtomicUsize::new(0));
    let q = Arc::new(AtomicUsize::new(0));
    let l = Arc::new(AtomicUsize::new(0));
    let s_cb = s.clone();
    let q_cb = q.clone();
    let l_cb = l.clone();
    sub_reg.on_subscriber_declared(move |_d, _r| {
        s_cb.fetch_add(1, Ordering::SeqCst);
    });
    q_reg.on_queryable_declared(move |_d, _r| {
        q_cb.fetch_add(1, Ordering::SeqCst);
    });
    l_reg.on_token_declared(move |_d, _r| {
        l_cb.fetch_add(1, Ordering::SeqCst);
    });

    let messages = vec![
        NetworkMessage::Declare(Box::new(declare_envelope_decl_subscriber(decl_subscriber(
            1,
            0,
            Some("a"),
        )))),
        NetworkMessage::Declare(Box::new(declare_envelope_decl_queryable(decl_queryable(
            2,
            0,
            Some("b"),
        )))),
        NetworkMessage::Declare(Box::new(declare_envelope_decl_token(decl_token(
            3,
            0,
            Some("c"),
        )))),
        NetworkMessage::Declare(Box::new(declare_envelope_decl_token(decl_token(
            4,
            0,
            Some("d"),
        )))),
    ];
    let peer_table = std::collections::HashMap::new();
    sub_reg.dispatch_messages(&messages, &peer_table);
    q_reg.dispatch_messages(&messages, &peer_table);
    l_reg.dispatch_messages(&messages, &peer_table);
    assert_eq!(s.load(Ordering::SeqCst), 1);
    assert_eq!(q.load(Ordering::SeqCst), 1);
    assert_eq!(l.load(Ordering::SeqCst), 2);

    // Suppress unused-import for DeclareVariant — the helper re-exports
    // it transitively but referencing it directly here makes the
    // dependency explicit for readers (no actual call site needed).
    let _ = std::marker::PhantomData::<DeclareVariant>;
}
