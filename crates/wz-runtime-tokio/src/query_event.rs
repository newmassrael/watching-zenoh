// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311r — consumer-facing wrappers for the queryable callback
//! signature. The wrappers decouple the application API from the
//! wire-codec layer:
//!
//! - [`QueryEvent`] replaces `&wz_codecs::query::Query` in the
//!   callback's first argument. Fields are unconditional plain types
//!   (`&str`, `Option<&[u8]>`, `u64`) so the callback signature stays
//!   stable across wz-codecs evolution and across feature gating that
//!   might one day make `wz_codecs::query::Query` conditionally
//!   available.
//! - [`ReplyEmitter`] replaces `&mut crate::query::QueryResponder` in
//!   the callback's second argument. The method surface
//!   (`reply` / `reply_del` / `reply_err` / `rid` / `keyexpr_literal` /
//!   `with_responder` / `clear_responder` / `responder`) mirrors
//!   `QueryResponder` 1:1 so the rename is mechanical at every call
//!   site; the wrapper hides the underlying
//!   `Vec<crate::query::QueryReply>` borrow from the application
//!   surface, paving the way for a future round to refactor the
//!   reply-staging mechanism without breaking application code.
//!
//! ## Why the wrappers are unconditional even when
//! `query-queryable` is OFF
//!
//! [`Session::declare_queryable`] is type-ungated (R311r — Result
//! form returning `Err(QueryableAliasError::FeatureDisabled)` when
//! the feature is OFF). Its callback parameter type must therefore be
//! a valid Rust type regardless of feature state. Both wrappers
//! contain a `#[cfg(not(feature = "query-queryable"))] PhantomData`
//! variant so the structs are well-formed when the registry-side
//! types they wrap are elided; the methods compile to no-ops in that
//! configuration because no `ReplyEmitter` instance is ever
//! constructed (the feature-OFF declare branch returns FeatureDisabled
//! before the registry-side wrapping happens). The PhantomData arm is
//! defensive: it preserves Rust's "all types in a public API must be
//! nameable across builds" contract without ever materialising into a
//! runtime instance.

#[cfg(not(feature = "query-queryable"))]
use std::marker::PhantomData;

/// R311r — application-visible projection of an inbound query that
/// triggered a queryable callback. Replaces direct exposure of
/// `&wz_codecs::query::Query` in the callback signature.
///
/// Field types are all unconditional plain types so the struct
/// compiles regardless of wz-codecs feature gating. The lifetime
/// borrows the resolved keyexpr literal + the optional parameters /
/// attachment byte slices from the dispatcher's per-callback stack
/// frame; user code that needs to retain the data beyond the callback
/// body must clone explicitly (`to_string()` / `to_vec()`).
///
/// ## Field mapping from `wz_codecs::query::Query`
///
/// - [`Self::keyexpr`] — the resolved literal keyexpr from the outer
///   `Request.keyexpr` envelope (alias-resolved through the peer
///   keyexpr table for `mapping_id != 0` forms).
/// - [`Self::parameters`] — `Query.parameters` raw byte slice (URL-
///   style query string; consumers typically convert via
///   `std::str::from_utf8`). `None` when the inbound query carries no
///   parameters segment.
/// - [`Self::attachment`] — the attachment ext payload extracted from
///   `Query.extensions` (zenoh-pico ext_id `_Z_MSG_EXT_ENC_ZBUF |
///   0x04`). `None` when no attachment ext is present.
/// - [`Self::rid`] — the request id from the outer `Request.rid`
///   envelope (correlation key for the reply chain).
#[derive(Debug, Clone, Copy)]
pub struct QueryEvent<'a> {
    /// Resolved keyexpr literal. Always non-empty (an un-resolvable
    /// keyexpr drops the dispatch before the callback is reached).
    pub keyexpr: &'a str,
    /// Raw parameters bytes (URL-style query string). `None` when
    /// the query carries no parameters segment.
    pub parameters: Option<&'a [u8]>,
    /// Attachment payload extracted from the Query ext-chain.
    /// `None` when no attachment ext is present.
    pub attachment: Option<&'a [u8]>,
    /// Request id (correlation key for the matching reply chain).
    pub rid: u64,
}

/// R311r — application-visible reply emitter. Replaces direct exposure
/// of `&mut crate::query::QueryResponder` in the callback signature.
///
/// Method surface mirrors `QueryResponder` 1:1 so the rename is
/// mechanical at every callsite. The wrapper holds an internal borrow
/// of the underlying `QueryResponder` when the `query-queryable`
/// feature is ON, or a [`PhantomData`] sentinel when OFF (the
/// feature-OFF declare branch returns `FeatureDisabled` before any
/// `ReplyEmitter` is constructed, so the no-op method bodies are
/// never reached in practice).
pub struct ReplyEmitter<'a> {
    #[cfg(feature = "query-queryable")]
    inner: &'a mut crate::query::QueryResponder<'a>,
    #[cfg(not(feature = "query-queryable"))]
    _marker: PhantomData<&'a mut ()>,
}

impl<'a> ReplyEmitter<'a> {
    /// Construct a wrapper around an internal `QueryResponder`.
    /// Crate-private; only the queryable dispatch path inside
    /// [`crate::query::QueryableRegistry`] should construct
    /// `ReplyEmitter` instances. Unconditional because
    /// `QueryResponder` is itself type-ungated after R311r so the
    /// `&mut QueryResponder` parameter type compiles in every
    /// consumer-feature subset; the feature-OFF branch never
    /// actually reaches this constructor (the fire_matching_queryables
    /// loop iterates an empty queryable list when no callback can be
    /// registered), so the `_marker` arm is compile-time scaffolding
    /// only.
    pub(crate) fn from_responder(inner: &'a mut crate::query::QueryResponder<'a>) -> Self {
        #[cfg(feature = "query-queryable")]
        {
            Self { inner }
        }
        #[cfg(not(feature = "query-queryable"))]
        {
            let _ = inner;
            Self {
                _marker: PhantomData,
            }
        }
    }

    /// Emit a Put-form data reply with the given payload bytes.
    /// Mirror of [`crate::query::QueryResponder::send_reply`]; see
    /// that doc-comment for the per-call accumulation semantics.
    pub fn reply(&mut self, payload: &[u8]) {
        #[cfg(feature = "query-queryable")]
        self.inner.send_reply(payload);
        #[cfg(not(feature = "query-queryable"))]
        {
            let _ = payload;
        }
    }

    /// Emit a Del-form reply (queryable signals deletion at the
    /// keyexpr). Mirror of
    /// [`crate::query::QueryResponder::send_reply_del`].
    pub fn reply_del(&mut self) {
        #[cfg(feature = "query-queryable")]
        self.inner.send_reply_del();
    }

    /// Emit an Err-form reply. Mirror of
    /// [`crate::query::QueryResponder::send_err`].
    pub fn reply_err(&mut self, encoding_id: Option<u32>, schema: Option<&str>, payload: &[u8]) {
        // R311cj — query-reply-err gates the Err-form reply emit on
        // top of the existing query-queryable gate. cfg-off (either
        // axis): silent no-op (R311g1 signature stability).
        #[cfg(all(feature = "query-queryable", feature = "query-reply-err"))]
        self.inner.send_err(encoding_id, schema, payload);
        #[cfg(not(all(feature = "query-queryable", feature = "query-reply-err")))]
        {
            let _ = (encoding_id, schema, payload);
        }
    }

    /// Attach a responder identity to every subsequent
    /// [`Self::reply`] / [`Self::reply_del`] / [`Self::reply_err`]
    /// call. Mirror of
    /// [`crate::query::QueryResponder::with_responder`]; panics on a
    /// `zid` length outside `1..=16` (zenoh-pico ZenohId wire
    /// constraint).
    pub fn with_responder(&mut self, zid: &[u8], eid: u32) -> &mut Self {
        #[cfg(feature = "query-queryable")]
        {
            self.inner.with_responder(zid, eid);
        }
        #[cfg(not(feature = "query-queryable"))]
        {
            let _ = (zid, eid);
        }
        self
    }

    /// Clear the responder identity attached via
    /// [`Self::with_responder`]. Mirror of
    /// [`crate::query::QueryResponder::clear_responder`].
    pub fn clear_responder(&mut self) -> &mut Self {
        #[cfg(feature = "query-queryable")]
        {
            self.inner.clear_responder();
        }
        self
    }

    /// Inbound request id this emitter is replying to. Mirror of
    /// [`crate::query::QueryResponder::rid`].
    pub fn rid(&self) -> u64 {
        #[cfg(feature = "query-queryable")]
        return self.inner.rid();
        #[cfg(not(feature = "query-queryable"))]
        return 0;
    }

    /// Resolved keyexpr literal this emitter is bound to. Mirror of
    /// [`crate::query::QueryResponder::keyexpr_literal`].
    pub fn keyexpr_literal(&self) -> &str {
        #[cfg(feature = "query-queryable")]
        return self.inner.keyexpr_literal();
        #[cfg(not(feature = "query-queryable"))]
        return "";
    }

    /// Current responder identity (read-only view). Mirror of
    /// [`crate::query::QueryResponder::responder`].
    pub fn responder(&self) -> Option<(&[u8], u32)> {
        #[cfg(feature = "query-queryable")]
        return self.inner.responder();
        #[cfg(not(feature = "query-queryable"))]
        return None;
    }
}
