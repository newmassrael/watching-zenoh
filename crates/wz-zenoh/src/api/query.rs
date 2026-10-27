//
// Copyright (c) 2023 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh 1.10.1, file
// src/api/query.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.1). A partial derivative:
// only `ReplyKeyExpr` is here, which the query a queryable receives says. The target and the
// consolidation of a query, the reply and its error, and the state a session keeps of its pending
// queries arrive with slice Z3b of docs/zenoh-api-on-the-engine.md; the documentation names the
// builders of a get in code spans until they exist.

use serde::Deserialize;

/// The kinds of accepted query replies.
///
/// The [`Queryable`](crate::query::Queryable) may serve glob-like key expressions.
/// E.g., the queryable may be declared with the key expression `foo/*`.
/// At the same time, it may send replies with more specific key expressions, e.g., `foo/bar` or `foo/baz`.
/// This may cause a situation when the queryable receives a query with the key expression `foo/bar`
/// and replies to it with the key expression `foo/baz`.
///
/// By default, this behavior is not allowed. Calling [`Query::reply`](crate::query::Query::reply) on
/// a query for `foo/bar` with key expression `foo/baz` will result in an error on the sending side.
///
/// But if the query is sent with the [`ReplyKeyExpr::Any`] parameter in `accept_replies` (of the
/// builder of a `Session::get`, or of the builder of a `Querier`) then the reply with a disjoint
/// key expression will be accepted for this query.
/// Currently, this information is passed in the [`Selector`](crate::api::selector::Selector) parameters as the `_anyke` parameter.
///
/// The [`Queryable`](crate::query::Queryable) may check this parameter with
/// [`Query::accepts_replies`](crate::query::Query::accepts_replies).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Deserialize)]
pub enum ReplyKeyExpr {
    /// Accept replies whose key expressions may not match the query key expression.
    Any,
    #[default]
    /// Accept replies whose key expressions match the query key expression.
    MatchingQuery,
}
