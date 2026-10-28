//
// Copyright (c) 2024 ZettaScale Technology
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
// src/api/builders/queryable.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.1). The
// declaration is made by the session over its engine (`Session::declare_queryable_inner`), which
// answers with the id of the declaration where upstream's answers with the state it keeps, so the
// builder is upstream's otherwise.

use std::future::{IntoFuture, Ready};

use zenoh_core::{Resolvable, Wait};
use zenoh_result::ZResult;

use crate::{
    api::{
        handlers::{locked, Callback, DefaultHandler, IntoHandler},
        key_expr::KeyExpr,
        queryable::{Query, Queryable, QueryableInner},
        sample::Locality,
    },
    Session,
};

/// A builder for initializing a [`Queryable`].
///
/// # Examples
/// ```
/// # #[tokio::main]
/// # async fn main() {
///
/// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
/// let queryable = session.declare_queryable("key/expression").await.unwrap();
/// # }
/// ```
#[must_use = "Resolvables do nothing unless you resolve them using `.await` or `zenoh::Wait::wait`"]
#[derive(Debug)]
pub struct QueryableBuilder<'a, 'b, Handler, const BACKGROUND: bool = false> {
    pub(crate) session: &'a Session,
    pub(crate) key_expr: ZResult<KeyExpr<'b>>,
    pub(crate) complete: bool,
    pub(crate) origin: Locality,
    pub(crate) handler: Handler,
}

impl<'a, 'b> QueryableBuilder<'a, 'b, DefaultHandler> {
    /// Receive the queries for this queryable with a callback.
    ///
    /// # Examples
    /// ```
    /// # #[tokio::main]
    /// # async fn main() {
    ///
    /// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
    /// let queryable = session
    ///     .declare_queryable("key/expression")
    ///     .callback(|query| println!(">> Handling query '{}'", query.selector()))
    ///     .await
    ///     .unwrap();
    /// # }
    /// ```
    #[inline]
    pub fn callback<F>(self, callback: F) -> QueryableBuilder<'a, 'b, Callback<Query>>
    where
        F: Fn(Query) + Send + Sync + 'static,
    {
        self.with(Callback::from(callback))
    }

    /// Receive the queries for this queryable with a mutable callback.
    ///
    /// Using this guarantees that your callback will never be called concurrently.
    /// If your callback is also accepted by the [`callback`](QueryableBuilder::callback) method, we suggest you use it instead of `callback_mut`.
    ///
    /// # Examples
    /// ```
    /// # #[tokio::main]
    /// # async fn main() {
    ///
    /// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
    /// let mut n = 0;
    /// let queryable = session
    ///     .declare_queryable("key/expression")
    ///     .callback_mut(move |query| {n += 1;})
    ///     .await
    ///     .unwrap();
    /// # }
    /// ```
    #[inline]
    pub fn callback_mut<F>(self, callback: F) -> QueryableBuilder<'a, 'b, Callback<Query>>
    where
        F: FnMut(Query) + Send + Sync + 'static,
    {
        self.callback(locked(callback))
    }

    /// Receive the queries for this Queryable with a [`Handler`](crate::handlers::IntoHandler).
    ///
    /// # Examples
    /// ```no_run
    /// # #[tokio::main]
    /// # async fn main() {
    ///
    /// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
    /// let queryable = session
    ///     .declare_queryable("key/expression")
    ///     .with(flume::bounded(32))
    ///     .await
    ///     .unwrap();
    /// while let Ok(query) = queryable.recv_async().await {
    ///     println!(">> Handling query '{}'", query.selector());
    /// }
    /// # }
    /// ```
    #[inline]
    pub fn with<Handler>(self, handler: Handler) -> QueryableBuilder<'a, 'b, Handler>
    where
        Handler: IntoHandler<Query>,
    {
        let QueryableBuilder {
            session,
            key_expr,
            complete,
            origin,
            handler: _,
        } = self;
        QueryableBuilder {
            session,
            key_expr,
            complete,
            origin,
            handler,
        }
    }
}

impl<'a, 'b> QueryableBuilder<'a, 'b, Callback<Query>> {
    /// Register the queryable callback to be run in background until the session is closed.
    ///
    /// Background builder doesn't return a `Queryable` object anymore.
    ///
    /// # Examples
    /// ```
    /// # #[tokio::main]
    /// # async fn main() {
    ///
    /// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
    /// // no need to assign and keep a variable with a background queryable
    /// session
    ///     .declare_queryable("key/expression")
    ///     .callback(|query| println!(">> Handling query '{}'", query.selector()))
    ///     .background()
    ///     .await
    ///     .unwrap();
    /// # }
    /// ```
    pub fn background(self) -> QueryableBuilder<'a, 'b, Callback<Query>, true> {
        QueryableBuilder {
            session: self.session,
            key_expr: self.key_expr,
            complete: self.complete,
            origin: self.origin,
            handler: self.handler,
        }
    }
}

impl<Handler, const BACKGROUND: bool> QueryableBuilder<'_, '_, Handler, BACKGROUND> {
    /// Change queryable completeness.
    #[inline]
    pub fn complete(mut self, complete: bool) -> Self {
        self.complete = complete;
        self
    }

    /// Restrict the matching queries that will be receive by this [`Queryable`]
    /// to the ones that have the given [`Locality`](crate::sample::Locality).
    #[inline]
    pub fn allowed_origin(mut self, origin: Locality) -> Self {
        self.origin = origin;
        self
    }
}

impl<Handler> Resolvable for QueryableBuilder<'_, '_, Handler>
where
    Handler: IntoHandler<Query> + Send,
    Handler::Handler: Send,
{
    type To = ZResult<Queryable<Handler::Handler>>;
}

impl<Handler> Wait for QueryableBuilder<'_, '_, Handler>
where
    Handler: IntoHandler<Query> + Send,
    Handler::Handler: Send,
{
    fn wait(self) -> <Self as Resolvable>::To {
        let callback_sync_group = self.session.callback_group();
        let session = self.session;
        let (callback, receiver) = self.handler.into_handler();
        let mut ke = self.key_expr?;
        ke = self.session.declare_nonwild_prefix(ke)?;
        session
            .declare_queryable_inner(
                &ke,
                self.complete,
                self.origin,
                callback,
                callback_sync_group.notifier(),
            )
            .map(|id| Queryable {
                inner: QueryableInner {
                    session: self.session.downgrade(),
                    id,
                    undeclare_on_drop: true,
                    key_expr: ke.into_owned(),
                },
                handler: receiver,
                callback_sync_group,
            })
    }
}

impl<Handler> IntoFuture for QueryableBuilder<'_, '_, Handler>
where
    Handler: IntoHandler<Query> + Send,
    Handler::Handler: Send,
{
    type Output = <Self as Resolvable>::To;
    type IntoFuture = Ready<<Self as Resolvable>::To>;

    fn into_future(self) -> Self::IntoFuture {
        std::future::ready(self.wait())
    }
}

impl Resolvable for QueryableBuilder<'_, '_, Callback<Query>, true> {
    type To = ZResult<()>;
}

impl Wait for QueryableBuilder<'_, '_, Callback<Query>, true> {
    fn wait(self) -> <Self as Resolvable>::To {
        let mut ke = self.key_expr?;
        ke = self.session.declare_nonwild_prefix(ke)?;
        // See the subscriber that runs in the background: its callback counts in the session's group.
        let notifier = self.session.callback_group().notifier();
        self.session.declare_queryable_inner(
            &ke,
            self.complete,
            self.origin,
            self.handler,
            notifier,
        )?;
        Ok(())
    }
}

impl IntoFuture for QueryableBuilder<'_, '_, Callback<Query>, true> {
    type Output = <Self as Resolvable>::To;
    type IntoFuture = Ready<<Self as Resolvable>::To>;

    fn into_future(self) -> Self::IntoFuture {
        std::future::ready(self.wait())
    }
}
