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
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh 1.10.2, file
// src/api/builders/matching_listener.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2). The
// listener is declared on the engine through the session (`WeakSession::declare_matches_listener_inner`),
// which answers with the id of the listener and not with the entry of a table, so the builder is
// upstream's but for the id it reads from that answer.

use std::{
    collections::HashSet,
    future::{IntoFuture, Ready},
    sync::{Arc, Mutex},
};

use zenoh_core::{Resolvable, Wait};
use zenoh_result::ZResult;

use crate::api::{
    cancellation::SyncGroupNotifier,
    handlers::{Callback, DefaultHandler, IntoHandler},
    key_expr::KeyExpr,
    matching::{MatchingListener, MatchingListenerInner, MatchingStatus, MatchingStatusType},
    sample::Locality,
    session::WeakSession,
    Id,
};

/// A builder for initializing a [`MatchingListener`]
/// returned by the [`Publisher::matching_listener`](crate::pubsub::Publisher::matching_listener)
/// or [`Querier::matching_listener`](crate::query::Querier::matching_listener) methods.
///
#[derive(Debug)]
pub struct MatchingListenerBuilder<'a, Handler, const BACKGROUND: bool = false> {
    pub(crate) session: &'a WeakSession,
    pub(crate) key_expr: &'a KeyExpr<'a>,
    pub(crate) destination: Locality,
    pub(crate) matching_listeners: &'a Arc<Mutex<HashSet<Id>>>,
    pub(crate) matching_status_type: MatchingStatusType,
    pub handler: Handler,
    pub(crate) parent_callback_sync_group_notifier: Option<SyncGroupNotifier>,
}

impl<'a> MatchingListenerBuilder<'a, DefaultHandler> {
    /// Receive the MatchingStatuses for this listener with a callback.
    ///
    /// # Examples
    /// ```
    /// # #[tokio::main]
    /// # async fn main() {
    ///
    /// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
    /// let publisher = session.declare_publisher("key/expression").await.unwrap();
    /// let matching_listener = publisher
    ///     .matching_listener()
    ///     .callback(|matching_status| {
    ///         if matching_status.matching() {
    ///             println!("Publisher has matching subscribers.");
    ///         } else {
    ///             println!("Publisher has NO MORE matching subscribers.");
    ///         }
    ///     })
    ///     .await
    ///     .unwrap();
    /// # }
    /// ```
    #[inline]
    pub fn callback<F>(self, callback: F) -> MatchingListenerBuilder<'a, Callback<MatchingStatus>>
    where
        F: Fn(MatchingStatus) + Send + Sync + 'static,
    {
        self.with(Callback::from(callback))
    }

    /// Receive the MatchingStatuses for this listener with a mutable callback.
    ///
    /// # Examples
    /// ```
    /// # #[tokio::main]
    /// # async fn main() {
    ///
    /// let mut n = 0;
    /// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
    /// let publisher = session.declare_publisher("key/expression").await.unwrap();
    /// let matching_listener = publisher
    ///     .matching_listener()
    ///     .callback_mut(move |_matching_status| { n += 1; })
    ///     .await
    ///     .unwrap();
    /// # }
    /// ```
    #[inline]
    pub fn callback_mut<F>(
        self,
        callback: F,
    ) -> MatchingListenerBuilder<'a, Callback<MatchingStatus>>
    where
        F: FnMut(MatchingStatus) + Send + Sync + 'static,
    {
        self.callback(crate::api::handlers::locked(callback))
    }

    /// Receive the MatchingStatuses for this listener with a [`Handler`](IntoHandler).
    ///
    /// # Examples
    /// ```no_run
    /// # #[tokio::main]
    /// # async fn main() {
    ///
    /// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
    /// let publisher = session.declare_publisher("key/expression").await.unwrap();
    /// let matching_listener = publisher
    ///     .matching_listener()
    ///     .with(flume::bounded(32))
    ///     .await
    ///     .unwrap();
    /// while let Ok(matching_status) = matching_listener.recv_async().await {
    ///     if matching_status.matching() {
    ///         println!("Publisher has matching subscribers.");
    ///     } else {
    ///         println!("Publisher has NO MORE matching subscribers.");
    ///     }
    /// }
    /// # }
    /// ```
    #[inline]
    pub fn with<Handler>(self, handler: Handler) -> MatchingListenerBuilder<'a, Handler>
    where
        Handler: IntoHandler<MatchingStatus>,
    {
        MatchingListenerBuilder {
            session: self.session,
            key_expr: self.key_expr,
            destination: self.destination,
            matching_listeners: self.matching_listeners,
            matching_status_type: self.matching_status_type,
            handler,
            parent_callback_sync_group_notifier: self.parent_callback_sync_group_notifier,
        }
    }
}

impl<'a> MatchingListenerBuilder<'a, Callback<MatchingStatus>> {
    /// Make listener run in the background until the publisher is undeclared.
    ///
    /// The background builder doesn't return a `MatchingListener` object anymore.
    ///
    /// # Examples
    /// ```
    /// # #[tokio::main]
    /// # async fn main() {
    ///
    /// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
    /// let publisher = session.declare_publisher("key/expression").await.unwrap();
    /// // no need to assign and keep a variable for a background listener
    /// publisher
    ///     .matching_listener()
    ///     .callback(|matching_status| {
    ///         if matching_status.matching() {
    ///             println!("Publisher has matching subscribers.");
    ///         } else {
    ///             println!("Publisher has NO MORE matching subscribers.");
    ///         }
    ///     })
    ///     .background()
    ///     .await
    ///     .unwrap();
    /// # }
    /// ```
    pub fn background(self) -> MatchingListenerBuilder<'a, Callback<MatchingStatus>, true> {
        MatchingListenerBuilder {
            session: self.session,
            destination: self.destination,
            matching_listeners: self.matching_listeners,
            key_expr: self.key_expr,
            matching_status_type: self.matching_status_type,
            handler: self.handler,
            parent_callback_sync_group_notifier: self.parent_callback_sync_group_notifier,
        }
    }
}

impl<Handler> Resolvable for MatchingListenerBuilder<'_, Handler>
where
    Handler: IntoHandler<MatchingStatus> + Send,
    Handler::Handler: Send,
{
    type To = ZResult<MatchingListener<Handler::Handler>>;
}

impl<Handler> Wait for MatchingListenerBuilder<'_, Handler>
where
    Handler: IntoHandler<MatchingStatus> + Send,
    Handler::Handler: Send,
{
    fn wait(self) -> <Self as Resolvable>::To {
        let callback_sync_group = self.session.callback_group();
        let (callback, handler) = self.handler.into_handler();
        let id = self.session.declare_matches_listener_inner(
            self.key_expr,
            self.destination,
            self.matching_status_type,
            callback,
            callback_sync_group.notifier(),
        )?;
        zlock!(self.matching_listeners).insert(id);
        Ok(MatchingListener {
            inner: MatchingListenerInner {
                session: self.session.clone(),
                matching_listeners: self.matching_listeners.clone(),
                id,
                undeclare_on_drop: true,
            },
            handler,
            callback_sync_group,
        })
    }
}

impl<Handler> IntoFuture for MatchingListenerBuilder<'_, Handler>
where
    Handler: IntoHandler<MatchingStatus> + Send,
    Handler::Handler: Send,
{
    type Output = <Self as Resolvable>::To;
    type IntoFuture = Ready<<Self as Resolvable>::To>;

    fn into_future(self) -> Self::IntoFuture {
        std::future::ready(crate::api::cancellation::blocking(|| self.wait()))
    }
}

impl Resolvable for MatchingListenerBuilder<'_, Callback<MatchingStatus>, true> {
    type To = ZResult<()>;
}

impl Wait for MatchingListenerBuilder<'_, Callback<MatchingStatus>, true> {
    fn wait(self) -> <Self as Resolvable>::To {
        let id = self.session.declare_matches_listener_inner(
            self.key_expr,
            self.destination,
            self.matching_status_type,
            self.handler,
            // A listener of a querier counts in the querier's group, which is the session's child;
            // one of an entity that has none, in the session's.
            self.parent_callback_sync_group_notifier
                .or_else(|| self.session.callback_group().notifier()),
        )?;
        zlock!(self.matching_listeners).insert(id);
        Ok(())
    }
}

impl IntoFuture for MatchingListenerBuilder<'_, Callback<MatchingStatus>, true> {
    type Output = <Self as Resolvable>::To;
    type IntoFuture = Ready<<Self as Resolvable>::To>;

    fn into_future(self) -> Self::IntoFuture {
        std::future::ready(crate::api::cancellation::blocking(|| self.wait()))
    }
}
