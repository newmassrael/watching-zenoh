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
// src/api/querier.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.1). A partial derivative:
// `QuerierState`, the entry of the table a session keeps of its queriers, is not here, since the
// engine keeps the declarations (docs/zenoh-api-on-the-engine.md, decision D3), and what concerns
// the matching of a querier (`matching_status`, `matching_listener` and the listeners it holds)
// arrives with slice Z4.

use core::fmt;
use std::{
    future::{IntoFuture, Ready},
    time::Duration,
};

use tracing::error;
use zenoh_core::{Resolvable, Wait};
use zenoh_protocol::{
    core::{CongestionControl, Parameters},
    network::request::ext::QueryTarget,
};
use zenoh_result::ZResult;
#[cfg(feature = "unstable")]
use {zenoh_config::wrappers::EntityGlobalId, zenoh_protocol::core::EntityGlobalIdProto};

use super::{
    builders::querier::QuerierGetBuilder,
    key_expr::KeyExpr,
    query::QueryConsolidation,
    sample::{Locality, QoS},
    session::{UndeclarableSealed, WeakSession},
    Id,
};
use crate::{
    api::{cancellation::SyncGroup, handlers::DefaultHandler, query::ReplyKeyExpr},
    qos::Priority,
};

/// A querier that allows sending queries to a [`Queryable`](crate::query::Queryable).
///
/// The querier is a preconfigured object that can be used to send multiple
/// queries to a given key expression. It is declared using
/// [`Session::declare_querier`](crate::Session::declare_querier).
///
/// # Examples
/// ```
/// # #[tokio::main]
/// # async fn main() {
///
/// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
/// let querier = session.declare_querier("key/expression").await.unwrap();
/// let replies = querier.get().await.unwrap();
/// # }
/// ```
#[derive(Debug)]
pub struct Querier<'a> {
    pub(crate) session: WeakSession,
    pub(crate) id: Id,
    pub(crate) key_expr: KeyExpr<'a>,
    pub(crate) qos: QoS,
    pub(crate) destination: Locality,
    pub(crate) target: QueryTarget,
    pub(crate) consolidation: QueryConsolidation,
    pub(crate) timeout: Duration,
    pub(crate) accept_replies: ReplyKeyExpr,
    pub(crate) undeclare_on_drop: bool,
    pub(crate) callback_sync_group: SyncGroup,
}

impl<'a> Querier<'a> {
    /// Returns the [`EntityGlobalId`] of this Querier.
    ///
    /// # Examples
    /// ```
    /// # #[tokio::main]
    /// # async fn main() {
    ///
    /// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
    /// let querier = session.declare_querier("key/expression")
    ///     .await
    ///     .unwrap();
    /// let querier_id = querier.id();
    /// # }
    /// ```
    #[zenoh_macros::unstable]
    pub fn id(&self) -> EntityGlobalId {
        EntityGlobalIdProto {
            zid: self.session.zid().into(),
            eid: self.id,
        }
        .into()
    }

    /// Returns the [`KeyExpr`] this querier sends queries on.
    #[inline]
    pub fn key_expr(&self) -> &KeyExpr<'a> {
        &self.key_expr
    }

    /// Get the [`CongestionControl`] applied when routing the data.
    #[inline]
    pub fn congestion_control(&self) -> CongestionControl {
        self.qos.congestion_control()
    }

    /// Get the [`Priority`] of the querier requests.
    #[inline]
    pub fn priority(&self) -> Priority {
        self.qos.priority()
    }

    /// See details in the [`ReplyKeyExpr`](crate::query::ReplyKeyExpr) documentation.
    ///
    /// Queries may or may not accept replies on key expressions that do not intersect with their own key expression.
    /// This getter allows you to check whether this querier accepts such disjoint replies.
    /// Currently, this information is passed in the [`Selector`](crate::api::selector::Selector) parameters as the `_anyke` parameter.
    #[inline]
    pub fn accept_replies(&self) -> ReplyKeyExpr {
        self.accept_replies
    }

    /// Send a query. Returns a builder to customize the query. The builder
    /// resolves to a [`handler`](crate::handlers) generating a series of
    /// [`Reply`](crate::api::query::Reply) values for each response received.
    ///
    /// # Examples
    /// ```
    /// # #[tokio::main]
    /// # async fn main() {
    ///
    /// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
    /// let querier = session.declare_querier("key/expression").await.unwrap();
    /// let replies = querier.get();
    /// # }
    /// ```
    #[inline]
    pub fn get(&self) -> QuerierGetBuilder<'_, '_, DefaultHandler> {
        QuerierGetBuilder {
            querier: self,
            #[cfg(feature = "unstable")]
            source_info: None,
            value: None,
            attachment: None,
            parameters: Parameters::empty(),
            handler: DefaultHandler::default(),
            #[cfg(feature = "unstable")]
            cancellation_token: None,
            #[cfg(feature = "unstable")]
            timestamp_instrumentation: None,
        }
    }

    /// Undeclare the [`Querier`], informing the network that it needn't optimize queries for its key expression anymore.
    ///
    /// # Examples
    /// ```
    /// # #[tokio::main]
    /// # async fn main() {
    ///
    /// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
    /// let querier = session.declare_querier("key/expression").await.unwrap();
    /// querier.undeclare().await.unwrap();
    /// # }
    /// ```
    pub fn undeclare(self) -> QuerierUndeclaration<'a> {
        UndeclarableSealed::undeclare_inner(self, ())
    }

    fn undeclare_impl(&mut self) -> ZResult<()> {
        // set the flag first to avoid double panic if this function panics
        self.undeclare_on_drop = false;
        self.session.undeclare_querier_inner(self.id)
    }

    #[zenoh_macros::internal]
    pub fn session(&self) -> &WeakSession {
        &self.session
    }
}

impl<'a> UndeclarableSealed<()> for Querier<'a> {
    type Undeclaration = QuerierUndeclaration<'a>;

    fn undeclare_inner(self, _: ()) -> Self::Undeclaration {
        QuerierUndeclaration {
            querier: self,
            wait_callbacks: false,
        }
    }
}

/// A [`Resolvable`] returned when undeclaring a querier.
///
/// # Examples
/// ```
/// # #[tokio::main]
/// # async fn main() {
///
/// let session = zenoh::open(zenoh::Config::default()).await.unwrap();
/// let querier = session.declare_querier("key/expression").await.unwrap();
/// querier.undeclare().await.unwrap();
/// # }
/// ```
#[must_use = "Resolvables do nothing unless you resolve them using `.await` or `zenoh::Wait::wait`"]
pub struct QuerierUndeclaration<'a> {
    querier: Querier<'a>,
    wait_callbacks: bool,
}

impl fmt::Debug for QuerierUndeclaration<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuerierUndeclaration")
            .field("querier", &self.querier)
            .field("wait_callbacks", &self.wait_callbacks)
            .finish()
    }
}

impl<'a> QuerierUndeclaration<'a> {
    #[zenoh_macros::internal_or_unstable]
    /// Block in undeclare operation until all currently running instances of reply and matching listeners' callbacks (if any) return.
    pub fn wait_callbacks(mut self) -> Self {
        self.wait_callbacks = true;
        self
    }
}

impl Resolvable for QuerierUndeclaration<'_> {
    type To = ZResult<()>;
}

impl Wait for QuerierUndeclaration<'_> {
    fn wait(mut self) -> <Self as Resolvable>::To {
        self.querier.undeclare_impl()?;
        if self.wait_callbacks {
            self.querier.callback_sync_group.wait();
        }
        Ok(())
    }
}

impl IntoFuture for QuerierUndeclaration<'_> {
    type Output = <Self as Resolvable>::To;
    type IntoFuture = Ready<<Self as Resolvable>::To>;

    fn into_future(self) -> Self::IntoFuture {
        std::future::ready(self.wait())
    }
}

impl Drop for Querier<'_> {
    fn drop(&mut self) {
        if self.undeclare_on_drop {
            if let Err(error) = self.undeclare_impl() {
                error!(error);
            }
        }
    }
}
