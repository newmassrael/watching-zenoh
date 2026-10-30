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
// src/api/builders/reply.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2). The response an
// error reply is made of is the engine's to write, so `ReplyErrBuilder` hands its payload and
// encoding to the query (`Query::reply_err_with`) where upstream's builds the response itself.

use std::future::{IntoFuture, Ready};

use uhlc::Timestamp;
use zenoh_core::{Resolvable, Wait};
use zenoh_protocol::core::CongestionControl;
use zenoh_result::ZResult;

#[cfg(feature = "unstable")]
use crate::api::sample::SourceInfo;
use crate::api::{
    builders::sample::{
        EncodingBuilderTrait, QoSBuilderTrait, SampleBuilder, SampleBuilderTrait,
        TimestampBuilderTrait,
    },
    bytes::{OptionZBytes, ZBytes},
    encoding::Encoding,
    key_expr::KeyExpr,
    publisher::Priority,
    queryable::Query,
    sample::QoSBuilder,
};

#[derive(Debug)]
pub struct ReplyBuilderPut {
    payload: ZBytes,
    encoding: Encoding,
}

#[derive(Debug)]
pub struct ReplyBuilderDelete;

/// A builder for a reply to a [`Query`](crate::query::Query): the sample of a put or of a delete
/// sent back to the one who asked.
///
/// Returned by [`Query::reply`](crate::query::Query::reply) and
/// [`Query::reply_del`](crate::query::Query::reply_del).
#[must_use = "Resolvables do nothing unless you resolve them using `.await` or `zenoh::Wait::wait`"]
#[derive(Debug)]
pub struct ReplyBuilder<'a, 'b, T> {
    query: &'a Query,
    key_expr: ZResult<KeyExpr<'b>>,
    kind: T,
    timestamp: Option<Timestamp>,
    qos: QoSBuilder,
    #[cfg(feature = "unstable")]
    source_info: Option<SourceInfo>,
    attachment: Option<ZBytes>,
}

impl<'a, 'b> ReplyBuilder<'a, 'b, ReplyBuilderPut> {
    pub(crate) fn new<TryIntoKeyExpr, IntoZBytes>(
        query: &'a Query,
        key_expr: TryIntoKeyExpr,
        payload: IntoZBytes,
    ) -> Self
    where
        TryIntoKeyExpr: TryInto<KeyExpr<'b>>,
        <TryIntoKeyExpr as TryInto<KeyExpr<'b>>>::Error: Into<zenoh_result::Error>,
        IntoZBytes: Into<ZBytes>,
    {
        Self {
            query,
            key_expr: key_expr.try_into().map_err(Into::into),
            qos: query.inner.qos.into(),
            kind: ReplyBuilderPut {
                payload: payload.into(),
                encoding: Encoding::default(),
            },
            timestamp: None,
            #[cfg(feature = "unstable")]
            source_info: None,
            attachment: None,
        }
    }
}

impl<'a, 'b> ReplyBuilder<'a, 'b, ReplyBuilderDelete> {
    pub(crate) fn new<TryIntoKeyExpr>(query: &'a Query, key_expr: TryIntoKeyExpr) -> Self
    where
        TryIntoKeyExpr: TryInto<KeyExpr<'b>>,
        <TryIntoKeyExpr as TryInto<KeyExpr<'b>>>::Error: Into<zenoh_result::Error>,
    {
        Self {
            query,
            key_expr: key_expr.try_into().map_err(Into::into),
            qos: query.inner.qos.into(),
            kind: ReplyBuilderDelete,
            timestamp: None,
            #[cfg(feature = "unstable")]
            source_info: None,
            attachment: None,
        }
    }
}

#[zenoh_macros::internal_trait]
impl<T> TimestampBuilderTrait for ReplyBuilder<'_, '_, T> {
    /// Sets the timestamp of this reply.
    fn timestamp<U: Into<Option<Timestamp>>>(self, timestamp: U) -> Self {
        Self {
            timestamp: timestamp.into(),
            ..self
        }
    }
}

#[zenoh_macros::internal_trait]
impl<T> SampleBuilderTrait for ReplyBuilder<'_, '_, T> {
    fn attachment<U: Into<OptionZBytes>>(self, attachment: U) -> Self {
        let attachment: OptionZBytes = attachment.into();
        Self {
            attachment: attachment.into(),
            ..self
        }
    }

    #[cfg(feature = "unstable")]
    fn source_info<TS: Into<Option<SourceInfo>>>(self, source_info: TS) -> Self {
        Self {
            source_info: source_info.into(),
            ..self
        }
    }
}

#[zenoh_macros::internal_trait]
impl<T> QoSBuilderTrait for ReplyBuilder<'_, '_, T> {
    #[deprecated = "calling this function has no impact, replies will use the query congestion control"]
    fn congestion_control(self, _congestion_control: CongestionControl) -> Self {
        self
    }

    #[deprecated = "calling this function has no impact, replies will use the query priority"]
    fn priority(self, _priority: Priority) -> Self {
        self
    }

    fn express(self, is_express: bool) -> Self {
        let qos = self.qos.express(is_express);
        Self { qos, ..self }
    }
}

#[zenoh_macros::internal_trait]
impl EncodingBuilderTrait for ReplyBuilder<'_, '_, ReplyBuilderPut> {
    fn encoding<T: Into<Encoding>>(self, encoding: T) -> Self {
        Self {
            kind: ReplyBuilderPut {
                encoding: encoding.into(),
                ..self.kind
            },
            ..self
        }
    }
}

impl<T> Resolvable for ReplyBuilder<'_, '_, T> {
    type To = ZResult<()>;
}

impl Wait for ReplyBuilder<'_, '_, ReplyBuilderPut> {
    fn wait(self) -> <Self as Resolvable>::To {
        let key_expr = self.key_expr?.into_owned();
        let sample = SampleBuilder::put(key_expr, self.kind.payload)
            .encoding(self.kind.encoding)
            .timestamp(self.timestamp)
            .qos(self.qos.into());
        #[cfg(feature = "unstable")]
        let sample = sample.source_info(self.source_info);
        let sample = sample.attachment(self.attachment);
        self.query._reply_sample(sample.into())
    }
}

impl Wait for ReplyBuilder<'_, '_, ReplyBuilderDelete> {
    fn wait(self) -> <Self as Resolvable>::To {
        let key_expr = self.key_expr?.into_owned();
        let sample = SampleBuilder::delete(key_expr)
            .timestamp(self.timestamp)
            .qos(self.qos.into());
        #[cfg(feature = "unstable")]
        let sample = sample.source_info(self.source_info);
        let sample = sample.attachment(self.attachment);
        self.query._reply_sample(sample.into())
    }
}

impl IntoFuture for ReplyBuilder<'_, '_, ReplyBuilderPut> {
    type Output = <Self as Resolvable>::To;
    type IntoFuture = Ready<<Self as Resolvable>::To>;

    fn into_future(self) -> Self::IntoFuture {
        std::future::ready(self.wait())
    }
}

impl IntoFuture for ReplyBuilder<'_, '_, ReplyBuilderDelete> {
    type Output = <Self as Resolvable>::To;
    type IntoFuture = Ready<<Self as Resolvable>::To>;

    fn into_future(self) -> Self::IntoFuture {
        std::future::ready(self.wait())
    }
}

/// A builder for an error reply to a [`Query`](crate::query::Query).
///
/// Returned by [`Query::reply_err`](crate::query::Query::reply_err).
#[must_use = "Resolvables do nothing unless you resolve them using `.await` or `zenoh::Wait::wait`"]
#[derive(Debug)]
pub struct ReplyErrBuilder<'a> {
    query: &'a Query,
    payload: ZBytes,
    encoding: Encoding,
}

impl<'a> ReplyErrBuilder<'a> {
    pub(crate) fn new<IntoZBytes>(query: &'a Query, payload: IntoZBytes) -> ReplyErrBuilder<'a>
    where
        IntoZBytes: Into<ZBytes>,
    {
        Self {
            query,
            payload: payload.into(),
            encoding: Encoding::default(),
        }
    }
}

#[zenoh_macros::internal_trait]
impl EncodingBuilderTrait for ReplyErrBuilder<'_> {
    fn encoding<T: Into<Encoding>>(self, encoding: T) -> Self {
        Self {
            encoding: encoding.into(),
            ..self
        }
    }
}

impl Resolvable for ReplyErrBuilder<'_> {
    type To = ZResult<()>;
}

impl Wait for ReplyErrBuilder<'_> {
    fn wait(self) -> <Self as Resolvable>::To {
        self.query.reply_err_with(self.payload, self.encoding)
    }
}

impl IntoFuture for ReplyErrBuilder<'_> {
    type Output = <Self as Resolvable>::To;
    type IntoFuture = Ready<<Self as Resolvable>::To>;

    fn into_future(self) -> Self::IntoFuture {
        std::future::ready(self.wait())
    }
}
