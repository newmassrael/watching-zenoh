// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The owned form, at [`TransportStorage`], of every codec that has no default
//! profile (one that holds a list the protocol bounds by nothing): the profile
//! such a value had before it named one, the heap where the build allocates
//! and the node's deployment where it does not. A site that already names
//! `crate::wire::WireStorage` keeps it.

use super::TransportStorage;

/// An owned `DeclFinal`.
#[cfg(feature = "codec-declare")]
pub type DeclFinalOwned = wz_codecs::decl_final::DeclFinalOwned<TransportStorage>;
/// An owned `DeclKexpr`.
#[cfg(feature = "codec-declare")]
pub type DeclKexprOwned = wz_codecs::decl_kexpr::DeclKexprOwned<TransportStorage>;
/// An owned `DeclQueryable`.
#[cfg(feature = "codec-declare")]
pub type DeclQueryableOwned = wz_codecs::decl_queryable::DeclQueryableOwned<TransportStorage>;
/// An owned `DeclSubscriber`.
#[cfg(feature = "codec-declare")]
pub type DeclSubscriberOwned = wz_codecs::decl_subscriber::DeclSubscriberOwned<TransportStorage>;
/// An owned `DeclToken`.
#[cfg(feature = "codec-declare")]
pub type DeclTokenOwned = wz_codecs::decl_token::DeclTokenOwned<TransportStorage>;
/// An owned `UndeclKexpr`.
#[cfg(feature = "codec-declare")]
pub type UndeclKexprOwned = wz_codecs::undecl_kexpr::UndeclKexprOwned<TransportStorage>;
/// An owned `UndeclQueryable`.
#[cfg(feature = "codec-declare")]
pub type UndeclQueryableOwned = wz_codecs::undecl_queryable::UndeclQueryableOwned<TransportStorage>;
/// An owned `UndeclSubscriber`.
#[cfg(feature = "codec-declare")]
pub type UndeclSubscriberOwned =
    wz_codecs::undecl_subscriber::UndeclSubscriberOwned<TransportStorage>;
/// An owned `UndeclToken`.
#[cfg(feature = "codec-declare")]
pub type UndeclTokenOwned = wz_codecs::undecl_token::UndeclTokenOwned<TransportStorage>;
/// An owned `Declare`.
#[cfg(feature = "codec-declare")]
pub type DeclareOwned = wz_codecs::declare::DeclareOwned<TransportStorage>;
/// The body of a [`DeclareOwned`].
#[cfg(feature = "codec-declare")]
pub type DeclareOwnedVariant = wz_codecs::declare::DeclareOwnedVariant<TransportStorage>;
/// An owned `Reply`.
#[cfg(feature = "codec-response")]
pub type ReplyOwned = wz_codecs::reply::ReplyOwned<TransportStorage>;
/// The body of a [`ReplyOwned`].
#[cfg(feature = "codec-response")]
pub type ReplyOwnedVariant = wz_codecs::reply::ReplyOwnedVariant<TransportStorage>;
/// An owned `Err`.
#[cfg(feature = "codec-response")]
pub type ErrOwned = wz_codecs::err::ErrOwned<TransportStorage>;
/// An owned `Response`.
#[cfg(feature = "codec-response")]
pub type ResponseOwned = wz_codecs::response::ResponseOwned<TransportStorage>;
/// The body of a [`ResponseOwned`].
#[cfg(feature = "codec-response")]
pub type ResponseOwnedVariant = wz_codecs::response::ResponseOwnedVariant<TransportStorage>;
/// An owned `ResponseFinal`.
#[cfg(feature = "codec-response-final")]
pub type ResponseFinalOwned = wz_codecs::response_final::ResponseFinalOwned<TransportStorage>;
/// An owned `Query`.
#[cfg(feature = "codec-request")]
pub type QueryOwned = wz_codecs::query::QueryOwned<TransportStorage>;
/// An owned `Request`.
#[cfg(feature = "codec-request")]
pub type RequestOwned = wz_codecs::request::RequestOwned<TransportStorage>;
/// The body of a [`RequestOwned`].
#[cfg(feature = "codec-request")]
pub type RequestOwnedVariant = wz_codecs::request::RequestOwnedVariant<TransportStorage>;
/// An owned `Push`.
#[cfg(feature = "codec-push")]
pub type PushOwned = wz_codecs::push::PushOwned<TransportStorage>;
/// The body of a [`PushOwned`].
#[cfg(feature = "codec-push")]
pub type PushOwnedVariant = wz_codecs::push::PushOwnedVariant<TransportStorage>;
/// An owned `MsgPut`.
pub type MsgPutOwned = wz_codecs::msg_put::MsgPutOwned<TransportStorage>;
/// An owned `MsgDel`.
pub type MsgDelOwned = wz_codecs::msg_del::MsgDelOwned<TransportStorage>;
/// An owned `ExtEnvelope`.
pub type ExtEnvelopeOwned = wz_codecs::ext_envelope::ExtEnvelopeOwned<TransportStorage>;
/// An owned `Oam`.
pub type OamOwned = wz_codecs::oam::OamOwned<TransportStorage>;
/// The body of an [`OamOwned`].
pub type OamOwnedVariant = wz_codecs::oam::OamOwnedVariant<TransportStorage>;
/// An owned `Interest`.
pub type InterestOwned = wz_codecs::interest::InterestOwned<TransportStorage>;
/// An owned `Hello`.
#[cfg(feature = "codec-hello")]
pub type HelloOwned = wz_codecs::hello::HelloOwned<TransportStorage>;
/// An owned `Linkstate`.
#[cfg(feature = "codec-linkstate")]
pub type LinkstateOwned = wz_codecs::linkstate::LinkstateOwned<TransportStorage>;
/// An owned `LinkstateList`.
#[cfg(feature = "codec-linkstate")]
pub type LinkstateListOwned = wz_codecs::linkstate_list::LinkstateListOwned<TransportStorage>;
