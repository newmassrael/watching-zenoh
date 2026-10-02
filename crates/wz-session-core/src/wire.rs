// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The owned wire types of the data plane, spelled at
//! [`WireStorage`](crate::network_message::WireStorage).
//!
//! # Why a module of aliases
//!
//! The generated owned types are generic over a storage profile and default to
//! the SCE one: `PushOwned` is `PushOwned<DefaultStorage>`. The messages a
//! receive path hands up are not the default any more on an AP build (they are
//! [`RxShared`](crate::rx_profile::RxShared), whose byte fields are ranges of the
//! frame), so a function that takes "a received Push" has to name that profile or
//! it silently names the wrong type. Naming it at every site would put a generic
//! argument on a few hundred lines; naming it once, here, under the short names
//! the sites already use, puts one `use` line on each file and nothing else.
//!
//! The aliases are for code that holds a RECEIVED message, or builds one that a
//! receive path will hold (a builder whose output is encoded and also dispatched
//! to a local subscriber, a test fixture handed to a registry). Code that works
//! on any profile is generic over `S: CodecStorage` instead and takes the
//! generated types directly; the two do not mix on one function.
//!
//! # What is not here
//!
//! Types the control plane owns stay on the default: a `Declare`'s key
//! expression, an `Init`'s extensions, an `Oam` body. A type that both planes
//! carry (`WireexprOwned`, `ExtEntryOwned`) is NOT aliased here for a reason a
//! reader would otherwise rediscover: a helper that took the alias would accept
//! one plane's value and refuse the other's. Those helpers are generic.

use sce_forge_runtime::codec::{CodecError, CodecStorage, SceByteBuf, SceStr};

pub use crate::network_message::WireStorage;

/// Copy `b` into the byte container of a wire-profile message field of declared
/// capacity `N`. The counterpart of [`codec_owned::owned_bytes`](crate::codec_owned::owned_bytes)
/// for fields of the data plane: that one builds the DEFAULT profile's
/// container, which is the wrong type for a field of a [`PushOwned`] on an AP
/// build. `N` is inferred from the field the result is assigned to.
///
/// A COPY on every profile: a builder's bytes are not part of any frame, so
/// there is nothing here to share.
#[allow(dead_code)] // used by the codec-gated builders; unused in no-codec subsets
pub fn wire_bytes<const N: usize>(
    b: &[u8],
) -> Result<<WireStorage as CodecStorage>::Bytes<N>, CodecError> {
    <<WireStorage as CodecStorage>::Bytes<N> as SceByteBuf>::from_slice(b)
}

/// Copy `s` into the text container of a wire-profile message field of declared
/// capacity `N`; see [`wire_bytes`].
#[allow(dead_code)] // used by the codec-gated builders; unused in no-codec subsets
pub fn wire_string<const N: usize>(
    s: &str,
) -> Result<<WireStorage as CodecStorage>::Str<N>, CodecError> {
    <<WireStorage as CodecStorage>::Str<N> as SceStr>::from_view(s)
}

/// A received (or about-to-be-dispatched) `Push`.
#[cfg(feature = "codec-push")]
pub type PushOwned = wz_codecs::push::PushOwned<WireStorage>;
/// The body of a [`PushOwned`].
#[cfg(feature = "codec-push")]
pub type PushOwnedVariant = wz_codecs::push::PushOwnedVariant<WireStorage>;

/// A received `Request`.
#[cfg(feature = "codec-request")]
pub type RequestOwned = wz_codecs::request::RequestOwned<WireStorage>;
/// The body of a [`RequestOwned`].
#[cfg(feature = "codec-request")]
pub type RequestOwnedVariant = wz_codecs::request::RequestOwnedVariant<WireStorage>;

/// A received `Response`.
#[cfg(feature = "codec-response")]
pub type ResponseOwned = wz_codecs::response::ResponseOwned<WireStorage>;
/// The body of a [`ResponseOwned`].
#[cfg(feature = "codec-response")]
pub type ResponseOwnedVariant = wz_codecs::response::ResponseOwnedVariant<WireStorage>;

/// The parts a wire-plane message is built from, at [`WireStorage`].
///
/// For the BUILDERS of `Push`, `Request` and `Response` messages
/// (`push_build`, `request_build`, `response_build`), which assemble every
/// part of a message at the wire profile and name each part's type to do it. A
/// reader that works on a part from either plane does not import these: it is
/// generic over the profile (`S: CodecStorage`), as `wireexpr_resolve` and
/// `attachment` are. The split is the one the module doc above draws, drawn
/// again at the leaves.
pub mod parts {
    use super::WireStorage;

    /// An extension entry of a wire-plane message's chain.
    pub type ExtEntryOwned = wz_codecs::ext_entry::ExtEntryOwned<WireStorage>;
    /// The body variant of an [`ExtEntryOwned`].
    pub type ExtEntryOwnedVariant = wz_codecs::ext_entry::ExtEntryOwnedVariant<WireStorage>;
    /// An `ExtZbuf` body.
    pub type ExtZbufOwned = wz_codecs::ext_zbuf::ExtZbufOwned<WireStorage>;
    /// A key expression.
    pub type WireexprOwned = wz_codecs::wireexpr::WireexprOwned<WireStorage>;
    /// The mapping arm of a [`WireexprOwned`].
    pub type WireexprOwnedVariant = wz_codecs::wireexpr::WireexprOwnedVariant<WireStorage>;
    /// The sender-mapped arm.
    pub type WireexprLocalOwned = wz_codecs::wireexpr_local::WireexprLocalOwned<WireStorage>;
    /// The receiver-mapped arm.
    pub type WireexprNonlocalOwned =
        wz_codecs::wireexpr_nonlocal::WireexprNonlocalOwned<WireStorage>;
    /// A Put body.
    pub type MsgPutOwned = wz_codecs::msg_put::MsgPutOwned<WireStorage>;
    /// A Del body.
    pub type MsgDelOwned = wz_codecs::msg_del::MsgDelOwned<WireStorage>;
    /// A timestamp.
    pub type TimestampOwned = wz_codecs::timestamp::TimestampOwned<WireStorage>;
    /// An encoding.
    pub type EncodingOwned = wz_codecs::encoding::EncodingOwned<WireStorage>;
    /// A Query body.
    #[cfg(feature = "codec-request")]
    pub type QueryOwned = wz_codecs::query::QueryOwned<WireStorage>;
    /// A Reply body.
    #[cfg(feature = "codec-response")]
    pub type ReplyOwned = wz_codecs::reply::ReplyOwned<WireStorage>;
    /// The body variant of a [`ReplyOwned`].
    #[cfg(feature = "codec-response")]
    pub type ReplyOwnedVariant = wz_codecs::reply::ReplyOwnedVariant<WireStorage>;
    /// An Err body.
    #[cfg(feature = "codec-response")]
    pub type ErrOwned = wz_codecs::err::ErrOwned<WireStorage>;
}
