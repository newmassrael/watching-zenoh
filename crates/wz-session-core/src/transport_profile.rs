// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The storage profile the owned parts of a transport message are held at: the
//! extension entries of an Init, an Open, a Join, a Frame or a Fragment, and the
//! bodies of the handshake.
//!
//! The heap where the build allocates, and the node's deployment
//! ([`wz_codecs::node::Node`]) where it does not. Never `Inline`, which is the
//! SCE default without an allocator: it holds each field at the protocol's
//! bound, and an extension's ZBuf body is bounded by a `u32` length, which no
//! array a node can give holds. The transport modules name the aliases here
//! rather than the codec's bare `*Owned` types, so the profile is chosen in this
//! one place and a module compiled with and without an allocator holds the same
//! type its callers build in either.

/// The profile of a transport message's owned parts.
#[cfg(feature = "alloc")]
pub type TransportStorage = sce_forge_runtime::codec::Heap;
/// See the `alloc` form of this alias.
#[cfg(not(feature = "alloc"))]
pub type TransportStorage = wz_codecs::node::Node;

/// An extension entry of a transport message's chain.
pub type ExtEntryOwned = wz_codecs::ext_entry::ExtEntryOwned<TransportStorage>;

/// The body variant of an [`ExtEntryOwned`].
pub type ExtEntryOwnedVariant = wz_codecs::ext_entry::ExtEntryOwnedVariant<TransportStorage>;

/// The ZBuf body of an [`ExtEntryOwned`].
pub type ExtZbufOwned = wz_codecs::ext_zbuf::ExtZbufOwned<TransportStorage>;

/// The storage profile a handshake body (an INIT or an OPEN) is decoded into:
/// the transport profile, except on the per-session slot profile
/// (`session-slot`), which reads a handshake into the node's deployment even
/// where the build allocates, so that reading a handshake allocates nothing
/// (fixed-memory step S5). The zid and the cookie are then arrays of the
/// capacities `deploy/codec_node.yaml` gives them, and a cookie past its
/// capacity is refused as `CapacityExceeded`. The accessors a reader uses
/// (`as_slice`) are the same on every profile.
#[cfg(any(feature = "codec-init-body", feature = "codec-open-body"))]
#[cfg(not(feature = "session-slot"))]
pub type HandshakeStorage = TransportStorage;
/// See the form of this alias without `session-slot`.
#[cfg(any(feature = "codec-init-body", feature = "codec-open-body"))]
#[cfg(feature = "session-slot")]
pub type HandshakeStorage = wz_codecs::node::Node;

pub mod owned;
