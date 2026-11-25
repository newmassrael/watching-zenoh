// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a session queues of a send its owner's deferral defers ([`crate::send_deferral`]): the
//! message's encoded body and what the dispatch is told about it.

#[cfg(any(
    feature = "codec-push",
    feature = "codec-request",
    feature = "codec-response",
    feature = "codec-response-final",
    feature = "declare-keyexpr",
    feature = "declare-subscriber",
    feature = "declare-queryable",
    feature = "declare-token",
    feature = "declare-interest",
    feature = "liveliness-token",
))]
use alloc::vec::Vec;

/// One send that was deferred: the message's body as the dispatch encodes it, and what the
/// dispatch is told about it, as a block-first job carries them ([`super::BlockFirstJob`]).
#[cfg(any(
    feature = "codec-push",
    feature = "codec-request",
    feature = "codec-response",
    feature = "codec-response-final",
    feature = "declare-keyexpr",
    feature = "declare-subscriber",
    feature = "declare-queryable",
    feature = "declare-token",
    feature = "declare-interest",
    feature = "liveliness-token",
))]
pub(super) struct DeferredSend {
    pub(super) conduit: super::Conduit,
    pub(super) qos: crate::sample::QosLevel,
    pub(super) stats_class: crate::stats::NetworkStatsClass,
    pub(super) body: Vec<u8>,
}
