// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Who is on the other end of a link, read off the handshake the session ran —
//! the validated routing identity and the authenticated name.
//!
//! R2702 — both readers lived in `linkstate_forward.rs`, and both have TWO
//! consumers with different lifetimes: routing keys its graph on the zid, and
//! the §5.16 enforcer uses the same two values as ACL subject axes. Keeping them
//! in the routing module meant the enforcer could only exist in a routing build,
//! which is half of what `access-acl`'s residual has been describing. They are
//! neither routing nor access control on their own — they are the session→host
//! identity boundary, which is why this module is named for that and not for
//! either consumer. `linkstate_forward` re-exports both, so every caller there
//! keeps its unqualified name.
//!
//! The conversion lives HERE rather than in session-core because
//! [`SessionLinkActions`] is `#![no_std]` and deliberately routing-agnostic: it
//! holds the peer's zid as the verbatim wire bytes and knows nothing of
//! [`Zid`]. That split is the reason there is a conversion at all.

use wz_routing_graph::Zid;
use wz_runtime_core::TimeSource;
use wz_session_core::link::SessionRuntime;
use wz_session_core::session_actions::SessionLinkActions;

/// This face's remote peer zid as the routing [`Zid`], or `None` if the
/// handshake did not surface one OR surfaced a non-conformant one — the SINGLE
/// session(`Vec<u8>`) -> routing(`Zid`) boundary every flood / forward path and
/// every §5.16 subject read goes through. The peer zid is captured verbatim from
/// the peer's INIT body (`SessionLinkActions::peer_zid`), so it is UNTRUSTED
/// wire data: validate it with the same `Zid::try_from` the linkstate ingest
/// uses (rejecting an empty / all-zero zid) rather than the infallible
/// `from_slice`, so a non-conformant peer cannot enter the graph as a
/// zero-identity node. A face whose zid is absent / rejected is held WITHOUT a
/// routing identity (it routes nothing), exactly like a zid-less face.
///
/// ⚠ For the ENFORCER that `None` is not an exemption and the distinction is
/// load-bearing: open-debt item 655 records that a peer chooses its own zid
/// bytes, so an interceptor that skipped an unattributable face would let the
/// peer choose to be unfiltered. The policy takes the `Option` and answers.
pub(crate) fn peer_zid_routing<R: SessionRuntime, T: TimeSource>(
    actions: &SessionLinkActions<R, T>,
) -> Option<Zid> {
    actions
        .peer_zid()
        .and_then(|bytes| Zid::try_from(bytes).ok())
}

/// R2631 — the name this face's peer AUTHENTICATED as, for an ACL `usernames`
/// subject: [`peer_zid_routing`]'s twin for the other session-derived identity,
/// and the one place every interceptor context reads it, so they cannot drift.
///
/// The bytes-to-name decision is `AuthIdentity::acl_username`'s, not this
/// function's. Without `session-extauth` no handshake can carry a name, so the
/// honest answer is `None` rather than a compile error at every caller.
pub(crate) fn peer_acl_username<R: SessionRuntime, T: TimeSource>(
    actions: &SessionLinkActions<R, T>,
) -> Option<String> {
    #[cfg(feature = "session-extauth")]
    {
        actions
            .peer_auth_id()
            .and_then(|id| id.acl_username().map(str::to_owned))
    }
    #[cfg(not(feature = "session-extauth"))]
    {
        let _ = actions;
        None
    }
}
