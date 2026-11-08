// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Addressing a query to one node: the part of the `targeted-query` policy that every engine
//! shares.
//!
//! # The decision
//!
//! A query goes to every link whose peers declared a queryable the key matches, and the caller
//! has no say in which. A caller that wants an answer from one node, a node it has just heard of
//! or one it must not mix with the others, names the node's identity. The identity is the one
//! the session handshake gave the link ([`crate::lifecycle_node::Zid`] is its fixed-size form);
//! it names a node, not a link or a queryable, because a node is what the caller knows and
//! the link that reaches it is the engine's business.
//!
//! # What a named query does
//!
//! It is sent on the link of that node and on no other. A node with no link is not asked and
//! the query is not widened to the others: widening would answer a question the caller did not
//! ask, from nodes it meant to leave out. The session-local leg and a multicast group are left
//! out too, since neither is the one node's link. This module holds only the value's rules; the
//! engine that holds the links applies them where it fans a query out.
//!
//! # The default is no target
//!
//! `None` is upstream's query, and it is the only one a build without the policy has. A call
//! that names a node in such a build is refused by [`crate::peer_target::admit_in_build`] with
//! a reason, not ignored.

/// The longest node identity, in bytes. A session identity is 1 to 16 bytes on the wire.
pub const MAX_PEER_ID_BYTES: usize = 16;

/// Why a target could not be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerTargetError {
    /// The identity has no bytes.
    Empty,
    /// The identity has more than [`MAX_PEER_ID_BYTES`] bytes.
    TooLong(usize),
    /// The build's `targeted-query` policy is off, so no query may name a node.
    PolicyOff,
}

impl core::fmt::Display for PeerTargetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => f.write_str("a query target must name a node by at least one byte"),
            Self::TooLong(n) => write!(
                f,
                "a query target of {n} bytes is longer than the {MAX_PEER_ID_BYTES} a node identity has"
            ),
            Self::PolicyOff => f.write_str(
                "this build does not let a query be addressed to one node \
                 (policy targeted-query is off)",
            ),
        }
    }
}

impl core::error::Error for PeerTargetError {}

/// The target `zid` names, checked for the shape of a node identity.
pub const fn check(zid: &[u8]) -> Result<(), PeerTargetError> {
    if zid.is_empty() {
        Err(PeerTargetError::Empty)
    } else if zid.len() > MAX_PEER_ID_BYTES {
        Err(PeerTargetError::TooLong(zid.len()))
    } else {
        Ok(())
    }
}

/// `target` admitted by a policy that is `enabled`, or the reason it is not: no target is always
/// admitted, and a target is admitted only when the policy is on and its shape is a node
/// identity's.
pub const fn admit(target: Option<&[u8]>, enabled: bool) -> Result<(), PeerTargetError> {
    match target {
        None => Ok(()),
        Some(zid) => {
            if !enabled {
                return Err(PeerTargetError::PolicyOff);
            }
            check(zid)
        }
    }
}

/// [`admit`] by this build's `targeted-query` policy: the call every entry point that takes a
/// target from a caller makes.
pub const fn admit_in_build(target: Option<&[u8]>) -> Result<(), PeerTargetError> {
    admit(
        target,
        crate::policy::SessionPolicy::from_build().targeted_query,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_target_is_admitted_whatever_the_policy() {
        assert_eq!(admit(None, false), Ok(()));
        assert_eq!(admit(None, true), Ok(()));
        assert_eq!(admit_in_build(None), Ok(()));
    }

    #[test]
    fn a_target_needs_the_policy_on() {
        let zid = [7u8; 16];
        assert_eq!(admit(Some(&zid), false), Err(PeerTargetError::PolicyOff));
        assert_eq!(admit(Some(&zid), true), Ok(()));
        let in_build = crate::policy::SessionPolicy::from_build().targeted_query;
        assert_eq!(admit_in_build(Some(&zid)).is_ok(), in_build);
    }

    #[test]
    fn a_target_has_the_shape_of_a_node_identity() {
        assert_eq!(check(&[]), Err(PeerTargetError::Empty));
        assert_eq!(check(&[1]), Ok(()));
        assert_eq!(check(&[1; MAX_PEER_ID_BYTES]), Ok(()));
        assert_eq!(
            check(&[1; MAX_PEER_ID_BYTES + 1]),
            Err(PeerTargetError::TooLong(MAX_PEER_ID_BYTES + 1))
        );
        // The shape is judged after the policy: an off policy says so first.
        assert_eq!(admit(Some(&[]), false), Err(PeerTargetError::PolicyOff));
        assert_eq!(admit(Some(&[]), true), Err(PeerTargetError::Empty));
    }
}
