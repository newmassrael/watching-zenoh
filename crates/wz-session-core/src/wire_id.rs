// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The widths zenoh gives the two identifiers a session allocates and the wire
//! carries: a key expression's scope and a request's id.
//!
//! Upstream reads both bounded, so a peer that states a wider value is refused
//! rather than truncated (`commons/zenoh-codec/src/core/wire_expr.rs` @
//! `let zodec = Zenoh080Bounded::<ExprId>::new();`,
//! `commons/zenoh-codec/src/network/request.rs` @
//! `let id: RequestId = bodec.read(&mut *reader)?;`). The codecs read them at
//! these widths (`sources/codecs/wireexpr_local.scxml`,
//! `wireexpr_nonlocal.scxml`, `request.scxml`, `response.scxml`,
//! `response_final.scxml`), which is where the refusal happens; a session holds
//! them at the same widths, so an identifier it allocates is one the wire can
//! carry and one it reads needs no narrowing.

/// A key expression's scope, and the id a `DeclareKeyExpr` maps it under
/// (`commons/zenoh-protocol/src/core/wire_expr.rs` @ `pub type ExprId = u16;`).
pub type ExprId = u16;

/// The `ExprId` a `DeclareKeyExpr` or `UndeclareKeyExpr` names, or the scope a
/// declaration's key expression extension carries, from the 64 bits it is read
/// into.
///
/// Upstream reads both UNBOUNDED and narrows them, so a wider value is
/// truncated and not refused (`commons/zenoh-codec/src/network/declare.rs` @
/// `let id: ExprId = self.codec.read(&mut *reader)?;` and @
/// `let scope: ExprLen = self.codec.read(&mut zeader)?;`, `Zenoh080` reads that
/// end in `x as $uint`), unlike the scope of a key expression, which it bounds.
/// The codec keeps those fields at 64 bits for that reason, and this is the one
/// place a session narrows them.
pub const fn declared_expr_id(wire: u64) -> ExprId {
    wire as ExprId
}

/// The key an `ExprId` has in a PEER's mapping table.
///
/// A peer's table is a session's generic id map (`crate::id_map::IdMap`, a
/// plain `HashMap` on the heap profile), which every kind of declared id shares
/// and which keys by 64 bits; an `ExprId` enters it widened, losing nothing.
/// Our own table (`SessionLinkActions::outbound_mappings`) holds only ids we
/// allocate and keys by `ExprId` itself.
pub const fn peer_key(id: ExprId) -> u64 {
    id as u64
}

/// [`peer_key`] of the id a `DeclareKeyExpr` or `UndeclareKeyExpr` names, as
/// upstream narrows it ([`declared_expr_id`]): what a peer's declaration binds
/// and unbinds.
pub const fn declared_peer_key(wire: u64) -> u64 {
    peer_key(declared_expr_id(wire))
}

/// A request's id, which its responses name
/// (`commons/zenoh-protocol/src/network/request.rs` @ `pub type RequestId = u32;`).
pub type RequestId = u32;

/// An interest's id (`commons/zenoh-protocol/src/network/interest.rs` @
/// `pub type InterestId = u32;`), which also correlates a liveliness get's
/// replies, as a request id correlates a get's.
pub type InterestId = u32;

/// The `InterestId` a session's 64-bit interest id is on the wire.
///
/// A session still allocates and tables interest ids at 64 bits; upstream reads
/// one unbounded and narrows it (`commons/zenoh-codec/src/network/interest.rs`
/// @ `let id = self.codec.read(&mut *reader)?;`, into an `InterestId`), so this
/// is the id a peer answers with, and the one a reply sink is handed.
pub const fn interest_id_as_read(id: u64) -> InterestId {
    id as InterestId
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_declared_id_wider_than_the_scope_is_truncated_as_upstream_reads_it() {
        assert_eq!(declared_expr_id(7), 7);
        assert_eq!(declared_expr_id(u64::from(ExprId::MAX)), ExprId::MAX);
        assert_eq!(declared_expr_id(u64::from(ExprId::MAX) + 1), 0);
        assert_eq!(declared_expr_id(0x1_0005), 5);
    }

    #[test]
    fn a_peer_key_is_the_id_widened_and_a_declared_one_is_narrowed_first() {
        assert_eq!(peer_key(ExprId::MAX), 0xFFFF);
        assert_eq!(declared_peer_key(0x1_0005), 5);
        assert_eq!(declared_peer_key(42), 42);
    }

    #[test]
    fn an_interest_id_is_narrowed_to_the_width_upstream_reads() {
        assert_eq!(interest_id_as_read(9), 9);
        assert_eq!(
            interest_id_as_read(u64::from(InterestId::MAX)),
            InterestId::MAX
        );
        assert_eq!(interest_id_as_read(u64::from(InterestId::MAX) + 3), 2);
    }
}
