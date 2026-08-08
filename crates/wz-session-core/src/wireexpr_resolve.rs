// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R310.5a / R311di-13 — `resolve_wireexpr` peer-keyexpr-table lookup.
//!
//! Free-standing helper shared by the application-layer remote-
//! declaration registries (`RemoteSubscriberRegistry`,
//! `RemoteQueryableRegistry`, `LivelinessRegistry`,
//! `LivelinessSubscriberRegistry`). Mirrors the resolver inside
//! `wz-runtime-tokio::pubsub::SubscriberRegistry` so the four sibling
//! registries don't need a reference back to that registry to compose
//! a literal keyexpr from a Wireexpr + the peer mapping table.
//!
//! ## The table is ONE id space, and the wire says which one it meant
//!
//! R311y604 — a keyexpr id means nothing on its own: it is an index into the
//! id space of whoever DECLARED it, and the `M` bit picks the space. Every
//! caller here holds the PEER's space, so an `M=1` (`Mapping::Sender`)
//! reference resolves and an `M=0` (`Mapping::Receiver`) one — which names OUR
//! space — resolves to `None` instead of being read out of the peer's table.
//!
//! Both upstreams keep the two apart: zenoh's face holds `remote_mappings` and
//! `local_mappings` and selects on the bit (`dispatcher/face.rs:126-127`), and
//! zenoh-pico carries `_mapping` on every `_z_wireexpr_t` for exactly this
//! reason — its own header says the field exists because "there are collisions
//! on `_id` value between peers/local" (`protocol/core.h:148-151`).
//!
//! **Resolving OUR ids is not built yet** and is deliberately not faked here.
//! The table for it exists (`SessionActions::outbound_mappings`, written by
//! `send_declare_keyexpr`) but nothing plumbs it to these registries, whose
//! only keyexpr table is the peer's. Until that plumbing lands, an `M=0` alias
//! is a refusal, which each caller already treats as "the peer named a mapping
//! it never declared" and drops — the same shape, one round earlier, as
//! answering it wrongly.

use alloc::string::{String, ToString};

use hashbrown::HashMap;

#[cfg(feature = "codec-declare")]
use wz_codecs::declare::{DeclareOwned, DeclareOwnedVariant};
use wz_codecs::wireexpr::WireexprOwnedVariant;

/// Resolve a `Wireexpr` to its literal keyexpr string using a peer
/// mapping table.
///
/// Composition rule (mirrors zenoh-pico
/// `_z_keyexpr_resolve_in_keyexprs_map`):
/// - `id == 0` → suffix verbatim (no table lookup, either mapping).
/// - `id != 0` **and `M=1`** → `table[id] + suffix` (table-base prefix +
///   optional per-message suffix).
/// - `id != 0` **and `M=0`** → `None`: the id names OUR space, not the
///   peer's, and [`resolve_wireexpr`] holds only the peer's (R311y604).
///
/// Returns `None` when `id != 0` and the table has no entry for
/// the id (the peer references a mapping it never declared). The
/// caller decides whether to skip the dispatch (preferred, the
/// declaration is incomplete) or surface the half-truth (currently
/// no caller does the latter).
/// Whether `body` is the EMPTY wire keyexpr (`id == 0` with no — or an empty —
/// suffix): zenoh's `WireExpr::empty()`, carried by keyexpr-less replies such
/// as the synthesized timeout `Err` (`build_response_err_empty`). A relay MUST
/// NOT route such a message through [`resolve_wireexpr`] (which returns `None`
/// for it — an empty keyexpr resolves to nothing) but pass it through with only
/// the rid rewritten, exactly as zenoh's `route_send_response` forwards a reply
/// with NO keyexpr resolution at all (`dispatcher/queries.rs:595-635`).
pub fn wireexpr_is_empty(body: &WireexprOwnedVariant) -> bool {
    let (id, suffix_opt) = match body {
        WireexprOwnedVariant::WireexprLocal(arm) => (arm.id, arm.suffix.as_deref()),
        WireexprOwnedVariant::WireexprNonlocal(arm) => (arm.id, arm.suffix.as_deref()),
    };
    id == 0 && suffix_opt.map_or(true, str::is_empty)
}

/// The TWO id spaces a Wireexpr's mapping bit can name.
///
/// A keyexpr id is only meaningful inside the space of whoever declared it,
/// and the wire says which one with the `M` bit. zenoh's face carries the two
/// tables side by side and picks between them on receive —
/// `Mapping::Sender => remote_mappings`, `Mapping::Receiver => local_mappings`
/// (`zenoh/src/net/routing/dispatcher/face.rs:126-127`). zenoh-pico draws the
/// same distinction with `_z_wireexpr_is_local` and encodes it as
/// `is_local ? M=1 : M=0` (`src/protocol/codec/network.c:42,116,250`).
///
/// In our codec the bit is already the variant tag: `WireexprLocal` is `M=1`
/// (the SENDER's space) and `WireexprNonlocal` is `M=0` (the RECEIVER's — that
/// is, OUR — space).
///
/// **Why an id in our own space arrives at all**, rather than being a
/// theoretical arm: zenoh PREFERS it. When it renders a keyexpr for a face it
/// takes `ctx.remote_expr_id` — the id the PEER declared — before its own
/// `local_expr_id`, and stamps the first with `Mapping::Receiver`
/// (`dispatcher/resource.rs:550-560` and the `get_best_key` match at `:625`).
/// So the moment wz calls `send_declare_keyexpr`, a zenoh peer starts naming
/// that id back at us with `M=0`, and reading it out of the peer's space would
/// silently resolve a DIFFERENT keyexpr — or none.
///
/// `table` is the PEER's id space, and only that space. An `M=0`
/// (`Mapping::Receiver`) reference names OUR space, which this resolver is not
/// given and therefore answers `None` for — never a lookup in the peer's table.
///
/// Answering out of the wrong space is worse than answering nothing. Both sides
/// number their mappings from 1, so a wrong-space read very likely FINDS an
/// entry and returns a confident, wrong keyexpr; `None` instead takes each
/// callsite's existing "the peer referenced a mapping it never declared" path
/// and drops the message. Until R311y604 both arms read `table`, which is the
/// wrong-space read.
pub fn resolve_wireexpr(
    body: &WireexprOwnedVariant,
    table: &HashMap<u64, String>,
) -> Option<String> {
    // The variant tag IS the mapping bit, so the arms cannot be folded: our
    // codec's `WireexprLocal` is `M=1` (the SENDER's space — the peer's, on an
    // inbound message) and `WireexprNonlocal` is `M=0` (the RECEIVER's = ours).
    let (id, suffix_opt, space) = match body {
        WireexprOwnedVariant::WireexprLocal(arm) => (arm.id, arm.suffix.as_deref(), Some(table)),
        WireexprOwnedVariant::WireexprNonlocal(arm) => (arm.id, arm.suffix.as_deref(), None),
    };
    if id == 0 {
        // id 0 names no mapping at all — the suffix IS the keyexpr, so it
        // resolves identically on either arm and consults no table. This is
        // why an `M=0` literal keeps working while an `M=0` ALIAS does not.
        suffix_opt.map(str::to_string)
    } else {
        let base = space?.get(&id)?.clone();
        Some(match suffix_opt {
            Some(s) => {
                let mut out = base;
                out.push_str(s);
                out
            }
            None => base,
        })
    }
}

/// Absorb one keyexpr (un)declaration into a peer's `id -> literal` mapping
/// table — the SSOT shared by the unicast router faces (each
/// `LinkstateForwarder` / `RouterForwarder` per-face `keyexpr_table`) and the
/// multicast per-peer ingress plane
/// (`MulticastDispatcher::apply_declared_aliases`, §5.21 router-multicast-faces
/// I3a). A `DeclKexpr` resolves its own (possibly itself-aliased) keyexpr
/// against the table so far, then binds `id -> literal` (zenoh registers the
/// mapping under the declaring face's resource table); an `UndeclKexpr` drops
/// the binding. Any other declaration body is a no-op here. Before this moved
/// to `wz-session-core` (R311y196) a byte-identical copy lived in
/// `wz-runtime-tokio::linkstate_forward`; the multicast ingress plane needs the
/// same absorb from the no_std session core, so the one definition lives here.
#[cfg(feature = "codec-declare")]
pub fn absorb_keyexpr_into(table: &mut HashMap<u64, String>, declare: &DeclareOwned) {
    match &declare.body {
        DeclareOwnedVariant::CodecZenohDeclKexpr(d) => {
            if let Some(literal) = resolve_wireexpr(&d.keyexpr.body, &*table) {
                table.insert(d.id, literal);
            }
        }
        DeclareOwnedVariant::CodecZenohUndeclKexpr(u) => {
            table.remove(&u.id);
        }
        _ => {}
    }
}

#[cfg(test)]
mod mapping_bit_tests {
    use super::*;
    use crate::codec_owned::owned_string;
    use wz_codecs::wireexpr_local::WireexprLocalOwned;
    use wz_codecs::wireexpr_nonlocal::WireexprNonlocalOwned;

    /// The peer's space, with ONE entry. Every test below asks about id `7`,
    /// which this table HAS — so a wrong-space read cannot fail by accident.
    fn peer_space() -> HashMap<u64, String> {
        let mut t = HashMap::new();
        t.insert(7u64, "peers/space/temp".to_string());
        t
    }

    /// `M=1` — the id names the SENDER's space, which on an inbound message is
    /// the peer's. This is the arm that was always correct.
    fn sender_mapped(id: u64, suffix: Option<&str>) -> WireexprOwnedVariant {
        WireexprOwnedVariant::WireexprLocal(WireexprLocalOwned {
            id,
            suffix_len: suffix.map(|s| s.len() as u64),
            suffix: suffix.map(owned_string).transpose().expect("suffix fits"),
        })
    }

    /// `M=0` — the id names the RECEIVER's space, i.e. ours.
    fn receiver_mapped(id: u64, suffix: Option<&str>) -> WireexprOwnedVariant {
        WireexprOwnedVariant::WireexprNonlocal(WireexprNonlocalOwned {
            id,
            suffix_len: suffix.map(|s| s.len() as u64),
            suffix: suffix.map(owned_string).transpose().expect("suffix fits"),
        })
    }

    /// THE DISCRIMINATOR. Id `7` is present in the peer's table, so the only
    /// thing that can distinguish the two arms is the mapping bit itself.
    ///
    /// Before R311y604 both arms read the peer table and this returned
    /// `Some("peers/space/temp")` for the `M=0` reference — a confident answer
    /// out of the wrong id space. A zenoh peer reaches this arm as soon as wz
    /// declares a keyexpr, because `get_best_key` prefers the id WE declared
    /// and stamps it `Mapping::Receiver` (`dispatcher/resource.rs:625`).
    #[test]
    fn an_alias_in_our_own_space_is_not_read_out_of_the_peers() {
        let peer = peer_space();
        assert_eq!(
            resolve_wireexpr(&sender_mapped(7, None), &peer).as_deref(),
            Some("peers/space/temp"),
            "M=1 names the peer's space and must still resolve there",
        );
        assert_eq!(
            resolve_wireexpr(&receiver_mapped(7, None), &peer),
            None,
            "M=0 names OUR space; resolving it out of the peer's table is the \
             wrong-space read this round removed",
        );
    }

    /// The suffix composes on the arm that does resolve, and the wrong-space
    /// refusal is not rescued by carrying one.
    #[test]
    fn the_suffix_composes_only_on_the_arm_that_owns_the_id() {
        let peer = peer_space();
        assert_eq!(
            resolve_wireexpr(&sender_mapped(7, Some("/in")), &peer).as_deref(),
            Some("peers/space/temp/in"),
        );
        assert_eq!(
            resolve_wireexpr(&receiver_mapped(7, Some("/in")), &peer),
            None
        );
    }

    /// `id == 0` names no mapping at all, so BOTH arms carry a literal keyexpr
    /// verbatim. This is the regression guard on the change: the overwhelming
    /// majority of wire keyexprs are `id == 0`, and had the refusal been keyed
    /// on the arm rather than on `id != 0` it would have silenced them.
    #[test]
    fn a_literal_keyexpr_is_carried_by_either_mapping() {
        let peer = peer_space();
        assert_eq!(
            resolve_wireexpr(&sender_mapped(0, Some("home/temp")), &peer).as_deref(),
            Some("home/temp"),
        );
        assert_eq!(
            resolve_wireexpr(&receiver_mapped(0, Some("home/temp")), &peer).as_deref(),
            Some("home/temp"),
            "an M=0 LITERAL consults no table and must keep working",
        );
    }

    /// An id the peer never declared still resolves to `None` on the arm that
    /// does own the space — the pre-existing "incomplete declaration" path is
    /// unchanged, so a caller cannot tell the two refusals apart by shape.
    #[test]
    fn an_undeclared_id_still_refuses_on_the_owning_arm() {
        let peer = peer_space();
        assert_eq!(resolve_wireexpr(&sender_mapped(9, None), &peer), None);
    }
}
