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
//! (Every intra-doc link in THIS module header is fully qualified on purpose:
//! the outer `///` on `pub mod wireexpr_resolve;` in `lib.rs` merges with it and
//! the pair resolves in the CRATE ROOT scope, where these names are not
//! imported. R311y739 paid five broken links to relearn it.)
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
//! **R311y739 — resolving OUR ids is now built.**
//! [`MappingSpaces`](crate::wireexpr_resolve::MappingSpaces) carries the
//! two spaces side by side exactly as zenoh's face does, and a caller that owns
//! an [`OwnMappingSpace`](crate::wireexpr_resolve::OwnMappingSpace) hands it over
//! with [`MappingSpaces::with_own`](crate::wireexpr_resolve::MappingSpaces::with_own); an
//! `M=0` alias then resolves out of OUR space and never out of the peer's. A
//! caller that genuinely has only the peer's space (a relay face, which absorbs
//! the peer's declarations and emits none of its own) keeps
//! [`MappingSpaces::peer_only`](crate::wireexpr_resolve::MappingSpaces::peer_only)
//! and keeps refusing `M=0` aliases — the refusal
//! is still the right answer THERE, because there is no second space to read.
//!
//! What the refusal cost while it was the only answer: a zenoh peer PREFERS the
//! id we declared and stamps it `Mapping::Receiver`, so every session that
//! called `send_declare_keyexpr` started losing the peer's aliased traffic on
//! the next message. The table was already being written
//! (`SessionActions::outbound_mappings`); only the plumbing to the registries
//! was missing.

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
///
/// R311y739 — a caller that DOES hold our own space calls
/// [`resolve_wireexpr_in`] with [`MappingSpaces::with_own`] and gets the `M=0`
/// arm answered out of the right space. This peer-only form stays for the
/// callers that have no second space to offer.
pub fn resolve_wireexpr(
    body: &WireexprOwnedVariant,
    table: &HashMap<u64, String>,
) -> Option<String> {
    resolve_wireexpr_in(body, MappingSpaces::peer_only(table))
}

/// OUR id space — the one an `M=0` (`Mapping::Receiver`) Wireexpr names.
///
/// A trait rather than a second `HashMap` parameter because the space already
/// EXISTS behind a lock somewhere else: `SessionActions::outbound_mappings` is
/// written by `send_declare_keyexpr` and read one id at a time through
/// `resolve_outbound_mapping`. Handing that surface over directly keeps ONE
/// copy of the fact — a second table shadowing it is the dual-write shape this
/// workspace has repeatedly found diverging, and it would go stale the moment
/// `send_undeclare_kexpr` pruned the original.
///
/// Per-id rather than borrow-the-whole-table for the same reason: a `Mutex`ed
/// table cannot lend a `&HashMap` past the guard, and a resolution needs
/// exactly one id.
pub trait OwnMappingSpace {
    /// The literal keyexpr this node declared for `id`, or `None` when it
    /// declared none (or retracted it). `id == 0` is never asked — it names no
    /// mapping on either arm.
    fn resolve_own_mapping(&self, id: u64) -> Option<String>;
}

/// A plain table is an own space too — the shape tests and any future per-face
/// local-mapping table use, without reaching for the locked session surface.
impl OwnMappingSpace for HashMap<u64, String> {
    fn resolve_own_mapping(&self, id: u64) -> Option<String> {
        self.get(&id).cloned()
    }
}

/// The TWO id spaces a face can consult, carried side by side.
///
/// This is zenoh's `FaceState` shape: `remote_mappings` and `local_mappings`
/// held together, with the `M` bit — not the caller — deciding which one a
/// reference reads (`dispatcher/face.rs:126-127`). zenoh-pico draws the same
/// line with `_z_wireexpr_is_local`.
///
/// [`peer_only`](Self::peer_only) is not a degraded form: a relay face absorbs
/// the peer's declarations and emits none of its own, so it HAS no second
/// space and refusing `M=0` is its correct answer. The distinction is
/// deliberate — a constructor that silently substituted the peer's table for a
/// missing own space would reintroduce the wrong-space read this type exists to
/// prevent.
#[derive(Clone, Copy)]
pub struct MappingSpaces<'a> {
    peer: &'a HashMap<u64, String>,
    own: Option<&'a dyn OwnMappingSpace>,
}

impl<'a> MappingSpaces<'a> {
    /// Only the peer's space is known. `M=0` aliases refuse.
    pub fn peer_only(peer: &'a HashMap<u64, String>) -> Self {
        Self { peer, own: None }
    }

    /// Both spaces are known. `M=1` reads the peer's, `M=0` reads ours.
    pub fn with_own(peer: &'a HashMap<u64, String>, own: &'a dyn OwnMappingSpace) -> Self {
        Self {
            peer,
            own: Some(own),
        }
    }

    /// The peer's space as a raw table, for a caller that must BIND into it
    /// rather than resolve against it — a `DeclKexpr` registers `id -> literal`
    /// in the peer's space and in no other.
    ///
    /// No production caller yet: `SubscriberRegistry::absorb_declare` reaches
    /// its own field directly. Kept because a pair type that cannot yield either
    /// half is the shape a future relay would have to re-add, and pinned by a
    /// test so a zero-caller accessor cannot be quietly wrong.
    pub fn peer(&self) -> &'a HashMap<u64, String> {
        self.peer
    }

    /// Whether an `M=0` alias can resolve at all. Diagnostic: it separates
    /// "this node has no own space" from "this node declared no such id",
    /// which the `None` of a resolution cannot.
    pub fn has_own(&self) -> bool {
        self.own.is_some()
    }
}

/// A bare peer table IS a valid pair — the one with no own space in it.
///
/// This exists so the registry fan can take `impl Into<MappingSpaces<'a>>` and
/// accept both forms: production hands over the pair (via
/// `SubscriberRegistry::mapping_spaces`), while a caller that has only the
/// peer's table — a relay face, a unit test pinning peer-side behaviour — passes
/// it directly and gets exactly the pre-R311y739 semantics.
///
/// The lifetime is NAMED at every such parameter, never `'_`: an anonymous
/// lifetime is unstable in argument-position `impl Trait`, and because the
/// affected signatures are feature-gated it compiles in some subsets and not
/// others — this round saw it pass a default build and fail four rounds later
/// under a wider feature set.
///
/// It is deliberately NOT a widening: converting a table yields
/// [`MappingSpaces::peer_only`], so an `M=0` alias still refuses. The conversion
/// cannot invent a space the caller does not have.
impl<'a> From<&'a HashMap<u64, String>> for MappingSpaces<'a> {
    fn from(peer: &'a HashMap<u64, String>) -> Self {
        Self::peer_only(peer)
    }
}

/// [`resolve_wireexpr`] against BOTH id spaces.
///
/// - `id == 0` → suffix verbatim, no table consulted, either mapping.
/// - `id != 0`, `M=1` → the PEER's space.
/// - `id != 0`, `M=0` → OUR space, or `None` when the caller supplied none.
///
/// Never reads one space to answer for the other. Both sides number their
/// mappings from 1, so a wrong-space read very likely FINDS an entry and
/// returns a confident, wrong keyexpr.
pub fn resolve_wireexpr_in(
    body: &WireexprOwnedVariant,
    spaces: MappingSpaces<'_>,
) -> Option<String> {
    // The variant tag IS the mapping bit, so the arms cannot be folded: our
    // codec's `WireexprLocal` is `M=1` (the SENDER's space — the peer's, on an
    // inbound message) and `WireexprNonlocal` is `M=0` (the RECEIVER's = ours).
    let (id, suffix_opt, arm) = match body {
        WireexprOwnedVariant::WireexprLocal(a) => (a.id, a.suffix.as_deref(), Space::Peer),
        WireexprOwnedVariant::WireexprNonlocal(a) => (a.id, a.suffix.as_deref(), Space::Own),
    };
    if id == 0 {
        // id 0 names no mapping at all — the suffix IS the keyexpr, so it
        // resolves identically on either arm and consults no table. This is
        // why an `M=0` literal resolves even with no own space installed.
        return suffix_opt.map(str::to_string);
    }
    let base = match arm {
        Space::Peer => spaces.peer.get(&id).cloned()?,
        Space::Own => spaces.own?.resolve_own_mapping(id)?,
    };
    Some(match suffix_opt {
        Some(s) => {
            let mut out = base;
            out.push_str(s);
            out
        }
        None => base,
    })
}

/// Which space an arm names. Local to the resolver — the public surface says
/// it with the `M` bit already in the variant tag.
enum Space {
    Peer,
    Own,
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

    /// OUR space, holding the SAME id `7` as [`peer_space`] under a DIFFERENT
    /// literal. Every two-space test below asks about `7`, so a read out of the
    /// wrong table cannot fail by accident — it fails by returning the other
    /// string, which is exactly the confident-wrong-answer this design refuses.
    fn own_space() -> HashMap<u64, String> {
        let mut t = HashMap::new();
        t.insert(7u64, "ours/space/temp".to_string());
        t
    }

    /// R311y739 THE DISCRIMINATOR. With both spaces supplied, each mapping bit
    /// reaches its OWN table — and the id is present in both, so a swapped
    /// lookup returns the sibling's literal rather than `None`.
    #[test]
    fn each_mapping_bit_resolves_in_its_own_space() {
        let (peer, own) = (peer_space(), own_space());
        let spaces = MappingSpaces::with_own(&peer, &own);
        assert_eq!(
            resolve_wireexpr_in(&sender_mapped(7, None), spaces).as_deref(),
            Some("peers/space/temp"),
            "M=1 names the peer's space",
        );
        assert_eq!(
            resolve_wireexpr_in(&receiver_mapped(7, None), spaces).as_deref(),
            Some("ours/space/temp"),
            "M=0 names OUR space -- reading the peer's would return \
             `peers/space/temp`, which is the wrong-space read",
        );
    }

    /// The suffix composes on BOTH arms once both spaces are known. Before
    /// R311y739 only the `M=1` arm could compose at all.
    #[test]
    fn the_suffix_composes_on_both_arms_when_both_spaces_are_known() {
        let (peer, own) = (peer_space(), own_space());
        let spaces = MappingSpaces::with_own(&peer, &own);
        assert_eq!(
            resolve_wireexpr_in(&sender_mapped(7, Some("/in")), spaces).as_deref(),
            Some("peers/space/temp/in"),
        );
        assert_eq!(
            resolve_wireexpr_in(&receiver_mapped(7, Some("/in")), spaces).as_deref(),
            Some("ours/space/temp/in"),
        );
    }

    /// [`MappingSpaces::peer`] hands back the SAME table it was built over, on
    /// both constructors. Pinned because it is the pair's only accessor with no
    /// production caller yet, and an untested zero-caller accessor is exactly the
    /// shape that gets to be quietly wrong: it could return the own space, or a
    /// copy, and nothing else in the crate would notice.
    #[test]
    fn the_peer_half_is_the_table_it_was_built_over() {
        let (peer, own) = (peer_space(), own_space());
        assert_eq!(
            MappingSpaces::peer_only(&peer).peer().get(&7).map(|s| &**s),
            Some("peers/space/temp"),
        );
        assert_eq!(
            MappingSpaces::with_own(&peer, &own)
                .peer()
                .get(&7)
                .map(|s| &**s),
            Some("peers/space/temp"),
            "installing an own space must not change which table `peer()` names",
        );
    }

    /// ANTI-VACUITY. The peer-only form must keep REFUSING `M=0` — otherwise
    /// the test above proves nothing about the space, only that some table was
    /// consulted. This pairs the two directions: with an own space the alias
    /// resolves, without one it does not, and the same `resolve_wireexpr_in`
    /// answers both.
    #[test]
    fn without_an_own_space_the_same_resolver_still_refuses_m0() {
        let peer = peer_space();
        let spaces = MappingSpaces::peer_only(&peer);
        assert!(!spaces.has_own());
        assert_eq!(resolve_wireexpr_in(&receiver_mapped(7, None), spaces), None);
        assert_eq!(
            resolve_wireexpr_in(&sender_mapped(7, None), spaces).as_deref(),
            Some("peers/space/temp"),
            "the M=1 arm is unaffected by the absence of the other space",
        );
    }

    /// An id WE never declared refuses on the `M=0` arm even with an own space
    /// installed — "no such mapping" and "no such space" both answer `None`,
    /// and neither falls back to the peer's table.
    #[test]
    fn an_id_we_never_declared_refuses_without_falling_back_to_the_peer() {
        let (peer, mut own) = (peer_space(), own_space());
        own.remove(&7);
        let spaces = MappingSpaces::with_own(&peer, &own);
        assert_eq!(
            resolve_wireexpr_in(&receiver_mapped(7, None), spaces),
            None,
            "id 7 IS in the peer's table; falling back to it is the defect",
        );
    }

    /// A literal (`id == 0`) still consults no table on either arm, with or
    /// without an own space. The overwhelming majority of wire keyexprs take
    /// this path, so it is the regression guard on the whole change.
    #[test]
    fn a_literal_keyexpr_consults_no_space_at_all() {
        let (peer, own) = (peer_space(), own_space());
        for spaces in [
            MappingSpaces::peer_only(&peer),
            MappingSpaces::with_own(&peer, &own),
        ] {
            assert_eq!(
                resolve_wireexpr_in(&sender_mapped(0, Some("home/temp")), spaces).as_deref(),
                Some("home/temp"),
            );
            assert_eq!(
                resolve_wireexpr_in(&receiver_mapped(0, Some("home/temp")), spaces).as_deref(),
                Some("home/temp"),
            );
        }
    }
}
