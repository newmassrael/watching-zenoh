// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y585 (A4) — the OBSERVER's key-expression tables: turning the numbers
//! on the wire back into paths, for a session this process never joined.
//!
//! ## Why a participant's resolver is not this
//!
//! [`crate::wireexpr_resolve::resolve_wireexpr`] already composes an id and a
//! suffix against a table, and a participant needs exactly ONE table per link:
//! the ids the PEER declared (`wz-runtime-tokio/src/linkstate_forward.rs:230-237`
//! — "populated from sourced `Declare(DeclKexpr)` messages the peer sent on
//! THIS link"). It needs no more, because the other number space is its own and
//! it never has to look anything up in it.
//!
//! An observer has neither number space. It must rebuild BOTH from the
//! Declare stream, and then — for every wire expression it meets — decide
//! WHICH of the two the number belongs to. Get that wrong and the same id
//! resolves to a different path, which is worse than not resolving it: an
//! unresolved id is visibly unresolved, and a wrongly-resolved one is a
//! confident lie.
//!
//! ## The rule, and where it comes from
//!
//! The `M` bit on a wire expression is ENCODER-PERSPECTIVE locality
//! (`sources/codecs/wireexpr.scxml:38-43`, mirroring zenoh-pico's
//! `_z_wireexpr_is_local`):
//!
//! ```text
//! M = 1  (WireexprLocal)     the sender's expression was local-rooted:
//!                            the id lives in the SENDER's number space
//! M = 0  (WireexprNonlocal)  it was remote-rooted:
//!                            the id lives in the PEER's number space
//! ```
//!
//! So for a message travelling in direction `D`, an id resolves against
//! `D`'s table when `M = 1` and against `D.peer()`'s table when `M = 0`. A
//! declaration itself is sent by `D` and therefore names an id in `D`'s
//! space — while the keyexpr it BINDS is a wire expression in its own right,
//! and takes the same `M` rule.
//!
//! ## Mid-session capture is the ordinary case
//!
//! An id declared before the first captured byte can never be recovered, and
//! saying so is the point of [`Resolved::Unresolved`]. A dissector that
//! rendered those as an empty string, or hid them, would be claiming the
//! capture was complete.

use alloc::string::{String, ToString};
use hashbrown::HashMap;

use crate::passive::Direction;
use wz_codecs::declare::{DeclareOwned, DeclareOwnedVariant};
use wz_codecs::wireexpr::{WireexprOwned, WireexprOwnedVariant};

/// What an observer could make of one wire expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved {
    /// The full literal key expression.
    Literal(String),
    /// The expression is zenoh's EMPTY wire keyexpr (`id == 0`, no suffix) —
    /// what a keyexpr-less reply carries. Distinct from
    /// [`Self::Unresolved`]: nothing is missing here, the message genuinely
    /// names no key.
    Empty,
    /// `id != 0` and the owning table has no binding for it. The ordinary
    /// cause is a capture that began after the declaration.
    Unresolved {
        /// The unresolved numeric id, so a view can render `<unresolved
        /// id=17>` rather than a blank.
        id: u64,
        /// WHOSE number space the id was looked up in — the half of the
        /// answer that says which side's Declare stream was missed.
        owner: Direction,
        /// The suffix that would have been appended, when there was one. A
        /// partial answer beats none: `<unresolved id=17>/pose` locates the
        /// message in a way the bare id does not.
        suffix: Option<String>,
    },
}

/// Per-direction `id -> keyexpr` bindings, rebuilt from an observed Declare
/// stream.
#[derive(Debug, Default)]
pub struct KeyexprTables {
    /// Ids declared BY [`Direction::A`], in A's own number space.
    a: HashMap<u64, String>,
    /// Ids declared BY [`Direction::B`].
    b: HashMap<u64, String>,
}

impl KeyexprTables {
    /// Empty tables — the state of an observer that has seen no Declare.
    pub fn new() -> Self {
        Self::default()
    }

    /// The table owning the ids `direction` declares.
    fn table(&self, direction: Direction) -> &HashMap<u64, String> {
        match direction {
            Direction::A => &self.a,
            Direction::B => &self.b,
        }
    }

    fn table_mut(&mut self, direction: Direction) -> &mut HashMap<u64, String> {
        match direction {
            Direction::A => &mut self.a,
            Direction::B => &mut self.b,
        }
    }

    /// How many bindings `direction` currently has. An observability gauge —
    /// a view that shows "12 of 30 expressions unresolved" wants it.
    pub fn len(&self, direction: Direction) -> usize {
        self.table(direction).len()
    }

    /// `true` when `direction` has declared nothing this observer saw.
    pub fn is_empty(&self, direction: Direction) -> bool {
        self.table(direction).is_empty()
    }

    /// Which number space an expression seen travelling in `direction`
    /// belongs to.
    ///
    /// This one function is the whole of A4's difficulty; everything else is
    /// bookkeeping. See the module docs for the `M`-bit rule it encodes.
    pub fn owner_of(direction: Direction, body: &WireexprOwnedVariant) -> Direction {
        match body {
            // M = 1: local-rooted at encode time — the sender's own space.
            WireexprOwnedVariant::WireexprLocal(_) => direction,
            // M = 0: remote-rooted — the receiver's space.
            WireexprOwnedVariant::WireexprNonlocal(_) => direction.peer(),
        }
    }

    /// Resolve one wire expression seen travelling in `direction`.
    pub fn resolve(&self, direction: Direction, expr: &WireexprOwned) -> Resolved {
        let owner = Self::owner_of(direction, &expr.body);
        let (id, suffix) = match &expr.body {
            WireexprOwnedVariant::WireexprLocal(a) => (a.id, a.suffix.as_deref()),
            WireexprOwnedVariant::WireexprNonlocal(a) => (a.id, a.suffix.as_deref()),
        };
        if id == 0 {
            return match suffix {
                Some(s) if !s.is_empty() => Resolved::Literal(s.to_string()),
                // `WireExpr::empty()` — a reply that names no key at all.
                _ => Resolved::Empty,
            };
        }
        match self.table(owner).get(&id) {
            Some(base) => Resolved::Literal(match suffix {
                Some(s) if !s.is_empty() => {
                    let mut out = String::with_capacity(base.len() + s.len());
                    out.push_str(base);
                    out.push_str(s);
                    out
                }
                _ => base.clone(),
            }),
            None => Resolved::Unresolved {
                id,
                owner,
                suffix: suffix.filter(|s| !s.is_empty()).map(str::to_string),
            },
        }
    }

    /// Fold one observed `Declare` into the tables.
    ///
    /// Only the two keyexpr arms move anything; the subscriber / queryable /
    /// token arms carry expressions but bind no id, so they are read by
    /// [`Self::resolve`] and change nothing here.
    ///
    /// Returns what the declaration bound, when it bound something — a view
    /// that logs "id 17 = demo/robots/**" wants it, and returning it is also
    /// what makes the binding testable without reaching into the tables.
    pub fn observe_declare(
        &mut self,
        direction: Direction,
        declare: &DeclareOwned,
    ) -> Option<(u64, Resolved)> {
        match &declare.body {
            DeclareOwnedVariant::CodecZenohDeclKexpr(d) => {
                // The BOUND expression is itself a wire expression and takes
                // the same M rule — a declaration may be rooted on an earlier
                // one. Resolving it BEFORE inserting is what makes a chained
                // declaration come out as a literal rather than as a second
                // id nobody later resolves.
                let bound = self.resolve(direction, &d.keyexpr);
                if let Resolved::Literal(ref path) = bound {
                    // The declarer owns the id, so it lands in the DECLARER's
                    // table regardless of how the bound expression was rooted.
                    self.table_mut(direction).insert(d.id, path.clone());
                }
                Some((d.id, bound))
            }
            DeclareOwnedVariant::CodecZenohUndeclKexpr(u) => {
                self.table_mut(direction).remove(&u.id);
                None
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wz_codecs::wireexpr_local::WireexprLocalOwned;
    use wz_codecs::wireexpr_nonlocal::WireexprNonlocalOwned;

    fn sfx(suffix: Option<&str>) -> Option<sce_forge_runtime::codec::HeapStr<128>> {
        suffix.map(|s| {
            sce_forge_runtime::codec::SceString::from_view(s).expect("fixture suffix fits")
        })
    }

    fn local(id: u64, suffix: Option<&str>) -> WireexprOwned {
        WireexprOwned {
            body: WireexprOwnedVariant::WireexprLocal(WireexprLocalOwned {
                id,
                suffix_len: suffix.map(|s| s.len() as u64),
                suffix: sfx(suffix),
            }),
        }
    }

    fn nonlocal(id: u64, suffix: Option<&str>) -> WireexprOwned {
        WireexprOwned {
            body: WireexprOwnedVariant::WireexprNonlocal(WireexprNonlocalOwned {
                id,
                suffix_len: suffix.map(|s| s.len() as u64),
                suffix: sfx(suffix),
            }),
        }
    }

    fn declaring(body: DeclareOwnedVariant) -> DeclareOwned {
        DeclareOwned {
            header: 0,
            interest_id: None,
            extensions: None,
            body,
        }
    }

    fn declare_kexpr(id: u64, expr: WireexprOwned) -> DeclareOwned {
        declaring(DeclareOwnedVariant::CodecZenohDeclKexpr(
            wz_codecs::decl_kexpr::DeclKexprOwned {
                header: 0,
                id,
                keyexpr: expr,
            },
        ))
    }

    /// A self-contained expression (`id == 0`) needs no table at all.
    #[test]
    fn a_zero_id_resolves_from_its_suffix_alone() {
        let t = KeyexprTables::new();
        assert_eq!(
            t.resolve(Direction::A, &local(0, Some("demo/a"))),
            Resolved::Literal("demo/a".to_string())
        );
    }

    /// zenoh's `WireExpr::empty()` is a real wire state and is NOT the same
    /// as an id that could not be resolved.
    #[test]
    fn the_empty_wire_expression_is_its_own_answer() {
        let t = KeyexprTables::new();
        assert_eq!(t.resolve(Direction::A, &local(0, None)), Resolved::Empty);
        assert_eq!(
            t.resolve(Direction::A, &local(0, Some(""))),
            Resolved::Empty
        );
    }

    /// THE CORE OF A4. The same id, the same direction, and two different
    /// answers depending on the M bit — because the bit says whose number
    /// space it is. An observer that ignored it would resolve one of these
    /// two to the other's path and report it with full confidence.
    #[test]
    fn the_m_bit_decides_whose_number_space_the_id_is_in() {
        let mut t = KeyexprTables::new();
        t.observe_declare(Direction::A, &declare_kexpr(7, local(0, Some("from/a"))));
        t.observe_declare(Direction::B, &declare_kexpr(7, local(0, Some("from/b"))));

        // Travelling A -> B. Local (M=1) is A's own id 7.
        assert_eq!(
            t.resolve(Direction::A, &local(7, None)),
            Resolved::Literal("from/a".to_string())
        );
        // Nonlocal (M=0) on the SAME direction is the PEER's id 7.
        assert_eq!(
            t.resolve(Direction::A, &nonlocal(7, None)),
            Resolved::Literal("from/b".to_string())
        );
    }

    /// The suffix is appended to the bound base, which is what makes one
    /// declaration serve a whole subtree.
    #[test]
    fn a_suffix_composes_onto_the_bound_base() {
        let mut t = KeyexprTables::new();
        t.observe_declare(
            Direction::A,
            &declare_kexpr(3, local(0, Some("demo/robots/"))),
        );
        assert_eq!(
            t.resolve(Direction::A, &local(3, Some("1/pose"))),
            Resolved::Literal("demo/robots/1/pose".to_string())
        );
    }

    /// A capture that began mid-session. The id is reported WITH the space it
    /// was looked up in and the suffix that would have followed, because
    /// `<unresolved id=17>/pose` locates a message and a blank does not.
    #[test]
    fn an_id_declared_before_the_capture_is_named_not_blanked() {
        let t = KeyexprTables::new();
        assert_eq!(
            t.resolve(Direction::B, &nonlocal(17, Some("/pose"))),
            Resolved::Unresolved {
                id: 17,
                // B sent it, M=0, so the id is A's.
                owner: Direction::A,
                suffix: Some("/pose".to_string()),
            }
        );
    }

    /// A declaration ROOTED on an earlier one resolves through it and lands
    /// as a literal. Inserting the unresolved form instead would leave a
    /// second id that nothing later resolves.
    #[test]
    fn a_chained_declaration_is_flattened_at_bind_time() {
        let mut t = KeyexprTables::new();
        t.observe_declare(Direction::A, &declare_kexpr(1, local(0, Some("demo/"))));
        let bound = t.observe_declare(Direction::A, &declare_kexpr(2, local(1, Some("robots/"))));
        assert_eq!(
            bound,
            Some((2, Resolved::Literal("demo/robots/".to_string())))
        );
        assert_eq!(
            t.resolve(Direction::A, &local(2, Some("1/pose"))),
            Resolved::Literal("demo/robots/1/pose".to_string())
        );
    }

    /// An Undeclare removes the binding, and a later reference to that id is
    /// unresolved again rather than stale.
    #[test]
    fn an_undeclare_retires_the_binding() {
        let mut t = KeyexprTables::new();
        t.observe_declare(Direction::A, &declare_kexpr(5, local(0, Some("demo/x"))));
        assert_eq!(t.len(Direction::A), 1);
        let undecl = declaring(DeclareOwnedVariant::CodecZenohUndeclKexpr(
            wz_codecs::undecl_kexpr::UndeclKexpr { header: 0, id: 5 },
        ));
        t.observe_declare(Direction::A, &undecl);
        assert!(t.is_empty(Direction::A));
        assert!(matches!(
            t.resolve(Direction::A, &local(5, None)),
            Resolved::Unresolved { id: 5, .. }
        ));
    }

    /// The two directions are independent stores: declaring in one must not
    /// make the id resolvable in the other.
    #[test]
    fn a_declaration_does_not_leak_into_the_other_direction() {
        let mut t = KeyexprTables::new();
        t.observe_declare(Direction::A, &declare_kexpr(9, local(0, Some("only/a"))));
        assert!(matches!(
            t.resolve(Direction::B, &local(9, None)),
            Resolved::Unresolved {
                id: 9,
                owner: Direction::B,
                ..
            }
        ));
    }
}
