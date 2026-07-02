// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! QueryableInfo extension on a DeclareQueryable — zenoh's `ext_info`
//! (`QueryableInfoType { complete, distance }`, the `zextz64!(0x01, false)` ext,
//! `commons/zenoh-protocol/src/network/declare.rs:431-460`). The data a
//! `QueryTarget::BestMatching` route needs: route a Query to the NEAREST COMPLETE
//! queryable (the smallest-distance entry with `complete == true`), else fall
//! back to all matching (zenoh `dispatcher/queries.rs:243-266`).
//!
//! Carried as a `Z64` ext on the DeclareQueryable BODY's ext chain (the wire
//! capacity R311ui added). The z64 value packs zenoh's exact layout
//! (`commons/zenoh-codec/src/network/declare.rs:553-576`):
//!
//! ```text
//!   value = (complete as u64) | ((distance as u64) << 8)
//! ```
//!
//! complete @ bit 0 (zenoh `queryable::ext::flag::C`), distance @ bits 8-23. The
//! DEFAULT `{ complete: false, distance: 0 }` packs to `0` and is OMITTED (no
//! ext, body header `Z` clear) — zenoh's omit-on-DEFAULT. Read / build route
//! through the shared [`read_z64_ext`](crate::ext_nodeid::read_z64_ext) /
//! [`set_z64_ext`](crate::ext_nodeid::set_z64_ext) chain SSOT, exactly like
//! [`ext_nodeid`](crate::ext_nodeid)'s `read_source` / `set_source`.

use alloc::vec::Vec;

use wz_codecs::ext_entry::ExtEntryOwned;

use crate::ext_nodeid::{read_z64_ext, set_z64_ext, EXT_ENC_Z64};

/// The QueryableInfo extension id — zenoh `zextz64!(0x01, false)`.
pub const QUERYABLE_INFO_EXT_ID: u8 = 0x01;
/// The QueryableInfo ext header for a terminal entry: `id | ENC_Z64`. NOTE: NO
/// `FLAG_M` — zenoh declares this ext NON-mandatory (`zextz64!(0x01, FALSE)`),
/// unlike the mandatory `ext_nodeid` (`0x33`). A receiver that does not
/// understand it may ignore it (M = 0), so the terminal header is `0x21`; the
/// chain-continuation `Z` bit is layered on by `set_z64_ext` if another ext
/// follows.
pub const QUERYABLE_INFO_EXT_HEADER: u8 = QUERYABLE_INFO_EXT_ID | EXT_ENC_Z64;
/// zenoh `queryable::ext::flag::C` (bit 0 of the z64 value) — the complete flag.
const COMPLETE_FLAG: u64 = 0x01;
/// The distance occupies the value bits above the flag byte (zenoh shifts the
/// `u16` distance left by 8).
const DISTANCE_SHIFT: u32 = 8;

/// A queryable's QueryableInfo (zenoh `QueryableInfoType`): whether it is
/// COMPLETE (can serve the whole query by itself, so a BestMatching route may go
/// to it alone) and its DISTANCE (hop count, accumulated as the declaration
/// propagates — the BestMatching ordering key). The DEFAULT is incomplete @ 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryableInfo {
    /// Whether the queryable can serve the whole query on its own.
    pub complete: bool,
    /// Hop distance to the queryable (the BestMatching nearest-first key).
    pub distance: u16,
}

impl QueryableInfo {
    /// zenoh's DEFAULT `{ complete: false, distance: 0 }` — an incomplete
    /// queryable at no recorded distance, the value OMITTED from the wire.
    pub const DEFAULT: Self = Self {
        complete: false,
        distance: 0,
    };

    /// The `QueryableInfo` for a LOCALLY-declared queryable — distance `0` (a
    /// node is zero hops from its own queryable; zenoh's client / simple
    /// queryable carries distance 0). The single SSOT for the "local declaration
    /// = distance 0" convention, so no producer site (the forwarder's
    /// `declare_queryable`, the session's `prepare_declare_queryable`, the
    /// reconnect replay) open-codes the `distance: 0` literal. BestMatching reads
    /// the GRAPH distance anyway, not this carried value.
    pub const fn local(complete: bool) -> Self {
        Self {
            complete,
            distance: 0,
        }
    }

    /// Merge two `QueryableInfo`s into the aggregate a node advertises when it
    /// covers a keyexpr via MORE THAN ONE queryable — zenoh's `merge_qabl_infos`
    /// (`hat/router/queries.rs:61-65`): `complete = self.complete || other.complete`
    /// (the aggregate can serve the whole query if ANY contributor can) and
    /// `distance = min` (the nearest contributor). Associative + commutative, so a
    /// fold over the contributor set is order-independent. NOTE: fold from the
    /// FIRST contributor (`Option`-seed), NEVER from [`DEFAULT`](Self::DEFAULT) —
    /// `DEFAULT.distance == 0` would collapse the `min` to 0 (zenoh seeds its fold
    /// with the first element for the same reason).
    #[must_use]
    pub fn merge(self, other: Self) -> Self {
        Self {
            complete: self.complete || other.complete,
            distance: self.distance.min(other.distance),
        }
    }
}

impl Default for QueryableInfo {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Pack into the z64 ext value, zenoh's exact layout
/// (`zenoh-codec .../declare.rs:556`): `(complete) | (distance << 8)`.
fn pack(info: QueryableInfo) -> u64 {
    (info.complete as u64) | ((info.distance as u64) << DISTANCE_SHIFT)
}

/// Unpack the z64 ext value (zenoh `.../declare.rs:575-576`).
fn unpack(value: u64) -> QueryableInfo {
    QueryableInfo {
        complete: value & COMPLETE_FLAG != 0,
        distance: (value >> DISTANCE_SHIFT) as u16,
    }
}

/// Read the QueryableInfo from a DeclareQueryable body's ext chain. An absent
/// ext is zenoh's DEFAULT `{ complete: false, distance: 0 }` (the omit-on-DEFAULT
/// inverse). A thin projection of the shared [`read_z64_ext`] over the
/// QueryableInfo id.
pub fn read_queryable_info(exts: Option<&Vec<ExtEntryOwned>>) -> QueryableInfo {
    read_z64_ext(exts, QUERYABLE_INFO_EXT_ID).map_or(QueryableInfo::DEFAULT, unpack)
}

/// Set / omit the QueryableInfo on a body's ext chain, mirroring zenoh's
/// omit-on-DEFAULT encoding: the DEFAULT `{ false, 0 }` (z64 value `0`) REMOVES
/// any existing entry, anything else inserts / replaces it. Returns whether the
/// chain is now NON-EMPTY, so the caller can sync the body's header `Z` flag. A
/// thin projection of the shared [`set_z64_ext`].
pub fn set_queryable_info(exts: &mut Option<Vec<ExtEntryOwned>>, info: QueryableInfo) -> bool {
    let value = pack(info);
    set_z64_ext(
        exts,
        QUERYABLE_INFO_EXT_ID,
        QUERYABLE_INFO_EXT_HEADER,
        (value != 0).then_some(value),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn merge_is_or_complete_and_min_distance() {
        let a = QueryableInfo {
            complete: false,
            distance: 3,
        };
        let b = QueryableInfo {
            complete: true,
            distance: 7,
        };
        // complete = OR, distance = min; commutative.
        let ab = a.merge(b);
        assert!(ab.complete, "either-complete makes the aggregate complete");
        assert_eq!(ab.distance, 3, "distance is the nearest contributor");
        assert_eq!(a.merge(b), b.merge(a), "merge is commutative");
        // Merging with a distance-0 peer must NOT be seeded from DEFAULT (which
        // would collapse min to 0 spuriously) — a genuine distance-0 contributor
        // still wins the min, but a real min is preserved when no 0 is present.
        let far = QueryableInfo {
            complete: false,
            distance: 100,
        };
        assert_eq!(a.merge(far).distance, 3, "min keeps the nearer 3, not 100");
    }

    #[test]
    fn pack_unpack_round_trips_every_field_combination() {
        for info in [
            QueryableInfo::DEFAULT,
            QueryableInfo {
                complete: true,
                distance: 0,
            },
            QueryableInfo {
                complete: false,
                distance: 5,
            },
            QueryableInfo {
                complete: true,
                distance: 300,
            },
            QueryableInfo {
                complete: true,
                distance: u16::MAX,
            },
        ] {
            assert_eq!(unpack(pack(info)), info, "pack/unpack must round-trip");
        }
    }

    #[test]
    fn pack_matches_zenohs_exact_bit_layout() {
        // zenoh-codec .../declare.rs:556 — complete @ bit 0, distance << 8.
        assert_eq!(pack(QueryableInfo::DEFAULT), 0, "DEFAULT packs to 0");
        assert_eq!(
            pack(QueryableInfo {
                complete: true,
                distance: 0
            }),
            0x01,
            "complete is bit 0 (zenoh flag::C)",
        );
        assert_eq!(
            pack(QueryableInfo {
                complete: false,
                distance: 1
            }),
            0x100,
            "distance << 8",
        );
        assert_eq!(
            pack(QueryableInfo {
                complete: true,
                distance: 2
            }),
            0x201,
            "complete bit 0 | distance << 8",
        );
    }

    #[test]
    fn read_absent_is_default() {
        assert_eq!(read_queryable_info(None), QueryableInfo::DEFAULT);
        // A chain with only some OTHER ext id reads DEFAULT for the queryable info.
        let other = ExtEntryOwned {
            header: 0x03 | EXT_ENC_Z64, // ext_nodeid id, not ours
            body: wz_codecs::ext_entry::ExtEntryOwnedVariant::CodecZenohExtZint(
                wz_codecs::ext_zint::ExtZint { value: 7 },
            ),
        };
        assert_eq!(
            read_queryable_info(Some(&vec![other])),
            QueryableInfo::DEFAULT,
        );
    }

    #[test]
    fn set_default_omits_and_set_value_round_trips() {
        let mut exts: Option<Vec<ExtEntryOwned>> = None;
        // The DEFAULT omits (no entry, chain stays empty).
        assert!(
            !set_queryable_info(&mut exts, QueryableInfo::DEFAULT),
            "DEFAULT must omit -> chain empty",
        );
        assert!(exts.is_none(), "no ext entry inserted for DEFAULT");

        // A non-default inserts + reads back exactly.
        let info = QueryableInfo {
            complete: true,
            distance: 42,
        };
        assert!(
            set_queryable_info(&mut exts, info),
            "non-default -> chain non-empty"
        );
        assert_eq!(read_queryable_info(exts.as_ref()), info);
        // The entry carries the non-mandatory header (no FLAG_M), terminal Z clear.
        assert_eq!(exts.as_ref().unwrap()[0].header, QUERYABLE_INFO_EXT_HEADER);

        // Re-setting to DEFAULT removes it again (omit-on-DEFAULT).
        assert!(!set_queryable_info(&mut exts, QueryableInfo::DEFAULT));
        assert!(exts.is_none(), "DEFAULT removed the entry");
    }
}
