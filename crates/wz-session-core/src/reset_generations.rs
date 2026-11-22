// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The lifecycle reset's table of generations (decision D6 of
//! `docs/session-lifecycle-intent.md`; the duplicate suppression of at-most-once calls, Birrell
//! and Nelson, 1984): the latest reset generation taken for each peer, so that a retransmission of
//! a reset closes no session once more.
//!
//! The rule is the SCE `algorithm` document `sources/algorithms/take_generation.scxml`, written
//! once for every profile: a generation newer than the one held, or the first of a peer, is taken
//! and held; one the table holds already, or an older one, is a duplicate of the last; a new peer
//! the full table has no room for is refused, and the table never evicts, since evicting a peer's
//! entry would let a retransmission of its reset close the session once more. The table is the
//! map that algorithm writes in place (SCE ADR 0108), keyed by the peer's zid read as the
//! unsigned 128-bit number zenoh compares, so two spellings of one zid on the wire are one key.
//!
//! Each profile states the table's bound and where the map keeps its entries (SCE ADR 0108, D4
//! "Storage"): a fixed-memory node the room it was built with, held inline in the table so that it
//! never allocates whatever else the build links, and a heap node [`HEAP_RESET_PEERS`], which no
//! node reaches, held on the heap. The storage is a parameter of the table's type rather than a
//! consequence of the build's features, because Cargo unifies an `alloc` feature across every
//! crate of one build, and a fixed-memory table must stay inline beside a heap one.

use sce_portable_bytes::BoundedMap;
/// The storage of a fixed-memory node's table, which never allocates (SCE ADR 0108, D4), named
/// here so that a node names it without depending on the map's crate.
pub use sce_portable_bytes::Inline;
/// The key a table's index hashes peers under (SCE ADR 0108, D8), which its host hands it.
pub use sce_portable_bytes::MapSeed;
use sce_portable_bytes::MapStorage;

use crate::lifecycle_node::{Generation, Zid};

mod generated {
    // Emitted by the xtask (`regen_statecharts_and_pools`) into one directory, so each unit names
    // the others it uses as `super::<unit>`.
    macro_rules! generated {
        ($($name:ident),* $(,)?) => {
            $(
                #[allow(dead_code, clippy::all)]
                pub(super) mod $name {
                    include!(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/../../out/wz-session-core/",
                        stringify!($name),
                        ".rs"
                    ));
                }
            )*
        };
    }
    generated!(
        reset_peer_schema,
        take_generation_kind,
        take_generation_duplicate,
        take_generation_result,
        put_outcome,
        take_generation,
    );
}

use generated::reset_peer_schema::ResetPeerSchemaPayload as Peer;
use generated::take_generation_result::TakeGenerationResult;

/// The seed a table is keyed by before its host has drawn one: zero, so that an inline table built
/// under it is all zero bytes, and a `static` holding one is placed in `.bss`
/// (SCE ADR 0108, D8). It is a key anyone knows: the host gives the table a drawn one with
/// [`ResetGenerations::reseed`] once it has one.
pub const UNDRAWN_SEED: MapSeed = MapSeed::from_halves(0, 0);

/// The bound of a heap node's table: half the numbers a map's slot holds, the largest bound whose
/// index (twice the bound) a 32-bit target can still count. A heap node's map, in heap storage,
/// takes its room as it fills, never this much up front, so the bound is one no node reaches and
/// a heap node never answers [`Generation::NoRoom`], as that answer's contract says.
pub const HEAP_RESET_PEERS: usize = (u32::MAX / 2) as usize;

/// The latest reset generation taken for each peer, for at most `N` peers, kept in the storage
/// `S`: [`Inline`] for a node that must never allocate, `Heap` for one whose bound it never
/// reaches. No default, so every holder states which, as it states the bound.
pub struct ResetGenerations<const N: usize, S: MapStorage> {
    taken: BoundedMap<Peer, u64, N, S>,
}

impl<const N: usize, S: MapStorage> ResetGenerations<N, S> {
    /// The empty table, its keys hashed under `seed` (SCE ADR 0108, D8). A host with an entropy
    /// source hands a seed drawn from it, so a peer cannot choose zids that crowd one chain of the
    /// table's index; a host with none hands a fixed one, which leaves a peer that knows it able
    /// to make each look-up walk at most the `N` entries the table holds. `const`, so a `static`
    /// can hold a table, all zero bytes when it is inline and built under [`UNDRAWN_SEED`].
    pub const fn with_seed(seed: MapSeed) -> Self {
        Self {
            taken: BoundedMap::with_seed(seed),
        }
    }

    /// Key the table by `seed` from now on, the generations it holds as they were: what a table
    /// built in a const context under [`UNDRAWN_SEED`] is given a drawn seed by.
    pub fn reseed(&mut self, seed: MapSeed) {
        self.taken.reseed(seed);
    }

    /// Take `generation` as the latest of the peer `zid`, unless one as late was taken.
    pub fn take(&mut self, zid: &Zid, generation: u64) -> Generation {
        match generated::take_generation::take_generation(&mut self.taken, peer(zid), generation) {
            TakeGenerationResult::Taken => Generation::Taken,
            TakeGenerationResult::Duplicate(duplicate) => Generation::Duplicate {
                last: duplicate.last,
            },
            TakeGenerationResult::NoRoom => Generation::NoRoom,
        }
    }

    /// How many peers the table holds a generation for.
    pub fn len(&self) -> usize {
        self.taken.len()
    }

    /// Whether the table holds no peer's generation.
    pub fn is_empty(&self) -> bool {
        self.taken.is_empty()
    }
}

/// The key of `zid`: its sixteen little-endian bytes read as the 128-bit number, low half first.
/// A zid's high zero bytes are part of no spelling of it (`credential_identity::canonical_zid`),
/// so every spelling of one zid reads to the same number.
fn peer(zid: &Zid) -> Peer {
    let mut low = [0u8; 8];
    let mut high = [0u8; 8];
    low.copy_from_slice(&zid[..8]);
    high.copy_from_slice(&zid[8..]);
    Peer {
        low: u64::from_le_bytes(low),
        high: u64::from_le_bytes(high),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: MapSeed = MapSeed::from_halves(0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210);

    fn zid(last: u8) -> Zid {
        let mut zid = [0u8; 16];
        zid[0] = 0x5a;
        zid[15] = last;
        zid
    }

    #[test]
    fn the_first_generation_of_a_peer_and_every_later_one_is_taken() {
        let mut table = ResetGenerations::<2, Inline>::with_seed(SEED);
        assert_eq!(table.take(&zid(1), 7), Generation::Taken);
        assert_eq!(table.take(&zid(1), 8), Generation::Taken);
        assert_eq!(table.take(&zid(1), u64::MAX), Generation::Taken);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn the_same_generation_or_an_older_one_is_a_duplicate_of_the_last() {
        let mut table = ResetGenerations::<2, Inline>::with_seed(SEED);
        assert_eq!(table.take(&zid(1), 7), Generation::Taken);
        assert_eq!(table.take(&zid(1), 7), Generation::Duplicate { last: 7 });
        assert_eq!(table.take(&zid(1), 3), Generation::Duplicate { last: 7 });
        // A duplicate leaves the last as it was.
        assert_eq!(table.take(&zid(1), 8), Generation::Taken);
        assert_eq!(table.take(&zid(1), 7), Generation::Duplicate { last: 8 });
    }

    #[test]
    fn a_generation_of_zero_is_taken_once() {
        let mut table = ResetGenerations::<1, Inline>::with_seed(SEED);
        assert_eq!(table.take(&zid(1), 0), Generation::Taken);
        assert_eq!(table.take(&zid(1), 0), Generation::Duplicate { last: 0 });
    }

    #[test]
    fn a_new_peer_the_full_table_has_no_room_for_is_refused_and_nothing_is_evicted() {
        let mut table = ResetGenerations::<2, Inline>::with_seed(SEED);
        assert_eq!(table.take(&zid(1), 1), Generation::Taken);
        assert_eq!(table.take(&zid(2), 1), Generation::Taken);
        assert_eq!(table.take(&zid(3), 1), Generation::NoRoom);
        // The peers held keep their generations, and still take later ones.
        assert_eq!(table.take(&zid(1), 1), Generation::Duplicate { last: 1 });
        assert_eq!(table.take(&zid(2), 2), Generation::Taken);
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn a_table_built_for_no_peer_refuses_every_one() {
        let mut table = ResetGenerations::<0, Inline>::with_seed(SEED);
        assert_eq!(table.take(&zid(1), 1), Generation::NoRoom);
        assert!(table.is_empty());
    }

    #[test]
    fn a_table_given_another_seed_keeps_what_it_holds() {
        let mut table = ResetGenerations::<2, Inline>::with_seed(UNDRAWN_SEED);
        assert_eq!(table.take(&zid(1), 4), Generation::Taken);
        assert_eq!(table.take(&zid(2), 9), Generation::Taken);
        table.reseed(SEED);
        assert_eq!(table.take(&zid(1), 4), Generation::Duplicate { last: 4 });
        assert_eq!(table.take(&zid(2), 10), Generation::Taken);
        assert_eq!(table.take(&zid(3), 1), Generation::NoRoom);
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn peers_whose_zids_differ_in_either_half_are_apart() {
        let mut table = ResetGenerations::<4, Inline>::with_seed(SEED);
        let mut low_only = [0u8; 16];
        low_only[0] = 1;
        let mut high_only = [0u8; 16];
        high_only[8] = 1;
        assert_eq!(table.take(&low_only, 5), Generation::Taken);
        assert_eq!(table.take(&high_only, 5), Generation::Taken);
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn an_inline_table_can_be_a_static_built_empty() {
        static TABLE: ResetGenerations<4, Inline> = ResetGenerations::with_seed(UNDRAWN_SEED);
        assert!(TABLE.is_empty());
        assert_eq!(TABLE.len(), 0);
    }

    /// The storage changes where the entries are kept, never what the table answers: a heap table
    /// of the same bound refuses a new peer when full, as an inline one does.
    #[cfg(feature = "alloc")]
    #[test]
    fn a_heap_table_answers_as_an_inline_one_of_the_same_bound() {
        let mut inline = ResetGenerations::<2, Inline>::with_seed(SEED);
        let mut heap = ResetGenerations::<2, sce_portable_bytes::Heap>::with_seed(SEED);
        let steps = [(1, 7), (1, 7), (1, 3), (2, 1), (3, 1), (1, 8), (2, 0)];
        for (last, generation) in steps {
            let expected = inline.take(&zid(last), generation);
            assert_eq!(heap.take(&zid(last), generation), expected);
        }
        assert_eq!(heap.take(&zid(3), 2), Generation::NoRoom);
        assert_eq!(heap.len(), inline.len());
        assert_eq!(heap.len(), 2);
    }
}
