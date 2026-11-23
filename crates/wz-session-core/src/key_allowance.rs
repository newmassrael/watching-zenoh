// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Which keys each declared peer may use (the per-peer allowance of the closed key set, built up
//! to the key gate): a read-only table of bits, one row for each peer the image declares and each
//! operation, one bit for each key of the closed key set.
//!
//! # What it is
//!
//! A closed image knows its peers when it is built, by their zids, and says for each what it may do on
//! which keys. The build derives from that a [`PeerAllowance`]: [`PeerAllowance::class_of`] finds the
//! row of a peer from its zid, once, when the peer is known, and [`PeerAllowance::allows`] answers for
//! that row, an operation and a [`KeyId`] with one bit test. It reads no
//! clock, allocates nothing and owns no memory: the arrays are `static` and written by
//! `scripts/lib/wz_key_set.py`.
//!
//! # The rules it states once
//!
//! * A peer that is not declared has no row ([`PeerAllowance::class_of`] answers `None`), and a message
//!   from it is allowed nothing: the table is closed over peers as it is over keys.
//! * A key outside the table, and a row or an operation outside it, are not allowed.
//! * The rows are in strict ascending order of the peer's zid bytes, so a zid is found by a binary
//!   search and is declared once.
//! * What a bit says is what the declaration says: key `k` is allowed to a peer for an operation when
//!   some pattern the declaration lists for that peer and operation intersects `k`. Only the concrete
//!   keys of the set carry a bit; the keys that are patterns carry none, since a data key is concrete.
//!   The model test of `tests/it/files/key_catalogue_model.rs` compares every bit of a generated table with the
//!   matcher.
//!
//! # A bad table is a build error
//!
//! [`PeerAllowance::try_new`] is a `const fn` that checks the shape (the zids' order, the size of the
//! bit array, the bits past the last key being zero) and answers with the reason. The generated table
//! is built by it in a `const` of the image's own crate, which stops the build on a refusal, so a
//! table the generator wrote wrongly is a build error there and this crate holds no panic for it.

use crate::key_catalogue::KeyId;

/// How many [`PeerOp`]s there are: the number of rows a peer has.
pub const PEER_OPS: usize = 1;

/// What a peer does with a key that the allowance decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PeerOp {
    /// The peer sends a message on the key: a Put or a Delete, which this node receives.
    Publish,
}

impl PeerOp {
    /// Every operation, in index order.
    pub const ALL: [PeerOp; PEER_OPS] = [PeerOp::Publish];

    /// The operation's place in [`Self::ALL`]: its row beside the peer's.
    pub const fn index(self) -> usize {
        match self {
            PeerOp::Publish => 0,
        }
    }
}

/// A peer the image declares: its row in the zid table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClassId(u16);

impl ClassId {
    /// The class at `index` of the zid table.
    pub const fn new(index: u16) -> Self {
        Self(index)
    }

    /// The class's row in the zid table.
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

/// Why a table is not one: the first property it breaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowanceError {
    /// More peers than a `u16` numbers.
    TooLarge,
    /// The zids are not in strictly ascending order of their bytes.
    ZidOrder,
    /// The bit array is not the size the peers, the operations and the keys make.
    BitsLength,
    /// A bit past the last key of a row is set.
    SpareBits,
}

impl AllowanceError {
    /// The reason in words, for the build error a bad table is.
    pub const fn describe(self) -> &'static str {
        match self {
            AllowanceError::TooLarge => "a peer allowance holds at most 65535 peers",
            AllowanceError::ZidOrder => "a peer allowance's zids are not strictly ascending",
            AllowanceError::BitsLength => {
                "a peer allowance's bits are not peers x operations x keys"
            }
            AllowanceError::SpareBits => "a peer allowance sets a bit past its last key",
        }
    }
}

/// The table of what each declared peer may do on each key. See the module note.
///
/// `bits` is one row of `ceil(keys / 8)` bytes for each peer and each operation, peer first: the row of
/// class `c` and operation `o` starts at `(c * PEER_OPS + o) * ceil(keys / 8)`, and key `k` is bit
/// `k % 8` of byte `k / 8` of it.
#[derive(Debug, Clone, Copy)]
pub struct PeerAllowance<'a> {
    zids: &'a [[u8; 16]],
    keys: usize,
    bits: &'a [u8],
}

impl<'a> PeerAllowance<'a> {
    /// The table over the generated arrays, or why they are not one. `keys` is the number of keys of
    /// the closed key set the bits are over.
    pub const fn try_new(
        zids: &'a [[u8; 16]],
        keys: usize,
        bits: &'a [u8],
    ) -> Result<Self, AllowanceError> {
        if zids.len() > u16::MAX as usize {
            return Err(AllowanceError::TooLarge);
        }
        let mut rest = zids;
        while let [before, after @ ..] = rest {
            if let [next, ..] = after {
                if !zid_less(before, next) {
                    return Err(AllowanceError::ZidOrder);
                }
            }
            rest = after;
        }
        let row = keys.div_ceil(8);
        let want = match zids.len().checked_mul(PEER_OPS) {
            Some(rows) => rows.checked_mul(row),
            None => None,
        };
        match want {
            Some(want) if want == bits.len() => {}
            _ => return Err(AllowanceError::BitsLength),
        }
        // The bits past the last key of each row are zero, so a row is the same bytes however it was
        // made and a count of its bits is a count of keys.
        let spare = keys % 8;
        if spare != 0 {
            // The bits at and above `spare` of a row's last byte.
            let mask = u8::MAX.wrapping_shl(spare as u32);
            let mut rest = bits;
            // `row` is not zero here, and the length is a whole number of rows, checked above.
            while rest.len() >= row && row > 0 {
                let (head, tail) = rest.split_at(row);
                if let [.., last] = head {
                    if *last & mask != 0 {
                        return Err(AllowanceError::SpareBits);
                    }
                }
                rest = tail;
            }
        }
        Ok(Self { zids, keys, bits })
    }

    /// How many peers the image declares.
    pub const fn class_count(&self) -> usize {
        self.zids.len()
    }

    /// The row of the declared peer whose zid is `zid`, once, when the peer is known: `None` for a zid
    /// the image does not declare, and for bytes that are not a zid's sixteen.
    pub fn class_of(&self, zid: &[u8]) -> Option<ClassId> {
        let target: &[u8; 16] = zid.try_into().ok()?;
        let at = self.zids.binary_search(target).ok()?;
        Some(ClassId::new(u16::try_from(at).ok()?))
    }

    /// Whether the peer of `class` may do `op` on `key`: one bit. `false` for a class, a key or an
    /// operation outside the table.
    pub fn allows(&self, class: ClassId, op: PeerOp, key: KeyId) -> bool {
        if class.index() >= self.zids.len() || key.index() >= self.keys {
            return false;
        }
        let row = self.keys.div_ceil(8);
        // An offset past the address space is no bit of the table.
        let at = class
            .index()
            .checked_mul(PEER_OPS)
            .and_then(|rows| rows.checked_add(op.index()))
            .and_then(|rows| rows.checked_mul(row))
            .and_then(|start| start.checked_add(key.index() / 8));
        match at.and_then(|at| self.bits.get(at)) {
            Some(byte) => byte
                .checked_shr((key.index() % 8) as u32)
                .is_some_and(|bits| bits & 1 == 1),
            None => false,
        }
    }
}

/// Whether `a` sorts strictly before `b` by bytes.
const fn zid_less(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let (mut a, mut b): (&[u8], &[u8]) = (a, b);
    while let ([x, a_rest @ ..], [y, b_rest @ ..]) = (a, b) {
        if *x != *y {
            return *x < *y;
        }
        a = a_rest;
        b = b_rest;
    }
    false
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    const A: [u8; 16] = [1; 16];
    const B: [u8; 16] = [2; 16];
    const ZIDS: [[u8; 16]; 2] = [A, B];
    // Ten keys: a row is two bytes. Peer A may use keys 0, 3 and 9; peer B may use key 1.
    const BITS: [u8; 4] = [0b0000_1001, 0b0000_0010, 0b0000_0010, 0b0000_0000];

    /// The two-peer table of these tests, for the tests of what is built on an allowance.
    pub(crate) const TABLE: PeerAllowance<'static> = match PeerAllowance::try_new(&ZIDS, 10, &BITS)
    {
        Ok(table) => table,
        Err(_) => panic!("the test table is a table"),
    };

    #[test]
    fn a_peer_is_found_by_its_zid_and_only_by_all_of_it() {
        assert_eq!(TABLE.class_of(&A), Some(ClassId::new(0)));
        assert_eq!(TABLE.class_of(&B), Some(ClassId::new(1)));
        assert_eq!(TABLE.class_of(&[3; 16]), None);
        assert_eq!(TABLE.class_of(&[1; 15]), None);
        assert_eq!(TABLE.class_of(&[1; 17]), None);
        assert_eq!(TABLE.class_of(&[]), None);
        assert_eq!(TABLE.class_count(), 2);
    }

    #[test]
    fn a_bit_is_what_the_row_says_and_nothing_else_is_allowed() {
        let a = ClassId::new(0);
        let b = ClassId::new(1);
        let allowed = |class, key| TABLE.allows(class, PeerOp::Publish, KeyId::new(key));
        let rows = |class| -> [bool; 10] { core::array::from_fn(|k| allowed(class, k as u16)) };
        let yes = true;
        let no = false;
        assert_eq!(
            rows(a),
            [yes, no, no, yes, no, no, no, no, no, yes],
            "peer A may use keys 0, 3 and 9"
        );
        assert_eq!(
            rows(b),
            [no, yes, no, no, no, no, no, no, no, no],
            "peer B may use key 1"
        );
        // Outside the table: a key past the last, a class past the last.
        assert!(!allowed(a, 10));
        assert!(!allowed(a, 200));
        assert!(!allowed(ClassId::new(2), 0));
    }

    #[test]
    fn a_table_that_breaks_a_property_is_refused_by_that_property() {
        let shape = |zids: &[[u8; 16]], keys: usize, bits: &[u8]| {
            PeerAllowance::try_new(zids, keys, bits).map(|t| t.class_count())
        };
        assert_eq!(shape(&[B, A], 10, &BITS), Err(AllowanceError::ZidOrder));
        assert_eq!(shape(&[A, A], 10, &BITS), Err(AllowanceError::ZidOrder));
        assert_eq!(
            shape(&ZIDS, 10, &BITS[..3]),
            Err(AllowanceError::BitsLength)
        );
        assert_eq!(shape(&ZIDS, 20, &BITS), Err(AllowanceError::BitsLength));
        // Bit 10 of peer A's row is past the last of ten keys.
        assert_eq!(
            shape(&ZIDS, 10, &[0b0000_1001, 0b0000_0110, 0, 0]),
            Err(AllowanceError::SpareBits)
        );
        assert_eq!(shape(&ZIDS, 10, &BITS), Ok(2));
    }

    #[test]
    fn a_table_of_no_peers_or_no_keys_is_a_table() {
        let none = PeerAllowance::try_new(&[], 10, &[]).expect("no peers");
        assert_eq!(none.class_of(&A), None);
        let empty = PeerAllowance::try_new(&ZIDS, 0, &[]).expect("no keys");
        assert!(!empty.allows(ClassId::new(0), PeerOp::Publish, KeyId::new(0)));
    }
}
