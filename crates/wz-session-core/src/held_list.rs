// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A list a message holds, kept within its bound as a type.
//!
//! The generated owned messages hold an extension chain or a list of slices as a `Bounded`
//! (SCE ADR 0065 section 6, R2), so a list past its bound is not a value: the encode no longer
//! refuses one, and a `Bounded` has no mutable access. What a chain's bound refused at the send
//! is refused here, where the list is made or edited, and the three ways this crate holds a list
//! are written once: `HeldList::entries` reads one, `held` and `one_entry` make one, and
//! `edit_chain` changes one (each needs the `alloc` feature, so none is linked from here).

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "alloc")]
use sce_forge_runtime::codec::CodecError;
use sce_forge_runtime::codec::{Bounded, SceList};

/// The entries of an optional list a message holds, as a slice.
pub trait HeldList<E> {
    /// The entries, or `None` for a list the message does not hold.
    fn entries(&self) -> Option<&[E]>;
}

impl<E, L: SceList<E>, const MAX: usize, const MIN: usize> HeldList<E>
    for Option<Bounded<L, MAX, MIN>>
{
    fn entries(&self) -> Option<&[E]> {
        self.as_ref().map(|list| SceList::as_slice(list.inner()))
    }
}

/// A decoded message holds its list as the `heapless` vector the decode filled, whose capacity is
/// the bound.
impl<E, const N: usize> HeldList<E> for Option<sce_forge_runtime::heapless::Vec<E, N>> {
    fn entries(&self) -> Option<&[E]> {
        self.as_deref()
    }
}

/// `list` within its bounds: at most `MAX` entries, and at least `MIN`, which is one for a chain
/// closed by an entry flag and none for every other list. A list past `MAX` is what a decode of
/// such a frame refuses, `TooManyElements`; one short of `MIN` is a chain with no entry, which no
/// frame can say, and is refused as a list out of its bounds, `LengthOutOfRange`.
#[cfg(feature = "alloc")]
pub fn held<E, const MAX: usize, const MIN: usize>(
    list: Vec<E>,
) -> Result<Bounded<Vec<E>, MAX, MIN>, CodecError> {
    if list.len() > MAX {
        return Err(CodecError::TooManyElements);
    }
    Bounded::new(list).ok_or(CodecError::LengthOutOfRange)
}

/// The list of the one entry `entry`, which every declared bound holds.
#[cfg(feature = "alloc")]
pub fn one_entry<E, const MAX: usize, const MIN: usize>(entry: E) -> Bounded<Vec<E>, MAX, MIN> {
    const { assert!(MAX >= 1, "a list of one entry needs a bound of one or more") };
    const { assert!(MIN <= 1, "a list of one entry holds at most one entry") };
    match Bounded::new(alloc::vec![entry]) {
        Some(list) => list,
        None => unreachable!("the bounds are checked when this is compiled"),
    }
}

/// Run `edit` on the chain as the growable list it is, and hold what it leaves.
///
/// An edit that leaves the chain with no entry leaves the message with no chain: a chain closed
/// by an entry flag holds one entry or more, so an empty one is not a chain the message can hold.
///
/// `edit` may leave the chain past its bound, which only an edit that adds an entry to a chain
/// already at its bound can. The message cannot be sent then, since no frame holds such a chain:
/// the error is the decode's refusal of one, `TooManyElements`, and the chain is gone from the
/// message, whose caller drops it. Nothing is cloned to keep it, since this runs on a relay's
/// path.
#[cfg(feature = "alloc")]
pub fn edit_chain<E, const MAX: usize, const MIN: usize, R>(
    chain: &mut Option<Bounded<Vec<E>, MAX, MIN>>,
    edit: impl FnOnce(&mut Option<Vec<E>>) -> R,
) -> Result<R, CodecError> {
    let mut list = chain.take().map(Bounded::into_inner);
    let answer = edit(&mut list);
    *chain = list.filter(|list| !list.is_empty()).map(held).transpose()?;
    Ok(answer)
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;

    #[test]
    fn an_edit_that_stays_within_the_bound_is_held() {
        let mut chain: Option<Bounded<Vec<u8>, 2>> = Some(one_entry(1));
        assert_eq!(
            edit_chain(&mut chain, |list| {
                list.get_or_insert_with(Vec::new).push(2);
                "answer"
            }),
            Ok("answer")
        );
        assert_eq!(chain.entries(), Some(&[1, 2][..]));
    }

    #[test]
    fn an_edit_that_leaves_none_holds_none() {
        let mut chain: Option<Bounded<Vec<u8>, 2>> = Some(one_entry(1));
        edit_chain(&mut chain, |list| *list = None).expect("nothing to hold");
        assert_eq!(chain.entries(), None);
    }

    /// The refusal a decode gives a frame with such a chain: the message cannot be sent.
    #[test]
    fn an_edit_past_the_bound_is_refused_and_the_chain_is_gone() {
        let mut chain: Option<Bounded<Vec<u8>, 1>> = Some(one_entry(1));
        assert_eq!(
            edit_chain(&mut chain, |list| {
                list.get_or_insert_with(Vec::new).push(2);
            }),
            Err(CodecError::TooManyElements)
        );
        assert_eq!(chain.entries(), None);
    }

    /// A chain of one entry or more that an edit empties is no chain at all.
    #[test]
    fn an_edit_that_empties_a_chain_of_one_or_more_holds_none() {
        let mut chain: Option<Bounded<Vec<u8>, 2, 1>> = Some(one_entry(1));
        edit_chain(&mut chain, |list| {
            if let Some(list) = list {
                list.clear();
            }
        })
        .expect("an empty chain is dropped, not refused");
        assert_eq!(chain.entries(), None);
    }

    #[test]
    fn a_list_past_its_bound_is_not_held() {
        assert_eq!(
            held::<u8, 1, 0>(alloc::vec![1, 2]).err(),
            Some(CodecError::TooManyElements)
        );
        assert_eq!(
            held::<u8, 2, 1>(alloc::vec![]).err(),
            Some(CodecError::LengthOutOfRange)
        );
        assert_eq!(
            Some(held::<u8, 2, 0>(alloc::vec![1, 2]).expect("within")).entries(),
            Some(&[1, 2][..])
        );
    }
}
