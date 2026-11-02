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

impl<E, L: SceList<E>, const MAX: usize> HeldList<E> for Option<Bounded<L, MAX>> {
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

/// `list` within its bound. A list past the bound is the refusal a chain's encode gave.
#[cfg(feature = "alloc")]
pub fn held<E, const MAX: usize>(list: Vec<E>) -> Result<Bounded<Vec<E>, MAX>, CodecError> {
    Bounded::new(list).ok_or(CodecError::TlvChainOverflow)
}

/// The list of the one entry `entry`, which every declared bound holds.
#[cfg(feature = "alloc")]
pub fn one_entry<E, const MAX: usize>(entry: E) -> Bounded<Vec<E>, MAX> {
    const { assert!(MAX >= 1, "a list of one entry needs a bound of one or more") };
    match Bounded::new(alloc::vec![entry]) {
        Some(list) => list,
        None => unreachable!("the bound is checked when this is compiled"),
    }
}

/// Run `edit` on the chain as the growable list it is, and hold what it leaves.
///
/// `edit` may leave the chain past its bound, which only an edit that adds an entry to a chain
/// already at its bound can. The message cannot be sent then, as its encode refused it before the
/// list was a type: the error is that refusal, and the chain is gone from the message, whose
/// caller drops it. Nothing is cloned to keep it, since this runs on a relay's path.
#[cfg(feature = "alloc")]
pub fn edit_chain<E, const MAX: usize, R>(
    chain: &mut Option<Bounded<Vec<E>, MAX>>,
    edit: impl FnOnce(&mut Option<Vec<E>>) -> R,
) -> Result<R, CodecError> {
    let mut list = chain.take().map(Bounded::into_inner);
    let answer = edit(&mut list);
    *chain = list.map(held).transpose()?;
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

    /// The refusal the encode gave before the list was a type: the message cannot be sent.
    #[test]
    fn an_edit_past_the_bound_is_refused_and_the_chain_is_gone() {
        let mut chain: Option<Bounded<Vec<u8>, 1>> = Some(one_entry(1));
        assert_eq!(
            edit_chain(&mut chain, |list| {
                list.get_or_insert_with(Vec::new).push(2);
            }),
            Err(CodecError::TlvChainOverflow)
        );
        assert_eq!(chain.entries(), None);
    }

    #[test]
    fn a_list_past_its_bound_is_not_held() {
        assert!(held::<u8, 1>(alloc::vec![1, 2]).is_err());
        assert_eq!(
            Some(held::<u8, 2>(alloc::vec![1, 2]).expect("within")).entries(),
            Some(&[1, 2][..])
        );
    }
}
