//
// Copyright (c) the contributors of Eclipse zenoh (see the NOTICE of eclipse-zenoh/zenoh)
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh-keyexpr 1.10.1, file
// src/keyexpr_tree/support.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.1), which carries
// no notice of its own; the declared license of that crate, EPL-2.0 OR Apache-2.0, applies.

//! Small pieces the trees share: the wildness a tree records, and an iterator that is either an
//! iterator or a single item.

use alloc::boxed::Box;
use core::ops::{Deref, DerefMut};

/// Allows specializing KeTrees based on their eventual storage of wild KEs.
///
/// This is useful to allow KeTrees to be much faster at iterating when the queried KE is non-wild,
/// and the KeTree is informed by its wildness that it doesn't contain any wilds.
pub trait IWildness: 'static {
    /// The wildness of a tree that holds no wild key expression.
    fn non_wild() -> Self;
    /// Whether the tree may hold a wild key expression.
    fn get(&self) -> bool;
    /// Record the wildness; returns the previous one.
    fn set(&mut self, wildness: bool) -> bool;
}

/// Disallows the KeTree from storing _any_ wild KE.
///
/// Attempting to store a wild KE on a `KeTree<NonWild>` will cause a panic.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NonWild;

impl IWildness for NonWild {
    fn non_wild() -> Self {
        NonWild
    }
    fn get(&self) -> bool {
        false
    }
    fn set(&mut self, wildness: bool) -> bool {
        if wildness {
            panic!("Attempted to set NonWild to wild, which breaks its contract. You likely attempted to insert a wild key into a `NonWild` tree. Use `bool` instead to make wildness determined at runtime.")
        }
        false
    }
}

/// A ZST that forces the KeTree to always believe it contains wild KEs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnknownWildness;

impl IWildness for UnknownWildness {
    fn non_wild() -> Self {
        UnknownWildness
    }
    fn get(&self) -> bool {
        true
    }
    fn set(&mut self, _wildness: bool) -> bool {
        true
    }
}

/// Stores the wildness of the KeTree at runtime, allowing it to select its
/// iteration algorithms based on the wildness at the moment of query.
impl IWildness for bool {
    fn non_wild() -> Self {
        false
    }
    fn get(&self) -> bool {
        *self
    }
    fn set(&mut self, wildness: bool) -> bool {
        core::mem::replace(self, wildness)
    }
}

/// Either one item, or an iterator of them.
pub enum IterOrOption<Iter: Iterator, Item> {
    Opt(Option<Item>),
    Iter(Iter),
}

impl<Iter: Iterator, Item> core::fmt::Debug for IterOrOption<Iter, Item> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Opt(_) => f.debug_tuple("Opt").field(&"..").finish(),
            Self::Iter(_) => f.debug_tuple("Iter").field(&"..").finish(),
        }
    }
}

impl<Iter: Iterator, Item> Iterator for IterOrOption<Iter, Item>
where
    Iter::Item: Coerce<Item>,
{
    type Item = Item;
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            IterOrOption::Opt(v) => v.take(),
            IterOrOption::Iter(it) => it.next().map(Coerce::coerce),
        }
    }
}

/// A conversion between the item types the two arms of [`IterOrOption`] yield: the identity, and
/// a boxed node to the node.
trait Coerce<Into> {
    fn coerce(self) -> Into;
}

impl<T> Coerce<T> for T {
    fn coerce(self) -> T {
        self
    }
}

impl<'a, T> Coerce<&'a T> for &'a Box<T> {
    fn coerce(self) -> &'a T {
        self.deref()
    }
}

impl<'a, T> Coerce<&'a mut T> for &'a mut Box<T> {
    fn coerce(self) -> &'a mut T {
        self.deref_mut()
    }
}

impl<Iter: Iterator, Item> From<Iter> for IterOrOption<Iter, Item> {
    fn from(it: Iter) -> Self {
        Self::Iter(it)
    }
}
