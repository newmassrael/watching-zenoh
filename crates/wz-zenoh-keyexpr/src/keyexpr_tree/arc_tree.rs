//
// Copyright (c) 2023 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh-keyexpr 1.10.2, file
// src/keyexpr_tree/arc_tree.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.2).

//! A KeTree whose nodes are shared: the tree and each node are held by `Arc`, and what the tree
//! contains is read and written only through a token.
//!
//! A [`TokenCell`](token_cell::prelude::TokenCell) holds a value that can be reached from any number of `Arc`s, and gives it out
//! only to whoever holds the token it was built with: a shared reference to the token reads, an
//! exclusive one writes, so the borrow rules of the token are the borrow rules of the whole tree.
//! The entry points of [`ITokenKeyExprTree`] take the token, check it against the tree (a wrong
//! token panics), and the nodes they return carry the token reference with them.
//!
//! Walking the tree down from a checked root does not check the token again at every node, since
//! every node of a tree is built with the token of the tree; where the code relies on that it says
//! so. The one thing the type system cannot hold is a mutable iterator that hands out nodes while
//! it walks below them: callers must not reshape the children of a node an iterator has yielded
//! while that iterator is alive, as with the other mutable iterators of this module.

use alloc::{
    string::String,
    sync::{Arc, Weak},
};
use core::fmt::Debug;

use token_cell::prelude::*;

use super::{box_tree::PruneResult, support::IterOrOption};
use crate::{
    keyexpr,
    keyexpr_tree::{support::IWildness, *},
};

/// The state of a [`KeArcTree`] that its token guards: the first level of nodes, and the wildness.
pub struct KeArcTreeInner<
    Weight,
    Wildness: IWildness,
    Children: IChildrenProvider<
        Arc<TokenCell<KeArcTreeNode<Weight, Weak<()>, Wildness, Children, Token>, Token>>,
    >,
    Token: TokenTrait,
> {
    children: Children::Assoc,
    wildness: Wildness,
}

impl<Weight, Wildness, Children, Token> core::fmt::Debug
    for KeArcTreeInner<Weight, Wildness, Children, Token>
where
    Wildness: IWildness,
    Children: IChildrenProvider<
        Arc<TokenCell<KeArcTreeNode<Weight, Weak<()>, Wildness, Children, Token>, Token>>,
    >,
    Token: TokenTrait,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeArcTreeInner")
            .field("children", &"..")
            .field("is_wild", &self.wildness.get())
            .finish()
    }
}

token_cell::token!(pub DefaultToken);

fn ketree_borrow<'a, T, Token: TokenTrait>(
    cell: &'a TokenCell<T, Token>,
    token: &'a Token,
) -> &'a T {
    cell.try_borrow(token)
        .unwrap_or_else(|_| panic!("Attempted to use KeArcTree with the wrong Token"))
}

fn ketree_borrow_mut<'a, T, Token: TokenTrait>(
    cell: &'a TokenCell<T, Token>,
    token: &'a mut Token,
) -> &'a mut T {
    cell.try_borrow_mut(token)
        .unwrap_or_else(|_| panic!("Attempted to mutably use KeArcTree with the wrong Token"))
}

/// A shared KeTree.
///
/// The tree and its nodes have shared ownership, while their mutability is managed through the `Token`.
///
/// Most of its methods are declared in the [`ITokenKeyExprTree`] trait.
pub struct KeArcTree<
    Weight,
    Token: TokenTrait = DefaultToken,
    Wildness: IWildness = bool,
    Children: IChildrenProvider<
        Arc<TokenCell<KeArcTreeNode<Weight, Weak<()>, Wildness, Children, Token>, Token>>,
    > = DefaultChildrenProvider,
> {
    inner: TokenCell<KeArcTreeInner<Weight, Wildness, Children, Token>, Token>,
}

impl<Weight, Token, Wildness, Children> core::fmt::Debug
    for KeArcTree<Weight, Token, Wildness, Children>
where
    Token: TokenTrait,
    Wildness: IWildness,
    Children: IChildrenProvider<
        Arc<TokenCell<KeArcTreeNode<Weight, Weak<()>, Wildness, Children, Token>, Token>>,
    >,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("KeArcTree").field(&"..").finish()
    }
}

impl<
        Weight,
        Wildness: IWildness,
        Children: IChildrenProvider<
            Arc<
                TokenCell<
                    KeArcTreeNode<Weight, Weak<()>, Wildness, Children, DefaultToken>,
                    DefaultToken,
                >,
            >,
        >,
    > KeArcTree<Weight, DefaultToken, Wildness, Children>
{
    /// Constructs the KeArcTree, returning it and its token, unless constructing the Token failed.
    ///
    /// # Type inference papercut
    /// Despite some of `KeArcTree`'s generic parameters having default values, those are only taken into
    /// account by the compiler when a type is named with some parameters omitted, and not when a type is
    /// inferred with the same parameters unconstrained.
    ///
    /// The simplest way to resolve this is to eventually assign to tree part of the return value
    /// to a variable or field whose type is named `KeArcTree<_>` (the `Weight` parameter can generally be inferred).
    pub fn new() -> Result<(Self, DefaultToken), <DefaultToken as TokenTrait>::ConstructionError> {
        let token = DefaultToken::new()?;
        Ok((Self::with_token(&token), token))
    }
}

impl<
        Weight,
        Wildness: IWildness,
        Children: IChildrenProvider<
            Arc<TokenCell<KeArcTreeNode<Weight, Weak<()>, Wildness, Children, Token>, Token>>,
        >,
        Token: TokenTrait,
    > KeArcTree<Weight, Token, Wildness, Children>
{
    /// Constructs the KeArcTree with a specific token.
    pub fn with_token(token: &Token) -> Self {
        Self {
            inner: TokenCell::new(
                KeArcTreeInner {
                    children: Default::default(),
                    wildness: Wildness::non_wild(),
                },
                token,
            ),
        }
    }

    /// Checks `token` against the tree and reads the tree's state for as long as the tree is
    /// borrowed, which is longer than the borrow of `token` that proves the right to read.
    ///
    /// # Safety
    /// The caller keeps `token`, shared or exclusive, borrowed for the whole of `'a`, as the
    /// entry points of [`ITokenKeyExprTree`] do by returning it with what they return: while it
    /// is, nothing else can reach the cells of this tree through another reference to the token.
    unsafe fn checked_inner<'a>(
        &'a self,
        token: &Token,
    ) -> &'a KeArcTreeInner<Weight, Wildness, Children, Token> {
        let _ = ketree_borrow(&self.inner, token);
        // SAFETY: the token was checked, and the caller's borrow of it covers `'a`.
        unsafe { &*self.inner.get() }
    }
}

#[allow(clippy::type_complexity)]
impl<
        'a,
        Weight: 'a,
        Wildness: IWildness + 'a,
        Children: IChildrenProvider<
                Arc<TokenCell<KeArcTreeNode<Weight, Weak<()>, Wildness, Children, Token>, Token>>,
            > + 'a,
        Token: TokenTrait + 'a,
    > ITokenKeyExprTree<'a, Weight, Token> for KeArcTree<Weight, Token, Wildness, Children>
where
    Children::Assoc: IChildren<
        Arc<TokenCell<KeArcTreeNode<Weight, Weak<()>, Wildness, Children, Token>, Token>>,
    >,
{
    type Node = (
        &'a Arc<TokenCell<KeArcTreeNode<Weight, Weak<()>, Wildness, Children, Token>, Token>>,
        &'a Token,
    );
    type NodeMut = (
        &'a Arc<TokenCell<KeArcTreeNode<Weight, Weak<()>, Wildness, Children, Token>, Token>>,
        &'a mut Token,
    );

    fn node(&'a self, token: &'a Token, at: &keyexpr) -> Option<Self::Node> {
        let inner = ketree_borrow(&self.inner, token);
        let mut chunks = at.chunks_impl();
        let mut node = inner.children.child_at(chunks.next()?)?.as_node();
        for chunk in chunks {
            node = ketree_borrow(node, token)
                .children
                .child_at(chunk)?
                .as_node();
        }
        Some((node, token))
    }

    fn node_mut(&'a self, token: &'a mut Token, at: &keyexpr) -> Option<Self::NodeMut> {
        // SAFETY: `token` is returned with the node, so it stays borrowed for `'a`.
        let inner = unsafe { self.checked_inner(token) };
        let mut chunks = at.chunks_impl();
        let mut node = inner.children.child_at(chunks.next()?)?.as_node();
        for chunk in chunks {
            // SAFETY: the tree's token is held, and every node of the tree is built with it.
            node = unsafe { &*node.get() }.children.child_at(chunk)?.as_node();
        }
        Some((node, token))
    }

    fn node_or_create(&'a self, token: &'a mut Token, at: &keyexpr) -> Self::NodeMut {
        let checked = ketree_borrow_mut(&self.inner, token);
        if at.is_wild_impl() {
            checked.wildness.set(true);
        }
        let inner: *mut KeArcTreeInner<Weight, Wildness, Children, Token> = checked;
        // SAFETY: the pointer is into `self`, which is borrowed for `'a`; the exclusive token is
        // returned with the node and so held for `'a`, and the borrow of it above has ended.
        let inner = unsafe { &mut *inner };
        let shared: &Token = &*token;
        let construct_node = |k: &keyexpr, parent| {
            Arc::new(TokenCell::new(
                KeArcTreeNode {
                    parent,
                    chunk: k.into(),
                    children: Default::default(),
                    weight: None,
                },
                shared,
            ))
        };
        let mut chunks = at.chunks_impl();
        let mut node = inner
            .children
            .entry(chunks.next().expect("a key expression has a chunk"))
            .get_or_insert_with(|k| construct_node(k, None));
        for chunk in chunks {
            let as_node: &Arc<
                TokenCell<KeArcTreeNode<Weight, Weak<()>, Wildness, Children, Token>, Token>,
            > = node.as_node();
            // SAFETY: the exclusive token is held, so nothing else reads or writes the node.
            node = unsafe { &mut *as_node.get() }
                .children
                .entry(chunk)
                .get_or_insert_with(|k| construct_node(k, Some(Arc::downgrade(as_node))));
        }
        (&*node, token)
    }

    type TreeIterItem = Self::Node;
    type TreeIter = TokenPacker<
        TreeIter<
            'a,
            Children,
            Arc<TokenCell<KeArcTreeNode<Weight, Weak<()>, Wildness, Children, Token>, Token>>,
            Weight,
        >,
        &'a Token,
    >;
    fn tree_iter(&'a self, token: &'a Token) -> Self::TreeIter {
        let inner = ketree_borrow(&self.inner, token);
        TokenPacker {
            iter: TreeIter::new(&inner.children),
            token,
        }
    }

    type TreeIterItemMut = Tokenized<
        &'a Arc<TokenCell<KeArcTreeNode<Weight, Weak<()>, Wildness, Children, Token>, Token>>,
        &'a mut Token,
    >;
    type TreeIterMut = TokenPacker<
        TreeIter<
            'a,
            Children,
            Arc<TokenCell<KeArcTreeNode<Weight, Weak<()>, Wildness, Children, Token>, Token>>,
            Weight,
        >,
        &'a mut Token,
    >;
    fn tree_iter_mut(&'a self, token: &'a mut Token) -> Self::TreeIterMut {
        // SAFETY: `token` is moved into the iterator, which keeps it for `'a`.
        let inner = unsafe { self.checked_inner(token) };
        TokenPacker {
            iter: TreeIter::new(&inner.children),
            token,
        }
    }

    type IntersectionItem = Self::Node;
    type Intersection = IterOrOption<
        TokenPacker<
            Intersection<
                'a,
                Children,
                Arc<TokenCell<KeArcTreeNode<Weight, Weak<()>, Wildness, Children, Token>, Token>>,
                Weight,
            >,
            &'a Token,
        >,
        Self::IntersectionItem,
    >;
    fn intersecting_nodes(&'a self, token: &'a Token, key: &'a keyexpr) -> Self::Intersection {
        let inner = ketree_borrow(&self.inner, token);
        if inner.wildness.get() || key.is_wild_impl() {
            IterOrOption::Iter(TokenPacker {
                iter: Intersection::new(&inner.children, key),
                token,
            })
        } else {
            IterOrOption::Opt(self.node(token, key))
        }
    }
    type IntersectionItemMut = Self::TreeIterItemMut;
    type IntersectionMut = IterOrOption<
        TokenPacker<
            Intersection<
                'a,
                Children,
                Arc<TokenCell<KeArcTreeNode<Weight, Weak<()>, Wildness, Children, Token>, Token>>,
                Weight,
            >,
            &'a mut Token,
        >,
        Self::IntersectionItemMut,
    >;
    fn intersecting_nodes_mut(
        &'a self,
        token: &'a mut Token,
        key: &'a keyexpr,
    ) -> Self::IntersectionMut {
        // SAFETY: `token` is moved into what is returned, which keeps it for `'a`.
        let inner = unsafe { self.checked_inner(token) };
        if inner.wildness.get() || key.is_wild_impl() {
            IterOrOption::Iter(TokenPacker {
                iter: Intersection::new(&inner.children, key),
                token,
            })
        } else {
            IterOrOption::Opt(self.node_mut(token, key).map(Into::into))
        }
    }

    type InclusionItem = Self::Node;
    type Inclusion = IterOrOption<
        TokenPacker<
            Inclusion<
                'a,
                Children,
                Arc<TokenCell<KeArcTreeNode<Weight, Weak<()>, Wildness, Children, Token>, Token>>,
                Weight,
            >,
            &'a Token,
        >,
        Self::InclusionItem,
    >;
    fn included_nodes(&'a self, token: &'a Token, key: &'a keyexpr) -> Self::Inclusion {
        let inner = ketree_borrow(&self.inner, token);
        if inner.wildness.get() || key.is_wild_impl() {
            IterOrOption::Iter(TokenPacker {
                iter: Inclusion::new(&inner.children, key),
                token,
            })
        } else {
            IterOrOption::Opt(self.node(token, key))
        }
    }
    type InclusionItemMut = Self::TreeIterItemMut;
    type InclusionMut = IterOrOption<
        TokenPacker<
            Inclusion<
                'a,
                Children,
                Arc<TokenCell<KeArcTreeNode<Weight, Weak<()>, Wildness, Children, Token>, Token>>,
                Weight,
            >,
            &'a mut Token,
        >,
        Self::InclusionItemMut,
    >;
    fn included_nodes_mut(&'a self, token: &'a mut Token, key: &'a keyexpr) -> Self::InclusionMut {
        // SAFETY: `token` is moved into what is returned, which keeps it for `'a`.
        let inner = unsafe { self.checked_inner(token) };
        if inner.wildness.get() || key.is_wild_impl() {
            IterOrOption::Iter(TokenPacker {
                iter: Inclusion::new(&inner.children, key),
                token,
            })
        } else {
            IterOrOption::Opt(self.node_mut(token, key).map(Into::into))
        }
    }

    type IncluderItem = Self::Node;
    type Includer = IterOrOption<
        TokenPacker<
            Includer<
                'a,
                Children,
                Arc<TokenCell<KeArcTreeNode<Weight, Weak<()>, Wildness, Children, Token>, Token>>,
                Weight,
            >,
            &'a Token,
        >,
        Self::IncluderItem,
    >;
    fn nodes_including(&'a self, token: &'a Token, key: &'a keyexpr) -> Self::Includer {
        let inner = ketree_borrow(&self.inner, token);
        if inner.wildness.get() || key.is_wild_impl() {
            IterOrOption::Iter(TokenPacker {
                iter: Includer::new(&inner.children, key),
                token,
            })
        } else {
            IterOrOption::Opt(self.node(token, key))
        }
    }
    type IncluderItemMut = Self::TreeIterItemMut;
    type IncluderMut = IterOrOption<
        TokenPacker<
            Includer<
                'a,
                Children,
                Arc<TokenCell<KeArcTreeNode<Weight, Weak<()>, Wildness, Children, Token>, Token>>,
                Weight,
            >,
            &'a mut Token,
        >,
        Self::IncluderItemMut,
    >;
    fn nodes_including_mut(&'a self, token: &'a mut Token, key: &'a keyexpr) -> Self::IncluderMut {
        // SAFETY: `token` is moved into what is returned, which keeps it for `'a`.
        let inner = unsafe { self.checked_inner(token) };
        if inner.wildness.get() || key.is_wild_impl() {
            IterOrOption::Iter(TokenPacker {
                iter: Includer::new(&inner.children, key),
                token,
            })
        } else {
            IterOrOption::Opt(self.node_mut(token, key).map(Into::into))
        }
    }
    type PruneNode = KeArcTreeNode<Weight, Weak<()>, Wildness, Children, Token>;

    fn prune_where<F: FnMut(&mut Self::PruneNode) -> bool>(
        &self,
        token: &mut Token,
        mut predicate: F,
    ) {
        let mut wild = false;
        let inner = ketree_borrow_mut(&self.inner, token);
        inner.children.filter_out(&mut |child| {
            // SAFETY: the exclusive token is held for the whole pruning.
            let node = unsafe { &mut *child.get() };
            match node.prune(&mut predicate) {
                PruneResult::Delete => KeArcTreeNode::dropped(child, &mut wild),
                PruneResult::NonWild => false,
                PruneResult::Wild => {
                    wild = true;
                    false
                }
            }
        });
        inner.wildness.set(wild);
    }
}

pub(crate) mod sealed {
    use alloc::sync::Arc;
    use core::ops::{Deref, DerefMut};

    use token_cell::prelude::{TokenCell, TokenCellTrait, TokenTrait};

    /// A node, or the cell of one, with the token that allows reading it (or, if the token is
    /// mutable, writing it).
    pub struct Tokenized<A, B>(pub A, pub(crate) B);

    impl<A, B> core::fmt::Debug for Tokenized<A, B> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_tuple("Tokenized").field(&"..").finish()
        }
    }

    /// The panic of an access through a token that does not belong to the cell.
    fn wrong_token<E, R>(_: E) -> R {
        panic!("Used wrong token to access TokenCell")
    }

    /// `Deref` and `DerefMut` of a cell, or an `Arc` of one, paired with a token: the token is
    /// checked against the cell at each use, so a pair built by hand from a cell and a token that
    /// are not of the same tree panics instead of reading what it must not.
    macro_rules! deref_through_token {
        ($($cell:ty),+) => {$(
            impl<T, Token: TokenTrait> Deref for Tokenized<&$cell, &Token> {
                type Target = T;
                fn deref(&self) -> &Self::Target {
                    self.0.try_borrow(self.1).unwrap_or_else(wrong_token)
                }
            }
            impl<T, Token: TokenTrait> Deref for Tokenized<&$cell, &mut Token> {
                type Target = T;
                fn deref(&self) -> &Self::Target {
                    self.0.try_borrow(&*self.1).unwrap_or_else(wrong_token)
                }
            }
            impl<T, Token: TokenTrait> DerefMut for Tokenized<&$cell, &mut Token> {
                fn deref_mut(&mut self) -> &mut Self::Target {
                    self.0.try_borrow_mut(&mut *self.1).unwrap_or_else(wrong_token)
                }
            }
        )+};
    }

    deref_through_token!(TokenCell<T, Token>, Arc<TokenCell<T, Token>>);

    impl<A, B> From<(A, B)> for Tokenized<A, B> {
        fn from((a, b): (A, B)) -> Self {
            Self(a, b)
        }
    }

    /// An iterator over nodes that pairs each with the token the iteration was started with.
    pub struct TokenPacker<I, T> {
        pub(crate) iter: I,
        pub(crate) token: T,
    }

    impl<I, T> core::fmt::Debug for TokenPacker<I, T> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("TokenPacker").finish_non_exhaustive()
        }
    }

    impl<'a, I: Iterator, T> Iterator for TokenPacker<I, &'a T> {
        type Item = (I::Item, &'a T);
        fn next(&mut self) -> Option<Self::Item> {
            self.iter.next().map(|i| (i, self.token))
        }
    }

    impl<'a, I: Iterator, T> Iterator for TokenPacker<I, &'a mut T> {
        type Item = Tokenized<I::Item, &'a mut T>;
        fn next(&mut self) -> Option<Self::Item> {
            self.iter.next().map(|i| {
                // SAFETY: this lets several `&mut T` to the token exist, one in each item yielded
                // so far. `Tokenized` keeps its token in a crate-private field, and its only uses
                // of it are the checked accesses to a single cell, one at a time per item, so the
                // copies are never used to reach one value twice; the iterator is the lender and
                // an item the borrower of that one token.
                Tokenized(i, unsafe { core::ptr::read(&self.token) })
            })
        }
    }
}
pub use sealed::{TokenPacker, Tokenized};

/// Selects the pointer type that holds a node's parent: an owning `Arc` or a non-owning `Weak`.
pub trait IArcProvider {
    type Ptr<T>: IArc<T>;
}

/// A pointer to a shared value that can be made weak and, if it is, upgraded back.
pub trait IArc<T> {
    fn weak(&self) -> Weak<T>;
    type UpgradeErr: Debug;
    fn upgrade(&self) -> Result<Arc<T>, Self::UpgradeErr>;
}
impl IArcProvider for Arc<()> {
    type Ptr<T> = Arc<T>;
}
impl IArcProvider for Weak<()> {
    type Ptr<T> = Weak<T>;
}
impl<T> IArc<T> for Arc<T> {
    fn weak(&self) -> Weak<T> {
        Arc::downgrade(self)
    }
    type UpgradeErr = core::convert::Infallible;
    fn upgrade(&self) -> Result<Arc<T>, core::convert::Infallible> {
        Ok(self.clone())
    }
}

/// The error of upgrading a weak pointer whose value is gone.
#[derive(Debug, Clone, Copy)]
pub struct WeakConvertError;
impl<T> IArc<T> for Weak<T> {
    fn weak(&self) -> Weak<T> {
        self.clone()
    }
    type UpgradeErr = WeakConvertError;
    fn upgrade(&self) -> Result<Arc<T>, WeakConvertError> {
        Weak::upgrade(self).ok_or(WeakConvertError)
    }
}

/// A node of a [`KeArcTree`]: its chunk, its weight if it has one, its children, and a pointer to
/// its parent, weak when the node is held by the tree.
#[allow(clippy::type_complexity)]
pub struct KeArcTreeNode<
    Weight,
    Parent: IArcProvider,
    Wildness: IWildness,
    Children: IChildrenProvider<
        Arc<TokenCell<KeArcTreeNode<Weight, Weak<()>, Wildness, Children, Token>, Token>>,
    >,
    Token: TokenTrait,
> {
    parent: Option<
        Parent::Ptr<TokenCell<KeArcTreeNode<Weight, Weak<()>, Wildness, Children, Token>, Token>>,
    >,
    chunk: OwnedKeyExpr,
    children: Children::Assoc,
    weight: Option<Weight>,
}

impl<Weight, Parent, Wildness, Children, Token> core::fmt::Debug
    for KeArcTreeNode<Weight, Parent, Wildness, Children, Token>
where
    Weight: Debug,
    Parent: IArcProvider,
    Wildness: IWildness,
    Children: IChildrenProvider<
        Arc<TokenCell<KeArcTreeNode<Weight, Weak<()>, Wildness, Children, Token>, Token>>,
    >,
    Token: TokenTrait,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeArcTreeNode")
            .field("has_parent", &self.parent.is_some())
            .field("chunk", &self.chunk)
            .field("children", &"..")
            .field("weight", &self.weight)
            .finish()
    }
}

impl<
        Weight,
        Wildness: IWildness,
        Children: IChildrenProvider<
            Arc<TokenCell<KeArcTreeNode<Weight, Weak<()>, Wildness, Children, Token>, Token>>,
        >,
        Token: TokenTrait,
    > KeArcTreeNode<Weight, Weak<()>, Wildness, Children, Token>
where
    Children::Assoc: IChildren<
        Arc<TokenCell<KeArcTreeNode<Weight, Weak<()>, Wildness, Children, Token>, Token>>,
    >,
{
    /// Prunes the subtree under this node, and says what is left of it.
    fn prune<F: FnMut(&mut Self) -> bool>(&mut self, predicate: &mut F) -> PruneResult {
        let mut result = PruneResult::NonWild;
        let mut wild = false;
        self.children.filter_out(&mut |child| {
            // SAFETY: the exclusive token is held for the whole pruning.
            let c = unsafe { &mut *child.get() };
            match c.prune(predicate) {
                PruneResult::Delete => Self::dropped(child, &mut wild),
                PruneResult::NonWild => false,
                PruneResult::Wild => {
                    wild = true;
                    false
                }
            }
        });
        if wild {
            result = PruneResult::Wild;
        }
        if predicate(self) && self.children.is_empty() {
            result = PruneResult::Delete
        } else if self.chunk.is_wild_impl() {
            result = PruneResult::Wild
        }
        result
    }

    /// Whether a child that pruning chose to delete leaves the tree. A node that something else
    /// holds an `Arc` of stays, and a wild one that stays must still count as wild, or a tree
    /// would answer a query with no wildcard from a lookup and miss it. The node has no children
    /// left, since pruning chose it, so its own chunk is all its wildness.
    fn dropped(child: &Arc<TokenCell<Self, Token>>, wild: &mut bool) -> bool {
        if Arc::strong_count(child) <= 1 {
            return true;
        }
        // SAFETY: the exclusive token is held for the whole pruning.
        if unsafe { &*child.get() }.chunk.is_wild_impl() {
            *wild = true;
        }
        false
    }
}

impl<
        Weight,
        Parent: IArcProvider,
        Wildness: IWildness,
        Children: IChildrenProvider<
            Arc<TokenCell<KeArcTreeNode<Weight, Weak<()>, Wildness, Children, Token>, Token>>,
        >,
        Token: TokenTrait,
    > UIKeyExprTreeNode<Weight>
    for Arc<TokenCell<KeArcTreeNode<Weight, Parent, Wildness, Children, Token>, Token>>
where
    Children::Assoc: IChildren<
        Arc<TokenCell<KeArcTreeNode<Weight, Weak<()>, Wildness, Children, Token>, Token>>,
    >,
{
    type Parent = <KeArcTreeNode<Weight, Parent, Wildness, Children, Token> as UIKeyExprTreeNode<
        Weight,
    >>::Parent;
    /// # Safety
    /// The caller holds the token the node's tree was built with, shared or exclusive.
    unsafe fn __parent(&self) -> Option<&Self::Parent> {
        // SAFETY: the token is held, as the caller guarantees.
        unsafe { (*self.get()).parent() }
    }

    /// # Safety
    /// The caller holds the token the node's tree was built with, shared or exclusive.
    unsafe fn __keyexpr(&self) -> OwnedKeyExpr {
        // SAFETY: the token is held, as the caller guarantees.
        unsafe { (*self.get()).keyexpr() }
    }

    /// # Safety
    /// The caller holds the token the node's tree was built with, shared or exclusive.
    unsafe fn __weight(&self) -> Option<&Weight> {
        // SAFETY: the token is held, as the caller guarantees.
        unsafe { (*self.get()).weight() }
    }

    type Child = <KeArcTreeNode<Weight, Parent, Wildness, Children, Token> as UIKeyExprTreeNode<
        Weight,
    >>::Child;

    type Children = <KeArcTreeNode<Weight, Parent, Wildness, Children, Token> as UIKeyExprTreeNode<
        Weight,
    >>::Children;

    /// # Safety
    /// The caller holds the token the node's tree was built with, shared or exclusive.
    unsafe fn __children(&self) -> &Self::Children {
        // SAFETY: the token is held, as the caller guarantees.
        unsafe { (*self.get()).children() }
    }
}

impl<
        Weight,
        Parent: IArcProvider,
        Wildness: IWildness,
        Children: IChildrenProvider<
            Arc<TokenCell<KeArcTreeNode<Weight, Weak<()>, Wildness, Children, Token>, Token>>,
        >,
        Token: TokenTrait,
    > HasChunk for KeArcTreeNode<Weight, Parent, Wildness, Children, Token>
{
    fn chunk(&self) -> &keyexpr {
        &self.chunk
    }
}

impl<
        Weight,
        Parent: IArcProvider,
        Wildness: IWildness,
        Children: IChildrenProvider<
            Arc<TokenCell<KeArcTreeNode<Weight, Weak<()>, Wildness, Children, Token>, Token>>,
        >,
        Token: TokenTrait,
    > IKeyExprTreeNode<Weight> for KeArcTreeNode<Weight, Parent, Wildness, Children, Token>
where
    Children::Assoc: IChildren<
        Arc<TokenCell<KeArcTreeNode<Weight, Weak<()>, Wildness, Children, Token>, Token>>,
    >,
{
}

impl<
        Weight,
        Parent: IArcProvider,
        Wildness: IWildness,
        Children: IChildrenProvider<
            Arc<TokenCell<KeArcTreeNode<Weight, Weak<()>, Wildness, Children, Token>, Token>>,
        >,
        Token: TokenTrait,
    > UIKeyExprTreeNode<Weight> for KeArcTreeNode<Weight, Parent, Wildness, Children, Token>
where
    Children::Assoc: IChildren<
        Arc<TokenCell<KeArcTreeNode<Weight, Weak<()>, Wildness, Children, Token>, Token>>,
    >,
{
    type Parent =
        Parent::Ptr<TokenCell<KeArcTreeNode<Weight, Weak<()>, Wildness, Children, Token>, Token>>;
    /// # Safety
    /// None is needed beyond access to the node itself.
    unsafe fn __parent(&self) -> Option<&Self::Parent> {
        self.parent.as_ref()
    }
    /// May panic if the node has been zombified (see [`Self::is_zombie`])
    ///
    /// # Safety
    /// The caller holds the token the node's tree was built with: the key expression is built from
    /// the node's ancestors, which are read through their cells.
    unsafe fn __keyexpr(&self) -> OwnedKeyExpr {
        // SAFETY: `_keyexpr` joins chunks of key expressions with `/`, which is a key expression.
        unsafe { OwnedKeyExpr::from_string_unchecked(self._keyexpr(0)) }
    }
    /// # Safety
    /// None is needed beyond access to the node itself.
    unsafe fn __weight(&self) -> Option<&Weight> {
        self.weight.as_ref()
    }

    type Child = Arc<TokenCell<KeArcTreeNode<Weight, Weak<()>, Wildness, Children, Token>, Token>>;
    type Children = Children::Assoc;
    /// # Safety
    /// None is needed beyond access to the node itself.
    unsafe fn __children(&self) -> &Self::Children {
        &self.children
    }
}

impl<
        Weight,
        Parent: IArcProvider,
        Wildness: IWildness,
        Children: IChildrenProvider<
            Arc<TokenCell<KeArcTreeNode<Weight, Weak<()>, Wildness, Children, Token>, Token>>,
        >,
        Token: TokenTrait,
    > IKeyExprTreeNodeMut<Weight> for KeArcTreeNode<Weight, Parent, Wildness, Children, Token>
where
    Children::Assoc: IChildren<
        Arc<TokenCell<KeArcTreeNode<Weight, Weak<()>, Wildness, Children, Token>, Token>>,
    >,
{
    fn parent_mut(&mut self) -> Option<&mut Self::Parent> {
        self.parent.as_mut()
    }
    fn weight_mut(&mut self) -> Option<&mut Weight> {
        self.weight.as_mut()
    }
    fn take_weight(&mut self) -> Option<Weight> {
        self.weight.take()
    }
    fn insert_weight(&mut self, weight: Weight) -> Option<Weight> {
        self.weight.replace(weight)
    }
    fn children_mut(&mut self) -> &mut Self::Children {
        &mut self.children
    }
}

impl<
        Weight,
        Wildness: IWildness,
        Children: IChildrenProvider<
            Arc<TokenCell<KeArcTreeNode<Weight, Weak<()>, Wildness, Children, Token>, Token>>,
        >,
        Token: TokenTrait,
    > KeArcTreeNode<Weight, Weak<()>, Wildness, Children, Token>
where
    Children::Assoc: IChildren<
        Arc<TokenCell<KeArcTreeNode<Weight, Weak<()>, Wildness, Children, Token>, Token>>,
    >,
{
    /// Under specific circumstances, a node that's been cloned from a tree might have a destroyed parent.
    /// Such a node is "zombified", and becomes unable to perform certain operations such as navigating its parents,
    /// which may be necessary for operations such as [`IKeyExprTreeNode::keyexpr`].
    ///
    /// To become zombified, a node and its parents must both have been pruned from the tree that constructed them, while at least one of the parents has also been dropped everywhere it was aliased through [`Arc`].
    pub fn is_zombie(&self) -> bool {
        match &self.parent {
            Some(parent) => match parent.upgrade() {
                // SAFETY: the parent is kept alive by `parent`, and the ancestors are only read
                // through their parent pointers, which are written when a node is built.
                Some(parent) => unsafe { &*parent.get() }.is_zombie(),
                None => true,
            },
            None => false,
        }
    }
}

impl<
        Weight,
        Parent: IArcProvider,
        Wildness: IWildness,
        Children: IChildrenProvider<
            Arc<TokenCell<KeArcTreeNode<Weight, Weak<()>, Wildness, Children, Token>, Token>>,
        >,
        Token: TokenTrait,
    > KeArcTreeNode<Weight, Parent, Wildness, Children, Token>
where
    Children::Assoc: IChildren<
        Arc<TokenCell<KeArcTreeNode<Weight, Weak<()>, Wildness, Children, Token>, Token>>,
    >,
{
    /// The key expression of the node, built from the root down with room for `capacity` more.
    fn _keyexpr(&self, capacity: usize) -> String {
        let mut s = match self.parent() {
            Some(parent) => {
                // The parent is held for as long as it is read: the tree may be dropped by another
                // holder meanwhile, and this is then the only thing keeping the parent alive.
                let parent = parent.upgrade().expect(
                    "Attempted to use a zombie KeArcTreeNode (see KeArcTreeNode::is_zombie())",
                );
                // SAFETY: a parent's chunk and parent pointer are written when it is built.
                let parent = unsafe { &*parent.get() };
                parent._keyexpr(capacity + self.chunk.len() + 1) + "/"
            }
            None => String::with_capacity(capacity + self.chunk.len()),
        };
        s.push_str(self.chunk.as_str());
        s
    }
}
