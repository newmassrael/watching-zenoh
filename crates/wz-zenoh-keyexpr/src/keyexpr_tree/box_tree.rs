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
// Modified by newmassrael in 2026 for watching-zenoh. Derived from zenoh-keyexpr 1.10.1, file
// src/keyexpr_tree/box_tree.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.1).

//! A KeTree that owns all of its nodes.

use alloc::{boxed::Box, string::String};
use core::ptr::NonNull;

use super::support::IterOrOption;
use crate::{
    keyexpr,
    keyexpr_tree::{support::IWildness, *},
};

/// A KeTree that uniquely owns all of its nodes, like a `HashMap` owns its entries.
///
/// `Wildness` records whether the tree may hold a wild key expression, which lets queries with no
/// wildcard be answered by a lookup; `Children` is how each node stores its children.
pub struct KeBoxTree<
    Weight,
    Wildness: IWildness = bool,
    Children: IChildrenProvider<Box<KeyExprTreeNode<Weight, Wildness, Children>>> = DefaultChildrenProvider,
> {
    children: Children::Assoc,
    wildness: Wildness,
}

impl<Weight, Wildness, Children> core::fmt::Debug for KeBoxTree<Weight, Wildness, Children>
where
    Wildness: IWildness,
    Children: IChildrenProvider<Box<KeyExprTreeNode<Weight, Wildness, Children>>>,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeBoxTree")
            .field("children", &"..")
            .field("is_wild", &self.wildness.get())
            .finish()
    }
}

impl<Weight> KeBoxTree<Weight, bool, DefaultChildrenProvider>
where
    DefaultChildrenProvider:
        IChildrenProvider<Box<KeyExprTreeNode<Weight, bool, DefaultChildrenProvider>>>,
{
    /// An empty tree, with the default storage of children and a wildness known at run time.
    pub fn new() -> Self {
        Default::default()
    }
}

impl<
        Weight,
        Children: IChildrenProvider<Box<KeyExprTreeNode<Weight, Wildness, Children>>>,
        Wildness: IWildness,
    > Default for KeBoxTree<Weight, Wildness, Children>
{
    fn default() -> Self {
        KeBoxTree {
            children: Default::default(),
            wildness: Wildness::non_wild(),
        }
    }
}

impl<
        'a,
        Weight,
        Children: IChildrenProvider<Box<KeyExprTreeNode<Weight, Wildness, Children>>>,
        Wildness: IWildness,
    > IKeyExprTree<'a, Weight> for KeBoxTree<Weight, Wildness, Children>
where
    Weight: 'a,
    Children: 'a,
    Children::Assoc: IChildren<
            Box<KeyExprTreeNode<Weight, Wildness, Children>>,
            Node = Box<KeyExprTreeNode<Weight, Wildness, Children>>,
        > + 'a,
{
    type Node = KeyExprTreeNode<Weight, Wildness, Children>;

    fn node(&'a self, at: &keyexpr) -> Option<&'a Self::Node> {
        let mut chunks = at.chunks_impl();
        let mut node = self.children.child_at(chunks.next()?)?;
        for chunk in chunks {
            node = node.as_node().children.child_at(chunk)?;
        }
        Some(node.as_node())
    }

    type TreeIterItem = <Self::TreeIter as Iterator>::Item;
    type TreeIter =
        TreeIter<'a, Children, Box<KeyExprTreeNode<Weight, Wildness, Children>>, Weight>;

    fn tree_iter(&'a self) -> Self::TreeIter {
        TreeIter::new(&self.children)
    }

    type IntersectionItem = <Self::Intersection as Iterator>::Item;
    type Intersection = IterOrOption<
        Intersection<'a, Children, Box<KeyExprTreeNode<Weight, Wildness, Children>>, Weight>,
        &'a Self::Node,
    >;

    fn intersecting_nodes(&'a self, ke: &'a keyexpr) -> Self::Intersection {
        if self.wildness.get() || ke.is_wild_impl() {
            Intersection::new(&self.children, ke).into()
        } else {
            let node = self.node(ke);
            IterOrOption::Opt(node)
        }
    }

    type InclusionItem = <Self::Inclusion as Iterator>::Item;
    type Inclusion = IterOrOption<
        Inclusion<'a, Children, Box<KeyExprTreeNode<Weight, Wildness, Children>>, Weight>,
        &'a Self::Node,
    >;

    fn included_nodes(&'a self, ke: &'a keyexpr) -> Self::Inclusion {
        if self.wildness.get() || ke.is_wild_impl() {
            Inclusion::new(&self.children, ke).into()
        } else {
            let node = self.node(ke);
            IterOrOption::Opt(node)
        }
    }

    type IncluderItem = <Self::Includer as Iterator>::Item;
    type Includer = IterOrOption<
        Includer<'a, Children, Box<KeyExprTreeNode<Weight, Wildness, Children>>, Weight>,
        &'a Self::Node,
    >;

    fn nodes_including(&'a self, ke: &'a keyexpr) -> Self::Includer {
        if self.wildness.get() || ke.is_wild_impl() {
            Includer::new(&self.children, ke).into()
        } else {
            let node = self.node(ke);
            IterOrOption::Opt(node)
        }
    }
}

impl<
        'a,
        Weight,
        Children: IChildrenProvider<Box<KeyExprTreeNode<Weight, Wildness, Children>>>,
        Wildness: IWildness,
    > IKeyExprTreeMut<'a, Weight> for KeBoxTree<Weight, Wildness, Children>
where
    Weight: 'a,
    Children: 'a,
    Children::Assoc: IChildren<
            Box<KeyExprTreeNode<Weight, Wildness, Children>>,
            Node = Box<KeyExprTreeNode<Weight, Wildness, Children>>,
        > + 'a,
{
    fn node_mut<'b>(&'b mut self, at: &keyexpr) -> Option<&'b mut Self::Node> {
        let mut chunks = at.chunks_impl();
        let mut node = self.children.child_at_mut(chunks.next()?)?;
        for chunk in chunks {
            node = node.as_node_mut().children.child_at_mut(chunk)?;
        }
        Some(node.as_node_mut())
    }

    fn remove(&mut self, at: &keyexpr) -> Option<Weight> {
        let node = self.node_mut(at)?;
        if !node.children.is_empty() {
            // A node that still has children stays, as a node with no weight.
            return node.weight.take();
        }
        // A leaf goes away: it is removed from the children of its parent, or of the tree.
        let chunk = node.chunk.clone();
        let parent = node.parent;
        match parent {
            None => &mut self.children,
            // SAFETY: the parent of a node of this tree is a node of this tree, boxed and so at a
            // stable address, and `&mut self` makes the access to it unique.
            Some(parent) => unsafe { &mut (*parent.as_ptr()).children },
        }
        .remove(&chunk)
        .and_then(|node| node.weight)
    }

    fn node_mut_or_create<'b>(&'b mut self, at: &keyexpr) -> &'b mut Self::Node {
        if at.is_wild_impl() {
            self.wildness.set(true);
        }
        let mut chunks = at.chunks_impl();
        let first = chunks.next().expect("a key expression has a chunk");
        let mut node = self.children.entry(first).get_or_insert_with(move |k| {
            Box::new(KeyExprTreeNode {
                parent: None,
                chunk: k.into(),
                children: Default::default(),
                weight: None,
            })
        });
        for chunk in chunks {
            let parent = NonNull::from(node.as_ref());
            node = node.children.entry(chunk).get_or_insert_with(move |k| {
                Box::new(KeyExprTreeNode {
                    parent: Some(parent),
                    chunk: k.into(),
                    children: Default::default(),
                    weight: None,
                })
            })
        }
        node
    }

    type TreeIterItemMut = <Self::TreeIterMut as Iterator>::Item;
    type TreeIterMut =
        TreeIterMut<'a, Children, Box<KeyExprTreeNode<Weight, Wildness, Children>>, Weight>;

    fn tree_iter_mut(&'a mut self) -> Self::TreeIterMut {
        TreeIterMut::new(&mut self.children)
    }

    type IntersectionItemMut = <Self::IntersectionMut as Iterator>::Item;
    type IntersectionMut = IterOrOption<
        IntersectionMut<'a, Children, Box<KeyExprTreeNode<Weight, Wildness, Children>>, Weight>,
        &'a mut Self::Node,
    >;

    fn intersecting_nodes_mut(&'a mut self, ke: &'a keyexpr) -> Self::IntersectionMut {
        if self.wildness.get() || ke.is_wild_impl() {
            IntersectionMut::new(&mut self.children, ke).into()
        } else {
            let node = self.node_mut(ke);
            IterOrOption::Opt(node)
        }
    }

    type InclusionItemMut = <Self::InclusionMut as Iterator>::Item;
    type InclusionMut = IterOrOption<
        InclusionMut<'a, Children, Box<KeyExprTreeNode<Weight, Wildness, Children>>, Weight>,
        &'a mut Self::Node,
    >;

    fn included_nodes_mut(&'a mut self, ke: &'a keyexpr) -> Self::InclusionMut {
        if self.wildness.get() || ke.is_wild_impl() {
            InclusionMut::new(&mut self.children, ke).into()
        } else {
            let node = self.node_mut(ke);
            IterOrOption::Opt(node)
        }
    }

    type IncluderItemMut = <Self::IncluderMut as Iterator>::Item;
    type IncluderMut = IterOrOption<
        IncluderMut<'a, Children, Box<KeyExprTreeNode<Weight, Wildness, Children>>, Weight>,
        &'a mut Self::Node,
    >;

    fn nodes_including_mut(&'a mut self, ke: &'a keyexpr) -> Self::IncluderMut {
        if self.wildness.get() || ke.is_wild_impl() {
            IncluderMut::new(&mut self.children, ke).into()
        } else {
            let node = self.node_mut(ke);
            IterOrOption::Opt(node)
        }
    }

    fn prune_where<F: FnMut(&mut Self::Node) -> bool>(&mut self, mut predicate: F) {
        let mut wild = false;
        self.children
            .filter_out(&mut |child| match child.as_mut().prune(&mut predicate) {
                PruneResult::Delete => true,
                PruneResult::NonWild => false,
                PruneResult::Wild => {
                    wild = true;
                    false
                }
            });
        self.wildness.set(wild);
    }
}

/// A node of a [`KeBoxTree`]: its chunk, its weight if it has one, its children, and its parent.
pub struct KeyExprTreeNode<Weight, Wildness: IWildness, Children: IChildrenProvider<Box<Self>>> {
    parent: Option<NonNull<Self>>,
    chunk: OwnedKeyExpr,
    children: Children::Assoc,
    weight: Option<Weight>,
}

impl<Weight, Wildness, Children> core::fmt::Debug for KeyExprTreeNode<Weight, Wildness, Children>
where
    Wildness: IWildness,
    Children: IChildrenProvider<Box<Self>>,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyExprTreeNode")
            .field("has_parent", &self.parent.is_some())
            .field("chunk", &self.chunk)
            .field("children", &"..")
            .field("has_weight", &self.weight.is_some())
            .finish()
    }
}

// SAFETY: the `parent` pointer is to a node of the same tree, which is owned by it as the node is,
// so moving or sharing a node across threads moves or shares the whole tree it belongs to, and
// that is as safe as its weights and children are.
unsafe impl<Weight: Send, Wildness: IWildness + Send, Children: IChildrenProvider<Box<Self>> + Send>
    Send for KeyExprTreeNode<Weight, Wildness, Children>
{
}

// SAFETY: as for `Send`.
unsafe impl<Weight: Sync, Wildness: IWildness + Sync, Children: IChildrenProvider<Box<Self>> + Sync>
    Sync for KeyExprTreeNode<Weight, Wildness, Children>
{
}

impl<Weight, Wildness: IWildness, Children: IChildrenProvider<Box<Self>>> IKeyExprTreeNode<Weight>
    for KeyExprTreeNode<Weight, Wildness, Children>
where
    Children::Assoc: IChildren<Box<Self>>,
{
}

impl<Weight, Wildness: IWildness, Children: IChildrenProvider<Box<Self>>> UIKeyExprTreeNode<Weight>
    for KeyExprTreeNode<Weight, Wildness, Children>
where
    Children::Assoc: IChildren<Box<Self>>,
{
    type Parent = Self;

    unsafe fn __parent(&self) -> Option<&Self> {
        // SAFETY: a mutable reference to the parent was needed to get a mutable reference to this
        // node in the first place, so no one else holds one while this node is borrowed.
        self.parent.as_ref().map(|node| unsafe { node.as_ref() })
    }

    unsafe fn __keyexpr(&self) -> OwnedKeyExpr {
        // SAFETY: the chunks of a node and of its parents joined by `/` are a key expression.
        unsafe { OwnedKeyExpr::from_string_unchecked(self.keyexpr_with_capacity(0)) }
    }

    unsafe fn __weight(&self) -> Option<&Weight> {
        self.weight.as_ref()
    }

    type Child = Box<Self>;
    type Children = Children::Assoc;

    unsafe fn __children(&self) -> &Self::Children {
        &self.children
    }
}

impl<Weight, Wildness: IWildness, Children: IChildrenProvider<Box<Self>>>
    IKeyExprTreeNodeMut<Weight> for KeyExprTreeNode<Weight, Wildness, Children>
where
    Children::Assoc: IChildren<Box<Self>>,
{
    fn parent_mut(&mut self) -> Option<&mut Self> {
        match &mut self.parent {
            None => None,
            // SAFETY: as for `__parent`.
            Some(node) => Some(unsafe { node.as_mut() }),
        }
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

impl<Weight, Wildness: IWildness, Children: IChildrenProvider<Box<Self>>>
    KeyExprTreeNode<Weight, Wildness, Children>
where
    Children::Assoc: IChildren<Box<Self>>,
{
    /// The key expression of the node, built from the root down with room for `capacity` more.
    fn keyexpr_with_capacity(&self, capacity: usize) -> String {
        let mut s = match self.parent() {
            Some(parent) => parent.keyexpr_with_capacity(capacity + self.chunk.len() + 1) + "/",
            None => String::with_capacity(capacity + self.chunk.len()),
        };
        s.push_str(self.chunk.as_str());
        s
    }

    /// Prune below this node, then this node if `predicate` says so and nothing is left below it.
    fn prune<F: FnMut(&mut Self) -> bool>(&mut self, predicate: &mut F) -> PruneResult {
        let mut result = PruneResult::NonWild;
        self.children
            .filter_out(&mut |child| match child.as_node_mut().prune(predicate) {
                PruneResult::Delete => true,
                PruneResult::NonWild => false,
                PruneResult::Wild => {
                    result = PruneResult::Wild;
                    false
                }
            });
        if predicate(self) && self.children.is_empty() {
            result = PruneResult::Delete
        } else if self.chunk.is_wild_impl() {
            result = PruneResult::Wild
        }
        result
    }
}

/// What pruning a node leaves: nothing, a subtree with no wild chunk, or one with a wild chunk.
pub(crate) enum PruneResult {
    Delete,
    NonWild,
    Wild,
}

impl<Weight, Wildness: IWildness, Children: IChildrenProvider<Box<Self>>> HasChunk
    for KeyExprTreeNode<Weight, Wildness, Children>
{
    fn chunk(&self) -> &keyexpr {
        &self.chunk
    }
}

impl<Weight, Wildness: IWildness, Children: IChildrenProvider<Box<Self>>> AsRef<Self>
    for KeyExprTreeNode<Weight, Wildness, Children>
{
    fn as_ref(&self) -> &Self {
        self
    }
}

impl<Weight, Wildness: IWildness, Children: IChildrenProvider<Box<Self>>> AsMut<Self>
    for KeyExprTreeNode<Weight, Wildness, Children>
{
    fn as_mut(&mut self) -> &mut Self {
        self
    }
}

impl<
        'a,
        K: AsRef<keyexpr>,
        Weight,
        Wildness: IWildness,
        Children: IChildrenProvider<Box<KeyExprTreeNode<Weight, Wildness, Children>>>,
    > core::iter::FromIterator<(K, Weight)> for KeBoxTree<Weight, Wildness, Children>
where
    Self: IKeyExprTreeMut<'a, Weight>,
{
    fn from_iter<T: IntoIterator<Item = (K, Weight)>>(iter: T) -> Self {
        let mut tree = Self::default();
        for (key, value) in iter {
            tree.insert(key.as_ref(), value);
        }
        tree
    }
}
