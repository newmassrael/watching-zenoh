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
// src/keyexpr_tree/iters/mod.rs (https://github.com/eclipse-zenoh/zenoh, tag 1.10.1).

//! The iterators of KeTrees: over the whole tree, and over the nodes that stand in a relation to a
//! key expression (intersection, inclusion, being included).
//!
//! The three relational iterators walk the tree depth first, parents before children, keeping the
//! key expression of the node they are at, and they are the same walk with a different test:
//! * a node is YIELDED when its key expression is in the relation to the query's;
//! * its children are VISITED when some descendant could be in any of the three relations. A
//!   descendant that is included by, or includes, the query also intersects it, so the test is for
//!   intersection alone, and it is made on the node's chunks, as follows.
//!
//! A node `n` without a `**` chunk matches sequences of exactly as many chunks as it has, so a
//! descendant `n/x` can intersect the query `c1/../cm` only if `n` intersects the head `c1/../ci`
//! of the query for some `i` from 1 to `m`: the head that ends at the chunk the last chunk of `n`
//! is matched against. A node with a `**` chunk may match fewer chunks than it has, and `**` does
//! not match a verbatim chunk, so no head of the query need intersect it while a descendant does
//! (`**/@a` under `**`, for the query `@a`); its children are always visited. Visiting more than
//! needed costs time and never a node, since a node is yielded only by the first test.
//!
//! Both tests are the relations of [`keyexpr`] themselves, so what the iterators agree on with
//! `intersects` and `includes` is a consequence and not a second implementation of the language.

use alloc::{string::String, vec::Vec};

use crate::keyexpr_tree::*;

mod tree_iter;
pub use tree_iter::{TreeIter, TreeIterMut};

/// Which relation to the query a walk yields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Relation {
    /// The node's key expression intersects the query.
    Intersection,
    /// The node's key expression is included by the query.
    Inclusion,
    /// The node's key expression includes the query.
    Includer,
}

impl Relation {
    /// Whether a node whose key expression is `path` is yielded for `key`.
    fn yields(self, path: &keyexpr, key: &keyexpr) -> bool {
        match self {
            Relation::Intersection => path.intersects(key),
            Relation::Inclusion => key.includes(path),
            Relation::Includer => path.includes(key),
        }
    }

    /// Whether the children of a node whose key expression is `path` can hold a node that is
    /// yielded for the query `key`, whose chunks end at the offsets `ends` (see the module).
    fn visits_children(path: &keyexpr, key: &keyexpr, ends: &[usize]) -> bool {
        if path.chunks_impl().any(|c| c.as_str() == "**") {
            return true;
        }
        ends.iter().any(|&end| {
            // SAFETY: a head of a canon key expression, cut at the end of a chunk, is one.
            let head = unsafe { keyexpr::from_str_unchecked(&key.as_str()[..end]) };
            path.intersects(head)
        })
    }
}

/// The state a relational walk shares: the query, the key expression of the node it is at, and the
/// stack of iterators over the children of each node on the way down.
struct Walk<Iter> {
    relation: Relation,
    key_text: String,
    /// The key expression of the node the walk is at.
    path: String,
    /// The offset in `key_text` at which each chunk of the query ends.
    ends: Vec<usize>,
    /// One frame per level: the iterator over a node's children, and the length `path` had at the
    /// node that owns them.
    frames: Vec<(Iter, usize)>,
}

impl<Iter> Walk<Iter> {
    fn new(relation: Relation, key: &keyexpr, root: Iter) -> Self {
        let text = key.as_str();
        let ends = text
            .match_indices('/')
            .map(|(at, _)| at)
            .chain(core::iter::once(text.len()))
            .collect();
        Self {
            relation,
            key_text: String::from(text),
            path: String::new(),
            ends,
            frames: alloc::vec![(root, 0)],
        }
    }

    fn key(&self) -> &keyexpr {
        // SAFETY: `key_text` was copied from a key expression.
        unsafe { keyexpr::from_str_unchecked(&self.key_text) }
    }

    /// Step into the node whose chunk is `chunk`, a child of the node that owns the frame whose
    /// `base` is given: set `path` to the node's key expression and answer whether to yield the
    /// node and whether to visit its children.
    fn enter(&mut self, base: usize, chunk: &keyexpr) -> (bool, bool) {
        self.path.truncate(base);
        if !self.path.is_empty() {
            self.path.push('/');
        }
        self.path.push_str(chunk.as_str());
        // SAFETY: a parent's key expression and a child's chunk, joined by `/`, are the child's.
        let path = unsafe { keyexpr::from_str_unchecked(&self.path) };
        // SAFETY: `key_text` was copied from a key expression.
        let key = unsafe { keyexpr::from_str_unchecked(&self.key_text) };
        let yielded = self.relation.yields(path, key);
        let descend = Relation::visits_children(path, key, &self.ends);
        (yielded, descend)
    }
}

/// Defines the immutable and mutable iterators of one relation.
macro_rules! relational_iterators {
    ($shared:ident, $mutable:ident, $relation:expr, $what:literal) => {
        #[doc = concat!("Iterates over the nodes of a tree whose key expression ", $what, ".")]
        pub struct $shared<
            'a,
            Children: IChildrenProvider<Node>,
            Node: UIKeyExprTreeNode<Weight>,
            Weight,
        > where
            Children::Assoc: IChildren<Node> + 'a,
        {
            walk: Walk<<Children::Assoc as IChildren<Node>>::Iter<'a>>,
            _marker: core::marker::PhantomData<(Weight, &'a Node)>,
        }

        impl<'a, Children: IChildrenProvider<Node>, Node: UIKeyExprTreeNode<Weight>, Weight>
            core::fmt::Debug for $shared<'a, Children, Node, Weight>
        where
            Children::Assoc: IChildren<Node> + 'a,
        {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.debug_struct(stringify!($shared))
                    .field("key", &self.walk.key())
                    .field("depth", &self.walk.frames.len())
                    .finish()
            }
        }

        impl<'a, Children: IChildrenProvider<Node>, Node: UIKeyExprTreeNode<Weight>, Weight>
            $shared<'a, Children, Node, Weight>
        where
            Children::Assoc: IChildren<Node> + 'a,
        {
            pub(crate) fn new(children: &'a Children::Assoc, key: &'a keyexpr) -> Self {
                Self {
                    walk: Walk::new($relation, key, children.children()),
                    _marker: core::marker::PhantomData,
                }
            }
        }

        impl<
                'a,
                Children: IChildrenProvider<Node>,
                Node: UIKeyExprTreeNode<Weight, Children = Children::Assoc> + 'a,
                Weight,
            > Iterator for $shared<'a, Children, Node, Weight>
        where
            Children::Assoc: IChildren<Node> + 'a,
        {
            type Item = &'a Node;

            fn next(&mut self) -> Option<Self::Item> {
                loop {
                    let (iterator, base) = self.walk.frames.last_mut()?;
                    let base = *base;
                    match iterator.next() {
                        Some(node) => {
                            let (yielded, descend) = self.walk.enter(base, node.chunk());
                            if descend {
                                // SAFETY: the children are borrowed for `'a` from the tree, as
                                // the node is, and the walk only reads them.
                                let children = unsafe { node.as_node().__children() }.children();
                                let depth = self.walk.path.len();
                                self.walk.frames.push((children, depth));
                            }
                            if yielded {
                                return Some(node.as_node());
                            }
                        }
                        None => {
                            self.walk.frames.pop();
                        }
                    }
                }
            }
        }

        #[doc = concat!("Iterates mutably over the nodes of a tree whose key expression ", $what, ".")]
        pub struct $mutable<
            'a,
            Children: IChildrenProvider<Node>,
            Node: UIKeyExprTreeNode<Weight>,
            Weight,
        > where
            Children::Assoc: IChildren<Node> + 'a,
        {
            walk: Walk<<Children::Assoc as IChildren<Node>>::IterMut<'a>>,
            _marker: core::marker::PhantomData<(Weight, &'a mut Node)>,
        }

        impl<'a, Children: IChildrenProvider<Node>, Node: UIKeyExprTreeNode<Weight>, Weight>
            core::fmt::Debug for $mutable<'a, Children, Node, Weight>
        where
            Children::Assoc: IChildren<Node> + 'a,
        {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.debug_struct(stringify!($mutable))
                    .field("key", &self.walk.key())
                    .field("depth", &self.walk.frames.len())
                    .finish()
            }
        }

        impl<'a, Children: IChildrenProvider<Node>, Node: UIKeyExprTreeNode<Weight>, Weight>
            $mutable<'a, Children, Node, Weight>
        where
            Children::Assoc: IChildren<Node> + 'a,
        {
            pub(crate) fn new(children: &'a mut Children::Assoc, key: &'a keyexpr) -> Self {
                Self {
                    walk: Walk::new($relation, key, children.children_mut()),
                    _marker: core::marker::PhantomData,
                }
            }
        }

        impl<
                'a,
                Children: IChildrenProvider<Node>,
                Node: IKeyExprTreeNodeMut<Weight, Children = Children::Assoc> + 'a,
                Weight,
            > Iterator for $mutable<'a, Children, Node, Weight>
        where
            Children::Assoc: IChildren<Node> + 'a,
        {
            type Item = &'a mut <Children::Assoc as IChildren<Node>>::Node;

            fn next(&mut self) -> Option<Self::Item> {
                loop {
                    let (iterator, base) = self.walk.frames.last_mut()?;
                    let base = *base;
                    match iterator.next() {
                        Some(node) => {
                            let (yielded, descend) = self.walk.enter(base, node.chunk());
                            if descend {
                                // SAFETY: the walk goes down into the children of a node it also
                                // yields, so the caller may hold the node while the walk reads
                                // below it; the API of mutable tree iterators hands out the
                                // parent and, later, its descendants, and relies on callers not
                                // touching a yielded node's children while the iterator lives.
                                let children = unsafe { &mut *(node.as_node_mut() as *mut Node) }
                                    .children_mut()
                                    .children_mut();
                                let depth = self.walk.path.len();
                                self.walk.frames.push((children, depth));
                            }
                            if yielded {
                                return Some(node);
                            }
                        }
                        None => {
                            self.walk.frames.pop();
                        }
                    }
                }
            }
        }
    };
}

relational_iterators!(
    Intersection,
    IntersectionMut,
    Relation::Intersection,
    "intersects a key expression"
);
relational_iterators!(
    Inclusion,
    InclusionMut,
    Relation::Inclusion,
    "is included by a key expression"
);
relational_iterators!(
    Includer,
    IncluderMut,
    Relation::Includer,
    "includes a key expression"
);
