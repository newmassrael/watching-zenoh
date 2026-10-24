// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The trait implementations that let a reference, a box or an `Arc` of a node be used where a node
//! is asked for: each forwards to the node it holds.

use alloc::{boxed::Box, sync::Arc};

use token_cell::prelude::{TokenCell, TokenCellTrait, TokenTrait};

use super::*;

impl<T: HasChunk> HasChunk for &T {
    fn chunk(&self) -> &keyexpr {
        T::chunk(self)
    }
}

impl<T: HasChunk> HasChunk for &mut T {
    fn chunk(&self) -> &keyexpr {
        T::chunk(self)
    }
}

impl<T: HasChunk> HasChunk for Box<T> {
    fn chunk(&self) -> &keyexpr {
        T::chunk(self)
    }
}

impl<T: HasChunk> HasChunk for Arc<T> {
    fn chunk(&self) -> &keyexpr {
        T::chunk(self)
    }
}

impl<T> AsNode<T> for T {
    fn as_node(&self) -> &T {
        self
    }
}

impl<T> AsNode<T> for &T {
    fn as_node(&self) -> &T {
        self
    }
}

impl<T> AsNode<T> for &mut T {
    fn as_node(&self) -> &T {
        self
    }
}

impl<T> AsNodeMut<T> for T {
    fn as_node_mut(&mut self) -> &mut T {
        self
    }
}

impl<T> AsNodeMut<T> for &mut T {
    fn as_node_mut(&mut self) -> &mut T {
        self
    }
}

/// `IKeyExprTreeNode` for a pointer type that derefs to a node, forwarding each accessor.
macro_rules! forward_node {
    ($($pointer:ty),+) => {$(
        impl<T: IKeyExprTreeNode<Weight>, Weight> IKeyExprTreeNode<Weight> for $pointer {}

        impl<T: IKeyExprTreeNode<Weight>, Weight> UIKeyExprTreeNode<Weight> for $pointer {
            type Parent = T::Parent;
            unsafe fn __parent(&self) -> Option<&Self::Parent> {
                T::parent(self)
            }
            unsafe fn __keyexpr(&self) -> OwnedKeyExpr {
                T::keyexpr(self)
            }
            unsafe fn __weight(&self) -> Option<&Weight> {
                T::weight(self)
            }
            type Child = T::Child;
            type Children = T::Children;
            unsafe fn __children(&self) -> &Self::Children {
                T::children(self)
            }
        }
    )+};
}

forward_node!(&T, &mut T, Box<T>);

/// `IKeyExprTreeNodeMut` for a pointer type that derefs to a node mutably.
macro_rules! forward_node_mut {
    ($($pointer:ty),+) => {$(
        impl<T: IKeyExprTreeNodeMut<Weight>, Weight> IKeyExprTreeNodeMut<Weight> for $pointer {
            fn parent_mut(&mut self) -> Option<&mut Self::Parent> {
                T::parent_mut(self)
            }
            fn weight_mut(&mut self) -> Option<&mut Weight> {
                T::weight_mut(self)
            }
            fn take_weight(&mut self) -> Option<Weight> {
                T::take_weight(self)
            }
            fn insert_weight(&mut self, weight: Weight) -> Option<Weight> {
                T::insert_weight(self, weight)
            }
            fn children_mut(&mut self) -> &mut Self::Children {
                T::children_mut(self)
            }
        }
    )+};
}

forward_node_mut!(&mut T, Box<T>);

impl<T: HasChunk, Token: TokenTrait> HasChunk for TokenCell<T, Token> {
    fn chunk(&self) -> &keyexpr {
        // SAFETY: a node's chunk is written when the node is built and never after, so reading it
        // does not race with an access through the token to the rest of the node.
        T::chunk(unsafe { &*self.get() })
    }
}

/// The panic of every access through the wrong token.
fn wrong_token<E, R>(_: E) -> R {
    panic!("Used wrong token to access TokenCell")
}

/// `IKeyExprTreeNode` for a node cell paired with a reference to a token: every accessor checks the
/// token against the cell, which is what makes the access safe.
macro_rules! token_node {
    ($($pair:ty),+ $(,)?) => {$(
        impl<T: IKeyExprTreeNode<Weight>, Weight, Token: TokenTrait> IKeyExprTreeNode<Weight>
            for $pair
        {
        }

        impl<T: IKeyExprTreeNode<Weight>, Weight, Token: TokenTrait> UIKeyExprTreeNode<Weight>
            for $pair
        {
            type Parent = T::Parent;
            unsafe fn __parent(&self) -> Option<&Self::Parent> {
                self.0.try_borrow(&*self.1).unwrap_or_else(wrong_token).parent()
            }
            unsafe fn __keyexpr(&self) -> OwnedKeyExpr {
                self.0.try_borrow(&*self.1).unwrap_or_else(wrong_token).keyexpr()
            }
            unsafe fn __weight(&self) -> Option<&Weight> {
                self.0.try_borrow(&*self.1).unwrap_or_else(wrong_token).weight()
            }
            type Child = T::Child;
            type Children = T::Children;
            unsafe fn __children(&self) -> &Self::Children {
                self.0.try_borrow(&*self.1).unwrap_or_else(wrong_token).children()
            }
        }
    )+};
}

/// `IKeyExprTreeNodeMut` for a node cell paired with a mutable reference to a token.
macro_rules! token_node_mut {
    ($($pair:ty),+ $(,)?) => {$(
        impl<T: IKeyExprTreeNodeMut<Weight>, Weight, Token: TokenTrait> IKeyExprTreeNodeMut<Weight>
            for $pair
        {
            fn parent_mut(&mut self) -> Option<&mut Self::Parent> {
                self.0.try_borrow_mut(&mut *self.1).unwrap_or_else(wrong_token).parent_mut()
            }
            fn weight_mut(&mut self) -> Option<&mut Weight> {
                self.0.try_borrow_mut(&mut *self.1).unwrap_or_else(wrong_token).weight_mut()
            }
            fn take_weight(&mut self) -> Option<Weight> {
                self.0.try_borrow_mut(&mut *self.1).unwrap_or_else(wrong_token).take_weight()
            }
            fn insert_weight(&mut self, weight: Weight) -> Option<Weight> {
                self.0
                    .try_borrow_mut(&mut *self.1)
                    .unwrap_or_else(wrong_token)
                    .insert_weight(weight)
            }
            fn children_mut(&mut self) -> &mut Self::Children {
                self.0.try_borrow_mut(&mut *self.1).unwrap_or_else(wrong_token).children_mut()
            }
        }
    )+};
}

use crate::keyexpr_tree::arc_tree::Tokenized;

token_node!(
    (&TokenCell<T, Token>, &Token),
    (&TokenCell<T, Token>, &mut Token),
    (&Arc<TokenCell<T, Token>>, &Token),
    (&Arc<TokenCell<T, Token>>, &mut Token),
    Tokenized<&TokenCell<T, Token>, &Token>,
    Tokenized<&TokenCell<T, Token>, &mut Token>,
    Tokenized<&Arc<TokenCell<T, Token>>, &Token>,
    Tokenized<&Arc<TokenCell<T, Token>>, &mut Token>,
);

token_node_mut!(
    (&TokenCell<T, Token>, &mut Token),
    (&Arc<TokenCell<T, Token>>, &mut Token),
    Tokenized<&TokenCell<T, Token>, &mut Token>,
    Tokenized<&Arc<TokenCell<T, Token>>, &mut Token>,
);
