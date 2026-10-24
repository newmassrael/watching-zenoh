// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The trait implementations that let a reference, a box or an `Arc` of a node be used where a node
//! is asked for: each forwards to the node it holds.

use alloc::{boxed::Box, sync::Arc};

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
