// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Where a session's unicast transport lies, and how whoever drives the session reaches it: by
//! `&mut`, lent by the place for the length of one call.
//!
//! A session's transport (the link's state, its receive and its send: `SessionLinkActions` and
//! what drives it) has one owner. In the one-face build that owner is a field of the session's
//! region, and the engine borrows the field. In a build of several faces or several threads, the
//! face policy keeps one transport for each face and the lock policy lends it under the lock. Each
//! is a [`TransportPlace`], and the driver, the session machine's binding and the session layer's
//! send all reach the transport through one: there is no counted handle shared between them, and
//! no form gives the transport a meaning another form does not.
//!
//! A place may hold no transport now (a face whose link is not up): it answers `None` and runs
//! nothing, and the caller reads that as the send or the input it would have been for a link that
//! is not there.

/// A place a session's transport lies in, lent by `&mut` for the length of one call.
pub trait TransportPlace {
    /// The transport the place holds.
    type Transport;

    /// Run `f` on the transport this place holds, lent for the length of `f`, and answer what
    /// `f` answered; `None`, with `f` not run, while the place holds none.
    fn lend<U>(&mut self, f: impl FnOnce(&mut Self::Transport) -> U) -> Option<U>;
}

/// A field that holds the transport once its link is made, and none before: the one-face
/// session's place.
impl<X> TransportPlace for Option<X> {
    type Transport = X;

    #[inline]
    fn lend<U>(&mut self, f: impl FnOnce(&mut X) -> U) -> Option<U> {
        self.as_mut().map(f)
    }
}

/// The one-face session's place in a region the allocator zeroed: none at zero bytes whatever the
/// transport's type, which an `Option` of it is not.
impl<X> TransportPlace for crate::bounded::ZeroOption<X> {
    type Transport = X;

    #[inline]
    fn lend<U>(&mut self, f: impl FnOnce(&mut X) -> U) -> Option<U> {
        self.as_mut().map(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A place that holds a transport lends it to the call, and what the call did to it is there
    /// after: the owner holds the one transport, changed.
    #[test]
    fn a_held_transport_is_lent_and_keeps_what_the_call_did() {
        let mut place = Some(7u32);
        let seen = place.lend(|transport| {
            *transport += 1;
            *transport
        });
        assert_eq!(seen, Some(8));
        assert_eq!(place, Some(8));
    }

    /// A place that holds no transport runs nothing and says so.
    #[test]
    fn a_place_with_no_transport_runs_nothing() {
        let mut place: Option<u32> = None;
        let mut ran = false;
        let seen = place.lend(|_transport| ran = true);
        assert_eq!(seen, None);
        assert!(!ran, "no transport, no call");
    }

    /// A caller generic over the place reaches the transport the same way whatever holds it.
    #[test]
    fn a_caller_generic_over_the_place_reaches_its_transport() {
        fn bump<P: TransportPlace<Transport = u32>>(place: &mut P) -> Option<u32> {
            place.lend(|transport| {
                *transport *= 2;
                *transport
            })
        }
        let mut place = Some(21u32);
        assert_eq!(bump(&mut place), Some(42));
        assert_eq!(bump(&mut None::<u32>), None);
    }

    /// A region's place of all zero bytes holds no transport and runs nothing; once the link is
    /// made it lends the transport as an `Option` does. Turned red by a zeroed place read as one
    /// that holds a transport.
    #[test]
    fn a_zeroed_region_place_holds_no_transport_until_one_is_made() {
        use crate::bounded::ZeroOption;
        // SAFETY: `ZeroOption` is `ZeroEmpty`: all zero bytes are a place that holds none.
        let mut place: ZeroOption<u32> = unsafe { core::mem::zeroed() };
        let mut ran = false;
        assert_eq!(place.lend(|_transport| ran = true), None);
        assert!(!ran, "no transport, no call");
        assert!(place.replace(5).is_none());
        assert_eq!(
            place.lend(|transport| {
                *transport += 1;
                *transport
            }),
            Some(6)
        );
        assert_eq!(place.as_ref(), Some(&6));
    }
}
