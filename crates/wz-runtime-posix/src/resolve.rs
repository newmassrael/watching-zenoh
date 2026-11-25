// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a host's resolver is handed and what is kept of its answer, the same on every host
//! (`net::resolve` over `getaddrinfo`, `windows::resolve` over Winsock's): the name with its
//! terminator, in the caller's frame, and each address it answers, once and in its order.

use core::net::SocketAddr;

use wz_runtime_coop::locator_text::HOST_NAME_MAX;

/// `host` followed by a 0 byte, as a C resolver reads a name; `None` for a host longer than
/// `HOST_NAME_MAX` or one that holds a 0 byte, which no name read from a dial's text is.
pub(crate) fn terminated(host: &str) -> Option<[u8; HOST_NAME_MAX + 1]> {
    if host.len() > HOST_NAME_MAX || host.as_bytes().contains(&0) {
        return None;
    }
    let mut name = [0u8; HOST_NAME_MAX + 1];
    name.get_mut(..host.len())?.copy_from_slice(host.as_bytes());
    Some(name)
}

/// Keep `at` in the place after the `count` addresses `found` holds, unless one of those is
/// `at`: how many it holds after. `None` once `found` has no place left, which ends the walk
/// of the answer.
pub(crate) fn keep(found: &mut [SocketAddr], count: usize, at: SocketAddr) -> Option<usize> {
    if found.get(..count).is_some_and(|kept| kept.contains(&at)) {
        return Some(count);
    }
    *found.get_mut(count)? = at;
    // `count` names a place of `found`, so the sum does not wrap.
    Some(count.wrapping_add(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A name is handed on with its terminator and nothing else, and a text a C resolver would
    /// read otherwise (one cut at a 0 byte, one past the room) is not handed on. Turned red by a
    /// name without its terminator or a longer one cut short.
    #[test]
    fn a_name_is_handed_on_with_its_terminator() {
        let name = terminated("localhost").expect("a name");
        assert_eq!(name.get(..10), Some(&b"localhost\0"[..]));
        let longest = "a".repeat(HOST_NAME_MAX);
        let name = terminated(&longest).expect("the longest name");
        assert_eq!(name.last(), Some(&0));
        assert_eq!(terminated(&"a".repeat(HOST_NAME_MAX + 1)), None);
        assert_eq!(terminated("local\0host"), None);
    }

    /// Each address is kept once, in the order answered, until no place is left. Turned red by an
    /// address kept twice, one written past the places, or the order changed.
    #[test]
    fn each_address_is_kept_once_in_its_order() {
        let (a, b, c) = (
            SocketAddr::from(([127, 0, 0, 1], 7447)),
            SocketAddr::from(([0u16, 0, 0, 0, 0, 0, 0, 1], 7447)),
            SocketAddr::from(([10, 0, 0, 1], 7447)),
        );
        let mut found = [SocketAddr::from(([0, 0, 0, 0], 0)); 2];
        let mut count = 0;
        for at in [b, b, a] {
            count = keep(&mut found, count, at).expect("a place left");
        }
        assert_eq!((count, found), (2, [b, a]));
        assert_eq!(keep(&mut found, count, a), Some(2), "kept already");
        assert_eq!(keep(&mut found, count, c), None, "no place left");
    }
}
