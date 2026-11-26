// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What a host's resolver is handed, the same on every host (`net::resolve` over `getaddrinfo`,
//! `windows::resolve` over Winsock's): the name with its terminator, in the caller's frame.

use wz_runtime_coop::locator_text::{NamedHost, HOST_NAME_MAX};

/// The host `name` followed by a 0 byte, as a C resolver reads a name. A name a dial's text was
/// read into is at most `HOST_NAME_MAX` bytes and holds no 0 byte, so the copy keeps all of it and
/// the byte after it ends it.
pub(crate) fn terminated(name: &NamedHost<'_>) -> [u8; HOST_NAME_MAX + 1] {
    let host = name.host().as_bytes();
    let mut text = [0u8; HOST_NAME_MAX + 1];
    if let Some(place) = text.get_mut(..host.len()) {
        place.copy_from_slice(host);
    }
    text
}

/// The host a dial's `text` names, for a test of what a resolver is handed.
#[cfg(test)]
pub(crate) fn named(text: &str) -> NamedHost<'_> {
    match wz_runtime_coop::locator_text::read_dial_target(text, true) {
        Ok(wz_runtime_coop::locator_text::DialTarget::Named(name)) => name,
        other => panic!("{text} names a host: {other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A name is handed on with its terminator and nothing else, the longest a dial reads whole.
    /// Turned red by a name without its terminator or a long one cut short.
    #[test]
    fn a_name_is_handed_on_with_its_terminator() {
        let text = terminated(&named("tcp/localhost:7447"));
        assert_eq!(text.get(..10), Some(&b"localhost\0"[..]));
        let labels = std::vec!["a".repeat(63); 5].join(".");
        let longest = labels.get(..HOST_NAME_MAX).expect("five labels are longer");
        let endpoint = std::format!("tcp/{longest}:7447");
        let text = terminated(&named(&endpoint));
        assert_eq!(text.get(..HOST_NAME_MAX), Some(longest.as_bytes()));
        assert_eq!(text.last(), Some(&0));
    }
}
