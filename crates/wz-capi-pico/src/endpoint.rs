// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! zenoh-pico's reading of an endpoint's text, `<protocol>/<address>[?metadata][#config]`: the one
//! place this ABI reads it, for the endpoint a session of the cooperative engine dials or listens
//! on and for the text pico reports a group's link by.
//!
//! pico takes the config after the first `#` (`vendor/zenoh-pico/src/link/endpoint.c` @
//! `char *p_start = (char *)memchr(_z_string_data(str), ENDPOINT_CONFIG_SEPARATOR, _z_string_len(str));`)
//! and reads it with the keys its link for the scheme declares, up to the first key that link does
//! not know, the last value of a key given twice standing, and refuses a pair that has no `=`
//! (`vendor/zenoh-pico/src/protocol/config.c` @ `z_result_t _z_str_intmap_from_strn(`). It
//! declares no metadata key, so the metadata is read and kept by no link.

/// The most config keys a link pico declares reads: the raweth link's four ([`config_keys`]).
const MAX_KEYS: usize = 4;

/// The config keys pico's link for `scheme` reads, in the order its mapping lists them: TCP's
/// (`vendor/zenoh-pico/include/zenoh-pico/link/config/tcp.h` @ `#define TCP_CONFIG_MAPPING_BUILD`),
/// UDP's, unicast and group alike (`vendor/zenoh-pico/include/zenoh-pico/link/config/udp.h` @
/// `#define UDP_CONFIG_MAPPING_BUILD`), and the raweth link's
/// (`vendor/zenoh-pico/src/transport/raweth/link.c` @ `#define RAWETH_CONFIG_MAPPING_BUILD`).
/// `None` for a scheme whose config this ABI does not read here, which goes on as it was written.
pub(crate) fn config_keys(scheme: &str) -> Option<&'static [&'static str]> {
    match scheme {
        "tcp" => Some(&["tout"]),
        "udp" => Some(&["iface", "tout", "join"]),
        "reth" => Some(&["iface", "ethtype", "mapping", "whitelist"]),
        _ => None,
    }
}

/// The scheme an endpoint's text opens with, empty when it names none.
pub(crate) fn scheme_of(endpoint: &str) -> &str {
    cut(endpoint, b'/').map_or("", |(scheme, _)| scheme)
}

/// `text` cut at its first `separator`, an ASCII byte, which neither half keeps; `None` when
/// `text` has none. Every separator of an endpoint's text is ASCII, so the text is read a byte at
/// a time and not searched for a character's encoding, as `str::split_once` searches it.
fn cut(text: &str, separator: u8) -> Option<(&str, &str)> {
    let at = text.bytes().position(|byte| byte == separator)?;
    let (head, tail) = text.split_at_checked(at)?;
    Some((head, tail.get(1..)?))
}

/// An endpoint as pico reads it with a link's `keys`: views into the endpoint's own text.
pub(crate) struct PicoEndpoint<'a> {
    /// `<protocol>/<address>`, the metadata left out.
    pub(crate) locator: &'a str,
    keys: &'static [&'static str],
    /// The value pico keeps of each of `keys`, in their order.
    values: [Option<&'a str>; MAX_KEYS],
    /// A pair with no `=` was met before the first unknown key: pico refuses the endpoint.
    malformed: bool,
}

impl<'a> PicoEndpoint<'a> {
    /// Read `endpoint` as pico's link of `keys` reads it.
    pub(crate) fn read(endpoint: &'a str, keys: &'static [&'static str]) -> Self {
        let (locator, config) = cut(endpoint, b'#').unwrap_or((endpoint, ""));
        let locator = cut(locator, b'?').map_or(locator, |(bare, _)| bare);
        let mut values = [None; MAX_KEYS];
        let mut malformed = false;
        // The pairs between the `;`, an empty one skipped.
        let mut rest = Some(config);
        while let Some(text) = rest {
            let pair = match cut(text, b';') {
                Some((pair, after)) => {
                    rest = Some(after);
                    pair
                }
                None => {
                    rest = None;
                    text
                }
            };
            if pair.is_empty() {
                continue;
            }
            let Some((key, value)) = cut(pair, b'=') else {
                malformed = true;
                break;
            };
            // A key past the room the values have is read as one the link does not know.
            let Some(slot) = keys
                .iter()
                .position(|known| *known == key)
                .and_then(|slot| values.get_mut(slot))
            else {
                break;
            };
            *slot = Some(value);
        }
        Self {
            locator,
            keys,
            values,
            malformed,
        }
    }

    /// Whether pico refuses the endpoint for a malformed config.
    pub(crate) fn is_malformed(&self) -> bool {
        self.malformed
    }

    /// The pairs pico keeps, key and value, in its link's order of the keys.
    fn pairs(&self) -> impl Iterator<Item = (&'static str, &'a str)> + '_ {
        self.keys
            .iter()
            .zip(&self.values)
            .filter_map(|(key, value)| value.map(|value| (*key, value)))
    }

    /// Hands `put` the text pico keeps of the endpoint, piece by piece: the locator, then, when
    /// a pair is kept, `separator` and the pairs, `key=value`, joined by `;`.
    fn write_text(&self, separator: &str, mut put: impl FnMut(&str)) {
        put(self.locator);
        let mut before = separator;
        for (key, value) in self.pairs() {
            put(before);
            put(key);
            put("=");
            put(value);
            before = ";";
        }
    }

    /// The bytes of the text pico keeps of the endpoint ([`Self::write_text`]).
    pub(crate) fn text_len(&self, separator: &str) -> usize {
        let mut len = 0usize;
        self.write_text(separator, |piece| len = len.saturating_add(piece.len()));
        len
    }

    /// The text pico keeps of the endpoint ([`Self::write_text`]), made once at its length: the
    /// one copy of it its holder keeps.
    pub(crate) fn text(&self, separator: &str) -> alloc::string::String {
        let mut text = alloc::string::String::with_capacity(self.text_len(separator));
        self.write_text(separator, |piece| text.push_str(piece));
        text
    }
}

/// Reads a unicast endpoint the program wrote, in place, as pico reads it, for a session of the
/// cooperative engine to dial or listen on: what pico's link reads stays for the engine, which
/// carries it out or refuses it; the metadata and the config keys past the first one pico's link
/// does not know are left out, as pico leaves them, so `tcp/127.0.0.1:7447#iface=lo` is dialled as
/// `tcp/127.0.0.1:7447`, which pico's TCP link binds to no interface either. A scheme whose
/// config this ABI does not read goes on as written. A malformed config is refused with pico's
/// `_Z_ERR_CONFIG_INVALID_VALUE`.
///
/// The text is read where the config holds it and the one the engine is handed is made once, at
/// its length, the engine's own copy. A kept text past the build's `MAX_LOCATOR_LEN`, the bound
/// every locator text of a session is held to, is refused with pico's
/// `_Z_ERR_SYSTEM_OUT_OF_MEMORY`, what its reading of a config answers when it has no memory to
/// hold a value in (`vendor/zenoh-pico/src/protocol/config.c` @
/// `ret = _Z_ERR_SYSTEM_OUT_OF_MEMORY;`), and nothing of it is cut short.
#[cfg(not(feature = "engine-tokio"))]
pub(crate) fn engine_endpoint(
    endpoint: &str,
) -> Result<alloc::string::String, crate::result::ZResult> {
    let Some(keys) = config_keys(scheme_of(endpoint)) else {
        return Ok(endpoint.into());
    };
    let read = PicoEndpoint::read(endpoint, keys);
    if read.is_malformed() {
        return Err(crate::result::Z_ERR_CONFIG_INVALID_VALUE);
    }
    if read.text_len("#") > wz_session_core::caps::MAX_LOCATOR_LEN {
        return Err(crate::result::Z_ERR_SYSTEM_OUT_OF_MEMORY);
    }
    Ok(read.text("#"))
}

#[cfg(all(test, not(feature = "engine-tokio")))]
mod tests {
    use super::*;
    use crate::prelude::*;
    use crate::result::{ZResult, Z_ERR_CONFIG_INVALID_VALUE, Z_ERR_SYSTEM_OUT_OF_MEMORY};
    use wz_session_core::caps::MAX_LOCATOR_LEN;

    /// The endpoint the engine is handed for `written`.
    fn dialled(written: &str) -> Result<String, ZResult> {
        engine_endpoint(written)
    }

    /// A TCP endpoint keeps what pico's TCP link reads and loses what it does not: an interface
    /// is no key of that link, so the locator is dialled bare; the metadata goes too.
    #[test]
    fn a_tcp_endpoint_keeps_what_picos_tcp_link_reads() {
        for (written, expected) in [
            ("tcp/127.0.0.1:9000#iface=lo", "tcp/127.0.0.1:9000"),
            ("tcp/127.0.0.1:9000", "tcp/127.0.0.1:9000"),
            ("tcp/127.0.0.1:9000?rel=1#iface=lo", "tcp/127.0.0.1:9000"),
            // The timeout is the link's key: it stays, for the engine to carry out or refuse.
            ("tcp/127.0.0.1:9000#tout=5", "tcp/127.0.0.1:9000#tout=5"),
            // Read up to the first key the link does not know.
            ("tcp/127.0.0.1:9000#iface=lo;tout=5", "tcp/127.0.0.1:9000"),
            (
                "tcp/127.0.0.1:9000#tout=5;iface=lo",
                "tcp/127.0.0.1:9000#tout=5",
            ),
        ] {
            assert_eq!(dialled(written).as_deref(), Ok(expected), "{written}");
        }
    }

    /// A UDP endpoint keeps its interface, which pico's UDP link reads, in that link's order of
    /// the keys.
    #[test]
    fn a_udp_endpoint_keeps_its_interface() {
        assert_eq!(
            dialled("udp/127.0.0.1:9000#tout=5;iface=lo").as_deref(),
            Ok("udp/127.0.0.1:9000#iface=lo;tout=5")
        );
    }

    /// A config pico cannot read is refused as pico refuses it; a scheme whose config this ABI
    /// does not read goes on as written.
    #[test]
    fn a_malformed_config_is_refused_and_an_unread_scheme_goes_as_written() {
        assert_eq!(
            dialled("tcp/127.0.0.1:9000#iface"),
            Err(Z_ERR_CONFIG_INVALID_VALUE)
        );
        assert_eq!(
            dialled("tls/127.0.0.1:9000#root_ca_certificate=x").as_deref(),
            Ok("tls/127.0.0.1:9000#root_ca_certificate=x")
        );
    }

    /// The kept text is made at its own length; the engine's endpoint is held to the build's
    /// `MAX_LOCATOR_LEN`, measured on what pico keeps and not on what was written, a text at the
    /// bound taken and one a byte past it refused.
    #[test]
    fn a_kept_text_past_its_room_is_refused() {
        let keys = config_keys("udp").unwrap();
        let read = PicoEndpoint::read("udp/127.0.0.1:9000#tout=5;iface=lo", keys);
        let kept = "udp/127.0.0.1:9000#iface=lo;tout=5";
        assert_eq!(read.text_len("#"), kept.len());
        let text = read.text("#");
        assert_eq!(text, kept);

        let host = "h".repeat(MAX_LOCATOR_LEN - "tcp/:9000".len());
        let at_bound = format!("tcp/{host}:9000");
        assert_eq!(at_bound.len(), MAX_LOCATOR_LEN);
        // The interface is left out before the bound is read.
        assert_eq!(
            dialled(&format!("{at_bound}#iface=lo")).as_deref(),
            Ok(at_bound.as_str())
        );
        assert_eq!(
            dialled(&format!("tcp/{host}h:9000")),
            Err(Z_ERR_SYSTEM_OUT_OF_MEMORY)
        );
    }

    /// An endpoint's text is cut at the first of each separator: the metadata goes, an empty pair
    /// is skipped, a value keeps an `=` of its own, and a text with no scheme names none.
    #[test]
    fn an_endpoint_is_cut_at_its_first_separators() {
        assert_eq!(cut("a#b#c", b'#'), Some(("a", "b#c")));
        assert_eq!(cut("#", b'#'), Some(("", "")));
        assert_eq!(cut("abc", b'#'), None);
        assert_eq!(scheme_of("tcp/127.0.0.1:9000"), "tcp");
        assert_eq!(scheme_of("no-scheme"), "");
        assert_eq!(
            dialled("udp/127.0.0.1:9000?rel=1#;;iface=lo;").as_deref(),
            Ok("udp/127.0.0.1:9000#iface=lo")
        );
        assert_eq!(
            dialled("tcp/127.0.0.1:9000#tout=5=6").as_deref(),
            Ok("tcp/127.0.0.1:9000#tout=5=6")
        );
    }

    /// Every link's keys have room among the values a reading keeps.
    #[test]
    fn every_links_keys_fit_the_values_kept() {
        for scheme in ["tcp", "udp", "reth"] {
            assert!(config_keys(scheme).unwrap().len() <= MAX_KEYS, "{scheme}");
        }
    }
}
