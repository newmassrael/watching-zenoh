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

// An endpoint's text is cut at an ASCII separator by the locator grammar's one cut, which reads it a
// byte at a time and searches for no character's encoding.
use wz_session_core::locator_grammar::{split_byte, split_once_byte as cut};

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
        // Read into the value handed back, so the values are not built apart and then moved in.
        let mut read = Self {
            locator,
            keys,
            values: [None; MAX_KEYS],
            malformed: false,
        };
        // The pairs between the `;`, an empty one skipped.
        for pair in split_byte(config, b';') {
            if pair.is_empty() {
                continue;
            }
            let Some((key, value)) = cut(pair, b'=') else {
                read.malformed = true;
                break;
            };
            // A key past the room the values have is read as one the link does not know.
            let Some(slot) = keys
                .iter()
                .position(|known| *known == key)
                .and_then(|slot| read.values.get_mut(slot))
            else {
                break;
            };
            *slot = Some(value);
        }
        read
    }

    /// Whether pico refuses the endpoint for a malformed config.
    pub(crate) fn is_malformed(&self) -> bool {
        self.malformed
    }

    /// Hands `put` the text pico keeps of the endpoint, piece by piece: the locator, then, when
    /// a pair is kept, `separator` and the pairs, `key=value`, in its link's order of the keys,
    /// joined by `;`.
    ///
    /// One loop over the keys, a key with no value passed over in it, and out of line, so the
    /// link's keys are read as data: inlined with them known, or with a search for the next kept
    /// pair of its own, the compiler writes the loop out once per key the longest link has and
    /// its first pair apart from the rest.
    #[inline(never)]
    fn write_text(&self, separator: &str, mut put: impl FnMut(&str)) {
        put(self.locator);
        let mut before = separator;
        for (at, &key) in self.keys.iter().enumerate() {
            let Some(&Some(value)) = self.values.get(at) else {
                continue;
            };
            put(before);
            put(key);
            put("=");
            put(value);
            before = ";";
        }
    }

    /// The bytes of the text pico keeps of the endpoint ([`Self::write_text`]).
    #[cfg(any(test, feature = "connectivity"))]
    pub(crate) fn text_len(&self, separator: &str) -> usize {
        let mut len = 0usize;
        self.write_text(separator, |piece| len = len.saturating_add(piece.len()));
        len
    }

    /// The text pico keeps of the endpoint ([`Self::write_text`]), made once at its length: the
    /// one copy of it its holder keeps.
    #[cfg(feature = "connectivity")]
    pub(crate) fn text(&self, separator: &str) -> alloc::string::String {
        let mut text = alloc::string::String::with_capacity(self.text_len(separator));
        self.write_text(separator, |piece| text.push_str(piece));
        text
    }
}

/// Whether a unicast endpoint the program wrote can be handed to a session of the cooperative
/// engine as pico reads it ([`with_engine_text`]): a scheme this build has no link for is refused
/// first, with pico's `_Z_ERR_CONFIG_LOCATOR_SCHEMA_UNKNOWN` ([`link_built`]), a malformed config
/// with pico's
/// `_Z_ERR_CONFIG_INVALID_VALUE`, and a kept text past the build's `MAX_LOCATOR_LEN`, the bound
/// every locator text of a session is held to, with pico's `_Z_ERR_SYSTEM_OUT_OF_MEMORY`, what its
/// reading of a config answers when it has no memory to hold a value in
/// (`vendor/zenoh-pico/src/protocol/config.c` @ `ret = _Z_ERR_SYSTEM_OUT_OF_MEMORY;`). Judged
/// before anything is opened, by the reading the engine's text is made by ([`kept_text`]), into a
/// locator text of the stack that is let go of here.
#[cfg(not(feature = "engine-tokio"))]
pub(crate) fn checked_endpoint(endpoint: &str) -> Result<(), crate::result::ZResult> {
    let scheme = scheme_of(endpoint);
    // A text with no scheme is the engine's to refuse, as an endpoint it cannot read.
    if !scheme.is_empty() && !link_built(scheme) {
        return Err(crate::result::Z_ERR_CONFIG_LOCATOR_SCHEMA_UNKNOWN);
    }
    kept_text(
        endpoint,
        &mut wz_session_core::locator_directory::LocatorText::new(),
    )
    .map(|_| ())
}

/// Whether this build has a link for `scheme`, as zenoh-pico's build has one for each link its
/// switches compile in and answers any other scheme `_Z_ERR_CONFIG_LOCATOR_SCHEMA_UNKNOWN` before
/// it opens anything (`vendor/zenoh-pico/src/link/link.c` @ `z_result_t _z_open_link(`, whose
/// last arm is `ret = _Z_ERR_CONFIG_LOCATOR_SCHEMA_UNKNOWN;`). The cooperative engine dials and
/// listens on `tcp/` in every build, as pico's TCP link is in every build of it; `udp/` with
/// pico's unicast UDP link (`link-udp`, `Z_FEATURE_LINK_UDP_UNICAST`), `tls/` with its secure
/// channel (`tls-mbedtls`), `serial/` with the host's ttys (`transport-link-serial`),
/// `unixpipe/`, which pico has no link for, with the host's named FIFOs
/// (`transport-link-unixpipe`, on Linux and Android; inert on a host with none), and `ws/` with WebSocket links over the host's TCP
/// (`transport-link-ws`). A group is no unicast endpoint and is not judged here.
#[cfg(not(feature = "engine-tokio"))]
fn link_built(scheme: &str) -> bool {
    match scheme {
        "tcp" => true,
        "udp" => cfg!(feature = "link-udp"),
        "tls" => cfg!(feature = "tls-mbedtls"),
        "serial" => cfg!(feature = "transport-link-serial"),
        "ws" => cfg!(feature = "transport-link-ws"),
        "unixpipe" => cfg!(all(
            feature = "transport-link-unixpipe",
            any(target_os = "linux", target_os = "android")
        )),
        _ => false,
    }
}

/// `use_text` handed a unicast endpoint the program wrote as pico reads it, for a session of the
/// cooperative engine to dial or listen on: what pico's link reads stays for the engine, which
/// carries it out or refuses it; the metadata and the config keys past the first one pico's link
/// does not know are left out, as pico leaves them, so `tcp/127.0.0.1:7447#iface=lo` is dialled as
/// `tcp/127.0.0.1:7447`, which pico's TCP link binds to no interface either. A scheme whose
/// config this ABI does not read goes on as written.
///
/// The text is made in a locator text of the stack, the form of the row the engine writes it
/// into, so no text of an endpoint is a value of the heap. One [`checked_endpoint`] refused is
/// handed over as written, for the engine to refuse by name.
#[cfg(not(feature = "engine-tokio"))]
pub(crate) fn with_engine_text<R>(endpoint: &str, use_text: impl FnOnce(&str) -> R) -> R {
    let mut kept = wz_session_core::locator_directory::LocatorText::new();
    use_text(kept_text(endpoint, &mut kept).unwrap_or(endpoint))
}

/// What pico's link for the scheme of `endpoint` keeps of it, made in `kept`, or `endpoint`
/// itself for a scheme whose config this ABI does not read; refused as [`checked_endpoint`] says,
/// a kept text past `kept`'s room being one past `MAX_LOCATOR_LEN`. The one reading of an
/// endpoint the check before the open and the text the engine is handed both make: out of line and
/// generic over nothing, so they cannot read an endpoint differently and the code is one copy.
#[cfg(not(feature = "engine-tokio"))]
#[inline(never)]
fn kept_text<'a>(
    endpoint: &'a str,
    kept: &'a mut wz_session_core::locator_directory::LocatorText,
) -> Result<&'a str, crate::result::ZResult> {
    let Some(keys) = config_keys(scheme_of(endpoint)) else {
        return Ok(endpoint);
    };
    let read = PicoEndpoint::read(endpoint, keys);
    if read.is_malformed() {
        return Err(crate::result::Z_ERR_CONFIG_INVALID_VALUE);
    }
    let mut fits = true;
    read.write_text("#", |piece| fits = fits && keep_piece(kept, piece));
    if fits {
        Ok(kept.as_str())
    } else {
        Err(crate::result::Z_ERR_SYSTEM_OUT_OF_MEMORY)
    }
}

/// `piece` appended to `kept` with one copy; `false`, and `kept` as it was, when it has no room
/// for it. Out of line: the text is written a piece at a time, and each piece of each pair would
/// carry the copy of its own.
#[cfg(not(feature = "engine-tokio"))]
#[inline(never)]
fn keep_piece(kept: &mut wz_session_core::locator_directory::LocatorText, piece: &str) -> bool {
    wz_session_core::bounded::push_text(kept, piece).is_ok()
}

#[cfg(all(test, not(feature = "engine-tokio")))]
mod tests {
    use super::*;
    use crate::prelude::*;
    use crate::result::{
        ZResult, Z_ERR_CONFIG_INVALID_VALUE, Z_ERR_CONFIG_LOCATOR_SCHEMA_UNKNOWN,
        Z_ERR_SYSTEM_OUT_OF_MEMORY,
    };
    use wz_session_core::caps::MAX_LOCATOR_LEN;

    /// The endpoint the engine is handed for `written`, whose config pico's link for its scheme
    /// reads whether or not this build has that link.
    fn dialled(written: &str) -> Result<String, ZResult> {
        kept_text(
            written,
            &mut wz_session_core::locator_directory::LocatorText::new(),
        )
        .map(|_| ())?;
        Ok(with_engine_text(written, |text: &str| String::from(text)))
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

    /// The kept pairs follow the link's order of its keys whatever order they were written in, a
    /// key with no value passed over: the separator comes before the first pair kept, which need
    /// not be the link's first key, and `;` between the rest. Turned red by a separator written
    /// before the link's first key only, or by a pair kept in the order it was written.
    #[test]
    fn the_kept_pairs_follow_the_links_order_and_pass_over_a_key_with_no_value() {
        for (written, expected) in [
            // The link's first key has no value: the separator comes before its second.
            (
                "udp/127.0.0.1:9000#join=1;tout=5",
                "udp/127.0.0.1:9000#tout=5;join=1",
            ),
            // The key between two kept ones has no value.
            (
                "udp/127.0.0.1:9000#join=1;iface=lo",
                "udp/127.0.0.1:9000#iface=lo;join=1",
            ),
            // Only the link's last key is kept.
            ("udp/127.0.0.1:9000#join=1", "udp/127.0.0.1:9000#join=1"),
            (
                "udp/127.0.0.1:9000#join=1;tout=5;iface=lo",
                "udp/127.0.0.1:9000#iface=lo;tout=5;join=1",
            ),
            (
                "reth/eth0#whitelist=a;ethtype=8",
                "reth/eth0#ethtype=8;whitelist=a",
            ),
        ] {
            assert_eq!(dialled(written).as_deref(), Ok(expected), "{written}");
            let read = PicoEndpoint::read(written, config_keys(scheme_of(written)).unwrap());
            assert_eq!(read.text_len("#"), expected.len(), "{written}");
        }
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
        assert_eq!(
            with_engine_text("udp/127.0.0.1:9000#tout=5;iface=lo", |text: &str| {
                String::from(text)
            }),
            kept
        );

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

    /// A piece is kept whole or not at all: one that fills the text to its room is taken, and one
    /// past it leaves the text as it was. Turned red by a piece written in part.
    #[test]
    fn a_piece_past_the_room_leaves_the_kept_text_as_it_was() {
        let mut kept = wz_session_core::locator_directory::LocatorText::new();
        let head = "h".repeat(MAX_LOCATOR_LEN - 1);
        assert!(keep_piece(&mut kept, &head));
        assert!(!keep_piece(&mut kept, "ab"));
        assert_eq!(kept.as_str(), head);
        assert!(keep_piece(&mut kept, "a"));
        assert_eq!(kept.as_str().len(), MAX_LOCATOR_LEN);
        assert!(!keep_piece(&mut kept, "b"));
    }

    /// An endpoint's text is cut at the first of each separator: the metadata goes, an empty pair
    /// is skipped, a value keeps an `=` of its own, and a text with no scheme names none.
    #[test]
    fn an_endpoint_is_cut_at_its_first_separators() {
        assert_eq!(cut("a#b#c", b'#'), Some(("a", "b#c")));
        assert_eq!(cut("#", b'#'), Some(("", "")));
        assert_eq!(cut("abc", b'#'), None);
        // Characters of more than one byte on either side of the cut are kept whole.
        assert_eq!(cut("\u{e9}#\u{fc}x", b'#'), Some(("\u{e9}", "\u{fc}x")));
        assert_eq!(cut("\u{e9}#", b'#'), Some(("\u{e9}", "")));
        assert_eq!(cut("\u{e9}\u{fc}", b'#'), None);
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

    /// An endpoint the check refuses is handed to the engine as written, for the engine to refuse
    /// by name, and one it takes is handed as the check read it: the two are one reading. Turned
    /// red by a text handed over in place of a refused endpoint, or by a check that reads the
    /// endpoint apart from the text.
    #[test]
    fn a_refused_endpoint_is_handed_over_as_written() {
        let host = "h".repeat(MAX_LOCATOR_LEN);
        let long = format!("tcp/{host}:9000#iface=lo");
        assert_eq!(checked_endpoint(&long), Err(Z_ERR_SYSTEM_OUT_OF_MEMORY));
        assert_eq!(
            with_engine_text(&long, |text: &str| String::from(text)),
            long
        );
        let malformed = "tcp/127.0.0.1:9000#tout";
        assert_eq!(checked_endpoint(malformed), Err(Z_ERR_CONFIG_INVALID_VALUE));
        assert_eq!(
            with_engine_text(malformed, |text: &str| String::from(text)),
            malformed
        );
        let unread = "tls/127.0.0.1:9000#root_ca_certificate=x";
        let unread_checked = if cfg!(feature = "tls-mbedtls") {
            Ok(())
        } else {
            Err(Z_ERR_CONFIG_LOCATOR_SCHEMA_UNKNOWN)
        };
        assert_eq!(checked_endpoint(unread), unread_checked);
        assert_eq!(
            with_engine_text(unread, |text: &str| String::from(text)),
            unread
        );
    }

    /// A scheme this build has no link for is refused before anything is opened, as zenoh-pico
    /// refuses one its switches left out; one it has goes on to the reading of its config, and a
    /// text with no scheme to the engine. Turned red by a scheme judged built that no link of the
    /// build opens, or by a built one refused.
    #[test]
    fn a_scheme_without_a_link_in_this_build_is_unknown() {
        for unknown in ["quic/127.0.0.1:7447", "reth/eth0", "tlsx/127.0.0.1:7447"] {
            assert_eq!(
                checked_endpoint(unknown),
                Err(Z_ERR_CONFIG_LOCATOR_SCHEMA_UNKNOWN),
                "{unknown}"
            );
        }
        for built in ["tcp/127.0.0.1:7447", "no-scheme"] {
            assert_eq!(checked_endpoint(built), Ok(()), "{built}");
        }
        for (endpoint, built) in [
            ("udp/127.0.0.1:7447", cfg!(feature = "link-udp")),
            ("tls/127.0.0.1:7447", cfg!(feature = "tls-mbedtls")),
            (
                "serial//dev/ttyS0#baudrate=9600",
                cfg!(feature = "transport-link-serial"),
            ),
            ("ws/127.0.0.1:7447", cfg!(feature = "transport-link-ws")),
            (
                "unixpipe//tmp/wz-pipe#file_mask=384",
                cfg!(all(
                    feature = "transport-link-unixpipe",
                    any(target_os = "linux", target_os = "android")
                )),
            ),
        ] {
            let expected = if built {
                Ok(())
            } else {
                Err(Z_ERR_CONFIG_LOCATOR_SCHEMA_UNKNOWN)
            };
            assert_eq!(checked_endpoint(endpoint), expected, "{endpoint}");
        }
    }

    /// Every link's keys have room among the values a reading keeps.
    #[test]
    fn every_links_keys_fit_the_values_kept() {
        for scheme in ["tcp", "udp", "reth"] {
            assert!(config_keys(scheme).unwrap().len() <= MAX_KEYS, "{scheme}");
        }
    }
}
