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

use crate::prelude::*;

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
    endpoint.split_once('/').map_or("", |(scheme, _)| scheme)
}

/// An endpoint as pico reads it with a link's `keys`.
pub(crate) struct PicoEndpoint<'a> {
    /// `<protocol>/<address>`, the metadata left out.
    pub(crate) locator: &'a str,
    keys: &'static [&'static str],
    /// The value pico keeps of each of `keys`, in their order.
    values: Vec<Option<&'a str>>,
    /// A pair with no `=` was met before the first unknown key: pico refuses the endpoint.
    malformed: bool,
}

impl<'a> PicoEndpoint<'a> {
    /// Read `endpoint` as pico's link of `keys` reads it.
    pub(crate) fn read(endpoint: &'a str, keys: &'static [&'static str]) -> Self {
        let (locator, config) = endpoint.split_once('#').unwrap_or((endpoint, ""));
        let locator = locator.split_once('?').map_or(locator, |(bare, _)| bare);
        let mut values = vec![None; keys.len()];
        let mut malformed = false;
        for pair in config.split(';').filter(|pair| !pair.is_empty()) {
            let Some((key, value)) = pair.split_once('=') else {
                malformed = true;
                break;
            };
            let Some(slot) = keys.iter().position(|known| *known == key) else {
                break;
            };
            values[slot] = Some(value);
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

    /// The pairs pico keeps, `key=value`, in its link's order of the keys.
    pub(crate) fn pairs(&self) -> impl Iterator<Item = String> + '_ {
        self.keys
            .iter()
            .zip(&self.values)
            .filter_map(|(key, value)| value.map(|value| format!("{key}={value}")))
    }
}

/// The endpoint a session of the cooperative engine dials or listens on for a unicast endpoint
/// the program wrote, read as pico reads it: what pico's link reads stays for the engine, which
/// carries it out or refuses it; the metadata and the config keys past the first one pico's link
/// does not know are left out, as pico leaves them, so `tcp/127.0.0.1:7447#iface=lo` is dialled as
/// `tcp/127.0.0.1:7447`, which pico's TCP link binds to no interface either. A scheme whose
/// config this ABI does not read goes on as written. A malformed config is refused with pico's
/// `_Z_ERR_CONFIG_INVALID_VALUE`.
#[cfg(not(feature = "engine-tokio"))]
pub(crate) fn engine_endpoint(endpoint: &str) -> Result<String, crate::result::ZResult> {
    let Some(keys) = config_keys(scheme_of(endpoint)) else {
        return Ok(endpoint.to_owned());
    };
    let read = PicoEndpoint::read(endpoint, keys);
    if read.is_malformed() {
        return Err(crate::result::Z_ERR_CONFIG_INVALID_VALUE);
    }
    let config: Vec<String> = read.pairs().collect();
    Ok(if config.is_empty() {
        read.locator.to_owned()
    } else {
        format!("{}#{}", read.locator, config.join(";"))
    })
}

#[cfg(all(test, not(feature = "engine-tokio")))]
mod tests {
    use super::*;

    /// A TCP endpoint keeps what pico's TCP link reads and loses what it does not: an interface
    /// is no key of that link, so the locator is dialled bare; the metadata goes too.
    #[test]
    fn a_tcp_endpoint_keeps_what_picos_tcp_link_reads() {
        for (written, dialled) in [
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
            assert_eq!(
                engine_endpoint(written).as_deref(),
                Ok(dialled),
                "{written}"
            );
        }
    }

    /// A UDP endpoint keeps its interface, which pico's UDP link reads, in that link's order of
    /// the keys.
    #[test]
    fn a_udp_endpoint_keeps_its_interface() {
        assert_eq!(
            engine_endpoint("udp/127.0.0.1:9000#tout=5;iface=lo").as_deref(),
            Ok("udp/127.0.0.1:9000#iface=lo;tout=5")
        );
    }

    /// A config pico cannot read is refused as pico refuses it; a scheme whose config this ABI
    /// does not read goes on as written.
    #[test]
    fn a_malformed_config_is_refused_and_an_unread_scheme_goes_as_written() {
        assert_eq!(
            engine_endpoint("tcp/127.0.0.1:9000#iface"),
            Err(crate::result::Z_ERR_CONFIG_INVALID_VALUE)
        );
        assert_eq!(
            engine_endpoint("tls/127.0.0.1:9000#root_ca_certificate=x").as_deref(),
            Ok("tls/127.0.0.1:9000#root_ca_certificate=x")
        );
    }
}
