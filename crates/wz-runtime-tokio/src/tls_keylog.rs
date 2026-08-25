// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y578 (G10) — TLS / QUIC session-key export in the NSS key-log format.
//!
//! ## Why this exists
//!
//! wz writes TLS and QUIC links but has never been able to WITNESS one. Every
//! other transport can be read back off a capture — that is what
//! [`wz_capture`](../../wz_capture/index.html) and
//! `wz_session_core::passive` are for — and an encrypted link is ciphertext to
//! all of it. That leaves wz's own TLS path proven only by "the handshake
//! completed and the bytes arrived", which is the standing debt R311y534
//! recorded as *TLS written but unwitnessed*.
//!
//! The standard answer is the key log: the same `SSLKEYLOGFILE` mechanism
//! curl, Firefox and Chrome implement, and the same file Wireshark's
//! `tls.keylog_file` preference reads. It is a text file of
//! `LABEL client_random secret` lines, one per derived secret
//! (`nss-crypto.org/reference/security/nss/legacy/key_log_format`).
//!
//! ## Why it is off unless asked for twice
//!
//! Exporting session keys makes the traffic readable to anyone holding the
//! file. That is the point, and it is also why it is not a runtime toggle
//! alone:
//!
//! 1. The `transport-link-tls-keylog` CARGO FEATURE is off by default, so a
//!    production build does not contain this code at all. A runtime-only
//!    switch would ship the capability into every binary and leave it one
//!    environment variable away from arming.
//! 2. Even in a build that has it, the log is written only when
//!    `SSLKEYLOGFILE` names a path. rustls reads that variable itself
//!    ([`rustls::KeyLogFile`]), so wz neither parses nor stores the path.
//!
//! Both conditions must hold. Neither alone arms it.

use std::sync::Arc;

use tokio_rustls::rustls::KeyLog;
// R311y578 — each arm of `key_log` uses exactly one of these, so the imports
// track the same predicate the function body does. A shared import would be
// unused in one arm under `-D warnings` (the R311y578 G7 rule, applied to
// this module's own two arms).
#[cfg(feature = "transport-link-tls-keylog")]
use tokio_rustls::rustls::KeyLogFile;
#[cfg(not(feature = "transport-link-tls-keylog"))]
use tokio_rustls::rustls::NoKeyLog;

/// The environment variable rustls reads for the log destination. Named here
/// only so callers and tests can refer to one constant; wz never reads it.
pub const KEYLOG_ENV: &str = "SSLKEYLOGFILE";

/// The key-log sink to install on a rustls config.
///
/// Returns a real [`KeyLogFile`] in a build that selected
/// `transport-link-tls-keylog`, and [`NoKeyLog`] otherwise. Callers install
/// the result unconditionally, so the two builds differ in behaviour and not
/// in control flow — a `#[cfg]` at each of the four config builders would be
/// four places to forget.
///
/// [`KeyLogFile`] is itself inert until `SSLKEYLOGFILE` is set: it resolves
/// the variable once on construction and drops every secret when it is
/// absent.
pub fn key_log() -> Arc<dyn KeyLog> {
    #[cfg(feature = "transport-link-tls-keylog")]
    {
        Arc::new(KeyLogFile::new())
    }
    #[cfg(not(feature = "transport-link-tls-keylog"))]
    {
        // Named rather than left as rustls's default so a reader of the
        // config builders sees the decision at the callsite either way.
        Arc::new(NoKeyLog)
    }
}

/// Whether this BUILD can export session keys at all.
///
/// The first of the two conditions. Exposed so a node can report its own
/// capability — an operator asking "why is my key log empty" needs to
/// distinguish a build without the feature from a build whose environment
/// variable is unset, and the two look identical from outside.
pub const fn keylog_supported() -> bool {
    cfg!(feature = "transport-link-tls-keylog")
}

/// Whether key export is ARMED right now: the feature is compiled in AND
/// `SSLKEYLOGFILE` names a destination.
///
/// Reads the environment on every call rather than caching, because the
/// answer is a statement about the process as it stands. rustls itself
/// samples the variable once per [`KeyLogFile`], so a change after a config
/// is built does not take effect — this predicate is for reporting, not for
/// deciding.
pub fn keylog_armed() -> bool {
    keylog_supported() && std::env::var_os(KEYLOG_ENV).is_some_and(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two conditions are INDEPENDENT, and the build-level one is the
    /// outer gate. Asserted against `cfg!` directly so the test states the
    /// same fact the callers rely on.
    #[test]
    fn support_is_a_build_fact_and_arming_needs_the_environment_too() {
        assert_eq!(
            keylog_supported(),
            cfg!(feature = "transport-link-tls-keylog")
        );
        if !keylog_supported() {
            assert!(
                !keylog_armed(),
                "a build without the feature can never be armed, whatever the environment says"
            );
        }
    }
}
