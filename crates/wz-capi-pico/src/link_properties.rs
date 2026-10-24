// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! What pico's link of a kind reports about itself: its MTU, whether it is a stream, and
//! whether it is reliable.
//!
//! Two planes report links in pico's words, the connectivity plane (`z_link_mtu`,
//! `z_link_is_streamed`, `z_link_is_reliable`) and the admin space's link document, and
//! the two are separate switches (`Z_FEATURE_CONNECTIVITY`, `Z_FEATURE_ADMIN_SPACE`), so
//! the table lives here rather than in either.

use wz_capi_core::runtime::session_glue::LinkKind;

/// `(mtu, is_streamed, is_reliable)` of a link, as pico's link of that kind
/// answers.
///
/// pico's five links fix all three per TYPE (`_z_get_link_mtu_tcp` and its
/// siblings, and `zl->_cap._flow` / `zl->_cap._is_reliable` beside them). A kind
/// pico has no link for keeps what the registry reports. A link whose kind the
/// driver cannot name reports pico's own zeros, which is what pico answers for a
/// transport with no link object at all
/// (`vendor/zenoh-pico/include/zenoh-pico/api/primitives.h` @
/// `static inline void _z_transport_link_properties_from_transport(`).
pub(crate) fn pico_link_properties(kind: Option<LinkKind>, reported_mtu: u16) -> (u16, bool, bool) {
    match kind {
        None => (0, false, false),
        // pico: stream, reliable, `return 65535;`.
        Some(LinkKind::Tcp) | Some(LinkKind::Tls) => (65535, true, true),
        // pico: datagram, unreliable, `return 1450;`.
        Some(LinkKind::Udp) => (1450, false, false),
        // pico: datagram, RELIABLE, `return 65535;` — the one link where the two
        // flags differ.
        Some(LinkKind::Ws) => (65535, false, true),
        // pico: datagram, unreliable, `_Z_SERIAL_MTU_SIZE`.
        Some(LinkKind::Serial) => (1500, false, false),
        Some(
            other @ (LinkKind::UdpReliable
            | LinkKind::Quic
            | LinkKind::QuicDatagram
            | LinkKind::Unixpipe
            | LinkKind::UnixsockStream
            | LinkKind::Vsock),
        ) => (reported_mtu, other.is_streamed(), other.is_reliable()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The link a face reports follows pico's table for the kinds pico has and
    /// the registry's answer for the rest.
    ///
    /// # Control
    ///
    /// Reporting the negotiated MTU for TCP (2048 from a pico peer) where pico's
    /// link says 65535 reds the first row.
    #[test]
    fn a_link_reports_what_pico_reports_for_its_kind() {
        let reported = 777;
        let table = [
            (Some(LinkKind::Tcp), (65535, true, true)),
            (Some(LinkKind::Tls), (65535, true, true)),
            (Some(LinkKind::Udp), (1450, false, false)),
            (Some(LinkKind::Ws), (65535, false, true)),
            (Some(LinkKind::Serial), (1500, false, false)),
            (None, (0, false, false)),
            // pico has no such link: the registry's answers stand.
            (Some(LinkKind::Quic), (reported, true, true)),
            (Some(LinkKind::QuicDatagram), (reported, false, false)),
            (Some(LinkKind::UdpReliable), (reported, true, true)),
            (Some(LinkKind::Unixpipe), (reported, true, true)),
        ];
        for (kind, want) in table {
            assert_eq!(pico_link_properties(kind, reported), want, "{kind:?}");
        }
        // Every kind the registry can report has a row above or an arm there;
        // this is the population, derived from the enum.
        for kind in LinkKind::ALL {
            let _ = pico_link_properties(Some(*kind), reported);
        }
    }
}
