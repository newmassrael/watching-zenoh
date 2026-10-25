// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R311y453 — the NIC names an address is configured on, the data source for the §5.16
//! `interfaces` SUBJECT axis, and the subject and endpoint pair of a link built from it.
//!
//! The reading of the host's interface table (which interfaces exist, which carry multicast,
//! which index an address selects, what `#iface=` names) is `wz_host_net::link_interfaces`: those
//! are facts about the host and not about this runtime, and the cooperative host reads the same
//! table the same way. They are re-exported here at their old path. What stays is what is spelled
//! in session-core's link types: the `{src,dst}` locator pair of a link and its §5.16 subject.

pub use wz_host_net::link_interfaces::*;

use std::net::{IpAddr, SocketAddr};

use wz_session_core::link::{LinkEndpoints, LinkKind, LinkSubject};

/// R311y473 — the `{src,dst}` LOCATOR PAIR of an IP-addressed link, for the
/// adminspace's per-link view (zenoh `link_to_json`,
/// `net/runtime/adminspace.rs:608-613`).
///
/// Both ends are required: `None` when either address could not be read, which
/// is the same "could not determine" honesty [`ip_link_subject`] applies to its
/// interface set. A half-known pair rendered as a locator would be a string an
/// admin client cannot dial and cannot tell apart from one it can.
///
/// The scheme comes from [`LinkKind::locator_for`] — the single table
/// `BoundListener::advertised_locator` also delegates to — so this emitter cannot
/// repeat the R311y470 defect of shipping a log word where a scheme belongs.
///
/// R2794 (open-debt item 814) — takes the link's KIND, the same value
/// [`ip_link_subject`] takes. Every pipeline used to hand one `InterceptorLink`
/// to both, which is where the two axes were fused: this function wants the
/// kind's advertised form, the subject wants what a rule sees.
pub fn ip_link_endpoints(
    kind: LinkKind,
    local: Option<SocketAddr>,
    peer: Option<SocketAddr>,
) -> Option<LinkEndpoints> {
    Some(LinkEndpoints::new(
        kind.locator_for(&local?.to_string()),
        kind.locator_for(&peer?.to_string()),
    ))
}

/// R311y473 — the `{src,dst}` pair of a link addressed by something other than an
/// IP socket: a unix-socket path, a vsock `cid:port`, a named pipe, a serial
/// device. The caller renders each end's ADDRESS; the scheme is applied here from
/// the same single table [`ip_link_endpoints`] uses.
pub fn addressless_link_endpoints(kind: LinkKind, local: &str, peer: &str) -> LinkEndpoints {
    LinkEndpoints::new(kind.locator_for(local), kind.locator_for(peer))
}

/// The §5.16 subject of an IP-addressed link: its protocol, plus the NICs its
/// LOCAL address sits on, resolved live at link open.
///
/// `local` is the socket's own address; `None` means the pipeline could not read
/// it, which propagates as an INDETERMINATE interface set (`None`) rather than an
/// empty one — the caller could not determine the NICs, which is not the same
/// statement as "there are none".
pub fn ip_link_subject(kind: LinkKind, local: Option<SocketAddr>) -> LinkSubject {
    LinkSubject {
        kind: Some(kind),
        interfaces: local.and_then(|addr| interface_names_for(addr.ip())),
        // R2698 — no certificate is reachable from an address alone. A link
        // that HAS one fills this in afterwards with
        // [`LinkSubject::with_cert_common_name`], which is the only way it can
        // be right: the chain exists for one window inside the link's own
        // `wire_*`, and this helper is called from every IP transport including
        // the ones that never see a certificate.
        cert_common_name: None,
        cert_credential_zid: None,
    }
}

/// The §5.16 subject of a UDP multicast GROUP link, from the `#iface=` the group was joined on.
///
/// A group socket is bound to the group's own address, which no NIC holds, so
/// [`ip_link_subject`] on its local address would answer "no NIC" and a rule narrowed by
/// `interfaces` would never match a group it was written for. The interface the membership
/// was installed on is what the group is on, and the locator says which:
///
/// * a NAME (`eth0`) is the NIC, taken as written;
/// * an ADDRESS (`192.0.2.7`) is resolved to the NIC(s) that hold it, live, as any other link's
///   local address is;
/// * no `#iface=` leaves the choice to the kernel's default route, which this does not read, so
///   the set is INDETERMINATE (`None`), not empty: a rule narrowed by `interfaces` still applies,
///   which is the fail-closed reading of "could not determine".
pub fn multicast_link_subject(iface: Option<&str>) -> LinkSubject {
    let interfaces = match iface {
        None => None,
        Some(selector) => match selector.parse::<IpAddr>() {
            Ok(address) => interface_names_for(address),
            Err(_) => Some(vec![selector.to_owned()]),
        },
    };
    LinkSubject {
        kind: Some(LinkKind::Udp),
        interfaces,
        cert_common_name: None,
        cert_credential_zid: None,
    }
}

/// The §5.16 subject of a link that has no IP address at all — a unix stream
/// socket, a named pipe, a serial tty, an AF_VSOCK channel.
///
/// Its interface set is DEFINITE (`Some`), never indeterminate: a rule narrowed
/// by `interfaces` is answered rather than skipped. zenoh cannot draw that line
/// — it reports `vec![]` for a failed lookup too
/// (`io/zenoh-link-commons/src/unicast.rs:112-118`).
///
/// R2548 — THE NAMES ARE A PARAMETER, and that is the whole point of this
/// signature. It used to take only the protocol and hard-code `Some(vec![])`,
/// on the reasoning that a link with no IP address is on no NIC. That is true
/// of the WIRE and false of UPSTREAM, which gives the four addressless links
/// FOUR different answers at the pin:
///
/// * `io/zenoh-links/zenoh-link-vsock/src/unicast.rs` @ `vec!["vsock".to_string()]`
///   — a deliberate pseudo-interface, so an ACL narrowed by `interfaces` can
///   target a vsock link at all;
/// * `io/zenoh-links/zenoh-link-serial/src/unicast.rs` @ `match z_serial::get_available_port_names()`
///   — the tty device names, without the path;
/// * `io/zenoh-links/zenoh-link-unixsock_stream/src/unicast.rs` @ `vec![]`, and
///   `io/zenoh-links/zenoh-link-unixpipe/src/unix/unicast.rs` @ `vec![]` too,
///   both declaring themselves "not supported".
///
/// A helper that assumed one of those four made the other three UNEXPRESSIBLE,
/// which is why the vsock divergence could not be fixed at its own call site
/// without fixing this. Each caller now STATES its answer and can be read
/// against the upstream link it mirrors.
pub fn addressless_link_subject(kind: LinkKind, interfaces: Vec<String>) -> LinkSubject {
    LinkSubject {
        kind: Some(kind),
        interfaces: Some(interfaces),
        // R2698 — none of the four addressless links presents a peer
        // certificate, so this is a definite absence rather than an unfilled
        // field.
        cert_common_name: None,
        cert_credential_zid: None,
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// A group joined on a named NIC is on that NIC; one joined with no `#iface=` is on a NIC
    /// nobody here has read, which is "could not determine" and not "none"; one joined by
    /// address is on whichever NIC holds the address. All three are UDP.
    #[test]
    fn a_group_link_is_on_the_interface_it_was_joined_on() {
        let named = multicast_link_subject(Some("eth7"));
        assert_eq!(named.kind, Some(LinkKind::Udp));
        assert_eq!(named.interfaces, Some(vec!["eth7".to_owned()]));

        let unspecified = multicast_link_subject(None);
        assert_eq!(unspecified.kind, Some(LinkKind::Udp));
        assert_eq!(
            unspecified.interfaces, None,
            "the default route is not read: indeterminate, so a scoped rule still applies"
        );

        let by_address = multicast_link_subject(Some("127.0.0.1"));
        assert_eq!(
            by_address.interfaces,
            interface_names_for(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            "an address is resolved to the NIC that holds it, as any link's local address is"
        );
    }
}
