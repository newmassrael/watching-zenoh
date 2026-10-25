use super::*;

use alloc::vec;

/// The locator grammar, including the two shapes that must be REJECTED rather than silently
/// defaulted — a scout onto a mis-parsed group finds nothing and looks like a network problem.
#[test]
fn the_multicast_locator_grammar_is_exact() {
    use core::net::IpAddr;

    assert_eq!(
        parse_multicast_locator(MULTICAST_LOCATOR_DEFAULT),
        Some((IpAddr::from([224, 0, 0, 224]), 7446))
    );
    assert!(parse_multicast_locator("tcp/224.0.0.224:7446").is_none());
    assert!(parse_multicast_locator("udp/224.0.0.224").is_none());
    assert!(parse_multicast_locator("").is_none());
    // An IPv6 group is bracketed, and an unbracketed one is not a socket address.
    assert_eq!(
        parse_multicast_locator("udp/[ff05::231]:7446"),
        Some((IpAddr::from([0xff05, 0, 0, 0, 0, 0, 0, 0x231]), 7446))
    );
    assert!(parse_multicast_locator("udp/ff05::231:7446").is_none());
}

fn hello(zid: u8) -> ScoutedHello {
    ScoutedHello {
        version: 0x09,
        whatami: None,
        zid: vec![zid],
        locators: Vec::new(),
    }
}

/// Both C ABIs' `z_scout` hand their closure the LAST responder first, because upstream's
/// accumulator is built by PREPENDING and `_z_scout` drains from the head.
///
/// The window records in arrival order, so this seam is the only place the two orders meet. Three
/// peers, not two: a two-element reversal is also a swap, a rotation, and a sort — three tells
/// them apart.
#[test]
fn the_closure_sees_the_last_responder_first() {
    let recorded = [hello(0xA1), hello(0xB2), hello(0xC3)];
    let mut seen = Vec::new();
    let n = deliver_in_upstream_order(&recorded, |h| seen.push(h.zid[0]));
    assert_eq!(n, 3, "every recorded peer is delivered");
    assert_eq!(
        seen,
        vec![0xC3, 0xB2, 0xA1],
        "reverse arrival order — upstream's slist is newest-first"
    );
}

/// The empty window delivers nothing and says so, which is the count both C ABIs' `z_scout` use
/// to decide between upstream's "Did not find any zenoh process." and "Dropping scout results."
/// lines.
#[test]
fn an_empty_window_delivers_nothing() {
    let mut seen = 0usize;
    assert_eq!(deliver_in_upstream_order(&[], |_| seen += 1), 0);
    assert_eq!(seen, 0);
}
