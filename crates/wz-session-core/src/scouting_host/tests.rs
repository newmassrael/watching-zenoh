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
        zid: [zid].into(),
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

/// A scouting window does not record a Hello whose zid is zero: it is no Hello, as for zenoh's
/// decoder. The same Hello naming a zid is recorded with it.
#[test]
fn a_hello_naming_a_zero_zid_is_not_a_scouted_hello() {
    let hello_of = |zid: &[u8]| {
        let mut hello = wz_codecs::lent::Hello::new();
        hello.version = wire_const::PROTOCOL_VERSION;
        hello.set_whatami(0x01);
        hello.set_zid_len_m1((zid.len() - 1) as u8);
        hello.zid = wz_codecs::Bounded::new(zid).unwrap();
        let mut wire = vec![wire_const::S_MID_HELLO];
        wire.extend_from_slice(&hello.encode_to_vec());
        wire
    };
    assert!(decode_scouted_hello(&hello_of(&[0, 0])).is_none());
    let named = decode_scouted_hello(&hello_of(&[0, 0x01])).expect("a Hello naming a zid");
    assert_eq!(named.zid, vec![0, 0x01]);
}

/// A row keeps a Hello's locators up to its bounds and counts the rest: one of exactly
/// `MAX_LOCATOR_LEN` bytes is kept, a longer one skipped, never cut short, and one past
/// `SCOUT_HELLO_LOCATORS` skipped; what is kept reads back in wire order. Turned red by a row that
/// cuts a locator short or keeps one past its text.
#[test]
fn a_row_keeps_locators_up_to_its_bounds_and_counts_the_rest() {
    let exact = "e".repeat(caps::MAX_LOCATOR_LEN);
    let long = "l".repeat(caps::MAX_LOCATOR_LEN + 1);
    let mut scouted = hello(0x42);
    scouted.locators.push(exact.clone());
    scouted.locators.push(long);
    for k in 0..caps::SCOUT_HELLO_LOCATORS {
        scouted.locators.push(alloc::format!("tcp/10.0.0.{k}:7447"));
    }
    let row = HelloRow::of(&scouted);
    assert_eq!(HelloFacts::locator_count(&row), caps::SCOUT_HELLO_LOCATORS);
    assert_eq!(row.skipped_locators(), 2);
    assert_eq!(row.advertised_locators(), scouted.locators.len());
    assert_eq!(HelloFacts::locator(&row, 0), Some(exact.as_str()));
    let kept: Vec<&str> = row.locators().collect();
    let expected: Vec<&str> = core::iter::once(exact.as_str())
        .chain(scouted.locators[2..].iter().map(String::as_str))
        .take(caps::SCOUT_HELLO_LOCATORS)
        .collect();
    assert_eq!(kept, expected);
    assert_eq!(row.to_hello().locators, expected);
    assert_eq!(row.zid, scouted.zid);
}

/// A table records `MAX_SCOUT_HELLOS` Hellos and refuses one more, which it counts, and its rows are
/// delivered last responder first, lent, as a host's list is. Turned red by a table that grows
/// past its rows.
#[test]
fn a_table_holds_its_rows_and_refuses_one_more() {
    let mut table = alloc::boxed::Box::new(HelloTable::new());
    for zid in 1..=caps::MAX_SCOUT_HELLOS {
        assert!(table.push(&HelloRow::of(&hello(zid as u8))), "row {zid}");
    }
    assert!(!table.push(&HelloRow::of(&hello(0xEE))));
    assert_eq!(table.len(), caps::MAX_SCOUT_HELLOS);
    assert_eq!(table.refused(), 1);
    assert_eq!(table.first().map(|row| row.zid[0]), Some(1));
    let mut seen = Vec::new();
    let delivered = deliver_rows_in_upstream_order(&table, |row| seen.push(row.zid[0]));
    assert_eq!(delivered, caps::MAX_SCOUT_HELLOS);
    let expected: Vec<u8> = (1..=caps::MAX_SCOUT_HELLOS)
        .rev()
        .map(|zid| zid as u8)
        .collect();
    assert_eq!(seen, expected);
}

/// A Hello decoded into a row in place, with no heap, is the row of the Hello the host's decoder
/// makes, and a Hello naming a zero zid is no row, as it is no scouted Hello.
#[test]
fn a_row_decoded_with_no_heap_is_the_scouted_hellos_row() {
    let hello_of = |zid: &[u8]| {
        let mut hello = wz_codecs::lent::Hello::new();
        hello.version = wire_const::PROTOCOL_VERSION;
        hello.set_whatami(0x01);
        hello.set_zid_len_m1((zid.len() - 1) as u8);
        hello.zid = wz_codecs::Bounded::new(zid).unwrap();
        let mut wire = vec![wire_const::S_MID_HELLO];
        wire.extend_from_slice(&hello.encode_to_vec());
        wire
    };
    let mut row = HelloRow::EMPTY;
    assert!(!row.decode_into(&hello_of(&[0, 0])));
    let wire = hello_of(&[0, 0x01]);
    let scouted = decode_scouted_hello(&wire).expect("a Hello naming a zid");
    assert!(row.decode_into(&wire));
    assert_eq!(row, HelloRow::of(&scouted));
    let mut table = alloc::boxed::Box::new(HelloTable::new());
    assert!(table.push(&row));
    table.clear();
    assert!(
        table.is_empty() && table.refused() == 0,
        "a cleared table holds nothing"
    );
}
