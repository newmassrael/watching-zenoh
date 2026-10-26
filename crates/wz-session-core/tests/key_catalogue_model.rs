// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The model test of the closed key set's table (`docs/closed-key-set.md`, decision D3): what the
//! generator precomputed is what the matcher the receive path runs answers.
//!
//! Three things are compared, because each is the other's only check:
//!
//! * every pair of keys over a small vocabulary: the generator's port of the matcher
//!   (`scripts/lib/wz_key_set.py`) against `keyexpr_intersects_text`, in both orders;
//! * every selection of the fixture's table against `keyexpr_intersects_text` over the entities
//!   it was derived from, and against the subscriber table's own scan, which is what a message
//!   on that key is delivered by today;
//! * the table's own reads: an id is its text's place, a text that is not declared is not found.
//!
//! The fixture and the corpus are generated; `wz_key_set.py --check` fails when either is stale.
#![cfg(all(
    feature = "key-set-closed",
    feature = "keyexpr-wildcard-single",
    feature = "keyexpr-wildcard-double",
    feature = "keyexpr-dollar-star"
))]

#[path = "key_set_data/corpus.rs"]
mod corpus;
// The generated table is a module of its own (`key_set`) that a file includes, as a node's
// generated `declared.rs` does.
mod fixture {
    include!("key_set_data/fixture.rs");
}

use fixture::key_set::{CATALOGUE, DECLARED};
use wz_session_core::key_catalogue::{EntityId, EntityKind, KeyId};
use wz_session_core::keyexpr_match::keyexpr_intersects_text;

fn key_ids() -> impl Iterator<Item = KeyId> {
    (0..CATALOGUE.key_count()).map(|index| KeyId::new(u16::try_from(index).expect("a u16 key")))
}

/// What the matcher says a key and a kind select over the declaration: the oracle.
fn expected(key: &str, kind: EntityKind) -> Vec<EntityId> {
    DECLARED
        .iter()
        .enumerate()
        .filter(|(_, (declared, pattern))| {
            *declared == kind && keyexpr_intersects_text(pattern, key)
        })
        .map(|(number, _)| EntityId::new(u16::try_from(number).expect("a u16 entity")))
        .collect()
}

#[test]
fn every_selection_is_what_the_glob_matcher_says() {
    let mut cells = 0usize;
    let mut selected = 0usize;
    let mut widest = 0usize;
    for key in key_ids() {
        let text = CATALOGUE.text(key);
        for kind in EntityKind::ALL {
            let want = expected(text, kind);
            let got = CATALOGUE.selection(key, kind);
            assert_eq!(got.as_slice(), want.as_slice(), "{kind:?} on `{text}`");
            // The matcher is symmetric, so the answer does not depend on which side is the key.
            for entity in &want {
                let (_, pattern) = DECLARED[entity.index()];
                assert!(
                    keyexpr_intersects_text(text, pattern),
                    "`{text}` against `{pattern}`"
                );
            }
            cells += 1;
            selected += want.len();
            widest = widest.max(want.len());
        }
    }
    // The fixture is not vacuous: it has cells, most kinds select something, and a wildcard key
    // selects several entities at once.
    assert_eq!(cells, CATALOGUE.key_count() * EntityKind::ALL.len());
    assert!(selected > cells, "selected {selected} over {cells} cells");
    assert!(widest >= 4, "the widest selection is {widest}");
}

#[cfg(feature = "alloc")]
#[test]
fn a_selection_is_the_subscriber_tables_own_answer() {
    use std::cell::RefCell;
    use std::rc::Rc;
    use wz_session_core::locality::Locality;
    use wz_session_core::pubsub::SubscriberTable;
    use wz_session_core::sample::Sample;
    use wz_session_core::sink::{SampleSink, SampleView};

    struct Tagged {
        tag: usize,
        fired: Rc<RefCell<Vec<usize>>>,
    }
    impl SampleSink for Tagged {
        fn deliver(&mut self, _sample: &dyn SampleView) {
            self.fired.borrow_mut().push(self.tag);
        }
    }

    let fired = Rc::new(RefCell::new(Vec::new()));
    let mut table: SubscriberTable<Tagged> = SubscriberTable::with_sink_backing();
    let subscribers: Vec<usize> = DECLARED
        .iter()
        .enumerate()
        .filter(|(_, (kind, _))| *kind == EntityKind::Subscriber)
        .map(|(number, _)| number)
        .collect();
    for &number in &subscribers {
        let sink = Tagged {
            tag: number,
            fired: Rc::clone(&fired),
        };
        table
            .register_sink(DECLARED[number].1, Locality::Any, sink)
            .expect("the subscriber table holds the fixture's subscribers");
    }
    for key in key_ids() {
        let text = CATALOGUE.text(key);
        fired.borrow_mut().clear();
        table.local_publish(&Sample::new_put(text, Vec::new()));
        let mut scanned: Vec<usize> = fired.borrow().clone();
        scanned.sort_unstable();
        let selection: Vec<usize> = CATALOGUE
            .selection(key, EntityKind::Subscriber)
            .iter()
            .map(EntityId::index)
            .collect();
        assert_eq!(selection, scanned, "subscribers of `{text}`");
    }
}

/// Register the fixture's subscribers in `table`, each a counting sink that records its entity
/// number in `fired`.
#[cfg(feature = "alloc")]
fn register_the_fixtures_subscribers(
    table: &mut wz_session_core::pubsub::SubscriberTable<Counted>,
    fired: &std::rc::Rc<std::cell::RefCell<Vec<usize>>>,
) {
    use std::rc::Rc;
    use wz_session_core::locality::Locality;

    for (number, (kind, pattern)) in DECLARED.iter().enumerate() {
        if *kind != EntityKind::Subscriber {
            continue;
        }
        let sink = Counted {
            tag: number,
            fired: Rc::clone(fired),
        };
        table
            .register_sink(pattern, Locality::Any, sink)
            .expect("the subscriber table holds the fixture's subscribers");
    }
}

/// A subscriber table with the fixture's subscribers registered, each a counting sink.
#[cfg(feature = "alloc")]
fn table_of_the_fixtures_subscribers() -> (
    wz_session_core::pubsub::SubscriberTable<Counted>,
    std::rc::Rc<std::cell::RefCell<Vec<usize>>>,
) {
    use std::cell::RefCell;
    use std::rc::Rc;
    use wz_session_core::pubsub::SubscriberTable;

    let fired = Rc::new(RefCell::new(Vec::new()));
    let mut table: SubscriberTable<Counted> = SubscriberTable::with_sink_backing();
    register_the_fixtures_subscribers(&mut table, &fired);
    (table, fired)
}

#[cfg(feature = "alloc")]
struct Counted {
    tag: usize,
    fired: std::rc::Rc<std::cell::RefCell<Vec<usize>>>,
}

#[cfg(feature = "alloc")]
impl wz_session_core::sink::SampleSink for Counted {
    fn deliver(&mut self, _sample: &dyn wz_session_core::sink::SampleView) {
        self.fired.borrow_mut().push(self.tag);
    }
}

#[cfg(feature = "alloc")]
#[test]
fn a_closed_table_drops_a_peers_key_outside_the_set_and_an_open_one_does_not() {
    use wz_session_core::key_gate::KeyGate;
    use wz_session_core::sample::Sample;

    // `lab/**` and `**` cover `lab/sensor/pressure`, which the image does not declare.
    let undeclared = Sample::new_put("lab/sensor/pressure", Vec::new());
    let declared = Sample::new_put("lab/sensor/temp", Vec::new());

    let (mut open, fired) = table_of_the_fixtures_subscribers();
    assert!(
        !KeyGate::of_build().is_closed(),
        "this test runs on an open build"
    );
    assert!(open.dispatch_borrowed(&undeclared, true) > 0);
    assert!(!fired.borrow().is_empty());
    assert_eq!(open.key_gate_refused().total, 0);

    let (mut closed, fired) = table_of_the_fixtures_subscribers();
    closed.set_key_gate(KeyGate::closed(&CATALOGUE));
    // A peer's message on a key outside the set reaches no subscriber, and is counted.
    assert_eq!(closed.dispatch_borrowed(&undeclared, true), 0);
    assert!(fired.borrow().is_empty());
    assert_eq!(closed.key_gate_refused().outside_set, 1);
    // A peer's message on a declared key reaches exactly the subscribers its selection names.
    let key = CATALOGUE.find_exact("lab/sensor/temp").expect("declared");
    let selection = CATALOGUE.selection(key, EntityKind::Subscriber).len();
    assert_eq!(closed.dispatch_borrowed(&declared, true), selection);
    assert_eq!(fired.borrow().len(), selection);
    assert_eq!(closed.key_gate_refused().total, 1);
    // The application's own publish is not a peer's message and is not gated.
    fired.borrow_mut().clear();
    assert!(closed.dispatch_borrowed(&undeclared, false) > 0);
    assert_eq!(closed.key_gate_refused().total, 1);
}

/// What every delivery of a peer's message on `text` fired, in the order it fired.
#[cfg(feature = "alloc")]
fn fired_on(
    table: &mut wz_session_core::pubsub::SubscriberTable<Counted>,
    fired: &std::rc::Rc<std::cell::RefCell<Vec<usize>>>,
    text: &str,
) -> Vec<usize> {
    fired.borrow_mut().clear();
    let sample = wz_session_core::sample::Sample::new_put(text, Vec::new());
    let count = table.dispatch_borrowed(&sample, true);
    let seen = fired.borrow().clone();
    assert_eq!(count, seen.len(), "the count is what fired, on `{text}`");
    seen
}

#[cfg(feature = "alloc")]
#[test]
fn delivery_by_selection_is_what_the_scan_delivers_in_the_order_it_delivers() {
    use wz_session_core::key_gate::KeyGate;

    let (mut scanned, scanned_fired) = table_of_the_fixtures_subscribers();

    // The gate is given first, so every subscription is made under it and numbered by it.
    let fired = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let mut numbered: wz_session_core::pubsub::SubscriberTable<Counted> =
        wz_session_core::pubsub::SubscriberTable::with_sink_backing();
    numbered.set_key_gate(KeyGate::closed(&CATALOGUE));
    register_the_fixtures_subscribers(&mut numbered, &fired);

    let mut compared = 0usize;
    let mut delivered = 0usize;
    for key in key_ids() {
        let text = CATALOGUE.text(key);
        let want = fired_on(&mut scanned, &scanned_fired, text);
        let got = fired_on(&mut numbered, &fired, text);
        assert_eq!(got, want, "subscribers of `{text}`, in registration order");
        compared += 1;
        delivered += got.len();
    }
    assert_eq!(compared, CATALOGUE.key_count());
    assert!(
        delivered > compared,
        "the keys reach several subscribers each, {delivered}"
    );
    assert_eq!(numbered.key_gate_refused().total, 0);
}

#[test]
fn every_bit_of_the_peer_allowance_is_what_the_matcher_says() {
    use fixture::key_set::{ALLOWED_PEERS, ALLOW_DECLARED};
    use wz_session_core::key_allowance::PeerOp;
    use wz_session_core::keyexpr_match::{is_wild, keyexpr_intersects_text};

    let allowance = ALLOWED_PEERS.expect("the fixture declares peers");
    assert_eq!(allowance.class_count(), ALLOW_DECLARED.len());
    let (mut allowed, mut refused, mut wildcard_keys) = (0usize, 0usize, 0usize);
    for (zid, op, patterns) in ALLOW_DECLARED {
        let class = allowance.class_of(&zid).expect("a declared peer has a row");
        let op = PeerOp::ALL[op];
        for key in key_ids() {
            let text = CATALOGUE.text(key);
            // A key is allowed when it is concrete and some listed pattern intersects it.
            let want = !is_wild(text)
                && patterns
                    .iter()
                    .any(|pattern| keyexpr_intersects_text(pattern, text));
            assert_eq!(
                allowance.allows(class, op, key),
                want,
                "peer {zid:?}, `{text}`, against {patterns:?}"
            );
            allowed += usize::from(want);
            refused += usize::from(!want);
            wildcard_keys += usize::from(is_wild(text));
        }
    }
    // Not vacuous: both answers occur, and the keys that are patterns were all refused.
    assert!(
        allowed > 10 && refused > allowed,
        "{allowed} allowed, {refused} refused"
    );
    assert!(wildcard_keys > 0);
    // `**` does not cross the verbatim chunk, so the peer allowed `**` still may not use `@/lab/adv`.
    let c3 = allowance
        .class_of(&[0xC3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        .expect("declared");
    let adv = CATALOGUE.find_exact("@/lab/adv").expect("declared");
    let set = CATALOGUE.find_exact("lab/ctl/set").expect("declared");
    assert!(!allowance.allows(c3, PeerOp::Publish, adv));
    assert!(allowance.allows(c3, PeerOp::Publish, set));
    // A peer that is not declared has no row.
    assert_eq!(allowance.class_of(&[9; 16]), None);
}

#[test]
fn a_gate_with_the_fixtures_allowance_asks_the_peer_what_it_may_publish() {
    use fixture::key_set::{ALLOWED_PEERS, CLOSED};
    use wz_session_core::key_allowance::PeerOp;
    use wz_session_core::key_gate::{KeyGate, Refusal};

    // What a node does with its generated file: the table, then the allowance.
    let table = CLOSED.expect("closed");
    let peers = ALLOWED_PEERS.expect("declared peers");
    let mut gate = KeyGate::closed(table).with_allowance(peers);
    let zid = |first: u8| {
        let mut bytes = [0u8; 16];
        bytes[0] = first;
        bytes
    };
    let a1 = peers.class_of(&zid(0xA1));
    let b2 = peers.class_of(&zid(0xB2));
    let stranger = peers.class_of(&zid(0x44));
    let publish = PeerOp::Publish;
    assert!(gate.admit_key_from(a1, publish, "lab/sensor/temp").is_ok());
    assert!(gate.admit_key_from(b2, publish, "lab/ctl/set").is_ok());
    assert_eq!(
        gate.admit_key_from(a1, publish, "lab/ctl/set"),
        Err(Refusal::PeerNotAllowed(publish))
    );
    assert_eq!(
        gate.admit_key_from(stranger, publish, "lab/sensor/temp"),
        Err(Refusal::PeerUnknown)
    );
    // A key outside the set is refused as that, for a declared peer too.
    assert_eq!(
        gate.admit_key_from(a1, publish, "lab/sensor/pressure"),
        Err(Refusal::OutsideSet)
    );
    let refused = gate.refused();
    assert_eq!(
        (
            refused.peer_not_allowed,
            refused.peer_unknown,
            refused.outside_set,
            refused.total
        ),
        (1, 1, 1, 3)
    );
}

#[cfg(feature = "alloc")]
#[test]
fn a_node_adopts_its_table_by_reading_closed() {
    use wz_session_core::key_gate::KeyGate;

    // What a node's code does with its generated `declared.rs`: one name, `Some` for a node that
    // states a closed key set, and the gate over it.
    let closed = fixture::key_set::CLOSED.expect("the fixture states a closed key set");
    assert_eq!(closed.key_count(), CATALOGUE.key_count());
    let fired = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let mut table: wz_session_core::pubsub::SubscriberTable<Counted> =
        wz_session_core::pubsub::SubscriberTable::with_sink_backing();
    if let Some(catalogue) = fixture::key_set::CLOSED {
        table.set_key_gate(KeyGate::closed(catalogue));
    }
    register_the_fixtures_subscribers(&mut table, &fired);
    assert!(!fired_on(&mut table, &fired, "lab/sensor/temp").is_empty());
    assert!(fired_on(&mut table, &fired, "lab/sensor/pressure").is_empty());
    assert_eq!(table.key_gate_refused().outside_set, 1);
}

#[cfg(feature = "alloc")]
#[test]
fn a_subscription_is_made_only_on_a_pattern_the_closed_image_declares() {
    use wz_session_core::key_gate::KeyGate;
    use wz_session_core::locality::Locality;
    use wz_session_core::registry_error::RegisterError;

    let fired = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let mut table: wz_session_core::pubsub::SubscriberTable<Counted> =
        wz_session_core::pubsub::SubscriberTable::with_sink_backing();
    table.set_key_gate(KeyGate::closed(&CATALOGUE));
    let sink = |tag| Counted {
        tag,
        fired: std::rc::Rc::clone(&fired),
    };
    // Declared as a subscriber.
    assert!(table
        .register_sink("lab/sensor/*", Locality::Any, sink(0))
        .is_ok());
    // In the set, but declared as a publisher and not as a subscriber.
    assert_eq!(
        table
            .register_sink("lab/ctl/get", Locality::Any, sink(1))
            .err(),
        Some(RegisterError::KeyNotInSet)
    );
    // Not in the set at all.
    assert_eq!(
        table
            .register_sink("lab/other/**", Locality::Any, sink(2))
            .err(),
        Some(RegisterError::KeyNotInSet)
    );
    assert_eq!(table.len(), 1);
    assert_eq!(table.key_gate_refused().total, 2);
}

#[cfg(feature = "alloc")]
#[test]
fn a_subscription_made_before_the_table_was_given_still_gets_its_messages() {
    use wz_session_core::key_gate::KeyGate;
    use wz_session_core::locality::Locality;

    let fired = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let mut table: wz_session_core::pubsub::SubscriberTable<Counted> =
        wz_session_core::pubsub::SubscriberTable::with_sink_backing();
    let sink = |tag| Counted {
        tag,
        fired: std::rc::Rc::clone(&fired),
    };
    // One the image declares, and one it does not: both exist before the gate is set.
    table
        .register_sink("lab/sensor/*", Locality::Any, sink(10))
        .expect("room");
    table
        .register_sink("lab/ctl/**", Locality::Any, sink(11))
        .expect("room");
    table.set_key_gate(KeyGate::closed(&CATALOGUE));
    // `lab/ctl/set` is in the set: the declared row is reached by number, the other by its pattern.
    assert_eq!(fired_on(&mut table, &fired, "lab/ctl/set"), vec![11]);
    assert_eq!(fired_on(&mut table, &fired, "lab/sensor/temp"), vec![10]);
    // A key outside the set is dropped for both.
    assert!(fired_on(&mut table, &fired, "lab/sensor/pressure").is_empty());
}

#[test]
fn the_table_is_the_declaration() {
    assert_eq!(CATALOGUE.entity_count(), DECLARED.len());
    for (number, (kind, pattern)) in DECLARED.iter().enumerate() {
        let row = CATALOGUE
            .entity(EntityId::new(u16::try_from(number).expect("a u16 entity")))
            .expect("every declared entity has a row");
        assert_eq!(row.kind, *kind);
        assert_eq!(CATALOGUE.text(row.key), *pattern);
    }
    // Entities are numbered by kind and then key: a number says nothing of declaration order.
    assert!(DECLARED
        .windows(2)
        .all(|pair| (pair[0].0, pair[0].1.as_bytes()) < (pair[1].0, pair[1].1.as_bytes())));
    // Keys are the distinct patterns, sorted by bytes, and each is its own id's text.
    let mut distinct: Vec<&str> = DECLARED.iter().map(|(_, pattern)| *pattern).collect();
    distinct.sort_unstable();
    distinct.dedup();
    assert_eq!(CATALOGUE.key_count(), distinct.len());
    for (index, key) in key_ids().enumerate() {
        assert_eq!(CATALOGUE.text(key), distinct[index]);
        assert_eq!(CATALOGUE.find_exact(distinct[index]), Some(key));
        assert_eq!(key.index(), index);
    }
}

#[test]
fn the_gate_admits_exactly_the_declared_roles() {
    use wz_session_core::key_gate::{Admitted, KeyGate, Refusal};
    let mut gate = KeyGate::closed(&CATALOGUE);
    let mut not_declared = 0usize;
    let mut declared_seen = 0usize;
    for key in key_ids() {
        let text = CATALOGUE.text(key);
        // A key of the set is admitted as a message's key, whatever roles it has.
        assert_eq!(gate.admit_key(text), Ok(Admitted::Key(key)), "`{text}`");
        for kind in EntityKind::ALL {
            let declared = DECLARED
                .iter()
                .any(|(entity, pattern)| *entity == kind && *pattern == text);
            let answer = gate.admit_declared(text, kind);
            if declared {
                assert_eq!(answer, Ok(Admitted::Key(key)), "{kind:?} on `{text}`");
                declared_seen += 1;
            } else {
                assert_eq!(
                    answer,
                    Err(Refusal::RoleNotDeclared(kind)),
                    "{kind:?} on `{text}`"
                );
                not_declared += 1;
            }
        }
    }
    assert_eq!(declared_seen, DECLARED.len());
    // Every undeclared (key, kind) pair was refused by role, and none by the set.
    let refused = gate.refused();
    assert_eq!(refused.role_not_declared, not_declared);
    assert_eq!(refused.outside_set, 0);
    assert_eq!(refused.total, not_declared);
    // The keys a declared pattern covers but that are not declared are outside the set.
    for text in ["lab/sensor/pressure", "lab/ctl/reset", "nothing", ""] {
        assert_eq!(gate.admit_key(text), Err(Refusal::OutsideSet), "`{text}`");
    }
    assert_eq!(gate.refused().outside_set, 4);
    // An open gate over the same keys admits all of them and counts none.
    let mut open = KeyGate::open();
    for text in ["lab/sensor/pressure", "nothing", ""] {
        assert_eq!(open.admit_key(text), Ok(Admitted::Unchecked));
    }
    assert_eq!(open.refused().total, 0);
}

#[test]
fn a_key_that_is_not_declared_is_not_found_even_when_a_declared_pattern_covers_it() {
    // `lab/**` and `lab/sensor/*` cover each of these, and none is a key of the set (decision D4).
    for undeclared in [
        "lab/sensor/pressure",
        "lab/ctl/reset",
        "lab/x",
        "lab/sensor/tem",
        "lab/sensor/temp/extra",
        "lab",
        "",
        "/",
        "lab/sensor/",
        "nothing",
    ] {
        assert_eq!(CATALOGUE.find_exact(undeclared), None, "`{undeclared}`");
    }
    // A pattern is found by its own text, since it is a key of the set.
    assert!(CATALOGUE.find_exact("lab/**").is_some());
    assert!(CATALOGUE.is_wildcard(CATALOGUE.find_exact("lab/**").expect("declared")));
    assert!(!CATALOGUE.is_wildcard(CATALOGUE.find_exact("lab/ctl/get").expect("declared")));
}

#[test]
fn the_generators_key_verdict_agrees_with_the_validator_on_every_short_text() {
    use corpus::{VERDICT, VERDICT_ALPHABET, VERDICT_MAX_LEN};
    use wz_session_core::keyexpr_canon::{canonize_keyexpr, validate_keyexpr};

    let digits: Vec<u8> = VERDICT.concat().into_bytes();
    let alphabet = VERDICT_ALPHABET.len();
    let mut index = 0usize;
    let mut accepted = 0usize;
    for length in 1..=VERDICT_MAX_LEN {
        for number in 0..alphabet.pow(length as u32) {
            // The first letter varies slowest: `number` read in base `alphabet`, most significant first.
            let text: String = (0..length)
                .map(|place| {
                    let power = alphabet.pow((length - 1 - place) as u32);
                    VERDICT_ALPHABET[(number / power) % alphabet]
                })
                .collect();
            let digit = (digits[index / 4] as char)
                .to_digit(16)
                .expect("a hex digit");
            let port = digit & (1 << (index % 4)) != 0;
            let validator = validate_keyexpr(&text).is_ok();
            assert_eq!(
                validator, port,
                "`{text}`: the validator and the generator's verdict"
            );
            if validator {
                accepted += 1;
                // What the validator accepts is what the subscriber table registers, byte for byte:
                // the declared key is the text the table holds.
                let stored = canonize_keyexpr(&text).expect("a key expression canonizes");
                assert_eq!(
                    &*stored,
                    text.as_str(),
                    "`{text}` is its own canonical form"
                );
            }
            index += 1;
        }
    }
    assert!(
        !validate_keyexpr("").is_ok(),
        "the empty text is not a key expression"
    );
    assert_eq!(
        digits.len(),
        index.div_ceil(4),
        "the corpus has the texts it says"
    );
    // Both verdicts occur in numbers: a corpus of only refusals would test nothing.
    assert!(
        accepted >= 100 && accepted < index / 2,
        "{accepted} of {index} texts accepted"
    );
}

#[test]
fn every_declared_key_of_the_fixture_is_a_key_expression() {
    use wz_session_core::keyexpr_canon::validate_keyexpr;
    for key in key_ids() {
        let text = CATALOGUE.text(key);
        assert!(validate_keyexpr(text).is_ok(), "`{text}`");
    }
}

#[test]
fn the_generators_port_agrees_with_the_matcher_on_every_pair() {
    use corpus::{KEYS, ROWS};
    assert_eq!(KEYS.len(), ROWS.len());
    let mut pairs = 0usize;
    let mut intersecting = 0usize;
    for (i, left) in KEYS.iter().enumerate() {
        let row = ROWS[i].as_bytes();
        assert_eq!(
            row.len(),
            (KEYS.len() - i).div_ceil(4),
            "row {i} is as long as its pairs"
        );
        for (offset, right) in KEYS[i..].iter().enumerate() {
            let digit = (row[offset / 4] as char).to_digit(16).expect("a hex digit");
            let port = digit & (1 << (offset % 4)) != 0;
            assert_eq!(
                keyexpr_intersects_text(left, right),
                port,
                "`{left}` against `{right}`"
            );
            assert_eq!(
                keyexpr_intersects_text(right, left),
                port,
                "`{right}` against `{left}`"
            );
            pairs += 1;
            intersecting += usize::from(port);
        }
    }
    // Both answers occur often: a corpus of only misses or only hits would test nothing.
    assert!(
        intersecting > pairs / 20,
        "{intersecting} of {pairs} pairs intersect"
    );
    assert!(
        intersecting < pairs - pairs / 20,
        "{intersecting} of {pairs} pairs intersect"
    );
}
