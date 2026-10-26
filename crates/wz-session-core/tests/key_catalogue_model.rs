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
    feature = "keyexpr-wildcard-single",
    feature = "keyexpr-wildcard-double",
    feature = "keyexpr-dollar-star"
))]

#[path = "key_set_data/corpus.rs"]
mod corpus;
#[path = "key_set_data/fixture.rs"]
mod fixture;

use fixture::{CATALOGUE, DECLARED};
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
