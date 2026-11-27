// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The machines a unicast client session runs (its session machine, its link's machine and, with
//! `reassembly`, a reassembly slot's) held to the class a reactive turn of the SCE runtime serves:
//! no `<history>`, no `<parallel>`, no transition of more than one target, selection by rows,
//! every `<final>` at the top level and no eventless transition. The runtime's general turn asks
//! for eventless transitions after every event and drains an internal queue; for this class one
//! external event selects at most one transition and nothing follows it, which is the turn
//! `docs/win-budget/size.md` section 7 asks of SCE. A document that leaves the class is found here,
//! in the build that links it, and not only in the image's size.

use sce_rust_runtime::{
    CandidateCell, CandidateRows, DocumentTables, StateId, StateKind, StateRow, TransitionId,
};

use crate::session_fsm_unicast::SESSION_FSM_UNICAST_TABLES;
use crate::unicast_link::UNICAST_LINK_TABLES;

/// Why `tables` is outside the class, or `None` when it is inside.
fn outside_the_class(tables: &DocumentTables<'_>) -> Option<&'static str> {
    if !tables.histories.is_empty() || tables.history.is_some() {
        return Some("a <history>");
    }
    if tables.parallel.is_some() {
        return Some("a <parallel>");
    }
    if !tables.targets.is_empty() {
        return Some("a transition of more than one target");
    }
    let Some(rows) = tables.candidates.as_ref() else {
        return Some("a selection not by rows");
    };
    if tables
        .states
        .iter()
        .any(|state| state.kind() == StateKind::Final && state.parent().is_some())
    {
        return Some("a <final> below the top level");
    }
    if rows
        .cells
        .iter()
        .any(|cell| cell.event() == tables.null_event)
    {
        return Some("an eventless transition");
    }
    None
}

#[test]
fn the_link_machine_is_of_the_reactive_class() {
    assert_eq!(outside_the_class(&UNICAST_LINK_TABLES), None);
}

#[cfg(feature = "reassembly")]
#[test]
fn a_reassembly_slot_machine_is_of_the_reactive_class() {
    assert_eq!(
        outside_the_class(&crate::reassembly_slot::REASSEMBLY_SLOT_TABLES),
        None
    );
}

#[cfg(not(feature = "session-unicast-accept"))]
#[test]
fn a_session_machine_that_only_opens_is_of_the_reactive_class() {
    assert_eq!(outside_the_class(&SESSION_FSM_UNICAST_TABLES), None);
}

// The acceptor's step from SentOpenAck to Established is eventless, so a build that accepts runs
// its session machine on the general turn.
#[cfg(feature = "session-unicast-accept")]
#[test]
fn a_session_machine_that_accepts_leaves_the_class_by_its_eventless_step() {
    assert_eq!(
        outside_the_class(&SESSION_FSM_UNICAST_TABLES),
        Some("an eventless transition")
    );
}

#[test]
fn each_form_outside_the_class_is_named() {
    let eventless = [CandidateCell::new(UNICAST_LINK_TABLES.null_event, 0)];
    let rows = UNICAST_LINK_TABLES
        .candidates
        .expect("the link machine selects by rows");
    let with_eventless = DocumentTables {
        candidates: Some(CandidateRows {
            first_cell: rows.first_cell,
            cells: &eventless,
            candidates: rows.candidates,
        }),
        ..UNICAST_LINK_TABLES
    };
    assert_eq!(
        outside_the_class(&with_eventless),
        Some("an eventless transition")
    );

    let nested_final = [
        StateRow::new(None, StateKind::Compound, StateId(1), Some(TransitionId(0))),
        StateRow::new(Some(StateId(0)), StateKind::Final, StateId(1), None),
    ];
    let with_nested_final = DocumentTables {
        states: &nested_final,
        ..UNICAST_LINK_TABLES
    };
    assert_eq!(
        outside_the_class(&with_nested_final),
        Some("a <final> below the top level")
    );

    let by_general_selection = DocumentTables {
        candidates: None,
        ..UNICAST_LINK_TABLES
    };
    assert_eq!(
        outside_the_class(&by_general_selection),
        Some("a selection not by rows")
    );

    let with_parallel = DocumentTables {
        parallel: Some(&sce_rust_runtime::PARALLEL),
        ..UNICAST_LINK_TABLES
    };
    assert_eq!(outside_the_class(&with_parallel), Some("a <parallel>"));

    let with_history = DocumentTables {
        history: Some(&sce_rust_runtime::HISTORY),
        ..UNICAST_LINK_TABLES
    };
    assert_eq!(outside_the_class(&with_history), Some("a <history>"));
}
