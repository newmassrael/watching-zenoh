// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The machines a unicast client session runs (its session machine, its link's machine and, with
//! `reassembly`, a reassembly slot's) held to the class a reactive turn of the SCE runtime serves:
//! no `<history>`, no `<parallel>`, no transition of more than one target, selection by rows,
//! every `<final>` at the top level and no eventless transition. The runtime's general turn asks
//! for eventless transitions after every event and drains an internal queue; for this class one
//! external event selects at most one transition and nothing follows it, which is the turn
//! `docs/win-budget/size.md` section 10 asks of SCE. A document that leaves the class is found
//! here, in the build that links it, and not only in the image's size.

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

/// The session machine is of the class whether the build accepts or only opens: the acceptor's
/// OpenAck is the effect of the OpenSyn's own transition into Established, not the entry of a
/// state left by an eventless step. The runtime's own reading of its tables agrees, which is what
/// its policy's `REACTIVE_TURN` starts from. Turned red, in a build with `session-unicast-accept`,
/// by an accepting state the source leaves without an event.
#[test]
fn the_session_machine_is_of_the_reactive_class() {
    assert_eq!(outside_the_class(&SESSION_FSM_UNICAST_TABLES), None);
    assert!(SESSION_FSM_UNICAST_TABLES.reactive_class());
}

/// The acceptor's OpenSyn ends the accept in Established in the one turn its event is taken, the
/// OpenAck sent on the way, with no state between the two for a turn to stop in. Turned red by a
/// transition of that event to any target but Established, or by one that carries no effect (the
/// OpenAck would then be sent by no step of the machine).
#[cfg(feature = "session-unicast-accept")]
#[test]
fn the_acceptors_open_syn_takes_it_to_established_sending_the_open_ack() {
    use crate::session_fsm_unicast::{SessionFsmUnicastEvent as E, SessionFsmUnicastState as S};
    let tables = &SESSION_FSM_UNICAST_TABLES;
    let [taken] = tables.candidates_of(S::ID_SentInitAck, E::ID_OpenSynReceived) else {
        panic!("SentInitAck takes the OpenSyn by one transition");
    };
    let taken = taken.transition();
    assert_eq!(
        tables.targets(taken),
        &[sce_rust_runtime::Target::state(S::ID_Established)]
    );
    assert!(tables.transition(taken).has_content());
}

/// The scouting machine a peer build links beside the session's is of the class too, so every
/// machine of such a build hands the runtime's one turn the same answer and the general turn's
/// macrostep completion has no caller there. Turned red by an eventless or raising step in the
/// scouting source.
#[cfg(feature = "scouting-active")]
#[test]
fn the_scouting_machine_is_of_the_reactive_class() {
    assert_eq!(outside_the_class(&crate::scouting::SCOUTING_TABLES), None);
    assert!(crate::scouting::SCOUTING_TABLES.reactive_class());
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
