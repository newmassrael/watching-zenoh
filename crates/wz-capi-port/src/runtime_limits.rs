// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The limits of the process's runtime, for every C ABI: one snapshot the process holds, which the
//! machines it makes apart from any session read when they are made.
//!
//! A C ABI's supervisor is the process's, and its reception supervisors and message catalogs are
//! made by doors that hold no session, so their limits are no session's: they are the runtime's,
//! and the library is the runtime. The process starts from the build's values; a program may state
//! lower ones once, before the first of those machines is made ([`state`]), as it may reserve
//! its object pools before its first object. The first machine takes the snapshot ([`take`]),
//! and a statement after it is refused: a machine made under the limits held before would run on
//! beside one made under the new ones, and the process would state two runtimes.
//!
//! An open whose document states them is held to them as well ([`agree`]): before the first
//! machine its rows become the process's, and after it an open that states others is refused,
//! while one that states the same rows or none proceeds.
//!
//! What a machine reads is the rows the limits lend it under the build's values
//! ([`ProcessRows`]): a value over the build's is refused when it is stated, under the limit's
//! name, so no machine is ever handed one.

use wz_session_core::limits::RuntimeLimits;
use wz_session_core::process_limits::{ProcessRefused, ProcessRows, ProcessStatement};

use crate::sync::Lock;

/// Why the process's runtime limits were not stated; the process holds what it held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateRefused {
    /// A machine of the process was made under the limits held: they are the process's now, and
    /// the statement would change them.
    Taken,
    /// A limit gives a machine of the process no rows under the build's value.
    Limit(ProcessRefused),
}

/// The snapshot a process holds, and whether a machine has taken it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Process {
    rows: ProcessRows,
    taken: bool,
}

impl Process {
    /// A process that has stated nothing and made no machine.
    const BUILD: Self = Self {
        rows: ProcessRows::BUILD,
        taken: false,
    };

    fn state(&mut self, limits: &RuntimeLimits) -> Result<ProcessRows, StateRefused> {
        let rows = ProcessRows::of(limits).map_err(StateRefused::Limit)?;
        if self.taken {
            return Err(StateRefused::Taken);
        }
        self.rows = rows;
        Ok(rows)
    }

    fn agree(&mut self, statement: &ProcessStatement) -> Result<ProcessRows, StateRefused> {
        if self.taken {
            return if statement.agrees_with(&self.rows) {
                Ok(self.rows)
            } else {
                Err(StateRefused::Taken)
            };
        }
        self.rows = statement.over(self.rows);
        Ok(self.rows)
    }

    fn take(&mut self) -> ProcessRows {
        self.taken = true;
        self.rows
    }
}

static PROCESS: Lock<Process> = Lock::new(Process::BUILD);

/// State the process's runtime limits: `limits`, a runtime's snapshot resolved from a document or
/// from code. Refused, the process holding what it held, when a limit is over the build's value
/// (judged first, so the same statement is refused the same way whenever it comes) and when a
/// machine of the process was made already. Answers the rows each machine will be lent.
pub fn state(limits: &RuntimeLimits) -> Result<ProcessRows, StateRefused> {
    PROCESS.with(|process| process.state(limits))
}

/// Hold the process to what an open's resolution states of its runtime limits (`statement`, its
/// rows already lent under the build's values, so no value over them reaches here): before a
/// machine of the process is made the stated rows replace the ones held, each limit apart, and
/// after it the open proceeds where it states the rows the process holds or states none, and is
/// refused where it states another. A limit the statement leaves unstated agrees with any row.
pub fn agree(statement: &ProcessStatement) -> Result<ProcessRows, StateRefused> {
    PROCESS.with(|process| process.agree(statement))
}

/// The rows the process's machines are lent, for the creator of one: from now on the process's
/// limits are no longer stated.
pub fn take() -> ProcessRows {
    PROCESS.with(Process::take)
}

/// The rows the process's machines are lent, read without taking them: what a report of the
/// process's memory counts.
pub fn held() -> ProcessRows {
    PROCESS.with(|process| process.rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wz_session_core::caps;
    use wz_session_core::limit_binding::Quota;

    /// A process that states nothing lends the build's rows, and its first machine takes them.
    #[test]
    fn a_process_that_states_nothing_lends_the_builds_rows() {
        let mut process = Process::BUILD;
        assert_eq!(process.take(), ProcessRows::BUILD);
        assert!(process.taken);
    }

    /// Lower limits stated before any machine are the ones the first machine takes; a statement
    /// after it is refused and the machine's rows stay as they were.
    #[test]
    fn limits_are_stated_before_the_first_machine_and_refused_after() {
        let mut limits = RuntimeLimits::defaults();
        if limits
            .select_e2e_supervised_streams(Quota::at_most(1))
            .is_err()
        {
            return;
        }
        let mut process = Process::BUILD;
        let stated = process.state(&limits).expect("one is under the build's");
        assert_eq!(stated.e2e_supervised_streams, 1);
        assert_eq!(process.take(), stated);
        assert_eq!(
            process.state(&RuntimeLimits::defaults()),
            Err(StateRefused::Taken)
        );
        assert_eq!(process.take(), stated);
    }

    /// An open's statement replaces the rows it states before a machine is made; after it, one
    /// that states the rows held or none proceeds and one that states another is refused, the
    /// rows held staying.
    #[test]
    fn an_open_agrees_with_the_taken_limits_or_is_refused() {
        let lowered = ProcessStatement {
            message_catalog_entries: Some(1),
            ..ProcessStatement::default()
        };
        let mut process = Process::BUILD;
        let stated = process
            .agree(&lowered)
            .expect("no machine has taken the limits");
        assert_eq!(stated.message_catalog_entries, 1);
        assert_eq!(
            stated.e2e_supervised_streams,
            ProcessRows::BUILD.e2e_supervised_streams,
            "a limit not stated keeps the row held"
        );
        assert_eq!(process.take(), stated);
        assert_eq!(process.agree(&lowered), Ok(stated), "the same value");
        assert_eq!(
            process.agree(&ProcessStatement::default()),
            Ok(stated),
            "no value"
        );
        let other = ProcessStatement {
            message_catalog_entries: Some(2),
            ..ProcessStatement::default()
        };
        assert_eq!(process.agree(&other), Err(StateRefused::Taken));
        assert_eq!(process.take(), stated);
    }

    /// A value over the build's is refused by the limit's name, before and after a machine, and
    /// the process holds what it held.
    #[test]
    fn a_value_over_the_builds_is_refused_by_name_and_changes_nothing() {
        let mut limits = RuntimeLimits::defaults();
        if limits
            .select_message_catalog_entries(Quota::at_most(caps::MESSAGE_CATALOG_ENTRIES + 1))
            .is_err()
        {
            return;
        }
        let mut process = Process::BUILD;
        let refused = process.state(&limits);
        assert!(
            matches!(
                refused,
                Err(StateRefused::Limit(ProcessRefused {
                    limit: "MESSAGE_CATALOG_ENTRIES",
                    ..
                }))
            ),
            "{refused:?}"
        );
        assert_eq!(process, Process::BUILD);
        process.take();
        assert!(matches!(
            process.state(&limits),
            Err(StateRefused::Limit(_))
        ));
    }
}
