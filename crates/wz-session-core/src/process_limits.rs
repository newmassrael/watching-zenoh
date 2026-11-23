// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! What the limits of a runtime give the machines a process holds apart from any session.
//!
//! A C ABI's supervisor of checkpoints is the process's, and its reception supervisors and message
//! catalogs are made by doors that hold no session. Their limits are the runtime's
//! ([`RuntimeLimits`]): the process resolves one snapshot of them and hands it to each such machine
//! it makes. The build's value of each limit is the ceiling: it sizes what the build reserves (the
//! supervisor's checkpoints), and a value a later stage states is lent under it
//! ([`Quota::lent_under`]) and never adds to it, so a value over it gives the machine no rows and
//! is refused under the limit's name.

use crate::caps;
use crate::limit_binding::{Quota, UnlentRows};
use crate::limits::RuntimeLimits;
use crate::policy_document::{Origin, ResolvedLimits};

/// How many rows each machine of the process holds, lent from a runtime's limits under the build's
/// values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessRows {
    /// The checkpoints the process's supervisor watches (`SUPERVISION_CHECKPOINTS`).
    pub supervision_checkpoints: usize,
    /// The messages one message catalog declares at most (`MESSAGE_CATALOG_ENTRIES`).
    pub message_catalog_entries: usize,
    /// The streams one reception supervisor holds at most (`E2E_SUPERVISED_STREAMS`).
    pub e2e_supervised_streams: usize,
}

/// A limit that gives a machine of the process no rows under the build's value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessRefused {
    /// The limit's id.
    pub limit: &'static str,
    /// Why.
    pub why: UnlentRows,
}

// A build whose own values give a machine of the process no rows does not compile: the refusal is
// a constant's, evaluated where the build is made.
const _: () = assert!(
    matches!(ProcessRows::of(&RuntimeLimits::BUILD), Ok(_)),
    "the build's runtime limits give every machine of the process its rows"
);

impl ProcessRows {
    /// The rows of a process whose runtime states nothing: the build's values. A build whose own
    /// values give a machine no rows does not compile.
    pub const BUILD: Self = match Self::of(&RuntimeLimits::BUILD) {
        Ok(rows) => rows,
        // Never taken: the assertion below stops the build that would take it.
        Err(_) => Self {
            supervision_checkpoints: 0,
            message_catalog_entries: 0,
            e2e_supervised_streams: 0,
        },
    };

    /// The rows `limits` give, each value lent under the build's: refused, naming the limit, where
    /// a value is over the build's or the build states none.
    pub const fn of(limits: &RuntimeLimits) -> Result<Self, ProcessRefused> {
        let supervision_checkpoints = match lent::<{ caps::SUPERVISION_CHECKPOINTS }>(
            "SUPERVISION_CHECKPOINTS",
            Quota::at_most(limits.supervision_checkpoints()),
        ) {
            Ok(rows) => rows,
            Err(refused) => return Err(refused),
        };
        let message_catalog_entries = match lent::<{ caps::MESSAGE_CATALOG_ENTRIES }>(
            "MESSAGE_CATALOG_ENTRIES",
            limits.message_catalog_entries(),
        ) {
            Ok(rows) => rows,
            Err(refused) => return Err(refused),
        };
        let e2e_supervised_streams = match lent::<{ caps::E2E_SUPERVISED_STREAMS }>(
            "E2E_SUPERVISED_STREAMS",
            limits.e2e_supervised_streams(),
        ) {
            Ok(rows) => rows,
            Err(refused) => return Err(refused),
        };
        Ok(Self {
            supervision_checkpoints,
            message_catalog_entries,
            e2e_supervised_streams,
        })
    }
}

/// What one resolution of a runtime's limits states of the rows of the process's machines: the rows
/// of each limit a layer stated, and nothing of the limits left at the build's value, which state
/// nothing to agree or disagree with.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProcessStatement {
    /// The checkpoints of the supervisor, where stated (`SUPERVISION_CHECKPOINTS`).
    pub supervision_checkpoints: Option<usize>,
    /// The messages of one catalog, where stated (`MESSAGE_CATALOG_ENTRIES`).
    pub message_catalog_entries: Option<usize>,
    /// The streams of one reception supervisor, where stated (`E2E_SUPERVISED_STREAMS`).
    pub e2e_supervised_streams: Option<usize>,
}

impl ProcessStatement {
    /// What `limits`, a creator's resolution, states of the process's machines: refused, naming
    /// the limit, where a stated value is over the build's.
    pub fn of(limits: &ResolvedLimits) -> Result<Self, ProcessRefused> {
        let rows = ProcessRows::of(&limits.runtime)?;
        let stated = |limit: &str| {
            !matches!(
                limits.provenance.origin(limit),
                None | Some(Origin::BuildDefault)
            )
        };
        Ok(Self {
            supervision_checkpoints: stated("SUPERVISION_CHECKPOINTS")
                .then_some(rows.supervision_checkpoints),
            message_catalog_entries: stated("MESSAGE_CATALOG_ENTRIES")
                .then_some(rows.message_catalog_entries),
            e2e_supervised_streams: stated("E2E_SUPERVISED_STREAMS")
                .then_some(rows.e2e_supervised_streams),
        })
    }

    /// Whether it states none of the rows.
    pub const fn is_empty(&self) -> bool {
        self.supervision_checkpoints.is_none()
            && self.message_catalog_entries.is_none()
            && self.e2e_supervised_streams.is_none()
    }

    /// Whether `rows` holds every row it states.
    pub fn agrees_with(&self, rows: &ProcessRows) -> bool {
        let agrees = |stated: Option<usize>, held: usize| match stated {
            None => true,
            Some(stated) => stated == held,
        };
        agrees(self.supervision_checkpoints, rows.supervision_checkpoints)
            && agrees(self.message_catalog_entries, rows.message_catalog_entries)
            && agrees(self.e2e_supervised_streams, rows.e2e_supervised_streams)
    }

    /// `rows` with every row it states in place of the one held.
    pub fn over(&self, rows: ProcessRows) -> ProcessRows {
        ProcessRows {
            supervision_checkpoints: self
                .supervision_checkpoints
                .unwrap_or(rows.supervision_checkpoints),
            message_catalog_entries: self
                .message_catalog_entries
                .unwrap_or(rows.message_catalog_entries),
            e2e_supervised_streams: self
                .e2e_supervised_streams
                .unwrap_or(rows.e2e_supervised_streams),
        }
    }
}

/// The rows `value` gives under `CEILING`, the build's value of the limit `limit`.
const fn lent<const CEILING: usize>(
    limit: &'static str,
    value: Quota,
) -> Result<usize, ProcessRefused> {
    match value.lent_under(Quota::at_most(CEILING)) {
        Ok(rows) => Ok(rows),
        Err(why) => Err(ProcessRefused { limit, why }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limit_binding::LimitSpec;
    use crate::limits::{E2eSupervisedStreams, MessageCatalogEntries, SupervisionCheckpoints};

    /// With nothing stated every machine holds the build's rows.
    #[test]
    fn a_runtime_that_states_nothing_gives_the_builds_rows() {
        assert_eq!(
            ProcessRows::BUILD,
            ProcessRows {
                supervision_checkpoints: caps::SUPERVISION_CHECKPOINTS,
                message_catalog_entries: caps::MESSAGE_CATALOG_ENTRIES,
                e2e_supervised_streams: caps::E2E_SUPERVISED_STREAMS,
            }
        );
        assert_eq!(
            ProcessRows::of(&RuntimeLimits::defaults()),
            Ok(ProcessRows::BUILD)
        );
    }

    /// A value under the build's is the machine's rows, each limit apart from the others.
    #[test]
    fn a_lowered_limit_gives_its_value_and_leaves_the_others() {
        let mut limits = RuntimeLimits::defaults();
        if !SupervisionCheckpoints::DOMAIN.is_singleton() && caps::SUPERVISION_CHECKPOINTS > 1 {
            limits
                .select_supervision_checkpoints(1)
                .expect("one is inside the domain");
            assert_eq!(
                ProcessRows::of(&limits).map(|rows| rows.supervision_checkpoints),
                Ok(1)
            );
        }
        if !MessageCatalogEntries::DOMAIN.is_singleton() && caps::MESSAGE_CATALOG_ENTRIES > 1 {
            limits
                .select_message_catalog_entries(Quota::at_most(1))
                .expect("one is inside the domain");
            assert_eq!(
                ProcessRows::of(&limits).map(|rows| rows.message_catalog_entries),
                Ok(1)
            );
        }
        if !E2eSupervisedStreams::DOMAIN.is_singleton() && caps::E2E_SUPERVISED_STREAMS > 1 {
            limits
                .select_e2e_supervised_streams(Quota::at_most(1))
                .expect("one is inside the domain");
            let rows = ProcessRows::of(&limits).expect("every value is under the build's");
            assert_eq!(rows.e2e_supervised_streams, 1);
        }
    }

    /// A value over the build's gives no rows and is refused under the limit's name; where the
    /// build's domain leaves it out the statement itself is refused.
    #[test]
    fn a_value_over_the_builds_is_refused_by_name() {
        let mut catalog = RuntimeLimits::defaults();
        match catalog
            .select_message_catalog_entries(Quota::at_most(caps::MESSAGE_CATALOG_ENTRIES + 1))
        {
            Ok(()) => assert_eq!(
                ProcessRows::of(&catalog),
                Err(ProcessRefused {
                    limit: "MESSAGE_CATALOG_ENTRIES",
                    why: UnlentRows::OverCeiling {
                        value: caps::MESSAGE_CATALOG_ENTRIES + 1,
                        ceiling: caps::MESSAGE_CATALOG_ENTRIES,
                    },
                })
            ),
            Err(_) => assert!(!MessageCatalogEntries::DOMAIN.contains(
                crate::limit_binding::LimitValue::Integer(caps::MESSAGE_CATALOG_ENTRIES + 1)
            )),
        }
        let mut streams = RuntimeLimits::defaults();
        match streams
            .select_e2e_supervised_streams(Quota::at_most(caps::E2E_SUPERVISED_STREAMS + 1))
        {
            Ok(()) => assert_eq!(
                ProcessRows::of(&streams).map_err(|refused| refused.limit),
                Err("E2E_SUPERVISED_STREAMS")
            ),
            Err(_) => assert!(E2eSupervisedStreams::DOMAIN.is_singleton()),
        }
        let mut checkpoints = RuntimeLimits::defaults();
        match checkpoints.select_supervision_checkpoints(caps::SUPERVISION_CHECKPOINTS + 1) {
            Ok(()) => assert_eq!(
                ProcessRows::of(&checkpoints).map_err(|refused| refused.limit),
                Err("SUPERVISION_CHECKPOINTS")
            ),
            Err(_) => assert!(!SupervisionCheckpoints::DOMAIN.contains(
                crate::limit_binding::LimitValue::Integer(caps::SUPERVISION_CHECKPOINTS + 1)
            )),
        }
    }

    /// A resolution states the rows of the limits a layer stated and nothing of the others; it
    /// agrees with rows that hold what it states, and its rows over held ones replace those alone.
    #[test]
    fn a_statement_holds_the_rows_a_layer_stated_and_nothing_else() {
        use crate::policy::SessionPolicy;
        use crate::policy_document::{resolve_under, Base, LimitStatement, Overrides};

        assert_eq!(
            ProcessStatement::of(&ResolvedLimits::unchanged(
                crate::limits::SessionLimits::defaults(),
                RuntimeLimits::defaults()
            )),
            Ok(ProcessStatement::default())
        );
        if MessageCatalogEntries::DOMAIN.is_singleton() || caps::MESSAGE_CATALOG_ENTRIES < 2 {
            return;
        }
        let stated = [LimitStatement::new(
            "MESSAGE_CATALOG_ENTRIES",
            crate::limit_binding::LimitValue::Integer(1),
        )];
        let Ok(resolved) = resolve_under(
            Base::node(SessionPolicy::defaults()),
            Overrides {
                limits: &stated,
                ..Overrides::default()
            },
        ) else {
            panic!("one is inside the domain");
        };
        let statement = ProcessStatement::of(&resolved.limits).expect("one is under the build's");
        assert_eq!(
            statement,
            ProcessStatement {
                message_catalog_entries: Some(1),
                ..ProcessStatement::default()
            }
        );
        assert!(!statement.is_empty());
        assert!(!statement.agrees_with(&ProcessRows::BUILD));
        let over = statement.over(ProcessRows::BUILD);
        assert_eq!(
            over,
            ProcessRows {
                message_catalog_entries: 1,
                ..ProcessRows::BUILD
            }
        );
        assert!(statement.agrees_with(&over));
        assert!(ProcessStatement::default().agrees_with(&over));
    }

    /// No bound stated is the build's value, as the storage it lends from has no more.
    #[test]
    fn no_bound_stated_is_lent_the_build_value() {
        let mut limits = RuntimeLimits::defaults();
        if limits
            .select_message_catalog_entries(Quota::UNBOUNDED)
            .is_ok()
        {
            assert_eq!(
                ProcessRows::of(&limits).map(|rows| rows.message_catalog_entries),
                Ok(caps::MESSAGE_CATALOG_ENTRIES)
            );
        }
    }
}
