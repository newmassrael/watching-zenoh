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

impl ProcessRows {
    /// The rows of a process whose runtime states nothing: the build's values. A build whose own
    /// values give a machine no rows does not compile.
    pub const BUILD: Self = match Self::of(&RuntimeLimits::BUILD) {
        Ok(rows) => rows,
        Err(_) => panic!("the build's runtime limits give every machine of the process its rows"),
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
