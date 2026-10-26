// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The conformance table of decision D7, `docs/session-lifecycle-intent.md`, as this crate's
//! adapters use it.
//!
//! The table itself, and its judge, are `wz_session_core::lifecycle_contract`: they live beside
//! the verdict's words so that the heap profile's adapter, which is in that crate, is held to the
//! same cases as the fixed-memory profile's, which are here. This module re-exports them and adds
//! what only a node of this crate has: an opener to serve a request through
//! ([`Recording`], a [`NodeOpening`] that remembers what it was asked), and the judge of what it
//! was asked read off that opener.
//!
//! Compiled for tests and for `test-support`, which a production build never names.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use wz_session_core::credential_identity::CREDENTIAL_ZID_BYTES;
use wz_session_core::lifecycle_wire::OpenOutcome;

pub use wz_session_core::lifecycle_contract::{
    judge_answers, Answer, Binding, Case, Violation, CASES, REPEATS,
};

use crate::node_opening::NodeOpening;

/// An opener that records what it was asked, for an adapter to serve a request through and a
/// judge to read. Its answer is fixed at construction, and its record is atomic, so it is `Sync`
/// and a transport that wants a `'static` opener can be given one.
pub struct Recording {
    permitted: bool,
    outcome: OpenOutcome,
    asked: AtomicU32,
    last: [AtomicU64; 2],
}

impl Recording {
    /// An opener that permits per `permitted` and answers `outcome` when asked.
    pub const fn new(permitted: bool, outcome: OpenOutcome) -> Self {
        Self {
            permitted,
            outcome,
            asked: AtomicU32::new(0),
            last: [AtomicU64::new(0), AtomicU64::new(0)],
        }
    }

    /// The opener this case's node binds.
    pub const fn for_case(case: &Case) -> Self {
        Self::new(case.permitted, case.outcome)
    }

    /// How many times it was asked.
    pub fn asked(&self) -> u32 {
        self.asked.load(Ordering::SeqCst)
    }

    /// The zid it was last asked for.
    pub fn last(&self) -> [u8; CREDENTIAL_ZID_BYTES] {
        let mut out = [0u8; CREDENTIAL_ZID_BYTES];
        out[..8].copy_from_slice(&self.last[0].load(Ordering::SeqCst).to_le_bytes());
        out[8..].copy_from_slice(&self.last[1].load(Ordering::SeqCst).to_le_bytes());
        out
    }
}

impl NodeOpening for Recording {
    fn permitted(&self) -> bool {
        self.permitted
    }

    fn open(&self, zid: &[u8; CREDENTIAL_ZID_BYTES]) -> OpenOutcome {
        let mut low = [0u8; 8];
        let mut high = [0u8; 8];
        low.copy_from_slice(&zid[..8]);
        high.copy_from_slice(&zid[8..]);
        self.last[0].store(u64::from_le_bytes(low), Ordering::SeqCst);
        self.last[1].store(u64::from_le_bytes(high), Ordering::SeqCst);
        self.asked.fetch_add(1, Ordering::SeqCst);
        self.outcome
    }
}

/// Whether what `opener` was asked is what the contract says of `case`.
pub fn judge_asking(case: &Case, opener: &Recording) -> Result<(), Violation> {
    wz_session_core::lifecycle_contract::judge_asking(case, opener.asked(), opener.last())
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::control_port;
    use crate::node_opening::{open_verdict, NoOpening};
    use std::string::{String, ToString};
    use std::vec::Vec;
    use wz_session_core::text_out::FixedText;

    /// Run the whole table through one adapter: `serve` makes one request for the case's peer
    /// through the opener and gives the answer it got, or `None`.
    fn conforms(serve: impl Fn(&Case, &Recording) -> Option<String>) {
        for case in CASES {
            let opener = Recording::for_case(case);
            let answers: Vec<Option<String>> = (0..REPEATS).map(|_| serve(case, &opener)).collect();
            let seen: Vec<Option<&str>> = answers.iter().map(Option::as_deref).collect();
            judge_answers(case, &seen).unwrap_or_else(|v| panic!("{v:?}: {seen:?}"));
            if matches!(case.binding, Binding::Bound) {
                judge_asking(case, &opener).unwrap_or_else(|v| panic!("{v:?}"));
            }
        }
    }

    /// The verdict function itself, which every transport of this crate calls.
    #[test]
    fn the_verdict_function_conforms() {
        conforms(|case, opener| {
            let mut out = FixedText::<192>::new();
            match case.binding {
                Binding::Bound => open_verdict(opener, case.peer_text).write_json(&mut out),
                Binding::Unbound => open_verdict(&NoOpening, case.peer_text).write_json(&mut out),
            }
            Some(out.prefix().to_string())
        });
    }

    /// The out-of-band transport: the line `open <peer>` through the control port.
    #[test]
    fn the_control_port_conforms() {
        conforms(|case, opener| {
            let line = std::format!("open {}", case.peer_text);
            let mut out = FixedText::<192>::new();
            match case.binding {
                Binding::Bound => control_port::answer(opener, &line, &mut out),
                Binding::Unbound => control_port::answer(&NoOpening, &line, &mut out),
            }
            assert!(!out.overflowed());
            Some(out.prefix().to_string())
        });
    }

    /// The recorder reports what it was asked, which the judge reads.
    #[test]
    fn the_recorder_reports_what_it_was_asked() {
        let case = &CASES[0];
        let opener = Recording::for_case(case);
        assert!(judge_asking(case, &opener).is_err(), "never asked");
        let mut zid = [0u8; CREDENTIAL_ZID_BYTES];
        zid[0] = 0x1f;
        opener.open(&zid);
        opener.open(&zid);
        assert!(judge_asking(case, &opener).is_ok());
        zid[0] = 0x2f;
        opener.open(&zid);
        assert!(judge_asking(case, &opener).is_err());
    }
}
