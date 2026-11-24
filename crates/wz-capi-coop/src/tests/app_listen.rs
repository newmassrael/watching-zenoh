// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A session that listens over the program's transport opens at the build's own limits: the
//! faces it admits and the handshakes it holds at once are the build's values, and its open
//! reserves what they size. An open that is refused says how, in the engine's own words.

use std::sync::{Arc, Mutex};

use wz_runtime_posix::{PosixClock, PosixEntropy};
use wz_session_core::app_link_table::{
    AppLinkKind, AppLinkTable, LinkHandle, ProgramOpen, ProgramSend,
};
use wz_session_core::app_transport::{
    AppPort, AppTransport, LockedCall, SessionTransport, TableLock,
};

use super::client_config;
use crate::app_link::AppLinks;
use crate::{CoopConfig, CoopEngine};

/// The program's table of links, behind a lock of the test's own.
struct Table(Mutex<AppLinkTable>);

impl TableLock for Table {
    fn lock_with(&self, f: &mut dyn FnMut(&mut AppLinkTable) -> LockedCall) -> LockedCall {
        f(&mut self.0.lock().unwrap())
    }
}

/// A program that takes every link the session asks it to open and writes whatever is sent.
struct Taking;

impl AppPort for Taking {
    fn open(&self, _link: LinkHandle, _kind: AppLinkKind, _locator: &str) -> ProgramOpen {
        ProgramOpen::Up
    }

    fn send(&self, _link: LinkHandle, bytes: &[u8]) -> ProgramSend {
        ProgramSend::Wrote(bytes.len())
    }

    fn close(&self, _link: LinkHandle) {}
}

/// A listener that dials nothing, at the build's limits (`client_config` states the faces and
/// handshakes the build admits), opens over a program that takes its port; a refusal fails the
/// test with the engine's refusal as it is.
#[test]
fn a_listener_at_the_builds_limits_opens_over_the_programs_transport() {
    let config = CoopConfig {
        listen: vec!["tcp/127.0.0.1:7447".to_owned()],
        ..client_config()
    };
    let transport = Arc::new(AppTransport::new(
        Box::new(Table(Mutex::new(AppLinkTable::new()))),
        Box::new(Taking),
    ));
    let links = AppLinks::new(SessionTransport::new(transport, &config.limits));
    if let Err(refused) = CoopEngine::open(links, PosixClock, PosixEntropy, config) {
        panic!("a listener at the build's limits is refused: {refused:?}");
    }
}
