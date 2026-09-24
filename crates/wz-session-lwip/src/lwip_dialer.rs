// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! R2831 (§5.23 `adminspace-write`) — the MCU node's dialer: what makes a
//! `udp/<ipv4>:<port>` endpoint in the connection control a live session.
//!
//! [`crate::connect_manager::ConnectManager`] decides WHEN to dial; this
//! module is the [`crate::connect_manager::Dialer`] that does it on lwIP. A
//! dial binds a fresh session socket on an ephemeral port, points a
//! [`crate::driver::LwipUdpDriver`] at the endpoint, and spawns an INITIATOR
//! session onto the firmware's local task set with
//! [`crate::session_drive::spawn_session`] — the same call a deploy `main()`
//! writes for its one configured peer, so a written endpoint and a compiled-in
//! one are the same kind of session.
//!
//! ## What this build can dial
//!
//! UDP over IPv4, by address. An endpoint with another scheme, or one that
//! carries upstream's `?metadata` / `#config` parts, is refused as
//! `Unsupported`: this link honours neither, and dialling it anyway would
//! quietly drop what the writer asked for. A host name is refused as
//! `BadAddress`, since the node has no resolver. Both are permanent for the
//! text, which is why the manager does not retry them.
//!
//! ## How an ended session is read
//!
//! A session has ended when its task has finished. Whether it had been
//! established is remembered from the session's own
//! `SessionLinkActions::is_established`, sampled each time the manager asks,
//! and that is the one approximation here: a session that establishes and
//! drops between two ticks of the manager reads as never established, so its
//! re-dial continues the old outage's period instead of starting a fresh one.
//! It errs towards waiting longer, never towards dialling harder.

use alloc::boxed::Box;
use alloc::rc::Rc;
use core::cell::RefCell;

use wz_link_lwip::rx_sockets::bind_session_rx;
use wz_link_lwip::{ipv4_addr_from_octets, LwipLink};
use wz_runtime_coop::{ClockSource, CoopLocalJoinHandle, CoopLocalSet, CoopRuntime, CoopTime};
use wz_session_core::close_reason::CloseReason;
use wz_session_core::driver_loop::{DriverOutcome, IterationEvent};
use wz_session_core::link::BoxedLinkDriver;
use wz_session_core::session_actions::SessionLinkActions;
use wz_session_core::session_init_params::SessionInitParams;
use wz_session_core::session_timeouts::SessionTimeouts;

use crate::connect_manager::{DialFailed, DialRefused, Dialer, Ended};
use crate::driver::{LwipUdpDriver, SharedSessionSocket};
use crate::session_drive::{spawn_session, SessionDriveConfig, SessionRole};

/// The action bundle of one MCU session.
pub type McuActions<C> = SessionLinkActions<CoopRuntime<C>, CoopTime<C>>;

/// What a dialled session reports its iterations to — typically
/// `crate::app_layer::dispatch_to` over the node's observer.
pub type EventSink = Box<dyn FnMut(IterationEvent<'_>)>;

/// Read `udp/<a.b.c.d>:<port>` into lwIP's address word and a port.
pub fn parse_udp_endpoint(endpoint: &str) -> Result<(u32, u16), DialRefused> {
    let rest = endpoint
        .strip_prefix("udp/")
        .ok_or(DialRefused::Unsupported)?;
    if rest.contains(['?', '#']) {
        return Err(DialRefused::Unsupported);
    }
    let (host, port) = rest.rsplit_once(':').ok_or(DialRefused::BadAddress)?;
    let port: u16 = digits(port).ok_or(DialRefused::BadAddress)?;
    if port == 0 {
        return Err(DialRefused::BadAddress);
    }
    let mut octets = [0u8; 4];
    let mut parts = host.split('.');
    for octet in &mut octets {
        *octet = parts
            .next()
            .and_then(digits)
            .ok_or(DialRefused::BadAddress)?;
    }
    if parts.next().is_some() {
        return Err(DialRefused::BadAddress);
    }
    Ok((ipv4_addr_from_octets(octets), port))
}

/// Decimal digits only: `str::parse` would also take a leading `+`.
fn digits<T: core::str::FromStr>(text: &str) -> Option<T> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// A session this dialer started.
pub struct LwipUdpSession<C: ClockSource + 'static> {
    handle: CoopLocalJoinHandle<DriverOutcome>,
    actions: Rc<McuActions<C>>,
    established: bool,
}

impl<C: ClockSource + 'static> LwipUdpSession<C> {
    /// The session's action bundle, to publish or declare through.
    pub fn actions(&self) -> &Rc<McuActions<C>> {
        &self.actions
    }
}

/// Dials UDP endpoints as initiator sessions on the firmware's task set.
///
/// `params` is asked for a fresh [`SessionInitParams`] per dial, so each
/// session can carry its own initial sequence number and cookie; `on_event`
/// is asked for the sink each new session reports to.
pub struct LwipUdpDialer<'a, C, P, E>
where
    C: ClockSource + 'static,
    P: FnMut() -> SessionInitParams,
    E: FnMut(&Rc<McuActions<C>>) -> EventSink,
{
    local: &'a CoopLocalSet<C>,
    link: Rc<LwipLink>,
    timeouts: SessionTimeouts,
    max_iters: Option<usize>,
    params: P,
    on_event: E,
}

impl<'a, C, P, E> LwipUdpDialer<'a, C, P, E>
where
    C: ClockSource + 'static,
    P: FnMut() -> SessionInitParams,
    E: FnMut(&Rc<McuActions<C>>) -> EventSink,
{
    /// A dialer spawning onto `local`, over `link`, with the handshake
    /// deadlines `timeouts`.
    pub fn new(
        local: &'a CoopLocalSet<C>,
        link: Rc<LwipLink>,
        timeouts: SessionTimeouts,
        params: P,
        on_event: E,
    ) -> Self {
        Self {
            local,
            link,
            timeouts,
            max_iters: None,
            params,
            on_event,
        }
    }

    /// Cap every session's iterations, for a test that must terminate.
    pub fn with_max_iters(mut self, max_iters: usize) -> Self {
        self.max_iters = Some(max_iters);
        self
    }
}

impl<'a, C, P, E> Dialer for LwipUdpDialer<'a, C, P, E>
where
    C: ClockSource + 'static,
    P: FnMut() -> SessionInitParams,
    E: FnMut(&Rc<McuActions<C>>) -> EventSink,
{
    type Session = LwipUdpSession<C>;

    fn dial(&mut self, endpoint: &str) -> Result<Self::Session, DialFailed> {
        let (addr, port) = parse_udp_endpoint(endpoint).map_err(DialFailed::Refused)?;
        // Port 0: lwIP picks a free local port, one per session.
        let socket = bind_session_rx(&self.link, 0).map_err(|_| DialFailed::Exhausted)?;
        let socket: SharedSessionSocket = Rc::new(RefCell::new(socket));
        let driver = Rc::new(LwipUdpDriver::new(socket, addr, port));
        let sink: Rc<dyn BoxedLinkDriver> = driver.clone();
        let runtime = self.local.runtime();
        let actions = McuActions::<C>::new_generic(sink, (self.params)(), CoopTime::new(runtime));
        let on_event = (self.on_event)(&actions);
        let handle = spawn_session(
            self.local,
            self.link.clone(),
            driver,
            actions.clone(),
            CoopTime::new(runtime),
            SessionDriveConfig {
                timeouts: self.timeouts,
                role: SessionRole::Initiator,
                max_iters: self.max_iters,
            },
            on_event,
        );
        Ok(LwipUdpSession {
            handle,
            actions,
            established: false,
        })
    }

    fn ended(&mut self, session: &mut Self::Session) -> Option<Ended> {
        session.established |= session.actions.is_established();
        if !session.handle.is_finished() {
            return None;
        }
        Some(if session.established {
            Ended::AfterEstablished
        } else {
            Ended::BeforeEstablished
        })
    }

    fn hang_up(&mut self, session: Self::Session) {
        // An established peer is told; a half-open one has nothing to close.
        if session.actions.is_established() {
            session.actions.send_close_with_reason(CloseReason::Generic);
        }
        session.handle.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    use wz_link_lwip::ipv4_addr_loopback;

    #[derive(Clone, Default)]
    struct FrozenClock;
    impl ClockSource for FrozenClock {
        fn now_us(&self) -> u64 {
            0
        }
    }

    /// A deterministic stand-in for a board's TRNG.
    struct Counting(u8);
    impl wz_session_core::entropy::EntropySource for Counting {
        fn try_fill_bytes(
            &mut self,
            buf: &mut [u8],
        ) -> Result<(), wz_session_core::entropy::EntropyUnavailable> {
            for b in buf {
                self.0 = self.0.wrapping_add(1);
                *b = self.0;
            }
            Ok(())
        }
    }

    fn params(zid: u8) -> SessionInitParams {
        SessionInitParams {
            version: 0x09,
            whatami: wz_session_core::WhatAmI::Peer,
            zid: vec![zid; 4],
            seq_num_res: 2,
            req_id_res: 2,
            batch_size: 1024,
            lease_ms: 10_000,
            initial_sn: 0,
            cookie: vec![],
            cookie_signing_key: wz_session_core::signing_key::SigningKey::new(vec![7u8; 32])
                .expect("key"),
        }
    }

    fn quiet(_: &Rc<McuActions<FrozenClock>>) -> EventSink {
        Box::new(|_| {})
    }

    #[test]
    fn only_udp_to_an_ipv4_address_is_dialable() {
        let lo = ipv4_addr_loopback();
        std::assert_eq!(parse_udp_endpoint("udp/127.0.0.1:7447"), Ok((lo, 7447)));
        for (text, why) in [
            ("tcp/127.0.0.1:7447", DialRefused::Unsupported),
            ("udp/127.0.0.1:7447#iface=eth0", DialRefused::Unsupported),
            ("udp/127.0.0.1:7447?prio=1", DialRefused::Unsupported),
            ("udp/router.local:7447", DialRefused::BadAddress),
            ("udp/127.0.0.1", DialRefused::BadAddress),
            ("udp/127.0.0.1:0", DialRefused::BadAddress),
            ("udp/127.0.0.1:+80", DialRefused::BadAddress),
            ("udp/127.0.0.256:7447", DialRefused::BadAddress),
            ("udp/127.0.0.1.5:7447", DialRefused::BadAddress),
            ("udp/[::1]:7447", DialRefused::BadAddress),
        ] {
            std::assert_eq!(parse_udp_endpoint(text), Err(why), "{text}");
        }
    }

    /// A dial opens a real session towards the endpoint: an acceptor on the
    /// same lwIP loopback completes the handshake with it, and once the
    /// session's task ends it reads as ended AFTER establishing. The control
    /// is a dial nobody answers, which ends BEFORE establishing.
    #[test]
    fn a_dialled_endpoint_becomes_an_established_session() {
        let (_serial, link) = wz_link_lwip::lwip_test_link();
        let link = Rc::new(link);
        let runtime = CoopRuntime::new(FrozenClock);
        let local = CoopLocalSet::new(&runtime);

        // The acceptor the dial will reach.
        let acceptor_port: u16 = 7494;
        let acceptor_socket: SharedSessionSocket = Rc::new(RefCell::new(
            bind_session_rx(&link, acceptor_port).expect("bind acceptor"),
        ));
        let acceptor_driver = Rc::new(LwipUdpDriver::new(acceptor_socket, 0, 0));
        let acceptor_sink: Rc<dyn BoxedLinkDriver> = acceptor_driver.clone();
        // An acceptor mints its cookie from a per-handshake nonce and refuses
        // to mint without an entropy source, so it is built through the seam
        // a board uses.
        let acceptor_actions = wz_runtime_coop::session_runtime::new_session_actions(
            acceptor_sink,
            params(0xa1),
            CoopTime::new(&runtime),
            Counting(1),
        );
        let _acceptor = spawn_session(
            &local,
            link.clone(),
            acceptor_driver,
            acceptor_actions.clone(),
            CoopTime::new(&runtime),
            SessionDriveConfig {
                timeouts: SessionTimeouts::spec_defaults(),
                role: SessionRole::Acceptor,
                max_iters: None,
            },
            |_| {},
        );

        let mut dialer = LwipUdpDialer::new(
            &local,
            link.clone(),
            SessionTimeouts::spec_defaults(),
            || params(0xb1),
            quiet,
        );
        let mut session = dialer.dial("udp/127.0.0.1:7494").expect("dialable");
        for _ in 0..64 {
            local.run_until_idle();
            if session.actions().is_established() {
                break;
            }
        }
        std::assert!(
            session.actions().is_established(),
            "the handshake completed\ninitiator: {:?}\nacceptor: {:?}",
            session.actions().trace_snapshot(),
            acceptor_actions.trace_snapshot()
        );
        std::assert!(acceptor_actions.is_established(), "on both ends");
        std::assert_eq!(dialer.ended(&mut session), None, "still live");

        session.handle.abort();
        std::assert_eq!(dialer.ended(&mut session), Some(Ended::AfterEstablished));

        // CONTROL: nobody listens on 7495, and the capped session ends first.
        let mut unanswered = LwipUdpDialer::new(
            &local,
            link.clone(),
            SessionTimeouts::spec_defaults(),
            || params(0xc1),
            quiet,
        )
        .with_max_iters(8);
        let mut lost = unanswered.dial("udp/127.0.0.1:7495").expect("dialable");
        for _ in 0..16 {
            local.run_until_idle();
        }
        std::assert_eq!(unanswered.ended(&mut lost), Some(Ended::BeforeEstablished));

        std::assert!(matches!(
            unanswered.dial("tcp/127.0.0.1:7447"),
            Err(DialFailed::Refused(DialRefused::Unsupported))
        ));
    }
}
