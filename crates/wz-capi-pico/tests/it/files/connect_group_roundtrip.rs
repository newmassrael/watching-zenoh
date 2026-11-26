// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
//! A session whose connect locator names a multicast group joins that group as its one transport,
//! as pico's client opens a multicast transport on such a locator
//! (`vendor/zenoh-pico/src/transport/manager.c` @ `case Z_LINK_CAP_TRANSPORT_RAWETH:`, in its
//! client open as in its peer open), and its puts reach the other members and theirs reach it.
//! Driven through the exported `z_*` symbols, as a C program drives them.
//!
//! Two shapes: a client that connects to the group beside a peer that listens on it, and two
//! clients that both connect to it. A session that read its connect locator as a unicast dial
//! would wait for an answer to its handshake that no member of a group sends, and fail its open.
//!
//! Each member subscribes to the whole key space of the test and puts its own payload; a
//! session also hears its own puts on its local plane, so what is asserted is that each heard the
//! payload of every OTHER member. The group is a real one on the loopback interface, so the test
//! needs a multicast route on the host, as every group test of the host's sockets does.

#![cfg(all(feature = "multicast-transport", target_os = "linux"))]

use std::ffi::{c_void, CStr, CString};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[cfg(feature = "peer")]
use wz_capi_pico::Z_CONFIG_LISTEN_KEY;
use wz_capi_pico::{
    z_bytes_copy_from_str, z_bytes_move, z_bytes_to_slice, z_close, z_closure_sample,
    z_closure_sample_move, z_config_default, z_config_loan_mut, z_config_move,
    z_declare_subscriber, z_loaned_sample_t, z_open, z_owned_config_t, z_owned_session_t,
    z_owned_slice_t, z_owned_subscriber_t, z_put, z_sample_payload, z_session_drop, z_session_loan,
    z_session_loan_mut, z_session_move, z_slice_data, z_slice_drop, z_slice_len, z_slice_loan,
    z_slice_move, z_subscriber_move, z_undeclare_subscriber, z_view_keyexpr_from_str,
    z_view_keyexpr_loan, z_view_keyexpr_t, zp_config_insert, Z_CONFIG_CONNECT_KEY,
    Z_CONFIG_MODE_KEY, Z_OK,
};
use wz_runtime_tokio_test_support::free_port;

/// How long the members are given to hear each other: a member's puts reach another once that
/// one has taken its JOIN, which pico's preset sends every 2.5 s, so several intervals with room.
const HEARD_WITHIN: Duration = Duration::from_secs(30);

/// What every member subscribes to.
const EVERY_KEY: &CStr = c"demo/connect-group/**";

/// The payloads heard by one member's subscriber, shared with its callback.
type Heard = Mutex<Vec<Vec<u8>>>;

unsafe extern "C" fn on_sample(sample: *const z_loaned_sample_t, context: *mut c_void) {
    let heard = &*(context as *const Heard);
    let mut slice: z_owned_slice_t = std::mem::zeroed();
    if z_bytes_to_slice(z_sample_payload(sample), &mut slice) == Z_OK {
        let loaned = z_slice_loan(&slice);
        let (data, len) = (z_slice_data(loaned), z_slice_len(loaned));
        if !data.is_null() {
            if let Ok(mut heard) = heard.lock() {
                heard.push(std::slice::from_raw_parts(data, len).to_vec());
            }
        }
        z_slice_drop(z_slice_move(&mut slice));
    }
}

unsafe extern "C" fn on_drop(context: *mut c_void) {
    drop(Arc::from_raw(context as *const Heard));
}

/// A group of this host's loopback interface on a port no other test is on.
fn loopback_group() -> CString {
    CString::new(format!("udp/224.0.0.224:{}#iface=lo", free_port())).unwrap()
}

/// One session on the group: its subscriber to [`EVERY_KEY`], what it heard there, and the key and
/// payload it puts.
struct Member {
    session: z_owned_session_t,
    subscriber: z_owned_subscriber_t,
    heard: Arc<Heard>,
    key: &'static CStr,
    says: &'static CStr,
}

impl Member {
    /// Open a session from `entries` and subscribe it to [`EVERY_KEY`].
    unsafe fn open(entries: &[(u8, &CStr)], key: &'static CStr, says: &'static CStr) -> Self {
        let mut cfg: z_owned_config_t = std::mem::zeroed();
        assert_eq!(z_config_default(&mut cfg), Z_OK);
        for (config_key, value) in entries {
            assert_eq!(
                zp_config_insert(z_config_loan_mut(&mut cfg), *config_key, value.as_ptr()),
                Z_OK
            );
        }
        let mut session: z_owned_session_t = std::mem::zeroed();
        assert_eq!(
            z_open(&mut session, z_config_move(&mut cfg), std::ptr::null()),
            Z_OK,
            "the session of {entries:?} did not open on its group"
        );
        let heard = Arc::new(Heard::default());
        let mut closure = std::mem::zeroed();
        assert_eq!(
            z_closure_sample(
                &mut closure,
                Some(on_sample),
                Some(on_drop),
                Arc::into_raw(Arc::clone(&heard)) as *mut c_void,
            ),
            Z_OK
        );
        let mut view: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut view, EVERY_KEY.as_ptr()), Z_OK);
        let mut subscriber: z_owned_subscriber_t = std::mem::zeroed();
        assert_eq!(
            z_declare_subscriber(
                z_session_loan(&session),
                &mut subscriber,
                z_view_keyexpr_loan(&view),
                z_closure_sample_move(&mut closure),
                std::ptr::null(),
            ),
            Z_OK
        );
        Self {
            session,
            subscriber,
            heard,
            key,
            says,
        }
    }

    /// Put this member's payload on its key.
    unsafe fn put(&self) {
        let mut view: z_view_keyexpr_t = std::mem::zeroed();
        assert_eq!(z_view_keyexpr_from_str(&mut view, self.key.as_ptr()), Z_OK);
        let mut payload = std::mem::zeroed();
        assert_eq!(
            z_bytes_copy_from_str(&mut payload, self.says.as_ptr()),
            Z_OK
        );
        assert_eq!(
            z_put(
                z_session_loan(&self.session),
                z_view_keyexpr_loan(&view),
                z_bytes_move(&mut payload),
                std::ptr::null(),
            ),
            Z_OK,
            "a put of {:?} on its group",
            self.says
        );
    }

    /// Whether this member's subscriber heard `payload`.
    fn has_heard(&self, payload: &CStr) -> bool {
        self.heard
            .lock()
            .unwrap()
            .iter()
            .any(|heard| heard.as_slice() == payload.to_bytes())
    }

    /// Undeclare the subscriber and close the session.
    unsafe fn close(mut self) {
        assert_eq!(
            z_undeclare_subscriber(z_subscriber_move(&mut self.subscriber)),
            Z_OK
        );
        z_close(z_session_loan_mut(&mut self.session), std::ptr::null());
        z_session_drop(z_session_move(&mut self.session));
    }
}

/// Each member puts until every member has heard the payload of every other one.
unsafe fn exchange(members: &[&Member]) {
    let deadline = Instant::now() + HEARD_WITHIN;
    let unheard = move || {
        members
            .iter()
            .flat_map(move |listener| {
                members
                    .iter()
                    .filter(move |speaker| speaker.says != listener.says)
                    .filter(move |speaker| !listener.has_heard(speaker.says))
                    .map(move |speaker| (listener.says, speaker.says))
            })
            .collect::<Vec<_>>()
    };
    loop {
        let missing = unheard();
        if missing.is_empty() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "within {HEARD_WITHIN:?} on the group, these members (listener, speaker) did not hear \
             each other: {missing:?}"
        );
        for member in members {
            member.put();
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// A client that connects to the group and a peer that listens on it hear each other's puts.
#[cfg(feature = "peer")]
#[test]
#[ignore = "environment-dependent: needs a multicast route on this host (Layer M runs it)"]
fn a_client_connecting_to_a_group_and_a_peer_listening_on_it_exchange_puts() {
    let _program = crate::programs::admit();
    let group = loopback_group();
    unsafe {
        let peer = Member::open(
            &[
                (Z_CONFIG_MODE_KEY, c"peer"),
                (Z_CONFIG_LISTEN_KEY, group.as_c_str()),
            ],
            c"demo/connect-group/peer",
            c"from-the-listening-peer",
        );
        let client = Member::open(
            &[
                (Z_CONFIG_MODE_KEY, c"client"),
                (Z_CONFIG_CONNECT_KEY, group.as_c_str()),
            ],
            c"demo/connect-group/client",
            c"from-the-connecting-client",
        );
        exchange(&[&peer, &client]);
        client.close();
        peer.close();
    }
}

/// Two clients that both connect to the group hear each other's puts: neither listens, so the
/// group each joined from its connect locator is the only transport between them.
#[test]
#[ignore = "environment-dependent: needs a multicast route on this host (Layer M runs it)"]
fn two_clients_connecting_to_one_group_exchange_puts() {
    let _program = crate::programs::admit();
    let group = loopback_group();
    unsafe {
        let first = Member::open(
            &[
                (Z_CONFIG_MODE_KEY, c"client"),
                (Z_CONFIG_CONNECT_KEY, group.as_c_str()),
            ],
            c"demo/connect-group/first",
            c"from-the-first-client",
        );
        let second = Member::open(
            &[
                (Z_CONFIG_MODE_KEY, c"client"),
                (Z_CONFIG_CONNECT_KEY, group.as_c_str()),
            ],
            c"demo/connect-group/second",
            c"from-the-second-client",
        );
        exchange(&[&first, &second]);
        second.close();
        first.close();
    }
}
