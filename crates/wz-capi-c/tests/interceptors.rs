// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The policy a node's config states is enforced on the paths a C program uses, in both
//! directions, and the same traffic with no policy is delivered.
//!
//! `access_control`, `low_pass_filter` and `downsampling` were read into the node's config and
//! then dropped at `z_open`: the ACL was refused outright (a node that starts without the policy
//! it was configured with is one its operator believes protected) and the other two were accepted
//! and ignored. Each leg below has its CONTROL, the identical traffic against a node with no
//! policy, because "the denied sample never arrived" proves nothing about a harness whose samples
//! never arrive.
//!
//! Two sending paths are driven, because they are different code: `z_put` on the session, and a
//! put on a declared publisher (the fast path that writes the frame without building a message).
//! A policy that holds on one and not the other is the bypass this file exists to find.

use std::ffi::{c_void, CString};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use wz_capi_c::abi::{
    z_loaned_sample_t, z_moved_bytes_t, z_moved_closure_sample_t, z_moved_config_t,
    z_moved_publisher_t, z_moved_session_t, z_owned_bytes_t, z_owned_closure_sample_t,
    z_owned_config_t, z_owned_publisher_t, z_owned_session_t, z_owned_subscriber_t,
    z_view_keyexpr_t,
};
use wz_capi_c::bytes::z_bytes_copy_from_buf;
use wz_capi_c::config::{z_config_default, z_config_loan_mut, zc_config_insert_json5};
use wz_capi_c::keyexpr::{z_view_keyexpr_from_str, z_view_keyexpr_loan};
use wz_capi_c::publisher::{
    z_declare_publisher, z_publisher_loan, z_publisher_put, z_undeclare_publisher,
};
use wz_capi_c::put::z_put;
use wz_capi_c::result::Z_OK;
use wz_capi_c::session::{z_close, z_open, z_session_drop, z_session_loan, z_session_loan_mut};
use wz_capi_c::sub::{z_closure_sample, z_declare_subscriber};
use wz_runtime_tokio_test_support::free_port;

/// The key the policy under test governs, and the key it does not.
const GOVERNED: &str = "denied/data";
const FREE: &str = "allowed/data";

/// How a program sends.
#[derive(Clone, Copy, Debug)]
enum Via {
    /// `z_put` on the session.
    SessionPut,
    /// `z_publisher_put` on a declared publisher.
    Publisher,
}

const BOTH_PATHS: [Via; 2] = [Via::SessionPut, Via::Publisher];

unsafe fn open_with(entries: &[(&str, String)]) -> (i8, z_owned_session_t) {
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    for (key, value) in entries {
        let key = CString::new(*key).unwrap();
        let value = CString::new(value.as_str()).unwrap();
        assert_eq!(
            zc_config_insert_json5(z_config_loan_mut(&mut cfg), key.as_ptr(), value.as_ptr()),
            Z_OK,
            "the config accepts {key:?}"
        );
    }
    let mut session: z_owned_session_t = std::mem::zeroed();
    let rc = z_open(
        &mut session,
        (&mut cfg as *mut z_owned_config_t).cast::<z_moved_config_t>(),
        std::ptr::null(),
    );
    (rc, session)
}

unsafe fn close_session(mut session: z_owned_session_t) {
    let _ = z_close(z_session_loan_mut(&mut session), std::ptr::null_mut());
    z_session_drop((&mut session as *mut z_owned_session_t).cast::<z_moved_session_t>());
}

struct CountCtx {
    hits: Arc<AtomicUsize>,
}

unsafe extern "C" fn on_sample(_sample: *const z_loaned_sample_t, ctx: *mut c_void) {
    (*(ctx as *const CountCtx))
        .hits
        .fetch_add(1, Ordering::SeqCst);
}

/// A subscriber on `key` that counts its samples; the context is freed by the caller after the
/// session closes.
unsafe fn count_samples(
    session: &z_owned_session_t,
    key: &str,
) -> (Arc<AtomicUsize>, *mut CountCtx) {
    let hits = Arc::new(AtomicUsize::new(0));
    let ctx = Box::into_raw(Box::new(CountCtx { hits: hits.clone() }));
    let mut sub: z_owned_subscriber_t = std::mem::zeroed();
    let mut closure: z_owned_closure_sample_t = std::mem::zeroed();
    z_closure_sample(&mut closure, Some(on_sample), None, ctx.cast());
    let ke = CString::new(key).unwrap();
    let mut view: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut view, ke.as_ptr()), Z_OK);
    assert_eq!(
        z_declare_subscriber(
            z_session_loan(session),
            &mut sub,
            z_view_keyexpr_loan(&view),
            (&mut closure as *mut z_owned_closure_sample_t).cast::<z_moved_closure_sample_t>(),
            std::ptr::null_mut(),
        ),
        Z_OK
    );
    (hits, ctx)
}

/// Something that can send one put on a key, by one of the two paths.
struct Sender<'a> {
    session: &'a z_owned_session_t,
    publisher: Option<(z_owned_publisher_t, String)>,
}

impl<'a> Sender<'a> {
    unsafe fn new(session: &'a z_owned_session_t, via: Via, key: &str) -> Self {
        let publisher = match via {
            Via::SessionPut => None,
            Via::Publisher => {
                let ke = CString::new(key).unwrap();
                let mut view: z_view_keyexpr_t = std::mem::zeroed();
                assert_eq!(z_view_keyexpr_from_str(&mut view, ke.as_ptr()), Z_OK);
                let mut publisher: z_owned_publisher_t = std::mem::zeroed();
                assert_eq!(
                    z_declare_publisher(
                        z_session_loan(session),
                        &mut publisher,
                        z_view_keyexpr_loan(&view),
                        std::ptr::null_mut(),
                    ),
                    Z_OK
                );
                Some((publisher, key.to_owned()))
            }
        };
        Self { session, publisher }
    }

    unsafe fn put(&self, key: &str, bytes: &[u8]) {
        let mut payload: z_owned_bytes_t = std::mem::zeroed();
        assert_eq!(
            z_bytes_copy_from_buf(&mut payload, bytes.as_ptr(), bytes.len()),
            Z_OK
        );
        let moved = (&mut payload as *mut z_owned_bytes_t).cast::<z_moved_bytes_t>();
        match &self.publisher {
            // A publisher is bound to the key it declared; the leg declares one per key.
            Some((publisher, declared)) => {
                assert_eq!(declared, key, "a publisher puts on the key it declared");
                assert_eq!(
                    z_publisher_put(z_publisher_loan(publisher), moved, std::ptr::null_mut()),
                    Z_OK
                );
            }
            None => {
                let ke = CString::new(key).unwrap();
                let mut view: z_view_keyexpr_t = std::mem::zeroed();
                assert_eq!(z_view_keyexpr_from_str(&mut view, ke.as_ptr()), Z_OK);
                assert_eq!(
                    z_put(
                        z_session_loan(self.session),
                        z_view_keyexpr_loan(&view),
                        moved,
                        std::ptr::null_mut(),
                    ),
                    Z_OK
                );
            }
        }
    }
}

impl Drop for Sender<'_> {
    fn drop(&mut self) {
        if let Some((mut publisher, _)) = self.publisher.take() {
            // SAFETY: a live publisher this value declared.
            unsafe {
                let _ = z_undeclare_publisher(
                    (&mut publisher as *mut z_owned_publisher_t).cast::<z_moved_publisher_t>(),
                );
            }
        }
    }
}

fn endpoint(port: u16) -> String {
    format!("[\"tcp/127.0.0.1:{port}\"]")
}

fn listener_entries(port: u16, policy: &[(&'static str, String)]) -> Vec<(&'static str, String)> {
    let mut entries = vec![
        ("scouting/multicast/enabled", "false".to_owned()),
        ("mode", "\"peer\"".to_owned()),
        ("listen/endpoints", endpoint(port)),
    ];
    entries.extend_from_slice(policy);
    entries
}

fn client_entries(port: u16, policy: &[(&'static str, String)]) -> Vec<(&'static str, String)> {
    let mut entries = vec![
        ("scouting/multicast/enabled", "false".to_owned()),
        ("mode", "\"client\"".to_owned()),
        ("connect/endpoints", endpoint(port)),
    ];
    entries.extend_from_slice(policy);
    entries
}

/// A policy denying `put` on [`GOVERNED`] in `flow`, for every peer, allowing the rest.
fn acl_denying_put(flow: &str) -> Vec<(&'static str, String)> {
    vec![
        ("access_control/enabled", "true".to_owned()),
        ("access_control/default_permission", "\"allow\"".to_owned()),
        (
            "access_control/rules",
            format!(
                r#"[{{ id: "deny_governed", key_exprs: ["denied/**"], messages: ["put"],
                      flows: ["{flow}"], permission: "deny" }}]"#
            ),
        ),
        (
            "access_control/subjects",
            r#"[{ id: "everyone" }]"#.to_owned(),
        ),
        (
            "access_control/policies",
            r#"[{ rules: ["deny_governed"], subjects: ["everyone"] }]"#.to_owned(),
        ),
    ]
}

/// What a listener's two subscribers counted after a client sent `burst` puts on the governed
/// key and then one on the free key (the marker: it is on the same link, after the burst, so once
/// it has arrived every governed sample that was going to arrive has).
struct Outcome {
    governed: usize,
    free: usize,
}

/// One scenario: a listener with `listener_policy`, a client with `client_policy`, the client
/// sends by `via`. The listener's subscribers count both keys.
fn run(
    listener_policy: &[(&'static str, String)],
    client_policy: &[(&'static str, String)],
    via: Via,
    burst: usize,
    payload: &[u8],
) -> Outcome {
    let port = free_port();
    // SAFETY: fresh configs and sessions, closed at the end of this function.
    unsafe {
        let (rc, listener) = open_with(&listener_entries(port, listener_policy));
        assert_eq!(rc, Z_OK, "the listener opens with its policy");
        let (governed_hits, governed_ctx) = count_samples(&listener, "denied/**");
        let (free_hits, free_ctx) = count_samples(&listener, "allowed/**");

        let (rc, client) = open_with(&client_entries(port, client_policy));
        assert_eq!(rc, Z_OK, "the client opens with its policy");
        let governed = Sender::new(&client, via, GOVERNED);
        let free = Sender::new(&client, via, FREE);

        // The subscription must have reached the client before anything is judged: put on the
        // free key until one arrives. (An ACL that denies the free key too would never get here,
        // which is a failure of the leg and says so.)
        let deadline = Instant::now() + Duration::from_secs(10);
        while free_hits.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
            free.put(FREE, b"warm");
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            free_hits.load(Ordering::SeqCst) > 0,
            "{via:?}: no sample on the free key ever arrived, so nothing below can be judged"
        );
        std::thread::sleep(Duration::from_millis(200));
        governed_hits.store(0, Ordering::SeqCst);
        free_hits.store(0, Ordering::SeqCst);

        for _ in 0..burst {
            governed.put(GOVERNED, payload);
            std::thread::sleep(Duration::from_millis(5));
        }
        free.put(FREE, b"marker");
        let deadline = Instant::now() + Duration::from_secs(5);
        while free_hits.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        // A quiet window, so a sample that is merely late is still counted.
        std::thread::sleep(Duration::from_millis(400));
        let outcome = Outcome {
            governed: governed_hits.load(Ordering::SeqCst),
            free: free_hits.load(Ordering::SeqCst),
        };

        drop(governed);
        drop(free);
        close_session(client);
        close_session(listener);
        drop(Box::from_raw(governed_ctx));
        drop(Box::from_raw(free_ctx));
        outcome
    }
}

#[test]
fn control_without_a_policy_every_put_arrives_on_both_paths() {
    for via in BOTH_PATHS {
        let outcome = run(&[], &[], via, 5, b"payload");
        assert_eq!(
            outcome.governed, 5,
            "{via:?}: the harness delivers the governed key"
        );
        assert_eq!(outcome.free, 1, "{via:?}: the marker arrives");
    }
}

#[test]
fn an_ingress_deny_rule_drops_the_governed_put_before_the_subscriber_on_both_paths() {
    for via in BOTH_PATHS {
        let outcome = run(&acl_denying_put("ingress"), &[], via, 5, b"payload");
        assert_eq!(
            outcome.governed, 0,
            "{via:?}: a put the listener's ingress policy denies reached its subscriber"
        );
        assert_eq!(
            outcome.free, 1,
            "{via:?}: the policy denied more than the key it names"
        );
    }
}

#[test]
fn an_egress_deny_rule_keeps_the_governed_put_off_the_wire_on_both_paths() {
    for via in BOTH_PATHS {
        let outcome = run(&[], &acl_denying_put("egress"), via, 5, b"payload");
        assert_eq!(
            outcome.governed, 0,
            "{via:?}: a put the sender's egress policy denies was sent"
        );
        assert_eq!(
            outcome.free, 1,
            "{via:?}: the policy denied more than the key it names"
        );
    }
}

/// A payload past the filter's limit is dropped and one within it is delivered, on a key the
/// filter names, so the control is the within-limit put on the same key.
#[test]
fn a_low_pass_filter_drops_a_payload_past_its_limit_on_both_paths() {
    let filter = vec![(
        "low_pass_filter",
        r#"[{ messages: ["put"], key_exprs: ["denied/**"], flows: ["ingress"],
              size_limit: 16 }]"#
            .to_owned(),
    )];
    for via in BOTH_PATHS {
        let within = run(&filter, &[], via, 3, &[7u8; 8]);
        assert_eq!(
            within.governed, 3,
            "{via:?}: a payload within the limit is delivered"
        );
        let past = run(&filter, &[], via, 3, &[7u8; 64]);
        assert_eq!(
            past.governed, 0,
            "{via:?}: a payload past the limit reached the subscriber"
        );
        assert_eq!(
            past.free, 1,
            "{via:?}: the filter dropped more than the key it names"
        );
    }
}

/// A put too big for one frame is fragmented, reassembled by the receiver, and turned into a
/// message in a different place from one that fits. A policy that held for the small put and not
/// for this one would be stepped around by exactly the traffic a size cap exists for, so the same
/// rules are asked of a payload several times the batch size. The control is the same payload
/// with no policy, which must arrive whole: without it a green result would only say the big put
/// never made it.
#[test]
fn a_put_too_big_for_one_frame_is_judged_like_one_that_fits_on_both_paths() {
    let big = vec![7u8; 200_000];
    let capped = vec![(
        "low_pass_filter",
        r#"[{ messages: ["put"], key_exprs: ["denied/**"], flows: ["ingress"],
              size_limit: 65536 }]"#
            .to_owned(),
    )];
    for via in BOTH_PATHS {
        let control = run(&[], &[], via, 2, &big);
        assert_eq!(
            control.governed, 2,
            "{via:?}: the harness does not deliver a payload this big, so nothing below proves anything"
        );
        let denied = run(&acl_denying_put("ingress"), &[], via, 2, &big);
        assert_eq!(
            denied.governed, 0,
            "{via:?}: a fragmented put the ingress policy denies reached the subscriber"
        );
        assert_eq!(
            denied.free, 1,
            "{via:?}: the policy denied more than the key it names"
        );
        let past_cap = run(&capped, &[], via, 2, &big);
        assert_eq!(
            past_cap.governed, 0,
            "{via:?}: a fragmented put past the size cap reached the subscriber"
        );
    }
}

/// A burst far faster than the rate lets through at most a couple of samples; the control is the
/// same burst with no rule, which delivers all of it.
#[test]
fn a_downsampling_rule_thins_a_burst_on_both_paths() {
    let rule = vec![(
        "downsampling",
        r#"[{ messages: ["put"], flows: ["ingress"],
              rules: [{ key_expr: "denied/**", freq: 1.0 }] }]"#
            .to_owned(),
    )];
    for via in BOTH_PATHS {
        let thinned = run(&rule, &[], via, 40, b"payload");
        assert!(
            thinned.governed <= 3,
            "{via:?}: {} of 40 samples passed a 1 Hz downsampling rule",
            thinned.governed
        );
        assert_eq!(
            thinned.free, 1,
            "{via:?}: the rule thinned more than the key it names"
        );
    }
}
