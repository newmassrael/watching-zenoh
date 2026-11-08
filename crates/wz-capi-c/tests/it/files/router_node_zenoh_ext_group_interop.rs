// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The group of a node opened through the C ABI (`router-node`) and a REAL zenoh-ext `Group`.
//!
//! # What is being claimed
//!
//! `node_group` holds a node and wz members that dial it, and `router_node_zenohd_interop` puts
//! a real zenohd between a node and a wz client; in both, every member is wz, so a member record,
//! a keep-alive or an announcement spelled wrongly in the node's group would be read back by the
//! same wrong reader. Here the other member is upstream's own group, the `z_view_size` example of
//! the pinned zenoh-ext, dialing the node as a client of the node's south. The node's group runs
//! its own transport (its announcement, its event subscriber, its member queryable and its
//! watchdog are the node's data plane and its periodic jobs, `wz_capi_core::group::node`), and
//! that transport is what these legs put in front of a foreign reader.
//!
//! # The legs
//!
//! 1. The node joins first. The oracle has never heard the node announce itself, so it learns
//!    the node from its keep-alive alone, asks for the record on the member's key (the only query
//!    of upstream's group, `zenoh-ext/src/group.rs` @ `let qres = format!`), and the node's member
//!    queryable answers. The oracle prints its own verdict, so the judgement is upstream's. The
//!    same leg first runs the node in ANOTHER group, where the oracle must fail: the node is open,
//!    dialed and beaconing, and only the group differs.
//! 2. The oracle joins first and the node after, with a lease of a minute: the node's first
//!    keep-alive is due 45 s later, far past the oracle's wait, so the node's announcement on the
//!    event key is the only way into the oracle's view.
//! 3. The node observes. The oracle joins after the node, and the node's view must name it; the
//!    oracle then exits, and the node must drop it within the lease the ORACLE stated (3 s,
//!    `zenoh-ext/examples/examples/z_view_size.rs` @ `.lease(Duration::from_secs(3))`). The node
//!    states a minute, so a node that timed the eviction on its own lease would keep the member.
//! 4. Two clients of the node, a wz client and the oracle, share no link, so all they hear of one
//!    another crosses the node: the wz client's beacon and record reach the oracle, and the
//!    oracle's announcement reaches the wz client. The same leg first puts the wz client on
//!    another node, where the oracle must fail, which is what makes a meeting a meeting through
//!    the node.
//!
//! # What is NOT claimed
//!
//! A `Leave` is in neither: no group, upstream's or wz's, sends one (`wz_group_membership_zenoh_
//! ext_interop` gives the finding); a member leaves a view by its lease, which is leg 3. The
//! election is computed by the same table the runtime's group uses, which that file measures
//! against upstream.
//!
//! `#[ignore]` (binary-dep e2e): needs the zenoh-ext example `z_view_size` that
//! `scripts/build-zenohd.sh` builds beside zenohd (or `WZ_ZENOH_EXT_EXAMPLES_DIR`). Run via
//! Layer Z / `--ignored`.

#![cfg(all(
    feature = "router-node",
    feature = "group",
    not(feature = "zenoh-c-no-unstable-api")
))]

use std::ffi::{c_void, CString};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use wz_capi_c::abi::{
    z_moved_config_t, z_moved_session_t, z_owned_config_t, z_owned_session_t, z_view_keyexpr_t,
    z_view_string_t,
};
use wz_capi_c::config::{z_config_default, z_config_loan_mut, zc_config_insert_json5};
use wz_capi_c::group::{
    wz_capi_c_closure_member, wz_capi_c_group_drop, wz_capi_c_group_join, wz_capi_c_group_loan,
    wz_capi_c_group_size, wz_capi_c_group_view, wz_capi_c_group_wait_for_view_size,
    wz_capi_c_loaned_member_t, wz_capi_c_member_id, wz_capi_c_member_new,
    wz_capi_c_member_options_default, wz_capi_c_member_options_t, wz_capi_c_moved_closure_member_t,
    wz_capi_c_moved_group_t, wz_capi_c_moved_member_t, wz_capi_c_owned_closure_member_t,
    wz_capi_c_owned_group_t, wz_capi_c_owned_member_t,
};
use wz_capi_c::keyexpr::{z_view_keyexpr_from_str, z_view_keyexpr_loan};
use wz_capi_c::result::Z_OK;
use wz_capi_c::session::{z_close, z_open, z_session_drop, z_session_loan, z_session_loan_mut};
use wz_capi_c::string::{z_string_data, z_string_len, z_view_string_loan};
use wz_runtime_tokio_test_support::free_port;

/// The group the members of a leg join.
const GROUP: &str = "wz/router-node/zenoh-ext/group";

/// The group the node or the wz client joins in a leg's control.
const OTHER_GROUP: &str = "wz/router-node/zenoh-ext/other";

const NODE_MEMBER: &str = "a-node";
const CLIENT_MEMBER: &str = "wz-client";
const ORACLE_MEMBER: &str = "oracle";

/// The lease of a wz member whose keep-alive a leg needs: the beacon comes every
/// `lease * refresh_ratio` (0.75 by default, upstream's), 2.25 s, well inside [`VIEW_TIMEOUT_SECS`].
const BEACON_LEASE_MS: u64 = 3_000;

/// The lease of a wz member whose keep-alive a leg must keep out: the first is due 45 s after the
/// join, past every wait of the leg.
const SILENT_LEASE_MS: u64 = 60_000;

/// How long the oracle waits for its view to reach the size it was asked for, after which it prints
/// that it failed and exits.
const VIEW_TIMEOUT_SECS: u64 = 8;

/// The timeout of an oracle that leg 3 asks for a size it cannot reach, so that it exits at a moment
/// the leg chose rather than when its view filled.
const OBSERVED_ORACLE_TIMEOUT_SECS: u64 = 3;

/// How long the oracle is given, past its own timeout, to print and exit.
const EXIT_MARGIN: Duration = Duration::from_secs(15);

/// How long a spawned oracle is given to join and say it is waiting.
const JOIN_BUDGET: Duration = Duration::from_secs(20);

/// How long the node is given to fold a foreign member into its view.
const VIEW_BUDGET: Duration = Duration::from_secs(20);

/// How long the node is given, after the oracle exited, to drop it. The oracle's last keep-alive
/// is at most 2.25 s before its exit and its lease is 3 s, so the node's deadline falls about
/// 0.75 s after the exit and its watchdog sweeps within a second of that. Falling back to the
/// node's own lease (60 s) or to upstream's default (18 s) lands outside.
const EVICTION_DEADLINE: Duration = Duration::from_secs(12);

/// Locate upstream's `z_view_size`, built by `scripts/build-zenohd.sh` beside zenohd.
fn view_size_oracle() -> PathBuf {
    let dir = match std::env::var("WZ_ZENOH_EXT_EXAMPLES_DIR") {
        Ok(dir) => PathBuf::from(dir),
        Err(_) => wz_codegen_build::artifact("target/zenohd"),
    };
    let path = dir.join("z_view_size");
    assert!(
        path.is_file(),
        "z_view_size is missing at {}; set WZ_ZENOH_EXT_EXAMPLES_DIR or run \
         scripts/build-zenohd.sh",
        path.display()
    );
    path
}

/// Everything `file` holds, from its start.
fn contents(file: &mut File) -> String {
    let mut text = String::new();
    file.seek(SeekFrom::Start(0))
        .expect("rewind the captured output");
    file.read_to_string(&mut text)
        .expect("read the captured output");
    text
}

/// Wait until `capture` holds `needle`, the child exits, or [`JOIN_BUDGET`] runs out; the error is
/// what the capture held then. The shape is `config_verdict_zenohd_interop`'s, which is the one the
/// barrier gate reads this crate's needles by.
fn wait_for_substring(
    child: &mut Child,
    capture: &mut File,
    needle: &str,
) -> Result<String, String> {
    let deadline = Instant::now() + JOIN_BUDGET;
    loop {
        let text = contents(capture);
        if text.contains(needle) {
            return Ok(text);
        }
        if let Ok(Some(status)) = child.try_wait() {
            // One more read: the line may have landed between the two calls.
            let text = contents(capture);
            if text.contains(needle) {
                return Ok(text);
            }
            return Err(format!("z_view_size exited ({status:?})\n{text}"));
        }
        if Instant::now() >= deadline {
            return Err(text);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A running `z_view_size`: a member of upstream's group that dials one endpoint as a client,
/// waits for its view to reach a size, prints its verdict and exits. Killed on drop.
struct Oracle {
    child: Child,
    output: File,
}

impl Oracle {
    /// Spawn the oracle against `port` and return once it has joined `group` and is waiting.
    fn spawn(port: u16, group: &str, size: usize, timeout_secs: u64) -> Self {
        let output = tempfile::tempfile().expect("a file for the oracle's output");
        let child = Command::new(view_size_oracle())
            .arg("--mode")
            .arg("client")
            .arg("-e")
            .arg(format!("tcp/127.0.0.1:{port}"))
            .arg("--no-multicast-scouting")
            .arg("--group")
            .arg(group)
            .arg("--size")
            .arg(size.to_string())
            .arg("--timeout")
            .arg(timeout_secs.to_string())
            .arg("--id")
            .arg(ORACLE_MEMBER)
            .env("RUST_LOG", "error")
            .stdout(Stdio::from(
                output.try_clone().expect("dup the oracle's output"),
            ))
            .stderr(Stdio::from(
                output.try_clone().expect("dup the oracle's output"),
            ))
            .spawn()
            .expect("z_view_size spawns");
        let mut oracle = Oracle { child, output };
        // The example prints this once `Group::join` has returned: its own announcement has gone
        // out, but its event subscriber is declared by a task the join only spawned
        // (`zenoh-ext/src/group.rs` @ `async fn net_event_handler(z: Arc<Session>, state: Arc<GroupState>) {`),
        // which is why a leg that needs the oracle to hear an announcement waits a little more.
        if let Err(held) = wait_for_substring(&mut oracle.child, &mut oracle.output, "waiting for")
        {
            panic!("z_view_size never said it joined and was waiting\n--- z_view_size ---\n{held}");
        }
        oracle
    }

    /// Wait for the oracle to exit and return everything it printed.
    fn verdict(mut self, timeout_secs: u64) -> String {
        let deadline = Instant::now() + Duration::from_secs(timeout_secs) + EXIT_MARGIN;
        loop {
            if self.child.try_wait().expect("poll z_view_size").is_some() {
                return contents(&mut self.output);
            }
            if Instant::now() >= deadline {
                panic!(
                    "z_view_size did not exit within its timeout and margin\n--- z_view_size ---\n{}",
                    contents(&mut self.output)
                );
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Oracle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Open a session with `entries` inserted as json5 values.
unsafe fn open(entries: &[(&str, String)]) -> z_owned_session_t {
    let mut cfg: z_owned_config_t = std::mem::zeroed();
    assert_eq!(z_config_default(&mut cfg), Z_OK);
    for (key, value) in entries {
        let k = CString::new(*key).unwrap();
        let v = CString::new(value.as_str()).unwrap();
        assert_eq!(
            zc_config_insert_json5(z_config_loan_mut(&mut cfg), k.as_ptr(), v.as_ptr()),
            Z_OK
        );
    }
    let mut session: z_owned_session_t = std::mem::zeroed();
    let rc = z_open(
        &mut session,
        (&mut cfg as *mut z_owned_config_t).cast::<z_moved_config_t>(),
        std::ptr::null(),
    );
    assert_eq!(rc, Z_OK, "a session opens on {entries:?}");
    session
}

unsafe fn close_session(mut session: z_owned_session_t) {
    let _ = z_close(z_session_loan_mut(&mut session), std::ptr::null_mut());
    z_session_drop((&mut session as *mut z_owned_session_t).cast::<z_moved_session_t>());
}

fn endpoints(port: u16) -> String {
    format!("[\"tcp/127.0.0.1:{port}\"]")
}

/// A node listening on `port` that keeps a south of clients apart.
unsafe fn node(port: u16) -> z_owned_session_t {
    open(&[
        ("mode", String::from("\"peer\"")),
        ("scouting/multicast/enabled", String::from("false")),
        ("listen/endpoints", endpoints(port)),
        (
            "gateway",
            String::from(r#"{ south: [ { filters: [ { modes: ["client"] } ] } ] }"#),
        ),
    ])
}

/// A wz client that dials `port`.
unsafe fn client(port: u16) -> z_owned_session_t {
    open(&[
        ("mode", String::from("\"client\"")),
        ("scouting/multicast/enabled", String::from("false")),
        ("connect/endpoints", endpoints(port)),
    ])
}

/// A view of `text`. A view points at the text it was made from, so the text is leaked: it must
/// outlive the view, which a leg holds to its end.
unsafe fn view(text: &str) -> z_view_keyexpr_t {
    let text: &'static CString = Box::leak(Box::new(CString::new(text).unwrap()));
    let mut view: z_view_keyexpr_t = std::mem::zeroed();
    assert_eq!(z_view_keyexpr_from_str(&mut view, text.as_ptr()), Z_OK);
    view
}

/// Join `group` as member `id` of `session`, with `lease_ms` and upstream's refresh ratio.
unsafe fn join(
    session: &z_owned_session_t,
    group: &str,
    id: &str,
    lease_ms: u64,
) -> wz_capi_c_owned_group_t {
    let id = view(id);
    let mut options: wz_capi_c_member_options_t = std::mem::zeroed();
    wz_capi_c_member_options_default(&mut options);
    options.lease_ms = lease_ms;
    let mut member: wz_capi_c_owned_member_t = std::mem::zeroed();
    assert_eq!(
        wz_capi_c_member_new(&mut member, z_view_keyexpr_loan(&id), &mut options),
        Z_OK
    );
    let group = view(group);
    let mut joined: wz_capi_c_owned_group_t = std::mem::zeroed();
    assert_eq!(
        wz_capi_c_group_join(
            &mut joined,
            z_session_loan(session),
            z_view_keyexpr_loan(&group),
            (&mut member as *mut wz_capi_c_owned_member_t).cast::<wz_capi_c_moved_member_t>(),
        ),
        Z_OK
    );
    joined
}

unsafe fn leave(mut group: wz_capi_c_owned_group_t) {
    wz_capi_c_group_drop(
        (&mut group as *mut wz_capi_c_owned_group_t).cast::<wz_capi_c_moved_group_t>(),
    );
}

unsafe fn view_text(view: &z_view_string_t) -> String {
    let loaned = z_view_string_loan(view);
    let bytes =
        std::slice::from_raw_parts(z_string_data(loaned).cast::<u8>(), z_string_len(loaned));
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// The ids the group's view reports, in the order it reports them.
unsafe fn view_ids(group: &wz_capi_c_owned_group_t) -> Vec<String> {
    unsafe extern "C" fn push(member: *const wz_capi_c_loaned_member_t, ctx: *mut c_void) {
        let mut id: z_view_string_t = std::mem::zeroed();
        assert_eq!(wz_capi_c_member_id(member, &mut id), Z_OK);
        (*(ctx as *mut Vec<String>)).push(view_text(&id));
    }
    let mut ids: Vec<String> = Vec::new();
    let mut closure: wz_capi_c_owned_closure_member_t = std::mem::zeroed();
    wz_capi_c_closure_member(
        &mut closure,
        Some(push),
        None,
        (&mut ids as *mut Vec<String>).cast::<c_void>(),
    );
    assert_eq!(
        wz_capi_c_group_view(
            wz_capi_c_group_loan(group),
            (&mut closure as *mut wz_capi_c_owned_closure_member_t)
                .cast::<wz_capi_c_moved_closure_member_t>(),
        ),
        Z_OK
    );
    ids
}

/// The oracle reached a view of `size` and named `id` in it.
fn established_with(verdict: &str, size: usize, id: &str) -> bool {
    verdict.contains(&format!("Established view size of {size}"))
        && verdict.lines().any(|line| line.trim() == format!("- {id}"))
}

/// Leg 1: a node that joined first is found by upstream's group through its keep-alive and the
/// record its member queryable serves; a node in another group is not.
#[test]
#[ignore = "binary-dep e2e (zenoh-ext z_view_size dials a node); Layer Z runs via --ignored"]
fn a_zenoh_ext_member_finds_a_node_that_joined_first_by_its_beacon_and_its_record() {
    // SAFETY: fresh sessions closed below.
    unsafe {
        let port = free_port();
        let elsewhere = node(port);
        let group = join(&elsewhere, OTHER_GROUP, NODE_MEMBER, BEACON_LEASE_MS);
        let control = Oracle::spawn(port, GROUP, 2, VIEW_TIMEOUT_SECS).verdict(VIEW_TIMEOUT_SECS);
        leave(group);
        close_session(elsewhere);
        assert!(
            control.contains("Failed to establish view size of 2"),
            "the oracle reached a view of 2 with the node in another group, so a view of 2 below \
             would not be the node's membership\n--- z_view_size ---\n{control}"
        );

        let port = free_port();
        let node = node(port);
        let group = join(&node, GROUP, NODE_MEMBER, BEACON_LEASE_MS);
        let verdict = Oracle::spawn(port, GROUP, 2, VIEW_TIMEOUT_SECS).verdict(VIEW_TIMEOUT_SECS);
        leave(group);
        close_session(node);
        assert!(
            established_with(&verdict, 2, NODE_MEMBER),
            "upstream's group never found the node that joined first: its keep-alive was not read \
             or its member queryable did not answer the query it provoked\n--- z_view_size ---\n\
             {verdict}"
        );
    }
}

/// Leg 2: a node that joins after upstream's group is heard by its announcement alone.
#[test]
#[ignore = "binary-dep e2e (zenoh-ext z_view_size dials a node); Layer Z runs via --ignored"]
fn a_zenoh_ext_member_that_joined_first_hears_the_announcement_of_a_node() {
    // SAFETY: fresh session closed below.
    unsafe {
        let port = free_port();
        let node = node(port);
        let oracle = Oracle::spawn(port, GROUP, 2, VIEW_TIMEOUT_SECS);
        // The oracle declares its event subscriber in a task its join spawned, after it said it was
        // waiting; the node announces itself once.
        std::thread::sleep(Duration::from_secs(1));
        let group = join(&node, GROUP, NODE_MEMBER, SILENT_LEASE_MS);
        let verdict = oracle.verdict(VIEW_TIMEOUT_SECS);
        leave(group);
        close_session(node);
        assert!(
            established_with(&verdict, 2, NODE_MEMBER),
            "upstream's group was waiting when the node joined and the node's first keep-alive is \
             45 s away, so the node's announcement was the only way in, and it was not read\n\
             --- z_view_size ---\n{verdict}"
        );
    }
}

/// Leg 3: a node folds a member of upstream's group into its view, and drops it on the lease that
/// member stated once it is gone.
#[test]
#[ignore = "binary-dep e2e (zenoh-ext z_view_size dials a node); Layer Z runs via --ignored"]
fn a_node_finds_a_zenoh_ext_member_and_drops_it_on_the_lease_it_stated() {
    // SAFETY: fresh session closed below.
    unsafe {
        let port = free_port();
        let node = node(port);
        let group = join(&node, GROUP, NODE_MEMBER, SILENT_LEASE_MS);
        // A size of three cannot be met by two members, so the oracle exits on its timeout.
        let oracle = Oracle::spawn(port, GROUP, 3, OBSERVED_ORACLE_TIMEOUT_SECS);
        let found = wz_capi_c_group_wait_for_view_size(
            wz_capi_c_group_loan(&group),
            2,
            VIEW_BUDGET.as_millis() as u64,
        );
        let found_ids = view_ids(&group);
        let verdict = oracle.verdict(OBSERVED_ORACLE_TIMEOUT_SECS);
        let gone_at = Instant::now();
        let mut dropped = false;
        while gone_at.elapsed() < EVICTION_DEADLINE {
            if wz_capi_c_group_size(wz_capi_c_group_loan(&group)) == 1 {
                dropped = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let left_ids = view_ids(&group);
        leave(group);
        close_session(node);
        assert!(
            found,
            "the node never folded upstream's member into its view: the member's announcement or \
             its record was not read\n--- z_view_size ---\n{verdict}"
        );
        assert_eq!(found_ids, [NODE_MEMBER, ORACLE_MEMBER]);
        assert!(
            dropped,
            "the node still held upstream's member {EVICTION_DEADLINE:?} after it exited, so the \
             eviction was not timed on the 3 s lease the member stated (view {left_ids:?})"
        );
        assert_eq!(left_ids, [NODE_MEMBER]);
    }
}

/// Leg 4: a wz client and upstream's group, two clients of one node that share no link, meet in a
/// group through the node; with the wz client on another node they do not.
#[test]
#[ignore = "binary-dep e2e (zenoh-ext z_view_size dials a node); Layer Z runs via --ignored"]
fn a_wz_client_and_a_zenoh_ext_member_meet_in_a_group_through_a_node() {
    // SAFETY: fresh sessions closed below.
    unsafe {
        let (port, apart_port) = (free_port(), free_port());
        let hub = node(port);
        let apart = node(apart_port);
        let wz = client(apart_port);
        let group = join(&wz, GROUP, CLIENT_MEMBER, BEACON_LEASE_MS);
        let control = Oracle::spawn(port, GROUP, 2, VIEW_TIMEOUT_SECS).verdict(VIEW_TIMEOUT_SECS);
        leave(group);
        close_session(wz);
        close_session(apart);
        assert!(
            control.contains("Failed to establish view size of 2"),
            "the oracle met a wz client that dials another node, so the harness joins the two by \
             some other path and a meeting below proves nothing\n--- z_view_size ---\n{control}"
        );

        let wz = client(port);
        let group = join(&wz, GROUP, CLIENT_MEMBER, BEACON_LEASE_MS);
        let oracle = Oracle::spawn(port, GROUP, 2, VIEW_TIMEOUT_SECS);
        let wz_sees = wz_capi_c_group_wait_for_view_size(
            wz_capi_c_group_loan(&group),
            2,
            VIEW_BUDGET.as_millis() as u64,
        );
        let wz_ids = view_ids(&group);
        let verdict = oracle.verdict(VIEW_TIMEOUT_SECS);
        leave(group);
        close_session(wz);
        close_session(hub);
        assert!(
            established_with(&verdict, 2, CLIENT_MEMBER),
            "upstream's group never found the wz client across the node: the client's keep-alive \
             or the query for its record did not cross\n--- z_view_size ---\n{verdict}"
        );
        assert!(
            wz_sees,
            "the wz client never heard upstream's member across the node\n--- z_view_size ---\n\
             {verdict}"
        );
        assert_eq!(wz_ids, [ORACLE_MEMBER, CLIENT_MEMBER]);
    }
}
