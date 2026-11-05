// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A node built from its declaration that takes ORDERS (decision D12 of
//! `docs/session-lifecycle-intent.md`): the lifecycle verbs it binds in band are decided for the zid
//! the key of the link a query arrived on proved, by the lists of commanders its declaration names,
//! and against stock zenoh, which shares no code with wz.
//!
//! The node is `slot-commander` (`deploy/nodes/slot-commander.toml`): a fixed-memory process with
//! no allocator that dials a router over `tls/127.0.0.1:17476`, listens on `tls/127.0.0.1:17477`,
//! grants `status` to one zid and `close` to another. A zid is named by a key and no key is
//! committed, so the test makes the keys when it runs, writes the declaration with each commander's
//! zid replaced by the zid of the key it made for that role, and builds the node from that file the
//! way a consumer builds one (`wz_package.py --node-file`). The file it runs is therefore the
//! artifact whose manifest was verified, for exactly the zids it is asked by.
//!
//! The askers are upstream's own `z_get` and `zenohd`. Three legs:
//!
//! - a node whose key names the zid granted `status` opens a session to the listener with that key
//!   and asks: the status of a peer is answered, and a `close` is refused by name, so the grant is
//!   per verb;
//! - a node whose key names no granted zid asks the same over the same listener: the status is
//!   refused, so the answer above was the grant and not the channel;
//! - the router the node dials holds the key of the zid granted `close`, and a client of that router
//!   CLAIMS the zid granted `status`: its `status` is refused and its `close` is decided (the peer is
//!   not found), so a query that came through a router is the router's, one hop, whatever the asker
//!   claims.
//!
//! The locators are fixed in the node, so the legs run one at a time (`--test-threads=1`).
//!
//! Requires python3, cargo (the node is built when the first leg runs) and the reference zenohd
//! and its examples (`scripts/build-zenohd.sh`). Runs on the `--ignored` lane; the file's `zenohd`
//! token keeps Layer E's sweep off it.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::Duration;

use wz_integration_tests::bounded::BoundedOutput as _;
use wz_integration_tests::common::{
    graceful_terminate, read_captured, wait_for_substring, zenoh_core_example_binary,
    zenohd_binary, ChildGuard,
};
use wz_runtime_tokio_test_support::{free_port, key_named_identity, KeyNamedIdentity};
use wz_session_core::credential_identity::zid_from_spki_der;

// The node says it listens once its port is bound, and says who it is when it is built.
// barrier-producer: deploy/host-slot-node/src/bin/declared_node.rs @ "HOST-WZ-LISTEN {}" for "HOST-WZ-LISTEN tls/127.0.0.1:17477"

/// The declaration the node is built from, with the zids the test replaces.
const DECLARATION: &str = "deploy/nodes/slot-commander.toml";
/// The zid the declaration grants `status`, which the test replaces with the zid of the key of a
/// node that opens a session to the listener.
const STATUS_ZID: &str = "zid = \"a1\"";
/// The zid the declaration grants `close`, which the test replaces with the zid of the router's key.
const CLOSE_ZID: &str = "zid = \"b2\"";
/// The router the node dials, and the port it listens on, as its declaration states them.
const ROUTER_LOCATOR: &str = "tls/127.0.0.1:17476";
const LISTENER: &str = "tls/127.0.0.1:17477";
/// What the node prints once its port is bound.
const LISTENING: &str = "HOST-WZ-LISTEN tls/127.0.0.1:17477";
/// The line the node says who it is on.
const READY: &str = "HOST-WZ-CLIENT READY ";
/// What the node prints when a session is up and the key of its link named the zid it claimed.
const VERIFIED: &str = "slot-commander: session established, peer verified";
/// How long the node may take to start, and to establish with a router that comes up late.
const BUDGET: Duration = Duration::from_secs(30);
/// How long a query may wait for its replies.
const QUERY_TIMEOUT_MS: &str = "5000";

/// What a lifecycle verb is refused with when the commander is not on the verb's list
/// (`wz_session_core::lifecycle_wire::RefusedReason`).
const STATUS_REFUSED: &str =
    "this node does not permit reading the status of the session with that peer";
const CLOSE_REFUSED: &str = "this node does not permit closing the session with that peer";

/// A zenoh id as zenoh's configuration spells one: lowercase hex of the id's bytes read as a
/// little-endian integer (`uhlc` 0.8.2 `src/id.rs` @ `write!(f, "{:x}", u128::from_le_bytes(self.0))`).
fn config_id(zid: &[u8; 16]) -> String {
    format!("{:x}", u128::from_le_bytes(*zid))
}

/// The key of one party and the zid it names.
struct Party {
    key: KeyNamedIdentity,
    zid: String,
}

impl Party {
    fn new() -> Self {
        let key = key_named_identity();
        let zid = config_id(&zid_from_spki_der(&key.spki_der));
        Self { key, zid }
    }
}

/// The node, built once for the keys it is asked by.
struct Built {
    /// The packaged node.
    node: PathBuf,
    /// Granted `status`: a node that opens a session to the listener.
    granted: Party,
    /// Granted nothing.
    stranger: Party,
    /// Granted `close`: the router the node dials.
    router: Party,
    /// Where the declaration, the package and the keys are, removed when the process ends.
    _dir: tempfile::TempDir,
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root")
}

/// Make the keys, write the declaration for their zids and build the node from it.
fn built() -> &'static Built {
    static BUILT: OnceLock<Built> = OnceLock::new();
    BUILT.get_or_init(|| {
        let root = repo_root();
        let (granted, stranger, router) = (Party::new(), Party::new(), Party::new());
        let dir = tempfile::tempdir().expect("a directory for the node");
        let text = std::fs::read_to_string(root.join(DECLARATION)).expect("read the declaration");
        assert_eq!(
            text.matches(STATUS_ZID).count(),
            1,
            "{DECLARATION} grants `status` once"
        );
        assert_eq!(
            text.matches(CLOSE_ZID).count(),
            1,
            "{DECLARATION} grants `close` once"
        );
        let text = text
            .replace(STATUS_ZID, &format!("zid = \"{}\"", granted.zid))
            .replace(CLOSE_ZID, &format!("zid = \"{}\"", router.zid));
        let file = dir.path().join("slot-commander.toml");
        std::fs::write(&file, text).expect("write the declaration");
        let out = dir.path().join("package");
        let built = Command::new("python3")
            .arg(root.join("scripts/lib/wz_package.py"))
            .args([
                "--platform",
                "linux-x86_64-glibc",
                "--artifact",
                "declared-node",
            ])
            .arg("--node-file")
            .arg(&file)
            .arg("--out")
            .arg(&out)
            .current_dir(&root)
            .output_bounded()
            .expect("run wz_package.py");
        assert!(
            built.status.success(),
            "the node did not build from its declaration\n{}{}",
            String::from_utf8_lossy(&built.stdout),
            String::from_utf8_lossy(&built.stderr)
        );
        let node = out.join("bin/declared-node");
        assert!(node.is_file(), "no node at {}", node.display());
        Built {
            node,
            granted,
            stranger,
            router,
            _dir: dir,
        }
    })
}

/// The PEM block the node printed, once it has printed all of it.
fn printed_certificate(captured: &str) -> Option<String> {
    let begin = captured.find("-----BEGIN CERTIFICATE-----")?;
    let end = captured[begin..].find("-----END CERTIFICATE-----")? + begin;
    let end = end + "-----END CERTIFICATE-----".len();
    Some(format!("{}\n", &captured[begin..end]))
}

/// The running node: its output, its zid and the certificate it presents, written where a peer's
/// configuration names it.
struct Node {
    child: ChildGuard,
    out: File,
    zid: String,
    certificate: PathBuf,
    _files: tempfile::TempDir,
}

impl Node {
    /// Start the node and wait until it listens.
    fn start() -> Self {
        let out = tempfile::tempfile().expect("a capture for the node");
        let child = ChildGuard::wrap(
            "slot-commander (declared node)",
            Command::new(&built().node)
                .stdout(Stdio::from(out.try_clone().expect("dup capture")))
                .stderr(Stdio::from(out.try_clone().expect("dup capture")))
                .spawn()
                .expect("spawn the node"),
        );
        let said = wait_for_substring(&mut out.try_clone().expect("dup"), LISTENING, BUDGET)
            .unwrap_or_else(|why| panic!("the node never said it listens\n{why}"));
        let zid = said
            .lines()
            .find_map(|line| line.split(READY).nth(1))
            .and_then(|rest| rest.split_whitespace().next())
            .unwrap_or_else(|| panic!("the node never said who it is\n{said}"))
            .to_owned();
        let files = tempfile::tempdir().expect("a directory for the node's certificate");
        let certificate = files.path().join("node.pem");
        std::fs::write(
            &certificate,
            printed_certificate(&said).expect("the node printed its certificate"),
        )
        .expect("write the node's certificate");
        Self {
            child,
            out,
            zid,
            certificate,
            _files: files,
        }
    }

    /// The key the node answers `verb` about `peer` under.
    fn verb_key(&self, verb: &str, peer: &str) -> String {
        format!("@/{}/client/session/{verb}/{peer}", self.zid)
    }

    fn output(&mut self) -> String {
        read_captured(&mut self.out)
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        graceful_terminate(self.child.child_mut(), Duration::from_secs(5));
    }
}

/// Write `party`'s key and certificate into `dir` and hand back their paths.
fn key_files(dir: &Path, party: &Party) -> (PathBuf, PathBuf) {
    let (cert, key) = (dir.join("party.pem"), dir.join("party.key"));
    std::fs::write(&cert, &party.key.cert_pem).expect("write the certificate");
    std::fs::write(&key, &party.key.key_pem).expect("write the key");
    (cert, key)
}

/// Ask `key` with a stock `z_get` configured by `config` (JSON5), and hand back the payloads of
/// the replies and everything it printed.
fn ask(config: &str, key: &str) -> (Vec<String>, String) {
    let files = tempfile::tempdir().expect("a directory for the asker's configuration");
    let path = files.path().join("z_get.json5");
    std::fs::write(&path, config).expect("write the asker's configuration");
    let output = Command::new(zenoh_core_example_binary("z_get"))
        .arg("-c")
        .arg(&path)
        .args(["-s", key, "-o", QUERY_TIMEOUT_MS])
        .output_bounded()
        .expect("run z_get");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let replies = text
        .lines()
        .filter_map(|line| line.strip_prefix(">> Received ('")?.strip_suffix("')"))
        .filter_map(|body| body.split_once("': '"))
        .map(|(_, value)| value.to_owned())
        .collect();
    (replies, text)
}

/// The configuration of a client that opens a mutual-TLS session to the node's listener with
/// `party`'s key, claiming the zid that key names.
fn direct_config(node: &Node, dir: &Path, party: &Party) -> String {
    let (cert, key) = key_files(dir, party);
    format!(
        "{{ id: {id:?}, mode: \"client\", connect: {{ endpoints: [{listener:?}] }}, \
         scouting: {{ multicast: {{ enabled: false }} }}, \
         transport: {{ link: {{ tls: {{ root_ca_certificate: {root:?}, enable_mtls: true, \
         connect_certificate: {cert:?}, connect_private_key: {key:?}, \
         verify_name_on_connect: false }} }} }} }}",
        id = party.zid,
        listener = LISTENER,
        root = node.certificate.display().to_string(),
        cert = cert.display().to_string(),
        key = key.display().to_string(),
    )
}

/// The one reply `ask` got, or a panic that says what came instead.
fn only_reply(asked: (Vec<String>, String), what: &str, node: &mut Node) -> String {
    let (replies, text) = asked;
    match replies.as_slice() {
        [one] => one.clone(),
        _ => panic!(
            "{what}: expected one reply, got {replies:?}\n--- z_get ---\n{text}\n--- node ---\n{}",
            node.output()
        ),
    }
}

// wz-proves: none -- the declared node of the fixed-memory profile has no catalog atom: its in-band verbs and its secure listener are the slot profile's own, and the catalog's lifecycle atoms name the heap runtime's
#[test]
#[ignore = "binary-dep e2e (the node is built from deploy/nodes/slot-commander.toml with keys made here, + zenohd's examples); runs via --ignored"]
fn a_zenoh_zget_granted_status_reads_it_on_its_own_session_and_is_refused_close() {
    let built = built();
    let mut node = Node::start();
    let dir = tempfile::tempdir().expect("a directory for the asker");
    let config = direct_config(&node, dir.path(), &built.granted);

    let status = only_reply(
        ask(&config, &node.verb_key("status", &built.stranger.zid)),
        "the granted status",
        &mut node,
    );
    assert!(
        status.starts_with("{\"verdict\":\"status\""),
        "the zid granted `status` asked it on its own session and was not answered: {status}\n{}",
        node.output()
    );
    assert!(
        node.output().contains(VERIFIED),
        "the node answered, but never read the asker's key as naming the zid it claimed\n{}",
        node.output()
    );
    let close = only_reply(
        ask(&config, &node.verb_key("close", &built.stranger.zid)),
        "the close it was not granted",
        &mut node,
    );
    assert!(
        close.contains(CLOSE_REFUSED),
        "the zid granted only `status` asked `close` and was not refused by name: {close}"
    );
}

// wz-proves: none -- the control of the leg above, for the same reason: no catalog atom names the fixed-memory profile's in-band verbs
#[test]
#[ignore = "binary-dep e2e (the node is built from deploy/nodes/slot-commander.toml with keys made here, + zenohd's examples); runs via --ignored"]
fn a_zenoh_zget_granted_nothing_is_refused_status_on_its_own_session() {
    let built = built();
    let mut node = Node::start();
    let dir = tempfile::tempdir().expect("a directory for the asker");
    let config = direct_config(&node, dir.path(), &built.stranger);

    let status = only_reply(
        ask(&config, &node.verb_key("status", &built.granted.zid)),
        "the status of a zid granted nothing",
        &mut node,
    );
    assert!(
        status.contains(STATUS_REFUSED),
        "a zid on no list asked `status` over the same listener and was not refused: {status}"
    );
}

// wz-proves: none -- the same node, for the same reason: what a router forwards is decided for the router's key, which no catalog atom names
#[test]
#[ignore = "binary-dep e2e (the node is built from deploy/nodes/slot-commander.toml with keys made here, + zenohd); runs via --ignored"]
fn through_zenohd_the_commander_is_the_router_and_not_the_client_that_asked() {
    let built = built();
    let mut node = Node::start();
    let files = tempfile::tempdir().expect("a directory for the router");
    let (cert, key) = key_files(files.path(), &built.router);
    let client_port = free_port();
    let config = files.path().join("zenohd.json5");
    std::fs::write(
        &config,
        format!(
            "{{ id: {id:?}, mode: \"router\", transport: {{ link: {{ tls: {{ \
             listen_certificate: {cert:?}, listen_private_key: {key:?}, \
             root_ca_certificate: {root:?}, enable_mtls: true }} }} }} }}",
            id = built.router.zid,
            cert = cert.display().to_string(),
            key = key.display().to_string(),
            root = node.certificate.display().to_string(),
        ),
    )
    .expect("write the router's configuration");
    let mut router_out = tempfile::tempfile().expect("a capture for the router");
    let mut router = ChildGuard::wrap(
        "zenohd (reference router, mutual tls)",
        Command::new(zenohd_binary())
            .arg("--config")
            .arg(&config)
            .args(["-l", ROUTER_LOCATOR, "-l"])
            .arg(format!("tcp/127.0.0.1:{client_port}"))
            .arg("--no-multicast-scouting")
            .args(["--rest-http-port", "none"])
            .stdout(Stdio::from(router_out.try_clone().expect("dup capture")))
            .stderr(Stdio::from(router_out.try_clone().expect("dup capture")))
            .spawn()
            .expect("spawn zenohd"),
    );
    if let Err(why) = wait_for_substring(&mut node.out, VERIFIED, BUDGET) {
        panic!(
            "the node never held a session with the router it pins\n--- node ---\n{why}\n\
             --- zenohd ---\n{}",
            read_captured(&mut router_out)
        );
    }

    // A client of the router that claims the zid granted `status`: a claim the router's link
    // cannot prove to the node.
    let claimed = format!(
        "{{ id: {id:?}, mode: \"client\", connect: {{ endpoints: [\"tcp/127.0.0.1:{client_port}\"] }}, \
         scouting: {{ multicast: {{ enabled: false }} }} }}",
        id = built.granted.zid,
    );
    let status = only_reply(
        ask(&claimed, &node.verb_key("status", &built.stranger.zid)),
        "the status asked through the router",
        &mut node,
    );
    assert!(
        status.contains(STATUS_REFUSED),
        "a status asked through the router by a client claiming the granted zid was not refused: \
         the node took a claim for a proof: {status}"
    );
    let close = only_reply(
        ask(&claimed, &node.verb_key("close", &built.stranger.zid)),
        "the close asked through the router",
        &mut node,
    );
    assert_eq!(
        close, "{\"verdict\":\"not_found\"}",
        "the router's key is granted `close`, so a close it forwards is decided (the node holds no \
         such peer); anything else is not the router being the commander"
    );
    graceful_terminate(router.child_mut(), Duration::from_secs(5));
}
