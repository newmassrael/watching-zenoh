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
//! The askers are upstream's own `z_get` and `zenohd`, and wz's C library as a consumer links it.
//! The legs:
//!
//! - a node whose key names the zid granted `status` opens a session to the listener with that key
//!   and asks: the status of a peer is answered, and a `close` is refused by name, so the grant is
//!   per verb;
//! - a node whose key names no granted zid asks the same over the same listener: the status is
//!   refused, so the answer above was the grant and not the channel;
//! - the WITNESS of a consumer's program: the zid granted `status` is the zid of a key a C client
//!   made on its first start with the library's door (`wz_capi_c_identity_make`), so every leg
//!   that presents that key presents one the library made. The client
//!   (`crates/wz-capi-c/tests/c_lifecycle_witness.c`, linked against the library built with
//!   `lifecycle-doors` and `identity-make`) opens its session from the canonical configuration
//!   (`deploy/clients/commander.json5`, its words filled), makes each verb's key from its words
//!   and reads each reply with the library: its `status` is answered and its `close` refused by
//!   name, and a client whose key is on no list is refused `status`;
//! - the router the node dials holds the key of the zid granted `close`, and a client of that router
//!   CLAIMS the zid granted `status`: its `status` is refused and its `close` is decided (the peer is
//!   not found), so a query that came through a router is the router's, one hop, whatever the asker
//!   claims;
//! - two declared nodes, each PROVISIONED with an identity (`[identity]`), and neither run before
//!   their zids are known: each identity is made as a device is registered, by the node's own
//!   executable (`--make-identity`, which keeps the key its owner's alone, prints the certificate,
//!   makes nothing a second time and nothing when half an identity is there), `wz_node.py --zid-of`
//!   prints each certificate's zid, the target (`slot-commander`) grants `status` to the subject's,
//!   and the subject
//!   (`deploy/nodes/slot-subject.toml`) holds the target by the target's and asks it over a session
//!   it opens to the target's listener: the status is answered and the close is refused, and each
//!   node proves the zid the tool printed.
//!
//! The locators are fixed in the node, so the legs run one at a time (`--test-threads=1`).
//!
//! Requires python3, cargo (the node is built when the first leg runs) and the reference zenohd
//! and its examples (`scripts/build-zenohd.sh`), and for the witness a C compiler, zenoh-c's
//! headers (`WZ_ZENOH_C_PREFIX`) and the library built with its doors, named by
//! `WZ_CAPI_C_LIFECYCLE_LIB`. Runs on the `--ignored` lane; the file's `zenohd`
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
// The node says who it is in parts (`Str("HOST-WZ-CLIENT READY ")` and its zid), which the
// matcher does not join.
// barrier-producer: deploy/host-slot-node/src/bin/declared_node.rs @ "HOST-WZ-CLIENT READY " for "HOST-WZ-CLIENT READY "

/// The declaration the node is built from, with the zids the test replaces.
const DECLARATION: &str = "deploy/nodes/slot-commander.toml";
/// The configuration a client that commands such a node opens its session from, with the words a
/// client fills in angle brackets.
const CANONICAL_CONFIG: &str = "deploy/clients/commander.json5";
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
    cert_pem: String,
    key_pem: String,
    zid: String,
    /// The files a client made its identity into with the library's door, which it presents as
    /// they are; `None` for a key the test made.
    made: Option<(PathBuf, PathBuf)>,
}

impl Party {
    fn new() -> Self {
        let key: KeyNamedIdentity = key_named_identity();
        let zid = config_id(&zid_from_spki_der(&key.spki_der));
        Self {
            cert_pem: key.cert_pem,
            key_pem: key.key_pem,
            zid,
            made: None,
        }
    }

    /// The identity a client of the C library makes on its first start
    /// (`wz_capi_c_identity_make`, through the witness), in `dir`. The zid is the one the door
    /// printed, held to the one the consumer's tool prints for the same certificate.
    fn made_by_the_library(dir: &Path) -> Self {
        let (cert, key) = (dir.join("client.pem"), dir.join("client.key"));
        let made = witness()
            .run(&["make", path_text(&cert), path_text(&key)])
            .unwrap_or_else(|why| panic!("the library made no identity: {why}"));
        let zid = made
            .lines()
            .find_map(|line| line.strip_prefix("zid "))
            .unwrap_or_else(|| panic!("the witness printed no zid: {made}"))
            .to_owned();
        assert_eq!(
            zid,
            zid_by_the_tool(&cert),
            "the zid the library wrote is not the one a peer computes from its certificate"
        );
        Self {
            cert_pem: std::fs::read_to_string(&cert).expect("read the made certificate"),
            key_pem: std::fs::read_to_string(&key).expect("read the made key"),
            zid,
            made: Some((cert, key)),
        }
    }
}

/// A path as the witness and a configuration take it.
fn path_text(path: &Path) -> &str {
    path.to_str().expect("a temporary path is UTF-8")
}

/// The witness: `crates/wz-capi-c/tests/c_lifecycle_witness.c`, compiled against `wz_capi_c.h`
/// and linked against the library built with the doors it calls, as a consumer's program is.
struct Witness {
    binary: PathBuf,
    libdir: PathBuf,
    _dir: tempfile::TempDir,
}

/// The library the witness links: `libwz_capi_c.so` built with `lifecycle-doors` and
/// `identity-make` (both off by default), named by the lane that built it.
const WITNESS_LIBRARY: &str = "WZ_CAPI_C_LIFECYCLE_LIB";

impl Witness {
    /// Run the witness with `args`: what it printed on standard output, or why it failed.
    fn run(&self, args: &[&str]) -> Result<String, String> {
        let output = Command::new(&self.binary)
            .args(args)
            .env("LD_LIBRARY_PATH", &self.libdir)
            .output_bounded()
            .map_err(|e| format!("run the witness: {e}"))?;
        let out = String::from_utf8_lossy(&output.stdout).into_owned();
        if output.status.success() {
            Ok(out)
        } else {
            Err(format!(
                "{} {args:?}\n{out}{}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }
}

/// Compile the witness once.
fn witness() -> &'static Witness {
    static WITNESS: OnceLock<Witness> = OnceLock::new();
    WITNESS.get_or_init(|| {
        let library = PathBuf::from(std::env::var(WITNESS_LIBRARY).unwrap_or_else(|_| {
            panic!(
                "{WITNESS_LIBRARY} names no library: build `cargo build -p wz-capi-c --features \
                 lifecycle-doors,identity-make` and name the libwz_capi_c.so it wrote"
            )
        }));
        assert!(
            library.is_file(),
            "{WITNESS_LIBRARY}: no file at {library:?}"
        );
        let libdir = library
            .parent()
            .expect("the library's directory")
            .to_owned();
        // `wz_capi_c.h` includes zenoh-c's `zenoh.h`: the headers of the pinned zenoh-c, under
        // the prefix the C lanes name (`WZ_ZENOH_C_PREFIX`, default `~/.local`).
        let include = std::env::var("WZ_ZENOH_C_PREFIX")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(std::env::var("HOME").expect("HOME")).join(".local"))
            .join("include");
        assert!(
            include.join("zenoh.h").is_file(),
            "no zenoh.h under {include:?} for wz_capi_c.h to include (WZ_ZENOH_C_PREFIX)"
        );
        let root = repo_root();
        let dir = tempfile::tempdir().expect("a directory for the witness");
        let binary = dir.path().join("c_lifecycle_witness");
        let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
        let compiled = Command::new(cc)
            .args(["-std=c11", "-Wall", "-Wextra", "-Werror"])
            .arg("-I")
            .arg(root.join("crates/wz-capi-c/include"))
            .arg("-I")
            .arg(&include)
            .arg(root.join("crates/wz-capi-c/tests/c_lifecycle_witness.c"))
            .arg("-L")
            .arg(&libdir)
            .args(["-lwz_capi_c", "-o"])
            .arg(&binary)
            .output_bounded()
            .expect("run the C compiler");
        assert!(
            compiled.status.success(),
            "the witness did not compile against wz_capi_c.h\n{}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        Witness {
            binary,
            libdir,
            _dir: dir,
        }
    })
}

/// The node, built once for the keys it is asked by.
struct Built {
    /// The packaged node.
    node: PathBuf,
    /// Granted `status`: a client that made its identity with the C library's door and opens a
    /// session to the listener.
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
        let dir = tempfile::tempdir().expect("a directory for the node");
        let client = dir.path().join("client");
        std::fs::create_dir(&client).expect("a directory for the client's identity");
        let granted = Party::made_by_the_library(&client);
        let (stranger, router) = (Party::new(), Party::new());
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
        let node = package(dir.path(), "slot-commander", &text);
        Built {
            node,
            granted,
            stranger,
            router,
            _dir: dir,
        }
    })
}

/// Write the declaration `text` of the node `id` into `dir` and build the node from it as a
/// consumer does (`wz_package.py --node-file`): the packaged executable.
fn package(dir: &Path, id: &str, text: &str) -> PathBuf {
    let root = repo_root();
    let file = dir.join(format!("{id}.toml"));
    std::fs::write(&file, text).expect("write the declaration");
    let out = dir.join(format!("package-{id}"));
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
        "{id} did not build from its declaration\n{}{}",
        String::from_utf8_lossy(&built.stdout),
        String::from_utf8_lossy(&built.stderr)
    );
    let node = out.join("bin/declared-node");
    assert!(node.is_file(), "no node at {}", node.display());
    node
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
        Self::run(&built().node, "slot-commander (declared node)", LISTENING)
    }

    /// Start the node `binary` and wait until it says `ready`.
    fn run(binary: &Path, what: &str, ready: &str) -> Self {
        let out = tempfile::tempfile().expect("a capture for the node");
        let child = ChildGuard::wrap(
            what,
            Command::new(binary)
                // The node's control channel is its standard input (`control = "pipe"`); these
                // legs send it nothing.
                .stdin(Stdio::null())
                .stdout(Stdio::from(out.try_clone().expect("dup capture")))
                .stderr(Stdio::from(out.try_clone().expect("dup capture")))
                .spawn()
                .expect("spawn the node"),
        );
        let said = wait_for_substring(&mut out.try_clone().expect("dup"), ready, BUDGET)
            .unwrap_or_else(|why| panic!("{what} never said {ready:?}\n{why}"));
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

    /// What the node has printed so far. Not named `output`: `bounded::census` reads the text of
    /// every test file for a bare `.output()` of a child and cannot tell this method from it.
    fn console(&mut self) -> String {
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
    std::fs::write(&cert, &party.cert_pem).expect("write the certificate");
    std::fs::write(&key, &party.key_pem).expect("write the key");
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
            node.console()
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
        node.console()
    );
    assert!(
        node.console().contains(VERIFIED),
        "the node answered, but never read the asker's key as naming the zid it claimed\n{}",
        node.console()
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

/// The canonical configuration of a commanding client (`deploy/clients/commander.json5`), with
/// its words filled for `party` asking `node`, written into `dir`.
fn canonical_config(node: &Node, dir: &Path, party: &Party) -> PathBuf {
    let text = std::fs::read_to_string(repo_root().join(CANONICAL_CONFIG))
        .expect("read the canonical configuration");
    let (cert, key) = match &party.made {
        Some(files) => files.clone(),
        None => {
            let files = key_files(dir, party);
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&files.1, std::fs::Permissions::from_mode(0o600))
                .expect("make the key its owner's alone");
            files
        }
    };
    let words = [
        ("<zid>", party.zid.clone()),
        ("<listener>", LISTENER.to_owned()),
        (
            "<node-certificate>",
            path_text(&node.certificate).to_owned(),
        ),
        ("<certificate>", path_text(&cert).to_owned()),
        ("<private-key>", path_text(&key).to_owned()),
    ];
    let mut filled = text;
    for (word, value) in words {
        assert_eq!(
            filled.matches(&format!("\"{word}\"")).count(),
            1,
            "{CANONICAL_CONFIG} names {word} once, as a value"
        );
        filled = filled.replace(&format!("\"{word}\""), &format!("{value:?}"));
    }
    let path = dir.join("commander.json5");
    std::fs::write(&path, filled).expect("write the filled configuration");
    path
}

/// What the witness read the one reply to `verb` about `about` as (`kind=… verdict=… reason=…`),
/// after holding the key it made to the key the node answers under.
fn witness_answer(config: &Path, verb: &str, about: &str, node: &mut Node) -> String {
    let asked = witness()
        .run(&["ask", path_text(config), verb, &node.zid, about])
        .unwrap_or_else(|why| {
            panic!(
                "the witness could not ask `{verb}`: {why}\n{}",
                node.console()
            )
        });
    let key = asked.lines().find_map(|line| line.strip_prefix("key "));
    assert_eq!(
        key,
        Some(node.verb_key(verb, about).as_str()),
        "the library made another key than the one the node answers `{verb}` under\n{asked}"
    );
    let replies: Vec<&str> = asked
        .lines()
        .filter_map(|line| line.strip_prefix("reply "))
        .collect();
    match replies.as_slice() {
        [one] => (*one).to_owned(),
        _ => panic!(
            "`{verb}`: expected one reply, got {replies:?}\n{asked}\n--- node ---\n{}",
            node.console()
        ),
    }
}

// wz-proves: none -- the client of the leg is the C library and the asked node the fixed-memory profile's, whose in-band verbs no catalog atom names
#[test]
#[ignore = "binary-dep e2e (the node is built from deploy/nodes/slot-commander.toml with keys made here, + the C library built with lifecycle-doors and identity-make); runs via --ignored"]
fn zenohd_lane_a_wz_capi_c_client_with_the_key_it_made_reads_its_grant_and_is_refused_the_rest() {
    let built = built();
    let mut node = Node::start();
    let dir = tempfile::tempdir().expect("a directory for the client's configuration");

    // The client that made its identity with the library's door, granted `status`, opening its
    // session from the canonical configuration: the verdict is the node's, read by the library.
    let config = canonical_config(&node, dir.path(), &built.granted);
    let status = witness_answer(&config, "status", &built.stranger.zid, &mut node);
    assert!(
        status.starts_with("kind=1 verdict=status "),
        "the client granted `status` asked it with its own key and was not answered: {status}\n{}",
        node.console()
    );
    let close = witness_answer(&config, "close", &built.stranger.zid, &mut node);
    assert_eq!(
        close,
        format!("kind=1 verdict=refused reason={CLOSE_REFUSED}"),
        "the client granted only `status` asked `close` and was not refused by name"
    );

    // The control: a client whose key names no granted zid, with the same configuration filled
    // for its key, is refused the same verb.
    let other = tempfile::tempdir().expect("a directory for the other client");
    let config = canonical_config(&node, other.path(), &built.stranger);
    let refused = witness_answer(&config, "status", &built.granted.zid, &mut node);
    assert_eq!(
        refused,
        format!("kind=1 verdict=refused reason={STATUS_REFUSED}"),
        "a client on no list asked `status` with its own key and was not refused by name"
    );
}

/// The lines the agent writes on the node's pipe, each with what its answer must read as: every
/// command the vocabulary states a pipe takes, and lines that are none of them.
fn pipe_lines(peer: &str) -> Vec<(String, &'static str)> {
    let line_bytes = wz_runtime_posix_line_bytes();
    vec![
        // At the bound the line is read, and is no command; one byte past it is not read.
        ("y".repeat(line_bytes), "unknown-command"),
        ("x".repeat(line_bytes + 1), "line-too-long"),
        ("whoami".to_owned(), "the zid"),
        (format!("status {peer}"), "status"),
        (format!("close {peer}"), "not_found"),
        // The node holds no peer by its zid, so it has no room to keep a generation in, and a
        // reset is refused for room before it closes anything; an open is refused the same way.
        (format!("reset {peer} 3"), "refused"),
        (format!("open {peer}"), "refused"),
        ("frobnicate".to_owned(), "unknown-command"),
        ("open".to_owned(), "open-takes-one-peer"),
        (String::new(), "unknown-command"),
        ("whoami".to_owned(), "the zid"),
    ]
}

/// The bytes of a command line the node reads (`LINE_BYTES` of wz-runtime-posix's `control`, which
/// the vocabulary states as `line_bytes`).
fn wz_runtime_posix_line_bytes() -> usize {
    let vocabulary = Command::new("python3")
        .arg(repo_root().join("scripts/lib/wz_node.py"))
        .args(["--vocabulary", "slot"])
        .output_bounded()
        .expect("run wz_node.py --vocabulary");
    assert!(
        vocabulary.status.success(),
        "wz_node.py --vocabulary failed"
    );
    let text = String::from_utf8(vocabulary.stdout).expect("UTF-8");
    let at = text
        .find("\"line_bytes\": ")
        .expect("the vocabulary states line_bytes")
        + 14;
    text[at..]
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .and_then(|n| n.parse().ok())
        .expect("a number")
}

// wz-proves: none -- the declared node of the fixed-memory profile has no catalog atom, and its pipe is the slot profile's own
#[test]
#[ignore = "binary-dep e2e (the node is built from deploy/nodes/slot-commander.toml with keys made here); runs via --ignored"]
fn zenohd_lane_pipe_answers_each_line_once_on_stdout_and_says_everything_else_on_stderr() {
    use std::io::{BufRead, BufReader, Write};
    use wz_session_core::lifecycle_wire::{Answer, ControlError};

    let built = built();
    let err = tempfile::tempfile().expect("a capture for the node's standard error");
    let mut child = ChildGuard::wrap(
        "slot-commander (declared node, on its pipe)",
        Command::new(&built.node)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(err.try_clone().expect("dup capture")))
            .spawn()
            .expect("spawn the node"),
    );
    let mut stdin = child.child_mut().stdin.take().expect("stdin");
    let stdout = child.child_mut().stdout.take().expect("stdout");
    let (lines_tx, lines) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let _ = lines_tx.send(line);
        }
    });
    let said = wait_for_substring(&mut err.try_clone().expect("dup"), LISTENING, BUDGET)
        .unwrap_or_else(|why| panic!("the node never said {LISTENING:?}\n{why}"));
    let zid = said
        .lines()
        .find_map(|line| line.split(READY).nth(1))
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or_else(|| panic!("the node never said who it is\n{said}"))
        .to_owned();

    let sent = pipe_lines(&built.stranger.zid);
    for (line, _) in &sent {
        writeln!(stdin, "{line}").expect("write a line on the pipe");
    }
    stdin.flush().expect("flush the pipe");
    let mut answers = Vec::new();
    for (line, expected) in &sent {
        let answer = lines.recv_timeout(BUDGET).unwrap_or_else(|_| {
            panic!(
                "no answer to {line:?} after {} answers {answers:?}\n{}",
                answers.len(),
                read_captured(&mut err.try_clone().expect("dup"))
            )
        });
        let read = Answer::read(answer.as_bytes()).unwrap_or_else(|| {
            panic!("the answer to {line:?} is no answer a node writes: {answer}")
        });
        let word = match read {
            Answer::Whoami(said) => {
                assert_eq!(said, zid, "`whoami` answered another zid than READY said");
                "the zid"
            }
            Answer::Verdict(verdict) => verdict.verdict,
            Answer::Error(error) => error.words(),
        };
        assert_eq!(word, *expected, "the answer to {line:?}: {answer}");
        answers.push(answer);
    }
    assert!(
        answers
            .iter()
            .any(|a| a.contains(ControlError::LineTooLong.words())),
        "a line past line_bytes was answered once, as such"
    );
    // One answer a line and nothing else: the pipe closed, the node stopped, standard output ends
    // with no line beyond the answers.
    drop(stdin);
    graceful_terminate(child.child_mut(), Duration::from_secs(5));
    reader.join().expect("the reader ends with standard output");
    let rest: Vec<String> = lines.try_iter().collect();
    assert!(
        rest.is_empty(),
        "standard output carried lines that answer no command: {rest:?}"
    );
    let console = read_captured(&mut err.try_clone().expect("dup"));
    assert!(
        console.contains(READY) && console.contains("-----BEGIN CERTIFICATE-----"),
        "the node's own lines and its certificate are on standard error\n{console}"
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

// ---- two declared nodes, each provisioned with an identity, one commanding the other ----

/// The declaration of the commanding node, with the zid of the node it commands to replace.
const SUBJECT_DECLARATION: &str = "deploy/nodes/slot-subject.toml";
/// The zid the subject's declaration names for the node it holds and asks.
const TARGET_ZID: &str = "c3";
/// The files the subject's declaration names for its identity, which the test replaces.
const SUBJECT_CERT: &str = "/etc/wz/slot-subject.crt";
const SUBJECT_KEY: &str = "/etc/wz/slot-subject.key";
/// What the subject says once it holds a session and is ready.
const SUBJECT_READY: &str = "HOST-WZ-CLIENT READY ";
/// The line the subject says each reply it keeps on.
const REPLY: &str = "HOST-WZ-REPLY ";

/// What `--make-identity` answered: its exit status, and what it printed on standard output and on
/// standard error.
fn make_identity_with(node: &Path, cert: &Path, key: &Path) -> (bool, String, String) {
    let made = Command::new(node)
        .arg("--make-identity")
        .arg(cert)
        .arg(key)
        .output_bounded()
        .expect("run the node's --make-identity");
    (
        made.status.success(),
        String::from_utf8_lossy(&made.stdout).into_owned(),
        String::from_utf8_lossy(&made.stderr).into_owned(),
    )
}

/// Make `name`'s identity as a device is registered: the node's own executable makes it in `dir`
/// (`--make-identity`), and the certificate it prints is all that leaves the device. The command is
/// held to what the vocabulary says of it: the key is its owner's alone, the printed certificate is
/// the file's, and a second run makes nothing and prints the same certificate. Hand back the two
/// paths.
fn make_identity(node: &Path, dir: &Path, name: &str) -> (PathBuf, PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let (cert, key) = (
        dir.join(format!("{name}.crt")),
        dir.join(format!("{name}.key")),
    );
    let (made, printed, said) = make_identity_with(node, &cert, &key);
    assert!(made, "{name}: --make-identity failed: {said}");
    let held = std::fs::read_to_string(&cert).expect("the certificate was written");
    assert_eq!(
        printed, held,
        "{name}: what --make-identity printed is not the certificate it wrote"
    );
    assert!(
        printed.starts_with("-----BEGIN CERTIFICATE-----\n")
            && printed.ends_with("-----END CERTIFICATE-----\n"),
        "{name}: standard output holds the certificate and nothing else: {printed:?}"
    );
    let mode = std::fs::metadata(&key)
        .expect("the key was written")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "{name}: the key is its owner's alone");
    let key_held = std::fs::read(&key).expect("read the key");
    let (again, printed_again, said) = make_identity_with(node, &cert, &key);
    assert!(again, "{name}: a second --make-identity failed: {said}");
    assert_eq!(
        printed_again, printed,
        "{name}: registering the device again changed the certificate it prints"
    );
    assert_eq!(
        (
            std::fs::read_to_string(&cert).expect("read the certificate"),
            std::fs::read(&key).expect("read the key")
        ),
        (held, key_held),
        "{name}: a second --make-identity overwrote the identity"
    );
    (cert, key)
}

/// The zid the tool a consumer is given (`wz_node.py --zid-of`) prints for `certificate`.
fn zid_by_the_tool(certificate: &Path) -> String {
    let printed = Command::new("python3")
        .arg(repo_root().join("scripts/lib/wz_node.py"))
        .arg("--zid-of")
        .arg(certificate)
        .output_bounded()
        .expect("run wz_node.py --zid-of");
    assert!(
        printed.status.success(),
        "wz_node.py --zid-of refused {}: {}",
        certificate.display(),
        String::from_utf8_lossy(&printed.stderr)
    );
    String::from_utf8_lossy(&printed.stdout).trim().to_owned()
}

/// The payload a reply the subject kept under a key that holds `tail`, decoded from the hex the
/// subject prints, once one is there.
fn kept_reply(out: &str, tail: &str) -> Option<String> {
    out.lines()
        .filter(|line| line.starts_with(REPLY) && line.contains(tail))
        .filter_map(|line| line.split(" hex=").nth(1))
        .rfind(|hex| !hex.is_empty())
        .map(|hex| {
            let bytes: Vec<u8> = (0..hex.len() / 2)
                .map(|at| u8::from_str_radix(&hex[2 * at..2 * at + 2], 16).expect("hex"))
                .collect();
            String::from_utf8_lossy(&bytes).into_owned()
        })
}

// wz-proves: none -- the declared node of the fixed-memory profile has no catalog atom: a provisioned identity and the verbs it is granted by are the slot profile's own
#[test]
#[ignore = "binary-dep e2e (both nodes are built from their declarations with identities made here); runs via --ignored"]
fn two_provisioned_nodes_command_by_a_zid_known_before_either_runs_with_no_zenohd() {
    let dir = tempfile::tempdir().expect("a directory for the two nodes");
    let stranger = Party::new();
    // Each device makes its identity with the node's executable, as a lab registers it: the key is
    // made where it is used and only the certificate is taken away. Any executable of a node with a
    // secure channel makes it, whatever its declaration, so the one the first legs built does, and
    // the two declarations below can each name the other's zid before either is built.
    let maker = &built().node;
    let (subject_cert, subject_key) = make_identity(maker, dir.path(), "subject");
    let (target_cert, target_key) = make_identity(maker, dir.path(), "target");

    // Half an identity is a fault and not an identity to complete: with the key there and its
    // certificate gone, nothing is made.
    let half = dir.path().join("half");
    std::fs::create_dir(&half).expect("a directory for half an identity");
    let (half_cert, half_key) = make_identity(maker, &half, "half");
    std::fs::remove_file(&half_cert).expect("take the certificate away");
    let (made, _, said) = make_identity_with(maker, &half_cert, &half_key);
    assert!(
        !made && said.contains("nothing is made") && !half_cert.exists(),
        "a key with no certificate beside it was completed: {said}"
    );

    // The zids are known before either node runs, from the tool a consumer is given and from the
    // certificate alone.
    let (subject_zid, target_zid) = (
        zid_by_the_tool(&subject_cert),
        zid_by_the_tool(&target_cert),
    );
    assert_ne!(subject_zid, target_zid, "two devices made two identities");

    // The target grants `status` to the subject's zid, and `close` to a zid no node here holds.
    let root = repo_root();
    let commander = std::fs::read_to_string(root.join(DECLARATION)).expect("read the declaration");
    let commander = commander
        .replace(STATUS_ZID, &format!("zid = \"{subject_zid}\""))
        .replace(CLOSE_ZID, &format!("zid = \"{}\"", stranger.zid))
        + &format!(
            "\n[identity]\ncertificate = {:?}\nprivate_key = {:?}\n",
            target_cert.display().to_string(),
            target_key.display().to_string()
        );
    // The subject holds the target by the zid the tool printed, and asks it.
    let asker = std::fs::read_to_string(root.join(SUBJECT_DECLARATION))
        .expect("read the subject's declaration");
    // The zid is named by the peer endpoint and by each querier's `of`, never inside a key: the
    // generator makes the keys.
    assert_eq!(asker.matches(&format!("\"{TARGET_ZID}\"")).count(), 4);
    assert!(
        !asker.lines().any(|line| line.starts_with("key = ")),
        "the subject's queriers name verbs, not keys"
    );
    let asker = asker
        .replace(&format!("\"{TARGET_ZID}\""), &format!("\"{target_zid}\""))
        .replace(SUBJECT_CERT, &subject_cert.display().to_string())
        .replace(SUBJECT_KEY, &subject_key.display().to_string());
    let target_node = package(dir.path(), "slot-commander", &commander);
    let subject_node = package(dir.path(), "slot-subject", &asker);

    let mut target_run = Node::run(&target_node, "slot-commander (provisioned)", LISTENING);
    assert_eq!(
        target_run.zid, target_zid,
        "the target proves a zid other than the one its provisioned key names"
    );
    let mut subject_run = Node::run(&subject_node, "slot-subject (provisioned)", SUBJECT_READY);
    assert_eq!(
        subject_run.zid, subject_zid,
        "the subject proves a zid other than the one its provisioned key names"
    );

    // The subject asks over the session it opened to the target's listener: its status is answered
    // and its close is refused by name.
    let deadline = std::time::Instant::now() + BUDGET;
    let (status, close) = loop {
        let said = subject_run.console();
        let found = (
            kept_reply(&said, "/session/status/"),
            kept_reply(&said, "/session/close/"),
        );
        if let (Some(status), Some(close)) = &found {
            break (status.clone(), close.clone());
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the subject kept no answer to both questions within {BUDGET:?}\n--- subject ---\n{said}\n\
             --- target ---\n{}",
            target_run.console()
        );
        std::thread::sleep(Duration::from_millis(200));
    };
    assert!(
        status.starts_with("{\"verdict\":\"status\""),
        "the subject's zid is granted `status` and was not answered: {status}"
    );
    assert!(
        close.contains(CLOSE_REFUSED),
        "the subject's zid is not granted `close` and was not refused by name: {close}"
    );

    // The subject says each verdict itself, read from the reply by the module that writes it, so a
    // lab needs no reader of the reply's bytes: the status of a peer neither node holds, and the
    // refusal with its sentence.
    let said = subject_run.console();
    for want in [
        format!(
            "HOST-WZ-VERDICT @/{target_zid}/client/session/status/d4 verdict=status open=0 \
             closing=0 intent=false"
        ),
        format!(
            "HOST-WZ-VERDICT @/{target_zid}/client/session/close/d4 verdict=refused \
             reason={CLOSE_REFUSED}"
        ),
    ] {
        assert!(
            said.lines().any(|line| line == want),
            "the subject did not say {want:?}\n--- subject ---\n{said}"
        );
    }
    // The querier about `self` asks under a key the subject ended with its own zid when it ran, and
    // the target answers the status of the session the subject holds with it.
    // It said each querier's key when it started, by the querier's place in its declaration.
    let said = subject_run.console();
    let itself = format!("status/{subject_zid}");
    for (at, about) in [
        ("0", "status/d4"),
        ("1", "close/d4"),
        ("2", itself.as_str()),
    ] {
        let want = format!("HOST-WZ-QUERIER {at} @/{target_zid}/client/session/{about}");
        assert!(
            said.lines().any(|line| line == want),
            "the subject did not say {want:?}\n--- subject ---\n{said}"
        );
    }
    let about_self = format!(
        "HOST-WZ-VERDICT @/{target_zid}/client/session/status/{subject_zid} verdict=status "
    );
    let deadline = std::time::Instant::now() + BUDGET;
    loop {
        let said = subject_run.console();
        if said.lines().any(|line| line.starts_with(&about_self)) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the subject's querier about itself was not answered within {BUDGET:?}: want \
             {about_self:?}\n--- subject ---\n{said}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}
