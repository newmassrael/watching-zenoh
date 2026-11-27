// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The passive hold of the fixed-memory profile (decision D10 of `docs/session-lifecycle-intent.md`)
//! as ONE scenario over a matrix of targets (decision D18: a witness runs on what ships). The
//! scenario is [`passive_hold`]: a node is asked `open passive <peer>`, a stock client that claims the
//! peer's zid with another key opens a session and is not held, the peer opens its session with its
//! own key and is held as the peer's one link (the status read says `established`, cause `passive`),
//! and a `close` ends that session and takes the peer out of the intent.
//!
//! | target | the node | how its verbs are asked | its sessions read from | run by |
//! | --- | --- | --- | --- | --- |
//! | the host process | `slot-commander` built from its declaration | its pipe | its console's session lines | Layer Z (`wz_declared_commander_zenohd_interop`) |
//! | the Zephyr image under QEMU | `deploy/zephyr-admin-node`, `overlays/qemu_admin_fixed_tls.conf` | in band, through a router whose key the image lists | its console's `accepted` lines | Layer Qza (this file) |
//! | the Zephyr image on the kit | the same node, `overlays/t2g_admin_fixed_tls.conf` | in band, the same way | the same lines on the kit's serial console | `scripts/kit-lane.sh passive` (this file) |
//!
//! The image has no pipe, so its verbs are asked the way they are used: a stock `zenohd` holding
//! the commander's key dials the image's `tls/` listener, which proves the commander's zid on that
//! link (decision D12), and a stock `z_get` that is a client of that router asks the verb's key under
//! the image's zid. The commander's key is made before the image is built, because the image's
//! commanders are compiled in (`CONFIG_WZ_COMMANDERS_*`, `scripts/zephyr-passive-witness.sh keys`);
//! the lane names it (`WZ_ZEPHYR_PASSIVE_COMMANDER_CERT`, `_KEY`). The peer and the claimant are
//! stock `z_queryable` clients that dial the image's listener directly with keys made here.
//!
//! The image is a target only where it runs: the QEMU leg boots the ELF the lane built
//! (`WZ_ZEPHYR_PASSIVE_QEMU_ELF`) on the board's emulated Ethernet with the listener forwarded to a
//! port of this host, and the kit leg reads the console the kit lane captures
//! (`WZ_ZEPHYR_PASSIVE_KIT_CONSOLE`, from byte `WZ_ZEPHYR_PASSIVE_KIT_MARK`, where the boot after
//! the lane's reset begins) and dials the address the image's READY line names. A leg whose image
//! is not named fails and says what is missing: a target the matrix declares is not passed by being
//! absent.
//!
//! Requires python3, the reference zenohd and its examples (`scripts/build-zenohd.sh`), and for the
//! QEMU leg `qemu-system-arm`. Runs on the `--ignored` lane; the file's `zenohd` token keeps
//! Layer E's sweep off it.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wz_integration_tests::common::{graceful_terminate, read_captured, ChildGuard};
use wz_runtime_tokio_test_support::free_port;

use super::wz_declared_commander_zenohd_interop::{
    ask_within, dialling_router, printed_certificate, zid_by_the_tool, Client, Party,
};

/// The answer to a passive `open` of a node there is room for.
const OPENING: &str = "{\"verdict\":\"opening\"}";
/// The answer to a `close` of a peer held by one link.
const CLOSING_ONE: &str = "{\"verdict\":\"closing\",\"links\":1}";
/// The machine of the status read of a peer waited for under a passive intent, with no session.
pub(super) const WAITING: &str = "\"machines\":[{\"state\":\"passive\"}]";
/// The machine of the status read of a peer held by the session it opened under a passive intent.
pub(super) const HELD: &str = "\"machines\":[{\"state\":\"established\",\"cause\":\"passive\"}]";
/// How long the node runs with a session that only claims the peer's zid before its status is
/// read: many ticks, each of which tells the connect manager the node's proven sessions.
const CLAIM_WINDOW: Duration = Duration::from_secs(2);

/// What the status read of a peer says: the links the node counts for the peer, whether the peer
/// is in its intent, and the document, whose machines the reader leaves out.
pub(super) struct Status {
    pub(super) open: u32,
    pub(super) closing: u32,
    pub(super) intent: bool,
    pub(super) document: String,
}

/// Read the answer to `status <zid>`, by the reader of every answer a node writes.
pub(super) fn read_status(zid: &str, document: String) -> Status {
    use wz_session_core::lifecycle_wire::Answer;
    let read = match Answer::read(document.as_bytes()) {
        Some(Answer::Verdict(read)) => read,
        _ => panic!("the answer to `status {zid}` is no verdict: {document}"),
    };
    match (read.verdict, read.held, read.intent) {
        ("status", Some(links), Some(intent)) => Status {
            open: links.open,
            closing: links.closing,
            intent,
            document,
        },
        _ => panic!("the answer to `status {zid}` is no status read: {document}"),
    }
}

/// A lifecycle verb the scenario asks, about one peer.
#[derive(Clone, Copy)]
pub(super) enum Verb<'a> {
    OpenPassive(&'a str),
    Status(&'a str),
    Close(&'a str),
}

impl Verb<'_> {
    /// The line a node's pipe takes for the verb.
    pub(super) fn pipe_line(self) -> String {
        match self {
            Self::OpenPassive(peer) => format!("open passive {peer}"),
            Self::Status(peer) => format!("status {peer}"),
            Self::Close(peer) => format!("close {peer}"),
        }
    }

    /// The key the verb is asked under in band, of the node `zid` that presents itself as
    /// `whatami` (`wz_session_core::lifecycle_wire`).
    fn key_under(self, zid: &str, whatami: &str) -> String {
        let about = match self {
            Self::OpenPassive(peer) => format!("open/passive/{peer}"),
            Self::Status(peer) => format!("status/{peer}"),
            Self::Close(peer) => format!("close/{peer}"),
        };
        format!("@/{zid}/{whatami}/session/{about}")
    }

    /// Whether asking the verb again changes nothing, so a query that came back empty may be asked
    /// again.
    fn is_read(self) -> bool {
        matches!(self, Self::Status(_))
    }
}

/// The sessions a node has said it took from peers that claim one zid, counted over its run: how
/// many came up with the key of their link proving the claim, how many came up without, and how many
/// ended.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct Sessions {
    pub(super) verified: usize,
    pub(super) not_verified: usize,
    pub(super) lost: usize,
}

/// A node the scenario runs against: where a peer dials it, the certificate it presents, its verbs
/// and what it has said of its sessions.
pub(super) trait PassiveTarget {
    /// The target, as a failure names it.
    fn name(&self) -> &'static str;
    /// The locator a client on this host dials to open a session with the node.
    fn listener(&self) -> &str;
    /// The certificate the node presents, written where a client's configuration names it.
    fn certificate(&self) -> &Path;
    /// How long the node may take to come up with a session, or to end one.
    fn budget(&self) -> Duration;
    /// Ask `verb` and take the one answer the node gives.
    fn ask(&mut self, verb: Verb<'_>) -> String;
    /// The sessions the node has said it took from peers that claim `claims`.
    fn sessions(&mut self, claims: &str) -> Sessions;
    /// What the node has said so far, for a failure.
    fn console(&mut self) -> String;
}

fn status(target: &mut dyn PassiveTarget, zid: &str) -> Status {
    let document = target.ask(Verb::Status(zid));
    read_status(zid, document)
}

/// Ask `status <zid>` until `done` holds of the answer or the target's budget runs out, and hand
/// back the last answer: a node tells its connect manager of its proven sessions on the tick after
/// one is up, not at the moment it says so.
fn status_until(
    target: &mut dyn PassiveTarget,
    zid: &str,
    done: impl Fn(&Status) -> bool,
) -> Status {
    let deadline = Instant::now() + target.budget();
    loop {
        let read = status(target, zid);
        if done(&read) || Instant::now() >= deadline {
            return read;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Whether the node says, within its budget, that the sessions of peers claiming `claims` reached
/// what `done` asks.
fn says_within(
    target: &mut dyn PassiveTarget,
    claims: &str,
    done: impl Fn(Sessions) -> bool,
) -> bool {
    let deadline = Instant::now() + target.budget();
    loop {
        if done(target.sessions(claims)) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// THE SCENARIO. A passive intent holds the session a stock client opens with the peer's own key
/// and not a session that only claims the peer's zid, the status read lists the held session as
/// the peer's one link, and a `close` ends it through the node.
pub(super) fn passive_hold(target: &mut dyn PassiveTarget) {
    let what = target.name();
    let (peer, other) = (Party::new(), Party::new());

    // The intent: the node waits for the peer, and holds no session with it.
    let opened = target.ask(Verb::OpenPassive(&peer.zid));
    assert_eq!(
        opened, OPENING,
        "{what}: a passive open of a node there is room for"
    );
    let waiting = status(target, &peer.zid);
    assert!(
        waiting.intent
            && waiting.open == 0
            && waiting.closing == 0
            && waiting.document.contains(WAITING),
        "{what}: the peer is waited for and has no link yet: {}",
        waiting.document
    );

    // CONTROL: a client that claims the peer's zid with another key opens the same kind of session
    // over the same channel. It is admitted, and the peer is still waited for.
    let mut claimant = Client::connect(target.listener(), target.certificate(), &other, &peer.zid);
    if !says_within(target, &peer.zid, |seen| seen.not_verified >= 1) {
        panic!(
            "{what}: the node admitted no session from the client that claims the peer's zid, so \
             this control says nothing\n--- node ---\n{}\n--- client ---\n{}",
            target.console(),
            claimant.printed()
        );
    }
    std::thread::sleep(CLAIM_WINDOW);
    let claimed = status(target, &peer.zid);
    assert!(
        claimed.intent && claimed.open == 0 && claimed.document.contains(WAITING),
        "{what}: a session whose key does not name the zid it claims was held as the peer's: {}",
        claimed.document
    );
    drop(claimant);
    if !says_within(target, &peer.zid, |seen| seen.lost >= 1) {
        panic!(
            "{what}: the claimant's session did not end when the claimant stopped\n--- node ---\n{}",
            target.console()
        );
    }

    // THE HOLD: the peer opens its session with its own key, and the node holds it as the peer's
    // one link under the passive intent.
    let mut client = Client::connect(target.listener(), target.certificate(), &peer, &peer.zid);
    if !says_within(target, &peer.zid, |seen| seen.verified >= 1) {
        panic!(
            "{what}: the peer's own session did not come up verified\n--- node ---\n{}\n\
             --- client ---\n{}",
            target.console(),
            client.printed()
        );
    }
    let held = status_until(target, &peer.zid, |read| read.open == 1);
    if !(held.intent && held.open == 1 && held.closing == 0 && held.document.contains(HELD)) {
        panic!(
            "{what}: the session the peer opened is not held as its link under the passive \
             intent: {}\n--- node ---\n{}",
            held.document,
            target.console()
        );
    }

    // CLOSE: the node ends that session itself and takes the peer out of the intent.
    let closed = target.ask(Verb::Close(&peer.zid));
    assert_eq!(
        closed, CLOSING_ONE,
        "{what}: a close of the held peer orders its one link closed"
    );
    if !says_within(target, &peer.zid, |seen| seen.lost >= 2) {
        panic!(
            "{what}: the session the peer opened was still up after the close\n--- node ---\n{}\n\
             --- client ---\n{}",
            target.console(),
            client.printed()
        );
    }
    let after = status(target, &peer.zid);
    assert!(
        !after.intent && after.open == 0 && after.closing == 0,
        "{what}: the closed peer is still in the intent or still counted: {}",
        after.document
    );
}

// ---- the Zephyr image as a target: under QEMU, and on the kit ----

/// The key of the commander the image was built to list for `open`, `close` and `status`.
const COMMANDER_CERT: &str = "WZ_ZEPHYR_PASSIVE_COMMANDER_CERT";
const COMMANDER_KEY: &str = "WZ_ZEPHYR_PASSIVE_COMMANDER_KEY";
/// The ELF the QEMU leg boots.
const QEMU_ELF: &str = "WZ_ZEPHYR_PASSIVE_QEMU_ELF";
/// The kit's console as the kit lane captures it, and the byte the boot after its reset begins at.
const KIT_CONSOLE: &str = "WZ_ZEPHYR_PASSIVE_KIT_CONSOLE";
const KIT_MARK: &str = "WZ_ZEPHYR_PASSIVE_KIT_MARK";
/// What the image prints once it listens: its zid and its locator follow
/// (`deploy/zephyr-admin-node/rust/src/fixed_admin.rs`, `start`).
const IMAGE_READY: &str = "ZEPHYR-WZ-ADMIN READY ";
/// What the image prints each time the set of established sessions peers opened to it changes
/// (`fixed_admin.rs`, `say_accepted`): each session's claimed zid, then `verified` or
/// `not verified`, comma-separated, or `none`.
const IMAGE_ACCEPTED: &str = "zephyr-admin-node: accepted";
/// The role the image presents itself as, which its admin keys carry.
const IMAGE_WHATAMI: &str = "peer";
/// How long the image may take to boot, to complete a handshake in software on its core, or to end
/// a session: a P-256 handshake takes about a second and a half per role on the kit, and longer
/// under emulation.
const IMAGE_BUDGET: Duration = Duration::from_secs(180);
/// How long a query through the router may wait for the image's reply.
const IMAGE_QUERY_TIMEOUT_MS: &str = "20000";
/// How many times a read the image did not answer is asked again.
const READ_ATTEMPTS: usize = 3;
/// The board's MAC under QEMU, as Layer Qz and Layer Qza pin it, and where its listener is on the
/// emulator's user network.
const QEMU_MAC: &str = "52:54:00:aa:bb:cc";
const QEMU_GUEST_LISTENER: &str = "10.0.2.15:7448";

/// The value of the environment variable `name`, or a failure that says what the leg lacks.
fn named(name: &str, what: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!(
            "{name} names no {what}: this leg runs where the lane that builds the image names it"
        )
    })
}

/// Count, over the image's `accepted` lines in the order it said them, the sessions claiming
/// `claims` that came up verified, came up not verified, and ended.
fn accepted_sessions(console: &str, claims: &str) -> Sessions {
    let mut seen = Sessions::default();
    let (mut verified, mut not_verified) = (0usize, 0usize);
    for line in console.lines() {
        let Some(rest) = line.trim_end().strip_prefix(IMAGE_ACCEPTED) else {
            continue;
        };
        let (mut now_verified, mut now_not_verified) = (0usize, 0usize);
        for entry in rest.trim().split(", ") {
            match entry.split_once(' ') {
                Some((zid, "verified")) if zid == claims => now_verified += 1,
                Some((zid, "not verified")) if zid == claims => now_not_verified += 1,
                _ => {}
            }
        }
        seen.verified += now_verified.saturating_sub(verified);
        seen.not_verified += now_not_verified.saturating_sub(not_verified);
        seen.lost +=
            verified.saturating_sub(now_verified) + not_verified.saturating_sub(now_not_verified);
        (verified, not_verified) = (now_verified, now_not_verified);
    }
    seen
}

/// The Zephyr image as a target: its console, the router that holds the commander's key and
/// dials it, and the asker's configuration for that router.
struct ImageTarget {
    name: &'static str,
    /// The image's console, a capture that grows while the image runs.
    console: File,
    /// The byte of the console this run's boot begins at.
    mark: usize,
    zid: String,
    listener: String,
    certificate: PathBuf,
    router: ChildGuard,
    router_out: File,
    /// A client of the router's `tcp/` port, which asks the verbs.
    asker: String,
    /// The emulator, for the QEMU leg: stopped when the target is dropped.
    qemu: Option<ChildGuard>,
    _files: tempfile::TempDir,
}

impl ImageTarget {
    /// Boot the ELF the lane built under QEMU, with the image's listener forwarded to a port of this
    /// host, and come up as its target.
    fn under_qemu() -> Self {
        let elf = PathBuf::from(named(QEMU_ELF, "Zephyr image to boot"));
        assert!(elf.is_file(), "{QEMU_ELF}: no file at {}", elf.display());
        let port = free_port();
        let console = tempfile::tempfile().expect("a capture for the image's console");
        let qemu = ChildGuard::wrap(
            "qemu-system-arm (deploy/zephyr-admin-node, mps2/an385)",
            Command::new("qemu-system-arm")
                .args(["-cpu", "cortex-m3", "-machine", "mps2-an385", "-nographic"])
                .args(["-monitor", "none", "-serial", "stdio", "-nic"])
                .arg(format!(
                    "user,model=lan9118,mac={QEMU_MAC},\
                     hostfwd=tcp:127.0.0.1:{port}-{QEMU_GUEST_LISTENER}"
                ))
                .arg("-kernel")
                .arg(&elf)
                .stdin(Stdio::null())
                .stdout(Stdio::from(console.try_clone().expect("dup capture")))
                .stderr(Stdio::from(console.try_clone().expect("dup capture")))
                .spawn()
                .expect("spawn qemu-system-arm"),
        );
        Self::come_up(
            "the Zephyr image under QEMU",
            console,
            0,
            Some(format!("tls/127.0.0.1:{port}")),
            Some(qemu),
        )
    }

    /// Read the console of the image the kit lane flashed and reset, from the byte its boot begins
    /// at, and come up as its target at the address its READY line names.
    fn on_the_kit() -> Self {
        let path = PathBuf::from(named(KIT_CONSOLE, "capture of the kit's console"));
        let mark = named(KIT_MARK, "byte the kit's boot begins at")
            .parse()
            .unwrap_or_else(|why| panic!("{KIT_MARK} is no byte offset: {why}"));
        let console = File::open(&path)
            .unwrap_or_else(|why| panic!("{KIT_CONSOLE}: {}: {why}", path.display()));
        Self::come_up("the Zephyr image on the kit", console, mark, None, None)
    }

    /// Wait for the image's READY line, hold its certificate to the zid the line claims, start the
    /// router with the commander's key dialling it, and wait until the image holds the router's
    /// session as the commander's and answers a read through it.
    fn come_up(
        name: &'static str,
        mut console: File,
        mark: usize,
        listener: Option<String>,
        qemu: Option<ChildGuard>,
    ) -> Self {
        let commander = Party::from_files(
            Path::new(&named(
                COMMANDER_CERT,
                "certificate of the commander the image lists",
            )),
            Path::new(&named(
                COMMANDER_KEY,
                "key of the commander the image lists",
            )),
        );
        let deadline = Instant::now() + IMAGE_BUDGET;
        let (line, said) = loop {
            let said = console_since(&mut console, mark);
            let found = said
                .lines()
                .find(|line| line.starts_with(IMAGE_READY))
                .map(str::to_owned);
            if let Some(line) = found {
                break (line, said);
            }
            assert!(
                Instant::now() < deadline,
                "{name} never said {IMAGE_READY:?} within {IMAGE_BUDGET:?}\n--- console ---\n{said}"
            );
            std::thread::sleep(Duration::from_millis(200));
        };
        let mut words = line[IMAGE_READY.len()..].split_whitespace();
        let (Some(zid), Some(locator)) = (words.next(), words.next()) else {
            panic!("{name}: the READY line names no zid and locator: {line:?}");
        };
        let zid = zid.to_owned();
        let listener = listener.unwrap_or_else(|| locator.to_owned());
        let files = tempfile::tempdir().expect("a directory for the image's target");
        let certificate = files.path().join("image.pem");
        let pem = printed_certificate(&said)
            .unwrap_or_else(|| panic!("{name} printed no certificate before READY\n{said}"));
        std::fs::write(&certificate, &pem).expect("write the image's certificate");
        assert_eq!(
            zid_by_the_tool(&certificate),
            zid,
            "{name}: the READY line claims a zid the key of the certificate it printed does not name"
        );

        // The commander: a router with the key the image lists, dialling the image's listener and
        // pinning the certificate it printed.
        let (router, router_out, port) = dialling_router(files.path(), &listener, &commander, &pem);
        let mut target = Self {
            name,
            console,
            mark,
            zid,
            listener,
            certificate,
            router,
            router_out,
            asker: format!(
                "{{ mode: \"client\", connect: {{ endpoints: [\"tcp/127.0.0.1:{port}\"] }}, \
                 scouting: {{ multicast: {{ enabled: false }} }} }}"
            ),
            qemu,
            _files: files,
        };
        if !says_within(&mut target, &commander.zid, |seen| seen.verified >= 1) {
            panic!(
                "{name}: the router with the commander's key never held a verified session with the \
                 image\n--- console ---\n{}\n--- zenohd ---\n{}",
                target.console(),
                read_captured(&mut target.router_out)
            );
        }
        // The router forwards a query only once the image's admin queryable is declared on the
        // router's session: a read about the commander itself is answered once it is.
        let reachable = target.ask(Verb::Status(&commander.zid));
        assert!(
            reachable.starts_with("{\"verdict\":\"status\""),
            "{name}: the commander the image lists was not answered a status: {reachable}"
        );
        target
    }
}

/// What the console `console` holds from byte `mark` on, with the carriage returns of a serial
/// line taken out.
fn console_since(console: &mut File, mark: usize) -> String {
    let all = read_captured(console);
    all.get(mark..).unwrap_or(&all).replace('\r', "")
}

impl PassiveTarget for ImageTarget {
    fn name(&self) -> &'static str {
        self.name
    }

    fn listener(&self) -> &str {
        &self.listener
    }

    fn certificate(&self) -> &Path {
        &self.certificate
    }

    fn budget(&self) -> Duration {
        IMAGE_BUDGET
    }

    fn ask(&mut self, verb: Verb<'_>) -> String {
        let key = verb.key_under(&self.zid, IMAGE_WHATAMI);
        let attempts = if verb.is_read() { READ_ATTEMPTS } else { 1 };
        let mut came = String::new();
        for _ in 0..attempts {
            let (replies, text) = ask_within(&self.asker, &key, IMAGE_QUERY_TIMEOUT_MS);
            if let [one] = replies.as_slice() {
                return one.clone();
            }
            came = format!("{replies:?}\n--- z_get ---\n{text}");
        }
        let console = self.console();
        let router = read_captured(&mut self.router_out);
        panic!(
            "{}: expected one reply to {key}, got {came}\n--- console ---\n{console}\n--- zenohd ---\n{router}",
            self.name
        );
    }

    fn sessions(&mut self, claims: &str) -> Sessions {
        accepted_sessions(&self.console(), claims)
    }

    fn console(&mut self) -> String {
        console_since(&mut self.console, self.mark)
    }
}

impl Drop for ImageTarget {
    fn drop(&mut self) {
        graceful_terminate(self.router.child_mut(), Duration::from_secs(5));
        if let Some(qemu) = self.qemu.as_mut() {
            graceful_terminate(qemu.child_mut(), Duration::from_secs(5));
        }
    }
}

/// The image a run names: under QEMU when `WZ_ZEPHYR_PASSIVE_QEMU_ELF` names its ELF (Layer Qza), on
/// the kit when `WZ_ZEPHYR_PASSIVE_KIT_CONSOLE` names the console the kit lane captures
/// (`scripts/kit-lane.sh passive`). One test over the two targets, as decision D18 asks: the same
/// steps, the target chosen by where the run is. A run that names neither has no image to judge
/// and fails by name, never passes.
fn the_named_image() -> ImageTarget {
    match (
        std::env::var_os("WZ_ZEPHYR_PASSIVE_QEMU_ELF").is_some(),
        std::env::var_os("WZ_ZEPHYR_PASSIVE_KIT_CONSOLE").is_some(),
    ) {
        (true, false) => ImageTarget::under_qemu(),
        (false, true) => ImageTarget::on_the_kit(),
        (true, true) => panic!(
            "WZ_ZEPHYR_PASSIVE_QEMU_ELF and WZ_ZEPHYR_PASSIVE_KIT_CONSOLE both name an image: name one"
        ),
        (false, false) => panic!(
            "no image named: set WZ_ZEPHYR_PASSIVE_QEMU_ELF (Layer Qza) or \
             WZ_ZEPHYR_PASSIVE_KIT_CONSOLE (scripts/kit-lane.sh passive)"
        ),
    }
}

// wz-proves: none -- the hold of a session a peer opens under a passive intent is decision D10 on the fixed-memory profile's listener, witnessed on the Zephyr image that ships it (decision D18); no catalog atom names it
#[test]
#[ignore = "binary-dep e2e (the Zephyr image under qemu-system-arm, or flashed to the kit by scripts/kit-lane.sh passive, + zenohd and its examples); runs via --ignored"]
fn zenohd_zephyr_image_passive_intent_holds_the_session_a_stock_client_opens_and_not_a_claim_of_its_zid(
) {
    passive_hold(&mut the_named_image());
}

#[test]
fn the_image_s_accepted_lines_count_each_session_of_a_claimed_zid_once() {
    let console = "\
        boot\n\
        zephyr-admin-node: accepted c0 verified\r\n\
        zephyr-admin-node: accepted c0 verified, 1f not verified\n\
        stack: peak 100 of 200 bytes\n\
        zephyr-admin-node: accepted c0 verified\n\
        zephyr-admin-node: accepted c0 verified, 1f verified\n\
        zephyr-admin-node: accepted none\n";
    assert_eq!(
        accepted_sessions(console, "1f"),
        Sessions {
            verified: 1,
            not_verified: 1,
            lost: 2,
        }
    );
    // The commander's session is another zid's, and a zid that only prefixes it is not it.
    assert_eq!(
        accepted_sessions(console, "c0"),
        Sessions {
            verified: 1,
            not_verified: 0,
            lost: 1,
        }
    );
    assert_eq!(accepted_sessions(console, "c"), Sessions::default());
}
