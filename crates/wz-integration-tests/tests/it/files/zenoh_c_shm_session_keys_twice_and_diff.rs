// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.27 `api-compat-c` -- the shared-memory keys a SESSION applies itself, one config document
//! handed to a C program linked against the real `libzenohc.so` and against wz's cdylib, the
//! effect read from outside the program.
//!
//! ## The promotion: `transport/shared_memory/transport_optimization/message_size_threshold` and
//! `transport/shared_memory/transport_optimization/messages`
//!
//! Upstream copies a plain payload into the session's own provider when the link's peer
//! negotiated shared memory, the payload is at least the threshold, and the message's kind is in
//! the list (`io/zenoh-transport/src/common/shm/interop.rs` @
//! `if slice.len() >= self.message_size_threshold {`, and per kind @ `let p = if policy.put {`,
//! @ `let p = if policy.query {` and @ `let p = if policy.reply {`). The receiver then holds a
//! shared-memory buffer where it would otherwise hold bytes, and that is what is read: a receiver
//! linked against the REAL library, the same program in every exchange, prints for each payload
//! it is handed whether `z_bytes_as_loaned_shm` takes it. Only the SENDER changes between the two
//! arms, and it is handed the document.
//!
//! Each kind is sent its own way, and the receiver takes it the matching way: a put, which the
//! receiver's subscriber is handed; the value of a get, which the receiver's queryable is handed;
//! and a reply, which the sender's queryable makes to the receiver's get. An error reply is not a
//! case: upstream's codec writes its payload in line whatever the transport did to it
//! (`commons/zenoh-codec/src/zenoh/err.rs` @ `let bodec = Zenoh080Bounded::<u32>::new();`), so
//! the receiver reads bytes from both libraries.
//!
//! The sender asks for its provider without waiting before it sends. Upstream builds the provider
//! the first time anything asks and hands it to the promotion only once a later ask receives the
//! built provider from the build (`io/zenoh-transport/src/common/shm/interop.rs` @
//! `ProviderInitStateInner::Initializing(join_handle) => match join_handle.try_recv() {`). A
//! BLOCKING ask receives it first (`zenoh-c/src/session.rs` @
//! `waiter.recv_async().await.ok().flatten()`), after which the promotion never does. The
//! non-blocking ask starts the build on both libraries and receives nothing, so every case below
//! decides on the key alone.
//!
//! ## The subsystem: `transport/shared_memory/mode`
//!
//! `init` makes the shared-memory subsystem of the process when the session opens, `lazy` leaves
//! it to the first buffer (`zenoh/src/net/runtime/mod.rs` @
//! `zenoh_config::ShmInitMode::Init => zenoh_shm::init::init(),`). Part of what it makes is the
//! metadata segment every provider of the process draws its chunks' headers from
//! (`commons/zenoh-shm/src/metadata/storage.rs` @ `let segment = Arc::new(MetadataSegment::create()?);`),
//! a POSIX object under `/dev/shm` the process maps. A program that opens a session and nothing
//! else reads its own `/proc/self/maps`: the number of distinct `/dev/shm` objects it maps after
//! an `init` open, less the number after a `lazy` one, is the subsystem the key made, and the two
//! libraries are compared on that difference. The absolute counts are not compared: the segment
//! a session's establishment maps is not this key's.
//!
//! An object is counted by its inode and not by its name. wz publishes a segment by linking a
//! staging file to `{id}.zenoh` and removing the staging name, so its mapping is listed under
//! the removed name (`crates/wz-runtime-tokio/src/posix_shm/unix.rs`, `OwnedSegment::create`);
//! the name says nothing the count needs, and the inode is the object either way.

#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use wz_integration_tests::bounded::{BoundedChild as _, BoundedOutput as _};
use wz_integration_tests::common::{
    assert_zenoh_c_arm_pairing, compile_zenoh_c_example, wz_capi_c_cdylib, zenoh_c_oracle,
    zenoh_c_shared_library, PortReservation,
};

/// A sender that opens a session from the config file it is given, asks for the session's
/// provider without waiting, and sends two plain payloads of one size of the kind its mode names:
/// `put` puts them, `query` gets with each as the value, and `reply` answers each of the
/// receiver's gets with one. Arguments: the config file, the key, the payload size in bytes, the
/// mode.
const SENDER: &str = r#"#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zenoh.h"

/* The payload every message carries. */
static uint8_t *g_buf = NULL;
static size_t g_size = 0;

static void on_query(z_loaned_query_t *query, void *arg) {
    (void)arg;
    z_owned_bytes_t payload;
    z_bytes_copy_from_buf(&payload, g_buf, g_size);
    int rc = z_query_reply(query, z_query_keyexpr(query), z_move(payload), NULL);
    printf("reply rc=%d\n", rc);
}

static void get_with_value(const z_loaned_session_t *s, const z_loaned_keyexpr_t *ke, int i) {
    z_owned_bytes_t payload;
    z_bytes_copy_from_buf(&payload, g_buf, g_size);
    z_owned_closure_reply_t closure;
    z_owned_fifo_handler_reply_t handler;
    z_fifo_channel_reply_new(&closure, &handler, 16);
    z_get_options_t opts;
    z_get_options_default(&opts);
    opts.payload = z_move(payload);
    opts.timeout_ms = 1000;
    int rc = z_get(s, ke, "", z_move(closure), &opts);
    printf("get %d rc=%d\n", i, rc);
    z_owned_reply_t reply;
    while (z_recv(z_loan(handler), &reply) == Z_OK) {
        z_drop(z_move(reply));
    }
    z_drop(z_move(handler));
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc != 5) { return 2; }
    const char *mode = argv[4];
    int put = strcmp(mode, "put") == 0;
    int query = strcmp(mode, "query") == 0;
    int reply = strcmp(mode, "reply") == 0;
    if (!put && !query && !reply) { return 2; }
    g_size = (size_t)atol(argv[3]);
    g_buf = malloc(g_size);
    if (g_buf == NULL) { return 6; }
    memset(g_buf, 'x', g_size);
    z_owned_config_t config;
    if (zc_config_from_file(&config, argv[1]) != Z_OK) { printf("config failed\n"); return 3; }
    z_owned_session_t s;
    if (z_open(&s, z_move(config), NULL) != Z_OK) { printf("open failed\n"); return 4; }
    z_view_keyexpr_t ke;
    if (z_view_keyexpr_from_str(&ke, argv[2]) != Z_OK) { return 5; }
    /* The queryable that replies is declared first, so that the receiver knows it when it asks. */
    z_owned_queryable_t qable;
    z_internal_queryable_null(&qable);
    if (reply) {
        z_owned_closure_query_t qcb;
        z_closure(&qcb, on_query, NULL, NULL);
        if (z_declare_queryable(z_loan(s), &qable, z_loan(ke), z_move(qcb), NULL) != Z_OK) {
            printf("queryable failed\n");
            return 7;
        }
    }
    /* Let the receiver's declaration reach this session. */
    z_sleep_ms(1500);

    /* Start the provider's build and take nothing out of it. */
    z_owned_shared_shm_provider_t provider;
    z_internal_shared_shm_provider_null(&provider);
    z_shm_provider_state state = Z_SHM_PROVIDER_STATE_ERROR;
    z_obtain_shm_provider(z_loan(s), false, &provider, &state);
    z_shared_shm_provider_drop(z_shared_shm_provider_move(&provider));
    z_sleep_ms(2000);

    for (int i = 0; put && i < 2; i++) {
        z_owned_bytes_t payload;
        z_bytes_copy_from_buf(&payload, g_buf, g_size);
        int rc = z_put(z_loan(s), z_loan(ke), z_move(payload), NULL);
        printf("put %d rc=%d\n", i, rc);
        z_sleep_ms(300);
    }
    for (int i = 0; query && i < 2; i++) {
        get_with_value(z_loan(s), z_loan(ke), i);
        z_sleep_ms(300);
    }
    /* The receiver asks from 5 s after it opened, which is after this session started its
       provider's build. */
    if (reply) { z_sleep_ms(4500); }
    z_sleep_ms(1000);
    z_drop(z_move(qable));
    z_session_drop(z_session_move(&s));
    free(g_buf);
    return 0;
}
"#;

/// A receiver with the real library's defaults that prints, for each payload it is handed of the
/// kind its mode names, whether the payload is a shared-memory buffer and how long it is: `put`
/// subscribes, `query` declares a queryable that reads each query's value, and `reply` gets
/// twice, 5 s after it opened, and reads each reply. Arguments: the endpoint to listen on, the
/// key, how many seconds a subscriber or a queryable runs, the mode.
const RECEIVER: &str = r#"#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zenoh.h"

static void report(const z_loaned_bytes_t *payload) {
    const z_loaned_shm_t *shm = NULL;
    int rc = z_bytes_as_loaned_shm(payload, &shm);
    printf("sample: shm=%s len=%zu\n", rc == 0 ? "yes" : "no", z_bytes_len(payload));
}

static void on_sample(z_loaned_sample_t *sample, void *arg) {
    (void)arg;
    report(z_sample_payload(sample));
}

static void on_query(z_loaned_query_t *query, void *arg) {
    (void)arg;
    const z_loaned_bytes_t *payload = z_query_payload(query);
    if (payload == NULL) { printf("sample: no value\n"); return; }
    report(payload);
}

static void ask(const z_loaned_session_t *s, const z_loaned_keyexpr_t *ke) {
    z_owned_closure_reply_t closure;
    z_owned_fifo_handler_reply_t handler;
    z_fifo_channel_reply_new(&closure, &handler, 16);
    z_get_options_t opts;
    z_get_options_default(&opts);
    opts.timeout_ms = 2000;
    z_get(s, ke, "", z_move(closure), &opts);
    z_owned_reply_t reply;
    while (z_recv(z_loan(handler), &reply) == Z_OK) {
        if (z_reply_is_ok(z_loan(reply))) {
            report(z_sample_payload(z_reply_ok(z_loan(reply))));
        }
        z_drop(z_move(reply));
    }
    z_drop(z_move(handler));
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc != 5) { return 2; }
    const char *mode = argv[4];
    if (strcmp(mode, "put") != 0 && strcmp(mode, "query") != 0 && strcmp(mode, "reply") != 0) {
        return 2;
    }
    z_owned_config_t config;
    z_config_default(&config);
    char listen[512];
    snprintf(listen, sizeof listen, "[\"%s\"]", argv[1]);
    zc_config_insert_json5(z_loan_mut(config), Z_CONFIG_LISTEN_KEY, listen);
    zc_config_insert_json5(z_loan_mut(config), Z_CONFIG_MULTICAST_SCOUTING_KEY, "false");
    z_owned_session_t s;
    int rc = z_open(&s, z_move(config), NULL);
    printf("open rc=%d\n", rc);
    if (rc != Z_OK) { return 3; }
    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, argv[2]);
    if (strcmp(mode, "put") == 0) {
        z_owned_closure_sample_t cb;
        z_closure(&cb, on_sample, NULL, NULL);
        z_owned_subscriber_t sub;
        if (z_declare_subscriber(z_loan(s), &sub, z_loan(ke), z_move(cb), NULL) != Z_OK) {
            printf("declare failed\n");
            return 4;
        }
        z_sleep_s((size_t)atoi(argv[3]));
        z_drop(z_move(sub));
    } else if (strcmp(mode, "query") == 0) {
        z_owned_closure_query_t cb;
        z_closure(&cb, on_query, NULL, NULL);
        z_owned_queryable_t qable;
        if (z_declare_queryable(z_loan(s), &qable, z_loan(ke), z_move(cb), NULL) != Z_OK) {
            printf("declare failed\n");
            return 4;
        }
        z_sleep_s((size_t)atoi(argv[3]));
        z_drop(z_move(qable));
    } else {
        z_sleep_ms(5000);
        for (int i = 0; i < 2; i++) {
            ask(z_loan(s), z_loan(ke));
            z_sleep_ms(300);
        }
    }
    z_drop(z_move(s));
    return 0;
}
"#;

/// A program that opens a session from the config file it is given and prints how many distinct
/// `/dev/shm` objects (by inode) the process maps once the open has settled. Argument: the config
/// file.
const MAPS_PROBE: &str = r#"#include <stdio.h>
#include <string.h>
#include "zenoh.h"

static int mapped_shm_objects(void) {
    FILE *maps = fopen("/proc/self/maps", "r");
    if (maps == NULL) { return -1; }
    static unsigned long seen[256];
    int n = 0;
    char line[1024];
    while (fgets(line, sizeof line, maps) != NULL) {
        if (strstr(line, " /dev/shm/") == NULL) { continue; }
        unsigned long inode = 0;
        if (sscanf(line, "%*s %*s %*s %*s %lu", &inode) != 1 || inode == 0) { continue; }
        int known = 0;
        for (int i = 0; i < n; i++) {
            if (seen[i] == inode) { known = 1; break; }
        }
        if (!known && n < 256) {
            seen[n] = inode;
            n++;
        }
    }
    fclose(maps);
    return n;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc != 2) { return 2; }
    z_owned_config_t config;
    if (zc_config_from_file(&config, argv[1]) != Z_OK) { printf("config failed\n"); return 3; }
    z_owned_session_t s;
    if (z_open(&s, z_move(config), NULL) != Z_OK) { printf("open failed\n"); return 4; }
    z_sleep_ms(500);
    printf("segments=%d\n", mapped_shm_objects());
    z_session_drop(z_session_move(&s));
    return 0;
}
"#;

const KEY: &str = "demo/example/shm-session-keys";

/// How long a receiver's subscriber or queryable runs: the sender's settle, warm-up and two puts
/// or gets fit inside it.
const RECEIVER_SECONDS: &str = "8";

/// The oracle, or `None` with a LOUD note naming what to do about it.
fn oracle_or_note() -> Option<PathBuf> {
    match zenoh_c_oracle() {
        Some((include, _libdir, _examples)) => Some(include),
        None => {
            eprintln!(
                "skip: the zenoh-c ORACLE is absent. This leg needs zenoh-c's headers \
                 and libzenohc.so (default prefix ~/.local, override WZ_ZENOH_C_PREFIX). \
                 Layer C1cc with WZ_C1CC_REQUIRE=1 fails instead of skipping."
            );
            None
        }
    }
}

/// Whether `include` is an oracle without the shared-memory and unstable arms, where neither the
/// provider nor `z_bytes_as_loaned_shm` is declared.
fn lacks_the_shm_arm(include: &Path) -> bool {
    let configure = std::fs::read_to_string(include.join("zenoh_configure.h")).unwrap_or_default();
    let defines = |name: &str| {
        configure
            .lines()
            .any(|l| l.trim() == format!("#define {name}"))
    };
    !(defines("Z_FEATURE_UNSTABLE_API") && defines("Z_FEATURE_SHARED_MEMORY"))
}

/// One program compiled against one library: the executable and the directory its library is in.
struct Built {
    exe: PathBuf,
    libdir: PathBuf,
}

/// The two libraries a program is linked against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Arm {
    /// The real `libzenohc.so`.
    Reference,
    /// wz's cdylib.
    Wz,
}

/// Compile `source` as `name` against `arm`'s library, in a directory of its own under `work`.
fn compile(name: &str, source: &str, include: &Path, work: &Path, arm: Arm) -> Built {
    let src_dir = work.join(format!("{name}-src"));
    std::fs::create_dir_all(&src_dir).expect("source dir");
    std::fs::write(src_dir.join(format!("{name}.c")), source).expect("write the source");
    let (libdir, link) = match arm {
        Arm::Reference => {
            let reference = zenoh_c_shared_library().expect("the oracle resolved above");
            let libdir = reference
                .parent()
                .expect("libzenohc.so has a parent")
                .to_path_buf();
            (libdir, "zenohc")
        }
        Arm::Wz => {
            let cdylib = wz_capi_c_cdylib();
            let libdir = cdylib.parent().expect("cdylib has a parent").to_path_buf();
            (libdir, "wz_capi_c")
        }
    };
    let out_dir = work.join(format!("{name}-{link}"));
    std::fs::create_dir_all(&out_dir).expect("build dir");
    let exe = compile_zenoh_c_example(name, &out_dir, include, &src_dir, &libdir, link)
        .unwrap_or_else(|diag| panic!("{name}.c does not link against {arm:?}'s library\n{diag}"));
    Built { exe, libdir }
}

/// The kind of message a case sends, as upstream's list names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Message {
    /// The sender puts; the receiver subscribes.
    Put,
    /// The sender gets with the payload as the value; the receiver's queryable reads it.
    Query,
    /// The receiver gets; the sender's queryable answers with the payload.
    Reply,
}

impl Message {
    /// The mode both programs are run in for this kind.
    fn mode(self) -> &'static str {
        match self {
            Message::Put => "put",
            Message::Query => "query",
            Message::Reply => "reply",
        }
    }
}

/// One promotion case: what it shows, the kind of message sent, the `transport_optimization`
/// members its document states, the size of the payload, and whether upstream's rule promotes
/// it.
struct PromotionCase {
    what: &'static str,
    message: Message,
    optimization: &'static str,
    size: usize,
    promoted: bool,
}

/// The document a sender of `case` is handed: a dial to the receiver, no scouting, and the case's
/// `transport_optimization` members.
fn sender_document(endpoint: &str, case: &PromotionCase) -> String {
    format!(
        r#"{{ connect: {{ endpoints: ["{endpoint}"] }},
  scouting: {{ multicast: {{ enabled: false }} }},
  transport: {{ shared_memory: {{ transport_optimization: {{ {} }} }} }} }}"#,
        case.optimization
    )
}

/// One exchange: the reference receiver listens, the sender on `sender` dials it with `case`'s
/// document and sends the case's kind of message, and the receiver's sample rows come back
/// sorted.
fn exchange(sender: &Built, receiver: &Built, case: &PromotionCase, work: &Path) -> Vec<String> {
    let reservation = PortReservation::pick();
    let endpoint = format!("tcp/127.0.0.1:{}", reservation.port());
    let mut receiving = Command::new(&receiver.exe)
        .args([
            endpoint.as_str(),
            KEY,
            RECEIVER_SECONDS,
            case.message.mode(),
        ])
        .env("LD_LIBRARY_PATH", &receiver.libdir)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the receiver");
    let mut lines = BufReader::new(receiving.stdout.take().expect("piped stdout")).lines();
    let mut printed: Vec<String> = Vec::new();
    for line in lines.by_ref() {
        let line = line.expect("read the receiver's stdout");
        let opened = line.starts_with("open rc=");
        printed.push(line);
        if opened {
            break;
        }
    }
    drop(reservation);
    let document = work.join("sender.json5");
    std::fs::write(&document, sender_document(&endpoint, case)).expect("write the document");
    let sent = Command::new(&sender.exe)
        .arg(document)
        .arg(KEY)
        .arg(case.size.to_string())
        .arg(case.message.mode())
        .env("LD_LIBRARY_PATH", &sender.libdir)
        .stderr(Stdio::null())
        .output_bounded()
        .expect("run the sender");
    assert!(
        sent.status.success(),
        "{}: the sender exited {:?}:\n{}",
        case.what,
        sent.status.code(),
        String::from_utf8_lossy(&sent.stdout)
    );
    printed.extend(lines.map(|line| line.expect("read the receiver's stdout")));
    receiving.wait_bounded().expect("the receiver ends");
    let mut rows: Vec<String> = printed
        .into_iter()
        .filter(|l| l.starts_with("sample:"))
        .collect();
    rows.sort();
    rows
}

/// The rows the reference receiver prints for `case` under upstream's rule: both messages, each a
/// shared-memory buffer exactly when the case promotes it.
fn expected_rows(case: &PromotionCase) -> Vec<String> {
    let shm = if case.promoted { "yes" } else { "no" };
    vec![format!("sample: shm={shm} len={}", case.size); 2]
}

/// Run every case with the real library's sender first, holding it to upstream's rule, then with
/// wz's, holding it to what the real library did.
fn promotion_differential(cases: &[PromotionCase]) {
    let Some(include) = oracle_or_note() else {
        return;
    };
    if lacks_the_shm_arm(&include) {
        eprintln!(
            "skip: this zenoh-c oracle is built without Z_FEATURE_SHARED_MEMORY and \
             Z_FEATURE_UNSTABLE_API, where the session's provider is not declared."
        );
        return;
    }
    assert_zenoh_c_arm_pairing(&include);
    let work = tempfile::tempdir().expect("tempdir for the compiled programs");
    let receiver = compile(
        "shm_keys_receiver",
        RECEIVER,
        &include,
        work.path(),
        Arm::Reference,
    );
    let sender_ref = compile(
        "shm_keys_sender",
        SENDER,
        &include,
        work.path(),
        Arm::Reference,
    );
    let sender_wz = compile("shm_keys_sender", SENDER, &include, work.path(), Arm::Wz);

    for case in cases {
        // The ORACLE first: a reference that did not deliver both messages, or that promoted
        // against the rule, makes the equality below say nothing about the key.
        let by_ref = exchange(&sender_ref, &receiver, case, work.path());
        assert_eq!(
            by_ref,
            expected_rows(case),
            "{}: the real library's sender did not deliver what upstream's rule says for this \
             document, so the case cannot adjudicate wz",
            case.what
        );
        let by_wz = exchange(&sender_wz, &receiver, case, work.path());
        assert_eq!(
            by_wz, by_ref,
            "§5.27 api-compat-c: {} ({:?}): with the same document, wz's sender delivered the \
             message otherwise than libzenohc's.\n--- wz ---\n{by_wz:#?}\n--- libzenohc ---\n\
             {by_ref:#?}",
            case.what, case.message
        );
    }
}

/// THE GATE for `transport/shared_memory/transport_optimization/message_size_threshold`: a put
/// is copied into shared memory from the threshold up and not below it, by wz's sender as by the
/// real library's, with upstream's 3072 when the document states none.
// wz-proves: api-compat-c zenoh-c->wz partial
#[test]
#[ignore = "reads a zenoh-c oracle; run by run-ci Layer C1cc (which builds the matching \
            ABI arm this needs)"]
fn the_message_size_threshold_decides_which_puts_travel_as_shared_memory_on_wz_and_libzenohc() {
    promotion_differential(&[
        PromotionCase {
            what: "no threshold stated, a payload above upstream's 3072",
            message: Message::Put,
            optimization: "",
            size: 4096,
            promoted: true,
        },
        PromotionCase {
            what: "no threshold stated, a payload below upstream's 3072",
            message: Message::Put,
            optimization: "",
            size: 2048,
            promoted: false,
        },
        PromotionCase {
            what: "a threshold of 1024 promotes a payload the default holds back",
            message: Message::Put,
            optimization: "message_size_threshold: 1024",
            size: 2048,
            promoted: true,
        },
        PromotionCase {
            what: "a payload exactly at the threshold",
            message: Message::Put,
            optimization: "message_size_threshold: 2048",
            size: 2048,
            promoted: true,
        },
        PromotionCase {
            what: "a threshold of 8192 holds back a payload the default promotes",
            message: Message::Put,
            optimization: "message_size_threshold: 8192",
            size: 4096,
            promoted: false,
        },
    ]);
}

/// THE GATE for `transport/shared_memory/transport_optimization/messages`: a put, the value of a
/// get and a reply are each copied into shared memory when the list names their kind and sent as
/// bytes when it does not, by wz's sender as by the real library's. The threshold is held at 1024
/// in every case, so only the list differs.
// wz-proves: api-compat-c zenoh-c->wz partial
#[test]
#[ignore = "reads a zenoh-c oracle; run by run-ci Layer C1cc (which builds the matching \
            ABI arm this needs)"]
fn the_promoted_messages_list_decides_which_messages_travel_as_shared_memory_on_wz_and_libzenohc() {
    promotion_differential(&[
        PromotionCase {
            what: "no list stated, upstream's put, query and reply: a put",
            message: Message::Put,
            optimization: "message_size_threshold: 1024",
            size: 4096,
            promoted: true,
        },
        PromotionCase {
            what: "a list without put",
            message: Message::Put,
            optimization: r#"message_size_threshold: 1024, messages: ["query", "reply"]"#,
            size: 4096,
            promoted: false,
        },
        PromotionCase {
            what: "a list naming put alone",
            message: Message::Put,
            optimization: r#"message_size_threshold: 1024, messages: ["put"]"#,
            size: 4096,
            promoted: true,
        },
        PromotionCase {
            what: "no list stated, upstream's put, query and reply: a query's value",
            message: Message::Query,
            optimization: "message_size_threshold: 1024",
            size: 4096,
            promoted: true,
        },
        PromotionCase {
            what: "a list without query",
            message: Message::Query,
            optimization: r#"message_size_threshold: 1024, messages: ["put", "reply"]"#,
            size: 4096,
            promoted: false,
        },
        PromotionCase {
            what: "a list naming query alone",
            message: Message::Query,
            optimization: r#"message_size_threshold: 1024, messages: ["query"]"#,
            size: 4096,
            promoted: true,
        },
        PromotionCase {
            what: "no list stated, upstream's put, query and reply: a reply",
            message: Message::Reply,
            optimization: "message_size_threshold: 1024",
            size: 4096,
            promoted: true,
        },
        PromotionCase {
            what: "a list without reply",
            message: Message::Reply,
            optimization: r#"message_size_threshold: 1024, messages: ["put", "query"]"#,
            size: 4096,
            promoted: false,
        },
        PromotionCase {
            what: "a list naming reply alone",
            message: Message::Reply,
            optimization: r#"message_size_threshold: 1024, messages: ["reply"]"#,
            size: 4096,
            promoted: true,
        },
    ]);
}

/// The number of `/dev/shm` objects the maps probe on `probe` reports for a session opened with
/// `shared_memory` (the members of `transport/shared_memory` the document states).
fn mapped_segments(probe: &Built, shared_memory: &str, work: &Path) -> i64 {
    let document = work.join("mode.json5");
    std::fs::write(
        &document,
        format!(
            r#"{{ listen: {{ endpoints: ["tcp/127.0.0.1:0"] }},
  scouting: {{ multicast: {{ enabled: false }} }},
  transport: {{ shared_memory: {{ {shared_memory} }} }} }}"#
        ),
    )
    .expect("write the document");
    let out = Command::new(&probe.exe)
        .arg(document)
        .env("LD_LIBRARY_PATH", &probe.libdir)
        .stderr(Stdio::null())
        .output_bounded()
        .expect("run the maps probe");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "the maps probe exited {:?} with `{shared_memory}`:\n{stdout}",
        out.status.code()
    );
    stdout
        .lines()
        .find_map(|l| l.strip_prefix("segments="))
        .and_then(|n| n.trim().parse().ok())
        .unwrap_or_else(|| panic!("the maps probe printed no count:\n{stdout}"))
}

/// What one library's open maps under `mode: "lazy"`, under `mode: "init"`, and with no mode
/// stated, in that order.
fn segments_by_mode(probe: &Built, work: &Path) -> [i64; 3] {
    [
        mapped_segments(probe, r#"enabled: true, mode: "lazy""#, work),
        mapped_segments(probe, r#"enabled: true, mode: "init""#, work),
        mapped_segments(probe, "enabled: true", work),
    ]
}

/// THE GATE for `transport/shared_memory/mode`: an open told `init` makes the shared-memory
/// subsystem and maps its metadata segment at once, one told `lazy` (or nothing) does not, by wz
/// as by the real library.
// wz-proves: api-compat-c zenoh-c->wz partial
#[test]
#[ignore = "reads a zenoh-c oracle; run by run-ci Layer C1cc (which builds the matching \
            ABI arm this needs)"]
fn the_shared_memory_mode_decides_whether_the_open_maps_the_subsystem_on_wz_and_libzenohc() {
    let Some(include) = oracle_or_note() else {
        return;
    };
    if lacks_the_shm_arm(&include) {
        eprintln!(
            "skip: this zenoh-c oracle is built without Z_FEATURE_SHARED_MEMORY and \
             Z_FEATURE_UNSTABLE_API, where the session has no shared-memory subsystem."
        );
        return;
    }
    assert_zenoh_c_arm_pairing(&include);
    let work = tempfile::tempdir().expect("tempdir for the compiled programs");
    let probe_ref = compile(
        "shm_mode_maps",
        MAPS_PROBE,
        &include,
        work.path(),
        Arm::Reference,
    );
    let probe_wz = compile("shm_mode_maps", MAPS_PROBE, &include, work.path(), Arm::Wz);

    let [ref_lazy, ref_init, ref_silent] = segments_by_mode(&probe_ref, work.path());
    // The ORACLE first: the real library's `init` open must map more than its `lazy` one, and a
    // document that states no mode must be `lazy`, or the difference compared below is not the
    // key's.
    assert!(
        ref_init > ref_lazy,
        "the real library's `init` open mapped {ref_init} segment(s) and its `lazy` open \
         {ref_lazy}, so the subsystem is not visible in the maps here and the key cannot be \
         adjudicated"
    );
    assert_eq!(
        ref_silent, ref_lazy,
        "the real library's open with no mode stated mapped otherwise than its `lazy` open"
    );

    let [wz_lazy, wz_init, wz_silent] = segments_by_mode(&probe_wz, work.path());
    assert_eq!(
        wz_init - wz_lazy,
        ref_init - ref_lazy,
        "§5.27 api-compat-c: the `init` open made a different number of segments on wz \
         ({wz_lazy} -> {wz_init}) than on libzenohc ({ref_lazy} -> {ref_init})"
    );
    assert_eq!(
        wz_silent, wz_lazy,
        "§5.27 api-compat-c: wz's open with no mode stated mapped {wz_silent} segment(s) where \
         its `lazy` open mapped {wz_lazy}; libzenohc maps the same for both"
    );
}
