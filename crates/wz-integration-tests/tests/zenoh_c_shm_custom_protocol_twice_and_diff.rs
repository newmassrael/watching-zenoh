// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.27 `api-compat-c` -- what a SENDER does with a chunk of a shared-memory protocol its
//! receiver may not be able to read, and what a RECEIVER opened over a client storage reads, on
//! wz's cdylib as on the real `libzenohc.so`: one C program per role, compiled once, linked twice,
//! the receivers' output diffed.
//!
//! ## Why this exists
//!
//! A shared-memory descriptor names a chunk; it does not say how to read it. A receiver reads a
//! chunk through the CLIENT its storage holds for the protocol the chunk's header names, and a
//! storage built by default holds one, for POSIX. A receiver that cannot read a protocol
//! therefore says so, in the segment it publishes at establishment: a list of the protocols its
//! reader has a client for. Upstream's sender asks that list for every buffer and sends the
//! buffer's DESCRIPTOR to a peer that lists its protocol and the buffer's BYTES to one that does
//! not. wz asked nothing: it sent the descriptor to every peer that had negotiated shared memory,
//! and a descriptor of a protocol the receiver has no client for is dropped on arrival.
//!
//! ## Measured on the real library before it was a test
//!
//! One C program puts three chunks from a provider of its own, whose backend is a POSIX segment the
//! program created under the protocol id 100500. A receiver whose storage holds a client for that
//! id reads each as shared memory (`shm=yes`). A receiver whose storage is the default, the global
//! one, or no storage at all is delivered the SAME three samples as bytes (`shm=no`, length 64): the
//! sender falls back. On wz the same sender delivered all three to the first receiver and NOTHING
//! to the second while every `z_put` answered success, which is the message lost behind a good
//! return code.
//!
//! ## What is compared
//!
//! For each of five receiver storages (none, the default, the global one, the default beside a
//! client of the program's own, and that client alone, which cannot read POSIX memory) and each of
//! three payloads (a chunk of the custom provider, a chunk of the default provider, plain bytes
//! as the control: the label follows the payload), the rows the receiver prints: what each of
//! three puts, three gets carrying a value and one reply arrived as. The real library's rows are
//! the oracle and are asserted FIRST, against the rule that a chunk arrives as shared memory only
//! where the storage holds a client for its protocol, so a reference that delivered nothing, or
//! that sent a descriptor where it should have sent bytes, makes the equality say nothing.
//!
//! ## The two halves
//!
//! - **The sender half** (R3065): wz's sender against the real library's receivers.
//! - **The receive half** (R3066): the real library's sender against wz's receivers, the program
//!   of which did not link before, because `z_open_with_custom_shm_clients` and
//!   `z_ref_shm_client_storage_global` did not exist. A wz receiver must resolve through the
//!   storage's clients AND publish the storage's protocols, or the real sender sends it bytes it
//!   could have read or descriptors it cannot.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use wz_integration_tests::bounded::BoundedOutput as _;
use wz_integration_tests::common::{
    assert_zenoh_c_arm_pairing, compile_zenoh_c_example, wz_capi_c_cdylib, zenoh_c_oracle,
    zenoh_c_shared_library, PortReservation,
};

/// A sender whose provider is a custom backend over a POSIX object it creates, under protocol
/// 100500. Arguments: the endpoint to dial, the key, the object name, and `chunk` (the custom
/// provider's), `posix` (the default provider's) or `bytes`.
const SENDER: &str = r#"#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "zenoh.h"

#define PROTO 100500u
#define SEG 42u
#define CHUNK 128u
#define NCHUNK 16u

typedef struct {
    uint8_t* base;
    bool busy[NCHUNK];
} ctx_t;

static void delete_fn(void* context) { (void)context; }
static void deref_segment_fn(void* context) { (void)context; }

static void alloc_fn(struct z_owned_chunk_alloc_result_t* result, const struct z_loaned_memory_layout_t* layout,
                     void* context) {
    ctx_t* c = (ctx_t*)context;
    size_t size = 0;
    z_alloc_alignment_t alignment;
    z_memory_layout_get_data(layout, &size, &alignment);
    if (size > CHUNK) {
        z_chunk_alloc_result_new_error(result, Z_ALLOC_ERROR_OUT_OF_MEMORY);
        return;
    }
    for (unsigned i = 0; i < NCHUNK; ++i) {
        if (!c->busy[i]) {
            c->busy[i] = true;
            z_owned_ptr_in_segment_t ptr;
            zc_threadsafe_context_t segment = {{NULL}, &deref_segment_fn};
            z_ptr_in_segment_new(&ptr, c->base + i * CHUNK, segment);
            z_allocated_chunk_t chunk;
            chunk.ptr = z_move(ptr);
            chunk.descriptpr.segment = SEG;
            chunk.descriptpr.chunk = i * CHUNK;
            chunk.descriptpr.len = (uint32_t)size;
            z_chunk_alloc_result_new_ok(result, chunk);
            return;
        }
    }
    z_chunk_alloc_result_new_error(result, Z_ALLOC_ERROR_OUT_OF_MEMORY);
}
static void free_fn(const struct z_chunk_descriptor_t* chunk, void* context) {
    ctx_t* c = (ctx_t*)context;
    c->busy[chunk->chunk / CHUNK] = false;
}
static size_t defragment_fn(void* context) { (void)context; return 0; }
static size_t available_fn(void* context) {
    ctx_t* c = (ctx_t*)context;
    size_t n = 0;
    for (unsigned i = 0; i < NCHUNK; ++i) { if (!c->busy[i]) { n += CHUNK; } }
    return n;
}
static void layout_for_fn(struct z_owned_memory_layout_t* layout, void* context) { (void)layout; (void)context; }
static z_protocol_id_t id_fn(void* context) { (void)context; return PROTO; }

static z_owned_shm_provider_t g_provider;
static int g_as_chunk = 0;

/* A payload carrying `text`: a chunk of the custom provider in `chunk` mode, plain bytes otherwise. */
static int make_payload(z_owned_bytes_t* out, const char* text) {
    if (g_as_chunk) {
        z_buf_layout_alloc_result_t alloc;
        z_shm_provider_alloc_gc_defrag_blocking(&alloc, z_loan(g_provider), 64);
        if (alloc.status != ZC_BUF_LAYOUT_ALLOC_STATUS_OK) { return -1; }
        uint8_t* buf = z_shm_mut_data_mut(z_loan_mut(alloc.buf));
        snprintf((char*)buf, 64, "%s", text);
        z_bytes_from_shm_mut(out, z_move(alloc.buf));
    } else {
        z_bytes_copy_from_str(out, text);
    }
    return 0;
}

/* The sender also ANSWERS: a get on `<key>/r` is replied with a payload made the same way. */
static void on_query(z_loaned_query_t* query, void* arg) {
    (void)arg;
    z_owned_bytes_t payload;
    if (make_payload(&payload, "reply") != 0) { return; }
    z_query_reply(query, z_query_keyexpr(query), z_move(payload), NULL);
}
static void on_reply(z_loaned_reply_t* reply, void* arg) { (void)reply; (void)arg; }
static void on_done(void* arg) { (void)arg; }

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc != 5) { return 2; }
    const char* endpoint = argv[1];
    const char* key = argv[2];
    const char* name = argv[3];
    int posix = strcmp(argv[4], "posix") == 0;
    int as_chunk = strcmp(argv[4], "chunk") == 0 || posix;
    g_as_chunk = as_chunk;

    int fd = shm_open(name, O_CREAT | O_RDWR, 0600);
    if (fd < 0) { printf("shm_open failed\n"); return 3; }
    if (ftruncate(fd, NCHUNK * CHUNK) != 0) { return 3; }
    uint8_t* base = mmap(NULL, NCHUNK * CHUNK, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) { return 3; }
    memset(base, 0, NCHUNK * CHUNK);
    ctx_t ctx;
    ctx.base = base;
    memset(ctx.busy, 0, sizeof ctx.busy);

    zc_context_t context = {&ctx, &delete_fn};
    zc_shm_provider_backend_callbacks_t callbacks = {&alloc_fn, &free_fn, &defragment_fn,
                                                     &available_fn, &layout_for_fn, &id_fn};
    if (posix) {
        /* the default provider: chunks of the POSIX protocol, which a storage built without the
         * default client set cannot read */
        z_shm_provider_default_new(&g_provider, 4096);
    } else {
        z_shm_provider_new(&g_provider, context, callbacks);
    }
    if (!z_internal_check(g_provider)) { printf("provider failed\n"); return 4; }

    z_owned_config_t config;
    z_config_default(&config);
    char connect[512];
    snprintf(connect, sizeof connect, "[\"%s\"]", endpoint);
    zc_config_insert_json5(z_loan_mut(config), Z_CONFIG_CONNECT_KEY, connect);
    zc_config_insert_json5(z_loan_mut(config), Z_CONFIG_MULTICAST_SCOUTING_KEY, "false");
    z_owned_session_t s;
    if (z_open(&s, z_move(config), NULL) < 0) { printf("open failed\n"); return 5; }
    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, key);
    char rkey[256];
    snprintf(rkey, sizeof rkey, "%s/r", key);
    z_view_keyexpr_t rke;
    z_view_keyexpr_from_str(&rke, rkey);
    char qkey[256];
    snprintf(qkey, sizeof qkey, "%s/q", key);
    z_view_keyexpr_t qke;
    z_view_keyexpr_from_str(&qke, qkey);

    z_owned_closure_query_t on_query_cb;
    z_closure(&on_query_cb, on_query, NULL, NULL);
    z_owned_queryable_t queryable;
    if (z_declare_queryable(z_loan(s), &queryable, z_loan(rke), z_move(on_query_cb), NULL) < 0) {
        printf("queryable failed\n");
        return 7;
    }
    z_sleep_ms(1500);

    for (int i = 0; i < 3; ++i) {
        char text[64];
        z_owned_bytes_t payload;
        snprintf(text, sizeof text, "custom-%d", i);
        if (make_payload(&payload, text) != 0) { printf("alloc failed\n"); return 6; }
        int rc = z_put(z_loan(s), z_loan(ke), z_move(payload), NULL);
        printf("put %d rc=%d\n", i, rc);

        /* the same payload kind as the VALUE of a get to the receiver's queryable */
        snprintf(text, sizeof text, "query-%d", i);
        z_owned_bytes_t value;
        if (make_payload(&value, text) != 0) { printf("alloc failed\n"); return 6; }
        z_get_options_t get_opts;
        z_get_options_default(&get_opts);
        get_opts.payload = z_move(value);
        z_owned_closure_reply_t reply_cb;
        z_closure(&reply_cb, on_reply, on_done, NULL);
        rc = z_get(z_loan(s), z_loan(qke), "", z_move(reply_cb), &get_opts);
        printf("get %d rc=%d\n", i, rc);
        z_sleep_ms(500);
    }
    z_sleep_ms(2500);
    z_drop(z_move(queryable));
    z_drop(z_move(s));
    z_drop(z_move(g_provider));
    shm_unlink(name);
    return 0;
}
"#;

/// A receiver that opens with a chosen client storage and prints, for each sample, whether its
/// payload is a shared-memory buffer and what it reads. Arguments: the endpoint to listen on, the
/// key, the object name, the storage (`plain`, `default`, `global`, `custom`, `customonly`) and
/// how many seconds to run.
const RECEIVER: &str = r#"#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "zenoh.h"

#define PROTO 100500u

static char* g_name = NULL;

static void delete_client_fn(void* context) { (void)context; }
static void delete_segment_fn(void* context) { (void)context; }
static uint8_t* map_fn(z_chunk_id_t chunk, void* context) { return (uint8_t*)context + chunk; }
static bool attach_fn(struct z_shm_segment_t* out_segment, z_segment_id_t id, void* context) {
    (void)context;
    (void)id;
    int fd = shm_open(g_name, O_RDWR, 0600);
    if (fd < 0) { return false; }
    uint8_t* base = mmap(NULL, 128 * 16, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (base == MAP_FAILED) { return false; }
    out_segment->context.context.ptr = base;
    out_segment->context.delete_fn = &delete_segment_fn;
    out_segment->callbacks.map_fn = &map_fn;
    return true;
}
static z_protocol_id_t client_id_fn(void* context) { (void)context; return PROTO; }

static void show(const char* what, const z_loaned_bytes_t* payload) {
    const z_loaned_shm_t* shm = NULL;
    int rc = z_bytes_as_loaned_shm(payload, &shm);
    z_owned_string_t text;
    z_bytes_to_string(payload, &text);
    printf("%s: shm=%s len=%zu text=%.*s\n", what, rc == 0 ? "yes" : "no", z_bytes_len(payload),
           (int)z_string_len(z_loan(text)), z_string_data(z_loan(text)));
    z_drop(z_move(text));
}

static void on_sample(z_loaned_sample_t* sample, void* arg) {
    (void)arg;
    show("sample", z_sample_payload(sample));
}

/* A get on `<key>/q` carries a value; print what kind of buffer it arrived as, and answer plainly. */
static void on_query(z_loaned_query_t* query, void* arg) {
    (void)arg;
    const z_loaned_bytes_t* value = z_query_payload(query);
    if (value != NULL) { show("query", value); }
    z_owned_bytes_t ack;
    z_bytes_copy_from_str(&ack, "ack");
    z_query_reply(query, z_query_keyexpr(query), z_move(ack), NULL);
}

/* The receiver asks the sender's queryable once and prints the kind of buffer the reply arrived as. */
static void on_reply(z_loaned_reply_t* reply, void* arg) {
    (void)arg;
    if (z_reply_is_ok(reply)) { show("reply", z_sample_payload(z_reply_ok(reply))); }
}
static void on_done(void* arg) { (void)arg; }

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc != 6) { return 2; }
    const char* endpoint = argv[1];
    const char* key = argv[2];
    g_name = argv[3];
    const char* mode = argv[4];
    int seconds = atoi(argv[5]);

    z_owned_config_t config;
    z_config_default(&config);
    char listen[512];
    snprintf(listen, sizeof listen, "[\"%s\"]", endpoint);
    zc_config_insert_json5(z_loan_mut(config), Z_CONFIG_LISTEN_KEY, listen);
    zc_config_insert_json5(z_loan_mut(config), Z_CONFIG_MULTICAST_SCOUTING_KEY, "false");

    z_owned_session_t s;
    int rc;
    if (strcmp(mode, "plain") == 0) {
        rc = z_open(&s, z_move(config), NULL);
    } else {
        z_owned_shm_client_storage_t storage;
        if (strcmp(mode, "default") == 0) {
            z_shm_client_storage_new_default(&storage);
        } else if (strcmp(mode, "global") == 0) {
            z_ref_shm_client_storage_global(&storage);
        } else {
            zc_owned_shm_client_list_t list;
            zc_shm_client_list_new(&list);
            zc_threadsafe_context_t context = {{NULL}, &delete_client_fn};
            zc_shm_client_callbacks_t callbacks = {&attach_fn, &client_id_fn};
            z_owned_shm_client_t client;
            z_shm_client_new(&client, context, callbacks);
            zc_shm_client_list_add_client(z_loan_mut(list), z_move(client));
            int with_default = strcmp(mode, "custom") == 0;
            if (z_shm_client_storage_new(&storage, z_loan(list), with_default) < 0) { printf("storage failed\n"); return 3; }
            z_drop(z_move(list));
        }
        rc = z_open_with_custom_shm_clients(&s, z_move(config), z_loan(storage));
        z_drop(z_move(storage));
    }
    printf("open rc=%d\n", rc);
    if (rc < 0) { return 4; }

    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, key);
    z_owned_closure_sample_t cb;
    z_closure(&cb, on_sample, NULL, NULL);
    z_owned_subscriber_t sub;
    if (z_declare_subscriber(z_loan(s), &sub, z_loan(ke), z_move(cb), NULL) < 0) { printf("declare failed\n"); return 5; }
    char qkey[256];
    snprintf(qkey, sizeof qkey, "%s/q", key);
    z_view_keyexpr_t qke;
    z_view_keyexpr_from_str(&qke, qkey);
    z_owned_closure_query_t on_query_cb;
    z_closure(&on_query_cb, on_query, NULL, NULL);
    z_owned_queryable_t queryable;
    if (z_declare_queryable(z_loan(s), &queryable, z_loan(qke), z_move(on_query_cb), NULL) < 0) {
        printf("queryable failed\n");
        return 6;
    }
    printf("ready\n");
    /* give the sender time to dial and declare its own queryable, then ask it once */
    z_sleep_ms(3000);
    char rkey[256];
    snprintf(rkey, sizeof rkey, "%s/r", key);
    z_view_keyexpr_t rke;
    z_view_keyexpr_from_str(&rke, rkey);
    z_owned_closure_reply_t reply_cb;
    z_closure(&reply_cb, on_reply, on_done, NULL);
    int get_rc = z_get(z_loan(s), z_loan(rke), "", z_move(reply_cb), NULL);
    printf("get rc=%d\n", get_rc);
    z_sleep_s((size_t)seconds);
    z_drop(z_move(queryable));
    z_drop(z_move(sub));
    z_drop(z_move(s));
    return 0;
}
"#;

const KEY: &str = "demo/example/custom-protocol";

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

fn needs_the_shm_oracle(include: &Path) -> bool {
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

/// Compile `source` as `name` against the arm named by `link` (`wz_capi_c` or `zenohc`) in `libdir`.
fn compile(
    name: &str,
    source: &str,
    include: &Path,
    work: &Path,
    libdir: &Path,
    link: &str,
) -> Result<Built, String> {
    let src_dir = work.join("src");
    std::fs::create_dir_all(&src_dir).expect("source dir");
    std::fs::write(src_dir.join(format!("{name}.c")), source).expect("write the source");
    let out_dir = work.join(link);
    std::fs::create_dir_all(&out_dir).expect("build dir");
    compile_zenoh_c_example(name, &out_dir, include, &src_dir, libdir, link).map(|exe| Built {
        exe,
        libdir: libdir.to_path_buf(),
    })
}

/// One exchange: the receiver listens, the sender dials and puts, and the receiver's printed
/// rows come back. Each exchange has its own port and its own shared-memory object, so
/// exchanges can run side by side.
///
/// The port is RESERVED for the receiver, which listens on it: the reservation is held until the
/// receiver says it has opened (its `open rc=` line, printed after the listener is bound), and
/// no longer, so a sibling exchange or test binary cannot take the number in between.
fn exchange(sender: &Built, receiver: &Built, mode: &str, kind: &str, n: usize) -> Vec<String> {
    let reservation = PortReservation::pick();
    let endpoint = format!("tcp/127.0.0.1:{}", reservation.port());
    let object = format!("/wzc_{}_{n}", std::process::id());
    let mut receiver_child = Command::new(&receiver.exe)
        .args([endpoint.as_str(), KEY, object.as_str(), mode, "7"])
        .env("LD_LIBRARY_PATH", &receiver.libdir)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the receiver");
    let mut lines = BufReader::new(receiver_child.stdout.take().expect("piped stdout")).lines();
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
    let sent = Command::new(&sender.exe)
        .args([endpoint.as_str(), KEY, object.as_str(), kind])
        .env("LD_LIBRARY_PATH", &sender.libdir)
        .stderr(Stdio::null())
        .output_bounded()
        .expect("run the sender");
    assert!(
        sent.status.success(),
        "the sender exited {:?}:\n{}",
        sent.status.code(),
        String::from_utf8_lossy(&sent.stdout)
    );
    // The rest of what the receiver prints, to its end.
    printed.extend(lines.map(|line| line.expect("read the receiver's stdout")));
    receiver_child.wait().expect("the receiver ends");
    // The three kinds of message the receiver prints arrive on their own threads, so the rows
    // are compared sorted: what is compared is WHAT arrived and as which kind of buffer.
    let mut rows: Vec<String> = printed
        .into_iter()
        .filter(|l| l.starts_with("sample:") || l.starts_with("query:") || l.starts_with("reply:"))
        .map(|row| {
            if kind == "posix" {
                without_text(row)
            } else {
                row
            }
        })
        .collect();
    rows.sort();
    rows
}

/// `row` without its ` text=` field. The default provider's chunks are compared by the kind of
/// buffer and its length alone: MEASURED, the REAL library's own rows for them carry an empty text
/// in all but one of twenty-one samples and `custom-1` in that one, so the text is not a thing two
/// runs of the same library agree on, let alone two libraries. The kind and the length are.
fn without_text(row: String) -> String {
    match row.find(" text=") {
        Some(at) => row[..at].to_owned(),
        None => row,
    }
}

/// THE GATE, the sender half: a chunk is delivered to EVERY receiver, as shared memory to one
/// whose storage holds a client for its protocol and as bytes to one whose does not, by wz's
/// sender as by the real library's.
// wz-proves: api-compat-c zenoh-c->wz partial
#[test]
#[ignore = "reads a zenoh-c oracle; run by run-ci Layer C1cc (which builds the matching \
            ABI arm this needs)"]
fn a_chunk_of_a_custom_protocol_is_sent_as_bytes_to_a_receiver_that_cannot_read_it_on_wz_and_libzenohc(
) {
    let Some(include) = oracle_or_note() else {
        return;
    };
    if needs_the_shm_oracle(&include) {
        eprintln!(
            "skip: this zenoh-c oracle is built without Z_FEATURE_SHARED_MEMORY and \
             Z_FEATURE_UNSTABLE_API, where the custom provider and client this reads are not \
             declared."
        );
        return;
    }
    assert_zenoh_c_arm_pairing(&include);
    let work = tempfile::tempdir().expect("tempdir for the compiled programs");

    let reference = zenoh_c_shared_library().expect("the oracle resolved above");
    let ref_libdir = reference.parent().expect("libzenohc.so has a parent");
    let wz_lib = wz_capi_c_cdylib();
    let wz_libdir = wz_lib.parent().expect("cdylib has a parent");

    let sender_ref = compile(
        "custom_sender",
        SENDER,
        &include,
        work.path(),
        ref_libdir,
        "zenohc",
    )
    .unwrap_or_else(|d| panic!("the sender does not link against the REAL libzenohc.so\n{d}"));
    let sender_wz = compile(
        "custom_sender",
        SENDER,
        &include,
        work.path(),
        wz_libdir,
        "wz_capi_c",
    )
    .unwrap_or_else(|d| {
        panic!("§5.27 api-compat-c: the sender does NOT link against wz's cdylib\n{d}")
    });
    // The receivers are the REFERENCE's on both rows: a receiver that is not wz's is the foreign
    // judge of what the sender put on the wire. The receiving half is the next test.
    let receiver = compile(
        "custom_receiver",
        RECEIVER,
        &include,
        work.path(),
        ref_libdir,
        "zenohc",
    )
    .unwrap_or_else(|d| panic!("the receiver does not link against the REAL libzenohc.so\n{d}"));

    let cases = every_case();
    let oracle = run_all(&sender_ref, &receiver, &cases, 0);
    let wz = run_all(&sender_wz, &receiver, &cases, cases.len());
    assert_matches_the_oracle(&cases, &oracle, &wz, "sender");
}

/// The receiver storages and sender kinds every exchange of this file is run over, as `(mode,
/// kind)`: five storages the receiver can open with, and the three payloads the sender can put.
fn every_case() -> Vec<(&'static str, &'static str)> {
    let modes = ["custom", "customonly", "default", "global", "plain"];
    let kinds = ["chunk", "posix", "bytes"];
    modes
        .iter()
        .flat_map(|m| kinds.iter().map(move |k| (*m, *k)))
        .collect()
}

/// How many exchanges run side by side. Each is two processes with a runtime of their own, so
/// "all of them at once" is a load and not a speed-up.
const WIDTH: usize = 10;

/// Run every case once, `WIDTH` at a time, and return each exchange's rows in case order. Every
/// exchange has its own port and shared-memory object, so they cannot meet each other; `base`
/// keeps the objects of separate calls apart.
fn run_all(
    sender: &Built,
    receiver: &Built,
    cases: &[(&'static str, &'static str)],
    base: usize,
) -> Vec<Vec<String>> {
    let mut out: Vec<Vec<String>> = Vec::with_capacity(cases.len());
    for (batch, group) in cases.chunks(WIDTH).enumerate() {
        let rows: Vec<Vec<String>> = std::thread::scope(|scope| {
            let handles: Vec<_> = group
                .iter()
                .enumerate()
                .map(|(i, (mode, kind))| {
                    let n = base + batch * WIDTH + i;
                    scope.spawn(move || exchange(sender, receiver, mode, kind, n))
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().expect("an exchange panicked"))
                .collect()
        });
        out.extend(rows);
    }
    out
}

/// What the REAL library does with a payload, which is the rule both tests compare wz to: shared
/// memory reaches a receiver only if its storage holds a client for the payload's protocol. The
/// custom provider's chunks are protocol 100500, held by the `custom` and `customonly` storages;
/// the default provider's are POSIX, held by every storage but `customonly`; bytes are never
/// shared memory.
fn expected_shm(mode: &str, kind: &str) -> &'static str {
    let held = match kind {
        "chunk" => matches!(mode, "custom" | "customonly"),
        "posix" => mode != "customonly",
        _ => false,
    };
    if held {
        "shm=yes"
    } else {
        "shm=no"
    }
}

/// Assert the real library's rows are the rule, FIRST, and that wz's equal them. `side` names
/// which half was wz's.
fn assert_matches_the_oracle(
    cases: &[(&'static str, &'static str)],
    oracle: &[Vec<String>],
    wz: &[Vec<String>],
    side: &str,
) {
    for (((mode, kind), ref_rows), wz_rows) in cases.iter().zip(oracle).zip(wz) {
        // Three puts, three gets carrying a value, and the one reply to the receiver's get.
        assert_eq!(
            ref_rows.len(),
            7,
            "the real {side}'s {kind} messages did not all reach a `{mode}` receiver: {ref_rows:?}"
        );
        let expected = expected_shm(mode, kind);
        assert!(
            ref_rows.iter().all(|r| r.contains(expected)),
            "the real library's {kind} messages with a `{mode}` receiver were not {expected}: \
             {ref_rows:?}"
        );
        assert_eq!(
            wz_rows, ref_rows,
            "§5.27 api-compat-c: with wz as the {side}, a {kind} put to a `{mode}` receiver was \
             delivered differently from libzenohc.\n--- wz ---\n{wz_rows:#?}\n--- libzenohc \
             ---\n{ref_rows:#?}"
        );
    }
}

/// THE GATE, the other half: a receiver OPENED OVER A CLIENT STORAGE reads what the real library's
/// sender puts, exactly as the real library's receiver does: as shared memory when its storage
/// holds a client for the payload's protocol, as bytes when it does not, and the sender's own
/// choice between the two is made off the list the receiver publishes, so a wz receiver that
/// listed the wrong protocols would be sent bytes it could have read or descriptors it cannot.
///
/// Both receivers are the same C program; only the library differs. The five storages are the
/// five ways a program can open: none, the default, the global one, the default beside a client of
/// its own, and a client of its own alone, which cannot read POSIX memory.
// wz-proves: api-compat-c zenoh-c->wz partial
#[test]
#[ignore = "reads a zenoh-c oracle; run by run-ci Layer C1cc (which builds the matching \
            ABI arm this needs)"]
fn a_receiver_over_a_client_storage_reads_what_the_real_sender_puts_on_wz_and_libzenohc() {
    let Some(include) = oracle_or_note() else {
        return;
    };
    if needs_the_shm_oracle(&include) {
        eprintln!(
            "skip: this zenoh-c oracle is built without Z_FEATURE_SHARED_MEMORY and \
             Z_FEATURE_UNSTABLE_API, where the custom provider and client this reads are not \
             declared."
        );
        return;
    }
    assert_zenoh_c_arm_pairing(&include);
    let work = tempfile::tempdir().expect("tempdir for the compiled programs");
    let reference = zenoh_c_shared_library().expect("the oracle resolved above");
    let ref_libdir = reference.parent().expect("libzenohc.so has a parent");
    let wz_lib = wz_capi_c_cdylib();
    let wz_libdir = wz_lib.parent().expect("cdylib has a parent");

    let sender = compile(
        "custom_sender",
        SENDER,
        &include,
        work.path(),
        ref_libdir,
        "zenohc",
    )
    .unwrap_or_else(|d| panic!("the sender does not link against the REAL libzenohc.so\n{d}"));
    let receiver_ref = compile(
        "custom_receiver",
        RECEIVER,
        &include,
        work.path(),
        ref_libdir,
        "zenohc",
    )
    .unwrap_or_else(|d| panic!("the receiver does not link against the REAL libzenohc.so\n{d}"));
    // THIS is the program that did not link before R3065: it names
    // `z_open_with_custom_shm_clients` and `z_ref_shm_client_storage_global`.
    let receiver_wz = compile(
        "custom_receiver",
        RECEIVER,
        &include,
        work.path(),
        wz_libdir,
        "wz_capi_c",
    )
    .unwrap_or_else(|d| {
        panic!("§5.27 api-compat-c: the receiver does NOT link against wz's cdylib\n{d}")
    });

    let cases = every_case();
    let oracle = run_all(&sender, &receiver_ref, &cases, 0);
    let wz = run_all(&sender, &receiver_wz, &cases, cases.len());
    assert_matches_the_oracle(&cases, &oracle, &wz, "receiver");
}
