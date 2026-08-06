// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.27 `api-compat-pico` — the `source_info` FOREIGN ADJUDICATOR for the
//! SEVEN option structs the put-plane adjudicator does not reach.
//!
//! ## What this closes
//!
//! R311y569 gave the pico ABI's `source_info` its first foreign adjudicator, and
//! that leg drives exactly one of the EIGHT option structs that carry the field:
//! `z_put_options_t`. Its own doc comment says so, and the debt ledger has
//! carried the remainder as "the get / querier / reply folds carry the same
//! field through the same seam and are NOT driven".
//!
//! "Same seam" is a claim, not a measurement. The seven have four different
//! senders and three different readers:
//!
//! | option struct | set by | read by |
//! |---|---|---|
//! | `z_get_options_t` | `z_get` | `z_query_source_info` on the queryable |
//! | `z_querier_get_options_t` | `z_querier_get` | `z_query_source_info` |
//! | `z_query_reply_options_t` | `z_query_reply` | `z_sample_source_info` on `z_reply_ok` |
//! | `z_query_reply_del_options_t` | `z_query_reply_del` | same, on a DELETE reply |
//! | `z_publisher_put_options_t` | `z_publisher_put` | `z_sample_source_info` on a subscriber |
//! | `z_publisher_delete_options_t` | `z_publisher_delete` | same, on a DELETE sample |
//! | `z_delete_options_t` | `z_delete` | same |
//!
//! The put plane's adjudicator cannot speak to any of them: it never constructs
//! a query and never declares a publisher, so `z_query_source_info` and the
//! whole declared-publisher seam are functions it does not call.
//!
//! ## Topology, and why it is the one it is
//!
//! Two sessions in one process over a real TCP link — the put adjudicator's
//! calibrated arrangement — but the two halves of this probe need OPPOSITE
//! directions, and each direction is forced by something measured rather than
//! chosen:
//!
//! - **The query legs** put the QUERYABLE on the listening side and the GET on
//!   the dialling side. One session does not work on this ABI: the oracle build
//!   sets `Z_FEATURE_LOCAL_QUERYABLE 0`
//!   (`target/zenoh-pico-build/zenohpico/include/zenoh-pico/config.h:62`), so a
//!   session's own queryable never sees its own get, and a probe built on it
//!   would block identically on both arms and be reported as agreement.
//! - **The publisher legs** reverse it: the PUBLISHER listens and the SUBSCRIBER
//!   dials. This tree's topology note records the measurement — a DECLARED
//!   publisher that dials out never arms its write filter, so
//!   subscriber-listens + publisher-dials delivers zero samples between two REAL
//!   picos. The put adjudicator gets away with the other direction because
//!   `z_put` declares nothing.
//!
//! Every receive uses a CHANNEL rather than a callback, and everything is
//! received on the main thread. That is what makes the two stdouts
//! line-comparable at all: a callback probe prints from the read task, so the
//! interleaving is a race and the diff would be measuring the scheduler.
//!
//! ## The ANCHORS
//!
//! R311y570's lesson is that a diff gate is an EQUALITY and goes silent when
//! both arms are wrong the same way. So the sn / eid constants this probe
//! carries are asserted line-by-line against BOTH arms individually, from this
//! file — which is outside the C program that prints them — before the two
//! stdouts are compared to each other. An arm that dropped every `source_info`
//! would fail its own anchor rather than diff clean.
//!
//! The `zid` is per-session and cannot match ACROSS arms, so as in the put
//! adjudicator only the round-trip boolean is printed, never the bytes.

use std::path::{Path, PathBuf};
use std::process::Command;

use wz_integration_tests::common::{
    compile_pico_source, wz_capi_pico_cdylib, zenoh_pico_include_dirs, zenoh_pico_library_dir,
    zenoh_pico_shared_library, PortReservation,
};

/// The seven `(eid, sn)` pairs the probe stamps, one per fold. Distinct values
/// per fold on purpose: a seam that carried ONE of them everywhere would diff
/// clean against itself, and these anchors are what make that visible.
const LEG_A_GET: (u32, u32) = (7001, 11001);
const LEG_A_REPLY: (u32, u32) = (7002, 11002);
const LEG_B_QUERIER: (u32, u32) = (7003, 11003);
const LEG_B_REPLY_DEL: (u32, u32) = (7004, 11004);
const LEG_C_PUBLISHER_PUT: (u32, u32) = (7005, 11005);
const LEG_C_PUBLISHER_DELETE: (u32, u32) = (7006, 11006);
const LEG_C_DELETE: (u32, u32) = (7007, 11007);

/// A queryable, a get, a querier get, a reply and a reply-del, each carrying its
/// own `source_info`, read back through the accessor the far side actually has.
///
/// Written here rather than patched into `vendor/zenoh-pico` for the reason the
/// put adjudicator gives: a patched submodule is a reference nobody can trust
/// twice.
///
/// Every `source_info` touch is inside `#ifdef Z_FEATURE_UNSTABLE_API` because
/// that is upstream's own condition — the option FIELDS
/// (`api/types.h:296,398,423,493`) and the two getters
/// (`api/primitives.h:1156,2243`) all sit behind it. Copying the condition
/// rather than inventing one is what keeps this program compilable against a
/// build that turns the flag off.
const PROBE: &str = r#"#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zenoh-pico.h"

/* `key` is `uint8_t`, not `const char *`: pico's config keys are small integer
   constants (`Z_CONFIG_LISTEN_KEY` is `0x42`) and `zp_config_insert` takes a
   `uint8_t`. Typing the parameter as a pointer round-trips only because a
   SysV-x86-64 truncation happens to be lossless for values that small. */
static int open_session(z_owned_session_t *out, uint8_t key, const char *endpoint) {
    z_owned_config_t config;
    z_config_default(&config);
    if (zp_config_insert(z_loan_mut(config), Z_CONFIG_MODE_KEY, "peer") < 0) return -1;
    if (zp_config_insert(z_loan_mut(config), key, endpoint) < 0) return -1;
    if (z_open(out, z_move(config), NULL) < 0) return -1;
    if (zp_start_read_task(z_loan_mut(*out), NULL) < 0) return -1;
    if (zp_start_lease_task(z_loan_mut(*out), NULL) < 0) return -1;
    return 0;
}

#ifdef Z_FEATURE_UNSTABLE_API
/* Print a source info under a tag. `expect_zid` is the zid of the session that
   STAMPED it, which this process knows for both sides because both sessions are
   its own. Only the round-trip boolean is printed: the bytes differ between the
   two arms for the one reason that is not a defect. */
static void print_source_info(const char *tag, const z_source_info_t *info, const z_id_t *expect_zid) {
    if (info == NULL) {
        printf("%s.present=0\n", tag);
        return;
    }
    printf("%s.present=1\n", tag);
    z_entity_global_id_t gid = z_source_info_id(info);
    unsigned sn = (unsigned)z_source_info_sn(info);
    unsigned eid = (unsigned)z_entity_global_id_eid(&gid);
    printf("%s.sn=%u\n", tag, sn);
    printf("%s.eid=%u\n", tag, eid);
    z_id_t got = z_entity_global_id_zid(&gid);
    printf("%s.zid_round_trips=%d\n", tag, memcmp(&got, expect_zid, sizeof *expect_zid) == 0);
}
#endif

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: probe <endpoint>\n"); return 2; }

    /* The QUERYABLE listens and the GET dials -- the same direction the put
       adjudicator uses, and the same reason: this tree's topology note. */
    z_owned_session_t srv;
    if (open_session(&srv, Z_CONFIG_LISTEN_KEY, argv[1]) < 0) { printf("open.srv=FAILED\n"); return 1; }

    z_view_keyexpr_t ke;
    if (z_view_keyexpr_from_str(&ke, "wz/pico/source_info/query") < 0) { printf("keyexpr=FAILED\n"); return 1; }

    z_owned_closure_query_t qclosure;
    z_owned_fifo_handler_query_t qhandler;
    if (z_fifo_channel_query_new(&qclosure, &qhandler, 4) < 0) { printf("query_channel=FAILED\n"); return 1; }
    z_owned_queryable_t qable;
    if (z_declare_queryable(z_loan(srv), &qable, z_loan(ke), z_move(qclosure), NULL) < 0) {
        printf("declare_queryable=FAILED\n"); return 1;
    }

    z_owned_session_t cli;
    if (open_session(&cli, Z_CONFIG_CONNECT_KEY, argv[1]) < 0) { printf("open.cli=FAILED\n"); return 1; }

    z_id_t cli_zid = z_info_zid(z_loan(cli));
    z_id_t srv_zid = z_info_zid(z_loan(srv));

    /* LEG C's subscriber is declared HERE, before either query leg, and that
       placement is the ordering primitive rather than a sleep. cli sends this
       Declare, then legs A and B each complete a full round trip through srv;
       by the time leg A's reply is in hand, srv has processed what cli sent
       before the query. Leg C then declares its publisher against state srv
       already holds, and prints the matching status before publishing so that a
       barrier that did NOT hold fails by name instead of silently delivering
       zero samples. */
    z_view_keyexpr_t pke;
    if (z_view_keyexpr_from_str(&pke, "wz/pico/source_info/pub") < 0) { printf("pub_keyexpr=FAILED\n"); return 1; }
    z_owned_closure_sample_t sclosure;
    z_owned_fifo_handler_sample_t shandler;
    if (z_fifo_channel_sample_new(&sclosure, &shandler, 8) < 0) { printf("sample_channel=FAILED\n"); return 1; }
    z_owned_subscriber_t sub;
    if (z_declare_subscriber(z_loan(cli), &sub, z_loan(pke), z_move(sclosure), NULL) < 0) {
        printf("declare_subscriber=FAILED\n"); return 1;
    }

    /* ================= LEG A: z_get, answered by z_query_reply ============= */
    z_entity_global_id_t get_gid;
    z_result_t get_gid_rc = z_entity_global_id_new(&get_gid, &cli_zid, 7001u);
    printf("legA.gid.rc=%d\n", (int)get_gid_rc);
    z_source_info_t get_info = z_source_info_new(&get_gid, 11001u);

    z_owned_closure_reply_t rclosure;
    z_owned_fifo_handler_reply_t rhandler;
    if (z_fifo_channel_reply_new(&rclosure, &rhandler, 4) < 0) { printf("reply_channel=FAILED\n"); return 1; }

    z_get_options_t gopts;
    z_get_options_default(&gopts);
#ifdef Z_FEATURE_UNSTABLE_API
    gopts.source_info = &get_info;
#endif
    z_result_t get_rc = z_get(z_loan(cli), z_loan(ke), "", z_move(rclosure), &gopts);
    printf("legA.get.rc=%d\n", (int)get_rc);
    if (get_rc < 0) { return 1; }

    z_owned_query_t qa;
    z_result_t qa_rc = z_recv(z_loan(qhandler), &qa);
    printf("legA.query.recv.rc=%d\n", (int)qa_rc);
    if (qa_rc != Z_OK) { return 1; }
    const z_loaned_query_t *lqa = z_loan(qa);
#ifdef Z_FEATURE_UNSTABLE_API
    /* THE GET FOLD's wire claim: the (zid, eid, sn) the GETTER set is what the
       QUERYABLE reads. `z_query_source_info` is the accessor no put-plane probe
       ever calls. */
    const z_source_info_t *qa_info = z_query_source_info(lqa);
    print_source_info("legA.query.source_info", qa_info, &cli_zid);
#endif

    z_entity_global_id_t rep_gid;
    z_result_t rep_gid_rc = z_entity_global_id_new(&rep_gid, &srv_zid, 7002u);
    printf("legA.reply.gid.rc=%d\n", (int)rep_gid_rc);
    z_source_info_t rep_info = z_source_info_new(&rep_gid, 11002u);

    z_owned_bytes_t body;
    z_bytes_copy_from_str(&body, "legA-reply");
    z_query_reply_options_t ropts;
    z_query_reply_options_default(&ropts);
#ifdef Z_FEATURE_UNSTABLE_API
    ropts.source_info = &rep_info;
#endif
    z_result_t reply_rc = z_query_reply(lqa, z_loan(ke), z_move(body), &ropts);
    printf("legA.reply.rc=%d\n", (int)reply_rc);
    z_drop(z_move(qa));

    z_owned_reply_t reply_a;
    z_result_t ra_rc = z_recv(z_loan(rhandler), &reply_a);
    printf("legA.reply.recv.rc=%d\n", (int)ra_rc);
    if (ra_rc == Z_OK) {
        const z_loaned_reply_t *lr = z_loan(reply_a);
        int is_ok = (int)z_reply_is_ok(lr);
        printf("legA.reply.is_ok=%d\n", is_ok);
        if (is_ok) {
            const z_loaned_sample_t *sm = z_reply_ok(lr);
            printf("legA.reply.kind=%d\n", (int)z_sample_kind(sm));
            z_owned_string_t payload;
            z_bytes_to_string(z_sample_payload(sm), &payload);
            printf("legA.reply.payload=%.*s\n",
                   (int)z_string_len(z_loan(payload)), z_string_data(z_loan(payload)));
            z_drop(z_move(payload));
#ifdef Z_FEATURE_UNSTABLE_API
            /* THE REPLY FOLD's wire claim: what the REPLIER stamped is what the
               GETTER reads off the reply's sample. */
            const z_source_info_t *rep_got = z_sample_source_info(sm);
            print_source_info("legA.reply.source_info", rep_got, &srv_zid);
#endif
        }
        z_drop(z_move(reply_a));
    }
    z_drop(z_move(rhandler));

    /* =========== LEG B: z_querier_get, answered by z_query_reply_del ======= */
    z_querier_options_t qropts;
    z_querier_options_default(&qropts);
    z_owned_querier_t querier;
    z_result_t decl_rc = z_declare_querier(z_loan(cli), &querier, z_loan(ke), &qropts);
    printf("legB.declare_querier.rc=%d\n", (int)decl_rc);
    if (decl_rc < 0) { return 1; }

    z_entity_global_id_t qr_gid;
    z_result_t qr_gid_rc = z_entity_global_id_new(&qr_gid, &cli_zid, 7003u);
    printf("legB.gid.rc=%d\n", (int)qr_gid_rc);
    z_source_info_t qr_info = z_source_info_new(&qr_gid, 11003u);

    z_owned_closure_reply_t rclosure2;
    z_owned_fifo_handler_reply_t rhandler2;
    if (z_fifo_channel_reply_new(&rclosure2, &rhandler2, 4) < 0) { printf("reply_channel2=FAILED\n"); return 1; }

    z_querier_get_options_t qgopts;
    z_querier_get_options_default(&qgopts);
#ifdef Z_FEATURE_UNSTABLE_API
    qgopts.source_info = &qr_info;
#endif
    z_result_t qg_rc = z_querier_get(z_loan(querier), "", z_move(rclosure2), &qgopts);
    printf("legB.querier_get.rc=%d\n", (int)qg_rc);
    if (qg_rc < 0) { return 1; }

    z_owned_query_t qb;
    z_result_t qb_rc = z_recv(z_loan(qhandler), &qb);
    printf("legB.query.recv.rc=%d\n", (int)qb_rc);
    if (qb_rc != Z_OK) { return 1; }
    const z_loaned_query_t *lqb = z_loan(qb);
#ifdef Z_FEATURE_UNSTABLE_API
    /* THE QUERIER FOLD: a DIFFERENT option struct than leg A's, reaching the
       same reader. `z_querier_get_options_t` orders `cancellation_token` before
       `source_info` where `z_get_options_t` orders them the other way, so a
       transposition here is exactly the defect class this fold can hide. */
    const z_source_info_t *qb_info = z_query_source_info(lqb);
    print_source_info("legB.query.source_info", qb_info, &cli_zid);
#endif

    z_entity_global_id_t del_gid;
    z_result_t del_gid_rc = z_entity_global_id_new(&del_gid, &srv_zid, 7004u);
    printf("legB.reply_del.gid.rc=%d\n", (int)del_gid_rc);
    z_source_info_t del_info = z_source_info_new(&del_gid, 11004u);

    z_query_reply_del_options_t dopts;
    z_query_reply_del_options_default(&dopts);
#ifdef Z_FEATURE_UNSTABLE_API
    dopts.source_info = &del_info;
#endif
    z_result_t del_rc = z_query_reply_del(lqb, z_loan(ke), &dopts);
    printf("legB.reply_del.rc=%d\n", (int)del_rc);
    z_drop(z_move(qb));

    z_owned_reply_t reply_b;
    z_result_t rb_rc = z_recv(z_loan(rhandler2), &reply_b);
    printf("legB.reply.recv.rc=%d\n", (int)rb_rc);
    if (rb_rc == Z_OK) {
        const z_loaned_reply_t *lr = z_loan(reply_b);
        int is_ok = (int)z_reply_is_ok(lr);
        printf("legB.reply.is_ok=%d\n", is_ok);
        if (is_ok) {
            const z_loaned_sample_t *sm = z_reply_ok(lr);
            /* A reply-DEL is a reply whose sample kind is DELETE. Printed
               because a fold that silently downgraded it to a PUT would still
               carry the source info and diff clean on the source-info lines. */
            printf("legB.reply.kind=%d\n", (int)z_sample_kind(sm));
#ifdef Z_FEATURE_UNSTABLE_API
            const z_source_info_t *del_got = z_sample_source_info(sm);
            print_source_info("legB.reply.source_info", del_got, &srv_zid);
#endif
        }
        z_drop(z_move(reply_b));
    }
    z_drop(z_move(rhandler2));

    /* ======= LEG C: the declared-publisher planes and session delete ======= */
    /* REVERSED direction from legs A and B: the PUBLISHER lives on the LISTENING
       session and the SUBSCRIBER on the DIALLING one. A declared publisher that
       dials out never arms its write filter -- measured between two REAL picos,
       where the obvious arrangement delivers zero samples. */
    z_owned_publisher_t pub;
    z_result_t pub_rc = z_declare_publisher(z_loan(srv), &pub, z_loan(pke), NULL);
    printf("legC.declare_publisher.rc=%d\n", (int)pub_rc);
    if (pub_rc < 0) { return 1; }

    /* The barrier, ASSERTED rather than assumed. If the subscriber's declare had
       not reached srv, this prints 0 and every source-info line below would be
       missing for a routing reason rather than a source-info one. */
    z_matching_status_t match_status;
    z_result_t match_rc = z_publisher_get_matching_status(z_loan(pub), &match_status);
    printf("legC.publisher.matching.rc=%d\n", (int)match_rc);
    printf("legC.publisher.matching=%d\n", (int)match_status.matching);

    z_entity_global_id_t pp_gid;
    z_result_t pp_gid_rc = z_entity_global_id_new(&pp_gid, &srv_zid, 7005u);
    printf("legC.publisher_put.gid.rc=%d\n", (int)pp_gid_rc);
    z_source_info_t pp_info = z_source_info_new(&pp_gid, 11005u);
    z_owned_bytes_t pbody;
    z_bytes_copy_from_str(&pbody, "legC-pub-put");
    z_publisher_put_options_t ppopts;
    z_publisher_put_options_default(&ppopts);
#ifdef Z_FEATURE_UNSTABLE_API
    ppopts.source_info = &pp_info;
#endif
    z_result_t pp_rc = z_publisher_put(z_loan(pub), z_move(pbody), &ppopts);
    printf("legC.publisher_put.rc=%d\n", (int)pp_rc);

    z_owned_sample_t sc1;
    z_result_t sc1_rc = z_recv(z_loan(shandler), &sc1);
    printf("legC.publisher_put.recv.rc=%d\n", (int)sc1_rc);
    if (sc1_rc == Z_OK) {
        const z_loaned_sample_t *sm = z_loan(sc1);
        printf("legC.publisher_put.kind=%d\n", (int)z_sample_kind(sm));
        z_owned_string_t body1;
        z_bytes_to_string(z_sample_payload(sm), &body1);
        printf("legC.publisher_put.payload=%.*s\n",
               (int)z_string_len(z_loan(body1)), z_string_data(z_loan(body1)));
        z_drop(z_move(body1));
#ifdef Z_FEATURE_UNSTABLE_API
        const z_source_info_t *pp_got = z_sample_source_info(sm);
        print_source_info("legC.publisher_put.source_info", pp_got, &srv_zid);
#endif
        z_drop(z_move(sc1));
    }

    z_entity_global_id_t pd_gid;
    z_result_t pd_gid_rc = z_entity_global_id_new(&pd_gid, &srv_zid, 7006u);
    printf("legC.publisher_delete.gid.rc=%d\n", (int)pd_gid_rc);
    z_source_info_t pd_info = z_source_info_new(&pd_gid, 11006u);
    z_publisher_delete_options_t pdopts;
    z_publisher_delete_options_default(&pdopts);
#ifdef Z_FEATURE_UNSTABLE_API
    pdopts.source_info = &pd_info;
#endif
    z_result_t pd_rc = z_publisher_delete(z_loan(pub), &pdopts);
    printf("legC.publisher_delete.rc=%d\n", (int)pd_rc);

    z_owned_sample_t sc2;
    z_result_t sc2_rc = z_recv(z_loan(shandler), &sc2);
    printf("legC.publisher_delete.recv.rc=%d\n", (int)sc2_rc);
    if (sc2_rc == Z_OK) {
        const z_loaned_sample_t *sm = z_loan(sc2);
        printf("legC.publisher_delete.kind=%d\n", (int)z_sample_kind(sm));
#ifdef Z_FEATURE_UNSTABLE_API
        const z_source_info_t *pd_got = z_sample_source_info(sm);
        print_source_info("legC.publisher_delete.source_info", pd_got, &srv_zid);
#endif
        z_drop(z_move(sc2));
    }

    /* The SESSION-level delete: `z_delete_options_t` is its own struct with its
       own field order, and nothing above touches it. */
    z_entity_global_id_t sd_gid;
    z_result_t sd_gid_rc = z_entity_global_id_new(&sd_gid, &srv_zid, 7007u);
    printf("legC.delete.gid.rc=%d\n", (int)sd_gid_rc);
    z_source_info_t sd_info = z_source_info_new(&sd_gid, 11007u);
    z_delete_options_t dlopts;
    z_delete_options_default(&dlopts);
#ifdef Z_FEATURE_UNSTABLE_API
    dlopts.source_info = &sd_info;
#endif
    z_result_t sd_rc = z_delete(z_loan(srv), z_loan(pke), &dlopts);
    printf("legC.delete.rc=%d\n", (int)sd_rc);

    z_owned_sample_t sc3;
    z_result_t sc3_rc = z_recv(z_loan(shandler), &sc3);
    printf("legC.delete.recv.rc=%d\n", (int)sc3_rc);
    if (sc3_rc == Z_OK) {
        const z_loaned_sample_t *sm = z_loan(sc3);
        printf("legC.delete.kind=%d\n", (int)z_sample_kind(sm));
#ifdef Z_FEATURE_UNSTABLE_API
        const z_source_info_t *sd_got = z_sample_source_info(sm);
        print_source_info("legC.delete.source_info", sd_got, &srv_zid);
#endif
        z_drop(z_move(sc3));
    }

    z_drop(z_move(pub));
    z_drop(z_move(sub));
    z_drop(z_move(shandler));
    z_drop(z_move(querier));
    z_drop(z_move(qable));
    z_drop(z_move(qhandler));
    z_drop(z_move(cli));
    z_drop(z_move(srv));
    printf("done\n");
    return 0;
}
"#;

/// Compile once, link twice, run both, return the two stdouts.
fn run_both_arms() -> (String, String) {
    let dir = tempfile::tempdir().expect("tempdir for the compiled probes");
    let src = dir.path().join("wz_pico_source_info_query.c");
    std::fs::write(&src, PROBE).expect("write the probe source");
    let includes = zenoh_pico_include_dirs();

    let cdylib = wz_capi_pico_cdylib();
    let wz_libdir = cdylib.parent().expect("cdylib has a parent").to_path_buf();
    let on_wz = compile_pico_source(&src, dir.path(), &includes, &wz_libdir, "wz_capi_pico")
        .unwrap_or_else(|diag| {
            panic!(
                "§5.27 api-compat-pico: the query-plane source-info probe does NOT link \
                 against wz's pico cdylib. A missing symbol here is a program upstream \
                 can write and wz cannot run.\n{diag}"
            )
        });

    // Through the REGISTERED resolver, not a path join: Layer A4 reads a test's
    // foreign class off the resolver functions its call graph names, so a
    // hand-built path makes the reference arm invisible to the audit even though
    // it links real pico.
    let reference = zenoh_pico_shared_library();
    assert!(
        reference.is_file(),
        "the reference libzenohpico.so vanished between resolution and use"
    );
    let ref_libdir = zenoh_pico_library_dir();
    let ref_dir = dir.path().join("reference");
    std::fs::create_dir_all(&ref_dir).expect("reference build dir");
    let on_ref = compile_pico_source(&src, &ref_dir, &includes, &ref_libdir, "zenohpico")
        .unwrap_or_else(|diag| {
            panic!(
                "the query-plane source-info probe does not link against the REAL \
                 libzenohpico.so\n{diag}"
            )
        });

    let run = |exe: &Path, libdir: &Path| -> (bool, String) {
        // A port EACH, held across the child's whole run: both arms LISTEN, so
        // sharing one would make the second fail to bind for a reason that has
        // nothing to do with either implementation.
        let port = PortReservation::pick();
        let out = Command::new(exe)
            .arg(format!("tcp/127.0.0.1:{}", port.port()))
            .env("LD_LIBRARY_PATH", libdir)
            .output()
            .unwrap_or_else(|why| panic!("spawn {}: {why}", exe.display()));
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
        )
    };
    let (wz_ok, wz_stdout) = run(&on_wz, &wz_libdir);
    let (ref_ok, ref_stdout) = run(&on_ref, &ref_libdir);
    assert!(
        ref_ok,
        "the REFERENCE arm failed, so this machine's oracle cannot serve as one here \
         — the comparison below would be meaningless.\n{ref_stdout}"
    );
    assert!(
        wz_ok,
        "the wz arm exited non-zero. Its stdout up to the failure:\n{wz_stdout}"
    );
    (wz_stdout, ref_stdout)
}

/// The oracle, or `None` with a LOUD note naming what to do about it.
fn oracle_or_note() -> Option<PathBuf> {
    let lib = zenoh_pico_library_dir().join("libzenohpico.so");
    if lib.is_file() {
        return Some(lib);
    }
    eprintln!(
        "skip: the zenoh-pico ORACLE is absent. This leg needs the CMake-built \
         libzenohpico.so and its generated config.h — run \
         scripts/build-zenoh-pico-cli.sh. Hosted CI provisions it before the \
         sweep that runs this, so a skip here is a LOCAL gap, not a passing run."
    );
    None
}

/// Every line this probe MUST print, on EITHER arm, for the diff below to be
/// measuring anything.
///
/// This is the anchor list, and it exists because R311y570 established that a
/// diff gate is an equality: two arms that both dropped `source_info` produce
/// identical stdouts and the diff reports the strongest result this file can
/// give while measuring nothing. Each expectation names a value chosen HERE, in
/// Rust, outside the C program that prints it.
fn anchors() -> Vec<String> {
    let mut want = vec![
        "legA.get.rc=0".to_string(),
        "legA.query.recv.rc=0".to_string(),
        "legA.reply.rc=0".to_string(),
        "legA.reply.is_ok=1".to_string(),
        "legA.reply.payload=legA-reply".to_string(),
        // Z_SAMPLE_KIND_PUT = 0, Z_SAMPLE_KIND_DELETE = 1 (`api/constants.h:165-166`).
        "legA.reply.kind=0".to_string(),
        "legB.declare_querier.rc=0".to_string(),
        "legB.querier_get.rc=0".to_string(),
        "legB.query.recv.rc=0".to_string(),
        "legB.reply_del.rc=0".to_string(),
        "legB.reply.is_ok=1".to_string(),
        "legB.reply.kind=1".to_string(),
        "legC.declare_publisher.rc=0".to_string(),
        // The ordering barrier, asserted: without a match the publisher's write
        // filter drops everything and leg C would report absence as agreement.
        "legC.publisher.matching.rc=0".to_string(),
        "legC.publisher.matching=1".to_string(),
        "legC.publisher_put.rc=0".to_string(),
        "legC.publisher_put.recv.rc=0".to_string(),
        "legC.publisher_put.kind=0".to_string(),
        "legC.publisher_put.payload=legC-pub-put".to_string(),
        "legC.publisher_delete.rc=0".to_string(),
        "legC.publisher_delete.recv.rc=0".to_string(),
        "legC.publisher_delete.kind=1".to_string(),
        "legC.delete.rc=0".to_string(),
        "legC.delete.recv.rc=0".to_string(),
        "legC.delete.kind=1".to_string(),
        "done".to_string(),
    ];
    for (tag, (eid, sn)) in [
        ("legA.query.source_info", LEG_A_GET),
        ("legA.reply.source_info", LEG_A_REPLY),
        ("legB.query.source_info", LEG_B_QUERIER),
        ("legB.reply.source_info", LEG_B_REPLY_DEL),
        ("legC.publisher_put.source_info", LEG_C_PUBLISHER_PUT),
        ("legC.publisher_delete.source_info", LEG_C_PUBLISHER_DELETE),
        ("legC.delete.source_info", LEG_C_DELETE),
    ] {
        want.push(format!("{tag}.present=1"));
        want.push(format!("{tag}.sn={sn}"));
        want.push(format!("{tag}.eid={eid}"));
        want.push(format!("{tag}.zid_round_trips=1"));
    }
    want
}

fn assert_anchored(arm: &str, stdout: &str) {
    let lines: Vec<&str> = stdout.lines().collect();
    let missing: Vec<String> = anchors()
        .into_iter()
        .filter(|want| !lines.iter().any(|line| *line == want.as_str()))
        .collect();
    assert!(
        missing.is_empty(),
        "the {arm} arm is missing {} anchored line(s). An arm that fails its own \
         anchors cannot participate in a diff — two arms that both drop \
         `source_info` produce identical stdouts.\nmissing: {:?}\n--- stdout ---\n{stdout}",
        missing.len(),
        missing,
    );
}

/// THE ADJUDICATOR: `source_info` survives all SEVEN remaining folds — get,
/// querier-get, reply, reply-del, publisher-put, publisher-delete and
/// session-delete — identically on wz's pico ABI and on the real
/// `libzenohpico.so`.
///
/// The reference arm LINKS `libzenohpico.so` itself rather than spawning a pico
/// CLI, so the foreign implementation answers every call the probe makes — the
/// accessors included, not only what reaches the wire.
///
/// Together with R311y569's put-plane leg this covers all eight option structs
/// that carry a `z_source_info_t*` on this ABI (`api/types.h:296,335,359,398,
/// 423,442,457,493`).
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "links the CMake-built libzenohpico.so oracle; run by run-ci Layer E, \
            whose ignored-test sweep carries no --skip token this file matches"]
fn the_remaining_source_info_planes_are_identical_on_wz_and_libzenohpico() {
    if oracle_or_note().is_none() {
        return;
    }
    let (wz_stdout, ref_stdout) = run_both_arms();

    // ANCHORS FIRST, on BOTH arms, and note that the reference arm gets the same
    // treatment as wz: an oracle that silently stopped carrying the field would
    // otherwise turn this file into a tautology.
    assert_anchored("REFERENCE", &ref_stdout);
    assert_anchored("wz", &wz_stdout);

    let wz: Vec<&str> = wz_stdout.lines().collect();
    let reference: Vec<&str> = ref_stdout.lines().collect();
    let mut differing: Vec<String> = Vec::new();
    for (i, expected) in reference.iter().enumerate() {
        match wz.get(i) {
            Some(actual) if actual == expected => {}
            Some(actual) => differing.push(format!("  wz: {actual}\n  ref: {expected}")),
            None => differing.push(format!("  wz: <missing>\n  ref: {expected}")),
        }
    }
    if wz.len() > reference.len() {
        for extra in &wz[reference.len()..] {
            differing.push(format!("  wz: {extra}\n  ref: <missing>"));
        }
    }
    assert!(
        differing.is_empty(),
        "{} of {} probe line(s) differ between wz's pico ABI and the real \
         libzenohpico:\n{}",
        differing.len(),
        reference.len(),
        differing.join("\n")
    );
}
