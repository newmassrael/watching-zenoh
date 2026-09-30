// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.27 `api-compat-pico` — which keyexprs a declaring C program puts on the
//! wire as DECLARATIONS, compiled once against the real zenoh-pico and once
//! against wz, and read off the wire rather than off either library's claim.
//!
//! ## What this exists to catch
//!
//! zenoh-pico 1.10.1 declares a keyexpr for an entity WITHOUT being asked:
//! `_z_declare_publisher` runs `_z_declared_keyexpr_declare` on the publisher's
//! key (`vendor/zenoh-pico/src/net/primitives.c` @
//! `_Z_CLEAN_RETURN_IF_ERR(_z_declared_keyexpr_declare(zn, &publisher->_key, keyexpr),`),
//! the subscriber and the queryable declare the key's NON-WILD PREFIX
//! (`_z_declared_keyexpr_declare_non_wild_prefix`), and `_z_write` then puts the
//! publisher's samples on the declared id rather than the literal
//! (`_z_declared_keyexpr_alias_to_wire`). A program never names any of this, so
//! no upstream example asserts it and the drop-in corpus cannot see it: a wz
//! build that publishes every sample on its literal links, runs and delivers.
//! What differs is the wire, so the wire is what is compared.
//!
//! ## The comparison
//!
//! The SAME driver source is compiled against upstream's headers twice, once
//! linked to the real `libzenohpico.so` and once to wz's cdylib, and each arm
//! dials a wz-ap-demo router through a recording tap. The dialer's half of the
//! recording is dissected and rendered as one line per declaration and per
//! data message, with every id replaced by the order it first appeared in —
//! ids are each library's own counters, so their VALUES cannot agree, while
//! whether a message carries an id, which one, and with what suffix can.
//!
//! The reference arm's content is asserted BEFORE the equality: two empty
//! renderings are equal, and this leg would then be measuring the harness.
//!
//! ## The oracle is a build product
//!
//! `libzenohpico.so` and its headers come from `scripts/build-zenoh-pico-cli.sh`
//! and the router is wz-ap-demo. Absence is a hard FAIL rather than a skip.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use wz_capture::Dissection;
use wz_codecs::declare::DeclareOwnedVariant;
use wz_codecs::wireexpr::{WireexprOwned, WireexprOwnedVariant};
use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, graceful_terminate, read_captured,
    spawn_on_ephemeral_port, wz_ap_demo_binary, wz_capi_pico_cdylib, zenoh_pico_include_dirs,
    zenoh_pico_library_dir,
};
use wz_integration_tests::wire_tap::{synthesise_pcap, tap_proxy};
use wz_session_core::inbound::InboundFrame;
use wz_session_core::network_message::NetworkMessage;
use wz_session_core::passive::{Carried, Direction, PassiveFrame};

/// The synthesised endpoint ports; only their ORDER matters to the dissector,
/// and the dialer's half is found from the handshake rather than from it.
const DIALER_PORT: u16 = 40_000;
const LISTENER_PORT: u16 = 7447;

/// The driver. Every entity kind pico auto-declares for is declared once, in a
/// fixed order with pauses between, so the two arms' renderings line up
/// message for message:
///
/// - a PUBLISHER on a literal key, then one put through it — pico declares the
///   whole key and the put rides the id;
/// - a SUBSCRIBER and a QUERYABLE on wild keys — pico declares the non-wild
///   prefix;
/// - a QUERIER and a liveliness TOKEN on literal keys;
/// - an explicit `z_declare_keyexpr` and a session put through it, the one
///   path wz already aliases, kept as the arms' shared anchor.
///
/// Then everything is undeclared in reverse, so the retractions are compared
/// too.
const DRIVER_SRC: &str = r#"
#include <stdio.h>
#include <string.h>
#include <zenoh-pico.h>

static void on_sample(z_loaned_sample_t *sample, void *ctx) { (void)sample; (void)ctx; }
static void on_query(z_loaned_query_t *query, void *ctx) { (void)query; (void)ctx; }
static void on_reply(z_loaned_reply_t *reply, void *ctx) { (void)reply; (void)ctx; }

static int view(z_view_keyexpr_t *ke, const char *s) {
    if (z_view_keyexpr_from_str(ke, s) < 0) {
        printf("driver: bad keyexpr %s\n", s);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    (void)argc;
    const char *endpoint = argv[1];

    z_owned_config_t config;
    z_config_default(&config);
    zp_config_insert(z_loan_mut(config), Z_CONFIG_MODE_KEY, "@MODE@");
    zp_config_insert(z_loan_mut(config), Z_CONFIG_CONNECT_KEY, endpoint);

    z_owned_session_t s;
    if (z_open(&s, z_move(config), NULL) < 0) {
        printf("driver: unable to open session\n");
        return -1;
    }
    z_sleep_ms(300);

    z_view_keyexpr_t pub_ke, sub_ke, qbl_ke, qry_ke, qry2_ke, tok_ke, lsub_ke, decl_ke;
    if (view(&pub_ke, "demo/kd/pub") < 0 || view(&sub_ke, "demo/kd/sub/**") < 0 ||
        view(&qbl_ke, "demo/kd/qbl/*/x") < 0 || view(&qry_ke, "demo/kd/qry") < 0 ||
        view(&qry2_ke, "demo/kd/qry2") < 0 ||
        view(&tok_ke, "demo/kd/tok") < 0 || view(&lsub_ke, "demo/kd/live/**") < 0 ||
        view(&decl_ke, "demo/kd/decl") < 0) {
        return -1;
    }

    z_owned_publisher_t pub;
    if (z_declare_publisher(z_loan(s), &pub, z_loan(pub_ke), NULL) < 0) {
        printf("driver: publisher failed\n");
        return -1;
    }
    z_sleep_ms(100);
    z_owned_bytes_t payload;
    z_bytes_copy_from_str(&payload, "pub-value");
    if (z_publisher_put(z_loan(pub), z_move(payload), NULL) < 0) {
        printf("driver: publisher put failed\n");
    }
    z_sleep_ms(100);
    if (z_publisher_delete(z_loan(pub), NULL) < 0) {
        printf("driver: publisher delete failed\n");
    }
    z_sleep_ms(100);

    z_owned_closure_sample_t sub_cb;
    z_closure(&sub_cb, on_sample, NULL, NULL);
    z_owned_subscriber_t sub;
    if (z_declare_subscriber(z_loan(s), &sub, z_loan(sub_ke), z_move(sub_cb), NULL) < 0) {
        printf("driver: subscriber failed\n");
        return -1;
    }
    z_sleep_ms(100);

    z_owned_closure_query_t qbl_cb;
    z_closure(&qbl_cb, on_query, NULL, NULL);
    z_owned_queryable_t qbl;
    if (z_declare_queryable(z_loan(s), &qbl, z_loan(qbl_ke), z_move(qbl_cb), NULL) < 0) {
        printf("driver: queryable failed\n");
        return -1;
    }
    z_sleep_ms(100);

    z_owned_querier_t qry;
    if (z_declare_querier(z_loan(s), &qry, z_loan(qry_ke), NULL) < 0) {
        printf("driver: querier failed\n");
        return -1;
    }
    z_sleep_ms(100);
    z_owned_closure_reply_t reply_cb;
    z_closure(&reply_cb, on_reply, NULL, NULL);
    if (z_querier_get(z_loan(qry), NULL, z_move(reply_cb), NULL) < 0) {
        printf("driver: querier get failed\n");
    }
    z_sleep_ms(300);

    /* A querier whose key the router DOES answer for: its write filter opens
       once the router's queryable declaration arrives, so this get goes out
       where the first querier's did not. Without this pair, two arms that both
       sent nothing would compare equal. */
    z_owned_querier_t qry2;
    if (z_declare_querier(z_loan(s), &qry2, z_loan(qry2_ke), NULL) < 0) {
        printf("driver: second querier failed\n");
        return -1;
    }
    z_sleep_ms(400);
    z_owned_closure_reply_t reply2_cb;
    z_closure(&reply2_cb, on_reply, NULL, NULL);
    if (z_querier_get(z_loan(qry2), NULL, z_move(reply2_cb), NULL) < 0) {
        printf("driver: second querier get failed\n");
    }
    z_sleep_ms(300);

    z_owned_closure_sample_t lsub_cb;
    z_closure(&lsub_cb, on_sample, NULL, NULL);
    z_owned_subscriber_t lsub;
    if (z_liveliness_declare_subscriber(z_loan(s), &lsub, z_loan(lsub_ke), z_move(lsub_cb), NULL) < 0) {
        printf("driver: liveliness subscriber failed\n");
        return -1;
    }
    z_sleep_ms(100);

    z_owned_liveliness_token_t tok;
    if (z_liveliness_declare_token(z_loan(s), &tok, z_loan(tok_ke), NULL) < 0) {
        printf("driver: token failed\n");
        return -1;
    }
    z_sleep_ms(100);

    z_owned_keyexpr_t declared;
    if (z_declare_keyexpr(z_loan(s), &declared, z_loan(decl_ke)) < 0) {
        printf("driver: declare keyexpr failed\n");
        return -1;
    }
    z_sleep_ms(100);
    z_owned_bytes_t decl_payload;
    z_bytes_copy_from_str(&decl_payload, "decl-value");
    if (z_put(z_loan(s), z_loan(declared), z_move(decl_payload), NULL) < 0) {
        printf("driver: declared put failed\n");
    }
    z_sleep_ms(100);

    z_undeclare_keyexpr(z_loan(s), z_move(declared));
    z_sleep_ms(100);
    z_drop(z_move(tok));
    z_sleep_ms(100);
    z_drop(z_move(lsub));
    z_sleep_ms(100);
    z_drop(z_move(qry2));
    z_sleep_ms(100);
    z_drop(z_move(qry));
    z_sleep_ms(100);
    z_drop(z_move(qbl));
    z_sleep_ms(100);
    z_drop(z_move(sub));
    z_sleep_ms(100);
    z_drop(z_move(pub));
    z_sleep_ms(300);

    z_drop(z_move(s));
    return 0;
}
"#;

/// One key held by several entities, in the order that shows the resource
/// table's rules: a publisher on a whole key and a keyexpr the program declared
/// itself on the same key, then two subscribers under one non-wild prefix,
/// released so that each key goes with its LAST holder.
///
/// pico keeps its declared keys in a table keyed by the key with a reference
/// count (`vendor/zenoh-pico/src/session/resource.c` @
/// `// declaration of already declared resource`): a key declared again returns
/// the SAME id and bumps the count, yet the declaration goes on the wire again
/// every time (`vendor/zenoh-pico/src/net/primitives.c` @
/// `z_result_t _z_declare_resource(_z_session_t *zn, const _z_string_t *key, uint16_t *out_id) {`
/// sends after registering, duplicate or not), and the key is retracted only
/// when the last holder lets go (`vendor/zenoh-pico/src/session/resource.c` @
/// `_z_resource_slist_value(res_ptr)->_refcount--;`). The advanced publisher and
/// subscriber lean on it: each of their components re-declares the same joined
/// key.
const SHARED_KEYS_DRIVER_SRC: &str = r#"
#include <stdio.h>
#include <string.h>
#include <zenoh-pico.h>

static void on_sample(z_loaned_sample_t *sample, void *ctx) { (void)sample; (void)ctx; }

static int view(z_view_keyexpr_t *ke, const char *s) {
    if (z_view_keyexpr_from_str(ke, s) < 0) {
        printf("driver: bad keyexpr %s\n", s);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    (void)argc;
    const char *endpoint = argv[1];

    z_owned_config_t config;
    z_config_default(&config);
    zp_config_insert(z_loan_mut(config), Z_CONFIG_MODE_KEY, "@MODE@");
    zp_config_insert(z_loan_mut(config), Z_CONFIG_CONNECT_KEY, endpoint);

    z_owned_session_t s;
    if (z_open(&s, z_move(config), NULL) < 0) {
        printf("driver: unable to open session\n");
        return -1;
    }
    z_sleep_ms(300);

    z_view_keyexpr_t whole_ke, prefix_ke;
    if (view(&whole_ke, "demo/kd/shared") < 0 || view(&prefix_ke, "demo/kd/prefix/**") < 0) {
        return -1;
    }

    z_owned_publisher_t pub1;
    if (z_declare_publisher(z_loan(s), &pub1, z_loan(whole_ke), NULL) < 0) {
        printf("driver: publisher failed\n");
        return -1;
    }
    z_sleep_ms(200);
    z_owned_keyexpr_t declared;
    if (z_declare_keyexpr(z_loan(s), &declared, z_loan(whole_ke)) < 0) {
        printf("driver: declare keyexpr failed\n");
        return -1;
    }
    z_sleep_ms(200);

    z_owned_closure_sample_t cb1, cb2;
    z_closure(&cb1, on_sample, NULL, NULL);
    z_closure(&cb2, on_sample, NULL, NULL);
    z_owned_subscriber_t sub1, sub2;
    if (z_declare_subscriber(z_loan(s), &sub1, z_loan(prefix_ke), z_move(cb1), NULL) < 0 ||
        z_declare_subscriber(z_loan(s), &sub2, z_loan(prefix_ke), z_move(cb2), NULL) < 0) {
        printf("driver: subscriber failed\n");
        return -1;
    }
    z_sleep_ms(200);

    /* The declared keyexpr goes first and the publisher second, so the key is
       retracted by its LAST holder (the publisher) and not by the one the
       program named: the declared keyexpr's release must put nothing on the
       wire while the publisher still holds the key. */
    z_undeclare_keyexpr(z_loan(s), z_move(declared));
    z_sleep_ms(150);
    z_drop(z_move(sub1));
    z_sleep_ms(150);
    z_drop(z_move(pub1));
    z_sleep_ms(150);
    z_drop(z_move(sub2));
    z_sleep_ms(300);

    z_drop(z_move(s));
    return 0;
}
"#;

/// Publishers declared with options, and what each one's samples carry.
///
/// pico keeps a publisher's encoding, congestion control, priority, express flag
/// and reliability in the publisher and sends every put and delete with them
/// (`vendor/zenoh-pico/src/net/primitives.c` @
/// `publisher->_congestion_control = congestion_control;`), so the declaration is
/// where they come from and nothing else about a put can supply them. Each of the
/// five is varied ALONE on a publisher of its own, and all of them together on
/// another, so a field wired to the wrong slot shows as a different rendering
/// rather than as the same default twice: a program whose options are all changed
/// at once cannot tell a priority that landed in the congestion bit from one that
/// landed where it belongs.
///
/// The publishers are, in order: everything changed (a put with no encoding of
/// its own, a put with one, a delete); nothing declared (NULL options); the
/// priority alone; express alone; best-effort alone; BLOCK alone; and an encoding
/// with a schema alone (a put with none of its own, a put with one). Then the
/// same options embedded in an ADVANCED publisher, without and with sequence
/// numbers, because pico builds that from a plain publisher declared with them.
const PUBLISHER_OPTIONS_DRIVER_SRC: &str = r#"
#include <stdio.h>
#include <string.h>
#include <zenoh-pico.h>

static int view(z_view_keyexpr_t *ke, const char *s) {
    if (z_view_keyexpr_from_str(ke, s) < 0) {
        printf("driver: bad keyexpr %s\n", s);
        return -1;
    }
    return 0;
}

static int put_text(const z_loaned_publisher_t *pub, const char *text, const char *own_encoding) {
    z_owned_bytes_t payload;
    z_bytes_copy_from_str(&payload, text);
    z_publisher_put_options_t opt;
    z_publisher_put_options_default(&opt);
    z_owned_encoding_t encoding;
    if (own_encoding != NULL) {
        z_encoding_from_str(&encoding, own_encoding);
        opt.encoding = z_move(encoding);
    }
    if (z_publisher_put(pub, z_move(payload), &opt) < 0) {
        printf("driver: put %s failed\n", text);
        return -1;
    }
    z_sleep_ms(150);
    return 0;
}

static int delete_it(const z_loaned_publisher_t *pub, const char *what) {
    if (z_publisher_delete(pub, NULL) < 0) {
        printf("driver: delete %s failed\n", what);
        return -1;
    }
    z_sleep_ms(150);
    return 0;
}

static int declare(const z_loaned_session_t *zs, z_owned_publisher_t *pub, const char *key,
                   const z_publisher_options_t *opt) {
    z_view_keyexpr_t ke;
    if (view(&ke, key) < 0) {
        return -1;
    }
    if (z_declare_publisher(zs, pub, z_loan(ke), opt) < 0) {
        printf("driver: declare %s failed\n", key);
        return -1;
    }
    z_sleep_ms(200);
    return 0;
}

static int adv_put(const ze_loaned_advanced_publisher_t *pub, const char *text, const char *own_encoding) {
    z_owned_bytes_t payload;
    z_bytes_copy_from_str(&payload, text);
    ze_advanced_publisher_put_options_t opt;
    ze_advanced_publisher_put_options_default(&opt);
    z_owned_encoding_t encoding;
    if (own_encoding != NULL) {
        z_encoding_from_str(&encoding, own_encoding);
        opt.put_options.encoding = z_move(encoding);
    }
    if (ze_advanced_publisher_put(pub, z_move(payload), &opt) < 0) {
        printf("driver: advanced put %s failed\n", text);
        return -1;
    }
    z_sleep_ms(150);
    return 0;
}

int main(int argc, char **argv) {
    (void)argc;
    const char *endpoint = argv[1];

    z_owned_config_t config;
    z_config_default(&config);
    zp_config_insert(z_loan_mut(config), Z_CONFIG_MODE_KEY, "@MODE@");
    zp_config_insert(z_loan_mut(config), Z_CONFIG_CONNECT_KEY, endpoint);

    z_owned_session_t s;
    if (z_open(&s, z_move(config), NULL) < 0) {
        printf("driver: unable to open session\n");
        return -1;
    }
    z_sleep_ms(300);
    const z_loaned_session_t *zs = z_loan(s);

    z_owned_publisher_t all, none, prio, express, unreliable, block, enc;
    z_publisher_options_t opt;
    z_owned_encoding_t encoding;

    /* Everything away from the default at once. */
    z_publisher_options_default(&opt);
    z_encoding_from_str(&encoding, "text/plain");
    opt.encoding = z_move(encoding);
    opt.congestion_control = Z_CONGESTION_CONTROL_BLOCK;
    opt.priority = Z_PRIORITY_REAL_TIME;
    opt.is_express = true;
    opt.reliability = Z_RELIABILITY_BEST_EFFORT;
    if (declare(zs, &all, "demo/po/all", &opt) < 0) return -1;
    if (put_text(z_loan(all), "all-plain", NULL) < 0) return -1;
    if (put_text(z_loan(all), "all-own", "application/json") < 0) return -1;
    if (delete_it(z_loan(all), "all") < 0) return -1;

    /* Nothing declared. */
    if (declare(zs, &none, "demo/po/none", NULL) < 0) return -1;
    if (put_text(z_loan(none), "none-plain", NULL) < 0) return -1;
    if (delete_it(z_loan(none), "none") < 0) return -1;

    /* One field at a time. */
    z_publisher_options_default(&opt);
    opt.priority = Z_PRIORITY_BACKGROUND;
    if (declare(zs, &prio, "demo/po/prio", &opt) < 0) return -1;
    if (put_text(z_loan(prio), "prio-plain", NULL) < 0) return -1;
    if (delete_it(z_loan(prio), "prio") < 0) return -1;

    z_publisher_options_default(&opt);
    opt.is_express = true;
    if (declare(zs, &express, "demo/po/express", &opt) < 0) return -1;
    if (put_text(z_loan(express), "express-plain", NULL) < 0) return -1;

    z_publisher_options_default(&opt);
    opt.reliability = Z_RELIABILITY_BEST_EFFORT;
    if (declare(zs, &unreliable, "demo/po/unreliable", &opt) < 0) return -1;
    if (put_text(z_loan(unreliable), "unreliable-plain", NULL) < 0) return -1;
    if (delete_it(z_loan(unreliable), "unreliable") < 0) return -1;

    z_publisher_options_default(&opt);
    opt.congestion_control = Z_CONGESTION_CONTROL_BLOCK;
    if (declare(zs, &block, "demo/po/block", &opt) < 0) return -1;
    if (put_text(z_loan(block), "block-plain", NULL) < 0) return -1;

    z_publisher_options_default(&opt);
    z_encoding_from_str(&encoding, "text/plain;utf-8");
    opt.encoding = z_move(encoding);
    if (declare(zs, &enc, "demo/po/enc", &opt) < 0) return -1;
    if (put_text(z_loan(enc), "enc-plain", NULL) < 0) return -1;
    if (put_text(z_loan(enc), "enc-own", "application/json;v1") < 0) return -1;

    /* The same options, embedded in an advanced publisher. */
    ze_advanced_publisher_options_t adv_opt;
    ze_advanced_publisher_options_default(&adv_opt);
    z_encoding_from_str(&encoding, "text/plain");
    adv_opt.publisher_options.encoding = z_move(encoding);
    adv_opt.publisher_options.congestion_control = Z_CONGESTION_CONTROL_BLOCK;
    adv_opt.publisher_options.priority = Z_PRIORITY_INTERACTIVE_LOW;
    adv_opt.publisher_options.is_express = true;
    adv_opt.publisher_options.reliability = Z_RELIABILITY_BEST_EFFORT;
    z_view_keyexpr_t adv_ke;
    if (view(&adv_ke, "demo/po/adv") < 0) return -1;
    ze_owned_advanced_publisher_t adv;
    if (ze_declare_advanced_publisher(zs, &adv, z_loan(adv_ke), &adv_opt) < 0) {
        printf("driver: advanced publisher failed\n");
        return -1;
    }
    z_sleep_ms(200);
    if (adv_put(ze_advanced_publisher_loan(&adv), "adv-plain", NULL) < 0) return -1;
    if (adv_put(ze_advanced_publisher_loan(&adv), "adv-own", "application/json") < 0) return -1;
    if (ze_advanced_publisher_delete(ze_advanced_publisher_loan(&adv), NULL) < 0) {
        printf("driver: advanced delete failed\n");
        return -1;
    }
    z_sleep_ms(150);

    /* With sequence numbers: the sample the publisher sends carries them and the
       QoS it was declared with. */
    ze_advanced_publisher_options_t seq_opt;
    ze_advanced_publisher_options_default(&seq_opt);
    seq_opt.publisher_options.priority = Z_PRIORITY_DATA_LOW;
    seq_opt.publisher_options.is_express = true;
    seq_opt.sample_miss_detection.is_enabled = true;
    z_view_keyexpr_t seq_ke;
    if (view(&seq_ke, "demo/po/seq") < 0) return -1;
    ze_owned_advanced_publisher_t seq;
    if (ze_declare_advanced_publisher(zs, &seq, z_loan(seq_ke), &seq_opt) < 0) {
        printf("driver: sequenced advanced publisher failed\n");
        return -1;
    }
    z_sleep_ms(200);
    if (adv_put(ze_advanced_publisher_loan(&seq), "seq-plain", NULL) < 0) return -1;

    /* Publisher detection with application metadata: the metadata replaces the
       placeholder chunk at the end of the detection token's key. */
    ze_advanced_publisher_options_t det_opt;
    ze_advanced_publisher_options_default(&det_opt);
    det_opt.publisher_detection = true;
    z_view_keyexpr_t meta_ke;
    if (view(&meta_ke, "meta/data") < 0) return -1;
    det_opt.publisher_detection_metadata = z_loan(meta_ke);
    z_view_keyexpr_t det_ke;
    if (view(&det_ke, "demo/po/detect") < 0) return -1;
    ze_owned_advanced_publisher_t det;
    if (ze_declare_advanced_publisher(zs, &det, z_loan(det_ke), &det_opt) < 0) {
        printf("driver: detecting advanced publisher failed\n");
        return -1;
    }
    z_sleep_ms(200);
    if (adv_put(ze_advanced_publisher_loan(&det), "detect-plain", NULL) < 0) return -1;

    ze_undeclare_advanced_publisher(ze_advanced_publisher_move(&det));
    z_sleep_ms(150);
    ze_undeclare_advanced_publisher(ze_advanced_publisher_move(&seq));
    z_sleep_ms(150);
    ze_undeclare_advanced_publisher(ze_advanced_publisher_move(&adv));
    z_sleep_ms(150);
    z_undeclare_publisher(z_publisher_move(&enc));
    z_undeclare_publisher(z_publisher_move(&block));
    z_undeclare_publisher(z_publisher_move(&unreliable));
    z_undeclare_publisher(z_publisher_move(&express));
    z_undeclare_publisher(z_publisher_move(&prio));
    z_undeclare_publisher(z_publisher_move(&none));
    z_undeclare_publisher(z_publisher_move(&all));
    z_sleep_ms(300);

    z_drop(z_move(s));
    return 0;
}
"#;

/// The advanced PUBLISHER in its three shapes, each with every option that makes
/// pico declare something.
///
/// pico builds an advanced publisher out of its own primitives
/// (`vendor/zenoh-pico/src/api/advanced_publisher.c` @
/// `_Z_RETURN_IF_ERR(z_declare_publisher(zs, &pub->_val._publisher, keyexpr, &opt.publisher_options));`
/// and the cache queryable, liveliness token and beacon publisher that follow),
/// so what it puts on the wire is what those primitives put there. The shapes
/// are the three sequencing modes: miss detection with a heartbeat, publisher
/// detection and a cache (sequence numbers); a cache alone (timestamps); and
/// none of them (a wrapped plain publisher). The heartbeat period is long enough
/// that no beacon goes out inside the leg: it is the DECLARATIONS that are
/// compared, and a beacon's count would only be timing.
///
/// The first publisher puts with an encoding and an attachment, so the put
/// options are read off the wire as well, and the wrapped plain one deletes.
///
/// ⚠ THE DELETE IS ON THE PUBLISHER WITH NO CACHE, and that is upstream's doing,
/// not a choice: zenoh-pico 1.10.1 crashes inside `ze_advanced_publisher_delete`
/// when the publisher has a cache — `_z_publisher_delete_impl` copies the Del
/// into the cache through `_z_sample_copy_data`, which copies an encoding the
/// delete path never set (a NULL dereference in `_z_encoding_copy`, measured
/// under gdb against the pinned library). A program that does it segfaults on
/// the reference, so the reference cannot be the oracle for it, and wz does not
/// copy a crash. A cached delete's replay is held by the runtime's own tests.
const ADVANCED_PUBLISHER_DRIVER_SRC: &str = r#"
#include <stdio.h>
#include <string.h>
#include <zenoh-pico.h>

static int view(z_view_keyexpr_t *ke, const char *s) {
    if (z_view_keyexpr_from_str(ke, s) < 0) {
        printf("driver: bad keyexpr %s\n", s);
        return -1;
    }
    return 0;
}

static int put_plain(const ze_loaned_advanced_publisher_t *pub, const char *text) {
    z_owned_bytes_t payload;
    z_bytes_copy_from_str(&payload, text);
    if (ze_advanced_publisher_put(pub, z_move(payload), NULL) < 0) {
        printf("driver: advanced put %s failed\n", text);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    (void)argc;
    const char *endpoint = argv[1];

    z_owned_config_t config;
    z_config_default(&config);
    zp_config_insert(z_loan_mut(config), Z_CONFIG_MODE_KEY, "@MODE@");
    zp_config_insert(z_loan_mut(config), Z_CONFIG_CONNECT_KEY, endpoint);

    z_owned_session_t s;
    if (z_open(&s, z_move(config), NULL) < 0) {
        printf("driver: unable to open session\n");
        return -1;
    }
    z_sleep_ms(300);

    z_view_keyexpr_t full_ke, plain_ke, cache_ke;
    if (view(&full_ke, "demo/kd/apub") < 0 || view(&plain_ke, "demo/kd/apub_plain") < 0 ||
        view(&cache_ke, "demo/kd/apub_cache") < 0) {
        return -1;
    }

    ze_advanced_publisher_options_t full_opt;
    ze_advanced_publisher_options_default(&full_opt);
    full_opt.cache.is_enabled = true;
    full_opt.cache.max_samples = 2;
    full_opt.sample_miss_detection.is_enabled = true;
    full_opt.sample_miss_detection.heartbeat_mode = ZE_ADVANCED_PUBLISHER_HEARTBEAT_MODE_PERIODIC;
    full_opt.sample_miss_detection.heartbeat_period_ms = 600000;
    full_opt.publisher_detection = true;
    ze_owned_advanced_publisher_t full;
    if (ze_declare_advanced_publisher(z_loan(s), &full, z_loan(full_ke), &full_opt) < 0) {
        printf("driver: full advanced publisher failed\n");
        return -1;
    }
    z_sleep_ms(300);

    if (put_plain(ze_advanced_publisher_loan(&full), "adv-value") < 0) {
        return -1;
    }
    z_sleep_ms(200);

    ze_advanced_publisher_put_options_t put_opt;
    ze_advanced_publisher_put_options_default(&put_opt);
    z_owned_encoding_t encoding;
    z_encoding_from_str(&encoding, "text/plain");
    z_owned_bytes_t attachment;
    z_bytes_copy_from_str(&attachment, "meta");
    put_opt.put_options.encoding = z_move(encoding);
    put_opt.put_options.attachment = z_move(attachment);
    z_owned_bytes_t second;
    z_bytes_copy_from_str(&second, "adv-value-2");
    if (ze_advanced_publisher_put(ze_advanced_publisher_loan(&full), z_move(second), &put_opt) < 0) {
        printf("driver: advanced put with options failed\n");
        return -1;
    }
    z_sleep_ms(200);

    /* No cache, no miss detection, no detection: a wrapped plain publisher. */
    ze_advanced_publisher_options_t plain_opt;
    ze_advanced_publisher_options_default(&plain_opt);
    ze_owned_advanced_publisher_t plain;
    if (ze_declare_advanced_publisher(z_loan(s), &plain, z_loan(plain_ke), &plain_opt) < 0) {
        printf("driver: plain advanced publisher failed\n");
        return -1;
    }
    z_sleep_ms(200);
    if (put_plain(ze_advanced_publisher_loan(&plain), "plain-value") < 0) {
        return -1;
    }
    z_sleep_ms(200);
    if (ze_advanced_publisher_delete(ze_advanced_publisher_loan(&plain), NULL) < 0) {
        printf("driver: advanced delete failed\n");
        return -1;
    }
    z_sleep_ms(200);

    /* A cache and nothing else: samples carry timestamps and no sequence. */
    ze_advanced_publisher_options_t cache_opt;
    ze_advanced_publisher_options_default(&cache_opt);
    ze_advanced_publisher_cache_options_default(&cache_opt.cache);
    cache_opt.cache.max_samples = 1;
    ze_owned_advanced_publisher_t cached;
    if (ze_declare_advanced_publisher(z_loan(s), &cached, z_loan(cache_ke), &cache_opt) < 0) {
        printf("driver: cached advanced publisher failed\n");
        return -1;
    }
    z_sleep_ms(200);
    if (put_plain(ze_advanced_publisher_loan(&cached), "cache-value") < 0) {
        return -1;
    }
    z_sleep_ms(200);

    /* In the reverse of the order they were made, so a key shared between the
       entities of one publisher is retracted by the last of them. */
    ze_undeclare_advanced_publisher(ze_advanced_publisher_move(&cached));
    z_sleep_ms(200);
    ze_undeclare_advanced_publisher(ze_advanced_publisher_move(&plain));
    z_sleep_ms(200);
    ze_undeclare_advanced_publisher(ze_advanced_publisher_move(&full));
    z_sleep_ms(300);

    z_drop(z_move(s));
    return 0;
}
"#;

/// The advanced SUBSCRIBER in three shapes, each with every option that makes
/// pico declare something.
///
/// pico builds an advanced subscriber out of its own primitives
/// (`vendor/zenoh-pico/src/api/advanced_subscriber.c` @
/// `_Z_CLEAN_RETURN_IF_ERR(z_declare_subscriber(zs, &sub->_val._subscriber, keyexpr,`
/// and the history query, late-publisher liveliness subscriber, heartbeat
/// subscriber and detection token that follow), so what it puts on the wire is
/// what those primitives put there, in THAT order — the heartbeat subscription
/// comes after the history query and the late-publisher subscription, not before.
///
/// The shapes are everything at once on a key that ends in a wildcard (so the
/// declared prefix is shorter than the key); the live subscription alone, on a
/// key with no wildcard; and history plus detection with a wildcard in the MIDDLE
/// of the key and a metadata suffix on the detection token. Nothing publishes: it
/// is the DECLARATIONS that are compared.
const ADVANCED_SUBSCRIBER_DRIVER_SRC: &str = r#"
#include <stdio.h>
#include <string.h>
#include <zenoh-pico.h>

static void on_sample(z_loaned_sample_t *sample, void *ctx) { (void)sample; (void)ctx; }

static int view(z_view_keyexpr_t *ke, const char *s) {
    if (z_view_keyexpr_from_str(ke, s) < 0) {
        printf("driver: bad keyexpr %s\n", s);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    (void)argc;
    const char *endpoint = argv[1];

    z_owned_config_t config;
    z_config_default(&config);
    zp_config_insert(z_loan_mut(config), Z_CONFIG_MODE_KEY, "@MODE@");
    zp_config_insert(z_loan_mut(config), Z_CONFIG_CONNECT_KEY, endpoint);

    z_owned_session_t s;
    if (z_open(&s, z_move(config), NULL) < 0) {
        printf("driver: unable to open session\n");
        return -1;
    }
    z_sleep_ms(300);

    z_view_keyexpr_t full_ke, plain_ke, middle_ke, meta_ke;
    if (view(&full_ke, "demo/kd/asub/**") < 0 || view(&plain_ke, "demo/kd/asub_plain") < 0 ||
        view(&middle_ke, "demo/kd/*/asub_middle") < 0 || view(&meta_ke, "info") < 0) {
        return -1;
    }

    /* Everything: live, history, late publishers, heartbeat recovery, detection. */
    ze_advanced_subscriber_options_t full_opt;
    ze_advanced_subscriber_options_default(&full_opt);
    full_opt.history.is_enabled = true;
    full_opt.history.detect_late_publishers = true;
    full_opt.history.max_samples = 2;
    full_opt.recovery.is_enabled = true;
    full_opt.recovery.last_sample_miss_detection.is_enabled = true;
    full_opt.recovery.last_sample_miss_detection.periodic_queries_period_ms = 0;
    full_opt.subscriber_detection = true;
    z_owned_closure_sample_t full_cb;
    z_closure(&full_cb, on_sample, NULL, NULL);
    ze_owned_advanced_subscriber_t full;
    if (ze_declare_advanced_subscriber(z_loan(s), &full, z_loan(full_ke), z_move(full_cb),
                                       &full_opt) < 0) {
        printf("driver: full advanced subscriber failed\n");
        return -1;
    }
    z_sleep_ms(300);

    /* Nothing but the live subscription: a wrapped plain subscriber. */
    ze_advanced_subscriber_options_t plain_opt;
    ze_advanced_subscriber_options_default(&plain_opt);
    z_owned_closure_sample_t plain_cb;
    z_closure(&plain_cb, on_sample, NULL, NULL);
    ze_owned_advanced_subscriber_t plain;
    if (ze_declare_advanced_subscriber(z_loan(s), &plain, z_loan(plain_ke), z_move(plain_cb),
                                       &plain_opt) < 0) {
        printf("driver: plain advanced subscriber failed\n");
        return -1;
    }
    z_sleep_ms(200);

    /* History and detection, no recovery; a wildcard in the middle of the key. */
    ze_advanced_subscriber_options_t middle_opt;
    ze_advanced_subscriber_options_default(&middle_opt);
    middle_opt.history.is_enabled = true;
    middle_opt.subscriber_detection = true;
    middle_opt.subscriber_detection_metadata = z_loan(meta_ke);
    z_owned_closure_sample_t middle_cb;
    z_closure(&middle_cb, on_sample, NULL, NULL);
    ze_owned_advanced_subscriber_t middle;
    if (ze_declare_advanced_subscriber(z_loan(s), &middle, z_loan(middle_ke), z_move(middle_cb),
                                       &middle_opt) < 0) {
        printf("driver: middle advanced subscriber failed\n");
        return -1;
    }
    z_sleep_ms(300);

    /* In the reverse of the order they were made, so a key shared between the
       entities of one subscriber is retracted by the last of them. */
    ze_undeclare_advanced_subscriber(ze_advanced_subscriber_move(&middle));
    z_sleep_ms(200);
    ze_undeclare_advanced_subscriber(ze_advanced_subscriber_move(&plain));
    z_sleep_ms(200);
    ze_undeclare_advanced_subscriber(ze_advanced_subscriber_move(&full));
    z_sleep_ms(300);

    z_drop(z_move(s));
    return 0;
}
"#;

/// Which C program a leg compiles against both libraries.
#[derive(Clone, Copy, Debug)]
enum Program {
    /// The plain entities: publisher, subscriber, queryable, queriers, token,
    /// liveliness subscriber and a declared keyexpr ([`DRIVER_SRC`]).
    Entities,
    /// One key held by several entities ([`SHARED_KEYS_DRIVER_SRC`]).
    SharedKeys,
    /// The advanced publisher in its three shapes
    /// ([`ADVANCED_PUBLISHER_DRIVER_SRC`]).
    AdvancedPublisher,
    /// The advanced subscriber in its three shapes
    /// ([`ADVANCED_SUBSCRIBER_DRIVER_SRC`]).
    AdvancedSubscriber,
    /// Publishers declared with options, plain and advanced
    /// ([`PUBLISHER_OPTIONS_DRIVER_SRC`]).
    PublisherOptions,
}

impl Program {
    fn name(self) -> &'static str {
        match self {
            Program::Entities => "entities",
            Program::SharedKeys => "shared_keys",
            Program::AdvancedPublisher => "advanced_publisher",
            Program::AdvancedSubscriber => "advanced_subscriber",
            Program::PublisherOptions => "publisher_options",
        }
    }

    fn source(self) -> &'static str {
        match self {
            Program::Entities => DRIVER_SRC,
            Program::SharedKeys => SHARED_KEYS_DRIVER_SRC,
            Program::AdvancedPublisher => ADVANCED_PUBLISHER_DRIVER_SRC,
            Program::AdvancedSubscriber => ADVANCED_SUBSCRIBER_DRIVER_SRC,
            Program::PublisherOptions => PUBLISHER_OPTIONS_DRIVER_SRC,
        }
    }

    /// How much of a data message the rendering carries. The plain entities
    /// publish nothing whose content is in question, and their legs have always
    /// compared the KEY a message names; the advanced publisher's samples carry
    /// the options it sequences and retains, and those are what it is for. A
    /// publisher declared with options is measured by the QoS its samples are
    /// SENT with, which is on the message's envelope and on the channel it rides.
    fn push_detail(self) -> PushDetail {
        match self {
            Program::PublisherOptions => PushDetail::Qos,
            Program::AdvancedPublisher => PushDetail::Whole,
            Program::Entities | Program::SharedKeys | Program::AdvancedSubscriber => {
                PushDetail::Key
            }
        }
    }
}

/// How much of a Push the rendering carries — see [`Program::push_detail`].
#[derive(Clone, Copy, Debug)]
enum PushDetail {
    /// The key it names.
    Key,
    /// The key, the kind, the envelope, and what the body carries.
    Whole,
    /// [`Self::Whole`], with the VALUE of each envelope extension (the QoS byte:
    /// priority, the no-drop bit and the express bit) and the channel the
    /// message rode: the transport frame's reliability and its priority.
    Qos,
}

/// Compile the program against upstream's headers, linked to `lib`. Only the
/// library differs between the arms, which is the whole point.
fn compile_driver(
    out_dir: &Path,
    libdir: &Path,
    libname: &str,
    arm: &str,
    topology: Topology,
    program: Program,
) -> PathBuf {
    let tag = format!("{arm}_{}_{}", topology.name(), program.name());
    let src = out_dir.join(format!("driver_{tag}.c"));
    std::fs::write(
        &src,
        program.source().replace("@MODE@", topology.session_mode()),
    )
    .expect("write driver source");
    let exe = out_dir.join(format!("driver_{tag}"));

    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
    let mut cmd = Command::new(&cc);
    cmd.arg(&src).arg("-DZENOH_LINUX");
    for inc in zenoh_pico_include_dirs() {
        cmd.arg(format!("-I{}", inc.display()));
    }
    cmd.arg("-o")
        .arg(&exe)
        .arg(format!("-L{}", libdir.display()))
        .arg(format!("-l{libname}"))
        .arg(format!("-Wl,-rpath,{}", libdir.display()));

    let out = cmd.output().expect("spawn C compiler");
    assert!(
        out.status.success(),
        "{arm} arm failed to build against {libname}:\n--- stderr ---\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    exe
}

/// What the driver's session is, and what it dials.
///
/// zenoh-pico asks for a keyexpr's peers differently by mode, and by WHAT its
/// peer is: a client always asks (`_z_add_interest` @ `if (zn->_mode ==
/// Z_WHATAMI_CLIENT || _z_session_has_router_peer(zn)`), a peer asks only when
/// one of its peers announced itself a router, and a peer whose peers are all
/// peers sends no Interest at all and reads what they push. wz's write filter
/// implements the same three branches, so each one needs its own measurement
/// against the real library.
#[derive(Clone, Copy, Debug)]
enum Topology {
    /// A client session dialling a wz node: the arm this file first measured.
    Client,
    /// A peer session dialling a wz ROUTER (`WhatAmI::Router` on the wire).
    PeerToRouter,
    /// A peer session dialling a wz PEER: no router peer, so no Interest.
    PeerToPeer,
}

impl Topology {
    fn name(self) -> &'static str {
        match self {
            Topology::Client => "client",
            Topology::PeerToRouter => "peer_to_router",
            Topology::PeerToPeer => "peer_to_peer",
        }
    }

    /// The `Z_CONFIG_MODE_KEY` value of the driver's own session.
    fn session_mode(self) -> &'static str {
        match self {
            Topology::Client => "client",
            Topology::PeerToRouter | Topology::PeerToPeer => "peer",
        }
    }

    /// The entities the far side declares: a subscriber on everything under
    /// `demo/`, which is what opens the publisher's write filter, and a
    /// queryable on ONE key the driver's second querier names, which is what
    /// opens that querier's.
    const ENTITIES: [&'static str; 6] = [
        "--key",
        "demo/**",
        "--queryable",
        "demo/kd/qry2",
        "--reply",
        "kd",
    ];

    /// The wz node the driver dials, as a demo argv.
    fn demo_args(self) -> Vec<&'static str> {
        // `--listen` is the default build's acceptor, and it announces
        // `WhatAmI::Peer` (`demo_session_init_params`, `NodeKind::Acceptor`), so
        // it is the peer a peer session has no router among. `--router` needs the
        // `routing-routes` feature and announces `WhatAmI::Router`.
        match self {
            Topology::Client | Topology::PeerToPeer => ["--listen", "127.0.0.1:0"]
                .into_iter()
                .chain(Self::ENTITIES)
                .collect(),
            // A router hosts no entities of its own: what it tells a peer is
            // what ANOTHER face declared, so the entities ride a provider node
            // behind it ([`Self::provider_args`]).
            Topology::PeerToRouter => vec!["--router", "127.0.0.1:0"],
        }
    }

    /// The node that declares [`Self::ENTITIES`] behind a router, when the
    /// dialed node cannot: its argv after `--connect <router>`.
    fn provider_args(self) -> Option<Vec<&'static str>> {
        match self {
            Topology::PeerToRouter => Some(Self::ENTITIES.to_vec()),
            Topology::Client | Topology::PeerToPeer => None,
        }
    }
}

/// A wz node that connects to `router_addr` and declares `entities`, held
/// until its guard drops. Returns once both declarations have gone out and the
/// router has held the face.
fn spawn_provider(
    demo: &Path,
    router_addr: &str,
    entities: &[&str],
    router_log: &mut std::fs::File,
) -> wz_integration_tests::common::ChildGuard {
    let stderr = tempfile::tempfile().expect("tempfile for provider stderr");
    let writer = stderr.try_clone().expect("dup provider stderr handle");
    let mut reader = stderr;
    let mut guard = wz_integration_tests::common::ChildGuard::wrap(
        "wz-ap-demo (provider behind the router)",
        Command::new(demo)
            .arg("--connect")
            .arg(router_addr)
            .args(entities)
            .env("RUST_LOG", "info")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::from(writer))
            .spawn()
            .expect("spawn the provider"),
    );
    for needle in ["DECLARED ROUTED SUBSCRIBER", "DECLARED ROUTED QUERYABLE"] {
        if let Err(captured) = wz_integration_tests::common::wait_for_substring(
            &mut reader,
            needle,
            Duration::from_secs(10),
        ) {
            let _ = guard.child_mut().kill();
            panic!("the provider never logged `{needle}`:\n{captured}");
        }
    }
    if let Err(captured) = wz_integration_tests::common::wait_for_substring(
        router_log,
        "face 0 UP",
        Duration::from_secs(10),
    ) {
        let _ = guard.child_mut().kill();
        panic!("the router never held the provider's face:\n{captured}");
    }
    // The router records the declarations when its own poll of the face yields
    // them, which is asynchronous to the provider logging that it sent them
    // (the same allowance `wz_router_forward` makes). Waiting on a router log
    // line would be waiting on one it does not write.
    std::thread::sleep(Duration::from_millis(500));
    guard
}

/// Run one arm against a fresh wz node behind a tap and return the recording.
fn record_arm(
    driver: &Path,
    arm: &str,
    topology: Topology,
) -> Vec<(wz_integration_tests::wire_tap::Side, Vec<u8>)> {
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let demo_stderr = tempfile::tempfile().expect("tempfile for router stderr");
    let (mut router, mut router_log, router_port) = spawn_on_ephemeral_port(
        &demo,
        &topology.demo_args(),
        "listening on 127.0.0.1:",
        "wz-ap-demo (node behind the tap)",
        demo_stderr,
    );
    // Before the tap, so the provider dials the node directly and its own
    // handshake is not in the recording: the recording is the DRIVER's.
    let provider = topology.provider_args().map(|entities| {
        spawn_provider(
            &demo,
            &format!("127.0.0.1:{router_port}"),
            &entities,
            &mut router_log,
        )
    });
    let (proxy_port, recording) = tap_proxy(router_port);

    let mut capture = tempfile::tempfile().expect("the driver capture");
    let status = Command::new(driver)
        .arg(format!("tcp/127.0.0.1:{proxy_port}"))
        .stdout(capture.try_clone().expect("dup stdout handle"))
        .stderr(capture.try_clone().expect("dup stderr handle"))
        .status()
        .unwrap_or_else(|e| panic!("{arm}: failed to run the driver: {e}"));
    assert!(
        status.success(),
        "{arm}: the driver exited {status:?}\n--- its stdout+stderr ---\n{}",
        read_captured(&mut capture)
    );
    if let Some(mut provider) = provider {
        graceful_terminate(provider.child_mut(), Duration::from_secs(5));
    }
    graceful_terminate(router.child_mut(), Duration::from_secs(5));
    // Let the relay threads see EOF before the recording is read.
    std::thread::sleep(Duration::from_millis(200));
    let segments = recording.lock().expect("recording lock").clone();
    assert!(
        !segments.is_empty(),
        "{arm}: the tap recorded nothing, so every assertion below would hold of \
         an empty capture"
    );
    segments
}

/// The direction the DIALER wrote: the one that opened with an `InitSyn`.
///
/// Derived from the handshake rather than from the synthesised port order, so
/// a change in how the pcap assigns directions reds here by name instead of
/// silently rendering the router's half.
fn dialer_direction(frames: &[&PassiveFrame]) -> Direction {
    let first_init = frames.iter().find_map(|f| match &f.frame {
        Ok(InboundFrame::Init { is_ack, .. }) => Some((f.direction, *is_ack)),
        _ => None,
    });
    match first_init {
        Some((direction, false)) => direction,
        Some((_, true)) => panic!("the first Init in the capture is an InitAck"),
        None => panic!("the capture carries no Init, so there is no handshake to orient by"),
    }
}

/// Stable names for each library's own counters, in first-seen order.
#[derive(Default)]
struct Names {
    ids: BTreeMap<(&'static str, u64), usize>,
}

impl Names {
    fn name(&mut self, space: &'static str, id: u64) -> String {
        let next = self.ids.iter().filter(|((s, _), _)| *s == space).count() + 1;
        let n = *self.ids.entry((space, id)).or_insert(next);
        format!("{space}{n}")
    }
}

/// The `@adv` detection keys carry the declaring session's zid and the entity's
/// id: `<key>/@adv/pub/<zid>/<eid>/_`. Both values are each library's own
/// counters (a random zid per session, an entity id from its own allocator), so
/// their VALUES cannot agree between the arms while their SHAPE can — the zid is
/// hex (`ZenohId`'s display drops one leading zero, so 31 or 32 digits) and the
/// entity id is a number — and the shape is what is compared. A segment that
/// does not have the shape is left as it is, so a key spelled wrongly still
/// shows.
fn normalize_adv_key(key: &str) -> String {
    let mut out = key.to_owned();
    for marker in ["/@adv/pub/", "/@adv/sub/"] {
        let Some(at) = out.find(marker) else {
            continue;
        };
        let head = out[..at + marker.len()].to_owned();
        let tail = out[at + marker.len()..].to_owned();
        let mut parts: Vec<String> = tail.split('/').map(str::to_owned).collect();
        if parts.first().is_some_and(|z| {
            (31..=32).contains(&z.len()) && z.chars().all(|c| c.is_ascii_hexdigit())
        }) {
            parts[0] = String::from("<zid>");
        }
        if parts
            .get(1)
            .is_some_and(|e| !e.is_empty() && e.chars().all(|c| c.is_ascii_digit()))
        {
            parts[1] = String::from("<eid>");
        }
        out = format!("{head}{}", parts.join("/"));
    }
    out
}

/// A wire expression as `<id>+"suffix"`, the id named in the keyexpr space.
fn wire(names: &mut Names, expr: &WireexprOwned) -> String {
    let (id, suffix) = match &expr.body {
        WireexprOwnedVariant::WireexprNonlocal(w) => {
            (w.id, w.suffix.as_ref().map(|s| s.to_string()))
        }
        WireexprOwnedVariant::WireexprLocal(w) => (w.id, w.suffix.as_ref().map(|s| s.to_string())),
    };
    let scope = if id == 0 {
        String::from("literal")
    } else {
        names.name("K", id)
    };
    format!(
        "{scope}+{:?}",
        normalize_adv_key(&suffix.unwrap_or_default())
    )
}

/// An extension chain as the header of each entry, plus a zbuf's LENGTH.
///
/// An undeclaration may carry the retracted key as a wire-expression extension
/// (pico's `_z_make_undecl_token(id, &wireexpr)`). Its bytes hold an id, whose
/// value cannot agree between the arms, so the length is rendered instead: it
/// still tells a literal suffix from an aliased one.
fn extensions(chain: Option<&[wz_codecs::ext_entry::ExtEntryOwned]>) -> String {
    use wz_codecs::ext_entry::ExtEntryOwnedVariant;
    let Some(chain) = chain else {
        return String::new();
    };
    let parts: Vec<String> = chain
        .iter()
        .map(|e| match &e.body {
            ExtEntryOwnedVariant::CodecZenohExtZbuf(z) => {
                format!("{:#04x}:zbuf[{}]", e.header, z.value_len)
            }
            _ => format!("{:#04x}", e.header),
        })
        .collect();
    if parts.is_empty() {
        String::new()
    } else {
        format!(" ext({})", parts.join(","))
    }
}

/// The extensions a Put or a Del carries inside its body, by identity.
///
/// The source info names the publisher by its session's zid and its entity id,
/// neither of which can agree between two libraries' sessions, so it is rendered
/// as present and no more; the attachment is the caller's own bytes, and every
/// other extension is named by its header.
fn body_extensions(chain: Option<&[wz_codecs::ext_entry::ExtEntryOwned]>) -> String {
    use wz_codecs::ext_entry::ExtEntryOwnedVariant;
    const SOURCE_INFO: u8 = 0x01;
    let Some(chain) = chain else {
        return String::from(" ext()");
    };
    let parts: Vec<String> = chain
        .iter()
        .map(|e| match &e.body {
            ExtEntryOwnedVariant::CodecZenohExtZbuf(z) if e.header & 0x1f == SOURCE_INFO => {
                let _ = z;
                format!("{:#04x}:source-info", e.header)
            }
            ExtEntryOwnedVariant::CodecZenohExtZbuf(z) => format!(
                "{:#04x}:{:?}",
                e.header,
                String::from_utf8_lossy(z.value.as_slice())
            ),
            _ => format!("{:#04x}", e.header),
        })
        .collect();
    format!(" ext({})", parts.join(","))
}

/// An extension chain as `extensions` renders it, with the VALUE of each integer
/// extension after its header: the QoS byte of a data message's envelope is one
/// (`0x01` for the id, `0x20` for the integer form; bits 0-2 the priority, bit 3
/// the no-drop flag that BLOCK sets, bit 4 the express flag).
fn valued_extensions(chain: Option<&[wz_codecs::ext_entry::ExtEntryOwned]>) -> String {
    use wz_codecs::ext_entry::ExtEntryOwnedVariant;
    let Some(chain) = chain else {
        return String::new();
    };
    let parts: Vec<String> = chain
        .iter()
        .map(|e| match &e.body {
            ExtEntryOwnedVariant::CodecZenohExtZint(z) => {
                format!("{:#04x}={:#04x}", e.header, z.value)
            }
            ExtEntryOwnedVariant::CodecZenohExtZbuf(z) => {
                format!("{:#04x}:zbuf[{}]", e.header, z.value_len)
            }
            _ => format!("{:#04x}", e.header),
        })
        .collect();
    if parts.is_empty() {
        String::new()
    } else {
        format!(" ext({})", parts.join(","))
    }
}

/// A data message whole: its envelope, its kind, whether it carries a timestamp
/// (its VALUE is each session's own clock and zid), its encoding, what its body
/// carries, and its payload. With `valued`, the envelope's integer extensions
/// carry their values ([`valued_extensions`]).
fn push_whole(p: &wz_codecs::push::PushOwned, valued: bool) -> String {
    use wz_codecs::push::PushOwnedVariant;
    let envelope = if valued {
        valued_extensions(p.extensions.as_deref())
    } else {
        extensions(p.extensions.as_deref())
    };
    let body = match &p.body {
        PushOwnedVariant::CodecZenohMsgPut(put) => format!(
            " put ts={} enc={} body{} payload={:?}",
            put.timestamp.is_some(),
            put.encoding.as_ref().map_or_else(
                || String::from("none"),
                |e| format!(
                    "{}+{:?}",
                    e.packed_id,
                    e.schema.as_ref().map(|s| s.to_string())
                )
            ),
            body_extensions(put.extensions.as_deref()),
            String::from_utf8_lossy(put.payload.as_slice()),
        ),
        PushOwnedVariant::CodecZenohMsgDel(del) => format!(
            " del ts={} body{}",
            del.timestamp.is_some(),
            body_extensions(del.extensions.as_deref())
        ),
        PushOwnedVariant::Default { tag, .. } => format!(" unknown-body {tag:#04x}"),
    };
    format!("{envelope}{body}")
}

/// One line per declaration and per data message the dialer sent, in order.
fn render(
    segments: &[(wz_integration_tests::wire_tap::Side, Vec<u8>)],
    detail: PushDetail,
) -> (Vec<String>, Vec<(u8, u8)>) {
    let pcap = synthesise_pcap(segments, DIALER_PORT, LISTENER_PORT);
    let dissection = Dissection::from_pcap(&pcap).expect("the synthesised pcap parses");
    let flows = dissection.flows();
    assert_eq!(
        flows.len(),
        1,
        "one relayed connection is one flow; got {}",
        flows.len()
    );
    let frames: Vec<&PassiveFrame> = flows[0].frames.iter().collect();
    let dialer = dialer_direction(&frames);
    let mut names = Names::default();
    let mut lines = Vec::new();
    let mut interest_headers = Vec::new();
    for frame in frames.iter().filter(|f| f.direction == dialer) {
        let Carried::Batch(batch) = &frame.carried else {
            continue;
        };
        // The channel a data message rode: the transport frame's reliability and
        // its priority. A batch never mixes them, so the message inherits its
        // frame's.
        let channel = match &frame.frame {
            Ok(InboundFrame::Frame {
                reliable, priority, ..
            }) => format!(
                "[{} p{}]",
                if *reliable { "reliable" } else { "best-effort" },
                priority.wire_byte()
            ),
            _ => String::from("[not a frame]"),
        };
        for message in &batch.messages {
            match message {
                NetworkMessage::Declare(d) => {
                    let line = match &d.body {
                        DeclareOwnedVariant::CodecZenohDeclKexpr(k) => {
                            let id = names.name("K", k.id);
                            format!("DeclKexpr {id} = {}", wire(&mut names, &k.keyexpr))
                        }
                        DeclareOwnedVariant::CodecZenohUndeclKexpr(k) => format!(
                            "UndeclKexpr {}{}",
                            names.name("K", k.id),
                            extensions(k.extensions.as_deref())
                        ),
                        DeclareOwnedVariant::CodecZenohDeclSubscriber(e) => format!(
                            "DeclSubscriber {} on {}{}",
                            names.name("S", e.id),
                            wire(&mut names, &e.keyexpr),
                            extensions(e.extensions.as_deref())
                        ),
                        DeclareOwnedVariant::CodecZenohUndeclSubscriber(e) => format!(
                            "UndeclSubscriber {}{}",
                            names.name("S", e.id),
                            extensions(e.extensions.as_deref())
                        ),
                        DeclareOwnedVariant::CodecZenohDeclQueryable(e) => format!(
                            "DeclQueryable {} on {}{}",
                            names.name("Q", e.id),
                            wire(&mut names, &e.keyexpr),
                            extensions(e.extensions.as_deref())
                        ),
                        DeclareOwnedVariant::CodecZenohUndeclQueryable(e) => format!(
                            "UndeclQueryable {}{}",
                            names.name("Q", e.id),
                            extensions(e.extensions.as_deref())
                        ),
                        DeclareOwnedVariant::CodecZenohDeclToken(e) => format!(
                            "DeclToken {} on {}{}",
                            names.name("T", e.id),
                            wire(&mut names, &e.keyexpr),
                            extensions(e.extensions.as_deref())
                        ),
                        DeclareOwnedVariant::CodecZenohUndeclToken(e) => format!(
                            "UndeclToken {}{}",
                            names.name("T", e.id),
                            extensions(e.extensions.as_deref())
                        ),
                        // A final closes an interest reply; it names no keyexpr.
                        DeclareOwnedVariant::CodecZenohDeclFinal(_) => continue,
                        DeclareOwnedVariant::Default { tag, .. } => {
                            format!("Declare(unknown tag {tag:#04x})")
                        }
                    };
                    lines.push(line);
                }
                NetworkMessage::Push(p) => {
                    let key = wire(&mut names, &p.keyexpr);
                    lines.push(match detail {
                        PushDetail::Key => format!("Push on {key}"),
                        PushDetail::Whole => format!("Push on {key}{}", push_whole(p, false)),
                        PushDetail::Qos => {
                            format!("Push on {key} {channel}{}", push_whole(p, true))
                        }
                    });
                }
                NetworkMessage::Request(r) => {
                    lines.push(format!("Request on {}", wire(&mut names, &r.keyexpr)))
                }
                // The interest's own id is each library's counter; what is
                // compared is the key it names, and whether it names one, and
                // its OPTION BITS — the current/future flags on the header and
                // the kinds/restricted/aggregate bits on the body, which is
                // where a client's interest differs from a peer's.
                //
                // The header's Z bit (an extension chain follows) is left OUT
                // of the rendering and pinned on its own, by
                // [`INTEREST_EXTENSION_BIT`].
                //
                // It is NAMED in first-seen order all the same, and the name is
                // carried onto the Final that retracts it, so a reading can say
                // WHICH interest was retracted — the peer arms need that, since
                // a pico peer retracts some of its interests and not others.
                NetworkMessage::Interest(i) => {
                    let name = names.name("I", i.interest_id);
                    lines.push(match &i.body {
                        Some(body) => {
                            // A Final has no body and, in both libraries, no
                            // extension chain, so only the others are pinned.
                            interest_headers.push((i.header, body.header));
                            let key = match body.keyexpr.as_ref() {
                                Some(k) => wire(&mut names, k),
                                None => String::from("(no key)"),
                            };
                            format!(
                                "Interest hdr={:#04x} body={:#04x} on {key} as {name}",
                                i.header & !INTEREST_EXTENSION_BIT,
                                body.header
                            )
                        }
                        None => format!("Interest (final) {name}"),
                    })
                }
                _ => {}
            }
        }
    }
    (lines, interest_headers)
}

/// The Z bit of a network message's header: an extension chain follows.
///
/// PINNED rather than masked away, because it is a real byte-level difference
/// and hiding it would make this leg say more than it measured. zenoh-pico's
/// Interests carry no extension. wz's WRITE-FILTER Interests carry none either
/// (header `0x79`, byte for byte pico's), but its LIVELINESS-subscriber Interest
/// stamps the QoS envelope (`0xd9`) as zenoh's session does. Both readings are
/// asserted below, so either side changing reds this leg by name. It is the
/// ENVELOPE's question — which bytes an implementation wraps a message in — and
/// not this leg's, which is about WHICH keys go on the wire; a pico peer decodes
/// wz's liveliness interests (`apfull_*_pico_interop`), so the difference is not
/// an interop break.
const INTEREST_EXTENSION_BIT: u8 = 0x80;

/// The `T` (TOKENS) kind bit of an Interest body header: the liveliness plane.
const INTEREST_BODY_TOKENS: u8 = 0x08;

/// What one topology's two arms put on the wire, rendered.
struct Arms {
    wz: Vec<String>,
    wz_interest_headers: Vec<(u8, u8)>,
    reference: Vec<String>,
    reference_interest_headers: Vec<(u8, u8)>,
}

/// Compile the driver once per library, run each through its own tap to a
/// fresh wz node of `topology`'s kind, and render what each dialer sent.
fn record_both_arms(topology: Topology, program: Program) -> Arms {
    let dir = tempfile::tempdir().expect("tempdir");
    let cdylib = wz_capi_pico_cdylib();
    let wz_libdir = cdylib
        .parent()
        .expect("cdylib has a parent directory")
        .to_path_buf();

    let wz_driver = compile_driver(
        dir.path(),
        &wz_libdir,
        "wz_capi_pico",
        "wz",
        topology,
        program,
    );
    let ref_driver = compile_driver(
        dir.path(),
        &zenoh_pico_library_dir(),
        "zenohpico",
        "reference",
        topology,
        program,
    );

    let detail = program.push_detail();
    let (reference, reference_interest_headers) =
        render(&record_arm(&ref_driver, "reference", topology), detail);
    let (wz, wz_interest_headers) = render(&record_arm(&wz_driver, "wz", topology), detail);
    Arms {
        wz,
        wz_interest_headers,
        reference,
        reference_interest_headers,
    }
}

/// wz's drop-in declares, and aliases, exactly the keyexprs the real zenoh-pico
/// does for the same program.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "cc-compiles a driver against both libraries and runs each through a \
            tap to a wz-ap-demo router; run by run-ci Layer E"]
fn a_declaring_program_puts_the_same_declarations_on_the_wire_as_the_real_pico() {
    let Arms {
        wz,
        wz_interest_headers,
        reference,
        reference_interest_headers,
    } = record_both_arms(Topology::Client, Program::Entities);

    // ANTI-VACUITY: the reference arm must carry the explicit declaration, the
    // put through it, and one declaration per entity the driver made. Two
    // renderings missing all of them are equal and prove nothing.
    for needle in [
        "DeclKexpr",
        "DeclSubscriber",
        "DeclQueryable",
        "DeclToken",
        "UndeclKexpr",
    ] {
        assert!(
            reference.iter().any(|l| l.starts_with(needle)),
            "the REFERENCE arm carries no `{needle}` line, so this leg is \
             measuring the harness rather than wz:\n{}",
            reference.join("\n")
        );
    }
    assert!(
        reference.iter().filter(|l| l.starts_with("Push")).count() >= 2,
        "the REFERENCE arm should carry the publisher's put and the declared \
         put:\n{}",
        reference.join("\n")
    );

    // The Z-bit pin (see [`INTEREST_EXTENSION_BIT`]): both readings, so a change
    // on either side is a finding and not an unread mask.
    assert!(
        !reference_interest_headers.is_empty()
            && reference_interest_headers
                .iter()
                .all(|(header, _)| header & INTEREST_EXTENSION_BIT == 0),
        "the real pico's Interests should carry no extension chain: {reference_interest_headers:02x?}"
    );
    assert!(
        wz_interest_headers
            .iter()
            .any(|(_, body)| body & INTEREST_BODY_TOKENS != 0),
        "wz's arm carries no liveliness Interest, so the pin below is vacuous: {wz_interest_headers:02x?}"
    );
    assert!(
        wz_interest_headers.iter().all(|(header, body)| {
            (header & INTEREST_EXTENSION_BIT != 0) == (body & INTEREST_BODY_TOKENS != 0)
        }),
        "wz's Interests should carry the QoS envelope on the liveliness one and only \
         there: {wz_interest_headers:02x?}"
    );

    // The write filter's two halves, in the REFERENCE arm, so equality below
    // cannot be two arms that both stayed silent: an Interest on the
    // publisher's own key and on each querier's, and one Query that WENT OUT
    // (the second querier's, whose key the router answers for) beside one that
    // did not (the first's, which nothing answers).
    for needle in ["Interest hdr=0x79 body=0xd3", "Interest hdr=0x79 body=0xd5"] {
        assert!(
            reference.iter().any(|l| l.starts_with(needle)),
            "the REFERENCE arm carries no `{needle}` line, so the write filter \
             is not in this leg:\n{}",
            reference.join("\n")
        );
    }
    assert_eq!(
        reference
            .iter()
            .filter(|l| l.starts_with("Request"))
            .count(),
        1,
        "the REFERENCE arm should send exactly the matched querier's Query and \
         suppress the unmatched one's:\n{}",
        reference.join("\n")
    );

    // A CLIENT retracts its subscriber and its queryable by id alone. The peer
    // arms below pin the other form, so each pin is a measurement of its own
    // mode and neither can pass on the other's frames.
    for exact in ["UndeclSubscriber S1", "UndeclQueryable Q1"] {
        assert!(
            reference.iter().any(|l| l == exact),
            "the REFERENCE arm has no id-only `{exact}`, so a client no longer retracts \
             by id alone:\n{}",
            reference.join("\n")
        );
    }

    // Everything, in wire order, whole: which keys are declared, on which ids,
    // with which suffix, which Interests are asked and retracted, which Query
    // is sent and which is not, and what is retracted in which order — for a
    // publisher, a subscriber, a queryable, two queriers, a token, a
    // liveliness subscriber and a keyexpr the program declared itself.
    assert_eq!(
        wz,
        reference,
        "wz's declarations differ from the real zenoh-pico's for the same \
         program.\n--- wz ---\n{}\n--- reference ---\n{}",
        wz.join("\n"),
        reference.join("\n")
    );
}

/// The Request line the renderer prints for a query on `literal`: the driver
/// declares each querier's key before it asks, and the renderer names a key by
/// the order its declaration appeared, so the name is read off that line.
fn request_on(lines: &[String], literal: &str) -> Option<String> {
    let suffix = format!("= literal+{literal:?}");
    lines.iter().find_map(|l| {
        let named = l.strip_prefix("DeclKexpr ")?.strip_suffix(&suffix)?;
        Some(format!("Request on {}+\"\"", named.trim_end()))
    })
}

/// The names of the Interests a line list asked FOR AN ENTITY, in the order
/// they were asked: every Interest whose body does not carry the liveliness
/// kind bit. Each is paired with its body header.
fn entity_interests(lines: &[String]) -> Vec<(String, u8)> {
    lines
        .iter()
        .filter_map(|l| {
            let rest = l.strip_prefix("Interest hdr=")?;
            let body = rest.split("body=").nth(1)?.get(..4)?;
            let body = u8::from_str_radix(body.trim_start_matches("0x"), 16).ok()?;
            let name = l.rsplit(" as ").next()?.to_owned();
            (body & INTEREST_BODY_TOKENS == 0).then_some((name, body))
        })
        .collect()
}

/// One measurement of a PEER session, in whichever topology, against the real
/// zenoh-pico: what wz puts on the wire must equal what the real library puts,
/// bar the two things named below, each of which is asserted to be exactly as
/// large as it is claimed to be.
///
/// ## Two divergences, both upstream's, both wz doing LESS
///
/// Neither is reproduced, on the same ground: a program cannot observe either,
/// and reproducing them would copy a defect rather than a behaviour.
///
/// 1. **A Query nothing answers is not sent.** A pico peer creates a write
///    filter through `_z_interest_replay_declare`, which replays every
///    declaration the session already holds against the new filter WITHOUT
///    regard to kind, so a subscriber the peer declared opens a QUERIER's
///    filter (`vendor/zenoh-pico/src/session/interest.c` @
///    `msg.type = _Z_INTEREST_MSG_TYPE_DECL_SUBSCRIBER;` beside
///    `_z_write_filter_callback`, which handles subscriber and queryable
///    declarations in one arm). The replay is kind-blind only for a peer: a
///    client's interest is AGGREGATE, and an aggregate replay matches on key
///    equality instead of intersection. wz opens a querier's filter on
///    queryables only, as zenoh does, so the first querier's Query — whose key
///    intersects a peer's subscriber and no queryable — stays unsent. The
///    querier is answered `Z_OK` with no reply either way.
/// 2. **A peer's entity interests are retracted.** A pico peer that asked never
///    sends `Interest(Final)` for a publisher's or querier's interest
///    (`vendor/zenoh-pico/src/net/primitives.c` @ `_z_remove_interest`, which
///    sends it for a client or multicast only), so a router keeps them until the
///    session closes. wz retracts them. Only a router is asked, so the
///    divergence is measured only where one exists.
fn assert_a_peer_puts_the_same_wire_as_the_real_pico(topology: Topology) {
    let Arms { wz, reference, .. } = record_both_arms(topology, Program::Entities);
    let show = || {
        format!(
            "--- wz ---\n{}\n--- reference ---\n{}",
            wz.join("\n"),
            reference.join("\n")
        )
    };

    // ANTI-VACUITY: the entities are in the reference, and so are the pushes.
    for needle in [
        "DeclKexpr",
        "DeclSubscriber",
        "DeclQueryable",
        "DeclToken",
        "UndeclKexpr",
    ] {
        assert!(
            reference.iter().any(|l| l.starts_with(needle)),
            "the REFERENCE arm carries no `{needle}` line, so this leg is \
             measuring the harness rather than wz:\n{}",
            reference.join("\n")
        );
    }
    assert!(
        reference.iter().filter(|l| l.starts_with("Push")).count() >= 2,
        "the REFERENCE arm should carry the publisher's put and the declared put:\n{}",
        reference.join("\n")
    );

    // A peer retracts a subscriber and a queryable NAMING THE KEY, where a
    // client retracts by id alone (pinned in the client leg above). The two
    // bodies' lengths differ because the subscriber is held on its non-wild
    // prefix and the queryable on its own.
    for prefix in [
        "UndeclSubscriber S1 ext(0x5f:zbuf[",
        "UndeclQueryable Q1 ext(0x5f:zbuf[",
    ] {
        assert!(
            reference.iter().any(|l| l.starts_with(prefix)),
            "the REFERENCE arm has no `{prefix}` line, so a peer no longer names its \
             key when it retracts:\n{}",
            reference.join("\n")
        );
    }

    // What the peer ASKS, by topology, in the reference and then as wz. An
    // Interest asked for an entity carries the current/future flags on its
    // header and, on its body, the kind and the aggregate bit; a client's is
    // `0xd3` / `0xd5` (pinned above) and a peer's is the same with the aggregate
    // bit (0x80) clear.
    let asked = entity_interests(&reference);
    match topology {
        Topology::PeerToPeer => assert!(
            asked.is_empty(),
            "a pico peer with no router among its peers asks nothing for its \
             entities, yet it asked {asked:?}:\n{}",
            reference.join("\n")
        ),
        Topology::PeerToRouter => assert_eq!(
            asked.iter().map(|(_, body)| *body).collect::<Vec<_>>(),
            [0x53, 0x55, 0x55],
            "a pico peer beside a router asks for the publisher's subscribers and for \
             each querier's queryables, WITHOUT the aggregate bit:\n{}",
            reference.join("\n")
        ),
        Topology::Client => unreachable!("the client leg is measured above"),
    }

    // Divergence 1, pinned from both sides. The Query of the querier whose key
    // no queryable holds goes out from the real library and does not from wz;
    // the other querier's goes out from both.
    let unmatched = request_on(&reference, "demo/kd/qry")
        .unwrap_or_else(|| panic!("no declaration of the first querier's key:\n{}", show()));
    let matched = request_on(&reference, "demo/kd/qry2")
        .unwrap_or_else(|| panic!("no declaration of the second querier's key:\n{}", show()));
    assert!(
        reference.contains(&unmatched) && reference.contains(&matched),
        "the REFERENCE arm should send both Queries: a peer's replay opens a \
         querier's filter on a subscriber it already holds:\n{}",
        show()
    );
    assert!(
        wz.contains(&matched) && !wz.contains(&unmatched),
        "wz should send the matched querier's Query and not the unmatched one's:\n{}",
        show()
    );
    let mut expected: Vec<String> = reference.clone();
    expected.retain(|l| *l != unmatched);
    assert_eq!(
        expected.len() + 1,
        reference.len(),
        "the unsent Query is exactly one line:\n{}",
        show()
    );

    // Divergence 2, pinned from both sides. Take out of wz's list the Finals it
    // sent for entity interests; what remains must be what the real library
    // sent, and the real library sent none of them.
    let entity_finals: Vec<String> = entity_interests(&wz)
        .into_iter()
        .map(|(name, _)| format!("Interest (final) {name}"))
        .collect();
    assert!(
        entity_finals.iter().all(|l| !reference.contains(l)),
        "the real pico retracted an entity interest, so a peer's Finals are no longer \
         the divergence this leg claims:\n{}",
        show()
    );
    let mut observed: Vec<String> = wz.clone();
    observed.retain(|l| !entity_finals.contains(l));
    assert_eq!(
        wz.len() - observed.len(),
        asked.len(),
        "wz should retract exactly the entity interests the peer asked, no more and \
         no fewer:\n{}",
        show()
    );

    // Everything else, whole and in wire order.
    assert_eq!(
        observed,
        expected,
        "wz's wire differs from the real zenoh-pico's beyond the two pinned divergences \
         for the same program.\n{}",
        show()
    );
}

/// A pico PEER with no router among its peers: it asks nothing, learns what the
/// peer volunteers, and retracts a subscriber and a queryable naming the key.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "cc-compiles a driver against both libraries and runs each through a \
            tap to a wz-ap-demo peer; run by run-ci Layer E"]
fn a_pico_peer_beside_a_peer_puts_the_same_wire_as_the_real_pico() {
    assert_a_peer_puts_the_same_wire_as_the_real_pico(Topology::PeerToPeer);
}

/// A pico PEER whose peer is a ROUTER: it asks for what its entities need,
/// without the aggregate bit a client sets, and is answered by what another
/// face declared. The `wz_router_` prefix keeps Layer E's `--skip wz_router` from
/// running it against the default-feature demo, which has no `--router`; Layer E5
/// builds the routing demo and runs it by name.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "cc-compiles a driver against both libraries and runs each through a \
            tap to a wz-ap-demo router with a provider behind it; run by run-ci \
            Layer E5"]
fn wz_router_hears_a_pico_peer_the_same_on_wz_and_on_the_real_pico() {
    assert_a_peer_puts_the_same_wire_as_the_real_pico(Topology::PeerToRouter);
}

/// A key several entities hold is ONE declaration with a count: declared again it
/// is the same id, announced again, and retracted when the last holder lets go.
///
/// The program holds one key through a publisher and a keyexpr it declared
/// itself, and one prefix through two subscribers, and releases them so that the
/// holder that the program NAMED last is not the one that retracts. The advanced
/// publisher and subscriber are made of entities that re-declare one joined key,
/// so this is the rule they stand on, measured without them.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "cc-compiles a driver against both libraries and runs each through a \
            tap to a wz-ap-demo node; run by run-ci Layer E"]
fn a_key_declared_twice_is_one_id_with_two_holders_on_the_wire_as_in_the_real_pico() {
    let Arms { wz, reference, .. } = record_both_arms(Topology::Client, Program::SharedKeys);

    let count =
        |lines: &[String], prefix: &str| lines.iter().filter(|l| l.starts_with(prefix)).count();
    // ANTI-VACUITY, in the REFERENCE arm so equality cannot be two arms that both
    // skipped the rule: the shared key is announced twice under ONE id and
    // retracted ONCE, and the prefix the two subscribers share likewise.
    assert_eq!(
        count(&reference, "DeclKexpr K1 ="),
        2,
        "the real pico should announce the shared key twice under one id:\n{}",
        reference.join("\n")
    );
    assert_eq!(
        count(&reference, "UndeclKexpr K1"),
        1,
        "the real pico should retract the shared key once, with its last holder:\n{}",
        reference.join("\n")
    );
    assert_eq!(
        count(&reference, "DeclKexpr K2 ="),
        2,
        "the real pico should announce the subscribers' shared prefix twice:\n{}",
        reference.join("\n")
    );
    assert_eq!(
        count(&reference, "UndeclKexpr K2"),
        1,
        "the real pico should retract the shared prefix once:\n{}",
        reference.join("\n")
    );
    // The program's own release of the declared keyexpr comes BEFORE the
    // publisher's drop and must put nothing on the wire: the only retraction of
    // the shared key follows the publisher's Interest being let go.
    let final_interest = reference
        .iter()
        .position(|l| l.starts_with("Interest (final)"))
        .expect("the publisher's interest is retracted");
    let retraction = reference
        .iter()
        .position(|l| l == "UndeclKexpr K1")
        .expect("the shared key is retracted");
    assert!(
        final_interest < retraction,
        "the shared key must outlive the program's own release of it, and go with \
         the publisher:\n{}",
        reference.join("\n")
    );

    assert_eq!(
        wz,
        reference,
        "wz's key table differs from the real zenoh-pico's for the same program.\n\
         --- wz ---\n{}\n--- reference ---\n{}",
        wz.join("\n"),
        reference.join("\n")
    );
}

/// The advanced publisher against the real pico in one topology. `asks` is the
/// body an Interest of the plain publishers carries in it — `None` for a session
/// that asks nothing.
fn assert_an_advanced_publisher_puts_the_same_wire_as_the_real_pico(
    topology: Topology,
    asks: Option<&str>,
) {
    let Arms { wz, reference, .. } = record_both_arms(topology, Program::AdvancedPublisher);

    let count =
        |lines: &[String], needle: &str| lines.iter().filter(|l| l.contains(needle)).count();
    // ANTI-VACUITY: the REFERENCE arm carries every component the program asked
    // for, so equality below cannot be two renderings that both left one out.
    for needle in [
        "DeclQueryable",
        "DeclToken",
        "UndeclToken",
        "UndeclQueryable",
        "UndeclKexpr",
    ] {
        assert!(
            reference.iter().any(|l| l.contains(needle)),
            "the REFERENCE arm carries no `{needle}` line, so this leg is measuring \
             the harness rather than wz:\n{}",
            reference.join("\n")
        );
    }
    // A write filter per plain publisher the program made: the full publisher's
    // own and its beacon's, the plain one's, and the cache-only one's — for a
    // session that asks, and none at all for one that does not.
    match asks {
        Some(body) => assert_eq!(
            count(&reference, &format!("Interest hdr=0x79 body={body}")),
            4,
            "the real pico should ask once per plain publisher, four in all:\n{}",
            reference.join("\n")
        ),
        None => assert_eq!(
            count(&reference, "Interest"),
            0,
            "the real pico should ask nothing here:\n{}",
            reference.join("\n")
        ),
    }
    // The samples: a put carrying a sequence number, a put carrying an encoding
    // and an attachment, a delete, one carrying a timestamp and no sequence
    // number (the cache-only publisher's), and a plain publisher's put with
    // neither.
    // (`enc=8+` is `text/plain`: the wire carries the encoding's id, not its name.)
    for needle in [
        "source-info",
        "enc=8+",
        "\"meta\"",
        " del ",
        "payload=\"cache-value\"",
        "payload=\"plain-value\"",
    ] {
        assert!(
            reference
                .iter()
                .any(|l| l.starts_with("Push") && l.contains(needle)),
            "the REFERENCE arm carries no Push with `{needle}`, so the sample half of this \
             leg is vacuous:\n{}",
            reference.join("\n")
        );
    }
    assert!(
        reference.iter().any(|l| l.starts_with("Push")
            && l.contains("payload=\"cache-value\"")
            && l.contains("ts=true")
            && !l.contains("source-info")),
        "the cache-only publisher should stamp a timestamp and no sequence number:\n{}",
        reference.join("\n")
    );

    // ⚠ ONE PINNED DIVERGENCE, in the topology where it exists and only there: a
    // pico peer that asked a router never retracts its interests
    // (`vendor/zenoh-pico/src/net/primitives.c` @ `// Build the declare message to
    // send on the wire (only needed in client mode or multicast transport)` in
    // `_z_remove_interest`), so the router keeps them until the session closes,
    // where wz retracts them. The entity legs above pin it the same way and for
    // the same reason: a leak no program can see, and one not worth copying. The
    // count is what is pinned — one retraction per Interest asked — so a
    // retraction that goes missing, or one too many, is still a finding.
    let observed: Vec<String> = match topology {
        Topology::PeerToRouter => {
            assert_eq!(
                reference
                    .iter()
                    .filter(|l| l.starts_with("Interest (final)"))
                    .count(),
                0,
                "the real pico peer should retract no interest it asked a router for:\n{}",
                reference.join("\n")
            );
            let retracted = wz
                .iter()
                .filter(|l| l.starts_with("Interest (final)"))
                .count();
            assert_eq!(
                retracted,
                4,
                "wz should retract exactly the four interests the publishers asked:\n{}",
                wz.join("\n")
            );
            wz.iter()
                .filter(|l| !l.starts_with("Interest (final)"))
                .cloned()
                .collect()
        }
        Topology::Client | Topology::PeerToPeer => wz,
    };
    assert_eq!(
        observed,
        reference,
        "wz's advanced publisher differs from the real zenoh-pico's for the same \
         program.\n--- wz ---\n{}\n--- reference ---\n{}",
        observed.join("\n"),
        reference.join("\n")
    );
}

/// An advanced publisher is what the real pico builds it from: a plain
/// publisher, a cache queryable, a liveliness token and a beacon publisher, each
/// declared on a declared key, and its puts and its delete carry the sequence
/// number, the timestamp, the encoding and the attachment the caller gave.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "cc-compiles a driver against both libraries and runs each through a \
            tap to a wz-ap-demo node; run by run-ci Layer E"]
fn an_advanced_publisher_puts_the_same_wire_as_the_real_pico() {
    assert_an_advanced_publisher_puts_the_same_wire_as_the_real_pico(
        Topology::Client,
        Some("0xd3"),
    );
}

/// The same program from a pico PEER with no router among its peers: nothing is
/// asked, and the retractions name their keys.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "cc-compiles a driver against both libraries and runs each through a \
            tap to a wz-ap-demo peer; run by run-ci Layer E"]
fn an_advanced_publisher_beside_a_peer_puts_the_same_wire_as_the_real_pico() {
    assert_an_advanced_publisher_puts_the_same_wire_as_the_real_pico(Topology::PeerToPeer, None);
}

/// The same program from a pico PEER beside a ROUTER: asked without the
/// aggregate bit. The `wz_router_` prefix keeps Layer E's `--skip wz_router` from
/// running it against the default-feature demo; Layer E5 builds the routing demo
/// and runs it by name.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "cc-compiles a driver against both libraries and runs each through a \
            tap to a wz-ap-demo router with a provider behind it; run by run-ci \
            Layer E5"]
fn wz_router_hears_a_pico_peer_advanced_publisher_the_same_on_wz_and_on_the_real_pico() {
    assert_an_advanced_publisher_puts_the_same_wire_as_the_real_pico(
        Topology::PeerToRouter,
        Some("0x53"),
    );
}

/// The advanced subscriber against the real pico in one topology.
fn assert_an_advanced_subscriber_declares_the_same_wire_as_the_real_pico(topology: Topology) {
    let Arms { wz, reference, .. } = record_both_arms(topology, Program::AdvancedSubscriber);

    // ANTI-VACUITY: the REFERENCE arm carries every component the program asked
    // for, so equality below cannot be two renderings that both left one out.
    for needle in [
        "DeclKexpr",
        "DeclSubscriber",
        "UndeclSubscriber",
        "DeclToken",
        "UndeclToken",
        "UndeclKexpr",
        "Request on",
    ] {
        assert!(
            reference.iter().any(|l| l.contains(needle)),
            "the REFERENCE arm carries no `{needle}` line, so this leg is measuring \
             the harness rather than wz:\n{}",
            reference.join("\n")
        );
    }
    assert_eq!(
        wz,
        reference,
        "wz's advanced subscriber differs from the real zenoh-pico's for the same \
         program.\n--- wz ---\n{}\n--- reference ---\n{}",
        wz.join("\n"),
        reference.join("\n")
    );
}

/// An advanced subscriber is what the real pico builds it from: a plain
/// subscriber, a history query, a liveliness subscriber, a heartbeat subscriber
/// and a liveliness token, each declared and named as its own entry point does,
/// in that order.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "cc-compiles a driver against both libraries and runs each through a \
            tap to a wz-ap-demo node; run by run-ci Layer E"]
fn an_advanced_subscriber_declares_the_same_wire_as_the_real_pico() {
    assert_an_advanced_subscriber_declares_the_same_wire_as_the_real_pico(Topology::Client);
}

/// The same program from a pico PEER with no router among its peers.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "cc-compiles a driver against both libraries and runs each through a \
            tap to a wz-ap-demo peer; run by run-ci Layer E"]
fn an_advanced_subscriber_beside_a_peer_declares_the_same_wire_as_the_real_pico() {
    assert_an_advanced_subscriber_declares_the_same_wire_as_the_real_pico(Topology::PeerToPeer);
}

/// The same program from a pico PEER beside a ROUTER. The `wz_router_` prefix
/// keeps Layer E's `--skip wz_router` from running it against the default-feature
/// demo; Layer E5 builds the routing demo and runs it by name.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "cc-compiles a driver against both libraries and runs each through a \
            tap to a wz-ap-demo router with a provider behind it; run by run-ci \
            Layer E5"]
fn wz_router_hears_a_pico_peer_advanced_subscriber_the_same_on_wz_and_on_the_real_pico() {
    assert_an_advanced_subscriber_declares_the_same_wire_as_the_real_pico(Topology::PeerToRouter);
}

/// What the real pico's samples carry for a publisher declared with options, and
/// what wz's must then carry, in one topology.
fn assert_declared_publisher_options_are_sent_as_the_real_pico_sends_them(topology: Topology) {
    let Arms { wz, reference, .. } = record_both_arms(topology, Program::PublisherOptions);

    let push_of = |lines: &[String], payload: &str| -> Option<String> {
        let needle = format!("payload={payload:?}");
        lines
            .iter()
            .find(|l| l.starts_with("Push") && l.contains(&needle))
            .cloned()
    };
    // ANTI-VACUITY, first: the REFERENCE arm carries every sample the program
    // made, so the equality below cannot be two renderings that both left one
    // out. (A delete has no payload, so it is counted.)
    for payload in [
        "all-plain",
        "all-own",
        "none-plain",
        "prio-plain",
        "express-plain",
        "unreliable-plain",
        "block-plain",
        "enc-plain",
        "enc-own",
        "adv-plain",
        "adv-own",
        "seq-plain",
        "detect-plain",
    ] {
        assert!(
            push_of(&reference, payload).is_some(),
            "the REFERENCE arm carries no Push with payload `{payload}`, so this leg is \
             measuring the harness rather than wz:\n{}",
            reference.join("\n")
        );
    }
    // The detection token's key ends in the metadata the program embedded, in
    // place of the placeholder chunk: the option no other line shows. (The token
    // names its key by a declaration, so the key is on the `DeclKexpr` line.)
    assert!(
        reference.iter().any(|l| l.starts_with("DeclKexpr")
            && l.contains("/@adv/pub/")
            && l.ends_with("/meta/data\"")),
        "the REFERENCE arm declares no detection key ending in the embedded \
         metadata, so the metadata half of this leg is vacuous:\n{}",
        reference.join("\n")
    );
    let deletes = reference
        .iter()
        .filter(|l| l.starts_with("Push") && l.contains(" del "))
        .count();
    assert_eq!(
        deletes,
        5,
        "the program deletes through five publishers (all, none, prio, unreliable and \
         the advanced one):\n{}",
        reference.join("\n")
    );

    // ANTI-VACUITY, second: the publishers really do send DIFFERENTLY. A rendering
    // in which every publisher sends the same thing would make each field's
    // wiring indistinguishable from any other's. The envelope and channel of the
    // samples that carry no encoding of their own must differ across the seven
    // plain publishers wherever their options differ.
    let qos_of = |payload: &str| -> String {
        let line = push_of(&reference, payload).expect("checked above");
        // Everything between the key and the kind: the channel and the envelope.
        let after_key = line
            .split_once(" [")
            .map(|(_, rest)| format!("[{rest}"))
            .expect("a Qos rendering names its channel");
        after_key
            .split(" put ")
            .next()
            .expect("split yields one part")
            .to_owned()
    };
    let distinct: std::collections::BTreeSet<String> = [
        "all-plain",
        "none-plain",
        "prio-plain",
        "express-plain",
        "unreliable-plain",
        "block-plain",
    ]
    .into_iter()
    .map(qos_of)
    .collect();
    assert_eq!(
        distinct.len(),
        6,
        "six publishers declared six different ways must send six different \
         envelope-and-channel renderings; got {distinct:#?}"
    );
    // The two the program declares alone on the CHANNEL: reliability is the frame's
    // reliable flag and nothing else, and only best-effort publishers clear it.
    assert!(
        qos_of("unreliable-plain").starts_with("[best-effort"),
        "a best-effort publisher rides the best-effort channel: {}",
        qos_of("unreliable-plain")
    );
    assert!(
        qos_of("none-plain").starts_with("[reliable"),
        "a publisher declared with nothing rides the reliable channel: {}",
        qos_of("none-plain")
    );
    // A put with an encoding of its own carries THAT encoding and the publisher's
    // QoS; a put with none carries the publisher's encoding. Two publishers, so
    // the encoding's id and its schema are both read off the wire. (The number is
    // the wire's packed id: the encoding's id shifted left one, the schema flag in
    // bit 0 — `text/plain` is 8, `application/json` 10, and a schema sets the
    // low bit.)
    for (payload, encoding) in [
        ("all-plain", " enc=8+None"),
        ("all-own", " enc=10+None"),
        ("enc-plain", " enc=9+Some(\"utf-8\")"),
        ("enc-own", " enc=11+Some(\"v1\")"),
    ] {
        let line = push_of(&reference, payload).expect("checked above");
        assert!(
            line.contains(encoding),
            "the reference sample `{payload}` should carry `{encoding}`:\n{line}"
        );
    }
    assert_eq!(
        qos_of("all-plain"),
        qos_of("all-own"),
        "a put's own encoding does not change the QoS the publisher sends with"
    );

    // ⚠ ONE PINNED DIVERGENCE, in the topology where it exists and only there, the
    // same one the advanced publisher's leg pins: a pico peer that asked a router
    // never retracts its interests (`vendor/zenoh-pico/src/net/primitives.c` @ `//
    // Build the declare message to send on the wire (only needed in client mode or
    // multicast transport)` in `_z_remove_interest`), where wz retracts them. The
    // count is what is pinned, one retraction per Interest asked, so a retraction
    // that goes missing or one too many is still a finding.
    let observed: Vec<String> = match topology {
        Topology::PeerToRouter => {
            assert_eq!(
                reference
                    .iter()
                    .filter(|l| l.starts_with("Interest (final)"))
                    .count(),
                0,
                "the real pico peer should retract no interest it asked a router for:\n{}",
                reference.join("\n")
            );
            let asked = reference
                .iter()
                .filter(|l| l.starts_with("Interest hdr="))
                .count();
            assert!(asked > 0, "the reference asked the router for nothing");
            let retracted = wz
                .iter()
                .filter(|l| l.starts_with("Interest (final)"))
                .count();
            assert_eq!(
                retracted,
                asked,
                "wz should retract exactly the interests the publishers asked:\n{}",
                wz.join("\n")
            );
            wz.iter()
                .filter(|l| !l.starts_with("Interest (final)"))
                .cloned()
                .collect()
        }
        Topology::Client | Topology::PeerToPeer => wz,
    };
    assert_eq!(
        observed,
        reference,
        "wz sends a declared publisher's samples differently from the real zenoh-pico \
         for the same program.\n--- wz ---\n{}\n--- reference ---\n{}",
        observed.join("\n"),
        reference.join("\n")
    );
}

/// A publisher declared with options sends every put and delete with them: its
/// encoding as the default a put's own overrides, and its congestion control,
/// priority, express flag and reliability on the envelope and the channel. Each is
/// varied alone as well as together, and an advanced publisher, which pico builds
/// out of a plain one, sends the QoS it was declared with.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "cc-compiles a driver against both libraries and runs each through a \
            tap to a wz-ap-demo node; run by run-ci Layer E"]
fn a_publisher_declared_with_options_sends_the_same_qos_as_the_real_pico() {
    assert_declared_publisher_options_are_sent_as_the_real_pico_sends_them(Topology::Client);
}

/// The same program from a pico PEER with no router among its peers.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "cc-compiles a driver against both libraries and runs each through a \
            tap to a wz-ap-demo peer; run by run-ci Layer E"]
fn a_publisher_declared_with_options_beside_a_peer_sends_the_same_qos_as_the_real_pico() {
    assert_declared_publisher_options_are_sent_as_the_real_pico_sends_them(Topology::PeerToPeer);
}

/// The same program from a pico PEER beside a ROUTER. The `wz_router_` prefix
/// keeps Layer E's `--skip wz_router` from running it against the default-feature
/// demo; Layer E5 builds the routing demo and runs it by name.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "cc-compiles a driver against both libraries and runs each through a \
            tap to a wz-ap-demo router with a provider behind it; run by run-ci \
            Layer E5"]
fn wz_router_hears_a_pico_peer_publisher_with_options_the_same_on_wz_and_on_the_real_pico() {
    assert_declared_publisher_options_are_sent_as_the_real_pico_sends_them(Topology::PeerToRouter);
}
