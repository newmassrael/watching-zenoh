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
    zp_config_insert(z_loan_mut(config), Z_CONFIG_MODE_KEY, "client");
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

/// Compile `DRIVER_SRC` against upstream's headers, linked to `lib`. Only the
/// library differs between the arms, which is the whole point.
fn compile_driver(out_dir: &Path, libdir: &Path, libname: &str, arm: &str) -> PathBuf {
    let src = out_dir.join(format!("driver_{arm}.c"));
    std::fs::write(&src, DRIVER_SRC).expect("write driver source");
    let exe = out_dir.join(format!("driver_{arm}"));

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

/// Run one arm against a fresh wz router behind a tap and return the
/// recording.
fn record_arm(driver: &Path, arm: &str) -> Vec<(wz_integration_tests::wire_tap::Side, Vec<u8>)> {
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let demo_stderr = tempfile::tempfile().expect("tempfile for router stderr");
    let (mut router, _router_log, router_port) = spawn_on_ephemeral_port(
        &demo,
        // A subscriber on everything under `demo/`, which is what opens the
        // publisher's write filter, and a queryable on ONE key the driver's
        // second querier names, which is what opens that querier's.
        &[
            "--listen",
            "127.0.0.1:0",
            "--key",
            "demo/**",
            "--queryable",
            "demo/kd/qry2",
            "--reply",
            "kd",
        ],
        "listening on 127.0.0.1:",
        "wz-ap-demo (router behind the tap)",
        demo_stderr,
    );
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
    format!("{scope}+{:?}", suffix.unwrap_or_default())
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

/// One line per declaration and per data message the dialer sent, in order.
fn render(
    segments: &[(wz_integration_tests::wire_tap::Side, Vec<u8>)],
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
                    lines.push(format!("Push on {}", wire(&mut names, &p.keyexpr)))
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
                NetworkMessage::Interest(i) => {
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
                                "Interest hdr={:#04x} body={:#04x} on {key}",
                                i.header & !INTEREST_EXTENSION_BIT,
                                body.header
                            )
                        }
                        None => String::from("Interest (final)"),
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

/// wz's drop-in declares, and aliases, exactly the keyexprs the real zenoh-pico
/// does for the same program.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "cc-compiles a driver against both libraries and runs each through a \
            tap to a wz-ap-demo router; run by run-ci Layer E"]
fn a_declaring_program_puts_the_same_declarations_on_the_wire_as_the_real_pico() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cdylib = wz_capi_pico_cdylib();
    let wz_libdir = cdylib
        .parent()
        .expect("cdylib has a parent directory")
        .to_path_buf();

    let wz_driver = compile_driver(dir.path(), &wz_libdir, "wz_capi_pico", "wz");
    let ref_driver = compile_driver(
        dir.path(),
        &zenoh_pico_library_dir(),
        "zenohpico",
        "reference",
    );

    let (reference, reference_interest_headers) = render(&record_arm(&ref_driver, "reference"));
    let (wz, wz_interest_headers) = render(&record_arm(&wz_driver, "wz"));

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
