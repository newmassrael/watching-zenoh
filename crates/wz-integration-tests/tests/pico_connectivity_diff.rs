// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.27 `api-compat-pico` — what a pico program is told about its peers,
//! compiled once against the real zenoh-pico and once against wz, run against
//! the same stimulus, and compared line for line.
//!
//! ## What this exists to catch
//!
//! `Z_FEATURE_CONNECTIVITY` is 115 symbols a program can name — `z_info_links`,
//! `z_declare_link_events_listener`, `z_link_mtu` — and a link census says only
//! that they are DEFINED. What a program prints with them is decided by things
//! no header states: the order pico tells a peer's arrival and departure in, the
//! values a link reports for itself (its MTU is a constant of the link TYPE and
//! not the negotiated batch), what a listener with `history` replays, and what
//! `z_info_links` and `z_info_transports` list. So those are what is compared.
//!
//! ## The comparison
//!
//! One C driver is compiled against upstream's headers twice, once linked to the
//! real `libzenohpico.so` and once to wz's cdylib. It opens a LISTENING peer
//! session, declares transport and link listeners, waits, lists what is
//! connected, declares a second pair of listeners with `history`, waits, and
//! closes. In between, the harness starts a wz-ap-demo that DIALS IN and later
//! kills it, so every arm sees an arrival, a listing and a departure. The
//! driver prints one line per event and per listing; the harness normalises what
//! each arm chooses for itself (the demo's zid, the ports) and compares the
//! rest.
//!
//! The reference arm's content is asserted BEFORE the equality: two empty
//! outputs are equal, and this leg would then be measuring the harness.
//!
//! ## The oracle is a build product
//!
//! `libzenohpico.so` and its headers come from `scripts/build-zenoh-pico-cli.sh`,
//! whose configuration compiles `Z_FEATURE_CONNECTIVITY` in, and the peer is
//! wz-ap-demo. Absence is a hard FAIL rather than a skip.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, graceful_terminate, read_captured, wz_ap_demo_binary,
    wz_capi_pico_cdylib, zenoh_pico_include_dirs, zenoh_pico_library_dir, ChildGuard,
};

/// The driver. Prints a marker for each phase, so the harness knows when to
/// start and end the peer, and one line per event and per listing.
const DRIVER_SRC: &str = r#"
#include <stdio.h>
#include <string.h>
#include <zenoh-pico.h>

#if Z_FEATURE_CONNECTIVITY == 1

static void say_zid(char *out, size_t cap, z_id_t zid) {
    z_owned_string_t text;
    z_id_to_string(&zid, &text);
    snprintf(out, cap, "%.*s", (int)z_string_len(z_loan(text)), z_string_data(z_loan(text)));
    z_drop(z_move(text));
}

static const char *kind_name(z_sample_kind_t kind) {
    return kind == Z_SAMPLE_KIND_PUT ? "PUT" : (kind == Z_SAMPLE_KIND_DELETE ? "DEL" : "???");
}

static void print_transport(const char *prefix, const char *tag, const char *kind,
                            const z_loaned_transport_t *transport) {
    char zid[64];
    say_zid(zid, sizeof(zid), z_transport_zid(transport));
    printf("%s %s transport%s%s zid=%s whatami=%d qos=%d multicast=%d shm=%d\n", prefix, tag,
           kind[0] ? " " : "", kind, zid, (int)z_transport_whatami(transport),
           (int)z_transport_is_qos(transport), (int)z_transport_is_multicast(transport),
           (int)z_transport_is_shm(transport));
    fflush(stdout);
}

static void print_link(const char *prefix, const char *tag, const char *kind,
                       const z_loaned_link_t *link) {
    char zid[64];
    say_zid(zid, sizeof(zid), z_link_zid(link));
    z_owned_string_t src, dst;
    z_link_src(link, &src);
    z_link_dst(link, &dst);
    printf("%s %s link%s%s zid=%s src=%.*s dst=%.*s mtu=%u streamed=%d reliable=%d\n", prefix, tag,
           kind[0] ? " " : "", kind, zid, (int)z_string_len(z_loan(src)), z_string_data(z_loan(src)),
           (int)z_string_len(z_loan(dst)), z_string_data(z_loan(dst)), (unsigned)z_link_mtu(link),
           (int)z_link_is_streamed(link), (int)z_link_is_reliable(link));
    fflush(stdout);
    z_drop(z_move(src));
    z_drop(z_move(dst));
}

static void on_transport_event(z_loaned_transport_event_t *event, void *ctx) {
    print_transport("event", (const char *)ctx, kind_name(z_transport_event_kind(event)),
                    z_transport_event_transport(event));
}

static void on_link_event(z_loaned_link_event_t *event, void *ctx) {
    print_link("event", (const char *)ctx, kind_name(z_link_event_kind(event)),
               z_link_event_link(event));
}

static void on_transport(z_loaned_transport_t *transport, void *ctx) {
    print_transport("listed", (const char *)ctx, "", transport);
}

static void on_link(z_loaned_link_t *link, void *ctx) {
    print_link("listed", (const char *)ctx, "", link);
}

static int declare(const z_loaned_session_t *zs, const char *tag, bool history,
                   z_owned_transport_events_listener_t *transports,
                   z_owned_link_events_listener_t *links) {
    z_owned_closure_transport_event_t tcb;
    z_closure(&tcb, on_transport_event, NULL, (void *)tag);
    z_transport_events_listener_options_t topt;
    z_transport_events_listener_options_default(&topt);
    topt.history = history;
    if (z_declare_transport_events_listener(zs, transports, z_move(tcb), &topt) < 0) {
        printf("driver: transport listener %s failed\n", tag);
        return -1;
    }
    z_owned_closure_link_event_t lcb;
    z_closure(&lcb, on_link_event, NULL, (void *)tag);
    z_link_events_listener_options_t lopt;
    z_link_events_listener_options_default(&lopt);
    lopt.history = history;
    if (z_declare_link_events_listener(zs, links, z_move(lcb), &lopt) < 0) {
        printf("driver: link listener %s failed\n", tag);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    (void)argc;
    const char *endpoint = argv[1];

    z_owned_config_t config;
    z_config_default(&config);
    zp_config_insert(z_loan_mut(config), Z_CONFIG_MODE_KEY, "peer");
    zp_config_insert(z_loan_mut(config), Z_CONFIG_LISTEN_KEY, endpoint);

    z_owned_session_t s;
    if (z_open(&s, z_move(config), NULL) < 0) {
        printf("driver: unable to open session\n");
        return -1;
    }

    /* A live pair, declared before anyone is connected. The transport listener
       is declared first, so an order that follows declaration would put it
       ahead of the link listener on a departure too. */
    z_owned_transport_events_listener_t live_t;
    z_owned_link_events_listener_t live_l;
    if (declare(z_loan(s), "live", false, &live_t, &live_l) < 0) {
        return -1;
    }
    printf("READY\n");
    fflush(stdout);

    z_sleep_ms(3000);

    z_owned_closure_transport_t listed_t;
    z_closure(&listed_t, on_transport, NULL, (void *)"info");
    z_info_transports(z_loan(s), z_move(listed_t));
    z_owned_closure_link_t listed_l;
    z_closure(&listed_l, on_link, NULL, (void *)"info");
    z_info_links(z_loan(s), z_move(listed_l), NULL);

    /* A second pair, declared with the peer already connected: it is told about
       the peer as PUT events before anything else. */
    z_owned_transport_events_listener_t replay_t;
    z_owned_link_events_listener_t replay_l;
    if (declare(z_loan(s), "replay", true, &replay_t, &replay_l) < 0) {
        return -1;
    }
    printf("LISTED\n");
    fflush(stdout);

    z_sleep_ms(4000);
    printf("DEPARTED\n");
    fflush(stdout);

    z_drop(z_move(live_l));
    z_drop(z_move(live_t));
    z_drop(z_move(replay_l));
    z_drop(z_move(replay_t));
    z_close(z_loan_mut(s), NULL);
    z_drop(z_move(s));
    printf("DONE\n");
    fflush(stdout);
    return 0;
}

#else
int main(void) {
    printf("driver: the reference headers do not compile Z_FEATURE_CONNECTIVITY in\n");
    return 2;
}
#endif
"#;

/// Compile the driver against upstream's headers, linked to `lib`. Only the
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

/// Wait until the driver's capture carries `needle`, which is how the harness
/// knows a phase has been reached.
fn wait_for_marker(capture: &mut File, needle: &str, budget: Duration, arm: &str) {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if read_captured(capture).contains(needle) {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!(
        "{arm}: the driver never printed {needle:?}:\n{}",
        read_captured(capture)
    );
}

/// Run one arm: start the driver listening, let it declare its listeners, dial
/// it with a wz-ap-demo, let it list, then kill the peer and let the driver see
/// it go. Returns everything the driver printed.
fn run_arm(driver: &Path, arm: &str) -> String {
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let port = wz_runtime_tokio_test_support::free_port();
    let endpoint = format!("tcp/127.0.0.1:{port}");

    let mut capture = tempfile::tempfile().expect("the driver capture");
    let mut driver_child = ChildGuard::wrap(
        format!("{arm} driver"),
        Command::new(driver)
            .arg(&endpoint)
            .stdout(capture.try_clone().expect("dup stdout handle"))
            .stderr(capture.try_clone().expect("dup stderr handle"))
            .spawn()
            .unwrap_or_else(|e| panic!("{arm}: failed to run the driver: {e}")),
    );
    wait_for_marker(&mut capture, "READY", Duration::from_secs(15), arm);

    let demo_stderr = tempfile::tempfile().expect("the demo's stderr");
    let mut peer = ChildGuard::wrap(
        format!("{arm} peer"),
        Command::new(&demo)
            .args(["--connect", &endpoint, "--key", "demo/connectivity"])
            .stdout(Stdio::null())
            .stderr(Stdio::from(demo_stderr))
            .spawn()
            .unwrap_or_else(|e| panic!("{arm}: failed to start the peer: {e}")),
    );
    wait_for_marker(&mut capture, "LISTED", Duration::from_secs(20), arm);
    // Let the listing settle, then the peer goes.
    std::thread::sleep(Duration::from_millis(300));
    graceful_terminate(peer.child_mut(), Duration::from_secs(5));
    wait_for_marker(&mut capture, "DONE", Duration::from_secs(20), arm);

    let status = driver_child
        .child_mut()
        .wait()
        .unwrap_or_else(|e| panic!("{arm}: waiting for the driver: {e}"));
    assert!(
        status.success(),
        "{arm}: the driver exited {status:?}\n--- its output ---\n{}",
        read_captured(&mut capture)
    );
    let text = read_captured(&mut capture);
    normalise(&text, port)
}

/// Replace what each arm chooses for itself: the peer's zid (random), the
/// listener's port and the peer's ephemeral port. Everything else is compared
/// as printed.
fn normalise(text: &str, listen_port: u16) -> String {
    // The peer's zid is the first `zid=` an event names.
    let peer_zid = text
        .lines()
        .find(|l| l.starts_with("event live transport PUT"))
        .and_then(|l| l.split("zid=").nth(1))
        .and_then(|rest| rest.split_whitespace().next())
        .map(str::to_owned);
    let mut out = text.to_owned();
    if let Some(zid) = &peer_zid {
        out = out.replace(zid.as_str(), "<peer-zid>");
    }
    out = out.replace(
        &format!("tcp/127.0.0.1:{listen_port}"),
        "tcp/127.0.0.1:<listen>",
    );
    // The peer's own port is the digits after the loopback host on a `dst`.
    let marker = "dst=tcp/127.0.0.1:";
    let mut rebuilt = String::with_capacity(out.len());
    let mut rest = out.as_str();
    while let Some(at) = rest.find(marker) {
        rebuilt.push_str(&rest[..at + marker.len()]);
        let tail = &rest[at + marker.len()..];
        let digits = tail.chars().take_while(char::is_ascii_digit).count();
        if digits > 0 {
            rebuilt.push_str("<peer>");
        }
        rest = &tail[digits..];
    }
    rebuilt.push_str(rest);
    rebuilt
}

/// Both libraries told the same way, line for line.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "cc-compiles a driver against both libraries and runs each against a \
            wz-ap-demo peer that dials in; run by run-ci Layer E"]
fn a_peer_arriving_listed_and_leaving_is_told_the_same_on_wz_and_on_the_real_pico() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cdylib = wz_capi_pico_cdylib();
    let wz_libdir = cdylib
        .parent()
        .expect("cdylib has a parent directory")
        .to_path_buf();

    let ref_driver = compile_driver(
        dir.path(),
        &zenoh_pico_library_dir(),
        "zenohpico",
        "reference",
    );
    let wz_driver = compile_driver(dir.path(), &wz_libdir, "wz_capi_pico", "wz");

    let reference = run_arm(&ref_driver, "reference");
    let wz = run_arm(&wz_driver, "wz");

    // ANTI-VACUITY: the REFERENCE arm carries every kind of line this leg is
    // about, so equality cannot be two outputs that both left one out.
    for needle in [
        "event live transport PUT",
        "event live link PUT",
        "event live link DEL",
        "event live transport DEL",
        "listed info transport",
        "listed info link",
        "event replay transport PUT",
        "event replay link PUT",
    ] {
        assert!(
            reference.lines().any(|l| l.starts_with(needle)),
            "the REFERENCE arm has no `{needle}` line, so this leg is measuring the \
             harness rather than wz:\n{reference}"
        );
    }
    // The order the listeners are told in: the transport and then its link on
    // an arrival, the link and then its transport on a departure.
    let order: Vec<&str> = reference
        .lines()
        .filter(|l| l.starts_with("event live "))
        .map(|l| l.split(" zid=").next().unwrap_or(l))
        .collect();
    assert_eq!(
        order,
        [
            "event live transport PUT",
            "event live link PUT",
            "event live link DEL",
            "event live transport DEL"
        ],
        "the real pico's order is not the one this leg was written for:\n{reference}"
    );

    assert_eq!(
        wz, reference,
        "wz tells a program about its peers differently from the real zenoh-pico.\n\
         --- wz ---\n{wz}\n--- reference ---\n{reference}"
    );
}
