// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! §5.27 `api-compat-pico` -- the session's READ TASK, compiled once against the
//! real zenoh-pico and once against wz, run against the same peers, and compared
//! line for line.
//!
//! ## What this exists to catch
//!
//! pico starts its background executor in `z_open` only `if
//! (opts.auto_start_read_task)` (`vendor/zenoh-pico/src/api/api.c` @ `if
//! (opts.auto_start_read_task) {`), and `zp_stop_read_task` /
//! `zp_start_read_task` stop and start it. The keep-alive, lease, read and accept
//! tasks all live in that executor, so a session without it reads nothing and
//! accepts nobody: what a peer sends waits in the socket. A program relies on it
//! to open a session, declare its subscribers, and only then let traffic in.
//!
//! wz accepted the flag and ignored it, answered `Z_OK` to start and stop and did
//! nothing, and reported `zp_read_task_is_running` as "not closed". A link does
//! not see that, and neither does a delivery test on a session that never stops
//! its task. What differs is whether a sample reaches a subscriber that was
//! declared AFTER the peer connected, so that is what is measured. The other half
//! of the contract is measured too: a `z_put` writes on the caller's thread in
//! pico, so it reaches the peer whether or not the task runs, and a `z_close` of a
//! stopped session returns.
//!
//! ## The comparison
//!
//! One C driver is compiled against upstream's headers twice, and run in three
//! modes. The peer is always a wz-ap-demo, which publishes five Puts right after
//! its session is established and subscribes to `demo/tx/**`, the key the driver
//! puts to.
//!
//! - `held`: the driver LISTENS with `auto_start_read_task` false. A demo dials
//!   in; nothing is accepted. The driver declares its subscriber, starts the task,
//!   gets the five Puts, stops it, puts while stopped, lets a SECOND demo dial in
//!   (held again), restarts, gets the second five and closes a stopped session.
//! - `default`: the same, with no options at all -- the negative arm. Without it a
//!   build that held every session back would pass `held` for a reason that has
//!   nothing to do with the option.
//! - `dial`: the driver DIALS a listening demo with `auto_start_read_task` false,
//!   which is the usual shape of the flag: a client opens, declares, then starts.
//!
//! - `dial-coalesced`: `dial` through a proxy that holds the demo's OPEN ack and
//!   its burst and delivers them in one write. The frames are already in the
//!   dialler's socket the moment its open is through, and its subscriber is not
//!   declared yet: a session that reads them in the poll that announced the open
//!   drops all five, where pico holds them for the subscriber. No ordinary peer
//!   puts data behind its OPEN ack, so without the proxy that window is never hit.
//!
//! The reference arm's content is asserted BEFORE the equality: two outputs that
//! both held nothing are equal, and this leg would then be measuring the harness.
//!
//! ## The oracle is a build product
//!
//! `libzenohpico.so` and its headers come from `scripts/build-zenoh-pico-cli.sh`
//! and the peers are wz-ap-demo. Absence is a hard FAIL rather than a skip.

use std::fs::File;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, demo_log_filter, graceful_terminate, read_captured,
    wait_for_substring, wz_ap_demo_binary, wz_capi_pico_cdylib, zenoh_pico_include_dirs,
    zenoh_pico_library_dir, ChildGuard,
};

/// The driver. `argv[1]` is the endpoint, `argv[2]` the mode.
///
/// Every line is one observation, and nothing random is printed. A counter per
/// burst (the peers publish values starting `a` and `b`) keeps the two bursts
/// apart without ordering anything between the callback thread and `main`.
const DRIVER_SRC: &str = r#"
#include <stdio.h>
#include <string.h>
#include <zenoh-pico.h>

static volatile int count_a = 0;
static volatile int count_b = 0;

static void on_sample(z_loaned_sample_t *sample, void *ctx) {
    (void)ctx;
    z_owned_string_t value;
    z_bytes_to_string(z_sample_payload(sample), &value);
    const char *data = z_string_data(z_loan(value));
    if (z_string_len(z_loan(value)) > 0 && data[0] == 'a') {
        __atomic_add_fetch(&count_a, 1, __ATOMIC_SEQ_CST);
    } else if (z_string_len(z_loan(value)) > 0 && data[0] == 'b') {
        __atomic_add_fetch(&count_b, 1, __ATOMIC_SEQ_CST);
    }
    z_drop(z_move(value));
}

/* Wait for a counter to reach `want`, at most ~8 s, and return what it holds. */
static int wait_for(volatile int *counter, int want) {
    for (int i = 0; i < 160; i++) {
        if (__atomic_load_n(counter, __ATOMIC_SEQ_CST) >= want) {
            break;
        }
        z_sleep_ms(50);
    }
    return __atomic_load_n(counter, __ATOMIC_SEQ_CST);
}

static void put_to_the_peer(const z_loaned_session_t *s, const char *what) {
    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, "demo/tx/from-driver");
    z_owned_bytes_t payload;
    z_bytes_copy_from_str(&payload, "from-the-driver");
    z_result_t rc = z_put(s, z_loan(ke), z_move(payload), NULL);
    printf("%s rc=%d\n", what, (int)rc);
}

static void start_twice(z_owned_session_t *s) {
    z_result_t rc = zp_start_read_task(z_loan_mut(*s), NULL);
    printf("start rc=%d running=%d\n", (int)rc, (int)zp_read_task_is_running(z_loan(*s)));
    rc = zp_start_read_task(z_loan_mut(*s), NULL);
    printf("start-again rc=%d running=%d\n", (int)rc, (int)zp_read_task_is_running(z_loan(*s)));
}

static void stop_twice(z_owned_session_t *s) {
    z_result_t rc = zp_stop_read_task(z_loan_mut(*s));
    printf("stop rc=%d running=%d\n", (int)rc, (int)zp_read_task_is_running(z_loan(*s)));
    rc = zp_stop_read_task(z_loan_mut(*s));
    printf("stop-again rc=%d running=%d\n", (int)rc, (int)zp_read_task_is_running(z_loan(*s)));
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 3) {
        printf("driver: usage: driver <endpoint> <held|default|dial>\n");
        return 2;
    }
    const char *endpoint = argv[1];
    int dial = strcmp(argv[2], "dial") == 0;
    int held = dial || strcmp(argv[2], "held") == 0;

    z_owned_config_t config;
    z_config_default(&config);
    zp_config_insert(z_loan_mut(config), dial ? Z_CONFIG_CONNECT_KEY : Z_CONFIG_LISTEN_KEY, endpoint);

    z_owned_session_t s;
    z_result_t rc;
    if (held) {
        z_open_options_t opt;
        z_open_options_default(&opt);
        opt.auto_start_read_task = false;
        rc = z_open(&s, z_move(config), &opt);
    } else {
        rc = z_open(&s, z_move(config), NULL);
    }
    if (rc < 0) {
        printf("driver: unable to open session\n");
        return 1;
    }
    printf("opened running=%d\n", (int)zp_read_task_is_running(z_loan(s)));

    z_view_keyexpr_t ke;
    z_view_keyexpr_from_str(&ke, "demo/rt/**");
    z_owned_closure_sample_t cb;
    z_closure(&cb, on_sample, NULL, NULL);
    z_owned_subscriber_t sub;
    if (z_declare_subscriber(z_loan(s), &sub, z_loan(ke), z_move(cb), NULL) < 0) {
        printf("driver: unable to declare the subscriber\n");
        return 1;
    }
    printf("READY\n");

    /* The first peer is connecting, or has connected, now. A running task
       delivers as soon as the handshake is through, so that mode waits for the
       first sample; a held one has nothing to wait for and is given the time a
       handshake and the demo's first burst would take. */
    int seen;
    if (held) {
        z_sleep_ms(1500);
        seen = __atomic_load_n(&count_a, __ATOMIC_SEQ_CST);
    } else {
        seen = wait_for(&count_a, 1);
    }
    printf("before-start running=%d samples>0=%d\n", (int)zp_read_task_is_running(z_loan(s)), seen > 0);

    /* A dialled session is connected while it is still stopped, so the put
       that does not need the read task is made here. */
    if (dial) {
        put_to_the_peer(z_loan(s), "put-while-stopped");
        z_sleep_ms(500);
    }

    start_twice(&s);
    printf("first-burst samples=%d\n", wait_for(&count_a, 5));

    stop_twice(&s);
    printf("STOPPED\n");

    if (!dial) {
        /* The listener's peer is connected: a put from a stopped session. */
        put_to_the_peer(z_loan(s), "put-while-stopped");
        /* The second peer dials in now, into a session that is not running. */
        z_sleep_ms(1500);
        printf("held-while-stopped samples=%d\n", __atomic_load_n(&count_b, __ATOMIC_SEQ_CST));

        rc = zp_start_read_task(z_loan_mut(s), NULL);
        printf("restart rc=%d running=%d\n", (int)rc, (int)zp_read_task_is_running(z_loan(s)));
        printf("second-burst samples=%d\n", wait_for(&count_b, 5));

        rc = zp_stop_read_task(z_loan_mut(s));
        printf("stop-before-close rc=%d running=%d\n", (int)rc, (int)zp_read_task_is_running(z_loan(s)));
    }

    z_close(z_loan_mut(s), NULL);
    printf("closed running=%d\n", (int)zp_read_task_is_running(z_loan(s)));
    z_drop(z_move(s));
    printf("DONE\n");
    return 0;
}
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

/// A wz-ap-demo that publishes five Puts of `value` under `demo/rt/<value>` and
/// subscribes to `demo/tx/**`. `mode_args` carries the role: `--connect <ep>` to
/// dial the driver, `--listen <host:port>` to be dialled. Its stderr is the
/// caller's, so what it received can be counted.
fn spawn_demo(demo: &Path, mode_args: &[&str], value: &str, stderr: File, arm: &str) -> ChildGuard {
    ChildGuard::wrap(
        format!("{arm} demo {value}"),
        Command::new(demo)
            .args(mode_args)
            .args(["--key", "demo/tx/**"])
            .args(["--publish", &format!("demo/rt/{value}"), "--value", value])
            .env("RUST_LOG", demo_log_filter())
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr))
            .spawn()
            .unwrap_or_else(|e| panic!("{arm}: failed to start the demo {value}: {e}")),
    )
}

/// Whole length-prefixed frames at the front of `pending` (a u16 little-endian
/// length and then that many bytes, which is how every zenoh stream link frames a
/// message), drained from it one at a time.
fn next_frame(pending: &mut Vec<u8>) -> Option<Vec<u8>> {
    if pending.len() < 2 {
        return None;
    }
    let total = 2 + usize::from(u16::from_le_bytes([pending[0], pending[1]]));
    if pending.len() < total {
        return None;
    }
    Some(pending.drain(..total).collect())
}

/// Carry the demo's bytes to the dialler, holding every frame after the first --
/// the INIT ack, which the dialler must have to send its OPEN -- and delivering
/// the held ones in ONE write once `hold` has passed since the first was held.
/// The OPEN ack is therefore in the same write as the burst that follows it, and
/// the dialler finds those frames already in its socket the moment its open is
/// through, which no ordinary peer arranges: the window is the point.
fn relay_held_then_coalesced(mut server: TcpStream, mut client: TcpStream, hold: Duration) {
    server
        .set_read_timeout(Some(Duration::from_millis(20)))
        .expect("read timeout on the demo side");
    let mut pending: Vec<u8> = Vec::new();
    let mut held: Vec<u8> = Vec::new();
    let mut passed = 0usize;
    let mut first_held_at: Option<Instant> = None;
    let mut released = false;
    let mut chunk = [0u8; 4096];
    loop {
        let eof = match server.read(&mut chunk) {
            Ok(0) => true,
            Ok(n) => {
                pending.extend_from_slice(&chunk[..n]);
                false
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                false
            }
            Err(_) => true,
        };
        while let Some(frame) = next_frame(&mut pending) {
            if released || passed < 1 {
                passed += 1;
                if client.write_all(&frame).is_err() {
                    return;
                }
            } else {
                first_held_at.get_or_insert_with(Instant::now);
                held.extend_from_slice(&frame);
            }
        }
        let due = first_held_at.is_some_and(|t| t.elapsed() >= hold);
        if (due || eof) && !held.is_empty() {
            released = true;
            if client.write_all(&held).is_err() {
                return;
            }
            held.clear();
        }
        if eof {
            let _ = client.shutdown(Shutdown::Write);
            return;
        }
    }
}

/// A proxy in front of the demo at `upstream_port` that runs
/// [`relay_held_then_coalesced`] for the one connection it serves. Returns the
/// port the dialler is to use.
fn spawn_coalescing_proxy(upstream_port: u16, hold: Duration) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the proxy");
    listener
        .set_nonblocking(true)
        .expect("a proxy listener that can be polled");
    let port = listener.local_addr().expect("proxy address").port();
    std::thread::spawn(move || {
        // A driver that never dials -- it died, or was built without the option
        // under test -- must not park this thread for the life of the process.
        let deadline = Instant::now() + Duration::from_secs(60);
        let client = loop {
            match listener.accept() {
                Ok((client, _)) => break client,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => {
                    eprintln!("coalescing proxy: the driver never dialled it ({e})");
                    return;
                }
            }
        };
        // The accepted socket is read and written blockingly by the relay.
        if client.set_nonblocking(false).is_err() {
            return;
        }
        let Ok(server) = TcpStream::connect(("127.0.0.1", upstream_port)) else {
            return;
        };
        let (Ok(mut from_client), Ok(mut to_server)) = (client.try_clone(), server.try_clone())
        else {
            return;
        };
        std::thread::spawn(move || {
            let _ = std::io::copy(&mut from_client, &mut to_server);
            let _ = to_server.shutdown(Shutdown::Write);
        });
        relay_held_then_coalesced(server, client, hold);
    });
    port
}

/// How many Puts on `demo/tx/**` a demo's log says it received.
fn received_from_the_driver(demo_stderr: &mut File) -> usize {
    read_captured(demo_stderr)
        .lines()
        .filter(|l| l.contains("SUBSCRIBER FIRED") && l.contains("keyexpr='demo/tx/"))
        .count()
}

/// Run one arm in one mode. Returns everything the driver printed, then the one
/// line the harness adds: what the first demo received from the driver.
fn run_arm(driver: &Path, arm: &str, mode: &str) -> String {
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let port = wz_runtime_tokio_test_support::free_port();
    let mut capture = tempfile::tempfile().expect("the driver capture");
    let mut first_stderr = tempfile::tempfile().expect("the first demo's stderr");

    // `dial-coalesced` is the `dial` leg through the proxy above: the driver is
    // told `dial` and the endpoint of the proxy, which connects to the demo once
    // the driver connects to it.
    let dials = mode.starts_with("dial");
    let driver_mode = if dials { "dial" } else { mode };
    let driver_port = if mode == "dial-coalesced" {
        spawn_coalescing_proxy(port, Duration::from_millis(1500))
    } else {
        port
    };

    let spawn_driver = |capture: &File| {
        ChildGuard::wrap(
            format!("{arm} driver"),
            Command::new(driver)
                .arg(format!("tcp/127.0.0.1:{driver_port}"))
                .arg(driver_mode)
                .stdout(capture.try_clone().expect("dup stdout handle"))
                .stderr(capture.try_clone().expect("dup stderr handle"))
                .spawn()
                .unwrap_or_else(|e| panic!("{arm}: failed to run the driver: {e}")),
        )
    };

    let mut demos: Vec<ChildGuard> = Vec::new();
    let mut driver_child;
    if dials {
        // The demo listens and the driver dials it, so the demo is ready first.
        let stderr = first_stderr.try_clone().expect("dup the demo's stderr");
        demos.push(spawn_demo(
            &demo,
            &["--listen", &format!("127.0.0.1:{port}")],
            "a-dial",
            stderr,
            arm,
        ));
        wait_for_substring(
            &mut first_stderr,
            "listening on 127.0.0.1:",
            Duration::from_secs(15),
        )
        .unwrap_or_else(|e| panic!("{arm}: the demo never listened: {e}"));
        driver_child = spawn_driver(&capture);
        wait_for_marker(&mut capture, "DONE", Duration::from_secs(40), arm);
    } else {
        driver_child = spawn_driver(&capture);
        wait_for_marker(&mut capture, "READY", Duration::from_secs(15), arm);
        let endpoint = format!("tcp/127.0.0.1:{port}");
        let stderr = first_stderr.try_clone().expect("dup the demo's stderr");
        demos.push(spawn_demo(
            &demo,
            &["--connect", &endpoint],
            "a-first",
            stderr,
            arm,
        ));
        wait_for_marker(&mut capture, "STOPPED", Duration::from_secs(30), arm);
        let second = tempfile::tempfile().expect("the second demo's stderr");
        demos.push(spawn_demo(
            &demo,
            &["--connect", &endpoint],
            "b-second",
            second,
            arm,
        ));
        wait_for_marker(&mut capture, "DONE", Duration::from_secs(40), arm);
    }

    // Let the demo's log catch up with what the driver put before it is counted.
    std::thread::sleep(Duration::from_millis(500));
    let received = received_from_the_driver(&mut first_stderr);
    for d in &mut demos {
        graceful_terminate(d.child_mut(), Duration::from_secs(5));
    }
    let status = driver_child
        .child_mut()
        .wait()
        .unwrap_or_else(|e| panic!("{arm}: waiting for the driver: {e}"));
    assert!(
        status.success(),
        "{arm}: the driver exited {status:?}\n--- its output ---\n{}",
        read_captured(&mut capture)
    );
    format!(
        "{}demo-received-from-driver={received}\n",
        read_captured(&mut capture)
    )
}

/// Compile the driver once per library and run each arm in `mode`.
fn both_arms(mode: &str) -> (String, String) {
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
    let reference = run_arm(&ref_driver, "reference", mode);
    let wz = run_arm(&wz_driver, "wz", mode);
    (wz, reference)
}

/// Every line in `needles` is in the REFERENCE arm's output, verbatim. The floor
/// comes before the equality: a reading in which nothing was ever held, or in
/// which the task was already running, would make the equality a statement about
/// the harness.
fn assert_reference_holds(reference: &str, needles: &[&str]) {
    for needle in needles {
        assert!(
            reference.lines().any(|l| l == *needle),
            "the REFERENCE arm has no `{needle}` line, so this leg is measuring the \
             harness rather than wz:\n{reference}"
        );
    }
}

fn assert_arms_agree(wz: &str, reference: &str) {
    assert_eq!(
        wz, reference,
        "wz's read task differs from the real zenoh-pico's.\n--- wz ---\n{wz}\n--- reference ---\n{reference}"
    );
}

/// A listening session opened without its read task accepts nobody and holds
/// what a later peer sends until the task is started; a put from it still
/// reaches the peer; closing it while stopped returns.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "cc-compiles a driver against both libraries and runs each against two \
            wz-ap-demo peers that dial in; run by run-ci Layer E"]
fn a_listening_session_opened_without_its_read_task_holds_traffic_until_it_is_started() {
    let (wz, reference) = both_arms("held");
    assert_reference_holds(
        &reference,
        &[
            "opened running=0",
            "before-start running=0 samples>0=0",
            "start rc=0 running=1",
            "start-again rc=0 running=1",
            "first-burst samples=5",
            "stop rc=0 running=0",
            "stop-again rc=0 running=0",
            "put-while-stopped rc=0",
            "held-while-stopped samples=0",
            "restart rc=0 running=1",
            "second-burst samples=5",
            "stop-before-close rc=0 running=0",
            "closed running=0",
            "demo-received-from-driver=1",
        ],
    );
    assert_arms_agree(&wz, &reference);
}

/// The negative arm: a session whose read task runs from the open delivers at
/// once, and stopping it still holds a peer that dials in afterwards. Without it
/// a build that held every session back would pass the leg above.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "cc-compiles a driver against both libraries and runs each against two \
            wz-ap-demo peers that dial in; run by run-ci Layer E"]
fn a_session_opened_with_its_read_task_delivers_at_once_and_stops_when_told() {
    let (wz, reference) = both_arms("default");
    assert_reference_holds(
        &reference,
        &[
            "opened running=1",
            "before-start running=1 samples>0=1",
            "start rc=0 running=1",
            "first-burst samples=5",
            "stop rc=0 running=0",
            "put-while-stopped rc=0",
            "held-while-stopped samples=0",
            "restart rc=0 running=1",
            "second-burst samples=5",
            "closed running=0",
            "demo-received-from-driver=1",
        ],
    );
    assert_arms_agree(&wz, &reference);
}

/// The same dialled session, but the demo's OPEN ack and its whole burst reach it
/// in one write: the five Puts are in its socket before it has returned from
/// `z_open`, and the subscriber that is to receive them does not exist yet. All
/// five must be there when the task is started.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "cc-compiles a driver against both libraries and runs each against a \
            wz-ap-demo listener behind a proxy; run by run-ci Layer E"]
fn a_dialled_session_whose_first_traffic_arrives_with_its_open_reads_none_of_it_until_started() {
    let (wz, reference) = both_arms("dial-coalesced");
    assert_reference_holds(
        &reference,
        &[
            "opened running=0",
            "before-start running=0 samples>0=0",
            "put-while-stopped rc=0",
            "start rc=0 running=1",
            "first-burst samples=5",
            "closed running=0",
            "demo-received-from-driver=1",
        ],
    );
    assert_arms_agree(&wz, &reference);
}

/// A dialled session opened without its read task is connected and cannot read:
/// the demo's burst waits in the socket, a put still reaches the demo, and the
/// declared subscriber sees all five once the task is started.
// wz-proves: api-compat-pico wz->pico partial
#[test]
#[ignore = "cc-compiles a driver against both libraries and runs each against a \
            wz-ap-demo listener; run by run-ci Layer E"]
fn a_dialled_session_opened_without_its_read_task_holds_traffic_until_it_is_started() {
    let (wz, reference) = both_arms("dial");
    assert_reference_holds(
        &reference,
        &[
            "opened running=0",
            "before-start running=0 samples>0=0",
            "put-while-stopped rc=0",
            "start rc=0 running=1",
            "first-burst samples=5",
            "stop rc=0 running=0",
            "closed running=0",
            "demo-received-from-driver=1",
        ],
    );
    assert_arms_agree(&wz, &reference);
}
