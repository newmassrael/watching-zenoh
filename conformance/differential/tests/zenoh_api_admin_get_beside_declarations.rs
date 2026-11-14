// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! A client that enables its admin space asks its own admin key again and again while another
//! thread of it declares a queryable and withdraws it without pause: upstream's crate (`up_zenoh`)
//! and wz's (`wz_zenoh`) as the router and the client, the same scenario on each, timed.
//!
//! ## The question
//!
//! A GET of the client's own key is answered by the client itself, but the query does not end
//! there: upstream's client hat routes a query from its session to its router as well, for as long
//! as no interest of the router has finalized the queryables of that key
//! (`zenoh/src/net/routing/hat/client/queries.rs` @ `if !has_interest_finalized {`), and the
//! session is told the query ended only when every face it went to has sent its final
//! (`zenoh/src/net/routing/dispatcher/queries.rs` @ `if let Some(query) = Arc::into_inner(query) {`).
//! So the router's final is behind whatever the client's link already carries towards it, the
//! declarations among it, and how long a GET takes depends on how far the router is behind the
//! declarer. The question is whether that holds for upstream too, and by how much: upstream's
//! nodes, both of them, are the control the wz pair is held against.
//!
//! What is read is what the asker sees: how long each GET took from the call to the end of its
//! replies, whether the client's own answer was among them, how long the GETs took together, and
//! how many declarations the declarer made meanwhile. The contract is a multiple of the control's
//! figures ([`SLOWER_AT_MOST`]), not an absolute bound: the control is what says which bound
//! upstream itself keeps on this host.

use std::{
    net::TcpListener,
    sync::{
        atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

/// A port nothing listens on, that the kernel never picks for a socket that binds port 0 (below
/// every platform's ephemeral range), and that no call of this function gives twice.
fn free_port() -> u16 {
    static NEXT: AtomicU16 = AtomicU16::new(0);
    loop {
        let offset = NEXT.fetch_add(1, Ordering::Relaxed);
        let port = 35_000 + ((std::process::id() % 8_000) as u16 + offset) % 14_000;
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

/// The GETs each arm asks.
const GETS: usize = 200;

/// The timeout each GET is asked with: a GET whose router never sends its final ends here.
const GET_TIMEOUT: Duration = Duration::from_secs(2);

/// How long an arm asks before it stops, whatever number of GETs it has made by then.
const BUDGET: Duration = Duration::from_secs(120);

/// How long the declarer runs alone before the first GET, so that the GETs are asked behind the
/// declarations already queued and not on an empty link.
const LEAD: Duration = Duration::from_millis(250);

/// The id the client is opened with, so its admin key is the same in every arm.
const CLIENT_ID: &str = "c1a5";

/// The id of the router.
const ROUTER_ID: &str = "a00032";

/// The key the declarer declares and withdraws.
const BESIDE: &str = "demo/beside/admin";

/// How many times the control's figure the subject's may be.
const SLOWER_AT_MOST: u32 = 2;

/// What a GET or a total may exceed that multiple by, which a host's noise moves when both figures
/// are a few milliseconds.
const NOISE: Duration = Duration::from_millis(50);

/// What one arm measured.
struct Measured {
    /// Which crate was the router and which the client.
    arm: &'static str,
    /// Each GET's time from the call to the end of its replies, in the order asked.
    gets: Vec<Duration>,
    /// The GETs whose replies held the client's own answer.
    answered: usize,
    /// How long the GETs took together.
    total: Duration,
    /// The declarations and withdrawals the declarer made from its start to the last GET's end.
    declarations: usize,
    /// How long the declarer ran until then.
    declaring: Duration,
}

impl Measured {
    /// The GET time at percentile `q` (0..=100).
    fn at(&self, q: usize) -> Duration {
        let mut sorted = self.gets.clone();
        sorted.sort_unstable();
        let index = (sorted.len() * q / 100).min(sorted.len().saturating_sub(1));
        sorted.get(index).copied().unwrap_or_default()
    }

    /// The GETs that ended on their timeout and not on the router's final.
    fn timed_out(&self) -> usize {
        let edge = GET_TIMEOUT.saturating_sub(Duration::from_millis(100));
        self.gets.iter().filter(|took| **took >= edge).count()
    }

    fn line(&self) -> String {
        format!(
            "admin-get-beside-declarations: arm={} gets={} answered={} timed_out={} total_ms={} \
             p50_ms={} p90_ms={} p99_ms={} max_ms={} declarations={} declarations_per_s={:.0}",
            self.arm,
            self.gets.len(),
            self.answered,
            self.timed_out(),
            self.total.as_millis(),
            self.at(50).as_millis(),
            self.at(90).as_millis(),
            self.at(99).as_millis(),
            self.at(100).as_millis(),
            self.declarations,
            self.declarations as f64 / self.declaring.as_secs_f64().max(f64::EPSILON),
        )
    }
}

/// Run `churn` (one declaration and its withdrawal) on a thread of its own without pause, and
/// after [`LEAD`] call `ask` (one GET, `true` when the client's own answer came) up to [`GETS`]
/// times within [`BUDGET`].
fn measure(
    arm: &'static str,
    mut churn: impl FnMut() + Send + 'static,
    mut ask: impl FnMut() -> bool,
) -> Measured {
    let stop = Arc::new(AtomicBool::new(false));
    let made = Arc::new(AtomicUsize::new(0));
    let declarer = {
        let (stop, made) = (Arc::clone(&stop), Arc::clone(&made));
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                churn();
                made.fetch_add(2, Ordering::Relaxed);
            }
        })
    };
    let declaring_since = Instant::now();
    std::thread::sleep(LEAD);
    let began = Instant::now();
    let mut gets = Vec::with_capacity(GETS);
    let mut answered = 0;
    while gets.len() < GETS && began.elapsed() < BUDGET {
        let asked = Instant::now();
        if ask() {
            answered += 1;
        }
        gets.push(asked.elapsed());
    }
    let total = began.elapsed();
    let declarations = made.load(Ordering::Relaxed);
    let declaring = declaring_since.elapsed();
    stop.store(true, Ordering::Relaxed);
    declarer.join().expect("the declarer ends");
    Measured {
        arm,
        gets,
        answered,
        total,
        declarations,
        declaring,
    }
}

macro_rules! arm {
    ($name:ident, $router:ident, $client:ident) => {
        mod $name {
            use super::*;
            use $client::Wait as _;
            use $router::Wait as _;

            /// The scenario with a router of `$router` and a client of `$client`.
            pub fn measured() -> Measured {
                let port = free_port();
                let router = $router::open(
                    $router::Config::from_json5(&format!(
                        r#"{{ id: "{ROUTER_ID}", mode: "router",
                              listen: {{ endpoints: ["tcp/127.0.0.1:{port}"] }},
                              scouting: {{ multicast: {{ enabled: false }} }} }}"#
                    ))
                    .expect("a configuration zenoh reads"),
                )
                .wait()
                .expect("the router opens");
                let client = Arc::new(
                    $client::open(
                        $client::Config::from_json5(&format!(
                            r#"{{ id: "{CLIENT_ID}", mode: "client",
                                  connect: {{ endpoints: ["tcp/127.0.0.1:{port}"] }},
                                  scouting: {{ multicast: {{ enabled: false }} }},
                                  adminspace: {{ enabled: true }} }}"#
                        ))
                        .expect("a configuration zenoh reads"),
                    )
                    .wait()
                    .expect("the client dials its router"),
                );
                let root = format!("@/{CLIENT_ID}/client");
                let churn = {
                    let client = Arc::clone(&client);
                    move || {
                        let queryable = client
                            .declare_queryable(BESIDE)
                            .callback(|_| {})
                            .wait()
                            .expect("declares");
                        queryable.undeclare().wait().expect("undeclares");
                    }
                };
                let ask = || {
                    let replies = client
                        .get(root.as_str())
                        .timeout(GET_TIMEOUT)
                        .wait()
                        .expect("asks");
                    let mut answered = false;
                    while let Ok(reply) = replies.recv() {
                        if let Ok(sample) = reply.result() {
                            answered |= sample.key_expr().to_string() == root;
                        }
                    }
                    answered
                };
                let measured = measure(
                    concat!(stringify!($router), "/", stringify!($client)),
                    churn,
                    ask,
                );
                drop(client);
                drop(router);
                measured
            }
        }
    };
}

arm!(up_router_up_client, up_zenoh, up_zenoh);
arm!(wz_router_wz_client, wz_zenoh, wz_zenoh);
arm!(up_router_wz_client, up_zenoh, wz_zenoh);
arm!(wz_router_up_client, wz_zenoh, up_zenoh);

/// The subject holds the contract against the control: each of its GETs is answered, and its
/// median GET, its 99th percentile and its total stay within [`SLOWER_AT_MOST`] times the
/// control's, give or take [`NOISE`].
fn held_against(control: &Measured, subject: &Measured) {
    assert!(
        !control.gets.is_empty() && control.answered == control.gets.len(),
        "the control is not a measurement of answered GETs: {}",
        control.line()
    );
    assert_eq!(
        subject.answered,
        subject.gets.len(),
        "a GET of the subject went unanswered: {}",
        subject.line()
    );
    assert!(
        subject.gets.len() >= control.gets.len(),
        "the subject asked fewer GETs within the budget than the control\n{}\n{}",
        control.line(),
        subject.line()
    );
    for (what, control_figure, subject_figure) in [
        ("median GET", control.at(50), subject.at(50)),
        ("99th percentile GET", control.at(99), subject.at(99)),
        ("total", control.total, subject.total),
    ] {
        assert!(
            subject_figure <= control_figure * SLOWER_AT_MOST + NOISE,
            "{what}: {subject_figure:?} against the control's {control_figure:?}, past \
             {SLOWER_AT_MOST} times it\n{}\n{}",
            control.line(),
            subject.line()
        );
    }
}

/// The wz router and client against upstream's: what upstream's own pair keeps is the bound.
#[test]
fn a_clients_own_admin_gets_beside_its_declarations_end_as_upstreams_do() {
    up_zenoh::try_init_log_from_env();
    let control = up_router_up_client::measured();
    println!("{}", control.line());
    let subject = wz_router_wz_client::measured();
    println!("{}", subject.line());
    held_against(&control, &subject);
}

/// Every pair of router and client, by the name [`ARMS_CHOSEN`] takes: the router's crate, then
/// the client's.
const ARMS: [(&str, fn() -> Measured); 4] = [
    ("up/up", up_router_up_client::measured),
    ("up/wz", up_router_wz_client::measured),
    ("wz/up", wz_router_up_client::measured),
    ("wz/wz", wz_router_wz_client::measured),
];

/// The environment variable that names the arms a measurement runs, separated by commas
/// (`wz/up` or `up/up,wz/up`), so that a profile holds one router's work alone. Unset or empty,
/// every arm runs.
const ARMS_CHOSEN: &str = "WZ_ADMIN_GET_ARMS";

/// The arms `chosen` names, in the order of [`ARMS`]; every arm for a list that names none.
/// Panics on a name that is not an arm, so that a typo does not measure nothing.
fn arms_named(chosen: Option<&str>) -> Vec<(&'static str, fn() -> Measured)> {
    let wanted: Vec<&str> = chosen
        .map(|list| {
            list.split(',')
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .collect()
        })
        .unwrap_or_default();
    for name in &wanted {
        assert!(
            ARMS.iter().any(|(arm, _)| arm == name),
            "{ARMS_CHOSEN} names `{name}`, which is not one of {:?}",
            ARMS.map(|(arm, _)| arm)
        );
    }
    ARMS.into_iter()
        .filter(|(arm, _)| wanted.is_empty() || wanted.contains(arm))
        .collect()
}

/// The mixed pairs beside the two whole ones, which say whether a difference is the router's or
/// the client's; [`ARMS_CHOSEN`] runs some of them alone.
#[test]
#[ignore = "a measurement that attributes a difference to the router or the client; run with \
            --ignored --nocapture, and WZ_ADMIN_GET_ARMS=wz/up for one arm"]
fn the_admin_gets_beside_declarations_measured_for_each_router_and_client() {
    let chosen = std::env::var(ARMS_CHOSEN).ok();
    for (_, measured) in arms_named(chosen.as_deref()) {
        println!("{}", measured().line());
    }
}

/// The choice of arms: none named is all of them, a list is those in the order of [`ARMS`], and
/// a name that is not an arm is refused.
#[test]
fn the_arms_are_chosen_by_name() {
    let names = |chosen: Option<&str>| -> Vec<&str> {
        arms_named(chosen).into_iter().map(|(arm, _)| arm).collect()
    };
    assert_eq!(names(None), ["up/up", "up/wz", "wz/up", "wz/wz"]);
    assert_eq!(names(Some("")), ["up/up", "up/wz", "wz/up", "wz/wz"]);
    assert_eq!(names(Some("wz/up")), ["wz/up"]);
    assert_eq!(names(Some(" wz/wz , up/up ")), ["up/up", "wz/wz"]);
    let refused = std::panic::catch_unwind(|| arms_named(Some("wz/zz")));
    assert!(refused.is_err(), "a name that is not an arm is refused");
}

/// The contract catches a subject that is slower than the control by more than the multiple.
#[test]
fn the_contract_sees_a_subject_slower_than_the_multiple() {
    let figures = |arm: &'static str, each: Duration| Measured {
        arm,
        gets: vec![each; 4],
        answered: 4,
        total: each * 4,
        declarations: 0,
        declaring: Duration::from_secs(1),
    };
    let control = figures("control", Duration::from_millis(100));
    let within = figures("within", Duration::from_millis(200));
    held_against(&control, &within);
    let slower = figures("slower", Duration::from_millis(300));
    let caught = std::panic::catch_unwind(|| held_against(&control, &slower));
    assert!(caught.is_err(), "a subject three times slower must fail");
}
