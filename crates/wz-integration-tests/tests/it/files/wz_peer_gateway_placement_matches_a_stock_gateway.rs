// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! Where a peer node that partitions its south places the remotes it dials, read side by
//! side off a stock gateway and a wz one given the same `gateway/south` rules and the same
//! two remotes.
//!
//! # The rule and the point it is read at
//!
//! The pin decides a remote's region from the node's rules: the first subregion whose
//! filters match the remote takes it, in the subregion's region of the remote's own mode,
//! and a remote no rule matches is north (`zenoh/src/net/runtime/region.rs` @
//! `fn compute_transient_region_of(`, folded with the remote's announced bound by
//! @ `pub(crate) fn compute_region_of(`). A peer node with a list of subregions builds a hat
//! per mode of each (`zenoh/src/net/routing/gateway.rs` @
//! `GatewaySouthConf::Custom(subregions) => {`).
//!
//! The decision is read where the node itself publishes it: the `region` of each
//! `sessions[]` entry of its admin root `@/<zid>/peer`, which upstream fills by running the
//! same function over the node's config (`zenoh/src/net/runtime/adminspace.rs` @
//! `region::compute_region_of(&peer, &config, transient_remote_bound.as_ref()).ok()?;`).
//! Both nodes answer the same GET, so the comparison is between two answers to one
//! question and not between one node's answer and the other's logs.
//!
//! # Topology
//!
//! * a stock peer (the pinned zenoh's `z_pub`, zid named by the first rule) and a wz peer
//!   (`wz-ap-demo --peer`, matched by the second rule, on its role), both listening, gossip
//!   off on the stock one so it meets nobody it is not dialed by;
//! * the gateway under test, which listens for the querier and dials the two remotes: a
//!   zenohd in mode `peer` from a config file, then a `wz-ap-demo --peer --gateway-south`
//!   hosting its admin space, one after the other against the same remotes;
//! * the querier, the pinned zenoh's `z_get` in mode `peer`, which the gateway places in the
//!   second subregion like the wz peer and which is left out of the comparison by its zid.
//!
//! The stock answer is required to be the rule's own reading before it is compared, so a
//! zenohd that never loaded the rules (every remote `north`) cannot make two wrong answers
//! agree.
//!
//! `#[ignore]` (binary-dep e2e): needs `target/zenohd/zenohd`, the core examples
//! `target/zenohd/zenoh_z_pub` and `zenoh_z_get` (`scripts/build-zenohd.sh`, source build),
//! and the `wz-ap-demo` binary. Loopback TCP only; no netns. Run via Layer Z / `--ignored`.

use std::fs::File;
use std::io::Write as _;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, demo_log_filter, line_with,
    parse_zenoh_admin_session_regions, read_captured, wait_for_exit, wait_for_substring,
    wait_for_tcp_accept_alive, wz_ap_demo_binary, zenoh_core_example_binary, zenohd_binary,
    ChildGuard, PortReservation, ZENOHD_TCP_ACCEPT_BUDGET,
};

/// The stock remote's zid, which the first rule names.
const STOCK_PEER_ZID: &str = "a1b2c1";

/// The wz remote's zid, which no rule names: the second rule takes it by its role.
const WZ_PEER_ZID: &str = "b1b2c1";

/// The stock gateway's zid.
const STOCK_GATEWAY_ZID: &str = "c1b2c1";

/// The wz gateway's zid.
const WZ_GATEWAY_ZID: &str = "d1b2c1";

/// The querier's zid, left out of the comparison.
const QUERIER_ZID: &str = "e1b2c1";

/// The south both gateways are given, one text: the stock remote by its zid, then every
/// other peer by its role. A remote matching the first matches the second as well, so the
/// first-match order is what the reading depends on.
const SOUTH: &str =
    r#"[ { filters: [ { zids: ["a1b2c1"] } ] }, { filters: [ { modes: ["peer"] } ] } ]"#;

/// The regions the pin's rule gives the two remotes under [`SOUTH`]: the stock peer in the
/// peer region of subregion 0, the wz peer in the peer region of subregion 1, as upstream
/// displays a region (`commons/zenoh-protocol/src/core/region.rs` @
/// `Region::South { id, mode } => write!(f, "south:{id}:{mode}"),`).
const RULE_READING: [(&str, &str); 2] = [
    (STOCK_PEER_ZID, "south:0:peer"),
    (WZ_PEER_ZID, "south:1:peer"),
];

/// The key both remotes and the wz gateway are given; nothing here is delivered on it.
const KEYEXPR: &str = "wz/placement/oracle";

/// How long a gateway has to list both remotes in its admin root.
const PLACEMENT_BUDGET: Duration = Duration::from_secs(40);

/// How long one `z_get` may run; its own query timeout is below this.
const GET_BUDGET: Duration = Duration::from_secs(15);

/// One gateway's answer: the region it gives each remote, in [`RULE_READING`]'s order,
/// and the admin body it was read from.
struct Placement {
    regions: Vec<(String, Option<String>)>,
    body: String,
}

/// GET `root` through a stock peer that dials `port`, and return the admin body it was
/// answered with, or `None` when no reply arrived.
fn get_admin_root(port: u16, root: &str) -> Option<String> {
    let output = tempfile::tempfile().expect("a file for z_get's output");
    let mut reader = output.try_clone().expect("dup z_get's output");
    let mut get = ChildGuard::wrap(
        "z_get (admin querier)",
        Command::new(zenoh_core_example_binary("z_get"))
            .args(["--mode", "peer", "-e"])
            .arg(format!("tcp/127.0.0.1:{port}"))
            .arg("--no-multicast-scouting")
            .arg("--cfg")
            .arg(format!("id:\"{QUERIER_ZID}\""))
            .arg("--cfg")
            .arg("scouting/gossip/enabled:false")
            .args(["-s", root, "-o", "5000"])
            .env("RUST_LOG", "error")
            .stdout(Stdio::from(output.try_clone().expect("dup z_get's output")))
            .stderr(Stdio::from(output))
            .spawn()
            .expect("z_get spawns"),
    );
    let _ = wait_for_exit(get.child_mut(), GET_BUDGET);
    let text = read_captured(&mut reader);
    let needle = format!(">> Received ('{root}': '");
    let line = line_with(&text, &needle)?;
    let body = line.split_once(&needle)?.1;
    Some(body.strip_suffix("')").unwrap_or(body).to_string())
}

/// GET the admin root of the gateway listening on `port` until it lists both remotes with a
/// region, and return what it placed them in.
fn read_placement(label: &str, port: u16, root: &str) -> Placement {
    let deadline = Instant::now() + PLACEMENT_BUDGET;
    let mut last = None;
    loop {
        if let Some(body) = get_admin_root(port, root) {
            let listed = parse_zenoh_admin_session_regions(&body);
            let regions: Vec<(String, Option<String>)> = RULE_READING
                .iter()
                .map(|(zid, _)| {
                    let region = listed
                        .iter()
                        .find(|(peer, _)| peer == zid)
                        .and_then(|(_, region)| region.clone());
                    (zid.to_string(), region)
                })
                .collect();
            if regions.iter().all(|(_, region)| region.is_some()) {
                return Placement { regions, body };
            }
            last = Some(body);
        }
        assert!(
            Instant::now() < deadline,
            "the {label} gateway never listed both remotes with a region in {root} within \
             {PLACEMENT_BUDGET:?}\n--- last admin body ---\n{}",
            last.as_deref().unwrap_or("(no reply)")
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// A zenohd peer from a config file: listening on `listen` for the querier, dialing every
/// port of `dial`, with [`SOUTH`] as its south. Returned once it accepts TCP, with the file
/// it was started on (held until it is killed) and its log.
fn spawn_stock_gateway(listen: u16, dial: [u16; 2]) -> (ChildGuard, tempfile::NamedTempFile, File) {
    let mut config = tempfile::Builder::new()
        .suffix(".json5")
        .tempfile()
        .expect("zenohd config file");
    write!(
        config,
        "{{ mode: \"peer\", id: \"{STOCK_GATEWAY_ZID}\", \
         listen: {{ endpoints: [\"tcp/127.0.0.1:{listen}\"] }}, \
         connect: {{ endpoints: [\"tcp/127.0.0.1:{}\", \"tcp/127.0.0.1:{}\"] }}, \
         scouting: {{ multicast: {{ enabled: false }}, gossip: {{ enabled: false }} }}, \
         gateway: {{ south: {SOUTH} }} }}",
        dial[0], dial[1]
    )
    .expect("write zenohd config");
    let log = tempfile::tempfile().expect("zenohd log");
    let reader = log.try_clone().expect("dup zenohd log");
    let mut zenohd = ChildGuard::wrap(
        "zenohd (stock gateway, mode peer)",
        Command::new(zenohd_binary())
            .arg("-c")
            .arg(config.path())
            .args(["--rest-http-port", "none"])
            .env("RUST_LOG", "error")
            .stdout(Stdio::from(log.try_clone().expect("dup zenohd log")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("spawn zenohd"),
    );
    if let Err(e) = wait_for_tcp_accept_alive(zenohd.child_mut(), listen, ZENOHD_TCP_ACCEPT_BUDGET)
    {
        panic!("zenohd (stock gateway): {e}");
    }
    (zenohd, config, reader)
}

/// A `wz-ap-demo --peer` gateway: listening on `listen` for the querier, dialing every port
/// of `dial`, with [`SOUTH`] as its south and its admin space hosted. Returned once the
/// admin space is bound, with the admin root it logged and its log.
fn spawn_wz_gateway(listen: u16, dial: [u16; 2]) -> (ChildGuard, String, File) {
    const ADMIN_KEY_NEEDLE: &str = "adminspace config GET at ";
    let demo = wz_ap_demo_binary();
    let log = tempfile::tempfile().expect("wz gateway log");
    let mut reader = log.try_clone().expect("dup wz gateway log");
    let mut gateway = ChildGuard::wrap(
        "wz-ap-demo (gateway, --peer --gateway-south)",
        Command::new(&demo)
            .arg("--peer")
            .arg(format!("127.0.0.1:{listen}"))
            .arg("--connect")
            .arg(format!("127.0.0.1:{},127.0.0.1:{}", dial[0], dial[1]))
            .args(["--gateway-south", SOUTH])
            .args(["--zid", WZ_GATEWAY_ZID, "--key", KEYEXPR])
            .arg("--config-queryable")
            .env("RUST_LOG", demo_log_filter())
            .stdout(Stdio::null())
            .stderr(Stdio::from(log))
            .spawn()
            .expect("spawn the wz gateway"),
    );
    let captured = wait_for_substring(&mut reader, ADMIN_KEY_NEEDLE, Duration::from_secs(20))
        .unwrap_or_else(|captured| {
            panic!("the wz gateway never logged its admin key\n--- wz gateway ---\n{captured}")
        });
    let config_key = line_with(&captured, ADMIN_KEY_NEEDLE)
        .and_then(|line| {
            line.split(ADMIN_KEY_NEEDLE)
                .nth(1)
                .map(|key| key.trim().to_string())
        })
        .expect("the admin key line carries the key");
    let root = config_key
        .strip_suffix("/config")
        .unwrap_or_else(|| panic!("the logged admin key is not a .../config key: {config_key}"))
        .to_string();
    if let Err(e) = wait_for_tcp_accept_alive(gateway.child_mut(), listen, ZENOHD_TCP_ACCEPT_BUDGET)
    {
        panic!("wz gateway: {e}");
    }
    (gateway, root, reader)
}

#[test]
#[ignore = "binary-dep e2e (zenohd + wz-ap-demo --features routing-peer,zenoh-config); Layer Z runs via --ignored"]
fn a_wz_peer_gateway_places_its_south_remotes_where_a_stock_gateway_does() {
    let ports = PortReservation::pick();
    let (stock_port, wz_port) = (ports.port(), ports.next_port());
    let (stock_gateway_port, wz_gateway_port) = (ports.next_port(), ports.next_port());
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);

    let said = tempfile::tempfile().expect("a file for the stock peer's output");
    let mut stock_peer = ChildGuard::wrap(
        "z_pub (stock remote)",
        Command::new(zenoh_core_example_binary("z_pub"))
            .args(["--mode", "peer", "-l"])
            .arg(format!("tcp/127.0.0.1:{stock_port}"))
            .arg("--no-multicast-scouting")
            .arg("--cfg")
            .arg(format!("id:\"{STOCK_PEER_ZID}\""))
            .arg("--cfg")
            .arg("scouting/gossip/enabled:false")
            .args(["-k", KEYEXPR])
            .env("RUST_LOG", "error")
            .stdout(Stdio::from(said.try_clone().expect("dup z_pub output")))
            .stderr(Stdio::from(said))
            .spawn()
            .expect("z_pub spawns"),
    );
    if let Err(e) =
        wait_for_tcp_accept_alive(stock_peer.child_mut(), stock_port, ZENOHD_TCP_ACCEPT_BUDGET)
    {
        panic!("z_pub (stock remote): {e}");
    }
    let mut wz_peer = ChildGuard::wrap(
        "wz-ap-demo (wz remote, --peer)",
        Command::new(&demo)
            .arg("--peer")
            .arg(format!("127.0.0.1:{wz_port}"))
            .args(["--zid", WZ_PEER_ZID, "--key", KEYEXPR])
            .env("RUST_LOG", demo_log_filter())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn the wz remote"),
    );
    if let Err(e) =
        wait_for_tcp_accept_alive(wz_peer.child_mut(), wz_port, ZENOHD_TCP_ACCEPT_BUDGET)
    {
        panic!("wz remote: {e}");
    }
    let remotes = [stock_port, wz_port];

    // The oracle first, and alone: the two gateways never hold the remotes at once.
    let stock = {
        let (mut gateway, _config, mut log) = spawn_stock_gateway(stock_gateway_port, remotes);
        let root = format!("@/{STOCK_GATEWAY_ZID}/peer");
        let placement = read_placement("stock", stock_gateway_port, &root);
        let _ = gateway.child_mut().kill();
        let _ = gateway.child_mut().wait();
        let expected: Vec<(String, Option<String>)> = RULE_READING
            .iter()
            .map(|(zid, region)| (zid.to_string(), Some(region.to_string())))
            .collect();
        assert_eq!(
            placement.regions,
            expected,
            "the stock gateway does not read the rules as the pin's source does, so it is no \
             oracle for them\n--- stock admin body ---\n{}\n--- zenohd log ---\n{}",
            placement.body,
            read_captured(&mut log)
        );
        placement
    };

    let (mut gateway, root, mut log) = spawn_wz_gateway(wz_gateway_port, remotes);
    // Every child of the leg has bound its port.
    drop(ports);
    let wz = read_placement("wz", wz_gateway_port, &root);
    let _ = gateway.child_mut().kill();
    let _ = gateway.child_mut().wait();
    assert_eq!(
        wz.regions,
        stock.regions,
        "the wz gateway places its south remotes where the stock gateway does not \
         (left: wz, right: stock)\n--- stock admin body ---\n{}\n--- wz admin body ---\n{}\n\
         --- wz gateway log ---\n{}",
        stock.body,
        wz.body,
        read_captured(&mut log)
    );

    let _ = wz_peer.child_mut().kill();
    let _ = wz_peer.child_mut().wait();
    let _ = stock_peer.child_mut().kill();
    let _ = stock_peer.child_mut().wait();
}
