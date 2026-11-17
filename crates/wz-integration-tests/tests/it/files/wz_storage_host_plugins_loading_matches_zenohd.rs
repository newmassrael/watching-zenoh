// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! `plugins_loading/enabled` and `plugins_loading/search_dirs`: whether a plugin the `plugins`
//! section names WITHOUT a `__path__` is looked up by name, and where, on a wz storage host and on
//! a stock zenohd handed the same document.
//!
//! ## What upstream does with the two keys
//!
//! The plugin manager is built over the config's library loader, which is EMPTY when
//! `plugins_loading/enabled` is off and searches `plugins_loading/search_dirs` when it is on
//! (`commons/zenoh-config/src/lib.rs` @ `if self.plugins_loading.enabled {`). A plugin named
//! without a path is then looked up by name: an empty loader leaves it unloaded with a warning
//! (`plugins/zenoh-plugin-trait/src/manager/dynamic_plugin.rs` @
//! `will not be loaded as plugin loading is disabled",`), and a loader that searches
//! tries each listed directory in order for the plugin's library file, failing with the file's
//! name when no directory holds it (`commons/zenoh-util/src/lib_loader.rs` @
//! `Err(zerror!("Library file '{}' not found", filename).into())`). A plugin that is not
//! `__required__` and fails to load is logged and the node runs on
//! (`zenoh/src/api/loader.rs` @ `tracing::error!("Plugin load failure: {e}")`).
//!
//! ## The observable, and why it is the outcome of the lookup
//!
//! The document names one plugin, `wzwit`, with no path and not required. The directory a row lists
//! holds a file under each implementation's library name for it, and the file is not a library: a
//! lookup that FINDS it fails to load it and names the file it found, inside that directory. So
//! each node's log says which of three things its lookup did: it did not look (disabled), it looked
//! and found nothing in the listed directories (not found), or it found the file in the listed
//! directory (found). The names differ by one prefix and by design: upstream's is `zenoh_plugin_`
//! (`zenoh/src/api/plugins.rs` @ `pub static ref PLUGIN_PREFIX: String = "zenoh_plugin_".to_string();`),
//! the ABI its libraries are built against, and wz's is
//! `wz_runtime_tokio::plugin_search_dirs::PLUGIN_LIBRARY_PREFIX`, the ABI a wz host loads.
//!
//! ## How each node is handed the document
//!
//! Each row hands both nodes its keys in one of two readings ([`Reading`]).
//!
//! The DAEMON reading is the document as a `--config` file. zenohd turns the lookup on over
//! whatever its file says
//! (`zenohd/src/main.rs` @ `config.plugins_loading.set_enabled(true).unwrap();`), and the wz
//! storage host reads a `--config` file with every override zenohd applies, this one included,
//! so a file's `enabled: false` is looked up on both.
//!
//! The STATED reading is the key's value as the plugin plane receives it, past the daemon's
//! override. zenohd is handed the document with the key again in `--cfg`, the one channel it
//! applies after that override
//! (`zenohd/src/main.rs` @ `config.insert(key.strip_prefix('/').unwrap_or(key), &mut deserializer)`).
//! The storage host is handed the three flags a `--config` file's keys expand to, `--plugins`,
//! `--plugin-search-dirs` and `--plugins-loading`, the last only when the key is on, with no file
//! whose reading would add it.
//!
//! zenohd's row is asserted first, so an upstream that stopped looking a plugin up this way is
//! reported as that and not as a wz defect.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wz_integration_tests::bounded::BoundedChild as _;
use wz_integration_tests::common::{
    assert_demo_binary_newer_than_sources, read_captured, wait_for_substring, wz_ap_demo_binary,
    zenohd_binary, ChildGuard, PortReservation,
};
use wz_runtime_tokio::plugin_search_dirs::plugin_library_file_name;

/// The plugin the document names, by its key in the `plugins` section.
const PLUGIN: &str = "wzwit";

/// The warning a node logs for a plugin it was told not to look up by name, upstream's words and
/// the wz plugin plane's.
const DISABLED: &str = "will not be loaded as plugin loading is disabled";

/// How long a node gets to report its lookup after it was started (zenohd) or after its first
/// session (the storage host, which applies its startup `plugins` section there).
const LOOKUP_BUDGET: Duration = Duration::from_secs(20);

/// How a row hands its keys to both nodes.
#[derive(Clone, Copy, Debug)]
enum Reading {
    /// The document as a `--config` file, which each binary reads with its daemon's overrides.
    Daemon,
    /// The key's value past the daemon's override: zenohd's `--cfg`, the storage host's flags.
    Stated,
}

/// What a node's lookup of [`PLUGIN`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lookup {
    /// The lookup by name is off: the plugin was not looked for.
    Disabled,
    /// The listed directories were searched and none held the plugin's library file.
    NotFound,
    /// The plugin's library file was found in the directory the row lists.
    FoundInTheListedDirectory,
}

/// The file zenohd looks [`PLUGIN`] up as: the platform's prefix, upstream's plugin prefix, the
/// name and the platform's suffix.
fn upstream_library() -> String {
    format!(
        "{}zenoh_plugin_{PLUGIN}{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    )
}

/// The lookup a node's log reports, or `None` while it reports none yet. `library` is the file
/// name that node looks the plugin up as; `holding` the directory that holds it.
fn lookup_in(log: &str, library: &str, holding: &Path) -> Option<Lookup> {
    if log.contains(DISABLED) {
        Some(Lookup::Disabled)
    } else if log.contains(&format!("{}/{library}", holding.display())) {
        Some(Lookup::FoundInTheListedDirectory)
    } else if log.contains(&format!("Library file '{library}' not found")) {
        Some(Lookup::NotFound)
    } else {
        None
    }
}

/// Poll `capture` until it reports a lookup, failing when `node` ends or the budget runs out first.
fn await_lookup(
    node: &mut ChildGuard,
    capture: &mut File,
    library: &str,
    holding: &Path,
    who: &str,
) -> Lookup {
    let deadline = Instant::now() + LOOKUP_BUDGET;
    loop {
        let log = read_captured(capture);
        if let Some(lookup) = lookup_in(&log, library, holding) {
            return lookup;
        }
        if let Ok(Some(status)) = node.child_mut().try_wait() {
            let log = read_captured(capture);
            if let Some(lookup) = lookup_in(&log, library, holding) {
                return lookup;
            }
            panic!("{who} ended ({status}) before it reported a lookup of `{PLUGIN}`\n{log}");
        }
        if Instant::now() >= deadline {
            panic!("{who} reported no lookup of `{PLUGIN}` within {LOOKUP_BUDGET:?}\n{log}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The search list as JSON5 text, the document's value and the storage host's flag alike.
fn search_list(search_dirs: &[&Path]) -> String {
    let list = search_dirs
        .iter()
        .map(|d| format!("{:?}", d.display().to_string()))
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{list}]")
}

/// The `plugins` section every row names: one plugin without a path, not required.
fn plugins_section() -> String {
    format!("{{ {PLUGIN}: {{}} }}")
}

/// The document every node of a row is handed: the lookup switch, the search list, and one plugin
/// named without a path.
fn write_document(dir: &Path, enabled: bool, search_dirs: &[&Path]) -> PathBuf {
    let list = search_list(search_dirs);
    let section = plugins_section();
    let path = dir.join("plugins_loading.json5");
    std::fs::write(
        &path,
        format!(
            "{{\n  plugins_loading: {{ enabled: {enabled}, search_dirs: {list} }},\n  \
             plugins: {section},\n}}\n"
        ),
    )
    .expect("write the document");
    path
}

/// zenohd's lookup for the document at `document`, whose `plugins_loading/enabled` is `enabled`,
/// in `reading`.
fn zenohd_lookup(document: &Path, reading: Reading, enabled: bool, holding: &Path) -> Lookup {
    let capture = tempfile::tempfile().expect("tempfile for the zenohd log");
    let writer = capture.try_clone().expect("dup the zenohd log handle");
    let mut reader = capture;
    let mut command = Command::new(zenohd_binary());
    command
        .env("RUST_LOG", "z=info")
        .env("NO_COLOR", "1")
        .args(["-l", "tcp/127.0.0.1:0", "--no-multicast-scouting"])
        .args(["--rest-http-port", "none"])
        .arg("--config")
        .arg(document);
    if let Reading::Stated = reading {
        command
            .arg("--cfg")
            .arg(format!("plugins_loading/enabled:{enabled}"));
    }
    let mut zenohd = ChildGuard::wrap(
        "zenohd (plugins_loading reference)",
        command
            .stdout(Stdio::from(
                writer.try_clone().expect("dup the zenohd stdout handle"),
            ))
            .stderr(Stdio::from(writer))
            .spawn()
            .expect("spawn zenohd"),
    );
    let lookup = await_lookup(
        &mut zenohd,
        &mut reader,
        &upstream_library(),
        holding,
        "zenohd",
    );
    let _ = zenohd.child_mut().kill();
    let _ = zenohd.child_mut().wait_bounded();
    lookup
}

/// Whether the demo's BUILD FEATURES line names `feature`.
fn names_feature(line: &str, feature: &str) -> bool {
    line.split([' ', '[', ']']).any(|word| word == feature)
}

/// What the wz storage host is handed for a row: the document as a `--config` file, or the
/// flags its keys expand to.
enum Handed<'a> {
    /// The daemon reading of the file at this path.
    File(&'a Path),
    /// The stated reading: the plugins section, the search list and the lookup switch as flags.
    Flags {
        search_dirs: &'a [&'a Path],
        enabled: bool,
    },
}

/// The wz storage host's lookup for what it is `handed`.
fn storage_host_lookup(demo: &Path, handed: &Handed<'_>, holding: &Path) -> Lookup {
    let reservation = PortReservation::pick();
    let addr = format!("127.0.0.1:{}", reservation.port());
    let capture = tempfile::tempfile().expect("tempfile for the storage host log");
    let writer = capture
        .try_clone()
        .expect("dup the storage host log handle");
    let mut reader = capture;
    let mut command = Command::new(demo);
    command.arg("--storage-host").arg(&addr);
    match handed {
        Handed::File(document) => {
            command.arg("--config").arg(document);
        }
        Handed::Flags {
            search_dirs,
            enabled,
        } => {
            command
                .arg("--plugins")
                .arg(plugins_section())
                .arg("--plugin-search-dirs")
                .arg(search_list(search_dirs));
            if *enabled {
                command.arg("--plugins-loading");
            }
        }
    }
    let mut host = ChildGuard::wrap(
        "wz-ap-demo --storage-host (plugins_loading)",
        command
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::from(writer))
            .spawn()
            .expect("spawn the wz storage host"),
    );
    let ready = match wait_for_substring(
        &mut reader,
        "adminspace config GET at ",
        Duration::from_secs(15),
    ) {
        Ok(captured) => captured,
        Err(captured) => {
            let _ = host.child_mut().kill();
            let _ = host.child_mut().wait_bounded();
            panic!("the storage host never became ready\n--- host ---\n{captured}");
        }
    };
    drop(reservation);
    let banner = ready
        .lines()
        .find(|l| l.contains("BUILD FEATURES = ["))
        .unwrap_or_default();
    for feature in ["plugin-dynamic-loading", "zenoh-config"] {
        assert!(
            names_feature(banner, feature),
            "the wz-ap-demo was built without `{feature}`, so the document's plugin keys \
             reach no plugin plane. Build it with `--no-default-features --features \
             preset-ap-full,zenoh-config`.\n{banner}"
        );
    }
    // The host applies its startup `plugins` section on its first session, so one is opened.
    let mut client = ChildGuard::wrap(
        "wz-ap-demo client (the storage host's first session)",
        Command::new(demo)
            .arg("--connect")
            .arg(&addr)
            .arg("--publish")
            .arg("wz/plugins-loading/first-session")
            .arg("--value")
            .arg("opened")
            .env("RUST_LOG", "warn")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn the first client"),
    );
    let lookup = await_lookup(
        &mut host,
        &mut reader,
        &plugin_library_file_name(PLUGIN),
        holding,
        "the wz storage host",
    );
    let _ = client.child_mut().kill();
    let _ = client.child_mut().wait_bounded();
    let _ = host.child_mut().kill();
    let _ = host.child_mut().wait_bounded();
    lookup
}

/// Where a row's search list points.
#[derive(Clone, Copy)]
enum Listed {
    /// A directory that holds no file of the plugin.
    Empty,
    /// The directory that holds a file under each implementation's library name for it.
    Holding,
}

/// One document, how it is handed, and the lookup zenohd makes for it.
struct Row {
    name: &'static str,
    reading: Reading,
    enabled: bool,
    search_dirs: &'static [Listed],
    expect: Lookup,
}

/// Every row on zenohd first, its lookup held to the row, then on the wz storage host, held to
/// zenohd's.
fn diff_rows(rows: &[Row]) {
    let demo = wz_ap_demo_binary();
    assert_demo_binary_newer_than_sources(&demo);
    let empty = tempfile::tempdir().expect("an empty search directory");
    let holding = tempfile::tempdir().expect("the directory holding the plugin's files");
    // Not libraries: a lookup that finds one fails to load it, naming the path it found.
    for library in [upstream_library(), plugin_library_file_name(PLUGIN)] {
        std::fs::write(holding.path().join(library), b"not a shared object")
            .expect("write a plugin file");
    }
    let documents = tempfile::tempdir().expect("a directory for the documents");
    let mut disagreements = Vec::new();
    for row in rows {
        let dirs: Vec<&Path> = row
            .search_dirs
            .iter()
            .map(|listed| match listed {
                Listed::Empty => empty.path(),
                Listed::Holding => holding.path(),
            })
            .collect();
        let document = write_document(documents.path(), row.enabled, &dirs);
        let reference = zenohd_lookup(&document, row.reading, row.enabled, holding.path());
        assert_eq!(
            reference, row.expect,
            "zenohd's lookup for `{}` is not what this file expects",
            row.name
        );
        let handed = match row.reading {
            Reading::Daemon => Handed::File(&document),
            Reading::Stated => Handed::Flags {
                search_dirs: &dirs,
                enabled: row.enabled,
            },
        };
        let wz = storage_host_lookup(&demo, &handed, holding.path());
        if wz != reference {
            disagreements.push(format!(
                "{}:\n  zenohd {reference:?}\n  wz     {wz:?}",
                row.name
            ));
        }
    }
    assert!(
        disagreements.is_empty(),
        "the storage host looks a plugin up differently from zenohd on {} of {} rows:\n{}",
        disagreements.len(),
        rows.len(),
        disagreements.join("\n")
    );
}

/// `plugins_loading/enabled`: stated off, a plugin named without a path is not looked for although
/// a listed directory holds it; stated on, the same directory is searched and the plugin found
/// there; off in the file the daemon reads, the daemon's override turns it on; on the wz storage
/// host as on zenohd.
// wz-proves: plugin-dynamic-loading zenohd->wz partial
#[test]
#[ignore = "binary-dep e2e (zenohd + wz-ap-demo --features preset-ap-full,zenoh-config); \
            Layer C1bp runs via --ignored"]
fn wz_storage_host_looks_a_plugin_up_by_name_only_when_enabled_as_zenohd_does() {
    diff_rows(&[
        Row {
            name: "enabled: false stated, the listed directory holds the plugin",
            reading: Reading::Stated,
            enabled: false,
            search_dirs: &[Listed::Holding],
            expect: Lookup::Disabled,
        },
        Row {
            name: "enabled: false in the file the daemon reads, the listed directory holds it",
            reading: Reading::Daemon,
            enabled: false,
            search_dirs: &[Listed::Holding],
            expect: Lookup::FoundInTheListedDirectory,
        },
        Row {
            name: "enabled: true stated, the listed directory holds the plugin",
            reading: Reading::Stated,
            enabled: true,
            search_dirs: &[Listed::Holding],
            expect: Lookup::FoundInTheListedDirectory,
        },
    ]);
}

/// `plugins_loading/search_dirs`: a list whose directories hold no file of the plugin finds
/// nothing, and a list that names the directory holding it after one that does not finds it there,
/// on the wz storage host as on zenohd.
// wz-proves: plugin-dynamic-loading zenohd->wz partial
#[test]
#[ignore = "binary-dep e2e (zenohd + wz-ap-demo --features preset-ap-full,zenoh-config); \
            Layer C1bp runs via --ignored"]
fn wz_storage_host_searches_the_listed_directories_in_order_as_zenohd_does() {
    diff_rows(&[
        Row {
            name: "search_dirs names only a directory without the plugin",
            reading: Reading::Daemon,
            enabled: true,
            search_dirs: &[Listed::Empty],
            expect: Lookup::NotFound,
        },
        Row {
            name: "search_dirs names the holding directory after an empty one",
            reading: Reading::Daemon,
            enabled: true,
            search_dirs: &[Listed::Empty, Listed::Holding],
            expect: Lookup::FoundInTheListedDirectory,
        },
    ]);
}
