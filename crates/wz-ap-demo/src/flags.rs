// SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael

//! The demo's command line as one table: every flag it reads, whether the flag takes a value,
//! and the build feature without which the flag would have no effect.
//!
//! The readers elsewhere look a flag up by name and never see the words they do not look for,
//! so a misspelt flag used to start a node configured as if it had not been written (a
//! misspelt config path started a node on defaults). [`check_argv`] reads the whole command
//! line against this table before any reader does, and refuses a word the table does not name,
//! a value-taking flag with no value, and a flag whose feature this build was made without.
//!
//! The table is the population and not a sample of it: a test sweeps the crate's sources for
//! every flag literal and refuses one the table does not name, and a table row no source reads.

/// What follows a flag on the command line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Arity {
    /// The flag stands alone.
    Switch,
    /// The next word is the flag's value. A repeatable flag is one of these each time.
    Value,
}

/// One flag the demo reads.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Flag {
    pub(crate) name: &'static str,
    pub(crate) arity: Arity,
    /// The cargo feature that gives the flag its effect, and whether this build has it. A flag
    /// whose reader runs in every build but whose effect a feature compiles in names it here;
    /// without the feature the flag is refused by name rather than taken and ignored.
    pub(crate) requires: Option<(&'static str, bool)>,
}

const fn switch(name: &'static str) -> Flag {
    Flag {
        name,
        arity: Arity::Switch,
        requires: None,
    }
}

const fn value(name: &'static str) -> Flag {
    Flag {
        name,
        arity: Arity::Value,
        requires: None,
    }
}

impl Flag {
    const fn requires(self, feature: &'static str, built: bool) -> Self {
        Flag {
            requires: Some((feature, built)),
            ..self
        }
    }
}

/// Every flag the demo reads, in name order.
pub(crate) const FLAGS: &[Flag] = &[
    value("--accept-pending"),
    value("--accept-timeout-ms"),
    value("--acl-deny"),
    value("--advanced-publish"),
    value("--advanced-publish-count"),
    value("--advanced-publish-heartbeat"),
    switch("--advanced-recovery"),
    switch("--advanced-recovery-heartbeat"),
    value("--advanced-recovery-periodic"),
    value("--advanced-subscribe"),
    value("--aggregation-publishers"),
    value("--aggregation-subscribers"),
    switch("--autoconnect"),
    value("--autoconnect-strategy"),
    switch("--batch"),
    value("--batch-size"),
    value("--cache-max"),
    value("--check-sessions"),
    value("--check-topology"),
    value("--check-topology-external"),
    value("--client-node"),
    switch("--compression").requires(
        "session-extcompression",
        cfg!(feature = "session-extcompression"),
    ),
    value("--config"),
    switch("--config-queryable"),
    switch("--config-writable"),
    switch("--config-write-permit"),
    value("--connect"),
    value("--connect-after"),
    value("--connect-exit-on-failure"),
    value("--connect-retry"),
    value("--connect-scouted"),
    value("--connect-timeout"),
    value("--cpu-share"),
    value("--declare-id"),
    value("--declare-token"),
    value("--del-key").requires("pubsub-delete", cfg!(feature = "pubsub-delete")),
    value("--delete"),
    value("--device-requires"),
    value("--downsample"),
    value("--downsample-freq"),
    value("--downsample-interface"),
    value("--downsample-link-protocol"),
    switch("--driver-vocabulary"),
    value("--drop-future-timestamp"),
    switch("--express-high"),
    value("--gateway-south"),
    switch("--govern-multicast"),
    value("--group-join"),
    value("--group-lease-secs"),
    value("--group-member-id"),
    switch("--help"),
    value("--history-max"),
    value("--history-max-age"),
    value("--interest-timeout"),
    value("--key"),
    value("--lease-ms"),
    value("--link-config"),
    value("--listen"),
    value("--listen-exit-on-failure"),
    value("--listen-retry"),
    value("--listen-timeout"),
    value("--liveliness-get"),
    value("--liveliness-get-after-ms"),
    value("--liveliness-subscribe"),
    switch("--liveliness-subscribe-history"),
    value("--liveliness-subscribe-on-sample"),
    switch("--low"),
    switch("--lowlatency").requires(
        "transport-lowlatency",
        cfg!(feature = "transport-lowlatency"),
    ),
    switch("--matching-log"),
    switch("--matching-poll"),
    value("--max-data-wait"),
    value("--max-links").requires("transport-multilink", cfg!(feature = "transport-multilink")),
    value("--max-payload"),
    value("--max-sessions"),
    value("--max-wait-before-drop-fragments-us"),
    value("--metadata"),
    value("--multicast-locator"),
    value("--multicast-max-sessions"),
    switch("--multicast-qos"),
    value("--namespace"),
    switch("--no-admin-read"),
    switch("--on-query-final-log"),
    switch("--on-query-reply-log"),
    switch("--on-remote-liveliness-log"),
    switch("--on-remote-queryable-log"),
    switch("--on-remote-subscriber-log"),
    value("--open-timeout-ms"),
    value("--peer"),
    value("--peer-mode"),
    value("--plugin"),
    value("--plugin-search-dirs"),
    value("--plugins"),
    switch("--plugins-loading"),
    value("--publish"),
    value("--publish-after-ms"),
    value("--put-key"),
    value("--put-payload"),
    switch("--qos").requires("transport-qos", cfg!(feature = "transport-qos")),
    switch("--querier-matching-all-complete"),
    value("--querier-matching-log"),
    value("--query"),
    value("--query-after-ms"),
    value("--query-attachment"),
    value("--query-params"),
    value("--query-timeout-ms"),
    value("--queryable"),
    switch("--queryable-complete"),
    value("--quic-ca"),
    value("--quic-cert"),
    value("--quic-key"),
    switch("--reconnect"),
    value("--reply"),
    value("--reply-err"),
    value("--reply-keyexpr"),
    value("--router"),
    value("--router-hat"),
    value("--router-link-weight"),
    value("--rx-buffer-size"),
    value("--rx-max-message-size"),
    switch("--scout"),
    value("--scout-addr"),
    value("--scout-autoconnect"),
    value("--scout-autoconnect-strategy"),
    value("--scout-iface"),
    switch("--scout-listen"),
    value("--scout-timeout-ms"),
    value("--scout-ttl"),
    value("--scouting-delay"),
    switch("--session-close-permit"),
    switch("--session-lifecycle"),
    value("--sessions"),
    switch("--shm").requires("session-extshm", cfg!(feature = "session-extshm")),
    value("--sn-resolution"),
    value("--stats-filters"),
    value("--storage-gc-lifespan-ms"),
    value("--storage-gc-period-ms"),
    value("--storage-host"),
    value("--storage-host-dir"),
    value("--storage-volume"),
    value("--storage-volume-config"),
    value("--subscribe"),
    value("--sweep-cadence-ms"),
    value("--timestamping"),
    value("--tls-ca"),
    value("--tls-cert"),
    value("--tls-key"),
    value("--tx-batching"),
    value("--tx-batching-time-limit-ms"),
    value("--tx-queue-allocation"),
    value("--tx-queue-size-background"),
    value("--tx-queue-size-control"),
    value("--tx-queue-size-data"),
    value("--tx-queue-size-data-high"),
    value("--tx-queue-size-data-low"),
    value("--tx-queue-size-interactive-high"),
    value("--tx-queue-size-interactive-low"),
    value("--tx-queue-size-real-time"),
    switch("--unsubscribe-after-data"),
    value("--value"),
    value("--wait-before-close-us"),
    value("--wait-before-drop-us"),
    value("--zid"),
    switch("-h"),
];

/// The table's row for `word`, if it names a flag.
pub(crate) fn lookup(word: &str) -> Option<&'static Flag> {
    FLAGS.iter().find(|flag| flag.name == word)
}

/// Read the operator's command line (without the program name) against [`FLAGS`].
///
/// `Err` names the first word that is not a flag of the table, a flag of the table this build
/// lacks the feature for, or a value-taking flag with no value after it. A value is the word
/// that follows its flag, whatever it spells, except a word that is itself a flag: that is a
/// value left out, and taking the next flag as the value would hide both.
pub(crate) fn check_argv(argv: &[String]) -> Result<(), String> {
    let mut words = argv.iter();
    while let Some(word) = words.next() {
        let Some(flag) = lookup(word) else {
            return Err(if word.starts_with('-') {
                format!("unknown flag {word} (--help lists the flags this binary reads)")
            } else {
                format!(
                    "unexpected argument {word:?}: a value follows the flag it belongs to \
                     (--help lists the flags this binary reads)"
                )
            });
        };
        if let Some((feature, false)) = flag.requires {
            return Err(format!(
                "{} requires the `{feature}` feature, which this build was made without \
                 (build: cargo build -p wz-ap-demo --features {feature})",
                flag.name
            ));
        }
        if flag.arity == Arity::Value {
            match words.next() {
                Some(value) if lookup(value).is_none() => {}
                Some(other) => {
                    return Err(format!("{} needs a value before {other}", flag.name));
                }
                None => return Err(format!("{} needs a value", flag.name)),
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| (*w).to_string()).collect()
    }

    /// The flag literals of one source file: every string literal that is exactly two dashes
    /// and a flag name.
    fn flag_literals(src: &str) -> Vec<&str> {
        let mut out = Vec::new();
        let mut rest = src;
        while let Some(at) = rest.find("\"--") {
            let tail = &rest[at + 1..];
            let name_len = tail[2..]
                .find(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'))
                .unwrap_or(tail.len() - 2);
            let literal = &tail[..2 + name_len];
            if name_len > 0 && tail[2 + name_len..].starts_with('"') {
                out.push(literal);
            }
            rest = &tail[2 + name_len..];
        }
        out
    }

    /// Every module of the crate but this one: the readers, the expansion and the help text.
    const SOURCES: &[(&str, &str)] = &[
        ("main.rs", include_str!("main.rs")),
        ("args.rs", include_str!("args.rs")),
        ("runner.rs", include_str!("runner.rs")),
        ("sessions.rs", include_str!("sessions.rs")),
        ("sessions_access.rs", include_str!("sessions_access.rs")),
        (
            "sessions_facilities.rs",
            include_str!("sessions_facilities.rs"),
        ),
        ("sessions_run.rs", include_str!("sessions_run.rs")),
        ("sessions_scouting.rs", include_str!("sessions_scouting.rs")),
        ("shutdown.rs", include_str!("shutdown.rs")),
        ("stop_event.rs", include_str!("stop_event.rs")),
        ("surface.rs", include_str!("surface.rs")),
        ("tasks.rs", include_str!("tasks.rs")),
        ("teardown.rs", include_str!("teardown.rs")),
        ("usage.rs", include_str!("usage.rs")),
    ];

    /// The table is the population: a flag literal anywhere in the crate is a row, and a row
    /// is a flag some source spells. A flag added to a reader without a row would be refused
    /// as unknown by the binary that reads it.
    #[test]
    fn the_table_is_every_flag_the_sources_spell() {
        let mut spelled: Vec<&str> = SOURCES
            .iter()
            .flat_map(|(_, src)| flag_literals(src))
            .collect();
        spelled.sort_unstable();
        spelled.dedup();
        assert!(
            spelled.len() >= 150,
            "the sweep found {} flags; it has stopped matching the sources",
            spelled.len()
        );
        let missing: Vec<&str> = spelled
            .iter()
            .copied()
            .filter(|name| lookup(name).is_none())
            .collect();
        assert!(
            missing.is_empty(),
            "flags read but not in the table: {missing:?}"
        );
        let stale: Vec<&str> = FLAGS
            .iter()
            .map(|flag| flag.name)
            .filter(|name| name.starts_with("--") && !spelled.contains(name))
            .collect();
        assert!(stale.is_empty(), "table rows no source spells: {stale:?}");
    }

    #[test]
    fn the_table_names_each_flag_once_in_order() {
        for pair in FLAGS.windows(2) {
            assert!(
                pair[0].name < pair[1].name,
                "{} then {}: the table is in name order with no repeat",
                pair[0].name,
                pair[1].name
            );
        }
    }

    /// Each feature a row names is one this crate declares, so the build hint it prints is a
    /// command that works.
    #[test]
    fn every_required_feature_is_a_feature_of_this_crate() {
        let manifest = include_str!("../Cargo.toml");
        for flag in FLAGS {
            if let Some((feature, _)) = flag.requires {
                assert!(
                    manifest.contains(&format!("\n{feature} = [")),
                    "{} names `{feature}`, which Cargo.toml does not declare",
                    flag.name
                );
            }
        }
    }

    #[test]
    fn a_command_line_of_known_flags_and_their_values_passes() {
        assert_eq!(
            check_argv(&argv(&[
                "--connect",
                "tcp/127.0.0.1:7447",
                "--key",
                "demo/x",
                "--publish",
                "demo/x",
                "--value",
                "-1",
                "--reconnect",
            ])),
            Ok(())
        );
        assert_eq!(check_argv(&argv(&[])), Ok(()));
        assert_eq!(check_argv(&argv(&["-h"])), Ok(()));
    }

    #[test]
    fn an_unknown_flag_is_refused_by_name() {
        let refused = check_argv(&argv(&["--conifg", "z.json5"])).unwrap_err();
        assert!(refused.starts_with("unknown flag --conifg"), "{refused}");
        let refused = check_argv(&argv(&["--listen", "tcp/0.0.0.0:7447", "-x"])).unwrap_err();
        assert!(refused.starts_with("unknown flag -x"), "{refused}");
    }

    #[test]
    fn a_word_no_flag_takes_is_refused() {
        let refused = check_argv(&argv(&["--reconnect", "yes"])).unwrap_err();
        assert!(
            refused.starts_with("unexpected argument \"yes\""),
            "{refused}"
        );
    }

    #[test]
    fn a_value_flag_without_its_value_is_refused() {
        assert_eq!(
            check_argv(&argv(&["--key"])),
            Err("--key needs a value".to_string())
        );
        assert_eq!(
            check_argv(&argv(&["--connect", "--key", "demo/x"])),
            Err("--connect needs a value before --key".to_string())
        );
    }

    /// A flag whose effect a feature compiles in is refused by name in a build without that
    /// feature, and taken in a build with it.
    #[test]
    fn a_flag_whose_feature_is_absent_is_refused_by_name() {
        for (flag, feature, built) in [
            ("--qos", "transport-qos", cfg!(feature = "transport-qos")),
            (
                "--lowlatency",
                "transport-lowlatency",
                cfg!(feature = "transport-lowlatency"),
            ),
            (
                "--compression",
                "session-extcompression",
                cfg!(feature = "session-extcompression"),
            ),
            ("--shm", "session-extshm", cfg!(feature = "session-extshm")),
        ] {
            let verdict = check_argv(&argv(&[flag]));
            if built {
                assert_eq!(verdict, Ok(()), "{flag} in a build with `{feature}`");
            } else {
                let refused = verdict.expect_err("refused without its feature");
                assert!(
                    refused.starts_with(&format!("{flag} requires the `{feature}` feature")),
                    "{refused}"
                );
            }
        }
        let max_links = check_argv(&argv(&["--max-links", "2"]));
        assert_eq!(max_links.is_ok(), cfg!(feature = "transport-multilink"));
        let del_key = check_argv(&argv(&["--del-key", "demo/x"]));
        assert_eq!(del_key.is_ok(), cfg!(feature = "pubsub-delete"));
    }
}
