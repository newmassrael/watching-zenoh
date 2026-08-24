// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// wz-ap-demo — CLI argument parsing + spec-type bundles.
//
// R285 — extracted from `main.rs` as part of Phase 1 module
// decomposition (the R281 carry). Pure code-move, no behaviour
// change. Holds:
//
//   * `Role` — `--listen` vs `--connect` discriminator;
//   * `PushOperation` — publisher_task dispatch shape (Put vs Del);
//   * `parse_pair` — argv lookup helper used by `main`;
//   * `demo_session_init_params` — role-conditional zenoh-pico
//     interop parameter block (per-role `whatami`, version,
//     resolutions, etc.);
//   * Four spec bundles (`DeclareEmitSpec`, `RemoteLogSpec`,
//     `ReplyConsumerSpec`, `QueryRoleSpec`) that ferry argv-derived
//     state from `main` into `run_demo` without inflating the
//     latter's argument list past clippy::too_many_arguments.

// R311y849 — the UNION of `parse_connect_retry`'s consumers, kept in step with
// the function's own gate below. Widening one and not the other is the same
// mistake in a smaller place: the arm compiles in and its type does not.
#[cfg(any(feature = "router-hat-router", feature = "routing-peer"))]
use wz::runtime_tokio::retry_period::RetryPolicy;
use wz::runtime_tokio::session_glue::{OsEntropy, SessionInitParams, SigningKey, WhatAmI};

/// R121f — session role select. `--listen` lands here as
/// `Acceptor`; `--connect` lands as `Initiator`. The two roles
/// drive different role-start FSM events (`InboundStart` vs
/// `OutboundStart` + `LinkOpened`) and different TCP setup
/// paths (bind+accept vs dial), but share the rest of the
/// session-FSM + outbound-publisher + inbound-subscriber wiring.
///
/// R311pw — `--reconnect` (application LIFECYCLE mode, distinct from the
/// compiled `session-reconnect` capability) rides on the `Initiator` variant
/// ONLY: zenoh-pico's `Z_FEATURE_AUTO_RECONNECT` is the CLIENT re-open path
/// (`_z_client_reopen_task_fn`), and an acceptor has no reopen-task model
/// (R311nv). Carrying the flag on the Initiator arm makes "an acceptor
/// reconnects" unrepresentable rather than a runtime guard. `reconnect = true`
/// runs the long-lived supervised lifecycle (re-dial + declaration replay on
/// link loss); `false` keeps the default round-trip-then-exit harness.
pub(crate) enum Role {
    Acceptor {
        listen: String,
        /// R311y375 — `--tls-cert <path>` / `--tls-key <path>`: the cert chain +
        /// private key PEM a `tls/...` --listen PRESENTS to a dialing peer (the
        /// accept mirror of the Initiator's `--tls-ca`, which the dialer verifies
        /// against). Feature-uniform (always parsed); `None` without the flags OR
        /// when built without the `tls` feature, in which case a `tls/...` listen
        /// surfaces the runtime's typed `Unsupported`. BOTH are required together
        /// for TLS. Read by `establish_link`'s Acceptor arm (`build_accept_config`,
        /// runner.rs); the reconnect/router paths are out of demo scope.
        tls_cert: Option<String>,
        tls_key: Option<String>,
        /// R311y401 — `--quic-cert <path>` / `--quic-key <path>`: the cert chain +
        /// private key PEM a `quic/...` --listen PRESENTS to a dialing peer (the
        /// QUIC twin of `tls_cert` / `tls_key`; SEPARATE flags because the demo builds
        /// QUIC's own server config (TLS-1.3 + ALPN hq-29) from them — the cert PEM
        /// itself is interchangeable, only the built ServerConfig differs).
        /// Feature-uniform (always parsed); `None` without the flags OR when built
        /// without the `quic` feature, in which case a `quic/...` listen surfaces the
        /// runtime's typed `Unsupported`. BOTH are required together for QUIC. Read
        /// by `establish_link`'s Acceptor arm (`build_accept_config`, runner.rs).
        quic_cert: Option<String>,
        quic_key: Option<String>,
        /// R311y505 — `--shm` on the ACCEPT side, and it is the arm that matters.
        ///
        /// zenoh sends its `Shm` challenge on the InitSyn unconditionally when the
        /// feature is built (`establishment/open.rs:152`), but on the InitAck only
        /// in REPLY to one it understood (`ext/shm.rs:455` returns `None` for an
        /// absent input). So a wz that only DIALS never receives a real zenoh
        /// `Shm` ext, and the question that matters — does wz's
        /// `peer_offered_shm` mistake zenoh's ZBuf@0x2 for its own UNIT@0x2 —
        /// stays untested. Only a wz ACCEPTOR that a zenohd dials gets that ext
        /// on the wire, and only one that OFFERS starts from `is_shm = true`, so
        /// a false positive is visible as `true` instead of `false`.
        shm: bool,
    },
    /// R311y365 — `tls_ca` is the `--tls-ca <path>` root-CA PEM a `tls/...`
    /// --connect verifies zenoh's/the peer's server cert against (server name
    /// `localhost`). ALWAYS present (feature-uniform match sites); `None` when
    /// no `--tls-ca` was given OR the demo was built without the `tls` feature,
    /// so a `tls/...` dial then surfaces the runtime's typed `Unsupported`. Only
    /// the one-shot `establish_link` reads it (the reconnect path is out of demo
    /// scope, runner.rs).
    Initiator {
        connect: String,
        reconnect: bool,
        tls_ca: Option<String>,
        /// R311y366 — the `--quic-ca <path>` root-CA PEM a `quic/...` --connect
        /// verifies the peer's server cert against (server name `localhost`), the
        /// QUIC sibling of `tls_ca`. Feature-uniform (always present on the match
        /// sites); `None` when no `--quic-ca` was given OR the demo was built
        /// without the `quic` feature, so a `quic/...` dial then surfaces the
        /// runtime's typed `Unsupported`. Read only by the one-shot
        /// `establish_link` (runner.rs).
        quic_ca: Option<String>,
        /// R311y369 — the `--namespace <prefix>` keyexpr namespace an Initiator
        /// installs on its opened session (`set_namespace`), so outbound keyexprs
        /// are prefixed `<prefix>/<key>` on the wire. Feature-uniform (always
        /// parsed); `None` without `--namespace` OR when built without the
        /// `namespace` feature, in which case the flag is inert. Applied once, on
        /// the one-shot open (runner.rs; reconnect is out of demo scope).
        namespace: Option<String>,
        /// R311y372 — `--lowlatency` offers the Z_EXT_LOWLATENCY transport ext on
        /// the InitSyn, so a peer that also offers it negotiates the lean
        /// transport that drops the Frame(sn) wrapper on the data path.
        /// Feature-uniform (always parsed + banner-logged); `false` without
        /// `--lowlatency` OR when the demo was built without the
        /// `transport-lowlatency` feature, in which case the flag is inert.
        /// R311y435 moved WHERE that inertness is decided: the flag now feeds
        /// `runner::initiator_offer`, which drops an unbuildable capability from
        /// the `SessionOffer` before the library sees it, because the library
        /// seam (`SessionLinkActions::apply_offer`) deliberately ERRORS on one
        /// instead of downgrading. Initiator-only and one-shot-only, like
        /// `namespace`: the reconnect path is out of demo scope, and an
        /// acceptor's lowlatency offer is not exercised by the demo.
        lowlatency: bool,
        /// R311y433 — `--compression` offers the Z_EXT_COMPRESSION unit ext (id
        /// 0x6) on the InitSyn, so a peer that also offers it negotiates the
        /// per-batch lz4 wrap on every post-establishment batch. Feature-uniform
        /// and inert-when-unbuilt on the same `initiator_offer` seam as
        /// `lowlatency`; initiator-only and one-shot-only.
        ///
        /// COMBINABLE with `--lowlatency` since R311y435, and the history is
        /// worth keeping because the guard outlived its reason by a round.
        /// R311y433 rejected the pair as having no coherent cross-impl wire
        /// meaning; R311y434 showed that was true only of a wz defect (wz wrapped
        /// compression OUTSIDE the lean encode, while zenoh's lean transport
        /// serializes straight to the link behind a 4-byte length prefix and
        /// never touches `WBatch` / `BatchHeader` —
        /// `zenoh-transport-1.5.0` `unicast/lowlatency/link.rs:33-73`), fixed it,
        /// and kept the rejection for a narrower LOCAL reason: `session_open` had
        /// one entrypoint per MODE and none staged both offers. R311y435's
        /// `initiate_and_open_session_with_offer` takes the SET, so that reason
        /// is gone and the guard went with it. On a lean link the negotiated wrap
        /// is INERT in wz exactly as in zenoh.
        compression: bool,
        /// R311y505 — `--shm` offers the SHM establishment capability on the
        /// InitSyn: a UNIT ext at id 0x2 (`extshm::SHM_ESTABLISHMENT_EXT_ID`),
        /// ANDed against whatever the peer reflects.
        ///
        /// It exists to put that offer in front of a FOREIGN peer, which nothing
        /// could do before: the library has carried
        /// `SessionOffer::with_shm` and `connect_and_open_session_with_shm` since
        /// R3b, but no spawnable binary ever set them, so the one extension wz
        /// places in zenoh's establishment ext space had never been on a wire a
        /// real zenohd read.
        ///
        /// Same `initiator_offer` seam as `lowlatency` / `compression`:
        /// feature-uniform, inert when `session-extshm` is unbuilt,
        /// initiator-only and one-shot-only. Combinable with both.
        shm: bool,
    },
}

/// R219 — publisher-task operation kind. `Put` carries the
/// application payload (`--value <text>`); `Delete` is payload-
/// less (zenoh-pico's `z_delete` wire form: `MsgDel` body, no
/// `payload_len`/`payload` fields). The same publisher_task drives
/// both shapes — Established-gating, optional `DECLARE` preamble,
/// and the BURST_COUNT emission loop are invariant; only the
/// inner action call (`send_push_literal`/`_aliased` vs
/// `send_push_del_literal`/`_aliased`) differs at the dispatch
/// site.
#[derive(Clone, Debug)]
pub(crate) enum PushOperation {
    Put { value: String },
    Delete,
}

/// R311y497 — the `--storage-volume <path.so>` + `--storage-volume-config <text>`
/// pair, as ONE value.
///
/// A struct rather than two `Option<String>` parameters threaded side by side into
/// [`crate::runner::run_storage_host`]: two adjacent same-typed optionals are the
/// shape a caller silently transposes, and a transposed pair here would `dlopen`
/// the operator's config text and hand the volume its own path as a directory.
/// The config is `Option` INSIDE the struct because a volume may legitimately need
/// none, while a path is what makes the whole thing exist.
///
/// Deliberately singular where `--plugin` is plural: a host loads a SET of
/// plugins, but a dynamic volume is configured, and pairing an i-th config to an
/// i-th path by argv order is an operator interface that misfires silently. One
/// loaded volume is the honest MVP bound; N is a mechanical follow-up that needs a
/// pairing syntax, not a second `Vec`.
/// R311y503 — `--storage-gc-period-ms <ms>` / `--storage-gc-lifespan-ms <ms>`:
/// the per-storage garbage-collection policy every storage this host spawns is
/// created with.
///
/// In zenoh this is per-storage CONFIG FILE state
/// (`garbage_collection: { period_s, lifespan_s }`, `backend-traits/config.rs`),
/// read by the host when it spawns the storage — NOT something a remote client
/// writes. The demo has no config file, so its flags are that surface, and they
/// are deliberately host-side for the same reason: the `storage-add` wire intent
/// carries a name and a keyexpr, and letting a remote peer choose how long this
/// node retains metadata would be a policy decision on the wrong side of the
/// admin gate.
///
/// Absent flags mean zenoh's defaults (30 s period, 86400 s lifespan), which is
/// what [`GarbageCollectionConfig::default`] already supplies — so the struct
/// carries only the OVERRIDES and an un-flagged host is byte-identical to the
/// pre-R311y503 one.
#[cfg(feature = "adminspace-config-hotreload")]
#[derive(Default, Clone, Copy)]
pub(crate) struct StorageGcArgs {
    /// Sweep interval override, in milliseconds.
    pub(crate) period_ms: Option<u64>,
    /// Metadata-age cutoff override, in milliseconds. `0` collects every entry
    /// on the next sweep, which is how a test makes a 24-hour default observable
    /// without waiting a day.
    pub(crate) lifespan_ms: Option<u64>,
}

#[cfg(feature = "adminspace-config-hotreload")]
pub(crate) struct DynamicVolumeArgs {
    /// The `.so` to `dlopen`. The volume's registry id is NOT taken from here —
    /// it is what the `.so` itself declares, so two different libraries cannot be
    /// registered under one operator-chosen name.
    pub(crate) path: String,
    /// The volume's own configuration string, verbatim. Its meaning belongs to the
    /// volume; the bundled example volume reads it as a root directory.
    pub(crate) config: Option<String>,
}

/// Every `<flag> <value>` pair in `args`, in argv order.
///
/// R311y492 — `--plugin` is repeatable because a plugin HOST loads a set, not a
/// singleton, and `parse_pair` silently keeps only the first. A flag that
/// accepts one value while its concept is plural is the shape that makes an
/// operator's second `--plugin` disappear without a word.
///
/// R2072 — the `zenoh-config` arm joined the gate rather than getting a second
/// splitter of its own: `--check-topology` is plural for the same reason
/// `--plugin` is, and a near-copy here would be a second opinion about what
/// "repeatable" means.
#[cfg(any(feature = "adminspace-config-hotreload", feature = "zenoh-config"))]
pub(crate) fn parse_repeated(args: &[String], flag: &str) -> Vec<String> {
    args.windows(2)
        .filter(|w| w[0] == flag)
        .map(|w| w[1].clone())
        .collect()
}

pub(crate) fn parse_pair(args: &[String], flag: &str) -> Option<String> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == flag {
            return it.next().cloned();
        }
    }
    None
}

/// R311y842 — turn the stock zenoh config an operator already has into the
/// argv this binary would otherwise have to be given by hand.
///
/// ## Why an argv EXPANSION rather than a second configuration path
///
/// Every flag below already has a meaning, a parser and tests. A `--config`
/// that reached past them into the runtime would be a second way to say the
/// same things, and the two would drift the first time a flag's semantics
/// moved. Expanding the file into the argv the operator would have typed keeps
/// exactly one configuration path and makes the translation a pure function
/// over strings — which is why this is testable without a session, a socket or
/// a file.
///
/// ## The mapping, and why each case
///
/// | the config says | argv gains |
/// |---|---|
/// | `mode: "router"` + a listen endpoint | `--router <ep>` |
/// | `mode: "peer"` + listen AND connect | `--peer <listen>` `--connect <a,b>` |
/// | a listen endpoint otherwise | `--listen <ep>` |
/// | a connect endpoint, nothing listening | `--connect <ep>` |
/// | `transport/unicast/max_links` | `--max-links <n>` |
/// | `transport/unicast/qos/enabled: true` | `--qos` |
/// | `transport/unicast/lowlatency: true` | `--lowlatency` |
/// | `transport/unicast/compression/enabled: true` | `--compression` |
/// | `transport/link/tx/batch_size` | `--batch-size <n>` |
/// | `transport/link/tx/lease` | `--lease-ms <n>` |
/// | an `adminspace` block at all | `--config-queryable` |
/// | `adminspace/permissions/read: false` | `--no-admin-read` |
/// | `adminspace/permissions/write: true` | `--config-writable` `--config-write-permit` |
///
/// R311y843 added the lower nine rows. R311y842 shipped the reader with only
/// the upper five wired, so eight of the fourteen keys it reports as
/// "honoured" reached nothing — a report that is true about the reader and
/// false about the node, which is a worse position than not reading them at
/// all. `every_key_the_reader_calls_honoured_reaches_the_demo_or_is_named_as_dropped`
/// is the gate that keeps the two halves together.
///
/// zenoh states the admin space as ONE `permissions.write`; wz splits it into
/// hosting the write subscriber (`--config-writable`) and permitting the write
/// (`--config-write-permit`), so the single upstream key expands to both —
/// either alone yields a node that does not do what the operator's file says.
///
/// A role the command line ALREADY named is left alone: the file supplies
/// defaults, the command line overrides them, which is the precedence zenohd
/// itself uses for its own `--listen` against a `-c` file.
///
/// Only keys the document NAMED are applied — never a value that merely
/// resolved to a default. `qos` reads `true` out of a config that never
/// mentions it, so acting on the merged value would add `--qos` to every
/// invocation and change the transport an operator asked for.
#[cfg(feature = "zenoh-config")]
pub(crate) fn expand_stock_zenoh_config(
    rest: &[String],
    read_file: impl FnOnce(&str) -> Result<String, String>,
) -> Result<Option<StockConfigExpansion>, String> {
    expand_stock_zenoh_config_for_build(
        rest,
        read_file,
        wz::runtime_tokio::compiled_in_link_schemes(),
    )
}

/// [`expand_stock_zenoh_config`] with the reader's link census named rather
/// than taken from this binary.
///
/// R2070 (open-debt item 487) — one function was answering two questions that
/// only look alike. "Does this key reach a flag" is about the READER's
/// key→flag mapping and is true or false whatever links are compiled in;
/// "can this node open that endpoint" is about the BUILD and is the refusal
/// this seam gained in R2070. They collided the moment the second arrived: the
/// honoured-key coverage fixture states the TLS root-CA case over a `tls/...`
/// endpoint, because `--tls-ca` has an endpoint-scheme precondition, and on a
/// default build that file is now refused before any key is read. Naming the
/// census makes each test say which of the two it is judging.
#[cfg(feature = "zenoh-config")]
pub(crate) fn expand_stock_zenoh_config_for_build(
    rest: &[String],
    read_file: impl FnOnce(&str) -> Result<String, String>,
    compiled_in_schemes: &[&str],
) -> Result<Option<StockConfigExpansion>, String> {
    use wz::runtime_tokio::zenoh_config::ZenohNodeConfig;

    let Some(path) = parse_pair(rest, "--config") else {
        return Ok(None);
    };
    let source = read_file(&path)?;
    let ingest =
        ZenohNodeConfig::from_json5(&source).map_err(|e| format!("--config: {path}: {e}"))?;
    // A defect is refused HERE rather than surfacing as a failed bind some
    // milliseconds later, which is the whole reason `validate` exists.
    //
    // R2070 (open-debt item 487) — and the reader passes its OWN link census,
    // because a config that is perfectly correct for the stock zenohd it was
    // written for can still name a scheme THIS demo binary was not built with.
    // `validate()` alone judged the file for zenohd and let `vsock/...` or
    // `ws/...` through on a default build, which put the failure back in the
    // post-start log this refusal exists to precede.
    let defects = ingest.config.validate_for_build(Some(compiled_in_schemes));
    if !defects.is_empty() {
        let mut msg = format!("--config: {path} cannot work:");
        for d in &defects {
            msg.push_str("\n  ");
            msg.push_str(&d.to_string());
        }
        return Err(msg);
    }

    let named = |key: &str| ingest.named.contains(&key);
    let cfg = &ingest.config;
    let mut added: Vec<String> = Vec::new();

    // The role flags, as a set: naming ANY of them on the command line means
    // the operator has chosen the topology and the file must not second-guess
    // it. `--scout` is here because it is a role too (discover, do not dial).
    const ROLE_FLAGS: &[&str] = &[
        "--listen",
        "--connect",
        "--router",
        "--peer",
        "--storage-host",
        "--scout",
    ];
    let role_on_cli = rest.iter().any(|a| ROLE_FLAGS.contains(&a.as_str()));
    if !role_on_cli {
        let listen = cfg.listen.first();
        let connect = &cfg.connect;
        match (cfg.mode, listen, connect.is_empty()) {
            (WhatAmI::Router, Some(ep), _) => {
                added.push("--router".into());
                added.push(ep.clone());
            }
            (WhatAmI::Peer, Some(ep), false) => {
                added.push("--peer".into());
                added.push(ep.clone());
                added.push("--connect".into());
                added.push(connect.join(","));
            }
            (_, Some(ep), _) => {
                added.push("--listen".into());
                added.push(ep.clone());
            }
            (_, None, false) => {
                added.push("--connect".into());
                added.push(connect[0].clone());
            }
            (_, None, true) => {}
        }
    }
    if named("transport/unicast/max_links") && !rest.iter().any(|a| a == "--max-links") {
        added.push("--max-links".into());
        added.push(cfg.max_links.to_string());
    }
    if named("transport/unicast/qos/enabled") && cfg.qos && !rest.iter().any(|a| a == "--qos") {
        added.push("--qos".into());
    }
    if named("transport/unicast/lowlatency")
        && cfg.lowlatency
        && !rest.iter().any(|a| a == "--lowlatency")
    {
        added.push("--lowlatency".into());
    }
    if named("transport/unicast/compression/enabled")
        && cfg.compression
        && !rest.iter().any(|a| a == "--compression")
    {
        added.push("--compression".into());
    }
    // The two that reach the WIRE rather than a local policy: `batch_size` and
    // `lease` are InitSyn / OpenSyn fields, so a dropped one is not a setting
    // that failed to apply but a value the peer is told and the operator was
    // not. Unlike the booleans above these are honoured at ANY value, because
    // there is no "off" for them — the file naming the key is the instruction.
    if named("transport/link/tx/batch_size") && !rest.iter().any(|a| a == "--batch-size") {
        added.push("--batch-size".into());
        added.push(cfg.batch_size.to_string());
    }
    if named("transport/link/tx/lease") && !rest.iter().any(|a| a == "--lease-ms") {
        added.push("--lease-ms".into());
        added.push(cfg.lease_ms.to_string());
    }
    // R311y844 — the ten keys wz already acted on. Each row is a flag that has
    // been in this binary for rounds, so what changed is not the capability but
    // the ability to ask for it from the file an operator already has. The
    // value-carrying ones honour ANY value (there is no "off" for a path or a
    // timeout, so naming the key IS the instruction); the two booleans follow
    // the rule the rest of this function uses and act only on a named `true`,
    // because acting on a merged default would add a flag to every invocation.
    // The TLS material is gated on the ENDPOINT SCHEME, which is the third kind
    // of precondition this round had to learn (after a cargo feature and a
    // sibling flag). `--tls-ca` opens its file EAGERLY — measured, as
    // `wz-ap-demo: No such file or directory (os error 2)` out of a `tcp/`
    // connect whose config happened to carry a CA path — so expanding it for a
    // node with no TLS link turns a valid config into a node that will not
    // start. zenoh scopes these keys to TLS links; so does this.
    let dials_tls = cfg.connect.iter().any(|e| e.starts_with("tls/"));
    let listens_tls = cfg.listen.iter().any(|e| e.starts_with("tls/"));
    for (key, flag, value, usable) in [
        ("id", "--zid", cfg.id.as_ref(), true),
        ("namespace", "--namespace", cfg.namespace.as_ref(), true),
        (
            "transport/link/tls/root_ca_certificate",
            "--tls-ca",
            cfg.tls_root_ca.as_ref(),
            dials_tls,
        ),
        (
            "transport/link/tls/listen_certificate",
            "--tls-cert",
            cfg.tls_listen_certificate.as_ref(),
            listens_tls,
        ),
        (
            "transport/link/tls/listen_private_key",
            "--tls-key",
            cfg.tls_listen_private_key.as_ref(),
            listens_tls,
        ),
    ] {
        if let Some(value) = value {
            if usable && named(key) && !rest.iter().any(|a| a == flag) {
                added.push(String::from(flag));
                added.push(value.clone());
            }
        }
    }
    // The millisecond keys, each gated on the PRECONDITION its flag carries.
    //
    // R311y844 measured this rather than assuming it, and the measurement
    // changed the round: four of the ten flags exit(2) when their precondition
    // is unmet — `--scout-timeout-ms requires --scout`, `--query-timeout-ms
    // requires --query`, and the two feature ones — so a first cut that emitted
    // them unconditionally turned an operator's VALID stock config into a node
    // that refuses to start, which is strictly worse than the "reported and
    // ignored" it replaced. Those rejections exist for a HAND-TYPED flag, where
    // silence would lose an instruction the operator gave directly; a key that
    // arrives inside a file full of keys wz cannot all act on is the opposite
    // case, and the honest answer there is to leave the flag off.
    let preconditioned: [(&str, &str, Option<u64>, bool); 3] = [
        (
            "queries_default_timeout",
            "--query-timeout-ms",
            cfg.queries_default_timeout_ms,
            rest.iter().any(|a| a == "--query"),
        ),
        (
            "routing/interests/timeout",
            "--interest-timeout",
            cfg.interests_timeout_ms,
            cfg!(feature = "routing-interest-pending-gc"),
        ),
        (
            "scouting/timeout",
            "--scout-timeout-ms",
            cfg.scouting_timeout_ms,
            rest.iter().any(|a| a == "--scout"),
        ),
    ];
    for (key, flag, value, usable) in preconditioned {
        if let Some(value) = value {
            if usable && named(key) && !rest.iter().any(|a| a == flag) {
                added.push(String::from(flag));
                added.push(value.to_string());
            }
        }
    }
    // R311y846 — whether the node is FINDABLE (`scouting/multicast/listen`).
    // Decided BEFORE the socket keys below, because it is one of their
    // preconditions: the group an operator names applies to answering as much as
    // to asking, and a config carrying `listen: true` alongside `address:` must
    // expand to both flags or to neither.
    //
    // Its own precondition is `--peer`, mirroring `--scout`'s: the responder is
    // spawned from `run_peer`'s advertise seam, so the flag is read there and
    // nowhere else, and emitting it into another mode would hand the binary an
    // argument it exits(2) on. The `cfg!` guard is the R311y844 rule — a key
    // whose sink is compiled out must not turn a valid stock config into a node
    // that refuses to start.
    //
    // R311y849 — the `--peer` precondition is met by the command line OR by
    // `added`, and the fix is not cosmetic. `--peer` is what the ROLE expansion
    // above emits for a `mode: "peer"` file, so before this round the key was
    // honoured only when the operator ALSO typed the role — and the invocation a
    // drop-in actually performs is `wz-ap-demo --config their.json5` and nothing
    // else. Measured by a test written against the old code: that invocation
    // expanded to `["--peer", …, "--connect", …]` with no `--scout-listen`, so
    // the node R311y846 made findable came up invisible on precisely the path
    // R311y846 exists to serve. `--scout` needs no such treatment: it is a role
    // the expansion never emits, so only a typed one can exist.
    let role_dials_as_peer = rest.iter().chain(added.iter()).any(|a| a == "--peer");
    let listen_expanded = cfg!(feature = "scouting-responder")
        && named("scouting/multicast/listen")
        && cfg.scout_multicast_listen == Some(true)
        && role_dials_as_peer
        && !rest.iter().any(|a| a == "--scout-listen");
    if listen_expanded {
        added.push("--scout-listen".into());
    }
    // R311y845 — WHERE the node looks for its peers. Same precondition as
    // `scouting/timeout` above (`--scout` on the command line), because the
    // three flags carry the same one: a scouting socket is an instruction to a
    // node that is scouting, and the demo rejects it otherwise. R311y846 widened
    // "is scouting" to include the answering direction, which joins the same
    // socket.
    let scouting = rest.iter().any(|a| a == "--scout")
        || rest.iter().any(|a| a == "--scout-listen")
        || listen_expanded;
    for (key, flag, value) in [
        (
            "scouting/multicast/address",
            "--scout-addr",
            cfg.scout_multicast_address.clone(),
        ),
        (
            "scouting/multicast/interface",
            "--scout-iface",
            cfg.scout_multicast_interface.clone(),
        ),
        (
            "scouting/multicast/ttl",
            "--scout-ttl",
            cfg.scout_multicast_ttl.map(|t| t.to_string()),
        ),
    ] {
        if let Some(value) = value {
            if scouting && named(key) && !rest.iter().any(|a| a == flag) {
                added.push(String::from(flag));
                added.push(value);
            }
        }
    }
    // R311y849 — `connect/retry` -> `--connect-retry <init>,<max>,<factor>`.
    //
    // The precondition is a run mode that DIALS, which is `--peer` or
    // `--router-hat`: those two own a connect list, and they are the only arms
    // that read the flag. A node with neither exits(2) on an argument it has no
    // parse for, so a stock config carrying `connect.retry` alongside a
    // `--listen` invocation must expand to nothing rather than to a refusal.
    //
    // The `cfg!` guard is the R311y844 rule and it is the UNION of the two arms'
    // features, matching the parser's own gate: a build with neither compiled in
    // has no sink, and expanding into it would turn a valid stock config into a
    // node that will not start.
    // The precondition is checked against the command line AND `added`, and the
    // second half is the whole drop-in case: when the operator names no role the
    // FILE supplies one, and that `--peer` is pushed into `added` above — it
    // never appears in `rest`. A test that looked only at what was typed would
    // withhold the flag from `wz-ap-demo --config their.json5` and nothing else,
    // which is the single invocation this path exists for. Measured, by a test
    // written before the fix: the config-only expansion came out
    // `["--peer", …, "--connect", …]` with no schedule at all.
    let dials = rest
        .iter()
        .chain(added.iter())
        .any(|a| a == "--peer" || a == "--router-hat");
    if named("connect/retry")
        && cfg!(any(feature = "routing-peer", feature = "router-hat-router"))
        && dials
        && !rest.iter().any(|a| a == "--connect-retry")
    {
        if let Some(retry) = cfg.connect_retry {
            added.push("--connect-retry".into());
            // Rendered in the flag's own three-comma-separated spelling, and
            // re-parsed by `parse_connect_retry` downstream on purpose: that
            // parser is the single place the acceptance POLICY lives (a factor
            // below 1.0 is refused there and nowhere else), so a config file
            // reaches the same boundary a command line does.
            added.push(format!(
                "{},{},{}",
                retry.period_init_ms, retry.period_max_ms, retry.period_increase_factor
            ));
        }
    }
    // R2063 (open-debt item 214) — `routing/peer/mode` reaches the flag that
    // implements it.
    //
    // Emitted only for `peer-to-peer`, because `linkstate` is what an absent
    // `--peer-mode` already means: adding the flag for the default would put a
    // word on the command line that changes nothing, and R311y844's rule for
    // this expansion is that an added flag is a DIFFERENCE the file asked for.
    // Withheld when the operator typed the flag, on the same rule every arm
    // here follows -- an explicit argv beats a file.
    if named("routing/peer/mode") && !cfg.peer_linkstate && !rest.iter().any(|a| a == "--peer-mode")
    {
        added.push("--peer-mode".into());
        added.push("peer-to-peer".into());
    }
    if named("transport/multicast/qos/enabled")
        && cfg.multicast_qos
        && cfg!(feature = "transport-qos")
        && !rest.iter().any(|a| a == "--multicast-qos")
    {
        added.push("--multicast-qos".into());
    }
    if named("transport/shared_memory/enabled")
        && cfg.shared_memory
        && !rest.iter().any(|a| a == "--shm")
    {
        added.push("--shm".into());
    }
    // The adminspace block, whose three upstream keys expand to four wz flags.
    // Keyed on the BLOCK rather than on `adminspace/enabled`, because a
    // document that names only a permission still describes an admin space —
    // that is the same reading `from_json5` takes when it builds the Option.
    if let Some(admin) = &cfg.adminspace {
        if !rest.iter().any(|a| a == "--config-queryable") {
            added.push("--config-queryable".into());
        }
        if !admin.read && !rest.iter().any(|a| a == "--no-admin-read") {
            added.push("--no-admin-read".into());
        }
        if admin.write {
            if !rest.iter().any(|a| a == "--config-writable") {
                added.push("--config-writable".into());
            }
            if !rest.iter().any(|a| a == "--config-write-permit") {
                added.push("--config-write-permit".into());
            }
        }
    }

    let mut argv: Vec<String> = rest.to_vec();
    argv.extend(added.iter().cloned());
    Ok(Some(StockConfigExpansion {
        path,
        argv,
        added,
        named: ingest.named,
        ignored: ingest.ignored,
    }))
}

/// What [`expand_stock_zenoh_config`] made of an operator's config file.
///
/// `ignored` is carried out rather than logged inside so the caller decides
/// where it goes — and so a test can assert on it as a value.
#[cfg(feature = "zenoh-config")]
#[derive(Debug)]
pub(crate) struct StockConfigExpansion {
    /// The file that was read.
    pub(crate) path: String,
    /// The command line the rest of `main` should parse.
    pub(crate) argv: Vec<String>,
    /// Only what the file contributed, in the order it was appended.
    pub(crate) added: Vec<String>,
    /// The honoured keys the file actually named.
    pub(crate) named: Vec<&'static str>,
    /// The keys the file carried that wz does not honour.
    pub(crate) ignored: Vec<String>,
}

/// R2072 (open-debt item 496) — `--check-topology <file>`, once per node:
/// answer the SET question about a whole deployment before any of it starts.
///
/// ## Why a surface of its own, and not a widening of `--config`
///
/// [`expand_stock_zenoh_config`] reads the ONE file this process is about to
/// become, and `validate_topology` cannot be reached from there. That node's
/// `connect` list points OUTSIDE a set of one, so every entry in it would come
/// back as a dangling target and the operator would be told their working
/// deployment is broken — the exact false positive R2070b built its controls
/// against. The set question needs the set, and only a caller holding every
/// node's file can supply it. This is that caller: R2070b shipped the verdict
/// with no consumer, and a verdict nothing asks for is a verdict nobody gets.
///
/// ## What the files are read as
///
/// A CLOSED deployment. "No node listens on it" means no node AMONG THESE, so
/// handing this a fragment is answerable and the answer is its outward dials —
/// the contract `validate_topology` states, surfaced here rather than
/// softened. Nothing is started, resolved or probed: the verdict is a property
/// of the documents, so it reproduces on a machine with no network.
///
/// Per-node defects are collected FIRST and named with the file that carried
/// them, because a set verdict over a config that cannot work on its own would
/// answer the harder question while the easier one is still open.
#[cfg(feature = "zenoh-config")]
pub(crate) fn check_topology(
    rest: &[String],
    read_file: impl FnMut(&str) -> Result<String, String>,
) -> Option<Result<String, String>> {
    check_topology_for_build(
        rest,
        read_file,
        wz::runtime_tokio::compiled_in_link_schemes(),
    )
}

/// [`check_topology`] with the reader's link census named rather than taken
/// from this binary.
///
/// R2070's rule, applied here: a verdict that depends on WHO READS IT takes the
/// reader as an argument. "Can this deployment form a network" is a property of
/// the documents; "can THIS build open that endpoint" is a property of cargo's
/// feature selection, and a test asking the first must not be answered with the
/// second.
#[cfg(feature = "zenoh-config")]
pub(crate) fn check_topology_for_build(
    rest: &[String],
    mut read_file: impl FnMut(&str) -> Result<String, String>,
    compiled_in_schemes: &[&str],
) -> Option<Result<String, String>> {
    use wz::runtime_tokio::zenoh_config::{validate_topology, ZenohNodeConfig};

    let paths = parse_repeated(rest, "--check-topology");
    if paths.is_empty() {
        return None;
    }

    // A file that cannot be read or parsed ABORTS the check rather than being
    // dropped from the set. Judging N-1 nodes and reporting on them would
    // manufacture the very set defects this surface exists to state truly: the
    // absent node is often the router, and without it the remainder is "every
    // node is a client" plus a dangling dial apiece.
    let mut configs = Vec::with_capacity(paths.len());
    let mut notes = String::new();
    for path in &paths {
        let source = match read_file(path) {
            Ok(source) => source,
            Err(message) => return Some(Err(message)),
        };
        let ingest = match ZenohNodeConfig::from_json5(&source) {
            Ok(ingest) => ingest,
            Err(e) => return Some(Err(format!("--check-topology: {path}: {e}"))),
        };
        // Said out loud for the reason `--config` says it: a verdict of "these
        // can form a network" over a document half of whose keys were never
        // read would be taken for "this file is understood".
        for key in &ingest.ignored {
            notes.push_str(&format!("--check-topology: {path}: IGNORED {key}\n"));
        }
        configs.push(ingest.config);
    }

    let mut defects = String::new();
    let mut count = 0usize;
    for (path, config) in paths.iter().zip(configs.iter()) {
        for defect in config.validate_for_build(Some(compiled_in_schemes)) {
            count += 1;
            defects.push_str(&format!("  {path}: {defect}\n"));
        }
    }
    for defect in validate_topology(&configs) {
        count += 1;
        defects.push_str(&format!("  {defect}\n"));
    }

    if count == 0 {
        Some(Ok(format!(
            "{notes}--check-topology: {} node(s) can form the network they describe",
            configs.len()
        )))
    } else {
        Some(Err(format!(
            "{notes}--check-topology: this deployment cannot work:\n{}",
            defects.trim_end_matches('\n')
        )))
    }
}

#[cfg(all(test, feature = "zenoh-config"))]
mod stock_config_tests {
    use super::*;

    use wz::runtime_tokio::zenoh_config::HONOURED_CONFIG_KEYS;

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| String::from(*s)).collect()
    }

    fn expand(cli: &[&str], file: &str) -> Result<StockConfigExpansion, String> {
        expand_stock_zenoh_config(&argv(cli), |_| Ok(String::from(file)))
            .map(|o| o.expect("--config was on the command line"))
    }

    /// [`expand`] as a build that carries EVERY link zenoh does.
    ///
    /// R2070 (open-debt item 487) — the key-coverage fixtures state the TLS
    /// root-CA case over a `tls/...` endpoint (that flag's precondition is an
    /// endpoint of that scheme), and on a default build the reader now refuses
    /// such a file before reading a key. That refusal is right, and it is
    /// witnessed by `a_scheme_this_build_has_no_backend_for_is_refused_up_front`;
    /// what it must not do is answer a question about key→flag mapping with a
    /// fact about cargo features. So the coverage test names its reader, and
    /// every other test here keeps using [`expand`] — the shipped path, census
    /// and all.
    fn expand_as_a_build_with_every_link(
        cli: &[&str],
        file: &str,
    ) -> Result<StockConfigExpansion, String> {
        expand_stock_zenoh_config_for_build(
            &argv(cli),
            |_| Ok(String::from(file)),
            wz::runtime_tokio::zenoh_config::ZENOH_LINK_PROTOCOLS,
        )
        .map(|o| o.expect("--config was on the command line"))
    }

    #[test]
    fn no_config_flag_leaves_the_command_line_untouched() {
        let out = expand_stock_zenoh_config(&argv(&["--listen", "127.0.0.1:1"]), |_| {
            panic!("must not read a file")
        })
        .unwrap();
        assert!(out.is_none());
    }

    /// The four topology cases, each stated as the argv an operator would
    /// otherwise have typed.
    #[test]
    fn each_topology_the_config_can_describe_becomes_the_argv_for_it() {
        for (file, want) in [
            (
                r#"{ mode: "router", listen: { endpoints: ["tcp/0.0.0.0:7447"] } }"#,
                vec!["--router", "tcp/0.0.0.0:7447"],
            ),
            (
                r#"{ mode: "peer",
                     listen: { endpoints: ["tcp/0.0.0.0:7447"] },
                     connect: { endpoints: ["tcp/a:7447", "tcp/b:7447"] } }"#,
                vec![
                    "--peer",
                    "tcp/0.0.0.0:7447",
                    "--connect",
                    "tcp/a:7447,tcp/b:7447",
                ],
            ),
            (
                r#"{ mode: "client", listen: { endpoints: ["tcp/0.0.0.0:7447"] } }"#,
                vec!["--listen", "tcp/0.0.0.0:7447"],
            ),
            (
                r#"{ mode: "client", connect: { endpoints: ["tcp/router:7447"] } }"#,
                vec!["--connect", "tcp/router:7447"],
            ),
        ] {
            let out = expand(&["--config", "z.json5"], file).unwrap();
            assert_eq!(out.added, argv(&want), "{file}");
            // The expansion APPENDS; it never rewrites what was already there.
            assert_eq!(&out.argv[..2], &argv(&["--config", "z.json5"])[..]);
        }
    }

    /// A topology named on the command line wins — the file supplies defaults,
    /// it does not overrule the operator standing in front of the machine.
    #[test]
    fn a_role_on_the_command_line_is_not_second_guessed_by_the_file() {
        for role in [
            vec!["--listen", "127.0.0.1:1"],
            vec!["--connect", "127.0.0.1:1"],
            vec!["--router", "127.0.0.1:1"],
            vec!["--peer", "127.0.0.1:1"],
            vec!["--storage-host", "127.0.0.1:1"],
            vec!["--scout"],
        ] {
            let mut cli = vec!["--config", "z.json5"];
            cli.extend(role.iter().copied());
            let out = expand(
                &cli,
                r#"{ mode: "router", listen: { endpoints: ["tcp/0.0.0.0:7447"] } }"#,
            )
            .unwrap();
            assert!(out.added.is_empty(), "{role:?} -> {:?}", out.added);
        }
    }

    /// Only what the document SAID is applied. `qos` resolves to zenoh's `true`
    /// for a file that never mentions it, and adding `--qos` on the strength of
    /// that would change the transport the operator asked for.
    #[test]
    fn a_defaulted_value_is_not_an_instruction_but_a_named_one_is() {
        let silent = expand(
            &["--config", "z.json5"],
            r#"{ mode: "client", connect: { endpoints: ["tcp/r:7447"] } }"#,
        )
        .unwrap();
        assert!(
            !silent.added.iter().any(|a| a == "--qos"),
            "{:?}",
            silent.added
        );
        assert!(!silent.added.iter().any(|a| a == "--max-links"));

        let explicit = expand(
            &["--config", "z.json5"],
            r#"{ mode: "client",
                 connect: { endpoints: ["tcp/r:7447"] },
                 transport: { unicast: { qos: { enabled: true },
                                         lowlatency: false,
                                         max_links: 4 } } }"#,
        )
        .unwrap();
        assert!(
            explicit.added.iter().any(|a| a == "--qos"),
            "{:?}",
            explicit.added
        );
        assert_eq!(
            explicit
                .added
                .iter()
                .position(|a| a == "--max-links")
                .map(|i| explicit.added[i + 1].clone()),
            Some(String::from("4"))
        );
        // Named but FALSE is still not an instruction to turn it on.
        assert!(!explicit.added.iter().any(|a| a == "--lowlatency"));
    }

    /// A transport flag the command line already set is left alone, the same
    /// rule the role flags follow.
    #[test]
    fn a_transport_flag_on_the_command_line_is_not_duplicated() {
        let out = expand(
            &["--config", "z.json5", "--max-links", "9", "--qos"],
            r#"{ mode: "client",
                 connect: { endpoints: ["tcp/r:7447"] },
                 transport: { unicast: { qos: { enabled: true }, max_links: 4 } } }"#,
        )
        .unwrap();
        // The ROLE still expands — no role flag was given — so the claim here
        // is about the transport pair only, and stating it that way is what
        // keeps this test from passing for the wrong reason.
        assert_eq!(out.added, argv(&["--connect", "tcp/r:7447"]));
    }

    /// A config that cannot work is refused BEFORE anything is started, which
    /// is the difference between a message and a node that is silently alone.
    #[test]
    fn a_topology_that_cannot_work_is_refused_up_front() {
        let err = expand(
            &["--config", "z.json5"],
            r#"{ mode: "peer", scouting: { multicast: { enabled: false } } }"#,
        )
        .unwrap_err();
        assert!(err.contains("cannot work"), "{err}");
        assert!(err.contains("nothing to connect to"), "{err}");

        let bad = expand(&["--config", "z.json5"], "{ mode: ").unwrap_err();
        assert!(bad.contains("not a JSON5 document"), "{bad}");

        let unreadable = expand_stock_zenoh_config(&argv(&["--config", "gone.json5"]), |p| {
            Err(format!("--config: cannot read {p}: no such file"))
        })
        .unwrap_err();
        assert!(unreadable.contains("gone.json5"), "{unreadable}");
    }

    /// R2070 (open-debt item 487) — a config that is correct FOR A STOCK
    /// ZENOHD and wrong for this binary. The scheme is a real zenoh one, so
    /// nothing about the file is malformed; what is missing is the link
    /// backend in the reader, and before this round the demo said nothing and
    /// failed at bind instead.
    ///
    /// The case is stated over a scheme that is NOT a default feature and is
    /// picked from the census at run time, so the test cannot go stale by
    /// asserting a gap that a later round closes: on a build that HAS every
    /// backend there is nothing to refuse, and the test says so rather than
    /// inventing a failure.
    #[test]
    fn a_scheme_this_build_has_no_backend_for_is_refused_up_front() {
        let census = wz::runtime_tokio::compiled_in_link_schemes();
        let Some(absent) = [
            "vsock",
            "serial",
            "unixpipe",
            "unixsock-stream",
            "ws",
            "tls",
        ]
        .into_iter()
        .find(|s| !census.contains(s)) else {
            // Every candidate is compiled in — there is no defect to produce,
            // and asserting one would be asserting the build's feature set.
            return;
        };
        let file =
            format!(r#"{{ mode: "client", connect: {{ endpoints: ["{absent}/host:7447"] }} }}"#);
        let err = expand(&["--config", "z.json5"], &file).unwrap_err();
        assert!(err.contains("cannot work"), "{err}");
        assert!(
            err.contains("this build has no link backend for"),
            "{absent} was not named as absent: {err}"
        );
        // CONTROL: the same file over a scheme the census DOES carry expands
        // instead of refusing, so the refusal is about the backend and not
        // about connect endpoints in general.
        let carried = census.first().expect("a build that can open something");
        let file =
            format!(r#"{{ mode: "client", connect: {{ endpoints: ["{carried}/host:7447"] }} }}"#);
        let out = expand(&["--config", "z.json5"], &file).expect("a carried scheme expands");
        assert_eq!(
            out.added,
            argv(&["--connect", &format!("{carried}/host:7447")])
        );
    }

    /// The keys wz does not honour reach the caller so they can be printed —
    /// the operator has to be able to see what their file did NOT do.
    ///
    /// R311y844 replaced this document's two examples. They were the TLS root
    /// CA and `queries_default_timeout`, and both are honoured now — which is
    /// that round in one sentence: the unhonoured list had been carrying keys
    /// wz could act on and simply had not been told about, alongside the ones
    /// it genuinely cannot. `plugins` and `transport/link/tx/threads` are the
    /// second kind (a plugin host; a TX thread pool wz does not have), so they
    /// are what this test is about now.
    #[test]
    fn the_keys_wz_does_not_honour_are_carried_out_to_be_reported() {
        let out = expand(
            &["--config", "z.json5"],
            r#"{ mode: "client",
                 connect: { endpoints: ["tcp/r:7447"] },
                 transport: { link: { tx: { threads: 8 } } },
                 plugins: {} }"#,
        )
        .unwrap();
        assert_eq!(out.ignored, vec!["plugins", "transport/link/tx/threads"]);
        assert_eq!(out.named, vec!["mode", "connect/endpoints"]);
    }

    /// R311y843 — every key wz REPORTS as honoured, paired with whether the
    /// demo does anything at all with it.
    ///
    /// R311y842 built the reader and its own report calls all fourteen keys
    /// "honoured", but only six reached a flag. The other eight were ingested
    /// and DROPPED at this boundary, which is worse than never reading them:
    /// the report is the surface an operator checks, and
    /// `--config z.json5: honoured [..., "transport/link/tx/lease"]` printed by
    /// a node that goes on to announce its own hard-coded ten-second lease is a
    /// truthful statement about the reader and a false one about the node.
    ///
    /// Each row is a CONTROL / VARIANT pair over the same expansion so the argv
    /// difference is attributable to the ONE key that differs — a variant that
    /// merely gains an endpoint would otherwise credit the key for the
    /// endpoint's flag. A key that changes nothing must be NAMED in
    /// `config_keys_the_demo_drops()`: the discipline
    /// `UNHONOURED_UPSTREAM_CONFIG_KEYS` applies to zenoh's surface, applied
    /// one level down to wz's own.
    ///
    /// The table is also checked for COVERAGE against `HONOURED_CONFIG_KEYS`,
    /// so a fifteenth honoured key cannot be added without stating here what
    /// the demo does with it.
    const LISTEN_ONLY: &str = r#"{ listen: { endpoints: ["tcp/0.0.0.0:7447"] } }"#;
    const CONNECT_ONLY: &str = r#"{ connect: { endpoints: ["tcp/r:7447"] } }"#;
    const LISTEN_TLS: &str = r#"{ listen: { endpoints: ["tls/0.0.0.0:7447"] } }"#;
    const CONNECT_TLS: &str = r#"{ connect: { endpoints: ["tls/r:7447"] } }"#;
    /// R311y845 — the argv half of the scouting socket: what `--scout-*`
    /// parses, and what an unset flag resolves to.
    ///
    /// The FALLBACK case is the one that needs a test of its own. Every other
    /// witness in this round — the reader's, the expansion's, Layer M's — is
    /// driven by a config that NAMES the address, so a resolver that ignored
    /// the defaults (or one that ignored the address) can still pass some of
    /// them. Both directions are pinned here.
    #[test]
    fn the_scouting_socket_resolves_to_what_was_named_or_to_zenohs_own_default() {
        const DEFAULT_GROUP: std::net::Ipv4Addr = std::net::Ipv4Addr::new(224, 0, 0, 224);
        const DEFAULT_PORT: u16 = 7446;

        // Nothing named -> zenoh's default socket, untouched.
        let bare = parse_scout_socket(&argv(&["--scout"])).unwrap();
        assert_eq!(bare, ScoutSocketArgs::default());
        assert_eq!(
            bare.group_and_port(DEFAULT_GROUP, DEFAULT_PORT),
            (DEFAULT_GROUP, DEFAULT_PORT)
        );

        // Named -> BOTH halves move. A resolver that took the group and kept
        // the default port would pass a group-only assertion.
        let moved = parse_scout_socket(&argv(&[
            "--scout",
            "--scout-addr",
            "224.0.0.99:7999",
            "--scout-iface",
            "eth0",
            "--scout-ttl",
            "4",
        ]))
        .unwrap();
        assert_eq!(
            moved.group_and_port(DEFAULT_GROUP, DEFAULT_PORT),
            (std::net::Ipv4Addr::new(224, 0, 0, 99), 7999)
        );
        assert_eq!(moved.interface.as_deref(), Some("eth0"));
        assert_eq!(moved.ttl, Some(4));

        // A malformed socket is REFUSED at the argv boundary, so the resolver
        // is never handed one — the same refusal the config reader makes, in
        // the same words, because the failure it prevents is the same node that
        // starts and joins nothing.
        for bad in ["224.0.0.99", "not-an-address"] {
            let err = parse_scout_socket(&argv(&["--scout", "--scout-addr", bad])).unwrap_err();
            assert!(err.contains("--scout-addr"), "{err}");
        }
        assert!(parse_scout_socket(&argv(&["--scout", "--scout-ttl", "x"]))
            .unwrap_err()
            .contains("--scout-ttl"));
    }

    /// R311y845 — the control for the three scouting-socket keys. A peer with
    /// no endpoints is a workable topology precisely BECAUSE multicast scouting
    /// is on by default: it has something to discover, which is what
    /// `validate()` checks for. Paired with a `--scout` command line (see
    /// `cli_for`), so no role flag expands and the argv delta is the one key.
    const SCOUT_ONLY: &str = r#"{ mode: "peer" }"#;

    /// Keys the reader ingests that reach NO behaviour in this binary.
    ///
    /// Empty is the goal and not the invariant — a key with no sink is a
    /// legitimate state, but it has to be written down here rather than hide
    /// behind a report that calls it honoured.
    /// R311y844 made this BUILD-DEPENDENT, and the two kinds inside it are
    /// worth telling apart. The first two rows are keys with no sink at all in
    /// this binary. The `cfg!` rows are keys whose sink exists but is compiled
    /// out here: their flags exit(2) when the feature is absent, so expanding
    /// into one would turn a valid stock config into a node that refuses to
    /// start — which is what the round measured its own first cut doing.
    fn config_keys_the_demo_drops() -> Vec<&'static str> {
        let mut out = vec![
            // Reachability, not a role: `scouting/multicast/enabled` says
            // whether to LISTEN for a scout beacon, and the demo's `--scout`
            // says to discover INSTEAD of dialling, which is a different
            // sentence. Mapping one onto the other would rewrite the
            // operator's topology.
            "scouting/multicast/enabled",
            // No sink in this binary: nothing on the demo's push path stamps a
            // source timestamp — `Timestamp` does not occur anywhere under
            // `wz-ap-demo/src/` — so there is no flag to expand into and
            // honouring it would be a claim about a plane that does not exist
            // yet.
            "timestamping/enabled",
        ];
        if !cfg!(feature = "routing-interest-pending-gc") {
            out.push("routing/interests/timeout");
        }
        if !cfg!(feature = "transport-qos") {
            out.push("transport/multicast/qos/enabled");
        }
        // R311y846 — the responder's flag exits(2) without its feature (the
        // demo says so and names the build), so a build without it must DROP the
        // key rather than expand into a refusal.
        if !cfg!(feature = "scouting-responder") {
            out.push("scouting/multicast/listen");
        }
        // R311y849 — `--connect-retry` is parsed by the `--peer` and
        // `--router-hat` arms only, and neither exists without its feature, so a
        // build with neither has no sink to expand into.
        if !cfg!(any(feature = "routing-peer", feature = "router-hat-router")) {
            out.push("connect/retry");
        }
        out
    }

    /// The invocation a key is applicable IN.
    ///
    /// R311y844 — two of the flags this table drives carry a command-line
    /// PRECONDITION and exit(2) without it (`--scout-timeout-ms requires
    /// --scout`, `--query-timeout-ms requires --query`), so the expansion
    /// withholds them there and a fixture that did not supply the precondition
    /// would read the withholding as "the key reaches nothing". Both sides of a
    /// pair get the same cli, so the delta stays attributable to the one key
    /// that differs.
    fn cli_for(key: &str) -> &'static [&'static str] {
        match key {
            "queries_default_timeout" => &["--config", "z.json5", "--query", "demo/**"],
            // R311y845 — the three scouting-socket keys carry the same
            // `--scout` precondition as the budget above, and for the same
            // reason the round had to measure rather than assume: without it
            // the demo exits(2), so an expansion that emitted them anyway would
            // turn a valid stock config into a node that refuses to start.
            "scouting/timeout"
            | "scouting/multicast/address"
            | "scouting/multicast/interface"
            | "scouting/multicast/ttl" => &["--config", "z.json5", "--scout"],
            // R311y846 — the answering direction's precondition is `--peer`,
            // not `--scout`: the responder is spawned from `run_peer`, and
            // `--scout` is a one-shot Initiator that exits on its first
            // discovery, which has nothing to answer with.
            "scouting/multicast/listen" => &["--config", "z.json5", "--peer", "tcp/127.0.0.1:0"],
            // R311y849 — the re-dial schedule's precondition is a run mode that
            // owns a connect LIST. `--peer` is used here rather than
            // `--router-hat` because it is the arm this round WIRED: the
            // `--router-hat` arm had read the flag since R311y786 and the peer
            // arm accepted and dropped it, so a fixture pointed at the router
            // would have passed against the defect.
            "connect/retry" => &["--config", "z.json5", "--peer", "tcp/127.0.0.1:0"],
            _ => &["--config", "z.json5"],
        }
    }

    /// `(key, control, variant)` — the variant differs from the control in
    /// exactly the one key, and must NAME it.
    fn honoured_key_fixtures() -> Vec<(&'static str, &'static str, &'static str)> {
        vec![
            (
                "mode",
                LISTEN_ONLY,
                r#"{ mode: "router", listen: { endpoints: ["tcp/0.0.0.0:7447"] } }"#,
            ),
            (
                "listen/endpoints",
                CONNECT_ONLY,
                r#"{ connect: { endpoints: ["tcp/r:7447"] },
                     listen: { endpoints: ["tcp/0.0.0.0:7447"] } }"#,
            ),
            (
                "connect/endpoints",
                LISTEN_ONLY,
                r#"{ listen: { endpoints: ["tcp/0.0.0.0:7447"] },
                     connect: { endpoints: ["tcp/r:7447"] } }"#,
            ),
            (
                "scouting/multicast/enabled",
                LISTEN_ONLY,
                r#"{ listen: { endpoints: ["tcp/0.0.0.0:7447"] },
                     scouting: { multicast: { enabled: false } } }"#,
            ),
            (
                "timestamping/enabled",
                LISTEN_ONLY,
                r#"{ listen: { endpoints: ["tcp/0.0.0.0:7447"] },
                     timestamping: { enabled: true } }"#,
            ),
            (
                "transport/unicast/max_links",
                LISTEN_ONLY,
                r#"{ listen: { endpoints: ["tcp/0.0.0.0:7447"] },
                     transport: { unicast: { max_links: 9 } } }"#,
            ),
            // `qos` RESOLVES to true in stock zenoh, so a document that names
            // only `lowlatency` describes a node that cannot start. Both sides
            // of this pair name `qos: false` — which adds nothing, since the
            // expansion acts on a named `true` — so the delta stays the one key.
            (
                "transport/unicast/lowlatency",
                r#"{ listen: { endpoints: ["tcp/0.0.0.0:7447"] },
                     transport: { unicast: { qos: { enabled: false } } } }"#,
                r#"{ listen: { endpoints: ["tcp/0.0.0.0:7447"] },
                     transport: { unicast: { qos: { enabled: false },
                                             lowlatency: true } } }"#,
            ),
            (
                "transport/unicast/qos/enabled",
                LISTEN_ONLY,
                r#"{ listen: { endpoints: ["tcp/0.0.0.0:7447"] },
                     transport: { unicast: { qos: { enabled: true } } } }"#,
            ),
            (
                "transport/unicast/compression/enabled",
                LISTEN_ONLY,
                r#"{ listen: { endpoints: ["tcp/0.0.0.0:7447"] },
                     transport: { unicast: { compression: { enabled: true } } } }"#,
            ),
            (
                "transport/link/tx/batch_size",
                LISTEN_ONLY,
                r#"{ listen: { endpoints: ["tcp/0.0.0.0:7447"] },
                     transport: { link: { tx: { batch_size: 4096 } } } }"#,
            ),
            (
                "transport/link/tx/lease",
                LISTEN_ONLY,
                r#"{ listen: { endpoints: ["tcp/0.0.0.0:7447"] },
                     transport: { link: { tx: { lease: 3000 } } } }"#,
            ),
            (
                "adminspace/enabled",
                LISTEN_ONLY,
                r#"{ listen: { endpoints: ["tcp/0.0.0.0:7447"] },
                     adminspace: { enabled: true } }"#,
            ),
            (
                "adminspace/permissions/read",
                LISTEN_ONLY,
                r#"{ listen: { endpoints: ["tcp/0.0.0.0:7447"] },
                     adminspace: { enabled: true, permissions: { read: false } } }"#,
            ),
            (
                "adminspace/permissions/write",
                LISTEN_ONLY,
                r#"{ listen: { endpoints: ["tcp/0.0.0.0:7447"] },
                     adminspace: { enabled: true, permissions: { write: true } } }"#,
            ),
            // R311y844 — the ten keys wz already acted on, each paired with the
            // flag that has carried it since long before the reader existed.
            (
                "id",
                LISTEN_ONLY,
                r#"{ listen: { endpoints: ["tcp/0.0.0.0:7447"] },
                     id: "0102030405060708" }"#,
            ),
            (
                "namespace",
                LISTEN_ONLY,
                r#"{ listen: { endpoints: ["tcp/0.0.0.0:7447"] },
                     namespace: "demo/ns" }"#,
            ),
            (
                "queries_default_timeout",
                LISTEN_ONLY,
                r#"{ listen: { endpoints: ["tcp/0.0.0.0:7447"] },
                     queries_default_timeout: 12000 }"#,
            ),
            (
                "routing/interests/timeout",
                LISTEN_ONLY,
                r#"{ listen: { endpoints: ["tcp/0.0.0.0:7447"] },
                     routing: { interests: { timeout: 9000 } } }"#,
            ),
            (
                "scouting/timeout",
                LISTEN_ONLY,
                r#"{ listen: { endpoints: ["tcp/0.0.0.0:7447"] },
                     scouting: { timeout: 2500 } }"#,
            ),
            (
                "transport/multicast/qos/enabled",
                LISTEN_ONLY,
                r#"{ listen: { endpoints: ["tcp/0.0.0.0:7447"] },
                     transport: { multicast: { qos: { enabled: true } } } }"#,
            ),
            // R2063 (open-debt item 214) — `peer-to-peer` and not the default,
            // for the reason the `scouting/multicast/listen` row above states:
            // the delta this gate looks for is a VALUE the file asked for, and
            // `linkstate` is what an absent flag already means.
            (
                "routing/peer/mode",
                LISTEN_ONLY,
                r#"{ listen: { endpoints: ["tcp/0.0.0.0:7447"] },
                     routing: { peer: { mode: "peer-to-peer" } } }"#,
            ),
            (
                "transport/shared_memory/enabled",
                LISTEN_ONLY,
                r#"{ listen: { endpoints: ["tcp/0.0.0.0:7447"] },
                     transport: { shared_memory: { enabled: true } } }"#,
            ),
            // The TLS three need a TLS endpoint in the fixture: the expansion
            // withholds the flags on a node with no TLS link, so a tcp control
            // would read the withholding as "the key reaches nothing".
            (
                "transport/link/tls/root_ca_certificate",
                CONNECT_TLS,
                r#"{ connect: { endpoints: ["tls/r:7447"] },
                     transport: { link: { tls: { root_ca_certificate: "/etc/ca.pem" } } } }"#,
            ),
            (
                "transport/link/tls/listen_certificate",
                LISTEN_TLS,
                r#"{ listen: { endpoints: ["tls/0.0.0.0:7447"] },
                     transport: { link: { tls: { listen_certificate: "/etc/srv.pem" } } } }"#,
            ),
            (
                "transport/link/tls/listen_private_key",
                LISTEN_TLS,
                r#"{ listen: { endpoints: ["tls/0.0.0.0:7447"] },
                     transport: { link: { tls: { listen_private_key: "/etc/srv.key" } } } }"#,
            ),
            // R311y845 — the scouting SOCKET. Both sides of each pair are a
            // `--scout` invocation (see `cli_for`), so the control expands to
            // nothing and the delta is the one key. Each value is deliberately
            // NOT the upstream default, so a demo that kept its compiled-in
            // group would show no argv difference and fail here.
            (
                "scouting/multicast/address",
                SCOUT_ONLY,
                r#"{ mode: "peer", scouting: { multicast: { address: "224.0.0.99:7999" } } }"#,
            ),
            (
                "scouting/multicast/interface",
                SCOUT_ONLY,
                r#"{ mode: "peer", scouting: { multicast: { interface: "eth0" } } }"#,
            ),
            (
                "scouting/multicast/ttl",
                SCOUT_ONLY,
                r#"{ mode: "peer", scouting: { multicast: { ttl: 4 } } }"#,
            ),
            // R311y846 — whether the node ANSWERS. The control names `false`
            // rather than omitting the key, so the delta is the VALUE and not
            // the key's presence: an expansion that emitted the flag whenever
            // the key was mentioned would pass a present/absent pair and fail
            // this one. Upstream's default is `true`, so `false` is also the
            // half a node would be surprised by.
            (
                "scouting/multicast/listen",
                r#"{ mode: "peer", scouting: { multicast: { listen: false } } }"#,
                r#"{ mode: "peer", scouting: { multicast: { listen: true } } }"#,
            ),
            // R311y849 — the control states NO retry block, so the delta is the
            // whole flag rather than a changed number. That is the honest
            // control here: `None` and zenoh's defaults BEHAVE alike, so a
            // control carrying `1000,4000,2` would differ from the variant only
            // in digits and would pass against an expansion that emitted the
            // flag unconditionally.
            (
                "connect/retry",
                r#"{ mode: "peer", connect: { endpoints: ["tcp/r:7447"] } }"#,
                r#"{ mode: "peer", connect: { endpoints: ["tcp/r:7447"],
                     retry: { period_init_ms: 250, period_max_ms: 9000,
                              period_increase_factor: 1.5 } } }"#,
            ),
        ]
    }

    #[test]
    fn every_key_the_reader_calls_honoured_reaches_the_demo_or_is_named_as_dropped() {
        let fixtures = honoured_key_fixtures();

        // COVERAGE, both directions: a new honoured key with no row here would
        // otherwise be silently untested, and a row for a key the reader no
        // longer honours would be testing nothing.
        let mut want: Vec<&str> = HONOURED_CONFIG_KEYS.to_vec();
        let mut got: Vec<&str> = fixtures.iter().map(|(k, _, _)| *k).collect();
        want.sort_unstable();
        got.sort_unstable();
        assert_eq!(
            got, want,
            "the fixture table and HONOURED_CONFIG_KEYS have diverged"
        );
        for dropped in config_keys_the_demo_drops() {
            assert!(
                HONOURED_CONFIG_KEYS.contains(&dropped),
                "{dropped} is pinned as dropped but is not a honoured key"
            );
        }

        let mut reached_nothing: Vec<&str> = Vec::new();
        for (key, control, variant) in &fixtures {
            let cli = cli_for(key);
            let base = expand_as_a_build_with_every_link(cli, control)
                .unwrap_or_else(|e| panic!("{key}: the control config is not readable: {e}"));
            let with = expand_as_a_build_with_every_link(cli, variant)
                .unwrap_or_else(|e| panic!("{key}: the variant config is not readable: {e}"));
            // Vacuity guard: a fixture that does not actually name the key
            // would report "dropped" for a typo in this table.
            assert!(
                with.named.contains(key),
                "{key}: the variant does not name it (named = {:?})",
                with.named
            );
            if with.added == base.added {
                reached_nothing.push(key);
            }
        }

        reached_nothing.sort_unstable();
        let mut pinned: Vec<&str> = config_keys_the_demo_drops();
        pinned.sort_unstable();
        assert_eq!(
            reached_nothing, pinned,
            "a key the report calls honoured reaches no behaviour and is not \
             named in config_keys_the_demo_drops() (or one named there now does \
             something and should be removed)"
        );
    }

    /// R2063 (open-debt item 214) — EVERY UPSTREAM KEY THIS DEMO'S `--help`
    /// CITES IS ONE THE READER HONOURS.
    ///
    /// # The population, and why it is worth a gate of its own
    ///
    /// Item 214 records that `UNHONOURED_UPSTREAM_CONFIG_KEYS` mixes two
    /// unrelated things under one name -- "wz cannot do this" and "the reader
    /// has not learned it yet" -- and that sweeping all 82 is a round of its
    /// own. It also points at a CHEAP SLICE that does not have to wait for that
    /// sweep: the demo's own usage text cites upstream keys by path, and a key
    /// this program tells an operator it implements had better be one the
    /// reader can read.
    ///
    /// That population is six lines, derived here from the usage text rather
    /// than listed, so a seventh citation arrives inside the gate instead of
    /// beside it.
    ///
    /// # The two spellings, and why both are swept
    ///
    /// Upstream writes these paths with slashes and zenoh's own documentation
    /// writes them with dots; this file does BOTH (`transport/link/tx/lease` at
    /// one line, `routing.peer.mode` at another). A sweep that knew only one
    /// form would have found five keys and reported the sixth as prose --
    /// which is exactly the citation that turned out to be unhonoured.
    #[test]
    fn every_upstream_key_the_usage_text_cites_is_one_the_reader_honours() {
        // The usage text as it ships, read rather than re-typed.
        let usage = include_str!("usage.rs");

        // A citation is `zenoh <path>` where the path has at least two
        // segments in either spelling. Trailing punctuation is stripped
        // because these appear inside sentences and parentheses.
        let mut cited: Vec<String> = Vec::new();
        for line in usage.lines() {
            let mut rest = line;
            while let Some(at) = rest.find("zenoh ") {
                rest = &rest[at + "zenoh ".len()..];
                let token: String = rest
                    .chars()
                    .take_while(|c| {
                        c.is_ascii_alphanumeric() || *c == '_' || *c == '/' || *c == '.'
                    })
                    .collect();
                let token = token.trim_end_matches('.').to_string();
                let slashed = token.replace('.', "/");
                if !slashed.is_empty() && slashed.contains('/') && !cited.contains(&slashed) {
                    cited.push(slashed);
                }
            }
        }
        cited.sort();

        // ── ANTI-VACUITY ─────────────────────────────────────────────────
        // A regex that stopped matching would find nothing and agree with
        // everything. The count is not pinned -- a new citation should not red
        // here, it should be CHECKED below -- but the sweep must reach the
        // scale item 214 measured.
        assert!(
            cited.len() >= 5,
            "the usage text cites {} upstream key(s); the sweep, not the file, \
             is what changed: {cited:?}",
            cited.len()
        );
        assert!(
            cited.iter().any(|k| k.contains('.') || k.contains('/')),
            "every citation must be a PATH: {cited:?}"
        );

        // ── THE CLAIM ────────────────────────────────────────────────────
        let unhonoured: Vec<&String> = cited
            .iter()
            .filter(|k| !HONOURED_CONFIG_KEYS.contains(&k.as_str()))
            .collect();
        assert!(
            unhonoured.is_empty(),
            "this program's own `--help` tells an operator it implements \
             {unhonoured:?}, and the config reader does not know those keys. A \
             citation is a PROMISE: either honour the key or stop naming it. \
             Cited: {cited:?}"
        );
    }

    /// Every double-quoted string literal in `src`, escapes left as written.
    ///
    /// Deliberately naive -- it does not know a comment from code -- because
    /// the two sweeps below want OVER-inclusion: a flag named in a comment and
    /// nowhere else is still a flag someone will type.
    fn string_literals(src: &str) -> Vec<&str> {
        let bytes = src.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] != b'"' {
                i += 1;
                continue;
            }
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() && bytes[j] != b'"' {
                j += if bytes[j] == b'\\' { 2 } else { 1 };
            }
            let end = j.min(bytes.len());
            if src.is_char_boundary(start) && src.is_char_boundary(end) {
                out.push(&src[start..end]);
            }
            i = end + 1;
        }
        out
    }

    /// The `--help` entry for one flag: its own line plus every continuation
    /// line under it, joined. A continuation is a printed line indented to the
    /// description column, which is how this file lays every entry out.
    fn usage_entry(src: &str, flag: &str) -> Option<String> {
        const DESCRIPTION_COLUMN: &str = "                             ";
        let head = format!("    --{flag} ");
        let literals = string_literals(src);
        let start = literals.iter().position(|l| l.starts_with(&head))?;
        let mut entry = literals[start].to_string();
        for line in &literals[start + 1..] {
            let Some(continuation) = line.strip_prefix(DESCRIPTION_COLUMN) else {
                break;
            };
            entry.push(' ');
            entry.push_str(continuation.trim());
        }
        Some(entry)
    }

    /// Every flag argv accepts is PRINTED by `--help`, or named below as a
    /// deliberate omission.
    ///
    /// WHY AN OMISSION IS A DEFECT AND NOT A SILENCE -- this file already makes
    /// the argument, about its other list: "an omission does not read as
    /// silence; it reads as 'that flag is off'". An operator reaching for wz in
    /// place of zenoh reads `--help` as the set of things this binary can do,
    /// and 48 of the 106 flags it accepts are not in it -- including, until this
    /// round, the ONLY run mode that announces the zenoh router role.
    ///
    /// A RATCHET, NOT A FIX. Documenting all 48 is a separate piece of work and
    /// some may deserve to stay hidden; what must not happen is a 49th joining
    /// them unnoticed. So the set is PINNED, not the count: a new undocumented
    /// flag fails here, and documenting one fails here too, telling the author
    /// to shrink the list in the same commit.
    #[test]
    fn every_flag_the_parser_accepts_is_printed_or_declared_absent() {
        const MAIN: &str = include_str!("main.rs");
        const ARGS: &str = include_str!("args.rs");
        const RUNNER: &str = include_str!("runner.rs");
        const USAGE: &str = include_str!("usage.rs");

        // Stored WITHOUT the leading dashes on purpose: this list lives inside
        // args.rs, which the sweep below reads, and a dashed literal here would
        // enter its own population -- a flag deleted from the parser would then
        // still look present, which is the one way this gate could go quietly
        // blind.
        //
        // The same care applies to PROSE in this file. The sweep is deliberately
        // naive about comments (see string_literals), so a dashed flag written
        // inside quotes anywhere here becomes a flag it hunts for. That is not
        // a silent failure -- an illustration written that way fails this test
        // by name, which is how this very comment got rewritten.
        const UNDOCUMENTED: &[&str] = &[
            "acl-deny",
            "advanced-publish-heartbeat",
            "batch",
            "config",
            "config-queryable",
            "config-writable",
            "config-write-permit",
            "connect-after",
            "connect-retry",
            "declare-id",
            "downsample",
            "downsample-freq",
            "downsample-interface",
            "downsample-link-protocol",
            "express-high",
            "group-join",
            "group-lease-secs",
            "group-member-id",
            "interest-timeout",
            "low",
            "max-links",
            "max-payload",
            "multicast-locator",
            "multicast-qos",
            "namespace",
            "no-admin-read",
            "plugin",
            "publish-after-ms",
            "put-key",
            "put-payload",
            "qos",
            "qos-band",
            "qos-rel",
            "quic-ca",
            "quic-cert",
            "quic-key",
            "shm",
            "storage-gc-lifespan-ms",
            "storage-gc-period-ms",
            "storage-host",
            "storage-host-dir",
            "storage-volume",
            "storage-volume-config",
            "subscribe",
            "tls-ca",
            "tls-cert",
            "tls-key",
            "unsubscribe-after-data",
        ];

        fn is_flag_name(name: &str) -> bool {
            name.starts_with(|c: char| c.is_ascii_lowercase())
                && name
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        }

        let mut parser: Vec<&str> = Vec::new();
        for src in [MAIN, ARGS, RUNNER] {
            for literal in string_literals(src) {
                if let Some(name) = literal.strip_prefix("--") {
                    if is_flag_name(name) {
                        parser.push(name);
                    }
                }
            }
        }
        parser.sort_unstable();
        parser.dedup();

        let mut printed: Vec<String> = Vec::new();
        for literal in string_literals(USAGE) {
            for tail in literal.split("--").skip(1) {
                let name: String = tail
                    .chars()
                    .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-')
                    .collect();
                if is_flag_name(&name) {
                    printed.push(name);
                }
            }
        }
        printed.sort_unstable();
        printed.dedup();

        // ── ANTI-VACUITY ─────────────────────────────────────────────────
        // Either sweep could stop matching and agree with everything. These
        // floors are far below the measured 106 / 62, so ordinary movement of
        // the argv surface does not touch them; only a broken sweep does.
        assert!(
            parser.len() >= 90,
            "the parser sweep found only {} flag(s); the sweep changed, not the file",
            parser.len()
        );
        assert!(
            printed.len() >= 50,
            "the usage sweep found only {} flag(s); the sweep changed, not the file",
            printed.len()
        );

        // ── THE CLAIM, BOTH DIRECTIONS ───────────────────────────────────
        let absent: Vec<&str> = parser
            .iter()
            .copied()
            .filter(|f| !printed.iter().any(|p| p == f))
            .collect();

        let unlisted: Vec<&&str> = absent
            .iter()
            .filter(|f| !UNDOCUMENTED.contains(f))
            .collect();
        assert!(
            unlisted.is_empty(),
            "argv accepts {unlisted:?} and `--help` never prints them. An \
             operator reads the help as what this binary can do, so an \
             undocumented flag reads as an absent capability. Print them, or \
             add them to UNDOCUMENTED and file why."
        );

        let now_documented: Vec<&&str> = UNDOCUMENTED
            .iter()
            .filter(|f| !absent.contains(*f))
            .collect();
        assert!(
            now_documented.is_empty(),
            "{now_documented:?} are listed as undocumented but `--help` now \
             prints them (or argv no longer accepts them). Shrink the list in \
             the same commit -- a backlog that cannot shrink is a count, not a \
             ratchet."
        );
    }

    /// Each run mode's `--help` entry names the zenoh wire role it announces.
    ///
    /// The flag names do NOT carry this: `--connect` announces `client` while
    /// naming neither, and `--router` announces `peer` -- only `--router-hat`
    /// announces `router`. An operator picking a flag by its name to stand in
    /// for a zenoh node therefore picks the wrong role, and nothing on the
    /// screen contradicts them. The role each mode announces is decided in
    /// `demo_session_init_params`, which is the SSOT this table follows.
    #[test]
    fn the_usage_text_names_the_wire_role_each_run_mode_announces() {
        const USAGE: &str = include_str!("usage.rs");

        // (flag, the role `demo_session_init_params` returns for its NodeKind)
        const ROLES: &[(&str, &str)] = &[
            ("listen", "peer"),
            ("connect", "client"),
            ("router", "peer"),
            ("router-hat", "router"),
            ("peer", "peer"),
        ];

        for (flag, role) in ROLES {
            let entry = usage_entry(USAGE, flag)
                .unwrap_or_else(|| panic!("`--{flag}` has no entry in the usage text at all"));
            let phrase = format!("zenoh {role} role");
            assert!(
                entry.contains(&phrase),
                "`--{flag}` announces the {role} role on the wire and its help \
                 entry never says so. Expected the phrase `{phrase}` in: {entry}"
            );
        }
    }

    /// R311y849 — `connect/retry` reaches the flag in the modes that dial and
    /// is WITHHELD everywhere else, spelled out rather than left to the census
    /// gate above (which only shows that the argv changed).
    ///
    /// The withholding half is the one worth a test. A `--listen`-only node has
    /// no parse for `--connect-retry` and exits(2) on it, so an expansion that
    /// emitted it would turn a valid operator config -- one that legitimately
    /// carries a retry block for the OTHER nodes in the deployment -- into a
    /// node that will not start. That is the failure R311y844 measured for four
    /// other flags and this file exists to keep measuring.
    #[test]
    #[cfg(any(feature = "routing-peer", feature = "router-hat-router"))]
    fn the_retry_schedule_reaches_only_the_modes_that_own_a_connect_list() {
        // A peer BINDS and dials, so the file carries both endpoint lists: the
        // role expansion produces `--peer` only from the pair, and a
        // connect-only file is a client dial however its `mode` reads.
        let file = r#"{ mode: "peer",
             listen: { endpoints: ["tcp/0.0.0.0:7447"] },
             connect: { endpoints: ["tcp/r:7447"],
                        retry: { period_init_ms: 250, period_max_ms: 9000,
                                 period_increase_factor: 1.5 } } }"#;

        // The dialing modes: the flag is emitted, in the parser's own spelling.
        for mode in [
            vec!["--config", "z.json5", "--peer", "tcp/127.0.0.1:0"],
            vec!["--config", "z.json5", "--router-hat", "tcp/127.0.0.1:0"],
        ] {
            let out = expand(&mode, file).unwrap();
            let at = out
                .added
                .iter()
                .position(|a| a == "--connect-retry")
                .unwrap_or_else(|| panic!("{mode:?}: no --connect-retry in {:?}", out.added));
            assert_eq!(out.added[at + 1], "250,9000,1.5");
            // And the value the flag's own parser makes of it is the schedule
            // the file asked for -- the two halves are joined here rather than
            // asserted to look alike, because the string is the only thing the
            // expansion controls and the policy is the parser's.
            let policy = parse_connect_retry(&out.argv)
                .expect("the expansion must emit something its own parser accepts")
                .expect("the flag is present");
            assert_eq!(policy.period_init_ms, 250);
            assert_eq!(policy.period_max_ms, 9000);
            assert_eq!(policy.period_increase_factor, 1.5);
        }

        // Every other mode: nothing, because the flag would be a refusal.
        for mode in [
            vec!["--config", "z.json5", "--listen", "tcp/127.0.0.1:0"],
            vec!["--config", "z.json5", "--connect", "tcp/r:7447"],
        ] {
            let out = expand(&mode, file).unwrap();
            assert!(
                !out.added.iter().any(|a| a == "--connect-retry"),
                "{mode:?} has no parse for the flag, so emitting it would \
                 exit(2) on a valid stock config: {:?}",
                out.added
            );
        }

        // THE DROP-IN CASE, and the one this round nearly shipped broken. When
        // the operator names no role, the file supplies one -- and the `--peer`
        // it supplies goes into `added`, never into the command line. A
        // precondition test that looked only at what was TYPED would withhold
        // the flag from the single invocation the whole config path exists for:
        // `wz-ap-demo --config their.json5` and nothing else.
        let drop_in = expand(&["--config", "z.json5"], file).unwrap();
        assert!(
            drop_in.added.iter().any(|a| a == "--peer"),
            "the file's `mode: peer` must supply the role: {:?}",
            drop_in.added
        );
        let at = drop_in
            .added
            .iter()
            .position(|a| a == "--connect-retry")
            .unwrap_or_else(|| {
                panic!(
                    "the config-only invocation dropped the schedule: {:?}",
                    drop_in.added
                )
            });
        assert_eq!(drop_in.added[at + 1], "250,9000,1.5");

        // An operator who typed the flag keeps it: the file supplies defaults,
        // it does not overrule the person at the machine (the same rule the
        // role flags follow).
        let typed = expand(
            &[
                "--config",
                "z.json5",
                "--peer",
                "tcp/127.0.0.1:0",
                "--connect-retry",
                "10,10,1",
            ],
            file,
        )
        .unwrap();
        assert!(!typed.added.iter().any(|a| a == "--connect-retry"));
    }

    /// R311y849 — the same drop-in question asked of R311y846's key, because
    /// the two share a shape: a precondition on a role the FILE can supply.
    ///
    /// This one matters more than the schedule it was found beside.
    /// `scouting/multicast/listen` is what makes a wz node FINDABLE by a stock
    /// zenoh network, and the invocation an operator performs when replacing a
    /// zenoh node is `wz-ap-demo --config their.json5` with no role typed. If
    /// the flag is withheld there, the capability R311y846 built is reachable
    /// only by someone who already knows to type `--peer --scout-listen` — which
    /// is not a drop-in, it is a rewrite of the deployment.
    #[test]
    #[cfg(all(feature = "scouting-responder", feature = "routing-peer"))]
    fn being_findable_survives_a_config_that_supplies_the_role_itself() {
        let file = r#"{ mode: "peer",
             listen: { endpoints: ["tcp/0.0.0.0:7447"] },
             connect: { endpoints: ["tcp/r:7447"] },
             scouting: { multicast: { enabled: true, listen: true } } }"#;

        let drop_in = expand(&["--config", "z.json5"], file).unwrap();
        assert!(
            drop_in.added.iter().any(|a| a == "--peer"),
            "the file supplies the role: {:?}",
            drop_in.added
        );
        assert!(
            drop_in.added.iter().any(|a| a == "--scout-listen"),
            "a config-only drop-in must still answer Scouts, or the node stays \
             invisible to the network it is replacing a member of: {:?}",
            drop_in.added
        );
    }

    /// R311y843 — the config's two WIRE values, followed from the file all the
    /// way to the parameters the node announces.
    ///
    /// The census gate above only shows that the argv CHANGED, and a flag this
    /// binary does not parse would satisfy it while the wire stayed exactly
    /// where it was — a green that measures the expansion talking to itself.
    /// This is the other half: the expanded argv is read back through
    /// [`TransportTuning::from_argv`], which is the same call `main` makes, and
    /// the params [`demo_session_init_params`] builds from it carry the
    /// operator's numbers rather than the demo's.
    ///
    /// `effective_batch_size()` rather than the field: that accessor is what
    /// `handshake_encode::encode_init` writes into the InitSyn
    /// (`crates/wz-session-core/src/handshake_encode.rs:106`), so it is the
    /// value the PEER is told. The last hop from these params to the bytes is
    /// wz-session-core's own gate; the hop this round added is the one here.
    #[test]
    fn the_batch_size_and_lease_a_config_names_reach_the_params_the_node_announces() {
        let exp = expand(
            &["--config", "z.json5"],
            r#"{ mode: "client",
                 connect: { endpoints: ["tcp/r:7447"] },
                 transport: { link: { tx: { batch_size: 4096, lease: 3000 } } } }"#,
        )
        .unwrap();
        assert!(
            exp.added.contains(&String::from("--batch-size"))
                && exp.added.contains(&String::from("--lease-ms")),
            "added = {:?}",
            exp.added
        );

        let tuned = TransportTuning::from_argv(&exp.argv).expect("the expansion is parseable");
        let params = demo_session_init_params(NodeKind::Initiator, tuned)
            .expect("OS entropy for the cookie signing key");
        assert_eq!(params.effective_batch_size(), 4096);
        assert_eq!(params.lease_ms, 3000);

        // CONTROL, in the same test: a node started WITHOUT the file announces
        // the demo's own pair, so the two assertions above cannot be passing on
        // a coincidence between the fixture and the default.
        let bare = demo_session_init_params(
            NodeKind::Initiator,
            TransportTuning::from_argv(&argv(&["--connect", "tcp/r:7447"])).unwrap(),
        )
        .expect("OS entropy for the cookie signing key");
        assert_eq!(bare.effective_batch_size(), 65535);
        assert_eq!(bare.lease_ms, 10_000);
    }

    /// The exact argv the adminspace block and the compression flag produce.
    ///
    /// The census gate is a DIFFERENCE test and would accept any change at all;
    /// this pins which flags, because zenoh's one `permissions.write` has to
    /// become both of wz's — hosting the write subscriber and permitting the
    /// write — and either alone is a node that does not do what the file says.
    #[test]
    fn the_adminspace_block_and_compression_expand_to_the_flags_that_carry_them() {
        let out = expand(
            &["--config", "z.json5"],
            r#"{ listen: { endpoints: ["tcp/0.0.0.0:7447"] },
                 transport: { unicast: { compression: { enabled: true } } },
                 adminspace: { enabled: true,
                               permissions: { read: false, write: true } } }"#,
        )
        .unwrap();
        assert_eq!(
            out.added,
            argv(&[
                "--listen",
                "tcp/0.0.0.0:7447",
                "--compression",
                "--config-queryable",
                "--no-admin-read",
                "--config-writable",
                "--config-write-permit",
            ])
        );
    }

    /// A value the operator mistyped is refused rather than rounded down to the
    /// demo's own — announcing a lease nobody asked for is the failure this
    /// round removes, and doing it after a parse error would be the same
    /// failure wearing a diagnostic.
    #[test]
    fn an_unreadable_wire_value_is_an_error_rather_than_a_silent_default() {
        for (cli, needle) in [
            (vec!["--batch-size", "70000"], "--batch-size expects"),
            (vec!["--batch-size", "0"], "zero-byte TX batch"),
            (vec!["--lease-ms", "3s"], "--lease-ms expects"),
            (vec!["--lease-ms", "0"], "already expired"),
        ] {
            let err = TransportTuning::from_argv(&argv(&cli))
                .expect_err("a value outside the type is not a tuning");
            assert!(err.contains(needle), "{cli:?} -> {err}");
        }
        assert_eq!(
            TransportTuning::from_argv(&argv(&["--listen", "tcp/a:1"])).unwrap(),
            TransportTuning::default()
        );
    }

    // ── R2072 (open-debt item 496) — the deployment check ────────────────
    //
    // Every fixture below states a defect AND the legitimate shape one
    // character away from it, in the same test. R2070b built `validate_topology`
    // that way and this surface inherits the reason: a false positive here tells
    // an operator their working deployment is broken, which is worse than the
    // silence it replaces.

    /// [`check_topology_for_build`] over a fixed set of in-memory files, with
    /// the command line DERIVED from them so no fixture can name one file and
    /// hand over another.
    ///
    /// The census is named rather than taken from this binary (R2070): every
    /// fixture here asks whether these documents can form a network, and that
    /// answer must not move when cargo's feature selection does.
    fn check(files: &[(&str, &str)]) -> Result<String, String> {
        let owned: Vec<(String, String)> = files
            .iter()
            .map(|(path, source)| (String::from(*path), String::from(*source)))
            .collect();
        let mut cli: Vec<String> = Vec::new();
        for (path, _) in &owned {
            cli.push(String::from("--check-topology"));
            cli.push(path.clone());
        }
        check_topology_for_build(
            &cli,
            |wanted| {
                owned
                    .iter()
                    .find(|(path, _)| path == wanted)
                    .map(|(_, source)| source.clone())
                    .ok_or_else(|| String::from("the fixture named a file it does not carry"))
            },
            wz::runtime_tokio::zenoh_config::ZENOH_LINK_PROTOCOLS,
        )
        .expect("the flag was on the command line")
    }

    const RTR_9: &str =
        r#"{ id: "rtr", mode: "router", listen: { endpoints: ["tcp/10.0.0.9:7447"] } }"#;
    const CLIENT_TO_9: &str =
        r#"{ id: "c1", mode: "client", connect: { endpoints: ["tcp/10.0.0.9:7447"] } }"#;

    /// A command line without the flag opens no file and judges nothing.
    ///
    /// The control for every fixture below: without it a reader that answered
    /// unconditionally would pass all of them and also fire on every ordinary
    /// run of this binary.
    #[test]
    fn without_the_flag_the_check_reads_nothing_and_judges_nothing() {
        let out = check_topology(&argv(&["--listen", "127.0.0.1:1"]), |_| {
            panic!("a command line without the flag must not open a file")
        });
        assert!(out.is_none(), "{out:?}");
    }

    /// A dial no node here answers is named; the SAME dialer beside the node
    /// that does answer it is not.
    ///
    /// The two sets differ by one digit of one address. A check that reported
    /// both would be telling an operator their working deployment is broken.
    #[test]
    fn a_dial_no_node_here_answers_is_named_and_the_matching_pair_is_not() {
        const DIALER: &str =
            r#"{ id: "edge", mode: "peer", connect: { endpoints: ["tcp/10.0.0.9:7447"] } }"#;
        const ELSEWHERE: &str =
            r#"{ id: "rtr", mode: "router", listen: { endpoints: ["tcp/10.0.0.8:7447"] } }"#;

        let err = check(&[("edge.json5", DIALER), ("rtr.json5", ELSEWHERE)])
            .expect_err("nothing in this set listens on 10.0.0.9");
        assert!(
            err.contains(r#"edge connects to "tcp/10.0.0.9:7447""#),
            "{err}"
        );

        let ok = check(&[("edge.json5", DIALER), ("rtr.json5", RTR_9)])
            .expect("the dial is answered by the node beside it");
        assert!(ok.contains("2 node(s) can form"), "{ok}");
    }

    /// One concrete address claimed twice is named; two nodes on the same
    /// WILDCARD are not.
    ///
    /// The control is the harder half. `tcp/0.0.0.0:7447` on two nodes is two
    /// machines doing the ordinary thing, and calling that a collision would
    /// refuse the commonest deployment there is.
    #[test]
    fn one_address_claimed_twice_is_named_and_two_wildcard_binds_are_not() {
        const B_9: &str =
            r#"{ id: "b", mode: "router", listen: { endpoints: ["tcp/10.0.0.9:7447"] } }"#;
        const WILD_A: &str =
            r#"{ id: "a", mode: "router", listen: { endpoints: ["tcp/0.0.0.0:7447"] } }"#;
        const WILD_B: &str =
            r#"{ id: "b", mode: "router", listen: { endpoints: ["tcp/0.0.0.0:7447"] } }"#;

        let err = check(&[("a.json5", RTR_9), ("b.json5", B_9)])
            .expect_err("two nodes cannot both bind one address");
        assert!(err.contains("is claimed by rtr, b"), "{err}");

        let ok = check(&[("a.json5", WILD_A), ("b.json5", WILD_B)])
            .expect("two machines binding every interface is not a collision");
        assert!(ok.contains("2 node(s) can form"), "{ok}");
    }

    /// A set of nothing but clients is named, and adding the one node that
    /// listens clears it.
    ///
    /// The two sets differ by exactly one node, so a check that passed both
    /// would be answering something other than the question asked.
    #[test]
    fn a_set_of_only_clients_is_named_and_one_listening_node_clears_it() {
        const C2: &str =
            r#"{ id: "c2", mode: "client", connect: { endpoints: ["tcp/10.0.0.9:7447"] } }"#;

        let err = check(&[("c1.json5", CLIENT_TO_9), ("c2.json5", C2)])
            .expect_err("a zenoh client never listens");
        assert!(err.contains("every node is a client"), "{err}");

        let ok = check(&[
            ("c1.json5", CLIENT_TO_9),
            ("c2.json5", C2),
            ("rtr.json5", RTR_9),
        ])
        .expect("the router is what they attach to");
        assert!(ok.contains("3 node(s) can form"), "{ok}");
    }

    /// A defect belonging to ONE node is named with the file that carried it,
    /// and the bad file is SECOND on purpose — a report that always printed the
    /// first path would pass a test that only asked whether a path appeared.
    #[test]
    fn a_per_node_defect_is_named_with_the_file_that_carried_it() {
        const BAD: &str =
            r#"{ id: "edge", mode: "peer", connect: { endpoints: ["banana/10.0.0.9:7447"] } }"#;

        let err = check(&[("rtr.json5", RTR_9), ("edge.json5", BAD)])
            .expect_err("`banana` is not a link protocol zenoh carries");
        assert!(err.contains("edge.json5:"), "{err}");
        assert!(!err.contains("rtr.json5:"), "{err}");
    }

    /// A clean verdict still names every key the check could not read.
    ///
    /// Without those lines "these can form a network" is read as "these files
    /// are understood", and an operator whose access-control block decides who
    /// may connect at all would have been told nothing about it.
    #[test]
    fn a_clean_verdict_still_names_every_key_the_check_could_not_read() {
        const WITH_ACL: &str = r#"{ id: "rtr", mode: "router",
             listen: { endpoints: ["tcp/10.0.0.9:7447"] },
             access_control: { enabled: true } }"#;

        let ok = check(&[("rtr.json5", WITH_ACL)]).expect("one router is a network of one");
        assert!(
            ok.contains("rtr.json5: IGNORED access_control/enabled"),
            "{ok}"
        );
        assert!(ok.contains("1 node(s) can form"), "{ok}");
    }

    /// A file that cannot be read, or that reads but is not a config, ABORTS
    /// the check rather than being dropped from the set.
    ///
    /// The discriminator is what the remaining nodes would say without it. The
    /// absent file here is the ROUTER, so a check that skipped it would report
    /// "every node is a client" plus a dangling dial — findings about a
    /// deployment that is fine, manufactured by a typo in a path.
    #[test]
    fn a_file_that_cannot_be_read_aborts_rather_than_shrinking_the_set() {
        let err = check_topology_for_build(
            &argv(&[
                "--check-topology",
                "c1.json5",
                "--check-topology",
                "rtr.json5",
            ]),
            |wanted| match wanted {
                "c1.json5" => Ok(String::from(CLIENT_TO_9)),
                other => Err(format!("cannot read {other}: no such file")),
            },
            wz::runtime_tokio::zenoh_config::ZENOH_LINK_PROTOCOLS,
        )
        .expect("the flag was on the command line")
        .expect_err("a file that cannot be read is not a deployment");
        assert!(err.contains("cannot read rtr.json5"), "{err}");
        assert!(!err.contains("every node is a client"), "{err}");

        let err = check(&[("c1.json5", CLIENT_TO_9), ("rtr.json5", "{ mode: ")])
            .expect_err("a truncated document is not a node");
        assert!(err.contains("rtr.json5:"), "{err}");
        assert!(!err.contains("every node is a client"), "{err}");
    }
}

/// R311y791 — every occurrence of a repeatable `--flag <value>` pair, in argv
/// order. [`parse_pair`] returns the FIRST and silently discards the rest,
/// which is the right shape for a flag that names one thing (one endpoint, one
/// token) and the wrong one for a flag that names a SET.
///
/// Argv order is preserved and load-bearing for the caller that needed this:
/// `--liveliness-subscribe` declares one subscriber per occurrence on ONE
/// session, and "the second subscriber" is only a meaningful phrase if the
/// order the operator wrote is the order the demo declares in.
pub(crate) fn parse_pairs(args: &[String], flag: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == flag {
            if let Some(v) = it.next() {
                out.push(v.clone());
            }
        }
    }
    out
}

/// R311y786 — parse `--connect-retry <init_ms>,<max_ms>,<factor>` into the
/// outbound re-dial schedule (zenoh's `connect.retry`:
/// `period_init_ms` / `period_max_ms` / `period_increase_factor`). Absent =>
/// `Ok(None)` and the caller keeps [`RetryPolicy::ZENOH_DEFAULT`], which is what
/// stock zenoh resolves for a config that omits the section.
///
/// Returns `Result` rather than calling `std::process::exit` the way
/// [`parse_qos_link`] does, for one reason: a parser that exits cannot be tested,
/// and the accept/reject SET is the whole content of this function. The caller
/// turns `Err` into the same exit code — a malformed value is REFUSED, never
/// degraded to the default. A silently-defaulted schedule is the failure mode
/// that looks healthy: the node runs, dials, reconnects, and paces itself by a
/// cadence the operator did not ask for and no log line contradicts.
///
/// A factor BELOW 1.0 is rejected, though the schedule itself would merely
/// collapse to zero (see [`RetryPeriod::next_ms`](wz::runtime_tokio::retry_period::RetryPeriod::next_ms)):
/// a shrinking retry period is not a configuration anyone means, and at this
/// layer — the one taking human input — the honest answer is a refusal rather
/// than a busy-loop the operator has to diagnose from behaviour.
/// R311y849 WIDENS the gate to the UNION of this parser's consumers, which is
/// now `--router-hat` AND `--peer`. It read `router-hat-router` alone on the
/// premise that `--router-hat` is "the run-mode that owns a connect list" — and
/// that premise was never true: `--peer <addr>` binds AND dials every
/// `--connect`, takes a comma-separated list, and re-dials a refused target on
/// this very schedule. Measured before the fix: a peer given
/// `--connect-retry 300,300,1` retried at 1s then 2s (zenoh's default), and a
/// peer given `--connect-retry banana` did not refuse — the arm never reached
/// the parser, so neither the value nor its VALIDATION applied.
///
/// The union spelling is deliberate and is the R311y845 rule: cfg on the set of
/// consumers rather than `allow(dead_code)`, so the arm that is off does not
/// hide a caller that is on.
///
/// Consequence for CI: a lane that names NEITHER feature selects ZERO of the
/// tests below and still exits 0, so the C1ay step names one.
#[cfg(any(feature = "router-hat-router", feature = "routing-peer"))]
pub(crate) fn parse_connect_retry(args: &[String]) -> Result<Option<RetryPolicy>, String> {
    let Some(spec) = parse_pair(args, "--connect-retry") else {
        return Ok(None);
    };
    let parts: Vec<&str> = spec.split(',').map(str::trim).collect();
    let [init, max, factor] = parts.as_slice() else {
        return Err(format!(
            "--connect-retry: `{spec}` is not a schedule; expected \
             <init_ms>,<max_ms>,<factor> (e.g. 1000,4000,2)"
        ));
    };
    let period_init_ms: u64 = init
        .parse()
        .map_err(|e| format!("--connect-retry: init `{init}` is not a millisecond count ({e})"))?;
    let period_max_ms: u64 = max
        .parse()
        .map_err(|e| format!("--connect-retry: max `{max}` is not a millisecond count ({e})"))?;
    let period_increase_factor: f64 = factor
        .parse()
        .map_err(|e| format!("--connect-retry: factor `{factor}` is not a number ({e})"))?;
    if !period_increase_factor.is_finite() || period_increase_factor < 1.0 {
        return Err(format!(
            "--connect-retry: factor `{factor}` must be finite and >= 1.0 (1 = a \
             constant delay, 2 = zenoh's default doubling)"
        ));
    }
    // The ceiling is BELOW the opening wait: the very first retry would already
    // exceed a bound the operator declared. zenoh's `> 0` guard would simply
    // clamp on the second attempt and never report it, so the value is caught
    // here — where there is still someone to tell.
    if period_max_ms > 0 && period_max_ms < period_init_ms {
        return Err(format!(
            "--connect-retry: max {period_max_ms}ms is below init {period_init_ms}ms; \
             use 0 for no ceiling"
        ));
    }
    Ok(Some(RetryPolicy {
        period_init_ms,
        period_max_ms,
        period_increase_factor,
    }))
}

/// R311y845 — WHERE `--scout` looks for its peers: zenoh's
/// `scouting/multicast/{address,interface,ttl}`, carried from argv to the
/// scouting socket.
///
/// Ungated on purpose, like every other flag in this file: the demo's rule is
/// that a flag's PARSE is identical in every build and only its EXECUTION is
/// feature-gated, so `--scout-addr` on a `scouting-active`-less binary reports
/// the same diagnostic as `--scout` itself rather than a parse error that
/// depends on the build.
///
/// `None` throughout means "no instruction", which is not the same as the
/// default: it is what lets the caller keep the compiled-in group without this
/// struct having to know what that group is.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct ScoutSocketArgs {
    /// `--scout-addr <ip>:<port>`, already known to parse as a v4 socket.
    pub(crate) address: Option<String>,
    /// `--scout-iface <name-or-ip>`.
    pub(crate) interface: Option<String>,
    /// `--scout-ttl <n>`.
    pub(crate) ttl: Option<u32>,
}

impl ScoutSocketArgs {
    /// The group and port to join: what the operator named, or the caller's
    /// defaults when they named nothing.
    ///
    /// Extracted from the scouting path rather than left inline so the FALLBACK
    /// is testable. That half is the one with no other witness: a resolver that
    /// ignored `address` entirely would still bind a working socket and still
    /// discover peers on a default-configured network, so every test that does
    /// not pin the fallback passes in a world where the key does nothing.
    ///
    /// `address` was validated as a v4 socket at the argv boundary (and at the
    /// config boundary before it), so the parse below cannot fail on operator
    /// input; keeping the fallible form and defaulting on `Err` means a future
    /// caller that skips the check degrades to the default group rather than
    /// panicking in a discovery path.
    ///
    /// Gated on the UNION of its two consumers — the `scouting-active` bind in
    /// `runner.rs` and this file's own `zenoh-config` test — rather than
    /// silenced with `allow(dead_code)`. R311y845 shipped it ungated and the
    /// pre-push changed-crate run (DEFAULT features, where neither consumer
    /// compiles) refused it as dead code, which is the gate working: every
    /// local run in that round had carried `--features ...,scouting-active`, so
    /// nothing before the hook had built the arm where this is unreachable.
    #[cfg(any(
        feature = "scouting-active",
        feature = "scouting-responder",
        all(test, feature = "zenoh-config")
    ))]
    pub(crate) fn group_and_port(
        &self,
        default_group: std::net::Ipv4Addr,
        default_port: u16,
    ) -> (std::net::Ipv4Addr, u16) {
        match self.address.as_deref().and_then(|a| a.parse().ok()) {
            Some(sock) => {
                let sock: std::net::SocketAddrV4 = sock;
                (*sock.ip(), sock.port())
            }
            None => (default_group, default_port),
        }
    }
}

/// Parse the three `--scout-*` socket flags.
///
/// A malformed value ABORTS rather than degrading to the default group, for the
/// reason `--connect-retry` aborts: a node that silently keeps looking at
/// `224.0.0.224` after being told to look elsewhere discovers nothing and says
/// nothing about why, and there is no downstream symptom that names the cause.
pub(crate) fn parse_scout_socket(args: &[String]) -> Result<ScoutSocketArgs, String> {
    let address = match parse_pair(args, "--scout-addr") {
        None => None,
        Some(raw) => {
            // The same check the config reader applies, and for the same
            // reason: zenoh types this key as a `SocketAddr`, so an address
            // without a port is a value neither implementation accepts.
            if raw.parse::<std::net::SocketAddrV4>().is_err() {
                return Err(format!(
                    "--scout-addr: `{raw}` is not an <ip>:<port> socket \
                     (e.g. 224.0.0.224:7446)"
                ));
            }
            Some(raw)
        }
    };
    let interface = match parse_pair(args, "--scout-iface") {
        Some(v) if v.is_empty() => {
            return Err(String::from(
                "--scout-iface: an empty name selects no interface; omit the \
                 flag for zenoh's `auto`",
            ))
        }
        other => other,
    };
    let ttl = match parse_pair(args, "--scout-ttl") {
        None => None,
        Some(raw) => match raw.parse::<u32>() {
            Ok(v) => Some(v),
            Err(e) => {
                return Err(format!("--scout-ttl: `{raw}` is not a hop count ({e})"));
            }
        },
    };
    Ok(ScoutSocketArgs {
        address,
        interface,
        ttl,
    })
}

/// R311y506 (session-extqos) — parse `--qos-band START-END` and `--qos-rel 0|1`
/// into the `QoSLink` metadata this node declares.
///
/// The two spellings are deliberately zenoh's own endpoint-metadata VALUES
/// (`prio=1-4` -> `--qos-band 1-4`, `rel=1` -> `--qos-rel 1`), so an operator can
/// carry a band between a zenohd endpoint string and this demo without
/// re-deriving it. `PriorityRange::from_str` accepts `start-end` over the wire
/// bytes 0..=7 (`core/mod.rs:377`) and `Reliability::from_str` accepts the
/// integer discriminant (`:531`, BestEffort=0 / Reliable=1) — both mirrored here.
///
/// A malformed value ABORTS rather than degrading to "no band". A band silently
/// dropped would leave the node negotiating the presence-only UNIT ext, and the
/// resulting session would look perfectly healthy while proving nothing about the
/// band the operator asked for — the failure mode a proof harness cannot see.
#[cfg(feature = "session-extqos")]
pub(crate) fn parse_qos_link(args: &[String]) -> Option<wz::runtime_tokio::extqos::QosLinkState> {
    use wz::runtime_tokio::config::LinkPriorityRange;
    use wz::runtime_tokio::extqos::QosLinkState;
    use wz::runtime_tokio::qos::Priority;

    fn priority(s: &str, flag: &str) -> Priority {
        let byte: u8 = s.parse().unwrap_or_else(|e| {
            eprintln!("wz-ap-demo: {flag}: `{s}` is not a priority byte ({e}); expected 0..=7");
            std::process::exit(2);
        });
        if byte as usize >= Priority::NUM {
            eprintln!("wz-ap-demo: {flag}: priority {byte} is out of range; expected 0..=7");
            std::process::exit(2);
        }
        Priority::from_wire(byte)
    }

    let priorities = parse_pair(args, "--qos-band").map(|spec| {
        let (start, end) = spec.split_once('-').unwrap_or_else(|| {
            eprintln!(
                "wz-ap-demo: --qos-band: `{spec}` is not a range; expected START-END (e.g. 1-4)"
            );
            std::process::exit(2);
        });
        LinkPriorityRange::new(priority(start, "--qos-band"), priority(end, "--qos-band"))
    });
    let reliability = parse_pair(args, "--qos-rel").map(|spec| match spec.trim() {
        "0" => wz::runtime_tokio::Reliability::BestEffort,
        "1" => wz::runtime_tokio::Reliability::Reliable,
        other => {
            eprintln!(
                "wz-ap-demo: --qos-rel: `{other}` is not a reliability; expected 0 \
                     (best-effort) or 1 (reliable)"
            );
            std::process::exit(2);
        }
    });
    if priorities.is_none() && reliability.is_none() {
        return None;
    }
    Some(QosLinkState {
        priorities,
        reliability,
    })
}

// R121d interop-tuned session params. Values aligned to
// zenoh-pico 1.5.0 defaults so the AP demo can complete a real
// session handshake against `z_put -m client`:
//
//   - `version = 0x09` matches `Z_PROTO_VERSION` in
//     zenoh-pico/include/zenoh-pico/config.h.in:190. The earlier
//     0x05 value (carried from the R121b MVP) was tolerated by
//     unicast but is one revision behind; matching the upstream
//     constant is the textbook interop default.
//   - `seq_num_res = 2` / `req_id_res = 2` match
//     `Z_SN_RESOLUTION` / `Z_REQ_RESOLUTION` (both 0x02) in the
//     same config header. The earlier `0` value resolved to an
//     8-bit SN window (`_z_sn_max(0) = 127`,
//     zenoh-pico/src/transport/utils.c:24-29), which would have
//     wrapped sequence numbers within a few frames.
//   - `batch_size = 65535` lets zenoh-pico cap to its own
//     `Z_BATCH_UNICAST_SIZE` (2048 in the bundled CLI build per
//     target/zenoh-pico-build/CMakeCache.txt). The earlier `0`
//     value crashed zenoh-pico inside `__unsafe_z_prepare_wbuf`
//     because the negotiation in
//     zenoh-pico/src/transport/unicast/transport.c:135-136
//     takes `min(own, peer)` and a zero-sized wbuf segfaults on
//     the first `_z_wbuf_put` (this was the R121d immediate
//     crash root cause).
//
// R121f — `whatami` is now role-conditional. zenoh-pico's
// production-tested handshake pattern is `Client → Peer/Router`
// (e.g. `z_put -m client` → wz-ap-demo --listen), AND `Peer →
// Peer-with-listen-locator` is fragile in zenoh-pico 1.5.0
// without prior multicast scouting (peer-peer over unicast TCP
// only is not the well-trodden path upstream). The R121f
// initiator path therefore announces `Client` (wire whatami =
// `(0x04 >> 1) & 0x03 = 0x02`) so a zenoh-pico
// `-m peer -l <locator>` listener accepts it via the same
// well-tested code path that R121c/d exercised in reverse
// (`z_put -m client` → wz acceptor).
//
// The acceptor side keeps `whatami = Peer (0x02)` from R121b/c/d
// — the existing R121c/e tests rely on this. Splitting the
// constant on role honours both directions.
//
// `lease = 10s`, `zid = 4-byte demo constant` carry from R121b
// unchanged. Production AP deployment will source these from
// deploy.yaml once the topology-schema migration (R123b-pre
// carry) lands.
/// The session-init `whatami`-determining node kind. Distinct from [`Role`] (the
/// single-session `--listen`/`--connect` discriminator) because R311qa's `--router`
/// is a THIRD node kind that is not an Acceptor: it picks the Peer `whatami` like
/// an acceptor but is modelled as its own kind rather than borrowing
/// `Role::Acceptor` (whose `listen` payload `demo_session_init_params` never
/// reads). [`Role::node_kind`] maps the single-session roles onto this.
pub(crate) enum NodeKind {
    Acceptor,
    Initiator,
    /// Only meaningful when the multi-peer router mode is compiled in.
    #[cfg(feature = "routing-router")]
    Router,
    /// Only meaningful when the peer-mesh mode is compiled in (R311qg). A peer
    /// both dials and accepts; like the router it announces the Peer `whatami`
    /// for now (a distinct WhatAmI refinement is a later atom).
    #[cfg(feature = "routing-peer")]
    Peer,
    /// P4 §5.21 ACTIVATION — the router-hat node (`--router-hat`): the ONE demo
    /// kind that announces a TRUE wire [`WhatAmI::Router`], driving the dual-mesh
    /// `RouterForwarder`. Distinct from [`NodeKind::Router`] (the star
    /// concentrator, which keeps the Peer stand-in wire value so the R121c/e
    /// accept tests and `run_router` are unchanged): the router-hat node needs
    /// the real Router role so connecting peers classify it into their linkstate
    /// graph as a router and this node partitions its two meshes by peer role.
    #[cfg(feature = "router-hat-router")]
    RouterHat,
    /// R311y277 (§5.23 `adminspace-config-hotreload` ACTIVATION) — the
    /// storage-hosting node (`--storage-host <listen>`): a bare-Session admin host
    /// that live-spawns storages from a stock zenoh-pico client's config-writes and
    /// reflects `storage_manager` `Started` in its plugins admin leg. Announces the
    /// Peer `whatami` (its admin key is `@/<zid>/peer/...`); distinct from the other
    /// kinds because it hosts a per-client Session with a `RuntimeStorageManager`
    /// rather than a forwarder (the y239 forward's reserved run-mode).
    #[cfg(feature = "adminspace-config-hotreload")]
    StorageHost,
}

impl Role {
    pub(crate) fn node_kind(&self) -> NodeKind {
        match self {
            Role::Acceptor { .. } => NodeKind::Acceptor,
            Role::Initiator { .. } => NodeKind::Initiator,
        }
    }
}

/// The zenoh protocol version byte this demo emits — `Z_PROTO_VERSION`
/// (zenoh-pico `include/zenoh-pico/config.h.in:190`), the value the interop
/// rationale above pins the session handshake to.
///
/// R311y428 — named rather than repeated: `--scout` emits it a SECOND time, in
/// the Scout frame's body byte 0 (`ScoutParams::version`), and a Scout that
/// announced a different version than the InitSyn that follows would be a wire
/// inconsistency with no single place to correct it.
pub(crate) const DEMO_PROTO_VERSION: u8 = 0x09;

/// The demo's default zenoh id, overridable with `--zid <hex>`.
///
/// R311y428 — named for the same reason as [`DEMO_PROTO_VERSION`]: `--scout`
/// puts it on the wire a second time (the Scout frame's `I`-flagged id, which
/// is how a responder identifies the scouter), and the Scout should announce
/// the identity the session that follows will open with.
pub(crate) const DEMO_ZID: [u8; 4] = [0x01, 0x02, 0x03, 0x04];

/// `--scout-timeout-ms` default: the TOTAL active-scouting budget in ms, spent
/// across repeated Scout cycles until a peer's Hello arrives.
///
/// Feature-uniform (NOT cfg'd on `scouting-active`), for the reason
/// [`LivelinessGetSpec::after_ms`] states for its own knob: the argv surface
/// must parse identically in the OFF build, where `--scout` is rejected with a
/// feature message rather than a parse error.
pub(crate) const DEFAULT_SCOUT_BUDGET_MS: u64 = 10_000;

/// R311y843 — the handshake values an operator can move, carried as ONE value
/// so that a further transport knob does not become a further parameter on
/// five run-mode signatures.
///
/// Both fields go on the WIRE: `batch_size` is the InitSyn's advertised TX
/// batch (the peer sizes its own buffer from it and the session negotiates the
/// min), `lease_ms` is the OpenSyn's lease (the peer's keepalive deadline for
/// this session). That is why they are settings the demo cannot keep to
/// itself: a node that ignores them is not merely locally misconfigured, it
/// tells the other end something the operator did not say.
///
/// [`Default`] is the pair the demo announced as literals before this type
/// existed, so a build with neither flag is byte-identical on the wire to the
/// one that came before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TransportTuning {
    /// InitSyn `batch_size`. The `0`-unset sentinel is `SessionInitParams`'
    /// own; this type never produces it, since a `0` from a config file is
    /// refused by `ZenohNodeConfig::validate` before it reaches here.
    pub(crate) batch_size: u16,
    /// OpenSyn lease, in milliseconds.
    pub(crate) lease_ms: u64,
}

impl Default for TransportTuning {
    fn default() -> Self {
        Self {
            batch_size: 65535,
            lease_ms: 10_000,
        }
    }
}

impl TransportTuning {
    /// Read `--batch-size <n>` / `--lease-ms <n>` off the command line.
    ///
    /// Both are the argv shape a stock zenoh config expands into, and both are
    /// equally usable by hand — that is the point of the expansion, and the
    /// reason the config does not reach past the command line into this
    /// struct.
    ///
    /// A malformed value is an ERROR rather than a silent fallback to the
    /// default: the operator asked for a specific wire announcement, and
    /// announcing a different one because their digits were unparseable is the
    /// failure this whole round exists to remove.
    pub(crate) fn from_argv(rest: &[String]) -> Result<Self, String> {
        let mut out = Self::default();
        if let Some(v) = parse_pair(rest, "--batch-size") {
            out.batch_size = v
                .parse::<u16>()
                .map_err(|_| format!("--batch-size expects 1..=65535 (a u16), got '{v}'"))?;
            if out.batch_size == 0 {
                return Err(String::from(
                    "--batch-size 0 would advertise a zero-byte TX batch",
                ));
            }
        }
        if let Some(v) = parse_pair(rest, "--lease-ms") {
            out.lease_ms = v
                .parse::<u64>()
                .map_err(|_| format!("--lease-ms expects milliseconds, got '{v}'"))?;
            if out.lease_ms == 0 {
                return Err(String::from(
                    "--lease-ms 0 would announce a lease that is already expired",
                ));
            }
        }
        Ok(out)
    }
}

/// R311y820 — FALLIBLE, because the cookie signing key is now drawn from OS
/// entropy rather than written as a literal, and there is no honest way to
/// absorb an entropy failure into a key. A host that cannot obtain entropy at
/// startup cannot serve an acceptor securely, so the caller declines to build
/// the bundle rather than opening one whose cookie MAC anybody can forge.
/// The error is `io::Error` rather than the port's own
/// [`EntropyUnavailable`](wz::runtime_tokio::session_glue::EntropyUnavailable)
/// because all five callers sit in `io::Result<()>` run-mode bodies; mapping
/// once here beats five `map_err`s, and a binary that cannot reach the OS
/// entropy pool is reporting an environment fault, which is what `io::Error`
/// names.
pub(crate) fn demo_session_init_params(
    kind: NodeKind,
    tuning: TransportTuning,
) -> std::io::Result<SessionInitParams> {
    let whatami = match kind {
        NodeKind::Acceptor => WhatAmI::Peer, // R121b/c/d/e baseline
        // The router accepts via the same well-tested Client->Peer direction as
        // the acceptor (a true WhatAmI::Router wire value is a later refinement,
        // R311qa carry), so it also announces Peer.
        #[cfg(feature = "routing-router")]
        NodeKind::Router => WhatAmI::Peer,
        // A hold-only mesh peer announces Peer too (whatami refinement later).
        #[cfg(feature = "routing-peer")]
        NodeKind::Peer => WhatAmI::Peer,
        // P4 §5.21 ACTIVATION — the router-hat node announces the TRUE Router
        // wire value (0b00), so a connecting peer's linkstate graph tags it as a
        // router and this node's RouterForwarder partitions faces by role. This
        // is the first wz run-mode to present WhatAmI::Router on the wire.
        #[cfg(feature = "router-hat-router")]
        NodeKind::RouterHat => WhatAmI::Router,
        // R311y277 — the storage host announces Peer, so its admin key is
        // `@/<zid>/peer/...` (the surface a pico z_get / z_put addresses).
        #[cfg(feature = "adminspace-config-hotreload")]
        NodeKind::StorageHost => WhatAmI::Peer,
        NodeKind::Initiator => WhatAmI::Client, // R121f initiator path
    };
    Ok(SessionInitParams {
        version: DEMO_PROTO_VERSION,
        whatami,
        zid: DEMO_ZID.to_vec(),
        seq_num_res: 2,
        req_id_res: 2,
        // R311y843 — the two handshake fields an operator's stock zenoh config
        // can move. They were literals here until the config reader had a way
        // to reach them, which meant `--config` reported
        // `transport/link/tx/lease` as honoured and the node then announced
        // this ten-second one.
        batch_size: tuning.batch_size,
        lease_ms: tuning.lease_ms,
        initial_sn: 0,
        cookie: Vec::new(),
        // R311y820 — DRAWN, not a literal. This site carried a 32-byte `0xAB`
        // constant with a comment promising that a
        // production deployment "MUST supply real per-process entropy via
        // `SigningKey::new_random()`" — a method R311ei had already removed,
        // so the note named a symbol that no longer existed and nothing ever
        // supplied the entropy. The key of every acceptor this binary opened
        // was therefore a literal in a public repository.
        cookie_signing_key: SigningKey::from_entropy(&mut OsEntropy).map_err(|e| {
            std::io::Error::other(format!(
                "no OS entropy for the cookie signing key ({e}); refusing to open a \
                 session whose anti-amplification cookie anybody could forge"
            ))
        })?,
    })
}

/// R311y345 — the publisher's `--publish` bundle. Was a bare
/// `(String, PushOperation, Option<u64>)` tuple threaded through `run_demo` and
/// `spawn_tasks`; `--publish-after-ms` would have made it a second consecutive
/// `Option<u64>`, distinguishable only by position at every call site. Named
/// per the sibling idiom here ([`DeclareEmitSpec`], [`QueryRoleSpec`],
/// [`RemoteLogSpec`], [`ReplyConsumerSpec`]) instead.
pub(crate) struct PublisherSpec {
    /// `--publish <keyexpr>` — the literal the burst emits on.
    pub(crate) keyexpr: String,
    /// `--value <text>` (Put) or `--delete` (Del).
    pub(crate) operation: PushOperation,
    /// `--declare-id <id>` — when set, a DeclKexpr preamble maps `id -> keyexpr`
    /// and the burst emits aliased Pushes carrying only the id.
    pub(crate) declare_id: Option<u64>,
    /// `--publish-after-ms <ms>` — hold the burst this long AFTER Established,
    /// leaving the line idle. The ordering a foreign peer needs to witness
    /// `transport-keepalive`: past the adopted lease, a peer expires a silent
    /// line, so a Push that still lands proves the KeepAlive held it open.
    pub(crate) publish_after_ms: Option<u64>,
    /// `--batch` — wrap the burst in a TX batching window (`zp_start_batching` /
    /// `zp_batch_stop` parity), so every Push rides ONE frame as a message chain
    /// instead of one frame each. The shape a foreign peer needs to witness
    /// `transport-batching`: surfacing every Push proves it walked the chain to
    /// the end.
    pub(crate) batch: bool,
    /// `--matching-log` — declare a `Publisher` on `keyexpr` plus a
    /// `Publisher::declare_matching_listener`, and log every matching-status
    /// TRANSITION it reports.
    ///
    /// The ordering a FOREIGN peer needs to witness `session-matching`: the
    /// transitions are caused entirely by the remote's own
    /// `Declare(DeclSubscriber)` / `Declare(UndeclSubscriber)`, so a pico
    /// `z_sub` arriving and leaving drives both edges without wz touching the
    /// wire. Registration itself never fires (pico transition-only), which is
    /// why the listener is installed PRE-DRIVE, before any inbound Declare can
    /// be dispatched.
    ///
    /// Binds to the atom's OWN gated code: `Publisher::declare_matching_listener`
    /// is `#[cfg(all(feature = "session-matching", feature = "declare-subscriber"))]`
    /// and rejects typed with the feature off. Its sibling
    /// `Publisher::get_matching_status` is gated on `declare-subscriber` ALONE, so
    /// polling would NOT bind the claim to `session-matching`.
    pub(crate) matching_log: bool,
}

/// R121k-5 / R311oy — bundle of declare-emit keyexprs the demo emits once the
/// session reaches Established. Holds `--declare-token` (the high-level
/// [`wz::runtime_tokio::session::Session::declare_token`] RAII liveliness
/// token) and `--liveliness-subscribe`. The former `--declare-subscriber` /
/// `--declare-queryable` raw-emit fields were retired in R311oy: `--key` /
/// `--queryable` now declare a ROUTED subscriber / queryable through the real
/// `Session::declare_{subscriber, queryable}` path (R311ou / R311ow), handled
/// in `install_session_handles` rather than the raw `send_declare_*` emit here.
pub(crate) struct DeclareEmitSpec {
    pub(crate) token_keyexpr: Option<String>,
    /// R280 — optional `--liveliness-subscribe <keyexpr>` payload.
    /// When `Some`, the demo calls
    /// [`wz::runtime_tokio::session::Session::declare_liveliness_subscriber`]
    /// once before the drive_session loop starts; the returned RAII
    /// handle lives at `run_demo` scope so `Drop` emits
    /// `Interest(Final)` when the demo terminates. Separate from
    /// `token_keyexpr` (which declares a
    /// [`wz::runtime_tokio::session::LivelinessToken`] on the
    /// peer-facing side) because a single demo instance can act as
    /// token publisher + token subscriber simultaneously on a wz↔wz
    /// round-trip.
    /// R311y791 — REPEATABLE. One subscriber is declared per entry, in argv
    /// order, all on the SAME session. Empty = no liveliness subscriber, which
    /// is what the absent flag used to mean as `None`.
    ///
    /// It became a list for a witness that needs exactly two on one session:
    /// a zenoh router answers a second CURRENT token interest from the same
    /// face with the id it already used for that resource (`make_token_id`
    /// reuses `local_tokens[res]` whenever the mode is future-bearing,
    /// `hat/router/token.rs:978-990`), so wz's own first-declaration-wins
    /// guard drops the reply and the second subscriber is served entirely by
    /// the local replay (R311y790).
    pub(crate) liveliness_subscriber_keyexpr: Vec<String>,
    /// R311y775 — `--querier-matching-log <keyexpr>`: declare a
    /// [`wz::runtime_tokio::session::Querier`] on `keyexpr` plus a
    /// `Querier::declare_matching_listener`, and log every matching-status
    /// TRANSITION it reports.
    ///
    /// The QUERYABLE-plane twin of `--matching-log`, and a SEPARATE knob rather
    /// than a mode of it: the two watch different registries
    /// (`RemoteSubscriberRegistry` vs `RemoteQueryableRegistry`), are gated on
    /// different features (`declare-subscriber` vs `declare-queryable`), and are
    /// driven by different foreign processes (a pico `z_sub` vs a pico
    /// `z_queryable`). Folding them into one flag would make a run that proves
    /// one look like a run that proves both.
    ///
    /// Valued rather than bare because it does NOT ride the publisher: a querier
    /// carries its own keyexpr, so `--publish` is not a precondition here the way
    /// it is for `--matching-log`.
    ///
    /// Deliberately NOT cfg-gated, for the same reason as `--matching-log`: the
    /// `session-matching`-OFF build must reach the same path and surface the
    /// typed reject, because that arm is the anti-vacuity twin.
    pub(crate) querier_matching_log_keyexpr: Option<String>,
    /// R311y798 — `--querier-matching-all-complete`: declare a SECOND querier
    /// on the very same `--querier-matching-log` keyexpr, differing in exactly
    /// one thing — its target is `QueryTarget::AllComplete` (a code span: this
    /// crate does not depend on wz-session-core directly, so the path is not a
    /// link it can resolve) — and log its transitions under a DISTINCT prefix.
    ///
    /// A bare companion of `--querier-matching-log` rather than a keyexpr of
    /// its own, and that is the whole point: the two queriers must be
    /// incapable of differing in anything but the target, because the claim
    /// this flag exists to witness is "the SAME foreign declaration is
    /// accepted by one and refused by the other". Giving it its own keyexpr
    /// would let a fixture pass on a keyexpr mismatch.
    ///
    /// The log prefix is `QUERIER ALLCOMPLETE MATCHING STATUS`, which contains
    /// neither `QUERIER MATCHING STATUS` nor is contained by it — so neither
    /// plane's grep can be satisfied by the other's line. That non-containment
    /// is checked by eye here because it is the property the fixture rests on:
    /// `--matching-log`'s own prefix is a substring of the querier's, and only
    /// the keyexpr in the pattern keeps those two apart.
    ///
    /// Deliberately NOT cfg-gated, same terms as its companion: a
    /// `query-target`-OFF build must reach the same path, where
    /// `effective_target` returns `None` and the AllComplete querier degrades
    /// into an ordinary one. A fixture that sees both prefixes report the same
    /// verdict has found exactly that build.
    pub(crate) querier_matching_all_complete: bool,
    /// R311ph — `--liveliness-subscribe-history`: declare the liveliness
    /// subscriber with `history = true` so the peer/router replays the CURRENT
    /// alive tokens on subscription (not just future declares). This makes an
    /// observer order-independent of when the token was declared — the fix for
    /// the leg-7 interop ordering race (a late-arriving `history = false`
    /// subscriber would miss an already-alive token).
    pub(crate) liveliness_subscriber_history: bool,
    /// R311y791 — `--liveliness-subscribe-on-sample <keyexpr>`: declare ONE
    /// more liveliness subscriber (always `history = true`) from inside the
    /// first subscriber's callback, the moment a `Put` proves this session
    /// already knows a token.
    ///
    /// Separate from the repeatable `--liveliness-subscribe` because the two
    /// differ in WHEN, and when is the whole observable: subscribers named by
    /// that flag are declared before the session is driven, so their
    /// `peer_token_table` is empty and there is nothing to replay. This one is
    /// declared after, which is the only arrangement in which the R311y790
    /// declare-time replay is the thing under test.
    pub(crate) liveliness_subscriber_on_sample: Option<String>,
    /// R311y442 — `--advanced-subscribe <keyexpr>`: declare an
    /// [`wz::runtime_tokio::AdvancedSubscriber`] with a STARTUP HISTORY GET, so a
    /// subscriber that joins after a publisher has already published recovers the
    /// cached samples from that publisher's `@adv` cache. Feature-uniform (always
    /// parsed) on the same terms as `namespace` / `lowlatency`: `None` without the
    /// flag OR when built without the `advanced` feature, in which case the flag is
    /// inert and `install_session_handles` says so on stderr rather than declaring
    /// a plain subscriber that would silently look like a working history.
    pub(crate) advanced_subscriber_keyexpr: Option<String>,
    /// R311y442 — `--history-max <N>`: the `_max=N` cap on the startup history GET
    /// ([`HistoryConfig::max_samples`]). `None` leaves the GET uncapped, which is
    /// the zenoh default. Only read when `advanced_subscriber_keyexpr` is `Some`.
    pub(crate) advanced_history_max: Option<usize>,
    /// R311y442 — `--history-max-age <secs>`: the `_time=[now(-secs)..]` age bound
    /// on the startup history GET ([`HistoryConfig::max_age`]).
    ///
    /// It exists to make the LIST SEPARATOR observable from outside, which no
    /// other knob can do. `_anyke` is provable with a single-parameter selector,
    /// but `;`-vs-`&` only shows up once a selector carries TWO parameters: under
    /// the `&` spelling a real zenoh cache reads `_max=2&_time=[..]` as one
    /// parameter keyed `_max` whose value fails to parse, drops the cap, and
    /// replies with its WHOLE ring. So `--history-max 2 --history-max-age N`
    /// against a 5-sample foreign cache answers 2 when the dialect is right and 5
    /// when it is wrong — a foreign witness for the separator, not just a unit test.
    pub(crate) advanced_history_max_age: Option<f64>,
    /// R311y443 — `--advanced-recovery`: arm SAMPLE-DRIVEN retransmission on the
    /// advanced subscriber ([`RecoveryConfig::sample_driven`]). Off by default,
    /// which is zenoh's default too — `.recovery()` is opt-in there as well.
    ///
    /// The flag is what makes the recovery path's RED/GREEN twin a one-argument
    /// difference. With it, a forward gap is buffered and back-filled by an
    /// `_sn=last+1..` GET; without it the same gap reports a `Miss` and delivers
    /// past the hole. Two runs of one binary over one fixture therefore separate
    /// "the sample came back because it was recovered" from "the sample was never
    /// lost" — which no single run can.
    ///
    /// Sample-driven only: neither `periodic_queries` nor `heartbeat` is armed,
    /// so a recovered sample is attributable to the gap that triggered the GET
    /// rather than to a timer or to a foreign publisher's beacon.
    pub(crate) advanced_recovery: bool,
    /// R311y444 — `--advanced-recovery-heartbeat`: additionally arm the HEARTBEAT
    /// retransmission trigger ([`RecoveryConfig::with_heartbeat`]), which declares
    /// a second subscriber on `<ke>/@adv/pub/**` and issues a recovery GET when a
    /// publisher's beacon reports samples past `last_delivered`.
    ///
    /// Requires `--advanced-recovery` (the trigger lives inside `RecoveryConfig`,
    /// so without recovery there is nothing to add it to); the parser rejects the
    /// pair rather than silently arming nothing.
    ///
    /// Kept separate from `--advanced-recovery` deliberately. The two triggers
    /// issue DIFFERENT selectors — sample-driven sends an OPEN `_sn=last+1..`
    /// while heartbeat sends a BOUNDED `_sn=last+1..hb` — and that difference is
    /// the only thing that distinguishes them on the wire when both could have
    /// fired, so a flag that armed both at once would make the distinction
    /// unobservable.
    pub(crate) advanced_recovery_heartbeat: bool,
    /// R311y447 — `--advanced-recovery-periodic <ms>`: additionally arm the
    /// PERIODIC retransmission trigger ([`RecoveryConfig::with_periodic_queries`]),
    /// a background loop that re-asks every known source `_sn=last+1..` on a
    /// cadence. `None` (default) leaves it unarmed.
    ///
    /// Requires `--advanced-recovery`, and kept separate from it for the same
    /// reason as the heartbeat twin: the three triggers must stay individually
    /// attributable.
    ///
    /// It carries a PERIOD rather than being a bare switch because the period is
    /// the observable. The periodic trigger emits the same OPEN `_sn=last+1..`
    /// selector the sample-driven one does, so selector shape cannot separate
    /// them — what separates them is that `periodic_requests`
    /// (`advanced_subscriber.rs:685-702`) asks on EVERY tick for every known
    /// source with no GET in flight, consulting nothing, while sample-driven
    /// needs a non-empty reorder buffer (`:605`). On a stream with no loss the
    /// two therefore differ in PRESENCE, not in shape — and a fixture asserting
    /// that needs to know the cadence to expect.
    ///
    /// R311y447-review — an earlier version of this doc said sample-driven fires
    /// "out of `handle_live`'s gap branch" and that `periodic_requests` mirrors
    /// zenoh's `PeriodicQuery::run`. Both were overstated: the sample-driven
    /// request is issued after the match on `!pending_samples.is_empty()`, which
    /// history buffering can also satisfy, and wz's periodic carries an in-flight
    /// gate upstream does not. See `periodic_requests`' own doc for the second.
    pub(crate) advanced_recovery_periodic_ms: Option<u64>,
    /// R311y445 — `--group-join <group>`'s bundle: join a zenoh-ext GROUP as a
    /// member and hold the session open so a foreign group peer sees this member
    /// in its view. `None` without the flag.
    ///
    /// A separate surface from the advanced-pubsub flags rather than an extension
    /// of them: the group plane is self-contained (its own bincode wire on its own
    /// keyexpr namespace, independent of `@adv`).
    pub(crate) group_join: Option<GroupJoinSpec>,
    /// R311y442 — `--advanced-publish <keyexpr>`'s bundle. The ANSWERING half of
    /// the advanced-pubsub plane: a wz [`AdvancedPublisher`] with a sample cache,
    /// which a FOREIGN advanced subscriber then drains. `None` without the flag.
    pub(crate) advanced_publish: Option<AdvancedPublishSpec>,
}

/// R311y442 — the `--advanced-publish` parameter bundle. A struct rather than
/// five more `Option` fields on [`DeclareEmitSpec`] for the reason the rest of
/// this module already settled: the task takes one spec, not a positional list.
///
/// The `advanced`-OFF build reports every field it is ignoring, one by one. That
/// is not a lint workaround: an operator who passed `--cache-max 8` to a binary
/// built without the feature needs to see that the depth was dropped too, not
/// just that the keyexpr was.
pub(crate) struct AdvancedPublishSpec {
    /// `--advanced-publish <keyexpr>` — the literal the burst publishes on, and
    /// the base of the `<keyexpr>/@adv/pub/<zid>/<eid>/_` cache KE derived from it.
    pub(crate) keyexpr: String,
    /// `--value <text>` — the burst payload, emitted as `[{idx:4}] {value}` to
    /// mirror upstream's own `z_advanced_pub` sample shape.
    pub(crate) value: String,
    /// `--advanced-publish-count <N>` — how many samples the burst emits.
    pub(crate) count: usize,
    /// `--cache-max <N>` — the publisher's cache depth (`CacheConfig::max_samples`).
    /// `None` keeps the wz default.
    pub(crate) cache_max: Option<usize>,
    /// Milliseconds between burst samples. Fixed rather than a flag: its only job
    /// is to keep the samples distinguishable in time for the `_time` filter, and
    /// a knob nothing varies is a knob that rots.
    pub(crate) interval_ms: u64,
    /// R311y444 — `--advanced-publish-heartbeat <ms>`: arm the publisher's
    /// last-sn heartbeat BEACON at this period
    /// (`MissDetectionConfig::heartbeat`). `None` (default) = no beacon, which
    /// is what makes the control twin of the beacon leg possible.
    ///
    /// This is the ANSWERING half's counterpart to `--advanced-recovery`: the
    /// beacon is what tells a subscriber that a sample it never saw exists at
    /// all. It matters most for the LAST sample of a burst, which no later live
    /// sample can reveal a gap before — so with the beacon off, a lost last
    /// sample is unrecoverable BY CONSTRUCTION rather than by timing.
    pub(crate) heartbeat_ms: Option<u64>,
    /// The publisher's source identity, stamped into every sample's `SourceInfo`
    /// and rendered into the `@adv` KE. Taken from the demo's `--zid`, so a
    /// multi-publisher fixture gets distinct `@adv` namespaces the same way it
    /// gets distinct session zids.
    pub(crate) zid: Vec<u8>,
}

/// R311y445 — the `--group-join` parameter bundle.
///
/// The `advanced`-OFF build reports every field it is ignoring, one by one, for
/// the same reason [`AdvancedPublishSpec`] does: an operator who passed a member
/// id needs to see that it was dropped too, not just that the group was.
pub(crate) struct GroupJoinSpec {
    /// `--group-join <group>` — the group name. Must be non-wild; `Group::join`
    /// rejects a wildcard and the demo surfaces that rejection rather than
    /// silently joining nothing.
    pub(crate) group: String,
    /// `--group-member-id <id>` — this member's id, which is the literal a
    /// foreign peer prints in its view listing, so a fixture greps for it.
    pub(crate) member_id: String,
    /// `--group-lease-secs <n>` — the member lease. A fixture matches it to the
    /// oracle's own `Duration::from_secs(3)` so both sides expire on one scale;
    /// wz's default (zenoh-ext's 18s) otherwise.
    pub(crate) lease_secs: Option<u64>,
}

/// R121k-5 — bool flag bundle for the three Remote* registry log
/// callbacks. Each `true` installs a callback that prints a
/// stderr line on the matching inbound Declare arm so an integration
/// test fixture can grep for the expected line shape.
pub(crate) struct RemoteLogSpec {
    pub(crate) on_remote_subscriber: bool,
    pub(crate) on_remote_queryable: bool,
    pub(crate) on_remote_liveliness: bool,
}

/// R121j-6-e2e — bool flag bundle for the initiator-side
/// ReplyRegistry log callbacks. Both flags require --query (the rid
/// the registry binds to is the rid of the outbound Query this demo
/// emits); the validation in `main` rejects mis-wired argv before
/// this struct is constructed. Each `true` installs a callback that
/// prints a stderr line on the matching inbound record so an
/// integration test fixture can grep for the expected line shape.
pub(crate) struct ReplyConsumerSpec {
    pub(crate) on_query_reply: bool,
    pub(crate) on_query_final: bool,
    /// R263 — pending-entry deadline (ms) propagated to the
    /// observer.replies.register call below. Value 0 means "no
    /// timeout" (deadline_ms = None at register; pre-R263 behaviour
    /// preserved). Value > 0 means "compute deadline_ms =
    /// session_clock.now_monotonic_ms() + query_timeout_ms" so the
    /// R264 sweep_task surfaces on_final within that wall-clock
    /// budget when no Final arrives.
    pub(crate) query_timeout_ms: u32,
    /// R270 — sweep_task tick period (ms). Lower values tighten
    /// the bound on `on_final`'s post-deadline wall-time at the cost
    /// of more wake-ups. Must be > 0 (the main-side parser rejects
    /// 0 explicitly so this struct field can stay an unwrapped u32).
    /// The pre-R270 hardcoded value (100 ms) is the default the
    /// parser supplies when `--sweep-cadence-ms` is absent, so
    /// every existing wz-ap-demo invocation retains identical
    /// behaviour.
    pub(crate) sweep_cadence_ms: u32,
}

/// R121j-6-e2e — bundle of the Q/R role config. Carries the
/// queryable side (--queryable + --reply pair) and the z_get side
/// (--query) so a single demo can act as queryable, z_get, both, or
/// neither. Kept distinct from the publisher / subscriber / declare
/// configs because the wire-side dispatch tables (QueryableRegistry,
/// ReplyRegistry) live in a different module than the pubsub one.
/// R121j-5c-e2e-demo carried (--queryable, --reply, --query) on
/// separate run_demo parameters; R121j-6-e2e consolidates them so
/// run_demo's clippy::too_many_arguments threshold stays satisfied
/// with the new reply_log_spec.
pub(crate) struct QueryRoleSpec {
    pub(crate) queryable: Option<QueryableSpec>,
    pub(crate) query: Option<QueryEmitSpec>,
    /// liveliness-get — optional `--liveliness-get <keyexpr>` bundle.
    /// When `Some`, the demo spawns an Established-gated
    /// [`crate::tasks::liveliness_get_task`] that issues one
    /// [`wz::runtime_tokio::session::Session::liveliness_get`] snapshot
    /// query and logs each `LIVELINESS GET REPLY` + the terminating
    /// `LIVELINESS GET FINAL`. Grouped with the query role (both are
    /// reply-consuming "get" surfaces) though the wire is the
    /// declaration plane (a CURRENT liveliness Interest), not the
    /// Request/Query plane.
    pub(crate) liveliness_get: Option<LivelinessGetSpec>,
}

/// R311y481 — the `--queryable` bundle. Was a bare `(String, String)` tuple
/// (pattern, reply_text) threaded through [`QueryRoleSpec`]; `--reply-err` makes
/// the answer a two-armed CHOICE rather than a second string, so it is named per
/// the sibling idiom here ([`PublisherSpec`], [`DeclareEmitSpec`],
/// [`LivelinessGetSpec`]) instead of growing into a triple whose arms would be
/// distinguishable only by position.
pub(crate) struct QueryableSpec {
    /// `--queryable <keyexpr>` — the pattern the routed queryable declares on.
    pub(crate) keyexpr: String,
    /// How this queryable answers a matching inbound Query.
    pub(crate) reply: QueryableReply,
    /// R311y798 — `--queryable-complete`: declare this queryable COMPLETE, i.e.
    /// able to answer its whole keyexpr alone. Two consequences, and the flag
    /// exists for the second:
    ///
    /// 1. on the WIRE it sets the `QueryableInfo` ext's `C` bit, which is what
    ///    a peer reads to decide whether an `AllComplete` query may reach it;
    /// 2. LOCALLY it is the operand of the completeness conjunct in both the
    ///    dispatch filter and the matching-status verdict, so it is the only
    ///    thing that lets a session-local queryable satisfy an `AllComplete`
    ///    querier on the same session.
    ///
    /// Default `false`, which is zenoh's builder default and pico's
    /// `_Z_QUERYABLE_COMPLETE_DEFAULT` — so a run without the flag emits the
    /// same bytes it always did (pico omits the ext entirely at that value).
    pub(crate) complete: bool,
}

/// R311y481 — the queryable's answer form: an OK Put-form reply (`--reply`) or
/// an ERR reply (`--reply-err`).
///
/// An enum rather than two `Option<String>` fields because the two are mutually
/// exclusive on the wire — a queryable answers a given Query with one or the
/// other, never both — and the parser rejects the pair. Making the exclusion
/// unrepresentable is cheaper than a runtime guard
/// (`feedback_unrepresentable_over_test`).
pub(crate) enum QueryableReply {
    /// `--reply <text>` — a Put-form Reply carrying `text` as the payload. The
    /// R121j-5c-e2e shape, unchanged.
    Ok(String),
    /// `--reply-err <text>` — an ERR-form Reply carrying `text` as the error
    /// payload, via [`wz_session_core::query_sink::ReplyOut::reply_err`].
    ///
    /// `reply_err` is signature-STABLE (ungated on the trait) but its emit is
    /// gated: `query.rs`'s impl calls `send_err` only under
    /// `#[cfg(feature = "query-reply-err")]` and drops the call otherwise. So an
    /// OFF build answers a matching Query with NOTHING — not with a degraded OK
    /// reply that would read like a working error path. That is what binds a
    /// foreign witness of this flag to the atom's OWN gated code
    /// (`feedback_claim_binds_to_atom_code`).
    Err(String),
}

/// R311y481 — the `--query` bundle. Was a bare `String` (the keyexpr) threaded
/// through `run_demo` and `spawn_background_tasks`; `--query-params` and
/// `--query-attachment` make it a three-field payload, so it is named per the
/// sibling idiom rather than grown into a tuple of two consecutive `Option`s.
///
/// Both new fields are feature-UNIFORM (always parsed), on the same terms as
/// `--namespace` / `--lowlatency` / `--publish-after-ms`: the argv surface must
/// parse identically in the OFF build. Their inertness is decided downstream by
/// `build_request_query_with_meta`, which threads `meta.parameters` only under
/// `#[cfg(feature = "query-selector-parameters")]` and `meta.attachment` only
/// under `#[cfg(feature = "query-attachment")]` — the atoms' own gates. A
/// build without them emits the same Query bytes as a run without the flags,
/// which is exactly the RED arm a damage test needs.
pub(crate) struct QueryEmitSpec {
    /// `--query <keyexpr>` — the literal the outbound Query carries.
    pub(crate) keyexpr: String,
    /// `--query-params <params>` — the URL-style selector parameters that ride
    /// the Query body's `Q_P` flag + params slice (what a zenoh selector spells
    /// after `?`). `None` elides the flag entirely.
    ///
    /// Foreign-observable with no patch: pico's stock queryable handlers print
    /// the keyexpr and the parameters CONCATENATED —
    /// `Received Query '<keyexpr><params>'` via `z_query_parameters`
    /// (`z_queryable.c:38-39`) — so a dropped `Q_P` slice prints the bare
    /// keyexpr and a witness on the full string separates the two.
    pub(crate) parameters: Option<String>,
    /// `--query-attachment <k>=<v>[,<k>=<v>…]` — kv pairs serialized into the
    /// Query attachment ext (0x05) in pico's `ze_serializer` sequence form.
    ///
    /// Pairs rather than an opaque blob because the ORACLE is structured: pico's
    /// `z_queryable_attachment` runs
    /// `ze_deserializer_deserialize_sequence_length` and prints one
    /// `i: <key>, <value>` line per pair, and a bare byte blob fails that
    /// deserialize and prints NOTHING (`z_queryable_attachment.c:71-87`). The
    /// same constraint the push-side `z_sub_attachment` witness lives under, so
    /// the same SSOT encodes it (`serialize_kv_attachment`).
    pub(crate) attachment: Option<Vec<(String, String)>>,
    /// `--query-after-ms <ms>` — hold the Query this long AFTER Established.
    ///
    /// The `--liveliness-get-after-ms` precedent, and needed for the SAME narrow
    /// reason that doc states: this Query is ONE-SHOT with no retry, so unlike the
    /// burst-driven publisher fixtures (whose 5x200ms burst covers the window for
    /// a remote declaration to land) it gets exactly one chance. A foreign
    /// queryable that has not finished declaring when the Query arrives never sees
    /// it, and the demo has nothing to absorb that with.
    ///
    /// This was MEASURED, not assumed: a hand run with no hold passed, and passed
    /// only because pico happened to print `Creating Queryable on` before the
    /// Query landed. Relying on that is the flake this knob removes — a fixture
    /// gates on pico's readiness line and sets the hold past it, so the ordering
    /// is owned rather than raced (`feedback_no_flaky_ever`,
    /// `feedback_hand_composed_fixture_needs_twin`).
    ///
    /// Deliberately NOT cfg-gated on any query atom, for the reason
    /// `--publish-after-ms` is not gated on `transport-keepalive`: it is a pure
    /// ordering delay, inert when the atoms are off, and it must stay reachable in
    /// the OFF build so the RED arm walks the identical path.
    pub(crate) after_ms: Option<u64>,
}

/// R311y353 — the `--liveliness-get` bundle. Was a bare `String` (the keyexpr)
/// threaded through `run_demo` and `spawn_background_tasks`; `--liveliness-get-
/// after-ms` makes it a two-field payload, so it is named per the sibling idiom
/// here ([`PublisherSpec`], [`DeclareEmitSpec`], [`QueryRoleSpec`],
/// [`RemoteLogSpec`], [`ReplyConsumerSpec`]) rather than grown into a tuple.
/// The atom's own surface has a further knob in reach for a later round
/// (`LivelinessGetOptions::timeout_ms`, which this task currently leaves at
/// `default()`), and a named struct is where that lands without touching a call
/// site.
pub(crate) struct LivelinessGetSpec {
    /// `--liveliness-get <keyexpr>` — the filter the CURRENT liveliness
    /// Interest carries.
    pub(crate) keyexpr: String,
    /// `--liveliness-get-after-ms <ms>` — hold the get this long AFTER
    /// Established.
    ///
    /// WHAT IT IS FOR, stated narrowly because R311y353 measured the wider claim
    /// and it was FALSE. The carried blocker for `liveliness-get` said the atom
    /// needed "an ordering the demo can't make" — wz asking before a foreign
    /// token holder had declared. That is NOT why the atom had no witness, and
    /// this knob is not what fixed it: a fixture can simply start the token
    /// holder first and gate on its declaration banner, and
    /// `wz_liveliness_get_zenohd_pico_interop.rs` passes with this hold set to
    /// nothing at all. The real blocker was zenoh-pico declining to answer any
    /// Interest on a unicast transport (`interest.c:533-535`), which no ordering
    /// could have touched.
    ///
    /// What survives is narrower and is a TIMING MARGIN, not a precondition: the
    /// get is ONE-SHOT and has no retry, so unlike the burst-driven tests here
    /// (whose 5x200ms burst is what "covers the window for the subscription to
    /// reach zenohd") it gets exactly one chance. The holder's banner proves it
    /// SENT its token, not that the router REGISTERED it. This hold covers that
    /// propagation window. It is a margin against a race not yet observed, kept
    /// because a one-shot proof has nothing else to absorb one — not evidence of
    /// a race that was.
    ///
    /// Deliberately NOT cfg-gated on `liveliness-get`, for the same reason
    /// `--publish-after-ms` is not gated on `transport-keepalive` and
    /// `--matching-log` is not gated on `session-matching`: it is a pure
    /// ordering delay, inert when the feature is off, and it must stay reachable
    /// in the OFF build. `Session::liveliness_get` is signature-stable and
    /// returns `LivelinessGetError::FeatureDisabled` when elided, so the OFF arm
    /// walks the identical path and logs no reply.
    pub(crate) after_ms: Option<u64>,
}

#[cfg(all(test, any(feature = "router-hat-router", feature = "routing-peer")))]
mod connect_retry_tests {
    use super::*;

    fn argv(spec: &str) -> Vec<String> {
        vec![
            "--router-hat".to_string(),
            "tcp/127.0.0.1:0".to_string(),
            "--connect-retry".to_string(),
            spec.to_string(),
        ]
    }

    /// The flag is OPTIONAL and its absence is not an error — the caller keeps
    /// zenoh's own default. Pinned so a future round cannot make the schedule
    /// mandatory without noticing that every existing invocation omits it.
    #[test]
    fn an_absent_flag_yields_none_not_an_error() {
        let args = vec!["--router-hat".to_string(), "tcp/127.0.0.1:0".to_string()];
        assert_eq!(parse_connect_retry(&args), Ok(None));
    }

    /// The accepted spelling, and it must reach all THREE fields unswapped —
    /// deliberately three distinct values, so a transposition cannot pass.
    #[test]
    fn a_triple_parses_into_all_three_fields() {
        let policy = parse_connect_retry(&argv("40,320,3")).unwrap().unwrap();
        assert_eq!(policy.period_init_ms, 40);
        assert_eq!(policy.period_max_ms, 320);
        assert_eq!(policy.period_increase_factor, 3.0);
        // And the parsed policy actually schedules: 40 -> 120 -> 320 (clamped).
        let mut period = policy.period();
        assert_eq!(
            (0..4).map(|_| period.next_ms()).collect::<Vec<_>>(),
            vec![40, 120, 320, 320]
        );
    }

    /// `factor 1` is the CONSTANT schedule — the pre-y786 behaviour, still
    /// reachable, because a deploy that wants a flat cadence must be able to say
    /// so rather than having it removed by the round that added growth.
    #[test]
    fn a_factor_of_one_is_accepted_as_the_constant_schedule() {
        let policy = parse_connect_retry(&argv("250,0,1")).unwrap().unwrap();
        assert!(!policy.grows());
        let mut period = policy.period();
        assert_eq!(
            (0..3).map(|_| period.next_ms()).collect::<Vec<_>>(),
            vec![250, 250, 250]
        );
    }

    /// Every REJECTED spelling, as a set. A malformed schedule must not degrade
    /// to the default: the node would run, dial, and reconnect on a cadence the
    /// operator did not ask for, with nothing in the logs contradicting it.
    #[test]
    fn malformed_schedules_are_refused_not_defaulted() {
        for spec in [
            "",              // empty
            "1000",          // one field
            "1000,4000",     // two fields
            "1000,4000,2,5", // four fields
            "abc,4000,2",    // init not a number
            "1000,xyz,2",    // max not a number
            "1000,4000,x",   // factor not a number
            "-1,4000,2",     // negative init (u64)
            "1000,4000,0.5", // shrinking factor
            "1000,4000,0",   // zero factor
            "1000,4000,nan", // non-finite factor
            "4000,1000,2",   // ceiling below the opening wait
        ] {
            let got = parse_connect_retry(&argv(spec));
            assert!(got.is_err(), "`{spec}` must be refused, got {got:?}");
        }
    }

    /// `max = 0` is zenoh's NO-CEILING sentinel, so it must survive the
    /// below-init check that rejects `4000,1000,2` — the one case where a
    /// smaller max is legal.
    #[test]
    fn a_zero_ceiling_is_not_read_as_below_init() {
        let policy = parse_connect_retry(&argv("1000,0,2")).unwrap().unwrap();
        assert_eq!(policy.period_max_ms, 0);
        let mut period = policy.period();
        assert_eq!(
            (0..3).map(|_| period.next_ms()).collect::<Vec<_>>(),
            vec![1000, 2000, 4000],
            "0 must mean unbounded here too, not an immediate clamp"
        );
    }
}
