// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
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
        /// R2099 (open-debt item 512, the `connect/endpoints` residue) — the
        /// candidate dial LIST, in the order the document (or the argv) named
        /// them, not a single address.
        ///
        /// `connect/endpoints` is a list in every stock zenoh document, and until
        /// this round the expansion's CLIENT arm emitted `connect[0]` and dropped
        /// the rest while reporting the key APPLIED — the same half-truth item
        /// 512 measured on `listen/endpoints`, one arm over.
        ///
        /// Upstream's client walks the list: `connect_peers_single_link`
        /// (`zenoh/src/net/runtime/orchestrator.rs:346-369`) tries each endpoint
        /// and returns on the first that opens, failing only when none did
        /// ("Unable to connect to any of {:?}!"). `establish_link` does exactly
        /// that. A single-element list is the byte-identical prior behaviour.
        connect: Vec<String>,
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
        /// R2087 (open-debt item 506) — `--qos` offers the QoS transport ext
        /// (UNIT ext 0x1) on the InitSyn, so a peer that also offers it
        /// negotiates the per-(priority, reliability) SN conduits.
        ///
        /// The flag itself is older than this field: it has selected the
        /// AGGREGATED (`--max-links > 1`) QoS path since R311y218. What it could
        /// not do was reach the SINGLE-link open, so `transport/unicast/qos/
        /// enabled` — a key the stock-config reader calls honoured, and expands
        /// into exactly this flag — settled into a boolean that no InitSyn ever
        /// read. Measured, both ways: the frame offered `["patch"]` whether the
        /// file said true or false, while its two siblings moved.
        ///
        /// Feature-uniform and inert-when-unbuilt on the same
        /// `runner::initiator_offer` seam as `lowlatency` / `compression`;
        /// initiator-only and one-shot-only. EXCLUSIVE with `lowlatency` —
        /// zenoh bails at `unicast/manager.rs:264` on the pair and
        /// [`TransportMode`](wz::runtime_tokio::session_open::TransportMode)
        /// cannot represent it, so `main` refuses the pair up front rather than
        /// letting the offer builder pick a winner.
        qos: bool,
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

/// R2099 (open-debt item 512) — one spelling of "an endpoint LIST on argv":
/// comma-separated, each member trimmed, empty members dropped.
///
/// The shape `--connect` has always had, promoted to a named function because
/// this round gives it to `--peer` and `--router-hat` too. `listen/endpoints` and
/// `connect/endpoints` are both LISTS in a stock zenoh document, and until this
/// round wz's two BINDING run-modes took a single address — so a document naming
/// two listen endpoints came up bound to one of them, with the key still reported
/// APPLIED. A shared function rather than a third inline `split(',')` because
/// three copies of a splitter is three opinions about what an empty member means.
///
/// Empty members are DROPPED rather than kept as `""`: a trailing comma is a
/// typo, and an empty string reaches `plan_endpoint` as a malformed locator whose
/// error names the empty string — an error about the user's typo, told in a way
/// that does not name it. Dropping leaves `--peer ""` (a genuinely empty value)
/// to be caught by `bind_all_endpoints`'s empty-list refusal, which says exactly
/// that.
pub(crate) fn split_endpoint_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(String::from)
        .collect()
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
/// | `mode: "router"` + a listen endpoint | `--router-hat <ep>` (+ `--connect <a,b>`) |
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
    // R2109 (open-debt item 514) — read BEFORE the ingest is taken apart below,
    // and read from the ingest rather than recomputed from `named`: what a
    // silence about `mode` MEANS is the reader's fact, not the expansion's.
    let mode_unstated = ingest.mode_left_unstated();
    // R2091 (open-debt item 508) — the BUILD axis, consulted by every site
    // rather than restated at four of them. `config_keys_the_demo_drops` was
    // the report's whole derivation before this round; it is now one of the
    // inputs to a per-key verdict, and binding the sites to it is what keeps
    // the two from drifting apart the next time a key gains a feature gate.
    let dropped_by_this_build = config_keys_the_demo_drops();
    let no_sink = |key: &str| {
        dropped_by_this_build
            .contains(&key)
            .then_some(KeyEffect::NoSinkInThisBuild)
    };
    let cfg = &ingest.config;
    let mut exp = Expansion {
        rest,
        added: Vec::new(),
        effects: Vec::new(),
    };

    // The role flags, as a set: naming ANY of them on the command line means
    // the operator has chosen the topology and the file must not second-guess
    // it. `--scout` is here because it is a role too (discover, do not dial).
    //
    // R2091 (open-debt item 508) — the set is [`RUN_MODE_ROLES`] rather than a
    // list of its own, and `--router-hat` is in it BECAUSE this round makes the
    // role expansion emit that flag: a second list would have to gain the entry
    // by hand, and a typed `--router-hat` beside a `mode: "router"` file would
    // otherwise carry the same run-mode flag twice with two addresses. The
    // table is ordered as `main` dispatches, so `find` returns the mode the
    // command line actually selects and not merely one it mentions.
    let typed_role: Option<(&str, WhatAmI)> = RUN_MODE_ROLES
        .iter()
        .copied()
        .find(|(flag, _)| exp.typed(flag));
    let role_on_cli = typed_role.is_some();

    // Which run-mode the FILE selects, and the wire role that run-mode
    // announces. `None` means this expansion selected none — either the
    // operator already chose one, or the document names no endpoint at all.
    //
    // ## R2091 (open-debt item 508) — the topology decision
    //
    // `mode: "router"` selects `--router-hat`, not `--router`.
    //
    // zenoh's `mode: "router"` is a node that announces `WhatAmI::Router` on
    // the wire and hosts the discovery a stock client's
    // `scouting/multicast/autoconnect: ["router"]` default asks for. `--router`
    // is neither of those things: `demo_session_init_params` maps
    // `NodeKind::Router` to `WhatAmI::Peer` (a stand-in kept so the R121c/e
    // accept tests are unchanged) and `run_router` spawns no responder. So the
    // file that deploys a zenoh router produced a wz node in a DIFFERENT role
    // that nothing on the network could find.  `--router-hat` is wz's router:
    // `WhatAmI::Router` on the wire, and since R2089 the responder host.
    //
    // Deliberately NOT `cfg!`-guarded, and that is the decision rather than an
    // omission. A guard would make the SAME file come up in a different
    // run-mode depending on which features the binary carries, which is worse
    // than a refusal: the operator gets a node that starts and is the wrong
    // thing. A build without the run-mode says so and exits(2), which is the
    // answer every other run-mode flag already gives. R311y844's rule — a key
    // whose SINK is compiled out must not turn a valid stock config into a node
    // that refuses to start — governs OPTIONAL keys, whose honest fallback is
    // to drop them; `mode` has no such fallback, because dropping it IS the
    // different-node-per-build disease. And the refusal class is not new:
    // measured on a build carrying `router-hat-router` and not `routing-router`,
    // this same file already exited 2 with "--router requires the
    // `routing-router` feature". After this round that build runs it.
    // ## R2091b (open-debt item 511) — the ROLE selects the run-mode, and the
    // endpoints only supply its address
    //
    // Until this round the run-mode was chosen by the SHAPE of the endpoint
    // lists, with `mode` used only to break the tie, so three ordinary stock
    // documents came up as something they did not say. All three measured, and
    // measured on BOTH implementations, because the claim is a divergence and a
    // divergence needs two readings:
    //
    // - `{ mode: "peer", listen: [..] }`. zenohd binds it and is findable; wz
    //   selected `--listen`, the one-shot acceptor, which answers no Scouts and
    //   leaves after a round-trip. It is not a peer deployment at all.
    // - `{ mode: "router", connect: [..] }` with no listen. zenohd binds port
    //   7447 on every interface (its own mode-dependent default) and is a
    //   ROUTER; wz selected `--connect` and came up as a CLIENT.
    // - `{ mode: "client", listen: [..] }`. zenohd starts and binds NOTHING,
    //   naming no locator; wz bound the endpoint. This one runs the other way --
    //   wz doing something upstream does not -- and it was found by asking the
    //   oracle rather than by reading wz.
    //
    // So: `mode` picks the run-mode, [`default_listen_endpoint`] supplies the
    // address when the document names none, and a client's `listen` is dropped
    // the way upstream drops it. A document that NAMES the key -- an explicitly
    // empty list included -- suppresses the default, which is also upstream's
    // behaviour (measured: an empty list starts a node that binds nothing).
    //
    // ## The cost, stated rather than hidden
    //
    // `mode: "peer"` now needs `routing-peer` and `mode: "router"` needs
    // `router-hat-router`, where before both could come up on a build with
    // neither. That is R2091's decision applied uniformly: a node that starts
    // and is the wrong thing is worse than one that refuses and says which
    // feature it wants. It is also narrower than it looks -- `--config` is
    // itself behind `zenoh-config`, which no default build carries, so the
    // population that can read a file at all is already a chosen build.
    let selected: Option<Selected> = if role_on_cli {
        None
    } else {
        let connect = &cfg.connect;
        // The address this node binds: what the document named, or upstream's
        // own default for this mode when it named nothing.
        //
        // ## R2099 (open-debt item 512) — the WHOLE list, not its first member
        //
        // This used to be `cfg.listen.first()`, and that single `.first()` was
        // item 512: a document naming two listen endpoints produced a node bound
        // to ONE of them while `listen/endpoints` was still reported APPLIED. The
        // measurement in the register is `{ mode: "router", listen: { endpoints:
        // ["tcp/127.0.0.1:0", "tcp/127.0.0.2:0"] } }` -> `--router-hat
        // tcp/127.0.0.1:0` and one `listening on` line.
        //
        // Upstream binds all of them: `bind_listeners_impl`
        // (`zenoh/src/net/runtime/orchestrator.rs:520-541`) loops the configured
        // slice calling `add_listener` on each. So the fix is (a) from the
        // register's two shapes -- IMPLEMENT the multi-bind -- and not (b), the
        // truncated report. `--peer` / `--router-hat` now take the comma list
        // `--connect` always took, and `runner::bind_all_endpoints` binds every
        // member and logs one `BOUND LISTEN ENDPOINT` line per address.
        let bind: Vec<String> = if cfg.listen.is_empty() {
            (!named("listen/endpoints"))
                .then(|| wz::runtime_tokio::zenoh_config::default_listen_endpoint(cfg.mode))
                .flatten()
                .map(|ep| vec![String::from(ep)])
                .unwrap_or_default()
        } else {
            cfg.listen.clone()
        };
        // The two BINDING modes take the same shape -- bind the whole listen
        // list, dial the whole connect list -- so they are one arm with the flag
        // as its only difference. A router federates by DIALLING its peer routers,
        // and `run_router_hat` reads that set off `--connect` exactly as the peer
        // arm does; the flag is withheld when the file carries no list, so a
        // lone node gains no empty argument.
        match (cfg.mode, bind) {
            (mode @ (WhatAmI::Router | WhatAmI::Peer), eps) if !eps.is_empty() => {
                let flag = if mode == WhatAmI::Router {
                    "--router-hat"
                } else {
                    "--peer"
                };
                let listen_carried = eps.len();
                exp.added.push(String::from(flag));
                exp.added.push(eps.join(","));
                if !connect.is_empty() {
                    exp.added.push("--connect".into());
                    exp.added.push(connect.join(","));
                }
                Some(Selected {
                    flag,
                    role: mode,
                    listen_carried,
                    connect_carried: connect.len(),
                })
            }
            // A binding mode whose document names an EMPTY listen list. zenohd
            // runs such a node -- it scouts and dials without accepting -- and
            // wz has no run-mode that binds nothing, so nothing is selected and
            // the verdict below says so rather than inventing an address the
            // file refused.
            (WhatAmI::Router | WhatAmI::Peer, _) => None,
            // A zenoh client never listens, so its `listen` list is not an
            // address here -- it is a key that reaches nothing, reported as
            // such below.
            //
            // R2099 — the WHOLE connect list, which is item 512's same-seam
            // residue: this arm used to emit `connect[0]` and drop the rest,
            // while `connect/endpoints` was reported Expanded. Upstream's client
            // does NOT stop at the first either -- `connect_peers_single_link`
            // (`orchestrator.rs:346-369`) walks the configured slice and returns
            // on the first endpoint that opens, which is exactly what
            // `runner::establish_link` now does with this list.
            (WhatAmI::Client, _) if !connect.is_empty() => {
                exp.added.push("--connect".into());
                exp.added.push(connect.join(","));
                Some(Selected {
                    flag: "--connect",
                    role: WhatAmI::Client,
                    // A client binds nothing, so no listen member reaches it --
                    // the `listen/endpoints` verdict below never consults this
                    // count on the client path (it is `WithheldFromThisRun`
                    // before it gets here), and zero is the honest value if it
                    // ever did.
                    listen_carried: 0,
                    connect_carried: connect.len(),
                })
            }
            (WhatAmI::Client, _) => None,
        }
    };

    // R2091 (open-debt item 508) — `mode` is APPLIED exactly when the run-mode
    // the endpoints selected announces the role the file asked for. Stated as a
    // comparison rather than as "some role flag was emitted", because the two
    // differ in the cases that matter: a `mode: "router"` document carrying only
    // `connect` endpoints selects `--connect`, and that comes up as a CLIENT.
    //
    // The typed half is the SAME comparison and not a blanket "the operator
    // wins": a `mode: "peer"` file beside a typed `--listen` describes the node
    // that actually came up, so calling it overridden would be a false alarm of
    // exactly the kind this verdict exists to remove.
    if named("mode") {
        exp.record(
            "mode",
            match (typed_role, selected) {
                (Some((_, role)), _) if role == cfg.mode => KeyEffect::AlreadyOnTheCommandLine,
                (Some(_), _) => KeyEffect::OverriddenOnTheCommandLine,
                (None, Some(s)) if s.role == cfg.mode => KeyEffect::Expanded,
                (None, Some(_)) => KeyEffect::NotTheRoleTheseEndpointsSelect,
                // R2091b (open-debt item 511) — reachable in exactly two ways
                // now, and they are different sentences. A CLIENT with nothing
                // to dial has no run-mode here because `--scout` is a role this
                // expansion never emits; a binding mode reaches it only by
                // naming an EMPTY listen list, which upstream honours as "bind
                // nothing" and wz has no run-mode for.
                (None, None) if cfg.mode == WhatAmI::Client => {
                    KeyEffect::WithheldFromThisRun("the document names nothing to dial")
                }
                (None, None) => KeyEffect::WithheldFromThisRun(
                    "the document names an empty listen list, and no run-mode here binds nothing",
                ),
            },
        );
    }
    if named("listen/endpoints") {
        exp.record(
            "listen/endpoints",
            match (role_on_cli, cfg.mode, cfg.listen.is_empty()) {
                (true, _, _) => KeyEffect::OverriddenOnTheCommandLine,
                // R2091b (open-debt item 511) — a zenoh client never listens, so
                // the endpoint it names reaches nothing HERE for the same reason
                // it reaches nothing in a real zenohd. Measured: handed
                // `{ mode: "client", listen: [..] }` a zenohd starts and names no
                // locator at all.
                (false, WhatAmI::Client, false) => {
                    KeyEffect::WithheldFromThisRun("a zenoh client never listens")
                }
                // An empty list is what binding nothing already means.
                (false, _, true) => KeyEffect::AlreadyTheBehaviour,
                // R2099 (open-debt item 512) — DERIVED, not asserted: how many of
                // the document's listen endpoints the selection actually put on
                // the command line, compared against how many it named. Before
                // this round the arm read `KeyEffect::Expanded` unconditionally
                // while the selection carried `listen.first()`.
                //
                // `selected` is `Some` here by construction (a binding mode with
                // a non-empty listen list always selects its flag, and the client
                // and empty-list cases are the arms above), so a `None` would be
                // a selection that changed shape without this verdict following —
                // reported as carrying nothing, which is the safe direction.
                (false, _, false) => {
                    list_key_effect(cfg.listen.len(), selected.map_or(0, |s| s.listen_carried))
                }
            },
        );
    }
    if named("connect/endpoints") {
        let dialled = matches!(
            selected,
            Some(Selected {
                flag: "--peer" | "--connect" | "--router-hat",
                ..
            })
        ) && !cfg.connect.is_empty();
        exp.record(
            "connect/endpoints",
            match (role_on_cli, cfg.connect.is_empty(), dialled) {
                (true, _, _) => KeyEffect::OverriddenOnTheCommandLine,
                (false, true, _) => KeyEffect::AlreadyTheBehaviour,
                // R2099 — the same derivation as `listen/endpoints` above, and it
                // is item 512's same-seam residue: the CLIENT arm used to emit
                // `connect[0]` and drop the rest while this said `Expanded`.
                (false, false, true) => {
                    list_key_effect(cfg.connect.len(), selected.map_or(0, |s| s.connect_carried))
                }
                (false, false, false) => {
                    KeyEffect::WithheldFromThisRun("this run's mode dials nothing")
                }
            },
        );
    }
    if named("transport/unicast/max_links") {
        exp.pair(
            "transport/unicast/max_links",
            "--max-links",
            cfg.max_links.to_string(),
            None,
        );
    }
    if named("transport/unicast/qos/enabled") {
        exp.presence("transport/unicast/qos/enabled", "--qos", cfg.qos, None);
    }
    if named("transport/unicast/lowlatency") {
        exp.presence(
            "transport/unicast/lowlatency",
            "--lowlatency",
            cfg.lowlatency,
            None,
        );
    }
    if named("transport/unicast/compression/enabled") {
        exp.presence(
            "transport/unicast/compression/enabled",
            "--compression",
            cfg.compression,
            None,
        );
    }
    // The two that reach the WIRE rather than a local policy: `batch_size` and
    // `lease` are InitSyn / OpenSyn fields, so a dropped one is not a setting
    // that failed to apply but a value the peer is told and the operator was
    // not. Unlike the booleans above these are honoured at ANY value, because
    // there is no "off" for them — the file naming the key is the instruction.
    if named("transport/link/tx/batch_size") {
        exp.pair(
            "transport/link/tx/batch_size",
            "--batch-size",
            cfg.batch_size.to_string(),
            None,
        );
    }
    if named("transport/link/tx/lease") {
        exp.pair(
            "transport/link/tx/lease",
            "--lease-ms",
            cfg.lease_ms.to_string(),
            None,
        );
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
    const NO_TLS_LINK: &str = "this deployment has no tls endpoint";
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
        if named(key) {
            match value {
                Some(value) => {
                    let blocked = (!usable).then_some(KeyEffect::WithheldFromThisRun(NO_TLS_LINK));
                    exp.pair(key, flag, value.clone(), blocked);
                }
                // A key the document names with no value asks for nothing, and
                // asking for nothing is what this node already does.
                None => exp.record(key, KeyEffect::AlreadyTheBehaviour),
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
    // R2091 (open-debt item 508) — and withholding the flag is no longer
    // SILENT. Each precondition names itself into the key's verdict, so a key
    // this run has nothing to parse is reported as read-and-not-applied with
    // the reason attached, rather than reported applied while reaching nothing.
    let preconditioned: [(&str, &str, Option<u64>, Option<KeyEffect>); 3] = [
        (
            "queries_default_timeout",
            "--query-timeout-ms",
            cfg.queries_default_timeout_ms,
            (!exp.typed("--query"))
                .then_some(KeyEffect::WithheldFromThisRun("this run has no --query")),
        ),
        (
            "routing/interests/timeout",
            "--interest-timeout",
            cfg.interests_timeout_ms,
            no_sink("routing/interests/timeout"),
        ),
        (
            "scouting/timeout",
            "--scout-timeout-ms",
            cfg.scouting_timeout_ms,
            (!exp.typed("--scout"))
                .then_some(KeyEffect::WithheldFromThisRun("this run does not scout")),
        ),
    ];
    for (key, flag, value, blocked) in preconditioned {
        if named(key) {
            match value {
                Some(value) => {
                    exp.pair(key, flag, value.to_string(), blocked);
                }
                None => exp.record(key, KeyEffect::AlreadyTheBehaviour),
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
    //
    // R2089 (open-debt item 222) — and the precondition is now `--peer` OR
    // `--router-hat`, because THIS ROUND made the second one true. The sentence
    // above ("the flag is read there and nowhere else") was a statement about
    // `run_peer` owning the only responder spawn; `run_router_hat` owns one too
    // now, so leaving the precondition at `--peer` would have left a comment
    // that lies about the code beside it and, worse, kept the ROUTER — the role
    // a stock client's `autoconnect` default actually asks for — unfindable on
    // the one invocation a drop-in performs. Measured before it was changed: a
    // `--router-hat` on the command line plus a file carrying `listen: true`
    // expanded to `argv += []` while REPORTING the key APPLIED.
    //
    // R2091 (open-debt item 508) — and `added` can now carry `--router-hat`,
    // which is what makes a `mode: "router"` drop-in findable. Before this round
    // the role expansion could only ever put `--peer` there, so a stock ROUTER
    // config met this precondition in NO invocation at all: the sentence that
    // used to stand here said `--router-hat` is only ever typed, and that was
    // true because `mode: "router"` mapped to `--router`.
    let role_answers_scouts = exp
        .rest
        .iter()
        .chain(exp.added.iter())
        .any(|a| a == "--peer" || a == "--router-hat");
    let listen_blocked = no_sink("scouting/multicast/listen").or_else(|| {
        (!role_answers_scouts).then_some(KeyEffect::WithheldFromThisRun(
            "this run's mode answers no scouts",
        ))
    });
    let listen_expanded = named("scouting/multicast/listen")
        && exp.presence(
            "scouting/multicast/listen",
            "--scout-listen",
            cfg.scout_multicast_listen == Some(true),
            listen_blocked,
        ) == KeyEffect::Expanded;
    // R311y845 — WHERE the node looks for its peers. Same precondition as
    // `scouting/timeout` above (`--scout` on the command line), because the
    // three flags carry the same one: a scouting socket is an instruction to a
    // node that is scouting, and the demo rejects it otherwise. R311y846 widened
    // "is scouting" to include the answering direction, which joins the same
    // socket.
    let scouting = exp.typed("--scout") || exp.typed("--scout-listen") || listen_expanded;
    const NO_SCOUT_SOCKET: &str = "this run neither asks for nor answers scouts";
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
        if named(key) {
            match value {
                Some(value) => {
                    let blocked =
                        (!scouting).then_some(KeyEffect::WithheldFromThisRun(NO_SCOUT_SOCKET));
                    exp.pair(key, flag, value, blocked);
                }
                None => exp.record(key, KeyEffect::AlreadyTheBehaviour),
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
    let dials = exp
        .rest
        .iter()
        .chain(exp.added.iter())
        .any(|a| a == "--peer" || a == "--router-hat");
    if named("connect/retry") {
        let blocked = no_sink("connect/retry").or_else(|| {
            (!dials).then_some(KeyEffect::WithheldFromThisRun(
                "this run's mode owns no connect list",
            ))
        });
        match cfg.connect_retry {
            // Rendered in the flag's own three-comma-separated spelling, and
            // re-parsed by `parse_connect_retry` downstream on purpose: that
            // parser is the single place the acceptance POLICY lives (a factor
            // below 1.0 is refused there and nowhere else), so a config file
            // reaches the same boundary a command line does.
            Some(retry) => {
                exp.pair(
                    "connect/retry",
                    "--connect-retry",
                    format!(
                        "{},{},{}",
                        retry.period_init_ms, retry.period_max_ms, retry.period_increase_factor
                    ),
                    blocked,
                );
            }
            None => exp.record("connect/retry", KeyEffect::AlreadyTheBehaviour),
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
    // here follows -- an explicit argv beats a file. A file that STATES the
    // default therefore reads as already-the-behaviour rather than as expanded,
    // which is the honest verdict for it.
    if named("routing/peer/mode") {
        if cfg.peer_linkstate {
            exp.record("routing/peer/mode", KeyEffect::AlreadyTheBehaviour);
        } else {
            exp.pair(
                "routing/peer/mode",
                "--peer-mode",
                String::from("peer-to-peer"),
                None,
            );
        }
    }
    if named("transport/multicast/qos/enabled") {
        exp.presence(
            "transport/multicast/qos/enabled",
            "--multicast-qos",
            cfg.multicast_qos,
            no_sink("transport/multicast/qos/enabled"),
        );
    }
    if named("transport/shared_memory/enabled") {
        exp.presence(
            "transport/shared_memory/enabled",
            "--shm",
            cfg.shared_memory,
            None,
        );
    }
    // R2112 (open-debt items 102 + 210) — `timestamping/enabled` reaches the
    // node that stamps.
    //
    // Emitted only when the file's answer DIFFERS from what this node's role
    // already does, on the `routing/peer/mode` rule above: an added flag is a
    // DIFFERENCE the file asked for, and a file that states zenoh's own default
    // is already-the-behaviour. The comparison is against the SHIPPED map
    // resolved for the run-mode this expansion selected, because that is the
    // map the node will run with absent a flag — `{ router: true, peer: false,
    // client: false }` (`DEFAULT_CONFIG.json5:206`), so the same document says
    // something different to a `--router-hat` than to a `--peer`.
    if named("timestamping/enabled") {
        // The role this node will ANNOUNCE: what the operator typed, else what
        // the endpoints selected. Not `cfg.mode` — that is the role the FILE
        // claims, and the two come apart exactly where `mode`'s own verdict
        // above reports `OverriddenOnTheCommandLine`.
        let run_role = typed_role.map(|(_, r)| r).or(selected.map(|s| s.role));
        match run_role {
            // The file resolved its per-role table for a role this run does not
            // play, so the boolean in `cfg.timestamping` answers a question
            // nobody asked. Withheld rather than expanded: emitting it would
            // hand the node the OTHER role's policy.
            Some(role) if role != cfg.mode => exp.record(
                "timestamping/enabled",
                KeyEffect::WithheldFromThisRun(
                    "the document resolves this key for a role this run does not announce",
                ),
            ),
            Some(role) => {
                let shipped =
                    wz::runtime_tokio::node_clock::TimestampingEnabled::default().get(role);
                if cfg.timestamping == shipped {
                    exp.record("timestamping/enabled", KeyEffect::AlreadyTheBehaviour);
                } else {
                    exp.pair(
                        "timestamping/enabled",
                        "--timestamping",
                        cfg.timestamping.to_string(),
                        None,
                    );
                }
            }
            None => exp.record(
                "timestamping/enabled",
                KeyEffect::WithheldFromThisRun("this run selects no run-mode to stamp on"),
            ),
        };
    }
    // The one key this binary models NOWHERE, said out loud rather than quietly
    // folded into the applied half.
    //
    // `scouting/multicast/enabled` is reachability, not a role: it says whether
    // to LISTEN for a scout beacon, and the demo's `--scout` says to discover
    // INSTEAD of dialling, which is a different sentence — mapping one onto the
    // other would rewrite the operator's topology.
    //
    // It is an UNCONDITIONAL member of `config_keys_the_demo_drops()` — there is
    // no build in which it gains a flag — so its verdict is written here rather
    // than derived from `no_sink`, and
    // `every_key_this_build_drops_is_told_so_by_the_site_that_decides_it` is
    // what refuses the two lists coming apart.
    if named("scouting/multicast/enabled") {
        exp.record("scouting/multicast/enabled", KeyEffect::NoSinkInThisBuild);
    }
    // The adminspace block, whose three upstream keys expand to four wz flags.
    // Keyed on the BLOCK rather than on `adminspace/enabled`, because a
    // document that names only a permission still describes an admin space —
    // that is the same reading `from_json5` takes when it builds the Option.
    //
    // zenoh states the admin space as ONE `permissions.write`; wz splits it
    // into hosting the write subscriber (`--config-writable`) and permitting
    // the write (`--config-write-permit`), so the single upstream key expands
    // to both — either alone yields a node that does not do what the operator's
    // file says, which is why the key's verdict below is the WEAKER of the two.
    match &cfg.adminspace {
        Some(admin) => {
            if named("adminspace/enabled") {
                exp.presence("adminspace/enabled", "--config-queryable", true, None);
            }
            if named("adminspace/permissions/read") {
                exp.presence(
                    "adminspace/permissions/read",
                    "--no-admin-read",
                    !admin.read,
                    None,
                );
            }
            if named("adminspace/permissions/write") {
                let hosted = exp.decide_presence("--config-writable", admin.write, None);
                let permitted = exp.decide_presence("--config-write-permit", admin.write, None);
                let effect = if hosted == permitted {
                    hosted
                } else if hosted.reached_the_node() && permitted.reached_the_node() {
                    KeyEffect::Expanded
                } else if hosted.reached_the_node() {
                    permitted
                } else {
                    hosted
                };
                exp.record("adminspace/permissions/write", effect);
            }
        }
        None => {
            // `enabled: false` is read as no admin space at all, and no admin
            // space is what this binary does with none of the four flags — so
            // the file's sentence IS this node's behaviour.
            for key in [
                "adminspace/enabled",
                "adminspace/permissions/read",
                "adminspace/permissions/write",
            ] {
                if named(key) {
                    exp.record(key, KeyEffect::AlreadyTheBehaviour);
                }
            }
        }
    }

    let Expansion { added, effects, .. } = exp;
    let mut argv: Vec<String> = rest.to_vec();
    argv.extend(added.iter().cloned());
    Ok(Some(StockConfigExpansion {
        path,
        argv,
        added,
        effects,
        named: ingest.named,
        ignored: ingest.ignored,
        stated_for_other_modes: ingest.stated_for_other_modes,
        mode: ingest.config.mode,
        mode_unstated,
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
    /// R2091 (open-debt item 508) — what became of each honoured key the file
    /// named, decided at the site that decides the flag.
    pub(crate) effects: Vec<(&'static str, KeyEffect)>,
    /// The honoured keys the file actually named.
    pub(crate) named: Vec<&'static str>,
    /// The keys the file carried that wz does not honour.
    pub(crate) ignored: Vec<String>,
    /// R2081 (open-debt item 500) — honoured keys the file states only for OTHER
    /// modes. Carried out rather than dropped for the same reason `ignored` is:
    /// the operator's file said something, and it did not say it to this node.
    pub(crate) stated_for_other_modes: Vec<&'static str>,
    /// The role this node ends up in, so the report above can name WHO the
    /// other-modes rows were not for.
    pub(crate) mode: WhatAmI,
    /// R2109 (open-debt item 514) — set when the file named no `mode` at all.
    ///
    /// The other four partitions all enumerate keys the file WROTE, so none of
    /// them can carry a key it did not: a mode-less document produced a report
    /// in which the word `mode` never appeared, and the run-mode it selected was
    /// visible only as a flag on the `argv +=` line an operator would have to
    /// know to read. Carried out as a value rather than printed inside the
    /// expansion for the reason `ignored` is: a test can assert on a value.
    pub(crate) mode_unstated: Option<wz::runtime_tokio::zenoh_config::UnstatedMode>,
}

#[cfg(feature = "zenoh-config")]
impl StockConfigExpansion {
    /// R2124 (open-debt item 504) — EVERY AXIS THIS EXPANSION CARRIES, AS
    /// LABELLED LINES, so the demo prints the report instead of composing it.
    ///
    /// # The gap this closes
    ///
    /// The reader's partition grew three times — `stated_for_other_modes`
    /// (item 500), the per-key verdicts (item 508), `mode_unstated` (item 514)
    /// — and each time an operator saw the new axis only because somebody
    /// remembered to add an `eprintln!` in `main`. Nothing bound the two.
    /// MEASURED before this existed: deleting the READ line reded nothing
    /// across 41 tests, and the only thing that ever caught a deletion was
    /// `dead_code`, which fires just when the deleted line was a field's LAST
    /// reader.
    ///
    /// # Why a list and not a `Display`
    ///
    /// The label is the half a test can hold. `every_axis_the_reader_hands_over
    /// _reaches_a_line` destructures this struct — so a new field does not
    /// compile until it is judged — and then checks that each REPORTING field's
    /// value actually reaches the rendered text. A single formatted blob would
    /// pass the second check by accident the moment any field's value appeared
    /// anywhere in it.
    ///
    /// The rendering is byte-for-byte what the six hand-written lines produced,
    /// because operators and the deploy leg both read these strings.
    pub(crate) fn report_lines(&self) -> Vec<(&'static str, String)> {
        let mut out: Vec<(&'static str, String)> = Vec::new();
        out.push(("READ", format!("{:?}", self.named)));
        out.push(("APPLIED", format!("{:?}", self.applied())));
        let read_only = self.read_but_not_applied_with_reasons();
        if !read_only.is_empty() {
            out.push(("READ BUT NOT APPLIED", format!("{read_only:?}")));
        }
        // R2109 (open-debt item 514) — the answer the three above cannot carry,
        // because all three enumerate keys the FILE WROTE. A document naming no
        // `mode` produced a report in which the word never appeared, while the
        // run-mode it silently selected sat on the `argv +=` line as a bare
        // flag — read one way by the zenoh library and the other by zenohd.
        if let Some(unstated) = &self.mode_unstated {
            out.push(("MODE UNSTATED", format!("- {unstated}")));
        }
        // R2081 (open-debt item 500) — a key the file states as a
        // `{ router, peer, client }` table naming no row for this node's mode
        // is neither honoured nor ignored: the operator's file spoke, and it
        // did not speak to this node.
        if !self.stated_for_other_modes.is_empty() {
            out.push((
                "STATED FOR OTHER MODES",
                format!(
                    "{:?} (this node is {})",
                    self.stated_for_other_modes,
                    self.mode.to_str()
                ),
            ));
        }
        // Said out loud rather than swallowed: a reader that applies what it
        // knows in silence lets a TLS root-CA path look like it took effect.
        for key in &self.ignored {
            out.push(("IGNORED", key.clone()));
        }
        out.push(("argv +=", format!("{:?}", self.added)));
        out
    }

    /// The honoured keys that reach a flag in THIS build.
    ///
    /// R2081 (open-debt item 208) — the split lives HERE and not at the print
    /// site, because a test cannot reach `main` and a second copy of the filter
    /// would be a second answer to "did my setting take effect". One derivation,
    /// read by the report and by the witnesses.
    /// R2091 (open-debt item 508) — derived from what the expansion DID, not
    /// from a per-build list of keys it could never do. The two differ every
    /// time a flag's precondition is unmet by the invocation: measured before
    /// this round, a `mode: "peer"` drop-in naming
    /// `scouting/multicast/{listen,address}`, `queries_default_timeout`,
    /// `transport/link/tls/root_ca_certificate` and `adminspace/enabled` printed
    /// all five as APPLIED with `argv += ["--listen", …]` and nothing else.
    pub(crate) fn applied(&self) -> Vec<&'static str> {
        self.named
            .iter()
            .copied()
            .filter(|k| self.effect(k).is_some_and(KeyEffect::reached_the_node))
            .collect()
    }

    /// The honoured keys that did NOT reach this node.
    ///
    /// A key with no recorded verdict lands HERE and not in [`Self::applied`],
    /// which is the safe side of the only bug this split can have: the report
    /// can never call a key applied unless a decision site said so.
    pub(crate) fn read_but_not_applied(&self) -> Vec<&'static str> {
        self.named
            .iter()
            .copied()
            .filter(|k| !self.effect(k).is_some_and(KeyEffect::reached_the_node))
            .collect()
    }

    /// [`Self::read_but_not_applied`], each key carrying WHY.
    ///
    /// Without the reason "not applied" sends an operator looking in their file
    /// for a defect that is in the invocation — a withheld `--scout-addr` is not
    /// a mistyped group, it is a run that answers no scouts.
    pub(crate) fn read_but_not_applied_with_reasons(&self) -> Vec<String> {
        self.read_but_not_applied()
            .into_iter()
            .map(|k| {
                let why = self
                    .effect(k)
                    .map_or_else(|| UNRECORDED_VERDICT.to_string(), KeyEffect::why_not);
                format!("{k} ({why})")
            })
            .collect()
    }

    fn effect(&self, key: &str) -> Option<KeyEffect> {
        self.effects
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, e)| *e)
    }
}

/// What [`StockConfigExpansion::read_but_not_applied_with_reasons`] prints for a
/// key no decision site spoke for.
///
/// Named rather than inlined so the gate that forbids it
/// (`every_named_key_gets_a_verdict_from_the_site_that_decides_its_flag`) checks
/// for the same string the report would print.
#[cfg(feature = "zenoh-config")]
pub(crate) const UNRECORDED_VERDICT: &str = "no decision site spoke for it";

/// R2091 (open-debt item 508) — what became of ONE honoured key the file named.
///
/// The report used to derive this from a per-BUILD list of keys with no sink,
/// which answers a question nobody asked: "could this binary EVER act on the
/// key". What an operator asks is whether THIS RUN did, and the two differ
/// wherever a flag carries a precondition the invocation does not meet. Six of
/// the honoured keys have such a precondition, and before this round every one
/// of them was reported APPLIED while the expansion silently withheld its flag.
#[cfg(feature = "zenoh-config")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyEffect {
    /// The file's value reached the command line, as the flag that carries it.
    Expanded,
    /// No flag, and none was needed: what the file states is what this binary
    /// does with the flag absent.
    AlreadyTheBehaviour,
    /// The operator typed the same value; the file is redundant, not ignored.
    AlreadyOnTheCommandLine,
    /// The operator typed a DIFFERENT value, and an explicit argv beats a file.
    OverriddenOnTheCommandLine,
    /// This BUILD compiled no sink for the key.
    NoSinkInThisBuild,
    /// This RUN has nothing the flag could qualify, so the expansion withheld
    /// it rather than hand the binary an argument it exits(2) on. The `&str`
    /// names what is missing.
    WithheldFromThisRun(&'static str),
    /// `mode` only: the run-mode these endpoints select announces a different
    /// role than the file asked for.
    NotTheRoleTheseEndpointsSelect,
    /// R2099 (open-debt item 512) — the key is a LIST and only SOME of its
    /// members reached the command line.
    ///
    /// [`Self::reached_the_node`] is FALSE for it, which is the whole point:
    /// item 512 was a `listen/endpoints` naming two addresses, a node bound to
    /// one of them, and the key reported APPLIED. "Applied to most of it" is not
    /// a state an operator can act on -- they read APPLIED and believe both
    /// addresses answer.
    ///
    /// Population ZERO for every expansion this binary produces, and that is a
    /// claim rather than an accident: both list-valued keys now carry every
    /// member (see [`list_key_effect`]'s callers). It is a live guard against a
    /// FUTURE run-mode that carries fewer, which is exactly the shape item 512
    /// took -- so its own witness drives [`list_key_effect`] directly rather
    /// than waiting for such a run-mode to exist.
    PartlyExpanded { named: usize, carried: usize },
}

/// R2099 (open-debt item 512) — the run-mode the FILE selected, and how much of
/// each endpoint LIST the emitted argv actually carries.
///
/// Was a `(&'static str, WhatAmI)` pair. It grew the two counts because the
/// `listen/endpoints` and `connect/endpoints` verdicts must be DERIVED from what
/// the selection emitted rather than asserted beside it: item 512 is a site that
/// wrote `listen.first()` and `KeyEffect::Expanded` three hundred lines apart,
/// with nothing in between comparing them. Now the same block that pushes the
/// flag records how many members went with it, and [`list_key_effect`] does the
/// comparison.
#[cfg(feature = "zenoh-config")]
#[derive(Clone, Copy)]
struct Selected {
    /// The run-mode flag this expansion emitted (`--peer` / `--router-hat` /
    /// `--connect`).
    flag: &'static str,
    /// The wire role that run-mode announces, compared against `mode`.
    role: WhatAmI,
    /// How many `listen/endpoints` members the emitted flag carries.
    listen_carried: usize,
    /// How many `connect/endpoints` members the emitted argv carries.
    connect_carried: usize,
}

/// R2099 (open-debt item 512) — the verdict for a LIST-valued key, derived from
/// how many members the document named against how many the expansion actually
/// put on the command line.
///
/// A FUNCTION of the two counts, not a judgement made at the decision site,
/// because item 512 is precisely what happens when the site asserts the verdict
/// instead of deriving it: the site that wrote `listen.first()` also wrote
/// `Expanded`, and nothing compared them. Both callers pass the count they
/// actually emitted, so a truncation cannot be reported as an application.
#[cfg(feature = "zenoh-config")]
fn list_key_effect(named: usize, carried: usize) -> KeyEffect {
    if carried == named {
        KeyEffect::Expanded
    } else {
        KeyEffect::PartlyExpanded { named, carried }
    }
}

#[cfg(feature = "zenoh-config")]
impl KeyEffect {
    /// Whether this node's behaviour carries what the file's key says.
    pub(crate) fn reached_the_node(self) -> bool {
        matches!(
            self,
            Self::Expanded | Self::AlreadyTheBehaviour | Self::AlreadyOnTheCommandLine
        )
    }

    /// The reason the report prints. Empty for the applied half, which never
    /// asks for one.
    ///
    /// R2099 — `String` rather than `&'static str` because
    /// [`Self::PartlyExpanded`] answers with NUMBERS, and an operator told "some
    /// of your endpoints reached the node" without being told how many has been
    /// given a puzzle instead of a fact.
    pub(crate) fn why_not(self) -> String {
        match self {
            Self::Expanded | Self::AlreadyTheBehaviour | Self::AlreadyOnTheCommandLine => {
                String::new()
            }
            Self::OverriddenOnTheCommandLine => "the command line says otherwise".into(),
            Self::NoSinkInThisBuild => "no sink in this build".into(),
            Self::WithheldFromThisRun(what) => what.into(),
            Self::NotTheRoleTheseEndpointsSelect => {
                "these endpoints select a run-mode in another role".into()
            }
            Self::PartlyExpanded { named, carried } => {
                format!("only {carried} of its {named} endpoints reach this run-mode")
            }
        }
    }
}

/// The expansion under construction: the flags it has added, and the verdict it
/// has recorded for each key it has passed.
///
/// R2091 (open-debt item 508) — the two travel together, and every site goes
/// through [`Expansion::pair`] / [`Expansion::presence`], because a site that
/// could report one thing and add another is exactly the defect item 508 names.
/// Before this round the report was derived a second time, from a different
/// input, at a different place.
#[cfg(feature = "zenoh-config")]
struct Expansion<'a> {
    rest: &'a [String],
    added: Vec<String>,
    effects: Vec<(&'static str, KeyEffect)>,
}

#[cfg(feature = "zenoh-config")]
impl Expansion<'_> {
    fn typed(&self, flag: &str) -> bool {
        self.rest.iter().any(|a| a == flag)
    }

    fn record(&mut self, key: &'static str, effect: KeyEffect) {
        self.effects.push((key, effect));
    }

    /// Decide a `<flag> <value>` key's fate AND act on the decision.
    fn decide_pair(
        &mut self,
        flag: &'static str,
        value: String,
        blocked: Option<KeyEffect>,
    ) -> KeyEffect {
        if let Some(blocked) = blocked {
            return blocked;
        }
        // Keyed on the flag's PRESENCE and not on `parse_pair`, so a trailing
        // `--max-links` with no value still counts as typed: the old code
        // withheld on presence, and reading it as absent would append a second
        // copy of a flag the operator already gave.
        if self.typed(flag) {
            return match parse_pair(self.rest, flag) {
                Some(typed) if typed == value => KeyEffect::AlreadyOnTheCommandLine,
                _ => KeyEffect::OverriddenOnTheCommandLine,
            };
        }
        self.added.push(String::from(flag));
        self.added.push(value);
        KeyEffect::Expanded
    }

    fn pair(
        &mut self,
        key: &'static str,
        flag: &'static str,
        value: String,
        blocked: Option<KeyEffect>,
    ) -> KeyEffect {
        let effect = self.decide_pair(flag, value, blocked);
        self.record(key, effect);
        effect
    }

    /// A presence flag: the file's `true` is what asks for it, and its `false`
    /// is what the absent flag already means.
    fn decide_presence(
        &mut self,
        flag: &'static str,
        on: bool,
        blocked: Option<KeyEffect>,
    ) -> KeyEffect {
        match (blocked, self.typed(flag), on) {
            (Some(blocked), _, _) => blocked,
            (None, true, true) => KeyEffect::AlreadyOnTheCommandLine,
            (None, true, false) => KeyEffect::OverriddenOnTheCommandLine,
            (None, false, true) => {
                self.added.push(String::from(flag));
                KeyEffect::Expanded
            }
            (None, false, false) => KeyEffect::AlreadyTheBehaviour,
        }
    }

    fn presence(
        &mut self,
        key: &'static str,
        flag: &'static str,
        on: bool,
        blocked: Option<KeyEffect>,
    ) -> KeyEffect {
        let effect = self.decide_presence(flag, on, blocked);
        self.record(key, effect);
        effect
    }
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
    use wz::runtime_tokio::zenoh_config::{validate_topology_with_external, ZenohNodeConfig};

    let paths = parse_repeated(rest, "--check-topology");
    // R2117 (open-debt item 498) — the listeners this deployment does NOT
    // manage, named by the operator.
    let external = parse_repeated(rest, "--check-topology-external");
    if paths.is_empty() {
        // A flag that silently does nothing is the refusal this file already
        // makes for `--payload-format` without `--fields`: an operator who
        // typed the widening and no set to widen has asked a question with no
        // subject, and answering `None` here would exit as if they had asked
        // for the demo instead.
        if !external.is_empty() {
            return Some(Err(String::from(
                "--check-topology-external names a listener outside the set and \
                 there is no set: give --check-topology <file> too",
            )));
        }
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
        // R2109 (open-debt item 514) — the SAME seam one surface over, and it
        // bites harder here than under `--config`: this check's whole verdict
        // is a function of the roles, and `validate_topology` is what says
        // "every node is a client, so nothing routes". A file the operator's
        // zenohd deployed as the ROUTER counts here as a peer, and the reader
        // has to be told which reading it just got a verdict under.
        if let Some(unstated) = ingest.mode_left_unstated() {
            notes.push_str(&format!(
                "--check-topology: {path}: MODE UNSTATED - {unstated}\n"
            ));
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
    let verdict = validate_topology_with_external(&configs, &external);
    for defect in &verdict.defects {
        count += 1;
        defects.push_str(&format!("  {defect}\n"));
    }

    // R2117 (open-debt item 498) — the ASSUMPTIONS the verdict rests on, said
    // whichever way it goes. A fragment that checks out does so because the
    // operator named an outside listener, and a report that swallowed that
    // would read exactly like a closed deployment answering for itself. Said
    // on the failure path too: a set with one real dangling dial and three
    // externally answered ones is a different thing to go and look at.
    for answered in &verdict.externally_answered {
        notes.push_str(&format!(
            "--check-topology: EXTERNAL {} -> {:?} answered by a declared \
             outside listener, not by a node in this set\n",
            answered.node, answered.endpoint
        ));
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

/// Keys the reader ingests that reach NO behaviour in this binary.
///
/// Empty is the goal and not the invariant — a key with no sink is a legitimate
/// state, but it has to be written down here rather than hide behind a report
/// that calls it honoured.
///
/// R311y844 made this BUILD-DEPENDENT, and the two kinds inside it are worth
/// telling apart. The first row is a key with no sink at all in this binary.
/// The `cfg!` rows are keys whose sink exists but is compiled out here:
/// their flags exit(2) when the feature is absent, so expanding into one would
/// turn a valid stock config into a node that refuses to start — which is what
/// the round measured its own first cut doing.
///
/// R2081 (open-debt item 208) — MOVED out of the test module, because the
/// runtime report needs the same list the gate checks. The `honoured` line said
/// what the READER took from the file and nothing about what the NODE does with
/// it, so an operator had to diff it against the `argv +=` line beside it by
/// hand. Two copies of this list would have been two answers to "did my setting
/// take effect"; one copy, read by both, is the point of the move.
#[cfg(feature = "zenoh-config")]
pub(crate) fn config_keys_the_demo_drops() -> Vec<&'static str> {
    let mut out = vec![
        // Reachability, not a role: `scouting/multicast/enabled` says whether to
        // LISTEN for a scout beacon, and the demo's `--scout` says to discover
        // INSTEAD of dialling, which is a different sentence. Mapping one onto
        // the other would rewrite the operator's topology.
        "scouting/multicast/enabled",
    ];
    if !cfg!(feature = "routing-interest-pending-gc") {
        out.push("routing/interests/timeout");
    }
    if !cfg!(feature = "transport-qos") {
        out.push("transport/multicast/qos/enabled");
    }
    // R311y846 — the responder's flag exits(2) without its feature (the demo
    // says so and names the build), so a build without it must DROP the key
    // rather than expand into a refusal.
    if !cfg!(feature = "scouting-responder") {
        out.push("scouting/multicast/listen");
    }
    // R311y849 — `--connect-retry` is parsed by the `--peer` and `--router-hat`
    // arms only, and neither exists without its feature, so a build with neither
    // has no sink to expand into.
    if !cfg!(any(feature = "routing-peer", feature = "router-hat-router")) {
        out.push("connect/retry");
    }
    out
}

#[cfg(all(test, feature = "zenoh-config"))]
mod stock_config_tests {
    use super::*;

    use wz::runtime_tokio::zenoh_config::{CONFIG_KEYS_PROVEN_ON_THE_WIRE, HONOURED_CONFIG_KEYS};

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
    ///
    /// R2091 (open-debt item 508) — the router row moved from `--router` to
    /// `--router-hat`, and the fifth row below is what that move is FOR: a
    /// federating router carries its peer routers in `connect`, and
    /// `run_router_hat` reads that set off `--connect` exactly as the peer arm
    /// does. `--router` had no such parse, so those endpoints used to be
    /// dropped on the floor.
    #[test]
    fn each_topology_the_config_can_describe_becomes_the_argv_for_it() {
        for (file, want) in [
            (
                r#"{ mode: "router", listen: { endpoints: ["tcp/0.0.0.0:7447"] } }"#,
                vec!["--router-hat", "tcp/0.0.0.0:7447"],
            ),
            (
                r#"{ mode: "router",
                     listen: { endpoints: ["tcp/0.0.0.0:7447"] },
                     connect: { endpoints: ["tcp/r2:7447", "tcp/r3:7447"] } }"#,
                vec![
                    "--router-hat",
                    "tcp/0.0.0.0:7447",
                    "--connect",
                    "tcp/r2:7447,tcp/r3:7447",
                ],
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
            // R2091b (open-debt item 511) — a peer with NO connect list is still
            // a peer. It used to be the one-shot acceptor, which answers no
            // Scouts and leaves after a round-trip.
            (
                r#"{ mode: "peer", listen: { endpoints: ["tcp/0.0.0.0:7447"] } }"#,
                vec!["--peer", "tcp/0.0.0.0:7447"],
            ),
            // R2091b — and a node that names no listen binds what a stock node
            // binds. Both values are upstream's own
            // (`DEFAULT_CONFIG.json5` `endpoints: { router: [..], peer: [..] }`),
            // and both were measured against a real zenohd: it answers on 7447
            // as a router and on an ephemeral port as a peer.
            (
                r#"{ mode: "router", connect: { endpoints: ["tcp/r2:7447"] } }"#,
                vec!["--router-hat", "tcp/[::]:7447", "--connect", "tcp/r2:7447"],
            ),
            (
                r#"{ mode: "peer", connect: { endpoints: ["tcp/r2:7447"] } }"#,
                vec!["--peer", "tcp/[::]:0", "--connect", "tcp/r2:7447"],
            ),
            // R2091b — a NAMED empty list suppresses that default, which is
            // upstream's behaviour too (measured: a zenohd handed an empty list
            // starts and names no locator). wz has no run-mode that binds
            // nothing, so it selects none rather than inventing an address the
            // document refused.
            (r#"{ mode: "peer", listen: { endpoints: [] } }"#, vec![]),
            // R2091b — a zenoh client NEVER listens, so the endpoint reaches
            // nothing. Measured on a real zenohd: handed this document it starts
            // and names no locator at all, while the same file as a peer answers
            // on that address.
            (
                r#"{ mode: "client", listen: { endpoints: ["tcp/0.0.0.0:7447"] } }"#,
                vec![],
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

    /// R2099 (open-debt item 512) — an endpoint LIST reaches the command line
    /// whole, in both keys and in every run-mode that reads them.
    ///
    /// This is the unit half of item 512. Until this round the binding arm took
    /// `listen.first()` and the CLIENT arm took `connect[0]`, so a document
    /// naming two addresses produced a node that used one of them — while the
    /// report called the key APPLIED. Each row states BOTH counts through the
    /// argv it expects, so a regression to `.first()` fails on the value and not
    /// on some downstream symptom.
    #[test]
    fn an_endpoint_list_reaches_the_command_line_whole() {
        for (file, want) in [
            // The register's own measurement of item 512, verbatim.
            (
                r#"{ mode: "router",
                     listen: { endpoints: ["tcp/127.0.0.1:0", "tcp/127.0.0.2:0"] } }"#,
                vec!["--router-hat", "tcp/127.0.0.1:0,tcp/127.0.0.2:0"],
            ),
            // The peer host is a DIFFERENT run-mode host with its own bind, so
            // it is asked separately rather than assumed to follow.
            (
                r#"{ mode: "peer",
                     listen: { endpoints: ["tcp/127.0.0.1:0", "tcp/127.0.0.2:0"] } }"#,
                vec!["--peer", "tcp/127.0.0.1:0,tcp/127.0.0.2:0"],
            ),
            // Both lists at once: a binding mode carries its whole listen list
            // AND its whole connect list, which is the row that would catch a
            // fix applied to one key and not the other.
            (
                r#"{ mode: "peer",
                     listen: { endpoints: ["tcp/127.0.0.1:0", "tcp/127.0.0.2:0"] },
                     connect: { endpoints: ["tcp/a:7447", "tcp/b:7447"] } }"#,
                vec![
                    "--peer",
                    "tcp/127.0.0.1:0,tcp/127.0.0.2:0",
                    "--connect",
                    "tcp/a:7447,tcp/b:7447",
                ],
            ),
            // The same-seam residue item 512 named: the CLIENT arm, which used
            // to emit `connect[0]` while `--peer` joined the whole list.
            // Upstream's client walks the list too — `connect_peers_single_link`
            // returns on the first endpoint that OPENS, not on the first named.
            (
                r#"{ mode: "client",
                     connect: { endpoints: ["tcp/r1:7447", "tcp/r2:7447"] } }"#,
                vec!["--connect", "tcp/r1:7447,tcp/r2:7447"],
            ),
        ] {
            let out = expand(&["--config", "z.json5"], file).unwrap();
            assert_eq!(out.added, argv(&want), "{file}");
        }
    }

    /// R2099 (open-debt item 512) — the verdict for a LIST-valued key is a
    /// FUNCTION of what the expansion carried, and a partial carry is NOT
    /// applied.
    ///
    /// [`KeyEffect::PartlyExpanded`] has population zero in every expansion this
    /// binary produces, which is exactly why its witness drives
    /// [`list_key_effect`] directly: a guard whose only test is "no expansion
    /// reaches it" is a guard nobody has ever seen work. The counts item 512
    /// actually measured — two named, one carried — are the row that matters.
    #[test]
    fn a_list_key_is_applied_only_when_every_member_of_it_was_carried() {
        assert_eq!(list_key_effect(2, 2), KeyEffect::Expanded);
        assert!(list_key_effect(2, 2).reached_the_node());
        assert_eq!(list_key_effect(1, 1), KeyEffect::Expanded);

        let partial = list_key_effect(2, 1);
        assert_eq!(
            partial,
            KeyEffect::PartlyExpanded {
                named: 2,
                carried: 1
            }
        );
        assert!(
            !partial.reached_the_node(),
            "a key whose list was truncated is not applied"
        );
        // The operator is told the numbers, not just that something is wrong:
        // "some of your endpoints" is a puzzle, "1 of its 2" is a fact.
        assert_eq!(
            partial.why_not(),
            "only 1 of its 2 endpoints reach this run-mode"
        );
        // And the direction that means "the flag carried nothing at all" is not
        // silently folded into success either.
        assert!(!list_key_effect(2, 0).reached_the_node());
    }

    /// A topology named on the command line wins — the file supplies defaults,
    /// it does not overrule the operator standing in front of the machine.
    #[test]
    fn a_role_on_the_command_line_is_not_second_guessed_by_the_file() {
        for role in [
            vec!["--listen", "127.0.0.1:1"],
            vec!["--connect", "127.0.0.1:1"],
            vec!["--router", "127.0.0.1:1"],
            // R2091 (open-debt item 508) — `--router-hat` is in the set BECAUSE
            // the role expansion now emits it. Without this row a typed
            // `--router-hat` plus the `mode: "router"` file below would append a
            // second one, and the operator's command line would carry the same
            // run-mode flag twice with two different addresses.
            vec!["--router-hat", "127.0.0.1:1"],
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

    /// R2124 (open-debt item 504) — EVERY AXIS THE READER HANDS OVER REACHES A
    /// REPORT LINE, OR SAYS WHY IT IS NOT ONE.
    ///
    /// # What was unbound
    ///
    /// `ZenohConfigIngest` grew a third partition (item 500), per-key verdicts
    /// (item 508) and a fourth answer about silence (item 514). Each reached an
    /// operator because a person added an `eprintln!` to `main`, and nothing
    /// would have noticed if they had not. MEASURED on the tree before this
    /// round: deleting the READ line left 41 tests green. The only thing that
    /// ever objected was `dead_code`, and only when the deleted line happened
    /// to be a field's LAST reader — which the READ line was not.
    ///
    /// # The two halves, and why neither alone is enough
    ///
    /// The DESTRUCTURE makes the population the struct rather than a list: a
    /// field added to `StockConfigExpansion` fails to compile here until
    /// someone puts it in one of the two classes below. That is item 400's
    /// prescription -- a hand list is wrong on the day it is written.
    ///
    /// The CONTENT CHECK is what stops the classification from being a label
    /// nobody honours: for a fixture where every axis has something in it,
    /// each REPORTING field's own value must appear in the rendered lines. A
    /// field classified as reported and then dropped from `report_lines` fails
    /// here even though the destructure is satisfied.
    #[test]
    fn every_axis_the_reader_hands_over_reaches_a_line() {
        // A file that lights up every axis at once: honoured keys that reach a
        // flag and ones that do not, an unhonoured key, a key stated only for
        // other modes, and no `mode` at all so the silence axis fires too.
        let out = expand(
            &["--config", "z.json5"],
            // No `mode`, so the silence axis fires and this node reads as
            // `peer`; `timestamping/enabled` then names a row for ROUTER only,
            // which is the axis that is neither honoured-here nor unreadable.
            r#"{ connect: { endpoints: ["tcp/r:7447"] },
                 timestamping: { enabled: { router: true } },
                 transport: { link: { tx: { threads: 8 } } },
                 plugins: {} }"#,
        )
        .unwrap();

        // Each REPORTING field, with a string drawn from ITS OWN value that
        // must survive into the rendered report. Drawn from the value rather
        // than written here, so the witness cannot drift from what the fixture
        // actually produced.
        #[allow(clippy::type_complexity)]
        let reporting: &[(&str, &str, fn(&StockConfigExpansion) -> Option<String>)] = &[
            ("named", "READ", |e| {
                e.named.first().map(|k| (*k).to_string())
            }),
            ("effects", "APPLIED", |e| {
                e.effects.first().map(|(k, _)| (*k).to_string())
            }),
            ("ignored", "IGNORED", |e| e.ignored.first().cloned()),
            ("stated_for_other_modes", "STATED FOR OTHER MODES", |e| {
                e.stated_for_other_modes.first().map(|k| (*k).to_string())
            }),
            ("mode_unstated", "MODE UNSTATED", |e| {
                e.mode_unstated.as_ref().map(|u| u.to_string())
            }),
            ("added", "argv +=", |e| e.added.first().cloned()),
            ("mode", "STATED FOR OTHER MODES", |e| {
                Some(e.mode.to_str().to_string())
            }),
        ];

        // NOT report axes, each with the reason it is not one. A field here is
        // a deliberate answer, which is the whole difference between this and
        // silence.
        let not_reported: &[(&str, &str)] = &[
            ("path", "the subject of every line, printed by the caller"),
            (
                "argv",
                "the OUTPUT of the expansion, not a statement about it",
            ),
        ];

        let lines = out.report_lines();
        assert!(
            !lines.is_empty(),
            "the fixture produced no report at all, so nothing below is measuring anything"
        );
        let rendered: String = lines
            .iter()
            .map(|(label, body)| format!("{label} {body}\n"))
            .collect();

        let mut missing: Vec<String> = Vec::new();
        for (field, label, witness) in reporting {
            let Some(w) = witness(&out) else {
                missing.push(format!(
                    "{field} is classified as reported and the fixture left it \
                     empty, so this test cannot tell whether it reaches a line"
                ));
                continue;
            };
            // The line with THIS label, not the report as a whole. See the
            // doc: `applied()` is derived from `named`, so a check that any
            // line may satisfy let the READ line be deleted in silence.
            let bodies: Vec<&str> = lines
                .iter()
                .filter(|(l, _)| l == label)
                .map(|(_, body)| body.as_str())
                .collect();
            if bodies.is_empty() {
                missing.push(format!(
                    "{field} is reported under {label:?} and the report has no \
                     such line at all; the reader knows something the operator \
                     is never told"
                ));
            } else if !bodies.iter().any(|body| body.contains(&w)) {
                missing.push(format!(
                    "{field} carries {w:?} and the {label:?} line(s) {bodies:?} \
                     do not; the axis is labelled and empty of its own value"
                ));
            }
        }
        assert!(
            missing.is_empty(),
            "{missing:#?}\n--- report ---\n{rendered}"
        );
        assert!(
            !not_reported.is_empty(),
            "the non-reporting class is empty; if that became true the \
             destructure below is the only thing left holding the population"
        );

        // The destructure. A field added to `StockConfigExpansion` does not
        // compile until it is listed above as one or the other.
        let StockConfigExpansion {
            path: _,
            argv: _,
            added: _,
            effects: _,
            named: _,
            ignored: _,
            stated_for_other_modes: _,
            mode: _,
            mode_unstated: _,
        } = out;
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

    /// R2139 (unregistered open-debt item 227) — A ROLE THE FILE SUPPLIES MUST
    /// HONOUR EVERY KEY A TYPED ROLE DOES.
    ///
    /// # The defect, and why every existing test was blind to it
    ///
    /// The expansion checks a flag's preconditions before emitting it —
    /// `--connect-retry` needs a run mode that owns a connect list,
    /// `--scout-listen` needs one that answers scouts — and it reads the run
    /// mode off the command line. But the expansion ITSELF puts `--peer` /
    /// `--router-hat` into `added` when the file carries `mode:`, and `added` is
    /// not the command line. A precondition that consults only what was TYPED
    /// therefore gets the answer exactly backwards: it works for an operator who
    /// spelled the role out, and fails for `wz-ap-demo --config their.json5`,
    /// which is the only invocation the config path exists for.
    ///
    /// R311y849 measured two instances, and one of them —
    /// `scouting/multicast/listen` — HAD SHIPPED BROKEN since R311y846: the
    /// round that made a wz node findable by stock zenoh left it invisible on
    /// precisely the path it was written to serve. Nothing caught it because
    /// `cli_for` TYPES the role for exactly the rows whose keys have a role
    /// precondition, so the whole fixture table asks the easy half of the
    /// question.
    ///
    /// # What this derives rather than lists
    ///
    /// The population is `honoured_key_fixtures()`, which the test above pins
    /// equal to `HONOURED_CONFIG_KEYS` in BOTH directions — so a new honoured
    /// key cannot arrive without a row here, and cannot arrive without this
    /// sweep seeing it. The roles come from `RUN_MODE_ROLES`, not from a list
    /// written here.
    ///
    /// A row is IN SCOPE when, with its typed role stripped, the file still
    /// supplies a role — which is MEASURED per row rather than decided by
    /// classifying flags. `--scout` is a role the expansion never emits, so a
    /// row that types it drops out by that measurement instead of by a rule
    /// someone has to maintain. Every out-of-scope row is counted WITH ITS
    /// REASON, and an empty in-scope set fails: a sweep of nothing would pass
    /// forever and read as coverage.
    ///
    /// # Why the comparison needs no per-key knowledge
    ///
    /// THE DELTA CANCELS THE ROLE. Each row is expanded twice per invocation —
    /// control and variant — and the role's own flags appear in both, so
    /// `variant.added − control.added` contains the key's effect and nothing
    /// else. Comparing that delta between "role typed" and "role from the file"
    /// is therefore a question about the key, not about the role, and it needs
    /// no table saying which flag each key should produce.
    ///
    /// # Why this is `#[cfg]`-gated, and how that was measured
    ///
    /// The two role-gated keys are the two whose sinks are feature-gated:
    /// `config_keys_the_demo_drops` DROPS `scouting/multicast/listen` without
    /// `scouting-responder`, and `connect/retry` without `routing-peer` or
    /// `router-hat-router`. On a build lacking them both in-scope rows expand to
    /// NOTHING in both invocations, the deltas match trivially, and this test
    /// passes having proved nothing — MEASURED: on `--features zenoh-config`
    /// alone it reported "2 row(s) checked" and stayed green with y849's fix
    /// reverted. That is the empty population wearing a disguise, and the
    /// in-scope floor could not see it because the rows were present.
    ///
    /// So the test exists only where its subject does, and a row whose typed
    /// invocation reaches nothing is DERIVED as either a no-sink skip (the key
    /// is in `config_keys_the_demo_drops`) or a FAILURE (it is not, so the row
    /// has stopped testing what it claims).
    #[cfg(all(
        feature = "scouting-responder",
        any(feature = "routing-peer", feature = "router-hat-router")
    ))]
    #[test]
    fn a_role_the_file_supplies_honours_every_key_a_typed_role_does() {
        /// `variant.added` minus `control.added`, which is the key's own effect.
        fn delta(base: &StockConfigExpansion, with: &StockConfigExpansion) -> Vec<String> {
            with.added
                .iter()
                .filter(|a| !base.added.contains(a))
                .cloned()
                .collect()
        }

        let roles: Vec<&str> = RUN_MODE_ROLES.iter().map(|(flag, _)| *flag).collect();
        let mut checked: Vec<&str> = Vec::new();
        let mut skipped: Vec<(&str, &str)> = Vec::new();

        for (key, control, variant) in honoured_key_fixtures() {
            let typed = cli_for(key);
            let typed_roles: Vec<&str> = typed
                .iter()
                .copied()
                .filter(|a| roles.contains(a))
                .collect();
            if typed_roles.is_empty() {
                skipped.push((key, "this row types no run-mode role"));
                continue;
            }
            // Drop the role flag AND its value: `--peer tcp/127.0.0.1:0` is one
            // argument pair, and leaving the locator behind would hand the
            // parser a bare positional.
            let mut stripped: Vec<&str> = Vec::new();
            let mut skip_value = false;
            for arg in typed {
                if skip_value {
                    skip_value = false;
                    continue;
                }
                if roles.contains(arg) {
                    skip_value = true;
                    continue;
                }
                stripped.push(arg);
            }

            let base_dropped = expand_as_a_build_with_every_link(&stripped, control)
                .unwrap_or_else(|e| panic!("{key}: control, role dropped: {e}"));
            let with_dropped = expand_as_a_build_with_every_link(&stripped, variant)
                .unwrap_or_else(|e| panic!("{key}: variant, role dropped: {e}"));

            // MEASURED, not classified: does the file supply THE SAME role that
            // was typed? "Some role" is not enough, and the first cut of this
            // test proved it by manufacturing a defect. `scouting/timeout` types
            // `--scout` while its file carries `mode: "peer"`, so dropping the
            // flag turns a scouting one-shot into a peer — a DIFFERENT NODE,
            // whose withholding of a scout timeout is correct. Requiring the
            // same role also retires the rule the class memory states by hand
            // (`--scout` is a role the expansion never emits, so only a typed
            // one can exist): that now falls out of the measurement instead of
            // being maintained beside it.
            let supplied_same = typed_roles
                .iter()
                .all(|r| with_dropped.added.iter().any(|a| a == r));
            if !supplied_same {
                skipped.push((
                    key,
                    "the file supplies no role, or a different one than the row \
                     types, so the two invocations are different nodes",
                ));
                continue;
            }

            let base_typed = expand_as_a_build_with_every_link(typed, control)
                .unwrap_or_else(|e| panic!("{key}: control, role typed: {e}"));
            let with_typed = expand_as_a_build_with_every_link(typed, variant)
                .unwrap_or_else(|e| panic!("{key}: variant, role typed: {e}"));

            // VACUITY, derived. A row whose TYPED invocation emits nothing has
            // no behaviour for the dropped one to differ from, so comparing the
            // two proves nothing — and it compares EQUAL, which is the direction
            // that reads as coverage. Whether that is legitimate is not a
            // judgement call: the build either has a sink for this key or it
            // does not, and `config_keys_the_demo_drops` is the answer.
            if delta(&base_typed, &with_typed).is_empty() {
                assert!(
                    config_keys_the_demo_drops().contains(&key),
                    "{key}: the TYPED invocation emits nothing, so this row \
                     compares two empty deltas and proves nothing — yet the key \
                     is not one this build drops. Either the fixture stopped \
                     naming the key or its sink went away silently."
                );
                skipped.push((key, "this build has no sink for the key"));
                continue;
            }

            assert_eq!(
                delta(&base_typed, &with_typed),
                delta(&base_dropped, &with_dropped),
                "{key}: the key reaches different behaviour depending on whether \
                 the ROLE was typed or supplied by the file's `mode:`. The \
                 expansion puts a file-supplied role in `added`, so a \
                 precondition that reads only the typed command line withholds \
                 this key from `wz-ap-demo --config <file>` — the one invocation \
                 the config path exists for. Check the precondition with \
                 `rest.iter().chain(exp.added.iter())`.\n\
                 typed argv   = {typed:?}\n\
                 dropped argv = {stripped:?}"
            );
            checked.push(key);
        }

        // A sweep of nothing passes forever. This one has to be looking at
        // something, and the count is printed so a shrinking population is
        // visible rather than silent.
        assert!(
            !checked.is_empty(),
            "no fixture row types a run-mode role that the file can also \
             supply, so this test checked NOTHING. Either `cli_for` stopped \
             typing roles or `honoured_key_fixtures` lost its role-gated rows — \
             say which, in the round that did it."
        );
        // Every out-of-scope row, with its reason. A lumped count is how a
        // shortfall stops being auditable.
        eprintln!(
            "role-parity: {} row(s) checked ({}), {} out of scope",
            checked.len(),
            checked.join(", "),
            skipped.len()
        );
        for (key, why) in &skipped {
            eprintln!("  skip {key} — {why}");
        }
    }

    /// R2140 (unregistered open-debt item 219) — WHEN A FLAG IS EMITTED, THE
    /// ARGV CARRIES THE PRECONDITION `main` WILL REFUSE IT WITHOUT.
    ///
    /// # The gap, in the item's own words
    ///
    /// The drop-in e2e leg covers ONE INVOCATION: a tcp-connecting client with
    /// `--publish`. Keys that apply only to a listening node, a `tls/` link,
    /// `--query` or `--scout` are NAMED by its fixture and their flags are
    /// WITHHELD, so that leg proves "withholding does not break the node" and
    /// says nothing about "when emitted, the flag is right". The census unit
    /// fixtures do supply those preconditions — but they read the argv STRING
    /// and never ask what the binary would do with it.
    ///
    /// R311y844 measured the failure this leaves open: an expansion that emitted
    /// `--scout-timeout-ms` unconditionally turned a VALID stock config into a
    /// node that exits(2) with `--scout-timeout-ms requires --scout`.
    ///
    /// # What this derives, and from where
    ///
    /// The refusals are `main`'s own, read out of `main.rs` with `include_str!`
    /// — the idiom the `--help` sweep in this module already uses — so a new
    /// `X requires Y` arrives inside this gate instead of beside it. ⚠ THE
    /// MESSAGES SPAN LINES: `--query-timeout-ms requires --query` is written as
    /// a `\`-continued literal, and a line-at-a-time reader finds four of these
    /// where there are more. `string_literals` returns the whole literal, and
    /// the continuation is flattened here.
    ///
    /// FEATURE preconditions (`--peer requires the \`routing-peer\` feature`)
    /// are counted and skipped: they are facts about the build, not about the
    /// argv, and the expansion already answers them through `cfg!` and
    /// `config_keys_the_demo_drops`.
    ///
    /// # Why the SHAPES are a set and not one
    ///
    /// That is the whole of item 219. Each fixture row is expanded in three
    /// shapes — the one `cli_for` builds to meet that key's own precondition,
    /// the bare drop-in (`--config` and nothing else), and the drop-in the e2e
    /// leg actually performs (`--publish`/`--value`). A flag emitted in any of
    /// them is checked in that one.
    #[test]
    fn every_flag_the_expansion_emits_carries_the_precondition_main_refuses_without() {
        const MAIN: &str = include_str!("main.rs");

        /// A refusal literal with its `\`-continuations flattened.
        fn flatten(lit: &str) -> String {
            let mut out = String::new();
            let mut chars = lit.chars().peekable();
            while let Some(c) = chars.next() {
                if c != '\\' {
                    out.push(c);
                    continue;
                }
                // A `\` before whitespace is a line continuation; anything else
                // is an ordinary escape and is kept as written.
                if chars.peek().is_some_and(|n| n.is_whitespace()) {
                    while chars.peek().is_some_and(|n| n.is_whitespace()) {
                        chars.next();
                    }
                    out.push(' ');
                } else {
                    out.push(c);
                }
            }
            out
        }

        fn first_flag(text: &str) -> Option<String> {
            let at = text.find("--")?;
            let token: String = text[at..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
                .collect();
            (token.len() > 2).then_some(token)
        }

        let mut pairs: Vec<(String, String)> = Vec::new();
        let mut feature_gated: Vec<String> = Vec::new();
        for lit in string_literals(MAIN) {
            let flat = flatten(lit);
            let Some(body) = flat.strip_prefix("wz-ap-demo: ") else {
                continue;
            };
            let Some((before, after)) = body.split_once(" requires ") else {
                continue;
            };
            let Some(flag) = first_flag(before) else {
                continue;
            };
            if after.contains("feature") && !after.trim_start().starts_with("--") {
                feature_gated.push(flag);
                continue;
            }
            let Some(needs) = first_flag(after) else {
                continue;
            };
            if !pairs.iter().any(|(f, n)| *f == flag && *n == needs) {
                pairs.push((flag, needs));
            }
        }

        // The derivation must have found something. A parser that silently
        // stopped recognising these messages would make every sweep below pass
        // over an empty set of rules.
        assert!(
            !pairs.is_empty(),
            "no `<flag> requires <flag>` refusal was derived from main.rs, so \
             this gate has no rules to enforce. Either the messages were \
             reworded or this reader broke."
        );

        // THE SHAPES. `cli_for` meets the row's own precondition; the other two
        // are the drop-in invocations, one of them the one the e2e leg performs.
        const DROP_IN: &[&str] = &["--config", "z.json5"];
        const DROP_IN_PUBLISH: &[&str] = &[
            "--config",
            "z.json5",
            "--publish",
            "demo/x",
            "--value",
            "hi",
        ];

        let mut checked: Vec<String> = Vec::new();
        let mut violations: Vec<String> = Vec::new();
        let mut emitted_seen: Vec<String> = Vec::new();

        for (key, _control, variant) in honoured_key_fixtures() {
            for shape in [cli_for(key), DROP_IN, DROP_IN_PUBLISH] {
                let Ok(out) = expand_as_a_build_with_every_link(shape, variant) else {
                    // A shape this row's config cannot be read in is not a
                    // finding here; the coverage test above owns readability.
                    continue;
                };
                let argv: Vec<&str> = out.argv.iter().map(String::as_str).collect();
                for flag in &out.added {
                    if !emitted_seen.contains(flag) {
                        emitted_seen.push(flag.clone());
                    }
                }
                for (flag, needs) in &pairs {
                    if !argv.contains(&flag.as_str()) {
                        continue;
                    }
                    checked.push(format!("{key}/{flag}"));
                    if !argv.contains(&needs.as_str()) {
                        violations.push(format!(
                            "{key} in shape {shape:?}: the argv carries `{flag}` \
                             without `{needs}`, and main refuses exactly that \
                             pair — a valid stock config would expand into a \
                             node that exits(2). argv = {argv:?}"
                        ));
                    }
                }
            }
        }

        assert!(violations.is_empty(), "{}", violations.join("\n"));

        // A sweep of nothing passes forever. At least one row/shape must have
        // actually put a refusable flag in front of the rules.
        assert!(
            !checked.is_empty(),
            "no fixture row in any shape produced an argv carrying a flag main \
             can refuse, so this gate checked NOTHING. The rules exist ({} \
             pair(s)) and {} distinct flag(s) were emitted, so either the \
             shapes stopped reaching them or the emissions changed.",
            pairs.len(),
            emitted_seen.len()
        );

        // The breakdown, because a total is not auditable. Named skips only:
        // a rule whose flag no shape ever emits, and the feature rules that are
        // about the build rather than the argv.
        let unreached: Vec<&str> = pairs
            .iter()
            .filter(|(f, _)| !checked.iter().any(|c| c.ends_with(f.as_str())))
            .map(|(f, _)| f.as_str())
            .collect();
        eprintln!(
            "argv-precondition: {} rule(s) derived from main.rs, {} check(s) \
             over {} row(s) x 3 shape(s); {} flag(s) emitted in total",
            pairs.len(),
            checked.len(),
            honoured_key_fixtures().len(),
            emitted_seen.len()
        );
        for (flag, needs) in &pairs {
            eprintln!("  rule {flag} requires {needs}");
        }
        for flag in &unreached {
            eprintln!("  skip {flag} — no shape emits it, so no argv here can break the rule");
        }
        for flag in &feature_gated {
            eprintln!("  skip {flag} — its precondition is a cargo feature, not an argv flag");
        }
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
            // R2087 — `qos` LEFT this list. It became an operator-facing flag on
            // the ordinary `--connect` path (open-debt item 506), so the reason
            // it was undocumented — it only selected the aggregated multilink
            // arm — stopped being true, and the ratchet said so before this
            // round noticed.
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

        // R2091 (open-debt item 508) — the pairs are READ OFF [`RUN_MODE_ROLES`]
        // rather than restated here. This test and the config expansion's `mode`
        // verdict ask the same question of the same flags, and a second copy of
        // the answer is a second thing to keep in step with
        // `demo_session_init_params`.
        //
        // `--storage-host` and `--scout` are excluded from the SWEEP, not from
        // the table: their usage entries describe a hosting mode and a discovery
        // step rather than a role an operator picks a node to be, so requiring
        // the phrase of them would be writing the test's convenience into the
        // help text.
        const NOT_PICKED_BY_ROLE: &[&str] = &["--storage-host", "--scout"];

        for (flag, whatami) in RUN_MODE_ROLES
            .iter()
            .filter(|(f, _)| !NOT_PICKED_BY_ROLE.contains(f))
        {
            let role = match whatami {
                WhatAmI::Router => "router",
                WhatAmI::Peer => "peer",
                WhatAmI::Client => "client",
            };
            let flag = flag.trim_start_matches("--");
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

    /// R2089 (open-debt item 222) — the same question asked of the ROUTER, which
    /// is the role a stock client's `autoconnect` default looks for.
    ///
    /// PROBED before it was fixed, and the reading is why this test exists: the
    /// invocation below expanded to `argv += []` while the binary REPORTED
    /// `scouting/multicast/listen` as APPLIED. A key that is announced applied
    /// and reaches no flag is worse than one that is announced ignored — the
    /// operator has been told the opposite of what happened.
    ///
    /// The negative arm is in the same test on purpose. `--router` is a
    /// DIFFERENT run mode (it announces the peer role on the wire and hosts no
    /// responder), so the widened precondition must not reach it: an expansion
    /// that emitted `--scout-listen` there would hand the binary an argument it
    /// exits(2) on, which is the failure R311y844 measured and this file's whole
    /// `usable` discipline exists to prevent.
    #[test]
    #[cfg(all(feature = "scouting-responder", feature = "router-hat-router"))]
    fn a_router_hat_told_to_be_findable_by_a_file_gets_the_flag() {
        let file = r#"{ scouting: { multicast: { enabled: true, listen: true } } }"#;

        let drop_in = expand(
            &["--router-hat", "tcp/127.0.0.1:0", "--config", "z.json5"],
            file,
        )
        .unwrap();
        assert!(
            drop_in.added.iter().any(|a| a == "--scout-listen"),
            "a ROUTER told by its file to be findable must answer Scouts; the \
             role every unconfigured client asks for is the one that cannot \
             afford to be silent: {:?}",
            drop_in.added
        );

        // THE CONTROL: the star router is not the responder's host.
        let star = expand(
            &["--router", "tcp/127.0.0.1:0", "--config", "z.json5"],
            file,
        )
        .unwrap();
        assert!(
            !star.added.iter().any(|a| a == "--scout-listen"),
            "--router hosts no responder and exits(2) on the flag, so the \
             expansion must withhold it: {:?}",
            star.added
        );
    }

    /// R2091 (open-debt item 508) — ONE stock zenoh router file, and nothing
    /// else on the command line, becomes a wz node in the ROUTER role that
    /// answers Scouts.
    ///
    /// This is the invocation an operator performs when they drop wz in where a
    /// zenohd was: `wz-ap-demo --config their.json5`. Before this round it
    /// expanded to `["--router", <ep>]` — a run-mode that announces
    /// `WhatAmI::Peer` on the wire (`demo_session_init_params`) and spawns no
    /// responder — so the file that deploys a router produced a node in the
    /// wrong role that nothing could find. R2089 had already made the ROUTER
    /// answer Scouts; what was missing is that no FILE could select it.
    ///
    /// The peer row is the CONTROL and it is in the same test: it shares every
    /// key with the router row and differs in the one word `mode`, so an
    /// expansion that emitted `--router-hat` for everything, or `--scout-listen`
    /// for everything, fails one of the two. The client row is the second
    /// control, and it is the one that keeps `--scout-listen` from being read as
    /// unconditional: a client dials and answers nothing.
    #[test]
    #[cfg(all(
        feature = "scouting-responder",
        feature = "routing-peer",
        feature = "router-hat-router"
    ))]
    fn a_stock_router_config_on_its_own_becomes_a_findable_router() {
        fn file(mode: &str, endpoints: &str) -> String {
            format!(
                r#"{{ mode: "{mode}", {endpoints},
                   scouting: {{ multicast: {{ enabled: true, listen: true,
                                            address: "224.0.0.99:7999" }} }} }}"#
            )
        }
        const LISTENS: &str = r#"listen: { endpoints: ["tcp/127.0.0.1:0"] }"#;
        const DIALS: &str = r#"connect: { endpoints: ["tcp/r:7447"] }"#;

        let router = expand(&["--config", "z.json5"], &file("router", LISTENS)).unwrap();
        assert_eq!(
            router.added[..2],
            argv(&["--router-hat", "tcp/127.0.0.1:0"])[..],
            "a `mode: \"router\"` file must select wz's ROUTER run-mode, which \
             is the only one that announces WhatAmI::Router: {:?}",
            router.added
        );
        assert!(
            !router.added.iter().any(|a| a == "--router"),
            "the star router announces the PEER role and hosts no responder, so \
             a router file that reached it is a node in the wrong role: {:?}",
            router.added
        );
        for flag in ["--scout-listen", "--scout-addr"] {
            assert!(
                router.added.iter().any(|a| a == flag),
                "a router told by its file to be findable must join the group \
                 it names ({flag} missing): {:?}",
                router.added
            );
        }

        // CONTROL 1 — the same document, one word different. A peer is findable
        // too, and it must NOT be reached through the router's flag.
        //
        // R2091b (open-debt item 511) — this control used to assert `--listen`,
        // and that assertion was the DEFECT written down: a `mode: "peer"`
        // document with no connect list selected the one-shot acceptor, which
        // answers no Scouts. It selects the peer mesh now, so the control also
        // carries item 511's own claim.
        let peer = expand(&["--config", "z.json5"], &file("peer", LISTENS)).unwrap();
        assert_eq!(
            peer.added[..2],
            argv(&["--peer", "tcp/127.0.0.1:0"])[..],
            "a `mode: \"peer\"` document selects the peer mesh, not the one-shot \
             acceptor: {:?}",
            peer.added
        );
        assert!(
            peer.added.iter().any(|a| a == "--scout-listen"),
            "and it is findable, which the acceptor never was: {:?}",
            peer.added
        );
        assert!(
            !peer.added.iter().any(|a| a == "--router-hat"),
            "only `mode: \"router\"` selects the router run-mode: {:?}",
            peer.added
        );

        // CONTROL 2 — a client dials and answers nothing, so the same
        // `listen: true` reaches no flag at all. Without this row the two
        // scouting assertions above would pass against an expansion that emitted
        // the flags unconditionally.
        let client = expand(&["--config", "z.json5"], &file("client", DIALS)).unwrap();
        assert_eq!(client.added, argv(&["--connect", "tcp/r:7447"]));
        assert!(
            !client.applied().contains(&"scouting/multicast/listen"),
            "a client answers no Scouts, so its file's `listen: true` reached \
             nothing and must not be reported applied: {:?}",
            client.applied()
        );
    }

    /// R2091b (open-debt item 511) — THE RUN-MODE IS THE ROLE THE FILE NAMES,
    /// NOT THE SHAPE OF ITS ENDPOINT LISTS.
    ///
    /// Three ordinary stock documents used to come up as something they did not
    /// say, and each was measured against a REAL zenohd before it was written
    /// here — the claim is a DIVERGENCE between two implementations, and one
    /// implementation cannot adjudicate that on its own:
    ///
    /// | the document | a real zenohd | wz, before this round |
    /// |---|---|---|
    /// | `peer` + listen | binds it and is findable | `--listen`, the one-shot acceptor |
    /// | `router` + connect, no listen | binds port 7447 as a ROUTER | `--connect`, a CLIENT |
    /// | `client` + listen | starts and binds NOTHING | bound the endpoint |
    ///
    /// The rows are each other's controls, which is why they are one test. Each
    /// differs from a neighbour in ONE word, so an expansion that answered a
    /// single run-mode for everything fails a row; the two default rows differ
    /// in which default they get, so one that hardcoded either address fails the
    /// other; and the empty-list row fails anything that materialises a default
    /// unconditionally.
    #[test]
    fn the_run_mode_is_the_role_the_file_names_not_the_shape_of_its_endpoints() {
        const L: &str = "tcp/127.0.0.1:7447";
        const C: &str = "tcp/r:7447";

        for (what, file, want) in [
            // ITEM 511 (a). A peer with no connect list is still a peer.
            (
                "peer + listen",
                format!(r#"{{ mode: "peer", listen: {{ endpoints: ["{L}"] }} }}"#),
                vec!["--peer", L],
            ),
            // ITEM 511 (b). A router that names no listen binds what a stock
            // router binds, and stays a ROUTER.
            (
                "router + connect",
                format!(r#"{{ mode: "router", connect: {{ endpoints: ["{C}"] }} }}"#),
                vec!["--router-hat", "tcp/[::]:7447", "--connect", C],
            ),
            // The control for that default: a different mode gets a DIFFERENT
            // address, so an expansion carrying one constant fails here.
            (
                "peer + connect",
                format!(r#"{{ mode: "peer", connect: {{ endpoints: ["{C}"] }} }}"#),
                vec!["--peer", "tcp/[::]:0", "--connect", C],
            ),
            // The control for materialising it at all: a NAMED empty list is
            // upstream's own way of saying "bind nothing", and wz has no
            // run-mode that binds nothing.
            (
                "peer + an empty listen list",
                String::from(r#"{ mode: "peer", listen: { endpoints: [] } }"#),
                vec![],
            ),
            // ITEM 511 (c). A zenoh client never listens.
            (
                "client + listen",
                format!(r#"{{ mode: "client", listen: {{ endpoints: ["{L}"] }} }}"#),
                vec![],
            ),
            // Its control: the same mode with something it CAN act on, so the
            // row above does not read as "a client reaches nothing whatever it
            // says".
            (
                "client + connect",
                format!(r#"{{ mode: "client", connect: {{ endpoints: ["{C}"] }} }}"#),
                vec!["--connect", C],
            ),
        ] {
            let out = expand(&["--config", "z.json5"], &file)
                .unwrap_or_else(|e| panic!("{what}: the fixture is not readable: {e}"));
            assert_eq!(out.added, argv(&want), "{what}: {file}");
        }

        // AND THE REPORT AGREES WITH THE ARGV, on the row where the two used to
        // disagree most: a client's listen endpoint reaches nothing, and saying
        // so is the difference between an operator who knows their file did not
        // take effect and one who does not.
        let client = expand(
            &["--config", "z.json5"],
            &format!(r#"{{ mode: "client", listen: {{ endpoints: ["{L}"] }} }}"#),
        )
        .unwrap();
        assert!(
            !client.applied().contains(&"listen/endpoints"),
            "{:?}",
            client.applied()
        );
        assert!(
            client
                .read_but_not_applied_with_reasons()
                .iter()
                .any(|l| l.contains("listen/endpoints (a zenoh client never listens)")),
            "{:?}",
            client.read_but_not_applied_with_reasons()
        );
        // The CONTROL for that verdict, in the same test: one word different,
        // and the same endpoint is applied.
        let peer = expand(
            &["--config", "z.json5"],
            &format!(r#"{{ mode: "peer", listen: {{ endpoints: ["{L}"] }} }}"#),
        )
        .unwrap();
        assert!(
            peer.applied().contains(&"listen/endpoints") && peer.applied().contains(&"mode"),
            "{:?}",
            peer.applied()
        );
    }

    /// R2091 (open-debt item 508) — A KEY WHOSE FLAG THIS RUN WITHHELD IS NOT
    /// REPORTED APPLIED.
    ///
    /// Measured before this round, on a real binary and a real file: an
    /// invocation whose `argv +=` line was `["--listen", "tcp/127.0.0.1:0"]` and
    /// nothing more printed `APPLIED [… "scouting/multicast/address",
    /// "scouting/multicast/listen", "queries_default_timeout", …]`. The report
    /// was derived from a per-BUILD list of keys with no sink, so every key
    /// withheld for an INVOCATION reason was counted as applied.
    ///
    /// The control is the same three keys in the same test, in an invocation
    /// that MEETS their preconditions. Without it this test would pass against a
    /// report that called nothing applied, which is the opposite lie.
    #[test]
    #[cfg(all(feature = "scouting-responder", feature = "routing-peer"))]
    fn a_key_whose_flag_this_run_withholds_is_not_reported_as_applied() {
        const WITHHELD_KEYS: [&str; 3] = [
            "scouting/multicast/listen",
            "scouting/multicast/address",
            "queries_default_timeout",
        ];
        fn body(mode: &str, endpoints: &str) -> String {
            format!(
                r#"{{ mode: "{mode}", {endpoints},
                   queries_default_timeout: 12000,
                   scouting: {{ multicast: {{ listen: true,
                                            address: "224.0.0.99:7999" }} }} }}"#
            )
        }

        // A CLIENT: it dials, answers no Scouts, and the command line has no
        // `--query` for the timeout to qualify.
        //
        // R2091b (open-debt item 511) — this fixture used to be a `mode: "peer"`
        // document with only a listen endpoint, and that shape no longer
        // withholds anything: it selects the peer mesh now, which answers. The
        // fixture moved rather than the claim -- what is measured is still "a
        // key whose flag this run withholds is not called applied", and a client
        // is a run that genuinely withholds all three.
        let withheld = expand(
            &["--config", "z.json5"],
            &body("client", r#"connect: { endpoints: ["tcp/r:7447"] }"#),
        )
        .unwrap();
        for flag in ["--scout-listen", "--scout-addr", "--query-timeout-ms"] {
            assert!(
                !withheld.added.iter().any(|a| a == flag),
                "the fixture is not measuring a withheld flag any more: {:?}",
                withheld.added
            );
        }
        let reasons = withheld.read_but_not_applied_with_reasons();
        for key in WITHHELD_KEYS {
            assert!(
                !withheld.applied().contains(&key),
                "{key} reached no flag and was reported applied: {:?}",
                withheld.applied()
            );
            let named = reasons
                .iter()
                .find(|line| line.starts_with(&format!("{key} (")))
                .unwrap_or_else(|| panic!("{key} is in neither half: {reasons:?}"));
            assert!(
                !named.contains(UNRECORDED_VERDICT),
                "{named}: a key with no verdict is a site that did not speak"
            );
        }

        // THE CONTROL. Same three keys, same document shape; one word of `mode`
        // different, plus the `--query` the timeout needs. A PEER hosts the
        // responder, so all three reach a flag.
        let met = expand(
            &["--config", "z.json5", "--query", "demo/**"],
            &body("peer", r#"connect: { endpoints: ["tcp/r:7447"] }"#),
        )
        .unwrap();
        for key in WITHHELD_KEYS {
            assert!(
                met.applied().contains(&key),
                "{key}: the control must reach a flag, or the assertions above \
                 are measuring a report that calls nothing applied: {:?} / {:?}",
                met.applied(),
                met.added
            );
        }
    }

    /// R2091 (open-debt item 508) — every honoured key the document names gets a
    /// verdict from the site that decides its flag, and the BUILD axis is the
    /// one `config_keys_the_demo_drops()` states.
    ///
    /// Both directions, because either alone is satisfiable by a bug: a key in
    /// the drop list with no site would report `applied` (the pre-round defect),
    /// and a site that answered `NoSinkInThisBuild` for a key not in the list
    /// would put the two lists back into the drift this binding exists to end.
    #[test]
    fn every_key_this_build_drops_is_told_so_by_the_site_that_decides_it() {
        let dropped = config_keys_the_demo_drops();
        for (key, _control, variant) in honoured_key_fixtures() {
            let exp = expand_as_a_build_with_every_link(cli_for(key), variant)
                .unwrap_or_else(|e| panic!("{key}: the variant config is not readable: {e}"));
            let effect = exp
                .effects
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, e)| *e)
                .unwrap_or_else(|| {
                    panic!("{key}: no decision site spoke for it ({:?})", exp.effects)
                });
            if dropped.contains(&key) {
                assert_eq!(effect, KeyEffect::NoSinkInThisBuild, "{key}");
            } else {
                assert_ne!(
                    effect,
                    KeyEffect::NoSinkInThisBuild,
                    "{key}: reported as having no sink while not in \
                     config_keys_the_demo_drops()"
                );
            }

            // And the two halves of the report partition `named` — no key is
            // dropped from both, and none is claimed by both.
            let mut both = exp.applied();
            both.extend(exp.read_but_not_applied());
            both.sort_unstable();
            let mut named = exp.named.clone();
            named.sort_unstable();
            assert_eq!(
                both, named,
                "{key}: the report's halves are not a partition"
            );
            for line in exp.read_but_not_applied_with_reasons() {
                assert!(!line.contains(UNRECORDED_VERDICT), "{key}: {line}");
            }
        }
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
                // R2091b (open-debt item 511) — `--peer`, because a document
                // that names no `mode` resolves to upstream's own default and
                // that default is `peer` (`DEFAULT_CONFIG.json5:12`). It used to
                // read as the one-shot acceptor.
                "--peer",
                "tcp/0.0.0.0:7447",
                "--compression",
                "--config-queryable",
                "--no-admin-read",
                "--config-writable",
                "--config-write-permit",
            ])
        );
    }

    /// A document that names NO `mode` is reported as naming none, in both
    /// readings of that silence.
    ///
    /// R2109 (open-debt item 514). The fixture above is the same shape and it
    /// shows the harm: `--peer` appears on the `argv +=` line and the word
    /// `mode` appears NOWHERE in the report, because every other partition
    /// enumerates keys the file wrote. An operator moving that file off zenohd
    /// -- which reads the same silence as `router` -- had nothing to read.
    ///
    /// Both roles are asserted from the CONSTANTS rather than from the literals
    /// `peer` / `router`. The values themselves are graded against upstream by
    /// the Layer Z leg that hands the same silence to a real zenohd; restating
    /// them here would put a second, unoracled pin on the same fact.
    #[test]
    fn a_document_that_names_no_mode_reports_both_readings_of_its_silence() {
        use wz::runtime_tokio::zenoh_config::{DAEMON_DEFAULT_MODE, LIBRARY_DEFAULT_MODE};

        let silent = expand(
            &["--config", "z.json5"],
            r#"{ listen: { endpoints: ["tcp/0.0.0.0:7447"] } }"#,
        )
        .unwrap();
        assert!(
            !silent.named.contains(&"mode"),
            "the fixture names the key, so there is no silence here to report: {:?}",
            silent.named
        );
        let unstated = silent
            .mode_unstated
            .expect("a document that names no `mode` left it unstated");
        assert_eq!(unstated.read_as, silent.mode);
        assert_eq!(unstated.read_as, LIBRARY_DEFAULT_MODE);
        assert_eq!(unstated.a_daemon_reads, DAEMON_DEFAULT_MODE);
        // The sentence, not just the struct: this is what `main` prints, and a
        // pair of roles nobody rendered tells an operator nothing.
        let said = unstated.to_string();
        for role in [LIBRARY_DEFAULT_MODE.to_str(), DAEMON_DEFAULT_MODE.to_str()] {
            assert!(
                said.contains(role),
                "the sentence never names `{role}`: {said}"
            );
        }
        assert!(said.contains("daemon"), "{said}");

        // CONTROL: the same file with the key NAMED reports no silence. Without
        // it a field that was unconditionally `Some` would pass everything
        // above and put the line on every run of this binary.
        let named = expand(
            &["--config", "z.json5"],
            r#"{ mode: "peer", listen: { endpoints: ["tcp/0.0.0.0:7447"] } }"#,
        )
        .unwrap();
        assert_eq!(
            named.mode, silent.mode,
            "the two fixtures must differ only in \
                    whether the key is WRITTEN, so the control cannot pass by \
                    selecting a different run-mode"
        );
        assert!(named.mode_unstated.is_none(), "{:?}", named.mode_unstated);
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

    /// EVERY honoured key is classified by what proves its EFFECT, and the three
    /// classes partition the surface.
    ///
    /// R2083 (open-debt item 220) — 220's complaint is that the config oracle
    /// compares VALUES: it shows wz read what zenoh read, and says nothing about
    /// wz doing it. It named the gap in prose — "the remaining ten have no
    /// chain" — and prose cannot be re-measured. This makes it a per-key fact:
    ///
    /// * `wire` — a leg reads the value back off a frame the node WROTE
    ///   (`CONFIG_KEYS_PROVEN_ON_THE_WIRE`, driven by the wire sweep in
    ///   `wz_reads_a_stock_zenohd_config`)
    /// * `no sink` — this build has nothing to expand into, and says so
    ///   (`config_keys_the_demo_drops`, already gated)
    /// * `argv only` — the expansion is witnessed and nothing past it is
    ///
    /// ⛔ The third class is 220 itself, and this test does NOT shrink it — it
    /// counts it. A key moving from `argv only` to `wire` is the work; a key
    /// appearing in neither of the first two without anyone noticing is what
    /// this partition makes impossible.
    #[test]
    fn every_honoured_key_is_classified_by_what_proves_its_effect() {
        let no_sink = config_keys_the_demo_drops();
        let wire: Vec<&str> = CONFIG_KEYS_PROVEN_ON_THE_WIRE.to_vec();

        // The two named classes must be disjoint: a key with no sink here cannot
        // also be one a frame carries, and a row in both would mean one of the
        // two lists is describing a different build than the other.
        for key in &wire {
            assert!(
                !no_sink.contains(key),
                "{key} is claimed both wire-proven and sink-less"
            );
        }

        let argv_only: Vec<&str> = HONOURED_CONFIG_KEYS
            .iter()
            .copied()
            .filter(|k| !wire.contains(k) && !no_sink.contains(k))
            .collect();

        // EXHAUSTIVE: the three classes are the surface, with nothing left over
        // and nothing invented.
        let mut union: Vec<&str> = wire.clone();
        union.extend(no_sink.iter().copied());
        union.extend(argv_only.iter().copied());
        union.sort_unstable();
        let mut honoured: Vec<&str> = HONOURED_CONFIG_KEYS.to_vec();
        honoured.sort_unstable();
        assert_eq!(
            union, honoured,
            "the three classes are not a partition of the honoured surface"
        );

        // The tally, printed rather than asserted: it is the size of open debt
        // 220 in this build, and a round that moves a key from `argv only` to
        // `wire` should be able to read the number without re-deriving it. An
        // assertion on it would be a count guard over a BUILD-DEPENDENT set,
        // which is the shape this project has paid for twice.
        eprintln!(
            "config-effect classes: wire {} / no sink {} / argv only {} of {} honoured",
            wire.len(),
            no_sink.len(),
            argv_only.len(),
            HONOURED_CONFIG_KEYS.len()
        );
        eprintln!("config-effect argv-only: {argv_only:?}");

        // ANTI-VACUITY, both ends. An empty `wire` would mean 220 gained nothing
        // and this test would still pass; an empty `argv only` would mean the
        // debt is closed, which is a claim that has to be made deliberately and
        // not arrived at by a list going quiet.
        assert!(
            !wire.is_empty(),
            "no key is proven on the wire, so this partition measures nothing"
        );
        assert!(
            !argv_only.is_empty(),
            "no key is argv-only any more — open debt 220 is closed, and closing \
             it is a decision to record rather than a state to discover here"
        );
    }

    /// READ and APPLIED are different sets, and a key that is read while
    /// reaching nothing lands in both halves correctly.
    ///
    /// R2081 (open-debt item 208) — the old report printed one list and called it
    /// "honoured", so an operator asking "did my setting take effect" had to diff
    /// it against the `argv +=` line themselves. `scouting/multicast/enabled` is
    /// the sharp case: the reader honours it and this binary has no sink for it
    /// at all, so it belongs in READ and must NOT appear in APPLIED.
    ///
    /// R2112 (open-debt items 102 + 210) — this test USED to name
    /// `timestamping/enabled` here, and that key moved: it now reaches
    /// `--timestamping` and therefore lands in APPLIED. Rewriting the fixture
    /// rather than deleting the test is the point — the split it measures is
    /// still real, only the key that has no sink has changed, and the one that
    /// moved is now this test's CONTROL below.
    #[test]
    fn a_key_that_is_read_while_reaching_nothing_is_not_reported_as_applied() {
        let exp = expand(
            &["--config", "z.json5", "--listen", "tcp/127.0.0.1:1"],
            r#"{ mode: "peer", scouting: { multicast: { enabled: true } } }"#,
        )
        .expect("the fixture is readable");

        assert!(
            exp.named.contains(&"scouting/multicast/enabled"),
            "{:?}",
            exp.named
        );
        assert!(
            exp.read_but_not_applied()
                .contains(&"scouting/multicast/enabled"),
            "{:?}",
            exp.read_but_not_applied()
        );
        assert!(
            !exp.applied().contains(&"scouting/multicast/enabled"),
            "a key with no sink in this build was reported as applied: {:?}",
            exp.applied()
        );

        // The CONTROL, and it is what makes the split a measurement rather than
        // a relabelling: a key that DOES reach a flag here must land in APPLIED.
        let reaching = expand(
            &["--config", "z.json5", "--listen", "tcp/127.0.0.1:1"],
            r#"{ mode: "peer", transport: { unicast: { max_links: 3 } } }"#,
        )
        .expect("the fixture is readable");
        assert!(
            reaching.applied().contains(&"transport/unicast/max_links"),
            "{:?}",
            reaching.applied()
        );
        assert!(reaching.read_but_not_applied().is_empty());

        // The two halves partition `named` — neither drops a key nor invents one.
        for e in [&exp, &reaching] {
            let mut both = e.applied();
            both.extend(e.read_but_not_applied());
            both.sort_unstable();
            let mut named = e.named.clone();
            named.sort_unstable();
            assert_eq!(both, named, "the report's two halves are not a partition");
        }
    }

    /// R2112 (open-debt item 210) — `timestamping/enabled` reaches an argv flag,
    /// and the flag it reaches carries the value the DOCUMENT resolved for this
    /// node's role.
    ///
    /// Three arms, because the key is MODE-DEPENDENT and a single arm cannot
    /// tell "the expansion honours the key" from "the expansion emits a
    /// constant":
    ///
    /// 1. A PEER asking to stamp. Upstream's shipped map disables a peer
    ///    (`{ router: true, peer: false, client: false }`,
    ///    `DEFAULT_CONFIG.json5:206`), so `true` is a difference the file asked
    ///    for and the flag carries it.
    /// 2. A ROUTER asking NOT to stamp. Same key, opposite value, and the flag
    ///    carries THAT — this is the arm that fails if the expansion hard-codes
    ///    a side.
    /// 3. A ROUTER stating the shipped default. No flag: an added argument must
    ///    be a DIFFERENCE, which is this expansion's rule for every other key
    ///    (see the `routing/peer/mode` arm), and a redundant `--timestamping
    ///    true` would report as Expanded while changing nothing.
    #[test]
    fn the_timestamping_key_reaches_the_flag_that_carries_it() {
        let stamping_peer = expand(
            &["--config", "z.json5"],
            r#"{ mode: "peer", listen: { endpoints: ["tcp/127.0.0.1:0"] },
                 timestamping: { enabled: true } }"#,
        )
        .expect("the fixture is readable");
        assert!(
            stamping_peer.applied().contains(&"timestamping/enabled"),
            "a peer that asked to stamp must report the key APPLIED: {:?}",
            stamping_peer.applied()
        );
        assert!(
            argv_pair(&stamping_peer.added, "--timestamping") == Some("true"),
            "the flag must carry the document's value: {:?}",
            stamping_peer.added
        );

        let quiet_router = expand(
            &["--config", "z.json5"],
            r#"{ mode: "router", listen: { endpoints: ["tcp/127.0.0.1:0"] },
                 timestamping: { enabled: false } }"#,
        )
        .expect("the fixture is readable");
        assert!(
            quiet_router.applied().contains(&"timestamping/enabled"),
            "a router that asked NOT to stamp must report the key APPLIED: {:?}",
            quiet_router.applied()
        );
        assert!(
            argv_pair(&quiet_router.added, "--timestamping") == Some("false"),
            "the flag must carry the document's value, not a constant: {:?}",
            quiet_router.added
        );

        let default_router = expand(
            &["--config", "z.json5"],
            r#"{ mode: "router", listen: { endpoints: ["tcp/127.0.0.1:0"] },
                 timestamping: { enabled: true } }"#,
        )
        .expect("the fixture is readable");
        assert!(
            argv_pair(&default_router.added, "--timestamping").is_none(),
            "a file stating zenoh's own default for this role must add no flag: {:?}",
            default_router.added
        );
        assert!(
            default_router.applied().contains(&"timestamping/enabled"),
            "no flag is needed, but the node DOES what the file says, so the key \
             is applied and not a key that reached nothing: {:?}",
            default_router.applied()
        );
    }

    /// The value an emitted `<flag> <value>` pair carries, or `None` when the
    /// flag was not emitted at all.
    fn argv_pair<'a>(added: &'a [String], flag: &str) -> Option<&'a str> {
        added
            .iter()
            .position(|a| a == flag)
            .and_then(|i| added.get(i + 1))
            .map(String::as_str)
    }

    /// The expansion carries the other-modes axis and the node's own role out to
    /// the report, rather than losing them at the boundary.
    #[test]
    fn the_expansion_carries_what_the_other_modes_line_needs() {
        let exp = expand(
            &["--config", "z.json5", "--listen", "tcp/127.0.0.1:1"],
            r#"{ mode: "client", timestamping: { enabled: { router: true } } }"#,
        )
        .expect("the fixture is readable");
        assert_eq!(exp.stated_for_other_modes, vec!["timestamping/enabled"]);
        assert_eq!(exp.mode, WhatAmI::Client);
        assert!(!exp.named.contains(&"timestamping/enabled"));
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

    /// A verdict reached over a mode-less document says which reading it was
    /// reached under.
    ///
    /// R2109 (open-debt item 514) — the same seam as the `--config` report one
    /// surface over, and sharper: this check's ENTIRE answer is a function of
    /// the roles. The fixture is a lone node whose file names `listen` and
    /// nothing else; wz grades it as a peer, a zenohd would have deployed it as
    /// a router, and "1 node(s) can form the network they describe" is true of
    /// both while meaning different networks.
    #[test]
    fn a_verdict_over_a_mode_less_document_says_which_reading_it_used() {
        use wz::runtime_tokio::zenoh_config::{DAEMON_DEFAULT_MODE, LIBRARY_DEFAULT_MODE};

        const SILENT: &str = r#"{ id: "edge", listen: { endpoints: ["tcp/10.0.0.9:7447"] } }"#;
        let ok = check(&[("edge.json5", SILENT)]).expect("one node is a network of one");
        assert!(ok.contains("edge.json5: MODE UNSTATED"), "{ok}");
        for role in [LIBRARY_DEFAULT_MODE.to_str(), DAEMON_DEFAULT_MODE.to_str()] {
            assert!(ok.contains(role), "the note never names `{role}`: {ok}");
        }

        // CONTROL: the SAME node with the key written carries no such line, so
        // the assertion above is about the silence and not about the check
        // having grown a line it always prints.
        let ok = check(&[("rtr.json5", RTR_9)]).expect("one router is a network of one");
        assert!(!ok.contains("MODE UNSTATED"), "{ok}");
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

/// The wire role each run-mode flag announces, in the order `main` DISPATCHES
/// them — so the first entry a command line matches is the mode that command
/// line actually selects.
///
/// The flag names do not carry this and cannot be read for it: `--connect`
/// announces `client` while naming neither, `--router` announces `peer`, and
/// only `--router-hat` announces `router`. [`demo_session_init_params`] is
/// where the decision is made; this is that decision as a table, so the two
/// callers who need it — the config expansion's `mode` verdict and the usage
/// text's own gate — read one answer instead of keeping two.
///
/// R2091 (open-debt item 508) — named this round because the expansion's `mode`
/// verdict became a COMPARISON. "Was a role flag emitted" is not the question an
/// operator asks; "did this node come up in the role my file named" is, and the
/// two differ whenever the endpoints select a mode in another role.
///
/// Gated like [`config_keys_the_demo_drops`], and for the same reason: both of
/// its readers are, so an ungated copy is dead code in a build without the
/// config reader.
#[cfg(feature = "zenoh-config")]
pub(crate) const RUN_MODE_ROLES: &[(&str, WhatAmI)] = &[
    ("--router", WhatAmI::Peer),
    ("--peer", WhatAmI::Peer),
    ("--router-hat", WhatAmI::Router),
    ("--storage-host", WhatAmI::Peer),
    // The single-session roles, which `main` reaches last.
    ("--listen", WhatAmI::Peer),
    ("--connect", WhatAmI::Client),
    // Scouting is pre-session locator resolution; everything downstream of the
    // resolved string is the ordinary one-shot Initiator (`main.rs`).
    ("--scout", WhatAmI::Client),
];

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

/// R2112 (open-debt items 102 + 210) — `--timestamping <true|false>`: whether
/// THIS node timestamps the data messages it relays that arrive without one.
///
/// The argv shape `timestamping/enabled` expands into, and — like
/// [`TransportTuning`] — equally usable by hand: the config expansion reaches
/// the command line and stops there, so nothing in this binary has two ways to
/// learn the same fact.
///
/// `None` means the operator said nothing, which is NOT the same as `false`:
/// zenoh's shipped map is per-role (`{ router: true, peer: false, client:
/// false }`, `DEFAULT_CONFIG.json5:206`), so silence resolves differently for a
/// `--router-hat` than for a `--peer` and only [`Self::map_for`] knows which.
/// Collapsing the silence to a boolean here would make a router stop stamping
/// the moment anyone passed the struct around.
#[derive(Clone, Copy, Default)]
pub(crate) struct NodeTimestamping {
    /// The operator's answer for the role this node plays, or `None` when they
    /// gave none.
    stated: Option<bool>,
}

impl NodeTimestamping {
    /// Read `--timestamping <true|false>` off the command line.
    ///
    /// A malformed value is an ERROR rather than a silent fallback, for
    /// [`TransportTuning::from_argv`]'s reason: the operator asked for a
    /// specific stamping policy, and quietly running the other one is exactly
    /// the failure the config expansion exists to remove. `true` / `false` are
    /// the only spellings, because they are the two json5 spellings the key
    /// itself has.
    pub(crate) fn from_argv(rest: &[String]) -> Result<Self, String> {
        match parse_pair(rest, "--timestamping") {
            None => Ok(Self::default()),
            Some(v) if v == "true" => Ok(Self { stated: Some(true) }),
            Some(v) if v == "false" => Ok(Self {
                stated: Some(false),
            }),
            Some(v) => Err(format!("--timestamping expects true or false, got '{v}'")),
        }
    }

    /// The `timestamping.enabled` map a node of role `whatami` should run with.
    ///
    /// Silence yields zenoh's shipped map verbatim; a stated value overrides
    /// only THIS role's entry, so the other two keep upstream's answer — the
    /// document resolved its key against one role and made no claim about the
    /// rest (see
    /// [`TimestampingEnabled::with_role`](wz::runtime_tokio::node_clock::TimestampingEnabled::with_role)).
    pub(crate) fn map_for(
        self,
        whatami: WhatAmI,
    ) -> wz::runtime_tokio::node_clock::TimestampingEnabled {
        let shipped = wz::runtime_tokio::node_clock::TimestampingEnabled::default();
        match self.stated {
            Some(on) => shipped.with_role(whatami, on),
            None => shipped,
        }
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
