// SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
// SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
//
// wz-ap-demo — CLI banner + `--help` text.
//
// R285 — extracted from `main.rs` as part of Phase 1 module
// decomposition (the R281 carry). Pure code-move, no behaviour
// change. The `ABOUT` constant doubles as the banner emitted ahead
// of role logging in `main`, and as the header line of the
// `--help` block; keeping both in one module keeps the version
// string single-sourced from `CARGO_PKG_VERSION`.

pub(crate) const ABOUT: &str = concat!(
    "wz-ap-demo ",
    env!("CARGO_PKG_VERSION"),
    " — AP MVP demo binary",
);

/// R311y482 — the compiled feature set, as ONE line on stderr, emitted by every
/// invocation before any mode branches.
///
/// WHY THIS EXISTS, and it is not convenience. Every feature-set-specific lane
/// writes the SAME artifact path (`crates/target/debug/wz-ap-demo`), so whichever
/// `cargo build` ran last wins, and a fixture that needs a different set silently
/// drives the wrong binary. That cost THREE misdiagnoses in one session: a
/// `preset-ap-full` reply-err leg read as a wz defect against an ap-client build;
/// `wz_advanced_pubsub_zenoh_ext_interop` reported 11 failures against an ap-full
/// build (which deliberately excludes `advanced`); and a damage test read GREEN.
/// In every case the captured stderr already existed and simply did not say which
/// binary had produced it.
///
/// Each entry is the demo's OWN cargo key, so this reports what argv can reach —
/// not what the wz library was compiled with. A key absent from the list is a
/// flag that will be rejected or run INERT, which is exactly the question a
/// failing fixture needs answered. Deliberately a flat sorted list rather than a
/// hash: a fixture asserts `contains("advanced")`, and a hash would force every
/// reader to look up what it meant.
///
/// R311y489 — the list is GENERATED (`build.rs`), not hand-maintained. It was a
/// `push_if!` enumeration until this round measured it against the manifest and
/// found four declared features it never mentioned — `adminspace-read`,
/// `routing-router-hat`, `storage-backend-filesystem`, and the `preset-*` keys
/// that name which binary this is at all. Given the promise the paragraph above
/// makes, an omission does not read as silence; it reads as "that flag is off".
/// The generator derives the key set from `[features]` and the on/off answer from
/// cargo's own `CARGO_FEATURE_*`, and fails the build on any enabled feature it
/// could not account for — so the two can no longer disagree.
pub(crate) fn build_features() -> String {
    format!(
        "wz-ap-demo: BUILD FEATURES = [{}]",
        BUILD_FEATURES.join(" ")
    )
}

include!(concat!(env!("OUT_DIR"), "/build_features.rs"));

pub(crate) fn print_usage() {
    eprintln!("{ABOUT}");
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("    wz-ap-demo (--listen <addr> | --connect <addr> [--reconnect] | --scout)");
    eprintln!("               [--key <keyexpr>]");
    eprintln!("               [--publish <keyexpr> --value <text>]");
    eprintln!("               [--delete <keyexpr>]");
    eprintln!("               [--queryable <keyexpr> --reply <text> | --reply-err <text>]");
    eprintln!("               [--query <keyexpr> [--query-params <params>]");
    eprintln!("                                  [--query-attachment <k>=<v>[,<k>=<v>...]]");
    eprintln!("                                  [--query-after-ms <ms>]]");
    eprintln!("               [--declare-token <keyexpr>]");
    eprintln!("               [--liveliness-subscribe <keyexpr>]");
    eprintln!(
        "               [--advanced-subscribe <keyexpr> [--history-max <N>] [--advanced-recovery]]"
    );
    eprintln!("               [--advanced-publish <keyexpr> --value <text>]");
    eprintln!("               [--on-remote-subscriber-log]");
    eprintln!("               [--on-remote-queryable-log]");
    eprintln!("               [--on-remote-liveliness-log]");
    eprintln!("               [--on-query-reply-log]");
    eprintln!("               [--on-query-final-log]");
    eprintln!("               [--query-timeout-ms <ms>]");
    eprintln!("               [--sweep-cadence-ms <ms>]");
    eprintln!();
    eprintln!("OPTIONS:");
    eprintln!("    --listen <addr>          acceptor mode (e.g. 127.0.0.1:7447)");
    eprintln!("    --connect <addr>         initiator mode (HOST:PORT or tcp/|ws/HOST:PORT)");
    eprintln!("    --lowlatency             offer the lowlatency transport on --connect");
    eprintln!("    --compression            offer per-batch lz4 compression on --connect");
    eprintln!("                             (Z_EXT_COMPRESSION 0x6; combinable with");
    eprintln!("                             --lowlatency, where the negotiated wrap");
    eprintln!("                             is inert on the lean wire, as upstream)");
    eprintln!("    --batch-size <n>         InitSyn TX batch advertised to the peer (1..=65535,");
    eprintln!("                             default 65535). zenoh transport/link/tx/batch_size");
    eprintln!("    --lease-ms <ms>          OpenSyn session lease announced to the peer");
    eprintln!("                             (default 10000). zenoh transport/link/tx/lease");
    eprintln!("    --scout                  initiator mode with a DISCOVERED locator: emit a");
    eprintln!("                             multicast Scout on 224.0.0.224:7446 and dial the");
    eprintln!("                             locator the first peer Hello advertises. Mutually");
    eprintln!("                             exclusive with --listen / --connect. Requires the");
    eprintln!("                             `scouting-active` build feature");
    eprintln!("    --scout-timeout-ms <ms>  total --scout discovery budget, spent across repeated");
    eprintln!("                             Scout cycles (default 10000; requires --scout)");
    eprintln!("    --router <addr>          multi-peer router mode: bind once, HOLD N concurrent");
    eprintln!(
        "                             peer faces (routing-router foundation, no forwarding)."
    );
    eprintln!("                             Requires the `routing-router` build feature.");
    eprintln!("    --peer <addr>            peer-MESH mode: bind <addr> AND dial every --connect");
    eprintln!("                             target, holding both directions and forwarding along");
    eprintln!("                             the linkstate spanning tree. --connect takes a");
    eprintln!(
        "                             comma-separated list here. Requires the `routing-peer`"
    );
    eprintln!("                             build feature.");
    eprintln!("    --peer-mode <linkstate|peer-to-peer>");
    eprintln!("                             zenoh routing.peer.mode — the SUBSYSTEM-wide peer");
    eprintln!("                             routing strategy; every peer AND router of the mesh");
    eprintln!("                             must agree. Default `linkstate` (what wz's data plane");
    eprintln!(
        "                             implements); `peer-to-peer` is zenoh's own default and"
    );
    eprintln!("                             switches the DISCOVERY plane so wz can learn and");
    eprintln!("                             gossip-autoconnect in a stock zenoh mesh. Requires");
    eprintln!("                             --peer.");
    eprintln!("    --zid <hex>              PIN this node's routing zid (else it is derived from");
    eprintln!("                             the listen port). REQUIRED for a non-IP listen, which");
    eprintln!("                             has no port to derive a distinct mesh id from.");
    eprintln!("    --autoconnect            gossip-autoconnect: DIAL peers discovered in the");
    eprintln!("                             link-state flood, growing the mesh past the static");
    eprintln!("                             --connect set (requires --peer). Off by default.");
    eprintln!("    --autoconnect-strategy <always|greater-zid>");
    eprintln!("                             tie-break for the above (requires --autoconnect).");
    eprintln!("                             `always` (default, and zenoh's default) dials every");
    eprintln!("                             admitted peer; `greater-zid` dials only when this");
    eprintln!("                             node's zid is the greater, so of a mutually-");
    eprintln!("                             discovering pair exactly one end dials.");
    eprintln!("    --reconnect              long-lived reconnect-supervised lifecycle for the");
    eprintln!("                             initiator (requires --connect): on link loss, re-dial");
    eprintln!("                             (re-resolving a hostname) + replay the declaration");
    eprintln!("                             cache instead of exiting. Default is round-trip-then-");
    eprintln!(
        "                             exit. pico Z_FEATURE_AUTO_RECONNECT parity (client-only)"
    );
    eprintln!("    --key <keyexpr>          DECLARE subscriber keyexpr (e.g. demo/example)");
    eprintln!("    --publish <keyexpr>      publisher keyexpr literal (e.g. demo/test)");
    eprintln!("    --value <text>           publisher payload text (required with --publish)");
    eprintln!("    --delete <keyexpr>       delete-keyexpr publisher (R219 MsgDel body)");
    eprintln!("                             mutually exclusive with --publish; no --value");
    eprintln!("    --queryable <keyexpr>    register a queryable for the given pattern;");
    eprintln!("                             each inbound Request(Query) whose keyexpr matches");
    eprintln!("                             fires a callback that emits one Reply via --reply");
    eprintln!("    --queryable-complete     declare that queryable COMPLETE (QueryableInfo C");
    eprintln!("                             bit on the wire; the operand an AllComplete query");
    eprintln!("                             filters on). Default false, as zenoh and pico do");
    eprintln!("    --reply <text>           OK Put-form reply payload for the queryable");
    eprintln!("                             (--queryable requires this or --reply-err)");
    eprintln!("    --reply-err <text>       answer with an ERR-form Reply carrying <text>");
    eprintln!("                             instead of --reply's OK one; the two are");
    eprintln!("                             mutually exclusive. Needs query-reply-err:");
    eprintln!("                             an OFF build answers NOTHING, not an OK reply");
    eprintln!("    --query <keyexpr>        send a single Request(Query) on this keyexpr");
    eprintln!("    --query-params <params>  put URL-style selector parameters on the Query");
    eprintln!("                             body (Q_P flag + slice) -- what a zenoh");
    eprintln!("                             selector spells after '?'. Requires --query");
    eprintln!("    --query-attachment <kv>  attach '<k>=<v>[,<k>=<v>...]' to the Query as a");
    eprintln!("                             ze_serializer kv sequence (ext 0x05). Requires");
    eprintln!("                             --query; INERT without query-attachment");
    eprintln!("    --query-after-ms <ms>    hold the one-shot Query this long after");
    eprintln!("                             Established, so a foreign queryable has time");
    eprintln!("                             to declare. Requires --query");
    eprintln!("                             literal once the session reaches Established");
    eprintln!("    --declare-token <keyexpr>");
    eprintln!("                             send a single Declare(DeclToken) on this keyexpr");
    eprintln!("                             literal once the session reaches Established");
    eprintln!("    --liveliness-subscribe <keyexpr>   [repeatable]");
    eprintln!("                             declare a liveliness subscriber on <keyexpr> (R280);");
    eprintln!("                             emits one Interest(KE|TO|R|F) on Established and");
    eprintln!("                             logs 'LIVELINESS SAMPLE slot=<n> PUT/DELETE' on every");
    eprintln!("                             matching peer DeclToken / UndeclToken arrival.");
    eprintln!(
        "                             Repeat for several subscribers on ONE session; slot=<n>"
    );
    eprintln!("                             is the argv position");
    eprintln!("    --liveliness-subscribe-history");
    eprintln!("                             declare the liveliness subscriber with history=true");
    eprintln!("                             (replay CURRENT alive tokens on subscription, not");
    eprintln!("                             just future declares); order-independent observer");
    eprintln!("    --liveliness-subscribe-on-sample <keyexpr>");
    eprintln!("                             declare ONE more liveliness subscriber (history=true)");
    eprintln!(
        "                             from inside the first one's callback, on the first PUT"
    );
    eprintln!("                             -- i.e. once this session already KNOWS a token. Logs");
    eprintln!(
        "                             'LIVELINESS SAMPLE slot=late'. The declare-time replay"
    );
    eprintln!("                             is the only thing that can serve it (R311y790/y791)");
    eprintln!("    --advanced-subscribe <keyexpr>");
    eprintln!("                             declare an AdvancedSubscriber on <keyexpr> whose");
    eprintln!("                             STARTUP HISTORY GET drains every matching publisher's");
    eprintln!("                             @adv cache, so a late joiner recovers what it missed;");
    eprintln!("                             logs 'ADVANCED SAMPLE' per delivered sample");
    eprintln!("                             (needs --features advanced; inert otherwise)");
    eprintln!("    --history-max <N>        cap that history GET at the newest N samples (_max=N)");
    eprintln!(
        "    --history-max-age <secs> bound it to the last <secs> seconds (_time=[now(-s)..])"
    );
    eprintln!("    --advanced-recovery      arm SAMPLE-DRIVEN retransmission: a forward gap in a");
    eprintln!("                             source's sequence numbers is buffered and back-filled");
    eprintln!("                             by an _sn=last+1.. GET, instead of reporting a MISS");
    eprintln!("                             and delivering past the hole");
    eprintln!("    --advanced-recovery-heartbeat");
    eprintln!("                             additionally arm the HEARTBEAT trigger: subscribe to");
    eprintln!("                             publishers' <ke>/@adv/pub/** beacons and issue a");
    eprintln!("                             BOUNDED _sn=last+1..hb GET when one reports ahead");
    eprintln!("                             (requires --advanced-recovery)");
    eprintln!("    --advanced-recovery-periodic <ms>");
    eprintln!("                             additionally arm the PERIODIC trigger: re-ask every");
    eprintln!("                             known source _sn=last+1.. every <ms>, whether or not");
    eprintln!("                             a gap was seen, so a lost LAST sample is recovered");
    eprintln!("                             (requires --advanced-recovery)");
    eprintln!("    --advanced-publish <keyexpr>");
    eprintln!(
        "                             declare an AdvancedPublisher on <keyexpr> with a sample"
    );
    eprintln!("                             cache and burst --value into it, then hold the cache");
    eprintln!("                             open so a late subscriber can still drain it");
    eprintln!("                             (needs --features advanced; inert otherwise)");
    eprintln!("    --advanced-publish-count <N>");
    eprintln!("                             samples in that burst (default 5)");
    eprintln!("    --cache-max <N>          the advanced publisher's cache depth");
    eprintln!("    --liveliness-get <keyexpr>");
    eprintln!("                             one-shot liveliness snapshot get on <keyexpr>;");
    eprintln!("                             emits one CURRENT Interest(KE|TO|R|C) on Established");
    eprintln!("    --liveliness-get-after-ms <ms>");
    eprintln!("                             hold that get <ms> after Established, so a foreign");
    eprintln!("                             token holder has time to declare first (a snapshot");
    eprintln!("                             only returns tokens that already exist)");
    eprintln!("                             and logs 'LIVELINESS GET REPLY' per alive token then");
    eprintln!("                             one 'LIVELINESS GET FINAL'");
    eprintln!("    --on-remote-subscriber-log");
    eprintln!("                             install a RemoteSubscriberRegistry callback that");
    eprintln!("                             logs 'REMOTE SUBSCRIBER DECLARED' on inbound");
    eprintln!("                             Declare(DeclSubscriber); paired with");
    eprintln!("                             'REMOTE SUBSCRIBER UNDECLARED' on UndeclSubscriber");
    eprintln!("    --on-remote-queryable-log");
    eprintln!("                             liveliness-equivalent for the queryable side");
    eprintln!("    --on-remote-liveliness-log");
    eprintln!("                             liveliness-equivalent for the DeclToken side");
    // R311y798 — the three matching knobs were undocumented here. `--matching-log`
    // (R311y347) and `--querier-matching-log` (R311y775) both shipped without a
    // usage line; adding the AllComplete companion without them would leave a
    // flag whose only documentation is the fixture that uses it.
    eprintln!("    --matching-log           install a Publisher matching listener on the");
    eprintln!("                             --publish keyexpr and log every TRANSITION");
    eprintln!("                             ('MATCHING STATUS ... matching=<bool>')");
    eprintln!("    --querier-matching-log <keyexpr>");
    eprintln!("                             the QUERYABLE-plane twin: a Querier on <keyexpr>");
    eprintln!("                             plus its matching listener, logging");
    eprintln!("                             'QUERIER MATCHING STATUS ...'");
    eprintln!("    --querier-matching-all-complete");
    eprintln!("                             add a SECOND querier on the SAME keyexpr whose");
    eprintln!("                             target is AllComplete, logging under");
    eprintln!("                             'QUERIER ALLCOMPLETE MATCHING STATUS ...'. Only a");
    eprintln!("                             COMPLETE queryable INCLUDING that keyexpr raises it");
    eprintln!("    --on-query-reply-log     install a ReplyRegistry callback that logs");
    eprintln!("                             'REPLY RECEIVED' on each inbound");
    eprintln!("                             Response(Reply|Err) for the --query rid");
    eprintln!("                             (requires --query)");
    eprintln!("    --on-query-final-log     install a ReplyRegistry on_final callback that");
    eprintln!("                             logs 'FINAL RECEIVED' when the matching");
    eprintln!("                             ResponseFinal terminates the reply chain");
    eprintln!("                             (requires --query)");
    eprintln!("    --query-timeout-ms <ms>  set a ReplyRegistry timeout for the outbound");
    eprintln!("                             Query's pending entry. When >0, the");
    eprintln!("                             on_final callback fires within");
    eprintln!("                             (timeout_ms + driver-loop-tick) of register");
    eprintln!("                             time if no peer Final arrives. 0 (default)");
    eprintln!("                             disables the timeout (requires --query)");
    eprintln!("    --sweep-cadence-ms <ms>  R264 sweep_task tick period in ms. Each tick");
    eprintln!("                             invokes ReplyRegistry::sweep_timed_out so");
    eprintln!("                             expired --query-timeout-ms entries fire their");
    eprintln!("                             on_final callback. Lower = tighter bound on");
    eprintln!("                             post-deadline wall-time at the cost of more");
    eprintln!("                             wake-ups. Must be > 0. Default 100");
    eprintln!("    --help, -h               print this help and exit");
    eprintln!();
    eprintln!("Exactly one of --listen / --connect / --scout is required.");
    eprintln!("At least one of --key / --publish / --delete / --queryable / --query / --declare-*");
    eprintln!("/ --on-remote-* must be supplied.");
}
