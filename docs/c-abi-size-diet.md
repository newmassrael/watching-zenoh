# The pico C ABI library without `std`: where the code-size waste is

The goal is owner decision D9: the C library's text no larger than zenoh-pico's (1.0x), and in
the end without `std` and without a heap. This note lists what the no_std form
(`pico-client-coop-nostd`: `os-posix,link-udp`, profile `capi-nostd`, fat LTO,
`panic = "abort"`) and the std cooperative form (`pico-client-coop`) carry beyond their
function, with an estimate for each target and the change made for it. It is a companion to
`docs/host-size-debt.md`, which covers the tokio cases and the decisions on planes.

Every figure is labelled. One figure is the main session's own measurement: `pico-client-coop`
(std) read 1,017,671 after T1 to T3, against 1,037,983 before (-20,312). **Read** figures come from `nm -S`, `readelf -S` and `objdump -d` of
two artifacts already built: the std form of the integration base (`release`,
`engine-coop,link-udp`, Berkeley text 1,037,983) and a no_std form built on 2026-11-22 from
a tree 177 commits behind that base (Berkeley text 565,157, 1.40x pico's 403,086). The no_std
reading is older than the code, so its per-symbol figures are a guide, not a measurement of this
branch. **Estimates** come from reading the code. Nothing here was built from this branch; the
commands in section 4 turn the estimates into measurements.

## 1. Where the bytes are (read)

Berkeley `text` counts every allocated read-only section, not only code:

| section | zenoh-pico | wz no_std | wz std coop |
|---------|-----------:|----------:|------------:|
| `.text` | 182,915 | 440,709 | 743,427 |
| `.eh_frame` + `.eh_frame_hdr` | 72,096 | 32,788 | 116,568 |
| `.gcc_except_table` | 0 | 72 | 49,136 |
| `.rela.dyn` + `.rela.plt` | 25,296 | 39,624 | 55,944 |
| `.rodata*` | 5,392 | 24,842 | 44,208 |
| `.dynsym` + `.dynstr` + `.gnu.hash` + versions | 88,815 | 26,822 | 28,392 |
| `.plt*` | 28,464 | 56 | 64 |

Code is where the gap is: 441K against pico's 183K. The symbols of the no_std form by crate:
`wz_session_core` 167K, `wz_capi_coop` 59K, `wz_codecs` 36K, `core` 34K, `alloc` 25K,
`wz_runtime_coop` 20K, `wz_capi_pico` 17K plus about 40K in the exported `z_*` functions,
`sce_rust_runtime` 13K.

The formatter is already small in the no_std form: the panic handler ignores its `PanicInfo`
(`crates/wz-capi-pico/src/os/no_std_host.rs`), so no panic message is formatted, and the whole
`core::fmt` / `core::str` reach read about 10.6K. What keeps it linked is ordinary formatting in
the open and dial paths and in the doors (section 2, T2 and T3), and `Locator`'s `Display` (T4).

## 2. Targets

| id | target | form | estimate | status |
|----|--------|------|---------:|--------|
| T1 | lent record walk generic over its consumer | both | std -8K to -14K, no_std -5K to -6K | landed here; with T2 and T3, std read -20,312 |
| T2 | `z_keyexpr_concat` / `z_keyexpr_join` through `format!` | both | -0.3K direct | landed here |
| T3 | open and dial refusals formatted into a `String` | both | -1.5K to -3K | landed here |
| T4 | `Locator` text through `core::fmt` and `SocketAddr`'s `Display` | both | -3K to -5K | landed before round 2 (see T4) |
| T5 | `expect` / panic locations on reachable paths | both | -1K to -2K | candidate |
| T6 | relative relocations (`.rela.dyn`) packed (DT_RELR) | both | std -52.5K, no_std -37.7K | landed as a named Linux link choice |
| T7 | unwind tables of the prebuilt `core` / `alloc` | no_std | about -30K | owner decision |
| T8 | owned records in a build that lends every one | both | -0.3K to -3K | record buffer landed in round 2; outcome list candidate |
| T9 | per-limit generic selectors (`limit_binding`, `policy_binding`) | both | -3K to -4K | domain check landed here |
| T10 | observer planes kept out of line for the stack | both | at most -0.5K | not worth a change alone |
| T11 | the owned encoders compiled twice (count, then write) | both | -2.5K to -5K no_std | landed in round 2 |
| T12 | the remote queryable plane in a build without `query` | both | -3K to -5K | landed in round 2 |

### T1: one walk for every consumer (landed, `refactor(session-core): Walk lent records through one dispatch body`)

`network_message::try_for_each_record_while` and every `lend_*` reader were generic over the
closure that takes a record. Each closure gave a copy of the walk and of each reader, and a
generic caller (`drive::walk_records_in_place<R, T>`) was compiled in the runtime's crate, so the
codec's lent decoders it reaches were compiled there a second time. Read in the std form:
`lend_push`, `lend_declare`, `lend_oam` and `lend_interest` twice each (12,000 together, the
smaller copy of each about 5,800), and 8,850 bytes of byte-identical second copies of
`MsgPutIn<Lent<Node>>::decode_into` (1,938), the four `Decl*` and four `Undecl*`
`decode_into`, `DeclFinal`, and the zbuf slice list's `refill`. The walk now forwards to one
`#[inline(never)]` body, `walk_records`, and every reader takes the consumer as
`&mut dyn FnMut`, so all of it is compiled once, in `wz-session-core`. Fat LTO merges
identical bodies, so the no_std form loses only the per-closure copies. Cost: one indirect call
per record, and the consumer's body is a frame of its own under the reader's.

### T2: keyexpr joins (landed, `refactor(capi-pico): Join keyexpr texts without the formatter`)

Both doors joined two `&str` with `format!`, which reaches `alloc::fmt::format_inner`,
`core::fmt::write` and `<str as Display>` (through `Formatter::pad`). They concatenate now.

### T3: typed open refusals (landed, `refactor(capi-coop): State an open refusal as a typed reason`)

`OpenError::{Listen, Group, Unreachable}` held a `String` made with `format!` and the `Debug` of
`DialRefused`, `LinkOpenError` and `CloseReason`, in `Core::poll_links`, `Core::dial_from`,
`Core::dial_answered`, `begin_dial`, and the "not built" refusals inlined into `open_on_coop`
(the read no_std form shows `format_inner` called from exactly these, and from T2's two doors).
The C ABI maps each to a code and never reads the words. They hold `EndpointRefusal` (the
endpoint and a `Refusal` reason) now. The text survives as `Display` and is formatted only by a
program that prints it. With T2, no `format!` is left on the client's paths, so `format_inner`
and the `String` writer should leave the no_std form. `core::fmt::write` stays for T4.

### T4: locator text without the formatter (landed before round 2)

The base of round 2 already writes it without `core::fmt`: `Locator::text`
(`crates/wz-runtime-coop/src/session_drive.rs`) pushes the scheme and the end through
`TextOut::push_socket_addr` and `TextOut::push_ip` (`crates/wz-session-core/src/text_out.rs`):
dotted IPv4, RFC 5952 IPv6 (lowercase groups, the first longest run of two or more zero groups
folded to `::`, a single zero group kept, an IPv4-mapped address as `::ffff:a.b.c.d`), `[..]`
around an IPv6 end and `%scope` inside it. The tests hold it to `Display`'s own text:
`text_out::tests::an_address_is_written_as_the_formatter_writes_it` (no run, one group alone, a run
at either end, two runs of which the first or the longer wins, the unspecified, loopback,
IPv4-compatible and IPv4-mapped forms, a scope of `u32::MAX`) and the locator test of
`udp_link.rs`, which compares `Locator::text` with `format!("{locator}")`. `Locator`'s `Display` is
left for the program-supplied transport (`app-transport`) and the listener's local text
(`listen`), neither of which the no_std case builds, and a read of `wz-runtime-posix`,
`wz-host-sync` and `wz-capi-port` finds no other formatting on the client's paths (the
`multicast.rs` `Display` is `group-host`'s, `scouting.rs` is `scout`'s).

### T5: panic sites (candidate)

Each panic location is 24 bytes of `.data.rel.ro` plus a 24-byte relocation (T6) plus its call.
The read no_std form has 254 relocations into `.rodata.str1.1`, most of them file names of panic
locations. Reachable `expect` sites: `Registry::watch_publishers` and `watch_queriers`, and
`MsgPutIn::try_into_owned_in` (where it is still linked). Where the condition is an invariant,
the right form is a code path that cannot panic (a `match` that returns, or an index type
that cannot be out of range), not a cheaper panic. Gating `Debug` derives behind
`debug_assertions` gains nothing: an impl nothing calls is not linked.

### T6: relative relocations (landed as a named Linux link choice, owner decision 2026-11-23)

The no_std form carries 1,590 `R_X86_64_RELATIVE` entries, 24 bytes each: vtables and function
pointers (486 into `.text`), string slices (254), panic locations, and GOT entries for calls into
the prebuilt `core` (418). The std form carries 2,215. Linking with `-z pack-relative-relocs`
(DT_RELR) writes them as a bitmap in `.relr.dyn`.

**What was done** (`build(capi-pico): Pack the Linux C ABI library's relative relocations`).
`crates/.cargo/capi-packed-relocs.toml` gives `-C link-arg=-Wl,-z,pack-relative-relocs` to a
build for `cfg(all(target_os = "linux", target_env = "gnu"))` and to nothing else, named with
`--config` and the host's target (`--target`), so the build scripts, which run on the build
host, are linked as before. The two forms of the Linux library:

| form | build | loader | linker |
|------|-------|--------|--------|
| packed | `--config .cargo/capi-packed-relocs.toml --target x86_64-unknown-linux-gnu` (after `.cargo/capi-nostd.toml` for the no_std form) | glibc 2.36 or later; an older one refuses the library by the version need `GLIBC_ABI_DT_RELR` | GNU ld 2.38, lld 15 or later |
| compatible | the same build without that file | any the library's other symbol versions allow | any |

The size cases `pico-client-coop` and `pico-client-coop-nostd` name the file
(`Case.cargo_configs` in `scripts/lib/capability_cost_gate.py`). No Linux release package of
the pico library exists to carry the choice: `release.yml` attaches the Windows packages only
(`pico_windows_package.py`, PE, where the choice does not arise), and the Linux entry of the
target-build contract (`wz_package.py`, platform `linux-x86_64-glibc`) builds with plain
`--release`, the compatible form. A Linux package that ships the packed form names it as such
beside the compatible one, and its manifest's glibc floor reads 2.36 for it: `elf_facts.glibc_floor`
counts `GLIBC_ABI_DT_RELR` as glibc 2.36 (`fix(scripts): Read a DT_RELR version need as glibc
2.36`). Windows (PE) and the MCU images (static) have no such relocations.

**Refused by name, not dropped.** An older GNU ld ignores `-z pack-relative-relocs` with a
warning, and a linker that wrote DT_RELR without the version need would leave a library that an
older loader runs unrelocated. So the gate holds every library linked with the flag, and its
reference, to a dynamic section with DT_RELR and a version need on `GLIBC_ABI_DT_RELR`
(`link_findings`); either missing fails the run in `--measure` too, and no ceiling reading is
taken from the pair.

**Fairness.** The reference is zenoh-pico "as the same build", so it is linked with the same
linker arguments as its case (`reference_args`: `-DCMAKE_SHARED_LINKER_FLAGS`, part of the
reference's cache key). Both sides move; the cut is nonetheless wz's, because the read reference
has 58 relative relocations (its calls go through 888 PLT slots, which DT_RELR does not touch).
The gate prints the linker of each library from its `.comment`. Read on 2026-11-23: the wz
libraries are linked by the toolchain's own lld (`Linker: LLD 22.1.6`, the default linker of
`x86_64-unknown-linux-gnu` on the pinned toolchain) and the reference by the C compiler's, GNU ld
(2.42 on the coordinating host; hosted C1cs runs on ubuntu-22.04, GNU ld 2.38 and glibc 2.35,
which builds and reads the packed form but could not load it). The coordinating host's own cargo
configuration links its host target with mold (`-fuse-ld=mold`, mold 2.30.0). cargo joins that
table with a file named by `--config`, so the gate's no_std case, built that way, was linked by
mold on that host (the no_std library read here names mold 2.30.0, the std one lld), while the
flags of the environment, which every other case was built with, replace it. The gate now reads
a case's configuration files itself and passes their flags in the environment
(`fix(gate): Build configured size cases apart from the caller's config`), so every case is
linked by the toolchain's linker unless the caller exports another. The two arms are still linked
by different linkers (lld against GNU ld), as they were before this change; linking both with one
is a separate choice for the owner.

**What the gate's number moves by.** The gate reads Berkeley `size` text, which counts every
allocated read-only section: `.rela.dyn`, `.relr.dyn`, `.eh_frame` and `.eh_frame_hdr` are in
it (`.data.rel.ro` and the GOT are writable, so they are data). From the relocation offsets of
the read libraries, packed with the standard encoding (an address word, then 63-entry bitmaps):

| library | relative relocations | `.rela.dyn` removed | `.relr.dyn` | text moves by |
|---------|---------------------:|--------------------:|------------:|--------------:|
| std (`pico-client-coop`) | 2,215 | 53,160 | 632 | about -52,500 |
| no_std (`pico-client-coop-nostd`) | 1,590 | 38,160 | 440 | about -37,700 |
| zenoh-pico reference | 58 | 1,392 | 32 | about -1,360 |

The version need adds about 34 bytes to each. Ratios against the committed ceiling readings:
no_std 565,295 / 403,086 = 1.4025 to about 527,600 / 401,760 = 1.313; std 1,030,646 / 403,086
= 2.5569 to about 978,150 / 401,760 = 2.435. These are estimates from the read libraries; the
no_std one was linked by mold, and lld may place a few relocations differently.

### T7: unwind tables of the prebuilt standard crates (owner decision)

`force-unwind-tables=no` reaches only the crates this build compiles, so `core` and `alloc`
keep theirs (about 29K plus 3.8K of header). Nothing unwinds (`panic = "abort"`, and an
`extern "C"` door aborts on a foreign unwind). Dropping them needs a linker script that
discards `.eh_frame` or a toolchain that builds `core` (`-Z build-std`, nightly), and a
debugger then has no unwind tables for those frames. zenoh-pico itself carries 72K of them.

### T8: owned records in a build that lends every one (record buffer landed in round 2)

Re-scoped from the std form's thin-LTO copies (fat LTO for the C ABI profiles remains the cure for
those, 15,683 bytes read in the std form): in the no_std case the receive lends every record
(`rx-lent-control`, no `transport-stats`, no `routing-namespace`), so no record is ever decoded into
an owned `NetworkMessage`, yet the walk's one-record buffer was a `Vec<NetworkMessage>` that every
record cleared, which links the drop of every owned message kind for a list that is always empty.
Landed (`refactor(session-core): Hold no owned record where every one is lent`): `RecordBuf` is the
marker of no size there, as it already was without an allocator. Estimate -0.3K alone; the drop
glue itself stays while anything else drops an owned message.

What still links it: `DriverLoopOutcome::FramePayload { messages: Vec<NetworkMessage>, .. }`. In
the lend-only build the walk reports an empty frame as a `FramePayload` with an empty list and the
tables read every batch through `driver_loop::owned_records`, which answers `None` there, but any
outcome dropped where its variant is not known (`dispatch_parked_in_place`, the handshake
outcomes) drops through the variant's `Vec<NetworkMessage>`. The cure is the record buffer's: a
list of no size in that build. Candidate, not done: some twenty readers of `messages` across
`wz-session-core`, `wz-session-mcu`, `wz-runtime-coop` and the tokio runtime would each need the
same gate. Estimate -1K to -3K (the owned kinds' drop glue).

### T9: per-limit selectors (domain check landed, `refactor(session-core): Check a limit's domain in one function`)

`limit_binding::select_at::<S, L>` (57 instances, 5,758 in std) and `held_at` (63, 891), with
`policy_binding::select_at` (32, 895), are one function per limit, each converting a
`LimitValue` into the limit's own type and storing it at the field `L` names. An outlined form
would hold the conversion once per value type and the field as data in the limit's table
entry. That is a change of the table's construction. The part that needs no such change is
landed: `Limited::select` inlined the domain's check and the refusal it builds into every
selector (the 27 instances of 125 to 199 bytes; the pinned ones fold to about 30), and now
calls one out-of-line `admit` with the limit's id and domain. Estimate: -2.5K to -3.5K in
either form, the selector entries' own setters left.

### T10: observer planes out of line (measured by the main session)

The planes `SlotObserverOf::dispatch_event_among` calls are `#[inline(never)]` so each plane's
temporaries are in a frame of their own. In `pico-client-coop` three planes are split out
(`SubscriberTable` +4,343, `RemoteSubscriberTable` +2,244, `RemoteQueryableTable` +2,736, the
flush +564) and the fan lost 9,673: net about +214. What the inliner had shared is the event match
and `record.declare()`. The two remote declaration planes could share one out-of-line call that
reads the declare once; the gain is at most a few hundred bytes, so the split stays.

### T11: the owned encoders compiled twice (landed in round 2)

Every owned send sized its slot with the codec's `measure` (`PushWire::measure`,
`DeclareWire::measure`, `InterestWire::measure`, ...: the generated field walk over `CountSink`) and
then wrote it with the same walk over `TxSink<dyn TxBuf>`, two instances of each message's whole
encoder (the Put body, the key, the extension entries, every declaration body). Landed
(`refactor(session-core): Count a lent send with the encoder it writes`): in the lend-only build
(`tx-lend-only`) the length is the body writer the dispatch then runs, run once into
`tx_buf::CountTxBuf`, a buffer that keeps no byte (`tx_buf::encoded_len`), so each encoder is
compiled once. It covers `frame_encode::push_capacity_hint` and the Declare, Oam, Request,
Response, ResponseFinal and Interest dispatches of `session_actions`. The heap profile keeps
`measure`, which costs no indirect call per field on the AP's paths. The plain Put was already
written once (`lent_push::plain_put_len`), and the lent Response counts by its direct writer's
layout. Estimate -2.5K to -5K in the no_std case (Push, Declare and Interest walks; Request and
Response join with `query` and `queryable`). The `CountSink` count of a lent `Request`
(`send_get_parts`) is left: it is one walk of the borrowed writer, which the build has no second
instance of.

### T12: the remote queryable plane without `query` (landed in round 2)

Landed (`refactor(capi-coop): Link the peers' queryables only with a query plane`):
`wz-session-core/declare-queryable` moved from `wz-capi-coop`'s base list to its `query` and
`queryable` features. A client with neither links no `RemoteQueryableTable`, no dispatch of a
peer's queryable declarations and no queriers' matching listener. What such a build answers, by
name: a matching listener and a write filter on the queryables plane are refused before an
Interest is asked (`engine::counts`: a listener as id 0, a filter as none; the ABI asks neither
without `query`), and a declaration watch of queryables is refused with `PlaneNotBuilt`, as one of
tokens is without `liveliness` (`decl_watch::hears`): the build has nothing to tell it from.
`slot_observer::OtherPeers::answers` has a default (`false`), so a build where another crate
unified `declare-queryable` in still compiles the engine's `OtherPeers`. Estimate -3K to -5K.

## 3. Features the shipped profile enables that the ABI does not reach

Resolved with `cargo tree -e features` for `os-posix,link-udp`: `wz-session-core` got
`declare-queryable` (T12, now with `query` or `queryable` only), `declare-interest` and `session-matching` (read by the publisher's
matching status, reachable), and `pubsub-*` (each read by a field of
`z_put_options_t`, reachable). `hashbrown` with `foldhash` is linked (a `HashMap<u16, String>`'s
`reserve_rehash` read 1,424 in the no_std form), which a no-heap form replaces anyway.

## 4. How to measure

```
python3 scripts/lib/capability_cost_gate.py --measure pico-client-coop
python3 scripts/lib/capability_cost_gate.py --measure pico-client-coop-nostd
```

Per target, from two builds of the case before and after the commit:

```
python3 scripts/lib/footprint_attribution.py --old <before.so> --new <after.so> \
  --scope 'network_message::(lend_|walk_records|try_for_each)' --scope 'decode_into' \
  --scope 'alloc::fmt|core::fmt|core::net' --scope 'OpenError|EndpointRefusal'
```

and `nm -S --size-sort -C` of the std form for duplicate names (T8): two entries with one
demangled name are two copies.

For round 2's three changes, the same with `--scope 'CountSink|CountTxBuf|encoded_len'` (T11: the
`CountSink` instances of `PushWire`, `DeclareWire` and `InterestWire` gone),
`--scope 'RemoteQueryable|watch_queriers'` (T12) and `--scope 'drop_in_place<.*NetworkMessage'` (T8).

## 5. Round 2: where the no_std form's code goes, and what pico's build does not carry

**Attribution (read and estimated).** The read of section 1, by crate: `wz_session_core` 167K,
`wz_capi_coop` 59K, the exported `z_*` functions about 40K and `wz_capi_pico`'s own 17K,
`wz_codecs` 36K, `core` 34K, `alloc` 25K, `wz_runtime_coop` 20K, `sce_rust_runtime` 13K. Within
`wz_session_core`, from the code paths the case links (`wz-capi-coop`'s base list, `host-sys`,
`rx-lent-only`, `tx-lend-only`, `initial-sn-compact`, `limits-lent-at-open`, and `wz-session-mcu`'s
`dial`, `transport-keepalive`, `reassembly`), the estimate is: the send side of `session_actions`
(dispatch, batching, fragmentation, lending, the owned builders it is handed) 45K to 60K; the
receive walk and the lent readers (`drive`, `driver_loop`, `network_message`, `lent_*`) 25K to
35K; the application tables and their planes (`observer`, `slot_observer`, `declare/*`, matching)
25K to 35K; policy and limit resolution (`policy_document`, `policy`, `limits`, the bindings and
the generated tables) 10K to 18K; the generated session machine and its binding 10K to 15K;
key expressions, reassembly, the lease and the rest the remainder. These are estimates: section 4's
`nm -S` of a build, grouped by the path prefix of each symbol, turns them into a reading.

**The wz features the case carries that pico's same build does not.** For each: whether an export
the pico ABI must have reaches it, what was done, and the estimate (from the code; none measured).

| # | feature (where) | reached from a required export | verdict | estimate |
|---|-----------------|--------------------------------|---------|---------:|
| 1 | policy and limit resolution (`policy_document`, `policy`, `limits`, `policy_binding`, `limit_binding`) | only through `wz_ext_config_policy` / `wz_ext_config_profile`, which `z_open` composes (`config_policy::PolicyStatements::compose_into`); with neither door called it is the build defaults | lighter form: a capability for the two doors, off in the pico client profiles, and an open that takes the build defaults with no resolver. Owner decision: the doors are documented as in every build and the gate pins 445 exports | -6K to -12K |
| 2 | the session's arena and its lent rows (`wz-capi-coop/arena.rs`, `bounded::Lent`, `Quota::lent_under`) | `z_open` | kept: it is the no-heap form decision D9 asks for (pico mallocs per object); the MCU heap work owns it | (6K to 10K, kept) |
| 3 | the generated session machine (`sce_rust_runtime`, `session_fsm_unicast` and its binding) | every open | kept: the machine is the SCXML source's; pico's handshake is hand-written | (10K to 15K, kept) |
| 4 | the owned Put and Delete with options (`push_build::build_push_*_with_meta`, `PushOwned` and its drop) | `z_put` / `z_publisher_put` with an encoding, attachment or timestamp, every delete | lighter form: a borrowed writer for a Put or Del with its body extensions (`lent_push::write_plain_put` extended), each field held to the owned builder's bytes as `the_direct_writer_is_the_codecs_bytes` holds the plain one. Not done: a writer and its equality tests per field | -4K to -8K |
| 5 | owned declarations and interests in the heap lend-only build (`declare_build`, `interest_build`, `DeclareOwned`, `InterestOwned`) | `z_declare_subscriber`, `z_declare_keyexpr`, matching, interests | lighter form: the borrowed writers the no-allocator build already sends with (`lent_control`, `LentDeclaration`) used in `tx-lend-only` too; T11 already compiles the owned encoder once | -3K to -6K |
| 6 | the delivery lane (`wz-capi-coop/lane.rs`) | every delivery | kept: callbacks run after the session's lock (decision D8) | (3K to 5K, kept) |
| 7 | the droppable publish handed off (`HandedLeg`, `hand_off`, `send_handed`) | a put that finds the session held | kept: what D8 owes a droppable put; pico waits on its own lock | (1.5K to 3K, kept) |
| 8 | the faces table for more than one link (`FaceRows`, `Others`, `max_faces`) | the dial face; others come from `listen`, `group` and `attach_face` | lighter form: a one-face registry where no second face can come. Not touched: the registry is another worker's in this round | -2K to -4K |
| 9 | the remote queryable plane | none without `query` / `queryable` | cut (T12) | -3K to -5K |
| 10 | source info on put and delete (`pubsub-source-info` in `wz-capi-coop`'s base list) | none without `unstable-api`: the option field reads as null and `z_sample_source_info` is not exported | cut candidate: move the feature to `wz-capi-pico`'s `unstable-api`, gate the four `with_source_info` calls of `pubsub.rs` and the lane test that names it. Not done: three crates and the lane record's field | -1K to -2K |
| 11 | owned records reported where every one is lent (`FramePayload.messages`) | none in the lend-only build (`owned_records` answers `None`) | record buffer cut (T8); the outcome list is a candidate (T8) | -1K to -3K |
| 12 | the owned encoders counted by a second instance | owned sends | cut (T11) | -2.5K to -5K |
| 13 | the outbound key mappings in a `hashbrown` map with `foldhash` | `z_declare_keyexpr` | lighter form: a table of the build's `MAX_DECLARED_KEYEXPRS` rows; the no-heap work replaces it anyway | -1.5K to -3K |
| 14 | typed refusals and their counters (`OpenError`, `EndpointRefusal`, `SendWireError`, `tx_refusals`, `InPlaceFallbacks`) | the doors map each to a code | kept: the codes a program reads; the words are formatted only by a program that prints them (T3) | (1K to 2K, kept) |
| 15 | wz doors in every build (`wz_ext_conformance_digest`, the key-wire-form doors of `key_ids`) | none of pico's | owner decision with item 1: the same pin of the export count | -0.3K to -1K |

Items 1, 4, 5, 8, 10 and 13 together are the bulk of what a reading can name: -17K to -35K. Against
the measured 542,460 and pico's 403,086 (the 1.0x goal needs -139K), code volume of this kind is
not the whole answer: T6 and T7 (-66K, owner decisions) and the session-core send side are the
other two places to look.
