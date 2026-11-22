# The pico C ABI library without `std`: where the code-size waste is

The goal is owner decision D9: the C library's text no larger than zenoh-pico's (1.0x), and in
the end without `std` and without a heap. This note lists what the no_std form
(`pico-client-coop-nostd`: `os-posix,link-udp`, profile `capi-nostd`, fat LTO,
`panic = "abort"`) and the std cooperative form (`pico-client-coop`) carry beyond their
function, with an estimate for each target and the change made for it. It is a companion to
`docs/host-size-debt.md`, which covers the tokio cases and the decisions on planes.

Every figure is labelled. **Read** figures come from `nm -S`, `readelf -S` and `objdump -d` of
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
| T1 | lent record walk generic over its consumer | both | std -8K to -14K, no_std -5K to -6K | landed here |
| T2 | `z_keyexpr_concat` / `z_keyexpr_join` through `format!` | both | -0.3K direct | landed here |
| T3 | open and dial refusals formatted into a `String` | both | -1.5K to -3K | landed here |
| T4 | `Locator` text through `core::fmt` and `SocketAddr`'s `Display` | both | -3K to -5K | candidate |
| T5 | `expect` / panic locations on reachable paths | both | -1K to -2K | candidate |
| T6 | 1,590 relative relocations (`.rela.dyn`) | both | about -36K no_std | owner decision |
| T7 | unwind tables of the prebuilt `core` / `alloc` | no_std | about -30K | owner decision |
| T8 | generic copies thin LTO keeps in two crates | std | -10K to -20K | candidate |
| T9 | per-limit generic selectors (`limit_binding`, `policy_binding`) | both | -3K to -4K | candidate |
| T10 | observer planes kept out of line for the stack | both | at most -0.5K | not worth a change alone |
| T11 | the Put encoder compiled twice (count, then write) | both | about -1.4K | candidate |
| T12 | the remote queryable plane in a build without `query` | both | -3K to -5K | candidate |

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

### T4: locator text without the formatter (candidate)

`wz_runtime_coop::session_drive::Locator`'s `Display` is `write!(f, "{}/{}", scheme, at)`, and
`Locator::text` (1,334 in the read no_std form) writes it into a fixed buffer. That links
`core::fmt::write`, `SocketAddr`'s `Display` (`core::net`, about 3K) and
`Formatter::pad_integral`. A writer of its own (dotted IPv4, the port, and RFC 5952 IPv6 with the
longest zero run folded and `[..]` around it) would take all three out. It needs tests against
`SocketAddr`'s own text for the IPv6 edge cases (a v4-mapped address, a scope id) before it can
replace it.

### T5: panic sites (candidate)

Each panic location is 24 bytes of `.data.rel.ro` plus a 24-byte relocation (T6) plus its call.
The read no_std form has 254 relocations into `.rodata.str1.1`, most of them file names of panic
locations. Reachable `expect` sites: `Registry::watch_publishers` and `watch_queriers`, and
`MsgPutIn::try_into_owned_in` (where it is still linked). Where the condition is an invariant,
the right form is a code path that cannot panic (a `match` that returns, or an index type
that cannot be out of range), not a cheaper panic. Gating `Debug` derives behind
`debug_assertions` gains nothing: an impl nothing calls is not linked.

### T6: relative relocations (owner decision)

The no_std form carries 1,590 `R_X86_64_RELATIVE` entries, 24 bytes each: vtables and function
pointers (486 into `.text`), string slices (254), panic locations, and GOT entries for calls into
the prebuilt `core` (418). Linking with `-z pack-relative-relocs` (DT_RELR) packs them into a
bitmap of about 1K. That would be a rustflag in `.cargo/capi-nostd.toml`. It requires a loader
that knows DT_RELR (glibc 2.36 or later, Android API 28 or later) and a linker that writes it
(GNU ld 2.38, lld 15, mold). On an older loader the library fails to load with a
`GLIBC_ABI_DT_RELR` version error. That is a statement about which hosts the library
supports, so it is the owner's.

### T7: unwind tables of the prebuilt standard crates (owner decision)

`force-unwind-tables=no` reaches only the crates this build compiles, so `core` and `alloc`
keep theirs (about 29K plus 3.8K of header). Nothing unwinds (`panic = "abort"`, and an
`extern "C"` door aborts on a foreign unwind). Dropping them needs a linker script that
discards `.eh_frame` or a toolchain that builds `core` (`-Z build-std`, nightly), and a
debugger then has no unwind tables for those frames. zenoh-pico itself carries 72K of them.

### T8: copies thin LTO keeps (candidate)

The release profile is thin LTO. A generic instantiated from two crates is compiled in each, and
the linker keeps both. Read in the std form: 21,120 bytes of byte-identical second copies, 15,683
of them wz or SCE code. T1 removes the decoder family (8,850). The rest is mostly drop glue of
owned forms (`DeclareVariantIn<Heap>`, `InboundFrame`, `NetworkMessage`, `PushVariantIn<Heap>`)
and an `ExtEntryWire` writer. Two cures: fat LTO for the C ABI profiles (the no_std form already
has it, and it read 4,830 of such copies), or making the owned-form users non-generic as T1
did.

### T9: per-limit selectors (candidate)

`limit_binding::select_at::<S, L>` (57 instances, 5,758 in std) and `held_at` (63, 891), with
`policy_binding::select_at` (32, 895), are one function per limit, each converting a
`LimitValue` into the limit's own type and storing it at the field `L` names. An outlined form
would hold the conversion once per value type and the field as data in the limit's table
entry. That is a change of the table's construction; the estimate is the selectors less one
copy per value type.

### T10: observer planes out of line (measured by the main session)

The planes `SlotObserverOf::dispatch_event_among` calls are `#[inline(never)]` so each plane's
temporaries are in a frame of their own. In `pico-client-coop` three planes are split out
(`SubscriberTable` +4,343, `RemoteSubscriberTable` +2,244, `RemoteQueryableTable` +2,736, the
flush +564) and the fan lost 9,673: net about +214. What the inliner had shared is the event match
and `record.declare()`. The two remote declaration planes could share one out-of-line call that
reads the declare once; the gain is at most a few hundred bytes, so the split stays.

### T11: the Put encoded by two sinks (candidate)

`push_build::build_msg_put_with_meta` reaches `MsgPutWire::write_source` over `CountSink`
(1,375) to size the message and over `TxSink` (1,951) to write it. One pass that writes, then
reads the length it wrote, keeps one instance. The generated encoder is SCE's, so the change is
on the wz side, at the call.

### T12: the remote queryable plane without `query` (candidate)

`wz-capi-coop` names `wz-session-core/declare-queryable` in every build, so a client without
`query` still links the remote queryable table, its dispatch (2,736) and its matching listener
seeding. In the cooperative engine its readers are the querier's matching status (`query`) and
the declaration watch. If that watch is the only reader without `query`, the feature can follow
`query` and the watch's queryable arm the same gate. Not done here: the watch is an ABI door,
and what it answers in a build without `query` is a behaviour to decide first.

## 3. Features the shipped profile enables that the ABI does not reach

Resolved with `cargo tree -e features` for `os-posix,link-udp`: `wz-session-core` gets
`declare-queryable` (T12), `declare-interest` and `session-matching` (read by the publisher's
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
