# Windows lane (arch-win-ext): the DLL's growth, its link, and the extension doors

The Windows rows of `deploy/pico_host_ceiling.json` grade the read-only sections of the DLL (its
code, constants, unwind data and export table, `pico_windows_package.py` `pe_sizes`) against
zenoh-pico built in the same job. This note reads why those rows rose from the hosted reading of
2026-11-25 to that of 2026-11-27, what the link and code generation of the DLL still lack, and what
each extension door costs, and it states the steps that remove bytes, each landable alone. It
extends `docs/c-abi-architecture.md` (principles P1 to P12, layers L0 to L4, migration section 5),
`docs/c-abi-size-diet.md` and `docs/win-budget/size.md`; it changes none of them.

## 1. What of the migration has landed (read from `git log origin/main`)

| step of section 5 | state on main | what it means for the Windows DLL |
|---|---|---|
| 1 ledger gate | landed (`scripts/lib/size_ledger_gate.py`, `deploy/size_ledger.json`) | Linux only: the ledger reads ELF line tables; the Windows rows grade section sizes, no area |
| 2 totality lints | landed with a register (`scripts/lib/totality_debt_gate.py`) | same code on both hosts |
| 3 transport views | landed | same |
| 4 one table set | partly: the slot maps and the session's one table set (`session_tables.rs`, 2026-11-23), the region's lent tables (`bounded.rs` `TableLender`, `wz-capi-coop/src/arena.rs`, 2026-11-25); the engine's registry still holds its own tables | lane arch-l3-rows |
| 5 thin facade | not landed: `wz-capi-port` is still in the release graph (`cargo tree -p wz-capi-pico-lib` for the host-peer features) | lane arch-l4-facade |
| 6 thin driver | 6a partly (a session's region reserved with its arena, 2026-11-25); 6b to 6d open | lane arch-l0-driver |
| 7 SCE codegen totality | open | SCE |

## 2. The growth of 2026-11-25 to 2026-11-27, attributed

### 2.1 The readings

`pico-api-windows-x64` (the release profile without wz's doors, `LIKE_PROFILE = "host-peer"`), from
the job log of each completed Platform run between the two rows (`gh api
repos/{owner}/{repo}/actions/jobs/<job>/logs`, the lines `pico-api-windows-x64: text=`), with the
size gate's client on the same host:

| run | head | api x64 text | step | .text | .rdata | .pdata | client x64 text |
|---|---|---:|---:|---:|---:|---:|---:|
| 45556149010 | 20ee0c0a19 | 1,072,858 | | 949,848 | 100,666 | 22,344 | 309,972 |
| 45627233202 | 4f8c806a44 | 1,088,582 | +15,724 | 968,184 | 98,162 | 22,236 | 302,062 |
| 45654176033 | 65283e4307 | 1,092,586 | +4,004 | 972,888 | 97,522 | 22,176 | 302,378 |
| 45694985181 | a5c0c53c0b | 1,091,918 | -668 | | | | 302,098 |
| 45710597332 | cf6ca09636 | 1,093,518 | +1,600 | 973,816 | 97,538 | 22,164 | 302,370 |
| 45751782241 | b405504697 | 1,095,092 | +1,574 | 989,624 | 88,320 | 17,148 | 290,550 |
| 45798145732 | 72ce26dae9 | 1,095,108 | +16 | | | | 290,566 |
| 45855288322 | 9d2add546c | 1,078,344 | -16,764 | 974,904 | 86,256 | 17,184 | 285,646 |
| 45886271611 | 6879b6e18d | 1,098,061 | +19,717 | 995,009 | 85,304 | 17,748 | 287,929 |
| 45891778676 | f5a045229a | 1,097,725 | -336 | | | | 288,113 |
| 45903071476 | e96298f265 | 1,096,169 | -1,556 | | | | 287,513 |
| 45923879841 | 9136bec74d | 1,092,305 | -3,864 | 989,137 | 85,420 | 17,748 | 284,077 |

The x86 rows moved the same way (api x86 993,151 to 1,005,604, +12,453). The reference moved too:
zenoh-pico x64 409,384 to 408,138 and x86 317,739 to 317,011, since its DLL is linked by the same
`lld-link` as wz's (`1f209f47c7`, `fix(package): Link the Windows size reference with the DLL's
linker`). Of the x64 ratio's rise from 2.6207 to 2.6763, 0.0081 is that denominator and the rest is
wz's +19,447 bytes.

### 2.2 The intervals and what landed in them

| interval | x64 | what landed (first-parent landings; commits that touch `crates/*/src`) |
|---|---:|---|
| 20ee0c0a19..4f8c806a44 | +15,724 | the int-fix and int191 to int195 integrations (395 source commits): the fixed session's state in its region (`feat(capi-coop): Keep a fixed session's ... in its region`), the one-link and direct reads (`sz-direct`, `struct-*`), handing samples, queries and replies one row at a time from the read, the SCE pin `b616325c65` with its regenerated codecs |
| 4f8c806a44..cf6ca09636 | +4,936 | the int196 to int204 integrations (116 source commits): the clocks' and the sleep's one body, the lease and handshake bounds counted from the end of a millisecond, the size ledger's line-table ruler |
| cf6ca09636..b405504697 | +1,574 | the C library crate and the host engine: `058afaed50` (`Split the C library artifact from the ABI rlib`), `e5ccf14226` (`Name os-host as the pico base's engine feature`), `451e94b75c` (`Build the Windows pico DLL as the C library crate`): .text +15,808, .rdata -9,218, .pdata -5,016 (418 fewer unwound functions) |
| d3ce0c261b..9d2add546c | -16,764 | int206 and `b41ebe855e` (`Compile the cookie MAC's SHA-256 small on a host`): `sha2::sha256::compress256` 11,594 to 693 bytes in the release DLL; the table walks by stride (`c0f4cb0ffd`, `3cc981fc43`) |
| 9d2add546c..6879b6e18d | +19,717 | the direct read of every face (`23c219abbd` `Hold every face's send place for an operation`, `edfad95157` `Send a direct publish to each face on its own hold`, `284bcb7501` `Read every direct face after one wait`), whose operation body is the 22 copies of 2.3; the C runtime in the library (`1efd7e1f01`, `f5e2976475`: `wz-msvc-runtime` +5,025 bytes of functions, Visual Studio's startup bodies about -2,900), the group read of the multicast lane (`88710f3c2f` to `ba5926333f`: `group_drive::step_reading` 13,938, `HeldSession::build` 7,521 and `GroupPump::step` 6,180 new, `group_drive::step` 9,080 and `GroupTxStage::held_to` 4,786 gone), `df0fbc3340` (`Read a quiet face alone to its look's deadline`) |
| 6879b6e18d..9136bec74d | -5,756 | `43277507df`, `41a6aa071a` (one body for the endpoint texts and the lazy sample views), `e849cc60a6`, `997327ce1e` |

### 2.3 The release DLL by owner, function by function

No hosted run uploads the like-for-like DLL; the release DLL (host-peer and every door) is uploaded
with its PDB (`pico-windows-package-x64-single[-nostd]`). Its function bytes (each body once, by its
address, from `llvm-pdbutil dump --symbols`), run 45556149010 against run 45923879841: 3,705 bodies
of 1,428,408 bytes against 3,020 of 1,520,749; the read-only sections 1,649,918 against 1,703,725.

| owner (first path segment) | 11-25 | 11-27 | change |
|---|---:|---:|---:|
| wz_capi_coop | 198,742 | 302,552 | +103,810 |
| wz_capi_pico | 242,668 | 325,208 | +82,540 |
| wz_session_core | 352,199 | 312,724 | -39,475 |
| wz_session_mcu | 31,422 | 49,554 | +18,132 |
| core | 108,211 | 92,588 | -15,623 |
| wz_app_frame | 152,497 | 139,039 | -13,458 |
| sha2 | 12,836 | 693 | -12,143 |
| wz_app_schema | 59,320 | 47,389 | -11,931 |
| wz_codecs | 45,302 | 34,654 | -10,648 |
| wz_runtime_posix | 21,790 | 13,481 | -8,309 |
| sce_rust_runtime | 16,763 | 9,153 | -7,610 |
| wz_runtime_coop | 70,354 | 77,586 | +7,232 |
| wz_msvc_runtime | 0 | 5,025 | +5,025 |

685 fewer bodies with 92 KB more code: the engine's and the doors' bodies took in what the session
core, the codecs and `core` held as bodies of their own (fat LTO inlines across the crates), and two
generic bodies of the direct read multiplied: `wz_capi_coop::engine::direct::...::run` in 22 copies
(24,999 bytes, none on 11-25) and `wz_session_core::tx_buf::...::write_wire` in 20 (11,273).

### 2.4 Why the Linux case read the other way

1. The case differs. Layer C1cs's `pico-client-coop-nostd` is `os-host,link-udp`; the Windows
   like-for-like is host-peer: `scout, peer, multicast-transport, query, queryable, liveliness,
   liveliness-get, advanced, unstable-api, connectivity, multi-thread`. The groups' read, the peers'
   direct read and the query legs of those landings are in the second alone. The same window moved
   the Windows client the way it moved Linux: 309,972 to 284,077.
2. The ruler differs. The Linux ledger counts function bytes; the Windows row counts every read-only
   section, so each body adds its `.pdata` entry (12 bytes), its `.xdata` record and, on
   average, 7 bytes of `int3` before the next 16-byte boundary: a generic copy costs about 30 bytes
   more on Windows than in the ledger.
3. The denominator moved (2.1), and the C runtime is now the library's (2.2).

### 2.5 Commands for a symbol diff

From the hosted artifacts (any Linux host with `gh` and `llvm-pdbutil`; the release DLL and its PDB):

```sh
gh run download 45556149010 -n pico-windows-package-x64-single-nostd -D old
gh run download 45923879841 -n pico-windows-package-x64-single -D new
for s in old new; do
  (cd "$s" && unzip -q -o ./*.zip)
  llvm-pdbutil dump --symbols "$s"/*/release/bin/wz_capi_pico.pdb |
    awk -v q='`' '/S_[GL]PROC32/ { n = $0; sub("^[^" q "]*" q, "", n); sub(q "$", "", n); getline;
           if (match($0, /addr = [0-9a-f]+:[0-9a-f]+, code size = [0-9]+/)) {
             split(substr($0, RSTART, RLENGTH), a, /[ ,=]+/); print a[2] "\t" a[5] "\t" n } }' |
    sort -u -t "$(printf '\t')" -k1,1 > "$s.fns"
  awk -F '\t' '{ c = $3; sub(/^enum2\$</, "", c); sub(/[:<].*/, "", c); b[c] += $2 }
       END { for (k in b) print k "\t" b[k] }' "$s.fns" | sort -t "$(printf '\t')" -k1,1 > "$s.owners"
done
join -t "$(printf '\t')" -a1 -a2 -e 0 -o 0,1.2,2.2 old.owners new.owners |
  awk -F '\t' '{ print $3 - $2 "\t" $0 }' | sort -n
```

The like-for-like DLL of a commit, on pc3-win, from `crates/` (the line the `--size-features` step
runs, with its debug information on so the PDB names every body):

```sh
CARGO_PROFILE_CAPI_NOSTD_DEBUG=full cargo rustc -p wz-capi-pico-lib --lib \
  --target x86_64-pc-windows-msvc --no-default-features \
  --features abi/os-host,abi/link-udp,abi/scout,abi/peer,abi/multicast-transport,abi/query,abi/queryable,abi/liveliness,abi/liveliness-get,abi/advanced,abi/unstable-api,abi/connectivity,abi/multi-thread \
  --profile capi-nostd --config .cargo/capi-nostd.toml --target-dir target/api-x64 \
  -- -C link-arg=/Brepro -C link-arg=/PDBALTPATH:%_PDB%
llvm-pdbutil dump --symbols target/api-x64/x86_64-pc-windows-msvc/capi-nostd/deps/wz_capi_pico.pdb
```

A door's row is the same line with `,abi/<door>` appended to the features.

## 3. The link and the code generation of the DLL

What the linker was given is in the PDB (`S_ENVBLOCK` of the linker's module, run 45923879841):
`/OPT:REF,ICF /DLL /DEBUG /Brepro /NODEFAULTLIB`, linked by `rust-lld` as `lld-link`.

| setting | Linux (`capi-nostd`) | Windows | state |
|---|---|---|---|
| one program, one codegen unit | `lto = "fat"`, `codegen-units = 1` | same profile | held |
| speed of the per-sample code | `opt-level = 3`; the code run once (`wz-app-schema`, `wz-auth`, `wz-tls-pem`, `sha2`) at `"s"` | same profile | held |
| panic | `abort` | same | held |
| unused code and data removed, identical bodies folded | rustc's `--gc-sections`; identical bodies made aliases of one address (the ledger counts them once) | `/OPT:REF,ICF`, given by rustc (read from the PDB above) | held |
| debug information | line tables, measured with it taken off | full, in the PDB beside the DLL; no byte of it is in a graded section | held |
| unwind tables | dropped (`force-unwind-tables=no`, T7) | kept: x64 exception dispatch reads `.pdata`; the reference keeps its own | held (both sides) |
| relative relocations | packed (T6) | `.reloc` is discardable and not graded | not applicable |
| section and file alignment | not graded | the rows read each section's size in memory, not its aligned extent | not applicable |
| jump tables | LLVM's floor (the floor of 8 was taken back, `74968fff53`) | same | held |
| alignment of innermost loops | 16 bytes, padded with no-ops | 16 bytes; 18,867 bytes of no-ops of two bytes or more in the x64 release DLL (`llvm-objdump -d`, 2,399 of them) | **missing: step W1** |
| alignment of functions | 16 bytes, between bodies; not in the ledger, in the section | 16 bytes, 21,860 bytes of `int3` in the x64 release DLL | **missing: step W2** |

The 554 one-byte no-ops are the x64 rule that a call must not end in an epilogue; they stay.

## 4. The extension doors

### 4.1 What each door adds

Each row is host-peer with one door, against host-peer (`--size-features`, "adds +N bytes"):

| door | implies | x64 11-25 | x64 11-27 | x86 11-27 | x64 beyond what it implies |
|---|---|---:|---:|---:|---:|
| message-payload | message-catalog | 250,948 | 250,944 | 220,624 | 121,020 |
| replay-cache | query, queryable, remote-declaration-watch, e2e-receiver | 168,052 | 169,576 | 154,084 | about 76,000 |
| message-catalog | | 124,636 | 129,924 | 111,020 | 129,924 |
| instance-key | | 111,508 | 110,032 | 96,164 | 110,032 |
| e2e-sender | | 76,092 | 83,024 | 70,668 | 83,024 |
| e2e-sender-demux | e2e-receiver | 74,136 | 80,900 | 70,524 | 2,520 |
| e2e-receiver | | 73,468 | 78,380 | 67,776 | 78,380 |
| app-transport | | 61,852 | 67,880 | 65,860 | 67,880 |
| config-document | config-policy | 54,384 | 49,968 | 45,188 | 26,376 |
| device-requires | | 40,312 | 40,036 | 27,976 | 40,036 |
| shared-key-ids | | 23,436 | 26,664 | 24,088 | 26,664 |
| config-policy | | 28,696 | 23,592 | 24,492 | 23,592 |
| time-base | | (no row) | 21,244 | 20,848 | 21,244 |
| remote-declaration-watch | | 16,792 | 15,220 | 14,340 | 15,220 |
| e2e-supervision | | 9,444 | 13,892 | 13,288 | 13,892 |
| conformance-digest | | 176 | 128 | 124 | 128 |

The doors over `wz-app-frame` (e2e-sender, e2e-receiver, instance-key, message-catalog,
message-payload, replay-cache) each pay for the frame crate's common part again in their own row,
since each row is host-peer with that door alone. Of that crate's reach in the release DLL, the
largest parts that no sample's own work runs are its JSON reader of profiles (`wz_app_schema::e2e_profile`, 23,609 bytes, `Profile::from_tree` 8,498
of them), `alloc`'s ordered map (`alloc::collections`, 22,603 in the release DLL) and the
formatting machinery of refusals written as text (`core::fmt`, 9,393).

### 4.2 The layers that hold one fact twice, in these doors

| fact | held by | and again by |
|---|---|---|
| the reader of a payload's schema, run once when a schema is handed over | `wz-app-schema` (the `.proto` text reader), built for size | `wz-app-frame`'s `proto_descriptor` and `proto_decode::SchemaSet::from_descriptor_set` (39,635 bytes), built at `opt-level = 3` |
| the catalog's document, read once | `wz_app_schema::catalog_plan::CatalogPlan` (built for size) | `wz_app_frame::message_catalog::Catalog::parse`, at level 3, inlined into the door: `zext_message_catalog_new` is 15,951 bytes |
| each catalog message's key expression | `Catalog`'s `key_expr: String` | the door's `Held::keys: Vec<CString>` (`wz-capi-pico/src/message_catalog.rs`), a second copy made for C |
| a refusal | the reader's typed cause | the same cause written to a `String` with `format!` and handed to the door (`write_refusal(refusal, &why.to_string())`) |
| a replay publisher's ring and a subscriber's round | `wz-session-core` (`replay-cache`) | the door's `replay_publisher::Shared` and `replay_subscriber::State`, with `on_query` (5,787) and `on_reply_drop` (2,855) bodies of their own |
| the host's entropy | `wz_runtime_posix::windows::WindowsEntropy` (`BCryptGenRandom`) | the `getrandom` crate, in the doors (`wz-capi-pico/src/os/windows.rs`, `scout.rs`) and in the SCE runtime, which is why the library's build script writes import libraries for `bcrypt` and `advapi32` |

### 4.3 The largest three

- **message-payload** (121,020 bytes beyond the catalog). The schema reader of `FileDescriptorSet`
  is cold code built for speed; `Payload` and `Writer` (`wz_app_frame::message_payload`, 24,344) and
  the door's `set_at` (9,013) are the per-sample part. Design: the descriptor reader moves to
  `wz-app-schema` beside the text reader, both yielding the same `proto_types` tables, so the crate
  boundary is again the line between once and per sample (step D1); the door sets and reads values
  through one body per kind of value, a typed path resolved once into a field index the program
  keeps (step D4).
- **replay-cache** (about 76,000 bytes beyond what it implies). The door holds the replay state the
  session core already has a row for. Design: the publisher's ring and the subscriber's round are
  session-core rows reached by handle (P1, P7); the door answers a query and orders a reply by one
  call into the core; `PieceJoiner::join` (11,491) joins pieces in the place the round lends rather
  than into a `Vec` (step D5).
- **message-catalog** (129,924). Read once, yet its parse is level-3 code inlined into the door, its
  keys are kept twice and its refusals drag `core::fmt` and `alloc`'s ordered map in. Design: the
  catalog is `wz-app-schema`'s value, read once into tables sized by the limit the build states
  (`limits_with_messages`), each key stored once with its terminating NUL so the door lends a
  pointer into it (step D2); a refusal is a typed cause with the document path as offsets, written
  as text only by the door that hands it to C, through one writer (step D3).

## 5. Steps

Each lands alone; the bytes are estimates from the readings above unless marked measured.

| step | change | bytes (estimate) | receive Ir (about 3,073 per message) | held by |
|---|---|---|---|---|
| **W1 (landed here)** | no innermost loop aligned on x86 and x64 (`-x86-experimental-pref-innermost-loop-alignment=0`, `crates/.cargo/capi-nostd.toml`) | pico-client-coop-nostd ledger -1.3 to -2.7 KB (1.2% of text is loop padding); api x64 -6 to -12 KB; release x64 up to -18.9 KB | no-ops removed from loop entries: equal or lower, never higher; no call added | the cost gate's selftest (`config_rustflags` of the file per target, and the flag in the built case's flags); the ledger and the Windows rows read the bytes; the perf matrix reads Ir and cycles |
| W2 | functions at 2-byte boundaries (`-align-all-functions=1`) on x86 and x64 | api x64 -8 to -12 KB; release x64 about -19 KB; nothing in the ledger, which counts no padding | none: padding between bodies is never executed; cycles read on pc3-win and the Linux matrix before it lands | as W1 |
| D1 | the `FileDescriptorSet` reader into `wz-app-schema` | message-payload and instance-key rows -10 to -14 KB each | none (run once per schema) | `wz-app-frame`'s `proto_descriptor_tests` moved with it; the payload doors' tests |
| D2 | the catalog read by `wz-app-schema` into fixed tables, keys stored once | message-catalog -15 to -25 KB, every door implying it the same | none | `message_catalog_tests`; `wz-capi-pico`'s catalog door tests |
| D3 | refusals as typed causes, one text writer at the door | -6 to -10 KB in each `wz-app-frame` door that is the build's only user of `core::fmt` | none | the refusal tests of each reader, by cause and path |
| D4 | the payload's value doors through one body per kind, the path resolved once | message-payload -10 to -20 KB | per value set or read: lower (no path walk) | `message_payload_tests`, the door tests |
| D5 | replay state in the session core's rows; joins in the lent place | replay-cache -20 to -35 KB | none on a plain sample; a replayed one lower (no copy) | the replay round tests of the core and the door |
| E1 | one entropy body on Windows (`WindowsEntropy`) for wz's own callers | under 1 KB; the doors stop naming `getrandom` (the SCE runtime's remains an SCE item) | none | the scout and session id tests on Windows |

The generic copies of the direct read (`engine::direct::...::run` x22, `tx_buf::...::write_wire` x20)
are the engine's and the session core's send side, lane arch-engine-own; each copy costs the Windows
rows about 30 bytes beyond its body (2.4).

## 6. Verification of W1 (the main session's)

- Layer C1cs: `pico-client-coop-nostd`'s ledger total and every area at or under their rows; its
  multi-byte no-ops counted before and after (`objdump -d --no-show-raw-insn <lib> | grep -c
  'nop[wl]'`).
- The cost gate's selftest (`capability_cost_gate.py --selftest`).
- The perf matrix's arm W, receive Ir per message against the last reading (about 3,073): equal or
  lower.
- Platform's Windows package job: `pico-api-windows-*` and `pico-release-windows-*` read lower.
