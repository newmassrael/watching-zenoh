# Size: the language area, what each feature adds to it, and why

Status: an analysis and design note, with its first step carried in the same branch (L1). Nothing
here was built, run or measured by this lane: every byte figure is either **read** from the
documents named in section 1 or an **estimate**, labelled so, with its basis. It answers three
questions about the size ledger's `language` area, which the minimal case wins (wz 10,047 against
zenoh-pico's 45,028) and the like-for-like twin of the Windows release loses (76,244 against
59,485, 1.28 times): what each feature adds to it, which wz code pulls each share in and whether
the share is a promise (contract) or a form, and which structural steps take each share, with what
each is expected to read. `min-split.md` section 9.1 (F2) and the feature notes of
`docs/c-abi-migration/` (`feat-mcast.md`, `feat-peer.md`, `peer-proportion.md`,
`feat-query.md`) hold readings and steps this note relies on; it designs no step they carry.

## 1. The reading

- **The explain documents** (schema 5, pin `6a881c21dad1`) of the three cases the ledger holds,
  written in the verification worktree `vb-2` on 2026-11-28 between 01:19 and 01:20, the latest
  complete set: `explain-pico-client-coop-nostd.json`, `explain-pico-peer-coop.json` and
  `explain-pico-api-coop-nostd.json` under `crates/target/size-ledger/`. The language totals of
  `vb-16` (2026-11-27, 23:53 to 23:55) and `vb-4` (22:44 and 22:45) are the same to the byte.
- **The per-feature reports** (`size_ledger_gate.py --per-feature`, schema 1) of `vb-15`, written
  on 2026-11-27 at 15:17 (`pico-api-coop-nostd`) and 14:27 (`pico-peer-coop`). They are older
  than the explain documents: their last step reads language 93,595 where the explain reads
  76,244, and their peer step 36,126 against 27,179. Their figures are not today's; the order of
  the features by what each adds is what this note reads from them. A report from `origin/main`
  at `df994d7913` was being written when this note was; `vb-4` held only explain documents.

| case | features | wz | zenoh-pico | ratio |
|------|----------|---:|-----------:|------:|
| `pico-client-coop-nostd` | `os-host`, `link-udp` | 10,047 | 45,028 | 0.22 |
| `pico-peer-coop` | + `peer` (and the `scout` it brings) | 27,179 | 46,674 | 0.58 |
| `pico-api-coop-nostd` | the `host-peer` profile: zenoh-pico's default build with the advanced plane, the unstable API and connectivity | 76,244 | 59,485 | 1.28 |

The ledger's row of the client (17,953, 2026-11-26) is a reading of that day; today's is 10,047.

## 2. What the area holds

The area is not the language runtime alone. Its rules (`deploy/size_ledger.json`, `rules`) place
in it, on wz's side, the owners `core`, `core_arch`, `compiler_builtins`, `alloc`, `hashbrown`,
`foldhash`, `log`, `__rustc` and `portable_atomic`, **and** wz's own collections and text
utilities: `heapless`, `wz_session_core::bounded`, `wz_session_core::text_out` and
`sce_portable_bytes`; on zenoh-pico's side its collections (`src/collections`,
`include/zenoh-pico/collections`), its utilities (`src/utils`, `include/zenoh-pico/utils`), its
I/O buffers (`src/protocol/iobuf.c`), its configuration map (`src/protocol/config.c`) and the C
toolchain's out-of-line bodies. The two sides are counterparts: a collection is language support
whichever library writes it.

Two rules of the line reading decide what a byte of that kind costs here (`size_ledger_gate.py`,
"Who wrote a byte"):

- Rust's runtime (`core`, `alloc`) inlined into a function written outside it is that function's
  code, in that function's area. Only a runtime function left out of line stays in language.
- `heapless`, `bounded`, `text_out` and `portable_atomic` are not the runtime: their lines keep
  their file wherever they are inlined, so every inlined push, slice and length of a wz table is
  language, as every inlined function of zenoh-pico's collection headers is.

So the area grows with what a feature *stores*, much more than with what it calls in the runtime.

## 3. (1) What each feature adds

### 3.1 By feature (the per-feature report, 2026-11-27 15:17)

| step | wz added | zenoh-pico added | wz over zenoh-pico | wz added, every area | language's share |
|------|---------:|-----------------:|-------------------:|---------------------:|-----------------:|
| +scout | 16,953 | 1,422 | 15,531 | 54,024 | 31% |
| +peer | 9,408 | 224 | 9,184 | 100,584 | 9% |
| +multicast-transport | 18,141 | 396 | 17,745 | 164,426 | 11% |
| +query | 6,569 | 983 | 5,586 | 85,595 | 8% |
| +queryable | 3,040 | 611 | 2,429 | 61,716 | 5% |
| +liveliness | 3,556 | 2,001 | 1,555 | 38,063 | 9% |
| +liveliness-get | 1,823 | 0 | 1,823 | 8,730 | 21% |
| +advanced | 14,375 | 3,983 | 10,392 | 121,520 | 12% |
| +connectivity | 9,540 | 3,330 | 6,210 | 60,260 | 16% |
| +multi-thread | 425 | 1,507 | -1,082 | 26,613 | 2% |

The base row is the report's (9,765 then; 10,047 now). The five features that add most are the ones
that bring tables and text: scouting, the multicast transport, the advanced plane, connectivity and
the peer role. Multi-threading adds 425.

### 3.2 By the job of the body (the explain documents of section 1)

Each body's language bytes are classed by what the body is (appendix A gives the rule). "Inlined
into wz bodies" is the lines of `bounded`, `heapless`, `portable_atomic`, `text_out` and
`sce_portable_bytes` inlined into wz functions, with the runtime lines inlined into those.

| job of the body | client | peer | api | api - client |
|---|---:|---:|---:|---:|
| inlined into wz bodies | 8,339 | 12,668 | 38,986 | +30,647 |
| drop glue | 799 | 2,419 | 9,584 | +8,785 |
| text out (text_out) | 0 | 2,297 | 5,579 | +5,579 |
| growth (alloc::Vec) | 312 | 2,639 | 5,133 | +4,821 |
| float text (dec2flt) | 0 | 0 | 4,825 | +4,825 |
| address text in (core::net) | 0 | 2,352 | 3,288 | +3,288 |
| sort | 0 | 3,157 | 3,157 | +3,157 |
| text in (str) | 487 | 1,500 | 2,962 | +2,475 |
| Arc/Rc release | 92 | 120 | 1,391 | +1,299 |
| VecDeque | 0 | 0 | 971 | +971 |
| atomics (own body) | 0 | 0 | 341 | +341 |
| panic stubs | 18 | 27 | 27 | +9 |
| **total** | **10,047** | **27,179** | **76,244** | **+66,197** |

### 3.3 By owner

| owner (file) | client | peer | api | api - client |
|---|---:|---:|---:|---:|
| `wz_session_core::bounded` | 6,194 | 9,333 | 25,365 | +19,171 |
| `heapless::vec` | 1,422 | 1,813 | 10,736 | +9,314 |
| `wz_session_core::text_out` | 0 | 2,388 | 7,202 | +7,202 |
| `core::ptr` | 646 | 3,168 | 6,592 | +5,946 |
| `alloc::raw_vec` | 326 | 1,601 | 3,685 | +3,359 |
| `core::net::parser` | 0 | 1,620 | 2,119 | +2,119 |
| `core::num::imp::dec2flt::decimal_seq` | 0 | 0 | 1,866 | +1,866 |
| `portable_atomic::imp::core_atomic` | 361 | 610 | 1,521 | +1,160 |
| `heapless::string` | 235 | 303 | 1,222 | +987 |
| `core::num::imp::dec2flt::parse` | 0 | 0 | 822 | +822 |
| `alloc::sync` | 55 | 90 | 747 | +692 |
| `core::result` | 0 | 325 | 680 | +680 |
| `core::cmp` | 0 | 402 | 678 | +678 |
| `core::num::uint_macros` | 31 | 194 | 632 | +601 |
| `core::slice` | 0 | 322 | 599 | +599 |
| `core::num::imp::dec2flt::slow` | 0 | 0 | 458 | +458 |
| `alloc::rc` | 0 | 0 | 430 | +430 |
| `core::slice::memchr` | 0 | 0 | 416 | +416 |
| `core::ops::function` | 44 | 52 | 439 | +395 |
| `core::ptr::non_null` | 8 | 59 | 400 | +392 |
| `core::num::imp::dec2flt::lemire` | 0 | 0 | 358 | +358 |
| `portable_atomic` | 30 | 32 | 379 | +349 |
| `sce_portable_bytes` | 0 | 381 | 343 | +343 |
| `core::slice::sort::shared::smallsort` | 0 | 337 | 337 | +337 |
| the other 93 owners | 695 | 4,149 | 8,218 | +7,523 |

### 3.4 zenoh-pico's side

| zenoh-pico file | client | peer | api | api - client |
|---|---:|---:|---:|---:|
| `include/zenoh-pico/collections/slice.h` | 3,565 | 3,592 | 6,057 | +2,492 |
| `include/zenoh-pico/collections/intmap.h` | 1,201 | 1,327 | 3,268 | +2,067 |
| `src/protocol/iobuf.c` | 3,195 | 3,195 | 3,195 | 0 |
| `src/collections/bytes.c` | 3,125 | 3,125 | 3,125 | 0 |
| `src/collections/advanced_cache.c` | 0 | 0 | 2,576 | +2,576 |
| `src/collections/list.c` | 2,525 | 2,525 | 2,525 | 0 |
| `include/zenoh-pico/collections/internal/hashmap_template_internal.h` | 2,811 | 2,811 | 2,460 | -351 |
| `src/utils/time_range.c` | 2,369 | 2,369 | 2,369 | 0 |
| `src/collections/string.c` | 1,899 | 1,899 | 1,899 | 0 |
| `src/collections/vec.c` | 1,867 | 1,867 | 1,867 | 0 |
| `include/zenoh-pico/collections/string.h` | 1,317 | 1,676 | 1,768 | +451 |
| `src/protocol/config.c` | 1,641 | 1,641 | 1,641 | 0 |
| the other 53 files | 19,513 | 20,647 | 26,735 | +7,222 |

zenoh-pico's language is flat because its collections are written once, type-erased (`void *`
elements, with each element type's copy, clear and compare functions handed in by
`_Z_ELEM_DEFINE`), and its shared library compiles and keeps all of them whatever the build uses:
the minimal build already carries its sorted map, LRU cache, rings, FIFOs, hash maps and time
ranges. What it adds with the features is the header-inline code of more element types
(`slice.h`, `intmap.h`, `refcount.h`) and the advanced cache (`advanced_cache.c`, 2,576). wz's
minimal case wins by 35 KB because it links only the copies it instantiates; its twin loses
because every table type a feature brings is a copy of its own.

## 4. (2) Where each share comes from, and contract or form

### 4.1 What the area does not hold

- **The panic machinery: 27 bytes.** `core::panicking::panic_bounds_check`,
  `panic_nounwind_fmt` and `core::slice::index::slice_index_fail`, nine bytes each, the abort the
  `capi-nostd` profile makes of every panic. The totality register (`docs/c-abi-architecture.md`
  section 7) holds no row, and the one panic no lint names (`BoundedVec::remove`'s `assert!`) is
  a branch to those stubs where it is inlined. P6 has nothing left to take out of this area; what a
  bounds check still costs is a branch in its caller, counted in the caller's area.
- **Formatting: 0 bytes.** No body of `core::fmt` is in the library (no `Formatter`,
  `pad_integral` or `fmt::write`): the doors and the scouting window write text through
  `text_out` (`refactor(runtime-posix): Pin a scout's ask socket without core::fmt`). The six
  `<FixedText<N> as core::fmt::Write>::write_str` bodies (811) are `text_out`'s own sink.
- **`memcpy` and its kin: 0 bytes.** Both libraries call the C library's, which is outside the text
  of either; `compiler_builtins` places nothing.

The 1.28 is therefore not the runtime the earlier reading named (the standard library, panics,
formatting): it is collections, and a handful of runtime routines one call each pulls in.

### 4.2 The shares

Bytes are the api twin's (`pico-api-coop-nostd`), by body (section 3.2) or by owner (3.3).

| share | bytes | pulled in by | the feature | contract or form |
|-------|------:|--------------|-------------|------------------|
| `bounded` inlined | 25,365 (owner; client 6,194) | every table of the session's storage policy (`Storage::Seq`, `Rows`): the open's lay-out (`RegistryOf::new` 1,012, `lend_session` 998, `lend_set` 757, `assemble` 558 of its 238 bodies), the tables' drops (`drop_row` in 17 copies, 1,137) and each push, length and slice where the engine uses a table | every feature that keeps a table | **mixed**: that a table is bounded and lent at the open is the promise (P3, D12; `min-split.md` C1); that each row type has its own copy of the code is form (P5, "a non-generic core plus thin typed wrappers", not yet applied to the sequences) |
| `heapless` inlined | 11,958 (owner; client 1,657) | `heapless::Vec<T, N>` and `String<N>` held directly in engine rows: `MemberRecords::record` 1,738 (the multicast dispatch), `FaceLinkRow`'s `clone` 661 and `of_group_member` 1,119, the advanced subscriber's rows | multicast, advanced, connectivity | **form**: one copy for each `(T, N)`, and a row of them cloned field by field |
| drop glue | 9,584 (client 799) | rows that hold `Vec`, `Rc`, `Arc` or `Box`: `EngineSubscriber` 948, `SessionTables` 614, `PortPeer` 563, `GroupFace` 559, `AdvancedPublisherOn` 545, 68 more | advanced, multicast, peer, scout | **form**: a region's rows own no allocation (P3) and need none; the glue is the alloc types' |
| `alloc::Vec` growth | 5,133 (client 312) | `RawVec<T>::grow_one` for 24 element types (99 each): the group's `GroupFace`, `GroupPump`, `Announced`, `StagedMessage`, `MemberDeclarations`, `OwedKeyexprs`, `(UdpGroup, u16)`; scouting's `ScoutedHello`, `ScoutMember`, `ScoutRxIgnored` and the interface table's `InterfaceRow` and `IpAddr`; the advanced plane's `CachedSample`, `RecoveryRequest`; the listeners, the task store, the thread ids; nine `finish_grow` and seven `do_reserve_and_handle` copies; a `try_process` collect of an extension chain 493 | multicast, scout, advanced, peer, multi-thread | **form, or a breach**: under D12 (the release) a growth after the open is what the contract refuses; under on-use (the zenoh-pico preset, `docs/c-abi-migration/heap-native.md` section 6.1) it is 24 copies of what `on_use::take_rows` does once for every row type |
| text out | 5,579 (client 0) | `text_out`: `push_socket_addr` for `String` 1,061 and `FixedText<64>` 521, `push_ipv4` in three copies 1,218, `write_str` in six 811, `ipv6_text` 1,608 (already one body) | the engine's link rows (`CoopEngine::drive_link` 1,008, `FaceLinkRow::of_group_member`: a link's ends as text, which connectivity hands out), scout (`#iface=`), advanced (`recovery_key`, `seconds_text`, `history_key`) | **behaviour, in a larger form**: zenoh-pico writes the same text; the copies for each sink are form |
| float text | 4,825 (client 0) | `<f64 as FromStr>::from_str` 3,287 and `dec2flt`'s slow path: the `_time` parameter's durations (`wz_session_core::time_range::parse_duration`), which the advanced cache reads to answer a query (`wz_ext_pubsub::advanced_cache`, through `time_range::parse`) | advanced | **contract**: a duration is upstream's `f64` reading of the text (`time_range.rs`, "Grammar"). zenoh-pico reads it with the C library's `strtod` (`src/utils/time_range.c`), outside its text on a host and inside it on an MCU image: an asymmetry of the reading, not a share zenoh-pico does without |
| address text in | 3,288 (client 0) | `core::net`'s parser: `group_locator::parse_group_locator` (the group and `#bind=` by `SocketAddr::from_str`, `#join=` by `IpAddr::from_str`), `scouting_host` (a Hello's locator, `rest.parse::<SocketAddr>()`), `wz_runtime_posix::multicast` (`#iface=` as `Ipv4Addr`, `Ipv6Addr`, `IpAddr`; the scouting window pins each ask socket by its address written as that text, which this reads back) | multicast, scout | **form**: a second reader of a grammar the library already reads with `wz_runtime_coop::locator_text`, written to keep `core::net`'s reader out and held to its answers by `the_ipv4_reader_reads_what_core_reads` and `the_ipv6_reader_reads_what_core_reads` (P1, one owner of a fact, applied to code) |
| sort | 3,157 (client 0) | `quicksort::<usize>` 2,545, `ipnsort` 301, `median3_rec` 167, `heapsort` 144: one `[usize]::sort_unstable`, in `wz_runtime_posix::scouting::ScoutMembers::drain` (the places of the members whose read failed, put in order to remove them back to front) | scout | **form**: no answer needs the order; L1 |
| text in | 2,962 (client 487) | `from_utf8` 487 (a C text read as `&str`, checked once, `min-split.md` 9.1); `str::trim`'s Unicode whitespace 619 (`wz_capi_pico::scout`, a scout config value); `String::from_utf8_lossy`'s decoder 394 (interface names, `wz_runtime_posix::interfaces`; an encoding's text, `encoding_hint::hint_to_string_in`); `CharSearcher` 709, `split_once` 149, `u32::from_ascii_radix` 412 (the grammars' readers) | scout, multicast, the encoding doors | **contract** for `from_utf8`; **form** for the Unicode trim and the lossy decoder; the readers' searches stay |
| `Arc` and `Rc` | 1,391 (client 92) | `drop_slow` in 15 copies: the group stage's `Rc<Inner>`, the advanced cache's `Arc<Mutex<Ring>>`, `Arc<PicoPlane>`, the multicast reply sink's `Rc<RefCell<..>>` | advanced, multicast | **form**: no reference counting inside a session (P3); `feat-mcast.md` F8b for the stage |
| `VecDeque` | 971 (client 0) | the reply queue `VecDeque<(u64, InboundReply)>` 657, the advanced cache 163, the group stage 151 | query, advanced, multicast | **form**, as growth |
| atomics | 1,900 (owner; client 391) | native read-modify-writes inlined in the engine (`min-split.md` F2) | every build that calls doors from several threads | **contract** (C4, the host's lock), set down only by the owner's ruling F2 asks for |
| panic | 27 | section 4.1 | none | **contract** (P6), nothing to take |

Summed: of the twin's 76,244, at least 10,600 is contract (float text 4,825, atomics 1,900, the
UTF-8 check 487 and the panic stubs 27, 7,239 named, and `bounded`'s open-time lay-out, of which
the four bodies named hold 3,325 and the rest is unread), and the rest form, most of it the copies
of collection code for each row type.

### 4.3 Why the copies grow with the features

A feature brings rows: a group brings its faces, pumps, stage and member records; scouting its
members and hellos; the advanced plane its cache and recovery requests; connectivity its link
texts. In wz each row type is a type parameter: `LentSeq<T>`, `BoundedVec<T, N, P>`,
`heapless::Vec<T, N>`, `Vec<T>`, `VecDeque<T>`, `Rc<T>`, each instantiated for it, and fat LTO
inlines the instance into each caller. `bounded` already writes the operations that are no part of
a read as one body over bytes (`drop_rows`, `place_seqs`, the lent push), which is why the client
pays 6,194 for it; the rest of its operations, `heapless` and every `alloc` collection a feature
holds outside the storage policy are still one copy per type. zenoh-pico pays its general form once
and a few small element functions per type. The growth is therefore not a cost of the features'
behaviour: it is the form of their storage.

## 5. (3) The steps

Each is a structural step, not a diet: what it changes is where a job's code lives. Bytes are the
api twin's language area unless the column says otherwise; "receive Ir" is the instructions a
received message costs in the cells of `ir-receive.md` and `ir-multicast.md`.

| step | what | expected bytes (estimate, basis) | receive Ir | the test that turns red | order |
|------|------|-----------------------------------|-----------|-------------------------|-------|
| **L1 (this branch)** | The scouting window's drain marks a member whose read failed where it lies (`ScoutMember::lost`) and drops the marked ones in one `retain` as it ends, so the members keep their order and no list of places is sorted | -3,157 in `pico-peer-coop` and the twin (the four sort bodies, read in both), and up to -99 in the peer case (`RawVec<usize>::grow_one`, whose callers there other than the drain's list are unread); `Vec::retain` replaces `Vec::remove` in `window_hellos` (driver area, 0 to +200). Client: 0, it has no scouting | 0: the window's reads are no session's receive | `scouting::tests::a_member_whose_read_fails_is_dropped_and_the_rest_keep_their_order`: red if a lost member stays, a live one goes or the order moves (a removal by swap) | first: one file, no contract |
| L2 | One reader of address text: `locator_text`'s readers (`socket_addr_v4`, `socket_addr_v6`, `ipv6_address`, `ipv4_address`) move down into `wz-session-core` beside `locator_grammar`, the grammar both crates share, with an `IpAddr` reader; `locator_text`, `group_locator`, `scouting_host` and `wz_runtime_posix::multicast` read through them. A socket's interface is handed to the socket layer as the address or name it was read as, not as text read again, so the scouting window's ask sockets write and read no address text | -2,300 to -3,300 in the twin, -1,800 to -2,350 in the peer case (`core::net`'s eight bodies, 3,288 and 2,352, less the bare-address entry the moved reader gains); client 0 | 0: endpoints are read at the open and in a Hello | the two differential tests move with the readers and gain an `IpAddr` and a bare `Ipv6Addr` case; `group_locator`'s, `scouting_host`'s and the `#iface=` tests hold the callers | after L1; files of `wz-session-core`, `wz-runtime-coop`, `wz-runtime-posix` |
| L3 | The text sink as a core and a wrapper: one out-of-line composer writes an address with its port into a buffer of `SOCKET_ADDR_TEXT_LEN` (the form `ipv6_text`, `decimal` and `hexadecimal` have), the trait's `push_ip` and `push_socket_addr` push its text once, and `FixedText<N>` writes through one body over its bytes, length and count, `N` left to the storage | -2,500 to -3,000 in the twin (of `push_socket_addr` 1,582, `push_ipv4` 1,218 and `write_str` 811, one composer of 500 to 700 and one write of about 150 stay), -1,000 to -1,500 in the peer case | 0: text is written at a link's events, a scout and a door's call | `text_out`'s tests (each writer equal to `Display`), `an_ask_socket_is_pinned_by_the_text_of_its_address`, the connectivity doors' tests of a link's text | independent; `wz_session_core::text_out` alone |
| L4 | The feature planes' rows under the session's storage policy: the 24 grown element types, the three `VecDeque`s and the `Rc` and `Arc` cells of section 4.2 become `Storage::Seq` and `Rows` tables and `Placed` values, so the release lends them at the open (D12) and the on-use preset takes each in `on_use`'s one body. `feat-mcast.md` F8b carries the group stage's part, `docs/c-abi-migration/sz-open.md` O9 the open's heap cells | -5,000 to -9,000: growth 5,133, `VecDeque` 971, `Arc` and `Rc` 1,391 and the alloc types' share of the drop glue (3,000 to 5,000 of 9,584) go, less the copies of `bounded`'s code the new tables bring before L5 (3,000 to 5,000) | expected 0 or lower: a lent push has no growth branch; the multicast and advanced cells read it | the no-heap gate (`HEAP_ABORT` of `capability_cost_gate.py`, `deploy/no_heap_ratchet.json`), `heap-native.md`'s tests, F8b's stage tests, each plane's own | by plane, each with its feature note's lane |
| L5 | The sequences as one untyped core (P5): `bounded`'s remaining operations that are no read (push past the lent one, insert, remove, retain, truncate, clear) one body each over `(base, len, room, size, align)` and a drop function where the type has drop glue, `LentSeq<T>` and `BoundedVec<T, N, P>` thin typed wrappers, and the engine's `heapless` rows moved onto the same core (`Storage::Scratch` and the rows held directly), as `text.md` S2 did for the slot map (`RawSlots`). A row of fixed text and fixed lists is `Copy`, so a clone is a copy | -5,000 to -12,000 in the twin, -1,000 to -3,000 in the peer case, -500 to -1,500 in the client (unread: which operations hold `bounded`'s 25,365 is not in the report, whose owners name bodies and not lines; its first measurement is a symbol diff of one table type moved) | at risk: a read stays typed and inline; a push or a removal a received message reaches (`MemberRecords::record`, a reply's queue) becomes a call with a size; every Ir cell reads it, and an operation on a message's receive stays typed where it moves the cell (C4) | `bounded`'s tests, the arena and region tests, the slot map's, the Ir cells | after L4, so the tables L4 brings are written once |
| L6 | Float text: the owner's ruling. (a) keep `core`'s reader, the contract as it is; (b) read a duration as an exact decimal into whole nanoseconds: the same instant as upstream's `f64` to within a nanosecond, and another one at a range's edge where the two round apart, which the ruling accepts or not; (c) the platform's `strtod`, as zenoh-pico does, refused here because its decimal point is the C locale's, so a program's `setlocale` would change what a selector means | (a) 0; (b) -4,300 to -4,800; (c) -4,825 on a host, 0 on an MCU image, whose C library is linked | (b) lower on a query that carries `_time` | `time_range`'s tests against upstream's answers; (b) adds the texts whose reading moves | the owner's |
| L7 | Text routines a grammar does not need: the scout config's values trimmed as ASCII (`str::trim_ascii`, the trim `config_limits` already makes), and an interface's name kept as bytes where it is compared or handed back to the system, not decoded lossily into a `String` | -600 to -1,000 (the Unicode trim 619 with its table; the lossy decoder 394 goes only if its other caller, `encoding_hint::hint_to_string_in`, keeps bytes too) | 0 | `wz_capi_pico::scout`'s config tests, `interfaces`' tests, the encoding doors' tests | unread first: what zenoh-pico's scout reader does with whitespace in a value |
| L8 | Atomics: `min-split.md` F2, the owner's ruling on the case's threads | up to -1,900 | 0 to lower | `one_thread` tests | the owner's |

## 6. What remains, and whether the area can win

Read on the twin's 76,244 against zenoh-pico's 59,485:

- L1 to L4 and L7 (form only, no contract touched): -13,600 to -19,500, to 56,800 to 62,700,
  0.95 to 1.05 of zenoh-pico.
- With L5: -18,600 to -31,500, to 44,800 to 57,700, 0.75 to 0.97.
- With the owner's (b) of L6: 4,300 to 4,800 less again.

So the area reaches parity with the form steps that need no ruling, and wins only with L5. That
is an estimate: "wins" is said of a reading, not of this note. What stays after every step is the
contract of section 4.2 (at least 10,600, less what the owner's rulings of L6 and L8 set down) and
one copy of the collections' core, which zenoh-pico pays too.

## 7. Measurement cells

- After each step: `size_ledger_gate.py --explain` of the three cases (the language bytes, the
  bodies the step names gone, the driver area's bytes for L1), and the rows `--measure` prints
  tighter, which the main session commits.
- After L2, L4 and L5: `--per-feature` of the twin's chain, to read each feature's language
  column again; this note's section 3.1 is a reading of an older tree.
- L4 and L5: the receive Ir cells of `ir-receive.md` and `ir-multicast.md` on the twin's build,
  before and after, each step on its own.
- L5's first measurement, before any design is fixed: one table type moved onto the core and the
  symbol diff (`nm -C -S`) of the library, which says what one type's copies are.

## Appendix A. How a body was classed

A body of the area is classed by its name, first rule that matches: `core::ptr::drop_glue` or
`drop_in_place`: drop glue; `drop_slow`: `Arc` and `Rc`; `alloc::raw_vec`, `__rust_alloc`,
`alloc::alloc`, `alloc::vec`, `spec_from_iter`, `try_process`: growth; `dec2flt` or
`<f64 as FromStr>`: float text; `core::net::` or the address types' `FromStr`: address text in;
`slice::sort`: sort; `text_out`, `write_str` of `fmt::Write`, `push_socket_addr`, `push_ipv4`,
`ipv6_text`: text out; `from_utf8`, `Utf8Chunks`, `trim_matches`, `CharSearcher`, `split_once`,
`from_ascii_radix`, `str::pattern`, `memchr`: text in; `VecDeque`; `panicking`,
`slice_index_fail`, `capacity_overflow`: panic; `portable_atomic` or `core::sync::atomic`:
atomics. Any other body is a wz function, and its language bytes are the collection and atomic
lines inlined into it. The classes sum to the area's total in each case.
