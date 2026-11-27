# Feature lane conn-scout: what `connectivity` and `scout` cost, and which part of it is form

Status: design of the lane, with its first steps committed beside it (section 7). Nothing here was
built, run or measured by this lane. Every byte figure is either **read** from the documents named
in section 1 or an **estimate**, labelled so, with its basis. No explain document of the cases was
on this machine when the note was written, so the pairing below is read from the code of both
libraries against the owner and body figures those documents left, and each step names what its
measurement is to read.

## 1. The reading

- The per-feature report of `pico-api-coop-nostd` (2026-11-27, read through
  `docs/c-abi-migration/peer-rows.md` section 8.3 and `docs/win-budget/lang-rt.md` section 3.1):
  `scout` adds 54,024 against zenoh-pico's 4,850, of which language 16,953 against 1,422;
  `connectivity` adds 60,260 against 17,378, of which language 9,540 against 3,330.
- The peer case's scout step (`docs/c-abi-migration/peer-proportion.md` section 2, group G0):
  33,472 against 4,850. Owners: `scouting_host` 5,978, `capi_pico::scout` 4,802,
  `runtime_posix::interfaces` 4,094, `runtime_posix::multicast` 3,864, `text_out` 2,388,
  `runtime_posix::scouting` 1,984, `core::net::parser` 1,620, `scouting_message` 1,597. Bodies:
  `scout::window_hellos` 14,427, `z_scout` 3,148, `z_hello_clone` 1,752, `ipv6_text` 1,608.
  zenoh-pico: `_z_scout_inner` +2,970 (its static helpers inlined), `z_scout` 533,
  `_z_scout_process_hello` 380.
- `lang-rt.md` L1 (the drain's sort) is landed: 3,157 of the step's language left with it.

`window_hellos` is one body because fat LTO inlines into it everything a window reaches that has
no other caller in the peer case: the interface table, the multicast socket layer, the text the
ask sockets were pinned by and its reader, the window machine's host and both of its record forms.
Its 14,427 is therefore read by the owners above, not by its own lines.

## 2. The scout, paired

| work | zenoh-pico | wz | kind |
|------|------------|----|------|
| which interfaces a window asks on | `_z_scout_init_links` walks `getifaddrs` with `_z_udp_unicast_interface_iterator_next` (`src/link/transport/udp/udp_posix.c`), every UP interface of the locator's family once by name (`_z_udp_posix_iface_was_visited`) | `interfaces::InterfaceTable::read` copied every entry into an owned row (`String` by `from_utf8_lossy`, `if_nametoindex` per name, a `Vec` grown per row), then `multicast_interface_addresses` kept a `Vec<&str>` of names | **form**: the same walk; the owned table is a second copy of the list (SC3, done) |
| the ask sockets | `_z_scout_open_link`: a UDP unicast link per interface, opened with the interface's name as the endpoint's `iface` | `ScoutMembers::open` wrote each address as `#iface=` text (`text_out`, `ipv6_text` 1,608), and `bind_sender` read it back (`core::net`'s IPv4 and IPv6 readers), resolved it as a locator key (the name arm's table reads, the IPv6 arm's index lookups, `fill_unspecified`'s fallbacks) | **form**: the address is known; the text and the key resolution are a round trip (SC1, done) |
| the group socket | none: a scout reads on its per-interface links alone (`src/session/scout.c` @ `_z_scout_read`) | `bind_joined(.., RxBind::Group)`: a socket joined to the group, a receive member beside the ask sockets, and the asker of last resort when no interface could be asked on | **contract** (row K1 of section 5) |
| sending the Scout | `_z_scout_send`: encode into a 32-byte `_z_wbuf_t`, send on every link, sent when one link sent | `ScoutMembers::send` over the frame the window machine staged (`ScoutFrame`) | same work |
| reading Hellos | `_z_scout_read`: one wait over the links (`_z_socket_wait_readable` with a ready mask), `_z_scout_recv` decodes into `_z_hello_t` on the heap | `ScoutMembers::drain` and `wait` (a `Vec<&S>` collected per wait), the machine's `window_datagram`, a `HelloRow` decoded in place | same work; the per-wait `Vec` and the member list's growth are form (SC5) |
| the window machine | a `while` over `z_clock_elapsed_ms` | the generated scouting statechart, pumped by `ScoutWindow` | **form in a larger structure**: one machine for both engines (the SCE rule, not stepped here) |
| recording a Hello | `_z_hello_slist_push_empty`, locators copied onto the heap | `ScoutingActions` holds BOTH record forms and picks one at run time by `lent: Option<LentTable>`: the lent table (the C ABI's) and the heap collection (`Vec<ScoutedHello>`, `Option<String>`, `Vec<ScoutRxIgnored>`, the tokio engine's); the window holds its state `Shared` behind an `Arc` or `Held` in its place, also picked at run time | **form**: two record forms and two holdings linked where one is used (SC2) |
| the datagrams a window did not take | `_Z_ERROR` on a failed decode, `_Z_ERR_MESSAGE_UNEXPECTED` on another MID | `classify_ignored_scout_rx` (self echo, another node's Scout, a locator-less Hello, an unknown MID, undecodable), counted (`IgnoredCounts`) and logged by verdict | **contract** (row K2) |
| the C door | `z_scout` 533: reads the config's `what`, `zid`, `timeout` and multicast locator, calls `_z_scout` | `z_scout` 3,148: the same reads, the scout config's values trimmed (`str::trim`, Unicode), the locator by `parse_multicast_locator` (`SocketAddr::from_str`), the claim of the process's table | the Unicode trim and the second address reader are **form** (SC4, SC6); the claim is the no-heap contract (the table is static, so two threads share it) |
| an owned hello | `z_hello_clone` copies `_z_hello_t` | `z_hello_clone` 1,752: a `Box<HelloState>` with a boxed `StringArrayState` of `String`s | **form** of the same copy (SC7) |

What peer-rows.md section 8.3 called the interface enumeration's **behaviour** is not one: zenoh-pico
enumerates the host's interfaces too on POSIX and lwIP (`include/zenoh-pico/link/transport/udp_unicast.h`
defines `ZP_PLATFORM_HAS_UDP_INTERFACE_ITERATOR` for both). What differs is the rule: zenoh-pico
takes every UP interface of the family and pins its link by name, wz takes the first IPv4 address of
every interface that is up, running and `IFF_MULTICAST`. Both are one walk; the rule's difference
costs no code.

## 3. Connectivity, paired

zenoh-pico's plane is `src/api/connectivity.c` (799 lines) and the info doors of `src/api/api.c`;
wz's is `crates/wz-capi-pico/src/connectivity.rs` over the engine's face rows
(`wz_session_core::face::FaceLinkRow`, `wz_capi_port::told`).

| work | zenoh-pico | wz | kind |
|------|------------|----|------|
| a transport and a link as values | `_z_info_transport_from_peer` (api.c), `_z_info_link_t` with two `_z_string_t` copied from the peer's endpoints | `transport_of_row`, `link_of_row`: the row's `src` and `dst` (`RowText`, written by the engine with `push_socket_addr` when the link is placed) copied again into a leaked `Box<[u8]>` each (`ConnText::new`) | **form**: a link's ends are written as text in the engine and copied at the door (CN1) |
| a group member's link | `_z_endpoint_to_string` of the group's endpoint, once per member (`src/transport/multicast/rx.c`) | `pico_group_endpoint_text`: the group's endpoint read again with `PicoEndpoint::read` and written into a `String` at every row handed out | **form**: the text is the group's, fixed when it is joined (CN2) |
| the info walks | `z_info_transports`, `z_info_links` walk the peers under the session's lock | `rows`: `face_link_at` row by row, no lock held between two rows | same work |
| listeners: declare, undeclare, the table | `z_declare_transport_events_listener` and its link twin: a callback in the session's list, removed under its lock | `Table<S, N>`, `Entry<S>`, `next_in`, `take_in`, `admit`, `end_replay`, `retire_entry`, `Delivery<E>`, each written once and instantiated for the transport listener and again for the link listener | **form**: two copies of one table (CN3) |
| dispatching an arrival and a departure | `_z_connectivity_peer_connected` and `_disconnected` dispatch to every listener from the task that saw the peer: `_z_connectivity_dispatch_transport_event` clones the listener map under the session's lock, lets it go and calls each closure outside it | one hub per session handed rows by the engine's face watch through a queue of `MAX_FACE_WATCH_ROWS`, delivered outside every lock | same work, outside every lock in both (section 5 corrects the first reading); the queue is form (CN4) |
| history | `_z_connectivity_replay_transport_history` replays under the transport's peer lock, before the listener is inserted, so no arrival interleaves | the replay runs outside the lock; what arrives meanwhile waits in `Pending<E>` (`MAX_CONNECTIVITY_REPLAY_EVENTS`), folded by row | **contract** (row K3): the queue exists because the replay holds no lock |
| a row the queue lost | none: nothing is queued, nothing is lost | `Told`, `converge_transports`, `converge_links`: the rows told kept (`MAX_CONNECTIVITY_TOLD_ROWS`) and the listener brought to the faces as they stand after a loss | **form**: the loss exists because the hand-out is queued; delivering as the face changes (CN4) removes the queue, the loss and the reconciliation |
| what a link of a kind zenoh-pico lacks reports | none | the registry's answers (QUIC, unixpipe, vsock, unix sockets) | wz's link kinds; no code of the plane's own |

## 4. Steps

Each step leaves the bytes and the receive instructions of the minimal case
`pico-client-coop-nostd` unchanged: it links neither `scout` nor `connectivity`, and no step
below touches a path a received message takes. Estimates are the peer case's for the scout and the
twin's (`pico-api-coop-nostd`) for connectivity; each names its basis.

| step | what changes | estimate | the test that turns red |
|------|--------------|---------:|-------------------------|
| SC1 | A window's sockets made from plans it states: the group socket from the plan of no key (`bind_scout_group`), each ask socket from a plan pinned to its address (`bind_scout_asker`), the address typed `Ipv4Addr` as the interface table reads it. No `#iface=` text is written or read, no locator key resolved | -4,500 to -7,500 (most of `text_out` 2,388 and the IPv4 and IPv6 readers of `core::net::parser` 1,620, the key resolution of `multicast` 3,864 and the table questions of `interfaces` 4,094 that only `#iface=` asks; `parse_multicast_locator`'s `SocketAddr` reader stays) | `multicast::tests::a_scouting_asker_is_bound_to_its_address_and_leaves_by_it` (red if the asker binds the wildcard, leaves by another interface, sets an option the pinned sender does not, or is made for an IPv6 group), `a_scouting_group_plan_is_a_plan_of_no_key`, `scouting::tests::an_ask_socket_is_bound_to_the_address_it_is_handed` |
| SC3 | The window's question walks `getifaddrs`' list where the system holds it (`HostList`, `HostEntries`) and copies no row; an entry is taken when no earlier entry of its interface was, asked of the entries (zenoh-pico's `_z_udp_posix_iface_was_visited`); the owned table reads through the same walk | -1,200 to -1,800 (`from_utf8_lossy` 394, the rows' `String`s, growth and drop glue, `if_nametoindex` per name, the `Vec<&str>` of names) | `interfaces::tests::posix::a_window_asks_by_the_first_ipv4_of_each_multicast_interface` (the rule over made rows), `the_walk_and_the_table_read_the_same_entries` (red if the walk skips an entry or reads a field otherwise), `the_hosts_table_is_read_and_answers_by_the_same_rules` |
| SC2 | The record form and the holding as types: `ScoutingActions` over a record type (the lent table, or the heap collection the tokio engine keeps), and a window held in its place or shared as a type of its own, so a C library's window links neither the collection (`decode_scouted_hello`'s `String`s, the `Vec<ScoutedHello>` and `Vec<ScoutRxIgnored>` growth, their drop glue, `discovered`) nor the `Arc` arm (`new_scouting_engine`, `drop_slow`) | -2,500 to -4,000 (the heap arm of `window_datagram` and `record_hello_and_emit`, the three collections' drop glue and growth, of `scouting_host` 5,978) | `scouting_host`'s tests over both forms, unchanged in what they assert; a new test that a window over a table records into it and keeps no list (red if a lent window grows a collection) |
| SC4 | The scout config's values trimmed as ASCII (`str::trim_ascii`), as `config_limits` trims | -600 (the Unicode `trim` 619 and its table, `lang-rt.md` L7) | `wz_capi_pico::scout`'s config tests, with a value padded by a non-ASCII space, which zenoh-pico does not trim either |
| SC5 | The window's members and its wait in fixed storage: the members in a table of the scout's interface bound, as zenoh-pico's `_z_scout_links` is a static vector of `Z_MAX_NUM_SCOUT_INTERFACES`, and the members' poll set made once with them, not collected twice (`Vec<&S>` in `ScoutMembers::wait`, `Vec<pollfd>` in `wait_readable_any`) at every idle wait of 2 ms | -400 to -800 (`RawVec<ScoutMember>` growth, the two collects, `lang-rt.md` L4's scouting share); fewer instructions a window's idle turn | `scouting::tests` (every member read, a lost member dropped in order); a new bound test (red if a member past the bound is kept) |
| SC6 | The multicast locator read by the engine's own reader of address text (`lang-rt.md` L2: `locator_text`'s readers moved into `wz-session-core` beside `locator_grammar`), so a scout links no `core::net` reader | -1,000 to -1,600 (what SC1 leaves of `core::net::parser`) | `parse_multicast_locator`'s tests, and L2's differential tests |
| SC7 | An owned hello's locators in one block of the hello's own (lengths and bytes), not a boxed array of `String`s | -800 to -1,200 (of `z_hello_clone` 1,752) | `z_hello_clone`'s and `z_hello_locators`' door tests |
| CN1 | A face row carries a link's ends as addresses with their kind, not as text; the door writes each end once, into the C string it hands out | -2,500 to -4,000 (`push_socket_addr` for `RowText`, `FaceLinkRow`'s clone 661 and `of_group_member` 1,119, of `lang-rt.md` section 4.2's text out) | the connectivity doors' tests of a link's `src` and `dst`, `pico_abi_option_layout` |
| CN2 | A group's link text written once, when the group is joined, and read by the door | -800 to -1,500 (`PicoEndpoint::read` and its `String` per row) | `pico_group_endpoint_text`'s tests, `connectivity_events` |
| CN3 | One listener table and one delivery over an event that names its plane (transport or link), not two instances | -2,000 to -4,000 (the second copy of `Table`, `Delivery`, `Pending` and their drop glue) | `told_tests`, `place_tests`, `connectivity_events` |
| CN4 | The hub told as the face changes, from the engine's face watch, outside the engine's lock, with no queue between: no row is lost, so no row told is kept and no listener is brought to the faces after a loss | -4,000 to -7,000 (`Told`, `converge_transports`, `converge_links`, `MAX_CONNECTIVITY_TOLD_ROWS`' rows; the face watch's queue in the twin) | `told_tests` retire with what they test; `connectivity_events`'s order (transport `PUT` then link `PUT`, link `DELETE` then transport `DELETE`) holds |

Order: SC1, SC3 and SC4 (done), then SC2, SC5 and SC7 (the scout's plane alone), SC6 after
`lang-rt.md` L2; CN3, then CN1 with CN2 (the engine's face row, the open plan and the door), CN4
last (the engine's face watch). Section 8 says why SC7 and CN2 changed.

## 5. Contract: rows for `contract-switches.md`

Each behaviour of these planes that zenoh-pico lacks, for the owner's ruling (a capability on in a
build that names nothing, off in the zenoh-pico preset). `contract-switches.md` was not on the base
of this lane; these rows are to be appended there with its next free ids. Each row's evidence was
read in the pinned zenoh-pico tree (`vendor/zenoh-pico`), and K3's was corrected by that reading
(below the table).

| row | behaviour | evidence in zenoh-pico | off, it loses | estimate (bytes) | proposed switch | defaults |
|-----|-----------|------------------------|---------------|-----------------:|-----------------|----------|
| K1 `scout-group-socket` | a window also reads on a socket joined to the scouting group, and asks on it when no interface can be asked on | `src/session/scout.c` @ `return _z_scout_links_size(&scout->_links) > 0 ? _Z_RES_OK : _Z_ERR_TRANSPORT_OPEN_FAILED;`: a scout opens per-interface unicast links alone and fails with none; no link of it is joined to the group | a Hello sent to the group rather than to the asker is not heard, and a host that lists no interface finds nobody (its window has no member and ends at once, as zenoh-pico's fails) | 800 to 1,500 (`bind_scout_group`, `joined_on`'s join and the group's bind, the group member's arm of `ScoutMembers::from_parts`) | `CONFIG_WZ_CAP_SCOUT_GROUP_SOCKET`, cargo feature `scout-group-socket` of `wz-runtime-posix` and `wz-capi-coop` | on (Kconfig `default y`); `n` in `configs/zenoh-pico_defconfig`; implies nothing |
| K2 `scout-rx-verdicts` | a datagram a window does not take is classified (self echo, another node's Scout, a locator-less Hello, an unknown MID, undecodable), counted by verdict (`IgnoredCounts`) and logged at the verdict's severity | `src/session/scout.c` @ `ret = _Z_ERR_MESSAGE_UNEXPECTED;` in `_z_scout_recv`, and `_z_scout_read`'s `_Z_ERROR("Failed to receive scouting message from link %zu: %d", i, ret);`: one error code, one line, no count | the counts and the per-verdict lines; a datagram not taken is still dropped and still does not advance the window (`hello_advances_window` is the window's rule, not the verdict's) | 600 to 1,200 (`classify_ignored_scout_rx`, `ScoutingActions::record_ignored`'s arms, `IgnoredCounts`) | `CONFIG_WZ_CAP_SCOUT_RX_VERDICTS`, cargo feature `scout-rx-verdicts` of `wz-session-core`, `wz-capi-coop`, `wz-capi-pico` and `wz-capi-core` | on; `n` in the zenoh-pico defconfig; implies nothing |
| K3 `connectivity-unlocked-replay` | a listener's history replay holds no lock of the session's faces, so a callback in it may read the faces (`z_info_transports`, `z_info_links`); what arrives meanwhile is told after it, folded by row (`Pending`) | `src/api/connectivity.c` @ `_z_connectivity_replay_transport_history`: the replay calls the closure under `_z_transport_peer_mutex_lock(transport_common);`, and the listener is inserted only after it (`id = session->_connectivity_next_listener_id++;` under `_z_session_mutex_lock_if_open`) | the queue: the replay runs under the face table's read, as zenoh-pico's runs under its peer lock, so an arrival waits for it rather than queueing; a callback of the replay that reads the faces waits on itself, as in zenoh-pico | 1,500 to 2,500 (`Pending`, `end_replay`, `finish_replay`'s fold) | `CONFIG_WZ_CAP_CONNECTIVITY_UNLOCKED_REPLAY`, cargo feature `connectivity-unlocked-replay` of `wz-capi-pico` | on; `n` in a preset based on zenoh-pico that turns `connectivity` on (the zenoh-pico defconfig has `CONFIG_WZ_CAP_CONNECTIVITY=n`, so it names nothing of it); implies `connectivity` |

K3 corrected: the lane's first reading said zenoh-pico dispatches an arrival and a departure under
its session lock. It does not: `_z_connectivity_dispatch_transport_event` and its link twin clone
the listener map under `_z_session_mutex_lock(session);`, let it go, and call each closure outside
it. Delivery outside every lock is therefore shared behaviour and no row; what zenoh-pico lacks is
the replay without a lock, which is K3 as it now stands.

Not rows: the claim of the process's scout table (the no-heap contract: a static table is shared
by every thread), a Hello's locator quota (`MAX_LOCATOR_LEN`, the same contract), the link kinds
zenoh-pico lacks (no code of the plane's own).

What each switch needs to land, none of which this lane can run: a `[[capability]]` of
`deploy/wz-config.toml` with the id, `kconfig`, `upstream_off = ["zenoh-pico"]`, `abis`
`["core", "pico"]` (every capability is in `core`, `wz_config.py`'s `validate_caps`, so K3's is
too, its core feature carrying the name alone) and `implies = []`, and
`scripts/lib/wz_config.py` run to emit `deploy/Kconfig.capabilities`, the defconfigs and the
generated limits it writes (its `--check` fails on a hand-edited one); then the cargo feature at
every use, with the build without it compiling: K1 gates `bind_scout_group` and the group member
of `ScoutMembers::open` (a window then has ask members alone, and `from_parts`'s fallback to the
group goes with it); K2 gates `classify_ignored_scout_rx` and the per-verdict arms, leaving one
count of datagrams not taken (the conservation the window's tests read: taken or counted); K3 gates
`Pending` and the replay's fold, the off form holding the face table's read across the replay.
The census (`upstream_feature_census.py`), the prose-name and the no-allocator gates read a new
capability name, so the main session runs them with the generator.

None of the three implies its plane, as landed: a switch on by default whose Kconfig entry
selected `scout` or `connectivity` would turn the plane back on in a build that turned it off and
left the behaviour at its default. Each is a behaviour of a plane, as `advanced-source-retention`
is of `advanced`, so it implies nothing and its cargo feature forwards weakly: without the plane
there is no window, or no hub, for it to change. The first reading of this section had each imply
its plane.

## 6. Measurement cells

- After each scout step: `size_ledger_gate.py --explain pico-peer-coop` (`window_hellos`, the
  owners of section 1) and `--measure` of `pico-peer-coop` and `pico-api-coop-nostd`.
- After each connectivity step: `--explain pico-api-coop-nostd` (the doors area, `link_of_row`,
  `FaceLinkRow`'s bodies).
- Every step: the bytes and the receive instructions of `pico-client-coop-nostd`, to read
  unchanged.

## 7. Where the steps stand

| step | commit | what was done | what its tests hold |
|------|--------|---------------|---------------------|
| SC1 | `refactor(runtime-posix): Make a scout's sockets from plans, not keys` | as planned; `bind_joined` and `bind_sender` keep the key resolution for the group plane and share `joined_on` with the scout's group socket. `multicast_interface_addresses` answers `Ipv4Addr`, the type of what it gives | an asker is bound to its address, leaves by it, keeps the options the pinned sender keeps, does not block, and is refused for an IPv6 group; the scout's group plan is the plan of no key |
| SC4 | `refactor(capi-pico): Trim a scout's config values of ASCII space alone` | as planned; zenoh-pico reads the numbers with `strtol`, which skips the C locale's (ASCII) space, and the locator untrimmed | ASCII padding is taken off `what` and the budget; a value led by a no-break space states nothing and leaves the default |
| SC3 | `refactor(runtime-posix): Ask a scout's interfaces of the host's list` | as planned; `InterfaceTable::read` reads through the same walk, an interface's index asked by its name's bytes | the rule over made rows (one address an interface, IPv6, joined groups, loopback, down and carrier-less interfaces left out); the walk and the owned table list the same entries; each index is the one its name finds |
| SC2 | `refactor(session-core): Name a scout window's record and holding` | as planned, as two pairs of types. The record: `ScoutingActions<R, K>` over `K: HelloRecord<R>`, the heap collection `HelloList` (the tokio engine's, the default `K`) or the lent table `LentTable` (the C library's), each with the reads of its own form (`scouted_hellos` and `ignored_datagrams` of the list, `hellos_refused` of the table); the count of datagrams not taken stays every window's. The holding: `ScoutWindow<S: WindowHolding>`, `SharedWindowState` (an `Arc`) or `LentWindowState` (held in the window's place), the machine reaching it through `ActionsReach` (the `Arc`, or `PlacedActions`, a pointer). The actions' bodies are the state's own methods, so the binding is four calls. `ScoutingActions::over_table`'s `Arc` form had no caller and is gone | the window's tests over both forms, unchanged in what they assert (the collection has no bound, a lent table counts past its rows, a window built in its place is the window built by value); `a_window_over_a_lent_table_holds_its_state_in_its_place` now reads the lent record as a pointer that owns nothing it would drop (red if it grows a list, a string or an `Arc`), records its answer in the table, and holds a shared window's `Arc` at two (the window and its machine) |
| SC5 (the set) | `refactor(runtime-posix): Make a scout window's wait set with its members` | the half of SC5 that needs no new limit: `ReadableAmong`, a socket's poll entry (`pollfd`, `WSAPOLLFD`) made once as a member joins the window, kept in the members' order and dropped with each lost member; `ScoutMembers::wait` hands the set as it stands, so neither collect is made at a wait (`wait_readable_any` is gone from `MulticastSocket`) | `a_member_whose_read_fails_is_dropped_and_the_rest_keep_their_order` reads the set against the members after every drain (red if the set leaves their order or keeps a lost member's entry); the real wait test is unchanged |
| K1 | `feat(runtime-posix): Switch a scout window's group socket by capability` | the capability `scout-group-socket` (section 5's row, implying nothing), the cargo feature of `wz-runtime-posix`, `wz-capi-coop`, `wz-capi-pico` and `wz-capi-core` (its name alone there), on in each default list and off in the zenoh-pico preset. A window is made of its ask members (`ScoutMembers::asking`); with the switch the group socket joins after them (`listening_on_group`) and asks only when none does, so the fallback is decided where the group member is taken. Off, `bind_scout_group` and its plan (`Plan::unpinned`) are not compiled, and a window given no address has no member | with the switch: the group socket asks alone and listens beside an ask member; without it: a window opened on no address is empty and one on the loopback holds that ask socket alone (red if the group is joined without the switch); in either build a window of no member asks nobody; the ask plan is the IPv4 plan pinned to its address |
| SC5 (the rows) | `refactor(runtime-posix): Hold a scout window's members in fixed rows` | the members and the wait set in `BoundedVec` rows of the static policy, `MAX_SCOUT_INTERFACES` (default 10, zenoh-pico's `Z_MAX_NUM_SCOUT_INTERFACES`, a capacity of the runtime bound at the build) plus one for the group's socket with K1; an address past the bound opens no socket and is counted (`left_out`, a warning, as zenoh-pico warns); a lost member is dropped by moving the kept ones forward and popping the rest. The window asks the interfaces by a walk of the host's list where the system holds it (`walk_multicast_interface_addresses`, `FirstIpv4OfEach`), so it collects no addresses; the owned forms read through the same walk | a window of one more member than the bound keeps the first `MAX_SCOUT_INTERFACES` in order with their entries and counts one (red if a member past the bound is kept or not counted); a window opened on two addresses past the bound binds the bound's sockets and counts two (red if a socket it cannot keep is opened); the walk of the host's list answers what the owned table does |
| K2 | `feat(session-core): Switch a scout window's verdicts by capability` | the capability `scout-rx-verdicts` (implying nothing), the cargo feature of `wz-session-core`, `wz-capi-coop`, `wz-capi-pico` and `wz-capi-core`; `wz-runtime-tokio`'s `scouting-active` selects it, as the tokio engine lists and reads the verdicts. With it, unchanged. Without it `ScoutRxIgnored`, `classify_ignored_scout_rx`, the heap record's list and the per-verdict logs are not compiled, and `IgnoredCounts` is one count of the datagrams not taken, read by `total` as before | the window's conservation, each datagram not taken counted once, holds in both builds (`a_datagram_that_is_not_an_answer_is_named_and_the_window_goes_on` reads the total, the verdicts under the switch); the counts by verdict and their sum with it, one count without it; the window's rule `hello_advances_window` tested apart from the verdicts |
| CN3 (the delivery) | `refactor(capi-pico): Deliver both planes' listener events as one type` | an event names its plane (`ConnEvent`: a transport's or a link's, each as that plane's callback reads it), so one `Delivery` and one `Pending` serve both planes where each was instantiated for the transport event and again for the link event. The delivery holds the closure with its event's type left out (`EventCall`, erased at the door by `erase_transport_call` and `erase_link_call`, as `pubsub`'s `erase_sample_call` is) and its plane, and hands the closure an event of that plane alone | the replay tests over the one delivery, unchanged in what they assert; `a_delivery_hands_its_closure_the_events_of_its_plane_alone` (red if `Delivery::call` hands the closure an event of the other plane: the transport callback reads a link event and logs a line) |
| CN3 (the place) | `refactor(capi-pico): Lay both planes' listeners out in one place type` | one handle state (`ListenerState`) and one kept part (`Listener`: the delivery and the link filter, `None` for a transport listener) make one place type, `ListenerPlace`, which the pools of both kinds lay out (`object_slot`'s layouts, `process_pool`'s plan); one `place_listener` writes it, the pool kind read off the plane. `Listened`, `LetGo` and the second instantiation of the place's code (`hold_entity`, `kept_at`, `retire_entity`, `Slot::take_entity` and `fill_in_place` over the second pair) are gone | the place tests of the cooperative engine (`place_tests`: a listener of each plane holds a place of its session's own kind and gives it back), unchanged |
| CN3 (the table) | `refactor(capi-pico): Keep a hub's listeners of both planes in one table` | one `Table` under one lock: a row (`ListenerRow`: the entry and the replay's mark) for each listener each plane's limit admits, read as the plane's slice, so a row's place is its listener's place in the plane's told notes; ids come from the hub, so one `undeclare` takes a listener of either plane. One `declare`, `release_listener`, `fan` and `converge` over the plane, with `key_of_row` and `event_of_row` the one place a plane's key and event are made, and `Listener::hears` what a replay and a convergence tell | `a_row_a_replay_keeps_is_given_to_no_other_listener_until_it_ended` now over the plane's slice and the hub's `end_replay` (red if a free row ignores the replay's mark, or a replay's end frees the other plane's row); `undeclaring_a_listener_takes_no_listener_of_the_other_plane` (red if each plane numbers its listeners apart: the link listener's undeclare takes the transport listener); the rows tests of each plane, unchanged |
| CN1 (the row) | `refactor(session-core): Hold a face row's link ends as facts, not text` | `FaceLinkRow`'s `src` and `dst` texts became `ends: RowEnds`: the ends a driver lent (`Lent`: the kind, and each end an IP address or a name, `LentEnd`), a group member's (`Member`: the group's locator and the address the member's datagrams come from), or two locators a snapshot holds written (`Written`, the tokio engine's rows, read off `FaceSnapshot`). `FaceLinkRow::write_src` and `write_dst` write a locator with `link::write_locator` (now public, still the one writer) where the row is read; `member_end` is the one writer of a member's end, for its row and its snapshot (`GroupMemberLink`). The engine writes no locator into a row: `end_row`, `ends_row`, `udp_row`, `member_row` and `udp_text` are gone. The pico door writes each end once into the string it hands out (`ConnText::written`: on the stack, one allocation of the text's length) | `a_row_holds_the_ends_its_driver_lent_and_reads_as_their_locators` (red if a row writes another scheme, suffix or address than the driver's ends, or keeps an end's text rather than its address), `a_group_members_row_is_the_row_of_its_snapshot_held_in_place` now reads the member's address in the row, `a_member_end_is_written_whole` (the widest IPv6 end, and a UDP group's member written as no group's), `a_links_ends_are_written_where_they_are_handed_out` in the pico door (red if the door writes another scheme, none, or cuts a name past the row's bound); the snapshot, told-row and queue tests unchanged in what they assert |
| CN2 | `refactor(capi-pico): Write a session's group text once, at its open` | as planned: `GroupText`, pico's text of the endpoint the session joins its group by (`pico_group_endpoint_text`), is written by each open where it plans the join (the tokio engine's and the cooperative engine's, before the config it is read from goes), handed to `PicoSessionExt::new` and kept by the hub (`Connectivity::group`), which every door that hands out a member's link reads (`z_info_links`, a listener's events, its replay and its convergence). No row is read as pico's endpoint text again. The engine's row still carries the endpoint the group was joined by, which other ABIs' snapshots read (`GroupLink`) | `a_members_link_starts_at_the_text_the_open_wrote` (red if the door reads the group's text for a unicast link, or ignores it for a member, which then starts at the group's locator); `a_group_members_link_starts_at_the_joined_endpoint` and its raweth twin unchanged in what they assert, reading through `GroupText` as the open writes it |
| CN1 (the queue) | `refactor(capi-pico): Hold a replay's arrivals as keys, told from rows` | takes back CN3's queue growth by holding no event at all: a queue row is a change (`Held`: the row's key and whether it came), the same for either plane, and its event is written when it is told, from the row the engine keeps as it notes the listener told. `SessionEngine::tell_came` and `tell_went` answer that row (`Option<FaceLinkRow>`) where they answered whether to tell: the row as it stands, or as it was told it came, read from its tomb (the cooperative engine's face tomb, a group's member tomb, the port's `ToldLedger`). A held change owns nothing, so `Pending::release` and the events' release on a fold are gone | the replay tests of the delivery over held changes, unchanged in what they assert (a PUT and DEL that cancel, a reconnect told in order, a queue past its rows that converges once, holding allocates nothing); the engine's told tests now read the row a departure is told by (`a_told_face_that_goes_keeps_its_tomb_until_its_departure_is_told`, the second departure kept apart, `a_member_told_stays_as_its_tomb_until_its_departure_is_told`, `a_tombstone_stays_until_every_listener_told_it_came_was_told_it_left`: red if a departure is told of another row than the one it was told came as); a compile-time bound holds a queue row below two transport events |

## 8. What waits, and why

- **SC5, the members' fixed storage**, landed (section 7): `MAX_SCOUT_INTERFACES` is a limit of
  `deploy/wz-config.toml`, its generated outputs written by `scripts/lib/wz_config.py --write`,
  which this lane does not run.
- **SC7: its premise is false on the measured cases.** `z_hello_clone` boxes a `HelloState` with a
  `StringArrayState` of `String`s only in a library without the process pools, which is the tokio
  engine's without `object-pool` (`crates/wz-capi-pico/build.rs`). Every cooperative library has
  the pools, and there an owned hello is already one block of its own, `KeptHello` (the hello, its
  array, the views and the locator text) in a slot of the pool of kept hellos. The 1,752 bytes read
  in section 1 are that block's copy (`KeptHello::write_at`) and the pool's slot code, not a
  boxed array. What remains of the step is a smaller copy: a kept hello holding a `HelloRow` (its
  `ends` and `text`, which a row already holds) and making its views from it, so the text and
  its bounds have one layout; to be measured before it is planned.
- **SC6 waits on `lang-rt.md` L2**, owned by another lane. What it needs from L2: a reader in
  `wz-session-core`, beside `locator_grammar`, of a socket address's text (`IPV4:PORT` and
  `[IPV6]:PORT`, the bracketed form `parse_multicast_locator` documents and tests) answering
  `(IpAddr, u16)` or `SocketAddr`, refusing what `SocketAddr::from_str` refuses (an unbracketed
  IPv6 address with a port, a missing port). With it, `parse_multicast_locator` reads `rest` with
  that reader in place of `rest.parse::<SocketAddr>()`, its tests unchanged
  (`the_multicast_locator_grammar_is_exact`), and a scout links no `core::net` reader.
- **CN3** landed (section 7) in three steps, the delivery, the place and the table, each built
  on the last. Its one residue, a queue row sized by the link event (about 64 bytes a row more for
  a transport listener's place), is taken back by CN1's queue step, and more: a queue row is now a
  key and a direction, 40 bytes on a 64-bit target where a row held 136 (an estimate from the
  types' sizes: `ToldKey` 32, the link event 96 and its tag, the key), so each listener's place,
  of either plane, holds about 768 bytes less at the default `MAX_CONNECTIVITY_REPLAY_EVENTS` of
  8, in a build with `connectivity`. The receive path is not touched: no step of CN3 or CN1 is
  on the way a message takes.
- **CN1 and CN2** landed (section 7). What each is expected to read, for the cells of section 6
  to confirm: text falls by the engine's locator writing into a row (`end_row`'s two writes and
  its `FixedText`, `push_socket_addr` for a member's `udp_row`, the raweth member's text at
  every member row) and by `PicoEndpoint::read` and its `String` at every member's link handed
  out; the door's `ConnText::written` and `write_locator` are the write that stays, once. Two
  residues, stated rather than hidden: a row's ends are a little larger than its two texts were
  (`RowEnds`'s `Lent` holds a kind beside two ends of a name's size, about 8 bytes a row on a
  64-bit target, an estimate), which the face watch's queue, each face's kept row and the hub's
  told rows each hold; and the hub keeps the group's text (one `GroupRowText` a session with
  `connectivity`). Not done here, and owed: `wz_runtime_coop::udp_link::ends_fit` refuses an IP
  link whose locator would not fit `MAX_LOCATOR_LEN`, a rule written so that no face row spills
  to the heap; a row now holds an IP end as its address, so whether the rule still has a reader
  that needs it (the bounded `LinkEndpoints` of `session-slot`) is to be read before it is
  kept or narrowed.
- **CN4** is not begun. It keeps its plan and its order: the hub told as the face changes, from
  the engine's face watch, with no queue between, which removes `Told`, `catch_up` and
  `MAX_CONNECTIVITY_TOLD_ROWS`'s rows.
- **K1 and K2** landed (section 7). **K3 waits on CN4: its off form's premise is false while the
  hub is handed queued rows.** Section 5 says the off form holds the face table's read across the
  replay, so that an arrival waits for it rather than queueing. It does not wait: the rows reach the
  hub from the face watch's queue (`MAX_FACE_WATCH_ROWS`) through `Connectivity::on_face_row`,
  outside every lock of the engine, so a read of the face table held by the replaying thread stops
  no row already queued, and a row the replay's walk found standing may also wait in the queue, to
  be told again when it is handed out. A lock of the hub's own around the replay and the hand-out
  would serialize them, and then a callback that declares a listener with history from inside a
  delivery would wait on itself, which zenoh-pico's delivery, outside every lock, does not. What
  the off form needs is the hand-out CN4 makes: the hub told as the face changes, in the order the
  face table changes, so that one lock orders the change, its telling and a replay's walk. K3's
  capability, its features and its off form land with or after CN4; no capability is declared
  before the code it switches.
