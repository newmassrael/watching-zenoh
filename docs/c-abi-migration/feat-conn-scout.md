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
| dispatching an arrival and a departure | `_z_connectivity_peer_connected` and `_disconnected` dispatch to every listener from the task that saw the peer, under the session's lock (`_z_connectivity_dispatch_transport_event`) | one hub per session handed rows by the engine's face watch through a queue of `MAX_FACE_WATCH_ROWS`, delivered outside every lock | **contract** (row K3): a callback that calls the session back runs; zenoh-pico holds its lock across it |
| history | `_z_connectivity_replay_transport_history` replays under the peer's and the session's locks, so nothing interleaves | the replay runs outside the lock; what arrives meanwhile waits in `Pending<E>` (`MAX_CONNECTIVITY_REPLAY_EVENTS`), folded by row | part of K3: the queue exists because the replay holds no lock |
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
| SC5 | The window's members and its wait in fixed storage: the members in a table of the scout's interface bound, as zenoh-pico's `_z_scout_links` is a static vector of `Z_MAX_NUM_SCOUT_INTERFACES`, and the wait over the members' sockets without a collected `Vec<&S>` | -400 to -800 (`RawVec<ScoutMember>` growth, the wait's collect, `lang-rt.md` L4's scouting share) | `scouting::tests` (every member read, a lost member dropped in order); a new bound test (red if a member past the bound is kept) |
| SC6 | The multicast locator read by the engine's own reader of address text (`lang-rt.md` L2: `locator_text`'s readers moved into `wz-session-core` beside `locator_grammar`), so a scout links no `core::net` reader | -1,000 to -1,600 (what SC1 leaves of `core::net::parser`) | `parse_multicast_locator`'s tests, and L2's differential tests |
| SC7 | An owned hello's locators in one block of the hello's own (lengths and bytes), not a boxed array of `String`s | -800 to -1,200 (of `z_hello_clone` 1,752) | `z_hello_clone`'s and `z_hello_locators`' door tests |
| CN1 | A face row carries a link's ends as addresses with their kind, not as text; the door writes each end once, into the C string it hands out | -2,500 to -4,000 (`push_socket_addr` for `RowText`, `FaceLinkRow`'s clone 661 and `of_group_member` 1,119, of `lang-rt.md` section 4.2's text out) | the connectivity doors' tests of a link's `src` and `dst`, `pico_abi_option_layout` |
| CN2 | A group's link text written once, when the group is joined, and read by the door | -800 to -1,500 (`PicoEndpoint::read` and its `String` per row) | `pico_group_endpoint_text`'s tests, `connectivity_events` |
| CN3 | One listener table and one delivery over an event that names its plane (transport or link), not two instances | -2,000 to -4,000 (the second copy of `Table`, `Delivery`, `Pending` and their drop glue) | `told_tests`, `place_tests`, `connectivity_events` |
| CN4 | The hub told as the face changes, from the engine's face watch, outside the engine's lock, with no queue between: no row is lost, so no row told is kept and no listener is brought to the faces after a loss | -4,000 to -7,000 (`Told`, `converge_transports`, `converge_links`, `MAX_CONNECTIVITY_TOLD_ROWS`' rows; the face watch's queue in the twin) | `told_tests` retire with what they test; `connectivity_events`'s order (transport `PUT` then link `PUT`, link `DELETE` then transport `DELETE`) holds |

Order: SC1 and SC3 (done), then SC2, SC5 and SC7 (the scout's plane alone), SC4 (the scout door,
one line), SC6 after `lang-rt.md` L2; CN3 and CN2 (the door alone), CN1 (the engine's face row
and the door), CN4 last (the engine's face watch).

## 5. Contract: rows for `contract-switches.md`

Each behaviour of these planes that zenoh-pico lacks, for the owner's ruling (a capability on in a
build that names nothing, off in the zenoh-pico preset). `contract-switches.md` was not on the base
of this lane; these rows are to be appended there with its next free ids.

| row | behaviour | zenoh-pico's absence | off, it loses | estimate |
|-----|-----------|----------------------|---------------|---------:|
| K1 `scout-group-socket` | a window also reads on a socket joined to the scouting group, and asks on it when no interface can be asked on | `_z_scout_init_links` opens per-interface links alone and fails a scout with none (`return _z_scout_links_size(&scout->_links) > 0 ? _Z_RES_OK : _Z_ERR_TRANSPORT_OPEN_FAILED;`) | a Hello sent to the group rather than to the asker is not heard, and a host that lists no interface finds nobody | 800 to 1,500 (`joined_on`'s join and the group's bind) |
| K2 `scout-rx-verdicts` | a datagram a window does not take is classified (self echo, another node's Scout, locator-less Hello, unknown MID, undecodable), counted and logged by verdict | `_z_scout_recv` returns the decode's error or `_Z_ERR_MESSAGE_UNEXPECTED` and `_z_scout_read` logs it | the counts (`IgnoredCounts`) and the debug lines; a malformed datagram is still dropped | 600 to 1,200 (`classify_ignored_scout_rx`, `record_ignored`) |
| K3 `connectivity-unlocked-delivery` | a connectivity listener is called outside the session's locks, so it may call the session; a history replay holds no lock and what arrives meanwhile is told after it (`Pending`) | `_z_connectivity_dispatch_transport_event` and the history replay run under `_z_session_mutex_lock` | the replay and the events dispatched under the face table's read, as zenoh-pico does; a callback that calls the session back waits on itself | 1,500 to 2,500 (`Pending`, `end_replay`) |

Not rows: the claim of the process's scout table (the no-heap contract: a static table is shared
by every thread), a Hello's locator quota (`MAX_LOCATOR_LEN`, the same contract), the link kinds
zenoh-pico lacks (no code of the plane's own).

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
| SC3 | `refactor(runtime-posix): Ask a scout's interfaces of the host's list` | as planned; `InterfaceTable::read` reads through the same walk, an interface's index asked by its name's bytes | the rule over made rows (one address an interface, IPv6, joined groups, loopback, down and carrier-less interfaces left out); the walk and the owned table list the same entries; each index is the one its name finds |
