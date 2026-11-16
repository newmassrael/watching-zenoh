# The admin space of a client

What the pinned upstream (zenoh 1.10.2) declares and answers as a node's admin
space when the node is a CLIENT, compared with a peer and a router, and what wz
does in each place. Every upstream claim is an anchor (`path` @ `needle`) into
the pinned tree.

## 1. Whether there is an admin space at all

| Fact | Upstream | Anchor |
|---|---|---|
| Switch | `adminspace.enabled`, default `false`; the runtime starts the admin space only when it is set, in every mode | `zenoh/src/net/runtime/mod.rs` @ `let start_admin_space = *config.adminspace.enabled();` |
| zenohd | turns it on whatever `mode` says, so a zenohd started as a client has one | `zenohd/src/main.rs` @ `config.adminspace.set_enabled(true)` |
| Library client | has none unless its config enables it | (the default above) |

wz: a single-session client of `wz-ap-demo` hosts one with `--config-queryable`.
`wz-ap-demo --config <file>` is the daemon form and reads the file as zenohd
does, through the one table of zenohd's writes over its file
(`DAEMON_OVERRIDES` in `crates/wz-runtime-tokio/src/zenoh_config.rs`): it hosts
the admin space in every run-mode that has one, whatever the file says about
`adminspace/enabled` (an explicit `false` included, which the report names as
overridden), under the permissions the file states. The expansion adds
`--config-queryable` to the client, the client node and the peer, with or
without an `adminspace` block; the router host (`adminspace-router-linkstate`)
and the storage host serve theirs with no flag. A build without the demo's
`adminspace-core` feature refuses the flag by name, and the expansion hands a
client none and withholds the block's keys; the one-shot acceptor hosts none in
any build.

The `zenoh` API preset (`wz-zenoh`) reads the same key the same way: a session
opened with `adminspace.enabled` hosts the runtime admin space in every mode,
and one opened without it hosts none. Its defaults are upstream's, field for
field, because its config crate is the family copy of upstream's:

| Key | Upstream default | `wz-zenoh-config` default | Anchor |
|---|---|---|---|
| `adminspace/enabled` | `false` | `false` | `commons/zenoh-config/src/lib.rs` @ `AdminSpaceConf {` and `DEFAULT_CONFIG.json5` @ `/// Enables the admin space` |
| `adminspace/permissions/read` | `true` | `true` | `commons/zenoh-config/src/lib.rs` @ `impl Default for PermissionsConf {` |
| `adminspace/permissions/write` | `false` | `false` | (the same impl) |

## 2. What is declared

`AdminSpace::start` makes the same two declarations in every mode, rooted at
`@/<zid>/<whatami>` where `<whatami>` is the runtime's own mode
(`zenoh/src/net/runtime/adminspace.rs` @ `let whatami_str = runtime.state.whatami.to_str();`).

| Declaration | Key | Info | Anchor |
|---|---|---|---|
| Queryable | `@/<zid>/<whatami>/**` | `QueryableInfoType::DEFAULT`: `complete = false`, `distance = 0` | `zenoh/src/net/runtime/adminspace.rs` @ `ext_info: QueryableInfoType::DEFAULT,` and `commons/zenoh-protocol/src/network/declare.rs` @ `pub complete: bool, // Default false: incomplete` |
| Subscriber | `@/<zid>/<whatami>/config/**` | write path only | `zenoh/src/net/runtime/adminspace.rs` @ `wire_expr: [&root_key, "/config/**"].concat().into(),` |

Locality: both are sent through a face of the runtime's routing tables
(`zenoh/src/net/runtime/adminspace.rs` @ `let primitives = runtime.state.router.new_session(admin.clone());`),
so they are ROUTED entities: a client's hat declares them to its router, and a
query from any node that reaches the router is forwarded to the client. That is
what lets another client ask `@/<zid>/client` over the client's own link.

The session's own admin space, `@/<zid>/session/**`, is a different thing: it is
declared in every mode too (`zenoh/src/api/session.rs` @ `admin::init(session.downgrade());`)
but session-local (`zenoh/src/api/admin.rs` @ `Locality::SessionLocal,`), so no
other node can reach it.

## 3. What each key answers, by mode

The handlers are registered in every mode; what differs is what the mode's hat
gives them to answer from. A GET with `permissions.read = false` gets the Final
alone (`zenoh/src/net/runtime/adminspace.rs` @ `if !conf.adminspace.permissions().read {`).

| Key under `@/<zid>/<whatami>` | Client | Peer | Router | Anchor |
|---|---|---|---|---|
| (root) `local_data` | one JSON object | same | same | `zenoh/src/net/runtime/adminspace.rs` @ `"plugins": plugins,` |
| `metrics` | build-info gauge, or the stats registry with `stats` | same | same | `zenoh/src/net/runtime/adminspace.rs` @ `add_handler!("metrics", metrics);` |
| `linkstate/<region>` | nothing: it reads peer and router hats only | the peer hat's graph | the router hat's graph | `zenoh/src/net/runtime/adminspace.rs` @ `fn linkstate_data(prefix: &keyexpr, context: &AdminContext, query: Query) {` |
| `route/successor/**` | nothing | nothing | the successor table | `zenoh/src/net/runtime/adminspace.rs` @ `hat.mode().is_router()` |
| `subscriber/**`, `queryable/**`, `token/**` | what the client's faces declared to it | per hat | per hat | `zenoh/src/net/routing/hat/client/pubsub.rs` @ `for sub in self.face_hat(face).remote_subs.values() {` |
| `publisher/**`, `querier/**` | nothing: the client hat lists none | per hat | per hat | `zenoh/src/net/routing/hat/client/pubsub.rs` @ `fn sourced_publishers(&self, _tables: &TablesData) -> HashMap<Arc<Resource>, Sources> {` and `zenoh/src/net/routing/hat/client/queries.rs` @ `fn sourced_queriers(&self, _tables: &TablesData)` |
| `plugins/**`, `status/plugins/**` | only in a `plugins` build, from the started plugins | same | same | `zenoh/src/net/runtime/adminspace.rs` @ `add_handler!("plugins", "**", plugins_data);` |
| `config` (GET) | no such leg: `config/**` is write-only | same | same | (section 2) |

The root object's fields are the same in every mode, keys sorted as
`serde_json` writes them:

| Field | Client | Anchor |
|---|---|---|
| `zid` | the node's | `zenoh/src/net/runtime/adminspace.rs` @ `"zid": context.runtime.state.zid,` |
| `version` | the build's long version | `zenoh/src/net/runtime/adminspace.rs` @ `"version": &*LONG_VERSION,` |
| `metadata` | the config's `metadata`, `null` when unset | `zenoh/src/net/runtime/adminspace.rs` @ `"metadata": context.runtime.config().lock().metadata(),` |
| `locators` | the listeners without the loopback ones: `[]` for a client, which binds nothing | `zenoh/src/net/runtime/adminspace.rs` @ `.get_locators_noloopback()` |
| `sessions` | one entry per unicast transport (`links`, `peer`, `region`, `shm`, `weight`, `whatami`), then one per multicast peer; a client's lists its router | `zenoh/src/net/runtime/adminspace.rs` @ `"region": transport_unicast_to_region(transport)` |
| `plugins` | `null` without the `plugins` feature, else the started plugins | `zenoh/src/net/runtime/adminspace.rs` @ `let plugins = serde_json::Value::Null;` |
| (stats) | merged in on `_stats` with the `stats` feature | `zenoh/src/net/runtime/adminspace.rs` @ `k == "_stats" && v != "false"` |

No field names the node's own role: a client and a router with the same facts
answer the same bytes under different keys.

## 4. wz

One answerer serves every role: `wz_admin::adminspace::answer_admin_query`,
whose keys come from `admin_queryable_key(zid, whatami)` and whose root
document is `write_local_data_json`. A host passes its role in; none of them
fixes it.

| Host | Role in the keys | Where the role comes from |
|---|---|---|
| `wz-ap-demo --connect` / `--scout` with `--config-queryable` | `client` | the session's handshake params, through `Session::declare_adminspace_with_config` |
| `wz-ap-demo --peer` with `--config-queryable` | `peer` | the node's params |
| `wz-ap-demo --client-node` with `--config-queryable` | `client` | the node's params: the peer's mesh announcing the client role, which a client document naming listen and connect endpoints expands to |
| `wz-ap-demo --router-hat` (`adminspace-router-linkstate`) | `router` | the node's params |
| `wz-ap-demo --storage-host` | `peer` | the session's params |
| `Session::declare_adminspace*` (library) | the session's | its params |
| MCU slot and fixed admin spaces | the node's | its identity |
| `wz-zenoh` session, any mode, `adminspace.enabled`, any features | `client`, `peer` or `router` | the config's `mode`, read once at the open by `runtime_admin::start`; one host function (`host_admin_space`) for both engines |

Every host declares the admin queryable not complete, `ADMIN_QUERYABLE_COMPLETE`,
as upstream does in every mode (`zenoh/src/net/runtime/adminspace.rs` @
`ext_info: QueryableInfoType::DEFAULT,`). The `linkstate` legs are upstream's:
one `linkstate/<region>` leg for each region of a peer or a router hat, named as
upstream's `Region` displays it, byte for byte (`north`, `south:<id>:<mode>`;
`commons/zenoh-protocol/src/core/region.rs` @
`Region::South { id, mode } => write!(f, "south:{id}:{mode}"),`), and answered by
a peer as by a router (`zenoh/src/net/runtime/adminspace.rs` @
`fn linkstate_data(prefix: &keyexpr, context: &AdminContext, query: Query) {`).
The routes are a router's alone. A peer Session answers its `north` region with
the single-hop graph of itself and its one link, rendered by the one renderer a
node's tables use (`single_hop_graph_text`).

The `zenoh` API preset runs a session on one of two engines, and the one host
function answers on both through one seam, `Engine::host_admin_queryable`:

| Engine | Which sessions | Declared as | Answers from |
|---|---|---|---|
| the node (`Engine::Router`) | a router; a peer that listens and does not scout; a client that keeps a `gateway/south` | a queryable the router hosts, not complete | the router's tables: its faces as `sessions`, their declarations by kind, and, for a router alone, the successor routes |
| the registry of faces (`Engine::Tokio`) | every other client, and a peer that fits no node | a routed queryable on every face, not complete | one `sessions[]` row per face, each read by `SessionAdminRow::admin_session_of_peer`, the reading the library's Session host uses, then one row per member of each group it joined (`McastGroupMembership::admin_peers`, upstream's `let transport_multicast_peer_to_json =`); its listeners as `locators` |

The registry's answer is made inside the dispatch of whichever session the
query came in on, the local plane included, so it reads the faces and the
groups from a `TransportsCell` the registry rewrites under its own lock and
never takes that lock: a declaration takes the registry lock before it reaches
the plane, and the reverse order would deadlock against it.

The single-session client declares the pair upstream declares, routed, with the
queryable's default info (`complete = false`): the queryable and, under
`adminspace-write`, the `config/**` subscriber, both answering from and writing
into one config seeded with the operator's permits and `metadata`. Its
`locators` is `[]`, as upstream's client is. Its `sessions` lists its one
transport, the router. The router-tier legs are not declared by a client, which
is what upstream's client answers with too.

Beyond upstream, every wz host answers a `config` GET leg and `wz/surface`;
both sit under the same root.

### Residuals

| Residual | Upstream | Why it stays |
|---|---|---|
| The one-shot acceptor (`--listen`) hosts no admin space and refuses `--config-queryable` | has no one-shot acceptor: a client that listens binds its endpoints and dials (`zenoh/src/net/runtime/orchestrator.rs` @ `async fn start_client(&self) -> ZResult<()> {`), and every listening node hosts its admin space | the one-shot acceptor is a wz harness mode with no upstream counterpart; upstream's listening client is `--client-node` now, which a client document naming both lists expands to, and which hosts it |
| A client document that names listen endpoints and nothing to dial runs no node | scouts for a router, then binds and dials | the expansion emits no scouting run; the verdict names the key withheld |
| R2091b measured a zenohd handed `{ mode: "client", listen: [..] }` and saw no locator named, which the demo and `default_listen_endpoint`'s doc read as "a client never listens" | binds before it dials, by the source above; zenohd prints only the locators that are not loopback (`zenoh/src/net/runtime/orchestrator.rs` @ `for locator in &locators_noloopback {`) | the expansion now follows the source; a Layer Z leg that hands zenohd a client document naming both lists and dials its listener is what settles the measurement, and `default_listen_endpoint`'s doc still carries the earlier reading |
| The session's own admin space (`@/<zid>/session/**`) of the `zenoh` preset exists only in a build with `unstable` | upstream's session declares it whatever the features (`zenoh/src/api/session.rs` @ `admin::init(session.downgrade());`) | it is built on the preset's transport and link views, which are its unstable API; the runtime's admin space no longer is |
| A router node of the `zenoh` preset that joined a multicast group lists no group member in `sessions` | lists each member after the unicast transports | the group's member table is held by the node's driver task and not handed to `RouterState`; the registry of faces lists its members |
| The `zenoh` preset answers `linkstate/<region>` from a queryable of its own, session-local, and the routed admin queryable answers no `linkstate` leg | routed with the rest | routing it makes every peer with an admin space answer a `@/*/peer/linkstate/north` GET, which this crate's gossip tests read the first reply of; the node and the demo's hosts answer it routed |
| A client node whose `gateway/south` holds peer hats answers no `linkstate` leg | answers the region of each peer hat it holds | the demo's and the preset's client hosts answer none; the client hat itself holds no graph |

## 5. Witnesses

| Test | What it measures |
|---|---|
| `wz-admin` `every_role_answers_its_own_root_with_one_document` | one answerer, the same document under each role's root, nothing under another role's |
| `wz-admin` `a_client_manifest_lists_its_own_keys_and_no_router_leg` | a client's manifest stays under its root and lists no router-tier leg |
| `wz-runtime-tokio` `declare_adminspace_with_config_answers_a_client_under_its_own_role` | a client session answers at `@/<zid>/client` with the host's metadata, and not at `@/<zid>/peer` |
| `wz-runtime-tokio` `declare_adminspace_with_config_announces_a_clients_queryable_on_the_wire` | the queryable goes out as a declaration naming `@/<zid>/client/**` |
| `wz-ap-demo` `session_admin_tests`, `a_client_document_enables_its_admin_space_where_the_build_hosts_one`, `an_acceptor_run_has_the_admin_keys_withheld` | the flag, the refusals by run-mode and build, and the config expansion that hands the flag over |
| `wz-ap-demo` `the_daemon_form_hosts_the_admin_space_in_every_mode_whatever_the_file_says`, `a_disabled_block_still_states_the_permissions_the_daemon_form_serves`, `the_daemon_admin_flag_is_added_once_and_only_where_a_run_mode_hosts_on_it`, `each_run_mode_states_how_it_hosts_the_daemon_admin_space` | a `--config` run hosts the admin space in every mode with no block, `enabled: true` and `enabled: false`, keeps the permissions a disabled block states, and adds the flag once and only where a run-mode hosts on it |
| `wz-runtime-tokio` `admin_session_of_peer_files_the_row_under_the_named_peer` | the one `sessions[]` row reading both the Session host and the preset's registry use: none before a peer is named, then the peer's zid, its role once announced, no weight |
| `wz-zenoh` `a_client_answers_its_admin_space_through_its_router` | a preset client on the registry of faces, asked `@/<zid>/client` by another client through a router node: one answer with its zid, metadata, `[]` locators and the router as its one session; nothing under `router`; a client that leaves the switch off answers nothing |
| `wz-zenoh` `a_peer_node_answers_its_admin_space_under_its_own_role` | a peer on the node engine answers under `peer`, nothing under `router`, and no successor route |
| `wz-zenoh` `the_admin_space_is_off_and_read_only_by_default` | the preset's defaults are upstream's three values, built in code and read from a document |
| `wz-zenoh` `a_clients_own_admin_get_ends_while_entities_are_declared_beside_it` | a client's own-key GET, 200 times, ends while another thread declares and undeclares queryables: the answer reads the `TransportsCell`, not the registry |
| `wz-zenoh` `a_peer_on_a_group_lists_its_members_in_its_admin_space` | a registry peer on a group lists the other member with its role, group and one link, and no unicast field |
| `wz-admin` `router_admin_keys_match_zenoh_form`, `router_admin_linkstate_get_replies_each_region_text_plain`, `router_admin_linkstate_region_get_scopes_to_one_leg`, `a_peer_answers_the_linkstate_of_its_region` | the `linkstate/<region>` keys, one reply per region, a peer's region under its own role |
| `wz-runtime-tokio` `a_router_names_its_linkstate_regions_as_upstream_displays_them` | a router's regions are `north` and `south:0:peer`, from the forwarder and from the handle a host keeps |
| `wz-runtime-tokio` `the_admin_queryable_is_declared_incomplete` | an `AllComplete` GET of the root meets no queryable, the `All` control is answered |
| `wz-runtime-tokio` `a_peer_session_answers_its_north_region_and_a_client_session_none` | the Session host's single-hop `north` graph for a peer, and nothing for a client |
| `wz-ap-demo` `client_node_binary` (3) and the expansion rows `client + listen + connect` | `--client-node` refused without a router and beside `--peer`, bound with one; the client document naming both lists expands to it and applies all three keys |
| `conformance/differential` `zenoh_api_client_admin_space` (Layer E18) | upstream's crate and wz's as the client, with an upstream router and an upstream asker: the same lines (answered, the root's field names, zid, metadata, locators, the session's field names, peer and role, nothing under `router`), and the control that a client answering nothing is a difference |
| `wz-integration-tests` `wz_client_adminspace_zenohd_interop` (Layer Z) | a zenohd client behind a zenohd router (the control), a wz client behind it, a wz client behind a wz router, and a wz client started from a client config with no `adminspace` block behind a wz router, each asked `@/<zid>/client` by another client and judged by one predicate |
