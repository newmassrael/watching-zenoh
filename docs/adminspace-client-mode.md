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

wz: a single-session client of `wz-ap-demo` hosts one with `--config-queryable`,
which is what a stock config's `adminspace` block expands to; a build without
the demo's `adminspace-core` feature refuses the flag by name and the config
expansion withholds the block's keys rather than handing the flag over.

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
| `wz-ap-demo --router-hat` (`adminspace-router-linkstate`) | `router` | the node's params |
| `wz-ap-demo --storage-host` | `peer` | the session's params |
| `Session::declare_adminspace*` (library) | the session's | its params |
| MCU slot and fixed admin spaces | the node's | its identity |

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

| Residual | Why it stays |
|---|---|
| The one-shot acceptor (`--listen`) hosts no admin space and refuses `--config-queryable` | its bound listener is held inside the open helper, so its `local_data` could not list the locator it accepts on; `--peer` hosts a peer's |
| The `zenoh` API preset (`wz-zenoh`) hosts the runtime admin space only for a router node, under a fixed `router` role, and declares its `linkstate` queryable session-local | its client and peer engines expose no admin views or hosted queryable seam yet; a client session of that preset answers `@/<zid>/session/**` alone |
| `admin_legs` lists `linkstate/peers` for a router only, while the `--peer` host serves it | the manifest predicates the router-tier legs on the role string |

## 5. Witnesses

| Test | What it measures |
|---|---|
| `wz-admin` `every_role_answers_its_own_root_with_one_document` | one answerer, the same document under each role's root, nothing under another role's |
| `wz-admin` `a_client_manifest_lists_its_own_keys_and_no_router_leg` | a client's manifest stays under its root and lists no router-tier leg |
| `wz-runtime-tokio` `declare_adminspace_with_config_answers_a_client_under_its_own_role` | a client session answers at `@/<zid>/client` with the host's metadata, and not at `@/<zid>/peer` |
| `wz-runtime-tokio` `declare_adminspace_with_config_announces_a_clients_queryable_on_the_wire` | the queryable goes out as a declaration naming `@/<zid>/client/**` |
| `wz-ap-demo` `session_admin_tests`, `a_client_document_enables_its_admin_space_where_the_build_hosts_one`, `an_acceptor_run_has_the_admin_keys_withheld` | the flag, the refusals by run-mode and build, and the config expansion that hands the flag over |
| `wz-integration-tests` `wz_client_adminspace_zenohd_interop` (Layer Z) | a zenohd client behind a zenohd router (the control), a wz client behind it, and a wz client behind a wz router, each asked `@/<zid>/client` by another client and judged by one predicate |
