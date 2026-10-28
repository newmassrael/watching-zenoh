# A peer node on the region-hat forwarder

Status: design note. It states what is measured, what is decided and what is
still open; it is not a specification and the atomic store does not parse it.
It is the plan behind step (b) of open-debt item 751, the one the rounds that
built the router subregion (R3219, R3220) left unstarted.

## 1. The question

A node with a custom `gateway/south` partition holds several hats: the pin
builds client, peer and router hats per subregion for every node mode
(`zenoh/src/net/routing/gateway.rs` @ `GatewaySouthConf::Custom(subregions) => {`).
A router in wz does this today. A peer does not, because wz's peer plane,
`LinkstateForwarder` (`crates/wz-runtime-tokio/src/linkstate_forward.rs`,
about 20,000 lines), is one net and one region. `--gateway-south` is therefore
refused on every run mode but `--router-hat`, and the config key stays
unhonoured.

The tempting repair is to give `LinkstateForwarder` a region map of its own.
That would build the same structure a second time, in the plane the pin does not
have: the pin has ONE routing dispatcher whose hats differ by region, and a
node's mode only decides which hat sits north.

## 2. What is measured

- The router forwarder already keys its tables by region and takes the node
  mode as an argument where it asks what a region is: `regions_of(mode,
  partition)` and `hat_kind(region, node_mode)` in `routing_region.rs`, and
  `Hat::for_region` per region. What fixes it to a router is wider than the 28
  lines of `router_forward.rs` that name `WhatAmI::Router` (the three predicates
  `is_leaf`, `is_peer_hat` and `is_router_hat` among them, and the two places
  that build `tables.hats`): the north region is spelled `ROUTERS_REGION` 75
  times and the south peer region `PEERS_REGION` 47 times, the north net is
  reached as `routers_net` 84 times, and the three predicates are called 35
  times. For a peer the north hat is the peer hat and the peer region is a
  SOUTH region of a router only, so those names have to become "the north
  region" and "the region whose hat is a peer hat" before a peer can use them.
  That, and not the 28 lines, is the size of step 1.
- A face's region is already computed from the node mode, the remote's mode and
  the bound the remote announced (`extbound::region_and_bound_of`), and the
  multicast group's region by `multicast_region_and_bound_of`; both take the
  node mode.
- The router's peer region is already the pin's peer hat: a single-hop gossip
  `Network`, face-based publication, and the opt-in link-state mode as a flag
  on that one net (`set_peer_region_full_linkstate`, R2896). So the link-state
  extension is not a different forwarder; in wz's router it is a mode of a hat.
- `LinkstateForwarder` carries state of three kinds, read off its fields: the
  state of ONE region's net (the graph, the subscriber, queryable and token
  interest tables, the data and query route memos, the tree recompute flag);
  the state of ONE face (client subscriptions, queryables and tokens, future
  interests, the pending-query return table, joined links); and the state of the
  NODE (hosted subscribers and queryables with their redelivery queues, the
  interceptor chains and their cache version, the gossip target and the
  autoconnect policy, the shared-memory relay, the counters).

## 3. Decision: a peer is the region-hat forwarder at node mode Peer

Cost is not weighed (owner, 2026-09-21 on this item; the same direction was
given for this arc on 2026-10-27): the structure is the pin's. A peer node is the forwarder that already exists,
constructed with node mode Peer. Its north hat is the peer hat, in gossip mode
by default and in the link-state mode where `--peer-mode linkstate` asks for it,
which keeps the owner's decision of 2026-08-31 on that extension. Its south
regions are the ones `regions_of(Peer, partition)` gives, and faces are placed
by `region_of`. `LinkstateForwarder` is retired when the planes it serves have
moved, not before.

The owner boundary the R3220 carry named dissolves rather than being decided:
the link-state extension is a flag of the NORTH peer hat, and a partition adds
SOUTH hats, so the two compose without a rule that refuses either. What the
extension does to the north hat is unchanged.

## 4. Order of work

Each step lands alone, keeps every live door's answer unchanged, and is judged
by tests that already exist before it is judged by new ones. The order is part
of the decision, as it was for the router: the structure first, then the planes
over it one at a time, and the retirement last.

1. Make the forwarder's node mode a value, and the region names it reads
   mode-relative. The router remains the default and nothing moves. The step
   also lists, from the code,
   every surface `LinkstateForwarder` has that `RouterForwarder` does not
   (the gossip target, autoconnect, the lifecycle directory, the hosted-handler
   redelivery queues are the candidates), so the later steps are sized by a
   list and not by a guess.
2. A peer constructor and the peer's regions: node mode Peer, north peer hat,
   south client regions, faces placed by `region_of(Peer, ...)`. No plane runs
   over it yet; the tests are the placement tables.
3. The data plane for a peer node, held equal to `LinkstateForwarder` by a
   differential gate: the same inbound frame sequences go to both and the
   frames each emits are compared, as `redecode_gate.rs` holds the second
   dissection pass equal to the first. The peer E2E files that exist are the
   population.
4. The query plane, the same way.
5. The token and interest planes, the same way.
6. The node-level surfaces from step 1's list, each moved or declared absent
   with its reason.
7. `run_peer` takes the new forwarder, `LinkstateForwarder` goes with its tests
   moved, `--gateway-south` is accepted on `--peer`, and the config key moves
   to honoured with the census pins in that commit.

## 5. Step 1, as landed

The forwarder's node mode is a value now. `Tables` holds `node_mode`; the
constructor takes it (`RouterForwarder::build`), every public constructor
still passes `WhatAmI::Router`, and nothing reads a router out of a constant:

- `is_leaf`, `is_peer_hat` and `is_router_hat` take the node mode and ask
  `hat_kind(region, node_mode)`; every production call passes
  `self.tables.node_mode`. Outside the tests, `WhatAmI::Router` is still named
  by the two public constructors and by `mcast_ingress_region`, the multicast
  ingress, which stays a router-only plane until step 6.
- A hat's net is seeded with the node's own mode (`MeshHat::new`), the face
  placement reads it (`place_face`), a partition builds its hats from it
  (`with_south_partition`) and the node clock gates on it.
- `ROUTERS_REGION` is `NORTH_REGION` and `routers_net()` is `north_net()`:
  the region and its graph exist on every node, and what they hold depends on
  the mode. The public admin names (`routers_net_view`,
  `routers_net_node_count`) keep their names; they are step 6.

The router tests are the proof that nothing moved: 258 router tests and 12
region tests pass unchanged in count.

What the list of surfaces measured. Public methods of `LinkstateForwarder`
with no namesake on `RouterForwarder` (61 against 63; 31 are absent), in four
kinds:

- Node as a publisher and subscriber: `publish`, `publish_delete`,
  `publish_qos`, `propagate`, `declare_subscription`, `undeclare_subscription`,
  `declare_queryable`, `undeclare_queryable`. The router hosts through
  `register_local_subscriber` and `register_local_queryable` and has no
  publisher entry; step 6 decides whether the peer's hosted entries move
  onto those two or the router gains the publisher.
- Net policy and gossip: `set_gossip_target`, `set_self_locators`,
  `set_full_linkstate`, `with_trees_delay`, `ingest_inbound_linkstate`. The
  router has `set_peer_region_full_linkstate`, `set_gossip_multihop` and
  `node_locators`; the gossip target and the self locators have no router
  twin yet.
- Interest garbage collection (`routing-interest-pending-gc`):
  `set_interest_timeout`, `pending_interests_len`, `interests_timed_out`.
- Witnesses the tests read: `dot`, `edge_count`, `node_count`, `recomputes`,
  `route_successors_hex`, `tree_children_of`, `net_view`, `client_qabls_seen`,
  `interested`, `interested_queryables`, `publisher_sources`,
  `querier_sources`, `queryable_sources`, `subscriber_sources`,
  `token_sources`. Each moves with the test that reads it.

## 6. Step 2, as landed

`RouterForwarder::peer` builds the forwarder at node mode Peer. It is
test-only: no plane has been held equal to `LinkstateForwarder` for a peer, so
nothing outside the tests can reach a peer forwarder yet. Three placement
tests are the step's evidence:

- the hats are `auto_regions(Peer)` exactly: the peer hat in `North`, a broker
  hat for the clients' south region and for `Local`, no south peer region;
  the north net runs gossip, not full link-state;
- a router and a peer remote are placed in `North` (each gets a link in the
  peer hat's graph) and a client in the clients' region with no link, where a
  router node would put the same peer in its south peer region;
- with a `gateway/south` subregion, the hats are `regions_of(Peer, partition)`
  and the rules place a named peer in `South { id, Peer }`, an unnamed one in
  `North`.

What the tests showed: on a peer node `North` IS the first peer-hat region, so
the accessors that answer "the first peers region" (`first_peers_net`, and the
admin `linkstatepeers_net_node_count` over it) answer the north graph. That is
the pin's meaning of a peer hat, and no router-shaped caller breaks on it; it
does mean step 6 must not read those accessors as "the south peers" for a peer.

## 7. Step 3, publish and subscribe, as landed

`router_forward/peer_differential_tests.rs` plays the same scene into
`LinkstateForwarder` and into the region-hat peer through `FaceForwarder` and
compares what each sent each face after each step, decoded (a declaration's id
and a sequence number are not compared). Five scenes: two peers; a peer, a router
and a client; faces that come up after a subscription; a subscription withdrawn
and a face gone; a client that puts. Each runs in both modes. The population is
these scenes and not the peer E2E files the plan named: those need a foreign
binary and are read on hosted CI, where this gate runs offline in under a second.

- **Gossip, the pin's mode: equal data, two differences, both the pin's.**
  `LinkstateForwarder` sends a new link its own entry and every node it knows,
  where the pin sends the linked neighbours the graph holds, zid only, and
  never self (`zenoh/src/net/protocol/network.rs` @ `// Send all nodes linkstate on new link`);
  the region-hat peer sends the pin's list, graded by its own test. And
  `LinkstateForwarder` re-advertises a declaration to a tree child at the next
  recompute although it told the face at face-up; the pin's peer hat has no
  tree. Both are listed in `explained` with the rule, and the test fails when a
  listed difference stops occurring.
- **Link-state, wz's extension: equal data and equal topology, no allowed
  difference.** Getting there took two rules in the region-hat peer, both for a
  PEER node whose hat net is full link-state and for no other hat: the hat
  relays inside its region along the tree (`face_based`, six rule sites that
  were `is_peer_hat`), and it does not replay declarations at face-up
  (`replay_declarations_to_new_face`), because the replay answers a remote that
  does not speak link-state and a subsystem running the extension has none
  (R2896: "a mode has to be the same across a subsystem"), so the replay
  beside the recompute sent each declaration twice. Each was found by the gate
  failing without it.
- **The pin has no link-state peer mode at all.** `routing.peer.mode` is
  "deprecated and has no effect" in 1.10.1
  (`commons/zenoh-config/src/lib.rs` @ `are deprecated and have no effect`),
  and the peer hat sends to an owned face
  only what came from another region (`zenoh/src/net/routing/hat/peer/pubsub.rs`
  @ `if ctx.subs.is_some() && self.region() != *src_region {`). So the
  extension is wz's, graded against `LinkstateForwarder` and nothing else, as
  the owner accepted on 2026-08-31: its external witness count is zero.

What the gate does not cover and step 3 therefore does not claim: priorities
and reliability channels, ids and aliases, attachments and timestamps, a
three-hop tree, and every plane other than publish and subscribe.

## 8. Step 4, queries, as landed

The same gate carries the query plane: three more scenes (queries between a
peer, a client and a router; a queryable declared before the faces come up; a
queryable's face going down mid-query), with `Queryable`, `Query`, `Reply` and
`Final` steps. A forwarder numbers the queries it relays by its own table, so a
`Reply` or `Final` answers the last `Request` that was forwarded to that face
and is still open, and the compared `Request` leaves its id out; the `Response`
and `ResponseFinal` a querier receives carry the querier's own id, which both
planes must restore, and are compared with it.

- **Link-state: equal, with no code change in the forwarder.** The tree rule of
  step 3 already carried the query route, the reply return and the final. The
  gate is sensitive to it: with the query rule (`mesh_query_block`) put back to
  the pin's face-based form the link-state test fails on the first peer-to-peer
  query, the Request not being forwarded and the querier being sent a final.
- **Gossip: the same single difference, now for queryables too.**
  `LinkstateForwarder` re-advertises a `DeclareQueryable` at the recompute as it
  does a `DeclareSubscriber`; the explained difference covers both. A query from
  a peer to a peer's queryable is forwarded by neither plane in gossip, which is
  the pin's rule for a query inside one region
  (`zenoh/src/net/routing/hat/peer/queries.rs` @ `if self.region() != *src_region {`).
- Non-vacuity: the scenes must deliver answers to a querier in gossip mode, and
  more of them in link-state mode.

What the first pass left, and a second pass paid (three more scenes, steps
`QueryWith`, `ReplyErr` and `Advance`, and a clock injected into both nodes):

- **What a querier asks for** reaches the queryables unchanged and the answers
  return: target `All` and `AllComplete`, each consolidation mode, a timeout and
  parameters. The compared `Request` now carries the target, the timeout and
  the query body.
- **An `Err` reply** is relayed to the querier under its own id, and a query
  nobody answers ends with the relay's own `Err("Timeout")` and the final when
  the clock passes the default deadline; a reply that arrives after it is
  dropped by both.
- **A query open across a recompute**: a router comes up and the tick recomputes
  the tree while a query is pending, and the reply and the final still reach the
  querier; a second query from the new router is answered.

No difference was found, in either mode, beyond the gossip one already listed:
this pass found no defect in either plane. Each thing the scenes claim is
counted in what was sent (a `Request` carrying each target and the timeout, an
`Err` reply, the `Err("Timeout")`, a reply across a recompute), so a scene that
stopped producing one fails rather than passes equal over nothing.

A third pass paid what the second one still listed, which had no reason to be
left (three more scenes, and a `ReplyAfterFinal` step for a reply that loses
the race to its own final):

- **A timeout shorter than the default.** A querier carries 2,000 ms and the
  clock moves 3,000 ms, so only a relay that arms its deadline from the carried
  value ends the query (`ext_timeout.unwrap_or(queries_default_timeout)`): both
  planes send the querier `Err("Timeout")` and the final under the querier's
  own id, and drop the reply that comes after.
- **Consolidation.** A queryable answers one keyexpr twice under each mode and
  both replies reach the querier in both planes: neither plane consolidates at
  the relay, the querier does.
- **Final and reply in every order.** One of two branches ends with no answer,
  the other answers, and the querier's final comes only after both; the finals
  in the opposite order; a reply after its own final is dropped. Equal.

No difference and no defect, and each is counted in what was sent (the
`Err("Timeout")` under the carried deadline, both replies of a consolidated
query, the answer after one branch ended and the final after both).

Not covered in the query plane: a query forwarded across more than one hop of a
tree, which needs the three-hop scene the publish plane lacks too.

## 9. The network gate

The one-node gate scripts what arrives on each face, so it cannot see what only
a network does. `router_forward/peer_network_tests.rs` builds the same topology
from `LinkstateForwarder` nodes and from region-hat peers and wires the nodes to
each other with a deterministic frame pump: what a node sent on a face is
delivered, in order, to the face at the far end until nothing is in flight; then
every node ticks and the pump runs again until a tick sends nothing. Nothing is
handed over: a link-state graph has to be exchanged, a subscription has to be
flooded, a query's answer has to find its way back. What is compared is what
the END POINTS (clients attached to a node) received after each step, with the
duplicates a multiset keeps, and a pump that does not settle is a failure of its
own, so loop freedom is graded by the same run that grades delivery.

Nine scenes: two nodes; a chain of four (a Put and a query across three links);
a star; a ring of four (two paths, a flood that can go round); a diamond; a chain
that grows (a node and its publisher join after the subscription); a line
published from the middle; a subscription withdrawn across three links; a ring
that loses a link (the tree is recomputed and the next Put goes the other way,
then the last way is cut); queries along a line.

- **Link-state: equal in every scene, and exactly once.** Every Put reaches each
  subscriber once across three links, through a hub, round a ring, along two
  equal paths and after a cut; a query along a line is answered and sent exactly
  one final.
- **Gossip: equal, and the equal is meaningful.** A Put crosses one link and
  never a second, in both planes, which is the pin's peer hat (the rule of
  section 7), counted rather than assumed.
- **A defect, found by the gate and fixed in the region-hat forwarder.** A client
  attached AFTER a subscription was told it, unasked, by the region-hat peer and
  by nothing in the pin: the pin's broker hat, which owns a client face, "is
  never the north hat, thus there are no interests to re-propagate"
  (`zenoh/src/net/routing/hat/broker/mod.rs` @ `// 1. The broker hat is never the north hat, thus there are no interests to re-propagate`),
  and a client asks with an Interest, as zenoh-pico in client mode does. The
  token plane already left a client out of the face-up replay on that evidence;
  the subscriber and queryable planes had not. The replay now skips a client
  face. This is a rule of the broker hat and so applies to a ROUTER node too,
  where it was the same deviation: it is a change to the router's behaviour, made
  because the pin is the oracle there as here, and the 266 router tests (264
  and the two of this gate) pass with it; the router's end-to-end legs that need
  a pico or a stock zenohd are read on hosted CI.

## 10. Step 5, tokens and interests

Both gates carry the two planes. The one-node gate gains `Interest`,
`InterestFinal`, `Token` and `Untoken` steps and three scenes (a client asks
what peers declared; a peer and a router ask what a client declared; liveliness
tokens), with what is compared widened to the interest an answer belongs to, the
interests a node propagates and the token declarations. The network gate gains
the same steps for end points and two scenes (an interest across a chain;
liveliness across a chain). Tokens are built under `routing-token-tables`; the
gates are run with and without it.

Two corrections to the harness first, because they were mine and not the
planes': a face that reuses a declaration id replaces what it named, a protocol
violation and no scene, so every declaration now carries an id of its own; and a
retraction carries the id AND the key, as zenoh-pico sends it, since a retraction
by key alone no longer found a declaration with an id.

What is equal: a client's interests (current and future, subscribers, queryables,
tokens) are answered the same by both planes, and an interest answered across
three links is answered the same in both modes.

What differs, the same in both modes, each with the pin's rule, and the region-hat
peer graded against it by `the_region_hat_peer_answers_interests_and_tokens_as_the_pins_dispatcher_does`:

- **An Interest from a router is refused.** The pin's dispatcher refuses it
  (`zenoh/src/net/routing/dispatcher/interests.rs` @ `if self.state.whatami.is_router() {`):
  nothing is sent, not even a final. `LinkstateForwarder` answers with a final.
- **A current Interest from a peer is answered with the declarations the other
  hats hold, then a final** (`zenoh/src/net/routing/dispatcher/interests.rs` @
  `hats[region].send_current_subscribers(` and `@ hats[region].send_declare_final(ctx.reborrow(), msg.id, &src);`).
  This is the dispatcher's release behaviour: a current subscriber Interest from
  a north peer is itself outside the pin's protocol (its peer hat asserts that a
  current Interest from the north asks for tokens only), and the region-hat peer
  does what the dispatcher does with it. `LinkstateForwarder` sends the final
  alone. This one is stated as what it is, a choice between two readings of a
  message the pin does not expect, and not as a defect of either.
- **A token reaches a client that asked for tokens with a future interest.**
  The pin's broker hat propagates a token to a south face that holds a matching
  remote interest. `LinkstateForwarder`'s token plane is partial and does not,
  across one node or across three links (the network gate allows the same one
  difference and requires it to occur).
- **A client's token interest is brokered to the peers, with
  `routing-interest-pending-gc`.** The peer's token table does not hold the mesh
  tier (`dump_interest_tokens`), so `LinkstateForwarder` asks its peers as well as
  its gateways, answers the client with the tokens it holds, owes the final until
  the peers have answered, and withdraws the copy when the client ends its
  interest. The pin's peer hat holds the mesh tier and sends a current-and-future
  interest on only to the faces whose remote bound is south
  (`zenoh/src/net/routing/hat/peer/interests.rs` @ `.filter(|f| f.remote_bound.is_south())`),
  which a peer of this node is not, so the region-hat peer closes the interest at
  once and carries nothing. What the client receives is the same but for the
  final's place; the nodes carry more to get there. This reason exists only in a
  build with both `routing-token-tables` and `routing-interest-pending-gc`: the
  gates were red on hosted CI in the one build that has both (the 83-feature leg
  of Layer C1bnl) and green in the two builds the previous step ran. Both gates
  allow it there and require it to occur, and in no other build.

No defect was found in the region-hat peer in this step, and no forwarder code
changed.

## 11. Step 6, node surfaces, first part

Step 6 is sized by what `run_peer` calls on `LinkstateForwarder` and the region-hat
forwarder lacks, which is shorter than the 31 methods of section 5 because most of
those are witnesses a test reads. It goes in parts, each judged by the two gates.

What the region-hat forwarder already had, so nothing moves: autoconnect
(`enable_autoconnect_into`), the lifecycle directory, `admin_sessions`, the hosted
queryable and subscriber registrations, the interceptor install and its counters,
the query timeout, and the topology mode (`set_peer_region_full_linkstate`, which
at node mode Peer is the north peer hat).

Moved in this part, all test-only until step 7 gives them a caller (as step 2 did
for the constructor):

- **The node's own Put** (`publish`, `publish_qos`, `publish_delete`). The pin
  routes it as a message of a face in the `Local` region, a client of the node
  that holds no wire (`zenoh/src/net/routing/gateway.rs` @ `Region::Local,`).
  That face is `LOCAL_FACE`, never registered in `faces`, and the Put takes the
  route of a leaf-region Put: the client faces that subscribed, the hosted
  subscribers, every mesh, a multicast group. `express` is threaded to the egress
  of those legs, which until now were always sent without it.
- **The node's locators** (`set_self_locators`) on every mesh hat's net, because
  the pin asks its runtime for them at every net's message
  (`zenoh/src/net/protocol/network.rs` @ `get_locators_noloopback()`).
- **The size of the north graph** (`north_net_node_count`, `north_net_edge_count`),
  which a peer reads as its one graph. The router's `routers_net_node_count` is
  the same read.

The gates gained a `NodeSession` seam both planes implement, a `NodePut` and a
`NodeDelete` step, a graph size compared after every step, a scene of a node
publishing (two peers, two clients, a withdrawal, a face going down), and a scene
of a node publishing along a chain of five. Three differences surfaced, each
`LinkstateForwarder` leaving the pin, and none a defect of the region-hat peer:

- **The node's Put reaches the clients that subscribed**, in both modes. The pin's
  broker hat routes to every owned face with a subscription whatever region the
  message came from (`zenoh/src/net/routing/hat/broker/pubsub.rs` @
  `if ctx.subs.is_some() {`); `LinkstateForwarder::publish` reaches its tree
  children and its gateways and no client face. The network gate allows it and
  requires it to occur; every face the old plane reaches gets the same message.
- **The graph a gossip peer keeps**, gossip mode only. The pin's `add_link` adds
  a node for what a neighbour told it and not for a link coming up
  (`zenoh/src/net/protocol/network.rs` @ `if self.full_linkstate || self.gossip_multihop {`),
  and a gossip flood forms no edge; `LinkstateForwarder` adds the node at once
  and an edge after a recompute. Nothing routes by it. The link-state extension
  keeps the same graph in both planes.
- **A list sent when a link goes down**, gossip mode only. The pin's
  `remove_link` forgets the link and sends nothing in gossip
  (`zenoh/src/net/protocol/network.rs` @ `self.graph[self.idx].links.retain(|dest, _| dest != zid);`);
  `LinkstateForwarder` tells the faces that remain its own entry.

Declared absent, with the reason, so step 7 does not look for them:

- **`set_gossip_target`.** In the pin the target gates which neighbours a node's
  locators are told to (`zenoh/src/net/protocol/network.rs` @
  `self.gossip_target.matches(target_whatami)`), and who receives a flood is
  decided by the face's region. `LinkstateForwarder` uses it as a flood gate, and
  nothing outside its own tests ever calls it, so no door carries the setting.
  The router forwarder says the same of itself (`set_gossip_multihop`).
- **The interest garbage collector** (`set_interest_timeout`,
  `pending_interests_len`, `interests_timed_out`). It collects the copies of a
  client's token interest that `LinkstateForwarder` brokers to its peers. The
  pin's peer hat sends such an interest on only to south-bound faces and the
  region-hat peer holds none, so there is nothing to collect
  (section 10, `TOKEN_INTEREST_BROKERED`). Step 7 has to move
  `wz_peer_interest_pending_gc_pico_interop`, which asserts the brokered copy.

Still to do in step 6 after this part: the admin sources, the north net view and
the counters `run_peer` prints, which part three has.

### Part two: the node's declarations and hosted handlers

The node's own declarations are the pin's: a session declares a subscriber or a
queryable WITH its callback, and a declaration without one does not exist. So
the four bare entries are not moved but replaced. `register_local_subscriber`
and `register_local_queryable` are the declaration, and what was missing was
their inverse: `unregister_local_subscriber` and `unregister_local_queryable`,
test-only until step 7. A retraction goes through the fold that decided the
registration (`repropagate`), so a client holding the same key keeps the interest
alive, and a complete queryable leaving a key that a client's incomplete one
still holds lowers the advertisement to incomplete instead of withdrawing it, as
the peer plane's union refcount does (the hosting scene holds the two planes
equal at both).
`LinkstateForwarder`'s bare `declare_subscription` and `declare_queryable` are
declared absent. Two calls in `run_peer` use the bare form, the demo's
unsubscribe-after-data flag, and step 7 moves them to a registration with a
no-op handler.

The refused call is no longer dropped. A hosted subscriber that publishes into
its own pattern was refused when it was called from inside itself, and the
router's twin dropped the sample with a warning because nothing could reach
that arm. A node that can publish reaches it. The sample is now queued on the
thread, bounded at the pin's reception channel size with the oldest dropped, and
given to the handler by the outermost delivery of the thread once the handler
is out. The queue is per thread because the refusal is: only a call from inside
the handler is refused, and that is on the handler's own thread. A handler taken
back is marked, and what was queued for it is skipped.

Not moved, and the reason: a hosted handler cannot unregister ITSELF from inside
its own body, which the peer plane allows (`undeclare_purges_a_pending_self_echo`).
The router's handler runs under the tables' read guard and a retraction writes
the tables, so it would wait for the guard it runs under. This is the rule the
router's hosted handlers have always had, and it is stated rather than removed.
A hosted queryable's redelivery is not built either: a query originates from a
face, the node has no querier entry on this plane, and a handler that queries
its own key has no path to do it.

The gate gained `host_subscriber`, `unhost_subscriber`, `host_queryable` and
`unhost_queryable` on `NodeSession`, a `hosted` plane compared after every step
(what each hosted handler was given), and a scene of a node hosting. Two more
`LinkstateForwarder` departures surfaced, both in both modes:

- **The node's own Put reaches the subscribers it hosts.** The pin delivers to
  the session's own callbacks unless the Put was sent to remote destinations only
  (`zenoh/src/api/session.rs` @ `state.subscriber_callbacks(true, SubscriberKind::Subscriber, &wire_expr, false);`);
  `LinkstateForwarder::publish` reaches none.
- **A queryable declared again with what it already was.** A second, incomplete
  queryable on a key whose first is complete changes nothing the other regions
  fold out of it, and the pin propagates a declaration only when that changes
  (`zenoh/src/net/routing/dispatcher/queries.rs` @ `tables.hats[dst].propagate_queryable(ctx.reborrow(), res.clone(), other_info);`).
  `LinkstateForwarder` declares the key again, complete as before.

Three tests grade the queue on the region-hat peer: the single echo is given once
after the delivery, a handler that always echoes is given the queue's size and the
delivery ends, and a retracted handler is given nothing of what was left in the
queue.

### Part three: the admin legs, the net view and the counters

The router's admin host had three legs of the declarations (`subscriber`,
`queryable`, `token`) and `LinkstateForwarder` had five: the `publisher` and
`querier` legs are folded from the FUTURE interests the faces declared, which is
what a publisher and a querier put on the wire. The region-hat forwarder now has
them too (`RouterDeclarationsView::publishers`, `queriers`), which the router
host gets as well, since it is the same view. Two things carry them:

- A mesh face's future subscriber or queryable interest is stored for the admin
  legs and for nothing else, under the mesh role that keeps the face off every
  push path (`store_reporting_only_interest`, the peer plane's admission). Before,
  the region-hat forwarder stored a CLIENT's interest only.
- The tier of a row is the kind of hat that owns the face it came from, as in the
  pin: a broker hat reports its faces as `clients`, a peer hat as `peers`, and a
  router hat reports none (`zenoh/src/net/routing/hat/router/pubsub.rs` @
  `fn sourced_publishers`, which returns nothing). An interest from a face the
  router hat owns is left out.

The north net view needs no new method: `peers_net_view` reads the first peer-hat
region, which on a peer node is the north region. The counters `run_peer` prints
gain `client_queryables_seen` and `north_interested`, test-only until step 7; the
other counters it reads already exist on both planes.

The gate gained an `admin` plane, a `counters` plane and a `linkview` plane (the
DOT the `linkstate/peers` leg renders), each compared after every step, a scene of
queriers and publishers declaring themselves, and a count of which tier each leg
names over all scenes, because the first run of that count showed that no scene
had ever reached the `querier` leg. With the scene the two planes agree on every
row of every leg, the tiers included, except the node itself:

- **The node named among the sources of its own declarations.** `LinkstateForwarder`
  names the node among the `peers` of a subscription it hosts and counts it among
  the nodes `interested` in a key; the region-hat forwarder keeps the rule the
  router's host has always had, that a node is not a source of its own
  declarations. Both leave the pin, whose broker hat serves the `Local` region and
  names the node's own face among the `clients`
  (`zenoh/src/net/routing/hat/broker/pubsub.rs` @ `srcs.clients.push(face.zid);`).
  Decided in section 12: the pin's two rules, built at steps 6d and 6e.
- **The graph of a gossip peer** reaches the `linkview` plane too, as it does the
  `graph` plane (`GOSSIP_GRAPH`).

The `linkview` plane compares the DOT and the route successors together
(`route_successors_hex`), and the `graph` plane the node and edge counts
(`edge_count`). Declared absent: `interested_queryables` (a test witness the
shipped node never calls), `with_trees_delay` (the region-hat forwarder takes its
clock whole), `ingest_inbound_linkstate` and `propagate` (it ingests through
`forward` and floods through its hats), `tree_children_of` and `recomputes` (each
moves with the unit test that reads it at step 7). `with_drop_future_timestamp`
has a twin on the region-hat forwarder already.

With part three the list of section 5 is answered: each surface is moved, already
there, or declared absent with its reason. What step 6 leaves for step 7 is a
call-site migration, not a missing surface, and the admin output and structure of
section 12 (steps 6d and 6e).

## 12. Decision: the node's own face, and the north source (owner direction, 2026-10-28)

The question part three left open was who a node's own declarations name as their
source in the admin legs. It is decided by the pin's structure and not by any of
the three behaviours the tree has, none of which follows it. Cost is not weighed;
the structure is the pin's.

What the pin does, read from the pinned checkout and not from a running zenohd:

1. A node's own session is a FACE of the dispatcher in the `Local` region, whose
   mode is client (`zenoh/src/net/routing/gateway.rs` @ `Region::Local,` and
   `commons/zenoh-protocol/src/core/region.rs` @ `Region::Local => Some(WhatAmI::Client),`).
   The broker hat serves it, so its declarations are the face's declarations like
   a client's, and the legs list the face's zid among the `clients`
   (`zenoh/src/net/routing/hat/broker/pubsub.rs` @ `srcs.clients.push(face.zid);`).
2. The dispatcher's merge adds the NODE's own zid to the north bucket of every
   entity a SOUTH region sourced, by the mode of the north hat, and the `Local` and
   every client region are south
   (`zenoh/src/net/routing/dispatcher/tables.rs` @ `fn add_north_source(`): `peers`
   on a peer node, `routers` on a router. It applies to subscribers, queryables and
   tokens and not to publishers and queriers.

So on a peer node a subscription the node hosts is
`{routers: [], peers: [self], clients: [self]}`, and one a client c holds is
`{routers: [], peers: [self], clients: [c]}`; a neighbouring peer's is
`{routers: [], peers: [that peer], clients: []}` and gets no north source, because
the north region is not south. A router node does the same with `routers`.

Against it, as measured by the gate and by reading: `LinkstateForwarder` names the
node among the `peers` of what the node HOSTS and nowhere else (which is what the
e2e files pin), so it has neither rule as the pin states them: a client's
subscription gets no north source, and a hosted one gets no `clients` entry. The
region-hat forwarder had neither rule, which is also the router's state, and a
router unit test pinned it from a reading of the router hat's own filter that is
about the router hat's table and not about the merge.

The structure that follows, in the order it is built:

- **Step 6d, the output.** The admin fold of the region-hat forwarder applies the
  merge rule: for the entities a south-bound hat sourced, the node is added to the
  north bucket by the north hat's mode. The node's own hosted declarations are
  listed among the `clients` under its own zid. The router host changes with it, as
  it shares the view, and its unit tests are changed in the same commit to the
  pin's body. Landed. The three e2e files that pin `clients: []` for a hosted
  declaration (`wz_peer_adminspace_to_pico_zget`, `wz_peer_adminspace_introspection`,
  `apfull_adminspace_pico_interop`) drive `run_peer`, which is still
  `LinkstateForwarder` and so still answers `clients: []`; they change in step 7,
  in the commit that moves `run_peer`, to `{"routers":[],"peers":[<zid>],"clients":[<zid>]}`.
  None of those legs can be run here: the first hosted run is read for them.
- **Step 6e, the structure.** The hosted entries stop being a side list. They
  become the declarations of the `Local` face in the `Local` broker hat, with the
  handler held by the declaration, so that routing, the fold of what the node
  advertises, the client delivery and the admin legs read one table for the node's
  own declarations and for a client's, as the pin does, and the `host` contributors
  of the fold (`local_subscribers`, `local_queryables`) go. The output of 6d does
  not move; the gates hold it. Landed, in two parts:
  - **The declarations.** The node's subscriptions and queryables are held by the
    `Local` broker hat under `LOCAL_FACE`, keyed by declaration id as a client's are.
    `Holder::Host` and its eight arms are gone: the fold reads the hat. The admin
    legs name the face by the node's zid. What the session does with a Put or a Query
    addressed to it stays the session's callbacks (`local_subscribers`,
    `local_queryables`), which are kept for delivery only, as the pin keeps them in the
    session and not in its tables. The folds that mean "the clients a router has" or
    "who a wire send reaches" read `client_regions`, every region but `Local`.
  - **The query route.** The node's face is a branch of every query, as it was never
    before: the router answered from its hosted queryables only when nothing else was
    routed to. It now answers beside the others and closes the query only when it is the
    whole route; under `All` and `AllComplete` the two planes agree on the new scene
    (a hosted queryable and a client's on one key). Under BestMatching the planes
    differ, and the pin says which is right: it computes the final route region by
    region, `for dst in rtables.hats.regions()` calling `compute_final_route` for each, so the `Local` hat answers
    for itself beside the best of every other region. `LinkstateForwarder` answers from
    its own queryable and asks no one else, and the gate records that as its departure
    (`BEST_MATCHING_PER_HAT`).

The gate's reason `HOSTED_IN_ADMIN_LEGS` is therefore not a standing allowance: at
6d it is replaced by the two rules above, graded on the region-hat forwarder
against the pin, and the `LinkstateForwarder` side is a departure recorded as the
others are (the first rule missing for a hosted declaration).

## 13. Open

- **The router's BestMatching was one winner across the meshes and the clients; the
  pin's is one for each region. Fixed (owner, 2026-10-28).** Step 6e read
  `compute_final_route` for the `Local` hat and found that the pin 1.10.1 runs it once
  for every hat and merges the routes, where `best_query_winner` took the globally
  nearest complete queryable and forwarded to that one (its comment cited a union route
  sorted by distance, the shape of an earlier layout). A router with a complete
  queryable in the router region and another in the client region forwarded the query to
  one of them and the pin forwards it to both. `forward_request_best_matching` now picks
  per region: each mesh region's nearest complete queryable (the inbound direction and a
  refused hop left out), each client region's lowest complete face, and all of a region's
  matching queryables where it has none complete; the node's own face is the `Local`
  hat's pick. It changes what every router with several regions sends. The old test that
  pinned the global rule, `best_matching_prefers_a_local_client_over_a_mesh_queryable`,
  is now `best_matching_asks_each_region_for_its_nearest_complete_queryable`, and
  `a_region_with_no_complete_queryable_is_asked_whole_beside_another_regions_pick` holds
  the per-region fallback. Read the first hosted run for the router query legs.

- The size of step 1's list is unknown until it is made, and the number of
  rounds after it follows from it. The router's own program ran from round 2865
  to round 2898 and its follow-ups ran past round 3220.
- Hosted verdicts for the peer E2E files that need a foreign binary are not
  available locally; steps 3 to 5 depend on reading them.
- Peer-mode partitions are witnessed against a stock zenohd only after step 7.
