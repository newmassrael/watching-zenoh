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

## 8. Open

- The size of step 1's list is unknown until it is made, and the number of
  rounds after it follows from it. The router's own program ran from round 2865
  to round 2898 and its follow-ups ran past round 3220.
- Hosted verdicts for the peer E2E files that need a foreign binary are not
  available locally; steps 3 to 5 depend on reading them.
- Peer-mode partitions are witnessed against a stock zenohd only after step 7.
