# Router data plane: scaling design

Status: proposed. A design note, not a registered document (see CLAUDE.md, "SSOT contract").

This note says why the AP router's per-message cost grows with the number of connected subscribers,
what the data plane has to guarantee instead, and the order in which to change it. Every number below
was measured with the tools named in section 6; nothing here is a claim about hardware other than the
host it was measured on, and each measurement is one run per cell.

## 1. What was measured

Setup: `wz-ap-demo --router-hat` (release profile, thin LTO, one codegen unit, `preset-ap-client` plus
`router-hat-router`) pinned to two cores of one host; clients are `wz-ap-demo --sessions` processes on
other cores of the same host, each session subscribing to its own key and publishing to its neighbour's.
CPU time is the router process's user plus system time from `/proc/<pid>/stat`; the number of messages
forwarded is the router's own `forwarded mesh data (N push(es))` counter. The offered load is 12.8k
messages per second in every row, so the rows differ in the number of subscribers and in nothing else.

| Subscribers | CPU per forwarded message, steady | With 16 sessions/s joining and leaving |
|---|---|---|
| 256 | 22.1 us | 25.9 us (+17%) |
| 1024 | 38.5 us | 55.7 us (+45%) |
| 4096 | 129.4 us | not measurable (see below) |

A fit of the steady column is roughly `17 us + 0.03 us * subscribers`: the cost of one message depends on
how many subscribers exist, not on how many it is delivered to (one, in this workload).

At 4096 subscribers the router thread reached 91% of one core and forwarded 7.0k messages per second of
the 12.8k offered. Within about twelve seconds 4347 faces went DOWN (lease expiry), after which the
steady population was gone. The router degraded by dropping its links, not by shedding load.

Two settings decided the rest of what was seen and are recorded because they are not the defaults a
reader would guess:

- `max_sessions` is 1000 by default (upstream's default as well). The 1001st session is refused; a
  run with more subscribers than that measures the refusal, not the router.
- With `runtime-tokio-uring` (part of `preset-ap-full`) each face holds a 32 MiB registered buffer
  region, measured as 33.8 MiB resident per face. Without it a face costs about 87-100 KiB. The router
  numbers above use the build without it.

## 2. Why the cost grows: findings

Each finding is a function at commit `f65af9717` of `crates/wz-runtime-tokio/src`.

F1. Delivery visits every face. `deliver_to_client_subscribers` (router_forward.rs) obtains the faces a
message goes to from the cached `client_route`, as a sorted list, in constant time. It then delivers
through `fan_out_tier_qos`, which iterates every face the router holds, filters by tier, and for each
one calls `peer_zid_routing` before asking the per-face closure whether the face is a target. The
closure used for client delivery ignores the zid and only tests membership of the list it already has.
`peer_zid_routing` (peer_identity.rs) takes the session's mutex, clones a `Vec<u8>`, and converts it
with `Zid::try_from`. With one target and N faces that is N-1 wasted lock, copy, convert and free
sequences per message. A profile with call chains (frame pointers on, 1024 subscribers) put
`peer_zid` at 13.3%, `Zid::try_from` at 6.5%, `memmove` at 7.5% and the loop body of `forward` at
18.8% of cycles, every one of them called from `RouterForwarder::forward`.

F2. A face's identity is read from the session each time. `RouterFaceState` has a `peer_zid` field,
but only under `adminspace-introspection-handlers`, where a single reader (the admin `Sources` body)
uses it. Identity is a fact about a face in every build; the data plane is a reader in every build.

F3. A change to the subscription table discards every cached route. `RouteCache::get_or_compute`
(route_cache.rs) clears the whole map when the table version differs from the one it was filled at.
After one subscribe or unsubscribe, the next message for each key recomputes its route from scratch
(`client_route` scans the subscriptions; on a miss, `names_a_resource` compares keys across every
client). The cost of one flush is proportional to (keys in use) x (subscriptions), and a service where
devices come and go flushes continuously. The churn rows above are consistent with this; they do not
prove it, because the cost of accepting and tearing down a session is in the same number.

F4. The forwarder is single-threaded by construction (`Rc`, `RefCell`). A second core does not help the
data plane; throughput is bounded by `1 / (cost of one message)`.

F5. Nothing protects the control plane from the data plane. When the one thread is saturated, keepalive
and lease handling wait behind data, so links expire and the load that caused it is replaced by a
reconnect storm.

## 3. Invariants the data plane has to hold

I1. The cost of forwarding a message whose route is cached does not depend on the number of faces or
subscriptions the router holds. It depends on the number of faces the message is delivered to.

I2. Computing a route costs in proportion to the subscriptions that match the key, not to all of them.

I3. A subscribe or unsubscribe invalidates only the cached routes whose key intersects the declared key.

I4. Keepalive and lease processing is never delayed by data. Under overload the router sheds data
(counted, observable) and keeps its links.

I5. What is on the wire does not change: interoperability with the reference router and with the
embedded client, ordering per (face, key), reliability and priority handling, and every access-control
decision stay as they are. These changes are internal to how a route is represented and found.

I6. Each invariant above is held by a test that can fail for exactly one reason (section 5).

## 4. Design

### 4.1 A route is a list of targets, and identity is stored (I1)

- A face's routing zid is stored in `RouterFaceState` unconditionally and set once, when the face is
  registered, as a `Zid` (a small `Copy` value). `peer_zid_routing` stays the one place that derives it
  and is called from register, not from the per-message path.
- Delivery takes the target list and looks each target up in the face table by id. The loop body that
  checks egress access control, sends, and counts is moved out of `fan_out_tier_qos` into a helper both
  paths call, so the access-control and accounting rules exist once.
- `fan_out_tier_qos` keeps its contract for the callers that really do ask every face (topology floods).
  The client-delivery and tree-forward callers move to the targeted path.
- A face that has gone is absent from the table, so a cached target that outlives its face is skipped.
  Face removal also bumps the version of the routes that held it (4.2), so it is not skipped for long.
- Landed: the stored zid, the shared egress helper, and the targeted fan-out for client delivery. The
  tree-forward path (`forward_push_tier`) still walks the faces of its tier, now reading the stored zid
  instead of deriving it; its targets are zids, so moving it to the targeted path needs a zid-to-face
  index, which is not built until a measurement of a router-heavy mesh asks for it. The router tier
  holds a handful of faces; the clients are the population that grows.

### 4.2 Subscription index and incremental invalidation (I2, I3)

- Subscriptions with no wildcard are kept in a hash map from key to the set of faces; a message whose key
  is a literal finds its literal subscribers in constant time. Subscriptions with a wildcard are kept in
  a trie over the key's chunks, whose traversal cost depends on the wildcard subscriptions that could
  match, as the upstream resource tree's does. The wildcard and intersection semantics are the existing
  ones (`keyexpr_intersects_target`); this changes how candidates are found, not what matches.
- A cached route is attached to the key it was computed for. A declaration for key K marks stale the
  cached keys that intersect K, found through the same index. Nothing else is recomputed.
- The resource test (`names_a_resource`) becomes a lookup in the index rather than a scan.

### 4.3 Control plane before data (I4)

- Keepalive and lease handling for a face does not wait behind that face's, or any face's, data.
- A face is served at most a fixed number of messages per scheduling round, so one busy face cannot
  starve the rest.
- When the per-face or router-wide queue passes a bound, data messages are dropped and counted
  (reliable and best-effort treated as the protocol defines them); links are kept. The counter is
  exposed on the admin space next to the existing ones.

### 4.4 Using more than one core

The data plane stays single-threaded per router process. The deployment shards instead: the service
already assigns each group to a slot and each slot to an instance, and a router process per slot range
serves that range's devices. This uses every core without changing any ordering guarantee, bounds the
number of subscriptions per process, and is the same table the application needs for horizontal
scaling. A multi-threaded data plane is not planned; section 7 says what would make it necessary.

## 5. How each invariant is held

This repository's own record is that a time threshold on a shared runner generates flakes (the
decode-cost lane in `scripts/run-ci.sh` asserts none, for that reason). So the invariants are held in
two different ways, and a timing number is never what fails a build.

Structural invariants are asserted on counters, which are exact. A counter is what a router already
keeps for the same purpose (`client_route_computes` is one) or a new one beside it.

| Invariant | Test | Asserts |
|---|---|---|
| I1 | a router holding 64 client faces forwards one Push to one subscriber | faces visited equals 1; only that subscriber was sent a frame |
| I1 | the same with 1024 faces | the same numbers, so the count does not depend on the table |
| I1 | a face's zid after register | the stored zid equals what the session reports, so the path reads it and does not derive it |
| I1 | a targeted fan-out over a vanished face and a face of another tier | only the target of the tier is asked; every target is counted as visited |
| I2 | a literal key's route is computed by a lookup | routes computed equals 1 after one publish and stays 1 after more |
| I3 | after a subscribe for an unrelated key, a cached route is served | `client_route_computes` unchanged by the next publish to the cached key |
| I3 | after a subscribe for an intersecting key, that route is recomputed once | `client_route_computes` increases by one |
| I4 | a router past its queue bound under a data flood | data dropped is counted; faces going DOWN is zero |
| I5 | the existing interoperability tests against the reference router and the embedded client | unchanged |

Timing is measured, not asserted. One opt-in lane runs the real binaries (`wz-ap-demo --router-hat`
and `--sessions`) at the subscriber counts and churn rate of section 1 and prints the table of that
section. What it does assert is the population, as the decode-cost lane does: every session
connected, none refused, no face went DOWN in the measurement window, and the router forwarded at
least 80% of what was offered. A run in which any of that fails measures something other than the data
plane, and says so.

The structural tests land with the change that makes each of them pass, so the repository never
contains a red gate; most of them fail today for the reasons in section 2. The measurement lane lands
first, so the starting point is a number committed with the tool that produced it and not a number
remembered.

## 6. Tools

The measurements used `wz-ap-demo --router-hat <addr> --max-sessions <n>` and
`wz-ap-demo --sessions <file>` (`subscribe` and `publish` driver roles). The router was started under
`taskset` and read through `/proc`. The profile used `perf record -g` on a build with
`-C force-frame-pointers=yes`; without frame pointers the call chains are cut at the first frame.

## 7. Not decided, and what would decide it

- Whether the wildcard trie is needed at all for the service this router carries. Subscriptions there
  may all be literal. Section 4.2 builds the literal path first and the trie only if a measured workload
  with wildcard subscriptions shows the scan.
- Whether a multi-threaded data plane is ever needed. It would be if one slot range cannot be served by
  one core after 4.1 and 4.2 and cannot be split further. The measurement that would show it is the
  single-process throughput after those changes, on the host class the service runs on.
- The queue bounds and the per-round message count of 4.3. They are tuned against the I4 test, not
  chosen in advance.
