# Pool monitor

`pool-monitor` (capability, off by default, `WZ_CAP_POOL_MONITOR`) lets a node say how full each of
its fixed pools is and how full each has been. It is wz's own: no upstream library keeps the
number, so it is off in every original.

## What a pool is

A fixed pool is a table or a stage of declared capacity. It holds at most `N` entries and refuses
the next one: the session slot table, the id-keyed tables a peer writes (its keyexpr aliases, the
subscribers, queryables and tokens it declares), the stage of replies a queryable has staged, the
reassembly slots. Each already counted what it refused, in a field of its own. That left two
questions without an answer:

* **How many pools does a node have, and which is the full one?** The counters were scattered
  over five files and nothing listed them, so a node that refused something could not say which
  table it was.
* **How close did a pool that never refused come?** A refusal count says a pool was too small. It
  does not say by how much, and it says nothing of a pool that was one entry short of refusing.
  The number that answers it is the high-water mark: the most entries the pool has held.

## The model

`wz_session_core::pool_gauge`:

| Item | What it is |
|---|---|
| `PoolStat` | name, capacity, entries held, high-water mark, entries refused |
| `PoolGauge` | how a pool answers: `pool_stat(name)`. The owner names the pool, because one table type is two pools in two places |
| `HighWater` | the mark, the only state a pool stores for this |

The mark is `Option` in a `PoolStat`: `None` is a build that keeps none, which is not zero. A reader
that sees `None` knows the pool's past is not known, and `PoolStat::has_been_full` says so
(`Some(true)` when the pool is full now, `None` when it is not and no mark is kept).

## What it costs

`HighWater` has no field without the `pool-monitor` feature, so a table that holds one is the size
it was, and `deploy/session_slot_bytes.json` does not move. With the feature a pool stores one
`u32` and a pool records it where an entry is added: one compare in the insert path of a pool that
is already doing a bounds check. The session slot table counts its taken slots only in a build
that keeps the mark.

## Pools that answer today

| Pool | Owner type | Counts of its own |
|---|---|---|
| id-keyed tables a peer writes | `id_map::FixedIdMap` | rows, refusals |
| session slots | `session_slot::SessionSlots` | taken slots, refusals |

## Not yet

The reply stage's two tables, the reassembly slots, the pump and task cells, and the listener's
lanes keep their own counters and do not yet answer as pools. Nothing lists a node's pools yet, and
nothing serves them. The trait that lists them (an owner calls a visitor once per pool, so a build
with no heap lists as one with a heap does) and the document a node publishes, with the resource
snapshot's admin-space route, come with the first reader, so that neither exists without one.
