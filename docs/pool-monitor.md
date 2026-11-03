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
| pump cells | `session_drive::PumpSlots` (`wz-runtime-coop`) | taken cells, refusals |
| task cells | `static_executor::ExecutorState` (`wz-runtime-coop`), as `CoopRuntime` | cells holding a task or an unread result, spawns refused for want of a cell |

The task table counts a spawn refused because the task is too large for a cell apart
(`Refusals::too_large`): that is not a want of room, and a larger table would not cure it, so
the pool's `refused` is the spawns that found no free cell and no more.

## Listing the pools

An owner of pools implements `PoolList::visit_pools(&self, visit)`: it calls `visit` once per
pool, in a fixed order, so a build with no heap lists its pools as one with a heap does, and
nothing is collected. The MCU session host (`wz-session-mcu`'s `SessionHost`) is the first owner:
it lists `session-slots`, then `pump-cells`, then `task-cells`.

`write_pool_document(&owner, &mut writer)` writes what an owner lists as a document, in JSON
without whitespace and without an allocator:

```text
{"version":1,"pools":[{"name":"session-slots","capacity":4,"in_use":1,"high_water":3,"refused":0}]}
```

`high_water` is `null` in a build that keeps no mark, which is not zero. A pool's name is lower-case
letters, digits and `-`; the writer refuses any other name with an error, so a name never breaks
the document. A reader that does not know `version` reads none of it.

## Not yet

The reply stage's two tables, the reassembly slots and the listener's lanes keep their own
counters and do not yet answer as pools. Nothing serves the document: a node's program
calls `write_pool_document` on the host it holds and sends the text where it wants, and the
admin-space route and a `wz_ext_*` door are for the first consumer that asks for one. No firmware
image of the repository turns the mark on or prints the document yet.
