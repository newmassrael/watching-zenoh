# Declaration sync pacing

Status: design, not built. Written 2026-10-25 so that the decision it needs is made once, by the
sessions that own the pieces it touches, and not rediscovered in a half-built change.

## What it is

When a node has a session to a peer that holds none of its declarations (a new session, or the
session after a reconnect), the node tells the peer everything it has declared: key expressions,
subscribers, queryables, tokens and interests. Today this is one call, `replay_declarations`
(`crates/wz-session-core/src/session_actions.rs`), which walks the declaration cache and emits
every entry before it returns. That is upstream's behaviour and the default of this design.

A node that wants the peer not to take a burst of control messages at once, or that must not spend
more than a bounded amount of work in one turn of its loop, needs the replay in bounded turns:
a number of messages per turn, a wait between turns, and a limit on how long it waits for the
peer's answer to an interest. That is the policy `declaration-sync-pacing` and its three limits.
It is the same shape as the bounded-turn work the router already does for fan-out.

Paired with it is a question the node cannot answer today: has it finished telling its peers what
it has declared? Without pacing the answer is nearly always yes by the time the call returns, so
nobody asked. With pacing it is a real state, and the node needs to be able to wait for it.

## The knobs

| Name | Kind | Default | Meaning |
|---|---|---|---|
| `declaration-sync-pacing` | policy, bool | off | Off: the replay is one call, as upstream. On: it runs in turns. |
| `DECLARATION_SYNC_BURST_MESSAGES` | limit | 8 when on | Messages emitted in one turn. Zero is refused. |
| `DECLARATION_SYNC_INTERVAL_MS` | limit | 10 when on | Wait between turns. Zero is refused. |
| `DECLARATION_SYNC_FINAL_TIMEOUT_MS` | limit | 1000 when on | How long the sync waits for the peer's final for an interest before it counts the interest as unanswered and goes on. Never longer than the session's own lease. NOT DECLARED YET: it is declared with phase 3, the first code that reads it. |

A value of a limit is refused at build time when it is zero (the heap runtime asserts it where it
reads them), and the timeout, when it is declared, must not be shorter than the interval; every
limit here is declared in `deploy/wz-config.toml`.

## What has to stay true

1. **Order.** The peer's tables are empty. A declaration that names a key expression by its
   mapping id is valid only after the declaration of that key expression. Replay is in the host's
   replay order, in every turn, and that order puts everything a declaration depends on before it.
2. **A live declaration made during the replay is sent when everything it depends on has been.**
   Its place in the replay order is after what it depends on, so there are two cases: its place is
   at or past the cursor, and the replay will reach it, so the caller emits nothing; its place is
   before the cursor, so everything it depends on is already at the peer, and the caller emits it
   at once. An aliased declaration sent ahead of the key expression it names is a protocol error on
   the peer, and neither case does that.
3. **A live undeclaration made during the replay is sent if and only if the peer already saw the
   declaration.** If the replay has not reached it yet (its place is at or past the cursor), the
   entry is dropped and nothing is sent; the peer never learned of it. If it has (before the
   cursor), the retraction is sent.
4. **Exactly once.** Each declaration is emitted once per session, whatever the interleaving of
   replay and live calls, and a refused send is retried at the entry it failed on and never from
   the beginning of the list.
5. **A close, reset or reconnect during the replay discards the cursor.** The next session's peer
   has nothing, so its replay starts at the beginning, and a cursor is never resumed on another
   session.
6. **Off is byte-identical to today.** A build with the policy off emits the same frames in the
   same order as before this existed, which a pair of tests names.
7. **Every session that replays is paced, per session.** A dialled session and an accepted one
   both replay to their peer, so each has its own cursor.
8. **A multicast group is not paced.** It declares nothing and has no peer to wait for.
9. **"Synced" is a statement about ESTABLISHED sessions, not about whether a session exists.** The
   node is stable when every established session's cursor is at the end of its list, its
   listeners are bound, and every connection it was configured to make and to wait for is
   established. A listening node with no client yet is stable (nothing is owed); a node that must
   connect is not stable until it has, and a session that exists but is not yet established, or
   whose cursor is short of the end, makes the node not stable.

## Three hosts, three shapes, one cursor

The first draft of this note put the cursor in the heap runtime's declaration cache. The owners
showed that cannot be the shared part, because the three hosts keep their declarations in three
different shapes:

| Host | Where its declarations live | Declares at run time | Today's replay |
|---|---|---|---|
| Heap runtime (tokio) | one ordered `Vec` of cached declarations, `SessionCore::declaration_cache` | yes | `replay_declarations`, one call, from the reconnect driver |
| Cooperative engine | separate lists by kind (key expressions, subscribers, interests, queryables, tokens, liveliness) | yes | `Core::redeclare`, one call, kinds in a fixed order |
| Fixed-memory slot node | one `&'static [Declaration]` built at start, wire id = index + 1 | no | `replay_declarations` (`slot_client`), one turn per established session over a per-session `ReplayCursor`, a burst and an interval from `ReplayPacing` (in `wz-session-core`, the one type the heap runtime shares) when the policy is on and the whole list when it is off, and a per-session next-turn time that holds the next turn back; a refused send resumes at the entry it failed on (it was the whole list from index 0 before phase 4 landed for this host) |

What is common is not a cache. It is a position in a sequence the host can recite in a fixed order.
So the shared part is a pure type with no list, no clock, no heap and no I/O, in `wz-session-core`:

```
ReplayCursor { next: usize, total: usize }

begin(total)                  start at the beginning of a sequence of `total` entries
turn(burst) -> Range<usize>   the entries to emit now; advances `next` past them
refused(at)                   a send failed at entry `at`: the next turn starts there, not at 0
inserted(place)               a live declaration took `place` in the order
                              -> Emit now (place < next)  |  Owed (place >= next, total grows)
removed(place)                a live undeclaration of the entry at `place`
                              -> Retract (place < next, next shrinks)  |  Silent (total shrinks)
finished()                    next == total
```

Each host owns its sequence and its clock and calls the cursor:

- the heap runtime reads the cache as the sequence and the supervisor runs the turns;
- the cooperative engine maps the sequence to its lists in `redeclare`'s order (the place of an entry
  is its kind's offset plus its index) and its pump runs the turns on its clock;
- the slot node's sequence is the static slice, the cursor replaces the per-session `declared` flag,
  and a refused send resumes at the entry it failed on.

The cursor states rules 2 to 4 once, as the return values of `inserted` and `removed`, and a host
cannot get them wrong without ignoring a returned value. That is the reason it is a type and not a
convention in three files.

## Design

- **Declare, while a replay runs.** The host calls `inserted(place)`. `Owed`: it stores the entry
  and emits nothing; the cursor will reach it. `Emit now`: it stores the entry and emits it.
- **Undeclare, while a replay runs.** The host calls `removed(place)`. `Retract`: it emits the
  retraction. `Silent`: nothing is sent.
- **A turn** emits the range `turn(burst)` returns, with `burst` =
  `DECLARATION_SYNC_BURST_MESSAGES`, and a refused emit calls `refused(at)`. When the cursor is
  `finished()` the replay is complete and a declaration made after that is emitted by its caller,
  as before.
- **The host owns the pacing.** The tokio supervisor sleeps `DECLARATION_SYNC_INTERVAL_MS` between
  turns, the cooperative engine and the slot node use their clocks. The core only says "one turn,
  and whether there is more".
- **The wait** is `declarations_synced` per session (cursor finished and no interest of the replay
  awaiting its final, within `DECLARATION_SYNC_FINAL_TIMEOUT_MS`), and a node-level
  `wait_declarations_stable(timeout)` by rule 9, which also restarts if the declaration count or
  the topology changed while it waited, so a declaration made during the wait is not missed.

With the policy off the cursor is never used: the replay is the same single call each host makes
today (rule 6). The slot node's repeat-from-zero after a refused send is a defect whether or not
pacing is on, and the cursor removes it; that part is worth landing as its own change.

## Phases

1. This document. DONE.
2. `ReplayCursor` in `wz-session-core`, pure, with a unit test per return value of `inserted` and
   `removed`. DONE. Then the policy `declaration-sync-pacing` with its burst and interval limits,
   declared in the same change as the first code that reads them (a switch no code reads is not
   landed). DONE for the heap runtime, the first host: `DeclarationCache` holds the replay and the
   cursor together, every live declaration and retraction goes through one per-kind method of
   `SessionLinkActions` that asks the cache what to do about the peer, and the reconnect
   supervisor (`ReconnectingSession`) runs the turns between the session's own work (`select!`,
   one task, so a failing turn ends the drive with its error). Off is the same single call, with
   a test that a paced replay of one turn sends the unpaced replay's bytes, and a supervisor test
   over real TCP for both.
3. `declarations_synced` and `wait_declarations_stable` on the heap session, and the per-peer
   completion of the queryable and token planes beside the subscriber plane that has it today
   (`initial_final`).
4. The cooperative engine's `redeclare` and the slot node's `declare_all` take the cursor, each
   written by the session that owns the file (the cooperative engine: session 11; the slot node:
   session ef, who offered to do or review it). This document does not edit their files. DONE for
   the slot node: the cursor (a refused send resumes where it failed), then the policy's burst and
   interval through the shared `ReplayPacing`, with `SlotClientNode::declarations_synced`. The
   cooperative engine's `redeclare` is not done.

## What a user of aliased sends must know

A declaration made during a paced replay is replayed in its turn, and a data message that names a
mapping id (an aliased publish) is valid at the peer only after the declaration of that mapping has
reached it. A literal publish names its key in full and is always valid. An application that sends
aliased messages therefore waits for `declarations_synced` (phase 3) before it does; until that
exists, such an application keeps the policy off.

## Not part of this

The router's replay of its own declarations to a new face
(`replay_declarations_to_new_face`) belongs to the router work. Its bytes are bounded by the credit
stage; its turns are not, and are decided with the router's task-per-face work
(`docs/router-task-per-face.md`). A replayed Declare there is a held or probe-sent message like any
other, so a router replaying thousands of declarations to a new face still runs them in one loop
turn today. That is a router item that should take the cursor idea later, after the task-per-face
phase, because then a replay is a task and a turn bound becomes an await point instead of a
resumable cursor. Agreed with the router session on 2026-10-25.

## Open for the owners

Settled with the owners on 2026-10-25:

- The cache cannot own the emit: the cooperative engine and the slot node have no such cache. The
  rules live in the `ReplayCursor` type each host calls (session 11 for the cooperative engine and
  session ef for the slot node answered; the router's replay is out of scope, see above).
- The multicast group is not paced (rule 8).
- The reconnect driver of the heap runtime (`reconnect.rs`) has no session working in it that
  anyone could name; its last commits are from 2026-10-18 and earlier. Phase 2 edits one call there
  and says so in its round.

Still open:

- The per-peer completion of the queryable and token planes (phase 3) needs the wire's interest
  final for those planes; whether the peers send it for every plane is to be measured against
  upstream before the design of `declarations_synced` is final.
- The fixed-memory profile has no allocator, so `ReplayCursor` and its returns are plain values
  there; the cursor's `total` growing on `Owed` assumes the host's sequence can grow, which the
  slot node's static slice cannot (it never declares at run time), and the cooperative engine's
  fixed lists can only up to their capacity. A host that cannot grow answers its own `inserted`
  with a refusal; the cursor does not decide that.
