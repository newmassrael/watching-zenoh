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
| `DECLARATION_SYNC_FINAL_TIMEOUT_MS` | limit | 1000 when on | How long the sync waits for the peer's final for an interest before it counts the interest as unanswered and goes on. Never longer than the session's own lease. |

A value of a limit is refused at build time when it is zero or when the timeout is shorter than
the interval, as every limit here is checked where it is declared (`deploy/wz-config.toml`).

## What has to stay true

1. **Order.** The peer's tables are empty. A declaration that names a key expression by its
   mapping id is valid only after the declaration of that key expression. Replay is in the order
   the declarations were made, in every turn.
2. **A live declaration made during the replay reaches the peer after everything the replay still
   owes it, never before.** An aliased declaration sent ahead of the key expression it names is
   a protocol error on the peer.
3. **A live undeclaration made during the replay is sent if and only if the peer already saw the
   declaration.** If the replay has not reached it yet, the entry is dropped from the cache and
   nothing is sent; the peer never learned of it. If it has, the retraction is sent.
4. **Exactly once.** Each cached declaration is emitted once per session, whatever the interleaving
   of replay and live calls.
5. **A reconnect during the replay starts the replay again from the beginning**: the new session's
   peer has nothing.
6. **Off is byte-identical to today.** A build with the policy off emits the same frames in the same
   order as before this existed, which a pair of tests names.

## Why the obvious place does not hold rule 2 and 3

The cache append and the wire emit are two steps in different places. The typed emit methods of
`SessionLinkActions`, the seam-routed `Session::declare_*` of the runtime, and the C ABI faces
each emit and then cache (or prune), and there is no single function every one of them passes
through that knows both the entry and the intent. A gate on `dispatch_declare` alone misses the
seam-routed paths and cannot tell an undeclaration of a replayed entry from one of an unreplayed
entry without reading the id out of the frame.

So the design puts the state where both steps already meet: the declaration cache.

## Design

The cache gains a **sync cursor**: the index of the first entry the current session's peer has not
been told, held beside the cache in `SessionCore`. It exists only while a paced sync is running.

- **Declare, while a sync runs.** The caller appends to the cache and does not emit. The cursor
  will reach the entry. The caller learns nothing different: it returns as it does today.
- **Undeclare, while a sync runs.** The prune reports the position it removed. Position below the
  cursor: the peer saw it, the retraction is emitted and the cursor moves down by one. At or above
  the cursor: nothing is emitted.
- **A turn** emits up to `DECLARATION_SYNC_BURST_MESSAGES` entries from the cursor and advances it.
  When the cursor reaches the end of the cache the sync is complete and the cursor is dropped, so a
  declaration made after that is emitted by its caller, as before.
- **The loop owns the pacing.** The runtime drives the turns, as it already drives the reconnect:
  the tokio supervisor sleeps `DECLARATION_SYNC_INTERVAL_MS` between turns, and the cooperative
  engine asks its clock. The core only says "one turn, and whether there is more".
- **The wait** is `declarations_synced`: true for a session when it has no sync running and no
  interest of the sync is awaiting its final. A node-level `wait_declarations_stable(timeout)`
  completes when it is true for every live session, the listeners are bound, and neither the
  declaration count nor the topology changed across the check, so a declaration made while it
  waits restarts it.

The emit side is the part that needs the owners of the session lifecycle: the rule "append and do
not emit" has to be applied at each declare entry point, or lifted into the one place that
decides, and that is a change to the shared session API of the slot node, the C ABIs and the
runtime.

## Phases

1. This document, and the three limits and the policy declared and generated, off.
2. The cursor and the turn in `wz-session-core`, with the pair of tests for rules 1-4 and 6 over a
   recording link; the reconnect driver of `wz-runtime-tokio` runs the turns (rule 5).
3. `declarations_synced` and `wait_declarations_stable` on the session, and the per-peer completion
   of the queryable and token planes beside the subscriber plane that has it today
   (`initial_final`).
4. The cooperative engine and the fixed-memory node, which have no heap cache: their cursor is an
   index into the node's declaration table and the turn is one call of its pump.

## Not part of this

The router's replay of its own declarations to a new face
(`replay_declarations_to_new_face`) belongs to the router work and is bounded there by its credit
stage. Pacing a router's replay is a different question (it replays other nodes' declarations,
many per face) and is not decided here.

## Open for the owners

- Whether rule 2 and 3 are applied at each declare entry point or lifted into the cache itself, so
  that the emit is the cache's job and no caller can forget it. The second is the better shape and
  the larger change.
- Whether the sync of a multicast group, which has no peer to wait for, is paced at all.
