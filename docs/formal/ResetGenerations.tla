-------------------------- MODULE ResetGenerations --------------------------
(***************************************************************************)
(* How a node keeps ResetOnceService: the table of reset generations (S5   *)
(* M5 and S2 30 of docs/zenoh-logic-as-sce-kinds.md, section 7.1; level 2 *)
(* of SCE ADR 0115, D2). The rule is sources/algorithms/take_generation.   *)
(* scxml; each profile keeps it over a table of at most Room peers.        *)
(*                                                                         *)
(* A reset of a peer the table holds is a DUPLICATE when the generation    *)
(* held is as late as the one asked; otherwise it is TAKEN, the table      *)
(* REMEMBERS the later generation in place, and the session is ended. A    *)
(* peer the table does not hold is taken while the table has room; with   *)
(* none it is REFUSED, and no peer held is EVICTED to make room.           *)
(*                                                                         *)
(* Each constant that is a part of the protocol can be switched off, and   *)
(* TLC must then find a violation.                                         *)
(*                                                                         *)
(* Taken as given:                                                         *)
(*   A reset is taken whole, one at a time: on the fixed-memory profile    *)
(*     under the store's critical section,                                 *)
(*     `crates/wz-session-mcu/src/connect_manager.rs` @                    *)
(*     `fn with<R>(&self, f: impl FnOnce(&mut Tables) -> R) -> R {`, and on  *)
(*     the heap profile under the table's RefCell,                         *)
(*     `crates/wz-session-core/src/lifecycle_query.rs` @                   *)
(*     `resets: RefCell<ResetGenerations<HEAP_RESET_PEERS, Heap>>,`.        *)
(*   One peer is one key: the zid read as the 128-bit number zenoh         *)
(*     compares, so two spellings of one zid are one peer,                 *)
(*     `crates/wz-session-core/src/reset_generations.rs` @ `fn peer(zid: &Zid) -> Peer {`. *)
(*   A taken reset ends the session; a duplicate and a refusal end         *)
(*     nothing (lifecycle_node::lifecycle_verdict).                        *)
(*                                                                         *)
(* What the upstream presets do: neither zenoh nor zenoh-pico has a        *)
(* lifecycle reset; it is wz's verb (decision D6), and the promise is read *)
(* against at-most-once calls (Birrell and Nelson, 1984), not a preset.    *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS Peers, Generations,
          Room,        \* the peers the table holds: MAX_PEER_NODES, or HEAP_RESET_PEERS
          Remember,    \* a later generation is written in place (take_generation.scxml, the put)
          Latest,      \* a duplicate is one the held generation is as late as (the `>=` guard)
          NeverEvict,  \* a new peer of a full table is refused, nothing held is evicted
          RefuseFull,  \* a full table takes no new peer (the put answers `full`)
          NoGen        \* a model value: no generation held, comparable with every value

VARIABLES taken,  \* taken[p]: the generation held for p, or NoGen
          ended,  \* ended[p]: the generations that ended a session of p, in order
          said    \* the last answer: <<peer, generation, kind, last generation taken>>

vars == <<taken, ended, said>>

Held == {p \in Peers : taken[p] # NoGen}

Full == Cardinality(Held) >= Room

Dup(p, g) == IF Latest THEN taken[p] >= g ELSE taken[p] = g

Init == /\ taken = [p \in Peers |-> NoGen]
        /\ ended = [p \in Peers |-> <<>>]
        /\ said = <<>>

\* The session of p is ended by the reset of generation g.
End(p, g) == /\ ended' = [ended EXCEPT ![p] = Append(@, g)]
             /\ said' = <<p, g, "taken", g>>

Duplicate(p, g) == /\ p \in Held /\ Dup(p, g)
                   /\ said' = <<p, g, "duplicate", taken[p]>>
                   /\ UNCHANGED <<taken, ended>>

TakeHeld(p, g) == /\ p \in Held /\ ~Dup(p, g)
                  /\ taken' = IF Remember THEN [taken EXCEPT ![p] = g] ELSE taken
                  /\ End(p, g)

TakeNew(p, g) == /\ p \notin Held
                 /\ ~Full \/ (NeverEvict /\ ~RefuseFull)
                 /\ taken' = [taken EXCEPT ![p] = g]
                 /\ End(p, g)

Evict(p, g, q) == /\ ~NeverEvict /\ p \notin Held /\ Full /\ q \in Held
                  /\ taken' = [taken EXCEPT ![q] = NoGen, ![p] = g]
                  /\ End(p, g)

Refuse(p, g) == /\ p \notin Held /\ Full /\ NeverEvict /\ RefuseFull
                /\ said' = <<p, g, "noroom", g>>
                /\ UNCHANGED <<taken, ended>>

Next == \E p \in Peers, g \in Generations :
            \/ Duplicate(p, g) \/ TakeHeld(p, g) \/ TakeNew(p, g) \/ Refuse(p, g)
            \/ \E q \in Peers : Evict(p, g, q)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
\* No reset ends a session of a peer twice, nor after a later one did: the generations that
\* ended its sessions rise.
AtMostOnce ==
    \A p \in Peers : \A i \in 1..(Len(ended[p]) - 1) : ended[p][i] < ended[p][i + 1]

\* The table holds no more peers than its room.
Bounded == Cardinality(Held) <= Room

\* Keeps a broken variant's exploration finite: a run past it has broken AtMostOnce already.
Short == \A p \in Peers : Len(ended[p]) <= Cardinality(Generations) + 1

-----------------------------------------------------------------------------
\* What the protocol implements (SCE ADR 0115, D2): the service a resetting peer relies on.
Service == INSTANCE ResetOnceService WITH
    Peers <- Peers,
    Generations <- Generations,
    ended <- ended,
    said <- said

Refines == Service!Spec

=============================================================================
