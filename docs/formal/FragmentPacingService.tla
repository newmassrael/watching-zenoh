------------------------ MODULE FragmentPacingService ------------------------
(***************************************************************************)
(* What a program that sends over a datagram link whose writer paces its   *)
(* fragments may rely on (the datagram-fragment-pacing policy, S1 29 of    *)
(* docs/zenoh-logic-as-sce-kinds.md; level 1 of SCE ADR 0115, D1). No run  *)
(* count, clock reading or wait is in it.                                  *)
(*                                                                         *)
(* The writer writes each datagram it is asked to write, in the order      *)
(* asked, at the moment asked or later. Every datagram written is in the   *)
(* log with the time it was asked and the time it was written:            *)
(*                                                                         *)
(*   Spaced: fragments written back to back, each less than Gap after the  *)
(*     fragment before it, are at most Burst in a row;                     *)
(*   BoundedDelay: a datagram that is not a fragment is written when it    *)
(*     is asked; a fragment no later than when it is asked or Gap after    *)
(*     the datagram written before it, whichever is later;                 *)
(*   LetsBurst: a fragment is written later than asked only when the Burst *)
(*     datagrams written before it are fragments, of which none but the    *)
(*     first was held: a run of Burst fragments goes through between two   *)
(*     waits.                                                              *)
(*                                                                         *)
(* Taken as given:                                                         *)
(*   Nothing: it is what a sender may rely on, and names no mechanism.     *)
(***************************************************************************)
EXTENDS Naturals, Sequences

CONSTANTS Burst,   \* fragments let through back to back, at least 1
          Gap,     \* the time a held fragment waits after the last write
          MaxTime  \* the last time a behaviour reaches (bounds the exploration)

VARIABLES now,  \* the time
          log   \* the datagrams written: <<kind, asked, written>>, in order

vars == <<now, log>>

Kinds == {"fragment", "other"}

Max(a, b) == IF a >= b THEN a ELSE b

Held(l, i) == l[i][3] > l[i][2]

\* The i-th datagram is a fragment written less than Gap after a fragment before it.
Fast(l, i) == /\ i > 1
              /\ l[i][1] = "fragment" /\ l[i - 1][1] = "fragment"
              /\ l[i][3] - l[i - 1][3] < Gap

\* No Burst fast datagrams in a row end at the i-th: Burst + 1 fragments each less than Gap
\* after the one before.
SpacedAt(l, i) == ~(i >= Burst /\ \A j \in (i - Burst + 1)..i : Fast(l, j))

BoundedDelayAt(l, i) ==
    IF l[i][1] = "other" \/ i = 1
    THEN l[i][3] = l[i][2]
    ELSE l[i][3] <= Max(l[i][2], l[i - 1][3] + Gap)

LetsBurstAt(l, i) ==
    Held(l, i) =>
        /\ l[i][1] = "fragment"
        /\ i > Burst
        /\ \A j \in (i - Burst)..(i - 1) : l[j][1] = "fragment"
        /\ \A j \in (i - Burst + 1)..(i - 1) : ~Held(l, j)

Promised(l, i) == SpacedAt(l, i) /\ BoundedDelayAt(l, i) /\ LetsBurstAt(l, i)

Init == /\ now = 0
        /\ log = <<>>

Tick == /\ now < MaxTime
        /\ now' = now + 1
        /\ UNCHANGED log

Write == \E k \in Kinds, at \in now..(now + Gap) :
            /\ log' = Append(log, <<k, now, at>>)
            /\ now' = at
            /\ Promised(log', Len(log'))

Next == Tick \/ Write

Spec == Init /\ [][Next]_vars

=============================================================================
