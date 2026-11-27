-------------------------- MODULE ResetOnceService --------------------------
(***************************************************************************)
(* What a peer that resets its session with a node may rely on (decision   *)
(* D6 of docs/session-lifecycle-intent.md; level 1 of SCE ADR 0115, D1).   *)
(* No table, bound, key or lock is in it.                                  *)
(*                                                                         *)
(* A reset names a generation. It ends the peer's session only when its    *)
(* generation is later than every one that ended a session of that peer    *)
(* before: a retransmission of a reset, or an older reset arriving late,   *)
(* ends nothing and is answered as a duplicate of the last generation      *)
(* taken. A node may refuse the reset of a peer it has taken none of, for  *)
(* want of room, and the refusal ends nothing; a peer it has taken a reset *)
(* of is never refused.                                                    *)
(*                                                                         *)
(* Taken as given:                                                         *)
(*   Nothing: it is what a peer may rely on, and names no mechanism.       *)
(***************************************************************************)
EXTENDS Naturals, Sequences

CONSTANTS Peers, Generations

VARIABLES ended,  \* ended[p]: the generations that ended a session of p, in order
          said    \* the last answer: <<peer, generation, kind, last generation taken>>

vars == <<ended, said>>

Last(s) == s[Len(s)]

Init == /\ ended = [p \in Peers |-> <<>>]
        /\ said = <<>>

Take(p, g) == /\ ended[p] = <<>> \/ Last(ended[p]) < g
              /\ ended' = [ended EXCEPT ![p] = Append(@, g)]
              /\ said' = <<p, g, "taken", g>>

Duplicate(p, g) == /\ ended[p] # <<>> /\ g <= Last(ended[p])
                   /\ said' = <<p, g, "duplicate", Last(ended[p])>>
                   /\ UNCHANGED ended

Refuse(p, g) == /\ ended[p] = <<>>
                /\ said' = <<p, g, "noroom", g>>
                /\ UNCHANGED ended

Next == \E p \in Peers, g \in Generations :
            Take(p, g) \/ Duplicate(p, g) \/ Refuse(p, g)

Spec == Init /\ [][Next]_vars

=============================================================================
