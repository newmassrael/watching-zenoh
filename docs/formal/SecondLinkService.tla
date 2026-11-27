-------------------------- MODULE SecondLinkService --------------------------
(***************************************************************************)
(* What two nodes that dial each other at once may rely on of the links    *)
(* between them (level 1 of SCE ADR 0115, D1). No book, row, rank or       *)
(* handshake step is in it.                                                *)
(*                                                                         *)
(* Each link between the two nodes is either CARRIED, taken up at both     *)
(* ends, or CLOSED before it carried anything. At most one link carries,   *)
(* and once every link is decided one of them does: the two nodes end     *)
(* with exactly one link and neither end sees a declaration twice.         *)
(*                                                                         *)
(* Taken as given:                                                         *)
(*   Nothing: it is what a node may rely on, and names no mechanism.       *)
(***************************************************************************)
CONSTANTS Links

VARIABLES carried, \* the links taken up at both ends
          closed   \* the links closed before they carried anything

vars == <<carried, closed>>

Init == /\ carried = {}
        /\ closed = {}

Carry(l) == /\ l \notin carried \cup closed
            /\ carried = {}
            /\ carried' = {l}
            /\ UNCHANGED closed

\* The last link still undecided is not closed while none carries.
Close(l) == /\ l \notin carried \cup closed
            /\ (carried # {} \/ closed \cup {l} # Links)
            /\ closed' = closed \cup {l}
            /\ UNCHANGED carried

Next == \E l \in Links : Carry(l) \/ Close(l)

Spec == Init /\ [][Next]_vars

=============================================================================
