------------------------- MODULE FaceCollisionService -------------------------
(***************************************************************************)
(* What a node's routing may rely on of the faces a loop holds to one      *)
(* remote node (level 1 of SCE ADR 0115, D1). No table, rule, park or      *)
(* departure order is in it.                                               *)
(*                                                                         *)
(* The loop holds at most one face to the node at a time, and the routing  *)
(* graph holds a link to the node exactly while it does: a face is HELD    *)
(* and the graph gains the link, the face LEAVES and the graph loses it.   *)
(*                                                                         *)
(* Taken as given:                                                         *)
(*   Nothing: it is what the routing may rely on, and names no mechanism.  *)
(***************************************************************************)
CONSTANTS Faces

VARIABLES held,  \* the faces the loop holds to the node
          graph  \* whether the routing graph holds a link to the node

vars == <<held, graph>>

Init == /\ held = {}
        /\ graph = FALSE

Hold(f) == /\ held = {}
           /\ held' = {f}
           /\ graph' = TRUE

Leave(f) == /\ f \in held
            /\ held' = {}
            /\ graph' = FALSE

Next == \E f \in Faces : Hold(f) \/ Leave(f)

Spec == Init /\ [][Next]_vars

=============================================================================
