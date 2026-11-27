------------------------- MODULE QueryFinalService -------------------------
(***************************************************************************)
(* What a querier, and a program that declared a queryable, may rely on    *)
(* of a query that reached a session (level 1 of SCE ADR 0115, D1). No     *)
(* table, row, lock, round or callback order is in it.                     *)
(*                                                                         *)
(* A query arrives. It is then either REFUSED whole or ANSWERED. A refused *)
(* query ran no queryable's callback, and its querier is sent nothing,     *)
(* not even a Final. An answered query runs the callback of each queryable *)
(* at most once; once a callback ran, replies may be sent; then exactly    *)
(* one Final is sent, and nothing after it.                                *)
(*                                                                         *)
(* Taken as given:                                                         *)
(*   Nothing: it is what a user may rely on, and names no mechanism.       *)
(***************************************************************************)
EXTENDS Sequences

CONSTANTS Queries, Queryables

VARIABLES phase,   \* phase[r]: new, open, refused or done
          called,  \* called[r]: the queryables whose callback ran for r
          wire     \* wire[r]: what the querier of r was sent, in order

vars == <<phase, called, wire>>

Init == /\ phase = [r \in Queries |-> "new"]
        /\ called = [r \in Queries |-> {}]
        /\ wire = [r \in Queries |-> <<>>]

Arrive(r) == /\ phase[r] = "new"
             /\ phase' = [phase EXCEPT ![r] = "open"]
             /\ UNCHANGED <<called, wire>>

Refuse(r) == /\ phase[r] = "open" /\ called[r] = {} /\ wire[r] = <<>>
             /\ phase' = [phase EXCEPT ![r] = "refused"]
             /\ UNCHANGED <<called, wire>>

Call(r, q) == /\ phase[r] = "open" /\ q \notin called[r]
              /\ called' = [called EXCEPT ![r] = @ \cup {q}]
              /\ UNCHANGED <<phase, wire>>

Reply(r) == /\ phase[r] = "open" /\ called[r] # {}
            /\ wire' = [wire EXCEPT ![r] = Append(@, "reply")]
            /\ UNCHANGED <<phase, called>>

Finish(r) == /\ phase[r] = "open"
             /\ phase' = [phase EXCEPT ![r] = "done"]
             /\ wire' = [wire EXCEPT ![r] = Append(@, "final")]
             /\ UNCHANGED called

Next == \E r \in Queries :
            \/ Arrive(r) \/ Refuse(r) \/ Reply(r) \/ Finish(r)
            \/ \E q \in Queryables : Call(r, q)

Spec == Init /\ [][Next]_vars

=============================================================================
