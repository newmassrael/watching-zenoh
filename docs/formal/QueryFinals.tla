----------------------------- MODULE QueryFinals -----------------------------
(***************************************************************************)
(* How a session answers a query that reached its queryables, and when it  *)
(* sends the query's ResponseFinal (S7 13 of                               *)
(* docs/zenoh-logic-as-sce-kinds.md, W16; level 2 of SCE ADR 0115, D2).    *)
(*                                                                         *)
(* A frame is DISPATCHED under the session's lock. Each queryable a query  *)
(* reaches HOLDS the query's Final in a row of a table of Rows rows, and a *)
(* call is begun and held in the round of deliveries; a query with no row  *)
(* left is REFUSED, and stays refused for the rest of its dispatch. At the *)
(* end of the dispatch the Final is OWED: sent at once when nothing holds  *)
(* it, never when the query was refused, and otherwise left DUE on its     *)
(* row. A callback runs with no lock held; its replies go out, and its     *)
(* hold is let go of under the lock, the Final going out with the last     *)
(* hold. A program may KEEP the query past its callback (a hold more), and *)
(* a reply to a kept query holds a keep of its own while it answers. The   *)
(* session's own get takes a row under the lock and may give it back with  *)
(* the table's lock alone, also while a dispatch runs.                     *)
(*                                                                         *)
(* Each constant that is a part of the protocol can be switched off, and   *)
(* TLC must then find a violation.                                         *)
(*                                                                         *)
(* Taken as given:                                                         *)
(*   The dispatch of a frame, from its first query to the Finals it owes,  *)
(*     runs under the session's lock, and a hold is let go of under the    *)
(*     same lock: crates/wz-capi-coop/src/engine.rs:4300-4321 and          *)
(*     :9853-9854, through live_on_link and live (:7792-7816).             *)
(*   The table of held Finals has its own lock, and the drop of the own    *)
(*     get's row takes it alone: crates/wz-session-core/src/               *)
(*     query_plane.rs:314-321, the row dropped at the end of the get       *)
(*     (crates/wz-capi-coop/src/engine.rs:11540, :11823-11827).            *)
(*   A callback runs with no session lock held, once the round hands its   *)
(*     delivery out (query_plane.rs:10-21), and a keep takes the table's   *)
(*     lock alone (crates/wz-capi-coop/src/engine/query.rs:529-551).       *)
(*   What the session sends on a query's link leaves in the order it was   *)
(*     sent; the Final joins the frame the turn's replies were held in     *)
(*     (engine.rs:9867-9876).                                              *)
(*   The link of a query stays the session's: a link lost, under which no  *)
(*     reply or Final is sent (query_plane.rs:32-37), is not modelled.     *)
(*   LiveSpec: a program lets go of a query it keeps, and a callback ends. *)
(*                                                                         *)
(* What the upstream presets do, which the promise is read against:        *)
(*   zenoh-pico sends the Final when the last reference to the query is    *)
(*     dropped,                                                            *)
(*    `vendor/zenoh-pico/src/net/query.c` @ `// Send REPLY_FINAL message`, *)
(*     at once when no queryable matched,                                  *)
(*     `vendor/zenoh-pico/src/session/queryable.c` @ `if (qle_nb == 0) {`, *)
(*     and runs no callback and sends nothing when it cannot build the     *)
(*     query,                                                              *)
(*     `vendor/zenoh-pico/src/session/queryable.c` @ `_z_query_rc_t query = _z_query_rc_new_undefined();`. *)
(*   zenoh sends it when the last Query is dropped,                        *)
(*     `zenoh/src/api/queryable.rs` @ `impl Drop for QueryInner {`.        *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS Queries, Queryables,
          Rows,        \* the rows of the table of held Finals: MAX_PENDING_FINALS
          MaxReplies,  \* the replies one query is sent, for a finite exploration
          MaxOwn,      \* the rows the session's own get takes, one after another
          Hold,        \* the Final waits for the last hold (query_plane.rs:250-254)
          RefuseFull,  \* a query with no row left is refused (query_plane.rs:148-156, :229-235)
          Sticky,      \* a refused query stays refused in its dispatch (query_plane.rs:224-228)
          OweRefused,  \* the Final of a refused query is never sent (query_plane.rs:242-249)
          GiveBack,    \* a hold whose call was not begun is given back (query_plane.rs:483-485, :532-534)
          ReplyKeeps   \* a reply to a kept query holds a keep (engine/query.rs:553-577)

Free == "free"

VARIABLES phase,     \* phase[r]: new, dispatch, owed, done or refused
          pending,   \* pending[r]: the queryables the dispatch of r is still to reach
          holds,     \* holds[r]: the holds on the row of r; 0 is no row
          due,       \* due[r]: the Final of r is owed and waits on its row
          refusedL,  \* the queries refused in the running dispatch (FinalHolds::refused)
          refusedAt, \* refusedAt[r]: a queryable of r was refused for want of a row
          offered,   \* offered[r]: the calls begun for r, held in the round
          running,   \* running[r]: the queryables whose callback runs for r
          keeps,     \* keeps[r]: the keeps the program holds of r
          replying,  \* replying[r]: no, begun or written, a reply to the kept r
          called,    \* called[r]: the queryables whose callback ran for r
          wire,      \* wire[r]: what the querier of r was sent
          lock,      \* the query the session's lock is held to dispatch, or Free
          own,       \* the session's own get holds a row
          ownTaken   \* the rows the own get took

vars == <<phase, pending, holds, due, refusedL, refusedAt, offered, running, keeps,
          replying, called, wire, lock, own, ownTaken>>

Used == Cardinality({r \in Queries : holds[r] > 0}) + (IF own THEN 1 ELSE 0)

Replies(r) == Cardinality({i \in 1..Len(wire[r]) : wire[r][i] = "reply"})

Init == /\ phase = [r \in Queries |-> "new"]
        /\ pending = [r \in Queries |-> {}]
        /\ holds = [r \in Queries |-> 0]
        /\ due = [r \in Queries |-> FALSE]
        /\ refusedL = {}
        /\ refusedAt = [r \in Queries |-> FALSE]
        /\ offered = [r \in Queries |-> {}]
        /\ running = [r \in Queries |-> {}]
        /\ keeps = [r \in Queries |-> 0]
        /\ replying = [r \in Queries |-> "no"]
        /\ called = [r \in Queries |-> {}]
        /\ wire = [r \in Queries |-> <<>>]
        /\ lock = Free
        /\ own = FALSE
        /\ ownTaken = 0

-----------------------------------------------------------------------------
\* Let go of one hold of r, under the session's lock: the Final goes out with the last hold when it
\* was owed (query_plane.rs:260-271 and :202-218; engine.rs:9853-9876).
Release(r) ==
    /\ holds' = [holds EXCEPT ![r] = @ - 1]
    /\ IF holds[r] = 1 /\ due[r]
         THEN /\ wire' = [wire EXCEPT ![r] = Append(@, "final")]
              /\ phase' = [phase EXCEPT ![r] = "done"]
              /\ due' = [due EXCEPT ![r] = FALSE]
         ELSE UNCHANGED <<wire, phase, due>>

\* A frame carries the query r: its dispatch takes the session's lock.
Arrive(r) ==
    /\ lock = Free /\ phase[r] = "new"
    /\ phase' = [phase EXCEPT ![r] = "dispatch"]
    /\ pending' = [pending EXCEPT ![r] = Queryables]
    /\ lock' = r
    /\ UNCHANGED <<holds, due, refusedL, refusedAt, offered, running, keeps, replying, called,
                   wire, own, ownTaken>>

\* The dispatch of r reaches the queryable q (QueryPlane::arrive and admit_call,
\* query_plane.rs:457-486 and :521-536; FinalHolds::admit, :223-236). The call is begun or, with
\* its latch full or the round with no room, not begun.
Reach(r, q, begun) ==
    /\ lock = r /\ q \in pending[r]
    /\ pending' = [pending EXCEPT ![r] = @ \ {q}]
    /\ IF Sticky /\ r \in refusedL THEN
          UNCHANGED <<holds, refusedL, refusedAt, offered>>
       ELSE IF holds[r] > 0 \/ Used < Rows \/ ~RefuseFull THEN
          IF begun THEN
             /\ holds' = [holds EXCEPT ![r] = @ + 1]
             /\ offered' = [offered EXCEPT ![r] = @ \cup {q}]
             /\ UNCHANGED <<refusedL, refusedAt>>
          ELSE IF GiveBack THEN
             \* Taken and given back at once: the dispatch owes nothing yet, so nothing is sent.
             UNCHANGED <<holds, offered, refusedL, refusedAt>>
          ELSE
             /\ holds' = [holds EXCEPT ![r] = @ + 1]
             /\ UNCHANGED <<offered, refusedL, refusedAt>>
       ELSE
          /\ refusedL' = refusedL \cup {r}
          /\ refusedAt' = [refusedAt EXCEPT ![r] = TRUE]
          /\ UNCHANGED <<holds, offered>>
    /\ UNCHANGED <<phase, due, running, keeps, replying, called, wire, lock, own, ownTaken>>

\* The dispatch ends and owes the Final of r (engine.rs:4316-4319; FinalHolds::owe,
\* query_plane.rs:241-257); the session's lock is let go of.
Owe(r) ==
    /\ lock = r /\ pending[r] = {}
    /\ lock' = Free
    /\ IF OweRefused /\ r \in refusedL THEN
          /\ refusedL' = refusedL \ {r}
          /\ phase' = [phase EXCEPT ![r] = "refused"]
          /\ UNCHANGED <<due, wire>>
       ELSE IF Hold /\ holds[r] > 0 THEN
          /\ due' = [due EXCEPT ![r] = TRUE]
          /\ phase' = [phase EXCEPT ![r] = "owed"]
          /\ UNCHANGED <<refusedL, wire>>
       ELSE
          /\ wire' = [wire EXCEPT ![r] = Append(@, "final")]
          /\ phase' = [phase EXCEPT ![r] = "done"]
          /\ UNCHANGED <<refusedL, due>>
    /\ UNCHANGED <<pending, holds, refusedAt, offered, running, keeps, replying, called, own,
                   ownTaken>>

\* The round hands a held call to its callback, with no lock held.
Call(r, q) ==
    /\ q \in offered[r]
    /\ offered' = [offered EXCEPT ![r] = @ \ {q}]
    /\ running' = [running EXCEPT ![r] = @ \cup {q}]
    /\ called' = [called EXCEPT ![r] = @ \cup {q}]
    /\ UNCHANGED <<phase, pending, holds, due, refusedL, refusedAt, keeps, replying, wire, lock,
                   own, ownTaken>>

\* A callback replies, the reply sent under the session's lock.
Reply(r) ==
    /\ lock = Free /\ running[r] # {} /\ Replies(r) < MaxReplies
    /\ wire' = [wire EXCEPT ![r] = Append(@, "reply")]
    /\ UNCHANGED <<phase, pending, holds, due, refusedL, refusedAt, offered, running, keeps,
                   replying, called, lock, own, ownTaken>>

\* A callback keeps its query past its end: a hold more (FinalHolds::keep, query_plane.rs:183-197).
Keep(r, q) ==
    /\ q \in running[r] /\ keeps[r] = 0 /\ holds[r] > 0
    /\ holds' = [holds EXCEPT ![r] = @ + 1]
    /\ keeps' = [keeps EXCEPT ![r] = 1]
    /\ UNCHANGED <<phase, pending, due, refusedL, refusedAt, offered, running, replying, called,
                   wire, lock, own, ownTaken>>

\* A callback ends and its turn lets go of its hold (engine.rs:9818-9877, Release::Hold).
Return(r, q) ==
    /\ lock = Free /\ q \in running[r]
    /\ running' = [running EXCEPT ![r] = @ \ {q}]
    /\ Release(r)
    /\ UNCHANGED <<pending, refusedL, refusedAt, offered, keeps, replying, called, lock, own,
                   ownTaken>>

\* The program begins a reply to the query it keeps (reply_kept, engine/query.rs:556-570): a keep
\* of the reply's own, taken with the table's lock alone, refused when the query is no longer kept.
KeptReplyBegin(r) ==
    /\ keeps[r] > 0 /\ replying[r] = "no" /\ Replies(r) < MaxReplies
    /\ replying' = [replying EXCEPT ![r] = "begun"]
    /\ holds' = IF ReplyKeeps THEN [holds EXCEPT ![r] = @ + 1] ELSE holds
    /\ UNCHANGED <<phase, pending, due, refusedL, refusedAt, offered, running, keeps, called, wire,
                   lock, own, ownTaken>>

\* The reply goes out under the session's lock (engine/query.rs:571-575).
KeptReplyWrite(r) ==
    /\ lock = Free /\ replying[r] = "begun"
    /\ replying' = [replying EXCEPT ![r] = "written"]
    /\ wire' = [wire EXCEPT ![r] = Append(@, "reply")]
    /\ UNCHANGED <<phase, pending, holds, due, refusedL, refusedAt, offered, running, keeps,
                   called, lock, own, ownTaken>>

\* The reply's keep is let go of under the session's lock (engine/query.rs:576).
KeptReplyDone(r) ==
    /\ lock = Free /\ replying[r] = "written"
    /\ replying' = [replying EXCEPT ![r] = "no"]
    /\ IF ReplyKeeps THEN Release(r) ELSE UNCHANGED <<holds, wire, phase, due>>
    /\ UNCHANGED <<pending, refusedL, refusedAt, offered, running, keeps, called, lock, own,
                   ownTaken>>

\* The program lets go of the query it keeps (FinalHolds::release_kept, engine.rs:9830-9832).
LetGo(r) ==
    /\ lock = Free /\ keeps[r] > 0
    /\ keeps' = [keeps EXCEPT ![r] = @ - 1]
    /\ Release(r)
    /\ UNCHANGED <<pending, refusedL, refusedAt, offered, running, replying, called, lock, own,
                   ownTaken>>

\* The session's own get takes a row under the session's lock before it asks
\* (OwnFinalHold::take, engine.rs:11579), and gives it back with the table's lock alone.
OwnTake ==
    /\ lock = Free /\ ~own /\ ownTaken < MaxOwn /\ (Used < Rows \/ ~RefuseFull)
    /\ own' = TRUE /\ ownTaken' = ownTaken + 1
    /\ UNCHANGED <<phase, pending, holds, due, refusedL, refusedAt, offered, running, keeps,
                   replying, called, wire, lock>>

OwnDrop ==
    /\ own /\ own' = FALSE
    /\ UNCHANGED <<phase, pending, holds, due, refusedL, refusedAt, offered, running, keeps,
                   replying, called, wire, lock, ownTaken>>

-----------------------------------------------------------------------------
Next ==
    \/ \E r \in Queries :
          \/ Arrive(r) \/ Owe(r) \/ Reply(r) \/ LetGo(r)
          \/ KeptReplyBegin(r) \/ KeptReplyWrite(r) \/ KeptReplyDone(r)
          \/ \E q \in Queryables :
                \/ \E begun \in BOOLEAN : Reach(r, q, begun)
                \/ Call(r, q) \/ Keep(r, q) \/ Return(r, q)
    \/ OwnTake \/ OwnDrop

Spec == Init /\ [][Next]_vars

\* A dispatch goes on, a held call is handed out, a callback ends, a reply begun is written, a
\* program lets go of what it keeps, and the own get gives its row back.
Fair ==
    /\ \A r \in Queries :
          /\ WF_vars(\E q \in Queryables, begun \in BOOLEAN : Reach(r, q, begun))
          /\ WF_vars(Owe(r))
          /\ WF_vars(KeptReplyWrite(r)) /\ WF_vars(KeptReplyDone(r))
          /\ WF_vars(LetGo(r))
          /\ \A q \in Queryables : WF_vars(Call(r, q)) /\ WF_vars(Return(r, q))
    /\ WF_vars(OwnDrop)

LiveSpec == Spec /\ Fair

-----------------------------------------------------------------------------
\* A querier is sent nothing after the Final, and one Final at most.
NothingAfterFinal ==
    \A r \in Queries : \A i \in 1..Len(wire[r]) : wire[r][i] = "final" => i = Len(wire[r])

\* A query refused for want of a row ran no callback and was sent nothing, not even a Final.
RefusedSilent ==
    \A r \in Queries : refusedAt[r] => (called[r] = {} /\ wire[r] = <<>>)

\* The table holds no more rows than it was lent.
Bounded == Used <= Rows

\* Every query that arrived ends, answered with its Final or refused.
Ends == \A r \in Queries : (phase[r] # "new") ~> (phase[r] \in {"done", "refused"})

\* No query holds a row: from every state the table can come to hold none of them.
NoRowHeld == \A r \in Queries : holds[r] = 0

-----------------------------------------------------------------------------
\* What the protocol implements (SCE ADR 0115, D2): the service a querier and a queryable rely on.
Service == INSTANCE QueryFinalService WITH
    Queries <- Queries,
    Queryables <- Queryables,
    phase <- [r \in Queries |->
                CASE phase[r] \in {"dispatch", "owed"} -> "open"
                  [] OTHER -> phase[r]],
    called <- called,
    wire <- wire

Refines == Service!Spec

=============================================================================
