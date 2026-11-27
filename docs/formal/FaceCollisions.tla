---------------------------- MODULE FaceCollisions ----------------------------
(***************************************************************************)
(* How the tokio runtime's accept loop keeps the promise of               *)
(* FaceCollisionService when links to a node it holds keep coming up      *)
(* (S4 26 of docs/zenoh-logic-as-sce-kinds.md; level 2 of SCE ADR 0115,   *)
(* D2).                                                                    *)
(*                                                                         *)
(* A link that completed its handshake to a node no face holds is HELD. A  *)
(* link to a node the face h holds is refused when h is CLOSING already    *)
(* (a third link while a replacement is under way), and is otherwise       *)
(* judged by the forwarder's rule: refused, or kept. A kept link is PARKED *)
(* behind h, which is asked to close; when h's DEPARTURE has been          *)
(* processed (the graph, keyed by the node's zid, loses its link to the    *)
(* node), the parked link is admitted as any other link is, in the same    *)
(* turn of the loop. The rule's verdict is any of the two, so every order  *)
(* of kept and refused links is explored.                                  *)
(*                                                                         *)
(* The tables are sources/algorithms/link_collision_rival.scxml,           *)
(* link_collision_park.scxml and link_collision_departed.scxml over the    *)
(* sets `dialled` and `closing`; the parked opens are the loop's            *)
(* (crates/wz-runtime-tokio/src/link_collision.rs @                        *)
(* `pub(crate) struct LinkCollisions<P> {`).                              *)
(*                                                                         *)
(* Each constant that is a part of the protocol can be switched off, and   *)
(* TLC must then find a violation.                                         *)
(*                                                                         *)
(* Taken as given:                                                         *)
(*   The loop is one task: a link's resolution, a departure and the        *)
(*     admission of what was parked behind it are steps of it, one at a    *)
(*     time (crates/wz-runtime-tokio/src/accept_loop.rs @                  *)
(*     `if let Some(parked) = self.collisions.departed(departed) {`).       *)
(*   A face's departure removes the graph's link to its node, keyed by    *)
(*     the node's zid and not by the face (accept_loop.rs @                *)
(*     `self.forwarder.deregister(face.id);`).                              *)
(*   A face asked to close does leave; a face never asked does not, and a  *)
(*     face that cannot be closed alone (one link of an aggregated         *)
(*     session) is not modelled.                                           *)
(*                                                                         *)
(* What upstream does, which the promise is read against: zenoh keeps one  *)
(* transport for each remote zid,                                          *)
(*   `io/zenoh-transport/src/unicast/manager.rs` @ `init_existing_transport_unicast`. *)
(***************************************************************************)
EXTENDS FiniteSets, Naturals

CONSTANTS Links,         \* the links that come up to the one node
          None,          \* no link: what nothing is parked behind
          Park,          \* a kept link waits for the held face to leave (link_collision_park.scxml)
          ThirdRefused   \* a link to a node whose face is closing is refused (link_collision_rival.scxml)

VARIABLES state,   \* state[l]: idle, held, refused, parked, closing or gone
          faces,   \* the faces the loop holds to the node
          graph,   \* whether the graph holds a link to the node
          parked,  \* parked[h]: the link parked behind the face h, or None
          turn     \* the link a departure freed, admitted before the loop's turn ends, or None

vars == <<state, faces, graph, parked, turn>>

Init == /\ state = [l \in Links |-> "idle"]
        /\ faces = {}
        /\ graph = FALSE
        /\ parked = [l \in Links |-> None]
        /\ turn = None

Admit(l) == /\ faces' = faces \cup {l}
            /\ graph' = TRUE

\* A link comes up to a node no face holds.
Fresh(l) ==
    /\ turn = None
    /\ state[l] = "idle" /\ faces = {}
    /\ state' = [state EXCEPT ![l] = "held"]
    /\ Admit(l)
    /\ UNCHANGED <<parked, turn>>

\* A link comes up to the node the face h holds: refused, or kept and parked behind h.
Rival(l, h, keep) ==
    /\ turn = None
    /\ state[l] = "idle" /\ h \in faces
    /\ UNCHANGED turn
    /\ IF (ThirdRefused /\ state[h] = "closing") \/ ~keep
       THEN /\ state' = [state EXCEPT ![l] = "refused"]
            /\ UNCHANGED <<faces, graph, parked>>
       ELSE IF Park
            THEN /\ state' = [state EXCEPT ![l] = "parked", ![h] = "closing"]
                 /\ parked' = [parked EXCEPT ![h] = l]
                 /\ UNCHANGED <<faces, graph>>
            ELSE /\ state' = [state EXCEPT ![l] = "held", ![h] = "closing"]
                 /\ Admit(l)
                 /\ UNCHANGED parked

\* The closing face h has left and its departure is processed: the graph loses the node's link.
\* What was parked behind it is freed, to be admitted before the turn ends.
Depart(h) ==
    /\ turn = None
    /\ state[h] = "closing"
    /\ state' = [state EXCEPT ![h] = "gone"]
    /\ faces' = faces \ {h}
    /\ graph' = FALSE
    /\ parked' = [parked EXCEPT ![h] = None]
    /\ turn' = parked[h]

\* The link a departure freed is admitted as any other link is, in the same turn.
AdmitParked ==
    /\ turn # None
    /\ state' = [state EXCEPT ![turn] = "held"]
    /\ Admit(turn)
    /\ turn' = None
    /\ UNCHANGED parked

Next == \/ AdmitParked
        \/ \E l \in Links :
              \/ Fresh(l) \/ Depart(l)
              \/ \E h \in Links, keep \in BOOLEAN : Rival(l, h, keep)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
\* The loop holds at most one face to the node.
OneFace == Cardinality(faces) <= 1

\* The graph holds a link to the node exactly while a face does.
GraphKept == graph = (faces # {})

\* A parked link waits behind a face, and is admitted when it leaves: none is dropped unseen.
NoneLost == \A l \in Links : state[l] = "parked" => (turn = l \/ \E h \in Links : parked[h] = l)

-----------------------------------------------------------------------------
Service == INSTANCE FaceCollisionService WITH
    Faces <- Links,
    held <- faces,
    graph <- graph

Refines == Service!Spec

=============================================================================
