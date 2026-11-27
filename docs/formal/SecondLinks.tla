------------------------------ MODULE SecondLinks ------------------------------
(***************************************************************************)
(* How two nodes' link books keep the promise of SecondLinkService when    *)
(* each dials the other at once (S1 55 of docs/zenoh-logic-as-sce-kinds.md;*)
(* level 2 of SCE ADR 0115, D2). Link x is dialled by node a, link y by    *)
(* node b.                                                                 *)
(*                                                                         *)
(* A link's handshake asks the books three things in order: its INITIATOR *)
(* reserves it when the InitAck names the remote, its ACCEPTOR reserves it *)
(* when the OpenSyn does (and is established from then, as it sends the    *)
(* OpenAck), and the initiator CONFIRMS it before it takes the OpenAck. A  *)
(* refusal at any of the three closes the link, which carried nothing. A   *)
(* reservation reads the other link's row in the same book: an            *)
(* ESTABLISHED row keeps its place; a row in its handshake that went the   *)
(* same way keeps its place; one that went the other way is judged by the  *)
(* two zids' ranks, the link the lower one dialled being kept and the      *)
(* other SUPERSEDED, which its initiator's confirmation refuses.           *)
(*                                                                         *)
(* The verdict of a row is sources/algorithms/link_rival.scxml and the     *)
(* zid rule sources/algorithms/judge_second_link.scxml; the book is        *)
(* LinkBook (crates/wz-session-core/src/link_admission.rs @                *)
(* `pub fn reserve(&mut self, token: u64, remote_zid: &[u8]) -> bool {`).  *)
(*                                                                         *)
(* Each constant that is a part of the protocol can be switched off, and   *)
(* TLC must then find a violation.                                         *)
(*                                                                         *)
(* Taken as given:                                                         *)
(*   Each book is asked under its node's lock, one question at a time     *)
(*     (LinkRegistry, link_admission.rs @ `impl<R: Runtime> LinkAdmission *)
(*     for LinkRegistry<R> {`).                                            *)
(*   Only a link its acceptor admitted and its initiator confirmed carries *)
(*     anything: the acceptor answers only the OpenSyn it admitted, and    *)
(*     the initiator sends nothing before the OpenAck it took.             *)
(*   Both nodes rank the zids by one `link-tie-order`, so they agree on    *)
(*     which is the lower (AIsLower).                                      *)
(*   A closed link keeps its rows until it is released, and a release is  *)
(*     not modelled: the books are read as the unit test                   *)
(*     `two_nodes_that_dial_each_other_at_once_end_with_one_link` reads    *)
(*     them.                                                               *)
(*                                                                         *)
(* What upstream does, which the promise is read against: zenoh keeps one  *)
(* transport for each remote zid and refuses a second link to a held node, *)
(*   `io/zenoh-transport/src/unicast/manager.rs` @                         *)
(*   `init_existing_transport_unicast`;                                    *)
(* the collision of two links that cross is resolved by the identifiers,   *)
(* as BGP resolves a connection collision (RFC 4271 section 6.8).          *)
(***************************************************************************)
EXTENDS FiniteSets, Naturals

CONSTANTS AIsLower,         \* node a's zid ranks below node b's
          ZidRule,          \* two crossing links are judged by the zids (judge_second_link.scxml)
          EstablishedHolds  \* an established row keeps its place (link_rival.scxml)

Nodes == {"a", "b"}
Links == {"x", "y"}

Initiator(l) == IF l = "x" THEN "a" ELSE "b"
Acceptor(l) == IF l = "x" THEN "b" ELSE "a"
Other(l) == IF l = "x" THEN "y" ELSE "x"
Lower(n) == IF n = "a" THEN AIsLower ELSE ~AIsLower

VARIABLES row,     \* row[n][l]: none, hs (in its handshake), est or sup, in n's book
          step,    \* step[l]: start, initRes, accRes, done or dead
          carried  \* the links confirmed, which carry declarations

vars == <<row, step, carried>>

Init == /\ row = [n \in Nodes |-> [l \in Links |-> "none"]]
        /\ step = [l \in Links |-> "start"]
        /\ carried = {}

\* What the row of the other link in n's book says of l, dialled by n or not (link_rival.scxml).
Says(n, l, dialled) ==
    LET o == Other(l)
        heldDialled == Initiator(o) = n
        judged == IF dialled = Lower(n) THEN "replace" ELSE "refuse"
    IN CASE row[n][o] \in {"none", "sup"} -> "none"
         [] row[n][o] = "est" /\ EstablishedHolds -> "refuse"
         [] heldDialled = dialled -> "refuse"
         [] ZidRule -> judged
         [] OTHER -> "refuse"

\* n reserves l in its book: refused, or admitted, a superseded rival marked.
Reserve(n, l, dialled, next) ==
    LET says == Says(n, l, dialled)
    IN IF says = "refuse"
       THEN /\ step' = [step EXCEPT ![l] = "dead"]
            /\ UNCHANGED row
       ELSE /\ row' = [row EXCEPT ![n][l] = IF dialled THEN "hs" ELSE "est",
                                  ![n][Other(l)] = IF says = "replace" THEN "sup" ELSE @]
            /\ step' = [step EXCEPT ![l] = next]

InitiatorReserve(l) ==
    /\ step[l] = "start"
    /\ Reserve(Initiator(l), l, TRUE, "initRes")
    /\ UNCHANGED carried

AcceptorReserve(l) ==
    /\ step[l] = "initRes"
    /\ Reserve(Acceptor(l), l, FALSE, "accRes")
    /\ UNCHANGED carried

InitiatorConfirm(l) ==
    /\ step[l] = "accRes"
    /\ LET n == Initiator(l)
       IN IF row[n][l] = "sup"
          THEN /\ step' = [step EXCEPT ![l] = "dead"]
               /\ UNCHANGED <<row, carried>>
          ELSE /\ row' = [row EXCEPT ![n][l] = "est"]
               /\ step' = [step EXCEPT ![l] = "done"]
               /\ carried' = carried \cup {l}

Next == \E l \in Links :
            \/ InitiatorReserve(l) \/ AcceptorReserve(l) \/ InitiatorConfirm(l)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
\* At most one link carries declarations.
AtMostOne == Cardinality(carried) <= 1

\* Once both handshakes have ended, one link carries.
OneWhenSettled == (\A l \in Links : step[l] \in {"done", "dead"}) => carried # {}

-----------------------------------------------------------------------------
Service == INSTANCE SecondLinkService WITH
    Links <- Links,
    carried <- carried,
    closed <- {l \in Links : step[l] = "dead"}

Refines == Service!Spec

=============================================================================
