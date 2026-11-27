------------------------------ MODULE PicoApiService ------------------------------
(***************************************************************************)
(* What a program written to zenoh-pico's API may rely on (level 1 of SCE  *)
(* ADR 0115, D1): a session opened and closed; the publishers,             *)
(* subscribers, queryables and liveliness tokens it declares and           *)
(* undeclares; the samples a put or a delete delivers; the replies to a get *)
(* and its end; what a liveliness subscriber is told. No table, lock,      *)
(* sequence number, task or frame is in it.                                *)
(*                                                                         *)
(* The session whose callbacks run is the session of this module: its      *)
(* subscribers, liveliness subscribers, queryables and gets. Publishers and *)
(* tokens may be of any session, this one among them, and the network      *)
(* between the sessions is environment.                                    *)
(*                                                                         *)
(* SESSION. Declarations are made on an open session. Closing it ends every *)
(* subscriber, liveliness subscriber and queryable it holds and every get  *)
(* still waiting, and once close returns no callback of the session runs.  *)
(*                                                                         *)
(* GONE. Once the undeclaration of a subscriber, a liveliness subscriber or *)
(* a queryable returns, its callback does not run again; once a get has    *)
(* ended, its reply callback does not run again (NothingAfterGone).        *)
(*                                                                         *)
(* SAMPLES. A put or a delete on key k is delivered only to subscribers    *)
(* whose key expression intersects k, never to one undeclared before it    *)
(* was put, and to each at most once (AtMostOnce). The samples of one      *)
(* publisher on one reliability channel reach a subscriber in the order    *)
(* they were put (InOrder). A sample put before a subscriber was declared  *)
(* may reach it or not. What may be lost, by the sample's class:           *)
(*   best effort: any sample;                                              *)
(*   reliable, congestion control DROP: any sample, as best effort;        *)
(*   reliable, congestion control BLOCK: none while the link to the        *)
(*     subscriber's session holds (ReliableNoGap): a subscriber is given   *)
(*     every such sample put between two losses of the link.               *)
(* A loss of the link (Break) may lose every sample in flight.             *)
(*                                                                         *)
(* QUERIES. At the session of the queryables a get reaches, the query is   *)
(* refused whole or answered as QueryFinalService states, which this module *)
(* instantiates whole as its clause of a queryable. The querier is given   *)
(* only replies that were sent, and its get then ENDS exactly once: at the *)
(* Final, at its timeout, or when its session closes. Every get ends       *)
(* (GetsEnd), since its timeout comes.                                     *)
(*                                                                         *)
(* LIVELINESS. A liveliness subscriber is told PUT of a token that is alive *)
(* and reachable, and DELETE of one it may have been told of that was      *)
(* undeclared or whose link was lost; per token the two alternate, and the *)
(* first may be a DELETE when the subscriber was declared after the token  *)
(* was seen. A DELETE is never told of a token that is alive while its     *)
(* link holds (NoFalseDeath).                                              *)
(*                                                                         *)
(* THE NETWORK is environment, with the faults of a channel of ADR 0115 D7 *)
(* (amended 2026-11-23). What a user sees of each: a duplicated frame,     *)
(* nothing; a reordered frame, a loss (the late one is dropped, never      *)
(* delivered out of order); a lost frame, a loss; a link lost whole, a     *)
(* Break, after which the session may reconnect (Reconnect).               *)
(*                                                                         *)
(* Taken as given, each a constant a configuration takes out:              *)
(*   OneRoute: the samples of a publisher reach a subscribing session over *)
(*     one chain of links. zenoh-pico judges order and repetition per peer: *)
(*     `vendor/zenoh-pico/src/transport/unicast/rx.c` @ `if (_z_sn_precedes(ztu->_common._sn_res, peer->_sn_rx_best_effort, msg->_sn)) {` *)
(*     and drops what is out of order,                                     *)
(*     `vendor/zenoh-pico/src/transport/unicast/rx.c` @ `_Z_INFO("Best effort message dropped because it is out of order");` *)
(*   StreamLink: the link under a reliable channel loses and reorders      *)
(*     nothing short of being lost whole (TCP, TLS). zenoh-pico takes a    *)
(*     reliable frame by its order alone and asks for none again:          *)
(*     `vendor/zenoh-pico/src/transport/unicast/rx.c` @ `// @TODO: amend once reliability is in place. For the time being only` *)
(*   TimelyLink: a link that holds delivers within the lease. A peer not   *)
(*     heard from for a lease is judged gone,                              *)
(*     `vendor/zenoh-pico/src/transport/unicast/lease.c` @ `_Z_INFO("Closing session because it has expired after %zums", ztu->_common._lease);` *)
(*     and every token known through it is told DELETE,                    *)
(*     `vendor/zenoh-pico/src/transport/unicast/lease.c` @ `_z_liveliness_subscription_undeclare_all(zs);` *)
(*   WaitsForCallbacks: close and undeclare return after the last run of   *)
(*     the callbacks they end. It is a clause of the promise, not of the   *)
(*     environment, stated by zenoh-pico for close,                        *)
(*     `vendor/zenoh-pico/src/session/utils.c` @ `this is the only way to guarantee that after _z_session_close returns,` *)
(*     and kept by an undeclaration that waits for its callback's drop,    *)
(*     `vendor/zenoh-pico/src/net/primitives.c` @ `? _z_sync_group_wait(&sub->_callback_drop_sync_group)` *)
(*   LiveSpec: a get's timeout comes (the clock runs),                     *)
(*     `vendor/zenoh-pico/src/session/query.c` @ `_Z_INFO("Dropping query because of timeout");` *)
(*                                                                         *)
(* What zenoh-pico 1.10.2 does, which the rest is read against:            *)
(*   a sample goes to the subscriptions whose key intersects its own,      *)
(*     `vendor/zenoh-pico/src/session/subscription.c` @ `if (origin_allowed && _z_keyexpr_intersects(&sub_val->_key._inner, key)) {` *)
(*     a delete by the same path as a put,                                 *)
(*     `vendor/zenoh-pico/src/api/api.c` @ `keyexpr, NULL, NULL, Z_SAMPLE_KIND_DELETE, opt.congestion_control` *)
(*     and an undeclared subscription is out of the list before it returns, *)
(*     `vendor/zenoh-pico/src/session/subscription.c` @ `zn->_subscriptions = _z_subscription_rc_slist_drop_first_filter(zn->_subscriptions, _z_subscription_rc_eq, sub);` *)
(*   congestion control DROP drops a sample, BLOCK waits,                  *)
(*     `vendor/zenoh-pico/include/zenoh-pico/api/constants.h` @ `Messages are dropped in case` *)
(*     `vendor/zenoh-pico/src/transport/common/tx.c` @ `_Z_INFO("Dropping zenoh message because of congestion control");` *)
(*     and DROP is a put's default,                                        *)
(*     `vendor/zenoh-pico/include/zenoh-pico/api/constants.h` @ `static inline z_congestion_control_t z_internal_congestion_control_default_push(void) {` *)
(*   a get ends by the drop of its reply closure, at the Final,            *)
(*     `vendor/zenoh-pico/src/session/query.c` @ `// Finalize query if requested: drop pending query and trigger dropper callback,` *)
(*     `vendor/zenoh-pico/src/session/query.c` @ `pen_qry->_dropper(pen_qry->_arg);` *)
(*     at close, `vendor/zenoh-pico/src/session/utils.c` @ `_z_flush_pending_queries(zn);` *)
(*     and a reply for a get that ended is given to no one,                *)
(*     `vendor/zenoh-pico/src/session/query.c` @ `// Not concerned by the reply` *)
(*     and with consolidation LATEST the replies are given at the Final,   *)
(*     none at a timeout,                                                  *)
(*     `vendor/zenoh-pico/src/session/query.c` @ `if (pen_qry->_consolidation == Z_CONSOLIDATION_MODE_LATEST && do_finalize) {` *)
(*   a queryable replies from its callback, or from a query it took,       *)
(*     `vendor/zenoh-pico/include/zenoh-pico/api/primitives.h` @ `be called multiple times to send multiple replies to a query. The reply will be considered complete when the callback` *)
(*   a liveliness subscriber is told PUT and DELETE,                       *)
(*     `vendor/zenoh-pico/include/zenoh-pico/api/liveliness.h` @ `Liveliness token subscribers on an intersecting key expression will receive a PUT sample when connectivity` *)
(*     and a token's declaration seen again is not told again,             *)
(*     `vendor/zenoh-pico/src/session/liveliness.c` @ `_Z_DEBUG("Duplicate token id %i", (int)id);` *)
(*                                                                         *)
(* Not in it: a liveliness subscriber's history and the liveliness get;    *)
(* consolidation; the key expression algebra past equality and one         *)
(* wildcard subscriber; a query's target and the keys of queryables;       *)
(* payloads, encodings, attachments, timestamps; matching listeners and    *)
(* the advanced publisher and subscriber; the close of a publisher's or a  *)
(* token's own session, which is their undeclaration here.                 *)
(***************************************************************************)
EXTENDS Naturals, Sequences

CONSTANTS Pubs,        \* publishers, of any session
          Keys,        \* the keys a sample is put on
          Subs,        \* this session's subscribers; a subscriber in Keys is on that key
          Wild,        \* the subscriber on a key expression every key intersects
          MaxPuts,     \* the samples put, for a finite exploration
          Queries,     \* this session's gets, each a query once it reaches a queryable
          Queryables,  \* this session's queryables
          MaxReplies,  \* the replies one query is sent, for a finite exploration
          Tokens,      \* liveliness tokens, of any session
          LSubs,       \* this session's liveliness subscribers
          WaitsForCallbacks, \* close and undeclare return after their callbacks' last run
          OneRoute,    \* one chain of links from a publisher to this session
          StreamLink,  \* a reliable channel's link loses only whole
          TimelyLink   \* a link that holds delivers within the lease

VARIABLES session,    \* init, open or closed
          linked,     \* the link from this session to the rest holds
          pub,        \* pub[p]: none, declared or gone
          sub,        \* sub[s]: none, declared or gone
          puts,       \* every sample put, in order: its publisher, key and class
          pending,    \* pending[<<s, r, p, c>>]: the samples of p on channel c in flight to s on route r
          got,        \* got[s]: the samples s was given, in order
          gap,        \* history: a reliable BLOCK sample was lost while the link held
          qbl,        \* qbl[q]: none, declared or gone
          phase, called, wire, \* QueryFinalService's, of each query
          get,        \* get[g]: none, pending or ended
          rcvd,       \* rcvd[g]: the replies g's querier was given
          tok,        \* tok[t]: none, alive or gone
          lsub,       \* lsub[l]: none, declared or gone
          seen,       \* seen[t]: this session holds t alive, as it last told
          last,       \* last[<<l, t>>]: what l was last told of t: none, put or del
          falseDeath, \* history: a DELETE was told of a token alive with its link holding
          late        \* history: a callback ran for what was gone

QF == INSTANCE QueryFinalService

samplesV == <<pub, sub, puts, pending, got, gap>>
queryV == <<qbl, phase, called, wire, get, rcvd>>
livV == <<tok, lsub, seen, last, falseDeath>>
vars == <<session, linked, late, samplesV, queryV, livV>>

Classes == {"reliable_block", "reliable_drop", "best_effort"}
Channels == {"reliable", "best_effort"}
ChannelOf(c) == IF c = "best_effort" THEN "best_effort" ELSE "reliable"
Routes == IF OneRoute THEN {1} ELSE {1, 2}
Ways == Subs \X Routes \X Pubs \X Channels
Intersects(k, s) == s = Wild \/ s = k
\* What the environment may lose of a sample while the link holds.
Losable(id) == puts[id].cls # "reliable_block" \/ ~StreamLink
\* A callback runs for what is declared; for what is gone only if its end did not wait.
MayCall(ph) == ph = "declared" \/ (~WaitsForCallbacks /\ ph = "gone")
Gone(f) == [e \in DOMAIN f |-> IF f[e] = "declared" THEN "gone" ELSE f[e]]
IsReply(e) == e = "reply"
Replies(w) == Len(SelectSeq(w, IsReply))

Init == /\ session = "init"
        /\ linked = TRUE
        /\ pub = [p \in Pubs |-> "none"]
        /\ sub = [s \in Subs |-> "none"]
        /\ puts = <<>>
        /\ pending = [x \in Ways |-> <<>>]
        /\ got = [s \in Subs |-> <<>>]
        /\ gap = FALSE
        /\ qbl = [q \in Queryables |-> "none"]
        /\ QF!Init
        /\ get = [g \in Queries |-> "none"]
        /\ rcvd = [g \in Queries |-> 0]
        /\ tok = [t \in Tokens |-> "none"]
        /\ lsub = [l \in LSubs |-> "none"]
        /\ seen = [t \in Tokens |-> FALSE]
        /\ last = [x \in LSubs \X Tokens |-> "none"]
        /\ falseDeath = FALSE
        /\ late = FALSE

(* The session *)

Open == /\ session = "init"
        /\ session' = "open"
        /\ UNCHANGED <<linked, late, samplesV, queryV, livV>>

Close == /\ session = "open"
         /\ session' = "closed"
         /\ sub' = Gone(sub)
         /\ qbl' = Gone(qbl)
         /\ lsub' = Gone(lsub)
         /\ get' = [g \in Queries |-> IF get[g] = "pending" THEN "ended" ELSE get[g]]
         /\ UNCHANGED <<linked, late, pub, puts, pending, got, gap,
                        phase, called, wire, rcvd, tok, seen, last, falseDeath>>

(* The environment's link *)

Break == /\ linked
         /\ linked' = FALSE
         /\ pending' = [x \in Ways |-> <<>>]
         /\ UNCHANGED <<session, late, pub, sub, puts, got, gap, queryV, livV>>

Reconnect == /\ ~linked
             /\ linked' = TRUE
             /\ UNCHANGED <<session, late, samplesV, queryV, livV>>

(* Samples *)

DeclarePub(p) == /\ pub[p] = "none"
                 /\ pub' = [pub EXCEPT ![p] = "declared"]
                 /\ UNCHANGED <<session, linked, late, sub, puts, pending, got, gap, queryV, livV>>

UndeclarePub(p) == /\ pub[p] = "declared"
                   /\ pub' = [pub EXCEPT ![p] = "gone"]
                   /\ UNCHANGED <<session, linked, late, sub, puts, pending, got, gap, queryV, livV>>

DeclareSub(s) == /\ session = "open" /\ sub[s] = "none"
                 /\ sub' = [sub EXCEPT ![s] = "declared"]
                 /\ UNCHANGED <<session, linked, late, pub, puts, pending, got, gap, queryV, livV>>

UndeclareSub(s) == /\ sub[s] = "declared"
                   /\ sub' = [sub EXCEPT ![s] = "gone"]
                   /\ UNCHANGED <<session, linked, late, pub, puts, pending, got, gap, queryV, livV>>

\* A sample is put; it is in flight, on every route, to each subscriber whose key
\* intersects its own and that is not gone, while the link holds.
Put(p, k, c) ==
    /\ pub[p] = "declared" /\ Len(puts) < MaxPuts
    /\ puts' = Append(puts, [pub |-> p, key |-> k, cls |-> c])
    /\ pending' = [x \in Ways |->
                     IF /\ linked /\ x[3] = p /\ x[4] = ChannelOf(c)
                        /\ Intersects(k, x[1]) /\ sub[x[1]] # "gone"
                     THEN Append(pending[x], Len(puts) + 1)
                     ELSE pending[x]]
    /\ UNCHANGED <<session, linked, late, pub, sub, got, gap, queryV, livV>>

\* The i-th sample in flight on way x is given to its subscriber; the ones before it on
\* that way are lost.
Deliver(x, i) ==
    LET s == x[1]
        q == pending[x]
        lost == {q[j] : j \in 1..(i - 1)}
    IN /\ MayCall(sub[s])
       /\ \A id \in lost : Losable(id)
       /\ got' = [got EXCEPT ![s] = Append(@, q[i])]
       /\ pending' = [pending EXCEPT ![x] = SubSeq(q, i + 1, Len(q))]
       /\ gap' = (gap \/ \E id \in lost : puts[id].cls = "reliable_block")
       /\ late' = (late \/ sub[s] = "gone")
       /\ UNCHANGED <<session, linked, pub, sub, puts, queryV, livV>>

(* Queries: the querier's get and, at the queryables' session, QueryFinalService *)

Issue(g) == /\ session = "open" /\ get[g] = "none"
            /\ get' = [get EXCEPT ![g] = "pending"]
            /\ UNCHANGED <<session, linked, late, samplesV, qbl, phase, called, wire, rcvd, livV>>

DeclareQbl(q) == /\ session = "open" /\ qbl[q] = "none"
                 /\ qbl' = [qbl EXCEPT ![q] = "declared"]
                 /\ UNCHANGED <<session, linked, late, samplesV, phase, called, wire, get, rcvd, livV>>

UndeclareQbl(q) == /\ qbl[q] = "declared"
                   /\ qbl' = [qbl EXCEPT ![q] = "gone"]
                   /\ UNCHANGED <<session, linked, late, samplesV, phase, called, wire, get, rcvd, livV>>

\* The steps of QueryFinalService, each as it states it, and only while its session holds.
QArrive(r) == /\ get[r] # "none" /\ QF!Arrive(r)
              /\ UNCHANGED <<session, linked, late, samplesV, qbl, get, rcvd, livV>>

QRefuse(r) == /\ QF!Refuse(r)
              /\ UNCHANGED <<session, linked, late, samplesV, qbl, get, rcvd, livV>>

QCall(r, q) == /\ MayCall(qbl[q]) /\ QF!Call(r, q)
               /\ late' = (late \/ qbl[q] = "gone")
               /\ UNCHANGED <<session, linked, samplesV, qbl, get, rcvd, livV>>

QReply(r) == /\ session = "open" /\ Len(wire[r]) < MaxReplies /\ QF!Reply(r)
             /\ UNCHANGED <<session, linked, late, samplesV, qbl, get, rcvd, livV>>

QFinish(r) == /\ session = "open" /\ QF!Finish(r)
              /\ UNCHANGED <<session, linked, late, samplesV, qbl, get, rcvd, livV>>

\* The querier is given a reply that was sent and not given yet; one never given is lost.
Receive(g) == /\ \/ get[g] = "pending"
                 \/ ~WaitsForCallbacks /\ get[g] = "ended"
              /\ rcvd[g] < Replies(wire[g])
              /\ rcvd' = [rcvd EXCEPT ![g] = @ + 1]
              /\ late' = (late \/ get[g] = "ended")
              /\ UNCHANGED <<session, linked, samplesV, qbl, phase, called, wire, get, livV>>

EndAtFinal(g) == /\ get[g] = "pending"
                 /\ wire[g] # <<>> /\ wire[g][Len(wire[g])] = "final"
                 /\ get' = [get EXCEPT ![g] = "ended"]
                 /\ UNCHANGED <<session, linked, late, samplesV, qbl, phase, called, wire, rcvd, livV>>

Timeout(g) == /\ get[g] = "pending"
              /\ get' = [get EXCEPT ![g] = "ended"]
              /\ UNCHANGED <<session, linked, late, samplesV, qbl, phase, called, wire, rcvd, livV>>

(* Liveliness *)

DeclareTok(t) == /\ tok[t] = "none"
                 /\ tok' = [tok EXCEPT ![t] = "alive"]
                 /\ UNCHANGED <<session, linked, late, samplesV, queryV, lsub, seen, last, falseDeath>>

UndeclareTok(t) == /\ tok[t] = "alive"
                   /\ tok' = [tok EXCEPT ![t] = "gone"]
                   /\ UNCHANGED <<session, linked, late, samplesV, queryV, lsub, seen, last, falseDeath>>

DeclareLSub(l) == /\ session = "open" /\ lsub[l] = "none"
                  /\ lsub' = [lsub EXCEPT ![l] = "declared"]
                  /\ UNCHANGED <<session, linked, late, samplesV, queryV, tok, seen, last, falseDeath>>

UndeclareLSub(l) == /\ lsub[l] = "declared"
                    /\ lsub' = [lsub EXCEPT ![l] = "gone"]
                    /\ UNCHANGED <<session, linked, late, samplesV, queryV, tok, seen, last, falseDeath>>

Tell(t, kind) == [x \in LSubs \X Tokens |->
                   IF x[2] = t /\ MayCall(lsub[x[1]]) THEN kind ELSE last[x]]
TellsGone == \E l \in LSubs : lsub[l] = "gone" /\ MayCall(lsub[l])

Appear(t) == /\ session = "open" /\ linked /\ tok[t] = "alive" /\ ~seen[t]
             /\ seen' = [seen EXCEPT ![t] = TRUE]
             /\ last' = Tell(t, "put")
             /\ late' = (late \/ TellsGone)
             /\ UNCHANGED <<session, linked, samplesV, queryV, tok, lsub, falseDeath>>

\* A token told alive is told gone when it was undeclared or its link was lost; a link
\* slower than the lease is judged lost while it holds.
Vanish(t) == /\ session = "open" /\ seen[t]
             /\ tok[t] = "gone" \/ ~linked \/ ~TimelyLink
             /\ seen' = [seen EXCEPT ![t] = FALSE]
             /\ last' = Tell(t, "del")
             /\ falseDeath' = (falseDeath \/ (tok[t] = "alive" /\ linked))
             /\ late' = (late \/ TellsGone)
             /\ UNCHANGED <<session, linked, samplesV, queryV, tok, lsub>>

Next == \/ Open \/ Close \/ Break \/ Reconnect
        \/ \E p \in Pubs : DeclarePub(p) \/ UndeclarePub(p)
        \/ \E p \in Pubs, k \in Keys, c \in Classes : Put(p, k, c)
        \/ \E s \in Subs : DeclareSub(s) \/ UndeclareSub(s)
        \/ \E x \in Ways : \E i \in 1..Len(pending[x]) : Deliver(x, i)
        \/ \E q \in Queryables : DeclareQbl(q) \/ UndeclareQbl(q)
        \/ \E r \in Queries :
              \/ Issue(r) \/ QArrive(r) \/ QRefuse(r) \/ QReply(r) \/ QFinish(r)
              \/ Receive(r) \/ EndAtFinal(r) \/ Timeout(r)
              \/ \E q \in Queryables : QCall(r, q)
        \/ \E t \in Tokens : DeclareTok(t) \/ UndeclareTok(t) \/ Appear(t) \/ Vanish(t)
        \/ \E l \in LSubs : DeclareLSub(l) \/ UndeclareLSub(l)

Spec == Init /\ [][Next]_vars

LiveSpec == Spec /\ \A g \in Queries : WF_vars(Timeout(g))

(* What the promise says, each as a check *)

\* No callback runs for a subscriber, liveliness subscriber or queryable whose end
\* returned, nor for a get that ended.
NothingAfterGone == ~late

\* The samples of one publisher on one channel reach a subscriber in the order put.
InOrder == \A s \in Subs : \A i, j \in 1..Len(got[s]) :
               (/\ i < j
                /\ puts[got[s][i]].pub = puts[got[s][j]].pub
                /\ ChannelOf(puts[got[s][i]].cls) = ChannelOf(puts[got[s][j]].cls))
               => got[s][i] <= got[s][j]

\* No subscriber is given a sample twice.
AtMostOnce == \A s \in Subs : \A i, j \in 1..Len(got[s]) : i < j => got[s][i] # got[s][j]

\* No reliable sample put with congestion control BLOCK is lost while the link holds.
ReliableNoGap == ~gap

\* No DELETE is told of a token that is alive while its link holds.
NoFalseDeath == ~falseDeath

\* Every get ends.
GetsEnd == \A g \in Queries : (get[g] = "pending") ~> (get[g] = "ended")

=============================================================================
