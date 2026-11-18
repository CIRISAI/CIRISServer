---------------------------- MODULE DirectorySeat ----------------------------
(* A directory seat: the bare minimum a seated serve node does for a node joining the mesh (DESIGN.md).

   It serves the genesis bundle, admits a node's own signed registration (its key:record and its signed
   transport_destination binding, one message), answers a lookup for a key with that key's own newest signed
   binding when the route is one a forwarder may serve (CC 5.4.6: an unowned node's route, or a referral to an
   announced node whose owner offers relay), and copies verified rows to and from its replicas. It signs nothing,
   holds nothing but those rows, keeps no first-come state, and decides nothing that the rows do not decide.

   The world: nodes that root on the bundle, join on a transport identity and may move to another one (a wipe, a
   crash, a restart: the CIRISEdge#1004 shape); an adversary that sends forged registrations and unauthenticated
   announces from its own transport identity; and optionally a Byzantine replica that serves any row it has seen
   and any bundle. A joining node verifies what it is told before it dials.

   Planted breaks are constants; each twin configuration turns one on and must fail on its own property.

   Traceability: every action and operator below carries a `@trace` tag. `impl=<rust path>` names the one Rust
   function that implements it (and that function names it back with `@tla <Name>`); `env` is the world the seat
   does not implement; `plant` is a break that exists only to be caught. scripts/trace_check.py checks both
   directions. *)
EXTENDS Naturals, FiniteSets

CONSTANTS Keys,          \* federation keys of joining nodes
          BareKeys,      \* unowned nodes (a bare server): their route is public (CC 5.4.6)
          RelayKeys,     \* owned, announced nodes whose owner offers relay: referable (CC 5.4.3, 5.4.6)
          HonestTids,    \* transport identities honest nodes use
          AdvTid,        \* the adversary's own transport identity
          Seats,         \* directory replicas named by the bundle (or behind one seated name)
          Byz,           \* replicas that lie (subset of Seats)
          MaxVer,        \* bound on a node's moves; ver stands for the binding's signed asserted_at
          FirstCome,     \* plant: an unauthenticated first announce binds a key to a transport (CIRISEdge#1004)
          NoDerive,      \* plant: admission skips key_id = H(pubkey) (a record under someone else's name)
          SeatAuthority, \* plant: the seat may write a binding for a key it does not hold (canonical priming)
          ServeOwned,    \* plant: the seat serves an owned, unreferable node's route
          NoAnchor       \* plant: a node accepts a bundle that does not match its out-of-band anchor

OwnedKeys == Keys \ (BareKeys \cup RelayKeys)
Honest    == Seats \ Byz
Tids      == HonestTids \cup {AdvTid}
NoTid     == "none"
NoAnswer  == [key |-> "none"]
\* The adversary announces every key from its own transport identity before anyone else.
AdvHints  == {<<k, AdvTid>> : k \in Keys}
Signers   == Keys \cup Seats \cup {"adv"}
Reg       == [key : Keys, tid : Tids, ver : 0..MaxVer, signer : Signers, rec : {"true", "forged"}]

\* The adversary's registrations, sent before anything happens: one under each key's name with its own public key
\* in the record (the signature verifies against that record; only key_id = H(pub) catches it), and one signed by
\* its own key and claiming the name.
Forged == { [key |-> k, tid |-> AdvTid, ver |-> MaxVer, signer |-> k,     rec |-> "forged"] : k \in Keys }
     \cup { [key |-> k, tid |-> AdvTid, ver |-> MaxVer, signer |-> "adv", rec |-> "true"]   : k \in Keys }

VARIABLES root,       \* per node: the bundle it rooted on
          joined,     \* per node
          tid,        \* per node: its current transport identity
          ver,        \* per node: the asserted_at of its newest binding
          net,        \* every registration ever sent (links retry, so a set)
          held,       \* per seat: the verified rows it holds -- its ONLY state in the design
          resident,   \* per seat, per key: the first-come binding (non-empty only under the FirstCome plant)
          misdirected \* a node ever accepted, and would dial, a transport its key never published
vars == <<root, joined, tid, ver, net, held, resident, misdirected>>

\* Derived, to keep the state small: what honest nodes signed, and what was announced on the wire.
Genuine(m) == m.signer = m.key /\ m.rec = "true"
published  == {<<m.key, m.tid>> : m \in {x \in net : Genuine(x)}}
hints      == AdvHints \cup published

TypeOK ==
    /\ root \in [Keys -> {"none", "genesis", "forged"}]
    /\ joined \in [Keys -> BOOLEAN]
    /\ tid \in [Keys -> Tids \cup {NoTid}]
    /\ ver \in [Keys -> 0..MaxVer]
    /\ net \subseteq Reg
    /\ held \in [Seats -> SUBSET Reg]
    /\ resident \in [Seats -> [Keys -> Tids \cup {NoTid}]]
    /\ misdirected \in BOOLEAN

----------------------------------------------------------------------------
(* Operators the seat implements. *)

\* @trace op=Valid impl=seat::verify_registration
\* The row's signature verifies under the record it carries, and the record's key_id is the hash of its key.
Valid(m) ==
    /\ \/ m.signer = m.key
       \/ SeatAuthority /\ m.signer \in Seats
    /\ m.rec = "true" \/ NoDerive

HasKey(s, k) == \E m \in held[s] : m.key = k

\* @trace op=Admissible impl=seat::admissible
\* A genuine registration is admissible whatever else the seat has heard. Under the plant, an unproven first
\* announce for the key on another transport blocks it until the key is known by some other path.
Admissible(s, m) ==
    /\ Valid(m)
    /\ FirstCome => (resident[s][m.key] \in {NoTid, m.tid} \/ HasKey(s, m.key))

\* @trace op=Servable impl=seat::servable
\* CC 5.4.6: a forwarder serves the routes of unowned nodes; an owned node's route only in a referral, which the
\* owner's relay offer makes. Never an unannounced or non-offering owned node's.
Servable(k) == k \in BareKeys \cup RelayKeys \/ ServeOwned

Newest(C) == CHOOSE m \in C : \A m2 \in C : m2.ver <= m.ver

\* @trace op=Answer impl=seat::answer_lookup
\* A function of the held rows only: two replicas holding the same rows answer the same.
Answer(s, k) ==
    LET C == {m \in held[s] : m.key = k}
    IN IF C = {} \/ ~Servable(k) THEN NoAnswer ELSE Newest(C)

\* @trace op=NodeAccepts impl=client::accept_answer
\* The joining node's own check, independent of the seat: it never takes the seat's word for a key.
NodeAccepts(m, k) == m.key = k /\ m.signer = k /\ m.rec = "true"

Source(s) == IF s \in Byz THEN net ELSE held[s]
AnswerSet(s, k) ==
    IF s \in Byz THEN {m \in net : m.key = k}
    ELSE IF Answer(s, k) = NoAnswer THEN {} ELSE {Answer(s, k)}
ServedBundles(s) == IF s \in Byz THEN {"genesis", "forged"} ELSE {"genesis"}

----------------------------------------------------------------------------
Init ==
    /\ root = [k \in Keys |-> "none"]
    /\ joined = [k \in Keys |-> FALSE]
    /\ tid = [k \in Keys |-> NoTid]
    /\ ver = [k \in Keys |-> 0]
    /\ net = Forged
    /\ held = [s \in Seats |-> {}]
    /\ resident = [s \in Seats |-> [k \in Keys |-> NoTid]]
    /\ misdirected = FALSE

\* @trace action=FetchBundle impl=client::accept_bundle
\* A node fetches the bundle from a seat and keeps it only if it matches the anchor it was built with (CC 5.3.4).
FetchBundle(k, s) ==
    /\ root[k] = "none"
    /\ \E b \in ServedBundles(s) :
          /\ b = "genesis" \/ NoAnchor
          /\ root' = [root EXCEPT ![k] = b]
    /\ UNCHANGED <<joined, tid, ver, net, held, resident, misdirected>>

\* @trace action=Join env
\* A rooted node signs its key record and binding and sends them as one registration; it also announces.
Join(k, t) ==
    /\ root[k] = "genesis"
    /\ ~joined[k]
    /\ joined' = [joined EXCEPT ![k] = TRUE]
    /\ tid' = [tid EXCEPT ![k] = t]
    /\ ver' = [ver EXCEPT ![k] = 0]
    /\ net' = net \cup {[key |-> k, tid |-> t, ver |-> 0, signer |-> k, rec |-> "true"]}
    /\ UNCHANGED <<root, held, resident, misdirected>>

\* @trace action=Move env
\* The node comes back on another transport identity (a wipe or a restart) and signs a newer binding.
Move(k, t) ==
    /\ joined[k]
    /\ ver[k] < MaxVer
    /\ t # tid[k]
    /\ tid' = [tid EXCEPT ![k] = t]
    /\ ver' = [ver EXCEPT ![k] = @ + 1]
    /\ net' = net \cup {[key |-> k, tid |-> t, ver |-> ver[k] + 1, signer |-> k, rec |-> "true"]}
    /\ UNCHANGED <<root, joined, held, resident, misdirected>>

\* @trace action=Hear plant
\* The first-come bind: an unauthenticated announce for a key the seat does not know becomes resident.
Hear(s, h) ==
    /\ FirstCome
    /\ s \in Honest
    /\ h \in hints
    /\ resident[s][h[1]] = NoTid
    /\ ~HasKey(s, h[1])
    /\ resident' = [resident EXCEPT ![s][h[1]] = h[2]]
    /\ UNCHANGED <<root, joined, tid, ver, net, held, misdirected>>

\* @trace action=Admit impl=seat::admit_registration
Admit(s, m) ==
    /\ s \in Honest
    /\ m \in net
    /\ m \notin held[s]
    /\ Admissible(s, m)
    /\ held' = [held EXCEPT ![s] = @ \cup {m}]
    /\ UNCHANGED <<root, joined, tid, ver, net, resident, misdirected>>

\* @trace action=Sync impl=seat::sync_from_replica
\* A replica takes another's rows and re-verifies every one: a replica is a source of rows, never of trust.
Sync(s1, s2) ==
    /\ s2 \in Honest
    /\ s1 # s2
    /\ LET new == {m \in Source(s1) : m \notin held[s2] /\ Admissible(s2, m)}
       IN /\ new # {}
          /\ held' = [held EXCEPT ![s2] = @ \cup new]
    /\ UNCHANGED <<root, joined, tid, ver, net, resident, misdirected>>

\* @trace action=SeatMint plant
\* The seat writes a binding no key signed (the "canonical priming" default of pre-#413 rows, or an operator pin).
SeatMint(s, k, t) ==
    /\ SeatAuthority
    /\ s \in Honest
    /\ held' = [held EXCEPT ![s] = @ \cup {[key |-> k, tid |-> t, ver |-> MaxVer, signer |-> s, rec |-> "true"]}]
    /\ UNCHANGED <<root, joined, tid, ver, net, resident, misdirected>>

\* @trace action=Lookup impl=seat::serve_lookup
\* A joined node asks a seat for a key and dials what it accepts. The seat half is Answer; the node half NodeAccepts.
Lookup(n, k, s) ==
    /\ joined[n]
    /\ n # k
    /\ \E m \in AnswerSet(s, k) :
          /\ NodeAccepts(m, k)
          /\ misdirected' = (misdirected \/ <<k, m.tid>> \notin published)
    /\ UNCHANGED <<root, joined, tid, ver, net, held, resident>>

Next ==
    \/ \E k \in Keys, s \in Seats : FetchBundle(k, s)
    \/ \E k \in Keys, t \in HonestTids : Join(k, t) \/ Move(k, t)
    \/ \E s \in Seats, h \in hints : Hear(s, h)
    \/ \E s \in Seats, m \in net : Admit(s, m)
    \/ \E s1, s2 \in Seats : Sync(s1, s2)
    \/ \E s \in Seats, k \in Keys, t \in Tids : SeatMint(s, k, t)
    \/ \E n, k \in Keys, s \in Seats : Lookup(n, k, s)

\* Only the seat is fair: it admits what is admissible and syncs what is new. Nodes and the adversary owe nothing.
Fairness ==
    \A s \in Honest :
        /\ WF_vars(\E m \in net : Admit(s, m))
        /\ WF_vars(\E s1 \in Seats : Sync(s1, s))

Spec == Init /\ [][Next]_vars /\ Fairness

----------------------------------------------------------------------------
(* Safety. *)

\* A node roots only on the bundle its anchor names; a lying replica can withhold it, never replace it.
Inv_RootIsAnchor == \A k \in Keys : root[k] # "forged"

\* No authority over keys: every row an honest seat holds was signed by the key it is about.
Inv_NoAuthority == \A s \in Honest : \A m \in held[s] : m.signer = m.key

\* Never directs to an unrooted or swapped key: an honest seat answers only with a binding the key itself signed,
\* under the key's own record, for a transport the node really used.
Inv_NeverSwapped ==
    \A s \in Honest, k \in Keys :
        LET a == Answer(s, k)
        IN a # NoAnswer => /\ a.signer = k
                           /\ a.rec = "true"
                           /\ <<k, a.tid>> \in published

\* The same, at the node, whatever the replica it asked: a Byzantine seat can deny or go stale, never swap.
Inv_NodeNeverSwapped == ~misdirected

\* An owned node that offers no relay never has its route served (CC 5.4.6).
Inv_OwnedRouteUnserved == \A s \in Honest, k \in OwnedKeys : Answer(s, k) = NoAnswer

\* No first-come lockout, as a state predicate: every genuine registration on the wire is admissible at every
\* honest seat, whatever announces the seat has heard and whoever heard first.
Inv_NoLockout ==
    \A s \in Honest, m \in net :
        (m.signer = m.key /\ m.rec = "true" /\ m \notin held[s]) => Admissible(s, m)

(* Liveness. *)

Fresh(s, k) == \E m \in held[s] : m.key = k /\ m.tid = tid[k] /\ m.ver = ver[k] /\ m.signer = k /\ m.rec = "true"

\* A node that registers is eventually known at every honest seat by its current binding: its key record is
\* public there whatever its kind.
Prop_Registered == \A k \in Keys, s \in Honest : <>[](joined[k] => Fresh(s, k))

\* ...and, where its route is servable, every honest seat eventually answers with its current transport.
Prop_Discoverable ==
    \A k \in BareKeys \cup RelayKeys, s \in Honest :
        <>[](joined[k] => (Answer(s, k) # NoAnswer /\ Answer(s, k).tid = tid[k]))
=============================================================================
