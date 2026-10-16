------------------------------ MODULE AddDevice ------------------------------
(* "Add device": a new device B asks its owner's existing device A to claim it,
   peer to peer on edge's first-contact opaque plane (CIRISEdge#683, the
   server's device-join kind 0x0000_0002). No canonical store.

   B is unowned. It signs a join request with its OWN node key, carrying its
   self-signed key record, a fresh 32-byte challenge, and the public halves of
   the device occurrence keys it minted for itself (nothing secret crosses).
   A rate-limits the request BEFORE any cryptography (per sender key, node-wide
   ceiling), admits B's key (which grants nothing), and holds the request
   pending. A shows the owner a MATCHING CODE derived by A from (requester key,
   challenge) -- never supplied by the requester -- and B shows the same code.
   On approval the OWNER signs two rows: the owner-binding owner -> B-node and
   B's device occurrence under the owner's self. A answers on B's inbound link
   with those rows; B admits introductions only from a SOLICITED answer (its
   own challenge) signed by A's key, which B pinned from A's v3 contact code.
   Once B's occurrence is active, A (holding the owner's pen) re-wraps the
   self DEKs to it (CIRISServer#678, self_rewrap).

   The adversary: any number of fresh keys (keys are free), sees every request
   (including B's challenge), sends any request, and injects any answer -- but
   cannot forge the owner's or A's signatures. *)
EXTENDS Naturals, FiniteSets

CONSTANTS b,            \* the honest new device
          Attackers,    \* adversary device keys
          Challenges,   \* fresh-challenge space
          Ceiling,      \* A's node-wide pending ceiling
          Quota,        \* per-sender admissions per window
          Careful,      \* TRUE: the owner approves only the request whose code
                        \*       matches the one on the device in their hand
          Window,       \* TRUE: A admits join requests only while the owner has
                        \*       opened "add a device" on A
          FairAdmission \* TRUE: A's limiter evicts fairly (edge FSD_RATE_LIMIT D2), so
                        \*       B's request is admitted whenever room recurs

Devices == {b} \cup Attackers
Req == [from: Devices, ch: Challenges]
Code(r) == <<r.from, r.ch>>          \* derived by A, injective in the key
NoReq == [from |-> b, ch |-> "none"]  \* B has sent nothing yet (never in sent)

VARIABLES sent,      \* requests on the network (adversary sees all)
          pending,   \* requests A holds
          admitted,  \* [Devices -> Nat] admissions this window
          approved, denied,
          answers,   \* answers on the network: [req, verdict, signer]
          bReq,      \* B's outstanding request, or NoReq
          bState,    \* "unowned" | "requested" | "owned" | "denied"
          owned,     \* devices with an owner-signed owner-binding
          occ,       \* device occurrences the owner signed under the self
          dek,       \* devices granted the self DEK
          open       \* the owner opened "add a device" on A
vars == <<sent, pending, admitted, approved, denied, answers, bReq, bState, owned, occ, dek, open>>

Signers == {"A"} \cup Attackers
Answer == [req: Req, verdict: {"approve", "deny"}, signer: Signers]

TypeOK == /\ sent \subseteq Req /\ pending \subseteq sent
          /\ admitted \in [Devices -> 0..Quota]
          /\ approved \subseteq sent /\ denied \subseteq sent
          /\ answers \subseteq Answer
          /\ bState \in {"unowned", "requested", "owned", "denied"}
          /\ owned \subseteq Devices /\ occ \subseteq Devices /\ dek \subseteq Devices
          /\ open \in BOOLEAN

Init == /\ sent = {} /\ pending = {} /\ admitted = [d \in Devices |-> 0]
        /\ approved = {} /\ denied = {} /\ answers = {}
        /\ bReq = NoReq /\ bState = "unowned"
        /\ owned = {} /\ occ = {} /\ dek = {} /\ open = ~Window

\* ── B ──
BRequest(c) == /\ bState = "unowned"
               /\ LET r == [from |-> b, ch |-> c] IN
                    /\ r \notin sent
                    /\ sent' = sent \cup {r} /\ bReq' = r /\ bState' = "requested"
               /\ UNCHANGED <<pending, admitted, approved, denied, answers, owned, occ, dek, open>>

\* B admits an answer only if solicited (its own challenge) and signed by the
\* A key it pinned from the v3 code.
BReceive(a) == /\ bState = "requested" /\ a \in answers
               /\ a.req = bReq /\ a.signer = "A"
               /\ bState' = IF a.verdict = "approve" THEN "owned" ELSE "denied"
               /\ UNCHANGED <<sent, pending, admitted, approved, denied, answers, bReq, owned, occ, dek, open>>

\* ── the adversary ──
AttackerRequest(m, c) == /\ LET r == [from |-> m, ch |-> c] IN
                              /\ r \notin sent /\ sent' = sent \cup {r}
                         /\ UNCHANGED <<pending, admitted, approved, denied, answers, bReq, bState, owned, occ, dek, open>>

\* Only an answer to B's OWN request can matter (B ignores every other one), and
\* "approve" is the forgery that could do harm; a forged "deny" only stalls B.
AttackerForge(m, r, v) == /\ r = bReq /\ v = "approve"
                          /\ answers' = answers \cup {[req |-> r, verdict |-> v, signer |-> m]}
                          /\ UNCHANGED <<sent, pending, admitted, approved, denied, bReq, bState, owned, occ, dek, open>>

\* ── A ──
OwnerOpens == /\ ~open /\ open' = TRUE
              /\ UNCHANGED <<sent, pending, admitted, approved, denied, answers, bReq, bState, owned, occ, dek>>

\* rate limit before crypto: per-sender quota, node-wide ceiling, window
AAdmit(r) == /\ open /\ r \in sent \ pending
             /\ admitted[r.from] < Quota /\ Cardinality(pending) < Ceiling
             /\ pending' = pending \cup {r}
             /\ admitted' = [admitted EXCEPT ![r.from] = @ + 1]
             /\ UNCHANGED <<sent, approved, denied, answers, bReq, bState, owned, occ, dek, open>>

\* time passes: the per-sender quota window rolls over (fresh keys and fresh
\* windows are free to the adversary)
WindowRoll == /\ admitted' = [d \in Devices |-> 0]
              /\ UNCHANGED <<sent, pending, approved, denied, answers, bReq, bState, owned, occ, dek, open>>

\* an ANSWERED request frees its slot at once. (TLC found the bug this prevents:
\* if decided requests keep their slot, an attacker whose requests the owner
\* DENIES fills the node-wide ceiling with dead entries and B is never admitted.)
ARetire(r) == /\ r \in pending \cap (approved \cup denied)
              /\ pending' = pending \ {r}
              /\ UNCHANGED <<sent, admitted, approved, denied, answers, bReq, bState, owned, occ, dek, open>>

\* an undecided ATTACKER request expires (fair eviction frees room; the quota does
\* not refill until the window rolls). B's own request does not expire in the
\* honest scenario: the owner, holding B, answers within the window.
AExpire(r) == /\ r \in pending \ (approved \cup denied) /\ r.from \in Attackers
              /\ pending' = pending \ {r}
              /\ UNCHANGED <<sent, admitted, approved, denied, answers, bReq, bState, owned, occ, dek, open>>

\* the owner approves: signs owner -> r.from AND r.from's occurrence under the self
OwnerApprove(r) == /\ r \in pending \ (approved \cup denied)
                   /\ Careful => (bState = "requested" /\ r = bReq /\ Code(r) = Code(bReq))
                   /\ approved' = approved \cup {r}
                   /\ owned' = owned \cup {r.from}
                   /\ occ' = occ \cup {r.from}
                   /\ answers' = answers \cup {[req |-> r, verdict |-> "approve", signer |-> "A"]}
                   /\ UNCHANGED <<sent, pending, admitted, denied, bReq, bState, dek, open>>

OwnerDeny(r) == /\ r \in pending \ (approved \cup denied)
                /\ Careful => r # bReq        \* the honest owner approves the device in hand
                /\ denied' = denied \cup {r}
                /\ answers' = answers \cup {[req |-> r, verdict |-> "deny", signer |-> "A"]}
                /\ UNCHANGED <<sent, pending, admitted, approved, bReq, bState, owned, occ, dek, open>>

\* A (holding the pen) re-wraps the self DEKs to an active occurrence
Rewrap(d) == /\ d \in occ \ dek /\ dek' = dek \cup {d}
             /\ UNCHANGED <<sent, pending, admitted, approved, denied, answers, bReq, bState, owned, occ, open>>

Honest == \/ \E c \in Challenges : BRequest(c)
          \/ \E a \in answers : BReceive(a)
          \/ OwnerOpens
          \/ \E r \in sent : AAdmit(r)
          \/ \E r \in pending : OwnerApprove(r) \/ OwnerDeny(r) \/ AExpire(r) \/ ARetire(r)
          \/ \E d \in Devices : Rewrap(d)
Adversary == \/ WindowRoll
             \/ \E m \in Attackers, c \in Challenges : AttackerRequest(m, c)
             \/ \E m \in Attackers, r \in sent, v \in {"approve", "deny"} : AttackerForge(m, r, v)
Next == Honest \/ Adversary

\* Liveness assumes an owner who approves B's request when it is pending and
\* the code matches, a network that delivers, and A admitting B's request when
\* there is room. The adversary gets no fairness.
BJoin == \E r \in sent : r = bReq /\ (AAdmit(r) \/ OwnerApprove(r))
Fair == /\ WF_vars(OwnerOpens)
        /\ IF FairAdmission THEN SF_vars(\E r \in sent : r = bReq /\ AAdmit(r))
                            ELSE WF_vars(\E r \in sent : r = bReq /\ AAdmit(r))
        /\ SF_vars(\E r \in sent : r = bReq /\ OwnerApprove(r))
        /\ WF_vars(\E a \in answers : BReceive(a))
        /\ WF_vars(\E d \in Devices : Rewrap(d))
        /\ WF_vars(\E c \in Challenges : BRequest(c))
        /\ \A r \in Req : r.from \in Attackers => WF_vars(AExpire(r))
        /\ \A r \in Req : WF_vars(ARetire(r))
Spec == Init /\ [][Next]_vars /\ Fair

\* ── safety ──
Inv_Type == TypeOK
\* no device is ever owned without the owner's approval of ITS request
Inv_OwnedOnlyApproved == \A d \in owned : \E r \in approved : r.from = d
\* no occurrence of the self without the owner's signature on approval
Inv_OccOnlyApproved == occ \subseteq {r.from : r \in approved}
\* the self DEK reaches only owner-signed occurrences
Inv_DekOnlyOccurrences == dek \subseteq occ
\* B believes it is owned only if the owner really signed its binding
Inv_BOwnedIsReal == bState = "owned" => b \in owned
\* the adversary never ends up owning a device of this person (needs Careful)
Inv_NoAttackerOwned == owned \cap Attackers = {}
\* A's resources stay bounded under any flood
Inv_PendingBounded == Cardinality(pending) <= Ceiling
\* nothing is admitted outside an opened window
Inv_WindowRespected == Window /\ ~open => pending = {}

\* ── liveness ──
Prop_BJoinsAndReadsSelf == <>(bState = "owned" /\ b \in dek)
=============================================================================
