# AddDevice — the "add device" flow, model-checked

`AddDevice.tla` models a new device **B** joining its owner's identity through the
owner's existing device **A**, peer to peer on edge's first-contact opaque plane
(CIRISEdge#683, the server's device-join kind `0x0000_0002`), against an adversary
that holds any number of fresh keys, sees every request (including B's challenge),
sends any request and injects any answer — but cannot forge A's or the owner's
signatures. B is a new **occurrence of the same identity** (its own signing and
content-KEM keys), never a second identity. Conventions follow
`CIRISConstitution/formal/accord_halt`.

| config | constants | expectation | TLC verdict (2026-10-16) |
|---|---|---|---|
| `AddDevice_safety.cfg` | 2 attackers, ceiling 2, quota 1, careful owner, window, fair admission | all 8 safety invariants hold | **no error** — 211,849 distinct states |
| `AddDevice_careless.cfg` | owner approves any pending request | `Inv_NoAttackerOwned` is violated | **violated** (as designed) — the matching code is load-bearing |
| `AddDevice_live.cfg` | 1 attacker, ceiling 2 | B is owned and holds the self DEK | **no error** — 3,409 distinct states |
| `AddDevice_sybil.cfg` | attackers ≥ ceiling, quota windows roll, admission only weakly fair | liveness fails | **violated** (as designed) — availability can be denied by a refilling flooder |
| `AddDevice_sybil_fair.cfg` | same, A's limiter evicts fairly (edge `FSD_RATE_LIMIT` D2) | B still joins | **no error** — 74,681 distinct states |

## Safety invariants

- `Inv_OwnedOnlyApproved` — no device is owned without the owner's approval of its request.
- `Inv_OccOnlyApproved` — no occurrence of the self without the owner's signature on approval.
- `Inv_DekOnlyOccurrences` — the self DEK reaches only owner-signed occurrences.
- `Inv_BOwnedIsReal` — B believes it is owned only if the owner really signed its binding (forged answers are rejected: wrong signer, or not solicited).
- `Inv_NoAttackerOwned` — the adversary never owns a device of this person (requires the careful owner + matching code).
- `Inv_PendingBounded` — A's pending set never exceeds the node-wide ceiling, under any flood.
- `Inv_WindowRespected` — nothing is admitted while the owner has not opened "add a device".
- `Inv_Type`.

## What the model found and what it requires of the implementation

1. **An answered request must free its slot at once.** The first liveness run failed: requests the owner *denied* stayed in A's pending set, an attacker filled the node-wide ceiling with dead entries, and B was never admitted. Fixed in the model (`ARetire`); the server must evict decided requests, not only expire undecided ones.
2. **The matching code is required, and A must derive it** from (requester key, challenge) — never accept a code the requester supplies. With a careless owner the adversary gets a device owned (`AddDevice_careless`).
3. **Per-key limits do not stop sybils** (keys are free). The ceiling bounds A's resources (safety holds under any flood) but availability holds only with fair eviction (`AddDevice_sybil` vs `_fair`). Residual risk: availability only, never safety.
4. **B pins A's key from the v3 contact code** and admits introductions only from a solicited answer on its own challenge — the model's forged answers (`AttackerForge`) never move B.

Assumptions: the honest owner holds B, compares the codes, answers within the window and never denies B's own request; B's request does not expire before the owner acts; the network delivers honest messages (weak fairness); the adversary gets no fairness.

Run: `java -cp tla2tools.jar tlc2.TLC -workers 4 -deadlock -config AddDevice_<cfg>.cfg AddDevice.tla`
