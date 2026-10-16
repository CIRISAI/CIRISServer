# FSD — Add a device: a new device joins its owner's identity (CIRISServer#177)

Status: **implementing** (0.5.228 cycle). Model: [`formal/add_device`](../formal/add_device/README.md)
(TLC, five configurations). Constitution: carve-out filed with CIRISConstitution (an unowned
node's one permitted message is a device-join request); recommendations adopted below, Eric rules.

## 1. What the person does

1. On the **new** device B, the first-run wizard offers **Add device**. The person enters their
   fedID the way *Share my ID* shows it: the QR (photo), the long form (paste), or the short form.
2. On the **existing** device A, the person opens **Add a device** (a time-boxed window).
3. Both screens show the same **matching code**. A asks *Consent to claim new device?*
4. On **Yes**, B finishes setup signed in as the person, holding its own keys as a new
   **occurrence of the same identity**, and the person's files open on it.

B is never a second identity: the fedID on B is the same identity as on A, with a different
keypair (Eric, 2026-10-16). No key material crosses the wire in either direction.

## 2. The exchange

Peer to peer on edge's first-contact opaque plane — **CIRISEdge#683**, `FSD/FIRST_CONTACT.md`
§2.2, the server's device-join kind **`0x0000_0002`**. No canonical store: the canonical only
relays transport bytes as it already does. NAT is fine: every answer rides B's inbound link.

```text
B (unowned, node key minted at boot)                A (owned; owner's pen opens here)
  mints device occurrence keys (sign + content-KEM)
  ── join {node_code, challenge, label, device_class,
           occurrence_key_record, encryption_pubkeys} ──▶ edge: rate (sender, link, node-wide)
     signed by B's NODE key, first contact                 → PoP → admit B's key (grants nothing)
                                                         host: window open? ceilings? → PENDING
  ◀── {status: pending, request_id, match_code} ───────   match_code = H(B key ‖ challenge)
  shows match_code                                       owner sees "Consent…?" + match_code
  ── status {request_id, challenge} (poll) ────────────▶
                                                         owner approves (owner session):
                                                           owner pen signs owner → B-node,
                                                           owner pen signs B's occurrence
                                                           (content-only form, persist #851),
                                                           A records both locally, re-wraps the
                                                           self DEKs to B's occurrence
  ◀── {status: approved, setup_root, occurrence}  ─────  answer introductions: A's key (edge),
      introductions: owner key record, owner → A,          owner key, owner → A, owner → B
      owner → B
  admits introductions (solicited only)
  applies the occurrence (persist verifies the owner's signature)
  POST /v1/setup/root {setup_root + its OWN claim PIN}   — B's local presence still proven
  wizard collects its owner session (claimed-session, PIN, loopback, once)
```

## 3. Normative properties

- **N1 — The matching code is derived by A**, from (requester key, challenge), never supplied by
  the requester. An attacker who copies B's challenge still shows a different code. (Model:
  `Code(r)` depends on `r.from`; `AddDevice_careless` shows an owner who cannot tell requests
  apart can be made to own an attacker's device.)
- **N2 — An unowned node's one permitted message** is the device-join request, under the plane's
  anti-spam order: per-sender and node-wide limits **before any cryptography**, no answer to a
  request edge refuses (#554 D3). Host-side: requests are held only while the owner has opened
  **Add a device**; a request arriving while the window is closed is refused with a generic
  answer and never queued.
- **N3 — Bounded and fair.** A holds at most `PENDING_CEILING` requests and one per sender; a
  **decided request (approved or denied) frees its slot at once** (TLC found the starvation:
  a denied flood held the ceiling); undecided requests expire. Residual risk: availability
  only, never safety (`AddDevice_sybil` vs `_fair`); no proof-of-work (CC: joining costs
  nothing).
- **N4 — Binding first, occurrence second.** The owner signs both in one approval; B applies the
  occurrence once the owner's key is held and the binding before it links.
- **N5 — B pins A.** B addresses A's node from the v3 code (or the directory for a short form)
  and admits introductions only from a **solicited** answer: its own challenge, the key it
  addressed, the transport the request left on (edge's requester order).
- **N6 — No key material crosses.** B's device keys are minted on B; only public halves and
  self-signed records travel. On deny or expiry B discards them.

## 4. Surfaces

### On B (the new device) — loopback, first-run only

| Route | Body | Answer |
|---|---|---|
| `POST /v1/setup/add-device` | `{contact, label?}` — `contact` is the QR/long form/short form | `{state: "requested", match_code, target_node}` or a typed refusal |
| `GET /v1/setup/add-device` | — | `{state: requested\|approved\|applied\|denied\|expired\|failed, match_code, detail}` |

After `applied`, the wizard collects its session with the existing
`POST /v1/setup/claimed-session {claim_pin}`.

### On A (the existing device) — owner session

| Route | Purpose |
|---|---|
| `POST /v1/self/device-requests/open {seconds?}` | Open the **Add a device** window (default 10 min, max 30). |
| `GET /v1/self/device-requests` | Pending requests: `request_id, label, device_class, match_code, requested_at` and the window. |
| `POST /v1/self/device-requests/{id}/approve` | The owner's consent: signs and records the binding and the occurrence, re-wraps the self DEKs. |
| `POST /v1/self/device-requests/{id}/deny` | Refuse; frees the slot. |

### 4.1 Refusal ids (for the client bundle)

| id | English |
|---|---|
| `add_device.already_owned` | this device already has an owner |
| `add_device.no_transport` | this device has no mesh transport running, so it cannot reach your other device |
| `add_device.unknown_identity` | could not find that identity |
| `add_device.no_device` | that code names no device to ask — open Share my ID on your other device and use its QR or long form |
| `add_device.mint_failed` | could not mint this device's keys |
| `add_device.rng` | no randomness for the challenge |
| `add_device.unreachable` | could not reach your other device |
| `add_device.not_accepting` | your other device is not accepting new devices — open Add a device on it, then try again |
| `add_device.unexpected` | unexpected answer from your other device |
| `add_device.request_unknown` | no such pending request |
| `add_device.approve_failed` | the approval could not be signed and recorded |

### On the wire — opaque kind `0x0000_0002`

JSON payloads, `op` discriminated: `join` and `status` (B → A); answers carry `status`
`pending | approved | denied | unknown | not_accepting`.

## 5. What already exists and is reused

- Edge first contact: `send_opaque_request_introducing`, `register_opaque_answerer`,
  `OpaqueAnswer { introductions }` (CIRISEdge#683).
- The owner-binding builder and B's acceptance: `claim_remote::build_claim_for_target`,
  `auth::bootstrap` `setup_root` (PIN, NodeCode pin, Strict verify, ROOT, held session).
- The signed occurrence: persist's content-only form (#851) via
  `produce_signed_identity_occurrence` + `put_identity_occurrence`.
- The self-DEK grant: `Engine::rekey_self_occurrence_add` at approval; B's node also becomes a
  content occurrence on its self-room tick and `self_rewrap` (#678) re-wraps to it.
- The link: `replication_reconcile::own_device_peers` (no consent grant between one owner's nodes).

## 6. Not in this cut

- B's key custody is the default device custody: the Ed25519 half as a seed file, the ML-DSA-65
  half sealed in B's key store (`identity::mint_local_device_occurrence`). B's owner pen opens
  as the occurrence; the owner capsule accepts an active occurrence of the owner
  (`signer_acts_for`). Owner-pen flows that need the identity's **root** key (minting a new
  identity-level record) stay on the device holding it.
- Policy after a device is owned (who may evict, quorum fast path, reverse-quorum window):
  CIRISConstitution's `formal/self_roster`.
