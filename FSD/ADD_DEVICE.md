# FSD — Add a device: a new device joins its owner's identity (CIRISServer#177)

Status: **implementing** (0.5.228 cycle). Model: [`formal/add_device`](../formal/add_device/README.md)
(TLC, five configurations). Constitution: carve-out filed with CIRISConstitution (an unowned
node's one permitted message is a device-join request); recommendations adopted below, Eric rules.

## 1. What the person does

**On the new device B (first-run wizard):**
1. The first step asks: **Set up a new CIRIS ID**, or **Add this device to an existing CIRIS ID**.
2. The person names the device, for example "S23 Phone" or "2023 Laptop". This is the optional custom name; it travels with the request so the approver sees it.
3. For an existing ID, they enter their fedID the way *Share my ID* shows it: the QR (photo), the long form (paste) or the short form. The wizard **never asks for a fedID name** on this path. The identity is the existing one, and B's status names it (`owner_key_id`) once the approval verifies.
4. The rest of the wizard (every option the new node needs) is completed as usual while the approval happens on the other device.
5. At the end, the wizard calls **`POST /v1/setup/add-device/complete`**. The claim is applied there, at the same point in first run as a new identity's claim. Then the wizard collects its session with `POST /v1/setup/claimed-session {claim_pin}`.

**On the existing device A:** the person opens **Add a device** (a time-boxed window). Both screens show the same **matching code**, and A asks *Consent to claim new device?*

B is never a second identity: the fedID on B is the same identity as on A, with a different keypair (Eric, 2026-10-16). No key material crosses the wire in either direction.

**B's keypair is a ROSTER KEY of that fedID** (CC 3.3.6.3, ruled 2026-10-18, CIRISConstitution#178):
- **One fedID string.** The fedID, UID included, is the same string on every device.
- **Each roster key has its own id.** B's key is named `<fedID>-<fingerprint of its own Ed25519 key>` (`CLM-self-roster-key-id`). The genesis key is roster key one, nothing more.
- **The device name is the node key's.** The roster key never carries it; 0.5.231's `device-<hex>-<fp>` is refused. A's approval checks the name before it signs anything (`add_device::roster_key_named_under`).
- **Any live roster key signs as the fedID** for every owner act: consent, the owner-binding and its widening, root acceptance, self room, contacts, and approving the next device (`CLM-self-roster-authority`). On the server that is `auth::verify::signer_acts_for`, used by the owner capsule and by `peer::owner_consent_pen` (CIRISServer#793). Persist's steward gate resolves a roster key to the fedID at the row's `asserted_at` (CIRISPersist#1099). Until that lands, B cannot announce itself.
- **One roster key per node**, separate from the node key (`CLM-self-roster-one-key-per-node`).
- **Adding and evicting keys** follows the CC 3.3.6.3 policy: unilateral at one key (this approval), the lone path at two, quorum or lone path from three (CIRISPersist#1099).

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

## 2.1 Validate on arrival, apply at the end of first run (0.5.231)

The approval is **verified the moment it arrives and applied only when first run completes**. First-run timing is then the same whether the person sets up a new identity or joins an existing one.

The signer (A) is remote, so A's approval carries the owner's **full v3 code**: fedID, Ed25519 key, ML-DSA-65 commitment, and A's node with its transport key. B verifies offline, with no canonical lookup:
1. the approval pins B's own NodeCode;
2. the v3 code names the fedID the person entered;
3. the fedID's fingerprint matches the code's Ed25519 key;
4. the owner-binding's Ed25519 key is the code's, and its full ML-DSA-65 key matches the code's commitment (`AdmittedHybridKey::admit`);
5. the owner-binding verifies: its structure and the hybrid signature, Strict (`ownership::verify_signed_owner_binding`, the verify half of `apply_signed_owner_binding`, with no writes);
6. the occurrence names this identity and B's minted key, and its hybrid signature verifies under the same keys (JCS of the envelope, the bytes persist checks);
7. B still holds its claim PIN.

A verified approval is **held** in memory and on disk (`<home>/add_device_pending.json`, 0600, public signed material only), so a restart mid-wizard still completes. `POST /v1/setup/add-device/complete` applies it: the binding through B's own `setup/root` with its claim PIN, then the occurrence and the active identity. Completing before approval answers 409 `add_device.not_approved`.

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
| `GET /v1/setup/add-device` | — | `{state: idle\|requested\|approved\|applied\|denied\|expired\|failed, match_code, owner_key_id, detail}`. `idle` = no request on this boot. `approved` = verified and held, not yet applied. `expired` = the request lapsed here (15 min) or the other device no longer holds it. |
| `DELETE /v1/setup/add-device` | — | The person changed their mind: retires the poll, discards a held approval and the request's never-used keys, and sends the other device a **withdraw** (`op: "withdraw"`, same sender and challenge only). The other device drops a pending request; an approved one is **undone** there (its occurrence revoked and owner-binding withdrawn, by `evict_device` under the owner-binding's loop authority). Answers `{state: "idle", detail: "cancelled"}`; 409 `add_device.already_owned` once the claim applied. |
| `POST /v1/setup/add-device/complete` | — | Applies the held approval at the end of first run: `{state: "applied", …}`, or 409 `add_device.not_approved`, or 502 `add_device.apply_failed`. |

After `complete` answers `applied`, the wizard collects its session with the existing
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
| `add_device.not_approved` | your other device has not approved this one yet |
| `add_device.apply_failed` | the approval could not be applied on this device |

### 4.2 Restarts, and the HTTP status of every refusal

**Restarts.** Only an `approved` request survives a restart of the new device: the verified approval is held on disk and the status answers `approved` again after boot. A restart while `requested` comes back as `idle`. The minted request keys were never used, so the wizard sends a new request, and the other device's stale entry expires on its own.

| id | HTTP | when |
|---|---|---|
| `add_device.already_owned` | 409 | this device already has an owner |
| `add_device.not_accepting` | 409 | the other device has not opened Add a device |
| `add_device.not_approved` | 409 | `complete` before the approval |
| `add_device.unknown_identity` | 404 | the entered fedID does not resolve |
| `add_device.no_device` | 404 | the code names no device to ask |
| `add_device.request_unknown` | 404 | approve/deny of a request the owner's device no longer holds |
| `add_device.unreachable` | 502 | the other device could not be reached |
| `add_device.unexpected` | 502 | the other device answered something unrecognised |
| `add_device.apply_failed` | 502 | applying the held approval failed (`detail` says why) |
| `add_device.no_transport` | 503 | no mesh transport on this device |
| `add_device.mint_failed` | 500 | minting or registering this device's keys failed (`detail` says why) |
| `add_device.rng` | 500 | no randomness for the challenge |
| `add_device.approve_failed` | 500 | the owner's device could not sign or record the approval |

**The claim carries no owner password.** It is the owner-binding through `setup/root` with the device's own claim PIN. A host that also keeps a local account (the agent) must not assume a password-claimed node on this path.

### On the wire — opaque kind `0x0000_0002`

JSON payloads, `op` discriminated: `join`, `status` and `withdraw` (B → A); answers carry `status`
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
  half sealed in B's key store (`identity::mint_local_device_occurrence`, alias = the fedID).
  B's owner pen opens as its roster key, and nothing is reserved to the genesis key
  (CC 3.3.6.3).
- Policy after a device is owned (who may evict, quorum fast path, reverse-quorum window):
  CIRISConstitution's `formal/self_roster`.
