# FSD — Self-DEK for the user FedID (0.5.56)

> **STATUS — IMPLEMENTED (server-only) in 0.5.56.** Substrate adopted: edge **v7.3.1** /
> persist **v11.2.0** / verify family **v8.3.0** (CIRISVerify#151 `self_enc` derive +
> CIRISPersist#304 wrap-once dedup, both landed exactly as specced). Server: a new
> `identity::derive_self_enc_pubkeys(ed25519_seed)` (mirrors `derive_wallet_keypair`);
> the **portable** mint (`mint_portable_software_occurrence`) derives the x25519 +
> ML-KEM-768 content-enc keypair from the Ed25519 seed and attaches the pubkeys to the
> occurrence at the `bind_occurrence_core` call in `portable_occurrence.rs` — so the
> occurrence enters the self-DEK cascade instead of fail-secure excluding it. Because the
> keypair is a pure function of the seed, a **restore re-derives the identical key** (proven
> by `tests/portable_occurrence.rs::portable_keyset_derives_self_enc_pubkeys_and_enters_the_dek_cascade`).
> The occurrence-management **UI (roster + add + revoke + "reads self content" badge) already
> existed** end-to-end (`OccurrenceView.has_encryption_pubkeys` → `SelfOccurrence.hasEncryptionPubkeys`
> → `IdentityManagementScreen` badge) — no client rebuild needed; the existing client driving
> the 0.5.56 wheel produces self-DEK-capable occurrences. **Deferred:** deriving for the
> `self_login` app/agent occurrences (client passes public enc keys — a client-plumbing pass);
> hardware-sealed/pkcs11 (non-extractable seed) stay enc-less (generate-fresh-and-seal future work).



**Goal:** a user FedID (`eric-moore-v1`) owns a **self DEK** so every occurrence (Mac SE /
USB-restore / laptop TPM) can read self-scoped content, with the encryption identity
**derived from the FedID's base seed** so it travels for free on backup/restore and is
mathematically bound to the one canonical identity.

**Substrate status:** DONE. persist 11 ships the whole cascade (`Engine::self_at_login`,
`rekey_self_occurrence_add`, `at_rest_cascade`); ciris-crypto ships `public_from_secret` +
`generate_keypair_deterministic`; verify exposes wrap/unwrap. The only gap is
client/server **glue** + the two derive functions.

**Upstream issues:** CIRISVerify#151 (derive fns + FFI export), CIRISPersist#304
(identity-level wrap-once DX).

---

## Design: derive, don't generate (for the *self* case)

Mirror the shipped `ciris-crypto::secp256k1::derive_wallet_keypair` pattern (HKDF from the
Ed25519 seed, domain-separated):

- `derive_self_enc_x25519(seed)`   → HKDF(info="ciris/self-enc/x25519/v1")   → 32B → pub
- `derive_self_enc_mlkem768(seed)` → HKDF(info="ciris/self-enc/ml-kem-768/v1") → 64B → ek

**Consequence:** every occurrence that holds the base seed re-derives the **identical** enc
keypair → self DEK wrapped **once to the identity** → restore is free (no per-device rekey).

**Two flows coexist (this is correct, not a conflict):**
| Adding an occurrence | Holds base seed? | Enc key | Cascade |
|---|---|---|---|
| **Restore my FedID** (USB → laptop) | yes | re-derives **identical** | wrap-once / rekey is a no-op |
| **Log in as myself on a *separate* device** (mint local + associate) | no (own seed) | **distinct** | standard `rekey_self_occurrence_add` re-wrap |

The existing `IdentityManagementScreen` add/revoke UI already covers both; revoke drops the
occurrence's wrap (read access) via the cascade.

**Hardware (2FA/YubiKey) caveat:** the Ed25519 slot-9c key is non-extractable — you cannot
HKDF from it. Derive the enc identity from the **sealed companion seed that the FedID backup
actually carries** (the platform/software-sealed half, same one the ML-DSA-65 sealed-seed
half uses), never from the token. The rule is: *derive from whatever the backup carries,* so
the enc identity is portable wherever the FedID is.

> Scope: derive only for **self / single-principal**. Community DEKs keep independent keys +
> epoch rotation for forward-secrecy on member removal — do **not** derive there.

---

## Build list

### 1. CIRISVerify#151 — the two derive fns + FFI/wheel export
Block on this; everything else consumes it.

### 2. Server mint attaches enc pubkeys — **this is the wizard path**
The wizard is server-side by invariant ("NO keys/crypto in Kotlin", SetupViewModel.kt:750).
So the change lands in `src/identity.rs::mint_user_identity`:
- after sealing the base seed, **derive** x25519 + ML-KEM-768 from it (CIRISVerify#151),
- attach the enc pubkeys to the **first occurrence / identity** so the self DEK exists from
  the moment the FedID is born,
- the wizard UI (`runFederationIdentitySetup` / `associateExistingFederationId`) keeps
  calling `mintUserIdentity()` **unchanged** — it just gets back an identity that already
  has a self DEK.

### 3. Occurrence-enroll attaches enc pubkeys — the "add device" path
`POST /v1/self/occurrence` and `/v1/self/login` already *accept* `encryption_pubkeys`
(occurrence.rs, self_login.rs); today the client sends `None` → fail-secure **excluded** from
the cascade. Populate them:
- **restore flow** (occurrence holds the seed): node re-derives → identical pubkeys.
- **separate-device flow**: that device derives from *its* seed → distinct pubkeys → standard
  rewrap.

### 4. UI — manage/add/revoke self occurrences  ✅ ALREADY EXISTS
`IdentityManagementScreen.kt` (roster + per-device revoke + add-device + portable occurrence,
nav "My Identity") + `IdentityManagementViewModel` + API client
`getSelfOccurrences/addOccurrence/revokeOccurrence/createPortableOccurrence`. **Only addition
for 0.5.56:** surface per-row **"can read self content"** state (derived from whether the
occurrence carries enc pubkeys / holds a DEK grant) so the user sees that revoke also drops
read access, and that a no-enc-key occurrence is sign-only.

### 5. (separate bucket, not self-DEK) safety endpoints
`/v1/safety/minor-steward/{request,accept}`, `/v1/safety/reports` for the stewardship +
reverse-quorum UI to persist end-to-end. Independent of the self-DEK work.

---

## Acceptance
Mint `eric-moore-v1` in the wizard → it has a self DEK (enc pubkeys on occurrence 1). Back up
→ restore on the laptop → the restored occurrence **re-derives the identical enc key** and
reads the same self content with **no rekey ceremony**. Add a separate device via "My
Identity" → distinct enc key, cascade rewraps. Revoke it → it loses read access.
