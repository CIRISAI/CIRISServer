# Bridge upgrade — v0.5.62 (substrate floor bump + node recovery/UX + owner-fed-ID surfaces)

**What this cut is:** the cumulative bridge from the **v0.5.56** floor through **v0.5.62**
(0.5.57 → 0.5.62). It moves the substrate floor (edge v7.4.1 / persist v11.5.0), adds node
recovery + new operator endpoints, and is the first release on which the founder fed-ID was
**minted + self-claimed + USB-backed-up end-to-end** (field-proven on macOS).

No migration script (persist auto-migrates on open). Headless node operators (Node A / Node
B) are unaffected by the client (desktop/mobile) changes; both are noted below for the app users.

## Substrate floor (CHANGED)
- edge **v7.4.1** (carrier; was v7.3.1) · persist **v11.5.0** (was v11.2.0) · verify family
  **v8.3.0** (verify-core + ciris-crypto + ciris-keyring co-pinned; **unchanged**).
- Leviculum **v0.8.1+ciris.1** — unchanged (the RNS phone-radio floor).
- persist v11.5.0 applies its new migrations (V92+) automatically on first open. No script.

## What changed — operator-relevant (node)

### ⚠️ persist v11.5.0 stewardship gate (CC 3.2 / CC 1.15.6)
A `delegates_to` onto a **USER-role target** is now REFUSED unless it is adult→minor
guardianship (an adult user is un-stewardable — presumption of sovereignty for an unverified
age). This is a **write-time** gate; existing persisted edges are untouched.
- CIRISServer adapts: the **device-grant on-behalf-of agent** is now minted as
  `identity_type::AGENT` (a capability delegation, not stewardship), so `POST
  /v1/auth/device/{delegate,approve}` keeps working. No operator action; flagged so you
  recognize a `target_age_unverified` 500 if any downstream tooling still mints a USER-role
  delegate target.

### ⚠️ post-wipe process EXIT (0.5.60) — supervise the process
`POST /v1/system/data/reset-account` (data-only) and `/wipe-signing-key` (data+keys) now
**exit the process ~800 ms after responding**. The DB is cleared out from under the running
node; continuing would death-spiral on `disk I/O error`. On exit, the 0.5.58 **unbrick**
(`federation_signer` → `open_or_create`) brings a wiped/fresh home back to **first-run** on
the next boot. **Run the node under a supervisor** (systemd `Restart=always`, container
`restart: unless-stopped`) so it comes back automatically; a bare CLI run must be re-launched.

### New node endpoints (0.5.57)
- `GET /v1/telemetry/logs` — tails `<home>/logs/ciris-server.log*` (node now writes a daily
  rolling file log in addition to stdout).
- `POST /v1/system/data/reset-account` (data-only) / `…/wipe-signing-key` (data+keys) —
  owner-gated, double-confirm; mirror the agent's two-mode wipe (see exit note above).
- `GET /v1/my-data/lens-identifier` — node-appropriate consent record.
- `seed_identity_graph()` seeds a `node/identity` graph node at boot so the client Graph
  page is non-empty on a fresh node.

### Name-driven fed-ID (0.5.59) + active-alias resolution (0.5.62)
- `POST /v1/self/identity` now derives the `key_id` alias from the `label` (slug) when no
  explicit `key_id` is given: `eric-moore-v1` → `eric-moore-v1-<fp>` (was always
  `<node>-user-<fp>`). An `active_user_alias` pointer is written at mint.
- claim-remote, device-grant, **and set-age** (`POST /v1/self/age`, fixed in 0.5.62) all
  resolve that pointer at request time, so they find the name-driven fed-ID, not `<node>-user`.

### Custody ladder (0.5.61)
The user-identity mint resolves **YubiKey (if available AND selected) → TPM/Secure-Enclave
(if available) → software (last resort)**: a rung whose hardware can't open falls to the next
instead of failing. `backend=null` (the default) takes the platform-sealed path
(`SealedEd25519Signer`, keychain/software-at-rest fallback). pkcs11 is opt-in.

### edge v7.4.1 dual-destination announce (0.5.60)
Named announce + explicit-hash back-compat — the boot WARN
`announce error: Explicit-hash destinations cannot be announced` is gone.

### Serial LoRa / RNode transport (0.5.58) — OFF by default
`src/radio.rs` adds a concrete serial RNode driver attached when `net.radio.*` config:* is
enabled (opt-in; cfg-gated to serial-capable targets: macOS / Windows / linux-gnu
x86_64+aarch64). KISS wire-correct vs Leviculum ref but **hardware-unvalidated** — do not
rely on it for the mesh yet.

## What changed — client (desktop/mobile app users only)
- First-run wizard **auto-mints** the fed-ID on Next from the typed name (+ mint-if-absent
  backstop at self-claim), so a software/keychain `eric-moore-v1` is created without a
  YubiKey; optional "name this device" step.
- Identity page + node-graph centre vertex now show the **owner fed-ID** (`eric-moore-v1`),
  not the node key (`ciris-client`).
- nodes/trust/graph UI cleanup; key collapsed behind `?`; Logs node/agent source dropdown;
  Transport card writes `net.radio.*`.

## Scope / honest boundaries
- The self-DEK semantics from v0.5.56 are unchanged (derived only for the self; community
  DEKs keep independent keys + epoch rotation; hardware-sealed/pkcs11 stay enc-less).
- macOS CLI custody is **keychain/software-at-rest** (Secure Enclave needs a signed, entitled
  app bundle — `errSecMissingEntitlement`). Non-blocking by design; the node logs it honestly.

## Upgrade runbook (per node)
1. `pip install -U ciris-server==0.5.62` (each node; persist auto-migrates on open). Existing
   owner-bindings, identities, and consent topology are preserved — this is an in-place
   upgrade, **not** a re-provision.
2. Restart the node. Confirm the boot banner shows the substrate floor and (if owned) the
   `owner=<your-fed-id>` projection on `GET /v1/setup/owned-nodes`.
3. If you run under a supervisor, confirm the restart policy (see the post-wipe exit note) —
   only relevant if you intend to use the wipe endpoints.

## Cross-device fed-ID path (proven on 0.5.62)
- **mint** `eric-moore-v1` via the client wizard (software/keychain, no YubiKey) → self-claim
  → owned node, SYSTEM_ADMIN.
- **back up** via `POST /v1/self/occurrence/portable` (client "create portable copy") to USB
  → a `…-portable-…` occurrence bound to the owner's self; the self-DEK rides the Ed25519
  seed (re-derives identical on restore).
- **restore** on another device via `POST /v1/self/associate` → re-derives the identical enc
  key → reads the same self content. (Restore round-trip is the recommended validation before
  relying on the backup.)

No env vars; no migration step beyond the auto-migrate. Boot model unchanged from 0.5.x
(`--home` is the one input; all other config is baked constants or `config:*` CEG).
