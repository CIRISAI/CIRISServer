# Bridge upgrade — v0.5.56 (self-DEK end-to-end)

**What this cut is:** a **server-only** adoption of the substrate triple that ships the
self-DEK pieces, plus the server wiring that makes a portable user fed-ID self-DEK-capable.
No client rebuild, no migration script (persist auto-migrates on open).

## Substrate floor
- edge **v7.3.1** (carrier) · persist **v11.2.0** · verify family **v8.3.0**
  (verify-core + ciris-crypto + ciris-keyring co-pinned; ciris-crypto gains the `self-enc` feature).
- Leviculum v0.8.1+ciris.1 (unchanged — the RNS phone-radio floor).

## What changed (behavior)
- A **portable** user fed-ID (`POST /v1/self/occurrence/portable`, the client's "create a
  portable copy / add a device" flow) now **derives** its content-encryption keypair
  (x25519 + ML-KEM-768) from the Ed25519 base seed and attaches the pubkeys to the
  occurrence. The occurrence therefore **enters the self-DEK cascade** (can read the self's
  at-rest content) instead of being fail-secure excluded.
- **Portability is free:** the keypair is a pure function of the seed, so restoring the
  keyset on another device (`POST /v1/self/associate`) re-derives the **identical** key.
  The self-DEK is wrapped once (CIRISPersist#304); every seed-holder opens it. **No
  per-device re-key ceremony.**
- The occurrence roster already shows a **"reads self content"** badge per device
  (`has_encryption_pubkeys`); it now lights up for portable occurrences.

## Scope / honest boundaries
- **Derived only for the self (single principal).** Community DEKs keep independent keys +
  epoch rotation (forward secrecy on member removal) — unchanged.
- **Hardware-sealed (SE/TPM) / pkcs11 (YubiKey)** identities have a non-extractable Ed25519
  seed → cannot derive → stay enc-less (sign-only; fail-secure excluded). They are
  non-portable anyway. Future: generate-fresh-and-seal.
- **self_login app/agent occurrences** still take client-supplied (public) enc pubkeys;
  deriving those server-side is a follow-up client-plumbing pass.

## Re-provision runbook (the proven cross-device path)
1. `pip install ciris-server==0.5.56` (per device; node auto-migrates persist on open).
2. Mint / restore the portable user fed-ID via the client's **My Identity** page:
   - **mint** a portable copy on device A → occurrence now carries derived enc pubkeys.
   - **back up** the keyset directory (USB) — carries the Ed25519 seed.
   - **associate** (restore) on device B → re-derives the identical enc key → reads the
     same self content. Roster shows the "reads self content" badge on both.
3. Add/revoke devices from the same page (`/v1/self/occurrence`, `/v1/self/occurrence/revoke`).

No env vars, no migration step beyond the auto-migrate. Boot model unchanged from 0.5.x.
