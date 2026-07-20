# FSD — Mesh Genesis (a portable, self-verifying mesh-in-a-box: trust root + ≥1 serve node)

**Status:** PROPOSED (spec). The portable generalization of the baked
`canonical_seed.json` genesis into a **handoff artifact** — the thing you attach to a
fresh or un-trusted node to give it a trust root and a working serve node in one move.
Not law — derives from the constitution below.

**Constitution baseline:** the pluggable-trust-root model (trust is an explicit
`trust(user → root)` edge) + CC 3.4.1/4.2.1 (`accord:*`, the humanity-accord anchor) +
CC 5.3.2 (content-addressed, self-verifying bytes). Adds no new trust root and no new
key — it *packages* existing scrub-signed records.
**Subsystem:** `src/accord_provision.rs` (the co-scrub records it bundles) +
`src/compose.rs` (bootstrap/prime) + persist `federation/genesis` (the seed it
generalizes).
**Companion specs:** `FSD/TRUST_ROOT_CAPABILITY_GATE.md` (a genesis object is how a node
re-enables — §6 "attach a new trust root"), `FSD/MESH_SEED_RUNBOOK_POST_DELEGATION.md`,
`FSD/BRIDGE_SEED_MESH.md`, CIRISPersist#480 (the baked seed), CIRISServer#300/#304.

---

## 1. What it is

A **mesh genesis object** is a single, portable, self-verifying artifact that carries the
minimum needed to *be* a mesh you can trust and use:

1. **The trust root** — the humanity-accord family record + the accord-holder KeyRecords
   (their pinned anchor pubkeys). This is the terminus every chain roots to and the thing
   a receiver forms `trust(user → root)` against.
2. **At least one serve node** — an `infra:serve`-blessed canonical KeyRecord, scrub-signed
   m-of-n **by the accord holders in (1)**, carrying its transport hints (so it is
   dialable). Without a serve node a trust root is inert: it can vouch but nothing can
   receive/serve traces. The genesis therefore bundles ≥1 so the mesh *functions* on
   attach, not just validates.

Optional (not required for the minimum): `infra:attest` CI/pipeline keys (so the receiver
can validate build manifests too), and additional serve/store/transport nodes.

**Minimum viable mesh = trust root + 1 serve node.** That is the invariant this object
guarantees: attach it and you have something to trust *and* something to serve you.

## 2. Self-verifying structure (no external directory)

The object verifies **internally**, offline:
- the serve node's scrub chain roots to the accord-holder anchor pubkeys carried in (1)
  — `provenance_chain` confirms `serve_node → holder scrubs → accord family`, using only
  bytes inside the object;
- the accord family record's own anchor pubkeys are the pinned terminus (the receiver
  pins them as the root of trust on attach);
- the serve node carries `roles:["infra:serve"]` in its signed envelope, so its
  trace-recipient authority is attested by the same holders, not self-claimed.

A tampered or forged genesis fails these checks — the object is trustworthy because it
proves its own m-of-n rooting, not because of where it came from. It is therefore safe to
transfer over any channel (file, QR, device-to-device, USB).

## 3. Portability

A single content-addressed bundle (canonical JSON; SHA-256-addressable per CC 5.3.2),
small enough to move by hand. It is **stateless and idempotent** to apply: attaching the
same genesis twice is a no-op (records are content-addressed; the trust edge is set-once).

## 4. Attach / bootstrap flow

Attaching a genesis to a node:
1. **Ingest + verify** the bundle (§2) — reject on any chain/role/anchor failure
   (fail-closed).
2. **Pin the trust root** — write `trust(user → accord)` (the edge from
   `TRUST_ROOT_CAPABILITY_GATE` §1) and pin the accord anchor pubkeys.
3. **Adopt the serve node(s)** — root their KeyRecords, seed their transport hints, and
   prime replication toward them (the delivery controller can now reach a serve node).
4. **Capabilities unlock** — `trust_root_valid(node)` (capability-gate §2) now returns
   true: a valid trust-rooted humanity accord is present, its kill switch is enabled, and
   a serve node exists. Agent capabilities + manifest validation resume.

This is exactly the capability gate's re-enablement path (§6): a node that nuked its trust
(or a fresh node with none) attaches a genesis object and comes back to life — trust,
serve, and the consented kill switch all restored on one edge.

## 5. Relationship to the baked seed

`persist canonical_seed.json` bakes **one** mesh's genesis into a build (the default
canonical every fresh node roots to). The mesh genesis object is the **portable, runtime
handoff** form of the same idea: the same record shapes (accord family + holders + an
`infra:serve` canonical), but transferable and attachable at runtime rather than compiled
in. A genesis object can be *produced from* a live mesh (export the accord + a serve node)
and *consumed by* another node to join or re-root — the seed generalized into a passport.

## 6. Non-goals / boundaries

- Not a key-custody transfer — it carries only public records + attestations, never seed
  or secret material (like the `pubkey`/manifest artifacts, never a seed byte).
- Not a full directory dump — the minimum is trust root + 1 serve node; a fuller export is
  allowed but the guarantee is only the minimum-viable-mesh invariant.
- Does not bypass consent — attaching a genesis writes the `trust(user → root)` edge, an
  explicit, deletable, nuclear-revocable act (capability-gate §1); the user is choosing a
  trust root, not being assigned one.
