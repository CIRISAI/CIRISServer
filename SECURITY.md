# Security policy

## Reporting a vulnerability

Two private channels, either is fine:

- **GitHub private vulnerability reporting** — the *Security* tab on any of the
  repositories in scope below. Enabled on all of them.
- **Email `info@ciris.ai`** — put `SECURITY` in the subject line. This is the
  same address CIRISAgent's policy uses, so a reporter who finds either
  repository first lands in the same place.

Do not open a public issue for anything you believe is exploitable.

**Disclosure:** we ask for two weeks before public disclosure, to patch and
notify users — matching CIRISAgent's published policy. If two weeks is not
enough for a fix we will say so and agree a date with you rather than let it
slide silently.

There is no published PGP key. If you need one before sending details, say so in
a one-line email and one will be minted and published rather than exchanged in
private.

Useful in a report, in rough order of value: the version or commit, the transport
and backend (Reticulum / HTTPS, SQLite / Postgres), what you observed, and the
smallest reproduction you have. A packet capture or a failing test is worth more
than a description. If you have only a suspicion, send the suspicion.

## What to expect, and what to do if you do not get it

| | target |
|---|---|
| acknowledgement | 3 working days |
| initial assessment — in scope, severity, whether it reproduces | 10 working days |
| fix or a dated plan | 30 days for anything remotely exploitable |

**This is one person with no rota.** Illness, travel or a dead laptop are all
plausible reasons for silence, and none of them should leave you holding a live
finding with nowhere to put it. So: **if you have had no acknowledgement after 5
working days, open a public issue that says only that you sent a report on a
given date and have not heard back.** No details, no repro. That is not a
disclosure, it is a ping with a timestamp, and it is explicitly welcome.

See [`GOVERNANCE.md`](GOVERNANCE.md) §2 for why the response capacity is one
person and what is being done about it.

## Disclosure

Coordinated, with a default of **90 days from acknowledgement** to public
disclosure, whichever comes first of that and a shipped fix.

- Shorter if it is being exploited, or if the fix is trivial and shipping it
  discloses it anyway.
- Longer only by agreement, and only for a reason we will state publicly
  afterwards — usually that a fix must land in a substrate crate
  (`ciris-persist` / `ciris-edge` / `ciris-verify`) and be adopted by a pinned
  tag here before it is safe to describe.
- You will be credited by name or handle in the commit and `CHANGELOG.md` unless
  you ask not to be.

There is **no bug bounty**. There is no money. Saying so up front is more useful
than letting you discover it after the work.

## Scope

In scope:

| artefact | where |
|---|---|
| `CIRISServer` — this repo, the `ciris-server` binary and the composition | https://github.com/CIRISAI/CIRISServer |
| `CIRISPersist` — corpus, admission, the Registry-of-Record | https://github.com/CIRISAI/CIRISPersist |
| `CIRISEdge` — transport and replication over Reticulum / HTTPS / packet radio | https://github.com/CIRISAI/CIRISEdge |
| `CIRISVerify` — the hybrid crypto core | https://github.com/CIRISAI/CIRISVerify |
| the vendored KMP client | [`client/`](client/) — desktop, Android, iOS |
| the published wheels | PyPI `ciris-server`, abi3, all published platforms |
| release binaries | the `v*` tag artefacts, and their Sigstore signatures |

Out of scope, but tell us anyway if it looks bad: the public website, CI cache
infrastructure (`CIRISCache`), and vulnerabilities in third-party dependencies —
report those upstream first, then tell us so the pin can move.

**Already known and documented** — a report that only restates one of these is
not a finding, but a *new exploitation path* on one of them is:

- **The receive plane is peer-blind.** Consent is SEND-only and does not gate
  what a node accepts; any admitted key writes signed rows naming anyone.
  Subject-side consent exists for `capacity:*` alone (CC#46).
  `FSD/MESH_GOVERNANCE_AND_ADMIN_OPS.md` §0.
- **Equivocation is free.** A key can sign contradictory claims to different
  peers at the same `asserted_at`; both verify; nothing compares them.
- **Every removal is an append on a pull-only plane.** Revoke, purge, erase,
  de-admit and halt alike. Unreached holders never learn.
- **The halt latch is not reversible in-band.** `src/accord_halt.rs` latches to
  disk and `exit(42)`s; `check_halt_gate` refuses boot. A halted node is not
  running, so the un-halt cannot reach it. There is no expiry and no severance
  window.
- **Ingest is deliberately open.** `src/ingest_http.rs` and
  `POST /v1/accord/canonical/gossip-partial` are unauthenticated by design —
  "ingest is open and cheap; admission is the gate" (`FSD/THREAT_MODEL.md`). A
  way *through* admission is very much a finding; the openness of ingest is not.
- **Rate limiting is one quota on one path.** `PeerWriteQuota` ships in persist
  (v22.0.0, `federation/replication/admission.rs`) and guards `put_attestation`
  at 600 writes per 60 s per `attesting_key_id`, with a 4096-peer tracked-set
  cap. Nothing else in the system is rate limited, and
  `DEFAULT_OPERATIONAL_PAGE_LIMIT` is `u32::MAX`. A resource exhaustion on any
  other plane is in scope and probably real.

## The crypto, stated honestly

The substrate is **hybrid Ed25519 + ML-DSA-65** for signatures throughout, with
**X-Wing** (X25519 + ML-KEM-768) for the MLS epoch keys on the realtime A/V
spine. The current pins are `ciris-verify v10.6.3` / `ciris-persist v24.2.0` /
`ciris-edge v15.9.1`.

**The crypto core has not had an external review.** No third-party audit, no
formal verification, no published cryptanalysis. The underlying primitives come
from established implementations, but everything above them is ours and
unreviewed: the hybrid composition and its verification order, the envelope
canonicalization the signature covers, the admission gates, the m-of-n family
and quorum resolution, the key-record and delegation walk. Those are where the
interesting bugs would be, and nobody outside this project has looked at them.

Two known-real examples of the class, so this is not an abstract disclaimer:

- A signed-row liveness refresh rewrote four envelope-covered columns while
  preserving the signature, so every peer refused the row — corrupt *by
  construction*, because a monotonic guard forced the covered field to advance
  (`CIRISPersist#541`).
- Two validators over the same bytes returned opposite verdicts: `verify_bundle`
  passed a genesis bundle that `put_public_key` refused, so a producer got a
  green light and shipped an artefact that could not install
  (`CIRISPersist#554`).

Neither was found by review. Both were found by something real running.

Treat any assurance claim you cannot trace to a file in these repos as absent.

## Artefact integrity

- **Wheels** publish to PyPI by **Trusted Publishing** (OIDC): owner `CIRISAI`,
  repository `CIRISServer`, workflow `publish-pypi.yml`, environment `pypi`.
  There is no stored API token, so there is no token to steal.
- Every tag's wheel is gated through the CIRISConformance cohabitation suite on
  both SQLite and Postgres before publish. A failure blocks the publish.
- **Release binaries** are signed with **Sigstore keyless** (`cosign sign-blob`)
  using the workflow's OIDC identity; each artefact ships a `.sig` and a `.pem`.
- A build-pipeline hybrid keypair exists (`CIRIS_BUILD_ED25519_SECRET` /
  `CIRIS_BUILD_MLDSA_SECRET`) and its public halves can be blessed by an accord
  holder (`.github/workflows/export-pipeline-pubkeys.yml`). The **signed
  BuildManifest self-attestation** that would make the pipeline a first-class
  participant in the conformance fabric is a documented TODO in
  `.github/workflows/release.yml`, not a shipped feature.

## What this project does not have

Verified against the repositories and their settings, so a researcher does not
waste time assuming otherwise:

- No `cargo-audit` or `cargo-deny` job in `.github/workflows/`.
- Dependabot security updates: **disabled**.
- Secret scanning and push protection: **disabled**.
- No reproducible builds. A wheel cannot currently be rebuilt bit-for-bit and
  compared to the published one.
- No security-response rota, no on-call, no second responder
  ([`GOVERNANCE.md`](GOVERNANCE.md) §2.4).

None of these is hard. They are unpaid. If one of them matters to you more than
the others, saying so in an issue is a legitimate way to change the order.
