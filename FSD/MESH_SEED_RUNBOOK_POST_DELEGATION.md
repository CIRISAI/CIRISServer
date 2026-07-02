# Mesh-seed runbook — what I do after you issue the delegation grant

**Goal:** promote Node A (`ciris-canonical-1`) and Node B (`ciris-status-1`) from
self-scoped to federation-scoped, and wire the bilateral `consent:replication:v1`
peering A↔B — **entirely through the LOCAL node's API using the delegation grant**,
never by curling the remote nodes directly.

Status going in: **A and B are already owner-bound** to your fed-ID
(`eric-moore-v2-portable-…`) at `cohort_scope: self`. The claim step is DONE. What
remains is the two OPT-IN federation acts: **announce** (promote) and **peer**.

---

## 0. Preconditions (I verify these first, no side effects)

1. Local node (lapbuntu2) is up on `http://127.0.0.1:4243` running the 0.5.71 binary.
2. You have issued a fresh delegation offer; I claim it →
   `dgrant:…` (`owner:act-on-behalf`, SYSTEM_ADMIN + FullAccess, ~1h TTL).
3. Sanity: `GET /v1/auth/me` with the dgrant returns `role: SYSTEM_ADMIN`.
4. `GET /v1/setup/owned-nodes` (dgrant) lists A and B under your owner fed-ID.

I do **not** proceed if any of these fail; I report and stop.

---

## 1. The authority model (why this is the crux)

Announce and peering are **not** self-only local ops the way lapbuntu2's own announce
is. Per `src/federation_admin.rs:10‑13` the design is explicit:

> the client orchestrates the bilateral A↔B setup by driving the pair of owner
> operations — fetch A's + B's self-key-records, then **POST peering to A (peer = B)
> and to B (peer = A)** — but the authority for each grant stays **local to the node
> that signs it**.

Concretely:

| Op | Endpoint | Must run ON | Auth |
|----|----------|-------------|------|
| Fetch key record | `GET /v1/federation/self-key-record` | A and B | **none** (public, self-signed pubkey record) |
| Promote / announce | `POST /v1/federation/announce` | A and B (each promotes *its own* binding) | **owner SYSTEM_ADMIN bearer** on that node |
| Peer | `POST /v1/federation/peering` | A (peer=B) and B (peer=A) | **owner SYSTEM_ADMIN bearer** on that node |

So each write **must be authored on the target node** and needs a **SYSTEM_ADMIN
bearer session on that node**. The local dgrant is a session on **lapbuntu2 only** —
it does not authenticate me to A or B.

### The one real gap

Today the local node exposes exactly one remote-proxy: `claim-remote`
(`src/claim_remote.rs:181` — the local node signs with your fed-ID and POSTs to the
target's `/v1/setup/root`). There is **no** equivalent `announce-remote` or
`peer-remote` proxy. `announce_self_handler` (`src/claim_remote.rs:655`) promotes only
`st.node_key_id` (lapbuntu2 itself); `/v1/federation/peering` is gated on a local
bearer session (`federation_admin.rs require_owner`).

Getting a bearer on A/B needs a `password_hash` on their ROOT cert
(`src/auth/session.rs:381` — `login` refuses a cert with no password). `claim_remote`
can set that via its `owner_password` field ("so the owner can get a SYSTEM_ADMIN
session"), but A and B were claimed **without** a password, and they're already claimed
(re-claim → 409).

**⇒ There is no path today to announce/peer A and B purely through lapbuntu2's current
API. One of the two options below has to close the gap first.**

---

## 2. Two ways to close the gap — I recommend Option A

### Option A (recommended, architecture-consistent): build the local proxy endpoints

Mirror `claim-remote`. Add two owner-gated (dgrant-reachable) endpoints on the LOCAL
node that sign with your fed-ID and forward to a named remote:

- `POST /v1/federation/announce-remote  { node_code | target_url }`
- `POST /v1/federation/peer-remote      { self_url, peer_url }` (drives both directions)

Each resolves your user signer (`compose::resolve_user_signer`, same as claim-remote),
authenticates to the remote as the owner, and performs the remote's own announce /
peering. This is the "you configure them via the local grant / client, not directly"
model made real: **I only ever call `127.0.0.1:4243`; lapbuntu2 does the signed remote
call.** It is a small, well-scoped increment (~claim-remote sized) and it also unblocks
future owned-remote administration generally (ties into #8 mesh-addressing).

Sub-steps once built:
1. `POST /v1/federation/announce-remote {target_url: A}` → A promotes self→federation, sets `net.announce_ownership=true` (effective next A boot).
2. Same for B.
3. `GET` A's and B's `/v1/federation/self-key-record` (public) via the proxy.
4. `POST /v1/federation/peer-remote {self_url: A, peer_url: B}` → registers B's key on A + emits A's `consent:replication:v1` grant scoped to B; then the reverse on B.
5. Verify: `GET /v1/federation/peers` on A shows B and vice-versa; reconciler converges.

### Option B (pragmatic, works today, but bends the constraint): sessions on A and B

The KMP client is designed to hold sessions on A and B directly and drive the exact
same two POSTs. If you drive it from the app (or authorize me to obtain a bearer on
each via a password you set through an `upgrade-owner`/re-provision), the flow is:

1. Ensure A and B ROOT certs have a password (set one via a re-provision / upgrade-owner path — they currently have none).
2. `POST A/v1/auth/login` and `POST B/v1/auth/login` → two bearers.
3. `POST A/v1/federation/announce`, `POST B/v1/federation/announce`.
4. `GET A/self-key-record`, `GET B/self-key-record`.
5. `POST A/v1/federation/peering {peer = B record}`, `POST B/v1/federation/peering {peer = A record}`.
6. Verify peers both directions.

This is "directly" against A/B, which is what you asked me to avoid — so I'd only take
this route on your explicit say-so, and preferably driven through the app UI rather
than my curl.

---

## 3. Post-conditions I check either way

- A's owner-binding `delegates_to(owner→A)` now `cohort_scope: federation`; same for B.
- A's and B's `net.announce_ownership = true` (takes effect on their next boot — I note that a restart of A and B is required for the Reticulum identity announce to actually carry the attestation).
- `consent:replication:v1` grants exist both directions; `GET /v1/federation/peers` on each shows the other.
- Nothing on lapbuntu2's own scope changed unless you also asked to announce lapbuntu2.

## 4. What I will NOT do

- Curl `108.61.242.236` directly with improvised requests.
- Touch your key material / seed files to "inspect."
- Announce anything you didn't ask to announce (announce is opt-in, default OFF).
- Set a password on A/B without asking.

---

### My recommendation

Approve **Option A**: I build `announce-remote` + `peer-remote` on the local node
(one commit, mirrors claim-remote, ~its size), cut it into a 0.5.72, then run the seed
end-to-end from `127.0.0.1:4243` with the dgrant. That is the only path that both
completes the seed and honors "configure via the local grant, not directly."
