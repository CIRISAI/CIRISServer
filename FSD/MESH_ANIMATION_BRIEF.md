# Design request — "The mesh, in motion": an ALM + holonomic explainer animation

> **To:** the design team · **From:** CIRISServer · **Status:** request / brief
> **Companion docs (the source of truth for every number here):**
> [`FSD/PQC_AV_STREAMING_BENCH.md`](PQC_AV_STREAMING_BENCH.md) (measured + capacity model),
> the capability page (<https://cirisai.github.io/CIRISServer/>), and the **v0.7
> scaling toy** `CIRISNodeCore/examples/scale_model.rs` (the fountain/holonomic model).
> **Provenance discipline is non-negotiable** — see §6. Every quantitative claim the
> animation makes must be badge-able **MEASURED · MODEL · FRONTIER**, exactly as the
> page badges them. We would rather under-claim than ship a beautiful lie.

---

## 1. The ask, in one sentence

Make a short (target **45–75 s**), loopable animation that makes someone *feel*,
without narration, **why a 2,000-person encrypted space runs on the participants'
own home uplinks with no datacenter** — by showing the two things that make it
possible and that no centralized product has:

1. **ALM** — *application-layer multicast*: one sealed copy enters a **tree of
   peer-relays**, never a star. Nobody fans out to 2,000.
2. **Holonomic storage/delivery** — content is **shattered into fountain symbols**;
   *any sufficient subset reconstructs the whole*. The picture survives losing a
   third of the room.

If a viewer comes away understanding *"one copy in, the room forwards it for itself,
and it heals when pieces drop,"* the animation has done its job.

---

## 2. Why this matters (the feeling to land)

The incumbent mental model is a **star**: every webcam goes up to a datacenter, the
datacenter sends every face back down, and you see at most 49 tiles. The animation
must replace that picture in the viewer's head with a **living tree that the room
grows for itself**, where presence is cheap, encryption is end-to-end, and the
"server" is just *the next peer over*.

Emotional arc: **claustrophobic star → breathing peer tree → it gets hit and keeps
going.** Awe should come from *resilience and self-organization*, not from a big
number.

---

## 3. Storyboard (scene by scene, with the grounding numbers)

Treat each scene's numbers as captions/HUD you may show or may keep as fidelity
constraints on the motion. Tier labels and counts are **real** — use them.

### Scene 0 — The star we're replacing  *(≈5 s)*
- A dense grid of webcam tiles. A hard **cap at 49 tiles** snaps shut; the rest of a
  large room becomes a grey "+1,951" counter. All arrows route through one glowing
  central **datacenter** brick.
- *Feeling:* centralized, bottlenecked, capped.
- *Grounding:* Zoom/Meet/Teams gallery caps ~49 (MODEL/cited). This is the foil.

### Scene 1 — One copy in  *(≈8 s)*
- A single publisher (a phone) emits **one** sealed packet upward — *not* 2,000
  arrows. Show it as a single bright capsule. Label: **"1 sealed copy."**
- *Grounding:* publisher emits once; fan-out is the tree's job, not the sender's
  (ALM, MODEL/§3). Sender CPU to seal is trivial — see Scene 5.

### Scene 2 — The tree builds itself  *(≈12 s — the hero shot)*
- The copy lands on a relay parent, which **splits to a handful of children**, which
  split again — a tree growing downward/outward until it touches all 2,000 peers.
- Use the **real tier shape** (fan-out f≈12 ⇒ **4 tiers**):
  **root → 2 → 14 → 167 → 2,000.** Depth is **O(log_f N)**, *not* linear.
- Critically: **leaf peers forward nothing** (a phone just receives + publishes its
  own dot). The forwarding load lives on the **"fat interior"** — peers with real
  donated uplink. Show interior nodes visibly "wider" (thicker pipes) than leaves.
- No central brick anywhere. The tree is the only structure on screen.
- *Feeling:* the room assembling its own delivery fabric, organically.
- *Grounding (MODEL/§3):* tier sizes from the capacity model; fan-out bounded by each
  peer's **measured** uplink; topology is a **deterministic pure function of
  witnessed state — no leader**, "no node can lie its way to the center."

### Scene 3 — Presence at scale  *(≈8 s)*
- Pull back to the **viewer's** POV: 2,000 little **presence dots** (4-px blobs,
  1–2 fps shimmer) all alive at once around the screen edge; one is **focus-pulled**
  to full-quality video when the viewer "looks at" it.
- HUD, honest operating point: **"2,000 presence dots · ~5 kbps each · ~10 Mbps to
  your device."** When the focus-pull happens, that one stream resolves to full
  720p/8K from its *top* layer.
- *Grounding (MODEL/§2, matches the page hero):* presence dot ~5 kbps → ~10 Mbps
  downlink at N=2,000; the room's **total** donated uplink ≈ **20 Gbps = N²·b**,
  which **ordinary asymmetric homes sum to with no datacenter.** Do **not** headline
  the 50 kbps/100 Mbps "video thumbnail" point — that one needs a prosumer interior
  (be consistent with the page; see §6).

### Scene 4 — Holographic layers (the "holonomic" delivery half)  *(≈10 s)*
- Show one stream as **stacked layers** (a base `{0,0,0}` dot layer + higher
  spatial/quality layers). The relay **drops un-subscribed layers *before* sealing** —
  visualize layers being sliced off at a relay so only what you asked for flows down.
- Then the fountain view: a chunk **shatters into ~26 symbols**; each peer holds
  **one symbol (~5% of the content)**. Symbols rain out to many holders.
- *Grounding:* SVC layering **ships today (FRONTIER label for symmetric M>2 MDC** —
  the codec doesn't exist yet, M=2 is the default). Fountain (v0.7 toy):
  **N=20 source + K=6 repair symbols**, each holder stores **1/N ≈ 5%**, target
  **H=30 holders**, network overhead **H/N = 1.5×** (vs **5×** for whole-copy — call
  this out, it's a 3.3× win).

### Scene 5 — It gets hit, and heals  *(≈12 s — the emotional payoff)*
- **5a — path redundancy (ALM):** a relay subtree goes dark (node turns red and
  drops). The stream **instantly re-routes** through a **backup parent** — the
  picture never stutters. Show **primary + 2 backups** (MAX_BACKUPS=2) as ghosted
  alternate edges that light up on failure.
- **5b — fountain survival (holonomic):** kill a **third of the symbol-holders**
  (10 of 30 go dark). A meter reads **"20 / 30 symbols — reconstructing"** and the
  full frame **rebuilds from the survivors**, crisp.
- *Feeling:* you can hit it hard and it shrugs.
- *Grounding (MODEL, both CI-proven in this repo):* `tests/chaos_mesh.rs` —
  path-redundant chunk decodes from any **surviving** path; survival floor is **any
  20 of 30** holders (**33% loss tolerance**), survival probability
  **P(Binomial(H,q) ≥ N) ≈ 99.7% at q=0.85**. *Optional truth-in-advertising:* the
  reconstruction floor is **5 viable symbols** (MIN_VIABLE_SYMBOLS).

### Scene 6 — The seal (why a relay can betray you and lose)  *(≈8 s)*
- Zoom into one relay hop. The packet has **two shells**: an **outer** shell the
  relay opens and **re-seals** (per-link), and an **inner** shell it **can never
  open** (end-to-end). Render the inner core as an opaque, glowing solid that stays
  sealed *through every hop*. A "compromised" relay (red) opens the outer shell and
  finds **only ciphertext** inside.
- *Grounding (MEASURED + FRONTIER):* two-layer AEAD — inner AES-256-GCM under a
  per-(stream,epoch) DEK (E2E; relays never hold it), outer AES-256-GCM under a
  per-link key from a hybrid **X25519 + ML-KEM-768** handshake. The relay-reseal
  primitive `open_av_outer` **ships** (CIRISEdge#149, edge v4.2.0); inner ciphertext
  is **byte-identical across hops** (`tests/alm_chain.rs`, CI-proven). **100% hybrid
  post-quantum, hard cut — no classical-only path.**

### Scene 7 — Resolve / loop  *(≈4 s)*
- Pull all the way back: the breathing tree of 2,000, dots alive, no datacenter in
  frame, the title line. Loop seamlessly back to Scene 1's single copy.
- Optional end-card line: *"One copy in. The room carries it. It heals when pieces
  drop. End-to-end, post-quantum, no datacenter."*

---

## 4. Visual & motion language (suggestions, not constraints)

- **Tree, never star.** The single most important compositional rule. If a frame
  ever looks like spokes into a hub, it's wrong (that's Scene 0, the foil).
- **Pipe thickness = donated uplink.** Interior peers have fat pipes; leaves have
  thin ones. This *is* the supply-ledger story, shown not told.
- **Two shells = two colors.** Outer (per-link, openable by relays) vs inner (E2E,
  never openable). Keep the inner core visually inviolate end to end.
- **Symbols are granular, not whole.** A fountain chunk should visibly *shatter* into
  many small pieces; reconstruction is pieces *converging*, not a copy *arriving*.
- **Heal = continuity.** On failure the motion must read as "no stutter," not
  "recovers after a beat." The point is it doesn't drop.
- Calm, organic, breathing — biological/mycelial over corporate-network-diagram.
- Accessible: don't encode meaning in color alone (failure also = shape/opacity).

---

## 5. Deliverables (proposed — confirm with us)

- **Master:** 1080p (and 4K) MP4/ProRes, 45–75 s, **silent** (motion must stand
  without audio) + an **optional** sound-design pass.
- **Loop:** a seamless ~10 s loop of the hero tree (Scenes 2–3) for the site header.
- **Stills:** the tree hero (Scene 2), the two-shell seal (Scene 6), the heal moment
  (Scene 5) — for docs / social / the capability page.
- **Web-light:** a Lottie/SVG-animation or short webm version light enough to embed
  on <https://cirisai.github.io/CIRISServer/> without a heavy payload.

---

## 6. Honesty discipline — the **MEASURED · MODEL · FRONTIER** rule

This is the same discipline the capability page lives under, and it is the one
non-negotiable constraint. **Any number or capability shown must carry — or be
truthfully assignable to — one of three provenance classes.** If you're unsure which
class a thing is, ask us; don't guess upward.

| class | means | examples in this animation |
|---|---|---|
| **MEASURED** | real benchmark in this repo, host-relative | ~437 ns/relay hop · ~0.44 µs/added tier · AEAD ~2.2 GiB/s · ML-KEM tax ~80–90 µs **once per peer-link, never per frame** · inner ciphertext byte-identical across hops |
| **MODEL** | bandwidth/probability arithmetic over the v0.7 toy + capacity model — **not** a live N-node test | tier sizes (2000→167→14→2→root) · ~10 Mbps downlink @ 2,000 dots · 20 Gbps room total (N²·b) · 1.5× vs 5× overhead · any-20-of-30 survival |
| **FRONTIER** | the wire/substrate ships, the **production piece does not exist yet** | symmetric **M>2 MDC** video (NeuralMDC-class codec doesn't exist; **M=2 is the default**) · the full 2,000-stream live federation (the chain primitive is proven; the full harness is design — CIRISConformance#16) |

**Hard "do nots":**
- **Do not** headline the **50 kbps / 100 Mbps** thumbnail point. The honest,
  consistent operating point — matching the page hero — is the **~5 kbps presence
  dot → ~10 Mbps downlink → ~20 Gbps room total from ordinary home uplinks**. The
  50 kbps point needs a *prosumer fat interior*; if you show it at all, show it as
  the "more than presence costs more" step, never the headline.
- **Do not** imply a live 2,000-person deployment exists today. The crypto path and
  the relay-chain primitive are **measured/shipped**; the full-room sim is **MODEL/
  design**. "Here's how it works and what the math says," not "here's a product demo."
- **Do not** invent a CO₂/energy number on screen. (The v0.7 toy *has* an energy
  model, but the per-byte comparison isn't substantiated enough to headline — we just
  removed that claim from the page.) "Removes the centralized control plane" is the
  safe framing if you need a sustainability beat.
- **Do not** show relays reading content. The whole point of Scene 6 is they can't.

When in doubt: the numbers in §3 and the table above are the contract. Pull anything
else from the companion docs, or ask.

---

## 7. Quick technical fact sheet (for captions / fidelity)

- **ALM tree (MODEL):** one copy in; per-node fan-out f bounded by *measured* uplink;
  depth O(log_f N); at f≈12, N=2,000 ⇒ **4 tiers, 2000→167→14→2→root**; **primary +
  2 backup** parents; deterministic, leaderless topology.
- **Relay forwarding (MODEL):** ~150 Mbps egress/core ⇒ ~3,000 blob or ~60 full-720p
  forwards per core. CPU is *not* the limit — **donated uplink is.**
- **Supply ledger (MODEL):** everyone-sees-everyone = N×N delivery; room's total
  donated uplink = **N²·b**. @ N=2,000: 5 kbps→20 Gbps (ordinary homes); 50 kbps→
  200 Gbps (prosumer interior).
- **Holonomic fountain (v0.7 toy, MODEL):** RaptorQ; **N=20** source + **K=6** repair;
  hold **1/N ≈ 5%** each; target **H=30** holders; overhead **1.5×** (vs 5×); rebuild
  from **any 20 of 30** (33% loss); floor **5** viable symbols; survival
  **P(Binomial(H,q)≥N) ≈ 99.7% @ q=0.85**.
- **Layers (SVC today / MDC FRONTIER):** base `{0,0,0}` ≈ presence layer; relays drop
  un-subscribed layers *before* sealing.
- **Crypto (MEASURED + shipped):** inner AES-256-GCM (per-(stream,epoch) DEK, E2E) +
  outer AES-256-GCM (per-link, X25519+ML-KEM-768 KEX); `open_av_outer` re-seals the
  outer shell **without touching the DEK**; 100% hybrid PQC, hard cut.
- **Measured chain (this repo):** ~437 ns/relay hop (blob), ~0.44 µs/added tier,
  inner ciphertext byte-identical across 1–5 hops (`benches/` + `tests/alm_chain.rs`,
  `tests/chaos_mesh.rs`).
