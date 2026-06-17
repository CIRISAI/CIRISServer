package ai.ciris.fabric.net

/**
 * The CIRISServer fabric/mesh endpoint map — the single source of truth for
 * every path this client targets, and the precise wiring plan for the surfaces
 * that are scaffolded.
 *
 * ## Repoint notes (CIRISAgent client → CIRISServer)
 *
 * The CIRISAgent KMP client targeted the Python agent's API
 * (ciris_engine/logic/adapters/api/routes/...) under paths like
 * "/v1/federation/", "/v1/system/peers/", "/v1/my-data/", behind
 * `Authorization: Bearer`. CIRISServer is a Rust Reticulum node; its public
 * read surface is:
 *
 *   - GET /v1/identity   — persist `LocalIdentityAggregate`, served by
 *     `src/compose.rs::identity_router` (merged onto the lens read-API
 *     listener via `read_api_with_extra`). **LIVE today.**
 *   - GET /lens/api/v1/  — the 7 frozen lens read endpoints, served by
 *     `crates/ciris-lens-core/src/role/node.rs`. **LIVE today** (gated on the
 *     host meeting the lens-store disk minimum).
 *
 * The federation directory / content / trust / consent / governance surfaces
 * are NOT yet exposed by CIRISServer's HTTP listener — they fold in with the
 * **registry slice (Server 0.5, CIRISRegistry#76)** and the **node slice
 * (Server 1.0, CIRISNodeCore#38)**, both currently `todo!()` in
 * `compose.rs::compose_registry` / `compose_node`. Until those land, the paths
 * below are the agreed targets; the client methods stay scaffolded.
 *
 * Auth for ALL of these is the federation-signed `x-ciris-*` header contract
 * (see [ai.ciris.fabric.auth.FederationSigner]), NOT Bearer tokens.
 */
object FabricEndpoints {

    // ── PROVEN (live on the CIRISServer read-API listener today) ──────────────

    /** Six-key node identity. compose.rs::identity_router. */
    const val IDENTITY = "/v1/identity"

    /** Frozen lens read API root. node.rs UxConfig api_root. */
    const val LENS_ROOT = "/lens/api/v1"
    const val LENS_SCORES = "$LENS_ROOT/scores"
    const val LENS_DETECTION_EVENTS = "$LENS_ROOT/detection_events"
    const val LENS_MANIFOLD_AGGREGATE = "$LENS_ROOT/manifold_conformity_aggregate"
    const val LENS_CALIBRATION_BUNDLES = "$LENS_ROOT/calibration_bundles"

    // ── SCAFFOLD: registry slice — Server 0.5 (CIRISRegistry#76) ──────────────
    // Federation directory reads, per-peer trust/consent, trust-graph mgmt.
    // Paths mirror the agent client's federation routes; final shapes are
    // pinned when ciris-registry-core attaches to the shared Edge.

    /** Federation directory: list peers (canonical + organic). */
    const val FEDERATION_PEERS = "/v1/federation/peers"

    /** Single peer detail + Edge reachability. {keyId} */
    const val FEDERATION_PEER = "/v1/federation/peers" // + "/$keyId"

    /** Signal-style SAS for out-of-band key verification. {keyId}/sas */
    const val FEDERATION_PEER_SAS_SUFFIX = "/sas"

    /** Per-peer trust toggle (untrust / re-root inputs). PUT {keyId}/trust */
    const val FEDERATION_PEER_TRUST_SUFFIX = "/trust"

    /** Edge metrics snapshot (replication / health). */
    const val FEDERATION_METRICS = "/v1/federation/metrics"

    /** Local identity card (signer_key_id, crate version, peer counts). */
    const val FEDERATION_IDENTITY_CARD = "/v1/federation/identity"

    /** NodeCode QR peer-bootstrap: share my code / add from a peer's code. */
    const val NODE_CODE_MINE = "/v1/system/peers/my-node-code"
    const val NODE_CODE_ADD = "/v1/system/peers/add-from-code"

    /** Content fetch by SHA-256 from a known holder. POST {contentId} */
    const val FEDERATION_CONTENT = "/v1/federation/content" // + "/$contentId"

    /** Live federation events (SSE). {channel} */
    const val FEDERATION_EVENTS = "/v1/federation/events" // + "/$channel"

    // ── SCAFFOLD: node slice — Server 1.0 (CIRISNodeCore#38) ──────────────────
    // Canonical-group membership + voting, WBD/Wise-Authority deferral routing,
    // governance/safety surfaces, accord/PDMA-transparency.

    /** Wise-Authority / WBD deferral routing (compose_node route_deferral). */
    const val WISE_AUTHORITY_DEFERRALS = "/v1/wa/deferrals"

    /** Canonical-group membership + voting (CIRISNodeCore consensus). */
    const val GROUPS = "/v1/groups"
    const val GROUP_VOTE_SUFFIX = "/vote"

    /** Child-safety: report → surface → act pipeline. */
    const val SAFETY_REPORTS = "/v1/safety/reports"

    /** Takedown coordination across the mesh. */
    const val SAFETY_TAKEDOWNS = "/v1/safety/takedowns"

    /** Accord / WBD / PDMA transparency disclosures. */
    const val TRANSPARENCY = "/v1/transparency"

    // ── SCAFFOLD: CEG-native erasure (GDPR right-to-be-forgotten) ─────────────
    // The data subject emits a signed `withdraws`/revocation against their OWN
    // content; the substrate honours it via the §19.7 hard-delete. This is the
    // in-app path (distinct from a DSAR admin endpoint). The withdrawal is a
    // federation-SIGNED write (so it propagates as a first-class CEG event),
    // hence the federation-signer is mandatory here even under AllowAll.

    /** Emit a signed withdrawal/revocation against own content (§19.7). */
    const val ERASURE_WITHDRAW = "/v1/erasure/withdraw"

    /** DSAR-style erasure receipt / status lookup. {receiptId} */
    const val ERASURE_RECEIPTS = "/v1/erasure/receipts"
}
