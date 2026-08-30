package ai.ciris.fabric.model.identity

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * The node's six-key federation identity — the body of `GET /v1/identity`.
 *
 * **This is the proven vertical slice.** Field names mirror, byte-for-byte, the
 * Rust `LocalIdentityAggregate` that CIRISServer serializes (CIRISPersist
 * v8.4.0 `src/federation/identity_aggregate.rs`, surfaced by
 * `src/compose.rs::identity_router` / `local_identity_json`). CEG 1.0
 * §5.6.8.8.2.
 *
 * Adapted from the CIRISAgent KMP client's `FederationIdentityAggregate`
 * (`models/federation/FederationIdentityAggregate.kt`). The agent client read
 * this shape from the agent's `GET /v1/system/peers/federation-identity`
 * envelope; CIRISServer serves the SAME persist struct **directly** at
 * `GET /v1/identity` (no `{data:…}` envelope, no companion NodeCode wrapper),
 * and adds three fields the agent client omitted:
 *   - [didKey]               — `did:key` form of the signing key (optional).
 *   - [identityHash]         — stable hash over the aggregate (continuity check).
 *   - [evaluatedAtUnixMs]    — assembly timestamp (epoch ms).
 *
 * The SIX keys across three roles (all sourced from the ONE federation signing
 * identity + the Reticulum transport identity — see compose.rs):
 *   1. Signing:   Ed25519 ([ed25519PubkeyB64], hardware-sealed) +
 *                 optional ML-DSA-65 ([mlDsa65PubkeyB64], PQC).
 *   2. Reticulum: X25519 ([reticulumX25519PubkeyB64]) + Ed25519
 *                 ([reticulumEd25519PubkeyB64]).
 *   3. Content:   X25519 ([contentX25519PubkeyB64]) + optional ML-KEM-768
 *                 ([contentMlKem768PubkeyB64], PQC).
 *
 * [keyId] is THE federation address peers / lens / registry use to reach this
 * node. It is NOT necessarily the key the pubkeys below belong to — see
 * [keyMaterialKeyId] and [keyMaterialBelongsToAnotherKey]. Optional capability keys default to null — older persist builds and
 * non-PQC deployments omit them. `ignoreUnknownKeys` is set on the JSON parser
 * so forward-compatible field additions don't break decode.
 */
@Serializable
data class LocalIdentityAggregate(
    @SerialName("aggregate_version")
    val aggregateVersion: Int = 0,
    @SerialName("key_id")
    val keyId: String,
    @SerialName("pqc_key_id")
    val pqcKeyId: String? = null,
    @SerialName("ed25519_pubkey_b64")
    val ed25519PubkeyB64: String,
    @SerialName("ml_dsa_65_pubkey_b64")
    val mlDsa65PubkeyB64: String? = null,
    @SerialName("reticulum_x25519_pubkey_b64")
    val reticulumX25519PubkeyB64: String? = null,
    @SerialName("reticulum_ed25519_pubkey_b64")
    val reticulumEd25519PubkeyB64: String? = null,
    @SerialName("content_x25519_pubkey_b64")
    val contentX25519PubkeyB64: String? = null,
    @SerialName("content_ml_kem_768_pubkey_b64")
    val contentMlKem768PubkeyB64: String? = null,
    // ── CIRISServer / persist v8.4.0 extras (absent on the agent endpoint) ──
    @SerialName("did_key")
    val didKey: String? = null,
    @SerialName("identity_hash")
    val identityHash: String? = null,
    @SerialName("evaluated_at_unix_ms")
    val evaluatedAtUnixMs: Long? = null,
    // ── The node/actor split (CIRISServer 0.5.196) ─────────────────────────
    /**
     * Whose key material the pubkeys above actually are.
     *
     * On a node carrying an agent, the signing and content-KEM pubkeys come
     * from the ENGINE's signer — the ACTOR — while [keyId] is the NODE's
     * address. Those are two different keys, and before this field the
     * disagreement was invisible: a consumer verifying a fingerprint, or
     * sealing to this identity, would use the wrong one and get no warning.
     *
     * Null on a server too old to say. Null is "unknown", NOT "they match".
     */
    @SerialName("key_material_key_id")
    val keyMaterialKeyId: String? = null,
    /** This node's own key — always present on a 0.5.196+ server. */
    @SerialName("node_key_id")
    val nodeKeyId: String? = null,
    /** The agent's key, when one is installed. Null on a relay-only node. */
    @SerialName("actor_key_id")
    val actorKeyId: String? = null,
    /** `node` / `agent` / `user`, read from the federation directory. */
    @SerialName("identity_type")
    val identityType: String? = null,
) {
    /** PQC signing material present (ML-DSA-65 pubkey and/or its key id). */
    val hasPqc: Boolean
        get() = mlDsa65PubkeyB64 != null || pqcKeyId != null

    /** Reticulum transport keys present (either half of the pair). */
    val hasReticulum: Boolean
        get() = reticulumX25519PubkeyB64 != null || reticulumEd25519PubkeyB64 != null

    /** Content-encryption keys present (X25519 and/or ML-KEM-768). */
    val hasContentEncryption: Boolean
        get() = contentX25519PubkeyB64 != null || contentMlKem768PubkeyB64 != null

    /**
     * **Do the pubkeys above belong to [keyId]?**
     *
     * `true` when the server says they belong to a different key — on a split
     * node, the actor's. Verify a fingerprint or seal to this identity only
     * after checking this.
     *
     * `false` when they agree AND when the server did not say. Null is
     * unknown, and unknown must not read as a warning any more than it reads
     * as an all-clear — a client that treated silence as a mismatch would
     * flag every older server.
     */
    val keyMaterialBelongsToAnotherKey: Boolean
        get() = keyMaterialKeyId != null && keyMaterialKeyId != keyId

    /** This node carries an agent as well as being a node. */
    val isSplitNode: Boolean
        get() = actorKeyId != null && nodeKeyId != null && actorKeyId != nodeKeyId
}
