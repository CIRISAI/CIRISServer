package ai.ciris.fabric.model.federation

import kotlinx.datetime.Instant
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

// Copied from the CIRISAgent KMP client (models/federation/FederationContent.kt).
// Content fetch by SHA-256 from a known holder (no global directory). The
// sha256(decode(payload)) == content_id invariant is enforced Edge-side; the
// client does not re-verify. SCAFFOLD until compose_node/registry expose
// POST /v1/federation/content/{content_id}.

/** `POST /v1/federation/content/{content_id}` request. */
@Serializable
data class FederationContentRequest(
    @SerialName("peer_key_id") val peerKeyId: String,
    @SerialName("timeout_ms") val timeoutMs: Int = 5000,
)

/** `POST /v1/federation/content/{content_id}` success response. */
@Serializable
data class FederationContentResponse(
    @SerialName("content_id") val contentId: String,
    @SerialName("content_type") val contentType: String? = null,
    @SerialName("payload_base64") val payloadBase64: String,
    @SerialName("size_bytes") val sizeBytes: Long,
    @SerialName("fetched_at") val fetchedAt: Instant,
)
