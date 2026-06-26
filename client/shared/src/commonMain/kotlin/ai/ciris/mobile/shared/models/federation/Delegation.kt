package ai.ciris.mobile.shared.models.federation

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * One LIVE delegation the owner has granted — an active device-authorization
 * grant (`dgrant:`). The owner authorized a client (agent) to act on their behalf
 * with attribution. Source: ``GET /v1/auth/device/grants`` on the local node.
 */
@Serializable
data class DelegationDto(
    /** The actor the delegation is attributed to (e.g. ``claude-agent``). */
    @SerialName("client_id")
    val clientId: String,
    /** The granted scope (e.g. ``owner:act-on-behalf``). */
    val scope: String,
    /**
     * Unix-epoch seconds the delegated token expires. **Nullable** — the node
     * omits this for a non-expiring (durable) grant, so a required field broke
     * `listDelegations` deserialization (`MissingFieldException`). `null` = no expiry.
     */
    @SerialName("expires_at")
    val expiresAt: Long? = null,
)

@Serializable
data class DelegationsResponse(
    val grants: List<DelegationDto> = emptyList(),
)

/**
 * The result of creating a delegation the owner hands to an agent — the response
 * of ``POST /v1/auth/device/delegate``. The owner gives the agent the
 * [claimUrl] + [pin]; the agent claims it (``POST /v1/auth/device/claim``) to
 * receive its delegated token. The PIN expires after [expiresIn] seconds.
 */
@Serializable
data class CreateDelegationResponse(
    /** The relative claim endpoint the agent posts the PIN to. */
    @SerialName("claim_url")
    val claimUrl: String,
    /** The short human-handover secret (e.g. ``ABCD-1234``). */
    val pin: String,
    /** The client/actor id the delegation is attributed to (e.g. ``ciris-...``). */
    @SerialName("client_id")
    val clientId: String,
    /** The granted scope (e.g. ``["owner:act-on-behalf"]``). */
    val scope: List<String> = emptyList(),
    /** Seconds until the PIN expires. */
    @SerialName("expires_in")
    val expiresIn: Long = 0,
)
