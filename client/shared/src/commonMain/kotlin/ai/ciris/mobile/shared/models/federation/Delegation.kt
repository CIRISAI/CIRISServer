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
    /** Unix-epoch seconds the delegated token expires. */
    @SerialName("expires_at")
    val expiresAt: Long,
)

@Serializable
data class DelegationsResponse(
    val grants: List<DelegationDto> = emptyList(),
)
