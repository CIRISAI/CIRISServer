package ai.ciris.fabric.model.federation

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

// Copied from the CIRISAgent KMP client (models/federation/NodeCode.kt).
// NodeCode QR peer-bootstrap. SCAFFOLD until the registry slice (Server 0.5)
// exposes /v1/system/peers/{my-node-code,add-from-code}.

/** `GET /v1/system/peers/my-node-code` — shareable QR/dashed peer-invite code. */
@Serializable
data class NodeCodeShareResponse(
    val code: String,
    @SerialName("qr_payload") val qrPayload: String,
    @SerialName("key_id") val keyId: String,
    @SerialName("alias_hint") val aliasHint: String? = null,
)

/** `POST /v1/system/peers/add-from-code` request. */
@Serializable
data class NodeCodeAddRequest(val code: String)

/** `POST /v1/system/peers/add-from-code` response. */
@Serializable
data class NodeCodeAddResponse(
    val peer: LocalPeerState,
    @SerialName("was_already_present") val wasAlreadyPresent: Boolean,
)
