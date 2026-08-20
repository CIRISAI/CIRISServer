package ai.ciris.mobile.shared.models.chat

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * **User-to-user chat — the CEG object model, not a message model.**
 *
 * A chat message IS a `scores` attestation on `chat:message:v1`, authored by the
 * owner's federation identity and placed at the `community` cohort scope. The
 * server projects it (`src/contacts_chat.rs::ChatMessage`) with its CEG identity
 * intact — `attestation_id`, `attesting_key_id`, `cohort_scope`, and the folded
 * `status` — precisely so the client can render it with the SAME
 * `AttestationCard` + `AttestationHamburger` it uses for every other attestation.
 *
 * Do not add a `{from, text, at}` convenience shape here. A second, weaker
 * object model for rows that are ordinary attestations is exactly what the
 * server's own doc comment refuses to ship.
 */
@Serializable
data class CegChatMessage(
    @SerialName("attestation_id")
    val attestationId: String,
    @SerialName("attesting_key_id")
    val attestingKeyId: String = "",
    @SerialName("attested_key_id")
    val attestedKeyId: String = "",
    @SerialName("attestation_type")
    val attestationType: String = "scores",
    @SerialName("subject_key_ids")
    val subjectKeyIds: List<String> = emptyList(),
    @SerialName("cohort_scope")
    val cohortScope: String = COHORT_SCOPE_COMMUNITY,
    @SerialName("community_id")
    val communityId: String = "",
    /** `live` | `superseded` | `withdrawn` | `recanted` — persist's own vocabulary. */
    val status: String = STATUS_LIVE,
    /** The composer row that produced a non-`live` [status]; omitted when live. */
    @SerialName("status_attestation_id")
    val statusAttestationId: String? = null,
    val body: String = "",
    @SerialName("content_type")
    val contentType: String = "text/plain",
    /** RFC3339. The transcript is ordered by this, ascending (OLDEST FIRST). */
    @SerialName("asserted_at")
    val assertedAt: String = "",
    /** `true` when this node's owner authored the message. Drives alignment + authority. */
    val mine: Boolean = false,
) {
    val isLive: Boolean get() = status == STATUS_LIVE

    companion object {
        const val STATUS_LIVE = "live"
        const val STATUS_SUPERSEDED = "superseded"
        const val STATUS_WITHDRAWN = "withdrawn"
        const val STATUS_RECANTED = "recanted"
        const val COHORT_SCOPE_COMMUNITY = "community"
    }
}

/** ``POST /v1/chat`` body — open (or re-open) the two-member room with `key_id`. */
@Serializable
data class StartChatRequest(
    @SerialName("key_id")
    val keyId: String,
)

/**
 * ``POST /v1/chat`` → the pair community.
 *
 * [communityId] is DERIVED from the two `key_id`s sorted, so both ends dial the
 * same room without agreeing on who initiated; [freshlyCreated] is `false` when
 * the existing row was returned rather than re-authored.
 */
@Serializable
data class ChatCommunity(
    @SerialName("community_id")
    val communityId: String,
    @SerialName("community_name")
    val communityName: String = "",
    @SerialName("member_key_ids")
    val memberKeyIds: List<String> = emptyList(),
    @SerialName("cohort_scope")
    val cohortScope: String = CegChatMessage.COHORT_SCOPE_COMMUNITY,
    @SerialName("freshly_created")
    val freshlyCreated: Boolean = false,
)

/** ``GET /v1/chat/{community_id}/messages`` → the transcript, OLDEST FIRST. */
@Serializable
data class ChatTranscript(
    @SerialName("community_id")
    val communityId: String = "",
    @SerialName("cohort_scope")
    val cohortScope: String = CegChatMessage.COHORT_SCOPE_COMMUNITY,
    val messages: List<CegChatMessage> = emptyList(),
    val total: Int = 0,
)

/** ``POST /v1/chat/{community_id}/messages`` body. */
@Serializable
data class SendChatMessageRequest(
    val body: String,
    @SerialName("content_type")
    val contentType: String? = null,
)

/**
 * ``POST /v1/chat/{community_id}/messages`` → the emitted attestation.
 *
 * [message] is `null` when the row LANDED but the read-back projection did not
 * resolve. That is a SUCCESS, not a failure — the server says so explicitly
 * rather than reporting a failed send. Treat it as sent and refresh the list.
 */
@Serializable
data class SendChatMessageResult(
    @SerialName("attestation_id")
    val attestationId: String,
    @SerialName("community_id")
    val communityId: String = "",
    @SerialName("cohort_scope")
    val cohortScope: String = CegChatMessage.COHORT_SCOPE_COMMUNITY,
    val message: CegChatMessage? = null,
)
