package ai.ciris.mobile.shared.models.federation

import kotlinx.datetime.Instant
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * **A contact** — a federation identity this node has emitted a
 * `consent:replication:v1` grant to, as served by ``GET /v1/contacts``.
 *
 * The wire shape is a [LocalPeerState] (the same projection
 * ``GET /v1/federation/peers`` serves) with four contact-only members added by
 * `src/contacts_chat.rs::list_contacts`: [contact], [chatCommunityId],
 * [chatStarted] and [occurrenceKeyIds].
 *
 * # Why this is a separate DTO and not `LocalPeerState` + four fields
 *
 * The server has a documented degraded arm: a contact whose key it can no
 * longer PROJECT (a de-admitted key with the consent grant still standing) is
 * still reported, as `{key_id, canonical, trust}` plus the four contact members
 * — deliberately, so a live grant the human authored never becomes invisible.
 * `LocalPeerState` declares `pubkey_ed25519_base64` and `first_seen`
 * non-nullable with no default, so decoding that arm into it throws and the
 * WHOLE list fails. Every field the degraded arm can omit is optional here.
 */
@Serializable
data class Contact(
    @SerialName("key_id")
    val keyId: String,
    @SerialName("pubkey_ed25519_base64")
    val pubkeyEd25519Base64: String? = null,
    @SerialName("pubkey_ml_dsa_65_base64")
    val pubkeyMlDsa65Base64: String? = null,
    val canonical: Boolean = false,
    val trust: PeerTrustState = PeerTrustState.UNKNOWN,
    @SerialName("first_seen")
    val firstSeen: Instant? = null,
    val appearance: PeerAppearance? = null,
    @SerialName("alias_override")
    val aliasOverride: String? = null,
    val notes: String? = null,
    @SerialName("last_seen")
    val lastSeen: Instant? = null,
    /** Always `true` on this route — the discriminator against a bare peer card. */
    val contact: Boolean = true,
    /**
     * The DERIVED two-party community id for a chat with this contact. Present
     * whether or not the room exists yet; [chatStarted] is what says it does.
     */
    @SerialName("chat_community_id")
    val chatCommunityId: String = "",
    /** The pair community already exists on this node (the room has been opened). */
    @SerialName("chat_started")
    val chatStarted: Boolean = false,
    /** The devices this contact actually speaks from. Reported, never required. */
    @SerialName("occurrence_key_ids")
    val occurrenceKeyIds: List<String> = emptyList(),
) {
    /**
     * The key material this node can project for the contact is missing — the
     * de-admitted-but-still-consented arm above. Rendered as a warning rather
     * than hidden, because the grant is real and only the human can retract it.
     */
    val projectionMissing: Boolean get() = pubkeyEd25519Base64.isNullOrBlank()
}

/** ``GET /v1/contacts`` → `{ "contacts": [...], "total": N }`. */
@Serializable
data class ContactListResponse(
    val contacts: List<Contact> = emptyList(),
    val total: Int = 0,
)

/** ``POST /v1/contacts`` body. */
@Serializable
data class AddContactRequest(
    @SerialName("key_id")
    val keyId: String,
)

/** ``POST /v1/contacts`` → the emitted (or already-standing) consent grant. */
@Serializable
data class AddContactResponse(
    @SerialName("key_id")
    val keyId: String,
    @SerialName("consent_attestation_id")
    val consentAttestationId: String = "",
    /** `false` = an existing grant was returned, not re-emitted (the route is idempotent). */
    @SerialName("freshly_emitted")
    val freshlyEmitted: Boolean = false,
    @SerialName("occurrence_key_ids")
    val occurrenceKeyIds: List<String> = emptyList(),
    @SerialName("chat_community_id")
    val chatCommunityId: String = "",
)
