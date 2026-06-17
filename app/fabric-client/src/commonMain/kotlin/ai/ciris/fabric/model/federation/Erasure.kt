package ai.ciris.fabric.model.federation

import kotlinx.datetime.Instant
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * CEG-native erasure (GDPR Art. 17 right-to-be-forgotten) — the IN-APP path.
 *
 * The user clarified erasure is BOTH a DSAR endpoint AND in-app CEG-native;
 * this is the in-app path. The data subject emits a federation-SIGNED
 * `withdraws`/revocation against their OWN content; the substrate honours it via
 * the §19.7 hard-delete and propagates the withdrawal as a first-class CEG
 * event so replicas drop the content too.
 *
 * Treated as a first-class governance surface (not a settings toggle). Because
 * the withdrawal is a signed WRITE, the federation signer is mandatory here even
 * under the AllowAll local-dev posture — an unsigned withdrawal is meaningless
 * (the substrate must know WHO is revoking WHAT).
 *
 * NEW model (no CIRISAgent counterpart — the agent client only had a coarse
 * `DELETE /v1/my-data/lens-traces` DSAR call in DataManagementScreen). SCAFFOLD
 * until the node slice (Server 1.0) exposes POST /v1/erasure/withdraw.
 */
@Serializable
data class WithdrawRequest(
    /** Content the subject is revoking — SHA-256 content_id(s) they authored. */
    @SerialName("content_ids") val contentIds: List<String>,
    /** The revoking subject's federation key_id (MUST match the signer). */
    @SerialName("subject_key_id") val subjectKeyId: String,
    /** Optional human reason, recorded in the erasure receipt. */
    val reason: String? = null,
    /**
     * Whether to propagate the withdrawal to peers holding replicas
     * (§19.7 mesh hard-delete). Default true — the whole point of CEG-native
     * erasure is that it travels with the content.
     */
    @SerialName("propagate_to_replicas") val propagateToReplicas: Boolean = true,
)

/** `POST /v1/erasure/withdraw` response — the erasure receipt. */
@Serializable
data class WithdrawReceipt(
    @SerialName("receipt_id") val receiptId: String,
    @SerialName("content_ids") val contentIds: List<String>,
    /** local | propagating | mesh_complete | failed */
    val status: String,
    @SerialName("hard_deleted_local") val hardDeletedLocal: Boolean,
    @SerialName("replicas_notified") val replicasNotified: Int = 0,
    @SerialName("issued_at") val issuedAt: Instant,
)
