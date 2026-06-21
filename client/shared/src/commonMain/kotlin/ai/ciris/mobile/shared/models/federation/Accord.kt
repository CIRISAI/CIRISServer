package ai.ciris.mobile.shared.models.federation

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * The HUMANITY_ACCORD server surface — the constitutional safe-mesh floor
 * (CIRISServer #41, src/accord.rs). The accord is a small roster of
 * hardware-attested holders who jointly hold a `quorum:2/3` kill-switch over
 * constitutional invocations (CC 4.2.1). The app drives the LOCAL node only with
 * the owner session — it holds NO keys and does NO crypto; the server signs.
 *
 * Sources:
 *   - family    : ``GET /v1/accord/family``
 *   - holders   : ``GET /v1/accord-holders``
 *   - invocations: ``GET /v1/accord/invocations``
 *   - concur    : ``POST /v1/accord/invocation/concur`` (owner-gated)
 */

/** One member of the accord family roster. */
@Serializable
data class AccordFamilyMemberDto(
    @SerialName("key_id")
    val keyId: String,
    /** Optional role label (e.g. ``founder``), or null. */
    val role: String? = null,
)

/**
 * The accord family — the entrenched constitutional roster + its consensus
 * protocol. ``GET /v1/accord/family`` (404 / empty when no accord family yet).
 */
@Serializable
data class AccordFamilyDto(
    @SerialName("family_key_id")
    val familyKeyId: String,
    @SerialName("family_name")
    val familyName: String,
    /** The consensus protocol — e.g. ``quorum:2/3``. */
    @SerialName("consensus_protocol")
    val consensusProtocol: String,
    /** Whether the accord is entrenched (constitutionally fixed). */
    val entrenched: Boolean = false,
    val members: List<AccordFamilyMemberDto> = emptyList(),
)

/**
 * One accord holder in the registry — a key that may concur on invocations. The
 * holder is FIPS / hardware-attested; the app never sees private material, only
 * the published public keys. ``GET /v1/accord-holders``.
 */
@Serializable
data class AccordHolderDto(
    @SerialName("key_id")
    val keyId: String,
    @SerialName("pubkey_ed25519_base64")
    val pubkeyEd25519Base64: String,
    @SerialName("pubkey_ml_dsa_65_base64")
    val pubkeyMlDsa65Base64: String? = null,
)

/** ``GET /v1/accord-holders`` response. */
@Serializable
data class AccordHoldersResponse(
    val threshold: Int = 2,
    @SerialName("holder_count")
    val holderCount: Int = 0,
    val holders: List<AccordHolderDto> = emptyList(),
)

/**
 * One pending (or settled) accord invocation. The [invocationKind] drives a
 * MANDATED distinct visual treatment per CC 4.2.1:
 *   - ``CONSTITUTIONAL`` — strong / emergency (the kill-switch)
 *   - ``notify``         — neutral informational
 *   - ``drill``          — muted / test
 *
 * ``GET /v1/accord/invocations``.
 */
@Serializable
data class AccordInvocationDto(
    @SerialName("invocation_kind")
    val invocationKind: String,
    @SerialName("invocation_id")
    val invocationId: String,
    @SerialName("quorum_met")
    val quorumMet: Boolean = false,
    /** The holder key_ids that have validly signed this invocation. */
    @SerialName("valid_signers")
    val validSigners: List<String> = emptyList(),
    @SerialName("quorum_threshold")
    val quorumThreshold: Int = 2,
    /** The holder key_ids on the roster for this invocation. */
    @SerialName("roster_member_ids")
    val rosterMemberIds: List<String> = emptyList(),
)

/** ``GET /v1/accord/invocations`` response. */
@Serializable
data class AccordInvocationsResponse(
    val invocations: List<AccordInvocationDto> = emptyList(),
)

/** ``POST /v1/accord/invocation/concur`` response (the local holder concurred). */
@Serializable
data class AccordConcurResponse(
    @SerialName("invocation_kind")
    val invocationKind: String,
    @SerialName("invocation_id")
    val invocationId: String,
    @SerialName("quorum_met")
    val quorumMet: Boolean = false,
    @SerialName("valid_signers")
    val validSigners: List<String> = emptyList(),
)

/**
 * ``POST /v1/accord/provision-holder`` response — the two artifacts a portable
 * accord holder mints on their device (CIRISServer#41, src/accord_provision.rs).
 * The node did all the crypto from the holder's already-FIPS-approved YubiKey +
 * the chosen ML-DSA USB path; the app holds NO keys. The holder then asks the
 * node owner to register them (``POST /v1/accord/holder``).
 *
 * [holderRecord] + [custodyAttestation] are opaque signed JSON objects (the
 * verify-core ``SignedKeyRecord`` + ``SignedCegObject``); the app never inspects
 * their internals, so they ride as raw [kotlinx.serialization.json.JsonElement].
 */
@Serializable
data class AccordProvisionResponse(
    @SerialName("key_id")
    val keyId: String,
    @SerialName("holder_record")
    val holderRecord: kotlinx.serialization.json.JsonElement? = null,
    @SerialName("custody_attestation")
    val custodyAttestation: kotlinx.serialization.json.JsonElement? = null,
)
