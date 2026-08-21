package ai.ciris.mobile.shared.models.federation

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Wire models for **node-ownership claim, driven through the LOCAL node** —
 * `POST {localNodeUrl}/v1/setup/claim-remote`.
 *
 * ARCHITECTURE: the app is a NODE. It runs a local ciris-server with the full
 * substrate (JCS canonicalization + hybrid signing + the federation Engine). To
 * claim ownership of a remote/target node, the app does NOT build or sign
 * anything in Kotlin — it simply hands its LOCAL node the target's NodeCode + the
 * one-time claim PIN + the cohort scope. The local node then, IN ITS SUBSTRATE:
 *
 *  1. decodes the NodeCode,
 *  2. builds the owner-binding `delegates_to(user → target, infra:*)`,
 *  3. JCS-canonicalizes + HYBRID-SIGNS it with the owner's federation identity,
 *  4. POSTs the signed artifact to the target node's `/v1/setup/root`.
 *
 * The app therefore holds NO federation keys and performs NO federation crypto.
 * This is a plain UNSIGNED localhost call; the local node authenticates the
 * operator via the normal session.
 *
 * Node-side source of truth: `claim-remote` handler in CIRISServer.
 */
@Serializable
data class ClaimRemoteRequest(
    /**
     * The target node's full `CIRIS-V1-...` NodeCode string. The LOCAL node
     * decodes it to learn the target's identity + address, then builds and signs
     * the owner-binding delegation against it.
     */
    @SerialName("node_code")
    val nodeCode: String,
    /**
     * One-time **claim PIN** the operator reads off the TARGET node's console at
     * first-run. The local node forwards it inside the signed claim it POSTs to
     * the target's `/v1/setup/root`; the target rejects a wrong/expired PIN.
     */
    @SerialName("claim_pin")
    val claimPin: String,
    /**
     * The **cohort scope** the owner is adding the target node to — one of
     * `"self"` | `"family"` | `"community"`. Required; a missing/invalid value is
     * rejected by the local node (`400`).
     */
    @SerialName("cohort_scope")
    val cohortScope: String,
    /**
     * OPTIONAL owner login password — sent ONLY on the loopback **self-claim** so
     * the local node sets the ROOT cert's password, giving the owner a SYSTEM_ADMIN
     * session via `POST /v1/auth/login` (the prerequisite for approving a
     * device-auth grant). Never sent when claiming a remote node.
     */
    @SerialName("owner_password")
    val ownerPassword: String? = null,
    /**
     * OPTIONAL friendly owner username (self-claim only) → stamped as the ROOT
     * cert's name so the owner can log in with it (e.g. `eric`) instead of the
     * derived wa_id.
     */
    @SerialName("owner_username")
    val ownerUsername: String? = null,
    // Vendor drift #21: node-side OAuth owner fields (CIRISServer#384). The
    // CIRISAgent v2.9.28 re-vendor deleted them; restored verbatim. Upstream
    // changed nothing else in this file, so there is no upstream improvement to
    // merge around them.
    /**
     * The claiming owner's OAuth provider (`google` / `apple`), when they signed
     * in rather than setting a password.
     *
     * **This is an OAuth owner's only session path (CIRISServer#384.)** The claim
     * installs the ROOT cert and rotates the setup bearer, so every later call
     * 401s by design and the only route back is `/v1/auth/login`. A password
     * owner has [ownerPassword]; an OAuth owner has none, so without this the
     * claim succeeded and then the owner could authenticate to nothing — the age
     * band and the federation announce were silently skipped while the wizard
     * still reported success.
     *
     * The node stamps the pair on the ROOT cert, and OAuth sign-in resolves an
     * existing cert by `(provider, subject)` before minting anything — so the
     * owner signs in with Google and lands on the SYSTEM_ADMIN session.
     */
    @SerialName("owner_oauth_provider")
    val ownerOauthProvider: String? = null,
    /**
     * The provider's stable subject (`sub`) paired with [ownerOauthProvider].
     * Send BOTH or NEITHER — the node keys its lookup on the pair, so a half
     * pair writes a ROOT cert the sign-in can never find.
     */
    @SerialName("owner_oauth_external_id")
    val ownerOauthExternalId: String? = null,
)

/**
 * Response of `POST {localNodeUrl}/v1/setup/claim-remote`.
 *
 * Surfaced verbatim by the claim UI. On success the local node has built, signed,
 * and delivered the owner-binding delegation to the target, which bound the owner
 * as ROOT and bridged the [role] (e.g. `SYSTEM_ADMIN`).
 */
@Serializable
data class ClaimRemoteResponse(
    /** The target node's `wa_id` that was claimed. */
    @SerialName("wa_id")
    val waId: String? = null,
    /** The owner federation identity that claimed it (`key_id`). */
    @SerialName("identity_key_id")
    val identityKeyId: String? = null,
    /** The bridged API role on the target — `SYSTEM_ADMIN` on success. */
    val role: String? = null,
    /** Error string when the claim was rejected (non-2xx bodies). */
    val error: String? = null,
    // Vendor drift #21: the claim-minted owner session (CIRISServer#393),
    // deleted by the CIRISAgent v2.9.28 re-vendor and restored verbatim.
    /**
     * The owner's session, minted BY the claim (CIRISServer#393).
     *
     * The claim proves ownership with a one-time PIN and a hybrid signature over
     * the owner-binding — strictly stronger evidence than a password. Before
     * this the wizard then had to log in again to obtain an owner session, which
     * an OAuth owner simply cannot do: `owner_login SKIPPED
     * (password_present=false)`, and with it `set_age`, `announce` and
     * `federation_consent` all skipped while the app fell back to the login
     * screen. The node was claimed correctly and the user was bounced.
     *
     * The node passes the target's setup/root body straight through, so this
     * arrives on both the self-claim and the remote-claim paths.
     */
    @SerialName("access_token")
    val accessToken: String? = null,
    @SerialName("token_type")
    val tokenType: String? = null,
    @SerialName("expires_in")
    val expiresIn: Long? = null,
)
