package ai.ciris.mobile.shared.models

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * A completed browser sign-in, collected by the desktop app that started it.
 *
 * The browser and the app are two processes for one act, so the node parks this
 * against the app's nonce and hands it over exactly once. It carries the
 * identity as well as the bearer on purpose: on first run the wizard derives the
 * federation-ID name from `<provider>-<subject>`, and an app holding only a
 * session would know it was signed in without knowing as whom.
 */
@Serializable
data class OAuthHandoff(
    @SerialName("access_token")
    val accessToken: String,
    @SerialName("token_type")
    val tokenType: String = "Bearer",
    @SerialName("expires_in")
    val expiresIn: Long = 0,
    /** The local certificate this sign-in resolved to (or created). */
    @SerialName("user_id")
    val userId: String = "",
    val role: String = "",
    val provider: String = "",
    /** The provider's stable subject — the fed-ID name is derived from it. */
    @SerialName("external_id")
    val externalId: String = "",
    val email: String? = null,
    /**
     * The provider's OIDC ID token, when this sign-in produced one
     * (CIRISServer#434).
     *
     * CIRIS_PROXY uses a Google ID token as its `api_key`. The native clients
     * hold one already — they supply it as the login credential — but a desktop
     * sign-in happens in a BROWSER, so this hand-off is the app's only view of
     * the provider response. Without it the wizard reached
     * `llm_api_key = googleIdToken ?: ""` and configured the proxy with an
     * empty key.
     *
     * Null when the provider issues none (GitHub and Discord are OAuth2, not
     * OIDC). The node omits the key entirely in that case, so null here means
     * "there was none", never "it was blank".
     */
    @SerialName("id_token")
    val idToken: String? = null,
)
