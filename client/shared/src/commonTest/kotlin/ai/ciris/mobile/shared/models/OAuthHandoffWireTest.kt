package ai.ciris.mobile.shared.models

import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * The desktop browser hand-off wire contract, pinned against the body
 * `CIRISServer/src/auth/oauth.rs` actually builds (`HandoffPayload`, served by
 * `oauth_handoff`).
 *
 * This is the DTO-drops-the-meaningful-field shape in its purest form. The
 * client decodes with `ignoreUnknownKeys`, so a wrong `@SerialName` does not
 * fail — it yields `null`, and `null` here is indistinguishable from the
 * legitimate "this provider issues no ID token". The field would read as absent
 * forever and desktop CIRIS_PROXY would go on being configured with an empty
 * key, which is exactly how CIRISServer#434 presented.
 *
 * So both cases are pinned: present and correctly named, and genuinely absent.
 */
class OAuthHandoffWireTest {

    private val json = Json { ignoreUnknownKeys = true; isLenient = true }

    /**
     * `GET /v1/auth/oauth/handoff`, 200, after a Google sign-in — the session
     * grant flattened alongside the identity, with the provider's ID token.
     */
    private val googleHandoff = """
    {
      "status": "complete",
      "access_token": "sess:wa-root-1:9f2c1e",
      "token_type": "Bearer",
      "expires_in": 86400,
      "user_id": "wa-root-1",
      "role": "SYSTEM_ADMIN",
      "provider": "google",
      "external_id": "108423319902184623111",
      "email": "eric@ciris.ai",
      "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImExIn0.eyJzdWIiOiIxMDgifQ.sig"
    }
    """

    /**
     * The same route after a provider that issues no ID token. The node omits
     * the key entirely rather than sending `null` or `""`.
     */
    private val githubHandoff = """
    {
      "status": "complete",
      "access_token": "sess:wa-root-1:aa11bb",
      "token_type": "Bearer",
      "expires_in": 86400,
      "user_id": "wa-root-1",
      "role": "SYSTEM_ADMIN",
      "provider": "github",
      "external_id": "5551212"
    }
    """

    @Test
    fun theIdTokenSurvivesDecodingUnderTheNodesOwnKeyName() {
        val h = json.decodeFromString(OAuthHandoff.serializer(), googleHandoff)

        // The whole point: CIRIS_PROXY sends this AS the LLM api_key, so a
        // re-encode or a truncation is as bad as a drop.
        assertEquals(
            "eyJhbGciOiJSUzI1NiIsImtpZCI6ImExIn0.eyJzdWIiOiIxMDgifQ.sig",
            h.idToken,
            "id_token must decode verbatim — it is a signed credential",
        )

        // It rides ALONGSIDE the session and the identity, not instead of them.
        assertEquals("sess:wa-root-1:9f2c1e", h.accessToken)
        assertEquals("google", h.provider)
        assertEquals("108423319902184623111", h.externalId)
        assertEquals("eric@ciris.ai", h.email)
    }

    @Test
    fun aProviderWithNoIdTokenDecodesAsNullNotAsAFailure() {
        val h = json.decodeFromString(OAuthHandoff.serializer(), githubHandoff)

        assertNull(h.idToken, "an absent id_token is a fact about the provider")
        // And the sign-in is still fully usable — absence is not an error.
        assertEquals("sess:wa-root-1:aa11bb", h.accessToken)
        assertEquals("github", h.provider)
    }
}
