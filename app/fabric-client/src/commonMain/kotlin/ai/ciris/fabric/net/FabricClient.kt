package ai.ciris.fabric.net

import ai.ciris.fabric.auth.FederationSigner
import ai.ciris.fabric.auth.NoopFederationSigner
import ai.ciris.fabric.model.identity.LocalIdentityAggregate
import ai.ciris.fabric.platform.PlatformLogger
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.isSuccess
import io.ktor.serialization.kotlinx.json.json
import kotlinx.serialization.json.Json

/**
 * HTTP client for CIRISServer's fabric/mesh surfaces.
 *
 * Copied in spirit from the CIRISAgent KMP client's `CIRISApiClient`, but
 * stripped of every agent-card method (chat / runtime / cognitive-state /
 * billing / setup / location / adapters / services / telemetry) and repointed
 * at CIRISServer's REAL endpoints with federation-signed auth instead of
 * `Authorization: Bearer`.
 *
 * PROVEN slice: [getIdentity] → `GET /v1/identity`.
 * SCAFFOLD: the rest of the fabric surface (lens reads, federation directory,
 * content, trust, consent, governance) is mapped in [FabricEndpoints] and
 * stubbed below with precise wiring TODOs — those endpoints land as the
 * registry (Server 0.5) and node (Server 1.0) slices fold into the substrate.
 *
 * @param baseUrl e.g. `http://127.0.0.1:8080` — the lens read-API listener
 *   (`ServerConfig::read_api_addr`) that also serves `GET /v1/identity` via the
 *   `extra` router merged in `compose.rs::serve`.
 * @param signer produces the `x-ciris-*` federation-signed headers. Defaults to
 *   [NoopFederationSigner] for the open / AllowAll local-dev posture.
 */
class FabricClient(
    val baseUrl: String,
    private val signer: FederationSigner = NoopFederationSigner,
    private val httpClient: HttpClient = defaultHttpClient(),
) {
    /**
     * `GET /v1/identity` → the node's six-key [LocalIdentityAggregate].
     *
     * The PROVEN vertical slice. Empty-body GET, so the federation signature (if
     * any) is over `b""` per the node.rs auth contract. Decodes the persist
     * `LocalIdentityAggregate` JSON directly (no envelope).
     */
    suspend fun getIdentity(): LocalIdentityAggregate {
        val resp = signedGet(FabricEndpoints.IDENTITY)
        if (!resp.status.isSuccess()) {
            throw FabricApiException(
                "GET ${FabricEndpoints.IDENTITY} failed: HTTP ${resp.status.value} — ${resp.bodyAsText()}",
            )
        }
        return resp.body()
    }

    // ── SCAFFOLD: CEG-native erasure (right-to-be-forgotten) ──────────────────

    /**
     * Emit a federation-SIGNED withdrawal against the subject's OWN content
     * (`POST /v1/erasure/withdraw`). The substrate honours it via the §19.7
     * hard-delete and propagates to replicas when [propagateToReplicas].
     *
     * The signed-write contract: the canonical bytes are the JSON request BODY
     * (NOT empty), so the federation signature covers the actual withdrawal
     * payload. This is why an unsigned withdrawal is rejected even under
     * AllowAll — the substrate must cryptographically know WHO revokes WHAT.
     *
     * TODO(Server 1.0 / CIRISNodeCore#38): the endpoint is not yet served by
     * CIRISServer's HTTP listener (`compose.rs::compose_node` is `todo!()`).
     * Wiring once it lands:
     *   1. serialize [ai.ciris.fabric.model.federation.WithdrawRequest] to bytes;
     *   2. `signer.signHeaders(bodyBytes)` — body-signed, signer MANDATORY here;
     *   3. POST with those headers + the JSON body;
     *   4. decode [WithdrawReceipt].
     * The model + UI + signed-write rule are complete; only this POST is open.
     */
    @Suppress("UNUSED_PARAMETER")
    suspend fun withdrawContent(
        contentIds: List<String>,
        subjectKeyId: String,
        reason: String?,
        propagateToReplicas: Boolean,
    ): ai.ciris.fabric.model.federation.WithdrawReceipt {
        TODO(
            "POST ${FabricEndpoints.ERASURE_WITHDRAW} — body-signed withdrawal. " +
                "Lands with the node slice (Server 1.0). See FabricEndpoints + WithdrawRequest.",
        )
    }

    /**
     * Issue a signed GET. GET bodies are empty, so the canonical signed bytes
     * are `ByteArray(0)` — matching `node.rs`'s empty-body rule.
     */
    private suspend fun signedGet(path: String): HttpResponse {
        val headers = signer.signHeaders(ByteArray(0))
        PlatformLogger.d(TAG, "GET $baseUrl$path (signed=${headers.isNotEmpty()})")
        return httpClient.get("$baseUrl$path") {
            headers.forEach { (k, v) -> header(k, v) }
        }
    }

    fun close() = httpClient.close()

    companion object {
        private const val TAG = "FabricClient"

        val json = Json {
            ignoreUnknownKeys = true
            isLenient = true
            explicitNulls = false
        }

        fun defaultHttpClient(): HttpClient = HttpClient {
            install(ContentNegotiation) { json(json) }
        }
    }
}

/** Thrown for non-2xx fabric API responses. */
class FabricApiException(message: String, cause: Throwable? = null) :
    RuntimeException(message, cause)
