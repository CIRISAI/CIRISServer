package ai.ciris.fabric.auth

/**
 * Produces the CIRISServer federation-signed-request headers.
 *
 * **This is the load-bearing repoint from the CIRISAgent client.** The agent
 * client authenticated read traffic with `Authorization: Bearer <jwt>`.
 * CIRISServer's read API does NOT use bearer tokens — it reuses the substrate's
 * hybrid request-auth contract (the SAME scheme `ciris-persist`'s secrets
 * server uses). See `crates/ciris-lens-core/src/role/node.rs`
 * (`require_federation_signature`) and `src/compose.rs`.
 *
 * Each request carries:
 *   - `x-ciris-signing-key-id`        : the caller's `federation_keys.key_id`.
 *   - `x-ciris-signature-ed25519`     : base64 Ed25519 signature over the BODY.
 *   - `x-ciris-signature-ml-dsa-65`   : base64 ML-DSA-65 signature over the BODY
 *                                       (REQUIRED under HybridPolicy::Strict —
 *                                       the project's hard-cut default;
 *                                       optional under Ed25519Fallback).
 *
 * The **canonical bytes are the request BODY**. GETs (identity, lens reads,
 * peer/metrics reads) have an empty body, so the signature is over `b""`. This
 * matches persist's contract, which signs the body and explicitly handles the
 * empty-body case.
 *
 * NOTE on local-dev: when the server runs `PeerAcl::AllowAll` (the documented
 * open / local-dev posture — what `src/compose.rs` passes today), the auth
 * middleware is a passthrough and signing is OPTIONAL. [NoopFederationSigner]
 * covers that case so the identity slice works against a stock local node with
 * zero key material. Production (a real ACL) REQUIRES a real signer.
 */
interface FederationSigner {
    /** The caller's `federation_keys.key_id`, or null if unauthenticated. */
    val keyId: String?

    /**
     * Sign [body] (the canonical request bytes; empty for GETs) and return the
     * `x-ciris-*` headers to attach. Returns an empty map when there is no key
     * material (unauthenticated / AllowAll local-dev).
     *
     * @param body the request body bytes; pass an empty array for GET requests.
     * @return header name → value, ready to set on the outgoing request.
     */
    suspend fun signHeaders(body: ByteArray): Map<String, String>

    companion object {
        const val HEADER_KEY_ID = "x-ciris-signing-key-id"
        const val HEADER_ED25519 = "x-ciris-signature-ed25519"
        const val HEADER_ML_DSA_65 = "x-ciris-signature-ml-dsa-65"
    }
}

/**
 * Unauthenticated signer for the open / `PeerAcl::AllowAll` local-dev posture
 * `src/compose.rs` ships today. Attaches no headers — the server's auth
 * middleware passes the request through. Swap in a real keystore-backed signer
 * for a production node behind a federation ACL.
 */
object NoopFederationSigner : FederationSigner {
    override val keyId: String? = null
    override suspend fun signHeaders(body: ByteArray): Map<String, String> = emptyMap()
}

/**
 * Hybrid Ed25519 + ML-DSA-65 federation signer — the production posture
 * (`HybridPolicy::Strict`).
 *
 * SCAFFOLD: the hybrid signing primitives must come from a platform keystore
 * (the SAME hardware-sealed Ed25519 + software ML-DSA-65 the Rust node holds —
 * see `src/compose.rs::federation_signer` / `federation_pqc_signer`). KMP has no
 * built-in Ed25519/ML-DSA; wire these to expect/actual platform crypto (e.g.
 * Android Keystore / iOS Secure Enclave for Ed25519; a Kotlin ML-DSA-65 impl or
 * a shared cdylib FFI for the PQC half). The header layout + empty-body GET rule
 * are already correct here — only the two `sign*` lambdas remain.
 */
class HybridFederationSigner(
    override val keyId: String,
    private val signEd25519: suspend (ByteArray) -> ByteArray,
    private val signMlDsa65: (suspend (ByteArray) -> ByteArray)? = null,
    private val base64: (ByteArray) -> String,
) : FederationSigner {
    override suspend fun signHeaders(body: ByteArray): Map<String, String> {
        val headers = mutableMapOf(
            FederationSigner.HEADER_KEY_ID to keyId,
            FederationSigner.HEADER_ED25519 to base64(signEd25519(body)),
        )
        signMlDsa65?.let { headers[FederationSigner.HEADER_ML_DSA_65] = base64(it(body)) }
        return headers
    }
}
