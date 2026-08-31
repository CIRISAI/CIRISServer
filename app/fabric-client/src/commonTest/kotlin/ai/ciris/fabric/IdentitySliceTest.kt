package ai.ciris.fabric

import ai.ciris.fabric.net.FabricClient
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.ktor.serialization.kotlinx.json.json
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Proves the PROVEN slice: the [ai.ciris.fabric.model.identity.LocalIdentityAggregate]
 * decodes the EXACT JSON CIRISServer's `GET /v1/identity` serializes.
 *
 * The fixture below is the persist v8.4.0 `LocalIdentityAggregate`
 * `serde_json` shape (src/federation/identity_aggregate.rs), which
 * `compose.rs::local_identity_json` returns verbatim. If CIRISServer's field
 * names drift, this test breaks — exactly the early-warning we want.
 */
class IdentitySliceTest {

    private val identityJson = """
        {
          "aggregate_version": 1,
          "key_id": "ciris-node-abc123",
          "pqc_key_id": "ciris-node-abc123-pqc",
          "ed25519_pubkey_b64": "ZWQyNTUxOXB1YmtleWJhc2U2NA==",
          "ml_dsa_65_pubkey_b64": "bWxkc2E2NXB1YmtleQ==",
          "reticulum_x25519_pubkey_b64": "cmV0eDI1NTE5",
          "reticulum_ed25519_pubkey_b64": "cmV0ZWQyNTUxOQ==",
          "content_x25519_pubkey_b64": "Y29udGVudHgyNTUxOQ==",
          "content_ml_kem_768_pubkey_b64": "bWxrZW03Njg=",
          "did_key": "did:key:z6Mkabc",
          "identity_hash": "deadbeefcafe",
          "evaluated_at_unix_ms": 1750000000000
        }
    """.trimIndent()

    private fun clientReturning(status: HttpStatusCode, body: String): FabricClient {
        val engine = MockEngine { _ ->
            respond(
                content = body,
                status = status,
                headers = headersOf(HttpHeaders.ContentType, "application/json"),
            )
        }
        val http = HttpClient(engine) { install(ContentNegotiation) { json(FabricClient.json) } }
        return FabricClient(baseUrl = "http://127.0.0.1:8080", httpClient = http)
    }

    @Test
    fun identity_decodes_full_six_key_aggregate() = runTest {
        val client = clientReturning(HttpStatusCode.OK, identityJson)
        val id = client.getIdentity()

        assertEquals("ciris-node-abc123", id.keyId)
        assertEquals(1, id.aggregateVersion)
        assertTrue(id.hasPqc, "ML-DSA-65 present → hasPqc")
        assertTrue(id.hasReticulum, "reticulum keys present")
        assertTrue(id.hasContentEncryption, "content keys present")
        assertEquals("did:key:z6Mkabc", id.didKey)
        assertEquals("deadbeefcafe", id.identityHash)
        assertEquals(1750000000000L, id.evaluatedAtUnixMs)
    }

    @Test
    fun identity_tolerates_minimal_non_pqc_node() = runTest {
        // A relay node with no PQC / content keys yet — optional fields omitted.
        val minimal = """
            {"aggregate_version":1,"key_id":"k","ed25519_pubkey_b64":"AAAA"}
        """.trimIndent()
        val client = clientReturning(HttpStatusCode.OK, minimal)
        val id = client.getIdentity()
        assertEquals("k", id.keyId)
        assertTrue(!id.hasPqc)
        assertTrue(!id.hasReticulum)
    }

    /**
     * **A split node's identity must not read as self-consistent.**
     *
     * On a node carrying an agent, `key_id` is the NODE's address while the
     * signing and content pubkeys are the ACTOR's. 0.5.195 shipped that
     * disagreement silently; 0.5.196 names it with `key_material_key_id`. This
     * client had `ignoreUnknownKeys = true`, so before these fields existed it
     * decoded the payload happily and DISCARDED the one signal that said the
     * pubkeys belong to someone else — leaving the shipped client in exactly
     * the ambiguous state the server change set out to end.
     */
    @Test
    fun splitNodeIdentityNamesWhoOwnsTheKeyMaterial() = runTest {
        val json = """
            {
              "aggregate_version": 1,
              "key_id": "ciris-node-bootstrap-peulxofzaj",
              "ed25519_pubkey_b64": "ZWQyNTUxOXB1YmtleWJhc2U2NA==",
              "key_material_key_id": "ciris-agent-bootstrap-mplbdbzbed",
              "node_key_id": "ciris-node-bootstrap-peulxofzaj",
              "actor_key_id": "ciris-agent-bootstrap-mplbdbzbed",
              "identity_type": "node"
            }
        """.trimIndent()
        val engine = MockEngine {
            respond(
                content = json,
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json"),
            )
        }
        val http = HttpClient(engine) { install(ContentNegotiation) { json() } }
        val identity = FabricClient(http, "http://node.test").getIdentity()

        assertEquals("ciris-node-bootstrap-peulxofzaj", identity.keyId)
        assertEquals("ciris-agent-bootstrap-mplbdbzbed", identity.keyMaterialKeyId)
        assertEquals("ciris-agent-bootstrap-mplbdbzbed", identity.actorKeyId)
        assertEquals("node", identity.identityType)
        assertTrue(
            identity.keyMaterialBelongsToAnotherKey,
            "the pubkeys are the actor's, so a consumer must not verify them against key_id",
        )
        assertTrue(identity.isSplitNode)
    }

    /**
     * An older server says nothing, and silence is UNKNOWN — not a mismatch.
     * A client that flagged every server without the field would cry wolf on
     * every deployment that has not upgraded.
     */
    @Test
    fun anOlderServerSilenceIsNotAMismatch() = runTest {
        val json = """
            {
              "aggregate_version": 1,
              "key_id": "ciris-node-abc123",
              "ed25519_pubkey_b64": "ZWQyNTUxOXB1YmtleWJhc2U2NA=="
            }
        """.trimIndent()
        val engine = MockEngine {
            respond(
                content = json,
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json"),
            )
        }
        val http = HttpClient(engine) { install(ContentNegotiation) { json() } }
        val identity = FabricClient(http, "http://node.test").getIdentity()

        assertEquals(null, identity.keyMaterialKeyId)
        assertTrue(!identity.keyMaterialBelongsToAnotherKey)
        assertTrue(!identity.isSplitNode)
    }
}
