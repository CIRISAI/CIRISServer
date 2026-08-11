package ai.ciris.mobile.shared.models

import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The tier-4 de-admit wire contract for the refusal an operator is most likely
 * to meet, pinned against the body `CIRISServer/src/admin_ops.rs` actually
 * builds (`de_admit` + `DeAdmitFailure`).
 *
 * # Why this file exists
 *
 * persist v30.10.0 made revoking someone else's key require the `slash` duty
 * conferred by a trust root this node accepts (CIRISPersist#596 item 1), and
 * CIRISServer#383's 61 leaked QA keys are blocked on precisely that grant. So
 * the FIRST thing a real operator will see from this route is a refusal — and
 * before the server change that paired with this test, it arrived as a Rust
 * debug string in one locale, naming no remedy.
 *
 * The distinction being pinned is the one this codebase keeps re-learning:
 * **`refused` and `error` are different answers.** `refused` means the substrate
 * was asked and said no; `error` means it never answered. They point an operator
 * in opposite directions — go get a grant, versus go debug a node — and a client
 * that renders them alike sends people to fix a healthy machine.
 *
 * Server-side, `tests/admin_ops.rs::tier_4_deadmit_…` asserts the server EMITS
 * this shape. This asserts the client READS it. Neither test alone catches a
 * rename, which is the failure mode: a DTO that parses cleanly while silently
 * dropping the field that carried the meaning.
 */
class DeadmitRefusalWireTest {

    private val json = Json { ignoreUnknownKeys = true; isLenient = true }

    /**
     * `POST /v1/admin/deadmit`, 200 — the act was NOT performed. A 200 with a
     * refused target is deliberate: the ladder call itself succeeded, and the
     * per-target verdict is data, not an exception.
     */
    private val deadmitRefused200 = """
    {
      "op": "de_admission",
      "tier": 4,
      "source_locale": "en",
      "selection_hash": "9f2b1c0d4e6a8b3c5d7e9f0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e",
      "revoked_after": "2026-08-01T00:00:00+00:00",
      "results": [
        {
          "target_key_id": "leaked-qa-key-01",
          "outcome": "refused",
          "reason": "federation_delegated_scope_unauthorized",
          "message": {
            "id": "admin.deadmit.refused.no_slash_grant",
            "text": "This node is not authorised to de-admit someone else's key. Revoking a key that is not your own is a moderation act, and it needs the `slash` duty granted to this node by a trust root it accepts. Nothing was changed. Ask an accord holder to delegate `slash` for federation duties to this node, then run the same selection again — the preview hash still applies."
          },
          "error": "DelegatedScopeUnauthorized { signer: \"node-a-omff5xbiyl\", on_behalf_of: \"leaked-qa-key-01\", scope: \"slash\" }"
        }
      ]
    }
    """

    @Test
    fun a_deadmit_refusal_keeps_its_token_its_localizable_text_and_its_detail() {
        val parsed = json.decodeFromString<AdminOpResponse>(deadmitRefused200)
        assertEquals(4, parsed.tier)

        val target = parsed.results.single()
        assertEquals("leaked-qa-key-01", target.targetKeyId)

        // `refused`, NOT `error` — the substrate answered a question about
        // authority. This is the whole point of the pin.
        assertEquals("refused", target.outcome)

        // The stable persist token survives to the client rather than being
        // flattened into prose a UI would have to string-match.
        assertEquals("federation_delegated_scope_unauthorized", target.reason)

        // The localizable pair, which is what the operator actually reads. The
        // `id` is what carries it into the other 28 languages; text alone would
        // pin the English and localize nothing.
        val message = assertNotNull(target.message)
        assertEquals("admin.deadmit.refused.no_slash_grant", message.id)
        val text = assertNotNull(message.text)
        assertTrue(
            text.contains("slash") && text.contains("accord holder"),
            "the refusal must name the REMEDY, not merely the denial: $text",
        )
        assertTrue(
            text.contains("Nothing was changed"),
            "a refused de-admission must say it changed nothing — an operator " +
                "who assumes a partial write will go hunting for one: $text",
        )

        // The substrate's own words stay available for the debug pane, ADDITIVE
        // to the localized text rather than instead of it.
        assertTrue(
            assertNotNull(target.error).contains("slash"),
            "the raw detail is kept for debugging",
        )

        // And nothing was minted: a refusal must not carry a revocation id, or a
        // UI would report the act as done.
        assertEquals(null, target.revocationId)
    }

    /**
     * The success arm of the same route, so the two are pinned against each
     * other. A test that only ever saw the refusal could not tell a route that
     * refuses correctly from one that refuses always.
     */
    private val deadmitRevoked200 = """
    {
      "op": "de_admission",
      "tier": 4,
      "results": [
        {
          "target_key_id": "leaked-qa-key-01",
          "outcome": "revoked",
          "revocation_id": "rev-0f1e2d3c",
          "event_id": "evt-4b5a6978"
        }
      ]
    }
    """

    @Test
    fun a_performed_deadmit_carries_a_revocation_id_and_no_refusal() {
        val target = json.decodeFromString<AdminOpResponse>(deadmitRevoked200).results.single()
        assertEquals("revoked", target.outcome)
        assertEquals("rev-0f1e2d3c", target.revocationId)
        assertEquals(null, target.reason)
        assertEquals(null, target.message)
        assertEquals(null, target.error)
    }
}
