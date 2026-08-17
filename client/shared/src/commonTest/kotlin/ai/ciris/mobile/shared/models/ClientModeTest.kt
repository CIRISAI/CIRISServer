package ai.ciris.mobile.shared.models

import ai.ciris.mobile.shared.api.parseNodeHealth
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * **The node-vs-agent gate must not latch the wrong way** (CIRISServer#390).
 *
 * The universal client derives its ONE node-vs-agent gate from
 * `/v1/system/health`, which since server 0.5.168 is the MERGED health: the
 * folded brain's `cognitive_state`/`services` over the node's own, plus the
 * THREE-state `data.agent.{folded,reachable}`. The live defect: the fold boots
 * the brain on a daemon thread AFTER the node composes, so a probe at READY can
 * see `folded=true / reachable=false` — a brain that EXISTS but has not bound
 * yet — and the client committed to NODE, hiding the 22 cognitive lights of the
 * very agent it was talking to for the whole session.
 *
 * `clientModeFrom` had ZERO coverage before this file. These pin the pure
 * derivation (no HTTP — the SetupExternalAuthTest pattern) and pin the Kotlin
 * `parseNodeHealth` read against the envelopes the Rust side emits
 * (`src/health.rs`, asserted by `tests/folded_health.rs`) — server-side those
 * tests prove the server EMITS the shape; this proves the client READS it.
 * Neither alone catches a rename.
 */
class ClientModeTest {

    // ─── The pure derivation ────────────────────────────────────────────────

    @Test
    fun a_bare_node_is_NODE_and_the_answer_is_final() {
        val probe = clientModeFrom(
            cognitiveState = null, serviceCount = 0,
            agentFolded = false, agentReachable = false,
        )
        assertEquals(ClientMode.NODE, probe.mode)
        assertFalse(
            probe.undetermined,
            "no brain is attached — NODE is a real verdict here, not a guess to retry",
        )
    }

    @Test
    fun a_folded_reachable_brain_with_a_cognitive_state_is_AGENT() {
        val probe = clientModeFrom(
            cognitiveState = "WORK", serviceCount = 2,
            agentFolded = true, agentReachable = true,
        )
        assertEquals(ClientMode.AGENT, probe.mode)
        assertFalse(probe.undetermined)
    }

    @Test
    fun a_folded_reachable_brain_with_only_a_service_map_is_still_AGENT() {
        // A brain may answer before its cognitive loop reports a state; a
        // non-empty service map alone already proves there is an agent.
        val probe = clientModeFrom(
            cognitiveState = null, serviceCount = 2,
            agentFolded = true, agentReachable = true,
        )
        assertEquals(ClientMode.AGENT, probe.mode)
        assertFalse(probe.undetermined)
    }

    @Test
    fun folded_but_unreachable_is_UNDETERMINED_the_caller_must_retry_not_latch_NODE() {
        // The live #390 defect state: brain attached, not answering (yet).
        // `mode` is NOT a verdict while `undetermined` is set — the caller's
        // contract is a bounded re-probe, and committing NODE here is exactly
        // the latch that hid the 22 cognitive lights for a whole session.
        val probe = clientModeFrom(
            cognitiveState = null, serviceCount = 0,
            agentFolded = true, agentReachable = false,
        )
        assertTrue(
            probe.undetermined,
            "a brain that EXISTS but is not answering is a third state, not a bare node",
        )
    }

    @Test
    fun the_two_arg_form_is_the_pre_0_5_168_derivation_and_is_always_final() {
        // No agent block on the wire ⇒ nothing to be undetermined about.
        assertEquals(ClientMode.NODE, clientModeFrom(null, 0))
        assertEquals(ClientMode.AGENT, clientModeFrom("WORK", 0))
        assertEquals(ClientMode.AGENT, clientModeFrom(null, 22))
    }

    // ─── parseNodeHealth pinned against the Rust emit (tests/folded_health.rs) ──
    //
    // The three states of `/v1/system/health` as `src/health.rs` builds them:
    // `node_health()` is always the base, `folded_health` adds `agent` and (when
    // the brain answers) merges its `cognitive_state`/`services` on top. The
    // brain halves below are copied verbatim from the Rust tests' `spawn_brain`
    // bodies, so a server-side rename breaks this file too.

    /** Rust: `a_bare_node_reports_no_agent_and_no_cognitive_state`. */
    private val bareNodeEnvelope = """
    {
      "data": {
        "status": "ok",
        "role": "fabric-node",
        "version": "0.5.176",
        "services": {},
        "conformance": { "build_profiles": ["node"], "declared_at": "/v1/federation/conformance" },
        "agent": { "folded": false, "reachable": false }
      }
    }
    """

    /**
     * Rust: `a_folded_brain_enriches_the_nodes_own_health` — the brain body
     * `{"status":"ok","cognitive_state":"WORK","services":{"llm":"ok","memory":"ok"}}`
     * merged over the node's own health, node halves (role/conformance) surviving.
     */
    private val foldedReachableEnvelope = """
    {
      "data": {
        "status": "ok",
        "role": "fabric-node",
        "version": "0.5.176",
        "services": { "llm": "ok", "memory": "ok" },
        "conformance": { "build_profiles": ["node"], "declared_at": "/v1/federation/conformance" },
        "cognitive_state": "WORK",
        "agent": { "folded": true, "reachable": true }
      }
    }
    """

    /** Rust: `an_unreachable_brain_is_distinguished_from_no_brain`. */
    private val foldedUnreachableEnvelope = """
    {
      "data": {
        "status": "ok",
        "role": "fabric-node",
        "version": "0.5.176",
        "services": {},
        "conformance": { "build_profiles": ["node"], "declared_at": "/v1/federation/conformance" },
        "agent": { "folded": true, "reachable": false }
      }
    }
    """

    @Test
    fun parse_bare_node_envelope_reads_NODE_with_no_agent_block_claimed() {
        val h = parseNodeHealth(bareNodeEnvelope)
        assertEquals("ok", h.status)
        assertEquals("fabric-node", h.role)
        assertEquals("0.5.176", h.version)
        assertEquals(null, h.cognitiveState)
        assertEquals(0, h.serviceCount)
        assertFalse(h.agentFolded)
        assertFalse(h.agentReachable)

        val probe = clientModeFrom(h.cognitiveState, h.serviceCount, h.agentFolded, h.agentReachable)
        assertEquals(ClientMode.NODE, probe.mode)
        assertFalse(probe.undetermined)
    }

    @Test
    fun parse_folded_reachable_envelope_reads_AGENT_and_keeps_the_node_half() {
        val h = parseNodeHealth(foldedReachableEnvelope)
        // The agent half arrived...
        assertEquals("WORK", h.cognitiveState)
        assertEquals(2, h.serviceCount)
        assertTrue(h.agentFolded)
        assertTrue(h.agentReachable)
        // ...and the node's own half survived the merge (the Rust test's
        // "union, not a redirect" assertion, read from this side of the wire).
        assertEquals("ok", h.status)
        assertEquals("fabric-node", h.role)
        assertEquals("0.5.176", h.version)

        assertEquals(
            ClientMode.AGENT,
            clientModeFrom(h.cognitiveState, h.serviceCount, h.agentFolded, h.agentReachable).mode,
        )
    }

    @Test
    fun parse_folded_unreachable_envelope_is_undetermined_not_a_bare_node() {
        val h = parseNodeHealth(foldedUnreachableEnvelope)
        assertEquals(null, h.cognitiveState)
        assertTrue(h.agentFolded, "a configured brain is FOLDED even when it is not answering")
        assertFalse(h.agentReachable, "…and unreachable, which is a different fact from 'there is no brain'")

        val probe = clientModeFrom(h.cognitiveState, h.serviceCount, h.agentFolded, h.agentReachable)
        assertTrue(probe.undetermined, "the client must retry, never latch NODE on this envelope")
    }

    @Test
    fun parse_tolerates_a_bare_object_without_the_data_envelope() {
        // Verbatim from Rust `a_brain_answering_without_the_data_envelope_still_contributes`
        // (tests/folded_health.rs:146): the server merge tolerates this shape
        // (`brain.get("data").unwrap_or(&brain)`), and the client parse mirrors
        // that tolerance — being strict over a shape difference would
        // reintroduce the same outcome, a real agent rendered as a bare node.
        val h = parseNodeHealth("""{ "status": "ok", "cognitive_state": "DREAM" }""")
        assertEquals("ok", h.status)
        assertEquals("DREAM", h.cognitiveState)
        assertEquals(ClientMode.AGENT, clientModeFrom(h.cognitiveState, h.serviceCount))
    }

    // ─── The version-mismatch banner ────────────────────────────────────────

    @Test
    fun version_mismatch_never_fires_on_an_unknown_node_version() {
        assertFalse(isVersionMismatch(null, "0.5.176"))
        assertFalse(isVersionMismatch("", "0.5.176"))
        assertFalse(isVersionMismatch("   ", "0.5.176"))
    }

    @Test
    fun version_mismatch_ignores_the_v_prefix() {
        assertFalse(isVersionMismatch("v0.5.176", "0.5.176"))
    }

    @Test
    fun version_mismatch_fires_on_a_real_difference() {
        assertTrue(isVersionMismatch("0.5.175", "0.5.176"))
    }
}
