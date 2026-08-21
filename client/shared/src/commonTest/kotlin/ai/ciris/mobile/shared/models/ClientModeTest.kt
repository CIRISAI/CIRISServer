package ai.ciris.mobile.shared.models

// NODE VENDOR DRIFT #29 (restored after the 2.9.28 re-vendor dropped it):
// the parseNodeHealth envelope pins below read the restored wire parse
// (CIRISApiClient.kt, NODE VENDOR DRIFT #26).
import ai.ciris.mobile.shared.api.parseNodeHealth
import kotlin.test.Test
import kotlin.test.assertEquals
// Vendor drift #23: used by the restored node-mode assertions below.
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * **A half-started brain is not an agent** (CIRISAgent#1075).
 *
 * [clientModeFrom] is the ONE node-vs-agent gate. Everything that must not call
 * an AGENT-only endpoint keys off it — the shared API client is handed the
 * result so every poller stops at once.
 *
 * It used to read a non-null `cognitive_state` as proof of an agent. A brain
 * with no config starts 10 of its 22 services to serve the setup wizard and
 * reports `cognitive_state = "SETUP"` throughout, so the client ran the full
 * AGENT UI against a runtime with no telemetry, no audit and no LLM bus. On a
 * live macOS install that produced a 503 per poll, every 3 seconds, with a Java
 * stack trace each time — including on `addLlmProvider`, so the user could not
 * configure their way out of it.
 *
 * The first attempted fix keyed on `serviceCount == 0` and was INERT: the count
 * comes from the `services` map in `/v1/system/health`, which during first-run
 * holds the 10 that ARE running. These cases pin the real signal — the brain's
 * own answer about whether it is configured — so that mistake cannot return.
 */
class ClientModeTest {

    @Test
    fun setup_state_brain_with_no_config_is_NODE_not_AGENT() {
        assertEquals(
            ClientMode.NODE,
            clientModeFrom(cognitiveState = "SETUP", serviceCount = 10, brainUnconfigured = true),
            "a brain running its 10 first-run services has no telemetry, audit or LLM bus — " +
                "running the AGENT UI against it is what produced the 503 storm",
        )
    }

    @Test
    fun service_count_alone_must_not_decide_it() {
        // The exact shape of the inert fix: SETUP, but the wizard's services are
        // up, so any check of the form `serviceCount == 0` never fires.
        assertEquals(
            ClientMode.NODE,
            clientModeFrom("SETUP", serviceCount = 10, brainUnconfigured = true),
            "first-run reports a NON-ZERO service count; a gate keyed on zero is dead code",
        )
    }

    @Test
    fun a_configured_agent_in_SETUP_is_still_an_AGENT() {
        // Mid-boot on a configured install: cognitive_state is SETUP but the brain
        // HAS config, so it is a real agent coming up and must not be demoted.
        assertEquals(
            ClientMode.AGENT,
            clientModeFrom("SETUP", serviceCount = 22, brainUnconfigured = false),
            "SETUP alone must not demote a configured agent — only the brain's own " +
                "'I am not configured' may",
        )
    }

    @Test
    fun a_working_agent_is_an_AGENT() {
        assertEquals(ClientMode.AGENT, clientModeFrom("WORK", serviceCount = 22))
        assertEquals(ClientMode.AGENT, clientModeFrom("DREAM", serviceCount = 22))
    }

    @Test
    fun a_bare_node_is_a_NODE() {
        // The canonical node health envelope: role fabric-node, no cognitive_state,
        // empty service map.
        assertEquals(ClientMode.NODE, clientModeFrom(cognitiveState = null, serviceCount = 0))
    }

    @Test
    fun a_service_map_alone_still_proves_an_agent() {
        // An agent that reports services but no cognitive_state stays AGENT — this
        // path predates the fix and must not regress.
        assertEquals(ClientMode.AGENT, clientModeFrom(cognitiveState = null, serviceCount = 22))
    }

    @Test
    fun an_unreachable_setup_probe_does_not_downgrade_a_real_agent() {
        // The call site defaults brainUnconfigured to false when the probe fails,
        // so a transient setup-status outage must never demote a live agent to
        // NODE and blank its UI.
        assertEquals(
            ClientMode.AGENT,
            clientModeFrom("WORK", serviceCount = 22, brainUnconfigured = false),
        )
    }

    // ─── Vendor drift #23: the node half of this file (CIRISServer#390) ─────
    //
    // The CIRISAgent v2.9.28 re-vendor dropped every node-mode assertion this
    // file carried. The subset that survives the CURRENT `clientModeFrom` API
    // was restored first, below. The rest — the folded-brain THREE-state probe
    // and the `parseNodeHealth` envelope pins — had to wait for commonMain:
    // the same re-vendor removed BOTH APIs. They are back (NODE VENDOR DRIFT
    // #26 in CIRISApiClient.kt, #27 in ClientMode.kt), and so are their tests
    // (NODE VENDOR DRIFT #29, further down).

    @Test
    fun a_bare_node_is_NODE_and_either_agent_signal_alone_is_AGENT() {
        // A node reports NEITHER half of the agent enrichment, so it is NODE —
        // the verdict the whole node-mode UI keys off. Either half ALONE is
        // already an agent: a cognitive_state with an empty service map (a
        // brain that answered before its service map filled), or a service map
        // with no cognitive_state.
        assertEquals(ClientMode.NODE, clientModeFrom(null, 0))
        assertEquals(ClientMode.AGENT, clientModeFrom("WORK", 0))
        assertEquals(ClientMode.AGENT, clientModeFrom(null, 22))
    }

    // ─── NODE VENDOR DRIFT #29: the folded-brain THREE-state probe ─────────
    //
    // (restored after the 2.9.28 re-vendor dropped it — CIRISServer#390.)
    //
    // A CIRIS node can have (1) no brain, (2) a brain that is folded and
    // answering, (3) a brain attached but NOT answering. Three facts, three
    // fixes. The re-vendor's two-state view collapsed (3) into (1), so a
    // folded agent read as a bare node and the client hid the 22 cognitive
    // lights of the very agent it was talking to. `mode` is NOT a verdict
    // while `undetermined` is set.

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
    fun the_two_axes_compose_a_half_started_brain_that_ANSWERED_is_still_NODE() {
        // NODE VENDOR DRIFT #29 + CIRISAgent#1075: the two restorations meet
        // here. An answering folded brain is normally AGENT, but a brain that
        // said "I hold no config" is the wizard, not an agent — and because it
        // SPOKE to say so, that NODE is final, not a state to retry.
        val probe = clientModeFrom(
            cognitiveState = "SETUP", serviceCount = 10,
            agentFolded = true, agentReachable = true,
            brainUnconfigured = true,
        )
        assertEquals(ClientMode.NODE, probe.mode)
        assertFalse(probe.undetermined, "the brain answered — there is nothing left to retry")
    }

    // ─── NODE VENDOR DRIFT #29: parseNodeHealth pinned against the Rust emit ──
    //
    // (restored after the 2.9.28 re-vendor dropped it — tests/folded_health.rs.)
    //
    // The three states of `/v1/system/health` as `src/health.rs` builds them:
    // `node_health()` is always the base, `folded_health` adds `agent` and (when
    // the brain answers) merges its `cognitive_state`/`services` on top. The
    // brain halves below are copied verbatim from the Rust tests' `spawn_brain`
    // bodies, so a server-side rename breaks this file too. Server-side those
    // tests prove the server EMITS the shape; these prove the client READS it.
    // Neither alone catches a rename.

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
    //
    // Vendor drift #23: `isVersionMismatch` drives the node-vs-client
    // VERSION-MISMATCH banner and has no other coverage in commonTest; the
    // re-vendor removed its only three tests. Restored verbatim — the API is
    // unchanged in the current ClientMode.kt.

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
