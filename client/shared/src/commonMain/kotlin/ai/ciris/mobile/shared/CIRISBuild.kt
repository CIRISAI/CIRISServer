package ai.ciris.mobile.shared

/**
 * Build-time facts about the CIRIS app.
 *
 * # `HAS_AGENT` is gone — the gate is the PROBE now (CIRISServer#479)
 *
 * This object used to carry `const val HAS_AGENT`, and agent-only surfaces were
 * eliminated at COMPILE time: the node client shipped without them, the agent
 * repo vendored the same file and flipped the flag. That made the flavor a
 * property of the ARTIFACT, and it was wrong in both directions:
 *
 *  - a node that later gained a brain kept the node UX until someone
 *    reinstalled a different build (CIRISServer#479 is exactly this report);
 *  - and the packaging had to ship two ~63 MiB desktop bundles to say one
 *    thing, which does not fit in one wheel.
 *
 * An agent IS a node that has had a brain added, so the question "are the agent
 * surfaces live?" is about the ATTACHED NODE and has to be asked at runtime.
 * The answer is the probed [ai.ciris.mobile.shared.models.ClientMode] —
 * `data.agent.{folded,reachable}` from the merged `/v1/system/health`
 * (CIRISServer#390) — threaded as `hasAgent` into the surfaces that branch on
 * it: the landing screen, the epistemic nav groups, and the setup step flow.
 *
 * The flag is DELETED rather than deprecated on purpose. A build constant that
 * nothing reads is the CIRISServer#365 shape (nine `mesh_config` keys, zero
 * consumers), and leaving this one in place would invite the next
 * compile-time branch — which is the thing that has to stop being possible.
 *
 * Every default is NODE-first: a surface that has not yet learned the answer
 * shows the node behaviour, because revealing agent affordances on a brainless
 * node is the wrong guess that costs something, while the reverse merely
 * arrives a moment late.
 */
object CIRISBuild
