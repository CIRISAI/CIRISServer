package ai.ciris.mobile.shared.models

/**
 * The ONE node-vs-agent gate for the universal client.
 *
 * The same app runs against either:
 *   - a bare **ciris-server node** (no AI/brain)            → [NODE]
 *   - a full **CIRIS agent** (ciris-server + cognitive brain) → [AGENT]
 *
 * NODE VENDOR DRIFT #27 (restored after the 2.9.28 re-vendor dropped it): the
 * THREE-state folded-brain verdict (CIRISServer#390). Upstream's two-state
 * account of this gate is restored to ours below; upstream's `brainUnconfigured`
 * demotion (CIRISAgent#1075) is KEPT and composed with it.
 *
 * This is the single source of truth: it is derived from the server capability
 * probe (see [clientModeFrom]) after the server is reachable — at startup, and
 * again on every node switch — held as app/startup state in `CIRISApp`, and
 * read everywhere that must branch on node-vs-agent (the 22 cognitive service
 * lights, "agent" wording in login/status/startup, the WORK-state wait). Do NOT
 * scatter ad-hoc probes — everything keys off this gate.
 *
 * Canonical signal (see `src/health.rs` server-side, CIRISServer#390): since
 * server 0.5.168 `/v1/system/health` is the node's health MERGED with the
 * folded brain's — a bare node serves
 * `{"data":{"status":"ok","role":"fabric-node","services":{},"agent":{"folded":false,…}}}`
 * with **no `cognitive_state`**; a folded brain's `cognitive_state` + service
 * map are merged on top, and `data.agent.{folded,reachable}` carries the
 * THREE-state verdict. AGENT iff the server reports a `cognitive_state`, a
 * non-empty agent service map, or an answering folded brain; NODE otherwise —
 * unless the brain is folded-but-not-answering, which is UNDETERMINED (see
 * [ModeProbe]) and must be retried, never latched. A brain that answers but
 * says it is still unconfigured is NODE either way (CIRISAgent#1075).
 */
enum class ClientMode {
    /** Bare ciris-server node — no cognitive brain, no 22-service map. */
    NODE,

    /** Full CIRIS agent — ciris-server + cognitive brain (reports cognitive_state). */
    AGENT;

    val isAgent: Boolean get() = this == AGENT
    val isNode: Boolean get() = this == NODE
}

/**
 * NODE VENDOR DRIFT #27 (restored after the 2.9.28 re-vendor dropped it).
 *
 * A mode derivation that can say "not yet" ([undetermined]) without growing the
 * two-valued [ClientMode] enum — 20+ call sites branch on NODE-vs-AGENT and a
 * third enum value would force every one of them to answer a question they
 * cannot. [undetermined] is a RETRY signal, not a verdict: the caller must
 * re-probe (bounded) and must NOT latch [mode] as final while it is set.
 */
data class ModeProbe(val mode: ClientMode, val undetermined: Boolean)

/**
 * Derive the [ClientMode] from a probed `/v1/system/health` snapshot. AGENT iff
 * the server reports a `cognitive_state` (the agent enrichment) OR a non-empty
 * agent service map; otherwise a bare NODE.
 *
 * A brain that has not completed setup is NODE regardless of what it reports —
 * see [brainUnconfigured].
 *
 * This is the TWO-QUESTION-FREE form: it answers only "is this an agent?" and
 * its answer is final. Surfaces that carry `data.agent.{folded,reachable}` — the
 * node's merged health since server 0.5.168 — should call the [ModeProbe]
 * overload instead, which can additionally say "a brain exists but has not
 * answered yet" (CIRISServer#390). Kept as the plain-[ClientMode] entry point so
 * every existing call site (`CIRISApp`'s startup gate, the `getSystemStatus`
 * fallback, the pre-0.5.168 wire shape) compiles and behaves unchanged.
 *
 * @param cognitiveState the `cognitive_state` field (null when absent — the node case).
 * @param serviceCount the agent service count reported in the health envelope (0 on a node).
 * @param brainUnconfigured the brain says it still needs setup and holds no config,
 *   so its 10 first-run services are the wizard's, not an agent's. Only the brain
 *   knows this; the health envelope alone cannot distinguish it from a real agent.
 */
fun clientModeFrom(
    cognitiveState: String?,
    serviceCount: Int,
    brainUnconfigured: Boolean = false,
): ClientMode =
    when {
        // A HALF-STARTED BRAIN IS NOT AN AGENT (CIRISAgent#1075).
        //
        // A brain with no config starts 10 of its 22 services — enough to serve
        // the setup wizard, not enough to be an agent. It still reports a
        // `cognitive_state` of "SETUP", and that non-null value was taken as
        // proof of an agent, so the client ran the full AGENT UI against a
        // runtime missing telemetry, audit and the LLM bus. Every AGENT-only
        // poller then hammered services that do not exist:
        //
        //     listAdapters      503
        //     getAuditEntries   503   (every 3s, with a full stack trace each)
        //     getLlmBusStatus   503
        //     getLlmProviders   503
        //     addLlmProvider    503   <- so the user could not configure an escape
        //
        // This gate exists precisely to stop AGENT-only pollers firing at a
        // server that cannot answer them — its call site says so. It just had no
        // way to know that SETUP is not readiness.
        //
        // KEYED ON THE BRAIN'S OWN SETUP STATE, NOT ON SERVICE COUNT. The first
        // version of this check tested `serviceCount == 0`, which never fires:
        // the count is derived from the `services` map in /v1/system/health, and
        // during first-run that map holds the 10 that ARE running. Only the brain
        // can say whether it is configured, so the caller asks it and passes the
        // answer in.
        brainUnconfigured -> ClientMode.NODE
        cognitiveState != null || serviceCount > 0 -> ClientMode.AGENT
        else -> ClientMode.NODE
    }

/**
 * NODE VENDOR DRIFT #27 (restored after the 2.9.28 re-vendor dropped it):
 * the THREE-state derivation, now composed with upstream's `brainUnconfigured`.
 *
 * Server 0.5.168 (CIRISServer#390) made the NODE's `/v1/system/health` the
 * UNION of both meanings: the brain's `cognitive_state`/`services` are merged
 * over the node's own health, plus `data.agent.{folded,reachable}` — THREE
 * states, not two. "No brain attached" and "a brain is attached and did not
 * answer" are different facts with different fixes, and before the split both
 * rendered as a bare NODE, hiding the 22 cognitive lights of the very agent
 * the client was talking to.
 *
 *   - AGENT iff a `cognitive_state` arrived, the agent service map is
 *     non-empty, or a folded brain ANSWERED (folded && reachable — a brain
 *     that answers is an agent even if its health omitted the usual fields).
 *   - [ModeProbe.undetermined] iff `folded && !reachable`: a brain EXISTS but
 *     is not answering yet. The fold boots the brain on a daemon thread AFTER
 *     the node composes, so an early probe legitimately lands here — the
 *     caller must retry, never commit NODE.
 *
 * TWO QUESTIONS, TWO PARAMETER GROUPS. The folded/reachable pair answers "is a
 * brain attached, and is it talking?"; [brainUnconfigured] answers "did that
 * brain say it is still a setup wizard?" — the axis this overload inherits from
 * the three-argument form above rather than re-deciding. When set it wins
 * outright: the brain ANSWERED (that is the only way a caller can learn it), so
 * NODE is a real verdict and there is nothing to retry, even if a stale
 * `reachable=false` arrived in the same breath.
 *
 * [agentFolded]/[agentReachable] deliberately carry NO defaults: that is what
 * keeps this overload and the plain-[ClientMode] one unambiguous — a call with
 * three or fewer arguments is the [ClientMode] form, four or more is this one.
 *
 * @param cognitiveState the `cognitive_state` field (null when absent — the node case).
 * @param serviceCount the agent service count reported in the health envelope (0 on a node).
 * @param agentFolded `data.agent.folded` — a brain is configured on this node
 *        (false when absent, which is also the pre-0.5.168 wire shape).
 * @param agentReachable `data.agent.reachable` — the folded brain answered the
 *        node's own health probe.
 * @param brainUnconfigured as above (CIRISAgent#1075) — the brain's own answer
 *        that it holds no config. Defaults false: a caller that cannot ask must
 *        not downgrade a live agent.
 */
fun clientModeFrom(
    cognitiveState: String?,
    serviceCount: Int,
    agentFolded: Boolean,
    agentReachable: Boolean,
    brainUnconfigured: Boolean = false,
): ModeProbe {
    // A folded brain that ANSWERED is an agent even if its health omitted the
    // usual fields — unless it answered "I am not configured yet".
    val answeringFold = agentFolded && agentReachable && !brainUnconfigured
    return ModeProbe(
        mode = if (answeringFold) {
            ClientMode.AGENT
        } else {
            clientModeFrom(cognitiveState, serviceCount, brainUnconfigured)
        },
        undetermined = agentFolded && !agentReachable && !brainUnconfigured,
    )
}

/**
 * The client build version, used for the node-vs-client VERSION-MISMATCH banner.
 *
 * AUTHORITATIVE in committed source and kept in lockstep with the release
 * version (Cargo.toml `[package].version`) by `scripts/sync-client-version.sh`
 * — the pre-commit hook runs it on a version-bump commit, and CI runs it with
 * `--check` (build-wheels.yml) and FAILS on drift. CI never edits this at build
 * time: it is a `const val` in the foundational commonMain module, so mutating
 * it recompiled the whole Compose client and defeated the desktop-JAR gradle
 * cache every leg (CIRISServer#272). Do not hand-edit — run the script.
 *
 * NODE VENDOR DRIFT #27 (restored after the 2.9.28 re-vendor dropped it): the
 * paragraph below. DOWNSTREAM (CIRISAgent, which vendors this file) the rule is
 * different: there is no Cargo.toml there, so the value must equal the
 * `ciris-server==` pin in requirements.txt and the matching Android gradle pin.
 * Nothing enforced that and it drifted — the app showed a VERSION-MISMATCH
 * banner against the node it ships with — so they added
 * `tools/dev/check_version_alignment.py`. Their comment asserting "IN THIS REPO
 * there is no sync script" is true there and FALSE here; do not let it travel
 * back with a vendor sync (it did, in 2.9.28).
 */
const val CLIENT_VERSION = "0.5.187"

/**
 * Whether [nodeVersion] differs materially from [CLIENT_VERSION] — i.e. a
 * non-blocking "update recommended" banner should be shown. Compares the
 * leading `major.minor.patch` (ignoring any pre-release/build suffix) and only
 * flags an actual mismatch (never flags when the node version is unknown/blank).
 */
fun isVersionMismatch(nodeVersion: String?, clientVersion: String = CLIENT_VERSION): Boolean {
    val node = nodeVersion?.trim()?.removePrefix("v")?.takeWhile { it.isDigit() || it == '.' }
    if (node.isNullOrBlank()) return false
    val client = clientVersion.trim().removePrefix("v").takeWhile { it.isDigit() || it == '.' }
    return node != client
}
