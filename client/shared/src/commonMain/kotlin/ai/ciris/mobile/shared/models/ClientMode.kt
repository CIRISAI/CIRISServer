package ai.ciris.mobile.shared.models

/**
 * The ONE node-vs-agent gate for the universal client.
 *
 * The same app runs against either:
 *   - a bare **ciris-server node** (no AI/brain)            → [NODE]
 *   - a full **CIRIS agent** (ciris-server + cognitive brain) → [AGENT]
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
 * [ModeProbe]) and must be retried, never latched.
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
 * A mode derivation that can say "not yet" ([undetermined]) without growing the
 * two-valued [ClientMode] enum — 20+ call sites branch on NODE-vs-AGENT and a
 * third enum value would force every one of them to answer a question they
 * cannot. [undetermined] is a RETRY signal, not a verdict: the caller must
 * re-probe (bounded) and must NOT latch [mode] as final while it is set.
 */
data class ModeProbe(val mode: ClientMode, val undetermined: Boolean)

/**
 * Derive the node-vs-agent verdict from a probed `/v1/system/health` snapshot.
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
 * @param cognitiveState the `cognitive_state` field (null when absent — the node case).
 * @param serviceCount the agent service count reported in the health envelope (0 on a node).
 * @param agentFolded `data.agent.folded` — a brain is configured on this node
 *        (false when absent, which is also the pre-0.5.168 wire shape).
 * @param agentReachable `data.agent.reachable` — the folded brain answered the
 *        node's own health probe.
 */
fun clientModeFrom(
    cognitiveState: String?,
    serviceCount: Int,
    agentFolded: Boolean = false,
    agentReachable: Boolean = false,
): ModeProbe {
    val agent = cognitiveState != null || serviceCount > 0 || (agentFolded && agentReachable)
    return ModeProbe(
        mode = if (agent) ClientMode.AGENT else ClientMode.NODE,
        undetermined = agentFolded && !agentReachable,
    )
}

/**
 * Two-argument form for the pre-0.5.168 surfaces that carry no `agent` block
 * (the brain's own health, `getSystemStatus`). Same derivation, and the answer
 * is final by construction — with no folded/unreachable axis there is nothing
 * to be undetermined about, so this stays a plain [ClientMode] and existing
 * call sites compile unchanged.
 */
fun clientModeFrom(cognitiveState: String?, serviceCount: Int): ClientMode =
    clientModeFrom(cognitiveState, serviceCount, agentFolded = false, agentReachable = false).mode

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
 * DOWNSTREAM (CIRISAgent, which vendors this file) the rule is different: there
 * is no Cargo.toml there, so the value must equal the `ciris-server==` pin in
 * requirements.txt and the matching Android gradle pin. Nothing enforced that
 * and it drifted — the app showed a VERSION-MISMATCH banner against the node it
 * ships with — so they added `tools/dev/check_version_alignment.py`. Their
 * comment asserting "IN THIS REPO there is no sync script" is true there and
 * FALSE here; do not let it travel back with a vendor sync.
 */
const val CLIENT_VERSION = "0.5.184"

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
