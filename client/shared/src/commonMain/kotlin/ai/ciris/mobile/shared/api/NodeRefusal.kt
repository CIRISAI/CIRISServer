package ai.ciris.mobile.shared.api

/**
 * **A refusal the node TYPED**, carried to the UI without being flattened to a
 * sentence (CIRISServer#389).
 *
 * The auth surface's refusal body is `{error, reason_id}` — an English fallback
 * plus a stable id a client resolves in the reader's own language. Throwing a
 * plain `RuntimeException(error)` at the call site discards the id, which is the
 * whole point of the contract: `contacts.unknown_fed_id` and
 * `contacts.store_unavailable` both render as red text, and they have opposite
 * remedies (go admit the key vs. go look at the node).
 *
 * [reasonId] is the localization key. A screen resolves it and falls back to
 * [detail] — the server's English — when the bundle has no entry, which is the
 * designed degradation, not an error.
 */
class NodeRefusal(
    /** The node's `reason_id`, or null when the body carried none. */
    val reasonId: String?,
    /** The node's English `error` / `detail`, or null. */
    val detail: String?,
    /** The HTTP status that carried the refusal. */
    val statusCode: Int,
) : RuntimeException(detail ?: reasonId ?: "node refused ($statusCode)")
