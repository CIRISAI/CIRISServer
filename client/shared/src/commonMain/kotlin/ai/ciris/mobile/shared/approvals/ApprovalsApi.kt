package ai.ciris.mobile.shared.approvals

import ai.ciris.mobile.shared.api.CIRISApiClient
import ai.ciris.mobile.shared.api.DeferralData
import ai.ciris.mobile.shared.api.ResolveDeferralData
import ai.ciris.mobile.shared.api.TicketData
import ai.ciris.mobile.shared.api.WAStatusData
import ai.ciris.mobile.shared.platform.PlatformLogger

/**
 * The narrow API surface the approval screen needs.
 *
 * Extracted as an interface for one reason: [ai.ciris.mobile.shared.viewmodels.WiseAuthorityViewModel]
 * previously took the concrete 12k-line [CIRISApiClient], which made its logic
 * — new-approval detection, the ≤-requested constraint, error and
 * permission-denied handling — untestable. A HITL gate whose behaviour cannot
 * be asserted is not a control.
 */
interface ApprovalsApi {

    /** WA service health + the pending-deferral count. */
    suspend fun fetchWAStatus(): WAStatusData

    /** Pending Wisdom-Based Deferrals. */
    suspend fun fetchDeferrals(): List<DeferralData>

    /**
     * Resolve a deferral.
     * @param resolution must be one of `approve` / `reject` / `modify` —
     *   the server validates against `^(approve|reject|modify)$`. Use
     *   [ApprovalDecision.wireResolution] rather than a literal.
     */
    suspend fun resolveDeferral(deferralId: String, resolution: String, guidance: String): ResolveDeferralData

    /**
     * Tickets the agent proposed and cannot itself start — `status=blocked`
     * carrying `metadata.__proposal__`.
     *
     * Implementations must return an empty list (not throw) when the server
     * has **no tickets API at all**, so a deployment without it still shows
     * deferrals. Every other failure — expired token, server error, network
     * blip, unparseable body — must throw. "Empty" and "unknown" are different
     * facts about a blocked agent, and only one of them may clear the card,
     * the badge and the notification path.
     */
    suspend fun fetchProposals(): List<TicketData>

    /**
     * Full budget state for one ticket, including remaining trust headroom.
     * Returns null when the server does not expose it — headroom enhances the
     * approval dialog, it is never a precondition for showing it.
     */
    suspend fun fetchTicketBudget(ticketId: String): TicketBudgetState?

    /**
     * Issue a budget envelope against a proposal ticket.
     *
     * A grant above the agent's request is permitted but must have been
     * confirmed by a human first — see [BudgetApprovalSeam.validateGrant]. The
     * over-grant *marking* is not passed here: the server derives it and carries
     * it inside the signed payload, which is the only version of that fact worth
     * having.
     */
    suspend fun grantBudget(
        ticketId: String,
        amount: String,
        currency: String,
        purpose: String,
        expiresInHours: Int,
    ): BudgetGrantOutcome

    /**
     * Move a ticket to a new status. Promotion (`blocked` → `pending`) is what
     * actually starts the work; granting a budget does not.
     */
    suspend fun updateTicketStatus(ticketId: String, status: String, notes: String?): Boolean
}

/**
 * Production [ApprovalsApi] — a thin adapter over [CIRISApiClient].
 *
 * Deliberately contains no policy: every decision (what counts as a proposal,
 * what the ≤ constraint is, how errors map) lives in [BudgetApprovalSeam] or
 * the ViewModel, so this class stays a mechanical translation.
 */
class CIRISApprovalsApi(private val client: CIRISApiClient) : ApprovalsApi {

    private companion object {
        const val TAG = "CIRISApprovalsApi"

        /**
         * Statuses that mean *the feature is not in this build of the server*,
         * as opposed to *this request failed*. 404/405 are what a router that
         * has never heard of `/v1/tickets` answers; 501 is what one that knows
         * the route and refuses to implement it answers.
         *
         * 401/403 are deliberately **not** here: an expired token is a failure
         * to read the proposals, not proof there are none.
         */
        val UNSUPPORTED_ENDPOINT_STATUSES = setOf(404, 405, 501)

        /**
         * [CIRISApiClient] renders a non-2xx as `RuntimeException("API error:
         * HTTP <code>")`; Ktor's own `ResponseException` messages read
         * `... invalid: <code> <reason>`. Both shapes are matched here rather
         * than in the client, because only this caller knows which codes mean
         * "absent feature" — the client has no business deciding that for
         * every one of its ~70 call sites.
         */
        val HTTP_STATUS_IN_MESSAGE = Regex("""(?:HTTP|invalid:)\s*(\d{3})""")
    }

    /**
     * True only for the one response that legitimately means "no tickets API".
     *
     * A positive match is required, so anything unrecognised — a socket error,
     * a serialization failure, a coroutine cancellation — falls through to
     * being thrown. That default is the whole point of the classifier: an
     * unknown failure must never be reported to the operator as "no approvals".
     */
    private fun isTicketsApiAbsent(e: Exception): Boolean {
        val status = HTTP_STATUS_IN_MESSAGE.find(e.message ?: return false)
            ?.groupValues?.get(1)?.toIntOrNull() ?: return false
        return status in UNSUPPORTED_ENDPOINT_STATUSES
    }

    override suspend fun fetchWAStatus(): WAStatusData = client.getWAStatus()

    override suspend fun fetchDeferrals(): List<DeferralData> = client.getDeferrals()

    override suspend fun resolveDeferral(
        deferralId: String,
        resolution: String,
        guidance: String,
    ): ResolveDeferralData = client.resolveDeferral(deferralId, resolution, guidance)

    override suspend fun fetchProposals(): List<TicketData> = try {
        // limit = null requests the UNBOUNDED form. The endpoint is newest-first
        // with no offset in its contract, so any fixed window makes every poll
        // re-fetch the same newest-N: with more than N blocked proposals, the
        // older ones never reached the card, badge, or notifier — their agents
        // waiting indefinitely while newer items came and went. Blocked
        // proposals are bounded by how many agents can be blocked at once, not
        // by history, so the unbounded read stays small in practice.
        client.listTickets(statusFilter = BudgetApprovalSeam.PROPOSAL_STATUS, limit = null)
            .filter { BudgetApprovalSeam.isProposal(it.status, it.metadata) }
    } catch (e: Exception) {
        if (isTicketsApiAbsent(e)) {
            // A deployment without the tickets API must still show deferrals.
            PlatformLogger.d(TAG, "[fetchProposals] no tickets API on this server (${e.message}) — treating as none")
            emptyList()
        } else {
            // Everything else is rethrown, because swallowing it publishes a
            // lie: the caller merges this list into the approval list, so an
            // empty return after a 401 or a 500 *erases* the agent's blocked
            // proposals from the card, the badge and the notifier while the
            // agent goes on waiting for a human. The deferral fetch can still
            // succeed, so nothing else would tell the operator anything is
            // wrong. Failing loudly leaves the previous list standing and puts
            // an error on the screen instead.
            PlatformLogger.e(TAG, "[fetchProposals] failed: ${e::class.simpleName}: ${e.message}")
            throw e
        }
    }

    override suspend fun fetchTicketBudget(ticketId: String): TicketBudgetState? =
        client.getTicketBudget(ticketId)

    override suspend fun grantBudget(
        ticketId: String,
        amount: String,
        currency: String,
        purpose: String,
        expiresInHours: Int,
    ): BudgetGrantOutcome =
        client.grantTicketBudget(ticketId, amount, currency, purpose, expiresInHours)

    override suspend fun updateTicketStatus(ticketId: String, status: String, notes: String?): Boolean =
        client.updateTicketStatus(ticketId, status, notes)
}

/**
 * Project a deferral onto the unified [PendingApproval].
 *
 * Deferrals never carry a budget: budget requests ride the ticket path (see
 * [BudgetApprovalSeam]). The `context` map is passed through for display only.
 */
fun DeferralData.toPendingApproval(): PendingApproval = PendingApproval(
    id = deferralId,
    kind = ApprovalKind.DEFERRAL,
    title = question ?: reason,
    detail = reason,
    createdAt = createdAt,
    priority = priority,
    requestedBy = deferredBy,
    status = status,
    context = context ?: emptyMap(),
)

/**
 * Project a proposal ticket onto the unified [PendingApproval].
 *
 * Returns null when the ticket is not an unapproved proposal, so callers can
 * `mapNotNull` a raw ticket list without re-implementing the predicate.
 */
fun TicketData.toPendingApprovalOrNull(): PendingApproval? {
    if (!BudgetApprovalSeam.isProposal(status, metadata)) return null
    val proposal = BudgetApprovalSeam.parseProposal(metadata)
    val requested = BudgetApprovalSeam.parseRequestedBudget(metadata)
    return PendingApproval(
        id = ticketId,
        kind = ApprovalKind.TICKET_PROPOSAL,
        title = proposal?.goalDescription?.takeIf { it.isNotBlank() }
            ?: notes?.takeIf { it.isNotBlank() }
            ?: "$displayType proposal",
        detail = notes.orEmpty(),
        createdAt = submittedAt,
        priority = when {
            priority >= 8 -> "high"
            priority >= 5 -> "medium"
            else -> "normal"
        },
        requestedBy = proposal?.proposedBy ?: "agent",
        status = status,
        requestedBudget = requested,
        grantedBudget = BudgetApprovalSeam.parseGrantedBudget(metadata),
        budgetSpend = BudgetApprovalSeam.parseBudgetSpend(metadata),
        proposal = proposal,
    )
}
