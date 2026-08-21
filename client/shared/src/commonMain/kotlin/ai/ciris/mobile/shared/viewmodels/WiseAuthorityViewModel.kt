package ai.ciris.mobile.shared.viewmodels

import ai.ciris.mobile.shared.api.CIRISApiClient
import ai.ciris.mobile.shared.api.DeferralData
import ai.ciris.mobile.shared.api.WAStatusData
import ai.ciris.mobile.shared.approvals.ApprovalNotifier
import ai.ciris.mobile.shared.approvals.ApprovalsApi
import ai.ciris.mobile.shared.approvals.BudgetApprovalSeam
import ai.ciris.mobile.shared.approvals.BudgetCapability
import ai.ciris.mobile.shared.approvals.BudgetGrantError
import ai.ciris.mobile.shared.approvals.BudgetGrantOutcome
import ai.ciris.mobile.shared.approvals.CIRISApprovalsApi
import ai.ciris.mobile.shared.approvals.InMemoryNotifiedApprovalStore
import ai.ciris.mobile.shared.approvals.PendingApproval
import ai.ciris.mobile.shared.approvals.PlatformApprovalNotificationSink
import ai.ciris.mobile.shared.approvals.SecureStorageNotifiedApprovalStore
import ai.ciris.mobile.shared.approvals.TicketBudgetState
import ai.ciris.mobile.shared.approvals.toPendingApproval
import ai.ciris.mobile.shared.approvals.toPendingApprovalOrNull
import ai.ciris.mobile.shared.platform.PlatformLogger
import ai.ciris.mobile.shared.platform.SecureStorage
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * Shared ViewModel for the human-in-the-loop approval surface.
 *
 * Folds the two sources of pending human decisions into one list:
 *  - Wisdom-Based Deferrals (`/v1/wa/deferrals`), and
 *  - agent ticket proposals awaiting approval, which may carry a **requested
 *    budget** (#938/#939) that only a human may issue.
 *
 * ── How the client learns about new approvals ───────────────────────────────
 *
 * **Polling. There is no push.** The API exposes WebSocket streams for
 * messages / telemetry / reasoning / logs, but deferrals and tickets are not
 * among them, so nothing arrives unsolicited. Two loops run at different
 * cadences for different reasons:
 *
 *  - [startApprovalWatch] — [WATCH_INTERVAL_MS], runs for the whole
 *    authenticated session regardless of which screen is showing. This is what
 *    makes the nav badge and the notification possible; without it an operator
 *    only discovers a blocked agent by navigating to this screen, which is the
 *    exact failure the surface exists to prevent.
 *  - [startPolling] — [POLL_INTERVAL_MS], while the approval screen is visible,
 *    so the list feels live under a decision.
 *
 * Both feed the same [ApprovalNotifier], which dedupes, so overlapping loops
 * cannot produce duplicate notifications.
 */
class WiseAuthorityViewModel(
    private val api: ApprovalsApi,
    private val notifier: ApprovalNotifier? = null,
) : ViewModel() {

    /**
     * Production constructor. Persists notification dedupe state to
     * [SecureStorage] so an app restart does not re-announce everything the
     * operator has already seen.
     */
    constructor(apiClient: CIRISApiClient, secureStorage: SecureStorage) : this(
        api = CIRISApprovalsApi(apiClient),
        notifier = ApprovalNotifier(
            sink = PlatformApprovalNotificationSink,
            store = SecureStorageNotifiedApprovalStore(secureStorage),
        ),
    )

    /**
     * Constructor for hosts without secure storage wired. Dedupe is
     * process-scoped: a restart may re-announce still-pending approvals once.
     */
    constructor(apiClient: CIRISApiClient) : this(
        api = CIRISApprovalsApi(apiClient),
        notifier = ApprovalNotifier(
            sink = PlatformApprovalNotificationSink,
            store = InMemoryNotifiedApprovalStore(),
        ),
    )

    companion object {
        private const val TAG = "WiseAuthorityViewModel"

        /** Foreground cadence while the approval screen is open. */
        private const val POLL_INTERVAL_MS = 10000L

        /** Session-wide cadence that drives the badge + notifications. */
        private const val WATCH_INTERVAL_MS = 30000L
    }

    private fun log(level: String, method: String, message: String) {
        val fullMessage = "[$method] $message"
        when (level) {
            "DEBUG" -> PlatformLogger.d(TAG, fullMessage)
            "INFO" -> PlatformLogger.i(TAG, fullMessage)
            "WARN" -> PlatformLogger.w(TAG, fullMessage)
            "ERROR" -> PlatformLogger.e(TAG, fullMessage)
            else -> PlatformLogger.i(TAG, fullMessage)
        }
    }

    private fun logDebug(method: String, message: String) = log("DEBUG", method, message)
    private fun logInfo(method: String, message: String) = log("INFO", method, message)
    private fun logWarn(method: String, message: String) = log("WARN", method, message)
    private fun logError(method: String, message: String) = log("ERROR", method, message)

    // WA Status
    private val _waStatus = MutableStateFlow<WAStatusData?>(null)
    val waStatus: StateFlow<WAStatusData?> = _waStatus.asStateFlow()

    // Deferrals list (raw — retained for the existing deferral UI)
    private val _deferrals = MutableStateFlow<List<DeferralData>>(emptyList())
    val deferrals: StateFlow<List<DeferralData>> = _deferrals.asStateFlow()

    /** The unified pending-approval list: deferrals + unapproved ticket proposals. */
    private val _approvals = MutableStateFlow<List<PendingApproval>>(emptyList())
    val approvals: StateFlow<List<PendingApproval>> = _approvals.asStateFlow()

    /**
     * How many decisions the agent is blocked on. Drives the nav badge. Kept
     * as a separate flow so nav can observe a count without holding the list.
     */
    private val _pendingApprovalCount = MutableStateFlow(0)
    val pendingApprovalCount: StateFlow<Int> = _pendingApprovalCount.asStateFlow()

    /**
     * Approval alerts are being SUPPRESSED because the OS denied notification
     * permission.
     *
     * Re-exposed from the notifier, which is private here, so a surface can tell
     * the operator. On Android 13+ `POST_NOTIFICATIONS` starts DENIED and nothing
     * in this app ever requests it, so on a fresh install the session-wide watcher
     * runs, finds work, and silently drops every alert. A denial nobody is told
     * about is indistinguishable from an agent that never needed anything — which
     * is the one thing this surface exists to disprove.
     *
     * This is the HONEST MINIMUM, not the cure: the cure is an Activity-backed
     * runtime request behind an explicit opt-in, and the platform seam carries no
     * Activity today (see ApprovalNotifier's KDoc for what that needs).
     */
    val notificationsBlocked: StateFlow<Boolean> =
        notifier?.notificationsBlocked ?: MutableStateFlow(false).asStateFlow()

    /** Whether this server exposes budget *issuance*. See [BudgetCapability]. */
    private val _budgetCapability = MutableStateFlow(BudgetCapability.UNKNOWN)
    val budgetCapability: StateFlow<BudgetCapability> = _budgetCapability.asStateFlow()

    /**
     * Full budget state for the approval currently open in the dialog, fetched
     * on open. Its [TicketBudgetState.headroom] is what lets an operator see how
     * much room the deployment has left — approving an amount with no view of
     * the remaining envelope is not meaningful consent.
     *
     * Null while nothing is open, and null when the server does not expose the
     * endpoint; the dialog then renders from ticket metadata alone and simply
     * omits the headroom row.
     */
    private val _selectedBudgetState = MutableStateFlow<TicketBudgetState?>(null)
    val selectedBudgetState: StateFlow<TicketBudgetState?> = _selectedBudgetState.asStateFlow()

    /**
     * Which approval's dialog is open right now, or null when none is.
     *
     * This is the *identity of the open dialog*, and it is the only thing that
     * can tell a budget response that is still wanted from one whose dialog has
     * since been dismissed or replaced. The fetched [TicketBudgetState.ticketId]
     * cannot: it is whatever the request asked for, so comparing it against the
     * id that same request captured is true by construction and guards nothing.
     *
     * Plain field rather than a flow or an atomic on purpose — [viewModelScope]
     * is main-confined, so every write here (dialog open/close) and every read
     * (a resumed fetch) happens on the same dispatcher.
     */
    private var openApprovalId: String? = null

    // Loading state
    private val _isLoading = MutableStateFlow(false)
    val isLoading: StateFlow<Boolean> = _isLoading.asStateFlow()

    // Error state
    private val _error = MutableStateFlow<String?>(null)
    val error: StateFlow<String?> = _error.asStateFlow()

    // Success message (e.g., after resolving deferral)
    private val _successMessage = MutableStateFlow<String?>(null)
    val successMessage: StateFlow<String?> = _successMessage.asStateFlow()

    // Connection state
    private val _isConnected = MutableStateFlow(false)
    val isConnected: StateFlow<Boolean> = _isConnected.asStateFlow()

    // Resolving deferral / granting budget state
    private val _isResolving = MutableStateFlow(false)
    val isResolving: StateFlow<Boolean> = _isResolving.asStateFlow()

    // Polling jobs
    private var pollingJob: Job? = null
    private var watchJob: Job? = null
    private var isFirstLoad = true
    private var pollingStarted = false
    private var watchStarted = false

    init {
        logInfo("init", "WiseAuthorityViewModel initialized (polling deferred until startPolling() called)")
        // NOTE: Don't auto-start polling here - wait for startPolling() to be called
        // when the screen becomes visible and has a valid auth token
    }

    /**
     * Start the session-wide approval watch.
     *
     * Call once the user is authenticated, not when a screen opens — the whole
     * point is that the operator learns about a blocked agent *without*
     * navigating anywhere. Idempotent.
     */
    fun startApprovalWatch() {
        if (watchStarted) {
            logDebug("startApprovalWatch", "Watch already running, skipping")
            return
        }
        watchStarted = true
        val method = "startApprovalWatch"
        logInfo(method, "Starting session-wide approval watch (interval=${WATCH_INTERVAL_MS}ms)")

        watchJob = viewModelScope.launch {
            while (isActive) {
                try {
                    fetchDataInternal()
                    _isConnected.value = true
                } catch (e: Exception) {
                    // Quiet: the watch runs everywhere, so a blip must not paint
                    // an error banner over an unrelated screen.
                    logDebug(method, "Watch cycle failed: ${e::class.simpleName}: ${e.message}")
                }
                delay(WATCH_INTERVAL_MS)
            }
        }
    }

    /**
     * Stop the session-wide watch (logout / shutdown) AND clear the
     * session-owned approval state.
     *
     * The clear is not tidiness: this ViewModel is scoped to [CIRISApp], so it
     * outlives the login session. Cancelling only the watcher left the previous
     * user's badge count and proposal details standing for the NEXT user until
     * their first successful fetch — or indefinitely when that fetch failed.
     * What a signed-out client shows must not be another user's approvals.
     *
     * The notifier's persisted dedupe set is deliberately NOT cleared: it is
     * device-scoped at-most-once by design (its own doc: restarting the app
     * must not re-announce). A next user's OWN backlog still notifies — those
     * ids were never remembered.
     */
    fun stopApprovalWatch() {
        logInfo("stopApprovalWatch", "Stopping approval watch")
        watchJob?.cancel()
        watchJob = null
        watchStarted = false
        _waStatus.value = null
        _deferrals.value = emptyList()
        _approvals.value = emptyList()
        _pendingApprovalCount.value = 0
        _budgetCapability.value = BudgetCapability.UNKNOWN
        _selectedBudgetState.value = null
        openApprovalId = null
        _error.value = null
        _successMessage.value = null
        _isConnected.value = false
        _isResolving.value = false
    }

    /**
     * Start automatic polling.
     * Must be called explicitly when the screen becomes visible.
     */
    fun startPolling() {
        if (pollingStarted) {
            logDebug("startPolling", "Polling already started, skipping")
            return
        }
        pollingStarted = true
        val method = "startPolling"
        logInfo(method, "Starting WA polling (interval=${POLL_INTERVAL_MS}ms)")

        pollingJob = viewModelScope.launch {
            var pollCount = 0
            while (isActive) {
                pollCount++
                logDebug(method, "Poll cycle #$pollCount starting")

                try {
                    fetchDataInternal()
                    _isConnected.value = true
                    _error.value = null

                    if (pollCount % 6 == 0) {
                        logInfo(method, "Poll cycle #$pollCount completed successfully")
                    }
                } catch (e: Exception) {
                    logError(method, "Poll cycle #$pollCount failed: ${e::class.simpleName}: ${e.message}")
                    _isConnected.value = false
                    _error.value = "Connection error: ${e.message}"
                } finally {
                    if (isFirstLoad) {
                        logInfo(method, "First load complete")
                        _isLoading.value = false
                        isFirstLoad = false
                    }
                }

                delay(POLL_INTERVAL_MS)
            }
        }
    }

    /**
     * Stop automatic polling
     */
    fun stopPolling() {
        val method = "stopPolling"
        logInfo(method, "Stopping WA polling")
        pollingJob?.cancel()
        pollingJob = null
        pollingStarted = false // Allow restart
    }

    /**
     * Manual refresh triggered by user
     */
    fun refresh() {
        val method = "refresh"
        logInfo(method, "Manual refresh triggered")

        viewModelScope.launch {
            _isLoading.value = true
            logDebug(method, "Loading state set to true")

            try {
                fetchDataInternal()
                _isConnected.value = true
                _error.value = null
                logInfo(method, "Manual refresh completed successfully")
            } catch (e: Exception) {
                logError(method, "Manual refresh failed: ${e::class.simpleName}: ${e.message}")
                _isConnected.value = false
                _error.value = "Refresh failed: ${e.message}"
            } finally {
                _isLoading.value = false
                logDebug(method, "Loading state set to false")
            }
        }
    }

    /**
     * Fetch WA status, deferrals and proposal tickets, rebuild the unified
     * approval list, and hand it to the notifier.
     *
     * Deferral fetch failures propagate (the screen shows a connection error).
     * Proposal fetch failures ALSO propagate — except the specific
     * feature-absent responses (404/405/501, see [ApprovalsApi.isTicketsApiAbsent]),
     * because a deployment may legitimately have no tickets API and that must
     * not blank the deferral list. A 401/500/transient failure is NOT proof of
     * absence and no longer silently empties the approval card.
     */
    private suspend fun fetchDataInternal() {
        val method = "fetchDataInternal"
        logDebug(method, "Fetching approval data from API")

        try {
            val status = api.fetchWAStatus()
            _waStatus.value = status
            logDebug(
                method,
                "WA status: healthy=${status.serviceHealthy}, activeWAs=${status.activeWAs}, " +
                    "pendingDeferrals=${status.pendingDeferrals}"
            )

            val deferrals = api.fetchDeferrals()
            _deferrals.value = deferrals
            logDebug(method, "Fetched ${deferrals.size} deferrals")

            val proposals = api.fetchProposals().mapNotNull { it.toPendingApprovalOrNull() }
            if (proposals.isNotEmpty()) {
                logDebug(method, "Fetched ${proposals.size} agent proposal(s) awaiting approval")
            }

            val unified = deferrals.map { it.toPendingApproval() } + proposals
            _approvals.value = unified
            _pendingApprovalCount.value = unified.count { it.status.equals("pending", ignoreCase = true) ||
                it.status.equals(BudgetApprovalSeam.PROPOSAL_STATUS, ignoreCase = true) }

            notifyNewApprovals(unified)
        } catch (e: Exception) {
            logError(method, "Failed to fetch approval data: ${e::class.simpleName}: ${e.message}")
            throw e
        }
    }

    /**
     * Hand the current approvals to the notifier.
     *
     * Wrapped: a notification failure must never break a poll cycle or blank
     * the list the operator is reading.
     */
    private suspend fun notifyNewApprovals(approvals: List<PendingApproval>) {
        val n = notifier ?: return
        try {
            val notified = n.onApprovalsObserved(approvals)
            if (notified.isNotEmpty()) {
                logInfo("notifyNewApprovals", "Notified ${notified.size} new approval(s)")
            }
        } catch (e: Exception) {
            logWarn("notifyNewApprovals", "Notification failed (non-fatal): ${e.message}")
        }
    }

    /**
     * Resolve a pending deferral
     */
    fun resolveDeferral(deferralId: String, resolution: String, guidance: String) {
        val method = "resolveDeferral"
        logInfo(method, "Resolving deferral: id=$deferralId, resolution=$resolution")

        viewModelScope.launch {
            _isResolving.value = true
            _error.value = null

            try {
                val result = api.resolveDeferral(deferralId, resolution, guidance)
                logInfo(method, "Deferral resolved: ${result.deferralId}, success=${result.success}")

                _successMessage.value = "Deferral resolved successfully"
                notifier?.forget(deferralId)

                // Refresh to update the list
                fetchDataInternal()
            } catch (e: Exception) {
                logError(method, "Failed to resolve deferral: ${e::class.simpleName}: ${e.message}")
                _error.value = "Failed to resolve deferral: ${e.message}"
            } finally {
                _isResolving.value = false
            }
        }
    }

    /**
     * Load the budget state (and remaining trust headroom) for an approval the
     * user has just opened.
     *
     * Deliberately fire-and-forget and non-fatal: the dialog renders
     * immediately from data already in the list, and the headroom row appears
     * a moment later if the server supplies it. A server without the endpoint
     * produces no error state — only a missing row.
     */
    fun loadBudgetState(approvalId: String) {
        val method = "loadBudgetState"
        // Claim the dialog *before* suspending. Opening B is what makes A's
        // in-flight read obsolete, so obsolescence has to be recorded at the
        // moment of the open, not when some response happens to land.
        openApprovalId = approvalId
        viewModelScope.launch {
            try {
                val state = api.fetchTicketBudget(approvalId)
                // UPSTREAM RELAY CANDIDATE (CIRISAgent#1086 pattern): this file
                // was byte-identical to CIRISAgent 2.9.28 before this guard, so
                // the race is upstream's too — 2.9.28:409 publishes on a ticketId
                // echo alone, and 2.9.28:421 wipes the flow unconditionally.
                //
                // Publish only while this approval is still the open one.
                //
                // A response for a dialog the operator has already dismissed or
                // replaced must never become the state the *current* dialog
                // renders and validates against: the dialog reads headroom
                // straight off this flow and runs the local amount check
                // against it, so a stale figure landing here — or, just as bad,
                // a null one wiping the live figure — silently changes what the
                // operator is being asked to consent to. Comparing
                // `state.ticketId` to `approvalId` cannot catch this; it only
                // confirms the server echoed the ticket we asked for.
                if (approvalId != openApprovalId) {
                    logDebug(
                        method,
                        "Discarding budget state for $approvalId — open dialog is now " +
                            (openApprovalId ?: "none")
                    )
                    return@launch
                }
                if (state == null || state.ticketId == approvalId) {
                    _selectedBudgetState.value = state
                }
                if (state?.headroom != null) {
                    logDebug(
                        method,
                        "Headroom for $approvalId: ${state.headroom.amount} ${state.headroom.currency} " +
                            "(max_tx=${state.headroom.maxTransaction}, daily=${state.headroom.dailyRemaining})"
                    )
                }
            } catch (e: Exception) {
                logDebug(method, "Budget state unavailable for $approvalId: ${e.message}")
                // Blank only the dialog this failure actually belongs to. A 404
                // for an approval the operator has moved on from must not take
                // the open dialog's headroom with it — losing the ceiling is
                // exactly how an over-envelope amount gets past the local check.
                if (approvalId == openApprovalId) {
                    _selectedBudgetState.value = null
                }
            }
        }
    }

    /** Drop the loaded budget state when the dialog closes. */
    fun clearBudgetState() {
        // Releasing the claim is what marks any read still in flight obsolete;
        // without it a slow response lands after the dialog is gone and
        // re-publishes state for an approval nobody is looking at any more.
        openApprovalId = null
        _selectedBudgetState.value = null
    }

    /**
     * Issue a budget envelope against an agent proposal — the human approval
     * that unblocks spend.
     *
     * A grant **above** the agent's request is permitted — the agent may have
     * asked for too little, and an AUTHORITY user is the one with standing to
     * correct that — but never silently: [overGrantConfirmed] must be true, and
     * the caller is expected to have shown the human by how much. The trust
     * ceiling is a separate, harder bound that no confirmation overrides.
     *
     * @param promote when true, also PATCH the ticket to `pending` so the work
     *   actually starts. Granting money and starting work are separate
     *   decisions, and the UI makes both visible.
     * @param overGrantConfirmed the human explicitly acknowledged exceeding the
     *   request, having been shown the ratio.
     */
    fun grantBudget(
        approvalId: String,
        amount: String,
        currency: String,
        purpose: String,
        expiresInHours: Int,
        promote: Boolean,
        overGrantConfirmed: Boolean = false,
        onResult: (BudgetGrantOutcome) -> Unit = {},
    ) {
        val method = "grantBudget"
        val approval = _approvals.value.firstOrNull { it.id == approvalId }
        val requested = approval?.requestedBudget

        if (requested == null) {
            logError(method, "No requested budget on approval $approvalId")
            val outcome = BudgetGrantOutcome(
                ok = false,
                error = BudgetGrantError.UNKNOWN,
                message = "This approval does not carry a budget request",
            )
            _error.value = outcome.message
            onResult(outcome)
            return
        }

        val validation = BudgetApprovalSeam.validateGrant(
            requested = requested,
            amount = amount,
            expiresInHours = expiresInHours,
            purpose = purpose,
            // Only apply headroom actually loaded for THIS approval, so a stale
            // figure from a previously-open dialog can never gate a grant.
            headroom = _selectedBudgetState.value
                ?.takeIf { it.ticketId == approvalId }
                ?.headroom,
            overGrantConfirmed = overGrantConfirmed,
        )
        if (!validation.ok) {
            logWarn(method, "Local validation refused grant: ${validation.error} (${validation.message})")
            _error.value = validation.message ?: describe(validation.error)
            onResult(validation)
            return
        }

        val overGrant = validation.overGrant
        logInfo(
            method,
            "Granting $amount $currency on $approvalId (expiry=${expiresInHours}h, promote=$promote" +
                (overGrant?.let { ", EXCEEDS REQUEST ${it.requestedAmount} by ${it.display.ifBlank { "<5%" }}" } ?: "") +
                ")"
        )

        viewModelScope.launch {
            _isResolving.value = true
            _error.value = null

            try {
                val outcome = api.grantBudget(approvalId, amount, currency, purpose, expiresInHours)

                if (outcome.ok) {
                    _budgetCapability.value = BudgetCapability.AVAILABLE
                    val signedNote = if (outcome.granted?.signed == false) " (unsigned — no WA signing key)" else ""
                    // Echo what the SERVER recorded, not what we asked for — the
                    // marking is derived there and is the version that counts.
                    val overNote = outcome.granted
                        ?.takeIf { it.exceedsRequest }
                        ?.let { g ->
                            g.requestedAmountAtGrant
                                ?.let { req -> " — above the $req requested" }
                                ?: " — above the agent's request"
                        }
                        ?: overGrant?.let { " — above the ${it.requestedAmount} requested" }
                        ?: ""
                    _successMessage.value = "Approved $amount $currency$overNote$signedNote"

                    // UPSTREAM RELAY CANDIDATE (CIRISAgent#1086 pattern):
                    // CIRISAgent 2.9.28:522 forgets the id unconditionally right
                    // here, so a grant without promotion re-notifies there too.
                    //
                    // Only a *successful* promotion retires the notification id.
                    // Issuing a budget without promoting deliberately leaves the
                    // ticket blocked, so the proposal is still in the pending set
                    // and the refresh below re-observes it — forgetting the id
                    // there would re-notify the operator about the very approval
                    // they just acted on. Same rule as [updateProposalStatus].
                    if (promote) {
                        val promoted = api.updateTicketStatus(
                            approvalId,
                            BudgetApprovalSeam.PROMOTED_STATUS,
                            null,
                        )
                        if (promoted) {
                            notifier?.forget(approvalId)
                        } else {
                            _error.value = "Budget approved, but starting the work failed — promote it manually"
                            logWarn(method, "Grant succeeded but promotion failed for $approvalId")
                        }
                    }
                } else {
                    if (outcome.error == BudgetGrantError.ENDPOINT_UNAVAILABLE) {
                        _budgetCapability.value = BudgetCapability.UNAVAILABLE
                    }
                    _error.value = outcome.message ?: describe(outcome.error)
                    logError(method, "Grant refused: ${outcome.error} ${outcome.message}")
                }

                fetchDataInternal()
                onResult(outcome)
            } catch (e: Exception) {
                logError(method, "Grant failed: ${e::class.simpleName}: ${e.message}")
                val outcome = BudgetGrantOutcome(false, BudgetGrantError.UNKNOWN, e.message)
                _error.value = "Failed to approve budget: ${e.message}"
                onResult(outcome)
            } finally {
                _isResolving.value = false
            }
        }
    }

    /**
     * Start the work on a proposal without changing its budget — the promotion
     * half of the decision, for proposals that ask for no money or whose budget
     * was already issued.
     */
    fun promoteProposal(approvalId: String, note: String?) {
        val method = "promoteProposal"
        logInfo(method, "Promoting proposal $approvalId to ${BudgetApprovalSeam.PROMOTED_STATUS}")
        updateProposalStatus(
            approvalId,
            BudgetApprovalSeam.PROMOTED_STATUS,
            note,
            "Approved — work started",
            // Promotion takes the proposal out of the pending set.
            retiresNotification = true,
        )
    }

    /** Refuse a proposal outright. Nothing is issued and the work never starts. */
    fun rejectProposal(approvalId: String, reason: String?) {
        val method = "rejectProposal"
        logInfo(method, "Rejecting proposal $approvalId")
        updateProposalStatus(
            approvalId,
            BudgetApprovalSeam.REJECTED_STATUS,
            reason,
            "Proposal rejected",
            // Rejection takes the proposal out of the pending set.
            retiresNotification = true,
        )
    }

    /**
     * "Not now" — record why and leave the proposal blocked. Nothing is issued,
     * the work does not start, and the agent stays fail-closed, which is the
     * correct default when a human has not decided.
     */
    fun deferProposal(approvalId: String, note: String?) {
        val method = "deferProposal"
        logInfo(method, "Deferring proposal $approvalId (status unchanged)")
        updateProposalStatus(
            approvalId,
            BudgetApprovalSeam.PROPOSAL_STATUS,
            note,
            "Left for later",
            // "Not now" leaves the proposal exactly where it was — still
            // blocked, still pending — so it must stay marked as
            // already-notified. Retiring the id here would let the refresh that
            // follows the defer re-observe the unchanged proposal as new and
            // notify again the instant the operator asked to be left alone.
            retiresNotification = false,
        )
    }

    /**
     * UPSTREAM RELAY CANDIDATE (CIRISAgent#1086 pattern): CIRISAgent 2.9.28 has
     * no such flag — 2.9.28:598 forgets the id on every status write, the defer
     * that leaves the proposal pending included, so the bug is upstream's too.
     *
     * @param retiresNotification whether this transition removes the approval
     *   from the pending set. Only then may the notifier forget the id:
     *   forgetting means "announce it again if it comes back", and for a status
     *   that leaves the item pending, the [fetchDataInternal] below *is* it
     *   coming back — immediately, which reads as a notification bug rather
     *   than as the decision the operator made.
     */
    private fun updateProposalStatus(
        approvalId: String,
        status: String,
        note: String?,
        successText: String,
        retiresNotification: Boolean,
    ) {
        viewModelScope.launch {
            _isResolving.value = true
            _error.value = null
            try {
                val ok = api.updateTicketStatus(approvalId, status, note)
                if (ok) {
                    _successMessage.value = successText
                    if (retiresNotification) {
                        notifier?.forget(approvalId)
                    }
                } else {
                    _error.value = "Server refused the update"
                }
                fetchDataInternal()
            } catch (e: Exception) {
                logError("updateProposalStatus", "Failed: ${e.message}")
                _error.value = "Failed to update: ${e.message}"
            } finally {
                _isResolving.value = false
            }
        }
    }

    private fun describe(error: BudgetGrantError?): String = when (error) {
        BudgetGrantError.FORBIDDEN_ROLE ->
            "Approving a budget requires the AUTHORITY role — an admin account is not enough"
        BudgetGrantError.TICKET_NOT_FOUND -> "That proposal no longer exists"
        BudgetGrantError.NESTING_VIOLATION ->
            "That exceeds this deployment's trust envelope — approve a smaller amount"
        BudgetGrantError.ENDPOINT_UNAVAILABLE ->
            "This server does not support budget approval yet"
        BudgetGrantError.OVER_GRANT_UNCONFIRMED ->
            "That is more than the agent asked for — confirm the amount to approve it"
        BudgetGrantError.INVALID_AMOUNT -> "Enter a valid amount"
        BudgetGrantError.INVALID_EXPIRY -> "Enter a valid expiry"
        BudgetGrantError.MISSING_PURPOSE -> "Say what the money is for"
        else -> "Budget approval failed"
    }

    /**
     * Clear any error state
     */
    fun clearError() {
        val method = "clearError"
        logDebug(method, "Clearing error state")
        _error.value = null
    }

    /**
     * Clear success message
     */
    fun clearSuccess() {
        val method = "clearSuccess"
        logDebug(method, "Clearing success message")
        _successMessage.value = null
    }

    override fun onCleared() {
        logInfo("onCleared", "ViewModel cleared, cancelling polling jobs")
        super.onCleared()
        pollingJob?.cancel()
        watchJob?.cancel()
    }
}
