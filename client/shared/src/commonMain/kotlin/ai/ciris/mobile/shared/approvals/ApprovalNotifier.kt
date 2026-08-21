package ai.ciris.mobile.shared.approvals

import ai.ciris.mobile.shared.platform.PlatformLogger
import ai.ciris.mobile.shared.platform.ScheduledTaskNotifications
import ai.ciris.mobile.shared.platform.SecureStorage
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * ═══════════════════════════════════════════════════════════════════════════
 * "A new approval is waiting on you" — the notification half of the HITL
 * surface.
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * The platform notification plumbing already exists: [ScheduledTaskNotifications]
 * has real Android (NotificationManager + WorkManager), iOS
 * (UNUserNotificationCenter), desktop (system tray) and wasmJs implementations.
 * What it did **not** have was a caller for "something arrived that needs you"
 * — it was wired exclusively to scheduled-task *time* triggers, a
 * calendar/reminder shape. This class supplies the missing caller. It adds no
 * new `expect`/`actual`: the four platform implementations are reused as-is
 * through [ScheduledTaskNotifications.showImmediateNotification].
 *
 * ── The contract ────────────────────────────────────────────────────────────
 *
 * **At most once per approval.** The dedupe key is [PendingApproval.id]. An
 * approval that has been notified is never notified again, no matter how many
 * poll cycles observe it — otherwise a 30-second poll against three pending
 * approvals is 360 notifications an hour and the operator turns notifications
 * off, which is strictly worse than not shipping this.
 *
 * **At most once means at most once *concurrently*.** Two callers exist by
 * design — the session-wide watch and the approvals screen — and they overlap.
 * Reading the remembered set, deciding what is fresh and writing it back is
 * therefore one critical section under [gate], never three suspending steps
 * that another observation can interleave with. See [onApprovalsObserved].
 *
 * **At-most-once, not at-least-once.** If the sink throws, the id is still
 * marked notified. A permanently failing sink must not accumulate an
 * ever-growing retry set, and a notification is a convenience — the badge and
 * the card are the surface of record.
 *
 * **Permission denial does not consume the key.** If notification permission is
 * absent we show nothing and mark nothing, so the approvals that arrived while
 * permission was denied will each fire exactly once if the user later grants
 * it. This class never *prompts* — prompting needs an Activity on Android and
 * this object only ever sees an application context. It does, however, publish
 * [notificationsBlocked], because a denial that nobody is told about is
 * indistinguishable from a working notifier that has nothing to say.
 *
 * **Bursts collapse.** More than [burstThreshold] new approvals in one
 * observation produce a single summary notification rather than a stack of
 * them. First launch against a backlog is the common case here.
 *
 * **Failure is never fatal.** Every platform call is wrapped; a platform with
 * no notification support (wasmJs logs to console; desktop without a system
 * tray falls back to a log line) degrades to silence. Nothing here can throw
 * into the caller, so a missing notification can never crash or block a screen.
 */
class ApprovalNotifier(
    private val sink: ApprovalNotificationSink,
    private val store: NotifiedApprovalStore,
    /** Cap on remembered ids. Insertion-ordered; oldest evicted first. */
    private val maxRemembered: Int = 300,
    /** Above this many new approvals at once, collapse to one summary. */
    private val burstThreshold: Int = 3,
    private val strings: ApprovalNotificationStrings = ApprovalNotificationStrings(),
) {
    /** Lazily hydrated from [store] on first observation. */
    private var notified: LinkedHashSet<String>? = null

    /**
     * Serializes the whole read-decide-write cycle over [notified] and [store].
     *
     * Not a nicety. The hydrate step suspends — on Android [SecureStorage] is
     * EncryptedSharedPreferences read on `Dispatchers.IO` — so before this
     * existed the session-wide watch and the Wise Authority screen could both
     * be *inside* the first `loadNotified()` while the field was still null.
     * Each then got its own empty set, classified the same backlog as fresh,
     * and notified it twice; the second write also clobbered the first. It bit
     * hardest exactly where it hurts most: at login, against the largest set.
     *
     * Held across the platform emit as well, so a key can never be marked
     * notified by one caller while another is still deciding to emit it. The
     * lock is uncontended in the steady state (10s / 30s cadences) and the
     * section is short, so nothing worth optimising is being given up.
     */
    private val gate = Mutex()

    private val _notificationsBlocked = MutableStateFlow(false)

    /**
     * True once an approval has actually gone un-announced because the platform
     * denies notification permission.
     *
     * Exists because silent failure here is indistinguishable from success: the
     * watch runs, the sink is called, nothing appears, and nobody is told. On a
     * fresh Android 13+ install `POST_NOTIFICATIONS` starts denied and no code
     * path in this app ever prompts for it, so this is the *default* state, not
     * an edge case. Whoever renders the approval surface should read this and
     * say "alerts are off — turn them on in system settings"; see the class
     * doc's note on prompting staying outside this class.
     *
     * Raised only when something was actually suppressed, never on a bare
     * permission check, so an empty backlog cannot raise a false alarm. It is
     * lowered again as soon as permission is seen to be present — including on
     * an otherwise-quiet cycle, so the banner does not outlive the problem.
     */
    val notificationsBlocked: StateFlow<Boolean> = _notificationsBlocked.asStateFlow()

    /**
     * Feed the current set of pending approvals in. Emits a platform
     * notification for each id not seen before.
     *
     * @return the ids that were notified on this call — empty when nothing is
     *   new, when permission is absent, or when the list is empty. Returned for
     *   testability and for callers that want to log; the UI does not need it.
     */
    suspend fun onApprovalsObserved(approvals: List<PendingApproval>): List<String> = gate.withLock {
        val seen = loadNotified()
        val fresh = approvals.filter { it.id !in seen }
        if (fresh.isEmpty()) {
            // Nothing to announce. Re-check permission *only* while we are
            // claiming alerts are off, so a "notifications are disabled" banner
            // clears once the user grants it — without paying a platform
            // permission call on every quiet poll cycle.
            if (_notificationsBlocked.value && safeHasPermission()) _notificationsBlocked.value = false
            return@withLock emptyList()
        }

        // Check permission *before* consuming any dedupe keys, so a later grant
        // of permission still surfaces everything that arrived meanwhile.
        if (!safeHasPermission()) {
            // WARN, not DEBUG: this is the fresh-install default on Android 13+
            // and it means the operator is not being told the agent is blocked.
            PlatformLogger.w(
                TAG,
                "[onApprovalsObserved] ${fresh.size} new approval(s) but notification permission is absent — " +
                    "badge and card still show them",
            )
            _notificationsBlocked.value = true
            return@withLock emptyList()
        }
        _notificationsBlocked.value = false

        val notifiedNow = if (fresh.size > burstThreshold) {
            emit(SUMMARY_ID, strings.summaryTitle(fresh.size), strings.summaryBody(fresh.size))
            fresh.map { it.id }
        } else {
            fresh.forEach { emit(it.id, strings.title(it), strings.body(it)) }
            fresh.map { it.id }
        }

        remember(notifiedNow)
        notifiedNow
    }

    /**
     * Forget an id so a later re-appearance notifies again. Used when the user
     * resolves an approval from the UI — nothing depends on it, but it keeps
     * the remembered set honest rather than monotonically growing.
     *
     * Takes [gate] for the same reason [onApprovalsObserved] does: a resolve
     * lands from the UI while a poll cycle is mid-write, and a read-modify-write
     * that raced the poll's write would resurrect the id it just removed.
     */
    suspend fun forget(id: String) = gate.withLock {
        val seen = loadNotified()
        if (seen.remove(id)) {
            runCatching { store.persist(seen) }
                .onFailure { PlatformLogger.w(TAG, "[forget] persist failed: ${it.message}") }
        }
    }

    /**
     * Caller must already hold [gate] — [Mutex] is not reentrant, so this and
     * [remember] stay private and lock-free by contract rather than re-taking it.
     */
    private suspend fun loadNotified(): LinkedHashSet<String> {
        notified?.let { return it }
        val loaded = runCatching { store.load() }
            .onFailure { PlatformLogger.w(TAG, "[loadNotified] load failed, starting empty: ${it.message}") }
            .getOrDefault(emptySet())
        return LinkedHashSet(loaded).also { notified = it }
    }

    /** Caller must already hold [gate]. See [loadNotified]. */
    private suspend fun remember(ids: List<String>) {
        val seen = loadNotified()
        seen.addAll(ids)
        while (seen.size > maxRemembered) {
            val oldest = seen.firstOrNull() ?: break
            seen.remove(oldest)
        }
        runCatching { store.persist(seen) }
            .onFailure { PlatformLogger.w(TAG, "[remember] persist failed: ${it.message}") }
    }

    private fun safeHasPermission(): Boolean =
        runCatching { sink.hasPermission() }
            .onFailure { PlatformLogger.w(TAG, "[hasPermission] threw, treating as denied: ${it.message}") }
            .getOrDefault(false)

    private fun emit(id: String, title: String, body: String) {
        runCatching { sink.show(id, title, body) }
            .onFailure {
                // Deliberately swallowed: the badge + card remain the surface of
                // record, and an unavailable notification channel must never
                // propagate into the polling loop or the screen.
                PlatformLogger.w(TAG, "[emit] notification failed for $id: ${it.message}")
            }
    }

    companion object {
        private const val TAG = "ApprovalNotifier"

        /** Dedupe/notification id used for the collapsed burst notification. */
        const val SUMMARY_ID = "ciris_approvals_summary"
    }
}

/** Where a notification actually goes. Swapped for a fake in tests. */
interface ApprovalNotificationSink {
    fun hasPermission(): Boolean
    suspend fun requestPermission(): Boolean
    fun show(id: String, title: String, body: String)
}

/**
 * The production sink — delegates to the existing four platform
 * implementations. No new `expect`/`actual` is introduced.
 */
object PlatformApprovalNotificationSink : ApprovalNotificationSink {
    override fun hasPermission(): Boolean =
        runCatching { ScheduledTaskNotifications.hasNotificationPermission() }.getOrDefault(false)

    override suspend fun requestPermission(): Boolean =
        runCatching { ScheduledTaskNotifications.requestNotificationPermission() }.getOrDefault(false)

    override fun show(id: String, title: String, body: String) {
        // taskId doubles as the platform notification id, which is what gives
        // us one-notification-per-approval replacement semantics on Android
        // rather than a growing stack.
        ScheduledTaskNotifications.showImmediateNotification(title, body, id)
    }
}

/** Persistence for "which approvals have already been notified". */
interface NotifiedApprovalStore {
    suspend fun load(): Set<String>
    suspend fun persist(ids: Set<String>)
}

/** Test / fallback store. Survives nothing. */
class InMemoryNotifiedApprovalStore(initial: Set<String> = emptySet()) : NotifiedApprovalStore {
    private var ids: Set<String> = initial
    override suspend fun load(): Set<String> = ids
    override suspend fun persist(ids: Set<String>) {
        this.ids = ids
    }
}

/**
 * Production store — persists to [SecureStorage] so a restart does not
 * re-notify everything already seen. Uses the same storage abstraction the app
 * already uses for tokens, which is EncryptedSharedPreferences on Android,
 * Keychain on iOS and keyring on desktop.
 */
class SecureStorageNotifiedApprovalStore(
    private val storage: SecureStorage,
    private val key: String = "hitl_notified_approvals",
) : NotifiedApprovalStore {

    override suspend fun load(): Set<String> =
        storage.get(key).getOrNull()
            ?.split('\n')
            ?.filter { it.isNotBlank() }
            ?.toSet()
            ?: emptySet()

    override suspend fun persist(ids: Set<String>) {
        storage.save(key, ids.joinToString("\n"))
    }
}

/**
 * Notification copy. Extracted so tests assert on structure rather than
 * wording, and so a localized provider can be injected without touching the
 * dedupe logic. Defaults are English; [ai.ciris.mobile.shared.localization.LocalizationHelper]
 * is used by the app-level factory to localize them.
 */
open class ApprovalNotificationStrings {
    open fun title(approval: PendingApproval): String = when {
        approval.needsBudgetDecision ->
            "Budget approval needed: ${approval.requestedBudget?.requestedAmount} " +
                "${approval.requestedBudget?.requestedCurrency}"
        approval.kind == ApprovalKind.TICKET_PROPOSAL -> "The agent needs your approval"
        else -> "The agent is waiting on you"
    }

    open fun body(approval: PendingApproval): String = approval.title.take(180)

    open fun summaryTitle(count: Int): String = "$count approvals waiting on you"

    open fun summaryBody(count: Int): String =
        "The agent is blocked on $count decisions. Open CIRIS to review them."
}
