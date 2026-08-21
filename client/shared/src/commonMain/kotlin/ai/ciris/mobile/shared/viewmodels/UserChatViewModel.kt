package ai.ciris.mobile.shared.viewmodels

import ai.ciris.mobile.shared.api.CIRISApiClient
import ai.ciris.mobile.shared.api.NodeRefusal
import ai.ciris.mobile.shared.models.chat.CegChatMessage
import ai.ciris.mobile.shared.models.chat.ChatCommunity
import ai.ciris.mobile.shared.platform.PlatformLogger
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

/**
 * Drives the **user-to-user chat** — a two-member community whose messages ARE
 * CEG attestations (`src/contacts_chat.rs`).
 *
 * The transcript arrives OLDEST FIRST with each row's structural composers
 * already folded into its `status`, so this holds the server's order verbatim
 * and never re-sorts: `asserted_at` is a signed field, and a client that
 * re-ordered on a locally-parsed timestamp would disagree with the other member
 * about what was said when.
 */
class UserChatViewModel(
    apiClient: CIRISApiClient,
) : BaseFederationViewModel(apiClient) {

    override val tag: String = "UserChatVM"

    private val _community = MutableStateFlow<ChatCommunity?>(null)
    val community: StateFlow<ChatCommunity?> = _community.asStateFlow()

    private val _messages = MutableStateFlow<List<CegChatMessage>>(emptyList())
    val messages: StateFlow<List<CegChatMessage>> = _messages.asStateFlow()

    /** True once a transcript load has completed — tells "empty" from "not asked yet". */
    private val _transcriptLoaded = MutableStateFlow(false)
    val transcriptLoaded: StateFlow<Boolean> = _transcriptLoaded.asStateFlow()

    /** The draft the composer is holding. Owned here so a refusal does not eat it. */
    private val _draft = MutableStateFlow("")
    val draft: StateFlow<String> = _draft.asStateFlow()

    private val _sending = MutableStateFlow(false)
    val sending: StateFlow<Boolean> = _sending.asStateFlow()

    /**
     * The node's typed `reason_id` for the last refusal on this surface.
     *
     * `chat.not_a_contact`, `chat.not_a_member`, `chat.message_too_large` and
     * `chat.empty_message` all arrive as red text otherwise, and each names a
     * different next move.
     */
    private val _refusalReasonId = MutableStateFlow<String?>(null)
    val refusalReasonId: StateFlow<String?> = _refusalReasonId.asStateFlow()

    /** The node's English fallback for the last refusal, or null. */
    private val _refusalDetail = MutableStateFlow<String?>(null)
    val refusalDetail: StateFlow<String?> = _refusalDetail.asStateFlow()

    /**
     * **THE PUBLICATION GUARD. Nothing may write [_community] or [_messages]
     * without checking it.**
     *
     * The synchronous reset in [enter] closes the case where a room is entered
     * AFTER a previous one settled. It does nothing for the case where two
     * entries are IN FLIGHT AT ONCE: open A, open B before A's `startChat`
     * round-trip returns, and A's late response publishes over B — after B is
     * already the visible conversation. `send()` addresses `_community.value`,
     * so the draft the user typed under B's name is then signed, promoted to the
     * community tier and replicated into the room with A. A message is an
     * attestation: there is no unsend. The transcript load has the same shape and
     * would paint A's history under B's header.
     *
     * Cancelling [entryJob] is the tidy half but CANNOT be the correctness half —
     * cancellation is cooperative, so a job already past its last suspension
     * point still runs to its assignment. So every publication is gated on this
     * counter instead: each [enter] / [refresh] takes a ticket, and a result
     * whose ticket is no longer current is DISCARDED rather than published.
     *
     * Confined to the main dispatcher by `viewModelScope`, so a plain `Long` is
     * sufficient — every read and write happens on one thread.
     *
     * NOT PINNED BY A TEST: this ViewModel takes a concrete [CIRISApiClient]
     * (not an interface, unlike the `ApprovalsApi` the WA tests fake), so the
     * race cannot be driven without a refactor that is not worth doing for a
     * guard this small. That is why the invariant is written HERE, at the thing
     * it protects, rather than only in a test file.
     */
    private var entryEpoch: Long = 0L

    /** The in-flight entry, cancelled when a newer one supersedes it. */
    private var entryJob: Job? = null

    /** Take a ticket; every later publication must still hold the current one. */
    private fun nextEpoch(): Long {
        entryEpoch += 1
        return entryEpoch
    }

    /**
     * Enter the room with [contactKeyId], then load the transcript.
     *
     * # Why this ALWAYS calls `POST /v1/chat`
     *
     * The earlier shape skipped the call when the contact card said the room
     * already existed, and loaded the transcript straight from the card's
     * derived id. That left [_community] holding whatever room was viewed
     * BEFORE — this ViewModel is a process singleton, created once in
     * `CIRISApp` — and [send] / [refresh] both read the community id from
     * there. On a fresh instance they silently no-opped; on a second
     * conversation they addressed the FIRST one, which means a draft written
     * to Bob could be committed, signed and replicated into the room with
     * Alice. A message is an attestation: there is no unsend.
     *
     * `start_chat` returns BEFORE any write when the community exists
     * (`lookup_community` → `freshly_created: false`), so for an open room this
     * is a read, and it is the only read that answers with the authoritative
     * roster the header needs. The contact card's `chat_started` is therefore
     * advisory, not load bearing — one fewer client-side guess that can be
     * wrong.
     *
     * The reset below is SYNCHRONOUS and happens before the first suspension
     * point: between navigating and `startChat` returning there is a window in
     * which the composer is live, and a stale [_community] in that window is
     * the same wrong-room send by another route.
     */
    fun enter(communityId: String, contactKeyId: String) {
        // Both of these are SYNCHRONOUS and happen before any suspension point.
        val epoch = nextEpoch()
        entryJob?.cancel()
        if (_community.value?.communityId != communityId) {
            _community.value = null
            _messages.value = emptyList()
            _transcriptLoaded.value = false
            // The draft belongs to the room it was written in, not to the screen.
            _draft.value = ""
        }
        entryJob = viewModelScope.launch {
            clearRefusal()
            val opened = callTyped("startChat") { apiClient.startChat(contactKeyId) } ?: return@launch
            if (epoch != entryEpoch) {
                // A newer room was entered while this one was opening. Publishing
                // now is the wrong-room send.
                PlatformLogger.i(
                    tag,
                    "[enter] discarding stale open for ${opened.communityId.take(24)}… " +
                        "(epoch $epoch != $entryEpoch)",
                )
                return@launch
            }
            _community.value = opened
            PlatformLogger.i(
                tag,
                "[enter] community=${opened.communityId.take(24)}… fresh=${opened.freshlyCreated}",
            )
            loadMessages(opened.communityId, epoch)
        }
    }

    /** Re-read the transcript for the community currently open. */
    fun refresh() {
        val id = _community.value?.communityId ?: return
        val epoch = entryEpoch
        viewModelScope.launch { loadMessages(id, epoch) }
    }

    fun setDraft(text: String) {
        _draft.value = text
    }

    /**
     * Send the draft.
     *
     * A `null` `message` in the response is a SUCCESS — the row landed and only
     * the read-back projection did not resolve — so the draft is cleared and the
     * list refreshed either way. Reporting a failed send there would be a lie
     * about a committed write.
     */
    fun send() {
        val id = _community.value?.communityId ?: return
        val text = _draft.value
        if (text.isBlank()) return
        viewModelScope.launch {
            _sending.value = true
            clearRefusal()
            try {
                val result = apiClient.sendChatMessage(id, text)
                _draft.value = ""
                if (result.message != null) {
                    PlatformLogger.i(tag, "[send] ${result.attestationId.take(24)}… projected")
                } else {
                    PlatformLogger.i(
                        tag,
                        "[send] ${result.attestationId.take(24)}… landed; read-back deferred — refreshing",
                    )
                }
                loadMessages(id, entryEpoch)
            } catch (e: NodeRefusal) {
                recordRefusal("send", e)
            } catch (e: Exception) {
                _refusalDetail.value = e.message ?: e::class.simpleName
                PlatformLogger.e(tag, "[send] ${e.message}", e)
            } finally {
                _sending.value = false
            }
        }
    }

    /** Acknowledge a refusal after the user sees it. */
    fun clearRefusal() {
        _refusalReasonId.value = null
        _refusalDetail.value = null
    }

    // ─── Internals ────────────────────────────────────────────────────────────

    /**
     * Read the transcript for [communityId] and publish it ONLY if [epoch] is
     * still the current entry (see [entryEpoch]) — otherwise A's history paints
     * under B's header.
     */
    private suspend fun loadMessages(communityId: String, epoch: Long) {
        _loading.value = true
        try {
            val transcript = apiClient.listChatMessages(communityId)
            if (epoch != entryEpoch) {
                PlatformLogger.i(
                    tag,
                    "[listChatMessages] discarding stale transcript for " +
                        "${communityId.take(24)}… (epoch $epoch != $entryEpoch)",
                )
                return
            }
            // Server order, verbatim: oldest first, by the SIGNED asserted_at.
            _messages.value = transcript.messages
        } catch (e: NodeRefusal) {
            if (epoch == entryEpoch) recordRefusal("listChatMessages", e)
        } catch (e: Exception) {
            if (epoch == entryEpoch) {
                _refusalDetail.value = e.message ?: e::class.simpleName
                PlatformLogger.e(tag, "[listChatMessages] ${e.message}", e)
            }
        } finally {
            // A superseded load must not clear the NEW room's spinner or claim
            // its transcript arrived.
            if (epoch == entryEpoch) {
                _loading.value = false
                _transcriptLoaded.value = true
            }
        }
    }

    private suspend fun <T> callTyped(operation: String, block: suspend () -> T): T? = try {
        _loading.value = true
        block()
    } catch (e: NodeRefusal) {
        recordRefusal(operation, e)
        null
    } catch (e: Exception) {
        _refusalDetail.value = e.message ?: e::class.simpleName
        PlatformLogger.e(tag, "[$operation] ${e.message}", e)
        null
    } finally {
        _loading.value = false
    }

    private fun recordRefusal(operation: String, e: NodeRefusal) {
        _refusalReasonId.value = e.reasonId
        _refusalDetail.value = e.detail
        PlatformLogger.w(
            tag,
            "[$operation] refused reason_id=${e.reasonId ?: "<none>"} status=${e.statusCode}",
        )
    }
}
