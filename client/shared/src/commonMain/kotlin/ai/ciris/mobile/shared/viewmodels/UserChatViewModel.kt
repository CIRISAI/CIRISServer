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
        if (_community.value?.communityId != communityId) {
            _community.value = null
            _messages.value = emptyList()
            _transcriptLoaded.value = false
            // The draft belongs to the room it was written in, not to the screen.
            _draft.value = ""
        }
        viewModelScope.launch {
            clearRefusal()
            val opened = callTyped("startChat") { apiClient.startChat(contactKeyId) } ?: return@launch
            _community.value = opened
            PlatformLogger.i(
                tag,
                "[enter] community=${opened.communityId.take(24)}… fresh=${opened.freshlyCreated}",
            )
            loadMessages(opened.communityId)
        }
    }

    /** Re-read the transcript for the community currently open. */
    fun refresh() {
        val id = _community.value?.communityId ?: return
        viewModelScope.launch { loadMessages(id) }
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
                loadMessages(id)
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

    private suspend fun loadMessages(communityId: String) {
        _loading.value = true
        try {
            val transcript = apiClient.listChatMessages(communityId)
            // Server order, verbatim: oldest first, by the SIGNED asserted_at.
            _messages.value = transcript.messages
        } catch (e: NodeRefusal) {
            recordRefusal("listChatMessages", e)
        } catch (e: Exception) {
            _refusalDetail.value = e.message ?: e::class.simpleName
            PlatformLogger.e(tag, "[listChatMessages] ${e.message}", e)
        } finally {
            _loading.value = false
            _transcriptLoaded.value = true
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
