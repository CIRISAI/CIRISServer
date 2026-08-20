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
     * Open (or re-open) the room with [contactKeyId], then load the transcript.
     *
     * `POST /v1/chat` is idempotent on the DERIVED pair id, so this is also the
     * safe way to re-enter an existing conversation.
     */
    fun open(contactKeyId: String) {
        viewModelScope.launch {
            clearRefusal()
            val opened = callTyped("startChat") { apiClient.startChat(contactKeyId) } ?: return@launch
            _community.value = opened
            PlatformLogger.i(
                tag,
                "[open] community=${opened.communityId.take(24)}… fresh=${opened.freshlyCreated}",
            )
            loadMessages(opened.communityId)
        }
    }

    /**
     * Enter a room whose id is already known (a contact card carries the derived
     * `chat_community_id` whether or not the room exists yet).
     *
     * [alsoStart] is what handles the "not yet" case: the transcript route
     * refuses `chat.unknown_community` for a room that was never opened, and
     * opening it is exactly what the user asked for by tapping the contact.
     */
    fun enter(communityId: String, contactKeyId: String, alsoStart: Boolean) {
        if (alsoStart) {
            open(contactKeyId)
        } else {
            viewModelScope.launch {
                clearRefusal()
                loadMessages(communityId)
            }
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
