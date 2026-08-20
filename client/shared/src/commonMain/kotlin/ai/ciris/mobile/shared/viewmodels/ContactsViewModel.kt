package ai.ciris.mobile.shared.viewmodels

import ai.ciris.mobile.shared.api.CIRISApiClient
import ai.ciris.mobile.shared.api.NodeRefusal
import ai.ciris.mobile.shared.models.federation.Contact
import ai.ciris.mobile.shared.models.federation.LocalPeerState
import ai.ciris.mobile.shared.platform.PlatformLogger
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * Drives the **Contacts** screen, which serves two different questions from two
 * different routes — deliberately, because they are two different sets.
 *
 *  - **Browse mode** — ``GET /v1/contacts``: the people the owner has actually
 *    consented to replicate with. This is the node client's HOME surface, so
 *    "who can I talk to" must not be answered with "every key this node has
 *    ever seen announced".
 *  - **Picker mode** (Delegations) — ``GET /v1/federation/peers``: any KNOWN
 *    identity. A delegation target need not be a contact, and narrowing the
 *    picker to contacts would silently remove valid targets.
 *
 * Contacts ⊂ peers, so the two lists are not interchangeable in either
 * direction. The contact set is persist's revocation-FOLDED consent peer set —
 * a withdrawn grant is already absent, which is why there is no "remove
 * contact" call here to pair with [addContact].
 */
class ContactsViewModel(
    apiClient: CIRISApiClient,
) : BaseFederationViewModel(apiClient) {

    override val tag: String = "ContactsVM"

    // ── Contacts (browse mode — GET /v1/contacts) ────────────────────────────

    private val _allContacts = MutableStateFlow<List<Contact>>(emptyList())

    private val _contacts = MutableStateFlow<List<Contact>>(emptyList())
    val contacts: StateFlow<List<Contact>> = _contacts.asStateFlow()

    /** True once a contacts load has completed — tells "empty" from "not asked yet". */
    private val _contactsLoaded = MutableStateFlow(false)
    val contactsLoaded: StateFlow<Boolean> = _contactsLoaded.asStateFlow()

    // ── Raw peer list (picker mode — all, unsearched) ────────────────────────

    private val _allPeers = MutableStateFlow<List<LocalPeerState>>(emptyList())

    // ── Search query (applies to whichever list is showing) ──────────────────

    private val _searchQuery = MutableStateFlow("")
    val searchQuery: StateFlow<String> = _searchQuery.asStateFlow()

    // ── Filtered peer view (recomputed whenever _allPeers or _searchQuery changes) ─

    private val _peers = MutableStateFlow<List<LocalPeerState>>(emptyList())
    val peers: StateFlow<List<LocalPeerState>> = _peers.asStateFlow()

    // ── Selection (used in picker mode) ──────────────────────────────────────

    private val _selectedPeer = MutableStateFlow<LocalPeerState?>(null)
    val selectedPeer: StateFlow<LocalPeerState?> = _selectedPeer.asStateFlow()

    // ── Add-a-contact ────────────────────────────────────────────────────────

    private val _addBusy = MutableStateFlow(false)
    val addBusy: StateFlow<Boolean> = _addBusy.asStateFlow()

    /**
     * The node's typed `reason_id` for the last add refusal, or null.
     *
     * Kept BESIDE [addError] rather than folded into it: the id is what lets the
     * screen tell `contacts.unknown_fed_id` ("admit the key first") from
     * `contacts.self_contact` ("that is you") from `contacts.store_unavailable`
     * ("the node could not answer"), and those have nothing in common but the
     * colour red.
     */
    private val _addRefusalReasonId = MutableStateFlow<String?>(null)
    val addRefusalReasonId: StateFlow<String?> = _addRefusalReasonId.asStateFlow()

    /** The node's English fallback for the last add refusal, or null. */
    private val _addError = MutableStateFlow<String?>(null)
    val addError: StateFlow<String?> = _addError.asStateFlow()

    /** The contact key_id most recently added — one-shot, consumed by the screen. */
    private val _justAdded = MutableStateFlow<Contact?>(null)
    val justAdded: StateFlow<Contact?> = _justAdded.asStateFlow()

    init {
        load()
    }

    /** Initial load — idempotent; safe to call from a LaunchedEffect. */
    fun load() {
        refresh()
    }

    /** Pull a fresh contact list AND peer list from the node. */
    fun refresh() {
        refreshContacts()
        refreshPeers()
    }

    /** Pull a fresh contact list (browse mode). */
    fun refreshContacts() {
        viewModelScope.launch {
            runApi("listContacts") { apiClient.listContacts() }?.let { resp ->
                _allContacts.value = sortedContacts(resp.contacts)
                applySearch()
            }
            // Loaded means "the question was asked", success or not — an empty
            // list after a failed call must not render as "you have no contacts".
            _contactsLoaded.value = true
        }
    }

    /** Pull a fresh peer list from the node (picker mode). */
    fun refreshPeers() {
        viewModelScope.launch {
            runApi("listFederationPeers") {
                apiClient.listFederationPeers()
            }?.let { resp ->
                _allPeers.value = sortedPeers(resp.peers)
                applySearch()
            }
        }
    }

    /** Update the search query and refilter both lists locally. */
    fun setSearchQuery(q: String) {
        _searchQuery.value = q
        applySearch()
    }

    /** Set (or clear) the picked identity. */
    fun selectPeer(peer: LocalPeerState?) {
        _selectedPeer.value = peer
    }

    /**
     * Add a contact by fedID. On success the list is refreshed and [justAdded]
     * carries the new contact so the screen can offer to open the chat.
     *
     * Refusals land in [addRefusalReasonId] + [addError] rather than the shared
     * [error] channel, so a failed add does not blank the list the user is
     * looking at.
     */
    fun addContact(keyId: String) {
        val trimmed = keyId.trim()
        if (trimmed.isEmpty()) return
        viewModelScope.launch {
            _addBusy.value = true
            _addRefusalReasonId.value = null
            _addError.value = null
            try {
                val added = apiClient.addContact(trimmed)
                PlatformLogger.i(
                    tag,
                    "[addContact] ${trimmed.take(16)}… freshly_emitted=${added.freshlyEmitted}",
                )
                refreshContacts()
                _justAdded.value = Contact(
                    keyId = added.keyId,
                    chatCommunityId = added.chatCommunityId,
                    occurrenceKeyIds = added.occurrenceKeyIds,
                )
            } catch (e: NodeRefusal) {
                _addRefusalReasonId.value = e.reasonId
                _addError.value = e.detail
                PlatformLogger.w(
                    tag,
                    "[addContact] refused reason_id=${e.reasonId ?: "<none>"} status=${e.statusCode}",
                )
            } catch (e: Exception) {
                _addError.value = e.message ?: e::class.simpleName
                PlatformLogger.e(tag, "[addContact] ${e.message}", e)
            } finally {
                _addBusy.value = false
            }
        }
    }

    /** Acknowledge the one-shot [justAdded] after the screen has acted on it. */
    fun consumeJustAdded() {
        _justAdded.value = null
    }

    /** Acknowledge an add refusal after the user sees it. */
    fun clearAddError() {
        _addRefusalReasonId.value = null
        _addError.value = null
    }

    // ─── Internals ────────────────────────────────────────────────────────────

    private fun applySearch() {
        val q = _searchQuery.value.trim().lowercase()
        _peers.value = if (q.isEmpty()) {
            _allPeers.value
        } else {
            _allPeers.value.filter { peer ->
                peer.keyId.lowercase().contains(q) ||
                    (peer.aliasOverride?.lowercase()?.contains(q) == true) ||
                    (peer.notes?.lowercase()?.contains(q) == true) ||
                    peer.trust.wire.contains(q) ||
                    peer.pubkeyEd25519Base64.lowercase().contains(q)
            }
        }
        _contacts.value = if (q.isEmpty()) {
            _allContacts.value
        } else {
            _allContacts.value.filter { c ->
                c.keyId.lowercase().contains(q) ||
                    (c.aliasOverride?.lowercase()?.contains(q) == true) ||
                    (c.notes?.lowercase()?.contains(q) == true) ||
                    c.trust.wire.contains(q) ||
                    (c.pubkeyEd25519Base64?.lowercase()?.contains(q) == true)
            }
        }
        PlatformLogger.d(
            tag,
            "applySearch q=${q.take(20)} → ${_peers.value.size}/${_allPeers.value.size} peers, " +
                "${_contacts.value.size}/${_allContacts.value.size} contacts",
        )
    }

    companion object {
        /**
         * Canonical peers first; within each group sort trusted > unknown >
         * untrusted > blocked, then most-recently-seen first.
         */
        private fun trustPriority(peer: LocalPeerState): Int = when (peer.trust) {
            ai.ciris.mobile.shared.models.federation.PeerTrustState.TRUSTED -> 0
            ai.ciris.mobile.shared.models.federation.PeerTrustState.UNKNOWN -> 1
            ai.ciris.mobile.shared.models.federation.PeerTrustState.UNTRUSTED -> 2
            ai.ciris.mobile.shared.models.federation.PeerTrustState.BLOCKED -> 3
        }

        fun sortedPeers(peers: List<LocalPeerState>): List<LocalPeerState> =
            peers.sortedWith(
                compareByDescending<LocalPeerState> { it.canonical }
                    .thenBy { trustPriority(it) }
                    .thenByDescending { it.lastSeen?.toEpochMilliseconds() ?: 0L },
            )

        /**
         * Open conversations first (a started chat is the thing the user came
         * for), then most-recently-seen, then by key_id so the order is stable
         * across refreshes when nothing else separates two rows.
         */
        fun sortedContacts(contacts: List<Contact>): List<Contact> =
            contacts.sortedWith(
                compareByDescending<Contact> { it.chatStarted }
                    .thenByDescending { it.lastSeen?.toEpochMilliseconds() ?: 0L }
                    .thenBy { it.keyId },
            )
    }
}
