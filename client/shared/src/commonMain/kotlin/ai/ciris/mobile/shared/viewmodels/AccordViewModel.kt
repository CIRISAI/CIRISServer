package ai.ciris.mobile.shared.viewmodels

import ai.ciris.mobile.shared.api.CIRISApiClient
import ai.ciris.mobile.shared.models.federation.AccordFamilyDto
import ai.ciris.mobile.shared.models.federation.AccordHolderDto
import ai.ciris.mobile.shared.models.federation.AccordInvocationDto
import ai.ciris.mobile.shared.platform.PlatformLogger
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * Drives the **Accord** screen — the HUMANITY_ACCORD constitutional surface
 * (CIRISServer #41). It surfaces the entrenched accord family + its
 * `quorum:2/3` consensus protocol, the hardware-attested holder roster, and the
 * pending invocations with quorum status. The owner may **concur** on a pending
 * invocation the local holder hasn't yet signed.
 *
 * No-crypto posture (mirrors Delegations): the app drives the LOCAL node only
 * with the owner session and holds NO keys. `concur` just POSTs — the node signs
 * with the resolved local holder signer.
 */
class AccordViewModel(
    private val apiClient: CIRISApiClient,
) : ViewModel() {

    companion object {
        private const val TAG = "AccordVM"
    }

    private val _family = MutableStateFlow<AccordFamilyDto?>(null)
    val family: StateFlow<AccordFamilyDto?> = _family.asStateFlow()

    private val _holders = MutableStateFlow<List<AccordHolderDto>>(emptyList())
    val holders: StateFlow<List<AccordHolderDto>> = _holders.asStateFlow()

    private val _holderThreshold = MutableStateFlow(2)
    val holderThreshold: StateFlow<Int> = _holderThreshold.asStateFlow()

    private val _invocations = MutableStateFlow<List<AccordInvocationDto>>(emptyList())
    val invocations: StateFlow<List<AccordInvocationDto>> = _invocations.asStateFlow()

    private val _loading = MutableStateFlow(false)
    val loading: StateFlow<Boolean> = _loading.asStateFlow()

    private val _busy = MutableStateFlow(false)
    val busy: StateFlow<Boolean> = _busy.asStateFlow()

    private val _error = MutableStateFlow<String?>(null)
    val error: StateFlow<String?> = _error.asStateFlow()

    private val _notice = MutableStateFlow<String?>(null)
    val notice: StateFlow<String?> = _notice.asStateFlow()

    init {
        refresh()
    }

    /** Reload the accord family, holder roster, and pending invocations. */
    fun refresh() {
        _loading.value = true
        viewModelScope.launch {
            try {
                _family.value = apiClient.getAccordFamily()
                val holders = apiClient.getAccordHolders()
                _holders.value = holders.holders
                _holderThreshold.value = holders.threshold
                _invocations.value = apiClient.getAccordInvocations()
                // The owner's nodes — the admit-node target picker selects from these.
                _ownedNodes.value = try {
                    apiClient.getOwnedNodes().nodes.map { it.keyId }.filter { it.isNotBlank() }
                } catch (e: Exception) {
                    PlatformLogger.w(TAG, "[refresh] owned-nodes: ${e.message}")
                    emptyList()
                }
                _canonicalServers.value = try {
                    apiClient.listCanonicalServers().servers
                } catch (e: Exception) {
                    PlatformLogger.w(TAG, "[refresh] canonical-servers: ${e.message}")
                    emptyList()
                }
                _canonicalWithdrawals.value = try {
                    apiClient.listCanonicalWithdrawals().withdrawals
                } catch (e: Exception) {
                    PlatformLogger.w(TAG, "[refresh] canonical-withdrawals: ${e.message}")
                    emptyList()
                }
                _error.value = null
            } catch (e: Exception) {
                PlatformLogger.w(TAG, "[refresh] ${e.message}")
                _error.value = "Couldn't load the accord: ${e.message}"
            } finally {
                _loading.value = false
            }
        }
    }

    /**
     * Concur on a pending invocation as the local holder. Requires the owner
     * session (sign in first). The node signs with the resolved local holder
     * signer; the app sends no crypto.
     */
    fun concur(invocationKind: String, invocationId: String) {
        if (_busy.value) return
        _busy.value = true
        _error.value = null
        _notice.value = null
        viewModelScope.launch {
            try {
                val res = apiClient.concurInvocation(invocationKind, invocationId)
                _notice.value = if (res.quorumMet) {
                    "Concurred — quorum met (${res.validSigners.size} signers)."
                } else {
                    "Concurred — ${res.validSigners.size} signer(s) so far."
                }
                refresh()
            } catch (e: Exception) {
                PlatformLogger.w(TAG, "[concur] ${e.message}")
                val msg = e.message.orEmpty()
                _error.value = when {
                    msg.contains("401") -> "Sign in as the owner first, then concur."
                    msg.contains("403") -> "This node isn't a current accord holder."
                    else -> "Couldn't concur: ${e.message}"
                }
            } finally {
                _busy.value = false
            }
        }
    }

    private val _admitSavedTo = MutableStateFlow<String?>(null)
    val admitSavedTo: StateFlow<String?> = _admitSavedTo.asStateFlow()

    /** The owner's nodes (key_ids) — the admit-node target picker's options. */
    private val _ownedNodes = MutableStateFlow<List<String>>(emptyList())
    val ownedNodes: StateFlow<List<String>> = _ownedNodes.asStateFlow()

    /** The selected target node resolved to its hybrid pubkeys (from the local
     *  directory) — so the card auto-fills both pubkeys instead of a manual paste. */
    private val _resolvedTarget = MutableStateFlow<ResolvedTarget?>(null)
    val resolvedTarget: StateFlow<ResolvedTarget?> = _resolvedTarget.asStateFlow()

    data class ResolvedTarget(val keyId: String, val ed25519: String, val mldsa: String)

    /**
     * Resolve a selected owned node to its Ed25519 + ML-DSA-65 pubkeys via the LOCAL
     * directory (`GET /v1/federation/peers/{key_id}`) — no manual paste. A node
     * whose row is missing its ML-DSA half (a legacy bookmark) can't be admitted
     * until re-claimed (0.5.75 writes hybrid-complete rows).
     */
    fun resolveTargetNode(keyId: String) {
        _resolvedTarget.value = null
        if (keyId.isBlank()) return
        viewModelScope.launch {
            try {
                val peer = apiClient.getFederationPeer(keyId).peer
                val ml = peer.pubkeyMlDsa65Base64
                if (ml.isNullOrBlank()) {
                    _error.value =
                        "$keyId has no ML-DSA key in the directory yet — re-claim it first."
                } else {
                    _resolvedTarget.value = ResolvedTarget(keyId, peer.pubkeyEd25519Base64, ml)
                }
            } catch (e: Exception) {
                PlatformLogger.w(TAG, "[resolveTargetNode] ${e.message}")
                _error.value = "Couldn't load $keyId's keys: ${e.message}"
            }
        }
    }

    /**
     * **Admit a node to the trust root** (CIRISServer#140 / CIRISVerify#162). The
     * local accord holder RE-OPENS their YubiKey + USB-wrapped ML-DSA and
     * scrub-signs the target node's registration (+ emits their own
     * `steward,accord_holder` anchor); the node writes the genesis **seed object**
     * to a predictable outbox path (surfaced as [admitSavedTo]) the operator hands
     * to CIRISPersist to bake. The app sends NO crypto — the YubiKey touch IS consent.
     */
    fun admitNode(
        holderKeyId: String,
        mldsaUsbPath: String,
        targetKeyId: String,
        targetEd25519Base64: String,
        targetMlDsa65Base64: String,
        userPin: String?,
    ) {
        if (_busy.value) return
        _busy.value = true
        _error.value = null
        _notice.value = null
        _admitSavedTo.value = null
        viewModelScope.launch {
            try {
                val res = apiClient.admitNode(
                    holderKeyId = holderKeyId,
                    mldsaUsbPath = mldsaUsbPath,
                    targetKeyId = targetKeyId,
                    targetEd25519Base64 = targetEd25519Base64,
                    targetMlDsa65Base64 = targetMlDsa65Base64,
                    userPin = userPin,
                )
                _admitSavedTo.value = res.savedTo
                _notice.value =
                    "Admitted $targetKeyId — seed saved to ${res.savedTo}. Hand it to persist to bake."
                refresh()
            } catch (e: Exception) {
                PlatformLogger.w(TAG, "[admitNode] ${e.message}")
                val msg = e.message.orEmpty()
                _error.value = when {
                    msg.contains("401") || msg.contains("403") ->
                        "Sign in as the owner on this node first."
                    msg.contains("501") || msg.contains("NotSupported", ignoreCase = true) ->
                        "This build lacks pkcs11 — admit-node needs the YubiKey signer."
                    else -> "Couldn't admit the node: ${e.message}"
                }
            } finally {
                _busy.value = false
            }
        }
    }

    // ── Canonical servers (CIRISServer#164) ─────────────────────────────────
    // A canonical server is a mesh-seed anchor: a node an accord holder scrub-signed
    // AND flagged `canonical`. Mirrors the admit-node section (same YubiKey + USB
    // scrub) plus an OPTIONAL bootstrap transport address.

    private val _canonicalServers =
        MutableStateFlow<List<ai.ciris.mobile.shared.models.federation.CanonicalServerDto>>(emptyList())
    val canonicalServers: StateFlow<List<ai.ciris.mobile.shared.models.federation.CanonicalServerDto>> =
        _canonicalServers.asStateFlow()

    private val _canonicalSavedTo = MutableStateFlow<String?>(null)
    val canonicalSavedTo: StateFlow<String?> = _canonicalSavedTo.asStateFlow()

    /** The selected canonical target resolved to its hybrid pubkeys (mirrors
     *  [resolvedTarget]; separate so it doesn't collide with the admit-node picker). */
    private val _canonicalResolvedTarget = MutableStateFlow<ResolvedTarget?>(null)
    val canonicalResolvedTarget: StateFlow<ResolvedTarget?> = _canonicalResolvedTarget.asStateFlow()

    /** The withdrawn / superseded canonical servers audit log. */
    private val _canonicalWithdrawals =
        MutableStateFlow<List<ai.ciris.mobile.shared.models.federation.CanonicalWithdrawalDto>>(emptyList())
    val canonicalWithdrawals:
        StateFlow<List<ai.ciris.mobile.shared.models.federation.CanonicalWithdrawalDto>> =
        _canonicalWithdrawals.asStateFlow()

    /**
     * A canonical row the operator picked to **replace / update**: the form is
     * pre-filled with this record's key_id + both pubkeys + current IP so the
     * operator edits the IP and re-submits [addCanonicalServer] (a 1-of-N re-mint
     * that embeds the updated IP in a fresh scrubbed record). Consumed + cleared by
     * the screen (which seeds its local form state + scrolls to the add form).
     */
    data class CanonicalReplaceSeed(
        val keyId: String,
        val ed25519: String,
        val mldsa: String,
        val ip: String,
    )

    private val _canonicalReplaceTarget = MutableStateFlow<CanonicalReplaceSeed?>(null)
    val canonicalReplaceTarget: StateFlow<CanonicalReplaceSeed?> = _canonicalReplaceTarget.asStateFlow()

    /** Reload the canonical-servers roster (also refreshed on [refresh]). */
    fun loadCanonicalServers() {
        viewModelScope.launch {
            try {
                _canonicalServers.value = apiClient.listCanonicalServers().servers
            } catch (e: Exception) {
                PlatformLogger.w(TAG, "[loadCanonicalServers] ${e.message}")
            }
        }
    }

    /**
     * **Select an existing canonical server to replace / update.** Seeds the
     * add-canonical form with the row's key_id + both pubkeys (as the resolved
     * target — no owned-node re-pick needed) and its current IP, so the operator
     * only edits the IP and re-submits. A row missing its ML-DSA half can't be
     * replaced in-app (re-mint it from the owned-nodes picker instead).
     */
    fun selectCanonicalForReplace(
        server: ai.ciris.mobile.shared.models.federation.CanonicalServerDto,
    ) {
        val ml = server.pubkeyMlDsa65Base64
        if (ml.isNullOrBlank()) {
            _error.value =
                "${server.keyId} has no ML-DSA key in its record — re-mint it from the owned-nodes picker instead."
            return
        }
        val ip = server.transportHints?.firstOrNull { it.kind == "ip" }?.destination.orEmpty()
        _canonicalResolvedTarget.value = ResolvedTarget(server.keyId, server.pubkeyEd25519Base64, ml)
        _canonicalReplaceTarget.value = CanonicalReplaceSeed(server.keyId, server.pubkeyEd25519Base64, ml, ip)
    }

    /** Clear the replace seed once the screen has consumed it into its form. */
    fun clearCanonicalReplaceSeed() {
        _canonicalReplaceTarget.value = null
    }

    /**
     * **Withdraw a canonical server** (CIRISServer#164). DESTRUCTIVE — needs a
     * 2-of-3 accord proposal (a second/third holder must co-sign); a lone holder
     * cannot complete it. [proposalDigest] names the authorizing accord proposal.
     */
    fun withdrawCanonical(keyId: String, proposalDigest: String) {
        if (_busy.value) return
        if (proposalDigest.isBlank()) {
            _error.value = "Enter the 2-of-3 accord proposal digest first."
            return
        }
        _busy.value = true
        _error.value = null
        _notice.value = null
        viewModelScope.launch {
            try {
                val res = apiClient.withdrawCanonical(keyId, proposalDigest)
                _notice.value = if (res.withdrawn) {
                    "Withdrew $keyId from the trust root."
                } else {
                    "Withdrawal recorded for $keyId — awaiting the 2-of-3 quorum."
                }
                refresh()
                loadCanonicalServers()
            } catch (e: Exception) {
                PlatformLogger.w(TAG, "[withdrawCanonical] ${e.message}")
                val msg = e.message.orEmpty()
                _error.value = when {
                    msg.contains("401") || msg.contains("403") ->
                        "Sign in as the owner on this node first."
                    else -> "Couldn't withdraw the canonical server: ${e.message}"
                }
            } finally {
                _busy.value = false
            }
        }
    }

    /**
     * Resolve a selected owned node to its Ed25519 + ML-DSA-65 pubkeys for the
     * canonical-add picker (mirrors [resolveTargetNode]). A node whose row is
     * missing its ML-DSA half can't be made canonical until re-claimed.
     */
    fun resolveCanonicalTarget(keyId: String) {
        _canonicalResolvedTarget.value = null
        if (keyId.isBlank()) return
        viewModelScope.launch {
            try {
                val peer = apiClient.getFederationPeer(keyId).peer
                val ml = peer.pubkeyMlDsa65Base64
                if (ml.isNullOrBlank()) {
                    _error.value =
                        "$keyId has no ML-DSA key in the directory yet — re-claim it first."
                } else {
                    _canonicalResolvedTarget.value = ResolvedTarget(keyId, peer.pubkeyEd25519Base64, ml)
                }
            } catch (e: Exception) {
                PlatformLogger.w(TAG, "[resolveCanonicalTarget] ${e.message}")
                _error.value = "Couldn't load $keyId's keys: ${e.message}"
            }
        }
    }

    /**
     * **Add a canonical server** (CIRISServer#164). The local accord holder RE-OPENS
     * their YubiKey + USB-wrapped ML-DSA and scrub-signs the target node's
     * registration, ALSO flagging it `canonical` so it becomes a mesh-seed anchor;
     * the node writes the genesis **seed object** to a predictable outbox path
     * (surfaced as [canonicalSavedTo]) the operator hands to CIRISPersist to bake.
     * An OPTIONAL bootstrap transport ([transportKind] + [destination]) is recorded
     * as the canonical server's address. The app sends NO crypto — the touch IS consent.
     */
    fun addCanonicalServer(
        holderKeyId: String,
        mldsaUsbPath: String,
        targetKeyId: String,
        targetEd25519Base64: String,
        targetMlDsa65Base64: String,
        userPin: String?,
        transportKind: String? = null,
        destination: String? = null,
    ) {
        if (_busy.value) return
        _busy.value = true
        _error.value = null
        _notice.value = null
        _canonicalSavedTo.value = null
        viewModelScope.launch {
            try {
                val res = apiClient.addCanonicalServer(
                    holderKeyId = holderKeyId,
                    mldsaUsbPath = mldsaUsbPath,
                    targetKeyId = targetKeyId,
                    targetEd25519Base64 = targetEd25519Base64,
                    targetMlDsa65Base64 = targetMlDsa65Base64,
                    userPin = userPin,
                    transportKind = transportKind?.takeIf { it.isNotBlank() },
                    destination = destination?.takeIf { it.isNotBlank() },
                )
                _canonicalSavedTo.value = res.seedSavedTo
                _notice.value =
                    "Added canonical server ${res.canonicalKeyId}" +
                        (res.seedSavedTo?.let { " — seed saved to $it. Hand it to persist to bake." } ?: ".")
                refresh()
                loadCanonicalServers()
            } catch (e: Exception) {
                PlatformLogger.w(TAG, "[addCanonicalServer] ${e.message}")
                val msg = e.message.orEmpty()
                _error.value = when {
                    msg.contains("401") || msg.contains("403") ->
                        "Sign in as the owner on this node first."
                    msg.contains("501") || msg.contains("NotSupported", ignoreCase = true) ->
                        "This build lacks pkcs11 — add-canonical needs the YubiKey signer."
                    else -> "Couldn't add the canonical server: ${e.message}"
                }
            } finally {
                _busy.value = false
            }
        }
    }

    fun clearMessages() {
        _error.value = null
        _notice.value = null
    }
}
