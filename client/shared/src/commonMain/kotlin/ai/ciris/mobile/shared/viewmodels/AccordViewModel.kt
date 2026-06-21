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

    fun clearMessages() {
        _error.value = null
        _notice.value = null
    }
}
