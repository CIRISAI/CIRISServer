package ai.ciris.fabric.viewmodel

import ai.ciris.fabric.model.identity.LocalIdentityAggregate
import ai.ciris.fabric.net.FabricClient
import ai.ciris.fabric.platform.PlatformLogger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * The PROVEN slice's view-model: loads the node's six-key identity from
 * `GET /v1/identity` and exposes it as UI state.
 *
 * Adapted from the CIRISAgent client's `NetworkIdentityViewModel`, reduced to
 * the single round-trip CIRISServer actually serves today (the agent client
 * made three: identity-card + node-code + aggregate; CIRISServer exposes the
 * aggregate directly at /v1/identity, the other two arrive with the registry
 * slice). Plain coroutines + StateFlow so it has no UI-framework coupling.
 */
class IdentityViewModel(
    private val client: FabricClient,
    private val scope: CoroutineScope,
) {
    data class UiState(
        val loading: Boolean = false,
        val identity: LocalIdentityAggregate? = null,
        val error: String? = null,
    )

    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    fun load() {
        _state.value = _state.value.copy(loading = true, error = null)
        scope.launch {
            try {
                val identity = client.getIdentity()
                _state.value = UiState(loading = false, identity = identity)
                PlatformLogger.i(TAG, "identity loaded: key_id=${identity.keyId}")
            } catch (e: Throwable) {
                _state.value = UiState(loading = false, error = e.message ?: "unknown error")
                PlatformLogger.e(TAG, "identity load failed", e)
            }
        }
    }

    companion object {
        private const val TAG = "IdentityViewModel"
    }
}
