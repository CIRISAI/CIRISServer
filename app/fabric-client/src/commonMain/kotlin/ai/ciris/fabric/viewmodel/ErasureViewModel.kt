package ai.ciris.fabric.viewmodel

import ai.ciris.fabric.model.federation.WithdrawReceipt
import ai.ciris.fabric.net.FabricClient
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * View-model for the CEG-native erasure (right-to-be-forgotten) surface.
 *
 * The data subject lists the content_ids they authored and emits a signed
 * withdrawal; the substrate §19.7 hard-deletes and (optionally) propagates.
 *
 * SCAFFOLD: [submit] calls [FabricClient.withdrawContent], which is itself
 * scaffolded (TODO marks the unwritten POST /v1/erasure/withdraw — the endpoint
 * lands with the node slice, Server 1.0). The UI flow, validation, and signed-
 * write requirement are real; only the network round-trip is pending.
 */
class ErasureViewModel(
    private val client: FabricClient,
    private val subjectKeyId: String?,
    private val scope: CoroutineScope,
) {
    data class UiState(
        val contentIdsInput: String = "",
        val reason: String = "",
        val propagate: Boolean = true,
        val submitting: Boolean = false,
        val receipt: WithdrawReceipt? = null,
        val error: String? = null,
    ) {
        /** Parsed, non-blank content ids (one per line / comma). */
        val contentIds: List<String>
            get() = contentIdsInput.split('\n', ',').map { it.trim() }.filter { it.isNotEmpty() }

        /** A signed withdrawal needs a subject key AND at least one content id. */
        val canSubmit: Boolean
            get() = !submitting && contentIds.isNotEmpty()
    }

    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    fun onContentIdsChange(v: String) { _state.value = _state.value.copy(contentIdsInput = v) }
    fun onReasonChange(v: String) { _state.value = _state.value.copy(reason = v) }
    fun onPropagateChange(v: Boolean) { _state.value = _state.value.copy(propagate = v) }

    fun submit() {
        val s = _state.value
        if (!s.canSubmit) return
        if (subjectKeyId == null) {
            _state.value = s.copy(error = "No federation signing key — a withdrawal is a SIGNED write and cannot be emitted unauthenticated.")
            return
        }
        _state.value = s.copy(submitting = true, error = null, receipt = null)
        scope.launch {
            try {
                val receipt = client.withdrawContent(
                    contentIds = s.contentIds,
                    subjectKeyId = subjectKeyId,
                    reason = s.reason.ifBlank { null },
                    propagateToReplicas = s.propagate,
                )
                _state.value = _state.value.copy(submitting = false, receipt = receipt)
            } catch (e: Throwable) {
                _state.value = _state.value.copy(submitting = false, error = e.message ?: "withdrawal failed")
            }
        }
    }
}
