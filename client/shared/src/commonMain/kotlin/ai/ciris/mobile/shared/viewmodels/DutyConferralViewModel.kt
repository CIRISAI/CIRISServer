package ai.ciris.mobile.shared.viewmodels

import ai.ciris.mobile.shared.api.CIRISApiClient
import ai.ciris.mobile.shared.platform.PlatformLogger
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.serialization.json.JsonElement

/**
 * Drives the **Delegate moderation duty** card — conferring `slash` / `moderate` /
 * `review` on another self, with an explicit answer to "may they pass it on, and
 * how far?".
 *
 * Two loopback + owner-gated routes, the accord co-scrub shape:
 *  - [propose] mints the FIRST scrub. The returned `partial` does NOT yet confer
 *    the duty (it is 1 of `quorum_needed`).
 *  - [cosign] appends THIS holder's scrub to that partial. When
 *    [scrubCount] meets [quorumNeeded] the node flips [adopted] and the duty is
 *    conferred.
 *
 * The `partial` is OPAQUE: it is held as a raw [JsonElement] and handed back to
 * the node byte-for-byte, because the envelope's signature covers its exact
 * bytes. The app never re-encodes it and never reads its internals.
 *
 * ARCHITECTURE: the app holds NO keys and performs NO crypto. It supplies the
 * holder's key_id + ML-DSA USB path; the LOCAL node opens the hardware and signs
 * (the YubiKey touch is the consent).
 */
class DutyConferralViewModel(
    private val apiClient: CIRISApiClient,
) : ViewModel() {

    companion object {
        private const val TAG = "DutyConferralVM"

        /** The duty verbs the node accepts. */
        const val DUTY_SLASH = "slash"
        const val DUTY_MODERATE = "moderate"
        const val DUTY_REVIEW = "review"

        /** The global sub-delegation rail — a null depth is bounded by THIS. */
        const val GLOBAL_DEPTH_RAIL = 5
    }

    // ── The conferral being composed ─────────────────────────────────────────

    /** The self the duty is conferred ON. */
    private val _subjectKeyId = MutableStateFlow("")
    val subjectKeyId: StateFlow<String> = _subjectKeyId.asStateFlow()

    /** `slash` | `moderate` | `review`. */
    private val _duty = MutableStateFlow(DUTY_MODERATE)
    val duty: StateFlow<String> = _duty.asStateFlow()

    /** May the subject pass the duty on at all? */
    private val _subDelegation = MutableStateFlow(false)
    val subDelegation: StateFlow<Boolean> = _subDelegation.asStateFlow()

    /** Further hops allowed; null = bounded only by [GLOBAL_DEPTH_RAIL]. */
    private val _subDelegationDepth = MutableStateFlow<Int?>(null)
    val subDelegationDepth: StateFlow<Int?> = _subDelegationDepth.asStateFlow()

    // ── The signing holder ───────────────────────────────────────────────────

    /** The accord holder's seal alias (its YubiKey + USB ML-DSA opens it). */
    private val _holderKeyId = MutableStateFlow("")
    val holderKeyId: StateFlow<String> = _holderKeyId.asStateFlow()

    /** The folder holding the USB-wrapped ML-DSA half. */
    private val _usbPath = MutableStateFlow("")
    val usbPath: StateFlow<String> = _usbPath.asStateFlow()

    // ── Co-scrub progress ────────────────────────────────────────────────────

    /** The opaque partial — round-tripped VERBATIM into the next [cosign]. */
    private val _partial = MutableStateFlow<JsonElement?>(null)
    val partial: StateFlow<JsonElement?> = _partial.asStateFlow()

    private val _scrubCount = MutableStateFlow(0)
    val scrubCount: StateFlow<Int> = _scrubCount.asStateFlow()

    private val _quorumNeeded = MutableStateFlow(0)
    val quorumNeeded: StateFlow<Int> = _quorumNeeded.asStateFlow()

    /** True once the conferral met quorum — the duty is conferred. */
    private val _adopted = MutableStateFlow(false)
    val adopted: StateFlow<Boolean> = _adopted.asStateFlow()

    /**
     * What the adopted grant says, in the node's own words ("moderate conferred on
     * X; sub-delegation: 2 hops"). Read-back beats inference: the operator sees the
     * sentence the node signed, not the one the form implied.
     */
    private val _conferred = MutableStateFlow<String?>(null)
    val conferred: StateFlow<String?> = _conferred.asStateFlow()

    private val _inProgress = MutableStateFlow(false)
    val inProgress: StateFlow<Boolean> = _inProgress.asStateFlow()

    private val _error = MutableStateFlow<String?>(null)
    val error: StateFlow<String?> = _error.asStateFlow()

    // ── Field setters (the card is a form; the VM owns its state) ────────────

    fun setSubjectKeyId(value: String) {
        _subjectKeyId.value = value
    }

    fun setDuty(value: String) {
        _duty.value = value
    }

    fun setHolderKeyId(value: String) {
        _holderKeyId.value = value
    }

    fun setUsbPath(value: String) {
        _usbPath.value = value
    }

    /**
     * Set the delegation-depth choice. The two axes move TOGETHER — "leaf" is
     * (false, null); "N further hops" is (true, N); "unbounded" is (true, null),
     * i.e. bounded only by the global rail. Setting them independently is how a
     * client ends up asking for "no sub-delegation, depth 3".
     */
    fun setDelegationDepth(subDelegation: Boolean, depth: Int?) {
        _subDelegation.value = subDelegation
        _subDelegationDepth.value = if (subDelegation) depth else null
    }

    /**
     * Replace the partial (e.g. one pasted / handed over from the holder who
     * proposed it on another device), so THIS holder can [cosign] it.
     */
    fun setPartial(value: JsonElement?) {
        _partial.value = value
    }

    fun clearError() {
        _error.value = null
    }

    /** Drop the in-flight conferral and start a fresh one. */
    fun reset() {
        _partial.value = null
        _scrubCount.value = 0
        _quorumNeeded.value = 0
        _adopted.value = false
        _conferred.value = null
        _error.value = null
    }

    // ── The two round-trips ──────────────────────────────────────────────────

    /**
     * Scrub #1 — confer the duty. The result is a partial that still needs
     * [quorumNeeded] − 1 more holder scrubs before it takes effect.
     */
    fun propose() {
        val subject = _subjectKeyId.value.trim()
        val holder = _holderKeyId.value.trim()
        val usb = _usbPath.value.trim()
        if (subject.isEmpty()) {
            _error.value = "Enter the fed-ID (key_id) of the self you're conferring the duty on."
            return
        }
        if (holder.isEmpty() || usb.isEmpty()) {
            _error.value = "Enter the accord holder's key_id and the ML-DSA USB folder — the node signs with them."
            return
        }
        if (_inProgress.value) return
        _inProgress.value = true
        _error.value = null
        viewModelScope.launch {
            try {
                val result = apiClient.proposeDutyConferral(
                    holderKeyId = holder,
                    mldsaUsbPath = usb,
                    subjectKeyId = subject,
                    duty = _duty.value,
                    subDelegation = _subDelegation.value,
                    subDelegationDepth = _subDelegationDepth.value,
                )
                applyResult(result)
            } catch (e: Exception) {
                PlatformLogger.w(TAG, "[propose] ${e.message}")
                _error.value = friendly(e, "Couldn't propose the duty conferral")
            } finally {
                _inProgress.value = false
            }
        }
    }

    /**
     * Append THIS holder's scrub to the pending [partial]. The partial goes back
     * to the node UNCHANGED — the signature covers its exact bytes.
     */
    fun cosign() {
        val pending = _partial.value
        val holder = _holderKeyId.value.trim()
        val usb = _usbPath.value.trim()
        if (pending == null) {
            _error.value = "There's nothing to cosign yet — propose the conferral first (or paste a partial)."
            return
        }
        if (holder.isEmpty() || usb.isEmpty()) {
            _error.value = "Enter the accord holder's key_id and the ML-DSA USB folder — the node signs with them."
            return
        }
        if (_inProgress.value) return
        _inProgress.value = true
        _error.value = null
        viewModelScope.launch {
            try {
                val result = apiClient.cosignDutyConferral(
                    holderKeyId = holder,
                    mldsaUsbPath = usb,
                    partial = pending,
                )
                applyResult(result)
            } catch (e: Exception) {
                PlatformLogger.w(TAG, "[cosign] ${e.message}")
                _error.value = friendly(e, "Couldn't cosign the duty conferral")
            } finally {
                _inProgress.value = false
            }
        }
    }

    /** Both routes answer the same body — one place absorbs it. */
    private fun applyResult(result: ai.ciris.mobile.shared.models.federation.DutyConferralResponse) {
        // Keep the last good partial when a response omits it (adopted records
        // have nothing left to hand on).
        result.partial?.let { _partial.value = it }
        _scrubCount.value = result.scrubCount
        _quorumNeeded.value = result.quorumNeeded
        _adopted.value = result.adopted
        _conferred.value = result.conferred
    }

    /** Map the transport failure onto something the operator can act on. */
    private fun friendly(e: Exception, prefix: String): String {
        val msg = e.message.orEmpty()
        return when {
            msg.contains("401") || msg.contains("403") ->
                "Sign in as the owner on this node first — conferring a duty is owner-gated."
            msg.contains("404") ->
                "This node doesn't serve the duty routes yet — update the node."
            msg.contains("timed out", ignoreCase = true) || msg.contains("Timeout", ignoreCase = true) ->
                "Timed out waiting for the holder's key — touch it when it blinks and retry."
            else -> "$prefix: ${e.message}"
        }
    }
}
