package ai.ciris.fabric.model.federation

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

// Copied (slimmed) from the CIRISAgent KMP client
// (models/federation/FederationMetrics.kt). Edge metrics snapshot for the
// replication/health surface. SCAFFOLD until GET /v1/federation/metrics is
// exposed by the registry/node slice. Family sub-keys are open-ended.
@Serializable
data class FederationMetricsResponse(
    @SerialName("envelopes_sent_total") val envelopesSentTotal: Map<String, Long> = emptyMap(),
    @SerialName("envelopes_received_total") val envelopesReceivedTotal: Map<String, Long> = emptyMap(),
    @SerialName("send_failures_total") val sendFailuresTotal: Map<String, Long> = emptyMap(),
    @SerialName("verify_failures_total") val verifyFailuresTotal: Map<String, Long> = emptyMap(),
    @SerialName("durable_queue_depth") val durableQueueDepth: Map<String, Long> = emptyMap(),
    @SerialName("transport_bytes_in_total") val transportBytesInTotal: Map<String, Long> = emptyMap(),
    @SerialName("transport_bytes_out_total") val transportBytesOutTotal: Map<String, Long> = emptyMap(),
    @SerialName("peer_reachability_ratio") val peerReachabilityRatio: Map<String, Double> = emptyMap(),
    @SerialName("inline_text_subscriber_count") val inlineTextSubscriberCount: Long = 0L,
) {
    fun getEnvelopesSent(): Long = envelopesSentTotal.values.sum()
    fun getEnvelopesReceived(): Long = envelopesReceivedTotal.values.sum()
    fun getVerifyFailures(): Long = verifyFailuresTotal.values.sum()
    fun getQueueDepth(): Long = durableQueueDepth.values.sum()

    /** Mean reachability across observed (peer, medium) pairs, null if none. */
    fun meanReachabilityRatio(): Double? =
        if (peerReachabilityRatio.isEmpty()) null else peerReachabilityRatio.values.average()
}
