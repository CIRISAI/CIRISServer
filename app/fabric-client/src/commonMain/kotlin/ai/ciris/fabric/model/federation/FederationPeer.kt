package ai.ciris.fabric.model.federation

import kotlinx.datetime.Instant
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

// Copied from the CIRISAgent KMP client (models/federation/{FederationPeer,
// LocalPeerState}.kt), repackaged into ai.ciris.fabric. Field/@SerialName layout
// is preserved verbatim so the wire shape matches the federation-directory
// surface CIRISServer's registry slice (Server 0.5) will expose. SCAFFOLD until
// compose_registry lands.

/** Trust state of a federation peer — locked vocabulary; lowercase wire. */
@Serializable
enum class PeerTrustState {
    @SerialName("trusted") TRUSTED,
    @SerialName("untrusted") UNTRUSTED,
    @SerialName("blocked") BLOCKED,
    @SerialName("unknown") UNKNOWN,
    ;

    val wire: String
        get() = when (this) {
            TRUSTED -> "trusted"; UNTRUSTED -> "untrusted"
            BLOCKED -> "blocked"; UNKNOWN -> "unknown"
        }

    companion object {
        fun fromWire(s: String?): PeerTrustState = when (s?.lowercase()) {
            "trusted" -> TRUSTED; "untrusted" -> UNTRUSTED
            "blocked" -> BLOCKED; else -> UNKNOWN
        }
    }
}

/** Per-peer (icon, fg, bg) appearance — local-user owned, never wire-trusted. */
@Serializable
data class PeerAppearance(
    val icon: String? = null,
    @SerialName("fg_color") val fgColor: String? = null,
    @SerialName("bg_color") val bgColor: String? = null,
)

/** Persisted local state for one federation peer (canonical or organic). */
@Serializable
data class LocalPeerState(
    @SerialName("key_id") val keyId: String,
    @SerialName("pubkey_ed25519_base64") val pubkeyEd25519Base64: String,
    val canonical: Boolean,
    val trust: PeerTrustState,
    @SerialName("first_seen") val firstSeen: Instant,
    val appearance: PeerAppearance? = null,
    @SerialName("alias_override") val aliasOverride: String? = null,
    val notes: String? = null,
    @SerialName("last_seen") val lastSeen: Instant? = null,
)

/** `GET /v1/federation/peers`. */
@Serializable
data class FederationPeerListResponse(
    val peers: List<LocalPeerState> = emptyList(),
    val total: Int = 0,
)

/** Per-transport reachability tuple `(ratio, last_ok_ts)`. */
@Serializable
data class EdgeReachabilityEntry(
    val ratio: Double,
    @SerialName("last_ok_ts") val lastOkTs: Long,
)

/** Per-medium reachability map; EMPTY = "not measured yet" (not 0.0%). */
@Serializable
data class EdgePeerReachability(
    @SerialName("by_medium") val byMedium: Map<String, EdgeReachabilityEntry> = emptyMap(),
)

/** `GET /v1/federation/peers/{key_id}`. */
@Serializable
data class FederationPeerDetailResponse(
    val peer: LocalPeerState,
    val reachability: EdgePeerReachability? = null,
)

/** Signal-style SAS for verifying a peer key out-of-band. */
@Serializable
data class FederationPeerSASResponse(
    val words: List<String>,
    val digits: String,
    @SerialName("key_id") val keyId: String,
)

/** Body for `PUT /v1/federation/peers/{key_id}/trust` — the untrust toggle. */
@Serializable
data class FederationPeerTrustUpdateRequest(val trust: PeerTrustState)
