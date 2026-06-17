package ai.ciris.fabric.ui.screens

import ai.ciris.fabric.model.identity.LocalIdentityAggregate
import ai.ciris.fabric.viewmodel.IdentityViewModel
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp

/**
 * The PROVEN slice's screen: renders the node's six-key federation identity
 * (`GET /v1/identity`).
 *
 * Adapted from the CIRISAgent client's `NetworkIdentityScreen` "Federation ID
 * card" section, stripped of the agent-card chrome (node-code QR + identity
 * card it also rendered are deferred to the registry slice). Shows the three
 * key roles + the persist continuity fields (did_key / identity_hash).
 */
@Composable
fun IdentityScreen(viewModel: IdentityViewModel) {
    val state by viewModel.state.collectAsState()

    LaunchedEffect(Unit) { viewModel.load() }

    Column(
        modifier = Modifier.fillMaxWidth().padding(16.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Node Identity", style = MaterialTheme.typography.headlineSmall)
        Text(
            "Six-key federation identity — GET /v1/identity",
            style = MaterialTheme.typography.bodySmall,
        )

        when {
            state.loading -> CircularProgressIndicator()
            state.error != null -> {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(16.dp)) {
                        Text("Failed to load identity", style = MaterialTheme.typography.titleMedium)
                        Text(state.error ?: "", style = MaterialTheme.typography.bodySmall)
                    }
                }
                Button(onClick = { viewModel.load() }) { Text("Retry") }
            }
            state.identity != null -> IdentityCard(state.identity!!)
        }
    }
}

@Composable
private fun IdentityCard(id: LocalIdentityAggregate) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            KeyRow("key_id", id.keyId)
            KeyRow("aggregate_version", id.aggregateVersion.toString())

            Text("Signing", style = MaterialTheme.typography.titleSmall)
            KeyRow("ed25519", id.ed25519PubkeyB64)
            KeyRow("ml-dsa-65 (PQC)", id.mlDsa65PubkeyB64 ?: "—")
            KeyRow("pqc_key_id", id.pqcKeyId ?: "—")

            Text("Reticulum transport", style = MaterialTheme.typography.titleSmall)
            KeyRow("x25519", id.reticulumX25519PubkeyB64 ?: "—")
            KeyRow("ed25519", id.reticulumEd25519PubkeyB64 ?: "—")

            Text("Content encryption", style = MaterialTheme.typography.titleSmall)
            KeyRow("x25519", id.contentX25519PubkeyB64 ?: "—")
            KeyRow("ml-kem-768 (PQC)", id.contentMlKem768PubkeyB64 ?: "—")

            Text("Continuity", style = MaterialTheme.typography.titleSmall)
            KeyRow("did_key", id.didKey ?: "—")
            KeyRow("identity_hash", id.identityHash ?: "—")
        }
    }
}

@Composable
private fun KeyRow(label: String, value: String) {
    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, style = MaterialTheme.typography.labelMedium)
        Text(
            value,
            style = MaterialTheme.typography.bodySmall,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.padding(start = 12.dp),
        )
    }
}
