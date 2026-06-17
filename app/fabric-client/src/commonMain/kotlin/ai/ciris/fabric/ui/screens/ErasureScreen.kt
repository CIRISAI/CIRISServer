package ai.ciris.fabric.ui.screens

import ai.ciris.fabric.viewmodel.ErasureViewModel
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
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/**
 * CEG-native erasure (GDPR right-to-be-forgotten) — the IN-APP path.
 *
 * The data subject lists the content they authored and emits a SIGNED
 * withdrawal/revocation; the substrate §19.7 hard-deletes and propagates to
 * replicas. A first-class governance surface (STEP 2 of the port), distinct
 * from a DSAR admin endpoint.
 *
 * NEW screen — the CIRISAgent client only had a coarse "delete my lens traces"
 * button in DataManagementScreen. This is the per-content, signed, mesh-aware
 * withdrawal.
 */
@Composable
fun ErasureScreen(viewModel: ErasureViewModel) {
    val state by viewModel.state.collectAsState()

    Column(
        modifier = Modifier.fillMaxWidth().padding(16.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Right to be forgotten", style = MaterialTheme.typography.headlineSmall)
        Text(
            "Emit a signed withdrawal against your own content. The substrate " +
                "hard-deletes it (§19.7) and asks replicas to drop it too.",
            style = MaterialTheme.typography.bodySmall,
        )

        OutlinedTextField(
            value = state.contentIdsInput,
            onValueChange = viewModel::onContentIdsChange,
            label = { Text("Content IDs (SHA-256, one per line)") },
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = state.reason,
            onValueChange = viewModel::onReasonChange,
            label = { Text("Reason (optional)") },
            modifier = Modifier.fillMaxWidth(),
        )
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text("Propagate to replicas (mesh hard-delete)")
            Switch(checked = state.propagate, onCheckedChange = viewModel::onPropagateChange)
        }

        Button(onClick = { viewModel.submit() }, enabled = state.canSubmit) {
            Text("Withdraw (signed)")
        }

        if (state.submitting) CircularProgressIndicator()

        state.error?.let { err ->
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp)) {
                    Text("Withdrawal failed", style = MaterialTheme.typography.titleMedium)
                    Text(err, style = MaterialTheme.typography.bodySmall)
                }
            }
        }
        state.receipt?.let { r ->
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("Erasure receipt", style = MaterialTheme.typography.titleMedium)
                    Text("receipt_id: ${r.receiptId}", style = MaterialTheme.typography.bodySmall)
                    Text("status: ${r.status}", style = MaterialTheme.typography.bodySmall)
                    Text("hard_deleted_local: ${r.hardDeletedLocal}", style = MaterialTheme.typography.bodySmall)
                    Text("replicas_notified: ${r.replicasNotified}", style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
}
