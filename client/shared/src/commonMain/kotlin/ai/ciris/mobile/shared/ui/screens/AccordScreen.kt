package ai.ciris.mobile.shared.ui.screens

import ai.ciris.mobile.shared.localization.localizedString
import ai.ciris.mobile.shared.models.federation.AccordInvocationDto
import ai.ciris.mobile.shared.platform.DirectoryPickerDialog
import ai.ciris.mobile.shared.platform.testable
import ai.ciris.mobile.shared.platform.testableClickable
import ai.ciris.mobile.shared.ui.components.CIRISIcons
import androidx.compose.foundation.layout.Box
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.TextButton
import ai.ciris.mobile.shared.viewmodels.AccordViewModel
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * **Accord** — the HUMANITY_ACCORD constitutional surface (CIRISServer #41).
 *
 * A read view of the entrenched accord family + its `quorum:2/3` consensus
 * protocol, the FIPS / hardware-attested holder roster, and the pending
 * invocations with their quorum status. The owner may **concur** on a pending
 * invocation the local holder hasn't yet signed.
 *
 * Per CC 4.2.1 the three invocation kinds carry a MANDATED distinct visual
 * treatment: CONSTITUTIONAL = strong / emergency (red), notify = neutral, drill
 * = muted / test. See [invocationStyle].
 *
 * No crypto in the app: the app drives the LOCAL node only with the owner
 * session and holds no keys. `concur` just POSTs — the server signs.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AccordScreen(
    viewModel: AccordViewModel,
    onBack: () -> Unit,
    /**
     * Open the guided genesis ceremony. Shown ONLY when no accord family is
     * registered yet (i.e. `getAccordFamily()` 404s) — this is how a founder trio
     * stands up a NEW mesh's 2-of-3 human kill-switch. When a family exists the
     * roster is shown as today (no CTA).
     */
    onStartCeremony: () -> Unit = {},
) {
    val family by viewModel.family.collectAsState()
    val holders by viewModel.holders.collectAsState()
    val holderThreshold by viewModel.holderThreshold.collectAsState()
    val invocations by viewModel.invocations.collectAsState()
    val loading by viewModel.loading.collectAsState()
    val busy by viewModel.busy.collectAsState()
    val error by viewModel.error.collectAsState()
    val notice by viewModel.notice.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(localizedString("mobile.accord_title")) },
                navigationIcon = {
                    IconButton(
                        onClick = onBack,
                        modifier = Modifier.testableClickable("btn_accord_back") { onBack() },
                    ) {
                        Icon(CIRISIcons.arrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { pad ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(pad)
                .padding(horizontal = 16.dp)
                .verticalScroll(rememberScrollState()),
        ) {
            Spacer(Modifier.height(8.dp))
            Text(
                text = localizedString("mobile.accord_subtitle"),
                fontSize = 13.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            // ── Messages ─────────────────────────────────────────────────────
            notice?.let { msg ->
                Spacer(Modifier.height(8.dp))
                Surface(
                    shape = RoundedCornerShape(10.dp),
                    color = MaterialTheme.colorScheme.secondaryContainer,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        msg,
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.onSecondaryContainer,
                        modifier = Modifier.padding(10.dp).testable("accord_notice"),
                    )
                }
            }
            error?.let { msg ->
                Spacer(Modifier.height(8.dp))
                Surface(
                    shape = RoundedCornerShape(10.dp),
                    color = MaterialTheme.colorScheme.errorContainer,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        msg,
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.onErrorContainer,
                        modifier = Modifier.padding(10.dp).testable("accord_error"),
                    )
                }
            }

            // ── Humanity Accord (family) ─────────────────────────────────────
            Spacer(Modifier.height(16.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    localizedString("mobile.accord_family_title"),
                    fontSize = 15.sp,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.weight(1f),
                )
                if (loading) {
                    CircularProgressIndicator(modifier = Modifier.size(14.dp), strokeWidth = 2.dp)
                }
            }
            Spacer(Modifier.height(8.dp))

            val fam = family
            if (fam == null && !loading) {
                Text(
                    localizedString("mobile.accord_family_empty"),
                    fontSize = 13.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                // Found-a-new-accord CTA — only when NO family exists yet. This is
                // the entry to the guided genesis ceremony (6 keys / 3 humans).
                Spacer(Modifier.height(12.dp))
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = MaterialTheme.colorScheme.primaryContainer,
                    modifier = Modifier.fillMaxWidth().testable("accord_ceremony_cta"),
                ) {
                    Column(modifier = Modifier.fillMaxWidth().padding(14.dp)) {
                        Text(
                            localizedString("mobile.accord_ceremony_cta_title"),
                            fontSize = 15.sp,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.onPrimaryContainer,
                        )
                        Spacer(Modifier.height(6.dp))
                        Text(
                            localizedString("mobile.accord_ceremony_cta_desc"),
                            fontSize = 12.sp,
                            color = MaterialTheme.colorScheme.onPrimaryContainer,
                        )
                        Spacer(Modifier.height(12.dp))
                        Button(
                            onClick = onStartCeremony,
                            modifier = Modifier
                                .fillMaxWidth()
                                .testableClickable("btn_accord_start_ceremony") { onStartCeremony() },
                        ) {
                            Icon(CIRISIcons.shield, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(8.dp))
                            Text(localizedString("mobile.accord_ceremony_cta_btn"))
                        }
                    }
                }
            } else if (fam != null) {
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = MaterialTheme.colorScheme.surfaceVariant,
                    modifier = Modifier
                        .fillMaxWidth()
                        .testable("accord_family_card"),
                ) {
                    Column(modifier = Modifier.fillMaxWidth().padding(12.dp)) {
                        Text(fam.familyName, fontSize = 15.sp, fontWeight = FontWeight.Bold)
                        Spacer(Modifier.height(2.dp))
                        Text(
                            fam.familyKeyId,
                            fontSize = 11.sp,
                            fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Spacer(Modifier.height(8.dp))
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            // Consensus protocol chip (e.g. quorum:2/3).
                            Surface(
                                shape = RoundedCornerShape(8.dp),
                                color = MaterialTheme.colorScheme.tertiaryContainer,
                            ) {
                                Text(
                                    fam.consensusProtocol,
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Bold,
                                    fontFamily = FontFamily.Monospace,
                                    color = MaterialTheme.colorScheme.onTertiaryContainer,
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                                )
                            }
                            if (fam.entrenched) {
                                Spacer(Modifier.width(8.dp))
                                // Entrenched badge.
                                Surface(
                                    shape = RoundedCornerShape(8.dp),
                                    color = MaterialTheme.colorScheme.primaryContainer,
                                ) {
                                    Text(
                                        localizedString("mobile.accord_entrenched"),
                                        fontSize = 11.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = MaterialTheme.colorScheme.onPrimaryContainer,
                                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                                    )
                                }
                            }
                        }
                    }
                }
            }

            // ── Holder roster ────────────────────────────────────────────────
            Spacer(Modifier.height(20.dp))
            Text(
                localizedString("mobile.accord_holders_title"),
                fontSize = 15.sp,
                fontWeight = FontWeight.Bold,
            )
            Spacer(Modifier.height(4.dp))
            Text(
                localizedString("mobile.accord_holders_desc"),
                fontSize = 12.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(8.dp))

            if (holders.isEmpty() && !loading) {
                Text(
                    localizedString("mobile.accord_holders_empty"),
                    fontSize = 13.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                holders.forEach { h ->
                    Surface(
                        shape = RoundedCornerShape(12.dp),
                        color = MaterialTheme.colorScheme.surfaceVariant,
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(bottom = 8.dp)
                            .testable("row_accord_holder_${h.keyId}"),
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth().padding(12.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Icon(
                                CIRISIcons.keySecure,
                                contentDescription = null,
                                modifier = Modifier.size(18.dp),
                                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                            Spacer(Modifier.width(10.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    h.keyId,
                                    fontSize = 13.sp,
                                    fontWeight = FontWeight.Bold,
                                    fontFamily = FontFamily.Monospace,
                                )
                                Text(
                                    localizedString("mobile.accord_holder_attested"),
                                    fontSize = 11.sp,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                    }
                }
            }

            // ── Admit a node to the trust root (CIRISServer#140 / CIRISVerify#162) ──
            // An accord holder (A1) scrub-signs a node's registration on their own
            // YubiKey + USB key, producing the genesis seed persist bakes. 1-of-N:
            // a single holder suffices. The app holds NO keys — the touch is consent.
            Spacer(Modifier.height(20.dp))
            Text(
                "Admit node to trust root",
                fontSize = 15.sp,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.testable("accord_admit_node_title"),
            )
            Text(
                "An accord holder scrub-signs a node's registration with their YubiKey + " +
                    "USB key, producing the genesis seed. A single holder (1-of-N) is enough.",
                fontSize = 12.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 4.dp, bottom = 8.dp),
            )
            val admitBusy by viewModel.busy.collectAsState()
            val admitSavedTo by viewModel.admitSavedTo.collectAsState()
            val admitRoster by viewModel.holders.collectAsState()
            val admitOwnedNodes by viewModel.ownedNodes.collectAsState()
            val admitTarget by viewModel.resolvedTarget.collectAsState()
            var admitHolderKeyId by remember { mutableStateOf("") }
            var admitUsbPath by remember { mutableStateOf("") }
            var admitPin by remember { mutableStateOf("") }
            var holderMenu by remember { mutableStateOf(false) }
            var nodeMenu by remember { mutableStateOf(false) }
            var showUsbPicker by remember { mutableStateOf(false) }

            // (2) Holder — pick from the seeded roster instead of typing the key_id.
            Box(modifier = Modifier.fillMaxWidth()) {
                OutlinedButton(
                    onClick = { holderMenu = true },
                    modifier = Modifier.fillMaxWidth().testable("dd_admit_holder"),
                ) {
                    Text(admitHolderKeyId.ifBlank { "Select your accord holder key…" })
                }
                DropdownMenu(expanded = holderMenu, onDismissRequest = { holderMenu = false }) {
                    if (admitRoster.isEmpty()) {
                        DropdownMenuItem(
                            text = { Text("no holders seeded yet (needs persist v12.0.2)") },
                            onClick = { holderMenu = false },
                        )
                    }
                    admitRoster.forEach { h ->
                        DropdownMenuItem(
                            text = { Text(h.keyId, fontFamily = FontFamily.Monospace) },
                            onClick = { admitHolderKeyId = h.keyId; holderMenu = false },
                            modifier = Modifier.testableClickable("mi_admit_holder_${h.keyId}") {
                                admitHolderKeyId = h.keyId; holderMenu = false
                            },
                        )
                    }
                }
            }
            Spacer(Modifier.height(6.dp))

            // (3) Target — pick from your owned nodes; the node's hybrid pubkeys are
            //     auto-filled from the local directory (no manual paste).
            Box(modifier = Modifier.fillMaxWidth()) {
                OutlinedButton(
                    onClick = { nodeMenu = true },
                    modifier = Modifier.fillMaxWidth().testable("dd_admit_target"),
                ) {
                    Text(admitTarget?.keyId ?: "Select the node to admit…")
                }
                DropdownMenu(expanded = nodeMenu, onDismissRequest = { nodeMenu = false }) {
                    if (admitOwnedNodes.isEmpty()) {
                        DropdownMenuItem(text = { Text("no owned nodes") }, onClick = { nodeMenu = false })
                    }
                    admitOwnedNodes.forEach { n ->
                        DropdownMenuItem(
                            text = { Text(n, fontFamily = FontFamily.Monospace) },
                            onClick = { viewModel.resolveTargetNode(n); nodeMenu = false },
                            modifier = Modifier.testableClickable("mi_admit_target_$n") {
                                viewModel.resolveTargetNode(n); nodeMenu = false
                            },
                        )
                    }
                }
            }
            admitTarget?.let { t ->
                Text(
                    "✓ ${t.keyId} — both hybrid pubkeys loaded",
                    fontSize = 11.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 4.dp).testable("accord_admit_target_resolved"),
                )
            }
            Spacer(Modifier.height(6.dp))

            // (4) USB PQC materials — browse instead of typing the path.
            OutlinedTextField(
                value = admitUsbPath,
                onValueChange = { admitUsbPath = it },
                singleLine = true,
                label = { Text("USB folder (PQC materials)") },
                trailingIcon = {
                    TextButton(
                        onClick = { showUsbPicker = true },
                        modifier = Modifier.testableClickable("btn_admit_browse_usb") { showUsbPicker = true },
                    ) { Text("Browse") }
                },
                modifier = Modifier.fillMaxWidth().testable("input_admit_usb_path"),
            )
            DirectoryPickerDialog(
                show = showUsbPicker,
                onDirectoryPicked = { admitUsbPath = it; showUsbPicker = false },
                onDismiss = { showUsbPicker = false },
            )
            Spacer(Modifier.height(6.dp))
            OutlinedTextField(
                value = admitPin,
                onValueChange = { admitPin = it },
                singleLine = true,
                label = { Text("YubiKey PIN (optional)") },
                modifier = Modifier.fillMaxWidth().testable("input_admit_pin"),
            )
            Spacer(Modifier.height(8.dp))
            Button(
                onClick = {
                    admitTarget?.let { t ->
                        viewModel.admitNode(
                            admitHolderKeyId, admitUsbPath, t.keyId, t.ed25519, t.mldsa,
                            admitPin.ifBlank { null },
                        )
                    }
                },
                enabled = !admitBusy && admitHolderKeyId.isNotBlank() &&
                    admitUsbPath.isNotBlank() && admitTarget != null,
                modifier = Modifier.fillMaxWidth().testable("btn_admit_node"),
            ) {
                Text(if (admitBusy) "Admitting — touch your YubiKey…" else "Admit node — touch your YubiKey")
            }
            admitSavedTo?.let { path ->
                Spacer(Modifier.height(8.dp))
                Text(
                    "Seed saved to (hand it to persist to bake):\n$path",
                    fontSize = 12.sp,
                    fontFamily = FontFamily.Monospace,
                    modifier = Modifier.padding(6.dp).testable("accord_admit_saved_to"),
                )
            }

            // ── Canonical servers (CIRISServer#164) ─────────────────────────────
            // A canonical server is a mesh-seed anchor: a node an accord holder
            // scrub-signed AND flagged `canonical`. Mirrors the admit-node section
            // (same YubiKey + USB scrub) plus an OPTIONAL bootstrap transport address.
            Spacer(Modifier.height(20.dp))
            Text(
                localizedString("mobile.accord_canonical_title"),
                fontSize = 15.sp,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.testable("accord_canonical_title"),
            )
            Text(
                localizedString("mobile.accord_canonical_desc"),
                fontSize = 12.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 4.dp, bottom = 8.dp),
            )
            val canonicalServers by viewModel.canonicalServers.collectAsState()
            val canonicalSavedTo by viewModel.canonicalSavedTo.collectAsState()
            val canonicalTarget by viewModel.canonicalResolvedTarget.collectAsState()
            val canonicalOwnedNodes by viewModel.ownedNodes.collectAsState()
            val canonicalRoster by viewModel.holders.collectAsState()
            var canonicalHolderKeyId by remember { mutableStateOf("") }
            var canonicalUsbPath by remember { mutableStateOf("") }
            var canonicalPin by remember { mutableStateOf("") }
            var canonicalTransportKind by remember { mutableStateOf("") }
            var canonicalDestination by remember { mutableStateOf("") }
            var canonicalHolderMenu by remember { mutableStateOf(false) }
            var canonicalNodeMenu by remember { mutableStateOf(false) }
            var canonicalUsbPicker by remember { mutableStateOf(false) }

            // Current canonical servers roster.
            if (canonicalServers.isEmpty()) {
                Text(
                    localizedString("mobile.accord_canonical_empty"),
                    fontSize = 12.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.testable("accord_canonical_empty"),
                )
            } else {
                canonicalServers.forEach { s ->
                    Surface(
                        shape = RoundedCornerShape(8.dp),
                        color = MaterialTheme.colorScheme.surfaceVariant,
                        modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp)
                            .testable("row_canonical_server_${s.keyId}"),
                    ) {
                        Column(modifier = Modifier.padding(10.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(
                                    s.keyId,
                                    fontSize = 12.sp,
                                    fontFamily = FontFamily.Monospace,
                                    modifier = Modifier.weight(1f),
                                )
                                Spacer(Modifier.width(6.dp))
                                Surface(
                                    shape = RoundedCornerShape(4.dp),
                                    color = MaterialTheme.colorScheme.primary,
                                ) {
                                    Text(
                                        localizedString("mobile.accord_canonical_badge"),
                                        fontSize = 10.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = MaterialTheme.colorScheme.onPrimary,
                                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                    )
                                }
                            }
                            s.scrubKeyId?.takeIf { it.isNotBlank() }?.let { scrub ->
                                Text(
                                    localizedString("mobile.accord_canonical_scrubbed_by", "holder", scrub),
                                    fontSize = 10.sp,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    modifier = Modifier.padding(top = 2.dp),
                                )
                            }
                        }
                    }
                }
            }
            Spacer(Modifier.height(10.dp))

            Text(
                localizedString("mobile.accord_canonical_add_title"),
                fontSize = 13.sp,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.testable("accord_add_canonical_title"),
            )
            Spacer(Modifier.height(6.dp))

            // (1) Holder — pick from the seeded roster.
            Box(modifier = Modifier.fillMaxWidth()) {
                OutlinedButton(
                    onClick = { canonicalHolderMenu = true },
                    modifier = Modifier.fillMaxWidth().testable("dd_canonical_holder"),
                ) {
                    Text(canonicalHolderKeyId.ifBlank { localizedString("mobile.accord_canonical_holder_select") })
                }
                DropdownMenu(expanded = canonicalHolderMenu, onDismissRequest = { canonicalHolderMenu = false }) {
                    if (canonicalRoster.isEmpty()) {
                        DropdownMenuItem(
                            text = { Text(localizedString("mobile.accord_canonical_no_holders")) },
                            onClick = { canonicalHolderMenu = false },
                        )
                    }
                    canonicalRoster.forEach { h ->
                        DropdownMenuItem(
                            text = { Text(h.keyId, fontFamily = FontFamily.Monospace) },
                            onClick = { canonicalHolderKeyId = h.keyId; canonicalHolderMenu = false },
                            modifier = Modifier.testableClickable("mi_canonical_holder_${h.keyId}") {
                                canonicalHolderKeyId = h.keyId; canonicalHolderMenu = false
                            },
                        )
                    }
                }
            }
            Spacer(Modifier.height(6.dp))

            // (2) Target — pick from your owned nodes; hybrid pubkeys auto-fill.
            Box(modifier = Modifier.fillMaxWidth()) {
                OutlinedButton(
                    onClick = { canonicalNodeMenu = true },
                    modifier = Modifier.fillMaxWidth().testable("dd_canonical_target"),
                ) {
                    Text(canonicalTarget?.keyId ?: localizedString("mobile.accord_canonical_target_select"))
                }
                DropdownMenu(expanded = canonicalNodeMenu, onDismissRequest = { canonicalNodeMenu = false }) {
                    if (canonicalOwnedNodes.isEmpty()) {
                        DropdownMenuItem(text = { Text(localizedString("mobile.accord_canonical_no_owned")) }, onClick = { canonicalNodeMenu = false })
                    }
                    canonicalOwnedNodes.forEach { n ->
                        DropdownMenuItem(
                            text = { Text(n, fontFamily = FontFamily.Monospace) },
                            onClick = { viewModel.resolveCanonicalTarget(n); canonicalNodeMenu = false },
                            modifier = Modifier.testableClickable("mi_canonical_target_$n") {
                                viewModel.resolveCanonicalTarget(n); canonicalNodeMenu = false
                            },
                        )
                    }
                }
            }
            canonicalTarget?.let { t ->
                Text(
                    localizedString("mobile.accord_canonical_target_resolved", "key", t.keyId),
                    fontSize = 11.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 4.dp).testable("accord_canonical_target_resolved"),
                )
            }
            Spacer(Modifier.height(6.dp))

            // (3) USB PQC materials — browse instead of typing the path.
            OutlinedTextField(
                value = canonicalUsbPath,
                onValueChange = { canonicalUsbPath = it },
                singleLine = true,
                label = { Text(localizedString("mobile.accord_canonical_usb_label")) },
                trailingIcon = {
                    TextButton(
                        onClick = { canonicalUsbPicker = true },
                        modifier = Modifier.testableClickable("btn_canonical_browse_usb") { canonicalUsbPicker = true },
                    ) { Text(localizedString("mobile.accord_canonical_browse")) }
                },
                modifier = Modifier.fillMaxWidth().testable("input_canonical_usb_path"),
            )
            DirectoryPickerDialog(
                show = canonicalUsbPicker,
                onDirectoryPicked = { canonicalUsbPath = it; canonicalUsbPicker = false },
                onDismiss = { canonicalUsbPicker = false },
            )
            Spacer(Modifier.height(6.dp))
            OutlinedTextField(
                value = canonicalPin,
                onValueChange = { canonicalPin = it },
                singleLine = true,
                label = { Text(localizedString("mobile.accord_canonical_pin_label")) },
                modifier = Modifier.fillMaxWidth().testable("input_canonical_pin"),
            )
            Spacer(Modifier.height(6.dp))

            // (4) OPTIONAL bootstrap transport — the address other nodes dial.
            OutlinedTextField(
                value = canonicalTransportKind,
                onValueChange = { canonicalTransportKind = it },
                singleLine = true,
                label = { Text(localizedString("mobile.accord_canonical_transport_label")) },
                modifier = Modifier.fillMaxWidth().testable("input_canonical_transport_kind"),
            )
            Spacer(Modifier.height(6.dp))
            OutlinedTextField(
                value = canonicalDestination,
                onValueChange = { canonicalDestination = it },
                singleLine = true,
                label = { Text(localizedString("mobile.accord_canonical_destination_label")) },
                modifier = Modifier.fillMaxWidth().testable("input_canonical_destination"),
            )
            Spacer(Modifier.height(8.dp))
            Button(
                onClick = {
                    canonicalTarget?.let { t ->
                        viewModel.addCanonicalServer(
                            canonicalHolderKeyId, canonicalUsbPath, t.keyId, t.ed25519, t.mldsa,
                            canonicalPin.ifBlank { null },
                            canonicalTransportKind.ifBlank { null },
                            canonicalDestination.ifBlank { null },
                        )
                    }
                },
                enabled = !busy && canonicalHolderKeyId.isNotBlank() &&
                    canonicalUsbPath.isNotBlank() && canonicalTarget != null,
                modifier = Modifier.fillMaxWidth().testable("btn_add_canonical"),
            ) {
                Text(
                    if (busy) localizedString("mobile.accord_canonical_add_btn_busy")
                    else localizedString("mobile.accord_canonical_add_btn"),
                )
            }
            canonicalSavedTo?.let { path ->
                Spacer(Modifier.height(8.dp))
                Text(
                    localizedString("mobile.accord_canonical_saved_to", "path", path),
                    fontSize = 12.sp,
                    fontFamily = FontFamily.Monospace,
                    modifier = Modifier.padding(6.dp).testable("accord_canonical_saved_to"),
                )
            }

            // ── Pending invocations ──────────────────────────────────────────
            Spacer(Modifier.height(20.dp))
            Text(
                localizedString("mobile.accord_invocations_title"),
                fontSize = 15.sp,
                fontWeight = FontWeight.Bold,
            )
            Spacer(Modifier.height(8.dp))

            if (invocations.isEmpty() && !loading) {
                Text(
                    localizedString("mobile.accord_invocations_empty"),
                    fontSize = 13.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                invocations.forEach { inv ->
                    InvocationCard(
                        inv = inv,
                        busy = busy,
                        onConcur = { viewModel.concur(inv.invocationKind, inv.invocationId) },
                    )
                }
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}

/**
 * The MANDATED per-kind visual treatment (CC 4.2.1). CONSTITUTIONAL is the
 * kill-switch and gets strong emergency styling; notify is neutral; drill is
 * muted / test. Returned colors are resolved against the active theme.
 */
private data class InvocationStyle(
    val container: Color,
    val onContainer: Color,
    val border: Color,
    val labelKey: String,
)

@Composable
private fun invocationStyle(kind: String): InvocationStyle {
    val cs = MaterialTheme.colorScheme
    return when (kind.uppercase()) {
        "CONSTITUTIONAL" -> InvocationStyle(
            container = cs.errorContainer,
            onContainer = cs.onErrorContainer,
            border = cs.error,
            labelKey = "mobile.accord_kind_constitutional",
        )
        "DRILL" -> InvocationStyle(
            // Muted / test — surfaceVariant + dimmed border.
            container = cs.surfaceVariant,
            onContainer = cs.onSurfaceVariant,
            border = cs.outlineVariant,
            labelKey = "mobile.accord_kind_drill",
        )
        else -> InvocationStyle(
            // notify (and any unknown kind) — neutral informational.
            container = cs.secondaryContainer,
            onContainer = cs.onSecondaryContainer,
            border = cs.secondary,
            labelKey = "mobile.accord_kind_notify",
        )
    }
}

@Composable
private fun InvocationCard(
    inv: AccordInvocationDto,
    busy: Boolean,
    onConcur: () -> Unit,
) {
    val style = invocationStyle(inv.invocationKind)
    val isConstitutional = inv.invocationKind.uppercase() == "CONSTITUTIONAL"

    Surface(
        shape = RoundedCornerShape(12.dp),
        color = style.container,
        // The CONSTITUTIONAL emergency styling gets a heavier border.
        border = BorderStroke(if (isConstitutional) 2.dp else 1.dp, style.border),
        modifier = Modifier
            .fillMaxWidth()
            .padding(bottom = 8.dp)
            .testable("row_accord_invocation_${inv.invocationId}"),
    ) {
        Column(modifier = Modifier.fillMaxWidth().padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                // Kind badge — the mandated distinct treatment.
                Surface(
                    shape = RoundedCornerShape(6.dp),
                    color = style.border,
                ) {
                    Text(
                        localizedString(style.labelKey),
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        color = style.container,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                    )
                }
                Spacer(Modifier.width(8.dp))
                if (inv.quorumMet) {
                    Icon(
                        CIRISIcons.check,
                        contentDescription = "Quorum met",
                        modifier = Modifier.size(18.dp),
                        tint = style.onContainer,
                    )
                }
            }
            Spacer(Modifier.height(8.dp))
            Text(
                inv.invocationId,
                fontSize = 13.sp,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace,
                color = style.onContainer,
            )
            Spacer(Modifier.height(4.dp))
            // Quorum progress: validSigners.size / quorumThreshold.
            Text(
                localizedString("mobile.accord_quorum")
                    .replace("{signed}", inv.validSigners.size.toString())
                    .replace("{threshold}", inv.quorumThreshold.toString()),
                fontSize = 12.sp,
                color = style.onContainer,
            )

            // Concur — shown only while quorum is not yet met. The app sends no
            // crypto; the node signs with the resolved local holder signer.
            if (!inv.quorumMet) {
                Spacer(Modifier.height(10.dp))
                Button(
                    onClick = onConcur,
                    enabled = !busy,
                    modifier = Modifier
                        .fillMaxWidth()
                        .testableClickable("btn_accord_concur_${inv.invocationId}") { onConcur() },
                ) {
                    if (busy) {
                        CircularProgressIndicator(modifier = Modifier.size(14.dp), strokeWidth = 2.dp)
                        Spacer(Modifier.width(8.dp))
                    }
                    Text(localizedString("mobile.accord_concur"))
                }
            }
        }
    }
}
