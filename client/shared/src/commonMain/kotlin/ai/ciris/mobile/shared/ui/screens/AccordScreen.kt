package ai.ciris.mobile.shared.ui.screens

import ai.ciris.mobile.shared.localization.localizedString
import ai.ciris.mobile.shared.models.federation.AccordInvocationDto
import ai.ciris.mobile.shared.platform.DirectoryPickerDialog
import ai.ciris.mobile.shared.platform.testable
import ai.ciris.mobile.shared.platform.testableClickable
import ai.ciris.mobile.shared.ui.components.CIRISIcons
import ai.ciris.mobile.shared.ui.icons.CIRISMaterialIcons
import ai.ciris.mobile.shared.ui.icons.Visibility
import ai.ciris.mobile.shared.ui.icons.VisibilityOff
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
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.layout.positionInRoot
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch

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
    val haltStatus by viewModel.haltStatus.collectAsState()
    val drills by viewModel.drills.collectAsState()
    val announcements by viewModel.announcements.collectAsState()
    val loading by viewModel.loading.collectAsState()
    val busy by viewModel.busy.collectAsState()
    val error by viewModel.error.collectAsState()
    val notice by viewModel.notice.collectAsState()

    // Local, uncommitted inputs for the holder actions (drill id + announce text).
    var drillId by remember { mutableStateOf("") }
    var announceMessage by remember { mutableStateOf("") }

    // Hoisted so the "Replace / update" action can scroll the add-canonical form
    // into view (see the LaunchedEffect on the canonical replace seed below). The
    // scroll target is derived from the form's on-screen position relative to the
    // scroll viewport top, both captured in root coordinates.
    val scrollState = rememberScrollState()
    val scope = rememberCoroutineScope()
    var columnTopRootY by remember { mutableStateOf(0f) }

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
                .onGloballyPositioned { columnTopRootY = it.positionInRoot().y }
                .verticalScroll(scrollState),
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

            // ── ACTIVE-HALT banner (CC 4.2.1 / 4.2.3) ────────────────────────
            // The most prominent thing on the card when the kill-switch is engaged:
            // a 2-of-3 CONSTITUTIONAL halt has latched this node down (not a
            // recoverable pause). Read-only — the app never clears the latch.
            if (haltStatus?.halted == true) {
                Spacer(Modifier.height(12.dp))
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = MaterialTheme.colorScheme.errorContainer,
                    border = BorderStroke(2.dp, MaterialTheme.colorScheme.error),
                    modifier = Modifier.fillMaxWidth().testable("accord_halt_banner"),
                ) {
                    Column(modifier = Modifier.fillMaxWidth().padding(14.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                CIRISIcons.shield,
                                contentDescription = null,
                                modifier = Modifier.size(22.dp),
                                tint = MaterialTheme.colorScheme.error,
                            )
                            Spacer(Modifier.width(10.dp))
                            Text(
                                localizedString("mobile.accord_halt_active_title"),
                                fontSize = 16.sp,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.onErrorContainer,
                            )
                        }
                        Spacer(Modifier.height(8.dp))
                        Text(
                            localizedString("mobile.accord_halt_active_desc"),
                            fontSize = 12.sp,
                            color = MaterialTheme.colorScheme.onErrorContainer,
                        )
                        haltStatus?.record?.let { rec ->
                            Spacer(Modifier.height(8.dp))
                            rec.invocationId?.let { id ->
                                Text(
                                    localizedString("mobile.accord_halt_invocation")
                                        .replace("{id}", id),
                                    fontSize = 11.sp,
                                    fontFamily = FontFamily.Monospace,
                                    color = MaterialTheme.colorScheme.onErrorContainer,
                                )
                            }
                            rec.latchedAt?.let { at ->
                                Text(
                                    localizedString("mobile.accord_halt_latched_at")
                                        .replace("{when}", at),
                                    fontSize = 11.sp,
                                    color = MaterialTheme.colorScheme.onErrorContainer,
                                )
                            }
                            if (rec.validSigners.isNotEmpty()) {
                                Text(
                                    localizedString("mobile.accord_halt_signers")
                                        .replace("{signers}", rec.validSigners.joinToString(", ")),
                                    fontSize = 11.sp,
                                    fontFamily = FontFamily.Monospace,
                                    color = MaterialTheme.colorScheme.onErrorContainer,
                                )
                            }
                        }
                    }
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
            var showAdmitPin by remember { mutableStateOf(false) }
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
                label = { Text("YubiKey PIN") },
                visualTransformation =
                    if (showAdmitPin) VisualTransformation.None else PasswordVisualTransformation(),
                trailingIcon = {
                    IconButton(
                        onClick = { showAdmitPin = !showAdmitPin },
                        modifier = Modifier.testableClickable("btn_admit_pin_toggle") {
                            showAdmitPin = !showAdmitPin
                        },
                    ) {
                        Icon(
                            if (showAdmitPin) CIRISMaterialIcons.Filled.VisibilityOff
                            else CIRISMaterialIcons.Filled.Visibility,
                            contentDescription = if (showAdmitPin) "Hide PIN" else "Show PIN",
                            modifier = Modifier.size(18.dp),
                        )
                    }
                },
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
                    admitUsbPath.isNotBlank() && admitPin.isNotBlank() && admitTarget != null,
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
            val canonicalWithdrawals by viewModel.canonicalWithdrawals.collectAsState()
            val canonicalReplaceSeed by viewModel.canonicalReplaceTarget.collectAsState()
            var canonicalHolderKeyId by remember { mutableStateOf("") }
            var canonicalUsbPath by remember { mutableStateOf("") }
            var canonicalPin by remember { mutableStateOf("") }
            var showCanonicalPin by remember { mutableStateOf(false) }
            // The transport defaults to `ip` — the IP now rides INSIDE the signed
            // record envelope, so it must be set at mint time.
            var canonicalTransportKind by remember { mutableStateOf("ip") }
            var canonicalDestination by remember { mutableStateOf("") }
            var canonicalHolderMenu by remember { mutableStateOf(false) }
            var canonicalNodeMenu by remember { mutableStateOf(false) }
            var canonicalUsbPicker by remember { mutableStateOf(false) }
            // Shared 2-of-3 proposal digest for the destructive canonical ops
            // (withdraw / supersede); a lone holder cannot complete either.
            var canonicalProposalDigest by remember { mutableStateOf("") }
            var showSupersedeNote by remember { mutableStateOf(false) }
            // The add-canonical form's on-screen Y (root coords), captured for the
            // "Replace / update" scroll-into-view.
            var addCanonicalFormRootY by remember { mutableStateOf(0f) }

            // When a canonical row is picked to replace/update, seed the local form
            // (IP + transport=ip) from the VM seed and scroll the add form into view.
            LaunchedEffect(canonicalReplaceSeed) {
                canonicalReplaceSeed?.let { seed ->
                    canonicalTransportKind = "ip"
                    canonicalDestination = seed.ip
                    val target = (scrollState.value + (addCanonicalFormRootY - columnTopRootY))
                        .toInt().coerceIn(0, scrollState.maxValue)
                    scope.launch { scrollState.animateScrollTo(target) }
                    viewModel.clearCanonicalReplaceSeed()
                }
            }

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
                    val currentIp = s.transportHints?.firstOrNull { it.kind == "ip" }?.destination
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
                            // Current IP (the transport_hints ip destination, baked
                            // into the signed record) — or "no address".
                            Text(
                                localizedString(
                                    "mobile.accord_canonical_current_ip",
                                    "ip",
                                    currentIp?.takeIf { it.isNotBlank() }
                                        ?: localizedString("mobile.accord_canonical_ip_none"),
                                ),
                                fontSize = 11.sp,
                                fontFamily = FontFamily.Monospace,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.padding(top = 3.dp)
                                    .testable("canonical_server_ip_${s.keyId}"),
                            )
                            s.scrubKeyId?.takeIf { it.isNotBlank() }?.let { scrub ->
                                Text(
                                    localizedString("mobile.accord_canonical_scrubbed_by", "holder", scrub),
                                    fontSize = 10.sp,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    modifier = Modifier.padding(top = 2.dp),
                                )
                            }
                            // Row ops: Replace/update (1-of-N re-mint), plus the
                            // destructive 2-of-3 withdraw / supersede.
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                TextButton(
                                    onClick = { viewModel.selectCanonicalForReplace(s) },
                                    modifier = Modifier.testableClickable("btn_canonical_replace_${s.keyId}") {
                                        viewModel.selectCanonicalForReplace(s)
                                    },
                                ) { Text(localizedString("mobile.accord_canonical_replace")) }
                                TextButton(
                                    onClick = {
                                        viewModel.withdrawCanonical(s.keyId, canonicalProposalDigest)
                                    },
                                    enabled = !busy && canonicalProposalDigest.isNotBlank(),
                                    modifier = Modifier.testableClickable("btn_canonical_withdraw_${s.keyId}") {
                                        viewModel.withdrawCanonical(s.keyId, canonicalProposalDigest)
                                    },
                                ) {
                                    Text(
                                        localizedString("mobile.accord_canonical_withdraw"),
                                        color = MaterialTheme.colorScheme.error,
                                    )
                                }
                                TextButton(
                                    onClick = { showSupersedeNote = true },
                                    modifier = Modifier.testableClickable("btn_canonical_supersede_${s.keyId}") {
                                        showSupersedeNote = true
                                    },
                                ) { Text(localizedString("mobile.accord_canonical_supersede")) }
                            }
                        }
                    }
                }
            }

            // ── Destructive ops (2-of-3) — shared proposal digest + note ─────────
            Spacer(Modifier.height(8.dp))
            Text(
                localizedString("mobile.accord_canonical_destructive_title"),
                fontSize = 13.sp,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.testable("accord_canonical_destructive_title"),
            )
            Text(
                localizedString("mobile.accord_canonical_destructive_note"),
                fontSize = 12.sp,
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.padding(top = 4.dp, bottom = 6.dp)
                    .testable("accord_canonical_destructive_note"),
            )
            OutlinedTextField(
                value = canonicalProposalDigest,
                onValueChange = { canonicalProposalDigest = it },
                singleLine = true,
                label = { Text(localizedString("mobile.accord_canonical_proposal_digest_label")) },
                modifier = Modifier.fillMaxWidth().testable("input_canonical_proposal_digest"),
            )
            if (showSupersedeNote) {
                Spacer(Modifier.height(6.dp))
                Text(
                    localizedString("mobile.accord_canonical_supersede_todo"),
                    fontSize = 12.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.testable("accord_canonical_supersede_todo"),
                )
                // TODO(#164): assemble the successor SignedKeyRecord for
                //   POST /v1/accord/canonical/supersede { old_key_id, new_record,
                //   proposal_digest } in-app — the new_record is a full re-scrubbed
                //   record and is complex to build client-side; done out-of-band for now.
            }
            Spacer(Modifier.height(10.dp))

            Text(
                localizedString("mobile.accord_canonical_add_title"),
                fontSize = 13.sp,
                fontWeight = FontWeight.Bold,
                modifier = Modifier
                    .onGloballyPositioned { addCanonicalFormRootY = it.positionInRoot().y }
                    .testable("accord_add_canonical_title"),
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
                visualTransformation =
                    if (showCanonicalPin) VisualTransformation.None else PasswordVisualTransformation(),
                trailingIcon = {
                    IconButton(
                        onClick = { showCanonicalPin = !showCanonicalPin },
                        modifier = Modifier.testableClickable("btn_canonical_pin_toggle") {
                            showCanonicalPin = !showCanonicalPin
                        },
                    ) {
                        Icon(
                            if (showCanonicalPin) CIRISMaterialIcons.Filled.VisibilityOff
                            else CIRISMaterialIcons.Filled.Visibility,
                            contentDescription = if (showCanonicalPin) "Hide PIN" else "Show PIN",
                            modifier = Modifier.size(18.dp),
                        )
                    }
                },
                modifier = Modifier.fillMaxWidth().testable("input_canonical_pin"),
            )
            Spacer(Modifier.height(6.dp))

            // (4) Bootstrap transport — the IP now rides INSIDE the signed record
            //     envelope, so it is set at mint time (defaults to `ip`).
            OutlinedTextField(
                value = canonicalDestination,
                onValueChange = { canonicalDestination = it },
                singleLine = true,
                label = { Text(localizedString("mobile.accord_canonical_ip_label")) },
                modifier = Modifier.fillMaxWidth().testable("input_canonical_destination"),
            )
            Spacer(Modifier.height(6.dp))
            OutlinedTextField(
                value = canonicalTransportKind,
                onValueChange = { canonicalTransportKind = it },
                singleLine = true,
                label = { Text(localizedString("mobile.accord_canonical_transport_label")) },
                modifier = Modifier.fillMaxWidth().testable("input_canonical_transport_kind"),
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
                    canonicalUsbPath.isNotBlank() && canonicalPin.isNotBlank() &&
                    canonicalTarget != null,
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

            // ── Withdrawn / superseded history ──────────────────────────────────
            Spacer(Modifier.height(16.dp))
            Text(
                localizedString("mobile.accord_canonical_withdrawals_title"),
                fontSize = 13.sp,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.testable("accord_canonical_withdrawals_title"),
            )
            Spacer(Modifier.height(6.dp))
            if (canonicalWithdrawals.isEmpty()) {
                Text(
                    localizedString("mobile.accord_canonical_withdrawals_empty"),
                    fontSize = 12.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.testable("accord_canonical_withdrawals_empty"),
                )
            } else {
                canonicalWithdrawals.forEach { w ->
                    Surface(
                        shape = RoundedCornerShape(8.dp),
                        color = MaterialTheme.colorScheme.surfaceVariant,
                        modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp)
                            .testable("row_canonical_withdrawal_${w.keyId}"),
                    ) {
                        Column(modifier = Modifier.padding(10.dp)) {
                            Text(
                                w.keyId,
                                fontSize = 12.sp,
                                fontFamily = FontFamily.Monospace,
                            )
                            w.withdrawnAt?.takeIf { it.isNotBlank() }?.let { at ->
                                Text(
                                    localizedString("mobile.accord_canonical_withdrawn_at", "at", at),
                                    fontSize = 10.sp,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    modifier = Modifier.padding(top = 2.dp),
                                )
                            }
                            w.supersededBy?.takeIf { it.isNotBlank() }?.let { by ->
                                Text(
                                    localizedString("mobile.accord_canonical_superseded_by", "by", by),
                                    fontSize = 10.sp,
                                    fontFamily = FontFamily.Monospace,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    modifier = Modifier.padding(top = 2.dp),
                                )
                            }
                        }
                    }
                }
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

            // ── Holder actions: start a drill / post an announce ─────────────
            // Holder-gated server-side (401/403 surface as an error). A drill is a
            // NON-BINDING rehearsal of the kill-switch delivery path; an announce is
            // a single-holder notify. Neither ever halts.
            Spacer(Modifier.height(20.dp))
            Text(
                localizedString("mobile.accord_actions_title"),
                fontSize = 15.sp,
                fontWeight = FontWeight.Bold,
            )
            Spacer(Modifier.height(4.dp))
            Text(
                localizedString("mobile.accord_actions_desc"),
                fontSize = 12.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(10.dp))
            OutlinedTextField(
                value = drillId,
                onValueChange = { drillId = it },
                singleLine = true,
                label = { Text(localizedString("mobile.accord_drill_id_label")) },
                enabled = !busy,
                modifier = Modifier.fillMaxWidth().testable("input_accord_drill_id"),
            )
            Spacer(Modifier.height(8.dp))
            OutlinedButton(
                onClick = {
                    viewModel.initiateDrill(drillId)
                    drillId = ""
                },
                enabled = !busy && drillId.isNotBlank(),
                modifier = Modifier
                    .fillMaxWidth()
                    .testableClickable("btn_accord_start_drill") {
                        viewModel.initiateDrill(drillId); drillId = ""
                    },
            ) {
                Text(localizedString("mobile.accord_start_drill"))
            }
            Spacer(Modifier.height(14.dp))
            OutlinedTextField(
                value = announceMessage,
                onValueChange = { announceMessage = it },
                label = { Text(localizedString("mobile.accord_announce_label")) },
                enabled = !busy,
                modifier = Modifier.fillMaxWidth().testable("input_accord_announce"),
            )
            Spacer(Modifier.height(8.dp))
            OutlinedButton(
                onClick = {
                    viewModel.initiateAnnounce(announceMessage)
                    announceMessage = ""
                },
                enabled = !busy && announceMessage.isNotBlank(),
                modifier = Modifier
                    .fillMaxWidth()
                    .testableClickable("btn_accord_post_announce") {
                        viewModel.initiateAnnounce(announceMessage); announceMessage = ""
                    },
            ) {
                Text(localizedString("mobile.accord_post_announce"))
            }

            // ── Received drills ──────────────────────────────────────────────
            Spacer(Modifier.height(20.dp))
            Text(
                localizedString("mobile.accord_drills_title"),
                fontSize = 15.sp,
                fontWeight = FontWeight.Bold,
            )
            Spacer(Modifier.height(8.dp))
            if (drills.isEmpty() && !loading) {
                Text(
                    localizedString("mobile.accord_drills_empty"),
                    fontSize = 13.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                drills.forEach { ev -> AccordEventCard(ev = ev, isAnnounce = false) }
            }

            // ── Announcements ────────────────────────────────────────────────
            Spacer(Modifier.height(20.dp))
            Text(
                localizedString("mobile.accord_announcements_title"),
                fontSize = 15.sp,
                fontWeight = FontWeight.Bold,
            )
            Spacer(Modifier.height(8.dp))
            if (announcements.isEmpty() && !loading) {
                Text(
                    localizedString("mobile.accord_announcements_empty"),
                    fontSize = 13.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                announcements.forEach { ev -> AccordEventCard(ev = ev, isAnnounce = true) }
            }

            Spacer(Modifier.height(24.dp))
        }
    }
}

/**
 * One surfaced NON-BINDING accord event — a completed drill or an announcement.
 * Muted styling (neither is an emergency): the drill is a rehearsal, the announce a
 * single-holder notify. Shows the id, when it was recorded, the signer(s), and (for
 * an announce) the bound message.
 */
@Composable
private fun AccordEventCard(
    ev: ai.ciris.mobile.shared.models.federation.AccordEventDto,
    isAnnounce: Boolean,
) {
    Surface(
        shape = RoundedCornerShape(12.dp),
        color = MaterialTheme.colorScheme.surfaceVariant,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
        modifier = Modifier
            .fillMaxWidth()
            .padding(bottom = 8.dp)
            .testable("row_accord_event_${ev.eventType}_${ev.invocationId}"),
    ) {
        Column(modifier = Modifier.fillMaxWidth().padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Surface(
                    shape = RoundedCornerShape(6.dp),
                    color = MaterialTheme.colorScheme.outlineVariant,
                ) {
                    Text(
                        localizedString(
                            if (isAnnounce) "mobile.accord_kind_notify" else "mobile.accord_kind_drill",
                        ),
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp),
                    )
                }
                Spacer(Modifier.width(8.dp))
                Text(
                    ev.invocationId,
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Bold,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (isAnnounce) {
                ev.message?.let { msg ->
                    Spacer(Modifier.height(6.dp))
                    Text(msg, fontSize = 13.sp, color = MaterialTheme.colorScheme.onSurface)
                }
            }
            Spacer(Modifier.height(6.dp))
            Text(
                localizedString("mobile.accord_event_recorded_at").replace("{when}", ev.recordedAt),
                fontSize = 11.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (ev.signers.isNotEmpty()) {
                Text(
                    localizedString(
                        if (isAnnounce) "mobile.accord_event_from" else "mobile.accord_event_signers",
                    ).replace("{signers}", ev.signers.joinToString(", ")),
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
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
