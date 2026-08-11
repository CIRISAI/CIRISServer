package ai.ciris.mobile.shared.ui.screens

import ai.ciris.mobile.shared.localization.localizedString
import ai.ciris.mobile.shared.platform.testable
import ai.ciris.mobile.shared.platform.testableClickable
import ai.ciris.mobile.shared.ui.components.CIRISIcons
import ai.ciris.mobile.shared.viewmodels.DutyConferralViewModel
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
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * **Delegate moderation duty** — confer `slash` / `moderate` / `review` on another
 * self, and say in ONE control how far they may pass it on.
 *
 * The two axes of sub-delegation ("may they delegate at all?" and "how many further
 * hops?") are a single dropdown on purpose: they are one decision, and splitting
 * them into a switch plus a number is how a conferral ends up saying "may not
 * delegate, depth 3". Every option is on the menu — nothing is hidden behind an
 * "advanced" toggle, because the operator is choosing how far their own authority
 * travels.
 *
 * The conferral is a co-scrub: [DutyConferralViewModel.propose] mints scrub #1 and
 * the resulting opaque partial needs `quorum_needed` distinct holder scrubs before
 * it takes effect. The app holds NO keys — the LOCAL node opens the holder's
 * YubiKey + USB ML-DSA and signs.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DutyConferralScreen(
    viewModel: DutyConferralViewModel,
    onBack: () -> Unit,
) {
    val subjectKeyId by viewModel.subjectKeyId.collectAsState()
    val duty by viewModel.duty.collectAsState()
    val subDelegation by viewModel.subDelegation.collectAsState()
    val subDelegationDepth by viewModel.subDelegationDepth.collectAsState()
    val holderKeyId by viewModel.holderKeyId.collectAsState()
    val usbPath by viewModel.usbPath.collectAsState()
    val partial by viewModel.partial.collectAsState()
    val scrubCount by viewModel.scrubCount.collectAsState()
    val quorumNeeded by viewModel.quorumNeeded.collectAsState()
    val adopted by viewModel.adopted.collectAsState()
    val conferred by viewModel.conferred.collectAsState()
    val inProgress by viewModel.inProgress.collectAsState()
    val error by viewModel.error.collectAsState()

    var dutyExpanded by remember { mutableStateOf(false) }
    var depthExpanded by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(localizedString("duty.title")) },
                navigationIcon = {
                    IconButton(
                        onClick = onBack,
                        modifier = Modifier.testableClickable("btn_duty_back") { onBack() },
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
                localizedString("duty.subtitle"),
                fontSize = 13.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            // ── The error, first and loud ─────────────────────────────────────
            error?.let { msg ->
                Spacer(Modifier.height(12.dp))
                Surface(
                    shape = RoundedCornerShape(10.dp),
                    color = MaterialTheme.colorScheme.errorContainer,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Icon(
                            CIRISIcons.warning,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.onErrorContainer,
                            modifier = Modifier.size(18.dp),
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(
                            msg,
                            fontSize = 13.sp,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.onErrorContainer,
                            modifier = Modifier.weight(1f).testable("duty_error"),
                        )
                    }
                }
            }

            // ── The conferral ─────────────────────────────────────────────────
            Spacer(Modifier.height(12.dp))
            Surface(
                shape = RoundedCornerShape(12.dp),
                color = MaterialTheme.colorScheme.surfaceVariant,
                modifier = Modifier.fillMaxWidth().testable("duty_conferral_card"),
            ) {
                Column(modifier = Modifier.fillMaxWidth().padding(16.dp)) {
                    SectionHeader(CIRISIcons.shield, localizedString("duty.section_conferral"))

                    OutlinedTextField(
                        value = subjectKeyId,
                        onValueChange = { viewModel.setSubjectKeyId(it) },
                        singleLine = true,
                        enabled = !inProgress,
                        label = { Text(localizedString("duty.subject_label")) },
                        placeholder = { Text(localizedString("duty.subject_placeholder")) },
                        modifier = Modifier.fillMaxWidth().testable("input_duty_subject"),
                    )

                    // ── DUTY verb ─────────────────────────────────────────────
                    Spacer(Modifier.height(12.dp))
                    ExposedDropdownMenuBox(
                        expanded = dutyExpanded,
                        onExpandedChange = { dutyExpanded = it },
                    ) {
                        OutlinedTextField(
                            value = localizedString(dutyLabelKey(duty)),
                            onValueChange = {},
                            readOnly = true,
                            enabled = !inProgress,
                            label = { Text(localizedString("duty.verb_label")) },
                            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = dutyExpanded) },
                            modifier = Modifier
                                .fillMaxWidth()
                                .menuAnchor()
                                .testableClickable("input_duty_verb") { dutyExpanded = !dutyExpanded },
                        )
                        ExposedDropdownMenu(
                            expanded = dutyExpanded,
                            onDismissRequest = { dutyExpanded = false },
                        ) {
                            DUTY_VERBS.forEach { verb ->
                                DropdownMenuItem(
                                    text = { Text(localizedString(dutyLabelKey(verb))) },
                                    onClick = {
                                        viewModel.setDuty(verb)
                                        dutyExpanded = false
                                    },
                                    modifier = Modifier.testableClickable("menu_duty_$verb") {
                                        viewModel.setDuty(verb)
                                        dutyExpanded = false
                                    },
                                )
                            }
                        }
                    }
                    Spacer(Modifier.height(4.dp))
                    Text(
                        localizedString("duty.verb_help"),
                        fontSize = 11.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )

                    // ── Delegation depth (both axes, one control) ─────────────
                    Spacer(Modifier.height(12.dp))
                    val selected = DEPTH_OPTIONS.firstOrNull {
                        it.subDelegation == subDelegation && it.depth == subDelegationDepth
                    } ?: DEPTH_OPTIONS.first()
                    ExposedDropdownMenuBox(
                        expanded = depthExpanded,
                        onExpandedChange = { depthExpanded = it },
                    ) {
                        OutlinedTextField(
                            value = localizedString(selected.labelKey),
                            onValueChange = {},
                            readOnly = true,
                            enabled = !inProgress,
                            label = { Text(localizedString("duty.depth_label")) },
                            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = depthExpanded) },
                            modifier = Modifier
                                .fillMaxWidth()
                                .menuAnchor()
                                .testableClickable("input_duty_depth") { depthExpanded = !depthExpanded },
                        )
                        ExposedDropdownMenu(
                            expanded = depthExpanded,
                            onDismissRequest = { depthExpanded = false },
                        ) {
                            DEPTH_OPTIONS.forEach { option ->
                                DropdownMenuItem(
                                    text = { Text(localizedString(option.labelKey)) },
                                    onClick = {
                                        viewModel.setDelegationDepth(option.subDelegation, option.depth)
                                        depthExpanded = false
                                    },
                                    modifier = Modifier.testableClickable(option.testTag) {
                                        viewModel.setDelegationDepth(option.subDelegation, option.depth)
                                        depthExpanded = false
                                    },
                                )
                            }
                        }
                    }
                    Spacer(Modifier.height(4.dp))
                    Text(
                        localizedString("duty.depth_help"),
                        fontSize = 11.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }

            // ── The signing holder ────────────────────────────────────────────
            Spacer(Modifier.height(16.dp))
            Surface(
                shape = RoundedCornerShape(12.dp),
                color = MaterialTheme.colorScheme.surfaceVariant,
                modifier = Modifier.fillMaxWidth().testable("duty_holder_card"),
            ) {
                Column(modifier = Modifier.fillMaxWidth().padding(16.dp)) {
                    SectionHeader(CIRISIcons.keySecure, localizedString("duty.section_holder"))
                    Text(
                        localizedString("duty.holder_desc"),
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = holderKeyId,
                        onValueChange = { viewModel.setHolderKeyId(it) },
                        singleLine = true,
                        enabled = !inProgress,
                        label = { Text(localizedString("duty.holder_label")) },
                        placeholder = { Text(localizedString("duty.holder_placeholder")) },
                        modifier = Modifier.fillMaxWidth().testable("input_duty_holder"),
                    )
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = usbPath,
                        onValueChange = { viewModel.setUsbPath(it) },
                        singleLine = true,
                        enabled = !inProgress,
                        label = { Text(localizedString("duty.usb_label")) },
                        placeholder = { Text(localizedString("duty.usb_placeholder")) },
                        modifier = Modifier.fillMaxWidth().testable("input_duty_usb"),
                    )
                }
            }

            // ── Propose / cosign ──────────────────────────────────────────────
            Spacer(Modifier.height(16.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Button(
                    onClick = { viewModel.propose() },
                    enabled = !inProgress,
                    modifier = Modifier.testableClickable("btn_duty_propose") { viewModel.propose() },
                ) {
                    Text(localizedString("duty.propose_button"))
                }
                Spacer(Modifier.width(8.dp))
                OutlinedButton(
                    onClick = { viewModel.cosign() },
                    enabled = !inProgress && partial != null,
                    modifier = Modifier.testableClickable("btn_duty_cosign") { viewModel.cosign() },
                ) {
                    Text(localizedString("duty.cosign_button"))
                }
                if (inProgress) {
                    Spacer(Modifier.width(8.dp))
                    CircularProgressIndicator(modifier = Modifier.size(14.dp), strokeWidth = 2.dp)
                }
            }

            // ── Co-scrub progress ─────────────────────────────────────────────
            Spacer(Modifier.height(16.dp))
            Surface(
                shape = RoundedCornerShape(12.dp),
                color = if (adopted) {
                    MaterialTheme.colorScheme.secondaryContainer
                } else {
                    MaterialTheme.colorScheme.surfaceVariant
                },
                modifier = Modifier.fillMaxWidth().testable("duty_status_card"),
            ) {
                Column(modifier = Modifier.fillMaxWidth().padding(16.dp)) {
                    SectionHeader(CIRISIcons.identityDiamond, localizedString("duty.section_status"))
                    if (partial == null && scrubCount == 0) {
                        Text(
                            localizedString("duty.not_started"),
                            fontSize = 12.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.testable("duty_not_started"),
                        )
                    } else {
                        Text(
                            localizedString(
                                "duty.signatures",
                                mapOf("have" to scrubCount.toString(), "need" to quorumNeeded.toString()),
                            ),
                            fontSize = 15.sp,
                            fontWeight = FontWeight.Bold,
                            fontFamily = FontFamily.Monospace,
                            modifier = Modifier.testable("duty_scrub_count"),
                        )
                        Spacer(Modifier.height(6.dp))
                        if (adopted) {
                            Text(
                                localizedString("duty.adopted"),
                                fontSize = 13.sp,
                                fontWeight = FontWeight.Bold,
                                color = MaterialTheme.colorScheme.onSecondaryContainer,
                                modifier = Modifier.testable("duty_adopted"),
                            )
                            // The node's own one-line read-back of the grant — what
                            // was signed, not what the form implied.
                            conferred?.let { line ->
                                Spacer(Modifier.height(4.dp))
                                Text(
                                    line,
                                    fontSize = 12.sp,
                                    fontFamily = FontFamily.Monospace,
                                    color = MaterialTheme.colorScheme.onSecondaryContainer,
                                    modifier = Modifier.testable("duty_conferred"),
                                )
                            }
                        } else {
                            Text(
                                localizedString("duty.pending_hint"),
                                fontSize = 12.sp,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.testable("duty_pending"),
                            )
                        }
                    }
                }
            }

            Spacer(Modifier.height(24.dp))
        }
    }
}

/** The duty verbs, in the order the node documents them. */
private val DUTY_VERBS = listOf(
    DutyConferralViewModel.DUTY_SLASH,
    DutyConferralViewModel.DUTY_MODERATE,
    DutyConferralViewModel.DUTY_REVIEW,
)

/** Bundle id for a duty verb's label. */
private fun dutyLabelKey(verb: String): String = "duty.verb_$verb"

/**
 * One delegation-depth choice — the (sub_delegation, depth) PAIR the node wants,
 * never two independently-settable controls. `depth = null` with sub-delegation on
 * means "bounded only by the global rail (5)".
 */
private data class DepthOption(
    val labelKey: String,
    val subDelegation: Boolean,
    val depth: Int?,
    val testTag: String,
)

/** Every option, always on the menu — nothing hidden behind "advanced". */
private val DEPTH_OPTIONS = listOf(
    DepthOption("duty.depth_leaf", false, null, "menu_duty_depth_leaf"),
    DepthOption("duty.depth_1", true, 1, "menu_duty_depth_1"),
    DepthOption("duty.depth_2", true, 2, "menu_duty_depth_2"),
    DepthOption("duty.depth_3", true, 3, "menu_duty_depth_3"),
    DepthOption("duty.depth_4", true, 4, "menu_duty_depth_4"),
    DepthOption("duty.depth_5", true, 5, "menu_duty_depth_5"),
    DepthOption("duty.depth_unbounded", true, null, "menu_duty_depth_unbounded"),
)
