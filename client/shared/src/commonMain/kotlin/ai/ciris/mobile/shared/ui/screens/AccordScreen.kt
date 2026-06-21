package ai.ciris.mobile.shared.ui.screens

import ai.ciris.mobile.shared.localization.localizedString
import ai.ciris.mobile.shared.models.federation.AccordInvocationDto
import ai.ciris.mobile.shared.platform.testable
import ai.ciris.mobile.shared.platform.testableClickable
import ai.ciris.mobile.shared.ui.components.CIRISIcons
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
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
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
