package ai.ciris.mobile.shared.ui.screens

import ai.ciris.mobile.shared.localization.localizedString
import ai.ciris.mobile.shared.platform.TestAutomation
import ai.ciris.mobile.shared.platform.testable
import ai.ciris.mobile.shared.platform.testableClickable
import ai.ciris.mobile.shared.ui.components.CIRISIcons
import ai.ciris.mobile.shared.viewmodels.DelegationsViewModel
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
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
import androidx.compose.material3.FilledTonalButton
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
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * **Delegations** — authorize an agent or another person to act on your behalf.
 *
 * Organized as three clear flows (the same shape Consent uses):
 *  - **Offer a code** (OUTGOING) — you generate a one-time offer code / PIN to hand
 *    to an agent or person so they can act for you.
 *  - **Approve a code** (INCOMING) — someone gives you a request code; you review +
 *    approve it (the human-consent gate).
 *  - **Manage** (CRUD) — the active delegations, with a revoke control.
 *
 * The app drives the LOCAL node only with your owner session — it holds no keys.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DelegationsScreen(
    viewModel: DelegationsViewModel,
    onBack: () -> Unit,
    /** Navigate to the Contacts picker so the user can choose a known fed-ID. */
    onOpenContacts: (() -> Unit)? = null,
    /**
     * When the user picks an identity in the Contacts picker and returns here,
     * this is the selected key_id. Delegations reads it and fills [existingKeyId].
     * The caller should clear this after it's been consumed (by passing null again).
     */
    pickedIdentityKeyId: String? = null,
    /** Called after [pickedIdentityKeyId] has been consumed so the caller can clear it. */
    onPickedIdentityConsumed: (() -> Unit)? = null,
) {
    val delegations by viewModel.delegations.collectAsState()
    val loading by viewModel.loading.collectAsState()
    val busy by viewModel.busy.collectAsState()
    val error by viewModel.error.collectAsState()
    val notice by viewModel.notice.collectAsState()
    val lastCreated by viewModel.lastCreated.collectAsState()
    var userCode by remember { mutableStateOf("") }
    var delegateLabel by remember { mutableStateOf("") }
    // mode: "create" = mint a fresh agent fed-ID; "existing" = bind a known key_id.
    var delegateMode by remember { mutableStateOf("create") }
    var existingKeyId by remember { mutableStateOf("") }
    // The active pane: "offer" (outgoing) | "incoming" (approve) | "manage" (CRUD).
    var pane by remember { mutableStateOf("offer") }

    // Test automation: let the UI-automation server's /input drive this screen's
    // text fields (they're `testable()` = position-only, so without this collector
    // /input silently no-ops and createDelegation bails on an empty label). Mirrors
    // LoginScreen/SetupScreen.
    val textInputRequest by TestAutomation.textInputRequests.collectAsState()
    LaunchedEffect(textInputRequest) {
        textInputRequest?.let { request ->
            when (request.testTag) {
                "input_delegation_label" -> {
                    delegateLabel = if (request.clearFirst) request.text else delegateLabel + request.text
                    TestAutomation.clearTextInputRequest()
                }
                "input_delegation_key_id" -> {
                    existingKeyId = if (request.clearFirst) request.text else existingKeyId + request.text
                    TestAutomation.clearTextInputRequest()
                }
                "input_delegation_code" -> {
                    userCode = if (request.clearFirst) request.text else userCode + request.text
                    TestAutomation.clearTextInputRequest()
                }
            }
        }
    }

    // When the Contacts picker returns a selection, fill the key_id field + jump to
    // the Offer pane in "existing fed-ID" mode.
    LaunchedEffect(pickedIdentityKeyId) {
        if (!pickedIdentityKeyId.isNullOrBlank()) {
            existingKeyId = pickedIdentityKeyId
            delegateMode = "existing"
            pane = "offer"
            onPickedIdentityConsumed?.invoke()
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(localizedString("mobile.delegations_title")) },
                navigationIcon = {
                    IconButton(
                        onClick = onBack,
                        modifier = Modifier.testableClickable("btn_delegations_back") { onBack() },
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
                text = "Delegate to an agent or person",
                fontSize = 16.sp,
                fontWeight = FontWeight.Bold,
            )
            Spacer(Modifier.height(2.dp))
            Text(
                text = "Authorize an agent or another person's fed-ID to act on your behalf — " +
                    "offer them a code, approve a code they gave you, or manage what's active.",
                fontSize = 13.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            // ── Delegate vs Steward explainer (CC 0.5.1) ─────────────────────
            // Two DIFFERENT relationships the user must not conflate:
            //  • Delegate → TO an agent or trusted person (a duty/agency) — THIS page.
            //  • Steward  → OF a node / community / child (accountable responsibility)
            //    — managed under Nodes, not here.
            Spacer(Modifier.height(12.dp))
            Surface(
                shape = RoundedCornerShape(12.dp),
                color = MaterialTheme.colorScheme.surfaceVariant,
                modifier = Modifier.fillMaxWidth().testable("delegations_relationship_explainer"),
            ) {
                Column(modifier = Modifier.fillMaxWidth().padding(12.dp)) {
                    Text(
                        "Two different relationships",
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Bold,
                    )
                    Spacer(Modifier.height(8.dp))
                    RelationshipRow(
                        icon = CIRISIcons.robot,
                        title = "Delegate → to an agent or person",
                        body = "You hand a duty / agency TO someone (an agent or a trusted person) " +
                            "so they can act for you. That's what this page does.",
                    )
                    Spacer(Modifier.height(8.dp))
                    RelationshipRow(
                        icon = CIRISIcons.nodeBox,
                        title = "Steward → of a node, community, or child",
                        body = "You are the accountable, responsible party FOR a node / community / " +
                            "child — never an owner OF one. Manage those under Nodes, not here.",
                    )
                }
            }

            // ── Messages (always visible across panes) ───────────────────────
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
                        modifier = Modifier.padding(10.dp).testable("delegations_notice"),
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
                        modifier = Modifier.padding(10.dp).testable("delegations_error"),
                    )
                }
            }

            // ── 3-pane selector: Offer (out) · Approve (in) · Manage (CRUD) ──
            Spacer(Modifier.height(14.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                PaneTab("Offer a code", pane == "offer", "btn_delegation_pane_offer") { pane = "offer" }
                PaneTab("Approve a code", pane == "incoming", "btn_delegation_pane_incoming") { pane = "incoming" }
                PaneTab("Manage", pane == "manage", "btn_delegation_pane_manage") { pane = "manage" }
            }

            Spacer(Modifier.height(16.dp))
            when (pane) {
                "offer" -> OfferPane(
                    busy = busy,
                    delegateLabel = delegateLabel,
                    onLabelChange = { delegateLabel = it },
                    delegateMode = delegateMode,
                    onModeChange = { delegateMode = it },
                    existingKeyId = existingKeyId,
                    onExistingKeyIdChange = { existingKeyId = it },
                    onOpenContacts = onOpenContacts,
                    lastCreated = lastCreated,
                    onCreate = { viewModel.createDelegation(delegateLabel, delegateMode, existingKeyId) },
                    onClearCreated = {
                        viewModel.clearLastCreated()
                        delegateLabel = ""
                        existingKeyId = ""
                    },
                )
                "incoming" -> IncomingPane(
                    busy = busy,
                    userCode = userCode,
                    onUserCodeChange = { userCode = it },
                    onApprove = { viewModel.approve(userCode); userCode = "" },
                )
                else -> ManagePane(
                    loading = loading,
                    busy = busy,
                    delegations = delegations,
                    onRevoke = { viewModel.revoke(it) },
                )
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}

/** One row of the Delegate-vs-Steward explainer: glyph + bold title + body. */
@Composable
private fun RelationshipRow(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    title: String,
    body: String,
) {
    Row(verticalAlignment = Alignment.Top) {
        Icon(
            icon,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(20.dp),
        )
        Spacer(Modifier.width(10.dp))
        Column {
            Text(title, fontSize = 13.sp, fontWeight = FontWeight.Bold)
            Text(
                body,
                fontSize = 12.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

/** One segmented selector button. Selected = filled-tonal, unselected = outlined. */
@Composable
private fun RowScope.PaneTab(
    label: String,
    selected: Boolean,
    testTag: String,
    onClick: () -> Unit,
) {
    if (selected) {
        FilledTonalButton(
            onClick = onClick,
            modifier = Modifier.weight(1f).testableClickable(testTag) { onClick() },
        ) {
            Text(label, fontSize = 12.sp, fontWeight = FontWeight.Bold)
        }
    } else {
        OutlinedButton(
            onClick = onClick,
            modifier = Modifier.weight(1f).testableClickable(testTag) { onClick() },
        ) {
            Text(label, fontSize = 12.sp)
        }
    }
}

/** OUTGOING — generate an offer code / PIN to hand to an agent or person. */
@Composable
private fun OfferPane(
    busy: Boolean,
    delegateLabel: String,
    onLabelChange: (String) -> Unit,
    delegateMode: String,
    onModeChange: (String) -> Unit,
    existingKeyId: String,
    onExistingKeyIdChange: (String) -> Unit,
    onOpenContacts: (() -> Unit)?,
    lastCreated: ai.ciris.mobile.shared.models.federation.CreateDelegationResponse?,
    onCreate: () -> Unit,
    onClearCreated: () -> Unit,
) {
    Column(modifier = Modifier.fillMaxWidth()) {
        Text(
            "Generate an offer code",
            fontSize = 15.sp,
            fontWeight = FontWeight.Bold,
        )
        Spacer(Modifier.height(4.dp))
        Text(
            "Authorize an agent or person to act on your behalf. You'll get a claim URL + PIN to hand to them.",
            fontSize = 12.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(
            value = delegateLabel,
            onValueChange = onLabelChange,
            singleLine = true,
            enabled = !busy,
            label = { Text("Label (e.g. my-laptop-agent)") },
            modifier = Modifier.fillMaxWidth().testable("input_delegation_label"),
        )
        Spacer(Modifier.height(8.dp))
        // Mode choice — create a new fed-ID vs use an existing one.
        Row(verticalAlignment = Alignment.CenterVertically) {
            OutlinedButton(
                onClick = { onModeChange("create") },
                enabled = !busy,
                modifier = Modifier.testableClickable("btn_delegation_mode_create") { onModeChange("create") },
            ) {
                Text(
                    "New fed-ID",
                    fontWeight = if (delegateMode == "create") FontWeight.Bold else FontWeight.Normal,
                )
            }
            Spacer(Modifier.width(8.dp))
            OutlinedButton(
                onClick = { onModeChange("existing") },
                enabled = !busy,
                modifier = Modifier.testableClickable("btn_delegation_mode_existing") { onModeChange("existing") },
            ) {
                Text(
                    "Existing fed-ID",
                    fontWeight = if (delegateMode == "existing") FontWeight.Bold else FontWeight.Normal,
                )
            }
        }
        if (delegateMode == "existing") {
            Spacer(Modifier.height(8.dp))
            if (onOpenContacts != null) {
                OutlinedButton(
                    onClick = onOpenContacts,
                    enabled = !busy,
                    modifier = Modifier.fillMaxWidth().testableClickable("btn_delegation_choose_identity") { onOpenContacts() },
                ) {
                    Icon(CIRISIcons.person, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(6.dp))
                    Text(
                        if (existingKeyId.isBlank()) "Choose from Contacts"
                        else "Change identity (${existingKeyId.take(12)}…)",
                    )
                }
                Spacer(Modifier.height(6.dp))
            }
            OutlinedTextField(
                value = existingKeyId,
                onValueChange = onExistingKeyIdChange,
                singleLine = true,
                enabled = !busy,
                label = {
                    Text(if (onOpenContacts != null) "Or paste a key_id manually" else "Existing fed-ID key_id")
                },
                modifier = Modifier.fillMaxWidth().testable("input_delegation_key_id"),
            )
        }
        Spacer(Modifier.height(8.dp))
        Button(
            onClick = onCreate,
            enabled = !busy && delegateLabel.isNotBlank(),
            modifier = Modifier.fillMaxWidth().testableClickable("btn_delegation_create") { onCreate() },
        ) {
            if (busy) {
                CircularProgressIndicator(modifier = Modifier.size(14.dp), strokeWidth = 2.dp)
                Spacer(Modifier.width(8.dp))
            }
            Text("Generate offer code")
        }

        // ── Created result — the URL + PIN to hand over ──────────────────────
        lastCreated?.let { created ->
            Spacer(Modifier.height(12.dp))
            Surface(
                shape = RoundedCornerShape(12.dp),
                color = MaterialTheme.colorScheme.primaryContainer,
                modifier = Modifier.fillMaxWidth().testable("delegation_created_card"),
            ) {
                Column(modifier = Modifier.fillMaxWidth().padding(14.dp)) {
                    Text(
                        "Hand this to the agent or person",
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onPrimaryContainer,
                    )
                    Spacer(Modifier.height(8.dp))
                    Text("PIN", fontSize = 11.sp, color = MaterialTheme.colorScheme.onPrimaryContainer)
                    Text(
                        created.pin,
                        fontSize = 32.sp,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onPrimaryContainer,
                        modifier = Modifier.testable("delegation_created_pin"),
                    )
                    Spacer(Modifier.height(8.dp))
                    Text("Claim URL", fontSize = 11.sp, color = MaterialTheme.colorScheme.onPrimaryContainer)
                    Text(
                        created.claimUrl,
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onPrimaryContainer,
                        modifier = Modifier.testable("delegation_created_url"),
                    )
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "Client: ${created.clientId}",
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.onPrimaryContainer,
                        modifier = Modifier.testable("delegation_created_client_id"),
                    )
                    Spacer(Modifier.height(6.dp))
                    Text(
                        "Hand this URL + PIN over; it expires in ${created.expiresIn / 60} minutes.",
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.onPrimaryContainer,
                    )
                    Spacer(Modifier.height(10.dp))
                    Button(
                        onClick = onClearCreated,
                        modifier = Modifier.testableClickable("btn_delegation_created_done") { onClearCreated() },
                    ) {
                        Text("Done")
                    }
                }
            }
        }
    }
}

/** INCOMING — view + approve a request code someone gave you. */
@Composable
private fun IncomingPane(
    busy: Boolean,
    userCode: String,
    onUserCodeChange: (String) -> Unit,
    onApprove: () -> Unit,
) {
    Column(modifier = Modifier.fillMaxWidth()) {
        Text(
            localizedString("mobile.delegations_add_title"),
            fontSize = 15.sp,
            fontWeight = FontWeight.Bold,
        )
        Spacer(Modifier.height(4.dp))
        Text(
            localizedString("mobile.delegations_add_desc"),
            fontSize = 12.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.height(8.dp))
        OutlinedTextField(
            value = userCode,
            onValueChange = onUserCodeChange,
            singleLine = true,
            enabled = !busy,
            label = { Text(localizedString("mobile.delegations_code_label")) },
            modifier = Modifier.fillMaxWidth().testable("input_delegation_code"),
        )
        Spacer(Modifier.height(8.dp))
        Button(
            onClick = onApprove,
            enabled = !busy && userCode.isNotBlank(),
            modifier = Modifier.fillMaxWidth().testableClickable("btn_delegation_approve") { onApprove() },
        ) {
            if (busy) {
                CircularProgressIndicator(modifier = Modifier.size(14.dp), strokeWidth = 2.dp)
                Spacer(Modifier.width(8.dp))
            }
            Text(localizedString("mobile.delegations_approve"))
        }
    }
}

/** MANAGE — the active delegations (CRUD: list + revoke). */
@Composable
private fun ManagePane(
    loading: Boolean,
    busy: Boolean,
    delegations: List<ai.ciris.mobile.shared.models.federation.DelegationDto>,
    onRevoke: (String) -> Unit,
) {
    Column(modifier = Modifier.fillMaxWidth()) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                localizedString("mobile.delegations_active_title"),
                fontSize = 15.sp,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.weight(1f),
            )
            if (loading) {
                CircularProgressIndicator(modifier = Modifier.size(14.dp), strokeWidth = 2.dp)
            }
        }
        Spacer(Modifier.height(8.dp))

        if (delegations.isEmpty() && !loading) {
            Text(
                localizedString("mobile.delegations_empty"),
                fontSize = 13.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else {
            delegations.forEach { d ->
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = MaterialTheme.colorScheme.surfaceVariant,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(bottom = 8.dp)
                        .testable("row_delegation_${d.clientId}"),
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(12.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(d.clientId, fontSize = 14.sp, fontWeight = FontWeight.Bold)
                            Text(
                                d.scope,
                                fontSize = 12.sp,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        OutlinedButton(
                            onClick = { onRevoke(d.clientId) },
                            enabled = !busy,
                            modifier = Modifier.testableClickable("btn_revoke_${d.clientId}") { onRevoke(d.clientId) },
                        ) {
                            Text(localizedString("mobile.delegations_revoke"))
                        }
                    }
                }
            }
        }
    }
}
