package ai.ciris.mobile.shared.ui.screens

import ai.ciris.mobile.shared.localization.localizedString
import ai.ciris.mobile.shared.platform.testable
import ai.ciris.mobile.shared.platform.testableClickable
import ai.ciris.mobile.shared.ui.components.CIRISIcons
import ai.ciris.mobile.shared.viewmodels.DelegationsViewModel
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
 * **Delegations** — the owner's view of who they've authorized to act on their
 * behalf, and the control to authorize a new one (the device-authorization flow).
 *
 * An agent generates a device code out-of-band and shows you a short `user_code`;
 * you enter it here and approve (the human-consent gate). The local node mints a
 * delegated token carrying your authority, attributed to that agent. Active
 * delegations are listed with a revoke control. The app drives the LOCAL node
 * only with your owner session — it holds no keys.
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

    // When the Contacts picker returns a selection, fill the key_id field.
    LaunchedEffect(pickedIdentityKeyId) {
        if (!pickedIdentityKeyId.isNullOrBlank()) {
            existingKeyId = pickedIdentityKeyId
            delegateMode = "existing"
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
                text = localizedString("mobile.delegations_subtitle"),
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

            // ── Delegate to an agent (owner creates → hands URL + PIN) ───────
            Spacer(Modifier.height(16.dp))
            Text(
                "Delegate to an agent",
                fontSize = 15.sp,
                fontWeight = FontWeight.Bold,
            )
            Spacer(Modifier.height(4.dp))
            Text(
                "Authorize an agent to act on your behalf. You'll get a URL and PIN to hand to it.",
                fontSize = 12.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = delegateLabel,
                onValueChange = { delegateLabel = it },
                singleLine = true,
                enabled = !busy,
                label = { Text("Agent label (e.g. my-laptop-agent)") },
                modifier = Modifier.fillMaxWidth().testable("input_delegation_label"),
            )
            Spacer(Modifier.height(8.dp))
            // Mode choice — create a new fed-ID vs use an existing one.
            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedButton(
                    onClick = { delegateMode = "create" },
                    enabled = !busy,
                    modifier = Modifier.testableClickable("btn_delegation_mode_create") {
                        delegateMode = "create"
                    },
                ) {
                    Text(
                        "New fed-ID",
                        fontWeight = if (delegateMode == "create") FontWeight.Bold else FontWeight.Normal,
                    )
                }
                Spacer(Modifier.width(8.dp))
                OutlinedButton(
                    onClick = { delegateMode = "existing" },
                    enabled = !busy,
                    modifier = Modifier.testableClickable("btn_delegation_mode_existing") {
                        delegateMode = "existing"
                    },
                ) {
                    Text(
                        "Existing fed-ID",
                        fontWeight = if (delegateMode == "existing") FontWeight.Bold else FontWeight.Normal,
                    )
                }
            }
            if (delegateMode == "existing") {
                Spacer(Modifier.height(8.dp))
                // "Choose identity" button — opens Contacts picker when available.
                if (onOpenContacts != null) {
                    OutlinedButton(
                        onClick = onOpenContacts,
                        enabled = !busy,
                        modifier = Modifier.fillMaxWidth().testableClickable("btn_delegation_choose_identity") {
                            onOpenContacts()
                        },
                    ) {
                        Icon(
                            CIRISIcons.person,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp),
                        )
                        Spacer(Modifier.width(6.dp))
                        Text(
                            if (existingKeyId.isBlank()) "Choose from Contacts"
                            else "Change identity (${existingKeyId.take(12)}…)",
                        )
                    }
                    Spacer(Modifier.height(6.dp))
                }
                // Manual key_id fallback — always shown so the user can type directly.
                OutlinedTextField(
                    value = existingKeyId,
                    onValueChange = { existingKeyId = it },
                    singleLine = true,
                    enabled = !busy,
                    label = {
                        Text(
                            if (onOpenContacts != null) "Or paste a key_id manually"
                            else "Existing fed-ID key_id"
                        )
                    },
                    modifier = Modifier.fillMaxWidth().testable("input_delegation_key_id"),
                )
            }
            Spacer(Modifier.height(8.dp))
            Button(
                onClick = {
                    viewModel.createDelegation(delegateLabel, delegateMode, existingKeyId)
                },
                enabled = !busy && delegateLabel.isNotBlank(),
                modifier = Modifier.fillMaxWidth().testableClickable("btn_delegation_create") {
                    viewModel.createDelegation(delegateLabel, delegateMode, existingKeyId)
                },
            ) {
                if (busy) {
                    CircularProgressIndicator(modifier = Modifier.size(14.dp), strokeWidth = 2.dp)
                    Spacer(Modifier.width(8.dp))
                }
                Text("Create delegation")
            }

            // ── Created result — the URL + PIN to hand over ──────────────────
            lastCreated?.let { created ->
                Spacer(Modifier.height(12.dp))
                Surface(
                    shape = RoundedCornerShape(12.dp),
                    color = MaterialTheme.colorScheme.primaryContainer,
                    modifier = Modifier
                        .fillMaxWidth()
                        .testable("delegation_created_card"),
                ) {
                    Column(modifier = Modifier.fillMaxWidth().padding(14.dp)) {
                        Text(
                            "Hand this to the agent",
                            fontSize = 13.sp,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.onPrimaryContainer,
                        )
                        Spacer(Modifier.height(8.dp))
                        Text(
                            "PIN",
                            fontSize = 11.sp,
                            color = MaterialTheme.colorScheme.onPrimaryContainer,
                        )
                        Text(
                            created.pin,
                            fontSize = 32.sp,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.onPrimaryContainer,
                            modifier = Modifier.testable("delegation_created_pin"),
                        )
                        Spacer(Modifier.height(8.dp))
                        Text(
                            "Claim URL",
                            fontSize = 11.sp,
                            color = MaterialTheme.colorScheme.onPrimaryContainer,
                        )
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
                            "Hand this URL + PIN to the agent; it expires in ${created.expiresIn / 60} minutes.",
                            fontSize = 12.sp,
                            color = MaterialTheme.colorScheme.onPrimaryContainer,
                        )
                        Spacer(Modifier.height(10.dp))
                        Button(
                            onClick = {
                                viewModel.clearLastCreated()
                                delegateLabel = ""
                                existingKeyId = ""
                            },
                            modifier = Modifier.testableClickable("btn_delegation_created_done") {
                                viewModel.clearLastCreated()
                                delegateLabel = ""
                                existingKeyId = ""
                            },
                        ) {
                            Text("Done")
                        }
                    }
                }
            }

            // ── Approve a new delegation ─────────────────────────────────────
            Spacer(Modifier.height(20.dp))
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
                onValueChange = { userCode = it },
                singleLine = true,
                enabled = !busy,
                label = { Text(localizedString("mobile.delegations_code_label")) },
                modifier = Modifier.fillMaxWidth().testable("input_delegation_code"),
            )
            Spacer(Modifier.height(8.dp))
            Button(
                onClick = { viewModel.approve(userCode); userCode = "" },
                enabled = !busy && userCode.isNotBlank(),
                modifier = Modifier.fillMaxWidth().testableClickable("btn_delegation_approve") {
                    viewModel.approve(userCode); userCode = ""
                },
            ) {
                if (busy) {
                    CircularProgressIndicator(modifier = Modifier.size(14.dp), strokeWidth = 2.dp)
                    Spacer(Modifier.width(8.dp))
                }
                Text(localizedString("mobile.delegations_approve"))
            }

            // ── Active delegations ───────────────────────────────────────────
            Spacer(Modifier.height(20.dp))
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
                                onClick = { viewModel.revoke(d.clientId) },
                                enabled = !busy,
                                modifier = Modifier.testableClickable("btn_revoke_${d.clientId}") {
                                    viewModel.revoke(d.clientId)
                                },
                            ) {
                                Text(localizedString("mobile.delegations_revoke"))
                            }
                        }
                    }
                }
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}
